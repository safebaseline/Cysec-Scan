package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"

	"cysec/internal/ai"
	"cysec/internal/events"
	"cysec/internal/model"
	"cysec/internal/netproxy"
	"cysec/internal/plugins"
	"cysec/internal/ua"
	"cysec/internal/weakness"
)

// 弱点管理：网站链接爬取（暗链/坏链/敏感字）在 detectWeb 内联执行；
// WIH JS 敏感信息检测结果归并到弱点表（不再进漏洞库）。

const weaknessSettingsKey = "weakness_settings"

// weaknessSettings 即时读取界面配置（未保存用默认）并合并订阅词表：
// 敏感字 = 手动词库 + 订阅词表；暗链关键词 = 历史暗链词 ∪ 手动词库 ∪ 订阅中 ForDark 文件词表
// （手动词库两用；订阅内容审核类词库默认不参与暗链，避免外链锚文本误报，可在文件上勾选"暗"启用）
func (e *Engine) weaknessSettings() weakness.Settings {
	st := weakness.DefaultSettings()
	if saved, _ := e.store.GetSetting(weaknessSettingsKey); saved != "" {
		_ = json.Unmarshal([]byte(saved), &st)
	}
	if st.MaxPages <= 0 {
		st.MaxPages = 50
	}
	if st.MaxLinks <= 0 {
		st.MaxLinks = 50
	}
	legacyDark := st.DarkKeywords
	manual := st.SensitiveWords
	st.SensitiveWords = weakness.MergeSensWords(manual, e.cachedSensWords())
	st.DarkKeywords = weakness.MergeSensWords(legacyDark, manual, e.cachedSensDark())
	return st
}

// rawWeaknessSettings 界面原始配置（不合并订阅词表）——设置读写接口使用，
// 避免上万订阅词灌入手动词库输入框
func (e *Engine) rawWeaknessSettings() weakness.Settings {
	st := weakness.DefaultSettings()
	if saved, _ := e.store.GetSetting(weaknessSettingsKey); saved != "" {
		_ = json.Unmarshal([]byte(saved), &st)
	}
	return st
}

// pageFinding 弱点结果 + 来源页面上下文（入库 page_url/page_title 用）
type pageFinding struct {
	f                  weakness.Finding
	pageURL, pageTitle string
}

// runWeaknessScan 对单个 Web 资产执行全站链接爬取与暗链/坏链/敏感字检测并入库。
// 爬虫引擎：colly（gocolly/colly v2）从站点入口沿同站内链 BFS 逐页抓取
// （上限 st.MaxPages 页，任务取消即停）；每页独立判定，弱点携带所属页面与标题；
// 坏链对全站去重后的链接集合探测一次（引用位置取首次出现页面）。
func (e *Engine) runWeaknessScan(task *model.ScanTask, w *plugins.WebResult, body string, timeoutSec int) {
	st := e.weaknessSettings()
	if !st.Enabled {
		return
	}
	uaHdr := map[string]string{"User-Agent": ua.Get()}
	stopCh := runCancel(e, task.ID)
	stopped := func() bool {
		if stopCh == nil {
			return false
		}
		select {
		case <-stopCh:
			return true
		default:
			return false
		}
	}
	pages := weakness.CrawlSite(w.URL, netproxy.NewHTTPClient(maxInt(timeoutSec, 5), 0), uaHdr, st.MaxPages, stopped)

	pfs := []pageFinding{}
	linkCount := 0
	type seenLink struct {
		l                  weakness.Link
		pageURL, pageTitle string
	}
	seen := map[string]seenLink{}
	var order []string
	// 爬虫已成功抓取的页面（HTTP 200）无需再探测——既省请求，也消除并发压力下
	// 重复请求瞬时失败导致的"不可达"误报
	crawled := make(map[string]bool, len(pages))
	for _, p := range pages {
		crawled[weakness.PageKey(p.URL)] = true
	}
	crawledSkipped := 0
	for _, p := range pages {
		linkCount += len(p.Links)
		for _, f := range weakness.Classify(p.URL, p.Links, p.Text, st) {
			pfs = append(pfs, pageFinding{f: f, pageURL: p.URL, pageTitle: p.Title})
		}
		for _, l := range p.Links {
			if _, ok := seen[l.URL]; ok {
				continue
			}
			seen[l.URL] = seenLink{l: l, pageURL: p.URL, pageTitle: p.Title}
			if crawled[weakness.PageKey(l.URL)] {
				crawledSkipped++
				continue
			}
			order = append(order, l.URL)
		}
	}
	// 暗链目标内容核验：隐藏外链（词库未命中）请求目标页，标题/正文命中暗链词库才报
	if !st.DarkVerifyDisabled {
		pfs = e.verifyDarkFindings(task, pfs, st, timeoutSec, stopped)
	}
	// 坏链检测（去重后受限并发 + 上限，走全局代理与 UA，带来源页 Referer）
	dedupe := make([]weakness.Link, len(order))
	for i, u := range order {
		dedupe[i] = seen[u].l
	}
	doer := newDoer(maxInt(timeoutSec, 10), w.URL)
	brokenFetch := func(u string) (int, int) {
		var (
			resp *plugins.HTTPResponse
			err  error
		)
		// 防盗链站点校验 Referer，无来源会误判 404/403
		if rd, ok := doer.(interface {
			DoReferer(url, referer string) (*plugins.HTTPResponse, error)
		}); ok {
			resp, err = rd.DoReferer(u, seen[u].pageURL)
		} else {
			resp, err = doer.Do(u)
		}
		switch {
		case err == nil && resp != nil:
			return resp.StatusCode, weakness.FetchOK
		case isDomainNotFound(err):
			return 0, weakness.FetchDead
		default:
			return 0, weakness.FetchFail
		}
	}
	brokenFindings, bs := weakness.CheckBroken(dedupe, st, brokenFetch)
	for _, f := range brokenFindings {
		s := seen[f.URL]
		pfs = append(pfs, pageFinding{f: f, pageURL: s.pageURL, pageTitle: s.pageTitle})
	}
	// 批量入库（单事务）：全站扫描一次产生数十条弱点，逐条单事务是写放大源
	batch := make([]model.Weakness, len(pfs))
	for i, pf := range pfs {
		batch[i] = model.Weakness{
			ProjectID: task.ProjectID, TaskID: task.ID, WebURL: w.URL,
			PageURL: pf.pageURL, PageTitle: pf.pageTitle,
			Type: pf.f.Type, URL: pf.f.URL, Anchor: pf.f.Anchor, StatusCode: pf.f.StatusCode,
			Detail: pf.f.Detail, Severity: pf.f.Severity, Evidence: pf.f.Evidence, Context: pf.f.Context,
		}
	}
	newFlags, ids, err := e.store.UpsertWeaknessBatch(batch)
	if err == nil {
		for i := range newFlags {
			if newFlags[i] {
				events.Publish("weaknesses")
				break
			}
		}
		for i, pf := range pfs {
			if newFlags[i] {
				// 实时 AI 研判：新增弱点即入队（开关与等级过滤在出队时判断）
				e.SubmitWeaknessAIAnalyze(ids[i], ai.VulnContext{
					VulnID: pf.f.Type, Name: pf.f.Anchor, Severity: pf.f.Severity, Description: pf.f.Detail,
					URL: pf.pageURL, Evidence: pf.f.Evidence,
				})
			}
		}
	}
	if len(pages) > 0 {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("弱点检测 %s：爬取页面 %d/%d，链接 %d 条（去重 %d，已验证跳过 %d），检出 %d 项（暗链/坏链/敏感字）",
			w.URL, len(pages), st.MaxPages, linkCount, len(dedupe), crawledSkipped, len(pfs)))
		if linkCount == 0 {
			for _, pg := range pages {
				if pg.SPAHint {
					// 纯前端渲染站点：HTML 无静态链接，页面由 JS 动态生成，静态爬取只能看到入口页
					e.store.LogTask(task.ID, "info", fmt.Sprintf("站点 %s 疑似纯前端渲染（SPA）：HTML 内无静态链接，页面由 JavaScript 动态生成，静态爬取仅覆盖入口页（链接爬取/暗链/坏链检测受限，首页与引用 JS 仍参与敏感字与 WIH 检测）", w.URL))
					break
				}
			}
		}
		if bs.Checked+bs.Ignored > 0 {
			e.store.LogTask(task.ID, "info", fmt.Sprintf("坏链探测：%d 条（忽略域名 %d）——失效 %d、域名无法解析 %d、无法验证未报 %d（网络失败重试仍失败，不作为坏链）",
				bs.Checked, bs.Ignored, bs.Broken, bs.Dead, bs.Unverified))
		}
	}
}

// isDomainNotFound 网络错误是否为 DNS 域名不存在（明确死链）。
// 代理模式下 DNS 由代理解析，客户端判不出该错误，按"无法验证"处理（保守不报）。
func isDomainNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// verifyDarkFindings 暗链目标页内容核验：对全部暗链候选并发请求目标页（受限并发，
// 走全局代理与 UA，限额 st.MaxLinks），对响应做二次暗链词库匹配：
//   - 隐藏且词库未命中（NeedsVerify）：目标页标题/正文命中关键词才保留，详情附目标页
//     标题、命中词、状态码与命中片段；未命中或不可达则丢弃（消除"隐藏联系方式"类误报）
//   - 锚文本/URL 已命中（无需核验）：不受核验结果影响（死站赌链不能漏），可达时回填
//     状态码与目标页标题作为增强证据
func (e *Engine) verifyDarkFindings(task *model.ScanTask, pfs []pageFinding, st weakness.Settings, timeoutSec int, stopped func() bool) []pageFinding {
	urls := map[string]bool{}
	for _, pf := range pfs {
		if pf.f.Type == "darklink" {
			urls[pf.f.URL] = true
		}
	}
	if len(urls) == 0 {
		return pfs
	}
	doer := newDoer(maxInt(timeoutSec, 5), "")
	var mu sync.Mutex
	verified := map[string]weakness.DarkVerify{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	checked := 0
	// 排序后再截断限额：map 遍历随机，超限截掉的任意子集会导致两次扫描结果不可复现
	urlList := make([]string, 0, len(urls))
	for u := range urls {
		urlList = append(urlList, u)
	}
	sort.Strings(urlList)
	verifyLimit := st.MaxLinks
	if verifyLimit < 1 {
		verifyLimit = 10
	}
	for _, u := range urlList {
		if stopped() {
			break
		}
		mu.Lock()
		if checked >= verifyLimit {
			mu.Unlock()
			break
		}
		checked++
		mu.Unlock()
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp, err := doer.Do(u)
			if err != nil || resp == nil {
				return
			}
			v := weakness.VerifyDarkBody(resp.StatusCode, resp.Body, st)
			mu.Lock()
			verified[u] = v
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	out := make([]pageFinding, 0, len(pfs))
	dropped := 0
	for _, pf := range pfs {
		if pf.f.Type != "darklink" {
			out = append(out, pf)
			continue
		}
		v, reachable := verified[pf.f.URL]
		if pf.f.NeedsVerify {
			if reachable && v.HitKw != "" {
				pf.f.StatusCode = v.Code
				pf.f.Detail = fmt.Sprintf("隐藏外链且目标页内容命中暗链关键词「%s」（目标页标题：%s，HTTP %d）",
					v.HitKw, orDefaultStr(v.Title, "-"), v.Code)
				if v.Snippet != "" {
					pf.f.Evidence = v.Snippet
				}
				out = append(out, pf)
			} else {
				dropped++
			}
			continue
		}
		if reachable {
			pf.f.StatusCode = v.Code
			pf.f.Detail = fmt.Sprintf("%s（目标页标题：%s，HTTP %d）", pf.f.Detail, orDefaultStr(v.Title, "-"), v.Code)
			if v.HitKw != "" {
				pf.f.Detail += fmt.Sprintf("，内容亦命中「%s」", v.HitKw)
				if pf.f.Evidence == "" && v.Snippet != "" {
					pf.f.Evidence = v.Snippet
				}
			}
		}
		out = append(out, pf)
	}
	if len(urls) > 0 {
		hits, unreach := 0, 0
		for u := range urls {
			if v, ok := verified[u]; !ok {
				unreach++
			} else if v.HitKw != "" {
				hits++
			}
		}
		e.store.LogTask(task.ID, "info", fmt.Sprintf("暗链目标核验：候选 %d 条（内容命中 %d、未命中 %d、不可达 %d），丢弃待核验未命中 %d 条",
			len(urls), hits, len(urls)-hits-unreach, unreach, dropped))
	}
	return out
}

// saveWihWeakness WIH 检测结果写入弱点表（type=wih）
func (e *Engine) saveWihWeakness(task *model.ScanTask, w *plugins.WebResult, vr plugins.VulnResult) {
	isNew, id, err := e.store.UpsertWeaknessID(model.Weakness{
		ProjectID: task.ProjectID, TaskID: task.ID, WebURL: w.URL,
		PageURL: w.URL, PageTitle: w.Title,
		Type: "wih", URL: w.URL, Anchor: vr.Name,
		Detail: vr.Description, Severity: vr.Severity, Evidence: vr.Evidence,
	})
	if err != nil {
		log.Printf("[弱点] WIH 结果入库失败: %v", err)
	}
	if isNew {
		e.SubmitWeaknessAIAnalyze(id, ai.VulnContext{
			VulnID: vr.VulnID, Name: vr.Name, Severity: vr.Severity, Description: vr.Description,
			URL: w.URL, Evidence: vr.Evidence, Response: vr.Response,
		})
	}
	e.store.LogTask(task.ID, "info", "检出弱点 [WIH] "+vr.Name+" @ "+w.URL)
}

// CurrentWeaknessSettings 暴露给 API 层读取（原始配置，不含订阅合并词表）
func (e *Engine) CurrentWeaknessSettings() weakness.Settings { return e.rawWeaknessSettings() }

// SetWeaknessSettings 保存并即时生效（API 层调用）。
// 暗链关键词已并入统一词库（界面不再单独编辑）：入参为空时保留历史自定义暗链词不丢失。
func (e *Engine) SetWeaknessSettings(st weakness.Settings) error {
	if st.MaxPages <= 0 {
		st.MaxPages = 50
	}
	if st.MaxLinks <= 0 {
		st.MaxLinks = 50
	}
	if len(st.DarkKeywords) == 0 {
		if old := e.rawWeaknessSettings(); len(old.DarkKeywords) > 0 {
			st.DarkKeywords = old.DarkKeywords
		}
	}
	data, _ := json.Marshal(st)
	return e.store.SetSetting(weaknessSettingsKey, string(data))
}

var _ = ua.Get // 保持 ua 引用（报文兜底在调用方）

// phaseSummary 任务阶段摘要（日志用）
func phaseSummary(task *model.ScanTask) string {
	if strings.TrimSpace(task.Phases) == "" {
		return "兼容模式"
	}
	return strings.ReplaceAll(task.Phases, ",", "+")
}

// runAliveCheck Web 资产存活检测：逐站点探测可达性与状态码，状态翻转记变化
func (e *Engine) runAliveCheck(task *model.ScanTask) {
	webs := e.store.WebsOfProject(task.ProjectID)
	doer := newDoer(maxInt(task.TimeoutSec, 5), "")
	up, down := 0, 0
	for i := range webs {
		w := &webs[i]
		select {
		case <-runCancel(e, task.ID):
			return
		default:
		}
		resp, err := doer.Do(w.URL)
		if err != nil || resp == nil {
			down++
			e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "web", Asset: w.URL, Change: "remove", Detail: "存活检测：不可达"})
			continue
		}
		up++
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "web", Asset: w.URL, Change: "add", Detail: fmt.Sprintf("存活检测：HTTP %d", resp.StatusCode)})
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("Web 存活检测完成：%d 个站点，存活 %d，不可达 %d", len(webs), up, down))
}
