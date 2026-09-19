package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"cysec/internal/model"
	"cysec/internal/plugins"
	"cysec/internal/ua"
	"cysec/internal/vulnrule"
)

// 官方 nuclei 引擎实时扫描：发现新的 Web 资产即提交扫描（与实时漏洞扫描/AI 研判同模式）。
// 队列消费采用微批聚合：先取队首，随后在窗口内继续收集（最多 nucleiBatchMax 个），
// 一次引擎调用跑完整批——引擎初始化需编译全部启用模板（数秒），逐资产新建实例在大批量
// 发现场景开销过大；窗口仅数秒，保持"发现即扫"的体感。
// xray / afrog 源规则仍由自研执行器在 detectWeb 内联执行。

const (
	nucleiScanQueueCap = 512
	nucleiBatchWindow  = 5 * time.Second
	nucleiBatchMax     = 20
)

// startNucleiScan 启动实时 nuclei 扫描消费循环（单 worker：引擎实例创建成本高）
func (e *Engine) startNucleiScan() {
	e.nucleiScanQueue = make(chan autoScanJob, nucleiScanQueueCap)
	go func() {
		for {
			first, ok := <-e.nucleiScanQueue
			if !ok {
				return
			}
			batch := []autoScanJob{first}
			timer := time.NewTimer(nucleiBatchWindow)
		drain:
			for len(batch) < nucleiBatchMax {
				select {
				case j := <-e.nucleiScanQueue:
					batch = append(batch, j)
				case <-timer.C:
					break drain
				}
			}
			timer.Stop()
			e.runNucleiBatchJobs(batch)
		}
	}()
}

// SubmitNucleiScan 提交新 Web 资产的官方引擎扫描（队列满时丢弃并记日志）
func (e *Engine) SubmitNucleiScan(taskID, projectID int64, url string) {
	if e.nucleiScanQueue == nil || url == "" {
		return
	}
	select {
	case e.nucleiScanQueue <- autoScanJob{taskID: taskID, projectID: projectID, url: url}:
	default:
		log.Printf("[nuclei] 扫描队列已满（%d），跳过 %s", nucleiScanQueueCap, url)
	}
}

// taskFor 解析批次任务上下文：真实任务取库内记录（超时/日志归属），合成任务用默认值
func (e *Engine) taskFor(j autoScanJob) *model.ScanTask {
	if j.taskID > 0 {
		if t, err := e.store.GetTask(j.taskID); err == nil {
			return t
		}
	}
	return &model.ScanTask{ProjectID: j.projectID, Mode: "standard", TimeoutSec: maxInt(e.cfg.Scan.TimeoutSeconds, 5)}
}

// enabledNucleiRuleIDs 读取启用的 nuclei 源规则 ID（受规则库设置开关与限额约束）
func (e *Engine) enabledNucleiRuleIDs() []string {
	st := vulnrule.DefaultSettings()
	if saved, _ := e.store.GetSetting("vuln_rule_settings"); saved != "" {
		json.Unmarshal([]byte(saved), &st)
	}
	if !st.EnabledInScan {
		return nil
	}
	ids := []string{}
	for _, r := range e.store.EnabledRulesForScan(st.MaxPerTarget) {
		if r.Source == "nuclei" {
			ids = append(ids, r.RuleID)
		}
	}
	return ids
}

// runNucleiBatchJobs 执行一批实时扫描任务：一次引擎调用跑完批内全部资产
func (e *Engine) runNucleiBatchJobs(jobs []autoScanJob) {
	if len(jobs) == 0 || vulnrule.NucleiTemplateRoot() == "" {
		return
	}
	ids := e.enabledNucleiRuleIDs()
	if len(ids) == 0 {
		return
	}
	// URL 去重并保留 job 映射（结果回填任务上下文用）
	urlJobs := map[string]autoScanJob{}
	urls := []string{}
	for _, j := range jobs {
		k := normalizeWebKey(j.url)
		if k == "" {
			continue
		}
		if _, dup := urlJobs[k]; !dup {
			urls = append(urls, j.url)
		}
		urlJobs[k] = j
	}
	if len(urls) == 0 {
		return
	}
	e.taskLog(0, "info", fmt.Sprintf("nuclei 官方引擎：批次对 %d 个 Web 资产执行 %d 条启用规则", len(urls), len(ids)))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 任一批内真实任务被取消 → 中止引擎扫描
	go func() {
		watched := []chan struct{}{}
		seen := map[int64]bool{}
		for _, j := range jobs {
			if j.taskID > 0 && !seen[j.taskID] {
				seen[j.taskID] = true
				watched = append(watched, runCancel(e, j.taskID))
			}
		}
		select {
		case <-ctx.Done():
		case <-waitAny(watched):
			cancel()
		}
	}()

	findings, err := vulnrule.RunNucleiBatch(ctx, urls, ids, maxInt(e.taskFor(jobs[0]).TimeoutSec, 5))
	if err != nil {
		e.taskLog(jobs[0].taskID, "warn", "nuclei 引擎执行异常: "+err.Error())
	}

	// Web 资产字段映射（按项目缓存，IP/端口/域名回填）
	webCache := map[int64][]model.AssetWeb{}
	webOf := func(j autoScanJob) *model.AssetWeb {
		if _, ok := webCache[j.projectID]; !ok {
			webCache[j.projectID] = e.store.WebsOfProject(j.projectID)
		}
		for i := range webCache[j.projectID] {
			w := &webCache[j.projectID][i]
			if normalizeWebKey(w.URL) == normalizeWebKey(j.url) {
				return w
			}
		}
		return nil
	}

	matched := 0
	perTask := map[int64]int{}
	for _, f := range findings {
		j, ok := urlJobs[normalizeWebKey(f.URL)]
		if !ok {
			j = jobs[0] // 兜底：nuclei 返回的 base URL 与传入不一致时归入首个任务
		}
		task := e.taskFor(j)
		w := &plugins.WebResult{URL: j.url, Port: atoiOrZero(f.Port), IP: f.Host}
		if aw := webOf(j); aw != nil {
			w.IP, w.Domain, w.Port, w.URL = aw.IP, aw.Domain, aw.Port, aw.URL
		}
		// 报文兜底：多请求链 / interactsh 匹配等场景官方事件可能缺 request/response，
		// 重建最小请求报文 + 合成响应摘要，保证前端报文查看不为空
		req, resp := f.Request, f.Response
		if strings.TrimSpace(req) == "" {
			req = rebuildMinimalRequest(f)
		}
		if strings.TrimSpace(resp) == "" {
			resp = rebuildMinimalResponse(f)
		}
		e.saveVuln(task, plugins.VulnResult{
			VulnID:      f.TemplateID,
			Name:        orDefaultStr(f.Name, f.TemplateID),
			Severity:    orDefaultStr(f.Severity, "info"),
			Description: f.Description,
			Solution:    "参考模板修复建议: " + f.TemplateID,
			Evidence:    orDefaultStr(f.MatchedAt, f.URL),
			Request:     req,
			Response:    resp,
			Component:   "规则库(nuclei)",
			Scanner:     "nuclei-engine",
		}, w)
		log.Printf("[nuclei] 检出 %s %s %s", strings.ToUpper(orDefaultStr(f.Severity, "info")), orDefaultStr(f.Name, f.TemplateID), orDefaultStr(f.MatchedAt, f.URL))
		matched++
		perTask[j.taskID]++
	}
	for tid, n := range perTask {
		e.taskLog(tid, "info", fmt.Sprintf("nuclei 官方引擎：%s 检出 %d 个漏洞", e.taskURLSummary(tid, n), n))
	}
	if matched == 0 {
		e.taskLog(0, "info", fmt.Sprintf("nuclei 官方引擎：批次 %d 个资产未检出漏洞", len(urls)))
	}
}

// taskURLSummary 任务日志摘要（真实任务给简短说明；合成任务只走服务端日志）
func (e *Engine) taskURLSummary(taskID int64, n int) string {
	if taskID > 0 {
		return fmt.Sprintf("任务 #%d", taskID)
	}
	return "实时扫描"
}

// ScanAssetsWithNucleiRules 用指定的 nuclei 规则批量扫描全部 Web 资产（跨项目），
// 返回检出数。由 POC 目录监控 / 模板源更新的"新增规则"路径调用，
// 替代自研执行器，消除该路径的匹配语义误报。
func (e *Engine) ScanAssetsWithNucleiRules(ruleIDs []string, timeoutSec int) int {
	if len(ruleIDs) == 0 || vulnrule.NucleiTemplateRoot() == "" {
		return 0
	}
	webs := e.store.AllWebAssets()
	wl := e.LoadWhitelist()
	urls := []string{}
	webByKey := map[string]*model.AssetWeb{}
	for i := range webs {
		w := &webs[i]
		if Whitelisted(wl, w.IP, w.Domain) {
			continue
		}
		k := normalizeWebKey(w.URL)
		if _, dup := webByKey[k]; dup {
			continue
		}
		webByKey[k] = w
		urls = append(urls, w.URL)
	}
	if len(urls) == 0 {
		return 0
	}
	findings, err := vulnrule.RunNucleiBatch(context.Background(), urls, ruleIDs, timeoutSec)
	if err != nil {
		log.Printf("[nuclei] 新增规则扫描异常: %v", err)
	}
	matched := 0
	for _, f := range findings {
		w := webByKey[normalizeWebKey(f.URL)]
		if w == nil {
			continue
		}
		e.saveVuln(&model.ScanTask{ProjectID: w.ProjectID, Mode: "standard", TimeoutSec: timeoutSec}, plugins.VulnResult{
			VulnID:      f.TemplateID,
			Name:        orDefaultStr(f.Name, f.TemplateID),
			Severity:    orDefaultStr(f.Severity, "info"),
			Description: f.Description,
			Solution:    "参考模板修复建议: " + f.TemplateID,
			Evidence:    orDefaultStr(f.MatchedAt, f.URL),
			Request:     f.Request,
			Response:    f.Response,
			Component:   "POC监控(nuclei)",
			Scanner:     "nuclei-engine",
		}, &plugins.WebResult{URL: w.URL, IP: w.IP, Domain: w.Domain, Port: w.Port})
		matched++
	}
	log.Printf("[nuclei] 新增规则扫描：%d 资产 × %d 规则，检出 %d", len(urls), len(ruleIDs), matched)
	return matched
}

// taskLog 任务日志：真实任务写任务日志，合成任务（ID=0）写服务端日志
func (e *Engine) taskLog(taskID int64, level, msg string) {
	if taskID > 0 {
		e.store.LogTask(taskID, level, msg)
		return
	}
	log.Printf("[nuclei] %s", msg)
}

// waitAny 返回任一 channel 就绪即触发的合并 channel（全空/全 nil 则永不触发）
func waitAny(chans []chan struct{}) chan struct{} {
	merged := make(chan struct{})
	active := 0
	for _, ch := range chans {
		if ch == nil {
			continue
		}
		active++
		go func(c chan struct{}) {
			select {
			case <-c:
				merged <- struct{}{}
			case <-merged:
			}
		}(ch)
	}
	if active == 0 {
		return nil // nil channel：select 永远不命中该分支
	}
	return merged
}

func normalizeWebKey(u string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u)), "/")
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// rebuildMinimalRequest 重建最小请求报文（官方事件缺 request 时兜底）：
// 方法 + 命中 URL + 全局出站头，注明为重建报文
func rebuildMinimalRequest(f vulnrule.NucleiFinding) string {
	m := "GET"
	target := orDefaultStr(f.MatchedAt, f.URL)
	lower := strings.ToLower(target)
	if strings.Contains(lower, "post") {
		m = "POST"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", m, target)
	fmt.Fprintf(&b, "Host: %s\r\n", hostOfURL(target))
	for k, v := range ua.CurrentHeaders() {
		if k == "Host" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n\r\n[注] 原始请求报文未被引擎保留（多请求链/interactsh 模板），此为重建报文。")
	return b.String()
}

// rebuildMinimalResponse 合成响应摘要（官方事件缺 response 时兜底）
func rebuildMinimalResponse(f vulnrule.NucleiFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[注] 原始响应报文未被引擎保留（多请求链/interactsh 模板）。\r\n\r\n")
	fmt.Fprintf(&b, "命中位置: %s\r\n", orDefaultStr(f.MatchedAt, f.URL))
	if f.MatcherName != "" {
		fmt.Fprintf(&b, "匹配器: %s\r\n", f.MatcherName)
	}
	if len(f.Tags) > 0 {
		fmt.Fprintf(&b, "标签: %s\r\n", f.Tags)
	}
	return b.String()
}

func hostOfURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
