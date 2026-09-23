package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"cysec/internal/events"
	"cysec/internal/netproxy"
	"cysec/internal/store"
	"cysec/internal/ua"
	"cysec/internal/weakness"
)

// 敏感字词库订阅（引擎侧）：拉取、缓存、与手动词库合并、每日自动更新。
// 词表本体存 settings（weakness_senssub_words），引擎内存缓存避免逐资产重复解析大 JSON。

const (
	sensSubCfgKey    = "weakness_senssub_cfg"
	sensSubStateKey  = "weakness_senssub_state"
	sensSubWordsKey  = "weakness_senssub_words"  // 订阅拉取词表（每次更新整体覆盖）
	sensSubDarkKey   = "weakness_senssub_dark"   // 订阅中标记"用作暗链关键词"的文件词表
	sensSubCustomKey = "weakness_senssub_custom" // 手工补充词条（更新保留，暗链/敏感字两用）
	sensSubExclKey   = "weakness_senssub_excludes" // 排除词条（删除记录，更新时过滤不带回）
)

// SensSubView 界面所需的订阅视图（配置 + 状态，不含词表）
type SensSubView struct {
	weakness.SubConfig
	State weakness.SubState `json:"state"`
}

// rawURL 拼 raw 地址：中文路径按段转义
func rawURL(base, path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.TrimRight(base, "/") + "/" + strings.Join(segs, "/")
}

// sensSubConfig 读取订阅配置（从未保存时用默认预设；已保存的自定义配置——含空文件清单——按用户配置原样生效）
func (e *Engine) sensSubConfig() weakness.SubConfig {
	if saved, _ := e.store.GetSetting(sensSubCfgKey); saved != "" {
		var c weakness.SubConfig
		if json.Unmarshal([]byte(saved), &c) == nil && strings.TrimSpace(c.Base) != "" {
			return weakness.NormalizeSubConfig(c)
		}
	}
	return weakness.DefaultSubConfig()
}

// SetSensSubConfig 保存订阅配置（API 层调用）
func (e *Engine) SetSensSubConfig(c weakness.SubConfig) error {
	c = weakness.NormalizeSubConfig(c)
	data, _ := json.Marshal(c)
	return e.store.SetSetting(sensSubCfgKey, string(data))
}

// SensSubView 当前配置 + 状态（设置接口随弱点配置一并返回）
func (e *Engine) SensSubView() SensSubView {
	v := SensSubView{SubConfig: e.sensSubConfig()}
	if saved, _ := e.store.GetSetting(sensSubStateKey); saved != "" {
		json.Unmarshal([]byte(saved), &v.State)
	}
	return v
}

// cachedSensWords 生效敏感字词表 =（订阅拉取 ∪ 手工补充）− 排除词条，去重；
// 首次访问从库加载合并，之后走内存缓存（更新/增删时刷新）
func (e *Engine) cachedSensWords() []string {
	e.sensMu.Lock()
	loaded := e.sensWords != nil
	e.sensMu.Unlock()
	if !loaded {
		e.refreshSensCache()
	}
	e.sensMu.Lock()
	defer e.sensMu.Unlock()
	return e.sensWords
}

// cachedSensDark 生效暗链订阅词表 =（ForDark 文件拉取词 ∪ 手工补充）− 排除词条
func (e *Engine) cachedSensDark() []string {
	e.sensMu.Lock()
	loaded := e.sensDark != nil
	e.sensMu.Unlock()
	if !loaded {
		e.refreshSensCache()
	}
	e.sensMu.Lock()
	defer e.sensMu.Unlock()
	return e.sensDark
}

// sensSubList 读取词表类 settings（JSON 字符串数组）
func (e *Engine) sensSubList(key string) []string {
	if saved, _ := e.store.GetSetting(key); saved != "" {
		var l []string
		if json.Unmarshal([]byte(saved), &l) == nil {
			return l
		}
	}
	return nil
}

func (e *Engine) saveSensSubList(key string, l []string) {
	if data, err := json.Marshal(l); err == nil {
		e.store.SetSetting(key, string(data))
	}
}

// refreshSensCache 依据存储（拉取/暗链拉取/手工/排除）重算敏感字与暗链两份生效词表并刷新缓存
func (e *Engine) refreshSensCache() {
	pull := e.sensSubList(sensSubWordsKey)
	darkPull := e.sensSubList(sensSubDarkKey)
	custom := e.sensSubList(sensSubCustomKey)
	exSet := map[string]bool{}
	for _, w := range e.sensSubList(sensSubExclKey) {
		if w != "" {
			exSet[w] = true
		}
	}
	filter := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, w := range in {
			if !exSet[w] {
				out = append(out, w)
			}
		}
		return out
	}
	sens := filter(weakness.MergeSensWords(pull, custom))
	dark := filter(weakness.MergeSensWords(darkPull, custom))
	e.sensMu.Lock()
	e.sensWords = sens
	e.sensDark = dark
	e.sensMu.Unlock()
	e.syncSensStateCount()
}

// syncSensStateCount 词表变动（清空/增删/恢复/更新）后同步状态里的生效词数，
// 界面"词库共 N 词 / 上次更新…共 N 词"读该字段——不同步会残留旧值误导用户
func (e *Engine) syncSensStateCount() {
	var st weakness.SubState
	if saved, _ := e.store.GetSetting(sensSubStateKey); saved != "" {
		json.Unmarshal([]byte(saved), &st)
	}
	st.WordCount = len(e.cachedSensWords())
	if sd, err := json.Marshal(st); err == nil {
		e.store.SetSetting(sensSubStateKey, string(sd))
	}
}

// sanitizeSensSubLists 启动清理：剔除历史存量词表中的单字/超长词条
// （解析器加过滤规则前入库的），使检测词库即刻符合统一规则，无需重新拉取。
func (e *Engine) sanitizeSensSubLists() {
	removed := 0
	for _, key := range []string{sensSubWordsKey, sensSubDarkKey, sensSubCustomKey} {
		list := e.sensSubList(key)
		out := make([]string, 0, len(list))
		for _, w := range list {
			if weakness.ValidSensWord(w) {
				out = append(out, w)
				continue
			}
			removed++
		}
		if len(out) != len(list) {
			e.saveSensSubList(key, out)
		}
	}
	if removed > 0 {
		log.Printf("[敏感字订阅] 启动清理：剔除单字/超长词条 %d 个（统一规则：最短 2 字符）", removed)
		e.refreshSensCache()
	}
}

// ClearSensWords 清空词库：拉取/暗链/手工三份词表全部清空并刷新缓存（排除清单保留，
// 用户显式删除过的词在下次订阅更新时仍不会带回）。返回清空的生效词数。
func (e *Engine) ClearSensWords() int {
	n := len(e.cachedSensWords())
	e.saveSensSubList(sensSubWordsKey, nil)
	e.saveSensSubList(sensSubDarkKey, nil)
	e.saveSensSubList(sensSubCustomKey, nil)
	e.refreshSensCache()
	log.Printf("[敏感字订阅] 词库已清空（%d 词；排除清单保留 %d 条）", n, len(e.sensSubList(sensSubExclKey)))
	events.Publish("assets")
	return n
}

// DiscoverSubFiles 自动发现 GitHub 订阅源内的 .txt 词库文件（tree API 直连失败走镜像重试）。
// 返回按路径排序的相对路径清单，供界面勾选导入；非 GitHub 源返回错误（自定义 raw 源需手工填路径）。
func (e *Engine) DiscoverSubFiles(base string) ([]string, error) {
	api := weakness.GitHubTreeAPI(base)
	if api == "" {
		return nil, errors.New("仅支持 GitHub 仓库源自动发现（github.com / raw.githubusercontent.com）；自定义源请手工添加文件路径")
	}
	mirror := e.sensSubConfig().Mirror
	body, _, err := sensSubFetch(30, mirror, api)
	if err != nil {
		return nil, fmt.Errorf("获取仓库文件列表失败: %w", err)
	}
	var tr struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		return nil, fmt.Errorf("文件列表解析失败: %w", err)
	}
	out := []string{}
	for _, it := range tr.Tree {
		if it.Type != "blob" || !strings.HasSuffix(strings.ToLower(it.Path), ".txt") {
			continue
		}
		if strings.HasPrefix(it.Path, ".") || strings.Contains(it.Path, "/.") {
			continue // 跳过 .github 等元数据目录
		}
		out = append(out, it.Path)
	}
	sort.Strings(out)
	return out, nil
}

// SensWordItem 词条 + 来源（pull=订阅拉取 / custom=手工补充）
type SensWordItem struct {
	Word   string `json:"word"`
	Origin string `json:"origin"`
}

// SensWordsPage 词库管理页：词条分页 + 三类词量统计
type SensWordsPage struct {
	Items     []SensWordItem `json:"items"`
	Total     int            `json:"total"`    // 匹配（或全部）词条数
	Pull      int            `json:"pull"`     // 订阅拉取词条数（排除前）
	Custom    int            `json:"custom"`   // 手工补充词条数
	Excluded  int            `json:"excluded"` // 排除词条数
	Effective int            `json:"effective"` // 生效词条数
}

// SensSubWords 已入库词条搜索（大小写不敏感包含匹配，分页返回，附来源与各类词量统计）
func (e *Engine) SensSubWords(q string, offset, limit int) SensWordsPage {
	words := e.cachedSensWords()
	origin := map[string]string{}
	for _, w := range e.sensSubList(sensSubWordsKey) {
		origin[w] = "pull"
	}
	for _, w := range e.sensSubList(sensSubCustomKey) {
		if _, pulled := origin[w]; !pulled {
			origin[w] = "custom" // 同词既在拉取又在手工时来源记拉取
		}
	}
	q = strings.ToLower(strings.TrimSpace(q))
	matched := make([]string, 0, len(words))
	for _, w := range words {
		if q == "" || strings.Contains(strings.ToLower(w), q) {
			matched = append(matched, w)
		}
	}
	total := len(matched)
	items := []SensWordItem{}
	if offset >= 0 && offset < total {
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		end := offset + limit
		if end > total {
			end = total
		}
		for _, w := range matched[offset:end] {
			o := origin[w]
			if o == "" {
				o = "pull"
			}
			items = append(items, SensWordItem{Word: w, Origin: o})
		}
	}
	pull := e.sensSubList(sensSubWordsKey)
	custom := e.sensSubList(sensSubCustomKey)
	return SensWordsPage{Items: items, Total: total,
		Pull: len(pull), Custom: len(custom), Excluded: len(e.sensSubList(sensSubExclKey)), Effective: len(words)}
}

// ExcludedSensWords 排除清单（被删除的词条）搜索，附总数
func (e *Engine) ExcludedSensWords(q string) ([]string, int) {
	q = strings.ToLower(strings.TrimSpace(q))
	out := []string{}
	for _, w := range e.sensSubList(sensSubExclKey) {
		if q == "" || strings.Contains(strings.ToLower(w), q) {
			out = append(out, w)
		}
	}
	return out, len(e.sensSubList(sensSubExclKey))
}

// RestoreSensWords 恢复排除词条：仅移出排除清单（词条经下次订阅更新或手工新增回到生效词表），
// 返回移出数量。
func (e *Engine) RestoreSensWords(words []string) int {
	set := map[string]bool{}
	for _, w := range words {
		if w = strings.TrimSpace(w); w != "" {
			set[w] = true
		}
	}
	if len(set) == 0 {
		return 0
	}
	ex := e.sensSubList(sensSubExclKey)
	rest := make([]string, 0, len(ex))
	n := 0
	for _, w := range ex {
		if set[w] {
			n++
			continue
		}
		rest = append(rest, w)
	}
	if n == 0 {
		return 0
	}
	e.saveSensSubList(sensSubExclKey, rest)
	e.refreshSensCache()
	log.Printf("[敏感字订阅] 恢复排除词条 %d 个", n)
	return n
}

// AddSensSubWords 手工补充词条：并入手工清单并从排除清单移出（如曾被删）。
// 逐词校验（统一规则：最短 2 字符、上限 60，单字词不入检测词库），返回实际新增数。
func (e *Engine) AddSensSubWords(words []string) int {
	cur := map[string]bool{}
	for _, w := range e.sensSubList(sensSubCustomKey) {
		cur[w] = true
	}
	added := 0
	for _, w := range words {
		w = strings.TrimSpace(w)
		if !weakness.ValidSensWord(w) || cur[w] {
			continue
		}
		cur[w] = true
		added++
	}
	if added == 0 {
		return 0
	}
	list := make([]string, 0, len(cur))
	for w := range cur {
		list = append(list, w)
	}
	sort.Strings(list)
	e.saveSensSubList(sensSubCustomKey, list)
	// 手工词从排除清单移出，立即生效
	if ex := e.sensSubList(sensSubExclKey); len(ex) > 0 {
		exSet := map[string]bool{}
		for _, w := range words {
			exSet[strings.TrimSpace(w)] = true
		}
		rest := make([]string, 0, len(ex))
		for _, w := range ex {
			if !exSet[w] {
				rest = append(rest, w)
			}
		}
		e.saveSensSubList(sensSubExclKey, rest)
	}
	e.refreshSensCache()
	log.Printf("[敏感字订阅] 手工补充词条 %d 个", added)
	return added
}

// DeleteSensSubWords 删除词条：仅记入排除清单（拉取/手工清单保持原样，由 refreshSensCache 统一压制），
// 这样恢复（移出排除）时两类词条都能立即回到生效词表。返回从生效词表移除的数量。
func (e *Engine) DeleteSensSubWords(words []string) int {
	delSet := map[string]bool{}
	for _, w := range words {
		if w = strings.TrimSpace(w); w != "" {
			delSet[w] = true
		}
	}
	if len(delSet) == 0 {
		return 0
	}
	// 排除清单合并（去重）
	exSet := map[string]bool{}
	ex := e.sensSubList(sensSubExclKey)
	for _, w := range ex {
		exSet[w] = true
	}
	for w := range delSet {
		if !exSet[w] {
			exSet[w] = true
			ex = append(ex, w)
		}
	}
	e.saveSensSubList(sensSubExclKey, ex)
	before := len(e.cachedSensWords())
	e.refreshSensCache()
	removed := before - len(e.cachedSensWords())
	log.Printf("[敏感字订阅] 删除词条 %d 个（已记入排除清单，更新不带回）", removed)
	return removed
}

// sensSubFetch 订阅文件/清单拉取：直连（不走全局代理——订阅属平台自身出站而非目标扫描，
// 同空间测绘约定），直连失败且配置了镜像前缀时再经镜像重试一次。编码归一交给 ParseLexicon。
func sensSubFetch(timeoutSec int, mirror, u string) (body, contentType string, err error) {
	fetch := func(target string) (string, string, error) {
		client := netproxy.NewDirectHTTPClient(timeoutSec, 3)
		req, ferr := http.NewRequest("GET", target, nil)
		if ferr != nil {
			return "", "", ferr
		}
		ua.Apply(req)
		resp, ferr := client.Do(req)
		if ferr != nil {
			return "", "", ferr
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 单文件 4MB 上限
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return string(b), resp.Header.Get("Content-Type"), nil
	}
	if body, contentType, err = fetch(u); err == nil {
		return body, contentType, nil
	}
	if m := strings.TrimRight(mirror, "/"); m != "" {
		return fetch(m + "/" + u)
	}
	return "", "", err
}

// UpdateSensSub 立即拉取全部勾选词库：解析去重后词表与状态入库、刷新缓存。
// 任一文件失败不中断其余文件，状态记录失败明细（LastOK=false）。
func (e *Engine) UpdateSensSub() weakness.SubState {
	e.subUpdMu.Lock()
	defer e.subUpdMu.Unlock()

	cfg := e.sensSubConfig()
	var words []string
	var darkWords []string
	errs := []string{}
	fc := map[string]int{}
	for _, f := range cfg.Files {
		if !f.Enabled {
			continue
		}
		body, ct, err := sensSubFetch(60, cfg.Mirror, rawURL(cfg.Base, f.Path))
		if err != nil {
			errs = append(errs, f.Name+": "+err.Error())
			log.Printf("[敏感字订阅] 拉取失败 %s: %v", f.Name, err)
			continue
		}
		ws := weakness.ParseLexicon(ct, body)
		fc[f.Name] = len(ws)
		words = append(words, ws...)
		if f.ForDark {
			darkWords = append(darkWords, ws...)
		}
	}
	// 拉取词表剔除排除清单（用户删除过的词不带回）后整体覆盖
	exSet := map[string]bool{}
	for _, w := range e.sensSubList(sensSubExclKey) {
		exSet[w] = true
	}
	filter := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, w := range in {
			if !exSet[w] {
				out = append(out, w)
			}
		}
		return out
	}
	words = filter(weakness.MergeSensWords(nil, words))
	darkWords = filter(weakness.MergeSensWords(nil, darkWords))
	e.saveSensSubList(sensSubWordsKey, words)
	e.saveSensSubList(sensSubDarkKey, darkWords)
	e.refreshSensCache()
	st := weakness.SubState{
		LastUpdate: store.NowLocal(),
		LastOK:     len(errs) == 0 && len(words) > 0,
		WordCount:  len(e.cachedSensWords()),
		FileCount:  fc,
		Errors:     errs,
	}
	if sd, err := json.Marshal(st); err == nil {
		e.store.SetSetting(sensSubStateKey, string(sd))
	}
	log.Printf("[敏感字订阅] 更新完成：生效 %d 词（%d/%d 个文件成功）", st.WordCount, len(fc), len(cfg.Files)-len(errs))
	events.Publish("assets") // 词表变化影响后续弱点检测，触发面板刷新
	return st
}

// sensSubLoop 每日自动更新：到设定时刻且当日未更新过则拉取（失败也记录当日已尝试，次日再试）
func (e *Engine) sensSubLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopPoll:
			return
		case <-ticker.C:
			cfg := e.sensSubConfig()
			if !cfg.AutoUpdate {
				continue
			}
			var st weakness.SubState
			if saved, _ := e.store.GetSetting(sensSubStateKey); saved != "" {
				json.Unmarshal([]byte(saved), &st)
			}
			now := store.NowLocal() // 平台统一 CST 墙钟串 "2006-01-02 15:04:05"
			if len(now) >= 16 && len(st.LastUpdate) >= 16 && now[:10] == st.LastUpdate[:10] {
				continue // 今日已更新/已尝试
			}
			want := strings.TrimSpace(cfg.UpdateTime)
			if len(want) != 5 || now[11:16] < want {
				continue // 未到更新时刻（HH:MM 零填充，字典序即时间序）
			}
			log.Printf("[敏感字订阅] 每日自动更新触发（%s）", want)
			e.UpdateSensSub()
		}
	}
}
