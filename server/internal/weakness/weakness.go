// Package weakness 弱点管理检测：网站链接爬取（HTML 解析）、暗链识别（隐藏展示/暗链词库/
// 目标页内容核验）、坏链检测（HTTP 状态/可达性）、敏感字检测（页面文本词库命中）。
// 词库与开关由界面配置（settings 表 weakness_settings），未启用则跳过。
package weakness

import (
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Settings 弱点检测配置（界面可编辑）
type Settings struct {
	Enabled            bool     `json:"enabled"`              // 扫描时执行弱点检测
	MaxPages           int      `json:"max_pages"`            // 每站点最大爬取页面数（同站内链 BFS 全站爬取）
	MaxLinks           int      `json:"max_links"`            // 每站点最多检查的链接数（含内链外链）
	DarkVerifyDisabled bool     `json:"dark_verify_disabled"` // 关闭暗链目标内容核验（隐藏外链不请求目标页直接报，旧行为）
	DarkKeywords       []string `json:"dark_keywords"`        // 暗链关键词（锚文本/域名/目标页内容命中 → 暗链）
	SensitiveWords     []string `json:"sensitive_words"`      // 页面敏感字词库
	BrokenIgnoreHosts  []string `json:"broken_ignore_hosts"`  // 坏链忽略域名（后缀匹配；备案站等 WAF 域名不探测）
}

// DefaultSettings 出厂配置（词库可在界面编辑/清空）
func DefaultSettings() Settings {
	// 注意两份词库必须是独立切片：共享底层数组时，json 反序列化会复用切片内存，
	// 先后解码 dark_keywords/sensitive_words 互相覆盖产生字段别名（暗链词=敏感字词）
	words := []string{
		"赌博", "博彩", "彩票", "六合彩", "私服", "澳门", "威尼斯人", "太阳城",
		"色情", " AV ", "一夜情", "约炮", "裸聊",
		"办证", "代开发票", "发票", "刷单", "套现", "贷款秒批", "无抵押贷款",
		"黑客", "外挂", "作弊器", "银商", "上下分",
	}
	return Settings{
		Enabled:           true,
		MaxPages:          50,
		MaxLinks:          50,
		DarkKeywords:      append([]string{}, words...),
		SensitiveWords:    append([]string{}, words...),
		BrokenIgnoreHosts: []string{"beian.miit.gov.cn", "beian.gov.cn"}, // 备案站 WAF 拦自动化请求，探测必"不可达"
	}
}

// Link 页面提取的链接
type Link struct {
	URL     string // 绝对化后的链接
	Anchor  string // 锚文本（截断）
	Hidden  bool   // 自身或祖先以隐藏样式展示（display:none / visibility:hidden / opacity:0 / font-size:0 / 绝对定位出屏）
	Inner   bool   // 同站点内链
	Context string // 引用位置：祖先链 + <a> 标签渲染片段（详情弹窗展示 URL 在页面何处被引用）
}

// Finding 弱点检测结果（引擎侧负责入库）
type Finding struct {
	Type        string // darklink / brokenlink / sensword
	URL         string
	Anchor      string
	StatusCode  int
	Detail      string
	Severity    string
	Evidence    string
	Context     string // 引用位置（链接类弱点）：祖先元素链 + 锚标签 HTML 片段
	NeedsVerify bool   // 暗链待核验：隐藏且锚文本/URL 未命中词库，需目标页内容命中关键词才报
}

// ExtractLinks 解析 HTML 提取链接与隐藏标记；同时返回剥离标签后的页面文本（敏感字用）
func ExtractLinks(pageURL, body string) (links []Link, text string) {
	if strings.TrimSpace(body) == "" {
		return nil, ""
	}
	node, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil, ""
	}
	base := hostOf(pageURL)
	var walk func(n *html.Node, hidden bool, chain string)
	var tb strings.Builder
	walk = func(n *html.Node, hidden bool, chain string) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				href := attrOf(n, "href")
				if href != "" && !strings.HasPrefix(href, "javascript:") && !strings.HasPrefix(href, "#") &&
					!strings.HasPrefix(href, "mailto:") && !strings.HasPrefix(href, "tel:") {
					abs := absolute(pageURL, href)
					if abs != "" {
						links = append(links, Link{
							URL:     abs,
							Anchor:  truncate(nodeText(n), 80),
							Hidden:  hidden || hiddenStyle(attrOf(n, "style")),
							Inner:   hostOf(abs) == base,
							Context: truncate(strings.Trim(chain, " >")+" ▸ "+renderNode(n), 400),
						})
					}
				}
			case "style", "script":
				return // 样式与脚本内容不进入文本
			}
			if n.Data == "div" || n.Data == "span" || n.Data == "section" || n.Data == "ul" || n.Data == "li" || n.Data == "p" || n.Data == "td" {
				hidden = hidden || hiddenStyle(attrOf(n, "style"))
			}
		}
		if n.Type == html.TextNode {
			tb.WriteString(n.Data)
			tb.WriteString(" ")
		}
		childChain := chain
		if n.Type == html.ElementNode && n.Data != "a" {
			childChain = truncate(strings.Trim(chain, " >")+" < "+n.Data+classChain(n), 200)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, hidden, childChain)
		}
	}
	walk(node, false, "")
	return links, tb.String()
}

// renderNode 渲染节点为 HTML 片段（引用位置展示用）
func renderNode(n *html.Node) string {
	var b strings.Builder
	_ = html.Render(&b, n)
	return b.String()
}

// classChain 元素的 class/id 简述（#id.class 形式）
func classChain(n *html.Node) string {
	out := ""
	if c := attrOf(n, "id"); c != "" {
		out += "#" + c
	}
	if cl := attrOf(n, "class"); cl != "" {
		out += "." + strings.Join(strings.Fields(cl), ".")
	}
	return out
}

// hiddenStyleRepos 隐藏样式判定：裸子串包含会把 opacity:0.5、font-size:0.9em、
// left:-99999px 等正常样式误判为隐藏（暗链误报源），改为边界感知匹配
var hiddenStyleRepos = []*regexp.Regexp{
	regexp.MustCompile(`display\s*:\s*none\b`),
	regexp.MustCompile(`visibility\s*:\s*hidden\b`),
	regexp.MustCompile(`opacity\s*:\s*0(\.0+)?\s*(;|!|$)`),
	regexp.MustCompile(`font-size\s*:\s*0(\.0+)?(px|em|rem|pt)?\s*(;|!|$)`),
	regexp.MustCompile(`filter\s*:\s*alpha\(opacity\s*=\s*0\s*\)`),
	regexp.MustCompile(`(?:left|top|margin-left|margin-top)\s*:\s*-(9999|99999)(px)?\b`),
	regexp.MustCompile(`position\s*:\s*absolute\s*;\s*left\s*:\s*-`),
}

// hiddenStyle 判断 style 属性是否为隐藏展示（暗链常见手法；边界感知，见 hiddenStyleRepos）
func hiddenStyle(style string) bool {
	s := strings.ToLower(strings.ReplaceAll(style, " ", ""))
	if s == "" {
		return false
	}
	for _, re := range hiddenStyleRepos {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// Classify 暗链/敏感字判定（不发起网络请求）；links 来自 ExtractLinks。
// 暗链三条路径：① 隐藏展示且锚文本/URL 命中词库 → 直接报（死站赌链不能漏）；
// ② 隐藏展示但未命中词库 → NeedsVerify（引擎请求目标页，内容命中暗链词库才报）；
// ③ 可见外链锚文本/URL 命中词库 → 直接报。
func Classify(pageURL string, links []Link, text string, st Settings) []Finding {
	out := []Finding{}
	for _, l := range links {
		if l.Inner {
			continue // 内链（含 display:none 的下拉菜单/标签页导航，站点极常见）不进入暗链判定：
			// 暗链语义为外部可疑链接，隐藏内链逐条核验只会产生误报与额外请求
		}
		kw := MatchDarkKeyword(l.Anchor+" "+l.URL, st)
		if l.Hidden {
			if kw != "" {
				out = append(out, Finding{Type: "darklink", URL: l.URL, Anchor: l.Anchor, Severity: "high",
					Detail: "隐藏展示且命中暗链关键词「" + kw + "」", Context: l.Context})
			} else {
				out = append(out, Finding{Type: "darklink", URL: l.URL, Anchor: l.Anchor, Severity: "high",
					Detail: "隐藏展示的外部/可疑链接（display:none 等隐藏样式，暗链典型手法）", Context: l.Context,
					NeedsVerify: true})
			}
			continue
		}
		if kw != "" {
			out = append(out, Finding{Type: "darklink", URL: l.URL, Anchor: l.Anchor, Severity: "high",
				Detail: "外链命中暗链关键词「" + kw + "」", Context: l.Context})
		}
	}
	for _, kw := range st.SensitiveWords {
		if kw == "" {
			continue
		}
		if i := strings.Index(strings.ToLower(text), strings.ToLower(kw)); i >= 0 {
			out = append(out, Finding{Type: "sensword", URL: pageURL + "#" + kw, Anchor: kw, Severity: "medium",
				Detail: "页面文本命中敏感字「" + kw + "」", Evidence: snippetAround(text, i)})
		}
	}
	return out
}

// MatchDarkKeyword 返回 s 中首个命中的暗链关键词（大小写不敏感包含匹配）
func MatchDarkKeyword(s string, st Settings) string {
	if s == "" {
		return ""
	}
	low := strings.ToLower(s)
	for _, kw := range st.DarkKeywords {
		if kw != "" && strings.Contains(low, strings.ToLower(kw)) {
			return kw
		}
	}
	return ""
}

// DarkVerify 暗链目标页核验结论（引擎注入抓取，匹配为纯函数）
type DarkVerify struct {
	Code    int    // 目标页状态码（不可达时 0）
	Title   string // 目标页 <title>
	HitKw   string // 目标页标题/正文命中的暗链关键词（空 = 未命中）
	Snippet string // 正文命中上下文片段（Evidence）
}

// VerifyDarkBody 对暗链目标页响应做二次词库匹配：标题或正文（摘除 script/style）
// 命中暗链关键词时给出命中词与上下文片段；body 为空（不可达/非文本）视为未命中
func VerifyDarkBody(code int, body string, st Settings) DarkVerify {
	v := DarkVerify{Code: code}
	if strings.TrimSpace(body) == "" {
		return v
	}
	title, text := PageTitleAndText(body)
	v.Title = truncate(strings.TrimSpace(title), 120)
	if kw := MatchDarkKeyword(title, st); kw != "" {
		v.HitKw = kw
		v.Snippet = "标题：" + v.Title
		return v
	}
	if kw := MatchDarkKeyword(text, st); kw != "" {
		v.HitKw = kw
		if i := strings.Index(strings.ToLower(text), strings.ToLower(kw)); i >= 0 {
			v.Snippet = snippetAround(text, i)
		}
	}
	return v
}

// PageTitleAndText 解析 HTML 的 <title> 与正文文本（script/style/noscript 摘除）
func PageTitleAndText(body string) (title, text string) {
	node, err := html.Parse(strings.NewReader(body))
	if err != nil || node == nil {
		return "", ""
	}
	var tb, tbb strings.Builder
	titleDone := false // 只取首个 title（svg 图标 title/异常多 title 会污染页面标题）
	var walk func(n *html.Node, inTitle bool)
	walk = func(n *html.Node, inTitle bool) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "noscript":
				return
			case "title":
				if titleDone {
					return
				}
				titleDone = true
			}
		}
		isTitle := inTitle || (n.Type == html.ElementNode && n.Data == "title")
		if n.Type == html.TextNode {
			if isTitle {
				tbb.WriteString(n.Data)
			} else {
				tb.WriteString(n.Data)
				tb.WriteString(" ")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, isTitle)
		}
	}
	walk(node, false)
	return tbb.String(), tb.String()
}

// snippetAround 提取 idx 附近的上下文片段（敏感字/暗链核验证据）
func snippetAround(text string, idx int) string {
	if len(text) <= 400 {
		return text
	}
	// 按 rune 对齐窗口边界（idx 来自 ToLower 后的匹配，字节偏移可能落在多字节字符中间，
	// 字符串切片不 panic 但会产生非法 UTF-8，经 []rune 转换兜底）
	lo, hi := idx-100, idx+200
	if lo < 0 {
		lo = 0
	}
	if hi > len(text) {
		hi = len(text)
	}
	loRunes := []rune(text[lo:idx])
	hiRunes := []rune(text[idx:hi])
	if len(loRunes) > 100 {
		loRunes = loRunes[len(loRunes)-100:]
	}
	if len(hiRunes) > 200 {
		hiRunes = hiRunes[:200]
	}
	return "…" + string(loRunes) + string(hiRunes) + "…"
}

// 坏链探测结果分类（fetch 返回）
const (
	FetchOK   = 0 // 收到 HTTP 响应
	FetchFail = 1 // 网络层失败（超时/连接拒绝/WAF 拦截等，无法验证链接是否失效）
	FetchDead = 2 // DNS 域名不存在（域名失效，明确死链）
)

// BrokenStats 坏链探测统计（任务日志输出）
type BrokenStats struct {
	Checked    int // 实际探测的链接数
	Ignored    int // 命中忽略域名跳过（备案站等）
	Unverified int // 网络失败重试仍失败，未报（误报控制：无法验证 ≠ 失效）
	Dead       int // 域名无法解析
	Broken     int // 明确 HTTP >=400 失效
}

// CheckBroken 坏链检测：并发探测每条链接（上限 st.MaxLinks 条）。
// 误报控制：① 命中 st.BrokenIgnoreHosts 的域名跳过（备案站等 WAF 域名探测必"不可达"）；
// ② 网络层失败（超时/拒绝/被拦）≠ 失效——延迟重试一次，仍失败不报；
// ③ DNS 域名不存在为明确死链，报"域名无法解析"；
// ④ 仅明确的 HTTP >=400 判坏链。fetch 由引擎注入（走全局代理、全局 UA 与来源页 Referer）。
func CheckBroken(links []Link, st Settings, fetch func(url string) (code int, errKind int)) ([]Finding, BrokenStats) {
	var stats BrokenStats
	out := []Finding{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	for _, l := range links {
		mu.Lock()
		if st.MaxLinks < 1 { // 限额由引擎归一（默认 50），此处仅防误配 0/负值死循环
			mu.Unlock()
			break
		}
		if stats.Checked >= st.MaxLinks {
			mu.Unlock()
			break
		}
		if hostIgnored(l.URL, st.BrokenIgnoreHosts) {
			stats.Ignored++
			mu.Unlock()
			continue
		}
		stats.Checked++
		mu.Unlock()
		wg.Add(1)
		go func(l Link) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			code, kind := fetch(l.URL)
			if kind == FetchFail {
				time.Sleep(500 * time.Millisecond)
				code, kind = fetch(l.URL) // 网络失败重试一次（并发压力/瞬时抖动/WAF 软限流）
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case kind == FetchDead:
				stats.Dead++
				out = append(out, Finding{Type: "brokenlink", URL: l.URL, Anchor: l.Anchor,
					Detail: "域名无法解析（域名失效，明确死链）", Severity: "medium", Context: l.Context})
			case kind == FetchFail:
				stats.Unverified++ // 无法验证：不报（超时/被 WAF 拦截不代表链接失效）
			case code >= 400:
				stats.Broken++
				detail := "链接返回 HTTP " + itoa(code)
				sev := "low"
				if code >= 500 {
					sev = "medium"
				}
				out = append(out, Finding{Type: "brokenlink", URL: l.URL, Anchor: l.Anchor, StatusCode: code, Detail: detail, Severity: sev, Context: l.Context})
			}
		}(l)
	}
	wg.Wait()
	return out, stats
}

// hostIgnored 链接 host 是否命中忽略清单（后缀匹配且标签边界：beian.miit.gov.cn 覆盖其子域）
func hostIgnored(u string, hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	h := hostOf(u)
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp // 显式端口形式（beian.miit.gov.cn:443）同样命中忽略清单
	}
	for _, raw := range hosts {
		p := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(raw), "."))
		if p == "" {
			continue
		}
		if h == p || strings.HasSuffix(h, "."+p) {
			return true
		}
	}
	return false
}

// ---------- 小工具 ----------

func attrOf(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
			b.WriteString(" ")
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

func hostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	return strings.ToLower(s)
}

func absolute(base, href string) string {
	h := href
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		return h
	}
	if strings.HasPrefix(h, "//") {
		if i := strings.Index(base, ":"); i > 0 {
			return base[:i] + ":" + h
		}
		return "http:" + h
	}
	b := base
	if i := strings.Index(b, "://"); i >= 0 {
		root := b[:i+3] + hostOf(b)
		if strings.HasPrefix(h, "/") {
			return root + h
		}
		if i := strings.LastIndex(b, "/"); i > len("https://")-1 {
			b = b[:i+1]
		} else {
			b = root + "/"
		}
		for strings.HasPrefix(h, "../") {
			h = h[3:]
			if i := strings.LastIndex(b[:len(b)-1], "/"); i >= 0 {
				b = b[:i+1]
			}
		}
		return b + h
	}
	return h
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
