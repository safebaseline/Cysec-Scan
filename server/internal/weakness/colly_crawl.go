package weakness

import (
	"net/http"
	"path"
	"strings"

	"cysec/internal/charset"

	"github.com/PuerkitoBio/goquery"
	"github.com/gocolly/colly/v2"
	"golang.org/x/net/html"
)

// Page 单页爬取结果（全站爬取的组成单元）
type Page struct {
	URL     string // 页面绝对 URL
	Title   string // <title>（入库 page_title）
	Code    int    // HTTP 状态码（2xx/3xx 视为"已验证可达"，引擎据此跳过坏链探测；404 页不算）
	Links   []Link // 页面内全部超链接（含外链；坏链/暗链检测输入）
	Text    string // 摘除 script/style 后的正文（敏感字检测输入）
	SPAHint bool   // 页面无 <a href> 但引用了 JS 脚本——疑似纯前端渲染站点，静态爬取看不到其真实页面
}

// CrawlPage 基于 colly 的单页抓取：拉取一页并提取标题、全部超链接与正文文本。
// 传输由调用方注入（引擎传代理感知 client 与全局 UA 头）；Link 携带隐藏检测、锚文本与引用位置
// （祖先链 + <a> 标签 HTML 片段）。javascript:/mailto:/tel:/# 链接忽略。
func CrawlPage(pageURL string, hc *http.Client, headers map[string]string) Page {
	var p Page
	p.URL = pageURL
	c := colly.NewCollector()
	if hc == nil {
		hc = directClient()
	}
	c.SetClient(hc)
	if len(headers) > 0 {
		hdr := http.Header{}
		for k, v := range headers {
			hdr.Set(k, v)
		}
		c.Headers = &hdr
	}
	var tb strings.Builder
	c.OnResponse(func(r *colly.Response) {
		p.Code = r.StatusCode
		// 字符集归一：GBK/GB18030 中文站点直接按 UTF-8 解析会乱码入库（与 restrictedDoer 同口径）
		body := charset.Normalize(r.Body, contentTypeOf(r))
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			return
		}
		p.Title = truncate(strings.TrimSpace(doc.Find("title").First().Text()), 120)
		doc.Find("a[href]").Each(func(_ int, sel *goquery.Selection) {
			node := sel.Get(0)
			if node == nil {
				return
			}
			href, _ := sel.Attr("href")
			if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "#") ||
				strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "tel:") {
				return
			}
			abs := absURL(r, href)
			if abs == "" {
				return
			}
			p.Links = append(p.Links, Link{
				URL:     abs,
				Anchor:  truncate(strings.TrimSpace(sel.Text()), 80),
				Hidden:  hiddenStyle(styleOf(sel)) || inheritedHidden(node),
				Inner:   hostOf(abs) == hostOf(pageURL),
				Context: truncate(nodeAncestorChain(node, "")+" ▸ "+renderNodeHTML(node), 400),
			})
		})
		// SPA 识别（须在摘除 script 节点前判定）：无任何 <a href> 导航但引用了 JS——
		// 页面/链接由脚本在浏览器中动态生成
		if len(p.Links) == 0 && doc.Find("script[src]").Length() > 0 {
			p.SPAHint = true
		}
		doc.Find("script,style,noscript").Each(func(_ int, sel *goquery.Selection) {
			sel.Remove() // 从 DOM 摘除脚本/样式后再取正文，保证敏感字文本纯净
		})
		tb.WriteString(doc.Text())
	})
	_ = c.Visit(pageURL) // 抓取失败（超时/非 2xx 由 OnResponse 状态码区分）返回空 Page，调用方按空页处理
	p.Text = tb.String()
	return p
}

// CrawlSite 全站爬取：从站点入口沿同站内链 BFS 逐页抓取，覆盖站点全部可达页面。
// 仅跟随与入口同 host 的页面型链接（图片/样式/脚本等资源扩展名与外链不进队列），
// URL 按去锚点/去尾斜杠归一后去重；maxPages 限制抓取页数（<=0 取 50），
// stop 返回 true 时立即终止（任务取消）。抓取失败的页面跳过（其链接不入队）。
func CrawlSite(entryURL string, hc *http.Client, headers map[string]string, maxPages int, stop func() bool) []Page {
	if maxPages <= 0 {
		maxPages = 50
	}
	if hc == nil {
		hc = directClient()
	}
	visited := map[string]bool{PageKey(entryURL): true}
	queue := []string{entryURL}
	pages := []Page{}
	for len(queue) > 0 && len(pages) < maxPages {
		if stop != nil && stop() {
			break
		}
		u := queue[0]
		queue = queue[1:]
		p := CrawlPage(u, hc, headers)
		// 仅收录成功响应（2xx/3xx）且有检测输入的页面；错误状态页（如 404 兜底页）
		// 不算"已验证可达"，留给坏链探测判定，其链接也不入队
		if p.Code < 200 || p.Code >= 400 || (len(p.Links) == 0 && strings.TrimSpace(p.Text) == "") {
			continue
		}
		pages = append(pages, p)
		for _, l := range p.Links {
			if !l.Inner || !isPageLike(l.URL) {
				continue
			}
			if k := PageKey(l.URL); !visited[k] {
				visited[k] = true
				queue = append(queue, l.URL)
			}
		}
	}
	return pages
}

// contentTypeOf 从 colly 响应取 Content-Type（头 map 形式）
func contentTypeOf(r *colly.Response) string {
	if v := r.Headers.Get("Content-Type"); v != "" {
		return v
	}
	return ""
}

// directClient 兜底直连（不读系统/环境代理），与引擎注入的代理感知 client 语义一致
func directClient() *http.Client {
	return &http.Client{Timeout: 15 * 1e9, Transport: &http.Transport{Proxy: nil}}
}

// assetExts 不作为页面抓取的资源扩展名（坏链检测仍会探测这些链接）
var assetExts = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".bmp": true,
	".svg": true, ".ico": true, ".css": true, ".js": true, ".mjs": true, ".map": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true, ".flv": true, ".wmv": true,
	".zip": true, ".rar": true, ".7z": true, ".tar": true, ".gz": true, ".bz2": true,
	".exe": true, ".msi": true, ".apk": true, ".dmg": true, ".iso": true,
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".pdf": true, ".xml": true, ".txt": true,
}

// isPageLike 是否为可继续抓取的页面链接（http/https 且非资源扩展名）
func isPageLike(u string) bool {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return false
	}
	p := u
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return !assetExts[strings.ToLower(path.Ext(p))]
}

// PageKey URL 归一化去重键：去锚点 + 去尾斜杠（引擎复用：剔除爬虫已验证可达的页面）
func PageKey(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u = u[:i]
	}
	return strings.TrimSuffix(u, "/")
}

// absURL 复用 colly 的 URL 绝对化（Request 上下文基于访问页 URL）
func absURL(r *colly.Response, href string) string {
	req := r.Request
	if req == nil {
		return href
	}
	return req.AbsoluteURL(href)
}

func styleOf(sel *goquery.Selection) string {
	v, _ := sel.Attr("style")
	return v
}

// inheritedHidden 向上检查祖先 style 的隐藏样式（display:none 等）
func inheritedHidden(n *html.Node) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type != html.ElementNode {
			continue
		}
		if hiddenStyle(attrValue(p, "style")) {
			return true
		}
	}
	return false
}

// nodeAncestorChain 从当前节点向上构建祖先链（tag#id.class，最外层在前，含 style 隐藏标记）
func nodeAncestorChain(n *html.Node, chain string) string {
	if n == nil || n.Type != html.ElementNode {
		return chain
	}
	seg := n.Data
	if id := attrValue(n, "id"); id != "" {
		seg += "#" + id
	}
	if cl := attrValue(n, "class"); cl != "" {
		seg += "." + strings.Join(strings.Fields(cl), ".")
	}
	if chain == "" {
		chain = seg
	} else {
		chain = seg + " < " + chain
	}
	if len(chain) > 200 {
		return chain
	}
	return nodeAncestorChain(n.Parent, chain)
}

func attrValue(n *html.Node, key string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

// renderNodeHTML 渲染节点为 HTML 片段（引用位置展示）
func renderNodeHTML(n *html.Node) string {
	if n == nil {
		return ""
	}
	var b strings.Builder
	_ = html.Render(&b, n)
	return b.String()
}
