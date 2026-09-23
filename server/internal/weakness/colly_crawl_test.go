package weakness

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// colly 爬虫引擎单测：本地 httptest 靶站，验证链接提取（相对/绝对）、隐藏检测、
// 锚文本、内链判定、引用位置与正文提取（script/style 摘除）。
func TestCollyCrawlExtractsLinks(t *testing.T) {
	page := `<!DOCTYPE html><html><head><title>测试页</title><style>a{color:red}</style></head><body>
<div style="display:none"><a href="https://dark.example.com/bet">暗链锚文本</a></div>
<a href="/about">相对链接</a>
<a href="https://ext.example.com/x">外链</a>
<a href="javascript:alert(1)">js</a><a href="mailto:a@b.c">mail</a><a href="#">self</a>
<script>var x='脚本内容';</script>
<p>正文包含中文内容</p>
</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	}))
	defer srv.Close()

	p := CrawlPage(srv.URL, nil, map[string]string{"User-Agent": "cysec-test"})
	if p.Title != "测试页" {
		t.Fatalf("title extraction failed: %q", p.Title)
	}
	if !strings.Contains(p.Text, "正文包含中文内容") {
		t.Fatalf("text extraction failed: %q", p.Text)
	}
	if strings.Contains(p.Text, "脚本内容") || strings.Contains(p.Text, "color:red") {
		t.Fatalf("script/style leaked into text: %q", p.Text)
	}
	if len(p.Links) != 3 {
		t.Fatalf("want 3 links (js/mailto/# ignored), got %d: %+v", len(p.Links), p.Links)
	}
	byURL := map[string]Link{}
	for _, l := range p.Links {
		byURL[l.URL] = l
	}
	dark, ok := byURL["https://dark.example.com/bet"]
	if !ok || !dark.Hidden || dark.Inner {
		t.Fatalf("dark link: %+v", dark)
	}
	if dark.Anchor != "暗链锚文本" || dark.Context == "" || !strings.Contains(dark.Context, "div") {
		t.Fatalf("dark anchor/context: %+v", dark)
	}
	rel, ok := byURL[srv.URL+"/about"]
	if !ok || !rel.Inner {
		t.Fatalf("relative link not inner: %+v", p.Links)
	}
	ext, ok := byURL["https://ext.example.com/x"]
	if !ok || ext.Inner {
		t.Fatalf("external marked inner: %+v", p.Links)
	}
}

// 全站爬取：入口页沿同站内链 BFS 覆盖全部页面；资源扩展名/外链不入队；
// 同一 URL 去锚点/尾斜杠去重；maxPages 限制抓取页数。
func TestCrawlSiteWalksAllPages(t *testing.T) {
	pages := map[string]string{
		"/":            `<html><head><title>首页</title></head><body><a href="/about">关于</a> <a href="/news/">新闻</a> <a href="/style.css">样式</a> <a href="https://ext.example.com/">外站</a> <a href="/about#contact">锚点重复</a> <a href="/gone">失效页</a></body></html>`,
		"/about":       `<html><head><title>关于页</title></head><body><a href="/">返回首页</a> <a href="/news/list">新闻列表</a><p>关于我们 赌博</p></body></html>`,
		"/news/":       `<html><head><title>新闻页</title></head><body><a href="/news/detail?id=1">详情</a></body></html>`,
		"/news/list":   `<html><head><title>列表页</title></head><body>列表内容</body></html>`,
		"/news/detail": `<html><head><title>详情页</title></head><body>详情内容</body></html>`,
		"/style.css":   "body{}",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := pages[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found")) // 404 兜底页带正文：不应被收录为"已验证可达"页面
			return
		}
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	got := CrawlSite(srv.URL, nil, nil, 50, nil)
	byURL := map[string]Page{}
	for _, p := range got {
		byURL[p.URL] = p
	}
	root := strings.TrimSuffix(srv.URL, "/") // colly 将根路径 "/" 归一为无尾斜杠
	for _, want := range []string{root, root + "/about", root + "/news/", root + "/news/list", root + "/news/detail?id=1"} {
		if _, ok := byURL[want]; !ok {
			t.Fatalf("page %s not crawled; got %+v", want, pageURLs(got))
		}
	}
	if _, ok := byURL[root+"/style.css"]; ok {
		t.Fatalf("css asset should not be crawled as page")
	}
	if _, ok := byURL[root+"/gone"]; ok {
		t.Fatalf("404 fallback page should not be collected as verified page")
	}
	if byURL[root].Title != "首页" || byURL[root+"/about"].Title != "关于页" {
		t.Fatalf("per-page titles: %+v", got)
	}
	if !strings.Contains(byURL[root+"/about"].Text, "赌博") {
		t.Fatalf("per-page text missing: %+v", byURL[root+"/about"])
	}
	// 页数上限
	if capped := CrawlSite(srv.URL, nil, nil, 2, nil); len(capped) != 2 {
		t.Fatalf("maxPages=2 want 2 pages, got %d: %+v", len(capped), pageURLs(capped))
	}
	// 任务取消：立即停止
	if stopped := CrawlSite(srv.URL, nil, nil, 50, func() bool { return true }); len(stopped) != 0 {
		t.Fatalf("stopped crawl should return 0 pages, got %+v", pageURLs(stopped))
	}
}

func pageURLs(ps []Page) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.URL
	}
	return out
}

// SPA 站点识别：页面无 <a href> 但引用 JS 脚本（如 ai.hzpt.edu.cn 的 Vue 单页应用），
// 静态爬取只见入口页——SPAHint 标记供引擎输出提示日志，避免误判为爬虫故障
func TestCrawlPageSPAHint(t *testing.T) {
	spa := `<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8"/>
<title>杭科院AI资源中心</title>
<script type="module" crossorigin src="/assets/index-5vefajII.js"></script>
<link rel="stylesheet" href="/assets/index-Ci2FK6gS.css"/></head>
<body><div id="app"></div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(spa))
	}))
	defer srv.Close()

	p := CrawlPage(srv.URL, nil, nil)
	if !p.SPAHint {
		t.Fatalf("SPA 站点应标记 SPAHint: %+v", p)
	}
	if len(p.Links) != 0 || p.Title != "杭科院AI资源中心" {
		t.Fatalf("SPA 页面应 0 链接且保留标题: %+v", p)
	}
	pages := CrawlSite(srv.URL, nil, nil, 9999, nil)
	if len(pages) != 1 || !pages[0].SPAHint {
		t.Fatalf("全站爬取 SPA 应只有入口页且带标记: %+v", pageURLs(pages))
	}

	// 普通页面（有链接）不应误标
	normal := `<html><head><title>普通页</title><script src="/app.js"></script></head>
<body><a href="/x">链接</a></body></html>`
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path == "/x" {
			w.Write([]byte(`<html><head><title>x</title></head><body>ok</body></html>`))
			return
		}
		w.Write([]byte(normal))
	}))
	defer srv2.Close()
	if p2 := CrawlPage(srv2.URL, nil, nil); p2.SPAHint {
		t.Fatalf("含 <a href> 的页面不应标记 SPA: %+v", p2)
	}
}
