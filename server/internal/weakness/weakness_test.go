package weakness

import (
	"strings"
	"sync"
	"testing"
)

const page = `<!DOCTYPE html><html><body>
<div style="display:none"><a href="https://casino-evil.example.com/bet">澳门威尼斯人赌场</a></div>
<div style="visibility:hidden"><a href="https://quiet-contact.example.com">联系方式</a></div>
<a href="/about">关于我们</a>
<a href="/broken-page">失效页面</a>
<a href="https://partner.normal.example.com">正常合作外链</a>
<a href="https://bet-lottery.example.cn">彩票投注网</a>
<p>本站提供在线赌博与代开发票服务，欢迎咨询。</p>
</body></html>`

func TestExtractAndClassify(t *testing.T) {
	st := DefaultSettings()
	links, text := ExtractLinks("http://site.example.com/index.html", page)
	if len(links) != 6 {
		t.Fatalf("links=%d want 6: %+v", len(links), links)
	}
	// 隐藏外链（display:none 祖先）
	var dark *Link
	for i := range links {
		if links[i].Hidden && strings.Contains(links[i].URL, "casino-evil") {
			dark = &links[i]
			break
		}
	}
	if dark == nil || !strings.Contains(dark.URL, "casino-evil") {
		t.Fatalf("hidden link not detected: %+v", links)
	}
	if dark.Inner {
		t.Fatalf("casino link should be external")
	}
	// 内链识别
	if !links[2].Inner || links[2].URL != "http://site.example.com/about" {
		t.Fatalf("relative link not resolved: %+v", links[2])
	}
	fs := Classify("http://site.example.com", links, text, st)
	kinds := map[string]int{}
	byURL := map[string]Finding{}
	for _, f := range fs {
		kinds[f.Type]++
		byURL[f.URL] = f
	}
	if kinds["darklink"] != 3 { // 隐藏命中词库 + 隐藏待核验 + 可见关键词外链
		t.Fatalf("darklink=%d %+v", kinds["darklink"], fs)
	}
	// 隐藏且锚文本命中词库：直接报，无需核验
	if f := byURL["https://casino-evil.example.com/bet"]; f.NeedsVerify || !strings.Contains(f.Detail, "隐藏展示且命中") {
		t.Fatalf("hidden kw-hit should report without verify: %+v", f)
	}
	// 隐藏但锚文本/URL 未命中词库：需目标页内容核验
	if f := byURL["https://quiet-contact.example.com"]; !f.NeedsVerify {
		t.Fatalf("hidden no-kw should need verify: %+v", f)
	}
	// 可见外链锚文本命中词库：直接报
	if f := byURL["https://bet-lottery.example.cn"]; f.NeedsVerify {
		t.Fatalf("visible kw-hit should not need verify: %+v", f)
	}
	if kinds["sensword"] < 2 { // 赌博 + 代开发票
		t.Fatalf("sensword=%d", kinds["sensword"])
	}
	if kinds["sensword"] > 0 {
		for _, f := range fs {
			if f.Type == "sensword" && !strings.Contains(f.Evidence, "…") == false && f.Evidence == "" {
				t.Fatalf("sensword evidence empty")
			}
		}
	}
	// 正常外链不应报暗链
	for _, f := range fs {
		if f.Type == "darklink" && strings.Contains(f.URL, "partner.normal") {
			t.Fatalf("normal external link misclassified")
		}
	}
}

// 坏链误报控制：404 报、网络失败重试成功不报、重试仍失败不报（无法验证）、
// DNS 域名不存在报"域名无法解析"、忽略域名不请求
func TestCheckBroken(t *testing.T) {
	links := []Link{
		{URL: "http://x/ok", Inner: true},
		{URL: "http://x/404", Inner: true},
		{URL: "http://x/flaky", Inner: true},             // 首次网络失败，重试成功 → 不报
		{URL: "http://x/timeout", Inner: true},           // 重试仍失败 → 不报
		{URL: "http://dead.example.com/", Inner: false},  // DNS 域名不存在 → 报
		{URL: "http://beian.miit.gov.cn/", Inner: false}, // 忽略域名 → 不请求
		{URL: "http://www.beian.gov.cn/x", Inner: false}, // 忽略域名子域 → 不请求
	}
	var mu sync.Mutex
	calls := map[string]int{}
	out, stats := CheckBroken(links, Settings{MaxLinks: 10, BrokenIgnoreHosts: []string{"beian.miit.gov.cn", "beian.gov.cn"}},
		func(u string) (int, int) {
			mu.Lock()
			calls[u]++
			n := calls[u]
			mu.Unlock()
			switch u {
			case "http://x/ok":
				return 200, FetchOK
			case "http://x/404":
				return 404, FetchOK
			case "http://x/flaky":
				if n == 1 {
					return 0, FetchFail
				}
				return 200, FetchOK
			case "http://x/timeout":
				return 0, FetchFail
			case "http://dead.example.com/":
				return 0, FetchDead
			}
			return 0, FetchFail
		})
	byURL := map[string]Finding{}
	for _, f := range out {
		byURL[f.URL] = f
	}
	if len(out) != 2 {
		t.Fatalf("findings=%d want 2 (404 + dead domain): %+v", len(out), out)
	}
	if f := byURL["http://x/404"]; f.Type != "brokenlink" || f.StatusCode != 404 || f.Severity != "low" {
		t.Fatalf("404 finding: %+v", f)
	}
	dead := byURL["http://dead.example.com/"]
	if dead.Detail == "" || dead.Severity != "medium" || dead.StatusCode != 0 {
		t.Fatalf("dead-domain finding: %+v", dead)
	}
	if _, reported := byURL["http://x/timeout"]; reported {
		t.Fatalf("unverified link should not be reported")
	}
	if _, reported := byURL["http://x/flaky"]; reported {
		t.Fatalf("flaky link (retry ok) should not be reported")
	}
	if stats.Unverified != 1 || stats.Ignored != 2 || stats.Dead != 1 || stats.Broken != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if calls["http://x/flaky"] != 2 || calls["http://x/timeout"] != 2 {
		t.Fatalf("network-failure links should be retried once: %+v", calls)
	}
	if _, probed := calls["http://beian.miit.gov.cn/"]; probed {
		t.Fatalf("ignored host should not be probed")
	}
	if _, probed := calls["http://www.beian.gov.cn/x"]; probed {
		t.Fatalf("ignored host subdomain should not be probed")
	}
}

func TestHostIgnored(t *testing.T) {
	hosts := []string{"beian.miit.gov.cn", ".example.gov.cn"}
	for _, u := range []string{
		"http://beian.miit.gov.cn/",
		"https://www.beian.miit.gov.cn/portal", // 子域
		"http://a.b.example.gov.cn/x",
	} {
		if !hostIgnored(u, hosts) {
			t.Fatalf("%s should be ignored", u)
		}
	}
	for _, u := range []string{
		"http://notbeian.miit.gov.cn/", // 前缀相似但标签边界不同
		"http://miit.gov.cn/",
		"http://gov.cn/",
	} {
		if hostIgnored(u, hosts) {
			t.Fatalf("%s should not be ignored", u)
		}
	}
	if hostIgnored("http://x/", nil) {
		t.Fatalf("empty list should ignore nothing")
	}
}

func TestHiddenStyleVariants(t *testing.T) {
	for _, st := range []string{"display: none", "visibility:HIDDEN", "opacity:0.0", "font-size:0px", "position:absolute;left:-9999px"} {
		if !hiddenStyle(st) {
			t.Fatalf("%q should be hidden", st)
		}
	}
	for _, st := range []string{"color:red", "display:block", ""} {
		if hiddenStyle(st) {
			t.Fatalf("%q should not be hidden", st)
		}
	}
}

// 暗链目标页内容核验：标题/正文命中词库、script/style 不参与、未命中与空响应
func TestVerifyDarkBody(t *testing.T) {
	st := DefaultSettings()
	evil := `<!DOCTYPE html><html><head><title>正规站点</title><style>.x{color:red}</style></head><body>
<script>var kw = "赌博";</script><p>欢迎访问，我们提供 博彩 娱乐服务。</p></body></html>`
	v := VerifyDarkBody(200, evil, st)
	if v.HitKw == "" {
		t.Fatalf("body kw should hit: %+v", v)
	}
	if v.Title != "正规站点" || v.Code != 200 || v.Snippet == "" {
		t.Fatalf("verify fields: %+v", v)
	}
	if strings.Contains(v.Snippet, "var kw") || strings.Contains(v.Snippet, "color:red") {
		t.Fatalf("script/style leaked into snippet: %q", v.Snippet)
	}

	titleHit := `<!DOCTYPE html><html><head><title>澳门赌场线上投注</title></head><body>normal</body></html>`
	if v := VerifyDarkBody(200, titleHit, st); v.HitKw == "" || !strings.Contains(v.Snippet, "澳门赌场线上投注") {
		t.Fatalf("title hit: %+v", v)
	}

	clean := `<!DOCTYPE html><html><head><title>联系页面</title></head><body>客服电话与邮箱</body></html>`
	if v := VerifyDarkBody(200, clean, st); v.HitKw != "" || v.Snippet != "" {
		t.Fatalf("clean page should not hit: %+v", v)
	}
	if v := VerifyDarkBody(0, "", st); v.HitKw != "" || v.Title != "" {
		t.Fatalf("empty body (unreachable) should not hit: %+v", v)
	}
}
