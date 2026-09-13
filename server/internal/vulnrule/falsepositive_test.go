package vulnrule

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDslPassFilters403(t *testing.T) {
	// 模拟 WAF/CDN 返回 403 拦截页
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("Access Denied - You do not have permission to access this resource."))
	}))
	defer srv.Close()

	r, _ := ParseFile("fp.yaml", []byte(`
id: fp-403-test
info:
  name: FP 403 Test
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/something"
    matchers:
      - type: word
        words:
          - "anything"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if res.Matched {
		t.Fatalf("403 拦截页不应命中: %+v", res)
	}
}

func TestDslPassFilters404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("404 Not Found"))
	}))
	defer srv.Close()

	r, _ := ParseFile("fp404.yaml", []byte(`
id: fp-404
info:
  name: FP 404
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers:
      - type: word
        words:
          - "x"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if res.Matched {
		t.Fatalf("404 不应命中: %+v", res)
	}
}

func TestDslPassFiltersShortBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok")) // 只有2字节
	}))
	defer srv.Close()

	r, _ := ParseFile("fp-short.yaml", []byte(`
id: fp-short
info:
  name: FP Short
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "x"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if res.Matched {
		t.Fatalf("过短响应体不应命中: %+v", res)
	}
}

func TestDslPassFiltersWAFPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<html><body>Access Denied. Your request has been blocked by Web Application Firewall. Please complete the security check (captcha).</body></html>"))
	}))
	defer srv.Close()

	r, _ := ParseFile("fp-waf.yaml", []byte(`
id: fp-waf
info:
  name: FP WAF
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "x"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if res.Matched {
		t.Fatalf("WAF拦截页特征不应命中: %+v", res)
	}
}

func TestDslPassStillMatchesValidResponse(t *testing.T) {
	// 确保真实漏洞场景（200 + 足够长 + 与基线不同的响应体）仍然命中
	// 注意：真实漏洞页只出现在特定路径，随机路径应返回不同内容（404）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte(`<html><head><title>Admin Console</title></head><body>Welcome to the Admin Console. Version 4.2.1. User: admin. Role: administrator.</body></html>`))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	r, _ := ParseFile("fp-ok.yaml", []byte(`
id: fp-ok
info:
  name: Valid Match
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "Admin Console"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if !res.Matched {
		t.Fatalf("正常页面+足够内容应命中: %+v", res)
	}
}
