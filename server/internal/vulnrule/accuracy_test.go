package vulnrule

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBaselineRejectsCDNUniformPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>Welcome</title></head><body><p>Welcome to our service. This is the default page for all requests.</p></body></html>"))
	}))
	defer srv.Close()

	r, _ := ParseFile("cdn.yaml", []byte(`
id: cdn-fp-test
info:
  name: CDN FP Test
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-admin/setup-config.php"
    matchers:
      - type: word
        words:
          - "Welcome"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if res.Matched {
		t.Fatalf("CDN统一页面不应命中: %+v", res)
	}
}

func TestBaselineAllowsRealVuln(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("<html><body>Admin Console - Version 4.2.1 - Debug mode enabled. Current user: admin (administrator role). System configuration panel with sensitive data exposed."))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}))
	defer srv.Close()

	r, _ := ParseFile("real.yaml", []byte(`
id: real-vuln-test
info:
  name: Real Vuln Test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: word
        words:
          - "Admin Console"
        internal: true
`))
	res := Run(r, srv.URL, 5)
	if !res.Matched {
		t.Fatalf("真实漏洞应命中: %+v", res)
	}
}

func TestSPAPageDetection(t *testing.T) {
	spa := `<html><head><noscript>Enable JavaScript</noscript></head><body><div id="root"></div></body></html>`
	if !strings.Contains(spa, "<div id=") {
		t.Fatal("SPA 检测失败")
	}
}
