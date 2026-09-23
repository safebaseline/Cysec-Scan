package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// soft-404 基线：SPA/通配路由站点对任意路径返回同一 200 页面 → 基准 ok 且 200
func TestSoftBaselineProbe(t *testing.T) {
	ResetSoftBaselineCache()
	spa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>SPA 首页兜底内容</body></html>"))
	}))
	defer spa.Close()

	b := baselineOf(spa.URL, 3)
	if !b.ok || b.status != 200 || b.bodyFP == "" {
		t.Fatalf("SPA 站基准: %+v", b)
	}
	// 命中响应与基准一致（同页面）→ 判 soft-404
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>SPA 首页兜底内容</body></html>"
	if !isSoft404Response(resp, b) {
		t.Fatal("与基准一致的响应应判 soft-404")
	}
	// 真漏洞响应（不同内容）→ 不抑制
	real := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>phpPgAdmin login</body></html>"
	if isSoft404Response(real, b) {
		t.Fatal("真实漏洞响应不应被抑制")
	}
	// 非 200 基准（正常站返回 404）→ 不启用抑制
	ResetSoftBaselineCache()
	normal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Write([]byte("home"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("404 page"))
	}))
	defer normal.Close()
	b2 := baselineOf(normal.URL, 3)
	if !b2.ok || b2.status != 404 {
		t.Fatalf("正常站基准应为 404: %+v", b2)
	}
	if isSoft404Response("HTTP/1.1 200 OK\r\n\r\nhome", b2) {
		t.Fatal("404 基准站不应抑制")
	}
}

// 报文解析边界：裸 LF 头分隔、空正文不误判
func TestIsSoft404ResponseEdge(t *testing.T) {
	b := softBaseline{ok: true, status: 200, bodyFP: bodyFingerprint([]byte("X"))}
	if isSoft404Response("", b) {
		t.Fatal("空报文不判")
	}
	if !isSoft404Response("HTTP/1.1 200 OK\n\nX", b) {
		t.Fatal("裸 LF 分隔也应正确剥离头（此处应命中）")
	}
	if isSoft404Response("HTTP/1.1 200 OK\r\n\r\n", b) {
		t.Fatal("空正文不判")
	}
	if isSoft404Response("HTTP/1.1 200 OK\r\n\r\nY", b) {
		t.Fatal("不同正文不判")
	}
	_ = strings.TrimSpace
	_ = time.Now
}
