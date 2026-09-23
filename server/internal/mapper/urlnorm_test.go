package mapper

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func addrPort2(addr string) int {
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://"))
	n, _ := strconv.Atoi(p)
	return n
}

func TestNormalizeURL(t *testing.T) {
	if NormalizeURL("example.com", 80) != "http://example.com" {
		t.Fatal("port 80 -> http")
	}
	if NormalizeURL("example.com", 443) != "https://example.com" {
		t.Fatal("port 443 -> https")
	}
	if NormalizeURL("host:8443", 8443) != "https://host:8443" {
		t.Fatal("port 8443 -> https")
	}
	// 非标准 TLS 端口：起一个本地 TLS 服务，探测应返回 https
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tlsPort := addrPort2(srv.URL)
	if NormalizeURL("127.0.0.1:"+strconv.Itoa(tlsPort), tlsPort) != "https://127.0.0.1:"+strconv.Itoa(tlsPort) {
		t.Fatal("非标准 TLS 端口应探测为 https")
	}
	// 非标准纯 HTTP 端口
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer httpSrv.Close()
	httpPort := addrPort2(httpSrv.URL)
	if got := NormalizeURL("127.0.0.1:"+strconv.Itoa(httpPort), httpPort); got != "http://127.0.0.1:"+strconv.Itoa(httpPort) {
		t.Fatal("纯 HTTP 端口应为 http://，got " + got)
	}
	if NormalizeURL("http://a.com", 80) != "http://a.com" {
		t.Fatal("已有 http 不变")
	}
	if NormalizeURL("https://a.com", 443) != "https://a.com" {
		t.Fatal("已有 https 不变")
	}
	if NormalizeURL("", 80) != "" {
		t.Fatal("空 URL 不变")
	}
}
