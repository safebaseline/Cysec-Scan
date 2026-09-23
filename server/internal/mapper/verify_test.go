package mapper

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func addrPort(addr string) int {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

func TestVerifyAlive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// 找一个必然关闭的端口
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("无法监听本地端口")
	}
	deadPort := addrPort(deadLn.Addr().String())
	deadLn.Close()

	recs := []Record{
		{IP: "127.0.0.1", Port: addrPort(srv.URL), Provider: "t"}, // TCP 存活
		{IP: "127.0.0.1", Port: deadPort, Provider: "t"},          // TCP 失效 → 剔除
		{URL: srv.URL, Provider: "t"},                             // URL 存活
		{Domain: "example.com", Provider: "t"},                    // 无可探测目标 → 保留
	}
	alive, dead := VerifyAlive(recs, 3, 8)
	if len(alive) != 3 || dead != 1 {
		t.Fatalf("alive=%d dead=%d, want 3/1", len(alive), dead)
	}
	for _, r := range alive {
		if r.Port == deadPort {
			t.Fatal("失效记录不应保留")
		}
	}
}
