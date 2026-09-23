package engine

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchVulnPackets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("c8c605999f3d8352d7bb792cf3fdb25b found"))
	}))
	defer srv.Close()
	req, resp := fetchVulnPackets(srv.URL+"/api/x?order=1", 5)
	if !strings.Contains(req, "GET /api/x?order=1 HTTP/") || !strings.Contains(req, "Host:") {
		t.Fatalf("request dump bad: %q", req)
	}
	if !strings.Contains(resp, "HTTP/") || !strings.Contains(resp, "c8c605999f3d8352d7bb792cf3fdb25b") {
		t.Fatalf("response dump bad: %q", resp)
	}
	if _, r := fetchVulnPackets("", 5); r != "" {
		t.Fatalf("empty target should return empty")
	}
}
