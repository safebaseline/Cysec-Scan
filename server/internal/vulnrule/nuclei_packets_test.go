package vulnrule

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 实证 nuclei SDK 事件是否携带请求/响应报文与 MatchedAt（线上表现为报文丢失，只能补抓根 URL）
func TestRunNucleiBatchPackets(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/panel/") {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>cysec-panel-probe-ok</body></html>"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tpl := `id: cysec-panel-test
info:
  name: Cysec Panel Detect
  author: cysec-e2e
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/panel/index.html"
    matchers:
      - type: word
        words:
          - "cysec-panel-probe-ok"
`
	if err := os.WriteFile(filepath.Join(dir, "cysec-panel-test.yaml"), []byte(tpl), 0o644); err != nil {
		t.Fatal(err)
	}
	old := nucleiTemplateRoot
	SetNucleiTemplateRoot(filepath.ToSlash(dir))
	defer SetNucleiTemplateRoot(old)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	findings, err := RunNucleiBatch(ctx, []string{srv.URL}, []string{"cysec-panel-test"}, 5)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("模板未命中（复现失败）")
	}
	f := findings[0]
	t.Logf("MatchedAt=%q", f.MatchedAt)
	t.Logf("Request前120=%q", truncateForLog(f.Request, 120))
	t.Logf("Response前120=%q", truncateForLog(f.Response, 120))
	if !strings.Contains(f.MatchedAt, "/panel/") {
		t.Errorf("MatchedAt 应含模板路径: %q", f.MatchedAt)
	}
	if !strings.Contains(f.Request, "/panel/index.html") {
		t.Errorf("事件 Request 未携带模板真实请求: %q", truncateForLog(f.Request, 200))
	}
	if !strings.Contains(f.Response, "cysec-panel-probe-ok") {
		t.Errorf("事件 Response 未携带命中响应: %q", truncateForLog(f.Response, 200))
	}
}

func truncateForLog(s string, n int) string {
	s = strings.ReplaceAll(s, "\r\n", "\\r\\n")
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
