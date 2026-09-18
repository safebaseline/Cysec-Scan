package vulnrule

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestNucleiRawRequestPreserved 验证官方引擎回调中的 request/response 是否保留
func TestNucleiRawRequestPreserved(t *testing.T) {
	if os.Getenv("NUCLEI_LIVE") == "" {
		t.Skip("set NUCLEI_LIVE=1")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ROOT_MARKER_OK"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tpl := `id: rawtest
info:
  name: raw test
  author: t
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
    matchers:
      - type: word
        words:
          - "ROOT_MARKER_OK"
`
	if err := os.WriteFile(filepath.Join(dir, "tpl.yaml"), []byte(tpl), 0644); err != nil {
		t.Fatal(err)
	}
	SetNucleiTemplateRoot(dir)

	findings, err := RunNucleiBatch(context.Background(), []string{srv.URL}, []string{"rawtest"}, 5)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings=%d", len(findings))
	}
	f := findings[0]
	t.Logf("REQ len=%d head=%q", len(f.Request), truncS(f.Request, 80))
	t.Logf("RESP len=%d head=%q", len(f.Response), truncS(f.Response, 80))
	if f.Request == "" || f.Response == "" {
		t.Fatal("finding has empty request/response — 丢报文复现")
	}
}

func truncS(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
