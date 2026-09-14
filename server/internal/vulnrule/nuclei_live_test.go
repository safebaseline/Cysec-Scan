package vulnrule

import (
	"context"
	"os"
	"testing"
)

// TestNucleiLive 联网/本地实跑官方引擎（NUCLEI_LIVE=1 时执行）
func TestNucleiLive(t *testing.T) {
	if os.Getenv("NUCLEI_LIVE") == "" {
		t.Skip("set NUCLEI_LIVE=1")
	}
	root := os.Getenv("NUCLEI_TPL_ROOT")
	if root == "" {
		t.Skip("set NUCLEI_TPL_ROOT")
	}
	SetNucleiTemplateRoot(root)
	f, err := RunNucleiBatch(context.Background(), []string{"http://127.0.0.1:18103"},
		[]string{"e2e-marker-found", "e2e-word-absent"}, 5)
	if err != nil {
		t.Fatalf("完整错误: %+v", err)
	}
	t.Logf("findings=%d", len(f))
	for _, x := range f {
		t.Logf("hit: %s @ %s", x.TemplateID, x.MatchedAt)
	}
}
