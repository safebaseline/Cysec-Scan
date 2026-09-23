package builtin

import (
	"strings"
	"testing"
	"unicode/utf8"

	"cysec/internal/plugins"

	"cysec/internal/charset"
)

type fakeClient struct {
	status int
	body   string
	ct     string
}

func (f fakeClient) Do(url string) (*plugins.HTTPResponse, error) {
	return &plugins.HTTPResponse{StatusCode: f.status, Body: f.body, ContentType: f.ct}, nil
}

func TestLeakScanCustomRules(t *testing.T) {
	orig := CurrentLeakPaths()
	defer SetLeakPaths(orig)

	SetLeakPaths([]LeakPath{
		{Path: "backup.zip", Name: "备份文件", Severity: "high", Keyword: "PK"},
		{Path: "/custom", Severity: "low"}, // 无关键词：200+正文非空即命中
	})
	if got := CurrentLeakPaths(); len(got) != 2 || got[0].Path != "/backup.zip" {
		t.Fatalf("normalize failed: %+v", got)
	}
	if !strings.HasPrefix(CurrentLeakPaths()[0].VulnID, "CYSEC-LEAK-") {
		t.Fatalf("vuln id not generated: %+v", CurrentLeakPaths()[0])
	}
	s := &leakRiskScanner{}
	ctx := plugins.RiskContext{Web: &plugins.WebResult{URL: "http://t"}, Client: fakeClient{status: 200, body: "PK\x03\x04zipdata", ct: "application/zip"}}
	out := s.Scan(ctx)
	if len(out) != 2 {
		t.Fatalf("want 2 hits got %d: %+v", len(out), out)
	}
	// 关键词不命中
	SetLeakPaths([]LeakPath{{Path: "/backup.zip", Keyword: "NOT-IN-BODY", Severity: "high"}})
	if out := s.Scan(ctx); len(out) != 0 {
		t.Fatalf("keyword miss should not hit: %+v", out)
	}
	// 未配置 → 跳过
	SetLeakPaths(nil)
	if out := s.Scan(ctx); out != nil {
		t.Fatalf("empty rules should skip: %+v", out)
	}
	// 404 不命中
	SetLeakPaths([]LeakPath{{Path: "/x", Severity: "high"}})
	if out := s.Scan(plugins.RiskContext{Web: &plugins.WebResult{URL: "http://t"}, Client: fakeClient{status: 404, body: "x"}}); len(out) != 0 {
		t.Fatalf("404 should not hit")
	}
}

// GBK 页面响应体经 restrictedDoer 后应被规范化为合法 UTF-8，锚文本不再乱码
func TestNormalizeBodyCharsetGBK(t *testing.T) {
	gbkBody := []byte{0xd6, 0xd0, 0xce, 0xc4, 0xb2, 0xe2, 0xca, 0xd4} // "中文测试" 的 GBK 编码
	if utf8.Valid(gbkBody) {
		t.Skip("环境异常：GBK 字节被误判为合法 UTF-8")
	}
	out := charset.Normalize(gbkBody, "text/html; charset=GBK")
	if string(out) != "中文测试" {
		t.Fatalf("GBK decode got %q", out)
	}
	if out := charset.Normalize([]byte("正常utf8"), ""); string(out) != "正常utf8" {
		t.Fatalf("utf8 passthrough got %q", out)
	}
	garbage := charset.Normalize([]byte{0xff, 0xfe, 0x81}, "")
	if !utf8.Valid(garbage) {
		t.Fatalf("fallback should be valid utf8, got %q", garbage)
	}
}
