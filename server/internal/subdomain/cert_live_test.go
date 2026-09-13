package subdomain

import (
	"os"
	"strings"
	"testing"
)

// TestCertQueryLive 真实请求 crt.name 的联网测试（默认跳过，CERT_LIVE=1 时执行）
func TestCertQueryLive(t *testing.T) {
	if os.Getenv("CERT_LIVE") == "" {
		t.Skip("set CERT_LIVE=1 to run live test")
	}
	subs := CertQuery("example.com", 15)
	if len(subs) == 0 {
		t.Fatal("crt.name 未返回子域名")
	}
	for _, s := range subs {
		if !strings.HasSuffix(s, ".example.com") {
			t.Fatalf("返回了非目标域的子域: %s", s)
		}
	}
	t.Logf("收集到 %d 个子域，示例: %s", len(subs), subs[0])
}
