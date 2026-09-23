package store

import "testing"

func TestFPAssetIgnored(t *testing.T) {
	entries := []string{"blocked.gov.cn", "192.0.2.0/24", "http://bad.example.com", "1.2.3.4"}
	cases := []struct {
		kind, val string
		want      bool
	}{
		{"domain", "gdb.blocked.gov.cn", true}, // 域名根后缀
		{"domain", "a.b.blocked.gov.cn", true}, // 多级
		{"domain", "blocked.gov.cn", true},     // 相等
		{"domain", "allow.edu.cn", false},
		{"domain", "fakeblocked.gov.cn", false}, // 伪后缀
		{"ip", "192.0.2.77", true},              // CIDR
		{"ip", "192.0.2.0", true},
		{"ip", "192.0.1.1", false},
		{"ip", "1.2.3.4", true}, // 精确 IP
		{"ip", "1.2.3.5", false},
		{"web", "http://bad.example.com/x", true}, // URL 前缀
		{"web", "http://bad.example.com", true},   // 相等
		{"web", "http://bad.example.com.evil.cn", false},
		{"domain", "", false}, // 空值
	}
	for _, c := range cases {
		if got := FPAssetIgnored(entries, c.kind, c.val); got != c.want {
			t.Errorf("%s %q: got %v want %v", c.kind, c.val, got, c.want)
		}
	}
	if FPAssetIgnored(nil, "domain", "anything") {
		t.Fatal("empty entries should allow all")
	}
}
