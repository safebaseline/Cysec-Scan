package store

import (
	"testing"
)

func TestDomainMatchesApex(t *testing.T) {
	roots := []string{"demo.edu.cn", "demo2.cn"}
	cases := []struct {
		domain string
		want   bool
	}{
		{"demo.edu.cn", true},
		{"www.demo.edu.cn", true},
		{"a.b.demo.edu.cn", true},
		{"demo2.cn", true},
		{"jenkins.demo2.cn", true},
		{"gdb.other.gov.cn", false},     // 不同根
		{"fakedemo.edu.cn", false},      // 伪后缀（未对齐标签边界）
		{"demo.edu.cn.evil.com", false}, // 后缀包含但不结尾
		{"", false},
		{"DEMO.EDU.CN", true}, // 大小写不敏感
	}
	for _, c := range cases {
		if got := DomainMatchesApex(c.domain, roots); got != c.want {
			t.Errorf("%q: got %v want %v", c.domain, got, c.want)
		}
	}
	// 空 roots（纯 IP 任务 / 未启用）：全部放行
	for _, d := range []string{"anything.gov.cn", "x.y.z", ""} {
		if !DomainMatchesApex(d, nil) {
			t.Errorf("empty roots should allow %q", d)
		}
	}
}
