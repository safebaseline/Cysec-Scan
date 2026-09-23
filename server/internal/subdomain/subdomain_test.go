package subdomain

import (
	"fmt"
	"strings"
	"testing"
)

func fakeLookup(resolved map[string]string) lookupFunc {
	return func(host string) ([]string, string, error) {
		if ip, ok := resolved[host]; ok {
			return []string{ip}, "", nil
		}
		return nil, "", fmt.Errorf("no such host")
	}
}

func TestBruteBasicAndWildcardFilter(t *testing.T) {
	// 泛解析：任何子域都解析到 1.1.1.1；www 与 api 解析到独立 IP
	resolved := map[string]string{}
	for _, w := range []string{"a", "b", "randomx"} {
		_ = w
	}
	// 预填泛解析（brute 内部会随机探测，fake 里所有未知主机返回错误即可；已知泛解析前缀直接放 map）
	resolved["www.example.com"] = "2.2.2.2"
	resolved["api.example.com"] = "3.3.3.3"
	resolved["dev.example.com"] = "1.1.1.1" // 泛解析 IP
	// 让随机泛解析探测也命中（任何以 wildcard- 开头的主机）
	lk := func(host string) ([]string, string, error) {
		if strings.HasPrefix(host, "www.") || strings.HasPrefix(host, "api.") || strings.HasPrefix(host, "dev.") {
			return fakeLookup(resolved)(host)
		}
		// 随机探测标签（12位随机） => 泛解析到 1.1.1.1
		if label := strings.SplitN(host, ".", 2)[0]; len(label) == 12 {
			return []string{"1.1.1.1"}, "", nil
		}
		return nil, "", fmt.Errorf("nx")
	}
	got := brute("example.com", []string{"www", "api", "dev", "notexist"}, 4, lk)
	if len(got) != 2 {
		t.Fatalf("应保留 www/api 两条（dev 命中泛解析 IP 被过滤）: %+v", got)
	}
	subs := map[string]bool{}
	for _, r := range got {
		subs[r.Subdomain] = true
	}
	if !subs["www.example.com"] || !subs["api.example.com"] {
		t.Fatalf("结果错误: %+v", got)
	}
}

func TestBruteNoWildcard(t *testing.T) {
	lk := func(host string) ([]string, string, error) {
		if host == "www.example.com" {
			return []string{"9.9.9.9"}, "cname.example.net.", nil
		}
		return nil, "", fmt.Errorf("nx")
	}
	got := brute("example.com", []string{"www", "mail"}, 2, lk)
	if len(got) != 1 || got[0].IP != "9.9.9.9" || got[0].CNAME != "cname.example.net" {
		t.Fatalf("无泛解析时结果: %+v", got)
	}
}

func TestWordlistDedup(t *testing.T) {
	seen := map[string]bool{}
	for _, w := range DefaultWordlist {
		if seen[w] {
			t.Fatalf("字典重复项: %s", w)
		}
		seen[w] = true
	}
	if len(DefaultWordlist) < 500 {
		t.Fatalf("内置字典过小: %d", len(DefaultWordlist))
	}
}
