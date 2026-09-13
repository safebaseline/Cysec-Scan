package engine

import (
	"sort"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	ips, domains, urls, err := ParseTargets("192.168.1.1\n10.0.0.0/30\nexample.com\nhttps://foo.example.com:8443/x\n1.2.3.4-1.2.3.5", "mixed", 1000)
	if err != nil {
		t.Fatal(err)
	}
	wantIPs := []string{"192.168.1.1", "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "1.2.3.4", "1.2.3.5"}
	if len(ips) != len(wantIPs) {
		t.Fatalf("ips = %v, want %v", ips, wantIPs)
	}
	for i, w := range wantIPs {
		if ips[i] != w {
			t.Fatalf("ips[%d] = %s, want %s", i, ips[i], w)
		}
	}
	if len(domains) != 2 || domains[0] != "example.com" {
		t.Fatalf("domains = %v", domains)
	}
	if len(urls) != 1 {
		t.Fatalf("urls = %v", urls)
	}
}

func TestParseTargetsReorderBug(t *testing.T) {
	// 验证 URL 中的 IP / 域名也能进入资产列表
	_, domains, _, _ := ParseTargets("https://a.test.com", "url", 10)
	if len(domains) != 1 || domains[0] != "a.test.com" {
		t.Fatalf("domains = %v", domains)
	}
}

func TestParsePorts(t *testing.T) {
	top := []int{80, 443}
	if got := ParsePorts("", top, 1024); len(got) != 2 {
		t.Fatalf("default ports = %v", got)
	}
	if got := ParsePorts("80,443,8080", top, 1024); len(got) != 3 {
		t.Fatalf("ports = %v", got)
	}
	if got := ParsePorts("80-85", top, 1024); len(got) != 6 {
		t.Fatalf("range = %v", got)
	}
	if got := ParsePorts("full", top, 1024); len(got) != 65535 {
		t.Fatalf("full = %d", len(got))
	}
}

func TestDefaultPortsByMode(t *testing.T) {
	top := []int{80, 443}
	if got := DefaultPortsByMode("quick", top); len(got) != 2 {
		t.Fatalf("quick 应为常见端口: %v", got)
	}
	if got := DefaultPortsByMode("standard", top); len(got) != 1000 {
		t.Fatalf("standard 应为 Top1000: %d", len(got))
	}
	if got := DefaultPortsByMode("deep", top); len(got) != 65535 || got[0] != 1 || got[65534] != 65535 {
		t.Fatalf("deep 应为全端口: %d", len(got))
	}
	// Top1000 覆盖常见服务端口且有序
	if tp := Top1000Ports(); !sort.IntsAreSorted(tp) {
		t.Fatal("Top1000 应有序")
	}
	for _, want := range []int{22, 80, 443, 1433, 3306, 3389, 6379, 8080, 8443, 9200, 27017} {
		found := false
		for _, p := range Top1000Ports() {
			if p == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Top1000 缺少常见端口 %d", want)
		}
	}
}

func TestWhitelisted(t *testing.T) {
	items := []string{"192.168.1.10", "10.0.0.0/8", "example.com", "*.corp.cn", ""}
	if !Whitelisted(items, "192.168.1.10", "") {
		t.Fatal("精确 IP 应命中")
	}
	if !Whitelisted(items, "10.20.30.40", "") {
		t.Fatal("CIDR 内应命中")
	}
	if Whitelisted(items, "11.1.1.1", "") {
		t.Fatal("CIDR 外不应命中")
	}
	if !Whitelisted(items, "", "example.com") || !Whitelisted(items, "", "a.example.com") {
		t.Fatal("域名及子域名应命中")
	}
	if Whitelisted(items, "", "notexample.com") {
		t.Fatal("后缀相似但非子域名不应命中")
	}
	if !Whitelisted(items, "", "x.corp.cn") {
		t.Fatal("*.corp.cn 通配应命中子域名")
	}
	if Whitelisted(items, "2.2.2.2", "b.com") {
		t.Fatal("无关资产不应命中")
	}
}

func TestParseIntervalCustom(t *testing.T) {
	if ParseInterval("6h") != 6*time.Hour {
		t.Fatal("6h")
	}
	if ParseInterval("48h") != 48*time.Hour {
		t.Fatal("48h")
	}
	if ParseInterval("168h") != 7*24*time.Hour {
		t.Fatal("168h")
	}
	if ParseInterval("0h") != 0 {
		t.Fatal("0h 应非法")
	}
	if ParseInterval("99999h") != 0 {
		t.Fatal("超上限应非法")
	}
	if ParseInterval("xh") != 0 {
		t.Fatal("非数字应非法")
	}
	if ParseInterval("30m") != 0 {
		t.Fatal("分钟不支持")
	}
	if ParseInterval("8h") != 8*time.Hour {
		t.Fatal("预设 8h")
	}
	if ParseInterval("1w") != 7*24*time.Hour {
		t.Fatal("预设 1w")
	}
}

func TestIsPrivateIP(t *testing.T) {
	if IsPrivateIP("192.168.1.1") != "private" {
		t.Fatal("192.168.1.1 应为内网")
	}
	if IsPrivateIP("8.8.8.8") != "public" {
		t.Fatal("8.8.8.8 应为公网")
	}
}

func TestParseTargetsCIDRLimit(t *testing.T) {
	_, _, _, err := ParseTargets("10.0.0.0/8", "ip", 1000)
	if err == nil {
		t.Fatal("超大 CIDR 应报错")
	}
}
