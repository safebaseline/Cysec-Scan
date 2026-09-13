package store

import (
	"testing"

	"cysec/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUpsertIPDedup(t *testing.T) {
	s := openTest(t)
	isNew, err := s.UpsertIP(model.AssetIP{ProjectID: 1, IP: "1.2.3.4", Source: "import"})
	if err != nil || !isNew {
		t.Fatalf("首次插入应为新资产: %v %v", isNew, err)
	}
	isNew, err = s.UpsertIP(model.AssetIP{ProjectID: 1, IP: "1.2.3.4", Source: "import"})
	if err != nil || isNew {
		t.Fatalf("重复插入应去重: %v %v", isNew, err)
	}
	n, _ := s.Count("asset_ips", 1, "", nil)
	if n != 1 {
		t.Fatalf("count = %d", n)
	}
}

func TestUpsertVulnDedup(t *testing.T) {
	s := openTest(t)
	v := model.Vulnerability{ProjectID: 1, VulnID: "CYSEC-T-001", Name: "test", Severity: "high", IP: "1.2.3.4", Port: 80, URL: "http://1.2.3.4"}
	isNew, err := s.UpsertVuln(v)
	if err != nil || !isNew {
		t.Fatalf("首次: %v %v", isNew, err)
	}
	isNew, err = s.UpsertVuln(v)
	if err != nil || isNew {
		t.Fatalf("相同资产+端口+URL+漏洞ID 应去重: %v %v", isNew, err)
	}
	// 不同 URL 不去重
	v2 := v
	v2.URL = "http://1.2.3.4/x"
	isNew, err = s.UpsertVuln(v2)
	if err != nil || !isNew {
		t.Fatalf("不同 URL 应视为新漏洞: %v %v", isNew, err)
	}
}

func TestIPDetail(t *testing.T) {
	s := openTest(t)
	s.UpsertIP(model.AssetIP{ProjectID: 1, IP: "1.2.3.4"})
	s.UpsertPort(model.AssetPort{ProjectID: 1, IP: "1.2.3.4", Port: 80, Service: "HTTP", Category: "Web 服务器"})
	s.UpsertVuln(model.Vulnerability{ProjectID: 1, VulnID: "V1", Name: "n", Severity: "low", IP: "1.2.3.4", Port: 80, URL: "http://1.2.3.4"})
	d, err := s.IPDetail(1, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if len(d["ports"].([]map[string]any)) != 1 || len(d["vulnerabilities"].([]map[string]any)) != 1 {
		t.Fatalf("关联数据不完整: %v", d)
	}
}
