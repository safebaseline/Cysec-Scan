package mapper

import (
	"path/filepath"
	"strings"
	"testing"

	"cysec/internal/store"
)

// 集成：FOFA 纯 IP 记录（host 字段为空 → Record.URL 为空）经 Import 落库时应合成 Web 资产，
// 端口入库与 Web 入库一致；非 HTTP 服务不生成 Web。
func TestImportSynthesizesWebForHostlessRecords(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	newIPs, _, newPorts, newWebs := Import(st, 1, 0, []Record{
		{IP: "1.2.3.4", Port: 11001, Service: "HTTP", Provider: "fofa"},
		{IP: "1.2.3.4", Port: 3306, Service: "MySQL", Provider: "fofa"},
	}, nil, nil)
	if newIPs != 1 || newPorts != 2 {
		t.Fatalf("ips=%d ports=%d", newIPs, newPorts)
	}
	if newWebs != 1 {
		t.Fatalf("webs=%d, want 1 (仅 HTTP 记录合成)", newWebs)
	}
	ws := st.WebsOfProject(1)
	if len(ws) != 1 || ws[0].URL != "http://1.2.3.4:11001" {
		t.Fatalf("webs=%v", ws)
	}
}

// 域名一致性校验：测绘带回杂域名（roots 非空）时域名/杂域名 Web 丢弃、IP/端口保留
func TestImportRejectsInconsistentDomains(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	recs := []Record{
		{IP: "1.1.1.1", Port: 80, Domain: "www.xxxx.edu.cn", Provider: "fofa"},            // 一致
		{IP: "2.2.2.2", Port: 80, Domain: "xxxx.xxxx.gov.cn", Provider: "fofa"},            // 杂域名
		{IP: "3.3.3.3", Port: 8080, URL: "http://xxxx.xxxx.gov.cn:8080", Provider: "fofa"}, // 杂域名 vhost
		{IP: "4.4.4.4", Port: 443, URL: "https://4.4.4.4", Provider: "fofa"},              // IP 形态 Web 不受影响
	}
	_, nd, np, nw := Import(st, 1, 0, recs, []string{"xxxx.edu.cn"}, nil)
	if nd != 1 {
		t.Fatalf("domains=%d want 1（仅一致域名入库）", nd)
	}
	if np != 4 {
		t.Fatalf("ports=%d want 4（IP/端口维度不受域名过滤影响）", np)
	}
	if nw != 4 { // 杂域名丢弃后按 IP 重合成 Web：www.xxxx.edu.cn + 2.2.2.2:80 + 3.3.3.3:8080 + https://4.4.4.4
		t.Fatalf("webs=%d want 4（杂域名 vhost 改按 IP 维度入库）", nw)
	}
	for _, w := range st.WebsOfProject(1) {
		if strings.Contains(w.URL, "xxxx.xxxx.gov.cn") {
			t.Fatalf("杂域名不应出现在 Web URL 中: %s", w.URL)
		}
	}
	// roots 为空：全部放行
	st2, _ := store.Open(filepath.Join(t.TempDir(), "t2.db"))
	defer st2.Close()
	_, nd2, _, nw2 := Import(st2, 1, 0, recs, nil, nil)
	if nd2 != 2 || nw2 != 4 {
		t.Fatalf("empty roots: domains=%d webs=%d want 2/4（纯 IP/未启用：全部放行）", nd2, nw2)
	}
}
