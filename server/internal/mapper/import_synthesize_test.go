package mapper

import (
	"path/filepath"
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
	})
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
