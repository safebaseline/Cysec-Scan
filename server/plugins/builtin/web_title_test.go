package builtin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GBK 站点标题归一：ProbeWeb 漏归一时 GBK 字节原样入库形成逐字节乱码
func TestProbeWebGBKTitle(t *testing.T) {
	// "KINGOSOFT高校智慧校园教学综合服务平台" 的 GBK 编码页面
	gbkBody := append([]byte("<html><head><title>KINGOSOFT"),
		0xb8, 0xdf, 0xd0, 0xa3, 0xd6, 0xc7, 0xbb, 0xdb, 0xd0, 0xa3, 0xd4, 0xb0,
		0xbd, 0xcc, 0xd1, 0xa7, 0xd7, 0xdb, 0xba, 0xcf, 0xb7, 0xfe, 0xce, 0xf1, 0xc6, 0xbd, 0xcc, 0xa8)
	gbkBody = append(gbkBody, []byte("</title></head><body>ok</body></html>")...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html") // 无 charset 声明，须按字节内容判定
		w.Write(gbkBody)
	}))
	defer srv.Close()

	wr := ProbeWeb(srv.URL, "127.0.0.1", 5)
	if wr == nil {
		t.Fatal("ProbeWeb nil")
	}
	if !strings.Contains(wr.Title, "高校智慧校园") || strings.ContainsAny(wr.Title, "\ufffdУѧ԰") {
		t.Fatalf("GBK 标题乱码: %q", wr.Title)
	}
}
