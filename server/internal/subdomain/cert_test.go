package subdomain

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseCertLines(t *testing.T) {
	body := "example.com\r\n" +
		"www.example.com\n" +
		"*.wild.example.com\r\n" +
		"dev.example.com\n" +
		"DEV.example.com \n" +
		"notexample.org\n" +
		"sub.other.com\n" +
		"\n" +
		".dot.example.com.\n"
	got := parseCertLines("example.com", body)
	want := []string{"www.example.com", "wild.example.com", "dev.example.com", "dot.example.com"}
	if len(got) != len(want) {
		t.Fatalf("解析结果数量不符: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 项不符: got %s want %s", i, got[i], want[i])
		}
	}
}

func TestParseCertLinesEmpty(t *testing.T) {
	if got := parseCertLines("example.com", ""); len(got) != 0 {
		t.Fatalf("空响应应无结果: %v", got)
	}
	if got := parseCertLines("example.com", "\n\n"); len(got) != 0 {
		t.Fatalf("空白响应应无结果: %v", got)
	}
}

// crt.sh 备用源 JSON 解析：name_value 多行展开、*. 前缀剥离、跨域过滤
func TestParseCertShJSON(t *testing.T) {
	body := `[{"issuer_name":"CA","common_name":"*.a.example.com","name_value":"*.a.example.com\na.example.com\nwww.b.example.com"},
{"issuer_name":"CA","common_name":"other.com","name_value":"x.other.com"}]`
	got := parseCertShJSON("example.com", body)
	want := []string{"a.example.com", "www.b.example.com"}
	if len(got) != len(want) {
		t.Fatalf("crt.sh 解析: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("crt.sh 解析顺序: %v want %v", got, want)
		}
	}
}

// 双源回落：主源命中即用（source=crt.name）；主源为空回落 crt.sh（JSON 解析，source=crt.sh）
func TestCertQueryDualSourceFallback(t *testing.T) {
	sh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name_value":"*.a.example.com\na.example.com\nb.example.com"}]`))
	}))
	defer sh.Close()
	name := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("a.example.com\nb.example.com\nc.example.com\n"))
	}))
	defer name.Close()

	certPrimaryURL, certFallbackURL = name.URL, sh.URL
	defer func() { certPrimaryURL, certFallbackURL = CertQueryURL, CertFallbackURL }()

	r := CertQueryVerbose("example.com", 5)
	if r.Source != "crt.name" || len(r.Items) != 3 {
		t.Fatalf("主源命中: %+v", r)
	}

	// 主源返回空 → 回落 crt.sh
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	}))
	defer empty.Close()
	certPrimaryURL = empty.URL
	r2 := CertQueryVerbose("example.com", 5)
	if r2.Source != "crt.sh" || len(r2.Items) != 2 {
		t.Fatalf("回落 crt.sh: %+v", r2)
	}

	// 两源均失败 → source 空
	certFallbackURL = "http://127.0.0.1:1"
	r3 := CertQueryVerbose("example.com", 2)
	if r3.Source != "" || len(r3.Items) != 0 {
		t.Fatalf("双源失败: %+v", r3)
	}
}
