package ai

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIBases(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"https://api.openai.com", []string{"https://api.openai.com/v1", "https://api.openai.com"}},
		{"https://api.openai.com/", []string{"https://api.openai.com/v1", "https://api.openai.com"}},
		{"https://api.openai.com/v1", []string{"https://api.openai.com/v1"}},
		{"https://api.openai.com/v1/", []string{"https://api.openai.com/v1"}},
		{"http://localhost:11434", []string{"http://localhost:11434/v1", "http://localhost:11434"}},
		{"https://gate.example.com/v2", []string{"https://gate.example.com/v2"}},
		{"https://api.example.com/v1/chat/completions", []string{"https://api.example.com/v1"}},
		{"  https://api.x.com  ", []string{"https://api.x.com/v1", "https://api.x.com"}},
	}
	for _, c := range cases {
		got := apiBases(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("apiBases(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("apiBases(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// TestListModelsMock 三种 base_url 写法都能拿到模型列表（补 /v1、已带 /v1、404 回退裸路径）
func TestListModelsMock(t *testing.T) {
	mk := func(paths map[string]string) *httptest.Server {
		mux := http.NewServeMux()
		for p, resp := range paths {
			resp := resp
			mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
				if resp == "404" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.Header.Get("Authorization") != "Bearer sk-test" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(resp))
			})
		}
		return httptest.NewServer(mux)
	}
	v1Body := `{"data":[{"id":"gpt-4o-mini"},{"id":"gpt-4o"}]}`
	cases := []struct {
		name   string
		paths  map[string]string
		withV1 bool
	}{
		{"补v1", map[string]string{"/v1/models": v1Body}, false},
		{"已带v1", map[string]string{"/v1/models": v1Body}, true},
		{"404回退裸路径", map[string]string{"/models": `{"data":[{"id":"qwen-plus"}]}`, "/v1/models": "404"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := mk(tc.paths)
			defer srv.Close()
			base := srv.URL
			if tc.withV1 {
				base += "/v1"
			}
			models, err := ListModels(Config{BaseURL: base, APIKey: "sk-test"})
			if err != nil {
				t.Fatalf("获取模型失败: %v", err)
			}
			if len(models) == 0 {
				t.Fatal("模型列表为空")
			}
			t.Logf("模型: %v", models)
		})
	}
}
