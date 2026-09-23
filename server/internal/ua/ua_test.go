package ua

import (
	"net/http"
	"net/textproto"
	"testing"
)

func TestSetGet(t *testing.T) {
	orig := Get()
	defer Set(orig)
	Set("MyAgent/2.0")
	if Get() != "MyAgent/2.0" {
		t.Fatalf("got %s", Get())
	}
	Set("  ") // 空白回退不变
	if Get() != "MyAgent/2.0" {
		t.Fatal("空白不应改变值")
	}
	Set("") // 空串不应清空
	if Get() != "MyAgent/2.0" {
		t.Fatal("空串不应改变值")
	}
}

func TestDefault(t *testing.T) {
	if Get() == "" {
		t.Fatal("默认值不应为空")
	}
}

func TestSetHeadersApply(t *testing.T) {
	SetHeaders(map[string]string{
		"x-scan-token": "authorized", // 小写键应被规范化
		"Cookie":       "session=abc",
		" empty ":      "",  // 空值忽略
		"":             "v", // 空键忽略
	})
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	Apply(req)
	if got := req.Header.Get("X-Scan-Token"); got != "authorized" {
		t.Errorf("自定义头未生效: %q", got)
	}
	if got := req.Header.Get("Cookie"); got != "session=abc" {
		t.Errorf("Cookie 未生效: %q", got)
	}
	if req.Header.Get("User-Agent") == "" {
		t.Errorf("User-Agent 应始终设置")
	}
	if _, ok := req.Header[textproto.CanonicalMIMEHeaderKey("empty")]; ok {
		t.Errorf("空值头不应设置")
	}
	// 规则自带头在 Apply 之后设置可覆盖
	req.Header.Set("Cookie", "rule=own")
	if req.Header.Get("Cookie") != "rule=own" {
		t.Errorf("规则自带头应可覆盖全局头")
	}
	SetHeaders(nil)
	req2, _ := http.NewRequest("GET", "http://example.com/", nil)
	Apply(req2)
	if req2.Header.Get("X-Scan-Token") != "" {
		t.Errorf("清空后不应携带自定义头")
	}
}

func TestHeadersUserAgent(t *testing.T) {
	origUA := Get()
	defer Set(origUA)
	SetHeaders(map[string]string{
		"User-Agent": "TestUA/9.9",
		"X-Extra":    "1",
	})
	if Get() != "TestUA/9.9" {
		t.Fatalf("headers 中的 User-Agent 应成为全局 UA: %q", Get())
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	Apply(req)
	if req.Header.Get("User-Agent") != "TestUA/9.9" {
		t.Errorf("Apply 应使用全局 UA")
	}
	if req.Header.Get("X-Extra") != "1" {
		t.Errorf("其余附加头应保留")
	}
}
