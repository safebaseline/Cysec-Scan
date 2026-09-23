package vulnrule

import "testing"

func TestEvalDSL(t *testing.T) {
	ctx := DSLContext{Body: `<html><title>Test Page</title></html>`, Header: "Content-Type: text/html\r\nServer: nginx", StatusCode: 200, Method: "GET", ContentType: "text/html"}
	tests := []struct {
		expr string
		want bool
	}{
		{`status_code == 200`, true},
		{`status_code == 404`, false},
		{`contains(body, "Test Page")`, true},
		{`contains(body, "NotFound")`, false},
		{`!contains(body, "NotFound")`, true},
		{`!contains(body, "Test")`, false},
		{`contains(to_lower(body), "test page")`, true},
		{`contains(body, "title") && contains(body, "html")`, true},
		{`contains(body, "xxx") || contains(body, "title")`, true},
		{`contains_any(body, "xxx", "yyy", "title")`, true},
		{`contains_all(body, "title", "html")`, true},
		{`contains_all(body, "title", "xxx")`, false},
		{`starts_with(body, "<html>")`, true},
		{`ends_with(body, "</html>")`, true},
		{`len(body) > 10`, true},
		{`len(body) < 5`, false},
		{`method == "GET"`, true},
		{`contains(header, "nginx")`, true},
		{`contains(content_type, "text/html")`, true},
		{`status_code == 200 && contains(body, "Test")`, true},
		{`status_code == 404 || contains(body, "Test")`, true},
		{`!regex("root:x:0:0", body)`, true},
		{`md5("hello") == "5d41402abc4b2a76b9719d911017c592"`, true},
		{`base64("hi") == "aGk="`, true},
		{`substr("hello world", 0, 5) == "hello"`, true},
		{`trim_space("  hi  ") == "hi"`, true},
		{`(status_code == 200 && contains(body,"x")) || contains(body,"title")`, true},
	}
	for _, tt := range tests {
		got, err := EvalDSL(tt.expr, ctx)
		if err != nil {
			t.Errorf("EvalDSL(%q) error: %v", tt.expr, err)
			continue
		}
		if got != tt.want {
			t.Errorf("EvalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
		}
	}
}
