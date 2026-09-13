package wih

import "testing"

func TestDefaultRulesCompile(t *testing.T) {
	st := DefaultSettings()
	if len(st.Rules) < 10 {
		t.Fatalf("默认规则过少: %d", len(st.Rules))
	}
	for _, r := range st.Rules {
		if _, err := Compile(r.Pattern); err != nil {
			t.Errorf("规则 %s 编译失败: %v", r.ID, err)
		}
	}
}

func TestScanBodyHits(t *testing.T) {
	st := DefaultSettings()
	body := `
		var config = { accessKeyId: "LTAI4GExampleKey12345678", api_token: "glc_exampleexampleexampleexample1234567890abcd" };
		var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";
		contact: someone@example.com
	`
	hits := ScanBody(st.Rules, body)
	got := map[string]bool{}
	for _, h := range hits {
		got[h.RuleID] = true
	}
	for _, want := range []string{"Aliyun_AK_ID", "jwt_token", "grafana_cloud_api_token"} {
		if !got[want] {
			t.Errorf("未命中规则 %s，实际命中: %v", want, got)
		}
	}
	// email 规则默认关闭，不应命中
	if got["email"] {
		t.Errorf("已禁用的 email 规则不应命中")
	}
}

func TestScanBodyDisabledRule(t *testing.T) {
	st := DefaultSettings()
	st.Rules = []Rule{{ID: "x", Name: "x", Enabled: false, Severity: "info", Pattern: "abc"}}
	if hits := ScanBody(st.Rules, "abc"); len(hits) != 0 {
		t.Fatalf("禁用规则不应命中: %v", hits)
	}
}

func TestExcludeRules(t *testing.T) {
	st := DefaultSettings()
	st.Excludes = []ExcludeRule{
		{Name: "排除指定站点的阿里云AK", ID: "Aliyun_AK_ID", Target: `regex:cdn\.example\.com`, Enabled: true},
	}
	h := Hit{RuleID: "Aliyun_AK_ID"}
	if !st.Excluded(h, "https://cdn.example.com/static/app.js") {
		t.Errorf("命中应被排除规则过滤")
	}
	if st.Excluded(h, "https://other.example.com/static/app.js") {
		t.Errorf("不匹配的 target 不应排除")
	}
	h2 := Hit{RuleID: "jwt_token"}
	if st.Excluded(h2, "https://cdn.example.com/static/app.js") {
		t.Errorf("不匹配的 id 不应排除")
	}
}

func TestNormalize(t *testing.T) {
	st := DefaultSettings()
	st.MaxJSPerSite = -1
	st.Rules = append(st.Rules, Rule{ID: "bad", Pattern: "([unclosed"}, Rule{ID: "", Pattern: "x"}, DefaultSettings().Rules[0])
	st.Normalize()
	if st.MaxJSPerSite != defaultMaxJS {
		t.Errorf("MaxJSPerSite 应被修正为默认值")
	}
	for _, r := range st.Rules {
		if r.ID == "bad" {
			t.Errorf("编译失败的规则应被剔除")
		}
		if r.Severity == "" || r.Severity == "info" && r.ID == "Aliyun_AK_ID" {
			// 保留原 severity
		}
	}
	// 重复 ID 应被去重
	count := map[string]int{}
	for _, r := range st.Rules {
		count[r.ID]++
	}
	for id, n := range count {
		if n > 1 {
			t.Errorf("规则 %s 重复 %d 次", id, n)
		}
	}
}

func TestExtractJSLinks(t *testing.T) {
	body := `
		<html><head>
		<script src="/static/app.js"></script>
		<script src='https://cdn.example.com/lib/vue.min.js'></script>
		<script src="data:application/javascript;base64,xxx"></script>
		<script>inline code</script>
		</head><body></body></html>
	`
	links := ExtractJSLinks("https://www.example.com/index.html", body, 10)
	if len(links) != 2 {
		t.Fatalf("应提取 2 个 JS 链接, got %v", links)
	}
	if links[0] != "https://www.example.com/static/app.js" {
		t.Errorf("相对路径解析错误: %s", links[0])
	}
	if links[1] != "https://cdn.example.com/lib/vue.min.js" {
		t.Errorf("绝对路径解析错误: %s", links[1])
	}
	// limit 生效
	if links := ExtractJSLinks("https://www.example.com/", body, 1); len(links) != 1 {
		t.Errorf("limit 未生效")
	}
}
