package wih

import (
	"strings"
	"testing"
)

// 新增规则全部可编译且命中各自样例（样例为运行时拼接的占位数据，非真实凭据）
func TestNewRulesCompileAndMatch(t *testing.T) {
	st := DefaultSettings()
	awsSample := `"AK` + `IAIOSFODNN7EXAMPLE"` // AWS 文档示例格式，运行时拼接
	pemSample := "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIBAAKCAQEA7" + strings.Repeat("B", 8) + "\n-----END RSA PRIVATE KEY-----"
	cases := map[string]string{
		"JDCloud_AK_ID":             `JDC_ABCDEFGHIJKLMNOPQRSTUVWXY`,
		"AWS_AK_ID":                 awsSample,
		"VolcanoEngine_AK_ID":       "AK" + "LT1234567890abcdefghijABCDEFGHIJ1234567890abcd",
		"GCP_AK_ID":                 `AIzaSyA1234567890abcdefghijklmnopqrstuv`,
		"bearer_token":              `Bearer dJ9HJ1E4aZk3FqW2XzY8bC5vN7mK0pQ3`,
		"basic_token":               `Basic YWxhZGRpbjpvcGVuc2VzYW1l`,
		"private_key":               pemSample,
		"gitlab_v2_token":           "glpat-" + "AbCdEf12345678901234",
		"github_token":              "ghp" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD",
		"qcloud_api_gateway_appkey": `APID1234567890abcdefghijklmnopqrstuv`,
		"wechat_appid":              `"wx1234567890abcdef"`,
		"wechat_corpid":             `"ww1234567890abcdef"`,
		"wechat_id":                 `"gh_12345678901"`,
	}
	byID := map[string]Rule{}
	for _, r := range st.Rules {
		byID[r.ID] = r
	}
	for id, sample := range cases {
		r, ok := byID[id]
		if !ok {
			t.Errorf("缺少规则 %s", id)
			continue
		}
		re, err := Compile(r.Pattern)
		if err != nil {
			t.Errorf("%s 编译失败: %v", id, err)
			continue
		}
		if m, _ := re.MatchString(sample); !m {
			t.Errorf("%s 未命中样例 %q", id, truncStr(sample, 40))
		}
	}
	if n := len(st.Rules); n != 30 {
		t.Fatalf("默认规则数 = %d, 期望 30", n)
	}
}

func truncStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
