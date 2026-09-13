// 模板变量解析：学习 nuclei 的变量系统——variables/set 定义、上下文变量、
// 辅助函数（rand*/base64/replace 等）、以及执行时对 Words/DSL 中变量的替换。
package vulnrule

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// tmplVarRe 匹配 {{varName}} 或 {{func(args)}}
var tmplVarRe = regexp.MustCompile(`\{\{([^}]+)\}\}`)

// ParseVariablesYAML 解析 nuclei variables / xray-afrog set 段的值为字符串。
// 支持：字面量、base64()、md5()、url_encode()、hex()、reverse()、randstr、rand_text_*()。
// 返回 false 表示含不可解析的动态函数参数（如 md5(r1) 引用其他变量）。
func ParseVariablesYAML(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			if resolved, ok := resolveVarExpr(s); ok {
				out[k] = resolved
			} else {
				out[k] = s // 保留原始表达式，执行时可能可解
			}
		} else {
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

// resolveVarExpr 解析单个变量表达式
func resolveVarExpr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", true
	}
	// 函数调用
	if m := regexp.MustCompile(`^(base64|md5|url_encode|urlencode|hex|reverse)\((.+)\)$`).FindStringSubmatch(s); m != nil {
		inner := strings.Trim(m[2], `"'`)
		switch m[1] {
		case "base64":
			return b64(inner), true
		case "md5":
			return md5Hex(inner), true
		case "url_encode", "urlencode":
			return urlEncode(inner), true
		case "hex":
			return hexEncode(inner), true
		case "reverse":
			return reverseStr(inner), true
		}
	}
	// 随机类函数 → 确定占位值
	if m := regexp.MustCompile(`^(randstr|rand_text_alpha|rand_text_numeric|rand_text_alphanumeric|rand_base|rand_int|rand_char|rand_ip)\(`).FindStringSubmatch(s); m != nil {
		return "cysec", true
	}
	if s == "randstr" {
		return "cysec", true
	}
	// 字面量（可能带引号）
	return strings.Trim(s, `"'`), true
}

// SubstituteAll 对 ExecStep 的 Path/Body/Headers/Words/Regexes/DSL 做完整变量替换。
// 在执行前调用，确保匹配器中的模板变量也被替换。
func SubstituteAll(step *ExecStep, vars map[string]string, baseURL string) {
	sub := func(s string) string { return substituteRich(s, vars, baseURL) }
	step.Path = sub(step.Path)
	step.Body = sub(step.Body)
	for k, v := range step.Headers {
		step.Headers[k] = sub(v)
	}
	for i := range step.Groups {
		for j := range step.Groups[i].Words {
			step.Groups[i].Words[j] = sub(step.Groups[i].Words[j])
		}
		for j := range step.Groups[i].Regexes {
			step.Groups[i].Regexes[j] = sub(step.Groups[i].Regexes[j])
		}
		// DSL 表达式（Type="dsl"）也做变量替换
		if step.Groups[i].Type == "dsl" {
			for j := range step.Groups[i].Words {
				step.Groups[i].Words[j] = sub(step.Groups[i].Words[j])
			}
		}
	}
}

// substituteRich 增强版变量替换：支持上下文变量、自定义变量、rand 类、函数调用
func substituteRich(s string, vars map[string]string, baseURL string) string {
	u := parseURL(baseURL)
	host, port, scheme, path := "", "", "", ""
	if u != nil {
		host = u.Hostname()
		port = u.Port()
		scheme = u.Scheme
		path = u.Path
	}
	hostname := host
	if port != "" && port != "80" && port != "443" {
		hostname = host + ":" + port
	}

	repl := map[string]string{
		"{{BaseURL}}":  baseURL,
		"{{RootURL}}":  baseURL,
		"{{Hostname}}": hostname,
		"{{Host}}":     host,
		"{{Port}}":     port,
		"{{Scheme}}":   scheme,
		"{{Path}}":     path,
		"{{randstr}}":  "cysec",
		// OOB 占位（exec.go 的 OOB 块会先替换为实际值；此处兜底处理残留）
		"{{interactsh-url}}": "oob.placeholder.invalid",
	}

	// 自定义变量优先
	for k, v := range vars {
		repl["{{"+k+"}}"] = v
	}

	// 逐个替换已知变量
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}

	// 处理剩余的 {{func(...)}} 调用
	s = tmplVarRe.ReplaceAllStringFunc(s, func(m string) string {
		expr := strings.TrimSuffix(strings.TrimPrefix(m, "{{"), "}}")
		expr = strings.TrimSpace(expr)
		if resolved, ok := resolveVarExpr(expr); ok {
			return resolved
		}
		return m // 无法解析的保留原样
	})

	return s
}

// ---- 辅助函数 ----

func parseURL(raw string) *url.URL {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func urlEncode(s string) string {
	return url.QueryEscape(s)
}

func hexEncode(s string) string {
	return hex.EncodeToString([]byte(s))
}

func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
