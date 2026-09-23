package engine

import (
	"net/url"
	"regexp"
	"strings"

	"cysec/internal/plugins"
	"cysec/plugins/builtin"
)

// newWebProber 返回 Web 探测函数（复用 builtin 的非破坏性 GET 探测）
func newWebProber(timeoutSec int) func(string, string) *plugins.WebResult {
	return func(rawURL, ip string) *plugins.WebResult {
		return builtin.ProbeWeb(rawURL, ip, timeoutSec)
	}
}

func fetchBody(rawURL string, timeoutSec int) string {
	resp, err := builtin.NewDoer(timeoutSec).Do(rawURL)
	if err != nil || resp == nil {
		return ""
	}
	return resp.Body
}

func newDoer(timeoutSec int, _ string) plugins.HTTPDoer {
	return builtin.NewDoer(timeoutSec)
}

var (
	linkRe  = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']|src\s*=\s*["']([^"']+)["']`)
	jsAPIRe = regexp.MustCompile(`(?i)["'](/api/[A-Za-z0-9_\-./\?=%&]+)["']`)
)

// extractLinks 从响应体提取同站链接与 API 路径
func extractLinks(baseURL, body string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(u string) {
		if !seen[u] && len(out) < 200 {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, m := range linkRe.FindAllStringSubmatch(body, -1) {
		raw := m[1]
		if raw == "" {
			raw = m[2]
		}
		if raw == "" || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "#") {
			continue
		}
		ref, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref)
		if abs.Hostname() != base.Hostname() {
			continue // 不越出授权范围
		}
		add(abs.String())
	}
	for _, m := range jsAPIRe.FindAllStringSubmatch(body, -1) {
		add(base.Scheme + "://" + base.Host + m[1])
	}
	return out
}

func orDefaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func builtinCategory(port int, service string) string {
	return builtin.CategoryOf(port, service)
}
