package builtin

import (
	"regexp"
	"strings"

	"cysec/internal/plugins"
)

// ruleFingerprinter 规则指纹库（Web Server / Framework / CMS / Frontend）
// 指纹规则支持通过规则文件动态更新（见 configs/fingerprints.yaml），此处为内置基础库。
type ruleFingerprinter struct{}

func (f *ruleFingerprinter) Name() string { return "rule-fingerprinter" }

type fpRule struct {
	Category string
	Name     string
	Re       *regexp.Regexp
}

var fpRules = compileRules([][3]string{
	// Web Server
	{"web_server", "Nginx", `(?i)^nginx`},
	{"web_server", "Apache", `(?i)^apache|httpd`},
	{"web_server", "IIS", `(?i)^microsoft-iis`},
	{"web_server", "Caddy", `(?i)^caddy`},
	{"web_server", "Tomcat", `(?i)^coyote|tomcat`},
	{"web_server", "Jetty", `(?i)^jetty`},
	// Framework
	{"framework", "Spring", `(?i)\bspring[-_ ]?(boot|framework|security|mvc)|x-spring|whitelabel error page`},
	{"framework", "Laravel", `(?i)laravel[_-]?session|\blaravel\b`},
	{"framework", "ThinkPHP", `(?i)think_php|thinkphp`},
	{"framework", "Django", `(?i)csrfmiddlewaretoken|\bdjango\b`},
	{"framework", "Flask", `(?i)\bflask\b`},
	{"framework", "Express", `(?i)x-powered-by:\s*express|^express$`},
	{"framework", "ASP.NET", `(?i)asp\.net|x-aspnet-version`},
	// CMS
	{"cms", "WordPress", `(?i)wp-content|wordpress`},
	{"cms", "Discuz", `(?i)discuz`},
	{"cms", "Joomla", `(?i)joomla`},
	{"cms", "Drupal", `(?i)drupal`},
	{"cms", "Shiro", `(?i)rememberme=deleteme`},
	// Frontend
	{"frontend", "Vue", `(?i)\bvue(?:\.js|\.runtime)?\b|v-bind|__vue__|data-v-app`},
	{"frontend", "React", `(?i)\breact(?:[-.]dom|\.production)?\b|_reactroot|data-reactroot|__react`},
	{"frontend", "Angular", `(?i)\bangular(?:\.min)?\.js\b|ng-version|ng-app`},
	{"frontend", "jQuery", `(?i)jquery`},
	{"frontend", "Bootstrap", `(?i)bootstrap`},
})

func compileRules(rs [][3]string) []fpRule {
	out := []fpRule{}
	for _, r := range rs {
		out = append(out, fpRule{Category: r[0], Name: r[1], Re: regexp.MustCompile(r[2])})
	}
	return out
}

func (f *ruleFingerprinter) Match(web plugins.WebResult, body string) []plugins.FingerprintResult {
	hay := strings.ToLower(strings.Join([]string{
		web.Server,
		web.Headers["X-Powered-By"],
		web.Headers["Set-Cookie"],
		body,
	}, "\n"))
	results := []plugins.FingerprintResult{}
	seen := map[string]bool{}
	for _, r := range fpRules {
		key := r.Category + "/" + r.Name
		if seen[key] {
			continue
		}
		if r.Re.MatchString(hay) {
			seen[key] = true
			results = append(results, plugins.FingerprintResult{Category: r.Category, Name: r.Name, Detail: "matched rule " + r.Name})
		}
	}
	return results
}
