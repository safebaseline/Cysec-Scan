package builtin

import (
	"fmt"
	"strings"

	"cysec/internal/plugins"
)

// 内置风险检测仅保留敏感路径泄露检测（非破坏性 GET 探测）。
// 安全头 / SSL/TLS / 组件版本检测已按需求移除；漏洞检测主链路为规则库 PoC + WIH。

// ---------- 信息泄露 / 敏感路径（非破坏性 GET 探测） ----------

type leakRiskScanner struct{}

func (s *leakRiskScanner) Name() string     { return "leak-risk" }
func (s *leakRiskScanner) Category() string { return "leak" }

var leakPaths = []struct {
	path   string
	vulnID string
	name   string
	sev    string
	hit    func(status int, body string, ct string) bool
}{
	{"/.git/config", "CYSEC-LEAK-001", "Git 仓库信息泄露", "high",
		func(st int, b, ct string) bool { return st == 200 && strings.Contains(b, "[core]") }},
	{"/.env", "CYSEC-LEAK-002", "环境变量文件泄露", "high",
		func(st int, b, ct string) bool {
			return st == 200 && len(b) > 10 && (strings.Contains(b, "APP_KEY") || strings.Contains(b, "DB_PASSWORD") ||
				strings.Contains(b, "DATABASE_URL") || strings.Contains(b, "SECRET_KEY") ||
				(strings.Contains(b, "APP_ENV") && strings.Contains(b, "=")))
		}},
	{"/server-status", "CYSEC-LEAK-003", "Apache server-status 暴露", "medium",
		func(st int, b, ct string) bool {
			return st == 200 && strings.Contains(strings.ToLower(b), "apache status")
		}},
	{"/phpmyadmin/", "CYSEC-LEAK-004", "phpMyAdmin 管理端暴露", "medium",
		func(st int, b, ct string) bool {
			return st == 200 && strings.Contains(strings.ToLower(b), "phpmyadmin")
		}},
	{"/actuator/health", "CYSEC-LEAK-005", "Spring Boot Actuator 暴露", "high",
		func(st int, b, ct string) bool {
			return st == 200 && strings.Contains(b, "UP") && strings.Contains(strings.ToLower(ct), "json")
		}},
	{"/robots.txt", "CYSEC-LEAK-006", "robots.txt 泄露敏感路径", "info",
		func(st int, b, ct string) bool { return st == 200 && strings.Contains(b, "Disallow") }},
}

func (s *leakRiskScanner) Scan(ctx plugins.RiskContext) []plugins.VulnResult {
	if ctx.Web == nil || ctx.Client == nil {
		return nil
	}
	out := []plugins.VulnResult{}
	base := strings.TrimRight(ctx.Web.URL, "/")
	for _, lp := range leakPaths {
		resp, err := ctx.Client.Do(base + lp.path)
		if err != nil || resp == nil {
			continue
		}
		// 403/404/5xx 响应不判为泄露
		if resp.StatusCode >= 400 {
			continue
		}
		// SPA/通用页面过滤
		bodyLen := len(resp.Body)
		if bodyLen > 300 {
			bodyLen = 300
		}
		lr := strings.ToLower(string(resp.Body[:bodyLen]))
		if strings.Contains(lr, "<div id=") || strings.Contains(lr, "assets/index") || strings.Contains(lr, "noscript") {
			continue // SPA 页面，非真实后端响应
		}
		if lp.hit(resp.StatusCode, resp.Body, resp.ContentType) {
			respDump := fmt.Sprintf("HTTP/1.1 %d\r\nContent-Type: %s\r\n\r\n%s", resp.StatusCode, resp.ContentType, riskTruncate(resp.Body, 4096))
			out = append(out, plugins.VulnResult{
				VulnID:      lp.vulnID,
				Name:        lp.name,
				Severity:    lp.sev,
				Description: "敏感路径可被未授权访问（HTTP " + fmt.Sprint(resp.StatusCode) + "）。",
				Solution:    "限制该路径访问权限或从生产环境移除。",
				Evidence:    "GET " + lp.path + " -> " + fmt.Sprint(resp.StatusCode),
				Request:     "GET " + ctx.Web.URL + lp.path + " HTTP/1.1",
				Response:    respDump,
				Component:   "Web",
				Scanner:     "builtin",
			})
		}
	}
	return out
}

func riskTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
