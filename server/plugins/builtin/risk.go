package builtin

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"cysec/internal/netproxy"
	"cysec/internal/plugins"
)

// 全部风险检测均为低风险、非破坏性检测（GET 请求 / TLS 握手 / Banner 判定）

// ---------- HTTP 安全头 / 配置风险 ----------

type headerRiskScanner struct{}

func (s *headerRiskScanner) Name() string     { return "header-risk" }
func (s *headerRiskScanner) Category() string { return "config" }

func (s *headerRiskScanner) Scan(ctx plugins.RiskContext) []plugins.VulnResult {
	if ctx.Web == nil {
		return nil
	}
	out := []plugins.VulnResult{}
	checks := []struct {
		header string
		vulnID string
		name   string
		sev    string
		desc   string
		sol    string
	}{
		{"X-Frame-Options", "CYSEC-HDR-001", "缺失 X-Frame-Options 头", "low",
			"响应缺失 X-Frame-Options 头，可能遭受点击劫持（Clickjacking）攻击。",
			"配置响应头 X-Frame-Options: DENY 或 SAMEORIGIN / CSP frame-ancestors。"},
		{"X-Content-Type-Options", "CYSEC-HDR-002", "缺失 X-Content-Type-Options 头", "low",
			"缺失 X-Content-Type-Options: nosniff，浏览器可能进行 MIME 嗅探导致 XSS。",
			"配置响应头 X-Content-Type-Options: nosniff。"},
		{"Strict-Transport-Security", "CYSEC-HDR-003", "缺失 HSTS 头", "low",
			"HTTPS 站点缺失 Strict-Transport-Security，可能遭受 SSL 剥离攻击。",
			"配置 Strict-Transport-Security: max-age=31536000。"},
		{"X-Powered-By", "CYSEC-HDR-004", "泄露 X-Powered-By 技术栈信息", "info",
			"响应头泄露后端技术栈，便于攻击者针对性利用。",
			"移除 X-Powered-By 响应头。"},
	}
	isHTTPS := strings.HasPrefix(ctx.Web.URL, "https")
	// 非成功响应（>=400）不做安全头检测；SPA/静态页面也跳过（无后端处理）
	if ctx.Web != nil && (ctx.Web.StatusCode >= 400 || ctx.Web.StatusCode == 0) {
		return nil
	}
	if len(ctx.Body) > 0 {
		bodyLen := len(ctx.Body)
		if bodyLen > 300 {
			bodyLen = 300
		}
		lb := strings.ToLower(ctx.Body[:bodyLen])
		if strings.Contains(lb, "<div id=") || strings.Contains(lb, "assets/index") || strings.Contains(lb, "noscript") {
			return nil // SPA 前端页面，安全头由 CDN/静态服务器控制
		}
	}
	respDump := webResponseDump(ctx)
	for _, c := range checks {
		if c.header == "Strict-Transport-Security" && !isHTTPS {
			continue
		}
		if ctx.Headers[c.header] == "" {
			out = append(out, plugins.VulnResult{
				VulnID: c.vulnID, Name: c.name, Severity: c.sev,
				Description: c.desc, Solution: c.sol, Component: "HTTP Header",
				Request:  fmt.Sprintf("GET %s HTTP/1.1", ctx.Web.URL),
				Response: respDump,
			})
		}
	}
	return out
}

func riskSortStrings(strs []string) {
	for i := 1; i < len(strs); i++ {
		for j := i; j > 0 && strs[j] < strs[j-1]; j-- {
			strs[j], strs[j-1] = strs[j-1], strs[j]
		}
	}
}

func riskTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// webResponseDump 由 RiskContext 重建响应报文
func webResponseDump(ctx plugins.RiskContext) string {
	if ctx.Web == nil {
		return ""
	}
	var b strings.Builder
	// Burp Suite 风格：状态行 + 全部响应头 + Content-Length + 空行 + 完整响应体
	fmt.Fprintf(&b, "HTTP/1.1 %d\r\n", ctx.Web.StatusCode)
	keys := make([]string, 0, len(ctx.Headers))
	for k := range ctx.Headers {
		keys = append(keys, k)
	}
	riskSortStrings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, ctx.Headers[k])
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(ctx.Body))
	b.WriteString("\r\n")
	b.WriteString(ctx.Body) // 完整响应体，不截断
	return b.String()
}

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
			})
		}
	}
	return out
}

// ---------- SSL/TLS 风险 ----------

type tlsRiskScanner struct{}

func (s *tlsRiskScanner) Name() string     { return "tls-risk" }
func (s *tlsRiskScanner) Category() string { return "ssl" }

func (s *tlsRiskScanner) Scan(ctx plugins.RiskContext) []plugins.VulnResult {
	if ctx.Web == nil || !strings.HasPrefix(ctx.Web.URL, "https") {
		return nil
	}
	out := []plugins.VulnResult{}
	u, err := url.Parse(ctx.Web.URL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	conn, err := netproxy.TLSDial(net.JoinHostPort(host, port), 5*time.Second,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionSSL30})
	if err != nil {
		return nil
	}
	defer conn.Close()
	ver := conn.ConnectionState().Version
	if ver <= tls.VersionTLS11 {
		out = append(out, plugins.VulnResult{
			VulnID:   "CYSEC-TLS-001",
			Request:  "TLS handshake " + net.JoinHostPort(host, port),
			Response: "negotiated " + tlsVersionName(ver), Name: "使用不安全的 TLS 版本（≤TLS1.1）", Severity: "high",
			Description: fmt.Sprintf("服务端协商使用 %s，存在 BEAST/POODLE 等协议级风险。", tlsVersionName(ver)),
			Solution:    "禁用 TLS1.0/1.1 与 SSLv3，仅启用 TLS1.2+。",
			Component:   "TLS", Evidence: "negotiated " + tlsVersionName(ver),
		})
	}
	cert := conn.ConnectionState().PeerCertificates[0]
	if time.Now().After(cert.NotAfter) {
		out = append(out, plugins.VulnResult{
			VulnID: "CYSEC-TLS-002", Name: "SSL 证书已过期", Severity: "medium",
			Description: "站点证书已于 " + cert.NotAfter.Format("2006-01-02") + " 过期。",
			Solution:    "更新 SSL 证书。", Component: "TLS",
			Evidence: "expired " + cert.NotAfter.Format("2006-01-02"),
		})
	}
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// ---------- 组件风险（版本披露 / 已知风险组件） ----------

type componentRiskScanner struct{}

func (s *componentRiskScanner) Name() string     { return "component-risk" }
func (s *componentRiskScanner) Category() string { return "component" }

func (s *componentRiskScanner) Scan(ctx plugins.RiskContext) []plugins.VulnResult {
	if ctx.Web == nil {
		return nil
	}
	out := []plugins.VulnResult{}
	server := ctx.Headers["Server"]
	if containsAny(server, "PHP/5.", "PHP/4.") {
		out = append(out, plugins.VulnResult{
			VulnID: "CYSEC-CMP-001", Name: "使用已停止维护的 PHP 版本", Severity: "medium",
			Description: "Server 头披露 PHP 主版本已 EOL：" + server,
			Solution:    "升级到受支持的 PHP 版本并隐藏版本号。",
			Component:   "PHP", Evidence: server,
		})
	}
	if containsAny(server, "Apache/2.2.", "Apache/2.0.") {
		out = append(out, plugins.VulnResult{
			VulnID: "CYSEC-CMP-002", Name: "使用 EOL 版本 Apache", Severity: "medium",
			Description: "Server 头披露 Apache 版本已停止维护：" + server,
			Solution:    "升级到受支持的 Apache 版本并隐藏版本号。",
			Component:   "Apache", Evidence: server,
		})
	}
	if containsAny(server, "Microsoft-IIS/6", "Microsoft-IIS/7.0") {
		out = append(out, plugins.VulnResult{
			VulnID: "CYSEC-CMP-003", Name: "使用老旧版本 IIS", Severity: "low",
			Description: "Server 头披露 IIS 版本较老：" + server,
			Solution:    "升级 IIS 或隐藏版本信息。",
			Component:   "IIS", Evidence: server,
		})
	}
	reqDesc := ""
	respDesc := ""
	if ctx.Web != nil {
		reqDesc = fmt.Sprintf("GET %s HTTP/1.1", ctx.Web.URL)
		respDesc = webResponseDump(ctx)
	}
	if ctx.Port != nil && reqDesc == "" {
		reqDesc = fmt.Sprintf("TCP connect %s:%d", ctx.IP, ctx.Port.Port)
		respDesc = ctx.Port.Banner
	}
	_ = reqDesc
	_ = respDesc
	// 端口层面的敏感服务暴露
	if ctx.Port != nil {
		switch ctx.Port.Service {
		case "Redis":
			out = append(out, plugins.VulnResult{
				VulnID:   "CYSEC-SVC-001",
				Request:  fmt.Sprintf("TCP connect %s:%d", ctx.IP, ctx.Port.Port),
				Response: ctx.Port.Banner, Name: "Redis 服务暴露", Severity: "high",
				Description: "Redis 端口对外可达，历史上多起未授权访问导致 RCE/数据泄露。",
				Solution:    "绑定 127.0.0.1、启用密码认证与 ACL，防火墙限制来源。",
				Component:   "Redis", Evidence: ctx.Port.Banner,
			})
		case "MySQL", "PostgreSQL", "MongoDB", "MSSQL":
			out = append(out, plugins.VulnResult{
				VulnID:   "CYSEC-SVC-002",
				Request:  fmt.Sprintf("TCP connect %s:%d", ctx.IP, ctx.Port.Port),
				Response: ctx.Port.Banner, Name: ctx.Port.Service + " 数据库服务暴露", Severity: "medium",
				Description: "数据库端口对外可达，存在弱口令与未授权访问风险。",
				Solution:    "限制数据库仅内网访问，启用强密码与最小权限账号。",
				Component:   ctx.Port.Service, Evidence: ctx.Port.Banner,
			})
		case "Docker":
			out = append(out, plugins.VulnResult{
				VulnID:   "CYSEC-SVC-003",
				Request:  fmt.Sprintf("TCP connect %s:%d", ctx.IP, ctx.Port.Port),
				Response: ctx.Port.Banner, Name: "Docker Remote API 未授权暴露", Severity: "critical",
				Description: "2375 端口 Docker API 对外暴露，可被未授权接管容器宿主机。",
				Solution:    "关闭 2375 对外暴露，启用 TLS 认证的 2376 或绑定本地 socket。",
				Component:   "Docker", Evidence: ctx.Port.Banner,
			})
		}
	}
	return out
}

func containsAny(s string, subs ...string) bool {
	sl := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(sl, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
