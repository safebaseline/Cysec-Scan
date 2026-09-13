// Package builtin 内置插件集：注册所有默认发现/测绘/扫描/指纹/风险能力。
// 第三方扩展可实现 internal/plugins 中的接口并调用 Register*，无需修改核心逻辑。
package builtin

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"cysec/internal/netproxy"
	"cysec/internal/plugins"
)

func init() {
	plugins.RegisterProber(&tcpProber{})
	plugins.RegisterPortScanner(&connectScanner{})
	plugins.RegisterServiceIdentifier(&bannerIdentifier{})
	plugins.RegisterResolver(&goResolver{})
	plugins.RegisterMapper(&localMapper{})
	plugins.RegisterFingerprinter(&ruleFingerprinter{})
	// 漏洞检测链 = 漏洞规则库（nuclei/xray/afrog PoC）+ 敏感路径检测 + WIH JS 敏感信息检测。
	// 内置的 HTTP 安全头 / SSL/TLS / 组件版本检测已按需求移除，不再注册。
	plugins.RegisterRiskScanner(&leakRiskScanner{})
	plugins.RegisterRiskScanner(&wihRiskScanner{})
}

// ---------- 存活探测（TCP Ping，避免依赖原始套接字权限） ----------

type tcpProber struct{}

func (p *tcpProber) Name() string { return "tcp-prober" }

func (p *tcpProber) Probe(ip string, timeoutSec int) plugins.ProbeResult {
	for _, port := range []int{80, 443, 22, 445, 3389, 8080} {
		start := time.Now()
		conn, err := netproxy.DirectDialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), time.Duration(timeoutSec)*time.Second)
		if err == nil {
			conn.Close()
			return plugins.ProbeResult{Alive: true, Method: fmt.Sprintf("tcp/%d", port), LatencyMs: time.Since(start).Milliseconds()}
		}
	}
	return plugins.ProbeResult{Alive: false, Method: "tcp"}
}

// ---------- 端口扫描（TCP connect 扫描） ----------

type connectScanner struct{}

func (s *connectScanner) Name() string { return "connect-scanner" }

func (s *connectScanner) Scan(ip string, ports []int, timeoutSec int) []plugins.PortResult {
	type item struct{ open bool }
	out := make([]item, len(ports))
	sem := make(chan struct{}, 256)
	var wg sync.WaitGroup
	for i, port := range ports {
		wg.Add(1)
		go func(i, port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			conn, err := netproxy.DirectDialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), time.Duration(timeoutSec)*time.Second)
			if err == nil {
				conn.Close()
				out[i].open = true
			}
		}(i, port)
	}
	wg.Wait()
	results := make([]plugins.PortResult, 0)
	for i, it := range out {
		if it.open {
			results = append(results, plugins.PortResult{Port: ports[i], Protocol: "tcp", State: "open"})
		}
	}
	return results
}

// ---------- 服务识别（端口规则 + Banner 抓取） ----------

type bannerIdentifier struct{}

func (b *bannerIdentifier) Name() string { return "banner-identifier" }

var portService = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
	135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
	995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker", 3306: "MySQL",
	3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 7001: "WebLogic",
	8080: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

// 资产分拣：端口 -> 类别（需求文档 第七节）
var portCategory = map[int]string{
	22: "服务器", 3389: "服务器", 5900: "服务器",
	23: "网络设备", 161: "网络设备",
	53: "DNS", 25: "邮件服务", 110: "邮件服务", 143: "邮件服务",
	445: "文件服务", 139: "文件服务", 21: "文件服务",
	3306: "数据库", 5432: "数据库", 6379: "数据库", 27017: "数据库", 1433: "数据库", 1521: "数据库", 9200: "数据库", 11211: "数据库",
	80: "Web 服务器", 443: "Web 服务器", 8080: "Web 服务器", 8443: "Web 服务器", 8888: "Web 服务器", 7001: "中间件",
}

func (b *bannerIdentifier) Identify(ip string, pr plugins.PortResult, timeoutSec int) plugins.PortResult {
	if svc, ok := portService[pr.Port]; ok && pr.Service == "" {
		pr.Service = svc
	}
	conn, err := netproxy.DirectDialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(pr.Port)), time.Duration(timeoutSec)*time.Second)
	if err != nil {
		return pr
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
	conn.Write([]byte("\r\n"))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		pr.Banner = strings.TrimSpace(string(buf[:n]))
		if pr.Service == "" {
			pr.Service = guessServiceFromBanner(pr.Banner)
		}
		if v := extractVersion(pr.Banner); v != "" {
			pr.Version = v
		}
	}
	return pr
}

func guessServiceFromBanner(banner string) string {
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "ssh"):
		return "SSH"
	case strings.Contains(b, "ftp"):
		return "FTP"
	case strings.Contains(b, "http/1"):
		return "HTTP"
	case strings.Contains(b, "mysql") || strings.Contains(b, "mariadb"):
		return "MySQL"
	case strings.Contains(b, "redis"):
		return "Redis"
	case strings.Contains(b, "mongodb"):
		return "MongoDB"
	case strings.Contains(b, "postgres"):
		return "PostgreSQL"
	case strings.Contains(b, "smtp"):
		return "SMTP"
	case strings.HasPrefix(b, "220"):
		return "SMTP"
	case strings.HasPrefix(b, "230"):
		return "FTP"
	}
	return "未知"
}

var versionRe = regexp.MustCompile(`([0-9]+\.){1,3}[0-9]+[a-zA-Z0-9\-]*`)

func extractVersion(banner string) string {
	return versionRe.FindString(banner)
}

// CategoryOf 端口/服务 -> 资产分拣类别
func CategoryOf(port int, service string) string {
	if c, ok := portCategory[port]; ok {
		return c
	}
	switch {
	case strings.Contains(service, "HTTP"):
		return "Web 服务器"
	case strings.Contains(service, "SQL") || strings.Contains(service, "Redis") || strings.Contains(service, "MongoDB"):
		return "数据库"
	case service != "" && service != "未知":
		return "服务器"
	}
	return "未知资产"
}

// ---------- DNS 解析 ----------

type goResolver struct{}

func (r *goResolver) Name() string { return "go-resolver" }

func (r *goResolver) Resolve(domain string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resolver := &net.Resolver{}
	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil && cname != "" && strings.TrimSuffix(cname, ".") != domain {
		if addrs, err := resolver.LookupHost(ctx, strings.TrimSuffix(cname, ".")); err == nil && len(addrs) > 0 {
			return addrs[0], strings.TrimSuffix(cname, "."), nil
		}
	}
	addrs, err := resolver.LookupHost(ctx, domain)
	if err == nil && len(addrs) > 0 {
		return addrs[0], "", nil
	}
	return "", "", err
}
