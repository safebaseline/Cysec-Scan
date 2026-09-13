// 证书透明度（CT）被动子域名收集：crt.name 按 apex 域名查询历史证书中出现的子域。
// 与爆破互补：不依赖字典，能发现未在字典内的历史子域；出站走全局代理与 UA 池。
package subdomain

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"cysec/internal/netproxy"
	"cysec/internal/ua"
)

// CertQueryURL 证书透明度查询接口（纯文本响应，每行一个子域，可含 *. 通配前缀）
const CertQueryURL = "https://crt.name/v1/search"

// certMaxResults 单域名最多采集子域数（防大域结果冲击后续解析与入库）
const certMaxResults = 2000

// CertQuery 通过 crt.name 证书透明度接口被动收集 domain 的子域名
func CertQuery(domain string, timeoutSec int) []string {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}
	client := netproxy.NewHTTPClient(timeoutSec, 0)
	req, err := http.NewRequest(http.MethodGet, CertQueryURL+"?apex="+url.QueryEscape(domain), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", ua.Get())
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return parseCertLines(domain, string(body))
}

// parseCertLines 解析纯文本响应：小写去空格、去 *. 前缀、仅保留 domain 的子域并去重（apex 本身不计）
func parseCertLines(domain, body string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, line := range strings.Split(body, "\n") {
		name := strings.TrimPrefix(normalizeDomain(strings.TrimSuffix(line, "\r")), "*.")
		if name == "" || name == domain {
			continue
		}
		if !strings.HasSuffix(name, "."+domain) {
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
		if len(out) >= certMaxResults {
			break
		}
	}
	return out
}

func normalizeDomain(s string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
}
