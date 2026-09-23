// 证书透明度（CT）被动子域名收集：crt.name（纯文本）为主源，crt.sh（JSON）备用——
// 按 apex 域名查询历史证书中出现的子域。与爆破互补：不依赖字典，能发现未在字典内的历史子域；
// 出站走全局代理与 UA 池。
package subdomain

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"cysec/internal/netproxy"
	"cysec/internal/ua"
)

// CertQueryURL 证书透明度主查询接口（纯文本响应，每行一个子域，可含 *. 通配前缀）
const CertQueryURL = "https://crt.name/v1/search"

// CertFallbackURL 备用接口（crt.sh JSON：name_value 内 \n 分隔多个子域）
const CertFallbackURL = "https://crt.sh"

// 可注入地址（测试指向本地 httptest，运行时为常量值）
var certPrimaryURL = CertQueryURL
var certFallbackURL = CertFallbackURL

// certMaxResults 单域名最多采集子域数（防大域结果冲击后续解析与入库）
const certMaxResults = 2000

// CertQuery 证书透明度被动收集 domain 的子域名：主源 crt.name，为空或失败时回落 crt.sh
func CertQuery(domain string, timeoutSec int) []string {
	if out := certQueryName(domain, timeoutSec); len(out) > 0 {
		return out
	}
	return certQuerySh(domain, timeoutSec)
}

// CertQueryDetail 收集结果带命中源标识（界面展示用）
type CertQueryDetail struct {
	Items  []string `json:"items"`
	Source string   `json:"source"` // crt.name / crt.sh / 空（均失败）
}

// CertQueryVerbose 带来源的收集（即时收集接口用）
func CertQueryVerbose(domain string, timeoutSec int) CertQueryDetail {
	if out := certQueryName(domain, timeoutSec); len(out) > 0 {
		return CertQueryDetail{Items: out, Source: "crt.name"}
	}
	if out := certQuerySh(domain, timeoutSec); len(out) > 0 {
		return CertQueryDetail{Items: out, Source: "crt.sh"}
	}
	return CertQueryDetail{}
}

func certQueryName(domain string, timeoutSec int) []string {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}
	body, ok := certHTTPGet(certPrimaryURL+"?apex="+url.QueryEscape(domain), timeoutSec)
	if !ok {
		return nil
	}
	return parseCertLines(domain, body)
}

func certQuerySh(domain string, timeoutSec int) []string {
	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil
	}
	// crt.sh 匹配子域语法：%.<apex>，output=json 按 name_value 展开子域（可含 \n 多行与 *. 前缀）
	body, ok := certHTTPGet(certFallbackURL+"/?q="+url.QueryEscape("%."+domain)+"&output=json", timeoutSec)
	if !ok {
		return nil
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal([]byte(body), &rows) != nil {
		return nil
	}
	joined := strings.Builder{}
	for _, r := range rows {
		joined.WriteString(r.NameValue)
		joined.WriteString("\n")
	}
	return parseCertLines(domain, joined.String())
}

// parseCertShJSON 解析 crt.sh JSON 响应为子域列表（测试用，与 certQuerySh 同逻辑）
func parseCertShJSON(domain, body string) []string {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if json.Unmarshal([]byte(body), &rows) != nil {
		return nil
	}
	joined := strings.Builder{}
	for _, r := range rows {
		joined.WriteString(r.NameValue)
		joined.WriteString("\n")
	}
	return parseCertLines(domain, joined.String())
}

func certHTTPGet(u string, timeoutSec int) (string, bool) {
	client := netproxy.NewHTTPClient(timeoutSec, 0)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", ua.Get())
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(body), true
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
