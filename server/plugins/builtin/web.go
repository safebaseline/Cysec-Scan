package builtin

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"cysec/internal/charset"
	"cysec/internal/netproxy"
	"cysec/internal/plugins"
	"cysec/internal/ua"
)

// probeWeb 探测一个 URL，返回 Web 资产信息（非破坏性 GET，出站走全局代理）
func ProbeWeb(rawURL, ip string, timeoutSec int) *plugins.WebResult {
	client := netproxy.NewHTTPClient(timeoutSec, 3)
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", ua.Get())
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = strings.Join(resp.Header.Values(k), "; ")
	}
	w := &plugins.WebResult{
		URL:         rawURL,
		IP:          ip,
		StatusCode:  resp.StatusCode,
		Server:      headers["Server"],
		ContentType: headers["Content-Type"],
		RespSize:    int64(len(body)),
		Headers:     headers,
		// 标题提取前先做编码归一（GBK/GB18030 → UTF-8）：此处漏归一会把 GBK 站点
		// 标题按原始字节入库，形成"Уѧ԰"式逐字节乱码（restrictedDoer 与 colly 爬虫均有归一）
		Title:       extractTitle(string(charset.Normalize(body, headers["Content-Type"]))),
		Certificate: peerCertificate(resp.TLS),
	}
	u := strings.SplitN(strings.TrimPrefix(rawURL, "http://"), "/", 2)
	if strings.HasPrefix(rawURL, "https") {
		u = strings.SplitN(strings.TrimPrefix(rawURL, "https://"), "/", 2)
		w.Protocol = "https"
	} else {
		w.Protocol = "http"
	}
	if hp := u[0]; strings.Contains(hp, ":") {
		parts := strings.Split(hp, ":")
		w.Domain = hostIsDomain(parts[0])
		w.Port = atoiSafe(parts[1])
	} else {
		w.Domain = hostIsDomain(hp)
		w.Port = 80
		if w.Protocol == "https" {
			w.Port = 443
		}
	}
	return w
}

func hostIsDomain(h string) string {
	if net.ParseIP(h) != nil {
		return ""
	}
	return h
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(m[1])
	if r := []rune(t); len(r) > 200 { // 按 rune 截断，避免中文标题从多字节字符中间切断产生非法 UTF-8
		t = string(r[:200])
	}
	return t
}

func peerCertificate(ts *tls.ConnectionState) string {
	if ts == nil || len(ts.PeerCertificates) == 0 {
		return ""
	}
	c := ts.PeerCertificates[0]
	return c.Subject.CommonName + " | issuer: " + c.Issuer.CommonName +
		" | expires: " + c.NotAfter.Format("2006-01-02")
}

// restrictedDoer 引擎使用的受限 HTTP 客户端封装（出站走全局代理）
type restrictedDoer struct{ timeoutSec int }

func (d restrictedDoer) Do(url string) (*plugins.HTTPResponse, error) {
	return d.do(url, "")
}

// DoReferer 带来源页 Referer 的受限请求（坏链检测用：防盗链站点无 Referer 会误判 404）
func (d restrictedDoer) DoReferer(url, referer string) (*plugins.HTTPResponse, error) {
	return d.do(url, referer)
}

func (d restrictedDoer) do(url, referer string) (*plugins.HTTPResponse, error) {
	client := netproxy.NewHTTPClient(d.timeoutSec, 0)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	ua.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	body = charset.Normalize(body, resp.Header.Get("Content-Type"))
	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = strings.Join(resp.Header.Values(k), "; ")
	}
	return &plugins.HTTPResponse{
		StatusCode:  resp.StatusCode,
		Headers:     headers,
		Body:        string(body),
		ContentType: headers["Content-Type"],
		RespSize:    int64(len(body)),
	}, nil
}

func NewDoer(timeoutSec int) plugins.HTTPDoer { return restrictedDoer{timeoutSec: timeoutSec} }
