package builtin

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

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
		Title:       extractTitle(string(body)),
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
	if len(t) > 200 {
		t = t[:200]
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
	client := netproxy.NewHTTPClient(d.timeoutSec, 0)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua.Get())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
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
