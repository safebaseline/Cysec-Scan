package mapper

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- 通用 HTTP 辅助 ----------

func httpGet(rawURL string) ([]byte, error) {
	resp, err := httpClient().Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return body, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))
	}
	return body, nil
}

func httpPost(rawURL string, payload any, headers map[string]string) ([]byte, error) {
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return body, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))
	}
	return body, nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// 各引擎官方默认端点；Base URL 支持界面配置（留空用默认，便于切换镜像/内网代理地址）
const (
	defaultFOFAURL     = "https://fofa.info/api/v1/search/all"
	defaultQuakeURL    = "https://quake.360.cn/api/v3/search/quake_service"
	defaultShodanURL   = "https://api.shodan.io/shodan/host/search"
	defaultZeroZoneURL = "https://0.zone/api/data/"
	defaultZoomEyeURL  = "https://api.zoomeye.org/v2/search"
)

// endpointURL 取配置的 Base URL（去掉尾部 / 便于拼接查询参数），空则用默认
func endpointURL(configured, def string) string {
	u := strings.TrimSpace(configured)
	if u == "" {
		u = def
	}
	return strings.TrimRight(u, "/")
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int(t)) {
			return strconv.Itoa(int(t))
		}
		return fmt.Sprint(t)
	case []any:
		for _, e := range t {
			if s := firstStr(e); s != "" {
				return s
			}
		}
	case nil:
		return ""
	}
	return ""
}

func firstInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	case []any:
		for _, e := range t {
			if n := firstInt(e); n > 0 {
				return n
			}
		}
	}
	return 0
}

// getServiceName 从测绘引擎返回的服务/协议信息推断服务名（复用端口规则）
func getServiceName(port int, proto, service, product string) string {
	if service != "" {
		return strings.ToUpper(service)
	}
	if strings.Contains(strings.ToLower(product), "nginx") || strings.Contains(strings.ToLower(product), "apache") {
		if port == 443 || port == 8443 {
			return "HTTPS"
		}
		return "HTTP"
	}
	p := strings.ToLower(proto)
	if strings.Contains(p, "http") || strings.Contains(p, "web") {
		if port == 443 || port == 8443 {
			return "HTTPS"
		}
		return "HTTP"
	}
	if s := portSvcGuess(port); s != "" {
		return s
	}
	return ""
}

func portSvcGuess(port int) string {
	m := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 110: "POP3",
		135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
		993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker",
		3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
		7001: "WebLogic", 8080: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9200: "Elasticsearch",
		11211: "Memcached", 27017: "MongoDB",
	}
	return m[port]
}

// ---------- 节流与限流重试 ----------

// providerMinIntervalMs 各引擎两次 API 请求的内置最小间隔（防 429）
var providerMinIntervalMs = map[string]int{
	"fofa": 1200, "quake": 800, "shodan": 1100, "0.zone": 1100, "zoomeye": 1100,
}

var (
	thMu   sync.Mutex
	thLast = map[string]time.Time{}
)

// effectiveInterval 取内置默认与配置的较大值
func effectiveInterval(name string, cfg Config) int {
	def := providerMinIntervalMs[name]
	if cfg.IntervalMs > def {
		return cfg.IntervalMs
	}
	return def
}

// throttle 保证同一引擎两次请求间隔不小于 interval 毫秒
func throttle(name string, intervalMs int) {
	if intervalMs <= 0 {
		return
	}
	for {
		thMu.Lock()
		now := time.Now()
		last, ok := thLast[name]
		next := last.Add(time.Duration(intervalMs) * time.Millisecond)
		if !ok || !now.Before(next) {
			thLast[name] = now
			thMu.Unlock()
			return
		}
		thMu.Unlock()
		time.Sleep(next.Sub(now))
	}
}

// isRateLimited 识别限流响应
func isRateLimited(status int, body []byte) bool {
	if status == 429 {
		return true
	}
	b := string(body)
	return strings.Contains(b, "请求速度过快") || strings.Contains(b, "Too Many Requests") || strings.Contains(b, "rate limit")
}

// providerGet 带节流与限流退避重试的 GET
func providerGet(name string, intervalMs int, rawURL string) ([]byte, error) {
	backoffs := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}
	var body []byte
	var err error
	for attempt := 0; ; attempt++ {
		throttle(name, intervalMs)
		body, err = httpGet(rawURL)
		if err == nil {
			return body, nil
		}
		if attempt >= len(backoffs) || !isRateLimited(errStatus(err), []byte(err.Error())) {
			return body, err
		}
		time.Sleep(backoffs[attempt])
	}
}

// providerPost 带节流与限流退避重试的 POST
func providerPost(name string, intervalMs int, rawURL string, payload any, headers map[string]string) ([]byte, error) {
	backoffs := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}
	var body []byte
	var err error
	for attempt := 0; ; attempt++ {
		throttle(name, intervalMs)
		body, err = httpPost(rawURL, payload, headers)
		if err == nil {
			return body, nil
		}
		if attempt >= len(backoffs) || !isRateLimited(errStatus(err), []byte(err.Error())) {
			return body, err
		}
		time.Sleep(backoffs[attempt])
	}
}

func errStatus(err error) int {
	// httpGet/httpPost 错误格式 "HTTP 429: body"
	if m := regexp.MustCompile(`HTTP (\d{3})`).FindStringSubmatch(err.Error()); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// ---------- FOFA ----------

// fofaProvider FOFA（fofa.info）：GET /api/v1/search/all，email+key 鉴权，qbase64 查询
type fofaProvider struct{}

func (p *fofaProvider) Name() string { return "fofa" }
func (p *fofaProvider) Ready(c Config) bool {
	return c.FOFAEnable && c.FOFAKey != ""
}

func (p *fofaProvider) Query(c Config, target string, isDomain bool) ([]Record, error) {
	q := fmt.Sprintf(`ip="%s"`, target)
	if isDomain {
		q = fmt.Sprintf(`domain="%s"`, target)
	}
	// fields 顺序决定 results 数组的解析顺序
	fields := "ip,port,protocol,domain,host,title,server"
	u := endpointURL(c.FOFABaseURL, defaultFOFAURL) + "?" + url.Values{
		"key":     {c.FOFAKey},
		"qbase64": {b64(q)},
		"fields":  {fields},
		"size":    {strconv.Itoa(c.Size)},
	}.Encode()
	body, err := httpGet(u)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Error   bool       `json:"error"`
		Errmsg  string     `json:"errmsg"`
		Size    int        `json:"size"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	if resp.Error {
		return nil, fmt.Errorf("FOFA API: %s", resp.Errmsg)
	}
	idx := map[string]int{}
	for i, f := range strings.Split(fields, ",") {
		idx[f] = i
	}
	get := func(row []string, f string) string {
		if i, ok := idx[f]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	recs := []Record{}
	for _, row := range resp.Results {
		ip, portS := get(row, "ip"), get(row, "port")
		port, _ := strconv.Atoi(portS)
		rec := Record{
			IP: ip, Port: port, Protocol: get(row, "protocol"),
			Domain: get(row, "domain"), URL: get(row, "host"),
			Title: get(row, "title"), Server: get(row, "server"),
		}
		rec.Service = getServiceName(port, rec.Protocol, "", rec.Server)
		recs = append(recs, rec)
	}
	return recs, nil
}

// ---------- Quake（360） ----------

// quakeProvider Quake：POST /api/v3/search/quake_service，X-QuakeToken 鉴权
type quakeProvider struct{}

func (p *quakeProvider) Name() string        { return "quake" }
func (p *quakeProvider) Ready(c Config) bool { return c.QuakeEnable && c.QuakeKey != "" }

func (p *quakeProvider) Query(c Config, target string, isDomain bool) ([]Record, error) {
	q := fmt.Sprintf(`ip:"%s"`, target)
	if isDomain {
		q = fmt.Sprintf(`domain:"%s"`, target)
	}
	body, err := providerPost(p.Name(), effectiveInterval(p.Name(), c), endpointURL(c.QuakeBaseURL, defaultQuakeURL), map[string]any{
		"query": q, "size": c.Size, "start": 0, "latest": true,
		"include": []string{"ip", "port", "transport", "domain", "service.name", "service.product",
			"service.http.title", "service.http.host", "service.http.server", "service.http.path"},
	}, map[string]string{"X-QuakeToken": c.QuakeKey})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    []struct {
			IP        string `json:"ip"`
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Domain    string `json:"domain"`
			Service   struct {
				Name    string `json:"name"`
				Product string `json:"product"`
				HTTP    struct {
					Title  string `json:"title"`
					Host   string `json:"host"`
					Server string `json:"server"`
					Path   string `json:"path"`
				} `json:"http"`
			} `json:"service"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("Quake API(%d): %s", resp.Code, resp.Message)
	}
	recs := []Record{}
	for _, d := range resp.Data {
		domain := d.Domain
		if domain == "" {
			domain = d.Service.HTTP.Host
		}
		rec := Record{
			IP: d.IP, Port: d.Port, Protocol: d.Transport, Domain: domain,
			Service: getServiceName(d.Port, d.Transport, d.Service.Name, d.Service.Product),
			Title:   d.Service.HTTP.Title, Server: d.Service.HTTP.Server,
			Fingerprint: d.Service.Product,
		}
		if strings.Contains(strings.ToLower(rec.Service), "http") {
			scheme := "http"
			if d.Port == 443 || d.Port == 8443 || strings.Contains(strings.ToLower(d.Service.Name), "https") {
				scheme = "https"
			}
			host := d.IP
			if domain != "" {
				host = domain
			}
			if (scheme == "http" && d.Port != 80) || (scheme == "https" && d.Port != 443) {
				host = fmt.Sprintf("%s:%d", host, d.Port)
			}
			rec.URL = scheme + "://" + host
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// ---------- Shodan ----------

// shodanProvider Shodan：GET /shodan/host/search，key 参数鉴权，minify 精简
type shodanProvider struct{}

func (p *shodanProvider) Name() string        { return "shodan" }
func (p *shodanProvider) Ready(c Config) bool { return c.ShodanEnable && c.ShodanKey != "" }

func (p *shodanProvider) Query(c Config, target string, isDomain bool) ([]Record, error) {
	q := fmt.Sprintf("ip:%s", target)
	if isDomain {
		q = fmt.Sprintf("hostname:%s", target)
	}
	u := endpointURL(c.ShodanBaseURL, defaultShodanURL) + "?" + url.Values{
		"key":    {c.ShodanKey},
		"query":  {q},
		"minify": {"true"},
	}.Encode()
	body, err := providerGet(p.Name(), effectiveInterval(p.Name(), c), u)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Error   string `json:"error"`
		Total   int    `json:"total"`
		Matches []struct {
			IPStr     string   `json:"ip_str"`
			Port      int      `json:"port"`
			Transport string   `json:"transport"`
			Product   string   `json:"product"`
			Hostnames []string `json:"hostnames"`
			Domains   []string `json:"domains"`
			HTTP      struct {
				Title  string `json:"title"`
				Host   string `json:"host"`
				Server string `json:"server"`
			} `json:"http"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("Shodan API: %s", resp.Error)
	}
	recs := []Record{}
	for _, m := range resp.Matches {
		domain := ""
		if len(m.Hostnames) > 0 {
			domain = m.Hostnames[0]
		}
		if domain == "" && len(m.Domains) > 0 {
			domain = m.Domains[0]
		}
		rec := Record{
			IP: m.IPStr, Port: m.Port, Protocol: m.Transport, Domain: domain,
			Service: getServiceName(m.Port, m.Transport, "", m.Product),
			Title:   m.HTTP.Title, Server: m.HTTP.Server, Fingerprint: m.Product,
		}
		if strings.Contains(strings.ToLower(rec.Service), "http") {
			scheme := "http"
			if m.Port == 443 || m.Port == 8443 {
				scheme = "https"
			}
			host := m.IPStr
			if m.HTTP.Host != "" {
				host = m.HTTP.Host
			} else if domain != "" {
				host = domain
			}
			if (scheme == "http" && m.Port != 80) || (scheme == "https" && m.Port != 443) {
				host = fmt.Sprintf("%s:%d", host, m.Port)
			}
			rec.URL = scheme + "://" + host
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// ---------- 0.zone（零零信安） ----------

// zeroZoneProvider 0.zone：POST /api/data/，zone_key_id 鉴权，query_type 切换资产类型
type zeroZoneProvider struct{}

func (p *zeroZoneProvider) Name() string        { return "0.zone" }
func (p *zeroZoneProvider) Ready(c Config) bool { return c.ZeroZoneEnable && c.ZeroZoneKeyID != "" }

func (p *zeroZoneProvider) Query(c Config, target string, isDomain bool) ([]Record, error) {
	// site 类型不支持 domain 字段，按域名查询时使用 url 字段（包含匹配）
	q := fmt.Sprintf("ip=%s", target)
	if isDomain {
		q = fmt.Sprintf("url==%s", target)
	}
	body, err := providerPost(p.Name(), effectiveInterval(p.Name(), c), endpointURL(c.ZeroZoneBaseURL, defaultZeroZoneURL), map[string]any{
		"query": q, "query_type": "site", "zone_key_id": c.ZeroZoneKeyID,
		"page": 1, "pagesize": minInt(c.Size, 100),
	}, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("0.zone API(%d): %s", resp.Code, resp.Message)
	}
	recs := []Record{}
	for _, d := range resp.Data {
		port := firstInt(d["port"])
		component := firstStr(d["component"])
		service := firstStr(d["service"])
		rec := Record{
			IP: firstStr(d["ip"]), Port: port, Domain: firstStr(d["cname"]),
			URL: firstStr(d["url"]), Title: firstStr(d["title"]),
			Server: component, Fingerprint: component,
			Service: getServiceName(port, service, service, component),
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// ---------- ZoomEye ----------

// zoomEyeProvider ZoomEye（钟馗之眼）：POST /v2/search，API-KEY 头鉴权，qbase64 查询
type zoomEyeProvider struct{}

func (p *zoomEyeProvider) Name() string        { return "zoomeye" }
func (p *zoomEyeProvider) Ready(c Config) bool { return c.ZoomEyeEnable && c.ZoomEyeKey != "" }

func (p *zoomEyeProvider) Query(c Config, target string, isDomain bool) ([]Record, error) {
	q := fmt.Sprintf(`ip="%s"`, target)
	if isDomain {
		q = fmt.Sprintf(`domain="%s"`, target)
	}
	body, err := providerPost(p.Name(), effectiveInterval(p.Name(), c), endpointURL(c.ZoomEyeBaseURL, defaultZoomEyeURL), map[string]any{
		"qbase64": b64(q), "page": 1, "pagesize": minInt(c.Size, 100), "sub_type": "v4",
	}, map[string]string{"API-KEY": c.ZoomEyeKey})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("响应解析失败: %v", err)
	}
	// ZoomEye 成功码为 60000
	if resp.Code != 60000 {
		return nil, fmt.Errorf("ZoomEye API(%d): %s", resp.Code, resp.Message)
	}
	recs := []Record{}
	for _, d := range resp.Data {
		svc, _ := d["service"].(map[string]any)
		port := firstInt(d["port"])
		transport := firstStr(d["transport"])
		serviceName := firstStr(svc["name"])
		product := firstStr(svc["product"])
		var httpTitle, httpHost string
		if httpv, ok := svc["http"].(map[string]any); ok {
			httpTitle = firstStr(httpv["title"])
			httpHost = firstStr(httpv["host"])
		}
		rec := Record{
			IP: firstStr(d["ip"]), Port: port, Protocol: transport,
			Domain: firstStr(d["domain"]), Title: httpTitle, Fingerprint: product,
			Service: getServiceName(port, transport, serviceName, product),
		}
		if httpHost != "" {
			rec.URL = httpHost
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
