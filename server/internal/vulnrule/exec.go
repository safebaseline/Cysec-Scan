package vulnrule

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"cysec/internal/netproxy"
	"cysec/internal/oob"
	"cysec/internal/ua"
)

// RunResult 单规则执行结果
type RunResult struct {
	Matched  bool   `json:"matched"`
	Evidence string `json:"evidence"`
	Request  string `json:"request,omitempty"`  // 命中请求的原始报文
	Response string `json:"response,omitempty"` // 命中响应的原始报文
	Requests int    `json:"requests"`
	Err      string `json:"error,omitempty"`
}

// Run 对目标 URL 执行规则（非破坏性：仅按规则发起 HTTP 请求并匹配响应）
func Run(rule *Rule, target string, timeoutSec int) RunResult {
	var exec ExecRule
	if rule.Parsed != "" {
		if err := json.Unmarshal([]byte(rule.Parsed), &exec); err != nil || len(exec.Steps) == 0 {
			return RunResult{Err: "规则不可执行"}
		}
	} else if rule.execTmp != nil {
		exec = *rule.execTmp
	} else {
		return RunResult{Err: "规则不可执行"}
	}
	if !isSafeMethod(exec.Steps) {
		return RunResult{Err: "规则包含非安全方法，已跳过"}
	}

	// OOB 反连检测：复用全局会话，为本条规则生成唯一子域
	var oobSrv *oob.Server
	var oobSubdomain string // 本规则的唯一子域前缀（用于精确匹配回调）
	if exec.NeedsOOB {
		srv, err := oob.New() // 全局单例（首次注册，后续复用）
		if err != nil {
			return RunResult{Err: "OOB服务不可用: " + err.Error()}
		}
		oobSrv = srv
		oobURL := oobSrv.NewURL() // 每条规则独立子域，同一会话
		oobSubdomain = strings.SplitN(oobURL, ".", 2)[0]
		for i := range exec.Steps {
			exec.Steps[i].Path = strings.ReplaceAll(exec.Steps[i].Path, "{{interactsh-url}}", oobURL)
			exec.Steps[i].Body = strings.ReplaceAll(exec.Steps[i].Body, "{{interactsh-url}}", oobURL)
			for k, v := range exec.Steps[i].Headers {
				exec.Steps[i].Headers[k] = strings.ReplaceAll(v, "{{interactsh-url}}", oobURL)
			}
		}
		if exec.Vars == nil {
			exec.Vars = map[string]string{}
		}
		exec.Vars["interactsh-url"] = oobURL
	}

	res := RunResult{}
	base := strings.TrimRight(target, "/")

	// 基线指纹探测：CDN/WAF/SPA 对所有路径返回同一页面 → 用随机路径取基线
	baselineHash, _ := baselineFingerprint(base, timeoutSec)
	if baselineHash != "" {
		// 该目标是 CDN/WAF/SPA，标记基线以便后续每步响应对比
	}

	// WAF/CDN 拦截页检测：第一步先探测基线响应
	// 如果根路径返回 403/404 且体很小，标记该目标可能有 WAF，后续规则需更严格
	wafBlocked := detectWAF(base, timeoutSec)

	stepOK := make([]bool, len(exec.Steps))
	for i, st := range exec.Steps {
		ok, ev, reqText, respText, err := runStep(st, exec.Vars, base, timeoutSec)
		// WAF 拦截页过滤：目标被 WAF 拦截时，非 2xx 响应不视为命中
		if wafBlocked && ok {
			for _, g := range st.Groups {
				if g.Type == "dsl_pass" {
					ok = false
					ev += " [WAF拦截页过滤]"
					break
				}
			}
		}
		// 基线响应对比：对无可靠匹配条件的组生效
		// dsl_pass（无条件通过）与 internal 匹配器（nuclei 语义中不参与命中判定，
		// 特征词过于通用）都不能独立证明漏洞，若响应与随机路径基线完全一致，
		// 说明命中内容是 CDN/WAF/SPA 的通用页面而非漏洞响应。
		// 非 internal 的 word/regex/status 组有明确特征，不做基线否决。
		if ok && baselineHash != "" {
			allUnreliable := len(st.Groups) > 0
			for _, g := range st.Groups {
				if g.Type != "dsl_pass" && !g.Internal {
					allUnreliable = false
					break
				}
			}
			if allUnreliable {
				respBody := ""
				if parts := strings.SplitN(respText, "\r\n\r\n", 2); len(parts) == 2 {
					respBody = parts[1]
				}
				if isBaselineMatch(respBody, baselineHash) {
					ok = false
					ev += " [基线对比：CDN/SPA通用页面]"
				}
			}
		}
		res.Requests++
		if err != nil {
			res.Err = err.Error()
			continue
		}
		stepOK[i] = ok
		if ok && res.Evidence == "" {
			res.Evidence = ev
			res.Request = reqText
			res.Response = respText
		}
	}
	// OOB 反连检测：智能等待回调（立即查→1秒轮询→超时5秒），精确匹配本规则的子域
	if exec.NeedsOOB && oobSrv != nil {
		interactions := oobSrv.WaitForCallback(oobSubdomain, 5*time.Second)
		if len(interactions) > 0 {
			res.Matched = true
			proto := interactions[0].Protocol
			res.Evidence = fmt.Sprintf("OOB callback: %s from %s (host=%s)", proto, interactions[0].Remote, interactions[0].Host)
			if interactions[0].RawReq != "" {
				req := interactions[0].RawReq
				if len(req) > 200 {
					req = req[:200]
				}
				res.Response = "OOB interaction:\n" + req
			}
			return res
		}
		// 无回调 → 不命中（即使 HTTP 步骤匹配了，没有 OOB 确认就不算漏洞）
		res.Matched = false
		return res
	}

	// 步骤间组合
	logic := exec.Logic
	if logic == "" {
		logic = "and"
	}
	if len(exec.Steps) == 1 {
		res.Matched = stepOK[0] && res.Err == ""
		return res
	}
	if logic == "or" {
		for _, ok := range stepOK {
			if ok {
				res.Matched = true
				return res
			}
		}
		return res
	}
	// and：全部命中且无错误
	if res.Err != "" {
		return res
	}
	for _, ok := range stepOK {
		if !ok {
			return res
		}
	}
	res.Matched = true
	return res
}

func isSafeMethod(steps []ExecStep) bool {
	for _, s := range steps {
		switch s.Method {
		case "GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE":
		default:
			return false
		}
	}
	return true
}

// detectWAF 检测目标是否被 WAF/CDN 拦截（根路径 403/404 且响应体短）
func detectWAF(base string, timeoutSec int) bool {
	client := &http.Client{
		Timeout:       time.Duration(maxInt(timeoutSec, 5)) * time.Second,
		Transport:     netproxy.NewTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("GET", base+"/", nil)
	if err != nil {
		return false
	}
	ua.Apply(req)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if (resp.StatusCode == 403 || resp.StatusCode == 404) && len(body) < 600 {
		return true
	}
	return false
}

func runStep(st ExecStep, vars map[string]string, base string, timeoutSec int) (bool, string, string, string, error) {
	// 完整变量替换：Path/Body/Headers/Matchers 中的 {{var}} 全部替换（含自定义变量、rand 类、函数调用）
	SubstituteAll(&st, vars, base)
	fullURL := buildURL(base, st.Path)
	if fullURL == "" {
		return false, "", "", "", fmt.Errorf("路径为空")
	}
	client := &http.Client{
		Timeout:   time.Duration(maxInt(timeoutSec, 5)) * time.Second,
		Transport: netproxy.NewTransport(),
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !st.FollowRedirect || len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	method := orDefault(st.Method, "GET")
	requestBody := st.Body
	var body io.Reader
	if requestBody != "" {
		body = strings.NewReader(requestBody)
	}
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return false, "", "", "", err
	}
	ua.Apply(req)
	for k, v := range st.Headers {
		req.Header.Set(k, v)
	}
	reqDump := dumpRequest(method, fullURL, req, requestBody)
	reqStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, "", "", "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	headerText := headersText(resp)
	elapsedMs := time.Since(reqStart).Milliseconds()

	// 匹配：含 || 分支时任一分支全真即命中；否则按组间 and/or
	if len(st.Branches) > 0 {
		matched := false
		for _, branch := range st.Branches {
			all := true
			for _, g := range branch {
				if !matchGroup(g, resp.StatusCode, string(respBody), headerText, elapsedMs, method) {
					all = false
					break
				}
			}
			if all {
				matched = true
				break
			}
		}
		ev := fmt.Sprintf("%s %s -> HTTP %d %dms", method, shortPath(fullURL), resp.StatusCode, elapsedMs)
		return matched, ev, reqDump, dumpResponse(resp, respBody), nil
	}
	logic := orDefault(st.Logic, "and")
	results := make([]bool, len(st.Groups))
	for gi, g := range st.Groups {
		results[gi] = matchGroup(g, resp.StatusCode, string(respBody), headerText, elapsedMs, method)
	}
	matched := combine(results, logic)
	ev := fmt.Sprintf("%s %s -> HTTP %d (%s)", method, shortPath(fullURL), resp.StatusCode, matchNames(st.Groups, results))
	return matched, ev, reqDump, dumpResponse(resp, respBody), nil
}

// dumpRequest 重建请求报文（方法/URL/头/体，体截断）
func dumpRequest(method, url string, req *http.Request, body string) string {
	var b strings.Builder
	// Burp Suite 风格请求报文：请求行 + Host 头 + 全部请求头 + 空行 + 完整请求体
	u, _ := urlParse(url)
	host := ""
	if u != nil {
		host = u.Host
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, url)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		for _, v := range req.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	// Content-Length: Go http 包发送时自动添加，此处不重复
	b.WriteString("\r\n")
	if body != "" {
		b.WriteString(body)
	}
	return b.String()
}

// dumpResponse 重建响应报文（状态/头/体，体截断）
func dumpResponse(resp *http.Response, body []byte) string {
	var b strings.Builder
	// Burp Suite 风格响应报文：状态行 + 全部响应头（含 Content-Length）+ 空行 + 完整响应体
	fmt.Fprintf(&b, "HTTP/1.1 %s\r\n", resp.Status)
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

func matchGroup(g ExecGroup, status int, body, headerText string, elapsedMs int64, dslMethod string) bool {
	// 时延类匹配（时间盲注检测）
	switch g.Type {
	case "latency_gte":
		return len(g.Status) > 0 && elapsedMs >= int64(g.Status[0])
	case "latency_lte":
		return len(g.Status) > 0 && elapsedMs <= int64(g.Status[0])
	}
	part := g.Part
	if part == "" {
		part = "body"
	}
	var hay string
	switch part {
	case "header":
		hay = headerText
	case "all":
		hay = body + "\n" + headerText
	default:
		hay = body
	}
	if g.Lowercase {
		hay = strings.ToLower(hay)
	}
	var ok bool
	switch g.Type {
	case "dsl_pass":
		// 全 internal 匹配器：不能作为命中依据，只做最宽松的合理性校验。
		// 误报率极高（92%），因此必须严格过滤：
		// 1. 状态码必须 200（其余全部拒绝）
		ok = status == 200
		// 2. 响应体足够长（>200字节，排除 CDN/WAF 简短拦截页和空壳）
		if ok && len(body) < 200 {
			ok = false
		}
		// 3. WAF/CDN/错误页关键词
		if ok {
			lb := strings.ToLower(body[:min(len(body), 500)])
			for _, fp := range []string{"access denied", "access forbidden", "blocked", "captcha", "security check",
				"request blocked", "not authorized", "waf", "firewall", "rate limit", "too many requests",
				"403 forbidden", "404 not found", "error page", "web application error",
				"not found", "error occurred", "server error", "bad request", "unauthorized"} {
				if strings.Contains(lb, fp) {
					ok = false
					break
				}
			}
		}
		// 4. SPA/静态前端页面特征（通用页面，与漏洞无关）
		if ok {
			has_spa := strings.Contains(body, "<div id=") || strings.Contains(body, "assets/index-") ||
				strings.Contains(body, "assets/main.") || strings.Contains(body, "noscript")
			if has_spa {
				ok = false
			}
		}
		// 5. 响应体看起来是纯静态页（无动态内容特征）
		if ok {
			has_dynamic := strings.Contains(body, "<?php") || strings.Contains(body, "<%") ||
				strings.Contains(body, "{{") || strings.Contains(body, "debug") ||
				strings.Contains(body, "admin") || strings.Contains(body, "login") ||
				strings.Contains(body, "upload") || strings.Contains(body, "config") ||
				strings.Contains(body, "api/") || strings.Contains(body, "user")
			if !has_dynamic {
				// 纯静态页面不太可能是漏洞响应
				ok = false
			}
		}
	case "dsl":
		// nuclei DSL 表达式：由 EvalDSL 求值
		ctx := DSLContext{
			Body: body, Header: headerText, StatusCode: status,
			Method: dslMethod, ContentType: extractHeader(headerText, "Content-Type"),
			Location:    extractHeader(headerText, "Location"),
			DurationSec: float64(elapsedMs) / 1000.0,
		}
		all := true
		for _, expr := range g.Words {
			res, err := EvalDSL(expr, ctx)
			if err != nil || !res {
				all = false
				break
			}
		}
		ok = all
	case "status":
		ok = false
		for _, s := range g.Status {
			if status == s {
				ok = true
				break
			}
		}
	case "prefix":
		ok = false
		for _, w := range g.Words {
			if strings.HasPrefix(hay, w) {
				if g.Condition == "and" {
					continue
				}
				ok = true
				break
			} else if g.Condition == "and" {
				return g.Negate
			}
		}
	case "word":
		if g.Lowercase {
			ws := make([]string, len(g.Words))
			for i, w := range g.Words {
				ws[i] = strings.ToLower(w)
			}
			ok = matchAnyAll(hay, ws, g.Condition, false)
		} else {
			ok = matchAnyAll(hay, g.Words, g.Condition, false)
		}
	case "regex":
		ok = matchAnyAllRegex(hay, g.Regexes, g.Condition)
	}
	if g.Negate {
		return !ok
	}
	return ok
}

func matchAnyAllRegex(hay string, regexes []string, condition string) bool {
	if len(regexes) == 0 {
		return false
	}
	for _, re := range regexes {
		compiled, err := regexp.Compile(re)
		if err != nil {
			if condition == "and" {
				return false
			}
			continue
		}
		hit := compiled.MatchString(hay)
		if condition == "and" && !hit {
			return false
		}
		if condition != "and" && hit {
			return true
		}
	}
	return condition == "and"
}

func matchAnyAll(hay string, words []string, condition string, lower bool) bool {
	if lower {
		for i, w := range words {
			words[i] = strings.ToLower(w)
		}
	}
	if condition == "and" {
		for _, w := range words {
			if w == "" {
				continue
			}
			if !strings.Contains(hay, w) {
				return false
			}
		}
		return len(words) > 0
	}
	for _, w := range words {
		if w == "" {
			continue
		}
		if strings.Contains(hay, w) {
			return true
		}
	}
	return false
}

func extractHeader(headerText, name string) string {
	for _, line := range strings.Split(headerText, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(name)+":") {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

func combine(results []bool, logic string) bool {
	if len(results) == 0 {
		return false
	}
	if logic == "or" {
		for _, r := range results {
			if r {
				return true
			}
		}
		return false
	}
	for _, r := range results {
		if !r {
			return false
		}
	}
	return true
}

// buildURL 组装完整 URL
func buildURL(base, path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return base
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

// substitute 模板变量替换
func substitute(s string, vars map[string]string, baseURL string) string {
	u, _ := url.Parse(baseURL)
	host := ""
	port := ""
	if u != nil {
		host = u.Hostname()
		port = u.Port()
	}
	repl := map[string]string{
		"{{BaseURL}}":  baseURL,
		"{{RootURL}}":  baseURL,
		"{{Hostname}}": host,
		"{{Host}}":     host,
		"{{Port}}":     port,
		"{{Scheme}}":   u.Scheme,
		"{{Path}}":     u.Path,
		"{{randstr}}":  "cysecscan",
	}
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func headersText(resp *http.Response) string {
	var b strings.Builder
	for k, vs := range resp.Header {
		lk := http.CanonicalHeaderKey(k)
		for _, v := range vs {
			b.WriteString(lk + ": " + v + "\n")
		}
	}
	return b.String()
}

func matchNames(groups []ExecGroup, results []bool) string {
	names := []string{}
	for i, ok := range results {
		if ok && i < len(groups) {
			names = append(names, groups[i].Type)
		}
	}
	if len(names) == 0 {
		return "no match"
	}
	return strings.Join(names, "+")
}

func shortPath(u string) string {
	if len(u) > 90 {
		return u[:90] + "…"
	}
	return u
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = tls.VersionTLS10

func urlParse(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// baselineFingerprint 对目标做基线探测（访问随机不存在路径），
// 获取该目标的"通用响应体"指纹。CDN/WAF/SPA 会对此返回与真实页面相同的响应。
func baselineFingerprint(baseURL string, timeoutSec int) (bodyHash string, statusCode int) {
	client := &http.Client{
		Timeout:       time.Duration(maxInt(timeoutSec, 5)) * time.Second,
		Transport:     netproxy.NewTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	// 访问两个随机不存在路径取交集
	hashes := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		randomPath := fmt.Sprintf("/cysec_%d_%d", i, time.Now().UnixNano()%100000)
		req, err := http.NewRequest("GET", baseURL+randomPath, nil)
		if err != nil {
			return "", 0
		}
		ua.Apply(req)
		resp, err := client.Do(req)
		if err != nil {
			return "", 0
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		// 用响应体（去除时间戳等动态内容）计算指纹
		normalized := normalizeBody(string(body))
		h := fmt.Sprintf("%x", md5.Sum([]byte(normalized)))
		hashes = append(hashes, h)
		statusCode = resp.StatusCode
	}
	// 两次探测结果一致 → 该目标对所有路径返回同一页面（CDN/WAF/SPA）
	if len(hashes) == 2 && hashes[0] == hashes[1] {
		return hashes[0], statusCode
	}
	return "", statusCode // 不一致 → 真实服务器，不做基线过滤
}

// normalizeBody 去除动态内容（时间戳、随机数、CSRF token 等）后再哈希
func normalizeBody(body string) string {
	// 去除数字序列（时间戳、ID等）
	reg := regexp.MustCompile(`[0-9]{4,}`)
	body = reg.ReplaceAllString(body, "N")
	// 去除长随机字符串
	reg2 := regexp.MustCompile(`[a-f0-9]{16,}`)
	body = reg2.ReplaceAllString(body, "R")
	// 压缩空白
	body = strings.Join(strings.Fields(body), " ")
	return body
}

// isBaselineMatch 判断当前响应是否与基线一致（CDN/WAF 通用页面）
func isBaselineMatch(respBody, baselineHash string) bool {
	if baselineHash == "" {
		return false
	}
	normalized := normalizeBody(respBody)
	h := fmt.Sprintf("%x", md5.Sum([]byte(normalized)))
	return h == baselineHash
}
