package builtin

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"cysec/internal/plugins"
	"cysec/internal/ua"
)

// 敏感路径泄露检测（非破坏性 GET 探测）。规则完全由界面自定义（漏洞规则库→敏感路径检测），
// 引擎不内置任何路径：未配置即跳过检测。

// ---------- 信息泄露 / 敏感路径（非破坏性 GET 探测） ----------

// LeakPath 单条敏感路径规则
type LeakPath struct {
	Path     string `json:"path"`              // 以 / 开头的探测路径
	Name     string `json:"name"`              // 漏洞名称（空则用路径）
	Severity string `json:"severity"`          // critical/high/medium/low/info
	Keyword  string `json:"keyword,omitempty"` // 命中需正文包含的关键词（空=仅状态码+正文非空判定）
	VulnID   string `json:"vuln_id,omitempty"` // 稳定漏洞编号（空则按路径哈希生成）
}

var (
	leakMu    sync.RWMutex
	leakRules []LeakPath
)

// SetLeakPaths 注入当前生效的敏感路径规则（界面保存 / 启动恢复时调用，即时生效）
func SetLeakPaths(ps []LeakPath) {
	out := make([]LeakPath, 0, len(ps))
	for _, p := range ps {
		p.Path = strings.TrimSpace(p.Path)
		if p.Path == "" {
			continue
		}
		if !strings.HasPrefix(p.Path, "/") {
			p.Path = "/" + p.Path
		}
		if p.Severity == "" {
			p.Severity = "medium"
		}
		if p.Name == "" {
			p.Name = "敏感路径泄露 " + p.Path
		}
		if p.VulnID == "" {
			p.VulnID = leakIDOf(p.Path)
		}
		out = append(out, p)
	}
	leakMu.Lock()
	leakRules = out
	leakMu.Unlock()
}

// CurrentLeakPaths 当前生效规则（空切片=未配置，扫描跳过）
func CurrentLeakPaths() []LeakPath {
	leakMu.RLock()
	defer leakMu.RUnlock()
	return append([]LeakPath(nil), leakRules...)
}

// leakIDOf 自定义路径的稳定漏洞编号（CYSEC-LEAK-<路径哈希前8位>）
func leakIDOf(path string) string {
	sum := md5.Sum([]byte(strings.ToLower(path)))
	return "CYSEC-LEAK-" + hex.EncodeToString(sum[:])[:8]
}

// 不提供任何默认/经典规则集：敏感路径检测的规则完全由使用者在界面自定义。

type leakRiskScanner struct{}

func (s *leakRiskScanner) Name() string     { return "leak-risk" }
func (s *leakRiskScanner) Category() string { return "leak" }

func (s *leakRiskScanner) Scan(ctx plugins.RiskContext) []plugins.VulnResult {
	if ctx.Web == nil || ctx.Client == nil {
		return nil
	}
	rules := CurrentLeakPaths()
	if len(rules) == 0 {
		return nil // 未配置敏感路径规则，跳过
	}
	out := []plugins.VulnResult{}
	base := strings.TrimRight(ctx.Web.URL, "/")
	for _, lp := range rules {
		resp, err := ctx.Client.Do(base + lp.Path)
		if err != nil || resp == nil {
			continue
		}
		// 403/404/5xx 响应不判为泄露
		if resp.StatusCode != 200 {
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
		// 命中判定：状态 200 + 关键词（未配置关键词时要求正文非空）
		kw := strings.TrimSpace(lp.Keyword)
		if kw != "" {
			if !strings.Contains(strings.ToLower(resp.Body), strings.ToLower(kw)) {
				continue
			}
		} else if len(strings.TrimSpace(resp.Body)) == 0 {
			continue
		}
		respDump := fmt.Sprintf("HTTP/1.1 %d\r\nContent-Type: %s\r\n\r\n%s", resp.StatusCode, resp.ContentType, riskTruncate(resp.Body, 4096))
		reqDump := fmt.Sprintf("GET %s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",
			ctx.Web.URL, lp.Path, hostOfWebURL(ctx.Web.URL), ua.Get())
		out = append(out, plugins.VulnResult{
			VulnID:      lp.VulnID,
			Name:        lp.Name,
			Severity:    lp.Severity,
			Description: "敏感路径可被未授权访问（HTTP " + fmt.Sprint(resp.StatusCode) + "）。",
			Solution:    "限制该路径访问权限或从生产环境移除。",
			Evidence:    "GET " + lp.Path + " -> " + fmt.Sprint(resp.StatusCode),
			Request:     reqDump,
			Response:    respDump,
			Component:   "Web",
			Scanner:     "builtin",
		})
	}
	return out
}

func riskTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func hostOfWebURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
