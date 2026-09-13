package builtin

import (
	"fmt"
	"strings"

	"cysec/internal/plugins"
	"cysec/internal/wih"
)

// ---------- WIH JS 敏感信息检测（Web Info Hunter） ----------
// 规则集源自 ifacker/WIHscan（MIT），对站点首页与引用 JS 做正则敏感信息检测。
// 作为 RiskScanner 插件注册：标准/深度扫描阶段随其他风险检测一并执行，非破坏性（仅 GET）。

type wihRiskScanner struct{}

func (s *wihRiskScanner) Name() string     { return "wih" }
func (s *wihRiskScanner) Category() string { return "leak" }

func (s *wihRiskScanner) Scan(ctx plugins.RiskContext) []plugins.VulnResult {
	st := wih.Current()
	if !st.EnabledInScan || ctx.Web == nil {
		return nil
	}
	siteURL := ctx.Web.URL
	out := []plugins.VulnResult{}
	emit := func(hits []wih.Hit, source string) {
		for _, h := range hits {
			if st.Excluded(h, source) {
				continue
			}
			out = append(out, plugins.VulnResult{
				VulnID:      "WIH-" + h.RuleID,
				Name:        "[WIH] " + h.Name,
				Severity:    h.Severity,
				Description: fmt.Sprintf("在 %s 中发现敏感信息：%s（命中内容已截断保存）", source, h.Name),
				Solution:    "从前端代码/构建产物中移除该敏感信息；已泄露的凭据（AK/SK、Token、密码等）应立即轮换。",
				Evidence:    h.Match,
				Request:     "GET " + source,
				Response:    h.Match,
				Scanner:     "wih",
				Component:   "WIH",
			})
		}
	}
	// 1) 站点首页/响应体本身
	emit(wih.ScanBody(st.Rules, ctx.Body), siteURL)
	// 2) 页面引用的外部 JS（受限客户端，走全局出站代理与 UA 池）
	for _, js := range wih.ExtractJSLinks(siteURL, ctx.Body, st.MaxJSPerSite) {
		resp, err := ctx.Client.Do(js)
		if err != nil || resp == nil || resp.Body == "" {
			continue
		}
		if !looksLikeText(resp.ContentType) && !looksLikeText(resp.Headers["Content-Type"]) {
			continue
		}
		emit(wih.ScanBody(st.Rules, resp.Body), js)
	}
	return out
}

// looksLikeText 仅对文本类内容（js/html/纯文本）执行匹配，避免二进制误报与资源浪费
func looksLikeText(contentType string) bool {
	ct := strings.ToLower(contentType)
	return ct == "" || strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml")
}
