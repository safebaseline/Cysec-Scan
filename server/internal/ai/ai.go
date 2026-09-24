// Package ai AI 研判引擎：调用 OpenAI 兼容 API 分析漏洞报文，判定误报/实报。
package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cysec/internal/netproxy"
)

// Config AI 配置（存 settings 表 key=ai_config）
type Config struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Provider   string `json:"provider" yaml:"provider"` // openai / azure / ollama / custom
	BaseURL    string `json:"base_url" yaml:"base_url"` // API 端点（如 https://api.openai.com/v1）
	APIKey     string `json:"api_key" yaml:"api_key"`
	Model      string `json:"model" yaml:"model"` // 如 gpt-4o-mini / qwen-plus / deepseek-chat
	TimeoutSec int    `json:"timeout_sec" yaml:"timeout_sec"`

	// AI 自动研判（全局）
	AutoAnalyze     bool   `json:"auto_analyze" yaml:"auto_analyze"`           // 扫描完成后自动对新检出漏洞做 AI 研判
	AutoMinSeverity string `json:"auto_min_severity" yaml:"auto_min_severity"` // 仅对指定等级及以上做自动研判
}

// DefaultConfig 默认配置
func DefaultConfig() Config {
	return Config{
		Enabled:    false,
		Provider:   "openai",
		BaseURL:    "https://api.openai.com/v1",
		Model:      "gpt-4o-mini",
		TimeoutSec: 30,
	}
}

// Verdict AI 研判结果
type Verdict struct {
	Mark       string `json:"mark"`       // confirmed / false_positive / ignored
	Confidence string `json:"confidence"` // high / medium / low
	Reasoning  string `json:"reasoning"`  // AI 分析理由
	Error      string `json:"error,omitempty"`
}

// VulnContext 漏洞上下文（传给 AI 的信息）
type VulnContext struct {
	VulnID      string
	Name        string
	Severity    string
	Description string
	URL         string
	IP          string
	Port        int
	Service     string
	Evidence    string
	Request     string
	Response    string
	// 弱点研判上下文（弱点管理专用；Kind=weakness 时生效）
	Kind        string `json:"kind,omitempty"`        // 空=漏洞 / weakness=弱点
	SiteURL     string `json:"site_url,omitempty"`     // 所属站点
	PageURL     string `json:"page_url,omitempty"`     // 所属页面
	PageTitle   string `json:"page_title,omitempty"`   // 页面标题
	StatusCode  int    `json:"status_code,omitempty"`  // 链接状态码
	Detail      string `json:"detail,omitempty"`       // 检测结论原文
	Anchor      string `json:"anchor,omitempty"`       // 锚文本/命中词
	ContextHTML string `json:"context_html,omitempty"` // 引用位置（链接在页面中的 HTML 片段）
}

// systemPrompt AI 研判提示词（漏洞口径）
const systemPrompt = `你是一位资深网络安全分析师。请根据以下漏洞检测结果，研判该漏洞是"实报"还是"误报"。

分析要点：
1. 仔细比对请求报文和响应报文的内容
2. 检查响应是否真正证明漏洞存在（而不仅是状态码或通用页面特征）
3. 判断检测规则是否存在泛匹配（如匹配到了通用 404/默认页）
4. 考虑上下文：服务类型、端口、URL 路径是否与漏洞匹配
5. 如果报文证据不足以确认，倾向判为误报

输出 JSON 格式（严格遵循）：
{"mark":"confirmed|false_positive","confidence":"high|medium|low","reasoning":"简要分析理由（50字以内）"}

- confirmed: 漏洞真实存在，报文证据充分
- false_positive: 误报，报文证据不足或匹配到了无关内容
- confidence: 判断置信度`

// weaknessSystemPrompt 弱点研判提示词（弱点管理专用口径）
const weaknessSystemPrompt = `你是一位资深网站安全运营分析师，负责研判网站弱点检测结果（暗链/坏链/敏感字/敏感信息泄露）是"实报"还是"误报"。

分析要点：
1. 结合所属站点与页面内容语境判断：链接出现在正文、参考资料、页脚友链等位置的含义不同
2. 坏链：关注状态码与检测结论——域名无法解析/404/410 通常是真实死链（实报）；412/429/403 多为防护拦截（倾向误报）；跳转链接（百度/bilibili 等）失效常见
3. 暗链：隐藏样式 + 陌生外链 + 赌博色情类关键词是典型挂马（实报）；知名网站的正常链接即使隐藏也多为模板/统计代码（倾向误报）
4. 敏感字：单个常用词（如"兼职/激情/地址"）在正常文章语境中命中多为词库泛匹配（倾向误报）；明确的赌博/色情内容才是实报
5. 敏感信息泄露：真实密钥/Token 格式完整且非示例值（实报）；示例值/文档片段（误报）
6. 证据不足以确认时，倾向判为误报

输出 JSON 格式（严格遵循）：
{"mark":"confirmed|false_positive","confidence":"high|medium|low","reasoning":"简要分析理由（50字以内）"}

- confirmed: 弱点真实存在
- false_positive: 误报（词库泛匹配/正常内容/防护拦截等）
- confidence: 判断置信度`

// Analyze 调用 AI 分析漏洞
func Analyze(cfg Config, vuln VulnContext) (*Verdict, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("AI 研判未启用")
	}
	if cfg.BaseURL == "" || cfg.APIKey == "" || cfg.Model == "" {
		return nil, fmt.Errorf("AI 配置不完整（需 base_url / api_key / model）")
	}

	userPrompt := buildUserPrompt(vuln)
	sys := systemPrompt
	if vuln.Kind == "weakness" {
		sys = weaknessSystemPrompt
	}

	respBody, err := callLLM(cfg, sys, userPrompt)
	if err != nil {
		return nil, err
	}

	// 解析 AI 返回的 JSON
	return parseVerdict(respBody)
}

// buildUserPrompt 构建用户提示词
func buildUserPrompt(v VulnContext) string {
	if v.Kind == "weakness" {
		return buildWeaknessPrompt(v)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "漏洞信息：\n")
	fmt.Fprintf(&b, "- 规则ID: %s\n", v.VulnID)
	fmt.Fprintf(&b, "- 漏洞名称: %s\n", v.Name)
	fmt.Fprintf(&b, "- 风险等级: %s\n", v.Severity)
	if v.Description != "" {
		d := v.Description
		if len(d) > 300 {
			d = d[:300]
		}
		fmt.Fprintf(&b, "- 描述: %s\n", d)
	}
	fmt.Fprintf(&b, "- 目标: %s:%d (%s)\n", v.IP, v.Port, v.URL)
	if v.Service != "" {
		fmt.Fprintf(&b, "- 服务: %s\n", v.Service)
	}
	if v.Evidence != "" {
		fmt.Fprintf(&b, "- 检测证据: %s\n", v.Evidence)
	}
	fmt.Fprintf(&b, "\n--- 请求报文 ---\n%s\n", truncate(v.Request, 2000))
	fmt.Fprintf(&b, "\n--- 响应报文 ---\n%s\n", truncate(v.Response, 3000))
	fmt.Fprintf(&b, "\n请研判并输出 JSON。")
	return b.String()
}

// callLLM 调用 OpenAI 兼容 API（直连，不走全局出站代理）
// weaknessTypeLabel 弱点类型中文化
var weaknessTypeLabel = map[string]string{
	"darklink": "暗链", "brokenlink": "坏链", "sensword": "敏感字", "wih": "敏感信息泄露",
}

// buildWeaknessPrompt 弱点研判用户提示词：补齐所属站点/页面/标题/状态码/引用位置等上下文
func buildWeaknessPrompt(v VulnContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "弱点检测结果：\n")
	if lbl := weaknessTypeLabel[v.VulnID]; lbl != "" {
		fmt.Fprintf(&b, "- 类型: %s\n", lbl)
	} else {
		fmt.Fprintf(&b, "- 类型: %s\n", v.VulnID)
	}
	if v.Severity != "" {
		fmt.Fprintf(&b, "- 风险等级: %s\n", v.Severity)
	}
	if v.SiteURL != "" {
		fmt.Fprintf(&b, "- 所属站点: %s\n", v.SiteURL)
	}
	if v.PageURL != "" {
		fmt.Fprintf(&b, "- 所属页面: %s\n", v.PageURL)
	}
	if v.PageTitle != "" {
		fmt.Fprintf(&b, "- 页面标题: %s\n", truncate(v.PageTitle, 120))
	}
	if v.URL != "" {
		fmt.Fprintf(&b, "- 触发链接/命中位置: %s\n", v.URL)
	}
	if v.Anchor != "" {
		fmt.Fprintf(&b, "- 锚文本/命中词: %s\n", truncate(v.Anchor, 120))
	}
	if v.StatusCode != 0 {
		fmt.Fprintf(&b, "- 状态码: %d\n", v.StatusCode)
	}
	if v.Detail != "" {
		fmt.Fprintf(&b, "- 检测结论: %s\n", truncate(v.Detail, 400))
	}
	if v.Evidence != "" {
		fmt.Fprintf(&b, "- 命中内容/上下文: %s\n", truncate(v.Evidence, 600))
	}
	if v.ContextHTML != "" {
		fmt.Fprintf(&b, "- 引用位置（该链接在页面中的 HTML 片段）: %s\n", truncate(v.ContextHTML, 800))
	}
	if v.Response != "" {
		fmt.Fprintf(&b, "\n--- 相关响应（如有） ---\n%s\n", truncate(v.Response, 2000))
	}
	fmt.Fprintf(&b, "\n请结合页面语境研判该弱点并输出 JSON。")
	return b.String()
}

func callLLM(cfg Config, systemPrompt, userPrompt string) (string, error) {
	reqBody := map[string]any{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": 0.1,
		// 给足输出空间：推理类模型（R1/qwq 等）先输出思考过程，200 token 会在 JSON 出现前被截断
		"max_tokens": 1024,
	}
	data, _ := json.Marshal(reqBody)

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	// AI 接口直连（Transport 显式禁用代理：不受全局代理与进程代理环境变量影响，
	// 与空间测绘/敏感字订阅同约定——平台自身出站而非对授权目标的扫描流量）
	client := netproxy.NewDirectHTTPClient(int(timeout.Seconds()), 0)

	var lastErr error
	for _, base := range apiBases(cfg.BaseURL) {
		req, err := http.NewRequest("POST", base+"/chat/completions", bytes.NewReader(data))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("AI API 调用失败: %v", err)
			continue // 网络失败换下一候选路径（补 /v1 与原样两种前缀）
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 {
			lastErr = fmt.Errorf("AI API HTTP 404: %s", truncate(string(body), 200))
			continue // 404 多为 base_url 版本段不符，尝试另一候选
		}
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("AI API HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		}

		// 解析 OpenAI 兼容响应
		var result struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return "", fmt.Errorf("AI 响应解析失败: %v", err)
		}
		if len(result.Choices) == 0 {
			return "", fmt.Errorf("AI 返回空结果")
		}
		return result.Choices[0].Message.Content, nil
	}
	return "", lastErr
}

// apiBases 返回候选 API 前缀：base_url 未带版本段（/v1、/v2…）时优先补 /v1，其次原样；
// 兼容 https://api.openai.com 与 https://api.openai.com/v1 两种写法（404/网络失败时依次回退）
func apiBases(raw string) []string {
	b := strings.TrimRight(strings.TrimSpace(raw), "/")
	b = strings.TrimSuffix(b, "/chat/completions") // 兼容误把完整端点当 base_url 的写法
	if hasVersionSuffix(b) {
		return []string{b}
	}
	return []string{b + "/v1", b}
}

func hasVersionSuffix(b string) bool {
	i := strings.LastIndex(b, "/")
	if i < 0 || i == len(b)-1 {
		return false
	}
	seg := b[i+1:]
	if len(seg) < 2 || seg[0] != 'v' {
		return false
	}
	for _, c := range seg[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseVerdict 从 AI 回复中提取 JSON
func parseVerdict(content string) (*Verdict, error) {
	content = stripThinking(content)
	// 优先取 ```json ... ``` / ``` ... ``` 围栏内容
	if fenced := extractFenced(content); fenced != "" {
		content = fenced
	}
	start := strings.Index(content, "{")
	end := strings.LastIndex(content, "}")
	if start < 0 || end < start {
		return nil, fmt.Errorf("AI 回复不含 JSON: %s", truncate(content, 100))
	}
	jsonStr := content[start : end+1]

	var v Verdict
	if err := json.Unmarshal([]byte(jsonStr), &v); err != nil {
		return nil, fmt.Errorf("AI JSON 解析失败: %v", err)
	}
	// 校验 mark 值
	if v.Mark != "confirmed" && v.Mark != "false_positive" {
		return nil, fmt.Errorf("AI 返回无效 mark: %s", v.Mark)
	}
	return &v, nil
}

// stripThinking 剥离推理类模型（DeepSeek-R1 / QwQ 等）的思考过程：
// 成对的 <think>...</think> 整段去除；未闭合的 <think>（截断）则保留其之后的内容
func stripThinking(s string) string {
	for {
		i := strings.Index(s, "<think>")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], "</think>")
		if j < 0 {
			return s[i+len("<think>"):] // 未闭合：思考被 max_tokens 截断，取已产出的正文
		}
		s = s[:i] + s[i+j+len("</think>"):]
	}
}

// extractFenced 提取 markdown 代码围栏内容（```json {...} ```），无围栏返回空串
func extractFenced(s string) string {
	start := strings.Index(s, "```")
	if start < 0 {
		return ""
	}
	rest := s[start+3:]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
		rest = rest[nl+1:] // 跳过 ```json 这一行
	}
	if end := strings.Index(rest, "```"); end >= 0 {
		return rest[:end]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ListModels 从 OpenAI 兼容 API 获取可用模型列表（直连，不走全局出站代理；
// base_url 未带 /v1 时自动补全，404/网络失败回退另一候选路径）
func ListModels(cfg Config) ([]string, error) {
	if cfg.BaseURL == "" || cfg.APIKey == "" {
		return nil, fmt.Errorf("需要先填写 API 地址和 API Key")
	}
	client := netproxy.NewDirectHTTPClient(15, 0) // 直连，不走全局代理与环境变量代理
	var lastErr error
	for _, base := range apiBases(cfg.BaseURL) {
		req, err := http.NewRequest("GET", base+"/models", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("请求失败: %v", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 {
			lastErr = fmt.Errorf("HTTP 404: %s", truncate(string(body), 200))
			continue // 版本段不符，尝试另一候选
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		}
		var result struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("解析失败: %v", err)
		}
		models := []string{}
		for _, m := range result.Data {
			models = append(models, m.ID)
		}
		return models, nil
	}
	return nil, lastErr
}

// ShouldAutoAnalyze 判断漏洞是否满足自动研判条件
func ShouldAutoAnalyze(cfg Config, severity string) bool {
	if !cfg.Enabled || !cfg.AutoAnalyze {
		return false
	}
	order := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	minSev := cfg.AutoMinSeverity
	if minSev == "" {
		minSev = "low"
	}
	return order[severity] >= order[minSev]
}
