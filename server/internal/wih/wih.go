// Package wih 实现 Web Info Hunter：对站点页面与 JS 文件内容做敏感信息正则检测。
// 默认规则集移植自 ifacker/WIHscan（MIT License, Copyright (c) 2023 ifacker），
// 使用 regexp2 以兼容 WIH 生态规则（支持环视等高级语法）。
package wih

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
)

// Rule 单条敏感信息检测规则
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Severity string `json:"severity"` // high/medium/low/info
	Pattern  string `json:"pattern"`
}

// ExcludeRule 排除规则（抑制误报）：各字段为 AND 关系，全部满足才排除；
// target 按 JS/页面 URL 匹配，content 按命中内容匹配，均支持 regex: 前缀
type ExcludeRule struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Target  string `json:"target"`
	Content string `json:"content"`
	Enabled bool   `json:"enabled"`
}

// Settings WIH 检测设置（整体存 settings 表 wih_settings 键）
type Settings struct {
	EnabledInScan bool          `json:"enabled_in_scan"` // 风险检测阶段对站点执行
	MaxJSPerSite  int           `json:"max_js_per_site"` // 每站点最多抓取的 JS 数
	Rules         []Rule        `json:"rules"`
	Excludes      []ExcludeRule `json:"excludes"`
}

// Hit 单条命中
type Hit struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

const (
	maxMatchesPerRule = 3       // 单规则单文件最多记录的命中数
	maxMatchLen       = 200     // 命中内容截断长度
	defaultMaxJS      = 20      // 默认每站点 JS 抓取上限
	maxBodyScan       = 2 << 20 // 参与匹配的内容上限（2MB）
)

// DefaultSettings 默认规则集（移植自 WIHscan，severity/名称按平台口径标注）
func DefaultSettings() Settings {
	r := func(id, name, severity, pattern string, enabled bool) Rule {
		return Rule{ID: id, Name: name, Severity: severity, Pattern: pattern, Enabled: enabled}
	}
	return Settings{
		EnabledInScan: true,
		MaxJSPerSite:  defaultMaxJS,
		Rules: []Rule{
			r("email", "邮箱地址", "info", `\b[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,61}\b`, false),
			r("id_card", "身份证号", "medium", `\b([1-9]\d{5}(19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx])\b`, true),
			r("phone", "手机号", "info", `\b1[3-9]\d{9}\b`, false),
			r("jwt_token", "JWT Token", "medium", `eyJ[A-Za-z0-9_/+\-]{10,}={0,2}\.[A-Za-z0-9_/+\-\\]{15,}={0,2}\.[A-Za-z0-9_/+\-\\]{10,}={0,2}`, true),
			r("Aliyun_AK_ID", "阿里云 AccessKey ID", "high", `\bLTAI[A-Za-z\d]{12,30}\b`, true),
			r("QCloud_AK_ID", "腾讯云 AccessKey ID", "high", `\bAKID[A-Za-z\d]{13,40}\b`, true),
			r("JDCloud_AK_ID", "京东云 AccessKey ID", "high", `\bJDC_[0-9A-Z]{25,40}\b`, true),
			r("AWS_AK_ID", "亚马逊 AccessKey ID", "high", `["'](?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["']`, true),
			r("VolcanoEngine_AK_ID", "火山引擎 AccessKey ID", "high", `\b(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}\b`, true),
			r("Kingsoft_AK_ID", "金山云 AccessKey ID", "high", `\bAKLT[a-zA-Z0-9\-_]{16,28}\b`, true),
			r("GCP_AK_ID", "谷歌云 AccessKey ID", "high", `\bAIza[0-9A-Za-z_\-]{35}\b`, true),
			r("bearer_token", "Bearer Token", "medium", `\b[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}\b`, true),
			r("basic_token", "Basic Token", "medium", `\b[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}\b`, true),
			r("auth_token", "Authorization Token", "medium", `["'\[]*[Aa]uthorization["'\]]*\s*[:=]\s*['"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}['"]?`, true),
			r("private_key", "私钥（PRIVATE KEY）", "critical", `-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[a-zA-Z0-9/\n\r=+]*-----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`, true),
			r("gitlab_v2_token", "GitLab Token", "high", `\bglpat-[a-zA-Z0-9\-=_]{20,22}\b`, true),
			r("github_token", "GitHub Token", "high", `\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}\b`, true),
			r("qcloud_api_gateway_appkey", "腾讯云 API 网关 APPKEY", "high", `\bAPID[a-zA-Z0-9]{32,42}\b`, true),
			r("wechat_appid", "微信公众号/小程序 APPID", "low", `["'](wx[a-z0-9]{15,18})["']`, true),
			r("wechat_corpid", "企业微信 corpid", "low", `["'](ww[a-z0-9]{15,18})["']`, true),
			r("wechat_id", "微信公众号 ID", "low", `["'](gh_[a-z0-9]{11,13})["']`, true),
			r("password", "疑似密码", "high", `(?i)(?:admin_?pass|password|[a-z]{3,15}_?password|user_?pass|user_?pwd|admin_?pwd)\\?['"]*\s*[:=]\s*\\?['"][a-z0-9!@#$%&*]{5,20}\\?['"]`, true),
			r("wechat_webhookurl", "企业微信机器人 Webhook", "medium", `\bhttps://qyapi.weixin.qq.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}\b`, true),
			r("dingtalk_webhookurl", "钉钉机器人 Webhook", "medium", `\bhttps://oapi.dingtalk.com/robot/send\?access_token=[a-z0-9]{50,80}\b`, true),
			r("feishu_webhookurl", "飞书机器人 Webhook", "medium", `\bhttps://open.feishu.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}\b`, true),
			r("slack_webhookurl", "Slack Webhook", "medium", `\bhttps://hooks.slack.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}\b`, true),
			r("grafana_api_key", "Grafana API Key", "high", `\beyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}\b`, true),
			r("grafana_cloud_api_token", "Grafana Cloud API Token", "high", `\bglc_[A-Za-z0-9\-_+/]{32,200}={0,2}\b`, true),
			r("grafana_service_account_token", "Grafana 服务账号 Token", "high", `\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b`, true),
			r("app_key", "前端应用密钥", "high", `\b(?:VUE|APP|REACT)_[A-Z_0-9]{1,15}_(?:KEY|PASS|PASSWORD|TOKEN|APIKEY)['"]*[:=]"(?:[A-Za-z0-9_\-]{15,50}|[a-z0-9/+]{50,100}==?)"`, true),
		},
	}
}

// Normalize 规范化设置：修正参数范围、剔除无效规则
func (s *Settings) Normalize() {
	if s.MaxJSPerSite <= 0 || s.MaxJSPerSite > 100 {
		s.MaxJSPerSite = defaultMaxJS
	}
	seen := map[string]bool{}
	rules := make([]Rule, 0, len(s.Rules))
	for _, r := range s.Rules {
		r.ID = strings.TrimSpace(r.ID)
		r.Pattern = strings.TrimSpace(r.Pattern)
		if r.ID == "" || r.Pattern == "" || seen[r.ID] {
			continue
		}
		if _, err := Compile(r.Pattern); err != nil {
			continue // 编译失败的规则直接丢弃，避免运行期反复报错
		}
		switch r.Severity {
		case "critical", "high", "medium", "low", "info":
		default:
			r.Severity = "info"
		}
		seen[r.ID] = true
		rules = append(rules, r)
	}
	s.Rules = rules
	if s.Rules == nil {
		s.Rules = []Rule{}
	}
	if s.Excludes == nil {
		s.Excludes = []ExcludeRule{}
	}
}

// ---- 规则编译缓存 ----

var (
	reMu    sync.Mutex
	reCache = map[string]*regexp2.Regexp{}
)

// Compile 编译规则正则（带缓存；失败返回 err）。
// MatchTimeout 30s：regexp2 是回溯引擎且默认永不超时，界面可编辑规则——
// 一条灾难性回溯模式即可把扫描 goroutine 永久挂死。
func Compile(pattern string) (*regexp2.Regexp, error) {
	reMu.Lock()
	defer reMu.Unlock()
	if re, ok := reCache[pattern]; ok {
		return re, nil
	}
	re, err := regexp2.Compile(pattern, 0)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = 30 * time.Second
	if len(reCache) > 512 {
		reCache = map[string]*regexp2.Regexp{} // 防御性上限：规则频繁改动时避免缓存无限增长
	}
	reCache[pattern] = re
	return re, nil
}

// ScanBody 对单段内容执行全部启用规则，返回命中列表
func ScanBody(rules []Rule, body string) []Hit {
	if len(rules) == 0 || body == "" {
		return nil
	}
	if len(body) > maxBodyScan {
		body = body[:maxBodyScan]
	}
	out := []Hit{}
	for _, r := range rules {
		if !r.Enabled || r.Pattern == "" {
			continue
		}
		re, err := Compile(r.Pattern)
		if err != nil {
			continue
		}
		n := 0
		m, _ := re.FindStringMatch(body)
		for m != nil {
			out = append(out, Hit{RuleID: r.ID, Name: r.Name, Severity: r.Severity, Match: truncate(m.String(), maxMatchLen)})
			n++
			if n >= maxMatchesPerRule {
				break
			}
			m, _ = re.FindNextMatch(m)
		}
	}
	return out
}

// Excluded 判断命中是否被排除规则过滤（exclude 各字段 AND；target 匹配来源 URL，content 匹配命中内容）
func (s *Settings) Excluded(h Hit, sourceURL string) bool {
	for _, ex := range s.Excludes {
		if !ex.Enabled {
			continue
		}
		if ex.ID != "" && ex.ID != h.RuleID {
			continue
		}
		if ex.Target != "" && !fieldMatch(ex.Target, sourceURL) {
			continue
		}
		if ex.Content != "" && !fieldMatch(ex.Content, h.Match) {
			continue
		}
		return true
	}
	return false
}

// fieldMatch 排除字段匹配：regex: 前缀走正则（部分匹配），否则子串包含
func fieldMatch(cond, s string) bool {
	if strings.HasPrefix(cond, "regex:") {
		re, err := regexp.Compile(strings.TrimPrefix(cond, "regex:"))
		if err != nil {
			return false
		}
		return re.MatchString(s)
	}
	return strings.Contains(s, cond)
}

// ExtractJSLinks 从 HTML 中提取外部脚本地址（script src），相对路径基于 baseURL 解析
func ExtractJSLinks(baseURL, body string, limit int) []string {
	if limit <= 0 {
		limit = defaultMaxJS
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		raw := strings.TrimSpace(m[1])
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			continue
		}
		u, err := base.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		clean := u.String()
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

var scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]+src\s*=\s*["']([^"']+)["']`)

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- 全局当前设置（引擎插件读取；API 保存与启动加载时更新） ----

var current atomic.Value

// SetCurrent 更新全局当前设置（保存前会规范化）
func SetCurrent(s Settings) {
	s.Normalize()
	current.Store(s)
}

// Current 读取全局当前设置（未初始化时返回默认值）
func Current() Settings {
	if v, ok := current.Load().(Settings); ok {
		return v
	}
	return DefaultSettings()
}
