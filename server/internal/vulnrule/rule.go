// Package vulnrule 漏洞规则引擎：解析 nuclei / xray / afrog 三种 YAML PoC 格式，
// 归一为统一执行模型并按目标执行检测（非破坏性 HTTP 请求 + 响应匹配）。
package vulnrule

import "time"

// Rule 入库后的规则记录
type Rule struct {
	ID          int64     `json:"id"`
	Source      string    `json:"source"`  // nuclei / xray / afrog
	RuleID      string    `json:"rule_id"` // nuclei: id；xray: name；afrog: id
	Name        string    `json:"name"`
	Severity    string    `json:"severity"` // critical/high/medium/low/info
	Tags        string    `json:"tags"`
	Description string    `json:"description"`
	FilePath    string    `json:"file_path"`
	Supported   bool      `json:"supported"` // 表达式/匹配器是否可被本引擎执行
	Enabled     bool      `json:"enabled"`
	Raw         string    `json:"raw"` // 原始 YAML
	Parsed      string    `json:"-"`   // ExecRule JSON（入库字段）
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	execTmp     *ExecRule `json:"-"` // 解析暂存
	unsupported bool      `json:"-"` // 表达式含引擎不支持的结构
}

// ExecRule 可执行模型（序列化存库）
type ExecRule struct {
	Steps    []ExecStep        `json:"steps"`
	Logic    string            `json:"logic"` // 步骤间 and / or
	Vars     map[string]string `json:"vars"`
	NeedsOOB bool              `json:"needs_oob,omitempty"` // 含 {{interactsh-url}} → 需 OOB 反连检测
}

// ExecStep 一次 HTTP 请求 + 匹配组
type ExecStep struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"` // 完整路径（相对则拼 BaseURL）
	Body           string            `json:"body"`
	Headers        map[string]string `json:"headers"`
	FollowRedirect bool              `json:"follow_redirect"`
	Logic          string            `json:"logic"`              // 匹配组间 and/or
	Groups         []ExecGroup       `json:"groups"`             // 单分支（无 ||）时的匹配组
	Branches       [][]ExecGroup     `json:"branches,omitempty"` // 表达式含 || 时按分支组合（任一分支全真即命中）
}

// ExecGroup 单个匹配器
type ExecGroup struct {
	Type      string   `json:"type"`      // word / regex / status / prefix / latency_gte / latency_lte
	Part      string   `json:"part"`      // body / header / all
	Condition string   `json:"condition"` // 组内 and/or
	Words     []string `json:"words"`
	Regexes   []string `json:"regexes"`
	Status    []int    `json:"status"`
	Negate    bool     `json:"negate"`
	Lowercase bool     `json:"lowercase,omitempty"` // 匹配前转小写（icontains / to_lower）
	Internal  bool     `json:"internal,omitempty"`  // nuclei internal 匹配器：特征不可靠，命中需基线对比佐证
}

// 设置（扫描时执行规则的全局开关与限额）
type Settings struct {
	EnabledInScan bool `json:"enabled_in_scan" yaml:"enabled_in_scan"`
	MaxPerTarget  int  `json:"max_per_target" yaml:"max_per_target"` // 每个目标最多执行的规则数
}

func DefaultSettings() Settings { return Settings{EnabledInScan: true, MaxPerTarget: 0} } // 0 = 加载全部规则

// ImportResult 导入结果
type ImportResult struct {
	FilesScanned int      `json:"files_scanned"`
	Imported     int      `json:"imported"`    // 新增
	Updated      int      `json:"updated"`     // 更新
	Unsupported  int      `json:"unsupported"` // 解析成功但引擎暂不可执行
	Failed       int      `json:"failed"`
	Errors       []string `json:"errors"`
}

// normalizeSeverity 统一等级
func normalizeSeverity(s string, def string) string {
	switch lower(s) {
	case "critical", "high", "medium", "low", "info":
		return lower(s)
	case "严重":
		return "critical"
	case "高危", "高":
		return "high"
	case "中危", "中":
		return "medium"
	case "低危", "低":
		return "low"
	case "":
		return def
	}
	return def
}

func lower(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}
