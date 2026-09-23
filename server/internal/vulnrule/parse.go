package vulnrule

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseFile 解析单个规则文件，自动识别 nuclei / xray / afrog 格式
func ParseFile(path string, content []byte) (*Rule, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %v", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("空文件")
	}
	var (
		r   *Rule
		err error
	)
	switch {
	case hasKey(raw, "http"):
		r, err = parseNuclei(content)
	case hasKey(raw, "rules"):
		if hasKey(raw, "id") {
			r, err = parseAfrog(content) // afrog：id + info + rules(CEL)
		} else {
			r, err = parseXray(content) // xray：name + transport + rules(CEL)
		}
	case hasKey(raw, "network"), hasKey(raw, "dns"), hasKey(raw, "websocket"), hasKey(raw, "headless"):
		return nil, fmt.Errorf("暂不支持的模板类型（network/dns/headless）")
	default:
		return nil, fmt.Errorf("无法识别的规则格式")
	}
	if err != nil {
		return nil, err
	}
	r.FilePath = path
	r.Raw = string(content)
	exec := r.execTmp
	if exec == nil {
		exec = &ExecRule{}
	}
	if b, e := json.Marshal(exec); e == nil {
		r.Parsed = string(b)
	}
	r.Supported = !r.unsupported && len(exec.Steps) > 0
	return r, nil
}

func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

// ---------- nuclei / afrog（http matchers 格式） ----------

type tplInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        string   `yaml:"tags"`
	Reference   []string `yaml:"reference"`
}

type tplMatcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Condition string   `yaml:"condition"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Negate    bool     `yaml:"negate"`
	DSL       []string `yaml:"dsl"`
	Binary    []string `yaml:"binary"`
	Internal  bool     `yaml:"internal"`
}

type tplRequest struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Raw               []string          `yaml:"raw"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []tplMatcher      `yaml:"matchers"`
	Redirects         bool              `yaml:"redirects"`
	MaxRedirects      int               `yaml:"max-redirects"`
}

type tplNuclei struct {
	ID        string         `yaml:"id"`
	Info      tplInfo        `yaml:"info"`
	Variables map[string]any `yaml:"variables"`
	HTTP      []tplRequest   `yaml:"http"`
}

func parseNuclei(content []byte) (*Rule, error) {
	var t tplNuclei
	if err := yaml.Unmarshal(content, &t); err != nil {
		return nil, err
	}
	if t.ID == "" {
		return nil, fmt.Errorf("缺少 id")
	}
	r := &Rule{
		Source:      "nuclei",
		RuleID:      t.ID,
		Name:        t.Info.Name,
		Severity:    normalizeSeverity(t.Info.Severity, "medium"),
		Tags:        t.Info.Tags,
		Description: t.Info.Description,
		Enabled:     true,
	}
	exec := &ExecRule{Logic: "or", Vars: map[string]string{}} // 多 path 展开为 or
	for k, v := range t.Variables {
		exec.Vars[k] = plainVar(v)
	}
	// 检测 OOB 模板（含 {{interactsh-url}} 或 interactsh 匹配器）
	rawStr := string(content)
	if strings.Contains(rawStr, "{{interactsh-url}}") || strings.Contains(rawStr, "interactsh_protocol") || strings.Contains(rawStr, "interactsh_request") {
		exec.NeedsOOB = true
		// OOB 规则：在 Vars 中预注册 interactsh-url 占位（执行时替换为实际 OOB 服务 URL）
		exec.Vars["interactsh-url"] = "{{interactsh-url}}" // 保留标记，执行时由 oob.Server 替换
	}
	for _, req := range t.HTTP {
		groups, ok := matcherGroups(req.Matchers)
		if !ok {
			continue // 含完全无法解析的匹配器 → 规则整体不支持
		}
		if len(req.Raw) > 0 && len(req.Path) == 0 {
			// raw 请求：解析首行(方法/路径)+头+体，模板变量留给执行器替换
			if st, ok := parseRawRequest(req.Raw[0], groups, orDefault(lower(req.MatchersCondition), "or")); ok { // nuclei 官方缺省 or
				exec.Steps = append(exec.Steps, st)
			}
			continue
		}
		// Path 为空但也没 raw 的（可能仅有 extractors 或 internal 匹配器）→ 跳过
		for _, p := range req.Path {
			exec.Steps = append(exec.Steps, ExecStep{
				Method:         orDefault(upperMethod(req.Method), "GET"),
				Path:           p,
				Body:           req.Body,
				Headers:        req.Headers,
				FollowRedirect: req.Redirects || req.MaxRedirects > 0,
				Logic:          orDefault(lower(req.MatchersCondition), "or"), // nuclei 官方缺省 or
				Groups:         groups,
			})
		}
	}
	r.execTmp = exec
	return r, nil
}

// parseRawRequest 解析 raw HTTP 请求文本（学习 nuclei raw 模板格式）。
// 兼容 @timeout 前缀行、无 HTTP/ 尾缀的请求行、管道块(|)缩进。
func parseRawRequest(raw string, groups []ExecGroup, logic string) (ExecStep, bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	// 跳过 nuclei 注释指令行（@timeout 等）与空行
	start := 0
	for start < len(lines) {
		t := strings.TrimSpace(lines[start])
		if t == "" || strings.HasPrefix(t, "@") {
			start++
			continue
		}
		break
	}
	if start >= len(lines) {
		return ExecStep{}, false
	}
	lines = lines[start:]
	if len(lines) == 0 {
		return ExecStep{}, false
	}
	// 请求行：METHOD /path HTTP/1.1 或 METHOD /path（nuclei 省略协议版本）
	reqLine := regexp.MustCompile(`^([A-Z]+)\s+(\S+)`).FindStringSubmatch(strings.TrimSpace(lines[0]))
	if reqLine == nil {
		return ExecStep{}, false
	}
	step := ExecStep{
		Method: reqLine[1], Path: reqLine[2],
		Headers: map[string]string{}, Groups: groups, Logic: logic,
	}
	for i := 1; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		if strings.TrimSpace(line) == "" {
			if i+1 < len(lines) {
				step.Body = strings.Join(lines[i+1:], "\n")
			}
			break
		}
		if kv := strings.SplitN(line, ":", 2); len(kv) == 2 {
			step.Headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return step, true
}

// matcherGroups 转换 nuclei 匹配器；返回 ok=false 表示存在不可执行的匹配器
func matcherGroups(ms []tplMatcher) ([]ExecGroup, bool) {
	groups := []ExecGroup{}
	for _, m := range ms {
		g := ExecGroup{Type: m.Type, Part: m.Part, Condition: m.Condition, Negate: m.Negate,
			Words: m.Words, Regexes: m.Regex, Status: m.Status, Internal: m.Internal}
		switch m.Type {
		case "word", "regex", "status":
			if g.Condition == "" {
				g.Condition = "or"
			}
			if g.Part == "" {
				g.Part = "body"
			}
		case "dsl":
			gs, ok := dslGroup(m.DSL, m.Internal)
			if !ok {
				return nil, false
			}
			groups = append(groups, gs...)
			continue
		case "binary":
			// binary：hex 编码字节序列，转为 word 匹配（近似）
			words := make([]string, len(m.Binary))
			for i, b := range m.Binary {
				words[i] = b // 保留 hex 字符串，匹配时按字符串包含处理
			}
			if g.Condition == "" {
				g.Condition = "or"
			}
			g.Words = words
		default:
			return nil, false
		}
		groups = append(groups, g)
	}
	return groups, true
}

// dslGroup 将 DSL 表达式转换为通用匹配组，由执行器调用 EvalDSL 求值。
// 支持 nuclei DSL 的函数（contains/regex/md5/base64/len 等数十个）、变量（body/header/status_code 等）、
// 比较（==/!=/</>）与逻辑运算（&&/||/!）。internal 匹配器仅做变量捕获，跳过不参与命中判定。
func dslGroup(dsl []string, internal bool) ([]ExecGroup, bool) {
	if len(dsl) == 0 {
		return nil, false
	}
	out := []ExecGroup{}
	for _, raw := range dsl {
		expr := strings.TrimSpace(unquote(strings.TrimSpace(raw)))
		if expr == "" {
			continue
		}
		if internal {
			// internal 匹配器：不参与命中判定，跳过
			continue
		}
		out = append(out, ExecGroup{Type: "dsl", Words: []string{expr}, Condition: "and"})
	}
	if len(out) == 0 {
		// 全部 internal：不再无条件命中。
		// nuclei 语义中 internal 匹配器仅做变量捕获不参与判定，
		// 我们降级为 dsl_pass（带错误页过滤），避免大量误报
		if internal {
			return []ExecGroup{{Type: "dsl_pass", Words: []string{}, Condition: "and"}}, true
		}
		return nil, false
	}
	return out, true
}

var (
	dslStatusRe    = regexp.MustCompile(`^status_code(_\d+)?\s*==\s*(\d+)$`)
	dslDurGteRe    = regexp.MustCompile(`^duration\s*>=\s*([\d.]+)$`)
	dslDurLteRe    = regexp.MustCompile(`^duration\s*<=\s*([\d.]+)$`)
	dslContains    = regexp.MustCompile(`^contains\((to_lower\()?body\)?\s*,\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\)$`)
	dslHeaderC     = regexp.MustCompile(`^contains\((to_lower\()?content_type\)?\s*,\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\)$`)
	dslAllHdrC     = regexp.MustCompile(`^contains\((to_lower\()?all_headers\)?\s*,\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\)$`)
	dslHdrC        = regexp.MustCompile(`^contains\((to_lower\()?header\)?\s*,\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\)$`)
	dslContainsAll = regexp.MustCompile(`^contains_all\((to_lower\()?body\)?\s*,((?:\s*"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'\s*,?)+)$`)
)

// dslAtom 单个条件 → 匹配组
func dslAtom(a string) (ExecGroup, bool) {
	if a == "" {
		return ExecGroup{}, false
	}
	if m := dslStatusRe.FindStringSubmatch(a); m != nil {
		// status_code_N（多响应）近似映射为当前响应状态码
		return ExecGroup{Type: "status", Part: "body", Condition: "or", Status: []int{atoi(m[2])}}, true
	}
	if m := dslDurGteRe.FindStringSubmatch(a); m != nil {
		return ExecGroup{Type: "latency_gte", Status: []int{int(parseSeconds(m[1]))}}, true
	}
	if m := dslDurLteRe.FindStringSubmatch(a); m != nil {
		return ExecGroup{Type: "latency_lte", Status: []int{int(parseSeconds(m[1]))}}, true
	}
	if m := dslContains.FindStringSubmatch(a); m != nil {
		return ExecGroup{Type: "word", Part: "body", Condition: "and",
			Words: []string{unescapeYaml(unquote(m[2]))}, Lowercase: m[1] != ""}, true
	}
	if m := dslHeaderC.FindStringSubmatch(a); m != nil {
		return ExecGroup{Type: "word", Part: "header", Condition: "and",
			Words: []string{"content-type: " + strings.ToLower(unescapeYaml(unquote(m[2])))}, Lowercase: true}, true
	}
	if m := dslAllHdrC.FindStringSubmatch(a); m != nil {
		return ExecGroup{Type: "word", Part: "header", Condition: "and",
			Words: []string{unescapeYaml(unquote(m[2]))}}, true
	}
	if m := dslHdrC.FindStringSubmatch(a); m != nil {
		return ExecGroup{Type: "word", Part: "header", Condition: "and",
			Words: []string{unescapeYaml(unquote(m[2]))}}, true
	}
	if m := dslContainsAll.FindStringSubmatch(a); m != nil {
		lits := regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`).FindAllString(m[2], -1)
		words := []string{}
		for _, l := range lits {
			words = append(words, unescapeYaml(unquote(l)))
		}
		if len(words) == 0 {
			return ExecGroup{}, false
		}
		return ExecGroup{Type: "word", Part: "body", Condition: "and", Words: words, Lowercase: m[1] != ""}, true
	}
	return ExecGroup{}, false
}

// dslOrGroup 处理 'a || b'：仅支持同类型（status 合并多码 / 同 part word 合并 or）
func dslOrGroup(expr string) (ExecGroup, bool) {
	parts := strings.Split(expr, "||")
	var statuses []int
	var words []string
	var part, lower string
	for _, p := range parts {
		g, ok := dslAtom(strings.TrimSpace(p))
		if !ok {
			return ExecGroup{}, false
		}
		switch g.Type {
		case "status":
			statuses = append(statuses, g.Status...)
		case "word":
			if part != "" && part != g.Part {
				return ExecGroup{}, false
			}
			part = g.Part
			if lower != "" && lower != boolStr(g.Lowercase) {
				return ExecGroup{}, false
			}
			lower = boolStr(g.Lowercase)
			words = append(words, g.Words...)
		default:
			return ExecGroup{}, false
		}
	}
	if len(statuses) > 0 && len(words) == 0 {
		return ExecGroup{Type: "status", Part: "body", Condition: "or", Status: statuses}, true
	}
	if len(words) > 0 && len(statuses) == 0 {
		return ExecGroup{Type: "word", Part: part, Condition: "or", Words: words, Lowercase: lower == "true"}, true
	}
	return ExecGroup{}, false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func parseSeconds(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%g", &f)
	return f * 1000 // 秒 → 毫秒
}

// ---------- xray / afrog（CEL 表达式格式） ----------

type celStep struct {
	Request struct {
		Method         string            `yaml:"method"`
		Path           string            `yaml:"path"`
		Headers        map[string]string `yaml:"headers"`
		Body           string            `yaml:"body"`
		FollowRedirect bool              `yaml:"follow_redirects"`
		Search         string            `yaml:"search"`
	} `yaml:"request"`
	Expression string `yaml:"expression"`
}

type tplXray struct {
	Name       string             `yaml:"name"`
	Transport  string             `yaml:"transport"`
	Rules      map[string]celStep `yaml:"rules"`
	Expression string             `yaml:"expression"`
	Detail     struct {
		Author        string   `yaml:"author"`
		Description   string   `yaml:"description"`
		Links         []string `yaml:"links"`
		Tags          []string `yaml:"tags"`
		Vulnerability struct {
			ID    string `yaml:"id"`
			Level string `yaml:"level"`
		} `yaml:"vulnerability"`
	} `yaml:"detail"`
}

type tplAfrog struct {
	ID      string         `yaml:"id"`
	Info    tplInfo        `yaml:"info"`
	Set     map[string]any `yaml:"set"`
	tplXray `yaml:",inline"`
}

func parseXray(content []byte) (*Rule, error) {
	var t tplXray
	if err := yaml.Unmarshal(content, &t); err != nil {
		return nil, err
	}
	if t.Name == "" || len(t.Rules) == 0 {
		return nil, fmt.Errorf("缺少 name 或 rules")
	}
	r := &Rule{
		Source:      "xray",
		RuleID:      t.Name,
		Name:        t.Name,
		Severity:    normalizeSeverity(t.Detail.Vulnerability.Level, "high"),
		Tags:        strings.Join(t.Detail.Tags, ","),
		Description: t.Detail.Description,
		Enabled:     true,
	}
	exec, ok := buildCelExec(t.Rules, t.Expression, nil)
	r.execTmp = exec
	r.unsupported = !ok
	return r, nil
}

func parseAfrog(content []byte) (*Rule, error) {
	var t tplAfrog
	if err := yaml.Unmarshal(content, &t); err != nil {
		return nil, err
	}
	if t.ID == "" || len(t.Rules) == 0 {
		return nil, fmt.Errorf("缺少 id 或 rules")
	}
	r := &Rule{
		Source:      "afrog",
		RuleID:      t.ID,
		Name:        t.Info.Name,
		Severity:    normalizeSeverity(t.Info.Severity, "high"),
		Tags:        t.Info.Tags,
		Description: t.Info.Description,
		Enabled:     true,
	}
	vars := map[string]string{}
	for k, v := range t.Set {
		s, ok := evalSetVar(v)
		if !ok {
			r.unsupported = true
			continue
		}
		vars[k] = s
	}
	exec, ok := buildCelExec(t.Rules, t.Expression, vars)
	r.execTmp = exec
	if !ok {
		r.unsupported = true
	}
	return r, nil
}

// buildCelExec 将命名规则步骤 + 顶层 expression 转为执行模型
func buildCelExec(rules map[string]celStep, topExpr string, vars map[string]string) (*ExecRule, bool) {
	names := orderedRuleNames(rules, topExpr)
	if len(names) == 0 {
		return &ExecRule{Logic: "and", Vars: vars}, false
	}
	logic := "and"
	switch topLogic(topExpr, names) {
	case "or":
		logic = "or"
	case "and":
	case "mixed":
		return &ExecRule{Logic: "and", Vars: vars}, false
	}
	exec := &ExecRule{Logic: logic, Vars: vars}
	okAll := true
	for _, n := range names {
		st := rules[n]
		groups, ok := celGroups(st.Expression)
		var branches [][]ExecGroup
		if !ok {
			// 尝试顶层 || 分支
			branches, ok = ParseBranches(st.Expression)
			if !ok {
				okAll = false
				continue
			}
		}
		exec.Steps = append(exec.Steps, ExecStep{
			Method:         orDefault(upperMethod(st.Request.Method), "GET"),
			Path:           st.Request.Path,
			Body:           st.Request.Body,
			Headers:        st.Request.Headers,
			FollowRedirect: st.Request.FollowRedirect,
			Logic:          "and",
			Groups:         groups,
			Branches:       branches,
		})
		if st.Request.Search != "" {
			okAll = false // search 回填暂不支持
		}
	}
	return exec, okAll && len(exec.Steps) == len(names)
}

// orderedRuleNames 按顶层表达式顺序取步骤名；失败则按 r0,r1 排序兜底
func orderedRuleNames(rules map[string]celStep, topExpr string) []string {
	if topExpr != "" {
		re := regexp.MustCompile(`\b(r\d+)\s*\(`)
		out := []string{}
		for _, m := range re.FindAllStringSubmatch(topExpr, -1) {
			if _, ok := rules[m[1]]; ok && !contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	// 兜底：r0,r1,... 字典序
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

func topLogic(expr string, names []string) string {
	if expr == "" || len(names) <= 1 {
		return "single"
	}
	lit := expr
	for _, n := range names {
		lit = strings.ReplaceAll(lit, n+"()", "")
	}
	hasOr := strings.Contains(lit, "||")
	hasAnd := strings.Contains(lit, "&&")
	switch {
	case hasOr && hasAnd:
		return "mixed"
	case hasOr:
		return "or"
	default:
		return "and"
	}
}

var (
	celStatusRe  = regexp.MustCompile(`response\.status\s*==\s*(\d+)`)
	celBodyBRe   = celBytesRe(`response\.body`, "")
	celTitleBRe  = celBytesRe(`response\.title`, "")
	celHeaderRe  = regexp.MustCompile(`response\.headers\["([^"]+)"\]\.contains\((?:b)?(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\)`)
	celBodyStrRe = regexp.MustCompile(`response\.body\.contains\("((?:[^"\\]|\\.)*)"\)`)
	celBMatchRe  = regexp.MustCompile(`(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\.bmatches\(response\.body\)`)
	celBStartsRe = celBytesRe(`response\.body`, `bstartsWith`)
	celIContRe   = regexp.MustCompile(`response\.body\.icontains\("((?:[^"\\]|\\.)*)"\)`)
	celLatGteRe  = regexp.MustCompile(`response\.latency\s*>=\s*(\d+)`)
	celLatLteRe  = regexp.MustCompile(`response\.latency\s*<=\s*(\d+)`)
)

// celBytesRe 构造 bytes 字面量匹配：field.bcontains(b'x') / b"x" / bytes('x') / bytes("x") / bytes(string('x'))；
// op 可指定 bcontains（默认）或 bstartsWith
func celBytesRe(field, op string) *regexp.Regexp {
	if op == "" {
		op = `bcontains`
	}
	q := `(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`
	return regexp.MustCompile(field + `\.` + op + `\((?:b` + q + `|bytes\((?:string\()?` + q + `\)?\))\)`)
}

// celGroups 解析 CEL 表达式。支持 && 组合、顶层 || 分支（任一分支全真命中）、
// status/body/title/header/bmatches 正则/bstartsWith/icontains/latency 等结构。
func celGroups(expr string) ([]ExecGroup, bool) {
	return celGroupsBranch(expr, false)
}

func celGroupsBranch(expr string, isBranch bool) ([]ExecGroup, bool) {
	if strings.TrimSpace(expr) == "" {
		return nil, false
	}
	// 顶层 || 拆分（字面量与括号感知）
	if !isBranch {
		if parts := splitTopLevelOR(expr); len(parts) > 1 {
			return nil, false // 由调用方处理分支
		}
	}
	groups := []ExecGroup{}
	if strings.Contains(stripStringLiterals(expr), "||") {
		return nil, false
	}
	residue := stripKnown(stripStringLiterals(expr))
	if residue != "" {
		return nil, false
	}
	for _, m := range celStatusRe.FindAllStringSubmatch(expr, -1) {
		groups = append(groups, ExecGroup{Type: "status", Part: "body", Condition: "or", Status: []int{atoi(m[1])}})
	}
	for _, m := range celBodyBRe.FindAllStringSubmatch(expr, -1) {
		if lit := firstNonEmpty(m[1], m[2], m[3], m[4]); lit != "" {
			groups = append(groups, ExecGroup{Type: "word", Part: "body", Condition: "and", Words: []string{unescapeYaml(lit)}})
		}
	}
	for _, m := range celTitleBRe.FindAllStringSubmatch(expr, -1) {
		if lit := firstNonEmpty(m[1], m[2], m[3], m[4]); lit != "" {
			groups = append(groups, ExecGroup{Type: "word", Part: "body", Condition: "and", Words: []string{unescapeYaml(lit)}})
		}
	}
	for _, m := range celHeaderRe.FindAllStringSubmatch(expr, -1) {
		hdr, word := m[1], firstNonEmpty(m[2], m[3])
		groups = append(groups, ExecGroup{Type: "word", Part: "header", Condition: "and", Words: []string{hdr + ": " + word}})
	}
	for _, m := range celBodyStrRe.FindAllStringSubmatch(expr, -1) {
		groups = append(groups, ExecGroup{Type: "word", Part: "body", Condition: "and", Words: []string{unescapeYaml(m[1])}})
	}
	for _, m := range celBMatchRe.FindAllStringSubmatch(expr, -1) {
		if lit := firstNonEmpty(m[1], m[2]); lit != "" {
			groups = append(groups, ExecGroup{Type: "regex", Part: "body", Condition: "or", Regexes: []string{unescapeYaml(lit)}})
		}
	}
	for _, m := range celBStartsRe.FindAllStringSubmatch(expr, -1) {
		if lit := firstNonEmpty(m[1], m[2], m[3], m[4]); lit != "" {
			groups = append(groups, ExecGroup{Type: "prefix", Part: "body", Condition: "and", Words: []string{unescapeYaml(lit)}})
		}
	}
	for _, m := range celIContRe.FindAllStringSubmatch(expr, -1) {
		groups = append(groups, ExecGroup{Type: "word", Part: "body", Condition: "and", Words: []string{unescapeYaml(m[1])}, Lowercase: true})
	}
	for _, m := range celLatGteRe.FindAllStringSubmatch(expr, -1) {
		groups = append(groups, ExecGroup{Type: "latency_gte", Status: []int{atoi(m[1])}})
	}
	for _, m := range celLatLteRe.FindAllStringSubmatch(expr, -1) {
		groups = append(groups, ExecGroup{Type: "latency_lte", Status: []int{atoi(m[1])}})
	}
	if len(groups) == 0 {
		return nil, false
	}
	return groups, true
}

// ParseBranches 顶层 || 分支解析（导出供构建 ExecStep）
func ParseBranches(expr string) ([][]ExecGroup, bool) {
	parts := splitTopLevelOR(expr)
	if len(parts) <= 1 {
		return nil, false
	}
	branches := [][]ExecGroup{}
	for _, p := range parts {
		g, ok := celGroupsBranch(p, true)
		if !ok {
			return nil, false
		}
		branches = append(branches, g)
	}
	return branches, true
}

// splitTopLevelOR 字面量与括号感知地按顶层 || 切分
func splitTopLevelOR(expr string) []string {
	out := []string{}
	depth := 0
	inS, inD := false, false
	last := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case c == '\\' && (inS || inD):
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case inS || inD:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && i+1 < len(expr) && expr[i+1] == '|' && depth == 0:
			out = append(out, expr[last:i])
			i++
			last = i + 1
		}
	}
	out = append(out, expr[last:])
	if len(out) == 1 {
		return nil
	}
	return out
}

// stripStringLiterals 去除字符串字面量（单/双引号），避免字面量中的 ||/&& 干扰
func stripStringLiterals(s string) string {
	var b strings.Builder
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && (inS || inD):
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case inS || inD:
			// 字面量内容与引号一并省略
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// stripKnown 去掉可识别的结构，返回残留（非空说明含未知语法）
func stripKnown(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	// 先去掉所有括号（字面量已被移除，函数参数仅剩外壳标识符）
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	reps := []string{
		"response.status==", "&&", "||",
		"response.body.bcontains", "response.title.bcontains",
		"response.body.contains", "response.title.contains",
		"response.body.bstartswith", "response.title.bstartswith",
		"response.body.icontains", "response.title.icontains",
		"response.headers[].contains", "response.headers[].bcontains", "response.headers[].icontains",
		"response.content_type.contains", "response.content_type.bcontains",
		"response.raw_header.contains", "response.raw_header.bcontains",
		".bmatchesresponse.body", ".matchesresponse.body", ".bmatchesresponse.title",
		"response.latency>=", "response.latency<=", "response.latency==",
		"bytes", "string", "b", // 已知函数外壳参数残留（顺序：先长后短）
	}
	for _, rep := range reps {
		s = strings.ReplaceAll(s, rep, "")
	}
	s = regexp.MustCompile(`\d+`).ReplaceAllString(s, "")
	return s
}

// evalSetVar 计算 set 变量：base64/md5/url_encode/urlencode/hex/reverse('x')；
// randstr/rand_text_*/rand_int 等随机函数用确定值占位（避免不可执行）
func evalSetVar(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return fmt.Sprint(v), true
	}
	t := strings.TrimSpace(s)
	lit := `"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'`
	call := func(name string) (string, bool) {
		m := regexp.MustCompile(`^` + name + `\(\s*(?:` + lit + `)\s*\)$`).FindStringSubmatch(t)
		if m == nil {
			return "", false
		}
		return unescapeYaml(firstNonEmpty(m[1], m[2])), true
	}
	if x, ok := call(`base64`); ok {
		return base64.StdEncoding.EncodeToString([]byte(x)), true
	}
	if x, ok := call(`md5`); ok {
		sum := md5.Sum([]byte(x))
		return hex.EncodeToString(sum[:]), true
	}
	if x, ok := call(`url_encode`); ok {
		return url.QueryEscape(x), true
	}
	if x, ok := call(`urlencode`); ok {
		return url.QueryEscape(x), true
	}
	if x, ok := call(`hex`); ok {
		return hex.EncodeToString([]byte(x)), true
	}
	if x, ok := call(`reverse`); ok {
		r := []rune(x)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r), true
	}
	// 随机类函数：确定占位
	for _, rf := range []string{`randstr`, `rand_text_alpha`, `rand_text_numeric`, `rand_text_alphanumeric`, `rand_base`, `rand_int`, `rand_char`} {
		if regexp.MustCompile(`^` + rf + `\(`).MatchString(t) {
			return "cysec", true
		}
	}
	if regexp.MustCompile(`^(md5|sha256|base64|url_encode|urlencode|hex|reverse)\(`).MatchString(t) {
		// 已知函数但参数引用其他变量：保留原表达式，执行时用 SubstituteAll 替换后再算
		return t, true
	}
	return unescapeYaml(t), true
}

func plainVar(v any) string {
	if s, ok := v.(string); ok {
		return unescapeYaml(s)
	}
	return fmt.Sprint(v)
}

// ---------- 辅助 ----------

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func unescapeYaml(s string) string {
	s = strings.NewReplacer(`\"`, `"`, `\'`, `'`, `\\`, `\`, `\n`, "\n", `\t`, "\t").Replace(s)
	return s
}

func upperMethod(m string) string { return strings.ToUpper(strings.TrimSpace(m)) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func atoi(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
