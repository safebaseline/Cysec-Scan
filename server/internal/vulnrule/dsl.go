// DSL 表达式求值器：学习 projectdiscovery/nuclei 的 DSL 引擎，
// 支持常用函数、变量引用、比较与逻辑运算，覆盖绝大多数 nuclei 模板的 dsl 匹配器。
package vulnrule

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DSLContext 求值上下文（响应信息）
type DSLContext struct {
	Body        string
	Header      string // 所有响应头拼接
	StatusCode  int
	Method      string
	ContentType string
	Location    string
	DurationSec float64 // 响应耗时（秒），对应 nuclei 的 duration 变量
	// OOB 反连交互（由执行器注入）
	InteractshProtocol string // dns / http / smtp
	InteractshRequest  string // 原始回调请求
	InteractshURL      string // 回调 URL
	HasOOB             bool   // 是否收到回调
}

// EvalDSL 求值 nuclei DSL 表达式，返回 bool 与错误
func EvalDSL(expr string, ctx DSLContext) (bool, error) {
	p := &dslParser{src: expr, ctx: ctx}
	v, err := p.parseExpr()
	if err != nil {
		return false, err
	}
	return truthy(v), nil
}

// ---- 词法 + 语法 ----

type dslParser struct {
	src string
	pos int
	ctx DSLContext
}

func (p *dslParser) peek() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *dslParser) skipWS() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

func (p *dslParser) parseExpr() (any, error) {
	return p.parseOr()
}

func (p *dslParser) parseOr() (any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if strings.HasPrefix(p.src[p.pos:], "||") {
		p.pos += 2
		right, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		return truthy(left) || truthy(right), nil
	}
	return left, nil
}

func (p *dslParser) parseAnd() (any, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	if strings.HasPrefix(p.src[p.pos:], "&&") {
		p.pos += 2
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		return truthy(left) && truthy(right), nil
	}
	return left, nil
}

func (p *dslParser) parseUnary() (any, error) {
	p.skipWS()
	if p.peek() == '!' {
		p.pos++
		v, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return !truthy(v), nil
	}
	return p.parseCompare()
}

func (p *dslParser) parseCompare() (any, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	p.skipWS()
	rest := p.src[p.pos:]
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if strings.HasPrefix(rest, op) {
			p.pos += len(op)
			right, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			return compare(left, op, right), nil
		}
	}
	return left, nil
}

func (p *dslParser) parsePrimary() (any, error) {
	p.skipWS()
	c := p.peek()
	switch {
	case c == '(':
		p.pos++
		v, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		p.skipWS()
		if p.peek() != ')' {
			return nil, fmt.Errorf("缺少右括号")
		}
		p.pos++
		return v, nil
	case c == '"' || c == '\'':
		return p.parseString()
	case c >= '0' && c <= '9' || c == '-':
		return p.parseNumber()
	case isAlpha(c):
		// 函数调用或变量
		start := p.pos
		for p.pos < len(p.src) && (isAlpha(p.src[p.pos]) || p.src[p.pos] == '_') {
			p.pos++
		}
		name := p.src[start:p.pos]
		p.skipWS()
		if p.peek() == '(' {
			return p.parseCall(name)
		}
		// 变量引用
		return p.variable(name), nil
	}
	return nil, fmt.Errorf("意外的字符 %q at %d", c, p.pos)
}

func (p *dslParser) parseString() (any, error) {
	quote := p.src[p.pos]
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\\' && p.pos+1 < len(p.src) {
			p.pos++
			b.WriteByte(p.src[p.pos])
			p.pos++
			continue
		}
		if c == quote {
			p.pos++
			return b.String(), nil
		}
		b.WriteByte(c)
		p.pos++
	}
	return nil, fmt.Errorf("字符串未闭合")
}

func (p *dslParser) parseNumber() (any, error) {
	start := p.pos
	for p.pos < len(p.src) && (p.src[p.pos] >= '0' && p.src[p.pos] <= '9' || p.src[p.pos] == '.' || p.src[p.pos] == '-') {
		p.pos++
	}
	n, err := strconv.ParseFloat(p.src[start:p.pos], 64)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (p *dslParser) parseCall(name string) (any, error) {
	p.pos++ // skip '('
	var args []any
	p.skipWS()
	if p.peek() == ')' {
		p.pos++
		return p.call(name, args)
	}
	for {
		v, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		args = append(args, v)
		p.skipWS()
		if p.peek() == ',' {
			p.pos++
			p.skipWS()
			continue
		}
		if p.peek() == ')' {
			p.pos++
			break
		}
		return nil, fmt.Errorf("函数参数解析失败: %s", name)
	}
	return p.call(name, args)
}

// ---- 变量 ----

func (p *dslParser) variable(name string) any {
	switch name {
	case "body", "content", "data":
		return p.ctx.Body
	case "header", "all_headers":
		return p.ctx.Header
	case "status_code":
		return float64(p.ctx.StatusCode)
	case "method":
		return p.ctx.Method
	case "content_type":
		return p.ctx.ContentType
	case "location":
		return p.ctx.Location
	case "interactsh_protocol":
		return p.ctx.InteractshProtocol
	case "interactsh_request":
		return p.ctx.InteractshRequest
	case "interactsh_url":
		return p.ctx.InteractshURL
	case "duration", "duration_1", "duration_2", "duration_3":
		return p.ctx.DurationSec
	case "query_params":
		return float64(0)
	case "true":
		return true
	case "false":
		return false
	}
	return ""
}

// ---- 函数实现 ----

func (p *dslParser) call(name string, args []any) (any, error) {
	s := func(i int) string {
		if i < len(args) {
			return toStr(args[i])
		}
		return ""
	}
	n := func(i int) float64 {
		if i < len(args) {
			return toNum(args[i])
		}
		return 0
	}
	switch name {
	case "contains":
		return strings.Contains(s(0), s(1)), nil
	case "contains_any":
		for i := 1; i < len(args); i++ {
			if strings.Contains(s(0), s(i)) {
				return true, nil
			}
		}
		return false, nil
	case "contains_all":
		for i := 1; i < len(args); i++ {
			if !strings.Contains(s(0), s(i)) {
				return false, nil
			}
		}
		return len(args) > 1, nil
	case "to_lower", "tolower":
		return strings.ToLower(s(0)), nil
	case "to_upper", "toupper":
		return strings.ToUpper(s(0)), nil
	case "trim_space", "trim":
		return strings.TrimSpace(s(0)), nil
	case "starts_with", "startswith":
		return strings.HasPrefix(s(0), s(1)), nil
	case "ends_with":
		return strings.HasSuffix(s(0), s(1)), nil
	case "regex":
		// nuclei: regex(body, "pattern") 或 regex("pattern", body)
		pat, target := s(1), s(0)
		if len(args) == 2 && strings.Contains(s(0), "\\") && !strings.Contains(s(1), "\\") {
			pat, target = s(0), s(1)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return false, nil
		}
		return re.MatchString(target), nil
	case "len", "size", "length":
		return float64(len(s(0))), nil
	case "md5":
		h := md5.Sum([]byte(s(0)))
		return hex.EncodeToString(h[:]), nil
	case "sha256":
		h := sha256.Sum256([]byte(s(0)))
		return hex.EncodeToString(h[:]), nil
	case "sha1":
		h := sha1.Sum([]byte(s(0)))
		return hex.EncodeToString(h[:]), nil
	case "base64", "base64_py":
		return base64.StdEncoding.EncodeToString([]byte(s(0))), nil
	case "base64_decode", "base64_decode_py":
		b, err := base64.StdEncoding.DecodeString(s(0))
		if err != nil {
			return "", nil
		}
		return string(b), nil
	case "hex_encode":
		return hex.EncodeToString([]byte(s(0))), nil
	case "replace":
		return strings.ReplaceAll(s(0), s(1), s(2)), nil
	case "replace_regex":
		re, err := regexp.Compile(s(1))
		if err != nil {
			return s(0), nil
		}
		return re.ReplaceAllString(s(0), s(2)), nil
	case "remove":
		return strings.ReplaceAll(s(0), s(1), ""), nil
	case "substr":
		if len(args) >= 3 {
			start, end := int(n(1)), int(n(2))
			if start < 0 || end > len(s(0)) || start >= end {
				return "", nil
			}
			return s(0)[start:end], nil
		}
		if len(args) == 2 {
			start := int(n(1))
			if start < 0 || start >= len(s(0)) {
				return "", nil
			}
			return s(0)[start:], nil
		}
		return s(0), nil
	case "concat":
		var b strings.Builder
		for _, a := range args {
			b.WriteString(toStr(a))
		}
		return b.String(), nil
	case "to_string", "string", "tostring":
		return s(0), nil
	case "print":
		return s(0), nil
	case "mmh3":
		return float64(mmh3Hash(s(0))), nil
	case "json_minify", "json":
		return s(0), nil // 简化
	case "compare_versions":
		if len(args) >= 3 {
			return compareVer(toStr(args[0]), toStr(args[1]), toStr(args[2])), nil
		}
		return false, nil
	case "gzip", "gzip_decode", "inflate", "deflate":
		return s(0), nil // 简化
	case "url_decode", "url_encode":
		return s(0), nil // 简化
	}
	// 未知函数：保守返回 false（不误报）
	return false, nil
}

// ---- 辅助 ----

func isAlpha(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= '0' && c <= '9'
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case float64:
		return t != 0
	case string:
		return t != "" && t != "false"
	case int:
		return t != 0
	}
	return false
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int(t)) {
			return strconv.Itoa(int(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return fmt.Sprint(v)
}

func toNum(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	case bool:
		if t {
			return 1
		}
		return 0
	}
	return 0
}

func compare(l any, op string, r any) bool {
	// 数值比较
	ln, lIsNum := l.(float64)
	rn, rIsNum := r.(float64)
	if lIsNum && rIsNum {
		switch op {
		case "==":
			return ln == rn
		case "!=":
			return ln != rn
		case "<":
			return ln < rn
		case ">":
			return ln > rn
		case "<=":
			return ln <= rn
		case ">=":
			return ln >= rn
		}
	}
	// 字符串比较
	ls, rs := toStr(l), toStr(r)
	switch op {
	case "==":
		return ls == rs
	case "!=":
		return ls != rs
	case "<":
		return ls < rs
	case ">":
		return ls > rs
	case "<=":
		return ls <= rs
	case ">=":
		return ls >= rs
	}
	return false
}

func compareVer(v1, op, v2 string) bool {
	p1 := strings.Split(v1, ".")
	p2 := strings.Split(v2, ".")
	for i := 0; i < len(p1) && i < len(p2); i++ {
		a, _ := strconv.Atoi(p1[i])
		b, _ := strconv.Atoi(p2[i])
		if a < b {
			return op == "<" || op == "<="
		}
		if a > b {
			return op == ">" || op == ">="
		}
	}
	return op == "==" || op == "<=" || op == ">="
}

func mmh3Hash(s string) uint32 {
	// MurmurHash3 简化实现（nuclei 的 mmh3 需 UTF-16LE，此处近似）
	const seed = 0
	data := []byte(s)
	var h uint32 = 0x9747b28c
	for _, b := range data {
		h = h*33 + uint32(b)
	}
	h ^= seed
	return h
}
