// Package plugins 定义平台统一的插件架构。
// 所有发现、测绘、扫描、指纹与风险检测能力均以插件形式注册，
// 新增能力无需修改核心业务逻辑（见需求文档 第二十九节）。
package plugins

import (
	"fmt"
	"sort"
	"sync"
)

// ProbeResult 存活探测结果
type ProbeResult struct {
	Alive     bool
	Method    string // icmp/tcp/http/https/dns
	LatencyMs int64
}

// PortResult 端口扫描结果
type PortResult struct {
	Port     int
	Protocol string
	State    string
	Banner   string
	Service  string
	Version  string
}

// WebResult Web 资产识别结果
type WebResult struct {
	URL         string
	IP          string
	Domain      string
	Port        int
	Protocol    string
	StatusCode  int
	Title       string
	Server      string
	ContentType string
	RespSize    int64
	Certificate string
	Headers     map[string]string
}

// FingerprintResult 技术指纹
type FingerprintResult struct {
	Category string // web_server / framework / cms / frontend
	Name     string
	Detail   string
}

// VulnResult 风险检测结果
type VulnResult struct {
	VulnID      string
	Name        string
	Severity    string // critical/high/medium/low/info
	Description string
	Solution    string
	Evidence    string
	Request     string // 检测时的请求报文
	Response    string // 检测时的响应报文
	Scanner     string // 检测来源标识（builtin / rule:nuclei 等）
	Component   string
}

// RiskContext 风险检测插件拿到的上下文
type RiskContext struct {
	Web     *WebResult
	Port    *PortResult
	IP      string
	Body    string // 首页响应体（截断）
	Headers map[string]string
	Client  HTTPDoer
}

// HTTPDoer 由引擎注入的受限 HTTP 客户端（带超时、限定目标）
type HTTPDoer interface {
	Do(url string) (*HTTPResponse, error)
}

type HTTPResponse struct {
	StatusCode  int
	Headers     map[string]string
	Body        string
	ContentType string
	RespSize    int64
}

// ---- 插件接口 ----

type Prober interface {
	Name() string
	Probe(ip string, timeoutSec int) ProbeResult
}

type PortScanner interface {
	Name() string
	Scan(ip string, ports []int, timeoutSec int) []PortResult
}

type ServiceIdentifier interface {
	Name() string
	Identify(ip string, pr PortResult, timeoutSec int) PortResult // enrich
}

type DomainResolver interface {
	Name() string
	Resolve(domain string) (ip string, cname string, err error)
}

type SpaceMapper interface { // 空间测绘数据源插件（Provider）
	Name() string
	// Map 对单个 IP 测绘：返回关联的 domain/port/service/url 等信息；无结果返回 nil
	Map(ip string) []MappingRecord
}

type MappingRecord struct {
	IP          string
	Domain      string
	Port        int
	Protocol    string
	Service     string
	URL         string
	Title       string
	Fingerprint string
	Source      string
}

type Fingerprinter interface {
	Name() string
	Match(web WebResult, body string) []FingerprintResult
}

type RiskScanner interface {
	Name() string
	Category() string // web/service/config/leak/ssl/component
	Scan(ctx RiskContext) []VulnResult
}

// ---- 注册中心 ----

var (
	mu             sync.RWMutex
	probers        = map[string]Prober{}
	portScanners   = map[string]PortScanner{}
	serviceIDs     = map[string]ServiceIdentifier{}
	resolvers      = map[string]DomainResolver{}
	mappers        = map[string]SpaceMapper{}
	fingerprinters = map[string]Fingerprinter{}
	riskScanners   = map[string]RiskScanner{}
)

func RegisterProber(p Prober)                       { mu.Lock(); probers[p.Name()] = p; mu.Unlock() }
func RegisterPortScanner(p PortScanner)             { mu.Lock(); portScanners[p.Name()] = p; mu.Unlock() }
func RegisterServiceIdentifier(s ServiceIdentifier) { mu.Lock(); serviceIDs[s.Name()] = s; mu.Unlock() }
func RegisterResolver(r DomainResolver)             { mu.Lock(); resolvers[r.Name()] = r; mu.Unlock() }
func RegisterMapper(m SpaceMapper)                  { mu.Lock(); mappers[m.Name()] = m; mu.Unlock() }
func RegisterFingerprinter(f Fingerprinter)         { mu.Lock(); fingerprinters[f.Name()] = f; mu.Unlock() }
func RegisterRiskScanner(r RiskScanner)             { mu.Lock(); riskScanners[r.Name()] = r; mu.Unlock() }

func AllProbers() []Prober {
	mu.RLock()
	defer mu.RUnlock()
	out := []Prober{}
	for _, p := range probers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func AllPortScanners() []PortScanner {
	mu.RLock()
	defer mu.RUnlock()
	out := []PortScanner{}
	for _, p := range portScanners {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func AllServiceIdentifiers() []ServiceIdentifier {
	mu.RLock()
	defer mu.RUnlock()
	out := []ServiceIdentifier{}
	for _, s := range serviceIDs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func AllResolvers() []DomainResolver {
	mu.RLock()
	defer mu.RUnlock()
	out := []DomainResolver{}
	for _, r := range resolvers {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func AllMappers() []SpaceMapper {
	mu.RLock()
	defer mu.RUnlock()
	out := []SpaceMapper{}
	for _, m := range mappers {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func AllFingerprinters() []Fingerprinter {
	mu.RLock()
	defer mu.RUnlock()
	out := []Fingerprinter{}
	for _, f := range fingerprinters {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
func AllRiskScanners() []RiskScanner {
	mu.RLock()
	defer mu.RUnlock()
	out := []RiskScanner{}
	for _, r := range riskScanners {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ListPlugins 调试用：列出已注册插件
func ListPlugins() map[string][]string {
	return map[string][]string{
		"prober": names(len(probers), func(i func(string)) {
			for n := range probers {
				i(n)
			}
		}),
		"port_scanner": names(len(portScanners), func(i func(string)) {
			for n := range portScanners {
				i(n)
			}
		}),
		"service": names(len(serviceIDs), func(i func(string)) {
			for n := range serviceIDs {
				i(n)
			}
		}),
		"resolver": names(len(resolvers), func(i func(string)) {
			for n := range resolvers {
				i(n)
			}
		}),
		"mapper": names(len(mappers), func(i func(string)) {
			for n := range mappers {
				i(n)
			}
		}),
		"fingerprint": names(len(fingerprinters), func(i func(string)) {
			for n := range fingerprinters {
				i(n)
			}
		}),
		"risk": names(len(riskScanners), func(i func(string)) {
			for n := range riskScanners {
				i(n)
			}
		}),
	}
}

func names(n int, iter func(func(string))) []string {
	out := make([]string, 0, n)
	iter(func(s string) { out = append(out, s) })
	sort.Strings(out)
	return out
}

var _ = fmt.Sprintf
