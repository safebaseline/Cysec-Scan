// Package mapper 空间测绘数据源（Provider）注册中心。
// 对接 FOFA / Quake / Shodan / 0.zone(零零信安) / ZoomEye 五个网络空间测绘引擎，
// 统一输入目标（IP 或域名），统一输出归一化的测绘记录（IP/Domain/Port/Service/URL/Title/指纹）。
// 出站请求统一走 netproxy（受全局代理配置控制）。
package mapper

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"cysec/internal/netproxy"
)

// Config 空间测绘配置（config.yaml 可给默认值，界面可运行时修改并持久化）
type Config struct {
	Enabled    bool `yaml:"enabled" json:"enabled"`         // 总开关
	Size       int  `yaml:"size" json:"size"`               // 每个引擎单次查询条数（默认100）
	IntervalMs int  `yaml:"interval_ms" json:"interval_ms"` // 每引擎两次请求最小间隔毫秒（0=用内置默认，防 429 限流）

	FOFAEnable  bool   `yaml:"fofa_enable" json:"fofa_enable"`
	FOFAKey     string `yaml:"fofa_key" json:"fofa_key"`
	FOFABaseURL string `yaml:"fofa_base_url" json:"fofa_base_url"`

	QuakeEnable  bool   `yaml:"quake_enable" json:"quake_enable"`
	QuakeKey     string `yaml:"quake_key" json:"quake_key"`
	QuakeBaseURL string `yaml:"quake_base_url" json:"quake_base_url"`

	ShodanEnable  bool   `yaml:"shodan_enable" json:"shodan_enable"`
	ShodanKey     string `yaml:"shodan_key" json:"shodan_key"`
	ShodanBaseURL string `yaml:"shodan_base_url" json:"shodan_base_url"`

	ZeroZoneEnable  bool   `yaml:"zerozone_enable" json:"zerozone_enable"`
	ZeroZoneKeyID   string `yaml:"zerozone_key_id" json:"zerozone_key_id"`
	ZeroZoneBaseURL string `yaml:"zerozone_base_url" json:"zerozone_base_url"`

	ZoomEyeEnable  bool   `yaml:"zoomeye_enable" json:"zoomeye_enable"`
	ZoomEyeKey     string `yaml:"zoomeye_key" json:"zoomeye_key"`
	ZoomEyeBaseURL string `yaml:"zoomeye_base_url" json:"zoomeye_base_url"`
}

// Record 归一化测绘记录（对应需求文档 6.3 统一输出）
type Record struct {
	Provider    string
	IP          string
	Domain      string
	Port        int
	Protocol    string
	Service     string
	URL         string
	Title       string
	Server      string
	Fingerprint string
}

// Provider 测绘引擎适配器接口
type Provider interface {
	Name() string
	// Query target 为 IP 或域名；isDomain 指示是否按域名查询
	Query(cfg Config, target string, isDomain bool) ([]Record, error)
	// Ready 该引擎当前是否已配置启用
	Ready(cfg Config) bool
}

var (
	mu       sync.RWMutex
	current  = Config{Size: 100}
	registed = []Provider{}
)

func init() {
	Register(&fofaProvider{}, &quakeProvider{}, &shodanProvider{}, &zeroZoneProvider{}, &zoomEyeProvider{})
}

// Register 注册测绘引擎适配器
func Register(ps ...Provider) {
	mu.Lock()
	registed = append(registed, ps...)
	mu.Unlock()
}

// Configure 设置当前生效配置（运行时热更新）
func Configure(c Config) {
	if c.Size <= 0 {
		c.Size = 100
	}
	if c.Size > 1000 {
		c.Size = 1000
	}
	mu.Lock()
	current = c
	mu.Unlock()
}

// Current 当前生效配置
func Current() Config {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Providers 已注册引擎列表
func Providers() []Provider {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Provider, len(registed))
	copy(out, registed)
	return out
}

// QueryAll 用当前配置查询所有已启用引擎；返回记录与各引擎错误信息
func QueryAll(target string) ([]Record, map[string]string) {
	return QueryAllWith(Current(), target)
}

// QueryAllWith 指定配置查询（用于未保存的配置测试）
func QueryAllWith(cfg Config, target string) ([]Record, map[string]string) {
	if !cfg.Enabled || target == "" {
		return nil, nil
	}
	isDomain := net.ParseIP(target) == nil
	records := []Record{}
	errs := map[string]string{}
	for _, p := range Providers() {
		if !p.Ready(cfg) {
			continue
		}
		recs, err := p.Query(cfg, target, isDomain)
		if err != nil {
			errs[p.Name()] = err.Error()
			continue
		}
		for i := range recs {
			recs[i].Provider = p.Name()
		}
		records = append(records, recs...)
	}
	return records, errs
}

// httpClient 测绘引擎 API 出站直连，不走全局代理（即使配置了代理）
func httpClient() *http.Client { return netproxy.NewDirectHTTPClient(30, 0) }

// Describe 状态描述
func Describe() string {
	cfg := Current()
	if !cfg.Enabled {
		return "disabled"
	}
	on := []string{}
	for _, p := range Providers() {
		if p.Ready(cfg) {
			on = append(on, p.Name())
		}
	}
	if len(on) == 0 {
		return "enabled（未配置任何数据源）"
	}
	return "enabled: " + strings.Join(on, ", ")
}
