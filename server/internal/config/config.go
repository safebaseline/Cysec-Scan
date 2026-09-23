package config

import (
	"os"

	"cysec/internal/ai"
	"cysec/internal/mapper"
	"cysec/internal/netproxy"

	"gopkg.in/yaml.v3"
)

type Config struct {
	AI        ai.Config         `yaml:"ai"` // AI 研判配置（界面保存时写回；启动时种子到设置表）
	Server    Server            `yaml:"server"`
	UserAgent string            `yaml:"user_agent"` // 已废弃：兼容旧配置，headers 中的 User-Agent 优先
	Headers   map[string]string `yaml:"headers"`    // 出站请求 HTTP 头：User-Agent 为全局 UA，其余为漏洞扫描引擎附加头
	Database  Database          `yaml:"database"`
	Worker    Worker            `yaml:"worker"`
	Auth      Auth              `yaml:"auth"`
	Scan      Scan              `yaml:"scan"`
	Proxy     Proxy             `yaml:"proxy"`
	Mapping   mapper.Config     `yaml:"mapping"`
}

// Proxy 全局出站代理（类型定义位于 netproxy，此处为别名）
type Proxy = netproxy.Proxy

type Server struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Database struct {
	Driver string `yaml:"driver"`
	Path   string `yaml:"path"`
}

type Worker struct {
	Concurrency int `yaml:"concurrency"`
}

type Auth struct {
	BootstrapAdminUser string `yaml:"bootstrap_admin_user"`
	BootstrapAdminPass string `yaml:"bootstrap_admin_pass"`
	TokenTTLHours      int    `yaml:"token_ttl_hours"`
}

type Scan struct {
	SubdomainBrute     bool     `yaml:"subdomain_brute"`
	SubdomainWorkers   int      `yaml:"subdomain_workers"`
	SubdomainWordlist  string   `yaml:"subdomain_wordlist"`   // 可选：额外字典文件路径
	SubdomainCertQuery bool     `yaml:"subdomain_cert_query"` // 证书透明度（crt.name）被动收集，与爆破互补
	WebAutoScan        bool     `yaml:"web_autoscan"`         // 新增 Web 资产实时漏洞扫描（全部来源）
	TimeoutSeconds     int      `yaml:"timeout_seconds"`
	MaxTargetsPerTask  int      `yaml:"max_targets_per_task"`
	AuthorizedCIDRs    []string `yaml:"authorized_cidrs"` // 空表示不额外限制（仍限定任务目标范围内）
	TopPorts           []int    `yaml:"top_ports"`
	MaxPortPerTarget   int      `yaml:"max_ports_per_target"`
	RiskCheckPaths     []string `yaml:"risk_check_paths"`
}

func Default() *Config {
	return &Config{
		Server:    Server{Host: "0.0.0.0", Port: 8080},
		UserAgent: "CysecScan/1.0 (authorized-scan)",
		Database:  Database{Driver: "sqlite", Path: "data/cysec.db"},
		Worker:    Worker{Concurrency: 8},
		Auth:      Auth{BootstrapAdminUser: "admin", BootstrapAdminPass: "admin123", TokenTTLHours: 72},
		Scan: Scan{
			SubdomainBrute:     true,
			SubdomainWorkers:   500,
			SubdomainCertQuery: true,
			WebAutoScan:        true,
			TimeoutSeconds:     5,
			MaxTargetsPerTask:  65536,
			TopPorts: []int{
				21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
				993, 995, 1433, 1521, 2375, 3306, 3389, 5432, 5900,
				6379, 7001, 8080, 8443, 8888, 9200, 11211, 27017,
			},
			MaxPortPerTarget: 1024,
			RiskCheckPaths: []string{
				"/robots.txt", "/.git/config", "/server-status",
				"/phpmyadmin/", "/actuator/health", "/admin/",
				"/api/", "/.env", "/backup.zip", "/console",
			},
		},
		Proxy:   Proxy{Enable: false, Type: "http"},
		Mapping: mapper.Config{Enabled: false, Size: 100},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
