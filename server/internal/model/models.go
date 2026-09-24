package model

import "time"

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`    // bcrypt hash
	Role      string    `json:"role"` // admin / auditor / viewer
	CreatedAt time.Time `json:"created_at"`
}

type Project struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// AssetIP IP 资产
type AssetIP struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	IP          string    `json:"ip"`
	Network     string    `json:"network"` // public / private
	Alive       bool      `json:"alive"`
	ProbeMethod string    `json:"probe_method"`
	LatencyMs   int64     `json:"latency_ms"`
	LastProbe   time.Time `json:"last_probe"`
	RiskScore   int       `json:"risk_score"`
	FirstSeen   time.Time `json:"first_seen"`
	Source      string    `json:"source"`
}

// AssetDomain 域名资产
type AssetDomain struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	Domain    string    `json:"domain"`
	CNAME     string    `json:"cname"`
	IP        string    `json:"ip"` // 解析 IP
	FirstSeen time.Time `json:"first_seen"`
	Source    string    `json:"source"`
}

// AssetPort 端口资产
type AssetPort struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"` // tcp/udp
	State     string    `json:"state"`
	Service   string    `json:"service"`
	Version   string    `json:"version"`
	Banner    string    `json:"banner"`
	Category  string    `json:"category"` // 资产分拣类别
	FirstSeen time.Time `json:"first_seen"`
	Source    string    `json:"source"`
}

// AssetWeb Web 资产
type AssetWeb struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	URL         string    `json:"url"`
	IP          string    `json:"ip"`
	Domain      string    `json:"domain"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	StatusCode  int       `json:"status_code"`
	Title       string    `json:"title"`
	Server      string    `json:"server"`
	ContentType string    `json:"content_type"`
	RespSize    int64     `json:"resp_size"`
	Certificate string    `json:"certificate"`
	Headers     string    `json:"headers"` // JSON
	Tech        string    `json:"tech"`    // 识别出的指纹，逗号分隔
	FirstSeen   time.Time `json:"first_seen"`
	Source      string    `json:"source"`
}

// AssetURL URL 资产池
type AssetURL struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	WebID       int64     `json:"web_id"`
	URL         string    `json:"url"`
	Method      string    `json:"method"`
	StatusCode  int       `json:"status_code"`
	ContentType string    `json:"content_type"`
	RespSize    int64     `json:"resp_size"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
}

// AssetFingerprint 技术指纹
type AssetFingerprint struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	WebURL    string    `json:"web_url"`
	Category  string    `json:"category"` // web_server / framework / cms / frontend
	Name      string    `json:"name"`
	Detail    string    `json:"detail"`
	FirstSeen time.Time `json:"first_seen"`
}

// Vulnerability 漏洞结果（指纹: 资产+端口+URL+漏洞ID 去重）
type Vulnerability struct {
	ID          int64     `json:"id"`
	ProjectID   int64     `json:"project_id"`
	VulnID      string    `json:"vuln_id"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"` // critical/high/medium/low/info
	IP          string    `json:"ip"`
	Domain      string    `json:"domain"`
	Port        int       `json:"port"`
	URL         string    `json:"url"`
	Service     string    `json:"service"`
	Component   string    `json:"component"`
	Description string    `json:"description"`
	Solution    string    `json:"solution"`
	Evidence    string    `json:"evidence"`
	Request     string    `json:"request"`  // 检测请求报文
	Response    string    `json:"response"` // 检测响应报文
	Mark        string    `json:"mark"`     // confirmed/false_positive/ignored/空=未标记
	Scanner     string    `json:"scanner"`
	AIMark      string    `json:"ai_mark"`      // AI 研判结论（confirmed/false_positive）
	AIConfidence string   `json:"ai_confidence"` // 置信度
	AIReasoning string    `json:"ai_reasoning"` // AI 推理依据（详情页展示）
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type ScanTask struct {
	ID             int64      `json:"id"`
	ProjectID      int64      `json:"project_id"`
	Name           string     `json:"name"`
	Mode           string     `json:"mode"`        // quick / standard / deep
	Targets        string     `json:"targets"`     // 换行分隔
	TargetType     string     `json:"target_type"` // ip / domain / url
	Ports          string     `json:"ports"`       // 空=常用端口, "1-65535"=全端口, 逗号分隔
	Status         string     `json:"status"`      // pending/running/paused/done/failed/canceled
	Progress       int        `json:"progress"`
	Concurrency    int        `json:"concurrency"`
	TimeoutSec     int        `json:"timeout_sec"`
	Priority       int        `json:"priority"`
	CronExpr       string     `json:"cron_expr"`            // 非空表示周期任务
	ScanInterval   string     `json:"scan_interval"`        // 周期：8h / 24h / 1w，空=一次性
	Phases         string     `json:"phases"`               // 执行阶段（逗号分隔 collect/vulnscan/weakness/alive；空=按 mode 兼容映射）
	ApexRoots      string     `json:"apex_roots,omitempty"` // 运行时：任务输入域名根（逗号分隔），域名一致性校验基准（不落库）
	FPIgnores      []string   `json:"-"`                    // 运行时：项目误报资产配置（命中的采集资产不入库）
	SubdomainBrute bool       `json:"subdomain_brute"`      // 资产收集阶段是否执行子域名爆破
	CreatedBy      string     `json:"created_by"`
	Error          string     `json:"error"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
}

type ScanLog struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type AssetChange struct {
	ID        int64     `json:"id"`
	ProjectID int64     `json:"project_id"`
	TaskID    int64     `json:"task_id"`
	AssetType string    `json:"asset_type"` // ip/domain/port/web/url/vuln
	Asset     string    `json:"asset"`
	Change    string    `json:"change"` // add / remove
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

type SystemLog struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Object    string    `json:"object"`
	ClientIP  string    `json:"client_ip"`
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}

type Token struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Weakness 弱点管理记录：暗链 / 坏链 / 敏感字 / WIH JS 敏感信息（统一归并展示）
type Weakness struct {
	ID         int64  `json:"id"`
	ProjectID  int64  `json:"project_id"`
	TaskID     int64  `json:"task_id"`
	WebURL     string `json:"web_url"`    // 所属站点
	PageURL    string `json:"page_url"`   // 问题所在页面链接（链接类=发现链接的页面；敏感字/WIH=命中页面）
	PageTitle  string `json:"page_title"` // 问题所在页面标题
	Type       string `json:"type"`       // darklink / brokenlink / sensword / wih
	URL        string `json:"url"`        // 触发链接（敏感字为站点 URL）
	Anchor     string `json:"anchor"`     // 锚文本
	StatusCode int    `json:"status_code"`
	Detail     string `json:"detail"`
	Severity   string `json:"severity"`
	Evidence      string `json:"evidence"` // WIH 命中内容 / 敏感字上下文
	Context       string `json:"context"`  // 引用位置（链接类弱点）：祖先链 + 锚标签 HTML 片段
	Mark          string `json:"mark"`
	AIMark        string `json:"ai_mark"`       // AI 研判结论（confirmed/false_positive）
	AIConfidence  string `json:"ai_confidence"` // 置信度
	AIReasoning   string `json:"ai_reasoning"`  // AI 推理依据（详情页展示）
	CreatedAt     string `json:"created_at"`
}
