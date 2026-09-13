package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cysec/internal/ai"
	"cysec/internal/config"
	"cysec/internal/mapper"
	"cysec/internal/model"
	"cysec/internal/plugins"
	"cysec/internal/store"
	"cysec/internal/subdomain"
	"cysec/internal/vulnrule"

	_ "cysec/plugins/builtin" // 注册内置插件
)

// Engine 任务调度器 + 扫描流水线
type Engine struct {
	store *store.Store
	cfg   *config.Config

	mu       sync.Mutex
	running  map[int64]*taskRun // taskID -> 运行状态
	queue    chan int64
	stopPoll chan struct{}
}

type taskRun struct {
	cancel chan struct{}
	pause  chan struct{}
	resume chan struct{}
}

func New(st *store.Store, cfg *config.Config) *Engine {
	e := &Engine{
		store:    st,
		cfg:      cfg,
		running:  map[int64]*taskRun{},
		queue:    make(chan int64, 1024),
		stopPoll: make(chan struct{}),
	}
	go e.pollLoop()
	go e.monitorLoop()
	return e
}

// ParseInterval 周期字符串 -> 时长；非法返回 0
// 支持预设（8h / 24h / 1w）与自定义小时数（如 6h、48h、168h）
func ParseInterval(s string) time.Duration {
	switch s {
	case "8h":
		return 8 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "1w":
		return 7 * 24 * time.Hour
	}
	// 自定义 Nh（1 ≤ n ≤ 8760）
	if m := regexp.MustCompile(`^(\d{1,4})h$`).FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n >= 1 && n <= 8760 {
			return time.Duration(n) * time.Hour
		}
	}
	return 0
}

// monitorLoop 资产监控调度：每分钟检查周期任务，上次运行结束 + 周期到期后自动重新排队
func (e *Engine) monitorLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopPoll:
			return
		case <-ticker.C:
			tasks, err := e.store.RecurringTasks()
			if err != nil {
				continue
			}
			for _, t := range tasks {
				d := ParseInterval(t.ScanInterval)
				if d <= 0 || t.Status != "done" || t.EndedAt == nil {
					continue
				}
				if time.Since(*t.EndedAt) >= d {
					e.store.LogTask(t.ID, "info", "周期任务到期（"+t.ScanInterval+"），自动重新执行")
					e.store.RequeueTask(t.ID)
				}
			}
		}
	}
}

// pollLoop 任务轮询：取 pending 任务按优先级执行（MVP 单机 Worker；多 Worker 可通过共享队列扩展）
func (e *Engine) pollLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopPoll:
			return
		case <-ticker.C:
			id, ok := e.store.NextPendingTask()
			if !ok {
				continue
			}
			go e.Execute(id)
		}
	}
}

// Submit 提交任务（状态 pending，由 pollLoop 调度）
func (e *Engine) Submit(taskID int64) error {
	return e.store.UpdateTask(taskID, map[string]any{"status": "pending", "progress": 0})
}

// Execute 同步执行任务（含暂停/取消检查）
func (e *Engine) Execute(taskID int64) {
	e.mu.Lock()
	if _, ok := e.running[taskID]; ok {
		e.mu.Unlock()
		return
	}
	run := &taskRun{cancel: make(chan struct{}), pause: make(chan struct{}), resume: make(chan struct{})}
	e.running[taskID] = run
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.running, taskID)
		e.mu.Unlock()
	}()

	task, err := e.store.GetTask(taskID)
	if err != nil {
		return
	}
	runStart := time.Now()
	now := runStart
	e.store.UpdateTask(taskID, map[string]any{"status": "running", "started_at": now})
	e.store.LogTask(taskID, "info", "任务开始执行，模式="+task.Mode)

	// 目标解析（授权范围）
	ips, domains, urls, err := ParseTargets(task.Targets, task.TargetType, e.cfg.Scan.MaxTargetsPerTask)
	if err != nil {
		e.store.UpdateTask(taskID, map[string]any{"status": "failed", "error": err.Error(), "ended_at": time.Now()})
		e.store.LogTask(taskID, "error", "目标解析失败: "+err.Error())
		return
	}
	e.store.LogTask(taskID, "info", fmt.Sprintf("目标解析完成: %d IP, %d Domain, %d URL", len(ips), len(domains), len(urls)))

	// 域名解析 -> IP
	authorized := map[string]bool{}
	for _, ip := range ips {
		authorized[ip] = true
	}
	for _, d := range domains {
		e.upsertDomain(task, d, "")
		for _, r := range plugins.AllResolvers() {
			if ip, cname, err := r.Resolve(d); err == nil && ip != "" {
				if !isAuthorized(ip, authorized, ips) {
					// 仅当解析 IP 落在任务授权的 IP 范围内才纳入；否则仅记录解析关系
					e.upsertDomain(task, d, ip)
					e.store.LogTask(taskID, "info", "域名 "+d+" 解析到 "+ip+"（未授权范围，仅记录关联）")
				} else {
					e.upsertDomain(task, d, ip)
					ips = appendIfNew(ips, ip)
				}
				if cname != "" {
					e.store.Exec(`UPDATE asset_domains SET cname=? WHERE project_id=? AND domain=?`, cname, task.ProjectID, d)
				}
				break
			}
		}
	}
	// 子域名爆破：目标为域名时执行（学习 ksubdomain：高并发 DNS + 字典 + 泛解析过滤）
	if e.cfg.Scan.SubdomainBrute {
		for _, d := range domains {
			select {
			case <-runCancel(e, task.ID):
			default:
			}
			ips = e.bruteSubdomains(task, d, ips)
		}
	}
	for _, ip := range ips {
		authorized[ip] = true
	}

	// URL 直接导入 Web 资产池
	for _, u := range urls {
		e.detectWeb(task, u, "", task.TimeoutSec)
	}

	// 空间资产测绘（所有模式）：IP/域名 → FOFA/Quake/Shodan/0.zone/ZoomEye 等 Provider
	// 测绘结果自动归一为资产并建立关联，测绘新发现的 IP 纳入后续本地扫描验证
	ips = e.spaceMapping(task, ips, domains)

	// IP 流水线（并发受任务配置限制）
	sem := make(chan struct{}, maxInt(task.Concurrency, 1))
	var wg sync.WaitGroup
	total := len(ips)
	done := 0
	var progMu sync.Mutex
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case <-run.cancel:
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			if paused := e.waitIfPaused(run); paused {
				return
			}
			select {
			case <-run.cancel:
				return
			default:
			}
			e.scanIP(task, ip)
			progMu.Lock()
			done++
			p := done * 100 / maxInt(total, 1)
			progMu.Unlock()
			e.store.UpdateTask(taskID, map[string]any{"progress": p})
		}(ip)
	}
	wg.Wait()

	// 资产监控：周期任务对本轮新增的 Web 资产默认执行漏洞扫描（即使任务是快速模式；
	// 白名单资产仍会被跳过）
	if task.ScanInterval != "" {
		newWebs := e.store.NewWebsSince(task.ID, runStart)
		if len(newWebs) > 0 {
			e.store.LogTask(task.ID, "info", fmt.Sprintf("本轮新增 %d 个 Web 资产，默认执行漏洞扫描", len(newWebs)))
			force := *task // 以标准模式语义执行风险检测与规则，绕过快速模式门控
			force.Mode = "standard"
			for _, u := range newWebs {
				select {
				case <-runCancel(e, task.ID):
				default:
				}
				e.detectWeb(&force, u, "", task.TimeoutSec)
			}
		}
	}

	// AI 自动研判：在所有检测完成、漏洞入库后执行
	e.autoAIAnalyze(task)

	// 风险评分
	e.scoreIPs(task.ProjectID, ips)

	status := "done"
	e.mu.Lock()
	select {
	case <-run.cancel:
		status = "canceled"
	default:
	}
	e.mu.Unlock()
	e.store.UpdateTask(taskID, map[string]any{"status": status, "progress": 100, "ended_at": time.Now()})
	e.store.LogTask(taskID, "info", "任务结束: "+status)
}

func isAuthorized(ip string, authorized map[string]bool, ips []string) bool {
	if len(authorized) == 0 && len(ips) == 0 {
		return true
	}
	for _, x := range ips {
		if x == ip {
			return true
		}
	}
	return authorized[ip]
}

// scanIP 单 IP 完整流水线：存活 -> 端口 -> 服务 -> Web -> 指纹 -> 风险
func (e *Engine) scanIP(task *model.ScanTask, ip string) {
	// 1. 资产入库 + 存活探测
	isNew, _ := e.store.UpsertIP(model.AssetIP{ProjectID: task.ProjectID, IP: ip, Network: IsPrivateIP(ip), Source: "task"})
	if isNew {
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "ip", Asset: ip, Change: "add"})
	}
	prober := plugins.AllProbers()[0]
	probe := prober.Probe(ip, task.TimeoutSec)
	e.store.UpdateIPAlive(ip, task.ProjectID, probe.Alive, probe.Method, probe.LatencyMs)
	if !probe.Alive {
		e.store.LogTask(task.ID, "info", ip+" 存活探测失败(可能离线或过滤)")
		// 快速模式且未显式指定端口时直接跳过（探测列表不含目标端口的目标）；显式指定端口或标准/深度模式继续端口确认
		if task.Mode == "quick" && task.Ports == "" {
			return
		}
	}

	// 2. 端口扫描：快速=常见端口，标准=Top1000，深度=全端口（任务显式指定优先）
	ports := ParsePorts(task.Ports, DefaultPortsByMode(task.Mode, e.cfg.Scan.TopPorts), e.cfg.Scan.MaxPortPerTarget)
	scanner := plugins.AllPortScanners()[0]
	openPorts := scanner.Scan(ip, ports, task.TimeoutSec)
	e.store.LogTask(task.ID, "info", fmt.Sprintf("%s 端口扫描完成: %d open", ip, len(openPorts)))

	// 3. 服务识别 + 分拣 + Web 识别
	idents := plugins.AllServiceIdentifiers()
	for _, pr := range openPorts {
		for _, id := range idents {
			pr = id.Identify(ip, pr, task.TimeoutSec)
		}
		category := categorize(pr.Port, pr.Service)
		isNewPort, _ := e.store.UpsertPort(model.AssetPort{
			ProjectID: task.ProjectID, IP: ip, Port: pr.Port, Protocol: pr.Protocol,
			State: pr.State, Service: pr.Service, Version: pr.Version, Banner: truncate(pr.Banner, 500),
			Category: category, Source: "task",
		})
		if isNewPort {
			e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "port", Asset: fmt.Sprintf("%s:%d", ip, pr.Port), Change: "add", Detail: pr.Service})
		}
		// HTTP 服务 -> Web 资产发现
		if strings.Contains(strings.ToUpper(pr.Service), "HTTP") {
			scheme := "http"
			if pr.Port == 443 || pr.Port == 8443 || strings.Contains(strings.ToUpper(pr.Service), "HTTPS") {
				scheme = "https"
			}
			webURL := fmt.Sprintf("%s://%s", scheme, joinHostPort(ip, pr.Port))
			e.detectWeb(task, webURL, ip, task.TimeoutSec)
		}
	}
}

// detectWeb Web 资产识别 + 指纹 + 风险检测 + URL 发现
func (e *Engine) detectWeb(task *model.ScanTask, webURL, ip string, timeoutSec int) {
	// 通过 mapper 插件中的 probeWeb 等价逻辑：直接用 doer 抓取
	doer := newWebProber(timeoutSec)
	w := doer(webURL, ip)
	if w == nil {
		if ip == "" { // 显式导入的 URL 不存活也记录
			w = &plugins.WebResult{URL: webURL, StatusCode: 0}
		} else {
			return
		}
	}
	headersJSON, _ := json.Marshal(w.Headers)
	w.URL = mapper.NormalizeURL(w.URL, w.Port)
	webID, isNew, err := e.store.UpsertWeb(model.AssetWeb{
		ProjectID: task.ProjectID, URL: w.URL, IP: w.IP, Domain: w.Domain, Port: w.Port,
		Protocol: w.Protocol, StatusCode: w.StatusCode, Title: w.Title, Server: w.Server,
		ContentType: w.ContentType, RespSize: w.RespSize, Certificate: w.Certificate,
		Headers: string(headersJSON), Source: "task",
	})
	if err != nil {
		return
	}
	if isNew {
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "web", Asset: w.URL, Change: "add", Detail: w.Title})
	}

	// 技术指纹
	body := fetchBody(webURL, timeoutSec)
	techs := []string{}
	for _, fp := range plugins.AllFingerprinters() {
		for _, r := range fp.Match(*w, body) {
			techs = append(techs, r.Name)
			e.store.UpsertFingerprint(model.AssetFingerprint{
				ProjectID: task.ProjectID, WebURL: w.URL, Category: r.Category, Name: r.Name, Detail: r.Detail,
			})
		}
	}
	if len(techs) > 0 {
		e.store.Exec(`UPDATE asset_web SET tech=? WHERE id=?`, strings.Join(techs, ","), webID)
	}
	// 主 URL 进入 URL 资产池
	e.store.UpsertURL(model.AssetURL{
		ProjectID: task.ProjectID, WebID: webID, URL: w.URL, StatusCode: w.StatusCode,
		ContentType: w.ContentType, RespSize: w.RespSize, Source: "web-root",
	})

	// 资产白名单：不对白名单内的资产执行任何漏洞扫描动作（发现/端口扫描不受影响）
	if task.Mode != "quick" && Whitelisted(e.LoadWhitelist(), w.IP, w.Domain) {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("资产 %s/%s 在白名单中，跳过漏洞扫描", w.IP, w.Domain))
		return
	}
	// 风险检测（非破坏性）
	if task.Mode != "quick" {
		riskCtx := plugins.RiskContext{
			Web: w, IP: w.IP, Body: truncate(body, 100000), Headers: w.Headers,
			Client: newDoer(timeoutSec, webURL),
		}
		for _, rs := range plugins.AllRiskScanners() {
			for _, vr := range rs.Scan(riskCtx) {
				e.saveVuln(task, vr, w)
			}
		}
		// 标准/深度模式：执行漏洞规则库（nuclei/xray/afrog PoC，全部漏洞扫描）
		e.runVulnRules(task, w)
	}

	// 深度模式：URL / API 发现（从首页提取链接）
	if task.Mode == "deep" {
		e.discoverURLs(task, webID, webURL, body, timeoutSec)
	}
}

// bruteSubdomains 对域名执行子域名爆破并入库；解析出的新 IP 纳入后续扫描
func (e *Engine) bruteSubdomains(task *model.ScanTask, domain string, ips []string) []string {
	wordlist := subdomain.DefaultWordlist
	if e.cfg.Scan.SubdomainWordlist != "" {
		if data, err := os.ReadFile(e.cfg.Scan.SubdomainWordlist); err == nil {
			for _, w := range strings.Split(string(data), "\n") {
				if w = strings.TrimSpace(strings.ToLower(w)); w != "" {
					wordlist = append(wordlist, w)
				}
			}
		}
	}
	results := subdomain.Brute(domain, subdomain.Options{
		Workers:    e.cfg.Scan.SubdomainWorkers,
		Wordlist:   wordlist,
		Resolvers:  subdomain.DefaultResolvers,
		TimeoutSec: maxInt(task.TimeoutSec, 3),
	})
	newIPs := 0
	for _, r := range results {
		isNew, err := e.store.UpsertDomain(model.AssetDomain{
			ProjectID: task.ProjectID, Domain: r.Subdomain, CNAME: r.CNAME, IP: r.IP, Source: "subdomain-brute",
		})
		if err == nil && isNew {
			e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "domain",
				Asset: r.Subdomain, Change: "add", Detail: "子域名爆破发现 " + r.IP})
		}
		before := len(ips)
		ips = appendIfNew(ips, r.IP)
		if len(ips) > before {
			newIPs++
			isNewIP, _ := e.store.UpsertIP(model.AssetIP{ProjectID: task.ProjectID, IP: r.IP, Source: "subdomain-brute"})
			if isNewIP {
				e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "ip",
					Asset: r.IP, Change: "add", Detail: "子域名爆破解析"})
			}
		}
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("子域名爆破 %s：发现 %d 个子域名，新增 %d 个解析 IP",
		domain, len(results), newIPs))
	return ips
}

// autoAIAnalyze 对本次任务新检出的漏洞批量 AI 研判并自动标记
func (e *Engine) autoAIAnalyze(task *model.ScanTask) {
	cfg := ai.DefaultConfig()
	if saved, _ := e.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	if !cfg.Enabled || !cfg.AutoAnalyze {
		return
	}
	e.store.LogTask(task.ID, "info", "AI 自动研判开始（最低等级: "+cfg.AutoMinSeverity+"）")

	// 取本次任务新检出的漏洞（最近 60 分钟内）
	vulns, err := e.store.QueryPage("vulnerabilities", task.ProjectID,
		"first_seen >= ?", []any{time.Now().Add(-60 * time.Minute).Format("2006-01-02 15:04:05")}, "id", 200, 0)
	if err != nil {
		e.store.LogTask(task.ID, "warn", "AI 自动研判查询漏洞失败: "+err.Error())
		return
	}
	if len(vulns) == 0 {
		e.store.LogTask(task.ID, "info", "AI 自动研判：无新漏洞，跳过")
		return
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("AI 自动研判：发现 %d 个待分析漏洞", len(vulns)))

	analyzed, skipped, failed := 0, 0, 0
	for _, v := range vulns {
		sev, _ := v["severity"].(string)
		if !ai.ShouldAutoAnalyze(cfg, sev) {
			skipped++
			continue
		}
		vid, _ := v["vuln_id"].(string)
		port, _ := v["port"].(int64)
		verdict, err := ai.Analyze(cfg, ai.VulnContext{
			VulnID:      vid,
			Name:        str(v, "name"),
			Severity:    sev,
			Description: str(v, "description"),
			URL:         str(v, "url"),
			IP:          str(v, "ip"),
			Port:        int(port),
			Evidence:    str(v, "evidence"),
			Request:     str(v, "request"),
			Response:    str(v, "response"),
		})
		if err != nil {
			failed++
			e.store.LogTask(task.ID, "warn", fmt.Sprintf("AI 研判 %s 失败: %v", vid, err))
			continue
		}
		id, _ := v["id"].(int64)
		if err := e.store.SetVulnMark(id, verdict.Mark); err == nil {
			analyzed++
			e.store.LogTask(task.ID, "info", fmt.Sprintf("AI 研判 %s: %s（%s）%s", vid, verdict.Mark, verdict.Confidence, verdict.Reasoning))
		}
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("AI 自动研判完成：分析 %d / 跳过 %d / 失败 %d", analyzed, skipped, failed))
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

// spaceMapping 空间测绘：对所有 IP 与域名目标查询已启用的测绘数据源并导入结果，返回扩展后的 IP 列表
func (e *Engine) spaceMapping(task *model.ScanTask, ips, domains []string) []string {
	cfg := mapper.Current()
	if !cfg.Enabled {
		e.store.LogTask(task.ID, "info", "空间测绘未启用（可在 系统设置→空间测绘 中开启）")
		return ips
	}
	targets := append(append([]string{}, ips...), domains...)
	for _, t := range targets {
		select {
		case <-runCancel(e, task.ID):
			return ips
		default:
		}
		recs, errs := mapper.QueryAll(t)
		// 测绘资产先做存活性探测，仅存活的入库（测绘引擎索引可能含已失效的历史资产）
		alive, dead := mapper.VerifyAlive(recs, maxInt(task.TimeoutSec, 3), 32)
		nip, nd, np, nw := mapper.Import(e.store, task.ProjectID, task.ID, alive)
		e.store.LogTask(task.ID, "info", fmt.Sprintf("空间测绘 %s：获得 %d 条记录，存活 %d 条（失效 %d 条未入库）；入库新增 IP %d / 域名 %d / 端口 %d / Web %d",
			t, len(recs), len(alive), dead, nip, nd, np, nw))
		for name, err := range errs {
			e.store.LogTask(task.ID, "warn", "测绘引擎 "+name+" 查询 "+t+" 失败: "+err)
		}
		// 测绘发现的 IP 纳入后续本地扫描验证
		for _, r := range recs {
			if r.IP != "" {
				ips = appendIfNew(ips, r.IP)
			}
		}
	}
	return ips
}

// runCancel 运行中任务的取消通道（不存在则返回 nil）
func runCancel(e *Engine, taskID int64) chan struct{} {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.running[taskID]; ok {
		return r.cancel
	}
	return nil
}

// WhitelistEntries 白名单配置（settings key=scan_whitelist）
type WhitelistEntries struct {
	Items []string `json:"items"`
}

// LoadWhitelist 读取白名单（每行一个：IP / CIDR / 域名，域名自动覆盖子域名）
func (e *Engine) LoadWhitelist() []string {
	var w WhitelistEntries
	if saved, _ := e.store.GetSetting("scan_whitelist"); saved != "" {
		json.Unmarshal([]byte(saved), &w)
	}
	return w.Items
}

// Whitelisted 判定资产是否命中白名单：精确 IP / CIDR 网段 / 域名（含子域名）
func Whitelisted(items []string, ip, domain string) bool {
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if ip != "" {
			if it == ip {
				return true
			}
			if strings.Contains(it, "/") {
				if _, cidr, err := net.ParseCIDR(it); err == nil {
					if pip := net.ParseIP(ip); pip != nil && cidr.Contains(pip) {
						return true
					}
				}
			}
		}
		if domain != "" && it != "" {
			d := strings.ToLower(domain)
			w := strings.ToLower(strings.TrimPrefix(it, "*."))
			if d == w || strings.HasSuffix(d, "."+w) {
				return true
			}
		}
	}
	return false
}

// runVulnRules 执行漏洞规则库中启用的 PoC 规则（限额 + 严重度优先）
func (e *Engine) runVulnRules(task *model.ScanTask, w *plugins.WebResult) {
	st := vulnrule.DefaultSettings()
	if saved, _ := e.store.GetSetting("vuln_rule_settings"); saved != "" {
		json.Unmarshal([]byte(saved), &st)
	}
	if !st.EnabledInScan {
		return
	}
	rules := e.store.EnabledRulesForScan(st.MaxPerTarget)
	if len(rules) == 0 {
		return
	}
	if st.MaxPerTarget > 0 {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("规则库已加载 %d 条规则（限额 %d）", len(rules), st.MaxPerTarget))
	} else {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("规则库已加载全部 %d 条规则", len(rules)))
	}
	matched := 0
	for i := range rules {
		select {
		case <-runCancel(e, task.ID):
			return
		default:
		}
		if i > 0 && i%1000 == 0 {
			e.store.LogTask(task.ID, "info", fmt.Sprintf("规则执行进度 %d/%d（已检出 %d）", i, len(rules), matched))
		}
		res := vulnrule.Run(&rules[i], w.URL, task.TimeoutSec)
		if res.Err != "" {
			continue
		}
		if res.Matched {
			matched++
			e.saveVuln(task, plugins.VulnResult{
				VulnID:      rules[i].RuleID,
				Name:        orDefaultStr(rules[i].Name, rules[i].RuleID),
				Severity:    rules[i].Severity,
				Description: rules[i].Description,
				Solution:    "参考规则修复建议: " + rules[i].RuleID,
				Evidence:    res.Evidence,
				Request:     res.Request,
				Response:    res.Response,
				Component:   "规则库(" + rules[i].Source + ")",
				Scanner:     "rule:" + rules[i].Source,
			}, w)
		}
	}
	if matched > 0 {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("规则库检出 %d 个漏洞 (%s)", matched, w.URL))
	}
}

func (e *Engine) saveVuln(task *model.ScanTask, vr plugins.VulnResult, w *plugins.WebResult) {
	v := model.Vulnerability{
		ProjectID: task.ProjectID, VulnID: vr.VulnID, Name: vr.Name, Severity: vr.Severity,
		IP: w.IP, Domain: w.Domain, Port: w.Port, URL: w.URL,
		Component: vr.Component, Description: vr.Description, Solution: vr.Solution,
		Evidence: vr.Evidence, Request: vr.Request, Response: vr.Response, Scanner: orDefaultStr(vr.Scanner, "builtin"),
	}
	isNew, err := e.store.UpsertVuln(v)
	if err == nil && isNew {
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "vuln",
			Asset: fmt.Sprintf("%s@%s", vr.VulnID, w.URL), Change: "add", Detail: vr.Name + " [" + vr.Severity + "]"})
	}
}

func (e *Engine) discoverURLs(task *model.ScanTask, webID int64, baseURL, body string, timeoutSec int) {
	found := 0
	for _, link := range extractLinks(baseURL, body) {
		if found >= 100 {
			break
		}
		doer := newDoer(timeoutSec, baseURL)
		if resp, err := doer.Do(link); err == nil && resp != nil && resp.StatusCode > 0 {
			isNew, _ := e.store.UpsertURL(model.AssetURL{
				ProjectID: task.ProjectID, WebID: webID, URL: link, StatusCode: resp.StatusCode,
				ContentType: resp.ContentType, RespSize: resp.RespSize, Source: "crawler",
			})
			if isNew {
				e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "url", Asset: link, Change: "add"})
				found++
			}
		}
	}
}

func (e *Engine) upsertDomain(task *model.ScanTask, domain, ip string) {
	isNew, err := e.store.UpsertDomain(model.AssetDomain{ProjectID: task.ProjectID, Domain: domain, IP: ip, Source: "task"})
	if err == nil && isNew {
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "domain", Asset: domain, Change: "add"})
	}
}

// scoreIPs 资产风险评分（需求文档 第二十五节）
func (e *Engine) scoreIPs(projectID int64, ips []string) {
	for _, ip := range ips {
		score := 0
		sev := map[string]int{}
		rows, _ := e.store.QueryPage("vulnerabilities", projectID, "ip=?", []any{ip}, "", 1000, 0)
		for _, v := range rows {
			if s, ok := v["severity"].(string); ok {
				sev[s]++
			}
		}
		score += sev["critical"]*25 + sev["high"]*12 + sev["medium"]*5 + sev["low"]*1
		portCount, _ := e.store.Count("asset_ports", projectID, "ip=?", []any{ip})
		webCount, _ := e.store.Count("asset_web", projectID, "ip=?", []any{ip})
		score += minInt(portCount, 10)*2 + minInt(webCount, 10)*3
		// 敏感服务加分
		rows2, _ := e.store.QueryPage("asset_ports", projectID, "ip=? AND service IN ('Docker','Redis','MongoDB','MySQL','PostgreSQL','MSSQL','Elasticsearch')", []any{ip}, "", 100, 0)
		score += len(rows2) * 8
		if score > 100 {
			score = 100
		}
		e.store.UpdateIPScore(projectID, ip, score)
	}
}

// Pause / Resume / Cancel
func (e *Engine) Pause(taskID int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.running[taskID]; ok {
		select {
		case <-runPause(r):
		default:
			r.pause <- struct{}{}
		}
	}
	return e.store.UpdateTask(taskID, map[string]any{"status": "paused"})
}

func runPause(r *taskRun) chan struct{} { return r.pause }

func (e *Engine) Resume(taskID int64) error {
	e.mu.Lock()
	if r, ok := e.running[taskID]; ok {
		select {
		case r.resume <- struct{}{}:
		default:
		}
	}
	e.mu.Unlock()
	return e.store.UpdateTask(taskID, map[string]any{"status": "running"})
}

func (e *Engine) Cancel(taskID int64) error {
	e.mu.Lock()
	if r, ok := e.running[taskID]; ok {
		select {
		case <-r.cancel:
		default:
			close(r.cancel)
		}
		// 唤醒可能暂停的协程使其退出
		select {
		case r.resume <- struct{}{}:
		default:
		}
	}
	e.mu.Unlock()
	return e.store.UpdateTask(taskID, map[string]any{"status": "canceled", "ended_at": time.Now()})
}

func (e *Engine) waitIfPaused(run *taskRun) bool {
	select {
	case <-run.pause:
		select {
		case <-run.cancel:
			return true
		case <-run.resume:
			return false
		}
	case <-run.cancel:
		return true
	default:
		return false
	}
}

func categorize(port int, service string) string {
	// 复用 builtin 的分拣规则通过插件接口获取
	for _, id := range plugins.AllServiceIdentifiers() {
		_ = id
	}
	return builtinCategory(port, service)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func joinHostPort(host string, port int) string {
	if port == 80 {
		return host
	}
	if port == 443 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}
