package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cysec/internal/ai"
	"cysec/internal/config"
	"cysec/internal/events"
	"cysec/internal/mapper"
	"cysec/internal/model"
	"cysec/internal/netproxy"
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

	mu              sync.Mutex
	running         map[int64]*taskRun // taskID -> 运行状态
	stopPoll        chan struct{}
	autoScanQueue   chan autoScanJob  // 新增 Web 资产实时漏洞扫描队列（nil 表示未启用）
	aiQueue         chan aiAnalyzeJob // 新增漏洞实时 AI 研判队列（nil 表示未启用）
	nucleiScanQueue chan autoScanJob  // 新 Web 资产官方 nuclei 引擎实时扫描队列（nil 表示未启用）

	sensMu    sync.Mutex   // 敏感字/暗链订阅词表内存缓存
	sensWords []string     // 生效敏感字词表（nil = 未加载）
	sensDark  []string     // 生效暗链关键词订阅部分（nil = 未加载）
	subUpdMu  sync.Mutex   // 订阅拉取串行化（手动/自动并发触发）
}

// taskRun 任务运行句柄：cancel 关闭即取消；pause/resume 用"关闭=广播"传递信号——
// 暂停对全部并发 worker 可见（而非单消费者信号），恢复时轮换新通道以支持多次暂停。
type taskRun struct {
	cancel  chan struct{}
	pause   chan struct{}
	resume  chan struct{}
	pmu     sync.Mutex // 保护 pause/resume 通道的轮换
	scanMu  sync.Mutex
	scanned map[string]bool // 本轮任务已内联执行过检测的资产（key=phase\x00url/ip），独立阶段补扫据此去重
}

func New(st *store.Store, cfg *config.Config) *Engine {
	e := &Engine{
		store:    st,
		cfg:      cfg,
		running:  map[int64]*taskRun{},
		stopPoll: make(chan struct{}),
	}
	go e.pollLoop()
	go e.monitorLoop()
	go e.sensSubLoop()
	e.sanitizeSensSubLists() // 启动清理存量词表中的单字词条（同步执行，先于词表缓存加载）
	e.cachedSensWords()      // 触发词表缓存加载并同步状态词数（上次运行清空/增删后状态可能残留旧值）
	e.startAutoScan()
	e.startAIAnalyze()
	e.startNucleiScan()
	return e
}

// ParseInterval 周期字符串 -> 时长；非法返回 0。
// 预设（8h / 24h / 1w）与自定义整数小时 Nh（1 ≤ n ≤ 8760，如 6h）；
// 自定义周期按小时设计，纯数字（如 6）也按小时解析。
func ParseInterval(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", "0":
		return 0
	case "8h":
		return 8 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "1w":
		return 7 * 24 * time.Hour
	}
	s = strings.TrimSuffix(s, "h") // 纯数字按小时
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 8760 {
		return 0
	}
	return time.Duration(n) * time.Hour
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
				if d <= 0 || t.EndedAt == nil {
					continue
				}
				// done 正常重排；failed（上次执行出错）也纳入到期重试，周期监控不因一次失败停摆；
				// canceled=用户主动停止、running/pending=执行流负责，均不重排
				if t.Status != "done" && t.Status != "failed" {
					continue
				}
				if time.Since(*t.EndedAt) >= d {
					msg := "周期任务到期（" + t.ScanInterval + "），自动重新执行"
					if t.Status == "failed" {
						msg = "周期任务到期（" + t.ScanInterval + "），上次执行失败，自动重试"
					}
					e.store.LogTask(t.ID, "info", msg)
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

// IsRunning 判断任务是否存在存活执行协程
func (e *Engine) IsRunning(taskID int64) bool {
	e.mu.Lock()
	_, ok := e.running[taskID]
	e.mu.Unlock()
	return ok
}

// StopAndWait 取消任务的存活执行并等待其退出（限时）。
// 修复重启竞态：旧执行协程未退出时，新 Execute 会被防重入守卫静默丢弃，
// 任务状态将卡在 pending；重启前必须先让旧执行真正结束。
func (e *Engine) StopAndWait(taskID int64, timeout time.Duration) bool {
	_ = e.Cancel(taskID)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !e.IsRunning(taskID) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return !e.IsRunning(taskID)
}

// Submit 提交任务（状态 pending，由 pollLoop 调度）
func (e *Engine) Submit(taskID int64) error {
	return e.store.UpdateTask(taskID, map[string]any{"status": "pending", "progress": 0})
}

// Execute 同步执行任务（含暂停/取消检查）
func (e *Engine) Execute(taskID int64) {
	events.Publish("tasks")
	defer events.Publish("tasks")
	e.mu.Lock()
	if _, ok := e.running[taskID]; ok {
		e.mu.Unlock()
		return
	}
	// pause/resume 关闭即广播：全部并发 worker 在检查点感知暂停，恢复轮换新通道
	run := &taskRun{cancel: make(chan struct{}), pause: make(chan struct{}), resume: make(chan struct{}), scanned: map[string]bool{}}
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
	e.store.UpdateTask(taskID, map[string]any{"status": "running", "started_at": store.NowLocal()})
	e.store.LogTask(taskID, "info", "任务开始执行，模式="+task.Mode+"，阶段="+phaseSummary(task))
	if netproxy.Enabled() {
		e.store.LogTask(taskID, "info", "全局代理已启用：Web 探测与漏洞扫描走代理，端口扫描/服务识别走直连")
	}

	// 目标解析（授权范围）
	ips, domains, urls, err := ParseTargets(task.Targets, task.TargetType, e.cfg.Scan.MaxTargetsPerTask)
	if err != nil {
		e.store.UpdateTask(taskID, map[string]any{"status": "failed", "error": err.Error(), "ended_at": store.NowLocal()})
		e.store.LogTask(taskID, "error", "目标解析失败: "+err.Error())
		return
	}
	e.store.LogTask(taskID, "info", fmt.Sprintf("目标解析完成: %d IP, %d Domain, %d URL", len(ips), len(domains), len(urls)))
	// 项目误报资产配置：命中的后续采集资产不再入库
	task.FPIgnores = e.store.GetFPAssets(task.ProjectID)
	if len(task.FPIgnores) > 0 {
		e.store.LogTask(taskID, "info", fmt.Sprintf("误报资产配置生效：%d 条（命中的采集资产不入库）", len(task.FPIgnores)))
	}

	// 域名一致性校验基准：任务输入的域名根（设置开关关闭或纯 IP 任务时为空=放行）
	if domainConsistencyEnabled(e.store) {
		roots := make([]string, 0, len(domains))
		for _, d := range domains {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				roots = append(roots, d)
			}
		}
		task.ApexRoots = strings.Join(roots, ",")
		if len(roots) > 0 {
			e.store.LogTask(taskID, "info", "域名一致性校验已启用，基准根："+task.ApexRoots)
		}
	}

	// 域名解析 -> IP（并发：大批量域名目标串行解析需数小时，限定 32 worker）
	var ipsMu sync.Mutex
	domainJobs := make(chan string)
	var dwg sync.WaitGroup
	for w := 0; w < 32; w++ {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			for d := range domainJobs {
				select {
				case <-runCancel(e, task.ID):
					continue
				default:
				}
				e.upsertDomain(task, d, "")
				for _, r := range plugins.AllResolvers() {
					if ip, cname, err := r.Resolve(d); err == nil && ip != "" {
						// 目标域名是用户显式指定的扫描对象，其解析 IP 一律纳入授权范围，
						// 加入 IP 列表参与后续端口扫描与资产收集
						ipsMu.Lock()
						ips = appendIfNew(ips, ip)
						ipsMu.Unlock()
						e.upsertDomain(task, d, ip)
						e.store.LogTask(taskID, "info", "域名 "+d+" 解析到 "+ip+"（目标域名，已纳入扫描）")
						if cname != "" {
							e.store.Exec(`UPDATE asset_domains SET cname=? WHERE project_id=? AND domain=?`, cname, task.ProjectID, d)
						}
						break
					}
				}
			}
		}()
	}
	for _, d := range domains {
		domainJobs <- d
	}
	close(domainJobs)
	dwg.Wait()
	select {
	case <-runCancel(e, task.ID):
		e.finishCanceled(taskID)
		return
	default:
	}
	// 子域名收集（爆破 + 证书透明度）；任务域名与收集到的子域名随后按 https/http 探测为 Web 资产
	webDomains := append([]string{}, domains...)
	if e.cfg.Scan.SubdomainBrute {
		for _, d := range domains {
			if runCanceled(e, task.ID) {
				e.finishCanceled(taskID)
				return
			}
			var names []string
			if task.SubdomainBrute || task.Phases == "" { // 显式关闭仅对阶段化任务生效
				ips, names = e.bruteSubdomains(task, d, ips)
			}
			webDomains = append(webDomains, names...)
		}
	}
	// 证书透明度被动收集：不依赖字典，能发现历史子域（crt.name）
	if e.cfg.Scan.SubdomainCertQuery {
		for _, d := range domains {
			if runCanceled(e, task.ID) {
				e.finishCanceled(taskID)
				return
			}
			var names []string
			ips, names = e.certSubdomains(task, d, ips)
			webDomains = append(webDomains, names...)
		}
	}
	// URL 直接导入 Web 资产池
	for _, u := range urls {
		e.detectWeb(task, u, "", task.TimeoutSec)
	}

	// 域名 Web 探测：vhost/CDN 场景下同一 IP 承载多个站点，按域名（Host 头）探测补充 Web 资产
	e.probeDomainWebs(task, webDomains)

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
			if paused := run.waitIfPaused(); paused {
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

	// 子域名+端口拼接探测：域名按其解析 IP 本轮发现的开放 Web 端口拼 http(s)://域名:端口
	// 补充探测（覆盖非常用端口上的 vhost 站点；80/443 已由 probeDomainWebs 默认探测覆盖）
	e.probeDomainPortWebs(task, webDomains)

	// 独立阶段补扫：未选择"资产收集"，或选择了采集但未选"端口扫描"（本轮不产生新 Web 资产），
	// 此时所选漏洞扫描/弱点检测对项目存量 Web 资产执行；本轮任务已内联检测过的资产（含域名
	// 探测/URL 导入路径发现的新 Web）跳过，避免同任务内重复扫描；白名单资产不执行漏洞扫描
	if !phaseOn(task, "collect") || !phaseOn(task, "portscan") {
		webs := e.store.WebsOfProject(task.ProjectID)
		if phaseOn(task, "vulnscan") {
			scanned, skipped := 0, 0
			for i := range webs {
				w := &webs[i]
				if e.assetScanned(taskID, "vuln", w.URL) || e.whitelistHit(w.IP, w.Domain, w.URL) {
					skipped++
					continue
				}
				e.runVulnRules(task, &plugins.WebResult{URL: w.URL, IP: w.IP, Domain: w.Domain, Port: w.Port})
				e.SubmitNucleiScan(task.ID, task.ProjectID, w.URL)
				scanned++
			}
			e.store.LogTask(taskID, "info", fmt.Sprintf("漏洞扫描阶段：对项目 Web 资产执行规则库 %d 个（跳过本轮已扫/白名单 %d 个）", scanned, skipped))
		}
		if phaseOn(task, "weakness") {
			scanned, skipped := 0, 0
			for i := range webs {
				w := &webs[i]
				if e.assetScanned(taskID, "weak", w.URL) {
					skipped++
					continue
				}
				timeout := maxInt(task.TimeoutSec, 5)
				wr := &plugins.WebResult{URL: w.URL, IP: w.IP, Domain: w.Domain, Port: w.Port, Title: w.Title}
				if h := json.Unmarshal([]byte(orDefaultStr(w.Headers, "{}")), &wr.Headers); h != nil {
					wr.Headers = nil // 存量 Web 的响应头 JSON 解析失败时不阻断，仅 WIH 头检测降级
				}
				body := fetchBody(w.URL, timeout)
				e.runWeaknessScan(task, wr, body, timeout)
				// WIH 归并弱点管理：无端口阶段时不在 detectWeb 内联执行，这里补跑
				riskCtx := plugins.RiskContext{Web: wr, Body: truncate(body, 100000), Headers: wr.Headers, Client: newDoer(timeout, w.URL)}
				for _, rs := range plugins.AllRiskScanners() {
					if rs.Name() != "wih" {
						continue
					}
					for _, vr := range rs.Scan(riskCtx) {
						e.saveWihWeakness(task, wr, vr)
					}
				}
				scanned++
			}
			e.store.LogTask(taskID, "info", fmt.Sprintf("弱点检测阶段：对项目 Web 资产执行链接爬取与 WIH 检测 %d 个（跳过本轮已扫 %d 个）", scanned, skipped))
		}
		if phaseOn(task, "portscan") {
			ipsOf := e.store.IPsOfProject(task.ProjectID)
			scanned := 0
			for _, ip := range ipsOf {
				select {
				case <-runCancel(e, task.ID):
					e.finishCanceled(taskID)
					return
				default:
				}
				if e.assetScanned(taskID, "portscan", ip) {
					continue
				}
				e.scanIP(task, ip)
				scanned++
			}
			e.store.LogTask(taskID, "info", fmt.Sprintf("端口扫描阶段：对项目 %d 个 IP 资产执行端口扫描", scanned))
		}
		if phaseOn(task, "alive") {
			e.runAliveCheck(task)
		}
	} else if phaseOn(task, "alive") {
		e.runAliveCheck(task)
	}

	// 注：新增 Web 资产的默认漏洞扫描已由实时扫描器（autoscan）承担——
	// 快速模式任务在 detectWeb 发现新资产时即提交异步扫描，覆盖全部来源，无需任务末补扫

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
	e.store.UpdateTask(taskID, map[string]any{"status": status, "progress": 100, "ended_at": store.NowLocal()})
	e.store.LogTask(taskID, "info", "任务结束: "+status)
}

// domainConsistencyEnabled 读取域名一致性校验开关（默认开启）
func domainConsistencyEnabled(st *store.Store) bool {
	if saved, _ := st.GetSetting("domain_consistency"); saved != "" {
		var cfg struct {
			Enabled bool `json:"enabled"`
		}
		if json.Unmarshal([]byte(saved), &cfg) == nil {
			return cfg.Enabled
		}
	}
	return true
}

// apexRootsOf 任务的域名一致性基准（逗号分隔转切片）
func apexRootsOf(task *model.ScanTask) []string {
	p := strings.TrimSpace(task.ApexRoots)
	if p == "" {
		return nil
	}
	return strings.Split(p, ",")
}

// scanIP 单 IP 完整流水线：存活 -> 端口 -> 服务 -> Web -> 指纹 -> 风险
func (e *Engine) scanIP(task *model.ScanTask, ip string) {
	// 误报资产配置：IP（或所在网段）命中则整体跳过
	if store.FPAssetIgnored(task.FPIgnores, "ip", ip) {
		e.store.LogTask(task.ID, "info", ip+" 命中误报资产配置，跳过")
		return
	}
	// 1. 资产入库 + 存活探测
	isNew, _ := e.store.UpsertIP(model.AssetIP{ProjectID: task.ProjectID, IP: ip, Network: IsPrivateIP(ip), Source: "task"})
	if isNew {
		events.Publish("assets")
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
	// 端口扫描为独立阶段：未勾选时仅完成资产入库与存活探测
	if !phaseOn(task, "portscan") {
		e.store.LogTask(task.ID, "info", ip+" 跳过端口扫描（未勾选端口扫描阶段）")
		return
	}
	e.markAssetScanned(task.ID, "portscan", ip)
	ports := ParsePorts(task.Ports, DefaultPortsByMode(task.Mode, e.cfg.Scan.TopPorts), e.cfg.Scan.MaxPortPerTarget)
	scanner := plugins.AllPortScanners()[0]
	openPorts := scanner.Scan(ip, ports, task.TimeoutSec)
	e.store.LogTask(task.ID, "info", fmt.Sprintf("%s 端口扫描完成: %d open", ip, len(openPorts)))

	// 3. 服务识别 + 分拣 + Web 识别（端口结果单事务批量入库，削减写放大）
	idents := plugins.AllServiceIdentifiers()
	type httpTarget struct {
		scheme string
		port   int
	}
	portRows := make([]model.AssetPort, 0, len(openPorts))
	httpTargets := []httpTarget{}
	for _, pr := range openPorts {
		for _, id := range idents {
			pr = id.Identify(ip, pr, task.TimeoutSec)
		}
		category := categorize(pr.Port, pr.Service)
		portRows = append(portRows, model.AssetPort{
			ProjectID: task.ProjectID, IP: ip, Port: pr.Port, Protocol: pr.Protocol,
			State: pr.State, Service: pr.Service, Version: pr.Version, Banner: truncate(pr.Banner, 500),
			Category: category, Source: "task",
		})
		if strings.Contains(strings.ToUpper(pr.Service), "HTTP") {
			scheme := "http"
			if pr.Port == 443 || pr.Port == 8443 || strings.Contains(strings.ToUpper(pr.Service), "HTTPS") {
				scheme = "https"
			}
			httpTargets = append(httpTargets, httpTarget{scheme: scheme, port: pr.Port})
		}
	}
	newFlags, err := e.store.UpsertPortsBatch(portRows)
	if err != nil {
		e.store.LogTask(task.ID, "warn", ip+" 端口批量入库失败: "+err.Error())
		newFlags = make([]bool, len(portRows))
	}
	portNew := false
	for i := range portRows {
		if i < len(newFlags) && newFlags[i] {
			portNew = true
			e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "port", Asset: fmt.Sprintf("%s:%d", ip, portRows[i].Port), Change: "add", Detail: portRows[i].Service})
		}
	}
	if portNew {
		events.Publish("assets")
	}
	// HTTP 服务 -> Web 资产发现
	for _, t := range httpTargets {
		webURL := fmt.Sprintf("%s://%s", t.scheme, joinHostPort(ip, t.port))
		e.detectWeb(task, webURL, ip, task.TimeoutSec)
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
	// 误报资产配置：Web URL/host 命中则不入库（含其指纹/URL/检测链）
	if store.FPAssetIgnored(task.FPIgnores, "web", w.URL) {
		return
	}
	webID, isNew, err := e.store.UpsertWeb(model.AssetWeb{
		ProjectID: task.ProjectID, URL: w.URL, IP: w.IP, Domain: w.Domain, Port: w.Port,
		Protocol: w.Protocol, StatusCode: w.StatusCode, Title: w.Title, Server: w.Server,
		ContentType: w.ContentType, RespSize: w.RespSize, Certificate: w.Certificate,
		Headers: string(headersJSON), Source: "task",
	})
	if err != nil {
		return
	}
	// 资产白名单：不对白名单内的资产执行任何漏洞扫描动作（发现/端口扫描不受影响）
	whitelisted := task.Mode != "quick" && e.whitelistHit(w.IP, w.Domain, w.URL)
	// 漏洞扫描执行条件：本任务勾选了漏洞扫描，或该项目存在勾选了漏洞扫描的任务（项目级意图——
	// 项目里表达过要做漏洞扫描，该项目新增的 Web 资产即扫描）
	vulnOn := phaseOn(task, "vulnscan") || e.projectWantsVulnScan(task.ProjectID)
	if isNew {
		events.Publish("assets")
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "web", Asset: w.URL, Change: "add", Detail: w.Title})
		if whitelisted {
			e.store.LogTask(task.ID, "info", fmt.Sprintf("资产 %s/%s 在白名单中，跳过漏洞扫描", w.IP, w.Domain))
		} else if vulnOn {
			// 漏洞扫描执行（勾选即扫；未勾选但项目存在勾选漏洞扫描的任务时同样执行）：
			// 新 Web 资产提交官方 nuclei 引擎（发现即扫），规则库在下方统一执行
			e.SubmitNucleiScan(task.ID, task.ProjectID, w.URL)
		}
		// 项目无任何勾选漏洞扫描的任务且本任务未勾选：不触发漏洞扫描
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
	// Web 探测明细（新发现/更新均记录，含状态码、标题与指纹，镜像到控制台）
	techStr := "-"
	if len(techs) > 0 {
		techStr = strings.Join(techs, ",")
	}
	state := "更新"
	if isNew {
		state = "发现"
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("%s Web 资产 %s [状态 %d] 标题 %q 指纹: %s", state, w.URL, w.StatusCode, w.Title, techStr))
	// 主 URL 进入 URL 资产池
	e.store.UpsertURL(model.AssetURL{
		ProjectID: task.ProjectID, WebID: webID, URL: w.URL, StatusCode: w.StatusCode,
		ContentType: w.ContentType, RespSize: w.RespSize, Source: "web-root",
	})

	// 资产白名单命中（前置计算）：此处仅拦截内联扫描链
	if whitelisted {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("资产 %s/%s 在白名单中，跳过漏洞扫描", w.IP, w.Domain))
		return
	}
	// 风险检测（非破坏性）：WIH 属于弱点管理扫描，仅随弱点检测阶段执行；
	// 其余风险检测（指纹/泄露等）仅随漏洞扫描执行（任务勾选或项目意图）
	if task.Mode != "quick" {
		weakOn := phaseOn(task, "weakness")
		if weakOn || vulnOn {
			riskCtx := plugins.RiskContext{
				Web: w, IP: w.IP, Body: truncate(body, 100000), Headers: w.Headers,
				Client: newDoer(timeoutSec, webURL),
			}
			for _, rs := range plugins.AllRiskScanners() {
				if rs.Name() == "wih" {
					if !weakOn {
						continue // 未勾选弱点检测：WIH 不执行（此前仅丢弃结果，扫描本身仍会抓取 JS）
					}
					for _, vr := range rs.Scan(riskCtx) {
						e.saveWihWeakness(task, w, vr) // WIH 检测结果归并到弱点管理
					}
					continue
				}
				if !vulnOn {
					continue
				}
				for _, vr := range rs.Scan(riskCtx) {
					e.saveVuln(task, vr, w)
				}
			}
		}
		// 弱点管理：链接爬取（暗链/坏链/敏感字）
		if phaseOn(task, "weakness") {
			e.runWeaknessScan(task, w, body, timeoutSec)
			e.markAssetScanned(task.ID, "weak", w.URL)
		}
		// 执行漏洞规则库（nuclei/xray/afrog PoC，全部漏洞扫描）——条件同上（任务勾选或项目意图）
		if vulnOn {
			e.runVulnRules(task, w)
			e.markAssetScanned(task.ID, "vuln", w.URL)
		}
	}

	// 深度模式：URL / API 发现（从首页提取链接）
	if task.Mode == "deep" {
		e.discoverURLs(task, webID, webURL, body, timeoutSec)
	}
}

// bruteSubdomains 对域名执行子域名爆破并入库；返回（追加新解析 IP 的 ips，发现的子域列表）
func (e *Engine) bruteSubdomains(task *model.ScanTask, domain string, ips []string) ([]string, []string) {
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
		if store.FPAssetIgnored(task.FPIgnores, "domain", r.Subdomain) {
			continue
		}
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
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Subdomain)
	}
	return ips, names
}

// certSubdomains 证书透明度（crt.name）被动收集子域名并入库；返回（追加新解析 IP 的 ips，成功解析的子域列表）
func (e *Engine) certSubdomains(task *model.ScanTask, domain string, ips []string) ([]string, []string) {
	subs := subdomain.CertQuery(domain, maxInt(task.TimeoutSec, 5))
	if len(subs) == 0 {
		e.store.LogTask(task.ID, "info", fmt.Sprintf("证书透明度收集 %s：未发现子域名", domain))
		return ips, nil
	}
	// 并发解析（32）：CT 记录可能已过期，解析失败仅入库域名不填 IP
	type item struct{ sub, ip, cname string }
	sem := make(chan struct{}, 32)
	out := make(chan item, len(subs))
	var wg sync.WaitGroup
	for _, s := range subs {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			it := item{sub: s}
			for _, r := range plugins.AllResolvers() {
				if v, cn, err := r.Resolve(s); err == nil && v != "" {
					it.ip, it.cname = v, cn
					break
				}
			}
			out <- it
		}(s)
	}
	wg.Wait()
	close(out)
	newIPs := 0
	resolved := make([]string, 0, len(subs))
	for it := range out {
		select {
		case <-runCancel(e, task.ID):
			return ips, resolved // 任务已取消：跳过剩余入库
		default:
		}
		if store.FPAssetIgnored(task.FPIgnores, "domain", it.sub) {
			continue
		}
		if it.ip != "" && store.DomainMatchesApex(it.sub, apexRootsOf(task)) {
			resolved = append(resolved, it.sub)
			isNew, err := e.store.UpsertDomain(model.AssetDomain{
				ProjectID: task.ProjectID, Domain: it.sub, CNAME: it.cname, IP: it.ip, Source: "crt-cert",
			})
			if err == nil && isNew {
				e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "domain",
					Asset: it.sub, Change: "add", Detail: "证书透明度(crt.name)发现 " + it.ip})
			}
			before := len(ips)
			ips = appendIfNew(ips, it.ip)
			if len(ips) > before {
				newIPs++
				isNewIP, _ := e.store.UpsertIP(model.AssetIP{ProjectID: task.ProjectID, IP: it.ip, Source: "crt-cert"})
				if isNewIP {
					e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "ip",
						Asset: it.ip, Change: "add", Detail: "证书透明度子域解析"})
				}
			}
		} else if store.DomainMatchesApex(it.sub, apexRootsOf(task)) {
			// 未解析到 IP：仅登记域名（INSERT OR IGNORE，避免空值覆盖已有 cname/ip）；同样过一致性校验
			if res, err := e.store.Exec(`INSERT OR IGNORE INTO asset_domains(project_id,domain,source) VALUES(?,?,?)`,
				task.ProjectID, it.sub, "crt-cert"); err == nil {
				if n, _ := res.RowsAffected(); n > 0 {
					e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "domain",
						Asset: it.sub, Change: "add", Detail: "证书透明度(crt.name)发现（未解析）"})
				}
			}
		}
	}
	e.store.LogTask(task.ID, "info", fmt.Sprintf("证书透明度收集 %s：发现 %d 个子域名，新增 %d 个解析 IP",
		domain, len(subs), newIPs))
	return ips, resolved
}

// probeDomainWebs 将任务域名与收集到的子域名按 https/http 探测为 Web 资产（vhost 场景与 IP 探测互补）。
// 仅存活域名入库（探测失败的跳过，避免 CT 历史子域污染资产表），并发受 Worker.Concurrency 限制。
func (e *Engine) probeDomainWebs(task *model.ScanTask, names []string) {
	seen := map[string]bool{}
	list := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.Trim(n, ".")); n != "" && !seen[n] {
			seen[n] = true
			list = append(list, n)
		}
	}
	if len(list) == 0 {
		return
	}
	workers := e.cfg.Worker.Concurrency
	if workers <= 0 {
		workers = 8
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := 0
	timeout := maxInt(task.TimeoutSec, 3)
	probeOne := func(name string) {
		for _, scheme := range []string{"https", "http"} {
			select {
			case <-runCancel(e, task.ID):
				return
			default:
			}
			u := scheme + "://" + name
			if newWebProber(timeout)(u, "") == nil {
				continue // 不存活：不作为资产入库
			}
			mu.Lock()
			found++
			mu.Unlock()
			e.detectWeb(task, u, "", timeout)
		}
	}
	for _, n := range list {
		select {
		case <-runCancel(e, task.ID):
			wg.Wait()
			e.store.LogTask(task.ID, "info", "域名 Web 探测：任务已取消")
			return
		default:
		}
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			probeOne(n)
		}(n)
	}
	wg.Wait()
	e.store.LogTask(task.ID, "info", fmt.Sprintf("域名 Web 探测完成：%d 个域名（含任务域名与收集子域），发现 %d 个存活 Web 站点",
		len(list), found))
}

// probeDomainPortWebs 子域名+端口拼接探测：对每个域名按其解析 IP 上发现的开放 Web 端口，
// 拼 http(s)://域名:端口 探测为 Web 资产。覆盖非常用端口（如 :8080/:8443）上的 vhost 站点——
// IP 视角能看到端口开放，但按域名（Host 头）访问才呈现真实站点。80/443 由 probeDomainWebs 默认探测覆盖，此处跳过。
func (e *Engine) probeDomainPortWebs(task *model.ScanTask, names []string) {
	seen := map[string]bool{}
	list := make([]string, 0, len(names))
	for _, n := range names {
		if n = strings.ToLower(strings.Trim(n, ".")); n != "" && !seen[n] {
			seen[n] = true
			list = append(list, n)
		}
	}
	if len(list) == 0 {
		return
	}
	ipMap := e.store.DomainIPMap(task.ProjectID, list)
	type job struct {
		name  string
		port  int
		https bool
	}
	jobs := []job{}
	jobSeen := map[string]bool{}
	for _, n := range list {
		ip := ipMap[n]
		if ip == "" {
			continue // 未解析到 IP：无从关联端口
		}
		for _, pr := range e.store.OpenPortServices(task.ProjectID, ip) {
			if pr.Port == 80 || pr.Port == 443 {
				continue
			}
			if !isWebPort(pr.Port, pr.Service) {
				continue
			}
			key := fmt.Sprintf("%s:%d", n, pr.Port)
			if jobSeen[key] {
				continue
			}
			jobSeen[key] = true
			jobs = append(jobs, job{name: n, port: pr.Port, https: pr.Port == 8443 || strings.Contains(strings.ToUpper(pr.Service), "HTTPS")})
		}
	}
	if len(jobs) == 0 {
		return
	}
	workers := e.cfg.Worker.Concurrency
	if workers <= 0 {
		workers = 8
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := 0
	timeout := maxInt(task.TimeoutSec, 3)
	for _, j := range jobs {
		select {
		case <-runCancel(e, task.ID):
			wg.Wait()
			e.store.LogTask(task.ID, "info", "域名+端口拼接探测：任务已取消")
			return
		default:
		}
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			select {
			case <-runCancel(e, task.ID):
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			u := "http://" + joinHostPort(j.name, j.port)
			if j.https {
				u = "https://" + joinHostPort(j.name, j.port)
			}
			if newWebProber(timeout)(u, "") == nil {
				return // 不存活：不作为资产入库
			}
			mu.Lock()
			found++
			mu.Unlock()
			e.detectWeb(task, u, "", timeout)
		}(j)
	}
	wg.Wait()
	e.store.LogTask(task.ID, "info", fmt.Sprintf("域名+端口拼接探测完成：%d 个组合，发现 %d 个存活 Web 站点", len(jobs), found))
}

// isWebPort 判断端口是否值得按 Web 探测：服务标识含 HTTP，或属于常见 Web 备用端口
func isWebPort(port int, service string) bool {
	if strings.Contains(strings.ToUpper(service), "HTTP") {
		return true
	}
	switch port {
	case 8000, 8888, 9000, 9090, 7001, 5000, 3000, 10000:
		return true
	}
	return false
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
		nip, nd, np, nw := mapper.Import(e.store, task.ProjectID, task.ID, alive, apexRootsOf(task), task.FPIgnores)
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

// runCanceled 任务是否已请求取消（非阻塞）
func runCanceled(e *Engine, taskID int64) bool {
	select {
	case <-runCancel(e, taskID):
		return true
	default:
		return false
	}
}

// finishCanceled 以取消态收尾任务（各阶段检测到取消时统一调用）
func (e *Engine) finishCanceled(taskID int64) {
	e.store.UpdateTask(taskID, map[string]any{"status": "canceled", "progress": 0, "ended_at": store.NowLocal()})
	e.store.LogTask(taskID, "info", "任务结束: canceled")
}

// markAssetScanned 标记本轮任务已对资产（Web URL / IP）内联执行过某阶段检测，
// 供独立阶段补扫去重（避免 collect 关闭时同任务内重复扫描）
func (e *Engine) markAssetScanned(taskID int64, phase, asset string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r, ok := e.running[taskID]; ok && r.scanned != nil {
		r.scanMu.Lock()
		r.scanned[phase+"\x00"+asset] = true
		r.scanMu.Unlock()
	}
}

// assetScanned 查询标记（任务不在运行态视为未标记）
func (e *Engine) assetScanned(taskID int64, phase, asset string) bool {
	e.mu.Lock()
	r, ok := e.running[taskID]
	e.mu.Unlock()
	if !ok || r.scanned == nil {
		return false
	}
	r.scanMu.Lock()
	defer r.scanMu.Unlock()
	return r.scanned[phase+"\x00"+asset]
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
// projectWantsVulnScan 项目级漏洞扫描意图（store 查询的包装）
func (e *Engine) projectWantsVulnScan(projectID int64) bool {
	return e.store.ProjectWantsVulnScan(projectID)
}

// whitelistHit 判定 Web 资产是否命中白名单：WebResult/AssetWeb 的 IP、Domain 可能为空
// （URL 导入/实时扫描路径探测时无 IP 上下文），从 URL host 兜底提取参与匹配
func (e *Engine) whitelistHit(ip, domain, rawURL string) bool {
	if ip == "" && domain == "" {
		if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
			if net.ParseIP(u.Hostname()) != nil {
				ip = u.Hostname()
			} else {
				domain = u.Hostname()
			}
		}
	}
	return Whitelisted(e.LoadWhitelist(), ip, domain)
}

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
	// nuclei 源规则由官方引擎在任务级批量阶段执行（本内联阶段跳过，避免双重执行与自研执行器误报）
	filtered := make([]vulnrule.Rule, 0, len(rules))
	for _, r := range rules {
		if r.Source != "nuclei" {
			filtered = append(filtered, r)
		}
	}
	rules = filtered
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
	id, isNew, err := e.store.UpsertVuln(v)
	if err == nil && isNew {
		// 新检出漏洞统一记一条任务日志（LogTask 会镜像到控制台，nuclei 侧另有引擎明细行）
		e.store.LogTask(task.ID, "info", fmt.Sprintf("检出漏洞 [%s] %s %s", vr.Severity, vr.Name, w.URL))
		e.store.AddChange(model.AssetChange{ProjectID: task.ProjectID, TaskID: task.ID, AssetType: "vuln",
			Asset: fmt.Sprintf("%s@%s", vr.VulnID, w.URL), Change: "add", Detail: vr.Name + " [" + vr.Severity + "]"})
		// 实时 AI 研判：新增漏洞即入队异步分析（等级过滤与开关在出队时判断）
		e.SubmitAIAnalyze(id, ai.VulnContext{
			VulnID: vr.VulnID, Name: vr.Name, Severity: vr.Severity, Description: vr.Description,
			URL: w.URL, IP: w.IP, Port: w.Port,
			Evidence: vr.Evidence, Request: vr.Request, Response: vr.Response,
		})
	}
	events.Publish("vulns")
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

// Pause / Resume / Cancel。
// Pause/Resume 仅对运行中任务有效：非运行态（pending/已完成等）直接改库会造成
// 状态机死锁（pollLoop 只拉起 pending，paused 任务永不调度）。
func (e *Engine) Pause(taskID int64) error {
	events.Publish("tasks")
	e.mu.Lock()
	r := e.running[taskID]
	e.mu.Unlock()
	if r == nil {
		return fmt.Errorf("任务不在运行中，无法暂停")
	}
	r.pauseBroadcast()
	return e.store.UpdateTask(taskID, map[string]any{"status": "paused"})
}

func (e *Engine) Resume(taskID int64) error {
	events.Publish("tasks")
	e.mu.Lock()
	r := e.running[taskID]
	e.mu.Unlock()
	if r == nil {
		return fmt.Errorf("任务不在运行中，无法恢复")
	}
	r.resumeBroadcast()
	return e.store.UpdateTask(taskID, map[string]any{"status": "running"})
}

func (e *Engine) Cancel(taskID int64) error {
	events.Publish("tasks")
	e.mu.Lock()
	r := e.running[taskID]
	e.mu.Unlock()
	if r != nil {
		r.cancelBroadcast()
	}
	return e.store.UpdateTask(taskID, map[string]any{"status": "canceled", "ended_at": store.NowLocal()})
}

// phaseOn 任务阶段判定：phases 非空按显式组合（collect/vulnscan/weakness/alive），
// 否则按旧 mode 兼容映射（quick=采集+存活，standard/deep=采集+漏洞+弱点）。
func phaseOn(task *model.ScanTask, phase string) bool {
	if p := strings.TrimSpace(task.Phases); p != "" {
		return strings.Contains(","+p+",", ","+phase+",")
	}
	switch task.Mode {
	case "quick":
		return phase == "collect" || phase == "portscan" || phase == "alive"
	default: // standard / deep
		return phase == "collect" || phase == "portscan" || phase == "vulnscan" || phase == "weakness"
	}
}

// pauseBroadcast 关闭 pause 通道=向全部 worker 广播暂停（重复暂停幂等）
func (r *taskRun) pauseBroadcast() {
	r.pmu.Lock()
	defer r.pmu.Unlock()
	select {
	case <-r.pause:
	default:
		close(r.pause)
	}
}

// resumeBroadcast 处于暂停态才恢复：唤醒全部 parked worker，并轮换新的 pause/resume 通道（支持再次暂停）
func (r *taskRun) resumeBroadcast() {
	r.pmu.Lock()
	defer r.pmu.Unlock()
	select {
	case <-r.pause:
		r.pause = make(chan struct{})
		close(r.resume)
		r.resume = make(chan struct{})
	default:
	}
}

// cancelBroadcast 关闭 cancel 并唤醒可能暂停的 worker 使其退出
func (r *taskRun) cancelBroadcast() {
	select {
	case <-r.cancel:
	default:
		close(r.cancel)
	}
	r.pmu.Lock()
	defer r.pmu.Unlock()
	select {
	case <-r.resume:
	default:
		close(r.resume)
	}
}

// waitIfPaused 检查点：暂停广播期间 park（全部 worker 可见），直到恢复或取消。
// 先在锁内快照 pause/resume 通道（恢复会轮换通道，避免与 select 求值竞争）。
func (run *taskRun) waitIfPaused() bool {
	run.pmu.Lock()
	pauseCh, resumeCh := run.pause, run.resume
	run.pmu.Unlock()
	select {
	case <-pauseCh:
		select {
		case <-run.cancel:
			return true
		case <-resumeCh:
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
