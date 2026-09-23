// cysec 攻击面资产发现与风险检测平台 - API + Worker 一体化服务
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cysec/internal/ai"
	"cysec/internal/api"
	"cysec/internal/auth"
	"cysec/internal/config"
	"cysec/internal/consolelog"
	"cysec/internal/engine"
	"cysec/internal/mapper"
	"cysec/internal/model"
	"cysec/internal/netproxy"
	"cysec/internal/store"
	"cysec/internal/ua"
	"cysec/internal/vulnrule"
	"cysec/internal/wih"

	"cysec/plugins/builtin"
	"github.com/gin-gonic/gin"
)

func main() {
	cfgPath := flag.String("config", "configs/config.yaml", "配置文件路径")
	flag.Parse()

	// 初始化检测：config.yaml 不存在则生成默认配置；数据库文件不存在则由存储层自动建库建表
	cfg, err := ensureConfig(*cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	if cfg.UserAgent != "" {
		ua.Set(cfg.UserAgent) // 兼容旧版独立 user_agent 字段；headers 中的 User-Agent 优先生效
	}
	ua.SetHeaders(cfg.Headers) // config.yaml headers 段：User-Agent 为全局 UA，其余为漏洞扫描引擎附加头
	if err := os.MkdirAll(filepath.Dir(cfg.Database.Path), 0o755); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	// 启动备份：拷贝现有数据库到 data/backups/（保留最近 7 份），防止意外清空不可恢复
	backupDB(filepath.Dir(cfg.Database.Path), cfg.Database.Path)

	dbExisted := false
	if _, err := os.Stat(cfg.Database.Path); err == nil {
		dbExisted = true
	} else if m, _ := filepath.Glob(cfg.Database.Path + "?*"); len(m) > 0 {
		dbExisted = true // SQLite 驱动会把连接参数拼进实际文件名
	}
	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()
	// Console 运行日志：标准 log 输出镜像入 system_logs（stderr 照常输出），
	// 尽早安装以覆盖后续全部运行日志；日志管理界面"Console 运行"页签可查
	consolelog.Start(st)
	// 孤儿任务恢复：进程重启前仍 running 的任务复位 pending 重新执行（否则周期调度永久停摆）
	if ids := st.RecoverOrphanRunning(); len(ids) > 0 {
		log.Printf("[启动恢复] 复位上次被中断的任务 %d 个: %v", len(ids), ids)
	}
	if !dbExisted {
		log.Printf("[初始化] 未检测到数据库文件，已自动创建并初始化全部数据表: %s", cfg.Database.Path)
	}

	// 全局出站代理（http / socks5，支持用户名密码）：界面运行时修改优先于 config.yaml
	if saved, _ := st.GetSetting("proxy"); saved != "" {
		var p config.Proxy
		if json.Unmarshal([]byte(saved), &p) == nil {
			cfg.Proxy = p
		}
	}
	if err := netproxy.Configure(cfg.Proxy); err != nil {
		log.Fatalf("代理配置无效: %v", err)
	}

	// 空间测绘数据源（FOFA/Quake/Shodan/0.zone/ZoomEye）：界面运行时修改优先于 config.yaml
	if saved, _ := st.GetSetting("mapping"); saved != "" {
		var m mapper.Config
		if json.Unmarshal([]byte(saved), &m) == nil {
			cfg.Mapping = m
		}
	}
	mapper.Configure(cfg.Mapping)
	log.Printf("空间测绘: %s", mapper.Describe())

	// POC 文件仓库默认类型目录：xray / nuclei / afrog 依次存放三种 POC；
	// 模板源更新克隆目录默认在 poc/nuclei 下，旧 data/templates 一次性迁移并修正规则路径
	pocRoot := filepath.Join(filepath.Dir(cfg.Database.Path), "poc")
	for _, d := range []string{"xray", "nuclei", "afrog"} {
		os.MkdirAll(filepath.Join(pocRoot, d), 0o755)
	}
	// 一次性迁移：旧克隆目录 data/templates 合并移动到 data/poc/nuclei（目标目录已存在时逐项移动）
	oldTpl := filepath.Join(filepath.Dir(cfg.Database.Path), "templates")
	newTpl := filepath.Join(pocRoot, "nuclei")
	if entries, err := os.ReadDir(oldTpl); err == nil {
		os.MkdirAll(newTpl, 0o755)
		moved := 0
		for _, e := range entries {
			src := filepath.Join(oldTpl, e.Name())
			dst := filepath.Join(newTpl, e.Name())
			if _, err := os.Stat(dst); err != nil {
				if os.Rename(src, dst) == nil {
					moved++
				}
			}
		}
		if moved > 0 {
			log.Printf("[模板源] 已迁移 %d 个克隆仓库 %s -> %s", moved, oldTpl, newTpl)
		}
		os.Remove(oldTpl)
	}
	st.Exec(`UPDATE vuln_rules SET file_path = REPLACE(file_path, ?, ?) WHERE file_path LIKE ?`,
		oldTpl+string(os.PathSeparator), newTpl+string(os.PathSeparator), oldTpl+"%")

	a := auth.New(st, cfg.Auth.BootstrapAdminUser, cfg.Auth.BootstrapAdminPass, cfg.Auth.TokenTTLHours)
	if err := a.Bootstrap(); err != nil {
		log.Fatalf("初始化管理员失败: %v", err)
	}
	a.WarnDefaultPassword()

	// AI 研判配置：设置表无记录时从 config.yaml 的 ai 段种子（界面保存后以设置表为准并写回 yaml）
	if saved, _ := st.GetSetting("ai_config"); saved == "" && cfg.AI.BaseURL != "" {
		if data, err := json.Marshal(cfg.AI); err == nil {
			st.SetSetting("ai_config", string(data))
			log.Printf("[初始化] AI 研判配置已从 config.yaml 载入（provider=%s model=%s）", cfg.AI.Provider, cfg.AI.Model)
		}
	}

	// WIH JS 敏感信息检测：启动时从库中恢复设置（界面保存后即时生效）
	if saved, _ := st.GetSetting("wih_settings"); saved != "" {
		var ws wih.Settings
		if json.Unmarshal([]byte(saved), &ws) == nil && len(ws.Rules) > 0 {
			wih.SetCurrent(ws)
		}
	}

	// 一次性迁移：历史 WIH 漏洞归并到弱点管理表（幂等，settings 键守护）
	if flag, _ := st.GetSetting("wih_weakness_migrated"); flag != "1" {
		res, err := st.Exec(`INSERT OR IGNORE INTO weaknesses(project_id,task_id,web_url,type,url,anchor,status_code,detail,severity,evidence,created_at)
			SELECT project_id, 0, COALESCE(url,''), 'wih', COALESCE(url,''), name, 0,
				COALESCE(description,''), severity, COALESCE(evidence,''), COALESCE(first_seen,?)
			FROM vulnerabilities WHERE scanner='wih'`, store.NowLocal())
		if err == nil {
			n, _ := res.RowsAffected()
			if _, derr := st.Exec(`DELETE FROM vulnerabilities WHERE scanner='wih'`); derr == nil && n > 0 {
				log.Printf("[迁移] WIH 历史检测结果 %d 条已归并到弱点管理", n)
			}
			st.SetSetting("wih_weakness_migrated", "1")
		}
	}

	// 敏感路径检测：启动时从库中恢复界面自定义规则（未配置则该检测跳过）
	if saved, _ := st.GetSetting("leak_paths"); saved != "" {
		var lps []builtin.LeakPath
		if json.Unmarshal([]byte(saved), &lps) == nil {
			builtin.SetLeakPaths(lps)
		}
	}

	// 全局代理连通性守护：配置了代理即周期检测，异常自动切直连、恢复自动切回
	if flag, _ := st.GetSetting("proxy_health_active"); flag == "1" {
		netproxy.SetHealthActive(true)
	}
	if t, _ := st.GetSetting("proxy_health_target"); t != "" {
		netproxy.SetHealthProbeTarget(t)
	}
	netproxy.StartHealthWatch(
		func() int {
			if saved, _ := st.GetSetting("proxy_health_interval"); saved != "" {
				if v, err := strconv.Atoi(saved); err == nil && v >= 10 {
					return v
				}
			}
			return 60
		},
		func(enable bool) {
			p := netproxy.Current()
			p.Enable = enable
			netproxy.Configure(p)
			data, _ := json.Marshal(p)
			st.SetSetting("proxy", string(data))
			state := "连通正常，流量切回全局代理"
			if !enable {
				state = "连通异常，走全局代理的流量已切换直连（检测继续）"
			}
			st.SystemLog(model.SystemLog{Username: "system", Action: "proxy_health", ClientIP: "127.0.0.1", Result: state})
			log.Printf("[代理守护] %s", state)
		},
	)

	e := engine.New(st, cfg)

	// 测绘导入产生的新增 Web 资产 → 实时漏洞扫描（与任务发现/手动导入同一入口）
	mapper.SetNewWebHandler(func(projectID int64, url string) { e.SubmitAutoScan(projectID, url) })

	// 模板源每日自动更新（学习 nuclei-poc-main/.github/workflows/daily-run.yml）
	vulnrule.SetSourceConfigProvider(func() vulnrule.SourceConfig {
		c := vulnrule.DefaultSourceConfig()
		if saved, _ := st.GetSetting("rule_sources"); saved != "" {
			json.Unmarshal([]byte(saved), &c)
		}
		c.Normalize()
		return c
	})
	go dailyRuleUpdate(st, cfg)

	// POC 目录监控：data/poc 新增规则文件 → 自动入库 → 对全部资产 Web 站点执行新规则扫描
	if wcSaved, _ := st.GetSetting("poc_watcher"); wcSaved != "" {
		var wc vulnrule.WatcherConfig
		if json.Unmarshal([]byte(wcSaved), &wc) == nil {
			vulnrule.ConfigureWatcher(wc)
		}
	}
	os.MkdirAll(pocRoot, 0o755)
	// 官方 nuclei 引擎模板根目录（克隆仓库与导入模板均在此）
	vulnrule.SetNucleiTemplateRoot(filepath.Join(pocRoot, "nuclei"))
	// 新增规则（POC 目录监控 或 模板源更新）→ 对全部资产执行新规则扫描
	vulnrule.SetNewRulesHandler(func(rules []vulnrule.Rule) {
		scanAllAssetsWithNewRules(e, st, rules)
	})
	// 存量 Web 资产 URL 协议补全（TLS 探测，异步不阻塞启动）
	go mapper.MigrateWebURLs(st.DB())
	vulnrule.StartWatcher(pocRoot, st.UpsertVulnRule, vulnrule.InvokeNewRulesHandler)
	r := api.NewRouter(st, cfg, a, e, *cfgPath)

	// 前端静态资源（嵌入 web/dist）
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.Contains(p, "..") {
			c.Status(404)
			return
		}
		if p == "/" {
			p = "/index.html"
		}
		data, err := webdist.ReadFile("webdist" + p)
		if err != nil {
			// SPA 兜底：未命中文件返回 index.html
			data, err = webdist.ReadFile("webdist/index.html")
			if err != nil {
				c.Status(404)
				return
			}
			p = "/index.html"
		}
		c.Data(200, mimeByExt(p), data)
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Cysec-Scan 服务启动: http://%s (默认账号 %s)", addr, cfg.Auth.BootstrapAdminUser)
	log.Printf("出站代理: %s", netproxy.Describe())
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

// dailyRuleUpdate 每日定时模板源更新：在配置的 auto_time（默认 02:00）触发；
// 若今日时段已运行过则顺延至次日，时间设置改动后 30 分钟内热生效
func dailyRuleUpdate(st *store.Store, cfg *config.Config) {
	root := filepath.Join(filepath.Dir(cfg.Database.Path), vulnrule.CloneSubDir)
	saveState := func(src vulnrule.Source) {
		s := vulnrule.DefaultSourceConfig()
		if saved, _ := st.GetSetting("rule_sources"); saved != "" {
			json.Unmarshal([]byte(saved), &s)
		}
		s.Normalize()
		for i := range s.Sources {
			if s.Sources[i].URL == src.URL {
				s.Sources[i].LastUpdate = src.LastUpdate
				s.Sources[i].LastResult = src.LastResult
			}
		}
		s.LastRun = time.Now().Format(time.RFC3339)
		data, _ := json.Marshal(s)
		st.SetSetting("rule_sources", string(data))
	}
	loadCfg := func() vulnrule.SourceConfig {
		c := vulnrule.DefaultSourceConfig()
		if saved, _ := st.GetSetting("rule_sources"); saved != "" {
			json.Unmarshal([]byte(saved), &c)
		}
		c.Normalize()
		return c
	}
	for {
		c := loadCfg()
		if !c.AutoDaily {
			time.Sleep(5 * time.Minute)
			continue
		}
		now := time.Now()
		hh, mm := 2, 0
		if parts := strings.Split(c.AutoTime, ":"); len(parts) == 2 {
			a, e1 := strconv.Atoi(parts[0])
			b, e2 := strconv.Atoi(parts[1])
			if e1 == nil && e2 == nil {
				hh, mm = a, b
			}
		}
		next := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
		if lastRun, err := time.Parse(time.RFC3339, c.LastRun); err == nil && !lastRun.Before(next) {
			next = next.Add(24 * time.Hour) // 今日时段已运行过
		} else if !next.After(now) {
			next = next.Add(24 * time.Hour) // 今日时刻已过
		}
		wait := next.Sub(now)
		if wait > 30*time.Minute {
			time.Sleep(30 * time.Minute)
			continue
		}
		time.Sleep(wait)
		log.Printf("[模板源] 定时自动更新触发（%s）", c.AutoTime)
		if vulnrule.StartUpdate(root, st.UpsertVulnRule, saveState) {
			st.SystemLog(model.SystemLog{Username: "system", Action: "auto_update_rule_sources", Result: "started"})
		}
		time.Sleep(2 * time.Minute)
	}
}

// scanAllAssetsWithNewRules 用新增规则对所有项目的 Web 资产执行漏洞扫描
// newRulesScanMu 防重入：POC 目录监控 / 模板源更新 / 界面手动导入并发触发时
// 串行执行全资产补扫，避免对目标双倍流量与扫描状态互相覆盖
var newRulesScanMu sync.Mutex

func scanAllAssetsWithNewRules(e *engine.Engine, st *store.Store, rules []vulnrule.Rule) {
	newRulesScanMu.Lock()
	defer newRulesScanMu.Unlock()
	vulnrule.MarkScanState(true)
	defer vulnrule.MarkScanState(false)
	start := time.Now()
	webs := st.AllWebAssets()
	matchedTotal := 0
	// 白名单资产跳过漏洞扫描
	var wl engine.WhitelistEntries
	if saved, _ := st.GetSetting("scan_whitelist"); saved != "" {
		json.Unmarshal([]byte(saved), &wl)
	}
	filtered := make([]model.AssetWeb, 0, len(webs))
	// 项目级意图过滤：仅对该项目存在"勾选漏洞扫描任务"的项目补扫——
	// 从未勾选过漏洞扫描的项目，规则新增不触发对其资产的扫描
	wants := map[int64]bool{}
	projectWants := func(pid int64) bool {
		if v, ok := wants[pid]; ok {
			return v
		}
		v := st.ProjectWantsVulnScan(pid)
		wants[pid] = v
		return v
	}
	noIntent := 0
	for _, w := range webs {
		if engine.Whitelisted(wl.Items, w.IP, w.Domain) {
			continue
		}
		if !projectWants(w.ProjectID) {
			noIntent++
			continue
		}
		filtered = append(filtered, w)
	}
	skipped := len(webs) - len(filtered)
	webs = filtered
	if len(filtered) == 0 {
		vulnrule.SetLastScan(map[string]any{
			"rules": len(rules), "assets": 0, "matched": 0,
			"at": start.Format(time.RFC3339), "note": "无可扫描 Web 资产（项目未勾选漏洞扫描或白名单跳过）",
		})
		return
	}
	log.Printf("[新增规则] 检测到 %d 条新增规则，对 %d 个 Web 资产补扫（项目未勾选漏洞扫描跳过 %d 个，白名单跳过 %d 个）", len(rules), len(filtered), noIntent, skipped)
	// nuclei 源规则由官方引擎批量执行（自研执行器对官方模板误报率高）
	nucleiIDs := []string{}
	otherRules := []vulnrule.Rule{}
	for _, r := range rules {
		if r.Source == "nuclei" {
			nucleiIDs = append(nucleiIDs, r.RuleID)
		} else {
			otherRules = append(otherRules, r)
		}
	}
	if len(nucleiIDs) > 0 {
		matchedTotal += e.ScanAssetsWithNucleiRules(nucleiIDs, 8)
	}
	rules = otherRules
	for i := range rules {
		for _, w := range webs {
			res := vulnrule.Run(&rules[i], w.URL, 8)
			if res.Err != "" || !res.Matched {
				continue
			}
			matchedTotal++
			vid, isNew, _ := st.UpsertVuln(model.Vulnerability{
				ProjectID:   w.ProjectID,
				VulnID:      rules[i].RuleID,
				Name:        rules[i].Name,
				Severity:    rules[i].Severity,
				IP:          w.IP,
				Domain:      w.Domain,
				Port:        w.Port,
				URL:         w.URL,
				Component:   "POC监控(" + rules[i].Source + ")",
				Description: rules[i].Description,
				Evidence:    res.Evidence,
				Request:     res.Request,
				Response:    res.Response,
				Scanner:     "poc-watcher",
			})
			if isNew {
				st.AddChange(model.AssetChange{
					ProjectID: w.ProjectID, AssetType: "vuln",
					Asset: rules[i].RuleID + "@" + w.URL, Change: "add",
					Detail: "POC 目录新增规则检出: " + rules[i].Name,
				})
				// 实时 AI 研判：新增漏洞即入队
				e.SubmitAIAnalyze(vid, ai.VulnContext{
					VulnID: rules[i].RuleID, Name: rules[i].Name, Severity: rules[i].Severity,
					Description: rules[i].Description, URL: w.URL, IP: w.IP, Port: w.Port,
					Evidence: res.Evidence, Request: res.Request, Response: res.Response,
				})
			}
		}
	}
	vulnrule.SetLastScan(map[string]any{
		"rules": len(rules), "assets": len(webs), "matched": matchedTotal,
		"at":      time.Now().Format(time.RFC3339),
		"elapsed": time.Since(start).Round(time.Second).String(),
	})
	st.SystemLog(model.SystemLog{
		Username: "system", Action: "poc_watcher_scan",
		Result: fmt.Sprintf("rules=%d assets=%d matched=%d", len(rules), len(webs), matchedTotal),
	})
	log.Printf("[POC监控] 扫描完成：规则 %d × 资产 %d，检出 %d（耗时 %s）", len(rules), len(webs), matchedTotal, time.Since(start).Round(time.Second))
}

// ensureConfig 检测配置文件：存在则直接加载；不存在则生成默认模板后加载
func ensureConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); err == nil {
		return config.Load(path) // 已存在，跳过初始化
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建配置目录失败: %w", err)
	}
	// 优先复制同目录的 config.example.yaml（发布包内置示例，即默认配置内容）
	example := filepath.Join(filepath.Dir(path), "config.example.yaml")
	if data, err := os.ReadFile(example); err == nil && len(data) > 0 {
		if werr := os.WriteFile(path, data, 0o644); werr == nil {
			log.Printf("[初始化] 未检测到配置文件，已从示例模板生成: %s", path)
			return config.Load(path)
		}
	}
	// 裸二进制（无示例文件）回退内置默认模板
	if err := os.WriteFile(path, exampleConfigYAML, 0o644); err != nil {
		return nil, fmt.Errorf("生成默认配置失败: %w", err)
	}
	log.Printf("[初始化] 未检测到配置文件，已生成默认配置: %s", path)
	return config.Load(path)
}

// exampleConfigYAML 内置默认配置模板：与仓库根目录 configs/config.example.yaml 内容一致，
// 经 go:embed 嵌入二进制；config_template_test.go 中的防漂移测试保证两份内容同步。
//
//go:embed config.example.yaml
var exampleConfigYAML []byte

// backupDB 启动时备份数据库文件（存在才备份），保留最近 keepN 份
func backupDB(dataDir, dbPath string) {
	// SQLite 驱动会把连接参数拼进实际文件名（cysec.db?_pragma=...），按前缀定位真实文件
	real := dbPath
	if _, err := os.Stat(dbPath); err != nil {
		if m, _ := filepath.Glob(dbPath + "?*"); len(m) > 0 {
			real = m[0]
		}
	}
	st, err := os.Stat(real)
	if err != nil || st.Size() == 0 {
		return
	}
	dbPath = real
	bkDir := filepath.Join(dataDir, "backups")
	os.MkdirAll(bkDir, 0o755)
	dst := filepath.Join(bkDir, "cysec-"+time.Now().Format("20060102-150405")+".db")
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return
	}
	sizeKB := len(data) / 1024
	// WAL 未合并时（如上次异常退出）：旁路文件单独存放为同名 -wal，
	// 恢复时与主库一并拷回才是完整可用的库（直接拼接进主库会破坏 SQLite 文件格式）
	if wal, err := os.ReadFile(dbPath + "-wal"); err == nil && len(wal) > 0 {
		if werr := os.WriteFile(dst+"-wal", wal, 0o644); werr == nil {
			sizeKB += len(wal) / 1024
		}
	}
	if err := os.WriteFile(dst, data, 0o644); err == nil {
		log.Printf("[备份] 数据库已备份至 %s (%d KB)", dst, sizeKB)
	}
	// 清理旧备份，保留最近 7 份
	entries, _ := os.ReadDir(bkDir)
	type finfo struct {
		name string
		mod  time.Time
	}
	var list []finfo
	for _, e := range entries {
		// 仅按主库文件计数；-wal/-shm 旁路文件随对应主库一同清理
		if !e.IsDir() && strings.HasPrefix(e.Name(), "cysec-") && strings.HasSuffix(e.Name(), ".db") {
			if info, err := e.Info(); err == nil {
				list = append(list, finfo{e.Name(), info.ModTime()})
			}
		}
	}
	// 按修改时间新到旧排序，仅当超过 7 份时清理更旧的
	sort.Slice(list, func(i, j int) bool { return list[i].mod.After(list[j].mod) })
	if len(list) > 7 {
		for _, f := range list[7:] {
			os.Remove(filepath.Join(bkDir, f.name))
			os.Remove(filepath.Join(bkDir, f.name+"-wal"))
			os.Remove(filepath.Join(bkDir, f.name+"-shm"))
		}
	}
}

func mimeByExt(p string) string {
	switch {
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".js"):
		return "application/javascript"
	case strings.HasSuffix(p, ".css"):
		return "text/css"
	case strings.HasSuffix(p, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(p, ".png"):
		return "image/png"
	case strings.HasSuffix(p, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(p, ".json"):
		return "application/json"
	}
	return "application/octet-stream"
}
