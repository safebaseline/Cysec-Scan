// Package api REST API 层（需求文档 第二十八节）
package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cysec/internal/ai"
	"cysec/internal/auth"
	"cysec/internal/config"
	"cysec/internal/engine"
	"cysec/internal/mapper"
	"cysec/internal/model"
	"cysec/internal/netproxy"
	"cysec/internal/plugins"
	"cysec/internal/store"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"cysec/internal/vulnrule"
	"cysec/internal/wih"

	"github.com/gin-gonic/gin"
)

type API struct {
	store      *store.Store
	cfg        *config.Config
	auth       *auth.Auth
	engine     *engine.Engine
	configPath string // 配置文件路径（代理等设置写回）
}

func NewRouter(st *store.Store, cfg *config.Config, a *auth.Auth, e *engine.Engine, configPath string) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	api := &API{store: st, cfg: cfg, auth: a, engine: e, configPath: configPath}
	r := gin.New()
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{SkipPaths: []string{"/api/health"}}), gin.Recovery())

	r.POST("/api/login", api.login)
	r.GET("/api/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	authed := r.Group("/api")
	authed.Use(a.Middleware())

	// 项目
	authed.POST("/projects", a.Middleware("admin"), api.createProject)
	authed.GET("/projects", api.listProjects)
	authed.DELETE("/projects/:id", a.Middleware("admin"), api.deleteProject)

	// 资产导入（IP/Domain/URL，自动去重）
	authed.POST("/assets", a.Middleware("admin", "auditor"), api.importAssets)
	authed.GET("/assets", api.listAssets)
	authed.GET("/assets/ip/:ip", api.ipDetail)
	authed.DELETE("/assets/:type/:id", a.Middleware("admin"), api.deleteAsset)
	authed.DELETE("/assets/:type", a.Middleware("admin"), api.clearAssets)

	// 资产列表 API
	authed.GET("/ips", api.listIPs)
	authed.GET("/domains", api.listDomains)
	authed.GET("/ports", api.listPorts)
	authed.GET("/services", api.listServices)
	authed.GET("/urls", api.listURLs)
	authed.GET("/webs", api.listWebs)

	// 漏洞
	authed.GET("/vulnerabilities", api.listVulns)
	authed.GET("/vulnerabilities/:id", api.getVulnDetail)
	authed.PUT("/vulnerabilities/:id/mark", a.Middleware("admin", "auditor"), api.markVuln)
	authed.DELETE("/vulnerabilities/:id", a.Middleware("admin", "auditor"), api.deleteVuln)
	authed.DELETE("/vulnerabilities", a.Middleware("admin"), api.clearVulns)
	authed.POST("/vulnerabilities/:id/ai-analyze", a.Middleware("admin", "auditor"), api.aiAnalyzeVuln)
	authed.POST("/vulnerabilities/ai-analyze-all", a.Middleware("admin", "auditor"), api.aiAnalyzeAll)
	authed.POST("/system/ai/models", a.Middleware("admin"), api.aiListModels)

	// 任务
	authed.POST("/tasks", a.Middleware("admin", "auditor"), api.createTask)
	authed.GET("/tasks", api.listTasks)
	authed.GET("/tasks/:id", api.getTask)
	authed.GET("/tasks/:id/logs", api.taskLogs)
	authed.POST("/tasks/:id/pause", a.Middleware("admin", "auditor"), api.pauseTask)
	authed.POST("/tasks/:id/resume", a.Middleware("admin", "auditor"), api.resumeTask)
	authed.POST("/tasks/:id/cancel", a.Middleware("admin", "auditor"), api.cancelTask)
	authed.DELETE("/tasks/:id", a.Middleware("admin", "auditor"), api.deleteTask)
	authed.POST("/tasks/:id/run", a.Middleware("admin", "auditor"), api.runTask)

	// 统计 / 搜索 / 变化 / 报告导出
	authed.GET("/stats", api.stats)
	authed.GET("/search", api.search)
	authed.GET("/changes", api.changes)
	authed.GET("/reports", api.reports)
	authed.GET("/export", api.export)

	// 系统管理
	authed.GET("/system/plugins", api.plugins)
	authed.GET("/system/ai", api.getAIConfig)
	authed.PUT("/system/ai", a.Middleware("admin"), api.setAIConfig)
	authed.GET("/system/whitelist", api.getWhitelist)
	authed.PUT("/system/whitelist", a.Middleware("admin"), api.setWhitelist)
	authed.GET("/system/logs", a.Middleware("admin", "auditor"), api.systemLogs)
	authed.GET("/system/proxy", api.getProxy)
	authed.PUT("/system/proxy", a.Middleware("admin"), api.setProxy)
	authed.POST("/system/proxy/test", a.Middleware("admin"), api.testProxy)
	authed.GET("/system/mapping", api.getMapping)
	authed.PUT("/system/mapping", a.Middleware("admin"), api.setMapping)
	authed.POST("/system/mapping/test", a.Middleware("admin"), api.testMapping)
	authed.POST("/mapping/query", a.Middleware("admin", "auditor"), api.mappingQuery)
	authed.GET("/vuln-rules", api.listVulnRules)
	authed.GET("/vuln-rules/stats", api.vulnRuleStats)
	authed.POST("/vuln-rules/import", a.Middleware("admin"), api.importVulnRules)
	authed.GET("/vuln-rules/settings", api.getVulnRuleSettings)
	authed.PUT("/vuln-rules/settings", a.Middleware("admin"), api.setVulnRuleSettings)
	authed.GET("/vuln-rules/:id", api.getVulnRule)
	authed.POST("/vuln-rules/:id/toggle", a.Middleware("admin"), api.toggleVulnRule)
	authed.DELETE("/vuln-rules/:id", a.Middleware("admin"), api.deleteVulnRule)
	authed.DELETE("/vuln-rules", a.Middleware("admin"), api.clearVulnRules)
	authed.POST("/vuln-rules/:id/test", a.Middleware("admin", "auditor"), api.testVulnRule)
	authed.GET("/poc-files", api.listPocFiles)
	authed.POST("/poc-files/mkdir", a.Middleware("admin"), api.mkdirPocFiles)
	authed.POST("/poc-files/save", a.Middleware("admin"), api.savePocFile)
	authed.DELETE("/poc-files", a.Middleware("admin"), api.deletePocFile)
	authed.POST("/poc-files/import", a.Middleware("admin", "auditor"), api.importPocFiles)
	authed.GET("/vuln-rules/sources", api.getRuleSources)
	authed.PUT("/vuln-rules/sources", a.Middleware("admin"), api.setRuleSources)
	authed.POST("/vuln-rules/sources/update", a.Middleware("admin"), api.updateRuleSources)
	authed.GET("/vuln-rules/watcher", api.getWatcher)
	authed.PUT("/vuln-rules/watcher", a.Middleware("admin"), api.setWatcher)
	authed.GET("/wih/settings", api.getWihSettings)
	authed.PUT("/wih/settings", a.Middleware("admin"), api.setWihSettings)
	authed.POST("/wih/test", a.Middleware("admin", "auditor"), api.testWihScan)
	authed.POST("/logout", api.logout)

	return r
}

func (api *API) login(c *gin.Context) {
	var req struct{ Username, Password string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}
	token, err := api.auth.Login(req.Username, req.Password)
	if err != nil {
		api.store.SystemLog(model.SystemLog{Username: req.Username, Action: "login", ClientIP: c.ClientIP(), Result: "failed"})
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: req.Username, Action: "login", ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"token": token})
}

func (api *API) logout(c *gin.Context) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	api.auth.Logout(token)
	c.JSON(200, gin.H{"ok": true})
}

func projID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Query("project_id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "缺少 project_id"})
		return 0, false
	}
	return id, true
}

func page(c *gin.Context) (int, int) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	return limit, offset
}

// ---------- 项目 ----------

func (api *API) createProject(c *gin.Context) {
	var p model.Project
	if err := c.ShouldBindJSON(&p); err != nil || p.Name == "" {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	id, err := api.store.CreateProject(&p)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "create_project", Object: p.Name, ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"id": id})
}

// deleteProject 删除项目及全部关联数据
func (api *API) deleteProject(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	p, err := api.store.GetProject(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "项目不存在"})
		return
	}
	// 终止该项目运行中的任务
	rows, _ := api.store.QueryPage("scan_tasks", id, "status IN ('running','pending','paused')", nil, "", 100, 0)
	for _, r := range rows {
		if tid, ok := r["id"].(int64); ok {
			api.engine.Cancel(tid)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if err := api.store.DeleteProject(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "delete_project",
		Object: fmt.Sprint(p["name"]), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

func (api *API) listProjects(c *gin.Context) {
	ps, err := api.store.ListProjects()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, ps)
}

// ---------- 资产导入（去重） ----------

func (api *API) importAssets(c *gin.Context) {
	var req struct {
		ProjectID int64  `json:"project_id"`
		Type      string `json:"type"` // ip / domain / url / mixed
		Content   string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ProjectID <= 0 || strings.TrimSpace(req.Content) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 project_id 与 content"})
		return
	}
	if _, err := api.store.GetProject(req.ProjectID); err != nil {
		c.JSON(404, gin.H{"error": "项目不存在"})
		return
	}
	ips, domains, urls, err := engine.ParseTargets(req.Content, req.Type, api.cfg.Scan.MaxTargetsPerTask)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var newIPs, newDomains int
	for _, ip := range ips {
		isNew, _ := api.store.UpsertIP(model.AssetIP{ProjectID: req.ProjectID, IP: ip, Network: engine.IsPrivateIP(ip), Source: "import"})
		if isNew {
			newIPs++
		}
	}
	for _, d := range domains {
		isNew, _ := api.store.UpsertDomain(model.AssetDomain{ProjectID: req.ProjectID, Domain: d, Source: "import"})
		if isNew {
			newDomains++
		}
	}
	for _, u := range urls {
		isNew, _ := api.store.UpsertURL(model.AssetURL{ProjectID: req.ProjectID, URL: u, Method: "GET", Source: "import"})
		// 新导入的 URL 交实时漏洞扫描器：探测建 Web 资产 + 风险检测 + 规则库
		if isNew {
			api.engine.SubmitAutoScan(req.ProjectID, u)
		}
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "import_assets", Object: fmt.Sprintf("project=%d", req.ProjectID), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{
		"ips": len(ips), "domains": len(domains), "urls": len(urls),
		"new_ips": newIPs, "new_domains": newDomains,
	})
}

// ---------- 资产列表 ----------

func (api *API) listTable(c *gin.Context, table, defOrder string) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	limit, offset := page(c)
	where := ""
	args := []any{}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		switch table {
		case "asset_ips":
			where, args = "ip LIKE ?", append(args, "%"+q+"%")
		case "asset_domains":
			where, args = "domain LIKE ?", append(args, "%"+q+"%")
		case "asset_ports":
			where, args = "(ip LIKE ? OR CAST(port AS TEXT) LIKE ? OR service LIKE ?)", append(args, "%"+q+"%", "%"+q+"%", "%"+q+"%")
		case "asset_web":
			where, args = "(url LIKE ? OR title LIKE ? OR tech LIKE ?)", append(args, "%"+q+"%", "%"+q+"%", "%"+q+"%")
		case "asset_urls":
			where, args = "url LIKE ?", append(args, "%"+q+"%")
		case "vulnerabilities":
			where, args = "(name LIKE ? OR vuln_id LIKE ? OR ip LIKE ? OR url LIKE ? OR component LIKE ?)", append(args, "%"+q+"%", "%"+q+"%", "%"+q+"%", "%"+q+"%", "%"+q+"%")
		}
		if table == "asset_ports" && q == "" {
			where = ""
		}
	}
	if sev := c.Query("severity"); sev != "" && table == "vulnerabilities" {
		if where != "" {
			where += " AND "
		}
		where += "severity=?"
		args = append(args, sev)
	}
	total, _ := api.store.Count(table, pid, where, args)
	rows, err := api.store.QueryPage(table, pid, where, args, defOrder, limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"total": total, "items": rows})
}

func (api *API) listAssets(c *gin.Context) {
	typ := c.DefaultQuery("type", "ip")
	switch typ {
	case "ip":
		api.listTable(c, "asset_ips", "ip")
	case "domain":
		api.listTable(c, "asset_domains", "domain")
	case "web":
		api.listTable(c, "asset_web", "url")
	case "url":
		api.listTable(c, "asset_urls", "url")
	case "port":
		api.listTable(c, "asset_ports", "ip, port")
	default:
		c.JSON(400, gin.H{"error": "type 必须为 ip/domain/web/url/port"})
	}
}

func (api *API) listIPs(c *gin.Context)     { api.listTable(c, "asset_ips", "risk_score DESC, ip") }
func (api *API) listDomains(c *gin.Context) { api.listTable(c, "asset_domains", "domain") }
func (api *API) listPorts(c *gin.Context)   { api.listTable(c, "asset_ports", "ip, port") }
func (api *API) listURLs(c *gin.Context)    { api.listTable(c, "asset_urls", "url") }
func (api *API) listWebs(c *gin.Context)    { api.listTable(c, "asset_web", "url") }
func (api *API) listVulns(c *gin.Context) {
	// 列表不返回 request/response 报文（详情接口按需获取）
	pid, ok := projID(c)
	if !ok {
		return
	}
	limit, offset := page(c)
	where := ""
	args := []any{}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		where, args = "(name LIKE ? OR vuln_id LIKE ? OR ip LIKE ? OR url LIKE ? OR component LIKE ?)", []any{"%" + q + "%", "%" + q + "%", "%" + q + "%", "%" + q + "%", "%" + q + "%"}
	}
	if sev := c.Query("severity"); sev != "" {
		if where != "" {
			where += " AND "
		}
		where += "severity=?"
		args = append(args, sev)
	}
	if mark := c.Query("mark"); mark != "" {
		if where != "" {
			where += " AND "
		}
		if mark == "unmarked" {
			where += "COALESCE(mark,'')=''"
		} else {
			where += "mark=?"
			args = append(args, mark)
		}
	}
	total, _ := api.store.Count("vulnerabilities", pid, where, args)
	rows, err := api.store.QueryPage("vulnerabilities", pid, where, args,
		"CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, last_seen DESC", limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	for _, r := range rows {
		delete(r, "request")
		delete(r, "response")
	}
	c.JSON(200, gin.H{"total": total, "items": rows})
}

// getAIConfig 读取 AI 配置
func (api *API) getAIConfig(c *gin.Context) {
	cfg := ai.DefaultConfig()
	if saved, _ := api.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	// 脱敏返回（不返回完整 API Key）
	safe := cfg
	if len(safe.APIKey) > 8 {
		safe.APIKey = safe.APIKey[:4] + "****" + safe.APIKey[len(safe.APIKey)-4:]
	}
	c.JSON(200, safe)
}

// setAIConfig 保存 AI 配置
func (api *API) setAIConfig(c *gin.Context) {
	var cfg ai.Config
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	// 如果 API Key 是脱敏格式且与当前保存的一致，保留原 Key
	if strings.Contains(cfg.APIKey, "****") {
		var old ai.Config
		if saved, _ := api.store.GetSetting("ai_config"); saved != "" {
			json.Unmarshal([]byte(saved), &old)
			if strings.HasPrefix(old.APIKey, strings.SplitN(cfg.APIKey, "****", 2)[0]) {
				cfg.APIKey = old.APIKey
			}
		}
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 30
	}
	if cfg.TimeoutSec > 120 {
		cfg.TimeoutSec = 120
	}
	data, _ := json.Marshal(cfg)
	if err := api.store.SetSetting("ai_config", string(data)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "set_ai_config",
		Object: cfg.Provider + "/" + cfg.Model, ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

// aiAnalyzeAll 对项目全部未标记漏洞批量 AI 研判（异步）
func (api *API) aiAnalyzeAll(c *gin.Context) {
	pid, err := strconv.ParseInt(c.Query("project_id"), 10, 64)
	if err != nil || pid <= 0 {
		c.JSON(400, gin.H{"error": "缺少 project_id"})
		return
	}
	cfg := ai.DefaultConfig()
	if saved, _ := api.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	if !cfg.Enabled {
		c.JSON(400, gin.H{"error": "AI 研判未启用"})
		return
	}
	// 取全部未标记漏洞
	vulns, err := api.store.QueryPage("vulnerabilities", pid, "COALESCE(mark,'') = ''", nil, "id", 500, 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if len(vulns) == 0 {
		c.JSON(200, gin.H{"started": true, "count": 0, "note": "无未标记漏洞"})
		return
	}
	count := len(vulns)
	go func() {
		for _, v := range vulns {
			id, _ := v["id"].(int64)
			v2, err := api.store.GetVulnerability(id)
			if err != nil {
				continue
			}
			verdict, err := ai.Analyze(cfg, ai.VulnContext{
				VulnID: v2.VulnID, Name: v2.Name, Severity: v2.Severity, Description: v2.Description,
				URL: v2.URL, IP: v2.IP, Port: v2.Port, Evidence: v2.Evidence,
				Request: v2.Request, Response: v2.Response,
			})
			if err != nil {
				continue
			}
			api.store.SetVulnMark(id, verdict.Mark)
		}
		api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "ai_analyze_all",
			Object: fmt.Sprintf("project=%d count=%d", pid, count), ClientIP: c.ClientIP(), Result: "done"})
	}()
	c.JSON(200, gin.H{"started": true, "count": count})
}

// aiListModels 获取 AI 可用模型列表
func (api *API) aiListModels(c *gin.Context) {
	var req struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	// 如果没传，从已保存的配置读取
	cfg := ai.DefaultConfig()
	if saved, _ := api.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	if req.BaseURL != "" {
		cfg.BaseURL = req.BaseURL
	}
	if req.APIKey != "" && !strings.Contains(req.APIKey, "****") {
		cfg.APIKey = req.APIKey
	}
	models, err := ai.ListModels(cfg)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"models": models})
}

// aiAnalyzeVuln AI 研判漏洞
func (api *API) aiAnalyzeVuln(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := api.store.GetVulnerability(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "漏洞不存在"})
		return
	}
	cfg := ai.DefaultConfig()
	if saved, _ := api.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	verdict, err := ai.Analyze(cfg, ai.VulnContext{
		VulnID: v.VulnID, Name: v.Name, Severity: v.Severity, Description: v.Description,
		URL: v.URL, IP: v.IP, Port: v.Port, Service: v.Service,
		Evidence: v.Evidence, Request: v.Request, Response: v.Response,
	})
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	// 自动写入 AI 标记
	if err := api.store.SetVulnMark(id, verdict.Mark); err != nil {
		c.JSON(500, gin.H{"error": "标记写入失败: " + err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "ai_analyze",
		Object:   fmt.Sprintf("vuln#%d=%s(confidence=%s)", id, verdict.Mark, verdict.Confidence),
		ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, verdict)
}

// clearVulns 清空当前项目全部漏洞
func (api *API) clearVulns(c *gin.Context) {
	pid, err := strconv.ParseInt(c.Query("project_id"), 10, 64)
	if err != nil || pid <= 0 {
		c.JSON(400, gin.H{"error": "缺少 project_id"})
		return
	}
	n, err := api.store.ClearVulnerabilities(pid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "clear_vulnerabilities",
		Object: fmt.Sprintf("project=%d", pid), ClientIP: c.ClientIP(), Result: fmt.Sprintf("deleted=%d", n)})
	c.JSON(200, gin.H{"ok": true, "deleted": n})
}

// deleteVuln 删除漏洞
func (api *API) deleteVuln(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if _, err := api.store.GetVulnerability(id); err != nil {
		c.JSON(404, gin.H{"error": "漏洞不存在"})
		return
	}
	if err := api.store.DeleteVulnerability(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "delete_vuln",
		Object: fmt.Sprintf("vuln#%d", id), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

// markVuln 标记漏洞状态（实报/误报/忽略/取消标记）
func (api *API) markVuln(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Mark string `json:"mark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := api.store.SetVulnMark(id, req.Mark); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "mark_vuln",
		Object: fmt.Sprintf("vuln#%d=%s", id, req.Mark), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true, "mark": req.Mark})
}

// getVulnDetail 漏洞详情（含请求/响应报文）
func (api *API) getVulnDetail(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	v, err := api.store.GetVulnerability(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "漏洞不存在"})
		return
	}
	c.JSON(200, v)
}

func (api *API) listServices(c *gin.Context) {
	api.listTable(c, "asset_ports", "service, ip, port")
}

// IPDetail IP 资产画像 / 关联视图（需求文档 十八、十九节）
func (api *API) ipDetail(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	detail, err := api.store.IPDetail(pid, c.Param("ip"))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, detail)
}

// ---------- 任务 ----------

func (api *API) createTask(c *gin.Context) {
	var t model.ScanTask
	if err := c.ShouldBindJSON(&t); err != nil || t.ProjectID <= 0 || strings.TrimSpace(t.Targets) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 project_id 与 targets"})
		return
	}
	if _, err := api.store.GetProject(t.ProjectID); err != nil {
		c.JSON(404, gin.H{"error": "项目不存在"})
		return
	}
	if t.Mode == "" {
		t.Mode = "standard"
	}
	if !map[string]bool{"quick": true, "standard": true, "deep": true}[t.Mode] {
		c.JSON(400, gin.H{"error": "mode 必须为 quick/standard/deep"})
		return
	}
	if t.Concurrency <= 0 || t.Concurrency > 256 {
		t.Concurrency = 8
	}
	if t.TimeoutSec <= 0 {
		t.TimeoutSec = api.cfg.Scan.TimeoutSeconds
	}
	if t.Priority <= 0 {
		t.Priority = 5
	}
	if t.ScanInterval != "" && engine.ParseInterval(t.ScanInterval) == 0 {
		c.JSON(400, gin.H{"error": "scan_interval 须为 8h / 24h / 1w 或自定义小时 Nh（如 6h），或留空"})
		return
	}
	t.CreatedBy = c.GetString("username")
	id, err := api.store.CreateTask(&t)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "create_task", Object: fmt.Sprintf("task=%d project=%d", id, t.ProjectID), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"id": id, "status": "pending"})
}

func (api *API) listTasks(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	limit, offset := page(c)
	where := ""
	args := []any{}
	if s := c.Query("status"); s != "" {
		where, args = "status=?", append(args, s)
	}
	if c.Query("recurring") == "true" {
		if where != "" {
			where += " AND "
		}
		where += "coalesce(scan_interval,'') != ''"
	}
	total, _ := api.store.Count("scan_tasks", pid, where, args)
	rows, err := api.store.QueryPage("scan_tasks", pid, where, args, "id DESC", limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	// 周期任务补充下次执行时间
	if c.Query("recurring") == "true" {
		for _, r := range rows {
			next := ""
			if iv, _ := r["scan_interval"].(string); iv != "" && r["status"] == "done" {
				var base time.Time
				switch v := r["ended_at"].(type) {
				case time.Time:
					base = v
				default:
					ended := fmt.Sprint(v)
					for _, layout := range []string{time.RFC3339Nano, time.RFC3339,
						"2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999-07:00",
						"2006-01-02 15:04:05"} {
						if t, err := time.Parse(layout, ended); err == nil {
							base = t
							break
						}
					}
				}
				if !base.IsZero() {
					next = base.Add(engine.ParseInterval(iv)).Format("2006-01-02 15:04:05")
				}
			}
			r["next_run"] = next
		}
	}
	c.JSON(200, gin.H{"total": total, "items": rows})
}

// deleteTask 删除任务（运行中先终止；连带任务日志）
func (api *API) deleteTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	t, err := api.store.GetTask(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "任务不存在"})
		return
	}
	if t.Status == "running" || t.Status == "pending" || t.Status == "paused" {
		api.engine.Cancel(id)
		time.Sleep(300 * time.Millisecond) // 留出终止传播时间
	}
	if err := api.store.DeleteTask(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "delete_task", Object: fmt.Sprintf("task=%d", id), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

// clearAssets 清空当前项目指定类型的全部资产
func (api *API) clearAssets(c *gin.Context) {
	typ := c.Param("type")
	pid, err := strconv.ParseInt(c.Query("project_id"), 10, 64)
	if err != nil || pid <= 0 {
		c.JSON(400, gin.H{"error": "缺少 project_id"})
		return
	}
	n, err := api.store.ClearAssets(pid, typ)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "clear_assets",
		Object: fmt.Sprintf("%s project=%d", typ, pid), ClientIP: c.ClientIP(), Result: fmt.Sprintf("deleted=%d", n)})
	c.JSON(200, gin.H{"ok": true, "deleted": n})
}

// deleteAsset 删除资产（type: ip/domain/port/web/url）
func (api *API) deleteAsset(c *gin.Context) {
	typ := c.Param("type")
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	pid, _ := strconv.ParseInt(c.Query("project_id"), 10, 64)
	tableMap := map[string]string{"ip": "asset_ips", "domain": "asset_domains", "port": "asset_ports", "web": "asset_web", "url": "asset_urls"}
	tbl, ok := tableMap[typ]
	if !ok || id <= 0 || pid <= 0 {
		c.JSON(400, gin.H{"error": "参数错误：需要合法 type、id 与 project_id"})
		return
	}
	res, err := api.store.Exec(`DELETE FROM `+tbl+` WHERE id=? AND project_id=?`, id, pid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "资产不存在"})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "delete_asset", Object: fmt.Sprintf("%s#%d", typ, id), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

// getWhitelist 资产白名单（不对白名单内资产执行漏洞扫描动作）
func (api *API) getWhitelist(c *gin.Context) {
	var w engine.WhitelistEntries
	if saved, _ := api.store.GetSetting("scan_whitelist"); saved != "" {
		json.Unmarshal([]byte(saved), &w)
	}
	c.JSON(200, w)
}

func (api *API) setWhitelist(c *gin.Context) {
	var w engine.WhitelistEntries
	if err := c.ShouldBindJSON(&w); err != nil {
		c.JSON(400, gin.H{"error": "参数错误：{items:[...]}，每项为 IP / CIDR / 域名"})
		return
	}
	// 规范化与校验
	clean := []string{}
	for _, it := range w.Items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if strings.Contains(it, "/") {
			if _, _, err := net.ParseCIDR(it); err != nil {
				c.JSON(400, gin.H{"error": "非法 CIDR: " + it})
				return
			}
		} else if net.ParseIP(it) == nil && !strings.Contains(it, ".") {
			c.JSON(400, gin.H{"error": "非法条目(需 IP/CIDR/域名): " + it})
			return
		}
		clean = append(clean, it)
	}
	w.Items = clean
	data, _ := json.Marshal(w)
	if err := api.store.SetSetting("scan_whitelist", string(data)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "set_whitelist", Object: fmt.Sprintf("%d 项", len(clean)), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, w)
}

// runTask 立即执行/重新执行任务
func (api *API) runTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	t, err := api.store.GetTask(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "任务不存在"})
		return
	}
	if t.Status == "running" || t.Status == "pending" {
		c.JSON(400, gin.H{"error": "任务已在执行队列中"})
		return
	}
	if t.Status == "paused" {
		c.JSON(400, gin.H{"error": "任务处于暂停状态，请先恢复或终止"})
		return
	}
	if err := api.store.RequeueTask(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (api *API) getTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	t, err := api.store.GetTask(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "任务不存在"})
		return
	}
	c.JSON(200, t)
}

func (api *API) taskLogs(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	logs, err := api.store.TaskLogs(id, 200)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, logs)
}

func (api *API) pauseTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := api.engine.Pause(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (api *API) resumeTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := api.engine.Resume(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (api *API) cancelTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := api.engine.Cancel(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// ---------- 统计 / 搜索 / 变化 / 报告 ----------

func (api *API) stats(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	stats, err := api.store.ProjectStats(pid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, stats)
}

func (api *API) search(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	kw := strings.TrimSpace(c.Query("q"))
	if kw == "" {
		c.JSON(400, gin.H{"error": "缺少 q"})
		return
	}
	results, err := api.store.Search(pid, kw)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, results)
}

func (api *API) changes(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	limit, _ := page(c)
	rows, err := api.store.ListChanges(pid, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, rows)
}

func (api *API) reports(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	stats, _ := api.store.ProjectStats(pid)
	// 高风险资产 Top
	highRisk, _ := api.store.QueryPage("asset_ips", pid, "risk_score > 0", nil, "risk_score DESC", 20, 0)
	vulns, _ := api.store.QueryPage("vulnerabilities", pid, "", nil,
		"CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END", 500, 0)
	c.JSON(200, gin.H{
		"generated_at":    time.Now().Format(time.RFC3339),
		"stats":           stats,
		"high_risk_ips":   highRisk,
		"vulnerabilities": vulns,
	})
}

// export CSV / JSON 导出（需求文档 27、36 节）
func (api *API) export(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	table := c.DefaultQuery("type", "vulnerabilities")
	tableMap := map[string]string{
		"ips": "asset_ips", "domains": "asset_domains", "ports": "asset_ports",
		"webs": "asset_web", "urls": "asset_urls", "vulnerabilities": "vulnerabilities",
	}
	t, okT := tableMap[table]
	if !okT {
		c.JSON(400, gin.H{"error": "type 必须为 ips/domains/ports/webs/urls/vulnerabilities"})
		return
	}
	rows, err := api.store.QueryPage(t, pid, "", nil, "id", 100000, 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	format := c.DefaultQuery("format", "json")
	name := table + "_" + time.Now().Format("20060102_150405")
	if format == "csv" {
		c.Header("Content-Disposition", "attachment; filename="+name+".csv")
		c.Status(200)
		w := csv.NewWriter(c.Writer)
		if len(rows) > 0 {
			header := []string{}
			for k := range rows[0] {
				header = append(header, k)
			}
			w.Write(header)
			for _, r := range rows {
				line := []string{}
				for _, k := range header {
					line = append(line, fmt.Sprint(r[k]))
				}
				w.Write(line)
			}
		}
		w.Flush()
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+name+".json")
	c.JSON(200, rows)
}

// ---------- 系统 ----------

func (api *API) plugins(c *gin.Context) {
	c.JSON(200, plugins.ListPlugins())
}

func (api *API) systemLogs(c *gin.Context) {
	logs, err := api.store.ListSystemLogs(200)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, logs)
}

// ---------- 代理配置（界面设置） ----------

// getProxy 返回当前生效的代理配置
func (api *API) getProxy(c *gin.Context) {
	c.JSON(200, gin.H{"proxy": netproxy.Current(), "status": netproxy.Describe()})
}

// setProxy 运行时更新全局代理：校验 → 生效（立即对扫描流量生效）→ 持久化到 DB（重启后仍生效）
func (api *API) setProxy(c *gin.Context) {
	var p config.Proxy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := netproxy.Configure(p); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	data, _ := json.Marshal(p)
	if err := api.store.SetSetting("proxy", string(data)); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	// 同步写回配置文件（重启后 config.yaml 即为最新）
	api.writeProxyToConfig(p)
	api.store.SystemLog(model.SystemLog{
		Username: c.GetString("username"), Action: "set_proxy",
		Object: netproxy.Describe(), ClientIP: c.ClientIP(), Result: "success",
	})
	c.JSON(200, gin.H{"proxy": p, "status": netproxy.Describe()})
}

// writeProxyToConfig 将代理配置写回 config.yaml 的 proxy 段
func (api *API) writeProxyToConfig(p config.Proxy) {
	if api.configPath == "" {
		return
	}
	data, err := os.ReadFile(api.configPath)
	if err != nil {
		return
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return
	}
	if m == nil {
		m = map[string]any{}
	}
	pm := map[string]any{
		"enable":   p.Enable,
		"type":     p.Type,
		"host":     p.Host,
		"port":     p.Port,
		"username": p.Username,
		"password": p.Password,
	}
	m["proxy"] = pm
	out, err := yaml.Marshal(m)
	if err != nil {
		return
	}
	if err := os.WriteFile(api.configPath, out, 0o644); err == nil {
		log.Printf("[配置] 代理设置已写回 %s", api.configPath)
	}
}

// ---------- 空间测绘数据源配置 ----------

func (api *API) getMapping(c *gin.Context) {
	c.JSON(200, gin.H{"mapping": mapper.Current(), "status": mapper.Describe()})
}

func (api *API) setMapping(c *gin.Context) {
	var m mapper.Config
	if err := c.ShouldBindJSON(&m); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	mapper.Configure(m)
	data, _ := json.Marshal(m)
	if err := api.store.SetSetting("mapping", string(data)); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{
		Username: c.GetString("username"), Action: "set_mapping",
		Object: mapper.Describe(), ClientIP: c.ClientIP(), Result: "success",
	})
	c.JSON(200, gin.H{"mapping": mapper.Current(), "status": mapper.Describe()})
}

// testMapping 用表单配置（未保存也可）对目标做一次测绘测试
func (api *API) testMapping(c *gin.Context) {
	var req struct {
		Mapping mapper.Config `json:"mapping"`
		Target  string        `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Target == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 target"})
		return
	}
	if req.Mapping.Size == 0 {
		req.Mapping.Size = 100
	}
	recs, errs := mapper.QueryAllWith(req.Mapping, req.Target)
	returned := recs
	if len(returned) > 20 {
		returned = returned[:20]
	}
	c.JSON(200, gin.H{
		"ok": len(errs) == 0 || len(recs) > 0, "target": req.Target,
		"total": len(recs), "results": returned, "errors": errs,
	})
}

// mappingQuery 即时测绘并导入项目：IP/域名 → 测绘数据源 → 资产库
func (api *API) mappingQuery(c *gin.Context) {
	var req struct {
		ProjectID int64  `json:"project_id"`
		Target    string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ProjectID <= 0 || strings.TrimSpace(req.Target) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 project_id 与 target"})
		return
	}
	if _, err := api.store.GetProject(req.ProjectID); err != nil {
		c.JSON(404, gin.H{"error": "项目不存在"})
		return
	}
	recs, errs := mapper.QueryAll(strings.TrimSpace(req.Target))
	if len(recs) == 0 && len(errs) > 0 {
		msgs := []string{}
		for k, v := range errs {
			msgs = append(msgs, k+": "+v)
		}
		c.JSON(502, gin.H{"error": "测绘查询失败", "detail": msgs})
		return
	}
	// 存活探测后再入库
	alive, dead := mapper.VerifyAlive(recs, 4, 32)
	nip, nd, np, nw := mapper.Import(api.store, req.ProjectID, 0, alive)
	api.store.SystemLog(model.SystemLog{
		Username: c.GetString("username"), Action: "mapping_query",
		Object: req.Target, ClientIP: c.ClientIP(), Result: fmt.Sprint(len(recs), " records"),
	})
	c.JSON(200, gin.H{
		"target": req.Target, "total": len(recs),
		"verified_alive": len(alive), "dropped_dead": dead,
		"new_ips": nip, "new_domains": nd, "new_ports": np, "new_webs": nw,
		"sample": headN(alive, 10), "errors": errs,
	})
}

// ---------- 漏洞规则库 ----------

// importVulnRules 从服务器目录递归导入 .yml/.yaml 规则（nuclei/xray/afrog 自动识别）
func (api *API) importVulnRules(c *gin.Context) {
	var req struct {
		Path string `json:"path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Path) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 path（服务器上的规则目录）"})
		return
	}
	res, err := vulnrule.ImportDir(strings.TrimSpace(req.Path), api.store.UpsertVulnRule)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{
		Username: c.GetString("username"), Action: "import_vuln_rules",
		Object: req.Path, ClientIP: c.ClientIP(),
		Result: fmt.Sprintf("new=%d update=%d unsupported=%d", res.Imported, res.Updated, res.Unsupported),
	})
	c.JSON(200, res)
}

func (api *API) listVulnRules(c *gin.Context) {
	limit, offset := page(c)
	where := ""
	args := []any{}
	conds := []string{}
	if v := c.Query("source"); v != "" {
		conds = append(conds, "source=?")
		args = append(args, v)
	}
	if v := c.Query("severity"); v != "" {
		conds = append(conds, "severity=?")
		args = append(args, v)
	}
	if v := c.Query("enabled"); v != "" {
		conds = append(conds, "enabled=?")
		args = append(args, btoi(v == "true" || v == "1"))
	}
	if v := c.Query("supported"); v != "" {
		conds = append(conds, "supported=?")
		args = append(args, btoi(v == "true" || v == "1"))
	}
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		conds = append(conds, "(rule_id LIKE ? OR name LIKE ? OR tags LIKE ?)")
		args = append(args, "%"+q+"%", "%"+q+"%", "%"+q+"%")
	}
	if len(conds) > 0 {
		where = strings.Join(conds, " AND ")
	}
	rows, total, err := api.store.ListVulnRules(where, args,
		"CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id DESC", limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"total": total, "items": rows})
}

func (api *API) vulnRuleStats(c *gin.Context) {
	c.JSON(200, api.store.VulnRuleStats())
}

func (api *API) getVulnRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	r, err := api.store.GetVulnRule(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	c.JSON(200, r)
}

func (api *API) toggleVulnRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := api.store.SetVulnRuleEnabled(id, req.Enabled); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// clearVulnRules 清空整个规则库
func (api *API) clearVulnRules(c *gin.Context) {
	n, err := api.store.ClearVulnRules()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "clear_vuln_rules",
		Object: fmt.Sprintf("%d rules", n), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true, "deleted": n})
}

func (api *API) deleteVulnRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := api.store.DeleteVulnRule(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// testVulnRule 用单条规则对目标 URL 试探
func (api *API) testVulnRule(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Target == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 target URL"})
		return
	}
	r, err := api.store.GetVulnRule(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "规则不存在"})
		return
	}
	res := vulnrule.Run(r, req.Target, 10)
	c.JSON(200, res)
}

// ---------- WIH JS 敏感信息检测（Web Info Hunter，规则集源自 ifacker/WIHscan / MIT） ----------

const wihSettingsKey = "wih_settings"

// loadWih 从设置读取 WIH 配置（无保存时返回默认规则集）
func (api *API) loadWih() wih.Settings {
	if saved, _ := api.store.GetSetting(wihSettingsKey); saved != "" {
		var st wih.Settings
		if json.Unmarshal([]byte(saved), &st) == nil && len(st.Rules) > 0 {
			st.Normalize()
			return st
		}
	}
	return wih.DefaultSettings()
}

func (api *API) getWihSettings(c *gin.Context) {
	c.JSON(200, api.loadWih())
}

func (api *API) setWihSettings(c *gin.Context) {
	var st wih.Settings
	if err := c.ShouldBindJSON(&st); err != nil {
		c.JSON(400, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	st.Normalize()
	data, _ := json.Marshal(st)
	if err := api.store.SetSetting(wihSettingsKey, string(data)); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	wih.SetCurrent(st) // 即时生效（引擎插件读取全局当前设置）
	c.JSON(200, st)
}

// testWihScan 对指定 URL（页面或 JS）即时执行当前启用规则（对应 WIHscan 的 -u 模式）
func (api *API) testWihScan(c *gin.Context) {
	var req struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Target) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 target URL"})
		return
	}
	target := strings.TrimSpace(req.Target)
	st := wih.Current()
	hits, err := wih.ScanURL(st.Rules, target, 10)
	if err != nil {
		c.JSON(502, gin.H{"error": "抓取失败: " + err.Error()})
		return
	}
	out := make([]wih.Hit, 0, len(hits))
	for _, h := range hits {
		if !st.Excluded(h, target) {
			out = append(out, h)
		}
	}
	c.JSON(200, gin.H{"target": target, "hits": out})
}

// ---------- 模板源管理与在线更新 ----------

const ruleSourcesSettingKey = "rule_sources"

func (api *API) loadSourceCfg() vulnrule.SourceConfig {
	cfg := vulnrule.DefaultSourceConfig()
	if saved, _ := api.store.GetSetting(ruleSourcesSettingKey); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	cfg.Normalize()
	return cfg
}

func (api *API) saveSourceCfg(cfg vulnrule.SourceConfig) {
	data, _ := json.Marshal(cfg)
	api.store.SetSetting(ruleSourcesSettingKey, string(data))
}

func (api *API) getRuleSources(c *gin.Context) {
	cfg := api.loadSourceCfg()
	c.JSON(200, gin.H{"config": cfg, "updating": vulnrule.Updating(), "log": vulnrule.UpdateLog()})
}

func (api *API) setRuleSources(c *gin.Context) {
	var req vulnrule.SourceConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	old := api.loadSourceCfg()
	req.Normalize()
	req.AutoTime = vulnrule.NormalizeAutoTime(req.AutoTime)
	// 源地址与镜像前缀将进入 git 命令参数，仅允许 http/https，防参数注入
	for _, s := range req.Sources {
		if s.URL != "" && !vulnrule.ValidGitURL(s.URL) {
			c.JSON(400, gin.H{"error": "非法源地址（仅允许 http/https）: " + s.URL})
			return
		}
	}
	if req.Mirror != "" && !vulnrule.ValidGitURL(req.Mirror) {
		c.JSON(400, gin.H{"error": "非法镜像前缀（仅允许 http/https）: " + req.Mirror})
		return
	}
	// 允许空源列表（用户清空全部源）
	// 保留已有源的状态字段
	for i := range req.Sources {
		for _, o := range old.Sources {
			if o.URL == req.Sources[i].URL {
				req.Sources[i].LastUpdate = o.LastUpdate
				req.Sources[i].LastResult = o.LastResult
				req.Sources[i].RuleCount = o.RuleCount
			}
		}
	}
	req.LastRun = old.LastRun
	api.saveSourceCfg(req)
	c.JSON(200, gin.H{"config": req})
}

// updateRuleSources 触发后台更新（clone/pull + 导入），前端轮询 GET sources 获取进度
// 克隆默认存放在 POC 仓库的 nuclei 类型目录：data/poc/nuclei/owner/repo
func (api *API) updateRuleSources(c *gin.Context) {
	root := filepath.Join(filepath.Dir(api.cfg.Database.Path), vulnrule.CloneSubDir)
	started := vulnrule.StartUpdate(root, api.store.UpsertVulnRule, func(src vulnrule.Source) {
		cfg := api.loadSourceCfg()
		for i := range cfg.Sources {
			if cfg.Sources[i].URL == src.URL {
				cfg.Sources[i].LastUpdate = src.LastUpdate
				cfg.Sources[i].LastResult = src.LastResult
			}
		}
		cfg.LastRun = time.Now().Format(time.RFC3339)
		api.saveSourceCfg(cfg)
	})
	if !started {
		c.JSON(409, gin.H{"error": "已有更新任务在进行中"})
		return
	}
	api.store.SystemLog(model.SystemLog{
		Username: c.GetString("username"), Action: "update_rule_sources",
		ClientIP: c.ClientIP(), Result: "started",
	})
	c.JSON(200, gin.H{"started": true})
}

// ---------- POC 目录监控 ----------

func (api *API) getWatcher(c *gin.Context) {
	c.JSON(200, vulnrule.WatcherState())
}

func (api *API) setWatcher(c *gin.Context) {
	var wc vulnrule.WatcherConfig
	if err := c.ShouldBindJSON(&wc); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	vulnrule.ConfigureWatcher(wc)
	data, _ := json.Marshal(wc)
	if err := api.store.SetSetting("poc_watcher", string(data)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, vulnrule.WatcherState())
}

// ---------- 漏洞规则扫描设置 ----------

func (api *API) getVulnRuleSettings(c *gin.Context) {
	st := vulnrule.DefaultSettings()
	if saved, _ := api.store.GetSetting("vuln_rule_settings"); saved != "" {
		json.Unmarshal([]byte(saved), &st)
	}
	if st.MaxPerTarget < 0 || st.MaxPerTarget > 100000 {
		st.MaxPerTarget = 0
	}
	c.JSON(200, st)
}

func (api *API) setVulnRuleSettings(c *gin.Context) {
	var st vulnrule.Settings
	if err := c.ShouldBindJSON(&st); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if st.MaxPerTarget < 0 || st.MaxPerTarget > 100000 {
		st.MaxPerTarget = 0 // 0 = 加载全部规则
	}
	data, _ := json.Marshal(st)
	if err := api.store.SetSetting("vuln_rule_settings", string(data)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, st)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func headN(recs []mapper.Record, n int) []mapper.Record {
	if len(recs) > n {
		return recs[:n]
	}
	return recs
}

// testProxy 经当前表单代理配置测试连通性（未保存也可测试）
func (api *API) testProxy(c *gin.Context) {
	var req struct {
		Proxy  config.Proxy `json:"proxy"`
		Target string       `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	// 临时应用表单配置进行测试，结束后恢复
	prev := netproxy.Current()
	if err := netproxy.Configure(req.Proxy); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	latency, err := netproxy.Test(req.Target, 8*time.Second)
	netproxy.Configure(prev)
	if err != nil {
		c.JSON(200, gin.H{"ok": false, "error": err.Error(), "target": req.Target})
		return
	}
	c.JSON(200, gin.H{"ok": true, "latency_ms": latency, "target": req.Target, "via": netproxy.DescribeOf(req.Proxy)})
}

var _ = http.StatusOK
var _ = json.Marshal
