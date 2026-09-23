// Package api REST API 层（需求文档 第二十八节）
package api

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cysec/internal/ai"
	"cysec/internal/auth"
	"cysec/internal/config"
	"cysec/internal/engine"
	"cysec/internal/events"
	"cysec/internal/mapper"
	"cysec/internal/model"
	"cysec/internal/netproxy"
	"cysec/internal/plugins"
	"cysec/internal/store"
	"cysec/internal/subdomain"
	"cysec/internal/weakness"
	"cysec/plugins/builtin"
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
	// 安全响应头：nosniff 防 MIME 嗅探、DENY/no-referrer 防点击劫持与引用泄漏，
	// CSP 将脚本/连接收敛到同源（前端为纯外链资源的 SPA，SSE 亦为同源）；
	// 同时给请求体封顶（默认无限），防超大 JSON/YAML 解析拖垮服务
	r.Use(func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<20)
		c.Next()
	})

	r.POST("/api/login", api.login)
	r.GET("/api/health", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })

	authed := r.Group("/api")
	authed.Use(a.Middleware())

	// SSE 实时事件流（EventSource 无法带 Authorization 头，走 ?token= 认证）：
	// 引擎写路径发布 assets/vulns/weaknesses/tasks 主题，前端事件驱动刷新
	authed.GET("/events", api.sseEvents)

	// 项目
	authed.POST("/projects", a.Middleware("admin"), api.createProject)
	authed.GET("/projects", api.listProjects)
	authed.DELETE("/projects/:id", a.Middleware("admin"), api.deleteProject)

	// 资产导入（IP/Domain/URL，自动去重）
	authed.POST("/assets", a.Middleware("admin", "auditor"), api.importAssets)
	authed.GET("/assets", api.listAssets)
	// 证书透明度即时收集（只读，不入库；导入复用 POST /api/assets type=domain）
	authed.GET("/subdomains/ct", api.ctCollect)
	authed.GET("/fp-assets", api.getFPAssets)
	authed.PUT("/fp-assets", a.Middleware("admin", "auditor"), api.setFPAssets)
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
	authed.PUT("/tasks/:id", a.Middleware("admin", "auditor"), api.updateTask)
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
	authed.DELETE("/system/logs", a.Middleware("admin"), api.clearSystemLogs)
	authed.GET("/system/proxy", api.getProxy)
	authed.PUT("/system/proxy", a.Middleware("admin"), api.setProxy)
	authed.GET("/system/proxy-health", api.getProxyHealth)
	authed.PUT("/system/proxy-health", a.Middleware("admin"), api.setProxyHealth)
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
	authed.GET("/system/leak-paths", api.getLeakPaths)
	authed.PUT("/system/leak-paths", a.Middleware("admin"), api.setLeakPaths)
	authed.GET("/weaknesses", api.listWeaknesses)
	authed.DELETE("/weaknesses/:id", a.Middleware("admin", "auditor"), api.deleteWeakness)
	authed.DELETE("/weaknesses", a.Middleware("admin", "auditor"), api.clearWeaknesses)
	authed.GET("/weakness/settings", api.getWeaknessSettings)
	authed.PUT("/weakness/settings", a.Middleware("admin"), api.setWeaknessSettings)
	authed.PUT("/weakness/senssub", a.Middleware("admin"), api.setSensSub)
	authed.POST("/weakness/senssub/update", a.Middleware("admin", "auditor"), api.updateSensSub)
	authed.POST("/weakness/senssub/discover", a.Middleware("admin", "auditor"), api.discoverSensSub)
	authed.GET("/weakness/senssub/words", api.sensSubWords)
	authed.POST("/weakness/senssub/words", a.Middleware("admin", "auditor"), api.sensSubWordsAdd)
	authed.DELETE("/weakness/senssub/words", a.Middleware("admin", "auditor"), api.sensSubWordsDel)
	authed.POST("/weakness/senssub/words/clear", a.Middleware("admin"), api.sensSubWordsClear)
	authed.GET("/weakness/senssub/excludes", api.sensSubExcludes)
	authed.POST("/weakness/senssub/excludes/restore", a.Middleware("admin", "auditor"), api.sensSubExcludesRestore)
	authed.GET("/system/domain-consistency", api.getDomainConsistency)
	authed.PUT("/system/domain-consistency", a.Middleware("admin"), api.setDomainConsistency)
	authed.POST("/system/domain-consistency/cleanup", a.Middleware("admin"), api.cleanupDomains)
	authed.PUT("/weaknesses/:id/mark", a.Middleware("admin", "auditor"), api.markWeakness)
	authed.POST("/weaknesses/:id/ai-analyze", a.Middleware("admin", "auditor"), api.aiAnalyzeWeakness)
	authed.POST("/weaknesses/ai-analyze-all", a.Middleware("admin", "auditor"), api.aiAnalyzeAllWeakness)
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
	authed.POST("/auth/password", api.changePassword)

	return r
}

func (api *API) login(c *gin.Context) {
	var req struct{ Username, Password string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}
	token, err := api.auth.Login(c.ClientIP(), req.Username, req.Password)
	if err != nil {
		if err == auth.ErrRateLimited {
			api.store.SystemLog(model.SystemLog{Username: req.Username, Action: "login", ClientIP: c.ClientIP(), Result: "rate_limited"})
			c.JSON(429, gin.H{"error": "登录尝试过于频繁，请稍后再试"})
			return
		}
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

// changePassword 当前登录用户修改自己的密码（需验证旧密码，成功后吊销其他会话）
func (api *API) changePassword(c *gin.Context) {
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}
	if len(req.NewPassword) < 6 {
		c.JSON(400, gin.H{"error": "新密码至少 6 位"})
		return
	}
	if len(req.NewPassword) > 72 {
		c.JSON(400, gin.H{"error": "新密码过长（最多 72 位）"})
		return
	}
	username := c.GetString("username")
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	if err := api.auth.ChangePassword(username, req.OldPassword, req.NewPassword, token); err != nil {
		if errors.Is(err, auth.ErrUnauthorized) {
			api.store.SystemLog(model.SystemLog{Username: username, Action: "change_password", ClientIP: c.ClientIP(), Result: "failed"})
			c.JSON(400, gin.H{"error": "旧密码不正确"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: username, Action: "change_password", ClientIP: c.ClientIP(), Result: "success"})
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
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "create_project", Object: p.Name, ClientIP: c.ClientIP(), Result: fmt.Sprintf("created id=%d", id)})
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
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "delete_project", Object: fmt.Sprint(p["name"]), ClientIP: c.ClientIP(), Result: "started"})
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

// ctCollect 证书透明度即时收集：?domain=根域名，返回 CT 日志中的历史子域
// （crt.name 主源、crt.sh 备用，均失败时 source 为空）。只读查询，导入走 POST /api/assets。
func (api *API) ctCollect(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	if domain == "" || !strings.Contains(domain, ".") || strings.ContainsAny(domain, " /\\") {
		c.JSON(400, gin.H{"error": "参数错误: 需要有效的根域名（如 example.com）"})
		return
	}
	r := subdomain.CertQueryVerbose(domain, 20)
	c.JSON(200, gin.H{"items": r.Items, "total": len(r.Items), "source": r.Source})
}

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
	var newIPs, newDomains, newURLs, failed int
	for _, ip := range ips {
		isNew, err := api.store.UpsertIP(model.AssetIP{ProjectID: req.ProjectID, IP: ip, Network: engine.IsPrivateIP(ip), Source: "import"})
		if err != nil {
			failed++
			continue
		}
		if isNew {
			newIPs++
		}
	}
	for _, d := range domains {
		isNew, err := api.store.UpsertDomain(model.AssetDomain{ProjectID: req.ProjectID, Domain: d, Source: "import"})
		if err != nil {
			failed++
			continue
		}
		if isNew {
			newDomains++
		}
	}
	for _, u := range urls {
		isNew, err := api.store.UpsertURL(model.AssetURL{ProjectID: req.ProjectID, URL: u, Method: "GET", Source: "import"})
		if err != nil {
			failed++
			continue
		}
		// 新导入的 URL 交实时漏洞扫描器：探测建 Web 资产 + 风险检测 + 规则库
		if isNew {
			newURLs++
			api.engine.SubmitAutoScan(req.ProjectID, u)
		}
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "import_assets", Object: fmt.Sprintf("project=%d", req.ProjectID), ClientIP: c.ClientIP(), Result: "success"})
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "import_assets", Object: req.Type, ClientIP: c.ClientIP(), Result: fmt.Sprintf("ips=%d domains=%d urls=%d", len(ips), len(domains), len(urls))})
	c.JSON(200, gin.H{
		"ips": len(ips), "domains": len(domains), "urls": len(urls),
		"new_ips": newIPs, "new_domains": newDomains, "new_urls": newURLs, "failed": failed,
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
	// 脱敏返回（不返回完整 API Key；短 key 全掩码，避免明文回显）
	safe := cfg
	if len(safe.APIKey) > 8 {
		safe.APIKey = safe.APIKey[:4] + "****" + safe.APIKey[len(safe.APIKey)-4:]
	} else if safe.APIKey != "" {
		safe.APIKey = "****"
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
	// 同步写回配置文件（重启后 config.yaml 即为最新）
	api.writeAIToConfig(cfg)
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "set_ai_config",
		Object: cfg.Provider + "/" + cfg.Model, ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

// configWriteMu config.yaml 写回互斥（AI/测绘/代理等多处写回并发时防丢段）
var configWriteMu sync.Mutex

// writeMappingToConfig 将空间测绘数据源配置写回 config.yaml 的 mapping 段
func (api *API) writeMappingToConfig(m mapper.Config) {
	if api.configPath == "" {
		return
	}
	configWriteMu.Lock()
	defer configWriteMu.Unlock()
	data, err := os.ReadFile(api.configPath)
	if err != nil {
		return
	}
	var y map[string]any
	if err := yaml.Unmarshal(data, &y); err != nil {
		return
	}
	if y == nil {
		y = map[string]any{}
	}
	y["mapping"] = map[string]any{
		"enabled": m.Enabled, "size": m.Size, "interval_ms": m.IntervalMs,
		"fofa_enable": m.FOFAEnable, "fofa_key": m.FOFAKey, "fofa_base_url": m.FOFABaseURL, "fofa_interval_ms": m.FOFAIntervalMs,
		"quake_enable": m.QuakeEnable, "quake_key": m.QuakeKey, "quake_base_url": m.QuakeBaseURL, "quake_interval_ms": m.QuakeIntervalMs,
		"shodan_enable": m.ShodanEnable, "shodan_key": m.ShodanKey, "shodan_base_url": m.ShodanBaseURL, "shodan_interval_ms": m.ShodanIntervalMs,
		"zerozone_enable": m.ZeroZoneEnable, "zerozone_key_id": m.ZeroZoneKeyID, "zerozone_base_url": m.ZeroZoneBaseURL, "zerozone_interval_ms": m.ZeroZoneIntervalMs,
		"zoomeye_enable": m.ZoomEyeEnable, "zoomeye_key": m.ZoomEyeKey, "zoomeye_base_url": m.ZoomEyeBaseURL, "zoomeye_interval_ms": m.ZoomEyeIntervalMs,
	}
	out, err := yaml.Marshal(y)
	if err != nil {
		return
	}
	if err := os.WriteFile(api.configPath, out, 0o644); err == nil {
		log.Printf("[配置] 空间测绘数据源设置已写回 %s", api.configPath)
	}
}

// writeAIToConfig 将 AI 研判配置写回 config.yaml 的 ai 段
func (api *API) writeAIToConfig(cfg ai.Config) {
	if api.configPath == "" {
		return
	}
	configWriteMu.Lock()
	defer configWriteMu.Unlock()
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
	m["ai"] = map[string]any{
		"enabled":           cfg.Enabled,
		"provider":          cfg.Provider,
		"base_url":          cfg.BaseURL,
		"api_key":           cfg.APIKey,
		"model":             cfg.Model,
		"timeout_sec":       cfg.TimeoutSec,
		"auto_analyze":      cfg.AutoAnalyze,
		"auto_min_severity": cfg.AutoMinSeverity,
	}
	out, err := yaml.Marshal(m)
	if err != nil {
		return
	}
	if err := os.WriteFile(api.configPath, out, 0o644); err == nil {
		log.Printf("[配置] AI 研判设置已写回 %s", api.configPath)
	}
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
	// gin.Context 在 handler 返回后会被回收复用：进入异步 goroutine 前先捕获用户名/IP
	username, clientIP := c.GetString("username"), c.ClientIP()
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
		api.store.SystemLog(model.SystemLog{Username: username, Action: "ai_analyze_all",
			Object: fmt.Sprintf("project=%d count=%d", pid, count), ClientIP: clientIP, Result: "done"})
	}()
	c.JSON(200, gin.H{"started": true, "count": count, "note": "单次最多研判 500 条未标记漏洞"})
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
	if id <= 0 {
		c.JSON(400, gin.H{"error": "参数错误：非法 id"})
		return
	}
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
	c.JSON(200, localTimeJSON(v))
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
	if t.Phases != "" {
		// 阶段化任务：校验阶段取值（collect/vulnscan/weakness/alive），mode 仅作展示
		valid := map[string]bool{"collect": true, "portscan": true, "vulnscan": true, "weakness": true, "alive": true}
		for _, ph := range strings.Split(t.Phases, ",") {
			if !valid[ph] {
				c.JSON(400, gin.H{"error": "phases 含非法阶段: " + ph})
				return
			}
		}
		if t.Mode == "" {
			t.Mode = "custom"
		}
	} else if t.Mode == "" {
		t.Mode = "standard"
	}
	if !map[string]bool{"quick": true, "standard": true, "deep": true, "custom": true}[t.Mode] {
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
	if typ == "web" {
		// 级联删除其 URL 与指纹，避免仪表盘 URL 计数残留
		if _, err := api.store.DeleteWebCascade(pid, id); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"ok": true})
		return
	}
	// 删除 IP 资产级联其端口（与误报资产清理同口径，避免仪表盘端口计数残留）
	if typ == "ip" {
		if rows, err := api.store.QueryPage("asset_ips", pid, "id=?", []any{id}, "", 1, 0); err == nil && len(rows) > 0 {
			if ip, _ := rows[0]["ip"].(string); ip != "" {
				api.store.Exec(`DELETE FROM asset_ports WHERE project_id=? AND ip=?`, pid, ip)
			}
		}
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
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "run_task", Object: c.Param("id"), ClientIP: c.ClientIP(), Result: "restart"})
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
	// 旧执行协程仍在运行时直接重入队会被引擎防重入守卫静默丢弃（状态卡 pending），
	// 先取消并等待其退出（限时 30 秒），仍退不出则拒绝重启
	if api.engine.IsRunning(id) && !api.engine.StopAndWait(id, 30*time.Second) {
		c.JSON(409, gin.H{"error": "上一次执行仍在收尾（大批量目标收尾较慢），请稍后重试重启"})
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
	c.JSON(200, localTimeJSON(t))
}

// updateTask 编辑任务参数（仅待执行/已完成/已终止/失败状态可改；运行中与暂停中不可）
func (api *API) updateTask(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	t, err := api.store.GetTask(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "任务不存在"})
		return
	}
	switch t.Status {
	case "running", "pending", "paused":
		c.JSON(400, gin.H{"error": "任务执行中/排队中/暂停中不可编辑，请先终止或等待结束"})
		return
	}
	var req struct {
		Name           string `json:"name"`
		Targets        string `json:"targets"`
		Mode           string `json:"mode"`
		Ports          string `json:"ports"`
		Concurrency    int    `json:"concurrency"`
		TimeoutSec     int    `json:"timeout_sec"`
		Priority       int    `json:"priority"`
		ScanInterval   string `json:"scan_interval"`
		Phases         string `json:"phases"`
		SubdomainBrute *bool  `json:"subdomain_brute"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Targets) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 targets"})
		return
	}
	if req.Mode == "" {
		req.Mode = t.Mode
	}
	if !map[string]bool{"quick": true, "standard": true, "deep": true, "custom": true}[req.Mode] {
		c.JSON(400, gin.H{"error": "mode 必须为 quick/standard/deep"})
		return
	}
	if req.Phases != "" {
		for _, ph := range strings.Split(req.Phases, ",") {
			if !map[string]bool{"collect": true, "portscan": true, "vulnscan": true, "weakness": true, "alive": true}[ph] {
				c.JSON(400, gin.H{"error": "phases 含非法阶段: " + ph})
				return
			}
		}
	}
	if req.ScanInterval != "" && engine.ParseInterval(req.ScanInterval) == 0 {
		c.JSON(400, gin.H{"error": "scan_interval 须为 8h / 24h / 1w 或自定义小时 Nh（如 6h），或留空"})
		return
	}
	if req.Concurrency <= 0 || req.Concurrency > 256 {
		req.Concurrency = 8
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = api.cfg.Scan.TimeoutSeconds
	}
	if req.Priority <= 0 {
		req.Priority = t.Priority
	}
	if req.SubdomainBrute != nil {
		api.store.UpdateTask(id, map[string]any{"subdomain_brute": *req.SubdomainBrute})
	}
	if err := api.store.UpdateTask(id, map[string]any{
		"name": strings.TrimSpace(req.Name), "targets": strings.TrimSpace(req.Targets),
		"mode": req.Mode, "ports": strings.TrimSpace(req.Ports),
		"concurrency": req.Concurrency, "timeout_sec": req.TimeoutSec,
		"priority": req.Priority, "scan_interval": req.ScanInterval,
		"phases": req.Phases,
	}); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	updated, _ := api.store.GetTask(id)
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "update_task", Object: fmt.Sprintf("task=%d", id), ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, updated)
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
	limit, offset := page(c)
	rows, total, err := api.store.ListChangesPaged(pid, c.Query("q"), c.Query("type"), c.Query("change"), limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"items": rows, "total": total})
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
		"weaknesses": "weaknesses",
	}
	t, okT := tableMap[table]
	if !okT {
		c.JSON(400, gin.H{"error": "type 必须为 ips/domains/ports/webs/urls/vulnerabilities/weaknesses"})
		return
	}
	// 弱点导出尊重界面当前筛选（类型/搜索/标记），与列表口径一致
	var rows []map[string]any
	var err error
	if table == "weaknesses" {
		rows, _, err = api.store.ListWeaknessesPaged(pid, c.Query("q"), c.Query("wk"), c.Query("mark"), 100000, 0)
	} else {
		rows, err = api.store.QueryPage(t, pid, "", nil, "id", 100000, 0)
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	format := c.DefaultQuery("format", "json")
	name := table + "_" + time.Now().Format("20060102_150405")
	if format == "csv" {
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", "attachment; filename="+name+".csv")
		c.Status(200)
		// UTF-8 BOM：中文 Windows 的 Excel 对无 BOM 的 CSV 按系统 ANSI(GBK) 解析，
		// 中文全部乱码（实测无 BOM 时 GBK 解码直接报非法字节）；带 BOM 后 Excel 正确识别 UTF-8
		c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})
		w := csv.NewWriter(c.Writer)
		if len(rows) > 0 {
			// 固定列序（map 遍历随机）；按首行列名排序保证每次导出一致
			header := make([]string, 0, len(rows[0]))
			for k := range rows[0] {
				header = append(header, k)
			}
			sort.Strings(header)
			w.Write(header)
			for _, r := range rows {
				line := make([]string, 0, len(header))
				for _, k := range header {
					line = append(line, csvSanitize(fmt.Sprint(r[k])))
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

// sseEvents SSE 实时事件流：心跳 15s 保活，连接断开自动清理订阅
func (api *API) sseEvents(c *gin.Context) {
	ch, cancel := events.Subscribe()
	defer cancel()
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Stream(func(w io.Writer) bool {
		select {
		case ev := <-ch:
			c.SSEvent("message", ev)
			return true
		case <-time.After(15 * time.Second):
			c.SSEvent("ping", "keepalive")
			return true
		case <-c.Request.Context().Done():
			return false
		}
	})
}

// csvSanitize CSV 公式注入防护：扫描目标可控内容（标题/报文/证据）以 = + - @ 制表符开头时
// 加单引号前缀，避免分析师用 Excel 打开导出文件时触发公式/DDE 执行
func csvSanitize(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

// ---------- 系统 ----------

func (api *API) plugins(c *gin.Context) {
	c.JSON(200, plugins.ListPlugins())
}

func (api *API) systemLogs(c *gin.Context) {
	limit, offset := page(c)
	items, total, err := api.store.SystemLogsPaged(c.Query("q"), c.Query("type"), limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"items": items, "total": total})
}

// clearSystemLogs 清空系统日志（日志管理页，仅 admin）
func (api *API) clearSystemLogs(c *gin.Context) {
	n, err := api.store.ClearSystemLogs()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"deleted": n})
}

// ---------- 代理配置（界面设置） ----------

// getProxy 返回当前生效的代理配置（含连通性守护状态）
func (api *API) getProxy(c *gin.Context) {
	c.JSON(200, gin.H{"proxy": netproxy.Current(), "status": netproxy.Describe(), "health": netproxy.DescribeHealth()})
}

// getProxyHealth 读取代理连通性守护配置
func (api *API) getProxyHealth(c *gin.Context) {
	interval := 60
	if saved, _ := api.store.GetSetting("proxy_health_interval"); saved != "" {
		if v, err := strconv.Atoi(saved); err == nil && v > 0 {
			interval = v
		}
	}
	c.JSON(200, gin.H{"enabled": netproxy.HealthActive(), "interval_sec": interval, "state": netproxy.DescribeHealth(), "target": netproxy.HealthProbeTarget()})
}

// setProxyHealth 更新守护检测间隔与开关（开关：true=显式启用守护，false=停用守护；
// 保存代理时 enable=true 仍会自动激活，enable=false 停用——用户显式操作优先）
func (api *API) setProxyHealth(c *gin.Context) {
	var req struct {
		IntervalSec int    `json:"interval_sec"`
		Enabled     *bool  `json:"enabled"`
		Target      string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.IntervalSec > 0 && req.IntervalSec < 10 {
		c.JSON(400, gin.H{"error": "检测间隔至少 10 秒"})
		return
	}
	if req.IntervalSec > 0 {
		api.store.SetSetting("proxy_health_interval", strconv.Itoa(req.IntervalSec))
	}
	if t := strings.TrimSpace(req.Target); t != "" {
		api.store.SetSetting("proxy_health_target", t)
		netproxy.SetHealthProbeTarget(t)
	}
	if req.Enabled != nil {
		netproxy.SetHealthActive(*req.Enabled)
		if *req.Enabled {
			api.store.SetSetting("proxy_health_active", "1")
			api.store.SetSetting("proxy_health_useroff", "0") // 显式开启：恢复保存代理时自动激活
		} else {
			api.store.SetSetting("proxy_health_active", "0")
			api.store.SetSetting("proxy_health_useroff", "1") // 显式关闭：保存代理不再自动激活，直至用户重新开启
		}
		api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "proxy_health_toggle",
			ClientIP: c.ClientIP(), Result: fmt.Sprintf("enabled=%v", *req.Enabled)})
	}
	// 请求不带 interval_sec（0，不修改）时回显实际生效值，避免前端显示与配置不一致
	interval := req.IntervalSec
	if interval <= 0 {
		interval = 60
		if saved, _ := api.store.GetSetting("proxy_health_interval"); saved != "" {
			if v, err := strconv.Atoi(saved); err == nil && v > 0 {
				interval = v
			}
		}
	}
	c.JSON(200, gin.H{"enabled": netproxy.HealthActive(), "interval_sec": interval, "state": netproxy.DescribeHealth(), "target": netproxy.HealthProbeTarget()})
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
	// 连通性守护接线：保存启用的代理（host/port 完整）且未被用户显式关闭时激活；停用/清空代理则关闭守护
	userOff := false
	if flag, _ := api.store.GetSetting("proxy_health_useroff"); flag == "1" {
		userOff = true
	}
	activate := p.Enable && p.Host != "" && p.Port > 0 && !userOff
	netproxy.SetHealthActive(activate)
	if activate {
		api.store.SetSetting("proxy_health_active", "1")
	} else {
		api.store.SetSetting("proxy_health_active", "0")
	}
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
	configWriteMu.Lock()
	defer configWriteMu.Unlock()
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
	// 同步写回配置文件（重启后 config.yaml 即为最新）
	api.writeMappingToConfig(m)
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
	// 按引擎分组：计数用于界面提示（否则多引擎结果混在一起，排在后面的引擎
	// 会被前面的大结果量引擎淹没，看起来像"没有数据"）；抽样改为每引擎各取
	// 前 8 条，保证每个参与的引擎在预览表中都可见
	counts := map[string]int{}
	byProvider := map[string][]mapper.Record{}
	for _, r := range recs {
		counts[r.Provider]++
		if len(byProvider[r.Provider]) < 8 {
			byProvider[r.Provider] = append(byProvider[r.Provider], r)
		}
	}
	sample := []mapper.Record{}
	for _, p := range mapper.Providers() {
		sample = append(sample, byProvider[p.Name()]...)
	}
	if len(sample) > 20 {
		sample = sample[:20]
	}
	// 未参与的引擎（未勾选启用或未填密钥被静默跳过）单独列出，便于排查
	skipped := []string{}
	for _, p := range mapper.Providers() {
		if _, ok := counts[p.Name()]; !ok {
			if _, erred := errs[p.Name()]; !erred {
				skipped = append(skipped, p.Name())
			}
		}
	}
	c.JSON(200, gin.H{
		"ok": len(errs) == 0 || len(recs) > 0, "target": req.Target,
		"total": len(recs), "counts": counts, "skipped": skipped,
		"results": sample, "errors": errs,
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
	nip, nd, np, nw := mapper.Import(api.store, req.ProjectID, 0, alive, nil, api.store.GetFPAssets(req.ProjectID)) // 手动测绘查询不做一致性过滤（无任务域名基准），但尊重误报资产配置
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
	res, newRules, err := vulnrule.ImportDirCollect(strings.TrimSpace(req.Path), api.store.UpsertVulnRule)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// 与 POC 目录监控/模板源更新同口径：新增可执行规则 → 对存量 Web 资产补扫
	usable := []vulnrule.Rule{}
	for _, r := range newRules {
		if r.Supported {
			usable = append(usable, r)
		}
	}
	rescan := len(usable)
	if rescan > 0 {
		vulnrule.InvokeNewRulesHandler(usable)
	}
	api.store.SystemLog(model.SystemLog{
		Username: c.GetString("username"), Action: "import_vuln_rules",
		Object: req.Path, ClientIP: c.ClientIP(),
		Result: fmt.Sprintf("new=%d update=%d unsupported=%d 触发存量资产补扫规则=%d", res.Imported, res.Updated, res.Unsupported, rescan),
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

// ---------- 误报资产配置（项目级） ----------

func (api *API) getFPAssets(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	c.JSON(200, gin.H{"items": api.store.GetFPAssets(pid)})
}

func (api *API) setFPAssets(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	var req struct {
		Items []string `json:"items"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := api.store.SetFPAssets(pid, req.Items); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	// 同步清理已入库的匹配资产（IP 含端口 / 域名 / Web 含 URL 与指纹 / 独立 URL）
	dIP, dDomain, dWeb, dURL, _ := api.store.CleanupFPAssets(pid, req.Items)
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "set_fp_assets",
		Object: fmt.Sprintf("project=%d n=%d", pid, len(req.Items)), ClientIP: c.ClientIP(),
		Result: fmt.Sprintf("cleaned ips=%d domains=%d webs=%d urls=%d", dIP, dDomain, dWeb, dURL)})
	c.JSON(200, gin.H{"items": req.Items, "cleaned": gin.H{"ips": dIP, "domains": dDomain, "webs": dWeb, "urls": dURL}})
}

// ---------- 域名一致性校验 ----------

func (api *API) getDomainConsistency(c *gin.Context) {
	enabled := true
	if saved, _ := api.store.GetSetting("domain_consistency"); saved != "" {
		var cfg struct {
			Enabled bool `json:"enabled"`
		}
		if json.Unmarshal([]byte(saved), &cfg) == nil {
			enabled = cfg.Enabled
		}
	}
	c.JSON(200, gin.H{"enabled": enabled})
}

func (api *API) setDomainConsistency(c *gin.Context) {
	var cfg struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	data, _ := json.Marshal(cfg)
	if err := api.store.SetSetting("domain_consistency", string(data)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, cfg)
}

// cleanupDomains 存量一次性清理：按给定根域名删除不一致的域名资产与杂域名 Web 资产
func (api *API) cleanupDomains(c *gin.Context) {
	var req struct {
		Roots []string `json:"roots"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Roots) == 0 {
		c.JSON(400, gin.H{"error": "参数错误：需要 roots（每行一个根域名）"})
		return
	}
	nd, nw, err := api.store.CleanupInconsistentDomains(req.Roots)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "domain_cleanup",
		Object: strings.Join(req.Roots, ","), ClientIP: c.ClientIP(), Result: fmt.Sprintf("domains=%d webs=%d", nd, nw)})
	c.JSON(200, gin.H{"deleted_domains": nd, "deleted_webs": nw})
}

// ---------- 弱点管理（暗链 / 坏链 / 敏感字 / WIH） ----------

func (api *API) listWeaknesses(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	limit, offset := page(c)
	items, total, err := api.store.ListWeaknessesPaged(pid, c.Query("q"), c.Query("type"), c.Query("mark"), limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"items": items, "total": total})
}

func (api *API) deleteWeakness(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	if id <= 0 {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := api.store.DeleteWeakness(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (api *API) clearWeaknesses(c *gin.Context) {
	pid, ok := projID(c)
	if !ok {
		return
	}
	n, err := api.store.ClearWeaknesses(pid, c.Query("type"))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"deleted": n})
}

// markWeakness 标记弱点（实报/误报/取消）
func (api *API) markWeakness(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var req struct {
		Mark string `json:"mark"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || id <= 0 {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if err := api.store.SetWeaknessMark(id, req.Mark); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// aiAnalyzeWeakness AI 研判单条弱点（同步返回结论并写入标记）
func (api *API) aiAnalyzeWeakness(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	w, err := api.store.GetWeakness(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "弱点不存在"})
		return
	}
	cfg := ai.DefaultConfig()
	if saved, _ := api.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	verdict, err := ai.Analyze(cfg, ai.VulnContext{
		VulnID: w.Type, Name: w.Anchor, Severity: w.Severity, Description: w.Detail,
		URL: w.URL, Evidence: w.Evidence,
	})
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	if err := api.store.SetWeaknessMark(id, verdict.Mark); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, verdict)
}

// aiAnalyzeAllWeakness 项目全部未标记弱点批量 AI 研判（异步）
func (api *API) aiAnalyzeAllWeakness(c *gin.Context) {
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
	rows, err := api.store.UnmarkedWeaknesses(pid, 500)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if len(rows) == 0 {
		c.JSON(200, gin.H{"started": true, "count": 0, "note": "无未标记弱点"})
		return
	}
	count := 0
	for _, r := range rows {
		get := func(k string) string {
			if v, ok := r[k]; ok {
				return fmt.Sprint(v)
			}
			return ""
		}
		id, _ := strconv.ParseInt(get("id"), 10, 64)
		if id <= 0 {
			continue
		}
		api.engine.SubmitWeaknessAIAnalyze(id, ai.VulnContext{
			VulnID: get("type"), Name: get("anchor"), Severity: get("severity"), Description: get("detail"),
			URL: get("url"), Evidence: get("evidence"),
		})
		count++
	}
	c.JSON(200, gin.H{"started": true, "count": count, "note": "单次最多研判 500 条未标记弱点"})
}

// weaknessSettingsResp 弱点设置响应：检测配置 + 敏感字订阅（配置与状态，不含词表本体）
type weaknessSettingsResp struct {
	weakness.Settings
	SensSub engine.SensSubView `json:"senssub"`
}

func (api *API) weaknessSettingsResp() weaknessSettingsResp {
	return weaknessSettingsResp{Settings: api.engine.CurrentWeaknessSettings(), SensSub: api.engine.SensSubView()}
}

func (api *API) getWeaknessSettings(c *gin.Context) {
	c.JSON(200, api.weaknessSettingsResp())
}

func (api *API) setWeaknessSettings(c *gin.Context) {
	var st weakness.Settings
	if err := c.ShouldBindJSON(&st); err != nil {
		c.JSON(400, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	if err := api.engine.SetWeaknessSettings(st); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	c.JSON(200, api.weaknessSettingsResp())
}

// setSensSub 保存敏感字词库订阅配置；preset=true 恢复默认预设（konsheng/Sensitive-lexicon）；
// update=true 保存后立即拉取（界面「立即更新」走此路径，保证勾选未保存的文件也一并生效）
func (api *API) setSensSub(c *gin.Context) {
	var req struct {
		weakness.SubConfig
		Preset bool `json:"preset"`
		Update bool `json:"update"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	cfg := req.SubConfig
	if req.Preset {
		cfg = weakness.DefaultSubConfig()
	} else if strings.TrimSpace(cfg.Base) == "" {
		c.JSON(400, gin.H{"error": "参数错误: 需提供订阅源地址（github 仓库或 raw 基址）"})
		return
	}
	if err := api.engine.SetSensSubConfig(cfg); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	if req.Update {
		api.engine.UpdateSensSub()
	}
	c.JSON(200, api.engine.SensSubView())
}

// updateSensSub 立即拉取订阅词库（直连失败自动镜像重试）
func (api *API) updateSensSub(c *gin.Context) {
	c.JSON(200, api.engine.UpdateSensSub())
}

// discoverSensSub 自动发现订阅源（GitHub 仓库）内的 .txt 词库文件
func (api *API) discoverSensSub(c *gin.Context) {
	var req struct {
		Base string `json:"base"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Base) == "" {
		c.JSON(400, gin.H{"error": "参数错误: 需提供订阅源地址"})
		return
	}
	files, err := api.engine.DiscoverSubFiles(req.Base)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"files": files})
}

// sensSubWords 已入库词条搜索与管理视图（?q=&offset=&limit=，附拉取/手工/排除统计）
func (api *API) sensSubWords(c *gin.Context) {
	q := c.Query("q")
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	c.JSON(200, api.engine.SensSubWords(q, offset, limit))
}

// sensSubWordsAdd 手工补充词条（支持批量；自动移出排除清单）
func (api *API) sensSubWordsAdd(c *gin.Context) {
	var req struct {
		Words []string `json:"words"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Words) == 0 {
		c.JSON(400, gin.H{"error": "参数错误: 需提供 words 数组"})
		return
	}
	n := api.engine.AddSensSubWords(req.Words)
	c.JSON(200, gin.H{"added": n})
}

// sensSubWordsDel 删除词条（记入排除清单，订阅更新不带回）
func (api *API) sensSubWordsDel(c *gin.Context) {
	var req struct {
		Words []string `json:"words"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Words) == 0 {
		c.JSON(400, gin.H{"error": "参数错误: 需提供 words 数组"})
		return
	}
	n := api.engine.DeleteSensSubWords(req.Words)
	c.JSON(200, gin.H{"removed": n})
}

// sensSubWordsClear 清空词库（拉取/暗链/手工三份词表；排除清单保留）
func (api *API) sensSubWordsClear(c *gin.Context) {
	n := api.engine.ClearSensWords()
	c.JSON(200, gin.H{"cleared": n})
}

// sensSubExcludes 排除清单查询（?q=）
func (api *API) sensSubExcludes(c *gin.Context) {
	items, total := api.engine.ExcludedSensWords(c.Query("q"))
	c.JSON(200, gin.H{"items": items, "excluded": total})
}

// sensSubExcludesRestore 恢复排除词条（移出排除清单，立即回到生效词表）
func (api *API) sensSubExcludesRestore(c *gin.Context) {
	var req struct {
		Words []string `json:"words"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Words) == 0 {
		c.JSON(400, gin.H{"error": "参数错误: 需提供 words 数组"})
		return
	}
	n := api.engine.RestoreSensWords(req.Words)
	c.JSON(200, gin.H{"restored": n})
}

// ---------- 敏感路径检测（界面自定义规则，引擎不内置路径） ----------

const leakPathsKey = "leak_paths"

// loadLeakPaths 读取已保存的敏感路径规则（未保存返回空集——扫描将跳过该检测）
func (api *API) loadLeakPaths() []builtin.LeakPath {
	if saved, _ := api.store.GetSetting(leakPathsKey); saved != "" {
		var ps []builtin.LeakPath
		if json.Unmarshal([]byte(saved), &ps) == nil {
			return ps
		}
	}
	return []builtin.LeakPath{}
}

func (api *API) getLeakPaths(c *gin.Context) {
	c.JSON(200, gin.H{"items": api.loadLeakPaths()})
}

func (api *API) setLeakPaths(c *gin.Context) {
	var req struct {
		Items []builtin.LeakPath `json:"items"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	builtin.SetLeakPaths(req.Items) // 先规范化（补 /、默认等级、生成编号），再保存规范化结果
	data, _ := json.Marshal(builtin.CurrentLeakPaths())
	if err := api.store.SetSetting(leakPathsKey, string(data)); err != nil {
		c.JSON(500, gin.H{"error": "保存失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"items": builtin.CurrentLeakPaths()})
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

// localTimeJSON 将结构体序列化为 JSON，并把 time.Time 的 RFC3339 T..Z 时间
// 规范为本地 24 小时制串（驱动按 UTC 解析本地墙钟数字，数字即本地时间）
func localTimeJSON(v any) map[string]any {
	data, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]any{}
	}
	re := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$`)
	var walk func(x any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			if mm := re.FindStringSubmatch(t); mm != nil {
				return mm[1] + " " + mm[2]
			}
			return t
		case map[string]any:
			for k, vv := range t {
				t[k] = walk(vv)
			}
			return t
		case []any:
			for i, vv := range t {
				t[i] = walk(vv)
			}
			return t
		}
		return x
	}
	return walk(m).(map[string]any)
}
