// POC 文件仓库：平台统一存放 PoC 文件的目录（data/poc），
// 支持目录浏览、创建文件夹（含多级）、上传 .yml/.yaml、删除、一键导入规则库。
package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cysec/internal/model"
	"cysec/internal/vulnrule"

	"github.com/gin-gonic/gin"
)

// pocBaseDir POC 文件仓库根目录（数据库同级目录下的 poc/）
func (api *API) pocBaseDir() string {
	return filepath.Join(filepath.Dir(api.cfg.Database.Path), "poc")
}

// PocTypeDirs POC 仓库默认的三个类型目录：依次存放 xray / nuclei / afrog 三种 POC
var PocTypeDirs = []string{"xray", "nuclei", "afrog"}

// EnsurePocDirs 确保 POC 仓库及默认类型目录存在（启动时与每次浏览时调用）
func (api *API) EnsurePocDirs() {
	base := api.pocBaseDir()
	os.MkdirAll(base, 0o755)
	for _, d := range PocTypeDirs {
		os.MkdirAll(filepath.Join(base, d), 0o755)
	}
}

// safePocPath 将相对路径限制在 POC 仓库内，防目录穿越
func (api *API) safePocPath(rel string) (string, error) {
	base := api.pocBaseDir()
	rel = strings.Trim(strings.ReplaceAll(rel, "\\", "/"), "/")
	if rel == "" {
		return base, nil
	}
	if strings.Contains(rel, "..") {
		return "", fmt.Errorf("非法路径")
	}
	full := filepath.Join(base, filepath.FromSlash(rel))
	absBase, err1 := filepath.Abs(base)
	absFull, err2 := filepath.Abs(full)
	if err1 != nil || err2 != nil {
		return "", fmt.Errorf("非法路径")
	}
	if absBase == absFull || strings.HasPrefix(absFull, absBase+string(os.PathSeparator)) {
		return absFull, nil
	}
	return "", fmt.Errorf("非法路径")
}

// listPocFiles GET /api/poc-files?path=
func (api *API) listPocFiles(c *gin.Context) {
	api.EnsurePocDirs()
	rel := c.Query("path")
	full, err := api.safePocPath(rel)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		c.JSON(404, gin.H{"error": "目录不存在"})
		return
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	type entry struct {
		Name    string `json:"name"`
		IsDir   bool   `json:"is_dir"`
		Size    int64  `json:"size"`
		ModTime string `json:"mod_time"`
	}
	items := []entry{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, entry{
			Name:    e.Name(),
			IsDir:   e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}
	// 目录在前，名称排序
	for i := 1; i < len(items); i++ {
		for j := i; j > 0; j-- {
			a, b := items[j-1], items[j]
			if (a.IsDir == b.IsDir && a.Name <= b.Name) || a.IsDir {
				break
			}
			items[j-1], items[j] = b, a
		}
	}
	c.JSON(200, gin.H{"base": "poc", "path": strings.Trim(rel, "/"), "entries": items})
}

// mkdirPocFiles POST /api/poc-files/mkdir {path}（支持多级创建）
func (api *API) mkdirPocFiles(c *gin.Context) {
	var req struct {
		Path string `json:"path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Path) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 path"})
		return
	}
	full, err := api.safePocPath(req.Path)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := os.MkdirAll(full, 0o755); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "poc_mkdir", Object: req.Path, ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true, "path": strings.Trim(req.Path, "/")})
}

// savePocFile POST /api/poc-files/save {path, content}（仅允许 .yml/.yaml）
func (api *API) savePocFile(c *gin.Context) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Path) == "" {
		c.JSON(400, gin.H{"error": "参数错误：需要 path 与 content"})
		return
	}
	name := filepath.Base(strings.ReplaceAll(req.Path, "\\", "/"))
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".yml" && ext != ".yaml" {
		c.JSON(400, gin.H{"error": "仅支持 .yml / .yaml 文件"})
		return
	}
	full, err := api.safePocPath(req.Path)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// 先校验是合法规则再保存，并取得自动识别的 POC 类型
	parsed, err := vulnrule.ParseFile(name, []byte(req.Content))
	if err != nil {
		c.JSON(400, gin.H{"error": "POC 解析失败: " + err.Error()})
		return
	}
	// 未显式指定类型目录时，按识别的格式自动归类（xray / nuclei / afrog）
	normalized := strings.Trim(strings.ReplaceAll(req.Path, "\\", "/"), "/")
	first := ""
	if i := strings.Index(normalized, "/"); i > 0 {
		first = normalized[:i]
	}
	// 路径第一级不是类型目录（含根目录直传）→ 按识别格式自动归类
	typed := true
	for _, d := range PocTypeDirs {
		if first == d {
			typed = false // 已在类型目录内，保持用户指定路径
			break
		}
	}
	if typed {
		normalized = parsed.Source + "/" + normalized
		if nf, err := api.safePocPath(normalized); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		} else {
			full = nf
		}
	}
	os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.WriteFile(full, []byte(req.Content), 0o644); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "poc_save", Object: normalized, ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true, "path": normalized, "type": parsed.Source})
}

// deletePocFile DELETE /api/poc-files?path=（文件或目录递归删除，根目录不可删）
func (api *API) deletePocFile(c *gin.Context) {
	rel := c.Query("path")
	if strings.TrimSpace(rel) == "" {
		c.JSON(400, gin.H{"error": "不能删除 POC 根目录"})
		return
	}
	full, err := api.safePocPath(rel)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if _, err := os.Stat(full); err != nil {
		c.JSON(404, gin.H{"error": "不存在"})
		return
	}
	if err := os.RemoveAll(full); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "poc_delete", Object: rel, ClientIP: c.ClientIP(), Result: "success"})
	c.JSON(200, gin.H{"ok": true})
}

// importPocFiles POST /api/poc-files/import {path}（将该子目录导入规则库）
func (api *API) importPocFiles(c *gin.Context) {
	var req struct {
		Path string `json:"path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Path = ""
	}
	full, err := api.safePocPath(req.Path)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if st, err := os.Stat(full); err != nil || !st.IsDir() {
		c.JSON(404, gin.H{"error": "目录不存在"})
		return
	}
	res, err := vulnrule.ImportDir(full, api.store.UpsertVulnRule)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	api.store.SystemLog(model.SystemLog{Username: c.GetString("username"), Action: "poc_import", Object: req.Path, ClientIP: c.ClientIP(),
		Result: fmt.Sprintf("new=%d update=%d", res.Imported, res.Updated)})
	c.JSON(200, res)
}

var _ = time.Now
