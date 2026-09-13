// 模板源在线更新：学习自 nuclei-poc-main 脚本集（1-clone_repos.py / main.py / daily-run.yml）。
// 流程：按源列表顺序 git clone --depth 1（首次）或 git pull（更新）到 data/templates/owner/repo，
// 随后逐源解析导入规则库；源列表顺序即优先级，先到先得（官方源放最前）。
package vulnrule

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cysec/internal/netproxy"
	"cysec/internal/ua"
)

// SourceConfig 模板源配置（持久化于 settings 表 key=rule_sources）
type SourceConfig struct {
	Sources   []Source `json:"sources"`
	AutoDaily bool     `json:"auto_daily"` // 每日自动更新（学习 daily-run.yml）
	AutoTime  string   `json:"auto_time"`  // 每日自动更新时间 HH:MM（默认 02:00）
	Mirror    string   `json:"mirror"`     // GitHub 镜像加速前缀（如 https://ghfast.top），拼接在 github URL 前
	LastRun   string   `json:"last_run"`   // 上次全局更新时间 RFC3339
}

// Source 单个模板源
type Source struct {
	URL        string `json:"url"`
	Enabled    bool   `json:"enabled"`
	LastUpdate string `json:"last_update"` // 上次更新时间
	LastResult string `json:"last_result"` // 上次结果描述
	RuleCount  int    `json:"rule_count"`  // 上次导入/更新条数
}

// DefaultMirror GitHub 连接不顺畅时的默认镜像前缀（可在界面修改为 ghfast.top 等可用镜像）
const DefaultMirror = "https://ghproxy.com"

// NormalizeAutoTime 规范化 HH:MM（非法回退 02:00）
func NormalizeAutoTime(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "02:00"
	}
	h, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return "02:00"
	}
	return fmt.Sprintf("%02d:%02d", h, m)
}

// DefaultSourceConfig 预置源：官方模板库启用；社区源示例默认停用
func DefaultSourceConfig() SourceConfig {
	return SourceConfig{
		AutoTime:  "02:00",
		Mirror:    DefaultMirror,
		AutoDaily: false,
		Sources: []Source{
			{URL: "https://github.com/projectdiscovery/nuclei-templates", Enabled: true},
			{URL: "https://github.com/adysec/nuclei_poc", Enabled: false},
		},
	}
}

// Normalize 清理与校验（不回填默认源——用户删除全部源后应保持为空）
func (c *SourceConfig) Normalize() {
	if c.Sources == nil {
		c.Sources = []Source{}
	}
	for i := range c.Sources {
		c.Sources[i].URL = strings.TrimSpace(c.Sources[i].URL)
	}
}

// ValidGitURL 校验模板源/镜像地址：仅允许 http(s) 且主机非空。
// 拦截以 "-" 开头（会被 git 解析为选项，如 --upload-pack）或伪协议
// （如 ext::/ssh://，git 会按传输协议执行命令）的值，防参数注入。
func ValidGitURL(u string) bool {
	u = strings.TrimSpace(u)
	if u == "" || strings.HasPrefix(u, "-") {
		return false
	}
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "http" || p.Scheme == "https") && p.Host != ""
}

// 更新运行状态（内存，供 API 轮询）
var (
	updMu     sync.Mutex
	updating  bool
	updateLog []string
)

// Updating 是否正在更新
func Updating() bool {
	updMu.Lock()
	defer updMu.Unlock()
	return updating
}

// UpdateLog 最近更新日志
func UpdateLog() []string {
	updMu.Lock()
	defer updMu.Unlock()
	out := make([]string, len(updateLog))
	copy(out, updateLog)
	return out
}

func logf(format string, args ...any) {
	updMu.Lock()
	defer updMu.Unlock()
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, args...)
	updateLog = append(updateLog, line)
	if len(updateLog) > 200 {
		updateLog = updateLog[len(updateLog)-100:]
	}
}

func repoDirName(url string) string {
	parts := strings.Split(strings.TrimRight(strings.TrimSpace(url), "/"), "/")
	if len(parts) >= 2 {
		return strings.ToLower(filepath.Join(parts[len(parts)-2], strings.TrimSuffix(parts[len(parts)-1], ".git")))
	}
	return strings.ToLower(strings.NewReplacer(":", "_", "/", "_", ".", "_").Replace(url))
}

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// StartUpdate 异步启动全部启用源的更新与导入；返回是否成功启动
func StartUpdate(rootDir string, upsert func(Rule) (bool, error), onUpdate func(Source)) bool {
	updMu.Lock()
	if updating {
		updMu.Unlock()
		return false
	}
	updating = true
	updateLog = nil
	updMu.Unlock()
	SuppressWatcher(true) // 批量克隆期间抑制 POC 目录监控，结束后恢复
	go func() {
		defer func() {
			SuppressWatcher(false)
			updMu.Lock()
			updating = false
			updMu.Unlock()
		}()
		if !gitAvailable() {
			logf("更新失败：服务器未安装 git")
			return
		}
		cfg := CurrentSourceConfig()
		done := 0
		allNew := []Rule{}
		for i := range cfg.Sources {
			src := cfg.Sources[i]
			if !src.Enabled {
				continue
			}
			if !ValidGitURL(src.URL) {
				logf("✗ %s: 非法源地址（仅允许 http/https 且以主机名开头），已跳过", src.URL)
				src.LastResult = "失败: 非法源地址"
				if onUpdate != nil {
					onUpdate(src)
				}
				continue
			}
			logf("开始更新 %s", src.URL)
			res, newRules, err := UpdateOneRepoMirror(rootDir, src.URL, cfg.Mirror, upsert)
			if err != nil {
				logf("✗ %s: %v", src.URL, err)
				src.LastResult = "失败: " + err.Error()
			} else {
				logf("✓ %s: %s", src.URL, res)
				src.LastResult = res
				src.LastUpdate = time.Now().Format(time.RFC3339)
				done++
				if len(newRules) > 0 {
					logf("  %s 新增 %d 条规则，将参与全资产扫描", filepath.Base(repoDirName(src.URL)), len(newRules))
				}
				allNew = append(allNew, newRules...)
			}
			if onUpdate != nil {
				onUpdate(src)
			}
		}
		logf("更新完成：%d/%d 个源成功", done, countEnabled(cfg))
		// 与库中已有规则对比后，仅对本次「新增」的 POC 触发全部资产的漏洞扫描
		if len(allNew) > 0 {
			logf("本次更新共新增 %d 条规则，触发全资产扫描…", len(allNew))
			InvokeNewRulesHandler(allNew)
		}
	}()
	return true
}

func countEnabled(c SourceConfig) int {
	n := 0
	for _, s := range c.Sources {
		if s.Enabled {
			n++
		}
	}
	return n
}

// CurrentSourceConfig 读取持久化的源配置（由 store 注入实现）
var currentSourceCfg SourceConfig
var sourceCfgMu sync.RWMutex

// SetSourceConfigProvider 注册读取最新源配置的函数（避免包循环依赖）
var sourceCfgProvider func() SourceConfig

func SetSourceConfigProvider(f func() SourceConfig) { sourceCfgProvider = f }

func CurrentSourceConfig() SourceConfig {
	if sourceCfgProvider != nil {
		return sourceCfgProvider()
	}
	sourceCfgMu.RLock()
	defer sourceCfgMu.RUnlock()
	return currentSourceCfg
}

// cloneURL 应用镜像前缀（仅对 github.com 地址，且镜像本身须为合法 http(s) 地址）
func cloneURL(url, mirror string) string {
	mirror = strings.TrimRight(strings.TrimSpace(mirror), "/")
	if mirror != "" && ValidGitURL(mirror) && strings.HasPrefix(url, "https://github.com/") {
		return mirror + "/" + url
	}
	return url
}

// gitCommand 构造走平台全局代理的 git 命令
func gitCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_HTTP_USER_AGENT="+ua.Get())
	if p := netproxy.Current(); p.Enable && p.Type != "" && p.Type != "none" {
		var proxyURL string
		if p.Type == "socks5" || p.Type == "socks5h" {
			proxyURL = fmt.Sprintf("socks5://%s:%s@%s:%d", p.Username, p.Password, p.Host, p.Port)
		} else {
			proxyURL = fmt.Sprintf("http://%s:%s@%s:%d", p.Username, p.Password, p.Host, p.Port)
		}
		cmd.Env = append(cmd.Env,
			"HTTP_PROXY="+proxyURL, "HTTPS_PROXY="+proxyURL, "ALL_PROXY="+proxyURL,
		)
	}
	return cmd
}

// DefaultCloneRoot 模板源克隆存放根目录：POC 仓库的 nuclei 类型目录
// （完整路径为 <数据库目录>/poc/nuclei，由调用方拼接）
const CloneSubDir = "poc/nuclei"

// UpdateOneRepo 单源更新：clone 或 pull，然后导入目录
func UpdateOneRepo(rootDir, url string, upsert func(Rule) (bool, error)) (string, error) {
	sum, _, err := UpdateOneRepoMirror(rootDir, url, "", upsert)
	return sum, err
}

// newRulesHandler 新增规则处理器（main.go 注册：对全部资产执行新规则扫描）
var newRulesHandler func([]Rule)

// SetNewRulesHandler 注册"新增规则 → 全资产扫描"处理器（模板源更新与 POC 目录监控共用）
func SetNewRulesHandler(f func([]Rule)) { newRulesHandler = f }

// InvokeNewRulesHandler 触发新增规则处理（异步，防重入）
func InvokeNewRulesHandler(rules []Rule) {
	if len(rules) == 0 || newRulesHandler == nil {
		return
	}
	go newRulesHandler(rules)
}

// UpdateOneRepoMirror 支持镜像前缀的单源更新；返回结果摘要、本次新增的规则、错误
func UpdateOneRepoMirror(rootDir, rawURL, mirror string, upsert func(Rule) (bool, error)) (string, []Rule, error) {
	if !ValidGitURL(rawURL) {
		return "", nil, fmt.Errorf("非法源地址（仅允许 http/https）: %s", rawURL)
	}
	dir := filepath.Join(rootDir, repoDirName(rawURL))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if st, err := os.Stat(filepath.Join(dir, ".git")); err == nil && st.IsDir() {
		// 模板镜像同步：fetch + 硬重置到远端最新（兼容分叉/强制推送，且新版 git 需显式合并策略）
		if out, err := gitCommand(ctx, "-C", dir, "fetch", "--depth", "1", "origin").CombinedOutput(); err != nil {
			return "", nil, fmt.Errorf("git fetch 失败: %s", truncateOut(out))
		}
		if out, err := gitCommand(ctx, "-C", dir, "reset", "--hard", "FETCH_HEAD").CombinedOutput(); err != nil {
			return "", nil, fmt.Errorf("git reset 失败: %s", truncateOut(out))
		}
		gitCommand(ctx, "-C", dir, "clean", "-qfd").Run()
	} else {
		os.MkdirAll(filepath.Dir(dir), 0o755)
		// GitHub 连接不顺畅时自动加镜像前缀重试：先直连，失败后用镜像前缀（默认 https://ghproxy.com）
		attempts := []string{rawURL}
		if m := strings.TrimRight(strings.TrimSpace(mirror), "/"); m != "" && ValidGitURL(m) {
			attempts = append(attempts, m+"/"+rawURL)
		} else {
			attempts = append(attempts, DefaultMirror+"/"+rawURL)
		}
		var lastErr string
		cloned := false
		for _, au := range attempts {
			out, err := gitCommand(ctx, "clone", "--depth", "1", au, dir).CombinedOutput()
			if err == nil {
				cloned = true
				if au != rawURL {
					logf("（直连失败，已通过镜像前缀完成克隆: %s）", hostOf(au))
				}
				break
			}
			lastErr = truncateOut(out)
			os.RemoveAll(dir) // 清理半成品目录再重试
			logf("克隆失败（%s），尝试下一种方式…", hostOf(au))
		}
		if !cloned {
			return "", nil, fmt.Errorf("git clone 失败: %s", lastErr)
		}
	}
	res, newRules, err := ImportDirCollect(dir, upsert)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("扫描 %d，新增 %d，更新 %d，不可执行 %d，失败 %d",
		res.FilesScanned, res.Imported, res.Updated, res.Unsupported, res.Failed), newRules, nil
}

func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j > 0 {
			return rest[:j]
		}
		return rest
	}
	return u
}

func truncateOut(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
