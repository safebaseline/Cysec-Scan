// 官方 nuclei 引擎嵌入（github.com/projectdiscovery/nuclei/v3/lib，MIT）。
// 用于 source=nuclei 规则的真实语义执行——自研简化执行器对官方模板的
// 匹配器语义覆盖不全（unsupported matcher 近似、软 404 未识别等），误报率高；
// 官方引擎保证模板执行结果与 nuclei CLI 完全一致。
package vulnrule

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"cysec/internal/netproxy"
	"cysec/internal/ua"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiCfg "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// disableUpdateOnce 进程级关闭 nuclei 内置的版本检查与模板自动更新
// （模板由平台模板源管理；否则引擎初始化会外联 GitHub 下载官方模板库，直连环境直接超时失败）
var disableUpdateOnce sync.Once

// NucleiFinding 官方引擎检出结果（对齐平台漏洞模型）
type NucleiFinding struct {
	TemplateID  string
	Name        string
	Severity    string
	Description string
	Tags        string
	Host        string
	Port        string
	Scheme      string
	URL         string // 目标基础 URL
	MatchedAt   string // 命中位置
	MatcherName string
	Request     string
	Response    string
}

// nucleiTemplateRoot nuclei 模板根目录（data/poc/nuclei，含克隆的模板仓库与导入的模板）
var nucleiTemplateRoot string

// SetNucleiTemplateRoot 设置模板根目录（main 启动时接线）
func SetNucleiTemplateRoot(p string) { nucleiTemplateRoot = p }

// NucleiTemplateRoot 返回当前模板根目录（未设置返回空串）
func NucleiTemplateRoot() string { return nucleiTemplateRoot }

// RunNucleiBatch 用官方 nuclei 引擎对一批目标执行指定的 nuclei 模板（按模板 ID 过滤）。
// 出站遵循全局代理配置；超时按任务参数；附带全局出站请求头（含 UA）；ctx 取消即中止扫描。
func RunNucleiBatch(ctx context.Context, targets, templateIDs []string, timeoutSec int) ([]NucleiFinding, error) {
	if len(targets) == 0 || len(templateIDs) == 0 || nucleiTemplateRoot == "" {
		return nil, nil
	}
	if timeoutSec <= 0 {
		timeoutSec = 8
	}
	disableUpdateOnce.Do(func() { nucleiCfg.DefaultConfig.DisableUpdateCheck() })

	var mu sync.Mutex
	findings := []NucleiFinding{}

	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithTemplatesOrWorkflows(nucleilib.TemplateSources{
			Templates: []string{nucleiTemplateRoot},
		}),
		nucleilib.WithTemplateFilters(nucleilib.TemplateFilters{IDs: templateIDs}),
		nucleilib.WithNetworkConfig(nucleilib.NetworkConfig{
			Timeout: timeoutSec, Retries: 1, MaxHostError: 30, SystemResolvers: true,
		}),
		nucleilib.WithConcurrency(nucleilib.Concurrency{
			TemplateConcurrency: 25, HostConcurrency: 10, TemplatePayloadConcurrency: 10,
			HeadlessHostConcurrency: 5, HeadlessTemplateConcurrency: 5, JavascriptTemplateConcurrency: 10,
			ProbeConcurrency: 25,
		}),
		nucleilib.WithVerbosity(verbosity()),
		// 模板由平台自身的模板源管理，禁用引擎内置的模板自动升级/下载（避免初始化时外联 GitHub 超时）
		nucleilib.WithTemplateUpdateCallback(true, nil),
		nucleilib.WithResultCallback(func(event *output.ResultEvent) {
			f := NucleiFinding{
				TemplateID:  event.TemplateID,
				Name:        event.Info.Name,
				Severity:    event.Info.SeverityHolder.Severity.String(),
				Description: event.Info.Description,
				Tags:        event.Info.Tags.String(),
				Host:        event.Host,
				Port:        event.Port,
				Scheme:      event.Scheme,
				URL:         event.URL,
				MatchedAt:   event.Matched,
				MatcherName: event.MatcherName,
				Request:     event.Request,
				Response:    event.Response,
			}
			if f.Severity == "" || f.Severity == "unknown" {
				f.Severity = "info"
			}
			mu.Lock()
			findings = append(findings, f)
			mu.Unlock()
		}),
	}
	// 全局出站代理（Web/漏洞层走代理的分流策略）
	if p := netproxy.Current(); p.Enable && p.Type != "" && p.Type != "none" {
		host := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
		px := p.Type + "://" + host
		if p.Username != "" || p.Password != "" {
			px = p.Type + "://" + p.Username + ":" + p.Password + "@" + host
		}
		opts = append(opts, nucleilib.WithProxy([]string{px}, false))
	}
	// 全局出站请求头（User-Agent 为全局 UA，其余为扫描引擎附加头）
	var hdrs []string
	for k, v := range ua.CurrentHeaders() {
		hdrs = append(hdrs, k+": "+v)
	}
	if len(hdrs) > 0 {
		opts = append(opts, nucleilib.WithHeaders(hdrs))
	}

	ne, err := nucleilib.NewNucleiEngine(opts...)
	if err != nil {
		return nil, fmt.Errorf("nuclei 引擎初始化失败: %w", err)
	}
	defer ne.Close()
	ne.LoadTargets(targets, false)
	if err := ne.ExecuteCallbackWithCtx(ctx); err != nil {
		return findings, fmt.Errorf("nuclei 执行失败: %w", err)
	}
	return findings, nil
}

// verbosity 输出级别：默认静默；NUCLEI_DEBUG=1 时输出调试（请求/响应报文）
func verbosity() nucleilib.VerbosityOptions {
	if os.Getenv("NUCLEI_DEBUG") == "1" {
		return nucleilib.VerbosityOptions{Verbose: true, Debug: true, DebugRequest: true, DebugResponse: true}
	}
	return nucleilib.VerbosityOptions{Silent: true}
}
