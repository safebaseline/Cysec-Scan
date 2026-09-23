package engine

import (
	"cysec/internal/model"
	"cysec/internal/store"
)

// 新增 Web 资产实时漏洞扫描：所有来源（任务发现 / 手动导入 / 测绘导入）新增的 Web 资产
// 在入库后异步执行风险检测 + 漏洞规则库扫描（标准模式语义；白名单资产跳过）。
// 任务内标准/深度模式已在 detectWeb 内联扫描，不重复提交；快速模式任务、手动导入 URL、
// 空间测绘导入产生的 Web 资产由此扫描器兜底——替代原「周期任务对新资产补扫」的逻辑，覆盖面更全。

// autoScanJob 实时扫描任务
type autoScanJob struct {
	taskID    int64 // 归属任务（实时扫描等合成上下文为 0，日志走服务端输出）
	projectID int64
	url       string
}

const (
	autoScanWorkers = 4    // 全局并发（独立于任务并发，避免占用扫描流水线额度）
	autoScanQueue   = 1024 // 队列上限（满则丢弃，导入大批量时不拖垮写入）
)

// startAutoScan 启动实时扫描器（scan.web_autoscan 关闭时不启动）
func (e *Engine) startAutoScan() {
	if !e.cfg.Scan.WebAutoScan {
		return
	}
	e.autoScanQueue = make(chan autoScanJob, autoScanQueue)
	for i := 0; i < autoScanWorkers; i++ {
		go func() {
			for j := range e.autoScanQueue {
				e.runAutoScan(j)
			}
		}()
	}
}

// SubmitAutoScan 提交新增 Web 资产的实时扫描（队列满时丢弃）
func (e *Engine) SubmitAutoScan(projectID int64, url string) {
	if e.autoScanQueue == nil || url == "" {
		return
	}
	select {
	case e.autoScanQueue <- autoScanJob{projectID: projectID, url: url}:
	default:
	}
}

// runAutoScan 实时扫描器兜底（测绘/导入来源的新 Web）：探测/指纹/弱点检测照做，
// 漏洞扫描严格按项目级意图——合成任务用 custom+collect,weakness 阶段，
// detectWeb 的 vulnOn 退化为"项目存在勾选漏洞扫描的任务"，未勾选不再触发
// （此前合成 standard 任务 phaseOn(vulnscan)=true，绕过意图判定导致未勾选也产出漏洞）。
// 合成任务 ID=0：检测产生的漏洞正常入库与记变化，任务日志由 store 层过滤非法 ID 不落库。
func (e *Engine) runAutoScan(j autoScanJob) {
	timeout := maxInt(e.cfg.Scan.TimeoutSeconds, 5)
	task := &model.ScanTask{ProjectID: j.projectID, Mode: "custom", Phases: "collect,weakness", TimeoutSec: timeout, FPIgnores: e.store.GetFPAssets(j.projectID)}
	// 误报资产配置：命中则整条跳过（与任务路径同规则）
	if store.FPAssetIgnored(task.FPIgnores, "web", j.url) {
		return
	}
	e.detectWeb(task, j.url, "", timeout)
	// nuclei 源规则：交官方引擎实时扫描同样遵循项目意图（项目无勾选漏洞扫描的任务不提交）
	if e.projectWantsVulnScan(j.projectID) {
		e.SubmitNucleiScan(0, j.projectID, j.url)
	}
}
