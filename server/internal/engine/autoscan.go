package engine

import (
	"cysec/internal/model"
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

// runAutoScan 以标准模式语义执行完整 Web 检测链（探测/指纹/风险检测/WIH/规则库）。
// 合成任务 ID=0：检测产生的漏洞正常入库与记变化，任务日志由 store 层过滤非法 ID 不落库。
func (e *Engine) runAutoScan(j autoScanJob) {
	timeout := maxInt(e.cfg.Scan.TimeoutSeconds, 5)
	task := &model.ScanTask{ProjectID: j.projectID, Mode: "standard", TimeoutSec: timeout}
	e.detectWeb(task, j.url, "", timeout)
	// nuclei 源规则：新 Web 资产交官方引擎实时扫描（串行队列）
	e.SubmitNucleiScan(0, j.projectID, j.url)
}
