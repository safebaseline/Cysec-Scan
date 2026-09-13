package engine

import (
	"encoding/json"
	"log"

	"cysec/internal/ai"
)

// 实时 AI 研判：新增漏洞入库即异步研判（替代原「任务结束后批量研判」）。
// 有界队列 + 双 worker：AI 调用慢（数秒到数十秒），不阻塞扫描流水线；
// 每次研判即时读取 ai_config 设置，配置改动无需重启；等级过滤在出队时判断。

const (
	aiAnalyzeWorkers  = 2
	aiAnalyzeQueueCap = 1024
)

// aiAnalyzeJob 实时研判任务（携带研判所需的漏洞上下文）
type aiAnalyzeJob struct {
	id  int64
	ctx ai.VulnContext
}

// startAIAnalyze 启动实时研判 worker
func (e *Engine) startAIAnalyze() {
	e.aiQueue = make(chan aiAnalyzeJob, aiAnalyzeQueueCap)
	for i := 0; i < aiAnalyzeWorkers; i++ {
		go func() {
			for j := range e.aiQueue {
				e.runAIAnalyze(j)
			}
		}()
	}
}

// SubmitAIAnalyze 提交新增漏洞的实时研判（队列满时丢弃并记日志）
func (e *Engine) SubmitAIAnalyze(id int64, ctx ai.VulnContext) {
	if e.aiQueue == nil || id <= 0 {
		return
	}
	select {
	case e.aiQueue <- aiAnalyzeJob{id: id, ctx: ctx}:
	default:
		log.Printf("[AI] 研判队列已满（%d），跳过漏洞 %s", aiAnalyzeQueueCap, ctx.VulnID)
	}
}

func (e *Engine) runAIAnalyze(j aiAnalyzeJob) {
	cfg := ai.DefaultConfig()
	if saved, _ := e.store.GetSetting("ai_config"); saved != "" {
		json.Unmarshal([]byte(saved), &cfg)
	}
	if !cfg.Enabled || !cfg.AutoAnalyze {
		return
	}
	if !ai.ShouldAutoAnalyze(cfg, j.ctx.Severity) {
		return
	}
	verdict, err := ai.Analyze(cfg, j.ctx)
	if err != nil {
		log.Printf("[AI] 研判 %s 失败: %v", j.ctx.VulnID, err)
		return
	}
	if err := e.store.SetVulnMark(j.id, verdict.Mark); err == nil {
		log.Printf("[AI] 研判 %s: %s（%s）%s", j.ctx.VulnID, verdict.Mark, verdict.Confidence, verdict.Reasoning)
	}
}
