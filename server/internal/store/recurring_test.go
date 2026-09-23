package store

import (
	"testing"
	"time"

	"cysec/internal/model"
)

// TestRecurringDuePath 周期调度到期判定链路（时区回归）：
// scan_interval=1h、status=done、ended_at 为 65 分钟前的 CST 墙钟串时，
// RecurringTasks 应取到该任务且 EndedAt 距现在 >= 1h。
// 背景：DATETIME 列的墙钟文本会被 modernc 驱动按 UTC 预解析成 Z 结尾 RFC3339，
// timeParse 若按 UTC 解析将少算 8 小时，周期任务每轮都晚 8 小时才重排。
func TestRecurringDuePath(t *testing.T) {
	s := openTest(t)
	id, err := s.CreateTask(&model.ScanTask{ProjectID: 1, Name: "t", Mode: "custom",
		Targets: "http://127.0.0.1:1/", ScanInterval: "1h", Phases: "collect"})
	if err != nil || id <= 0 {
		t.Fatalf("create: %v", err)
	}
	old := time.Now().In(localLocation).Add(-65 * time.Minute).Format(localTimeFmt)
	if err := s.UpdateTask(id, map[string]any{"status": "done", "ended_at": old}); err != nil {
		t.Fatalf("update: %v", err)
	}
	tasks, err := s.RecurringTasks()
	if err != nil {
		t.Fatalf("recurring: %v", err)
	}
	found := false
	for _, tk := range tasks {
		if tk.ID != id {
			continue
		}
		found = true
		if tk.Status != "done" || tk.EndedAt == nil {
			t.Fatalf("status=%s endedAt=%v", tk.Status, tk.EndedAt)
		}
		if since := time.Since(*tk.EndedAt); since < time.Hour {
			t.Fatalf("ended_at 解析偏移: since=%v (期望 >=1h) ended=%v", since, tk.EndedAt)
		}
	}
	if !found {
		t.Fatal("RecurringTasks 未返回周期任务")
	}
}
