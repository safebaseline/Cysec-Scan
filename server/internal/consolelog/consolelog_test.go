package consolelog

import (
	"strings"
	"testing"

	"cysec/internal/model"
	"cysec/internal/store"
)

func TestCollectorBufferAndTrim(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	c := &collector{store: s}

	// 行缓冲：空行丢弃、常规行入缓冲
	c.Write([]byte("2026-01-01 [引擎] 扫描启动\n"))
	c.Write([]byte("\n"))
	if len(c.buf) != 1 {
		t.Fatalf("buf=%d want 1", len(c.buf))
	}

	// 超长行截断
	long := strings.Repeat("x", maxLine+100)
	c.Write([]byte(long))
	if got := c.buf[1]; len(got) != maxLine+len("…[截断]") {
		t.Fatalf("truncation failed: %d", len(got))
	}

	// 洪峰保护：超出 bufCap 丢最旧
	for i := 0; i < bufCap+10; i++ {
		c.Write([]byte("line"))
	}
	if len(c.buf) != bufCap {
		t.Fatalf("cap overflow: %d", len(c.buf))
	}
	if c.buf[0] != "line" {
		t.Fatalf("oldest should be dropped: %q", c.buf[0])
	}
}

func TestTrimConsoleLogs(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	for i := 0; i < 30; i++ {
		s.SystemLog(model.SystemLog{Action: "console", Result: "line"})
	}
	s.SystemLog(model.SystemLog{Action: "op", Result: "keep-me"})
	s.TrimConsoleLogs(10)
	items, total, err := s.SystemLogsPaged("", "console", 100, 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 10 || len(items) != 10 {
		t.Fatalf("console keep=10, got %d/%d", total, len(items))
	}
	// 非 console 日志不受淘汰影响
	_, opTotal, _ := s.SystemLogsPaged("", "op", 10, 0)
	if opTotal != 1 {
		t.Fatalf("op logs must not be trimmed: %d", opTotal)
	}
}

func TestInsertConsoleLogsTypedAndMigrate(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	// 批量入库的行必须带 action='console'（回归：曾写空串导致 Console 页签查 0 条且混入操作日志）
	s.InsertConsoleLogs([]string{"line-1", "line-2"})
	_, total, err := s.SystemLogsPaged("", "console", 10, 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 2 {
		t.Fatalf("console rows=%d want 2", total)
	}
	_, opTotal, _ := s.SystemLogsPaged("", "op", 10, 0)
	if opTotal != 0 {
		t.Fatalf("console rows must not leak into op tab: %d", opTotal)
	}
	// 历史空 action 行迁移归位
	s.Exec(`INSERT INTO system_logs(username,action,object,client_ip,result,created_at) VALUES('','','','','legacy','2006-01-02 15:04:05')`)
	s.MigrateOrphanConsoleLogs()
	_, total2, _ := s.SystemLogsPaged("", "console", 10, 0)
	if total2 != 3 {
		t.Fatalf("after migrate console rows=%d want 3", total2)
	}
}
