// Package consolelog 程序运行 Console 日志记录：把标准 log 库输出（采集/引擎/
// 实时扫描/AI 研判等运行日志）镜像到 system_logs（action=console），日志管理
// 界面可按"Console 运行"页签查看检索。stderr 输出保持不变（控制台可见）。
package consolelog

import (
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"cysec/internal/store"
)

const (
	flushInterval = 3 * time.Second // 批量入库周期
	maxLine       = 2048            // 单行截断（Console 行可能带大段报文）
	bufCap        = 8192            // 内存待入库缓冲上限（超出丢最旧，防瞬时洪峰占内存）
	dbKeep        = 20000           // 库内保留条数上限（超出自动淘汰最旧）
)

type collector struct {
	mu    sync.Mutex
	buf   []string
	store *store.Store
}

// Start 安装全局 log 输出镜像并启动批量入库循环（进程生命周期常驻）。
// 在 main 中尽早调用——之后的全部 log.Printf 均被记录。
func Start(st *store.Store) {
	st.MigrateOrphanConsoleLogs() // 历史空 action 行归位 console（批量入库早期版本缺陷）
	c := &collector{store: st}
	log.SetOutput(io.MultiWriter(os.Stderr, c))
	go c.loop()
}

// Write 实现 io.Writer：按行切分入缓冲（log 标准库保证单次 Write 为完整行）
func (c *collector) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")
	if line == "" {
		return len(p), nil
	}
	if len(line) > maxLine {
		line = line[:maxLine] + "…[截断]"
	}
	c.mu.Lock()
	if len(c.buf) >= bufCap {
		c.buf = c.buf[1:] // 洪峰保护：丢最旧
	}
	c.buf = append(c.buf, line)
	c.mu.Unlock()
	return len(p), nil
}

// loop 周期性批量入库（单事务）并淘汰超出保留上限的旧记录
func (c *collector) loop() {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		batch := c.buf
		c.buf = nil
		c.mu.Unlock()
		if len(batch) == 0 {
			continue
		}
		c.store.InsertConsoleLogs(batch)
		c.store.TrimConsoleLogs(dbKeep)
	}
}
