package engine

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 验证暂停/恢复的广播语义：暂停后全部并发 worker 停在检查点（而非只拦住一个），
// 恢复后全部继续，取消后全部退出；且支持多次暂停-恢复循环。
func TestPauseResumeBroadcast(t *testing.T) {
	run := &taskRun{cancel: make(chan struct{}), pause: make(chan struct{}), resume: make(chan struct{})}
	var working, stopped int32
	const workers = 5
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if run.waitIfPaused() {
					return // 取消
				}
				atomic.AddInt32(&working, 1)
				time.Sleep(5 * time.Millisecond) // 模拟扫描一个目标
				atomic.AddInt32(&working, -1)
			}
		}()
	}
	waitWorking := func() int32 { time.Sleep(30 * time.Millisecond); return atomic.LoadInt32(&working) }

	// 稳定运行
	if w := waitWorking(); w == 0 {
		t.Fatalf("workers should be running, got %d", w)
	}
	// 暂停：全部停住
	run.pauseBroadcast()
	if w := waitWorking(); w != 0 {
		t.Fatalf("after pause all workers should stop, %d still working", w)
	}
	stoppedNow := atomic.LoadInt32(&stopped)
	_ = stoppedNow
	// 恢复：全部继续
	run.resumeBroadcast()
	if w := waitWorking(); w == 0 {
		t.Fatalf("after resume workers should run again")
	}
	// 再次暂停（通道轮换正确性）
	run.pauseBroadcast()
	if w := waitWorking(); w != 0 {
		t.Fatalf("second pause failed, %d still working", w)
	}
	// 取消：唤醒退出
	run.cancelBroadcast()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("workers did not exit after cancel")
	}
	close(stop)
}
