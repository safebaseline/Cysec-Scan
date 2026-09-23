package events

import (
	"sync"
	"testing"
	"time"
)

func TestPublishSubscribe(t *testing.T) {
	ch, cancel := Subscribe()
	defer cancel()
	Publish("vulns")
	select {
	case ev := <-ch:
		if ev.Topic != "vulns" {
			t.Fatalf("topic: %s", ev.Topic)
		}
	case <-time.After(time.Second):
		t.Fatalf("event not received")
	}
}

func TestThrottleMerge(t *testing.T) {
	ch, cancel := Subscribe()
	defer cancel()
	// 连续发布：300ms 节流窗口内只投递第一条
	Publish("assets")
	Publish("assets")
	Publish("assets")
	time.Sleep(50 * time.Millisecond)
	n := 0
	for {
		select {
		case <-ch:
			n++
			continue
		default:
		}
		break
	}
	if n != 1 {
		t.Fatalf("throttled publish should deliver 1, got %d", n)
	}
}

func TestCancelUnsubscribes(t *testing.T) {
	ch, cancel := Subscribe()
	cancel()
	Publish("vulns")
	time.Sleep(20 * time.Millisecond)
	select {
	case <-ch:
		t.Fatalf("cancelled subscription must not receive")
	default:
	}
}

func TestConcurrentPublish(t *testing.T) {
	_, cancel := Subscribe()
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Publish("vulns")
			Publish("assets")
		}()
	}
	wg.Wait() // 不死锁/不 panic 即通过（非阻塞投递）
}
