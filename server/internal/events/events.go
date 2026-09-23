// Package events 轻量事件总线：引擎写路径发布主题（assets/vulns/weaknesses/tasks），
// SSE 端点广播给前端实现事件驱动刷新（替代 4-5 秒高频轮询，轮询降级为兜底）。
// Publish 按 300ms 节流合并——前端收到任一事件即整体刷新对应面板，高频写入
// （如批量漏洞入库）不会逐条推送。
package events

import (
	"sync"
	"time"
)

// Event 推送给前端的事件（topic: assets / vulns / weaknesses / tasks / changes / system）
type Event struct {
	Topic string `json:"topic"`
	At    int64  `json:"at"`
}

const (
	chanBuf  = 16
	throttle = 300 * time.Millisecond
)

var (
	mu   sync.RWMutex
	subs = map[chan Event]struct{}{}
	last sync.Map // topic -> time.Time（节流）
)

// Publish 发布主题事件（节流合并 + 非阻塞投递：慢消费者缓冲满时丢弃本条，等下一条）
func Publish(topic string) {
	if v, ok := last.Load(topic); ok {
		if t, _ := v.(time.Time); time.Since(t) < throttle {
			return
		}
	}
	last.Store(topic, time.Now())
	ev := Event{Topic: topic, At: time.Now().Unix()}
	mu.RLock()
	defer mu.RUnlock()
	for ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// Subscribe 订阅事件流；返回通道与取消函数（连接断开时必须调用，防泄漏）
func Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, chanBuf)
	mu.Lock()
	subs[ch] = struct{}{}
	mu.Unlock()
	return ch, func() {
		mu.Lock()
		delete(subs, ch)
		mu.Unlock()
	}
}
