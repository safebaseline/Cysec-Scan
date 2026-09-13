package mapper

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"cysec/internal/netproxy"
	"cysec/plugins/builtin"
)

// VerifyAlive 对测绘记录做存活性探测，返回存活记录与被剔除的失效数。
// 探测策略（与扫描流量一致走全局代理）：
//   - 有 IP+Port：TCP 连通探测（快，引擎无关）
//   - 仅有 URL：HTTP 探测（状态码 > 0 即存活）
//   - 无可探测目标（如仅域名）：保留（不做裁决）
func VerifyAlive(recs []Record, timeoutSec int, concurrency int) ([]Record, int) {
	if timeoutSec <= 0 {
		timeoutSec = 4
	}
	if concurrency <= 0 {
		concurrency = 32
	}
	keep := make([]bool, len(recs))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range recs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			keep[i] = probeRecord(recs[i], timeoutSec)
		}(i)
	}
	wg.Wait()
	out := make([]Record, 0, len(recs))
	dead := 0
	for i := range recs {
		if keep[i] {
			out = append(out, recs[i])
		} else {
			dead++
		}
	}
	return out, dead
}

// probeRecord 单条记录存活性判定
func probeRecord(r Record, timeoutSec int) bool {
	// 优先 TCP 探测 IP:Port
	if r.IP != "" && r.Port > 0 {
		conn, err := netproxy.DialTimeout("tcp", net.JoinHostPort(r.IP, fmt.Sprint(r.Port)), dur(timeoutSec))
		if err == nil {
			conn.Close()
			return true
		}
		return false
	}
	// 仅 URL：HTTP 探测
	if r.URL != "" && strings.Contains(r.URL, "://") {
		if w := builtin.ProbeWeb(r.URL, r.IP, timeoutSec); w != nil && w.StatusCode > 0 {
			return true
		}
		return false
	}
	// 无可探测目标（仅域名等）：保留
	return true
}

func dur(sec int) time.Duration { return time.Duration(sec) * time.Second }
