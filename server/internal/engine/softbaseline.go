package engine

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"cysec/internal/netproxy"
	"cysec/internal/ua"
)

// soft-404 误报抑制：大量"检测/exposure"类 nuclei 模板采用「状态码 200 + 弱特征」判定，
// 在前端路由 SPA / 通配路由站点上（任意路径返回同一 200 页面）会批量误报。
// 做法：对每个目标先探测一个必然不存在的随机路径，记录基准响应指纹（状态码 + 正文 SHA-256）；
// 引擎检出漏洞后，将命中响应与基准比对——正文指纹一致（该响应不具备路径区分度）即判
// soft-404 误报，不入库并记日志。真实漏洞的响应内容必然与基准不同，不受影响。

// softBaseline 目标站点的 soft-404 基准指纹
type softBaseline struct {
	ok     bool   // 探测成功（失败则不启用抑制，宁可多报不 silently 漏报）
	status int
	bodyFP string
}

type softBaselineCache struct {
	mu sync.Mutex
	m  map[string]softBaseline
	at time.Time
}

const softBaselineTTL = 10 * time.Minute

var softCache = &softBaselineCache{m: map[string]softBaseline{}}

func bodyFingerprint(b []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// probeSoftBaseline 对 baseURL（仅 http/https）探测随机不存在路径，返回基准指纹。
// 出站与漏洞引擎同口径（全局代理感知 client + 全局 UA）。
func probeSoftBaseline(baseURL string, timeoutSec int) softBaseline {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return softBaseline{}
	}
	root := strings.TrimRight(baseURL, "/")
	probe := fmt.Sprintf("%s/cysec-soft404-%d", root, time.Now().UnixNano()%1e9)
	rq, err := http.NewRequest("GET", probe, nil)
	if err != nil {
		return softBaseline{}
	}
	ua.Apply(rq)
	rs, err := netproxy.NewHTTPClient(maxInt(timeoutSec, 5), 0).Do(rq)
	if err != nil {
		return softBaseline{}
	}
	defer rs.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(rs.Body, 256*1024))
	return softBaseline{ok: true, status: rs.StatusCode, bodyFP: bodyFingerprint(body)}
}

// baselineOf 取（带 TTL 缓存的）目标基准；探测失败也缓存，避免重复探测
func baselineOf(baseURL string, timeoutSec int) softBaseline {
	key := strings.TrimRight(baseURL, "/")
	softCache.mu.Lock()
	if time.Since(softCache.at) > softBaselineTTL {
		softCache.m = map[string]softBaseline{}
		softCache.at = time.Now()
	}
	b, ok := softCache.m[key]
	softCache.mu.Unlock()
	if ok {
		return b
	}
	b = probeSoftBaseline(key, timeoutSec)
	softCache.mu.Lock()
	softCache.m[key] = b
	softCache.mu.Unlock()
	return b
}

// ResetSoftBaselineCache 清空基准缓存（测试用）
func ResetSoftBaselineCache() {
	softCache.mu.Lock()
	softCache.m = map[string]softBaseline{}
	softCache.mu.Unlock()
}

// isSoft404Response 判断命中响应是否与基准不可区分（响应无路径区分度）。
// raw 为完整 HTTP 报文（含状态行与头部）；取空行后的正文比对指纹。
func isSoft404Response(raw string, b softBaseline) bool {
	if !b.ok || b.status != 200 || raw == "" {
		return false
	}
	body := raw
	// 剥离头部：首个 CRLFCRLF 之后为正文（兼容裸 LF）
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		body = raw[i+4:]
	} else if i := strings.Index(raw, "\n\n"); i >= 0 {
		body = raw[i+2:]
	}
	if body == "" {
		return false
	}
	return bodyFingerprint([]byte(body)) == b.bodyFP
}
