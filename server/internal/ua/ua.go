// Package ua 全局 User-Agent 配置：所有出站请求统一使用
package ua

import (
	"net/http"
	"net/textproto"
	"strings"
	"sync"
)

var (
	mu  sync.RWMutex
	val = "CysecScan/1.0 (authorized-scan)"
)

// Set 设置全局 User-Agent（空串回退默认）
func Set(s string) {
	mu.Lock()
	defer mu.Unlock()
	if v := strings.TrimSpace(s); v != "" {
		val = v
	}
}

// Get 当前 User-Agent
func Get() string {
	mu.RLock()
	defer mu.RUnlock()
	return val
}

// ---- 附加请求头（漏洞扫描引擎出站请求统一携带，来自 config.yaml 的 headers 段） ----

var (
	extraMu  sync.RWMutex
	extraHdr = map[string]string{}
)

// SetHeaders 设置全局附加请求头（键做规范化，空键/空值忽略）。
// User-Agent 特殊处理：作为全局 UA 生效（ua.Get 的所有使用点一致），不重复存入附加头。
func SetHeaders(h map[string]string) {
	clean := make(map[string]string, len(h))
	for k, v := range h {
		ck := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(k))
		if ck == "" || strings.TrimSpace(v) == "" {
			continue
		}
		if ck == "User-Agent" {
			Set(v)
			continue
		}
		clean[ck] = v
	}
	extraMu.Lock()
	extraHdr = clean
	extraMu.Unlock()
}

// Apply 将全局 User-Agent 与附加请求头写入请求。
// 漏洞扫描引擎的全部出站请求经此设置；规则 YAML 自带的 headers 在其后设置，可按规则覆盖。
func Apply(req *http.Request) {
	req.Header.Set("User-Agent", Get())
	extraMu.RLock()
	defer extraMu.RUnlock()
	for k, v := range extraHdr {
		req.Header.Set(k, v)
	}
}
