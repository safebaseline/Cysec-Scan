// Package ua 全局 User-Agent 配置：所有出站请求统一使用
package ua

import (
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
