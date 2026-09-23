// 时区工具：平台所有展示型时间列（created_at / first_seen / last_seen /
// started_at / ended_at / last_probe）统一写入中国时区（UTC+8）、24 小时制
// 字符串 "2006-01-02 15:04:05"，不依赖 SQLite CURRENT_TIMESTAMP（其恒为 UTC）。
// tokens.expires_at 为内部过期比对字段，保留 time.Time 带偏移格式，不在此列。
package store

import "time"

var (
	localLocation = time.FixedZone("CST", 8*3600) // 中国标准时间 UTC+8
	localTimeFmt  = "2006-01-02 15:04:05"
)

// NowLocal 当前中国时区时间（24 小时制字符串）——所有时间列写入统一使用
func NowLocal() string { return time.Now().In(localLocation).Format(localTimeFmt) }
