package mapper

import (
	"database/sql"
	"log"
)

// MigrateWebURLs 存量数据迁移：对无 http(s):// 前缀的 Web 资产 URL 做协议探测后补全。
// 由 main 启动后异步调用，不阻塞启动。
func MigrateWebURLs(db *sql.DB) {
	rows, err := db.Query(`SELECT id, url, port FROM asset_web WHERE url NOT LIKE 'http%'`)
	if err != nil {
		return
	}
	type item struct {
		id   int64
		url  string
		port int
	}
	var items []item
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.url, &it.port) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	if len(items) == 0 {
		return
	}
	fixed := 0
	for _, it := range items {
		nu := NormalizeURL(it.url, it.port)
		if nu != it.url {
			if _, err := db.Exec(`UPDATE asset_web SET url=? WHERE id=?`, nu, it.id); err == nil {
				fixed++
			}
		}
	}
	if fixed > 0 {
		log.Printf("[迁移] Web 资产 URL 协议补全完成：%d 条（TLS 探测判定 http/https）", fixed)
	}
}
