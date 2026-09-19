package mapper

import (
	"database/sql"
	"log"
	"strconv"
	"strings"
)

// MigrateWebURLs 存量数据迁移（main 启动后异步调用，不阻塞启动）：
//  1. 无 http(s):// 前缀的 Web 资产 URL：TLS 探测后补全协议；
//  2. 已落库为 http:// 但端口实际是 TLS 的（测绘误判，页面表现为
//     400 "The plain HTTP request was sent to HTTPS port"）：直接替换为 https，
//     同项目已存在相同 https URL 时删除旧行避免重复。
func MigrateWebURLs(db *sql.DB) {
	migrateBareURLs(db)
	migrateHTTPToHTTPS(db)
}

func migrateBareURLs(db *sql.DB) {
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

// migrateHTTPToHTTPS 把误落为 http:// 的 TLS 端口 Web 资产纠正为 https://
func migrateHTTPToHTTPS(db *sql.DB) {
	rows, err := db.Query(`SELECT id, project_id, url, port FROM asset_web WHERE url LIKE 'http://%'`)
	if err != nil {
		return
	}
	type item struct {
		id    int64
		pid   int64
		url   string
		port  int
	}
	var items []item
	for rows.Next() {
		var it item
		if rows.Scan(&it.id, &it.pid, &it.url, &it.port) == nil {
			items = append(items, it)
		}
	}
	rows.Close()
	fixed, merged := 0, 0
	for _, it := range items {
		host := strings.TrimPrefix(it.url, "http://")
		port := it.port
		if port <= 0 { // 端口列缺失时从 URL 尾部解析
			if i := strings.LastIndex(host, ":"); i > 0 {
				if p, err := strconv.Atoi(host[i+1:]); err == nil {
					port = p
				}
			}
		}
		if !probeTLS(host, port) {
			continue
		}
		nu := "https://" + host
		var existID int64
		err := db.QueryRow(`SELECT id FROM asset_web WHERE project_id=? AND url=? LIMIT 1`, it.pid, nu).Scan(&existID)
		switch {
		case err == nil: // 同项目已有 https 行：删除旧 http 行去重
			if _, err := db.Exec(`DELETE FROM asset_web WHERE id=?`, it.id); err == nil {
				merged++
			}
		case err == sql.ErrNoRows:
			if _, err := db.Exec(`UPDATE asset_web SET url=? WHERE id=?`, nu, it.id); err == nil {
				fixed++
			}
		}
	}
	if fixed+merged > 0 {
		log.Printf("[迁移] Web 资产协议纠偏完成：http→https 替换 %d 条、去重合并 %d 条（TLS 端口曾被误记为 http）", fixed, merged)
	}
}
