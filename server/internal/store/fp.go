package store

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
)

// 误报资产配置（项目级）：命中的后续采集资产不再入库。
// 条目支持：域名根（后缀匹配）、IP、CIDR（如 192.0.2.0/24）、URL 前缀。

// GetFPAssets 读取项目的误报资产配置
func (s *Store) GetFPAssets(projectID int64) []string {
	if saved, _ := s.GetSetting(fpKey(projectID)); saved != "" {
		var items []string
		if json.Unmarshal([]byte(saved), &items) == nil {
			return items
		}
	}
	return nil
}

// SetFPAssets 保存项目的误报资产配置
func (s *Store) SetFPAssets(projectID int64, items []string) error {
	data, _ := json.Marshal(items)
	return s.SetSetting(fpKey(projectID), string(data))
}

func fpKey(projectID int64) string { return "fp_assets:" + strconv.FormatInt(projectID, 10) }

// FPAssetIgnored 判定资产是否命中误报配置（kind: ip/domain/web/url）
func FPAssetIgnored(entries []string, kind, value string) bool {
	if len(entries) == 0 || strings.TrimSpace(value) == "" {
		return false
	}
	val := strings.ToLower(strings.TrimSpace(value))
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		// CIDR 条目：IP 命中网段即忽略（解析失败按普通条目匹配——URL 也含 "/"）
		if _, ipnet, err := net.ParseCIDR(e); err == nil {
			if ip := net.ParseIP(hostOfVal(val)); ip != nil && ipnet.Contains(ip) {
				return true
			}
			continue // 合法 CIDR 但未命中：下一条
		}
		if val == e {
			return true
		}
		switch kind {
		case "domain":
			if strings.HasSuffix(val, "."+e) {
				return true
			}
		case "web", "url":
			if strings.HasPrefix(val, e) {
				// 前缀命中后要求边界：完全相等、后跟路径 /?#，或恰好多出 scheme 边界
				if len(val) == len(e) {
					return true
				}
				if c := val[len(e)]; c == '/' || c == '?' || c == '#' {
					return true
				}
			}
			if h := hostOfVal(val); h != "" && (h == e || strings.HasSuffix(h, "."+e)) {
				return true
			}
		}
	}
	return false
}

// hostOfVal 提取 URL/host 形态值的 host 部分（去 scheme/路径/端口）
func hostOfVal(v string) string {
	s := v
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, ".")
}

// CleanupFPAssets 按误报配置清理项目内已入库的匹配资产：
// IP（含其端口）、域名、Web（含其 URL 与指纹）、独立 URL。返回各类删除数。
func (s *Store) CleanupFPAssets(projectID int64, entries []string) (ips, domains, webs, urls int64, err error) {
	// IP（含 CIDR 命中）→ 级联其端口
	if rows, qerr := s.db.Query(`SELECT id, ip FROM asset_ips WHERE project_id=?`, projectID); qerr == nil {
		ids := []any{}
		ipVals := []string{}
		for rows.Next() {
			var id int64
			var ip string
			if rows.Scan(&id, &ip) == nil && FPAssetIgnored(entries, "ip", ip) {
				ids = append(ids, id)
				ipVals = append(ipVals, ip)
			}
		}
		rows.Close()
		for _, ip := range ipVals {
			s.db.Exec(`DELETE FROM asset_ports WHERE project_id=? AND ip=?`, projectID, ip)
		}
		if len(ids) > 0 {
			if _, derr := s.db.Exec(`DELETE FROM asset_ips WHERE id IN (`+phN(len(ids))+`)`, ids...); derr == nil {
				ips = int64(len(ids))
			}
		}
	}
	// 域名（后缀匹配）
	if rows, qerr := s.db.Query(`SELECT id, domain FROM asset_domains WHERE project_id=?`, projectID); qerr == nil {
		ids := []any{}
		for rows.Next() {
			var id int64
			var d string
			if rows.Scan(&id, &d) == nil && FPAssetIgnored(entries, "domain", d) {
				ids = append(ids, id)
			}
		}
		rows.Close()
		if len(ids) > 0 {
			if _, derr := s.db.Exec(`DELETE FROM asset_domains WHERE id IN (`+phN(len(ids))+`)`, ids...); derr == nil {
				domains = int64(len(ids))
			}
		}
	}
	// Web（URL/host 命中）→ 级联其 URL 与指纹
	if rows, qerr := s.db.Query(`SELECT id, url FROM asset_web WHERE project_id=?`, projectID); qerr == nil {
		ids := []any{}
		urlVals := []string{}
		for rows.Next() {
			var id int64
			var u string
			if rows.Scan(&id, &u) == nil && FPAssetIgnored(entries, "web", u) {
				ids = append(ids, id)
				urlVals = append(urlVals, u)
			}
		}
		rows.Close()
		for _, u := range urlVals {
			s.db.Exec(`DELETE FROM asset_fingerprints WHERE project_id=? AND web_url=?`, projectID, u)
		}
		if len(ids) > 0 {
			// 级联其衍生 URL（按 web_id，与 DeleteWebCascade 同口径，避免悬空 web_id 孤儿）
			args := make([]any, 0, len(ids)+1)
			args = append(args, projectID)
			args = append(args, ids...)
			s.db.Exec(`DELETE FROM asset_urls WHERE project_id=? AND web_id IN (`+phN(len(ids))+`)`, args...)
			if _, derr := s.db.Exec(`DELETE FROM asset_web WHERE id IN (`+phN(len(ids))+`)`, ids...); derr == nil {
				webs = int64(len(ids))
			}
		}
	}
	// 独立 URL（web 已删或本就独立的，按 URL 本身命中）
	if rows, qerr := s.db.Query(`SELECT id, url FROM asset_urls WHERE project_id=?`, projectID); qerr == nil {
		ids := []any{}
		for rows.Next() {
			var id int64
			var u string
			if rows.Scan(&id, &u) == nil && FPAssetIgnored(entries, "url", u) {
				ids = append(ids, id)
			}
		}
		rows.Close()
		if len(ids) > 0 {
			if _, derr := s.db.Exec(`DELETE FROM asset_urls WHERE id IN (`+phN(len(ids))+`)`, ids...); derr == nil {
				urls = int64(len(ids))
			}
		}
	}
	return ips, domains, webs, urls, nil
}

// phN 生成 n 个问号占位符
func phN(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			out += ","
		}
		out += "?"
	}
	return out
}
