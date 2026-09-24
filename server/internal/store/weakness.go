package store

import (
	"fmt"
	"log"
	"net"
	"strings"

	"cysec/internal/model"
)

// UpsertWeakness 弱点入库（按 项目+站点+类型+链接 去重，重复出现仅刷新时间），返回是否新增
func (s *Store) UpsertWeakness(w model.Weakness) (bool, error) {
	isNew, _, err := s.UpsertWeaknessID(w)
	return isNew, err
}

// UpsertWeaknessID 同 UpsertWeakness，并返回记录 ID（实时 AI 研判入队用）
func (s *Store) UpsertWeaknessID(w model.Weakness) (bool, int64, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO weaknesses(project_id,task_id,web_url,page_url,page_title,type,url,anchor,status_code,detail,severity,evidence,context,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		w.ProjectID, w.TaskID, w.WebURL, w.PageURL, w.PageTitle, w.Type, w.URL, w.Anchor, w.StatusCode, w.Detail, w.Severity, w.Evidence, w.Context, NowLocal())
	if err != nil {
		return false, 0, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		id, _ := res.LastInsertId()
		return true, id, nil
	}
	_, err = s.db.Exec(`UPDATE weaknesses SET anchor=?, status_code=?, detail=?, severity=?, evidence=?, context=?, page_url=?, page_title=?, created_at=?
		WHERE project_id=? AND web_url=? AND type=? AND url=?`,
		w.Anchor, w.StatusCode, w.Detail, w.Severity, w.Evidence, w.Context, w.PageURL, w.PageTitle, NowLocal(), w.ProjectID, w.WebURL, w.Type, w.URL)
	var id int64
	s.db.QueryRow(`SELECT id FROM weaknesses WHERE project_id=? AND web_url=? AND type=? AND url=?`,
		w.ProjectID, w.WebURL, w.Type, w.URL).Scan(&id)
	return false, id, err
}

// UpsertWeaknessBatch 批量入库（单事务）：全站扫描一次产生数十条弱点，
// 逐条单事务在 WAL+fsync 下是主要写放大源。返回 (是否新增, id) 与逐条版本等价
func (s *Store) UpsertWeaknessBatch(ws []model.Weakness) ([]bool, []int64, error) {
	newFlags := make([]bool, len(ws))
	ids := make([]int64, len(ws))
	if len(ws) == 0 {
		return newFlags, ids, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return newFlags, ids, err
	}
	defer tx.Rollback()
	for i, w := range ws {
		res, err := tx.Exec(`INSERT OR IGNORE INTO weaknesses(project_id,task_id,web_url,page_url,page_title,type,url,anchor,status_code,detail,severity,evidence,context,created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			w.ProjectID, w.TaskID, w.WebURL, w.PageURL, w.PageTitle, w.Type, w.URL, w.Anchor, w.StatusCode, w.Detail, w.Severity, w.Evidence, w.Context, NowLocal())
		if err != nil {
			return newFlags, ids, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			newFlags[i] = true
			ids[i], _ = res.LastInsertId()
			continue
		}
		if _, err := tx.Exec(`UPDATE weaknesses SET anchor=?, status_code=?, detail=?, severity=?, evidence=?, context=?, page_url=?, page_title=?, created_at=?
			WHERE project_id=? AND web_url=? AND type=? AND url=?`,
			w.Anchor, w.StatusCode, w.Detail, w.Severity, w.Evidence, w.Context, w.PageURL, w.PageTitle, NowLocal(), w.ProjectID, w.WebURL, w.Type, w.URL); err != nil {
			return newFlags, ids, err
		}
		tx.QueryRow(`SELECT id FROM weaknesses WHERE project_id=? AND web_url=? AND type=? AND url=?`,
			w.ProjectID, w.WebURL, w.Type, w.URL).Scan(&ids[i])
	}
	return newFlags, ids, tx.Commit()
}

// InsertConsoleLogs Console 运行日志批量入库（单事务，action=console）
func (s *Store) InsertConsoleLogs(lines []string) {
	if len(lines) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	for _, line := range lines {
		if _, err := tx.Exec(`INSERT INTO system_logs(username,action,object,client_ip,result,created_at) VALUES('','console','','',?,?)`,
			line, NowLocal()); err != nil {
			return
		}
	}
	tx.Commit()
}

// MigrateOrphanConsoleLogs 历史数据归位：批量入库早期版本把 action 写成空串，
// 导致 Console 页签查不到且这些行混入操作日志页签；启动时一次性修正
func (s *Store) MigrateOrphanConsoleLogs() {
	s.db.Exec(`UPDATE system_logs SET action='console' WHERE action='' AND username='' AND client_ip=''`)
}

// ListWeaknessesPaged 弱点分页查询（q 匹配 站点/链接/锚文本/详情，type/mark 可选过滤）
func (s *Store) ListWeaknessesPaged(projectID int64, q, typ, mark string, limit, offset int) ([]map[string]any, int, error) {
	where, args := `project_id=?`, []any{projectID}
	if mark == "unmarked" {
		where += ` AND COALESCE(mark,'')=''`
	} else if mark != "" {
		where += ` AND mark=?`
		args = append(args, mark)
	}
	if q != "" {
		where += ` AND (web_url LIKE ? OR url LIKE ? OR anchor LIKE ? OR detail LIKE ? OR evidence LIKE ?)`
		for i := 0; i < 5; i++ {
			args = append(args, "%"+q+"%")
		}
	}
	if typ != "" {
		where += ` AND type=?`
		args = append(args, typ)
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM weaknesses WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT * FROM weaknesses WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	ms, err := scanMaps(rows)
	return ms, total, err
}

// DeleteWeakness 删除单条
func (s *Store) DeleteWeakness(id int64) error {
	_, err := s.db.Exec(`DELETE FROM weaknesses WHERE id=?`, id)
	return err
}

// ClearWeaknesses 清空指定项目（type 为空=全部类型）
func (s *Store) ClearWeaknesses(projectID int64, typ string) (int64, error) {
	var res interface{ RowsAffected() (int64, error) }
	var err error
	if typ == "" {
		res, err = s.db.Exec(`DELETE FROM weaknesses WHERE project_id=?`, projectID)
	} else {
		res, err = s.db.Exec(`DELETE FROM weaknesses WHERE project_id=? AND type=?`, projectID, typ)
	}
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SetWeaknessMark 标记弱点状态（confirmed=实报 / false_positive=误报 / ”=取消）
func (s *Store) SetWeaknessMark(id int64, mark string) error {
	allowed := map[string]bool{"": true, "confirmed": true, "false_positive": true}
	if !allowed[mark] {
		return fmt.Errorf("无效标记: %s", mark)
	}
	_, err := s.db.Exec(`UPDATE weaknesses SET mark=? WHERE id=?`, mark, id)
	return err
}

// GetWeakness 弱点详情（含标记/AI 研判结果/引用位置，详情弹窗用）
func (s *Store) GetWeakness(id int64) (*model.Weakness, error) {
	w := &model.Weakness{}
	err := s.db.QueryRow(`SELECT id,project_id,web_url,type,url,anchor,status_code,detail,severity,evidence,page_url,page_title,coalesce(context,''),coalesce(mark,''),coalesce(ai_mark,''),coalesce(ai_confidence,''),coalesce(ai_reasoning,'') FROM weaknesses WHERE id=?`, id).
		Scan(&w.ID, &w.ProjectID, &w.WebURL, &w.Type, &w.URL, &w.Anchor, &w.StatusCode, &w.Detail, &w.Severity, &w.Evidence,
			&w.PageURL, &w.PageTitle, &w.Context, &w.Mark, &w.AIMark, &w.AIConfidence, &w.AIReasoning)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// SetWeaknessAI AI 研判结果留存（标记照旧写 mark，AI 明细单独留存供详情页展示）
func (s *Store) SetWeaknessAI(id int64, mark, confidence, reasoning string) error {
	_, err := s.db.Exec(`UPDATE weaknesses SET ai_mark=?, ai_confidence=?, ai_reasoning=? WHERE id=?`, mark, confidence, reasoning, id)
	return err
}

// UnmarkedWeaknesses 项目内未标记弱点（批量 AI 研判用）
func (s *Store) UnmarkedWeaknesses(projectID int64, limit int) ([]map[string]any, error) {
	return s.QueryPage("weaknesses", projectID, "COALESCE(mark,'')=''", nil, "id", limit, 0)
}

// IPsOfProject 项目内全部 IP 资产（独立端口扫描阶段用）
func (s *Store) IPsOfProject(projectID int64) []string {
	rows, err := s.db.Query(`SELECT ip FROM asset_ips WHERE project_id=? ORDER BY id`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			out = append(out, ip)
		}
	}
	return out
}

// DomainMatchesApex 域名一致性校验（从后往前逐标签比对）：
// domain 等于任一 root，或以 "."+root 结尾（标签边界对齐，防伪后缀）。
// roots 为空（纯 IP 任务 / 未启用校验）时全部放行。
func DomainMatchesApex(domain string, roots []string) bool {
	if len(roots) == 0 {
		return true
	}
	d := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}
	for _, r := range roots {
		r = strings.ToLower(strings.Trim(strings.TrimSpace(r), "."))
		if r == "" {
			continue
		}
		if d == r || strings.HasSuffix(d, "."+r) {
			return true
		}
	}
	return false
}

// IsIPStr 判断字符串是否为 IP 字面量（域名过滤时跳过 IP 形态的 host）
func IsIPStr(s string) bool { return net.ParseIP(strings.TrimSpace(s)) != nil }

// CleanupInconsistentDomains 存量清理：删除与给定根域名不一致的域名资产，
// 以及 URL host 为这些杂域名的 Web 资产。返回删除的 (域名数, Web 数)。
func (s *Store) CleanupInconsistentDomains(roots []string) (int64, int64, error) {
	var delDomains, delWebs int64
	if rows, err := s.db.Query(`SELECT id, domain FROM asset_domains`); err == nil {
		ids := []any{}
		examples := []string{}
		for rows.Next() {
			var id int64
			var d string
			if rows.Scan(&id, &d) == nil && !DomainMatchesApex(d, roots) {
				ids = append(ids, id)
				if len(examples) < 5 {
					examples = append(examples, d)
				}
			}
		}
		rows.Close()
		if len(ids) > 0 {
			if _, err := s.db.Exec(`DELETE FROM asset_domains WHERE id IN (`+placeholders(len(ids))+`)`, ids...); err == nil {
				delDomains = int64(len(ids))
				log.Printf("[清理] 删除不一致域名 %d 条（示例：%s）", delDomains, strings.Join(examples, ", "))
			}
		}
	}
	if rows, err := s.db.Query(`SELECT id, url FROM asset_web`); err == nil {
		type deadWeb struct {
			id  int64
			url string
		}
		dead := []deadWeb{}
		for rows.Next() {
			var id int64
			var u string
			if rows.Scan(&id, &u) != nil {
				continue
			}
			host := u
			if i := strings.Index(host, "://"); i >= 0 {
				host = host[i+3:]
			}
			if i := strings.IndexAny(host, "/?#"); i >= 0 {
				host = host[:i]
			}
			if host != "" && !IsIPStr(host) && !DomainMatchesApex(host, roots) {
				dead = append(dead, deadWeb{id: id, url: u})
			}
		}
		rows.Close()
		// 级联删除其衍生 URL 与指纹（与 DeleteWebCascade 同口径），并分批避免超出 SQLite 变量上限
		ids := []any{}
		for _, w := range dead {
			if _, err := s.db.Exec(`DELETE FROM asset_urls WHERE web_id=?`, w.id); err != nil {
				log.Printf("[清理] 杂域名 Web 衍生 URL 删除失败 web=%s: %v", w.url, err)
			}
			if _, err := s.db.Exec(`DELETE FROM asset_fingerprints WHERE web_url=?`, w.url); err != nil {
				log.Printf("[清理] 杂域名 Web 指纹删除失败 web=%s: %v", w.url, err)
			}
			ids = append(ids, w.id)
		}
		for start := 0; start < len(ids); start += 500 {
			end := start + 500
			if end > len(ids) {
				end = len(ids)
			}
			chunk := ids[start:end]
			if _, err := s.db.Exec(`DELETE FROM asset_web WHERE id IN (`+placeholders(len(chunk))+`)`, chunk...); err == nil {
				delWebs += int64(len(chunk))
			} else {
				log.Printf("[清理] 杂域名 Web 删除失败: %v", err)
			}
		}
	}
	return delDomains, delWebs, nil
}

// placeholders 生成 n 个问号占位符
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// SystemLogsPaged 日志管理分页查询（type: ”=全部 / login=登录 / op=操作 / proxy_health=代理切换 /
// console=程序运行 Console；q 匹配 用户/动作/对象/结果）
func (s *Store) SystemLogsPaged(q, typ string, limit, offset int) ([]map[string]any, int, error) {
	where, args := "1=1", []any{}
	if q != "" {
		if typ == "console" {
			// Console 页签搜索只匹配日志内容（action 恒为 console、username 恒空，
			// 多列 OR LIKE 在 2 万条 console 记录上是无谓的全表放大）
			where += ` AND result LIKE ?`
			args = append(args, "%"+q+"%")
		} else {
			where += ` AND (username LIKE ? OR action LIKE ? OR object LIKE ? OR result LIKE ?)`
			for i := 0; i < 4; i++ {
				args = append(args, "%"+q+"%")
			}
		}
	}
	switch typ {
	case "login":
		where += ` AND action='login'`
	case "proxy_health":
		where += ` AND action='proxy_health'`
	case "console":
		where += ` AND action='console'`
	case "op":
		where += ` AND action NOT IN ('login','proxy_health','console')`
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM system_logs WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT * FROM system_logs WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	ms, err := scanMaps(rows)
	return ms, total, err
}

// ClearSystemLogs 清空日志（保留审计意义，仅 admin 可调）
func (s *Store) ClearSystemLogs() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM system_logs`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TrimConsoleLogs Console 运行日志保留上限淘汰（只删 action=console 的最旧记录，
// 其余审计日志不受影响）；Console 日志由程序持续产生，无上限会无限膨胀
func (s *Store) TrimConsoleLogs(keep int) {
	if keep <= 0 {
		return
	}
	s.db.Exec(`DELETE FROM system_logs WHERE action='console' AND id <=
		(SELECT id FROM system_logs WHERE action='console' ORDER BY id DESC LIMIT 1 OFFSET ?)`, keep)
}
