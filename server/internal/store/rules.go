package store

import (
	"database/sql"
	"fmt"
	"time"

	"cysec/internal/model"
	"cysec/internal/vulnrule"
)

// UpsertVulnRule 导入/更新漏洞规则。
// 去重策略（学习 nuclei-poc-main/4-remove_duplicated.py）：以 (source, rule_id) 唯一，
// 同一文件路径（同一模板源仓库）重复导入时更新内容；不同仓库的重复模板保留先到者优先
// （源列表按优先级排序，官方库应排在最前）。
func (s *Store) UpsertVulnRule(r vulnrule.Rule) (bool, error) {
	// 已存在且来自其他仓库 → 跳过（保留高优先级源的版本）
	var existPath string
	err := s.db.QueryRow(`SELECT file_path FROM vuln_rules WHERE source=? AND rule_id=?`, r.Source, r.RuleID).Scan(&existPath)
	if err == nil && existPath != "" && existPath != r.FilePath {
		return false, nil
	}
	res, err := s.db.Exec(`INSERT OR IGNORE INTO vuln_rules(source,rule_id,name,severity,tags,description,file_path,supported,enabled,raw,parsed)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.Source, r.RuleID, r.Name, r.Severity, r.Tags, r.Description, r.FilePath,
		boolInt(r.Supported), boolInt(r.Enabled), r.Raw, r.Parsed)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.Exec(`UPDATE vuln_rules SET name=?,severity=?,tags=?,description=?,file_path=?,supported=?,raw=?,parsed=?,updated_at=? WHERE source=? AND rule_id=?`,
		r.Name, r.Severity, r.Tags, r.Description, r.FilePath, boolInt(r.Supported), r.Raw, r.Parsed, time.Now(), r.Source, r.RuleID)
	return false, err
}

// ListVulnRules 规则列表（全局，非项目维度）
func (s *Store) ListVulnRules(where string, args []any, order string, limit, offset int) ([]map[string]any, int, error) {
	q := `SELECT id,source,rule_id,name,severity,tags,description,file_path,supported,enabled,created_at,updated_at FROM vuln_rules`
	if where != "" {
		q += " WHERE " + where
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM vuln_rules`+map[bool]string{true: " WHERE " + where, false: ""}[where != ""], args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if order == "" {
		order = "id DESC"
	}
	rows, err := s.db.Query(q+" ORDER BY "+order+" LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	ms, err := scanMaps(rows)
	return ms, total, err
}

// GetVulnRule 单条规则（含 raw/parsed）
func (s *Store) GetVulnRule(id int64) (*vulnrule.Rule, error) {
	var r vulnrule.Rule
	var sup, ena int
	err := s.db.QueryRow(`SELECT id,source,rule_id,name,severity,tags,description,file_path,supported,enabled,raw,parsed,created_at,updated_at FROM vuln_rules WHERE id=?`, id).
		Scan(&r.ID, &r.Source, &r.RuleID, &r.Name, &r.Severity, &r.Tags, &r.Description, &r.FilePath, &sup, &ena, &r.Raw, &r.Parsed, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.Supported, r.Enabled = sup == 1, ena == 1
	return &r, nil
}

// SetVulnRuleEnabled 启用/停用
func (s *Store) SetVulnRuleEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE vuln_rules SET enabled=?, updated_at=? WHERE id=?`, boolInt(enabled), time.Now(), id)
	return err
}

// ClearVulnRules 清空规则库（全部删除）
func (s *Store) ClearVulnRules() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM vuln_rules`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteVulnRule 删除
func (s *Store) DeleteVulnRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM vuln_rules WHERE id=?`, id)
	return err
}

// VulnRuleStats 规则统计
func (s *Store) VulnRuleStats() map[string]any {
	out := map[string]any{"by_source": map[string]any{}, "by_severity": map[string]any{}}
	var total, sup, ena int
	s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(supported),0), COALESCE(SUM(enabled),0) FROM vuln_rules`).Scan(&total, &sup, &ena)
	out["total"], out["supported"], out["enabled"] = total, sup, ena
	rows, err := s.db.Query(`SELECT source, COUNT(*) FROM vuln_rules GROUP BY source`)
	if err == nil {
		m := map[string]any{}
		for rows.Next() {
			var k string
			var n int
			rows.Scan(&k, &n)
			m[k] = n
		}
		rows.Close()
		out["by_source"] = m
	}
	rows2, err := s.db.Query(`SELECT severity, COUNT(*) FROM vuln_rules GROUP BY severity`)
	if err == nil {
		m := map[string]any{}
		for rows2.Next() {
			var k string
			var n int
			rows2.Scan(&k, &n)
			m[k] = n
		}
		rows2.Close()
		out["by_severity"] = m
	}
	return out
}

// SetVulnMark 标记漏洞状态（confirmed=实报 / false_positive=误报 / ignored=忽略 / ”=未标记）
func (s *Store) SetVulnMark(id int64, mark string) error {
	allowed := map[string]bool{"": true, "confirmed": true, "false_positive": true, "ignored": true}
	if !allowed[mark] {
		return fmt.Errorf("无效标记: %s", mark)
	}
	_, err := s.db.Exec(`UPDATE vulnerabilities SET mark=? WHERE id=?`, mark, id)
	return err
}

// GetVulnMark 读取漏洞标记
func (s *Store) GetVulnMark(id int64) (string, error) {
	var mark string
	err := s.db.QueryRow(`SELECT COALESCE(mark,'') FROM vulnerabilities WHERE id=?`, id).Scan(&mark)
	return mark, err
}

// DeleteVulnerability 删除漏洞
func (s *Store) DeleteVulnerability(id int64) error {
	_, err := s.db.Exec(`DELETE FROM vulnerabilities WHERE id=?`, id)
	return err
}

// ClearVulnerabilities 清空全部漏洞（指定项目）
func (s *Store) ClearVulnerabilities(projectID int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM vulnerabilities WHERE project_id=?`, projectID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EnabledRulesForScan 取扫描用规则：仅启用且可执行，按严重度排序；limit<=0 表示加载全部
func (s *Store) EnabledRulesForScan(limit int) []vulnrule.Rule {
	q := `SELECT id,source,rule_id,name,severity,description,parsed FROM vuln_rules
		WHERE enabled=1 AND supported=1
		ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, id`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = s.db.Query(q+` LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(q)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []vulnrule.Rule{}
	for rows.Next() {
		var r vulnrule.Rule
		if err := rows.Scan(&r.ID, &r.Source, &r.RuleID, &r.Name, &r.Severity, &r.Description, &r.Parsed); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// AllWebAssets 跨项目取全部 Web 资产（供 POC 目录监控触发的新规则全资产扫描）
func (s *Store) AllWebAssets() []model.AssetWeb {
	rows, err := s.db.Query(`SELECT project_id, url, ip, domain, port FROM asset_web ORDER BY id`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.AssetWeb{}
	for rows.Next() {
		var w model.AssetWeb
		if rows.Scan(&w.ProjectID, &w.URL, &w.IP, &w.Domain, &w.Port) == nil {
			out = append(out, w)
		}
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var _ = sql.ErrNoRows

// WebsOfProject 取项目内全部 Web 资产的基础字段（官方 nuclei 引擎结果映射用）
func (s *Store) WebsOfProject(projectID int64) []model.AssetWeb {
	rows, err := s.db.Query(`SELECT project_id, url, ip, domain, port FROM asset_web WHERE project_id=?`, projectID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []model.AssetWeb{}
	for rows.Next() {
		var w model.AssetWeb
		if rows.Scan(&w.ProjectID, &w.URL, &w.IP, &w.Domain, &w.Port) == nil {
			out = append(out, w)
		}
	}
	return out
}
