package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cysec/internal/model"

	_ "github.com/ncruces/go-sqlite3/driver"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	migrateLegacyFilename(path)
	// DSN 必须带 file: 前缀，驱动才会解析 ?_pragma= 连接参数；
	// 否则整串拼进文件名，Windows 下 ? 为非法字符直接报错，Linux 下 pragma 静默失效
	db, err := sql.Open("sqlite3", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite 写串行化，避免 busy
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// migrateLegacyFilename 历史版本 DSN 未带 file: 前缀，磁盘上的库文件名带 ?_pragma=... 后缀，
// 启动时改回规范名（连同 -wal/-shm 旁路文件），避免旧数据被当成不存在而重新建库
func migrateLegacyFilename(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	matches, _ := filepath.Glob(path + "?*")
	for _, m := range matches {
		dst := path
		switch {
		case strings.HasSuffix(m, "-wal"):
			dst = path + "-wal"
		case strings.HasSuffix(m, "-shm"):
			dst = path + "-shm"
		}
		if m == dst {
			continue
		}
		if _, err := os.Stat(dst); err != nil {
			os.Rename(m, dst)
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// 增量迁移：周期扫描列与漏洞报文列（已存在时忽略报错）
	s.db.Exec(`ALTER TABLE scan_tasks ADD COLUMN scan_interval TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE vulnerabilities ADD COLUMN request TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE vulnerabilities ADD COLUMN response TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE vulnerabilities ADD COLUMN mark TEXT DEFAULT ''`) // confirmed/false_positive/ignored
	s.backfillVulnPackets()
	s.migrateTimestampsToLocal()
	s.migrateTaskPhases()
	return nil
}

// migrateTimestampsToLocal 存量时间戳统一为中国时区 24 小时制。历史数据混存两种格式：
// 1) SQLite CURRENT_TIMESTAMP 写入的 UTC 串 "YYYY-MM-DD HH:MM:SS" —— 统一 +8 小时；
// 2) Go time.Time 写入的本地带偏移 ISO 串 "YYYY-MM-DDTHH:MM:SS...+08:00" —— 去偏移规范为本地串。
// tokens.expires_at 为内部过期比对字段（time.Time 往返），不参与迁移。
// 幂等：settings 键 tz_local=1 标记只跑一次。
func (s *Store) migrateTimestampsToLocal() {
	if flag, _ := s.GetSetting("tz_local"); strings.TrimSpace(flag) == "1" {
		return
	}
	// 普通列：全部为 UTC 串或空
	utcCols := [][2]string{
		{"scan_logs", "created_at"}, {"asset_changes", "created_at"}, {"system_logs", "created_at"},
		{"users", "created_at"}, {"projects", "created_at"}, {"scan_tasks", "created_at"},
		{"vulnerabilities", "first_seen"}, {"vulnerabilities", "last_seen"},
		{"asset_ips", "first_seen"}, {"asset_domains", "first_seen"}, {"asset_ports", "first_seen"},
		{"asset_web", "first_seen"}, {"asset_urls", "first_seen"}, {"asset_fingerprints", "first_seen"},
	}
	// 混存列：started_at/ended_at/last_probe 历史上由 time.Time 写入（ISO+偏移）
	mixedCols := [][2]string{
		{"scan_tasks", "started_at"}, {"scan_tasks", "ended_at"}, {"asset_ips", "last_probe"},
	}
	total := int64(0)
	run := func(q string, args ...any) {
		if res, err := s.db.Exec(q, args...); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				total += n
			}
		}
	}
	for _, c := range utcCols {
		run(fmt.Sprintf(`UPDATE %s SET %s = datetime(%s, '+8 hours')
			WHERE %s IS NOT NULL AND %s != '' AND %s NOT LIKE '%%T%%'`, c[0], c[1], c[1], c[1], c[1], c[1]))
	}
	for _, c := range mixedCols {
		// ISO 带偏移（本地墙钟）-> 去偏移规范
		run(fmt.Sprintf(`UPDATE %s SET %s = substr(replace(%s, 'T', ' '), 1, 19)
			WHERE %s IS NOT NULL AND %s LIKE '%%T%%'`, c[0], c[1], c[1], c[1], c[1]))
		// UTC 串 -> +8
		run(fmt.Sprintf(`UPDATE %s SET %s = datetime(%s, '+8 hours')
			WHERE %s IS NOT NULL AND %s != '' AND %s NOT LIKE '%%T%%'`, c[0], c[1], c[1], c[1], c[1], c[1]))
	}
	s.SetSetting("tz_local", "1")
	if total > 0 {
		log.Printf("[迁移] 时间戳已统一为中国时区（UTC+8）24 小时制，共更新 %d 行", total)
	}
}

// backfillVulnPackets 存量修复：早期版本部分 nuclei 漏洞（多请求链/interactsh 模板）报文为空，
// 用命中位置重建请求报文摘要并注明，避免前端报文查看为空
func (s *Store) backfillVulnPackets() {
	res, err := s.db.Exec(`UPDATE vulnerabilities
		SET request = 'GET ' || url || ' HTTP/1.1' || CHAR(10) || CHAR(10) || '[注] 原始请求报文未被早期版本引擎保留（多请求链/interactsh 模板），此为重建报文。',
		    response = '[注] 原始响应报文未被早期版本引擎保留（多请求链/interactsh 模板）。' || CHAR(10) || '命中位置: ' || COALESCE(evidence,'')
		WHERE COALESCE(request,'')='' AND COALESCE(response,'')='' AND scanner='nuclei-engine'`)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[迁移] 已为 %d 条历史 nuclei 漏洞回填重建报文", n)
		}
	}
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  expires_at DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS asset_ips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  network TEXT DEFAULT '',
  alive INTEGER DEFAULT 0,
  probe_method TEXT DEFAULT '',
  latency_ms INTEGER DEFAULT 0,
  last_probe DATETIME,
  risk_score INTEGER DEFAULT 0,
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source TEXT DEFAULT '',
  UNIQUE(project_id, ip)
);
CREATE TABLE IF NOT EXISTS asset_domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  cname TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source TEXT DEFAULT '',
  UNIQUE(project_id, domain)
);
CREATE TABLE IF NOT EXISTS asset_ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT DEFAULT 'tcp',
  state TEXT DEFAULT 'open',
  service TEXT DEFAULT '',
  version TEXT DEFAULT '',
  banner TEXT DEFAULT '',
  category TEXT DEFAULT '未知资产',
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source TEXT DEFAULT '',
  UNIQUE(project_id, ip, port, protocol)
);
CREATE TABLE IF NOT EXISTS asset_web (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  url TEXT NOT NULL,
  ip TEXT DEFAULT '',
  domain TEXT DEFAULT '',
  port INTEGER DEFAULT 0,
  protocol TEXT DEFAULT '',
  status_code INTEGER DEFAULT 0,
  title TEXT DEFAULT '',
  server TEXT DEFAULT '',
  content_type TEXT DEFAULT '',
  resp_size INTEGER DEFAULT 0,
  certificate TEXT DEFAULT '',
  headers TEXT DEFAULT '',
  tech TEXT DEFAULT '',
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source TEXT DEFAULT '',
  UNIQUE(project_id, url)
);
CREATE TABLE IF NOT EXISTS asset_urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  web_id INTEGER NOT NULL DEFAULT 0,
  url TEXT NOT NULL,
  method TEXT DEFAULT 'GET',
  status_code INTEGER DEFAULT 0,
  content_type TEXT DEFAULT '',
  resp_size INTEGER DEFAULT 0,
  source TEXT DEFAULT '',
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, url)
);
CREATE TABLE IF NOT EXISTS asset_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  web_url TEXT NOT NULL,
  category TEXT DEFAULT '',
  name TEXT NOT NULL,
  detail TEXT DEFAULT '',
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, web_url, category, name)
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  vuln_id TEXT NOT NULL,
  name TEXT NOT NULL,
  severity TEXT NOT NULL,
  ip TEXT DEFAULT '',
  domain TEXT DEFAULT '',
  port INTEGER DEFAULT 0,
  url TEXT DEFAULT '',
  service TEXT DEFAULT '',
  component TEXT DEFAULT '',
  description TEXT DEFAULT '',
  solution TEXT DEFAULT '',
  evidence TEXT DEFAULT '',
  scanner TEXT DEFAULT '',
  first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, ip, port, url, vuln_id)
);
CREATE TABLE IF NOT EXISTS scan_tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  mode TEXT DEFAULT 'standard',
  targets TEXT NOT NULL,
  target_type TEXT DEFAULT 'ip',
  ports TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  concurrency INTEGER DEFAULT 8,
  timeout_sec INTEGER DEFAULT 5,
  priority INTEGER DEFAULT 5,
  cron_expr TEXT DEFAULT '',
  phases TEXT DEFAULT '',
  subdomain_brute INTEGER DEFAULT 0,
  created_by TEXT DEFAULT '',
  error TEXT DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  started_at DATETIME,
  ended_at DATETIME
);
CREATE TABLE IF NOT EXISTS scan_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  level TEXT DEFAULT 'info',
  message TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS asset_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  task_id INTEGER NOT NULL,
  asset_type TEXT NOT NULL,
  asset TEXT NOT NULL,
  change TEXT NOT NULL,
  detail TEXT DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS system_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  action TEXT NOT NULL,
  object TEXT DEFAULT '',
  client_ip TEXT DEFAULT '',
  result TEXT DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vuln_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  name TEXT DEFAULT '',
  severity TEXT DEFAULT 'medium',
  tags TEXT DEFAULT '',
  description TEXT DEFAULT '',
  file_path TEXT DEFAULT '',
  supported INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1,
  raw TEXT DEFAULT '',
  parsed TEXT DEFAULT '',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(source, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_rules_sev ON vuln_rules(severity, enabled);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ports_ip ON asset_ports(project_id, ip);
CREATE INDEX IF NOT EXISTS idx_vuln_proj ON vulnerabilities(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_web_proj ON asset_web(project_id);
CREATE INDEX IF NOT EXISTS idx_tasks_proj ON scan_tasks(project_id, status);
CREATE TABLE IF NOT EXISTS weaknesses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  task_id INTEGER NOT NULL DEFAULT 0,
  web_url TEXT DEFAULT '',
  page_url TEXT DEFAULT '',
  page_title TEXT DEFAULT '',
  type TEXT NOT NULL,             -- darklink / brokenlink / sensword / wih
  url TEXT DEFAULT '',
  anchor TEXT DEFAULT '',
  status_code INTEGER DEFAULT 0,
  detail TEXT DEFAULT '',
  severity TEXT DEFAULT 'low',
  evidence TEXT DEFAULT '',
  context TEXT DEFAULT '',
  mark TEXT DEFAULT '',
  created_at DATETIME NOT NULL,
  UNIQUE(project_id, web_url, type, url)
);
CREATE INDEX IF NOT EXISTS idx_weak_proj ON weaknesses(project_id, type);
CREATE INDEX IF NOT EXISTS idx_weak_mark ON weaknesses(project_id, type, mark);
CREATE INDEX IF NOT EXISTS idx_syslog_action ON system_logs(action, id);
CREATE INDEX IF NOT EXISTS idx_scanlogs_task ON scan_logs(task_id);
`

// migrateTaskPhases 旧库补列（已存在时报错忽略）
func (s *Store) migrateTaskPhases() {
	s.db.Exec(`ALTER TABLE scan_tasks ADD COLUMN phases TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE scan_tasks ADD COLUMN subdomain_brute INTEGER DEFAULT 0`)
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN mark TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN context TEXT DEFAULT ''`)
	// AI 研判结果留存（详情页展示）：标记/置信度/推理依据
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN ai_mark TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN ai_confidence TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN ai_reasoning TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE vulnerabilities ADD COLUMN ai_mark TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE vulnerabilities ADD COLUMN ai_confidence TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE vulnerabilities ADD COLUMN ai_reasoning TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN page_url TEXT DEFAULT ''`)
	s.db.Exec(`ALTER TABLE weaknesses ADD COLUMN page_title TEXT DEFAULT ''`)
	// 级联删除上线前的存量孤儿：web 已删但 URL/指纹残留（仪表盘计数虚高的根因）
	if res, err := s.db.Exec(`DELETE FROM asset_urls WHERE web_id != 0 AND web_id NOT IN (SELECT id FROM asset_web)`); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[迁移] 清理孤儿 URL 资产 %d 条（所属 Web 已删除）", n)
		}
	}
	if res, err := s.db.Exec(`DELETE FROM asset_fingerprints WHERE web_url != '' AND web_url NOT IN (SELECT url FROM asset_web)`); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[迁移] 清理孤儿指纹 %d 条（所属 Web 已删除）", n)
		}
	}
}

func (s *Store) Exec(query string, args ...any) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

// ---------- 通用查询 ----------

func (s *Store) QueryPage(table string, projectID int64, where string, args []any, order string, limit, offset int) ([]map[string]any, error) {
	q := fmt.Sprintf("SELECT * FROM %s WHERE project_id=?", table)
	if where != "" {
		q += " AND " + where
	}
	if order == "" {
		order = "id DESC"
	}
	q += fmt.Sprintf(" ORDER BY %s LIMIT ? OFFSET ?", order)
	args = append(append([]any{projectID}, args...), limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMaps(rows)
}

func (s *Store) Count(table string, projectID int64, where string, args []any) (int, error) {
	q := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE project_id=?", table)
	if where != "" {
		q += " AND " + where
	}
	args = append([]any{projectID}, args...)
	var n int
	err := s.db.QueryRow(q, args...).Scan(&n)
	return n, err
}

func scanMaps(rows *sql.Rows) ([]map[string]any, error) {
	cols, _ := rows.Columns()
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := map[string]any{}
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			// DATETIME 列经驱动扫描为 time.Time（本地墙钟数字被按 UTC 解析）；
			// 直接 Format 还原本地数字，避免 JSON 序列化成 T..Z 后前端再加时区
			if tt, ok := v.(time.Time); ok {
				v = tt.Format(localTimeFmt)
			}
			m[c] = v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- 用户 / 令牌 ----------

func (s *Store) GetUser(username string) (*model.User, error) {
	u := &model.User{}
	var created sql.NullString
	err := s.db.QueryRow(`SELECT id,username,password,role,created_at FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Password, &u.Role, &created)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = timeParse(created)
	return u, nil
}

func timeParse(v sql.NullString) time.Time {
	if !v.Valid || v.String == "" {
		return time.Time{}
	}
	// 无偏移墙钟串按平台统一写入时区（UTC+8）解析。
	// 注意驱动陷阱：DATETIME 声明列中的墙钟文本会被 modernc 驱动按 UTC 预解析，
	// 经 database/sql 转成 Z 结尾 RFC3339 字符串再到达这里——其墙钟数字实为 CST，
	// 零偏移结果需按 CST 重新解释（time.Parse 默认 UTC 会让周期到期判断少算 8 小时）。
	if t, err := time.ParseInLocation(time.DateTime, v.String, localLocation); err == nil {
		return t
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05.999999999-07:00"} {
		if t, err := time.Parse(layout, v.String); err == nil {
			if _, off := t.Zone(); off == 0 {
				return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), localLocation)
			}
			return t
		}
	}
	return time.Time{}
}

func (s *Store) CreateUser(u *model.User) error {
	_, err := s.db.Exec(`INSERT INTO users(username,password,role,created_at) VALUES(?,?,?,?)`, u.Username, u.Password, u.Role, NowLocal())
	return err
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) UpdateUserPassword(username, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password=? WHERE username=?`, hash, username)
	return err
}

// DeleteUserTokensExcept 吊销该用户除 keep 外的全部会话（改密后踢掉其他登录态）
func (s *Store) DeleteUserTokensExcept(username, keep string) error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE username=? AND token<>?`, username, keep)
	return err
}

func (s *Store) SaveToken(t model.Token) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO tokens(token,username,expires_at) VALUES(?,?,?)`, t.Token, t.Username, t.ExpiresAt)
	return err
}

func (s *Store) GetToken(token string) (model.Token, error) {
	t := model.Token{}
	var exp sql.NullString
	err := s.db.QueryRow(`SELECT token,username,expires_at FROM tokens WHERE token=?`, token).
		Scan(&t.Token, &t.Username, &exp)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("[auth] 读取会话失败: %v", err) // 排障可见性：锁/IO 类错误不再静默 401
		}
		return t, err
	}
	t.ExpiresAt = timeParse(exp)
	return t, nil
}

func (s *Store) DeleteToken(token string) error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE token=?`, token)
	return err
}

// ---------- 项目 ----------

func (s *Store) CreateProject(p *model.Project) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO projects(name,description,created_at) VALUES(?,?,?)`, p.Name, p.Description, NowLocal())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteProject 删除项目及其全部数据（各类资产、漏洞、弱点、指纹、变化、任务与任务日志、
// 项目级误报资产配置）
func (s *Store) DeleteProject(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	tables := []string{"asset_ips", "asset_domains", "asset_ports", "asset_web", "asset_urls",
		"asset_fingerprints", "vulnerabilities", "weaknesses", "asset_changes"}
	for _, t := range tables {
		if _, err := tx.Exec(`DELETE FROM `+t+` WHERE project_id=?`, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM scan_logs WHERE task_id IN (SELECT id FROM scan_tasks WHERE project_id=?)`, id); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM scan_tasks WHERE project_id=?`, id); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM projects WHERE id=?`, id); err != nil {
		tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`DELETE FROM settings WHERE key=?`, fmt.Sprintf("fp_assets:%d", id)); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.InvalidateStats(id)
	return nil
}

// ProjectWantsVulnScan 项目级漏洞扫描意图：该项目下是否存在勾选了"漏洞扫描"阶段的任务
// （含旧版 standard/deep 模式任务——其语义本就包含漏洞扫描）。
// 新增 Web 资产是否扫描、规则库新增时是否对该项目存量补扫，均由该意图决定。
func (s *Store) ProjectWantsVulnScan(projectID int64) bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM scan_tasks
		WHERE project_id=? AND (phases LIKE '%vulnscan%' OR (COALESCE(phases,'')='' AND mode IN ('standard','deep')))`,
		projectID).Scan(&n)
	return n > 0
}

func (s *Store) ListProjects() ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT * FROM projects ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMaps(rows)
}

func (s *Store) GetProject(id int64) (map[string]any, error) {
	rows, err := s.db.Query(`SELECT * FROM projects WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ms, err := scanMaps(rows)
	if err != nil || len(ms) == 0 {
		return nil, ErrNotFound
	}
	return ms[0], nil
}

// ---------- 资产 Upsert（去重核心） ----------

func (s *Store) UpsertIP(a model.AssetIP) (bool, error) { // returns isNew
	res, err := s.db.Exec(`INSERT INTO asset_ips(project_id,ip,network,source,first_seen) VALUES(?,?,?,?,?)
		ON CONFLICT(project_id,ip) DO NOTHING`, a.ProjectID, a.IP, a.Network, a.Source, NowLocal())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) UpdateIPAlive(ip string, projectID int64, alive bool, method string, latency int64) error {
	_, err := s.db.Exec(`UPDATE asset_ips SET alive=?,probe_method=?,latency_ms=?,last_probe=? WHERE project_id=? AND ip=?`,
		alive, method, latency, NowLocal(), projectID, ip)
	return err
}

func (s *Store) UpdateIPScore(projectID int64, ip string, score int) error {
	_, err := s.db.Exec(`UPDATE asset_ips SET risk_score=? WHERE project_id=? AND ip=?`, score, projectID, ip)
	return err
}

// DomainIPMap 批量查询域名当前记录的解析 IP（域名+端口拼接探测用）
func (s *Store) DomainIPMap(projectID int64, domains []string) map[string]string {
	out := map[string]string{}
	if len(domains) == 0 {
		return out
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(domains)), ",")
	args := make([]any, 0, len(domains)+1)
	args = append(args, projectID)
	for _, d := range domains {
		args = append(args, d)
	}
	rows, err := s.db.Query(`SELECT domain, ip FROM asset_domains WHERE project_id=? AND domain IN (`+ph+`)`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var d, ip string
		if rows.Scan(&d, &ip) == nil && ip != "" {
			out[d] = ip
		}
	}
	return out
}

// OpenPortServices 返回某 IP 全部开放端口的（端口, 服务）列表
func (s *Store) OpenPortServices(projectID int64, ip string) []model.AssetPort {
	out := []model.AssetPort{}
	rows, err := s.db.Query(`SELECT port, service FROM asset_ports WHERE project_id=? AND ip=? AND state='open'`, projectID, ip)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var p model.AssetPort
		if rows.Scan(&p.Port, &p.Service) == nil {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) UpsertDomain(d model.AssetDomain) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO asset_domains(project_id,domain,cname,ip,source,first_seen) VALUES(?,?,?,?,?,?)`,
		d.ProjectID, d.Domain, d.CNAME, d.IP, d.Source, NowLocal())
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.Exec(`UPDATE asset_domains SET cname=?, ip=? WHERE project_id=? AND domain=?`, d.CNAME, d.IP, d.ProjectID, d.Domain)
	return false, err
}

func (s *Store) UpsertPort(p model.AssetPort) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO asset_ports(project_id,ip,port,protocol,state,service,version,banner,category,source,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		p.ProjectID, p.IP, p.Port, p.Protocol, p.State, p.Service, p.Version, p.Banner, p.Category, p.Source, NowLocal())
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.Exec(`UPDATE asset_ports SET state=?,service=?,version=?,banner=?,category=? WHERE project_id=? AND ip=? AND port=? AND protocol=?`,
		p.State, p.Service, p.Version, p.Banner, p.Category, p.ProjectID, p.IP, p.Port, p.Protocol)
	return false, err
}

// UpsertPortsBatch 端口批量入库（单事务）：单 IP 端口扫描结果一次写完，
// 与逐条 UpsertPort 等价，返回每条是否新增
func (s *Store) UpsertPortsBatch(ps []model.AssetPort) ([]bool, error) {
	newFlags := make([]bool, len(ps))
	if len(ps) == 0 {
		return newFlags, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return newFlags, err
	}
	defer tx.Rollback()
	for i, p := range ps {
		res, err := tx.Exec(`INSERT OR IGNORE INTO asset_ports(project_id,ip,port,protocol,state,service,version,banner,category,source,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			p.ProjectID, p.IP, p.Port, p.Protocol, p.State, p.Service, p.Version, p.Banner, p.Category, p.Source, NowLocal())
		if err != nil {
			return newFlags, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			newFlags[i] = true
			continue
		}
		if _, err := tx.Exec(`UPDATE asset_ports SET state=?,service=?,version=?,banner=?,category=? WHERE project_id=? AND ip=? AND port=? AND protocol=?`,
			p.State, p.Service, p.Version, p.Banner, p.Category, p.ProjectID, p.IP, p.Port, p.Protocol); err != nil {
			return newFlags, err
		}
	}
	return newFlags, tx.Commit()
}

func (s *Store) UpsertWeb(w model.AssetWeb) (int64, bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO asset_web(project_id,url,ip,domain,port,protocol,status_code,title,server,content_type,resp_size,certificate,headers,tech,source,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		w.ProjectID, w.URL, w.IP, w.Domain, w.Port, w.Protocol, w.StatusCode, w.Title, w.Server, w.ContentType, w.RespSize, w.Certificate, w.Headers, w.Tech, w.Source, NowLocal())
	if err != nil {
		return 0, false, err
	}
	isNew := false
	if n, _ := res.RowsAffected(); n > 0 {
		isNew = true
	} else {
		s.db.Exec(`UPDATE asset_web SET ip=?,domain=?,port=?,status_code=?,title=?,server=?,content_type=?,resp_size=?,certificate=?,tech=? WHERE project_id=? AND url=?`,
			w.IP, w.Domain, w.Port, w.StatusCode, w.Title, w.Server, w.ContentType, w.RespSize, w.Certificate, w.Tech, w.ProjectID, w.URL)
	}
	var id int64
	s.db.QueryRow(`SELECT id FROM asset_web WHERE project_id=? AND url=?`, w.ProjectID, w.URL).Scan(&id)
	return id, isNew, nil
}

func (s *Store) UpsertURL(u model.AssetURL) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO asset_urls(project_id,web_id,url,method,status_code,content_type,resp_size,source,first_seen) VALUES(?,?,?,?,?,?,?,?,?)`,
		u.ProjectID, u.WebID, u.URL, u.Method, u.StatusCode, u.ContentType, u.RespSize, u.Source, NowLocal())
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	_, err = s.db.Exec(`UPDATE asset_urls SET status_code=?,content_type=?,resp_size=? WHERE project_id=? AND url=?`,
		u.StatusCode, u.ContentType, u.RespSize, u.ProjectID, u.URL)
	return false, err
}

func (s *Store) UpsertFingerprint(f model.AssetFingerprint) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO asset_fingerprints(project_id,web_url,category,name,detail,first_seen) VALUES(?,?,?,?,?,?)`,
		f.ProjectID, f.WebURL, f.Category, f.Name, f.Detail, NowLocal())
	return err
}

// UpsertVuln 漏洞去重: 资产+端口+URL+漏洞ID
// UpsertVuln 漏洞统一入库去重（资产+端口+URL+漏洞ID），返回（库内 ID，是否新增）
func (s *Store) UpsertVuln(v model.Vulnerability) (int64, bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO vulnerabilities(project_id,vuln_id,name,severity,ip,domain,port,url,service,component,description,solution,evidence,request,response,scanner,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.ProjectID, v.VulnID, v.Name, v.Severity, v.IP, v.Domain, v.Port, v.URL, v.Service, v.Component, v.Description, v.Solution, v.Evidence, v.Request, v.Response, v.Scanner, NowLocal(), NowLocal())
	if err != nil {
		return 0, false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		id, _ := res.LastInsertId()
		return id, true, nil
	}
	_, err = s.db.Exec(`UPDATE vulnerabilities SET last_seen=?, evidence=?, request=?, response=? WHERE project_id=? AND ip=? AND port=? AND url=? AND vuln_id=?`,
		NowLocal(), v.Evidence, v.Request, v.Response, v.ProjectID, v.IP, v.Port, v.URL, v.VulnID)
	if err != nil {
		return 0, false, err
	}
	var id int64
	s.db.QueryRow(`SELECT id FROM vulnerabilities WHERE project_id=? AND ip=? AND port=? AND url=? AND vuln_id=?`,
		v.ProjectID, v.IP, v.Port, v.URL, v.VulnID).Scan(&id)
	return id, false, nil
}

// GetVulnerability 漏洞详情（含请求/响应报文）
func (s *Store) GetVulnerability(id int64) (*model.Vulnerability, error) {
	v := &model.Vulnerability{}
	err := s.db.QueryRow(`SELECT id,project_id,vuln_id,name,severity,ip,domain,port,url,service,component,description,solution,evidence,coalesce(request,''),coalesce(response,''),coalesce(mark,''),scanner,coalesce(ai_mark,''),coalesce(ai_confidence,''),coalesce(ai_reasoning,''),first_seen,last_seen
		FROM vulnerabilities WHERE id=?`, id).
		Scan(&v.ID, &v.ProjectID, &v.VulnID, &v.Name, &v.Severity, &v.IP, &v.Domain, &v.Port, &v.URL,
			&v.Service, &v.Component, &v.Description, &v.Solution, &v.Evidence, &v.Request, &v.Response,
			&v.Mark, &v.Scanner, &v.AIMark, &v.AIConfidence, &v.AIReasoning, &v.FirstSeen, &v.LastSeen)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// SetVulnAI AI 研判结果留存（标记照旧写 mark，AI 明细单独留存供详情页展示）
func (s *Store) SetVulnAI(id int64, mark, confidence, reasoning string) error {
	_, err := s.db.Exec(`UPDATE vulnerabilities SET ai_mark=?, ai_confidence=?, ai_reasoning=? WHERE id=?`, mark, confidence, reasoning, id)
	return err
}

// ---------- 任务 ----------

func (s *Store) CreateTask(t *model.ScanTask) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scan_tasks(project_id,name,mode,targets,target_type,ports,status,concurrency,timeout_sec,priority,cron_expr,created_by,scan_interval,phases,subdomain_brute,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ProjectID, t.Name, t.Mode, t.Targets, t.TargetType, t.Ports, "pending", t.Concurrency, t.TimeoutSec, t.Priority, t.CronExpr, t.CreatedBy, t.ScanInterval, t.Phases, boolInt(t.SubdomainBrute), NowLocal())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// scanTaskColumns UpdateTask 允许更新的列白名单（列名会拼入 SQL，禁止外部输入）
var scanTaskColumns = map[string]bool{
	"status": true, "progress": true, "error": true, "started_at": true, "ended_at": true,
	"name": true, "targets": true, "mode": true, "ports": true,
	"concurrency": true, "timeout_sec": true, "priority": true, "scan_interval": true,
	"phases": true, "subdomain_brute": true,
}

func (s *Store) UpdateTask(id int64, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	sets := []string{}
	args := []any{}
	for k, v := range fields {
		if !scanTaskColumns[k] {
			return fmt.Errorf("非法更新字段: %s", k)
		}
		sets = append(sets, k+"=?")
		args = append(args, v)
	}
	args = append(args, id)
	_, err := s.db.Exec(fmt.Sprintf(`UPDATE scan_tasks SET %s WHERE id=?`, strings.Join(sets, ",")), args...)
	return err
}

func (s *Store) GetTask(id int64) (*model.ScanTask, error) {
	t := &model.ScanTask{}
	var started, ended sql.NullString
	var sb int
	err := s.db.QueryRow(`SELECT id,project_id,name,mode,targets,target_type,ports,status,progress,concurrency,timeout_sec,priority,coalesce(cron_expr,''),created_by,coalesce(error,''),created_at,started_at,ended_at,coalesce(scan_interval,''),coalesce(phases,''),coalesce(subdomain_brute,0) FROM scan_tasks WHERE id=?`, id).
		Scan(&t.ID, &t.ProjectID, &t.Name, &t.Mode, &t.Targets, &t.TargetType, &t.Ports, &t.Status, &t.Progress, &t.Concurrency, &t.TimeoutSec, &t.Priority, &t.CronExpr, &t.CreatedBy, &t.Error, &t.CreatedAt, &started, &ended, &t.ScanInterval, &t.Phases, &sb)
	t.SubdomainBrute = sb == 1
	if err != nil {
		return nil, err
	}
	if started.Valid {
		if ts := timeParse(started); !ts.IsZero() {
			t.StartedAt = &ts
		}
	}
	if ended.Valid {
		if te := timeParse(ended); !te.IsZero() {
			t.EndedAt = &te
		}
	}
	return t, nil
}

// NextPendingTask 取下一个待执行任务（优先级高者优先）
func (s *Store) NextPendingTask() (int64, bool) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM scan_tasks WHERE status='pending' ORDER BY priority ASC, id ASC LIMIT 1`).Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

// DeleteTask 删除任务及其日志
func (s *Store) DeleteTask(id int64) error {
	s.db.Exec(`DELETE FROM scan_logs WHERE task_id=?`, id)
	_, err := s.db.Exec(`DELETE FROM scan_tasks WHERE id=?`, id)
	return err
}

// LogTask 任务日志落库，并镜像到控制台（console 运行日志：资产采集 / 漏洞引擎全程可见）。
// 合成任务（ID<=0：实时扫描、手动导入触发的检测链）不落库，仅输出控制台。
func (s *Store) LogTask(taskID int64, level, msg string) {
	tag := ""
	switch level {
	case "warn":
		tag = "[警告]"
	case "error":
		tag = "[错误]"
	}
	if taskID <= 0 {
		log.Printf("[实时扫描]%s %s", tag, msg)
		return
	}
	s.db.Exec(`INSERT INTO scan_logs(task_id,level,message,created_at) VALUES(?,?,?,?)`, taskID, level, msg, NowLocal())
	log.Printf("[任务#%d]%s %s", taskID, tag, msg)
}

func (s *Store) TaskLogs(taskID int64, limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT * FROM scan_logs WHERE task_id=? ORDER BY id DESC LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMaps(rows)
}

func (s *Store) AddChange(c model.AssetChange) {
	s.db.Exec(`INSERT INTO asset_changes(project_id,task_id,asset_type,asset,change,detail,created_at) VALUES(?,?,?,?,?,?,?)`,
		c.ProjectID, c.TaskID, c.AssetType, c.Asset, c.Change, c.Detail, NowLocal())
}

// RecurringTasks 所有配置了扫描周期的任务
func (s *Store) RecurringTasks() ([]*model.ScanTask, error) {
	rows, err := s.db.Query(`SELECT id FROM scan_tasks WHERE coalesce(scan_interval,'') != '' ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	out := []*model.ScanTask{}
	for _, id := range ids {
		if t, err := s.GetTask(id); err == nil {
			out = append(out, t)
		}
	}
	return out, nil
}

// RequeueTask 周期任务到期重新排队
func (s *Store) RequeueTask(id int64) error {
	_, err := s.db.Exec(`UPDATE scan_tasks SET status='pending', progress=0, error='' WHERE id=?`, id)
	return err
}

// RecoverOrphanRunning 启动恢复：上次进程退出时仍处于 running 的任务没有存活执行协程，
// 复位为 pending 重新执行（否则永久卡死：轮询只取 pending、周期调度只认 done/failed，
// 周期任务会就此停止周期扫描）。返回恢复的任务 ID。
func (s *Store) RecoverOrphanRunning() []int64 {
	rows, err := s.db.Query(`SELECT id FROM scan_tasks WHERE status='running'`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		s.db.Exec(`UPDATE scan_tasks SET status='pending', progress=0 WHERE id=?`, id)
		s.LogTask(id, "warn", "检测到进程重启，任务上次被中断：已自动恢复排队重新执行")
	}
	return ids
}

// ClearAssets 清空项目全部资产（各类资产表；web 级联清理其 URL 与指纹）
func (s *Store) ClearAssets(projectID int64, assetType string) (int64, error) {
	tableMap := map[string]string{"ip": "asset_ips", "domain": "asset_domains", "port": "asset_ports", "web": "asset_web", "url": "asset_urls"}
	tbl, ok := tableMap[assetType]
	if !ok {
		return 0, fmt.Errorf("无效资产类型: %s", assetType)
	}
	if assetType == "web" {
		// 级联：web 衍生的 URL（web_id 挂钩的）与指纹一并清理；独立导入的 URL（web_id=0）保留
		s.db.Exec(`DELETE FROM asset_urls WHERE project_id=? AND web_id IN (SELECT id FROM asset_web WHERE project_id=?)`, projectID, projectID)
		s.db.Exec(`DELETE FROM asset_fingerprints WHERE project_id=? AND web_url IN (SELECT url FROM asset_web WHERE project_id=?)`, projectID, projectID)
	}
	res, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE project_id=?", tbl), projectID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	s.InvalidateStats(projectID)
	return n, nil
}

// DeleteWebCascade 删除单个 Web 资产并级联清理其 URL 与指纹，返回删除的 URL 数

// DeleteWebCascade 删除单个 Web 资产并级联清理其 URL 与指纹，返回删除的 URL 数
func (s *Store) DeleteWebCascade(projectID, webID int64) (int64, error) {
	var url string
	if err := s.db.QueryRow(`SELECT url FROM asset_web WHERE id=? AND project_id=?`, webID, projectID).Scan(&url); err != nil {
		return 0, err
	}
	if _, err := s.db.Exec(`DELETE FROM asset_urls WHERE project_id=? AND web_id=?`, projectID, webID); err != nil {
		return 0, err
	}
	s.db.Exec(`DELETE FROM asset_fingerprints WHERE project_id=? AND web_url=?`, projectID, url)
	res, err := s.db.Exec(`DELETE FROM asset_web WHERE id=? AND project_id=?`, webID, projectID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *Store) ListChanges(projectID int64, limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT * FROM asset_changes WHERE project_id=? ORDER BY id DESC LIMIT ?`, projectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMaps(rows)
}

// ListChangesPaged 变化记录分页查询（按 id 倒序），q 匹配资产/详情，typ/change 为可选过滤，返回当前页与总数
func (s *Store) ListChangesPaged(projectID int64, q, typ, change string, limit, offset int) ([]map[string]any, int, error) {
	where, args := `project_id=?`, []any{projectID}
	if q != "" {
		where += ` AND (asset LIKE ? OR detail LIKE ?)`
		args = append(args, "%"+q+"%", "%"+q+"%")
	}
	if typ != "" {
		where += ` AND asset_type=?`
		args = append(args, typ)
	}
	if change != "" {
		where += ` AND change=?`
		args = append(args, change)
	}
	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM asset_changes WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`SELECT * FROM asset_changes WHERE `+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	ms, err := scanMaps(rows)
	return ms, total, err
}

func (s *Store) SystemLog(l model.SystemLog) {
	s.db.Exec(`INSERT INTO system_logs(username,action,object,client_ip,result,created_at) VALUES(?,?,?,?,?,?)`,
		l.Username, l.Action, l.Object, l.ClientIP, l.Result, NowLocal())
}

func (s *Store) ListSystemLogs(limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(`SELECT * FROM system_logs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMaps(rows)
}

// ---------- 系统设置 ----------

// GetSetting 读取系统设置（不存在返回空串）
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetSetting 写入系统设置（如运行时修改的代理配置）
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ---------- 统计 / 搜索 ----------

// statsCacheEntry 仪表盘统计短缓存：多表 COUNT/GROUP BY 聚合在 5s 轮询下重复执行，
// 缓存 2 秒（扫描高峰 UI 数据最多滞后 2s，轮询命中率 ~60%）；返回值为共享只读 map
type statsCacheEntry struct {
	data map[string]any
	at   time.Time
}

var (
	statsCacheMu sync.Mutex
	statsCache   = map[int64]statsCacheEntry{}
)

func (s *Store) ProjectStats(projectID int64) (map[string]any, error) {
	statsCacheMu.Lock()
	if e, ok := statsCache[projectID]; ok && time.Since(e.at) < 2*time.Second {
		statsCacheMu.Unlock()
		return e.data, nil
	}
	statsCacheMu.Unlock()
	stats := map[string]any{}
	counts := map[string]string{
		"ips": "asset_ips", "domains": "asset_domains", "ports": "asset_ports",
		"web": "asset_web", "urls": "asset_urls", "vulns": "vulnerabilities",
	}
	for k, table := range counts {
		var n int
		if err := s.db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE project_id=?`, table), projectID).Scan(&n); err != nil {
			return nil, err
		}
		stats[k] = n
	}
	bySev := map[string]any{}
	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM vulnerabilities WHERE project_id=? GROUP BY severity`, projectID)
	if err == nil {
		for rows.Next() {
			var sev string
			var n int
			rows.Scan(&sev, &n)
			bySev[sev] = n
		}
		rows.Close()
	}
	stats["vuln_by_severity"] = bySev
	// 等级 × 标记 分组计数（仪表盘每行内联实报/误报/未标记细分）
	bySevMarks := map[string]map[string]int{}
	if mrows, err := s.db.Query(`SELECT severity, COALESCE(mark,''), COUNT(*) FROM vulnerabilities WHERE project_id=? GROUP BY severity, mark`, projectID); err == nil {
		for mrows.Next() {
			var sev, mk string
			var n int
			mrows.Scan(&sev, &mk, &n)
			if bySevMarks[sev] == nil {
				bySevMarks[sev] = map[string]int{}
			}
			bySevMarks[sev][mk] = n
		}
		mrows.Close()
	}
	stats["vuln_by_severity_marks"] = bySevMarks
	// 弱点按类型统计 + 未处置（未标记）计数（仪表盘实时展示）
	var wkTotal, wkUnmarked int
	s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(CASE WHEN COALESCE(mark,'')='' THEN 1 ELSE 0 END),0) FROM weaknesses WHERE project_id=?`, projectID).Scan(&wkTotal, &wkUnmarked)
	stats["weaknesses"] = wkTotal
	stats["weakness_unmarked"] = wkUnmarked
	byType := map[string]any{}
	if wrows, err := s.db.Query(`SELECT type, COUNT(*) FROM weaknesses WHERE project_id=? GROUP BY type`, projectID); err == nil {
		for wrows.Next() {
			var t string
			var n int
			wrows.Scan(&t, &n)
			byType[t] = n
		}
		wrows.Close()
	}
	stats["weakness_by_type"] = byType
	// 类型 × 标记 分组计数（同漏洞口径）
	byTypeMarks := map[string]map[string]int{}
	if trows, err := s.db.Query(`SELECT type, COALESCE(mark,''), COUNT(*) FROM weaknesses WHERE project_id=? GROUP BY type, mark`, projectID); err == nil {
		for trows.Next() {
			var tp, mk string
			var n int
			trows.Scan(&tp, &mk, &n)
			if byTypeMarks[tp] == nil {
				byTypeMarks[tp] = map[string]int{}
			}
			byTypeMarks[tp][mk] = n
		}
		trows.Close()
	}
	stats["weakness_by_type_marks"] = byTypeMarks
	var vulnUnmarked int
	s.db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE project_id=? AND COALESCE(mark,'')=''`, projectID).Scan(&vulnUnmarked)
	stats["vuln_unmarked"] = vulnUnmarked
	// 标记维度计数（仪表盘实报/误报/未标记展示，漏洞与弱点各一组）
	var vulnConfirmed, vulnFalse int
	s.db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN mark='confirmed' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN mark='false_positive' THEN 1 ELSE 0 END),0) FROM vulnerabilities WHERE project_id=?`, projectID).Scan(&vulnConfirmed, &vulnFalse)
	stats["vuln_confirmed"] = vulnConfirmed
	stats["vuln_false_positive"] = vulnFalse
	var wkConfirmed, wkFalse int
	s.db.QueryRow(`SELECT COALESCE(SUM(CASE WHEN mark='confirmed' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN mark='false_positive' THEN 1 ELSE 0 END),0) FROM weaknesses WHERE project_id=?`, projectID).Scan(&wkConfirmed, &wkFalse)
	stats["weakness_confirmed"] = wkConfirmed
	stats["weakness_false_positive"] = wkFalse
	statsCacheMu.Lock()
	statsCache[projectID] = statsCacheEntry{data: stats, at: time.Now()}
	statsCacheMu.Unlock()
	return stats, nil
}

// InvalidateStats 项目数据整体变化（删除项目/清空资产）时失效统计缓存
func (s *Store) InvalidateStats(projectID int64) {
	statsCacheMu.Lock()
	delete(statsCache, projectID)
	statsCacheMu.Unlock()
}

func (s *Store) Search(projectID int64, keyword string) ([]map[string]any, error) {
	kw := "%" + keyword + "%"
	results := []map[string]any{}
	queries := map[string]string{
		"ip":       `SELECT ip AS value, 'ip' AS type FROM asset_ips WHERE project_id=? AND ip LIKE ?`,
		"domain":   `SELECT domain AS value, 'domain' AS type FROM asset_domains WHERE project_id=? AND domain LIKE ?`,
		"url":      `SELECT url AS value, 'web' AS type FROM asset_web WHERE project_id=? AND (url LIKE ? OR title LIKE ?)`,
		"port":     `SELECT ip||':'||port AS value, 'port' AS type FROM asset_ports WHERE project_id=? AND (ip LIKE ? OR CAST(port AS TEXT) LIKE ?)`,
		"vulnerab": `SELECT name||' @ '||coalesce(url,ip) AS value, 'vulnerability' AS type FROM vulnerabilities WHERE project_id=? AND (name LIKE ? OR vuln_id LIKE ? OR component LIKE ?)`,
	}
	for typ, q := range queries {
		args := []any{projectID}
		n := strings.Count(q, "?") - 1
		for i := 0; i < n; i++ {
			args = append(args, kw)
		}
		rows, err := s.db.Query(q, args...)
		if err != nil {
			continue
		}
		ms, _ := scanMaps(rows)
		rows.Close()
		for _, m := range ms {
			m["category"] = typ
			results = append(results, m)
		}
	}
	return results, nil
}

// IPDetail IP 资产详情：关联域名/端口/Web/漏洞（资产关联与画像）
func (s *Store) IPDetail(projectID int64, ip string) (map[string]any, error) {
	out := map[string]any{"ip": ip}
	rows, _ := s.db.Query(`SELECT * FROM asset_ips WHERE project_id=? AND ip=?`, projectID, ip)
	ms, _ := scanMaps(rows)
	rows.Close()
	if len(ms) > 0 {
		out["info"] = ms[0]
	}
	for key, q := range map[string]string{
		"domains":         `SELECT * FROM asset_domains WHERE project_id=? AND ip=?`,
		"ports":           `SELECT * FROM asset_ports WHERE project_id=? AND ip=? ORDER BY port`,
		"web":             `SELECT * FROM asset_web WHERE project_id=? AND ip=?`,
		"vulnerabilities": `SELECT * FROM vulnerabilities WHERE project_id=? AND ip=? ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
	} {
		rows, err := s.db.Query(q, projectID, ip)
		if err != nil {
			return nil, err
		}
		list, _ := scanMaps(rows)
		rows.Close()
		out[key] = list
	}
	return out, nil
}
