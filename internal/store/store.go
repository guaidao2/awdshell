// Package store 提供本地持久化（SQLite，纯 Go 驱动免 CGO）。
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"

	_ "modernc.org/sqlite"
)

// ErrNotFound 表示记录不存在。
var ErrNotFound = errors.New("记录不存在")

// Store 是数据访问入口。
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS targets(
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  host         TEXT NOT NULL,
  port         INTEGER NOT NULL DEFAULT 22,
  username     TEXT NOT NULL,
  auth_kind    TEXT NOT NULL DEFAULT 'password',
  secret_id    TEXT NOT NULL DEFAULT '',
  tags         TEXT NOT NULL DEFAULT '[]',
  grp          TEXT NOT NULL DEFAULT '',
  start_dir    TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS secrets(
  id         TEXT PRIMARY KEY,
  nonce      BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connections(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id  TEXT NOT NULL DEFAULT '',
  name       TEXT NOT NULL DEFAULT '',
  host       TEXT NOT NULL,
  port       INTEGER NOT NULL,
  username   TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER NOT NULL DEFAULT 0,
  exit_code  INTEGER NOT NULL DEFAULT 0,
  bytes_in   INTEGER NOT NULL DEFAULT 0,
  bytes_out  INTEGER NOT NULL DEFAULT 0,
  error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_connections_started ON connections(started_at DESC);
CREATE TABLE IF NOT EXISTS settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`

// Open 打开（或创建）数据库。
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 桌面场景单连接足够，且能避免 SQLITE_BUSY。
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("执行 %s 失败: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化表结构失败: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().UnixMilli() }

// ---------- 目标 ----------

// ListTargets 返回全部目标（按名称排序）。
func (s *Store) ListTargets() ([]domain.Target, error) {
	rows, err := s.db.Query(`SELECT id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at FROM targets ORDER BY grp ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询目标失败: %w", err)
	}
	defer rows.Close()
	return scanTargets(rows)
}

// RecentTargets 返回最近使用过的目标。
func (s *Store) RecentTargets(limit int) ([]domain.Target, error) {
	rows, err := s.db.Query(`SELECT id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at FROM targets
		WHERE last_used_at > 0 ORDER BY last_used_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询最近目标失败: %w", err)
	}
	defer rows.Close()
	return scanTargets(rows)
}

func scanTargets(rows *sql.Rows) ([]domain.Target, error) {
	out := []domain.Target{}
	for rows.Next() {
		var t domain.Target
		var tags string
		if err := rows.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.Username, &t.AuthKind,
			&t.SecretID, &tags, &t.Group, &t.StartDir, &t.CreatedAt, &t.UpdatedAt, &t.LastUsedAt); err != nil {
			return nil, fmt.Errorf("读取目标失败: %w", err)
		}
		_ = json.Unmarshal([]byte(tags), &t.Tags)
		if t.Tags == nil {
			t.Tags = []string{}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTarget 取单个目标。
func (s *Store) GetTarget(id string) (domain.Target, error) {
	var t domain.Target
	var tags string
	err := s.db.QueryRow(`SELECT id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at FROM targets WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.Username, &t.AuthKind,
			&t.SecretID, &tags, &t.Group, &t.StartDir, &t.CreatedAt, &t.UpdatedAt, &t.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, fmt.Errorf("读取目标失败: %w", err)
	}
	_ = json.Unmarshal([]byte(tags), &t.Tags)
	if t.Tags == nil {
		t.Tags = []string{}
	}
	return t, nil
}

// SaveTarget 新建或更新目标。
func (s *Store) SaveTarget(t domain.Target) (domain.Target, error) {
	ts := now()
	tags, _ := json.Marshal(t.Tags)
	if t.Tags == nil {
		tags = []byte("[]")
	}
	if t.CreatedAt == 0 {
		t.CreatedAt = ts
	}
	t.UpdatedAt = ts
	_, err := s.db.Exec(`INSERT INTO targets(id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, host=excluded.host, port=excluded.port, username=excluded.username,
			auth_kind=excluded.auth_kind, secret_id=excluded.secret_id, tags=excluded.tags,
			grp=excluded.grp, start_dir=excluded.start_dir, updated_at=excluded.updated_at`,
		t.ID, t.Name, t.Host, t.Port, t.Username, t.AuthKind, t.SecretID, string(tags), t.Group, t.StartDir,
		t.CreatedAt, t.UpdatedAt, t.LastUsedAt)
	if err != nil {
		return t, fmt.Errorf("保存目标失败: %w", err)
	}
	return t, nil
}

// DeleteTarget 删除目标及其凭据。
func (s *Store) DeleteTarget(id string) error {
	t, err := s.GetTarget(id)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM targets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("删除目标失败: %w", err)
	}
	if t.SecretID != "" {
		_, _ = s.db.Exec(`DELETE FROM secrets WHERE id = ?`, t.SecretID)
	}
	return nil
}

// TouchTarget 更新最后使用时间。
func (s *Store) TouchTarget(id string) error {
	_, err := s.db.Exec(`UPDATE targets SET last_used_at = ? WHERE id = ?`, now(), id)
	if err != nil {
		return fmt.Errorf("更新使用时间失败: %w", err)
	}
	return nil
}

// ---------- 凭据密文 ----------

// PutSecret 写入（或覆盖）一条密文。
func (s *Store) PutSecret(id string, nonce, ciphertext []byte) error {
	_, err := s.db.Exec(`INSERT INTO secrets(id,nonce,ciphertext,created_at) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext`,
		id, nonce, ciphertext, now())
	if err != nil {
		return fmt.Errorf("保存凭据失败: %w", err)
	}
	return nil
}

// GetSecret 读取一条密文。
func (s *Store) GetSecret(id string) (nonce, ciphertext []byte, err error) {
	err = s.db.QueryRow(`SELECT nonce,ciphertext FROM secrets WHERE id = ?`, id).Scan(&nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("读取凭据失败: %w", err)
	}
	return nonce, ciphertext, nil
}

// ---------- 连接历史 ----------

// AddConnection 记录一次连接开始。
func (s *Store) AddConnection(rec domain.ConnectionRecord) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO connections(target_id,name,host,port,username,started_at)
		VALUES(?,?,?,?,?,?)`, rec.TargetID, rec.Name, rec.Host, rec.Port, rec.Username, rec.StartedAt)
	if err != nil {
		return 0, fmt.Errorf("写入连接历史失败: %w", err)
	}
	return res.LastInsertId()
}

// FinishConnection 更新一次连接的结束状态。
func (s *Store) FinishConnection(id int64, exitCode int, bytesIn, bytesOut int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE connections SET ended_at=?, exit_code=?, bytes_in=?, bytes_out=?, error=?
		WHERE id = ?`, now(), exitCode, bytesIn, bytesOut, errMsg, id)
	if err != nil {
		return fmt.Errorf("更新连接历史失败: %w", err)
	}
	return nil
}

// ListConnections 返回连接历史。
func (s *Store) ListConnections(limit int) ([]domain.ConnectionRecord, error) {
	rows, err := s.db.Query(`SELECT id,target_id,name,host,port,username,started_at,ended_at,
		exit_code,bytes_in,bytes_out,error FROM connections ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询连接历史失败: %w", err)
	}
	defer rows.Close()
	out := []domain.ConnectionRecord{}
	for rows.Next() {
		var c domain.ConnectionRecord
		if err := rows.Scan(&c.ID, &c.TargetID, &c.Name, &c.Host, &c.Port, &c.Username,
			&c.StartedAt, &c.EndedAt, &c.ExitCode, &c.BytesIn, &c.BytesOut, &c.Error); err != nil {
			return nil, fmt.Errorf("读取连接历史失败: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- 设置 ----------

// GetSetting 读取一个设置项。
func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

// PutSetting 写入一个设置项。
func (s *Store) PutSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("保存设置失败: %w", err)
	}
	return nil
}

// PruneConnections 清理连接历史：删掉超过 keepDays 天的记录，并且只保留最近 keepMax 条。
// 两个条件任一为 0 表示该条件不启用。返回删除的行数。
func (s *Store) PruneConnections(keepDays, keepMax int) (int64, error) {
	var removed int64
	if keepDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -keepDays).UnixMilli()
		res, err := s.db.Exec(`DELETE FROM connections WHERE started_at < ?`, cutoff)
		if err != nil {
			return removed, fmt.Errorf("清理过期连接历史失败: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if keepMax > 0 {
		res, err := s.db.Exec(`DELETE FROM connections WHERE id NOT IN (
			SELECT id FROM connections ORDER BY started_at DESC LIMIT ?)`, keepMax)
		if err != nil {
			return removed, fmt.Errorf("清理超额连接历史失败: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	return removed, nil
}

// MarkStaleConnections 把"没有结束时间"的连接记录标记为中断。
// 程序被强杀、崩溃或断电时会留下这种记录（ended_at = 0），启动时清理一次，避免历史里永远挂着"进行中"。
func (s *Store) MarkStaleConnections(reason string) (int64, error) {
	res, err := s.db.Exec(`UPDATE connections SET ended_at = started_at, exit_code = 1, error = ?
		WHERE ended_at = 0`, reason)
	if err != nil {
		return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// migrate 为老库补新增列（SQLite 不支持 ADD COLUMN IF NOT EXISTS，先查 PRAGMA）。
func migrate(db *sql.DB) error {
	have := map[string]bool{}
	rows, err := db.Query(`PRAGMA table_info(targets)`)
	if err != nil {
		return fmt.Errorf("读取表结构失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("解析表结构失败: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !have["start_dir"] {
		if _, err := db.Exec(`ALTER TABLE targets ADD COLUMN start_dir TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("迁移 start_dir 列失败: %w", err)
		}
	}
	return nil
}
