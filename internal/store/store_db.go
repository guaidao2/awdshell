package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DBConn 是一条保存下来的数据库连接配置。
//
// 密码不以明文落盘：这里只存 SecretID，密文在 secrets 表里，
// 与 SSH 凭据走同一套 XChaCha20-Poly1305 加密。
type DBConn struct {
	ID        string `json:"id"`
	TargetID  string `json:"target_id"`
	Target    string `json:"target"` // 目标名，列表里显示用
	Name      string `json:"name"`
	Kind      string `json:"kind"` // mysql | postgres
	Addr      string `json:"addr"`
	Username  string `json:"username"`
	Database  string `json:"database"`
	SecretID  string `json:"-"`
	ReadOnly  bool   `json:"read_only"`
	MaxRows   int    `json:"max_rows"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// ensureDBConns 是历史遗留的空实现 —— db_conns 已并入 store.go 的 schema，
// 每次 Open 都会建。保留函数只为不惊动调用方。
//
// 原来的实现挂在包级 sync.Once 上，而 sync.Once 是**进程级**而不是"每个库一次"：
// 同进程出现第二个 *Store 时这张表就是没有（实测 ListDBConns 报 no such table），
// 而且包级错误变量只试一次，首次失败（瞬时 locked、磁盘满）之后本进程永远返回旧错误。
func (s *Store) ensureDBConns() error { return nil }

// SaveDBConn 新增或更新一条连接配置。
func (s *Store) SaveDBConn(c DBConn) (DBConn, error) {
	if err := s.ensureDBConns(); err != nil {
		return c, err
	}
	now := time.Now().UnixMilli()
	if c.CreatedAt == 0 {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	if c.MaxRows <= 0 {
		c.MaxRows = 500
	}
	_, err := s.db.Exec(`INSERT INTO db_conns
		(id, target_id, target, name, kind, addr, username, database, secret_id, read_only, max_rows, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			target_id = excluded.target_id,
			target    = excluded.target,
			name      = excluded.name,
			kind      = excluded.kind,
			addr      = excluded.addr,
			username  = excluded.username,
			database  = excluded.database,
			secret_id = excluded.secret_id,
			read_only = excluded.read_only,
			max_rows  = excluded.max_rows,
			updated_at = excluded.updated_at`,
		c.ID, c.TargetID, c.Target, c.Name, c.Kind, c.Addr, c.Username, c.Database,
		c.SecretID, boolToInt(c.ReadOnly), c.MaxRows, c.CreatedAt, c.UpdatedAt)
	if err != nil {
		return c, err
	}
	return c, nil
}

// ListDBConns 列出连接配置；targetID 为空时返回全部。
func (s *Store) ListDBConns(targetID string) ([]DBConn, error) {
	if err := s.ensureDBConns(); err != nil {
		return nil, err
	}
	query := `SELECT id, target_id, target, name, kind, addr, username, database,
		secret_id, read_only, max_rows, created_at, updated_at FROM db_conns`
	args := []any{}
	if targetID != "" {
		query += ` WHERE target_id = ?`
		args = append(args, targetID)
	}
	query += ` ORDER BY name, created_at`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []DBConn{}
	for rows.Next() {
		var c DBConn
		var ro int
		if err := rows.Scan(&c.ID, &c.TargetID, &c.Target, &c.Name, &c.Kind, &c.Addr,
			&c.Username, &c.Database, &c.SecretID, &ro, &c.MaxRows, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.ReadOnly = ro == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetDBConn 取一条连接配置。
func (s *Store) GetDBConn(id string) (DBConn, error) {
	if err := s.ensureDBConns(); err != nil {
		return DBConn{}, err
	}
	var c DBConn
	var ro int
	err := s.db.QueryRow(`SELECT id, target_id, target, name, kind, addr, username, database,
		secret_id, read_only, max_rows, created_at, updated_at FROM db_conns WHERE id = ?`, id).
		Scan(&c.ID, &c.TargetID, &c.Target, &c.Name, &c.Kind, &c.Addr,
			&c.Username, &c.Database, &c.SecretID, &ro, &c.MaxRows, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// 与 store.go 里其它 Get 保持一致：调用方会把它包进用户可见文案，
		// 回原始 sql.ErrNoRows 会让界面出现 sql: no rows in result set。
		return DBConn{}, ErrNotFound
	}
	if err != nil {
		return DBConn{}, err
	}
	c.ReadOnly = ro == 1
	return c, nil
}

// DeleteDBConn 删除连接配置，并清掉它对应的密文。
//
// 两条 DELETE 放在**一个事务**里，而且 GetDBConn 出错时**不再照删配置**：
// 以前读配置失败（瞬时 locked、行不存在）也照样往下删 db_conns，密文却删不掉，
// 结果要么留孤儿密文、要么在"没读到密文 id"的情况下把配置删得只剩个空壳。
// 现在读不到就直接返回错误，什么都不动。
func (s *Store) DeleteDBConn(id string) error {
	if err := s.ensureDBConns(); err != nil {
		return err
	}
	c, err := s.GetDBConn(id)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // 成功后 Rollback 返回 ErrTxDone，无害

	if c.SecretID != "" {
		if _, err := tx.Exec(`DELETE FROM secrets WHERE id = ?`, c.SecretID); err != nil {
			return fmt.Errorf("删除数据库连接凭据失败: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM db_conns WHERE id = ?`, id); err != nil {
		return fmt.Errorf("删除数据库连接失败: %w", err)
	}
	return tx.Commit()
}

// DeleteDBConnsOfTarget 删除某个目标下的全部连接配置（目标被删时调用）。
//
// **空 targetID 一律拒绝**：db_conns 里 target_id 的默认值就是空串（早期没归属
// 目标的配置、或按连接名直接建的配置），传空串进来会命中 `WHERE target_id = ”`，
// 把这一批**全局**配置一起删掉（实测 3 条删成 1 条）。调用方要删全部必须显式说清楚。
func (s *Store) DeleteDBConnsOfTarget(targetID string) error {
	if strings.TrimSpace(targetID) == "" {
		return errors.New("拒绝按空 target_id 删除数据库连接配置（会误删不属于任何目标的全局配置）")
	}
	if err := s.ensureDBConns(); err != nil {
		return err
	}
	list, err := s.ListDBConns(targetID)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // 成功后 Rollback 返回 ErrTxDone，无害

	for _, c := range list {
		if c.SecretID != "" {
			if _, err := tx.Exec(`DELETE FROM secrets WHERE id = ?`, c.SecretID); err != nil {
				return fmt.Errorf("删除数据库连接凭据失败: %w", err)
			}
		}
	}
	if _, err := tx.Exec(`DELETE FROM db_conns WHERE target_id = ?`, targetID); err != nil {
		return fmt.Errorf("删除数据库连接失败: %w", err)
	}
	return tx.Commit()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
