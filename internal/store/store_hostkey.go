package store

import (
	"database/sql"
	"errors"
	"time"
)

// HostKey 是一台主机被记录下来的主机密钥指纹。
type HostKey struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

// ensureHostKeys 是历史遗留的空实现 —— known_hosts 已并入 store.go 的 schema，
// 每次 Open 都会建。保留函数只为不惊动调用方。
//
// 原来挂在包级 sync.Once 上：sync.Once 是**进程级**而不是"每个库一次"，
// 同进程第二个 *Store 上这张表就是没有，且包级错误只试一次、失败后永不再建。
func (s *Store) ensureHostKeys() error { return nil }

// GetHostKey 取一台主机已记录的密钥；没有记录时返回 (nil, nil)。
func (s *Store) GetHostKey(host string, port int) (*HostKey, error) {
	if err := s.ensureHostKeys(); err != nil {
		return nil, err
	}
	var hk HostKey
	err := s.db.QueryRow(`SELECT host, port, key_type, fingerprint, first_seen, last_seen
		FROM known_hosts WHERE host = ? AND port = ?`, host, port).
		Scan(&hk.Host, &hk.Port, &hk.KeyType, &hk.Fingerprint, &hk.FirstSeen, &hk.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &hk, nil
}

// SaveHostKey 记录（或覆盖）主机密钥。
func (s *Store) SaveHostKey(hk HostKey) error {
	if err := s.ensureHostKeys(); err != nil {
		return err
	}
	// 全项目其它时间戳都是**毫秒**；这里以前用秒，而读侧没有 normalizeTS，
	// 于是 first_seen / last_seen 会显示成 1970-01-21。
	now := time.Now().UnixMilli()
	if hk.FirstSeen == 0 {
		hk.FirstSeen = now
	}
	hk.LastSeen = now
	_, err := s.db.Exec(`INSERT INTO known_hosts (host, port, key_type, fingerprint, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, port) DO UPDATE SET
			key_type = excluded.key_type,
			fingerprint = excluded.fingerprint,
			last_seen = excluded.last_seen`,
		hk.Host, hk.Port, hk.KeyType, hk.Fingerprint, hk.FirstSeen, hk.LastSeen)
	return err
}

// TouchHostKey 更新最近使用时间。
func (s *Store) TouchHostKey(host string, port int) error {
	if err := s.ensureHostKeys(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE known_hosts SET last_seen = ? WHERE host = ? AND port = ?`,
		time.Now().UnixMilli(), host, port)
	return err
}

// ForgetHostKey 清除一台主机的密钥记录（确认对端换过密钥后使用）。
func (s *Store) ForgetHostKey(host string, port int) (int64, error) {
	if err := s.ensureHostKeys(); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM known_hosts WHERE host = ? AND port = ?`, host, port)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListHostKeys 列出全部已记录的主机密钥。
func (s *Store) ListHostKeys() ([]HostKey, error) {
	if err := s.ensureHostKeys(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT host, port, key_type, fingerprint, first_seen, last_seen
		FROM known_hosts ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []HostKey{}
	for rows.Next() {
		var hk HostKey
		if err := rows.Scan(&hk.Host, &hk.Port, &hk.KeyType, &hk.Fingerprint, &hk.FirstSeen, &hk.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, hk)
	}
	return out, rows.Err()
}
