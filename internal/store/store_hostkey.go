package store

import (
	"database/sql"
	"errors"
	"sync"
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

var hostKeyOnce sync.Once
var hostKeyErr error

func (s *Store) ensureHostKeys() error {
	hostKeyOnce.Do(func() {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS known_hosts (
				host        TEXT NOT NULL,
				port        INTEGER NOT NULL,
				key_type    TEXT NOT NULL DEFAULT '',
				fingerprint TEXT NOT NULL DEFAULT '',
				first_seen  INTEGER NOT NULL DEFAULT 0,
				last_seen   INTEGER NOT NULL DEFAULT 0,
				PRIMARY KEY (host, port)
			)`,
		}
		for _, q := range stmts {
			if _, err := s.db.Exec(q); err != nil {
				hostKeyErr = err
				return
			}
		}
	})
	return hostKeyErr
}

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
	now := time.Now().Unix()
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
		time.Now().Unix(), host, port)
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
