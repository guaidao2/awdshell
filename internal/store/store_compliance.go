package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// ComplianceReport 是一次基线核查的留存记录。
//
// 为什么要落库：核查报告原本只活在前端页面上，切个目标或关掉页面就没了，
// "这台机器上次什么结论"根本回答不了，也做不了前后对比。
type ComplianceReport struct {
	ID        int64           `json:"id"`
	TS        int64           `json:"ts"`
	TargetID  string          `json:"target_id"`
	Target    string          `json:"target"`
	Score     int             `json:"score"`
	Total     int             `json:"total"`
	Pass      int             `json:"pass"`
	Fail      int             `json:"fail"`
	Manual    int             `json:"manual"`
	Error     int             `json:"error"`
	ElapsedMs int64           `json:"elapsed_ms"`
	Results   json.RawMessage `json:"results"` // 完整结果，供回看与对比
}

var complianceOnce sync.Once
var complianceErr error

func (s *Store) ensureComplianceReports() error {
	complianceOnce.Do(func() {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS compliance_reports (
				id         INTEGER PRIMARY KEY AUTOINCREMENT,
				ts         INTEGER NOT NULL,
				target_id  TEXT NOT NULL DEFAULT '',
				target     TEXT NOT NULL DEFAULT '',
				score      INTEGER NOT NULL DEFAULT 0,
				total      INTEGER NOT NULL DEFAULT 0,
				pass       INTEGER NOT NULL DEFAULT 0,
				fail       INTEGER NOT NULL DEFAULT 0,
				manual     INTEGER NOT NULL DEFAULT 0,
				err_count  INTEGER NOT NULL DEFAULT 0,
				elapsed_ms INTEGER NOT NULL DEFAULT 0,
				results    TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX IF NOT EXISTS idx_compliance_ts ON compliance_reports(ts)`,
			`CREATE INDEX IF NOT EXISTS idx_compliance_target ON compliance_reports(target_id)`,
		}
		for _, q := range stmts {
			if _, err := s.db.Exec(q); err != nil {
				complianceErr = err
				return
			}
		}
	})
	return complianceErr
}

// SaveComplianceReport 保存一次核查报告。
func (s *Store) SaveComplianceReport(r ComplianceReport) (int64, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return 0, err
	}
	if r.TS == 0 {
		r.TS = time.Now().Unix()
	}
	res, err := s.db.Exec(`INSERT INTO compliance_reports
		(ts, target_id, target, score, total, pass, fail, manual, err_count, elapsed_ms, results)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.TS, r.TargetID, r.Target, r.Score, r.Total, r.Pass, r.Fail, r.Manual, r.Error, r.ElapsedMs, string(r.Results))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListComplianceReports 列出某目标的核查历史（不含完整结果，列表用不上）。
func (s *Store) ListComplianceReports(targetID string, limit int) ([]ComplianceReport, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 30
	}
	query := `SELECT id, ts, target_id, target, score, total, pass, fail, manual, err_count, elapsed_ms
		FROM compliance_reports`
	args := []any{}
	if targetID != "" {
		query += ` WHERE target_id = ?`
		args = append(args, targetID)
	}
	query += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ComplianceReport{}
	for rows.Next() {
		var r ComplianceReport
		if err := rows.Scan(&r.ID, &r.TS, &r.TargetID, &r.Target, &r.Score,
			&r.Total, &r.Pass, &r.Fail, &r.Manual, &r.Error, &r.ElapsedMs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetComplianceReport 取一次报告的完整内容。
func (s *Store) GetComplianceReport(id int64) (*ComplianceReport, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return nil, err
	}
	var r ComplianceReport
	var raw string
	err := s.db.QueryRow(`SELECT id, ts, target_id, target, score, total, pass, fail, manual,
		err_count, elapsed_ms, results FROM compliance_reports WHERE id = ?`, id).
		Scan(&r.ID, &r.TS, &r.TargetID, &r.Target, &r.Score, &r.Total, &r.Pass,
			&r.Fail, &r.Manual, &r.Error, &r.ElapsedMs, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Results = json.RawMessage(raw)
	return &r, nil
}

// PruneComplianceReports 删除 before 之前的报告。
func (s *Store) PruneComplianceReports(before int64) (int64, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM compliance_reports WHERE ts < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
