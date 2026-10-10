package store

import (
	"sync"
	"time"
)

// ScanEvent 是一条落库的攻击事件。
//
// 为什么要落库：单次日志扫描的结果是临时的，而"来源 IP 排行""攻击时间线"
// 这类态势数据必须跨多次扫描、跨目标累计才看得出来。库表由本文件自行维护，
// 不影响 store.go 里既有的表结构。
type ScanEvent struct {
	// TS 是毫秒（与其他跨边界时间戳一致）
	TS         int64  `json:"ts"`
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	Severity   string `json:"severity"`
	Category   string `json:"category"`
	SourceIP   string `json:"source_ip"`
	LineNo     int    `json:"line_no"`
	Decoded    bool   `json:"decoded"`
	Sample     string `json:"sample"`
}

// NameCount 是通用计数项。
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// AddrCount 是来源地址的聚合。
type AddrCount struct {
	IP        string `json:"ip"`
	Count     int    `json:"count"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
	Targets   int    `json:"targets"`
	Critical  int    `json:"critical"`
}

// TimeBucket 是时间线上的一个点。
type TimeBucket struct {
	Bucket string `json:"bucket"`
	Count  int    `json:"count"`
}

// ThreatStats 是态势聚合结果。
type ThreatStats struct {
	Total        int          `json:"total"`
	Since        int64        `json:"since"`
	Until        int64        `json:"until"`
	DecodedTotal int          `json:"decoded_total"`
	BySourceIP   []AddrCount  `json:"by_source_ip"`
	ByCategory   []NameCount  `json:"by_category"`
	BySeverity   []NameCount  `json:"by_severity"`
	ByTarget     []NameCount  `json:"by_target"`
	ByRule       []NameCount  `json:"by_rule"`
	Timeline     []TimeBucket `json:"timeline"`
	Recent       []ScanEvent  `json:"recent"`
}

var scanEventOnce sync.Once
var scanEventErr error

// ensureScanEvents 建表（只做一次）。索引按查询方式建：按时间过滤、按来源 IP 聚合。
func (s *Store) ensureScanEvents() error {
	scanEventOnce.Do(func() {
		stmts := []string{
			`CREATE TABLE IF NOT EXISTS scan_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ts INTEGER NOT NULL,
				target_id TEXT NOT NULL DEFAULT '',
				target_name TEXT NOT NULL DEFAULT '',
				path TEXT NOT NULL DEFAULT '',
				kind TEXT NOT NULL DEFAULT '',
				rule_id TEXT NOT NULL DEFAULT '',
				rule_name TEXT NOT NULL DEFAULT '',
				severity TEXT NOT NULL DEFAULT '',
				category TEXT NOT NULL DEFAULT '',
				source_ip TEXT NOT NULL DEFAULT '',
				line_no INTEGER NOT NULL DEFAULT 0,
				decoded INTEGER NOT NULL DEFAULT 0,
				sample TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE INDEX IF NOT EXISTS idx_scan_events_ts ON scan_events(ts)`,
			`CREATE INDEX IF NOT EXISTS idx_scan_events_ip ON scan_events(source_ip)`,
			`CREATE INDEX IF NOT EXISTS idx_scan_events_target ON scan_events(target_id)`,
		}
		for _, q := range stmts {
			if _, err := s.db.Exec(q); err != nil {
				scanEventErr = err
				return
			}
		}
	})
	return scanEventErr
}

// InsertScanEvents 批量写入攻击事件。
func (s *Store) InsertScanEvents(events []ScanEvent) error {
	if len(events) == 0 {
		return nil
	}
	if err := s.ensureScanEvents(); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`INSERT INTO scan_events
		(ts, target_id, target_name, path, kind, rule_id, rule_name, severity, category, source_ip, line_no, decoded, sample)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		decoded := 0
		if e.Decoded {
			decoded = 1
		}
		if _, err := stmt.Exec(e.TS, e.TargetID, e.TargetName, e.Path, e.Kind,
			e.RuleID, e.RuleName, e.Severity, e.Category, e.SourceIP, e.LineNo, decoded, e.Sample); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ThreatStats 聚合指定时间之后的事件（since 为毫秒）。
// targetID 非空时只统计这台主机 —— 态势默认看全局，但排查单台机器时要能只看它。
func (s *Store) ThreatStats(since int64, targetID string) (ThreatStats, error) {
	stats := ThreatStats{
		Since:      since,
		Until:      time.Now().UnixMilli(),
		BySourceIP: []AddrCount{},
		ByCategory: []NameCount{},
		BySeverity: []NameCount{},
		ByTarget:   []NameCount{},
		ByRule:     []NameCount{},
		Timeline:   []TimeBucket{},
		Recent:     []ScanEvent{},
	}
	if err := s.ensureScanEvents(); err != nil {
		return stats, err
	}

	where := "ts >= ?"
	args := []any{since}
	if targetID != "" {
		where += " AND target_id = ?"
		args = append(args, targetID)
	}

	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(decoded), 0) FROM scan_events WHERE `+where, args...).
		Scan(&stats.Total, &stats.DecodedTotal); err != nil {
		return stats, err
	}
	if stats.Total == 0 {
		return stats, nil
	}

	// 来源 IP：次数、首末时间、涉及目标数、其中 critical 条数
	rows, err := s.db.Query(`SELECT source_ip, COUNT(*) AS c,
		MIN(ts), MAX(ts), COUNT(DISTINCT target_id),
		SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)
		FROM scan_events WHERE `+where+` AND source_ip <> ''
		GROUP BY source_ip ORDER BY c DESC LIMIT 30`, args...)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var a AddrCount
		if err := rows.Scan(&a.IP, &a.Count, &a.FirstSeen, &a.LastSeen, &a.Targets, &a.Critical); err != nil {
			rows.Close()
			return stats, err
		}
		stats.BySourceIP = append(stats.BySourceIP, a)
	}
	rows.Close()

	simple := []struct {
		col  string
		dest *[]NameCount
		lim  int
	}{
		{"category", &stats.ByCategory, 20},
		{"severity", &stats.BySeverity, 8},
		{"rule_id", &stats.ByRule, 20},
	}
	for _, item := range simple {
		rs, err := s.db.Query(`SELECT `+item.col+`, COUNT(*) AS c FROM scan_events WHERE `+where+`
			GROUP BY `+item.col+` ORDER BY c DESC LIMIT ?`, append(args, item.lim)...)
		if err != nil {
			return stats, err
		}
		for rs.Next() {
			var n NameCount
			if err := rs.Scan(&n.Name, &n.Count); err != nil {
				rs.Close()
				return stats, err
			}
			*item.dest = append(*item.dest, n)
		}
		rs.Close()
	}

	// 目标分布：哪台机器被打得最多
	rs, err := s.db.Query(`SELECT target_name, COUNT(*) AS c FROM scan_events WHERE `+where+`
		GROUP BY target_name ORDER BY c DESC LIMIT 20`, args...)
	if err != nil {
		return stats, err
	}
	for rs.Next() {
		var n NameCount
		if err := rs.Scan(&n.Name, &n.Count); err != nil {
			rs.Close()
			return stats, err
		}
		stats.ByTarget = append(stats.ByTarget, n)
	}
	rs.Close()

	// 时间线：按天分桶。ts 存的是毫秒，先除回秒再交给 sqlite 的日期函数
	tl, err := s.db.Query(`SELECT date(ts / 1000, 'unixepoch', 'localtime') AS d, COUNT(*) AS c
		FROM scan_events WHERE `+where+` GROUP BY d ORDER BY d`, args...)
	if err != nil {
		return stats, err
	}
	for tl.Next() {
		var b TimeBucket
		if err := tl.Scan(&b.Bucket, &b.Count); err != nil {
			tl.Close()
			return stats, err
		}
		stats.Timeline = append(stats.Timeline, b)
	}
	tl.Close()

	// 最近事件
	rec, err := s.db.Query(`SELECT ts, target_id, target_name, path, kind, rule_id, rule_name,
		severity, category, source_ip, line_no, decoded, sample
		FROM scan_events WHERE `+where+` ORDER BY ts DESC, id DESC LIMIT 60`, args...)
	if err != nil {
		return stats, err
	}
	for rec.Next() {
		var e ScanEvent
		var decoded int
		if err := rec.Scan(&e.TS, &e.TargetID, &e.TargetName, &e.Path, &e.Kind, &e.RuleID,
			&e.RuleName, &e.Severity, &e.Category, &e.SourceIP, &e.LineNo, &decoded, &e.Sample); err != nil {
			rec.Close()
			return stats, err
		}
		e.Decoded = decoded == 1
		stats.Recent = append(stats.Recent, e)
	}
	rec.Close()

	return stats, nil
}

// PruneScanEvents 删除 before 之前的事件，返回删除条数。
func (s *Store) PruneScanEvents(before int64) (int64, error) {
	if err := s.ensureScanEvents(); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM scan_events WHERE ts < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ClearScanEvents 清空全部攻击事件，返回删除条数。
func (s *Store) ClearScanEvents() (int64, error) {
	if err := s.ensureScanEvents(); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM scan_events`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ScanEventCount 返回事件总数（用于界面展示与清理判断）。
func (s *Store) ScanEventCount() (int, error) {
	if err := s.ensureScanEvents(); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM scan_events`).Scan(&n)
	return n, err
}
