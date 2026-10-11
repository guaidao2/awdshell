package store

import (
	"database/sql"
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

// ensureScanEvents 是历史遗留的空实现 —— scan_events 与它的三个索引已并入
// store.go 的 schema，每次 Open 都会建。保留函数只为不惊动调用方。
//
// 原来挂在包级 sync.Once 上：sync.Once 是**进程级**而不是"每个库一次"，
// 同进程第二个 *Store 上这张表就是没有，且包级错误只试一次、失败后永不再建。
func (s *Store) ensureScanEvents() error { return nil }

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

	// 来源 IP：次数、首末时间、涉及目标数、其中 critical 条数。
	//
	// 每个循环都走 collectRows：它保证 Close 之后**必查 rows.Err()**。
	// 以前五个循环都是"迭代完就 Close"，迭代中途出错（驱动报错、查询被中断）
	// 会被当成"结果就这么多"，态势页静默少数据。
	if err := collectRows(func() (*sql.Rows, error) {
		return s.db.Query(`SELECT source_ip, COUNT(*) AS c,
		MIN(ts), MAX(ts), COUNT(DISTINCT target_id),
		SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END)
		FROM scan_events WHERE `+where+` AND source_ip <> ''
		GROUP BY source_ip ORDER BY c DESC LIMIT 30`, args...)
	},
		func(rows *sql.Rows) error {
			var a AddrCount
			if err := rows.Scan(&a.IP, &a.Count, &a.FirstSeen, &a.LastSeen, &a.Targets, &a.Critical); err != nil {
				return err
			}
			stats.BySourceIP = append(stats.BySourceIP, a)
			return nil
		}); err != nil {
		return stats, err
	}

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
		if err := collectRows(func() (*sql.Rows, error) {
			return s.db.Query(`SELECT `+item.col+`, COUNT(*) AS c FROM scan_events WHERE `+where+`
			GROUP BY `+item.col+` ORDER BY c DESC LIMIT ?`, append(args, item.lim)...)
		},
			func(rows *sql.Rows) error {
				var n NameCount
				if err := rows.Scan(&n.Name, &n.Count); err != nil {
					return err
				}
				*item.dest = append(*item.dest, n)
				return nil
			}); err != nil {
			return stats, err
		}
	}

	// 目标分布：哪台机器被打得最多
	if err := collectRows(func() (*sql.Rows, error) {
		return s.db.Query(`SELECT target_name, COUNT(*) AS c FROM scan_events WHERE `+where+`
		GROUP BY target_name ORDER BY c DESC LIMIT 20`, args...)
	},
		func(rows *sql.Rows) error {
			var n NameCount
			if err := rows.Scan(&n.Name, &n.Count); err != nil {
				return err
			}
			stats.ByTarget = append(stats.ByTarget, n)
			return nil
		}); err != nil {
		return stats, err
	}

	// 时间线：按天分桶。ts 存的是毫秒，先除回秒再交给 sqlite 的日期函数
	if err := collectRows(func() (*sql.Rows, error) {
		return s.db.Query(`SELECT date(ts / 1000, 'unixepoch', 'localtime') AS d, COUNT(*) AS c
		FROM scan_events WHERE `+where+` GROUP BY d ORDER BY d`, args...)
	},
		func(rows *sql.Rows) error {
			var b TimeBucket
			if err := rows.Scan(&b.Bucket, &b.Count); err != nil {
				return err
			}
			stats.Timeline = append(stats.Timeline, b)
			return nil
		}); err != nil {
		return stats, err
	}

	// 最近事件
	if err := collectRows(func() (*sql.Rows, error) {
		return s.db.Query(`SELECT ts, target_id, target_name, path, kind, rule_id, rule_name,
		severity, category, source_ip, line_no, decoded, sample
		FROM scan_events WHERE `+where+` ORDER BY ts DESC, id DESC LIMIT 60`, args...)
	},
		func(rows *sql.Rows) error {
			var e ScanEvent
			var decoded int
			if err := rows.Scan(&e.TS, &e.TargetID, &e.TargetName, &e.Path, &e.Kind, &e.RuleID,
				&e.RuleName, &e.Severity, &e.Category, &e.SourceIP, &e.LineNo, &decoded, &e.Sample); err != nil {
				return err
			}
			e.Decoded = decoded == 1
			stats.Recent = append(stats.Recent, e)
			return nil
		}); err != nil {
		return stats, err
	}

	return stats, nil
}

// collectRows 收一个 query 闭包与一个逐行 scan 回调，保证**无论怎么退出都 Close，
// 并且 Close 之后必查 rows.Err()**。
//
// 为什么要这样：迭代中途出错时 rows.Next() 只是返回 false，错误挂在 rows.Err()
// 上。老写法（迭代完直接 Close）会把"查询中途失败"当成"结果就这么多"，
// 态势页静默少数据 —— 用户看到的是一个不报错的错结论。
//
// 收闭包而不是收 (*sql.Rows, error)：Go 不允许把多值调用和别的实参混在同一个
// 调用里（`f(g())` 只能独占实参表），传闭包既绕开这条限制，也让"查询失败"与
// "迭代失败"在同一个地方被处理。
func collectRows(query func() (*sql.Rows, error), scan func(*sql.Rows) error) error {
	rows, err := query()
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
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
