package store

import (
	"database/sql"
	"encoding/json"
	"errors"
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

// ensureComplianceReports 现在是空操作，保留只为不动调用点。
//
// 建表已经挪到 store.Open 执行的 schema 常量里（跟其它表一样，
// 每次 Open 都跑 CREATE TABLE IF NOT EXISTS）。
//
// 原来这里挂着包级 sync.Once，scope 是"进程"而不是"这个库"：
// 同一进程里打开第二个库时建表不会执行，SaveComplianceReport 会报
// "no such table: compliance_reports"。单实例时看不出来，是潜伏问题。
func (s *Store) ensureComplianceReports() error { return nil }

// complianceTSMigration 把老库里的秒级时间戳刷成毫秒。
//
// 老版本（v0.1.0 及更早）这里是 `time.Now().Unix()`，而全项目统一用毫秒。
// 必须在**写侧**迁移，只靠读侧的 normalizeTS 不够：
//   - PruneComplianceReports 是拿原始 ts 和毫秒 before 在 SQL 里比大小的，
//     秒级行会被当成"1970 年的过期数据"直接删掉；
//   - ORDER BY ts DESC 也会把秒级行永远排在最后。
//
// 条件用**固定范围**而不是"小于某个量级"，也不用"现在+1天"这种依赖时钟的上界：
//
//	下界 946684800  = 2000-01-01 的秒值（本项目 2026 年才有数据，不会更早）
//	上界 4102444800 = 2100-01-01 的秒值
//
// 毫秒值都 >= 1e12，天然落在这个区间之外，不会被重复乘。
// 不用"现在+86400"是因为机器时钟偏移超过一天时，那些老记录会被漏掉迁移，
// 之后被保留期清理当成 1970 年的数据删掉。
// 幂等：换算后不再满足条件。
const complianceTSMigration = `UPDATE compliance_reports SET ts = ts * 1000
	WHERE ts >= 946684800 AND ts < 4102444800`

// hostKeyTSMigration 把老库 known_hosts 里的**秒级**时间戳刷成毫秒。
//
// 写侧已经是 UnixMilli（见 SaveHostKey），但升级上来的老库里 first_seen /
// last_seen 还是秒值（实测 first_seen=1791544791，按毫秒解释是 1970-01-21）。
// 读侧没有 normalizeTS，所以必须在写侧一次性迁移。
//
// 判据与 complianceTSMigration 完全一致（同为秒值区间），幂等：换算成毫秒后
// 都 >= 1e12，天然落在这个区间之外，不会被重复乘。
// 两列各自独立判断：只迁移落在秒值区间里的那一列，不去动已经正常的另一列。
const hostKeyTSMigration = `UPDATE known_hosts SET
		first_seen = CASE WHEN first_seen >= 946684800 AND first_seen < 4102444800
			THEN first_seen * 1000 ELSE first_seen END,
		last_seen  = CASE WHEN last_seen  >= 946684800 AND last_seen  < 4102444800
			THEN last_seen  * 1000 ELSE last_seen  END
	WHERE (first_seen >= 946684800 AND first_seen < 4102444800)
	   OR (last_seen  >= 946684800 AND last_seen  < 4102444800)`

// SaveComplianceReport 保存一次核查报告。
func (s *Store) SaveComplianceReport(r ComplianceReport) (int64, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return 0, err
	}
	if r.TS == 0 {
		r.TS = time.Now().UnixMilli()
	}
	// 调用方给的秒级/坏值 TS 必须在这里收拾掉：PruneComplianceReports 拿的是
	// 原始 ts 与毫秒 before 比大小，秒级行会被当成 1970 年的数据直接删掉。
	r.TS = normalizeOrNow(r.TS)
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
	if limit <= 0 {
		limit = 30
	}
	if limit > 500 {
		limit = 500
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
		r.TS = normalizeTS(r.TS)
		out = append(out, r)
	}
	return out, rows.Err()
}

// normalizeTS 把老库里遗留的秒级时间戳归一到毫秒。
//
// 毫秒化是在 v0.1.0 之后才统一的，升级上来的库里可能还留着秒级记录：
// 不归一的话，它们会被保留期清理当成过期数据直接删掉，
// 或者在前端被当作毫秒显示成 1970 年。
//
// **判据与 SQL 迁移（complianceTSMigration / hostKeyTSMigration）用同一个区间**，
// 不再用 `ts < 1e11` 这种量级阈值：量级阈值是"猜"（1e11 毫秒 = 1973-03-03，
// 再往前的毫秒值会被当成秒再乘 1000），固定区间是"说清楚"——
// 本项目 2026 年才有数据，秒值必然落在 [2000-01-01, 2100-01-01) 里，
// 毫秒值（>= 1e12）天然在外面。两处判据一致，读侧与写侧才不会各说各话。
func normalizeTS(ts int64) int64 {
	if isSecondValue(ts) {
		return ts * 1000
	}
	return ts
}

// 与 complianceTSMigration 里的区间接上：946684800 = 2000-01-01 的秒值，
// 4102444800 = 2100-01-01 的秒值。
const (
	secondValueLower = 946684800
	secondValueUpper = 4102444800
)

// isSecondValue 判断一个时间戳是不是"秒级"（而不是毫秒级）。
func isSecondValue(ts int64) bool {
	return ts >= secondValueLower && ts < secondValueUpper
}

// normalizeOrNow 把调用方给的时间戳收拾成一个合法的毫秒值。
//
// 为什么要校验：`SaveComplianceReport` 接受调用方传进来的 TS，而
// `PruneComplianceReports(before_ms)` 是拿原始 ts 在 SQL 里比大小的 ——
// 秒级的行会被当成 1970 年的过期数据**直接删掉**（要等下次打开库才被迁移救回）。
// 三种情况分开处理：
//   - 0：调用方没给 → 用现在（原有行为）；
//   - 落在秒值区间：明确是秒 → 换算成毫秒再落库；
//   - 其它（负数、1980 年前的毫秒值之类）：当"坏值"用现在替换，
//     而不是让它进库变成一条永远排在最后、还会被清理当垃圾删掉的记录。
func normalizeOrNow(ts int64) int64 {
	if ts == 0 {
		return time.Now().UnixMilli()
	}
	if isSecondValue(ts) {
		return ts * 1000
	}
	if ts < secondValueLower {
		return time.Now().UnixMilli()
	}
	return ts
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
	r.TS = normalizeTS(r.TS)
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

// DeleteComplianceReport 删掉一份核查报告，返回实际删掉的行数。
// 保留期清理是"后台定时"，用户还得能自己删掉某一次跑坏的结论。
func (s *Store) DeleteComplianceReport(id int64) (int64, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`DELETE FROM compliance_reports WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ClearComplianceReports 清空核查报告；targetID 为空表示全部清掉。
// 返回删掉的条数。
func (s *Store) ClearComplianceReports(targetID string) (int64, error) {
	if err := s.ensureComplianceReports(); err != nil {
		return 0, err
	}
	var res sql.Result
	var err error
	if targetID == "" {
		res, err = s.db.Exec(`DELETE FROM compliance_reports`)
	} else {
		res, err = s.db.Exec(`DELETE FROM compliance_reports WHERE target_id = ?`, targetID)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
