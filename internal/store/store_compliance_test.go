package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 本文件覆盖核查报告的时间戳迁移与删除/清空。
//
// 两点约定（改这个文件时注意）：
//  1. 迁移现在挂在 store.Open 的 migrate() 里，不在 ensureComplianceReports 里
//     （那个函数带包级 sync.Once，scope 是"进程"而不是"这个库"）。
//     测试里用 insertRawReportTS 手动建表 + 插数据，再显式执行 complianceTSMigration，
//     以此模拟"老库 + 进程启动时迁移一次"。
//  2. 不依赖测试执行顺序：每条用例都用自己的 newTestStore（独立目录与 db 文件）。

// 秒级时间戳的迁移：老版本（v0.1.0 及更早）写的是 Unix()，现在统一毫秒。
//
// 这一条踩过两次：第一次只在读侧加了归一（normalizeTS），以为修好了，
// 实际上 PruneComplianceReports 仍拿原始 ts 和毫秒 before 在 SQL 里比大小，
// 秒级行会被当成 "1970 年的过期数据" 直接删掉。所以必须有写侧迁移。

// createComplianceTableRaw 手动建表，**不**触发 ensure（那会顺带跑迁移）。
// 用来模拟"老库"：表已经存在、里面已经有秒级时间戳的数据。
func createComplianceTableRaw(t *testing.T, st *Store) {
	t.Helper()
	_, err := st.db.Exec(`CREATE TABLE IF NOT EXISTS compliance_reports (
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
	)`)
	if err != nil {
		t.Fatalf("建表失败: %v", err)
	}
}

// insertRawReportTS 直接写一条指定 ts 的报告，绕过任何归一逻辑。
func insertRawReportTS(t *testing.T, st *Store, ts int64, target string) int64 {
	t.Helper()
	createComplianceTableRaw(t, st)
	res, err := st.db.Exec(`INSERT INTO compliance_reports
		(ts, target_id, target, score, total, pass, fail, manual, err_count, elapsed_ms, results)
		VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0, 0, '[]')`, ts, target, target)
	if err != nil {
		t.Fatalf("插入失败: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

// rawTS 直接读库里的 ts，不经过读侧的 normalizeTS 兜底 ——
// 要验证的是"数据库里的值被改了"，而不是"返回值被改了"。
func rawTS(t *testing.T, st *Store, id int64) int64 {
	t.Helper()
	var ts int64
	if err := st.db.QueryRow(`SELECT ts FROM compliance_reports WHERE id = ?`, id).Scan(&ts); err != nil {
		t.Fatalf("读 ts 失败: %v", err)
	}
	return ts
}

func TestMigrateComplianceTimestamps(t *testing.T) {
	st := newTestStore(t)

	// 造一条"老库"里的秒级记录（2025-06-15 左右）
	sec := int64(1750000000)
	id := insertRawReportTS(t, st, sec, "old-target")
	if got := rawTS(t, st, id); got != sec {
		t.Fatalf("插入的原始值应保持秒级，得到 %d", got)
	}

	if _, err := st.db.Exec(complianceTSMigration); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	// 库里应该已经变成毫秒
	if got := rawTS(t, st, id); got != sec*1000 {
		t.Errorf("迁移后库里应是毫秒 %d，得到 %d", sec*1000, got)
	}

	// 幂等：再跑一次不该翻倍
	if _, err := st.db.Exec(complianceTSMigration); err != nil {
		t.Fatalf("二次迁移失败: %v", err)
	}
	if got := rawTS(t, st, id); got != sec*1000 {
		t.Errorf("迁移应幂等，二次执行后得到 %d", got)
	}

	// 已经是毫秒的记录不能被误伤
	nowMs := time.Now().UnixMilli()
	id2 := insertRawReportTS(t, st, nowMs, "new-target")
	if _, err := st.db.Exec(complianceTSMigration); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if got := rawTS(t, st, id2); got != nowMs {
		t.Errorf("毫秒记录不该被改动，得到 %d（原 %d）", got, nowMs)
	}
}

// 迁移的核心价值：**仍在保留期内**的老记录不会被误删。
//
// 注意这里用 30 天前的秒级时间戳，而不是某个很久以前的日期：
// 迁移只是把单位从秒改成毫秒，它不会让真正过期的记录复活
// （2025 年的报告相对 90 天保留期本来就是过期的，迁移后照样该删）。
// 要验证的是"没过期的记录不会因为单位不一致被当成 1970 年"。
//
// 这条测试必须手动建表、显式调迁移来模拟"进程启动时跑过一次"：
//   - 先调 ensureComplianceReports 的话，迁移在那时就跑完了，
//     之后插进去的秒级值变成"迁移之后混进来的"，测不到救老数据这个场景；
//   - 而 ensureComplianceReports 带包级 sync.Once，同进程只执行一次，
//     也不能指望它在每个测试里都重新触发迁移。
func TestMigrationProtectsOldReportsFromPrune(t *testing.T) {
	st := newTestStore(t)

	// 模拟老库：表已存在，里面有一条 30 天前的**秒级**记录
	sec := time.Now().AddDate(0, 0, -30).Unix()
	id := insertRawReportTS(t, st, sec, "old-target")
	if got := rawTS(t, st, id); got != sec {
		t.Fatalf("插入的原始值应保持秒级，得到 %d", got)
	}

	// 模拟进程启动时的那一次迁移
	if _, err := st.db.Exec(complianceTSMigration); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if got := rawTS(t, st, id); got != sec*1000 {
		t.Fatalf("迁移后库里应是毫秒 %d，得到 %d", sec*1000, got)
	}

	// 按 90 天保留期清理：30 天前的记录在保留期内，不该被删
	before := time.Now().AddDate(0, 0, -90).UnixMilli()
	if n, err := st.PruneComplianceReports(before); err != nil {
		t.Fatalf("清理失败: %v", err)
	} else if n != 0 {
		t.Fatalf("这条记录只有 30 天，不该被 90 天保留期清掉（删了 %d 行）", n)
	}

	// 读出来的日期也要对，不能是 1970
	list, err := st.ListComplianceReports("old-target", 10)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("应剩 1 条，得到 %d", len(list))
	}
	got := time.UnixMilli(list[0].TS)
	want := time.Now().AddDate(0, 0, -30)
	if got.Year() != want.Year() || got.Month() != want.Month() || got.Day() != want.Day() {
		t.Errorf("时间戳应是 30 天前（%s），得到 %s",
			want.Format("2006-01-02"), got.Format("2006-01-02"))
	}
}

// 对照：不做迁移的话，同一条记录会被当成 1970 年的数据误删。
// 把"为什么需要迁移"钉住，避免以后有人觉得迁移多余把它删掉。
func TestWithoutMigrationOldReportGetsPruned(t *testing.T) {
	st := newTestStore(t)
	// 30 天前，但用秒级表示（老库的样子）
	sec := time.Now().AddDate(0, 0, -30).Unix()
	insertRawReportTS(t, st, sec, "old-target")

	// 不迁移，直接按 90 天（毫秒）清理：秒级值远小于毫秒阈值，会被误删
	n, err := st.PruneComplianceReports(time.Now().AddDate(0, 0, -90).UnixMilli())
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("不迁移时这条记录会被误删（预期 1 行），实际删了 %d 行 —— "+
			"如果这里变成 0，说明清理逻辑改了，需要重新审视迁移是否还有必要", n)
	}
}

// 清理确实按毫秒工作：真正过期的会被删掉。
func TestPruneRemovesActuallyExpired(t *testing.T) {
	st := newTestStore(t)
	// 两年前的报告（毫秒）
	insertRawReportTS(t, st, time.Now().AddDate(-2, 0, 0).UnixMilli(), "t1")
	// 昨天的报告
	insertRawReportTS(t, st, time.Now().AddDate(0, 0, -1).UnixMilli(), "t2")

	n, err := st.PruneComplianceReports(time.Now().AddDate(0, 0, -90).UnixMilli())
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 1 {
		t.Errorf("应正好删掉 1 条过期报告，得到 %d", n)
	}
	list, _ := st.ListComplianceReports("", 10)
	if len(list) != 1 || list[0].Target != "t2" {
		t.Errorf("应只剩 t2，得到 %+v", list)
	}
}

// 删除与清空：核查报告以前只能等后台按保留期清理，用户删不掉。
func TestDeleteAndClearComplianceReports(t *testing.T) {
	st := newTestStore(t)
	a := insertRawReportTS(t, st, time.Now().UnixMilli(), "hostA")
	insertRawReportTS(t, st, time.Now().UnixMilli(), "hostA")
	insertRawReportTS(t, st, time.Now().UnixMilli(), "hostB")

	// 删单条：返回实际删掉的行数（删不存在的 id 必须是 0，接口据此回 404）
	n, err := st.DeleteComplianceReport(a)
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if n != 1 {
		t.Errorf("应删掉 1 行，得到 %d", n)
	}
	if n2, _ := st.DeleteComplianceReport(a); n2 != 0 {
		t.Errorf("重复删除应返回 0，得到 %d", n2)
	}

	// 按目标清空只影响那一台
	n, err = st.ClearComplianceReports("hostA")
	if err != nil {
		t.Fatalf("清空失败: %v", err)
	}
	if n != 1 {
		t.Errorf("hostA 应剩 1 条被清掉，得到 %d", n)
	}
	if list, _ := st.ListComplianceReports("hostB", 10); len(list) != 1 {
		t.Errorf("hostB 的记录不该被动，得到 %d 条", len(list))
	}

	// 空 targetID 是全清（接口层要求显式 all=true 才允许走到这里）
	n, err = st.ClearComplianceReports("")
	if err != nil {
		t.Fatalf("全清失败: %v", err)
	}
	if n != 1 {
		t.Errorf("全清应删掉 hostB 那 1 条，得到 %d", n)
	}
	if list, _ := st.ListComplianceReports("", 10); len(list) != 0 {
		t.Errorf("全清后应为空，得到 %d 条", len(list))
	}
}

// 建表不再挂包级 sync.Once：同一进程里打开第二个库也要能用。
//
// 原来 Once 的 scope 是"进程"而不是"这个库"，第二个库跑 SaveComplianceReport
// 会报 "no such table: compliance_reports"。单实例时看不出来，是潜伏问题。
func TestSecondStoreInSameProcess(t *testing.T) {
	a := newTestStore(t)
	if _, err := a.SaveComplianceReport(ComplianceReport{Target: "a"}); err != nil {
		t.Fatalf("第一个库保存失败: %v", err)
	}
	b := newTestStore(t)
	if _, err := b.SaveComplianceReport(ComplianceReport{Target: "b"}); err != nil {
		t.Fatalf("第二个库保存失败（建表还挂在包级 Once 上？）: %v", err)
	}
	if list, _ := a.ListComplianceReports("", 10); len(list) != 1 {
		t.Errorf("库 A 应有 1 条，得到 %d", len(list))
	}
	if list, _ := b.ListComplianceReports("", 10); len(list) != 1 {
		t.Errorf("库 B 应有 1 条，得到 %d", len(list))
	}
}

// 覆盖 store.Open → migrate 这一步。
//
// 之前几版测试都是"手动建表 + 直接 Exec 迁移常量"，于是把 migrate 里那句调用
// 删掉测试照样过 —— 真正要保证的是"重新打开一个老库时会被迁移"。
func TestOpenMigratesLegacyTimestamps(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-migrate-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "legacy.db")

	// 模拟老库：表已存在，里面是一条 30 天前的**秒级**记录
	sec := time.Now().AddDate(0, 0, -30).Unix()
	first, err := Open(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	if _, err := first.db.Exec(
		`INSERT INTO compliance_reports (ts, target_id, target, results) VALUES (?, 't', 't', '[]')`,
		sec); err != nil {
		t.Fatalf("写入老记录失败: %v", err)
	}
	_ = first.Close()

	// 重新打开：migrate 应该把秒刷成毫秒
	second, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	var ts int64
	if err := second.db.QueryRow(`SELECT ts FROM compliance_reports`).Scan(&ts); err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if ts != sec*1000 {
		t.Errorf("重新打开后应被迁移成毫秒 %d，得到 %d（migrate 里那句调用还在吗）", sec*1000, ts)
	}

	// 而且这条 30 天前的记录不会被 90 天保留期清理误删
	if n, err := second.PruneComplianceReports(time.Now().AddDate(0, 0, -90).UnixMilli()); err != nil {
		t.Fatalf("清理失败: %v", err)
	} else if n != 0 {
		t.Errorf("30 天前的记录不该被 90 天保留期清掉，删了 %d 行", n)
	}
}

func TestDeleteAndClearConnections(t *testing.T) {
	st := newTestStore(t)
	// 复用 store_test.go 里的 addConn（它不设 target_id）
	addConn(t, st, "10.0.0.1", time.Now().UnixMilli())
	addConn(t, st, "10.0.0.1", time.Now().UnixMilli())
	addConn(t, st, "10.0.0.2", time.Now().UnixMilli())

	// 按一个不存在的目标清空：不能误删别的数据
	n, err := st.ClearConnections("no-such-target")
	if err != nil {
		t.Fatalf("清空失败: %v", err)
	}
	if n != 0 {
		t.Errorf("按不存在的目标清空应删 0 行，得到 %d", n)
	}
	if list, _ := st.ListConnections(10); len(list) != 3 {
		t.Errorf("不该动到别的记录，应剩 3 条，得到 %d", len(list))
	}

	// 全清
	n, err = st.ClearConnections("")
	if err != nil {
		t.Fatalf("全清失败: %v", err)
	}
	if n != 3 {
		t.Errorf("全清应删掉 3 条，得到 %d", n)
	}
	if list, _ := st.ListConnections(10); len(list) != 0 {
		t.Errorf("全清后应为空，得到 %d 条", len(list))
	}
}
