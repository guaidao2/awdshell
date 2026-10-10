package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
)

// 这组测试固化全代码审计里 store 包那几条修复，断言都写成"改回错误版本会红"。

// ---------- 低6：两条 DELETE 必须在一个事务里 ----------

// blockSecretDelete 把 secrets 换成"删不动的视图"，制造第二步 DELETE 失败。
//
// 这样就能精确验到"回滚"：以前是两条独立的 DELETE（第二次的错误还被 `_` 吞掉），
// targets 已经删了、secrets 留下 → 孤儿密文；有事务时整体回滚，目标还在。
// 返回还原用的清理函数。
func blockSecretDelete(t *testing.T, st *Store) func() {
	t.Helper()
	mustExec := func(q string) {
		t.Helper()
		if _, err := st.db.Exec(q); err != nil {
			t.Fatalf("准备动作失败（%s）: %v", q, err)
		}
	}
	mustExec(`ALTER TABLE secrets RENAME TO secrets_real`)
	mustExec(`CREATE VIEW secrets AS SELECT id, nonce, ciphertext, created_at FROM secrets_real`)
	mustExec(`CREATE TRIGGER secrets_no_delete INSTEAD OF DELETE ON secrets
		BEGIN SELECT RAISE(ABORT, '注入的删除失败'); END`)

	return func() {
		_, _ = st.db.Exec(`DROP TRIGGER IF EXISTS secrets_no_delete`)
		_, _ = st.db.Exec(`DROP VIEW IF EXISTS secrets`)
		_, _ = st.db.Exec(`ALTER TABLE secrets_real RENAME TO secrets`)
	}
}

// DeleteTarget 的凭据删除失败时，目标必须还在（整体回滚），错误必须交出来。
func TestDeleteTargetRollsBackWhenSecretDeleteFails(t *testing.T) {
	st := newTestStore(t)

	if _, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "web-01", Host: "10.0.0.5", Port: 22,
		Username: "root", AuthKind: domain.AuthPassword, SecretID: "s1",
	}); err != nil {
		t.Fatalf("保存目标失败: %v", err)
	}
	if err := st.PutSecret("s1", []byte("nonce"), []byte("cipher")); err != nil {
		t.Fatalf("写凭据失败: %v", err)
	}

	restore := blockSecretDelete(t, st)
	defer restore()

	err := st.DeleteTarget("t1")
	if err == nil {
		t.Fatal("凭据删除失败时 DeleteTarget 必须返回错误（以前被 `_` 吞掉）")
	}
	if _, err := st.GetTarget("t1"); err != nil {
		t.Fatalf("第二步失败必须整体回滚，目标不该被删掉: %v", err)
	}
	if _, _, err := st.GetSecret("s1"); err != nil {
		t.Fatalf("回滚后密文也该还在: %v", err)
	}
}

// DeleteDBConn 读不到配置时不做任何删除。
//
// **诚实说明**：这一半（`GetDBConn` 出错就早退）在当前 API 下**没法做"改回旧版
// 必红"的断言** —— 读失败的场合，后面那句 DELETE 同样会失败，两种实现都返回
// 错误、也都没删掉东西，外部观察不到差别。所以这条测试只钉住"不 delete 数据"
// 这个结果；真正能区分新旧实现的是下面那条（密文删不掉时整体回滚）。
//
// 保留早退本身仍值得：它让"读不到就别动"成为显式合同，将来若换成分库/多句柄、
// 或读取走缓存而写走主库，旧写法就会删掉一条根本没读到的配置。
func TestDeleteDBConnDoesNotDeleteWhenReadFails(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-dbconn-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "test.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}

	if _, err := st.SaveDBConn(DBConn{
		ID: "c1", TargetID: "t1", Name: "web-db", Kind: "mysql",
		Addr: "127.0.0.1:3306", Username: "root", Database: "app",
		SecretID: "s1", ReadOnly: true, MaxRows: 500,
	}); err != nil {
		t.Fatalf("保存连接配置失败: %v", err)
	}
	if err := st.PutSecret("s1", []byte("nonce"), []byte("cipher")); err != nil {
		t.Fatalf("写凭据失败: %v", err)
	}

	// 关掉句柄：GetDBConn 必然失败（database/sql 不会自动重开）
	if err := st.db.Close(); err != nil {
		t.Fatalf("关句柄失败: %v", err)
	}
	if _, err := st.GetDBConn("c1"); err == nil {
		t.Fatal("测试前提不成立：句柄关了 GetDBConn 还是成功了")
	}
	if err := st.DeleteDBConn("c1"); err == nil {
		t.Fatal("读不到配置时必须返回错误")
	}

	// 数据与密文都必须原样还在（换一个句柄看落盘状态）
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("重开失败: %v", err)
	}
	defer st2.Close()
	got, err := st2.GetDBConn("c1")
	if err != nil {
		t.Fatalf("读失败不代表可以删掉它，实际已丢失: %v", err)
	}
	if got.SecretID != "s1" {
		t.Fatalf("配置被改动了: %+v", got)
	}
	if _, _, err := st2.GetSecret("s1"); err != nil {
		t.Fatalf("密文也不该被动过: %v", err)
	}
}

// DeleteDBConn 写路径失败（密文删不掉）时，配置也不能被删掉。
func TestDeleteDBConnRollsBackWhenSecretDeleteFails(t *testing.T) {
	st := newTestStore(t)

	if _, err := st.SaveDBConn(DBConn{
		ID: "c1", TargetID: "t1", Name: "web-db", Kind: "mysql",
		Addr: "127.0.0.1:3306", Username: "root", Database: "app",
		SecretID: "s1", ReadOnly: true, MaxRows: 500,
	}); err != nil {
		t.Fatalf("保存连接配置失败: %v", err)
	}
	if err := st.PutSecret("s1", []byte("nonce"), []byte("cipher")); err != nil {
		t.Fatalf("写凭据失败: %v", err)
	}

	restore := blockSecretDelete(t, st)
	defer restore()

	if err := st.DeleteDBConn("c1"); err == nil {
		t.Fatal("密文删除失败时必须返回错误")
	}
	if _, err := st.GetDBConn("c1"); err != nil {
		t.Fatalf("失败必须整体回滚，配置不该被删掉: %v", err)
	}
}

// ---------- 低7：空 targetID 不许做全量删除 ----------

func TestDeleteDBConnsOfTargetRejectsEmptyTargetID(t *testing.T) {
	st := newTestStore(t)

	for _, id := range []string{"g1", "g2", "g3"} {
		if _, err := st.SaveDBConn(DBConn{
			ID: id, TargetID: "", Name: id, Kind: "mysql",
			Addr: "127.0.0.1:3306", Username: "root", Database: "app",
		}); err != nil {
			t.Fatalf("保存连接配置 %s 失败: %v", id, err)
		}
	}

	if err := st.DeleteDBConnsOfTarget(""); err == nil {
		t.Fatal("空 targetID 必须直接报错（以前会删掉所有 target_id='' 的配置）")
	}
	list, err := st.ListDBConns("")
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("空 targetID 不该删掉任何东西：期望 3 条，实际 %d 条", len(list))
	}

	// 正常路径不能被一起挡掉
	if err := st.DeleteDBConnsOfTarget("t2"); err != nil {
		t.Fatalf("非空 targetID 应当照常工作: %v", err)
	}
}

func TestDeleteDBConnsOfTargetOnlyTouchesThatTarget(t *testing.T) {
	st := newTestStore(t)

	if _, err := st.SaveDBConn(DBConn{
		ID: "keep", TargetID: "t1", Name: "keep", Kind: "mysql",
		Addr: "127.0.0.1:3306", Username: "root", Database: "app",
	}); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if _, err := st.SaveDBConn(DBConn{
		ID: "drop", TargetID: "t2", Name: "drop", Kind: "mysql",
		Addr: "127.0.0.1:3306", Username: "root", Database: "app",
	}); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	if err := st.DeleteDBConnsOfTarget("t2"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, err := st.GetDBConn("keep"); err != nil {
		t.Fatalf("别的目标的配置被误删: %v", err)
	}
	if _, err := st.GetDBConn("drop"); err == nil {
		t.Fatal("目标 t2 的配置没删掉")
	}
}

// ---------- 低8：只标"本次打开之前开始的"会话 ----------

// 启动时标中断不能碰"本次打开之后才开始"的会话（两个实例共用数据目录的场景）。
func TestMarkStaleConnectionsOnlyMarksOlderOnes(t *testing.T) {
	st := newTestStore(t)

	// 崩溃残留：本次启动之前就开始了，ended_at 还是 0
	oldID, err := st.AddConnection(domain.ConnectionRecord{
		Host: "old", Port: 22, Username: "root", StartedAt: time.Now().UnixMilli() - 60_000,
	})
	if err != nil {
		t.Fatalf("插入旧记录失败: %v", err)
	}
	// 正在跑的会话：本次打开之后才开始（模拟另一个实例刚建的连接）
	liveID, err := st.AddConnection(domain.ConnectionRecord{
		Host: "live", Port: 22, Username: "root", StartedAt: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("插入新记录失败: %v", err)
	}

	n, err := st.MarkStaleConnections("程序未正常退出")
	if err != nil {
		t.Fatalf("标记失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("只该标 1 条（旧的），实际标了 %d 条", n)
	}

	list, err := st.ListConnections(10)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	byID := map[int64]domain.ConnectionRecord{}
	for _, c := range list {
		byID[c.ID] = c
	}
	if got := byID[oldID]; got.EndedAt == 0 {
		t.Errorf("崩溃残留没有被标记: %+v", got)
	}
	if got := byID[liveID]; got.EndedAt != 0 {
		t.Errorf("正在跑的会话被标成中断了（后启动的实例会把前一个的会话标脏）: %+v", got)
	}
}

// ---------- 低10：迁移撞上 duplicate column 要当"已迁移" ----------

// 建一个"老库"：targets 没有 start_dir 列，且没有 schema 常量里的索引。
func createLegacyDB(t *testing.T, path string) {
	t.Helper()
	st, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if _, err := st.db.Exec(`DROP TABLE IF EXISTS secrets`); err != nil {
		t.Fatalf("DROP 失败: %v", err)
	}
	if _, err := st.db.Exec(`DROP TABLE IF EXISTS targets`); err != nil {
		t.Fatalf("DROP 失败: %v", err)
	}
	if _, err := st.db.Exec(`CREATE TABLE targets(
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL,
		host         TEXT NOT NULL,
		port         INTEGER NOT NULL DEFAULT 22,
		username     TEXT NOT NULL,
		auth_kind    TEXT NOT NULL DEFAULT 'password',
		secret_id    TEXT NOT NULL DEFAULT '',
		tags         TEXT NOT NULL DEFAULT '[]',
		grp          TEXT NOT NULL DEFAULT '',
		created_at   INTEGER NOT NULL,
		updated_at   INTEGER NOT NULL,
		last_used_at INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatalf("建老表失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关库失败: %v", err)
	}
}

// 两个实例同时打开老库：慢的那个会撞上 duplicate column name，必须当"已迁移"忽略。
//
// 这条竞态没法在测试里稳定复现（要精确卡在 PRAGMA 与 ALTER 之间），所以拆成两半验：
//  1. 直接验判据本身认得出 SQLite 真实给出的那个错误形态；
//  2. 验"列已经有了"的库照样能打开、能正常读写（迁移不会让第二次打开起不来）。
func TestDuplicateColumnErrorIsRecognized(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-dupcol-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// 拿驱动真实给出的错误文本，不要自己编字符串 —— 判据就靠它
	st, err := Open(filepath.Join(dir, "d.db"))
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	defer st.Close()
	_, dupErr := st.db.Exec(`ALTER TABLE targets ADD COLUMN start_dir TEXT NOT NULL DEFAULT ''`)
	if dupErr == nil {
		t.Fatal("测试前提不成立：start_dir 已经存在，这条 ALTER 应当报 duplicate column name")
	}
	if !isDuplicateColumn(dupErr) {
		t.Fatalf("真实的 duplicate column name 错误没被认出来（第二个实例会起不来）: %v", dupErr)
	}

	// 别的失败不能被误当成"已迁移"，否则迁移会静默失效
	for _, other := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"就是坏库", errors.New("database disk image is malformed")},
		{"锁住了", errors.New("database is locked")},
		{"权限", errors.New("unable to open database file")},
	} {
		if isDuplicateColumn(other.err) {
			t.Errorf("%s 不该被当成已迁移", other.name)
		}
	}
}

// 诊断式复现：记录"另一个实例"有没有抢到 migrate 的 PRAGMA 与 ALTER 之间的窗口。
//
// **为什么不做成必红断言**：从外部没法稳定卡准那个窗口（另一次 ALTER 必须恰好
// 落在 migrate 的 PRAGMA 读完、写语句还没开始时，WAL 下写者还互相排队），
// 强行做只会得到 flaky 测试。所以这里只观察、诚实跳过，不假装覆盖。
//
// 真正兜住 low10 的是 TestDuplicateColumnErrorIsRecognized：它拿**驱动真实给出的**
// duplicate column name 错误文本去验判据，其余错误必须不匹配（否则迁移会静默失效）。
// 那一条在被改回错误版本时会红。
func TestMigrateToleratesDuplicateColumnRace(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-dupcol-race-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "legacy.db")
	createLegacyDB(t, path)

	other, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("开第二个句柄失败: %v", err)
	}
	defer other.Close()
	if _, err := other.Exec(`PRAGMA busy_timeout=500`); err != nil {
		t.Fatalf("设置 busy_timeout 失败: %v", err)
	}

	// 另一次 ALTER：抢在前面就赢了窗口，撞上写锁就输了
	win := make(chan bool, 1)
	go func() {
		time.Sleep(time.Millisecond)
		_, e := other.Exec(`ALTER TABLE targets ADD COLUMN start_dir TEXT NOT NULL DEFAULT ''`)
		win <- e == nil
	}()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("撞上 duplicate column name 时必须当成已迁移，而不是起不来: %v", err)
	}
	defer st.Close()
	won := <-win

	// 列必须有且只有一个（不管是哪一边加的）
	var hasCol int
	rows, err := st.db.Query(`PRAGMA table_info(targets)`)
	if err != nil {
		t.Fatalf("读表结构失败: %v", err)
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if name == "start_dir" {
			hasCol++
		}
	}
	rows.Close()
	if hasCol != 1 {
		t.Fatalf("start_dir 列状态不对：实际 %d 个", hasCol)
	}
	if !won {
		t.Skip("另一个实例没能抢到窗口（时序相关）：low10 的判据由 TestDuplicateColumnErrorIsRecognized 覆盖")
	}
	t.Log("另一个实例抢到了窗口，Open 仍然成功")
}

// 老库真的能被打开并正常用（迁移没有把启动搞挂）。
func TestOpenLegacyDBStillWorks(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-legacy-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "legacy.db")
	createLegacyDB(t, path)

	st, err := Open(path)
	if err != nil {
		t.Fatalf("老库应当能打开: %v", err)
	}
	defer st.Close()

	var hasCol int
	rows, err := st.db.Query(`PRAGMA table_info(targets)`)
	if err != nil {
		t.Fatalf("读表结构失败: %v", err)
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if name == "start_dir" {
			hasCol++
		}
	}
	rows.Close()
	if hasCol != 1 {
		t.Fatalf("start_dir 列没被迁移出来：实际 %d 个", hasCol)
	}

	if _, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "web", Host: "10.0.0.1", Port: 22,
		Username: "root", AuthKind: domain.AuthPassword, StartDir: "/srv",
	}); err != nil {
		t.Fatalf("迁移后的库不可用: %v", err)
	}
	got, err := st.GetTarget("t1")
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if got.StartDir != "/srv" {
		t.Fatalf("start_dir 没落库: %+v", got)
	}

	// 第二个实例（同一份文件再开一次）也必须能起来：列已经有了，迁移直接跳过
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("第二个实例打不开同一个库: %v", err)
	}
	defer st2.Close()
	if _, err := st2.GetTarget("t1"); err != nil {
		t.Fatalf("第二个实例读不到数据: %v", err)
	}
}
