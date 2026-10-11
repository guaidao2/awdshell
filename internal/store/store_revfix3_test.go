package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
)

// 这组测试固化 revfix3 这一批修复（复审 rev42 抓出的"看起来修好了、实际没生效"）。
// 每条断言都写成"改回错误版本会红"：
//   - 高1 第三步（留档重建成功）的 note 必须报出"副文件被驱动删除"
//   - 高2 Close 必须真的把 last_clean_exit 写进库（低1/低2 同源）
//   - 低4 留档重建之后**下次启动**要能指出旧数据在哪个留档文件里
//   - 额外 PutSettingsKV：单事务、中间失败整体回滚、busyRetry 与 PutSetting 一致

// ---------- 高1：第三步成功时 note 不能把"副文件被驱动删除"丢掉 ----------

// 审计实测的形态：主库是 21 字节垃圾，旁边一份 39 字节非空 -wal。
// openOnce 在建连接时就把 -wal 删了 → moveSidecars 无事可做 → missingSidecarPaths
// 正确报出这条 -wal → 老实现把它只喂给 error 链，而第三步是**成功返回**、
// 拼的是全新的一段 note，于是用户手里一个字都没提 -wal。
//
// 断言用的是**副文件的原始路径**（不是 `.stale-*` 落点）：这条路径只有
// "驱动删了它"这个分支会说出来，所以"把 lostSidecars 从第三步的 note 里去掉"
// 这个变异必然红。
func TestOpenDetailThirdStepNoteNamesDriverDeletedSidecar(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	if err := os.WriteFile(path, []byte("not a sqlite database!!"), 0o600); err != nil {
		t.Fatalf("造坏主库失败: %v", err)
	}
	// 非空 -wal：这里面"可能含着全部已提交的数据"，正是必须点名的那一份
	const pretendWal = "pretend this holds committed frames"
	if err := os.WriteFile(path+"-wal", []byte(pretendWal), 0o600); err != nil {
		t.Fatalf("造 -wal 失败: %v", err)
	}

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("这个组合应当走完补救流程，实际失败: %v", err)
	}
	defer st.Close()
	t.Logf("note = %q", note)

	if strings.Contains(note, ".stale-") {
		t.Skipf("本机这次没让驱动删掉那个 -wal（被我们移走了），造不出该形态: %q", note)
	}
	if !strings.Contains(note, path+"-wal") {
		t.Fatalf("note 没提被驱动删掉的 -wal —— 用户不会知道"+
			"那份可能含着全部已提交数据的文件已经没了、该去备份里找: %q", note)
	}
	if !strings.Contains(note, "驱动") || !strings.Contains(note, "删除") {
		t.Errorf("note 没把「被驱动删除」这件事说清楚: %q", note)
	}
	// 留档说明仍然要在（这条路径最后是换了新库）
	if !strings.Contains(note, corruptArchiveSuffix) {
		t.Errorf("note 没提留档文件: %q", note)
	}
	// 前置条件：那份 39 字节的 -wal 已经不在原路径上了。
	// **不能断言"文件不存在"**：新建的库同样是 WAL 模式，这次打开会在同一个路径上
	// 重新建出一个空的 -wal（正是它掩盖了上面那个判据，所以检测必须算在 openOnce 之前）。
	// 只认内容：原路径上的 -wal 里不该再有我们写进去的那句假数据。
	if got, readErr := os.ReadFile(path + "-wal"); readErr == nil {
		if strings.Contains(string(got), pretendWal) {
			t.Errorf("原始 -wal 的内容还挂在原路径上，这条测试没走到「驱动删除」那个分支")
		}
	}
}

// 反向锁：正常库（旁白没有任何留档文件、也没有副文件被动过）的 note 必须还是空串。
// 加"丢副文件"提示时最容易犯的错是让每个库都弹一次警告。
func TestOpenDetailHealthyDatabaseStillHasEmptyNote(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	st0, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if _, err := st0.SaveTarget(domain.Target{
		ID: "t1", Name: "web", Host: "10.0.0.5", Port: 22,
		Username: "root", AuthKind: domain.AuthPassword,
	}); err != nil {
		t.Fatalf("写数据失败: %v", err)
	}
	_ = st0.Close()

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer st.Close()
	if note != "" {
		t.Fatalf("正常库不该有任何补救说明: %q", note)
	}
}

// ---------- 高2 / 低1 / 低2：Close 必须真的把 last_clean_exit 写进库 ----------

// 老实现是"先 s.db.Close() 再 writeLastCleanExit()"：写的是一个已经关掉的句柄，
// 必然失败、错误还被 `_ =` 吞掉。实测 Close 之后
// `SELECT value FROM settings WHERE key='last_clean_exit'` 报
// `sql: no rows in result set`，预置 value=1 再 Close 仍然是 1。
//
// 判据用**裸连接**读（不走 Store，避免"读到的是别的东西"这种解释）：
//   - 修复后：一条毫秒时间戳，且落在 Close 前后这段时间里；
//   - 改回"先关句柄再写"：查不到行 → 必红。
func TestClosePersistsLastCleanExit(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	// 预置一个旧值：Close 必须把它更新掉（"值没变就不写"的守卫已经删掉了 ——
	// 它以前永远为假，留着只会让人以为这里省了一次写）
	if err := st.PutSetting(lastCleanExitKey, "1"); err != nil {
		t.Fatalf("预置旧值失败: %v", err)
	}
	before := time.Now().UnixMilli()
	if err := st.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	first := rawLastCleanExit(t, path)
	if first < before-1000 || first > time.Now().UnixMilli()+1000 {
		t.Errorf("last_clean_exit=%d 不是这次 Close 写的（Close 前 %d）", first, before)
	}

	// 第二次干净退出要刷新这个时刻：writeLastCleanExit 现在是"每次都写"（有意的）
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("第二次打开失败: %v", err)
	}
	time.Sleep(3 * time.Millisecond)
	if err := st2.Close(); err != nil {
		t.Fatalf("第二次 Close 失败: %v", err)
	}
	second := rawLastCleanExit(t, path)
	if second <= first {
		t.Errorf("第二次干净退出没有刷新时刻：%d → %d", first, second)
	}
}

// rawLastCleanExit 用裸连接读 settings 里的 last_clean_exit（读不到就直接判失败）。
func rawLastCleanExit(t *testing.T, path string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("裸连接打开失败: %v", err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, lastCleanExitKey).Scan(&raw); err != nil {
		t.Fatalf("Close 之后 settings 里没有 %s —— 说明写打在已经关掉的句柄上了: %v",
			lastCleanExitKey, err)
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || ts <= 1 {
		t.Fatalf("last_clean_exit 不是新的毫秒时间戳: %q", raw)
	}
	return ts
}

// ---------- 低4：留档重建之后，下次启动必须指出旧数据在哪 ----------

// 真实的形态（复审 P2-4）：留档重建成功 → 那次 note 只在当时的会话里出现过；
// **下次启动** openOnce 成功、note 为空串，用户拿到一个空库、没有任何线索指向
// 旁边那份 `.corrupt-*`，而旧数据全在里面。老实现这里实测就是 ok + note=""。
//
// 两条断言：
//   - 空库 + 有留档文件 → note 必须点名留档文件（去掉 archivedLibraryNote 调用必红）；
//   - 库里一旦有用户数据 → note 必须恢复空串（去掉"空库才说"的限制必红：
//     留档文件是设计上要求用户**永久保留**的，不做限制就会每次启动都念一遍）。
func TestArchivedEmptyLibraryIsNamedOnNextStartup(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database file"), 0o600); err != nil {
		t.Fatalf("造坏库失败: %v", err)
	}

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("损坏库应当被补救，实际失败: %v", err)
	}
	if !strings.Contains(note, corruptArchiveSuffix) {
		t.Fatalf("第一次补救的 note 没提留档文件: %q", note)
	}
	archive := ""
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), corruptArchiveSuffix) {
			archive = e.Name()
		}
	}
	if archive == "" {
		t.Fatal("盘上没有留档文件")
	}
	_ = st.Close()

	// 第二次启动：当前是新建的空库，旁边躺着留档文件
	st2, note2, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("第二次打开失败: %v", err)
	}
	t.Logf("第二次 note = %q", note2)
	if !strings.Contains(note2, archive) {
		t.Fatalf("第二次启动没点名留档文件 —— 用户拿到空库且没有任何线索（复审 P2-4）: %q", note2)
	}
	if !strings.Contains(note2, corruptArchiveSuffix) {
		t.Errorf("提示里没有可辨认的留档文件后缀: %q", note2)
	}

	// 用起来之后不再念
	if _, err := st2.SaveTarget(domain.Target{
		ID: "t1", Name: "web", Host: "10.0.0.5", Port: 22,
		Username: "root", AuthKind: domain.AuthPassword,
	}); err != nil {
		t.Fatalf("重建后的库不可用: %v", err)
	}
	_ = st2.Close()

	st3, note3, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("第三次打开失败: %v", err)
	}
	defer st3.Close()
	if note3 != "" {
		t.Errorf("库里已经有数据了还在念留档文件（用户每次启动都被吓一次）: %q", note3)
	}
}

// ---------- 额外：PutSettingsKV ----------

// 一次调用把多组键值都写进去（顺序无关，最后状态要对）。
func TestPutSettingsKVWritesAllPairs(t *testing.T) {
	st := newTestStore(t)

	pairs := [][2]string{
		{"app.conn_keep_days", "30"},
		{"app.conn_keep_max", "500"},
		{"app.event_keep_days", "7"},
		{"app.term_font_size", "14"},
		{"app.term_scrollback", "5000"},
		{"app.trash_on_delete", "false"},
		{"app.term_track_cwd", "true"},
		{"app.download_dir", "D:\\dl"},
	}
	if err := st.PutSettingsKV(pairs); err != nil {
		t.Fatalf("PutSettingsKV 失败: %v", err)
	}
	for _, kv := range pairs {
		if got := st.GetSetting(kv[0], "<缺>"); got != kv[1] {
			t.Errorf("%s 期望 %q，实际 %q", kv[0], kv[1], got)
		}
	}

	// 幂等：同样的批次再写一次，结果不变（走的是 ON CONFLICT DO UPDATE）
	if err := st.PutSettingsKV(pairs); err != nil {
		t.Fatalf("第二次 PutSettingsKV 失败: %v", err)
	}
	if got := st.GetSetting("app.conn_keep_days", ""); got != "30" {
		t.Errorf("重复写入后值变了: %q", got)
	}

	// 空批次不该开事务、也不该报错
	if err := st.PutSettingsKV(nil); err != nil {
		t.Errorf("空批次应当成功: %v", err)
	}
}

// **中间一条失败时，前面的也不生效**（复审点名要测的那条）。
//
// 怎么让"中间那条"必然失败：在测试库里给 settings 挂一个 BEFORE INSERT/UPDATE
// 触发器，只对指定的 key 抛 RAISE(ABORT)。这不需要在生产代码里开测试注入点，
// 失败点是确定的（错误码是 CONSTRAINT 不是 BUSY，所以不会走 busyRetry 重试）。
//
// 判据：
//   - 修复后（整个批次一个事务）：返回错误，且**三组键一个都没变**；
//   - 改回逐项 PutSetting（旧的 service 行为）：第一组已经落库 → 必红。
func TestPutSettingsKVRollsBackWholeBatch(t *testing.T) {
	st := newTestStore(t)

	// 先放两个旧值：失败的批次不能把它们改掉（也不该把新键留下）
	if err := st.PutSetting("probe.a", "old-a"); err != nil {
		t.Fatalf("预置 probe.a 失败: %v", err)
	}
	if err := st.PutSetting("probe.c", "old-c"); err != nil {
		t.Fatalf("预置 probe.c 失败: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TRIGGER probe_fail_insert BEFORE INSERT ON settings
		 WHEN NEW.key = 'probe.bad'
		 BEGIN SELECT RAISE(ABORT, 'probe: 故意让中间这一条写不进去'); END`,
		`CREATE TRIGGER probe_fail_update BEFORE UPDATE ON settings
		 WHEN NEW.key = 'probe.bad'
		 BEGIN SELECT RAISE(ABORT, 'probe: 故意让中间这一条写不进去'); END`,
	} {
		if _, err := st.db.Exec(stmt); err != nil {
			t.Fatalf("挂触发器失败: %v", err)
		}
	}

	err := st.PutSettingsKV([][2]string{
		{"probe.a", "new-a"},
		{"probe.bad", "new-bad"},
		{"probe.c", "new-c"},
	})
	if err == nil {
		t.Fatal("中间那条必然失败，PutSettingsKV 却成功了")
	}
	if !strings.Contains(err.Error(), "probe.bad") {
		t.Errorf("错误里要点名写失败的那一项: %v", err)
	}

	if got := st.GetSetting("probe.a", "<缺>"); got != "old-a" {
		t.Errorf("批次回滚了，但 probe.a 已经被改掉了（部分写入）: %q", got)
	}
	if got := st.GetSetting("probe.c", "<缺>"); got != "old-c" {
		t.Errorf("批次回滚了，但 probe.c 已经被改掉了（部分写入）: %q", got)
	}
	// 失败点之前的键不能被"补写"出来，失败点之后的键更不能出现
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = 'probe.bad'`).Scan(&n); err != nil {
		t.Fatalf("查 probe.bad 失败: %v", err)
	}
	if n != 0 {
		t.Errorf("写失败的那一项居然落库了")
	}

	// 事务要能继续用：把触发器摘掉之后同一批必须成功（证明失败没把连接/事务卡死）
	for _, name := range []string{"probe_fail_insert", "probe_fail_update"} {
		if _, err := st.db.Exec(`DROP TRIGGER ` + name); err != nil {
			t.Fatalf("摘触发器失败: %v", err)
		}
	}
	if err := st.PutSettingsKV([][2]string{{"probe.a", "new-a"}, {"probe.bad", "new-bad"}}); err != nil {
		t.Fatalf("摘掉触发器之后同一批应当成功: %v", err)
	}
	if got := st.GetSetting("probe.bad", "<缺>"); got != "new-bad" {
		t.Errorf("重试写入没落库: %q", got)
	}
}

// busyRetry 语义与 PutSetting 一致：另一实例持写锁的瞬时窗口里，整批重试一次就过去，
// 而不是把"保存设置"整个失败掉。
//
// **必须先把连接的 busy_timeout 压成 0**：DSN 里带 `busy_timeout=5000`，
// 持锁 100ms 这种情形会被它直接等过去 —— 实测：把 busyRetry 从 PutSettingsKV 里
// 去掉，不压 busy_timeout 的版本**照样全绿**（测的是 DSN 超时，不是 busyRetry）。
// 压成 0 之后"撞锁"才是立刻返回的 BUSY，重试才真的在起作用。
//
// 造法：持锁 100ms（< busyRetryDelay 200ms）+ busy_timeout=0，
// 并先做一次自检直写（必须立刻 BUSY）。
//   - 修复后：两个键都写进去；
//   - 去掉 busyRetry：整批直接失败 → 必红。
func TestPutSettingsKVRetriesTransientBusy(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.db.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatalf("压 busy_timeout 失败: %v", err)
	}

	holder, err := sql.Open("sqlite", dsn(st.dbPath))
	if err != nil {
		t.Fatalf("开连接失败: %v", err)
	}
	defer holder.Close()
	holder.SetMaxOpenConns(1)
	conn, err := holder.Conn(t.Context())
	if err != nil {
		t.Fatalf("取连接失败: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("抢写锁失败: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = conn.ExecContext(t.Context(), "ROLLBACK")
	}()

	// 自检：零等待的直写必须立刻撞 BUSY
	probeStart := time.Now()
	if _, err := st.db.Exec(`INSERT INTO settings(key,value) VALUES('probe.selfcheck','x')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err == nil {
		t.Fatalf("自检失败：锁在别人手里，直写却成功了（busy_timeout 没压成 0？）")
	}
	if d := time.Since(probeStart); d > 60*time.Millisecond {
		t.Fatalf("自检失败：直写等了 %v 才报错，说明它还在等锁而不是立刻 BUSY", d)
	}

	if err := st.PutSettingsKV([][2]string{{"probe.x", "1"}, {"probe.y", "2"}}); err != nil {
		t.Fatalf("瞬时 BUSY 应当重试一次后成功，实际失败: %v", err)
	}
	for _, k := range []string{"probe.x", "probe.y"} {
		if got := st.GetSetting(k, "<缺>"); got == "<缺>" {
			t.Errorf("重试写入没落库: %s", k)
		}
	}
}
