package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
)

// 这组测试固化第二轮审计（audit42）里 store 包那几条修复。
//
// 每条断言都写成"改回错误版本会红"：
//   - H1  打开成功但驱动丢了非空 -wal → note 必须报出来
//   - M3  迁移前先探有没有行要改 + BUSY 短延时重试
//   - M4  跨进程误标活会话（按 owner_pid 判、逐行判）
//   - M5  留档后新建失败 → 错误里必须带留档路径（L2 同源）
//   - L1  副文件改名失败的原因要进用户文本
//   - L3  PruneConnections 两条 DELETE 同一个事务
//   - L4  ThreatStats 的 rows.Err() 必须查
//   - L5  DeleteTarget 的"先读后写"窗口
//   - L6  busy_timeout / foreign_keys 进 DSN（换新连接也要生效）
//   - L7  PRAGMA user_version 写入 + 版本比自己新就拒绝
//   - L8  normalizeTS 区间判据 + GetSetting 不再吞读错误

// ---------- H1：成功路径必须报"驱动丢弃了副文件" ----------

// 端到端：主库完好、旁边那份非空 -wal 在"打开成功"的过程中**被驱动丢弃**时，
// OpenDetail 必须在 note 里说明，而不是 ok + note=""。
//
// 这条是 H1 那条修复的回归锁：把成功路径改回 `return s, "", nil`
// （或者把快照挪到第一次 openOnce 之后）就必红。
//
// 造法（**注入点**）：本机实测驱动在"垃圾 -wal + 合法主库"这种形态下会把 -wal
// 留在原地（只是不认它的内容），"打开前有、打开后没了"这个可观察量造不出来
// （审计报告那台机器上驱动是删掉了它）。钩子在"打开成功、判定之前"触发一次，
// 拿到 Store 是为了能先关句柄再挪走那份副文件 —— 那正是"驱动丢了数据"对外部的样子。
func TestH1SuccessPathReportsDiscardedSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awdshell.db")

	// 真库：有表有数据
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

	// 旁边放一个非空的 -wal（"可能含着全部已提交数据"的那种形态）
	if err := os.WriteFile(path+"-wal", []byte("pretend this holds committed frames"), 0o600); err != nil {
		t.Fatalf("造 -wal 失败: %v", err)
	}

	sawLost := false
	orig := openOnceSucceededHook
	openOnceSucceededHook = func(s *Store) {
		// 钩子在"打开成功、判定之前"跑：先关句柄（Windows 上打开着的 -wal 挪不动），
		// 再看那份副文件还在不在。
		//   - 已经不在了：说明这次打开确实把它丢掉了（本机在建立连接时就会删掉），
		//     下面的 note 断言直接适用；
		//   - 还在：主动挪走它，造出等价形态。
		_ = s.db.Close()
		if _, statErr := os.Stat(path + "-wal"); statErr != nil {
			sawLost = true
			return
		}
		if err := os.Rename(path+"-wal", path+"-wal.discarded"); err != nil {
			t.Logf("挪走 -wal 失败: %v", err)
			return
		}
		sawLost = true
	}
	defer func() { openOnceSucceededHook = orig }()

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Skipf("这次打开没成功（%v），测试前提不成立", err)
	}
	defer st.Close()

	if !sawLost {
		t.Skip("这份 -wal 既没被打开过程丢掉、也挪不动，本机造不出该形态")
	}

	if note == "" {
		t.Fatal("打开前 -wal 非空、打开后被丢弃，note 却是空的 —— " +
			"用户会在不知情的情况下继续往这个库写（等于毁掉从备份恢复的最后机会）")
	}
	if !strings.Contains(note, "-wal") {
		t.Errorf("note 没点名被丢弃的副文件: %q", note)
	}
	if !strings.Contains(note, "丢弃") {
		t.Errorf("note 没说清是'被驱动丢弃'（而不是别的补救）: %q", note)
	}
	// 不能借着这条警告去做留档重建：主库是好的，绝不能改名
	if strings.Contains(note, ".corrupt-") {
		t.Errorf("主库是好的，不该走留档重建: %q", note)
	}
}

// 正常库不能被误报：旁边那份 0 字节副文件被驱动清掉是常态，不是丢数据。
func TestH1EmptySidecarIsNotReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.db")

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("造空库失败: %v", err)
	}
	if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
		t.Fatalf("造空 -wal 失败: %v", err)
	}
	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer st.Close()
	if strings.Contains(note, "丢弃") {
		t.Fatalf("0 字节副文件被当成'丢了数据'（每个正常库都会被吓一次）: %q", note)
	}
}

// ---------- M3：迁移前先探 + BUSY 短延时重试 ----------

// 干净库（没有行要改）在别人持写锁时启动，必须走"只读探针 + 跳过"，而不是
// 去抢写锁。修复前每次启动无条件发两条迁移 UPDATE，另一实例持写锁时要等满
// busy_timeout（生产值 5000ms）然后以
// 「迁移核查报告时间戳失败: database is locked (5)」退出，程序起不来。
//
// 锁持 **8 秒**（> busy_timeout=5s），判据是"打开成功"：
//   - 修复后：只读探针不取写锁 → 立刻成功（实测 ~0.1s，日志里能看到）；
//   - 改回无条件写：写锁要等满 5s → `database is locked` → 必红。
//
// 判据不只是"打开成功"，**还必须看耗时**：这条测试持锁 8 秒 = 1.6 × busy_timeout，
// 只断言 err==nil 的话，"去掉只读探针（退回无条件 UPDATE）"的变异会一直等到锁释放
// （实测 8.067s）然后**成功返回** —— 正确实现与错误实现的外部表现完全一样，测试
// 照样全绿，等于没锁住任何东西（复审 P0-3 实测：基线 1.45ms 绿 / 变异 8.067s 绿）。
// 所以加一条"干净库必须在 1 秒内返回"的上限：探针在时实测 2ms（余量 500 倍），
// 去了探针就是 ~8s，一眼能分开。
//
// 为什么不用"持锁 20 秒"那条路：那只是让变异等得更久，判据仍然是二值的
// "成功/失败"，而正确实现的耗时优势（2ms vs 10.25s）本来就更直接。
// 为什么耗时阈值在这里可靠：`PRAGMA journal_mode=WAL` 对**已经是 WAL** 的库是
// 无操作的，实测在别人持写锁时也只花 2ms（审计用持锁 20 秒对照验证过），
// 不会把持锁时间混进这条断言。
func TestM3CleanStartupSkipsMigrationUnderWriteLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clean.db")

	st0, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	_ = st0.Close()

	// 另一实例：占住写锁 8 秒（> busy_timeout）
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("开连接失败: %v", err)
	}
	defer raw.Close()
	raw.SetMaxOpenConns(1)
	if _, err := raw.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatalf("设 busy_timeout 失败: %v", err)
	}
	conn, err := raw.Conn(t.Context())
	if err != nil {
		t.Fatalf("取连接失败: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("抢写锁失败: %v", err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(8 * time.Second)
		_, _ = conn.ExecContext(t.Context(), "ROLLBACK")
		close(released)
	}()

	started := time.Now()
	st, _, err := OpenDetail(path)
	elapsed := time.Since(started)
	if err != nil {
		_, _ = conn.ExecContext(t.Context(), "ROLLBACK")
		<-released
		t.Fatalf("干净库的启动不该被别人的写锁挡住（应当先探、没有行要改就跳过）: %v", err)
	}
	_ = st.Close()
	if elapsed > time.Second {
		_, _ = conn.ExecContext(t.Context(), "ROLLBACK")
		<-released
		t.Fatalf("干净库启动用了 %v（> 1s）—— 说明它在为「没有行要改」的迁移抢写锁，"+
			"只读探针没了（复审 P0-3：只断言 err==nil 的话这条变异会被持锁时长吃掉）", elapsed)
	}
	_, _ = conn.ExecContext(t.Context(), "ROLLBACK")
	<-released
}

// 真有行要改、且别人正持锁时，BUSY 要短延时重试一次而不是直接失败。
//
// **必须先把这条连接的 busy_timeout 压成 0**：DSN 里带 `busy_timeout=5000`，
// 而这里只持锁 100ms —— 不压的话第一次写会老老实实等 100ms 然后成功，测的就不是
// busyRetry 而是 DSN 的超时。实测（复审 rev42 这条的变异没守住）：把 busyRetry
// 从 PutSetting 里整个去掉，老版本（持锁 300ms + 不动 busy_timeout）**仍然全绿**
// —— 因为 5000ms 的 busy_timeout 把 300ms 的锁直接等过去了。
//
// 造法：持锁 100ms（< busyRetryDelay 200ms）+ 连接 busy_timeout=0
//   - 第一次写立刻得 BUSY（不等待）→ 睡 200ms → 重试时锁已释放（100ms 就放了）；
//   - 自检：抢锁期间先直写一次，必须**立刻**失败且耗时极短 —— 证明"零等待 +
//     锁在别人手里"这两件事都真的生效了，不然这条测试又是在测别的东西；
//   - 去掉 busyRetry：第一次 BUSY 直接失败 → 必红。
func TestM3BusyRetryOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "busy.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	defer st.Close()
	if _, err := st.db.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatalf("压 busy_timeout 失败: %v", err)
	}

	holder, err := sql.Open("sqlite", dsn(path))
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

	// 自检：零等待的直写必须立刻撞 BUSY（证明环境成立，而不是"其实在等锁"）
	probeStart := time.Now()
	if _, err := st.db.Exec(`INSERT INTO settings(key,value) VALUES('probe.selfcheck','x')
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err == nil {
		t.Fatalf("自检失败：锁在别人手里，直写却成功了（busy_timeout 没压成 0？）")
	}
	if d := time.Since(probeStart); d > 60*time.Millisecond {
		t.Fatalf("自检失败：直写等了 %v 才报错，说明它还在等锁而不是立刻 BUSY", d)
	}

	if err := st.PutSetting("audit42_retry_probe", "v"); err != nil {
		t.Fatalf("瞬时 BUSY 应当重试一次后成功，实际失败: %v", err)
	}
	if got := st.GetSetting("audit42_retry_probe", ""); got != "v" {
		t.Fatalf("重试写没落库: %q", got)
	}
}

// ---------- M4：跨进程不能凭 bootAt 误标活会话 ----------

// 写下记录的进程还活着时，它那条"进行中"的记录不能被标 —— 哪怕那条记录是
// **本进程启动之前**开始的老记录（跨进程形态就是这样：A 一直在跑，B 后启动）。
// 判据必须是逐行的 owner_pid + 进程存活，而不是一条 UPDATE 里的
// `started_at < bootAt`。
//
//   - 修复后：ownerAlive 说"那个 pid 还在" → 标记 0 条；
//   - 改回一条 UPDATE（只比 started_at < bootAt）→ 标 1 条 → 必红。
func TestM4AliveForeignProcessIsNotMarked(t *testing.T) {
	st := newTestStore(t)

	id, err := st.AddConnection(domain.ConnectionRecord{
		Host: "peer", Port: 22, Username: "root", StartedAt: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("写入连接失败: %v", err)
	}
	// 造出"另一个进程在本进程启动之前就建了这条会话"：pid 不是本进程，
	// 且 started_at 早于本进程启动（老判据会把它标掉）。started_at 必须是**秒级
	// 毫秒值**（早期测试里写成 bootAt-2000 会因为差 2 秒落在 bootAt 之前而生效，
	// 但这里直接写死 3 秒前的绝对时间，避免精度问题）。
	if _, err := st.db.Exec(`UPDATE connections SET owner_pid = 991998, started_at = ? WHERE id = ?`,
		time.Now().UnixMilli()-3000, id); err != nil {
		t.Fatalf("改成别的进程写的失败: %v", err)
	}

	origAlive := ownerAlive
	ownerAlive = func(pid int) bool { return pid == 991998 } // 那个进程还活着
	defer func() { ownerAlive = origAlive }()

	n, err := st.MarkStaleConnections("程序未正常退出")
	if err != nil {
		t.Fatalf("标记失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("别人正在跑的会话被标脏了（标记 %d 条）—— 判据里没有 owner_pid 这条？", n)
	}

	list, err := st.ListConnections(10)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(list) != 1 || list[0].EndedAt != 0 || list[0].Error != "" {
		t.Fatalf("活连接被改动了: %+v", list)
	}

	// 判据不能变成"谁也不标"：那个进程没了，就是崩溃残留，照旧要标
	ownerAlive = func(pid int) bool { return false }
	n2, err := st.MarkStaleConnections("程序未正常退出")
	if err != nil {
		t.Fatalf("标记失败: %v", err)
	}
	if n2 != 1 {
		t.Fatalf("进程已消失的残留会话应当被标 1 条，实际 %d 条", n2)
	}
}

// ---------- M5/L2：留档后新建失败，错误里必须带留档路径 ----------

// 主库损坏 → 留档改名成功 → 在原路径新建空库失败。这时错误如果不带留档路径，
// 用户下次启动看到的是一个"一切正常"的空库（0 字节文件在 sqlite 眼里是合法空库），
// 没有任何线索指向 `.corrupt-*`。
//
// **诚实说明**：这条分支在本机（Windows）**没法端到端造出来** —— 试过的三种
// 造法（留档前占用原路径的只读句柄、让原路径变成目录、让父目录只读）都先在
// "rename 主库"那一步失败（错误里本来就带路径），走不到"新建失败"。
// 所以这里把**错误文本本身**钉死：分支里必须出现 backup 变量。改回
// `fmt.Errorf("数据库已损坏，留档为 %s 后新建也失败: %w", ...)` 之前那版
// （只写"留档为 %s"）不会红，但把 backup 从文案里去掉就必红 —— 这正是要锁住的行为。
func TestM5RebuildFailureErrorNamesBackupPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awdshell.db")
	backup := path + ".corrupt-20260101-000000.000000000"

	// 复刻生产代码那一行的构造方式（同一个格式串、同一个 backup 变量位置）
	err := rebuildFailedError(backup, errors.New("disk I/O error"), nil)
	if !strings.Contains(err.Error(), backup) {
		t.Fatalf("新建失败的错误里没有留档路径（用户找不到旧数据）: %v", err)
	}
	if !strings.Contains(err.Error(), ".stale-") {
		t.Fatalf("错误里没提旁边可能还有 .stale-* 副文件: %v", err)
	}

	// 这条失败出口同样不能丢掉"驱动删了副文件"——与第三步的 note 同类
	// （复审 H1：信息只喂给 error 链、成功出口各自为政，就在这个函数上重演过一次）
	lost := path + "-wal"
	err = rebuildFailedError(backup, errors.New("disk I/O error"), []string{lost})
	if !strings.Contains(err.Error(), lost) {
		t.Fatalf("错误里没有那条被驱动删掉的副文件（它可能含着全部已提交的数据）: %v", err)
	}
	if !strings.Contains(err.Error(), "驱动") {
		t.Fatalf("错误里没说清是驱动把副文件删了: %v", err)
	}
}

// ---------- L1：副文件改名失败的原因要进用户文本 ----------

// -wal 改名失败（被占用/权限）时，用户必须知道它还挂在原路径上、别当垃圾删了。
// 以前 moveErr 只当布尔用，失败原因从不进 error/note。
//
// 同样是"故障文本"层面的判据：端到端造 rename 失败要么看驱动脸色（Windows 允许
// 重命名被打开的文件），要么在 rename 之前就失败。所以直接验装配函数。
func TestL1MoveFailureReasonReachesUser(t *testing.T) {
	orig := errors.New("file is not a database")
	moved := []movedSidecar{{Src: "a.db-shm", Dst: "a.db-shm.stale-STAMP"}}
	moveErr := errors.New("rename a.db-wal: Access is denied")

	got := wrapLostSidecars(orig, nil, moved, moveErr)
	if got == nil {
		t.Fatal("装配函数不该返回 nil")
	}
	msg := got.Error()
	if !strings.Contains(msg, "Access is denied") {
		t.Fatalf("改名失败的原因没进用户文本（用户不知道是权限还是占用）: %v", msg)
	}
	if !strings.Contains(msg, "没能移到一边") {
		t.Fatalf("用户看不出'有副文件没搬走、别删它': %v", msg)
	}
	if !errors.Is(got, orig) {
		t.Fatalf("原始错误被丢掉了（错误链断了）: %v", got)
	}

	// 没失败时不能凭空加这句
	if clean := wrapLostSidecars(orig, nil, moved, nil); strings.Contains(clean.Error(), "没能移到一边") {
		t.Fatalf("没失败却报了失败: %v", clean)
	}

	// 被驱动删掉的副文件必须点名（moved 为空时也要报）
	lost := wrapLostSidecars(orig, []string{"a.db-wal"}, nil, nil)
	if !strings.Contains(lost.Error(), "a.db-wal") || !strings.Contains(lost.Error(), "驱动已删除") {
		t.Fatalf("驱动删掉的副文件没被点名: %v", lost)
	}
}

// ---------- L3：PruneConnections 两条 DELETE 必须同一个事务 ----------

// 行为判据：两条 DELETE 在一起时最终留下的必须是"最新 2 条"，被删的条数要对得上。
//
// **诚实说明**：这次修复（把两条独立 `s.db.Exec` 收进一个 `tx`）在 SQLite 上
// **从外部观察不到差别** —— 单连接下 autocommit 的每一条语句与显式事务中的语句
// 对后续语句的可见性完全一样，改回独立 Exec 时这条测试照样绿（我用"代理视图 +
// 触发器计次"验过：两种实现都响 4 次）。真正能看出差别的只有代码本身：现在两条
// DELETE 挂在同一个 `tx` 上、只有一次 `Commit`，任一步出错整体回滚 ——
// 这条测试负责的是"改动没有破坏清理语义"。
func TestL3PruneConnectionsKeepsNewest(t *testing.T) {
	st := newTestStore(t)

	old := time.Now().AddDate(0, 0, -60).UnixMilli()
	fresh := time.Now().UnixMilli()
	// 6 条：1 条过期 + 5 条新的
	for i, ts := range []int64{old, fresh, fresh + 1, fresh + 2, fresh + 3, fresh + 4} {
		if _, err := st.AddConnection(domain.ConnectionRecord{
			Host: "h", Port: 22, Username: "root", StartedAt: ts + int64(i),
		}); err != nil {
			t.Fatalf("插入连接失败: %v", err)
		}
	}

	n, err := st.PruneConnections(30, 2)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if n != 4 {
		t.Fatalf("该删 4 条（1 条过期 + 裁掉 3 条超额的），实际 %d 条", n)
	}
	list, err := st.ListConnections(10)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("最终该只剩最新 2 条，实际 %d 条", len(list))
	}
	if list[0].StartedAt <= list[1].StartedAt {
		t.Fatalf("留下的不是最新的两条: %+v", list)
	}
	if list[1].StartedAt < fresh {
		t.Fatalf("留下的记录里有那条过期的: %+v", list)
	}

	// 两个条件都不启用时不该开事务、也不该删东西
	if n, err := st.PruneConnections(0, 0); err != nil || n != 0 {
		t.Fatalf("0/0 应当什么都不做: n=%d err=%v", n, err)
	}
}

// ---------- L4：ThreatStats 必须查 rows.Err() ----------

// 让"后续查询失败"发生在**迭代中途**：先把 byTarget 要用的列删掉，再调
// ThreatStats —— 第一条查询（按来源 IP）照常成功，第二条（按目标名）会以
// `no such column: target_name` 失败。老实现（迭代完直接 Close）会把它当成
// "结果就这么多"，ThreatStats 于是返回 nil error + 一份**少数据的**统计。
//
// 两个坑（都踩过）：
//  1. schema 变更必须走**另一条连接**：Store 是 MaxOpenConns=1，原连接上再发
//     一条语句会等自己释放连接 → 死锁到测试超时（实测 10 分钟超时）；
//  2. 变更必须在 ThreatStats 之前**真的生效**：实测在第一条 rows 还开着的时候
//     发 ALTER，它要等锁释放、与后面的查询并发，本连接会继续用缓存的 schema，
//     后面那些查询反而全部成功、错误根本出不来。
//
// **诚实说明**：这条**抓不住** `collectRows` 里把 `return rows.Err()` 改成
// `return nil` 那种回退 —— 第二条查询在 `Query()` 这一步就失败了（错误经返回值
// 交出，不经过 rows.Err()），两条实现都会让 ThreatStats 返回错误。它守住的是
// "查询失败不会被吞成 nil error + 少数据的统计"这个行为，以及 collectRows 这条
// 收敛路径没有把错误吃掉。
func TestL4ThreatStatsChecksRowsErr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UnixMilli()
	if err := st.InsertScanEvents([]ScanEvent{
		{TS: now, TargetID: "t1", TargetName: "web", SourceIP: "10.0.0.9", Severity: "critical", Category: "rce", RuleID: "r1"},
		{TS: now + 1, TargetID: "t1", TargetName: "web", SourceIP: "10.0.0.8", Severity: "low", Category: "scan", RuleID: "r2"},
	}); err != nil {
		t.Fatalf("写事件失败: %v", err)
	}

	admin, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("开管理连接失败: %v", err)
	}
	defer admin.Close()
	admin.SetMaxOpenConns(1)
	if _, err := admin.Exec(`PRAGMA busy_timeout=0`); err != nil {
		t.Fatalf("设 busy_timeout 失败: %v", err)
	}
	if _, err := admin.Exec(`ALTER TABLE scan_events DROP COLUMN target_name`); err != nil {
		t.Fatalf("测试前提不成立：删列失败 %v", err)
	}

	stats, err := st.ThreatStats(now-1000, "")
	if err == nil {
		t.Fatalf("查询中途失败被当成'结果就这么多'：ThreatStats 返回 nil error（rows.Err 没查）: bySourceIP=%d byTarget=%v",
			len(stats.BySourceIP), stats.ByTarget)
	}
	if !strings.Contains(err.Error(), "target_name") {
		t.Fatalf("错误不是后续查询失败造成的，测试前提可疑: %v", err)
	}
	// 第一条查询确实跑成功了 —— 说明错误来自"迭代中途"，不是一开始就失败
	if len(stats.BySourceIP) != 2 {
		t.Fatalf("第一条查询没跑出结果（测试前提不成立）: %v", stats.BySourceIP)
	}
}

// ---------- L5：DeleteTarget 的"读 secret_id"与"删目标"必须原子 ----------

// 老实现是"先 GetTarget（事务外读 secret_id）→ 再开事务删"，两步之间没有锁。
// 现在两个动作在同一条 DELETE ... RETURNING 里。
//
// **诚实说明：这条在"改回旧版必红"这一条上做不到**。要落进旧版那条缝隙，需要在
// "读完成"与"事务开始"之间插一次写提交；但本包的 Store 是 MaxOpenConns(1)，
// 那时的连接已经还回池里，同进程里任何写在时序上都落在事务之前 —— 两种实现看到
// 的是同一个 secret_id（实测：改成旧写法这条测试照样绿）。
// 所以这里只钉**行为正确性**：目标被删、它那一行的密文跟着走、别人的密文不动。
// 直接能看出差别的地方在 store.go 的代码本身：DeleteTarget 里没有事务外的 GetTarget。
func TestL5DeleteTargetRemovesItsOwnSecretOnly(t *testing.T) {
	st := newTestStore(t)

	if _, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "web", Host: "10.0.0.5", Port: 22,
		Username: "root", AuthKind: domain.AuthPassword, SecretID: "own-secret",
	}); err != nil {
		t.Fatalf("保存目标失败: %v", err)
	}
	if err := st.PutSecret("own-secret", []byte("n"), []byte("own")); err != nil {
		t.Fatalf("写自己密文失败: %v", err)
	}
	if err := st.PutSecret("other-secret", []byte("n"), []byte("other")); err != nil {
		t.Fatalf("写别人密文失败: %v", err)
	}

	if err := st.DeleteTarget("t1"); err != nil {
		t.Fatalf("删除目标失败: %v", err)
	}
	if _, err := st.GetTarget("t1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("目标没被删掉: %v", err)
	}
	if _, _, err := st.GetSecret("own-secret"); err == nil {
		t.Fatalf("目标没了、它自己的密文还在（孤儿密文能解出明文口令）")
	}
	if _, _, err := st.GetSecret("other-secret"); err != nil {
		t.Fatalf("删一个目标时误删了别人的密文: %v", err)
	}

	// 删不存在的目标要明确报错，不能静默成功（RETURNING 没有行 = ErrNoRows）
	if err := st.DeleteTarget("t1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删不存在的目标应当报 ErrNotFound，实际: %v", err)
	}
}

// ---------- L6：busy_timeout / foreign_keys 必须进 DSN ----------

// 连接级 PRAGMA 只作用于当时那条连接：连接被换掉就退回默认值。
//   - 修复后：sql.Open(dsn(path)) 的**新连接**上 foreign_keys=1；
//   - 改回 sql.Open(path)：新连接 foreign_keys=0 → 必红。
func TestL6DSNCarriesConnectionPragmas(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pragma.db")

	openWithPragma := func(dsnPath string) (int, int) {
		db, err := sql.Open("sqlite", dsnPath)
		if err != nil {
			t.Fatalf("打开失败: %v", err)
		}
		defer db.Close()
		var fk, busy int
		if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
			t.Fatalf("读 foreign_keys 失败: %v", err)
		}
		if err := db.QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
			t.Fatalf("读 busy_timeout 失败: %v", err)
		}
		return fk, busy
	}

	fk, busy := openWithPragma(path)
	if fk != 0 {
		t.Fatalf("前提不成立：不给 DSN 时 foreign_keys 竟然是开的（%d）", fk)
	}
	if busy != 0 {
		t.Fatalf("前提不成立：不给 DSN 时 busy_timeout 竟然不是 0（%d）", busy)
	}

	fk, busy = openWithPragma(dsn(path))
	if fk != 1 {
		t.Fatalf("DSN 没带上 foreign_keys（新连接退回 OFF）: %d", fk)
	}
	if busy != 5000 {
		t.Fatalf("DSN 没带上 busy_timeout（新连接退回 0）: %d", busy)
	}
}

// ---------- L7：PRAGMA user_version ----------

// 打开时写入版本号；比自己新的库必须明确拒绝（老客户端照常写会破坏新数据）。
func TestL7SchemaVersionWrittenAndNewerRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ver.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	var ver int
	if err := st.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		t.Fatalf("读版本失败: %v", err)
	}
	if ver != schemaVersion {
		t.Fatalf("打开后 user_version=%d，期望 %d（版本号没写进去）", ver, schemaVersion)
	}
	if _, err := st.db.Exec(`PRAGMA user_version = 9999`); err != nil {
		t.Fatalf("写版本失败: %v", err)
	}
	_ = st.Close()

	if _, _, err := OpenDetail(path); err == nil {
		t.Fatal("比自己新的库必须拒绝打开，实际成功了（老客户端会写坏新数据）")
	} else if !strings.Contains(err.Error(), "结构版本") {
		t.Fatalf("拒绝的理由不对: %v", err)
	}
}

// ---------- L8：normalizeTS 判据 + GetSetting 不吞读错误 ----------

// 2026-10-11 那天的秒值，多处测试共用。
const secs2026 = int64(1791544791)

func TestL8NormalizeTSUsesSameRangeAsMigration(t *testing.T) {
	cases := []struct {
		in   int64
		want int64
	}{
		{secs2026, secs2026 * 1000},        // 2026 年的秒值 → 毫秒
		{946684800, 946684800000},          // 区间下界（2000-01-01 秒值）
		{4102444800, 4102444800},           // 区间上界不再是秒
		{secs2026 * 1000, secs2026 * 1000}, // 本来就是毫秒，不能重复乘
		{1e10, 1e10},                       // 1973 年的毫秒值：旧判据（ts<1e11）会错乘 1000
		{1000, 1000},                       // 小值（1970 年的毫秒）不能被当秒
		{0, 0},
	}
	for _, c := range cases {
		if got := normalizeTS(c.in); got != c.want {
			t.Errorf("normalizeTS(%d)=%d，期望 %d（判据必须与 SQL 迁移的区间一致）", c.in, got, c.want)
		}
	}
}

// 秒级/坏值 TS 必须在**写侧**就被收拾成毫秒。
//
// 为什么写侧而不是读侧：PruneComplianceReports 是拿**原始 ts** 与毫秒 before 在
// SQL 里比大小的，秒级行会被当成 1970 年的"祖传数据"直接删掉（等下次 Open 才会
// 被迁移救回）。读侧的 normalizeTS 挡不住这件事，所以这里直接查**落库的原始值**：
//   - 修复后：落库就是 secs*1000；
//   - 改回不校验（旧版）：落库是 secs → 必红。
func TestL8SaveComplianceReportNormalizesTS(t *testing.T) {
	st := newTestStore(t)

	const secs = int64(1791544791) // 2026-10-11 的秒值
	id, err := st.SaveComplianceReport(ComplianceReport{TS: secs, TargetID: "new", Score: 90})
	if err != nil {
		t.Fatalf("保存报告失败: %v", err)
	}

	var rawTS int64
	if err := st.db.QueryRow(`SELECT ts FROM compliance_reports WHERE id = ?`, id).Scan(&rawTS); err != nil {
		t.Fatalf("读原始 ts 失败: %v", err)
	}
	if rawTS != secs*1000 {
		t.Fatalf("秒级 TS 没在写侧归一：落库 %d（期望 %d）—— 它会被保留期清理当成 1970 年的数据删掉",
			rawTS, secs*1000)
	}

	// 零值仍然盖成"现在"（原有行为）
	nowID, err := st.SaveComplianceReport(ComplianceReport{TargetID: "now"})
	if err != nil {
		t.Fatalf("保存零值 TS 的报告失败: %v", err)
	}
	var nowTS int64
	if err := st.db.QueryRow(`SELECT ts FROM compliance_reports WHERE id = ?`, nowID).Scan(&nowTS); err != nil {
		t.Fatalf("读 ts 失败: %v", err)
	}
	if nowTS < time.Now().Add(-time.Hour).UnixMilli() {
		t.Fatalf("零值 TS 没盖成现在: %d", nowTS)
	}
}

// normalizeOrNow：坏值（1980 年前的毫秒值之类）不能被原样塞进库里 ——
// 那会变成一条永远排在最后、还会被清理当垃圾删掉的记录。
func TestL8NormalizeOrNowRejectsBadValues(t *testing.T) {
	now := time.Now().UnixMilli()

	if got := normalizeOrNow(0); got < now-1000 || got > now+1000 {
		t.Errorf("0 应当盖成现在，实际 %d", got)
	}
	if got := normalizeOrNow(secs2026); got != secs2026*1000 {
		t.Errorf("秒值应当乘 1000，实际 %d", got)
	}
	// 区间**之外**的值不动：1e10 秒是 2286 年、1e11 毫秒是 1973-03-03，
	// 两者都不该被乘 1000。
	if got := normalizeOrNow(int64(1e10)); got != int64(1e10) {
		t.Errorf("区间外的值不该被改动: %d", got)
	}
	if got := normalizeOrNow(int64(1e11)); got != int64(1e11) {
		t.Errorf("1973 年的毫秒值不该被当秒乘 1000（旧判据 `ts<1e11` 的 bug）: %d", got)
	}
	// 区间**之内**的就是秒（与 SQL 迁移同一判据）
	if got := normalizeOrNow(secs2026); got != secs2026*1000 {
		t.Errorf("区间内的秒值应当乘 1000，实际 %d", got)
	}
	if got := normalizeOrNow(-5); got < now-1000 {
		t.Errorf("负值应当被当坏值盖成现在，实际 %d", got)
	}
	good := now - 60_000
	if got := normalizeOrNow(good); got != good {
		t.Errorf("正常毫秒值不该被改动: %d → %d", good, got)
	}
}

// GetSetting 读不动库时不能再把"设过的值"显示成默认值。
func TestL8GetSettingErrSurfacesReadFailure(t *testing.T) {
	st := newTestStore(t)
	if err := st.PutSetting("theme", "dark"); err != nil {
		t.Fatalf("写设置失败: %v", err)
	}
	if got, err := st.GetSettingErr("theme", "light"); err != nil || got != "dark" {
		t.Fatalf("正常读取失败: %q %v", got, err)
	}
	if got, err := st.GetSettingErr("nope", "light"); err != nil || got != "light" {
		t.Fatalf("没设过的键应当返回默认值且不报错: %q %v", got, err)
	}

	// 关掉句柄：读必然失败（database/sql 不会自动重开）
	if err := st.db.Close(); err != nil {
		t.Fatalf("关句柄失败: %v", err)
	}
	if _, err := st.GetSettingErr("theme", "light"); err == nil {
		t.Fatal("库读不动时必须交出错误（以前直接吞成默认值，设置页显示假的现状）")
	}
}

// ---------- M2 的另一半：删除检测不能嵌在"移走了东西"分支里 ----------

// missingSidecarPaths 必须在**一个副文件都没移成**时也跑：那种情况下用户手里
// 只有一句 "file is not a database"，不会知道旁边的 -wal 已经没了。
//
// 这条用返回值层面的判据钉住（端到端会看驱动脸色）：moved 为空时照样要能报出
// "打开前存在、现在没了"的副文件。
func TestM2LostDetectionWorksWithoutAnyMoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awdshell.db")

	if err := os.WriteFile(path+"-wal", []byte("w"), 0o600); err != nil {
		t.Fatalf("造 -wal 失败: %v", err)
	}
	snap := sidecarSnapshot(path)
	if err := os.Remove(path + "-wal"); err != nil {
		t.Fatalf("移除失败: %v", err)
	}
	// moved 为空（改名被占用挡住时就是这个形态）
	if lost := missingSidecarPaths(path, snap, nil); len(lost) != 1 {
		t.Fatalf("一个副文件都没移走时，删除检测没跑: %v", lost)
	}
}

// ---------- 目标：给 helper 进程造一个有 -wal 的活库 ----------

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(path); err == nil && st.Size() > 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("等超时: " + path)
}
