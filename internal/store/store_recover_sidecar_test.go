package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
)

// 这组测试固化复审里的两条 store 修复，断言都写成"改回错误版本会红"。

// ---------- 中1：交出去的文本必须点名副文件的落点 ----------

// 第一步移走副文件之后仍然打不开时，note 里必须带上 `.stale-*` 落点。
//
// 场景怎么定的（实测，不是猜的）：`path` 不是数据库、旁边的 -wal 是**空文件**。
// 这是少数真能走到"移走副文件"的形态 —— 打开失败时驱动对副文件的处理不一样：
//   - -wal 是**非空**垃圾：驱动把它当 WAL 尝试恢复，失败时会把 -wal/-shm 一并
//     删掉，于是 moveSidecars 没东西可移（那种情况丢的是数据，见下一条测试）；
//   - -shm 是目录、或 -wal 非空时报 `unable to open database file (526)`
//     （CANTOPEN），looksCorrupt 认不出来，第一步压根不会执行。
//
// 只有"主库不是数据库 + 空 -wal"能稳定走到留档重建。
//
// 修复前：note 里只有 `.corrupt-*` 与"旧数据从留档文件恢复"，一个字都不提
// `.stale-*`（实测 note 里 strings.Contains(note,"stale") == false）。用户照着
// note 去那个新建的空库旁边找数据，而真正装着已提交数据的副文件名字从未出现过。
func TestOpenDetailNoteNamesMovedSidecar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awdshell.db")

	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database file"), 0o600); err != nil {
		t.Fatalf("造坏库失败: %v", err)
	}
	// 空 -wal：驱动不会把它当"待恢复的 WAL"删掉，moveSidecars 才有东西可移
	if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
		t.Fatalf("造空 -wal 失败: %v", err)
	}

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("这个组合应当走完补救流程，实际失败: %v", err)
	}
	defer st.Close()

	if !strings.Contains(note, "-wal.stale-") {
		t.Fatalf("note 没报出副文件的落点，用户会漏掉可能含已提交数据的文件：%q", note)
	}

	// 落点必须是盘上真实存在的文件，而不是一句空话
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("读目录失败: %v", readErr)
	}
	stale := ""
	for _, e := range entries {
		if strings.Contains(e.Name(), "-wal.stale-") {
			stale = e.Name()
		}
	}
	if stale == "" {
		t.Fatalf("note 说有落点，盘上却没有 .stale 文件：%q", note)
	}
	if !strings.Contains(note, stale) {
		t.Errorf("note 里的落点与盘上的文件名对不上：note=%q 盘上=%q", note, stale)
	}
	// 留档重建的说明也要在（这条路径最后是换了新库）
	if !strings.Contains(note, ".corrupt-") {
		t.Errorf("note 没提留档文件: %q", note)
	}
}

// 空 -shm 也走同一条路（两种副文件都要被点名，不能只认 -wal）。
func TestOpenDetailNoteNamesMovedSHM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awdshell.db")

	if err := os.WriteFile(path, []byte("this is definitely not a sqlite database file"), 0o600); err != nil {
		t.Fatalf("造坏库失败: %v", err)
	}
	if err := os.WriteFile(path+"-shm", nil, 0o600); err != nil {
		t.Fatalf("造空 -shm 失败: %v", err)
	}

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("这个组合应当走完补救流程，实际失败: %v", err)
	}
	defer st.Close()

	if !strings.Contains(note, "-shm.stale-") {
		t.Errorf("note 没报出 -shm 的落点：%q", note)
	}
}

// 驱动在打开失败时可能**已经删掉**副文件 —— 那种情形必须在文本里说明。
//
// 实测：主库不是数据库、旁边挂着 -wal（或 -shm）时，openOnce 返回
// `PRAGMA journal_mode=WAL 失败: file is not a database (26)`，而副文件有时**已经消失**
// （sqlite 是在删除 -wal/-shm 的过程中失败的）。用户手里只有这一句"不是数据库"，
// 他不会知道那个可能装着最新数据的副文件已经丢了、该去备份里找。
//
// 为什么这里只做单元测试、不做端到端：驱动"删不删"取决于当时挂了哪些副文件，
// 实测三种组合里只有一种会删（db+wal 有时删、db+shm 有时保留），端到端断言会
// 变成看驱动脸色的 flaky 测试。所以把判据本身钉死：给定"打开前存在、没被我们
// 移走、现在没了"，必须报出来；我们自己移走的、以及原本就不存在的，不能误报。
func TestMissingSidecarsDetectsDriverDeletionOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "awdshell.db")

	// -shm 打开前存在，现在没了，也不在我们移走的清单里 → 必须报
	if err := os.WriteFile(path+"-shm", []byte("s"), 0o600); err != nil {
		t.Fatalf("造 -shm 失败: %v", err)
	}
	existed := sidecarExisted(path)
	if len(existed) != 1 || existed[0] != "-shm" {
		t.Fatalf("打开前的副文件快照不对: %v", existed)
	}
	if err := os.Remove(path + "-shm"); err != nil {
		t.Fatalf("模拟驱动删除失败: %v", err)
	}
	lost := missingSidecars(path, existed, nil)
	if len(lost) != 1 || !strings.HasSuffix(lost[0], "-shm") {
		t.Fatalf("驱动删掉的副文件没被认出来: %v", lost)
	}

	// 我们自己移走的那份不算"被删"
	if err := os.WriteFile(path+"-wal", []byte("w"), 0o600); err != nil {
		t.Fatalf("造 -wal 失败: %v", err)
	}
	moved, err := moveSidecars(path, "STAMP")
	if err != nil || len(moved) != 1 {
		t.Fatalf("移走 -wal 失败: moved=%v err=%v", moved, err)
	}
	if got := missingSidecars(path, []string{"-wal"}, moved); len(got) != 0 {
		t.Errorf("我们自己移走的文件被误报成驱动删除: %v", got)
	}

	// 打开前不存在的，现在也不存在 —— 不能报（否则每个正常库都"数据丢了"）
	if got := missingSidecars(path, nil, nil); len(got) != 0 {
		t.Errorf("原本就没有的副文件被误报: %v", got)
	}
}

// moveSidecars 成功时必须返回**全部**移走的路径（不是只返回第一个）。
//
// 这是"返回 []string 而不是 string"的回归锁：改回只返回第一个时，拼出来的
// 文本里会丢掉 -shm，用户不知道旁边还有一份文件被挪动了。
func TestMoveSidecarsReturnsEveryMovedPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")

	for _, ext := range []string{"-wal", "-shm"} {
		if err := os.WriteFile(path+ext, []byte("x"), 0o600); err != nil {
			t.Fatalf("造 %s 失败: %v", ext, err)
		}
	}

	moved, err := moveSidecars(path, "STAMP")
	if err != nil {
		t.Fatalf("两个普通副文件都应当能移走: %v", err)
	}
	if len(moved) != 2 {
		t.Fatalf("移走了 %d 个副文件，应当返回全部 2 个: %v", len(moved), moved)
	}
	text := movedSidecarText(moved, " ")
	if !strings.Contains(text, "-wal.stale-STAMP") || !strings.Contains(text, "-shm.stale-STAMP") {
		t.Errorf("拼出来的文本漏了副文件: %q", text)
	}
	for _, ext := range []string{"-wal", "-shm"} {
		if _, statErr := os.Stat(path + ext); statErr == nil {
			t.Errorf("%s 还留在原路径上（只移动，不删除）", ext)
		}
	}
}

// moveSidecars 中途失败时必须把**此前已经移走**的路径带出来 —— 调用方就是靠这个
// 返回值在错误里点名落点的；返回空列表等于把已移走的副文件从记录里抹掉。
//
// 怎么造失败：把**第二个副文件的目的地**先占成一个非空目录。stamp 由调用方传入，
// 所以这个"目的地"是完全可预测的 —— Windows 上 os.Rename 能挪带内容的目录，
// 但把文件挪到一个非空目录上必然失败。
func TestMoveSidecarsReturnsPathsEvenOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.db")

	if err := os.WriteFile(path+"-wal", []byte("w"), 0o600); err != nil {
		t.Fatalf("造 -wal 失败: %v", err)
	}
	if err := os.WriteFile(path+"-shm", []byte("s"), 0o600); err != nil {
		t.Fatalf("造 -shm 失败: %v", err)
	}
	// 占住 -shm 的落点（非空目录）
	if err := os.Mkdir(path+"-shm.stale-STAMP", 0o700); err != nil {
		t.Fatalf("占位失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path+"-shm.stale-STAMP", "child"), []byte("x"), 0o600); err != nil {
		t.Fatalf("造占位内容失败: %v", err)
	}

	moved, err := moveSidecars(path, "STAMP")
	if err == nil {
		t.Fatal("第二个副文件挪不动时 moveSidecars 必须报错（以前把失败吞了）")
	}
	if len(moved) != 1 || !strings.HasSuffix(moved[0].Dst, "-wal.stale-STAMP") {
		t.Fatalf("失败前已移走的 -wal 必须出现在返回值里，实际 %v", moved)
	}
	if !strings.Contains(movedSidecarText(moved, " "), moved[0].Dst) {
		t.Errorf("拼出来的文本里没有落点: %q", movedSidecarText(moved, " "))
	}
	// 失败者不能假装成功
	for _, m := range moved {
		if strings.Contains(m.Dst, "-shm") {
			t.Errorf("挪失败的那一个不该出现在返回值里: %v", moved)
		}
	}
}

// ---------- 中2：bootAt 必须是进程级 ----------

// 第二个实例打开同一份数据目录时，不能把第一个实例**正在跑**的会话标脏。
//
// 修复前 bootAt 在每次 Open 时刷新，于是 st2 的判据是"晚于 st2 打开的时刻"，
// 而 st1 刚写入的那条 started_at 早于它 —— 实测标记 1 条，把活连接改成
// ended_at=... + error="程序未正常退出"。修复后 bootAt 取本进程启动时刻，
// 判据对同进程/跨进程的后来者一致成立，这条活连接不被标记。
func TestSecondStoreDoesNotMarkLiveConnectionStale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.db")

	st1, err := Open(path)
	if err != nil {
		t.Fatalf("打开第一个实例失败: %v", err)
	}
	defer st1.Close()

	liveID, err := st1.AddConnection(domain.ConnectionRecord{
		Host: "live", Port: 22, Username: "root", StartedAt: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("写入活跃会话失败: %v", err)
	}

	// 模拟"5ms 后另一个实例打开同一个库"
	time.Sleep(5 * time.Millisecond)
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("打开第二个实例失败: %v", err)
	}
	defer st2.Close()

	n, err := st2.MarkStaleConnections("程序未正常退出")
	if err != nil {
		t.Fatalf("标记失败: %v", err)
	}
	if n != 0 {
		t.Fatalf("正在跑的会话被标脏了：标记 %d 条（bootAt 又变回每次 Open 刷新了？）", n)
	}

	list, err := st1.ListConnections(10)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	for _, c := range list {
		if c.ID == liveID && (c.EndedAt != 0 || c.Error != "") {
			t.Fatalf("活连接的 ended_at/error 被改动了: %+v", c)
		}
	}

	// 判据不能因此变成"谁也不标"：崩溃残留（started_at 早于本进程启动）照旧要标
	oldID := liveID
	if _, err := st2.db.Exec(
		`UPDATE connections SET started_at = ? WHERE id = ?`,
		time.Now().UnixMilli()-60_000, oldID); err != nil {
		t.Fatalf("改 started_at 失败: %v", err)
	}
	n2, err := st2.MarkStaleConnections("程序未正常退出")
	if err != nil {
		t.Fatalf("标记失败: %v", err)
	}
	if n2 != 1 {
		t.Fatalf("崩溃残留（早于进程启动）应当被标 1 条，实际 %d 条", n2)
	}
}

// ---------- 低4：hostkey 秒 → 毫秒的幂等迁移 ----------

// 老库里的秒级 first_seen/last_seen 必须在 migrate 里被乘 1000；
// 已经是毫秒的值不能被重复乘；幂等（再打开一次不再变）。
func TestHostKeyLegacySecondsAreMigrated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostkey.db")

	// 建库 → 清成"迁移前"的状态：一条老秒值、一条已经是毫秒的正常值
	st0, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	const secs = int64(1791544791)
	// SaveHostKey 会自己盖 last_seen=now，所以用 SQL 直插成"老库原样"
	if _, err := st0.db.Exec(`INSERT INTO known_hosts(host,port,key_type,fingerprint,first_seen,last_seen)
		VALUES('old.example',22,'ssh-ed25519','fp-old',?,?)`,
		secs, secs); err != nil {
		t.Fatalf("造老数据失败: %v", err)
	}
	_ = st0.Close()

	// 再打开一次：migrate 应当把秒值换算掉
	st, err := Open(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer st.Close()

	old, err := st.GetHostKey("old.example", 22)
	if err != nil {
		t.Fatalf("读老记录失败: %v", err)
	}
	if old == nil {
		t.Fatal("老记录不见了")
	}
	if old.FirstSeen != secs*1000 || old.LastSeen != secs*1000 {
		t.Errorf("秒级时间戳没被迁移：first_seen=%d last_seen=%d（期望 %d）",
			old.FirstSeen, old.LastSeen, secs*1000)
	}
	// 按毫秒解释要落在 2026 年，而不是 1970-01-21
	if got := time.UnixMilli(old.FirstSeen).Year(); got != 2026 {
		t.Errorf("迁移后按毫秒解释落在 %d 年（说明还是秒值）", got)
	}

	// 已经是毫秒的值不能被重复乘（SaveHostKey 走正常写路径，再验一次不受影响）
	if err := st.SaveHostKey(HostKey{
		Host: "new.example", Port: 22, KeyType: "ssh-ed25519", Fingerprint: "fp-new",
	}); err != nil {
		t.Fatalf("写新记录失败: %v", err)
	}
	newRec, err := st.GetHostKey("new.example", 22)
	if err != nil {
		t.Fatalf("读新记录失败: %v", err)
	}
	if newRec == nil || newRec.FirstSeen < int64(1e12) {
		t.Errorf("新写入的不是毫秒：%+v", newRec)
	}

	// 幂等：关掉再开一次，值不变
	_ = st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("第三次打开失败: %v", err)
	}
	defer st2.Close()
	again, err := st2.GetHostKey("old.example", 22)
	if err != nil {
		t.Fatalf("再读失败: %v", err)
	}
	if again.FirstSeen != secs*1000 {
		t.Errorf("迁移不幂等：第二次打开后又变成 %d", again.FirstSeen)
	}
}

// hostKeyTSMigration 必须真的**挂在 migrate 上**，而且它的失败要把 Open 挡下来
// （静默走掉的话，老库里的秒值永远修不好，用户看到的就是 1970-01-21）。
//
// 造法：把 known_hosts 换成一个只读视图（`WHERE 0` 没有行）。migrate 里那条
// 「UPDATE known_hosts ...」打在上面必然失败：
//   - 修复后：migrate 返回错误 → Open 失败，错误文本里带着"迁移主机密钥时间戳失败"；
//   - 去掉那行调用：第二句根本不发，Open 照样成功 → 这条必红。
//
// 视图列顺序与 SELECT * 一致，不会因为列错位误触发别的错。
func TestHostKeyMigrationIsWiredIntoMigrate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hostkey-migrate.db")

	st0, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if _, err := st0.db.Exec(`ALTER TABLE known_hosts RENAME TO known_hosts_real`); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if _, err := st0.db.Exec(`CREATE VIEW known_hosts AS
		SELECT host, port, key_type, fingerprint, first_seen, last_seen
		FROM known_hosts_real WHERE 0`); err != nil {
		t.Fatalf("建视图失败: %v", err)
	}
	_ = st0.Close()

	_, err = Open(path)
	if err == nil {
		t.Fatal("hostKeyTSMigration 没有挂在 migrate 上（视图挡不住 UPDATE，Open 却成功了）")
	}
	if !strings.Contains(err.Error(), "主机密钥时间戳") {
		t.Errorf("Open 失败了，但不是迁移那条语句导致的：%v", err)
	}
}

// 迁移语句本身要能把秒值换算成毫秒、且不重复乘（两列各自判断）。
func TestHostKeyMigrationStatementConvertsSecondsIdempotently(t *testing.T) {
	st := newTestStore(t)
	const secs = int64(1791544791)
	const millis = int64(1791544791000)

	// 一条秒值 + 一条已经是毫秒的值（毫秒那条不能被再乘一次）
	if _, err := st.db.Exec(`INSERT INTO known_hosts(host,port,key_type,fingerprint,first_seen,last_seen)
		VALUES('secs.example',22,'k','fp-secs',?,?),
		      ('ms.example',22,'k','fp-ms',?,?)`, secs, secs, millis, millis); err != nil {
		t.Fatalf("造数据失败: %v", err)
	}
	for i := 0; i < 2; i++ { // 跑两遍验幂等
		if _, err := st.db.Exec(hostKeyTSMigration); err != nil {
			t.Fatalf("第 %d 次执行迁移失败: %v", i+1, err)
		}
	}

	secsRec, err := st.GetHostKey("secs.example", 22)
	if err != nil {
		t.Fatalf("读秒值记录失败: %v", err)
	}
	if secsRec.FirstSeen != millis || secsRec.LastSeen != millis {
		t.Errorf("秒值没被换算：%+v（期望 %d）", secsRec, millis)
	}
	msRec, err := st.GetHostKey("ms.example", 22)
	if err != nil {
		t.Fatalf("读毫秒记录失败: %v", err)
	}
	if msRec.FirstSeen != millis || msRec.LastSeen != millis {
		t.Errorf("已经是毫秒的值被重复乘了：%+v", msRec)
	}

	// 只迁一列的情形：first_seen 是秒、last_seen 已经是毫秒，不能把后者一起乘
	if _, err := st.db.Exec(`INSERT INTO known_hosts(host,port,key_type,fingerprint,first_seen,last_seen)
		VALUES('mixed.example',22,'k','fp-mixed',?,?)`, secs, millis); err != nil {
		t.Fatalf("造混合数据失败: %v", err)
	}
	if _, err := st.db.Exec(hostKeyTSMigration); err != nil {
		t.Fatalf("第三次执行迁移失败: %v", err)
	}
	mixed, err := st.GetHostKey("mixed.example", 22)
	if err != nil {
		t.Fatalf("读混合记录失败: %v", err)
	}
	if mixed.FirstSeen != millis {
		t.Errorf("first_seen（秒）没被换算：%d", mixed.FirstSeen)
	}
	if mixed.LastSeen != millis {
		t.Errorf("last_seen（本来已是毫秒）被改动了：%d", mixed.LastSeen)
	}
}
