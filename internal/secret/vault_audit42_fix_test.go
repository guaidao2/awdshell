package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 这组测试固化第二轮审计（audit42）里 secret 包的两条修复，断言都写成
// "改回错误版本会红"。

// ---------- M5：key.bin 丢失时不能静默生成新密钥 ----------

// 数据目录里已经有程序自己的东西（awdshell.db）却没有 key.bin，说明这不是首次运行
// 而是**密钥丢了**。以前这里会静默生成一把新密钥：程序照常启动、界面一切正常，
// 用户点连接才发现所有已存凭据都解不开（AEAD 拦得住，但没有任何一句话说明原因）。
//
//   - 修复后：返回明确错误并点名 key.bin 路径；不写盘、不生成新密钥；
//   - 改回"不存在就生成"：New 成功、目录里多出一个 key.bin → 必红。
func TestNewRefusesWhenKeyLost(t *testing.T) {
	dir := tempDir(t)
	// 程序自己的库文件在，key.bin 不在
	if err := os.WriteFile(filepath.Join(dir, "awdshell.db"), []byte("db"), 0o600); err != nil {
		t.Fatalf("造库文件失败: %v", err)
	}

	_, err := New(dir)
	if err == nil {
		t.Fatal("key.bin 丢失时不能静默生成新密钥（已有密文会全部变成废纸）")
	}
	msg := err.Error()
	if !bytes.Contains([]byte(msg), []byte("key.bin")) {
		t.Errorf("错误里必须点名 key.bin 路径，实际: %v", err)
	}
	// 路径在不同平台可能是相对的（tempDir 用的是 "./.test-vault-*"），
	// 所以按目录名判断，而不是整串比较。
	if !bytes.Contains([]byte(msg), []byte(filepath.Base(dir))) {
		t.Errorf("错误里必须给出数据目录，实际: %v", err)
	}
	// 不能偷偷写一把新密钥出来
	if _, statErr := os.Stat(filepath.Join(dir, "key.bin")); statErr == nil {
		t.Fatal("拒绝之后仍然生成了新 key.bin")
	}
}

// 上次写密钥留下的临时文件残留也算"用过这个目录"。
func TestNewRefusesWhenKeyTempLeftover(t *testing.T) {
	dir := tempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "key.bin.tmp"), []byte("x"), 0o600); err != nil {
		t.Fatalf("造残留失败: %v", err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("目录里有写密钥的残留时也不能当成首次运行")
	}
}

// 真正的首次运行（空目录）必须照常工作 —— 修复不能把正常路径挡掉。
func TestNewStillWorksOnFreshDir(t *testing.T) {
	dir := tempDir(t)
	v, err := New(dir)
	if err != nil {
		t.Fatalf("空目录是首次运行，必须成功: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.bin")); err != nil {
		t.Fatalf("首次运行没有生成 key.bin: %v", err)
	}
	// 旧密文仍然能解开（同一把密钥）
	nonce, ct, err := v.Seal("r", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	got, err := v.Open("r", nonce, ct)
	if err != nil || string(got) != "secret" {
		t.Fatalf("往返失败: %q %v", got, err)
	}
}

// 数据目录里只有用户的无关文件时不该被误判成"密钥丢了"（那会让程序起不来）。
//
// 这条以前**名不副实**：它只造了一个子目录，而实现里"任意普通文件都算用过这个
// 目录"—— 把那条判据（`default: return true`）去掉，测试仍然全绿（复审 P1-1 实测）。
// 现在真的造无关的普通文件，把判据改回"目录非空就算用过"就必红。
//
// 判据只认**程序自己的文件名**：awdshell.db 及其派生名、key.bin.tmp* 残留。
func TestNewDoesNotMisjudgeForeignFiles(t *testing.T) {
	dir := tempDir(t)
	// 子目录不算（例如用户自己在数据目录下建了备份目录）
	if err := os.MkdirAll(filepath.Join(dir, "backup"), 0o700); err != nil {
		t.Fatalf("建子目录失败: %v", err)
	}
	// 无关的普通文件同样不算：数据目录是 -data 指定的，用户把它指到一个
	// "已经放过东西"的目录是合法用法（手工建的、从别处拷来的目录）
	for _, name := range []string{
		"note.txt", "readme.md", "old-backup.zip",
		// **程序自己的日志也不算**（最容易搞错的一个）：main.go 的桌面形态是
		// "先开 awdshell.log → 再 secret.New → 最后 OpenDetail"，把日志算成
		// "用过这个目录"的话，全新安装会走到"key.bin 丢了"分支 → 100% 起不来
		// （正是 459461c 修掉的那类 P0）。fatalStartup 落的 startup-error.log
		// 同理：它只说明上次启动失败过，不说明这里有凭据数据。
		"awdshell.log", "startup-error.log",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("造 %s 失败: %v", name, err)
		}
	}

	v, err := New(dir)
	if err != nil {
		t.Fatalf("只有无关文件（含程序日志）时应当当首次运行: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "key.bin")); err != nil {
		t.Fatalf("首次运行没有生成 key.bin: %v", err)
	}
	// 建出来的密钥要真的能用（不能是个坏文件）
	nonce, ct, err := v.Seal("r", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	if got, err := v.Open("r", nonce, ct); err != nil || string(got) != "secret" {
		t.Fatalf("往返失败: %q %v", got, err)
	}
}

// 反向：程序**自己的**主库名（含 -wal/-shm 与 .corrupt-* 留档派生名）就是
// "这个目录里曾经有过数据"的证据 —— 有它却没有 key.bin 时必须如实报错，
// 不能安静地生成一把新密钥（那会让留档里的密文永远解不开）。
func TestNewRefusesOnProgramOwnDatabaseNames(t *testing.T) {
	for _, name := range []string{
		"awdshell.db",
		"awdshell.db-wal",
		"awdshell.db-shm",
		"awdshell.db.corrupt-20260101-000000.000000000",
	} {
		dir := tempDir(t)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("造 %s 失败: %v", name, err)
		}
		if _, err := New(dir); err == nil {
			t.Errorf("目录里有 %s 却没有 key.bin 时必须报错（这不是首次运行）", name)
		}
	}
}

// ---------- 抢占窗口：读别人"还没写满"的 key.bin 不能硬失败 ----------

// 首启并发用 O_CREATE|O_EXCL 抢真文件：赢家从"建出文件"到"写满 32 字节"之间有一个
// 窗口，抢输的一方老实现是**立刻 ReadFile 就判长度** —— 实测 0 字节报
// 「密钥长度非法: 0」、写了一半（16 字节）报「密钥长度非法: 16」，两种都是
// fatalStartup 退出，与"抢输的读回复用赢家那把密钥"的设计承诺不符（复审 P1-3）。
//
// 造法：先放一个 0 字节 key.bin（等价于赢家刚建出来），40ms 后写入完整的 32 字节
// （等价于赢家写完）。New 必须短睡重读到那把密钥，而不是报长度非法。
//   - 修复后：New 成功，拿到的就是后来写进去的那把（用同一个文件再 New 一次能解开）；
//   - 去掉重读：直接「密钥长度非法: 0」→ 必红。
func TestNewWaitsForHalfWrittenKeyInRaceWindow(t *testing.T) {
	dir := tempDir(t)
	keyPath := filepath.Join(dir, "key.bin")
	// 赢家刚 O_EXCL 建出文件、还没写内容
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatalf("造空 key.bin 失败: %v", err)
	}

	winnerKey := make([]byte, 32)
	for i := range winnerKey {
		winnerKey[i] = byte(i + 1)
	}
	go func() {
		time.Sleep(40 * time.Millisecond)
		_ = os.WriteFile(keyPath, winnerKey, 0o600)
	}()

	v, err := New(dir)
	if err != nil {
		t.Fatalf("抢占窗口里读到半写的 key.bin 不能硬失败（应当短睡重读）: %v", err)
	}

	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读 key.bin 失败: %v", err)
	}
	if !bytes.Equal(got, winnerKey) {
		t.Fatalf("磁盘上的密钥不是赢家写的那把: %x", got)
	}

	// 拿到的必须是赢家那把：用它加密，再用"重新读文件"构造的 Vault 解密
	nonce, ct, err := v.Seal("r", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	v2, err := New(dir)
	if err != nil {
		t.Fatalf("再次 New 失败: %v", err)
	}
	plain, err := v2.Open("r", nonce, ct)
	if err != nil || string(plain) != "secret" {
		t.Fatalf("抢占窗口里拿到的不是赢家那把密钥（密文解不开）: %q %v", plain, err)
	}
}

// ---------- M6：首启并发不能有"一方失败"或"两边密钥不一致" ----------

// 150/150 次的实测现象：两个实例同时初始化同一个空目录时，至少一个报错
// （共用 key.bin.tmp，先 rename 的把 tmp 移走、后一个撞 ENOENT）；
// 更坏的交错是两边都"成功"但各自覆盖 key.bin，密钥不一致。
//
// 修复后（O_CREATE|O_EXCL 抢真文件、抢输的读回复用）：
//   - 所有 goroutine 都成功；
//   - 拿到的密钥必须**完全一致**（同一把）；
//   - 目录里不留 .tmp 残留。
func TestNewConcurrentFirstRunAllSucceedWithSameKey(t *testing.T) {
	dir := tempDir(t)

	const n = 64
	type result struct {
		nonce, ct []byte
		err       error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			v, err := New(dir)
			if err != nil {
				results[i].err = err
				return
			}
			nonce, ct, err := v.Seal("probe", []byte("same-plaintext"))
			results[i].nonce, results[i].ct, results[i].err = nonce, ct, err
		}(i)
	}
	close(start)
	wg.Wait()

	// 1) 一个都不能失败
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("第 %d 个并发 New/Seal 失败（首启并发必须都能起来）: %v", i, r.err)
		}
	}
	// 2) 全部用同一把密钥：任何一方加密的密文，另一方都能解开
	key, err := os.ReadFile(filepath.Join(dir, "key.bin"))
	if err != nil {
		t.Fatalf("读 key.bin 失败: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key.bin 长度 = %d，期望 32", len(key))
	}
	v, err := New(dir)
	if err != nil {
		t.Fatalf("再次 New 失败: %v", err)
	}
	for i, r := range results {
		if _, err := v.Open("probe", r.nonce, r.ct); err != nil {
			t.Fatalf("第 %d 个 goroutine 的密文解不开 —— 首启并发出现了多把密钥: %v", i, err)
		}
	}
	// 3) 不留 tmp 残留
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "key.bin" {
			t.Errorf("目录里出现了预期外的文件: %s", e.Name())
		}
	}
}
