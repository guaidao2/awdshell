package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// 这一组守终审报告里的 M1：Close 被别人的写锁拖住。
//
// 背景：把"先关句柄再写"改成"先写再关句柄"（复审 P0-2/高2）之后，写这一步落到
// s.db 上，而它的 DSN 带着 busy_timeout=5000 —— 另一个连接持写锁时 Close 会跟着
// 等下去（终审实测阻塞 3.047s，加上 PutSetting 的 busyRetry 最坏约 10.2s）。
// 标记写不进去只是"下次启动多标几条残留"，绝不该让退出路径卡住。
//
// 这条与 TestClosePersistsLastCleanExit 是**成对**的：
//   - 那一条守"正常情况下必须真写进去"（防止为了不阻塞就退回"永远写不进去"）；
//   - 这一条守"抢不到锁时必须快速返回"（防止把它等成 5 秒）。
//
// 两条缺一条，另一种形态就会漏。

// closeFastLimit 是"关库路径必须多快返回"的上限。
//
// 终审给的要求是 < 1 秒。实现侧的等待上界是 closeWriteBusyTimeoutMS（200ms）
// 加一次连接建立的开销，所以 1 秒留了足够余量；而改回"走 s.db 上的 PutSetting"
// 会等 5s + 200ms 重试 —— 差一个数量级，这条断言分得开这两种实现。
const closeFastLimit = time.Second

// holdForeignWriteLock 用一条**独立连接**抢住这个库的写锁，返回释放函数。
//
// 用 BEGIN IMMEDIATE 而不是等某条语句自己撞上 BUSY：IMMEDIATE 在 BEGIN 那一刻
// 就取得写锁，所以"锁在我手里"这件事是确定的（而不是靠时序赌）。
func holdForeignWriteLock(t *testing.T, path string) func() {
	t.Helper()
	holder, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatalf("开持锁连接失败: %v", err)
	}
	holder.SetMaxOpenConns(1)
	conn, err := holder.Conn(t.Context())
	if err != nil {
		t.Fatalf("取持锁连接失败: %v", err)
	}
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("抢写锁失败（测试前提不成立）: %v", err)
	}
	return func() {
		_, _ = conn.ExecContext(t.Context(), "ROLLBACK")
		_ = conn.Close()
		_ = holder.Close()
	}
}

// rawSettingText 用裸连接读一个 settings 值（读不到时直接判失败，因为
// "读不到"与"还是旧值"在这条测试里必须分得开）。
func rawSettingText(t *testing.T, path, key string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("裸连接打开失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	var raw string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&raw); err != nil {
		t.Fatalf("读 settings.%s 失败: %v", key, err)
	}
	return raw
}

// TestCloseReturnsFastUnderForeignWriteLock 守 M1：别人持写锁时 Close 必须快速
// 返回、且不报错（标记写不进去只记一条日志）；锁释放之后另一次关闭照常写入。
//
// 改回错误版本会红：writeLastCleanExit 走 s.PutSetting（→ s.db，DSN 里
// busy_timeout=5000，再加 busyRetry 的 200ms 睡眠与重试）时，这里的耗时是
// 5s~10s，直接超过 closeFastLimit。
func TestCloseReturnsFastUnderForeignWriteLock(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	st, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	// 预置一个可辨认的旧值：Close 抢不到锁时它必须**原样留着**
	//（"写没写成"与"返回得快不快"是两件事，都要能看到证据）。
	if err := st.PutSetting(lastCleanExitKey, "1"); err != nil {
		t.Fatalf("预置旧值失败: %v", err)
	}

	release := holdForeignWriteLock(t, path)

	start := time.Now()
	closeErr := st.Close()
	elapsed := time.Since(start)

	// 先断言"锁真的被持着、标记没写进去"，再释放锁 —— 顺序反了的话，
	// "关闭很快"有可能只是因为它压根没去写。
	if got := rawSettingText(t, path, lastCleanExitKey); got != "1" {
		t.Errorf("别人持写锁时那次标记不该落库（说明锁没被真的持住，或写入绕过了锁）：%q", got)
	}
	release()

	if closeErr != nil {
		t.Errorf("别人持写锁时 Close 也不该报错（标记写不进去只该记日志）：%v", closeErr)
	}
	if elapsed > closeFastLimit {
		t.Errorf("别人持写锁时 Close 用了 %v（上限 %v）—— 关库路径被写锁拖住了，"+
			"用户点关闭后窗口要等这么久且没有任何反馈", elapsed, closeFastLimit)
	}
	t.Logf("持写锁期间 Close 耗时 %v", elapsed)

	// 锁释放之后：另一次干净关闭必须真的把时刻写进去（别为了不阻塞就退回
	// "永远写不进去"—— 那会让 MarkStaleConnections 的 cutoff 又变成死的）。
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("第二次打开失败: %v", err)
	}
	before := time.Now().UnixMilli()
	start = time.Now()
	if err := st2.Close(); err != nil {
		t.Fatalf("锁已释放，Close 不该失败: %v", err)
	}
	if d := time.Since(start); d > closeFastLimit {
		t.Errorf("没有别人持锁时 Close 也用了 %v（不该为这条写入付出等待）", d)
	}
	written := rawLastCleanExit(t, path) // 读不到 / 不是新毫秒值都会判失败
	if written < before-1000 || written > time.Now().UnixMilli()+1000 {
		t.Errorf("锁释放后的 Close 没写进这次的时刻：written=%d before=%d", written, before)
	}
}
