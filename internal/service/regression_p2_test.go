package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/dbx"
	"github.com/guaidao2/awdshell/internal/infra/logscan"
)

// 本文件钉的是第二轮全代码审计里 service 侧那两条：
//
//	P2-1 整次日志扫描没有时间预算（实测 2000 行 × 7.2KB 的正常内容要 53 秒，
//	     界面只有一个核在转、HTTP 请求不返回）
//	P2-4 max_rows / 体积上限的夹取点各写各的字面量（5000 / 1000 / 100）
//
// 每条都写成"改回错误版本会红"的形式。

// P2-1：扫描必须有时间预算，到点就停、并把"不完整"如实标出来。
//
// 走的是**真实的 ScanLog**（只有"把日志取回来"这一环用 readLog 替身，
// 那一环要真 SSH）：所以这条盯的是接线本身，而不是某个工具函数。
//
// 改回错误版本会红：ScanLog 里若退回成 logscan.ScanWithKind（无 ScanLimits），
// scanBudgetForTest 给的极小预算不会生效 —— Truncated 为 false、StoppedAtLine
// 为 0，整批行会被扫完（生产上就是那次 53 秒的卡顿）。
func TestScanLogStopsAtTimeBudget(t *testing.T) {
	// 第一行放一条必定命中的载荷（WEB-SQLI），后面全是"内容正常但很长"的填充行：
	// 这样既能验证"到点就停"，也能验证"停下时已经拿到的结果不会被丢掉"。
	var b strings.Builder
	b.WriteString("10.0.0.1 - - \"GET /x?id=1' UNION SELECT 1,2,3-- HTTP/1.1\" 200 1\n")
	filler := strings.Repeat("abcdefghij", 40) // 400 字节/行
	for i := 0; i < 600; i++ {
		b.WriteString("10.0.0.2 - - [10/Oct/2026:11:00:00 +0800] \"GET /ok/" + filler + " HTTP/1.1\" 200 2048\n")
	}
	text := b.String()

	svc := NewLogScanService(nil, nil, nil)
	svc.readLog = func(string, time.Duration) (string, error) { return text, nil }
	svc.scanBudgetForTest = 5 * time.Millisecond

	res, err := svc.ScanLog(context.Background(), "t1", "/var/log/nginx/access.log", 2000, logscan.KindWeb)
	if err != nil {
		t.Fatalf("扫描不该报错: %v", err)
	}
	if !res.Truncated {
		t.Fatalf("5ms 预算下 %d 行必须被判定为不完整（Truncated），实际完整 —— 说明预算没生效",
			strings.Count(text, "\n"))
	}
	if res.StoppedAtLine <= 0 {
		t.Error("停下时必须记下停在哪一行（StoppedAtLine），否则前端没法说清扫到哪儿了")
	}
	if !strings.Contains(res.TruncatedReason, "预算") {
		t.Errorf("原因要说明是时间预算耗尽，实际 %q", res.TruncatedReason)
	}
	if res.Scanned <= 0 {
		t.Error("预算耗尽前已经扫过的行不该白扫（Scanned 不能是 0）")
	}
	// **不丢结果**：截断不等于清空，停之前认出来的命中必须照常返回
	if len(res.Hits) == 0 {
		t.Error("截断时已命中的结果必须照常返回（Truncated 只是标记不完整，不是丢弃）")
	}

	// 反向：预算充足时不该标记不完整（别把 Truncated 写成常量 true）
	svc.scanBudgetForTest = time.Minute
	svc.readLog = func(string, time.Duration) (string, error) {
		return "10.0.0.1 ok\n10.0.0.2 ok\n", nil
	}
	full, err := svc.ScanLog(context.Background(), "t1", "/var/log/nginx/access.log", 2000, logscan.KindWeb)
	if err != nil {
		t.Fatalf("扫描不该报错: %v", err)
	}
	if full.Truncated {
		t.Errorf("预算充足时不该标记不完整，实际 reason=%q", full.TruncatedReason)
	}
}

// P2-1（另一半）：请求被取消时要提前收手，而不是把整批日志跑完。
//
// 改回错误版本会红：不带 Ctx 的 ScanWithKind 完全不看 ctx，
// 取消之后照样扫完全部行（Truncated=false）。
func TestScanLogHonoursCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 进函数之前就已经取消（等价于用户关掉页面）

	var b strings.Builder
	for i := 0; i < 300; i++ {
		b.WriteString("10.0.0.9 - - \"GET /x HTTP/1.1\" 200 1\n")
	}

	svc := NewLogScanService(nil, nil, nil)
	svc.readLog = func(string, time.Duration) (string, error) { return b.String(), nil }
	// 不设 scanBudgetForTest：用默认的 20 秒预算，保证截断只可能来自取消
	res, err := svc.ScanLog(ctx, "t1", "/var/log/nginx/access.log", 2000, logscan.KindWeb)
	if err != nil {
		t.Fatalf("扫描不该报错: %v", err)
	}
	if !res.Truncated {
		t.Fatal("context 已取消时必须提前收手并标记不完整")
	}
	if !strings.Contains(res.TruncatedReason, "取消") {
		t.Errorf("取消与超时要分开说（处理动作不同），实际 %q", res.TruncatedReason)
	}
	if res.StoppedAtLine <= 0 {
		t.Error("取消时同样要记下停在哪一行")
	}
}

// P2-1（第三半）：生产路径给的是 20 秒预算。
//
// 这个数字是本次修复的产品取舍（实测不带预算要 53 秒），把它钉住，
// 免得以后有人顺手改成 0（= 不限，等于把这次修复撤掉）或几十毫秒（正常日志都扫不完）。
func TestScanBudgetIsTwentySeconds(t *testing.T) {
	if scanBudget != 20*time.Second {
		t.Errorf("扫描时间预算应为 20s，实际 %v（0 表示不限，等于撤销这次修复）", scanBudget)
	}
	if scanMaxHits != logscan.DefaultMaxHits {
		t.Errorf("命中上限应跟引擎侧的默认值一致，实际 %d / %d", scanMaxHits, logscan.DefaultMaxHits)
	}
	if logscan.DefaultMaxHits != 5000 {
		t.Errorf("引擎侧默认命中上限变了（%d），service 的取舍要跟着复核", logscan.DefaultMaxHits)
	}
	// 没设测试覆盖时用的就是生产预算（否则上面两条只是摆设）
	svc := NewLogScanService(nil, nil, nil)
	if got := svc.budget(); got != scanBudget {
		t.Errorf("默认预算应为 %v，实际 %v", scanBudget, got)
	}
	svc.scanBudgetForTest = time.Millisecond
	if got := svc.budget(); got != time.Millisecond {
		t.Errorf("测试覆盖没生效，实际 %v", got)
	}
}

// P2-4：行数上限只有一套常量，三个夹取点引用同一组值。
//
// 改回错误版本会红：把夹取写回字面量（`if n > 5000 { n = 500 }`）时，
// clampQueryRows / clampMaxRowsToConn / ClampRequestedRows 就没有调用者，
// 下面的行为断言（尤其"0 不能变成不限"与"不能放大配置上限"）会先编译不过、
// 或者落到与常量不一致的结果上。
func TestRowLimitsUseOneSetOfConstants(t *testing.T) {
	// 数值本身就是口径（前端 max_rows 输入框的 max=5000 与它对齐）
	if MaxQueryRows != 5000 || DefaultQueryRows != 500 {
		t.Errorf("查询行数上限应为 5000/500，实际 %d/%d", MaxQueryRows, DefaultQueryRows)
	}
	if MaxPageRows != 1000 || DefaultPageRows != 100 {
		t.Errorf("分页行数上限应为 1000/100，实际 %d/%d", MaxPageRows, DefaultPageRows)
	}

	// 保存连接时的夹取：<=0 或超上限一律落回默认值
	for _, c := range []struct{ in, want int }{
		{0, DefaultQueryRows}, {-1, DefaultQueryRows}, {1, 1},
		{DefaultQueryRows, DefaultQueryRows}, {MaxQueryRows, MaxQueryRows},
		{MaxQueryRows + 1, DefaultQueryRows}, {999999, DefaultQueryRows},
	} {
		if got := clampQueryRows(c.in); got != c.want {
			t.Errorf("clampQueryRows(%d) = %d，期望 %d", c.in, got, c.want)
		}
	}

	// 执行查询时的夹取：客户端只能收小，不能放大连接配置里的上限
	for _, c := range []struct {
		requested, limit, want int
	}{
		{0, 3000, 3000},   // 没传 → 用配置上限
		{-5, 3000, 3000},  // 负数同"没传"
		{100, 3000, 100},  // 比上限小 → 按请求的来
		{99999, 500, 500}, // 比上限大 → 落到配置上限（不能放大）
		{MaxQueryRows + 1, MaxQueryRows, MaxQueryRows}, // 略超硬上限 → 收到硬上限
		{0, 99999, DefaultQueryRows},                   // 配置上限本身坏了（超范围）→ 统一落回默认值
		{0, 0, DefaultQueryRows},                       // 配置上限是 0（驱动会当"不限"）→ 兜底默认值
		{6000, 99999, DefaultQueryRows},                // 请求值与配置上限都超范围 → 收到默认值
	} {
		if got := clampMaxRowsToConn(c.requested, c.limit); got != c.want {
			t.Errorf("clampMaxRowsToConn(%d, %d) = %d，期望 %d", c.requested, c.limit, got, c.want)
		}
	}

	// HTTP 入参的夹取：0/负数表示"按连接配置来"（不能悄悄改成默认 500，
	// 那会把用户在连接里配的 2000 行上限压回 500）
	for _, c := range []struct{ in, want int }{
		{0, 0}, {-1, 0}, {100, 100}, {MaxQueryRows, MaxQueryRows},
		{MaxQueryRows + 1, MaxQueryRows}, {1 << 30, MaxQueryRows},
	} {
		if got := ClampRequestedRows(c.in); got != c.want {
			t.Errorf("ClampRequestedRows(%d) = %d，期望 %d", c.in, got, c.want)
		}
	}
}

// P2-4（真实路径）：保存连接时 max_rows 真的被夹到统一的那套上限上。
//
// 改回错误版本会红：这条走的是 SaveConn 的完整路径（落库 + 读回），
// 夹取被换成别的数（比如 1000）时会立刻对不上；
// 而"超范围落回默认值"若被改成"超范围就原样存"，
// 前端能填 5000 却在执行时被引擎按 500 处理，用户看到的数字与结果对不上。
func TestSaveConnClampsMaxRows(t *testing.T) {
	base := mkTempDir(t, ".test-db-maxrows-")
	st := openStore(t, base)
	// targets 只用来查目标名（不存在的 id 会返回错误，代码忽略它）；
	// vault 为 nil 也够用 —— 这条用例不传密码，不会走加解密。
	targets := NewTargetService(st, nil)
	ds := NewDatabaseService(targets, nil, st, nil)

	cases := []struct{ in, want int }{
		{0, DefaultQueryRows},
		{-7, DefaultQueryRows},
		{10, 10},
		{3000, 3000},
		{MaxQueryRows, MaxQueryRows},
		{MaxQueryRows + 1, DefaultQueryRows},
		{1 << 20, DefaultQueryRows},
	}
	for i, c := range cases {
		saved, err := ds.SaveConn(DBConnInput{
			TargetID: "no-such-target",
			Name:     fmt.Sprintf("conn-%d", i),
			Kind:     dbx.KindMySQL,
			MaxRows:  c.in,
		})
		if err != nil {
			t.Fatalf("保存连接失败（max_rows=%d）: %v", c.in, err)
		}
		if saved.MaxRows != c.want {
			t.Errorf("max_rows=%d 保存后应为 %d，实际 %d", c.in, c.want, saved.MaxRows)
		}
		// 读回来必须还是同一个数：store 层另有一道默认值夹取，
		// 两处口径不一致时这里会红（用户重开编辑框看到的数就变了）
		got, err := st.GetDBConn(saved.ID)
		if err != nil {
			t.Fatalf("读回连接失败: %v", err)
		}
		if got.MaxRows != c.want {
			t.Errorf("max_rows=%d 落库后读回应为 %d，实际 %d", c.in, c.want, got.MaxRows)
		}
	}
}
