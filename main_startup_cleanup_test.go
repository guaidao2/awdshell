package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/store"
)

// 本文件钉的是复审（第二轮修复之后的只读复审）剩下的两条，都在 main 的启动/退出路径上：
//
//	M5  fatalStartup 直接 os.Exit，跳过全部 defer —— 服务（从 goroutine 里）意外退出时
//	    库没关、连接池没关、会话没断
//	低L4 log.SetOutput 排在 `go apiSrv.Serve(ln)` 之后 —— 启动最初几条日志去向不定
//
// 每条都写成"改回错误版本会红"的形式。

// mainCodeLines 读 main.go 并只保留**代码行**（去掉整行注释、去掉行首空白）。
//
// 为什么必须去注释：这些判据用到的标识符在注释里也出现，不能让注释顶替真代码
// （main_hooks_test.go 的接线测试已经踩过这一点）。
func mainCodeLines(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读 main.go 失败: %v", err)
	}
	var out []string
	for _, l := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		out = append(out, trimmed)
	}
	return strings.Join(out, "\n")
}

// 低L4：桌面形态的日志重定向必须发生在**起服务之前**。
//
// 改回错误版本会红：旧代码里 `go apiSrv.Serve(ln)` 在 log.SetOutput(lf) 之前，
// 启动最初几条日志（规则库加载报告、残留连接标记、清理记录、服务自身的报错）
// 的去向取决于 goroutine 调度 —— 有时进文件、有时进虚空，用户事后翻日志
// 会发现开头是断的，排查最要紧的那几行恰好不在。
func TestDesktopLogRedirectPrecedesServing(t *testing.T) {
	body := mainCodeLines(t)

	// 取**最后一次**出现的位置：块被挪到后面（或复制成"前面一份死代码 +
	// 后面一份真的"）时，真正生效的那一份在最后，用 Index 会漏判。
	iLog := strings.LastIndex(body, "log.SetOutput(lf)")
	if iLog < 0 {
		t.Fatal("main.go 里找不到 log.SetOutput(lf) —— 桌面形态的日志不再落文件了？")
	}
	iServe := strings.Index(body, "apiSrv.Serve(ln)")
	if iServe < 0 {
		t.Fatal("main.go 里找不到 apiSrv.Serve(ln) —— 数据服务的启动方式变了，这条判据要跟着改")
	}
	if iLog > iServe {
		t.Errorf("log.SetOutput(lf)（偏移 %d）必须排在 apiSrv.Serve(ln)（偏移 %d）之前：\n"+
			"  排在后面的话，服务启动阶段的日志去向取决于 goroutine 调度（复审·低L4）", iLog, iServe)
	}
	// 反向：-web 形态**不能**把日志重定向到文件（用户就在终端里，要看得见）
	if !strings.Contains(body, "if !*webMode {") {
		t.Error("日志重定向必须仍然只在桌面形态生效（-web 形态的日志要打在终端上）")
	}
}

// M5：启动失败 / 服务意外退出时，资源收尾必须挂在收尾表上，而不是只靠 defer。
//
// 改回错误版本会红：把 registerCleanup 那几行换成"只有 defer"，
// fatalStartup 的 os.Exit 一跳过就没收尾了（e2e 由
// TestServerCrashClosesResourcesBeforeExit 端到端钉住库那一份）。
func TestStartupRegistersResourceCleanup(t *testing.T) {
	body := mainCodeLines(t)

	for _, want := range []string{
		// 库：Close 里要写 last_clean_exit（下次启动靠它区分"中断残留"）
		"registerCleanup(closeStore)",
		// 连接池与日志文件
		"registerCleanup(closePool)",
		"registerCleanup(closeLog)",
		// 会话 + 数据库隧道
		"registerCleanup(closeSessions)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("main.go 的启动路径里缺少 %q —— fatalStartup 的 os.Exit 会跳过 defer（复审 M5）：\n"+
				"  少了库：没有干净退出记录、-wal 不合并\n"+
				"  少了连接池/会话：SSH 连接与数据库隧道不会主动断开\n"+
				"  少了日志文件：日志尾部可能没落盘", want)
		}
	}

	// fatalStartup 必须先跑收尾再退出，且退出码仍是 1。
	iClean := strings.Index(body, "runCleanups()\nos.Exit(1)")
	if iClean < 0 {
		t.Error("fatalStartup 必须是「先 runCleanups() 再 os.Exit(1)」—— " +
			"只 os.Exit 就是复审 M5 那条（退出码 1 与收尾两件事都要）")
	}
	// 启动期 panic 的兜底同样是 os.Exit 路径，也要收尾
	if !strings.Contains(body, "runCleanups()\nreturn 1") {
		t.Error("handleStartupPanic 也直接由 os.Exit 结束，同样要先 runCleanups()")
	}
}

// 收尾表的语义：逆序执行（与 defer 一致）、只生效一次、单个动作 panic 不连累别人。
func TestRunCleanupsOrderAndIsolation(t *testing.T) {
	// 这条用例直接操作全局收尾表，跑完要还原（别的用例只读它）
	cleanupMu.Lock()
	saved := startupCleanups
	startupCleanups = nil
	cleanupMu.Unlock()
	t.Cleanup(func() {
		cleanupMu.Lock()
		startupCleanups = saved
		cleanupMu.Unlock()
	})
	oldOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(oldOut) })

	var order []string
	registerCleanup(func() { order = append(order, "first") })
	registerCleanup(func() { order = append(order, "second") })
	registerCleanup(func() { order = append(order, "third") })
	runCleanups()
	if got := strings.Join(order, ","); got != "third,second,first" {
		t.Errorf("收尾必须逆序执行（与 defer 一致），实际 %q", got)
	}
	// 再一次：表已经清空，不该重复执行（进程正要退出，重复关库会报错）
	runCleanups()
	if len(order) != 3 {
		t.Errorf("runCleanups 第二次调用不该再执行任何动作，实际 %v", order)
	}
	// nil 忽略（调用方可能是"没打开日志文件"的分支）
	registerCleanup(nil)
	runCleanups()

	// 一个动作 panic 不能把后面的挡住
	order = nil
	registerCleanup(func() { order = append(order, "ok1") })
	registerCleanup(func() { panic("探针：收尾动作自己炸了") })
	registerCleanup(func() { order = append(order, "ok2") })
	runCleanups()
	if got := strings.Join(order, ","); got != "ok2,ok1" {
		t.Errorf("单个收尾动作 panic 之后仍要把剩下的跑完，实际 %q", got)
	}
}

// onceFn 保证"正常返回的 defer"与"fatalStartup 的显式收尾"不会把同一个资源关两次。
func TestOnceFnRunsAtMostOnce(t *testing.T) {
	n := 0
	fn := onceFn(func() { n++ })
	fn()
	fn()
	fn()
	if n != 1 {
		t.Errorf("onceFn 包装的动作只该生效一次，实际执行了 %d 次", n)
	}
}

// M5（端到端）：服务意外退出时，库必须被**正确关闭**，退出码仍是 1，原因仍写给用户。
//
// 做法与 startup_test.go 的 panic 探针一致：用 go 的 -overlay 把 main.go 的一份
// 临时副本换进构建（仓库文件不动），副本里在 -web 分支上把监听器先关掉 ——
// 于是 `go httpSrv.Serve(ln)` 立刻失败，走的就是复审点名的那条路
// （**从 goroutine 里调 fatalStartup**，defer 一个都跑不到）。
//
// 判据用"库被干净关闭"在磁盘上的痕迹：SQLite 在**最后一个连接干净关闭**时会
// checkpoint 并删掉自己建的 awdshell.db-wal / awdshell.db-shm（实测：
// 关库后目录里只剩 awdshell.db；`os.Exit(1)` 不关库时两个文件都留着）。
//
// 为什么不用 settings 里的 last_clean_exit 当判据：文件级痕迹更硬、也更独立 ——
// 它连"库被绕过 Store 直接关掉"这种情况都能看出来，而 last_clean_exit 只能证明
// Store.Close() 自己跑通了。（本文件写的时候那条确实写不进去：store.Close() 是先
// s.db.Close() 再 writeLastCleanExit()，写的是已关掉的库、错误被 `_ =` 吞掉。
// store 侧后来已改成"先写标记再关句柄"，现在两条判据都成立，但这里仍用文件级痕迹。）
//
// 改回错误版本会红：fatalStartup 直接 os.Exit(1)，探针退出码仍然是 1、
// stderr 里仍然有"本地服务退出"，但 -wal/-shm 会留在数据目录里 —— 那条断言
// 专门盯这个差别。
func TestServerCrashClosesResourcesBeforeExit(t *testing.T) {
	if testing.Short() {
		t.Skip("要 go build 一个探针二进制，-short 下跳过")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("找不到 go 命令，跳过")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("取工作目录失败: %v", err)
	}
	base, err := os.MkdirTemp(".", ".test-fatal-cleanup-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if base, err = filepath.Abs(base); err != nil {
		t.Fatalf("取绝对路径失败: %v", err)
	}

	// 1) main.go 副本：在 -web 分支里把监听器先关掉，让 Serve 立刻失败
	src, err := os.ReadFile(filepath.Join(root, "main.go"))
	if err != nil {
		t.Fatalf("读 main.go 失败: %v", err)
	}
	const anchor = "\t\tdeps.Assets = assetsFS\n"
	if !strings.Contains(string(src), anchor) {
		t.Fatalf("main.go 里找不到注入点 %q —— 探针要跟着改", anchor)
	}
	patched := strings.Replace(string(src), anchor,
		anchor+"\t\t_ = ln.Close() // 探针注入：让下面的 Serve 立刻失败，走 fatalStartup\n", 1)
	mainCopy := filepath.Join(base, "main.go")
	if err := os.WriteFile(mainCopy, []byte(patched), 0o600); err != nil {
		t.Fatalf("写 main.go 副本失败: %v", err)
	}

	overlayPath := filepath.Join(base, "overlay.json")
	doc := map[string]map[string]string{"Replace": {filepath.Join(root, "main.go"): mainCopy}}
	ob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("组装 overlay 失败: %v", err)
	}
	if err := os.WriteFile(overlayPath, ob, 0o600); err != nil {
		t.Fatalf("写 overlay 失败: %v", err)
	}

	// 2) 构建探针
	exe := filepath.Join(base, "probe.exe")
	build := exec.Command(goBin, "build", "-overlay", overlayPath, "-o", exe, ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建探针失败: %v\n%s", err, out)
	}

	// 3) 跑 -web：服务一起就挂，进程该很快退出（不该卡在什么收尾上）
	dataDir := filepath.Join(base, "data")
	run := exec.Command(exe, "-web", "-open=false", "-data", dataDir)
	run.Dir = base
	var out bytes.Buffer
	run.Stdout = &out
	run.Stderr = &out
	if err := run.Start(); err != nil {
		t.Fatalf("启动探针失败: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- run.Wait() }()
	select {
	case <-waited:
	case <-time.After(60 * time.Second):
		_ = run.Process.Kill()
		t.Fatalf("服务意外退出后 60 秒还没结束（收尾卡住了？）: %s", out.String())
	}

	// 退出码仍是 1（收尾不能把"失败"变成"成功"）
	if code := run.ProcessState.ExitCode(); code != 1 {
		t.Errorf("服务意外退出的退出码应为 1，得到 %d：%s", code, out.String())
	}
	// 原因仍然写给用户（-web 形态走 stderr，不弹框）
	if !strings.Contains(out.String(), "本地服务退出") {
		t.Errorf("-web 形态下要把失败原因写到 stderr，实际输出：%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "startup-error.log")); err != nil {
		t.Errorf("启动失败的原因应落到 startup-error.log: %v", err)
	}

	// 库被正确关闭：SQLite 会 checkpoint 并删掉 -wal / -shm
	for _, name := range []string{"awdshell.db-wal", "awdshell.db-shm"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); err == nil {
			t.Errorf("库没有被干净关闭：%s 还留在数据目录里 —— "+
				"说明 fatalStartup 仍然是直接 os.Exit，跳过了 st.Close()（复审 M5）", name)
		}
	}
	// 库本身仍然可用（干净关闭不该把内容弄坏）：查询能跑通、表结构还在
	st, err := store.Open(filepath.Join(dataDir, "awdshell.db"))
	if err != nil {
		t.Fatalf("重新打开探针的库失败: %v", err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.ListTargets(); err != nil {
		t.Errorf("收尾之后库应当仍然可读（表结构完整）: %v", err)
	}
}
