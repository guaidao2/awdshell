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
)

// 启动期 panic 的收尾（旧账·低9/低15）。
//
// 改回错误版本会红：以前 recover 之后 main 正常返回，退出码是 0 ——
// 双击或脚本拿到的都是"成功"，出没出错完全看不出来。
func TestStartupPanicReturnsFailureCode(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-startup-panic-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// 桌面形态会弹原生框（阻塞），测试里先切成 -web 形态：只写日志。
	// 顺便把日志丢进黑洞，免得测试输出里混进一份 panic 堆栈。
	webModeFlag.Store(true)
	oldOut := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() {
		webModeFlag.Store(false)
		log.SetOutput(oldOut)
	})

	if code := handleStartupPanic(dir, "boom", []byte("goroutine 1 [running]:")); code != 1 {
		t.Errorf("启动期 panic 的退出码必须是非 0（1），得到 %d", code)
	}

	b, err := os.ReadFile(filepath.Join(dir, "startup-error.log"))
	if err != nil {
		t.Fatalf("panic 的原因应落到 startup-error.log：%v", err)
	}
	if !strings.Contains(string(b), "boom") {
		t.Errorf("日志里应有原始 panic 内容，得到 %q", string(b))
	}
}

// probeConsoleSrc 是探针用的 console_windows.go 替身：
// 不碰 MessageBoxW（真弹框会阻塞测试，也会弹到别人的屏幕上），
// 只把"走了弹框这条路"打到 stderr 上，让测试看得见。
const probeConsoleSrc = `//go:build windows

package main

import (
	"fmt"
	"os"
)

func showErrorBox(title, text string) { fmt.Fprintf(os.Stderr, "BOX-ERROR: %s: %s\n", title, text) }
func showNotice(title, text string)   { fmt.Fprintf(os.Stderr, "BOX-NOTICE: %s: %s\n", title, text) }
func attachParentConsole()            {}
func restoreConsoleCP()               {}
`

// 端到端：启动期 panic 必须让进程以非 0 退出，而且 -web 形态**不弹框**。
//
// 做法：用 go 的 -overlay 把 main.go 的一份临时副本换进构建（仓库文件不动），
// 副本里在启动路径上注入一条 panic；同时把 console_windows.go 换成"弹框只打
// stderr 标记"的版本 —— 于是这条测试既不起 GUI，又能看见到底有没有走弹框那条路。
//
// 改回错误版本会红：
//   - 去掉 os.Exit(1)（让 main 正常返回）→ 退出码 0；
//   - 让 -web 形态也弹框 → stderr 里出现 BOX-ERROR 标记。
func TestStartupPanicProbeExitsNonZeroWithoutBox(t *testing.T) {
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
	base, err := os.MkdirTemp(".", ".test-startup-probe-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	// 用绝对路径：探针要换工作目录运行，相对的可执行文件路径会被拼到新目录下
	if base, err = filepath.Abs(base); err != nil {
		t.Fatalf("取绝对路径失败: %v", err)
	}

	// 1) main.go 副本：在 defer recover 注册之后注入一条 panic
	src, err := os.ReadFile(filepath.Join(root, "main.go"))
	if err != nil {
		t.Fatalf("读 main.go 失败: %v", err)
	}
	const anchor = "if err := os.MkdirAll(*dataDir, 0o700); err != nil {"
	if !strings.Contains(string(src), anchor) {
		t.Fatalf("main.go 里找不到注入点 %q —— 探针要跟着改", anchor)
	}
	patched := strings.Replace(string(src), anchor,
		"panic(\"probe: 启动期 panic\") // 探针注入：必须在 defer recover 注册之后\n\t"+anchor, 1)
	mainCopy := filepath.Join(base, "main.go")
	if err := os.WriteFile(mainCopy, []byte(patched), 0o600); err != nil {
		t.Fatalf("写 main.go 副本失败: %v", err)
	}

	// 2) console_windows.go 副本：弹框改成 stderr 标记
	consoleCopy := filepath.Join(base, "console_windows.go")
	if err := os.WriteFile(consoleCopy, []byte(probeConsoleSrc), 0o600); err != nil {
		t.Fatalf("写 console_windows.go 副本失败: %v", err)
	}

	overlayPath := filepath.Join(base, "overlay.json")
	doc := map[string]map[string]string{"Replace": {
		filepath.Join(root, "main.go"):            mainCopy,
		filepath.Join(root, "console_windows.go"): consoleCopy,
	}}
	ob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("组装 overlay 失败: %v", err)
	}
	if err := os.WriteFile(overlayPath, ob, 0o600); err != nil {
		t.Fatalf("写 overlay 失败: %v", err)
	}

	// 3) 构建探针
	exe := filepath.Join(base, "probe.exe")
	build := exec.Command(goBin, "build", "-overlay", overlayPath, "-o", exe, ".")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建探针失败: %v\n%s", err, out)
	}

	// 4) 跑 -web：不弹框就该很快退出（弹框会一直阻塞，所以这里同时是一条超时断言）
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
		t.Fatalf("-web 形态下 panic 之后 60 秒还没退出（弹框会阻塞？）: %s", out.String())
	}

	if code := run.ProcessState.ExitCode(); code != 1 {
		t.Errorf("启动期 panic 的退出码应为 1，得到 %d（0 就是「出错了却报成功」）: %s", code, out.String())
	}
	if strings.Contains(out.String(), "BOX-ERROR") {
		t.Errorf("-web 形态不该走弹框那条路: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "startup-error.log")); err != nil {
		t.Errorf("启动失败的原因应落到 startup-error.log: %v", err)
	}
}
