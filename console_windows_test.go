//go:build windows

package main

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"unsafe"
)

// procGetHandleInformation 只在测试里用：查句柄有没有 HANDLE_FLAG_INHERIT。
// （syscall 包只导出了 SetHandleInformation，没有导出的查询函数。）
var procGetHandleInformation = syscall.NewLazyDLL("kernel32.dll").NewProc("GetHandleInformation")

// handleIsInheritable 报告句柄当前是否可被子进程继承。
func handleIsInheritable(t *testing.T, h syscall.Handle) bool {
	t.Helper()
	var flags uint32
	r, _, err := procGetHandleInformation.Call(uintptr(h), uintptr(unsafe.Pointer(&flags)))
	if r == 0 {
		t.Fatalf("查询句柄 %d 的继承标志失败: %v", h, err)
	}
	return flags&syscall.HANDLE_FLAG_INHERIT != 0
}

// 复审低L5：接管父控制台用的 CONOUT$ 句柄必须是**不可继承**的。
//
// 为什么不能靠 os.OpenFile 的默认行为：实测 Go 1.27 的 os.OpenFile 内部已经带了
// O_CLOEXEC（$GOROOT/src/os/file_windows.go 的 openFileNolog），所以"不写也算对"
// —— 但那个语义挂在标准库的实现细节上，换成 syscall.CreateFile 就直接丢掉，
// 所以本文件显式调用 makeNonInheritable 把它钉住。
//
// 这条用例先用 syscall.CreateFile + InheritHandle=1 造一个**真的可继承**的句柄
// （os.OpenFile 造不出来），确认前提成立，再看 makeNonInheritable 有没有把它清掉。
//
// 改回错误版本会红：makeNonInheritable 变成空操作（或直接删掉调用），
// 第二个断言就会报"句柄仍然可继承"。
func TestMakeNonInheritableClearsFlag(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-console-handle-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sa := &syscall.SecurityAttributes{
		Length:        uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		InheritHandle: 1,
	}
	p, err := syscall.UTF16PtrFromString(filepath.Join(dir, "h.txt"))
	if err != nil {
		t.Fatalf("拼路径失败: %v", err)
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, sa,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("创建可继承句柄失败: %v", err)
	}
	t.Cleanup(func() { _ = syscall.CloseHandle(h) })

	if !handleIsInheritable(t, h) {
		t.Fatal("前提不成立：InheritHandle=1 建出来的句柄本该可继承 —— 这条用例测不到东西了")
	}
	if err := makeNonInheritable(h); err != nil {
		t.Fatalf("makeNonInheritable 失败: %v", err)
	}
	if handleIsInheritable(t, h) {
		t.Error("makeNonInheritable 之后句柄不该再带 HANDLE_FLAG_INHERIT —— " +
			"否则子进程（main.go 里 rundll32 打开浏览器那条路）可能多拿到一个写控制台的句柄")
	}
	// 幂等：已经清过再清一次不该报错
	if err := makeNonInheritable(h); err != nil {
		t.Errorf("重复调用不该报错: %v", err)
	}
	// 无效句柄不该当成错误（attachParentConsole 里那个句柄可能拿不到）
	if err := makeNonInheritable(syscall.InvalidHandle); err != nil {
		t.Errorf("无效句柄应安静跳过，得到 %v", err)
	}
}

// 复审低L5：CONOUT$ 的句柄要**保存**下来，并且能关闭（可重复调用）。
//
// 它在整个进程生命周期里都要活着（os.Stdout / os.Stderr / log 都挂在它上面），
// 所以关闭只发生在收尾路径上 —— 收尾表里注册的就是 closeConsoleOut。
//
// 改回错误版本会红：旧代码把 *os.File 直接塞进 os.Stderr 就不管了，
// 既没有保存、也没有关闭的入口（closeConsoleOut 不存在，这条用例编译不过）。
func TestCloseConsoleOutClosesHandleOnce(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-console-close-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	f, err := os.OpenFile(filepath.Join(dir, "out.txt"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("打开临时文件失败: %v", err)
	}
	// 借用全局变量模拟"接管了控制台"，跑完还原
	consoleOutMu.Lock()
	old := consoleOut
	consoleOut = f
	consoleOutMu.Unlock()
	t.Cleanup(func() {
		consoleOutMu.Lock()
		consoleOut = old
		consoleOutMu.Unlock()
	})

	closeConsoleOut()
	if _, err := f.WriteString("x"); err == nil {
		t.Error("closeConsoleOut 之后句柄应当是关闭的（写应当失败）")
	}
	consoleOutMu.Lock()
	left := consoleOut
	consoleOutMu.Unlock()
	if left != nil {
		t.Error("closeConsoleOut 之后不该还留着句柄引用（重复调用会关第二次）")
	}
	// 幂等：没接管过、或者已经关过，都不该 panic
	closeConsoleOut()
	closeConsoleOut()
}

// 控制台代码页的两条边界（旧账·低12）。
//
// 改回错误版本会红：以前是"拿到当前值就记下来"，本来就是 65001 时也会记成
// 65001 —— 退出时"恢复"等于把 65001 又盖回去，而这个代码页是控制台的全局状态，
// 两个实例叠加（后启动的先退出）会让用户那个 cmd 窗口永久停在 UTF-8。
func TestConsoleCPDecision(t *testing.T) {
	if saved, set := consoleCPDecision(consoleCPUTF8); set || saved != 0 {
		t.Errorf("已经是 65001 时应不记不切，得到 saved=%d set=%v", saved, set)
	}
	if saved, set := consoleCPDecision(936); !set || saved != 936 {
		t.Errorf("936 应记下并切，得到 saved=%d set=%v", saved, set)
	}
	if saved, set := consoleCPDecision(0); !set || saved != 0 {
		t.Errorf("拿不到当前值（没有控制台）仍要尝试切，得到 saved=%d set=%v", saved, set)
	}
}

// savedConsoleCP 会被 main 与 HTTP goroutine 两边形读写（fatalStartup 会从
// handler 的 goroutine 走 restoreConsoleCP），-race 下这条必须干净。
//
// 改回错误版本会红：去掉 consoleCPMu 之后 `go test -race .` 会报数据竞争。
func TestConsoleCPAccessIsRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 200; k++ {
				setConsoleUTF8()
				restoreConsoleCP()
			}
		}()
	}
	wg.Wait()
	// 收尾：万一还有没还回去的原值，别把跑测试的那个控制台留在 UTF-8
	restoreConsoleCP()
}
