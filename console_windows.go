//go:build windows

package main

import (
	"log"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW    = user32.NewProc("MessageBoxW")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procAttachConsole  = kernel32.NewProc("AttachConsole")
	procGetStdHandle   = kernel32.NewProc("GetStdHandle")
	procGetConsoleCP   = kernel32.NewProc("GetConsoleOutputCP")
	procSetConsoleCP   = kernel32.NewProc("SetConsoleOutputCP")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
)

const (
	mbOK            = 0x00000000
	mbIconError     = 0x00000010
	mbIconInfo      = 0x00000040
	mbSetForeground = 0x00010000
	// AttachConsole(ATTACH_PARENT_PROCESS)：(DWORD)-1
	attachParentProcess = ^uintptr(0)
	// GetStdHandle 的常量：(DWORD)-10 / -11 / -12。
	// 别写错：曾经把 STD_ERROR_HANDLE 写成 ^uintptr(9)，那是 **stdin**，
	// 于是"已经有 stderr 就别抢"这道保护看的是 stdin，重定向照样被抢走。
	stdOutputHandle    = ^uintptr(10) // -11
	stdErrHandle       = ^uintptr(11) // -12
	invalidHandleValue = ^uintptr(0)  // INVALID_HANDLE_VALUE
	// 控制台输出代码页：UTF-8
	consoleCPUTF8 = 65001
)

// savedConsoleCP 是切换前的输出代码页，用于在退出路径上恢复（0 表示没切过）。
//
// 它会被两个 goroutine 摸到：main 的启动路径（setConsoleUTF8）与 HTTP goroutine
// 里的 fatalStartup（restoreConsoleCP），所以读写都要持 consoleCPMu ——
// 普通变量在 -race 下就是一条数据竞争报告。
var (
	consoleCPMu    sync.Mutex
	savedConsoleCP uintptr
)

// showErrorBox 弹一个原生错误框。
//
// 为什么需要：exe 是 GUI 子系统（PE Subsystem=2），双击运行时没有控制台，
// 启动阶段的 log.Fatalf 会写进虚空、程序一闪就没了，用户完全不知道发生了什么。
func showErrorBox(title, text string) {
	t, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	m, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	_, _, _ = procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(t)),
		uintptr(mbOK|mbIconError|mbSetForeground))
}

// showNotice 弹一个**信息**框（不是错误）。
//
// 用在"程序能继续跑，但用户必须知道发生了什么"的场合 ——
// 目前是数据库损坏后自动留档重建：不告诉他的话，他看到的是"数据凭空没了"，
// 而实际上旧文件还好好地躺在数据目录里。
func showNotice(title, text string) {
	t, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return
	}
	m, err := syscall.UTF16PtrFromString(text)
	if err != nil {
		return
	}
	_, _, _ = procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(m)),
		uintptr(unsafe.Pointer(t)),
		uintptr(mbOK|mbIconInfo|mbSetForeground))
}

func handleValid(h uintptr) bool {
	return h != 0 && h != invalidHandleValue
}

// isConsoleHandle 判断句柄指向的是控制台，而不是文件或管道。
// GetConsoleMode 只对控制台句柄成功。
func isConsoleHandle(h uintptr) bool {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

// consoleCPDecision 决定"要不要切代码页"，返回 (要记下的原值, 要不要切)。
//
// 抽出来是为了能被测试钉住，两条边界都踩过：
//   - 当前已经是 65001：**不记也不切**。记成 65001 的话退出时"恢复"等于
//     把 65001 又盖回去，而这个代码页是控制台的全局状态 —— 两个实例叠加
//     （后启动的先退出）会让用户那个 cmd 窗口永久停在 UTF-8；
//   - 拿不到当前值（0，没有控制台）：仍然"切"（SetConsoleOutputCP 会静默失败），
//     但没什么可恢复的，原值记 0。
func consoleCPDecision(cp uintptr) (saved uintptr, set bool) {
	if cp == consoleCPUTF8 {
		return 0, false
	}
	return cp, true
}

// setConsoleUTF8 记下当前输出代码页并切成 UTF-8。
//
// 为什么必须切：Go 的字符串是 UTF-8 字节，而中文 Windows 的 cmd 默认是 936(GBK)，
// 不切就是一片乱码（"鈥斺€?" 这种）。
func setConsoleUTF8() {
	consoleCPMu.Lock()
	defer consoleCPMu.Unlock()
	if savedConsoleCP != 0 {
		return // 已经切过：别把 65001 再记成"原值"
	}
	cp, _, _ := procGetConsoleCP.Call()
	saved, set := consoleCPDecision(cp)
	if !set {
		return
	}
	savedConsoleCP = saved
	_, _, _ = procSetConsoleCP.Call(consoleCPUTF8)
}

// attachParentConsole 让命令行下能看到输出。
//
// GUI 子系统的程序启动时不一定会拿到可用的标准输出，所以从 cmd 敲
// `awdshell.exe -h`、或启动失败时，可能什么都看不到。双击运行时没有父控制台，
// CONOUT$ 打不开，原样返回即可。
//
// 两条容易搞错的地方：
//   - stderr 已经被调用方接管（`> out.txt`、管道、`2>file`）时**不能**替换句柄，
//     否则输出会从用户指定的文件跑到控制台，文件里什么都没有。但句柄指向控制台时
//     仍要处理代码页。所以按流分别判断，不要一把全换。
//   - AttachConsole 返回 0 不等于"没有控制台"：从控制台子系统进程里调用、
//     或已经附加过时，它回 ERROR_ACCESS_DENIED，而 CONOUT$ 照样能打开。
//     所以以"能不能打开 CONOUT$"为准。
//
// 另外 log 包的输出在 init 时就绑定了 os.Stderr，改完变量必须显式 SetOutput，
// 否则日志仍然写到旧句柄。flag 包的 Output() 是每次动态读 os.Stderr 的，不用管。
func attachParentConsole() {
	errH, _, _ := procGetStdHandle.Call(stdErrHandle)
	if handleValid(errH) {
		// stderr 已经有有效句柄（重定向到文件、管道），不能替换它。
		//
		// 但**代码页仍要处理**：`awdshell.exe -web 2>log.txt` 时 stderr 是文件、
		// 而 stdout 还是控制台，中文横幅要正常显示就得切 UTF-8。
		// （这里不探 CONOUT$：未附加控制台时它打不开、SetConsoleOutputCP 会静默
		// 失败，那种分支看着有用其实什么都不做。）
		if isConsoleHandle(errH) {
			setConsoleUTF8()
			return
		}
		if outH, _, _ := procGetStdHandle.Call(stdOutputHandle); handleValid(outH) && isConsoleHandle(outH) {
			setConsoleUTF8()
		}
		return
	}

	_, _, _ = procAttachConsole.Call(attachParentProcess)

	out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return // 真的没有控制台（双击启动）
	}
	setConsoleUTF8()

	// 按流分别替换：stdout 可能也被重定向了，那种情况要保留它
	if h, _, _ := procGetStdHandle.Call(stdOutputHandle); !handleValid(h) {
		os.Stdout = out
	}
	os.Stderr = out
	log.SetOutput(out)
}

// restoreConsoleCP 把控制台输出代码页恢复成切换前的值。
//
// 不恢复的话，用户那个 cmd 窗口会一直停在 UTF-8 ——
// 后续在同窗口里跑老的 GBK 程序就会乱码。
func restoreConsoleCP() {
	consoleCPMu.Lock()
	defer consoleCPMu.Unlock()
	if savedConsoleCP != 0 {
		_, _, _ = procSetConsoleCP.Call(savedConsoleCP)
		savedConsoleCP = 0
	}
}
