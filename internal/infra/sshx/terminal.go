package sshx

import (
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Terminal 是一条交互式 shell 通道。
type Terminal struct {
	session *ssh.Session
	stdin   io.WriteCloser
	output  io.Reader

	// release 是池里那条连接的"长连接引用"释放函数（可能为 nil）。
	// 有它之后，只要终端还开着，reaper 就不会把这条连接按空闲回收。
	release   func()
	closeOnce sync.Once
}

// StartTerminalHeld 在已有连接上开交互 shell，并在它的整个生命周期里
// 持有这条池连接的长引用。
//
// 为什么需要：reaper 只看 lastUsed，而终端 I/O 走 Terminal、完全不碰池。
// "只开终端"（或窗口最小化、或长时间不敲键）时 lastUsed 停在开终端那一刻，
// reaper 会在最后一次 Acquire 后 5~6 分钟把连接关掉 —— 用户正在敲的终端突然断。
// 实测把 idle 调成 3 秒后，第一个 tick（60 秒）终端即断开、池里连接被摘除。
func (p *Pool) StartTerminalHeld(client *ssh.Client, cols, rows int, termName string) (*Terminal, error) {
	release := p.Hold(client)
	t, err := StartTerminal(client, cols, rows, termName)
	if err != nil {
		release()
		return nil, err
	}
	t.release = release
	return t, nil
}

// ptyTerminalModes 是申请 PTY 时发给远端的 termios。
//
// **关键标志必须显式列出来，不能只给 ECHO。** ssh 的 pty-req 里 modes 的语义是
// "客户端要求的 termios 值"，服务端逐项应用；**没有列出的项落到什么值并不保证**
// （OpenSSH 是在 tty 当前值的基线上覆盖，但基线本身不一定是完整的 cooked 模式，
// 不同实现更不一致）。只给 ECHO 时的实测表现：
//
//	回车显示成 ^M 且不生效（ICRNL 没开，CR 不会被转成 NL）
//	Ctrl+C 显示成 ^C 且不中断（ISIG 没开，不产生 SIGINT）
//	apt / vim / top 这类交互程序的按键全部对不上
//
// 下面的值对照 OpenSSH 客户端发出的 mode 表，也就是普通 Linux 终端的默认值。
func ptyTerminalModes() ssh.TerminalModes {
	return ssh.TerminalModes{
		// 特殊字符（值就是它的字符码）
		ssh.VINTR:    3,   // Ctrl+C
		ssh.VQUIT:    28,  // Ctrl+\
		ssh.VERASE:   127, // Backspace
		ssh.VKILL:    21,  // Ctrl+U
		ssh.VEOF:     4,   // Ctrl+D
		ssh.VSTART:   17,  // Ctrl+Q
		ssh.VSTOP:    19,  // Ctrl+S
		ssh.VSUSP:    26,  // Ctrl+Z
		ssh.VREPRINT: 18,  // Ctrl+R
		ssh.VWERASE:  23,  // Ctrl+W
		ssh.VLNEXT:   22,  // Ctrl+V
		ssh.VDISCARD: 15,  // Ctrl+O

		// 输入处理：ICRNL 决定"回车能不能当回车用"
		ssh.ICRNL:   1,
		ssh.IXON:    1,
		ssh.IMAXBEL: 1,
		ssh.IUTF8:   1,

		// 本地处理：ISIG 决定 Ctrl+C 是否产生信号，ICANON 决定行编辑
		ssh.ISIG:    1,
		ssh.ICANON:  1,
		ssh.ECHO:    1,
		ssh.ECHOE:   1,
		ssh.ECHOK:   1,
		ssh.IEXTEN:  1,
		ssh.ECHOCTL: 1,
		ssh.ECHOKE:  1,

		// 输出处理：ONLCR 决定换行之后要不要回到行首
		ssh.OPOST: 1,
		ssh.ONLCR: 1,

		// 控制模式与速率
		ssh.CS8:           1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
}

// StartTerminal 在已有连接上开一个带 PTY 的 shell。
func StartTerminal(client *ssh.Client, cols, rows int, termName string) (*Terminal, error) {
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	if termName == "" {
		termName = "xterm-256color"
	}

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建会话通道失败: %w", err)
	}

	if err := sess.RequestPty(termName, rows, cols, ptyTerminalModes()); err != nil {
		sess.Close()
		return nil, fmt.Errorf("申请 PTY 失败: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("获取标准输入失败: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("获取标准输出失败: %w", err)
	}
	// stderr 合并进同一路输出，避免两路交错。
	sess.Stderr = nil

	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, fmt.Errorf("启动 shell 失败: %w", err)
	}

	return &Terminal{session: sess, stdin: stdin, output: stdout}, nil
}

// Read 读取远端输出。
func (t *Terminal) Read(p []byte) (int, error) { return t.output.Read(p) }

// Write 向远端写入（键盘输入）。
func (t *Terminal) Write(p []byte) (int, error) { return t.stdin.Write(p) }

// Resize 调整远端 PTY 大小。
func (t *Terminal) Resize(cols, rows int) error {
	if cols <= 0 || rows <= 0 {
		return nil
	}
	// ssh 的 WindowChange 参数顺序是 (h, w)，即 (rows, cols)。
	return t.session.WindowChange(rows, cols)
}

// Wait 等待 shell 退出。
func (t *Terminal) Wait() error { return t.session.Wait() }

// Close 关闭会话，并释放池连接上的长引用。
func (t *Terminal) Close() error {
	var err error
	t.closeOnce.Do(func() {
		_ = t.stdin.Close()
		err = t.session.Close()
		if t.release != nil {
			t.release()
			t.release = nil
		}
	})
	return err
}
