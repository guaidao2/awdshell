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

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty(termName, rows, cols, modes); err != nil {
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
