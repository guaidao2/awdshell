package sshx

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrRunTimeout 是「命令执行超时」的哨兵错误。
//
// 为什么单独拎出来：超时只说明命令没跑完，**不代表连接坏了**。
// 之前超时返回的是一个普通错误，IsConnError 就把它归到「连接错误」一侧，
// 于是监控采集、日志扫描、目录同步只要慢一次超时，就会 Drop 掉那条共享连接，
// 把用户正在用的终端一起掐断 —— 和扫 btmp 那次是同一个坑的另一半。
var ErrRunTimeout = errors.New("命令执行超时")

// IsConnError 判断这个错误是不是「连接本身不可用」，而不是命令自己失败。
//
// 为什么必须区分：RunOutput 对命令退出码非 0 也会返回错误（ssh.ExitError），
// 而连接是共享的 —— 终端、文件、监控、日志扫描都用同一条。
// 把「命令失败」当成「连接坏了」去 Drop，会顺手掐断用户正在用的终端。
func IsConnError(err error) bool {
	if err == nil {
		return false
	}
	// 超时：命令没跑完而已，连接未必坏，不能因此丢弃共享连接
	if errors.Is(err, ErrRunTimeout) {
		return false
	}
	// 命令退出码非 0：连接是好的，绝不能因此丢弃共享连接
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return false
	}
	// 通道/会话开不出来：sshd 的 MaxSessions（默认 10）打满时会返回
	// `ssh: rejected: administratively prohibited`，**连接本身是健康的**
	//（同一时刻 Alive() 仍为 true）。按"连接坏了"处理会整条重连，
	// 顺手掐断用户正在用的终端 —— 而重连也解决不了 MaxSessions。
	var openErr *ssh.OpenChannelError
	if errors.As(err, &openErr) {
		return false
	}
	// 远端干净地拆了 session 但没发 exit-status（RFC 4254 允许这种收尾）
	var exitMissing *ssh.ExitMissingError
	if errors.As(err, &exitMissing) {
		return false
	}
	// 其余（会话创建失败、网络错误）按连接不可用处理
	return true
}

// RunOutput 在既有连接上开一条 exec 通道执行命令并返回 stdout（只读探测用，不占用交互 shell）。
func RunOutput(client *ssh.Client, command string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	// **NewSession 本身也要设超时**：它要开一条 channel 并等对端确认，而连接假死
	//（socket 还开着、对端不回包 —— 正是 Alive 存在的理由）时它会一直等。
	// 审计实测：服务端握手成功但永不接受 channel 时，带 800ms 超时的 RunOutput
	// 4 秒都不返回，于是 monitor 15s / logscan 25s / compliance 每项 10s 的超时
	// 全部形同虚设，goroutine 与 session 一起漏。
	sessCh := make(chan *ssh.Session, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := client.NewSession()
		if err != nil {
			errCh <- err
			return
		}
		sessCh <- s
	}()
	var sess *ssh.Session
	select {
	case sess = <-sessCh:
	case err := <-errCh:
		return "", fmt.Errorf("创建执行通道失败: %w", err)
	case <-time.After(timeout):
		// 超时返回前**必须把这条迟到的 session 收掉**（复审 中3）。
		//
		// 为什么：NewSession 在另一个 goroutine 里，它的结果只能落在 sessCh 上。
		// 超时分支以前直接 return，`defer sess.Close()` 还没注册 —— 于是
		// "开通道超时"每发生一次，就在 sshd 那边漏掉一条 session。而
		// sshd 的 MaxSessions 默认只有 10：漏满 10 条之后**所有**新会话都会
		// 被拒（`ssh: rejected: administratively prohibited`），而 IsConnError
		// 故意不把 OpenChannelError 当连接错误（重连也解决不了），于是
		// 界面表现为"什么都用不了，但连接是活的"，不会自动恢复。
		//
		// 处理分两步：
		//   1) 已经躺在缓冲里（1 容量）的就地关掉；
		//   2) 还没到的交给一个收尾 goroutine 等它到，到了立刻关。
		//      等一个有限的窗口：对端彻底假死时 NewSession 不会返回，
		//      无限等会变成"每超时一次漏一个 goroutine"（同样是漏，
		//      只是漏在本地）。窗口取 30s，远大于正常对端确认耗时。
		select {
		case s := <-sessCh:
			_ = s.Close()
		default:
			go func() {
				select {
				case s := <-sessCh:
					_ = s.Close()
				case <-time.After(30 * time.Second):
				}
			}()
		}
		return "", fmt.Errorf("%w（开执行通道超时 %s）", ErrRunTimeout, timeout)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()

	select {
	case err := <-done:
		out := strings.TrimSpace(stdout.String())
		if err != nil {
			// 用 %w 保留原始错误链：调用方要靠 errors.As 区分
			// "命令退出码非 0"（连接是好的）与"连接真的坏了"
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return out, fmt.Errorf("%w: %s", err, msg)
			}
			return out, err
		}
		return out, nil
	case <-time.After(timeout):
		// 先杀远端命令，再等 goroutine 收尾。
		// 不等的话每超时一次就漏一个卡在 sess.Run 上的 goroutine 和一条 session，
		// 连接假死时会 15 秒级地往外堆。
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			// 库实现没能把它弄醒，放弃等待（sess 已关闭，资源会被回收）
		}
		return "", fmt.Errorf("%w（%s）", ErrRunTimeout, timeout)
	}
}
