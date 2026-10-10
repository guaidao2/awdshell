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
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建执行通道失败: %w", err)
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
