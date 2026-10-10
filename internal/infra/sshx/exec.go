package sshx

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

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
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return out, fmt.Errorf("%v: %s", err, msg)
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
		return "", fmt.Errorf("执行超时（%s）", timeout)
	}
}
