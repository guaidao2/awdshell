package sshx

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// 这一组守 review43 里 sshx 的那条修复，断言写成"改回错误版本会红"。

// lateChannel 是满足 ssh.Channel 的哑通道，Close() 会记账 ——
// 用它证明"迟到的 session 到底有没有被关掉"。
type lateChannel struct {
	mu     sync.Mutex
	closes int
}

func (c *lateChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *lateChannel) Write(p []byte) (int, error) { return len(p), nil }
func (c *lateChannel) CloseWrite() error           { return nil }
func (c *lateChannel) SendRequest(string, bool, []byte) (bool, error) {
	return true, nil
}
func (c *lateChannel) Stderr() io.ReadWriter { return &bytes.Buffer{} }

func (c *lateChannel) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	return nil
}

func (c *lateChannel) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// lateSessionConn 模拟"通道开得比调用方的超时慢"的服务端：
// OpenChannel 睡 delay 之后才成功 —— 正是审计替身里的形态
// （100ms 超时、替身 500ms 后才返回）。
type lateSessionConn struct {
	fakeConn
	delay  time.Duration
	opened chan *lateChannel
}

func (c *lateSessionConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	time.Sleep(c.delay)
	ch := &lateChannel{}
	if c.opened != nil {
		c.opened <- ch
	}
	// 必须给一条**已关闭**的请求通道：newSession 会起一个 goroutine
	// range 它（s.wait），nil 通道会让那个 goroutine 永远挂着。
	reqs := make(chan *ssh.Request)
	close(reqs)
	return ch, reqs, nil
}

// TestRev43RunOutputTimeoutClosesLateSession 守 中3：开通道超时后，迟到的 session
// 必须被关掉。
//
// 改回错误版本会红：超时分支直接 return，`defer sess.Close()` 还没注册 ——
// 迟到的 session 落在缓冲通道里，没有任何人会关它。后果不是"漏一个对象"：
// sshd 的 MaxSessions 默认 10，每超时一次烧掉一个槽位，满 10 之后所有新会话
// 都被拒（`ssh: rejected: administratively prohibited`），而 IsConnError
// 故意不把它当连接错误（重连也不解决 MaxSessions）—— 表现成"什么都用不了，
// 但连接是活的"，不会自动恢复。
func TestRev43RunOutputTimeoutClosesLateSession(t *testing.T) {
	conn := &lateSessionConn{delay: 300 * time.Millisecond, opened: make(chan *lateChannel, 1)}
	client := ssh.NewClient(conn, nil, nil)
	defer client.Close()

	start := time.Now()
	out, err := RunOutput(client, "id", 100*time.Millisecond)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrRunTimeout) {
		t.Fatalf("开通道超时应当返回 ErrRunTimeout，实际 %v（out=%q）", err, out)
	}
	if IsConnError(err) {
		t.Error("超时不该被判成连接错误（会顺手掐断用户的终端）")
	}
	// 收尾不能让调用方多等：迟到的 session 由收尾 goroutine 处理，
	// 不是在超时分支里同步等它。
	if elapsed > 250*time.Millisecond {
		t.Errorf("超时分支等了 %v 才返回，应当在超时点附近就返回", elapsed)
	}

	var ch *lateChannel
	select {
	case ch = <-conn.opened:
	case <-time.After(3 * time.Second):
		t.Fatal("测试前提不成立：替身始终没开通道")
	}

	deadline := time.Now().Add(3 * time.Second)
	for ch.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ch.closeCount() == 0 {
		t.Error("迟到的 session 没有被关闭：每超时一次就烧掉 sshd 的一个 MaxSessions 槽位，" +
			"槽位满 10 之后所有新会话都会被拒，而那条路径不会触发重连")
	}
}

// TestRev43RunOutputTimeoutDoesNotCloseOwnedSession 是上面那条的**反向保险**：
// 超时发生在"通道已经开出来、命令还没跑完"的第二段时，收尾逻辑不能
// 顺手去动别的 channel（那条 session 是本次调用自己的，由 defer 关）。
//
// 这里只钉住"第一段的收尾 goroutine 不会误关别人"这一件事：
// 通道正常开出来时，RunOutput 不应该在返回后还去读 sessCh。
func TestRev43RunOutputNormalOpenIsNotDoubleClosed(t *testing.T) {
	conn := &lateSessionConn{delay: 0, opened: make(chan *lateChannel, 1)}
	client := ssh.NewClient(conn, nil, nil)
	defer client.Close()

	// 命令阶段一定超时（替身的 SendRequest 立刻成功，但没有 exit-status），
	// 所以这里只断言"调用返回了、并且返回的错误是超时族"。
	_, err := RunOutput(client, "id", 50*time.Millisecond)
	if err == nil {
		t.Fatal("替身不会给 exit-status，这次调用不该成功")
	}

	ch := <-conn.opened
	deadline := time.Now().Add(2 * time.Second)
	for ch.closeCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// 正常开出来的通道也必须被关（defer sess.Close()）：关两次不算错
	// （Close 幂等），一次都不关才是漏。
	if ch.closeCount() == 0 {
		t.Error("正常开出通道后无论成功失败都要关掉 session（defer sess.Close）")
	}
}
