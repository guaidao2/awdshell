package sshx

import (
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// 有持有者时，探活失败的连接**不许**在 Acquire 里被关掉。
//
// 审计实测（audit43 用例 4b）：Hold 住之后走一次 Acquire，closed=1 —— dropIf
// 因为 holders>0 只摘出不关（日志还写着"不主动关闭，避免掐断正在用的终端/SFTP"），
// 可紧接着的无条件 Close 把 holders 保护整个绕过了。结果正是它要防的事：
// 用户正敲的终端、上传中的 SFTP、跑了一半的合规当场断链。
//
// 同时钉住另一半：持有者全部释放后，那条被摘出的连接**必须**被关掉 ——
// 它已经不在 conns 里，CloseAll 遍历不到，不关就是一条 TCP 加一个 mux
// goroutine 永远漏着（实测 DropIf 后、release() 后、CloseAll() 后 closed 一直是 0）。
func TestAcquireDoesNotCloseHeldConnection(t *testing.T) {
	old := pingInterval
	pingInterval = 10 * time.Millisecond // 让下一次 Acquire 必定要探活
	defer func() { pingInterval = old }()

	p := NewPool(time.Minute)
	defer p.CloseAll()

	key := "t:22"
	closedFlag := int32(0)
	// dead=true：探活会失败
	c := ssh.NewClient(fakeConn{dead: true, closeFlag: &closedFlag}, nil, nil)
	p.Preload(key, c)
	release := p.Hold(c)

	time.Sleep(30 * time.Millisecond) // 越过 pingInterval

	var dialed int32
	got, err := p.Acquire(key, func() (*ssh.Client, error) {
		atomic.AddInt32(&dialed, 1)
		return ssh.NewClient(fakeConn{}, nil, nil), nil
	})
	if err != nil {
		t.Fatalf("Acquire 不该失败（应当重新拨号）：%v", err)
	}
	if got == c {
		t.Error("探活失败的那条不该被返回")
	}
	if n := atomic.LoadInt32(&closedFlag); n != 0 {
		t.Fatalf("有持有者时探活失败不许 Close（那会掐断正在用的终端），closedFlag=%d", n)
	}
	if atomic.LoadInt32(&dialed) != 1 {
		t.Errorf("应当重新拨号一次，实际 %d 次", dialed)
	}

	// 持有者释放后，那条被摘出的连接要被关掉
	release()
	if n := atomic.LoadInt32(&closedFlag); n != 1 {
		t.Error("持有者全部释放后，被摘出的连接应当被关闭（否则 TCP 与 mux goroutine 永远漏着）")
	}
}

// 没有持有者时，探活失败的连接照旧直接关掉（原有语义不能退化）。
func TestAcquireClosesUnheldDeadConnection(t *testing.T) {
	old := pingInterval
	pingInterval = 10 * time.Millisecond
	defer func() { pingInterval = old }()

	p := NewPool(time.Minute)
	defer p.CloseAll()

	key := "t:22"
	closedFlag := int32(0)
	c := ssh.NewClient(fakeConn{dead: true, closeFlag: &closedFlag}, nil, nil)
	p.Preload(key, c)

	time.Sleep(30 * time.Millisecond)

	if _, err := p.Acquire(key, func() (*ssh.Client, error) {
		return ssh.NewClient(fakeConn{}, nil, nil), nil
	}); err != nil {
		t.Fatalf("Acquire 不该失败：%v", err)
	}
	if atomic.LoadInt32(&closedFlag) != 1 {
		t.Error("没有持有者时，探活失败的连接应当被直接关闭")
	}
}
