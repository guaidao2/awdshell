package sshx

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeConn 是满足 ssh.Conn 的哑实现，用来造出一条"非 nil 但不连任何主机"的 client。
//
// 为什么不用 nil：*ssh.Client 的 Close() 会解引用内部字段，nil 直接 panic，
// 而 CloseAll 对池里每条连接都会 Close —— 用 nil 会把"实现有 bug"和
// "测试手法不对"混在一起。真握手需要一台目标机，单元测试里不该依赖。
type fakeConn struct {
	// dead 为真时 keepalive 请求失败，用来模拟一条"探活会判死"的连接。
	dead bool
	// closeFlag 非 nil 时，Close() 会把它置 1 —— 用来证明"有持有者时
	// dropIf 只摘出池、不真关连接"（关掉就等于掐断持有者的终端）。
	closeFlag *int32
}

func (fakeConn) ClientVersion() []byte { return []byte("SSH-2.0-fake") }
func (fakeConn) ServerVersion() []byte { return []byte("SSH-2.0-fake") }
func (fakeConn) User() string          { return "fake" }
func (fakeConn) SessionID() []byte     { return nil }
func (c fakeConn) Close() error {
	if c.closeFlag != nil {
		atomic.StoreInt32(c.closeFlag, 1)
	}
	return nil
}
func (fakeConn) Wait() error          { return nil }
func (fakeConn) LocalAddr() net.Addr  { return fakeAddr("fake-local") }
func (fakeConn) RemoteAddr() net.Addr { return fakeAddr("fake-remote") }

func (c fakeConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if c.dead && name == "keepalive@openssh.com" {
		return false, nil, errors.New("fake：连接已死")
	}
	return true, nil, nil
}

func (fakeConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("fake：不开通道")
}

func fakeClient() *ssh.Client { return ssh.NewClient(fakeConn{}, nil, nil) }

// fakeAddr 是 ssh.Conn 要求的地址占位。
type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

// TestAcquireReuseDoesNotRefreshLastPing 钉住 Acquire 里"并发兜底分支"的行为。
//
// 背景：dial 完发现 key 已被别人放好连接时，那个分支曾经顺手把 old.lastPing
// 刷成 now —— 那条连接**根本没被探活**。刷 lastPing 等于把它伪装成刚验活：
// 真死的话要再等一个 pingInterval（生产 15 秒）才会被发现，而这段时间里
// 监控、合规、日志扫描每个操作都要各自等到超时（15s / 10s / 25s），
// 界面上表现成"什么都慢"。
//
// 这个分支只能被并发撞出来，所以测试用"dial 里阻塞"把窗口焊死：
//
//	主 goroutine 进 Acquire → 占位 → dial()（阻塞在这里）
//	替身 goroutine → 把 key 换成一条"刚建好、还没探活"的连接
//	放开 dial → 主 goroutine 走兜底分支，必须原样保留替身那条的 lastPing
//
// 替身连接只有一个，兜底分支必然选中它（它此刻就挂在 key 上），所以是确定性的。
func TestAcquireReuseDoesNotRefreshLastPing(t *testing.T) {
	p := NewPool(5 * time.Minute)
	defer p.CloseAll()

	key := "race-target:22"
	fresh := time.Now()
	sentinel := time.Now().Add(-2 * time.Minute) // 替身那条连接的 lastPing 哨兵
	racing := make(chan struct{})
	release := make(chan struct{})
	replacement := fakeClient()
	// 第一轮探活用的旧连接：探活要**失败**，否则第一轮就把它当可用返回了，
	// 根本进不到第二轮（也就碰不到被测的兜底分支）。
	survived := ssh.NewClient(fakeConn{dead: true}, nil, nil)

	// 先塞一条"早就该探活"的连接：第一轮 Acquire 会探活它、发现是死的、摘掉，
	// 然后进入第二轮 —— 这时 key 是空的，才会走到 dial（也就是被测的兜底分支）。
	p.mu.Lock()
	p.conns[key] = &pooled{
		client:   survived,
		lastUsed: time.Now().Add(-time.Hour),
		lastPing: time.Now().Add(-time.Hour),
	}
	p.mu.Unlock()

	// 替身：等主 goroutine 进 dial 之后，把 key 换成"刚建好、还没探活"的连接。
	// 用"两分钟前"这个**明显可辨**的 lastPing 当哨兵：Windows 的时钟粒度可能让
	// time.Now() 前后两次取到同一个值（实测就是），拿"比 fresh 更新"当断言会漏判，
	// 而"还等于那个哨兵"在 bug 版下必然为假。
	go func() {
		<-racing
		p.mu.Lock()
		p.conns[key] = &pooled{client: replacement, lastUsed: fresh, lastPing: sentinel}
		p.mu.Unlock()
		close(release)
	}()

	dialed := false
	_, _ = p.Acquire(key, func() (*ssh.Client, error) {
		dialed = true
		close(racing) // 替身此刻把连接放进去
		<-release
		// 必须**成功**返回：dial 报错的话 Acquire 会直接返回错误，
		// 根本走不到被测的"发现 key 已被别人占掉"那条兜底分支。
		return fakeClient(), nil
	})

	if !dialed {
		t.Fatal("没走到 dial：这个测试必须覆盖并发兜底分支，否则它什么也没证明")
	}

	p.mu.Lock()
	cur := p.conns[key]
	p.mu.Unlock()
	if cur == nil {
		t.Fatal("兜底分支之后池里应当还有那条并发放进来的连接")
	}
	if cur.client != replacement {
		t.Fatal("兜底分支用错了连接：应当选并发放进来的那条")
	}
	if !cur.lastPing.Equal(sentinel) {
		t.Errorf("兜底分支把 lastPing 从 %v 改成了 %v —— 这条连接没被探活过，"+
			"改了就等于推迟一个 pingInterval 才发现它是死的", sentinel, cur.lastPing)
	}
}

// TestPoolCloseStopsReaper 守 L6：Pool 要有停止路径（CloseAll 会调它）。
//
// 这一版**真的断言 reaper 退出了**：旧版本只查"幂等 / 不 panic / 池清空"，
// 而池清空是 CloseAll 自己做的，跟 reaper 有没有退出毫无关系 —— 把
// `case <-p.done: return` 整段删掉它照样绿（本机 -race 也跑不了，
// 那个"靠竞态检测兜底"的计划等于没兜）。这里直接抓 goroutine 栈来判：
// 关停之后栈里不该再出现 (*Pool).reaper。
func TestPoolCloseStopsReaper(t *testing.T) {
	p := NewPool(time.Minute)

	now := time.Now()
	p.mu.Lock()
	p.conns["t:22"] = &pooled{client: fakeClient(), lastUsed: now, lastPing: now}
	p.mu.Unlock()

	p.Close()
	p.Close()    // 幂等：Close 与 CloseAll 都会调，不能 panic
	p.CloseAll() // 顺带再关一次 done 并回收连接

	if got := len(p.conns); got != 0 {
		t.Errorf("CloseAll 后池应为空，实际 %d 条", got)
	}

	// reaper 必须真的停了（不是"还在 select 但没人叫它"）
	waitReaperGone(t)

	// 停掉之后放一条，再 CloseAll 一次：重复调用不该有问题
	p.mu.Lock()
	p.conns["t2:22"] = &pooled{client: fakeClient(), lastUsed: now, lastPing: now}
	p.mu.Unlock()
	p.CloseAll()
	if got := len(p.conns); got != 0 {
		t.Errorf("第二次 CloseAll 后池应为空，实际 %d 条", got)
	}
}

// waitReaperGone 轮询 goroutine 栈，确认 (*Pool).reaper 已经退出。
//
// 为什么要轮询而不是直接抓一次：close(done) 之后 reaper 要走完当前一轮 select
// 才真正 return，中间有个很短的窗口。最长等 2 秒；超时就是真没退出。
func waitReaperGone(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if !stackHasReaper() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("CloseAll 之后 (*Pool).reaper 仍在运行 —— " +
				"done 通道没有被 select，连接会既不探活也不回收")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func stackHasReaper() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), "(*Pool).reaper")
}

// TestAcquireAfterCloseAllRefuses 守"关停之后池不再接受写入"。
//
// 改回错误版本会红：只清 map、不设 closed 标志时，CloseAll 之后 Acquire 会**重新
// dial 并把新连接插进池里**（实测 1 条），而 reaper 已经退出 —— 这条连接从此
// 既不探活也不回收，一直挂到进程结束。
func TestAcquireAfterCloseAllRefuses(t *testing.T) {
	p := NewPool(time.Minute)
	p.CloseAll()

	dialed := false
	got, err := p.Acquire("t:22", func() (*ssh.Client, error) {
		dialed = true
		return fakeClient(), nil
	})
	if err == nil {
		t.Fatalf("CloseAll 之后 Acquire 应当报错，却拿到了连接 %p", got)
	}
	if !errors.Is(err, ErrPoolClosed) {
		t.Errorf("应当是 ErrPoolClosed，实际 %v", err)
	}
	if dialed {
		t.Error("CloseAll 之后不该再 dial —— 新建的连接没人回收")
	}
	p.mu.Lock()
	n := len(p.conns)
	p.mu.Unlock()
	if n != 0 {
		t.Errorf("CloseAll 之后池里不该有连接，实际 %d 条", n)
	}
}

// TestDropIfSkipsHeldConnection 守"有人持有的连接不被 DropIf 摘掉"。
//
// 改回错误版本会红：旧 dropIf 不看 holders，直接把连接从池里删掉并 Close()，
// 正在用它的终端/SFTP 当场断（这正是 H1 那个坑的放大器 —— "连接坏了"本身
// 就可能误判，而误判的代价是把用户正在敲的终端掐断）。
func TestDropIfSkipsHeldConnection(t *testing.T) {
	p := NewPool(time.Minute)
	defer p.CloseAll()

	key := "t:22"
	closedFlag := int32(0)
	c := ssh.NewClient(fakeConn{closeFlag: &closedFlag}, nil, nil)
	p.mu.Lock()
	p.conns[key] = &pooled{client: c, lastUsed: time.Now(), lastPing: time.Now()}
	p.mu.Unlock()

	release := p.Hold(c)
	p.DropIf(key, c) // 有人持有：摘出池，但**不关**

	p.mu.Lock()
	_, still := p.conns[key]
	p.mu.Unlock()
	// 必须摘出：留在池里的话 Acquire 第二轮会因为 lastPing 刚刷过而不再探活，
	// 把这条**已知死连接**原样递给调用方（实测 got==dead、dialed=0）。
	if still {
		t.Fatal("有活跃持有者时 DropIf 应当把连接从池里摘出（否则死连接会被再发出去）")
	}
	// 但绝不能关：持有者（终端/上传/合规）手里还在用，关掉就是掐断用户的终端。
	if atomic.LoadInt32(&closedFlag) != 0 {
		t.Fatal("有活跃持有者时 DropIf 不能 Close 连接（终端会当场断）")
	}

	release()
	p.DropIf(key, c) // 没人持有了：正常摘掉

	p.mu.Lock()
	_, still = p.conns[key]
	p.mu.Unlock()
	if still {
		t.Error("持有者已释放，DropIf 应当把连接摘掉")
	}
}

// TestHoldAfterCloseAllIsNoop 守"关停之后 Hold 不计数"（否则释放函数找不到对象）。
func TestHoldAfterCloseAllIsNoop(t *testing.T) {
	p := NewPool(time.Minute)
	key := "t:22"
	closedFlag := int32(0)
	c := ssh.NewClient(fakeConn{closeFlag: &closedFlag}, nil, nil)
	p.mu.Lock()
	p.conns[key] = &pooled{client: c, lastUsed: time.Now(), lastPing: time.Now()}
	p.mu.Unlock()

	p.CloseAll()
	release := p.Hold(c) // 不该 panic，也不该留下计数
	release()
	release() // 幂等
}
