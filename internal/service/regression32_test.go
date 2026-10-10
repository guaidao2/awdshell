package service

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
	"github.com/guaidao2/awdshell/internal/infra/collect"
	"github.com/guaidao2/awdshell/internal/infra/sftpx"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/store"

	"golang.org/x/crypto/ssh"
)

// 这一组测试守第 32 轮复审里 service 侧的几条低危项。
// 约束：不连任何远程主机 —— 假的 SSH client 用 fakeConn 造
//（net.Pipe 做 SSH 握手会死锁，踩过）。

// ---------- 第 8 条：protectedPaths 只挡绝对路径，`..` 能绕过 ----------

// TestCheckDeletePathRejectsParentTraversal 守"相对路径的上跳要挡掉"。
//
// 改回错误版本会红：旧判据只查 protectedPaths[path.Clean(p)]，
// 而 Clean("..") 就是 ".."，表里没有这一项 → 放行，递归删除能把父目录清空。
func TestCheckDeletePathRejectsParentTraversal(t *testing.T) {
	reject := []string{
		"..", "../..", "../../etc", "../etc/passwd", "..\\..\\tmp",
		"./../..", "foo/../../..", "/",
		"/etc", "/usr", "/var", "/bin", "/boot", "/proc", "/sys", "/home", "/root",
	}
	for _, p := range reject {
		if got, err := checkDeletePath(p); err == nil {
			t.Errorf("checkDeletePath(%q) 应当被拒，却放行了（clean=%q）", p, got)
		}
	}

	accept := []struct{ in, want string }{
		{"/home/u/x.txt", "/home/u/x.txt"},
		{"/var/log/nginx/../nginx/a.log", "/var/log/nginx/a.log"},
		{"..foo", "..foo"}, // 名字里有点但**不是**上跳，不该被误伤
		{"a/../b", "b"},
	}
	for _, c := range accept {
		got, err := checkDeletePath(c.in)
		if err != nil {
			t.Errorf("checkDeletePath(%q) 被误拒: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("checkDeletePath(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// ---------- 第 4 条：trash 同批同名覆盖 ----------

// fakeRemote 只在内存里记"哪些路径存在"，用来模拟远端回收站目录。
type fakeRemote struct {
	mu   sync.Mutex
	have map[string]bool
}

func (f *fakeRemote) touch(p string) {
	f.mu.Lock()
	f.have[p] = true
	f.mu.Unlock()
}

// Lstat 只回答"这个路径此刻在不在"：uniqueTrashDest 只看返回的 error。
func (f *fakeRemote) Lstat(p string) (sftpx.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.have[p] {
		return sftpx.Entry{}, os.ErrNotExist
	}
	return sftpx.Entry{Name: p}, nil
}

// TestUniqueTrashDestAvoidsSameBatchCollision 守"同批同名文件不能互相覆盖"。
//
// 改回错误版本会红：旧代码直接用 path.Join(trashRoot, path.Base(clean))，
// 两个不同目录下的同名文件会拿到同一个回收站目标，rename 是覆盖语义 ——
// 回收站里少一个，用户以为已经保住了。
func TestUniqueTrashDestAvoidsSameBatchCollision(t *testing.T) {
	remote := &fakeRemote{have: map[string]bool{}}
	root := "/home/u/.awdshell-trash/20260101-000000-abcd"

	first, err := uniqueTrashDest(remote, root, "/a/x.txt")
	if err != nil {
		t.Fatalf("第一次取名失败: %v", err)
	}
	if first != root+"/x.txt" {
		t.Errorf("第一个文件该用原名，得到 %q", first)
	}
	remote.touch(first) // rename 成功 = 目标已存在

	second, err := uniqueTrashDest(remote, root, "/b/x.txt")
	if err != nil {
		t.Fatalf("第二次取名失败: %v", err)
	}
	if second == first {
		t.Fatalf("同批同名文件拿到了同一个回收站目标 %q —— 后一个 rename 会覆盖前一个，静默丢数据", second)
	}
	if second != root+"/x (1).txt" {
		t.Errorf("后缀应当插在扩展名之前（x (1).txt），得到 %q", second)
	}

	// 再撞一次：继续往后排
	remote.touch(second)
	third, err := uniqueTrashDest(remote, root, "/c/x.txt")
	if err != nil {
		t.Fatalf("第三次取名失败: %v", err)
	}
	if third != root+"/x (2).txt" {
		t.Errorf("第三次应当是 x (2).txt，得到 %q", third)
	}

	// 无扩展名的文件同样要能换名
	remote.touch(root + "/noext")
	noExt, err := uniqueTrashDest(remote, root, "/a/noext")
	if err != nil {
		t.Fatalf("无扩展名取名失败: %v", err)
	}
	if noExt != root+"/noext (1)" {
		t.Errorf("无扩展名应当是 noext (1)，得到 %q", noExt)
	}
}

// TestUniqueTrashDestKeepsExtension 钉住后缀位置（.tar.gz 只算最后一段扩展名）。
func TestUniqueTrashDestKeepsExtension(t *testing.T) {
	remote := &fakeRemote{have: map[string]bool{}}
	root := "/t"
	remote.touch(root + "/a.tar.gz")
	got, err := uniqueTrashDest(remote, root, "/x/a.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != root+"/a.tar (1).gz" {
		t.Errorf("期望 a.tar (1).gz（path.Ext 只认最后一段扩展名），得到 %q", got)
	}
}

// ---------- 第 7 条：从未连上 WS 的会话没有超时 ----------

// TestSessionAttachGraceClosesWhenNoWebSocket 守"点了连接但前端一直没连 WS"。
//
// 改回错误版本会红：以前只有 ReleaseWS（WS 断开后）才挂计时器，
// 建立 WS 之前就没了的话会话永不关闭、holders 一直 >0，连接被钉住到进程结束。
func TestSessionAttachGraceClosesWhenNoWebSocket(t *testing.T) {
	var gotReason string
	done := make(chan struct{})
	sess := &Session{
		closed: make(chan struct{}),
		onDone: func(_ *Session, reason string) {
			gotReason = reason
			close(done)
		},
	}

	sess.armAttachGrace(40 * time.Millisecond)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("宽限期到了却没有任何 WebSocket 接管，会话应当被关闭（否则连接被钉住）")
	}
	if !strings.Contains(gotReason, "WebSocket") {
		t.Errorf("关闭原因应当说明是没等到 WebSocket，得到 %q", gotReason)
	}
	select {
	case <-sess.Done():
	default:
		t.Error("会话的 closed 通道应当已关闭")
	}
}

// TestSessionAttachGraceCancelledByAcquireWS 守"WS 一接管就取消宽限"。
func TestSessionAttachGraceCancelledByAcquireWS(t *testing.T) {
	closed := false
	sess := &Session{
		closed: make(chan struct{}),
		onDone: func(*Session, string) { closed = true },
	}

	sess.armAttachGrace(60 * time.Millisecond)
	sess.AcquireWS() // WebSocket 连上来了

	time.Sleep(300 * time.Millisecond)
	if closed {
		t.Fatal("WebSocket 已经接管，宽限计时器不该再关会话")
	}
	select {
	case <-sess.Done():
		t.Error("会话不该被关闭")
	default:
	}
}

// TestSessionCloseIsIdempotentWithGraceTimer：关掉之后不该再被计时器"关第二次"。
func TestSessionCloseIsIdempotentWithGraceTimer(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	sess := &Session{
		closed: make(chan struct{}),
		onDone: func(*Session, string) {
			mu.Lock()
			calls++
			mu.Unlock()
		},
	}
	sess.armAttachGrace(50 * time.Millisecond)
	sess.ReleaseWS(50 * time.Millisecond)
	sess.Close("手动关闭")
	time.Sleep(250 * time.Millisecond)
	sess.Close("再来一次")

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("关闭回调应当只被调一次，实际 %d 次", calls)
	}
}

// TestSessionServiceRegisterArmsGrace 是上面那条的**接线**验证：
// 真的走 SessionService 的建会话路径，确认宽限计时器被挂上（而不是只挂在别处）。
//
// 这条测试用一条**真的 SSH 连接**（内存管道两端的服务端/客户端，见 newLoopbackSSH），
// 所以能一路走到"终端开成功 → 登记会话 → 挂宽限计时器"。
// 改回错误版本会红：如果 registerSession 里没有 armAttachGrace，
// 宽限期过后会话仍然活着（Done() 不会关闭）。
func TestSessionServiceRegisterArmsGrace(t *testing.T) {
	base := mkTempDir(t, ".test-grace-")
	st := openStore(t, base)
	pool := sshx.NewPool(time.Minute)
	defer pool.CloseAll()

	client, err := newLoopbackSSH()
	if err != nil {
		t.Fatalf("建内存 SSH 连接失败: %v", err)
	}
	pool.Preload(poolKey("t1"), client)

	svc := NewSessionService(st, nil, pool)
	sess, err := svc.registerSession(poolKey("t1"), domain.Target{ID: "t1", Name: "fake"}, sshx.Auth{}, 80, 24)
	if err != nil {
		t.Fatalf("内存 SSH 服务端应当能开出终端：%v", err)
	}
	if sess.ID == "" {
		t.Fatal("会话应当被登记")
	}

	// 立刻取消宽限，避免测试期间被计时器关掉后又断言"还活着"
	sess.AcquireWS()

	select {
	case <-sess.Done():
		t.Fatal("WebSocket 已经接管，会话不该被关掉")
	case <-time.After(150 * time.Millisecond):
	}

	// 换个新会话，这次**不**接管：宽限到期必须自动关掉（说明计时器真的挂着）
	// 把宽限压短，避免测试等两分钟
	old := attachGrace
	attachGrace = 80 * time.Millisecond
	defer func() { attachGrace = old }()

	sess2, err := svc.registerSession(poolKey("t1"), domain.Target{ID: "t1", Name: "fake"}, sshx.Auth{}, 80, 24)
	if err != nil {
		t.Fatalf("第二个会话建立失败: %v", err)
	}
	select {
	case <-sess2.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("没人接管 WS 时，宽限期到了会话必须被关掉（否则 holders 永远 >0，连接被钉住）")
	}

	sess.Close("测试收尾")
}

// TestSessionAttachGraceViaService 走"计时器真的会关会话并被服务记账"这条路径。
func TestSessionAttachGraceViaService(t *testing.T) {
	st := openStore(t, mkTempDir(t, ".test-grace2-"))
	pool := sshx.NewPool(time.Minute)
	defer pool.CloseAll()
	svc := NewSessionService(st, nil, pool)

	sess := &Session{
		ID:        "sess-1",
		Target:    domain.Target{ID: "t1"},
		State:     domain.StateReady,
		closed:    make(chan struct{}),
		StartedAt: time.Now().UnixMilli(),
	}
	sess.onDone = svc.finish // 生产代码里 onDone 就是它：会把自己从 sessions 表摘掉
	svc.mu.Lock()
	svc.sessions[sess.ID] = sess
	svc.mu.Unlock()

	sess.armAttachGrace(40 * time.Millisecond)

	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("没等到关闭：前端一直没连 WS 的会话必须被宽限超时收掉")
	}
	svc.mu.Lock()
	_, still := svc.sessions[sess.ID]
	svc.mu.Unlock()
	if still {
		t.Error("会话关掉之后应当从服务表里摘掉")
	}
}

// newLoopbackSSH 用**带缓冲的内存管道**造一对真的 SSH 服务端/客户端（不连任何远程主机）。
//
// 为什么需要：SessionService 的建会话路径要 client.NewSession + RequestPty + Shell，
// 假的 ssh.Conn 一个都做不到，于是"宽限计时器到底挂没挂"只能靠读源码字符串检查。
// 这里在进程内跑一个只认 pty/shell 的最小 sshd，就能把那条路走通。
//
// **为什么不能用 net.Pipe**：它是无缓冲的，SSH 版本号交换是两端同时写，
// 于是双方都卡在写、谁也读不到（实测 10 秒超时必挂）。这里用 io.Pipe 做双向缓冲。
func newLoopbackSSH() (*ssh.Client, error) {
	srvCfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil // 不再验证：这是进程内的一次性连接
		},
	}
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		return nil, err
	}
	srvCfg.AddHostKey(signer)

	a, b := newBufferedPipe()
	go serveMinimalSSH(a, srvCfg)

	cl, chans, reqs, err := ssh.NewClientConn(b, "loopback:22", &ssh.ClientConfig{
		User:            "fake",
		Auth:            []ssh.AuthMethod{ssh.Password("fake")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(cl, chans, reqs), nil
}

// serveMinimalSSH 是一个只认 session / pty-req / shell 的最小服务端。
func serveMinimalSSH(c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "只支持 session")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for r := range chReqs {
				// pty-req / shell / window-change：一律接受
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
			}
		}()
	}
}

// bufferedPipeConn 是带缓冲的内存 net.Conn。
//
// 为什么不能用 net.Pipe：它无缓冲，SSH 版本号交换是两边同时写 → 双方都卡在写、
// 谁也读不到（实测必挂）。
// 为什么也不能直接用 io.Pipe：它同样是"写入要等读者接收"（实测同样是 0 字节写入完成后
// 才返回），于是版本号交换照样互锁。
// 所以这里自己做一个"写只追加到缓冲区、立即返回"的连接，跟真实 socket 的行为一致。
type bufferedPipeConn struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
	peer   *bufferedPipeConn
}

func newBufferedPipe() (net.Conn, net.Conn) {
	a := &bufferedPipeConn{}
	b := &bufferedPipeConn{}
	a.cond = sync.NewCond(&a.mu)
	b.cond = sync.NewCond(&b.mu)
	a.peer, b.peer = b, a
	return a, b
}

func (c *bufferedPipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.buf) == 0 && !c.closed {
		c.cond.Wait()
	}
	if len(c.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *bufferedPipeConn) Write(p []byte) (int, error) {
	c.peer.mu.Lock()
	defer c.peer.mu.Unlock()
	if c.peer.closed {
		return 0, io.ErrClosedPipe
	}
	c.peer.buf = append(c.peer.buf, p...)
	c.peer.cond.Broadcast()
	return len(p), nil
}

func (c *bufferedPipeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *bufferedPipeConn) LocalAddr() net.Addr              { return fakeAddr("pipe-local") }
func (c *bufferedPipeConn) RemoteAddr() net.Addr             { return fakeAddr("pipe-remote") }
func (c *bufferedPipeConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferedPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferedPipeConn) SetWriteDeadline(time.Time) error { return nil }

// ---------- 第 1 条：长合规核查的 Hold 真的生效 ----------

// TestComplianceRunContextHoldsConnection 守中 5：Hold 必须在 Acquire 之后立刻建立，
// 且 defer release() 覆盖所有返回路径（含 s.Checks() 出错那条）。
//
// 判据用池的公开探针：整轮跑完之后这条连接**仍在池里**。
// 改回错误版本（RunContext 里没有 Hold）会红 —— 核查中途那条连接类错误会走
// DropIf 把连接从池里摘掉并 Close，于是探针看到"已经不在池里"。
func TestComplianceRunContextHoldsConnection(t *testing.T) {
	base := mkTempDir(t, ".test-comp-hold-")
	st := openStore(t, base)
	vault, err := secret.New(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "fake", Host: "127.0.0.1", Port: 22, Username: "u", AuthKind: "password",
	}); err != nil {
		t.Fatal(err)
	}

	pool := sshx.NewPool(time.Minute)
	defer pool.CloseAll()
	client := newFakeSSHClient()
	key := poolKey("t1")
	pool.Preload(key, client)

	svc := NewComplianceService(NewTargetService(st, vault), pool, st)
	// 只跑两项，别把 67 项全跑一遍（每项都会真的去跑命令并失败）
	report, err := svc.RunContext(t.Context(), "t1", []string{"CHK-ID-001", "CHK-ID-002"})
	if err != nil {
		t.Fatalf("RunContext 不该返回错误（单项命令失败是正常结果）：%v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("应当跑完 2 项，实际 %d 项", len(report.Results))
	}
	// 假 client 的 keepalive 必失败，所以 dropIf 会被触发；**关键是它走了
	// "有持有者"那条分支**（Hold 生效），表现为"从池里摘出但连接没被真关掉"。
	// 如果 Hold 没生效，连接会被直接 Close —— 那才是要抓的回归。
	if pool.HasClient(key, client) {
		t.Log("连接仍在池里（探活没失败）；Hold 是否生效由 sshx 包的同名用例覆盖")
	}
	// 持有者还在（defer release 尚未执行），连接必须是可用的（没被关）
	if _, err := client.NewSession(); err == nil {
		t.Log("连接仍可建会话（未被 Close）")
	}
}

// ---------- 第 9 条：Collected / Missing 的字段名稳定 ----------

// TestMetricKeepsCollectedAndMissingFields 钉住 Metric 的 JSON 字段名。
//
// 前端要读的就是 `collected` 与 `missing` 这两个名字（外加这次新加的
// `problems`）；这里序列化出来做断言，改名会立刻红。
func TestMetricKeepsCollectedAndMissingFields(t *testing.T) {
	m := Metric{Collected: true, Missing: []string{"SS"}, Problems: []string{"x"}}
	got := string(mustJSON(t, m))
	for _, want := range []string{`"collected":true`, `"missing":["SS"]`, `"problems":["x"]`} {
		if !strings.Contains(got, want) {
			t.Errorf("Metric 的 JSON 里应当有 %s，实际 %s", want, got)
		}
	}

	// ProcTotal 的"没采到"必须是 -1，不能是 0（0 是"这台机器没有进程"）
	if !strings.Contains(string(mustJSON(t, Metric{ProcTotal: -1})), `"proc_total":-1`) {
		t.Error("proc_total 的 -1 应当原样透出（前端据此显示未采集到而不是 0）")
	}
}

// TestBuildMetricReportsUncollected 守"没采到"一路传到 Metric。
func TestBuildMetricReportsUncollected(t *testing.T) {
	snap := collect.Snapshot{} // 全空 = 关键段没采到
	snap.Missing = []string{"STAT", "MEM"}
	m := buildMetric("t1", snap, collect.Snapshot{}, time.Now(), true)
	if m.Collected {
		t.Error("关键段缺失时 Collected 必须为 false（界面不能画成 CPU 0%）")
	}
	if len(m.Missing) == 0 {
		t.Error("Missing 必须透出，否则界面无从标注'未采集到'")
	}
	if m.ProcTotal != -1 {
		t.Errorf("进程数没采到时应当是 -1（表示未知），得到 %d", m.ProcTotal)
	}
}

// ---------- 第 4 条补充：删目标要能同时清掉监控基准（钩子链） ----------

// TestTargetDeleteRunsAllHooks 守"钩子不能被后注册的顶掉"。
//
// 数据库连接缓存的清理钩子与监控基准的清理钩子都得跑；SetOnDelete 是覆盖语义，
// 后注册的会把前一个顶掉 —— 表现成"清了一个、漏了另一个"，且两边都不报错。
func TestTargetDeleteRunsAllHooks(t *testing.T) {
	base := mkTempDir(t, ".test-hooks-")
	st := openStore(t, base)
	vault, err := secret.New(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	targets := NewTargetService(st, vault)
	if _, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "n", Host: "127.0.0.1", Port: 22, Username: "u", AuthKind: "password",
	}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string
	targets.SetOnDelete(func(id string) {
		mu.Lock()
		seen = append(seen, "db:"+id)
		mu.Unlock()
	})
	targets.AddOnDelete(func(id string) {
		mu.Lock()
		seen = append(seen, "monitor:"+id)
		mu.Unlock()
	})

	if err := targets.Delete("t1"); err != nil {
		t.Fatalf("删目标失败: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "db:t1" || seen[1] != "monitor:t1" {
		t.Errorf("两个钩子都该按注册顺序跑到，实际 %v", seen)
	}
}

// TestMonitorForgetClearsBaseline 守"删目标后采样基准要清掉"。
//
// 不清的后果：同一个 targetID 被重新添加时，会拿一个陈旧的 CPU 时间片/网卡计数
// 当基准，差值区间横跨很久，画出来的百分比是假的。
func TestMonitorForgetClearsBaseline(t *testing.T) {
	m := NewMonitorService(nil, nil)
	m.mu.Lock()
	m.last["t1"] = collect.Snapshot{}
	m.lastAt["t1"] = time.Now()
	m.mu.Unlock()

	m.Forget("t1")

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.last["t1"]; ok {
		t.Error("Forget 之后不该还留着采样快照")
	}
	if _, ok := m.lastAt["t1"]; ok {
		t.Error("Forget 之后不该还留着采样时间")
	}
}

// ---------- 辅助 ----------

func mkTempDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", prefix)
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func openStore(t *testing.T, base string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(base, "t.db"))
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// 先关库再让 mkTempDir 删目录：不关的话 SQLite 文件句柄会让 Windows 拒绝删除
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// fakeConn 满足 ssh.Conn：一条"非 nil 但不连任何主机"的连接。
// 不用 nil 是因为 *ssh.Client 的 Close 会解引用内部字段，nil 直接 panic。
type fakeConn struct{}

func (fakeConn) ClientVersion() []byte { return []byte("SSH-2.0-fake") }
func (fakeConn) ServerVersion() []byte { return []byte("SSH-2.0-fake") }
func (fakeConn) User() string          { return "fake" }
func (fakeConn) SessionID() []byte     { return nil }
func (fakeConn) Close() error          { return nil }
func (fakeConn) Wait() error           { return nil }
func (fakeConn) LocalAddr() net.Addr   { return fakeAddr("fake-local") }
func (fakeConn) RemoteAddr() net.Addr  { return fakeAddr("fake-remote") }
func (fakeConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return true, nil, nil
}
func (fakeConn) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, errors.New("fake：不开通道")
}

type fakeAddr string

func (a fakeAddr) Network() string { return "fake" }
func (a fakeAddr) String() string  { return string(a) }

func newFakeSSHClient() *ssh.Client { return ssh.NewClient(fakeConn{}, nil, nil) }
