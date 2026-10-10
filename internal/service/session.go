package service

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/store"

	"golang.org/x/crypto/ssh"
)

// Session 是一次活动的终端会话。
type Session struct {
	ID        string
	Target    domain.Target
	Token     string
	RecordID  int64
	StartedAt int64
	State     string

	client    *ssh.Client
	term      *sshx.Terminal
	mu        sync.Mutex
	in        int64
	out       int64
	closed    chan struct{}
	closeOnce sync.Once
	onDone    func(*Session, string)

	// wsTimer 是"等 WebSocket 接管/重连"的宽限计时器，见 armAttachGrace 与 ReleaseWS。
	wsTimer *time.Timer
}

// attachGrace 是"会话已建好（连接已 Hold）但还没有 WebSocket 接管"的宽限时间。
//
// 为什么必须有：用户在界面上点了连接，`Open` 当场就把池连接 Hold 住了（终端生命周期
// 内不解引用），可前端不一定接得上 WS —— 建 WS 之前页面就被关掉、网络断了、
// 或者升级请求干脆没发出来。那种会话没人会来调 ReleaseWS，于是它永远活着：
// holders 一直 >0，reaper 按设计不回收有持有者的连接，这条 SSH 连接就被一个
// 已经没人看的终端钉住到进程结束（修 reaper 之前它反倒会被顺带收掉，算是修复的副作用）。
//
// 取 2 分钟：正常"点连接 → 建 WS"是毫秒级的事，2 分钟足够容忍脚本加载慢、
// 用户切了个标签、本机短暂卡顿；又不至于让一条被遗弃的连接留很久。
var attachGrace = 2 * time.Minute

// armAttachGrace 挂上"等一下有没有 WebSocket 来接管"的计时器。
//
// 到期还没有人来（AcquireWS / Attach 都会取消它）就关掉会话 —— Close 里会走
// term.Close → release，把池连接的 Hold 释放掉，连接随即回到"空闲可回收"状态。
func (s *Session) armAttachGrace(after time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wsTimer != nil {
		s.wsTimer.Stop()
	}
	s.wsTimer = time.AfterFunc(after, func() {
		s.closeOnce.Do(func() {
			// 计时器到期与 AcquireWS 是并发的：谁先把 wsTimer 摘成 nil 谁说了算。
			// 抢不到（说明有人刚接管）就什么都不做。
			s.mu.Lock()
			armed := s.wsTimer != nil
			s.wsTimer = nil
			s.mu.Unlock()
			if armed {
				s.closeNow("未等到 WebSocket 连接，会话宽限期已过")
			}
		})
	})
}

// AcquireWS 在 WebSocket 接管会话时调用，取消断线/未连接的宽限。
func (s *Session) AcquireWS() {
	s.mu.Lock()
	if s.wsTimer != nil {
		s.wsTimer.Stop()
		s.wsTimer = nil
	}
	s.mu.Unlock()
}

// ReleaseWS 在 WebSocket 断开时调用：给一段宽限期再关会话。
//
// 为什么不立刻关：用户可能只是刷新页面或网络瞬断，直接关掉会让所有终端会话
// 连同滚动历史一起消失。宽限期内有新的 WebSocket 接管就继续用；
// 一直没人来才真正关闭 —— 这样既不丢会话，读协程也不会永久滞留在 sess.Read 上。
func (s *Session) ReleaseWS(grace time.Duration) {
	s.mu.Lock()
	if s.wsTimer != nil {
		s.wsTimer.Stop()
	}
	s.wsTimer = time.AfterFunc(grace, func() {
		s.closeOnce.Do(func() {
			s.mu.Lock()
			armed := s.wsTimer != nil
			s.wsTimer = nil
			s.mu.Unlock()
			if armed {
				s.closeNow("WebSocket 断开后未重连")
			}
		})
	})
	s.mu.Unlock()
}

// Read 读取远端输出。
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.term.Read(p)
	if n > 0 {
		s.mu.Lock()
		s.out += int64(n)
		s.mu.Unlock()
	}
	return n, err
}

// WriteInput 把键盘输入写到远端。
func (s *Session) WriteInput(p []byte) error {
	s.mu.Lock()
	s.in += int64(len(p))
	s.mu.Unlock()
	_, err := s.term.Write(p)
	return err
}

// Resize 调整远端 PTY。
func (s *Session) Resize(cols, rows int) error { return s.term.Resize(cols, rows) }

// Done 在会话结束时关闭。
func (s *Session) Done() <-chan struct{} { return s.closed }

// Stats 返回累计字节数。
func (s *Session) Stats() (in, out int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.in, s.out
}

// Wait 等待 shell 退出并返回错误（nil 表示正常退出）。
func (s *Session) Wait() error { return s.term.Wait() }

// Close 关闭会话（幂等）。
func (s *Session) Close(reason string) {
	s.closeOnce.Do(func() { s.closeNow(reason) })
}

// closeNow 是真正关闭：外部只能通过 Close / 宽限计时器进来，两者都先过 closeOnce。
//
// 顺带停掉宽限计时器并把它摘成 nil —— "会话已关"与"还挂着一个到点会再关一次的
// 计时器"不能同时成立（多留的那个计时器会让 closeNow 被调第二次）。
func (s *Session) closeNow(reason string) {
	s.mu.Lock()
	if s.wsTimer != nil {
		s.wsTimer.Stop()
		s.wsTimer = nil
	}
	s.mu.Unlock()

	if s.term != nil {
		_ = s.term.Close()
	}
	// 底层 SSH 连接由连接池共享（文件、探测也用它），这里不关，交给池的空闲回收。
	close(s.closed)
	if s.onDone != nil {
		s.onDone(s, reason)
	}
}

// SessionService 管理所有活动会话。
type SessionService struct {
	store   *store.Store
	targets *TargetService
	pool    *sshx.Pool

	mu       sync.Mutex
	sessions map[string]*Session

	// WSBase 由 HTTP 层注入，形如 ws://127.0.0.1:12345
	WSBase string
}

// NewSessionService 构造服务。终端与文件/探测共用连接池里的同一条 SSH 连接，
// 这样"同步终端目录"才能靠进程父子关系精确定位到我们自己的那个 shell。
func NewSessionService(st *store.Store, ts *TargetService, pool *sshx.Pool) *SessionService {
	return &SessionService{store: st, targets: ts, pool: pool, sessions: map[string]*Session{}}
}

// Open 建立连接并打开一个终端。
func (s *SessionService) Open(targetID string, cols, rows int) (*domain.SessionHandle, error) {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return nil, err
	}

	// 建连接 + 开终端 + 登记会话 + 挂"等 WebSocket 接管"的宽限计时器。
	// 最后那件事必须在会话一登记就做（原因见 registerSession 里的注释）。
	sess, err := s.registerSession(poolKey(target.ID), target, auth, cols, rows)
	if err != nil {
		return nil, err
	}

	// 后台等待 shell 退出（用户输入 exit 或连接断开）。
	go func() {
		waitErr := sess.Wait()
		reason := ""
		if waitErr != nil && waitErr != io.EOF {
			reason = waitErr.Error()
		}
		sess.Close(reason)
	}()

	return &domain.SessionHandle{
		SessionID: sess.ID,
		TargetID:  target.ID,
		Title:     target.Name,
		State:     domain.StateReady,
		WSURL:     fmt.Sprintf("%s/ws/term/%s", s.WSBase, sess.ID),
		WSToken:   sess.Token,
		Cols:      cols,
		Rows:      rows,
		RecordID:  sess.RecordID,
	}, nil
}

// registerSession 建好连接与终端、登记会话，**并挂上"等 WebSocket 接管"的宽限计时器**。
//
// 为什么单独拆出来：宽限计时器必须在会话一登记就挂上（原因见下面的注释），
// 而 Open 的其余部分要求一条真能开 shell 的 SSH 连接 —— 单元测试构造不出来。
// 拆出来之后这条路径可以被直接测到（TestSessionServiceArmsAttachGrace），
// 而不是只能靠"读源码字符串"这种一看就散的检查。
func (s *SessionService) registerSession(key string, target domain.Target, auth sshx.Auth, cols, rows int) (*Session, error) {
	client, err := s.pool.Acquire(key, func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return nil, err
	}
	// StartTerminalHeld：整个终端生命周期里持有这条池连接的长引用，
	// 否则 reaper 只看 lastUsed —— 而终端 I/O 完全不碰池，用户"只开终端"
	// 或窗口最小化时，5~6 分钟后这条连接会被自己人按空闲回收，正在敲的终端突然断。
	term, err := s.pool.StartTerminalHeld(client, cols, rows, "xterm-256color")
	if err != nil {
		// 这条连接是从池里拿的，可能是同目标终端/文件/监控共用的那一条。
		// 不能直接 Close，必须走 Drop 把它从池里摘掉，否则池里会留着一条已关闭的连接，
		// 同目标的其它操作会全部失败直到空闲回收。
		s.pool.DropIf(key, client) // 按身份删，别误删别人刚换上的那条
		return nil, err
	}

	recID, _ := s.store.AddConnection(domain.ConnectionRecord{
		TargetID:  target.ID,
		Name:      target.Name,
		Host:      target.Host,
		Port:      target.Port,
		Username:  target.Username,
		StartedAt: time.Now().UnixMilli(),
	})
	_ = s.store.TouchTarget(target.ID)

	sess := &Session{
		ID:        newID(),
		Target:    target,
		Token:     newToken(),
		RecordID:  recID,
		StartedAt: time.Now().UnixMilli(),
		State:     domain.StateReady,
		client:    client,
		term:      term,
		closed:    make(chan struct{}),
	}
	sess.onDone = s.finish

	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()

	// **必须在这里就挂上宽限计时器**：从这一刻起池连接已经被 Hold 住了（终端生命周期
	// 内不解引用），而"有没有 WebSocket 真正接管"是之后的事。前端如果在建 WS 之前
	// 就没了（页面关掉、升级请求没发出去），没人会来调 ReleaseWS —— 会话永远活着、
	// holders 永远 >0、reaper 按设计不回收，这条连接就被一个没人看的终端钉住。
	// 到期没人接管就 Close；Close 会释放 Hold（term.Close → release），连接回到可回收。
	sess.armAttachGrace(attachGrace)
	return sess, nil
}

// Attach 为仍然活着的会话签发一个新的一次性令牌，供断线重连使用。
//
// 断线（刷新页面、网络瞬断、切网络）后前端不必重新开一个会话 ——
// 会话在宽限期内还活着，重新附着上去就能接着用，终端里的上下文不会丢。
func (s *SessionService) Attach(id string) (*domain.SessionHandle, error) {
	sess, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("会话不存在或已结束")
	}
	select {
	case <-sess.Done():
		return nil, fmt.Errorf("会话已结束")
	default:
	}

	token := newToken()
	sess.mu.Lock()
	sess.Token = token
	sess.mu.Unlock()
	// 取消断线宽限：有人回来了
	sess.AcquireWS()

	return &domain.SessionHandle{
		SessionID: sess.ID,
		TargetID:  sess.Target.ID,
		Title:     sess.Target.Name,
		State:     sess.State,
		WSURL:     fmt.Sprintf("%s/ws/term/%s", s.WSBase, sess.ID),
		WSToken:   token,
		RecordID:  sess.RecordID,
	}, nil
}

func (s *SessionService) finish(sess *Session, reason string) {
	s.mu.Lock()
	delete(s.sessions, sess.ID)
	s.mu.Unlock()

	in, out := sess.Stats()
	exitCode := 0
	if reason != "" {
		exitCode = 1
	}
	_ = s.store.FinishConnection(sess.RecordID, exitCode, in, out, reason)
}

// Get 取出会话。
func (s *SessionService) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

// ConsumeToken 校验并消费一次性令牌（防重放）。
//
// Token 由**会话自己的 mu** 保护（Attach 写、这里读与清），不能在持有服务级
// `s.mu` 时去读它 —— 两把锁保护同一个字段，会有读到"旧值"的窗口。
// 实测真实序列（重连签发令牌 + WS 握手消费并发）：2000 次里 968 次把**刚签发**
// 的令牌判成无效，用户侧就是刷新/瞬断后重连偶发失败、只能重开终端。
//
// 这里先放掉 map 锁再拿会话锁，避免嵌套与锁序问题。
func (s *SessionService) ConsumeToken(id, token string) bool {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	s.mu.Unlock()
	if !ok || sess == nil || token == "" {
		return false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.Token != token {
		return false
	}
	sess.Token = "" // 一次性
	return true
}

// Close 关闭指定会话。
func (s *SessionService) Close(id string) {
	if sess, ok := s.Get(id); ok {
		sess.Close("")
	}
}

// List 返回活动会话（按开始时间排序）。
func (s *SessionService) List() []domain.SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.SessionInfo, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, domain.SessionInfo{
			SessionID: sess.ID,
			TargetID:  sess.Target.ID,
			Title:     sess.Target.Name,
			State:     sess.State,
			StartedAt: sess.StartedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt < out[j].StartedAt })
	return out
}

// CloseAll 关闭全部会话（退出时调用）。
func (s *SessionService) CloseAll() {
	s.mu.Lock()
	list := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		list = append(list, sess)
	}
	s.mu.Unlock()
	for _, sess := range list {
		sess.Close("")
	}
}

// TestConnection 只做认证探测，不开 shell（对应"测试连接"按钮）。
func (s *SessionService) TestConnection(targetID string) error {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return err
	}
	client, err := sshx.Dial(target.Host, target.Port, auth, 10*time.Second)
	if err != nil {
		return err
	}
	return client.Close()
}
