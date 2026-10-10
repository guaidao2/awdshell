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

	client *ssh.Client
	term   *sshx.Terminal
	mu     sync.Mutex
	in     int64
	out    int64
	closed chan struct{}
	once   sync.Once
	onDone func(*Session, string)

	// wsTimer 是 WebSocket 断开后的宽限计时器，见 ReleaseWS。
	wsTimer *time.Timer
}

// AcquireWS 在 WebSocket 接管会话时调用，取消断线宽限。
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
	defer s.mu.Unlock()
	if s.wsTimer != nil {
		s.wsTimer.Stop()
	}
	s.wsTimer = time.AfterFunc(grace, func() {
		s.Close("WebSocket 断开后未重连")
	})
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
	s.once.Do(func() {
		_ = s.term.Close()
		// 底层 SSH 连接由连接池共享（文件、探测也用它），这里不关，交给池的空闲回收。
		close(s.closed)
		if s.onDone != nil {
			s.onDone(s, reason)
		}
	})
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

	client, err := s.pool.Acquire(poolKey(target.ID), func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return nil, err
	}
	term, err := sshx.StartTerminal(client, cols, rows, "xterm-256color")
	if err != nil {
		// 这条连接是从池里拿的，可能是同目标终端/文件/监控共用的那一条。
		// 不能直接 Close，必须走 Drop 把它从池里摘掉，否则池里会留着一条已关闭的连接，
		// 同目标的其它操作会全部失败直到空闲回收。
		s.pool.Drop(poolKey(target.ID))
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
		RecordID:  recID,
	}, nil
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
func (s *SessionService) ConsumeToken(id, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || token == "" || sess.Token != token {
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
