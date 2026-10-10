// Package domain 放纯领域模型：不依赖 IO，可单测。
package domain

// 认证方式
const (
	AuthPassword   = "password"
	AuthPrivateKey = "privatekey"
	AuthAgent      = "agent"
)

// 会话状态
const (
	StateConnecting = "connecting"
	StateReady      = "ready"
	StateClosed     = "closed"
	StateError      = "error"
)

// Target 一台被管理的主机。
type Target struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Username   string   `json:"username"`
	AuthKind   string   `json:"auth_kind"` // password | privatekey | agent
	SecretID   string   `json:"secret_id"` // 指向 secrets 表，密文
	Tags       []string `json:"tags"`
	Group      string   `json:"group"`
	StartDir   string   `json:"start_dir"` // 登录后进入的目录；空或不存在则回退 SSH 默认（家目录）
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
	LastUsedAt int64    `json:"last_used_at"`
}

// Addr 返回 host:port 形式。
func (t Target) Addr() string {
	return joinHostPort(t.Host, t.Port)
}

// ConnectionRecord 一次连接的历史记录（用于"历史连接一键连"）。
type ConnectionRecord struct {
	ID        int64  `json:"id"`
	TargetID  string `json:"target_id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	StartedAt int64  `json:"started_at"`
	EndedAt   int64  `json:"ended_at"`
	ExitCode  int    `json:"exit_code"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
	Error     string `json:"error"`
}

// SessionHandle 是打开终端后返回给 UI 的句柄。
type SessionHandle struct {
	SessionID string `json:"session_id"`
	TargetID  string `json:"target_id"`
	Title     string `json:"title"`
	State     string `json:"state"`
	WSURL     string `json:"ws_url"`
	WSToken   string `json:"ws_token"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
	Error     string `json:"error,omitempty"`
	RecordID  int64  `json:"record_id"`
}

// SessionInfo 是活动会话的概览。
type SessionInfo struct {
	SessionID string `json:"session_id"`
	TargetID  string `json:"target_id"`
	Title     string `json:"title"`
	State     string `json:"state"`
	StartedAt int64  `json:"started_at"`
}
