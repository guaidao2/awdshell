package sshx

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

type recordingVerifier struct {
	called bool
	host   string
	port   int
	err    error
}

func (r *recordingVerifier) Check(host string, port int, key ssh.PublicKey) error {
	r.called = true
	r.host, r.port = host, port
	return r.err
}

// TestHostKeyCallbackFailClosed 守 L1：
//
// 没有注入校验器时必须**拒绝连接**（fail-closed），而不是放行。
// 以前这里是 `if verifier == nil { return nil }` —— 与"主机密钥必须校验"的
// 注释正好相反：任何忘了注入的调用路径都会静默变成不校验，中间人可无感接管。
func TestHostKeyCallbackFailClosed(t *testing.T) {
	SetHostKeyVerifier(nil) // 复位成"没注入"
	cb := hostKeyCallback("10.0.0.5", 22)
	if err := cb("10.0.0.5", nil, nil); err == nil {
		t.Error("没有校验器时必须拒绝连接，不能放行（这是 fail-open）")
	}

	// 注入之后必须真的走校验器，并且把 host/port 原样传进去
	called := &recordingVerifier{}
	SetHostKeyVerifier(called)
	defer SetHostKeyVerifier(nil)
	if err := cb("10.0.0.5", nil, nil); err != nil {
		t.Errorf("校验器通过时不该报错：%v", err)
	}
	if !called.called || called.host != "10.0.0.5" || called.port != 22 {
		t.Errorf("校验器没被正确调用：%+v", called)
	}
}
