// Package sshx 封装 SSH 连接与终端。
package sshx

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"

	"golang.org/x/crypto/ssh"
)

// Auth 是一次连接的认证材料（明文只在内存中短暂存在）。
type Auth struct {
	Kind       string
	Username   string
	Password   string
	PrivateKey []byte
	Passphrase string
}

// HostKeyVerifier 负责主机密钥的校验与首次记录（accept-new 语义）。
// 由上层实现（查库比对指纹），sshx 不关心存储。
type HostKeyVerifier interface {
	Check(host string, port int, key ssh.PublicKey) error
}

// verifier 由上层在启动时注入，避免每个调用点都要多传一个参数。
var verifier HostKeyVerifier

// SetHostKeyVerifier 注入主机密钥校验器。
func SetHostKeyVerifier(v HostKeyVerifier) { verifier = v }

// Dial 建立一条 SSH 连接。
func Dial(host string, port int, auth Auth, timeout time.Duration) (*ssh.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	methods, err := authMethods(auth)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User: auth.Username,
		Auth: methods,
		// 主机密钥必须校验：不校验的话中间人可以无感接管，凭据与后续所有操作都会暴露。
		// 首次连接按 accept-new 记录指纹，之后必须一致；不一致直接拒绝连接。
		HostKeyCallback: func(h string, remote net.Addr, key ssh.PublicKey) error {
			if verifier == nil {
				return nil
			}
			return verifier.Check(host, port, key)
		},
		Timeout: timeout,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	return client, nil
}

func authMethods(auth Auth) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	switch auth.Kind {
	case domain.AuthPrivateKey:
		var (
			signer ssh.Signer
			err    error
		)
		if auth.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(auth.PrivateKey, []byte(auth.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(auth.PrivateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("私钥解析失败: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	case domain.AuthAgent:
		// TODO v0.1 之后接入 ssh-agent（Windows 上走 Pageant/named pipe）
		return nil, errors.New("暂不支持 ssh-agent，请使用密码或私钥")
	default: // password
		if auth.Password == "" {
			return nil, errors.New("密码为空")
		}
		methods = append(methods, ssh.Password(auth.Password))
	}

	// 很多服务器只开 keyboard-interactive，补一个基于密码的应答。
	if auth.Password != "" {
		pw := auth.Password
		methods = append(methods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	return methods, nil
}
