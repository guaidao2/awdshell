// Package service 放应用服务：用例编排、凭据解密、审计。
package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/store"
)

// poolKey 是连接池的键：同一目标下终端、文件、探测共用同一条 SSH 连接的多条 channel。
func poolKey(targetID string) string { return "ssh:" + targetID }

// newID 生成 16 字节随机 ID（十六进制）。
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// newToken 生成一次性连接令牌。
func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("tok-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// credentialBlob 是加密后落库的凭据结构。
type credentialBlob struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// SaveTargetInput 是 UI 提交的目标表单。
type SaveTargetInput struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Port       int      `json:"port"`
	Username   string   `json:"username"`
	AuthKind   string   `json:"auth_kind"`
	Password   string   `json:"password"`
	PrivateKey string   `json:"private_key"`
	Passphrase string   `json:"passphrase"`
	Tags       []string `json:"tags"`
	Group      string   `json:"group"`
	StartDir   string   `json:"start_dir"` // 登录后进入的目录；留空 = 家目录
}

// TargetService 管理目标与凭据。
type TargetService struct {
	store *store.Store
	vault *secret.Vault
}

// NewTargetService 构造服务。
func NewTargetService(st *store.Store, v *secret.Vault) *TargetService {
	return &TargetService{store: st, vault: v}
}

// List 返回全部目标。
func (s *TargetService) List() ([]domain.Target, error) { return s.store.ListTargets() }

// Recent 返回最近连接过的目标（用于一键连接）。
func (s *TargetService) Recent(limit int) ([]domain.Target, error) {
	if limit <= 0 {
		limit = 12
	}
	return s.store.RecentTargets(limit)
}

// History 返回连接历史。
func (s *TargetService) History(limit int) ([]domain.ConnectionRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	return s.store.ListConnections(limit)
}

// Save 新建或更新目标；密码/私钥非空时重新加密落库。
func (s *TargetService) Save(in SaveTargetInput) (domain.Target, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	if in.Host == "" {
		return domain.Target{}, fmt.Errorf("主机地址不能为空")
	}
	if in.Username == "" {
		return domain.Target{}, fmt.Errorf("用户名不能为空")
	}
	if in.Port == 0 {
		in.Port = 22
	}
	if in.Name == "" {
		in.Name = in.Host
	}
	if in.AuthKind == "" {
		in.AuthKind = domain.AuthPassword
	}

	var existing domain.Target
	if in.ID != "" {
		if t, err := s.store.GetTarget(in.ID); err == nil {
			existing = t
		}
	}
	if in.ID == "" {
		in.ID = newID()
	}

	// 凭据：只要有新输入就整体重写密文；沿用已有 SecretID 时保留原密文。
	needSecret := in.Password != "" || in.PrivateKey != "" || in.Passphrase != ""
	secretID := existing.SecretID
	if needSecret {
		if secretID == "" {
			secretID = newID()
		}
		blob := credentialBlob{Password: in.Password, PrivateKey: in.PrivateKey, Passphrase: in.Passphrase}
		// 更新时若未填密码但填了私钥，保留原密码（避免误清空）。
		if existing.SecretID != "" && in.Password == "" {
			if old, err := s.reveal(existing.SecretID); err == nil {
				blob.Password = old.Password
			}
		}
		if existing.SecretID != "" && in.PrivateKey == "" {
			if old, err := s.reveal(existing.SecretID); err == nil {
				blob.PrivateKey = old.PrivateKey
				if blob.Passphrase == "" {
					blob.Passphrase = old.Passphrase
				}
			}
		}
		raw, err := json.Marshal(blob)
		if err != nil {
			return domain.Target{}, fmt.Errorf("序列化凭据失败: %w", err)
		}
		nonce, ct, err := s.vault.Seal(secretID, raw)
		if err != nil {
			return domain.Target{}, err
		}
		if err := s.store.PutSecret(secretID, nonce, ct); err != nil {
			return domain.Target{}, err
		}
	} else if existing.SecretID == "" && in.AuthKind != domain.AuthAgent {
		return domain.Target{}, fmt.Errorf("请填写密码或私钥")
	}

	// 标签为空时保留原值：编辑一次就把标签清空，用户会莫名其妙
	// （旧版本就是这样，标签只能靠外部导入，一编辑就丢）
	tags := in.Tags
	if len(tags) == 0 && len(existing.Tags) > 0 {
		tags = existing.Tags
	}

	t := domain.Target{
		ID:        in.ID,
		Name:      in.Name,
		Host:      in.Host,
		Port:      in.Port,
		Username:  in.Username,
		AuthKind:  in.AuthKind,
		SecretID:  secretID,
		Tags:      tags,
		Group:     in.Group,
		StartDir:  strings.TrimSpace(in.StartDir),
		CreatedAt: existing.CreatedAt,
	}
	return s.store.SaveTarget(t)
}

// Delete 删除目标。
func (s *TargetService) Delete(id string) error { return s.store.DeleteTarget(id) }

// Auth 取出目标与解密后的认证材料（调用方负责尽快丢弃）。
func (s *TargetService) Auth(id string) (domain.Target, sshx.Auth, error) {
	t, err := s.store.GetTarget(id)
	if err != nil {
		return t, sshx.Auth{}, err
	}
	auth := sshx.Auth{Kind: t.AuthKind, Username: t.Username}
	if t.SecretID != "" {
		blob, err := s.reveal(t.SecretID)
		if err != nil {
			return t, auth, err
		}
		auth.Password = blob.Password
		auth.PrivateKey = []byte(blob.PrivateKey)
		auth.Passphrase = blob.Passphrase
	}
	return t, auth, nil
}

func (s *TargetService) reveal(secretID string) (credentialBlob, error) {
	var blob credentialBlob
	nonce, ct, err := s.store.GetSecret(secretID)
	if err != nil {
		return blob, err
	}
	raw, err := s.vault.Open(secretID, nonce, ct)
	if err != nil {
		return blob, err
	}
	if err := json.Unmarshal(raw, &blob); err != nil {
		return blob, fmt.Errorf("解析凭据失败: %w", err)
	}
	return blob, nil
}
