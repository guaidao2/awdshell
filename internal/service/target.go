// Package service 放应用服务：用例编排、凭据解密、审计。
package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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

	// onDelete 是"目标被删掉时"要跑的清理钩子（由 main 注入：数据库连接池、
	// 监控采样基准等），**按注册顺序依次调用**。
	//
	// 为什么是列表而不是单个函数：删一个目标要清掉的东西不止一处（dbx 连接与
	// SSH 隧道、监控的 last/lastAt 基准），而 SetOnDelete 是覆盖语义 ——
	// 后注册的会把先注册的顶掉，表现成"清了一个、漏了另一个"，
	// 且两处都不报错（只是什么都不做）。
	//
	// 为什么要钩子而不是直接依赖：TargetService 不该反过来依赖 DatabaseService
	// 或 MonitorService（会形成 target → database → target 的循环）。但"删目标"
	// 必须能把它们持有的资源一起关掉 —— 否则配置删了、SSH 隧道还开着，
	// `/api/db/query` 仍能对着已删目标走通。
	onDelete []func(targetID string)

	// onSave 是"已有目标被更新时"要跑的清理钩子（同样由 main 注入）。
	//
	// 为什么更新也要清（审计 H2）：Save 更新分支**保留原 ID**，所以目标从
	// A 机改成 B 机之后，缓存里那份"上次采样的 CPU 时间片与网卡累计字节"
	// 还是 A 机的。下次采样拿它做差，CPU% 与网速是假的，而且 First=false ——
	// 界面按正常数值画出来，用户看不出这是错的。见 monitor.Forget。
	onSave []func(targetID string)

	// muHooks 保护 onDelete / onSave：钩子在启动时注册、在删除/保存目标时读取，
	// 启动顺序之外基本不会并发，但注册表本身不该是一个裸字段。
	muHooks sync.Mutex
}

// AddOnDelete 追加一个"目标删除时"的清理钩子。
func (s *TargetService) AddOnDelete(fn func(string)) {
	if fn == nil {
		return
	}
	s.muHooks.Lock()
	s.onDelete = append(s.onDelete, fn)
	s.muHooks.Unlock()
}

// AddOnSave 追加一个"已有目标被更新时"的清理钩子（追加语义，同 AddOnDelete）。
//
// 只对"更新已有目标"触发，新建目标不触发：新建没有任何旧状态可清。
func (s *TargetService) AddOnSave(fn func(string)) {
	if fn == nil {
		return
	}
	s.muHooks.Lock()
	s.onSave = append(s.onSave, fn)
	s.muHooks.Unlock()
}

// runSaveHooks 在"更新已有目标"落库之后跑清理钩子。
func (s *TargetService) runSaveHooks(targetID string) {
	s.muHooks.Lock()
	hooks := append([]func(string){}, s.onSave...)
	s.muHooks.Unlock()
	for _, fn := range hooks {
		fn(targetID)
	}
}

// SaveHookCount 返回已注册的"更新目标"钩子数量。
//
// 为什么要有它：Save 的清理发生在**控制面之外**（main.go 把 monitor.Forget 挂上来），
// 于是"接线漏了"这件事在任何直接调 TargetService 的测试里都看不出来 ——
// 实测：把 main.go 里那行 AddOnSave 删掉，功能测试照样绿（审计 H2 就是这么漏的）。
// main 包的启动自检用这个计数把它钉住。
func (s *TargetService) SaveHookCount() int {
	s.muHooks.Lock()
	defer s.muHooks.Unlock()
	return len(s.onSave)
}

// DeleteHookCount 同上，对应"删除目标"的钩子。
func (s *TargetService) DeleteHookCount() int {
	s.muHooks.Lock()
	defer s.muHooks.Unlock()
	return len(s.onDelete)
}

// SetOnDelete 注入"目标删除之后"的清理钩子（会**替换**已注册的全部钩子）。
//
// 保留它是为了兼容只注册一个钩子的调用点；要追加请用 AddOnDelete。
func (s *TargetService) SetOnDelete(fn func(string)) {
	s.muHooks.Lock()
	s.onDelete = nil
	if fn != nil {
		s.onDelete = append(s.onDelete, fn)
	}
	s.muHooks.Unlock()
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

// DeleteHistory 删掉一条连接历史。
func (s *TargetService) DeleteHistory(id int64) error {
	return s.store.DeleteConnection(id)
}

// ClearHistory 清空连接历史；targetID 为空表示全部清掉。
func (s *TargetService) ClearHistory(targetID string) (int64, error) {
	return s.store.ClearConnections(targetID)
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
	// isUpdate：这次是"改已有目标"而不是"新建"。更新会把原 ID 留下来，
	// 于是所有按 targetID 缓存的旧状态（监控采样基准、db 连接池）都成了
	// 另一台机器的数据 —— 落库之后要清一次（见文件末尾的 runSaveHooks）。
	isUpdate := existing.ID != ""
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
	saved, err := s.store.SaveTarget(t)
	if err != nil {
		return saved, err
	}
	// 更新已有的目标之后清一次缓存状态：主机/端口/用户名/凭据任何一项改了，
	// "上一次采样"的数据就属于另一台机器了（Save 会保留原 ID，见上面的 existing）。
	if isUpdate {
		s.runSaveHooks(saved.ID)
	}
	return saved, nil
}

// Delete 删除目标。
func (s *TargetService) Delete(id string) error {
	// **先关连接池，再删配置行**：DropConnsOfTarget 靠 ListDBConns(targetID)
	// 反查该目标下已建立的连接 id；如果先把 db_conns 删了，它查到 0 条、循环
	// 一次都不跑 —— 钩子就成了空操作，dbx.Conn 与 SSH 隧道会一直留到进程退出
	//（审计实测：删完目标后缓存里仍有 1 条、配置 0 条）。
	if len(s.onDelete) > 0 {
		s.muHooks.Lock()
		hooks := append([]func(string){}, s.onDelete...)
		s.muHooks.Unlock()
		for _, fn := range hooks {
			fn(id)
		}
	}
	// 连带清掉它的数据库连接配置与对应密文，
	// 否则目标删了、配置和密码密文会永久残留
	_ = s.store.DeleteDBConnsOfTarget(id)
	return s.store.DeleteTarget(id)
}

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
