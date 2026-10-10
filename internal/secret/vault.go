// Package secret 提供本地凭据加密。
//
// v0.1 采用"机器密钥文件"模式：首次运行生成 32 字节随机密钥，存 dataDir/key.bin（0600），
// 用 XChaCha20-Poly1305 对每条凭据独立加密，AAD 绑定记录 ID（防密文换位）。
// 后续按 docs/DESIGN.md ADR-005 增加主密码（Argon2id 派生 KEK 包裹 DEK）与 OS keyring 模式。
package secret

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

// Vault 持有一个 AEAD 实例。
type Vault struct {
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
	keyPath string
}

// New 打开（或首次创建）保险库。
func New(dataDir string) (*Vault, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	keyPath := filepath.Join(dataDir, "key.bin")

	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, chacha20poly1305.KeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("生成密钥失败: %w", err)
		}
		if err := writeKeyFile(keyPath, key); err != nil {
			return nil, fmt.Errorf("写入密钥失败: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("读取密钥失败: %w", err)
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("密钥长度非法: %d", len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AEAD 失败: %w", err)
	}
	return &Vault{aead: aead, keyPath: keyPath}, nil
}

// writeKeyFile **原子**写入密钥文件。
//
// 不能直接 WriteFile：写一半断电/崩溃会留下长度不合法的 key.bin，
// 下次启动 `New` 直接报"密钥长度非法" —— 用户看到的是"程序打不开、数据全丢"。
// 先写同目录的临时文件、fsync、再改名：任何时刻 key.bin 要么是旧的完整内容，
// 要么是新的完整内容，不会出现半截。
func writeKeyFile(path string, key []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// KeyPath 返回密钥文件路径（供诊断展示）。
func (v *Vault) KeyPath() string { return v.keyPath }

// Seal 加密一条记录，返回 nonce 与密文。
func (v *Vault) Seal(recordID string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}
	ciphertext = v.aead.Seal(nil, nonce, plaintext, []byte(recordID))
	return nonce, ciphertext, nil
}

// Open 解密一条记录。
func (v *Vault) Open(recordID string, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != v.aead.NonceSize() {
		return nil, fmt.Errorf("nonce 长度非法: %d", len(nonce))
	}
	plain, err := v.aead.Open(nil, nonce, ciphertext, []byte(recordID))
	if err != nil {
		return nil, fmt.Errorf("解密失败（密钥不匹配或数据损坏）: %w", err)
	}
	return plain, nil
}
