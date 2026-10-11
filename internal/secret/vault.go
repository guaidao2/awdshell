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
	"strings"
	"time"

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
//
// **"首次运行"与"密钥丢了"必须分开**：以前 key.bin 不存在就静默生成一把新密钥，
// 于是 key.bin 被清理工具/用户/备份还原弄丢之后，程序照常启动、界面一切正常，
// 用户点连接才发现所有已存凭据都解不开（AEAD 会拦住，不会解成别的东西，
// 但也没有一个字说明原因）。现在数据目录里已经有程序自己的东西（awdshell.db、
// 或上次写密钥留下的残留）却找不到 key.bin 时，直接报错并点名 key.bin 路径 ——
// 让用户先去找回那把密钥，而不是让程序安静地把已有密文变成废纸。
func New(dataDir string) (*Vault, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	keyPath := filepath.Join(dataDir, "key.bin")

	key, err := os.ReadFile(keyPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if used, why := dirLooksUsed(dataDir); used {
			return nil, fmt.Errorf("凭据密钥文件 %s 不存在，但数据目录不是空的（%s）："+
				"这不是首次运行，多半是 key.bin 被清理工具/备份还原弄丢了。"+
				"请先找回原来的 key.bin（没有它，已保存的密码与私钥永远解不开）；"+
				"确实要放弃旧凭据，请手动删除数据目录里的 awdshell.db 后重试",
				keyPath, why)
		}
		// 只抢"创建真文件"：赢的写、输的（ErrExist）读回复用赢家那把密钥。
		err = createKeyFileExclusive(keyPath)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("写入密钥失败: %w", err)
		}
		// 建完统一走"读 + 抢占窗口重读"（不复用上面那次读的结果：那次必然是 ErrNotExist）
		key, err = readKeySettled(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取密钥失败: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("读取密钥失败: %w", err)
	default:
		// 文件已经在（可能是别人刚抢建出来的）：长度不对时短睡重读几次 ——
		// 兜住"赢家已建文件、还没写满 32 字节"的窗口，见 readKeySettled。
		if len(key) != chacha20poly1305.KeySize {
			key, err = readKeySettled(keyPath)
			if err != nil {
				return nil, fmt.Errorf("读取密钥失败: %w", err)
			}
		}
	}
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("密钥长度非法: %d（%s）", len(key), keyPath)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AEAD 失败: %w", err)
	}
	return &Vault{aead: aead, keyPath: keyPath}, nil
}

// keyReadAttempts / keyReadRetryDelay 是"抢占窗口"里重读密钥的次数与间隔。
//
// 为什么需要（复审 P1-3）：首启并发用 O_CREATE|O_EXCL 抢真文件，赢家从"建出文件"
// 到"写满 32 字节"之间存在一个窗口（实测：0 字节、16 字节都能造出来）。输的一方
// 老实现立刻 ReadFile，读到 0 字节就报「密钥长度非法: 0」并 fatalStartup ——
// 与"抢输的读回复用赢家那把密钥"的设计承诺不符，等于是"并发首启有一方起不来"。
// 窗口是微秒级，5 次 × 20ms 足够跨过（也远小于任何启动超时）；
// 真的坏了（长度始终不对）才报错。
const (
	keyReadAttempts   = 5
	keyReadRetryDelay = 20 * time.Millisecond
)

// readKeySettled 读 key.bin，长度不对就短睡后重读，直到读满 32 字节或次数用尽。
//
// 返回最后一次读到的内容与错误；调用方仍然要自己判长度（次数用尽时把
// "密钥长度非法"如实报出去，不能拿半截当密钥用）。
func readKeySettled(path string) ([]byte, error) {
	var (
		key []byte
		err error
	)
	for i := 0; i < keyReadAttempts; i++ {
		key, err = os.ReadFile(path)
		if err == nil && len(key) == chacha20poly1305.KeySize {
			return key, nil
		}
		if i < keyReadAttempts-1 {
			time.Sleep(keyReadRetryDelay)
		}
	}
	return key, err
}

// 数据目录里"程序自己留下的东西"。见到任何一个都说明这不是首次运行。
const dbFileName = "awdshell.db"

// keyTempPrefix 是 key.bin 的临时文件名前缀。写密钥的残留也说明来过一次。
const keyTempPrefix = "key.bin.tmp"

// dirLooksUsed 判断数据目录里是不是已经有**程序自己留下的痕迹**。
//
// 判据只认程序自己的文件名，不认"目录里有没有别的文件"（复审 P1-2）：
// 数据目录由 `-data` 指定，用户完全可能指到一个已经有其它文件的目录（手工建的、
// 从别处拷来的、只放过一个 note.txt 的）。老实现把"任意普通文件都算用过这个目录"，
// 于是**首次启动直接 fatalStartup**，文案还是"key.bin 被清理工具弄丢了" ——
// 用户照它做也删不掉什么，程序就是起不来。
//
// 认两种痕迹：主库文件的派生名（awdshell.db、awdshell.db-wal/-shm、
// awdshell.db.corrupt-* 这类留档）、写密钥的临时文件残留。
//
// **awdshell.log 故意不算**（哪怕它明显是程序自己写的）：main.go 的顺序是
// "desktop 形态先开 awdshell.log → 再 secret.New → 最后 OpenDetail"，
// 把日志算成"用过"的话，**全新安装的桌面形态 100% 起不来**（走到 secret.New 时
// 目录里已经有 awdshell.log，于是被判成"这不是首次运行、key.bin 丢了"）——
// 那正是 459461c 修掉的那类 P0，不能引回来。
// fatalStartup 落的 startup-error.log 同理：它只说明上次启动失败过，
// 不说明这个目录里有凭据数据。
//
// **调用顺序的约束**（踩过，代价是全新安装 100% 起不来）：必须在创建 awdshell.db
// **之前**调用。main 里 store.OpenDetail 会创建主库文件，如果先开库再跑到这里，
// 一个全新的空目录会立刻被自己刚建出来的 awdshell.db 判成"不是首次运行"，
// 于是拒绝生成 key.bin 并退出。所以 main 里的顺序是 secret.New → OpenDetail。
func dirLooksUsed(dataDir string) (bool, string) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return false, ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue // 子目录（用户自己的备份目录之类）不算痕迹
		}
		name := e.Name()
		switch {
		case name == "key.bin":
			continue
		case strings.HasPrefix(name, dbFileName):
			// awdshell.db、awdshell.db-wal/-shm、awdshell.db.corrupt-* ……
			return true, "数据目录里有 " + name
		case strings.HasPrefix(name, keyTempPrefix):
			return true, "数据目录里有写密钥的残留文件 " + name
		}
	}
	return false, ""
}

// createKeyFileExclusive **独占**创建一个新密钥文件。
//
// 为什么不能"先生成密钥、再 tmp + rename"：首启并发时两个实例共用 key.bin.tmp，
// 先 rename 的把 tmp 移走、后一个的 rename 撞 ENOENT（实测 150/150 次至少一个
// 报错）；更坏的交错是两个都"成功"、各自把 key.bin 覆盖成自己的密钥 ——
// 两边都以为初始化成功，先写库的那份密文下次启动永远解不开。
// O_CREATE|O_EXCL 直接抢真文件：赢的写、输的读到 ErrExist 后读回复用。
//
// 内容先写满 32 字节随机密钥再 Sync，最后 Close。输的那一方在"文件已建、还没
// 写满"的窗口里读到的可能是 0 字节或半截内容 —— New 那边用 readKeySettled
// 短睡重读跨过这个窗口，仍然不对才报「密钥长度非法」，绝不会把半截当密钥用。
func createKeyFileExclusive(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path) // 别留一个空 key.bin 让下次启动报"长度非法"
		return fmt.Errorf("生成密钥失败: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// writeKeyFile **原子**写入密钥文件（覆盖已有内容）。
//
// 不能直接 WriteFile：写一半断电/崩溃会留下长度不合法的 key.bin，
// 下次启动 `New` 直接报"密钥长度非法" —— 用户看到的是"程序打不开、数据全丢"。
// 先写同目录的临时文件、fsync、再改名：任何时刻 key.bin 要么是旧的完整内容，
// 要么是新的完整内容，不会出现半截。
//
// **注意：首次创建不走这里**（见 createKeyFileExclusive）—— 用共享的
// key.bin.tmp + rename 做"首建"在并发首启时会互相踩（实测 150/150 次至少
// 一方报错）。本函数保留给"将来换密钥"这类**覆盖已知文件**的场景。
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
