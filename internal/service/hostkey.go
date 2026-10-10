package service

import (
	"fmt"
	"log"

	"github.com/guaidao2/awdshell/internal/store"

	"golang.org/x/crypto/ssh"
)

// 主机密钥校验（accept-new 语义）实现在这里，注入给 sshx 使用。
//
// 为什么必须校验：不校验的话中间人可以无感接管连接，密码、私钥、以及之后
// 所有终端操作与文件内容都会落到攻击者手里。对安全运维工具来说这是致命项。
//
// 策略：
//   - 首次连接某主机：记录指纹并放行（accept-new，不至于让用户没法用）
//   - 之后连接：指纹必须一致，不一致直接拒绝并说明原因与处理办法
//   - 确认对端确实换过密钥（重装系统、更换算法）后，可在目标编辑里清除记录

// Check 实现 sshx.HostKeyVerifier。
func (s *TargetService) Check(host string, port int, key ssh.PublicKey) error {
	fingerprint := ssh.FingerprintSHA256(key)
	keyType := key.Type()

	known, err := s.store.GetHostKey(host, port)
	if err != nil {
		// 读不到记录时不能默认放行 —— 那等于校验被绕过
		return fmt.Errorf("读取主机密钥记录失败，为安全起见拒绝连接: %w", err)
	}

	if known == nil {
		if err := s.store.SaveHostKey(store.HostKey{
			Host: host, Port: port, KeyType: keyType, Fingerprint: fingerprint,
		}); err != nil {
			return fmt.Errorf("记录主机密钥失败: %w", err)
		}
		log.Printf("首次连接 %s:%d，已记录主机密钥 %s", host, port, fingerprint)
		return nil
	}

	if known.Fingerprint != fingerprint {
		return fmt.Errorf("主机密钥与上次不一致，已拒绝连接\n\n"+
			"  首次记录：%s（%s）\n"+
			"  本次收到：%s（%s）\n\n"+
			"这可能是中间人攻击；也可能是对方重装了系统或更换了密钥。\n"+
			"确认是后者之后，在目标的编辑里清除已记录的主机密钥再连接。",
			known.Fingerprint, known.KeyType, fingerprint, keyType)
	}

	_ = s.store.TouchHostKey(host, port)
	return nil
}

// ForgetHostKey 清除某目标对应主机的密钥记录。
func (s *TargetService) ForgetHostKey(targetID string) (bool, error) {
	t, _, err := s.Auth(targetID)
	if err != nil {
		return false, err
	}
	n, err := s.store.ForgetHostKey(t.Host, t.Port)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// HostKeyInfo 返回某目标当前记录的主机密钥（没有则返回 nil）。
func (s *TargetService) HostKeyInfo(targetID string) (*store.HostKey, error) {
	t, _, err := s.Auth(targetID)
	if err != nil {
		return nil, err
	}
	return s.store.GetHostKey(t.Host, t.Port)
}
