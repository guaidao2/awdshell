package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".test-vault-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// 加解密往返。
func TestSealOpenRoundTrip(t *testing.T) {
	v, err := New(tempDir(t))
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	plain := []byte("root:SuperSecret123")
	nonce, ct, err := v.Seal("target-1", plain)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("密文里不该出现明文")
	}
	got, err := v.Open("target-1", nonce, ct)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("往返结果不一致: %q != %q", got, plain)
	}
}

// AAD 绑定记录 ID：换一个 recordID 必须解不开（防密文换位）。
func TestOpenRejectsWrongRecordID(t *testing.T) {
	v, err := New(tempDir(t))
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	nonce, ct, err := v.Seal("target-1", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	if _, err := v.Open("target-2", nonce, ct); err == nil {
		t.Fatal("换了 recordID 仍然解开 —— AAD 没起作用")
	}
}

// 密文被改一个字节必须被 Poly1305 抓住。
func TestOpenRejectsTampered(t *testing.T) {
	v, err := New(tempDir(t))
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	nonce, ct, err := v.Seal("r", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0xff
	if _, err := v.Open("r", nonce, bad); err == nil {
		t.Fatal("被篡改的密文仍然解开了")
	}
}

// nonce 长度不对要明确报错，而不是 panic 或静默。
func TestOpenRejectsBadNonce(t *testing.T) {
	v, err := New(tempDir(t))
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	_, ct, err := v.Seal("r", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	if _, err := v.Open("r", []byte{1, 2, 3}, ct); err == nil {
		t.Fatal("nonce 长度非法时应报错")
	}
}

// 两次 Seal 的 nonce 必须不同（同一个明文不能出相同密文）。
func TestNonceIsRandom(t *testing.T) {
	v, err := New(tempDir(t))
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	n1, c1, _ := v.Seal("r", []byte("same"))
	n2, c2, _ := v.Seal("r", []byte("same"))
	if bytes.Equal(n1, n2) || bytes.Equal(c1, c2) {
		t.Fatal("两次加密用了相同的 nonce/密文")
	}
}

// 密钥文件内容非法时必须明确失败（不能悄悄生成新密钥把已有数据废掉）。
func TestNewRejectsBadKeyLength(t *testing.T) {
	dir := tempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "key.bin"), []byte("too-short"), 0o600); err != nil {
		t.Fatalf("写测试密钥失败: %v", err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("密钥长度非法时 New 应报错")
	}
	// 而且不能把它覆盖成新密钥 —— 那会让用户已加密的数据永久解不开
	got, err := os.ReadFile(filepath.Join(dir, "key.bin"))
	if err != nil {
		t.Fatalf("读回密钥失败: %v", err)
	}
	if string(got) != "too-short" {
		t.Fatal("New 不该改写已有的非法密钥文件")
	}
}

// 同一个数据目录重复 New 必须复用同一把密钥（否则已存凭据全部解不开）。
func TestNewReusesExistingKey(t *testing.T) {
	dir := tempDir(t)
	v1, err := New(dir)
	if err != nil {
		t.Fatalf("第一次 New 失败: %v", err)
	}
	nonce, ct, err := v1.Seal("r", []byte("secret"))
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	v2, err := New(dir)
	if err != nil {
		t.Fatalf("第二次 New 失败: %v", err)
	}
	got, err := v2.Open("r", nonce, ct)
	if err != nil {
		t.Fatalf("换实例后解不开（密钥没复用）: %v", err)
	}
	if string(got) != "secret" {
		t.Fatalf("解出来是 %q", got)
	}
}

// 密钥文件是原子写的：写完之后目录里不该留 .tmp 残留。
func TestKeyFileNoLeftoverTemp(t *testing.T) {
	dir := tempDir(t)
	if _, err := New(dir); err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "key.bin" {
			t.Errorf("目录里出现了预期外的文件: %s", e.Name())
		}
	}
	key, err := os.ReadFile(filepath.Join(dir, "key.bin"))
	if err != nil {
		t.Fatalf("读密钥失败: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("密钥长度 = %d，期望 32", len(key))
	}
}
