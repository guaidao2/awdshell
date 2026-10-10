package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
)

// newTestStore 在包目录下建临时库（不用系统临时目录），测试结束清理。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".test-store-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	st, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func addConn(t *testing.T, st *Store, host string, startedAt int64) {
	t.Helper()
	_, err := st.AddConnection(domain.ConnectionRecord{
		Host: host, Port: 22, Username: "root", StartedAt: startedAt,
	})
	if err != nil {
		t.Fatalf("插入连接记录失败: %v", err)
	}
}

// TestPruneConnections 验证"按天数 + 按条数"两种清理都对。
func TestPruneConnections(t *testing.T) {
	st := newTestStore(t)

	oldTs := time.Now().AddDate(0, 0, -100).UnixMilli()
	nowTs := time.Now().UnixMilli()

	for i := 0; i < 3; i++ {
		addConn(t, st, "old", oldTs+int64(i))
	}
	for i := 0; i < 5; i++ {
		addConn(t, st, "new", nowTs+int64(i))
	}

	n, err := st.PruneConnections(30, 0)
	if err != nil {
		t.Fatalf("按天数清理失败: %v", err)
	}
	if n != 3 {
		t.Fatalf("按天数清理数量不对：期望 3，实际 %d", n)
	}

	n, err = st.PruneConnections(0, 2)
	if err != nil {
		t.Fatalf("按条数清理失败: %v", err)
	}
	if n != 3 {
		t.Fatalf("按条数清理数量不对：期望 3，实际 %d", n)
	}

	list, err := st.ListConnections(100)
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("剩余记录数不对：期望 2，实际 %d", len(list))
	}
	if list[0].Host != "new" {
		t.Fatalf("剩余记录不是最新的：%+v", list[0])
	}
}

// TestTargetRoundTrip 目标与凭据密文的基本读写。
func TestTargetRoundTrip(t *testing.T) {
	st := newTestStore(t)

	saved, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "web-01", Host: "10.0.0.5", Port: 22,
		Username: "root", AuthKind: domain.AuthPassword, SecretID: "s1",
	})
	if err != nil {
		t.Fatalf("保存目标失败: %v", err)
	}
	if saved.CreatedAt == 0 || saved.UpdatedAt == 0 {
		t.Fatalf("时间戳未落库: %+v", saved)
	}

	got, err := st.GetTarget("t1")
	if err != nil {
		t.Fatalf("读取目标失败: %v", err)
	}
	if got.Host != "10.0.0.5" || got.Username != "root" {
		t.Fatalf("读回内容不对: %+v", got)
	}

	if err := st.PutSecret("s1", []byte("nonce"), []byte("cipher")); err != nil {
		t.Fatalf("写凭据失败: %v", err)
	}
	nonce, cipher, err := st.GetSecret("s1")
	if err != nil {
		t.Fatalf("读凭据失败: %v", err)
	}
	if string(nonce) != "nonce" || string(cipher) != "cipher" {
		t.Fatalf("凭据内容不对: %s / %s", nonce, cipher)
	}

	// 删除目标应连带删除凭据
	if err := st.DeleteTarget("t1"); err != nil {
		t.Fatalf("删除目标失败: %v", err)
	}
	if _, _, err := st.GetSecret("s1"); err == nil {
		t.Fatal("删除目标后凭据仍存在")
	}
}
