package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guaidao2/awdshell/internal/domain"
)

func tempStoreDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".test-recover-")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// 正常数据库：不该触发任何补救，note 必须是空串。
func TestOpenDetailHealthyDatabase(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")
	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	defer st.Close()
	if note != "" {
		t.Fatalf("正常数据库不该有补救说明: %s", note)
	}
}

// 数据库文件损坏时必须能自动留档重建，而且**绝不删除**原文件
// —— 对安全运维来说那可能是证据。
func TestOpenDetailRecoversFromCorruptDatabase(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	// 造一个"不是数据库"的文件
	original := []byte("this is definitely not a sqlite database file, but it might be evidence")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("写坏文件失败: %v", err)
	}

	st, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("损坏数据库应当被补救，实际失败: %v", err)
	}
	defer st.Close()

	if note == "" {
		t.Fatal("补救之后必须给出说明（调用方要用它提示用户）")
	}
	if !strings.Contains(note, ".corrupt-") {
		t.Errorf("说明里应指出留档文件，实际: %s", note)
	}

	// 原文件必须被改名保留，内容一字不差
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读目录失败: %v", err)
	}
	backups := []string{}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			backups = append(backups, e.Name())
		}
	}
	if len(backups) == 0 {
		t.Fatal("原文件没有被留档 —— 只允许改名，不允许删除")
	}
	got, err := os.ReadFile(filepath.Join(dir, backups[0]))
	if err != nil {
		t.Fatalf("读留档文件失败: %v", err)
	}
	if string(got) != string(original) {
		t.Fatal("留档文件内容与原文件不一致")
	}

	// 新库必须真的能用
	if _, err := st.SaveTarget(domain.Target{
		ID: "t1", Name: "t1", Host: "127.0.0.1", Port: 22,
		Username: "root", AuthKind: "password",
	}); err != nil {
		t.Fatalf("重建后的库不可用: %v", err)
	}
	if _, err := st.GetTarget("t1"); err != nil {
		t.Fatalf("重建后的库读不回来: %v", err)
	}
}

// 副文件（-wal/-shm）不一致时先尝试移走重开，不该直接把主库留档。
func TestOpenDetailMovesStaleSidecars(t *testing.T) {
	dir := tempStoreDir(t)
	path := filepath.Join(dir, "awdshell.db")

	// 先建一个正常的库并关掉，让主库是合法的 SQLite 文件
	st, err := Open(path)
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	if _, err := st.SaveTarget(domain.Target{
		ID: "keep", Name: "keep", Host: "127.0.0.1", Port: 22,
		Username: "root", AuthKind: "password",
	}); err != nil {
		t.Fatalf("写目标失败: %v", err)
	}
	_ = st.Close()

	// 造一个垃圾 -wal：主库本身是好的，问题出在副文件
	if err := os.WriteFile(path+"-wal", []byte("garbage wal content"), 0o600); err != nil {
		t.Fatalf("写坏 wal 失败: %v", err)
	}

	st2, note, err := OpenDetail(path)
	if err != nil {
		t.Fatalf("副文件损坏应当被补救，实际失败: %v", err)
	}
	defer st2.Close()

	// 主库没有被留档：数据还在
	if _, err := st2.GetTarget("keep"); err != nil {
		t.Errorf("主库数据丢了（不该把主库留档重建）: %v", err)
	}
	if note != "" && strings.Contains(note, ".corrupt-") {
		t.Errorf("主库是好的，不该走留档重建：%s", note)
	}
}

// 权限类错误不该被当成"损坏"（否则会把用户还能救的库改名）。
func TestLooksCorruptOnlyMatchesRealCorruption(t *testing.T) {
	corrupt := []string{
		"file is not a database",
		"file is encrypted or is not a database",
		"database disk image is malformed",
		"SQLITE_CORRUPT: database corruption",
	}
	for _, m := range corrupt {
		if !looksCorrupt(errString(m)) {
			t.Errorf("%q 应被判定为损坏", m)
		}
	}
	other := []string{
		"unable to open database file: permission denied",
		"database is locked",
		"no such file or directory",
		"disk I/O error",
	}
	for _, m := range other {
		if looksCorrupt(errString(m)) {
			t.Errorf("%q 不该被判定为损坏（会误触发留档重建）", m)
		}
	}
	if looksCorrupt(nil) {
		t.Error("nil 不该判定为损坏")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
