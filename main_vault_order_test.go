package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/store"
)

// 「先建密钥、后开库」这个顺序是必须的 —— 反过来会让全新安装 100% 起不来。
//
// 复审实测（P0）：main 里原来是先 store.OpenDetail 再 secret.New。而
// OpenDetail 会**创建** awdshell.db，于是 secret.New 的 dirLooksUsed 在全新的
// 空目录里看到自己刚建出来的库文件，判定"这不是首次运行"、拒绝生成 key.bin
// 并报错退出 —— 新用户首次双击、换数据目录、CI 里跑临时实例，一律「闪一下就没了」。
//
// 这条测试把因果关系钉住：反向顺序必须失败（说明判据本身是活的），
// 正向顺序必须成功（说明两个语义能共存）。如果有人把 main 的顺序调回去，
// 这里的反向断言会解释清楚为什么。
func TestFreshDataDirNeedsVaultBeforeStore(t *testing.T) {
	// 反向：先建库，再建密钥 —— 必须报错
	dirA := t.TempDir()
	stA, _, err := store.OpenDetail(filepath.Join(dirA, "awdshell.db"))
	if err != nil {
		t.Fatalf("建库本身应当成功: %v", err)
	}
	_ = stA.Close()
	if _, err := secret.New(dirA); err == nil {
		t.Error("先建库再建密钥必须报错（目录里已有 awdshell.db，这正是 'key.bin 丢了' 的判据）；" +
			"如果这里通过了，说明判据失效，真丢了密钥会被静默换成新密钥")
	}

	// 正向：先建密钥，再建库 —— 必须成功
	dirB := t.TempDir()
	vault, err := secret.New(dirB)
	if err != nil {
		t.Fatalf("空目录下建密钥应当成功（首次运行）: %v", err)
	}
	if vault == nil {
		t.Fatal("应当返回可用的保险库")
	}
	stB, _, err := store.OpenDetail(filepath.Join(dirB, "awdshell.db"))
	if err != nil {
		t.Fatalf("建完密钥后开库应当成功: %v", err)
	}
	_ = stB.Close()

	// 反向再验一次：真丢了 key.bin（库还在）必须报错
	if err := os.Remove(filepath.Join(dirB, "key.bin")); err != nil {
		t.Fatalf("删 key.bin 失败: %v", err)
	}
	if _, err := secret.New(dirB); err == nil {
		t.Error("库还在但 key.bin 没了时必须报错，不能安静地换一把新密钥（那会让已有密文永远解不开）")
	}
}
