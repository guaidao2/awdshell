package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 下载目录相关的行为都是"把外部给的名字/内容写到本地磁盘"，
// 所以这里盯的重点是路径安全、不覆盖用户已有文件、并发时不互相踩。

// testDir 在**当前目录**下建临时目录（不用系统临时目录）。
// 与 store_test.go 保持一致：所有文件操作都留在工作区内。
func testDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".test-dl-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestSafeLocalName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"passwd", "passwd"},
		{"a.txt", "a.txt"},
		// 远端文件名是对方机器上的东西：可能带路径、可能是绝对路径
		{"../../../etc/passwd", "passwd"},
		{"..\\..\\windows\\system32\\cmd.exe", "cmd.exe"},
		{"/etc/shadow", "shadow"},
		{"dir/sub/file.log", "file.log"},
		{"\\\\server\\share\\x", "x"},
		{"C:\\Windows\\System32\\x.dll", "x.dll"},
		// Windows 非法字符与控制字符
		{"a:b*c?d\"e<f>g|h", "a_b_c_d_e_f_g_h"},
		{"tab\there", "tabhere"},
		{"line\nbreak", "linebreak"},
		{"a\x00b", "ab"},
		{"x.txt::$DATA", "x.txt__$DATA"},
		// 只有点、空格的情况不能变成目录穿越或空名
		{"..", "download"},
		{".", "download"},
		{"...", "download"},
		{"  ..  ", "download"},
		{"   ", "download"},
		{"", "download"},
		{"trailing.", "trailing"},
		{"trailing ", "trailing"},
		// Windows 保留设备名要加前缀：纯 NUL 会被当成设备打开，
		// Create/Write 都"成功"但磁盘上没有文件
		{"NUL", "_NUL"},
		{"nul", "_nul"},
		{"NUL.txt", "_NUL.txt"},
		{"CON", "_CON"},
		{"aux", "_aux"},
		{"COM1", "_COM1"},
		{"LPT9", "_LPT9"},
	}
	for _, c := range cases {
		if got := safeLocalName(c.in); got != c.want {
			t.Errorf("safeLocalName(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}

	// 关键性质：结果里不能再出现路径分隔符，否则能写到目录之外
	for _, evil := range []string{
		"../../../../tmp/pwn", "a/b", "a\\b", "..\\..\\x", "/abs/path",
		"....//x", "\\\\?\\C:\\x", "\\\\.\\PhysicalDrive0",
		"%2e%2e%2f", "..\u2215..\u2215x",
	} {
		got := safeLocalName(evil)
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("safeLocalName(%q) = %q，仍含路径分隔符", evil, got)
		}
		if got == ".." || got == "." {
			t.Errorf("safeLocalName(%q) = %q，仍能上跳", evil, got)
		}
	}
}

// createExclusive 用 O_EXCL 抢占文件名：
// 同名自动加序号、不覆盖已有文件。
func TestCreateExclusive(t *testing.T) {
	dir := testDir(t)

	f1, p1, err := createExclusive(dir, "a.txt")
	if err != nil {
		t.Fatalf("第一次创建失败: %v", err)
	}
	f1.Close()
	if filepath.Base(p1) != "a.txt" {
		t.Errorf("第一次应用原名，得到 %q", filepath.Base(p1))
	}

	f2, p2, err := createExclusive(dir, "a.txt")
	if err != nil {
		t.Fatalf("第二次创建失败: %v", err)
	}
	f2.Close()
	if p2 == p1 {
		t.Fatal("同名应换一个名字，否则会覆盖已有文件")
	}
	if filepath.Ext(p2) != ".txt" {
		t.Errorf("换名后扩展名应保留，得到 %q", p2)
	}

	// 内容确实是两份，互不覆盖
	_ = os.WriteFile(p1, []byte("first"), 0o644)
	_ = os.WriteFile(p2, []byte("second"), 0o644)
	if b, _ := os.ReadFile(p1); string(b) != "first" {
		t.Errorf("第一份被改掉了: %q", string(b))
	}

	// 无扩展名也要能换
	f3, _, err := createExclusive(dir, "noext")
	if err != nil {
		t.Fatalf("无扩展名创建失败: %v", err)
	}
	f3.Close()
	f4, _, err := createExclusive(dir, "noext")
	if err != nil {
		t.Fatalf("无扩展名第二次创建失败: %v", err)
	}
	f4.Close()

	// 超长名字：应截断后成功，而不是报 ERROR_INVALID_NAME 或空转
	long := strings.Repeat("a", 300) + ".txt"
	f5, p5, err := createExclusive(dir, long)
	if err != nil {
		t.Fatalf("超长名应能创建（截断），得到: %v", err)
	}
	f5.Close()
	if n := len(filepath.Base(p5)); n > 200 {
		t.Errorf("文件名应被截断，实际 %d 个字符", n)
	}
}

// 并发导出同一个名字：每个请求都该拿到自己的文件，不能互相覆盖。
//
// 旧实现是"先 Stat 再 Create"（TOCTOU）：实测 8 个并发只有 1 个文件留下，
// 但 5 个请求都报成功。改成 O_EXCL 之后每个请求都能拿到独立名字。
func TestSaveTextToDirConcurrent(t *testing.T) {
	dir := testDir(t)
	const n = 8

	var wg sync.WaitGroup
	paths := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths[i], errs[i] = SaveTextToDir(dir, "same.txt", fmt.Sprintf("内容-%d", i))
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("第 %d 个并发保存失败: %v", i, errs[i])
			continue
		}
		if paths[i] == "" {
			t.Errorf("第 %d 个并发保存返回空路径", i)
			continue
		}
		if seen[paths[i]] {
			t.Errorf("两个请求拿到了同一个路径: %s", paths[i])
		}
		seen[paths[i]] = true
		b, err := os.ReadFile(paths[i])
		if err != nil {
			t.Errorf("读第 %d 个文件失败: %v", i, err)
			continue
		}
		if !strings.Contains(string(b), fmt.Sprintf("内容-%d", i)) {
			t.Errorf("第 %d 个文件内容被别人覆盖了: %q", i, string(b))
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Errorf("应有 %d 个文件，实际 %d —— 有请求互相覆盖了", n, len(entries))
	}
}

// 目标名被一个同名**目录**占着时要换序号，不能直接失败。
//
// os.IsExist 认不出 Windows 的 "is a directory"，而这种情况很现实：
// 远端有个叫 logs 的文件，本地下载目录里正好有个 logs 目录。
func TestCreateExclusiveDirectoryConflict(t *testing.T) {
	dir := testDir(t)
	if err := os.Mkdir(filepath.Join(dir, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, p, err := createExclusive(dir, "logs")
	if err != nil {
		t.Fatalf("同名目录占着时应换序号，得到: %v", err)
	}
	f.Close()
	if filepath.Base(p) == "logs" {
		t.Errorf("不该用被目录占着的名字: %q", p)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("换名后的文件应存在: %v", err)
	}
	if st, err := os.Stat(filepath.Join(dir, "logs")); err != nil || !st.IsDir() {
		t.Error("原来的目录不该被动")
	}
}

func TestSaveTextToDir(t *testing.T) {
	dir := filepath.Join(testDir(t), "downloads") // 故意用还不存在的目录

	saved, err := SaveTextToDir(dir, "报告.html", "<html>核查</html>")
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if filepath.Dir(saved) != dir {
		t.Errorf("应写在指定目录里，得到 %q", saved)
	}
	b, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if string(b) != "<html>核查</html>" {
		t.Errorf("内容不一致: %q", string(b))
	}

	// 同名不覆盖，换名保存
	second, err := SaveTextToDir(dir, "报告.html", "第二份")
	if err != nil {
		t.Fatalf("第二次保存失败: %v", err)
	}
	if second == saved {
		t.Fatal("同名文件不该被覆盖")
	}
	if b, _ := os.ReadFile(saved); string(b) != "<html>核查</html>" {
		t.Error("第一份的文件被改掉了")
	}

	// 目录为空要报错，而不是写到不知道哪里去
	if _, err := SaveTextToDir("", "a.txt", "x"); err == nil {
		t.Error("空目录应报错")
	}
	if _, err := SaveTextToDir("   ", "a.txt", "x"); err == nil {
		t.Error("只有空白的目录应报错")
	}

	// 文件名想穿越也出不去：结果必须仍在下载目录里
	escaped, err := SaveTextToDir(dir, "../../../pwn.txt", "x")
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if filepath.Dir(escaped) != dir {
		t.Errorf("文件应仍落在下载目录里，得到 %q", escaped)
	}
	// 逐个检查上级目录里没有多出 pwn.txt
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "pwn.txt")); err == nil {
		t.Errorf("文件被写到下载目录之外: %s", filepath.Join(filepath.Dir(dir), "pwn.txt"))
	}

	// 超长名应截断后落盘
	longSaved, err := SaveTextToDir(dir, strings.Repeat("b", 300)+".csv", "x")
	if err != nil {
		t.Fatalf("超长名保存失败: %v", err)
	}
	if n := len(filepath.Base(longSaved)); n > 200 {
		t.Errorf("文件名应被截断，实际 %d", n)
	}
}
