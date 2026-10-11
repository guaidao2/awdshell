package compliance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 这一组固化 review43 里 compliance 的那条修复（中2），断言写成"改回错误版本会红"。
//
// 判定侧（model.go）与命令侧（checks/*.yaml）都要验：只验一边的话，
// "命令还是 `grep` 退出 1 → RunOutput 返回 ExitError → 判定提前 return"
// 这条链路照样是断的。

// rev43Shell 找一个能跑 sh 的解释器；找不到返回空串（测试跳过）。
func rev43Shell() string {
	for _, p := range []string{
		`C:\Users\guaidao2\AppData\Local\hermes\git\bin\bash.exe`,
		"/bin/sh", "/usr/bin/sh", "sh",
	} {
		if abs, err := exec.LookPath(p); err == nil {
			return abs
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// rev43Scratch 给这条测试开一个工作区内的临时目录。
//
// 按工作区纪律，临时文件不落系统临时目录：优先用 <工作区>/.tmp/revfix2 下
// 的独立目录，建不出来（只读检出等）才退回 t.TempDir()。
func rev43Scratch(t *testing.T) string {
	t.Helper()
	ws := filepath.Join("..", "..", "..", ".tmp", "revfix2")
	if err := os.MkdirAll(ws, 0o755); err == nil {
		dir, err := os.MkdirTemp(ws, "compliance-"+strconv.Itoa(os.Getpid())+"-")
		if err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			return dir
		}
	}
	return t.TempDir()
}

// runRev43Cmd 用 POSIX shell 跑一条检查命令，返回 (stdout, 退出码)。
func runRev43Cmd(t *testing.T, shell, cmd string) (string, int) {
	t.Helper()
	out, err := exec.Command(shell, "-c", cmd).Output()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("跑命令失败: %v", err)
		}
	}
	return string(out), code
}

// rev43Redirect 把命令里的绝对路径换成测试自己控制的路径。
//
// 替换顺序有讲究：先换长的（/etc/sudoers.d），否则 /etc/sudoers 会把它的前缀吃掉。
func rev43Redirect(cmd string, repl [][2]string) string {
	for _, r := range repl {
		cmd = strings.ReplaceAll(cmd, r[0], r[1])
	}
	return cmd
}

// rev43Builtin 取一条内置检查项（找不到就 Fatal）。
func rev43Builtin(t *testing.T, id string) Check {
	t.Helper()
	sets, problems, err := LoadSets()
	if err != nil {
		t.Fatalf("LoadSets 失败: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("内置检查项应当全部合法，problems=%v", problems)
	}
	for _, c := range AllChecks(sets) {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("找不到内置检查项 %s", id)
	return Check{}
}

// rev43RootChecks 是这轮受影响的 4 条：都要 root 才能读到结果。
//
// findings 是"真有问题"时的输出（用来钉住"不能因为加了 needs_root 就放过"）。
func rev43RootChecks() []struct {
	id      string
	finding string
} {
	return []struct {
		id      string
		finding string
	}{
		// 空口令账号：awk 打出来的第一列就是账号名，pattern \S 命中即 fail
		{"CHK-ID-002", "baduser"},
		// NOPASSWD 文本
		{"CHK-AC-005", `%adm ALL=(ALL) NOPASSWD: ALL`},
		// NOPASSWD + 危险程序
		{"CHK-PE-002", `root ALL=(ALL) NOPASSWD: /bin/find`},
		// env_keep 保留了可劫持的变量
		{"CHK-PE-006", `Defaults env_keep += "LD_PRELOAD"`},
	}
}

// TestRev43NeedsRootChecksReportReadability 守 中2：这 4 条要能给出三种结论，
// 而且命令侧必须先能"正常退出"。
//
// 改回错误版本会红：老命令（`grep … 2>/dev/null`，无 `|| true`）在没有匹配时
// 退出码为 1，RunOutput 返回 ExitError，Evaluate 在 err != nil 处就返回
// "检查命令执行失败：exit status 1" —— 干净 + root 的机器上这 4 条从来没 pass 过；
// 而"非 root 读不到"与"读到了、确实是空"在输出上分不开（needs_root 的空输出
// 兜底在 err != nil 之后，是死代码）。
func TestRev43NeedsRootChecksReportReadability(t *testing.T) {
	shell := rev43Shell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过命令级验证")
	}
	dir := rev43Scratch(t)

	sudoers := filepath.Join(dir, "sudoers")
	sudoersD := filepath.Join(dir, "sudoers.d")
	shadow := filepath.Join(dir, "shadow")
	missing := filepath.Join(dir, "nope", "x")

	if err := os.MkdirAll(sudoersD, 0o755); err != nil {
		t.Fatal(err)
	}
	// root + 干净的系统：sudoers 只有常规配置，shadow 里账号都有口令
	clean := "Defaults env_reset\nDefaults secure_path=\"/usr/sbin:/usr/bin:/sbin:/bin\"\nroot ALL=(ALL:ALL) ALL\n"
	if err := os.WriteFile(sudoers, []byte(clean), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadow, []byte("root:$6$abc:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	toSlash := func(p string) string { return filepath.ToSlash(p) }
	repl := [][2]string{
		{"/etc/sudoers.d", "'" + toSlash(sudoersD) + "'"},
		{"/etc/sudoers", "'" + toSlash(sudoers) + "'"},
		{"/etc/shadow", "'" + toSlash(shadow) + "'"},
	}
	// 读不到的情形：4 条命令指向不存在的文件（等价于非 root 登录读 0440 的 sudoers）
	replDenied := [][2]string{
		{"/etc/sudoers.d", "'" + toSlash(missing) + "'"},
		{"/etc/sudoers", "'" + toSlash(missing) + "'"},
		{"/etc/shadow", "'" + toSlash(missing) + "'"},
	}

	for _, rc := range rev43RootChecks() {
		chk := rev43Builtin(t, rc.id)

		// ① root + 干净：命令退出码必须是 0（否则判定端只会看到 ExitError）
		out, code := runRev43Cmd(t, shell, rev43Redirect(chk.Command, repl))
		if code != 0 {
			t.Errorf("%s：干净系统上命令退出码 %d（老命令在这里就死掉了，判定端只会看到 ExitError）：%q", rc.id, code, out)
		}
		if strings.Contains(out, markerReadDenied) {
			t.Errorf("%s：文件可读却报了读取被拒：%q", rc.id, out)
		}
		if r := Evaluate(chk, out, nil); r.Status != StatusPass {
			t.Errorf("%s：干净 + root 应当判 pass，实际 %s（%s）", rc.id, r.Status, r.Detail)
		}

		// ② 非 root（读不到）：必须 error 并说明需要 root，绝不判合规
		out, code = runRev43Cmd(t, shell, rev43Redirect(chk.Command, replDenied))
		if code != 0 {
			t.Errorf("%s：读不到时命令也必须以 0 退出（否则判定端拿到的是 ExitError）：%q", rc.id, out)
		}
		if !strings.Contains(out, markerReadDenied) {
			t.Errorf("%s：读不到时命令必须报 %s，实际输出 %q", rc.id, markerReadDenied, out)
		}
		r := Evaluate(chk, out, nil)
		if r.Status != StatusError {
			t.Errorf("%s：读不到时应当标 error，实际 %s（%s）", rc.id, r.Status, r.Detail)
		}
		if !strings.Contains(r.Detail, "root") {
			t.Errorf("%s：错误说明里要写清「需要 root」：%s", rc.id, r.Detail)
		}
		if strings.Contains(r.Output, markerReadOK) || strings.Contains(r.Output, markerReadDenied) {
			t.Errorf("%s：可读性标记是内部管线，不该出现在给用户看的输出里：%q", rc.id, r.Output)
		}

		// ③ 真有问题：仍然 fail（加了 needs_root 不能把真问题放过）
		if err := os.WriteFile(sudoers, []byte(rc.finding+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if rc.id == "CHK-ID-002" {
			if err := os.WriteFile(shadow, []byte(rc.finding+"::19000:0:99999:7:::\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		out, code = runRev43Cmd(t, shell, rev43Redirect(chk.Command, repl))
		if code != 0 {
			t.Errorf("%s：有发现时命令也应正常退出，实际 %d（%q）", rc.id, code, out)
		}
		if r := Evaluate(chk, out, nil); r.Status != StatusFail {
			t.Errorf("%s：命中时应当判 fail，实际 %s（输出 %q，说明 %s）", rc.id, r.Status, out, r.Detail)
		}

		// 复原成干净内容，供下一条
		if err := os.WriteFile(sudoers, []byte(clean), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(shadow, []byte("root:$6$abc:19000:0:99999:7:::\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRev43BuiltinRootChecksDeclareReadability 是命令侧的静态断言：
// 4 条命令都要自报可读性、都要把退出码压成 0、都保留 needs_root 且不带管道收尾。
func TestRev43BuiltinRootChecksDeclareReadability(t *testing.T) {
	for _, rc := range rev43RootChecks() {
		chk := rev43Builtin(t, rc.id)
		if !chk.NeedsRoot {
			t.Errorf("%s：读 /etc/shadow 或 /etc/sudoers 的项必须标 needs_root", rc.id)
		}
		if !strings.Contains(chk.Command, markerReadOK) || !strings.Contains(chk.Command, markerReadDenied) {
			t.Errorf("%s：命令必须自报可读性（%s / %s）：%s", rc.id, markerReadOK, markerReadDenied, chk.Command)
		}
		if !strings.Contains(chk.Command, "|| true") {
			t.Errorf("%s：必须用 `|| true` 把退出码压成 0（否则无匹配时的 ExitError 会让判定提前返回）：%s",
				rc.id, chk.Command)
		}
		if hasShellPipe(chk.Command) {
			t.Errorf("%s：不能用管道收尾（会把 EACCES / 无匹配的退出码换成管道尾部的）：%s", rc.id, chk.Command)
		}
		// pattern 要认得"读取被拒"（判定侧那层处理的双保险）
		if chk.Expect.Pattern == `\S` {
			if !compiledOK(chk.Expect.Pattern) {
				t.Errorf("%s：pattern 编译不过：%s", rc.id, chk.Expect.Pattern)
			}
			continue
		}
		if !strings.Contains(chk.Expect.Pattern, markerReadDenied) {
			t.Errorf("%s：选择性的 pattern 必须同时认 %s：%s", rc.id, markerReadDenied, chk.Expect.Pattern)
		}
	}
}

func compiledOK(pattern string) bool {
	_, err := compiled(pattern)
	return err == nil
}

// TestRev43NeedsRootEmptyOutputIsErrorForAllTypes 守中2 的第 2 步：
// `needs_root && 输出为空` 的兜底必须**对所有判定类型生效且可达**。
//
// 改回错误版本会红：兜底原来只写在 regex_not_match 分支里，而且因为
// "grep 无匹配 → ExitError → 提前 return"永远走不到；contains 空输出恒 fail
// （冤枉一条合规的项）、not_contains 空输出恒 pass（放过一条不合规的项）。
func TestRev43NeedsRootEmptyOutputIsErrorForAllTypes(t *testing.T) {
	types := []string{ExpectRegexMatch, ExpectRegexNotMatch, ExpectContains, ExpectNotContains}
	for _, typ := range types {
		chk := Check{ID: "T-" + typ, NeedsRoot: true, Expect: Expect{Type: typ, Pattern: "x"}}
		r := Evaluate(chk, "", nil)
		if r.Status != StatusError {
			t.Errorf("%s：needs_root 的空输出必须标 error（不能猜成 pass/fail），实际 %s（%s）",
				typ, r.Status, r.Detail)
		}
		if !strings.Contains(r.Detail, "root") {
			t.Errorf("%s：错误说明里要写清需要 root：%s", typ, r.Detail)
		}
	}

	// 不需要 root 的同类检查，空输出语义不变（空 = 没发现问题 → pass）
	plain := Check{ID: "T-plain", Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `\S`}}
	if r := Evaluate(plain, "", nil); r.Status != StatusPass {
		t.Errorf("不需要 root 的检查，空输出应仍判 pass，实际 %s", r.Status)
	}

	// 命令明确说了"读到了"时，空结果就是真的空 —— 干净 + root 的主机必须判 pass
	rooted := Check{ID: "T-ok", NeedsRoot: true, Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `\S`}}
	if r := Evaluate(rooted, markerReadOK+"\n", nil); r.Status != StatusPass {
		t.Errorf("命令报告读到了、输出为空时应当判 pass，实际 %s（%s）", r.Status, r.Detail)
	}
	// 读不到时不允许 pass（fail-open 的那一侧）
	if r := Evaluate(rooted, markerReadDenied+"\n", nil); r.Status == StatusPass {
		t.Error("命令报告读取被拒时绝不能判 pass")
	}
}
