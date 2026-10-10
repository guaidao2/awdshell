package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 这一组测试守的是 @@OK / @@EMPTY / @@NO 这套标记机制：它要把**三件不同的事**
// 分开表达，而不是两件。
//
//	@@OK     命令跑通了，而且真的有输出
//	@@EMPTY  命令跑通了，但输出就是空的（真的是空，不是没采到）
//	@@NO     命令不存在 / 不认这些参数（没采到）
//
// 改回"只有 @@OK/@@NO 两态"会红：PROCCOUNT 会把一个假的 0 报成正常值，
// 而 SS 会把"这台机器确实没有监听"报成"未采集到"。

// TestMarkerDistinguishesThreeStates 直接钉住三种标记的解析结果。
func TestMarkerDistinguishesThreeStates(t *testing.T) {
	out := strings.Join([]string{
		"@@STAT", "cpu  100 0 50 1000 20 0 5 0 0 0",
		"@@MEM", "MemTotal:       16384000 kB",
		"@@PROCCOUNT", "@@OK", "128",
		"@@SS", "@@EMPTY",
		"@@CONN", "@@NO",
		"@@END",
	}, "\n")

	s, missing := ParseDetailed(out)

	if s.ProcTotal != 128 || !s.ProcTotalValid {
		t.Errorf("@@OK 段应当被解析成 128，得到 %d（valid=%v）", s.ProcTotal, s.ProcTotalValid)
	}
	if hasStr(missing, "PROCCOUNT") {
		t.Errorf("@@OK + 有数据不该出现在 Missing 里：%v", missing)
	}
	// @@EMPTY：命令跑通了、就是空的 —— **不能**算缺失，否则用户会去查
	// "为什么没采到"，而真相是这台机器确实什么也没监听。
	if hasStr(missing, "SS") {
		t.Errorf("@@EMPTY 表示'确实是空'，不该进 Missing：%v", missing)
	}
	if len(s.Listeners) != 0 {
		t.Errorf("@@EMPTY 段的列表应当是空的，得到 %+v", s.Listeners)
	}
	// @@NO：命令不在，必须如实记成缺失
	if !hasStr(missing, "CONN") {
		t.Errorf("@@NO 应当进 Missing，实际 %v", missing)
	}
	if firstMarker("@@"+"NO") != markerNo {
		t.Error("@@NO 必须仍然可识别（新增 @@EMPTY 时最容易把它一起覆盖掉：那会让" +
			"'命令不存在'被当成陌生段名、段体里留着 '@@NO'，两边都失真）")
	}
	if !s.Collected {
		t.Errorf("STAT/MEM 都在，Collected 应为 true（missing=%v）", missing)
	}
}

// TestScriptThreeStateMarker 守"脚本真的会打这三种标记"。
//
// 上面那条测的是**解析端**；这条测的是**脚本端**（同属第 2 条要求）：
// 解析端认得 @@EMPTY、而脚本从来不打它，等于没修。
//
// 为什么这里只能查文本：本机的 sh（Git-Bash / MSYS）把 /usr/bin 固定在搜索顺序
// 前面，`command -v ps` 永远命中 /usr/bin/ps，替身目录压不住它（实测），
// 所以没法在本机真的造出"ps 跑通但零输出"。脚本的**行为**由
// TestScriptMarksDfFallbackAsOK / TestScriptProcCountAcceptsFallbackWithData
// 用替身验证（那两个只依赖替身**先**被命中，实测可行）。
func TestScriptThreeStateMarker(t *testing.T) {
	for _, m := range []string{markerYes, markerEmpty, markerNo} {
		if !strings.Contains(Script, `echo "`+m+`"`) {
			t.Errorf("脚本里从来没有打出过 %s —— 三态缺一态，解析端认得也没用", m)
		}
		if firstMarker(m) != m {
			t.Errorf("解析端认不出脚本会打的标记 %s", m)
		}
	}
	// @@EMPTY 必须至少出现在那两个"确实可能为空"的段落里（进程数与进程列表）
	if n := strings.Count(Script, `echo "`+markerEmpty+`"`); n < 2 {
		t.Errorf("@@EMPTY 只出现 %d 次 —— PROCCOUNT 与 PS 都该有'确实是空'这个出口", n)
	}
	// PROCCOUNT 必须先确认命令真的跑出了东西（老版本是 `ps -e --no-headers | wc -l`，
	// 对失败的命令照样输出 0 → 一个"成功的 0"）。这条把"有意图的边界"钉住：
	// 把判据换回 wc -l / tr 就会红。
	proc := scriptCode("PROCCOUNT", "CONN")
	if !strings.Contains(proc, "grep -c .") {
		t.Errorf("PROCCOUNT 段没有'先确认有非空输出'的判据（grep -c .）：%q", proc)
	}
	if strings.Contains(proc, "wc -l") {
		t.Errorf("PROCCOUNT 又回到了 wc -l —— 命令失败时它会给出一个假的 0：%q", proc)
	}
}

// TestProcCountFalseZeroIsMissing 守低 1：假的 0 不能当真的 0。
//
// 改回错误版本会红：BusyBox 上 `ps -e --no-headers` 失败、stdout 空，
// 而 `wc -l` 照样输出 0 —— 脚本打 @@OK + 0，解析端于是给出 ProcTotal=0
// 且 ProcTotalValid=true，界面上写着"0 个进程"，看起来是一次正常采样。
// 现在脚本必须先确认命令真跑出东西（grep -c .）才敢打 @@OK，空则打 @@EMPTY；
// 解析端把 @@EMPTY 的 ProcTotal 标成"无效"（服务层据此给前端 -1）。
func TestProcCountFalseZeroIsMissing(t *testing.T) {
	out := strings.Join([]string{
		"@@STAT", "cpu  100 0 50 1000 20 0 5 0 0 0",
		"@@MEM", "MemTotal:       16384000 kB",
		"@@PROCCOUNT", "@@EMPTY",
		"@@END",
	}, "\n")

	s, _ := ParseDetailed(out)
	if s.ProcTotalValid {
		t.Error("@@EMPTY 时进程总数是'不知道'，不能被标成有效（界面会画成 0 个进程）")
	}
	if s.ProcTotal != 0 {
		t.Errorf("@@EMPTY 时不该凭空给出总数，得到 %d", s.ProcTotal)
	}
	if !s.Collected {
		t.Errorf("STAT/MEM 完好时 Collected 仍应为 true（PROCCOUNT 是可选段）")
	}
}

// TestProcCountNoIsMissing 守"命令不存在时进 Missing"。
func TestProcCountNoIsMissing(t *testing.T) {
	out := strings.Join([]string{
		"@@STAT", "cpu  100 0 50 1000 20 0 5 0 0 0",
		"@@MEM", "MemTotal:       16384000 kB",
		"@@PROCCOUNT", "@@NO",
		"@@END",
	}, "\n")

	s, missing := ParseDetailed(out)
	if s.ProcTotalValid {
		t.Error("@@NO 时进程总数不能标成有效")
	}
	if !hasStr(missing, "PROCCOUNT") {
		t.Errorf("@@NO 的 PROCCOUNT 必须进 Missing，实际 %v", missing)
	}
}

// TestOptionalSectionEmptyBodyStillMissing 守"没有标记、段体又空"仍算缺失。
//
// 这一条与 TestMarkerDistinguishesThreeStates 是**互补**的：@@EMPTY 是"命令在、
// 确实是空"，而没有标记的空段体（脚本没跑到 / 命令被 2>/dev/null 吞了）必须仍然是
// "没采到"。两者混起来就会把"没采到"静默成"真的是 0"。
func TestOptionalSectionEmptyBodyStillMissing(t *testing.T) {
	out := "@@STAT\ncpu  100 0 50 1000 20 0 5 0 0 0\n@@MEM\nMemTotal: 100 kB\n@@SS\n@@END\n"
	_, missing := ParseDetailed(out)
	if !hasStr(missing, "SS") {
		t.Errorf("空段体且没有 @@EMPTY 标记时应当算缺失，实际 %v", missing)
	}
}

// TestUnknownSectionIsReported 守低 3：白名单外的段名不能静默并进上一段。
//
// 改回错误版本会红：以前 `@@NEWSEC` 那一行留在段体里、内容并进 STAT，
// 解析结果里看不出任何异常 —— 脚本以后新增段名而白名单没同步时，
// 用户会看到一列诡异的数据，而且没人知道它是怎么来的。
func TestUnknownSectionIsReported(t *testing.T) {
	out := strings.Join([]string{
		"@@STAT", "cpu  100 0 50 1000 20 0 5 0 0 0",
		"@@NEWSEC", "1.2.3.4 evil",
		"@@MEM", "MemTotal:       16384000 kB",
		"@@END",
	}, "\n")

	s, _ := ParseDetailed(out)
	if len(s.Problems) == 0 {
		t.Fatal("出现未知段名 @@NEWSEC 时应当记一条 Problems，实际一条都没有")
	}
	joined := strings.Join(s.Problems, " | ")
	if !strings.Contains(joined, "NEWSEC") {
		t.Errorf("Problems 里要点名是哪个段名，实际 %v", s.Problems)
	}
	// 行为本身不变：内容仍并进上一段（这里不改已有解析结果）
	if s.CPU.Total() == 0 {
		t.Error("已知段 STAT 的解析结果不该被这条提示影响")
	}
}

// TestUnparsedSectionReportedAsProblem 守"命令跑通了、但解析端一条都没提出东西"。
//
// 这一段是 @@OK，所以它**不该**进 Missing（数据确实采到了），但也不能一声不吭 ——
// 空表在界面上与"这台机器确实没有监听"长得一模一样。
func TestUnparsedSectionReportedAsProblem(t *testing.T) {
	out := strings.Join([]string{
		"@@STAT", "cpu  100 0 50 1000 20 0 5 0 0 0",
		"@@MEM", "MemTotal:       16384000 kB",
		"@@SS", "@@OK", "Netid State Recv-Q Send-Q Local",
		"@@END",
	}, "\n")

	s, missing := ParseDetailed(out)
	if hasStr(missing, "SS") {
		t.Errorf("SS 打了 @@OK，不该算缺失（数据是采到的）：%v", missing)
	}
	if len(s.Problems) == 0 {
		t.Fatal("@@OK 但一条监听都解析不出来，应当记进 Problems")
	}
	if !strings.Contains(strings.Join(s.Problems, " | "), "SS") {
		t.Errorf("Problems 要点名是哪一段，实际 %v", s.Problems)
	}
}

// TestScriptMarksDfFallbackAsOK 守住低 4：DF 退回分支有数据就不许标缺失。
//
// 这一条用真 shell 跑脚本（有 POSIX shell 才跑，没有就跳过），
// 把 df 换成一个"只认 -P、不认 -B1"的替身 —— 正是 BusyBox 的行为。
// 判据是脚本必须打出 @@OK，而不是 @@NO。
func TestScriptMarksDfFallbackAsOK(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}

	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// BusyBox 风格的 df：`-P -B1` 不认（退出码非 0），`-P` 正常输出。
	// 注意 -P 的输出保留表头，与真实 df 一致。
	dfScript := "#!/bin/sh\nfor a in \"$@\"; do\n  case \"$a\" in\n    -B1|--block-size=1) exit 1;;\n  esac\ndone\n" +
		"printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'\n" +
		"printf '/dev/sda1 102400 51200 51200 50%% /\\n'\n"
	dfPath := filepath.Join(bin, "df")
	if err := os.WriteFile(dfPath, []byte(dfScript), 0o755); err != nil {
		t.Fatal(err)
	}

	out := runScript(t, findPOSIXShell(), bin)
	if !strings.Contains(out, "@@DF") {
		t.Fatal("脚本输出里没有 @@DF 段")
	}
	body := sectionBody(out, "DF")
	if !strings.HasPrefix(body, "@@OK") {
		t.Errorf("df -B1 不可用但 df -P 有数据时应当打 @@OK，实际段体开头是 %q", firstLine(body))
	}
	s, missing := ParseDetailed(out)
	if hasStr(missing, "DF") {
		t.Errorf("退回分支有数据，DF 不该算缺失：%v", missing)
	}
	if len(s.Disks) == 0 {
		t.Error("退回分支的 df -P 输出应当能被解析出挂载点")
	}
}

// TestScriptProcCountAcceptsFallbackWithData 守脚本里 PROCCOUNT 的"先确认有数据"。
//
// 用替身 ps 扮演 BusyBox：`--no-headers` 不认（退出码非 0、无输出），
// 但 `ps -e` 有输出。判据是脚本必须打 @@OK 并给出一个 >0 的数 ——
// 假的 0 就是从"`wc -l` 对空输出照样给 0"来的。
func TestScriptProcCountAcceptsFallbackWithData(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	psScript := "#!/bin/sh\nfor a in \"$@\"; do\n" +
		"  case \"$a\" in --no-headers) exit 1;; esac\ndone\n" +
		"printf '  PID TTY          TIME CMD\\n'\n" +
		"printf '    1 ?        00:00:01 init\\n'\n"
	if err := os.WriteFile(filepath.Join(bin, "ps"), []byte(psScript), 0o755); err != nil {
		t.Fatal(err)
	}

	out := runScript(t, shell, bin)
	body := sectionBody(out, "PROCCOUNT")
	if !strings.HasPrefix(body, "@@OK") {
		t.Fatalf("ps -e 有输出时应当打 @@OK，实际段体开头是 %q", firstLine(body))
	}
	s, missing := ParseDetailed(out)
	if hasStr(missing, "PROCCOUNT") {
		t.Errorf("有数据时不该进 Missing：%v", missing)
	}
	if !s.ProcTotalValid || s.ProcTotal <= 0 {
		t.Errorf("应当给出一个有效的进程数，实际 total=%d valid=%v", s.ProcTotal, s.ProcTotalValid)
	}
}

// TestScriptMarkerSectionsCheckCommandExists 是一条**文本契约**测试：
// 每一个会打 @@EMPTY/@@NO 的段落，都必须先问过 `command -v`。
//
// 为什么只能查文本：Git-Bash / MSYS 的 sh 固定把 /usr/bin 挂在 PATH 后头，
// 而且 shell 函数也会被 `command -v` 认成"命令存在"（实测），
// 所以在本机没法真的模拟"这台机器没有 df/ss"。三态本身的语义由
// TestMarkerDistinguishesThreeStates 那一组在解析层钉住。
func TestScriptMarkerSectionsCheckCommandExists(t *testing.T) {
	cases := []struct{ section, cmd string }{
		{"DF", "df"}, {"PS", "ps"}, {"PROCCOUNT", "ps"}, {"CONN", "ss"}, {"SS", "ss"},
	}
	for _, c := range cases {
		// 脚本里的段头形态是 echo "@@NAME"（末尾没有换行，所以不能直接找 "@@NAME\n"）
		head := `echo "@@` + c.section + `"`
		i := strings.Index(Script, head)
		if i < 0 {
			t.Errorf("脚本里找不到 %s 段的输出语句（%s）", c.section, head)
			continue
		}
		// 取该段往下若干行（跳过注释），必须出现 command -v <cmd>
		rest := Script[i+len(head):]
		lines := strings.Split(rest, "\n")
		code := make([]string, 0, 4)
		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(l), "#") {
				continue
			}
			code = append(code, l)
			if len(code) == 4 {
				break
			}
		}
		window := strings.Join(code, "\n")
		if !strings.Contains(window, "command -v "+c.cmd) {
			t.Errorf("%s 段没有先用 command -v %s 判存在性，无法区分'命令不在'与'确实是空'："+
				"窗口内容 %q", c.section, c.cmd, window)
		}
		if !strings.Contains(Script[i:], "@@NO") {
			t.Errorf("%s 段没有任何 @@NO 分支 —— 命令不存在时会被报成'确实是空'", c.section)
		}
	}
}

// scriptSection 取采集脚本里 @@name 与 @@next 两段之间的**脚本文本**
// （注意不是 sectionBody：那个解析的是脚本的**输出**）。
func scriptSection(name, next string) string {
	i := strings.Index(Script, `echo "@@`+name+`"`)
	if i < 0 {
		return ""
	}
	rest := Script[i:]
	if j := strings.Index(rest, `echo "@@`+next+`"`); j >= 0 {
		return rest[:j]
	}
	return rest
}

// scriptCode 与 scriptSection 相同，但**去掉注释行** —— 判据要看真正的代码，
// 否则注释里提到 "wc -l" 就会让"回去用 wc -l"的检查自己误报。
func scriptCode(name, next string) string {
	var out []string
	for _, l := range strings.Split(scriptSection(name, next), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// findPOSIXShell 找一个能跑 sh 脚本的解释器；找不到返回空串（测试跳过）。
func findPOSIXShell() string {
	for _, p := range []string{
		`C:\Users\guaidao2\AppData\Local\hermes\git\bin\bash.exe`,
		"/bin/sh", "/usr/bin/sh", "sh",
	} {
		if p == "" {
			continue
		}
		if abs, err := exec.LookPath(p); err == nil {
			return abs
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// runScript 在给定了 PATH 的环境里跑采集脚本，返回 stdout。
func runScript(t *testing.T, shell, bin string) string {
	t.Helper()
	cmd := exec.Command(shell, "-c", Script)
	// 只留替身目录 + 系统目录：脚本要用的 grep/cat/head/uname/date 得在，
	// 而 ss/netstat/df/ps 要被"卸载"掉。
	cmd.Env = append(os.Environ(), "PATH="+bin+";/usr/bin:/bin")
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		out, err = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("采集脚本跑超时")
	}
	if err != nil {
		t.Fatalf("跑采集脚本失败: %v（输出 %q）", err, string(out))
	}
	return string(out)
}

// sectionBody 取 @@NAME 段的段体（到下一个 @@ 段名为止），用来断言标记。
func sectionBody(out, name string) string {
	lines := strings.Split(out, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "@@"+name {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return ""
	}
	var body []string
	for _, l := range lines[start:] {
		if strings.HasPrefix(l, "@@") && sectionNames[strings.TrimSpace(strings.TrimPrefix(l, "@@"))] {
			break
		}
		body = append(body, l)
	}
	return strings.Join(body, "\n")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
