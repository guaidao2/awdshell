package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这一组守的是 audit44 里 collect 那几条：@@OK1024 的单位、命令失败不再被
// 判成 "@@EMPTY（确实是空）"、netstat 形态的进程名、UPTIME/TZ 的缺失上报。
//
// 每一条都写成"改回错误版本会红"。

// TestParseDFScaledUnit 守 中-4：`df -P`（POSIX 默认）的数字单位是 1024 字节块。
//
// 改回错误版本会红：以前脚本的两个分支都打 @@OK，解析端无从分辨单位，
// 于是 `overlay 2097152 1048576 1048576 50% /`（实际 2 GiB）在界面上画成 2.0 MB
// —— 差 1024 倍，而且是**错误数据**（不是缺失数据），用户看到的是"这块盘要满了"。
func TestParseDFScaledUnit(t *testing.T) {
	const body = "Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
		"overlay 2097152 1048576 1048576 50% /\n"

	// @@OK（df -B1）分支：数字就是字节
	out := "@@STAT\ncpu  1 2 3 4 5 6 7 8 9 0\n@@MEM\nMemTotal: 100 kB\n@@DF\n@@OK\n" + body + "@@END\n"
	s, _ := ParseDetailed(out)
	if len(s.Disks) != 1 {
		t.Fatalf("@@OK 分支应解析出 1 个挂载点，实际 %+v", s.Disks)
	}
	if s.Disks[0].Total != 2097152 {
		t.Errorf("@@OK 分支是字节，不该缩放，得到 %d", s.Disks[0].Total)
	}

	// @@OK1024（df -P 退回）分支：要乘 1024
	out = "@@STAT\ncpu  1 2 3 4 5 6 7 8 9 0\n@@MEM\nMemTotal: 100 kB\n@@DF\n@@OK1024\n" + body + "@@END\n"
	s, _ = ParseDetailed(out)
	if len(s.Disks) != 1 {
		t.Fatalf("@@OK1024 分支应解析出 1 个挂载点，实际 %+v", s.Disks)
	}
	d := s.Disks[0]
	if d.Total != 2097152*1024 {
		t.Errorf("@@OK1024 的数字是 1024 字节块，Total 应是 %d（2 GiB），得到 %d",
			2097152*1024, d.Total)
	}
	if d.Used != 1048576*1024 || d.Avail != 1048576*1024 {
		t.Errorf("Used/Avail 也要按 1024 缩放，实际 used=%d avail=%d", d.Used, d.Avail)
	}
	if d.Percent != 50 {
		t.Errorf("百分比是比值，不该被缩放影响，得到 %v", d.Percent)
	}

	// 解析层直接调用：scale=1024 与 scale=1 只差倍数
	if got := parseDFScaled(body, 1024); len(got) != 1 || got[0].Total != 2097152*1024 {
		t.Errorf("parseDFScaled(body,1024) = %+v", got)
	}
	if got := parseDFScaled(body, 0); len(got) != 1 || got[0].Total != 2097152 {
		t.Errorf("scale=0 应回退成 1（不缩放），实际 %+v", got)
	}
}

// TestParseDFMarkerNotUnknown 守"新增的 @@OK1024 不能被当成未知段名"。
//
// 改回错误版本会红：splitSections 里串了 "name != OK/EMPTY/NO" 的硬编码比较，
// 新标记会被报成一条 Problems（"采集输出里有未知段名 @@OK1024"），
// 而且段体里那行标记还留着。
func TestParseDFMarkerNotUnknown(t *testing.T) {
	out := "@@STAT\ncpu  1 2 3 4 5 6 7 8 9 0\n@@MEM\nMemTotal: 100 kB\n" +
		"@@DF\n@@OK1024\n/dev/sda1 100 50 50 50% /\n@@END\n"
	s, _ := ParseDetailed(out)
	if len(s.Problems) != 0 {
		t.Errorf("@@OK1024 是已知标记，不该产生 Problems：%v", s.Problems)
	}
	if len(s.Disks) != 1 || s.Disks[0].Device != "/dev/sda1" {
		t.Errorf("标记行不该混进数据：%+v", s.Disks)
	}
	// 标记必须真的把单位带进解析（只"认得"标记、不缩放，等于没修）
	if s.Disks[0].Total != 100*1024 {
		t.Errorf("@@OK1024 的数字应乘 1024（100 块 = 102400 字节），得到 %d", s.Disks[0].Total)
	}
	if !isMarker(markerYes1024) {
		t.Error("isMarker 必须认得 @@OK1024，否则它在两处标记判据里都会被误判")
	}
}

// ---------- 脚本级：命令"存在但不认参数"不能报成"确实是空" ----------

// writeStub 在临时目录里写一个可执行替身，返回那个目录。
func writeStub(t *testing.T, name, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStubInto(t, dir, name, body)
	return dir
}

// writeStubInto 往已有的替身目录里再放一个替身（用来把系统里的同名命令压住）。
func writeStubInto(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// ssStub 生成一个"认真认参数"的 ss 替身。
//
//	reject -H ：-H 相关形态以非 0 退出（老 iproute2：认不出来）—— 输出为空
//	emptyH    ：带 -H 的形态空输出（模拟"命令把不认的参数静默忽略"）
//	lines     ：不带 -H 时打印的数据/表头（真数据时用）
//
// 注意 -H 要按"短选项集合里是否含 H"来判（真实的 ss 就是这么解析的，
// 参数是 -tnpH 而不是单独的 -H）。
func ssStub(rejectH bool, emptyH bool, lines string) string {
	var b strings.Builder
	b.WriteString("h=0\nfor a in \"$@\"; do case \"$a\" in -*) case \"$a\" in *H*) h=1;; esac;; esac; done\n")
	if rejectH {
		b.WriteString("[ \"$h\" = 1 ] && { echo 'ss: unrecognized option -H' >&2; exit 1; }\n")
	}
	if emptyH {
		b.WriteString("[ \"$h\" = 1 ] && exit 0\n")
	}
	if lines != "" {
		fmt.Fprintf(&b, "printf '%%s\\n' %s\n", shellQuoteLines(lines))
	}
	b.WriteString("exit 0\n")
	return b.String()
}

// shellQuoteLines 把多行文本变成若干条 printf 参数（单引号包起来）。
func shellQuoteLines(s string) string {
	parts := []string{}
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		parts = append(parts, "'"+strings.ReplaceAll(l, "'", `'\''`)+"'")
	}
	return strings.Join(parts, " ")
}

// TestScriptConnUnsupportedArgsIsNotOK 守 中-6：ss 存在、但**不认 -H 且什么都跑不出来**
// 时，脚本既不能报 @@OK（界面会说"采到了，就是空的"），也不能报 @@EMPTY
// （那是"确实一条连接都没有"），必须报 @@NO。
//
// 改回错误版本会红：老脚本里 ss 与 netstat 都不给数据就落进 `else echo "@@EMPTY"`，
// 实测 `@@DF\n@@EMPTY` 那种输入会让 Missing 里没有它、Problems 为空、列表为空、
// Collected=true —— 界面画一张空表，用户以为这台机器没有外联。
func TestScriptConnUnsupportedArgsIsNotOK(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	bin := writeStub(t, "ss", ssStub(true, false, ""))
	writeStubInto(t, bin, "netstat", "echo 'netstat: unrecognized option' >&2\nexit 1\n")

	out := runScript(t, shell, bin)
	body := sectionBody(out, "CONN")
	if !strings.HasPrefix(body, "@@NO") {
		t.Errorf("命令不认参数、什么都拿不到时应当报 @@NO，实际 %q", firstLine(body))
	}
	_, missing := ParseDetailed(out)
	if !hasStr(missing, "CONN") {
		t.Errorf("@@NO 的 CONN 必须进 Missing，实际 %v", missing)
	}
}

// TestScriptSSUnsupportedArgsIsNotOK 同上，针对监听端口那一段。
func TestScriptSSUnsupportedArgsIsNotOK(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	bin := writeStub(t, "ss", ssStub(true, false, ""))
	writeStubInto(t, bin, "netstat", "echo 'netstat: unrecognized option' >&2\nexit 1\n")

	out := runScript(t, shell, bin)
	body := sectionBody(out, "SS")
	if !strings.HasPrefix(body, "@@NO") {
		t.Errorf("命令不认参数、什么都拿不到时应当报 @@NO，实际 %q", firstLine(body))
	}
	_, missing := ParseDetailed(out)
	if !hasStr(missing, "SS") {
		t.Errorf("@@NO 的 SS 必须进 Missing，实际 %v", missing)
	}
}

// TestScriptConnFallsBackToNonHeaderForm 守"带 -H 的形态拿不到东西时，退回不带 -H
// 的形态仍要拿到数据"。
//
// 改回错误版本会红：老脚本把 `ss -tnpH` 的空输出直接当"确实是空"（@@EMPTY），
// 于是**明明有连接**的机器上连接列表是空的。这里让替身在带 -H 时空输出、
// 不带 -H 时给一条真连接 —— 正是"参数被静默忽略"的形态。
func TestScriptConnFallsBackToNonHeaderForm(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	conn := `ESTAB 0 0 10.0.0.5:22 10.0.0.1:54321 users:(("sshd",pid=1,fd=3))`
	// 带 -H 时什么都不给（参数被静默忽略），不带 -H 时给一条真连接
	bin := writeStub(t, "ss", ssStub(false, true, conn))

	out := runScript(t, shell, bin)
	body := sectionBody(out, "CONN")
	if !strings.HasPrefix(body, "@@OK") {
		t.Fatalf("退回分支拿到数据时应当报 @@OK，实际 %q", firstLine(body))
	}
	s, missing := ParseDetailed(out)
	if hasStr(missing, "CONN") {
		t.Errorf("有数据时 CONN 不该算缺失：%v", missing)
	}
	if len(s.Conns) != 1 || s.Conns[0].Process != "sshd" {
		t.Errorf("退回分支的连接应当被解析出来（含进程名），实际 %+v", s.Conns)
	}
}

// TestScriptConnGenuineEmptyIsEmpty 守"真正的空"仍要报 @@EMPTY 而不是 @@NO。
//
// 反过来也要钉住：ss 跑得动（退出码 0）—— 带 -H 的 canonical 形态什么都不给，
// 不带 -H 的形态给出**表头**但没有一条数据行 —— 这就是"确实是空"。
// 报成 @@NO 会让界面说"未采集到：连接"，把事实说成故障。
func TestScriptConnGenuineEmptyIsEmpty(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	// 表头里没有"地址:端口"，不是数据行
	bin := writeStub(t, "ss", ssStub(false, true, "State Recv-Q Send-Q Local Peer"))

	out := runScript(t, shell, bin)
	body := sectionBody(out, "CONN")
	if !strings.HasPrefix(body, "@@EMPTY") {
		t.Errorf("跑通了但确实没有连接时报 @@EMPTY，实际 %q", firstLine(body))
	}
	_, missing := ParseDetailed(out)
	if hasStr(missing, "CONN") {
		t.Errorf("@@EMPTY 是'确实是空'，不该进 Missing：%v", missing)
	}
}

// TestTrimProcBothForms 守 低-1：netstat 形态下进程名不能恒为空。
//
// 改回错误版本会红：trimProc 只认 ss 的 `users:(("name"…))`，
// BusyBox 目标（没有 ss）上"进程"这一栏永远是空的 —— 排查外联最需要的一列。
func TestTrimProcBothForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{`users:(("nginx",pid=123,fd=6))`, "nginx"},
		{`123/sshd`, "sshd"},
		{`5678/dhclient`, "dhclient"},
		{`-`, ""},       // 内核套接字，没有进程
		{``, ""},        // 空输入
		{`garbage`, ""}, // 认不出来就别编一个
	}
	for _, c := range cases {
		if got := trimProc(c.in); got != c.want {
			t.Errorf("trimProc(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}

	// 监听列表的两种形态都要能拿到进程名
	ss := parseListeners(`tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`)
	if len(ss) != 1 || ss[0].Process != "sshd" {
		t.Errorf("ss 形态的进程名解析错：%+v", ss)
	}
	ns := parseListeners(`tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 123/sshd`)
	if len(ns) != 1 || ns[0].Process != "sshd" {
		t.Errorf("netstat 形态的进程名解析错（老实现恒为空）：%+v", ns)
	}

	// 连接列表的 netstat 形态同样要带出进程名
	conns := parseConns(`tcp 0 0 10.0.0.5:22 10.0.0.1:54321 ESTABLISHED 4242/sshd`)
	if len(conns) != 1 || conns[0].Process != "sshd" {
		t.Errorf("netstat 连接的进程名解析错：%+v", conns)
	}
}

// TestUptimeAndTZCountAsOptionalSections 守 低-4：采不到 UPTIME/TZ 要说出来。
//
// 改回错误版本会红：这两段既不在 criticalSections 也不在 optionalSections，
// 段体缺失时既不进 Missing 也不产生 Problems —— UptimeSec=0 / TimeZone=""
// 静默进界面，看起来像"开机 0 秒、时区为空"这样的真实值。
func TestUptimeAndTZCountAsOptionalSections(t *testing.T) {
	if !hasStr(optionalSections, "UPTIME") || !hasStr(optionalSections, "TZ") {
		t.Fatalf("UPTIME/TZ 必须在 optionalSections 里，实际 %v", optionalSections)
	}
	// 关键段齐了、但没有 UPTIME / TZ 段
	out := "@@STAT\ncpu  1 2 3 4 5 6 7 8 9 0\n@@MEM\nMemTotal: 100 kB\n@@END\n"
	s, missing := ParseDetailed(out)
	if !hasStr(missing, "UPTIME") {
		t.Errorf("没采到 UPTIME 时应当进 Missing，实际 %v", missing)
	}
	if !hasStr(missing, "TZ") {
		t.Errorf("没采到 TZ 时应当进 Missing，实际 %v", missing)
	}
	// 它们是可选段：不影响 Collected
	if !s.Collected {
		t.Errorf("UPTIME/TZ 是可选段，不该把 Collected 拉成 false（missing=%v）", missing)
	}

	// 采到了就不该出现在 Missing 里
	out = "@@STAT\ncpu  1 2 3 4 5 6 7 8 9 0\n@@MEM\nMemTotal: 100 kB\n" +
		"@@UPTIME\n12345.67 9999.0\n@@TZ\nCST\n@@END\n"
	s, missing = ParseDetailed(out)
	if hasStr(missing, "UPTIME") || hasStr(missing, "TZ") {
		t.Errorf("采到了就不该算缺失：%v", missing)
	}
	if s.UptimeSec != 12345.67 || s.TimeZone != "CST" {
		t.Errorf("UPTIME/TZ 的解析结果不对：uptime=%v tz=%q", s.UptimeSec, s.TimeZone)
	}
}
