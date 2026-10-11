package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这一组固化 review43 里 collect 的两条修复，断言都写成"改回错误版本会红"。

// netstatStub 生成一个 netstat 替身：
//   - 把收到的参数追加到 argsFile（用来证明 CONN 段带上了 -p）
//   - 按参数形态给不同的输出：含 `u` 的（-tunlp，监听）给 listenLines，
//     否则（-tnp，连接）给 connLines —— 真实 netstat 就是这么分的，
//     两份输出混在一起会让解析端的"连接"里混进监听行。
func netstatStub(argsFile, connLines, listenLines string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "printf '%%s\\n' \"$*\" >> %s\n", shellQuotePath(argsFile))
	b.WriteString("case \"$*\" in\n")
	b.WriteString("  *u*)\n")
	if listenLines != "" {
		fmt.Fprintf(&b, "    printf '%%s\\n' %s\n", shellQuoteLines(listenLines))
	}
	b.WriteString("    ;;\n")
	b.WriteString("  *)\n")
	if connLines != "" {
		fmt.Fprintf(&b, "    printf '%%s\\n' %s\n", shellQuoteLines(connLines))
	}
	b.WriteString("    ;;\n")
	b.WriteString("esac\nexit 0\n")
	return b.String()
}

// shellQuotePath 把路径包成 shell 单引号串。
func shellQuotePath(p string) string {
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

// ssSilentStub 是一个"什么都不给"的 ss 替身：所有形态都空输出、退出码 0。
// 用它把执行路径逼到 netstat 分支（等价于目标机上没有可用的 ss）。
func ssSilentStub() string { return "exit 0\n" }

// 真实样本（与 rev43 复审用的 stubs 一致）
const (
	nsConnHead = "Active Internet connections (w/o servers)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State"
	nsConnHeadData = nsConnHead + "\n" +
		"tcp        0      0 10.0.0.5:22             10.0.0.1:54321          ESTABLISHED"
	nsListenHead = "Active Internet connections (only servers)\n" +
		"Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
	nsListenHeadData = nsListenHead + "\n" +
		"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd"
	ssConnHead = "State      Recv-Q Send-Q Local Address:Port  Peer Address:Port Process"
)

// TestRev43NetstatHeaderOnlyIsEmptyNotOK 守 中4：netstat 回退分支不能拿
// `grep -q .` 判"有数据"。
//
// 改回错误版本会红：netstat 的输出**永远带表头**（"Active Internet connections …"），
// 于是 grep -q . 恒真 —— 实测"没有 ss、netstat 只有表头"（这台机器确实没有连接）
// 被报成 @@CONN @@OK，解析端再给一条"格式不认识"的 Problems，
// 界面画一张空表而用户以为这台机器没有外联；正确的是 @@EMPTY。
func TestRev43NetstatHeaderOnlyIsEmptyNotOK(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// ss 存在但什么都给不出来（等价于目标机上没有可用的 ss）；
	// netstat 两个形态都只给表头（这台机器确实没有连接/监听）。
	writeStubInto(t, bin, "ss", ssSilentStub())
	writeStubInto(t, bin, "netstat",
		netstatStub(filepath.Join(dir, "args"), nsConnHead, nsListenHead))

	out := runScript(t, shell, bin)

	if body := sectionBody(out, "CONN"); !strings.HasPrefix(body, "@@EMPTY") {
		t.Errorf("netstat 只给表头（确实没有连接）时应当报 @@EMPTY，实际 %q", firstLine(body))
	}
	if body := sectionBody(out, "SS"); !strings.HasPrefix(body, "@@EMPTY") {
		t.Errorf("netstat 只给监听表头（确实没有监听）时应当报 @@EMPTY，实际 %q", firstLine(body))
	}

	s, missing := ParseDetailed(out)
	if hasStr(missing, "CONN") || hasStr(missing, "SS") {
		t.Errorf("@@EMPTY 是「跑通了、确实是空」，不该进 Missing：%v", missing)
	}
	for _, p := range s.Problems {
		if strings.Contains(p, "CONN") || strings.Contains(p, "SS") {
			t.Errorf("确实是空时不该报「格式不认识」：%s", p)
		}
	}
}

// TestRev43NetstatWithDataStillOK 是反向保险：真有数据时仍要 @@OK，
// 并且解析端要能提出连接/监听（改判据不能把有数据的机器也判成空）。
func TestRev43NetstatWithDataStillOK(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStubInto(t, bin, "ss", ssSilentStub())
	writeStubInto(t, bin, "netstat", netstatStub(filepath.Join(dir, "args"), nsConnHeadData, nsListenHeadData))

	out := runScript(t, shell, bin)
	if body := sectionBody(out, "CONN"); !strings.HasPrefix(body, "@@OK") {
		t.Fatalf("netstat 有数据时应当报 @@OK，实际 %q", firstLine(body))
	}
	if body := sectionBody(out, "SS"); !strings.HasPrefix(body, "@@OK") {
		t.Fatalf("netstat 有监听时应当报 @@OK，实际 %q", firstLine(body))
	}

	s, _ := ParseDetailed(out)
	if len(s.Conns) != 1 || s.Conns[0].LPort != 22 || s.Conns[0].RPort != 54321 {
		t.Errorf("netstat 形态的连接应被解析出来：%+v", s.Conns)
	}
	if len(s.Listeners) != 1 || s.Listeners[0].Port != 22 {
		t.Errorf("netstat 形态的监听应被解析出来：%+v", s.Listeners)
	}
}

// TestRev43NetstatConnUsesDashP 守 低3：CONN 段的 netstat 必须带 -p。
//
// 改回错误版本会红：脚本用的是 `netstat -tn`（没有 -p），进程名那一列恒为空 ——
// 而"哪个进程在往外连"正是排查外联时最需要的一列。
func TestRev43NetstatConnUsesDashP(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(dir, "args")
	// 带进程名的 netstat 形态（-p 才有这一列）
	connRow := "tcp        0      0 10.0.0.5:22             10.0.0.1:54321          ESTABLISHED 4242/sshd"
	listenRow := "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd"
	writeStubInto(t, bin, "ss", ssSilentStub())
	writeStubInto(t, bin, "netstat",
		netstatStub(argsFile, nsConnHead+"\n"+connRow, nsListenHead+"\n"+listenRow))

	out := runScript(t, shell, bin)
	if body := sectionBody(out, "CONN"); !strings.HasPrefix(body, "@@OK") {
		t.Fatalf("测试前提不成立：CONN 段没走到 netstat 分支（%q）", firstLine(body))
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("替身没被调用（读参数文件失败）：%v", err)
	}
	calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	connCall := ""
	for _, c := range calls {
		if !strings.Contains(c, "u") { // -tunlp（监听）带 u，-tnp（连接）不带
			connCall = c
		}
	}
	if connCall == "" {
		t.Fatalf("没找到 CONN 段的 netstat 调用，实际调用：%v", calls)
	}
	if !strings.Contains(connCall, "p") {
		t.Errorf("CONN 段的 netstat 必须带 -p（否则进程名恒为空），实际调用 %q", connCall)
	}

	// 有 -p 的那一列要真被解析出来
	s, _ := ParseDetailed(out)
	if len(s.Conns) != 1 {
		t.Fatalf("连接没解析出来：%+v", s.Conns)
	}
	if s.Conns[0].Process != "sshd" {
		t.Errorf("netstat -p 的 pid/name 列应被解析成进程名，实际 %q（输出 %+v）",
			s.Conns[0].Process, s.Conns[0])
	}
}

// TestRev43SSSilentlyIgnoringDashHIsEmpty 守中4 的第二个症状：
// ss **静默忽略 -H**、只给表头时也是 @@EMPTY（不是 @@OK）。
//
// 改回错误版本会红：canonical 形态（`ss -tnpH` / `ss -H -tunlp`）判的是
// `grep -q .`，而 "-H 被忽略" 时输出的正是表头 —— 恒真，于是这台**确实没有
// 连接/监听**的机器被报成 @@OK，解析端再给一条"格式不认识"的 Problems。
func TestRev43SSSilentlyIgnoringDashHIsEmpty(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}
	// 所有形态都给表头（-H 被静默忽略）；netstat 不存在
	bin := writeStub(t, "ss", ssStubForHeaderOnly(t))
	writeStubInto(t, bin, "netstat", "exit 1\n")

	out := runScript(t, shell, bin)
	if body := sectionBody(out, "CONN"); !strings.HasPrefix(body, "@@EMPTY") {
		t.Errorf("ss 忽略 -H、只给表头时 CONN 应当报 @@EMPTY，实际 %q", firstLine(body))
	}
	if body := sectionBody(out, "SS"); !strings.HasPrefix(body, "@@EMPTY") {
		t.Errorf("ss 忽略 -H、只给表头时 SS 应当报 @@EMPTY，实际 %q", firstLine(body))
	}
	_, missing := ParseDetailed(out)
	if hasStr(missing, "CONN") || hasStr(missing, "SS") {
		t.Errorf("「跑通了、确实是空」不该进 Missing：%v", missing)
	}
}

// ssStubForHeaderOnly 生成"所有参数形态都只给表头"的 ss 替身。
func ssStubForHeaderOnly(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("printf '%%s\\n' %s\nexit 0\n", shellQuoteLines(ssConnHead))
}

// TestRev43ParsePSKeepsFirstDataLine 守 提示3：表头行靠结构过滤，不靠"跳首行"。
//
// 改回错误版本会红（行为层面）：老实现 `if i == 0 { continue }` 依赖一个隐式契约
// —— 段体第一行一定是表头。契约一旦被破坏（段体没被剥掉标记、或 ps 换了输出形态），
// 第一行**真实进程**会被静默吃掉。表头本来就过不了"字段数 / 首列是数字"两道判据，
// 所以直接不跳更稳。
func TestRev43ParsePSKeepsFirstDataLine(t *testing.T) {
	header := "PID PPID USER %CPU %MEM RSS STAT COMMAND"
	rows := "1 0 root 0.0 0.1 1000 Ss /sbin/init\n" +
		"22 1 root 0.0 0.2 2000 S /usr/sbin/sshd -D"

	got := parsePS(header + "\n" + rows)
	if len(got) != 2 {
		t.Fatalf("表头 + 2 行数据应解析出 2 个进程，实际 %d：%+v", len(got), got)
	}

	// 段体的第一行就是数据行：不能被当成表头丢掉
	got = parsePS("7 1 root 0.0 0.1 512 S sleep 10\n")
	if len(got) != 1 || got[0].PID != 7 {
		t.Errorf("第一行就是数据时不该被跳过（老实现的 i==0 会静默吃掉一行），实际 %+v", got)
	}

	// 表头本身不能变成一条"进程"
	for _, p := range parsePS(header) {
		if p.Comm == "COMMAND" || p.PID == 0 {
			t.Errorf("表头被当成进程解析了：%+v", p)
		}
	}
}
