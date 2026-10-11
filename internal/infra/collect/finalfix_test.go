package collect

import (
	"fmt"
	"strings"
	"testing"
)

// 这一组守终审报告里的 M2：脚本级测试的替身必须**真的在跑**。
//
// 背景：那些测试原来是"把替身文件放进 PATH 靠前的目录"来替换 ss/netstat/df。
// 终审实测这个手法在本机不生效：git-bash 启动时把 /mingw64/bin:/usr/bin 插到
// PATH 最前面，替身永远轮不到（`command -v df` → /usr/bin/df），而本机恰好既没有
// ss 也没有 netstat。结果是这些测试拿**真工具**凑出了期望值 —— 在本机能抓到一部分
// 回归，换到装了 ss/netstat 的机器上就变成与实现无关的假绿/假红。
//
// 修法：runScript 改成用 shell 函数覆盖同名命令（函数优先于 PATH，见
// stubFunctionDefs）。这条测试就是那件事的判据：替身给出**真命令不可能给出**的
// 输出，只要有一个没出现，就说明又被真命令盖住了。

// TestScriptStubsReallyOverrideRealCommands 守 M2：脚本输出的内容必须来自替身。
//
// 改回错误版本会红（两种改法都红）：
//   - 把 runScript 退回"只靠 PATH 放替身"：本机的 df 是真 GNU df，
//     `/stub-mounted-here` 这个只存在于测试里的挂载点不会出现在输出里；
//   - 把 stubFunctionDefs 里的函数去掉/改名：同上，真命令不会被覆盖。
func TestScriptStubsReallyOverrideRealCommands(t *testing.T) {
	shell := findPOSIXShell()
	if shell == "" {
		t.Skip("本机没有可用的 POSIX shell，跳过脚本级验证")
	}

	// df 替身：只报测试自己的挂载点（真 df 报的是这台机器的真实分区）。
	bin := writeStub(t, "df", stubPrintf(
		"Filesystem 1-blocks Used Available Capacity Mounted on",
		"/dev/stub-disk 100 50 50 50% /stub-mounted-here"))

	// ss 替身：只报测试自己的连接与监听（真 ss 报的是这台机器的连接表）。
	// `-tunlp` 形态（带 l）多给一行监听 —— 与真实 ss 的参数语义一致。
	writeStubInto(t, bin, "ss",
		"case \"$*\" in\n"+
			"  *l*) printf '%s\\n' 'tcp LISTEN 0 4096 0.0.0.0:2222 0.0.0.0:* users:((\"stublisten\",pid=2,fd=4))';;\n"+
			"esac\n"+
			"printf '%s\\n' 'ESTAB 0 0 10.9.9.9:1234 10.9.9.8:4321 users:((\"stubonly\",pid=1,fd=3))'\n"+
			"exit 0\n")

	// netstat 不给替身：它必须绝无可能被跑到（本机没有，但别的机器有）。
	out := runScript(t, shell, bin)

	if !strings.Contains(out, "/stub-mounted-here") {
		t.Errorf("DF 段不是 df 替身给的（真命令盖住了替身）：%q", sectionBody(out, "DF"))
	}
	if !strings.Contains(out, "stubonly") || !strings.Contains(out, "stublisten") {
		t.Errorf("CONN/SS 段不是 ss 替身给的（真命令盖住了替身）：CONN=%q SS=%q",
			sectionBody(out, "CONN"), sectionBody(out, "SS"))
	}

	s, missing := ParseDetailed(out)

	if len(s.Disks) != 1 || s.Disks[0].Mount != "/stub-mounted-here" {
		t.Errorf("df 替身的挂载点没被解析出来：%+v", s.Disks)
	}
	if len(s.Conns) != 1 {
		t.Fatalf("ss 替身的连接没被解析出来：%+v", s.Conns)
	}
	if s.Conns[0].Process != "stubonly" || s.Conns[0].LPort != 1234 || s.Conns[0].RPort != 4321 {
		t.Errorf("ss 替身的连接内容不对：%+v", s.Conns[0])
	}
	if len(s.Listeners) != 1 || s.Listeners[0].Port != 2222 || s.Listeners[0].Process != "stublisten" {
		t.Errorf("ss 替身的监听没被解析出来：%+v", s.Listeners)
	}

	// 三段的标记都必须是"采到了"：替身给了数据，就不该落到 Missing
	for _, name := range []string{"DF", "CONN", "SS"} {
		if hasStr(missing, name) {
			t.Errorf("%s 段拿到了替身的数据，不该算缺失：%v", name, missing)
		}
	}
}

// stubPrintf 把若干行拼成 `printf '%s\n' '行1' '行2'` 形态的替身体。
func stubPrintf(lines ...string) string {
	return fmt.Sprintf("printf '%%s\\n' %s\n", shellQuoteLines(strings.Join(lines, "\n")))
}
