package sshx

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestStartTerminalActuallyUsesPTYTerminalModes 守"改了函数却没接到调用点"。
//
// 上面两条只测 ptyTerminalModes() 的返回值；把 StartTerminal 里的实参换回旧的
// 几项时它们照样绿（第一次写这个测试就踩了这个坑）—— 所以必须直接查调用点。
func TestStartTerminalActuallyUsesPTYTerminalModes(t *testing.T) {
	src, err := os.ReadFile("terminal.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "RequestPty(termName, rows, cols, ptyTerminalModes())") {
		t.Error("StartTerminal 申请 PTY 时没有用 ptyTerminalModes()：" +
			"改了函数却没接到调用点，交互标志（ICRNL/ISIG/ICANON 等）又会丢，回车变 ^M、Ctrl+C 变 ^C")
	}
}

// ptyRequiredModes 是交互必需的 termios 项：少任何一个，远端终端的按键就会对不上。
//
// 实测（只给 ECHO 时）：回车显示成 ^M 且不生效、Ctrl+C 显示成 ^C 且不中断、
// apt / vim / top 这类交互程序的按键全部异常。
var ptyRequiredModes = []struct {
	name string
	key  byte
	want uint32
}{
	{"VINTR（Ctrl+C）", ssh.VINTR, 3},
	{"VEOF（Ctrl+D）", ssh.VEOF, 4},
	{"VERASE（Backspace）", ssh.VERASE, 127},
	{"ICRNL（回车→换行）", ssh.ICRNL, 1},
	{"IXON", ssh.IXON, 1},
	{"IUTF8", ssh.IUTF8, 1},
	{"ISIG（Ctrl+C 产生信号）", ssh.ISIG, 1},
	{"ICANON（行编辑）", ssh.ICANON, 1},
	{"ECHO", ssh.ECHO, 1},
	{"ECHOE", ssh.ECHOE, 1},
	{"ECHOK", ssh.ECHOK, 1},
	{"IEXTEN", ssh.IEXTEN, 1},
	{"ECHOCTL", ssh.ECHOCTL, 1},
	{"OPOST（输出后处理）", ssh.OPOST, 1},
	{"ONLCR（\\n→\\r\\n）", ssh.ONLCR, 1},
	{"CS8", ssh.CS8, 1},
}

func TestPTYTerminalModesCoverInteractiveKeys(t *testing.T) {
	m := ptyTerminalModes()
	for _, c := range ptyRequiredModes {
		got, ok := m[c.key]
		if !ok {
			t.Errorf("%s 没有显式给出 —— 未列出的项在服务端落到什么值不保证", c.name)
			continue
		}
		if got != c.want {
			t.Errorf("%s 的值不对：got=%d want=%d", c.name, got, c.want)
		}
	}
	// 项数下限：只给 ECHO/速度三项是不够的，这里挡一下"有人又把它删回几项"。
	if len(m) < 25 {
		t.Errorf("modes 只有 %d 项，太少 —— 关键项没显式列出来", len(m))
	}
}

// TestPTYTerminalModesDoNotDependOnServerBaseline 守"不能只给 ECHO"这条判据。
//
// 服务端应用 pty-req 的 modes 时是"列了哪项就覆盖哪项、没列出的保持基线"，而基线
// 在不同 sshd 实现上不保证是完整的 cooked 模式。这里用两种极端基线各算一遍，
// 断言关键标志的结果**一致** —— 只有把关键项都显式列出来，结论才与基线无关。
//
// 改回旧实现（只给 ECHO + 两个速度）时这条会红：零基线下 ICRNL/ISIG/ICANON 都是 0。
func TestPTYTerminalModesDoNotDependOnServerBaseline(t *testing.T) {
	keys := make([]byte, 0, len(ptyRequiredModes))
	for _, c := range ptyRequiredModes {
		keys = append(keys, c.key)
	}
	apply := func(baseline uint32) map[byte]uint32 {
		out := make(map[byte]uint32, len(ptyRequiredModes))
		for _, k := range keys {
			out[k] = baseline
		}
		for k, v := range ptyTerminalModes() {
			out[k] = v
		}
		return out
	}
	zero := apply(0)   // 基线是全零（半 raw：ICANON/ISIG/ICRNL 全关）
	cooked := apply(1) // 基线是完整 cooked
	for _, c := range ptyRequiredModes {
		if zero[c.key] != cooked[c.key] {
			t.Errorf("%s 的结果依赖服务端基线（零基线=%d，cooked 基线=%d）—— 必须显式列出",
				c.name, zero[c.key], cooked[c.key])
		}
	}
}
