package collect

import (
	"strings"
	"testing"
)

// netstat 兜底形态的列序必须解析正确。
//
// 实测过的两个静默错误：连接的 Local 显示成对端、Remote 变成 "ESTABLISHED"
// （端口 0）；监听列表直接从 2 条变成 0 条（`0.0.0.0:*` 的端口解析成 0 被丢掉），
// 排查外联时看到的是一张空表。
func TestParseConnsBothForms(t *testing.T) {
	cases := []struct {
		name            string
		v, laddr, raddr string
		lport, rport    int
	}{
		{"ss", `ESTAB 0 0 10.0.0.5:22 10.0.0.1:54321 users:(("sshd",pid=1,fd=3))`, "10.0.0.5", "10.0.0.1", 22, 54321},
		{"netstat", `tcp 0 0 10.0.0.5:22 10.0.0.1:54321 ESTABLISHED`, "10.0.0.5", "10.0.0.1", 22, 54321},
	}
	for _, c := range cases {
		got := parseConns(c.v)
		if len(got) != 1 {
			t.Fatalf("%s: 期望 1 条连接，得到 %+v", c.name, got)
		}
		if got[0].Local != c.laddr || got[0].LPort != c.lport ||
			got[0].Remote != c.raddr || got[0].RPort != c.rport {
			t.Errorf("%s 解析错: local=%s:%d remote=%s:%d，期望 %s:%d → %s:%d",
				c.name, got[0].Local, got[0].LPort, got[0].Remote, got[0].RPort,
				c.laddr, c.lport, c.raddr, c.rport)
		}
	}
}

func TestParseListenersBothForms(t *testing.T) {
	cases := []struct{ name, v string }{
		{"ss", `tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`},
		{"netstat", `tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 123/sshd`},
	}
	for _, c := range cases {
		got := parseListeners(c.v)
		if len(got) != 1 || got[0].Port != 22 {
			t.Errorf("%s: 监听解析失败 -> %+v", c.name, got)
		}
	}
}

// meminfo 的取数范围必须覆盖 SwapTotal / SwapFree（它们在第 15 行起，
// 以前 `head -n 8` 永远取不到，界面 swap 恒为 0）。
func TestScriptCoversSwapFields(t *testing.T) {
	for _, key := range []string{"MemTotal", "MemFree", "MemAvailable", "SwapTotal", "SwapFree"} {
		if !strings.Contains(Script, key) {
			t.Errorf("采集脚本取不到 %s", key)
		}
	}
	if strings.Contains(Script, "head -n 8 /proc/meminfo") {
		t.Error("meminfo 还是只取前 8 行 —— SwapTotal/SwapFree 在第 15 行起")
	}
}
