package logscan

import (
	"fmt"
	"strings"
	"testing"
)

// 这一组守终审报告里的 L2：`authentication failure; … ruser= rhost=<IP>` 认不出来。
//
// 症状（终审实测，提交前后行为一致 → 既有缺口）：pam_unix 的 sshd 失败行写的是
// `ruser=` 而不是 `user=`，而替代分支的正则是 `authentication failure;[^\n]*?user=(\S+)`
// —— 于是这条真实形态**一个事件也提不出来**（预筛那一步是放行的，卡住的是正则）。
// 后果是同一台机器上"Failed password"立案、"authentication failure"静默，
// 而后者恰恰是 PAM 侧最常见的那一行。
//
// 两条判据都要有：这个形态必须立案、而且必须归到那个来源 IP 上；
// 同时不能因为放宽了账号那一段就把"没有来源 IP 的行"也算成事件。

const l2IP = "203.0.113.9"

// TestAuthFailureWithRuserIsExtracted 直接钉事件提取（分组序号与账号语义）。
func TestAuthFailureWithRuserIsExtracted(t *testing.T) {
	cases := []struct {
		name string
		line string
		user string
	}{
		{
			"pam_unix 的 sshd 失败行（ruser 为空，账号不在这行里）",
			"Oct 10 11:00:01 host sshd[123]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=" + l2IP,
			"",
		},
		{
			"带 pam_unix(sshd:auth) 前缀的同形态",
			"Oct 10 11:00:01 host sshd[123]: pam_unix(sshd:auth): authentication failure; " +
				"logname= uid=0 euid=0 tty=ssh ruser= rhost=" + l2IP,
			"",
		},
		{
			"ruser 有值",
			"Oct 10 11:00:01 host sshd[123]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser=admin rhost=" + l2IP,
			"admin",
		},
		{
			"老写法 user= 不能被这次改动弄坏",
			"Oct 10 11:00:01 host sshd[123]: authentication failure; logname= uid=0 euid=0 tty=ssh user=root rhost=" + l2IP,
			"root",
		},
		{
			// PAM 账号存在时的完整形态：`ruser=` 是空的，账号写在行尾的 `user=`。
			// 正则里的 `[^\n]*?` 非贪婪，会先在空的 ruser= 上停住 —— 不补一次
			// "回头找 user=" 就会把行里明明写着的账号丢成空串（终审实测的那一条）。
			"PAM 完整形态：ruser 空但行尾有 user=root",
			"Oct 10 11:00:01 host sshd[123]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=" + l2IP + "  user=root",
			"root",
		},
		{
			// 反向：真的没有账号列，就不能凭空造一个出来
			"只有 ruser= 与 rhost=，没有 user=",
			"Oct 10 11:00:01 host sshd[123]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=" + l2IP,
			"",
		},
	}
	for _, c := range cases {
		evs := extractAuthEvents([]string{c.line})
		if len(evs) != 1 {
			t.Errorf("%s：应当提取出 1 个事件，实际 %d（%+v）", c.name, len(evs), evs)
			continue
		}
		e := evs[0]
		if e.ip != l2IP {
			t.Errorf("%s：来源 IP 应当是 %s（老正则在这里提不出事件），实际 %q", c.name, l2IP, e.ip)
		}
		if e.user != c.user {
			t.Errorf("%s：账号应当是 %q，实际 %q", c.name, c.user, e.user)
		}
		if e.ok || e.neutral {
			t.Errorf("%s：authentication failure 必须是失败事件（不是成功、也不是中性）：%+v", c.name, e)
		}
	}

	// 反向保险：没有来源 IP 的行仍然不算事件（放宽账号那一段不该让 IP 变成可选）
	noIP := extractAuthEvents([]string{
		"Oct 10 11:00:01 host sshd[123]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser=",
	})
	if len(noIP) != 0 {
		t.Errorf("没有来源 IP 的失败行不该产出事件（IP 不是可选项）：%+v", noIP)
	}
}

// TestAuthFailureWithRuserBecomesBruteForce 走一遍完整链路：10 行 pam_unix 失败
// 必须立案、来源正确、失败次数与定位行都对。
//
// 改回错误版本会红：老正则提不出事件 → AnalyzeAuth 返回 0 条结论。
func TestAuthFailureWithRuserBecomesBruteForce(t *testing.T) {
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf(
			"Oct 10 11:00:%02d host sshd[%d]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%s",
			i, i, l2IP))
	}

	c := findCorrelation(AnalyzeAuth(lines, DefaultThresholds()), "brute_force")
	if c == nil {
		t.Fatalf("10 行 authentication failure 必须立案，实际 0 条（老正则提不出事件）")
	}
	if c.SourceIP != l2IP {
		t.Errorf("来源 IP 应当是 %s，实际 %q", l2IP, c.SourceIP)
	}
	if c.Failures != 10 {
		t.Errorf("失败次数应当是 10，实际 %d", c.Failures)
	}
	if c.FirstLine != 1 || c.LastLine != 10 {
		t.Errorf("定位行应当是 1~10，实际 %d~%d", c.FirstLine, c.LastLine)
	}
	if len(c.Evidence) == 0 || !strings.Contains(c.Evidence[0], "authentication failure") {
		t.Errorf("证据里要有原始失败行：%+v", c.Evidence)
	}
}
