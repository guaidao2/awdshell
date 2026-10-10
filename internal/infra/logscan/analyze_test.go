package logscan

import (
	"strings"
	"testing"
)

func joinLines(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func findCorrelation(cs []Correlation, kind string) *Correlation {
	for i := range cs {
		if cs[i].Kind == kind {
			return &cs[i]
		}
	}
	return nil
}

// TestAnalyzeBruteForce 同一来源反复失败，达到阈值后应报爆破尝试。
func TestAnalyzeBruteForce(t *testing.T) {
	var lines []string
	for i := 0; i < 8; i++ {
		lines = append(lines, `Oct 10 11:00:0`+string(rune('0'+i))+` host sshd[1234]: Failed password for root from 203.0.113.9 port 40000 ssh2`)
	}
	res := Scan(joinLines(lines...), "auth.log", RulesForKind(AllRules(), KindSystem))

	c := findCorrelation(res.Correlations, "brute_force")
	if c == nil {
		t.Fatalf("未报出爆破尝试，关联结果=%+v", res.Correlations)
	}
	if c.Failures < 8 {
		t.Errorf("失败次数统计不对：%d", c.Failures)
	}
	if c.SourceIP != "203.0.113.9" {
		t.Errorf("来源 IP 提取不对：%s", c.SourceIP)
	}
}

// TestAnalyzeSuccessAfterFail 失败多次之后登录成功，这是最该先看的一条。
func TestAnalyzeSuccessAfterFail(t *testing.T) {
	lines := []string{
		`Oct 10 11:00:01 host sshd[1]: Failed password for root from 203.0.113.9 port 40001 ssh2`,
		`Oct 10 11:00:02 host sshd[2]: Failed password for root from 203.0.113.9 port 40002 ssh2`,
		`Oct 10 11:00:03 host sshd[3]: Failed password for root from 203.0.113.9 port 40003 ssh2`,
		`Oct 10 11:00:04 host sshd[4]: Failed password for root from 203.0.113.9 port 40004 ssh2`,
		`Oct 10 11:00:05 host sshd[5]: Failed password for root from 203.0.113.9 port 40005 ssh2`,
		`Oct 10 11:00:06 host sshd[6]: Failed password for root from 203.0.113.9 port 40006 ssh2`,
		`Oct 10 11:00:07 host sshd[7]: Accepted password for root from 203.0.113.9 port 40007 ssh2`,
	}
	res := Scan(joinLines(lines...), "auth.log", RulesForKind(AllRules(), KindSystem))

	c := findCorrelation(res.Correlations, "success_after_fail")
	if c == nil {
		t.Fatalf("未报出「失败后成功」，关联结果=%+v", res.Correlations)
	}
	if c.Severity != SevCritical {
		t.Errorf("严重级别应为 critical，实际 %s", c.Severity)
	}
	if c.Failures != 6 || c.Successes != 1 {
		t.Errorf("统计不对：失败 %d 成功 %d", c.Failures, c.Successes)
	}
	// 报出这条时不该再重复报一次普通爆破
	if findCorrelation(res.Correlations, "brute_force") != nil {
		t.Error("同一来源已经报了「失败后成功」，不该再报一次普通爆破")
	}
}

// TestAnalyzeUserSweep 失败次数不多但换了很多用户名，属于撞库/枚举。
func TestAnalyzeUserSweep(t *testing.T) {
	users := []string{"admin", "test", "oracle", "postgres", "ubuntu", "deploy"}
	var lines []string
	for i, u := range users {
		lines = append(lines, `Oct 10 11:00:0`+string(rune('0'+i))+` host sshd[9]: Invalid user `+u+` from 198.51.100.7`)
	}
	res := Scan(joinLines(lines...), "auth.log", RulesForKind(AllRules(), KindSystem))

	c := findCorrelation(res.Correlations, "user_sweep")
	if c == nil {
		t.Fatalf("未报出账号枚举，关联结果=%+v", res.Correlations)
	}
	if len(c.Users) < 6 {
		t.Errorf("账号统计不全：%v", c.Users)
	}
}

// TestAnalyzeDistributed 同一账号被很多来源尝试，属于分布式爆破。
func TestAnalyzeDistributed(t *testing.T) {
	var lines []string
	for i := 0; i < 6; i++ {
		ip := "203.0.113." + string(rune('1'+i))
		lines = append(lines, `Oct 10 11:00:00 host sshd[9]: Failed password for root from `+ip+` port 40000 ssh2`)
	}
	res := Scan(joinLines(lines...), "auth.log", RulesForKind(AllRules(), KindSystem))

	if findCorrelation(res.Correlations, "distributed") == nil {
		t.Fatalf("未报出分布式爆破，关联结果=%+v", res.Correlations)
	}
}

// TestAnalyzeQuietOnNormalLogins 正常登录不该产生关联发现（避免天天喊狼来了）。
func TestAnalyzeQuietOnNormalLogins(t *testing.T) {
	lines := []string{
		`Oct 10 11:00:01 host sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2`,
		`Oct 10 11:00:02 host sshd[2]: Accepted publickey for deploy from 10.0.0.6 port 51001 ssh2`,
		`Oct 10 11:00:03 host systemd[1]: Started Session 12 of user root.`,
		`Oct 10 11:00:04 host CRON[2001]: (root) CMD (/usr/bin/backup.sh)`,
	}
	res := Scan(joinLines(lines...), "auth.log", RulesForKind(AllRules(), KindSystem))
	if len(res.Correlations) > 0 {
		t.Errorf("正常登录不该有关联发现，实际 %+v", res.Correlations)
	}
}

// TestAnalyzeEmptyInput 空输入与垃圾输入不许 panic。
func TestAnalyzeEmptyInput(t *testing.T) {
	for _, in := range []string{"", "\n\n", "garbage line", "%", "$IFS"} {
		_ = AnalyzeAuth(strings.Split(in, "\n"), DefaultThresholds())
	}
}
