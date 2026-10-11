package logscan

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// 这一组固化 review43 里 logscan 的几条修复，断言都写成"改回错误版本会红"。

// ---------- 中1：公钥爆破要立案 ----------

// TestRev43FailedMethodVariantsAreBruteForce 守 中1：失败形态不能只认
// `Failed password for`。
//
// 改回错误版本会红：`evFailRe` 只写了 `Failed password for`，于是
// `Failed publickey for root …`（公钥爆破）、`Failed none for`（客户端没给认证方式）
// 与 `Failed keyboard-interactive/pam for …`（方法名里带 `/`）全部不认 ——
// 审计实测 10 行 publickey 失败 + 10 行 [preauth] 断连的结论是 **0 条**，
// 换成 password 就正常立案。
func TestRev43FailedMethodVariantsAreBruteForce(t *testing.T) {
	const ip = "203.0.113.9"
	var lines []string
	methods := []string{"publickey", "none", "keyboard-interactive/pam", "gssapi-with-mic"}
	for i := 0; i < 8; i++ {
		// 一半带 sshd 标签、一半不带：预筛也不能只认 "failed password"
		//（不带标签的行是审计替身里的形态）
		if i%2 == 0 {
			lines = append(lines, fmt.Sprintf(
				"Oct 10 11:00:0%d host sshd[%d]: Failed %s for root from %s port 4000%d ssh2",
				i, i, methods[i%len(methods)], ip, i))
		} else {
			lines = append(lines, fmt.Sprintf(
				"Failed %s for root from %s port 4000%d ssh2", methods[i%len(methods)], ip, i))
		}
	}
	// 断连是中性事件（不参与失败计数），保留它做旁证
	for i := 0; i < 4; i++ {
		lines = append(lines, fmt.Sprintf(
			"Oct 10 11:00:1%d host sshd[9]: Connection closed by authenticating user root %s port 4001%d [preauth]", i, ip, i))
	}

	res := AnalyzeAuth(lines, DefaultThresholds())
	c := findCorrelation(res, "brute_force")
	if c == nil {
		t.Fatalf("publickey / none / keyboard-interactive 的失败必须立案，实际结论 %+v", res)
	}
	if c.Failures != 8 {
		t.Errorf("失败次数应为 8（断连不算失败），实际 %d", c.Failures)
	}
	if c.SourceIP != ip {
		t.Errorf("来源 IP 提取错：%s", c.SourceIP)
	}
	if c.Disconnects != 4 {
		t.Errorf("断连应作为中性旁证计数，实际 %d", c.Disconnects)
	}
	if len(c.Users) != 1 || c.Users[0] != "root" {
		t.Errorf("账号提取错：%v", c.Users)
	}
}

// `invalid user` / `illegal user` 两种写法都要认，且账号必须落在第 1 捕获组
// （调用方按 m[1:4] 找账号，分组序号一动就全错）。
func TestRev43FailedInvalidAndIllegalUserStillWork(t *testing.T) {
	lines := []string{
		`Oct 10 11:00:01 host sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 40000 ssh2`,
		`Oct 10 11:00:02 host sshd[2]: Failed publickey for invalid user oracle from 198.51.100.7 port 40001 ssh2`,
		`Oct 10 11:00:03 host sshd[3]: Failed password for illegal user test from 198.51.100.7 port 40002 ssh2`,
		`Oct 10 11:00:04 host sshd[4]: Failed keyboard-interactive/pam for invalid user postgres from 198.51.100.7 port 40003 ssh2`,
		`Oct 10 11:00:05 host sshd[5]: Failed none for nobody from 198.51.100.7 port 40004 ssh2`,
	}
	c := findCorrelation(AnalyzeAuth(lines, DefaultThresholds()), "user_sweep")
	if c == nil {
		t.Fatalf("5 个不同账号的失败应当立案（撞库），实际 0 条")
	}
	for _, want := range []string{"admin", "oracle", "test", "postgres", "nobody"} {
		found := false
		for _, u := range c.Users {
			if u == want {
				found = true
			}
		}
		if !found {
			t.Errorf("账号 %q 没被提取出来（分组序号变了？）：%v", want, c.Users)
		}
	}
}

// 反向保险：预筛放宽之后，普通系统日志不能被误当成认证失败。
func TestRev43PreFilterWideningDoesNotOverMatch(t *testing.T) {
	lines := []string{
		`Oct 10 11:00:01 host systemd[1]: Failed to start nginx.service: Unit not found.`,
		`Oct 10 11:00:02 host kernel: [  12.3] failed to load module`,
		`Oct 10 11:00:03 host CRON[2001]: (root) CMD (/usr/bin/backup.sh)`,
		`Oct 10 11:00:04 host sshd[2]: Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2`,
	}
	if got := AnalyzeAuth(lines, DefaultThresholds()); len(got) != 0 {
		t.Errorf("普通日志不该产出关联结论，实际 %+v", got)
	}
}

// ---------- 低1 / 低2：计数必须是"个数"，不是"事件条数" ----------

// TestRev43AccountCountIsDistinctNotPerEvent 守 低1：账号列表封顶后不能重复累加。
//
// 改回错误版本会红：老实现是
//
//	if !b.users[u] { b.userCount++; if len(b.users) < maxAuthListed { b.users[u] = true } }
//
// 集合满 64 之后新账号进不去，于是**同一账号再失败一次**时 `!b.users[u]` 又为真、
// userCount 再 +1。下面这组就是审计的复现：80 个不同账号（后 10 个各失败两次），
// 旧实现报 **90** 个 —— 撞库阈值与结论文案里的数字全是错的。
func TestRev43AccountCountIsDistinctNotPerEvent(t *testing.T) {
	const ip = "203.0.113.7"
	var lines []string
	add := func(u string) {
		lines = append(lines, fmt.Sprintf(
			"Jan  1 00:00:00 host sshd[1]: Failed password for %s from %s port 40000 ssh2", u, ip))
	}
	for i := 0; i < 64; i++ { // 前 64 个：各 1 次（正好填满列表上限）
		add(fmt.Sprintf("u%02d", i))
	}
	for i := 64; i < 70; i++ { // 再 6 个：各 1 次
		add(fmt.Sprintf("u%02d", i))
	}
	for i := 70; i < 80; i++ { // 最后 10 个：各 2 次（旧实现每个多加一次）
		add(fmt.Sprintf("u%02d", i))
		add(fmt.Sprintf("u%02d", i))
	}

	c := findCorrelation(AnalyzeAuth(lines, DefaultThresholds()), "user_sweep")
	if c == nil {
		t.Fatal("80 个不同账号的失败应当立案（撞库）")
	}
	if !strings.Contains(c.Detail, "尝试了 80 个不同账号") {
		t.Errorf("账号数应为 80 个不同账号，实际文案：%s", c.Detail)
	}
	if !strings.Contains(c.Detail, "等 80 个账号") {
		t.Errorf("列表封顶后的数字也要是真实的 80：%s", c.Detail)
	}
	if len(c.Users) != maxAuthListed {
		t.Errorf("结论文案里最多列出 %d 个账号，实际 %d", maxAuthListed, len(c.Users))
	}
}

// TestRev43SourceCountIsDistinctNotPerEvent 守 低2 的另一半：来源 IP 的计数
// 同样是"个数"（以前 ips 封顶、ipCount 计数，同一来源再出现一次就多加一个）。
//
// 改回错误版本会红：70 个不同来源（后 6 个各失败 2 次）会被报成 76 个来源。
func TestRev43SourceCountIsDistinctNotPerEvent(t *testing.T) {
	var lines []string
	add := func(ip string) {
		lines = append(lines, fmt.Sprintf(
			"Jan  1 00:00:00 host sshd[1]: Failed password for root from %s port 40000 ssh2", ip))
	}
	ipOf := func(i int) string { return fmt.Sprintf("10.1.%d.%d", i/256, i%256) }
	for i := 0; i < 64; i++ {
		add(ipOf(i))
	}
	for i := 64; i < 70; i++ {
		add(ipOf(i))
		add(ipOf(i))
	}

	th := DefaultThresholds()
	th.BruteForceFailures = 100 // 只看 distributed，避免被 byIP 的结论盖住
	th.BruteForceHigh = 100
	th.SweepUsers = 100
	c := findCorrelation(AnalyzeAuth(lines, th), "distributed")
	if c == nil {
		t.Fatal("同一个账号被 70 个来源尝试应当立案（分布式爆破）")
	}
	if !strings.Contains(c.Detail, "被 70 个来源尝试") {
		t.Errorf("来源数应为真实的 70 个，实际文案：%s", c.Detail)
	}
}

// TestRev43DroppedCountsAreDistinctNotEvents 守 低2：封顶时被丢掉的是
// "多少个来源/账号"，不是"多少条事件"。
//
// 改回错误版本会红：每个被丢掉的来源失败 3 次就会被报成 3 倍
// （"有 15 个来源未纳入统计"，而实际只有 5 个）。
func TestRev43DroppedCountsAreDistinctNotEvents(t *testing.T) {
	th := DefaultThresholds()
	th.BruteForceFailures = 100000 // 只关心 analysis_capped 那一条
	th.BruteForceHigh = 100000
	th.SweepUsers = 100000
	th.SweepIPs = 100000

	// ① 来源封顶：maxAuthSources 个来源各 1 次，再加 5 个新来源各 3 次
	var bySource []string
	for i := 0; i < maxAuthSources; i++ {
		bySource = append(bySource, fmt.Sprintf(
			"Jan  1 00:00:00 host sshd[1]: Failed password for root from 10.2.%d.%d port 40000 ssh2", i/256, i%256))
	}
	for k := 1; k <= 5; k++ {
		for n := 0; n < 3; n++ {
			bySource = append(bySource, fmt.Sprintf(
				"Jan  1 00:00:00 host sshd[1]: Failed password for root from 172.16.0.%d port 40000 ssh2", k))
		}
	}
	capped := findCorrelation(AnalyzeAuth(bySource, th), "analysis_capped")
	if capped == nil {
		t.Fatal("来源超上限必须如实标记封顶")
	}
	if !strings.Contains(capped.Detail, "有 5 个来源、0 个账号未纳入跨行统计") {
		t.Errorf("被丢掉的来源数应是 5（不是事件数 15）：%s", capped.Detail)
	}

	// ② 账号封顶：只用 1 个来源，maxAuthUsers 个账号各 1 次，再加 5 个新账号各 3 次
	var byUser []string
	const one = "203.0.113.50"
	for i := 0; i < maxAuthUsers; i++ {
		byUser = append(byUser, fmt.Sprintf(
			"Jan  1 00:00:00 host sshd[1]: Failed password for user%d from %s port 40000 ssh2", i, one))
	}
	for k := 1; k <= 5; k++ {
		for n := 0; n < 3; n++ {
			byUser = append(byUser, fmt.Sprintf(
				"Jan  1 00:00:00 host sshd[1]: Failed password for extra%d from %s port 40000 ssh2", k, one))
		}
	}
	capped = findCorrelation(AnalyzeAuth(byUser, th), "analysis_capped")
	if capped == nil {
		t.Fatal("账号超上限必须如实标记封顶")
	}
	if !strings.Contains(capped.Detail, "有 0 个来源、5 个账号未纳入跨行统计") {
		t.Errorf("被丢掉的账号数应是 5（不是事件数 15）：%s", capped.Detail)
	}
}

// ---------- 提示2：还没开始就被取消，不能说成"只检测到第 0 行" ----------

// cancelAfterCtx 在第 n 次 Err() 调用之后才开始报取消，
// 让"扫到一半被取消"这件事确定性地发生（不靠 sleep 抢时序）。
type cancelAfterCtx struct {
	after int
	calls int
}

func (c *cancelAfterCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAfterCtx) Done() <-chan struct{}       { return nil }
func (c *cancelAfterCtx) Value(any) any               { return nil }
func (c *cancelAfterCtx) Err() error {
	c.calls++
	if c.calls > c.after {
		return context.Canceled
	}
	return nil
}

// TestRev43CancelBeforeFirstLineSaysNotStarted 守 提示2：ctx 进来就已取消时，
// 文案不该是"只检测到第 0 行"（听起来像"扫过 0 行"），而是"尚未开始"。
func TestRev43CancelBeforeFirstLineSaysNotStarted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 进来就已经取消

	res := ScanWithLimits("a\nb\nc\n", "x.log", AllRules(), "", ScanLimits{Ctx: ctx})
	if !res.Truncated {
		t.Fatal("ctx 取消必须标记 Truncated")
	}
	if strings.Contains(res.TruncatedReason, "第 0 行") {
		t.Errorf("一行都没看过时不该说「只检测到第 0 行」：%q", res.TruncatedReason)
	}
	if !strings.Contains(res.TruncatedReason, "尚未开始") {
		t.Errorf("应当说清「尚未开始」：%q", res.TruncatedReason)
	}
	if !strings.Contains(res.TruncatedReason, "取消") {
		t.Errorf("取消与超时要分开说：%q", res.TruncatedReason)
	}
}

// 已经扫了一部分才被取消时，仍然要给出行号（不能把正常情况也改成"尚未开始"）。
func TestRev43CancelMidwayStillReportsLine(t *testing.T) {
	res := ScanWithLimits("a\nb\nc\nd\ne\n", "x.log", AllRules(), "",
		ScanLimits{Ctx: &cancelAfterCtx{after: 3}})
	if !res.Truncated {
		t.Fatal("取消后必须标记 Truncated")
	}
	if !strings.Contains(res.TruncatedReason, "只检测到第 3 行") {
		t.Errorf("扫过 3 行之后被取消，应报「只检测到第 3 行」：%q", res.TruncatedReason)
	}
	if strings.Contains(res.TruncatedReason, "尚未开始") {
		t.Errorf("已经扫过行时不能说「尚未开始」：%q", res.TruncatedReason)
	}
}

// ---------- 提示1：命中的"扫描事实"与"记录下来的列表"口径 ----------

// TestRev43ScanFactsVsRecordedHits 把两套口径钉住（提示1 的判断：语义讲得通，
// 保留行为、在字段注释里写明，不改）。
//
//   - len(Hits) / BySeverity / ByCategory / DecodedHits：**记录下来的**条目，
//     守"三个计数之和 == len(Hits)"。
//   - HitLineCount / TopIPs：这次**扫描看到的**事实，含达上限后没记录的那些行。
//
// 这条测试的作用是：谁以后想把 TopIPs 改成"只统计记录的命中"（或反过来），
// 会先在这里看到口径是有意为之的，而不是顺手改掉。
func TestRev43ScanFactsVsRecordedHits(t *testing.T) {
	payload := `<script>alert(1)</script> ../../../../etc/passwd union select 1,2 from users ` +
		`$(id) /bin/sh ;cat /etc/passwd sqlmap "/shell.php?cmd=id" ${jndi:ldap://x/a}`
	var b strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&b, "10.0.0.%d - - [01/Jan/2026:00:00:00 +0800] \"GET /?q=%s HTTP/1.1\" 200 1\n", i+1, payload)
	}
	res := ScanWithLimits(b.String(), "/var/log/nginx/access.log", AllRules(), KindWeb, ScanLimits{MaxHits: 5})

	if len(res.Hits) != 5 || res.DroppedHits == 0 {
		t.Fatalf("测试前提不成立：hits=%d dropped=%d", len(res.Hits), res.DroppedHits)
	}
	if res.HitLineCount != 3 {
		t.Errorf("HitLineCount 是「有命中的行数」，应当含被截断那些行（期望 3），实际 %d", res.HitLineCount)
	}
	sum := 0
	for _, v := range res.BySeverity {
		sum += v
	}
	if sum != len(res.Hits) {
		t.Errorf("BySeverity 合计必须等于 len(Hits)（记录口径），实际 %d != %d", sum, len(res.Hits))
	}
	if len(res.TopIPs) != 3 {
		t.Errorf("TopIPs 是扫描事实（三个来源都命中过），应当含未记录那些行（期望 3），实际 %+v", res.TopIPs)
	}
}
