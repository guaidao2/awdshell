package logscan

// 第二轮全代码审计（.tmp/audit41）里 logscan 包那批问题的回归测试。
//
// 每条断言都写成"改回错误版本会红"：配套的 mutant 用 go test -overlay 把
// 旧行为覆盖回源码（见 .tmp/fix41/），跑这些用例会失败。
//
// 特别提醒：有几个用例会往包级的"未实现名字"注册表里写（那正是被测行为），
// 所以它们必须先保存快照、用 t.Cleanup 还原 —— 否则 loader_test.go 的
// "没有未实现的变换/算子"断言会被污染（同一进程里顺序执行）。

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// preserveUnknownRegistry 保存/还原两个全局注册表（见文件头说明）。
func preserveUnknownRegistry(t *testing.T) {
	t.Helper()
	unknownMu.Lock()
	prevTransforms := make(map[string]bool, len(UnknownTransforms))
	for k, v := range UnknownTransforms {
		prevTransforms[k] = v
	}
	prevOperators := make(map[string]bool, len(unknownOperators))
	for k, v := range unknownOperators {
		prevOperators[k] = v
	}
	unknownMu.Unlock()
	t.Cleanup(func() {
		unknownMu.Lock()
		UnknownTransforms = prevTransforms
		unknownOperators = prevOperators
		unknownMu.Unlock()
	})
}

// ---------- 中1：断连是中性事件，不是认证失败 ----------

// 审计实测：5 行 `Connection closed by 203.0.113.9 [preauth]` 会被算成 5 次失败
// （brute_force/medium），再加 1 行 `Accepted password` 直接变成
// success_after_fail/critical。而 NAT 超时、跳板机断开、客户端重试都会留下断连。
func TestAudit41DisconnectIsNeutralNotFailure(t *testing.T) {
	disconnect := func(i int) string {
		return fmt.Sprintf("Jan  1 00:00:%02d host sshd[10]: Connection closed by 203.0.113.9 port 510%02d [preauth]", i, i)
	}
	var only []string
	for i := 0; i < 5; i++ {
		only = append(only, disconnect(i))
	}
	if got := AnalyzeAuth(only, DefaultThresholds()); len(got) != 0 {
		t.Errorf("5 条「Connection closed by」不该产出任何认证结论，实际 %d 条：%+v", len(got), got)
	}

	withOK := append(append([]string{}, only...),
		"Jan  1 00:01:00 host sshd[20]: Accepted password for root from 203.0.113.9 port 52000 ssh2")
	for _, c := range AnalyzeAuth(withOK, DefaultThresholds()) {
		if c.Kind == "success_after_fail" || c.Kind == "brute_force" {
			t.Errorf("断连不是失败：5 次断连 + 1 次正常登录不该立案，实际 %+v（failures=%d）", c, c.Failures)
		}
	}

	// 真失败 + 断连混在一起：失败数只数真失败，断连作为伴随计数出现
	var mixed []string
	for i := 0; i < 6; i++ {
		mixed = append(mixed, fmt.Sprintf("Jan  1 00:02:%02d host sshd[3]: Failed password for root from 203.0.113.9 port 400%02d ssh2", i, i))
	}
	mixed = append(mixed, disconnect(9))
	mixed = append(mixed, "Jan  1 00:03:00 host sshd[20]: Accepted password for root from 203.0.113.9 port 52001 ssh2")
	c := findCorrelation(AnalyzeAuth(mixed, DefaultThresholds()), "success_after_fail")
	if c == nil {
		t.Fatal("6 次真实失败 + 1 次成功登录应当立案")
	}
	if c.Failures != 6 {
		t.Errorf("失败次数应只数真实失败（6），实际 %d —— 断连被算成了失败？", c.Failures)
	}
	if c.Disconnects != 1 {
		t.Errorf("断连应当作为伴随计数出现（1 次），实际 %d", c.Disconnects)
	}
	if c.FirstLine != 1 || c.LastLine != 8 {
		// 1..6 是失败行、8 是成功行；第 7 行（断连）**不该**成为这条结论的定位行
		t.Errorf("行号应只涵盖参与结论的事件（1..8，跳过第 7 行的断连），实际 %d..%d", c.FirstLine, c.LastLine)
	}
	if !strings.Contains(c.Detail, "连接中断") {
		t.Errorf("伴随计数要写在详情里：%q", c.Detail)
	}
}

// 成功登录不该进 users / userIPs：
// 一台 NAT 后面 6 个账号正常登录 = 撞库？同一账号 6 个来源正常登录 = 分布式爆破？
func TestAudit41SuccessesAreNotSweepSources(t *testing.T) {
	var sweepLike []string
	for i := 0; i < 6; i++ {
		sweepLike = append(sweepLike, fmt.Sprintf(
			"Jan  1 00:0%d:00 host sshd[9]: Accepted password for user%d from 198.51.100.7 port 4000%d ssh2", i, i, i))
	}
	if got := AnalyzeAuth(sweepLike, DefaultThresholds()); len(got) != 0 {
		t.Errorf("同一来源 6 个账号登录成功不是撞库，实际产出 %+v", got)
	}

	var distLike []string
	for i := 0; i < 6; i++ {
		distLike = append(distLike, fmt.Sprintf(
			"Jan  1 00:10:00 host sshd[9]: Accepted publickey for deploy from 203.0.113.%d port 40000 ssh2", i+1))
	}
	if got := AnalyzeAuth(distLike, DefaultThresholds()); len(got) != 0 {
		t.Errorf("同一账号被 6 个来源登录成功不是分布式爆破，实际产出 %+v", got)
	}
}

// ---------- 中1/低7：阈值逐项校验、distributed 的真实计数与行号 ----------

// SweepIPs / SweepUsers 传 0 时旧实现 `len(ips) >= 0` 恒真 —— 阈值等于不存在。
func TestAudit41ThresholdsValidatedPerField(t *testing.T) {
	lines := []string{
		"Jan  1 00:00:01 host sshd[1]: Failed password for root from 203.0.113.1 port 40001 ssh2",
		"Jan  1 00:00:02 host sshd[2]: Failed password for root from 203.0.113.2 port 40002 ssh2",
	}
	th := DefaultThresholds()
	th.SweepIPs = 0
	for _, c := range AnalyzeAuth(lines, th) {
		if c.Kind == "distributed" {
			t.Errorf("SweepIPs 传 0 应回落到默认阈值（不再 `len(ips) >= 0` 恒真），实际立案：%+v", c)
		}
	}
	th2 := DefaultThresholds()
	th2.SweepUsers = 0
	for _, c := range AnalyzeAuth(lines, th2) {
		if c.Kind == "user_sweep" {
			t.Errorf("SweepUsers 传 0 应回落到默认阈值，实际立案：%+v", c)
		}
	}
	// 反向：显式给的小阈值必须照常生效（回落只针对 <=0）
	th3 := DefaultThresholds()
	th3.BruteForceFailures = 100
	th3.BruteForceHigh = 100
	th3.SweepIPs = 2
	if findCorrelation(AnalyzeAuth(lines, th3), "distributed") == nil {
		t.Error("显式 SweepIPs=2 时应当立案，说明阈值没有被回落逻辑吃掉")
	}
}

// distributed 的 Failures 以前填的是 IP 个数、FirstLine/LastLine 一直是 0。
func TestAudit41DistributedCountsFailuresAndLines(t *testing.T) {
	var lines []string
	for i := 0; i < 3; i++ {
		lines = append(lines,
			fmt.Sprintf("Jan  1 00:00:0%d host sshd[1]: Failed password for root from 203.0.113.1 port 4000%d ssh2", i, i),
			fmt.Sprintf("Jan  1 00:00:1%d host sshd[2]: Failed password for root from 203.0.113.2 port 4001%d ssh2", i, i))
	}
	th := DefaultThresholds()
	th.BruteForceFailures = 100 // 只看 distributed 那条，避免被 byIP 的结论盖住
	th.BruteForceHigh = 100
	th.SweepUsers = 100
	th.SweepIPs = 2
	c := findCorrelation(AnalyzeAuth(lines, th), "distributed")
	if c == nil {
		t.Fatalf("2 个来源尝试同一账号应当立案")
	}
	if c.Failures != 6 {
		t.Errorf("Failures 应是真实认证失败次数 6，实际 %d（旧实现填的是 IP 个数 2）", c.Failures)
	}
	if c.FirstLine != 1 || c.LastLine != 6 {
		t.Errorf("distributed 也要带上行号（期望 1..6），实际 %d..%d（旧实现一直是 0）", c.FirstLine, c.LastLine)
	}
	if len(c.Users) != 1 || c.Users[0] != "root" {
		t.Errorf("账号列表不对：%v", c.Users)
	}
}

// byIP / userIPs 不能让攻击者用"每行一个新 IP / 新账号"把内存拉爆。
func TestAudit41AnalyzeCapsSourcesAndUsers(t *testing.T) {
	n := maxAuthSources + 16
	lines := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lines = append(lines, fmt.Sprintf(
			"Jan  1 00:00:00 host sshd[1]: Failed password for u%d from 10.%d.%d.%d port 40000 ssh2",
			i, i/65536%256, i/256%256, i%256))
	}
	start := time.Now()
	got := AnalyzeAuth(lines, DefaultThresholds())
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("关联分析耗时 %v，上限似乎没生效", el)
	}
	var capped *Correlation
	for i := range got {
		if got[i].Kind == "analysis_capped" {
			capped = &got[i]
		}
	}
	if capped == nil {
		t.Errorf("%d 个来源（上限 %d）必须如实标记封顶，实际结论 %d 条", n, maxAuthSources, len(got))
	}
	if len(got) > 8 {
		t.Errorf("每个来源只失败 1 次，不该产出 %d 条结论：%+v", len(got), got)
	}
}

// ---------- 中3：anyOf 的子算子必须校验，不支持的整条跳过 ----------

func TestAudit41AnyOfSubOperatorRejectedNotSilentlyDropped(t *testing.T) {
	preserveUnknownRegistry(t)
	// 审计实测：这条规则旧实现 loaded=1、skipped=nil，合成的正则里没有 detectXSS，
	// 于是"看着加载了、其实不覆盖 XSS"。
	const doc = `version: 1
meta: {name: probe, category: ssti}
rules:
  - id: A41-1
    severity: high
    category: ssti
    message: "probe anyof"
    transforms: [lowercase]
    operator:
      name: anyOf
      params:
        operators:
          - name: regex
            params:
              pattern: "zz-never-match-zz"
          - name: detectXSS
`
	loaded, skipped, err := LoadRules([]byte(doc), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("anyOf 里出现不支持的子算子时必须整条跳过，实际 loaded=%d（合成正则=%v）—— 这正是审计实测的静默降级",
			len(loaded), loaded[0].Rule.Pattern)
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "detectXSS") {
		t.Errorf("跳过原因里应点名那个子算子，实际：%v", skipped)
	}
}

// 子算子里多写的参数（顶层写会被拒）同样不能被静默忽略。
func TestAudit41AnyOfSubOperatorParamsValidated(t *testing.T) {
	preserveUnknownRegistry(t)
	const doc = `version: 1
meta: {name: probe, category: ssti}
rules:
  - id: A41-2
    severity: high
    category: ssti
    message: "probe anyof params"
    transforms: [lowercase]
    operator:
      name: anyOf
      params:
        operators:
          - name: regex
            params:
              pattern: "ok"
              min_depth: 3
`
	loaded, skipped, err := LoadRules([]byte(doc), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(loaded) != 0 {
		t.Fatalf("子算子 regex 不支持 min_depth，应整条跳过，实际 loaded=%d", len(loaded))
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "min_depth") {
		t.Errorf("跳过原因里应点名那个参数，实际：%v", skipped)
	}
}

// 反向：合法的 anyOf（regex / pm / 嵌套 anyOf）必须照常加载并命中。
func TestAudit41AnyOfValidSubOperatorsStillLoad(t *testing.T) {
	preserveUnknownRegistry(t)
	const doc = `version: 1
meta: {name: probe, category: ssti}
rules:
  - id: A41-3
    severity: high
    category: ssti
    message: "probe anyof ok"
    transforms: [lowercase]
    operator:
      name: anyOf
      params:
        operators:
          - name: regex
            params:
              pattern: "ssti-a"
          - name: pm
            params:
              patterns: ["kw-b"]
          - name: anyOf
            params:
              operators:
                - name: regex
                  params:
                    pattern: "deep-c"
`
	loaded, skipped, err := LoadRules([]byte(doc), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("合法的 anyOf 应当加载成功，实际 loaded=%d skipped=%v", len(loaded), skipped)
	}
	for _, in := range []string{"ssti-a", "kw-b", "deep-c"} {
		if got := loaded[0].Rule.Match(in); got == "" {
			t.Errorf("子算子（含嵌套）应当命中 %q", in)
		}
	}
}

// 顶层规则里写了没实现的变换名，也要出现在 LoadReport.Skipped 里（不再只进内部注册表）。
func TestAudit41UnknownTransformReportedInSkipped(t *testing.T) {
	preserveUnknownRegistry(t)
	const doc = `version: 1
meta: {name: probe, category: rce}
rules:
  - id: A41-4
    severity: high
    category: rce
    message: "probe transform typo"
    transforms: [urlDecodee, lowercase]
    operator:
      name: pm
      params:
        patterns: ["cmd"]
`
	loaded, skipped, err := LoadRules([]byte(doc), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("未知变换名不改变「规则仍加载」的既有语义，实际 loaded=%d", len(loaded))
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "urlDecodee") {
		t.Errorf("未实现的变换名应出现在 skipped 里（否则调用方看不到「写了但不生效」），实际：%v", skipped)
	}

	// 对照：全部是已实现的变换时不该产生这条 skipped
	const okDoc = `version: 1
meta: {name: probe, category: rce}
rules:
  - id: A41-5
    severity: high
    category: rce
    message: "ok transforms"
    transforms: [urlDecode, lowercase]
    operator:
      name: pm
      params:
        patterns: ["cmd"]
`
	_, skippedOK, err := LoadRules([]byte(okDoc), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(skippedOK) != 0 {
		t.Errorf("已实现的变换不该产生 skipped，实际：%v", skippedOK)
	}
}

// ---------- 低6：重复 id 不去重会被算两遍 ----------

func TestAudit41DuplicateRuleIDNotLoadedTwice(t *testing.T) {
	preserveUnknownRegistry(t)
	const doc = `version: 1
meta: {name: probe, category: rce}
rules:
  - id: A41-DUP
    severity: high
    category: rce
    message: 第一条
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["first"]}}
  - id: A41-DUP
    severity: low
    category: rce
    message: 第二条
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["second"]}}
`
	loaded, skipped, err := LoadRules([]byte(doc), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("同 id 的两条规则只能加载一条（否则命中/落库/态势都算两遍），实际 loaded=%d", len(loaded))
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "重复") {
		t.Errorf("重复 id 要进 skipped，实际：%v", skipped)
	}
	if loaded[0].Rule.Match("first") == "" || loaded[0].Rule.Match("second") != "" {
		t.Error("重复时应保留先出现的那条")
	}

	// 反向：第一条因参数错误被跳过时，第二条好规则应当正常加载（不能被"见过这个 id"顺带丢掉）
	const doc2 = `version: 1
meta: {name: probe, category: rce}
rules:
  - id: A41-DUP2
    severity: high
    category: rce
    message: 坏的第一条
    transforms: [lowercase]
    operator: {name: regex}
  - id: A41-DUP2
    severity: low
    category: rce
    message: 好的第二条
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["second"]}}
`
	loaded2, _, err := LoadRules([]byte(doc2), "probe.yaml")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(loaded2) != 1 || loaded2[0].Rule.Match("second") == "" {
		t.Errorf("第一条被跳过时，第二条同 id 的好规则应当加载成功，实际 loaded=%d", len(loaded2))
	}
}

// ---------- 中4：detectXSS 不能只看第一个 '<' ----------

func TestAudit41DetectXSSScansEveryTagStart(t *testing.T) {
	for _, in := range []string{
		"<img src=x onerror=alert(1)>",
		"a < b and <img src=x onerror=alert(1)>",
		"price < 10 then <svg onload=alert(1)>",
		"3 < 5 <body onload=alert(1)>",
	} {
		if got := detectXSS(in); got == "" {
			t.Errorf("应当命中（前面出现过非标签 '<' 也不能漏）：%q", in)
		}
	}
	for _, in := range []string{
		"3 < 5 onerror = x",
		"a < b",
		"the onerror handler is documented",
		`<a href="javascript:void(0)">x</a>`,
	} {
		if got := detectXSS(in); got != "" {
			t.Errorf("不该命中：%q -> %q", in, got)
		}
	}
}

// ---------- 中5：$() / 反引号不能只看第一处 ----------

func TestAudit41ContainsShellCharsScansEverySubstitution(t *testing.T) {
	for _, in := range []string{
		"$(id)",
		"total price is $(price) and then $(id)",
		"$(price) $(whoami)",
		"Set the `PATH` variable, then run `id`",
		"first `notacommand` then `cat /etc/passwd`",
		// 长命令体：闭合括号/反引号在 32 字节探针窗口之外，不能因此漏掉
		"$(cat /etc/passwd /etc/shadow /etc/group /etc/hosts)",
		"`cat /etc/passwd /etc/shadow /etc/group /etc/hosts`",
	} {
		if got := containsShellChars(in); got == "" {
			t.Errorf("应当命中（真命令在后面也要看）：%q", in)
		}
	}
	for _, in := range []string{
		"total price is $(price) * 2",
		"Set the `PATH` variable in your shell profile",
		"$(document).ready(function(){ doSomething(); })",
		"$(this).val()",
		// 没闭合的 $() / 反引号不构成命令替换（维持旧行为）
		"total price is $(price",
		"see `here in the doc",
	} {
		if got := containsShellChars(in); got != "" {
			t.Errorf("不该命中：%q -> %q", in, got)
		}
	}
}

// ---------- 中2：整次扫描的时间预算 ----------

func TestAudit41ScanTimeBudgetStopsAndMarks(t *testing.T) {
	const n = 60
	worst := strings.Repeat(";", 8000) // 单行最坏形态：实测 ~50ms/行
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(worst)
		b.WriteString("\n")
	}
	start := time.Now()
	res := ScanWithLimits(b.String(), "worst.log", AllRules(), "", ScanLimits{MaxDuration: 40 * time.Millisecond})
	elapsed := time.Since(start)
	if !res.Truncated {
		t.Errorf("时间预算耗尽必须标记 Truncated（实际 scanned=%d/%d）—— 静默跑满就等于「整次扫描没有时间预算」", res.Scanned, n)
	}
	if res.StoppedAtLine == 0 {
		t.Error("StoppedAtLine 应记录停在哪一行")
	}
	if res.Scanned >= n {
		t.Errorf("40ms 的预算却扫完了全部 %d 行", n)
	}
	if elapsed > 3*time.Second {
		t.Errorf("40ms 的预算跑了 %v，预算没被检查", elapsed)
	}
	if !strings.Contains(res.TruncatedReason, "预算") {
		t.Errorf("原因里要说清是时间预算耗尽：%q", res.TruncatedReason)
	}

	// 既有入口（Scan / ScanWithKind / 零值 ScanLimits）行为不变：不标记截断
	plain := Scan("hello world\nsecond line\n", "x.log", AllRules())
	if plain.Truncated || plain.StoppedAtLine != 0 || plain.DroppedHits != 0 {
		t.Errorf("不传预算时不该标记截断：%+v", plain)
	}
}

func TestAudit41ScanContextCancelIsHonored(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 进来就已经取消
	res := ScanWithLimits("a\nb\nc\n", "x.log", AllRules(), "", ScanLimits{Ctx: ctx})
	if !res.Truncated {
		t.Error("ctx 取消时必须标记 Truncated")
	}
	if res.Scanned != 0 {
		t.Errorf("ctx 已取消就不该再扫任何一行，实际 scanned=%d", res.Scanned)
	}
}

// ---------- 低8：命中数量上限要如实标记，不能静默截断 ----------

func TestAudit41HitCapIsMarkedNotSilent(t *testing.T) {
	payload := `<script>alert(1)</script> ../../../../etc/passwd union select 1,2 from users ` +
		`$(id) /bin/sh ;cat /etc/passwd sqlmap "/shell.php?cmd=id" ${jndi:ldap://x/a}`
	var b strings.Builder
	for i := 0; i < 3; i++ {
		b.WriteString("10.0.0.9 - - [01/Jan/2026:00:00:00 +0800] \"GET /?q=")
		b.WriteString(payload)
		b.WriteString(" HTTP/1.1\" 200 1\n")
	}
	const cap = 5
	res := ScanWithLimits(b.String(), "/var/log/nginx/access.log", AllRules(), KindWeb, ScanLimits{MaxHits: cap})
	if len(res.Hits) != cap {
		t.Fatalf("命中数应当正好停在上限 %d，实际 %d", cap, len(res.Hits))
	}
	if !res.Truncated || res.DroppedHits == 0 {
		t.Errorf("达上限必须如实标记（truncated=%v dropped=%d），不能静默截断", res.Truncated, res.DroppedHits)
	}
	if !strings.Contains(res.TruncatedReason, "上限") {
		t.Errorf("原因里要写清已达上限：%q", res.TruncatedReason)
	}
	sum := 0
	for _, v := range res.BySeverity {
		sum += v
	}
	if sum != len(res.Hits) {
		t.Errorf("BySeverity 合计 %d 与 Hits %d 不一致（计数把没记录的那部分也算进去了）", sum, len(res.Hits))
	}
	// 正常规模不触发上限
	plain := Scan("GET /?id=1 HTTP/1.1\n", "/var/log/nginx/access.log", AllRules())
	if plain.Truncated || plain.DroppedHits != 0 {
		t.Errorf("正常扫描不该标记截断：%+v", plain)
	}
}
