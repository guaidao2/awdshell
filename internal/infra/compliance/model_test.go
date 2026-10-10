package compliance

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRunWithContextReportsUnknownIDs 守 L2：
//
// 以前 onlyIDs 里的未知 ID 被静默忽略 —— 实测指定 `[A TYPO-ID]` 只跑了 1 项，
// 界面上没有任何提示，用户会把"打错的那个 ID"当成"查过了且通过"。
func TestRunWithContextReportsUnknownIDs(t *testing.T) {
	checks := []Check{
		{ID: "A", Command: "a", Expect: Expect{Type: ExpectExitZero}},
		{ID: "B", Command: "b", Expect: Expect{Type: ExpectExitZero}},
	}
	exec := func(cmd string, timeout int) (string, error) { return "ok", nil }

	results, problems := RunWithContext(context.Background(), checks, exec,
		[]string{"A", "TYPO-ID"}, nil)

	if len(results) != 1 || results[0].ID != "A" {
		t.Fatalf("只应执行 A，实际 %+v", results)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "TYPO-ID") {
		t.Fatalf("未知 ID 必须出现在 problems 里，实际 %v", problems)
	}
	if !strings.Contains(problems[0], "已忽略") {
		t.Errorf("问题描述要说明这个 ID 被忽略了：%q", problems[0])
	}

	// 全部 ID 都存在时不该报问题（避免在界面上刷无意义的警示）
	_, problems = RunWithContext(context.Background(), checks, exec, []string{"A", "B"}, nil)
	if len(problems) != 0 {
		t.Errorf("ID 都有效时不该有 problems，实际 %v", problems)
	}

	// 兼容入口 Run 仍然工作（service 层还在用它）
	if got := Run(checks, exec, []string{"B"}, nil); len(got) != 1 || got[0].ID != "B" {
		t.Errorf("Run 的筛选行为变了：%+v", got)
	}
}

// TestRunWithContextCancel 守 L4：一轮 60+ 项必须能中途停下。
func TestRunWithContextCancel(t *testing.T) {
	checks := []Check{
		{ID: "A", Command: "a", Expect: Expect{Type: ExpectExitZero}},
		{ID: "B", Command: "b", Expect: Expect{Type: ExpectExitZero}},
		{ID: "C", Command: "c", Expect: Expect{Type: ExpectExitZero}},
		{ID: "D", Command: "d", Expect: Expect{Type: ExpectExitZero}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	ran := 0
	exec := func(cmd string, timeout int) (string, error) {
		ran++
		cancel() // 第一项跑完就取消
		return "ok", nil
	}

	results, problems := RunWithContext(ctx, checks, exec, nil, nil)
	if ran != 1 {
		t.Errorf("取消后不该继续跑命令，实际跑了 %d 次", ran)
	}
	if len(results) != 1 {
		t.Errorf("已经跑完的结果要保留（不让前面白跑），实际 %d 条", len(results))
	}
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, " "), "取消") {
		t.Errorf("取消必须记进 problems，实际 %v", problems)
	}
}

// TestFirstNumberStandalone 守 L9：数值项必须取"独立数字"，不能从版本号/地址里抠。
func TestFirstNumberStandalone(t *testing.T) {
	cases := []struct {
		in   string
		want float64
		ok   bool
	}{
		// 现在的 5 条数值检查项实际输出（必须继续正确）
		{"90", 90, true},
		{"5", 5, true},
		{"600", 600, true},
		{"750", 750, true},
		// 带文字的数字：独立 token 优先
		{"PASS_MAX_DAYS 90", 90, true},
		{"TMOUT=600", 600, true},
		{"共4条\n", 4, true},
		// 版本号与地址里的数字**不能**被当成独立数字：
		// 独立数字一个都没有时退回旧逻辑，但必须被 looksLikeVersion 挡住
		{"ntp-4.2.8p15\n", 0, false},
		{"1.2.3.4\n", 0, false},
		{"openssh-8.7p1\n", 0, false},
		{"2.8p15\n", 0, false},
		// 负数是独立数字（前面是空白）
		{"-1", -1, true},
		// 紧贴非数字文字的写法仍走旧逻辑兜底（这是保留 legacy 的唯一理由）
		{"abc12", 12, true},
		// 没有数字
		{"no numbers here", 0, false},
	}
	for _, c := range cases {
		got, ok := firstNumber(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("firstNumber(%q) = (%v,%v)，期望 (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}

	// 老逻辑的错法要能一眼看出来：这里是"没有独立数字"的输入，
	// 以前会分别返回 -4 与 1（判出来的合规性是反的）。
	if v, _ := firstNumber("ntp-4.2.8p15"); v == -4 {
		t.Error("仍在从版本号里抠出 -4")
	}
	if v, _ := firstNumber("1.2.3.4"); v == 1 {
		t.Error("仍在从 IP 里抠出 1")
	}

	// 数值项的整体判定也要跟着对
	min := Check{ID: "T", Expect: Expect{Type: ExpectNumericMin, Value: 1}}
	if r := Evaluate(min, "1.2.3.4\n", nil); r.Status != StatusError {
		t.Errorf("IP 里抠不出独立数字，应标 error（让人去看），实际 %s：%s", r.Status, r.Detail)
	}
}

// TestTruncateKeepsUTF8 守 L10：截断必须按 rune，不能把多字节字符切成半个。
//
// 背景：以前是 s[:n]（按字节切），中文输出被切到中间时产生非法 UTF-8，
// 进 JSON 被编码器换成 U+FFFD，界面上尾部出现一串问号。
func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("中文输出", 50) // 每字 3 字节
	for n := 1; n <= 40; n++ {
		got := truncate(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("truncate(中文, %d) 产生了非法 UTF-8：%q", n, got)
		}
		if strings.ContainsRune(got, utf8.RuneError) {
			t.Fatalf("truncate(中文, %d) 里出现了替换字符（老实现按字节切的症状）：%q", n, got)
		}
		if !strings.HasSuffix(got, "...") {
			t.Fatalf("截断后应带省略号：%q", got)
		}
	}

	// 具体一个会切坏的边界：3 字节字符的第 10 个字节处
	if got := truncate(strings.Repeat("中", 10), 10); !utf8.ValidString(got) {
		t.Errorf("第 10 字节处截断切出了非法 UTF-8：%q", got)
	}

	// 短字符串不动，空串不 panic
	if got := truncate("短", 10); got != "短" {
		t.Errorf("没超长就不该动：%q", got)
	}
	if got := truncate("abc", 0); got != "" {
		t.Errorf("n<=0 应返回空串，实际 %q", got)
	}
}
