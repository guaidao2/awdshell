package compliance

import "testing"

// 空 pattern 的检查项必须被拦住。
//
// 审计实测：空正则能匹配任何字符串 —— regex_match / contains 恒 pass、
// regex_not_match / not_contains 恒 fail，而且都不会报错。规则文件是外部可编辑的，
// 一条写漏 pattern 的规则会静默地"永远合规"，这比直接报错危险得多。
func TestValidateCheckRejectsEmptyPattern(t *testing.T) {
	base := func(typ, pattern string) Check {
		return Check{ID: "T1", Title: "t", Command: "echo x",
			Expect: Expect{Type: typ, Pattern: pattern}}
	}
	cases := []struct {
		name    string
		chk     Check
		wantBad bool
	}{
		{"regex_not_match 空 pattern", base(ExpectRegexNotMatch, ""), true},
		{"regex_not_match 全空白", base(ExpectRegexNotMatch, "   "), true},
		{"regex_match 空 pattern", base(ExpectRegexMatch, ""), true},
		{"contains 空 pattern", base(ExpectContains, ""), true},
		{"not_contains 空 pattern", base(ExpectNotContains, ""), true},
		{"regex_not_match 正常", base(ExpectRegexNotMatch, `\S`), false},
		{"contains 正常", base(ExpectContains, "PermitRootLogin yes"), false},
		{"manual 不需要 pattern", base(ExpectManual, ""), false},
		{"exit_zero 不需要 pattern", base(ExpectExitZero, ""), false},
		{"正则写错", base(ExpectRegexMatch, "([a-z"), true},
		{"缺 id", Check{Title: "t", Command: "echo"}, true},
		{"缺 command", Check{ID: "x", Title: "t"}, true},
	}
	for _, c := range cases {
		got := validateCheck(c.chk)
		if c.wantBad && got == "" {
			t.Errorf("%s：应当被拦住，实际通过了", c.name)
		}
		if !c.wantBad && got != "" {
			t.Errorf("%s：不该被拦住，实际：%s", c.name, got)
		}
	}
}

// 内置检查项必须全部通过校验（防止将来手写 YAML 时漏掉 pattern）。
func TestBuiltinChecksAllValidate(t *testing.T) {
	sets, problems, err := LoadSets()
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Errorf("内置检查项应当全部合法，problems=%v", problems)
	}
	n := 0
	for _, c := range AllChecks(sets) {
		if why := validateCheck(c); why != "" {
			t.Errorf("内置检查项 %s 没通过校验：%s", c.ID, why)
		}
		n++
	}
	if n == 0 {
		t.Fatal("没加载到任何内置检查项")
	}
	t.Logf("内置检查项 %d 条全部通过校验", n)
}
