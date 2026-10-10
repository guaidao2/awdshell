package compliance

import (
	"errors"
	"testing"
)

func TestLoadSets(t *testing.T) {
	sets, problems, err := LoadSets()
	if err != nil {
		t.Fatalf("加载检查项失败: %v", err)
	}
	if len(problems) > 0 {
		t.Errorf("加载有问题：%v", problems)
	}
	checks := AllChecks(sets)
	if len(checks) < 15 {
		t.Fatalf("检查项太少：%d", len(checks))
	}
	seen := map[string]bool{}
	for _, c := range checks {
		if seen[c.ID] {
			t.Errorf("检查项 ID 重复：%s", c.ID)
		}
		seen[c.ID] = true
		if c.Command == "" || c.Expect.Type == "" {
			t.Errorf("检查项 %s 不完整", c.ID)
		}
		if c.Timeout <= 0 {
			t.Errorf("检查项 %s 没有默认超时", c.ID)
		}
	}
}

func TestEvaluateRegexNotMatch(t *testing.T) {
	chk := Check{ID: "T1", Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `(?i)permitrootlogin\s+yes`}}

	r := Evaluate(chk, "permitrootlogin no\n", nil)
	if r.Status != StatusPass {
		t.Errorf("期望 pass，实际 %s（%s）", r.Status, r.Detail)
	}
	r = Evaluate(chk, "PermitRootLogin yes\n", nil)
	if r.Status != StatusFail {
		t.Errorf("期望 fail，实际 %s", r.Status)
	}
}

func TestEvaluateRegexMatchPerLine(t *testing.T) {
	chk := Check{ID: "T2", Expect: Expect{Type: ExpectRegexMatch, Pattern: `pam_faillock`}}
	body := "session required pam_unix.so\nauth required pam_faillock.so preauth\nauth required pam_unix.so\n"
	if r := Evaluate(chk, body, nil); r.Status != StatusPass {
		t.Errorf("逐行匹配应当命中，实际 %s", r.Status)
	}
}

func TestEvaluateNumeric(t *testing.T) {
	max := Check{ID: "T3", Expect: Expect{Type: ExpectNumericMax, Value: 90}}
	if r := Evaluate(max, "PASS_MAX_DAYS 90\n", nil); r.Status != StatusPass {
		t.Errorf("90 应满足 <=90，实际 %s", r.Status)
	}
	if r := Evaluate(max, "99999\n", nil); r.Status != StatusFail {
		t.Errorf("99999 应不满足 <=90，实际 %s", r.Status)
	}

	min := Check{ID: "T4", Expect: Expect{Type: ExpectNumericMin, Value: 8}}
	if r := Evaluate(min, "7\n", nil); r.Status != StatusFail {
		t.Errorf("7 应不满足 >=8，实际 %s", r.Status)
	}
	if r := Evaluate(min, "8\n", nil); r.Status != StatusPass {
		t.Errorf("8 应满足 >=8，实际 %s", r.Status)
	}
}

func TestEvaluateEmptyOutputOnNotMatch(t *testing.T) {
	// 「输出为空才算通过」是这类检查的常见形态（例如查有没有多余 UID 0 账号）
	chk := Check{ID: "T5", Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `\S`}}
	if r := Evaluate(chk, "\n", nil); r.Status != StatusPass {
		t.Errorf("空输出应 pass，实际 %s", r.Status)
	}
	if r := Evaluate(chk, "backdoor\n", nil); r.Status != StatusFail {
		t.Errorf("有输出应 fail，实际 %s", r.Status)
	}
}

func TestEvaluateErrorAndManual(t *testing.T) {
	errChk := Check{ID: "T6", Expect: Expect{Type: ExpectRegexMatch, Pattern: "x"}}
	r := Evaluate(errChk, "", errors.New("permission denied"))
	if r.Status != StatusError {
		t.Errorf("命令失败应标 error，实际 %s", r.Status)
	}

	manual := Check{ID: "T7", Expect: Expect{Type: ExpectManual}}
	r = Evaluate(manual, "some output", nil)
	if r.Status != StatusManual {
		t.Errorf("manual 类型应标 manual，实际 %s", r.Status)
	}
	r = Evaluate(manual, "", errors.New("boom"))
	if r.Status != StatusManual {
		t.Errorf("manual 类型命令失败也要给人工看，实际 %s", r.Status)
	}
}

func TestSummarizeScoreExcludesManualAndError(t *testing.T) {
	results := []Result{
		{Status: StatusPass, Category: "身份鉴别", Severity: "high"},
		{Status: StatusPass, Category: "身份鉴别", Severity: "high"},
		{Status: StatusFail, Category: "访问控制", Severity: "high"},
		{Status: StatusManual, Category: "访问控制", Severity: "low"},
		{Status: StatusError, Category: "访问控制", Severity: "medium"},
	}
	s := Summarize(results)
	if s.Total != 5 || s.Pass != 2 || s.Fail != 1 || s.Manual != 1 || s.Error != 1 {
		t.Fatalf("统计不对：%+v", s)
	}
	// 分母只算可判定的 3 项：2/3 = 66
	if s.Score != 66 {
		t.Errorf("分数应为 66，实际 %d", s.Score)
	}
	if s.ByCategory["身份鉴别"].Pass != 2 {
		t.Errorf("分类统计不对：%+v", s.ByCategory)
	}
}

func TestRunFiltersAndProgress(t *testing.T) {
	checks := []Check{
		{ID: "A", Command: "a", Expect: Expect{Type: ExpectExitZero}},
		{ID: "B", Command: "b", Expect: Expect{Type: ExpectExitZero}},
		{ID: "C", Command: "c", Expect: Expect{Type: ExpectExitZero}},
	}
	var done []int
	exec := func(cmd string, timeout int) (string, error) { return "ok", nil }

	results := Run(checks, exec, []string{"A", "C"}, func(d, t int) { done = append(done, d) })
	if len(results) != 2 {
		t.Fatalf("只应执行 2 项，实际 %d", len(results))
	}
	if results[0].ID != "A" || results[1].ID != "C" {
		t.Errorf("筛选结果不对：%+v", results)
	}
	if len(done) != 2 || done[1] != 2 {
		t.Errorf("进度回调不对：%v", done)
	}
}
