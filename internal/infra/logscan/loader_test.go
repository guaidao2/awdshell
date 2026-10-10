package logscan

import "testing"

// TestEmbeddedRulesLoadAndSelfTest 加载内嵌规则，并用规则自带的样本自检。
// 这里不用 t.Fatal 卡住：规则是从外部规则库搬来的，先如实报告通过率，再逐条修。
func TestEmbeddedRulesLoadAndSelfTest(t *testing.T) {
	loaded, report, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("加载内嵌规则失败: %v", err)
	}
	t.Logf("规则文件 %d 个 / 规则 %d 条 / 样本 %d 条", report.Files, report.Rules, report.TestCases)

	if len(report.Skipped) > 0 {
		t.Logf("跳过 %d 条：", len(report.Skipped))
		for _, s := range report.Skipped {
			t.Logf("  - %s", s)
		}
	}
	if len(report.UnknownTransforms) > 0 {
		t.Logf("未实现的变换: %v", report.UnknownTransforms)
	}
	if len(report.UnknownOperators) > 0 {
		t.Logf("未实现的算子: %v", report.UnknownOperators)
	}

	ok, bad, failures := SelfTest(loaded)
	t.Logf("单规则自测：通过 %d，失败 %d", ok, bad)
	for i, f := range failures {
		if i >= 40 {
			t.Logf("  ... 其余 %d 条省略", len(failures)-40)
			break
		}
		t.Logf("  %s", f)
	}

	cok, cbad, cfail := CrossTest(loaded)
	t.Logf("交叉测试（负样本跑全量规则）：通过 %d，失败 %d", cok, cbad)
	for i, f := range cfail {
		if i >= 30 {
			t.Logf("  ... 其余 %d 条省略", len(cfail)-30)
			break
		}
		t.Logf("  %s", f)
	}
}
