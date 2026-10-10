package logscan

import "testing"

// TestEmbeddedRulesLoadAndSelfTest 加载内嵌规则，并用规则自带的样本自检。
//
// 这里断言的是**不超过既有基线**，而不是"零失败"：规则库是从外部搬来的，
// 里面还有一批规则自身的问题（成因见下面的常量注释），本项目不打算在
// 这一版里重写它们。断言基线的作用是 —— 谁以后引入新的误报，测试立刻红，
// 而不是像以前那样只打一行 Logf、谁都没看见。
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
		t.Errorf("还有未实现的变换: %v", report.UnknownTransforms)
	}
	if len(report.UnknownOperators) > 0 {
		t.Errorf("还有未实现的算子: %v", report.UnknownOperators)
	}

	// 既有基线。两个数只允许变小，不允许变大。
	//
	// 单规则自测的 1 条：RCE-6001 的样本 `127.0.0.1` 是"参数值"形态，
	// 而 SelfTest 走 Scan 把它当**日志行**扫，没有分隔符+命令名的结构，
	// 自然不命中 —— 样本与使用场景的错配，不是算子的问题。
	//
	// 交叉测试的 15 条 —— 本项目的语义算子**一条都不贡献**。
	//
	// 移植 donothack 判据后曾多出 7 条，已通过"日志场景收紧"压掉
	//（堆叠查询要求分号前出现过引号、布尔比较要求引号上下文、
	// 伪协议后必须紧跟可执行内容、反引号/`$()` 内容必须是命令形态、
	// 注释标记之后不能再有正常文字）。
	//
	// 剩下的是**既有规则自身**的问题，与算子无关：
	//   - 命令类词表过宽（RCE-6004/6005/6006、SYS-1004、SCAN-2003）：
	//     把 `python -c 'print(1)'`、`systemctl enable nginx`、`chmod 777 ...`
	//     这类运维日常内容当成注入；
	//   - 正则过宽（SQLI-4014、XSS-5011、RCE-6012）：
	//     把 `choose 'cat' or 'dog'`、`<a href="javascript:void(0)">`、
	//     `<?php get_header(); ?>` 命中；
	//   - 上传类规则在**日志行**上命中（UPLOAD-1001/1002）：
	//     它们判的是文件名/路径形态，日志行里逐字出现 —— 这类规则**必须**留在
	//     日志链里（否则会丢掉 `GET /upload/shell.php.jpg` 这种真检出），
	//     代价就是 `https://example.com/index.php` 这种正常 URL 也会命中。
	const (
		selfTestFailBaseline  = 1
		crossTestFailBaseline = 15
	)

	ok, bad, failures := SelfTest(loaded)
	t.Logf("单规则自测：通过 %d，失败 %d", ok, bad)
	for i, f := range failures {
		if i >= 40 {
			t.Logf("  ... 其余 %d 条省略", len(failures)-40)
			break
		}
		t.Logf("  %s", f)
	}
	if bad > selfTestFailBaseline {
		t.Errorf("单规则自测失败 %d 条，超过既有基线 %d —— 新引入的误报？", bad, selfTestFailBaseline)
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
	if cbad > crossTestFailBaseline {
		t.Errorf("交叉测试失败 %d 条，超过既有基线 %d —— 新引入的跨规则误报？", cbad, crossTestFailBaseline)
	}
}
