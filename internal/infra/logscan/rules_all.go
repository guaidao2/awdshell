package logscan

import (
	"log"
	"sync"
)

// awdshell 内置的规则（WEB-* / AUTH-* / SYS-* 等）偏系统与认证场景，
// 搬进来的规则库（SQLI-* / XSS-* / RCE-* 等）偏 Web 载荷，两者互补，合并使用。

var (
	allRulesOnce sync.Once
	allRules     []Rule
	allReport    LoadReport
	allLoadErr   error
)

// AllRules 返回全部可用规则（awdshell 内置 + 内嵌规则库），只加载一次。
func AllRules() []Rule {
	allRulesOnce.Do(func() {
		loaded, report, err := LoadEmbedded()
		allReport = report
		allLoadErr = err
		if err != nil {
			log.Printf("日志检测规则库加载失败，仅使用内置规则: %v", err)
			allRules = DefaultRules
			return
		}
		merged := make([]Rule, 0, len(DefaultRules)+len(loaded))
		merged = append(merged, DefaultRules...)
		merged = append(merged, RulesOf(loaded)...)
		allRules = merged
	})
	return allRules
}

// RuleLoadReport 返回规则库的加载报告（供启动日志与界面展示）。
func RuleLoadReport() (LoadReport, error) {
	AllRules()
	return allReport, allLoadErr
}

// LogRuleReport 把规则加载情况写进日志，如实说明哪些规则没生效。
func LogRuleReport() {
	report, err := RuleLoadReport()
	if err != nil {
		log.Printf("日志检测规则库：加载失败 %v", err)
		return
	}
	log.Printf("日志检测规则库：%d 个文件 / %d 条规则（含内置 %d 条），自带样本 %d 条",
		report.Files, len(AllRules()), len(DefaultRules), report.TestCases)
	if len(report.Skipped) > 0 {
		log.Printf("日志检测规则库：跳过 %d 条（算子或正则不被支持）", len(report.Skipped))
		for _, s := range report.Skipped {
			log.Printf("  - %s", s)
		}
	}
	if len(report.UnknownTransforms) > 0 {
		log.Printf("日志检测规则库：未实现的变换 %v（相关规则会少一层解码）", report.UnknownTransforms)
	}
	// 未知算子最容易让人误判：界面上写着"参与规则 N 条"，
	// 但用户无从知道 RCE、LFI 这些分类里的旗舰规则其实没生效。
	if len(report.UnknownOperators) > 0 {
		log.Printf("日志检测规则库：未实现的算子 %v（用这些算子的规则已跳过）", report.UnknownOperators)
	}
}
