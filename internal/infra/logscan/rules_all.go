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

// LogRuleReport 记录规则库的加载情况。
//
// 只在**整个规则库都没加载起来**时报一行：那是会真正影响检测能力的事故。
//
// 至于"哪几条规则因为算子没实现被跳过"，**不打日志、也不上界面** ——
// 那是实现细节，属于开发期信息：运维用户拿到的应当是检测结论，
// 把"有 7 条规则没生效"摆出来只是自曝其短，对他排查问题没有帮助。
// 需要时用 RuleLoadReport 在调试或测试里查。
func LogRuleReport() {
	if _, err := RuleLoadReport(); err != nil {
		log.Printf("日志检测规则库加载失败，仅使用内置规则: %v", err)
	}
}
