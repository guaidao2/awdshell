// Package compliance 做主机安全基线核查（等保 2.0 / CIS 公开要求）。
//
// 与日志检测的分工：日志检测看的是"已经发生了什么"，基线核查看的是"当前配置对不对"。
// 检查项以 YAML 描述，判定规则也在 YAML 里，不把判断写死在代码里 ——
// 这样不同等级要求、不同客户的标准差异，改配置即可，不用改程序。
//
// 检查命令由检查项自己定义：多数是读取配置与状态，也有需要现场取证或采样的情况。
package compliance

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// 判定结果状态。
const (
	StatusPass   = "pass"   // 符合
	StatusFail   = "fail"   // 不符合
	StatusManual = "manual" // 需人工确认
	StatusError  = "error"  // 命令执行失败
)

// 期望判定的类型。
const (
	ExpectRegexMatch    = "regex_match"     // 输出匹配即符合
	ExpectRegexNotMatch = "regex_not_match" // 输出不匹配才符合
	ExpectContains      = "contains"        // 输出包含该字符串即符合
	ExpectNotContains   = "not_contains"    // 输出不包含才符合
	ExpectExitZero      = "exit_zero"       // 命令成功即符合
	ExpectNumericMax    = "numeric_max"     // 输出里的数字 <= value 才符合
	ExpectNumericMin    = "numeric_min"     // 输出里的数字 >= value 才符合
	ExpectManual        = "manual"          // 只展示输出，由人判断
)

// Expect 是一条检查的判定规则。
type Expect struct {
	Type    string  `yaml:"type"`
	Pattern string  `yaml:"pattern"`
	Value   float64 `yaml:"value"`
}

// Check 是一条基线检查项。
type Check struct {
	ID        string   `yaml:"id"`
	Title     string   `yaml:"title"`
	Category  string   `yaml:"category"`
	Severity  string   `yaml:"severity"`
	Refs      []string `yaml:"refs"`       // 对应条款，例如 "等保 8.1.4.1" / "CIS 5.2.8"
	Command   string   `yaml:"command"`    // 只读命令
	Expect    Expect   `yaml:"expect"`     // 判定规则
	Remedy    string   `yaml:"remedy"`     // 整改建议
	Note      string   `yaml:"note"`       // 补充说明
	Timeout   int      `yaml:"timeout"`    // 秒，缺省 10
	NeedsRoot bool     `yaml:"needs_root"` // 需要 root 才能读到结果
}

// Result 是一条检查的执行结果。
type Result struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Category  string   `json:"category"`
	Severity  string   `json:"severity"`
	Refs      []string `json:"refs"`
	Status    string   `json:"status"`
	Detail    string   `json:"detail"` // 判定说明
	Output    string   `json:"output"` // 命令输出（截断）
	Command   string   `json:"command"`
	Remedy    string   `json:"remedy"`
	Note      string   `json:"note"`
	NeedsRoot bool     `json:"needs_root"`
}

// doc 是检查项文件的顶层结构。
type doc struct {
	Version int     `yaml:"version"`
	Meta    Meta    `yaml:"meta"`
	Checks  []Check `yaml:"checks"`
}

// Meta 描述一份检查项集合。
type Meta struct {
	Name     string `yaml:"name"`
	Standard string `yaml:"standard"`
	Level    string `yaml:"level"`
	Author   string `yaml:"author"`
}

// Set 是一份加载好的检查项集合。
type Set struct {
	Meta   Meta
	Checks []Check
	Source string
}

// Evaluate 按检查项的判定规则给出结论。
// out 是命令输出，err 是执行错误。
func Evaluate(chk Check, out string, err error) Result {
	res := Result{
		ID: chk.ID, Title: chk.Title, Category: chk.Category, Severity: chk.Severity,
		Refs: chk.Refs, Command: chk.Command, Remedy: chk.Remedy, Note: chk.Note,
		NeedsRoot: chk.NeedsRoot,
		Output:    truncate(strings.TrimSpace(out), 1500),
	}

	// manual 类型即使命令失败也要把输出给人看
	if chk.Expect.Type == ExpectManual {
		res.Status = StatusManual
		res.Detail = "需人工确认（命令输出见下）"
		if err != nil {
			res.Detail = "命令执行失败，请人工确认：" + err.Error()
		}
		return res
	}

	if err != nil {
		// 命令跑不起来通常意味着"检测不到"而不是"不合规"，标成 error 让人去看
		res.Status = StatusError
		res.Detail = "检查命令执行失败：" + err.Error()
		return res
	}

	body := strings.TrimSpace(out)
	switch chk.Expect.Type {
	case ExpectRegexMatch:
		if matchPattern(chk.Expect.Pattern, body) {
			res.Status = StatusPass
			res.Detail = "输出符合预期"
		} else {
			res.Status = StatusFail
			res.Detail = "输出未匹配期望的模式"
		}

	case ExpectRegexNotMatch:
		if matchPattern(chk.Expect.Pattern, body) {
			res.Status = StatusFail
			res.Detail = "发现了不符合要求的内容"
		} else {
			res.Status = StatusPass
			res.Detail = "未发现不符合要求的内容"
		}

	case ExpectContains:
		if strings.Contains(body, chk.Expect.Pattern) {
			res.Status = StatusPass
			res.Detail = "输出包含期望内容"
		} else {
			res.Status = StatusFail
			res.Detail = "输出缺少期望内容"
		}

	case ExpectNotContains:
		if strings.Contains(body, chk.Expect.Pattern) {
			res.Status = StatusFail
			res.Detail = "输出包含不应出现的内容"
		} else {
			res.Status = StatusPass
			res.Detail = "输出符合要求"
		}

	case ExpectExitZero:
		res.Status = StatusPass
		res.Detail = "命令执行成功"

	case ExpectNumericMax, ExpectNumericMin:
		n, ok := firstNumber(body)
		if !ok {
			res.Status = StatusError
			res.Detail = "输出里没有可比较的数字：" + truncate(body, 120)
			return res
		}
		if chk.Expect.Type == ExpectNumericMax {
			if n <= chk.Expect.Value {
				res.Status = StatusPass
			} else {
				res.Status = StatusFail
			}
			res.Detail = fmt.Sprintf("实测 %g，要求不大于 %g", n, chk.Expect.Value)
		} else {
			if n >= chk.Expect.Value {
				res.Status = StatusPass
			} else {
				res.Status = StatusFail
			}
			res.Detail = fmt.Sprintf("实测 %g，要求不小于 %g", n, chk.Expect.Value)
		}

	default:
		res.Status = StatusManual
		res.Detail = "未知判定类型 " + chk.Expect.Type + "，请人工确认"
	}
	return res
}

// 正则缓存：检查项的模式是固定字符串，编译一次反复用。
var reCache sync.Map

func compiled(pattern string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(pattern); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	reCache.Store(pattern, re)
	return re, nil
}

// matchPattern 先整段匹配，再逐行匹配 ——
// 配置类检查关心的是"有没有哪一行不符合要求"，逐行试一次能避免
// 因为前后行干扰而漏判。
func matchPattern(pattern, body string) bool {
	re, err := compiled(strings.TrimSpace(pattern))
	if err != nil {
		return false
	}
	if re.MatchString(body) {
		return true
	}
	for _, line := range strings.Split(body, "\n") {
		if re.MatchString(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

// firstNumber 取输出里的第一个数字（用于数值比较）。
func firstNumber(s string) (float64, bool) {
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c == '-' && start < 0 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9') {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if v, err := strconv.ParseFloat(s[start:i], 64); err == nil {
				return v, true
			}
			start = -1
		}
	}
	if start >= 0 {
		if v, err := strconv.ParseFloat(s[start:], 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
