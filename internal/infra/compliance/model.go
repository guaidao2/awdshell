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
	Type    string  `yaml:"type" json:"type"`
	Pattern string  `yaml:"pattern" json:"pattern"`
	Value   float64 `yaml:"value" json:"value"`
}

// Check 是一条基线检查项。
type Check struct {
	ID        string   `yaml:"id" json:"id"`
	Title     string   `yaml:"title" json:"title"`
	Category  string   `yaml:"category" json:"category"`
	Severity  string   `yaml:"severity" json:"severity"`
	Refs      []string `yaml:"refs" json:"refs"`             // 对应条款，例如 "等保 8.1.4.1" / "CIS 5.2.8"
	Command   string   `yaml:"command" json:"command"`       // 只读命令
	Expect    Expect   `yaml:"expect" json:"expect"`         // 判定规则
	Remedy    string   `yaml:"remedy" json:"remedy"`         // 整改建议
	Note      string   `yaml:"note" json:"note"`             // 补充说明
	Timeout   int      `yaml:"timeout" json:"timeout"`       // 秒，缺省 10
	NeedsRoot bool     `yaml:"needs_root" json:"needs_root"` // 需要 root 才能读到结果
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
	Name     string `yaml:"name" json:"name"`
	Standard string `yaml:"standard" json:"standard"`
	Level    string `yaml:"level" json:"level"`
	Author   string `yaml:"author" json:"author"`
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
		matched, mErr := matchPattern(chk.Expect.Pattern, body)
		if mErr != nil {
			// 规则本身写错了（RE2 不支持的语法等）：绝不能当成"合规"，
			// 如实标 error 让人去看规则文件
			res.Status = StatusError
			res.Detail = "检查规则的正则无法编译：" + mErr.Error()
			break
		}
		if matched {
			res.Status = StatusPass
			res.Detail = "输出符合预期"
		} else {
			res.Status = StatusFail
			res.Detail = "输出未匹配期望的模式"
		}

	case ExpectRegexNotMatch:
		matched, mErr := matchPattern(chk.Expect.Pattern, body)
		if mErr != nil {
			// **这里原来是 fail-open**：matchPattern 编译失败返回 false，
			// 而 regex_not_match 的语义是"不匹配才符合"，于是"该报不合规的"
			// 被报成合规。现在编译失败一律标 error。
			res.Status = StatusError
			res.Detail = "检查规则的正则无法编译：" + mErr.Error()
			break
		}
		if matched {
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
//
// 返回 (是否匹配, 错误)。**错误必须传出去**：以前编译失败直接返回 false，
// 而 regex_not_match 的语义是"不匹配才符合"，于是"规则写错了"被当成"合规"
// （fail-open，该报不合规的报成合规）。
func matchPattern(pattern, body string) (bool, error) {
	re, err := compiled(strings.TrimSpace(pattern))
	if err != nil {
		return false, err
	}
	if re.MatchString(body) {
		return true, nil
	}
	for _, line := range strings.Split(body, "\n") {
		if re.MatchString(strings.TrimSpace(line)) {
			return true, nil
		}
	}
	return false, nil
}

// firstNumber 取输出里用于数值比较的数字。
//
// 优先取**独立的数字 token**（前后是空白 / 标点 / 行首行尾）：数值类的检查项
// 命令输出通常就是一行数字（`PASS_MAX_DAYS 90`、`5`、`0`），而老逻辑取的是
// "第一个数字字符起的一段"，遇到版本号与地址就取错 —— 实测 `ntp-4.2.8p15`
// 取到 -4、`1.2.3.4` 取到 1，判出来的合规性正好是反的。
//
// 独立数字一个都没有时才退回旧逻辑，且要排除版本号 / IP 形态：
// 否则 `ntp-4.2.8p15` 仍会被旧逻辑抠出 -4，等于没修。
func firstNumber(s string) (float64, bool) {
	for _, m := range standaloneNumRe.FindAllStringSubmatch(s, -1) {
		// 第 1 个捕获组才是数字本身（左右边界只是判据）
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			continue
		}
		return v, true
	}
	if v, ok := firstNumberLegacy(s); ok && !looksLikeVersion(s, v) {
		return v, true
	}
	return 0, false
}

// standaloneNumRe 匹配"前后不与字母数字下划线点相连"的数字（第 1 个捕获组是数字）。
// 用 ASCII 边界而不是 \b：中文语境下 \b 把汉字也算非单词字符，`共4条` 这类
// 紧贴中文的数字反而匹配不到。
// 边界里排除 `.` 是为了让 `1.2.3.4` 整段不匹配 —— 否则会取到 1。
var standaloneNumRe = regexp.MustCompile(`(?:^|[^0-9A-Za-z_.])(-?\d+(?:\.\d+)?)(?:$|[^0-9A-Za-z_.])`)

// numbersIn 返回 s 里所有独立数字（测试与调试用）。
func numbersIn(s string) []string {
	ms := standaloneNumRe.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	return out
}

// looksLikeVersion 判断 v 是不是藏在版本号 / IP / 域名里。
// 判据：数字紧邻 `.`，或紧跟在"字母+连字符"后面（`ntp-4`），或后面紧跟字母（`2.8p15`）。
// 这类数字不是"检查项报出来的数值"，不该拿来做阈值比较。
func looksLikeVersion(s string, v float64) bool {
	lit := strconv.FormatFloat(v, 'f', -1, 64)
	i := strings.Index(s, lit)
	if i < 0 {
		return false
	}
	var before, after byte
	if i > 0 {
		before = s[i-1]
	}
	if j := i + len(lit); j < len(s) {
		after = s[j]
	}
	if before == '.' || after == '.' {
		return true // 1.2.3.4 的 1、ntp-4.2 的 4
	}
	if before == '-' && i >= 2 && isAlnumASCII(s[i-2]) {
		return true // ntp-4 的 -4
	}
	if isAlphaASCII(after) {
		return true // 2.8p15 的 2
	}
	return false
}

func isAlnumASCII(c byte) bool { return isAlphaASCII(c) || (c >= '0' && c <= '9') }

func isAlphaASCII(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// firstNumberLegacy 是"取第一个数字字符起的一段"的老逻辑，只作兜底。
func firstNumberLegacy(s string) (float64, bool) {
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

// truncate 按 **rune** 截断。
//
// 按字节切会把多字节字符切成半个：结果不是合法 UTF-8，进 JSON 时被编码器
// 换成 U+FFFD，界面上尾部出现一串问号/方块。检查项输出里有中文（配置注释、
// 进程名）时特别明显。
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n { // 字节数都没超，rune 数更不会超，省一次遍历
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
