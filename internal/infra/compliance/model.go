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

// 命令侧的可读性标记（见 checks/*.yaml 里 needs_root 那几条命令）。
//
// 为什么需要（复审 中2）：需要 root 才能读的检查项在非 root 登录下 grep 会
// EACCES、什么都不输出，而"没输出"与"读到了、确实是空"在输出上长得一模一样。
// 原来想用 `needs_root && body == ""` 兜底，但那段**永远走不到**：
// grep 无匹配退出码 1 → sshx.RunOutput 返回 ExitError → Evaluate 在
// `err != nil` 处就返回 error（"检查命令执行失败：exit status 1"）。
// 实测干净 + root 的机器上这 4 条也从来没 pass 过。
//
// 现在命令自己把可读性说出来（`if [ -r … ]; then grep … || true; echo __AWD_READ_OK__;
// else echo __AWD_READ_DENIED__; fi`，`|| true` 让退出码恒 0，判定才走得到），
// 判定侧据此分辨三件事：
//
//	__AWD_READ_OK__     读到了 → 空结果可信（pass 或 fail 按规则判）
//	__AWD_READ_DENIED__ 读不到 → error（"需要 root"，绝不判合规）
//	两个都没有           老规则/自定义规则 → 保留"空输出 + needs_root → error"的兜底
const (
	markerReadOK     = "__AWD_READ_OK__"
	markerReadDenied = "__AWD_READ_DENIED__"
)

// readMarkers 从命令输出里取出可读性标记，返回去掉标记行后的正文。
//
// 标记行整行都是标记（命令里就是 echo 一行），所以整行丢掉；标记不参与内容匹配，
// 否则 `\S` 这种"有输出就不合规"的 pattern 会把标记本身当成发现。
//
// **判据是"整行 TrimSpace 后全等"，不是 Contains**（复审 L1，实测）：
//
//   - `%adm ALL=(ALL) NOPASSWD: ALL __AWD_READ_OK__` —— 一行真实的发现后面恰好跟着
//     标记串时，Contains 会把**整行**当成标记丢掉，正文变空；而 readable=true 又让
//     needs_root 的空输出兜底不生效（见 Evaluate），于是这条真问题被判 **pass**；
//   - 同一行里含 __AWD_READ_DENIED__ 时，Contains 会让它被判成"读取被拒"的 error，
//     把配置问题说成权限问题。
//
// 全等之后，这两行都留在正文里照规则判（前一个是 fail，后一个按内容判），而命令
// 真正 echo 出来的那行标记（前后可能带空白，`echo` 不会，但 shell 输出可能被包）
// 仍然识别得出来。
func readMarkers(out string) (body string, readable, denied bool) {
	kept := make([]string, 0, 8)
	for _, line := range strings.Split(out, "\n") {
		switch strings.TrimSpace(line) {
		case markerReadOK:
			readable = true
			continue
		case markerReadDenied:
			denied = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n"), readable, denied
}

// Evaluate 按检查项的判定规则给出结论。
// out 是命令输出，err 是执行错误。
func Evaluate(chk Check, out string, err error) Result {
	// 命令侧的可读性标记先摘掉：它们不是"配置内容"，不该参与判定，
	// 也不该出现在给用户看的输出里。
	body, readable, denied := readMarkers(out)
	res := Result{
		ID: chk.ID, Title: chk.Title, Category: chk.Category, Severity: chk.Severity,
		Refs: chk.Refs, Command: chk.Command, Remedy: chk.Remedy, Note: chk.Note,
		NeedsRoot: chk.NeedsRoot,
		Output:    truncate(strings.TrimSpace(body), 1500),
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

	// 命令报告"读不到"：这是权限问题，不是"没发现问题"。
	// **必须排在所有判定类型之前**，也不受 needs_root 标志是否写对的影响。
	if denied {
		res.Status = StatusError
		res.Detail = "命令报告读取被拒（权限不足）：这一项需要 root 才能读到结果，请用 root 或 sudo 复跑确认"
		return res
	}

	body = strings.TrimSpace(body)

	// 需要 root 的项输出为空时**不能直接判合规**。三件事要说清：
	//   ① 这段兜底现在**可达**了 —— 命令侧用 `|| true` 压掉了 grep 的退出码，
	//      不会再有"无匹配就 ExitError"提前 return（原来那段是死代码）；
	//   ② 放在 switch 之前，对**所有**判定类型生效：以前只有 regex_not_match 有，
	//      而 contains 空输出恒 fail（冤枉）、not_contains 空输出恒 pass（放过），
	//      两个方向都是假结论；
	//   ③ 命令已经用 __AWD_READ_OK__ 明确"读到了"时不算空 —— 这时空结果是真的空，
	//      pass/fail 照规则判（干净 + root 的主机就该判 pass）。
	if chk.NeedsRoot && body == "" && !readable {
		res.Status = StatusError
		res.Detail = "输出为空，但这一项需要 root 才能读到结果 —— 请用 root 复跑确认"
		return res
	}

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
			// 空输出在这里已是合规（"没发现问题"）。needs_root 的空输出兜底
			// 已在 switch 之前统一处理，不再需要这一分支的副本。
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
