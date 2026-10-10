package logscan

import (
	"fmt"
	"strings"
)

// 语义算子：规则 YAML 用 operator.name 引用，参数从 params 读。
//
// **移植自 donothack 的 internal/operator（规则的规格来源）**，判据与它保持一致：
// 两边共用同一套规则 YAML，语义不能各写各的。为便于对照，函数名与它保持一致。
//
// 为什么这些判据不用正则：它们是**多组特征的组合**。比如 SQL 注入要看有没有凑齐
// 注入的"结构"（union + select、引号闭合 + 比较式、注释收尾），一条正则要么漏
// （`union square station` 命中），要么把正常文本打死（`select your country`）。
//
// 每个算子返回命中的指纹名/描述（空串表示未命中），与 Match 的返回值语义一致。

// ---------------------------------------------------------------- SQL 注入

// sqliFingerprintNames 是 detectSQLi 能返回的全部指纹名。
//
// 两处用它：① 加载时校验规则里写的指纹名（写错直接拒绝该规则，
// 而不是静默失效 —— 那会让"我调过参数了"变成错觉）；② 文档与测试的单一事实来源。
var sqliFingerprintNames = []string{
	"union select",
	"time-based",
	"metadata table",
	"file/exec primitive",
	"stacked query",
	"boolean comparison",
	"subquery in boolean context",
	"quote + comment",
	"boolean tautology",
	"quote probing",
	"boolean expression",
}

func isKnownSQLiFingerprint(n string) bool {
	for _, k := range sqliFingerprintNames {
		if k == n {
			return true
		}
	}
	return false
}

// fingerprintSet 把规则里写的指纹名列表转成集合；空列表返回 nil（表示不过滤）。
// 未知指纹名直接报错 —— 写错时宁可拒绝加载，也不要静默失效。
func fingerprintSet(names []string) (map[string]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "" {
			continue
		}
		if !isKnownSQLiFingerprint(n) {
			return nil, fmt.Errorf("未知的 SQL 注入指纹 %q（可选：%s）",
				n, strings.Join(sqliFingerprintNames, "、"))
		}
		out[n] = true
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

type sqliOp struct {
	minLen  int
	only    map[string]bool // 非 nil = 只看这些指纹
	exclude map[string]bool // 命中这些指纹就当作没命中
}

func (o sqliOp) eval(in string) string {
	fp := sqliFingerprint(in, o.minLen)
	if fp == "" {
		return ""
	}
	// 指纹过滤：让"强弱信号"能分成两条不同分值的规则。
	// `quote probing`（值本身就是引号 / `1'`）是弱信号 —— 搜索框里搜一个引号
	// 是正常行为，它单独命中就够阈值的话，就成了"一个单引号封站"。
	if o.only != nil && !o.only[fp] {
		return ""
	}
	if o.exclude != nil && o.exclude[fp] {
		return ""
	}
	return fp
}

// sqliFingerprint 返回命中的指纹名，空串表示没命中。
func sqliFingerprint(in string, minLen int) string {
	if len(in) == 0 {
		return ""
	}
	s := collapseSpaces(lowerASCII(in))
	hasQuote := strings.ContainsAny(s, `'"`)

	// 1) 强特征：与长度无关
	if wordPair(s, "union", "select") {
		return "union select"
	}
	if containsAnyOf(s, "sleep(", "benchmark(", "pg_sleep(", "waitfor delay", "dbms_pipe.receive_message") {
		return "time-based"
	}
	if containsAnyOf(s, "information_schema", "mysql.user", "sys.objects", "sys.tables",
		"sys.columns", "pg_catalog", "all_tables", "sqlite_master") {
		return "metadata table"
	}
	if containsAnyOf(s, "into outfile", "into dumpfile", "load_file(", "xp_cmdshell", "sp_executesql") {
		return "file/exec primitive"
	}
	if stackedQuery(s) {
		return "stacked query"
	}

	// 1.5) 布尔比较：**恒真与矛盾都算**。
	// 攻击者做布尔盲注用的是矛盾式（`1 AND 1=2`，看响应差异），
	// 只认恒真就成了漏检。
	//
	// **日志场景的收紧**：要求出现过引号 ——
	// `Compare: 5 < 10 and 10 > 5` 这种正常句子在日志里很常见，
	// 而注入的布尔比较总伴随引号闭合（`1' and 1=2`）。
	if hasQuote && booleanComparison(s) {
		return "boolean comparison"
	}

	// 2) 需要引号上下文的特征
	if hasQuote {
		if subqueryFingerprint(s) {
			return "subquery in boolean context"
		}
		if quoteThenComment(s) {
			return "quote + comment"
		}
		if tautology(s) {
			return "boolean tautology"
		}
	}

	// 2.5) 语法性引号（错误型注入的探测形态）：整值就是引号，或 `1'`。
	if quoteProbing(s) {
		return "quote probing"
	}

	// 3) 弱特征：只在输入足够长时才认（避免 `1=1` 这类短文本误报）
	if len(s) >= minLen {
		// `and (select ...)` 这种子查询注入形态在正常文案里不会出现，没有引号也认
		if subqueryFingerprint(s) {
			return "subquery in boolean context"
		}
		if tautology(s) {
			return "boolean tautology"
		}
		if containsAnyOf(s, " or ", " and ") && strings.Contains(s, "=") && hasQuote {
			return "boolean expression"
		}
		if hasQuote && booleanComparison(s) {
			return "boolean comparison"
		}
	}
	return ""
}

// subqueryFingerprint 识别 `and (select ...)` / `or (select ...)` 形态。
func subqueryFingerprint(s string) bool {
	for _, kw := range []string{"and (", "or (", "and(", "or(", "&&(", "||("} {
		idx := 0
		for {
			i := strings.Index(s[idx:], kw)
			if i < 0 {
				break
			}
			rest := s[idx+i+len(kw):]
			if len(rest) > 32 {
				rest = rest[:32]
			}
			if strings.Contains(rest, "select") || strings.Contains(rest, "case when") {
				return true
			}
			idx += i + len(kw)
			if idx >= len(s) {
				break
			}
		}
	}
	return false
}

func tautology(s string) bool {
	for _, kw := range []string{" or ", " and ", "||", "&&"} {
		idx := 0
		for {
			i := strings.Index(s[idx:], kw)
			if i < 0 {
				break
			}
			rest := strings.TrimSpace(s[idx+i+len(kw):])
			if looksTautology(rest) {
				return true
			}
			idx += i + len(kw)
			if idx >= len(s) {
				break
			}
		}
	}
	return looksTautology(strings.TrimSpace(s))
}

func looksTautology(rest string) bool {
	pairs := []string{"1=1", "2>1", "1<2", "'1'='1", `"1"="1`, "'a'='a'", `"a"="a`, "true", "1 like 1"}
	for _, p := range pairs {
		if strings.HasPrefix(rest, p) {
			return true
		}
	}
	return false
}

// quoteThenComment 找"引号后面跟注释收尾"的形态。
//
// **日志场景的收紧**：`--` 在 SQL 里是**到行尾**的注释，所以注释标记之后
// 不该再有正常内容 —— `chapter 3' -- notes from the author` 是一句英文
// （另一条规则的负样本），而 `1'--`、`admin');--` 才是注入的收尾形态。
//
// **先做一次 O(n) 的必要条件判断**：下面的循环对每个引号都要做最多 64 字节的
// 子串搜索，64 KiB 的纯引号值要 1.36 ms；整串里没有注释标记时它不可能返回 true。
//
// **已知取舍（有意保留）**：每个引号只看后面 64 字节，更远的注释收尾形态认不出来。
// 这是为了不让"一行里成千上万个引号"退化成 O(n²)（上面那次 O(n) 预判只能挡住
// 完全没有注释标记的行）。真实注入的收尾形态（`1'--`、`admin');--`、
// `1'#`）都在引号紧后面，64 字节远远够；要放宽这个窗口，必须同时换掉这里的
// "每个引号做一次子串搜索"的做法，否则就是拿 CPU 换召回。
func quoteThenComment(s string) bool {
	if !strings.Contains(s, "--") && !strings.Contains(s, "/*") && !strings.ContainsRune(s, '#') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' && s[i] != '"' {
			continue
		}
		rest := s[i+1:]
		if len(rest) > 64 {
			rest = rest[:64]
		}
		if idx := strings.Index(rest, "--"); idx >= 0 && !hasWordsAfter(rest[idx+2:]) {
			return true
		}
		if trimmed := strings.TrimSpace(rest); strings.HasPrefix(trimmed, "#") && !hasWordsAfter(trimmed[1:]) {
			return true
		}
		if idx := strings.Index(rest, "/*"); idx >= 0 && !hasWordsAfter(rest[idx+2:]) {
			return true
		}
	}
	return false
}

// hasWordsAfter 判断这段里还有没有字母 —— 也就是"注释后面还跟着正常文字"。
// SQL 注释是到行尾的，注释后还有英文通常意味着这只是一句普通文案。
func hasWordsAfter(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// stackedQuery 找堆叠查询（`;` 后面接一条新语句）。
//
// **日志场景的收紧**：原实现只看分号后面是不是语句关键字，但日志行里
// `steps: 1; select the option below`、`Choose an item; update your profile`
// 这种正常句子到处都是。要求分号**前面出现过引号** ——
// 注入的堆叠形态必然带引号闭合（`1'; drop table users--`），
// 正常文案的分号不带引号。
func stackedQuery(s string) bool {
	// 同样的 O(n) 前置判断：按 `;` 展开的循环对每个分号都要 TrimSpace 与前缀比较，
	// 512 KiB 的分号串就是 O(n²)，比上面那个更狠。
	if !containsAnyKeyword(s) {
		return false
	}
	quoteBefore := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' {
			quoteBefore = true
			continue
		}
		if s[i] != ';' || !quoteBefore {
			continue
		}
		rest := strings.TrimSpace(s[i+1:])
		for _, kw := range stackedKeywords {
			if hasKeywordPrefix(rest, kw) {
				return true
			}
		}
	}
	return false
}

// hasKeywordPrefix 判断 rest 是否以关键字开头，比对时把 `+` 与空格视为等价。
//
// 为什么需要：查询串里的 `+` 代表空格，但 **REQUEST_URI 保留的是原始串**。
// 于是 `?id=1;DROP+TABLE+users` 走到这里，分号后面拿到 `drop+table+users`，
// 用 `HasPrefix(rest, "drop ")` 配不上 —— 这条堆叠注入曾整条漏检。
func hasKeywordPrefix(rest, kw string) bool {
	if len(rest) < len(kw) {
		return false
	}
	for i := 0; i < len(kw); i++ {
		c := rest[i]
		if c == '+' {
			c = ' '
		}
		if c != kw[i] {
			return false
		}
	}
	return true
}

var stackedKeywords = []string{
	"select ", "insert ", "update ", "delete ", "drop ", "create ", "alter ", "exec ", "shutdown",
}

// containsAnyKeyword 判断串里是否**可能出现**任何一个堆叠查询关键字。
// 用关键字前三个字符做一次线性判断，作为 stackedQuery 的 O(n) 前置。
func containsAnyKeyword(s string) bool {
	for _, kw := range stackedKeywords {
		n := 3
		if len(kw) < n {
			n = len(kw)
		}
		if strings.Contains(s, kw[:n]) {
			return true
		}
	}
	return false
}

func containsAnyOf(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// wordPair 判断 s 里是否按顺序出现两个独立单词（`union` … `select`）。
func wordPair(s, a, b string) bool {
	ia := indexWord(s, a)
	if ia < 0 {
		return false
	}
	return indexWord(s[ia+len(a):], b) >= 0
}

func indexWord(s, w string) int {
	idx := 0
	for {
		i := strings.Index(s[idx:], w)
		if i < 0 {
			return -1
		}
		pos := idx + i
		leftOK := pos == 0 || !isWordByte(s[pos-1])
		end := pos + len(w)
		rightOK := end >= len(s) || !isWordByte(s[end])
		if leftOK && rightOK {
			return pos
		}
		idx = pos + 1
		if idx >= len(s) {
			return -1
		}
	}
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// booleanComparison 识别布尔盲注的比较式：`and 1=2`、`or 2>1`、`and 'a'='b'`。
//
// 与 tautology 的区别：**不管真假**。攻击者用矛盾式做盲注（看响应差异），
// 只认恒真就是漏。
//
// 误报侧的处理：要求 and/or 两侧是**数字或引号包起来的字面量**，
// 正常文案里不会出现。
func booleanComparison(s string) bool {
	for _, kw := range []string{" and ", " or ", "&&", "||"} {
		idx := 0
		for {
			i := strings.Index(s[idx:], kw)
			if i < 0 {
				break
			}
			rest := strings.TrimSpace(s[idx+i+len(kw):])
			if looksComparison(rest) {
				return true
			}
			idx += i + len(kw)
			if idx >= len(s) {
				break
			}
		}
	}
	return false
}

// looksComparison 判断开头是不是 `操作数 比较符 操作数`。
func looksComparison(rest string) bool {
	if len(rest) < 3 {
		return false
	}
	// 操作数一：数字、引号字面量、或 true/false/null
	var operandLen int
	switch {
	case rest[0] >= '0' && rest[0] <= '9':
		operandLen = 1
		for operandLen < len(rest) && (rest[operandLen] >= '0' && rest[operandLen] <= '9' ||
			rest[operandLen] == '.') {
			operandLen++
		}
	case rest[0] == '\'' || rest[0] == '"':
		q := rest[0]
		end := strings.IndexByte(rest[1:], q)
		if end < 0 {
			return false
		}
		operandLen = end + 2
	case strings.HasPrefix(rest, "true"), strings.HasPrefix(rest, "false"), strings.HasPrefix(rest, "null"):
		operandLen = 4
	default:
		return false
	}
	rest = strings.TrimSpace(rest[operandLen:])
	if rest == "" {
		return false
	}
	// 比较符（含 SQL 的 <>、!=、>=、<=）
	switch rest[0] {
	case '=', '<', '>', '!':
	default:
		return false
	}
	opLen := 1
	if len(rest) > 1 && (rest[1] == '=' || rest[0] == '<' && rest[1] == '>') {
		opLen = 2
	}
	rest = strings.TrimSpace(rest[opLen:])
	if rest == "" {
		return false
	}
	// 操作数二：数字、引号字面量、true/false/null
	switch {
	case rest[0] >= '0' && rest[0] <= '9':
		return true
	case rest[0] == '\'' || rest[0] == '"':
		q := rest[0]
		return strings.IndexByte(rest[1:], q) >= 0
	case strings.HasPrefix(rest, "true"), strings.HasPrefix(rest, "false"), strings.HasPrefix(rest, "null"):
		return true
	}
	return false
}

// quoteProbing 识别"语法性引号"：整值就是引号，或数字后紧跟引号。
//
// 为什么敢拦：`O'Brien`、`it's`、`"quoted phrase"` 里引号都在**词内或成对**，
// 而错误型注入探测发的是一个**孤零零的引号**（`'`）或 `1'` 这种数字 + 引号。
// 这一点与 ModSecurity CRS 的判断一致 —— 单独引号在 CRS 里也是记分命中。
func quoteProbing(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || len(t) > 8 {
		return false
	}
	// 整值只有引号：' / " / '' / \"
	onlyQuotes := true
	for i := 0; i < len(t); i++ {
		if t[i] != '\'' && t[i] != '"' && t[i] != '`' {
			onlyQuotes = false
			break
		}
	}
	if onlyQuotes {
		return true
	}
	// 数字后紧跟引号：1' / 42"
	i := 0
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	if i == 0 || i == len(t) {
		return false
	}
	switch t[i] {
	case '\'', '"', '`':
		// 引号后面只允许再跟引号（1''）
		for j := i; j < len(t); j++ {
			if t[j] != '\'' && t[j] != '"' && t[j] != '`' {
				return false
			}
		}
		return true
	}
	return false
}

// ---------------------------------------------------------------- XSS

var (
	xssSchemeList = []string{"javascript:", "vbscript:", "data:text/html", "data:application/xhtml"}
	xssEventNames = []string{
		"onerror", "onload", "onclick", "onfocus", "onblur", "onmouseover", "onmouseenter",
		"onsubmit", "onchange", "onstart", "ontoggle", "onanimationstart", "onscroll",
	}
)

// detectXSS 判断文本是否含可利用的 XSS 形态。
//
// 关键收紧：**事件处理器必须与标签上下文同时出现**（`<` 后紧跟字母、
// 且属性在同一个标签内、前面是空白或引号）—— 光有 `onerror=` 是正常文案
// （"the onerror handler is documented"）。
func detectXSS(s string) string {
	low := lowerASCII(s)
	if len(low) < 4 {
		return ""
	}
	if strings.Contains(low, "<script") {
		return "script tag"
	}
	for _, scheme := range xssSchemeList {
		idx := strings.Index(low, scheme)
		if idx < 0 {
			continue
		}
		// **日志场景的收紧**：伪协议后面必须紧跟可执行内容。
		// 日志里 `<a href="javascript:void(0)">`（正常菜单）与
		// `Read 'JavaScript: The Good Parts'`（书名）都会命中 `javascript:`，
		// 而真载荷后面跟的是 `alert(` / `eval(` 这类。
		// （RE2 不支持回溯，所以用代码判断而不是一条正则。）
		if scheme == "javascript:" || scheme == "vbscript:" {
			if !isInlineScriptStart(low[idx+len(scheme):]) {
				continue
			}
		}
		return "scheme " + strings.TrimSuffix(scheme, ":")
	}
	if strings.Contains(low, "expression(") && strings.Contains(low, "(") {
		return "css expression"
	}
	if tagStart := strings.IndexByte(low, '<'); tagStart >= 0 {
		if handler := eventHandlerNear(low, tagStart); handler != "" {
			return "event handler " + handler
		}
	}
	if strings.Contains(low, "document.cookie") || strings.Contains(low, "document.write(") {
		return "dom sink"
	}
	return ""
}

// isInlineScriptStart 判断伪协议冒号后面跟的是不是可执行内容。
// 空格（书名 `JavaScript: The Good Parts`）与 `void(`（`javascript:void(0)`）
// 都排除掉。
func isInlineScriptStart(rest string) bool {
	if rest == "" {
		return false
	}
	if strings.HasPrefix(rest, "void") {
		return false
	}
	c := rest[0]
	return (c >= 'a' && c <= 'z') || c == '$' || c == '('
}

// eventHandlerNear 在 '<' 之后、标签结束之前找 on* 事件属性。
//
// 两条收紧条件（都是为了压误报）：
//  1. '<' 后面必须紧跟字母（是标签名），所以 `3 < 5 onerror = x` 不算；
//  2. 事件属性必须出现在同一个标签内（'<' 与 '>' 之间），不能跨标签乱找。
func eventHandlerNear(s string, lt int) string {
	if lt+1 >= len(s) {
		return ""
	}
	c := s[lt+1]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return ""
	}
	end := lt + 128
	if end > len(s) {
		end = len(s)
	}
	seg := s[lt:end]
	if gt := strings.IndexByte(seg, '>'); gt >= 0 {
		seg = seg[:gt]
	}
	for _, h := range xssEventNames {
		i := strings.Index(seg, h)
		if i < 0 {
			continue
		}
		// 前面必须是属性边界，避免 `microphone` 里命中 `phone` 这类
		if i > 0 {
			prev := seg[i-1]
			if prev != ' ' && prev != '\t' && prev != '\n' && prev != '/' && prev != '"' && prev != '\'' {
				continue
			}
		}
		rest := strings.TrimLeft(seg[i+len(h):], " \t\r\n")
		if strings.HasPrefix(rest, "=") {
			return h
		}
	}
	return ""
}

// ---------------------------------------------------------------- 路径穿越

var (
	pathWrappers = []string{"php://", "file://", "expect://", "phar://", "zip://", "data://"}
	// 不靠回溯层数、本身就该直接立案的敏感目标
	sensitivePaths = []string{
		"/etc/passwd", "/etc/shadow", "/proc/self/environ",
		`c:\windows\win.ini`, "boot.ini", "web-inf/web.xml",
	}
)

// detectPathTraversal 判断文本是否是路径穿越。
//
// minDepth 是要求的最少回溯层数：只要求一级会把 `?file=../templates/x.html`
// 这类正常相对路径打死（单级相对路径在业务里很常见）。
// 命中敏感文件或流包装器时不看层数 —— 那些本身就是结论。
func detectPathTraversal(s string, minDepth int) string {
	low := lowerASCII(s)
	depth := 0
	for i := 0; i+2 < len(low); i++ {
		if low[i] == '.' && low[i+1] == '.' && (low[i+2] == '/' || low[i+2] == '\\') {
			depth++
			i += 2
		}
	}
	if depth >= minDepth && minDepth > 0 {
		return "path traversal"
	}
	for _, w := range pathWrappers {
		if strings.Contains(low, w) {
			return "lfi wrapper " + strings.TrimSuffix(w, "://")
		}
	}
	for _, p := range sensitivePaths {
		if strings.Contains(low, p) {
			return "sensitive path"
		}
	}
	return ""
}

// ---------------------------------------------------------------- 命令注入

// shellCommands 是"分隔符后面出现就立案"的命令名表。
//
// 这份表不可能列全（`;pwd`、`;echo`、`;w` 一类都曾经不在表里），
// 所以它的定位是高置信度信号：表里的命令 + 分隔符 → 直接立案。
// 新命令往这里加就行，不要再靠一条条加规则。
var shellCommands = []string{
	// 信息收集
	"id", "whoami", "uname", "hostname", "w", "who", "ps", "pwd", "env", "printenv",
	"date", "uptime", "last", "lastlog", "df", "du", "free", "top", "lsof", "ss",
	"ifconfig", "ipconfig", "ip", "arp", "route", "netstat", "systeminfo", "tasklist",
	"nslookup", "dig", "host", "ping", "traceroute", "tracert", "nmap", "nc", "ncat",
	"telnet", "ftp", "ssh", "scp", "rsync", "curl", "wget",
	// 文件与内容
	"cat", "tac", "head", "tail", "more", "less", "ls", "dir", "find", "locate",
	"grep", "egrep", "fgrep", "awk", "sed", "cut", "sort", "uniq", "wc", "strings",
	"xxd", "od", "base64", "md5sum", "sha1sum", "sha256sum", "cp", "mv", "rm",
	"mkdir", "rmdir", "touch", "ln", "chmod", "chown", "chgrp", "tar", "zip", "unzip",
	"gzip", "gunzip", "bzip2", "7z",
	// 执行与解释器
	"sh", "bash", "dash", "zsh", "ksh", "csh", "ash", "busybox", "python", "python3",
	"perl", "ruby", "php", "node", "nodejs", "lua", "java", "gcc", "g++", "make",
	"cmd", "cmd.exe", "powershell", "pwsh", "cscript", "wscript", "mshta", "rundll32",
	"regsvr32", "certutil", "bitsadmin", "wmic", "schtasks", "reg", "net", "sc",
	// 进程与服务控制
	"kill", "killall", "pkill", "sudo", "su", "systemctl", "service", "crontab", "at",
	"mount", "umount", "insmod", "modprobe", "docker", "kubectl", "git", "vim", "vi",
	"nano", "emacs", "echo", "printf", "tee", "xargs", "eval", "exec", "source", "export",
	"arch", "nproc", "hostid", "getconf", "lscpu", "lsblk", "dmesg", "journalctl",
	"getent", "dmidecode", "vmstat", "mpstat", "iostat", "pidof", "pgrep", "stat",
	"readlink", "realpath", "shred", "fdisk", "runuser", "doas", "screen", "tmux",
	"nohup", "setsid", "timeout", "watch", "tr", "seq", "expr", "bc", "socat",
	"tftp", "sysctl", "groups", "users", "wall",
	// 提权、持久化与取证（审计补：命令替换里这几个很常见）
	"dd", "openssl", "chattr", "lsattr", "mkfifo", "mknod", "history", "setfacl",
	"iptables", "nft", "tcpdump", "strace", "ltrace", "gdb", "objdump", "readelf",
	"nm", "ldd", "rmmod", "lsmod", "modinfo", "swapoff", "ldconfig", "updatedb",
	"mlocate",
}

// containsShellCommand 判断这段文本里有没有出现命令名（可带路径前缀）。
// 用在 `$(...)` 与反引号的内容判定上：命令替换里得真的有命令，光有括号不算。
func containsShellCommand(s string) bool {
	s = strings.TrimSpace(trimPathPrefix(strings.TrimSpace(s)))
	if s == "" {
		return false
	}
	for _, cmd := range shellCommands {
		if !strings.HasPrefix(s, cmd) {
			continue
		}
		after := s[len(cmd):]
		if after == "" {
			return true
		}
		switch after[0] {
		case ' ', '\t', '/', '-', ';', '|', '&', '\n', '\r':
			return true
		}
	}
	return false
}

// trimPathPrefix 去掉命令名前的路径前缀（`/bin/id`、`./id`、`../../bin/id` → `id`）。
//
// **只在整段看起来是"纯路径"时才剥**（不含空格）：`cat /etc/passwd` 里也有 `/`，
// 无条件取最后一段会把命令名本身剥成 `passwd` —— 实测那样会让
// `; cat /etc/passwd`、`;cat${IFS}/etc/passwd` 这几条正样本漏检。
func trimPathPrefix(s string) string {
	// **只看开头一段**：调用方的输入可能是"整行剩余文本"（containsShellChars
	// 对每个分隔符都要调用它），而下面的 ContainsAny / LastIndexByte 都是 O(len(s))，
	// 于是 10 万个分号的单行会退化成 O(n²) —— 实测单行 2.23 秒、整行扫描 2.8 秒。
	// 命令名加路径不会超过 200 字节，多出来的部分对判断没有意义。
	const maxPrefix = 200
	if len(s) > maxPrefix {
		s = s[:maxPrefix]
	}
	if strings.ContainsAny(s, " \t") {
		return s // "命令 + 参数"形态，别动它
	}
	// 剥掉开头的 ./ 与 ../（`$(./id)`、`$(../../bin/id)`）
	for {
		switch {
		case strings.HasPrefix(s, "../"):
			s = s[3:]
			continue
		case strings.HasPrefix(s, "./"):
			s = s[2:]
			continue
		}
		break
	}
	// 再取最后一段（`/usr/bin/id`、`bin/id` 都剥成 `id`）
	if k := strings.LastIndexByte(s, '/'); k >= 0 && k+1 < len(s) {
		s = s[k+1:]
	}
	return s
}

// shellArgFollows 判断命令名后面是不是真的到了命令边界，
// 而不是命令名的一部分（`ls` 不能匹配 `lsass`、`id` 不能匹配 `identity`）。
func shellArgFollows(after string) bool {
	if after == "" {
		return true
	}
	switch after[0] {
	// `+` 也算：它在前端/后端的表单解码里代表空格（PHP 的 urldecode 就解 `+`），
	// 所以 `;cat+/etc/passwd` 在 Cookie/头里是成立的分隔。
	case ' ', '\t', '+', '-', ';', '|', '&', '\n', '\r':
		return true
	}
	return false
}

// looksLikeCommandLine 是**换行分隔**的额外收紧条件。
//
// 为什么只有换行需要它：`;`、`|`、`&&` 在正常文案里基本不出现，而换行到处都是
// —— 一段多行文本里"某行以 cat/sh/id 开头"完全可能。所以换行后跟命令名时，
// 还要看它像不像一条命令：命令到此为止，或者参数里有路径/选项/变量/重定向。
func looksLikeCommandLine(after string) bool {
	if after == "" {
		return true
	}
	switch after[0] {
	case ';', '|', '&':
		return true
	}
	arg := strings.TrimLeft(after, " \t+")
	if arg == "" {
		return true
	}
	if len(arg) > 200 {
		arg = arg[:200]
	}
	return strings.ContainsAny(arg, "/-$`<>")
}

// containsShellChars 判断文本里有没有命令注入的形态。
//
// 光看有没有 `;`、`|` 会把 `gzip, deflate, br;q=1.0`、`Cats; dogs` 全打成注入，
// 所以要求分隔符后面**确实是命令**，而且命令后面跟着命令边界。
//
// ${IFS} 自己折叠一次（不再只靠规则链的 normalizeIFS）。
//
// 理由：`;cat${IFS}/etc/passwd` 在 shell 里 `;` 与 `cat` 之间**就是空格**，但
// 本算子只看字面空白，`${IFS}` 不认，于是它返回空 —— 今天不漏检纯粹因为用到
// 它的规则都在链里带了 normalizeIFS，属于**隐式依赖**：新加一条算子/规则忘了
// 那个变换，攻击就静默漏过去（实测：算子直接跑返回空，先 ifsToSpace 再跑立刻
// 命中 "command after separator: cat"）。判定写在算子内部，这个依赖就不存在了。
//
// 代价可控：ifsToSpace 有 `strings.Contains(s, "IFS")` 的前置判断，普通日志行
// 只多一次子串扫描（与下面的 lowerASCII 同量级），不会引入分配。
func containsShellChars(s string) string {
	if strings.Contains(s, "IFS") {
		s = ifsToSpace(s)
	}
	low := lowerASCII(s)
	// $(...) 与反引号：**日志场景的收紧** —— 内容里必须出现命令名。
	// 光看 `$(` 会把 jQuery 的 `$(document).ready(function(){...})`、
	// 模板里的 `total price is $(price) * 2` 全打成命令注入，
	// 而这条规则是 5 分独立拦的。
	if i := strings.Index(low, "$("); i >= 0 {
		if j := strings.IndexByte(low[i+2:], ')'); j > 0 {
			if containsShellCommand(low[i+2 : i+2+j]) {
				return "command substitution $()"
			}
		}
	}
	// 反引号：要求里面也是命令形态。
	// `Set the ` + "`PATH`" + ` variable in your shell profile` 这种写法在日志里很常见，
	// 而 ` + "`id`" + `、` + "`cat /etc/passwd`" + ` 才是命令替换。
	if strings.Count(low, "`") >= 2 {
		if i := strings.IndexByte(low, '`'); i >= 0 {
			if j := strings.IndexByte(low[i+1:], '`'); j >= 0 {
				if containsShellCommand(low[i+1 : i+1+j]) {
					return "command substitution backtick"
				}
			}
		}
	}
	for i := 0; i < len(low); i++ {
		c := low[i]
		hardSep := c == ';' || c == '|' || c == '&'
		newlineSep := c == '\n' || c == '\r'
		if !hardSep && !newlineSep {
			continue
		}
		rest := strings.TrimLeft(low[i+1:], " \t")
		// 命令名前面可能带路径：`/bin/hostname`、`/usr/bin/id`
		rest = trimPathPrefix(rest)
		for _, cmd := range shellCommands {
			if !strings.HasPrefix(rest, cmd) {
				continue
			}
			after := rest[len(cmd):]
			if !shellArgFollows(after) {
				continue
			}
			if newlineSep && !looksLikeCommandLine(after) {
				continue
			}
			return "command after separator: " + cmd
		}
	}
	if strings.Contains(low, "> /") || strings.Contains(low, ">> /") || strings.Contains(low, "> /etc") {
		return "redirect to path"
	}
	if strings.HasPrefix(strings.TrimSpace(low), "wget http") ||
		strings.HasPrefix(strings.TrimSpace(low), "curl http") ||
		strings.Contains(low, " -o /") || strings.Contains(low, " --output ") {
		return "remote download"
	}
	return ""
}

// ---------------------------------------------------------------- Webshell

var (
	webShellFuncs = []string{
		"eval(", "assert(", "system(", "exec(", "passthru(", "shell_exec(", "popen(",
		"proc_open(", "base64_decode(", "create_function(", "call_user_func(", "preg_replace(",
	}
	webShellVars = []string{
		"$_get", "$_post", "$_request", "$_cookie", "$_server", "$_files",
		"request.form", "request.query", "runtime.getruntime().exec",
	}
)

// isWebshellContent 判断文本是不是 webshell 代码。
//
// 用的是"执行函数 + 上下文"的组合：只有执行函数不算（`system is down`、
// `we evaluated the proposal` 里有 system/eval 字样），还得配上用户输入源。
func isWebshellContent(s string) string {
	low := lowerASCII(s)
	hasFunc := ""
	for _, f := range webShellFuncs {
		if strings.Contains(low, f) {
			hasFunc = strings.TrimSuffix(f, "(")
			break
		}
	}
	if hasFunc == "" {
		if strings.Contains(low, "<%@") || strings.Contains(low, "<jsp:") {
			return "jsp tag"
		}
		return ""
	}
	for _, v := range webShellVars {
		if strings.Contains(low, v) {
			return hasFunc + " + 用户输入"
		}
	}
	// 只有函数调用没有变量源：交给别的规则，不在这里单独立案（降误报）
	return ""
}

// ---------------------------------------------------------------- 工具

// lowerASCII 只把 A-Z 折成小写，不碰其它字节。
// 相比 strings.ToLower 不分配、不受 Unicode 影响 —— 攻击载荷是 ASCII 形态。
func lowerASCII(in string) string {
	need := false
	for i := 0; i < len(in); i++ {
		if in[i] >= 'A' && in[i] <= 'Z' {
			need = true
			break
		}
	}
	if !need {
		return in
	}
	out := make([]byte, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// collapseSpaces 折叠连续空白。
//
// **先判断有没有要折叠的**：Builder.Grow 是无条件分配的，而正常请求里的值
// 绝大多数根本不需要折叠 —— 否则每个请求白搭几次分配。
func collapseSpaces(s string) string {
	if !needsCollapse(s) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	prev := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		isWS := c == ' ' || c == '\t' || c == '\n' || c == '\r'
		if isWS {
			if prev {
				continue
			}
			sb.WriteByte(' ')
			prev = true
			continue
		}
		sb.WriteByte(c)
		prev = false
	}
	return sb.String()
}

// needsCollapse 判断是否存在需要折叠的空白：
// 连续空白，以及 TAB/换行（它们会被折成单个空格，即使只有一个）。
func needsCollapse(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\t', '\n', '\r':
			return true
		case ' ':
			if i > 0 && s[i-1] == ' ' {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- 注册

// semanticOperatorNames 是所有已实现的语义算子名（小写）。
var semanticOperatorNames = map[string]bool{
	"detectsqli":          true,
	"detectxss":           true,
	"detectpathtraversal": true,
	"containsshellchars":  true,
	"iswebshellcontent":   true,
}

// operatorParamAllow 声明每个算子支持的参数键。
//
// **所有**算子都要过这张表（不只是语义算子）—— 否则 `regex + min_depth: 2`
// 这种"写了但不生效"的参数会被静默接受。判定"规则写了哪个参数"用非零值，
// 所以显式写 0（如 `min_fingerprint_len: 0`）等同于没写。
var operatorParamAllow = map[string]map[string]bool{
	"regex": {"pattern": true},
	"pm":    {"patterns": true},
	"anyof": {"operators": true},

	"detectsqli":          {"min_fingerprint_len": true, "fingerprints": true, "exclude_fingerprints": true},
	"detectxss":           {},
	"detectpathtraversal": {"min_depth": true},
	"containsshellchars":  {},
	"iswebshellcontent":   {},
}

// semanticParamAllow 保留为语义算子的子集视图（buildSemantic 之外的地方引用它）。
var semanticParamAllow = operatorParamAllow

// buildSemantic 按算子名构造判定函数；不支持的参数已在调用前拦掉。
// detectSQLi 的指纹名也在这里校验：写错直接拒绝该规则。
func buildSemantic(op string, p yamlParams) (func(string) string, error) {
	switch op {
	case "detectsqli":
		only, err := fingerprintSet(p.Fingerprints)
		if err != nil {
			return nil, err
		}
		excl, err := fingerprintSet(p.ExcludeFingerprints)
		if err != nil {
			return nil, err
		}
		o := sqliOp{minLen: p.MinFingerprintLen, only: only, exclude: excl}
		return o.eval, nil
	case "detectxss":
		return detectXSS, nil
	case "detectpathtraversal":
		depth := p.MinDepth
		return func(s string) string { return detectPathTraversal(s, depth) }, nil
	case "containsshellchars":
		return containsShellChars, nil
	case "iswebshellcontent":
		return isWebshellContent, nil
	}
	return nil, fmt.Errorf("未实现的语义算子 %q", op)
}
