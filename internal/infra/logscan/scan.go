package logscan

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Rule 是一条检测规则。
//
// 匹配语义与 WAF 规则一致：先在 rule.Chain（变换链）处理过的文本上匹配，
// 这样编码/混淆过的载荷也能认出来。
// Pattern 对应 regex 算子，Keywords 对应 pm（多关键词）算子，
// Semantic 对应 detectSQLi / detectXSS 这类语义算子（三者取其一）。
type Rule struct {
	ID       string
	Name     string
	Severity string
	Category string
	Pattern  *regexp.Regexp
	Keywords []string
	Chain    []Transform

	// Semantic 是语义算子的判定函数，返回命中的指纹名（空串表示未命中）。
	// 有些判据是多组特征的组合（SQL 注入要看结构、WebShell 要看执行函数+上下文），
	// 一条正则表达不清楚，就交给它判断。
	Semantic func(string) string

	// TransformNames 与 Chain 一一对应，用于算链指纹（同链只归一化一次）。
	TransformNames []string

	// chainKey 是变换链的指纹，用于同一行内复用归一化结果。
	chainKey string
	lowerKW  []string
	// decodeChain 只含链里的解码类变换，用于判断"这次命中到底是不是靠解码"。
	// 单纯大小写/空白归一不算解码——否则满屏都是"解码后命中"，标记就失去意义了。
	decodeChain    []Transform
	decodeNames    []string
	decodeKey      string
	decodeKeyValid bool
}

// decodeTransforms 是"还原/去混淆"性质的变换：它们能让原本看不出来的载荷现形。
// 这里刻意不收 lowercase / compressWhitespace / trim 这类纯规范化步骤 ——
// 那不是绕过手法，算进来的话每个大写攻击都会被标成"解码后命中"，标记就废了。
var decodeTransforms = map[string]bool{
	"urlDecode": true, "urlDecodeUni": true, "htmlEntityDecode": true,
	"jsDecode": true, "cssDecode": true, "sqlHexDecode": true,
	"base64Decode": true, "hexDecode": true,
	"normalizeIFS": true, "expandShellVars": true,
	"removeShellQuotes": true, "removeShellEscapes": true,
	"replaceComments": true, "removeComments": true,
	"normalizePath": true, "removeNulls": true,
}

// compile 做一次性的预处理（预小写关键词、算链指纹）。
func (r *Rule) compile() {
	if r.Severity == "" {
		r.Severity = SevMedium
	}
	// 这里不做过滤：lowerKW 必须与 Keywords 同下标，
	// 否则 Match 里按下标取回的关键词会错位（取到空串就会被判为未命中）。
	r.lowerKW = make([]string, 0, len(r.Keywords))
	for _, kw := range r.Keywords {
		r.lowerKW = append(r.lowerKW, strings.ToLower(strings.TrimSpace(kw)))
	}
	r.chainKey = strings.Join(r.TransformNames, ">")
	for i, name := range r.TransformNames {
		if decodeTransforms[name] {
			r.decodeChain = append(r.decodeChain, r.Chain[i])
			r.decodeNames = append(r.decodeNames, name)
		}
	}
	r.decodeKeyValid = len(r.decodeChain) > 0
	r.decodeKey = "dec:" + strings.Join(r.decodeNames, ">")
}

// Match 在给定文本上匹配；命中返回匹配到的片段或关键词。
func (r *Rule) Match(s string) string {
	if r.Semantic != nil {
		if m := r.Semantic(s); m != "" {
			return m
		}
	}
	if r.Pattern != nil {
		// 用 FindStringIndex 而不是 FindString：后者把"匹配到空串"与"没匹配"
		// 都返回空串 —— 一条能匹配空串的 pattern（`\d*`、`foo|`）会让规则
		// **永久静默失效**（实测 `\d*` 对 "abc123" 返回 ""）。
		if loc := r.Pattern.FindStringIndex(s); loc != nil {
			if loc[0] == loc[1] {
				return "（空匹配）"
			}
			return s[loc[0]:loc[1]]
		}
	}
	if len(r.lowerKW) > 0 {
		lower := strings.ToLower(s)
		for i, kw := range r.lowerKW {
			// 下标必须与 Keywords 一一对应：compile 时若过滤掉空串而这里不过滤，
			// 取到的就是另一个关键词（甚至空串），规则会静默失效。
			if kw == "" || i >= len(r.Keywords) {
				continue
			}
			if strings.Contains(lower, kw) {
				return r.Keywords[i]
			}
		}
	}
	return ""
}

// CompileRules 对一批规则做预处理（预小写关键词、算变换链指纹）。
// 没指定变换链的规则会套用 DefaultChain —— 这样零散定义的规则也能吃到解码能力。
func CompileRules(rules []Rule) []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	for i := range out {
		if out[i].Chain == nil {
			out[i].Chain = DefaultChain
			out[i].TransformNames = DefaultTransformNames
		}
		out[i].compile()
	}
	return out
}

// Hit 是一条命中记录。
type Hit struct {
	LineNo   int    `json:"line_no"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Matched  string `json:"matched"`
	Line     string `json:"line"`
	SourceIP string `json:"source_ip"`
	Time     string `json:"time"`
	// Decoded 为 true 表示原始行没命中，是变换（解码/去混淆）之后才命中的。
	Decoded bool `json:"decoded"`
}

// IPCount 来源 IP 计数。
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// Result 是一次扫描的结果。
type Result struct {
	Path         string         `json:"path"`
	Scanned      int            `json:"scanned"`
	Hits         []Hit          `json:"hits"`
	BySeverity   map[string]int `json:"by_severity"`
	ByCategory   map[string]int `json:"by_category"`
	TopIPs       []IPCount      `json:"top_ips"`
	HitLineCount int            `json:"hit_line_count"`
	DecodedHits  int            `json:"decoded_hits"`
	RuleCount    int            `json:"rule_count"`
	// Correlations 是跨行关联出来的发现（爆破统计、失败后成功等）。
	Correlations []Correlation `json:"correlations"`
	// Kind 是本次实际使用的规则集（web / system / all），KindAuto 表示它是自动推断的。
	Kind     string `json:"kind"`
	KindAuto bool   `json:"kind_auto"`
}

// Scan 逐行扫描文本。
//
// 每行对每条规则做两件事：先在原文上匹配，再在该规则的变换链处理后的文本上匹配；
// 只有变换后才命中的，标 Decoded —— 那通常意味着对方刻意做了混淆。
// maxLineBytes 是单行参与匹配的最大长度（超出部分直接截断）。
//
// 为什么需要：日志内容在 AWD 场景完全由攻击者控制，而语义算子会对"整行剩余文本"
// 做扫描 —— containsShellChars 对每个分隔符都要处理剩余部分。实测 10 万个分号的
// 单行要 2.8 秒，2000 行 8KB 分号能把界面卡住两分钟。日志行本来也不该有 8KB 正文。
const maxLineBytes = 8 << 10

// Scan 扫描文本，返回命中结果。日志类型由它自己按路径与内容推断
// （等价于 ScanWithKind(..., "")），保留这个签名只为不惊动既有调用方。
func Scan(text, path string, rules []Rule) Result {
	return ScanWithKind(text, path, rules, "")
}

// ScanWithKind 扫描文本，用调用方**已经算好**的日志类型决定要不要跑跨行认证关联。
//
// kind 传 "" 表示"没有算过"，由本函数按路径与内容推断（旧行为，完全等价）。
// 为什么要这个入口：本函数内部还会再调一次 GuessLogKind，而**规则筛选**是调用方
// 用另一个 kind 做的（service/logscan.go 先算 kind、RulesForKind 筛规则、再调 Scan）。
// 两者判出来不一样时，就会在错的规则集对应的日志上做关联分析 —— 前 300 行 syslog
// 占多数、后面夹着 web 行的混合日志会被判成 KindSystem，于是在 web 行上跑
// AnalyzeAuth（sshd/sudo 那套结构），既出噪音也对不上调用方显示的 kind。
// 把决定权收归调用方，内部这次推断只作兼容兜底。
//
// 不做成"只读 Result.Kind"：Result 是 Scan 的返回值，进来时还是空的，没有可读的 kind。
func ScanWithKind(text, path string, rules []Rule, kind string) Result {
	if rules == nil {
		rules = AllRules()
	}
	kindAuto := kind == "" || kind == KindAuto
	if kindAuto {
		kind = GuessLogKind(path, text)
	}
	res := Result{
		Path:       path,
		Hits:       []Hit{},
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
		RuleCount:  len(rules),
		// 把本次实际使用的类型回填给调用方：以前它必须自己再写一遍，
		// 而内部那次推断又和它不一致。
		Kind:     kind,
		KindAuto: kindAuto,
	}
	ipCount := map[string]int{}
	hitLines := map[int]bool{}

	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		// 单行长度上限：日志内容在 AWD 场景完全由攻击者控制，而语义算子里有对
		// "整行剩余文本"的扫描（containsShellChars 对每个分隔符都要处理剩余部分）。
		// 实测 10 万个分号的单行要 2.8 秒，`tail -n 2000` 下 2000 行 8KB 分号能把
		// 界面卡住两分钟。日志行本来也不该有这个量级，截断到 8KB 后照常扫。
		//
		// 这一刀必须**退到 rune 边界**：直接 line[:8<<10] 会把正好跨在第 8192
		// 字节上的多字节字符砍成半个，切出来的行本身就是非法 UTF-8，后面的匹配
		// 与证据行全建在坏串上。
		if len(line) > maxLineBytes {
			line = cutAtRuneBoundary(line, maxLineBytes)
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		res.Scanned++

		// 同一行内，相同变换链只算一次
		normCache := map[string]string{}
		getNorm := func(key string, chain []Transform) string {
			if key == "" {
				return line
			}
			if v, ok := normCache[key]; ok {
				return v
			}
			v := ApplyChain(line, chain)
			normCache[key] = v
			return v
		}

		var matched []struct {
			rule    *Rule
			text    string
			decoded bool
		}
		for ri := range rules {
			r := &rules[ri]
			norm := getNorm(r.chainKey, r.Chain)

			onRaw := r.Match(line)
			onNorm := ""
			if norm != line {
				onNorm = r.Match(norm)
			}
			if onRaw == "" && onNorm == "" {
				continue
			}
			mtext := onRaw
			decoded := false
			if onRaw == "" {
				mtext = onNorm
				// 命中依赖归一化时，再单独跑一遍"只做解码"的链：
				// 只有解码这一步确实改变了文本，才算真正的解码/编码绕过。
				if r.decodeKeyValid {
					decOnly := getNorm(r.decodeKey, r.decodeChain)
					decoded = decOnly != line
				}
			}
			matched = append(matched, struct {
				rule    *Rule
				text    string
				decoded bool
			}{r, mtext, decoded})
		}
		if len(matched) == 0 {
			continue
		}

		ip := extractIP(line)
		if ip != "" {
			ipCount[ip]++
		}
		hitLines[i+1] = true
		ts := extractTime(line)

		for _, m := range matched {
			if m.decoded {
				res.DecodedHits++
			}
			res.Hits = append(res.Hits, Hit{
				LineNo:   i + 1,
				RuleID:   m.rule.ID,
				RuleName: m.rule.Name,
				Severity: m.rule.Severity,
				Category: m.rule.Category,
				Matched:  truncate(m.text, 160),
				Line:     truncate(strings.TrimSpace(line), 500),
				SourceIP: ip,
				Time:     ts,
				Decoded:  m.decoded,
			})
			res.BySeverity[m.rule.Severity]++
			res.ByCategory[m.rule.Category]++
		}
	}
	res.HitLineCount = len(hitLines)

	// 跨行关联：单行规则看不出的模式（同一来源反复失败、失败多次后登录成功等）。
	//
	// **只在非 Web 日志上算**：AnalyzeAuth 找的是 sshd / sudo 那套结构，而 WEB 日志的
	// User-Agent 是攻击者可控文本 —— 写一行
	// `Failed password for root from 203.0.113.9 port 22 ssh2`、再来一行 Accepted，
	// 就能产出一条 `severity=critical` 的关联、IP 指向他随便填的地址（栽赃给 8.8.8.8 也行）。
	// 实测 6 行 nginx 日志 + 2 行 UA 注入 → 单行规则命中 0 条，却产出 critical 关联并落库。
	//
	// 判据用**参数传入的 kind**（调用方已算好），不再自己再猜一次 —— 两次判断不一致
	// 时就会在 web 行上跑认证关联（混合日志前 300 行 syslog 占多数即可触发）。
	if kind != KindWeb {
		res.Correlations = AnalyzeAuth(lines, DefaultThresholds())
	}

	rank := map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3}
	sort.SliceStable(res.Hits, func(i, j int) bool {
		ri, rj := rank[res.Hits[i].Severity], rank[res.Hits[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return res.Hits[i].LineNo < res.Hits[j].LineNo
	})

	for ip, c := range ipCount {
		res.TopIPs = append(res.TopIPs, IPCount{IP: ip, Count: c})
	}
	sort.Slice(res.TopIPs, func(i, j int) bool {
		if res.TopIPs[i].Count != res.TopIPs[j].Count {
			return res.TopIPs[i].Count > res.TopIPs[j].Count
		}
		return res.TopIPs[i].IP < res.TopIPs[j].IP
	})
	if len(res.TopIPs) > 10 {
		res.TopIPs = res.TopIPs[:10]
	}
	return res
}

var ipRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

func extractIP(line string) string {
	m := ipRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

var timeRe = regexp.MustCompile(`(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\w{3}[\s]+\d{1,2}[\s]+\d{2}:\d{2}:\d{2})`)

func extractTime(line string) string {
	m := timeRe.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// truncate 把长文本截到 n **字节**以内（n 之外再加省略号，若放得下）。
//
// 按 rune 边界切，不按字节切：日志里中文、日文很常见，`s[:n]` 会把一个汉字
// 砍成半个 —— 结果是**非法 UTF-8**，界面显示成乱码，而且它会被写进 scan_events
// 再被 json.Marshal 转义成一串 \ufffd，等于把证据行弄坏了。
//
// 长度口径保持"字节"：调用方（界面表格、报告）要的是"别太长"，
// 换成数 rune 反而会让中文行比原来长好几倍。所以从 rune 边界往回退到 ≤ n。
func truncate(s string, n int) string {
	// 输入本身可能就是**非法 UTF-8**（日志被二进制内容截断、GBK 行混进来、
	// tail 从半个多字节字符中间开始读）。只按 rune 边界往回退救不了这种输入：
	// 里面本来就没有合法边界，实测 28 字节的坏串在 n=31 时被**原样返回**，
	// 于是非法字节照样进库、进 JSON。这里先统一换成合法形态（非法字节 → U+FFFD）。
	// 长度口径不变：ToValidUTF8 只会替换非法字节，合法部分（含本文关心的中文）
	// 原样保留，所以下面那套"按字节算预算 + 退到 rune 边界"仍然成立。
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	// 先按"留 3 字节给省略号"算正文的预算；n 太小放不下省略号就干脆不放，
	// 保证返回值的**字节长度不超过 n**（调用方按字节算过位置，别回头超出去）。
	suffix := ""
	body := n
	if n >= 3 {
		suffix = "..."
		body = n - len(suffix)
	}
	// 截断点落在 rune 中间时往回退，直到是合法边界
	for body > 0 && !utf8.RuneStart(s[body]) {
		body--
	}
	if body <= 0 {
		return suffix
	}
	return s[:body] + suffix
}

// cutAtRuneBoundary 把 s 砍到**不超过** max 字节，且不切断多字节字符。
//
// 存在理由：maxLineBytes 那一刀以前是 s[:maxLineBytes] —— **按字节切**。若第
// 8192 字节正好是多字节字符的中间，切出来的行本身就是非法 UTF-8，后面的规则
// 匹配、证据行入库全建在这个坏串上。按 rune 边界退一步的代价只有几个字节。
func cutAtRuneBoundary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	i := max
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}
