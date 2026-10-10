package logscan

import (
	"regexp"
	"sort"
	"strings"
)

// Rule 是一条检测规则。
//
// 匹配语义与 WAF 规则一致：先在 rule.Chain（变换链）处理过的文本上匹配，
// 这样编码/混淆过的载荷也能认出来。Pattern 与 Keywords 二者至少有一个：
// Pattern 对应 regex 算子，Keywords 对应 pm（多关键词）算子。
type Rule struct {
	ID       string
	Name     string
	Severity string
	Category string
	Pattern  *regexp.Regexp
	Keywords []string
	Chain    []Transform

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
	if r.Pattern != nil {
		if m := r.Pattern.FindString(s); m != "" {
			return m
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
func Scan(text, path string, rules []Rule) Result {
	if rules == nil {
		rules = AllRules()
	}
	res := Result{
		Path:       path,
		Hits:       []Hit{},
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
		RuleCount:  len(rules),
	}
	ipCount := map[string]int{}
	hitLines := map[int]bool{}

	lines := strings.Split(text, "\n")
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
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

	// 跨行关联：单行规则看不出的模式（同一来源反复失败、失败多次后登录成功等）
	res.Correlations = AnalyzeAuth(lines, DefaultThresholds())

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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
