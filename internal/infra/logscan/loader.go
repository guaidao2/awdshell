package logscan

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var embeddedRules embed.FS

// ---------- 规则文件格式 ----------
//
// 与 WAF 的规则文件保持兼容：targets / phase / score / tags 这些 HTTP 处理链上的字段
// 在日志场景没有意义，解析时忽略；rules[].operator 与 transforms 原样使用。
// 这样同一份规则可以同时喂给 WAF 和日志检测，两边不用各维护一套。

type yamlDoc struct {
	Version int        `yaml:"version"`
	Meta    yamlMeta   `yaml:"meta"`
	Rules   []yamlRule `yaml:"rules"`
}

type yamlMeta struct {
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
}

type yamlRule struct {
	ID         string       `yaml:"id"`
	Phase      int          `yaml:"phase"`
	Severity   string       `yaml:"severity"`
	Category   string       `yaml:"category"`
	Score      int          `yaml:"score"`
	Message    string       `yaml:"message"`
	Tags       []string     `yaml:"tags"`
	Targets    []yamlTarget `yaml:"targets"`
	Transforms []string     `yaml:"transforms"`
	Operator   yamlOperator `yaml:"operator"`
	Test       yamlTest     `yaml:"test"`
}

// yamlTarget 是规则的适用集合。WAF 的 HTTP 处理链用它决定规则跑在哪个输入上；
// 日志扫描没有"集合"的概念，但**必须**用它把"只针对上传文件"的规则排除掉 ——
// 否则像 WS-9004（文件魔数，要 hexEncode 把原始字节转成十六进制）会被套到每一行
// 日志上，把 `#!/bin/sh`、`cafebabe` 这类纯文本也编码后撞上魔数表。
type yamlTarget struct {
	Collection string `yaml:"collection"`
}

// onlyFileContentTargets 判断规则是否**只**判上传文件的**内容**（FILES_MAGIC）。
//
// 为什么只认 FILES_MAGIC、不认 FILES：FILES 里的规则大多看**文件名**
// （`shell.php.jpg`、`avatar.png.php`），而文件名在访问日志里是逐字出现的
// （`GET /upload/shell.php.jpg HTTP/1.1`），跳掉它们会丢真检出 ——
// 上一版就是这么跳过头、被审计抓到的。
//
// 反过来 FILES_MAGIC 判的是**文件字节**（靠 hexEncode 把原始字节转成十六进制），
// 日志行里的文本被编码一遍正好撞上魔数表：`#!/bin/sh` → `23212f…`、
// `cafebabe` 本身就是纯 hex 会原样返回 —— 于是正常日志被判成 critical webshell。
func onlyFileContentTargets(ts []yamlTarget) bool {
	if len(ts) == 0 {
		return false
	}
	for _, t := range ts {
		if !strings.EqualFold(strings.TrimSpace(t.Collection), "FILES_MAGIC") {
			return false
		}
	}
	return true
}

type yamlOperator struct {
	Name   string     `yaml:"name"`
	Params yamlParams `yaml:"params"`
}

type yamlParams struct {
	Pattern   string         `yaml:"pattern"`
	Patterns  []string       `yaml:"patterns"`
	Operators []yamlOperator `yaml:"operators"`
	// 语义算子的参数
	MinFingerprintLen   int      `yaml:"min_fingerprint_len"`
	MinDepth            int      `yaml:"min_depth"`
	Fingerprints        []string `yaml:"fingerprints"`
	ExcludeFingerprints []string `yaml:"exclude_fingerprints"`
	// Extra 收下未在上面声明的参数，用来拒绝"写了但不生效"的参数
	Extra map[string]any `yaml:",inline"`
}

// firstUnknownParam 返回第一个该算子不支持的参数名（没有则空串）。
//
// 两处都要查：Extra 里是"结构体没声明的键"，而上面那些**已声明的字段**
// 只要被规则写了值，同样要按算子的白名单校验 ——
// 否则 `detectXSS + min_fingerprint_len: 8`、`detectXSS + pattern` 这类
// 会被静默接受、参数毫无作用，正好是 YAML 注释里说"加载器会拒绝"的那种情况。
func firstUnknownParam(op string, p yamlParams) string {
	allow := semanticParamAllow[op]
	for k := range p.Extra {
		if !allow[k] {
			return k
		}
	}
	check := func(name string, written bool) string {
		if written && !allow[name] {
			return name
		}
		return ""
	}
	for _, c := range []struct {
		name    string
		written bool
	}{
		{"pattern", p.Pattern != ""},
		{"patterns", len(p.Patterns) > 0},
		{"operators", len(p.Operators) > 0},
		{"min_fingerprint_len", p.MinFingerprintLen != 0},
		{"min_depth", p.MinDepth != 0},
		{"fingerprints", len(p.Fingerprints) > 0},
		{"exclude_fingerprints", len(p.ExcludeFingerprints) > 0},
	} {
		if bad := check(c.name, c.written); bad != "" {
			return bad
		}
	}
	return ""
}

type yamlTest struct {
	Positive []string `yaml:"positive"`
	Negative []string `yaml:"negative"`
}

// LoadedRule 是规则本体加上它自带的测试样本。
type LoadedRule struct {
	Rule
	Source   string
	Positive []string
	Negative []string
}

// LoadReport 记录加载时遇到的问题，供内部诊断（测试、调试）使用。
// 不要拿它去渲染界面或启动日志 —— 见 LogRuleReport 的说明。
type LoadReport struct {
	Files             int
	Rules             int
	Skipped           []string
	UnknownTransforms []string
	UnknownOperators  []string
	TestCases         int
}

// LoadEmbedded 加载编译进二进制的规则。
func LoadEmbedded() ([]LoadedRule, LoadReport, error) {
	var all []LoadedRule
	report := LoadReport{}

	entries, err := fs.ReadDir(embeddedRules, "rules")
	if err != nil {
		return nil, report, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		// 协议层规则检查的是 HTTP 报文结构（同名参数个数、字节范围、缺少某头等），
		// 对"一行日志文本"没有意义，留着只会像 "Started Session 12 of user root."
		// 这样的正常行上误报。这里跳过，并在报告里写明原因。
		if name == "00-protocol.yaml" {
			report.Skipped = append(report.Skipped,
				name+": 协议层规则（检查 HTTP 报文结构），不适用于日志行扫描，整体跳过")
			continue
		}
		data, err := embeddedRules.ReadFile(path.Join("rules", name))
		if err != nil {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s: 读取失败 %v", name, err))
			continue
		}
		loaded, skipped, err := LoadRules(data, name)
		if err != nil {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		report.Files++
		report.Rules += len(loaded)
		report.Skipped = append(report.Skipped, skipped...)
		all = append(all, loaded...)
	}

	for i := range all {
		report.TestCases += len(all[i].Positive) + len(all[i].Negative)
	}
	// 两个"未实现名字"注册表都走带锁快照：LoadRules 可能被并发调用，
	// 直接 range 一个会被并发写的 map 同样是运行时崩溃。
	report.UnknownTransforms = unknownTransformNames()
	report.UnknownOperators = unknownOperatorNames()
	return all, report, nil
}

// unknownOperators 记录规则里读到但本版本不支持的算子名。
//
// 与 UnknownTransforms 一样由 unknownMu 保护：LoadRules 是导出函数，可以被
// 并发调用，而**并发写 map 是运行时崩溃**（不是数据错乱）。
var unknownOperators = map[string]bool{}

// recordUnknownOperator 记下一个不支持的算子名（带锁）。
func recordUnknownOperator(name string) {
	unknownMu.Lock()
	unknownOperators[name] = true
	unknownMu.Unlock()
}

// unknownOperatorNames 取出不支持的算子名快照（带锁，已排序）。
func unknownOperatorNames() []string {
	unknownMu.Lock()
	out := make([]string, 0, len(unknownOperators))
	for name := range unknownOperators {
		out = append(out, name)
	}
	unknownMu.Unlock()
	sort.Strings(out)
	return out
}

// LoadRules 解析一份规则文件；返回加载成功的规则与被跳过的条目说明。
func LoadRules(data []byte, source string) ([]LoadedRule, []string, error) {
	var doc yamlDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("解析失败: %w", err)
	}

	var out []LoadedRule
	var skipped []string

	for _, yr := range doc.Rules {
		id := strings.TrimSpace(yr.ID)
		if id == "" {
			skipped = append(skipped, fmt.Sprintf("%s: 规则缺少 id", source))
			continue
		}

		rule := Rule{
			ID:       id,
			Name:     strings.TrimSpace(yr.Message),
			Severity: normalizeSeverity(yr.Severity),
			Category: strings.TrimSpace(yr.Category),
		}
		if rule.Name == "" {
			rule.Name = id
		}
		if rule.Category == "" {
			rule.Category = doc.Meta.Category
		}

		// 只判上传文件**内容**的规则（FILES_MAGIC）在日志行扫描里没有意义：
		// 它们判的是文件字节，而这里把每条规则套在每一行文本上。
		// 典型是 WS-9004（文件魔数，靠 hexEncode 把原始字节转成十六进制）——
		// 套到日志行上会把 `#!/bin/sh`、`cafebabe` 这类**纯文本**也编码一遍，
		// 正好撞上魔数表，于是正常的日志行被判成 critical 的 webshell。
		//
		// **注意只看 FILES_MAGIC，不看 FILES**：FILES 类规则大多判文件名，
		// 而文件名在访问日志里逐字出现，跳掉会丢真检出。
		if onlyFileContentTargets(yr.Targets) {
			skipped = append(skipped,
				fmt.Sprintf("%s(%s): 只判上传文件内容（FILES_MAGIC），不适用于日志行扫描，整体跳过", id, source))
			continue
		}

		// 参数白名单：**所有**算子都过一遍，不只是语义算子 ——
		// 否则 `regex + min_depth: 2`、`pm + min_fingerprint_len: 8` 这类
		// "写了但不生效"的参数会被静默接受。
		opName := strings.ToLower(strings.TrimSpace(yr.Operator.Name))
		if _, known := operatorParamAllow[opName]; known {
			if bad := firstUnknownParam(opName, yr.Operator.Params); bad != "" {
				skipped = append(skipped,
					fmt.Sprintf("%s(%s): %s 不支持参数 %q", id, source, opName, bad))
				continue
			}
		}

		// 算子：regex 用正则，pm 用关键词表
		switch opName {
		case "regex":
			expr := strings.TrimSpace(yr.Operator.Params.Pattern)
			if expr == "" {
				skipped = append(skipped, fmt.Sprintf("%s(%s): regex 算子没有 pattern", id, source))
				continue
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				// Go 的 RE2 不支持前瞻/后顾，规则里若用了这类语法只能跳过
				skipped = append(skipped, fmt.Sprintf("%s(%s): 正则无法编译: %v", id, source, err))
				continue
			}
			rule.Pattern = re

		case "pm":
			for _, kw := range yr.Operator.Params.Patterns {
				kw = strings.TrimSpace(kw)
				if kw != "" {
					rule.Keywords = append(rule.Keywords, kw)
				}
			}
			if len(rule.Keywords) == 0 {
				skipped = append(skipped, fmt.Sprintf("%s(%s): pm 算子没有 patterns", id, source))
				continue
			}

		case "anyof":
			// anyOf：任一子算子命中即算命中。子算子目前支持 regex 与 pm，
			// 统一合成一条 OR 正则（SSTI 那条规则就是这么写的）。
			var parts []string
			for _, sub := range yr.Operator.Params.Operators {
				switch strings.ToLower(strings.TrimSpace(sub.Name)) {
				case "regex":
					if p := strings.TrimSpace(sub.Params.Pattern); p != "" {
						parts = append(parts, "(?:"+p+")")
					}
				case "pm":
					for _, kw := range sub.Params.Patterns {
						if kw = strings.TrimSpace(kw); kw != "" {
							parts = append(parts, "(?:"+regexp.QuoteMeta(kw)+")")
						}
					}
				default:
					if n := strings.TrimSpace(sub.Name); n != "" {
						recordUnknownOperator(n)
					}
				}
			}
			if len(parts) == 0 {
				skipped = append(skipped, fmt.Sprintf("%s(%s): anyOf 里没有可用的子算子", id, source))
				continue
			}
			re, err := regexp.Compile(strings.Join(parts, "|"))
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s(%s): anyOf 合成正则失败: %v", id, source, err))
				continue
			}
			rule.Pattern = re

		default:
			name := strings.TrimSpace(yr.Operator.Name)
			lower := strings.ToLower(name)
			if !semanticOperatorNames[lower] {
				if name != "" {
					recordUnknownOperator(name)
					skipped = append(skipped, fmt.Sprintf("%s(%s): 暂不支持的算子 %q", id, source, name))
				} else {
					skipped = append(skipped, fmt.Sprintf("%s(%s): 缺少 operator", id, source))
				}
				continue
			}
			// 语义算子（参数已在上面的统一白名单里校验过）
			fn, err := buildSemantic(lower, yr.Operator.Params)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s(%s): %v", id, source, err))
				continue
			}
			rule.Semantic = fn
		}

		chain, chainNames := ChainFromNames(yr.Transforms)
		// 没写 transforms 的规则套默认链。CompileRules 的注释一直这么承诺，
		// 但 ChainFromNames(nil) 返回的是**非 nil 空切片**，`len(chain) == 0`
		// 这个条件从来没被满足过 —— 这类规则会拿到空链、在原始文本上匹配。
		// （规则库当前全都写了 transforms，所以是潜伏项。）
		if len(chain) == 0 {
			chain, chainNames = DefaultChain, DefaultTransformNames
		}
		rule.Chain = chain
		rule.TransformNames = chainNames
		rule.compile()

		out = append(out, LoadedRule{
			Rule:     rule,
			Source:   source,
			Positive: yr.Test.Positive,
			Negative: yr.Test.Negative,
		})
	}
	return out, skipped, nil
}

// RulesOf 取出纯规则列表。
func RulesOf(loaded []LoadedRule) []Rule {
	out := make([]Rule, 0, len(loaded))
	for i := range loaded {
		out = append(out, loaded[i].Rule)
	}
	return out
}

// SelfTest 用规则自带的样本自检：
// 正样本必须命中，负样本必须不命中。返回值是 (通过数, 失败数, 失败明细)。
func SelfTest(loaded []LoadedRule) (int, int, []string) {
	ok, bad := 0, 0
	var failures []string

	for i := range loaded {
		lr := &loaded[i]
		one := []Rule{lr.Rule}

		for _, pos := range lr.Positive {
			res := Scan(pos+"\n", "selftest", one)
			if len(res.Hits) == 0 {
				bad++
				failures = append(failures, fmt.Sprintf("[%s] 正样本未命中: %s", lr.ID, truncate(pos, 90)))
			} else {
				ok++
			}
		}
		for _, neg := range lr.Negative {
			res := Scan(neg+"\n", "selftest", one)
			if len(res.Hits) > 0 {
				bad++
				failures = append(failures, fmt.Sprintf("[%s] 负样本误报: %s", lr.ID, truncate(neg, 90)))
			} else {
				ok++
			}
		}
	}
	return ok, bad, failures
}

// CrossTest 把负样本拿去跑"全部规则"，用于发现规则之间的相互误报。
func CrossTest(loaded []LoadedRule) (int, int, []string) {
	all := RulesOf(loaded)
	ok, bad := 0, 0
	var failures []string
	for i := range loaded {
		for _, neg := range loaded[i].Negative {
			res := Scan(neg+"\n", "crosstest", all)
			if len(res.Hits) > 0 {
				ids := make([]string, 0, len(res.Hits))
				for _, h := range res.Hits {
					ids = append(ids, h.RuleID)
				}
				bad++
				failures = append(failures, fmt.Sprintf("负样本被 %v 命中: %s", ids, truncate(neg, 80)))
			} else {
				ok++
			}
		}
	}
	return ok, bad, failures
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium":
		return SevMedium
	case "low":
		return SevLow
	}
	return SevMedium
}
