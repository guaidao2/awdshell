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
	Transforms []string     `yaml:"transforms"`
	Operator   yamlOperator `yaml:"operator"`
	Test       yamlTest     `yaml:"test"`
}

type yamlOperator struct {
	Name   string     `yaml:"name"`
	Params yamlParams `yaml:"params"`
}

type yamlParams struct {
	Pattern   string         `yaml:"pattern"`
	Patterns  []string       `yaml:"patterns"`
	Operators []yamlOperator `yaml:"operators"`
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

// LoadReport 记录加载时遇到的问题，便于启动日志里如实说明。
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
	for name := range UnknownTransforms {
		report.UnknownTransforms = append(report.UnknownTransforms, name)
	}
	sort.Strings(report.UnknownTransforms)
	for name := range unknownOperators {
		report.UnknownOperators = append(report.UnknownOperators, name)
	}
	sort.Strings(report.UnknownOperators)
	return all, report, nil
}

var unknownOperators = map[string]bool{}

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

		// 算子：regex 用正则，pm 用关键词表
		switch strings.ToLower(strings.TrimSpace(yr.Operator.Name)) {
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
						unknownOperators[n] = true
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
			if name != "" {
				unknownOperators[name] = true
				skipped = append(skipped, fmt.Sprintf("%s(%s): 暂不支持的算子 %q", id, source, name))
			} else {
				skipped = append(skipped, fmt.Sprintf("%s(%s): 缺少 operator", id, source))
			}
			continue
		}

		chain, chainNames := ChainFromNames(yr.Transforms)
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
