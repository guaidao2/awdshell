package compliance

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed checks/*.yaml
var embeddedChecks embed.FS

// LoadSets 加载编译进二进制的检查项；返回集合与加载中发现的问题。
func LoadSets() ([]Set, []string, error) {
	entries, err := fs.ReadDir(embeddedChecks, "checks")
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var sets []Set
	var problems []string
	for _, name := range names {
		data, err := embeddedChecks.ReadFile(path.Join("checks", name))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: 读取失败 %v", name, err))
			continue
		}
		var d doc
		if err := yaml.Unmarshal(data, &d); err != nil {
			problems = append(problems, fmt.Sprintf("%s: 解析失败 %v", name, err))
			continue
		}
		valid := make([]Check, 0, len(d.Checks))
		for _, c := range d.Checks {
			if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.Command) == "" {
				problems = append(problems, fmt.Sprintf("%s: 有检查项缺少 id / title / command，已跳过", name))
				continue
			}
			if c.Expect.Type == "" {
				c.Expect.Type = ExpectManual
			}
			if c.Timeout <= 0 {
				c.Timeout = 10
			}
			if c.Severity == "" {
				c.Severity = "medium"
			}
			valid = append(valid, c)
		}
		sets = append(sets, Set{Meta: d.Meta, Checks: valid, Source: name})
	}
	return sets, problems, nil
}

// AllChecks 展开所有集合里的检查项。
func AllChecks(sets []Set) []Check {
	var out []Check
	for _, s := range sets {
		out = append(out, s.Checks...)
	}
	return out
}

// ExecFunc 是执行一条远程命令的函数（由上层用 SSH 实现）。
type ExecFunc func(command string, timeoutSec int) (string, error)

// Run 依次执行检查项并判定。
// onlyIDs 非空时只跑指定的项；progress 用于汇报进度（可为 nil）。
func Run(checks []Check, exec ExecFunc, onlyIDs []string, progress func(done, total int)) []Result {
	filter := map[string]bool{}
	for _, id := range onlyIDs {
		if id = strings.TrimSpace(id); id != "" {
			filter[id] = true
		}
	}

	selected := make([]Check, 0, len(checks))
	for _, c := range checks {
		if len(filter) > 0 && !filter[c.ID] {
			continue
		}
		selected = append(selected, c)
	}

	results := make([]Result, 0, len(selected))
	for i, c := range selected {
		out, err := exec(c.Command, c.Timeout)
		results = append(results, Evaluate(c, out, err))
		if progress != nil {
			progress(i+1, len(selected))
		}
	}
	return results
}

// CategoryStat 是按类别统计的结果。
type CategoryStat struct {
	Total  int `json:"total"`
	Pass   int `json:"pass"`
	Fail   int `json:"fail"`
	Manual int `json:"manual"`
	Error  int `json:"error"`
}

// Summary 是一次核查的汇总。
type Summary struct {
	Total      int                     `json:"total"`
	Pass       int                     `json:"pass"`
	Fail       int                     `json:"fail"`
	Manual     int                     `json:"manual"`
	Error      int                     `json:"error"`
	Score      int                     `json:"score"` // 0-100，仅按可判定的项算
	ByCategory map[string]CategoryStat `json:"by_category"`
	BySeverity map[string]CategoryStat `json:"by_severity"`
}

// Summarize 汇总结果：分数只按"能明确判定"的项算（人工确认与执行失败不计入分母），
// 否则一个读不到的项会把分数拉低，反而看不出真实的配置状况。
func Summarize(results []Result) Summary {
	s := Summary{
		Total:      len(results),
		ByCategory: map[string]CategoryStat{},
		BySeverity: map[string]CategoryStat{},
	}
	judged := 0
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Pass++
			judged++
		case StatusFail:
			s.Fail++
			judged++
		case StatusManual:
			s.Manual++
		case StatusError:
			s.Error++
		}

		cs := s.ByCategory[r.Category]
		cs.Total++
		addStatus(&cs, r.Status)
		s.ByCategory[r.Category] = cs

		vs := s.BySeverity[r.Severity]
		vs.Total++
		addStatus(&vs, r.Status)
		s.BySeverity[r.Severity] = vs
	}
	if judged > 0 {
		s.Score = int(float64(s.Pass) / float64(judged) * 100)
	} else {
		s.Score = -1 // 没有可判定的项
	}
	return s
}

func addStatus(c *CategoryStat, status string) {
	switch status {
	case StatusPass:
		c.Pass++
	case StatusFail:
		c.Fail++
	case StatusManual:
		c.Manual++
	case StatusError:
		c.Error++
	}
}
