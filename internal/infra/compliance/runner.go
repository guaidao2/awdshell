package compliance

import (
	"context"
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
			if why := validateCheck(c); why != "" {
				problems = append(problems, fmt.Sprintf("%s: %s", name, why))
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

// validateCheck 校验一条检查项，返回空串表示通过、否则是"为什么跳过"。
//
// 单独抽出来是为了能直接测这些判据（LoadSets 只读 embed，测不到手写的坏 YAML）。
// 两类必须拦住的写法：
//   - 正则无法编译：regex_not_match 的失败方向是"判成合规"（fail-open），
//     该报不合规的报成合规，比直接报错危险得多；
//   - **pattern 为空**：空正则/空串能匹配任何东西 —— regex_match、contains 恒 pass，
//     regex_not_match、not_contains 恒 fail，而且都不会报错。规则文件是外部可编辑的，
//     不能靠"当前 67 条都没写错"。
func validateCheck(c Check) string {
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Title) == "" || strings.TrimSpace(c.Command) == "" {
		return "有检查项缺少 id / title / command，已跳过"
	}
	typ := c.Expect.Type
	if typ == "" {
		typ = ExpectManual
	}
	pattern := strings.TrimSpace(c.Expect.Pattern)
	switch typ {
	case ExpectRegexMatch, ExpectRegexNotMatch:
		if pattern == "" {
			return fmt.Sprintf("检查项 %s 的 pattern 为空（空正则匹配一切），已跳过", c.ID)
		}
		if _, err := compiled(pattern); err != nil {
			return fmt.Sprintf("检查项 %s 的正则无法编译（%v），已跳过", c.ID, err)
		}
	case ExpectContains, ExpectNotContains:
		if pattern == "" {
			return fmt.Sprintf("检查项 %s 的 pattern 为空（空串匹配一切），已跳过", c.ID)
		}
	}
	return ""
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

// Run 依次执行检查项并判定（无取消）。
// onlyIDs 非空时只跑指定的项；progress 用于汇报进度（可为 nil）。
//
// 保留这个签名是为了兼容已有调用方；需要取消/需要知道"指定的 ID 没匹配上"时
// 用 RunWithContext。
func Run(checks []Check, exec ExecFunc, onlyIDs []string, progress func(done, total int)) []Result {
	results, _ := RunWithContext(context.Background(), checks, exec, onlyIDs, progress)
	return results
}

// RunWithContext 与 Run 相同，但支持中途取消，并把筛选时的问题回传。
//
// ctx 会在每项开始前检查一次：一轮 60+ 项在慢机器上要跑几分钟，用户点了取消
// 或退出目标时必须能停下来，而不是把整轮跑完。
//
// 返回的第二个值是 problems：目前包括"指定了但根本不存在的检查项 ID"。
// 以前这类 ID 被静默忽略（实测指定 `[A TYPO-ID]` 只跑了 1 项、界面上毫无提示，
// 用户会以为那一项已经查过且通过）。
//
// 取消时返回的是**已经跑完的那些**结果，不让前面白跑 —— 调用方应当把
// 不完整当成"部分结果"展示，而不是当成整轮通过。
func RunWithContext(ctx context.Context, checks []Check, exec ExecFunc, onlyIDs []string, progress func(done, total int)) ([]Result, []string) {
	if ctx == nil {
		ctx = context.Background()
	}

	var problems []string
	filter := map[string]bool{}
	for _, id := range onlyIDs {
		if id = strings.TrimSpace(id); id != "" {
			filter[id] = true
		}
	}

	selected := make([]Check, 0, len(checks))
	known := map[string]bool{}
	for _, c := range checks {
		known[c.ID] = true
		if len(filter) > 0 && !filter[c.ID] {
			continue
		}
		selected = append(selected, c)
	}

	// 未知 ID 必须报出来：否则"我指定了 3 项"和"实际只跑了 1 项"在界面上
	// 长得一模一样，用户会把没跑的项当成通过。
	for _, id := range onlyIDs {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		if !known[id] {
			problems = append(problems, fmt.Sprintf("检查项 ID %q 不存在，已忽略", id))
		}
	}

	results := make([]Result, 0, len(selected))
	for i, c := range selected {
		// 每项开始前看一眼取消：正在跑的那一项由 exec 自己的 timeout 收尾
		if err := ctx.Err(); err != nil {
			problems = append(problems,
				fmt.Sprintf("核查已取消，还有 %d 项未执行", len(selected)-i))
			break
		}
		out, err := exec(c.Command, c.Timeout)
		results = append(results, Evaluate(c, out, err))
		if progress != nil {
			progress(i+1, len(selected))
		}
	}
	return results, problems
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
