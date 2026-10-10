package logscan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Correlation 是跨行关联出来的发现。
//
// 单行规则看不出"同一个 IP 试了 300 次密码然后登录成功"这种事——那要跨行统计。
// 这类发现往往比单行命中更有价值，所以单独成一类结果。
type Correlation struct {
	Kind      string   `json:"kind"` // brute_force | success_after_fail | user_sweep | distributed
	Severity  string   `json:"severity"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail"`
	SourceIP  string   `json:"source_ip"`
	Users     []string `json:"users"`
	Failures  int      `json:"failures"`
	Successes int      `json:"successes"`
	FirstLine int      `json:"first_line"`
	LastLine  int      `json:"last_line"`
	FirstTime string   `json:"first_time"`
	LastTime  string   `json:"last_time"`
	Evidence  []string `json:"evidence"`
}

// AuthThresholds 是关联分析的阈值。
type AuthThresholds struct {
	// BruteForceFailures 同一来源失败多少次算爆破尝试。
	BruteForceFailures int
	// BruteForceHigh 失败多少次升级为高危。
	BruteForceHigh int
	// SweepUsers 同一来源尝试过多少个不同用户名算撞库。
	SweepUsers int
	// SweepIPs 同一个用户名被多少个来源尝试算分布式爆破。
	SweepIPs int
}

// DefaultThresholds 给一套保守的默认值：宁可少报，也不要每次都喊。
func DefaultThresholds() AuthThresholds {
	return AuthThresholds{
		BruteForceFailures: 5,
		BruteForceHigh:     20,
		SweepUsers:         5,
		SweepIPs:           5,
	}
}

// ---------- 事件提取 ----------

type authEvent struct {
	lineNo int
	time   string
	ip     string
	user   string
	ok     bool
	raw    string
}

// 常见 sshd / PAM 日志形态，覆盖 Debian、CentOS 与新老版本。
var (
	evFailRe = regexp.MustCompile(`(?i)(?:Failed password for(?: invalid user)?\s+(\S+)|authentication failure;[^\n]*?user=(\S+)|Invalid user\s+(\S+)\s+from)` +
		`[^\n]*?(?:from\s+|rhost=)?(\d{1,3}(?:\.\d{1,3}){3})`)
	evOKRe         = regexp.MustCompile(`(?i)Accepted\s+(?:password|publickey|keyboard-interactive|gssapi[^\s]*)\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})`)
	evDisconnectRe = regexp.MustCompile(`(?i)(?:Connection closed by|Connection reset by)\s+(?:authenticating user\s+(\S+)\s+)?(\d{1,3}(?:\.\d{1,3}){3})`)
)

func extractAuthEvents(lines []string) []authEvent {
	events := make([]authEvent, 0, 32)
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lower := strings.ToLower(line)
		// 先做一次廉价预筛，避免对每一行都跑几条正则
		if !strings.Contains(lower, "sshd") && !strings.Contains(lower, "pam_unix") &&
			!strings.Contains(lower, "authentication failure") && !strings.Contains(lower, "accepted ") &&
			!strings.Contains(lower, "failed password") && !strings.Contains(lower, "invalid user") {
			continue
		}
		ts := extractTime(line)

		if m := evOKRe.FindStringSubmatch(line); m != nil {
			events = append(events, authEvent{lineNo: i + 1, time: ts, user: m[1], ip: m[2], ok: true, raw: line})
			continue
		}
		if m := evFailRe.FindStringSubmatch(line); m != nil {
			user := ""
			for _, g := range m[1:4] {
				if g != "" {
					user = g
					break
				}
			}
			events = append(events, authEvent{lineNo: i + 1, time: ts, user: user, ip: m[4], raw: line})
			continue
		}
		if m := evDisconnectRe.FindStringSubmatch(line); m != nil {
			// 连接被关掉本身不算失败，但反复出现是爆破的伴随特征；这里只记事件不单独成结论
			events = append(events, authEvent{lineNo: i + 1, time: ts, user: m[1], ip: m[2], ok: false, raw: line})
		}
	}
	return events
}

// ---------- 关联 ----------

// AnalyzeAuth 从日志行里提取认证事件并按来源做关联。
func AnalyzeAuth(lines []string, th AuthThresholds) []Correlation {
	if th.BruteForceFailures <= 0 {
		th = DefaultThresholds()
	}
	events := extractAuthEvents(lines)
	if len(events) == 0 {
		return nil
	}

	type bucket struct {
		ip        string
		failures  int
		successes int
		users     map[string]bool
		firstLine int
		lastLine  int
		firstTime string
		lastTime  string
		evidence  []string
	}
	byIP := map[string]*bucket{}
	userIPs := map[string]map[string]bool{}

	for _, e := range events {
		if e.ip == "" {
			continue
		}
		b := byIP[e.ip]
		if b == nil {
			b = &bucket{ip: e.ip, users: map[string]bool{}, firstLine: e.lineNo, firstTime: e.time}
			byIP[e.ip] = b
		}
		if e.user != "" {
			b.users[e.user] = true
			if userIPs[e.user] == nil {
				userIPs[e.user] = map[string]bool{}
			}
			userIPs[e.user][e.ip] = true
		}
		if e.ok {
			b.successes++
		} else {
			b.failures++
		}
		b.lastLine = e.lineNo
		if e.time != "" {
			b.lastTime = e.time
			if b.firstTime == "" {
				b.firstTime = e.time
			}
		}
		if len(b.evidence) < 3 && isFailureLine(e) {
			b.evidence = append(b.evidence, truncate(strings.TrimSpace(e.raw), 300))
		}
	}

	var out []Correlation
	for _, b := range byIP {
		users := sortedKeys(b.users)

		// 失败多次之后登录成功：最值得先看的一条
		if b.failures >= th.BruteForceFailures && b.successes > 0 {
			out = append(out, Correlation{
				Kind:     "success_after_fail",
				Severity: SevCritical,
				Title:    "多次认证失败后登录成功（疑似爆破成功）",
				Detail: fmt.Sprintf("来自 %s 的 %d 次失败后出现了 %d 次成功登录，涉及账号 %s；请确认这次登录是否本人操作",
					b.ip, b.failures, b.successes, strings.Join(users, ", ")),
				SourceIP:  b.ip,
				Users:     users,
				Failures:  b.failures,
				Successes: b.successes,
				FirstLine: b.firstLine,
				LastLine:  b.lastLine,
				FirstTime: b.firstTime,
				LastTime:  b.lastTime,
				Evidence:  b.evidence,
			})
			continue
		}

		// 换了很多用户名：撞库/账号枚举。这条比单纯"次数多"更具体，所以先判。
		if len(users) >= th.SweepUsers {
			out = append(out, Correlation{
				Kind: "user_sweep", Severity: SevHigh,
				Title: "同一来源反复尝试多个账号（疑似撞库/账号枚举）",
				Detail: fmt.Sprintf("来自 %s 尝试了 %d 个不同账号：%s",
					b.ip, len(users), strings.Join(users, ", ")),
				SourceIP: b.ip, Users: users, Failures: b.failures, Successes: b.successes,
				FirstLine: b.firstLine, LastLine: b.lastLine,
				FirstTime: b.firstTime, LastTime: b.lastTime, Evidence: b.evidence,
			})
			continue
		}

		// 只有失败：按次数分级
		if b.failures >= th.BruteForceFailures {
			sev := SevMedium
			title := "疑似暴力破解尝试"
			if b.failures >= th.BruteForceHigh {
				sev = SevHigh
				title = "持续暴力破解尝试"
			}
			detail := fmt.Sprintf("来自 %s 的认证失败 %d 次", b.ip, b.failures)
			if len(users) > 0 {
				detail += "，尝试账号 " + strings.Join(users, ", ")
			}
			out = append(out, Correlation{
				Kind: "brute_force", Severity: sev, Title: title, Detail: detail,
				SourceIP: b.ip, Users: users, Failures: b.failures, Successes: b.successes,
				FirstLine: b.firstLine, LastLine: b.lastLine,
				FirstTime: b.firstTime, LastTime: b.lastTime, Evidence: b.evidence,
			})
			continue
		}
	}

	// 同一个账号被很多来源尝试：分布式爆破
	for user, ips := range userIPs {
		if len(ips) < th.SweepIPs {
			continue
		}
		list := sortedKeys(ips)
		out = append(out, Correlation{
			Kind: "distributed", Severity: SevHigh,
			Title:  "同一账号被多个来源尝试（疑似分布式爆破）",
			Detail: fmt.Sprintf("账号 %s 被 %d 个来源尝试：%s", user, len(list), strings.Join(list, ", ")),
			Users:  []string{user}, Failures: len(list),
		})
	}

	rank := map[string]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank[out[i].Severity], rank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].Failures > out[j].Failures
	})
	return out
}

func isFailureLine(e authEvent) bool { return !e.ok }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
