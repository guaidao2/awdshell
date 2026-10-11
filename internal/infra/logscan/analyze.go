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
	Kind      string   `json:"kind"` // brute_force | success_after_fail | user_sweep | distributed | analysis_capped
	Severity  string   `json:"severity"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail"`
	SourceIP  string   `json:"source_ip"`
	Users     []string `json:"users"`
	Failures  int      `json:"failures"`
	Successes int      `json:"successes"`
	// Disconnects 是**中性事件**的伴随计数（Connection closed/reset by）。
	// 它不参与任何阈值：断连可能是 NAT 超时、跳板机断开、客户端重试，
	// 把它当失败会把正常环境天天报成爆破（审计实测 5 条断连 + 1 次正常登录
	// 会被判成 critical 的"失败后成功"）。只在已经成结论时作为旁证列出。
	Disconnects int      `json:"disconnects,omitempty"`
	FirstLine   int      `json:"first_line"`
	LastLine    int      `json:"last_line"`
	FirstTime   string   `json:"first_time"`
	LastTime    string   `json:"last_time"`
	Evidence    []string `json:"evidence"`
}

// 关联分析的单次上限。
//
// 为什么需要：日志内容在 AWD 场景由攻击者完全控制，"来源 IP"与"账号名"都可以
// 每一行都不重样（`Failed password for u<i> from 203.0.113.<i>`），没有上限时
// byIP / userIPs 会随行数无界增长 —— 20000 行的日志就是 20000 个 map 项加
// 20000 个内层 map。这里给参与统计的项数封顶，并把封顶这件事如实报出来
// （见 analysis_capped），不静默丢。
const (
	maxAuthSources = 2048 // 参与关联统计的来源 IP 上限
	maxAuthUsers   = 2048 // 参与关联统计的账号上限
	// maxAuthListed 是**结论文案里**最多列出多少个来源 IP / 账号。
	//
	// 它只管"列出来的长度"（detail 字符串不能无限长），**不再用来给去重集合封顶**：
	// 以前集合一满 64 个就不再记录，计数靠"这个账号不在集合里"来判断，
	// 于是同一账号再失败一次就被重复计数（复审 低1/低2：80 个账号报成 90）。
	// 集合的规模与输入行数同阶（service 层单批上限 20000 行），这是精确计数
	// 必须付的代价；单批行数本身有界，所以不会随日志总量增长。
	maxAuthListed = 64
)

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

// normalizeThresholds **逐项**校验阈值。
//
// 原来只判 BruteForceFailures 一项：调用方传 `SweepIPs: 0` 而其余正常时，
// `len(ips) >= 0` 恒真 —— 每个出现过的账号都会产出一条 distributed，
// 阈值等于不存在。这里逐项回落到默认值。
func normalizeThresholds(th AuthThresholds) AuthThresholds {
	def := DefaultThresholds()
	if th.BruteForceFailures <= 0 {
		th.BruteForceFailures = def.BruteForceFailures
	}
	if th.BruteForceHigh <= 0 {
		th.BruteForceHigh = def.BruteForceHigh
	}
	if th.SweepUsers <= 0 {
		th.SweepUsers = def.SweepUsers
	}
	if th.SweepIPs <= 0 {
		th.SweepIPs = def.SweepIPs
	}
	// 高危线低于立案线时，"持续爆破"这条会跟普通爆破同时成立 —— 等于所有
	// 爆破都被标成高危。把高危线抬到至少等于立案线。
	if th.BruteForceHigh < th.BruteForceFailures {
		th.BruteForceHigh = th.BruteForceFailures
	}
	return th
}

// ---------- 事件提取 ----------

type authEvent struct {
	lineNo int
	time   string
	ip     string
	user   string
	ok     bool
	// neutral 表示"连接被关掉/重置"这类既不是失败也不是成功的事件。
	// 单列一个状态而不是复用 ok=false：复用会把 NAT 超时、跳板机断开、
	// 客户端重试都算成认证失败（见 evDisconnectRe 处的说明）。
	neutral bool
	raw     string
}

// 常见 sshd / PAM 日志形态，覆盖 Debian、CentOS 与新老版本。
//
// 失败形态**不能只认 `Failed password for`**（复审 中1）：公钥爆破留下的日志是
// `Failed publickey for root from …`，而 `Failed none for`（客户端没提供任何
// 认证方式）与 `Failed keyboard-interactive/pam for …`（PAM 交互认证，方法名里
// 带 `/`）同样一条都不认 —— 实测 10 行 `Failed publickey` 加 10 行
// `Connection closed by authenticating user …[preauth]`，结论是 **0 条**；
// 把 publickey 换成 password 就正常立案。断连的中性化本身是对的（见
// evDisconnectRe），所以这里只补失败形态的覆盖。
//
// 方法名收成"Failed <方法> for"：允许字母数字、`_`、`.`、`/`、`-`；
// `invalid user` 与老版本的 `illegal user` 两种写法都认。
// **账号必须是第 1 捕获组、IP 必须是第 4 捕获组**：调用方按 m[1:4] 找账号、
// 按 m[4] 取来源，分组序号一动就全错。
//
// `authentication failure;` 这条替代分支要同时认 `user=` 与 `ruser=`，而且账号
// 允许为空（复审 L2）：pam_unix 的 sshd 失败行是
// `authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9`
// —— 账号列在 `ruser=`（很多发行版这里是空的，账号只在后续行里），行里根本没有
// `user=`，所以老写法 `[^\n]*?user=(\S+)` 一个事件也提不出来（实测 0 条）。
// 写法上用 `(?:ruser|user)=` 而不是两个替代分支：**只留一个捕获组**，否则分组
// 序号会跟着分支漂移，m[1:4]/m[4] 的约定立刻失效；`ruser` 排在前面，`ruser=` 的
// `user=` 部分不会被当成另一次匹配。`(\S*)` 允许空 —— `ruser= rhost=` 是真实形态，
// 这里只取"能取到的账号"，取不到就留空（来源 IP 照样要归到那个 IP 上）。
var (
	evFailRe = regexp.MustCompile(`(?i)(?:Failed\s+[\w][\w./-]*\s+for(?:\s+(?:invalid|illegal)\s+user)?\s+(\S+)` +
		`|authentication failure;[^\n]*?(?:ruser|user)=(\S*)|Invalid user\s+(\S+)\s+from)` +
		`[^\n]*?(?:from\s+|rhost=)?(\d{1,3}(?:\.\d{1,3}){3})`)
	evOKRe         = regexp.MustCompile(`(?i)Accepted\s+(?:password|publickey|keyboard-interactive|gssapi[^\s]*)\s+for\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})`)
	evDisconnectRe = regexp.MustCompile(`(?i)(?:Connection closed by|Connection reset by)\s+(?:authenticating user\s+(\S+)\s+)?(\d{1,3}(?:\.\d{1,3}){3})`)
	// evUserTailRe 是"回头找一次行内 user="的补充判据，只在上面的正则取到空账号时用
	// （见 extractAuthEvents 里对 `ruser= rhost=IP  user=root` 完整形态的说明）。
	// `(?:^|\s)` 保证不会命中 `ruser=` 里的那截 —— `r` 与 `u` 之间没有词边界。
	evUserTailRe = regexp.MustCompile(`(?i)(?:^|\s)user=(\S+)`)
)

func extractAuthEvents(lines []string) []authEvent {
	events := make([]authEvent, 0, 32)
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lower := strings.ToLower(line)
		// 先做一次廉价预筛，避免对每一行都跑几条正则。
		//
		// 预筛**必须与 evFailRe 的覆盖面一样宽**（复审 中1）：以前这里写死了
		// "failed password"，于是不带 sshd 标签的 `Failed publickey for root from …`
		// 在预筛这一步就被丢掉了 —— 后面那条正则再宽也永远看不到它。
		// 这里只做廉价判断，真正的判据在正则里，宽一点只是多跑一次正则。
		if !strings.Contains(lower, "sshd") && !strings.Contains(lower, "pam_unix") &&
			!strings.Contains(lower, "authentication failure") && !strings.Contains(lower, "accepted ") &&
			!strings.Contains(lower, "failed") && !strings.Contains(lower, "invalid user") {
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
			// 正则里的 `(?:ruser|user)=(\S*)` 是**非贪婪**匹配，遇到 PAM 的完整形态
			// `authentication failure; … ruser= rhost=203.0.113.9  user=root`
			// 会先在空的 `ruser=` 上停住 —— 账号取到空串，而它明明就写在行尾。
			// ruser 为空时回头找一次行内的 `user=` 补上（`(?:^|\s)user=` 不会误命中
			// `ruser=` 里的那截，因为 `r` 与 `u` 之间没有词边界）。
			if user == "" {
				if um := evUserTailRe.FindStringSubmatch(line); um != nil {
					user = um[1]
				}
			}
			events = append(events, authEvent{lineNo: i + 1, time: ts, user: user, ip: m[4], raw: line})
			continue
		}
		if m := evDisconnectRe.FindStringSubmatch(line); m != nil {
			// 连接被关掉本身不算失败，但反复出现是爆破的伴随特征；这里只记事件不单独成结论。
			//
			// **必须记成中性事件**：这一行以前写的是 ok:false，而下游
			// `if e.ok { successes++ } else { failures++ }` 就把它算成了失败 ——
			// 注释与代码相反。实测 5 行 `Connection closed by 203.0.113.9 [preauth]`
			// 加 1 行正常 `Accepted password` 直接产出 critical 的"失败后成功"，
			// 而 NAT 超时、跳板机断开、客户端重试都会留下这种断连。
			events = append(events, authEvent{lineNo: i + 1, time: ts, user: m[1], ip: m[2], neutral: true, raw: line})
		}
	}
	return events
}

// ---------- 关联 ----------

// AnalyzeAuth 从日志行里提取认证事件并按来源做关联。
func AnalyzeAuth(lines []string, th AuthThresholds) []Correlation {
	th = normalizeThresholds(th)
	events := extractAuthEvents(lines)
	if len(events) == 0 {
		return nil
	}

	type bucket struct {
		ip          string
		failures    int
		successes   int
		disconnects int
		// users 是**全部**不同账号（计数用），结论里的列表由 capList 截断。
		//
		// 为什么不再给这个集合本身封顶（复审 低1）：以前是
		// `if !b.users[u] { userCount++; if len(b.users) < maxAuthListed { b.users[u] = true } }`
		// —— 集合满 64 个之后新账号**进不了集合**，于是同一账号再失败一次时
		// `!b.users[u]` 又为真、userCount 再 +1：实测 80 个账号（后 10 个各失败
		// 两次就会出现）被报成 90 个，撞库阈值与文案里的数字全是错的。
		// 去重集合与结论列表是两件事：集合要**准**，列表才封顶。
		users     map[string]bool
		firstLine int
		lastLine  int
		firstTime string
		lastTime  string
		evidence  []string
	}
	// userSources 是"同一个账号被哪些来源尝试过"的累计。
	// 只统计**失败**来源：把成功登录也算进去的话，一台 NAT 后面 5 个人登录
	// 同一个账号（或同一台机器上 5 个账号登录成功）就会被判成分布式爆破/撞库。
	type userSources struct {
		ips map[string]bool // 全部不同来源（计数用，列表由 capList 截断）
		// ipCount 不再单独维护：它与 len(ips) 必须永远相等，两份数字迟早会分叉
		//（以前 ips 封顶、ipCount 计数，同一来源再出现一次就多加一个）。
		failures            int
		firstLine, lastLine int
		firstTime, lastTime string
	}
	byIP := map[string]*bucket{}
	userIPs := map[string]*userSources{}
	// 封顶时被丢掉的名字用**集合**记：计的是"多少个来源/账号"，
	// 不是"多少次事件"（复审 低2）—— 每个来源失败 3 次会被报成 3 倍，
	// "有 N 个来源未纳入统计"这句话就成了假的。
	droppedSources := map[string]bool{}
	droppedUsers := map[string]bool{}

	for _, e := range events {
		if e.ip == "" {
			continue
		}
		b := byIP[e.ip]
		if b == nil {
			if len(byIP) >= maxAuthSources {
				// 来源过多：不再新建桶，但要把这件事报出去（不静默丢）
				droppedSources[e.ip] = true
				continue
			}
			b = &bucket{ip: e.ip, users: map[string]bool{}}
			byIP[e.ip] = b
		}
		if e.neutral {
			// 中性事件：只做伴随计数，不参与失败/成功统计，也不进 users
			b.disconnects++
			continue
		}
		if e.user != "" {
			// 账号集合只收**失败**来源：一台 NAT 后 5 个账号正常登录成功
			// 不是"撞库"（审计实测原实现会报 user_sweep）。
			if !e.ok {
				b.users[e.user] = true
				us := userIPs[e.user]
				if us == nil {
					if len(userIPs) >= maxAuthUsers {
						// 账号过多：这个账号不参与分布式统计（如实计入 droppedUsers），
						// 但它对本来源的失败计数照常 —— 不能整个事件都丢掉。
						droppedUsers[e.user] = true
					} else {
						us = &userSources{ips: map[string]bool{}, firstLine: e.lineNo, firstTime: e.time}
						userIPs[e.user] = us
					}
				}
				if us != nil {
					us.failures++
					us.lastLine = e.lineNo
					if e.time != "" {
						us.lastTime = e.time
					}
					// 去重集合本身不封顶（见 userSources.ips 的说明）：
					// 结论里列出多少个由 capList 截断，这里是计数。
					us.ips[e.ip] = true
				}
			}
		}
		if e.ok {
			b.successes++
		} else {
			b.failures++
		}
		// firstLine/lastLine 只跟"真正参与结论"的事件走：断连行不该成为
		// 一条爆破结论的定位行（它既不是失败也不是成功）。
		if b.firstLine == 0 {
			b.firstLine = e.lineNo
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
		// users 是全部不同账号（计数用）；结论里**列出**的个数由 capList 截断，
		// 但阈值与文案里的数字必须是真实那个（= len(b.users)）。
		userCount := len(b.users)
		users := capList(sortedKeys(b.users), maxAuthListed)
		listed := strings.Join(users, ", ")
		if userCount > len(users) {
			listed += fmt.Sprintf(" 等 %d 个账号", userCount)
		}
		// 断连只在"已经成了结论"时作为旁证出现，单独出现不立案
		companion := ""
		if b.disconnects > 0 {
			companion = fmt.Sprintf("（另有 %d 次连接中断/重置，未计入失败次数）", b.disconnects)
		}

		// 失败多次之后登录成功：最值得先看的一条
		if b.failures >= th.BruteForceFailures && b.successes > 0 {
			out = append(out, Correlation{
				Kind:     "success_after_fail",
				Severity: SevCritical,
				Title:    "多次认证失败后登录成功（疑似爆破成功）",
				Detail: fmt.Sprintf("来自 %s 的 %d 次失败后出现了 %d 次成功登录，涉及账号 %s%s；请确认这次登录是否本人操作",
					b.ip, b.failures, b.successes, listed, companion),
				SourceIP:    b.ip,
				Users:       users,
				Failures:    b.failures,
				Successes:   b.successes,
				Disconnects: b.disconnects,
				FirstLine:   b.firstLine,
				LastLine:    b.lastLine,
				FirstTime:   b.firstTime,
				LastTime:    b.lastTime,
				Evidence:    b.evidence,
			})
			continue
		}

		// 换了很多用户名：撞库/账号枚举。这条比单纯"次数多"更具体，所以先判。
		if userCount >= th.SweepUsers {
			out = append(out, Correlation{
				Kind: "user_sweep", Severity: SevHigh,
				Title: "同一来源反复尝试多个账号（疑似撞库/账号枚举）",
				Detail: fmt.Sprintf("来自 %s 尝试了 %d 个不同账号：%s%s",
					b.ip, userCount, listed, companion),
				SourceIP: b.ip, Users: users, Failures: b.failures, Successes: b.successes,
				Disconnects: b.disconnects,
				FirstLine:   b.firstLine, LastLine: b.lastLine,
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
			if userCount > 0 {
				detail += "，尝试账号 " + listed
			}
			detail += companion
			out = append(out, Correlation{
				Kind: "brute_force", Severity: sev, Title: title, Detail: detail,
				SourceIP: b.ip, Users: users, Failures: b.failures, Successes: b.successes,
				Disconnects: b.disconnects,
				FirstLine:   b.firstLine, LastLine: b.lastLine,
				FirstTime: b.firstTime, LastTime: b.lastTime, Evidence: b.evidence,
			})
			continue
		}
	}

	// 同一个账号被很多来源尝试：分布式爆破。
	// 这里的 Failures 是**真实的认证失败次数**（原来是 IP 个数 —— 每个来源只试
	// 一次时数字碰巧一样，试两次以上就偏小），行号也补上（原来一直是 0，
	// 界面点进去定位不到任何一行）。
	for user, us := range userIPs {
		ipCount := len(us.ips)
		if ipCount < th.SweepIPs {
			continue
		}
		list := capList(sortedKeys(us.ips), maxAuthListed)
		suffix := ""
		if ipCount > len(list) {
			suffix = fmt.Sprintf(" 等 %d 个来源", ipCount)
		}
		out = append(out, Correlation{
			Kind: "distributed", Severity: SevHigh,
			Title: "同一账号被多个来源尝试（疑似分布式爆破）",
			Detail: fmt.Sprintf("账号 %s 被 %d 个来源尝试，共 %d 次认证失败：%s%s",
				user, ipCount, us.failures, strings.Join(list, ", "), suffix),
			Users: []string{user}, Failures: us.failures,
			FirstLine: us.firstLine, LastLine: us.lastLine,
			FirstTime: us.firstTime, LastTime: us.lastTime,
		})
	}

	// 封顶了就要说：否则"统计口径变窄"这件事没有任何人看得见。
	// 数字取集合大小 —— 计的是来源/账号的**个数**，不是事件条数（复审 低2）。
	if len(droppedSources) > 0 || len(droppedUsers) > 0 {
		out = append(out, Correlation{
			Kind: "analysis_capped", Severity: SevLow,
			Title: "关联统计已达上限（结果不完整）",
			Detail: fmt.Sprintf("日志里的来源 IP / 账号数量超过关联分析的统计上限（各 %d 个），"+
				"有 %d 个来源、%d 个账号未纳入跨行统计；单行命中明细不受影响",
				maxAuthSources, len(droppedSources), len(droppedUsers)),
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

func isFailureLine(e authEvent) bool { return !e.ok && !e.neutral }

// capList 限制结论里列出的名字个数（detail 字符串不能无限长）。
func capList(in []string, max int) []string {
	if len(in) <= max {
		return in
	}
	return in[:max]
}

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
