package service

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/logscan"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/store"

	"golang.org/x/crypto/ssh"
)

// 单次扫描的预算与上限。
//
// 以前整次扫描没有任何时间预算：实测 2000 行 × 7.2KB 的**正常内容**要 53 秒，
// 这段时间里界面只有一个核在转、HTTP 请求不返回，用户既看不到进度也取消不掉。
const (
	// scanBudget 是规则匹配那一段的时间预算（取日志那一段另有自己的超时）。
	// 预算耗尽时扫描停在超时处，并在 Result 里如实标记 Truncated / StoppedAtLine，
	// 结果照常返回 —— 半份结果加一句"不完整"远比"什么都不回"有用。
	scanBudget = 20 * time.Second
	// scanMaxHits 与 logscan.DefaultMaxHits 同值（那边是引擎侧的兜底），
	// 这里显式引一次是为了让 service 的取舍有名字可指，不写字面量。
	scanMaxHits = logscan.DefaultMaxHits
)

// LogFile 是目标主机上一个可扫描的日志。
type LogFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Kind string `json:"kind"` // web | auth | system | other
}

// LogScanService 扫描目标主机日志里的攻击载荷与入侵痕迹。
type LogScanService struct {
	targets *TargetService
	pool    *sshx.Pool
	store   *store.Store

	// readLog 是"把日志尾部若干行取回来"的可替换钩子，nil 表示走 sshx
	//（见 read）。存在的唯一理由是测试：不替身这一环，就没法在不起 SSH 的
	// 情况下测到"整次扫描的时间预算"—— ScanLog 的前半段必须先拿到文本。
	readLog func(script string, timeout time.Duration) (string, error)
	// scanBudgetForTest 只在测试里设置（默认 0 = 用 scanBudget）：
	// 真跑 20 秒才能验到"到点就停"的话，这条用例没人愿意跑。
	scanBudgetForTest time.Duration
}

// NewLogScanService 构造服务。
func NewLogScanService(targets *TargetService, pool *sshx.Pool, st *store.Store) *LogScanService {
	return &LogScanService{targets: targets, pool: pool, store: st}
}

// 常见日志候选：存在才输出（路径 + 字节数）。
const logProbeScript = `for f in /var/log/nginx/access.log /var/log/nginx/error.log /var/log/apache2/access.log /var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog /var/log/btmp /var/log/wtmp; do [ -f "$f" ] && echo "$f|$(stat -c%s "$f" 2>/dev/null || echo 0)"; done`

// ListLogFiles 探测目标上存在的常见日志文件。
func (s *LogScanService) ListLogFiles(targetID string) ([]LogFile, error) {
	out, err := s.run(targetID, logProbeScript, 12*time.Second)
	if err != nil {
		return nil, err
	}
	files := []LogFile{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		f := LogFile{Path: parts[0], Kind: classifyLog(parts[0])}
		if len(parts) > 1 {
			fmt.Sscanf(parts[1], "%d", &f.Size)
		}
		files = append(files, f)
	}
	return files, nil
}

func classifyLog(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "access") || strings.Contains(lower, "error_log") ||
		strings.Contains(lower, "nginx") || strings.Contains(lower, "apache") || strings.Contains(lower, "httpd"):
		return "web"
	case strings.Contains(lower, "auth") || strings.Contains(lower, "secure") ||
		strings.Contains(lower, "btmp") || strings.Contains(lower, "wtmp"):
		return "auth"
	case strings.Contains(lower, "messages") || strings.Contains(lower, "syslog"):
		return "system"
	}
	return "other"
}

// ScanLog 扫描某个日志文件的尾部若干行。
//
// ctx 是发起这次扫描的请求的 context：整次扫描有 scanBudget 的时间预算，
// 用户关页面/切走时应当提前收手，而不是把整批日志跑完再把结果丢掉。
// 预算或取消导致的提前收工**不会丢结果**：Result.Truncated 为 true、
// TruncatedReason 说明原因、StoppedAtLine 说明停在哪一行，照常返回给前端。
func (s *LogScanService) ScanLog(ctx context.Context, targetID, path string, lines int, kind string) (logscan.Result, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return logscan.Result{}, fmt.Errorf("请选择要扫描的日志文件")
	}
	// 取一下目标名，落库时要记清是哪台机器。
	// targets 为 nil（测试构造）时跳过：这里只是给落库记录补一个好看的名字，
	// 不该成为"没有目标服务就没法扫描"的理由。
	targetName := targetID
	if s.targets != nil {
		if tg, _, err := s.targets.Auth(targetID); err == nil {
			targetName = tg.Name
		}
	}
	// 路径只允许常规字符，避免拼接进 shell 造成注入
	if strings.ContainsAny(path, ";&|`$()<>\"'\n\t ") {
		return logscan.Result{}, fmt.Errorf("日志路径含非法字符")
	}
	if lines <= 0 || lines > 20000 {
		lines = 2000
	}
	// btmp / wtmp 是 utmp 定长记录的二进制格式，直接 tail 出来是乱码（一行都认不出）；
	// 交给 lastb / last 解析成文本才有意义。
	//
	// 注意 lastb/last 是从文件尾部往回读的，-n 只取最近这些条，不会把整份读进来，
	// 所以不需要自己去截断文件（试过 tail -c 配 -f -，这个 util-linux 版本不认）。
	var cmd, utmpTool string
	switch filepath.Base(path) {
	case "btmp":
		cmd, utmpTool = fmt.Sprintf("lastb -n %d 2>/dev/null", lines), "lastb"
	case "wtmp":
		cmd, utmpTool = fmt.Sprintf("last -n %d 2>/dev/null", lines), "last"
	default:
		cmd = fmt.Sprintf("tail -n %d %s 2>/dev/null", lines, shellQuotePath(path))
	}

	out, err := s.read(targetID, cmd, 25*time.Second)
	if err != nil {
		// 读不到文件时退出码非 0，换成能看懂的提示
		if utmpTool != "" {
			return logscan.Result{}, fmt.Errorf("没读到登录记录（%s 没有输出）：%s\n"+
				"常见原因是这个文件是空的（这台机器上还没有失败登录），也可能是权限不足或格式不匹配。",
				utmpTool, path)
		}
		return logscan.Result{}, fmt.Errorf("读不到这个日志（文件不存在或当前账号没有权限）：%s", path)
	}
	if strings.TrimSpace(out) == "" {
		if utmpTool != "" {
			return logscan.Result{}, fmt.Errorf("%s 里没有记录（这台机器上还没有失败登录）：%s", utmpTool, path)
		}
		return logscan.Result{}, fmt.Errorf("这个日志是空的，或最近 %d 行内没有内容：%s", lines, path)
	}
	// 日志类型决定用哪套规则：auto 时按路径与内容推断。
	// 拿 Web 攻击规则去跑 sshd 日志只会制造噪音，反之亦然。
	auto := kind == "" || kind == logscan.KindAuto
	if auto {
		kind = logscan.GuessLogKind(path, out)
	}
	rules := logscan.RulesForKind(logscan.AllRules(), kind)
	// **把已经算好的 kind 传进去**：Scan 内部原来会自己再推断一次
	//（GuessLogKind），两次推断不一致时就会在 web 行上跑认证关联 ——
	// 混合日志（前 300 行 syslog 不少于 web 行）正好会撞上。
	// ScanWithKind 会把实际用的 Kind/KindAuto 回填进 Result。
	//
	// 走 runScan 而不是直接调 ScanWithKind：那里给了时间预算与 ctx，
	// 整次扫描不会再无上限地跑（见 scanBudget 的说明）。
	// 走 runScan 而不是直接调 ScanWithKind：那里给了时间预算与 ctx，
	// 整次扫描不会再无上限地跑（见 scanBudget 的说明）。
	res := runScan(ctx, out, path, rules, kind, s.budget())
	// RuleCount 要保留：RulesForKind 过后 rules 才是本次真正用的规则集，
	// ScanWithKind 里设的是 AllRules 的长度。
	res.RuleCount = len(rules)

	// 命中结果落库：态势页要看跨多次扫描、跨目标的累计，
	// 单次扫描的结果留在内存里是没法做排行与时间线的。
	if s.store != nil && (len(res.Hits) > 0 || len(res.Correlations) > 0) {
		// 毫秒：跨边界的时间戳统一用毫秒（连接历史与核查报告都是毫秒），
		// 之前这里用秒，以后做"按小时筛"或与连接历史关联必然错一次
		now := time.Now().UnixMilli()
		events := make([]store.ScanEvent, 0, len(res.Hits)+len(res.Correlations))
		for _, h := range res.Hits {
			events = append(events, store.ScanEvent{
				TS: now, TargetID: targetID, TargetName: targetName,
				Path: path, Kind: res.Kind,
				RuleID: h.RuleID, RuleName: h.RuleName,
				Severity: h.Severity, Category: h.Category,
				SourceIP: h.SourceIP, LineNo: h.LineNo,
				Decoded: h.Decoded, Sample: h.Line,
			})
		}
		// 跨行关联的结论同样落库。
		// 态势大屏最该先看到的就是"多次失败后登录成功"这类结论，
		// 只存单行命中的话它们扫完就消失了，也进不了跨目标累计。
		for _, c := range res.Correlations {
			events = append(events, store.ScanEvent{
				TS: now, TargetID: targetID, TargetName: targetName,
				Path: path, Kind: res.Kind,
				RuleID:   "CORR-" + c.Kind,
				RuleName: c.Title,
				Severity: c.Severity,
				Category: "correlation",
				SourceIP: c.SourceIP,
				LineNo:   c.FirstLine,
				Sample:   c.Detail,
			})
		}
		if err := s.store.InsertScanEvents(events); err != nil {
			log.Printf("写入攻击事件失败: %v", err)
		}
	}
	return res, nil
}

func shellQuotePath(p string) string {
	return "'" + strings.ReplaceAll(p, "'", `'\''`) + "'"
}

// runScan 是"把日志文本交给规则引擎"的唯一入口，预算与取消都在这里给。
//
// 为什么单独抽一层：ScanLog 要先把日志从目标机取回来（那一步单测做不到），
// 而"有没有给时间预算/会不会响应取消"这件事必须能被直接测到 —— 抽出来之后
// 测试可以自己造文本、ctx 与预算，改回无预算的 ScanWithKind 时立刻红。
//
// budget 由调用方给（生产路径传 scanBudget）：做成参数而不是直接读常量，
// 是为了让测试能用一个极小的预算验证"到点就停"，不必真跑 20 秒。
func runScan(ctx context.Context, text, path string, rules []logscan.Rule, kind string, budget time.Duration) logscan.Result {
	if ctx == nil {
		// 拿不到请求 context 时（内部调用、测试）用 Background，
		// 别让 nil 变成"取消不了"之外的另一种行为。
		ctx = context.Background()
	}
	return logscan.ScanWithLimits(text, path, rules, kind, logscan.ScanLimits{
		MaxDuration: budget,
		Ctx:         ctx,
		MaxHits:     scanMaxHits,
	})
}

// read 把日志文本取回来：测试可以用 readLog 替身顶上（见字段说明），
// 生产路径走 run（sshx）。
func (s *LogScanService) read(targetID, script string, timeout time.Duration) (string, error) {
	if s.readLog != nil {
		return s.readLog(script, timeout)
	}
	return s.run(targetID, script, timeout)
}

// budget 是本次扫描的时间预算（测试可覆盖，见 scanBudgetForTest）。
func (s *LogScanService) budget() time.Duration {
	if s.scanBudgetForTest > 0 {
		return s.scanBudgetForTest
	}
	return scanBudget
}

func (s *LogScanService) run(targetID, script string, timeout time.Duration) (string, error) {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return "", err
	}
	key := poolKey(targetID)
	conn, err := s.pool.Acquire(key, func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return "", err
	}
	out, err := sshx.RunOutput(conn, script, timeout)
	if err != nil {
		// 只有连接真的不可用才丢弃它。命令自己退出码非 0（比如 lastb 没读到东西）
		// 也走这里，但绝不能因此 Drop —— 这条连接是终端、文件、监控共用的，
		// 丢掉就等于把用户正在用的终端一起掐了。
		if sshx.IsConnError(err) {
			s.pool.DropIf(key, conn) // 按身份删，别误删别人刚换上的那条
		}
		return "", err
	}
	return out, nil
}
