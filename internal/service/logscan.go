package service

import (
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
func (s *LogScanService) ScanLog(targetID, path string, lines int, kind string) (logscan.Result, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return logscan.Result{}, fmt.Errorf("请选择要扫描的日志文件")
	}
	// 取一下目标名，落库时要记清是哪台机器
	targetName := targetID
	if tg, _, err := s.targets.Auth(targetID); err == nil {
		targetName = tg.Name
	}
	// 路径只允许常规字符，避免拼接进 shell 造成注入
	if strings.ContainsAny(path, ";&|`$()<>\"'\n\t ") {
		return logscan.Result{}, fmt.Errorf("日志路径含非法字符")
	}
	if lines <= 0 || lines > 20000 {
		lines = 2000
	}
	// btmp / wtmp 是 utmp 二进制格式，直接 tail 出来是乱码（一行都认不出）；
	// 交给 lastb / last 解析成文本才有意义，这两条命令也顺带把记录格式化好了。
	var cmd, utmpTool string
	switch filepath.Base(path) {
	case "btmp":
		cmd, utmpTool = fmt.Sprintf("lastb -n %d 2>/dev/null", lines), "lastb"
	case "wtmp":
		cmd, utmpTool = fmt.Sprintf("last -n %d 2>/dev/null", lines), "last"
	default:
		cmd = fmt.Sprintf("tail -n %d %s 2>/dev/null", lines, shellQuotePath(path))
	}

	out, err := s.run(targetID, cmd, 25*time.Second)
	if err != nil {
		// 读不到文件时退出码非 0，换成能看懂的提示
		if utmpTool != "" {
			return logscan.Result{}, fmt.Errorf("读不到这个登录记录（%s 解析失败：文件为空、权限不足或格式不匹配）：%s", utmpTool, path)
		}
		return logscan.Result{}, fmt.Errorf("读不到这个日志（文件不存在或当前账号没有权限）：%s", path)
	}
	if strings.TrimSpace(out) == "" {
		return logscan.Result{}, fmt.Errorf("这个日志是空的，或最近 %d 行内没有内容：%s", lines, path)
	}
	// 日志类型决定用哪套规则：auto 时按路径与内容推断。
	// 拿 Web 攻击规则去跑 sshd 日志只会制造噪音，反之亦然。
	auto := kind == "" || kind == logscan.KindAuto
	if auto {
		kind = logscan.GuessLogKind(path, out)
	}
	rules := logscan.RulesForKind(logscan.AllRules(), kind)
	res := logscan.Scan(out, path, rules)
	res.Kind = kind
	res.KindAuto = auto
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
		s.pool.Drop(key)
		return "", err
	}
	return out, nil
}
