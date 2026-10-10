package logscan

import (
	"strings"
	"testing"
	"time"
)

// WEB 日志里攻击者可控的 User-Agent 不能造出认证关联。
//
// AnalyzeAuth 找的是 sshd / sudo 那套"失败后成功"的结构，而 nginx 访问日志的
// User-Agent 是攻击者随便写的：填一行 `Failed password for root from 203.0.113.9`
// 再加一行 Accepted，以前就会产出 severity=critical 的关联、IP 指向他填的地址
// （栽赃给任意 IP 都行），而且会写进库。现在关联只在系统日志上算。
func TestWebLogUACannotForgeAuthCorrelation(t *testing.T) {
	text := strings.Join([]string{
		`10.0.0.1 - - [11/Oct/2026:10:00:00 +0800] "GET / HTTP/1.1" 200 10 "-" "Failed password for root from 203.0.113.9 port 22 ssh2"`,
		`10.0.0.2 - - [11/Oct/2026:10:00:01 +0800] "GET /a HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
		`10.0.0.3 - - [11/Oct/2026:10:00:02 +0800] "GET /b HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
		`10.0.0.4 - - [11/Oct/2026:10:00:03 +0800] "GET /c HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
		`10.0.0.5 - - [11/Oct/2026:10:00:04 +0800] "GET /d HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
		`10.0.0.6 - - [11/Oct/2026:10:00:05 +0800] "GET /e HTTP/1.1" 200 10 "-" "Mozilla/5.0"`,
		`10.0.0.7 - - [11/Oct/2026:10:00:06 +0800] "GET /f HTTP/1.1" 200 10 "-" "Accepted password for root from 203.0.113.9 port 22 ssh2"`,
	}, "\n")

	res := Scan(text, "/var/log/nginx/access.log", RulesForKind(AllRules(), KindWeb))
	if len(res.Correlations) != 0 {
		t.Errorf("WEB 日志不该产出认证关联，实际 %d 条（第一条 source_ip=%v）",
			len(res.Correlations), res.Correlations[0].SourceIP)
	}
}

// 系统日志里的同一批行仍要能关联出来（别把功能一起关掉）。
func TestSystemLogStillProducesAuthCorrelation(t *testing.T) {
	text := strings.Join([]string{
		"Oct 11 10:00:00 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:01 h sshd[2]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:02 h sshd[3]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:03 h sshd[4]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:04 h sshd[5]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:05 h sshd[6]: Accepted password for root from 203.0.113.9 port 22 ssh2",
	}, "\n")

	res := Scan(text, "/var/log/auth.log", RulesForKind(AllRules(), KindSystem))
	if len(res.Correlations) == 0 {
		t.Fatal("系统日志的爆破后成功应当产出关联")
	}
}

// 单行超长不能把扫描拖垮。
//
// containsShellChars 对每个分隔符都要处理"整行剩余文本"，10 万个分号的单行
// 修复前要 2.8 秒（`tail -n 2000` 下 2000 行 8KB 分号能把界面卡两分钟）。
// 现在 trimPathPrefix 只看开头 200 字节，且单行超过 8KB 会被截断。
func TestHugeLineDoesNotStallScan(t *testing.T) {
	huge := strings.Repeat(";", 100000)
	lines := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		lines = append(lines, huge)
	}
	text := strings.Join(lines, "\n")

	start := time.Now()
	_ = Scan(text, "/tmp/x.log", RulesForKind(AllRules(), KindSystem))
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("200 行 10 万分号扫了 %v，说明还是有 O(n²)", elapsed)
	}
	t.Logf("200 行 10 万分号: %v", elapsed)
}
