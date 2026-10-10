package logscan

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 这组测试固化复审里的 logscan 修复，断言都写成"改回错误版本会红"。

// ---------- 低5：truncate 对本来就非法的 UTF-8 输入也要归一 ----------

// 输入本身就是坏字节时，"退到 rune 边界"救不了它：里面根本没有合法边界。
// 实测修复前 truncate(28 字节的坏串, 31) 把非法串**原样返回** —— 证据行照样
// 以非法 UTF-8 进库、进 json.Marshal，界面上是一串乱码。
func TestTruncateNormalizesInvalidUTF8Input(t *testing.T) {
	// 造一个 28 字节、确定非法的串：25 个 ASCII + "日" 的前两个字节（缺第三个）
	bad := []byte(strings.Repeat("a", 26))
	bad = append(bad, 0xE6, 0x97) // "日" 的前两个字节，缺第三个
	if utf8.Valid(bad) {
		t.Fatal("测试前提不成立：造出来的串是合法 UTF-8")
	}
	in := string(bad)
	if len(in) != 28 {
		t.Fatalf("测试前提变了：长度 %d，期望 28", len(in))
	}

	// n 大于长度：走"原样返回"那条分支，以前非法串就从这里漏出去
	if got := truncate(in, 31); !utf8.ValidString(got) {
		t.Errorf("truncate(坏串, 31) 返回了非法 UTF-8：%q (% x)", got, got)
	}
	// n 小于长度：截断路径同样要合法
	for _, n := range []int{3, 5, 8, 12, 20, 28} {
		got := truncate(in, n)
		if !utf8.ValidString(got) {
			t.Errorf("truncate(坏串, %d) 返回了非法 UTF-8：%q (% x)", n, got, got)
		}
		if len(got) > n {
			t.Errorf("truncate(坏串, %d) 长度 %d 超上限", n, len(got))
		}
	}
	// 合法输入的行为不能变（中文按 3 字节算预算）
	if got := truncate("这是一条中文日志", 10); !utf8.ValidString(got) || len(got) > 10 {
		t.Errorf("合法中文输入的行为被改坏了：%q (%d 字节)", got, len(got))
	}
}

// 单行 8KB 截断也必须退到 rune 边界：直接 line[:8192] 会把正好跨在边界上的
// 多字节字符砍成半个，切出来的行本身就是非法 UTF-8。
//
// **这条锁的是 cutAtRuneBoundary 的契约**（返回合法 UTF-8、不超过上限），
// 不是"Scan 一定调了它"—— Scan 里那一刀在外部观察不到输出差异（见上面那条的
// 说明）。改回 `line[:maxLineBytes]` 这条不会红；改坏 cutAtRuneBoundary 的实现
// 才会红。诚实地写在这里，免得后来的人误以为它覆盖了调用点。
func TestCutAtRuneBoundaryKeepsValidUTF8(t *testing.T) {
	// 造一行"3 字节字符密排"的长文本：任何不等于 3 的倍数的刀口都落在字符中间
	line := strings.Repeat("中", 4000) // 12000 字节
	for _, max := range []int{maxLineBytes, maxLineBytes - 1, maxLineBytes - 2, 5, 4, 3, 1} {
		got := cutAtRuneBoundary(line, max)
		if !utf8.ValidString(got) {
			t.Errorf("cutAtRuneBoundary(_, %d) 切出了非法 UTF-8", max)
		}
		if len(got) > max {
			t.Errorf("cutAtRuneBoundary(_, %d) 长度 %d 超上限", max, len(got))
		}
	}
	// 不超过上限时原样返回
	short := "短"
	if got := cutAtRuneBoundary(short, 100); got != short {
		t.Errorf("不需要截断时应当原样返回：%q", got)
	}
}

// 端到端：命中行的证据必须是合法 UTF-8（会进库、进 JSON）。
//
// 这条覆盖的是 truncate 那一半（证据行、命中片段必须合法）。它**不覆盖** 8KB
// 那一刀 —— 诚实说明：证据行是"从行首往右 500 字节"，而 8KB 刀口在 8192 字节
// 处，切坏的那几个字节根本进不了证据行；`Line`/`Matched` 又各自只取 160/500
// 字节，所以"按字节切"在外部**观察不到输出差异**（差异是"合规性"而非检测力：
// 8192 处的半个字符对规则匹配没有正面作用，任何情况下都不该留非法字节）。
// 因此那一刀的判据放在 cutAtRuneBoundary 的单元测试里，并如实标注它锁的是
// 辅助函数的契约、不是"Scan 一定调了它"。
func TestScanHitLinesAreAlwaysValidUTF8(t *testing.T) {
	for _, prefixLen := range []int{0, 1, 2, 3} {
		line := strings.Repeat("A", 8000+prefixLen) + strings.Repeat("中", 100) +
			" union select 1 from users"
		res := Scan(line, "/var/log/app.log", AllRules())
		if len(res.Hits) == 0 {
			t.Fatalf("测试前提不成立（prefixLen=%d）：这行应当命中 SQL 注入", prefixLen)
		}
		for _, h := range res.Hits {
			if !utf8.ValidString(h.Line) {
				t.Errorf("prefixLen=%d 证据行不是合法 UTF-8", prefixLen)
			}
			if len(h.Line) > 500 {
				t.Errorf("prefixLen=%d 证据行 %d 字节超上限", prefixLen, len(h.Line))
			}
			if !utf8.ValidString(h.Matched) {
				t.Errorf("prefixLen=%d 命中片段不是合法 UTF-8", prefixLen)
			}
		}
	}
}

// ---------- 低6：containsShellChars 自己认 ${IFS} ----------

// `${IFS}` 在 shell 里就是空格，但算子只看字面空白 —— 修复前
// containsShellChars(";cat${IFS}/etc/passwd") 返回空串，今天不漏检纯粹因为用到
// 它的规则都在链里带了 normalizeIFS，属于**隐式依赖**（新加算子/规则忘带那个
// 变换就静默漏检）。现在算子自己先折叠一次，判定写在算子内部。
//
// 注意断言故意**不走变换链**：直接调算子。带链的端到端由 rules_test 的样本覆盖。
func TestContainsShellCharsUnderstandsIFS(t *testing.T) {
	positives := []string{
		";cat${IFS}/etc/passwd",
		";cat$IFS/etc/passwd",
		"|cat${IFS}/etc/passwd",
		"&&whoami${IFS}",
		";cat${IFS}9/etc/passwd", // ifsToSpace 覆盖 ${IFS}<数字> 的写法
	}
	for _, s := range positives {
		if got := containsShellChars(s); got == "" {
			t.Errorf("算子自己认不出 ${IFS}（又回到隐式依赖了）: %q", s)
		}
	}
	// 折叠不能把正常文案变成命中
	for _, s := range []string{
		"the IFS variable is documented here",
		"gzip, deflate, br;q=1.0",
		"set ${IFS} in your profile",
	} {
		if got := containsShellChars(s); got != "" {
			t.Errorf("正常文案被误报: %q -> %q", s, got)
		}
	}
}

// ---------- 低7：Scan 的跨行关联要用调用方算好的 kind ----------

// 混合日志（前 300 行 syslog 占多数、后面夹 web 行）在"路径判不出 kind"时会被
// GuessLogKind 判成 KindSystem，而调用方（service 层）可能已经按别的 kind 筛过
// 规则了。有了 ScanWithKind，调用方可以把已算好的 kind 传进来，内部不再自己猜。
func TestScanWithKindUsesCallerSuppliedKind(t *testing.T) {
	text := strings.Join([]string{
		"10.0.0.1 - - [11/Oct/2026:10:00:00 +0800] \"GET / HTTP/1.1\" 200 10 \"-\" \"Failed password for root from 203.0.113.9 port 22 ssh2\"",
		"10.0.0.2 - - [11/Oct/2026:10:00:01 +0800] \"GET /a HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"",
		"Oct 11 10:00:02 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:03 h sshd[2]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:04 h sshd[3]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:05 h sshd[4]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 11 10:00:06 h sshd[5]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"10.0.0.7 - - [11/Oct/2026:10:00:07 +0800] \"GET /f HTTP/1.1\" 200 10 \"-\" \"Accepted password for root from 203.0.113.9 port 22 ssh2\"",
	}, "\n")

	// 路径判不出 kind（没有 nginx/access 之类字样）→ 自动推断
	auto := GuessLogKind("app.log", text)
	if auto != KindSystem {
		t.Fatalf("测试前提变了：混合日志被判成 %q，期望 %q", auto, KindSystem)
	}

	// 调用方说这是 web 日志：不该在 web 行上跑认证关联
	web := ScanWithKind(text, "app.log", RulesForKind(AllRules(), KindWeb), KindWeb)
	if len(web.Correlations) != 0 {
		t.Errorf("调用方传了 kind=web，仍然在 web 行上跑了认证关联（%d 条）", len(web.Correlations))
	}
	if web.Kind != KindWeb || web.KindAuto {
		t.Errorf("结果里的 kind 回填不对：kind=%q auto=%v", web.Kind, web.KindAuto)
	}

	// 调用方说这是系统日志：关联照旧要出
	sys := ScanWithKind(text, "app.log", RulesForKind(AllRules(), KindSystem), KindSystem)
	if len(sys.Correlations) == 0 {
		t.Error("kind=system 时认证关联不该被关掉")
	}

	// 兼容包装：kind 传空 → 自动推断，行为与老 Scan 一致
	compat := Scan(text, "app.log", AllRules())
	if compat.Kind != auto || !compat.KindAuto {
		t.Errorf("Scan 的兼容行为变了：kind=%q auto=%v（期望 %q / true）", compat.Kind, compat.KindAuto, auto)
	}
	// 路径能判出 web 时，自动推断这一半的既有行为不能变
	webPath := Scan(text, "/var/log/nginx/access.log", AllRules())
	if webPath.Kind != KindWeb {
		t.Errorf("带 nginx 的路径应当判成 web，实际 %q", webPath.Kind)
	}
}
