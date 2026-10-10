package logscan

import (
	"fmt"
	"strings"
	"testing"
)

// 每条规则都自带 test.positive / test.negative 样本 —— 那是规则作者写下的
// 期望行为，也是算子实现的验收标准。这个测试逐条跑一遍：
// 正样本必须命中，负样本必须不命中。
//
// 注意这里用 `Rule.Match` 直接匹配**变换后**的样本，不走生产路径 `Scan`。
// 差别在 Scan 会按行切分：样本里的 `127.0.0.1\nid` 被切成两行后不再命中，
// 所以 SelfTest 是 596/5。Match 测的是"规则本身对不对"，
// 生产路径的覆盖由 loader_test.go 的 SelfTest / CrossTest 负责。
func TestRuleSamples(t *testing.T) {
	loaded, report, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	if len(report.UnknownOperators) > 0 {
		t.Errorf("还有未实现的算子: %v", report.UnknownOperators)
	}
	if len(report.UnknownTransforms) > 0 {
		t.Errorf("还有未实现的变换: %v", report.UnknownTransforms)
	}
	if len(loaded) == 0 {
		t.Fatal("没有加载到任何规则")
	}

	apply := func(r Rule, s string) string {
		for _, fn := range r.Chain {
			s = fn(s)
		}
		return s
	}

	checked := 0
	for _, lr := range loaded {
		r := lr.Rule
		for _, pos := range lr.Positive {
			checked++
			if got := r.Match(apply(r, pos)); got == "" {
				t.Errorf("%s 正样本未命中: %q", r.ID, pos)
			}
		}
		for _, neg := range lr.Negative {
			checked++
			if got := r.Match(apply(r, neg)); got != "" {
				t.Errorf("%s 负样本误报: %q（命中 %q）", r.ID, neg, got)
			}
		}
	}
	t.Logf("共验证 %d 个样本，覆盖 %d 条规则", checked, len(loaded))
}

// 语义算子必须真的接上了，而不是继续被当成"未实现的算子"跳过。
func TestSemanticOperatorsLoaded(t *testing.T) {
	loaded, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	want := map[string]bool{
		"SQLI-4009": false, // detectSQLi（排除弱指纹）
		"SQLI-4011": false, // detectSQLi（只要弱指纹）
		"XSS-5007":  false, // detectXSS
		"RCE-6001":  false, // containsShellChars
		"LFI-7001":  false, // detectPathTraversal
		"WS-9001":   false, // isWebshellContent
	}
	for _, lr := range loaded {
		if _, ok := want[lr.ID]; ok {
			if lr.Semantic == nil {
				t.Errorf("%s 应有语义算子实现", lr.ID)
			}
			want[lr.ID] = true
		}
	}
	for id, ok := range want {
		if !ok {
			t.Errorf("%s 没有加载成功（用它的算子仍未实现？）", id)
		}
	}
}

// 只判上传文件**内容**的规则（FILES_MAGIC）必须退出日志链；
// 但判**文件名**的规则必须留着 —— 文件名在访问日志里是逐字出现的
// （`GET /upload/shell.php.jpg HTTP/1.1`），跳掉它们会丢真检出。
// 上一版就是按"targets 里有 FILES 就跳"写的，跳过头被审计抓到。
func TestFileContentRulesExcludedButNameRulesKept(t *testing.T) {
	loaded, report, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	byID := map[string]Rule{}
	for _, lr := range loaded {
		byID[lr.ID] = lr.Rule
	}
	if _, ok := byID["WS-9004"]; ok {
		t.Error("WS-9004 判的是文件魔数（FILES_MAGIC），不该进日志链")
	}
	if !strings.Contains(strings.Join(report.Skipped, "\n"), "WS-9004") {
		t.Errorf("跳过清单里应出现 WS-9004：%v", report.Skipped)
	}
	for _, id := range []string{"WS-9003", "UPLOAD-1001", "UPLOAD-1002"} {
		if _, ok := byID[id]; !ok {
			t.Errorf("%s 判的是文件名/路径形态，日志行里会出现，不该被跳过", id)
		}
	}

	// 反过来：魔数那类**文本**不该再被判成 webshell。
	// `#!/bin/sh` 经 hexEncode 会变成 `23212f…`、`cafebabe` 本身就是纯 hex，
	// 都会撞上魔数表 —— 这断言的是"套上去也不误报"，不是"它没加载"。
	rules := RulesOf(loaded)
	for _, line := range []string{
		"the file starts with #!/bin/sh and is executable",
		"cafebabe is a magic number used by Java class files",
	} {
		for _, h := range Scan(line+"\n", "log", rules).Hits {
			if h.RuleID == "WS-9004" {
				t.Errorf("文本 %q 不该被 WS-9004 命中", line)
			}
		}
	}

	// 而文件名类规则要真能命中访问日志行
	hit := func(line, want string) bool {
		for _, h := range Scan(line+"\n", "log", rules).Hits {
			if h.RuleID == want {
				return true
			}
		}
		return false
	}
	if !hit("GET /upload/shell.php.jpg HTTP/1.1", "WS-9003") {
		t.Error("访问日志里的双扩展名文件名应该被 WS-9003 命中（真检出，别跳掉）")
	}
}

// 命令注入不能只看 `$(`：jQuery 与模板里到处都是它。
// 走**生产路径** Scan，规则的变换链（normalizeIFS 等）也参与。
func TestShellCharsFalsePositiveAndMisses(t *testing.T) {
	loaded, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	rules := RulesOf(loaded)
	hitsRCE := func(line string) bool {
		for _, h := range Scan(line+"\n", "log", rules).Hits {
			if h.RuleID == "RCE-6001" {
				return true
			}
		}
		return false
	}

	for _, s := range []string{
		"$(document).ready(function(){ doSomething(); })",
		"$(this).val()",
		"total price is $(price) * 2",
		"Set the `PATH` variable in your shell profile",
	} {
		if hitsRCE(s) {
			t.Errorf("正常文本被 RCE-6001 命中: %q", s)
		}
	}

	// 真命令替换不能漏 —— 含带路径、相对路径、以及审计指出的词表缺口
	for _, s := range []string{
		"$(id)", "$(cat /etc/passwd)", "`id`", "`cat /etc/passwd`", "$(whoami)",
		"$(/bin/id)", "$(./id)", "$(../../bin/id)",
		"$(openssl base64 -d <<< aWQ=)", "$(history)", "$(dd if=/dev/zero of=/tmp/x)",
		"; cat /etc/passwd", ";cat${IFS}/etc/passwd", ";cat$IFS/etc/passwd",
		"127.0.0.1;/bin/hostname", "| whoami", "127.0.0.1;id",
	} {
		if !hitsRCE(s) {
			t.Errorf("命令注入漏检: %q", s)
		}
	}
}

// Java 堆栈与常见 API 不该被判成 webshell/代码执行。
// 这条要同时覆盖 WS-9002 与 RCE-6007/6008 —— 它们用的是同一批词。
func TestJavaStackNotFlagged(t *testing.T) {
	loaded, _, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	rules := RulesOf(loaded)
	for _, line := range []string{
		"java.lang.Class.forName(org.h2.Driver) at com.example.Boot.<clinit>(Boot.java:12)",
		"new ProcessBuilder(\"java\", \"-jar\", \"app.jar\").start()",
		"at java.lang.Class.forName0(Native Method)",
	} {
		for _, h := range Scan(line+"\n", "log", rules).Hits {
			switch h.RuleID {
			case "WS-9002", "RCE-6007", "RCE-6008":
				t.Errorf("%s 不该命中 Java 堆栈/常见 API: %q", h.RuleID, line)
			}
		}
	}
}

// 参数白名单要覆盖**所有**算子，而且拦得住**已声明**的字段 ——
// 否则 `regex + min_depth: 2`、`detectXSS + min_fingerprint_len: 8`
// 这类"写了但不生效"的参数会被静默接受。
func TestOperatorParamAllowRejectsUnknownParams(t *testing.T) {
	cases := []struct{ op, param, val string }{
		{"detectXSS", "min_fingerprint_len", "8"},
		{"detectXSS", "pattern", `"x"`},
		{"containsShellChars", "fingerprints", `["quote probing"]`},
		{"isWebshellContent", "min_depth", "2"},
		{"detectSQLi", "patterns", `["a"]`},
		{"detectPathTraversal", "min_fingerprint_len", "8"},
		{"regex", "min_depth", "2"},
		{"regex", "patterns", `["a"]`},
		{"pm", "min_fingerprint_len", "8"},
	}
	for _, c := range cases {
		body := fmt.Sprintf(`
version: 1
meta:
  name: t
  author: t
  category: t
rules:
  - id: T-1
    severity: high
    category: t
    message: t
    transforms: [lowercase]
    operator:
      name: %s
      params:
        %s: %s
    test:
      positive: ["x"]
      negative: ["y"]
`, c.op, c.param, c.val)
		loaded, skipped, err := LoadRules([]byte(body), "t.yaml")
		if err != nil {
			t.Fatalf("%s: 加载失败: %v", c.op, err)
		}
		if len(loaded) != 0 {
			t.Errorf("%s 不该接受参数 %s，规则应被跳过", c.op, c.param)
			continue
		}
		if !strings.Contains(strings.Join(skipped, "\n"), c.param) {
			t.Errorf("%s 的跳过原因里应指出 %s，实际：%v", c.op, c.param, skipped)
		}
	}

	// 反向：算子用它**支持**的参数时必须正常加载
	okCases := []struct{ op, param, val string }{
		{"detectSQLi", "min_fingerprint_len", "8"},
		{"detectSQLi", "exclude_fingerprints", `["quote probing"]`},
		{"detectPathTraversal", "min_depth", "2"},
		{"regex", "pattern", `"abc"`},
		{"pm", "patterns", `["abc"]`},
	}
	for _, c := range okCases {
		body := fmt.Sprintf(`
version: 1
meta:
  name: t
  author: t
  category: t
rules:
  - id: T-1
    severity: high
    category: t
    message: t
    transforms: [lowercase]
    operator:
      name: %s
      params:
        %s: %s
    test:
      positive: ["abc"]
      negative: ["zzz"]
`, c.op, c.param, c.val)
		loaded, skipped, err := LoadRules([]byte(body), "t.yaml")
		if err != nil {
			t.Fatalf("%s: 加载失败: %v", c.op, err)
		}
		if len(loaded) != 1 {
			t.Errorf("%s 用支持的参数 %s 时应当加载成功，实际跳过：%v", c.op, c.param, skipped)
		}
	}
}

// 写错的指纹名必须被拒绝（而不是静默失效）。
func TestUnknownSQLiFingerprintRejected(t *testing.T) {
	const body = `
version: 1
meta:
  name: t
  author: t
  category: t
rules:
  - id: T-1
    severity: high
    category: sqli
    message: t
    transforms: [lowercase]
    operator:
      name: detectSQLi
      params:
        fingerprints: ["quote probingg"]
    test:
      positive: ["1'"]
      negative: ["O'Brien"]
`
	loaded, skipped, err := LoadRules([]byte(body), "t.yaml")
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(loaded) != 0 {
		t.Error("未知指纹名应导致规则被跳过")
	}
	if !strings.Contains(strings.Join(skipped, "\n"), "quote probingg") {
		t.Errorf("跳过原因里应指出写错的指纹名，实际：%v", skipped)
	}
}
