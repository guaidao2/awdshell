package logscan

import "testing"

// TestGuessLogKind 日志类型推断：路径优先，其次看内容。
func TestGuessLogKind(t *testing.T) {
	cases := []struct {
		path   string
		sample string
		want   string
	}{
		{"/var/log/nginx/access.log", "", KindWeb},
		{"/var/log/apache2/error.log", "", KindWeb},
		{"/var/log/httpd/access_log", "", KindWeb},
		{"/var/log/auth.log", "", KindSystem},
		{"/var/log/secure", "", KindSystem},
		{"/var/log/syslog", "", KindSystem},
		{"/var/log/messages", "", KindSystem},
		{"/tmp/myapp.log", `10.0.0.1 - - [10/Oct/2026:11:00:00 +0800] "GET / HTTP/1.1" 200 5`, KindWeb},
		{"/tmp/app.log", `Oct 10 11:00:00 host sshd[1234]: Accepted publickey for root`, KindSystem},
		{"/tmp/whatever.log", "some plain application text without any structure", KindAll},
	}
	for _, c := range cases {
		got := GuessLogKind(c.path, c.sample)
		if got != c.want {
			t.Errorf("GuessLogKind(%q) = %q, 期望 %q", c.path, got, c.want)
		}
	}
}

// TestRulesForKindSeparatesWebAndSystem 两套规则集不能串味：
// sshd 日志不该跑 SQL 注入规则，access.log 也不该跑提权规则。
func TestRulesForKindSeparatesWebAndSystem(t *testing.T) {
	all := AllRules()
	web := RulesForKind(all, KindWeb)
	sys := RulesForKind(all, KindSystem)

	if len(web) == 0 || len(sys) == 0 {
		t.Fatalf("规则集为空：web=%d system=%d", len(web), len(sys))
	}
	if len(web) >= len(all) || len(sys) >= len(all) {
		t.Errorf("分类没有起到过滤作用：all=%d web=%d system=%d", len(all), len(web), len(sys))
	}

	for _, r := range web {
		switch r.Category {
		case "auth", "privilege", "persistence", "system":
			t.Errorf("Web 规则集里混进了 %s 类规则：%s", r.Category, r.ID)
		}
	}
	for _, r := range sys {
		switch r.Category {
		case "sqli", "xss", "traversal", "lfi", "webshell", "ssti", "scanner":
			t.Errorf("系统规则集里混进了 %s 类规则：%s", r.Category, r.ID)
		}
	}

	// 全量必须覆盖两者
	if len(web) < 10 || len(sys) < 3 {
		t.Errorf("分类后规则太少，可能分类表写漏了：web=%d system=%d", len(web), len(sys))
	}
}

// TestSystemKindIgnoresWebPayload 拿带 Web 攻击特征的 sshd 日志行做验证：
// 用系统规则集时不该报出 Web 类问题，用全量规则集才会报。
func TestSystemKindIgnoresWebPayload(t *testing.T) {
	// 用户名里塞了注入，这在真实暴力破解里会出现；但用系统规则集时，
	// 我们只关心"认证失败"这件事本身，而不是用户名里的 SQL 片段。
	line := `Oct 10 11:00:00 host sshd[1234]: Failed password for invalid user 1' union select 1 from users from 10.0.0.5 port 22 ssh2`

	sysRes := Scan(line+"\n", "auth.log", RulesForKind(AllRules(), KindSystem))
	hasWeb := false
	for _, h := range sysRes.Hits {
		if webOnlyCategories[h.Category] {
			hasWeb = true
			t.Errorf("系统规则集仍报出了 Web 类问题：%s(%s)", h.RuleID, h.Category)
		}
	}

	allRes := Scan(line+"\n", "auth.log", AllRules())
	if len(allRes.Hits) == 0 {
		t.Error("全量规则集应当能报出这行里的认证失败")
	}
	if !hasWeb && len(allRes.Hits) == 0 {
		t.Error("两边都没命中，测试用例本身可能不对")
	}
}
