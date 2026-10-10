package logscan

import (
	"regexp"
	"strings"
)

// 日志类型：决定用哪套规则。
const (
	KindWeb    = "web"    // Web 访问 / 错误日志
	KindSystem = "system" // 系统与认证日志
	KindAll    = "all"    // 不分类型，全量规则
	KindAuto   = "auto"   // 交给 GuessLogKind 推断
)

// 只对 Web 日志有意义的攻击类别。
// 这些特征在 sshd / auth 这类日志里根本不会出现，拿去跑只会制造噪音。
var webOnlyCategories = map[string]bool{
	"sqli": true, "xss": true, "rce": true, "traversal": true, "lfi": true,
	"webshell": true, "ssti": true, "scanner": true, "recon": true,
	"protocol": true, "upload": true, "rfi": true, "xxe": true, "ssrf": true,
	"crlf": true, "openredirect": true,
}

// 只对系统 / 认证日志有意义的类别。
var systemOnlyCategories = map[string]bool{
	"auth": true, "privilege": true, "persistence": true, "system": true,
}

// RulesForKind 按日志类型筛选规则。
//
// 没归类的类别（malware / obfuscation / 空）视为通用，两边都跑。
func RulesForKind(rules []Rule, kind string) []Rule {
	if kind == "" || kind == KindAll || kind == KindAuto {
		return rules
	}
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if ruleAppliesTo(strings.ToLower(r.Category), kind) {
			out = append(out, r)
		}
	}
	return out
}

func ruleAppliesTo(category, kind string) bool {
	if webOnlyCategories[category] {
		return kind == KindWeb
	}
	if systemOnlyCategories[category] {
		return kind == KindSystem
	}
	return true
}

var (
	webPathRe    = regexp.MustCompile(`(?i)(nginx|apache|httpd|access|error_log|/www|/webroot|iis|tomcat|weblogic|haproxy|vhost)`)
	systemPathRe = regexp.MustCompile(`(?i)(auth|secure|syslog|messages|kern|cron|btmp|wtmp|daemon|dmesg|boot\.log|yum\.log|dpkg\.log)`)
	httpReqRe    = regexp.MustCompile(`"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+\S+\s+HTTP/[\d.]+"`)
	syslogRe     = regexp.MustCompile(`^\s*\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+[\w.+/-]+(\[\d+\])?:`)
)

// GuessLogKind 依据路径与内容推断日志类型；判不出来时返回 KindAll（跑全量）。
func GuessLogKind(path, text string) string {
	if webPathRe.MatchString(path) {
		return KindWeb
	}
	if systemPathRe.MatchString(path) {
		return KindSystem
	}

	lines := strings.Split(text, "\n")
	web, sys := 0, 0
	limit := len(lines)
	if limit > 300 {
		limit = 300
	}
	for i := 0; i < limit; i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch {
		case httpReqRe.MatchString(line):
			web++
		case syslogRe.MatchString(line):
			sys++
		}
	}
	switch {
	case web > 0 && web >= sys:
		return KindWeb
	case sys > 0:
		return KindSystem
	}
	return KindAll
}

// KindLabel 给界面用的中文名。
func KindLabel(kind string) string {
	switch kind {
	case KindWeb:
		return "Web 日志"
	case KindSystem:
		return "系统日志"
	case KindAll:
		return "全量规则"
	}
	return kind
}
