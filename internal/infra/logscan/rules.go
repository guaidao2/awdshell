// Package logscan 提供日志里的攻击载荷/入侵痕迹检测。
//
// 设计取向：宁可漏一点，也不要一堆误报。每条规则都要求足够具体的特征组合，
// 命中结果带上证据行与尽力提取的来源 IP，便于人工快速确认或排除。
package logscan

import "regexp"

// Severity 取值
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
)

// init 给内置规则套上默认变换链并做预处理。
func init() {
	for i := range DefaultRules {
		if DefaultRules[i].Chain == nil {
			DefaultRules[i].Chain = DefaultChain
			DefaultRules[i].TransformNames = DefaultTransformNames
		}
		DefaultRules[i].compile()
	}
}

// DefaultRules 内置规则集（Web 攻击、认证异常、后门痕迹）。
var DefaultRules = []Rule{
	{
		ID: "WEB-SQLI", Name: "SQL 注入载荷", Severity: SevHigh, Category: "sqli",
		Pattern: regexp.MustCompile(`(?i)(union\b[\s/*+%\w]{0,14}select\b` +
			`|select[\s\S]{1,60}?from[\s/*+%\w]{1,20}(?:users|admin|passwd|accounts|information_schema|mysql\.user|wp_users|t_user)` +
			`|(or|and)[\s/*+%\w]{0,6}1[\s/*+%]*=[\s/*+%]*1` +
			`|sleep[\s/*+%]*\(|benchmark[\s/*+%]*\(|information_schema` +
			`|load_file[\s/*+%]*\(|into[\s/*+%\w]{1,6}outfile|extractvalue[\s/*+%]*\(|updatexml[\s/*+%]*\(` +
			`)`)},
	{
		ID: "WEB-XSS", Name: "XSS 载荷", Severity: SevMedium, Category: "xss",
		Pattern: regexp.MustCompile(`(?i)(<script[\s>]|javascript:[\w(]|onerror[\s]*=|onload[\s]*=|alert[\s]*\(|document\.cookie|%3cscript)`)},
	{
		ID: "WEB-RCE", Name: "命令注入 / 远程执行载荷", Severity: SevCritical, Category: "rce",
		Pattern: regexp.MustCompile("(?i)(\\$\\(|`)[\\s]*(id|whoami|cat|ls|wget|curl|nc|bash|sh|python)\\b" +
			"|(;|\\||&&|%3b|%7c)[\\s]*(cat|ls|id|whoami|wget|curl|nc|bash|sh|python)[\\s/%]" +
			"|/(bin|usr/bin)/(sh|bash|nc|wget|curl)\\b" +
			"|(system|passthru|shell_exec|popen|exec)[\\s]*\\(")},
	{
		ID: "WEB-TRAVERSAL", Name: "路径穿越", Severity: SevHigh, Category: "traversal",
		Pattern: regexp.MustCompile(`(\.\./){2,}|(\.\.%2f){2,}|(%2e%2e%2f){1,}|%252e%252e|/etc/(passwd|shadow|hosts)\b|(win\.ini|boot\.ini)\b`)},
	{
		ID: "WEB-WEBSHELL", Name: "WebShell 访问或上传", Severity: SevCritical, Category: "webshell",
		Pattern: regexp.MustCompile(`(?i)(shell|cmd|backdoor|b374k|c99|r57|chopper|antsword|godzilla|behinder)[\w.-]*\.(php|jsp|jspx|asp|aspx)|\?[\w]*(cmd|exec|command|shell)=|(upload|file)[\w]*\.(php|jsp|asp)[^\s]*\?[^\s]*(upload|name)=`)},
	{
		ID: "WEB-SCANNER", Name: "扫描器 / 自动化工具特征", Severity: SevMedium, Category: "scanner",
		Pattern: regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|dirsearch|wpscan|acunetix|nessus|openvas|xsstrike|w3af|netsparker|zgrab|nuclei)`)},
	{
		ID: "WEB-SENSITIVE", Name: "敏感文件探测", Severity: SevMedium, Category: "recon",
		Pattern: regexp.MustCompile(`(?i)/(\.git/|\.svn/|\.env\b|\.DS_Store|web\.config|phpinfo\.php|\.ssh/id_rsa|actuator/(env|health|heapdump)|(backup|dump|www)\.(zip|tar\.gz|sql|rar)\b|/server-status|/manager/html)`)},
	{
		ID: "LOG-JNDI", Name: "JNDI 注入（Log4Shell 类）", Severity: SevCritical, Category: "rce",
		Pattern: regexp.MustCompile(`(?i)\$\{jndi:(ldap|rmi|dns|iiop|http)`)},
	{
		ID: "LOG-DESERIAL", Name: "反序列化载荷特征", Severity: SevHigh, Category: "rce",
		Pattern: regexp.MustCompile(`(rO0AB|H4sIA|aced0005|O:\d+:"[\w\\]+":\d+:\{)`)},
	{
		ID: "LOG-ENCODED", Name: "超长编码串（可能是编码后的载荷）", Severity: SevLow, Category: "obfuscation",
		Pattern: regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}|(%[0-9a-fA-F]{2}){20,}`)},
	{
		ID: "AUTH-BRUTEFORCE", Name: "认证失败 / 疑似暴力破解", Severity: SevHigh, Category: "auth",
		Pattern: regexp.MustCompile(`(?i)(failed password|authentication failure|invalid user|failed login|too many authentication failures|pam_unix\(.*\): authentication failure|Failed publickey)`)},

	{
		ID: "AUTH-PRIV", Name: "提权 / 权限变更", Severity: SevMedium, Category: "privilege",
		Pattern: regexp.MustCompile(`(?i)(sudo:[\s]+\S+[\s]*:[\s]*.*COMMAND=|su: pam_unix\(su:session\): session opened for user root|new user:|useradd|usermod -aG (sudo|wheel|docker))`)},
	{
		ID: "BACKDOOR-PERSIST", Name: "持久化痕迹（计划任务 / 启动项 / 密钥写入）", Severity: SevHigh, Category: "persistence",
		Pattern: regexp.MustCompile(`(?i)(crontab -l|crontab -e|/etc/cron\.|/etc/rc\.local|systemctl (enable|daemon-reload)|>>[\s]*~?/?\.ssh/authorized_keys|authorized_keys)`)},
	{
		ID: "RCE-REVSHELL", Name: "反弹 Shell / 数据外带", Severity: SevCritical, Category: "rce",
		Pattern: regexp.MustCompile(`(?i)(/dev/tcp/|nc\b[^\n]{0,20}-e\b|bash\b[^\n]{0,10}-i\b[^\n]{0,40}>&|python[^\n]{0,20}socket\.socket|mkfifo[^\n]{0,40}(nc|bash)|curl[^\n]{0,60}(-d|--data)[^\n]{0,40}@/etc/(passwd|shadow)|base64[^\n]{0,10}-d[^\n]{0,10}\|[^\n]{0,10}(sh|bash))`)},
	{
		ID: "SYS-MINING", Name: "挖矿 / 可疑外联特征", Severity: SevHigh, Category: "malware",
		Pattern: regexp.MustCompile(`(?i)(stratum\+tcp|minerd|xmrig|kdevtmpfsi|kinsing|/tmp/[a-z0-9]{8,}\b.*(curl|wget)|curl[^\n]*\|[\s]*(sh|bash)|wget[^\n]*-O[\s]*-[\s]*\|[\s]*(sh|bash))`)},
}
