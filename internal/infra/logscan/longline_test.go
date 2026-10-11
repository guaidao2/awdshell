package logscan

import (
	"strings"
	"testing"
)

// 超长单行不能只扫头部。
//
// 审计实测：nginx 的 URI / Referer / User-Agent 都是攻击者可控字段（各自可到 8k），
// 把 sqlmap 这类特征推到第 8192 字节之后就能整体绕过检测 ——
// 填充 8000 字节时仍命中 WEB-SCANNER，填充 8300（载荷偏移 8375）就只剩无关的
// LOG-ENCODED，而且不产生任何异常提示。现在头尾各留一半，两边都参与匹配。
func TestLongLineTailStillMatches(t *testing.T) {
	rules := RulesForKind(AllRules(), KindWeb)
	mk := func(pad int) string {
		return `10.0.0.1 - - [11/Oct/2026:10:00:00 +0800] "GET /?pad=` +
			strings.Repeat("A", pad) + ` HTTP/1.1" 200 1 "-" "sqlmap/1.7"`
	}
	for _, pad := range []int{10, 8000, 8300, 20000} {
		res := Scan(mk(pad), "/var/log/nginx/access.log", rules)
		found := false
		for _, h := range res.Hits {
			if h.RuleID == "SCAN-2001" || strings.Contains(h.RuleName, "扫描器") {
				found = true
				break
			}
		}
		if !found {
			var ids []string
			for _, h := range res.Hits {
				ids = append(ids, h.RuleID)
			}
			t.Errorf("填充 %d 字节（载荷偏移 %d）后应当仍能命中扫描器规则，实际命中 [%s]",
				pad, pad+75, strings.Join(ids, ","))
		}
	}
}

// 头尾拼接不能把行长搞爆，也不能切出非法 UTF-8。
func TestLongLineTruncationKeepsBudgetAndUTF8(t *testing.T) {
	// 全中文的长行：切在多字节字符中间会产出非法 UTF-8
	line := strings.Repeat("测", 5000) // 15000 字节
	got := cutAtRuneBoundary(line, maxLineBytes/2) + "\n" + tailAtRuneBoundary(line, maxLineBytes/2)
	if len(got) > maxLineBytes+1 { // +1 是中间那个 \n
		t.Errorf("截断后长度 %d 超了预算 %d", len(got), maxLineBytes)
	}
	for _, part := range strings.Split(got, "\n") {
		if !isValidUTF8(part) {
			t.Error("截断后出现了非法 UTF-8（切在了多字节字符中间）")
		}
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}
