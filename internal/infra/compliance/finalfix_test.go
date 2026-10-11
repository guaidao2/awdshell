package compliance

import (
	"strings"
	"testing"
)

// 这一组守终审报告里的 L1：可读性标记的识别是"整行全等"，不是"整行按子串丢弃"。
//
// 症状（终审实测）：`%adm ALL=(ALL) NOPASSWD: ALL __AWD_READ_OK__` 这种"发现行里
// 恰好带着标记串"的输入，会被 Contains 判成标记行、整行丢掉 —— 正文变空，
// 而 readable=true 又让 needs_root 的空输出兜底不生效（见 Evaluate），
// 一条真问题被判 **pass**；带 __AWD_READ_DENIED__ 时则被判成"读取被拒"的 error，
// 把配置问题说成权限问题。
//
// 两条断言方向都要有：**含**标记的行不许被吃掉，**就是**标记的行仍然要认出来。

// TestReadMarkersRequiresWholeLine 直接钉 readMarkers 的三态。
func TestReadMarkersRequiresWholeLine(t *testing.T) {
	// ① 只有真正的标记行才被摘掉（前后空白算同一行 —— echo 之外可能被包一层空白）
	body, ok, denied := readMarkers(markerReadOK + "\n")
	if !ok || denied || strings.TrimSpace(body) != "" {
		t.Errorf("整行标记没被认出来：body=%q ok=%v denied=%v", body, ok, denied)
	}
	body, ok, denied = readMarkers("  " + markerReadDenied + "  \n")
	if ok || !denied || strings.TrimSpace(body) != "" {
		t.Errorf("带空白的整行标记没被认出来：body=%q ok=%v denied=%v", body, ok, denied)
	}

	// ② 行里"含"标记串不算标记：改回 Contains 时这三条必红
	const finding = "%adm ALL=(ALL) NOPASSWD: ALL "
	body, ok, denied = readMarkers(finding + markerReadOK + "\n")
	if ok || denied {
		t.Errorf("发现行里恰好含 %s 时不该被当成标记（整行被吃掉 → 真问题变 pass）", markerReadOK)
	}
	if !strings.Contains(body, "NOPASSWD") {
		t.Errorf("发现行的正文被丢掉了：%q", body)
	}

	body, ok, denied = readMarkers(finding + markerReadDenied + "\n")
	if ok || denied {
		t.Errorf("发现行里恰好含 %s 时不该被当成标记（会被说成权限问题）", markerReadDenied)
	}
	if !strings.Contains(body, "NOPASSWD") {
		t.Errorf("发现行的正文被丢掉了：%q", body)
	}

	// ③ 没有标记时正文必须原样返回（不能因为遍历行就把内容改了）
	const plain = "root ALL=(ALL:ALL) ALL\nDefaults env_reset\n"
	body, ok, denied = readMarkers(plain)
	if ok || denied || body != plain {
		t.Errorf("没有标记时正文必须原样返回：body=%q ok=%v denied=%v", body, ok, denied)
	}
}

// TestEvaluateFindingLineCarryingMarkerIsNotSwallowed 守 L1 的判定后果：
// 「发现行 + 标记串」在 Evaluate 里必须按发现判，不能被吞成 pass / 权限 error。
func TestEvaluateFindingLineCarryingMarkerIsNotSwallowed(t *testing.T) {
	chk := Check{
		ID: "CHK-L1", NeedsRoot: true,
		Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `(?i)nopasswd`},
	}

	// ① 真问题：改回 Contains 时会判 pass（正文空 + readable=true 让兜底不生效）
	r := Evaluate(chk, "%adm ALL=(ALL) NOPASSWD: ALL "+markerReadOK+"\n", nil)
	if r.Status != StatusFail {
		t.Errorf("发现行不能被整行吃掉：应当判 fail，实际 %s（%s）", r.Status, r.Detail)
	}
	if !strings.Contains(r.Output, "NOPASSWD") {
		t.Errorf("给用户看的输出里必须留着那条发现：%q", r.Output)
	}

	// ② 同一行带 DENIED：按内容判（fail），不能说成"读取被拒"的权限问题
	r = Evaluate(chk, "%adm ALL=(ALL) NOPASSWD: ALL "+markerReadDenied+"\n", nil)
	if r.Status != StatusFail {
		t.Errorf("发现行不能被当成权限问题：应当判 fail，实际 %s（%s）", r.Status, r.Detail)
	}
	if strings.Contains(r.Detail, "读取被拒") {
		t.Errorf("配置问题不该被说成权限问题：%s", r.Detail)
	}

	// ③ 反向保险：真标记行仍然要生效（否则这条修复会把 L1 变成"标记全不认"）
	plain := Check{ID: "CHK-L1b", NeedsRoot: true,
		Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `\S`}}
	if r := Evaluate(plain, markerReadOK+"\n", nil); r.Status != StatusPass {
		t.Errorf("真的 __AWD_READ_OK__ 行必须仍被认成「读到了」（空结果可信）：%s（%s）", r.Status, r.Detail)
	}
	if r := Evaluate(plain, markerReadDenied+"\n", nil); r.Status != StatusError {
		t.Errorf("真的 __AWD_READ_DENIED__ 行必须仍判 error：%s（%s）", r.Status, r.Detail)
	} else if !strings.Contains(r.Detail, "root") {
		t.Errorf("读取被拒的说明里要写清需要 root：%s", r.Detail)
	}
	// 标记本身不许漏进给用户看的输出
	if r := Evaluate(plain, markerReadOK+"\n", nil); strings.Contains(r.Output, markerReadOK) {
		t.Errorf("可读性标记是内部管线，不该出现在 Output 里：%q", r.Output)
	}
}
