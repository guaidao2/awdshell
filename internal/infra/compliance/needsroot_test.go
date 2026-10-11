package compliance

import "testing"

// 标了 needs_root 的检查项读到空输出时不能判"符合"。
//
// 审计实测：非 root 登录读 /etc/sudoers（0440 root:root）会 EACCES，grep 什么都
// 不输出 —— 以前这被当成"没发现问题"，于是一条 critical（sudo 对危险命令免密）
// 在报告里显示成干净的"符合"，且没有任何提示。命令侧已去掉管道收尾并标了
// needs_root，这里是判定侧的双保险。
func TestNeedsRootEmptyOutputIsNotPass(t *testing.T) {
	needRoot := Check{
		ID: "T1", Title: "sudo 未对危险命令配置免密", Command: "grep -m 10 NOPASSWD /etc/sudoers",
		NeedsRoot: true,
		Expect:    Expect{Type: ExpectRegexNotMatch, Pattern: `\S`},
	}

	r := Evaluate(needRoot, "", nil)
	if r.Status == StatusPass {
		t.Errorf("需要 root 的检查读到空输出不该判 pass，实际 %s（%s）", r.Status, r.Detail)
	}

	// 命中时仍然是 fail（不能因为加了 needs_root 就把真问题放过）
	if r := Evaluate(needRoot, "root ALL=(ALL) NOPASSWD: /bin/bash", nil); r.Status != StatusFail {
		t.Errorf("命中时应当判 fail，实际 %s", r.Status)
	}

	// 不需要 root 的同类检查，空输出仍是"符合"（保持原语义：
	// "查有没有多余 UID 0 账号"这类空输出就是好事）
	plain := Check{
		ID: "T2", Title: "没有多余 UID 0 账号", Command: "awk -F: '$3==0 {print $1}' /etc/passwd",
		Expect: Expect{Type: ExpectRegexNotMatch, Pattern: `^root$`},
	}
	if r := Evaluate(plain, "", nil); r.Status != StatusPass {
		t.Errorf("不需要 root 的检查，空输出应当仍判 pass，实际 %s（%s）", r.Status, r.Detail)
	}
}

// 内置的三条 sudoers 检查项必须都标了 needs_root、且命令不带管道收尾。
//
// 管道会把 grep 的 EACCES 退出码（2）换成 head 的 0，于是"读不到"被当成
// "读到了、是空的" —— 这正是上面那条判定要防的场景。
func TestBuiltinSudoersChecksAreHardened(t *testing.T) {
	sets, problems, err := LoadSets()
	if err != nil {
		t.Fatalf("LoadSets 失败: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("内置检查项应当全部合法，problems=%v", problems)
	}
	want := map[string]bool{"CHK-AC-005": false, "CHK-PE-002": false, "CHK-PE-006": false}
	for _, c := range AllChecks(sets) {
		if _, ok := want[c.ID]; !ok {
			continue
		}
		want[c.ID] = true
		if !c.NeedsRoot {
			t.Errorf("%s 读 /etc/sudoers，必须标 needs_root（否则非 root 时会静默判合规）", c.ID)
		}
		if hasShellPipe(c.Command) {
			t.Errorf("%s 的命令用管道收尾，会把 EACCES 的退出码换成管道尾部的：%s", c.ID, c.Command)
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("内置检查项里找不到 %s", id)
		}
	}
}

// hasShellPipe 判断命令里有没有"真正的管道"。
//
// 必须跳过引号内的内容：这几条命令的正则里就有 `|`（`env_keep|env_reset|secure_path`、
// `(bash|/sh|...)`），那是 grep -E 的 alternation，不是管道；`||` 同理。
func hasShellPipe(cmd string) bool {
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '|':
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				i++ // `||`
				continue
			}
			return true
		}
	}
	return false
}
