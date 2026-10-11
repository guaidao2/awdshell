package dbx

import "testing"

// flattenSQL 必须跳过字符串字面量里的注释标记。
//
// 审计实测（audit41 高1）：以前 `SELECT '#x' INTO OUTFILE '/tmp/x'` 被判成
// **只读** —— 引号里的 `#` 被当成行注释，把后半条语句连同真正的写操作整段
// 吞掉，压平后只剩 `SELECT '`，于是 IsReadOnlySQL 返回 true，只读模式下把
// `INTO OUTFILE` 放行到目标机落文件。同文件的 hasStatementSeparator 与
// quoteAwareWords 都在跳引号内容，只有 flattenSQL 漏了这件事（三处词法不一致）。
func TestIsReadOnlySQLRejectsCommentMarkerInsideLiteral(t *testing.T) {
	writes := []string{
		"SELECT '#x' INTO OUTFILE '/tmp/x'",
		"SELECT '-- ' INTO OUTFILE '/tmp/x'",
		"SELECT '#x' INTO DUMPFILE '/tmp/x'",
		"SELECT '#', 1 INTO OUTFILE '/tmp/x'",
		"SELECT '#' ; DROP TABLE users",
		`SELECT "#" INTO OUTFILE '/tmp/x'`,
		"SELECT /* 普通注释 */ 1 INTO OUTFILE '/tmp/x'",
	}
	for _, sql := range writes {
		if IsReadOnlySQL(sql) {
			t.Errorf("应判为写（引号里的注释标记不是注释），实际判成只读: %q", sql)
		}
	}

	// 反向：字面量里的 into outfile、连写引号、反引号标识符都不能被误判
	reads := []string{
		"SELECT 'into outfile' AS note",
		"SELECT '#x' AS h",
		"SELECT 'a''b' AS s",
		"SELECT 'it''s', 1 FROM t",
		"SELECT `a#b` FROM t",
		"SELECT 'x' -- 行注释\nFROM t",
	}
	for _, sql := range reads {
		if !IsReadOnlySQL(sql) {
			t.Errorf("正常查询被误判成写: %q", sql)
		}
	}
}

// 引号内的内容要原样保留（不能被当注释吞掉），这是上面那组用例的机制层断言。
func TestFlattenSQLKeepsQuotedContent(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT '#x' INTO OUTFILE '/tmp/x'", "SELECT '#x' INTO OUTFILE '/tmp/x'"},
		{"SELECT '#', 1 INTO OUTFILE '/tmp/x'", "SELECT '#', 1 INTO OUTFILE '/tmp/x'"},
		{`SELECT "a--b" FROM t`, `SELECT "a--b" FROM t`},
		{"SELECT `a#b` FROM t", "SELECT `a#b` FROM t"},
		// 引号外的注释照旧被剥掉
		{"SELECT 1 # 注释\n", "SELECT 1"},
		{"SELECT 1 -- 注释\n", "SELECT 1"},
		{"SELECT /* 注释 */ 1", "SELECT 1"},
		// 可执行注释保留内容
		{"SELECT /*!50000 1 */", "SELECT 1"},
		// 连写引号：两个引号代表一个引号，后面的内容仍在字面量里
		{"SELECT 'it''s #1' FROM t", "SELECT 'it''s #1' FROM t"},
	}
	for _, c := range cases {
		if got := flattenSQL(c.in); got != c.want {
			t.Errorf("flattenSQL(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}
