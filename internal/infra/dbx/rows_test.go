package dbx

import (
	"strings"
	"testing"
)

// 这组测试把审计报告里逐条构造过的例子固化下来。
// 它们都是纯函数，不需要连数据库，改了判定逻辑立刻能发现退化。

func TestIsReadOnlySQLRejectsWriteBypasses(t *testing.T) {
	// 这些都是"看着像查询、语义上会写"的语句。
	// 审计实测过：早期版本把 with / explain 一律当只读，
	// 于是 PG 的 `WITH d AS (DELETE ... RETURNING *) SELECT * FROM d` 真的会删数据，
	// 而界面因为返回 0 列只显示"这条语句没有返回结果集"，用户看不出发生过什么。
	bad := []string{
		"WITH ids AS (SELECT id FROM t) DELETE FROM t WHERE id IN (SELECT id FROM ids)",
		"WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d",
		"WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x",
		"WITH ids AS (SELECT id FROM t) UPDATE t SET a=1 WHERE id IN (SELECT id FROM ids)",
		"with recursive x as (select 1) delete from t",
		"EXPLAIN ANALYZE DELETE FROM users",
		"explain analyze delete from users",
		"EXPLAIN (ANALYZE) DELETE FROM users",
		"SELECT 'x' INTO OUTFILE '/tmp/pwn'",
		"select * into dumpfile '/tmp/x' from t",
		"SELECT 1; DROP TABLE users",
		"SELECT 1;\nDROP TABLE users",
		// 裸写语句本来就不该通过
		"DELETE FROM t",
		"DROP TABLE t",
		"UPDATE t SET a=1",
		"INSERT INTO t VALUES (1)",
		"TRUNCATE t",
		"/* hi */ DROP TABLE users",
		"-- hi\nDROP TABLE users",
		"/*!50000 DROP TABLE users */",
		"",
		"-- 只有注释",
		"/* 未闭合注释",
	}
	for _, sql := range bad {
		if IsReadOnlySQL(sql) {
			t.Errorf("该被判成写操作，却放行了：%q", sql)
		}
	}
}

func TestIsReadOnlySQLAcceptsQueries(t *testing.T) {
	good := []string{
		"SELECT 1",
		"select * from t where a = 1",
		"SeLeCt 1",
		"  \n\tSELECT 1",
		"SHOW TABLES",
		"DESCRIBE t",
		"DESC t",
		"EXPLAIN SELECT 1",
		"EXPLAIN ANALYZE SELECT 1", // ANALYZE 只有配合写语句才危险
		"TABLE t",
		"VALUES (1)",
		"-- 注释\nSELECT 1",
		"/* c */ SELECT 1",
		"(SELECT 1)",
		"/* c */ (SELECT 1)",
		"WITH x AS (SELECT 1) SELECT * FROM x",
	}
	for _, sql := range good {
		if !IsReadOnlySQL(sql) {
			t.Errorf("这是纯查询，却被只读模式挡了：%q", sql)
		}
	}
}

func TestCheckIdent(t *testing.T) {
	// 合法
	for _, ok := range []string{"t_user", "user2", "a", "T_USER"} {
		if err := checkIdent(ok); err != nil {
			t.Errorf("%q 应该合法：%v", ok, err)
		}
	}
	// 会把 DDL / 标识符拼坏的写法一律拒绝
	for _, bad := range []string{"", "   ", "my table", "t;drop", "t'x", `t"x`, "t`x", "a\\b", "a\nb"} {
		if err := checkIdent(bad); err == nil {
			t.Errorf("%q 应该被拒绝", bad)
		}
	}
}

func TestCheckType(t *testing.T) {
	good := []string{"int", "varchar(64)", "numeric(10,2)", "timestamp", "text", "bigint unsigned"}
	for _, ok := range good {
		if err := checkType(ok); err != nil {
			t.Errorf("%q 应该合法：%v", ok, err)
		}
	}
	// 审计实测过：早期白名单放行逗号，于是 "int, evil text" 能塞进额外列定义
	bad := []string{
		"", "int, evil text", "int, PRIMARY KEY (evil)", "int REFERENCES t(id)",
		"int;DROP TABLE t", "int/*x*/", "int -- x", "1int", "int(1,2,3)",
	}
	for _, b := range bad {
		if err := checkType(b); err == nil {
			t.Errorf("%q 应该被拒绝", b)
		}
	}
}

func TestEscapeString(t *testing.T) {
	// MySQL/MariaDB 默认 sql_mode 下反斜杠是字符串里的转义符，
	// 只翻倍单引号的话，默认值填 C:\temp\ 就会把语句拼坏（字符串未闭合报 1064）
	cases := map[string]string{
		`abc`:      `abc`,
		`C:\temp\`: `C:\\temp\\`,
		`a'b`:      `a''b`,
		`a\'b`:     `a\\''b`,
	}
	for in, want := range cases {
		if got := escapeString(in); got != want {
			t.Errorf("escapeString(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestWhereClauseRejectsCommentMarkers(t *testing.T) {
	if _, err := whereClause(""); err != nil {
		t.Errorf("空条件应该合法：%v", err)
	}
	if _, err := whereClause("id > 10 AND name LIKE '%a%'"); err != nil {
		t.Errorf("普通条件应该合法：%v", err)
	}
	// # 是 MySQL 的行注释：漏了它就能把后面的 ORDER BY / LIMIT 一起注释掉，
	// 一次把全表拉回来
	for _, bad := range []string{"1=1 #", "1=1 --", "1=1;", "1=1 /*"} {
		if _, err := whereClause(bad); err == nil {
			t.Errorf("%q 应该被拒绝", bad)
		}
	}
}

func TestQuoteAndQualified(t *testing.T) {
	my := &Conn{kind: KindMySQL}
	pg := &Conn{kind: KindPostgres}

	for _, c := range []struct {
		conn *Conn
		in   string
		want string
	}{
		{my, "t", "`t`"},
		{my, "t`x", "`t``x`"}, // 标识符里的引号字符翻倍
		{pg, "t", `"t"`},
		{pg, `t"x`, `"t""x"`},
	} {
		if got := c.conn.quote(c.in); got != c.want {
			t.Errorf("quote(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}

	// MySQL 必须带库名：连接没配默认库时只写表名会报
	// Error 1046 (3D000): No database selected
	if got := my.qualified(TableRef{Database: "db", Table: "t"}); got != "`db`.`t`" {
		t.Errorf("MySQL qualified = %q", got)
	}
	if got := my.qualified(TableRef{Table: "t"}); got != "`t`" {
		t.Errorf("MySQL 无库名 qualified = %q", got)
	}
	if got := pg.qualified(TableRef{Schema: "s", Table: "t"}); got != `"s"."t"` {
		t.Errorf("PG qualified = %q", got)
	}
	// PG 的 public 也要写出来，避免依赖 search_path
	if got := pg.qualified(TableRef{Table: "t"}); got != `"public"."t"` {
		t.Errorf("PG 缺省 schema qualified = %q", got)
	}
}

func TestPlaceholder(t *testing.T) {
	my := &Conn{kind: KindMySQL}
	pg := &Conn{kind: KindPostgres}
	// pgx 只认 $1/$2；给它 ? 会直接报 syntax error at or near "AND"
	if got := my.placeholder(1); got != "?" {
		t.Errorf("MySQL placeholder = %q", got)
	}
	if got := pg.placeholder(1); got != "$1" {
		t.Errorf("PG placeholder(1) = %q", got)
	}
	if got := pg.placeholder(2); got != "$2" {
		t.Errorf("PG placeholder(2) = %q", got)
	}
}

func TestFormatValue(t *testing.T) {
	if got := formatValue(nil); got != "NULL" {
		t.Errorf("nil 应显示成 NULL，得到 %q", got)
	}
	if got := formatValue([]byte("abc")); got != "abc" {
		t.Errorf("文本字节应原样显示，得到 %q", got)
	}
	// 二进制不往界面塞：早期版本会把它显示成占位文本，
	// 而那个文本一旦被编辑回写就把真正的二进制内容覆盖掉了
	bin := []byte{1, 2, 0, 4}
	if got := formatValue(bin); got != "<4 字节二进制>" {
		t.Errorf("二进制应显示占位文本，得到 %q", got)
	}
	if got := formatValue(42); got != "42" {
		t.Errorf("数字应显示成 42，得到 %q", got)
	}
}

func TestIsNumericOrKeyword(t *testing.T) {
	for _, ok := range []string{"0", "1", "-1", "1.5", "NULL", "CURRENT_TIMESTAMP", "now()", "TRUE"} {
		if !isNumericOrKeyword(ok) {
			t.Errorf("%q 应被当成字面量/关键字", ok)
		}
	}
	// 这些必须当字符串处理并转义，不能原样拼进 DDL
	for _, no := range []string{"abc", "1; drop", "C:\\temp\\", "a'b"} {
		if isNumericOrKeyword(no) {
			t.Errorf("%q 不该被当成数字或关键字", no)
		}
	}
}

func TestIsReadOnlySQLExplainModifiers(t *testing.T) {
	// EXPLAIN 后面常跟修饰语。早期实现只 TrimPrefix 一次 "analyze"，
	// 于是 `EXPLAIN FORMAT=JSON SELECT 1` 这类纯查询被只读模式误挡；
	// 而 `EXPLAIN DELETE FROM t`（不带 ANALYZE，只出计划）也被误挡，
	// 与代码注释里写的行为矛盾。
	queries := []string{
		"EXPLAIN SELECT 1",
		"EXPLAIN FORMAT=JSON SELECT 1",
		"EXPLAIN FORMAT=TREE SELECT 1",
		"EXPLAIN EXTENDED SELECT 1",
		"EXPLAIN PARTITIONS SELECT 1",
		"EXPLAIN VERBOSE SELECT 1",
		"EXPLAIN ANALYZE SELECT 1",
		"EXPLAIN ANALYSE SELECT 1",
		"EXPLAIN (ANALYZE) SELECT 1",
		"EXPLAIN (ANALYZE, BUFFERS) SELECT 1",
		"explain format=json analyze select 1",
		// 不带 ANALYZE 的 EXPLAIN 只出计划，写语句也算只读
		"EXPLAIN DELETE FROM t",
		"EXPLAIN UPDATE t SET a=1",
		"EXPLAIN TABLE t",
	}
	for _, sql := range queries {
		if !IsReadOnlySQL(sql) {
			t.Errorf("这是只出计划的查询，却被只读模式挡了：%q", sql)
		}
	}

	// 带 ANALYZE 的写语句必须挡住 —— 数据库会真的执行它
	dangerous := []string{
		"EXPLAIN ANALYZE DELETE FROM t",
		"EXPLAIN ANALYSE DELETE FROM t",
		"EXPLAIN (ANALYZE) DELETE FROM t",
		"EXPLAIN (ANALYZE, BUFFERS) DELETE FROM t",
		"EXPLAIN FORMAT=JSON ANALYZE DELETE FROM t",
		"EXPLAIN(ANALYZE)DELETE FROM t",
		"EXPLAIN ANALYZE UPDATE t SET a=1",
		"EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
		"EXPLAIN ANALYZE WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
		"EXPLAIN ANALYZE SELECT 1; DROP TABLE t",
		"EXPLAIN ANALYZE SELECT 1 INTO OUTFILE '/tmp/x'",
	}
	for _, sql := range dangerous {
		if IsReadOnlySQL(sql) {
			t.Errorf("带 ANALYZE 的写语句被放行了：%q", sql)
		}
	}

	// 只有 EXPLAIN / 修饰语、没有语句：非法，按不安全处理
	for _, sql := range []string{"EXPLAIN", "EXPLAIN ANALYZE", "EXPLAIN (ANALYZE)", "EXPLAIN ()", "EXPLAIN ("} {
		if IsReadOnlySQL(sql) {
			t.Errorf("缺少被解释的语句，不该判为只读：%q", sql)
		}
	}
}

func TestIsReadOnlySQLSeparatorAndCommentBypasses(t *testing.T) {
	// 这两类都是"看着像查询、数据库会真的写"：
	//   1. INTO OUTFILE / DUMPFILE 会在目标机落文件；
	//   2. MySQL 的 /*! ... */ 是**可执行注释**，内容会真的执行。
	// 早期实现用字面子串匹配 + 把 /*...*/ 一律当注释丢掉，于是下面这些全被判成只读。
	bad := []string{
		// INTO OUTFILE 的分隔符与注释变体
		"SELECT 'x' INTO OUTFILE '/tmp/pwn'",
		"SELECT 'x' INTO  OUTFILE '/tmp/pwn'",
		"SELECT 'x' INTO\tOUTFILE '/tmp/pwn'",
		"SELECT 'x' INTO\nOUTFILE '/tmp/pwn'",
		"SELECT 'x' INTO/**/OUTFILE '/tmp/pwn'",
		"SELECT 'x' INTO /* c */ OUTFILE '/tmp/pwn'",
		"select * into dumpfile '/tmp/x' from t",
		"select * into/**/ dumpfile '/tmp/x' from t",
		"select * into  DUMPFILE '/tmp/x' from t",
		// MySQL 可执行注释藏 ANALYZE（内容会真的执行）
		"EXPLAIN /*!50000 ANALYZE */ DELETE FROM t",
		"EXPLAIN /*! ANALYZE */ DELETE FROM t",
		"EXPLAIN /*!50000 ANALYSE */ DELETE FROM t",
		// 可执行注释里藏分号
		"SELECT 1 /*! ; DROP TABLE t */",
	}
	for _, sql := range bad {
		if IsReadOnlySQL(sql) {
			t.Errorf("会真的写/执行的语句被放行了：%q", sql)
		}
	}

	// 尾分号是最普通的写法，不能因此被当成多语句挡掉
	// （Conn.Query 里本来就会 TrimSuffix 掉它，这道闸门要对齐）
	good := []string{
		"SELECT 1;",
		"select * from t where a = 1;",
		"SELECT 1;   ",
		"/* 只是注释 */ SELECT 1;",
		"SELECT 1 /* 普通注释 */",
		"SELECT 1 -- 行注释",
		"SELECT a--b FROM t", // 这不是注释（-- 后没有空白）
	}
	for _, sql := range good {
		if !IsReadOnlySQL(sql) {
			t.Errorf("纯查询被误挡：%q", sql)
		}
	}
}

func TestIsReadOnlySQLExplainEdgeCases(t *testing.T) {
	// 修饰语要用 token 全等比较，不能用前缀匹配 + 找空格：
	// 前缀匹配会把 VERBOSELY 当成 VERBOSE 剥掉，剩下的碎片当成语句，
	// 判据就变成假的（"不认识的东西假定它不执行"）。
	// 认不出被解释的语句时应当返回 false（只读模式下宁可不放行）。
	unknown := []string{
		"EXPLAIN VERBOSELY DELETE FROM t",
		"EXPLAIN FORMATTED SELECT 1",
		"EXPLAIN EXTENDEDLY DELETE FROM t",
		"EXPLAIN PARTITIONSX DELETE FROM t",
		"EXPLAIN GARBAGE DELETE FROM t",
	}
	for _, sql := range unknown {
		if IsReadOnlySQL(sql) {
			t.Errorf("认不出被解释的语句，不该放行：%q", sql)
		}
	}

	// 分隔符不只空格：TAB / 换行都算
	ok := []string{
		"EXPLAIN\tFORMAT=JSON\tSELECT 1",
		"EXPLAIN\nANALYZE\nSELECT 1",
		"EXPLAIN\tSELECT 1",
		"EXPLAIN -- 说明\nSELECT 1",
	}
	for _, sql := range ok {
		if !IsReadOnlySQL(sql) {
			t.Errorf("纯查询不该被挡：%q", sql)
		}
	}

	// 注释夹在 EXPLAIN 与修饰语之间：早期实现会一个修饰语都认不出，
	// 于是把 ANALYZE DELETE 当成"不执行"，直接放行
	danger := []string{
		"EXPLAIN -- c\nANALYZE DELETE FROM t",
		"EXPLAIN /* c */ ANALYZE DELETE FROM t",
		"EXPLAIN -- c\nANALYZE\tDELETE FROM t",
		"EXPLAIN /* a */ FORMAT=JSON /* b */ ANALYZE DELETE FROM t",
	}
	for _, sql := range danger {
		if IsReadOnlySQL(sql) {
			t.Errorf("带 ANALYZE 的写语句被放行了：%q", sql)
		}
	}

	// 带 ANALYZE 的纯查询仍然要放行
	if !IsReadOnlySQL("EXPLAIN ANALYZE\tSELECT 1") {
		t.Error("EXPLAIN ANALYZE SELECT 1 是纯查询，不该被挡")
	}

	// 畸形输入不能死循环或越界
	long := "EXPLAIN " + strings.Repeat("ANALYZE ", 5000) + "SELECT 1"
	_ = IsReadOnlySQL(long)
	parens := "EXPLAIN " + strings.Repeat("(", 1000)
	_ = IsReadOnlySQL(parens)
}
