package dbx

import (
	"strings"
	"testing"
)

// 这一组固化 audit41/audit44 里 dbx 那几条修复，断言都写成"改回错误版本会红"。

// TestWithClauseJudgesWordsQuoteAware 守 第 8 条：WITH 分支判写关键字要引号感知。
//
// 改回错误版本会红：以前是 strings.Contains(flat, "delete") 之类的**子串**判定，
// 于是字符串字面量里的 'delete' 也算命中 ——
// `WITH t AS (SELECT 'delete' AS a) SELECT * FROM t` 被判成写：
// 只读连接上被直接拒（明明只是查一个常量），非只读连接上走 ExecContext，
// **SELECT 的结果集被静默丢掉**，界面显示"无结果 / 影响 0 行"。
func TestWithClauseJudgesWordsQuoteAware(t *testing.T) {
	reads := []string{
		"WITH t AS (SELECT 'delete' AS a) SELECT * FROM t",
		"WITH t AS (SELECT 'update' AS a) SELECT * FROM t",
		`WITH t AS (SELECT "insert" AS a) SELECT * FROM t`,
		// 值是注释词也一样：它在引号里，不是关键字
		"WITH t AS (SELECT 'truncate merge' AS a) SELECT * FROM t",
	}
	for _, sql := range reads {
		if !IsReadOnlySQL(sql) {
			t.Errorf("引号里的写关键字不是关键字，应判只读: %q", sql)
		}
	}

	// 真的数据修改 CTE 一条都不能漏（判据收紧不能放过这些）
	writes := []string{
		"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
		"WITH u AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM u",
		"WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i",
		"WITH m AS (MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE) SELECT 1",
		"WITH x AS (SELECT 1) TRUNCATE t",
	}
	for _, sql := range writes {
		if IsReadOnlySQL(sql) {
			t.Errorf("数据修改 CTE 必须判成写: %q", sql)
		}
	}

	// 标识符形态（反引号）里的关键字同样不算：`delete` 是列名
	if !IsReadOnlySQL("WITH t AS (SELECT `delete` FROM x) SELECT * FROM t") {
		t.Error("反引号标识符里的 delete 是列名，不该判成写")
	}
}

// TestIsReadOnlySQLRejectsMoreSideEffectFunctions 守 第 9 条：副作用函数黑名单补全。
//
// 改回错误版本会红：审计实测下面这几条都被判成只读放行了 ——
// NEXT VALUE FOR 推进序列、set_config 直接把会话改成可写（最坏的一个）、
// lo_put 写大对象、pg_stat_reset 清统计、pg_switch_wal 切 WAL。
func TestIsReadOnlySQLRejectsMoreSideEffectFunctions(t *testing.T) {
	writes := []string{
		"SELECT NEXT VALUE FOR myseq",
		"SELECT next value for myseq",
		"SELECT next /* c */ value for myseq",
		"SELECT set_config('default_transaction_read_only', 'off', false)",
		"SELECT lo_put(0, 0, 'x')",
		"SELECT pg_stat_reset()",
		"SELECT pg_switch_wal()",
		"SELECT pg_create_restore_point('before-migration')",
	}
	for _, sql := range writes {
		if IsReadOnlySQL(sql) {
			t.Errorf("有副作用的函数/词组必须判成写: %q", sql)
		}
	}

	// 反向：正常的查询不能被顺手挡掉
	//（`value` 与 `for` 单独出现、next 与 value 不相邻都不算 NEXT VALUE FOR）
	reads := []string{
		"SELECT value FROM t",
		"SELECT * FROM t WHERE name = 'next'",
		"SELECT next_step FROM t",
		"SELECT next, value FROM t",
	}
	for _, sql := range reads {
		if !IsReadOnlySQL(sql) {
			t.Errorf("普通查询被误挡: %q", sql)
		}
	}
}

// TestTrailingSemicolonsMatchForwarding 守 第 10 条：尾部 ; 的判定口径要与转发一致。
//
// 改回错误版本会红：IsReadOnlySQL 用 TrimRight(s, "; ")（把**所有**尾部分号削掉）
// 判"SELECT 1;;"是只读，而 Conn.Query 只 TrimSuffix 一次 —— 真正发给 MySQL 的
// 还是 "SELECT 1;;"，那是语法错；反过来若判定侧一个都不削，只读连接上正常的
// "SELECT 1;" 又会被挡。两边必须用同一个函数。
func TestTrailingSemicolonsMatchForwarding(t *testing.T) {
	// 判定与转发都按"全部尾部分号"处理
	cases := map[string]string{
		"SELECT 1":       "SELECT 1",
		"SELECT 1;":      "SELECT 1",
		"SELECT 1;;":     "SELECT 1",
		"SELECT 1; ;":    "SELECT 1",
		"SELECT 1 ;  ":   "SELECT 1",
		"SELECT 'a;b'":   "SELECT 'a;b'",   // 引号里的分号不是尾部
		"SELECT 1;;DROP": "SELECT 1;;DROP", // 中间的分号不动
	}
	for in, want := range cases {
		if got := trimTrailingSemicolons(in); got != want {
			t.Errorf("trimTrailingSemicolons(%q) = %q，期望 %q", in, got, want)
		}
	}

	// **只削一个分号不够**：单个 TrimSuffix 正是老 Conn.Query 的写法，也是两处
	// 口径不一致的根因（判定说只读、转发却把 `SELECT 1;;` 发出去 → MySQL 语法错）。
	if got := trimTrailingSemicolons("SELECT 1;;"); got != "SELECT 1" {
		t.Errorf("尾部分号要削干净，得到 %q（只削一个会让 'SELECT 1;' 发到数据库报语法错）", got)
	}

	// 单分号仍是只读（最普通的写法不能被挡）
	if !IsReadOnlySQL("SELECT 1;") {
		t.Error("`SELECT 1;` 是最普通的写法，必须判只读")
	}
	// 双分号也按只读判：转发侧会把两个都削掉（口径一致），不会发出语法错的语句
	if !IsReadOnlySQL("SELECT 1;;") {
		t.Error("`SELECT 1;;` 与转发侧口径一致后应当判只读（两个分号都会被削掉）")
	}
	// 但"分号后面还有语句"仍然是多语句，必须拒
	if IsReadOnlySQL("SELECT 1; DROP TABLE t") {
		t.Error("尾分号之后还有语句是多语句，必须判写")
	}
	if IsReadOnlySQL("SELECT 1;; DROP TABLE t") {
		t.Error("多分号 + 后续语句同样是多语句，必须判写")
	}
}

// TestCheckTypeRejectsKeywordSequences 守 第 11 条：类型里不能藏约束/关键字。
//
// 改回错误版本会红：`[A-Za-z][A-Za-z0-9_ ]*` 等于放行任意词序列 ——
// 实测 `int PRIMARY KEY`、`int REFERENCES other`、`text DEFAULT 5` 都能过。
// 类型是**原样拼进 CREATE TABLE 的列定义**的，于是这三个分别能
// 顶掉我们自己的主键子句、建外键、改默认值。
func TestCheckTypeRejectsKeywordSequences(t *testing.T) {
	bad := []string{
		"int PRIMARY KEY",
		"int REFERENCES other",
		"text DEFAULT 5",
		"int NOT NULL",
		"int UNIQUE",
		"text CHECK (1=1)",
		"int COLLATE x",
		"int  int", // 多个空格
		"int;DROP TABLE t",
		"int, evil text",
	}
	for _, b := range bad {
		if err := checkType(b); err == nil {
			t.Errorf("类型 %q 应当被拒绝（会把约束/额外定义拼进 DDL）", b)
		}
	}

	// 正常写法不能被误伤（前端默认给的 varchar(128)/text 也在里面）
	good := []string{
		"int", "varchar(128)", "text", "numeric(10,2)", "timestamp",
		"bigint unsigned",       // MySQL 常用：一个空格的修饰词
		"int unsigned zerofill", // 探针里点名的另一个正常写法
		"double precision",
		"character varying(64)",
		"timestamp with time zone", // PG 的三词写法，不能误挡
		"int[]",
		"varchar(64)[]",
		"INT",
	}
	for _, g := range good {
		if err := checkType(g); err != nil {
			t.Errorf("类型 %q 是正常写法，被误挡：%v", g, err)
		}
	}
}

// TestEscapeStringIsDialectAware 守 第 12 条：PG 下反斜杠不翻倍。
//
// 改回错误版本会红：PostgreSQL 的 standard_conforming_strings 默认 on，
// 普通 '...' 字面量里 `\` 就是普通字符 —— 再翻倍等于把 C:\temp 存成 C:\\temp，
// 用户看到的值多一个反斜杠。MySQL 侧必须照旧翻倍（默认 sql_mode 下反斜杠是转义符）。
func TestEscapeStringIsDialectAware(t *testing.T) {
	my := &Conn{kind: KindMySQL}
	pg := &Conn{kind: KindPostgres}

	// MySQL：反斜杠翻倍（老行为不变，rows_test.go 里那组断言仍然成立）
	if got := my.escapeFor(`C:\temp`); got != `C:\\temp` {
		t.Errorf("MySQL escapeFor(`C:\\temp`) = %q，期望 %q", got, `C:\\temp`)
	}
	// PG：反斜杠**不**翻倍
	if got := pg.escapeFor(`C:\temp`); got != `C:\temp` {
		t.Errorf("PG 不该翻倍反斜杠，escapeFor = %q，期望 %q", got, `C:\temp`)
	}
	// 单引号两种方言都要翻倍（不然语句会被拼坏）
	for _, c := range []*Conn{my, pg} {
		if got := c.escapeFor(`a'b`); got != `a''b` {
			t.Errorf("%s 方言下单引号必须翻倍，得到 %q", c.kind, got)
		}
	}
	// 未知方言（既不是 MySQL）按 PG 的安全口径：不翻倍
	other := &Conn{kind: KindPostgres}
	if got := other.escapeFor(`x\y`); got != `x\y` {
		t.Errorf("非 MySQL 方言不该翻倍反斜杠，得到 %q", got)
	}

	// 老入口保持 MySQL 语义（兼容既有调用/测试）
	if got := escapeString(`C:\temp`); got != `C:\\temp` {
		t.Errorf("escapeString 应保持 MySQL 语义，得到 %q", got)
	}
}

// TestHasStatementSeparatorStillSkipsQuotes 是 第 10 条那处改动的**反向保险**：
// 统一口径之后，"引号里的分号"仍然不能被当成语句分隔符。
func TestHasStatementSeparatorStillSkipsQuotes(t *testing.T) {
	if hasStatementSeparator("SELECT 'a;b'") {
		t.Error("引号里的分号不是语句分隔符")
	}
	if !hasStatementSeparator("SELECT 1; SELECT 2") {
		t.Error("中间的分号必须被判成多语句")
	}
	// 只有尾部一个分号时，削掉之后就没有分隔符了
	if hasStatementSeparator(trimTrailingSemicolons("SELECT 1;")) {
		t.Error("尾部单分号削掉之后不该还有分隔符")
	}
	if !strings.Contains(trimTrailingSemicolons("SELECT 1;;"), "SELECT") {
		t.Error("削分号不能把语句本体也削掉")
	}
}
