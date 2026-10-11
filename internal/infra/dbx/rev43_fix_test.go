package dbx

import (
	"strings"
	"testing"
)

// 这一组固化 review43 里 dbx 的两条修复，断言都写成"改回错误版本会红"。

// TestRev43MySQLBackslashQuoteIsReadOnly 守 高1：`\` + 引号不能一律判成"写"。
//
// 改回错误版本会红：以前 hasStatementSeparator 里写的是
//
//	if c == '\\' && quote != '`' { if s[i+1] == quote { return true } }
//
// 也就是"反斜杠后面跟引号 → 有语句分隔符"，不分方言。MySQL 默认 sql_mode 下
// `\'` 是**字面量里的引号**（不是分隔），于是最普通的
// `SELECT 'it\'s' AS c` 被判成写，两条后果都很实在：
//   - 只读连接直接拒（"只读模式只允许查询类语句"）；
//   - 非只读连接走 ExecContext，**结果集被静默丢掉**，界面显示"影响 0 行"。
func TestRev43MySQLBackslashQuoteIsReadOnly(t *testing.T) {
	reads := []string{
		`SELECT 'it\'s' AS c`,
		`SELECT * FROM users WHERE name='O\'Brien'`,
		`SELECT 'a\'b\'c' AS s FROM t`,
		`SELECT * FROM t WHERE note='C:\\path\\to\\x' AND s='it\'s'`,
		// 方言要一路带进 EXPLAIN 的递归判定
		`EXPLAIN ANALYZE SELECT 'it\'s' AS c`,
		// 反引号标识符里的反斜杠本来就与转义无关
		"SELECT `a\\` FROM t",
	}
	for _, sql := range reads {
		if !IsReadOnlySQLFor(sql, KindMySQL) {
			t.Errorf("MySQL 方言下这是普通查询，不该判成写: %q", sql)
		}
	}

	// **写操作一条都不能被放过去**（复审确认过 INTO OUTFILE 那条没被绕过，
	// 这里连着方言一起钉住）：
	writes := []string{
		`SELECT 'a\'b' INTO OUTFILE '/tmp/x'`,
		`SELECT 'it\'s', 1 INTO DUMPFILE '/tmp/x'`,
		`SELECT 1; DROP TABLE t`,
		// `\\` 是转义后的反斜杠，引号真的收尾了 —— `;DROP` 是第二条语句
		`SELECT 'a\\';DROP TABLE t`,
		`SELECT 'it\'s' INTO OUTFILE '/tmp/x' FROM t`,
	}
	for _, sql := range writes {
		if IsReadOnlySQLFor(sql, KindMySQL) {
			t.Errorf("MySQL 方言下这条会真的写/落文件，必须判成写: %q", sql)
		}
	}
}

// TestRev43UnknownDialectStaysConservative 守"方言不明时保持原签名与保守方向"。
//
// 老签名 IsReadOnlySQL 必须仍在（service 侧还在用），而且必须是**保守的那一侧**：
// PG / SQLite 里 `\` 是普通字符，`SELECT 'a\';DROP TABLE t` 真的是两条语句 ——
// 按 MySQL 口径跳过就等于把多语句闸门关掉（整串被当成"未闭合的字符串"，
// 判成只读 → 走 QueryContext）。
func TestRev43UnknownDialectStaysConservative(t *testing.T) {
	// 方言不明：与老实现一致，判写（拒只读）
	if IsReadOnlySQL(`SELECT 'it\'s' AS c`) {
		t.Error("方言不明时 `\\'` 必须按保守口径判写（不能默认按 MySQL 的转义语义）")
	}
	if IsReadOnlySQL(`SELECT * FROM users WHERE name='O\'Brien'`) {
		t.Error("方言不明时不能放行带 `\\'` 的语句")
	}
	// PG 方言显式传入时同样是保守的
	if IsReadOnlySQLFor(`SELECT 'a\';DROP TABLE t`, KindPostgres) {
		t.Error("PG 里 `\\` 不转义，`SELECT 'a\\';DROP TABLE t` 是两条语句，必须判写")
	}
	if IsReadOnlySQLFor(`SELECT 'a\';DROP TABLE t`, "") {
		t.Error("空方言必须按最保守口径（等价于 IsReadOnlySQL）")
	}

	// 两种方言都该认的普通查询不受影响
	for _, sql := range []string{"SELECT 1", "SELECT 'a;b' AS x", "SELECT 'a''b' AS x", "SHOW TABLES"} {
		if !IsReadOnlySQLFor(sql, KindMySQL) || !IsReadOnlySQLFor(sql, KindPostgres) || !IsReadOnlySQL(sql) {
			t.Errorf("普通查询在任一方言下都该判只读: %q", sql)
		}
	}
}

// TestRev43CheckTypeAcceptsModifierAfterPrecision 守 低4：修饰词可以写在括号之后。
//
// 改回错误版本会红：老 typeRe 只允许修饰词出现在 `(...)` **之前**，
// 于是 MySQL 合法且常见的 `decimal(10,2) unsigned` 被拒
// （"这个字段类型写法不支持"），用户只是照文档写了个金额列。
func TestRev43CheckTypeAcceptsModifierAfterPrecision(t *testing.T) {
	good := []string{
		"decimal(10,2) unsigned",
		"decimal(10,2) unsigned zerofill",
		"numeric(10,2)",
		"varchar(64)",
		"int",
		"bigint unsigned",
		"int unsigned zerofill",
		"double precision",
		"timestamp with time zone",
		"character varying(64)",
		"int[]",
		"varchar(64)[]",
	}
	for _, g := range good {
		if err := checkType(g); err != nil {
			t.Errorf("类型 %q 是正常写法，被误挡：%v", g, err)
		}
	}

	// **放开"括号后有词"绝不能把 deny 名单也一起放开**（这才是这次改动的风险点）：
	// typeWords 以前在第一个 `(` 处截断，于是括号后面的词整段不过滤 ——
	// 下面这些会被原样拼进 CREATE TABLE 的列定义，顶掉我们自己的主键子句、
	// 建外键、改默认值。
	bad := []string{
		"varchar(64) primary key",
		"varchar(64) not null",
		"numeric(10,2) references other",
		"varchar(64) default 5",
		"int (10) unique",
		"text (1) check",
		"varchar(64) collate x",
		"varchar(64) generated always as (1)",
	}
	for _, b := range bad {
		if err := checkType(b); err == nil {
			t.Errorf("类型 %q 必须被拒绝（括号后面的词会绕过 deny 名单拼进 DDL）", b)
		}
	}

	// 机制层断言：typeWords 必须看到括号**后面**的词
	words := strings.Join(typeWords("varchar(64) primary key"), ",")
	if !strings.Contains(words, "primary") || !strings.Contains(words, "key") {
		t.Errorf("typeWords 把括号后面的词丢了（words=%q）—— deny 名单会形同不存在", words)
	}
}

// TestRev43QuoteAwareWordsIsDialectAware 是高1 的另一半：分词也得按方言处理反斜杠。
//
// 改回错误版本会红：quoteAwareWords 不认 `\'`，于是 MySQL 的
// `SELECT 'a\'b' INTO OUTFILE '/tmp/x'` 被切成 [select b tmp x] ——
// 凑不出 `into outfile`，这条**会落文件的语句反而判成只读**。
// 它以前"看起来没事"只是因为 hasStatementSeparator 那条过宽的判据一律判写，
// 而那条判据正是高1 要修的（修完就不能再靠它兜底）。
func TestRev43QuoteAwareWordsIsDialectAware(t *testing.T) {
	const sql = `SELECT 'a\'b' INTO OUTFILE '/tmp/x'`

	my := strings.Join(quoteAwareWordsIn(sql, true), " ")
	if !strings.Contains(my, "into outfile") {
		t.Errorf("MySQL 方言下 `\\'` 是字面量里的引号，into/outfile 应当落在字面量之外：%q", my)
	}
	// 非 MySQL（或方言不明）：`\'` 当场收尾，后面的内容被切成碎片 ——
	// 这条正是"必须分方言"的证据，也是它单独用不了的原因。
	other := strings.Join(quoteAwareWordsIn(sql, false), " ")
	if strings.Contains(other, "into outfile") {
		t.Errorf("非 MySQL 方言下的分词不该与 MySQL 一致（否则方言参数没生效）：%q", other)
	}

	// 两种方言都不该把字面量**内部**的 into outfile 当成写
	quoted := `SELECT 'into outfile' AS note`
	for _, esc := range []bool{true, false} {
		got := strings.Join(quoteAwareWordsIn(quoted, esc), " ")
		if strings.Contains(got, "into outfile") {
			t.Errorf("引号里的 into outfile 不是关键字（backslashEscapes=%v）：%q", esc, got)
		}
	}
}
