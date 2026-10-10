package dbx

import (
	"strings"
	"testing"
)

// 这组测试固化审计里 dbx 包那几条修复，断言都写成"改回错误版本会红"。

// ---------- 低2：MySQL 可执行注释不能被当普通注释剥掉 ----------

// `/*! ... */` 与 `/*!50000 ... */` 是**可执行注释**，MySQL 会把内容展开执行。
// 修复前前导注释被无条件剥掉，`/*!50000 DROP TABLE t */ SELECT 1` 剥成
// `SELECT 1`，实测被判成只读；只读连接下就会把它当查询发出去。
func TestExecutableCommentCannotSneakWrite(t *testing.T) {
	writes := []string{
		"/*!50000 DROP TABLE t */ SELECT 1",
		"/*!50000 DELETE FROM users */ SELECT 1",
		"/*! DROP TABLE t */",
		"/*!50000 INSERT INTO t VALUES (1) */ SELECT 1",
		"/*!50000 UPDATE t SET a=1 */ SELECT 1",
		"/*!50000 TRUNCATE t */ SELECT 1",
		"/*!50000 SELECT 1 INTO OUTFILE '/tmp/x' */ SELECT 1",
		"  \n\t/*!50000 DROP TABLE t */ SELECT 1", // 前导空白不该绕过
		"(/*!50000 DROP TABLE t */ SELECT 1)",     // 前导括号不该绕过
	}
	for _, sql := range writes {
		if IsReadOnlySQL(sql) {
			t.Errorf("可执行注释里的写操作被当成只读放行了: %q", sql)
		}
	}

	// 纯查询形态仍要放行：可执行注释里的 SELECT 放行是安全的（读而已）
	reads := []string{
		"/*!50000 SELECT 1 */",
		"/*! SELECT 1 */",
	}
	for _, sql := range reads {
		if !IsReadOnlySQL(sql) {
			t.Errorf("可执行注释里的纯查询被误挡（只读模式会什么都查不了）: %q", sql)
		}
	}
}

// EXPLAIN 后面跟可执行注释 ANALYZE 时，数据库会真的执行被解释的语句。
func TestExecutableCommentAnalyzeIsNotReadOnly(t *testing.T) {
	if IsReadOnlySQL("EXPLAIN /*!50000 ANALYZE */ DELETE FROM users") {
		t.Error("可执行注释里的 ANALYZE 会让数据库真的执行 DELETE，不能判成只读")
	}
	if !IsReadOnlySQL("EXPLAIN /*!50000 ANALYZE */ SELECT 1") {
		t.Error("EXPLAIN ANALYZE 一个纯查询应当放行")
	}
}

// ---------- 低4：筛选片段要拦住 INTO 的符号变体 ----------

func TestWhereClauseRejectsIntoOutfileVariants(t *testing.T) {
	bad := []string{
		"1=1 INTO  OUTFILE '/tmp/x'", // 双空格：字面量子串匹配认不出
		"1=1 INTO\tOUTFILE '/tmp/x'", // TAB
		"1=1 INTO/**/OUTFILE '/tmp/x'",
		"1=1 into outfile '/tmp/x'", // 大小写
		"1=1 INTO  DUMPFILE '/tmp/x'",
		"1=1 INTO evil", // PG 里是 CREATE TABLE AS、MySQL 是变量赋值
		"1=1 INTO  evil",
	}
	for _, f := range bad {
		if _, err := whereClause(f); err == nil {
			t.Errorf("筛选条件 %q 应当被拒绝（能借它落文件/建表）", f)
		}
	}

	// 注释与分号那几条老判据不能被放宽
	for _, f := range []string{"1=1 #", "1=1 --", "1=1;", "1=1 /*", "1=1 */"} {
		if _, err := whereClause(f); err == nil {
			t.Errorf("筛选条件 %q 应当被拒绝（能把后面的 ORDER BY / LIMIT 注释掉）", f)
		}
	}
}

// 正常筛选不能被上面那道收紧误伤。
func TestWhereClauseStillAcceptsNormalFilters(t *testing.T) {
	good := []string{
		"id > 10",
		"name LIKE '%a%'",
		"a = 1 AND b < 2",
		"id IN (SELECT id FROM other)",
		"created_at > '2026-01-01 00:00:00'",
		"note NOT LIKE '%into%'", // 值里的 into 不该被当成关键字
		"status = 'INTO'",
	}
	for _, f := range good {
		got, err := whereClause(f)
		if err != nil {
			t.Errorf("正常筛选 %q 被误挡: %v", f, err)
			continue
		}
		if !strings.HasPrefix(got, " WHERE ") {
			t.Errorf("whereClause(%q) = %q，缺 WHERE 前缀", f, got)
		}
	}
}

// ---------- 低5：库名 / schema 名也要过 checkIdent ----------

// 它们和表名一样会被 quote() 包进标识符（`db`.`t` / "s"."t"），
// 修复前只有表名过 checkIdent，库名里的引号只靠 quote() 翻倍兜着。
func TestCheckTableRefValidatesDatabaseAndSchema(t *testing.T) {
	for _, bad := range []struct {
		what string
		ref  TableRef
	}{
		{"库名带分号", TableRef{Database: "db; DROP TABLE t", Table: "t"}},
		{"库名带引号", TableRef{Database: "db`x", Table: "t"}},
		{"库名带空格", TableRef{Database: "my db", Table: "t"}},
		{"库名带单引号", TableRef{Database: "db'x", Table: "t"}},
		{"库名带换行", TableRef{Database: "db\nx", Table: "t"}},
		{"schema 带分号", TableRef{Schema: "public; DROP TABLE t", Table: "t"}},
		{"schema 带引号", TableRef{Schema: `pub"x`, Table: "t"}},
	} {
		if err := checkTableRef(bad.ref); err == nil {
			t.Errorf("%s 应当被拒绝: %+v", bad.what, bad.ref)
		}
	}

	// 空串是合法的：MySQL 用连接默认库、PG 回退 public
	for _, ok := range []TableRef{
		{Table: "t"},
		{Database: "app", Table: "t"},
		{Schema: "public", Table: "t"},
		{Database: "app_2024", Schema: "public", Table: "t_user"},
	} {
		if err := checkTableRef(ok); err != nil {
			t.Errorf("%+v 应当合法: %v", ok, err)
		}
	}
}

// ---------- 低3：页码上限（offset 整数溢出） ----------

// page = 2^62、size = 100 时 (page-1)*size 回绕成负数，拼出 `OFFSET -1000`。
//
// **注意 Go 里的大常数不算数**：`(1<<62-1)*100` 这种无类型常数表达式在编译期按
// 任意精度求值，赋给 int 时才模 2^64 截断，未必变成负数。要真的看到负 OFFSET，
// 得让"乘积"越过 int64 上限再回绕到负半区 —— 用变量 + 稍小的页号最直观。
// 这里只验纯逻辑：溢出确实会发生（说明这道闸门不是多余的），且闸门放行的
// 页号怎么乘都不会溢出。
func TestRowPageOffsetOverflowIsPrevented(t *testing.T) {
	// 先证明"没有上限时真的会溢出"，否则这个测试会变成空断言
	const (
		somePage = 1 << 55 // 2^55 已经足够：(2^55-1)*1000 越过 int64 上限
		maxSize  = 1000
	)
	page := somePage // 变量：避开无类型常数的任意精度求值
	if (page-1)*maxSize >= 0 {
		t.Fatalf("前提不成立：(%d-1)*%d 在本架构上没有回绕成负数，请重挑页号", somePage, maxSize)
	}

	// 闸门放行的最大页号，怎么乘都不能溢出
	if got := (maxRowPage - 1) * maxSize; got < 0 {
		t.Fatalf("上限之内的 offset 不该为负，实际 %d", got)
	}
	if maxRowPage > somePage {
		t.Fatalf("maxRowPage=%d 太大，溢出页号还能进到 SQL 拼接", maxRowPage)
	}
}
