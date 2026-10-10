package dbx

import "testing"

// 只读判据还要挡住"看着像 SELECT 的写"。
//
// 实测这些以前都被判成只读：`SELECT * INTO evil FROM t`（PG 里就是
// CREATE TABLE AS）、`SELECT nextval('s')`、`setval`、`lo_export(1,'/tmp/x')`、
// `pg_terminate_backend(1)`（照样能断别人的连接）、`pg_read_file('/etc/passwd')`、
// `SELECT 1 INTO @a`。服务端只读事务能兜住 SELECT INTO / nextval，
// 兜不住 pg_terminate_backend 这类函数动作。
func TestIsReadOnlySQLRejectsSideEffectFunctions(t *testing.T) {
	writes := []string{
		"SELECT * INTO evil FROM t",
		"SELECT 1 INTO @a",
		"SELECT nextval('s')",
		"SELECT setval('s', 1)",
		"SELECT lo_export(1, '/tmp/x')",
		"SELECT pg_terminate_backend(1)",
		"SELECT pg_cancel_backend(1)",
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT pg_sleep(5)",
		"SELECT dblink_exec('conn', 'delete from t')",
	}
	for _, sql := range writes {
		if IsReadOnlySQL(sql) {
			t.Errorf("应判为写/有副作用，实际判成只读: %q", sql)
		}
	}
}

// 纯查询仍要放行（别把只读模式变成"什么都查不了"）。
func TestIsReadOnlySQLStillReads(t *testing.T) {
	reads := []string{
		"SELECT id, name FROM users WHERE id = 1",
		"SELECT count(*) FROM t GROUP BY k HAVING count(*) > 1",
		"SELECT a FROM t1 JOIN t2 ON t1.id = t2.id",
		"WITH x AS (SELECT 1 AS n) SELECT n FROM x",
		"SELECT * FROM t ORDER BY id LIMIT 10 OFFSET 20",
	}
	for _, sql := range reads {
		if !IsReadOnlySQL(sql) {
			t.Errorf("正常查询不该被挡: %q", sql)
		}
	}
}
