package dbx

import "testing"

// 只读判据必须挡住"用注释把 into outfile 拆开"的写法。
//
// 实测过的绕过（修复前 IsReadOnlySQL 全返回 true，只读连接下照发到落文件）：
// `SELECT 'x' INTO--\nOUTFILE '/tmp/x'` 等。根因是 flattenSQL 丢弃 `--` 行注释时
// 不补空格，`into` 与 `outfile` 被粘成 `intooutfile`；`#` 行注释则压根没处理。
// 而 MySQL/MariaDB 里 `-- `（后跟空白/换行）与 `#` 都是到行尾的注释、换行只是空白，
// 服务端看到的是一条完整的 `SELECT 'x' INTO OUTFILE '/tmp/x'`。
func TestIsReadOnlySQLRejectsCommentSplitIntoOutfile(t *testing.T) {
	writes := []string{
		"SELECT 'x' INTO--\nOUTFILE '/tmp/x'",
		"SELECT 'x' INTO-- \nOUTFILE '/tmp/x'",
		"SELECT 'x' INTO--\r\nOUTFILE '/tmp/x'",
		"SELECT 'x' INTO#\nOUTFILE '/tmp/x'",
		"SELECT 'x' INTO--\nDUMPFILE '/tmp/x'",
		"SELECT 'x' INTO/**/OUTFILE '/tmp/x'",
		"SELECT 'x' INTO\tOUTFILE '/tmp/x'",
		"SELECT 'x' INTO\nOUTFILE '/tmp/x'",
	}
	for _, sql := range writes {
		if IsReadOnlySQL(sql) {
			t.Errorf("应判为写（会在目标机落文件），实际判成只读: %q", sql)
		}
	}
}

// 反向：正常查询不能被上面那道收紧误伤。
func TestIsReadOnlySQLStillAcceptsPlainSelect(t *testing.T) {
	reads := []string{
		"SELECT 1",
		"SELECT 1;",
		"select * from t",
		"SELECT * FROM t WHERE id = 1",
		"EXPLAIN SELECT 1",
		// `xinto outfile` 是粘词，不该被单词序列判据命中
		"SELECT xinto outfile FROM t",
	}
	for _, sql := range reads {
		if !IsReadOnlySQL(sql) {
			t.Errorf("正常查询应判只读: %q", sql)
		}
	}
}
