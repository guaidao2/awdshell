package dbx

import "testing"

func TestReviewFixes(t *testing.T) {
	// 反斜杠转义不是方言无关：PG/SQLite 下这是两条语句，不能判只读
	for _, s := range []string{
		`SELECT 'a\';DROP TABLE t`,
		`SELECT 'a\';DROP TABLE t;`,
		`SELECT "a\";DROP TABLE t`,
	} {
		if IsReadOnlySQL(s) {
			t.Errorf("应判写（反斜杠在 PG 下不转义）: %q", s)
		}
	}
	// 字符串字面量里的 into 不算
	for _, s := range []string{
		"SELECT 'into outfile' AS note",
		"SELECT * FROM t WHERE c = 'go into office'",
	} {
		if !IsReadOnlySQL(s) {
			t.Errorf("普通查询被误判成写: %q", s)
		}
	}
	// 真的 SELECT INTO 仍要拦
	if IsReadOnlySQL("SELECT * INTO evil FROM t") {
		t.Error("SELECT INTO 应判写")
	}
	// 真的多语句仍要拦
	if IsReadOnlySQL("SELECT 1; DROP TABLE t") {
		t.Error("多语句应判写")
	}
}
