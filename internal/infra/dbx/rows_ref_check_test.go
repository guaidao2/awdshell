package dbx

import (
	"strings"
	"testing"
)

// 这组测试固化复审里的 dbx 修复，断言都写成"改回错误版本会红"。

// ---------- 中3：CreateTable 的库/schema 名也要走 checkTableRef ----------

// spec.Database 里的引号以前是唯一没被拦的入口：它会被 quote() 包进
// `CREATE TABLE \`db\`.\`t\“，请求一路进到 SQL 才报"这张表或这个库不存在"，
// 而 SelectRows / InsertRow / UpdateRow / DeleteRows / ShowCreate 都在入口就
// 明确拒掉了。
//
// 这条断言**在真连数据库之前**就返回：手工构造的 Conn 没有 db 句柄，
// 只要校验漏了就会 panic（nil *sql.DB）或用不上的 SQL 路径 —— 两种都不会
// 给出"名称里不能有空格、引号或分号"这句。所以它精确地钉住"入口校验"。
func TestCreateTableValidatesDatabaseAndSchemaRef(t *testing.T) {
	bad := []TableSpec{
		{Database: `bad"quote`, Table: "t", Columns: []NewColumn{{Name: "id", Type: "int"}}},
		{Database: "bad name", Table: "t", Columns: []NewColumn{{Name: "id", Type: "int"}}},
		{Database: "bad;name", Table: "t", Columns: []NewColumn{{Name: "id", Type: "int"}}},
		{Database: "bad`tick", Table: "t", Columns: []NewColumn{{Name: "id", Type: "int"}}},
		{Schema: `bad"quote`, Table: "t", Columns: []NewColumn{{Name: "id", Type: "int"}}},
		{Schema: "bad name", Table: "t", Columns: []NewColumn{{Name: "id", Type: "int"}}},
	}
	for _, conn := range []*Conn{{kind: KindMySQL}, {kind: KindPostgres}} {
		for _, spec := range bad {
			err := conn.CreateTable(nil, spec)
			if err == nil {
				t.Errorf("%s 方言下 CreateTable(%+v) 应当被拒绝", conn.kind, spec)
				continue
			}
			if !strings.Contains(err.Error(), "名称里不能有空格、引号或分号") {
				t.Errorf("拒绝理由不对（说明没走 checkTableRef）：%v", err)
			}
		}
	}

	// 与单独调用 checkTableRef 完全一致（同一句判据）
	if err := checkTableRef(TableRef{Database: `bad"quote`}); err == nil {
		t.Fatal("测试前提不成立：checkTableRef 自己都没拦")
	}
}

// 空库/schema 名是合法的（MySQL 用连接默认库、PG 回退 public），合法的名字也
// 不能被新加的校验误挡 —— 这条只验判据本身，不往 nil db 上撞（那只会 panic，
// 与"名称校验"无关，断言不出任何东西）。
func TestCreateTableRefCheckDoesNotOverBlock(t *testing.T) {
	ok := []TableRef{
		{Table: "t"},
		{Database: "app_db", Table: "t"},
		{Schema: "public", Table: "t"},
		{Database: "app-db", Schema: "s1", Table: "t"},
	}
	for _, ref := range ok {
		if err := checkTableRef(ref); err != nil {
			t.Errorf("合法的库/schema 名被挡下了: %+v -> %v", ref, err)
		}
	}
}

// ColumnsInfo / PrimaryKeys 自身导出，调用方不一定先在 SelectRows 里过一遍，
// 所以它们也要自己校验库/schema 名。校验发生在真发查询之前 —— 这里同样
// 用"必须报名称错"来钉住它。
func TestColumnsInfoAndPrimaryKeysValidateTableRef(t *testing.T) {
	c := &Conn{kind: KindMySQL}
	if _, err := c.ColumnsInfo(nil, TableRef{Database: `bad"quote`, Table: "t"}); err == nil ||
		!strings.Contains(err.Error(), "名称里不能有空格、引号或分号") {
		t.Errorf("ColumnsInfo 没校验库名: %v", err)
	}
	if _, err := c.PrimaryKeys(nil, TableRef{Schema: "bad name", Table: "t"}); err == nil ||
		!strings.Contains(err.Error(), "名称里不能有空格、引号或分号") {
		t.Errorf("PrimaryKeys 没校验 schema 名: %v", err)
	}
}
