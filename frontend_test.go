package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// 前端（frontend/dist）的回归测试入口。
//
// 那 13 个业务脚本是免构建的原生 JS，这个项目刻意不引 npm 测试链；但这一批的
// 修复里有几条是行为层面的（WebSocket 守卫、innerHTML 转义、切目标重置计时），
// 光看代码、光跑 node --check 都验不出来。用例在 frontend/test/run.js，
// 这里只负责把它挂进 go test：非 0 退出就是测试失败，避免"跑过一次的探针"
// 随时间失效。
func TestFrontendRegression(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("找不到 node，跳过前端回归测试（frontend/test/run.js）")
	}
	cmd := exec.Command(node, filepath.Join("frontend", "test", "run.js"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("前端回归测试失败: %v\n%s", err, out)
	}
	t.Logf("前端回归测试输出：\n%s", out)
}
