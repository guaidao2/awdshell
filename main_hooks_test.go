package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guaidao2/awdshell/internal/domain"
	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"
)

// 这个文件守 audit44 H2 的两个面：**接线有没有挂**（main.go 里那两行）
// 与**挂上之后真的会清**（service 的行为）。

// TestStartupWiresMonitorCleanupHooks 是一条**接线契约**测试：main.go 的启动路径里
// 必须同时给"删目标"和"更新目标"挂上 monitor.Forget。
//
// 为什么只能查文本：清理动作的触发点在 service，但接线在 main 的启动流程里 ——
// 而启动流程要在真实数据目录上起库、起服务，测试里跑不动。实测过：把
// `targets.AddOnSave(monitor.Forget)` 那行删掉，service 包的功能测试照样全绿
// （它们自己把钩子挂上了）—— 审计 H2 就是这么一个"函数写好了、没人挂"的漏网之鱼。
//
// 改回错误版本会红：删掉任一条 AddOn* 接线，下面立刻找不到对应语句。
func TestStartupWiresMonitorCleanupHooks(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读 main.go 失败: %v", err)
	}
	code := string(src)
	// 只看**代码行**：注释里也提到这些标识符，不能让注释顶替真接线。
	var lines []string
	for _, l := range strings.Split(code, "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		lines = append(lines, trimmed)
	}
	body := strings.Join(lines, "\n")

	for _, want := range []string{
		"targets.AddOnDelete(monitor.Forget)",
		"targets.AddOnSave(monitor.Forget)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("main.go 的启动接线里缺少 %q ——\n"+
				"  少了 AddOnDelete：删掉的目标会留下采样基准\n"+
				"  少了 AddOnSave  ：把目标改成另一台机器后，下一次采样的 CPU%%/网速\n"+
				"                    拿旧主机的 /proc/stat 与网卡计数做差，是假值（审计 H2）",
				want)
		}
	}
	// 反向判据（"不许用 SetOnDelete"）**不写**：main.go 里确实有一处合法的
	// SetOnDelete(dbSvc.DropConnsOfTarget)，而它必须在 AddOnDelete 之前调用
	//（覆盖语义）。顺序这类东西由上面那两条正向断言 + 代码评审守，
	// 在这里写一条基于文本的负向匹配只会误报。
}

// TestSavePathClearsMonitorBaseline 走一遍**真实的 Save 路径**，确认接线挂上之后
// 更新目标真的会清掉采样基准（不只是"函数被调用了"）。
//
// 改回错误版本会红：Save 里少了 runSaveHooks（或 main 里少了 AddOnSave），
// 缓存里的旧快照就原样留着 —— 那就是 H2。
func TestSavePathClearsMonitorBaseline(t *testing.T) {
	base := t.TempDir()
	st, err := store.Open(filepath.Join(base, "t.db"))
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	vault, err := secret.New(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	targets := service.NewTargetService(st, vault)
	monitor := service.NewMonitorService(targets, nil)
	// 与 main.go 一致的两行接线
	targets.AddOnDelete(monitor.Forget)
	targets.AddOnSave(monitor.Forget)

	saved, err := targets.Save(service.SaveTargetInput{
		Name: "A", Host: "10.0.0.1", Username: "root", AuthKind: domain.AuthPassword, Password: "pw",
	})
	if err != nil {
		t.Fatalf("新建目标失败: %v", err)
	}
	// 模拟"已经采过一次 A 机"
	monitor.SeedBaselineForTest(saved.ID)
	if !monitor.HasBaselineForTest(saved.ID) {
		t.Fatal("测试前提不成立：基准没塞进去")
	}

	// 改成 B 机（同一个 targetID）
	if _, err := targets.Save(service.SaveTargetInput{
		ID: saved.ID, Name: "B", Host: "10.0.0.2", Username: "root",
		AuthKind: domain.AuthPassword, Password: "pw",
	}); err != nil {
		t.Fatalf("更新目标失败: %v", err)
	}
	if monitor.HasBaselineForTest(saved.ID) {
		t.Error("更新目标（换成另一台机器）之后不该留着旧主机的采样基准（审计 H2）")
	}
}
