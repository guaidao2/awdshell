package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseDFMountWithSpaces 守 L5②：挂载点含空格时必须完整取到。
//
// 背景：老实现取 strings.Fields(line) 的**最后一列**当挂载点。`df -P` 的列是
// 固定的（Filesystem 1024-blocks Used Available Capacity Mounted on），最后一列
// 才是挂载点，而挂载点可以含空格 —— 实测 `/mnt/my data` 被解析成 `data`，
// 界面上挂载点少了一截，按挂载点排查容量时对不上号。
func TestParseDFMountWithSpaces(t *testing.T) {
	out := "Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
		"/dev/sda1 102400 51200 51200 50% /mnt/my data\n" +
		"/dev/sdb1 204800 102400 102400 50% /\n"

	got := parseDF(out)
	if len(got) != 2 {
		t.Fatalf("应解析出 2 个挂载点，实际 %d：%+v", len(got), got)
	}
	if got[0].Mount != "/mnt/my data" {
		t.Errorf("含空格的挂载点解析错：得到 %q，期望 %q（老实现会退化成 data）",
			got[0].Mount, "/mnt/my data")
	}
	if got[0].Device != "/dev/sda1" || got[0].Total != 102400 || got[0].Used != 51200 {
		t.Errorf("同一行的其他列也解析错了：%+v", got[0])
	}
	if got[1].Mount != "/" {
		t.Errorf("普通挂载点解析错：%q", got[1].Mount)
	}

	// 表头不能被当成数据行
	for _, d := range got {
		if strings.Contains(d.Mount, "Mounted") {
			t.Errorf("表头被当成数据行了：%+v", d)
		}
	}
}

// TestParseDetailedReportsMissing 守 L5③ 与 L8：
//
//	① 精简镜像 / BusyBox 上 `ps --sort`、`df -B1`、`ss` 会被 2>/dev/null 吞掉，
//	   表现成一片空白 —— 脚本用 @@OK/@@NO 区分"命令不存在"与"采到了但为空"。
//	② 空输出时不能只返回全零快照：调用方必须能分辨"没采到"与"真的是 0"。
//
// 临时目录按要求开在工作区内（os.MkdirTemp(".", ".test-*")），不碰系统临时目录。
func TestParseDetailedReportsMissing(t *testing.T) {
	dir, err := os.MkdirTemp(".", ".test-*")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	defer os.RemoveAll(dir)

	// 用真实文件走一遍"输出 → 落盘 → 读回 → 解析"，不只在内存里拼字符串
	rawPath := filepath.Join(dir, "sample.txt")
	var sb strings.Builder
	for _, sec := range []struct {
		name, marker string
	}{
		{"STAT", ""}, {"MEM", ""}, {"LOAD", ""}, {"UPTIME", ""},
		{"DF", "@@NO"}, {"PS", "@@NO"}, {"CONN", "@@NO"}, {"SS", "@@NO"},
	} {
		sb.WriteString("@@" + sec.name + "\n")
		if sec.marker != "" {
			sb.WriteString(sec.marker + "\n")
		}
	}
	sb.WriteString("@@END\n")

	if err := os.WriteFile(rawPath, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("写样本失败: %v", err)
	}
	data, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("读样本失败: %v", err)
	}

	s, missing := ParseDetailed(string(data))
	if s.Collected {
		t.Error("STAT / MEM 都没采到，Collected 不该为 true —— 界面会把没采到画成 CPU 0%")
	}
	for _, name := range []string{"STAT", "MEM", "DF", "PS", "CONN", "SS"} {
		if !hasStr(missing, name) {
			t.Errorf("缺失段里应当有 %s，实际 %v", name, missing)
		}
	}
	// 老实现（只有 Parse、返回全零且不报错）在这里没法区分：
	// Missing 是本次新增的判据，必须非空。
	if len(s.Missing) == 0 {
		t.Error("Missing 不能为空：没有它就无法在界面上标注'未采集到'")
	}
}

// TestParseDetailedCollected 正常输出必须被判为"采到了"，否则会把好数据也标成未采集。
func TestParseDetailedCollected(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("@@STAT\ncpu  100 0 50 1000 20 0 5 0 0 0\n")
	sb.WriteString("@@MEM\nMemTotal:       16384000 kB\nMemFree:         1000000 kB\n")
	sb.WriteString("@@DF\n@@OK\n")
	sb.WriteString("Filesystem 1024-blocks Used Available Capacity Mounted on\n")
	sb.WriteString("/dev/sda1 100 50 50 50% /\n")
	sb.WriteString("@@PS\n@@OK\n")
	sb.WriteString("@@CONN\n@@OK\n")
	sb.WriteString("@@SS\n@@OK\n")
	sb.WriteString("@@END\n")

	s, missing := ParseDetailed(sb.String())
	if !s.Collected {
		t.Errorf("关键段都在，Collected 应为 true，实际 false（missing=%v）", missing)
	}
	if s.CPU.Total() == 0 {
		t.Error("CPU 时间片没解析出来")
	}
	if s.Mem["MemTotal"] != 16384000 {
		t.Errorf("内存没解析出来：%v", s.Mem)
	}
	// @@OK 标记本身不能被当成数据行（它自己在段体第一行）
	if len(s.Disks) != 1 || s.Disks[0].Mount != "/" {
		t.Errorf("磁盘没解析出来（或 @@OK 混进了数据）：%+v", s.Disks)
	}
}

func hasStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
