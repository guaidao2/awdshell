package main

import (
	"os"
	"strings"
	"testing"
)

// 启动失败时要把原因写下来 —— 窗口形态没有控制台，弹框是唯一的即时反馈，
// 日志文件则是事后能翻的记录。
func TestWriteStartupLog(t *testing.T) {
	// 在**当前目录**下建临时目录（不用系统临时目录）
	dir, err := os.MkdirTemp(".", ".test-startup-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := writeStartupLog(dir, "打开数据库失败: 测试")
	if path == "" {
		t.Fatal("writeStartupLog 应返回日志路径")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回日志失败: %v", err)
	}
	if !strings.Contains(string(b), "打开数据库失败: 测试") {
		t.Errorf("日志内容不含消息: %q", string(b))
	}

	// 追加而不是覆盖：第二次失败不该抹掉第一次的线索
	writeStartupLog(dir, "第二次失败")
	b2, _ := os.ReadFile(path)
	if !strings.Contains(string(b2), "打开数据库失败: 测试") ||
		!strings.Contains(string(b2), "第二次失败") {
		t.Errorf("日志应追加，实际内容: %q", string(b2))
	}

	// 空目录名不该panic，只返回空串
	if got := writeStartupLog("", "x"); got != "" {
		t.Errorf("空目录应返回空串，得到 %q", got)
	}
	if got := writeStartupLog("   ", "x"); got != "" {
		t.Errorf("空白目录应返回空串，得到 %q", got)
	}
}
