package sshx

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

// 这一组守的是「命令失败不等于连接坏」。
//
// 背景：RunOutput 对命令退出码非 0 也会返回错误（ssh.ExitError），而调用方曾经
// 把任何错误都当作连接不可用去丢弃共享连接。连接是终端、文件、监控、日志扫描
// 共用的，于是扫一个格式不对的日志（lastb 对空 btmp 会返回非 0）就把用户正在
// 用的终端一起切断了 —— 界面上表现为标签变红、终端显示 [连接已结束]。
func TestIsConnError(t *testing.T) {
	if IsConnError(nil) {
		t.Error("nil 不该算连接错误")
	}

	exitErr := &ssh.ExitError{}
	if IsConnError(exitErr) {
		t.Error("命令退出码非 0 不该算连接错误")
	}
	// 错误常被包装一层（我们自己在 RunOutput 里包过），必须仍能识别
	if IsConnError(fmt.Errorf("lastb 失败: %w", exitErr)) {
		t.Error("被 %w 包装的 ExitError 也要能识别出来")
	}

	// 超时只是命令没跑完，不代表连接坏了。
	// 否则监控采集、日志扫描、目录同步只要慢一次超时，就会 Drop 掉
	// 终端共用的那条连接，把用户正在用的会话一起掐断。
	if IsConnError(ErrRunTimeout) {
		t.Error("超时不该算连接错误")
	}
	if IsConnError(fmt.Errorf("%w（8s）", ErrRunTimeout)) {
		t.Error("被包装的超时错误也要能识别出来")
	}

	for _, msg := range []string{
		"connection reset by peer",
		"EOF",
		"创建执行通道失败: EOF",
	} {
		if !IsConnError(errors.New(msg)) {
			t.Errorf("%q 应该被判为连接错误", msg)
		}
	}
}
