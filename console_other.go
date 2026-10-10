//go:build !windows

package main

// 非 Windows 平台：没有 GUI 子系统这回事，控制台本来就正常；
// 也没有 MessageBox，退回标准错误输出。

import (
	"fmt"
	"os"
)

func showErrorBox(title, text string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", title, text)
}

func showNotice(title, text string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", title, text)
}

func attachParentConsole() {}

func restoreConsoleCP() {}
