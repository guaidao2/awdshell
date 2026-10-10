//go:build windows

package main

import (
	"sync"
	"testing"
)

// 控制台代码页的两条边界（旧账·低12）。
//
// 改回错误版本会红：以前是"拿到当前值就记下来"，本来就是 65001 时也会记成
// 65001 —— 退出时"恢复"等于把 65001 又盖回去，而这个代码页是控制台的全局状态，
// 两个实例叠加（后启动的先退出）会让用户那个 cmd 窗口永久停在 UTF-8。
func TestConsoleCPDecision(t *testing.T) {
	if saved, set := consoleCPDecision(consoleCPUTF8); set || saved != 0 {
		t.Errorf("已经是 65001 时应不记不切，得到 saved=%d set=%v", saved, set)
	}
	if saved, set := consoleCPDecision(936); !set || saved != 936 {
		t.Errorf("936 应记下并切，得到 saved=%d set=%v", saved, set)
	}
	if saved, set := consoleCPDecision(0); !set || saved != 0 {
		t.Errorf("拿不到当前值（没有控制台）仍要尝试切，得到 saved=%d set=%v", saved, set)
	}
}

// savedConsoleCP 会被 main 与 HTTP goroutine 两边形读写（fatalStartup 会从
// handler 的 goroutine 走 restoreConsoleCP），-race 下这条必须干净。
//
// 改回错误版本会红：去掉 consoleCPMu 之后 `go test -race .` 会报数据竞争。
func TestConsoleCPAccessIsRaceFree(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 200; k++ {
				setConsoleUTF8()
				restoreConsoleCP()
			}
		}()
	}
	wg.Wait()
	// 收尾：万一还有没还回去的原值，别把跑测试的那个控制台留在 UTF-8
	restoreConsoleCP()
}
