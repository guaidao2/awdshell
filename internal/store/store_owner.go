package store

import "os"

// processAlive 判断一个 pid 对应的进程是否还在跑。
//
// 判据（Windows）：os.FindProcess 走 OpenProcess，进程不存在时直接返回错误
// （ERROR_INVALID_PARAMETER），所以 err == nil 就是"还活着"，不需要再发信号。
// 本项目只交付 Windows 桌面形态（见 README / 构建链），故没有 unix 分支；
// 将来要在 unix 上跑，这里补一个 `p.Signal(syscall.Signal(0))` 的实现即可
// （那种写法在 unix 上 err==nil 表示"存在且有权发信号"）。
//
// 注意 pid 复用：Windows 复用 pid 是可能的，但"复用成另一个还活着的进程"
// 只会让我们**少标**一条崩溃残留（历史里多挂一条"进行中"），
// 而判错的另一头是"把别人正在跑的会话标脏"——两者相比少标是可接受的。
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	return err == nil
}
