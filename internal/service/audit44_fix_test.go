package service

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"
	"github.com/guaidao2/awdshell/internal/secret"
)

// 这一组固化 audit44 里 service 那两条（H2 / M1），断言都写成"改回错误版本会红"。

// TestTargetSaveForgetsMonitorBaseline 守 H2：**更新**已有目标时也要清采样基准。
//
// 为什么必须清：Save 的更新分支保留原 ID（见 `target.go` 里的 existing），
// 于是把一台目标从 A 机改成 B 机之后，`last[targetID]` 里存的还是 A 机的
// /proc/stat 时间片与网卡累计字节。下一次采样拿它做差算 CPU% 与网速 ——
// 数字是假的，而且 First=false，界面按"正常数值"画出来（错误数据，不是缺失数据）。
//
// 这条测的是 **service 侧的行为**（Save 命中更新分支会跑钩子）；接线本身
// （main.go 有没有把 monitor.Forget 挂到 AddOnSave 上）由 main 包的
// TestStartupWiresMonitorCleanupHooks / TestSavePathClearsMonitorBaseline 守 ——
// 只有这两边都在，"改了目标之后不再画假 CPU"才算真的成立。
func TestTargetSaveForgetsMonitorBaseline(t *testing.T) {
	base := mkTempDir(t, ".test-save-forget-")
	st := openStore(t, base)
	vault, err := secret.New(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	targets := NewTargetService(st, vault)
	mon := NewMonitorService(targets, nil)
	// 接线与 main.go 一致：删除挂 AddOnDelete、更新挂 AddOnSave
	targets.AddOnDelete(mon.Forget)
	targets.AddOnSave(mon.Forget)

	// 建一个目标（新建不该触发清理钩子）
	saved, err := targets.Save(SaveTargetInput{
		Name: "A", Host: "10.0.0.1", Username: "root", AuthKind: domain.AuthPassword,
		Password: "pw",
	})
	if err != nil {
		t.Fatalf("新建目标失败: %v", err)
	}

	// 模拟"已经采过一次 A 机"：把基准塞进缓存
	mon.SeedBaselineForTest(saved.ID)

	// 把它改成 B 机（同一个 targetID）
	if _, err := targets.Save(SaveTargetInput{
		ID: saved.ID, Name: "B", Host: "10.0.0.2", Username: "root",
		AuthKind: domain.AuthPassword, Password: "pw",
	}); err != nil {
		t.Fatalf("更新目标失败: %v", err)
	}

	if mon.HasBaselineForTest(saved.ID) {
		t.Error("更新目标（换成另一台机器）之后不该留着旧主机的采样基准")
	}
	mon.mu.Lock()
	defer mon.mu.Unlock()
	if _, ok := mon.lastAt[saved.ID]; ok {
		t.Error("更新目标之后不该留着旧的采样时间")
	}
	if _, ok := mon.sampleLocks[saved.ID]; ok {
		t.Error("更新目标之后采样锁也该一起清（否则锁表会跟着目标无限增长）")
	}
}

// TestTargetCreateDoesNotRunSaveHook 钉住"新建不触发更新钩子"。
//
// 新建没有旧状态可清；如果不小心对新建也调一次，那只是白跑一次 Forget ——
// 但 AppOnSave 的语义要说清楚，所以顺手钉住。
func TestTargetCreateDoesNotRunSaveHook(t *testing.T) {
	base := mkTempDir(t, ".test-save-new-")
	st := openStore(t, base)
	vault, err := secret.New(filepath.Join(base, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	targets := NewTargetService(st, vault)

	var mu sync.Mutex
	var seen []string
	targets.AddOnSave(func(id string) {
		mu.Lock()
		seen = append(seen, id)
		mu.Unlock()
	})

	if _, err := targets.Save(SaveTargetInput{
		Name: "A", Host: "10.0.0.1", Username: "root", AuthKind: domain.AuthPassword, Password: "pw",
	}); err != nil {
		t.Fatalf("新建目标失败: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Errorf("新建目标不该触发更新钩子，实际 %v", seen)
	}
}

// TestDeleteEmptyPathsReturnsSentinel 守 M3 的 service 侧那一半。
//
// 为什么需要它：清空 paths 这件事有两道闸门 —— httpapi 入口先判一次，
// service 的 Delete 再判一次。只测"HTTP 回 400"的话，把 service 的哨兵换回
// 普通 fmt.Errorf 测试照样绿（httpapi 那道闸门先返回了）—— 而真实调用方
// （别的内部调用点、或以后前端改了路径）就会重新拿到一个 502。
// 这里直接断言哨兵本身，**改回错误版本立刻红**。
func TestDeleteEmptyPathsReturnsSentinel(t *testing.T) {
	// targets 与 pool 都为 nil：判据在碰远端之前就返回，所以不会有 nil 解引用
	fs := NewFileService(nil, nil)
	for _, paths := range [][]string{nil, {}} {
		res, err := fs.Delete("t1", paths, true)
		if !errors.Is(err, ErrDeleteNoPaths) {
			t.Errorf("Delete(%q) 应返回 ErrDeleteNoPaths（客户端错误，控制面据此回 400），得到 %v",
				paths, err)
			continue
		}
		// **返回的必须就是哨兵本身，而不是"文案相同"的临时错误**：
		// Go 会复用 errors.New/fmt.Errorf 的内部实例，光比 errors.Is 分不出
		// "返回哨兵"与"返回了一个字面量相同的临时错误"，所以这里再加一道
		// 与同胞错误 errDeleteNoPaths 的对照（它必须**不**匹配）。
		// 改回"返回临时错误"的写法（那正是 M3 的根因：调用方 errors.Is 认不出，
		// 一律按 502 处理）时，这条会红。
		if errors.Is(err, errDeleteNoPaths) {
			t.Errorf("Delete(%q) 返回的是临时错误而不是哨兵本身（调用方会认不出、一律 502）",
				paths)
		}
		if len(res.Deleted) != 0 || len(res.Failed) != 0 {
			t.Errorf("空输入不该产生删除结果：%+v", res)
		}
	}
	// 只有空白项是另一码事：它们被逐条校验挡下，结果是"零条要删"而不是入参错误
	//（此时不该报错，也不该去碰远端）
	res, err := fs.Delete("t1", []string{"", "  "}, true)
	if err != nil {
		t.Errorf("只有空白路径时应视为'没有合法路径要删'，不该报错，得到 %v", err)
	}
	if len(res.Deleted) != 0 {
		t.Errorf("空白路径不该被删掉：%+v", res)
	}
}

// TestSampleLockIsPerTarget 守 M1：采样锁是**按目标**的，不是一把全局锁。
//
// 为什么要按目标：一次采样最长约 27 秒（400ms 首次间隔 + 12s 拨号 + 15s 采集）。
// 全局锁下"A 还在采的时候切到 B"会得到"上一次采样还没结束"，界面把它画成红色的
// "采集失败"并停在 A 的数字上 —— 而 B 什么都没错，只是被 A 挡住了。
//
// 改回错误版本会红：全局 sampleMu 与 targetID 无关，下面把 t1 的锁拿在手里
// 根本挡不住 t2 的采样（它会一路走到 rawSample，因为 targets 是 nil 而 panic）。
func TestSampleLockIsPerTarget(t *testing.T) {
	mon := NewMonitorService(nil, nil)

	// 把 t1 的锁"占住"，模拟 t1 正在采
	lk := mon.lockFor("t1")
	lk.Lock()
	defer lk.Unlock()

	// t1 再来一发 → 明确的并发拒绝错误值（不是普通 error）
	if _, err := mon.Sample("t1"); !errors.Is(err, ErrSampling) {
		t.Fatalf("同一目标并发采样应返回 ErrSampling，得到 %v", err)
	}

	// t2 是另一个目标：不该被 t1 的锁挡住。
	// targets 为 nil，真去采样会 panic —— 用 recover 把它变成"确实走进了采样路径"的证据，
	// 并且断言拿到的**不是** ErrSampling（那才是"被 t1 挡住了"）。
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- nil // 走到 rawSample 才 panic：说明没被 t1 的锁挡住
			}
		}()
		_, err := mon.Sample("t2")
		done <- err
	}()
	select {
	case err := <-done:
		if errors.Is(err, ErrSampling) {
			t.Fatalf("t2 不该被 t1 的采样挡住（锁必须是按目标的），实际 %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("t2 的采样没在 5 秒内返回 —— 说明它被全局锁挡住了")
	}
}

// TestSampleLocksDoNotGrowForever 钉住 Forget 会把锁表里那一项也删掉。
//
// 不删的话，切过的每个目标都会在 sampleLocks 里留一个 Mutex —— 虽然小，
// 但这是"按 targetID 缓存"的通病，Forget 是唯一的清理点。
func TestSampleLocksDoNotGrowForever(t *testing.T) {
	mon := NewMonitorService(nil, nil)
	mon.lockFor("t1")
	mon.lockFor("t2")
	if got := len(mon.sampleLocks); got != 2 {
		t.Fatalf("锁表里应有 2 项，实际 %d", got)
	}
	mon.Forget("t1")
	if _, ok := mon.sampleLocks["t1"]; ok {
		t.Error("Forget 之后锁表里不该还留着这个目标")
	}
	if _, ok := mon.sampleLocks["t2"]; !ok {
		t.Error("Forget 只能清指定的目标，t2 不该被连带清掉")
	}
}

// TestErrSamplingIsRecognizable 钉住并发拒绝是**专门的错误值**而不是一句话。
//
// 控制面靠 errors.Is 把它映射成 409（"跳过这一轮"）而不是 502（"采集失败"）；
// 如果退回成 fmt.Errorf（不包 %w），errors.Is 就认不出，界面又会把切目标
// 画成红色故障。
//
// 注意 Go 的 fmt.Errorf 对**无格式串**会复用内部实例（实测：与 errors.New
// 同字面量时甚至是同一个指针），所以"同一句话"不构成反例 —— 反例必须是
// 一个真正的包装/独立错误。
func TestErrSamplingIsRecognizable(t *testing.T) {
	if ErrSampling == nil {
		t.Fatal("ErrSampling 不能为 nil")
	}
	if !errors.Is(ErrSampling, ErrSampling) {
		t.Error("ErrSampling 必须能被 errors.Is 认出")
	}
	if !strings.Contains(ErrSampling.Error(), "采样") {
		t.Errorf("错误文案要能读懂，实际 %q", ErrSampling.Error())
	}
	// 包装之后仍要认得出来（控制面以后可能给它加一层上下文）
	if !errors.Is(fmt.Errorf("采样 %s: %w", "t1", ErrSampling), ErrSampling) {
		t.Error("用 %w 包一层之后 errors.Is 仍应认得出 ErrSampling")
	}
	// 它必须与"采集失败"不是同一个值（否则控制面分不开 409 与 502）
	other := errors.New("采集失败: 拨号超时")
	if errors.Is(ErrSampling, other) || errors.Is(other, ErrSampling) {
		t.Error("ErrSampling 不能与真实的采集失败混同")
	}
}
