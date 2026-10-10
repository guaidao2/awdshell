package logscan

import (
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// 这组测试固化审计里 logscan 包那几条修复，断言都写成"改回错误版本会红"。

// ---------- 低9：未实现名字的注册表必须有锁 ----------

// ChainFromNames / LoadRules 都是导出函数，可能被并发调用（-web 模式下两个请求
// 同时加载规则集，或规则重载与扫描并行）。修复前它们直接往包级 map 里写：
// **并发写 map 是运行时 fatal error**（不是数据错乱那么轻），跑 -race 也会直接报。
// 以前唯一调用方在 sync.Once 里，属于侥幸没炸。
//
// 未实现名字是**进程级注册表**，测试往里写会污染别的用例（loader_test 会断言
// "没有未实现的变换/算子"），所以这里用 t.Cleanup 把它还原成运行前的样子。
func TestUnknownRegistryIsConcurrencySafe(t *testing.T) {
	// 保存/还原全局注册表，别把测试污染带出去
	unknownMu.Lock()
	prevTransforms := make(map[string]bool, len(UnknownTransforms))
	for k, v := range UnknownTransforms {
		prevTransforms[k] = v
	}
	prevOperators := make(map[string]bool, len(unknownOperators))
	for k, v := range unknownOperators {
		prevOperators[k] = v
	}
	unknownMu.Unlock()
	t.Cleanup(func() {
		unknownMu.Lock()
		UnknownTransforms = prevTransforms
		unknownOperators = prevOperators
		unknownMu.Unlock()
	})

	const goroutines = 16
	const rounds = 64
	const fakeTransform = "transformThatDoesNotExistForConcurrencyTest"
	const fakeOperator = "operatorThatDoesNotExistForConcurrencyTest"

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				// 全是本版本没有的名字 → 每次都会写注册表
				ChainFromNames([]string{fakeTransform, "urlDecode", fakeTransform})
				LoadRules([]byte(fakeNameRuleYAML), "concurrency.yaml")
				// 读快照与写交替进行，覆盖"并发读 + 并发写"
				_ = unknownTransformNames()
				_ = unknownOperatorNames()
			}
		}()
	}
	wg.Wait()

	// 注册过程本身不能把已经记下的名字丢掉
	names := map[string]bool{}
	for _, n := range unknownTransformNames() {
		names[n] = true
	}
	if !names[fakeTransform] {
		t.Error("未知变换名没有被记进注册表（只是加了锁，别把记录也丢了）")
	}
	ops := map[string]bool{}
	for _, n := range unknownOperatorNames() {
		ops[n] = true
	}
	if !ops[fakeOperator] {
		t.Error("未知算子名没有被记进注册表")
	}
}

// fakeNameRuleYAML 是一条带未知 transforms 与未知算子的规则。
const fakeNameRuleYAML = `
rules:
  - id: TEST-UNKNOWN
    message: 未知名字
    severity: low
    category: test
    transforms:
      - transformThatDoesNotExistForConcurrencyTest
    operator:
      name: operatorThatDoesNotExistForConcurrencyTest
      params:
        pattern: "x"
`

// ---------- 低10：截断必须按 rune 切 ----------

// 按字节切会把中文日志断在半个字上：返回非法 UTF-8，界面显示乱码，
// 而且它会被写进 scan_events 再被 json.Marshal 转义成一串 \ufffd，证据行就废了。
func TestTruncateKeepsRuneBoundaries(t *testing.T) {
	// 每个汉字 3 字节：4 个字 = 12 字节。n=10 会落在第 4 个字的中间。
	line := "这是一条中文日志"
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 10, 11, 13, 20} {
		got := truncate(line, n)
		if !utf8.ValidString(got) {
			t.Errorf("truncate(%q, %d) = %q 不是合法 UTF-8（按字节切了）", line, n, got)
		}
		if len(got) > n {
			t.Errorf("truncate(%q, %d) 长度 %d 超过上限", line, n, len(got))
		}
		if n < len(line) && !strings.HasPrefix(line, strings.TrimSuffix(got, "...")) {
			t.Errorf("truncate(%q, %d) = %q 不是原文前缀", line, n, got)
		}
	}

	// 短文本原样返回
	if got := truncate("短", 100); got != "短" {
		t.Errorf("不需要截断时应当原样返回，得到 %q", got)
	}
	// 英文的既有行为不能变（每行 300/500/160 字节的截断口径）
	if got := truncate("abcdefghij", 5); got != "ab..." {
		t.Errorf("ASCII 截断行为变了：得到 %q，期望 \"ab...\"", got)
	}
	// 极端 n：不能崩、也不能越界
	for _, n := range []int{0, -1, 1, 2} {
		got := truncate(line, n)
		if !utf8.ValidString(got) {
			t.Errorf("truncate(_, %d) = %q 不是合法 UTF-8", n, got)
		}
		if n >= 0 && len(got) > n {
			t.Errorf("truncate(_, %d) 长度 %d 超过上限", n, len(got))
		}
	}
}

// 端到端：中文日志行被截断后，证据行仍要是合法 UTF-8（会进库、进 JSON）。
func TestScanTruncatesChineseLineSafely(t *testing.T) {
	// 造一条足够长、且命中规则的中文日志行
	long := strings.Repeat("中文日志内容", 200) + " union select 1 from users"
	res := Scan(long, "/var/log/auth.log", AllRules())
	if len(res.Hits) == 0 {
		t.Fatal("测试前提不成立：这行应当命中 SQL 注入规则")
	}
	for _, ev := range res.Hits {
		if !utf8.ValidString(ev.Line) {
			t.Errorf("证据行不是合法 UTF-8：%q", ev.Line)
		}
		if len(ev.Line) > 500 {
			t.Errorf("证据行长度 %d 超过 500 字节上限", len(ev.Line))
		}
	}
}
