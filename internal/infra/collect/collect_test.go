package collect

import "testing"

// 这一组测试守的是"解析目标机输出时不许 panic"。
//
// 背景：parseListeners 与 parseConns 都曾因为列数守卫不足而越界。
// panic 发生在 HTTP handler 的 goroutine 里，http.Server 不会 recover，
// 一次采样就能把整个桌面进程（连同所有活跃终端会话）带走 —— 所以这里
// 用畸形输入把它们钉住。

func TestParseListenersNoPanic(t *testing.T) {
	inputs := []string{
		"",                                        // 空
		"tcp LISTEN 0 128",                        // 4 列：曾经越界（fields[4]）
		"tcp LISTEN 0 128 0.0.0.0:22",             // 5 列，刚好够
		"tcp 0 0 127.0.0.1:22 ESTAB",              // netstat 形态的畸形行
		"udp UNCONN 0 0",                          // 3 列
		"Netid State Recv-Q Send-Q Local",         // 表头
		"Active Internet connections",             // netstat 表头
		"tcp LISTEN abc def 0.0.0.0:22 0.0.0.0:*", // 非数字列
		":::", // 只剩分隔符
	}
	for _, in := range inputs {
		_ = Parse(in) // 不 panic 即通过
	}
}

func TestParseConnsNoPanic(t *testing.T) {
	inputs := []string{
		"",
		"tcp 0 0 127.0.0.1:22 ESTAB", // 5 列：曾经越界（fields[5]）
		"tcp 0 0",                    // 3 列
		"ESTAB 0 0",                  // 3 列
		"tcp 0 0 10.0.0.5:22",        // 缺对端
		"tcp 0 0 10.0.0.5:22 10.0.0.1:1234 ESTAB",
		"Proto Recv-Q Send-Q Local Address Foreign Address State",
	}
	for _, in := range inputs {
		_ = Parse(in) // 不 panic 即通过
	}
}

// TestParseListenersRealOutput 用真实 ss -H -tunlp 输出验证正常解析。
// 注意 Parse 吃的是采集脚本的分段输出，所以要带 @@SS 标记。
func TestParseListenersRealOutput(t *testing.T) {
	out := "@@SS\n" + `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=815,fd=3))
tcp   LISTEN 0      244        127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=900,fd=5))
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*    users:(("dhclient",pid=700,fd=6))
` + "@@END\n"

	res := Parse(out)
	if len(res.Listeners) != 3 {
		t.Fatalf("应解析出 3 个监听项，实际 %d：%+v", len(res.Listeners), res.Listeners)
	}
	if res.Listeners[0].Port != 22 || res.Listeners[0].Process != "sshd" {
		t.Errorf("第一项解析不对：%+v", res.Listeners[0])
	}
	if res.Listeners[1].Addr != "127.0.0.1" || res.Listeners[1].Port != 5432 {
		t.Errorf("第二项解析不对：%+v", res.Listeners[1])
	}
}

// TestParseConnsRealOutput 用真实 ss -tnpH 输出验证正常解析。
func TestParseConnsRealOutput(t *testing.T) {
	out := "@@CONN\n" + `ESTAB 0 0 192.168.44.149:22 192.168.44.1:55014 users:(("sshd-session",pid=1234,fd=4))
ESTAB 0 0 10.0.0.5:44321 10.0.0.9:443 users:(("nginx",pid=500,fd=12))
` + "@@END\n"

	res := Parse(out)
	if len(res.Conns) != 2 {
		t.Fatalf("应解析出 2 条连接，实际 %d：%+v", len(res.Conns), res.Conns)
	}
	if res.Conns[0].Remote != "192.168.44.1" || res.Conns[0].RPort != 55014 {
		t.Errorf("第一条第对端解析不对：%+v", res.Conns[0])
	}
	if res.Conns[0].Process != "sshd-session" {
		t.Errorf("进程名解析不对：%q", res.Conns[0].Process)
	}
	if res.Conns[1].LPort != 44321 || res.Conns[1].RPort != 443 {
		t.Errorf("第二条第端口解析不对：%+v", res.Conns[1])
	}
}

// TestParseCPUCores 分核解析：第一行是总体，其余是分核。
func TestParseCPUCores(t *testing.T) {
	out := `cpu  100 0 50 1000 20 0 5 0 0 0
cpu0 50 0 25 500 10 0 2 0 0 0
cpu1 50 0 25 500 10 0 3 0 0 0`

	total, cores := parseCPUList(out)
	if total.Total() == 0 {
		t.Error("总体时间片没解析出来")
	}
	if len(cores) != 2 {
		t.Fatalf("应解析出 2 个核心，实际 %d", len(cores))
	}
	if cores[0].IdleAll() != 510 {
		t.Errorf("cpu0 的空闲时间片应为 510，实际 %d", cores[0].IdleAll())
	}
}
