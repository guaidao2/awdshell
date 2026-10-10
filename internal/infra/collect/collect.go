// Package collect 负责从目标主机采集系统指标（只读，走 ssh exec 通道）。
package collect

import (
	"strconv"
	"strings"
)

// Script 是一次采样执行的脚本：尽量少的往返，尽量只读 /proc 与基础命令。
// 分段标记 @@NAME 用于解析；缺失的命令用 2>/dev/null 兜住，解析端做容错。
const Script = `LC_ALL=C
echo "@@STAT"
grep '^cpu' /proc/stat 2>/dev/null
echo "@@MEM"
head -n 8 /proc/meminfo 2>/dev/null
echo "@@LOAD"
cat /proc/loadavg 2>/dev/null
echo "@@UPTIME"
cat /proc/uptime 2>/dev/null
echo "@@DF"
df -P -B1 2>/dev/null | tail -n +2 | head -n 16
echo "@@NET"
cat /proc/net/dev 2>/dev/null
echo "@@PS"
ps -eo pid,ppid,user,pcpu,pmem,rss,stat,comm,args --sort=-pcpu 2>/dev/null | head -n 51
echo "@@OSINFO"
grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release 2>/dev/null | head -n 2
echo "@@KERNEL"
uname -sr 2>/dev/null
echo "@@TZ"
date +%Z 2>/dev/null
echo "@@PROCCOUNT"
ps -e --no-headers 2>/dev/null | wc -l | tr -d " "
echo "@@CONN"
(ss -tnpH 2>/dev/null || netstat -tn 2>/dev/null) | head -n 120
echo "@@SS"
(ss -H -tunlp 2>/dev/null || netstat -tunlp 2>/dev/null) | head -n 40
echo "@@END"`

// CPUTimes 是 /proc/stat 第一行里的累计时间片。
type CPUTimes struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

// Total 返回总时间片。
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// IdleAll 返回空闲时间片（idle + iowait）。
func (c CPUTimes) IdleAll() uint64 { return c.Idle + c.IOWait }

// DiskUsage 单个挂载点。
type DiskUsage struct {
	Device  string  `json:"device"`
	Mount   string  `json:"mount"`
	Total   uint64  `json:"total"`
	Used    uint64  `json:"used"`
	Avail   uint64  `json:"avail"`
	Percent float64 `json:"percent"`
}

// NetIface 网卡累计字节。
type NetIface struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// ProcInfo 进程信息。
type ProcInfo struct {
	PID   int     `json:"pid"`
	PPID  int     `json:"ppid"`
	User  string  `json:"user"`
	CPU   float64 `json:"cpu"`
	Mem   float64 `json:"mem"`
	RSSKB uint64  `json:"rss_kb"`
	State string  `json:"state"`
	Comm  string  `json:"comm"`
	Args  string  `json:"args"`
}

// Conn 是一条网络连接（本端、对端、状态与进程）。
type Conn struct {
	State   string `json:"state"`
	Local   string `json:"local"`
	LPort   int    `json:"lport"`
	Remote  string `json:"remote"`
	RPort   int    `json:"rport"`
	Process string `json:"process"`
}

// Listener 监听端口。
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Process string `json:"process"`
}

// Snapshot 是一次原始采样的结果。
type Snapshot struct {
	CPU       CPUTimes
	CPUCores  []CPUTimes
	Mem       map[string]uint64 // MemTotal / MemAvailable / MemFree / SwapTotal / SwapFree 等（单位 KB）
	Load1     float64
	Load5     float64
	Load15    float64
	UptimeSec float64
	Disks     []DiskUsage
	Net       []NetIface
	Procs     []ProcInfo
	ProcTotal int
	Conns     []Conn
	Listeners []Listener
	OSName    string
	Kernel    string
	TimeZone  string
}

// Parse 解析采集脚本的输出。
func Parse(out string) Snapshot {
	s := Snapshot{Mem: map[string]uint64{}}
	sections := splitSections(out)

	if v, ok := sections["STAT"]; ok {
		s.CPU, s.CPUCores = parseCPUList(v)
	}
	if v, ok := sections["MEM"]; ok {
		s.Mem = parseMeminfo(v)
	}
	if v, ok := sections["LOAD"]; ok {
		s.Load1, s.Load5, s.Load15 = parseLoad(v)
	}
	if v, ok := sections["UPTIME"]; ok {
		s.UptimeSec = parseUptime(v)
	}
	if v, ok := sections["DF"]; ok {
		s.Disks = parseDF(v)
	}
	if v, ok := sections["NET"]; ok {
		s.Net = parseNetDev(v)
	}
	if v, ok := sections["PS"]; ok {
		s.Procs = parsePS(v)
	}
	if v, ok := sections["CONN"]; ok {
		s.Conns = parseConns(v)
	}
	if v, ok := sections["SS"]; ok {
		s.Listeners = parseListeners(v)
	}
	if v, ok := sections["OSINFO"]; ok {
		for _, line := range strings.Split(v, "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				s.OSName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}
	if v, ok := sections["KERNEL"]; ok {
		s.Kernel = strings.TrimSpace(v)
	}
	if v, ok := sections["TZ"]; ok {
		s.TimeZone = strings.TrimSpace(v)
	}
	if v, ok := sections["PROCCOUNT"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			s.ProcTotal = n
		}
	}
	return s
}

// splitSections 把 @@NAME 分段切开。
func splitSections(out string) map[string]string {
	res := map[string]string{}
	cur := ""
	var buf []string
	flush := func() {
		if cur != "" {
			res[cur] = strings.Join(buf, "\n")
		}
		buf = buf[:0]
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "@@") {
			flush()
			cur = strings.TrimSpace(strings.TrimPrefix(line, "@@"))
			continue
		}
		buf = append(buf, line)
	}
	flush()
	return res
}

// parseCPUList 解析 /proc/stat 里的 "cpu" 与 "cpuN" 行，第一项是总体，其余是分核。
func parseCPUList(v string) (CPUTimes, []CPUTimes) {
	var total CPUTimes
	var cores []CPUTimes
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "cpu") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ct := parseStatFields(fields)
		if fields[0] == "cpu" {
			total = ct
		} else {
			cores = append(cores, ct)
		}
	}
	return total, cores
}

// parseStat 解析单行 "cpu  user nice system idle iowait irq softirq steal"。
func parseStat(v string) CPUTimes {
	line := strings.TrimSpace(v)
	if line == "" {
		return CPUTimes{}
	}
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return CPUTimes{}
	}
	return parseStatFields(fields)
}

// parseStatFields 从已经切好的字段里取时间片。
func parseStatFields(fields []string) CPUTimes {
	var c CPUTimes
	num := func(i int) uint64 {
		if i >= len(fields) {
			return 0
		}
		n, _ := strconv.ParseUint(fields[i], 10, 64)
		return n
	}
	c.User = num(1)
	c.Nice = num(2)
	c.System = num(3)
	c.Idle = num(4)
	c.IOWait = num(5)
	c.IRQ = num(6)
	c.SoftIRQ = num(7)
	c.Steal = num(8)
	return c
}

// parseMeminfo 解析 /proc/meminfo 的 "Key:  value kB"。
func parseMeminfo(v string) map[string]uint64 {
	m := map[string]uint64{}
	for _, line := range strings.Split(v, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		m[key] = n
	}
	return m
}

func parseLoad(v string) (float64, float64, float64) {
	fields := strings.Fields(strings.TrimSpace(v))
	get := func(i int) float64 {
		if i >= len(fields) {
			return 0
		}
		f, _ := strconv.ParseFloat(fields[i], 64)
		return f
	}
	return get(0), get(1), get(2)
}

func parseUptime(v string) float64 {
	fields := strings.Fields(strings.TrimSpace(v))
	if len(fields) == 0 {
		return 0
	}
	f, _ := strconv.ParseFloat(fields[0], 64)
	return f
}

// parseDF 解析 df -P -B1 输出。
func parseDF(v string) []DiskUsage {
	out := []DiskUsage{}
	for _, line := range strings.Split(v, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		total, err1 := strconv.ParseUint(fields[1], 10, 64)
		used, err2 := strconv.ParseUint(fields[2], 10, 64)
		avail, err3 := strconv.ParseUint(fields[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		pct := 0.0
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		out = append(out, DiskUsage{
			Device:  fields[0],
			Total:   total,
			Used:    used,
			Avail:   avail,
			Percent: pct,
			Mount:   fields[len(fields)-1],
		})
	}
	return out
}

// parseNetDev 解析 /proc/net/dev。
func parseNetDev(v string) []NetIface {
	out := []NetIface{}
	for _, line := range strings.Split(v, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name == "" || strings.Contains(name, "|") {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		out = append(out, NetIface{Name: name, RxBytes: rx, TxBytes: tx})
	}
	return out
}

// parsePS 解析 ps 输出（pid ppid user pcpu pmem rss stat comm args）。
func parsePS(v string) []ProcInfo {
	out := []ProcInfo{}
	lines := strings.Split(v, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		cpu, _ := strconv.ParseFloat(fields[3], 64)
		mem, _ := strconv.ParseFloat(fields[4], 64)
		rss, _ := strconv.ParseUint(fields[5], 10, 64)
		comm := fields[7]
		args := strings.Join(fields[8:], " ")
		if args == "" {
			args = comm
		}
		out = append(out, ProcInfo{
			PID: pid, PPID: ppid, User: fields[2],
			CPU: cpu, Mem: mem, RSSKB: rss,
			State: fields[6], Comm: comm, Args: args,
		})
	}
	return out
}

// parseConns 解析 ss -tnpH 输出：
//
//	ESTAB 0 0 10.0.0.5:22 10.0.0.1:54321 users:(("sshd",pid=123,fd=3))
//
// netstat -tn 的输出列序不同，这里按"能找到两段地址"来兜底。
func parseConns(v string) []Conn {
	out := []Conn{}
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		state := fields[0]
		// ss 不带 -H 时第一列是 State；netstat 第一列是 Proto，
		// 形态为 Proto Recv-Q Send-Q Local Foreign State，取 State 至少要 6 列。
		if strings.HasPrefix(strings.ToLower(state), "tcp") || strings.HasPrefix(strings.ToLower(state), "udp") {
			if len(fields) < 6 {
				continue
			}
			state = fields[5]
			fields = fields[1:]
		}

		// 从第 3 列往后找第一段带端口的地址，它后面那一列就是对端
		localIdx := -1
		for i := 3; i < len(fields); i++ {
			if strings.Contains(fields[i], ":") {
				localIdx = i
				break
			}
		}
		if localIdx < 0 || localIdx+1 >= len(fields) {
			continue
		}
		remoteIdx := localIdx + 1

		laddr, lport := splitAddrPort(fields[localIdx])
		raddr, rport := splitAddrPort(fields[remoteIdx])
		if lport == 0 && rport == 0 {
			continue
		}

		proc := ""
		if i := strings.Index(line, "((\""); i >= 0 {
			rest := line[i+3:]
			if j := strings.Index(rest, "\""); j > 0 {
				proc = rest[:j]
			}
		} else if strings.HasPrefix(strings.ToLower(state), "tcp") {
			// netstat 形态没有进程信息
			proc = ""
		}

		out = append(out, Conn{
			State: state, Local: laddr, LPort: lport,
			Remote: raddr, RPort: rport, Process: proc,
		})
	}
	return out
}

// parseListeners 解析 ss -tunlp / netstat -tunlp 输出（尽力而为）。
func parseListeners(v string) []Listener {
	out := []Listener{}
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "Active") ||
			strings.HasPrefix(line, "Proto") {
			continue
		}
		fields := strings.Fields(line)
		// ss 至少要 Netid State Recv-Q Send-Q Local 五列。
		// 之前只判了 < 4，老 iproute2 或容器里的精简输出给到 4 列时
		// 下面取 fields[4] 会越界 panic —— 而 handler 里没人 recover，
		// 一次采样就能把整个程序带走。
		if len(fields) < 5 {
			continue
		}

		var proto, local, proc string
		if strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp") {
			// ss 格式：Netid State Recv-Q Send-Q Local Peer Process
			proto = fields[0]
			local = fields[4]
			if len(fields) > 6 {
				proc = strings.Join(fields[6:], " ")
			}
		} else {
			continue
		}

		addr, port := splitAddrPort(local)
		if port == 0 {
			continue
		}
		out = append(out, Listener{Proto: proto, Addr: addr, Port: port, Process: trimProc(proc)})
	}
	return out
}

func splitAddrPort(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, 0
	}
	port, _ := strconv.Atoi(s[idx+1:])
	addr := strings.Trim(s[:idx], "[]")
	return addr, port
}

// trimProc 从 `users:(("nginx",pid=123,fd=6))` 里取进程名。
func trimProc(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "((\""); i >= 0 {
		rest := s[i+3:]
		if j := strings.Index(rest, "\""); j > 0 {
			return rest[:j]
		}
	}
	return ""
}
