// Package collect 负责从目标主机采集系统指标（只读，走 ssh exec 通道）。
package collect

import (
	"fmt"
	"strconv"
	"strings"
)

// Script 是一次采样执行的脚本：尽量少的往返，尽量只读 /proc 与基础命令。
//
// 每段带一个状态标记，把**三件不同的事**分开表达（以前只有两件，"假的 0"就是从
// 这里漏出去的）：
//
//	@@OK     命令跑通了，而且**真的有输出**
//	@@EMPTY  命令跑通了，但输出就是空的（ss 确实 0 条监听、这台机器真的没进程）
//	@@NO     命令不存在 / 无条件不成立（精简镜像没有 ss、BusyBox 不认 ps -e）
//	          —— **解析端遇到它可以直接报错**（"连命令都没有，还解析什么"）
//
// 为什么必须分开：精简镜像 / BusyBox 上 `ps --sort`、`df -B1`、`ss` 这些可能根本
// 不存在，而 `2>/dev/null` 会把"命令不存在"和"确实没有数据"一起吞掉 —— 两者都
// 表现成一片空白。更糟的是第三种：`ps -e --no-headers 2>/dev/null | wc -l` 在
// BusyBox 上命令失败、stdout 空，`wc -l` 照样输出 `0`，于是解析端拿到一个
// **看起来完全正常的 0**（界面上写"0 个进程"），而它其实只是命令没跑通。
// 缺失的段由 ParseDetailed 汇总成 Missing，调用方据此标注"未采集到"。
const Script = `LC_ALL=C
echo "@@STAT"
grep '^cpu' /proc/stat 2>/dev/null
echo "@@MEM"
grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null
echo "@@LOAD"
cat /proc/loadavg 2>/dev/null
echo "@@UPTIME"
cat /proc/uptime 2>/dev/null
echo "@@DF"
# -P 保证一行一个文件系统（长设备名不会被折行），-B1 要 GNU coreutils。
# 以前是 df -P -B1 | head -n 16：去掉表头只剩 15 个挂载点，容器 / 多分区机器上
# 尾部挂载点会被静默丢掉。这里放宽到 64 行，同时**保留表头**（-P 的表头是固定的
# 6 列，解析端要靠它把"挂载点"和后面附带的说明行区分开）。
# 判据分三层：命令在不在（command -v）→ 有没有数据（grep -q .）→ 都没有就 @@NO。
# **不能只看 df -P -B1 的退出码**：那只能证明命令存在，不能证明解析端
# 拿得到数据；也不能只看有没有数据 —— 命令不存在时数据同样是空，会被误标 @@EMPTY。
if command -v df >/dev/null 2>&1; then
  if df -P -B1 2>/dev/null | head -n 64 | grep -q .; then
    echo "@@OK"
    df -P -B1 2>/dev/null | head -n 64
  elif df -P 2>/dev/null | head -n 64 | grep -q .; then
    # 退回分支：数据是有的（只是 -B1 不被支持，块大小按 1024 算），必须打 @@OK，
    # 否则界面上会说"未采集到"而用户明明看得见 df 的输出。
    echo "@@OK"
    df -P 2>/dev/null | head -n 64
  else
    echo "@@EMPTY"
  fi
else
  echo "@@NO"
fi
echo "@@NET"
cat /proc/net/dev 2>/dev/null
echo "@@PS"
# ps 的列选择与排序在 BusyBox 上不成立（没有 -eo/--sort）；标记出来让解析端
# 知道"工具缺失"而不是"没有进程"。
if command -v ps >/dev/null 2>&1; then
  if ps -eo pid,ppid,user,pcpu,pmem,rss,stat,comm,args --sort=-pcpu >/dev/null 2>&1; then
    echo "@@OK"
    ps -eo pid,ppid,user,pcpu,pmem,rss,stat,comm,args --sort=-pcpu 2>/dev/null | head -n 51
  else
    # 退回 BusyBox 风格的 ps：它没有 -o，列也不一样，解析端基本挑不出行，
    # 但至少把"真的有一份进程列表"留在输出里（配合 @@NO，界面上仍会说这段没采到，
    # 因为 PPID/CPU 这些列拿不到）。解析端另有"标了 @@OK 却解析不出东西"的兜底核对。
    echo "@@NO"
    ps 2>/dev/null | head -n 51
  fi
else
  echo "@@NO"
fi
echo "@@OSINFO"
grep -E "^(PRETTY_NAME|VERSION_ID)=" /etc/os-release 2>/dev/null | head -n 2
echo "@@KERNEL"
uname -sr 2>/dev/null
echo "@@TZ"
date +%Z 2>/dev/null
echo "@@PROCCOUNT"
# **不能只用 command -v ps 当判据**：BusyBox 上 ps 存在，但
# ps -e --no-headers 会失败、stdout 空，而 wc -l 照样输出 0 —— 解析端于是拿到
# 一个"成功的 0"，界面上写"0 个进程"。这里必须**先确认命令真跑出东西**再打 @@OK：
# 用 grep -c . 数非空行，0 就是不认（判据与 df 那段一致）。
if command -v ps >/dev/null 2>&1; then
  n=$(ps -e --no-headers 2>/dev/null | grep -c .)
  if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
    echo "@@OK"
    echo "$n"
  else
    n=$(ps -e 2>/dev/null | grep -c .)
    if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
      # 退回 ps -e（含表头）：行数会多算 1，但比一个假的 0 强
      echo "@@OK"
      echo "$n"
    else
      echo "@@EMPTY"
    fi
  fi
else
  echo "@@NO"
fi
echo "@@CONN"
# ss 优先，BusyBox 上没有就用 netstat；两个都没有时 @@NO 让界面说实话。
# 顺序是"命令在不在"→"有没有数据"：ss 在但权限不足（拿不到进程信息）时同样可能
# 输出为空，那种情况要退回 netstat，而不是报"未采集到"。
if command -v ss >/dev/null 2>&1; then
  if ss -tnpH 2>/dev/null | head -n 120 | grep -q .; then
    echo "@@OK"
    ss -tnpH 2>/dev/null | head -n 120
  elif command -v netstat >/dev/null 2>&1 && netstat -tn 2>/dev/null | head -n 120 | grep -q .; then
    echo "@@OK"
    netstat -tn 2>/dev/null | head -n 120
  else
    echo "@@EMPTY"
  fi
elif command -v netstat >/dev/null 2>&1; then
  if netstat -tn 2>/dev/null | head -n 120 | grep -q .; then
    echo "@@OK"
    netstat -tn 2>/dev/null | head -n 120
  else
    echo "@@EMPTY"
  fi
else
  echo "@@NO"
fi
echo "@@SS"
# 同上。**@@EMPTY 是这里的重点**：ss 正常执行、确实一条监听都没有时（比如刚装好的
# 容器里 sshd 还没起），以前会被判成"未采集到：SS"，把"真的是空"误报成"没采到"。
if command -v ss >/dev/null 2>&1; then
  if ss -H -tunlp 2>/dev/null | head -n 40 | grep -q .; then
    echo "@@OK"
    ss -H -tunlp 2>/dev/null | head -n 40
  elif command -v netstat >/dev/null 2>&1 && netstat -tunlp 2>/dev/null | head -n 40 | grep -q .; then
    echo "@@OK"
    netstat -tunlp 2>/dev/null | head -n 40
  else
    echo "@@EMPTY"
  fi
elif command -v netstat >/dev/null 2>&1; then
  if netstat -tunlp 2>/dev/null | head -n 40 | grep -q .; then
    echo "@@OK"
    netstat -tunlp 2>/dev/null | head -n 40
  else
    echo "@@EMPTY"
  fi
else
  echo "@@NO"
fi
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
	// ProcTotalValid 表示 ProcTotal 是**真的数出来的**。
	//
	// 为什么单独给一个标志：ProcTotal 是 int，而 0 在这件事上有两种完全不同的
	// 含义 —— "这台机器一个进程都没有"（几乎不可能）与"没数出来"。BusyBox 上
	// `ps -e --no-headers` 失败、`wc -l` 照样给 0，只靠数字分不开这两者，
	// 界面就会把一个假的 0 画成"0 个进程"。调用方应当在这个标志为 false 时
	// 显示"未采集到"，而不是显示 0。
	ProcTotalValid bool
	Conns          []Conn
	Listeners      []Listener
	OSName         string
	Kernel         string
	TimeZone       string

	// Collected 表示关键段（/proc/stat 的 CPU 与 /proc/meminfo 的内存）确实采到了。
	//
	// 为什么单独给一个字段：以前 Parse 对空输出也返回一个全零 Snapshot 且不报错，
	// 调用方分不清"没采到"和"真的是 0" —— 界面上会把一台没采集成功的机器画成
	// CPU 0% / 内存 0%，看起来像正常空闲。现在为空时 Collected=false。
	Collected bool `json:"collected"`
	// Missing 是采集脚本报"命令不存在 / 没拿到数据"的段名（见 Script 里的
	// @@OK / @@EMPTY / @@NO），例如精简镜像上没有 ss、BusyBox 上没有 ps --sort。
	Missing []string `json:"missing,omitempty"`
	// Problems 是"脚本说采到了、但解析端没能从中提出东西"的说明（人话，给界面提示用）。
	//
	// 为什么不并进 Missing：Missing 的语义是"这一段没采到"，而这些段落**采到了**，
	// 只是格式不被认识（老 iproute2、定制过的 BusyBox 等）。把它们混在一起会让
	// "没采到"这个判断失去意义；但也不能什么都不说 —— 那正是"界面画成空表、
	// 用户以为机器上真的什么都没有"的来源。
	Problems []string `json:"problems,omitempty"`
}

// criticalSections 是"没采到就没法算指标"的段：CPU 与内存合计。
// 只认这两段，是因为总 CPU 占用与内存占用全靠它们，缺了界面上的百分比就是假的。
var criticalSections = []string{"STAT", "MEM"}

// optionalSections 是"有更好、没有也不影响核心指标"的段。
// 它们的缺失会被记进 Snapshot.Missing，由调用方决定是否提示（例如精简镜像
// 没有 ss，排查外联时该提示"监听/连接列表未采集到"而不是画一张空表）。
var optionalSections = []string{"DF", "PS", "CONN", "SS", "NET", "OSINFO", "KERNEL", "PROCCOUNT"}

// Parse 解析采集脚本的输出，返回采样结果。
//
// **不再静默**：结果里带 Collected（关键段是否采到）与 Missing（缺了哪些段），
// 调用方应当据此后置"未采集到"的状态，而不是把全零当成真实值。
// 这个入口保留给不需要状态判断的调用点（等价于 ParseDetailed 的第一返回值）。
func Parse(out string) Snapshot {
	s, _ := ParseDetailed(out)
	return s
}

// ParseDetailed 解析采集脚本的输出，同时把"哪些段没采到"告诉调用方。
//
// 返回的第二个值是缺失段名（关键段与可选段合并，按 criticalSections /
// optionalSections 的顺序，便于调用方稳定比对）。空输出时两个关键段都缺，
// Collected=false —— 这就是"没采到"与"真的是 0"的分界。
func ParseDetailed(out string) (Snapshot, []string) {
	s := Snapshot{Mem: map[string]uint64{}}
	sections, unknown := splitSections(out)

	// 段名不在白名单里的 @@XXX：数据会（按 splitSections 的设计）并进上一段。
	// 这不是能静默的事 —— 脚本以后新增段名而白名单没同步时，新段的数据会污染前一段
	//（实测 `1.2.3.4 evil` 被并进了 STAT），而界面上完全看不出来。这里记一条。
	for _, name := range unknown {
		s.Problems = append(s.Problems,
			fmt.Sprintf("采集输出里有未知段名 @@%s（不在解析白名单里），它的内容被并入了上一段，可能影响该段解析", name))
	}

	// okSections 记下"脚本说这一段采到了（@@OK）"的名字；后面的核对要用它，
	// 而不是回头去看段体 —— 那时标记已经被 stripMarker 去掉了。
	okSections := map[string]bool{}

	// 命令是否存在由脚本自己标记（@@OK / @@EMPTY / @@NO）：先收一遍声明的缺失段，
	// 再叠加"段根本没出现"与"段是空的"两种情况。
	for _, name := range append(append([]string{}, criticalSections...), optionalSections...) {
		body, present := sections[name]
		if !present {
			s.Missing = append(s.Missing, name)
			continue
		}
		// 先把标记本身从段体里去掉，再判"空不空" —— 段体第一行就是标记，
		// 不去掉的话 `@@EMPTY\n` 的 TrimSpace 结果是 "@@EMPTY"、永远不空。
		//
		// **只有真的是标记才去**：STAT/MEM/LOAD 这些段本来就没有标记，
		// 无条件砍掉第一行会把 `cpu ...` 那一行数据丢掉（实测 Collected 直接变 false）。
		marker := firstMarker(body)
		switch marker {
		case markerYes, markerEmpty, markerNo:
			body = stripMarker(body)
			sections[name] = body
		default:
			marker = ""
		}

		switch marker {
		case markerNo:
			// 命令不在 / 不认这些参数：没采到
			s.Missing = append(s.Missing, name)
			continue
		case markerYes:
			okSections[name] = true
		}
		// 到底什么叫 Missing：**这一段的数据没拿到**。
		//   @@NO     命令不在 —— 没拿到
		//   无标记空段 /proc 读不出来、脚本没跑到 —— 没拿到
		//   @@EMPTY  命令跑通了、就是空的 —— **拿到了，只是确实是空**
		//            （这台机器真的没进程、ss 确实一条监听都没有）
		// 把 @@EMPTY 也塞进 Missing，界面上就会说"未采集到：SS"，
		// 用户于是去查"为什么采不到"，而真相是这台机器上确实没有监听。
		if strings.TrimSpace(body) == "" && marker != markerEmpty {
			s.Missing = append(s.Missing, name)
		}
		// 打了 @@NO 却还带着数据（BusyBox 上没有 -o 的 `ps` 兜底输出）：段体按
		// "没采到"记的是 Missing，段体本身原样保留 —— 解析器对陌生格式本就挑不出行，
		// 与"把这一段当没采到"并不矛盾。这里刻意**不**删段体：那是一处行为变更，
		// 而它救不了什么（下面有 unparsedProblems 会如实提示）。
	}

	// 关键段齐了才算"采到"：只有一段也说明这次采样拿不到完整指标
	s.Collected = true
	for _, name := range criticalSections {
		if contains(s.Missing, name) {
			s.Collected = false
			break
		}
	}

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
		// **只有脚本打了 @@OK（= 命令真跑出东西）才认这个总数**。
		// @@EMPTY / @@NO 时 ProcTotal 保持 0，但 ProcTotalValid=false ——
		// 因为 0 在这里的含义是"不知道"，而不是"零个进程"。
		// 以前 BusyBox 上 `ps -e --no-headers | wc -l` 输出 0、脚本打 @@OK，
		// 界面上就写着"0 个进程"，看起来像一次正常采样。
		if okSections["PROCCOUNT"] {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				s.ProcTotal = n
				s.ProcTotalValid = true
			}
		}
	}

	// **必须放在各个解析器跑完之后**：它要核对"脚本说采到了、解析端到底提出了几条"，
	// 放在前面的话所有列表都还是空的，每一段都会被误报成"格式不认识"。
	s.Problems = append(s.Problems, unparsedProblems(s, okSections)...)

	if len(s.Missing) == 0 {
		s.Missing = nil
	}
	if len(s.Problems) == 0 {
		s.Problems = nil
	}
	return s, s.Missing
}

// unparsedProblems 核对"脚本说采到了"的段是否真的解析出了东西。
//
// 为什么必须回头核一遍：标记只能证明**命令**跑通了，不能证明解析端认得这份输出。
// 老 iproute2 / BusyBox / 定制过的 netstat 都能给出"命令成功、格式陌生"的输出，
// 解析结果为空 —— 而空表在界面上与"这台机器确实没有监听"长得一模一样。
// 这类情况既不能算 Missing（数据是采到了），也不能不吭声（用户会当成真的空）。
// okSections 是脚本打了 @@OK 的段名集合（由 ParseDetailed 收集）。
func unparsedProblems(s Snapshot, okSections map[string]bool) []string {
	type probe struct {
		name  string
		count int
		scale string
	}
	probes := []probe{
		{"DF", len(s.Disks), "挂载点"},
		{"PS", len(s.Procs), "进程"},
		{"CONN", len(s.Conns), "连接"},
		{"SS", len(s.Listeners), "监听"},
	}
	var out []string
	for _, p := range probes {
		if !okSections[p.name] {
			continue
		}
		if p.count == 0 {
			out = append(out, fmt.Sprintf(
				"%s：命令跑通了但一条%s都没解析出来，列表可能是空的（输出格式不认识）", p.name, p.scale))
		}
	}
	return out
}

// 采集脚本里的段标记，三者语义严格区分（见 Script 的说明）：
//
//	@@OK     命令在，而且有输出
//	@@EMPTY  命令在、跑通了，但输出就是空的（"真的是空"，不是"没采到"）
//	@@NO     命令不在 / 不认这些参数（"没采到"）
const (
	markerYes   = "@@OK"
	markerEmpty = "@@EMPTY"
	markerNo    = "@@NO"
)

// firstMarker 取段体第一行的标记（没有标记时返回空串）。
func firstMarker(body string) string {
	line := body
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		line = body[:i]
	}
	return strings.TrimSpace(line)
}

// stripMarker 去掉段体第一行的标记，剩下的才是命令输出。
func stripMarker(body string) string {
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		return body[i+1:]
	}
	return ""
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// sectionNames 是**真正的分段名**白名单。
//
// 为什么必须白名单：段体第一行也会带 @@（@@OK / @@NO 用来标记"命令在不在"），
// 而 splitSections 以前把任何 @@ 开头行都当成新段 ——
// `@@DF\n@@NO\n` 会被切成"空的 DF 段 + 一个名叫 NO 的段"，
// 于是既认不出 DF 缺失，又凭空多出一个垃圾段。
var sectionNames = map[string]bool{
	"STAT": true, "MEM": true, "LOAD": true, "UPTIME": true, "DF": true,
	"NET": true, "PS": true, "OSINFO": true, "KERNEL": true, "TZ": true,
	"PROCCOUNT": true, "CONN": true, "SS": true, "END": true,
}

// splitSections 把 @@NAME 分段切开（只认白名单里的段名）。
//
// 第二个返回值是**白名单外的段名**（按出现顺序、去重）。
//
// 为什么不直接把它们也当段切开：段体第一行还带着 @@OK / @@EMPTY / @@NO 标记，
// 早期实现把任何 @@ 开头行都当新段，于是 `@@DF\n@@NO\n` 被切成"空的 DF 段 +
// 一个名叫 NO 的段"，既认不出 DF 缺失、又凭空多出垃圾段。白名单修掉了这个，
// 但代价是"未来新增的段名"会静默并进上一段 —— 所以这里把它们报出来，
// 由 ParseDetailed 记成 Problems，而不是悄悄吃掉。
func splitSections(out string) (map[string]string, []string) {
	res := map[string]string{}
	var unknown []string
	seen := map[string]bool{}
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
			name := strings.TrimSpace(strings.TrimPrefix(line, "@@"))
			if sectionNames[name] {
				flush()
				cur = name
				continue
			}
			// @@OK / @@EMPTY / @@NO 是状态标记（段体内容），**不是段名**：
			// 把它们当成"未知段名"会凭空冒出一堆假提示。除此之外的 @@XXX
			// 才是"白名单没同步"的信号：内容仍并进当前段（行为与以前一致，
			// 不改变已有解析结果），但要记一条。
			if name != "" && !strings.HasPrefix(name, "@") &&
				name != "OK" && name != "EMPTY" && name != "NO" && !seen[name] {
				seen[name] = true
				unknown = append(unknown, name)
			}
		}
		buf = append(buf, line)
	}
	flush()
	return res, unknown
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

// parseDF 解析 df -P [-B1] 输出。
//
// 为什么不能再用 strings.Fields 取最后一列：`df -P` 的列是固定的
// （Filesystem 1024-blocks Used Available Capacity Mounted on），最后一列是
// **挂载点**，而挂载点可以含空格。实测 `/mnt/my data` 用 Fields 切出来
// 最后一列是 `data`，界面上的挂载点就变成了 data。
// 改法：按列边界切——前 5 列不含空格，第 6 列起（到行尾）整段是挂载点。
func parseDF(v string) []DiskUsage {
	out := []DiskUsage{}
	for _, line := range strings.Split(v, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Fields 只切前 6 段，第 6 段是"挂载点 + 可能的空格"，所以能保住空格。
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		// 表头（Filesystem 1024-blocks ...）与 df 的折行说明行都会被这里滤掉
		total, err1 := strconv.ParseUint(f[1], 10, 64)
		used, err2 := strconv.ParseUint(f[2], 10, 64)
		avail, err3 := strconv.ParseUint(f[3], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}

		// 第 6 列起整段是挂载点。用索引而不是 Join(f[5:], " ")：
		// 后者会把挂载点里的连续空格压成一个，中文/带空格的路径会变形。
		rest := line
		for i := 0; i < 5; i++ {
			idx := strings.IndexFunc(rest, isSpace)
			if idx < 0 {
				break
			}
			rest = strings.TrimLeft(rest[idx:], " \t")
		}
		mount := strings.TrimRight(rest, " \t")
		if mount == "" {
			continue
		}

		pct := 0.0
		if total > 0 {
			pct = float64(used) / float64(total) * 100
		}
		out = append(out, DiskUsage{
			Device:  f[0],
			Total:   total,
			Used:    used,
			Avail:   avail,
			Percent: pct,
			Mount:   mount,
		})
	}
	return out
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' }

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
		start := 3
		if strings.HasPrefix(strings.ToLower(state), "tcp") || strings.HasPrefix(strings.ToLower(state), "udp") {
			if len(fields) < 6 {
				continue
			}
			state = fields[5]
			fields = fields[1:]
			// 切掉 Proto 之后是 Recv-Q Send-Q Local Foreign State，
			// 本地地址在索引 2（以前从 3 开始找，找到的其实是对端 ——
			// 于是 Local 显示成对端、Remote 变成 "ESTABLISHED" 且端口为 0）。
			start = 2
		}

		// 从"本地地址该在的位置"往后找第一段带端口的地址，它后面那一列就是对端
		localIdx := -1
		for i := start; i < len(fields); i++ {
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

// isNumeric 判断一个 token 是不是纯数字（用来区分 ss 与 netstat 的列序）。
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
			proto = fields[0]
			// 两种形态的列序不同：
			//   ss      : Netid State Recv-Q Send-Q Local Peer Process
			//   netstat : Proto Recv-Q Send-Q Local Foreign State [pid/name]
			// 判据：ss 的第二列是状态词（LISTEN/UNCONN…），netstat 的第二列是数字。
			//
			// 以前一律取 fields[4]：netstat 形态下那是对端 `0.0.0.0:*`，
			// 端口解析出来是 0 然后被 continue 掉 —— 监听列表**静默变空**，
			// 排查外联时看到的是一张空表。
			if isNumeric(fields[1]) {
				if len(fields) < 5 {
					continue
				}
				local = fields[3]
			} else {
				local = fields[4]
			}
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
