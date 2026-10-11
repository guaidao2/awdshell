package sshx

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// pingInterval 是两次探活之间的最小间隔。
// 每次 Acquire 都探会白白多加一个 RTT，所以按时间隔开。
//
// 用变量而不是常量，唯一原因是让测试能把间隔压到毫秒级去钉"续用分支不许刷 lastPing"。
var pingInterval = 15 * time.Second

// Pool 按 key 复用 SSH 连接：同一个目标只握手一次，终端/文件/监控共用同一条连接的不同 channel。
type Pool struct {
	mu    sync.Mutex
	conns map[string]*pooled
	idle  time.Duration
	// done 关闭后 reaper 退出；Close/CloseAll 都只关一次。
	done     chan struct{}
	closeOne sync.Once
	// closed 表示这个池已经关停（CloseAll 之后）。**关停之后不再接受任何写入**：
	// reaper 已经退出，之后放进池里的连接既不会被探活也不会被空闲回收，
	// 只会一直挂着直到进程结束。以前只清 map 不设标志，实测 CloseAll 之后
	// Acquire 仍会重新 dial 并插进池里，那些连接永远没人回收。
	closed bool
	// orphans 是"探活失败、已从池里摘出、但还有持有者"的连接。
	//
	// 为什么要单独记：dropIf 在 holders>0 时不能关（那是用户正在敲的终端、
	// 上传中的 SFTP、跑一半的合规），但也不能留在池里（Acquire 会把它当可用
	// 再发出去，而"探活失败"这个事实已经丢了）。摘出之后它既不在 conns 里、
	// 也没人管，只能等持有者释放时关闭 —— 否则这条 TCP 与 x/crypto 的 mux
	// goroutine 就永远漏着（审计实测：DropIf 后、release() 后、CloseAll() 后
	// closed 一直是 0，因为 CloseAll 只遍历 conns）。
	orphans map[*ssh.Client]*orphanConn
}

// orphanConn 是已摘出池、等持有者释放后关闭的连接。
type orphanConn struct {
	client  *ssh.Client
	holders int
}

// ErrPoolClosed 是"连接池已关停"的哨兵错误。
//
// 为什么不返回一个普通错误：调用方（终端、监控、合规、文件）需要能一眼分辨
// "这台机器连不上"与"程序正在退出"，后者不该弹给用户、也不该重试。
var ErrPoolClosed = errors.New("连接池已关停，不再接受新的连接申请")

// Close 停掉后台 reaper（不关连接）。进程级单例下 CloseAll 会顺带调用它，
// 单独写出来是为了让测试等短生命周期用法能干净收尾，不留一个每分钟醒一次的 goroutine。
func (p *Pool) Close() {
	p.closeOne.Do(func() { close(p.done) })
}

type pooled struct {
	client   *ssh.Client
	lastUsed time.Time
	lastPing time.Time
	// pinging 表示这条连接上已经有一次探活"在飞"。
	// x/crypto 的 mux 把 SendRequest 串行化了（全程持 globalSentMu），
	// 并发的第二次探活连请求都发不出去，会在自己的 3 秒里被误判成死连接。
	pinging bool
	// holders 是长连接持有者个数（终端、上传中的 SFTP、长合规核查）。
	// >0 时 reaper 不按空闲回收 —— 用户还在用，与"最近有没有 Acquire"无关。
	holders int
}

// NewPool 创建一个连接池；idle 为回收空闲连接的时间。
func NewPool(idle time.Duration) *Pool {
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	p := &Pool{conns: map[string]*pooled{}, idle: idle, done: make(chan struct{})}
	go p.reaper()
	return p
}

// Alive 用 SSH 的 keepalive 请求探活。
//
// 为什么需要它：连接假死时（对端进程没了但没发 RST，或中间设备悄悄断了会话）
// 套接字看起来还是好的，Acquire 会一直把这条死连接发出去，于是每个操作都要各自
// 等到超时才失败 —— 监控 15 秒、合规单命令 10 秒、日志 25 秒，界面上表现为"什么都慢"。
func Alive(c *ssh.Client) bool {
	if c == nil {
		return false
	}
	// 请求放在一个带缓冲的 channel 上，超时后 goroutine 仍会写进去然后自然结束
	// （缓冲 1，不会阻塞发送）。注意它可能还卡在 x/crypto 的 globalSentMu 上，
	// 那种情况下它会一直挂着 —— 这是"探活超时"的固有代价，不影响连接本身。
	done := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(3 * time.Second):
		return false
	}
}

// Acquire 取一条连接；不存在或已失效时用 dial 新建。
// 调用方在使用失败后应调用 Drop；长连接（终端、上传）请再用 Hold 加一个引用。
func (p *Pool) Acquire(key string, dial func() (*ssh.Client, error)) (*ssh.Client, error) {
	// 最多两轮：第一轮探活发现是死连接就丢掉，第二轮重新握手
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		if p.closed {
			// 关停之后一律拒绝：reaper 已经退出，这时候放进池里的连接
			// 没人探活、没人回收（见 closed 字段的说明）。
			p.mu.Unlock()
			return nil, ErrPoolClosed
		}
		if c, ok := p.conns[key]; ok {
			c.lastUsed = time.Now()
			needPing := time.Since(c.lastPing) > pingInterval && !c.pinging
			if needPing {
				c.pinging = true
				c.lastPing = time.Now()
			}
			client := c.client
			p.mu.Unlock()

			if !needPing {
				// 不需要探活，或已经有一次探活在飞 —— 后者直接当可用：
				// 真坏了的话下一次真实使用会报错，那时再 Drop。
				return client, nil
			}

			alive := Alive(client)

			// 复位 pinging（按身份）
			p.mu.Lock()
			if cur, still := p.conns[key]; still && cur.client == client {
				cur.pinging = false
			}
			p.mu.Unlock()

			// **按 alive 决定，而不是"有没有删掉池条目"**：
			// 探活在锁外做（最长 3 秒），这期间别人可能已经 Drop 掉这条并换上
			// 健康的新连接 —— 那时"池里挂的不是我手里这条"，按旧写法会把我手里
			// 这条**已经探活失败的死连接**返回给调用方（调用方必然失败，随后按
			// 约定 Drop(key) 又会删掉别人新建的那条），而且它已不在池里，
			// reaper 看不到、Hold 也找不到，成了永久泄漏的孤儿连接。
			if alive {
				return client, nil
			}
			// **不能在这里无条件 Close**：dropIf 在 holders>0 时已经把它从池里
			// 摘出（但不关，因为持有者还在用），这里再关一次就把 holders 保护
			// 整个绕过了 —— 日志写着"不主动关闭，避免掐断正在用的终端/SFTP"，
			// 紧接着自己把它关了（审计实测：Hold 住之后 Acquire 一次，closed=1）。
			// 有持有者的那条由 dropIf 记进 orphans，等持有者释放时关闭；
			// 没有持有者的那条 dropIf 已经关掉了。
			p.dropIf(key, client)
			continue // 下一轮重新握手
		}
		p.mu.Unlock()

		client, err := dial()
		if err != nil {
			return nil, err
		}

		p.mu.Lock()
		if p.closed {
			// dial 的这几秒里池被关停了（程序退出路径）：这条刚建好的连接
			// 不能放进池里，也没人会用，直接关掉并如实报错。
			p.mu.Unlock()
			_ = client.Close()
			return nil, ErrPoolClosed
		}
		if old, ok := p.conns[key]; ok { // 并发下可能已被别的调用放进去了
			// 只刷 lastUsed：这条"别人刚放进来的"连接**没被探活过**，
			// 刷 lastPing 等于把它伪装成刚验活 —— 真死的话要再等一个
			// pingInterval（15 秒）才会被发现，而这段时间里每个操作都要
			// 各自等到超时（监控 15s / 合规 10s / 日志 25s），
			// 界面上表现成"什么都慢"。让它按原计划被探活。
			old.lastUsed = time.Now()
			existing := old.client
			p.mu.Unlock()
			_ = client.Close()
			return existing, nil
		}
		now := time.Now()
		p.conns[key] = &pooled{client: client, lastUsed: now, lastPing: now}
		p.mu.Unlock()
		return client, nil
	}
	return nil, fmt.Errorf("连接 %s 反复失效，请检查网络连通性或凭据", key)
}

// Hold 给某条连接加一个"长连接引用"，返回幂等的释放函数。
//
// 引用计数 > 0 时 reaper 不按空闲回收这条连接，DropIf 也不会把它从池里摘掉
// （见 dropIf 的说明：有人正持有的连接不能被当成"坏连接"随手关掉）。
// 池已关停（CloseAll 之后）时它是个空操作 —— 那时连接已经不归池管了。
//
// 为什么需要：reaper 只看 lastUsed，
// 而终端 I/O 走 Terminal、**完全不碰池** —— 于是"只开终端"（或窗口最小化、
// 或长时间不敲键）时 lastUsed 停在开终端那一刻，reaper 会在最后一次 Acquire 后
// 5~6 分钟把连接关掉，用户正在敲的终端突然断。上传中的 SFTP、一轮 60+ 项的
// 合规核查是同一类。
func (p *Pool) Hold(client *ssh.Client) func() {
	if client == nil {
		return func() {}
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return func() {}
	}
	held := false
	for _, c := range p.conns {
		if c.client == client {
			c.holders++
			held = true
			break
		}
	}
	// 已经在 orphan 里的（探活失败被摘出、持有者还没放完）也要计数，
	// 否则 release 时计数对不上，那条连接永远不会被关。
	if !held {
		if o, ok := p.orphans[client]; ok {
			o.holders++
		}
	}
	p.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			var toClose *ssh.Client
			p.mu.Lock()
			found := false
			for _, c := range p.conns {
				if c.client == client {
					if c.holders > 0 {
						c.holders--
					}
					found = true
					break
				}
			}
			// 不在池里：它可能已被 dropIf 摘成 orphan（探活失败、但当时还有持有者，
			// 所以没关）。计数一旦归零就关掉 —— 否则这条 TCP 和 x/crypto 的 mux
			// goroutine 永远漏着：它不在 conns 里，CloseAll 也遍历不到。
			if !found {
				if o, ok := p.orphans[client]; ok {
					if o.holders > 0 {
						o.holders--
					}
					if o.holders == 0 {
						delete(p.orphans, client)
						toClose = client
					}
				}
			}
			p.mu.Unlock()
			if toClose != nil {
				_ = toClose.Close()
			}
		})
	}
}

// Drop 丢弃某个 key 的连接（使用中出错时调用，下次会重新握手）。
//
// 注意：它删的是"此刻挂在 key 上的那条"，不一定是调用方手里那条。
// 探活失败这类**锁外**判断请用 dropIf。
//
// 有活跃持有者（终端/SFTP/长核查）时它同样会关闭连接 —— 所以服务层应当优先用
// DropIf；这里保留 Drop 只是为了"确定没有并发者"的少数调用点。
func (p *Pool) Drop(key string) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	c, ok := p.conns[key]
	delete(p.conns, key)
	p.mu.Unlock()
	if ok {
		_ = c.client.Close()
	}
}

// DropIf 是 dropIf 的导出形式，供服务层在"拿到 client 之后、几分钟后才失败"的
// 场景里按身份摘连接 —— 那些场景里 key 可能早被换人，直接 Drop(key) 会删掉
// 别人新建的连接（终端当场断）。
func (p *Pool) DropIf(key string, client *ssh.Client) { p.dropIf(key, client) }

// Preload 往池里放一条连接（**只给测试用**）。
//
// 为什么需要它：服务层（合规核查、监控、文件）都是从池里 Acquire 的，
// 要给它们做不连远程主机的单元测试，就得先有办法把一条假 client 放进池里 ——
// 否则每个测试都只能靠 dial 真去连一台机器。生产代码不要调用它：
// 连接的生命周期必须由 Acquire/Drop/CloseAll 管。
func (p *Pool) Preload(key string, client *ssh.Client) {
	now := time.Now()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.conns[key] = &pooled{client: client, lastUsed: now, lastPing: now}
	p.mu.Unlock()
}

// HasClient 报"这条 client 此刻是否挂在 key 上"（**只给测试用**，见 Preload）。
func (p *Pool) HasClient(key string, client *ssh.Client) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.conns[key]
	return ok && c.client == client
}

// dropIf 只在"此刻池里挂的仍是这条 client"时才摘掉它。
//
// 为什么不能直接 Drop(key)：探活在锁外做（最长 3 秒），这期间另一条路径可能
// 已经摘掉旧连接、重新握手出健康的新连接放进同一个 key。这时按 key 删，
// 删掉的是**别人刚建好的那条** —— 它的持有者（正在用的终端、上传中的 SFTP、
// 正在采集的监控）会当场断链。实测并发下 12 轮里 12 轮复现。
//
// **holders > 0 时拒绝摘除**：这是本轮加的保护。持有者要么是用户正在敲的终端，
// 要么是上传中的 SFTP，要么是跑了一半的合规核查 —— 把有人持有的连接从池里删掉
// 等于当场掐断它（终端立刻显示 [连接已结束]）。判"连接坏了"这件事本身就可能误判
// （用户点开一个已删除的文件也能走到这里），所以宁可让一条可疑连接留在池里
// （下一次 Acquire 会探活、reaper 也会探），也不要冒着掐断终端的风险。
// 真正需要"无论如何都要断"的场景是关停，那由 CloseAll 负责（它不看 holders）。
func (p *Pool) dropIf(key string, client *ssh.Client) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	c, ok := p.conns[key]
	if !ok || c.client != client {
		p.mu.Unlock()
		return
	}
	if c.holders > 0 {
		holders := c.holders
		// **摘出池，但不 Close，并记进 orphans。**
		//
		// 不能 Close：持有者（终端/上传/合规）手里这条 client 还在用，关掉等于掐断
		// 用户正在敲的终端。也不能留在池里：Acquire 的第二轮会因为 lastPing 刚被刷过
		// 而不再探活，于是把这条**已知死连接**原样递给调用方（实测 got==dead、dialed=0），
		// 之后每个 pingInterval（15 秒）重复一次，而日志还说"先不丢弃"——与事实相反。
		//
		// 摘出去之后记进 orphans：持有者释放（holders 归零）时由 Hold 的 release
		// 负责关掉。不记的话这条连接既不在 conns 里、也没人管，TCP 与 mux goroutine
		// 就永远漏着。
		if p.orphans == nil {
			p.orphans = map[*ssh.Client]*orphanConn{}
		}
		// 已经在 orphan 里说明是第二次摘出：保留原有计数，别把持有者数冲掉。
		if o, dup := p.orphans[c.client]; dup {
			if holders > o.holders {
				o.holders = holders
			}
		} else {
			p.orphans[c.client] = &orphanConn{client: c.client, holders: holders}
		}
		delete(p.conns, key)
		p.mu.Unlock()
		log.Printf("sshx: 连接 %s 探活失败但仍被 %d 个使用方持有，已从池中摘出（持有者释放后关闭）；下次请求会重新建连", key, holders)
		return
	}
	delete(p.conns, key)
	p.mu.Unlock()
	_ = c.client.Close()
}

// CloseAll 关闭全部连接，并停掉 reaper。**关停之后池不再接受新的连接**
// （Acquire 返回 ErrPoolClosed）—— 否则会往里插一批没人回收的连接。
func (p *Pool) CloseAll() {
	// 先停 ticker：进程退出路径上不留一个还在跑的 goroutine。
	p.Close()
	p.mu.Lock()
	p.closed = true
	list := make([]*pooled, 0, len(p.conns))
	for _, c := range p.conns {
		list = append(list, c)
	}
	p.conns = map[string]*pooled{}
	// orphan 也要一并关：它们不在 conns 里，只遍历 conns 会让这些连接
	// 活着离开进程（TCP 挂着、mux goroutine 没退）。
	orphans := make([]*ssh.Client, 0, len(p.orphans))
	for _, o := range p.orphans {
		orphans = append(orphans, o.client)
	}
	p.orphans = nil
	p.mu.Unlock()
	for _, c := range list {
		_ = c.client.Close()
	}
	for _, c := range orphans {
		_ = c.Close()
	}
}

// reaper 周期性地回收空闲连接，并对仍在使用中的连接做一次心跳。
// 心跳有两个作用：让中间的 NAT / 防火墙别把会话清掉，以及尽早发现已经死掉的连接。
func (p *Pool) reaper() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			// Close/CloseAll 叫停：以前没有停止路径，ticker 会跟着进程活到底。
			return
		case <-ticker.C:
		}

		now := time.Now()

		type entry struct {
			key    string
			client *ssh.Client
		}
		var toClose, toPing []entry

		p.mu.Lock()
		for k, c := range p.conns {
			// 有终端/上传/长核查在用它：绝不按空闲回收，只刷心跳。
			// 这是 H2 的修复点 —— 以前只看 lastUsed，而终端完全不碰池。
			if c.holders == 0 && now.Sub(c.lastUsed) > p.idle {
				toClose = append(toClose, entry{k, c.client})
				delete(p.conns, k)
				continue
			}
			if now.Sub(c.lastPing) > pingInterval && !c.pinging {
				c.pinging = true
				c.lastPing = now
				toPing = append(toPing, entry{k, c.client})
			}
		}
		p.mu.Unlock()

		for _, e := range toClose {
			_ = e.client.Close()
		}
		for _, e := range toPing {
			alive := Alive(e.client)
			// 同样按身份复位/摘除：探活期间这个 key 可能已经换人了
			p.mu.Lock()
			if cur, still := p.conns[e.key]; still && cur.client == e.client {
				cur.pinging = false
			}
			p.mu.Unlock()
			if !alive {
				p.dropIf(e.key, e.client)
			}
		}
	}
}
