package sshx

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// pingInterval 是两次探活之间的最小间隔。
// 每次 Acquire 都探会白白多加一个 RTT，所以按时间隔开。
const pingInterval = 15 * time.Second

// Pool 按 key 复用 SSH 连接：同一个目标只握手一次，终端/文件/监控共用同一条连接的不同 channel。
type Pool struct {
	mu    sync.Mutex
	conns map[string]*pooled
	idle  time.Duration
}

type pooled struct {
	client   *ssh.Client
	lastUsed time.Time
	lastPing time.Time
}

// NewPool 创建一个连接池；idle 为回收空闲连接的时间。
func NewPool(idle time.Duration) *Pool {
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	p := &Pool{conns: map[string]*pooled{}, idle: idle}
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
// 调用方在使用失败后应调用 Drop 丢弃。
func (p *Pool) Acquire(key string, dial func() (*ssh.Client, error)) (*ssh.Client, error) {
	// 最多两轮：第一轮探活发现是死连接就丢掉，第二轮重新握手
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		if c, ok := p.conns[key]; ok {
			c.lastUsed = time.Now()
			needPing := time.Since(c.lastPing) > pingInterval
			if needPing {
				c.lastPing = time.Now()
			}
			client := c.client
			p.mu.Unlock()

			if !needPing || Alive(client) {
				return client, nil
			}
			p.Drop(key) // 探活失败：摘掉这条死连接，下一轮重连
			continue
		}
		p.mu.Unlock()

		client, err := dial()
		if err != nil {
			return nil, err
		}

		p.mu.Lock()
		if old, ok := p.conns[key]; ok { // 并发下可能已被别的调用放进去了
			old.lastUsed = time.Now()
			old.lastPing = time.Now()
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

// Drop 丢弃某个 key 的连接（使用中出错时调用，下次会重新握手）。
func (p *Pool) Drop(key string) {
	p.mu.Lock()
	c, ok := p.conns[key]
	delete(p.conns, key)
	p.mu.Unlock()
	if ok {
		_ = c.client.Close()
	}
}

// CloseAll 关闭全部连接。
func (p *Pool) CloseAll() {
	p.mu.Lock()
	list := make([]*pooled, 0, len(p.conns))
	for _, c := range p.conns {
		list = append(list, c)
	}
	p.conns = map[string]*pooled{}
	p.mu.Unlock()
	for _, c := range list {
		_ = c.client.Close()
	}
}

// reaper 周期性地回收空闲连接，并对仍在使用中的连接做一次心跳。
// 心跳有两个作用：让中间的 NAT / 防火墙别把会话清掉，以及尽早发现已经死掉的连接。
func (p *Pool) reaper() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()

		type entry struct {
			key    string
			client *ssh.Client
		}
		var toClose, toPing []entry

		p.mu.Lock()
		for k, c := range p.conns {
			if now.Sub(c.lastUsed) > p.idle {
				toClose = append(toClose, entry{k, c.client})
				delete(p.conns, k)
				continue
			}
			if now.Sub(c.lastPing) > pingInterval {
				c.lastPing = now
				toPing = append(toPing, entry{k, c.client})
			}
		}
		p.mu.Unlock()

		for _, e := range toClose {
			_ = e.client.Close()
		}
		for _, e := range toPing {
			if !Alive(e.client) {
				p.Drop(e.key)
			}
		}
	}
}
