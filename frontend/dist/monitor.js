/* awdshell 资源监控：系统概览 + 分核 CPU + 内存环形 + 网络折线 + 磁盘 + 进程池。
   与文件面板共用右侧栏位（同一时刻只显示一个）。
   图表全部用 CSS 与内联 SVG 画，不引任何图表库。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    targets: [],
    targetId: '',
    timer: null,
    loading: false,
    intervalMs: 3000,
    auto: true,
    metric: null,
    netHistory: [],     // [{rx, tx}] 最近 60 个采样点，用于画折线
    sortBy: 'cpu',      // cpu | mem | pid
    // 是否跟随当前激活的终端会话；用户手动改过下拉就置 false。
    // 必须显式给默认值：缺了它 !undefined 恒为真，同步逻辑会被自己挡掉。
    followActive: true,
    filter: '',
    // 采样序号：切目标或重新发起采样时自增，用来丢弃"切了目标才回来"的旧响应。
    // 必须有默认值 —— 缺了它 ++undefined 是 NaN，而 NaN !== NaN 恒真，
    // 会把所有响应都当成过期丢掉（界面永远不刷新）。
    loadSeq: 0,
    // 上一次**成功**采样的本地时刻：状态栏用它显示真实间隔，而不是宣称"每 3 秒"
    lastOkAt: 0,
    // 采样期间又被要求刷新（单飞闸把这次 tick 吞了）。必须显式给默认值，
    // 而且被吞这件事要让用户看得见，见 load()。
    pendingReload: false
  };

  // ---------- 工具 ----------

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // 数值字段兜底：后端少给一个字段时不能让它冒成 "Cannot read properties of undefined"
  //（toFixed 挂在 undefined 上），界面宁可显示 0。
  function num(v) { return Number(v) || 0; }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n <= 0) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    if (i === 0) return Math.round(n) + ' B';
    return n.toFixed(n < 10 ? 2 : 1) + ' ' + u[i];
  }

  function fmtBps(n) { return fmtBytes(n || 0) + '/s'; }

  function fmtUptime(sec) {
    sec = sec || 0;
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    if (d > 0) return d + ' 天 ' + h + ' 小时';
    if (h > 0) return h + ' 小时 ' + m + ' 分';
    return m + ' 分';
  }

  function level(p) {
    if (p >= 90) return 'crit';
    if (p >= 75) return 'warn';
    return '';
  }

  function setStatus(msg) {
    var el = $('status');
    if (el) el.textContent = msg;
  }

  async function req(path) {
    var res = await fetch(API + path, { headers: { 'Content-Type': 'application/json' } });
    if (!res.ok) {
      var msg = res.status + ' ' + res.statusText;
      try { var j = await res.json(); if (j && j.error) msg = j.error; } catch (e) { /* 忽略 */ }
      throw new Error(msg);
    }
    return res.json();
  }

  // ---------- 骨架（只建一次，之后只更新内容，避免把搜索框重建掉） ----------

  function renderShell() {
    $('monitor-area').innerHTML =
      '<div class="mo-toolbar">' +
      '  <select id="mo-target" class="mo-target"></select>' +
      '  <button id="mo-sync" class="mo-sync" title="默认跟随当前终端会话；手动选过目标后会锁定，点这里恢复跟随"></button>' +
      '  <button id="mo-refresh">刷新</button>' +
      '  <label class="mo-follow" title="每 3 秒触发一次采样；上一次没返回时会跳过本次，状态栏会说明"><input type="checkbox" id="mo-auto" checked /> 自动</label>' +
      '  <span class="mo-ts" id="mo-ts"></span>' +
      '</div>' +
      '<div class="mo-body" id="mo-body">' +
      '  <section class="mo-card mo-os" id="mo-os"></section>' +
      '  <section class="mo-card" id="mo-cpu"></section>' +
      '  <section class="mo-card" id="mo-mem"></section>' +
      '  <section class="mo-card" id="mo-net"></section>' +
      '  <section class="mo-card" id="mo-disk"></section>' +
      '  <section class="mo-card" id="mo-conn"></section>' +
      '  <section class="mo-card" id="mo-listen"></section>' +
      '  <section class="mo-card mo-procs" id="mo-procs">' +
      '    <div class="mo-card-head">' +
      '      <span>进程池</span>' +
      '      <span class="mo-proc-total" id="mo-proc-total"></span>' +
      '    </div>' +
      '    <div class="mo-proc-tools">' +
      '      <input id="mo-proc-filter" class="mo-proc-filter" placeholder="过滤命令或用户" spellcheck="false" />' +
      '      <button data-sort="cpu" class="mo-sort active">CPU</button>' +
      '      <button data-sort="mem" class="mo-sort">内存</button>' +
      '      <button data-sort="pid" class="mo-sort">PID</button>' +
      '    </div>' +
      '    <div class="mo-proc-list" id="mo-proc-list"></div>' +
      '  </section>' +
      '</div>';

    $('mo-target').addEventListener('change', function () {
      state.targetId = this.value;
      state.loadSeq++; // 作废在途的采样响应
      // 用户手动选了目标：这个视图锁定它，不再跟着会话跑
      state.followActive = false;
      state.netHistory = [];
      // 换主机了："距上次 N 秒"不能跨主机算（这个值以前只在这里漏了重置，
      // 于是一切目标，状态栏显示的是距**上一台**采样过了多久）
      state.lastOkAt = 0;
      renderSyncState();
      load(true);
    });
    $('mo-sync').addEventListener('click', function () {
      state.followActive = true;
      syncToActiveSession();
      renderSyncState();
      if (!$('monitor-area').hidden) load(true);
      setStatus('监控已恢复跟随当前终端会话');
    });
    $('mo-refresh').addEventListener('click', function () { load(true); });
    $('mo-auto').addEventListener('change', function () {
      state.auto = this.checked;
      schedule();
    });
    $('mo-proc-filter').addEventListener('input', function () {
      state.filter = this.value.trim().toLowerCase();
      renderProcs();
    });
    var sorts = document.querySelectorAll('.mo-sort');
    for (var i = 0; i < sorts.length; i++) {
      sorts[i].addEventListener('click', function () {
        state.sortBy = this.getAttribute('data-sort');
        var all = document.querySelectorAll('.mo-sort');
        for (var j = 0; j < all.length; j++) all[j].classList.toggle('active', all[j] === this);
        renderProcs();
      });
    }
  }

  function renderTargets() {
    var sel = $('mo-target');
    if (!sel) return;
    sel.innerHTML = state.targets.map(function (t) {
      return '<option value="' + esc(t.id) + '"' + (t.id === state.targetId ? ' selected' : '') + '>' + esc(t.name) + '</option>';
    }).join('') || '<option value="">无目标</option>';
  }

  // ---------- 各卡片 ----------

  // proc_total 为 -1 表示"没采到进程数"（不是 0 个进程）—— 以前 `|| 0` 会把它
  // 画成 "0"，看起来像一台干净空闲的机器，那是错误数据不是缺失数据。
  function fmtProcTotal(v) {
    var n = Number(v);
    if (!isFinite(n) || n < 0) return '--';
    return String(n);
  }

  function renderOS(m) {
    $('mo-os').innerHTML =
      '<div class="mo-os-head">' +
      '  <span class="mo-os-name" title="' + esc(m.os_name) + '">' + esc(m.os_name || '未知系统') + '</span>' +
      '  <span class="mo-os-tag">' + esc(m.timezone || '') + '</span>' +
      '</div>' +
      '<div class="mo-os-rows">' +
      '  <span>内核 <b>' + esc(m.kernel || '-') + '</b></span>' +
      '  <span>运行 <b>' + fmtUptime(m.uptime_sec) + '</b></span>' +
      '  <span>进程 <b>' + fmtProcTotal(m.proc_total) + '</b></span>' +
      '</div>';
  }

  function renderCPU(m) {
    var cpuPct = num(m.cpu_percent);
    var cores = (m.cpu_cores || []).map(function (c) {
      var cp = num(c.percent);
      return '<div class="mo-core">' +
        '<span class="mo-core-id">' + esc(c.id) + '</span>' +
        '<span class="mo-core-bar"><i class="' + level(cp) + '" style="width:' + Math.max(1.5, cp).toFixed(1) + '%"></i></span>' +
        '<span class="mo-core-num">' + cp.toFixed(1) + '%</span>' +
        '</div>';
    }).join('');

    $('mo-cpu').innerHTML =
      '<div class="mo-card-head">' +
      '  <span>CPU</span>' +
      '  <span class="mo-big ' + level(cpuPct) + '">' + cpuPct.toFixed(1) + '%</span>' +
      '</div>' +
      '<span class="mo-bar"><i class="' + level(cpuPct) + '" style="width:' + Math.max(1, cpuPct).toFixed(1) + '%"></i></span>' +
      '<div class="mo-sub">负载 ' + num(m.load1).toFixed(2) + ' / ' + num(m.load5).toFixed(2) + ' / ' + num(m.load15).toFixed(2) +
      '　' + (m.cpu_cores || []).length + ' 核</div>' +
      (cores ? '<div class="mo-cores">' + cores + '</div>' : '');
  }

  function renderMem(m) {
    var total = m.mem_total || 0;
    var used = m.mem_used || 0;
    var cached = m.mem_cached || 0;
    var buffers = m.mem_buffers || 0;
    var free = Math.max(0, total - used);
    var pct = num(m.mem_percent);

    // 环形图：conic-gradient 画已用 / 缓存 / 剩余三段
    var usedDeg = total > 0 ? (used / total) * 360 : 0;
    var cacheDeg = total > 0 ? ((cached + buffers) / total) * 360 : 0;
    var ring = 'conic-gradient(' +
      'var(--accent) 0deg ' + usedDeg.toFixed(1) + 'deg,' +
      'rgba(76,141,255,0.32) ' + usedDeg.toFixed(1) + 'deg ' + (usedDeg + cacheDeg).toFixed(1) + 'deg,' +
      'var(--bg-active) ' + (usedDeg + cacheDeg).toFixed(1) + 'deg 360deg)';

    $('mo-mem').innerHTML =
      '<div class="mo-card-head">' +
      '  <span>内存</span>' +
      '  <span class="mo-big ' + level(pct) + '">' + pct.toFixed(1) + '%</span>' +
      '</div>' +
      '<div class="mo-mem-wrap">' +
      '  <div class="mo-ring" style="background:' + ring + '">' +
      '    <div class="mo-ring-inner"><span class="mo-ring-num">' + fmtBytes(used) + '</span>' +
      '      <span class="mo-ring-label">/ ' + fmtBytes(total) + '</span></div>' +
      '  </div>' +
      '  <div class="mo-legend">' +
      '    <span><i style="background:var(--accent)"></i>已用 <b>' + fmtBytes(used) + '</b></span>' +
      '    <span><i style="background:rgba(76,141,255,0.32)"></i>缓存 <b>' + fmtBytes(cached + buffers) + '</b></span>' +
      '    <span><i style="background:var(--bg-active)"></i>空闲 <b>' + fmtBytes(free) + '</b></span>' +
      (m.swap_total > 0 ? '<span><i style="background:var(--warning)"></i>交换 <b>' + fmtBytes(m.swap_used) + '</b></span>' : '') +
      '  </div>' +
      '</div>';
  }

  function renderNet(m) {
    var ifaces = (m.net || []).filter(function (n) { return n.name !== 'lo'; });

    // 折线图：把历史上每个采样点的上下行速率画成两条线
    var hist = state.netHistory;
    var maxV = 1024;
    hist.forEach(function (h) { maxV = Math.max(maxV, h.rx, h.tx); });
    var W = 300, H = 56;
    function poly(key) {
      if (hist.length < 2) return '';
      return hist.map(function (h, i) {
        var x = (i / (hist.length - 1)) * W;
        var y = H - (h[key] / maxV) * (H - 6) - 3;
        return x.toFixed(1) + ',' + y.toFixed(1);
      }).join(' ');
    }

    var rows = ifaces.map(function (n) {
      return '<div class="mo-net-row">' +
        '<span class="mo-net-name">' + esc(n.name) + '</span>' +
        '<span class="mo-net-rate down">↓ ' + fmtBps(n.rx_bps) + '</span>' +
        '<span class="mo-net-rate up">↑ ' + fmtBps(n.tx_bps) + '</span>' +
        '<span class="mo-net-total">累计 ' + fmtBytes(n.rx_total) + ' / ' + fmtBytes(n.tx_total) + '</span>' +
        '</div>';
    }).join('');

    $('mo-net').innerHTML =
      '<div class="mo-card-head"><span>网络</span><span class="mo-net-peak">峰值 ' + fmtBps(maxV) + '</span></div>' +
      '<div class="mo-chart">' +
      '  <svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
      '    <polyline class="mo-line-rx" points="' + poly('rx') + '" />' +
      '    <polyline class="mo-line-tx" points="' + poly('tx') + '" />' +
      '  </svg>' +
      '  <div class="mo-chart-legend"><span class="down">下行</span><span class="up">上行</span></div>' +
      '</div>' +
      (rows || '<div class="mo-sub">没有可显示的网络接口</div>');
  }

  function renderDisk(m) {
    var disks = (m.disks || []).filter(function (d) {
      if (!d.total || d.total <= 0) return false;
      var dev = String(d.device || '').toLowerCase();
      var mount = String(d.mount || '');
      if (dev === 'none' || /^(tmpfs|udev|devtmpfs|overlay|shm|ramfs)/.test(dev)) return false;
      if (/^\/(run|sys|proc|dev)(\/|$)/.test(mount)) return false;
      return true;
    }).slice(0, 6);

    var rows = disks.map(function (d) {
      var dp = num(d.percent);
      return '<div class="mo-disk">' +
        '<div class="mo-disk-head"><span class="k">' + esc(d.mount) + '</span>' +
        '<span class="v">' + fmtBytes(d.used) + ' / ' + fmtBytes(d.total) + ' · ' + dp.toFixed(1) + '%</span></div>' +
        '<span class="mo-bar"><i class="' + level(dp) + '" style="width:' + Math.max(1, dp).toFixed(1) + '%"></i></span>' +
        '<div class="mo-disk-dev">' + esc(d.device) + '</div></div>';
    }).join('');

    $('mo-disk').innerHTML = '<div class="mo-card-head"><span>磁盘</span></div>' +
      (rows || '<div class="mo-sub">没有可显示的分区</div>');
  }

  // 网络连接：谁连着我、我连着谁、都在哪些端口上。
  // 对端端口排行是排查外联最直观的一列 —— 正常服务器不会往一堆奇怪的高位端口外连。
  function renderConn(m) {
    var conns = m.conns || [];
    var states = (m.conn_states || []).map(function (s) {
      return '<span class="mo-conn-state st-' + esc(String(s.name).toLowerCase()) + '">' +
        esc(s.name) + ' <b>' + s.count + '</b></span>';
    }).join('');

    function bars(items, prefix) {
      if (!items.length) return '';
      var max = num(items[0].count) || 1;
      return items.slice(0, 6).map(function (p) {
        var pc = num(p.count);
        return '<div class="mo-conn-bar">' +
          '<span class="k">' + prefix + esc(p.name) + '</span>' +
          '<span class="b"><i style="width:' + Math.max(6, (pc / max) * 100).toFixed(1) + '%"></i></span>' +
          '<span class="v">' + pc + '</span></div>';
      }).join('');
    }

    var list = conns.slice(0, 30).map(function (c) {
      return '<div class="mo-conn-row" title="' + esc(c.process || '') + '">' +
        '<span class="st st-' + esc(String(c.state).toLowerCase()) + '">' + esc(c.state) + '</span>' +
        // 端口走后端解析成 int，仍然照全站规矩 esc 一次：将来解析改成透传字符串时
        // 这里不会再变成一个 HTML 注入点
        '<span class="ep">' + esc(c.remote) + ':' + esc(c.rport) + '</span>' +
        '<span class="lp">← :' + esc(c.lport) + '</span>' +
        '<span class="proc">' + esc(c.process || '-') + '</span>' +
        '</div>';
    }).join('');

    $('mo-conn').innerHTML =
      '<div class="mo-card-head"><span>网络连接</span><span class="mo-net-peak">' + conns.length + ' 条</span></div>' +
      (states ? '<div class="mo-conn-states">' + states + '</div>' : '<div class="mo-sub">没有已建立的连接</div>') +
      (bars(m.conn_ports || [], ':') ? '<div class="mo-conn-group"><div class="mo-title">对端端口</div>' + bars(m.conn_ports || [], ':') + '</div>' : '') +
      (bars(m.conn_remote || [], '') ? '<div class="mo-conn-group"><div class="mo-title">对端地址</div>' + bars(m.conn_remote || [], '') + '</div>' : '') +
      (list ? '<div class="mo-conn-list">' + list + '</div>' : '');
  }

  // 监听端口：这台机器对外开了哪些端口、分别是谁在占。
  // 对外监听（非回环）标黄 —— 那才是真正的暴露面。
  function renderListeners(m) {
    var list = m.listeners || [];
    if (!list.length) {
      $('mo-listen').innerHTML = '<div class="mo-card-head"><span>监听端口</span></div>' +
        '<div class="mo-sub">没读到监听端口（目标机可能没有 ss / netstat）</div>';
      return;
    }
    var rows = list.slice(0, 30).map(function (l) {
      var pub = l.addr !== '127.0.0.1' && l.addr !== '::1' && l.addr !== '';
      return '<div class="mo-listen-row">' +
        '<span class="proto">' + esc(l.proto) + '</span>' +
        '<span class="port' + (pub ? ' pub' : '') + '">' + esc(l.port) + '</span>' +
        '<span class="addr">' + esc(l.addr || '*') + '</span>' +
        '<span class="proc">' + esc(l.process || '-') + '</span>' +
        '</div>';
    }).join('');

    $('mo-listen').innerHTML =
      '<div class="mo-card-head"><span>监听端口</span><span class="mo-net-peak">' + list.length + ' 个</span></div>' +
      '<div class="mo-listen-list">' + rows + '</div>';
  }

  function renderProcs() {
    var m = state.metric;
    if (!m) return;
    var totalTxt = fmtProcTotal(m.proc_total);
    $('mo-proc-total').textContent = totalTxt === '--'
      ? '未采集到进程数 · 列出 ' + (m.procs || []).length + ' 个'
      : totalTxt + ' 个 · 列出 ' + (m.procs || []).length + ' 个';

    var list = (m.procs || []).slice();
    if (state.filter) {
      list = list.filter(function (p) {
        return String(p.pid).indexOf(state.filter) >= 0 ||
          String(p.user).toLowerCase().indexOf(state.filter) >= 0 ||
          String(p.comm).toLowerCase().indexOf(state.filter) >= 0 ||
          String(p.args).toLowerCase().indexOf(state.filter) >= 0;
      });
    }
    if (state.sortBy === 'mem') {
      list.sort(function (a, b) { return num(b.mem) - num(a.mem); });
    } else if (state.sortBy === 'pid') {
      list.sort(function (a, b) { return num(a.pid) - num(b.pid); });
    } else {
      list.sort(function (a, b) { return num(b.cpu) - num(a.cpu); });
    }

    // 进程列表每 3 秒整体重建，不保留滚动位置的话永远读不完 ——
    // 想往下看第 60 个进程，刚到那就被弹回顶部
    var procList = $('mo-proc-list');
    var prevScrollTop = procList ? procList.scrollTop : 0;

    if (!list.length) {
      procList.innerHTML = '<div class="mo-sub">没有匹配的进程</div>';
      return;
    }

    procList.innerHTML =
      '<div class="mo-proc head"><span class="pid">PID</span><span class="user">用户</span>' +
      '<span class="cpu">CPU%</span><span class="mem">MEM%</span><span class="cmd">命令</span></div>' +
      list.map(function (p) {
        var pc = num(p.cpu);
        return '<div class="mo-proc" title="' + esc(p.args) + '">' +
          '<span class="pid">' + esc(p.pid) + '</span>' +
          '<span class="user">' + esc(p.user) + '</span>' +
          '<span class="cpu ' + (pc >= 50 ? 'hot' : '') + '">' + pc.toFixed(1) + '</span>' +
          '<span class="mem">' + num(p.mem).toFixed(1) + '</span>' +
          '<span class="cmd">' + esc(p.comm) + '</span>' +
          '</div>';
      }).join('');

    // 还原滚动位置
    if (prevScrollTop) procList.scrollTop = prevScrollTop;
  }

  function render(m) {
    // 后端给的不是对象（代理错误页、接口版本不匹配）时不要让它冒成
    // "Cannot read properties of undefined"，说一句人能看懂的话就退回
    if (!m || typeof m !== 'object') {
      setStatus('监控：数据格式不符合预期，已跳过这次刷新');
      return;
    }
    state.metric = m;

    // 记录网络历史用于折线
    var iface = (m.net || []).filter(function (n) { return n.name !== 'lo'; })[0];
    if (iface) {
      state.netHistory.push({ rx: iface.rx_bps || 0, tx: iface.tx_bps || 0 });
      if (state.netHistory.length > 60) state.netHistory.shift();
    }

    renderOS(m);
    renderCPU(m);
    renderMem(m);
    renderNet(m);
    renderDisk(m);
    renderConn(m);
    renderListeners(m);
    renderProcs();
    $('mo-ts').textContent = m.ts ? new Date(m.ts).toLocaleTimeString() : '--';
  }

  // ---------- 数据 ----------

  async function loadTargets() {
    state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    // 目标可能已被删除：清掉悬空的 targetId 与它留下的采样历史
    if (state.targetId && !state.targets.some(function (t) { return t.id === state.targetId; })) {
      state.targetId = '';
      state.loadSeq++;
      state.lastOkAt = 0; // 换过主机了：上一次成功采样的时刻不能再拿来算间隔
      state.netHistory = [];
    }
    if (!state.targetId && state.targets.length) state.targetId = state.targets[0].id;
    renderTargets();
  }

  // 切目标时不能被"正在采样"挡住：挡住的话新请求直接被丢掉，
  // 界面会一直停在上一台的数据上，而且此后不再自动刷新。
  async function load(showStatus) {
    if (!state.targetId) return;
    if (state.loading) {
      // 单飞闸把这次刷新吞掉了，而界面以前还在写"每 3 秒自动刷新"。
      // 慢链路下单次采样可能超过 3 秒，后续 tick 会被连着吞掉，
      // 挖矿、反弹 shell 这类短命进程完全可能落在被吞掉的空档里 ——
      // 所以被吞这件事必须让用户看见，同时报出上一次真正采到的时刻。
      state.pendingReload = true;
      setStatus('监控：上一次采样还没返回，这次刷新已跳过（上次成功 ' +
        (state.lastOkAt ? new Date(state.lastOkAt).toLocaleTimeString() : '未知') + '）');
      return;
    }
    state.loading = true;
    // 记下这一轮属于哪次请求、针对哪台目标。采样期间切了目标的话，
    // 这份响应回来时**不能往界面上贴** —— 否则 B 的目标下拉底下显示的
    // 是 A 的进程名、对端 IP、监听端口，而用户在对着它做判断。
    var seq = ++state.loadSeq;
    var tid = state.targetId;
    if (showStatus) setStatus('正在采集 …');
    try {
      var m = await req('/api/monitor?target_id=' + encodeURIComponent(tid));
      if (seq !== state.loadSeq || tid !== state.targetId) return;
      var old = $('mo-err');
      if (old) old.remove();
      render(m);
      // 不再宣称"每 3 秒自动刷新"：那是设定值，不是实际值（见上面单飞闸）。
      // 直接给出这一次成功采样的真实时刻，以及距上一次成功采样实际过了多久。
      var now = Date.now();
      var gapSec = state.lastOkAt ? Math.round((now - state.lastOkAt) / 1000) : 0;
      state.lastOkAt = now;
      // collected=false / problems 的提示**必须与这句合并成一次 setStatus**：
      // setStatus 就是 textContent=，先写会被后写覆盖，消息活不过几毫秒
      //（上一版就是这么写的，commit 说"已消费 collected"，界面上根本看不到）。
      var note = "";
      if (m.collected === false) {
        note = "　未采集到关键指标，面板数值不可信" +
          ((m.missing || []).length ? "（未采集到：" + (m.missing || []).join("、") + "）" : "");
      } else if ((m.problems || []).length) {
        note = "　" + (m.problems || []).join("；");
      }
      setStatus('监控：上次成功采样 ' + (m.ts ? new Date(m.ts).toLocaleTimeString() : new Date(now).toLocaleTimeString()) +
        (gapSec ? '（距上次 ' + gapSec + ' 秒）' : '') +
        (state.auto ? '' : '　手动刷新') + note);
    } catch (e) {
      if (seq !== state.loadSeq || tid !== state.targetId) return;
      var body = $('mo-body');
      if (body && !$('mo-err')) {
        body.insertAdjacentHTML('afterbegin', '<div class="mo-empty error-text" id="mo-err">采集失败：' + esc(e.message) + '</div>');
      }
      setStatus('监控采集失败：' + e.message);
    } finally {
      state.loading = false;
      // 采样期间切过目标：补一次，否则界面会一直停在上一台的数据上
      if (state.pendingReload) {
        state.pendingReload = false;
        load(false);
      }
    }
  }

  // 监控面板此刻是不是真的看得见：整页视图（设置 / 日志检测 / 基线核查 / 态势）
  // 打开时 work-body 是隐藏的，面板的 hidden 仍是 false，但用户看不到 ——
  // 这时不该继续每 3 秒采一次，那是白花的 SSH 往返。
  function monitorReallyVisible() {
    if ($('monitor-area').hidden) return false;
    var wb = $('work-body');
    return !!wb && wb.style.display !== 'none';
  }

  // 把"跟随中 / 已锁定"显示出来。
  // 之前锁定后界面毫无提示，用户看到的就是"我切了会话但监控不动"，像坏了一样。
  function renderSyncState() {
    if (window.AwdViews) window.AwdViews.followButton('mo-sync', state.followActive, '监控目标');
  }

  // 跟随当前激活的终端会话：切标签时监控跟着换主机。
  // 用户一旦手动改过下拉就锁定（state.followActive = false），不再自动覆盖 ——
  // 那是他明确的意图；但锁定必须看得见，见 renderSyncState。
  function syncToActiveSession() {
    if (!state.followActive) { renderSyncState(); return false; }
    var tid = window.AwdActiveTarget ? window.AwdActiveTarget() : '';
    if (!tid || tid === state.targetId) { renderSyncState(); return false; }
    state.targetId = tid;
    state.loadSeq++; // 换主机了：在途的旧采样响应一律作废
    state.netHistory = [];
    state.lastOkAt = 0; // 换主机：状态栏的"距上次 N 秒"不能跨主机算
    state.pendingReload = false;
    renderTargets();
    renderSyncState();
    return true;
  }

  function schedule() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    // 面板**看不见**时连定时器都不该起：分屏、或打开基线核查/日志检测这类整页视图时，
    // 监控面板只是被 hidden 掉，而定时器仍会每 3 秒醒一次、对目标机白跑一次采集
    //（SSH 往返 + 远端 ps/ss/proc）。在 AWD 里那是白花预算，慢链路下还会和别的视图
    // 抢同一条共享 SSH 连接。
    if (!state.auto || !monitorReallyVisible()) return;
    state.timer = setInterval(function () {
      if (monitorReallyVisible() && !document.hidden) load(false);
    }, state.intervalMs);
  }

  // ---------- 显隐 ----------

  function setMonitorVisible(show) {
    var area = $('monitor-area');
    if (show) {
      // 整页视图开着的时候点「监控」，用户的意图是看监控 —— 先把整页视图收起，
      // 否则按钮亮了但面板藏在 work-body 后面，什么都看不见。
      if (window.AwdViews) window.AwdViews.closeAll();
      if ($('files-area')) {
        $('files-area').hidden = true;
        window.dispatchEvent(new Event('awdshell:files-hide'));
      }
    }
    area.hidden = !show;
    if (window.AwdSidePanel) window.AwdSidePanel.sync('monitor');
    var btn = $('btn-monitor');
    if (btn) btn.classList.toggle('active', show);

    if (show) {
      // 每次打开都回到"跟随当前会话"：上次手动选的那台不该一直粘着
      state.followActive = true;
      if (!state.targets.length) {
        loadTargets().then(function () {
          syncToActiveSession();
          load(true);
        }).catch(function (e) { setStatus('加载目标失败：' + e.message); });
      } else {
        syncToActiveSession();
        renderTargets();
        load(true);
      }
      schedule();
    } else if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }
  }

  // ---------- 初始化 ----------

  function boot() {
    renderShell();
    $('btn-monitor').addEventListener('click', function () {
      setMonitorVisible($('monitor-area').hidden);
    });
    window.addEventListener('awdshell:monitor-hide', function () {
      // 面板可能只是被整页视图盖住，可见性变了就重排定时器；
      // 无条件停掉「自动」会导致关闭视图后数据再也不刷新。
      schedule();
    });
    // 切换终端会话时跟着换主机（用户手动选过就锁定，不覆盖）
    window.addEventListener('awdshell:connected', function () {
      if (syncToActiveSession() && !$('monitor-area').hidden) load(true);
    });
    // 关掉某个目标的最后一个 SSH 标签时，监控一起收起：
    // 别的视图（文件面板 / 日志检测 / 基线核查）都有这个联动，监控原来漏了，
    // 于是目标都关掉了它还在每 3 秒对着那台机器采一次
    window.addEventListener('awdshell:session-closed', function (e) {
      var d = (e && e.detail) || {};
      var area = $('monitor-area');
      if (!area || area.hidden) return;
      if (d.targetId !== state.targetId) return;
      var remaining = d.remainingTargets || [];
      if (remaining.indexOf(state.targetId) >= 0) return;
      setMonitorVisible(false);
      setStatus('该目标的会话已全部关闭，监控已收起');
    });
    // 目标被新建或删除后重取列表。
    // loadTargets 自己会把被删掉的目标换成列表里的第一台（并作废在途响应）；
    // 这里只补它没做的那件事：**目标真的换了**时，把采样历史与"上次成功时刻"
    // 一起重置，并重采一次 —— 否则界面会一直停在已删那台的旧数据上。
    // （以前这里写的是 `if (!state.targetId && ...) loadSeq++`，而 loadTargets
    // 在上一行就已经把 targetId 填好了，那个分支永远不成立。）
    window.addEventListener('awdshell:targets-changed', function () {
      var before = state.targetId;
      loadTargets().then(function () {
        if (state.targetId === before) return;
        state.loadSeq++;
        state.netHistory = [];
        state.lastOkAt = 0;
        if (!$('monitor-area').hidden) load(true);
      }).catch(function () {});
    });
    loadTargets().catch(function () { /* 首次打开时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
