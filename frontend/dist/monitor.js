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
    filter: ''
  };

  // ---------- 工具 ----------

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

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
      '  <label class="mo-follow" title="每 3 秒自动采样"><input type="checkbox" id="mo-auto" checked /> 自动</label>' +
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
      // 用户手动选了目标：这个视图锁定它，不再跟着会话跑
      state.followActive = false;
      state.netHistory = [];
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

  function renderOS(m) {
    $('mo-os').innerHTML =
      '<div class="mo-os-head">' +
      '  <span class="mo-os-name" title="' + esc(m.os_name) + '">' + esc(m.os_name || '未知系统') + '</span>' +
      '  <span class="mo-os-tag">' + esc(m.timezone || '') + '</span>' +
      '</div>' +
      '<div class="mo-os-rows">' +
      '  <span>内核 <b>' + esc(m.kernel || '-') + '</b></span>' +
      '  <span>运行 <b>' + fmtUptime(m.uptime_sec) + '</b></span>' +
      '  <span>进程 <b>' + (m.proc_total || 0) + '</b></span>' +
      '</div>';
  }

  function renderCPU(m) {
    var cores = (m.cpu_cores || []).map(function (c) {
      return '<div class="mo-core">' +
        '<span class="mo-core-id">' + c.id + '</span>' +
        '<span class="mo-core-bar"><i class="' + level(c.percent) + '" style="width:' + Math.max(1.5, c.percent).toFixed(1) + '%"></i></span>' +
        '<span class="mo-core-num">' + c.percent.toFixed(1) + '%</span>' +
        '</div>';
    }).join('');

    $('mo-cpu').innerHTML =
      '<div class="mo-card-head">' +
      '  <span>CPU</span>' +
      '  <span class="mo-big ' + level(m.cpu_percent) + '">' + m.cpu_percent.toFixed(1) + '%</span>' +
      '</div>' +
      '<span class="mo-bar"><i class="' + level(m.cpu_percent) + '" style="width:' + Math.max(1, m.cpu_percent).toFixed(1) + '%"></i></span>' +
      '<div class="mo-sub">负载 ' + m.load1.toFixed(2) + ' / ' + m.load5.toFixed(2) + ' / ' + m.load15.toFixed(2) +
      '　' + (m.cpu_cores || []).length + ' 核</div>' +
      (cores ? '<div class="mo-cores">' + cores + '</div>' : '');
  }

  function renderMem(m) {
    var total = m.mem_total || 0;
    var used = m.mem_used || 0;
    var cached = m.mem_cached || 0;
    var buffers = m.mem_buffers || 0;
    var free = Math.max(0, total - used);
    var pct = m.mem_percent || 0;

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
      return '<div class="mo-disk">' +
        '<div class="mo-disk-head"><span class="k">' + esc(d.mount) + '</span>' +
        '<span class="v">' + fmtBytes(d.used) + ' / ' + fmtBytes(d.total) + ' · ' + d.percent.toFixed(1) + '%</span></div>' +
        '<span class="mo-bar"><i class="' + level(d.percent) + '" style="width:' + Math.max(1, d.percent).toFixed(1) + '%"></i></span>' +
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
      var max = items[0].count || 1;
      return items.slice(0, 6).map(function (p) {
        return '<div class="mo-conn-bar">' +
          '<span class="k">' + prefix + esc(p.name) + '</span>' +
          '<span class="b"><i style="width:' + Math.max(6, (p.count / max) * 100).toFixed(1) + '%"></i></span>' +
          '<span class="v">' + p.count + '</span></div>';
      }).join('');
    }

    var list = conns.slice(0, 30).map(function (c) {
      return '<div class="mo-conn-row" title="' + esc(c.process || '') + '">' +
        '<span class="st st-' + esc(String(c.state).toLowerCase()) + '">' + esc(c.state) + '</span>' +
        '<span class="ep">' + esc(c.remote) + ':' + c.rport + '</span>' +
        '<span class="lp">← :' + c.lport + '</span>' +
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
        '<span class="port' + (pub ? ' pub' : '') + '">' + l.port + '</span>' +
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
    var total = m.proc_total || 0;
    $('mo-proc-total').textContent = total + ' 个 · 列出 ' + (m.procs || []).length + ' 个';

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
      list.sort(function (a, b) { return b.mem - a.mem; });
    } else if (state.sortBy === 'pid') {
      list.sort(function (a, b) { return a.pid - b.pid; });
    } else {
      list.sort(function (a, b) { return b.cpu - a.cpu; });
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
        return '<div class="mo-proc" title="' + esc(p.args) + '">' +
          '<span class="pid">' + p.pid + '</span>' +
          '<span class="user">' + esc(p.user) + '</span>' +
          '<span class="cpu ' + (p.cpu >= 50 ? 'hot' : '') + '">' + p.cpu.toFixed(1) + '</span>' +
          '<span class="mem">' + p.mem.toFixed(1) + '</span>' +
          '<span class="cmd">' + esc(p.comm) + '</span>' +
          '</div>';
      }).join('');

    // 还原滚动位置
    if (prevScrollTop) procList.scrollTop = prevScrollTop;
  }

  function render(m) {
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
    $('mo-ts').textContent = new Date(m.ts).toLocaleTimeString();
  }

  // ---------- 数据 ----------

  async function loadTargets() {
    state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    // 目标可能已被删除：清掉悬空的 targetId 与它留下的采样历史
    if (state.targetId && !state.targets.some(function (t) { return t.id === state.targetId; })) {
      state.targetId = '';
      state.last = null;
      state.lastAt = 0;
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
      state.pendingReload = true;
      return;
    }
    state.loading = true;
    if (showStatus) setStatus('正在采集 …');
    try {
      var m = await req('/api/monitor?target_id=' + encodeURIComponent(state.targetId));
      var old = $('mo-err');
      if (old) old.remove();
      render(m);
      setStatus('监控：' + (state.auto ? '每 3 秒自动刷新' : '手动刷新') + '　' + new Date(m.ts).toLocaleTimeString());
    } catch (e) {
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
    state.netHistory = [];
    state.last = null;
    state.lastAt = 0;
    state.pendingReload = false;
    renderTargets();
    renderSyncState();
    return true;
  }

  function schedule() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
    if (!state.auto) return;
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
    // 目标被新建或删除后重取列表
    window.addEventListener('awdshell:targets-changed', function () {
      loadTargets().then(function () {
        if (!state.targetId && state.targets.length) state.targetId = state.targets[0].id;
      }).catch(function () {});
    });
    loadTargets().catch(function () { /* 首次打开时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
