/* awdshell 前端（原生 JS，无构建步骤；终端渲染用 xterm.js） */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var WS_BASE = API.replace(/^http/, 'ws');
  var encoder = new TextEncoder();



  var $ = function (id) { return document.getElementById(id); };
  var el = {
    version: $('version'), search: $('search'), sidebar: $('sidebar-body'),
    tabs: $('tabs'), termArea: $('term-area'), status: $('status'),
    statSessions: $('stat-sessions'), statTargets: $('stat-targets'),
    modal: $('modal'), modalTitle: $('modal-title'), formError: $('form-error'),
    wrapPassword: $('wrap-password'), wrapKey: $('wrap-key'),
    f: {
      name: $('f-name'), host: $('f-host'), port: $('f-port'), username: $('f-username'),
      tags: $('f-tags'),
      auth: $('f-auth'), group: $('f-group'), startdir: $('f-startdir'), password: $('f-password'),
      privatekey: $('f-privatekey'), passphrase: $('f-passphrase')
    }
  };

  var state = {
    targets: [], recent: [], history: [], sessions: [],
    active: '', activeTarget: '', keyword: '', editing: '', saving: false,
    grid: '1' // 1 | cols2 | rows2 | grid4
  };

  // ---------------- 工具 ----------------

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function setStatus(msg) { el.status.textContent = msg; }

  function fmtTime(ms) {
    if (!ms) return '';
    var d = new Date(ms);
    var p = function (n) { return String(n).padStart(2, '0'); };
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function fmtDuration(h) {
    if (!h.ended_at) return '进行中';
    var s = Math.max(0, Math.round((h.ended_at - h.started_at) / 1000));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm';
    return Math.floor(s / 3600) + 'h' + Math.floor((s % 3600) / 60) + 'm';
  }

  // ---------------- API ----------------

  async function req(path, init) {
    var opt = Object.assign({ headers: { 'Content-Type': 'application/json' } }, init || {});
    var res = await fetch(API + path, opt);
    if (!res.ok) {
      var msg = res.status + ' ' + res.statusText;
      try { var j = await res.json(); if (j && j.error) msg = j.error; } catch (e) { /* 非 JSON */ }
      throw new Error(msg);
    }
    return res.json();
  }

  var api = {
    health: function () { return req('/api/health'); },
    targets: function () { return req('/api/targets'); },
    saveTarget: function (b) { return req('/api/targets', { method: 'POST', body: JSON.stringify(b) }); },
    deleteTarget: function (id) { return req('/api/targets/' + id, { method: 'DELETE' }); },
    testTarget: function (id) { return req('/api/targets/' + id, { method: 'POST' }); },
    recent: function () { return req('/api/recent'); },
    history: function () { return req('/api/history'); },
    openSession: function (targetId, cols, rows) {
      return req('/api/sessions', { method: 'POST', body: JSON.stringify({ target_id: targetId, cols: cols, rows: rows }) });
    },
    closeSession: function (id) { return req('/api/sessions/' + id, { method: 'DELETE' }); },
    // 断线重连：为仍然活着的会话换一个新的一次性令牌
    attachSession: function (id) { return req('/api/sessions/' + encodeURIComponent(id) + '/attach', { method: 'POST' }); }
  };

// 显示 / 清除已记录的主机密钥。
//
// 目标机重装或更换密钥后会被拒连，提示里说「在目标的编辑里清除已记录的主机密钥」——
// 这个入口以前只有后端接口、界面上没有，结果用户按提示找不到地方，
// 删掉目标重建也没用（known_hosts 按 host:port 独立存储，不随目标走）。
async function renderHostKeyInfo(targetID) {
  var box = document.getElementById('hostkey-box');
  if (!box) {
    box = document.createElement('div');
    box.id = 'hostkey-box';
    box.className = 'hostkey-box';
    var anchor = document.getElementById('wrap-password');
    if (!anchor || !anchor.parentNode) return;
    anchor.parentNode.insertBefore(box, anchor);
  }
  box.innerHTML = '';
  if (!targetID) { box.hidden = true; return; }
  box.hidden = false;
  box.innerHTML = '<span class="hint">读取已记录的主机密钥…</span>';
  try {
    var r = await req('/api/hostkeys?target_id=' + encodeURIComponent(targetID));
    if (!r.host_key) {
      box.innerHTML = '<span class="hint">还没有记录这台主机的主机密钥（首次连接时会记录）。</span>';
      return;
    }
    var hk = r.host_key;
    box.innerHTML =
      '<div class="hostkey-line"><span>主机密钥</span><code>' + esc(hk.fingerprint) + '</code></div>' +
      '<div class="hostkey-line"><span>类型</span><code>' + esc(hk.key_type) + '</code></div>' +
      '<button id="hostkey-forget" class="danger">清除已记录的主机密钥</button>' +
      '<p class="hint">对端重装系统或更换密钥后指纹会变，连接会被拒绝；确认无误再清除，下次连接按新指纹重新记录。</p>';
    document.getElementById('hostkey-forget').addEventListener('click', async function () {
      if (!window.confirm('确定清除已记录的主机密钥？下次连接会按新指纹重新记录。')) return;
      try {
        await req('/api/hostkeys/forget', { method: 'POST', body: JSON.stringify({ target_id: targetID }) });
        window.AwdToast.ok('已清除，下次连接会重新记录');
        renderHostKeyInfo(targetID);
      } catch (e) { window.AwdToast.error('清除失败：' + e.message); }
    });
  } catch (e) {
    box.innerHTML = '<span class="hint error-text">读取主机密钥失败：' + esc(e.message) + '</span>';
  }
}

  async function refreshAll() {
    // 目标列表走共享缓存（targets.js），各视图读到的是同一份
    var r = await Promise.all([targets(), api.recent(), api.history()]);
    state.targets = r[0] || []; state.recent = r[1] || []; state.history = r[2] || [];
    renderSidebar(); renderStats();
  }

  function targets() {
    return window.AwdTargets ? window.AwdTargets.load() : api.targets();
  }

  async function refreshHistory() {
    try {
      var r = await Promise.all([api.recent(), api.history()]);
      state.recent = r[0] || []; state.history = r[1] || [];
      renderSidebar();
    } catch (e) {
      // 原来是空 catch：连接历史刷不出来时界面毫无反应，看着像"点了没生效"
      setStatus('刷新连接历史失败：' + e.message);
    }
  }

  // ---------------- 侧栏 ----------------

  // 标签列表的统一取值：后端把 tags 给成 null、字符串或对象时，
  // 后面那串 .some / .map / .join 都会当场抛错，这里先收成数组
  function tagList(t) {
    return (t && Array.isArray(t.tags)) ? t.tags : [];
  }

  function filteredTargets() {
    var k = state.keyword.trim().toLowerCase();
    if (!k) return state.targets;
    return state.targets.filter(function (t) {
      var tags = tagList(t);
      return String(t.name || '').toLowerCase().indexOf(k) >= 0 ||
        String(t.host || '').toLowerCase().indexOf(k) >= 0 ||
        tags.some(function (x) { return String(x == null ? '' : x).toLowerCase().indexOf(k) >= 0; });
    });
  }

  function renderSidebar() {
    var list = filteredTargets();
    var html = '';

    if (state.recent.length) {
      html += '<section><h4>最近连接<span class="count">' + state.recent.length + '</span></h4><ul>';
      html += state.recent.map(function (t) {
        return '<li data-act="connect" data-id="' + esc(t.id) + '" class="' + (state.activeTarget === t.id ? 'active' : '') + '">' +
          '<span class="dot ready"></span><span class="name">' + esc(t.name) + '</span>' +
          '<span class="addr">' + esc(t.username) + '@' + esc(t.host) + '</span></li>';
      }).join('');
      html += '</ul></section>';
    }

    html += '<section><h4>全部目标<span class="count">' + list.length + '</span></h4><ul>';
    html += list.map(function (t) {
      return '<li data-act="connect" data-id="' + esc(t.id) + '" class="' + (state.activeTarget === t.id ? 'active' : '') + '">' +
        '<span class="dot"></span><span class="name">' + esc(t.name) + '</span>' +
        '<span class="addr">' + esc(t.username) + '@' + esc(t.host) + ':' + esc(t.port) + '</span>' +
        ((tagList(t).length) ? '<span class="tags">' + tagList(t).map(function (x) { return esc(x); }).join(' · ') + '</span>' : '') +
        '<span class="row-actions">' +
        '<button data-act="edit" data-id="' + esc(t.id) + '">编辑</button>' +
        '<button data-act="test" data-id="' + esc(t.id) + '">测试</button>' +
        '<button class="danger" data-act="delete" data-id="' + esc(t.id) + '">删除</button>' +
        '</span></li>';
    }).join('');
    if (!list.length) {
      html += '<li class="empty-row">还没有目标，点上方「新建目标」添加一台主机。</li>';
    }
    html += '</ul></section>';

    if (state.history.length) {
      // 连接历史也给了清空入口：这张表以前只能等后台按保留期清理，
      // 用户没有任何办法清掉自己的连接流水
      html += '<section><h4>连接历史<span class="count">' + state.history.length + '</span>' +
        '<button class="mini-btn" data-act="clear-history" title="清空全部连接历史">清空</button>' +
        '</h4><ul class="history-list">';
      html += state.history.slice(0, 40).map(function (h) {
        return '<li data-act="reconnect" data-id="' + esc(h.target_id || '') + '">' +
          '<span class="name">' + esc(h.name || h.host) + '</span>' +
          '<span class="meta">' + esc(h.username) + '@' + esc(h.host) + '</span>' +
          '<span class="time">' + fmtTime(h.started_at) + '</span>' +
          '<span class="dur' + (h.error ? ' bad' : '') + '">' + fmtDuration(h) + '</span></li>';
      }).join('');
      html += '</ul></section>';
    }

    el.sidebar.innerHTML = html;
  }

  function renderStats() {
    el.statSessions.textContent = state.sessions.length + ' 个会话';
    el.statTargets.textContent = state.targets.length + ' 台目标';
  }

  // 清空连接历史。以前只有后台按保留期清理这一条路，
  // 用户想清掉自己的连接流水没有任何办法。
  async function clearHistory() {
    if (!state.history.length) return;
    // 不报条数：界面只取了前 200 条、只渲染前 40 条，
    // 报出来的数跟库里实际要删的对不上，反而误导
    if (!window.confirm('清空全部连接历史？这个动作不可撤销。')) return;
    try {
      var r = await req('/api/history', {
        method: 'POST',
        body: JSON.stringify({ all: true })
      });
      state.history = [];
      renderSidebar();
      if (window.AwdToast) window.AwdToast.ok('已清空 ' + (r.deleted || 0) + ' 条连接历史');
      setStatus('连接历史已清空');
    } catch (e) {
      if (window.AwdToast) window.AwdToast.error('清空连接历史失败\n\n' + e.message);
    }
  }

  // ---------------- 标签与终端 ----------------

  function activeSession() {
    for (var i = 0; i < state.sessions.length; i++) {
      if (state.sessions[i].id === state.active) return state.sessions[i];
    }
    return null;
  }

  function renderTabs() {
    // 整个 tabs 是重建的，先记住横向滚动位置 ——
    // 不保留的话每次点标签都会跳回最左边，开十几个会话时刚点的那个会跑到屏幕外
    var prevScroll = el.tabs.scrollLeft;
    if (!state.sessions.length) {
      el.tabs.innerHTML = '<div class="tabs-empty">没有打开的会话</div>';
    } else {
      el.tabs.innerHTML = state.sessions.map(function (s) {
        // 用真实的连接状态上色：掉线后标签还亮着绿灯、还能继续点，
        // 用户对着一个不会响应的终端敲半天命令是很容易发生的事
        var st = s.state || 'connecting';
        var label = st === 'ready' ? '已连接' : (st === 'closed' ? '连接已断开' : '连接中');
        return '<div class="tab ' + (state.active === s.id ? 'active' : '') + '" data-act="activate" data-id="' + esc(s.id) + '">' +
          '<span class="dot ' + st + '" title="' + label + '"></span>' +
          '<span class="title">' + esc(s.title) + '</span>' +
          '<span class="close" data-act="close" data-id="' + esc(s.id) + '">x</span></div>';
      }).join('');
    }
    el.tabs.scrollLeft = prevScroll;
    // 让激活的标签保持在视野里
    var activeTab = el.tabs.querySelector('.tab.active');
    if (activeTab && activeTab.scrollIntoView) {
      activeTab.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }
    renderWelcome();
    renderStats();
  }

  function renderWelcome() {
    var w = document.getElementById('welcome');
    if (state.sessions.length) { if (w) w.remove(); return; }
    if (w) return;
    var d = document.createElement('div');
    d.id = 'welcome';
    d.className = 'welcome';
    d.innerHTML = '<h2>awdshell</h2>' +
      '<p>从左侧点一台主机即可打开终端。第一次使用先「新建目标」。</p>' +
      '<ul><li>凭据加密保存在本机，不写入日志</li>' +
      '<li>连接历史会保留，随时可以一键重连</li>' +
      '<li>终端数据走本地 WebSocket，只监听 127.0.0.1</li></ul>';
    el.termArea.appendChild(d);
  }

  // 当前分屏能显示几个终端
  function gridCapacity() {
    if (state.grid === 'grid4') return 4;
    if (state.grid === 'cols2' || state.grid === 'rows2') return 2;
    return 1;
  }

  // 需要显示在格子里的会话（当前激活的那个排第一，保证一定可见）
  function visibleSessions() {
    var cap = gridCapacity();
    var list = state.sessions.slice();
    var idx = -1;
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === state.active) { idx = i; break; }
    }
    if (idx > 0) {
      var first = list.splice(idx, 1)[0];
      list.unshift(first);
    }
    return list.slice(0, cap);
  }

  // 界面偏好（分屏模式等）统一走 views.js 里的 AwdPrefs
  function prefGet(key, def) {
    return window.AwdPrefs ? window.AwdPrefs.get(key, def) : def;
  }
  function prefSet(key, value) {
    if (window.AwdPrefs) window.AwdPrefs.set(key, value);
  }

  function setGrid(mode) {
    state.grid = mode;
    prefSet('grid', mode);
    var btns = document.querySelectorAll('[data-grid]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', btns[i].dataset.grid === mode);
    }
    // 分屏时把右侧面板收起来：一块屏要放几个终端，再占 470px 每格就太窄了
    var sideClosed = false;
    if (mode !== '1') {
      var fa = document.getElementById('files-area');
      var ma = document.getElementById('monitor-area');
      if ((fa && !fa.hidden) || (ma && !ma.hidden)) {
        if (fa) fa.hidden = true;
        if (ma) ma.hidden = true;
        window.dispatchEvent(new Event('awdshell:monitor-hide'));
        var fb = document.getElementById('btn-files');
        var mb = document.getElementById('btn-monitor');
        var rz = document.getElementById('files-resizer');
        if (fb) fb.classList.remove('active');
        if (mb) mb.classList.remove('active');
        if (rz) rz.hidden = true;
        sideClosed = true;
      }
    }
    applyActive();
    var label = mode === '1' ? '单屏显示' :
      (mode === 'cols2' ? '左右分屏' : (mode === 'rows2' ? '上下分屏' : '四格分屏'));
    setStatus(sideClosed ? (label + '（已收起右侧面板腾出宽度）') : label);
  }

  // 分屏时多出来的格子不是空白：直接列出目标，点一下就连上去。
  // 之前这里是空的，只能自己想到"去左边点一台主机"，等于没给入口。
  function renderEmptyPanes() {
    var cap = gridCapacity();
    // 一个会话都没有的时候不造空面板：欢迎页已经占满整个工作区，
    // 再来一块"这一格空着"会同时出现两层提示，看着像界面坏了
    if (!state.sessions.length) {
      var stale = document.querySelectorAll('.term-empty-pane');
      for (var k = 0; k < stale.length; k++) stale[k].remove();
      return;
    }
    var need = Math.max(0, cap - visibleSessions().length);
    var panes = document.querySelectorAll('.term-empty-pane');
    for (var i = panes.length - 1; i >= need; i--) panes[i].remove();
    if (need <= 0) return;

    for (var j = document.querySelectorAll('.term-empty-pane').length; j < need; j++) {
      var d = document.createElement('div');
      d.className = 'term-empty-pane';
      var btns = state.targets.map(function (tg) {
        // 目标名、用户名、主机都来自用户输入，一律转义后再拼
        return '<button class="ep-target" data-connect="' + esc(tg.id) + '">' +
          '<span class="ep-name">' + esc(tg.name) + '</span>' +
          '<span class="ep-addr">' + esc(tg.username) + '@' + esc(tg.host) + '</span>' +
          '</button>';
      }).join('') || '<div class="ep-hint">还没有目标，先点左上角「新建目标」</div>';

      d.innerHTML = '<div class="ep-inner">' +
        '<div class="ep-title">这一格空着</div>' +
        '<div class="ep-hint">点下面的主机就在这里开一个终端；也可以先在标签栏切换会话</div>' +
        '<div class="ep-targets">' + btns + '</div>' +
        '</div>';

      (function (pane) {
        pane.addEventListener('click', function (e) {
          var btn = e.target.closest ? e.target.closest('[data-connect]') : null;
          if (btn) connect(btn.getAttribute('data-connect'));
        });
      })(d);

      el.termArea.appendChild(d);
    }
  }

  function applyActive() {
    var visible = visibleSessions();
    state.sessions.forEach(function (s) {
      var on = visible.indexOf(s) >= 0;
      s.host.classList.toggle('visible', on);
      s.host.classList.toggle('pane-active', on && s.id === state.active);
    });
    el.termArea.className = 'term-area grid-' + state.grid;
    renderEmptyPanes();
    var s = activeSession();
    setTimeout(function () {
      visible.forEach(function (x) { safeFit(x); });
      if (s && shouldFocusTerminal()) s.term.focus();
    }, 40);
  }

  // 只有用户此刻不在输入框里、也没有弹窗打开时，才把焦点交给终端。
  // 否则在搜索框打字时顺手点一下分屏（或后台某个 connect 返回），
  // 后面敲的字符会被当成命令直接发到远程主机。
  function shouldFocusTerminal() {
    var m = document.getElementById('modal');
    var fm = document.getElementById('file-modal');
    if (m && !m.hidden) return false;
    if (fm && !fm.hidden) return false;
    var ae = document.activeElement;
    if (!ae || ae === document.body) return true;
    var tag = (ae.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return false;
    if (ae.isContentEditable) return false;
    return true;
  }

  // 建立（或重建）一条终端数据通道。
  // 抽成独立函数是为了断线重连：重连只需换一个新令牌再走一遍这里。
  function openWS(s, token) {
    var ws = new WebSocket(WS_BASE + '/ws/term/' + s.id + '?token=' + encodeURIComponent(token));
    ws.binaryType = 'arraybuffer';
    // 先占位、再关旧的：这样旧 socket 迟到的 onclose 会因 `s.ws !== ws` 被忽略，
    // 不会再去拉一条重连链（同一会话两个 WebSocket 会让终端输出交错，
    // 而且服务端令牌是一次性的，第二次 attach 会把第一次的作废）。
    var old = s.ws;
    s.ws = ws;
    if (old && old !== ws) {
      try { old.close(); } catch (e) { /* 忽略 */ }
    }
    s.warnedClosed = false;

    ws.onopen = function () {
      s.state = 'ready';
      s.reconnectAttempt = 0;
      renderTabs();
      safeFit(s);
    };
    ws.onmessage = function (ev) {
      // 这个 socket 已经被新的替换掉了：迟到的消息必须和 onclose 一样直接忽略。
      // 少了这道守卫时，旧 socket 迟来的一条 exit 会把**新**连接中的会话标成
      // state='closed' + gaveUp=true（标签显示"连接已结束"），而且新 socket 后续的
      // onclose 会被 gaveUp 挡掉 —— 那个标签此后不再自动重连。
      if (s.ws !== ws) return;
      if (typeof ev.data === 'string') {
        try {
          var m = JSON.parse(ev.data);
          if (m.type === 'exit') {
            s.term.write('\r\n\x1b[33m[连接已结束]\x1b[0m\r\n');
            s.state = 'closed';
            s.gaveUp = true; // shell 正常退出，不必重连
            renderTabs();
            setStatus(s.title + ' 会话已结束（这个标签已断开，可直接关闭）');
            // 主动关掉 WS：服务端 handler 没有读超时，不关的话它会一直
            // 阻塞在 ReadMessage，每个自然退出的会话都留一个 goroutine 和一条连接
            try { ws.close(); } catch (e) { /* 忽略 */ }
          }
        } catch (e) { /* 忽略 */ }
        return;
      }
      s.term.write(new Uint8Array(ev.data));
    };
    ws.onclose = function () {
      // 这个 socket 已经被新的替换掉了：迟到的 onclose 必须直接忽略。
      // 没有这道守卫时，重连链里 `s.reconnecting` 会在 openWS 之前就置回 false，
      // 于是旧 socket 的 onclose 再拉一条链 —— 同一会话出现两个 WebSocket。
      if (s.ws !== ws) return;
      if (s.gaveUp || s.closing) return;
      s.state = 'closed';
      renderTabs();
      scheduleReconnect(s);
    };
    // onerror 后面一定跟着 onclose，统一在 onclose 里处理
    ws.onerror = function () { /* 见 onclose */ };
  }

  // 断线重连的退避间隔（毫秒）
  var RECONNECT_DELAYS = [1000, 2000, 4000, 8000];

  // 断线后自动重连。
  // 服务端的会话在宽限期内还活着（默认 30 秒），重新附着上去就能接着用，
  // 终端里的上下文与滚动历史都不会丢；一直连不上才放弃。
  function scheduleReconnect(s) {
    if (s.reconnecting || s.closing || s.gaveUp) return;
    s.reconnecting = true;
    var attempt = 0;

    function tryOnce() {
      if (s.closing || s.gaveUp) { s.reconnecting = false; return; }
      s.state = 'connecting';
      renderTabs();
      setStatus(s.title + ' 连接断开，正在重连…');
      api.attachSession(s.id).then(function (h) {
        if (s.closing || s.gaveUp) { s.reconnecting = false; return; }
        s.reconnecting = false;
        s.term.write('\r\n\x1b[32m[已重新连接]\x1b[0m\r\n');
        openWS(s, h.ws_token);
      }).catch(function () {
        attempt++;
        if (attempt >= RECONNECT_DELAYS.length) {
          s.reconnecting = false;
          s.state = 'closed';
          s.warnedClosed = true;
          renderTabs();
          s.term.write('\r\n\x1b[31m[重连失败，会话已结束]\x1b[0m\r\n');
          setStatus(s.title + ' 重连失败，会话已结束');
          return;
        }
        setTimeout(tryOnce, RECONNECT_DELAYS[attempt]);
      });
    }
    setTimeout(tryOnce, RECONNECT_DELAYS[0]);
  }

  // 当前激活会话对应的目标。
  // 各视图打开时用它默认跟随当前会话；没有会话时返回空串，视图保持原样。
  window.AwdActiveTarget = function () {
    var s = activeSession();
    return s ? s.targetId : '';
  };

  // 统一的"导出一份文件"出口。
  //
  // 配了默认下载目录就走后端直接落盘 —— 浏览器下载只能落到系统默认下载目录，
  // 用户选不了地方，对运维来说很别扭（报告要交给别人、CSV 要接着处理）。
  // 没配目录就退回浏览器下载，保持和以前一样的行为。
  //
  // 返回：走后端时是保存到的完整路径；走浏览器时是 null。
  window.AwdSaveFile = async function (name, content, mime) {
    var dir = (window.AWD_SETTINGS && window.AWD_SETTINGS.download_dir) || '';
    if (dir) {
      try {
        var r = await req('/api/system/save-file', {
          method: 'POST',
          body: JSON.stringify({ name: name, content: content })
        });
        return r.saved_to || null;
      } catch (e) {
        // 后端这里会因为"没配默认下载目录 / 目录不可写"回 400。
        // 原来异常直接冒到调用方，用户看到的是"保存失败：没有配置默认下载目录"，
        // 而注释里承诺过"没配目录就退回浏览器下载" —— 那条路必须真的走通。
        if (window.AwdToast) {
          window.AwdToast.warn('后端保存失败（' + e.message + '），已改为浏览器下载。\n\n' +
            '想让文件直接落到指定目录，去「设置」里填默认下载目录。');
        }
      }
    }
    var blob = new Blob([content], { type: mime || 'application/octet-stream' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
    return null;
  };

  function safeFit(s) {
    try { s.fit.fit(); } catch (e) { /* 容器不可见时忽略 */ }
  }


  // 登录后进入配置的初始目录。目录不存在时由后端回退到家目录（此处只负责发 cd）。
  function applyStartDir(sessionId, targetId) {
    req('/api/files/startdir?target_id=' + encodeURIComponent(targetId)).then(function (info) {
      if (info.fallback) {
        setStatus('初始目录 ' + info.wanted + ' 不存在，已回退到 ' + info.path);
      }
      if (!info.path || info.source !== 'configured') return; // 没配置就不发命令，SSH 默认即家目录
      setTimeout(function () {
        var s = findSession(sessionId);
        if (s && s.ws && s.ws.readyState === WebSocket.OPEN) {
          s.ws.send(encoder.encode('cd ' + shellQuote(info.path) + '\n'));
          window.dispatchEvent(new CustomEvent('awdshell:cwd', { detail: { path: info.path } }));
        }
      }, 500);
    }).catch(function (e) {
      // 原来是空 catch：初始目录读不到时什么提示都没有，用户只看到终端停在别处
      setStatus('初始目录信息读取失败：' + e.message + '（不影响终端使用）');
    });
  }

  // 单引号安全引用（远端 shell 用）
  function shellQuote(p) {
    return "'" + String(p).replace(/'/g, "'\\''") + "'";
  }

  function findSession(id) {
    for (var i = 0; i < state.sessions.length; i++) {
      if (state.sessions[i].id === id) return state.sessions[i];
    }
    return null;
  }

  function connect(targetId) {
    var t = state.targets.filter(function (x) { return x.id === targetId; })[0];
    state.activeTarget = targetId;
    renderSidebar();
    setStatus('正在连接 ' + (t ? t.name + '（' + t.host + ':' + t.port + '）' : targetId) + ' ...');

    api.openSession(targetId, 120, 32).then(function (handle) {
      openTerminal(handle);
      setStatus('已连接 ' + (t ? t.username + '@' + t.host : handle.title));
      // 通知文件面板：切到同一个目标（同屏使用时省一次手动选择）
      window.dispatchEvent(new CustomEvent('awdshell:connected', { detail: { targetId: targetId } }));
      applyStartDir(handle.session_id, targetId);
      refreshHistory();
    }).catch(function (e) {
      setStatus('连接失败：' + e.message);
      // 防御：toast.js 万一没加载，不能把真实错误再吞一次（原来这里会抛
      // "Cannot read properties of undefined"，把"连接为什么失败"彻底盖住）
      if (window.AwdToast && window.AwdToast.error) {
        window.AwdToast.error('连接失败\n\n' + e.message);
      } else {
        console.error('连接失败：' + e.message);
      }
    });
  }

  // showTermMenu 是一个极简的右键菜单：只有剪贴板三项，不需要通用组件。
  var termMenuEl = null;
  function showTermMenu(x, y, items) {
    if (termMenuEl) { termMenuEl.remove(); termMenuEl = null; }
    var menu = document.createElement("div");
    menu.className = "term-menu";
    menu.style.left = x + "px";
    menu.style.top = y + "px";
    items.forEach(function (it) {
      var row = document.createElement("div");
      row.className = "term-menu-item" + (it.enabled === false ? " disabled" : "");
      row.textContent = it.label;
      row.addEventListener("mousedown", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        if (it.enabled === false) return;
        it.run();
        if (termMenuEl) { termMenuEl.remove(); termMenuEl = null; }
      });
      menu.appendChild(row);
    });
    document.body.appendChild(menu);
    termMenuEl = menu;
    var close = function () {
      if (termMenuEl) { termMenuEl.remove(); termMenuEl = null; }
      document.removeEventListener("mousedown", close, true);
      document.removeEventListener("keydown", close, true);
      window.removeEventListener("blur", close);
    };
    setTimeout(function () {
      document.addEventListener("mousedown", close, true);
      document.addEventListener("keydown", close, true);
      window.addEventListener("blur", close);
    }, 0);
  }

  function openTerminal(handle) {
    var S = window.AWD_SETTINGS || {};
    var term = new window.Terminal({
      fontFamily: '"JetBrains Mono", "Cascadia Code", Consolas, "Sarasa Mono SC", monospace',
      fontSize: S.term_font_size || 14,
      lineHeight: 1.2,
      cursorBlink: true,
      scrollback: S.term_scrollback || 10000,
      theme: {
        background: '#0f1115', foreground: '#e6eaf2', cursor: '#4c8dff', selectionBackground: '#2a323e',
        black: '#1c2129', red: '#ff5c5c', green: '#34d399', yellow: '#ffb020',
        blue: '#4c8dff', magenta: '#c792ea', cyan: '#2dd4bf', white: '#e6eaf2',
        brightBlack: '#6b7480', brightRed: '#ff8080', brightGreen: '#5ee0b0', brightYellow: '#ffc85a',
        brightBlue: '#6ba1ff', brightMagenta: '#d8b0f0', brightCyan: '#5fe3d4', brightWhite: '#ffffff'
      }
    });
    var fit = new window.FitAddon.FitAddon();
    term.loadAddon(fit);

    // ── 剪贴板 ──────────────────────────────────────────────
    // xterm 的默认行为是「Ctrl+C 一律发 SIGINT 给远端」，选中了文本也没法复制 ——
    // 唯一的复制入口变成鼠标拖选之后没有任何快捷键（用户报的就是这个）。
    // 这里补上 Windows Terminal / PuTTY 那套习惯：
    //   按键分配照 Linux 终端惯例，**不动 Ctrl+C**：
    //     Ctrl+Shift+C / Ctrl+Insert   -> 复制
    //     Ctrl+Shift+V / Shift+Insert  -> 粘贴（裸 Ctrl+V 交给浏览器默认 paste）
    //     Ctrl+C                       -> 永远放行，仍是 SIGINT（有选区也不抢）
    //     Ctrl+A                       -> 不拦，shell 里它是「移到行首」
    //   全选、复制、粘贴也在终端右键菜单里
    function copySelection(text) {
      if (!text) return false;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function () { legacyCopy(text); });
      } else {
        legacyCopy(text);
      }
      return true;
    }
    // WebView2 里 navigator.clipboard 在部分场景会拒绝（权限/焦点），留一条老路
    function legacyCopy(text) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch (e) { /* 两条路都不行就只能算了 */ }
      document.body.removeChild(ta);
    }
    function pasteFromClipboard() {
      if (navigator.clipboard && navigator.clipboard.readText) {
      navigator.clipboard.readText().then(function (txt) {
        if (txt) term.paste(txt);
      }).catch(function () { /* 读不到就让用户用 Ctrl+Shift+V 或鼠标中键 */ });
      }
    }

    var termKeyHandler = function (e) {
      if (e.type !== "keydown") return true;
      var ctrl = e.ctrlKey || e.metaKey;
      var key = e.key;

      // **Ctrl+C 永远放行**：它是 SIGINT，有选区残留时也要能中断命令。
      // 复制一律走 Ctrl+Shift+C（Linux 终端惯例），Ctrl+Insert 作为老习惯保留。
      if (ctrl && e.shiftKey && (key === "c" || key === "C")) {
        var sel = term.getSelection();
        if (sel) { copySelection(sel); return false; }
        return false;   // 没选区也拦，免得 Shift+Ctrl+C 被当成别的组合发下去
      }
      if (e.ctrlKey && key === "Insert") {
        var sel2 = term.getSelection();
        if (sel2) { copySelection(sel2); return false; }
        return true;
      }
      // 粘贴：Ctrl+Shift+V / Shift+Insert。
      // 裸 Ctrl+V 交给浏览器默认的 paste 事件（xterm 自己会处理），不要拦。
      if ((ctrl && e.shiftKey && (key === "v" || key === "V")) || (e.shiftKey && key === "Insert")) {
        pasteFromClipboard();
        return false;
      }
      // 注意：**不要拦 Ctrl+A** —— shell 里它是「光标移到行首」，很重要的编辑键。
      // 全选走右键菜单。
      return true;
    };
    // 防御：vendored xterm 换版本、或测试替身没实现这个方法时，不能让
    // "注册一个快捷键"把整条连接路径带崩（openTerminal 抛错会进 connect 的 catch）。
    if (typeof term.attachCustomKeyEventHandler === "function") {
      term.attachCustomKeyEventHandler(termKeyHandler);
    }


    var host = document.createElement('div');
    host.className = 'term-host';

    // 分屏时每格顶部显示主机名（单屏模式下这条会被 CSS 隐藏），
    // 否则几格并排时分不清哪个是哪个。
    var head = document.createElement('div');
    head.className = 'pane-head';
    var ptitle = document.createElement('span');
    ptitle.className = 'pane-title';
    ptitle.textContent = handle.title;
    var pclose = document.createElement('span');
    pclose.className = 'pane-close';
    pclose.textContent = 'x';
    pclose.title = '关闭这个会话';
    head.appendChild(ptitle);
    head.appendChild(pclose);

    var body = document.createElement('div');
    body.className = 'pane-body';
    host.appendChild(head);
    host.appendChild(body);
    el.termArea.appendChild(host);
    // 右键菜单：WebView2 的系统菜单里没有剪贴板项，自己给三个常用动作
    body.addEventListener("contextmenu", function (ev) {
      ev.preventDefault();
      var hasSel = !!term.getSelection();
      showTermMenu(ev.clientX, ev.clientY, [
        { label: "复制", enabled: hasSel, run: function () { copySelection(term.getSelection()); } },
        { label: "粘贴", run: pasteFromClipboard },
        { label: "全选", run: function () { if (term.selectAll) term.selectAll(); } }
      ]);
    });

    // 同一台主机开多个会话时标题完全一样，标签栏上分不清谁是谁，第二个起加序号
    var baseTitle = handle.title;
    var sameCount = state.sessions.filter(function (x) { return x.baseTitle === baseTitle; }).length;
    var s = {
      id: handle.session_id, targetId: handle.target_id, baseTitle: baseTitle,
      title: sameCount ? baseTitle + ' (' + (sameCount + 1) + ')' : baseTitle,
      term: term, fit: fit, host: host, body: body, ws: null, state: 'connecting'
    };
    state.sessions.push(s);
    term.open(body);

    pclose.addEventListener('click', function (e) { e.stopPropagation(); closeTab(s.id); });
      // 点哪一格哪一格就成为当前会话（已经是当前的就不重复处理）。
      //
      // **必须用 capture 阶段（第三个参数 true）**：xterm 内部那层输入元素会在冒泡阶段
      // stopPropagation，挂普通监听时「点终端区域」压根收不到事件 —— 分屏下点第二格
      // 不会切换当前会话，于是文件面板的「跟随当前会话」看起来跟的是第一格。
      host.addEventListener('mousedown', function () {
        if (state.active !== s.id) activate(s.id);
      }, true);
      // focusin 兜住不经 mousedown 的路径：Tab 切焦点、点标题栏空白等。
      host.addEventListener('focusin', function () {
        if (state.active !== s.id) activate(s.id);
      }, true);
    openWS(s, handle.ws_token);

    term.onData(function (d) {
      var ws = s.ws;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(encoder.encode(d));
        return;
      }
      // 连接已断时不能静默吞掉输入：用户会以为命令发出去了，
      // 实际什么都没发生，白等结果
      if (!s.warnedClosed) {
        s.warnedClosed = true;
        term.write('\r\n\x1b[31m[连接已断开，这里的输入不会被执行]\x1b[0m\r\n');
      }
    });
    term.onResize(function (size) {
      var ws = s.ws;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows }));
      }
    });

    // OSC 7：shell 报告当前工作目录（file://host/path），用于让文件面板跟随终端。
    if (term.parser && term.parser.registerOscHandler) {
      term.parser.registerOscHandler(7, function (data) {
        var m = /^file:\/\/[^\/]*(\/.*)$/.exec(String(data));
        if (m && m[1]) {
          var cwd = m[1];
          try { cwd = decodeURIComponent(cwd); } catch (e) { /* 保持原样 */ }
          window.dispatchEvent(new CustomEvent('awdshell:cwd', { detail: { path: cwd } }));
        }
        return false;
      });
    }

    state.active = s.id;
    renderTabs();
    applyActive();
  }

  function activate(id) {
    state.active = id;
    var s = activeSession();
    if (s) {
      var t = state.targets.filter(function (x) { return x.id === s.targetId; })[0];
      if (t) state.activeTarget = t.id;
    }
    renderTabs();
    renderSidebar();
    applyActive();
    // 切换标签时也通知文件面板：让它跟着当前终端走，而不是只在打开新会话时切。
    if (s) {
      window.dispatchEvent(new CustomEvent('awdshell:connected', { detail: { targetId: s.targetId } }));
    }
  }

  function closeTab(id) {
    var i = -1;
    for (var k = 0; k < state.sessions.length; k++) if (state.sessions[k].id === id) i = k;
    if (i < 0) return;
    var s = state.sessions[i];
    s.closing = true; // 用户主动关闭，不要触发自动重连
    api.closeSession(id).catch(function () { /* 可能已自然结束 */ });
    try { if (s.ws) s.ws.close(); } catch (e) { /* 忽略 */ }
    s.term.dispose();
    s.host.remove();
    state.sessions.splice(i, 1);
    // 告诉文件面板：这个目标还有没有别的会话开着（都关掉就把面板收起来）
    window.dispatchEvent(new CustomEvent('awdshell:session-closed', {
      detail: {
        targetId: s.targetId,
        remainingTargets: state.sessions.map(function (x) { return x.targetId; })
      }
    }));
    if (state.active === id) {
      var next = state.sessions[i - 1] || state.sessions[i];
      state.active = next ? next.id : '';
      // 自动切到别的标签时也要广播一次，否则各视图还停在被关掉那台上，
      // 而它们的按钮却显示"跟随会话"，看起来就像跟随坏了
      if (next) {
        window.dispatchEvent(new CustomEvent('awdshell:connected', { detail: { targetId: next.targetId } }));
      }
    }
    renderTabs();
    applyActive();
    refreshHistory();
  }

  // ---------------- 表单 ----------------

  function openForm(id) {
    state.editing = id || '';
    el.formError.textContent = '';
    if (id) {
      var t = state.targets.filter(function (x) { return x.id === id; })[0];
      if (!t) return;
      el.modalTitle.textContent = '编辑目标';
      el.f.name.value = t.name; el.f.host.value = t.host; el.f.port.value = t.port;
      el.f.username.value = t.username; el.f.auth.value = t.auth_kind || 'password';
      el.f.group.value = t.group || ''; el.f.startdir.value = t.start_dir || '';
      if (el.f.tags) el.f.tags.value = (t.tags || []).join(', ');
      renderHostKeyInfo(id);
      el.f.password.value = ''; el.f.privatekey.value = ''; el.f.passphrase.value = '';
      el.f.password.placeholder = '留空表示不修改已保存的密码';
    } else {
      el.modalTitle.textContent = '新建目标';
      el.f.name.value = ''; el.f.host.value = ''; el.f.port.value = 22;
      el.f.username.value = 'root'; el.f.auth.value = 'password'; el.f.group.value = ''; el.f.startdir.value = '';
      if (el.f.tags) el.f.tags.value = '';
      renderHostKeyInfo('');
      el.f.password.value = ''; el.f.privatekey.value = ''; el.f.passphrase.value = '';
      el.f.password.placeholder = '';
    }
    toggleAuth();
    el.modal.hidden = false;
    el.f.name.focus();
  }

  function closeForm() { el.modal.hidden = true; }

  function toggleAuth() {
    var isPwd = el.f.auth.value === 'password';
    el.wrapPassword.hidden = !isPwd;
    el.wrapKey.hidden = isPwd;
  }

  async function saveForm() {
    if (state.saving) return;
    el.formError.textContent = '';

    // 端口先校验：以前 99999 或 -1 也能存进去，连接时才失败，用户不知道错在哪
    var portRaw = el.f.port.value.trim();
    var port = parseInt(portRaw, 10);
    if (portRaw === '' ) {
      port = 22;
    } else if (!/^\d+$/.test(portRaw) || port < 1 || port > 65535) {
      el.formError.textContent = '端口要填 1 到 65535 之间的数字（默认 22）';
      state.saving = false;
      return;
    }
    if (!el.f.name.value.trim()) {
      el.formError.textContent = '名称不能为空';
      state.saving = false;
      return;
    }
    if (!el.f.host.value.trim()) {
      el.formError.textContent = '主机不能为空';
      state.saving = false;
      return;
    }
    if (!el.f.username.value.trim()) {
      el.formError.textContent = '用户名不能为空';
      state.saving = false;
      return;
    }

    state.saving = true;
    var body = {
      id: state.editing,
      name: el.f.name.value.trim(),
      host: el.f.host.value.trim(),
      port: port,
      username: el.f.username.value.trim(),
      auth_kind: el.f.auth.value,
      group: el.f.group.value.trim(),
      // 标签用逗号/空格分隔，统一成数组；之前表单里没有这个字段，
      // 搜索框却按标签匹配，等于有个能力用不了
      tags: (el.f.tags ? el.f.tags.value : '').split(/[,，\s]+/).map(function (x) {
        return x.trim();
      }).filter(Boolean),
      start_dir: el.f.startdir.value.trim(),
      password: el.f.password.value,
      private_key: el.f.privatekey.value,
      passphrase: el.f.passphrase.value
    };
    try {
      await api.saveTarget(body);
      closeForm();
      // 目标变了：让共享缓存失效并广播，各视图的下拉会一起刷新
      if (window.AwdTargets) window.AwdTargets.changed();
      else window.dispatchEvent(new Event('awdshell:targets-changed'));
      await refreshAll();
      setStatus('已保存');
    } catch (e) {
      el.formError.textContent = e.message;
    } finally {
      state.saving = false;
    }
  }

  function testTarget(id) {
    var t = state.targets.filter(function (x) { return x.id === id; })[0];
    var name = t ? t.name : id;
    setStatus('正在测试 ' + name + ' ...');
    api.testTarget(id).then(function (r) {
      setStatus(name + '：' + r.message);
    }).catch(function (e) {
      setStatus(name + ' 测试失败：' + e.message);
      window.AwdToast.error('测试连接失败\n\n' + e.message);
    });
  }

  // Ctrl+Tab 在标签之间循环切换
  function cycleTab(step) {
    var list = state.sessions;
    if (!list.length) return;
    var i = 0;
    for (var k = 0; k < list.length; k++) {
      if (list[k].id === state.active) { i = k; break; }
    }
    var next = (i + step + list.length) % list.length;
    activate(list[next].id);
  }

  function removeTarget(id) {
    var t = state.targets.filter(function (x) { return x.id === id; })[0];
    if (!t) return;
    var live = state.sessions.filter(function (s) { return s.targetId === id; }).length;
    var extra = live ? '\n\n它当前有 ' + live + ' 个打开的会话，会一并关闭。' : '';
    if (!window.confirm('删除目标「' + t.name + '」及其保存的凭据？' + extra)) return;
    api.deleteTarget(id).then(function () {
      // 这个目标已经不存在了：把相关会话关掉，并让各视图别再对着它发请求，
      // 否则下拉视觉上跳到第一台、请求却还打在已删除的那台上，弹"记录不存在"
      state.sessions.filter(function (s) { return s.targetId === id; }).forEach(function (s) {
        closeTab(s.id);
      });
      if (state.activeTarget === id) state.activeTarget = null;
      if (window.AwdTargets) window.AwdTargets.changed();
      else window.dispatchEvent(new Event('awdshell:targets-changed'));
      refreshAll();
      setStatus('已删除 ' + t.name);
    }).catch(function (e) { setStatus('删除失败：' + e.message); });
  }

  function reconnect(targetId) {
    if (!targetId) { setStatus('这条历史没有关联目标'); return; }
    var t = state.targets.filter(function (x) { return x.id === targetId; })[0];
    if (!t) { setStatus('该目标已不在列表中，请重新添加'); return; }
    connect(targetId);
  }

  // ---------------- 事件 ----------------

  function bind() {
    el.search.addEventListener('input', function () { state.keyword = el.search.value; renderSidebar(); });
    // 打完名字按回车直接连第一台匹配的主机，省得再去左边点一下
    el.search.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter') return;
      var k = el.search.value.trim().toLowerCase();
      var first = state.targets.filter(function (t) {
        if (!k) return true;
        return (String(t.name || '') + ' ' + String(t.host || '') + ' ' + tagList(t).join(' ')).toLowerCase().indexOf(k) >= 0;
      })[0];
      if (first) connect(first.id);
      else setStatus('没有匹配的主机');
    });
    $('btn-new').addEventListener('click', function () { openForm(''); });
    $('btn-cancel').addEventListener('click', closeForm);
    $('btn-save').addEventListener('click', saveForm);
    el.f.auth.addEventListener('change', toggleAuth);

    el.modal.addEventListener('click', function (e) { if (e.target === el.modal) closeForm(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !el.modal.hidden) closeForm();
      if (e.key === 'Enter' && !el.modal.hidden && e.target && e.target.tagName === 'INPUT') saveForm();

      // 终端里用不到这两个组合，留给界面：Ctrl+W 关标签、Ctrl+Tab 切换标签
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && (e.key === 'w' || e.key === 'W')) {
        if (state.active && el.modal.hidden) {
          e.preventDefault();
          closeTab(state.active);
        }
        return;
      }
      if (e.ctrlKey && e.key === 'Tab') {
        if (!state.sessions.length) return;
        e.preventDefault();
        cycleTab(e.shiftKey ? -1 : 1);
      }
    });

    el.sidebar.addEventListener('click', function (e) {
      var node = e.target.closest('[data-act]');
      if (!node) return;
      var act = node.dataset.act, id = node.dataset.id;
      if (act === 'connect') connect(id);
      else if (act === 'edit') openForm(id);
      else if (act === 'test') testTarget(id);
      else if (act === 'delete') removeTarget(id);
      else if (act === 'reconnect') reconnect(id);
      else if (act === 'clear-history') clearHistory();
    });

    el.tabs.addEventListener('click', function (e) {
      var node = e.target.closest('[data-act]');
      if (!node) return;
      if (node.dataset.act === 'close') closeTab(node.dataset.id);
      else if (node.dataset.act === 'activate') activate(node.dataset.id);
    });

    window.addEventListener('resize', function () {
      visibleSessions().forEach(function (s) { safeFit(s); });
    });

    var gridBtns = document.querySelectorAll('[data-grid]');
    for (var gi = 0; gi < gridBtns.length; gi++) {
      gridBtns[gi].addEventListener('click', function () { setGrid(this.dataset.grid); });
    }
  }

  async function boot() {
    el.version.textContent = CFG.version ? 'v' + CFG.version : '';
    bind();
    renderTabs();
    // 设置先加载，终端初始化时要用（字号、回滚行数）。
    try {
      window.AWD_SETTINGS = await req('/api/settings');
    } catch (e) {
      // 用默认值本身没错，但必须说出来：设置读不到时用户改字号、改下载目录
      // 都没反应（包括导出会因此退回浏览器下载），不说就像界面坏了
      if (window.AwdToast) window.AwdToast.warn('读取设置失败，已用默认值：' + e.message);
    }
    try {
      await refreshAll();
      setStatus('就绪');
    } catch (e) {
      setStatus('加载失败：' + e.message);
    }
  }

  boot();
})();
