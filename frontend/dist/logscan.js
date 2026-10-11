/* awdshell 日志检测：扫描远程日志里的攻击载荷与入侵痕迹。整页视图。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    targets: [],
    targetId: '',
    files: [],
    path: '',
    lines: 2000,
    kind: 'auto',
    // 是否跟随当前激活的终端会话；用户手动改过下拉就置 false
    followActive: true,
    scanning: false,
    result: null
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
    var u = ['B', 'KB', 'MB', 'GB'];
    var i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? Math.round(n) + ' B' : n.toFixed(n < 10 ? 2 : 1) + ' ' + u[i]);
  }

  // 级别统一显示中文：之前日志检测用英文、态势用中文，扫完一份日志
  // 还得在两种标签之间换算一下
  function sevLabel(s) {
    return { critical: '严重', high: '高', medium: '中', low: '低' }[s] || s;
  }

  function setStatus(msg) {
    var el = $('status');
    if (el) el.textContent = msg;
  }

  // level: 空 = 普通提示；'warn' = 需要留意（黄）；其它真值 = 失败（红）。
  // 以前只有布尔 isError —— 但"结果不完整"既不是成功、也不该看起来像失败：
  // 用红色会和"检测失败"混淆，可它又必须显眼，所以加中间态。
  function hint(msg, level) {
    var el = $('ls-hint');
    if (!el) return;
    el.textContent = msg || '';
    el.className = 'ls-hint' + (level === 'warn' ? ' warn' : (level ? ' error-text' : ''));
  }

  async function req(path, init) {
    var opt = Object.assign({ headers: { 'Content-Type': 'application/json' } }, init || {});
    var res = await fetch(API + path, opt);
    if (!res.ok) {
      var msg = res.status + ' ' + res.statusText;
      try { var j = await res.json(); if (j && j.error) msg = j.error; } catch (e) { /* 忽略 */ }
      // 各视图各有一份 req，统一把状态码挂在错误上，调用方才好按语义分支。
      var lErr = new Error(msg);
      lErr.status = res.status;
      throw lErr;
    }
    return res.json();
  }

  // ---------- 渲染 ----------

  function renderShell() {
    $('logscan-area').innerHTML =
      '<div class="ls-wrap">' +
      '  <div class="view-head">' +
      '    <span class="view-title">日志检测</span>' +
      '    <button class="view-close">关闭</button>' +
      '  </div>' +
      '  <div class="ls-toolbar">' +
      '    <select id="ls-target" class="ls-target"></select>' +
      '    <button id="ls-follow-state" class="awd-follow" title=""></button>' +
      '    <select id="ls-file" class="ls-file"></select>' +
      '    <input id="ls-path" class="ls-path" spellcheck="false" placeholder="也可以直接填路径，如 /var/log/myapp/app.log，回车即检测" />' +
      '    <select id="ls-kind" class="ls-kind" title="不同日志该跑不同的规则集：Web 攻击特征不会出现在 sshd 日志里">' +
      '      <option value="auto" selected>类型：自动判断</option>' +
      '      <option value="web">强制 Web 日志</option>' +
      '      <option value="system">强制系统日志</option>' +
      '      <option value="all">不分类（全量规则）</option>' +
      '    </select>' +
      '    <select id="ls-lines" class="ls-lines">' +
      '      <option value="500">最近 500 行</option>' +
      '      <option value="2000" selected>最近 2000 行</option>' +
      '      <option value="5000">最近 5000 行</option>' +
      '      <option value="20000">最近 20000 行</option>' +
      '    </select>' +
      '    <button id="ls-scan" class="primary">开始检测</button>' +
      '    <button id="ls-export" title="把命中的行与关联结论导成 CSV">导出结果</button>' +
      '  </div>' +
      '  <div class="ls-hint-line"><span class="ls-hint" id="ls-hint"></span></div>' +
      '  <div class="ls-body" id="ls-body">' +
      '    <div class="ls-empty">选择目标与日志文件，然后点「开始检测」。<br>' +
      '      规则覆盖：SQL 注入、XSS、命令注入、路径穿越、WebShell、扫描器、敏感文件探测、JNDI 注入、' +
      '      反序列化、认证爆破、提权、持久化、挖矿外联。</div>' +
      '  </div>' +
      '</div>';

    $('ls-target').addEventListener('change', function () {
      state.targetId = this.value;
      // 用户手动选了目标：这个视图锁定它，不再跟着会话跑
      state.followActive = false;
      state.result = null;
      loadFiles();
    });
    $('ls-file').addEventListener('change', function () {
      state.path = this.value;
      if ($('ls-path')) $('ls-path').value = this.value;
    });
    // 自定义路径：探测不到的日志（业务自己的目录、容器挂载进来的日志等）直接手填
    $('ls-path').addEventListener('input', function () { state.path = this.value.trim(); });
    $('ls-path').addEventListener('keydown', function (e) { if (e.key === 'Enter') scan(); });
    $('ls-lines').addEventListener('change', function () { state.lines = parseInt(this.value, 10) || 2000; });
    $('ls-kind').addEventListener('change', function () { state.kind = this.value; });
    $('ls-scan').addEventListener('click', scan);
    $('ls-export').addEventListener('click', exportCSV);
  }

  // 跟随状态可见 + 一键恢复（锁定是隐形的，用户会以为界面坏了）
  function renderSyncState() {
    if (!window.AwdViews) return;
    window.AwdViews.followButton('ls-follow-state', state.followActive, '检测目标', function () {
      state.followActive = true;
      syncToActiveSession();
      renderTargets();
      loadFiles();
      hint('已恢复跟随当前会话');
    });
  }

  function renderTargets() {
    var sel = $('ls-target');
    renderSyncState();
    sel.innerHTML = state.targets.map(function (t) {
      return '<option value="' + esc(t.id) + '"' + (t.id === state.targetId ? ' selected' : '') + '>' + esc(t.name) + '</option>';
    }).join('') || '<option value="">无目标</option>';
  }

  function renderFiles() {
    var sel = $('ls-file');
    if (!state.files.length) {
      sel.innerHTML = '<option value="">未发现常见日志</option>';
      return;
    }
    sel.innerHTML = state.files.map(function (f) {
      return '<option value="' + esc(f.path) + '">' + esc(f.path) + '（' + esc(f.kind) + '，' + fmtBytes(f.size) + '）</option>';
    }).join('');
    // 只在用户还没手填路径时才用探测结果，否则会把输入框里的路径冲掉
    if (!$('ls-path') || !$('ls-path').value.trim() || !state.path) {
      state.path = state.files[0].path;
      if ($('ls-path')) $('ls-path').value = state.path;
    }
  }

  function renderResult(res) {
    state.result = res;
    var sev = res.by_severity || {};
    var stat = function (cls, label, n) {
      return '<div class="ls-stat ' + cls + '"><span class="n">' + (n || 0) + '</span><span class="l">' + label + '</span></div>';
    };

    // 跨行关联（爆破统计、失败后成功等）单行规则看不出来，放在最上面
    var corr = (res.correlations || []).map(function (c) {
      var ev = (c.evidence && c.evidence.length)
        ? '<div class="corr-evidence">' + c.evidence.map(function (e) { return '<div>' + esc(e) + '</div>'; }).join('') + '</div>'
        : '';
      var meta = [];
      if (c.source_ip) meta.push('来源 ' + c.source_ip);
      if (c.failures) meta.push('失败 ' + c.failures + ' 次');
      if (c.successes) meta.push('成功 ' + c.successes + ' 次');
      // first_line/last_line 不在这里单独 esc：整段 meta 最后会 esc 一次
      //（单独 esc 会变成 &amp;lt; 这种双重转义，显示成字面量的 &lt;）
      if (c.first_line) meta.push('行 ' + c.first_line + (c.last_line && c.last_line !== c.first_line ? '-' + c.last_line : ''));
      return '<div class="ls-corr ' + esc(c.severity) + '">' +
        '<div class="ls-corr-head">' +
        '  <span class="sev ' + esc(c.severity) + '">' + esc(c.severity) + '</span>' +
        '  <span class="corr-title">' + esc(c.title) + '</span>' +
        (meta.length ? '<span class="corr-meta">' + esc(meta.join(' · ')) + '</span>' : '') +
        '</div>' +
        '<div class="corr-detail">' + esc(c.detail) + '</div>' +
        ev +
        '</div>';
    }).join('');

    if (!res.hits || !res.hits.length) {
      $('ls-body').innerHTML =
        '<div class="ls-stats">' + stat('', '扫描行数', res.scanned) + '</div>' +
        (corr ? '<div class="ls-corr-wrap"><div class="ls-section-title">关联发现</div>' + corr + '</div>' : '') +
        (corr ? '' : '<div class="ls-empty ok">这段日志里没有发现已知的攻击特征。</div>');
      return;
    }

    // 命中的行数可能上千（被刷的 access.log 能整篇命中），
    // 一次性塞进 DOM 会卡好几秒，所以只渲染前一批，其余靠导出看全
    var MAX_RENDER = 300;
    var shown = res.hits.slice(0, MAX_RENDER);
    var hits = shown.map(function (h) {
      return '<div class="ls-hit">' +
        '<div class="ls-hit-head">' +
        '  <span class="sev ' + esc(h.severity) + '">' + esc(sevLabel(h.severity)) + '</span>' +
        '  <span class="rule">' + esc(h.rule_id) + ' · ' + esc(h.rule_name) + '</span>' +
        '  <span class="meta">行 ' + esc(h.line_no) +
        (h.source_ip ? ' · ' + esc(h.source_ip) : '') +
        (h.time ? ' · ' + esc(h.time) : '') +
        (h.decoded ? '  <span class="dec-tag" title="原文没有命中，是解码/去混淆之后才发现的，通常意味着对方刻意混淆过">变形后命中</span>' : '') +
        '</span>' +
        '</div>' +
        '<div class="ls-hit-match">' + esc(h.matched) + '</div>' +
        '<div class="ls-hit-line">' + esc(h.line) + '</div>' +
        '</div>';
    }).join('') + (res.hits.length > MAX_RENDER
      ? '<div class="ls-empty">还有 ' + (res.hits.length - MAX_RENDER) +
        ' 条未显示（列表只渲染前 ' + MAX_RENDER + ' 条，用「导出结果」可以拿到全部）</div>'
      : '');

    var ips = (res.top_ips || []).map(function (x) {
      return '<span class="ls-ip">' + esc(x.ip) + ' <b>' + x.count + '</b></span>';
    }).join('');

    $('ls-body').innerHTML =
      '<div class="ls-stats">' +
      stat('', '扫描行数', res.scanned) +
      stat('', '命中行数', res.hit_line_count) +
      (res.decoded_hits ? stat('dec', '变形后命中', res.decoded_hits) : '') +
      stat('', '参与规则', res.rule_count) +
      ((res.correlations && res.correlations.length) ? stat('corr', '关联发现', res.correlations.length) : '') +
      stat('crit', 'critical', sev.critical) +
      stat('high', 'high', sev.high) +
      stat('med', 'medium', sev.medium) +
      stat('low', 'low', sev.low) +
      '</div>' +
      (corr ? '<div class="ls-corr-wrap"><div class="ls-section-title">关联发现（跨行统计）</div>' + corr + '</div>' : '') +
      (ips ? '<div class="ls-ips"><span class="ls-ips-label">可疑来源 IP</span>' + ips + '</div>' : '') +
      '<div class="ls-section-title">单行命中</div>' +
      '<div class="ls-hits">' + hits + '</div>';
  }

  // ---------- 数据 ----------

  async function loadTargets() {
    state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    // 目标可能已被删除：清掉悬空的 targetId 与上一台的检测结果
    if (state.targetId && !state.targets.some(function (t) { return t.id === state.targetId; })) {
      state.targetId = '';
      state.result = null;
      state.files = [];
      state.path = '';
      // 同一类问题：目标没了，下拉里不能留着它上次的文件名
      if ($('ls-path')) $('ls-path').value = '';
      renderFiles();
    }
    if (!state.targetId && state.targets.length) state.targetId = state.targets[0].id;
    renderTargets();
  }

  async function loadFiles() {
    if (!state.targetId) { state.files = []; renderFiles(); return; }
    hint('正在探测日志文件…');
    try {
      state.files = await req('/api/logs/files?target_id=' + encodeURIComponent(state.targetId));
      renderFiles();
      hint(state.files.length ? ('发现 ' + state.files.length + ' 个可扫描日志') : '没有发现常见日志文件，可手动改用文件面板查看');
    } catch (e) {
      state.files = [];
      renderFiles();
      hint('探测失败：' + e.message, true);
    }
  }

  // 把检测结果导成 CSV。命中行和跨行关联结论一起导出，
  // 关联结论（爆破成功之类）往往才是真正要看的东西。
  async function exportCSV() {
    var res = state.result;
    if (!res || (!(res.hits || []).length && !(res.correlations || []).length)) {
      hint('先跑一次检测，再导出', true);
      return;
    }
    var head = ['时间', '级别', '类别', '规则编号', '规则名', '来源地址', '行号', '解码后命中', '命中片段', '原始行'];
    var lines = [head.join(',')];

    (res.hits || []).forEach(function (h) {
      lines.push([
        new Date().toLocaleString(), h.severity, h.category, h.rule_id, h.rule_name,
        h.source_ip || '', h.line_no, h.decoded ? '是' : '否', h.match || '', h.line || ''
      ].map(csvCell).join(','));
    });
    (res.correlations || []).forEach(function (c) {
      lines.push([
        new Date().toLocaleString(), c.severity, '关联分析', 'CORR-' + c.kind, c.title,
        c.source_ip || '', c.first_line, '', c.detail || '', c.evidence || ''
      ].map(csvCell).join(','));
    });

    // 加 BOM，否则 Excel 打开中文会乱码
    var fname = '日志检测-' + String(state.path || 'log').replace(/[^\w.-]/g, '_') + '-' +
      new Date().toISOString().slice(0, 10) + '.csv';
    try {
      // 统一走保存出口：配了默认下载目录就落到那里，否则退回浏览器下载
      if (!window.AwdSaveFile) throw new Error('保存入口没加载，刷新一下页面');
      var saved = await window.AwdSaveFile(fname, '\ufeff' + lines.join('\r\n'), 'text/csv;charset=utf-8');
      hint(saved ? ('已保存到 ' + saved) : ('已导出 ' + (lines.length - 1) + ' 条记录'));
    } catch (e) {
      hint('保存失败：' + e.message, true);
    }
  }

  function csvCell(v) {
    var s = String(v == null ? '' : v);
    // 逗号、引号、换行都要用引号包起来，内部引号翻倍
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  async function scan() {
    if (state.scanning) return;
    if (!state.targetId || !state.path) { hint('请先选择目标与日志文件', true); return; }
    state.scanning = true;
    hint('正在读取并检测最近 ' + state.lines + ' 行…');
    setStatus('日志检测中：' + state.path);
    try {
      // 扫描会往 scan_events 写事件，后端只接受 POST；参数都在 query 里，body 为空
      var res = await req('/api/logs/scan?target_id=' + encodeURIComponent(state.targetId) +
        '&path=' + encodeURIComponent(state.path) + '&lines=' + state.lines +
        '&kind=' + encodeURIComponent(state.kind), { method: 'POST' });
      renderResult(res);
      var kindLabel = res.kind === 'web' ? 'Web 日志规则集' : (res.kind === 'system' ? '系统日志规则集' : '全量规则集');
      // 扫描有总时间预算（默认 20 秒）：超了会停在半途并如实标注，结果不完整。
      // 这句必须显眼 —— 用户拿一份"只扫了一半"的结果当全量结论会误判。
      var truncNote = res.truncated
        ? '　【结果不完整】' + (res.truncated_reason || ('扫描到第 ' + (res.stopped_at_line || 0) + ' 行时中止，其余行未检测'))
        : '';
      if (res.dropped_hits) {
        truncNote += '　另有 ' + res.dropped_hits + ' 条命中因超出上限未列出';
      }
      hint('检测完成：' + kindLabel + '（' + res.rule_count + ' 条规则' + (res.kind_auto ? '，类型为自动判断' : '，类型为手动指定') +
        '）　扫描 ' + res.scanned + ' 行，命中 ' + res.hit_line_count + ' 行 / ' + res.hits.length + ' 条' + truncNote,
        res.truncated ? 'warn' : '');
      setStatus(res.truncated ? '日志检测完成（结果不完整）：' + state.path : '日志检测完成：' + state.path);
    } catch (e) {
      hint('检测失败：' + e.message, true);
      setStatus('日志检测失败：' + e.message);
    } finally {
      state.scanning = false;
    }
  }

  // ---------- 显隐 ----------

  function toggleLogscan() {
    var on = window.AwdViews.toggle('logscan-area');
    if (on) {
      // 每次打开都回到"跟随当前会话"
      state.followActive = true;
      if (!state.targets.length) {
        loadTargets().then(function () {
          syncToActiveSession();
          loadFiles();
        }).catch(function (e) { hint('加载目标失败：' + e.message, true); });
      } else {
        syncToActiveSession();
        renderTargets();
        loadFiles();
      }
    }
  }

  // 跟随当前激活的终端会话；用户手动改过下拉就锁定
  function syncToActiveSession() {
    if (!state.followActive) return false;
    var tid = window.AwdActiveTarget ? window.AwdActiveTarget() : '';
    if (!tid || tid === state.targetId) return false;
    state.targetId = tid;
    state.result = null;
    state.files = [];
    state.path = '';
    // 光清 state 不清下拉是错的：下拉里还列着上一台主机的文件名，
    // 用户这时点「开始检测」就是拿**新目标 + 旧路径**发 POST。
    // 同时把手动路径输入框一起清掉，否则 renderFiles 里"用户手填过就不覆盖"
    // 的判断会让旧路径继续留在框里。
    if ($('ls-path')) $('ls-path').value = '';
    renderFiles();
    renderTargets();
    return true;
  }

  // ---------- 初始化 ----------

  function boot() {
    renderShell();
    $('btn-logscan').addEventListener('click', toggleLogscan);
    // 切换终端会话时跟着换主机（用户手动选过就锁定）
    window.addEventListener('awdshell:connected', function () {
      if (syncToActiveSession() && !$('logscan-area').hidden) loadFiles();
    });
    // 与文件面板同样的联动：这个目标的会话全关掉了，检测视图也跟着收起
    window.addEventListener('awdshell:session-closed', function (e) {
      var d = (e && e.detail) || {};
      var area = $('logscan-area');
      if (!area || area.hidden) return;
      if (d.targetId !== state.targetId) return;
      var remaining = d.remainingTargets || [];
      if (remaining.indexOf(state.targetId) >= 0) return;
      // 走 AwdViews 收起：自己改 hidden 再无条件把 work-body 的 display 恢复，
      // 会把此刻开着的别的整页视图一起露出来（叠层）。toggle 同时负责按钮态、
      // 工作区显隐和监控定时器的重排。
      if (window.AwdViews && window.AwdViews.isOpen('logscan-area')) {
        window.AwdViews.toggle('logscan-area');
        // toggle 收起视图时是无条件恢复工作区的；万一此刻还开着别的整页视图，
        // 再按回去，否则工作区会和那个视图叠在一起
        if (window.AwdViews.anyOpen()) $('work-body').style.display = 'none';
      } else {
        area.hidden = true;
        if (!window.AwdViews || !window.AwdViews.anyOpen()) $('work-body').style.display = '';
        var btn = $('btn-logscan');
        if (btn) btn.classList.remove('active');
      }
      setStatus('该目标的会话已全部关闭，日志检测已收起');
    });
    // 目标被新建或删除后重取列表，否则下拉里还是旧数据
    window.addEventListener('awdshell:targets-changed', function () {
      loadTargets().catch(function () {});
    });
    loadTargets().catch(function () { /* 首次打开时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
