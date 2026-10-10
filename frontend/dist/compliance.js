/* awdshell 安全基线核查：依据等保 2.0 与 CIS 公开要求检查主机配置。整页视图。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = { targets: [], targetId: '', report: null, running: false, filter: 'all', followActive: true };

  // ---------- 工具 ----------

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function setStatus(msg) {
    var el = $('status');
    if (el) el.textContent = msg;
  }

  function hint(msg, isError) {
    var el = $('cp-hint');
    if (!el) return;
    el.textContent = msg || '';
    el.className = isError ? 'cp-hint error-text' : 'cp-hint';
  }

  async function req(path, init) {
    var opt = Object.assign({ headers: { 'Content-Type': 'application/json' } }, init || {});
    var res = await fetch(API + path, opt);
    if (!res.ok) {
      var msg = res.status + ' ' + res.statusText;
      try { var j = await res.json(); if (j && j.error) msg = j.error; } catch (e) { /* 忽略 */ }
      throw new Error(msg);
    }
    return res.json();
  }

  function statusLabel(s) {
    return { pass: '符合', fail: '不符合', manual: '需人工', error: '未取到' }[s] || s;
  }

  // ---------- 渲染 ----------

  function renderShell() {
    $('compliance-area').innerHTML =
      '<div class="cp-wrap">' +
      '  <div class="view-head">' +
      '    <span class="view-title">安全基线核查</span>' +
      '    <button class="view-close">关闭</button>' +
      '  </div>' +
      '  <div class="cp-toolbar">' +
      '    <select id="cp-target" class="cp-target"></select>' +
      '    <button id="cp-follow-state" class="awd-follow" title=""></button>' +
      '    <button id="cp-run" class="primary">开始核查</button>' +
      '    <button id="cp-cancel" hidden>取消</button>' +
      '    <button id="cp-export" title="导出成一份可以直接交出去的核查报告">导出报告</button>' +
      '    <span class="cp-hint" id="cp-hint">检查项依据 GB/T 22239-2019 三级与 CIS 公开要求</span>' +
      '  </div>' +
      '  <div class="cp-body" id="cp-body">' +
      '    <div class="cp-empty">选择一台主机后点「开始核查」。' +
      '      核查会逐项读取目标机的配置与状态，并按等保与 CIS 的要求给出结论与整改建议。</div>' +
      '  </div>' +
      '</div>';

    $('cp-target').addEventListener('change', function () {
      state.targetId = this.value;
      // 用户手动选了目标：这个视图锁定它，不再跟着会话跑
      state.followActive = false;
      // 换目标就把上一台的报告清掉：留着会让人以为那是当前主机的结论
      state.report = null;
      var name = this.options[this.selectedIndex] ? this.options[this.selectedIndex].text : '';
      $('cp-body').innerHTML = '<div class="cp-empty">已切换到 ' + esc(name) +
        '，点「开始核查」重新检查这台主机。</div>';
      hint('目标已切换，请重新核查');
    });
    $('cp-run').addEventListener('click', run);
    $('cp-cancel').addEventListener('click', function () {
      if (state.abort) state.abort.abort();
    });
    $('cp-export').addEventListener('click', exportReport);
  }

  // 导出成一份自包含的 HTML 报告：安全运维一轮干完要交的核查结论，
  // 之前只能靠截图，也没法回答"这台机器上次是什么结论"。
  function exportReport() {
    var rep = state.report;
    if (!rep) { hint('先跑一次核查，再导出', true); return; }
    var s = rep.summary || {};
    var stamp = new Date().toLocaleString();
    var esc2 = esc;

    function rows(list) {
      return list.map(function (r) {
        return '<tr class="' + esc2(r.status) + '">' +
          '<td>' + esc2(r.id) + '</td>' +
          '<td>' + esc2(statusLabel(r.status)) + '</td>' +
          '<td>' + esc2(r.severity) + '</td>' +
          '<td>' + esc2(r.title) + '</td>' +
          '<td>' + esc2(r.detail) + '</td>' +
          '<td>' + esc2(r.remedy || '') + '</td>' +
          '<td class="cmd">' + esc2(r.command || '') + '</td>' +
          '</tr>';
      }).join('');
    }

    var html = '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">' +
      '<title>基线核查报告 - ' + esc2(rep.target) + '</title><style>' +
      'body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:32px;color:#1a1d23;line-height:1.6}' +
      'h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:26px 0 8px;border-bottom:1px solid #dfe3ea;padding-bottom:5px}' +
      '.meta{color:#6b7280;font-size:12px;margin-bottom:18px}' +
      '.sum{display:flex;gap:22px;flex-wrap:wrap;margin:14px 0}' +
      '.sum div{font-size:12px;color:#6b7280}.sum b{display:block;font-size:22px;color:#1a1d23}' +
      'table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}' +
      'th{background:#f4f6f9;text-align:left;padding:6px 8px;border:1px solid #dfe3ea;font-weight:600}' +
      'td{padding:6px 8px;border:1px solid #dfe3ea;vertical-align:top}' +
      'tr.fail td:nth-child(2){color:#c0392b;font-weight:600}' +
      'tr.pass td:nth-child(2){color:#1e8e3e}' +
      'tr.manual td:nth-child(2){color:#b8860b}' +
      '.cmd{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#6b7280;word-break:break-all}' +
      '</style></head><body>' +
      '<h1>安全基线核查报告</h1>' +
      '<div class="meta">目标：' + esc2(rep.target) + '　导出时间：' + esc2(stamp) +
      '　耗时：' + Math.round((rep.elapsed_ms || 0) / 1000) + ' 秒</div>' +
      '<div class="sum">' +
      '<div><b>' + (s.score == null ? '-' : s.score) + '</b>合规得分</div>' +
      '<div><b>' + (s.total || 0) + '</b>检查项</div>' +
      '<div><b>' + (s.pass || 0) + '</b>符合</div>' +
      '<div><b>' + (s.fail || 0) + '</b>不符合</div>' +
      '<div><b>' + (s.manual || 0) + '</b>需人工确认</div>' +
      '<div><b>' + (s.err || s.error || 0) + '</b>未取到</div>' +
      '</div>' +
      '<p class="meta">依据 GB/T 22239-2019（等保 2.0）三级要求与 CIS 公开加固要求。</p>' +
      '<h2>不符合项</h2><table><tr><th>编号</th><th>结论</th><th>级别</th><th>检查项</th><th>说明</th><th>整改建议</th><th>执行命令</th></tr>' +
      rows((rep.results || []).filter(function (r) { return r.status === 'fail'; })) + '</table>' +
      '<h2>需人工确认</h2><table><tr><th>编号</th><th>结论</th><th>级别</th><th>检查项</th><th>说明</th><th>整改建议</th><th>执行命令</th></tr>' +
      rows((rep.results || []).filter(function (r) { return r.status === 'manual'; })) + '</table>' +
      '<h2>未取到结果</h2><table><tr><th>编号</th><th>结论</th><th>级别</th><th>检查项</th><th>说明</th><th>整改建议</th><th>执行命令</th></tr>' +
      rows((rep.results || []).filter(function (r) { return r.status === 'error'; })) + '</table>' +
      '<h2>全部检查项</h2><table><tr><th>编号</th><th>结论</th><th>级别</th><th>检查项</th><th>说明</th><th>整改建议</th><th>执行命令</th></tr>' +
      rows(rep.results || []) + '</table>' +
      '</body></html>';

    var name = '基线核查-' + String(rep.target).replace(/[^\w.@-]/g, '_') + '-' +
      new Date().toISOString().slice(0, 10) + '.html';
    downloadBlob(html, name, 'text/html;charset=utf-8');
    hint('报告已导出：' + name);
  }

  function downloadBlob(content, filename, mime) {
    var blob = new Blob([content], { type: mime || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
  }

  // 跟随状态可见 + 一键恢复（锁定是隐形的，用户会以为界面坏了）
  function renderSyncState() {
    if (!window.AwdViews) return;
    window.AwdViews.followButton('cp-follow-state', state.followActive, '核查目标', function () {
      state.followActive = true;
      syncToActiveSession();
      renderTargets();
      hint('已恢复跟随当前会话');
    });
  }

  function renderTargets() {
    var sel = $('cp-target');
    renderSyncState();
    sel.innerHTML = state.targets.map(function (t) {
      return '<option value="' + esc(t.id) + '"' + (t.id === state.targetId ? ' selected' : '') + '>' + esc(t.name) + '</option>';
    }).join('') || '<option value="">无目标</option>';
  }

  function resultRow(r) {
    var out = r.output ? '<div class="cp-out">' + esc(r.output) + '</div>' : '';
    // 把执行过的命令显出来：复核结论时最需要知道"到底查了什么"，
    // 需要 root 才能读到结果的项目也在这里点明
    var cmd = r.command
      ? '<div class="cp-cmd" title="点击可选中复制">' + esc(r.command) + '</div>'
      : '';
    var rootTip = (r.needs_root && r.status !== 'pass')
      ? '<div class="cp-note">这一项需要 root 权限才能读到结果，请以 root 重新核查。</div>'
      : '';
    return '<div class="cp-item ' + esc(r.status) + '">' +
      '<div class="cp-item-head">' +
      '  <span class="cp-badge ' + esc(r.status) + '">' + statusLabel(r.status) + '</span>' +
      '  <span class="cp-id">' + esc(r.id) + '</span>' +
      '  <span class="cp-title">' + esc(r.title) + '</span>' +
      '  <span class="cp-sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span>' +
      '</div>' +
      '<div class="cp-detail">' + esc(r.detail) + '</div>' +
      (r.refs && r.refs.length ? '<div class="cp-refs">' + esc(r.refs.join(' · ')) + '</div>' : '') +
      (r.status === 'fail' || r.status === 'error' || r.status === 'manual' ? out : '') +
      rootTip +
      (r.status === 'fail' && r.remedy ? '<div class="cp-remedy"><b>整改建议</b>' + esc(r.remedy) + '</div>' : '') +
      (r.note ? '<div class="cp-note">' + esc(r.note) + '</div>' : '') +
      cmd +
      '</div>';
  }

  function renderReport(rep) {
    state.report = rep;
    var s = rep.summary;
    var stat = function (cls, label, n) {
      return '<div class="cp-stat ' + cls + '"><span class="n">' + (n || 0) + '</span><span class="l">' + label + '</span></div>';
    };

    var shown = rep.results.filter(function (r) {
      if (state.filter === 'fail') return r.status === 'fail';
      if (state.filter === 'manual') return r.status === 'manual' || r.status === 'error';
      return true;
    });

    var byCat = {};
    shown.forEach(function (r) {
      (byCat[r.category] = byCat[r.category] || []).push(r);
    });
    var groupHtml = Object.keys(byCat).map(function (cat) {
      var items = byCat[cat].map(resultRow).join('');
      var fail = byCat[cat].filter(function (r) { return r.status === 'fail'; }).length;
      return '<section class="cp-group">' +
        '<div class="cp-group-head"><span>' + esc(cat) + '</span>' +
        '<span class="cp-group-sub">' + byCat[cat].length + ' 项' + (fail ? '，其中 ' + fail + ' 项不符合' : '') + '</span></div>' +
        items + '</section>';
    }).join('');

    $('cp-body').innerHTML =
      '<div class="cp-score-wrap">' +
      '  <div class="cp-score">' +
      '    <span class="cp-score-num">' + (s.score >= 0 ? s.score : '--') + '</span>' +
      '    <span class="cp-score-label">合规得分</span>' +
      '  </div>' +
      '  <div class="cp-stats">' +
      stat('', '检查项', s.total) +
      stat('pass', '符合', s.pass) +
      stat('fail', '不符合', s.fail) +
      stat('manual', '需人工', s.manual) +
      stat('error', '未取到', s.error) +
      '  </div>' +
      '</div>' +
      '<div class="cp-meta">' + esc(rep.target) + ' · 耗时 ' + rep.elapsed_ms + ' ms · ' +
      new Date(rep.started_at).toLocaleString() +
      (s.score >= 0 ? '　（得分只统计能明确判定的项，需人工与未取到的不计入）' : '') + '</div>' +
      (rep.problems && rep.problems.length ? '<div class="cp-problems">检查项加载问题：' + esc(rep.problems.join('；')) + '</div>' : '') +
      '<div class="cp-filters">' +
      '  <button data-filter="all" class="' + (state.filter === 'all' ? 'active' : '') + '">全部 ' + s.total + '</button>' +
      '  <button data-filter="fail" class="' + (state.filter === 'fail' ? 'active' : '') + '">只看不符合 ' + s.fail + '</button>' +
      '  <button data-filter="manual" class="' + (state.filter === 'manual' ? 'active' : '') + '">需人工确认 ' + (s.manual + s.error) + '</button>' +
      '</div>' +
      (groupHtml || '<div class="cp-empty ok">这个筛选条件下没有项目。</div>');

    var fbs = $('cp-body').querySelectorAll('[data-filter]');
    for (var i = 0; i < fbs.length; i++) {
      fbs[i].addEventListener('click', function () {
        state.filter = this.getAttribute('data-filter');
        renderReport(state.report);
      });
    }
  }

  // ---------- 数据 ----------

  async function loadTargets() {
    state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    // 目标可能已被删除：清掉悬空的 targetId 与上一台的报告
    if (state.targetId && !state.targets.some(function (t) { return t.id === state.targetId; })) {
      state.targetId = '';
      state.report = null;
    }
    if (!state.targetId && state.targets.length) state.targetId = state.targets[0].id;
    renderTargets();
  }

  async function run() {
    if (state.running) return;
    if (!state.targetId) { hint('请先选择目标', true); return; }
    state.running = true;
    state.abort = new AbortController();
    var btn = $('cp-run');
    btn.disabled = true;
    var cancel = $('cp-cancel');
    if (cancel) cancel.hidden = false;
    hint('正在逐项检查，请稍候…');
    setStatus('基线核查中…');
    try {
      var rep = await req('/api/compliance/run', {
        method: 'POST',
        body: JSON.stringify({ target_id: state.targetId }),
        signal: state.abort.signal
      });
      renderReport(rep);
      hint('核查完成：' + rep.summary.total + ' 项，符合 ' + rep.summary.pass +
        '，不符合 ' + rep.summary.fail + '，需人工 ' + rep.summary.manual + '，未取到 ' + rep.summary.error);
      setStatus('基线核查完成：得分 ' + (rep.summary.score >= 0 ? rep.summary.score : '--'));
    } catch (e) {
      // 用户主动取消时不要报成失败
      if (e && e.name === 'AbortError') {
        hint('核查已取消（目标机上正在执行的那一条命令会自行结束）');
        setStatus('基线核查已取消');
      } else {
        hint('核查失败：' + e.message, true);
        setStatus('基线核查失败：' + e.message);
      }
    } finally {
      state.running = false;
      state.abort = null;
      btn.disabled = false;
      if (cancel) cancel.hidden = true;
    }
  }

  // ---------- 显隐 ----------

  function toggleCompliance() {
    var on = window.AwdViews.toggle('compliance-area');
    if (on) {
      // 每次打开都回到"跟随当前会话"
      state.followActive = true;
      if (!state.targets.length) {
        loadTargets().then(function () {
          syncToActiveSession();
          showSwitchHint();
        }).catch(function (e) { hint('加载目标失败：' + e.message, true); });
      } else {
        syncToActiveSession();
        renderTargets();
      }
    }
  }

  // 跟随当前激活的终端会话；用户手动改过下拉就锁定
  function syncToActiveSession() {
    if (!state.followActive) return false;
    var tid = window.AwdActiveTarget ? window.AwdActiveTarget() : '';
    if (!tid || tid === state.targetId) return false;
    state.targetId = tid;
    // 换了目标，上一台的报告必须清掉 —— 留着会让人以为是当前主机的结论
    state.report = null;
    $('cp-body').innerHTML = '<div class="cp-empty">已跟随当前会话切到这台主机，' +
      '点「开始核查」重新检查。</div>';
    hint('已跟随当前会话切换目标，请重新核查');
    renderTargets();
    return true;
  }

  function showSwitchHint() {
    renderTargets();
    if (state.report) return;
    var name = '';
    for (var i = 0; i < state.targets.length; i++) {
      if (state.targets[i].id === state.targetId) { name = state.targets[i].name; break; }
    }
    $('cp-body').innerHTML = '<div class="cp-empty">当前目标：' + esc(name) +
      '　点「开始核查」逐项读取这台主机的配置与状态。</div>';
  }

  // ---------- 初始化 ----------

  function boot() {
    renderShell();
    $('btn-compliance').addEventListener('click', toggleCompliance);
    // 切换终端会话时跟着换主机（用户手动选过就锁定）
    window.addEventListener('awdshell:connected', function () {
      syncToActiveSession();
    });
    // 与文件面板同样的联动：这个目标的会话全关掉了，核查视图也跟着收起
    window.addEventListener('awdshell:session-closed', function (e) {
      var d = (e && e.detail) || {};
      var area = $('compliance-area');
      if (!area || area.hidden) return;
      if (d.targetId !== state.targetId) return;
      var remaining = d.remainingTargets || [];
      if (remaining.indexOf(state.targetId) >= 0) return;
      area.hidden = true;
      $('work-body').style.display = '';
      var btn = $('btn-compliance');
      if (btn) btn.classList.remove('active');
      setStatus('该目标的会话已全部关闭，基线核查已收起');
    });
    // 目标被新建或删除后重取列表
    window.addEventListener('awdshell:targets-changed', function () {
      loadTargets().catch(function () {});
    });
    loadTargets().catch(function () { /* 首次打开时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
