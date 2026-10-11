/* awdshell 安全基线核查：依据等保 2.0 与 CIS 公开要求检查主机配置。整页视图。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    targets: [], targetId: '', report: null, running: false, filter: 'all', followActive: true,
    // 请求序号：这个视图里历史、报告、核查都是异步直接改写 cp-body，
    // 没有序号的话"选 A 点历史 → 没回来就切到 B"会把 A 的记录挂在 B 的标题下，
    // 甚至导出一份属于 A 的报告而界面显示 B。
    loadSeq: 0
  };

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
      // 各视图各有一份 req，统一把状态码挂在错误上，调用方才好按语义分支。
      var cErr = new Error(msg);
      cErr.status = res.status;
      throw cErr;
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
      '    <button id="cp-history" title="看这台主机以前跑过的核查结论">历史</button>' +
      '    <button id="cp-checks" title="看这次会检查哪些项目">检查项</button>' +
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
      // 作废在途请求：否则上一个目标的历史/报告回来会挂到新目标头上
      state.loadSeq++;
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
    $('cp-history').addEventListener('click', showHistory);
    $('cp-checks').addEventListener('click', showChecks);
  }

  // ---------- 历史：后端一直在存报告，但界面上以前只能看当场跑出来那份 ----------

  async function showHistory() {
    if (!state.targetId) { hint('先选一台主机', true); return; }
    var body = $('cp-body');
    var seq = ++state.loadSeq;
    var tid = state.targetId;
    var tname = targetName();
    body.innerHTML = '<div class="cp-empty">读取历史…</div>';
    try {
      var r = await req('/api/compliance/history?target_id=' + encodeURIComponent(tid) + '&limit=200');
      // 期间切过目标或又发起了别的请求：这份数据已经过期
      if (seq !== state.loadSeq || tid !== state.targetId) return;
      var list = r.reports || [];
      if (!list.length) {
        body.innerHTML = '<div class="cp-empty">这台主机还没有核查记录。点「开始核查」跑一次，结果会自动存下来。</div>';
        return;
      }
      var rows = list.map(function (h) {
        return '<div class="cp-hist-row" data-id="' + esc(h.id) + '">' +
          '<span class="cp-hist-time">' + esc(fmtTime(h.ts)) + '</span>' +
          '<span class="cp-hist-score">' + scoreText(h.score) + '</span>' +
          '<span class="cp-hist-sum">通过 ' + (h.pass || 0) + ' / 不合规 ' + (h.fail || 0) +
          ' / 待人工 ' + (h.manual || 0) + (h.error ? ' / 读取失败 ' + h.error : '') + '</span>' +
          '<span class="cp-hist-open">查看</span>' +
          '<button class="db-mini danger cp-hist-del" data-del="' + esc(h.id) + '" title="删掉这一次的结论">删</button>' +
          '</div>';
      }).join('');
      body.innerHTML =
        '<div class="cp-hist-head">' + esc(tname) + ' 的核查历史（最近 ' + list.length + ' 次）' +
        '<button class="db-mini danger cp-hist-clear" title="清空这台主机的全部核查记录">清空</button></div>' +
        '<div class="cp-hist">' + rows + '</div>' +
        '<div class="cp-hist-tip">点「查看」把那次结论调出来，同样可以「导出报告」。' +
        '保留期清理是后台按天的定时任务，这里可以随时自己删。</div>';
      Array.prototype.forEach.call(body.querySelectorAll('.cp-hist-row'), function (el) {
        el.addEventListener('click', function (ev) {
          // 点删除按钮时不要顺带把报告打开
          if (ev.target && ev.target.classList && ev.target.classList.contains('cp-hist-del')) return;
          loadReport(this.getAttribute('data-id'));
        });
      });
      Array.prototype.forEach.call(body.querySelectorAll('.cp-hist-del'), function (b) {
        b.addEventListener('click', function (ev) {
          ev.stopPropagation();
          deleteReport(this.getAttribute('data-del'));
        });
      });
      var clr = body.querySelector('.cp-hist-clear');
      if (clr) clr.addEventListener('click', function () { clearReports(tid, tname); });
    } catch (e) {
      if (seq !== state.loadSeq) return;
      body.innerHTML = '<div class="cp-empty error-text">读取历史失败：' + esc(e.message) + '</div>';
    }
  }

  // 得分 -1 表示"没有可判定的项"，不该显示成 -1 分
  function scoreText(score) {
    if (score == null || score < 0) return '--';
    return score + ' 分';
  }

  async function deleteReport(id) {
    if (!window.confirm('删掉这一次的核查结论？删了就找不回来了。')) return;
    try {
      await req('/api/compliance/delete?id=' + encodeURIComponent(id), { method: 'POST' });
      // 界面上正显示的那份可能就是刚删的：不清掉的话点「导出报告」
      // 导出的还是已经被删掉的内容
      state.report = null;
      if (window.AwdToast) window.AwdToast.ok('已删掉那条记录');
      showHistory();
    } catch (e) {
      if (window.AwdToast) window.AwdToast.error('删除失败\n\n' + e.message);
    }
  }

  async function clearReports(tid, tname) {
    if (!window.confirm('清空「' + tname + '」的全部核查记录？这个动作不可撤销。')) return;
    try {
      var r = await req('/api/compliance/clear', {
        method: 'POST',
        body: JSON.stringify({ target_id: tid })
      });
      if (window.AwdToast) window.AwdToast.ok('已清空 ' + (r.deleted || 0) + ' 条记录');
      // 界面上正显示的报告也一并清掉，免得看着像还在
      state.report = null;
      showHistory();
    } catch (e) {
      if (window.AwdToast) window.AwdToast.error('清空失败\n\n' + e.message);
    }
  }

  // 后端有两种报告形状，必须统一：
  //   当场跑的 service.Report   —— 有 summary{total,pass,fail,manual,error,score} 与 started_at
  //   库里读的 store.ComplianceReport —— 扁平字段 score/total/pass/fail/manual/error，时间字段是 ts
  // 不统一的话，从历史点进去回看会因为读不到 summary 直接抛错（renderReport 里没有兜底）。
  function normalizeReport(rep) {
    if (!rep) return rep;
    // results 是 json.RawMessage，嵌进 JSON 后本来就是数组；
    // 这里留字符串分支只是防止将来某处改成字符串存
    if (typeof rep.results === 'string') {
      try { rep.results = JSON.parse(rep.results); } catch (e) { rep.results = []; }
    }
    // 必须是数组：renderReport 里直接 .filter，字段落空或给成对象时
    // 用户看到的就是 "rep.results.filter is not a function"
    if (!Array.isArray(rep.results)) rep.results = [];
    if (!rep.summary) {
      rep.summary = {
        total: rep.total || 0,
        pass: rep.pass || 0,
        fail: rep.fail || 0,
        manual: rep.manual || 0,
        error: rep.error || 0,
        score: rep.score != null ? rep.score : -1
      };
    }
    if (!rep.started_at) rep.started_at = rep.ts || 0;
    if (!rep.problems) rep.problems = [];
    return rep;
  }

  async function loadReport(id) {
    var seq = ++state.loadSeq;
    var tid = state.targetId;
    hint('读取那份报告…');
    try {
      var rep = await req('/api/compliance/report?id=' + encodeURIComponent(id));
      if (seq !== state.loadSeq || tid !== state.targetId) return;
      // 后端这个 action 直接返回报告对象本身（不是 {report: ...}）
      var one = normalizeReport(rep.report || rep);
      // 报告归属要与当前选中的目标一致，否则宁可不开
      if (one.target_id && tid && one.target_id !== tid) {
        hint('这份报告属于别的主机，已取消打开', true);
        return;
      }
      state.report = one;
      renderReport(state.report);
      hint('已调出 ' + fmtTime(state.report.started_at || state.report.ts) + ' 的核查结论');
    } catch (e) {
      if (seq !== state.loadSeq) return;
      hint('读取报告失败：' + e.message, true);
    }
  }

  // ---------- 检查项：让人知道这次到底会查什么 ----------

  async function showChecks() {
    var body = $('cp-body');
    var seq = ++state.loadSeq;
    body.innerHTML = '<div class="cp-empty">读取检查项…</div>';
    try {
      // 检查项是全局的（后端不按目标筛），所以只校验序号即可
      var r = await req('/api/compliance/checks');
      if (seq !== state.loadSeq) return;
      var checks = r.checks || [];
      var groups = {};
      checks.forEach(function (c) {
        var g = c.category || '其他';
        (groups[g] = groups[g] || []).push(c);
      });
      var html = '<div class="cp-hist-head">共 ' + checks.length + ' 个检查项</div>';
      if (r.problems && r.problems.length) {
        html += '<div class="cp-checks-note">有 ' + r.problems.length + ' 条规则没加载成功：' +
          esc(r.problems.join('；')) + '</div>';
      }
      Object.keys(groups).forEach(function (g) {
        html += '<div class="cp-checks-group">' + esc(g) + '（' + groups[g].length + '）</div>';
        html += '<div class="cp-checks-list">' + groups[g].map(function (c) {
          return '<div class="cp-checks-row">' +
            '<span class="cp-checks-id">' + esc(c.id || '') + '</span>' +
            '<span class="cp-checks-title">' + esc(c.title || '') + '</span>' +
            '<span class="cp-checks-sev">' + esc(c.severity || '') + '</span>' +
            (c.needs_root ? '<span class="cp-checks-root" title="需要 root 才能读出结果">root</span>' : '') +
            '</div>';
        }).join('') + '</div>';
      });
      body.innerHTML = html;
    } catch (e) {
      if (seq !== state.loadSeq) return;
      body.innerHTML = '<div class="cp-empty error-text">读取检查项失败：' + esc(e.message) + '</div>';
    }
  }

  function targetName() {
    var sel = $('cp-target');
    if (!sel || sel.selectedIndex < 0) return '这台主机';
    return sel.options[sel.selectedIndex].text;
  }

  function fmtTime(ms) {
    if (!ms) return '-';
    var d = new Date(Number(ms));
    if (isNaN(d.getTime())) return '-';
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
      p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  // 导出成一份自包含的 HTML 报告：安全运维一轮干完要交的核查结论，
  // 之前只能靠截图，也没法回答"这台机器上次是什么结论"。
  async function exportReport() {
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
      '<div class="meta">目标：' + esc2(rep.target) +
      '　核查时间：' + esc2(fmtTime(rep.started_at || rep.ts)) +
      '　导出时间：' + esc2(stamp) +
      '　耗时：' + Math.round((rep.elapsed_ms || 0) / 1000) + ' 秒</div>' +
      '<div class="sum">' +
      '<div><b>' + (s.score >= 0 ? s.score : '--') + '</b>合规得分</div>' +
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
      reportDate(rep) + '.html';
    try {
      var saved = await downloadBlob(html, name, 'text/html;charset=utf-8');
      hint(saved ? ('报告已保存到 ' + saved) : ('报告已导出：' + name));
    } catch (e) {
      hint('保存失败：' + e.message, true);
    }
  }

  // 文件名用**那份报告**的日期，不是导出当天的日期 ——
  // 上个月的结论导出来却顶着今天的日期，交出去没法自证是哪一次跑的
  function reportDate(rep) {
    var ms = rep.started_at || rep.ts;
    if (!ms) return new Date().toISOString().slice(0, 10);
    var d = new Date(Number(ms));
    if (isNaN(d.getTime())) return new Date().toISOString().slice(0, 10);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }

  // 导出统一走 window.AwdSaveFile：
  // 配了默认下载目录就直接落到那里，否则退回浏览器下载。
  // 返回保存到的完整路径（走浏览器时是 null）。
  function downloadBlob(content, filename, mime) {
    if (!window.AwdSaveFile) {
      return Promise.reject(new Error('保存入口没加载'));
    }
    return window.AwdSaveFile(filename, content, mime);
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
      // statusLabel 对未知 status 是"原样返回"，所以它和 r.status 一样要转义
      //（导出 HTML 那条路径早就 esc 过了，这里以前漏了）
      '  <span class="cp-badge ' + esc(r.status) + '">' + esc(statusLabel(r.status)) + '</span>' +
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
    rep = normalizeReport(rep);
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
    // 记下发起时的目标与序号：核查要跑十几秒，期间用户可能切了目标
    var seq = ++state.loadSeq;
    var tid = state.targetId;
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
        body: JSON.stringify({ target_id: tid }),
        signal: state.abort.signal
      });
      // 期间切过目标、或点过历史：这份结论已经不属于当前界面，丢弃
      // （否则会把 A 的结论渲染在 B 的目标下，还能被导出）
      if (seq !== state.loadSeq || tid !== state.targetId) {
        hint('核查完成，但期间切换过目标，结果未显示（可到「历史」里查看）');
        return;
      }
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
      // 走 AwdViews 收起：自己改 hidden 再无条件恢复 work-body 的 display，
      // 会把此刻开着的别的整页视图一起露出来（叠层）
      if (window.AwdViews && window.AwdViews.isOpen('compliance-area')) {
        window.AwdViews.toggle('compliance-area');
        // toggle 收起视图时是无条件恢复工作区的；万一此刻还开着别的整页视图，
        // 再按回去，否则工作区会和那个视图叠在一起
        if (window.AwdViews.anyOpen()) $('work-body').style.display = 'none';
      } else {
        area.hidden = true;
        if (!window.AwdViews || !window.AwdViews.anyOpen()) $('work-body').style.display = '';
        var btn = $('btn-compliance');
        if (btn) btn.classList.remove('active');
      }
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
