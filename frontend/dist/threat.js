/* awdshell 威胁态势：把落库的攻击事件聚合成大屏。
   数据是跨目标、跨扫描次数累计的（来源 IP 排行、时间线、目标分布、攻击类型）。
   图表同样只用 CSS 与内联 SVG。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = { days: 7, stats: null, loading: false, targets: [], targetId: '', followActive: true };

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
    var el = $('th-hint');
    if (!el) return;
    el.textContent = msg || '';
    el.className = isError ? 'th-hint error-text' : 'th-hint';
  }

  // 时间戳统一是毫秒（与连接历史、核查报告一致）
  function fmtTime(ms) {
    if (!ms) return '-';
    var d = new Date(ms);
    var p = function (n) { return n < 10 ? '0' + n : '' + n; };
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function sevLabel(s) {
    return { critical: '严重', high: '高', medium: '中', low: '低' }[s] || s;
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

  // ---------- 骨架 ----------

  function renderShell() {
    $('threat-area').innerHTML =
      '<div class="th-wrap">' +
      '  <div class="view-head">' +
      '    <span class="view-title">威胁态势</span>' +
      '    <span class="th-hint" id="th-hint"></span>' +
      '    <button class="view-close">关闭</button>' +
      '  </div>' +
      '  <div class="th-toolbar">' +
      '    <select id="th-target" class="th-target" title="默认全部主机；选一台就只看它的态势"></select>' +
      '    <button id="th-follow-state" class="awd-follow" title=""></button>' +
      '    <div class="th-range">' +
      '      <button data-days="1">24 小时</button>' +
      '      <button data-days="7" class="active">7 天</button>' +
      '      <button data-days="30">30 天</button>' +
      '      <button data-days="90">90 天</button>' +
      '    </div>' +
      '    <button id="th-refresh">刷新</button>' +
      '    <button id="th-export" title="把排行与时间线导成 CSV">导出</button>' +
      '    <button id="th-clear" class="danger">清空数据</button>' +
      '    <span class="th-updated" id="th-updated"></span>' +
      '  </div>' +
      '  <div class="th-body" id="th-body">' +
      '    <div class="th-empty">还没有检测数据。到「日志检测」里对某台主机扫一次，' +
      '      命中结果会自动汇总到这里，形成来源排行与攻击时间线。</div>' +
      '  </div>' +
      '</div>';

    var btns = document.querySelectorAll('.th-range button');
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', function () {
        state.days = parseInt(this.getAttribute('data-days'), 10);
        var all = document.querySelectorAll('.th-range button');
        for (var j = 0; j < all.length; j++) all[j].classList.toggle('active', all[j] === this);
        load();
      });
    }
    $('th-refresh').addEventListener('click', load);
    $('th-export').addEventListener('click', exportStats);
    $('th-clear').addEventListener('click', clearAll);

    // 目标筛选：默认"全部主机"（跨目标汇总），也可以只看某一台
    $('th-target').addEventListener('change', function () {
      state.targetId = this.value;
      state.followActive = false;
      renderTargets();
      load();
    });
  }

  // 目标下拉：第一项是"全部主机"，其余是各台目标
  function renderTargets() {
    var sel = $('th-target');
    if (!sel) return;
    var html = '<option value="">全部主机</option>';
    html += state.targets.map(function (t) {
      return '<option value="' + esc(t.id) + '"' + (t.id === state.targetId ? ' selected' : '') + '>' +
        esc(t.name) + '</option>';
    }).join('');
    sel.innerHTML = html;

    if (window.AwdViews) {
      window.AwdViews.followButton('th-follow-state', state.followActive, '态势范围', function () {
        state.followActive = true;
        syncToActiveSession();
        renderTargets();
        load();
      });
    }
  }

  async function loadTargets() {
    try {
      state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    } catch (e) {
      state.targets = [];
    }
    renderTargets();
  }

  // 跟随当前会话：把筛选取成那台主机；用户选过"全部主机"或某台之后就不再自动改
  function syncToActiveSession() {
    if (!state.followActive) return false;
    var tid = window.AwdActiveTarget ? window.AwdActiveTarget() : '';
    if (!tid || tid === state.targetId) return false;
    state.targetId = tid;
    renderTargets();
    return true;
  }

  // 把态势数据导成 CSV：来源排行、类型分布、目标分布、时间线各一段。
  // 一段一个表头，方便直接贴进报告或表格工具。
  async function exportStats() {
    var st = state.stats;
    if (!st || !st.total) { hint('还没有数据可以导出', true); return; }

    function csvCell(v) {
      var s = String(v == null ? '' : v);
      return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }
    function section(title, head, rows) {
      var out = ['### ' + title, head.join(',')];
      rows.forEach(function (r) { out.push(r.map(csvCell).join(',')); });
      out.push('');
      return out;
    }

    var lines = [];
    lines.push('# 威胁态势　统计范围：最近 ' + state.days + ' 天　命中总数：' + st.total +
      '　解码后命中：' + st.decoded_total + '　导出时间：' + new Date().toLocaleString());
    lines.push('');

    lines = lines.concat(section('攻击来源排行', ['来源地址', '次数', '涉及目标数', '其中严重', '首次', '最近'],
      (st.by_source_ip || []).map(function (r) {
        return [r.ip, r.count, r.targets, r.critical, fmtTime(r.first_seen), fmtTime(r.last_seen)];
      })));
    lines = lines.concat(section('攻击类型分布', ['类型', '次数'],
      (st.by_category || []).map(function (r) { return [r.name, r.count]; })));
    lines = lines.concat(section('目标分布', ['目标', '次数'],
      (st.by_target || []).map(function (r) { return [r.name, r.count]; })));
    lines = lines.concat(section('命中规则', ['规则编号', '次数'],
      (st.by_rule || []).map(function (r) { return [r.name, r.count]; })));
    lines = lines.concat(section('时间线', ['日期', '次数'],
      (st.timeline || []).map(function (r) { return [r.bucket, r.count]; })));
    lines = lines.concat(section('最近事件', ['时间', '级别', '规则', '来源', '目标', '片段'],
      (st.recent || []).map(function (e) {
        return [fmtTime(e.ts), sevLabel(e.severity), e.rule_id, e.source_ip || '', e.target_name, e.sample || ''];
      })));

    // BOM：不加的话 Excel 打开中文会乱码
    var fname = '威胁态势-' + new Date().toISOString().slice(0, 10) + '.csv';
    try {
      if (!window.AwdSaveFile) throw new Error('保存入口没加载，刷新一下页面');
      var saved = await window.AwdSaveFile(fname, '\ufeff' + lines.join('\r\n'), 'text/csv;charset=utf-8');
      hint(saved ? ('已保存到 ' + saved) : '已导出态势数据');
    } catch (e) {
      hint('保存失败：' + e.message, true);
    }
  }

  // ---------- 渲染 ----------

  function timelineChart(tl) {
    if (!tl || !tl.length) return '';
    var W = 640, H = 90, pad = 4;
    // bucket / count 落空时不能直接算：undefined 参与运算会得到 NaN，
    // 整张图的柱子高度全变成 "NaN"，比不显示还难判断
    var max = 1;
    tl.forEach(function (b) { max = Math.max(max, Number(b && b.count) || 0); });
    var bw = Math.min(38, Math.max(4, (W - pad * 2) / tl.length - 3));

    var bars = tl.map(function (b, i) {
      var h = ((Number(b && b.count) || 0) / max) * (H - 22);
      var x = pad + i * ((W - pad * 2) / tl.length);
      var y = H - 16 - h;
      return '<rect class="th-bar" x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" ' +
        'width="' + bw.toFixed(1) + '" height="' + Math.max(1, h).toFixed(1) + '" rx="2">' +
        '<title>' + esc(b && b.bucket) + '：' + (Number(b && b.count) || 0) + ' 条</title></rect>';
    }).join('');

    // 只标首个与末个日期，中间交给柱子本身表达。
    // bucket 落空时 slice 会抛，先转成字符串再截。
    var first = String((tl[0] && tl[0].bucket) == null ? '' : tl[0].bucket).slice(5);
    var last = String((tl[tl.length - 1] && tl[tl.length - 1].bucket) == null ? '' : tl[tl.length - 1].bucket).slice(5);
    return '<div class="th-chart">' +
      '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' + bars + '</svg>' +
      '<div class="th-chart-axis"><span>' + esc(first) + '</span><span>' + esc(last) + '</span></div>' +
      '</div>';
  }

  function barList(items, opts) {
    opts = opts || {};
    if (!items || !items.length) return '<div class="th-sub">暂无数据</div>';
    var max = items[0].count || 1;
    return items.slice(0, opts.limit || 10).map(function (it) {
      var label = opts.label ? opts.label(it.name) : it.name;
      return '<div class="th-bar-row" title="' + esc(it.name + '：' + it.count) + '">' +
        '<span class="k">' + esc(label) + '</span>' +
        '<span class="b"><i class="' + (opts.cls || '') + '" style="width:' +
        Math.max(3, (it.count / max) * 100).toFixed(1) + '%"></i></span>' +
        '<span class="v">' + it.count + '</span></div>';
    }).join('');
  }

  function sourceTable(rows) {
    if (!rows || !rows.length) return '<div class="th-sub">暂无来源数据</div>';
    var body = rows.slice(0, 15).map(function (r) {
      return '<tr>' +
        '<td class="ip">' + esc(r.ip) + '</td>' +
        '<td class="num">' + r.count + '</td>' +
        '<td class="num">' + r.targets + '</td>' +
        '<td class="num ' + (r.critical > 0 ? 'crit' : '') + '">' + r.critical + '</td>' +
        '<td class="time">' + fmtTime(r.first_seen) + '</td>' +
        '<td class="time">' + fmtTime(r.last_seen) + '</td>' +
        '</tr>';
    }).join('');

    return '<div class="th-table-wrap"><table class="th-table">' +
      '<thead><tr><th>来源地址</th><th>次数</th><th>目标</th><th>严重</th><th>首次</th><th>最近</th></tr></thead>' +
      '<tbody>' + body + '</tbody></table></div>';
  }

  function recentList(rows) {
    if (!rows || !rows.length) return '<div class="th-sub">暂无事件</div>';
    return rows.slice(0, 24).map(function (e) {
      return '<div class="th-event sev-' + esc(e.severity) + '">' +
        '<span class="t">' + fmtTime(e.ts) + '</span>' +
        '<span class="sev">' + esc(sevLabel(e.severity)) + '</span>' +
        '<span class="rule">' + esc(e.rule_id) + '</span>' +
        (e.source_ip ? '<span class="ip">' + esc(e.source_ip) + '</span>' : '') +
        '<span class="target">' + esc(e.target_name) + '</span>' +
        '<span class="sample" title="' + esc(e.sample) + '">' + esc(e.sample) + '</span>' +
        '</div>';
    }).join('');
  }

  function render(st) {
    // 后端返回非对象（代理错误页、接口不匹配）时不要冒成
    // "Cannot read properties of null (reading 'total')"
    if (!st || typeof st !== 'object') {
      $('th-body').innerHTML = '<div class="th-empty error-text">数据格式不符合预期，请稍后重试</div>';
      return;
    }
    state.stats = st;

    if (!st.total) {
      $('th-body').innerHTML =
        '<div class="th-empty">所选时间范围内没有检测数据。到「日志检测」里扫一次日志，' +
        '命中结果会自动汇总到这里。</div>';
      return;
    }

    var critical = 0;
    (st.by_severity || []).forEach(function (s) { if (s.name === 'critical') critical = Number(s.count) || 0; });

    var card = function (cls, n, label, sub) {
      return '<div class="th-stat ' + cls + '"><span class="n">' + n + '</span>' +
        '<span class="l">' + label + '</span>' +
        (sub ? '<span class="s">' + sub + '</span>' : '') + '</div>';
    };

    $('th-body').innerHTML =
      '<div class="th-stats">' +
      card('', st.total, '命中总数', '所选时间范围内') +
      card('crit', critical, '严重级别', 'critical') +
      card('', (st.by_source_ip || []).length, '来源地址', '独立 IP 数') +
      card('', (st.by_target || []).length, '涉及主机', '被检测出问题的主机') +
      card('dec', (Number(st.decoded_total) || 0), '解码后命中', '原文看不出、解码才发现') +
      '</div>' +

      '<div class="th-grid">' +
      '  <section class="th-card th-span2">' +
      '    <div class="th-card-head"><span>攻击时间线</span><span class="th-sub">按天统计</span></div>' +
      timelineChart(st.timeline) +
      '  </section>' +

      '  <section class="th-card th-span2">' +
      '    <div class="th-card-head"><span>攻击来源排行</span>' +
      '      <span class="th-sub">共 ' + (st.by_source_ip || []).length + ' 个来源</span></div>' +
      sourceTable(st.by_source_ip) +
      '  </section>' +

      '  <section class="th-card">' +
      '    <div class="th-card-head"><span>攻击类型分布</span></div>' +
      barList(st.by_category, { limit: 10 }) +
      '  </section>' +

      '  <section class="th-card">' +
      '    <div class="th-card-head"><span>目标分布</span></div>' +
      barList(st.by_target, { limit: 10 }) +
      '  </section>' +

      '  <section class="th-card">' +
      '    <div class="th-card-head"><span>命中规则 TOP</span></div>' +
      barList(st.by_rule, { limit: 10 }) +
      '  </section>' +

      '  <section class="th-card">' +
      '    <div class="th-card-head"><span>严重级别分布</span></div>' +
      barList(st.by_severity, { limit: 6, label: sevLabel }) +
      '  </section>' +

      '  <section class="th-card th-span2">' +
      '    <div class="th-card-head"><span>最近事件</span>' +
      '      <span class="th-sub">最多 24 条</span></div>' +
      '    <div class="th-events">' + recentList(st.recent) + '</div>' +
      '  </section>' +
      '</div>';

    $('th-updated').textContent = '数据截至 ' + new Date().toLocaleTimeString();
  }

  // ---------- 数据 ----------

  async function load() {
    if (state.loading) return;
    state.loading = true;
    hint('正在汇总…');
    try {
      var q = '/api/threat/stats?days=' + state.days;
      if (state.targetId) q += '&target_id=' + encodeURIComponent(state.targetId);
      var st = await req(q);
      render(st);
      hint('统计范围：最近 ' + state.days + ' 天，共 ' + st.total + ' 条命中');
      setStatus('威胁态势：最近 ' + state.days + ' 天 ' + st.total + ' 条命中');
    } catch (e) {
      hint('加载失败：' + e.message, true);
      setStatus('威胁态势加载失败：' + e.message);
    } finally {
      state.loading = false;
    }
  }

  async function clearAll() {
    if (!window.confirm('确定清空全部检测结果？态势的排行与时间线会一并消失，且无法恢复。')) return;
    hint('正在清空…');
    try {
      var r = await req('/api/threat/clear', { method: 'POST' });
      hint('已清空 ' + r.deleted + ' 条');
      load();
    } catch (e) {
      hint('清空失败：' + e.message, true);
    }
  }

  // ---------- 显隐 ----------

  function toggleThreat() {
    var on = window.AwdViews.toggle('threat-area');
    if (on) {
      // 每次打开都回到"跟随当前会话"的范围
      state.followActive = true;
      loadTargets().then(function () {
        state.targetId = '';
        state.followActive = true;
        syncToActiveSession();
        renderTargets();
        load();
      });
    }
  }

  // ---------- 初始化 ----------

  function boot() {
    renderShell();
    $('btn-threat').addEventListener('click', toggleThreat);
    // 切换终端会话时跟着换主机（用户手动选过就锁定）
    window.addEventListener('awdshell:connected', function () {
      if (syncToActiveSession() && !$('threat-area').hidden) load();
    });
    window.addEventListener('awdshell:targets-changed', function () {
      loadTargets();
    });
    loadTargets().catch(function () { /* 首次打开时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
