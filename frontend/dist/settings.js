/* awdshell 设置面板。与 app.js / files.js 独立：只负责设置视图。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = { saving: false };

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

  function msg(text, isError) {
    var el = $('st-msg');
    if (!el) return;
    el.textContent = text || '';
    el.className = isError ? 'hint error-text' : 'hint';
  }

  function render() {
    $('settings-area').innerHTML =
      '<div class="st-wrap">' +
      '  <div class="view-head">' +
      '    <span class="view-title">设置</span>' +
      '    <button class="view-close">关闭</button>' +
      '  </div>' +
      '  <section>' +
      '    <h3>连接历史</h3>' +
      '    <div class="st-grid">' +
      '      <label>保留天数（0 = 不限）<input type="number" id="st-days" min="0" max="3650" /></label>' +
      '      <label>最多保留条数（0 = 不限）<input type="number" id="st-max" min="0" max="100000" /></label>' +
      '    </div>' +
      '    <p class="hint">超过限制的旧记录会被自动清理；程序启动时与每 6 小时各执行一次。历史只记录主机、用户、起止时间与错误原因，不记录终端内容。</p>' +
      '  </section>' +
      '  <section>' +
      '    <h3>终端</h3>' +
      '    <div class="st-grid">' +
      '      <label>字号<input type="number" id="st-font" min="10" max="24" /></label>' +
      '      <label>回滚行数<input type="number" id="st-scroll" min="1000" max="200000" /></label>' +
      '    </div>' +
      '    <label class="st-check"><input type="checkbox" id="st-cwd" /> 自动跟随终端目录（终端上报目录变化时自动跳过去，未生效时可用文件面板的「同步」按钮）</label>' +
      '    <p class="hint">字号与回滚行数在下次打开终端时生效。自动跟随依赖 shell 上报目录（OSC 7）；没配置的环境用文件面板上的「同步」按钮即可。</p>' +
      '  </section>' +
      '  <section>' +
      '    <h3>文件</h3>' +
      '    <label class="st-check"><input type="checkbox" id="st-trash" /> 删除时移入远程回收站（更安全）</label>' +
      '    <label class="st-dir-label">默认下载目录' +
      '      <span class="st-dir-row">' +
      '        <input type="text" id="st-download-dir" spellcheck="false" placeholder="留空则交给浏览器下载（只能落到系统默认下载目录）" />' +
      '        <button id="st-pick-dir" type="button">浏览…</button>' +
      '      </span>' +
      '    </label>' +
      '    <p class="hint">填了之后，文件下载与所有导出（核查报告、日志检测结果、威胁态势、数据表 CSV）都直接写到这个目录，不再经过浏览器。同名文件会自动加序号，不覆盖已有的。' +
      '      浏览器模式没有原生目录对话框，「浏览」会提示不支持，手动填路径即可。</p>' +
      '  </section>' +
      '  <section>' +
      '    <h3>检测结果数据</h3>' +
      '    <div class="st-grid">' +
      '      <label>保留天数（0 = 不限）<input type="number" id="st-event-days" min="0" max="3650" /></label>' +
      '    </div>' +
      '    <p class="hint">日志检测的命中结果会落库，用于生成态势（来源 IP 排行、攻击时间线、目标分布）。当前已记录 <b id="st-event-count">-</b> 条。' +
      '      超过保留天数的记录会在程序启动时与每 6 小时各清理一次；也可以在这里立刻清理或整表清空。</p>' +
      '    <div class="st-actions">' +
      '      <button id="st-event-prune">按保留期清理</button>' +
      '      <button id="st-event-clear" class="danger">清空全部结果</button>' +
      '      <span id="st-event-msg" class="hint"></span>' +
      '    </div>' +
      '  </section>' +
      '  <div class="st-actions">' +
      '    <button id="st-save" class="primary">保存设置</button>' +
      '    <button id="st-prune">立即清理历史</button>' +
      '    <span id="st-msg" class="hint"></span>' +
      '  </div>' +
      '</div>';

    $('st-save').addEventListener('click', save);
    $('st-prune').addEventListener('click', pruneNow);
    $('st-event-prune').addEventListener('click', pruneEvents);
    $('st-event-clear').addEventListener('click', clearEvents);
    $('st-pick-dir').addEventListener('click', pickDir);
  }

  // 选默认下载目录。桌面形态走 Wails 的原生目录对话框；
  // 浏览器模式后端会如实报"不支持"，让用户手填。
  async function pickDir() {
    var btn = $('st-pick-dir');
    btn.disabled = true;
    try {
      var r = await req('/api/system/pick-dir', { method: 'POST', body: '{}' });
      if (r.dir) {
        $('st-download-dir').value = r.dir;
        msg('已选目录，点「保存设置」生效');
      }
    } catch (e) {
      msg(e.message, true);
    } finally {
      btn.disabled = false;
    }
  }

  async function load() {
    try {
      var s = await req('/api/settings');
      $('st-days').value = s.conn_keep_days;
      $('st-max').value = s.conn_keep_max;
      $('st-font').value = s.term_font_size;
      $('st-scroll').value = s.term_scrollback;
      $('st-trash').checked = !!s.trash_on_delete;
      $('st-cwd').checked = s.term_track_cwd !== false;
      $('st-event-days').value = s.event_keep_days;
      $('st-download-dir').value = s.download_dir || '';
      loadEventCount();
      msg('已加载当前设置');
    } catch (e) {
      msg('加载设置失败：' + e.message, true);
    }
  }

  function num(id, def) {
    var v = parseInt($(id).value, 10);
    return isNaN(v) ? def : v;
  }

  async function save() {
    if (state.saving) return;
    state.saving = true;
    msg('保存中…');
    try {
      var out = await req('/api/settings', {
        method: 'POST',
        body: JSON.stringify({
          conn_keep_days: num('st-days', 90),
          conn_keep_max: num('st-max', 500),
          term_font_size: num('st-font', 14),
          term_scrollback: num('st-scroll', 10000),
          trash_on_delete: $('st-trash').checked,
          term_track_cwd: $('st-cwd').checked,
          event_keep_days: num('st-event-days', 30),
          download_dir: $('st-download-dir').value.trim()
        })
      });
      // 回写运行时设置：删除是否走回收站、终端目录是否跟随，读的都是
      // window.AWD_SETTINGS。不回写的话用户改完要重启程序才生效，设置项等于摆设。
      window.AWD_SETTINGS = out;
      // 回填经后端夹取后的实际值
      $('st-days').value = out.conn_keep_days;
      $('st-max').value = out.conn_keep_max;
      $('st-font').value = out.term_font_size;
      $('st-scroll').value = out.term_scrollback;
      msg('已保存（' + new Date().toLocaleTimeString() + '）');
    } catch (e) {
      msg('保存失败：' + e.message, true);
    } finally {
      state.saving = false;
    }
  }

  async function loadEventCount() {
    try {
      var c = await req('/api/threat/count');
      var el = $('st-event-count');
      if (el) el.textContent = c.count;
    } catch (e) { /* 数量拿不到不影响其他设置 */ }
  }

  async function pruneEvents() {
    var el = $('st-event-msg');
    el.textContent = '正在清理…';
    el.className = 'hint';
    try {
      var r = await req('/api/threat/prune', { method: 'POST' });
      var left = await req('/api/threat/count');
      el.textContent = '已删除 ' + r.deleted + ' 条，剩余 ' + left.count + ' 条';
      var cnt = $('st-event-count');
      if (cnt) cnt.textContent = left.count;
    } catch (e) {
      el.textContent = '清理失败：' + e.message;
      el.className = 'hint error-text';
    }
  }

  async function clearEvents() {
    if (!window.confirm('确定清空全部检测结果？态势页的历史排行与时间线会一并消失，且无法恢复。')) return;
    var el = $('st-event-msg');
    el.textContent = '正在清空…';
    el.className = 'hint';
    try {
      var r = await req('/api/threat/clear', { method: 'POST' });
      el.textContent = '已清空 ' + r.deleted + ' 条';
      var cnt = $('st-event-count');
      if (cnt) cnt.textContent = '0';
    } catch (e) {
      el.textContent = '清空失败：' + e.message;
      el.className = 'hint error-text';
    }
  }

  async function pruneNow() {
    msg('正在清理…');
    try {
      var r = await req('/api/prune', { method: 'POST' });
      msg('清理完成，删除了 ' + r.removed + ' 条历史记录');
    } catch (e) {
      msg('清理失败：' + e.message, true);
    }
  }

  function boot() {
    render();
    load();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
