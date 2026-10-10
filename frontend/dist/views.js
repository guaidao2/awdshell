/* 整页视图的统一开关。
 *
 * 之前设置、日志检测、基线核查、态势四页各自维护一份"另外三个 area 的 id +
 * 四个 btn 的 id"互斥列表，加第五个视图必然漏一处 —— 表现是按钮亮着但看不见，
 * 或者两个视图叠在一起。这里收成一份注册表，各页只管调 toggle。
 */
(function () {
  'use strict';

  var VIEWS = [
    { area: 'settings-area', btn: 'btn-settings' },
    { area: 'logscan-area', btn: 'btn-logscan' },
    { area: 'compliance-area', btn: 'btn-compliance' },
    { area: 'threat-area', btn: 'btn-threat' },
    { area: 'database-area', btn: 'btn-database' }
  ];

  function $(id) { return document.getElementById(id); }

  function isOpen(area) {
    var el = $(area);
    return !!el && !el.hidden;
  }

  function anyOpen() {
    for (var i = 0; i < VIEWS.length; i++) {
      if (isOpen(VIEWS[i].area)) return true;
    }
    return false;
  }

  // 打开某个视图（并收起其余）；已在显示中就收起它。返回是否变为"显示"
  function toggle(area) {
    var el = $(area);
    if (!el) return false;
    var willOpen = el.hidden;

    if (willOpen) closeAll();
    el.hidden = !willOpen;

    var wb = $('work-body');
    if (wb) wb.style.display = willOpen ? 'none' : '';

    syncButtons(willOpen ? area : '');
    // 工作区显隐变了：监控面板要重新判断自己是不是真的可见
    window.dispatchEvent(new Event('awdshell:monitor-hide'));
    window.dispatchEvent(new Event('resize'));
    return willOpen;
  }

  // 收起全部整页视图（不动当前打开的是哪一个）
  function closeAll() {
    for (var i = 0; i < VIEWS.length; i++) {
      var el = $(VIEWS[i].area);
      if (el) el.hidden = true;
    }
  }

  // 关闭全部并恢复工作区；返回是否确实有关掉了东西
  function closeAllViews() {
    var changed = false;
    for (var i = 0; i < VIEWS.length; i++) {
      var el = $(VIEWS[i].area);
      if (el && !el.hidden) { el.hidden = true; changed = true; }
    }
    if (changed) {
      var wb = $('work-body');
      if (wb) wb.style.display = '';
      syncButtons('');
      window.dispatchEvent(new Event('awdshell:monitor-hide'));
      window.dispatchEvent(new Event('resize'));
    }
    return changed;
  }

  // 让按钮的 active 状态与真实显隐一致
  function syncButtons(activeArea) {
    for (var i = 0; i < VIEWS.length; i++) {
      var b = $(VIEWS[i].btn);
      if (b) b.classList.toggle('active', VIEWS[i].area === activeArea);
    }
  }

  // 界面偏好：存 localStorage。隐私模式或存储被禁时静默退回默认值，
  // 不能让"存不了偏好"变成界面报错。
  var PREFIX = 'awd.';
  function prefGet(key, def) {
    try {
      var v = window.localStorage.getItem(PREFIX + key);
      return v === null ? def : v;
    } catch (e) { return def; }
  }
  function prefSet(key, value) {
    try { window.localStorage.setItem(PREFIX + key, String(value)); } catch (e) { /* 忽略 */ }
  }

  // 渲染"跟随会话 / 已锁定"状态按钮。
  //
  // 为什么需要它：跟随时一切正常，但用户一旦手动选过目标就会锁定，之后切会话
  // 视图不再跟着换 —— 而界面上毫无提示，看起来就像坏了。把状态显出来，
  // 并且给出恢复跟随的入口。
  function followButton(btnId, followActive, label, onRestore) {
    var el = document.getElementById(btnId);
    if (!el) return;
    var what = label || '本视图目标';
    if (followActive) {
      el.textContent = '跟随会话';
      el.className = 'awd-follow on';
      el.title = what + '跟随当前终端会话';
      el.onclick = null;
    } else {
      el.textContent = '已锁定 · 点此跟随';
      el.className = 'awd-follow off';
      el.title = '你手动选过目标，' + what + '已锁定；点一下恢复跟随当前会话';
      // 用 onclick 赋值而不是 addEventListener：本函数每次渲染都会调用，
      // 用后者会持续累积监听
      el.onclick = onRestore || null;
    }
  }

  window.AwdViews = {
    toggle: toggle,
    closeAll: closeAllViews,
    anyOpen: anyOpen,
    isOpen: isOpen,
    syncButtons: syncButtons,
    followButton: followButton
  };

  window.AwdPrefs = { get: prefGet, set: prefSet };
})();
