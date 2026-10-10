/* 目标列表的单一来源。
 *
 * 之前 app / files / monitor / logscan / compliance 各存一份副本，靠
 * awdshell:targets-changed 事件互相通知；只要哪个模块漏了监听，表现就是
 * "这个视图的下拉里还是旧列表，得重开一次视图"。这里收成一处缓存：
 * 所有视图读同一份，增删改之后由这里统一失效并广播。
 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');

  var cache = null;
  var inflight = null;

  function load(force) {
    if (cache && !force) return Promise.resolve(cache);
    if (inflight) return inflight;

    inflight = fetch(API + '/api/targets', { headers: { 'Content-Type': 'application/json' } })
      .then(function (res) {
        if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
        return res.json();
      })
      .then(function (list) {
        cache = list || [];
        inflight = null;
        return cache;
      })
      .catch(function (e) {
        inflight = null;
        throw e;
      });
    return inflight;
  }

  function invalidate() { cache = null; }

  function current() { return cache || []; }

  // 目标被新建 / 修改 / 删除之后调用：清掉缓存并广播，各视图会重新取
  function changed() {
    invalidate();
    window.dispatchEvent(new Event('awdshell:targets-changed'));
  }

  // 收到广播时先失效缓存，下一次 load 才会真的重新拉
  window.addEventListener('awdshell:targets-changed', invalidate);

  window.AwdTargets = {
    load: load,
    invalidate: invalidate,
    current: current,
    changed: changed
  };
})();
