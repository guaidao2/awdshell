/* 给本服务的所有请求自动带上控制面令牌。
 *
 * 背景：控制面只监听 127.0.0.1，但桌面形态（Wails WebView）与浏览器形态的
 * 页面来源不一样，靠 Origin 白名单去认"自己人"很容易把桌面形态自己挡在门外
 * —— 表现就是界面上所有请求报 Failed to fetch。
 *
 * 改成令牌：服务启动时随机生成，随 /runtime.js 注入页面，这里统一给请求加上。
 * 既不用猜来源，也让本机其它进程难以直接调用控制面。
 *
 * 用包装 window.fetch 的方式做，这样各模块的请求代码一行都不用改。
 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var TOKEN = CFG.token || '';
  if (!TOKEN) return; // 没注入令牌（例如直接打开静态文件）就按原样走

  var HEADER = 'X-Awd-Token';
  var origFetch = window.fetch;
  if (typeof origFetch !== 'function') return;

  function needsToken(url) {
    return url.indexOf('/api/') >= 0 || url.indexOf('/ws/') >= 0;
  }

  window.fetch = function (input, init) {
    try {
      var url = typeof input === 'string' ? input : ((input && input.url) || '');
      if (url && needsToken(url)) {
        init = init || {};
        var headers = new Headers(init.headers || (input && input.headers) || {});
        headers.set(HEADER, TOKEN);
        init.headers = headers;
        // fetch(Request, init) 时要把原 Request 拆开，否则 init 里的 headers 不生效
        if (typeof input !== 'string') {
          return origFetch.call(this, input.url, Object.assign({
            method: input.method,
            credentials: input.credentials,
            mode: input.mode,
            cache: input.cache,
            redirect: input.redirect,
            referrer: input.referrer,
            body: input.body,
            signal: init.signal || input.signal
          }, init));
        }
      }
    } catch (e) {
      // 包装出错也不能让原请求发不出去
    }
    return origFetch.call(this, input, init);
  };

  // WebSocket 不好统一加头，令牌走查询串；这里只暴露给需要的地方
  window.AwdToken = TOKEN;
})();
