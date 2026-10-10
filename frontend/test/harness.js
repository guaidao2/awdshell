/* 前端回归测试的假 DOM 环境（不联网、不起浏览器、不引任何依赖）。

   为什么要有它：frontend/dist 是免构建的原生 JS，这个项目刻意不引 npm 测试链
   （见 key 记忆：构建链只留 Go + Wails），但这一批修复里有几条是**行为**层面的
   —— WebSocket 守卫、innerHTML 转义、切目标重置计时 —— 光看代码/光跑 node --check
   都验不出来，只能真的把脚本跑起来。

   这里造一个最小替身：按 id 现取的假元素、一个假 WebSocket、一个可编程的 fetch。
   够跑 app.js / monitor.js / logscan.js / compliance.js 的渲染与消息路径。 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIST = path.join(__dirname, '..', 'dist');

// mkEl 造一个"够用"的元素：innerHTML 只是字符串（不做 DOM 解析，所以断言要看
// 拼出来的 HTML 里有没有原始 payload，而不是去查子元素）。
function mkEl(id) {
  const ls = {};
  const e = {
    id, tagName: 'DIV', _html: '', textContent: '', value: '', hidden: true, checked: false,
    disabled: false, title: '', className: '', selectedIndex: 0, options: [], children: [],
    parentNode: null, scrollTop: 0, scrollLeft: 0, style: {}, dataset: {},
    classList: {
      _s: {},
      add(c) { this._s[c] = 1; },
      remove(c) { delete this._s[c]; },
      toggle(c, on) { if (on === undefined) on = !this._s[c]; if (on) this._s[c] = 1; else delete this._s[c]; },
      contains(c) { return !!this._s[c]; }
    },
    get innerHTML() { return this._html; },
    set innerHTML(v) { this._html = String(v); },
    addEventListener(t, f) { (ls[t] = ls[t] || []).push(f); },
    removeEventListener() { },
    dispatchEvent() { return true; },
    fire(t, ev) { (ls[t] || []).forEach(f => f.call(this, ev || { target: this })); },
    appendChild(c) { this.children.push(c); if (c) c.parentNode = this; return c; },
    insertBefore(n) { this.children.unshift(n); return n; },
    removeChild(c) { return c; },
    remove() { },
    insertAdjacentHTML(p, h) { this._html = String(h) + this._html; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    closest() { return null; },
    getAttribute(k) { return this.dataset[k] !== undefined ? this.dataset[k] : null; },
    setAttribute(k, v) { this.dataset[k] = v; },
    removeAttribute() { },
    focus() { }, click() { }, contains() { return false; },
    scrollIntoView() { },
    get firstChild() { return this.children[0] || null; }
  };
  return e;
}

function mkTerminal() {
  return {
    // 记下终端里写过什么：断言"旧 socket 的 exit 有没有冒出一句假的连接已结束"
    written: [],
    open() { }, dispose() { }, loadAddon() { }, focus() { },
    write(b) { this.written.push(String(b)); },
    onData(f) { this._data = f; },
    onResize(f) { this._resize = f; },
    parser: { registerOscHandler() { return true; } }
  };
}

// 假 WebSocket：readyState 直接是 OPEN，onopen 异步补一次（浏览器也是异步的，
// openWS 里"onopen 之后才算 ready"那条路径才不会漏测）；
// close() 只置位、**不自动派发 onclose** —— 测试要自己决定什么时候派哪条消息。
function mkWebSocketClass(sockets) {
  function FakeWS(url) {
    this.url = url;
    this.readyState = 1;
    this.closed = false;
    this.sent = [];
    sockets.push(this);
    const self = this;
    setTimeout(function () { if (self.onopen) self.onopen(); }, 0);
  }
  FakeWS.OPEN = 1;
  FakeWS.CONNECTING = 0;
  FakeWS.CLOSING = 2;
  FakeWS.CLOSED = 3;
  FakeWS.prototype.send = function (d) { this.sent.push(d); };
  FakeWS.prototype.close = function () { this.closed = true; this.readyState = 3; };
  return FakeWS;
}

function ok(body) {
  return { ok: true, status: 200, statusText: 'OK', json: async () => body };
}

function createEnv(extra) {
  const els = {};
  const el = id => els[id] || (els[id] = mkEl(id));
  const winListeners = {};
  const docListeners = {};
  const sockets = [];
  const terminals = [];

  const sandbox = {
    console, setTimeout, clearTimeout, setInterval, clearInterval,
    Promise, Date, Math, JSON, Number, String, Boolean, Object, Array, RegExp, Error,
    isNaN, parseInt, parseFloat, encodeURIComponent, decodeURIComponent,
    TextEncoder, TextDecoder,
    Blob: function () { },
    URL: { createObjectURL() { return 'blob:x'; }, revokeObjectURL() { } },
    Event: function (t) { this.type = t; },
    CustomEvent: function (t, o) { this.type = t; this.detail = o && o.detail; },
    localStorage: { getItem() { return null; }, setItem() { } },
    confirm: () => true,
      // toast 替身：被测代码里到处是 window.AwdToast.xxx，缺了它会让
      // catch 分支自己抛错、把真实失败原因盖住
      AwdToast: { error() { }, warn() { }, info() { }, ok() { } },
    AbortController: function () { this.signal = {}; this.abort = function () { }; },
    WebSocket: mkWebSocketClass(sockets),
    Terminal: function () { const t = mkTerminal(); terminals.push(t); return t; },
    FitAddon: { FitAddon: function () { this.fit = function () { }; } },
    fetch: function () { throw new Error('这个用例没有装 fetch 替身'); },
    document: {
      readyState: 'complete',
      body: mkEl('body'),
      getElementById: el,
      createElement: t => mkEl('c-' + t),
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener(t, f) { (docListeners[t] = docListeners[t] || []).push(f); },
      activeElement: null
    },
    location: { origin: 'http://127.0.0.1:9' },
    __AWDSHELL__: { apiBase: 'http://127.0.0.1:9', version: 'test', token: 'test-token' }
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.addEventListener = (t, f) => { (winListeners[t] = winListeners[t] || []).push(f); };
  sandbox.removeEventListener = () => { };
  sandbox.dispatchEvent = ev => {
    (winListeners[ev && ev.type] || []).forEach(f => f(ev));
    return true;
  };
  Object.assign(sandbox, extra || {});

  const ctx = vm.createContext(sandbox);
  return {
    sandbox, el, els, sockets, terminals,
    load(f) { vm.runInContext(fs.readFileSync(path.join(DIST, f), 'utf8'), ctx, { filename: f }); },
    dispatch(type, detail) { sandbox.dispatchEvent(new sandbox.CustomEvent(type, { detail })); },
    sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  };
}

module.exports = { createEnv, ok, DIST };
