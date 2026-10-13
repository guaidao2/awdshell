/* 前端回归测试（node frontend/test/run.js，失败退出码 1）。

   钉的是复审报告里那几条前端问题：
     低2 app.js：WebSocket onmessage 少了 `s.ws !== ws` 守卫 —— 旧 socket 迟到
           一条 exit 会把**新**连接标成已断开，而且此后不再自动重连
     低7 compliance.js：statusLabel(r.status) 未转义
     低8 monitor.js 的 c.id / p.pid、logscan.js 的 h.line_no 未转义
     低9 monitor.js：下拉切目标没有重置 lastOkAt，"距上次 N 秒"会跨主机算
   每条都写成"改回错误版本会红"的形式。 */
'use strict';
const fs = require('fs');
const path = require('path');
const { createEnv, ok } = require('./harness');

const PAY = '<img src=x onerror=window.__PWN=1>';
let fails = 0;
function check(label, cond, extra) {
  console.log((cond ? '  ok   ' : '  FAIL ') + label + (extra !== undefined ? '  [' + extra + ']' : ''));
  if (!cond) fails++;
}

// ---------- 低2：WebSocket 守卫 ----------
async function caseWsGuard() {
  console.log('--- 低2) app.js：旧 socket 迟到的 exit 不能污染新连接 ---');
  const env = createEnv();
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/settings') >= 0) body = {};
    else if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A', host: 'h', port: 22, username: 'u' }];
    else if (u.indexOf('/api/recent') >= 0) body = [];
    else if (u.indexOf('/api/history') >= 0) body = [];
    else if (u.indexOf('/api/files/startdir') >= 0) body = { path: '', source: 'none' };
    else if (u.indexOf('/attach') >= 0) body = { session_id: 's1', target_id: 't1', title: 'A', ws_token: 'tok2' };
    else if (u.indexOf('/api/sessions') >= 0) body = { session_id: 's1', target_id: 't1', title: 'A', ws_token: 'tok1' };
    return ok(body);
  };
  env.load('app.js');
  await env.sleep(30);

  // 点左侧目标 → 开第一个会话（app.js 把点击委托挂在 sidebar-body 上）
  env.el('sidebar-body').fire('click', { target: { closest: () => ({ dataset: { act: 'connect', id: 't1' } }) } });
  await env.sleep(30);
  check('开出了第一条 WebSocket', env.sockets.length === 1, env.sockets.length);
  check('会话状态是 ready', env.el('tabs').innerHTML.indexOf('dot ready') >= 0, env.el('tabs').innerHTML);

  // 掉线 → 自动重连（1 秒退避）→ 第二条 socket 接管
  const ws1 = env.sockets[0];
  ws1.onclose();
  await env.sleep(1400);
  check('重连换出了第二条 WebSocket', env.sockets.length === 2, env.sockets.length);
  check('旧 socket 已被关掉', ws1.closed === true);
  const ws2 = env.sockets[1];

  // 关键一步：旧 socket 迟到一条 exit
  ws1.onmessage({ data: JSON.stringify({ type: 'exit', detail: '迟到的旧消息' }) });
  check('新连接没被标成已断开', env.el('tabs').innerHTML.indexOf('dot closed') < 0, env.el('tabs').innerHTML);
  const termText = env.terminals.map(t => t.written.join('')).join('');
  check('终端里没有冒出假的「连接已结束」', termText.indexOf('连接已结束') < 0, termText.slice(-60));

  // 真正的后果：新 socket 自己断开时还能不能自动重连（gaveUp 没被置位）
  ws2.onclose();
  await env.sleep(1400);
  check('新 socket 断开后仍会自动重连', env.sockets.length === 3, env.sockets.length);

  // 守卫不能把"真 exit"一起挡掉：当前 socket 的 exit 必须照旧生效
  const ws3 = env.sockets[2];
  check('重连后确实有第三条 socket', !!ws3, env.sockets.length);
  if (ws3) {
    ws3.onmessage({ data: JSON.stringify({ type: 'exit', detail: '正常退出' }) });
    check('当前 socket 的 exit 仍然生效', env.el('tabs').innerHTML.indexOf('dot closed') >= 0, env.el('tabs').innerHTML);
    check('当前 socket 自己关掉了', ws3.closed === true);
  }
}

// ---------- 低7：基线核查报告渲染 ----------
async function caseComplianceEscape() {
  console.log('--- 低7) compliance.js：未知 status 不能原样进 innerHTML ---');
  const env = createEnv({ AwdActiveTarget: () => 't1' });
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A' }];
    else if (u.indexOf('/api/compliance/history') >= 0) body = { reports: [] };
    else if (u.indexOf('/api/compliance/run') >= 0) {
      body = {
        target: 'A', started_at: 1, elapsed_ms: 5,
        summary: { total: 1, pass: 0, fail: 0, manual: 0, error: 0, score: 100 },
        results: [{ id: 'c1', status: PAY, severity: 'high', title: 'T', detail: 'D' }]
      };
    }
    return ok(body);
  };
  env.load('views.js');
  env.load('toast.js');
  env.load('compliance.js');
  await env.sleep(30);

  env.el('btn-compliance').fire('click');
  await env.sleep(30);
  env.el('cp-run').fire('click');
  await env.sleep(50);

  const html = env.el('cp-body').innerHTML;
  check('报告渲染出来了', html.indexOf('cp-item') >= 0, html.slice(0, 100));
  check('status 没原样进 innerHTML', html.indexOf('<img src=x') < 0);
  check('转义成了 &lt;img', html.indexOf('&lt;img') >= 0);
}

// ---------- 低8：监控的数值字段 ----------
async function caseMonitorEscape() {
  console.log('--- 低8) monitor.js：c.id / p.pid 不能原样进 innerHTML ---');
  const env = createEnv({ AwdActiveTarget: () => 't1' });
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A' }, { id: 't2', name: 'B' }];
    else if (u.indexOf('/api/monitor') >= 0) {
      body = {
        ts: Date.now(), os_name: 'Linux', cpu_percent: 1, load1: 1, load5: 1, load15: 1,
        cpu_cores: [{ id: PAY, percent: 1 }],
        mem_total: 100, mem_used: 10, net: [], disks: [], conns: [], listeners: [],
        procs: [{ pid: PAY, user: 'u', cpu: 1, mem: 1, comm: 'x', args: 'a' }]
      };
    }
    return ok(body);
  };
  env.load('monitor.js');
  await env.sleep(30);

  env.el('btn-monitor').fire('click');
  await env.sleep(60);
  check('CPU 卡片渲染出来了', env.el('mo-cpu').innerHTML.indexOf('mo-core') >= 0);
  check('c.id 已转义', env.el('mo-cpu').innerHTML.indexOf('<img src=x') < 0, env.el('mo-cpu').innerHTML.slice(0, 120));
  check('p.pid 已转义', env.el('mo-proc-list').innerHTML.indexOf('<img src=x') < 0, env.el('mo-proc-list').innerHTML.slice(0, 120));
}

// ---------- 低9：切目标不能沿用上一台的"距上次 N 秒" ----------
async function caseMonitorSwitchTarget() {
  console.log('--- 低9) monitor.js：切目标要重置"距上次"的计时 ---');
  const env = createEnv({ AwdActiveTarget: () => 't1' });
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A' }, { id: 't2', name: 'B' }];
    else if (u.indexOf('/api/monitor') >= 0) {
      body = {
        ts: Date.now(), os_name: 'Linux', cpu_percent: 1, load1: 1, load5: 1, load15: 1,
        cpu_cores: [], mem_total: 100, mem_used: 10, net: [], disks: [], conns: [], listeners: [], procs: []
      };
    }
    return ok(body);
  };
  env.load('monitor.js');
  await env.sleep(30);

  env.el('btn-monitor').fire('click');
  await env.sleep(60);
  const st1 = env.el('status').textContent;
  check('第一台主机第一次采样不该有"距上次"', st1.indexOf('距上次') < 0, st1);

  // 让"距上次"有 ≥1 秒可算，再手动切到第二台主机
  await env.sleep(1600);
  env.el('mo-target').value = 't2';
  env.el('mo-target').fire('change');
  await env.sleep(80);
  const st2 = env.el('status').textContent;
  check('切到第二台后的第一次采样不能沿用第一台的时刻', st2.indexOf('距上次') < 0, st2);
}

// ---------- 低8：日志检测的行号 ----------
async function caseLogscanEscape() {
  console.log('--- 低8) logscan.js：h.line_no 不能原样进 innerHTML ---');
  const env = createEnv({ AwdActiveTarget: () => 't1' });
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/logs/files') >= 0) body = [{ path: '/var/log/a.log', kind: 'system', size: 1 }];
    else if (u.indexOf('/api/logs/scan') >= 0) {
      body = {
        kind: 'system', rule_count: 1, scanned: 1, hit_line_count: 1, decoded_hits: 0,
        hits: [{ severity: 'high', rule_id: 'r1', rule_name: 'R', line_no: PAY, matched: 'm', line: 'l' }],
        correlations: [{ severity: 'high', title: 'c', detail: 'd', source_ip: '1.2.3.4', first_line: PAY }],
        by_severity: {}
      };
    } else if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A' }];
    return ok(body);
  };
  env.load('views.js');
  env.load('toast.js');
  env.load('logscan.js');
  await env.sleep(30);

  env.el('btn-logscan').fire('click');
  await env.sleep(50);
  env.el('ls-scan').fire('click');
  await env.sleep(50);

  const html = env.el('ls-body').innerHTML;
  check('命中行渲染出来了', html.indexOf('ls-hit') >= 0, html.slice(0, 100));
  check('h.line_no 已转义（命中行的行号）', html.indexOf('<img src=x') < 0);
  // 关联发现里的 first_line 走的是整段 meta 的 esc：既不能漏（上面那条），
  // 也不能在 meta 里再 esc 一次（那样会变成 &amp;lt; 双重转义）
  check('关联发现的行号既没漏也没双重转义',
    html.indexOf('corr-meta') >= 0 && html.indexOf('&amp;lt;') < 0);
}

// ---------- 前端一致性：8 份 req 的能力必须一致 ----------
//
// awdshell 的 8 个脚本**各有自己的一份 `req`**（app.js 那份不服务其它视图），
// 于是同一个修复要改 8 处 —— 已经因此漏过两次，都是终审抓出来的：
//   1) 只给 app.js 挂了 `res.status` → monitor.js 的 `if (e.status === 409)`
//      成了死代码，切目标时照样报红色"采集失败"；
//   2) 只给 app.js 展开了 `failed[]` → files.js 删除失败（409 的响应体**没有
//      error 字段**，只有 failed）只显示一句 "409 Conflict"，哪条路径为什么失败全丢。
//
// 这两条都是"代码看起来对了、跑起来没人管"的类型，所以用静态一致性检查盯住它们。
//
// **这条检查的能力边界（实测过，别高估）**：它是"存在性检查"，不是"可达性检查" ——
// 把分支短路成 `false && j.failed` 它照样通过。但实际发生过的两次漏改都是
// **整处没写**（一份 req 完全没有 status / 完全没有 failed 分支），那种形态它抓得住。
// 要抓死代码得真把 files.js 在假 DOM 里跑起来，成本明显更高，先不做。
async function caseReqConsistency() {
  console.log('--- 前端一致性）8 份 req：都挂 status，会删文件的那份要展开 failed ---');
  const all = ['app.js', 'compliance.js', 'database.js', 'files.js', 'logscan.js',
    'monitor.js', 'settings.js', 'threat.js'];
  const src = {};
  for (const f of all) {
    src[f] = fs.readFileSync(path.join(__dirname, '..', 'dist', f), 'utf8');
    check(f + ' 的 req 挂了 res.status', /\.status\s*=\s*res\.status/.test(src[f]));
  }
  // 老写法残留 = 有文件漏改（只要还 throw 裸 Error，调用方就拿不到状态码）
  for (const f of all) {
    if (f === 'app.js') continue; // app.js 在 !res.ok 里走的是 reqErr，下面单独看
    check(f + ' 没有残留裸 throw new Error(msg)',
      !/throw new Error\(msg\)/.test(src[f]));
  }
  check('app.js 也挂了 res.status', /\.status\s*=\s*res\.status/.test(src['app.js']));

  // /api/files/delete 的 409 响应体只有 {ok,trashed,deleted,failed} —— **没有 error**。
  // 谁调它，谁的 req 就必须认 failed，否则失败原因看不见。
  const deleteCallers = all.filter(f => /\/api\/files\/delete/.test(src[f]));
  check('至少有一个脚本会调 /api/files/delete', deleteCallers.length > 0, deleteCallers.join(','));
  for (const f of deleteCallers) {
    check(f + '（会调 delete）的 req 展开了 failed[]', /j\.failed/.test(src[f]));
  }
  // monitor.js 会调 /api/monitor，409 要能按状态码分支
  check('monitor.js 按 e.status 分支处理 409', /e\.status\s*===\s*409/.test(src['monitor.js']));
}

// ---------- 终端快捷键：一次按键只做一件事 ----------
//
// 症状（作者实测）：Ctrl+Shift+V 会粘贴两次。
//
// 根因：Chromium / WebView2 把 Ctrl+Shift+V（以及 Shift+Insert）也当成"粘贴"，
// 会在 xterm 的输入框上再派发一次 paste 事件、xterm 照单全收。而
// attachCustomKeyEventHandler 返回 false **只**表示"别把它当按键发给远端"，
// 并不阻止浏览器默认行为 —— 于是"读剪贴板粘一次 + xterm 自己粘一次"。
//
// 这条用例能跑起来的前提是 harness 的 Terminal 替身实现了
// attachCustomKeyEventHandler：此前它没有这个方法，typeof 判断为假、
// handler 从未注册，所以整个终端快捷键路径在测试里是空白。
async function caseTermKeyHandler() {
  console.log('--- 终端快捷键）粘贴键必须 preventDefault，否则一次按键粘两遍 ---');
  const env = createEnv({ navigator: { clipboard: { readText: async () => 'PASTED' } } });
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/settings') >= 0) body = {};
    else if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A', host: 'h', port: 22, username: 'u' }];
    else if (u.indexOf('/api/recent') >= 0) body = [];
    else if (u.indexOf('/api/history') >= 0) body = [];
    else if (u.indexOf('/api/files/startdir') >= 0) body = { path: '', source: 'none' };
    else if (u.indexOf('/api/sessions') >= 0) body = { session_id: 's1', target_id: 't1', title: 'A', ws_token: 'tok1' };
    return ok(body);
  };
  env.load('app.js');
  await env.sleep(30);
  env.el('sidebar-body').fire('click', { target: { closest: () => ({ dataset: { act: 'connect', id: 't1' } }) } });
  await env.sleep(30);

  const term = env.terminals[0];
  check('Terminal 替身注册上了按键处理（此前缺这个方法，整个快捷键路径没被测过）',
    typeof term._keyHandler === 'function');
  if (typeof term._keyHandler !== 'function') return;

  const mkEv = over => Object.assign({
    type: 'keydown', key: 'v', ctrlKey: true, shiftKey: true, metaKey: false,
    defaultPrevented: false,
    preventDefault: function () { this.defaultPrevented = true; }
  }, over || {});

  for (const [label, ev] of [
    ['Ctrl+Shift+V', mkEv()],
    ['Shift+Insert', mkEv({ key: 'Insert', ctrlKey: false })]
  ]) {
    const ret = term._keyHandler(ev);
    check(label + ' 阻止了浏览器默认粘贴（不拦就会再粘一次）', ev.defaultPrevented === true);
    check(label + ' 不让 xterm 把按键当输入发给远端', ret === false);
  }
  await env.sleep(20);
  check('剪贴板内容粘进了终端', term.pasted.join('|') === 'PASTED|PASTED', term.pasted.join('|'));

  // 没有 clipboard API 的环境：不能拦默认行为，否则浏览器默认粘贴也被挡住、
  // 整条粘贴路径彻底失效；但仍然不能让按键发给远端。
  env.sandbox.navigator.clipboard = null;
  const evNoApi = mkEv();
  const retNoApi = term._keyHandler(evNoApi);
  check('没有 clipboard API 时不拦默认行为（让浏览器默认粘贴兜底）', evNoApi.defaultPrevented === false);
  check('没有 clipboard API 时仍不让按键发给远端', retNoApi === false);

  // 这两条是作者明确要求过的语义，别被粘贴相关的改动带跑
  check('Ctrl+C 仍然放行（永远是 SIGINT）',
    term._keyHandler(mkEv({ key: 'c', shiftKey: false })) === true);
  check('Ctrl+A 仍然不拦（shell 里是移到行首）',
    term._keyHandler(mkEv({ key: 'a', shiftKey: false })) === true);
  const evCopy = mkEv({ key: 'c' });
  term._keyHandler(evCopy);
  check('Ctrl+Shift+C 也拦了默认行为（浏览器会当"打开开发者工具"）', evCopy.defaultPrevented === true);

  // 输入字节本身也要对：回车是单个 CR(13)、Ctrl+C 是单个 0x03。
  // 这两个字节要是发错（发成可见字符或别的编码），远端交互程序就认不出，
  // 表现正是"回车变 ^M、Ctrl+C 变 ^C"。后端确认是原样写 stdin，所以这一侧要钉死。
  term._data('\r');
  term._data('\x03');
  const sentBytes = env.sockets[0].sent
    .filter(x => x && typeof x !== 'string')
    .map(x => Array.from(x).join(','));
  check('回车发出的是单个 CR(13)', sentBytes.indexOf('13') >= 0, sentBytes.join(' | '));
  check('Ctrl+C 发出的是单个 0x03', sentBytes.indexOf('3') >= 0, sentBytes.join(' | '));
}

// ---------- 布局变化后终端要重新适配 ----------
//
// 症状（作者实测）：点「监控」，右侧面板出现、终端被挤窄，但**文字不换行**
//（列数没跟着更新）；点「文件面板」却会重排。
//
// 根因：终端可用宽度变了，而这些变化**不触发 window 的 resize 事件**。原先的做法
// 是让每个面板自己在显隐后派发 resize —— 全仓 9 处显隐点里只有 3 处派了
//（监控面板、日志检测、基线核查、分屏切换都没派），所以补一处还会漏下一处。
//
// 修法：终端对自己的容器挂 ResizeObserver，宽度一变就重排，与"谁改的布局"无关。
async function casePaneRefit() {
  console.log('--- 布局变化）容器宽度变了要重新适配终端 ---');
  const env = createEnv();
  env.sandbox.fetch = async function (url) {
    const u = String(url);
    let body = {};
    if (u.indexOf('/api/settings') >= 0) body = {};
    else if (u.indexOf('/api/targets') >= 0) body = [{ id: 't1', name: 'A', host: 'h', port: 22, username: 'u' }];
    else if (u.indexOf('/api/recent') >= 0) body = [];
    else if (u.indexOf('/api/history') >= 0) body = [];
    else if (u.indexOf('/api/files/startdir') >= 0) body = { path: '', source: 'none' };
    else if (u.indexOf('/api/sessions') >= 0) body = { session_id: 's1', target_id: 't1', title: 'A', ws_token: 'tok1' };
    return ok(body);
  };
  env.load('app.js');
  await env.sleep(30);
  env.el('sidebar-body').fire('click', { target: { closest: () => ({ dataset: { act: 'connect', id: 't1' } }) } });
  await env.sleep(30);

  check('终端容器挂了 ResizeObserver', env.resizeObservers.length >= 1, env.resizeObservers.length);
  const ro = env.resizeObservers[0];
  if (!ro) return;
  check('观察的是终端自己的容器', ro.targets.length === 1, ro.targets.length);

  const pane = ro.targets[0];
  // 先让会话建立路径上那几处 safeFit（渲染完成、初始目录回填）落定，
  // 否则"这一次变化到底重排了没有"会被它们干扰。
  await env.sleep(250);
  const before = env.fits.length;

  // 被整页视图盖住：宽高为 0，这时 fit 会算出无意义的行列数，必须跳过
  pane.clientWidth = 0; pane.clientHeight = 0;
  ro.trigger();
  await env.sleep(120);
  check('容器不可见时不重排', env.fits.length === before, env.fits.length - before);

  // 右侧面板出现 → 容器变窄 → 必须重排（这就是"点监控不换行"那条）
  pane.clientWidth = 800; pane.clientHeight = 600;
  ro.trigger();
  await env.sleep(120);
  check('容器宽度变化后重新适配终端', env.fits.length > before, env.fits.length - before);

  // 拖动分隔条时回调是高频的：必须去抖，不能每个回调都 fit 一次
  const mid = env.fits.length;
  ro.trigger(); ro.trigger(); ro.trigger();
  await env.sleep(120);
  check('连续多次变化被去抖成一次', env.fits.length === mid + 1, env.fits.length - mid);
}

(async () => {
  try {
    await caseWsGuard();
    await caseComplianceEscape();
    await caseMonitorEscape();
    await caseMonitorSwitchTarget();
    await caseLogscanEscape();
    await caseReqConsistency();
    await caseTermKeyHandler();
    await casePaneRefit();
  } catch (e) {
    console.log('  FAIL harness error: ' + (e && e.stack || e));
    fails++;
  }
  console.log(fails === 0 ? '\n前端回归：全部通过' : '\n前端回归：' + fails + ' 条断言失败');
  process.exit(fails === 0 ? 0 : 1);
})();
