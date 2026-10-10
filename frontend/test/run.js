/* 前端回归测试（node frontend/test/run.js，失败退出码 1）。

   钉的是复审报告里那几条前端问题：
     低2 app.js：WebSocket onmessage 少了 `s.ws !== ws` 守卫 —— 旧 socket 迟到
           一条 exit 会把**新**连接标成已断开，而且此后不再自动重连
     低7 compliance.js：statusLabel(r.status) 未转义
     低8 monitor.js 的 c.id / p.pid、logscan.js 的 h.line_no 未转义
     低9 monitor.js：下拉切目标没有重置 lastOkAt，"距上次 N 秒"会跨主机算
   每条都写成"改回错误版本会红"的形式。 */
'use strict';
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

(async () => {
  try {
    await caseWsGuard();
    await caseComplianceEscape();
    await caseMonitorEscape();
    await caseMonitorSwitchTarget();
    await caseLogscanEscape();
  } catch (e) {
    console.log('  FAIL harness error: ' + (e && e.stack || e));
    fails++;
  }
  console.log(fails === 0 ? '\n前端回归：全部通过' : '\n前端回归：' + fails + ' 条断言失败');
  process.exit(fails === 0 ? 0 : 1);
})();
