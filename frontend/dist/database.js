/* awdshell 数据库管理：通过目标机已有的 SSH 连接访问 MySQL / PostgreSQL。
 *
 * 不直连数据库（它通常只监听 127.0.0.1），也不往目标机装客户端：
 * 隧道与协议都在后端处理，这里只负责把结构、SQL 与结果呈现出来。
 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var MAX_RENDER_ROWS = 500;

  var state = {
    targets: [], targetId: '', followActive: true,
    conns: [], connId: '',
    databases: [], expanded: {}, tables: {}, columns: {},
    result: null, running: false, editing: null, cm: null,
    // 当前正在看的表（图形化那一半用它）
    table: null, tab: 'data',
    // 每次切目标/切连接自增，用来丢弃过期响应：
    // 否则旧连接的在途响应会把新状态写满，左侧树显示 A 的库表、
    // 点一下表名生成的 SQL 却发给 B（同名表时就是改错库）
    //
    // **必须在 state 里给出初值**：漏了的话 `++undefined` 是 NaN，而
    // `NaN !== NaN` 恒为真 —— 每次请求回来都会在"过期了，丢弃"那一步 return，
    // 于是连接列表和库表树永远空（表现成"测试连接正常，但图形化操作什么都读不出来"）。
    // 同类的坑这个项目踩过一次：state 里漏 followActive 时 !undefined 恒为真。
    connSeq: 0, treeSeq: 0
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
    var el = $('db-hint');
    if (!el) return;
    el.textContent = msg || '';
    el.className = isError ? 'db-hint error-text' : 'db-hint';
  }

  async function req(path, init) {
    var opt = Object.assign({ headers: { 'Content-Type': 'application/json' } }, init || {});
    var res = await fetch(API + path, opt);
    if (!res.ok) {
      var msg = res.status + ' ' + res.statusText;
      try { var j = await res.json(); if (j && j.error) msg = j.error; } catch (e) { /* 忽略 */ }
      // 各视图各有一份 req，统一把状态码挂在错误上，调用方才好按语义分支。
      var dErr = new Error(msg);
      dErr.status = res.status;
      throw dErr;
    }
    return res.json();
  }

  function currentConn() {
    for (var i = 0; i < state.conns.length; i++) {
      if (state.conns[i].id === state.connId) return state.conns[i];
    }
    return null;
  }

  // ---------- 骨架 ----------

  function renderShell() {
    $('database-area').innerHTML =
      '<div class="db-wrap">' +
      '  <div class="view-head">' +
      '    <span class="view-title">数据库</span>' +
      '    <span class="db-hint" id="db-hint">通过目标机的 SSH 连接访问，不需要目标机装客户端</span>' +
      '    <button class="view-close">关闭</button>' +
      '  </div>' +
      '  <div class="db-toolbar">' +
      '    <select id="db-target" class="db-target" title="数据库在哪台主机上"></select>' +
      '    <button id="db-follow-state" class="awd-follow" title=""></button>' +
      '    <select id="db-conn" class="db-conn" title="选择一条已保存的连接"></select>' +
      '    <button id="db-new">新建连接</button>' +
      '    <button id="db-newtable">新建表</button>' +
      '    <button id="db-edit">编辑</button>' +
      '    <button id="db-del" class="danger">删除</button>' +
      '  </div>' +
      '  <div class="db-body">' +
      '    <aside class="db-side">' +
      '      <div class="db-side-head">' +
      '        <span>对象</span>' +
      '        <button id="db-reload" title="重新读取库与表">刷新</button>' +
      '      </div>' +
      '      <div class="db-tree" id="db-tree"><div class="db-sub">选一条连接后点「刷新」读取库与表</div></div>' +
      '    </aside>' +
      '    <section class="db-main">' +
      '      <div class="db-tabs">' +
      '        <button class="db-tab active" data-tab="data">数据</button>' +
      '        <button class="db-tab" data-tab="sql">SQL</button>' +
      '        <button class="db-tab" data-tab="struct">结构</button>' +
      '        <span class="db-meta" id="db-meta"></span>' +
      '      </div>' +
      '      <div class="db-pane db-pane-data" id="db-pane-data">' +
      '        <div class="db-sub">在左边点一张表，这里直接显示数据；双击单元格可以改。</div>' +
      '      </div>' +
      '      <div class="db-pane" id="db-pane-sql" hidden>' +
      '        <div class="db-sql-bar">' +
      '          <span class="db-ro" id="db-ro"></span>' +
      '          <button id="db-run" class="primary">执行 (Ctrl+Enter)</button>' +
      '          <button id="db-clear">清空</button>' +
      '          <span class="db-meta" id="db-meta2"></span>' +
      '        </div>' +
      '        <div class="db-editor" id="db-editor"></div>' +
      '        <div class="db-result" id="db-result">' +
      '          <div class="db-sub">在上面写 SQL，然后按 Ctrl+Enter 或点「执行」</div>' +
      '        </div>' +
      '      </div>' +
      '      <div class="db-pane" id="db-pane-struct" hidden>' +
      '        <div class="db-sub">在左边点一张表，这里显示它的字段与建表语句。</div>' +
      '      </div>' +
      '    </section>' +
      '  </div>' +
      '  <div class="db-conn-form" id="db-form" hidden></div>' +
      '</div>';

    $('db-target').addEventListener('change', function () {
      state.targetId = this.value;
      state.followActive = false;
      state.connId = '';
      state.connSeq++; state.treeSeq++; // 切连接：列表与树都要作废
      renderFollow();
      loadConns();
    });
    $('db-follow-state').addEventListener('click', function () {
      state.followActive = true;
      state.connSeq++;
      syncToActiveSession();
      renderTargets();  // 显式刷一次按钮状态，否则文案会停在"已锁定"
      loadConns();
    });
    $('db-conn').addEventListener('change', function () {
      state.connId = this.value;
      state.connSeq++; state.treeSeq++; // 切连接：列表与树都要作废
      state.databases = [];
      state.expanded = {};
      state.tables = {};
      renderTree();
      renderRoBadge();
      setStatus('已选择连接');
    });
    $('db-new').addEventListener('click', function () { renderForm(null); });
    $('db-newtable').addEventListener('click', newTableDialog);
    $('db-edit').addEventListener('click', function () { renderForm(currentConn()); });
    $('db-del').addEventListener('click', removeConn);
    $('db-reload').addEventListener('click', loadTree);
    $('db-run').addEventListener('click', runSQL);
    $('db-clear').addEventListener('click', function () {
      if (state.cm) state.cm.setValue('');
    });
    $('db-tree').addEventListener('click', onTreeClick);
    // 右侧三个标签：数据 / SQL / 结构
    document.querySelectorAll('.db-tab').forEach(function (btn) {
      btn.addEventListener('click', function () { setTab(this.getAttribute('data-tab')); });
    });
  }

  // ---------- 图形化：把表交给 database-table.js 渲染 ----------

  // 打开某张表（点树里的表名时调用）
  function openTableData(db, schema, table) {
    state.table = { db: db || '', schema: schema || '', table: table };
    var conn = currentConn() || {};
    $('db-meta').textContent = (db ? db + '.' : '') + table;
    setTab('data');
    if (window.AwdTableData) {
      window.AwdTableData.open({
        connId: state.connId,
        ref: state.table,
        kind: conn.kind || '',
        readOnly: !!conn.read_only,
        host: $('db-pane-data')
      });
    }
  }

  function renderStructure() {
    if (!state.table || !window.AwdTableData) return;
    var conn = currentConn() || {};
    window.AwdTableData.structure({
      connId: state.connId,
      ref: state.table,
      kind: conn.kind || '',
      host: $('db-pane-struct')
    });
  }

  // 建表
  function newTableDialog() {
    if (!state.connId) { hint('先选一条连接', true); return; }
    var conn = currentConn() || {};
    var isPG = conn.kind === 'postgres';
    // MySQL 的"库"就是 information_schema.schemata，可以直接列出来当选项；
    // PostgreSQL 的库（datname）和 schema 是两回事，把库名当 schema 用会直接
    // 报 schema does not exist，所以 PG 这边只给一个默认 public 的输入框。
    var db = state.databases[0] || '';
    if (state.table && state.table.db) db = state.table.db;
    if (window.AwdTableData) {
      window.AwdTableData.createTable({
        connId: state.connId,
        kind: conn.kind || '',
        readOnly: !!conn.read_only,
        database: isPG ? '' : db,
        schema: isPG ? 'public' : '',
        databases: state.databases,
        pgMode: isPG,
        onDone: function () { loadTree(); }
      });
    }
  }

  // 给 database-table.js 用的桥
  window.AwdDbBridge = {
    req: req,
    esc: esc,
    hint: hint,
    setStatus: setStatus,
    currentConn: currentConn,
    table: function () { return state.table; },
    reloadTree: function () { return loadTree(); },
    toast: function () { return window.AwdToast; }
  };

  function setTab(name) {
    state.tab = name;
    document.querySelectorAll('.db-tab').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === name);
    });
    $('db-pane-data').hidden = name !== 'data';
    $('db-pane-sql').hidden = name !== 'sql';
    $('db-pane-struct').hidden = name !== 'struct';
    if (name === 'sql') {
      ensureEditor();
      // 编辑器原来在隐藏容器里建的话尺寸是 0，切回来必须刷新
      if (state.cm) setTimeout(function () { state.cm.refresh(); state.cm.focus(); }, 30);
    }
    if (name === 'struct' && state.table) renderStructure();
  }

  // ---------- 连接管理 ----------

  async function loadTargets() {
    try {
      state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    } catch (e) {
      state.targets = [];
    }
    if (state.targetId && !state.targets.some(function (t) { return t.id === state.targetId; })) {
      state.targetId = '';
    }
    if (!state.targetId && state.targets.length) state.targetId = state.targets[0].id;
    renderTargets();
  }

  function renderTargets() {
    var sel = $('db-target');
    if (!sel) return;
    sel.innerHTML = state.targets.map(function (t) {
      return '<option value="' + esc(t.id) + '"' + (t.id === state.targetId ? ' selected' : '') + '>' +
        esc(t.name) + '</option>';
    }).join('') || '<option value="">无目标</option>';
    renderFollow();
  }

  function renderFollow() {
    if (window.AwdViews) {
      window.AwdViews.followButton('db-follow-state', state.followActive, '数据库目标', function () {
        state.followActive = true;
        syncToActiveSession();
        loadConns();
      });
    }
  }

  // 跟随当前终端会话：数据库默认看用户正在操作的那台主机
  function syncToActiveSession() {
    if (!state.followActive) return false;
    var tid = window.AwdActiveTarget ? window.AwdActiveTarget() : '';
    if (!tid || tid === state.targetId) return false;
    state.targetId = tid;
    state.connId = '';
    renderTargets();
    return true;
  }

  async function loadConns() {
    // 换了连接/目标，左边的树必须一起清掉：
    // 否则树里还是上一个目标的库表，点下去会用新连接的 connId 去查旧库名
    state.databases = [];
    state.expanded = {};
    state.tables = {};
      // 记下这一轮属于哪次请求：切目标时旧响应回来不能往界面上贴。
      var seq = ++state.connSeq;
    try {
      var r = await req('/api/db/conns?target_id=' + encodeURIComponent(state.targetId));
        if (seq !== state.connSeq) return;
      state.conns = r.conns || [];
    } catch (e) {
        if (seq !== state.connSeq) return;
      state.conns = [];
      hint('读取连接列表失败：' + e.message, true);
    }
      if (seq !== state.connSeq) return;
    if (state.connId && !state.conns.some(function (c) { return c.id === state.connId; })) {
      state.connId = '';
    }
    if (!state.connId && state.conns.length) state.connId = state.conns[0].id;
    renderConns();
    renderTree();
    renderRoBadge();
  }

  function renderConns() {
    var sel = $('db-conn');
    if (!sel) return;
    sel.innerHTML = state.conns.map(function (c) {
      return '<option value="' + esc(c.id) + '"' + (c.id === state.connId ? ' selected' : '') + '>' +
        esc(c.name) + '（' + esc(c.kind) + '）</option>';
    }).join('') || '<option value="">还没有连接</option>';
    var has = state.conns.length > 0;
    $('db-edit').disabled = !has;
    $('db-del').disabled = !has;
  }

  function renderRoBadge() {
    var el = $('db-ro');
    if (!el) return;
    var c = currentConn();
    if (!c) { el.textContent = ''; return; }
    el.textContent = c.read_only ? '只读' : '可写';
    el.className = 'db-ro ' + (c.read_only ? 'ro' : 'rw');
    el.title = c.read_only
      ? '只允许查询类语句；要执行写操作请在编辑连接时取消「只读」'
      : '允许写操作，执行前请确认语句影响范围';
  }

  // 新建 / 编辑连接的表单（内联，不用弹窗）
  function renderForm(conn) {
    state.editing = conn;
    var f = $('db-form');
    f.hidden = false;
    var c = conn || { kind: 'postgres', addr: '', username: '', database: '', read_only: false, max_rows: 500 };
    f.innerHTML =
      '<div class="db-form-head">' + (conn ? '编辑连接' : '新建连接') + '</div>' +
      '<div class="db-form-grid">' +
      '  <label>名称<input id="df-name" value="' + esc(c.name || '') + '" placeholder="例如 业务库" /></label>' +
      '  <label>类型<select id="df-kind">' +
      '    <option value="postgres"' + (c.kind === 'postgres' ? ' selected' : '') + '>PostgreSQL</option>' +
      '    <option value="mysql"' + (c.kind === 'mysql' ? ' selected' : '') + '>MySQL</option>' +
      '  </select></label>' +
      '  <label>地址<input id="df-addr" value="' + esc(c.addr || '') + '" placeholder="127.0.0.1:5432（目标机视角）" /></label>' +
      '  <label>用户名<input id="df-user" value="' + esc(c.username || '') + '" /></label>' +
      '  <label>密码<input id="df-pass" type="password" placeholder="' + (conn ? '留空表示不修改' : '') + '" /></label>' +
      '  <label>默认库<input id="df-db" value="' + esc(c.database || '') + '" placeholder="可留空" /></label>' +
      '  <label>结果行数上限<input id="df-maxrows" type="number" min="10" max="5000" value="' + (c.max_rows || 500) + '" /></label>' +
      '  <label class="db-check"><input type="checkbox" id="df-ro"' + (c.read_only ? ' checked' : '') +
      ' /> 只读模式（勾上后只允许查询类语句，适合连生产库时防手滑）</label>' +
      '</div>' +
      '<div class="db-form-actions">' +
      '  <button id="df-test">测试连接</button>' +
      '  <button id="df-save" class="primary">保存</button>' +
      '  <button id="df-cancel">取消</button>' +
      '  <span class="db-hint" id="df-msg"></span>' +
      '</div>';

    function collect() {
      return {
        id: conn ? conn.id : '',
        target_id: state.targetId,
        name: $('df-name').value.trim(),
        kind: $('df-kind').value,
        addr: $('df-addr').value.trim(),
        username: $('df-user').value.trim(),
        password: $('df-pass').value,
        database: $('df-db').value.trim(),
        read_only: $('df-ro').checked,
        max_rows: parseInt($('df-maxrows').value, 10) || 500
      };
    }
    function msg(text, bad) {
      var el = $('df-msg');
      el.textContent = text;
      el.className = bad ? 'db-hint error-text' : 'db-hint';
    }

    $('df-test').addEventListener('click', async function () {
      msg('正在通过 SSH 试连…');
      try {
        var r = await req('/api/db/test', { method: 'POST', body: JSON.stringify(collect()) });
        msg(r.message || (r.error || ''), !r.ok);
      } catch (e) { msg('测试失败：' + e.message, true); }
    });
    $('df-save').addEventListener('click', async function () {
      msg('保存中…');
      try {
        var saved = await req('/api/db/conns', { method: 'POST', body: JSON.stringify(collect()) });
        state.connId = saved.id;
        f.hidden = true;
        await loadConns();
        hint('连接已保存（密码加密落盘）');
      } catch (e) { msg('保存失败：' + e.message, true); }
    });
    $('df-cancel').addEventListener('click', function () { f.hidden = true; });
  }

  async function removeConn() {
    var c = currentConn();
    if (!c) return;
    if (!window.confirm('删除连接「' + c.name + '」及其保存的密码？')) return;
    try {
      await req('/api/db/delete', { method: 'POST', body: JSON.stringify({ id: c.id }) });
      state.connId = '';
      await loadConns();
      hint('已删除连接 ' + c.name);
    } catch (e) { hint('删除失败：' + e.message, true); }
  }

  // ---------- 对象树 ----------

  async function loadTree() {
    if (!state.connId) { hint('先选一条连接', true); return; }
    var seq = ++state.treeSeq;
    hint('正在读取库列表…');
    try {
      var r = await req('/api/db/databases?conn_id=' + encodeURIComponent(state.connId));
      if (seq !== state.treeSeq) return; // 期间切过连接/目标，丢弃
      state.databases = r.databases || [];
      state.expanded = {};
      state.tables = {};
      renderTree();
      hint('共 ' + state.databases.length + ' 个库');
    } catch (e) {
      if (seq !== state.treeSeq) return;
      hint('读取库列表失败：' + e.message, true);
    }
  }

  function renderTree() {
    var box = $('db-tree');
    if (!box) return;
    if (!state.connId) {
      box.innerHTML = '<div class="db-sub">选一条连接后点「刷新」读取库与表</div>';
      return;
    }
    if (!state.databases.length) {
      box.innerHTML = '<div class="db-sub">点右上「刷新」读取库与表</div>';
      return;
    }
    box.innerHTML = state.databases.map(function (db) {
      var open = !!state.expanded[db];
      var tables = state.tables[db] || null;
      var inner = '';
      if (open) {
        if (!tables) inner = '<div class="db-sub">读取中…</div>';
        else if (!tables.length) inner = '<div class="db-sub">这个库里没有表</div>';
        else inner = tables.map(function (t) {
          return '<div class="db-item db-table" data-db="' + esc(db) + '" data-schema="' + esc(t.schema || '') +
            '" data-table="' + esc(t.name) + '" title="点一下看这张表的数据">' +
            '<span class="db-kind">' + (t.kind === 'VIEW' ? 'V' : 'T') + '</span>' +
            esc(t.name) + '</div>';
        }).join('');
      }
      return '<div class="db-node">' +
        '<div class="db-item db-db" data-db="' + esc(db) + '">' +
        '<span class="db-arrow">' + (open ? '▾' : '▸') + '</span>' + esc(db) + '</div>' +
        (open ? '<div class="db-children">' + inner + '</div>' : '') +
        '</div>';
    }).join('');
  }

  // 包一层：点表失败必须说出来。静默什么都不发生是最难查的一类问题。
  async function onTreeClick(e) {
    try {
      await handleTreeClick(e);
    } catch (err) {
      var msg = err && err.message ? err.message : String(err);
      if (window.AwdToast) window.AwdToast.error('打开这张表失败\n\n' + msg);
      else hint('打开这张表失败：' + msg, true);
    }
  }

  async function handleTreeClick(e) {
    var dbNode = e.target.closest ? e.target.closest('.db-db') : null;
    if (dbNode) {
      var db = dbNode.getAttribute('data-db');
      if (state.expanded[db]) {
        state.expanded[db] = false;
        renderTree();
        return;
      }
      state.expanded[db] = true;
      renderTree();
      if (!state.tables[db]) {
        var seq = state.treeSeq;
        try {
          var r = await req('/api/db/tables?conn_id=' + encodeURIComponent(state.connId) + '&db=' + encodeURIComponent(db));
          // 期间切过连接就丢弃：否则会把旧连接的表塞进新连接的树里
        if (seq !== state.treeSeq) return;
          state.tables[db] = r.tables || [];
        } catch (err) {
        if (seq !== state.treeSeq) return;
          state.tables[db] = [];
          hint('读取表列表失败：' + err.message, true);
        }
        renderTree();
      }
      return;
    }
    var tblNode = e.target.closest ? e.target.closest('.db-table') : null;
    if (tblNode) {
      var name = tblNode.getAttribute('data-table');
      var schema = tblNode.getAttribute('data-schema');
      var c = currentConn();
      // 点表名所属的库要现取：直接点表（没先点库）时上面那个 db 变量是空的
      var tblDb = tblNode.getAttribute('data-db') || '';

      // 主要动作：把这张表拉到"数据"页显示
      openTableData(tblDb, schema, name);

      // 顺手把查询写进编辑器（编辑器还没建就跳过，不能因此挡住图形化那半边）
      if (state.cm) {
        // 必须带上库名：MySQL 连接如果没配默认库，只写表名会直接报
        // Error 1046 (3D000): No database selected
        // 引号按数据库类型选：MySQL 默认 sql_mode 下双引号是字符串字面量，
        // FROM "t" 不是合法表引用；标识符里的引号字符要翻倍转义。
        var q = c && c.kind === 'mysql' ? '`' : '"';
        var escapeIdent = function (s) { return String(s).split(q).join(q + q); };
        var parts = [];
        if (c && c.kind === 'mysql') {
          if (tblDb) parts.push(q + escapeIdent(tblDb) + q);
        } else if (schema && schema !== 'public') {
          parts.push(q + escapeIdent(schema) + q);
        }
        parts.push(q + escapeIdent(name) + q);
        state.cm.setValue('SELECT * FROM ' + parts.join('.') + ' LIMIT 100;');
      }
    }
  }

  // ---------- SQL 执行 ----------

  // SQL 语法模式要单独加载。不加载的话 text/x-sql 没注册，
  // CodeMirror 会静默退回纯文本 —— 看着只是"没有高亮"，一个错都不报，
  // 所以这里加载完再回头把模式套上。
  var sqlModeState = 0;
  function ensureSqlMode() {
    if (!window.CodeMirror || window.CodeMirror.modes.sql) return;
    if (sqlModeState) return;
    sqlModeState = 1;
    var s = document.createElement('script');
    s.src = '/vendor/codemirror/mode/sql.js';
    s.onload = function () {
      // 编辑器可能已经建好了，补一次模式
      if (state.cm && window.CodeMirror.modes.sql) state.cm.setOption('mode', 'text/x-sql');
    };
    s.onerror = function () { /* 加载不到就纯文本，不影响写 SQL */ };
    document.head.appendChild(s);
  }

  function ensureEditor() {
    if (state.cm || !window.CodeMirror) return state.cm;
    ensureSqlMode();
    state.cm = CodeMirror($('db-editor'), {
      value: '',
      mode: 'text/x-sql',
      lineNumbers: true,
      lineWrapping: true,
      matchBrackets: true,
      autofocus: false,
      extraKeys: {
        'Ctrl-Enter': runSQL,
        'Cmd-Enter': runSQL
      }
    });
    return state.cm;
  }

  // 明显会大范围改数据的语句，执行前确认一次。
  //
  // 这比"只读模式"实用：日常要能直接改，但别让手滑的 DROP 或没有 WHERE 的
  // DELETE 悄悄跑掉（数据库里这种事没有回收站）。
  function dangerNote(sqlText) {
    var s = String(sqlText)
      .replace(/--[^\n]*/g, ' ')
      .replace(/\/\*[\s\S]*?\*\//g, ' ');
    var low = s.toLowerCase();
    if (/\b(drop|truncate)\b/.test(low)) return '这条语句会删除整个对象（DROP / TRUNCATE）';
    if (/\bdelete\b/.test(low) && !/\bwhere\b/.test(low)) return 'DELETE 没有 WHERE，会清空整张表';
    if (/\bupdate\b/.test(low) && !/\bwhere\b/.test(low)) return 'UPDATE 没有 WHERE，会改到全表';
    if (/\balter\s+table\b/.test(low)) return '这条语句会改表结构（ALTER TABLE）';
    return '';
  }

  async function runSQL() {
    if (state.running) return;
    if (!state.connId) { hint('先选一条连接', true); return; }
    var sqlText = state.cm ? state.cm.getValue().trim() : '';
    if (!sqlText) { hint('先写一条 SQL', true); return; }

    var danger = dangerNote(sqlText);
    if (danger && !window.confirm(danger + '。\n\n确定执行吗？')) return;

    state.running = true;
    hint('执行中…');
    setStatus('数据库查询执行中…');
    try {
      var res = await req('/api/db/query', {
        method: 'POST',
        body: JSON.stringify({ conn_id: state.connId, sql: sqlText })
      });
      state.result = res;
      renderResult(res);
      hint('完成：耗时 ' + res.elapsed_ms + ' ms' + (res.read_only ? '' : '，影响 ' + res.affected + ' 行'),
        false);
      setStatus('数据库查询完成（' + res.elapsed_ms + ' ms）');
    } catch (e) {
      hint('执行失败：' + e.message, true);
      setStatus('数据库查询失败');
    } finally {
      state.running = false;
    }
  }

  function renderResult(res) {
    var box = $('db-result');
    // 字段落空时不能直接 .length/.slice：用户看到的是
    // "Cannot read properties of undefined (reading 'length')"
    if (!res || typeof res !== 'object') {
      box.innerHTML = '<div class="db-sub error-text">数据格式不符合预期，请重试或改用 SQL 编辑器查看</div>';
      return;
    }
    var cols = res.columns || [];
    var dataRows = res.rows || [];
    if (!res.read_only) {
      box.innerHTML = '<div class="db-ok">语句已执行，影响 ' + (Number(res.affected) || 0) +
        ' 行（耗时 ' + (Number(res.elapsed_ms) || 0) + ' ms）</div>';
      return;
    }
    if (!cols.length) {
      box.innerHTML = '<div class="db-sub">这条语句没有返回结果集</div>';
      return;
    }
    if (!dataRows.length) {
      box.innerHTML = '<div class="db-sub">没有匹配的数据</div>';
      return;
    }

    var rows = dataRows.slice(0, MAX_RENDER_ROWS);
    var head = cols.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('');
    var body = rows.map(function (r) {
      return '<tr>' + (r || []).map(function (v) {
        var cls = v === 'NULL' ? ' class="db-null"' : '';
        return '<td' + cls + '>' + esc(v) + '</td>';
      }).join('') + '</tr>';
    }).join('');

    box.innerHTML =
      '<div class="db-result-meta">' + (Number(res.row_count) || 0) + ' 行' +
      (res.truncated ? '（已达上限，只显示前 ' + rows.length + ' 行）' : '') +
      '　' + (Number(res.elapsed_ms) || 0) + ' ms</div>' +
      '<div class="db-table-wrap"><table class="db-table-grid"><thead><tr>' + head + '</tr></thead>' +
      '<tbody>' + body + '</tbody></table></div>';
  }

  // ---------- 显隐 ----------

  function toggleDatabase() {
    var on = window.AwdViews.toggle('database-area');
    if (on) {
      ensureEditor();
      state.followActive = true;
      loadTargets().then(function () {
        syncToActiveSession();
        loadConns();
      });
    }
  }

  // ---------- 初始化 ----------

  function boot() {
    renderShell();
    $('btn-database').addEventListener('click', toggleDatabase);
    // 切换终端会话时跟着换主机（用户手动选过就锁定）
    window.addEventListener('awdshell:connected', function () {
      if (syncToActiveSession()) loadConns();
    });
    window.addEventListener('awdshell:targets-changed', function () {
      loadTargets().then(function () { loadConns(); });
    });
    loadTargets().catch(function () { /* 首次打开时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
