/* awdshell 数据库的图形化操作：表数据浏览、单元格编辑、增删行、结构查看、建表。
 *
 * 这一半是为了"不写 SQL 也能干活"：点一张表直接看数据、双击改值、加一行删一行，
 * 建表也有表单。SQL 编辑器那一半在 database.js 里，两边共用连接与库表树。
 *
 * 安全前提：所有写操作都要求表有主键（没有主键就没法安全定位单行，一律只读），
 * 标识符走后端引用与白名单，值走占位符。
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var bridge = function () { return window.AwdDbBridge; };
  var esc = function (v) { return bridge().esc(v); };
  var req = function (p, i) { return bridge().req(p, i); };

  // 提示统一从这里走。原来直接 bridge().toast().ok(...)：toast.js 没加载
  //（或加载失败）时 toast() 返回 undefined，取 .ok 就抛 TypeError，
  // 用户看到的是"保存失败"的假象 —— 其实数据已经写进去了。
  // 拿不到提示就不提示，绝不能因此打断操作流程。
  function toast(kind, msg) {
    var t = window.AwdToast || (bridge() && bridge().toast ? bridge().toast() : null);
    if (t && typeof t[kind] === 'function') t[kind](msg);
  }

  var PAGE_SIZES = [50, 100, 200, 500];

  var st = {
    connId: '', ref: null, kind: '', readOnly: false,
    page: 1, size: 100, order: '', dir: 'asc', filter: '',
    columns: [], primaryKey: [], rows: [], total: 0,
    editable: false, note: '', loading: false,
    // 新行草稿（表头下那一行）
    draft: null,
    host: null,
    // 请求序号。没有它的话：点大表 t1 后不等返回就点小表 t2，
    // t1 的响应后到会把表格数据换成 t1 的，而写操作的目标仍是 t2 ——
    // 双击改值就成了 "UPDATE t2 ... WHERE id=<t1 的 id>"，直接改错表。
    seq: 0
  };

  // 二进制列不能在表格里编辑：界面上显示的是"<N 字节二进制>"这种占位文本，
  // 一旦回写就等于把真正的二进制内容换成这串字，不可逆。
  function isBinaryCol(col) {
    var t = String((col && col.type) || '').toLowerCase();
    return /blob|binary|bytea|image|raw\b|bit\b/.test(t);
  }

  // 发给后端的表定位。
  // 注意字段名：后端 dbx.TableRef 的 JSON tag 是 database / schema / table，
  // 而本文件内部习惯用 db。读接口走 query 参数（db=）没问题，
  // 写接口走 JSON body，键名必须对得上，否则库名丢掉 —— MySQL 下就会报
  // Error 1046 (3D000): No database selected。
  function refJSON() {
    return {
      database: (st.ref && st.ref.db) || '',
      schema: (st.ref && st.ref.schema) || '',
      table: (st.ref && st.ref.table) || ''
    };
  }

  // 分页的两个数：st.total / st.size 任一落空（或 size 为 0）都会算出 NaN，
  // 界面变成"第 1 / NaN 页"，页码算错还会让「末页」把请求打到不存在的页上
  function pageSize() { return Number(st.size) || 100; }
  function pageCount() { return Math.max(1, Math.ceil((Number(st.total) || 0) / pageSize())); }

  // ---------- 数据 ----------

  async function load() {
    if (!st.connId || !st.ref) return;
    var seq = ++st.seq;
    st.loading = true;
    var qs = [
      'conn_id=' + encodeURIComponent(st.connId),
      'db=' + encodeURIComponent(st.ref.db || ''),
      'schema=' + encodeURIComponent(st.ref.schema || ''),
      'table=' + encodeURIComponent(st.ref.table),
      'page=' + st.page,
      'size=' + pageSize()
    ];
    if (st.order) {
      qs.push('order=' + encodeURIComponent(st.order));
      qs.push('dir=' + encodeURIComponent(st.dir));
    }
    if (st.filter) qs.push('filter=' + encodeURIComponent(st.filter));

    try {
      var r = await req('/api/db/rows?' + qs.join('&'));
      if (seq !== st.seq) return; // 期间切过表/连接，这份数据已经过期，丢弃
      st.columns = r.columns || [];
      st.rows = r.rows || [];
      st.total = Number(r.total) || 0;
      st.primaryKey = r.primary_key || [];
      st.editable = !!r.editable;
      st.note = r.note || '';
      st.draft = null;
      render();
      bridge().setStatus('读取 ' + st.ref.table + '：' + st.total + ' 行');
    } catch (e) {
      if (seq !== st.seq) return;
      st.rows = [];
      st.columns = [];
      st.note = '';
      render(e.message);
    } finally {
      if (seq === st.seq) st.loading = false;
    }
  }

  function pkOf(row) {
    if (!row || !st.primaryKey.length) return null;
    var key = {};
    for (var i = 0; i < st.primaryKey.length; i++) {
      var name = st.primaryKey[i];
      var idx = idxOf(name);
      if (idx < 0) return null;
      key[name] = cellToValue(row[idx], name);
    }
    // 空对象也要当"没有主键"，否则调用方的 if (!key) 挡不住
    return Object.keys(key).length ? key : null;
  }

  function idxOf(name) {
    for (var i = 0; i < st.columns.length; i++) {
      if (st.columns[i].name === name) return i;
    }
    return -1;
  }

  // 单元格显示的是字符串化后的值，写回时把明显的 NULL 还原成空
  function cellToValue(text, colName) {
    if (text === 'NULL') return null;
    return text;
  }

  // ---------- 渲染 ----------

  function render(errorMsg) {
    var host = st.host;
    if (!host) return;

    // 出错时也要把工具栏和错误位渲染出来：否则用户只看到"没有数据"，
    // 既看不到数据库报了什么，连筛选框都被抹掉了（没法改回去）
    if (errorMsg) {
      host.innerHTML =
        '<div class="db-grid-bar">' +
        '<span class="db-grid-title">' + esc(st.ref ? st.ref.table : '') + '</span>' +
        '<button id="db-grid-refresh">刷新</button>' +
        '<input id="db-grid-filter" class="db-grid-filter" placeholder="筛选条件" value="' +
        esc(st.filter) + '" />' +
        '<button id="db-grid-apply">应用筛选</button>' +
        '</div>' +
        '<div class="db-grid-error"><span class="error-text">' + esc(errorMsg) + '</span></div>';
      var rb = document.getElementById('db-grid-refresh');
      if (rb) rb.addEventListener('click', function () { load(); });
      var ab = document.getElementById('db-grid-apply');
      if (ab) {
        ab.addEventListener('click', function () {
          var f = document.getElementById('db-grid-filter');
          st.filter = f ? f.value.trim() : '';
          st.page = 1;
          load();
        });
      }
      return;
    }

    if (!st.rows.length && !st.columns.length) {
      host.innerHTML = '<div class="db-sub">这张表没有数据，或者没有权限读取。</div>';
      return;
    }

    var totalPages = pageCount();
    var head = ['<th class="db-act-col"></th>'];
    for (var c = 0; c < st.columns.length; c++) {
      var col = st.columns[c];
      var arrow = '';
      if (st.order === col.name) arrow = st.dir === 'desc' ? ' ▼' : ' ▲';
      var pk = col.primary_key ? '<span class="db-pk" title="主键">PK</span>' : '';
      head.push(
        '<th class="db-sortable" data-col="' + esc(col.name) + '" title="' +
        esc(col.name + ' ' + col.type) + '">' + pk + esc(col.name) + arrow + '</th>'
      );
    }
    if (st.editable) head.push('<th class="db-act-col">操作</th>');

    var body = '';

    // 新增行草稿
    if (st.draft) {
      body += '<tr class="db-draft">';
      body += '<td class="db-act-col">新</td>';
      for (var d = 0; d < st.columns.length; d++) {
        var dc = st.columns[d];
        var dis = dc.auto_increment ? ' disabled placeholder="自增"' : '';
        var ph = dc.nullable ? '可空' : '必填';
        body += '<td><input class="db-cell-input" data-draft="' + esc(dc.name) + '"' +
          dis + ' placeholder="' + ph + '" /></td>';
      }
      if (st.editable) {
        body += '<td class="db-act-col">' +
          '<button class="db-mini primary" id="db-draft-save">保存</button>' +
          '<button class="db-mini" id="db-draft-cancel">取消</button></td>';
      }
      body += '</tr>';
    }

    for (var r = 0; r < st.rows.length; r++) {
      var row = st.rows[r];
      body += '<tr data-row="' + r + '">';
      body += '<td class="db-act-col db-rownum">' + ((st.page - 1) * pageSize() + r + 1) + '</td>';
      for (var i = 0; i < st.columns.length; i++) {
        var v = row[i];
        var cls = v === 'NULL' ? 'db-null' : '';
        var binary = isBinaryCol(st.columns[i]);
        // 二进制列不给编辑入口：回写会把"<N 字节二进制>"这串字写进去，毁掉原内容
        if (st.editable && !binary) cls += ' db-cell-editable';
        var tip = binary ? '二进制列不支持在这里编辑，请用 SQL 编辑器' : '双击可以改';
        body += '<td class="' + cls.trim() + '" data-row="' + r + '" data-col="' + i + '"' +
          ' title="' + esc(tip) + '">' + esc(v) + '</td>';
      }
      if (st.editable) {
        body += '<td class="db-act-col"><button class="db-mini danger" data-del="' + r + '">删</button></td>';
      }
      body += '</tr>';
    }

    host.innerHTML =
      toolbarHtml(totalPages) +
      (st.note ? '<div class="db-note">' + esc(st.note) + '</div>' : '') +
      '<div class="db-table-wrap db-grid-wrap"><table class="db-table-grid db-grid">' +
      '<thead><tr>' + head.join('') + '</tr></thead><tbody>' + body + '</tbody></table></div>' +
      pagerHtml(totalPages) +
      '<div class="db-grid-error" id="db-grid-error"></div>';

    bind();
  }

  function toolbarHtml(totalPages) {
    var sizes = PAGE_SIZES.map(function (n) {
      return '<option value="' + n + '"' + (n === st.size ? ' selected' : '') + '>' + n + ' 行/页</option>';
    }).join('');
    return '<div class="db-grid-bar">' +
      '<span class="db-grid-title">' + esc(st.ref.table) + '</span>' +
      '<button id="db-grid-refresh" title="重新读取">刷新</button>' +
      '<select id="db-grid-size">' + sizes + '</select>' +
      '<input id="db-grid-filter" class="db-grid-filter" placeholder="筛选，例如 id > 10 AND name LIKE \'%a%\'"' +
      ' value="' + esc(st.filter) + '" />' +
      '<button id="db-grid-apply">应用筛选</button>' +
      (st.editable && !st.readOnly ? '<button id="db-grid-add" class="primary">新增行</button>' : '') +
      '<button id="db-grid-export">导出 CSV</button>' +
      '</div>';
  }

  function pagerHtml(totalPages) {
    return '<div class="db-grid-pager">' +
      '<button id="db-pg-first"' + (st.page <= 1 ? ' disabled' : '') + '>首页</button>' +
      '<button id="db-pg-prev"' + (st.page <= 1 ? ' disabled' : '') + '>上一页</button>' +
      '<span class="db-pg-info">第 ' + st.page + ' / ' + totalPages + ' 页　共 ' + st.total + ' 行</span>' +
      '<button id="db-pg-next"' + (st.page >= totalPages ? ' disabled' : '') + '>下一页</button>' +
      '<button id="db-pg-last"' + (st.page >= totalPages ? ' disabled' : '') + '>末页</button>' +
      '</div>';
  }

  function renderError(msg) {
    var el = $('db-grid-error');
    if (el) el.innerHTML = '<span class="error-text">' + esc(msg) + '</span>';
  }

  function bind() {
    var on = function (id, ev, fn) {
      var el = $(id);
      if (el) el.addEventListener(ev, fn);
    };
    on('db-grid-refresh', 'click', function () { load(); });
    on('db-grid-size', 'change', function () {
      st.size = parseInt(this.value, 10) || 100;
      st.page = 1;
      load();
    });
    on('db-grid-apply', 'click', function () {
      var f = $('db-grid-filter');
      st.filter = f ? f.value.trim() : '';
      st.page = 1;
      load();
    });
    var filterEl = $('db-grid-filter');
    if (filterEl) {
      filterEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { st.filter = this.value.trim(); st.page = 1; load(); }
      });
    }
    on('db-grid-add', 'click', function () { st.draft = {}; render(); });
    on('db-draft-cancel', 'click', function () { st.draft = null; render(); });
    on('db-draft-save', 'click', saveDraft);
    on('db-grid-export', 'click', exportCSV);

    on('db-pg-first', 'click', function () { st.page = 1; load(); });
    on('db-pg-prev', 'click', function () { if (st.page > 1) { st.page--; load(); } });
    on('db-pg-next', 'click', function () { st.page++; load(); });
    on('db-pg-last', 'click', function () {
      st.page = pageCount();
      load();
    });

    // 列头排序
    var ths = st.host.querySelectorAll('th.db-sortable');
    Array.prototype.forEach.call(ths, function (th) {
      th.addEventListener('click', function () {
        var col = this.getAttribute('data-col');
        if (st.order === col) {
          st.dir = st.dir === 'asc' ? 'desc' : 'asc';
        } else {
          st.order = col;
          st.dir = 'asc';
        }
        load();
      });
    });

    // 双击单元格编辑
    var tds = st.host.querySelectorAll('td.db-cell-editable');
    Array.prototype.forEach.call(tds, function (td) {
      td.addEventListener('dblclick', function () { startEdit(this); });
    });

    // 删行
    var dels = st.host.querySelectorAll('button[data-del]');
    Array.prototype.forEach.call(dels, function (b) {
      b.addEventListener('click', function () {
        deleteRow(parseInt(this.getAttribute('data-del'), 10));
      });
    });
  }

  // ---------- 单元格编辑 ----------

  function startEdit(td) {
    if (st.readOnly) {
      toast('warn', '这条连接是只读模式，改不了数据');
      return;
    }
    if (td.querySelector('input')) return;
    var rowIdx = parseInt(td.getAttribute('data-row'), 10);
    var colIdx = parseInt(td.getAttribute('data-col'), 10);
    var old = st.rows[rowIdx][colIdx];
    var col = st.columns[colIdx];

    var input = document.createElement('input');
    input.className = 'db-cell-input';
    input.value = old === 'NULL' ? '' : old;
    td.textContent = '';
    td.appendChild(input);
    input.focus();
    input.select();

    var finished = false;
    var commit = function (save) {
      if (finished) return;
      finished = true;
      var next = input.value;
      td.textContent = save ? (next === '' && col.nullable ? 'NULL' : next) : old;
      if (save && next !== (old === 'NULL' ? '' : old)) {
        saveCell(rowIdx, colIdx, next);
      }
    };
    input.addEventListener('blur', function () { commit(true); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); commit(true); }
      if (e.key === 'Escape') { e.preventDefault(); commit(false); }
    });
  }

  async function saveCell(rowIdx, colIdx, text) {
    var key = pkOf(st.rows[rowIdx]);
    if (!key) { toast('error', '缺少主键值，无法定位这一行'); return; }
    var col = st.columns[colIdx];
    var values = {};
    // 空输入 + 可空 → 置 NULL；否则按字符串写（数据库会自行转换）
    values[col.name] = (text === '' && col.nullable) ? null : text;

    try {
      var r = await req('/api/db/update', {
        method: 'POST',
        body: JSON.stringify({ conn_id: st.connId, ref: refJSON(), key: key, values: values })
      });
      if (r.affected === 0) {
        // MySQL 的 RowsAffected 是"实际改变"的行数，大小写不敏感时改 'abc'->'ABC'
        // 会被算成 0 行，所以不能说成"没匹配到"
        toast('warn', '数据库报告没有行发生变化（值可能与原来等价，或该行刚被别处改过）');
      } else {
        toast('ok', '已保存 ' + col.name);
      }
      load();
    } catch (e) {
      toast('error', '保存失败\n\n' + e.message);
      load();
    }
  }

  async function deleteRow(rowIdx) {
    var key = pkOf(st.rows[rowIdx]);
    if (!key) { toast('error', '缺少主键值，无法定位这一行'); return; }
    var desc = Object.keys(key).map(function (k) { return k + '=' + key[k]; }).join(', ');
    if (!window.confirm('删除这一行？\n\n' + desc)) return;
    try {
      var r = await req('/api/db/delete-rows', {
        method: 'POST',
        body: JSON.stringify({ conn_id: st.connId, ref: refJSON(), keys: [key] })
      });
      toast('ok', '已删除 ' + r.affected + ' 行');
      load();
    } catch (e) {
      toast('error', '删除失败\n\n' + e.message);
    }
  }

  async function saveDraft() {
    var inputs = st.host.querySelectorAll('[data-draft]');
    var values = {};
    var filled = 0;
    Array.prototype.forEach.call(inputs, function (inp) {
      var name = inp.getAttribute('data-draft');
      if (inp.disabled) return;
      var v = inp.value;
      if (v !== '') { values[name] = v; filled++; }
    });
    if (!filled) { toast('warn', '还没有填任何值'); return; }
    try {
      await req('/api/db/insert', {
        method: 'POST',
        body: JSON.stringify({ conn_id: st.connId, ref: refJSON(), values: values })
      });
      toast('ok', '已新增 1 行');
      st.draft = null;
      load();
    } catch (e) {
      toast('error', '新增失败\n\n' + e.message);
    }
  }

  async function exportCSV() {
    var head = st.columns.map(function (c) { return csvCell(c.name); }).join(',');
    var lines = [head];
    for (var r = 0; r < st.rows.length; r++) {
      lines.push(st.rows[r].map(function (v) { return csvCell(v); }).join(','));
    }
    var fname = st.ref.table + '-第' + st.page + '页.csv';
    try {
      // 带 BOM，Excel 打开中文才不乱码。
      // 统一走保存出口：配了默认下载目录就落到那里，否则退回浏览器下载。
      if (!window.AwdSaveFile) throw new Error('保存入口没加载，刷新一下页面');
      var saved = await window.AwdSaveFile(fname, '\ufeff' + lines.join('\r\n'), 'text/csv;charset=utf-8');
      toast('ok', saved ? ('已保存到 ' + saved) : ('已导出当前页 ' + st.rows.length + ' 行'));
    } catch (e) {
      toast('error', '保存失败\n\n' + e.message);
    }
  }

  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  // ---------- 结构 ----------

  async function structure(opts) {
    var host = opts.host;
    var seq = ++st.seq;
    host.innerHTML = '<div class="db-sub">读取结构…</div>';
    try {
      var qs = 'conn_id=' + encodeURIComponent(opts.connId) +
        '&db=' + encodeURIComponent(opts.ref.db || '') +
        '&schema=' + encodeURIComponent(opts.ref.schema || '') +
        '&table=' + encodeURIComponent(opts.ref.table);
      var cols = await req('/api/db/columns?' + qs);
      var ddl = { ddl: '' };
      try { ddl = await req('/api/db/ddl?' + qs); } catch (e) { /* 拿不到就不显示 */ }
      if (seq !== st.seq) return; // 期间切过表，丢弃

      var rows = (cols.columns || []).map(function (c) {
        return '<tr>' +
          '<td>' + esc(c.name) + '</td>' +
          '<td>' + esc(c.type) + '</td>' +
          '<td>' + (c.nullable ? '是' : '否') + '</td>' +
          '<td>' + (c.primary_key ? 'PK' : '') + '</td>' +
          '<td>' + esc(c.default) + '</td>' +
          '<td>' + esc(c.comment) + '</td>' +
          '</tr>';
      }).join('');

      host.innerHTML =
        '<div class="db-struct-head">' + esc(opts.ref.table) + ' 的字段</div>' +
        '<div class="db-table-wrap"><table class="db-table-grid">' +
        '<thead><tr><th>字段</th><th>类型</th><th>可空</th><th>键</th><th>默认值</th><th>备注</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>' +
        (ddl.ddl ? '<div class="db-struct-head">建表语句</div><pre class="db-ddl">' + esc(ddl.ddl) + '</pre>' : '');
    } catch (e) {
      if (seq !== st.seq) return;
      host.innerHTML = '<div class="db-sub error-text">读取结构失败：' + esc(e.message) + '</div>';
    }
  }

  // ---------- 建表 ----------

  function createTable(opts) {
    var overlay = document.createElement('div');
    overlay.className = 'db-modal-overlay';
    var cols = [
      { name: 'id', type: opts.kind === 'mysql' ? 'int' : 'integer', pk: true, ai: true, nn: true },
      { name: 'name', type: opts.kind === 'mysql' ? 'varchar(128)' : 'text', pk: false, ai: false, nn: false }
    ];
    var dbLabel = opts.kind === 'mysql' ? '所属库' : 'Schema';
    // 记住用户填过的表名与库/schema：paint() 会整块重建弹窗，
    // 不记住的话点「加一个字段」就把表名和选择清空了
    var form = {
      table: '',
      db: opts.pgMode ? (opts.schema || 'public') : (opts.database || '')
    };

    function colRow(c, i) {
      return '<tr data-idx="' + i + '">' +
        '<td><input class="ct-name" value="' + esc(c.name) + '" /></td>' +
        '<td><input class="ct-type" value="' + esc(c.type) + '" /></td>' +
        '<td><input type="checkbox" class="ct-nn"' + (c.nn ? ' checked' : '') + ' title="非空" /></td>' +
        '<td><input type="checkbox" class="ct-pk"' + (c.pk ? ' checked' : '') + ' title="主键" /></td>' +
        '<td><input type="checkbox" class="ct-ai"' + (c.ai ? ' checked' : '') + ' title="自增" /></td>' +
        '<td><input class="ct-def" value="' + esc(c.def || '') + '" placeholder="默认值" /></td>' +
        '<td><button class="db-mini danger ct-del">删</button></td>' +
        '</tr>';
    }

    function paint() {
      var body = cols.map(colRow).join('');
      // PostgreSQL 的 schema 不是库名，不能拿库列表当选项（会建到不存在的 schema 上），
      // 给一个默认 public 的输入框就够用
      var dbField = opts.pgMode
        ? '<label>' + dbLabel + '<input id="ct-db" value="' + esc(form.db) + '" placeholder="public" /></label>'
        : '<label>' + dbLabel + '<select id="ct-db">' +
          (opts.databases || []).map(function (d) {
            return '<option value="' + esc(d) + '"' + (d === form.db ? ' selected' : '') + '>' +
              esc(d) + '</option>';
          }).join('') + '</select></label>';
      var readOnlyNote = opts.readOnly
        ? '<span class="db-hint error-text">这条连接是只读模式，不能建表</span>' : '';
      overlay.innerHTML =
        '<div class="db-modal">' +
        '<div class="db-modal-head">新建表</div>' +
        '<div class="db-form-grid">' +
        '  ' + dbField +
        '  <label>表名<input id="ct-table" value="' + esc(form.table) + '" placeholder="例如 users" /></label>' +
        '</div>' +
        '<div class="db-struct-head">字段 ' +
        '<button class="db-mini" id="ct-add">加一个字段</button></div>' +
        '<div class="db-table-wrap"><table class="db-table-grid db-grid">' +
        '<thead><tr><th>名称</th><th>类型</th><th>非空</th><th>主键</th><th>自增</th><th>默认值</th><th></th></tr></thead>' +
        '<tbody id="ct-body">' + body + '</tbody></table></div>' +
        '<div class="db-form-actions">' +
        '  <button id="ct-ok" class="primary"' + (opts.readOnly ? ' disabled' : '') + '>建表</button>' +
        '  <button id="ct-cancel">取消</button>' +
        '  ' + readOnlyNote +
        '  <span class="db-hint" id="ct-msg"></span>' +
        '</div>' +
        '</div>';

      $('ct-add').addEventListener('click', function () {
        syncFromDom();
        cols.push({ name: '', type: opts.kind === 'mysql' ? 'varchar(128)' : 'text' });
        paint();
      });
      $('ct-cancel').addEventListener('click', function () { overlay.remove(); });
      $('ct-ok').addEventListener('click', submit);
      Array.prototype.forEach.call(overlay.querySelectorAll('.ct-del'), function (b) {
        b.addEventListener('click', function () {
          var tr = this.closest('tr');
          var idx = parseInt(tr.getAttribute('data-idx'), 10);
          syncFromDom();
          cols.splice(idx, 1);
          paint();
        });
      });
    }

    function syncFromDom() {
      // 表名与库/schema 也要保住
      var tEl = $('ct-table');
      if (tEl) form.table = tEl.value;
      var dEl = $('ct-db');
      if (dEl) form.db = dEl.value;
      var trs = overlay.querySelectorAll('#ct-body tr');
      Array.prototype.forEach.call(trs, function (tr) {
        var idx = parseInt(tr.getAttribute('data-idx'), 10);
        if (!cols[idx]) return;
        cols[idx].name = tr.querySelector('.ct-name').value.trim();
        cols[idx].type = tr.querySelector('.ct-type').value.trim();
        cols[idx].nn = tr.querySelector('.ct-nn').checked;
        cols[idx].pk = tr.querySelector('.ct-pk').checked;
        cols[idx].ai = tr.querySelector('.ct-ai').checked;
        cols[idx].def = tr.querySelector('.ct-def').value.trim();
      });
    }

    async function submit() {
      syncFromDom();
      var msg = $('ct-msg');
      var tableName = $('ct-table').value.trim();
      var dbName = $('ct-db').value;
      if (!tableName) { msg.textContent = '表名不能为空'; msg.className = 'db-hint error-text'; return; }
      var list = cols.filter(function (c) { return c.name; });
      if (!list.length) { msg.textContent = '至少要有一个字段'; msg.className = 'db-hint error-text'; return; }

      var spec = {
        table: tableName,
        database: opts.pgMode ? '' : dbName,
        schema: opts.pgMode ? dbName : '',
        columns: list.map(function (c) {
          return {
            name: c.name, type: c.type, nullable: !c.nn,
            primary_key: !!c.pk, auto_increment: !!c.ai, default: c.def || ''
          };
        })
      };
      msg.textContent = '建表中…';
      msg.className = 'db-hint';
      try {
        await req('/api/db/create-table', {
          method: 'POST',
          body: JSON.stringify({ conn_id: opts.connId, spec: spec })
        });
        toast('ok', '已建表 ' + tableName);
        overlay.remove();
        if (opts.onDone) opts.onDone();
      } catch (e) {
        msg.textContent = e.message;
        msg.className = 'db-hint error-text';
      }
    }

    document.body.appendChild(overlay);
    paint();
  }

  window.AwdTableData = {
    open: function (opts) {
      // 作废在途请求：open 之后 st.ref 已经指向新表，
      // 旧表的响应再回来就会把数据错配到新表的写操作上
      st.seq++;
      st.connId = opts.connId;
      st.ref = opts.ref;
      st.kind = opts.kind;
      st.readOnly = opts.readOnly;
      st.host = opts.host;
      st.page = 1;
      st.order = '';
      st.dir = 'asc';
      st.filter = '';
      load();
    },
    structure: structure,
    createTable: createTable,
    reload: load
  };
})();
