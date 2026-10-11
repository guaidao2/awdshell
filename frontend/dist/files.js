/* awdshell 文件管理面板（SFTP）。与 app.js 相互独立：负责文件面板的显示、导航与操作。 */
(function () {
  'use strict';

  var CFG = window.__AWDSHELL__ || {};
  var API = String(CFG.apiBase || location.origin).replace(/\/$/, '');
  var $ = function (id) { return document.getElementById(id); };

  var state = {
    targets: [],
    targetId: '',
    path: '/',
    entries: [],
    // 是否跟随当前激活的终端会话；用户手动改过下拉就置 false
    followActive: true,
    editing: null,
    saving: false,
    dragging: false,
    // 跟随开关与面板宽度从上一次的偏好里恢复
    follow: !(window.AwdPrefs && window.AwdPrefs.get('follow', '1') === '0'),
    lastPaths: {}
  };

  // ---------- 工具 ----------

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  function fmtTime(ms) {
    if (!ms) return '-';
    var d = new Date(ms);
    var p = function (n) { return String(n).padStart(2, '0'); };
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function setStatus(msg) {
    var el = $('status');
    if (el) el.textContent = msg;
  }

  function joinPath(dir, name) {
    if (dir === '/') return '/' + name;
    return dir.replace(/\/$/, '') + '/' + name;
  }

  function parentPath(p) {
    if (!p || p === '/') return '/';
    var parts = p.replace(/\/$/, '').split('/');
    parts.pop();
    return parts.join('/') || '/';
  }

  async function req(path, init) {
    var opt = Object.assign({ headers: { 'Content-Type': 'application/json' } }, init || {});
    var res = await fetch(API + path, opt);
    if (!res.ok) {
      var msg = res.status + ' ' + res.statusText;
      try {
        var j = await res.json();
        if (j && j.error) {
          msg = j.error;
        } else if (j && j.failed && j.failed.length) {
          // /api/files/delete 的"部分失败"回的是 {deleted, failed:[{path,error}], ok, trashed}
          // —— **顶层没有 error 字段**，不认 failed 就只能给用户一句 "409 Conflict"，
          // 哪条路径、为什么失败全丢（终审实测就是这个结果）。
          msg = j.failed.map(function (f) { return f.path + '：' + f.error; }).join('\n');
        }
      } catch (e) { /* 非 JSON */ }
      // 挂状态码：删除的"部分失败"回 409，调用方要能分辨"整体失败"与"删了但有别的失败"。
      var fErr = new Error(msg);
      fErr.status = res.status;
      throw fErr;
    }
    return res.json();
  }

  // ---------- 渲染 ----------

  function renderShell() {
    $('files-area').innerHTML =
      '<div class="fb-toolbar">' +
      '  <select id="fb-target" class="fb-target"></select>' +
      '  <button id="fb-follow-state" class="awd-follow" title=""></button>' +
      '  <button id="fb-up" title="上级目录">上级</button>' +
      '  <button id="fb-refresh" title="刷新">刷新</button>' +
      '  <button id="fb-upload" title="上传文件到当前目录">上传</button>' +
      '  <button id="fb-mkdir" title="新建目录">新建</button>' +
      '  <button id="fb-sync" title="跳到终端当前所在的目录">同步</button>' +
      '  <label class="fb-follow" title="跟随终端里 cd 到的目录"><input type="checkbox" id="fb-follow" checked /> 跟随</label>' +
      '  <input type="file" id="fb-file" multiple hidden />' +
      '</div>' +
      '<div class="fb-path" id="fb-path">/</div>' +
      '<div class="fb-list" id="fb-list"></div>' +
      '<div class="fb-status" id="fb-status"></div>';

    $('fb-target').addEventListener('change', function () {
      // 用户手动选了目标：文件面板锁定它，不再跟着会话跑
      state.followActive = false;
      openTarget(this.value);
    });
    $('fb-up').addEventListener('click', function () { loadDir(parentPath(state.path)); });
    $('fb-refresh').addEventListener('click', function () { loadDir(state.path); });
    $('fb-mkdir').addEventListener('click', doMkdir);
    $('fb-sync').addEventListener('click', syncTermCwd);
    $('fb-upload').addEventListener('click', function () { $('fb-file').click(); });
    $('fb-file').addEventListener('change', function (e) { doUpload(e.target.files); this.value = ''; });
    $('fb-follow').addEventListener('change', function () {
      state.follow = this.checked;
      if (window.AwdPrefs) window.AwdPrefs.set('follow', this.checked ? '1' : '0');
    });

    // 终端报告工作目录变化（OSC 7 或初始目录 cd）时跟随
    window.addEventListener('awdshell:cwd', function (e) {
      var cwdPath = e.detail && e.detail.path;
      if (!cwdPath || !state.follow) return;
      // 设置里的「自动跟随终端目录」是总开关，面板上的复选框是局部开关。
      // 之前只读面板自己的复选框，设置里关掉了照样跳。
      if ((window.AWD_SETTINGS || {}).term_track_cwd === false) return;
      if ($('files-area').hidden) return;
      loadDir(cwdPath);
    });

    $('fb-list').addEventListener('dblclick', function (e) {
      var row = e.target.closest('.fb-row');
      if (!row) return;
      var entry = findEntry(row.dataset.name);
      if (!entry) return;
      if (entry.is_dir) loadDir(entry.path);
      else doEdit(entry);
    });

    $('fb-list').addEventListener('click', function (e) {
      var btn = e.target.closest('[data-act]');
      var row = e.target.closest('.fb-row');
      if (!row) return;
      var entry = findEntry(row.dataset.name);
      if (!entry) return;
      if (btn) {
        var act = btn.dataset.act;
        if (act === 'chmod') doChmod(entry);
        else if (act === 'download') doDownload(entry);
        else if (act === 'edit') doEdit(entry);
        else if (act === 'rename') doRename(entry);
        else if (act === 'delete') doDelete(entry);
        return;
      }
      if (entry.is_dir) loadDir(entry.path);
    });
  }

  // 明确不能当文本编辑的后缀：压缩包、可执行/库、媒体、数据库、字体、镜像、vim 交换文件等。
  var BINARY_EXT = [
    '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.zst', '.7z', '.rar',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a', '.class', '.jar', '.war',
    '.deb', '.rpm', '.apk', '.msi', '.pyc', '.pyo',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.tiff', '.svgz',
    '.pdf', '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wav', '.flac', '.ogg',
    '.db', '.sqlite', '.sqlite3', '.mdb', '.dump',
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    '.iso', '.img', '.vmdk', '.qcow2', '.swp', '.swo', '.pcap', '.pcapng'
  ];

  function isBinaryName(name) {
    var base = String(name).split('/').pop().toLowerCase();
    var m = /\.[^.\/]+$/.exec(base);
    return m ? BINARY_EXT.indexOf(m[0]) >= 0 : false;
  }

  // 内置编辑器的上限，必须与后端 service.TextMaxBytes 保持一致。
  // 之前前端按 1MB 判断、后端在 256KB 截断，中间区间的文件点开会拿到截断内容，
  // 保存下去就把远端文件截短了。
  var TEXT_MAX_BYTES = 256 * 1024;

  // 能不能用内置编辑器打开：类型得像文本，且不超过后端上限。
  function canEdit(entry) {
    return !entry.is_dir && !isBinaryName(entry.name) && entry.size <= TEXT_MAX_BYTES;
  }

  function findEntry(name) {
    for (var i = 0; i < state.entries.length; i++) {
      if (state.entries[i].name === name) return state.entries[i];
    }
    return null;
  }

  // 权限列：查后门、找被改成 777 的目录、发现属主异常，都要靠这一列，
  // 之前只塞在 title 里等于没有
  function modeClass(e) {
    var m = String(e.mode || '');
    if (!m) return '';
    // 其他用户可写 / 有 SUID / SGID 的，属于值得一眼看到的
    if (e.is_dir ? /d.{7}w/.test(m) || /d.{6}w/.test(m) : /.{7}w/.test(m)) return 'warn';
    if (/[sS]/.test(m)) return 'warn';
    return '';
  }

  function renderList() {
    var rows = state.entries.map(function (e) {
      var actions;
      if (e.is_dir) {
        actions = '<button data-act="chmod">权限</button>' +
          '<button data-act="rename">改名</button><button class="danger" data-act="delete">删除</button>';
      } else {
        actions = (canEdit(e) ? '<button data-act="edit" class="key">编辑</button>' : '') +
          '<button data-act="download">下载</button>' +
          '<button data-act="chmod">权限</button>' +
          '<button data-act="rename">改名</button><button class="danger" data-act="delete">删除</button>';
      }
      return '<div class="fb-row" data-name="' + esc(e.name) + '" title="' + esc(e.mode) +
        (e.uid !== undefined && e.uid !== null ? ' 属主 ' + esc(String(e.uid)) + ':' + esc(String(e.gid)) : '') +
        (e.is_dir ? '（双击进入）' : '（双击也可以编辑）') + '">' +
        '<span class="fb-name ' + (e.is_dir ? 'dir' : '') + '">' + esc(e.name) + (e.is_dir ? '/' : '') + '</span>' +
        '<span class="fb-mode ' + modeClass(e) + '">' + esc(shortMode(e.mode)) + '</span>' +
        '<span class="fb-size">' + (e.is_dir ? '-' : fmtSize(e.size)) + '</span>' +
        '<span class="fb-time">' + fmtTime(e.mod_time) + '</span>' +
        '<span class="fb-actions">' + actions + '</span>' +
        '</div>';
    }).join('');
    $('fb-list').innerHTML =
      '<div class="fb-head fb-cols"><span>名称</span><span>权限</span><span>大小</span><span>修改时间</span><span>操作</span></div>' +
      (rows || '<div class="fb-empty">这个目录是空的</div>');
    $('fb-path').textContent = state.path;
    $('fb-status').textContent = state.entries.length + ' 项' + (state.targetId ? '' : '（先选目标）');
  }

  // shortMode 把 rwxr-xr-x 压成更短的等宽形式，面板横向空间有限
  function shortMode(mode) {
    var m = String(mode || '');
    if (!m) return '-';
    // 去掉最前面的文件类型字符，留 9 位权限
    return m.length > 9 ? m.slice(1) : m;
  }

  // 编辑权限：用 chmod 的八进制写法，最直观也最不容易写错
  async function doChmod(entry) {
    var cur = String(entry.mode || '');
    var octal = modeToOctal(cur);
    var input = window.prompt('修改 ' + targetLabel() + ' 的\n' + entry.path + '\n\n当前权限：' + cur +
      (octal ? '（' + octal + '）' : '') + '\n\n输入新的八进制权限（例如 644、755、600）：', octal || '');
    if (!input) return;
    input = input.trim();
    if (!/^[0-7]{3,4}$/.test(input)) {
      window.AwdToast.error('权限要写成 3 到 4 位八进制数，例如 644、755、600、4755。');
      return;
    }
    try {
      await req('/api/files/chmod', {
        method: 'POST',
        body: JSON.stringify({ target_id: state.targetId, path: entry.path, mode: input })
      });
      await loadDir(state.path);
      setStatus('已把 ' + entry.name + ' 的权限改为 ' + input);
    } catch (e) {
      window.AwdToast.error('修改权限失败\n\n' + e.message);
    }
  }

  // modeToOctal 把 rwxr-xr-x 换算成 755
  function modeToOctal(mode) {
    var m = String(mode || '');
    if (m.length < 10) return '';
    var triple = m.slice(1, 10);
    var out = '';
    for (var g = 0; g < 3; g++) {
      var s = triple.slice(g * 3, g * 3 + 3);
      var n = 0;
      if (s[0] === 'r') n += 4;
      if (s[1] === 'w') n += 2;
      if (s[2] === 'x' || s[2] === 's' || s[2] === 't') n += 1;
      out += n;
    }
    return out;
  }

  // 跟随状态可见 + 一键恢复。
  // 锁定是隐形的：用户切了会话发现面板不动，看起来就像坏了。
  function renderSyncState() {
    if (!window.AwdViews) return;
    window.AwdViews.followButton('fb-follow-state', state.followActive, '文件面板目标', function () {
      state.followActive = true;
      syncToActiveSession();
      renderTargets();
      setStatus('文件面板已恢复跟随当前会话');
    });
  }

  function renderTargets() {
    var sel = $('fb-target');
    if (!sel) return;
    renderSyncState();
    sel.innerHTML = state.targets.map(function (t) {
      return '<option value="' + esc(t.id) + '"' + (t.id === state.targetId ? ' selected' : '') + '>' +
        esc(t.name) + '</option>';
    }).join('') || '<option value="">无目标</option>';
  }

  // ---------- 数据 ----------

  async function loadTargets() {
    state.targets = await (window.AwdTargets ? window.AwdTargets.load() : req('/api/targets'));
    // 目标可能已被删除：先清掉悬空的 targetId，否则刷新时会弹"记录不存在"，
    // 而下拉视觉上已经跳到第一台了，看着像两个目标在打架
    if (state.targetId && !state.targets.some(function (t) { return t.id === state.targetId; })) {
      state.targetId = '';
      state.entries = [];
    }
    if (!state.targetId && state.targets.length) state.targetId = state.targets[0].id;
    renderTargets();
  }

  // 打开某个目标的文件视图：优先回到上次浏览的目录，否则用配置的初始目录
  // （初始目录不存在时后端会回退到家目录，这里只负责展示提示）。
  async function openTarget(tid) {
    if (tid) state.targetId = tid;
    if (!state.targetId) { setStatus('文件：请先选择一个目标'); return; }
    if (state.lastPaths[state.targetId]) {
      await loadDir(state.lastPaths[state.targetId]);
      return;
    }
    await loadInitialDir();
  }

  async function loadInitialDir() {
    var startPath = '/';
    try {
      var info = await req('/api/files/startdir?target_id=' + encodeURIComponent(state.targetId));
      if (info && info.path) startPath = info.path;
      if (info && info.fallback) {
        setStatus('初始目录 ' + info.wanted + ' 不存在，已回退到 ' + info.path);
      }
    } catch (e) {
      // 原来是空 catch：读不到初始目录就悄悄落到 /，用户看到的是"莫名其妙在根目录"。
      // 这里不能用 setStatus —— 紧接着的 loadDir 会把它覆盖掉，用浮层提示才留得住。
      if (window.AwdToast) {
        window.AwdToast.warn('读取初始目录失败，已从根目录 / 开始（' + e.message + '）');
      }
    }
    await loadDir(startPath);
  }

  // 主动查一次交互终端的当前目录并跳过去（对没配置 OSC 7 的环境最实用）。
  async function syncTermCwd() {
    if (!state.targetId) return;
    setStatus('正在获取终端目录…');
    try {
      var r = await req('/api/files/cwd?target_id=' + encodeURIComponent(state.targetId));
      if (r && r.path) {
        state.lastPaths[state.targetId] = r.path;
        if (!$('files-area').hidden) await loadDir(r.path);
        else { state.path = r.path; }
        setStatus('已同步到终端目录 ' + r.path);
      }
    } catch (e) {
      setStatus('同步终端目录失败：' + e.message);
      window.AwdToast.error('同步终端目录失败\n\n' + e.message);
    }
  }

  // 目录读取的请求序号：切目标或切目录时，早先发出的请求可能后返回，
  // 若不丢弃就会用旧列表盖住新目标 —— 用户在这个窗口里点行内按钮，
  // 请求会带着新 target_id 配旧路径，操作到另一台主机的同名文件上。
  var loadSeq = 0;

  async function loadDir(p) {
    if (!state.targetId) { setStatus('文件：请先选择一个目标'); return; }
    var dir = p || state.path || '/';
    var seq = ++loadSeq;
    var tid = state.targetId;
    setStatus('正在读取 ' + dir + ' ...');
    try {
      var entries = await req('/api/files/list?target_id=' + encodeURIComponent(tid) + '&path=' + encodeURIComponent(dir));
      if (seq !== loadSeq || tid !== state.targetId) return; // 过期响应，丢弃
      state.entries = entries;
      state.path = dir;
      state.lastPaths[tid] = dir;
      renderList();
      setStatus('文件：' + dir);
    } catch (e) {
      if (seq !== loadSeq) return;
      setStatus('读取目录失败：' + e.message);
      window.AwdToast.error('读取目录失败\n\n' + e.message);
    }
  }

  // 危险操作前把「在哪台机器上」说清楚 —— 只写文件名的话，
  // 用户没法判断自己是不是点错了目标。
  function targetLabel() {
    var list = state.targets || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].id === state.targetId) {
        return list[i].name + '（' + list[i].username + '@' + list[i].host + '）';
      }
    }
    return '目标 ' + String(state.targetId || '').slice(0, 8);
  }

  async function doMkdir() {
    if (!state.targetId) return;
    var name = window.prompt('新目录名称');
    if (!name) return;
    try {
      await req('/api/files/mkdir', { method: 'POST', body: JSON.stringify({ target_id: state.targetId, path: joinPath(state.path, name) }) });
      await loadDir(state.path);
      setStatus('已创建目录 ' + name);
    } catch (e) { window.AwdToast.error('创建目录失败\n\n' + e.message); }
  }

  async function doRename(entry) {
    var name = window.prompt('在 ' + targetLabel() + ' 的 ' + state.path + ' 下重命名「' + entry.name + '」\n\n新名称：', entry.name);
    if (!name || name === entry.name) return;
    // 改名不负责移动：带斜杠会被拼成另一个路径，属于意外操作
    if (name.indexOf('/') >= 0) {
      window.AwdToast.error('新名称里不能有斜杠。改名不能移动文件，要换目录请到目标目录里操作。');
      return;
    }
    try {
      await req('/api/files/rename', { method: 'POST', body: JSON.stringify({ target_id: state.targetId, old: entry.path, new: joinPath(state.path, name) }) });
      await loadDir(state.path);
      setStatus('已重命名为 ' + name);
    } catch (e) { window.AwdToast.error('重命名失败\n\n' + e.message); }
  }

  async function doDelete(entry) {
    var trash = (window.AWD_SETTINGS || {}).trash_on_delete !== false;
    var note = trash ? '将移入远程回收站（~/.awdshell-trash/，可还原）' : '将直接删除（当前设置未启用回收站）';
    if (!window.confirm('在 ' + targetLabel() + ' 的 ' + state.path + ' 下删除「' + entry.name + '」？\n\n' + note)) return;
    try {
      await req('/api/files/delete', { method: 'POST', body: JSON.stringify({ target_id: state.targetId, paths: [entry.path], trash: trash }) });
      await loadDir(state.path);
      setStatus(trash ? '已移入回收站：' + entry.name : '已删除：' + entry.name);
    } catch (e) {
      // 409 = 部分失败（`{deleted, failed:[{path,error}]}`，`req` 已经把 failed 逐条展开进
      // message）。删除是逐条执行的，所以**不能**笼统报"删除失败"就完事 —— 得刷新列表、
      // 把实际状态摆出来，否则用户会以为文件还在（或以为删掉了）。
      if (e.status === 409) {
        await loadDir(state.path);
        setStatus('删除未完全成功：' + entry.name);
        window.AwdToast.error('删除未成功\n\n' + e.message);
        return;
      }
      window.AwdToast.error('删除失败\n\n' + e.message);
    }
  }

  async function doDownload(entry) {
    var dir = (window.AWD_SETTINGS && window.AWD_SETTINGS.download_dir) || '';
    setStatus('正在下载 ' + entry.name + ' ...');
    try {
      if (dir) {
        // 配了默认下载目录：让后端把远端文件**流式**写到那里。
        // 既不经过浏览器（浏览器只能落到系统默认下载目录），
        // 也不会把整个文件读进内存 —— 大文件下载因此也轻了。
        var r = await req('/api/files/save-to-dir', {
          method: 'POST',
          body: JSON.stringify({ target_id: state.targetId, path: entry.path })
        });
        setStatus('已下载到 ' + r.saved_to);
        window.AwdToast.ok('已保存到\n' + r.saved_to);
        return;
      }
      // 没配目录：走浏览器下载（走 fetch 而不是 <a download>，
      // 后者拿不到失败——权限不足、目录、连接断都会变成 0 字节的"成功"文件）
      var res = await fetch(API + '/api/files/download?target_id=' + encodeURIComponent(state.targetId) +
        '&path=' + encodeURIComponent(entry.path));
      if (!res.ok) {
        var j = await res.json().catch(function () { return {}; });
        throw new Error(j.error || res.statusText);
      }
      var blob = await res.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = entry.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 5000);
      setStatus('已下载 ' + entry.name + '（' + (blob.size / 1024).toFixed(1) + ' KB）');
    } catch (e) {
      setStatus('下载失败：' + entry.name);
      window.AwdToast.error('下载失败：' + entry.name + '\n\n' + e.message);
    }
  }

  async function doUpload(files) {
    if (!files || !files.length || !state.targetId) return;
    // 先把目标和目录固定下来：上传途中用户可能切目标或切目录，
    // 循环里读实时的 state.path 会让后面的文件落到别的地方。
    var tid = state.targetId;
    var dir = state.path;
    var ok = 0;
    var failed = [];
    for (var i = 0; i < files.length; i++) {
      var fd = new FormData();
      fd.append('target_id', tid);
      fd.append('dir', dir);
      fd.append('file', files[i]);
      setStatus('上传中 ' + (i + 1) + '/' + files.length + '：' + files[i].name);
      try {
        var res = await fetch(API + '/api/files/upload', { method: 'POST', body: fd });
        if (!res.ok) {
          var j = await res.json().catch(function () { return {}; });
          throw new Error(j.error || res.statusText);
        }
        ok++;
      } catch (e) {
        // 单个失败不中断，继续传剩下的，最后一起报
        failed.push(files[i].name + '（' + e.message + '）');
      }
    }
    if (state.targetId === tid) await loadDir(dir);
    if (failed.length) {
      window.AwdToast.error('有 ' + failed.length + ' 个文件上传失败：\n\n' + failed.join('\n') +
        '\n\n成功的 ' + ok + ' 个已传到 ' + dir);
      setStatus('上传：成功 ' + ok + ' 个，失败 ' + failed.length + ' 个');
    } else {
      setStatus('上传完成：' + ok + ' 个文件已传到 ' + dir);
    }
  }

  // ---------- 编辑器（CodeMirror；按扩展名动态加载对应 mode）----------

  var cm = null;
  var loadedModes = {};

  // 扩展名 → 语法模式。
  //
  // .php 是混合模式：依赖 clike + htmlmixed（而 htmlmixed 又依赖 xml/javascript/css），
  // 全部列在 MODE_DEPS 里按顺序加载。缺一个 CodeMirror 都会静默退回 null 模式，
  // 然后在缩进时抛内部错误，看着就像编辑器坏了。
  var MODE_BY_EXT = {
    '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.ksh': 'shell',
    '.js': 'javascript', '.mjs': 'javascript', '.json': 'javascript',
    '.py': 'python', '.php': 'php',
    '.xml': 'xml', '.html': 'htmlmixed', '.htm': 'htmlmixed', '.svg': 'xml',
    '.css': 'css', '.yml': 'yaml', '.yaml': 'yaml', '.sql': 'sql',
    '.md': 'markdown', '.pl': 'perl', '.go': 'go', '.ps1': 'powershell',
    '.conf': 'properties', '.ini': 'properties', '.cnf': 'properties',
    '.service': 'properties', '.properties': 'properties', '.env': 'properties'
  };

  // 没有扩展名、但很常见的配置文件（按文件名判定）。
  var MODE_BY_NAME = {
    'profile': 'shell', 'bashrc': 'shell', 'bash_profile': 'shell', 'zshrc': 'shell',
    'crontab': 'shell', 'rc.local': 'shell', 'inittab': 'properties',
    'passwd': 'properties', 'shadow': 'properties', 'group': 'properties',
    'fstab': 'properties', 'hosts': 'properties', 'hostname': 'properties',
    'services': 'properties', 'sudoers': 'properties', 'my.cnf': 'properties',
    'resolv.conf': 'properties', 'nsswitch.conf': 'properties', 'ld.so.conf': 'properties',
    'sysctl.conf': 'properties', 'rsyslog.conf': 'properties', 'sshd_config': 'properties'
  };

  function modeFor(name) {
    var base = String(name).split('/').pop().toLowerCase();
    if (base === 'dockerfile' || base.indexOf('dockerfile.') === 0) return 'dockerfile';
    if (base.indexOf('nginx') === 0) return 'nginx';
    if (MODE_BY_NAME[base]) return MODE_BY_NAME[base];
    if (base.charAt(0) === '.' && /^\.(bash|zsh|ksh|profile|bashrc|bash_profile|zshrc|inputrc|shrc)/.test(base)) return 'shell';
    var m = /\.[^.\/]+$/.exec(base);
    return m ? (MODE_BY_EXT[m[0]] || '') : '';
  }

  // 文件名判断不出来时，看首行 shebang。
  function modeFromShebang(content) {
    var first = String(content).split('\n', 1)[0] || '';
    if (first.indexOf('#!') !== 0) return '';
    if (/bash|zsh|\bsh\b|ksh|dash/.test(first)) return 'shell';
    if (/python/.test(first)) return 'python';
    if (/perl/.test(first)) return 'perl';
    if (/pwsh|powershell/.test(first)) return 'powershell';
    return '';
  }

  // 每个语法模式需要先加载的依赖文件（顺序有意义）。
  //
  // 混合模式是这里的坑：php 依赖 htmlmixed + clike，htmlmixed 又依赖
  // xml + javascript + css。缺任何一个，CodeMirror.getMode 都会**静默**退回
  // null 模式，然后在缩进时抛内部错误（先报 htmlMode.indent is not a function，
  // 补了 htmlmixed 少 clike 就变成 reading 'prev'），看着就像编辑器坏了。
  var MODE_DEPS = {
    htmlmixed: ['xml', 'javascript', 'css', 'htmlmixed'],
    php: ['clike', 'xml', 'javascript', 'css', 'htmlmixed', 'php']
  };

  // 同一份脚本只插一次；失败后允许下次重试（瞬时失败不能永久钉死）
  var modeLoading = {};

  function loadScriptOnce(src) {
    if (modeLoading[src]) return modeLoading[src];
    var p = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      var done = false;
      // 没有超时的话，请求一挂住 await 就永不 settle，
      // 表现和"编辑器打不开"一模一样
      var timer = setTimeout(function () {
        if (done) return;
        done = true;
        s.remove();
        reject(new Error('加载超时 ' + src));
      }, 8000);
      s.src = src;
      s.onload = function () {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve();
      };
      s.onerror = function () {
        if (done) return;
        done = true;
        clearTimeout(timer);
        s.remove();
        reject(new Error('加载失败 ' + src));
      };
      document.head.appendChild(s);
    });
    p.catch(function () {
      if (modeLoading[src] === p) delete modeLoading[src];
    });
    modeLoading[src] = p;
    return p;
  }

  // ensureMode 按依赖顺序加载，返回是否**全部就绪**。
  // 调用方拿到 false 时要退回纯文本，而不是硬套一个残缺模式。
  async function ensureMode(name) {
    if (!name) return false;
    if (loadedModes[name] === 'ok') return true;

    var files = MODE_DEPS[name] || [name];
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      if (loadedModes[f] === 'ok') continue;
      try {
        await loadScriptOnce('/vendor/codemirror/mode/' + f + '.js');
      } catch (e) {
        return false; // 不落缓存：下次还能重试
      }
      // 脚本"下载成功"不等于模式"注册成功"，必须回头确认 CodeMirror 真的认识它：
      //   1) -web 模式下 SPA 回退会把 index.html 当 JS 返回（200），onload 照样触发
      //   2) 有的模式依赖缺 vendor 的 addon（dockerfile 需要 defineSimpleMode），
      //      执行期抛错但 onload 仍然成功
      // 不校验的话，这两种情况都会静默变成"没高亮"，而且完全不报错
      if (!window.CodeMirror.modes[f]) return false;
      loadedModes[f] = 'ok';
    }
    loadedModes[name] = 'ok';
    return true;
  }

  function ensureEditor() {
    if (cm || !window.CodeMirror) return cm;
    cm = window.CodeMirror($('file-editor'), {
      value: '',
      lineNumbers: true,
      lineWrapping: false,
      matchBrackets: true,
      autoCloseBrackets: true,
      styleActiveLine: true,
      indentUnit: 4,
      tabSize: 4,
      mode: null
    });
    return cm;
  }

  async function doEdit(entry) {
    if (isBinaryName(entry.name)) {
      window.AwdToast.error('这是二进制或压缩文件，内置编辑器打不开。\n\n请用「下载」取到本地后再处理。');
      return;
    }
    if (entry.size > TEXT_MAX_BYTES) {
      window.AwdToast.error('文件有 ' + (entry.size / 1024).toFixed(0) + ' KB，超过内置编辑器上限 256 KB。\n\n请用「下载」取到本地后再编辑，避免保存时把远端文件截短。');
      return;
    }
    try {
      var r = await req('/api/files/read?target_id=' + encodeURIComponent(state.targetId) + '&path=' + encodeURIComponent(entry.path));
      state.editing = entry;
      state.original = r.content; // 用于判断有没有未保存的改动
      $('file-modal-title').textContent = '编辑 ' + entry.name;
      $('file-error').textContent = '';
      $('file-modal').hidden = false;

      var mode = modeFor(entry.name) || modeFromShebang(r.content);
      // 依赖没加载齐就退回纯文本：硬套残缺模式会在缩进时抛
      // "xxx.indent is not a function"，编辑器直接打不开
      var modeReady = await ensureMode(mode);
      if (!modeReady) mode = '';

      var ed = ensureEditor();
      if (!ed) { window.AwdToast.error('编辑器未能加载'); return; }
      try {
        ed.setOption('mode', mode || null);
      } catch (err) {
        // 极少数模式下 setOption 仍可能抛，退回纯文本总比打不开强
        mode = '';
        ed.setOption('mode', null);
      }
      ed.setValue(r.content);
      ed.clearHistory();

      // state.editing / state.original 必须等编辑器内容换好之后再赋值。
      // 提前赋值的话，上面 await ensureMode 的那个窗口里用户按 Ctrl+S，
      // 保存用的是"新文件路径 + 上一个文件的内容"，会直接把远端新文件覆盖掉。
      state.editing = entry;
      state.original = r.content;
      // 内容就位之后才显示弹窗，避免出现"弹窗里是上一个文件"的错位状态
      $('file-modal').hidden = false;

      setTimeout(function () { ed.refresh(); ed.focus(); }, 40);
      setStatus(mode ? ('编辑 ' + entry.name + '（' + mode + ' 语法高亮）') : ('编辑 ' + entry.name + '（纯文本）'));
    } catch (e) { window.AwdToast.error('打开文件失败\n\n' + e.message); }
  }

  // 关闭编辑器前确认未保存的改动。
  // 改 sshd_config 这类文件时按一下 Esc 就全丢了，用户很难预料到。
  function closeEditor() {
    if (cm && state.original !== null && cm.getValue() !== state.original) {
      var name = state.editing ? state.editing.name : '文件';
      if (!window.confirm('「' + name + '」有未保存的改动，确定放弃吗？')) return;
    }
    $('file-modal').hidden = true;
    state.original = null;
  }

  async function saveFile() {
    if (!state.editing || state.saving || !cm) return;
    state.saving = true;
    try {
      await req('/api/files/write', {
        method: 'POST',
        body: JSON.stringify({ target_id: state.targetId, path: state.editing.path, content: cm.getValue() })
      });
      $('file-modal').hidden = true;
      state.original = null;
      await loadDir(state.path);
      setStatus('已保存 ' + state.editing.name);
    } catch (e) {
      $('file-error').textContent = e.message;
    } finally {
      state.saving = false;
    }
  }

  // ---------- 面板显示控制 ----------

  // 右侧栏位在“文件”和“监控”之间共用，同一时刻只显示一个。
  function syncSidePanel(except) {
    var files = !$('files-area').hidden;
    var monitor = $('monitor-area') ? !$('monitor-area').hidden : false;
    $('files-resizer').hidden = !(files || monitor);
    var fb = $('btn-files');
    var mb = $('btn-monitor');
    if (fb) fb.classList.toggle('active', files);
    if (mb) mb.classList.toggle('active', monitor);
    void except;
  }

  function setFilesVisible(show) {
    var area = $('files-area');
    var btn = $('btn-files');
    if (show && $('monitor-area')) {
      $('monitor-area').hidden = true;
      window.dispatchEvent(new Event('awdshell:monitor-hide'));
    }
    area.hidden = !show;
    syncSidePanel('files');
    if (btn) btn.classList.toggle('active', show);
    if (show) {
      // 每次打开都回到"跟随当前会话"：上次手动选的目录不该一直粘着
      state.followActive = true;
      if (!state.targets.length) {
        loadTargets().then(function () {
          syncToActiveSession();
          openTarget(state.targetId);
        }).catch(function (e) { setStatus('加载目标失败：' + e.message); });
      } else {
        syncToActiveSession();
        renderTargets();
        openTarget(state.targetId);
      }
    }
    window.dispatchEvent(new Event('resize'));
  }

  // 跟随当前激活的终端会话：切标签时文件面板跟着换主机。
  // 用户一旦手动改过下拉就锁定（followActive = false），不再自动覆盖。
  function syncToActiveSession() {
    if (!state.followActive) return false;
    var tid = window.AwdActiveTarget ? window.AwdActiveTarget() : '';
    if (!tid || tid === state.targetId) return false;
    state.targetId = tid;
    state.entries = [];
    state.path = '/';
    renderTargets();
    return true;
  }

  function toggleFiles() {
    setFilesVisible($('files-area').hidden);
  }

  function toggleSettings() {
    // 互斥与工作区显隐都交给统一组件，各视图不再各写一份列表
    window.AwdViews.toggle('settings-area');
  }

  // 分隔条：文件面板与监控面板共用一块栏位，拖动时改当前可见那个的宽度。
  // 宽度直接等于「窗口右边缘 - 鼠标位置」，不要再减常量——之前减了 140，手感是错的。
  function initResizer() {
    var rz = $('files-resizer');
    if (!rz) return;

    function currentArea() {
      var f = $('files-area');
      return (f && !f.hidden) ? f : $('monitor-area');
    }

    rz.addEventListener('mousedown', function (e) {
      state.dragging = true;
      e.preventDefault();
      document.body.classList.add('col-resizing');
    });
    window.addEventListener('mousemove', function (e) {
      if (!state.dragging) return;
      var area = currentArea();
      if (!area) return;
      var w = window.innerWidth - e.clientX;
      var min = 280;
      var max = Math.max(min, window.innerWidth - 420); // 左边至少给终端留 420px
      w = Math.max(min, Math.min(max, w));
      area.style.width = w + 'px';
      if (window.AwdPrefs) window.AwdPrefs.set('panelWidth', w);
    });
    // 结束拖动。窗口外松手收不到 mouseup，指针再动宽度还会继续变，
    // 所以失焦、指针取消、移出文档都当作结束
    function endDrag() {
      if (!state.dragging) return;
      state.dragging = false;
      document.body.classList.remove('col-resizing');
      window.dispatchEvent(new Event('resize'));
    }
    window.addEventListener('mouseup', endDrag);
    window.addEventListener('blur', endDrag);
    window.addEventListener('pointercancel', endDrag);
    document.addEventListener('mouseleave', endDrag);
    // 双击分隔条 = 恢复默认宽度
    rz.addEventListener('dblclick', function () {
      var area = currentArea();
      if (area) { area.style.width = '470px'; window.dispatchEvent(new Event('resize')); }
    });
  }

  // 整页视图的统一关闭：标题栏的「关闭」按钮或 Esc。
  // 具体逻辑在 views.js，这里只转一层。
  function closeViews() {
    if (!window.AwdViews) return false;
    return window.AwdViews.closeAll();
  }

  // ---------- 初始化 ----------

  window.AwdSidePanel = { sync: syncSidePanel };

  function boot() {
    renderShell();
    initResizer();

    // 恢复上次的面板宽度与跟随开关：每次都回到默认值会让人反复调
    if (window.AwdPrefs) {
      var savedW = parseInt(window.AwdPrefs.get('panelWidth', '0'), 10);
      if (savedW >= 280) {
        var fa = $('files-area'), ma = $('monitor-area');
        if (fa) fa.style.width = savedW + 'px';
        if (ma) ma.style.width = savedW + 'px';
      }
      if ($('fb-follow')) $('fb-follow').checked = state.follow;
    }

    // 「关闭」按钮用事件委托，设置页与日志检测页共用同一套逻辑
    document.addEventListener('click', function (e) {
      var el = e.target;
      if (el && el.classList && el.classList.contains('view-close')) closeViews();
    });
    window.addEventListener('keydown', function (e) {
      // Ctrl/Cmd+S 保存正在编辑的文件（之前只能点按钮，习惯上会按快捷键）
      if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
        // 一律 preventDefault：编辑器没开时不拦的话，浏览器会弹出「保存网页」
        e.preventDefault();
        if (!$('file-modal').hidden) saveFile();
        return;
      }
      if (e.key !== 'Escape') return;
      if (!$('file-modal').hidden) { closeEditor(); return; }
      closeViews();
    });
    $('file-cancel').addEventListener('click', closeEditor);
    $('file-save').addEventListener('click', saveFile);
    // 点编辑器外的遮罩也走同一套未保存确认
    $('file-modal').addEventListener('mousedown', function (e) {
      if (e.target === $('file-modal')) closeEditor();
    });
    $('btn-files').addEventListener('click', toggleFiles);
    $('btn-settings').addEventListener('click', toggleSettings);

    // 打开终端或切换标签时把文件面板切到同一个目标（同屏用时很顺手）；
    // 用户手动选过目标就锁定，不覆盖他的选择
    window.addEventListener('awdshell:connected', function () {
      if (syncToActiveSession() && !$('files-area').hidden) openTarget(state.targetId);
    });

    // 关掉某个目标的最后一个 SSH 标签时，文件面板一起收起
    window.addEventListener('awdshell:session-closed', function (e) {
      var d = (e && e.detail) || {};
      if ($('files-area').hidden) return;
      if (d.targetId !== state.targetId) return;
      var remaining = d.remainingTargets || [];
      if (remaining.indexOf(state.targetId) < 0) {
        setFilesVisible(false);
        setStatus('该目标的会话已全部关闭，文件面板已收起');
      }
    });

    // 目标被新建或删除后重取列表，否则下拉里还是旧数据
    window.addEventListener('awdshell:targets-changed', function () {
      loadTargets().catch(function () {});
    });
    loadTargets().catch(function () { /* 忽略：首次打开文件面板时会再试 */ });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
