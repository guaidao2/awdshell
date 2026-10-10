/* 统一的轻提示。
 *
 * 之前错误提示三种风格混用：window.alert（要手动关、打断操作、
 * 文案没法复制）、各页自己的内联 hint、监控面板的内联错误块。
 * 这里收成一种：右下角浮出、几秒后自己消失，错误停留久一些且可手动关。
 *
 * 破坏性操作仍然用原生 confirm —— 那个需要阻塞用户，浮层不合适。
 */
(function () {
  'use strict';

  var BOX_ID = 'awd-toast-box';
  var MAX_VISIBLE = 4;

  function ensureBox() {
    var box = document.getElementById(BOX_ID);
    if (box) return box;
    box = document.createElement('div');
    box.id = BOX_ID;
    box.className = 'awd-toast-box';
    document.body.appendChild(box);
    return box;
  }

  function show(msg, kind, ms) {
    if (!msg) return;
    var box = ensureBox();

    // 同类提示堆太多会盖住界面，超出的先清掉最旧的
    while (box.children.length >= MAX_VISIBLE) {
      box.removeChild(box.firstChild);
    }

    var el = document.createElement('div');
    el.className = 'awd-toast ' + (kind || 'info');

    var text = document.createElement('span');
    text.className = 'awd-toast-text';
    text.textContent = String(msg);
    el.appendChild(text);

    var close = document.createElement('button');
    close.className = 'awd-toast-close';
    close.textContent = 'x';
    close.title = '关闭';
    el.appendChild(close);

    var timer = null;
    function dismiss() {
      if (timer) clearTimeout(timer);
      if (!el.parentNode) return;
      el.classList.add('out');
      setTimeout(function () {
        if (el.parentNode) el.parentNode.removeChild(el);
      }, 160);
    }
    close.addEventListener('click', dismiss);

    // 错误停留久一点，让用户来得及看清
    var life = ms || (kind === 'error' ? 9000 : (kind === 'warn' ? 6000 : 3800));
    timer = setTimeout(dismiss, life);

    // 悬停时不自动消失（正在读的时候被收走很烦）
    el.addEventListener('mouseenter', function () { if (timer) clearTimeout(timer); });
    el.addEventListener('mouseleave', function () { timer = setTimeout(dismiss, 2000); });

    box.appendChild(el);
    return el;
  }

  window.AwdToast = {
    info: function (m, ms) { return show(m, 'info', ms); },
    ok: function (m, ms) { return show(m, 'ok', ms); },
    warn: function (m, ms) { return show(m, 'warn', ms); },
    error: function (m, ms) { return show(m, 'error', ms); }
  };
})();
