// web/assets/components/toast.js
// 职责：右下角轻提示 —— 成功/失败/警告/信息，写操作 warnings 与 API 错误的统一出口。
// 约束：文本只走 textContent；不插入任何响应内容为结构。

import { el, coerceText, describeError } from '../dom.js';

let container = null;

function host() {
  if (container && container.isConnected) return container;
  container = el('div', { class: 'toasts', attrs: { role: 'status', 'aria-live': 'polite' } });
  document.body.appendChild(container);
  return container;
}

function dismiss(node) {
  if (node && node.parentNode) node.parentNode.removeChild(node);
}

/**
 * @param {'ok'|'error'|'warn'|'info'} tone
 * @param {string} message
 * @param {{timeout?:number, detail?:string}} [opts]
 */
export function toast(tone, message, opts = {}) {
  const timeout = typeof opts.timeout === 'number' ? opts.timeout : tone === 'error' ? 9000 : 4200;
  const node = el(
    'div',
    { class: 'toast toast--' + tone },
    el(
      'div',
      { class: 'toast__text' },
      el('div', { text: coerceText(message) }),
      opts.detail ? el('div', { class: 'xs faint mono', text: coerceText(opts.detail) }) : null
    )
  );
  node.addEventListener('click', () => dismiss(node));
  host().appendChild(node);
  if (timeout > 0) globalThis.setTimeout(() => dismiss(node), timeout);
  return node;
}

export const notify = {
  ok: (message, opts) => toast('ok', message, opts),
  error: (message, opts) => toast('error', message, opts),
  warn: (message, opts) => toast('warn', message, opts),
  info: (message, opts) => toast('info', message, opts),
};

/** 把 ApiError / Error 转成提示；返回归一化后的错误信息。 */
export function toastError(err, fallback = '操作失败') {
  const info = describeError(err);
  toast('error', info.title || fallback, { detail: info.detail });
  return info;
}

/** 写操作返回体里的 warnings[]：这是"这次改动的副作用"，不能吞。 */
export function showWarnings(warnings, prefix = '副作用提示') {
  if (!Array.isArray(warnings) || warnings.length === 0) return;
  for (const warning of warnings) {
    const text = typeof warning === 'string' ? warning : warning && (warning.message || warning.code);
    toast('warn', prefix + '：' + coerceText(text || '未命名警告'), {
      timeout: 9000,
      detail: typeof warning === 'object' && warning && warning.detail ? warning.detail : '',
    });
  }
}
