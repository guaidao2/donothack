// web/assets/components/drawer.js
// 职责：右侧抽屉 —— 列表页进详情、单条规则查看的主交互形态。同时只允许开一个。
// 约束：内容由调用方传入已建好的节点；本文件不解析任何文本为结构。

import { el, clear, button } from '../dom.js';

let active = null;

/** 关闭当前抽屉（若存在）。 */
export function closeDrawer() {
  if (active) active.close();
}

function normalizeBody(body) {
  if (body === null || body === undefined) return [];
  if (Array.isArray(body)) return body;
  return [body];
}

/**
 * @param {{title:string, subtitle?:string, body?:Node|Node[], actions?:Node[], onClose?:Function}} spec
 * @returns {{close:Function, setBody:Function, setActions:Function, node:HTMLElement}}
 */
export function openDrawer(spec = {}) {
  if (active) active.close();

  const root = el('div');
  const scrim = el('div', { class: 'scrim' });
  const drawer = el('div', { class: 'drawer', attrs: { role: 'dialog', 'aria-modal': 'true' } });

  const closeBtn = button('关闭', { tone: 'ghost', size: 'sm', title: '关闭（Esc）', onClick: () => close() });
  const head = el(
    'div',
    { class: 'drawer__head' },
    el(
      'div',
      {},
      el('div', { class: 'drawer__title', text: spec.title || '' }),
      spec.subtitle ? el('div', { class: 'drawer__sub', text: spec.subtitle }) : null
    ),
    el('div', { class: 'drawer__close' }, closeBtn)
  );

  const body = el('div', { class: 'drawer__body' }, normalizeBody(spec.body));
  const foot = el('div', { class: 'drawer__foot' }, spec.actions || null);
  if (!spec.actions || spec.actions.length === 0) foot.classList.add('hidden');

  drawer.appendChild(head);
  drawer.appendChild(body);
  drawer.appendChild(foot);
  root.appendChild(scrim);
  root.appendChild(drawer);

  const previousFocus = document.activeElement;

  function onKeydown(event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      close();
    }
  }

  let closed = false;
  function close() {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKeydown);
    if (root.parentNode) root.parentNode.removeChild(root);
    if (active && active.root === root) active = null;
    if (previousFocus && typeof previousFocus.focus === 'function' && previousFocus.isConnected) {
      previousFocus.focus();
    }
    if (typeof spec.onClose === 'function') spec.onClose();
  }

  scrim.addEventListener('click', () => close());
  document.addEventListener('keydown', onKeydown);
  document.body.appendChild(root);
  closeBtn.focus();

  active = {
    root: root,
    close: close,
    setBody(next) {
      clear(body);
      for (const node of normalizeBody(next)) if (node) body.appendChild(node);
    },
    setActions(next) {
      clear(foot);
      const list = next || [];
      for (const node of list) if (node) foot.appendChild(node);
      if (list.length === 0) foot.classList.add('hidden');
      else foot.classList.remove('hidden');
    },
  };
  return active;
}
