// web/assets/components/modal.js
// 职责：模态对话框 —— 确认（危险操作二次确认）、提示、以及由字段声明生成的表单对话框。
// 约束：字段值由 input.value 读取，错误提示只写 textContent；不使用任何行内结构拼接。

import { el, clear, button, field, textInput, textArea, checkbox, selectInput, describeError } from '../dom.js';

function overlay() {
  return el('div', { class: 'modal', attrs: { role: 'dialog', 'aria-modal': 'true' } });
}

function buildField(spec) {
  if (spec.type === 'checkbox') {
    const node = checkbox(spec.label, { checked: !!spec.value });
    return { node: node, read: () => node.querySelector('input').checked, focus: () => node.querySelector('input') };
  }
  if (spec.type === 'select') {
    const select = selectInput(spec.options || [], { value: spec.value });
    return {
      node: field(spec.label, select, spec.hint),
      read: () => select.value,
      focus: () => select,
    };
  }
  if (spec.type === 'textarea') {
    const area = textArea({
      value: spec.value === undefined || spec.value === null ? '' : spec.value,
      placeholder: spec.placeholder || '',
      rows: spec.rows || 8,
    });
    return { node: field(spec.label, area, spec.hint), read: () => area.value, focus: () => area };
  }
  const input = textInput({
    type: spec.type || 'text',
    value: spec.value === undefined || spec.value === null ? '' : spec.value,
    placeholder: spec.placeholder || '',
    autocomplete: spec.autocomplete || 'off',
  });
  return {
    node: field(spec.label, input, spec.hint),
    read: () => input.value,
    focus: () => input,
  };
}

function readValues(fields) {
  const values = {};
  for (const entry of fields) values[entry.spec.name] = entry.read();
  return values;
}

/** 表单 onSubmit 返回这个哨兵时，对话框保持打开（用于"校验结果就地展示"这类流程）。 */
export const KEEP_OPEN = Symbol('keep-open');

/**
 * 通用对话框。
 * @param {{title:string, description?:string, fields?:Array, body?:Node, submitText?:string,
 *          cancelText?:string, danger?:boolean, wide?:boolean,
 *          onSubmit?:Function, onCancel?:Function}} spec
 * @returns {Promise<object|null>} 确认时 resolve 表单值（无字段时 {}），取消时 null
 */
export function openDialog(spec = {}) {
  return new Promise((resolve) => {
    const modal = overlay();
    const box = el('div', {
      class:
        'modal__box' +
        (spec.wide ? ' modal__box--wide' : '') +
        (spec.xwide ? ' modal__box--xwide' : ''),
    });
    const form = el('form', { attrs: { novalidate: 'novalidate' } });

    const head = el('div', { class: 'modal__head' });
    head.appendChild(el('span', { text: spec.title || '' }));
    // 头部也放一个关闭：弹窗很高时，底部的按钮可能不在视野里（这是"关不掉"的常见原因）
    head.appendChild(
      button('关闭', {
        tone: 'ghost',
        size: 'sm',
        onClick: () => finish(null),
      })
    );
    form.appendChild(head);

    const body = el('div', { class: 'modal__body' });
    if (spec.description) body.appendChild(el('p', { class: 'sm muted', text: spec.description }));
    if (spec.body) body.appendChild(spec.body);

    const fieldEntries = [];
    for (const fieldSpec of spec.fields || []) {
      const entry = buildField(fieldSpec);
      entry.spec = fieldSpec;
      fieldEntries.push(entry);
      body.appendChild(entry.node);
    }
    const errorLine = el('div', { class: 'field__error hidden' });
    body.appendChild(errorLine);
    form.appendChild(body);

    const cancelLabel = spec.cancelText === undefined ? '取消' : spec.cancelText;
    const foot = el('div', { class: 'modal__foot' });
    if (cancelLabel) {
      foot.appendChild(button(cancelLabel, { onClick: () => finish(null) }));
    }
    const submitBtn = button(spec.submitText || '确认', {
      tone: spec.danger ? 'danger' : 'primary',
      type: 'submit',
    });
    foot.appendChild(submitBtn);
    form.appendChild(foot);
    box.appendChild(form);
    modal.appendChild(box);
    // 点遮罩也关（点盒子内部不关）—— 这是最顺手的一条退路
    modal.addEventListener('click', (event) => {
      if (event.target === modal) finish(null);
    });

    const previousFocus = document.activeElement;
    let done = false;

    function onKeydown(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        finish(null);
      }
    }

    function finish(value) {
      if (done) return;
      done = true;
      document.removeEventListener('keydown', onKeydown);
      if (modal.parentNode) modal.parentNode.removeChild(modal);
      if (previousFocus && typeof previousFocus.focus === 'function' && previousFocus.isConnected) previousFocus.focus();
      resolve(value);
    }

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      errorLine.classList.add('hidden');
      const values = readValues(fieldEntries);
      const missing = fieldEntries.find(
        (entry) => entry.spec.required && (values[entry.spec.name] === '' || values[entry.spec.name] === null)
      );
      if (missing) {
        errorLine.textContent = '请填写：' + missing.spec.label;
        errorLine.classList.remove('hidden');
        missing.focus();
        return;
      }
      if (typeof spec.onSubmit !== 'function') {
        finish(values);
        return;
      }
      submitBtn.disabled = true;
      const original = submitBtn.textContent;
      submitBtn.textContent = '提交中…';
      try {
        const result = await spec.onSubmit(values);
        if (result === KEEP_OPEN) {
          submitBtn.disabled = false;
          submitBtn.textContent = original;
          return;
        }
        finish(result === undefined ? values : result);
      } catch (err) {
        const info = describeError(err);
        errorLine.textContent = info.detail ? info.title + '（' + info.detail + '）' : info.title;
        errorLine.classList.remove('hidden');
        submitBtn.disabled = false;
        submitBtn.textContent = original;
      }
    });

    document.addEventListener('keydown', onKeydown);
    document.body.appendChild(modal);
    const first = fieldEntries[0];
    if (first) first.focus();
    else submitBtn.focus();
  });
}

/** 二次确认（删除、轮换凭据等危险操作）。 */
export function confirmDialog(spec = {}) {
  return openDialog({
    title: spec.title || '确认操作',
    description: spec.description,
    body: spec.body,
    submitText: spec.confirmText || '确认',
    cancelText: spec.cancelText || '取消',
    danger: spec.danger !== false,
  }).then((values) => values !== null);
}

/** 只读提示。 */
export function alertDialog(spec = {}) {
  return openDialog({
    title: spec.title || '提示',
    description: spec.description,
    body: spec.body,
    xwide: spec.xwide,
    submitText: spec.okText || '知道了',
    cancelText: '',
  }).then(() => undefined);
}

export function closeAllDialogs() {
  for (const node of Array.from(document.querySelectorAll('.modal'))) {
    if (node.parentNode) node.parentNode.removeChild(node);
  }
}
