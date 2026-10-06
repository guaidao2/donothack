// web/assets/dom.js
// 职责：createElement 模板 helper、格式化、四种状态块、常用表单控件，以及 **payload 展示的唯一原语 renderCode**。
// 硬约束：所有文本写入走 textContent / createTextNode；本文件不含任何被门禁禁止的 DOM 写入 API。
//         任何视图都不许自己拼 HTML 字符串或自己建 <pre>，payload 一律调用 renderCode()。

export const SVG_NS = 'http://www.w3.org/2000/svg';

/** 把任意值转成可安全展示的文本（不参与任何解析）。 */
export function coerceText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  try {
    return JSON.stringify(value);
  } catch (err) {
    return String(value);
  }
}

function applyProps(node, props) {
  for (const key of Object.keys(props || {})) {
    const value = props[key];
    if (value === null || value === undefined) continue;
    if (key === 'class') node.setAttribute('class', coerceText(value));
    else if (key === 'text') node.textContent = coerceText(value);
    else if (key === 'attrs') {
      for (const name of Object.keys(value)) {
        const attrValue = value[name];
        if (attrValue === null || attrValue === undefined || attrValue === false) continue;
        node.setAttribute(name, coerceText(attrValue));
      }
    } else if (key === 'on') {
      for (const type of Object.keys(value)) node.addEventListener(type, value[type]);
    } else if (key === 'dataset') {
      for (const name of Object.keys(value)) node.dataset[name] = coerceText(value[name]);
    }
  }
}

function appendChildren(node, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false || child === true) continue;
    if (Array.isArray(child)) {
      appendChildren(node, child);
      continue;
    }
    if (child instanceof Node) node.appendChild(child);
    else node.appendChild(document.createTextNode(coerceText(child)));
  }
}

/** 创建元素：el('div', {class:'x', text:'y', attrs:{...}, on:{click:fn}}, ...children) */
export function el(tag, props, ...children) {
  const node = document.createElement(tag);
  applyProps(node, props);
  appendChildren(node, children);
  return node;
}

/** 创建 SVG 元素（图表手写 SVG 用）。 */
export function svgEl(tag, props, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  if (props && props.attrs) {
    for (const name of Object.keys(props.attrs)) {
      const value = props.attrs[name];
      if (value === null || value === undefined || value === false) continue;
      node.setAttribute(name, coerceText(value));
    }
  }
  if (props && props.text !== undefined && props.text !== null) node.textContent = coerceText(props.text);
  if (props && props.on) {
    for (const type of Object.keys(props.on)) node.addEventListener(type, props.on[type]);
  }
  appendChildren(node, children || []);
  return node;
}

/** 清空一个容器。 */
export function clear(node) {
  if (!node) return node;
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/** 用给定内容替换容器内容。 */
export function mount(node, ...children) {
  clear(node);
  appendChildren(node, children);
  return node;
}

export function textNode(value) {
  return document.createTextNode(coerceText(value));
}

/** 从对象里按候选键取第一个存在的值（支持 a.b 形式）；后端字段名尚未冻结时用它兜底。 */
export function pick(source, keys, fallback) {
  if (!source || typeof source !== 'object') return fallback;
  for (const key of keys) {
    const parts = String(key).split('.');
    let cursor = source;
    let ok = true;
    for (const part of parts) {
      if (cursor && typeof cursor === 'object' && part in cursor) cursor = cursor[part];
      else {
        ok = false;
        break;
      }
    }
    if (ok && cursor !== undefined && cursor !== null && cursor !== '') return cursor;
  }
  return fallback;
}

/** 列表类响应的容错取值：直接数组、或 {items|data|列表名} 包裹。 */
export function asArray(value, keys) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return [];
  const candidates = (keys || ['items', 'data', 'list', 'results', 'records']).concat([]);
  for (const key of candidates) {
    if (Array.isArray(value[key])) return value[key];
  }
  return [];
}

/** 把值渲染成"文本或节点"，供 kv 使用。 */
export function valueNode(value, fallback = '—') {
  if (value === null || value === undefined || value === '') return el('span', { class: 'faint', text: fallback });
  if (value instanceof Node) return value;
  return el('span', { text: coerceText(value) });
}

/* ── payload 展示：唯一原语 ─────────────────────────────────── */

/** 把任意 payload 值转成可打印文本。服务端已做 \xNN 可打印化，这里只兜底非字符串类型。 */
export function printableText(value) {
  if (value === null || value === undefined) return '(无)';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (err) {
    return String(value);
  }
}

async function copyText(value, trigger) {
  const original = trigger.textContent;
  let ok = false;
  try {
    if (globalThis.navigator && navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      ok = true;
    } else {
      const scratch = el('textarea', { attrs: { readonly: 'readonly' } });
      scratch.value = value;
      document.body.appendChild(scratch);
      scratch.select();
      ok = document.execCommand('copy');
      document.body.removeChild(scratch);
    }
  } catch (err) {
    ok = false;
  }
  trigger.textContent = ok ? '已复制' : '复制失败';
  globalThis.setTimeout(() => {
    trigger.textContent = original;
  }, 1400);
}

/**
 * renderCode —— payload / 代码文本的唯一展示通路。
 * 结构固定：<div.code><pre><code>textContent</code></pre></div>，绝不经过任何 HTML 解析。
 * @param {*} value 要展示的文本（payload、YAML、请求报文……）
 * @param {{label?:string, meta?:string, truncated?:boolean|number|string, tight?:boolean, copy?:boolean}} [opts]
 */
export function renderCode(value, opts = {}) {
  const print = printableText(value);
  const code = el('code', { text: print });
  const pre = el('pre', {}, code);

  const head = el(
    'div',
    { class: 'code__head' },
    el('span', { class: 'code__label', text: opts.label || 'CODE' }),
    opts.meta ? el('span', { class: 'code__meta', text: opts.meta }) : null
  );

  const actions = el('div', { class: 'code__actions' });
  if (opts.copy !== false) {
    actions.appendChild(
      button('复制', {
        tone: 'ghost',
        size: 'sm',
        title: '复制这段文本',
        onClick: (event) => copyText(print, event.currentTarget),
      })
    );
  }
  head.appendChild(actions);

  const box = el('div', { class: opts.tight ? 'code code--tight' : 'code' }, head, pre);

  if (opts.truncated) {
    const note =
      typeof opts.truncated === 'string'
        ? opts.truncated
        : '服务端已按上限截断，这里只是前一段可打印化结果。';
    box.appendChild(el('div', { class: 'code__truncated', text: note }));
  }
  return box;
}

/* ── 格式化 ─────────────────────────────────────────────────── */

const DASH = '—';

function toNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

export function fmtInt(value) {
  const n = toNumber(value);
  if (n === null) return DASH;
  const s = Math.round(n).toString();
  const neg = s.startsWith('-');
  const digits = neg ? s.slice(1) : s;
  return (neg ? '-' : '') + digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function fmtCompact(value) {
  const n = toNumber(value);
  if (n === null) return DASH;
  const abs = Math.abs(n);
  if (abs >= 1e9) return (n / 1e9).toFixed(abs >= 1e10 ? 0 : 1) + 'B';
  if (abs >= 1e6) return (n / 1e6).toFixed(abs >= 1e7 ? 0 : 1) + 'M';
  if (abs >= 1e4) return (n / 1e3).toFixed(0) + 'k';
  return fmtInt(n);
}

export function fmtFloat(value, digits = 1) {
  const n = toNumber(value);
  if (n === null) return DASH;
  return n.toFixed(digits);
}

export function fmtBytes(value) {
  const n = toNumber(value);
  if (n === null) return DASH;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = 0;
  while (Math.abs(v) >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return (i === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : 1)) + ' ' + units[i];
}

export function fmtMs(value) {
  const n = toNumber(value);
  if (n === null) return DASH;
  if (Math.abs(n) < 1) return n.toFixed(2) + ' ms';
  if (Math.abs(n) < 1000) return n.toFixed(1) + ' ms';
  return (n / 1000).toFixed(2) + ' s';
}

/** 秒 → 人类可读时长（运行时长、剩余时间）。 */
export function fmtSeconds(value) {
  const n = toNumber(value);
  if (n === null) return DASH;
  const sec = Math.max(0, Math.round(n));
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec / 60);
  if (m < 60) return m + 'm' + (sec % 60 ? ' ' + (sec % 60) + 's' : '');
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h' + (m % 60 ? ' ' + (m % 60) + 'm' : '');
  const d = Math.floor(h / 24);
  return d + 'd' + (h % 24 ? ' ' + (h % 24) + 'h' : '');
}

export function fmtPercent(ratio, digits = 1) {
  const n = toNumber(ratio);
  if (n === null) return DASH;
  return (n * 100).toFixed(digits) + '%';
}

export function fmtScore(value) {
  const n = toNumber(value);
  if (n === null) return DASH;
  return (n > 0 ? '+' : '') + n;
}

function pad2(n) {
  return n < 10 ? '0' + n : String(n);
}

export function fmtTime(value, fallback = DASH) {
  if (!value) return fallback;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return coerceText(value) || fallback;
  return (
    d.getFullYear() +
    '-' +
    pad2(d.getMonth() + 1) +
    '-' +
    pad2(d.getDate()) +
    ' ' +
    pad2(d.getHours()) +
    ':' +
    pad2(d.getMinutes()) +
    ':' +
    pad2(d.getSeconds())
  );
}

export function fmtRelative(value) {
  if (!value) return DASH;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return coerceText(value);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 0) return '刚刚';
  if (diff < 10) return '刚刚';
  if (diff < 60) return Math.floor(diff) + ' 秒前';
  if (diff < 3600) return Math.floor(diff / 60) + ' 分钟前';
  if (diff < 86400) return Math.floor(diff / 3600) + ' 小时前';
  if (diff < 86400 * 30) return Math.floor(diff / 86400) + ' 天前';
  return fmtTime(d);
}

export function fmtBool(value) {
  if (value === null || value === undefined) return DASH;
  return value ? '是' : '否';
}

/* ── 基础块 ─────────────────────────────────────────────────── */

export function button(label, opts = {}) {
  const cls = ['btn'];
  if (opts.tone) cls.push('btn--' + opts.tone);
  if (opts.size === 'sm') cls.push('btn--sm');
  if (opts.block) cls.push('btn--block');
  const node = el('button', { class: cls.join(' '), text: label, attrs: { type: opts.type || 'button' } });
  if (opts.title) node.setAttribute('title', opts.title);
  if (opts.disabled) node.disabled = true;
  if (opts.onClick) node.addEventListener('click', opts.onClick);
  return node;
}

export function linkButton(label, href, opts = {}) {
  const cls = ['btn'];
  if (opts.tone) cls.push('btn--' + opts.tone);
  if (opts.size === 'sm') cls.push('btn--sm');
  const attrs = { href: href };
  if (opts.download) attrs.download = opts.download === true ? '' : opts.download;
  if (opts.target) attrs.target = opts.target;
  if (opts.title) attrs.title = opts.title;
  return el('a', { class: cls.join(' '), text: label, attrs: attrs });
}

export function badge(text, tone = 'neutral', opts = {}) {
  const cls = ['badge', 'badge--' + tone];
  if (opts.block) cls.push('badge--block');
  const node = el('span', { class: cls.join(' '), text: text });
  if (opts.title) node.setAttribute('title', opts.title);
  return node;
}

export function pill(text) {
  return el('span', { class: 'pill', text: text });
}

export function pillList(items) {
  const wrap = el('div', { class: 'pill-list' });
  for (const item of items || []) wrap.appendChild(pill(item));
  return wrap;
}

export function sectionTitle(text) {
  return el('div', { class: 'section-title', text: text });
}

export function banner(tone, title, body, actions) {
  return el(
    'div',
    { class: 'banner banner--' + tone },
    el(
      'div',
      { class: 'banner__body' },
      title ? el('div', { class: 'banner__title', text: title }) : null,
      body || null
    ),
    actions && actions.length ? el('div', { class: 'banner__actions' }, actions) : null
  );
}

export function card(spec = {}) {
  const head =
    spec.title || spec.hint || spec.actions
      ? el(
          'div',
          { class: 'card__head' },
          spec.title ? el('span', { class: 'card__title', text: spec.title }) : null,
          spec.hint ? el('span', { class: 'card__hint', text: spec.hint }) : null,
          spec.actions && spec.actions.length ? el('div', { class: 'card__actions' }, spec.actions) : null
        )
      : null;
  const body = el('div', { class: spec.flush ? 'card__body card__body--flush' : 'card__body' }, spec.body || null);
  return el('div', { class: spec.class ? 'card ' + spec.class : 'card' }, head, body);
}

export function pageHeader(title, opts = {}) {
  return el(
    'div',
    { class: 'page__head' },
    el(
      'div',
      {},
      el('div', { class: 'page__title', text: title }),
      opts.subtitle ? el('div', { class: 'page__sub', text: opts.subtitle }) : null
    ),
    opts.actions && opts.actions.length ? el('div', { class: 'page__actions' }, opts.actions) : null
  );
}

export function toolbar(...children) {
  return el('div', { class: 'toolbar' }, children);
}

export function kvList(entries) {
  const node = el('div', { class: 'kv' });
  for (const entry of entries || []) {
    if (!entry) continue;
    node.appendChild(el('div', { class: 'kv__k', text: entry.k }));
    const valueNode = el('div', { class: 'kv__v' });
    if (entry.v === null || entry.v === undefined) valueNode.textContent = DASH;
    else if (entry.v instanceof Node) valueNode.appendChild(entry.v);
    else valueNode.textContent = coerceText(entry.v);
    node.appendChild(valueNode);
  }
  return node;
}

export function rankList(items, opts = {}) {
  const wrap = el('div', { class: 'rank' });
  const list = items || [];
  const max = list.reduce((acc, item) => Math.max(acc, toNumber(item.value) || 0), 0);
  for (const item of list) {
    const value = toNumber(item.value) || 0;
    const ratio = max > 0 ? value / max : 0;
    const row = el(
      'div',
      { class: 'rank__row' },
      el('span', { class: 'rank__key truncate', text: item.label, attrs: { title: item.title || item.label } }),
      el('span', { class: 'rank__val num', text: opts.format ? opts.format(item.value) : fmtInt(item.value) })
    );
    row.appendChild(barBar(ratio));
    wrap.appendChild(row);
  }
  return wrap;
}

/** 横向比例条：用手写 SVG 的百分比几何属性，不用任何行内 style。 */
function barBar(ratio) {
  const clamped = Math.max(0, Math.min(1, Number(ratio) || 0));
  return svgEl(
    'svg',
    {
      attrs: {
        class: 'rank__bar',
        viewBox: '0 0 100 3',
        preserveAspectRatio: 'none',
        'aria-hidden': 'true',
        focusable: 'false',
      },
    },
    svgEl('rect', { attrs: { class: 'rank__bar-track', x: 0, y: 0, width: '100%', height: 3, rx: 1.5 } }),
    svgEl('rect', {
      attrs: {
        class: 'rank__bar-fill',
        x: 0,
        y: 0,
        width: clamped > 0 ? (clamped * 100).toFixed(2) + '%' : '0',
        height: 3,
        rx: 1.5,
      },
    })
  );
}

export function meter(spec) {
  const value = toNumber(spec.value) || 0;
  const max = toNumber(spec.max);
  const ratio = max && max > 0 ? Math.min(1, value / max) : 0;
  const tone = ratio >= 0.9 ? 'meter__fill--danger' : ratio >= 0.75 ? 'meter__fill--warn' : '';
  return el(
    'div',
    { class: 'meter' },
    svgEl(
      'svg',
      {
        attrs: {
          class: 'meter__svg',
          viewBox: '0 0 100 6',
          preserveAspectRatio: 'none',
          role: 'img',
          'aria-label': spec.label || fmtInt(value),
        },
      },
      svgEl('rect', { attrs: { class: 'meter__track-rect', x: 0, y: 0, width: '100%', height: 6, rx: 3 } }),
      svgEl('rect', {
        attrs: {
          class: 'meter__fill-rect ' + tone,
          x: 0,
          y: 0,
          width: ratio > 0 ? (ratio * 100).toFixed(2) + '%' : '0',
          height: 6,
          rx: 3,
        },
      })
    ),
    el('div', {
      class: 'meter__label',
      text: spec.label || (max ? fmtInt(value) + ' / ' + fmtInt(max) : fmtInt(value)),
    })
  );
}

export function tabs(items, opts = {}) {
  const wrap = el('div', { class: 'tabs', attrs: { role: 'tablist' } });
  for (const item of items) {
    const active = item.key === opts.active;
    wrap.appendChild(
      el('button', {
        class: 'tabs__item',
        text: item.label,
        attrs: { type: 'button', role: 'tab', 'aria-selected': active ? 'true' : 'false' },
        on: {
          click: () => {
            if (!active && opts.onSelect) opts.onSelect(item.key);
          },
        },
      })
    );
  }
  return wrap;
}

export function field(label, control, hint) {
  return el(
    'label',
    { class: 'field' },
    el('span', { class: 'field__label', text: label }),
    control,
    hint ? el('span', { class: 'field__hint', text: hint }) : null
  );
}

export function textInput(opts = {}) {
  const attrs = {
    type: opts.type || 'text',
    placeholder: opts.placeholder || '',
    autocomplete: opts.autocomplete || 'off',
    spellcheck: 'false',
  };
  if (opts.name) attrs.name = opts.name;
  const node = el('input', { attrs: attrs, class: opts.class });
  if (opts.value !== undefined && opts.value !== null) node.value = String(opts.value);
  if (opts.disabled) node.disabled = true;
  if (opts.onInput) node.addEventListener('input', () => opts.onInput(node.value, node));
  if (opts.onChange) node.addEventListener('change', () => opts.onChange(node.value, node));
  if (opts.onEnter) {
    node.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') opts.onEnter(node.value, node);
    });
  }
  return node;
}

export function textArea(opts = {}) {
  const node = el('textarea', { attrs: { rows: String(opts.rows || 8), spellcheck: 'false', placeholder: opts.placeholder || '' } });
  if (opts.value) node.value = String(opts.value);
  if (opts.onInput) node.addEventListener('input', () => opts.onInput(node.value, node));
  return node;
}

export function selectInput(options, opts = {}) {
  const node = el('select', {});
  if (opts.disabled) node.disabled = true;
  for (const option of options || []) {
    const value = typeof option === 'string' ? option : option.value;
    const label =
      typeof option === 'string' ? option : option.label === undefined ? String(option.value) : option.label;
    const node2 = el('option', { text: label, attrs: { value: String(value) } });
    if (String(value) === String(opts.value)) node2.selected = true;
    node.appendChild(node2);
  }
  if (opts.onChange) node.addEventListener('change', () => opts.onChange(node.value));
  return node;
}

export function checkbox(labelText, opts = {}) {
  const box = el('input', { attrs: { type: 'checkbox' } });
  box.checked = !!opts.checked;
  if (opts.disabled) box.disabled = true;
  if (opts.onChange) box.addEventListener('change', () => opts.onChange(box.checked));
  return el('label', { class: 'field field--inline' }, box, el('span', { text: labelText }));
}

/* ── 四种状态 ───────────────────────────────────────────────── */

export function stateBlock(spec = {}) {
  const node = el(
    'div',
    { class: 'state' + (spec.tone === 'error' ? ' state--error' : '') + (spec.inline ? ' state--inline' : '') },
    spec.spinner ? el('div', { class: 'spinner' }) : null,
    spec.title ? el('div', { class: 'state__title', text: spec.title }) : null,
    spec.hint ? el('div', { class: 'state__hint', text: spec.hint }) : null,
    spec.detail ? el('div', { class: 'state__detail', text: spec.detail }) : null
  );
  if (spec.actions && spec.actions.length) {
    node.appendChild(el('div', { class: 'row' }, spec.actions));
  }
  return node;
}

export function loadingBlock(title = '加载中…') {
  return stateBlock({ spinner: true, title: title });
}

export function emptyState(spec = {}) {
  const title = spec.title || '暂无数据';
  const hint = spec.hint || '当前查询范围内没有记录。';
  const node = stateBlock({ title: title, hint: spec.detail ? hint : hint });
  if (spec.detail) node.appendChild(el('div', { class: 'state__detail', text: spec.detail }));
  if (spec.actions && spec.actions.length) node.appendChild(el('div', { class: 'row' }, spec.actions));
  return node;
}

export function describeError(err) {
  if (!err) return { title: '未知错误', detail: '', code: '' };
  const code = err.code || '';
  const status = err.status ? 'HTTP ' + err.status : '';
  const title = err.message || '请求失败';
  const parts = [];
  if (code) parts.push('code=' + code);
  if (status) parts.push(status);
  if (err.detail) parts.push(coerceText(err.detail));
  return { title: title, detail: parts.join(' · '), code: code };
}

export function errorState(err, spec = {}) {
  const info = describeError(err);
  const actions = [];
  if (spec.onRetry) actions.push(button(spec.retryLabel || '重试', { size: 'sm', onClick: spec.onRetry }));
  return stateBlock({
    tone: 'error',
    title: spec.title || info.title,
    hint: spec.hint || '这个视图需要后端 API；如果后端还没实现，这里会明确报错而不是显示假数据。',
    detail: info.detail,
    actions: actions,
  });
}

export function unauthorizedState(spec = {}) {
  const actions = [];
  if (spec.onRelogin) actions.push(button('重新登录', { tone: 'primary', size: 'sm', onClick: spec.onRelogin }));
  return stateBlock({
    tone: 'warn',
    title: spec.title || '需要认证',
    hint:
      spec.hint ||
      '会话不存在或已过期（HTTP 401）。请重新登录；控制台不会在未认证状态下展示任何业务数据。',
    actions: actions,
  });
}

/**
 * 统一的资源状态渲染：
 *   loading/idle → 加载态；unauthenticated → 需要认证；error → 错误 + 重试；ready 且空 → 空状态；ready → render(data)。
 */
export function renderState(container, state, spec = {}) {
  clear(container);
  const status = state ? state.status : 'idle';

  if (status === 'idle' || status === 'loading') {
    container.appendChild(loadingBlock(spec.loadingTitle || '加载中…'));
    return;
  }
  if (status === 'unauthenticated') {
    container.appendChild(unauthorizedState(spec.unauthorized));
    return;
  }
  if (status === 'error') {
    container.appendChild(errorState(state.error, spec));
    return;
  }

  const data = state ? state.data : null;
  const empty = spec.isEmpty ? spec.isEmpty(data) : defaultIsEmpty(data);
  if (empty) {
    container.appendChild(emptyState(spec.empty || {}));
    return;
  }
  if (!spec.render) {
    container.appendChild(emptyState(spec.empty || {}));
    return;
  }
  const rendered = spec.render(data);
  appendChildren(container, Array.isArray(rendered) ? rendered : [rendered]);
}

function defaultIsEmpty(data) {
  if (data === null || data === undefined) return true;
  if (Array.isArray(data)) return data.length === 0;
  return false;
}

/** 把 renderState 包成一个订阅回调，视图用起来就是一行。 */
export function bindState(container, resource, spec = {}) {
  const paint = (state) => renderState(container, state, spec);
  paint(resource.get());
  return resource.subscribe(paint);
}
