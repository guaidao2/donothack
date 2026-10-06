// web/assets/components/table.js
// 职责：列表页统一表格 —— 列定义、右对齐数字列、行点击进详情、空状态、加载/错误状态、翻页脚。
// 约束：单元格内容只经 textContent 写入；需要富结构时由列的 render 返回已建好的节点。

import {
  el,
  clear,
  emptyState,
  errorState,
  loadingBlock,
  unauthorizedState,
  coerceText,
} from '../dom.js';

function cellNode(column, row) {
  const tag = 'td';
  const classes = [];
  if (column.align === 'right') classes.push('col-num');
  if (column.wrap) classes.push('is-wrap');
  if (column.class) classes.push(column.class);

  const node = el(tag, { class: classes.join(' ') });
  if (column.width) node.setAttribute('data-w', String(column.width));

  let content = null;
  if (typeof column.render === 'function') content = column.render(row);
  else content = row ? row[column.key] : null;

  if (content === null || content === undefined) node.textContent = '—';
  else if (content instanceof Node) node.appendChild(content);
  else if (Array.isArray(content)) {
    for (const item of content) {
      if (item instanceof Node) node.appendChild(item);
      else node.appendChild(document.createTextNode(coerceText(item)));
    }
  } else node.textContent = coerceText(content);
  return node;
}

/**
 * 构建表格主体（不含状态处理）。
 * @param {{columns:Array, rows:Array, onRowClick?:Function, rowTitle?:Function}} spec
 */
export function tableNode(spec) {
  const thead = el('thead');
  const headRow = el('tr');
  for (const column of spec.columns || []) {
    const th = el('th', { text: column.label === undefined ? column.key : column.label });
    if (column.align === 'right') th.classList.add('col-num');
    if (column.wrap) th.classList.add('is-wrap');
    if (column.width) th.setAttribute('data-w', String(column.width));
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);

  const tbody = el('tbody');
  for (const row of spec.rows || []) {
    const tr = el('tr');
    if (spec.onRowClick) {
      tr.classList.add('is-clickable');
      tr.setAttribute('tabindex', '0');
      tr.setAttribute('role', 'button');
      tr.addEventListener('click', () => spec.onRowClick(row));
      tr.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          spec.onRowClick(row);
        }
      });
    }
    if (spec.rowTitle && typeof spec.rowTitle === 'function') {
      const title = spec.rowTitle(row);
      if (title) tr.setAttribute('title', title);
    }
    for (const column of spec.columns || []) tr.appendChild(cellNode(column, row));
    tbody.appendChild(tr);
  }

  return el('div', { class: 'table-wrap' }, el('table', { class: 'table' }, thead, tbody));
}

/** 表格脚：已显示多少条 / 是否还有下一页。cursor 分页不做 offset。 */
export function tableFoot(spec) {
  const parts = [];
  if (typeof spec.total === 'number') {
    parts.push('共 ' + spec.total + ' 条');
  } else {
    parts.push('已显示 ' + (spec.rows || []).length + ' 条');
  }
  if (spec.note) parts.push(spec.note);
  if (spec.partial) parts.push('服务端查询超时，返回的是部分结果');
  const foot = el('div', { class: 'table__foot' }, el('span', { text: parts.join(' · ') }));
  if (spec.hasMore && spec.onMore) {
    foot.appendChild(
      el(
        'button',
        {
          class: 'btn btn--sm',
          text: '加载更多',
          attrs: { type: 'button' },
          on: { click: spec.onMore },
        }
      )
    );
  }
  return foot;
}

function isEmptyRows(data, spec) {
  if (spec.isEmpty) return spec.isEmpty(data);
  if (!data) return true;
  if (Array.isArray(data)) return data.length === 0;
  if (Array.isArray(data.items)) return data.items.length === 0;
  return false;
}

function rowsOf(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  if (Array.isArray(data.items)) return data.items;
  if (Array.isArray(data.events)) return data.events;
  return [];
}

/**
 * 统一渲染：容器内容按资源状态替换。
 * @param {HTMLElement} container
 * @param {{status:string, data:*, error:*}} state
 * @param {object} spec 列定义 + empty/note/onRetry/onRowClick/total/hasMore/onMore
 */
export function renderTable(container, state, spec = {}) {
  clear(container);
  const status = state ? state.status : 'idle';

  if (status === 'idle' || status === 'loading') {
    container.appendChild(loadingBlock(spec.loadingTitle || '加载列表…'));
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
  if (isEmptyRows(data, spec)) {
    container.appendChild(emptyState(spec.empty || {}));
    return;
  }

  const rows = spec.rowsOf ? spec.rowsOf(data) : rowsOf(data);
  if (rows.length === 0) {
    container.appendChild(emptyState(spec.empty || {}));
    return;
  }

  container.appendChild(
    tableNode({
      columns: spec.columns,
      rows: rows,
      onRowClick: spec.onRowClick,
      rowTitle: spec.rowTitle,
    })
  );
  container.appendChild(
    tableFoot({
      rows: rows,
      total: spec.totalOf ? spec.totalOf(data) : data && typeof data.total === 'number' ? data.total : undefined,
      note: spec.note,
      partial: !!(data && data.partial),
      hasMore: spec.hasMoreOf ? spec.hasMoreOf(data) : !!(data && data.next_cursor),
      onMore: spec.onMore,
    })
  );
}
