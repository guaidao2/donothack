// web/assets/views/audit.js
// 职责：操作审计页 —— "谁在什么时候改了什么"。列表 + 详情（含 diff 与前后快照版本）。
// 取数：GET /console-audit（cursor 分页）。
// 约束：审计条目里的 diff / 原文一律用 renderCode 展示，不参与任何结构解析。

import { api } from '../api.js';
import {
  el,
  card,
  pageHeader,
  badge,
  button,
  toolbar,
  textInput,
  selectInput,
  kvList,
  renderCode,
  pick,
  asArray,
  fmtTime,
  coerceText,
} from '../dom.js';
import { renderTable } from '../components/table.js';
import { openDrawer } from '../components/drawer.js';

const RESULT_TONE = {
  ok: 'ok',
  success: 'ok',
  denied: 'warn',
  reject: 'warn',
  rejected: 'warn',
  error: 'danger',
  failed: 'danger',
  fail: 'danger',
};

const RANGE_OPTIONS = [
  { value: '1h', label: '最近 1 小时' },
  { value: '24h', label: '最近 24 小时' },
  { value: '7d', label: '最近 7 天' },
];

function resultBadge(result) {
  if (result === null || result === undefined || result === '') return badge('—', 'neutral');
  const key = String(result).toLowerCase();
  return badge(String(result), RESULT_TONE[key] || 'neutral');
}

function versionPair(row) {
  const before = pick(row, ['ruleset_version_before', 'version_before'], null);
  const after = pick(row, ['ruleset_version_after', 'version_after'], null);
  if (before === null && after === null) return el('span', { class: 'faint', text: '—' });
  return el(
    'span',
    { class: 'mono xs' },
    el('span', { text: before === null ? '—' : shortHash(before) }),
    el('span', { class: 'faint', text: ' → ' }),
    el('span', { text: after === null ? '—' : shortHash(after) })
  );
}

function shortHash(value) {
  const text = String(value);
  return text.length > 18 ? text.slice(0, 18) + '…' : text;
}

function diffNode(diff) {
  if (diff === null || diff === undefined) {
    return el('div', { class: 'chart__empty', text: '这条审计记录没有 diff。' });
  }
  const wrap = el('div', { class: 'diff' });
  if (typeof diff === 'string') {
    for (const line of diff.split('\n')) {
      const cls =
        line.startsWith('+') ? 'diff__line diff__line--add' : line.startsWith('-') ? 'diff__line diff__line--del' : 'diff__line';
      wrap.appendChild(el('div', { class: cls, text: line }));
    }
    return wrap;
  }
  if (Array.isArray(diff)) {
    for (const line of diff) {
      const text = typeof line === 'string' ? line : coerceText(pick(line, ['text', 'line', 'value'], line));
      const kind = typeof line === 'object' && line ? String(pick(line, ['kind', 'type', 'op'], '')) : '';
      const cls =
        kind === 'add' || text.startsWith('+')
          ? 'diff__line diff__line--add'
          : kind === 'del' || kind === 'remove' || text.startsWith('-')
          ? 'diff__line diff__line--del'
          : 'diff__line';
      wrap.appendChild(el('div', { class: cls, text: text }));
    }
    return wrap;
  }
  return renderCode(diff, { label: 'DIFF' });
}

function openAuditDetail(row) {
  const body = el(
    'div',
    { class: 'stack-2' },
    kvList(
      [
        { k: '时间', v: pick(row, ['ts', 'time', 'timestamp'], null) === null ? null : fmtTime(pick(row, ['ts', 'time', 'timestamp'])) },
        { k: '操作人', v: pick(row, ['actor', 'user', 'username'], null) },
        { k: '来源 IP', v: pick(row, ['src_ip', 'client_ip', 'ip'], null) === null ? null : el('span', { class: 'mono', text: String(pick(row, ['src_ip', 'client_ip', 'ip'])) }) },
        { k: '动作', v: pick(row, ['action', 'op', 'event'], null) === null ? null : el('span', { class: 'mono', text: String(pick(row, ['action', 'op', 'event'])) }) },
        { k: '目标', v: pick(row, ['target', 'object', 'subject'], null) === null ? null : el('span', { class: 'mono wrap-anywhere', text: String(pick(row, ['target', 'object', 'subject'])) }) },
        { k: '结果', v: resultBadge(pick(row, ['result', 'status', 'outcome'])) },
        { k: '规则集版本', v: versionPair(row) },
        { k: '错误', v: pick(row, ['error', 'message', 'detail'], null) === null ? null : renderCode(pick(row, ['error', 'message', 'detail']), { label: '错误', tight: true }) },
      ].filter((item) => item.v !== null && item.v !== undefined)
    ),
    el('div', { class: 'stack-2' }, el('div', { class: 'section-title', text: 'diff' }), diffNode(pick(row, ['diff', 'changes'], null))),
    el('div', { class: 'stack-2' }, el('div', { class: 'section-title', text: '原始记录' }), renderCode(row, { label: 'JSON' }))
  );

  openDrawer({
    title: '审计记录',
    subtitle: String(pick(row, ['action', 'op'], '')),
    body: body,
  });
}

export function render(container) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  const filters = { range: '24h', actor: '', action: '', result: '', target: '' };
  const tableHost = el('div');
  let rows = [];
  let nextCursor = '';
  let state = { status: 'loading', data: null, error: null };

  function params() {
    const out = { range: filters.range };
    if (filters.actor) out.actor = filters.actor;
    if (filters.action) out.action = filters.action;
    if (filters.result) out.result = filters.result;
    if (filters.target) out.target = filters.target;
    return out;
  }

  function paint() {
    renderTable(tableHost, state, {
      columns: [
        { key: 'ts', label: '时间', render: (row) => el('span', { class: 'mono xs', text: fmtTime(pick(row, ['ts', 'time', 'timestamp'])) }) },
        { key: 'actor', label: '操作人', render: (row) => el('span', { text: String(pick(row, ['actor', 'user', 'username'], '—')) }) },
        { key: 'src_ip', label: '来源 IP', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['src_ip', 'client_ip', 'ip'], '—')) }) },
        { key: 'action', label: '动作', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['action', 'op', 'event'], '—')) }) },
        { key: 'target', label: '目标', wrap: true, render: (row) => el('span', { class: 'mono', text: String(pick(row, ['target', 'object', 'subject'], '—')) }) },
        { key: 'result', label: '结果', render: (row) => resultBadge(pick(row, ['result', 'status', 'outcome'])) },
        { key: 'version', label: '规则集版本', render: (row) => versionPair(row) },
      ],
      empty: {
        title: '当前条件下没有审计记录',
        hint: '审计是"谁改了什么"的独立流水；如果刚部署过还没有写操作，这里就是空的。',
      },
      loadingTitle: '读取操作审计…',
      onRetry: () => load(true),
      onRowClick: (row) => openAuditDetail(row),
      hasMoreOf: (data) => !!(data && data.next_cursor),
      onMore: () => load(false),
      note: '点击行查看 diff 与前后快照版本',
    });
  }

  async function load(reset) {
    if (reset) {
      rows = [];
      nextCursor = '';
    }
    state = { status: 'loading', data: null, error: null };
    paint();
    try {
      const query = params();
      if (!reset && nextCursor) query.cursor = nextCursor;
      const payload = await api.consoleAudit(query);
      const items = asArray(payload, ['audit', 'items', 'data', 'records']);
      rows = reset ? items : rows.concat(items);
      nextCursor = pick(payload, ['next_cursor', 'cursor'], '') || '';
      const total = Number(pick(payload, ['total', 'count'], NaN));
      state = {
        status: 'ready',
        data: { items: rows, next_cursor: nextCursor, total: Number.isFinite(total) ? total : undefined, partial: !!pick(payload, ['partial', 'truncated'], false) },
        error: null,
      };
    } catch (err) {
      state = { status: err && err.code === 'unauthenticated' ? 'unauthenticated' : 'error', data: null, error: err };
    }
    paint();
  }

  page.appendChild(
    pageHeader('操作审计', {
      subtitle: '控制台与 CLI 的写操作都记在这里：actor、src_ip、action、target、diff、前后快照版本',
      actions: [button('刷新', { size: 'sm', onClick: () => load(true) })],
    })
  );

  page.appendChild(
    card({
      flush: true,
      body: [
        toolbar(
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '时间范围' }), selectInput(RANGE_OPTIONS, { value: filters.range, onChange: (v) => { filters.range = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '操作人' }), textInput({ value: filters.actor, placeholder: '精确匹配 actor', onInput: (v) => { filters.actor = v; }, onEnter: (v) => { filters.actor = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '动作' }), textInput({ value: filters.action, placeholder: '如 rules.disable', onInput: (v) => { filters.action = v; }, onEnter: (v) => { filters.action = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '目标' }), textInput({ value: filters.target, placeholder: '如 SQLI-942100', onInput: (v) => { filters.target = v; }, onEnter: (v) => { filters.target = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '结果' }), textInput({ value: filters.result, placeholder: 'ok / denied / error', onInput: (v) => { filters.result = v; }, onEnter: (v) => { filters.result = v; load(true); } })),
          button('查询', { size: 'sm', tone: 'primary', onClick: () => load(true) })
        ),
        tableHost,
      ],
    })
  );

  load(true);

  return () => {};
}
