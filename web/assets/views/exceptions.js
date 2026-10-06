// web/assets/views/exceptions.js
// 职责：例外与白名单页 —— 例外规则（路径/规则/IP）与 IP 黑白名单的增删改查。
// 取数：GET/POST/PATCH/DELETE /exceptions、GET/POST/DELETE /ip-lists。
// 重点：reason 与 expires 是强制字段；已过期或即将过期的例外在页面顶部显著提示，防止"临时例外变永久后门"。

import { api, warningsOf } from '../api.js';
import {
  el,
  card,
  pageHeader,
  badge,
  banner,
  button,
  toolbar,
  tabs,
  selectInput,
  pick,
  asArray,
  fmtInt,
  fmtTime,
} from '../dom.js';
import { renderTable } from '../components/table.js';
import { openDialog, confirmDialog } from '../components/modal.js';
import { notify, toastError, showWarnings } from '../components/toast.js';

const EXCEPTION_KIND_OPTIONS = [
  { value: 'path', label: '路径例外' },
  { value: 'rule', label: '规则例外' },
  { value: 'ip', label: 'IP / CIDR 例外' },
];

const LIST_KIND_OPTIONS = [
  { value: 'white', label: '白名单（直通）' },
  { value: 'black', label: '黑名单（直接拦）' },
];

const STATE_OPTIONS = [
  { value: '', label: '全部' },
  { value: 'active', label: '有效' },
  { value: 'expired', label: '已过期' },
];

/** 到期状态：后端给了就以它为准，否则按 expires 本地判断（只用于展示提示）。 */
function expiryInfo(item) {
  const explicit = pick(item, ['expired', 'is_expired'], null);
  const expires = pick(item, ['expires', 'expires_at', 'expire_at', 'until'], null);
  let expired = explicit === true;
  let soon = false;
  if (expires) {
    const t = new Date(expires).getTime();
    if (Number.isFinite(t)) {
      if (!expired) expired = t <= Date.now();
      soon = !expired && t - Date.now() < 24 * 3600 * 1000;
    }
  }
  return { expires: expires, expired: expired, soon: soon, hasExpiry: !!expires };
}

/** 距离到期的可读时长（只用于展示）。 */
function fmtUntil(value) {
  const t = new Date(value).getTime();
  if (!Number.isFinite(t)) return '—';
  const diff = Math.max(0, t - Date.now()) / 1000;
  if (diff < 3600) return Math.max(1, Math.ceil(diff / 60)) + ' 分钟';
  if (diff < 86400) return Math.floor(diff / 3600) + ' 小时';
  return Math.floor(diff / 86400) + ' 天';
}

function expiryBadge(item) {
  const info = expiryInfo(item);
  if (!info.hasExpiry) return badge('无到期时间', 'danger', { title: '没有 expires 字段的例外是永久后门，应当立即补上' });
  if (info.expired) return badge('已过期', 'neutral', { title: '已过期，不会生效：' + fmtTime(info.expires) });
  if (info.soon) return badge('即将到期', 'warn', { title: fmtTime(info.expires) });
  return badge(fmtUntil(info.expires) + '后到期', 'ok', { title: fmtTime(info.expires) });
}

function expiredBanner(items) {
  const expired = items.filter((item) => expiryInfo(item).expired);
  const soon = items.filter((item) => {
    const info = expiryInfo(item);
    return !info.expired && info.soon;
  });
  if (expired.length === 0 && soon.length === 0) return null;
  const parts = [];
  if (expired.length > 0) parts.push(expired.length + ' 条已过期（当前不生效，建议清理）');
  if (soon.length > 0) parts.push(soon.length + ' 条将在 24 小时内到期');
  return banner('warn', parts.join('；'), el('div', {
    class: 'sm',
    text: '例外必须带 reason 与 expires，到期自动失效 —— 这是防止"临时例外变永久后门"的硬约束。',
  }));
}

/* ── 例外规则 ───────────────────────────────────────────────── */

function renderExceptionsTab(host, ctx) {
  const state = { status: 'loading', data: null, error: null };
  const tableHost = el('div');
  const bannerHost = el('div');
  const filters = { state: '' };

  function paint() {
    renderTable(tableHost, state, {
      columns: [
        { key: 'kind', label: '类型', render: (row) => el('span', { text: String(pick(row, ['kind', 'type', 'scope'], '—')) }) },
        {
          key: 'value',
          label: '匹配值',
          wrap: true,
          render: (row) => {
            const value = String(pick(row, ['value', 'pattern', 'path', 'target', 'cidr'], '—'));
            return el('span', { class: 'mono wrap-anywhere', text: value });
          },
        },
        { key: 'reason', label: '原因（强制）', wrap: true, render: (row) => el('span', { class: 'sm', text: String(pick(row, ['reason', 'note', 'comment'], '—')) }) },
        { key: 'expires', label: '到期', render: (row) => expiryBadge(row) },
        { key: 'hits', label: '最近命中次数', align: 'right', render: (row) => el('span', { class: 'num', text: fmtInt(pick(row, ['hits', 'hit_count', 'hits_recent'], null)) }) },
        { key: 'created', label: '创建', render: (row) => el('span', { class: 'xs muted', text: fmtTime(pick(row, ['created_at', 'created', 'ts'], null)) }) },
        {
          key: 'actions',
          label: '操作',
          render: (row) => {
            const id = pick(row, ['id', 'uid', 'key'], null);
            if (!id) return el('span', { class: 'faint', text: '无 id' });
            const wrap = el('div', { class: 'row' });
            wrap.appendChild(
              button('续期/改理由', {
                size: 'sm',
                onClick: (event) => {
                  event.stopPropagation();
                  editException(id, row, load);
                },
              })
            );
            wrap.appendChild(
              button('删除', {
                size: 'sm',
                tone: 'danger',
                onClick: (event) => {
                  event.stopPropagation();
                  removeException(id, row, load);
                },
              })
            );
            return wrap;
          },
        },
      ],
      empty: {
        title: '当前没有例外',
        hint: filters.state ? '换个状态筛选看看。' : '例外是"放行"的显式授权；没有例外说明所有请求都走规则判定。',
      },
      loadingTitle: '读取例外列表…',
      onRetry: () => load(),
      note: '一条从来不命中的例外就是该删的',
    });
  }

  async function load() {
    state = { status: 'loading', data: null, error: null };
    paint();
    try {
      const query = {};
      if (filters.state) query.state = filters.state;
      const payload = await api.exceptions(query);
      const items = asArray(payload, ['exceptions', 'items', 'data']);
      const total = Number(pick(payload, ['total', 'count'], NaN));
      state = { status: 'ready', data: { items: items, total: Number.isFinite(total) ? total : undefined }, error: null };
      bannerHost.replaceChildren();
      const node = expiredBanner(items);
      if (node) bannerHost.appendChild(node);
    } catch (err) {
      state = { status: err && err.code === 'unauthenticated' ? 'unauthenticated' : 'error', data: null, error: err };
      bannerHost.replaceChildren();
    }
    paint();
  }

  async function createException() {
    const values = await openDialog({
      title: '新增例外',
      description: 'reason 与 expires 是强制字段：例外必须能解释、必须会过期。',
      fields: [
        { name: 'kind', label: '类型', type: 'select', options: EXCEPTION_KIND_OPTIONS, value: 'path' },
        { name: 'value', label: '匹配值', placeholder: '/admin/* 或 SQLI-942100 或 203.0.113.7/32', required: true },
        { name: 'reason', label: '原因', placeholder: '谁、为什么、工单号', required: true },
        { name: 'expires', label: '到期时间', type: 'datetime-local', required: true },
        { name: 'note', label: '备注', placeholder: '可选' },
      ],
      submitText: '创建',
      danger: false,
      onSubmit: async (form) => {
        const body = {
          kind: form.kind,
          value: form.value,
          reason: form.reason,
          expires: form.expires,
        };
        if (form.note) body.note = form.note;
        const result = await api.createException(body);
        showWarnings(warningsOf(result));
        notify.ok('例外已创建' + (result && result.snapshot_version ? '（快照 ' + result.snapshot_version + '）' : ''));
        await load();
      },
    });
    return values;
  }

  async function editException(id, row, refresh) {
    const info = expiryInfo(row);
    await openDialog({
      title: '修改例外到期 / 理由',
      description: '修改同样走 control.Apply；已过期的例外不会生效。',
      fields: [
        { name: 'reason', label: '原因', value: pick(row, ['reason', 'note', 'comment'], ''), required: true },
        { name: 'expires', label: '到期时间', type: 'datetime-local', value: info.expires ? String(info.expires).slice(0, 16) : '', required: true },
        { name: 'note', label: '备注', value: pick(row, ['note'], '') },
      ],
      submitText: '保存',
      danger: false,
      onSubmit: async (form) => {
        const result = await api.updateException(id, { reason: form.reason, expires: form.expires, note: form.note });
        showWarnings(warningsOf(result));
        notify.ok('例外已更新');
        await refresh();
      },
    });
  }

  async function removeException(id, row, refresh) {
    const ok = await confirmDialog({
      title: '删除例外',
      description:
        '删除后该请求重新参与规则判定。目标：' + String(pick(row, ['value', 'pattern', 'path', 'cidr'], id)),
      confirmText: '删除',
    });
    if (!ok) return;
    try {
      const result = await api.deleteException(id);
      showWarnings(warningsOf(result));
      notify.ok('例外已删除');
      await refresh();
    } catch (err) {
      toastError(err, '删除失败');
    }
  }

  host.appendChild(bannerHost);
  host.appendChild(
    card({
      flush: true,
      body: [
        toolbar(
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '状态' }), selectInput(STATE_OPTIONS, { value: filters.state, onChange: (v) => { filters.state = v; load(); } })),
          el('div', { class: 'row' , }, button('新增例外', { tone: 'primary', size: 'sm', onClick: createException })),
          el('div', { class: 'row' }, button('刷新', { size: 'sm', onClick: () => load() }))
        ),
        tableHost,
      ],
    })
  );

  load();
}

/* ── IP 名单 ────────────────────────────────────────────────── */

function renderIpListsTab(host) {
  const state = { status: 'loading', data: null, error: null };
  const tableHost = el('div');
  const filters = { list: '' };

  function paint() {
    renderTable(tableHost, state, {
      columns: [
        { key: 'cidr', label: 'CIDR', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['cidr', 'ip', 'value', 'network'], '—')) }) },
        {
          key: 'list',
          label: '名单',
          render: (row) => {
            const value = String(pick(row, ['list', 'kind', 'type'], '—')).toLowerCase();
            if (value === 'white' || value === 'allow') return badge('白名单', 'ok');
            if (value === 'black' || value === 'deny') return badge('黑名单', 'danger');
            return badge(value, 'neutral');
          },
        },
        { key: 'reason', label: '原因', wrap: true, render: (row) => el('span', { class: 'sm', text: String(pick(row, ['reason', 'note', 'comment'], '—')) }) },
        { key: 'expires', label: '到期', render: (row) => expiryBadge(row) },
        { key: 'hits', label: '命中次数', align: 'right', render: (row) => el('span', { class: 'num', text: fmtInt(pick(row, ['hits', 'hit_count'], null)) }) },
        {
          key: 'actions',
          label: '操作',
          render: (row) => {
            const id = pick(row, ['id', 'uid', 'cidr', 'ip'], null);
            if (!id) return el('span', { class: 'faint', text: '无 id' });
            return button('删除', {
              size: 'sm',
              tone: 'danger',
              onClick: async (event) => {
                event.stopPropagation();
                const ok = await confirmDialog({
                  title: '删除名单条目',
                  description: '目标：' + String(pick(row, ['cidr', 'ip', 'value'], id)),
                  confirmText: '删除',
                });
                if (!ok) return;
                try {
                  const result = await api.deleteIpEntry(id);
                  showWarnings(warningsOf(result));
                  notify.ok('名单条目已删除');
                  await load();
                } catch (err) {
                  toastError(err, '删除失败');
                }
              },
            });
          },
        },
      ],
      empty: { title: '名单为空', hint: '白名单直通、黑名单直接拦截；两者都应当带 reason 与 expires。' },
      loadingTitle: '读取名单…',
      onRetry: () => load(),
    });
  }

  async function load() {
    state = { status: 'loading', data: null, error: null };
    paint();
    try {
      const query = filters.list ? { list: filters.list } : {};
      const payload = await api.ipLists(query);
      const items = asArray(payload, ['ip_lists', 'items', 'data', 'entries']);
      const total = Number(pick(payload, ['total', 'count'], NaN));
      state = { status: 'ready', data: { items: items, total: Number.isFinite(total) ? total : undefined }, error: null };
    } catch (err) {
      state = { status: err && err.code === 'unauthenticated' ? 'unauthenticated' : 'error', data: null, error: err };
    }
    paint();
  }

  async function createEntry() {
    await openDialog({
      title: '新增名单条目',
      description: 'CIDR 格式（单 IP 写 /32）。白名单直通检测，黑名单直接拦截。',
      fields: [
        { name: 'cidr', label: 'CIDR', placeholder: '203.0.113.0/24', required: true },
        { name: 'list', label: '名单', type: 'select', options: LIST_KIND_OPTIONS, value: 'white' },
        { name: 'reason', label: '原因', placeholder: '谁、为什么、工单号', required: true },
        { name: 'expires', label: '到期时间', type: 'datetime-local', required: true },
      ],
      submitText: '创建',
      danger: false,
      onSubmit: async (form) => {
        const result = await api.createIpEntry(form);
        showWarnings(warningsOf(result));
        notify.ok('名单条目已创建');
        await load();
      },
    });
  }

  host.appendChild(
    card({
      flush: true,
      body: [
        toolbar(
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '名单类型' }), selectInput([{ value: '', label: '全部' }].concat(LIST_KIND_OPTIONS), { value: filters.list, onChange: (v) => { filters.list = v; load(); } })),
          el('div', { class: 'row' }, button('新增条目', { tone: 'primary', size: 'sm', onClick: createEntry })),
          el('div', { class: 'row' }, button('刷新', { size: 'sm', onClick: () => load() }))
        ),
        tableHost,
      ],
    })
  );

  load();
}

export function render(container) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  page.appendChild(
    pageHeader('例外与白名单', {
      subtitle: '例外必须带 reason 与 expires；到期自动失效',
    })
  );

  const host = el('div');
  const tabsHost = el('div');
  let active = 'exceptions';

  function tabItems() {
    return [
      { key: 'exceptions', label: '例外规则' },
      { key: 'ip-lists', label: 'IP 黑白名单' },
    ];
  }

  function renderTabs() {
    tabsHost.replaceChildren(
      tabs(tabItems(), {
        active: active,
        onSelect: (key) => {
          active = key;
          renderTabs();
          rebuild();
        },
      })
    );
  }

  function rebuild() {
    host.replaceChildren();
    if (active === 'exceptions') renderExceptionsTab(host);
    else renderIpListsTab(host);
  }

  page.appendChild(el('div', { class: 'card' }, tabsHost));
  page.appendChild(host);
  renderTabs();
  rebuild();

  return () => {};
}
