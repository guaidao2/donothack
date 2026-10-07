// web/assets/views/ratelimit.js
// 职责：CC 防护与限速页 —— 阈值配置（读取 + 整体编辑）、当前封禁列表与手动解封、状态表容量水位。
// 取数：GET/PUT /ratelimit、GET /bans、DELETE /bans/:ip。
// 说明：§5 没有逐字段描述 /ratelimit 的结构，所以这里把完整配置原样以代码模式展示，
//       编辑走"JSON 文本框 + 本地 JSON.parse 校验 + PUT 整体替换"，不猜字段、不造假表单。

import { api, warningsOf, snapshotVersionOf } from '../api.js';
import { createResource } from '../store.js';
import {
  el,
  card,
  pageHeader,
  badge,
  banner,
  button,
  kvList,
  meter,
  renderCode,
  bindState,
  pick,
  asArray,
  fmtInt,
  fmtSeconds,
  fmtTime,
  coerceText,
} from '../dom.js';
import { renderTable } from '../components/table.js';
import { openDialog, confirmDialog, KEEP_OPEN } from '../components/modal.js';
import { notify, toastError, showWarnings } from '../components/toast.js';

function capacityOf(payload) {
  const capacity = Number(pick(payload, ['table_capacity', 'ratelimit_table_capacity', 'capacity', 'state_table.capacity'], NaN));
  const used = Number(pick(payload, ['table_used', 'ratelimit_table_used', 'used', 'state_table.used', 'entries'], NaN));
  return { capacity: Number.isFinite(capacity) ? capacity : null, used: Number.isFinite(used) ? used : null };
}

function configSummary(payload) {
  const rows = [];
  const enabled = pick(payload, ['enabled', 'ratelimit.enabled', 'cc.enabled'], null);
  if (enabled !== null) rows.push({ k: '限速总开关', v: enabled ? badge('已开启', 'ok') : badge('已关闭', 'neutral') });
  const rps = pick(payload, ['requests_per_second', 'rps', 'rate', 'global.rps'], null);
  if (rps !== null) rows.push({ k: '全局限速', v: coerceText(rps) + ' 请求/秒' });
  const burst = pick(payload, ['burst', 'burst_size', 'global.burst'], null);
  if (burst !== null) rows.push({ k: '突发窗口', v: coerceText(burst) });
  const perIp = pick(payload, ['per_ip', 'per_ip_limit', 'ip_limit'], null);
  if (perIp !== null) rows.push({ k: '单 IP 阈值', v: coerceText(perIp) });
  const banDuration = pick(payload, ['ban_duration_s', 'ban_seconds', 'ban_duration'], null);
  if (banDuration !== null) rows.push({ k: '封禁时长', v: fmtSeconds(banDuration) });
  const paths = asArray(pick(payload, ['paths', 'path_rules', 'per_path'], []));
  if (paths.length > 0) {
    rows.push({
      k: '按路径规则（' + paths.length + ' 条）',
      v: kvList(
        paths.slice(0, 20).map((item) => ({
          k: String(pick(item, ['path', 'prefix', 'pattern'], '—')),
          v: coerceText(pick(item, ['limit', 'rps', 'value'], '—')),
        }))
      ),
    });
  }
  const whitelist = asArray(pick(payload, ['whitelist', 'white_list', 'bypass'], []));
  if (whitelist.length > 0) {
    rows.push({ k: '白名单直通（' + whitelist.length + ' 条）', v: coerceText(whitelist.slice(0, 10).join(', ')) });
  }
  return rows;
}

function bansTable(host, resource) {
  const tableHost = el('div');
  let state = { status: 'loading', data: null, error: null };

  function paint() {
    renderTable(tableHost, state, {
      columns: [
        { key: 'ip', label: 'IP', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['ip', 'client_ip', 'addr'], '—')) }) },
        { key: 'reason', label: '原因', wrap: true, render: (row) => el('span', { class: 'sm', text: String(pick(row, ['reason', 'cause', 'rule', 'source'], '—')) }) },
        {
          key: 'remaining',
          label: '剩余时间',
          align: 'right',
          render: (row) => {
            const explicit = pick(row, ['remaining_s', 'ttl_s', 'remaining'], null);
            if (explicit !== null && Number.isFinite(Number(explicit))) return el('span', { class: 'num', text: fmtSeconds(explicit) });
            const expires = pick(row, ['expires_at', 'expires', 'until'], null);
            if (expires) {
              const t = new Date(expires).getTime();
              if (Number.isFinite(t)) return el('span', { class: 'num', text: fmtSeconds(Math.max(0, (t - Date.now()) / 1000)) });
            }
            return el('span', { text: '—' });
          },
        },
        { key: 'since', label: '封禁时间', render: (row) => el('span', { class: 'xs muted', text: fmtTime(pick(row, ['banned_at', 'since', 'ts', 'created_at'], null)) }) },
        { key: 'hits', label: '触发次数', align: 'right', render: (row) => el('span', { class: 'num', text: fmtInt(pick(row, ['hits', 'count', 'violations'], null)) }) },
        {
          key: 'actions',
          label: '操作',
          render: (row) => {
            const ip = pick(row, ['ip', 'client_ip', 'addr'], null);
            if (!ip) return el('span', { class: 'faint', text: '无 IP' });
            return button('解封', {
              size: 'sm',
              onClick: async (event) => {
                event.stopPropagation();
                const ok = await confirmDialog({
                  title: '手动解封',
                  description: 'DELETE /bans/' + ip + '：立即解除该 IP 的封禁。解封是写操作，会记入操作审计。',
                  confirmText: '解封',
                  danger: false,
                });
                if (!ok) return;
                try {
                  const result = await api.unban(ip);
                  showWarnings(warningsOf(result));
                  notify.ok('已解封 ' + ip);
                  await load();
                } catch (err) {
                  toastError(err, '解封失败');
                }
              },
            });
          },
        },
      ],
      empty: { title: '当前没有封禁记录', hint: '没有封禁说明限速没有触发，或者封禁表刚被清空。' },
      loadingTitle: '读取封禁列表…',
      onRetry: () => load(),
      hasMoreOf: (data) => !!(data && data.next_cursor),
      onMore: () => load(false),
    });
  }

  let nextCursor = '';
  let rows = [];

  async function load(reset) {
    if (reset !== false) {
      rows = [];
      nextCursor = '';
    }
    state = { status: 'loading', data: null, error: null };
    paint();
    try {
      const query = {};
      if (nextCursor) query.cursor = nextCursor;
      const payload = await api.bans(query);
      const items = asArray(payload, ['bans', 'items', 'data']);
      rows = rows.concat(items);
      nextCursor = pick(payload, ['next_cursor', 'cursor'], '') || '';
      state = { status: 'ready', data: { items: rows, next_cursor: nextCursor }, error: null };
    } catch (err) {
      state = { status: err && err.code === 'unauthenticated' ? 'unauthenticated' : 'error', data: null, error: err };
    }
    paint();
  }

  host.appendChild(tableHost);
  load();
  return { host: tableHost, load: load, resource: resource };
}

export function render(container) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  const configRes = createResource(() => api.ratelimit());

  page.appendChild(
    pageHeader('CC 防护与限速', {
      subtitle: '阈值配置走 PUT /ratelimit 整体替换；封禁列表支持手动解封',
      actions: [
        button('刷新', { size: 'sm', onClick: () => configRes.load() }),
        button('编辑配置（JSON）', {
          size: 'sm',
          tone: 'primary',
          onClick: () => editConfig(configRes),
        }),
      ],
    })
  );

  /* 配置卡片 */
  const configBody = el('div', { class: 'stack-2' });
  const configCard = card({ title: '阈值配置', hint: 'GET /ratelimit', body: configBody });
  bindState(configBody, configRes, {
    loadingTitle: '读取限速配置…',
    onRetry: () => configRes.load(),
    empty: { title: '后端未返回限速配置' },
    render: (payload) => {
      const blocks = [];
      const summary = configSummary(payload);
      if (summary.length > 0) blocks.push(kvList(summary));
      else blocks.push(el('div', { class: 'chart__empty', text: '后端返回的配置里没有可识别的已知字段，下面给出原始内容。' }));

      const { capacity, used } = capacityOf(payload);
      if (capacity !== null) {
        const ratio = capacity > 0 && used !== null ? used / capacity : null;
        blocks.push(
          el(
            'div',
            { class: 'stack-1' },
            el('div', { class: 'xs faint', text: '限速状态表容量水位' }),
            meter({
              value: used === null ? 0 : used,
              max: capacity,
              label:
                (used === null ? '使用量未知' : fmtInt(used) + ' / ' + fmtInt(capacity)) +
                (ratio === null ? '' : '（' + (ratio * 100).toFixed(1) + '%）'),
            })
          )
        );
        if (ratio !== null && ratio >= 0.75) {
          blocks.push(
            banner('warn', '状态表接近容量上限', el('div', {
              class: 'sm',
              text: '使用率 ' + (ratio * 100).toFixed(1) + '%。表满后新条目会被拒绝，限速与封禁会失效 —— 需要调大容量或缩短封禁时长。',
            }))
          );
        }
      }

      blocks.push(el('div', { class: 'stack-2' }, renderCode(payload, { label: '配置原文（只读）', meta: 'GET /ratelimit' })));
      return blocks;
    },
  });

  async function editConfig(resource) {
    const current = resource.get().data;
    if (!current) {
      notify.warn('还没有读到当前配置，先刷新一次');
      return;
    }
    const area = el('textarea', { attrs: { rows: '18', spellcheck: 'false' } });
    // 只回填**可改**字段：GET 还会带 ban_window_s / ban_duration_s / stats 这些派生项，
    // 摆进编辑框会让人以为也能改（后端会收下并忽略，但界面上不该出现）。
    const EDITABLE = ['enabled', 'rps', 'burst', 'ban_after_hits', 'ban_window', 'ban_duration', 'whitelist'];
    const draft = {};
    for (const key of EDITABLE) {
      if (current[key] !== undefined) draft[key] = current[key];
    }
    let initial = '';
    try {
      initial = JSON.stringify(draft, null, 2);
    } catch (err) {
      initial = '';
    }
    area.value = initial;
    const errorLine = el('div', { class: 'field__error hidden' });

    await openDialog({
      title: '编辑限速配置',
      description:
        'PUT /ratelimit：这里只列出可改的字段（enabled、rps、burst、ban_after_hits、' +
        'ban_window、ban_duration、whitelist）。改完提交即成为新的阈值配置。',
      wide: true,
      body: el(
        'div',
        { class: 'stack-2' },
        el('div', { class: 'field' }, el('span', { class: 'field__label', text: 'JSON' }), area),
        errorLine
      ),
      submitText: '保存',
      danger: true,
      onSubmit: async () => {
        let parsed = null;
        try {
          parsed = JSON.parse(area.value);
        } catch (err) {
          errorLine.textContent = 'JSON 解析失败：' + (err && err.message ? err.message : '格式错误');
          errorLine.classList.remove('hidden');
          return KEEP_OPEN;
        }
        if (!parsed || typeof parsed !== 'object') {
          errorLine.textContent = '配置必须是一个 JSON 对象';
          errorLine.classList.remove('hidden');
          return KEEP_OPEN;
        }
        const ok = await confirmDialog({
          title: '确认替换限速配置',
          description: '这条写操作会立即影响线上限速行为，并记入操作审计。',
          confirmText: '替换',
        });
        if (!ok) return KEEP_OPEN;
        const result = await api.putRatelimit(parsed);
        showWarnings(warningsOf(result));
        notify.ok('限速配置已更新' + (snapshotVersionOf(result) ? '（快照 ' + snapshotVersionOf(result) + '）' : ''));
        await resource.load();
      },
    });
  }

  /* 封禁列表 */
  const banHost = el('div');
  const banCard = el('div', { class: 'card' }, el('div', { class: 'card__head' }, el('span', { class: 'card__title', text: '当前封禁列表' }), el('span', { class: 'card__hint', text: 'GET /bans' })));
  banCard.appendChild(el('div', { class: 'card__body card__body--flush' }, banHost));
  bansTable(banHost, null);

  page.appendChild(configCard);
  page.appendChild(banCard);

  configRes.load();

  return () => {};
}
