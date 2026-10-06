// web/assets/views/events.js
// 职责：攻击事件页 —— 列表（只显示摘要，绝不展开 payload）+ 详情（全链路、变换前/后代码块）。
// 取数：GET /events（cursor 分页）、GET /events/:id、GET /events/:id/raw（取证下载）、GET /events/stream（SSE）。
// 约束：payload 只在详情页通过 dom.renderCode 展示；列表页只出现参数名/算子/指纹等摘要字段。

import { api, eventsStreamUrl, eventRawUrl, eventsExportUrl } from '../api.js';
import { createResource, ui, debounce } from '../store.js';
import {
  el,
  card,
  pageHeader,
  badge,
  button,
  linkButton,
  checkbox,
  selectInput,
  textInput,
  toolbar,
  kvList,
  pillList,
  renderCode,
  bindState,
  pick,
  asArray,
  fmtInt,
  fmtMs,
  fmtScore,
  fmtTime,
  fmtRelative,
  sectionTitle,
} from '../dom.js';
import { renderTable } from '../components/table.js';
import { notify } from '../components/toast.js';

const VERDICT_TONE = {
  block: 'danger',
  blocked: 'danger',
  deny: 'danger',
  drop: 'danger',
  pass: 'ok',
  allow: 'ok',
  allowed: 'ok',
  log: 'info',
  monitor: 'info',
  detect: 'info',
  challenge: 'warn',
  tarpit: 'warn',
};

const VERDICT_OPTIONS = [
  { value: '', label: '全部裁决' },
  { value: 'block', label: 'BLOCK' },
  { value: 'log', label: 'LOG' },
  { value: 'pass', label: 'PASS' },
  { value: 'challenge', label: 'CHALLENGE' },
];

const RANGE_OPTIONS = [
  { value: '15m', label: '最近 15 分钟' },
  { value: '1h', label: '最近 1 小时' },
  { value: '6h', label: '最近 6 小时' },
  { value: '24h', label: '最近 24 小时' },
];

const LIMIT_OPTIONS = [
  { value: '50', label: '每页 50' },
  { value: '100', label: '每页 100' },
  { value: '200', label: '每页 200' },
];

export function verdictBadge(verdict) {
  const key = String(verdict === null || verdict === undefined ? '' : verdict).toLowerCase();
  return badge(verdict === null || verdict === undefined || verdict === '' ? '—' : String(verdict), VERDICT_TONE[key] || 'neutral');
}

function shortPath(value) {
  const text = value === null || value === undefined ? '' : String(value);
  return text.length > 64 ? text.slice(0, 63) + '…' : text;
}

function hitSummary(event) {
  const hit = asArray(pick(event, ['hits', 'rules', 'matches'], []))[0];
  const target = pick(hit || {}, ['targets.0.name', 'param', 'param_name', 'arg'], null);
  const fingerprint = pick(hit || {}, ['fingerprint', 'description', 'rule_desc'], null);
  const operator = pick(hit || {}, ['targets.0.operator', 'operator'], null);
  const parts = [];
  if (target) parts.push('参数 ' + String(target));
  if (operator) parts.push('算子 ' + String(operator));
  if (fingerprint) parts.push(String(fingerprint));
  if (parts.length === 0) parts.push(String(pick(event, ['summary', 'rule_id', 'category'], '—')));
  return parts.join(' · ');
}

/* ── 列表 ───────────────────────────────────────────────────── */

function renderList(container, ctx) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  const filters = {
    range: '1h',
    verdict: '',
    category: '',
    rule: '',
    ip: '',
    path: '',
    limit: 50,
  };

  let rows = [];
  let nextCursor = '';
  let listState = { status: 'loading', data: null, error: null };
  let stream = null;

  const tableHost = el('div');

  function params() {
    const out = { range: filters.range };
    if (filters.verdict) out.verdict = filters.verdict;
    if (filters.category) out.category = filters.category;
    if (filters.rule) out.rule = filters.rule;
    if (filters.ip) out.ip = filters.ip;
    if (filters.path) out.path = filters.path;
    out.limit = filters.limit;
    return out;
  }

  function paint() {
    renderTable(tableHost, listState, {
      columns: [
        { key: 'ts', label: '时间', render: (row) => el('span', { class: 'mono xs', text: fmtTime(pick(row, ['ts', 'time', 'timestamp'])) , attrs: { title: fmtRelative(pick(row, ['ts', 'time', 'timestamp'])) } }) },
        { key: 'client_ip', label: '客户端 IP', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['client_ip', 'src_ip', 'ip', 'remote_addr'], '—')) }) },
        { key: 'method', label: '方法', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['method', 'http_method'], '—')) }) },
        {
          key: 'path',
          label: '路径',
          wrap: true,
          render: (row) => {
            const full = String(pick(row, ['path', 'url', 'uri', 'request_uri'], '—'));
            return el('span', { class: 'mono truncate', text: shortPath(full), attrs: { title: full } });
          },
        },
        { key: 'rule', label: '命中规则', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['rule_id', 'hits.0.rule_id', 'rule'], '—')) }) },
        { key: 'category', label: '类目', render: (row) => el('span', { text: String(pick(row, ['category', 'hits.0.category'], '—')) }) },
        { key: 'score', label: '分数', align: 'right', render: (row) => el('span', { class: 'num', text: fmtScore(pick(row, ['score', 'total_score'], null)) }) },
        { key: 'verdict', label: '裁决', render: (row) => verdictBadge(pick(row, ['verdict', 'action', 'decision'])) },
        { key: 'latency', label: '耗时', align: 'right', render: (row) => el('span', { class: 'num', text: fmtMs(pick(row, ['latency_ms', 'total_latency_ms', 'duration_ms', 'elapsed_ms'], null)) }) },
        { key: 'summary', label: '摘要（不含 payload 原文）', wrap: true, render: (row) => el('span', { class: 'sm muted', text: hitSummary(row) }) },
      ],
      empty: {
        title: '当前过滤条件下没有事件',
        hint: '列表只显示命中事件；没有命中说明这段时间没有请求被判定为攻击，或者过滤条件过窄。',
      },
      loadingTitle: '查询事件…',
      onRetry: () => load(true),
      onRowClick: (row) => {
        const id = pick(row, ['id', 'event_id', 'uid'], null);
        if (!id) {
          notify.warn('这条事件没有 id 字段，无法打开详情');
          return;
        }
        ctx.navigate('/events/' + encodeURIComponent(String(id)));
      },
      hasMoreOf: (data) => !!(data && data.next_cursor),
      onMore: () => load(false),
      note: rows.length > 0 ? '点击行查看完整链路（payload 只在详情展开）' : undefined,
    });
  }

  async function load(reset) {
    if (reset) {
      rows = [];
      nextCursor = '';
    }
    listState = { status: 'loading', data: null, error: null };
    paint();
    try {
      const query = params();
      if (!reset && nextCursor) query.cursor = nextCursor;
      const payload = await api.events(query);
      const items = asArray(payload, ['events', 'items', 'data']);
      rows = reset ? items : rows.concat(items);
      nextCursor = pick(payload, ['next_cursor', 'cursor', 'next'], '') || '';
      const total = Number(pick(payload, ['total', 'count'], NaN));
      listState = {
        status: 'ready',
        data: {
          items: rows,
          next_cursor: nextCursor,
          total: Number.isFinite(total) ? total : undefined,
          partial: !!pick(payload, ['partial', 'truncated', 'timeout'], false),
        },
        error: null,
      };
    } catch (err) {
      listState = {
        status: err && err.code === 'unauthenticated' ? 'unauthenticated' : 'error',
        data: null,
        error: err,
      };
    }
    paint();
  }

  function stopStream() {
    if (stream) {
      stream.close();
      stream = null;
    }
  }

  function startStream() {
    if (stream) return;
    if (typeof globalThis.EventSource !== 'function') {
      notify.warn('当前浏览器不支持 SSE，实时推送不可用');
      return;
    }
    try {
      stream = new EventSource(eventsStreamUrl());
    } catch (err) {
      notify.error('无法建立实时连接', { detail: String(err && err.message ? err.message : err) });
      return;
    }
    stream.addEventListener('message', (event) => {
      let payload = null;
      try {
        payload = JSON.parse(event.data);
      } catch (err) {
        return;
      }
      const item = payload && payload.event ? payload.event : payload;
      if (!item || typeof item !== 'object') return;
      rows = [item].concat(rows);
      if (rows.length > 500) rows = rows.slice(0, 500);
      if (listState.status === 'ready') {
        listState = {
          status: 'ready',
          data: Object.assign({}, listState.data, { items: rows }),
          error: null,
        };
        paint();
      }
    });
    stream.addEventListener('error', () => {
      /* EventSource 会自动重连；不在这里刷屏提示。 */
    });
  }

  const streamToggle = checkbox('实时推送（SSE）', {
    checked: false,
    onChange: (checked) => {
      ui.set({ streamEnabled: checked });
      if (checked) {
        startStream();
        notify.info('已开启实时推送：新事件会插到列表顶部');
      } else {
        stopStream();
      }
    },
  });

  const applyFilter = debounce(() => load(true), 300);

  page.appendChild(
    pageHeader('攻击事件', {
      subtitle: '列表只显示摘要；payload 原文只在详情页以代码模式展开',
      actions: [
        streamToggle,
        linkButton('导出 JSONL', eventsExportUrl(params()), { size: 'sm', download: 'events.jsonl' }),
        linkButton('导出 CSV', eventsExportUrl(Object.assign(params(), { format: 'csv' })), { size: 'sm', download: 'events.csv' }),
      ],
    })
  );

  page.appendChild(
    card({
      flush: true,
      body: [
        toolbar(
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '时间范围' }), selectInput(RANGE_OPTIONS, { value: filters.range, onChange: (v) => { filters.range = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '裁决' }), selectInput(VERDICT_OPTIONS, { value: filters.verdict, onChange: (v) => { filters.verdict = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '类目' }), textInput({ value: filters.category, placeholder: '如 sqli', onEnter: (v) => { filters.category = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '规则 ID' }), textInput({ value: filters.rule, placeholder: '如 SQLI-942100', onEnter: (v) => { filters.rule = v; load(true); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '客户端 IP' }), textInput({ value: filters.ip, placeholder: '精确匹配', onEnter: (v) => { filters.ip = v; load(true); } })),
          el('div', { class: 'field toolbar__grow' }, el('span', { class: 'field__label', text: '路径' }), textInput({ value: filters.path, placeholder: '前缀或精确匹配', onInput: (v) => { filters.path = v; applyFilter(); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '每页' }), selectInput(LIMIT_OPTIONS, { value: String(filters.limit), onChange: (v) => { filters.limit = Number(v); load(true); } })),
          button('查询', { size: 'sm', tone: 'primary', onClick: () => load(true) })
        ),
        tableHost,
      ],
    })
  );

  load(true);

  return () => stopStream();
}

/* ── 详情 ───────────────────────────────────────────────────── */

function targetRow(target) {
  const name = pick(target, ['name', 'param', 'param_name', 'arg', 'key'], '—');
  const operator = pick(target, ['operator', 'op'], '—');
  const matched = pick(target, ['matched', 'match', 'result'], null);
  const fingerprint = pick(target, ['fingerprint', 'detail', 'description'], null);
  const before = pick(target, ['before', 'value_before', 'raw', 'original'], null);
  const after = pick(target, ['after', 'value_after', 'decoded', 'transformed'], null);
  const transforms = asArray(pick(target, ['transforms', 'transform_chain'], []));

  return el(
    'div',
    { class: 'hit ' + (matched ? 'hit--match' : 'hit--miss') },
    el(
      'div',
      { class: 'hit__head' },
      el('span', { class: 'mono strong', text: String(name) }),
      el('span', { class: 'pill', text: String(operator) }),
      matched === null ? null : badge(matched ? 'MATCH' : 'NO MATCH', matched ? 'danger' : 'neutral'),
      fingerprint ? el('span', { class: 'sm muted', text: String(fingerprint) }) : null
    ),
    transforms.length > 0
      ? el('div', { class: 'stack-1' }, el('div', { class: 'xs faint', text: '变换链' }), pillList(transforms.map((t) => String(t))))
      : null,
    before !== null || after !== null
      ? el(
          'div',
          { class: 'stack-2' },
          renderCode(before, { label: '变换前', tight: true }),
          renderCode(after, { label: '变换后', tight: true })
        )
      : null
  );
}

function renderDetailBody(event) {
  const blocks = [];

  const id = pick(event, ['id', 'event_id', 'uid'], null);
  const verdict = pick(event, ['verdict', 'action', 'decision']);
  const score = pick(event, ['score', 'total_score'], null);
  const threshold = pick(event, ['threshold', 'score_threshold'], null);
  const mode = pick(event, ['mode', 'detect_mode'], null);
  const rulesetVersion = pick(event, ['ruleset_version', 'ruleset.version'], null);
  const upstream = pick(event, ['upstream_latency_ms', 'upstream_ms'], null);
  const total = pick(event, ['latency_ms', 'total_latency_ms', 'duration_ms'], null);
  const source = pick(event, ['verdict_source', 'decision_source', 'verdict_reason'], null);

  blocks.push(
    kvList([
      { k: '事件 ID', v: id ? el('span', { class: 'mono wrap-anywhere', text: String(id) }) : null },
      { k: '时间', v: pick(event, ['ts', 'time', 'timestamp'], null) ? fmtTime(pick(event, ['ts', 'time', 'timestamp'])) : null },
      { k: '客户端 IP', v: el('span', { class: 'mono', text: String(pick(event, ['client_ip', 'src_ip', 'ip'], '—')) }) },
      { k: '方法 / 路径', v: el('span', { class: 'mono wrap-anywhere', text: String(pick(event, ['method'], '—')) + ' ' + String(pick(event, ['path', 'url', 'uri'], '—')) }) },
      { k: 'Host', v: pick(event, ['host', 'authority'], null) === null ? null : el('span', { class: 'mono', text: String(pick(event, ['host', 'authority'])) }) },
      { k: '最终裁决', v: el('span', {}, verdictBadge(verdict), source ? el('span', { class: 'sm muted', text: '　来源：' + String(source) }) : null) },
      { k: '分数累计', v: fmtScore(score) + (threshold === null ? '' : '　阈值 ' + fmtInt(threshold)) },
      { k: '检测模式', v: mode === null ? null : String(mode) },
      { k: '上游耗时 / 总耗时', v: fmtMs(upstream) + ' / ' + fmtMs(total) },
      { k: 'ruleset_version', v: rulesetVersion ? el('span', { class: 'mono', text: String(rulesetVersion) }) : null },
    ])
  );

  const hits = asArray(pick(event, ['hits', 'rules', 'matches', 'detections'], []));
  if (hits.length > 0) {
    const list = el('div', { class: 'sublist' });
    for (const hit of hits) {
      const ruleId = pick(hit, ['rule_id', 'id', 'rule'], '—');
      const category = pick(hit, ['category', 'class'], null);
      const hitScore = pick(hit, ['score', 'delta'], null);
      const phase = pick(hit, ['phase', 'stage'], null);
      const targets = asArray(pick(hit, ['targets', 'matches', 'details'], []));
      const transforms = asArray(pick(hit, ['transforms', 'transform_chain'], []));
      const block = el(
        'div',
        { class: 'phase' },
        el(
          'div',
          { class: 'phase__head' },
          el('span', { class: 'mono', text: String(ruleId) }),
          category ? badge(String(category), 'info') : null,
          phase ? el('span', { class: 'faint xs', text: String(phase) }) : null,
          hitScore === null ? null : el('span', { class: 'num sm', text: 'score ' + fmtScore(hitScore) })
        ),
        el(
          'div',
          { class: 'phase__body' },
          transforms.length > 0 ? pillList(transforms.map((t) => String(t))) : null,
          targets.length > 0
            ? targets.map(targetRow)
            : [
                renderCode(pick(hit, ['before', 'value_before', 'payload_before'], null), { label: '变换前', tight: true }),
                renderCode(pick(hit, ['after', 'value_after', 'payload_after'], null), { label: '变换后', tight: true }),
              ]
        )
      );
      list.appendChild(block);
    }
    blocks.push(el('div', { class: 'stack-2' }, sectionTitle('命中链路'), list));
  } else {
    const before = pick(event, ['payload_before', 'before', 'raw_request', 'original_payload'], null);
    const after = pick(event, ['payload_after', 'after', 'decoded_payload', 'normalized_payload'], null);
    blocks.push(
      el(
        'div',
        { class: 'stack-2' },
        sectionTitle('payload（变换前 / 变换后）'),
        renderCode(before, { label: '变换前', meta: '服务端可打印化', truncated: !!pick(event, ['payload_truncated', 'truncated'], false) }),
        renderCode(after, { label: '变换后', meta: '服务端可打印化' })
      )
    );
  }

  const rawUrls = el('div', { class: 'row row--wrap' });
  if (id) {
    rawUrls.appendChild(linkButton('下载原始字节', eventRawUrl(String(id)), { size: 'sm', download: true, title: '取证用：未经变换的请求原始字节' }));
  }
  blocks.push(
    el(
      'div',
      { class: 'stack-2' },
      sectionTitle('取证与合规'),
      el('div', {
        class: 'sm muted',
        text:
          '这里展示的是服务端可打印化（\\xNN、UTF-8 边界截断）之后的文本；' +
          'payload 原文默认不落盘，需要在设置页显式打开抓取开关。',
      }),
      rawUrls
    )
  );

  return blocks;
}

function renderDetail(container, ctx) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);
  const id = ctx.params.id;
  const resource = createResource(() => api.event(id));

  page.appendChild(
    pageHeader('事件详情', {
      subtitle: '事件 ' + id,
      actions: [
        button('返回列表', { size: 'sm', onClick: () => ctx.navigate('/events') }),
        button('刷新', { size: 'sm', onClick: () => resource.load() }),
      ],
    })
  );

  const host = el('div');
  page.appendChild(card({ body: host }));
  bindState(host, resource, {
    loadingTitle: '读取事件详情…',
    onRetry: () => resource.load(),
    empty: { title: '后端未返回该事件' },
    render: (event) => renderDetailBody(event),
  });
  resource.load();

  return () => {};
}

export function render(container, ctx) {
  if (ctx && ctx.params && ctx.params.id) return renderDetail(container, ctx);
  return renderList(container, ctx);
}
