// web/assets/views/dashboard.js
// 职责：概览页 —— 请求/拦截曲线、攻击类目分布、Top N、系统状态卡片、过载降级提示。
// 取数：GET /status、GET /metrics/summary、GET /metrics/timeseries?range=…
// 约束：字段缺失一律显示 "—"（不猜、不造数据）；请求失败或整体为空时显示明确的空/错误态。

import { api } from '../api.js';
import { createResource, ui } from '../store.js';
import {
  el,
  card,
  pageHeader,
  badge,
  banner,
  kvList,
  rankList,
  meter,
  bindState,
  pick,
  asArray,
  selectInput,
  fmtInt,
  fmtBytes,
  fmtPercent,
  fmtSeconds,
  fmtFloat,
  fmtTime,
} from '../dom.js';
import { lineChart, barChart } from '../components/chart.js';

const RANGES = [
  { value: '1h', label: '最近 1 小时' },
  { value: '6h', label: '最近 6 小时' },
  { value: '24h', label: '最近 24 小时' },
];

/** 数值统一入口：拿不到就是 null（显示 "—"），绝不用 0 冒充真实值。 */
function num(value) {
  if (value === null || value === undefined || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function toMillis(value) {
  const n = num(value);
  if (n === null) return null;
  return n > 1e12 ? n : n * 1000;
}

/** 时间序列容错解析：支持 {points|buckets:[{ts,requests,blocked}]} 与 {series:{requests:[[x,y]]}}。 */
function readTimeseries(payload) {
  if (!payload || typeof payload !== 'object') return { requests: [], blocked: [] };
  const requests = [];
  const blocked = [];
  const list = asArray(payload, ['points', 'buckets', 'minutes', 'data', 'items']);
  if (list.length > 0) {
    for (const item of list) {
      const x = toMillis(pick(item, ['ts', 't', 'time', 'minute', 'timestamp', 'start', 'bucket']));
      if (x === null) continue;
      requests.push({ x: x, y: num(pick(item, ['requests', 'total', 'request_count', 'req', 'count'], 0)) || 0 });
      blocked.push({
        x: x,
        y: num(pick(item, ['blocked', 'blocked_total', 'hits', 'block', 'deny', 'intercepted'], 0)) || 0,
      });
    }
    return { requests: requests, blocked: blocked };
  }
  if (payload.series && typeof payload.series === 'object') {
    const pairs = (key) => {
      const raw = payload.series[key];
      if (!Array.isArray(raw)) return [];
      return raw
        .filter((p) => Array.isArray(p) && p.length >= 2)
        .map((p) => ({ x: toMillis(p[0]), y: Number(p[1]) || 0 }))
        .filter((p) => p.x !== null);
    };
    return { requests: pairs('requests'), blocked: pairs('blocked') };
  }
  return { requests: requests, blocked: blocked };
}

function statCard(label, value, sub) {
  return card({
    body: el(
      'div',
      { class: 'stat' },
      el('div', { class: 'stat__label', text: label }),
      el('div', { class: 'stat__value', text: '' }, value),
      sub ? el('div', { class: 'stat__sub', text: sub }) : null
    ),
  });
}

function textStat(value) {
  return el('span', { text: value === null || value === undefined || value === '' ? '—' : String(value) });
}

function degradationBanner(status) {
  const level = num(pick(status, ['overload.level', 'degrade_level', 'degradation.level', 'level']));
  const mode = pick(status, ['mode', 'config.mode', 'detect_mode'], '');
  const rejected = num(pick(status, ['overload.rejected', 'degrade_rejected', 'rejected_degradations']));
  const reason = pick(status, ['overload.reason', 'degrade_reason', 'degradation.reason'], '');
  if (level === null && rejected === null) return null;
  if (level === 0 && !rejected) return null;

  const dangerous = level !== null && level >= 2 && String(mode) === 'block';
  const title = dangerous
    ? '已拒绝降级：block 模式下只允许 L1，超出的降级被拒绝并返回 503'
    : '系统处于降级状态 L' + (level === null ? '?' : level);

  return banner(
    dangerous ? 'danger' : 'warn',
    title,
    el(
      'div',
      { class: 'stack-1' },
      el('div', {
        class: 'sm',
        text:
          '当前模式：' +
          (mode || '—') +
          '　降级级别：' +
          (level === null ? '—' : 'L' + level) +
          (rejected ? '　已拒绝降级次数：' + fmtInt(rejected) : ''),
      }),
      reason ? el('div', { class: 'sm mono', text: String(reason) }) : null
    )
  );
}

function renderStatus(status) {
  const memUsed = num(pick(status, ['memory.used_bytes', 'memory_used_bytes', 'mem_used_bytes', 'rss_bytes']));
  const memPeak = num(pick(status, ['memory.peak_bytes', 'memory_peak_bytes', 'mem_peak_bytes']));
  const memBudget = num(pick(status, ['memory.budget_bytes', 'memory_budget_bytes', 'budget_bytes']));
  const gomax = num(pick(status, ['gomaxprocs', 'gomax_procs', 'GOMAXPROCS']));
  const uptime = num(pick(status, ['uptime_s', 'uptime_seconds', 'uptime']));
  const rulesVersion = pick(status, ['ruleset.version', 'ruleset_version', 'rules_version']);
  const rulesCount = num(pick(status, ['ruleset.count', 'ruleset.rules', 'rule_count', 'rules_count']));
  const profile = pick(status, ['profile', 'profile.name', 'resource_profile']);
  const version = pick(status, ['version', 'build_version']);
  const upstreamOk = pick(status, ['upstream.healthy', 'upstream_healthy', 'upstream.ok']);
  const upstreamLatency = num(pick(status, ['upstream.latency_ms', 'upstream_latency_ms']));
  const loadedAt = pick(status, ['ruleset.loaded_at', 'loaded_at', 'snapshot.loaded_at']);

  const grid = el(
    'div',
    { class: 'grid grid--stats' },
    statCard('Profile', textStat(profile), '资源档位'),
    statCard(
      '内存（当前 / 峰值）',
      el(
        'span',
        {},
        el('span', { text: memUsed === null ? '—' : fmtBytes(memUsed) }),
        el('span', { class: 'faint', text: ' / ' }),
        el('span', { text: memPeak === null ? '—' : fmtBytes(memPeak) })
      ),
      memBudget === null ? '预算未上报' : '预算 ' + fmtBytes(memBudget)
    ),
    statCard('GOMAXPROCS', textStat(gomax), '并行度'),
    statCard('运行时长', textStat(uptime === null ? null : fmtSeconds(uptime)), version ? '版本 ' + version : '版本未上报')
  );

  const kv = kvList([
    { k: '检测模式', v: textStat(pick(status, ['mode', 'config.mode', 'detect_mode'])) },
    { k: '规则集版本', v: rulesVersion ? el('span', { class: 'mono', text: String(rulesVersion) }) : null },
    { k: '规则条数', v: rulesCount === null ? null : fmtInt(rulesCount) },
    {
      k: '上游健康',
      v:
        upstreamOk === null || upstreamOk === undefined
          ? null
          : badge(upstreamOk ? '正常' : '异常', upstreamOk ? 'ok' : 'danger'),
    },
    { k: '上游耗时', v: upstreamLatency === null ? null : fmtFloat(upstreamLatency, 2) + ' ms' },
    { k: '快照加载时间', v: loadedAt ? fmtTime(loadedAt) : null },
  ]);

  const extra = el('div', { class: 'stack-2' });
  if (memBudget !== null && memBudget > 0 && memUsed !== null) {
    extra.appendChild(
      el(
        'div',
        { class: 'stack-1' },
        el('div', { class: 'xs faint', text: '进程内存占用 / 预算' }),
        meter({
          value: memUsed,
          max: memBudget,
          label: fmtBytes(memUsed) + ' / ' + fmtBytes(memBudget) + '（' + fmtPercent(memUsed / memBudget) + '）',
        })
      )
    );
  }

  const out = [grid, kv, extra];
  const degrade = degradationBanner(status);
  if (degrade) out.unshift(degrade);
  return out;
}

function renderSummary(summary) {
  const requests = num(pick(summary, ['requests_total', 'total_requests', 'requests']));
  const blocked = num(pick(summary, ['blocked_total', 'blocks_total', 'blocked', 'deny_total']));
  const explicitRatio = num(pick(summary, ['block_ratio', 'blocked_ratio']));
  const ratio = explicitRatio !== null ? explicitRatio : requests && blocked !== null ? blocked / requests : null;
  const hits = num(pick(summary, ['events_total', 'hits_total', 'attacks_total']));

  const categories = asArray(pick(summary, ['categories', 'by_category', 'category_distribution'], []));
  const topIps = asArray(pick(summary, ['top_ips', 'top_src_ips', 'top_client_ips'], []));
  const topPaths = asArray(pick(summary, ['top_paths', 'top_urls'], []));
  const topRules = asArray(pick(summary, ['top_rules', 'top_rule_ids'], []));

  const grid = el(
    'div',
    { class: 'grid grid--stats' },
    statCard('请求总数', textStat(requests === null ? null : fmtInt(requests))),
    statCard('拦截数', textStat(blocked === null ? null : fmtInt(blocked))),
    statCard('拦截比例', textStat(ratio === null ? null : fmtPercent(ratio))),
    statCard('命中事件', textStat(hits === null ? null : fmtInt(hits)))
  );

  const halves = el('div', { class: 'grid grid--halves' });

  const categoryItems = categories
    .map((item) => ({
      label: String(pick(item, ['name', 'category', 'key', 'label'], '')),
      value: num(pick(item, ['count', 'value', 'total', 'hits'], 0)) || 0,
    }))
    .filter((item) => item.label !== '');
  halves.appendChild(
    card({
      title: '攻击类目分布',
      body:
        categoryItems.length === 0
          ? el('div', { class: 'chart__empty', text: '当前范围内没有类目统计。' })
          : barChart({ items: categoryItems, height: 170 }),
    })
  );

  const rankCard = (title, list, keyNames, emptyText) =>
    card({
      title: title,
      body:
        list.length === 0
          ? el('div', { class: 'chart__empty', text: emptyText })
          : rankList(
              list.slice(0, 10).map((item) => ({
                label: String(pick(item, keyNames, '')),
                value: num(pick(item, ['count', 'value', 'total', 'hits'], 0)) || 0,
              }))
            ),
    });

  halves.appendChild(rankCard('Top 10 攻击源 IP', topIps, ['ip', 'client_ip', 'src', 'key'], '当前范围内没有攻击源。'));
  halves.appendChild(rankCard('Top 10 被攻击路径', topPaths, ['path', 'url', 'key'], '当前范围内没有路径统计。'));
  halves.appendChild(rankCard('Top 10 命中规则', topRules, ['id', 'rule_id', 'key'], '当前范围内没有命中规则。'));

  return [grid, halves];
}

function summaryIsEmpty(summary) {
  if (!summary || typeof summary !== 'object') return true;
  const keys = ['requests_total', 'total_requests', 'blocked_total', 'events_total', 'categories', 'top_ips', 'top_paths', 'top_rules'];
  for (const key of keys) {
    const value = summary[key];
    if (Array.isArray(value) ? value.length > 0 : value !== undefined && value !== null) return false;
  }
  return true;
}

export function render(container) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  const statusRes = createResource(() => api.status());
  const summaryRes = createResource(() => api.metricsSummary());
  const seriesRes = createResource(() => api.timeseries(ui.get().range));

  const chartHint = el('span', { class: 'card__hint', text: 'GET /metrics/timeseries?range=' + ui.get().range });
  const rangeSelect = selectInput(RANGES, {
    value: ui.get().range,
    onChange: (value) => {
      ui.set({ range: value });
      chartHint.textContent = 'GET /metrics/timeseries?range=' + value;
      seriesRes.load();
    },
  });

  page.appendChild(
    pageHeader('概览', {
      subtitle: '数据来自 /api/v1/status、/metrics/summary、/metrics/timeseries',
      actions: [rangeSelect],
    })
  );

  const statusCard = card({ title: '系统状态', hint: 'GET /status' });
  bindState(statusCard.querySelector('.card__body'), statusRes, {
    loadingTitle: '读取运行状态…',
    onRetry: () => statusRes.load(),
    empty: { title: '后端未返回状态' },
    render: renderStatus,
  });

  const summaryCard = card({ title: '流量与攻击摘要', hint: 'GET /metrics/summary' });
  bindState(summaryCard.querySelector('.card__body'), summaryRes, {
    loadingTitle: '读取指标…',
    onRetry: () => summaryRes.load(),
    isEmpty: summaryIsEmpty,
    empty: { title: '当前范围内没有指标', hint: '后端没有返回任何请求量或攻击统计。' },
    render: renderSummary,
  });

  const chartCard = card({ title: '请求量 / 拦截量', hint: null });
  chartCard.querySelector('.card__head').appendChild(chartHint);
  bindState(chartCard.querySelector('.card__body'), seriesRes, {
    loadingTitle: '读取时间序列…',
    onRetry: () => seriesRes.load(),
    isEmpty: (payload) => {
      const series = readTimeseries(payload);
      return series.requests.length === 0 && series.blocked.length === 0;
    },
    empty: { title: '当前范围内没有分钟桶数据', hint: '换个时间范围，或确认后端已开启聚合桶。' },
    render: (payload) => {
      const series = readTimeseries(payload);
      return lineChart({
        height: 200,
        series: [
          { name: '请求', tone: 1, points: series.requests },
          { name: '拦截', tone: 2, points: series.blocked },
        ],
        empty: { title: '当前范围内没有分钟桶数据', hint: '后端返回的时间序列为空。' },
      });
    },
  });

  page.appendChild(statusCard);
  page.appendChild(summaryCard);
  page.appendChild(chartCard);

  statusRes.load();
  summaryRes.load();
  seriesRes.load();

  return () => {};
}
