// web/assets/views/rules.js
// 职责：规则管理页 —— 规则集列表与筛选、单条规则抽屉（YAML 原文 / 命中统计 / 正负样本 / 启停）、
//       YAML 校验（保存前强制）、规则集 reload、变更影响预演。
// 取数：GET /rules、GET /rules/:id、PATCH /rules/:id、POST /rules/validate、GET /rulesets、
//       POST /rulesets/reload、POST /rulesets/preview。
// 约束：YAML 与样本一律用 renderCode 展示；启停走 PATCH（后端侧对应 control.Apply + Mutation）。

import { api, warningsOf, snapshotVersionOf } from '../api.js';
import { createResource } from '../store.js';
import {
  el,
  card,
  pageHeader,
  badge,
  button,
  toolbar,
  kvList,
  textInput,
  selectInput,
  renderCode,
  bindState,
  pick,
  asArray,
  fmtInt,
  fmtTime,
  fmtRelative,
  sectionTitle,
  coerceText,
} from '../dom.js';
import { renderTable } from '../components/table.js';
import { openDrawer, closeDrawer } from '../components/drawer.js';
import { confirmDialog, openDialog, KEEP_OPEN } from '../components/modal.js';
import { notify, toastError, showWarnings } from '../components/toast.js';

const SEVERITY_TONE = {
  critical: 'danger',
  high: 'danger',
  medium: 'warn',
  low: 'info',
  info: 'neutral',
};

const SEVERITY_OPTIONS = [
  { value: '', label: '全部严重度' },
  { value: 'critical', label: 'critical' },
  { value: 'high', label: 'high' },
  { value: 'medium', label: 'medium' },
  { value: 'low', label: 'low' },
];

const ENABLED_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'true', label: '已启用' },
  { value: 'false', label: '已停用' },
];

function severityBadge(severity) {
  const key = String(severity === null || severity === undefined ? '' : severity).toLowerCase();
  return badge(severity === null || severity === undefined || severity === '' ? '—' : String(severity), SEVERITY_TONE[key] || 'neutral');
}

function enabledBadge(enabled) {
  if (enabled === null || enabled === undefined) return badge('未知', 'neutral');
  return badge(enabled ? '已启用' : '已停用', enabled ? 'ok' : 'neutral');
}

function ruleIdOf(rule) {
  return pick(rule, ['id', 'rule_id', 'sid'], null);
}

function ruleRowsOf(payload) {
  const list = asArray(payload, ['rules', 'items', 'data']);
  return list;
}

/* ── 单条规则抽屉 ───────────────────────────────────────────── */

function ruleDetailBody(rule) {
  const blocks = [];
  const id = ruleIdOf(rule);
  const enabled = pick(rule, ['enabled', 'active'], null);
  const yaml = pick(rule, ['yaml', 'source', 'text', 'raw'], null);
  const hits = pick(rule, ['hits_total', 'hits', 'hit_count', 'stats.hits'], null);
  const lastHit = pick(rule, ['last_hit_at', 'last_hit', 'stats.last_hit_at'], null);
  const description = pick(rule, ['description', 'desc', 'message', 'name'], null);
  const category = pick(rule, ['category', 'class', 'tags.0'], null);
  const severity = pick(rule, ['severity', 'level'], null);
  const file = pick(rule, ['file', 'source_file', 'ruleset', 'path'], null);
  const positive = asArray(pick(rule, ['positive_samples', 'positives', 'examples.positive'], []));
  const negative = asArray(pick(rule, ['negative_samples', 'negatives', 'examples.negative'], []));

  blocks.push(
    kvList([
      { k: '规则 ID', v: id ? el('span', { class: 'mono', text: String(id) }) : null },
      { k: '状态', v: enabledBadge(enabled) },
      { k: '类目', v: category === null ? null : String(category) },
      { k: '严重度', v: severityBadge(severity) },
      { k: '来源文件', v: file === null ? null : el('span', { class: 'mono', text: String(file) }) },
      { k: '描述', v: description === null ? null : String(description) },
      { k: '命中次数', v: hits === null ? null : fmtInt(hits) + (lastHit ? '（最近 ' + fmtRelative(lastHit) + '）' : '') },
    ])
  );

  blocks.push(el('div', { class: 'stack-2' }, sectionTitle('规则 YAML 原文'), renderCode(yaml, { label: 'YAML' })));

  if (positive.length > 0 || negative.length > 0) {
    const samples = el('div', { class: 'sublist' });
    if (positive.length > 0) {
      samples.appendChild(el('div', { class: 'xs faint', text: '正样本（应当命中）' }));
      for (const sample of positive) samples.appendChild(renderCode(sample, { label: '应该命中', tight: true }));
    }
    if (negative.length > 0) {
      samples.appendChild(el('div', { class: 'xs faint', text: '负样本（不应命中）' }));
      for (const sample of negative) samples.appendChild(renderCode(sample, { label: '不应命中', tight: true }));
    }
    blocks.push(el('div', { class: 'stack-2' }, sectionTitle('正负样本'), samples));
  } else {
    blocks.push(
      el(
        'div',
        { class: 'stack-2' },
        sectionTitle('正负样本'),
        el('div', { class: 'chart__empty', text: '后端未在规则详情里返回正负样本；样本是保存前自测的依据，缺失时不要改这条规则。' })
      )
    );
  }

  return blocks;
}

function previewNode(preview) {
  if (!preview || typeof preview !== 'object') return null;
  const affected = pick(preview, ['affected_rules', 'affected', 'rule_count', 'changed_rules'], null);
  const version = pick(preview, ['snapshot_version', 'version_after', 'ruleset_version'], null);
  const warns = asArray(pick(preview, ['warnings', 'side_effects'], []));
  const rows = [];
  if (affected !== null) rows.push({ k: '受影响规则数', v: fmtInt(affected) });
  if (version !== null) rows.push({ k: '快照版本（预演）', v: el('span', { class: 'mono', text: String(version) }) });
  const diffLines = asArray(pick(preview, ['diff', 'lines', 'changes'], []));
  if (diffLines.length > 0) {
    const text = diffLines
      .map((line) => (typeof line === 'string' ? line : coerceText(pick(line, ['text', 'line', 'value'], ''))))
      .join('\n');
    rows.push({ k: '差异预览', v: renderCode(text, { label: 'DIFF', tight: true }) });
  }
  if (warns.length > 0) {
    rows.push({
      k: '副作用提示',
      v: el(
        'div',
        { class: 'stack-1' },
        warns.map((w) => el('div', { class: 'sm', text: coerceText(typeof w === 'string' ? w : pick(w, ['message', 'code'], '未命名警告')) }))
      ),
    });
  }
  if (rows.length === 0) return null;
  return kvList(rows);
}

function openRuleDrawer(ruleId, ctx, onChanged) {
  const resource = createResource(() => api.rule(ruleId));
  const bodyHost = el('div');
  const actionHost = el('div', { class: 'row row--wrap' });

  const drawer = openDrawer({
    title: '规则 ' + ruleId,
    subtitle: 'GET /rules/:id',
    body: bodyHost,
    actions: [actionHost],
    onClose: () => {
      if (ctx && ctx.params && ctx.params.id) ctx.navigate('/rules');
    },
  });

  let current = null;
  bindState(bodyHost, resource, {
    loadingTitle: '读取规则…',
    onRetry: () => resource.load(),
    empty: { title: '后端未返回该规则' },
    render: (rule) => {
      current = rule;
      return ruleDetailBody(rule);
    },
  });

  function rebuildActions() {
    actionHost.replaceChildren();
    if (!current) return;
    const enabled = pick(current, ['enabled', 'active'], null);
    actionHost.appendChild(
      button(enabled ? '停用这条规则' : '启用这条规则', {
        tone: enabled ? 'danger' : 'primary',
        size: 'sm',
        onClick: () => toggleRule(ruleId, !enabled, resource, onChanged),
      })
    );
    actionHost.appendChild(
      button('校验 YAML', {
        size: 'sm',
        onClick: () => openValidateDialog(pick(current, ['yaml', 'source', 'text', 'raw'], '')),
      })
    );
  }

  resource.subscribe(() => rebuildActions());
  resource.load().then(rebuildActions);
  rebuildActions();
  return drawer;
}

async function toggleRule(ruleId, nextEnabled, resource, onChanged) {
  let preview = null;
  let previewError = null;
  try {
    preview = await api.previewMutation({ kind: 'rule.enabled', id: ruleId, enabled: nextEnabled });
  } catch (err) {
    if (err && err.code !== 'not_found') previewError = err;
  }

  const bodyParts = [];
  const rendered = previewNode(preview);
  if (rendered) {
    bodyParts.push(el('div', { class: 'sm', text: '影响预演（/rulesets/preview）：' }), rendered);
  } else {
    bodyParts.push(
      el('div', {
        class: 'sm muted',
        text: previewError
          ? '影响预演失败：' + (previewError.message || '未知错误') + '。继续操作将直接应用变更。'
          : '后端未返回影响预演。继续操作将直接应用变更（PATCH /rules/' + ruleId + '）。',
      })
    );
  }

  const ok = await confirmDialog({
    title: nextEnabled ? '启用规则 ' + ruleId : '停用规则 ' + ruleId,
    description: '启停不是改文件，而是生成一条覆盖层 Mutation 走 control.Apply；失败会整体回滚。',
    body: el('div', { class: 'stack-2' }, bodyParts),
    confirmText: nextEnabled ? '启用' : '停用',
    danger: !nextEnabled,
  });
  if (!ok) return;

  try {
    const result = await api.patchRule(ruleId, { enabled: nextEnabled });
    const snapshot = snapshotVersionOf(result);
    notify.ok(
      (nextEnabled ? '已启用 ' : '已停用 ') + ruleId + (snapshot ? '（快照 ' + snapshot + '）' : ''),
      { detail: 'PATCH /rules/' + ruleId }
    );
    showWarnings(warningsOf(result));
    if (resource) await resource.load();
    if (typeof onChanged === 'function') onChanged();
  } catch (err) {
    toastError(err, '切换规则状态失败');
  }
}

async function openValidateDialog(yamlText) {
  const area = el('textarea', { attrs: { rows: '14', spellcheck: 'false' } });
  area.value = yamlText || '';
  const resultHost = el('div');

  await openDialog({
    title: '规则 YAML 校验',
    description: 'POST /rules/validate：语法、算子名、字面量长度、正负样本硬约束都会在这里检查；校验通过不代表已保存。',
    wide: true,
    body: el(
      'div',
      { class: 'stack-2' },
      el('div', { class: 'field' }, el('span', { class: 'field__label', text: 'YAML' }), area),
      resultHost
    ),
    cancelText: '关闭',
    submitText: '校验',
    danger: false,
    onSubmit: async () => {
      const payload = await api.validateRules({ yaml: area.value });
      resultHost.replaceChildren();
      const okFlag = pick(payload, ['ok', 'valid'], null);
      resultHost.appendChild(
        el(
          'div',
          { class: 'stack-2' },
          okFlag === false ? badge('校验未通过', 'danger') : badge('校验通过', 'ok'),
          kvList(
            [
              { k: '算子 / 变换', v: asArray(pick(payload, ['operators', 'used_operators'], [])).join(', ') || null },
              {
                k: '正负样本自测',
                v:
                  pick(payload, ['samples.ok', 'self_test.ok', 'samples_passed'], null) === null
                    ? null
                    : String(pick(payload, ['samples.ok', 'self_test.ok', 'samples_passed'])),
              },
              {
                k: '错误',
                v: asArray(pick(payload, ['errors', 'problems'], [])).length
                  ? renderCode(
                      asArray(pick(payload, ['errors', 'problems'], []))
                        .map((e) => coerceText(typeof e === 'string' ? e : pick(e, ['message', 'error', 'msg'], '')))
                        .join('\n'),
                      { label: '错误', tight: true }
                    )
                  : null,
              },
            ].filter((row) => row.v !== null)
          )
        )
      );
      return KEEP_OPEN;
    },
  });
}

export function render(container, ctx) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  const filters = { q: '', category: '', severity: '', enabled: '', file: '' };
  const tableHost = el('div');
  let state = { status: 'loading', data: null, error: null };

  function params() {
    const out = {};
    if (filters.q) out.q = filters.q;
    if (filters.category) out.category = filters.category;
    if (filters.severity) out.severity = filters.severity;
    if (filters.enabled) out.enabled = filters.enabled;
    if (filters.file) out.file = filters.file;
    return out;
  }

  function paint() {
    renderTable(tableHost, state, {
      columns: [
        { key: 'id', label: '规则 ID', render: (row) => el('span', { class: 'mono', text: String(pick(row, ['id', 'rule_id', 'sid'], '—')) }) },
        { key: 'category', label: '类目', render: (row) => el('span', { text: String(pick(row, ['category', 'class'], '—')) }) },
        { key: 'severity', label: '严重度', render: (row) => severityBadge(pick(row, ['severity', 'level'])) },
        { key: 'file', label: '来源文件', render: (row) => el('span', { class: 'mono xs', text: String(pick(row, ['file', 'source_file', 'ruleset', 'path'], '—')) }) },
        { key: 'enabled', label: '状态', render: (row) => enabledBadge(pick(row, ['enabled', 'active'], null)) },
        { key: 'hits', label: '命中次数', align: 'right', render: (row) => el('span', { class: 'num', text: fmtInt(pick(row, ['hits_total', 'hits', 'hit_count'], null)) }) },
        { key: 'description', label: '描述', wrap: true, render: (row) => el('span', { class: 'sm muted', text: String(pick(row, ['description', 'desc', 'name', 'message'], '—')) }) },
      ],
      empty: {
        title: '没有匹配的规则',
        hint: '调整筛选条件；如果规则集还没加载，先去「规则集」里执行一次 reload。',
      },
      loadingTitle: '读取规则集…',
      onRetry: () => load(),
      onRowClick: (row) => {
        const id = ruleIdOf(row);
        if (!id) {
          notify.warn('这条规则没有 id 字段');
          return;
        }
        ctx.navigate('/rules/' + encodeURIComponent(String(id)));
      },
      totalOf: (data) => (data && typeof data.total === 'number' ? data.total : undefined),
      note: '点击行查看 YAML 与正负样本',
    });
  }

  async function load() {
    state = { status: 'loading', data: null, error: null };
    paint();
    try {
      const payload = await api.rules(params());
      const items = ruleRowsOf(payload);
      const total = Number(pick(payload, ['total', 'count'], NaN));
      state = {
        status: 'ready',
        data: { items: items, total: Number.isFinite(total) ? total : undefined },
        error: null,
      };
    } catch (err) {
      state = { status: err && err.code === 'unauthenticated' ? 'unauthenticated' : 'error', data: null, error: err };
    }
    paint();
  }

  async function reloadRulesets() {
    const ok = await confirmDialog({
      title: '重新加载规则集',
      description: 'POST /rulesets/reload：从磁盘重新解析规则并做内置语料自测，成功才原子替换快照。',
      confirmText: '重新加载',
    });
    if (!ok) return;
    try {
      const result = await api.reloadRulesets();
      notify.ok('规则集已重新加载' + (snapshotVersionOf(result) ? '（快照 ' + snapshotVersionOf(result) + '）' : ''));
      showWarnings(warningsOf(result));
      await load();
      if (rulesetsRes.get().status !== 'loading') rulesetsRes.load();
    } catch (err) {
      toastError(err, '重新加载失败');
    }
  }

  const rulesetsRes = createResource(() => api.rulesets());

  page.appendChild(
    pageHeader('规则管理', {
      subtitle: '规则集来自内存快照；启停是一条 Mutation，走 control.Apply',
      actions: [
        button('校验 YAML', { size: 'sm', onClick: () => openValidateDialog('') }),
        button('重新加载规则集', { size: 'sm', danger: true, onClick: reloadRulesets }),
        button('刷新', { size: 'sm', onClick: () => load() }),
      ],
    })
  );

  const rulesetsCard = card({ title: '规则集', hint: 'GET /rulesets', body: el('div') });
  bindState(rulesetsCard.querySelector('.card__body'), rulesetsRes, {
    loadingTitle: '读取规则集列表…',
    onRetry: () => rulesetsRes.load(),
    empty: { title: '后端未返回规则集列表' },
    render: (payload) => {
      const list = asArray(payload, ['rulesets', 'items', 'data']);
      if (list.length === 0) return el('div', { class: 'chart__empty', text: '没有规则集。' });
      const rows = el('div', { class: 'sublist' });
      for (const item of list) {
        const enabled = pick(item, ['enabled', 'active'], null);
        rows.appendChild(
          el(
            'div',
            { class: 'row row--between' },
            el(
              'div',
              { class: 'stack-1' },
              el('span', { class: 'mono', text: String(pick(item, ['file', 'name', 'path', 'id'], '—')) }),
              el('span', {
                class: 'xs faint',
                text:
                  '规则 ' + fmtInt(pick(item, ['rules', 'count', 'rule_count'], null)) +
                  '　版本 ' + coerceText(pick(item, ['version', 'hash'], '—')) +
                  '　加载于 ' + fmtTime(pick(item, ['loaded_at', 'mtime'], null)),
              })
            ),
            enabled === null ? el('span') : enabledBadge(enabled)
          )
        );
      }
      return rows;
    },
  });

  page.appendChild(
    card({
      flush: true,
      body: [
        toolbar(
          el('div', { class: 'field toolbar__grow' }, el('span', { class: 'field__label', text: '关键词' }), textInput({ value: filters.q, placeholder: '规则 ID 或描述', onInput: (v) => { filters.q = v; }, onEnter: (v) => { filters.q = v; load(); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '类目' }), textInput({ value: filters.category, placeholder: '如 sqli', onInput: (v) => { filters.category = v; }, onEnter: (v) => { filters.category = v; load(); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '严重度' }), selectInput(SEVERITY_OPTIONS, { value: filters.severity, onChange: (v) => { filters.severity = v; load(); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '状态' }), selectInput(ENABLED_OPTIONS, { value: filters.enabled, onChange: (v) => { filters.enabled = v; load(); } })),
          el('div', { class: 'field' }, el('span', { class: 'field__label', text: '来源文件' }), textInput({ value: filters.file, placeholder: '按文件过滤', onInput: (v) => { filters.file = v; }, onEnter: (v) => { filters.file = v; load(); } })),
          button('查询', { size: 'sm', tone: 'primary', onClick: () => load() }),
        button('同步规则', {
          size: 'sm',
          onClick: async () => {
            // 手动同步：从配置的源（默认取最新发布 tag）拉规则，先自测通过才替换。
            // 失败必须说出来 —— 否则界面看着正常、其实还在用旧规则。
            try {
              const res = await api.rulesSync();
              const warn = asArray(pick(res || {}, ['warnings'], []))[0];
              notify.info(warn ? String(warn) : '规则集已同步');
              load();
            } catch (err) {
              notify.error('规则同步失败（本机规则未改动）', {
                detail: String(err && err.message ? err.message : err),
                timeout: 0,
              });
            }
          },
        })
        ),
        tableHost,
      ],
    })
  );

  page.appendChild(rulesetsCard);
  page.appendChild(
    el('div', {
      class: 'notice',
      text:
        '提示：§5 未定义"新建/保存规则正文"的端点（只有 PATCH /rules/:id 的启停），所以这里只提供 YAML 校验，不提供落盘保存。',
    })
  );

  load();
  rulesetsRes.load();

  if (ctx && ctx.params && ctx.params.id) {
    openRuleDrawer(decodeURIComponent(ctx.params.id), ctx, load);
  }

  return () => closeDrawer();
}
