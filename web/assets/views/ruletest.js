// web/assets/views/ruletest.js
// 职责：规则测试台 —— 粘一条真实原始请求（HTTP 报文或 cURL），看完整命中链路。
// 取数：POST /rules/test（与 CLI `donothack test -r` 共用同一个后端实现）。
// 约束：请求报文与 payload 一律 renderCode 展示；没有测试结果时显示明确的空状态，不预填样例数据。

import { api } from '../api.js';
import {
  el,
  card,
  pageHeader,
  badge,
  button,
  banner,
  kvList,
  pillList,
  renderCode,
  selectInput,
  textArea,
  mount,
  pick,
  asArray,
  fmtScore,
  fmtInt,
  fmtMs,
  coerceText,
  sectionTitle,
  errorState,
  loadingBlock,
} from '../dom.js';
import { notify, toastError } from '../components/toast.js';

const MODE_OPTIONS = [
  { value: 'raw', label: '原始 HTTP 报文' },
  { value: 'curl', label: 'cURL 命令' },
];

const VERDICT_TONE = {
  block: 'danger',
  deny: 'danger',
  drop: 'danger',
  log: 'info',
  monitor: 'info',
  pass: 'ok',
  allow: 'ok',
  challenge: 'warn',
};

function verdictBanner(result) {
  const verdict = pick(result, ['verdict', 'action', 'decision'], null);
  const score = pick(result, ['score', 'total_score'], null);
  const threshold = pick(result, ['threshold', 'score_threshold'], null);
  const mode = pick(result, ['mode', 'detect_mode'], null);
  const key = String(verdict || '').toLowerCase();
  const tone = VERDICT_TONE[key] || 'info';
  const scoreText = score === null ? '' : '（分数 ' + fmtScore(score) + (threshold === null ? '' : ' / 阈值 ' + fmtInt(threshold)) + '）';
  const title =
    'verdict: ' +
    (verdict === null ? '—' : String(verdict).toUpperCase()) +
    scoreText +
    (mode === null ? '' : '　模式 ' + String(mode));
  return banner(tone, title, el('div', {
    class: 'sm muted',
    text: '这条结果来自后端 /rules/test —— 与 CLI 完全同一条链路，控制台不做任何本地推断。',
  }));
}

function hitNode(hit) {
  const ruleId = pick(hit, ['rule_id', 'id', 'rule'], '—');
  const target = pick(hit, ['target', 'param', 'param_name', 'arg'], null);
  const category = pick(hit, ['category', 'class'], null);
  const transforms = asArray(pick(hit, ['transforms', 'transform_chain'], []));
  const before = pick(hit, ['before', 'value_before', 'raw', 'original'], null);
  const after = pick(hit, ['after', 'value_after', 'decoded', 'transformed'], null);
  const operator = pick(hit, ['operator', 'op'], null);
  const matched = pick(hit, ['matched', 'match', 'result'], null);
  const fingerprint = pick(hit, ['fingerprint', 'detail', 'description'], null);
  const delta = pick(hit, ['score', 'delta', 'score_delta'], null);
  const total = pick(hit, ['total', 'score_total', 'cumulative'], null);

  return el(
    'div',
    { class: 'hit ' + (matched ? 'hit--match' : 'hit--miss') },
    el(
      'div',
      { class: 'hit__head' },
      el('span', { class: 'mono strong', text: String(ruleId) }),
      target ? el('span', { class: 'pill', text: 'target: ' + String(target) }) : null,
      category ? badge(String(category), 'info') : null,
      operator ? el('span', { class: 'sm', text: 'operator: ' + String(operator) }) : null,
      matched === null ? null : badge(matched ? 'MATCH' : 'NO MATCH', matched ? 'danger' : 'neutral'),
      delta === null ? null : el('span', { class: 'num sm', text: 'score ' + fmtScore(delta) + (total === null ? '' : ' → total ' + fmtScore(total)) })
    ),
    transforms.length > 0
      ? el('div', { class: 'stack-1' }, el('div', { class: 'xs faint', text: 'transforms' }), pillList(transforms.map((t) => String(t))))
      : null,
    fingerprint ? el('div', { class: 'sm muted', text: 'fingerprint: ' + String(fingerprint) }) : null,
    before !== null || after !== null
      ? el(
          'div',
          { class: 'stack-2' },
          renderCode(before, { label: 'before', tight: true }),
          renderCode(after, { label: 'after', tight: true })
        )
      : null
  );
}

function phaseTitle(phase) {
  const name = pick(phase, ['phase', 'name', 'stage'], null);
  const hits = asArray(pick(phase, ['hits', 'matches', 'rules'], []));
  return 'phase ' + (name === null ? '?' : String(name)) + '（' + hits.length + ' 条命中）';
}

function resultBody(result) {
  const blocks = [];
  blocks.push(verdictBanner(result));

  const phases = asArray(pick(result, ['phases', 'stages'], []));
  const hits = asArray(pick(result, ['hits', 'matches', 'rules', 'detections'], []));

  if (phases.length > 0) {
    const list = el('div', { class: 'sublist' });
    for (const phase of phases) {
      const phaseHits = asArray(pick(phase, ['hits', 'matches', 'rules'], []));
      list.appendChild(
        el(
          'div',
          { class: 'phase' },
          el('div', { class: 'phase__head' }, el('span', { text: phaseTitle(phase) })),
          el(
            'div',
            { class: 'phase__body' },
            phaseHits.length === 0
              ? el('div', { class: 'sm faint', text: '（无命中）' })
              : phaseHits.map(hitNode)
          )
        )
      );
    }
    blocks.push(el('div', { class: 'stack-2' }, sectionTitle('命中链路'), list));
  } else if (hits.length > 0) {
    const byPhase = new Map();
    for (const hit of hits) {
      const key = String(pick(hit, ['phase', 'stage'], '?'));
      if (!byPhase.has(key)) byPhase.set(key, []);
      byPhase.get(key).push(hit);
    }
    const list = el('div', { class: 'sublist' });
    for (const key of Array.from(byPhase.keys())) {
      list.appendChild(
        el(
          'div',
          { class: 'phase' },
          el('div', { class: 'phase__head' }, el('span', { text: 'phase ' + key + '（' + byPhase.get(key).length + ' 条命中）' })),
          el('div', { class: 'phase__body' }, byPhase.get(key).map(hitNode))
        )
      );
    }
    blocks.push(el('div', { class: 'stack-2' }, sectionTitle('命中链路'), list));
  } else {
    blocks.push(
      el(
        'div',
        { class: 'stack-2' },
        sectionTitle('命中链路'),
        el('div', { class: 'chart__empty', text: '这条请求没有命中任何规则（phase1 / phase2 都没有命中）。' })
      )
    );
  }

  const trace = pick(result, ['trace', 'log', 'trace_lines', 'explain'], null);
  if (trace !== null) {
    const text = Array.isArray(trace) ? trace.map((line) => coerceText(line)).join('\n') : coerceText(trace);
    blocks.push(el('div', { class: 'stack-2' }, sectionTitle('判定轨迹'), renderCode(text, { label: 'TRACE', meta: '后端原始输出' })));
  }

  const parsed = pick(result, ['parsed', 'request', 'parsed_request'], null);
  if (parsed && typeof parsed === 'object') {
    blocks.push(
      el(
        'div',
        { class: 'stack-2' },
        sectionTitle('解析结果'),
        kvList([
          { k: '方法', v: coerceText(pick(parsed, ['method'], '—')) },
          { k: '路径', v: el('span', { class: 'mono wrap-anywhere', text: coerceText(pick(parsed, ['path', 'url', 'uri'], '—')) }) },
          { k: 'Host', v: pick(parsed, ['host', 'authority'], null) === null ? null : coerceText(pick(parsed, ['host', 'authority'])) },
          { k: '参数个数', v: asArray(pick(parsed, ['args', 'params', 'arguments'], [])).length || null },
        ])
      )
    );
  }

  const timing = pick(result, ['duration_ms', 'latency_ms', 'elapsed_ms', 'took_ms'], null);
  if (timing !== null) {
    blocks.push(el('div', { class: 'xs faint', text: '后端判定耗时 ' + fmtMs(timing) }));
  }

  return blocks;
}

export function render(container) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  const inputArea = textArea({
    rows: 16,
    placeholder:
      'GET /search?q=1%27%20OR%201%3D1-- HTTP/1.1\nHost: example.com\nUser-Agent: curl/8\n\n',
  });
  const modeSelect = selectInput(MODE_OPTIONS, { value: 'raw' });
  const resultHost = el('div', { class: 'stack-2' });
  let busy = false;

  resultHost.appendChild(
    el('div', { class: 'chart__empty', text: '还没有测试结果：粘一条真实请求后点「运行测试」。' })
  );

  async function run() {
    if (busy) return;
    const text = inputArea.value;
    if (!text || text.trim() === '') {
      notify.warn('请先粘贴原始请求报文或 cURL 命令');
      inputArea.focus();
      return;
    }
    busy = true;
    runButton.disabled = true;
    mount(resultHost, loadingBlock('后端正在跑完整链路…'));
    try {
      const payload = await api.testRule({ raw: text, format: modeSelect.value });
      mount(resultHost, resultBody(payload || {}));
    } catch (err) {
      mount(
        resultHost,
        errorState(err, {
          title: '测试失败',
          hint:
            err && err.code === 'not_found'
              ? '后端还没有实现 POST /rules/test。'
              : '请求没能完成判定；报文解析失败时后端会返回 {error:{code,message,detail}}。',
          onRetry: () => run(),
        })
      );
      if (!(err && err.code === 'unauthenticated')) toastError(err, '测试失败');
    } finally {
      busy = false;
      runButton.disabled = false;
    }
  }

  const runButton = button('运行测试', { tone: 'primary', onClick: () => run() });

  page.appendChild(
    pageHeader('规则测试台', {
      subtitle: 'POST /rules/test —— 与 CLI donothack test -r 共用同一个实现',
      actions: [modeSelect, runButton],
    })
  );

  page.appendChild(
    card({
      title: '原始请求',
      hint: '整段粘贴：请求行 / 头 / 空行 / body。控制台不会解析它，只原样发给后端。',
      body: el(
        'div',
        { class: 'stack-2' },
        el('div', { class: 'field' }, el('span', { class: 'field__label', text: '请求内容' }), inputArea),
        el('div', {
          class: 'xs faint',
          text: '提示：请求里的 payload 会由后端做可打印化后回传；本页只负责展示，不做任何解码推断。',
        })
      ),
    })
  );

  page.appendChild(card({ title: '判定链路', body: resultHost }));

  return () => {};
}
