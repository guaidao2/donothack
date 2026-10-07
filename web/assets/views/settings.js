// web/assets/views/settings.js
// 职责：系统设置页 —— 认证（口令/TOTP/api_token）、通知、日志与配置、备份、版本信息。
// 取数：POST /password、POST /totp/enroll、GET/PUT /notify、POST /notify/test、
//       GET /config、PUT /config、GET /config/diff、POST /config/reload、GET /backup、POST /restore、
//       GET /status、GET /session。
// 约束：拿不到的字段一律显示 "—"；没有端点的能力（如 api_token 轮换）明确写成"后端未定义"，不做假按钮。

import { api, backupUrl, warningsOf } from '../api.js';
import { createResource, session } from '../store.js';
import {
  el,
  card,
  pageHeader,
  badge,
  banner,
  button,
  linkButton,
  tabs,
  kvList,
  checkbox,
  field,
  textInput,
  renderCode,
  bindState,
  pick,
  asArray,
  fmtInt,
  fmtBytes,
  fmtSeconds,
  fmtTime,
  coerceText,
  sectionTitle,
} from '../dom.js';
import { openDialog, confirmDialog, alertDialog, KEEP_OPEN } from '../components/modal.js';
import { notify, toastError, showWarnings } from '../components/toast.js';

/* ── 小工具 ─────────────────────────────────────────────────── */

function setPath(target, path, value) {
  const parts = String(path).split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    if (!cursor[parts[i]] || typeof cursor[parts[i]] !== 'object') cursor[parts[i]] = {};
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function yesNo(value, tones) {
  if (value === null || value === undefined) return null;
  const tone = tones || { yes: 'ok', no: 'neutral' };
  return badge(value ? '是' : '否', value ? tone.yes : tone.no);
}

/* ── 认证 ───────────────────────────────────────────────────── */

function authSection(host) {
  const sessionRes = createResource(() => api.session());
  const body = el('div', { class: 'stack-2' });
  host.appendChild(card({ title: '登录与会话', hint: 'GET /session', body: body }));

  bindState(body, sessionRes, {
    loadingTitle: '读取会话…',
    onRetry: () => sessionRes.load(),
    empty: { title: '后端未返回会话信息' },
    render: (payload) => {
      const actor = pick(payload, ['actor', 'username', 'user', 'name'], session.get().actor);
      const idle = pick(payload, ['idle_timeout_s', 'idle_timeout', 'timeout_s'], null);
      const totp = pick(payload, ['totp_enabled', 'totp'], null);
      const mode = pick(payload, ['auth_mode', 'mode'], null);
      return el(
        'div',
        { class: 'stack-2' },
        kvList(
          [
            { k: '当前账号', v: actor ? el('span', { class: 'mono', text: String(actor) }) : null },
            { k: '认证模式', v: mode === null ? null : coerceText(mode) },
            { k: '闲置超时', v: idle === null ? null : fmtSeconds(idle) },
            { k: 'TOTP 两步验证', v: totp === null ? null : yesNo(totp, { yes: 'ok', no: 'warn' }) },
          ].filter((row) => row.v !== null)
        ),
        el(
          'div',
          { class: 'row row--wrap' },
          button('修改登录口令', { size: 'sm', tone: 'primary', onClick: () => changePassword(sessionRes) }),
          button('绑定 / 重绑 TOTP', { size: 'sm', onClick: () => enrollTotp() })
        ),
        el('div', {
          class: 'xs faint',
          text:
            'api_token 的生成与轮换：§5 的端点清单里没有对应接口（CLI 用的 X-Donothack-Token 走配置项 admin.api_token），' +
            '所以这里不放按钮，避免出现按了没反应的操作。',
        })
      );
    },
  });
  sessionRes.load();

  async function changePassword(res) {
    await openDialog({
      title: '修改登录口令',
      description: 'POST /password：修改后其它会话是否失效由后端决定。',
      fields: [
        // 字段名必须与后端 handlePassword 的 json tag 一致（old_password / new_password）；
        // 后端是 DisallowUnknownFields 的严格解码，写错名字会直接 400，而不是被静默忽略。
        { name: 'old_password', label: '当前口令', type: 'password', required: true },
        { name: 'new_password', label: '新口令', type: 'password', required: true },
        { name: 'confirm', label: '再输一次', type: 'password', required: true },
      ],
      submitText: '修改',
      danger: true,
      onSubmit: async (values) => {
        if (values.new_password !== values.confirm) throw new Error('两次输入的新口令不一致');
        const result = await api.changePassword({
          old_password: values.old_password,
          new_password: values.new_password,
        });
        showWarnings(warningsOf(result));
        notify.ok('口令已修改');
        await res.load();
      },
    });
  }

  async function enrollTotp() {
    try {
      const payload = await api.enrollTotp({});
      const secret = pick(payload, ['secret', 'totp_secret', 'base32'], null);
      const uri = pick(payload, ['otpauth_url', 'uri', 'url'], null);
      const qr = pick(payload, ['qr_data_uri', 'qr', 'qr_png'], null);

      const blocks = [];
      if (typeof qr === 'string' && qr.indexOf('data:image/') === 0) {
        const img = el('img', { attrs: { alt: 'TOTP 二维码', width: '180', height: '180' } });
        img.setAttribute('src', qr);
        blocks.push(el('div', { class: 'row' }, img));
      } else {
        blocks.push(
          el('div', {
            class: 'sm muted',
            text:
              '后端没有返回二维码图片（qr_data_uri），本轮前端也没有自写 QR 编码器 —— ' +
              '请手工把下面的密钥填进认证器 App（TOTP 标准，30 秒周期）。',
          })
        );
      }
      if (secret) blocks.push(renderCode(secret, { label: 'TOTP 密钥（base32）' }));
      if (uri) blocks.push(renderCode(uri, { label: 'otpauth URI' }));

      await alertDialog({ title: 'TOTP 绑定', description: '二维码与密钥只在本次响应里出现，请立即保存。', body: el('div', { class: 'stack-2' }, blocks) });
      sessionRes.load();
    } catch (err) {
      toastError(err, 'TOTP 绑定失败');
    }
  }
}

/* ── 通知 ───────────────────────────────────────────────────── */

function notifySection(host) {
  const resource = createResource(() => api.notify());
  const body = el('div', { class: 'stack-2' });
  host.appendChild(card({ title: '告警通知', hint: 'GET /notify', body: body }));

  bindState(body, resource, {
    loadingTitle: '读取通知配置…',
    onRetry: () => resource.load(),
    empty: { title: '后端未返回通知配置' },
    render: (payload) => {
      const enabled = pick(payload, ['enabled'], null);
      const url = pick(payload, ['webhook', 'url', 'endpoint', 'webhook_url'], null);
      const alerts = asArray(pick(payload, ['alerts', 'rules', 'triggers'], []));
      const blocks = [];

      blocks.push(
        kvList(
          [
            { k: '通知开关', v: yesNo(enabled) },
            { k: 'webhook', v: url === null ? null : el('span', { class: 'mono wrap-anywhere', text: String(url) }) },
          ].filter((row) => row.v !== null)
        )
      );

      if (alerts.length > 0) {
        const list = el('div', { class: 'stack-1' });
        for (const alert of alerts) {
          const on = pick(alert, ['enabled', 'active'], null);
          list.appendChild(
            el(
              'div',
              { class: 'row row--between' },
              el('span', { class: 'sm', text: String(pick(alert, ['name', 'key', 'event'], '—')) }),
              el(
                'span',
                { class: 'row' },
                el('span', {
                  class: 'xs faint',
                  text: pick(alert, ['threshold', 'value', 'condition'], null) === null ? '' : '阈值 ' + coerceText(pick(alert, ['threshold', 'value', 'condition'])),
                }),
                on === null ? el('span') : badge(on ? '已启用' : '已停用', on ? 'ok' : 'neutral')
              )
            )
          );
        }
        blocks.push(el('div', { class: 'stack-1' }, sectionTitle('告警规则'), list));
      } else {
        blocks.push(el('div', { class: 'chart__empty', text: '后端没有返回告警规则列表（拦截激增 / 规则加载失败 / 上游不可用 / 降级触发）。' }));
      }

      blocks.push(renderCode(payload, { label: '通知配置原文', meta: 'GET /notify' }));
      blocks.push(
        el(
          'div',
          { class: 'row row--wrap' },
          button('编辑（JSON）', { size: 'sm', tone: 'primary', onClick: () => editNotify(resource) }),
          button('发送测试通知', { size: 'sm', onClick: () => testNotify() })
        )
      );
      return blocks;
    },
  });
  resource.load();

  async function editNotify(res) {
    const current = res.get().data;
    if (!current) {
      notify.warn('还没有读到通知配置');
      return;
    }
    editJsonDialog({
      title: '编辑通知配置',
      description: 'PUT /notify：整体替换通知配置。',
      value: current,
      errorHint: '请检查 JSON 语法',
      onSave: async (parsed) => {
        const result = await api.putNotify(parsed);
        showWarnings(warningsOf(result));
        notify.ok('通知配置已保存');
        await res.load();
      },
    });
  }

  async function testNotify() {
    const ok = await confirmDialog({
      title: '发送测试通知',
      description: 'POST /notify/test：会真的往配置的 webhook 发一条测试消息。',
      confirmText: '发送',
      danger: false,
    });
    if (!ok) return;
    try {
      const result = await api.testNotify({});
      notify.ok('测试通知已发送' + (pick(result, ['status', 'code'], null) === null ? '' : '（HTTP ' + coerceText(pick(result, ['status', 'code'])) + '）'));
    } catch (err) {
      toastError(err, '测试通知失败');
    }
  }
}

/** 通用 JSON 编辑对话框：本地 parse 校验 + 确认后提交。 */
async function editJsonDialog(spec) {
  const area = el('textarea', { attrs: { rows: '18', spellcheck: 'false' } });
  try {
    area.value = JSON.stringify(spec.value, null, 2);
  } catch (err) {
    area.value = '';
  }
  const errorLine = el('div', { class: 'field__error hidden' });

  await openDialog({
    title: spec.title,
    description: spec.description,
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
        errorLine.textContent = 'JSON 解析失败：' + (err && err.message ? err.message : spec.errorHint || '格式错误');
        errorLine.classList.remove('hidden');
        return KEEP_OPEN;
      }
      const ok = await confirmDialog({
        title: '确认保存',
        description: '这是写操作：会立即影响线上行为并记入操作审计。',
        confirmText: '保存',
      });
      if (!ok) return KEEP_OPEN;
      await spec.onSave(parsed);
    },
  });
}

/* ── 日志与配置 ─────────────────────────────────────────────── */

function configSection(host) {
  const resource = createResource(() => api.config());
  const diffRes = createResource(() => api.configDiff());
  const body = el('div', { class: 'stack-2' });
  host.appendChild(card({ title: '运行配置', hint: 'GET /config', body: body }));

  bindState(body, resource, {
    loadingTitle: '读取运行配置…',
    onRetry: () => resource.load(),
    empty: { title: '后端未返回配置' },
    render: (payload) => {
      const blocks = [];
      const capture = pick(payload, ['log.capture_payload', 'capture_payload', 'logs.capture_payload'], null);
      const retention = pick(payload, ['log.retention_days', 'log.retain_days', 'retention_days'], null);
      const maxSize = pick(payload, ['log.max_size_mb', 'log.maxsize_mb'], null);
      const backups = pick(payload, ['log.max_backups', 'log.backups'], null);
      const totalQuota = pick(payload, ['log.total_max_mb', 'log.total_quota_mb'], null);
      const minFree = pick(payload, ['log.min_free_mb'], null);

      blocks.push(
        el(
          'div',
          { class: 'stack-2' },
          sectionTitle('日志'),
          kvList(
            [
              { k: '保留天数', v: retention === null ? null : coerceText(retention) + ' 天' },
              { k: '单文件上限', v: maxSize === null ? null : coerceText(maxSize) + ' MiB' },
              { k: '保留份数', v: backups === null ? null : coerceText(backups) },
              { k: '目录总配额', v: totalQuota === null ? null : coerceText(totalQuota) + ' MiB' },
              { k: '磁盘最低剩余', v: minFree === null ? null : coerceText(minFree) + ' MiB' },
              { k: 'payload 原文抓取', v: capture === null ? null : badge(capture ? '已开启' : '已关闭', capture ? 'danger' : 'ok') },
            ].filter((row) => row.v !== null)
          )
        )
      );

      const controls = el('div', { class: 'row row--wrap' });
      // payload 原文抓取**不是热改项**（改它要改配置落盘后重启），所以这里只显示状态，
      // 不给一个点了必然失败的开关 —— 以前那个勾选框调的是 PUT /config，
      // 而后端有意拒绝整份写配置（405），点了只会得到一个红条。
      controls.appendChild(
        el('span', {
          class: 'sm muted',
          text:
            capture === null
              ? '配置里没有 log.capture_payload 字段。'
              : 'payload 原文抓取改配置里的 log.capture_payload 后重启生效（不是热改项）。',
        })
      );
      controls.appendChild(button('查看与运行中的差异', { size: 'sm', onClick: () => diffRes.load() }));
      controls.appendChild(button('重新加载配置', { size: 'sm', danger: true, onClick: () => reloadConfig(resource) }));
      blocks.push(controls);

      blocks.push(
        banner('info', '其它配置项改哪里', el('div', {
          class: 'sm',
          text:
            '模式与阈值改上面那张"运行模式"卡；限速走 CC 防护与限速页；拦截页走拦截页；规则走规则管理；' +
            '监听地址、上游、TLS、real_ip 这些必须改配置落盘后重启 —— 控制台不提供整份写配置，' +
            '因为静默忽略改不了的字段会让人以为改生效了。',
        }))
      );

      blocks.push(
        banner('warn', 'payload 抓取的内存与合规影响', el('div', {
          class: 'sm',
          text:
            '打开后会记录请求原文：ring buffer 与日志体积都会明显上升（实测全量记录可达 22 MB/s），' +
            '并且原文可能包含口令、Cookie 等敏感信息。打不开是默认值，开之前确认合规允许。',
        }))
      );

      blocks.push(renderCode(payload, { label: '当前配置（只读）', meta: 'GET /config' }));
      return blocks;
    },
  });

  const diffBody = el('div');
  host.appendChild(card({ title: '配置差异（磁盘 vs 运行中）', hint: 'GET /config/diff', body: diffBody }));
  bindState(diffBody, diffRes, {
    loadingTitle: '读取差异…',
    onRetry: () => diffRes.load(),
    empty: { title: '当前没有差异', hint: '磁盘配置与运行中的快照一致。' },
    isEmpty: (payload) => {
      const diff = pick(payload, ['diff', 'lines', 'changes'], null);
      if (diff === null) return true;
      if (typeof diff === 'string') return diff.trim() === '';
      return asArray(diff).length === 0;
    },
    render: (payload) => {
      const diff = pick(payload, ['diff', 'lines', 'changes'], '');
      const text = typeof diff === 'string' ? diff : asArray(diff).map((line) => coerceText(pick(line, ['text', 'line', 'value'], line))).join('\n');
      return renderCode(text, { label: 'DIFF', meta: '磁盘 → 运行中' });
    },
  });
  diffRes.load();
  resource.load();

  async function reloadConfig(res) {
    const ok = await confirmDialog({
      title: '重新加载配置',
      description: 'POST /config/reload：从磁盘重新读取配置并做校验，失败则保持线上不变。',
      confirmText: '重新加载',
      danger: false,
    });
    if (!ok) return;
    try {
      const result = await api.reloadConfig();
      showWarnings(warningsOf(result));
      notify.ok('配置已重新加载');
      await res.load();
      diffRes.load();
    } catch (err) {
      toastError(err, '重新加载失败');
    }
  }
}

/* ── 运行模式（引擎热参数） ─────────────────────────────────────
 *
 * 这一块是"应急切模式"的入口：攻击已经在打的时候，运维要把 detect 改成 block。
 * 在此之前页面上根本没有这条路 —— 只能去磁盘改 config.yaml 再点重载，
 * 而那个"编辑运行配置"对话框点保存必然 405（后端有意拒绝整份写配置）。
 * 现在走 PUT /engine：与 reload 同一条 control.Apply，校验失败会回滚并如实报错。
 */

const ENGINE_MODES = [
  { key: 'detect', label: 'detect 只记录' },
  { key: 'block', label: 'block 拦截' },
  { key: 'mixed', label: 'mixed 按类目' },
];

function engineSection(host) {
  const res = createResource(() => api.engine());
  const body = el('div', { class: 'stack-3' });
  host.appendChild(card({ title: '运行模式', hint: 'GET / PUT /engine', body: body }));

  let draftMode = null;

  bindState(body, res, {
    loadingTitle: '读取引擎参数…',
    onRetry: () => res.load(),
    empty: { title: '后端未返回引擎参数' },
    render: (payload) => {
      const mode = String(pick(payload, ['mode'], '') || '');
      const threshold = pick(payload, ['inbound_anomaly_threshold', 'threshold'], null);
      const banOnBlock = pick(payload, ['ban_on_block'], null);
      const current = draftMode || mode;

      const modeRow = tabs(ENGINE_MODES, {
        active: current,
        onSelect: (key) => {
          draftMode = key;
          res.load();
        },
      });
      modeRow.classList.add('tabs--segmented');

      const thresholdInput = textInput({
        name: 'engine-threshold',
        type: 'number',
        value: threshold === null ? '' : String(threshold),
      });
      thresholdInput.min = '1';

      const apply = button('应用', {
        tone: 'primary',
        size: 'sm',
        onClick: async () => {
          const next = { mode: current };
          const th = Number(thresholdInput.value);
          if (Number.isFinite(th) && th >= 1 && th !== threshold) next.inbound_anomaly_threshold = th;
          // 切到会拦的模式是"立刻开始 403"的语义变化，必须让人确认一次。
          if (current !== mode && (current === 'block' || current === 'mixed')) {
            const okToSwitch = await confirmDialog({
              title: '切换到 ' + current + ' 模式',
              description:
                '切换后达到阈值的请求会立刻被拦截（403）。建议先确认规则集没有误报：' +
                '在 detect 模式下看一眼"攻击事件"里的命中情况再切。',
              confirmText: '切换并生效',
              danger: true,
            });
            if (!okToSwitch) return;
          }
          try {
            const result = await api.setEngine(next);
            showWarnings(warningsOf(result));
            notify.ok('运行模式已更新为 ' + String(pick(result, ['mode'], current)));
            draftMode = null;
            await res.load();
          } catch (err) {
            toastError(err, '切换失败（当前运行参数未改变）');
          }
        },
      });
      if (current === mode) apply.disabled = false;

      const rows = [
        { k: '当前生效', v: badge(mode || '未知', mode === 'block' ? 'danger' : mode === 'mixed' ? 'warn' : 'neutral') },
        {
          k: '命中即封禁',
          v: banOnBlock === null ? null : badge(banOnBlock ? '已开启' : '已关闭', banOnBlock ? 'warn' : 'neutral'),
        },
      ];

      return [
        el(
          'div',
          { class: 'stack-3' },
          modeRow,
          el(
            'div',
            { class: 'row row--wrap' },
            field('入站阈值（分数达到就拦）', thresholdInput, '默认 5；弱信号加起来才够，单条弱规则不会拦'),
            el('div', { class: 'row' }, apply)
          )
        ),
        kvList(rows.filter((r) => r.v !== null)),
        banner(
          'info',
          '三种模式的区别',
          el('div', {
            class: 'sm',
            text:
              'detect：全部只记录，不拦任何请求（上线初期用这个看误报）。' +
              'block：总分达到入站阈值就拦。mixed：按类目分别设阈值，某一类自己达标就拦（需在 config.yaml 里配 category_thresholds）。',
          })
        ),
      ];
    },
  });

  res.load();
}

/** editConfig 曾经在这里提供一个"编辑整份配置并保存"的对话框 —— 那条路点不通：
 *  后端有意拒绝 PUT /config（见 api_config.go 顶部：大部分配置项改了必须重启，
 *  静默忽略会让人以为改生效了），接口返回 405 并指路到各专用端点。
 *  所以这里不再提供整份编辑：能热改的走各自的专用入口，改不了的一律如实说"要重启"。
 */

/* ── 备份 ───────────────────────────────────────────────────── */

function backupSection(host) {
  const body = el('div', { class: 'stack-2' });
  host.appendChild(card({ title: '备份与导入', hint: 'GET /backup、POST /restore', body: body }));

  const fileInput = el('input', { attrs: { type: 'file', accept: '.tar.gz,.tgz,.tar' } });
  const previewHost = el('div', { class: 'stack-2' });
  const confirmBtn = button('确认导入', { tone: 'danger', size: 'sm', disabled: true });
  let previewOk = false;

  confirmBtn.addEventListener('click', async () => {
    if (!previewOk || !fileInput.files || fileInput.files.length === 0) return;
    const ok = await confirmDialog({
      title: '确认导入备份',
      description: 'POST /restore：会用备份内容覆盖当前配置与规则集，此操作不可撤销。',
      confirmText: '导入',
    });
    if (!ok) return;
    try {
      const form = new FormData();
      form.append('file', fileInput.files[0]);
      const result = await api.restore(form, {});
      showWarnings(warningsOf(result));
      notify.ok('备份已导入');
    } catch (err) {
      toastError(err, '导入失败');
    }
  });

  const previewBtn = button('预演导入影响', {
    size: 'sm',
    onClick: async () => {
      if (!fileInput.files || fileInput.files.length === 0) {
        notify.warn('请先选择一个备份文件');
        return;
      }
      previewHost.replaceChildren(el('div', { class: 'sm muted', text: '正在让后端预演…' }));
      try {
        const form = new FormData();
        form.append('file', fileInput.files[0]);
        const result = await api.restore(form, { query: { preview: '1' } });
        previewOk = true;
        confirmBtn.disabled = false;
        const warnings = warningsOf(result);
        previewHost.replaceChildren(
          el(
            'div',
            { class: 'stack-2' },
            banner('info', '预演完成', el('div', { class: 'sm', text: '下面是后端算出的影响；确认无误后再点"确认导入"。' })),
            renderCode(result, { label: '预演结果', meta: 'POST /restore?preview=1' }),
            warnings.length > 0
              ? renderCode(warnings.map((w) => coerceText(typeof w === 'string' ? w : pick(w, ['message', 'code'], ''))).join('\n'), { label: 'warnings', tight: true })
              : null
          )
        );
      } catch (err) {
        previewOk = false;
        confirmBtn.disabled = true;
        const info = toastError(err, '预演失败');
        previewHost.replaceChildren(el('div', { class: 'sm', text: info.title }));
      }
    },
  });

  fileInput.addEventListener('change', () => {
    previewOk = false;
    confirmBtn.disabled = true;
    previewHost.replaceChildren();
  });

  body.appendChild(
    el(
      'div',
      { class: 'stack-2' },
      sectionTitle('导出'),
      el('div', { class: 'row row--wrap' }, linkButton('下载配置 + 规则集 + 名单（tar.gz）', backupUrl(), { size: 'sm', download: true })),
      el('div', { class: 'xs faint', text: '备份内容与权限由后端决定；下载链接同样受会话认证保护。' }),
      sectionTitle('导入'),
      el('div', { class: 'xs faint', text: '导入前必须预演：预演只算影响不改线上状态。' }),
      el('div', { class: 'row row--wrap' }, fileInput, previewBtn, confirmBtn),
      previewHost
    )
  );
}

/* ── 版本与预算 ─────────────────────────────────────────────── */

const DOC_BUDGETS = [
  { profile: 'medium（目标档）', cpu: '2 vCPU', mem: '2 GiB', console: '控制台额外 RSS ≤ 24 MiB' },
  { profile: 'small（保底线）', cpu: '1 vCPU', mem: '512 MiB', console: '控制台额外 RSS ≤ 8 MiB' },
];

function aboutSection(host) {
  const resource = createResource(() => api.status());
  const body = el('div', { class: 'stack-2' });
  host.appendChild(card({ title: '版本与构建', hint: 'GET /status', body: body }));

  bindState(body, resource, {
    loadingTitle: '读取版本信息…',
    onRetry: () => resource.load(),
    empty: { title: '后端未返回状态' },
    render: (payload) => {
      const rows = [
        { k: '版本', v: pick(payload, ['version', 'build_version'], null) },
        { k: '构建时间', v: pick(payload, ['build_time', 'built_at'], null) === null ? null : fmtTime(pick(payload, ['build_time', 'built_at'])) },
        { k: 'Go 版本', v: pick(payload, ['go_version', 'goversion'], null) },
        { k: 'GOAMD64', v: pick(payload, ['goamd64', 'GOAMD64'], null) },
        { k: 'Profile', v: pick(payload, ['profile', 'resource_profile'], null) },
        { k: '检测模式', v: pick(payload, ['mode', 'detect_mode'], null) },
        { k: '运行时长', v: pick(payload, ['uptime_s', 'uptime_seconds'], null) === null ? null : fmtSeconds(pick(payload, ['uptime_s', 'uptime_seconds'])) },
        { k: '当前内存', v: pick(payload, ['memory.used_bytes', 'memory_used_bytes'], null) === null ? null : fmtBytes(pick(payload, ['memory.used_bytes', 'memory_used_bytes'])) },
      ].filter((row) => row.v !== null && row.v !== undefined && row.v !== '');
      return el(
        'div',
        { class: 'stack-2' },
        kvList(rows.length > 0 ? rows : [{ k: '版本信息', v: '后端没有返回可识别的版本字段' }]),
        renderCode(payload, { label: 'GET /status 原文', tight: true })
      );
    },
  });
  resource.load();

  const budgetRows = el('div', { class: 'table-wrap' });
  const table = el('table', { class: 'table' });
  const thead = el(
    'thead',
    {},
    el(
      'tr',
      {},
      el('th', { text: 'Profile' }),
      el('th', { text: 'CPU' }),
      el('th', { text: '内存' }),
      el('th', { text: '控制台预算' })
    )
  );
  const tbody = el('tbody');
  for (const row of DOC_BUDGETS) {
    tbody.appendChild(
      el(
        'tr',
        {},
        el('td', { text: row.profile }),
        el('td', { text: row.cpu }),
        el('td', { text: row.mem }),
        el('td', { class: 'is-wrap', text: row.console })
      )
    );
  }
  table.appendChild(thead);
  table.appendChild(tbody);
  budgetRows.appendChild(table);

  host.appendChild(
    card({
      title: '资源预算（文档值，非运行时数值）',
      hint: '',
      body: el(
        'div',
        { class: 'stack-2' },
        el('div', {
          class: 'xs faint',
          text: '这张表是文档里约定的预算，不是从后端读来的实时数据；实时占用请看上面的"当前内存"和概览页。',
        }),
        budgetRows
      ),
    })
  );
}

/* ── 页面 ───────────────────────────────────────────────────── */

const TAB_ITEMS = [
  { key: 'auth', label: '认证' },
  { key: 'notify', label: '通知' },
  { key: 'config', label: '日志与配置' },
  { key: 'backup', label: '备份' },
  { key: 'about', label: '版本' },
];

export function render(container) {
  const page = el('div', { class: 'page' });
  container.appendChild(page);

  page.appendChild(
    pageHeader('系统设置', {
      subtitle: '认证 / 通知 / 日志与配置 / 备份 / 版本；所有写操作都会记入操作审计',
    })
  );

  const tabsHost = el('div');
  const host = el('div');
  let active = 'auth';

  function renderTabs() {
    tabsHost.replaceChildren(
      tabs(TAB_ITEMS, {
        active: active,
        onSelect: (key) => select(key),
      })
    );
  }

  function select(key) {
    active = key;
    renderTabs();
    host.replaceChildren();
    if (key === 'auth') authSection(host);
    else if (key === 'notify') notifySection(host);
    else if (key === 'config') {
      // 运行模式（引擎热参数）是这张标签页里最要紧的入口：应急切 detect → block。
      engineSection(host);
      configSection(host);
    }
    else if (key === 'backup') backupSection(host);
    else aboutSection(host);
  }

  page.appendChild(el('div', { class: 'card' }, tabsHost));
  page.appendChild(host);
  renderTabs();
  select('auth');

  return () => {};
}
