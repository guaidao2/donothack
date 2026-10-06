// web/assets/views/settings.js
// 职责：系统设置页 —— 门槛（Basic 遮挡层）、认证（口令/TOTP/api_token）、通知、日志与配置、备份、版本信息。
// 取数：GET /gate、POST /gate/rotate、POST /gate/path/rotate、POST /gate/cert/selfsigned、
//       POST /password、POST /totp/enroll、GET/PUT /notify、POST /notify/test、
//       GET /config、PUT /config、GET /config/diff、POST /config/reload、GET /backup、POST /restore、
//       GET /status、GET /session。
// 约束：拿不到的字段一律显示 "—"；没有端点的能力（如 api_token 轮换）明确写成"后端未定义"，不做假按钮。

import { api, backupUrl, warningsOf, snapshotVersionOf } from '../api.js';
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

/* ── 门槛 ───────────────────────────────────────────────────── */

function gateSection(host) {
  const resource = createResource(() => api.gate());
  const body = el('div', { class: 'stack-2' });
  host.appendChild(card({ title: 'HTTP Basic 门槛', hint: 'GET /gate', body: body }));

  bindState(body, resource, {
    loadingTitle: '读取门槛配置…',
    onRetry: () => resource.load(),
    empty: { title: '后端未返回门槛配置' },
    render: (payload) => {
      const blocks = [];
      const enabled = pick(payload, ['enabled', 'gate.enabled', 'basic.enabled'], null);
      const realm = pick(payload, ['realm', 'gate.realm', 'basic.realm'], null);
      const user = pick(payload, ['username', 'user', 'gate.username', 'basic.username'], null);
      const rotatedAt = pick(payload, ['rotated_at', 'last_rotate', 'gate.rotated_at'], null);
      const pathTokenEnabled = pick(payload, ['path_token_enabled', 'gate.path_token_enabled', 'path_token.enabled'], null);
      const pathToken = pick(payload, ['path_token', 'gate.path_token'], null);
      const failed = pick(payload, ['gate_failures', 'failed_attempts', 'stats.failures'], null);
      const locked = asArray(pick(payload, ['locked_ips', 'banned', 'gate_locked'], []));
      const cert = pick(payload, ['cert', 'certificate', 'tls'], null);

      blocks.push(
        kvList(
          [
            { k: '门槛开关', v: yesNo(enabled) },
            { k: 'realm', v: realm === null ? null : el('span', { class: 'mono', text: String(realm) }) },
            { k: '门槛用户名', v: user === null ? null : el('span', { class: 'mono', text: String(user) }) },
            { k: '凭据轮换时间', v: rotatedAt ? fmtTime(rotatedAt) : null },
            { k: '随机路径遮挡', v: pathTokenEnabled === null ? null : yesNo(pathTokenEnabled, { yes: 'info', no: 'neutral' }) },
            {
              k: '当前路径',
              v: pathToken ? renderCode(pick(payload, ['url', 'path'], pathToken), { label: '控制台路径', tight: true }) : null,
            },
            { k: '门槛失败次数', v: failed === null ? null : fmtInt(failed) },
            {
              k: '被封禁 IP',
              v:
                locked.length === 0
                  ? null
                  : el(
                      'div',
                      { class: 'stack-1' },
                      locked.slice(0, 20).map((item) =>
                        el('div', { class: 'mono sm', text: coerceText(pick(item, ['ip', 'addr'], item)) })
                      )
                    ),
            },
            { k: '门槛凭据', v: el('span', { class: 'faint', text: '后端不返回明文；轮换即旧凭据立即失效' }) },
          ].filter((row) => row.v !== null)
        )
      );

      if (cert && typeof cert === 'object') {
        blocks.push(
          el(
            'div',
            { class: 'stack-2' },
            sectionTitle('TLS 证书'),
            kvList([
              { k: '来源', v: coerceText(pick(cert, ['source', 'kind', 'type'], '—')) },
              { k: '自签', v: yesNo(pick(cert, ['self_signed', 'selfsigned'], null)) },
              { k: '指纹', v: pick(cert, ['fingerprint', 'sha256'], null) === null ? null : el('span', { class: 'mono wrap-anywhere', text: String(pick(cert, ['fingerprint', 'sha256'])) }) },
              { k: '到期', v: pick(cert, ['not_after', 'expires_at'], null) === null ? null : fmtTime(pick(cert, ['not_after', 'expires_at'])) },
              { k: 'SAN', v: asArray(pick(cert, ['san', 'dns_names'], [])).join(', ') || null },
            ])
          )
        );
      }

      blocks.push(
        el(
          'div',
          { class: 'row row--wrap' },
          button('轮换门槛凭据', { tone: 'danger', size: 'sm', onClick: () => rotateGate(resource) }),
          button('重新生成随机路径', { size: 'sm', onClick: () => rotatePath(resource) }),
          button('重新生成自签证书', { size: 'sm', onClick: () => regenerateCert(resource) })
        )
      );

      blocks.push(
        el('div', {
          class: 'xs faint',
          text:
            '门槛只是"不让扫描器看见门"，不是认证边界；登录会话才是。门槛凭据与登录账号必须分开保管。',
        })
      );
      return blocks;
    },
  });
  resource.load();

  async function rotateGate(res) {
    await openDialog({
      title: '轮换门槛凭据',
      description: 'POST /gate/rotate：旧凭据提交后立即失效，已经打开登录页的浏览器下一次请求就会 401。',
      fields: [
        { name: 'username', label: '新门槛用户名（留空则由后端生成）' },
        { name: 'password', label: '新门槛口令', type: 'password', required: true },
        { name: 'confirm', label: '再输一次', type: 'password', required: true },
      ],
      submitText: '轮换',
      danger: true,
      onSubmit: async (values) => {
        if (values.password !== values.confirm) throw new Error('两次输入的口令不一致');
        const body = { password: values.password };
        if (values.username) body.username = values.username;
        const result = await api.rotateGate(body);
        showWarnings(warningsOf(result));
        notify.ok('门槛凭据已轮换，旧凭据立即失效');
        await res.load();
      },
    });
  }

  async function rotatePath(res) {
    const ok = await confirmDialog({
      title: '重新生成随机路径',
      description: 'POST /gate/path/rotate：旧链接立即失效，需要重新分发新地址给运维同事。',
      confirmText: '重新生成',
    });
    if (!ok) return;
    try {
      const result = await api.rotateGatePath();
      showWarnings(warningsOf(result));
      await alertDialog({
        title: '新的控制台路径',
        description: '请复制并安全地分发给运维同事；这一步之后旧地址不再可用。',
        body: renderCode(pick(result, ['path', 'url', 'path_token'], result), { label: '新路径' }),
      });
      await res.load();
    } catch (err) {
      toastError(err, '重新生成失败');
    }
  }

  async function regenerateCert(res) {
    const ok = await confirmDialog({
      title: '重新生成自签证书',
      description: 'POST /gate/cert/selfsigned：新证书生效后浏览器会再次提示"不安全"，需要重新确认一次。',
      confirmText: '重新生成',
      danger: false,
    });
    if (!ok) return;
    try {
      const result = await api.regenerateCert();
      showWarnings(warningsOf(result));
      await alertDialog({
        title: '新证书已生成',
        description: '核对下面的指纹（与浏览器里看到的应当一致）。',
        body: renderCode(pick(result, ['fingerprint', 'sha256', 'cert'], result), { label: '证书指纹' }),
      });
      await res.load();
    } catch (err) {
      toastError(err, '重新生成失败');
    }
  }
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
        { name: 'current_password', label: '当前口令', type: 'password', required: true },
        { name: 'new_password', label: '新口令', type: 'password', required: true },
        { name: 'confirm', label: '再输一次', type: 'password', required: true },
      ],
      submitText: '修改',
      danger: true,
      onSubmit: async (values) => {
        if (values.new_password !== values.confirm) throw new Error('两次输入的新口令不一致');
        const result = await api.changePassword({
          current_password: values.current_password,
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
      if (capture !== null) {
        controls.appendChild(
          checkbox('抓取 payload 原文（log.capture_payload）', {
            checked: !!capture,
            onChange: (checked) => toggleCapture(resource, payload, checked),
          })
        );
      } else {
        controls.appendChild(
          el('span', { class: 'xs faint', text: '配置里没有 log.capture_payload 字段，无法在控制台切换抓取开关。' })
        );
      }
      controls.appendChild(button('编辑配置（JSON）', { size: 'sm', onClick: () => editConfig(resource) }));
      controls.appendChild(button('查看与运行中的差异', { size: 'sm', onClick: () => diffRes.load() }));
      controls.appendChild(button('重新加载配置', { size: 'sm', danger: true, onClick: () => reloadConfig(resource) }));
      blocks.push(controls);

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

  async function toggleCapture(res, current, nextValue) {
    const ok = await confirmDialog({
      title: nextValue ? '确认开启 payload 抓取' : '确认关闭 payload 抓取',
      description:
        nextValue
          ? '开启后请求原文会被记录：内存与磁盘占用上升，且原文可能含敏感信息。请确认合规允许。'
          : '关闭后不再记录请求原文，控制台详情页只能看到摘要。',
      confirmText: nextValue ? '开启' : '关闭',
      danger: nextValue,
    });
    if (!ok) {
      res.load();
      return;
    }
    try {
      const next = cloneJson(current);
      setPath(next, 'log.capture_payload', nextValue);
      const result = await api.putConfig(next);
      showWarnings(warningsOf(result));
      notify.ok('配置已更新' + (snapshotVersionOf(result) ? '（快照 ' + snapshotVersionOf(result) + '）' : ''));
      await res.load();
      diffRes.load();
    } catch (err) {
      toastError(err, '更新配置失败');
      res.load();
    }
  }

  async function editConfig(res) {
    const current = res.get().data;
    if (!current) {
      notify.warn('还没有读到当前配置');
      return;
    }
    editJsonDialog({
      title: '编辑运行配置',
      description: 'PUT /config（带 Preview）：建议先点"查看与运行中的差异"确认改动范围。',
      value: current,
      onSave: async (parsed) => {
        const result = await api.putConfig(parsed);
        showWarnings(warningsOf(result));
        notify.ok('配置已更新');
        await res.load();
        diffRes.load();
      },
    });
  }

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
      hint: 'docs/PERFORMANCE.md',
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
  { key: 'gate', label: '门槛' },
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
      subtitle: '门槛 / 认证 / 通知 / 日志与配置 / 备份；所有写操作都会记入操作审计',
    })
  );

  const tabsHost = el('div');
  const host = el('div');
  let active = 'gate';

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
    if (key === 'gate') gateSection(host);
    else if (key === 'auth') authSection(host);
    else if (key === 'notify') notifySection(host);
    else if (key === 'config') configSection(host);
    else if (key === 'backup') backupSection(host);
    else aboutSection(host);
  }

  page.appendChild(el('div', { class: 'card' }, tabsHost));
  page.appendChild(host);
  renderTabs();
  select('gate');

  return () => {};
}
