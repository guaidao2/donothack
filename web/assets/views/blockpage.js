// web/assets/views/blockpage.js
// 职责：拦截页页 —— 自定义模板（编辑 / 预览 / 保存 / 恢复内置）与页面参数（状态码、品牌、联系方式）。
// 取数：GET /block-page、POST /block-page/preview、PUT /block-page。
// 重点：模板是 Go html/template（取值自动转义）；服务端在保存与启动时都拿样例渲染一次做校验，
//       编译不过整次拒绝、旧模板继续生效。预览不产生任何状态变更。

import { api, warningsOf } from '../api.js';
import {
  el,
  card,
  pageHeader,
  badge,
  banner,
  button,
  field,
  textArea,
  textInput,
  checkbox,
  kvList,
  renderCode,
  pick,
  asArray,
  coerceText,
  fmtBool,
} from '../dom.js';
import { notify, toastError, showWarnings } from '../components/toast.js';
import { confirmDialog, alertDialog } from '../components/modal.js';

// 预览用的样例请求：只是拿来渲染模板，不代表真实流量。
const SAMPLE = {
  method: 'GET',
  host: 'example.com',
  path: '/vulnerabilities/sqli/',
  category: 'sqli',
};

export function render(container) {
  const host = el('div', { class: 'page' });
  container.appendChild(host);

  const vm = {
    loading: true,
    error: null,
    info: null,
    draft: null, // null = 还没改过，显示服务端当前模板
    persist: true,
    preview: null,
    previewError: null,
    busy: false,
    opts: { status: '', branding: false, product_name: '', product_url: '', contact: '', title: '' },
  };

  // 模板输入框与参数输入框是常驻节点：重绘不重建，免得打字时丢焦点。
  const templateArea = textArea({
    rows: 18,
    placeholder: '{{.Title}}\n<p>请求已被拦下</p>',
    onInput: (value) => {
      vm.draft = value;
      paintActions();
    },
  });

  const optInputs = {
    status: textInput({ placeholder: '403', onInput: (v) => (vm.opts.status = v) }),
    product_name: textInput({ placeholder: '产品名（留空用默认）', onInput: (v) => (vm.opts.product_name = v) }),
    product_url: textInput({ placeholder: 'https://example.com', onInput: (v) => (vm.opts.product_url = v) }),
    contact: textInput({ placeholder: '误报申诉渠道，如 ops@example.com', onInput: (v) => (vm.opts.contact = v) }),
    title: textInput({ placeholder: '页面标题', onInput: (v) => (vm.opts.title = v) }),
  };
  const brandingBox = checkbox('显示产品名与版本', {
    checked: false,
    onChange: (checked) => (vm.opts.branding = checked),
  });

  function currentHTML() {
    if (vm.draft !== null) return vm.draft;
    if (vm.info) return String(pick(vm.info, ['html'], '') || '');
    return '';
  }

  async function load() {
    vm.loading = true;
    paint();
    try {
      vm.info = await api.blockPage();
      vm.error = null;
      const info = vm.info;
      vm.opts.status = pick(info, ['status'], '') === null ? '' : String(pick(info, ['status'], ''));
      vm.opts.branding = pick(info, ['branding'], false) === true;
      vm.opts.product_name = String(pick(info, ['product_name'], '') || '');
      vm.opts.product_url = String(pick(info, ['product_url'], '') || '');
      vm.opts.contact = String(pick(info, ['contact'], '') || '');
      vm.opts.title = String(pick(info, ['title'], '') || '');
      vm.draft = null;
      brandingBox.querySelector('input').checked = vm.opts.branding;
      optInputs.status.value = vm.opts.status;
      optInputs.product_name.value = vm.opts.product_name;
      optInputs.product_url.value = vm.opts.product_url;
      optInputs.contact.value = vm.opts.contact;
      optInputs.title.value = vm.opts.title;
      templateArea.value = currentHTML();
    } catch (err) {
      vm.error = err;
    }
    vm.loading = false;
    paint();
  }

  async function doPreview() {
    vm.busy = true;
    vm.preview = null;
    vm.previewError = null;
    paintActions();
    try {
      const res = await api.previewBlockPage(
        Object.assign({ html: currentHTML() }, SAMPLE)
      );
      vm.preview = String(pick(res, ['html', 'body', 'content'], '') || '');
      showWarnings(warningsOf(res));
      vm.busy = false;
      paint();
      // 结果同时弹出来：页面很长，只更新最下面那张卡等于"点了没反应"。
      await alertDialog({
        title: '预览：样例请求的渲染结果',
        description:
          '样例请求 ' + SAMPLE.method + ' ' + SAMPLE.host + SAMPLE.path +
          '（类目 ' + SAMPLE.category + '）。预览只渲染，不改任何状态。',
        body: renderCode(vm.preview, { label: '渲染结果', meta: '服务端 html/template 输出' }),
        okText: '关闭',
      });
    } catch (err) {
      vm.previewError = err;
      vm.busy = false;
      paint();
      const detail = pick(err && err.body ? err.body : {}, ['error.detail', 'detail'], '') || '';
      await alertDialog({
        title: '模板没通过渲染',
        description: '服务端编译或试渲染失败，当前模板未被改动。',
        body: el(
          'div',
          {},
          el('div', { text: String((err && err.message) || err) }),
          detail ? el('div', { class: 'mono sm', text: String(detail) }) : null
        ),
        okText: '关闭',
      });
    }
  }

  async function doSave() {
    vm.busy = true;
    paintActions();
    try {
      const body = {
        html: currentHTML(),
        persist: vm.persist,
        branding: vm.opts.branding,
      };
      const status = Number(vm.opts.status);
      if (Number.isFinite(status) && status > 0) body.status = status;
      for (const key of ['product_name', 'product_url', 'contact', 'title']) {
        const value = vm.opts[key];
        if (value !== '') body[key] = value;
      }
      const res = await api.putBlockPage(body);
      showWarnings(warningsOf(res));
      notify.ok(vm.persist ? '模板已保存并写入文件' : '模板已生效（仅内存，重启回退）');
      vm.busy = false;
      await load();
    } catch (err) {
      vm.busy = false;
      paintActions();
      toastError(err, '保存失败，原模板未改动');
    }
  }

  async function doReset() {
    const ok = await confirmDialog({
      title: '恢复内置模板',
      description: '当前自定义模板会被内置模板替换。写盘开关打开时会同时覆盖模板文件。',
      confirmText: '恢复内置',
      danger: true,
    });
    if (!ok) return;
    vm.busy = true;
    paintActions();
    try {
      const res = await api.putBlockPage({ reset: true, persist: vm.persist });
      showWarnings(warningsOf(res));
      notify.ok('已恢复内置模板');
      vm.busy = false;
      await load();
    } catch (err) {
      vm.busy = false;
      paintActions();
      toastError(err, '恢复失败');
    }
  }

  function useBuiltinSource() {
    const builtin = String(pick(vm.info || {}, ['builtin'], '') || '');
    if (!builtin) {
      notify.warn('还没读到内置模板，先刷新一次');
      return;
    }
    vm.draft = builtin;
    templateArea.value = builtin;
    paintActions();
    notify.ok('已把内置模板填进编辑框，改完记得保存');
  }

  const actionRow = el('div', { class: 'row row--gap' });

  function paintActions() {
    const changed = vm.draft !== null && vm.draft !== String(pick(vm.info || {}, ['html'], '') || '');
    const nodes = [
      button('预览', { tone: 'primary', size: 'sm', disabled: vm.busy, onClick: doPreview }),
      button('保存', { size: 'sm', disabled: vm.busy, onClick: doSave }),
      button('用内置模板做底稿', { size: 'sm', disabled: vm.busy, onClick: useBuiltinSource }),
      button('恢复内置', { tone: 'danger', size: 'sm', disabled: vm.busy, onClick: doReset }),
    ];
    if (changed) nodes.push(el('span', { class: 'sm muted', text: '有未保存的修改' }));
    if (vm.busy) nodes.push(el('span', { class: 'sm muted', text: '提交中…' }));
    actionRow.replaceChildren(...nodes);
  }

  function statusCard() {
    const info = vm.info || {};
    const compileError = String(pick(info, ['compile_error'], '') || '');
    const custom = pick(info, ['custom'], null) === true;
    const file = String(pick(info, ['file'], '') || '');
    const variables = asArray(pick(info, ['variables'], []));
    const varLines = variables
      .map((v) => '{{.' + String(pick(v, ['name'], '') || '') + '}}  ' + String(pick(v, ['desc'], '') || ''))
      .join('\n');
    return card({
      title: '当前状态',
      hint: '模板与参数在运行期原子替换，不需要重启',
      body: [
        kvList([
          { k: '模板来源', v: custom ? badge('自定义', 'ok') : badge('内置', 'neutral') },
          { k: '模板文件', v: file || '未配置（只能热改，重启回退内置）' },
          { k: '产品名显示', v: fmtBool(pick(info, ['branding'], false) === true) },
          { k: '快照版本', v: String(pick(info, ['snapshot'], '') || '—') },
        ]),
        compileError
          ? banner('warn', '当前模板编译失败', el('div', { class: 'mono sm', text: compileError }), [])
          : null,
        variables.length
          ? el(
              'div',
              {},
              el('div', { class: 'field__label', text: '模板里可用的字段' }),
              el('pre', { class: 'mono xs muted', text: varLines })
            )
          : null,
      ],
    });
  }

  function templateCard() {
    return card({
      title: '自定义模板',
      hint: 'Go html/template 语法，取值自动转义；留空表示使用内置模板',
      body: [
        el('div', { class: 'row row--gap' }, actionRow),
        field('模板内容', templateArea, '保存与启动时都会拿样例渲染一次，编译不过整次拒绝'),
        checkbox('同时写入模板文件（重启后仍然生效）', {
          checked: vm.persist,
          onChange: (checked) => (vm.persist = checked),
        }),
        el('div', {
          class: 'sm muted',
          text: '写入的是"模板文件"那一栏的路径，必须是相对路径（相对配置文件目录）；绝对路径会被拒绝，模板只在内存里生效。',
        }),
      ],
    });
  }

  function optionsCard() {
    return card({
      title: '页面参数',
      hint: '与模板一起提交；只填想改的项',
      body: [
        field('状态码', optInputs.status, '默认 403；限速与封禁固定用 429'),
        field('标题', optInputs.title),
        field('产品名', optInputs.product_name),
        field('产品主页', optInputs.product_url),
        field('误报申诉渠道', optInputs.contact),
        brandingBox,
      ],
    });
  }

  function previewCard() {
    if (vm.previewError) {
      const err = vm.previewError;
      const detail = pick(err && err.body ? err.body : {}, ['error.detail', 'detail'], '') || '';
      return card({
        title: '预览',
        body: [
          banner(
            'error',
            '模板没通过渲染',
            el(
              'div',
              {},
              el('div', { text: String((err && err.message) || err) }),
              detail ? el('div', { class: 'mono sm', text: String(detail) }) : null
            ),
            []
          ),
        ],
      });
    }
    if (!vm.preview) {
      return card({
        title: '预览',
        hint: '点上面的「预览」按钮，用样例请求渲染一次',
        body: [
          el('div', {
            class: 'sm muted',
            text:
              '样例请求：' +
              SAMPLE.method +
              ' ' +
              SAMPLE.host +
              SAMPLE.path +
              '（类目 ' +
              SAMPLE.category +
              '）。预览只渲染，不改任何状态。',
          }),
        ],
      });
    }
    return card({
      title: '预览',
      hint: '渲染结果源码（控制台只以代码模式展示，不执行模板里的脚本）',
      body: [renderCode(vm.preview, { label: '渲染结果', meta: '服务端 html/template 输出' })],
    });
  }

  function paint() {
    if (vm.loading && !vm.info) {
      host.replaceChildren(
        pageHeader('拦截页', { subtitle: '被拦住时返回给终端用户的那一页' }),
        card({ title: '读取配置', body: [el('div', { class: 'sm muted', text: '读取中…' })] })
      );
      return;
    }
    if (vm.error) {
      host.replaceChildren(
        pageHeader('拦截页', { subtitle: '被拦住时返回给终端用户的那一页' }),
        card({
          title: '读取失败',
          body: [
            el('div', { class: 'sm', text: String((vm.error && vm.error.message) || vm.error) }),
            el('div', {}, button('重试', { size: 'sm', onClick: load })),
          ],
        })
      );
      return;
    }
    paintActions();
    host.replaceChildren(
      pageHeader('拦截页', {
        subtitle: '改模板与文案；预览、保存都不需要重启',
        actions: [button('刷新', { size: 'sm', onClick: load })],
      }),
      statusCard(),
      templateCard(),
      optionsCard(),
      previewCard()
    );
  }

  paint();
  load();
}
