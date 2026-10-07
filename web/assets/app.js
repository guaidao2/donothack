// web/assets/app.js
// 职责：启动、布局（侧栏 + 顶栏 + 内容区）、路由注册、会话检查、登录页、全局错误出口。
// 启动顺序：安装 DOM 写入守卫 → 检查会话（GET /session）→ 未认证显示登录页 / 已认证进入外壳 → 启动路由。
// 约束：全部 DOM 由 createElement + textContent 生成；index.html 里没有任何内联脚本。

import { installWriteGuards, isDevMode } from './safe.js';
import { createRouter } from './router.js';
import { api, onUnauthorized, setCSRFToken } from './api.js';
import { session, ui } from './store.js';
import {
  el,
  clear,
  button,
  field,
  textInput,
  banner,
  describeError,
  stateBlock,
  pick,
  fmtSeconds,
} from './dom.js';
import { brandMark, navIcon } from './icons.js';
import { confirmDialog } from './components/modal.js';
import { notify } from './components/toast.js';

import { render as renderDashboard } from './views/dashboard.js';
import { render as renderEvents } from './views/events.js';
import { render as renderRules } from './views/rules.js';
import { render as renderRuleTest } from './views/ruletest.js';
import { render as renderExceptions } from './views/exceptions.js';
import { render as renderRatelimit } from './views/ratelimit.js';
import { render as renderBlockPage } from './views/blockpage.js';
import { render as renderSettings } from './views/settings.js';
import { render as renderAudit } from './views/audit.js';

/* ── 路由表 ─────────────────────────────────────────────────── */

const ROUTES = [
  { path: '/', name: 'dashboard', title: '概览', nav: '/', view: renderDashboard },
  { path: '/events', name: 'events', title: '攻击事件', nav: '/events', view: renderEvents },
  { path: '/events/:id', name: 'event-detail', title: '事件详情', nav: '/events', view: renderEvents },
  { path: '/rules', name: 'rules', title: '规则管理', nav: '/rules', view: renderRules },
  { path: '/rules/:id', name: 'rule-detail', title: '规则详情', nav: '/rules', view: renderRules },
  { path: '/ruletest', name: 'ruletest', title: '规则测试台', nav: '/ruletest', view: renderRuleTest },
  { path: '/exceptions', name: 'exceptions', title: '例外与白名单', nav: '/exceptions', view: renderExceptions },
  { path: '/ratelimit', name: 'ratelimit', title: 'CC 防护与限速', nav: '/ratelimit', view: renderRatelimit },
  { path: '/blockpage', name: 'blockpage', title: '拦截页', nav: '/blockpage', view: renderBlockPage },
  { path: '/settings', name: 'settings', title: '系统设置', nav: '/settings', view: renderSettings },
  { path: '/audit', name: 'audit', title: '操作审计', nav: '/audit', view: renderAudit },
];

const NAV_GROUPS = [
  {
    title: '监控',
    items: [
      { path: '/', label: '概览' },
      { path: '/events', label: '攻击事件' },
    ],
  },
  {
    title: '规则',
    items: [
      { path: '/rules', label: '规则管理' },
      { path: '/ruletest', label: '规则测试台' },
      { path: '/exceptions', label: '例外与白名单' },
    ],
  },
  {
    title: '防护',
    items: [{ path: '/ratelimit', label: 'CC 防护与限速' }],
  },
  {
    title: '系统',
    items: [
      { path: '/settings', label: '系统设置' },
      { path: '/blockpage', label: '拦截页' },
      { path: '/audit', label: '操作审计' },
    ],
  },
];

function metaContent(name) {
  const node = document.querySelector('meta[name="' + name + '"]');
  return node ? node.getAttribute('content') || '' : '';
}

/**
 * 控制台 base 前缀。优先取 <base href>（控制台固定挂在根路径），
 * 没有 <base> 时退回 <meta name="dh-base">，都没有就是根路径。
 */
function consoleBase() {
  const baseEl = document.querySelector('base');
  const href = baseEl ? baseEl.getAttribute('href') : '';
  if (href) {
    try {
      const path = new URL(href, globalThis.location.origin).pathname || '/';
      return path.endsWith('/') ? path : path + '/';
    } catch (err) {
      /* 落到 meta 兜底 */
    }
  }
  const metaBase = metaContent('dh-base');
  if (!metaBase) return '/';
  return metaBase.endsWith('/') ? metaBase : metaBase + '/';
}

const basePath = consoleBase();

const router = createRouter({
  routes: ROUTES,
  base: basePath,
  notFound: true,
});

const root = document.getElementById('app-root');
let viewCleanup = null;
let routeUnsubscribe = null;
let navNodes = [];

/* ── 全局错误出口 ───────────────────────────────────────────── */

function reportError(err, context) {
  const info = describeError(err);
  notify.error(context ? context + '：' + info.title : info.title, { detail: info.detail });
}

globalThis.__DONOTHACK_ON_ERROR__ = (err) => reportError(err, '内部错误');

globalThis.addEventListener('unhandledrejection', (event) => {
  reportError(event.reason, '未处理的异步错误');
});

globalThis.addEventListener('error', (event) => {
  if (event && event.message) reportError(new Error(String(event.message)), '运行时错误');
});

/* ── 屏幕切换 ───────────────────────────────────────────────── */

function showScreen(node) {
  if (viewCleanup) {
    try {
      viewCleanup();
    } catch (err) {
      reportError(err, '页面清理失败');
    }
    viewCleanup = null;
  }
  clear(root);
  root.appendChild(node);
}

function bootScreen(text) {
  return el(
    'div',
    { class: 'boot-screen' },
    el('div', { class: 'col' }, el('div', { class: 'spinner' }), el('span', { text: text }))
  );
}

/* ── 会话 ───────────────────────────────────────────────────── */

async function refreshSession() {
  try {
    const payload = await api.session();
    // CSRF：后端在 /session 里给的是**裸 token**，而 cookie 里存的是带 HMAC 的签名值。
    // 请求头必须用裸 token（服务端要它等于会话里的值），所以在这里把它存下来 ——
    // 早期前端直接读 cookie，等于把签名值当 token 发出去，所有写操作都会 403 csrf_mismatch。
    setCSRFToken(pick(payload, ['csrf', 'csrf_token'], ''));
    session.set({
      status: 'authenticated',
      actor: String(pick(payload, ['actor', 'username', 'user', 'name'], '') || ''),
      totpEnabled: !!pick(payload, ['totp_enabled', 'totp'], false),
      idleTimeoutS: pick(payload, ['idle_timeout_s', 'idle_timeout', 'timeout_s'], null),
      error: null,
    });
    return true;
  } catch (err) {
    if (err && err.code === 'unauthenticated') {
      session.set({ status: 'unauthenticated', actor: '', totpEnabled: false, idleTimeoutS: null, error: err });
      return false;
    }
    session.set({ status: 'error', actor: '', totpEnabled: false, idleTimeoutS: null, error: err });
    return false;
  }
}

onUnauthorized(() => {
  session.set({ status: 'unauthenticated', actor: '', totpEnabled: false, idleTimeoutS: null, error: null });
  if (routeUnsubscribe) {
    routeUnsubscribe();
    routeUnsubscribe = null;
  }
  renderLogin('会话已过期，请重新登录。');
});

/* ── 登录页 ─────────────────────────────────────────────────── */

function renderLogin(notice) {
  const username = textInput({ name: 'username', placeholder: '账号', autocomplete: 'username' });
  const password = textInput({ name: 'password', type: 'password', placeholder: '口令', autocomplete: 'current-password' });
  const totp = textInput({ name: 'totp', placeholder: 'TOTP 验证码（未启用可留空）' });
  const errorLine = el('div', { class: 'field__error hidden' });
  const submit = button('登录', { type: 'submit', tone: 'primary', block: true });

  const form = el(
    'form',
    {
      class: 'gate__form',
      on: {
        submit: async (event) => {
          event.preventDefault();
          errorLine.classList.add('hidden');
          if (!username.value || !password.value) {
            errorLine.textContent = '账号与口令都不能为空';
            errorLine.classList.remove('hidden');
            return;
          }
          submit.disabled = true;
          submit.textContent = '登录中…';
          try {
            const body = { username: username.value, password: password.value };
            if (totp.value) body.totp = totp.value;
            await api.login(body);
            const ok = await refreshSession();
            if (ok) {
              renderApp();
            } else {
              errorLine.textContent = '登录请求已接受，但会话仍未建立：请检查后端 /login 与 /session 的一致性';
              errorLine.classList.remove('hidden');
            }
          } catch (err) {
            const info = describeError(err);
            errorLine.textContent = info.detail ? info.title + '（' + info.detail + '）' : info.title;
            errorLine.classList.remove('hidden');
          } finally {
            submit.disabled = false;
            submit.textContent = '登录';
          }
        },
      },
    },
    field('账号', username),
    field('口令', password),
    field('TOTP（可选）', totp),
    errorLine,
    submit
  );

  showScreen(
    el(
      'div',
      { class: 'gate' },
      // 左栏：讲清这是什么。三个数字都取产品里的实数（规则数、攻击类别、响应体缓冲），
      // 不写营销口径的虚数 —— 登录页是运维第一次见到它的地方，也是唯一一次会读完的地方。
      el(
        'div',
        { class: 'gate__hero' },
        el(
          'div',
          { class: 'gate__hero-top' },
          el('div', { class: 'gate__hero-brand' }, brandMark(30), el('span', { text: 'donothack' })),
          el('h1', { class: 'gate__hero-title', text: '请求侧 Web 应用防火墙' }),
          el('p', {
            class: 'gate__hero-desc',
            text: '部署在业务服务之前，检查每个请求的头、体与参数；响应不检测、不缓冲、原样透传。单二进制，无外部依赖。',
          })
        ),
        el(
          'div',
          { class: 'gate__hero-stats' },
          heroStat('60', '出厂规则'),
          heroStat('9', '攻击类别'),
          heroStat('0', '响应体缓冲')
        )
      ),
      el(
        'div',
        { class: 'gate__panel' },
        el(
          'div',
          { class: 'card gate__card' },
          el(
            'div',
            { class: 'card__body' },
            el('div', { class: 'gate__brand', text: '登录控制台' }),
            el('div', { class: 'gate__desc', text: '表单登录 + 会话认证。' }),
            notice ? banner('warn', notice, null) : null,
            form
          )
        )
      )
    )
  );
  username.focus();
}

function heroStat(num, label) {
  return el(
    'div',
    { class: 'gate__hero-stat' },
    el('span', { class: 'gate__hero-num', text: num }),
    el('span', { class: 'gate__hero-label', text: label })
  );
}

/* ── 会话读取失败（后端不可用） ─────────────────────────────── */

function renderSessionError() {
  const err = session.get().error;
  showScreen(
    el(
      'div',
      { class: 'gate gate--single' },
      el(
        'div',
        { class: 'card gate__card' },
        el(
          'div',
          { class: 'card__body' },
          stateBlock({
            tone: 'error',
            title: '无法确认会话状态',
            hint: '控制台需要后端 /api/v1/session；后端没起来就会走到这里。',
            detail: describeError(err).detail,
            actions: [
              button('重试', {
                tone: 'primary',
                size: 'sm',
                onClick: async () => {
                  showScreen(bootScreen('正在重新检查会话…'));
                  await refreshSession();
                  renderApp();
                },
              }),
            ],
          })
        )
      )
    )
  );
}

/* ── 外壳 ───────────────────────────────────────────────────── */

function buildSidebar() {
  const sidebar = el('aside', { class: 'sidebar' });
  const version = el('span', { class: 'sidebar__brand-ver', text: '' });
  sidebar.appendChild(
    el(
      'div',
      { class: 'sidebar__brand' },
      brandMark(26),
      el('span', { class: 'sidebar__brand-name', text: 'donothack' }),
      version
    )
  );

  navNodes = [];
  for (const group of NAV_GROUPS) {
    sidebar.appendChild(el('div', { class: 'sidebar__group-title', text: group.title }));
    const nav = el('nav', { class: 'nav' });
    for (const item of group.items) {
      const link = el('a', {
        class: 'nav__item',
        attrs: { href: router.href(item.path), 'data-route': '1', 'data-nav': item.path },
      });
      link.appendChild(navIcon(item.path) || el('span', { class: 'nav__dot' }));
      link.appendChild(el('span', { text: item.label }));
      nav.appendChild(link);
      navNodes.push({ path: item.path, node: link });
    }
    sidebar.appendChild(nav);
  }

  const foot = el('div', { class: 'sidebar__foot' });
  foot.appendChild(el('span', { text: '控制台流量不进检测引擎' }));
  foot.appendChild(el('span', { text: '写操作记入操作审计' }));
  sidebar.appendChild(foot);
  return { sidebar: sidebar, version: version };
}

function markActiveNav(path) {
  for (const entry of navNodes) {
    const active = entry.path === '/' ? path === '/' : path === entry.path || path.indexOf(entry.path + '/') === 0;
    if (active) entry.node.setAttribute('aria-current', 'page');
    else entry.node.removeAttribute('aria-current');
  }
}

function renderShell() {
  const built = buildSidebar();

  const titleNode = el('div', { class: 'topbar__title', text: '概览' });
  const sessionInfo = session.get();
  const injectedVersion = metaContent('dh-version');
  const actorBadge = el('span', {
    class: 'badge badge--ok',
    text: sessionInfo.actor ? sessionInfo.actor : '已认证',
  });
  const meta = el(
    'div',
    { class: 'topbar__meta' },
    sessionInfo.idleTimeoutS ? el('span', { text: '闲置超时 ' + fmtSeconds(sessionInfo.idleTimeoutS) }) : null,
    injectedVersion ? el('span', { text: '版本 ' + injectedVersion }) : null,
    actorBadge
  );

  const logoutBtn = button('登出', {
    size: 'sm',
    tone: 'ghost',
    onClick: async () => {
      const ok = await confirmDialog({
        title: '登出控制台',
        description: '登出会销毁服务器上的会话，需要重新登录。',
        confirmText: '登出',
        danger: false,
      });
      if (!ok) return;
      try {
        await api.logout();
      } catch (err) {
        reportError(err, '登出请求失败');
      }
      session.set({ status: 'unauthenticated', actor: '', totpEnabled: false, idleTimeoutS: null, error: null });
      if (routeUnsubscribe) {
        routeUnsubscribe();
        routeUnsubscribe = null;
      }
      renderApp();
    },
  });

  const contentHost = el('div', { class: 'content' });
  const main = el(
    'div',
    { class: 'main' },
    el('header', { class: 'topbar' }, titleNode, el('div', { class: 'topbar__spacer' }), meta, logoutBtn),
    contentHost
  );

  showScreen(el('div', { class: 'shell' }, built.sidebar, main));

  // 版本号与运行态：能取到就填，取不到保持"未注入"。
  api
    .status()
    .then((status) => {
      const version = pick(status, ['version', 'build_version'], null);
      if (version) built.version.textContent = String(version);
      const profile = pick(status, ['profile', 'resource_profile'], null);
      if (profile) built.version.textContent = String(version || '') + ' · ' + String(profile);
    })
    .catch(() => {
      /* 顶部不展示错误：概览页会给出明确的后端不可用状态。 */
    });

  if (routeUnsubscribe) routeUnsubscribe();
  routeUnsubscribe = router.subscribe(renderRoute);
  router.start();
}

function renderRoute(route) {
  const title = route.route ? route.route.title : '未找到页面';
  ui.set({ path: route.path, routeName: route.name, title: title });
  const titleNode = root.querySelector('.topbar__title');
  if (titleNode) titleNode.textContent = title;
  document.title = title + ' · donothack 控制台';
  markActiveNav(route.route && route.route.nav ? route.route.nav : route.path);

  const contentHost = root.querySelector('.content');
  if (!contentHost) return;

  if (viewCleanup) {
    try {
      viewCleanup();
    } catch (err) {
      reportError(err, '页面清理失败');
    }
    viewCleanup = null;
  }
  clear(contentHost);

  const view = route.route ? route.route.view : null;
  if (typeof view !== 'function') {
    contentHost.appendChild(
      el(
        'div',
        { class: 'page' },
        stateBlock({
          title: '页面不存在',
          hint: '这个地址没有对应的控制台页面：' + route.path,
          actions: [button('回到概览', { tone: 'primary', size: 'sm', onClick: () => router.navigate('/') })],
        })
      )
    );
    return;
  }

  try {
    const cleanup = view(contentHost, {
      router: router,
      navigate: (path, options) => router.navigate(path, options),
      params: route.params,
      query: route.query,
      href: router.href,
    });
    if (typeof cleanup === 'function') viewCleanup = cleanup;
  } catch (err) {
    reportError(err, '页面渲染失败');
    contentHost.appendChild(
      el(
        'div',
        { class: 'page' },
        stateBlock({
          tone: 'error',
          title: '页面渲染失败',
          hint: '视图初始化时抛错，已中断本次渲染；下面的细节可以帮助定位。',
          detail: describeError(err).title,
        })
      )
    );
  }
}

/* ── 启动 ───────────────────────────────────────────────────── */

function renderApp() {
  const status = session.get().status;
  if (status === 'authenticated') renderShell();
  else if (status === 'unauthenticated') renderLogin(null);
  else if (status === 'error') renderSessionError();
  else showScreen(bootScreen('正在检查会话…'));
}

async function boot() {
  const guards = installWriteGuards();
  if (isDevMode() && globalThis.console) {
    globalThis.console.info(
      '[donothack] 开发模式：DOM 写入守卫已安装（' + (guards.guarded || []).length + ' 项），命中即抛错。'
    );
  }

  showScreen(bootScreen('正在检查会话…'));
  await refreshSession();
  renderApp();
}

boot();
