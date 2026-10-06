// web/assets/router.js
// 职责：History API 路由 —— 路径匹配、参数与查询串解析、base 前缀、点击代理、订阅变更。
// 说明：控制台可能挂在 gate.path_token 的随机前缀下，所有链接与导航都相对 base 生成。

function normalizeBase(base) {
  let b = typeof base === 'string' && base.length > 0 ? base : '/';
  if (!b.startsWith('/')) b = '/' + b;
  if (!b.endsWith('/')) b = b + '/';
  return b;
}

function splitSegments(path) {
  return String(path)
    .split('?')[0]
    .split('/')
    .filter((s) => s.length > 0);
}

function parseQuery(search) {
  const out = {};
  const raw = String(search || '');
  const q = raw.startsWith('?') ? raw.slice(1) : raw;
  if (!q) return out;
  for (const pair of q.split('&')) {
    if (!pair) continue;
    const idx = pair.indexOf('=');
    const key = idx < 0 ? pair : pair.slice(0, idx);
    const value = idx < 0 ? '' : pair.slice(idx + 1);
    try {
      out[decodeURIComponent(key)] = decodeURIComponent(value.replace(/\+/g, ' '));
    } catch (err) {
      out[key] = value;
    }
  }
  return out;
}

function buildQuery(params) {
  const parts = [];
  for (const key of Object.keys(params || {})) {
    const value = params[key];
    if (value === null || value === undefined || value === '') continue;
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
  }
  return parts.length > 0 ? '?' + parts.join('&') : '';
}

/**
 * @param {object} opts
 * @param {Array<{path:string, name:string, title?:string, view:Function}>} opts.routes
 * @param {string} [opts.base] 控制台前缀，例如 '/'
 * @param {Function} [opts.notFound] 未匹配时的视图工厂
 */
export function createRouter(opts) {
  const routes = Array.isArray(opts.routes) ? opts.routes.slice() : [];
  const base = normalizeBase(opts.base);
  const notFound = opts.notFound;
  const listeners = new Set();
  let current = { path: '/', name: '', params: {}, query: {}, href: '/' };
  let started = false;

  function match(path) {
    const segs = splitSegments(path);
    for (const route of routes) {
      const rsegs = splitSegments(route.path);
      if (rsegs.length !== segs.length) continue;
      const params = {};
      let ok = true;
      for (let i = 0; i < rsegs.length; i++) {
        const r = rsegs[i];
        if (r.startsWith(':')) params[r.slice(1)] = decodeURIComponent(segs[i]);
        else if (r !== segs[i]) {
          ok = false;
          break;
        }
      }
      if (ok) return { route, params };
    }
    return null;
  }

  function stripBase(pathname) {
    let p = pathname || '/';
    if (base !== '/') {
      const prefix = base.slice(0, -1);
      if (p === prefix) p = '/';
      else if (p.startsWith(prefix + '/')) p = p.slice(prefix.length);
    }
    return p.startsWith('/') ? p : '/' + p;
  }

  /** 生成带 base 前缀的链接地址，视图里的 <a href> 一律用它。 */
  function href(path) {
    const p = String(path || '/');
    const withSlash = p.startsWith('/') ? p.slice(1) : p;
    return base + withSlash;
  }

  function resolve() {
    const loc = globalThis.location;
    const path = stripBase(loc.pathname);
    const query = parseQuery(loc.search);
    const hit = match(path);
    const next = {
      path,
      query,
      href: loc.pathname + loc.search,
      name: hit ? hit.route.name : '',
      params: hit ? hit.params : {},
      route: hit ? hit.route : null,
      notFound: !hit,
    };
    current = next;
    for (const fn of Array.from(listeners)) fn(next);
    return next;
  }

  function navigate(path, options = {}) {
    const target = href(path) + buildQuery(options.query);
    if (options.replace) globalThis.history.replaceState({}, '', target);
    else globalThis.history.pushState({}, '', target);
    return resolve();
  }

  function onDocumentClick(event) {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const anchor = event.target && event.target.closest ? event.target.closest('a[data-route]') : null;
    if (!anchor) return;
    const target = anchor.getAttribute('href');
    if (!target || anchor.getAttribute('target')) return;
    event.preventDefault();
    navigate(stripBase(new URL(target, globalThis.location.origin).pathname), {
      query: parseQuery(new URL(target, globalThis.location.origin).search),
    });
  }

  return {
    base,
    routes,
    href,
    notFound,
    navigate,
    current: () => current,
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    start() {
      if (started) return current;
      started = true;
      document.addEventListener('click', onDocumentClick);
      globalThis.addEventListener('popstate', resolve);
      return resolve();
    },
    stop() {
      document.removeEventListener('click', onDocumentClick);
      globalThis.removeEventListener('popstate', resolve);
      started = false;
    },
  };
}

export { buildQuery, parseQuery };
