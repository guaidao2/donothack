// web/assets/api.js
// 职责：控制台与 /api/v1 的唯一出入口 —— URL 组装、统一错误对象、认证头与 CSRF 头、401 通知、SSE 与下载地址。
// 约定（docs/CONSOLE.md §5）：写操作一律 POST/PUT/PATCH/DELETE + 自定义头 + Origin 校验；
//   错误统一 {error:{code,message,detail}}；写操作返回 {ok, snapshot_version, warnings[]}。
// 注意：这里只负责取数与错误归一化，绝不把响应体当结构渲染（渲染一律走 dom.js / md.js）。

export const API_BASE = '/api/v1';
export const CONSOLE_HEADER = 'X-Donothack-Console';
export const CSRF_HEADER = 'X-Donothack-CSRF';
export const CSRF_COOKIE = 'donothack_csrf';

const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

export const ErrorCode = Object.freeze({
  NETWORK: 'network_error',
  UNAUTHENTICATED: 'unauthenticated',
  FORBIDDEN: 'forbidden',
  NOT_FOUND: 'not_found',
  BAD_RESPONSE: 'bad_response',
  HTTP: 'http_error',
});

export class ApiError extends Error {
  constructor(message, opts = {}) {
    super(message || '请求失败');
    this.name = 'ApiError';
    this.code = opts.code || ErrorCode.HTTP;
    this.status = typeof opts.status === 'number' ? opts.status : 0;
    this.detail = opts.detail || '';
    this.payload = opts.payload === undefined ? null : opts.payload;
  }
}

let unauthorizedHandler = null;

/** 注册 401 处理（app.js 用它切到登录页）。 */
export function onUnauthorized(fn) {
  unauthorizedHandler = fn;
}

function notifyUnauthorized() {
  if (typeof unauthorizedHandler === 'function') {
    try {
      unauthorizedHandler();
    } catch (err) {
      if (globalThis.console) globalThis.console.error('[api] 401 处理器异常', err);
    }
  }
}

export function readCookie(name) {
  const raw = globalThis.document && globalThis.document.cookie ? globalThis.document.cookie : '';
  if (!raw) return '';
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    const key = (idx < 0 ? part : part.slice(0, idx)).trim();
    if (key === name) return decodeURIComponent((idx < 0 ? '' : part.slice(idx + 1)).trim());
  }
  return '';
}

function csrfToken() {
  return readCookie(CSRF_COOKIE);
}

export function buildQuery(params) {
  const parts = [];
  for (const key of Object.keys(params || {})) {
    const value = params[key];
    if (value === null || value === undefined || value === '') continue;
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
  }
  return parts.length > 0 ? '?' + parts.join('&') : '';
}

function extractError(payload, status) {
  const err = payload && typeof payload === 'object' ? payload.error : null;
  if (err && typeof err === 'object') {
    return new ApiError(err.message || '请求失败', {
      code: err.code || ErrorCode.HTTP,
      status: status,
      detail: err.detail || '',
      payload: payload,
    });
  }
  return new ApiError('HTTP ' + status, { code: ErrorCode.HTTP, status: status, payload: payload });
}

/**
 * 底层请求。成功返回解析后的响应体（JSON 或文本）；失败抛 ApiError。
 * @param {string} path /api/v1 之后的路径，例如 '/status'
 * @param {{method?:string, query?:object, body?:*, headers?:object, signal?:AbortSignal, raw?:boolean}} [opts]
 */
export async function request(path, opts = {}) {
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { Accept: 'application/json' };
  Object.assign(headers, opts.headers || {});

  let body;
  if (opts.body !== undefined && opts.body !== null) {
    headers['Content-Type'] = 'application/json; charset=utf-8';
    body = JSON.stringify(opts.body);
  }
  if (WRITE_METHODS.indexOf(method) >= 0) {
    headers[CONSOLE_HEADER] = '1';
    const token = csrfToken();
    if (token) headers[CSRF_HEADER] = token;
  }

  const url = API_BASE + path + buildQuery(opts.query);
  let response;
  try {
    response = await fetch(url, {
      method: method,
      headers: headers,
      body: body,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: opts.signal,
    });
  } catch (err) {
    if (err && err.name === 'AbortError') throw err;
    throw new ApiError('无法连接控制台后端（' + (err && err.message ? err.message : '网络错误') + '）', {
      code: ErrorCode.NETWORK,
      status: 0,
    });
  }

  if (response.status === 401) {
    notifyUnauthorized();
    throw new ApiError('需要认证：会话不存在或已过期', {
      code: ErrorCode.UNAUTHENTICATED,
      status: 401,
      detail: '请重新登录控制台',
    });
  }

  if (response.status === 204 || response.status === 205) {
    if (!response.ok) throw new ApiError('HTTP ' + response.status, { code: ErrorCode.HTTP, status: response.status });
    return null;
  }

  const contentType = response.headers.get('content-type') || '';
  let payload = null;
  let text = '';
  try {
    if (!opts.raw && contentType.indexOf('application/json') >= 0) {
      payload = await response.json();
    } else {
      text = await response.text();
      payload = text;
      if (!opts.raw && contentType.indexOf('application/json') >= 0) {
        try {
          payload = JSON.parse(text);
        } catch (err) {
          payload = text;
        }
      }
    }
  } catch (err) {
    if (!response.ok) throw new ApiError('HTTP ' + response.status + '（响应体无法解析）', {
      code: ErrorCode.BAD_RESPONSE,
      status: response.status,
    });
    throw new ApiError('响应体不是合法 JSON', { code: ErrorCode.BAD_RESPONSE, status: response.status });
  }

  if (!response.ok) {
    if (response.status === 403) {
      throw new ApiError((payload && payload.error && payload.error.message) || '被拒绝：缺少自定义头 / Origin 校验未通过', {
        code: ErrorCode.FORBIDDEN,
        status: 403,
        detail: '写操作必须带 ' + CONSOLE_HEADER + ': 1，且 Origin 与站点一致',
        payload: payload,
      });
    }
    if (response.status === 404 || response.status === 501) {
      throw new ApiError('后端尚未实现该端点（HTTP ' + response.status + '）', {
        code: ErrorCode.NOT_FOUND,
        status: response.status,
        detail: method + ' ' + url,
        payload: payload,
      });
    }
    throw extractError(payload, response.status);
  }

  return payload;
}

/** 写操作结果里的 warnings 统一取出来给界面提示。 */
export function warningsOf(result) {
  if (!result || typeof result !== 'object') return [];
  if (Array.isArray(result.warnings)) return result.warnings;
  return [];
}

export function snapshotVersionOf(result) {
  if (!result || typeof result !== 'object') return '';
  return result.snapshot_version || '';
}

function seg(value) {
  return encodeURIComponent(String(value));
}

export function url(path, params) {
  return API_BASE + path + buildQuery(params);
}

export function eventsStreamUrl() {
  return url('/events/stream');
}

export function eventRawUrl(id) {
  return url('/events/' + seg(id) + '/raw');
}

export function eventsExportUrl(params) {
  return url('/events/export', params);
}

export function backupUrl() {
  return url('/backup');
}

/** /api/v1 端点封装。所有页面都只通过这里取数。 */
export const api = {
  /* 认证 */
  session: () => request('/session'),
  login: (credentials) => request('/login', { method: 'POST', body: credentials }),
  logout: () => request('/logout', { method: 'POST' }),
  changePassword: (body) => request('/password', { method: 'POST', body: body }),
  enrollTotp: (body) => request('/totp/enroll', { method: 'POST', body: body || {} }),

  /* 门槛 */
  gate: () => request('/gate'),
  rotateGate: (body) => request('/gate/rotate', { method: 'POST', body: body || {} }),
  rotateGatePath: () => request('/gate/path/rotate', { method: 'POST' }),
  regenerateCert: () => request('/gate/cert/selfsigned', { method: 'POST' }),

  /* 状态与指标 */
  status: () => request('/status'),
  metricsSummary: (params) => request('/metrics/summary', { query: params }),
  timeseries: (range) => request('/metrics/timeseries', { query: { range: range } }),

  /* 事件 */
  events: (params) => request('/events', { query: params }),
  event: (id) => request('/events/' + seg(id)),
  exportEvents: (params) => request('/events/export', { query: params }),

  /* 规则 */
  rules: (params) => request('/rules', { query: params }),
  rule: (id) => request('/rules/' + seg(id)),
  patchRule: (id, patch) => request('/rules/' + seg(id), { method: 'PATCH', body: patch }),
  validateRules: (body) => request('/rules/validate', { method: 'POST', body: body }),
  testRule: (body) => request('/rules/test', { method: 'POST', body: body }),
  rulesets: () => request('/rulesets'),
  reloadRulesets: () => request('/rulesets/reload', { method: 'POST' }),
  previewMutation: (body) => request('/rulesets/preview', { method: 'POST', body: body }),

  /* 例外与名单 */
  exceptions: (params) => request('/exceptions', { query: params }),
  createException: (body) => request('/exceptions', { method: 'POST', body: body }),
  updateException: (id, body) => request('/exceptions/' + seg(id), { method: 'PATCH', body: body }),
  deleteException: (id) => request('/exceptions/' + seg(id), { method: 'DELETE' }),
  ipLists: (params) => request('/ip-lists', { query: params }),
  createIpEntry: (body) => request('/ip-lists', { method: 'POST', body: body }),
  deleteIpEntry: (id) => request('/ip-lists/' + seg(id), { method: 'DELETE' }),

  /* 限速与封禁 */
  ratelimit: () => request('/ratelimit'),
  putRatelimit: (body) => request('/ratelimit', { method: 'PUT', body: body }),
  bans: (params) => request('/bans', { query: params }),
  unban: (ip) => request('/bans/' + seg(ip), { method: 'DELETE' }),

  /* 配置 */
  config: () => request('/config'),
  putConfig: (body) => request('/config', { method: 'PUT', body: body }),
  configDiff: () => request('/config/diff'),
  reloadConfig: () => request('/config/reload', { method: 'POST' }),

  /* 备份与通知 */
  restore: (body) => request('/restore', { method: 'POST', body: body }),
  notify: () => request('/notify'),
  putNotify: (body) => request('/notify', { method: 'PUT', body: body }),
  testNotify: (body) => request('/notify/test', { method: 'POST', body: body || {} }),

  /* 操作审计 */
  consoleAudit: (params) => request('/console-audit', { query: params }),
};
