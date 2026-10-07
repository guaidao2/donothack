// web/assets/api.js
// 职责：控制台与 /api/v1 的唯一出入口 —— URL 组装、统一错误对象、认证头与 CSRF 头、401 通知、SSE 与下载地址。
// 约定：写操作一律 POST/PUT/PATCH/DELETE + 自定义头 + Origin 校验；
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

// CSRF 的**裸 token**由 /session 与 /login 的响应体给出（app.js 在会话刷新时存进来）。
// cookie 里那个值是"裸 token.HMAC"，服务端要求请求头等于裸 token ——
// 早期这里只读 cookie，于是所有写操作都会 403 csrf_mismatch。
let csrfRawToken = '';

export function setCSRFToken(token) {
  csrfRawToken = typeof token === 'string' ? token : '';
}

function csrfToken() {
  return csrfRawToken || readCookie(CSRF_COOKIE);
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

/** 统一的后置处理：401 通知、错误归一化、JSON / 文本解析。 */
async function finalize(response, method, url, raw, opts) {
  const skipUnauthorized = !!(opts && opts.skipUnauthorized);

  if (response.status === 204 || response.status === 205) {
    if (!response.ok) throw new ApiError('HTTP ' + response.status, { code: ErrorCode.HTTP, status: response.status });
    return null;
  }

  const contentType = response.headers.get('content-type') || '';
  let payload = null;
  let text = '';
  try {
    if (!raw && contentType.indexOf('application/json') >= 0) {
      payload = await response.json();
    } else {
      text = await response.text();
      payload = text;
      if (!raw && contentType.indexOf('application/json') >= 0) {
        try {
          payload = JSON.parse(text);
        } catch (err) {
          payload = text;
        }
      }
    }
  } catch (err) {
    if (!response.ok) {
      throw new ApiError('HTTP ' + response.status + '（响应体无法解析）', {
        code: ErrorCode.BAD_RESPONSE,
        status: response.status,
      });
    }
    throw new ApiError('响应体不是合法 JSON', { code: ErrorCode.BAD_RESPONSE, status: response.status });
  }

  if (!response.ok) {
    if (response.status === 401) {
      const serverError = payload && typeof payload === 'object' ? payload.error : null;
      // 登录接口的 401 是"凭据不对"，不是"会话过期"：不能触发全局未认证处理，
      // 否则登录页会被整屏重绘成"会话已过期"，把行内错误提示冲掉（实测踩过）。
      if (!skipUnauthorized) notifyUnauthorized();
      if (serverError && serverError.code && serverError.code !== ErrorCode.UNAUTHENTICATED) {
        throw new ApiError(serverError.message || '请求未通过认证', {
          code: serverError.code,
          status: 401,
          detail: serverError.detail || '',
          payload: payload,
        });
      }
      throw new ApiError('需要认证：会话不存在或已过期', {
        code: ErrorCode.UNAUTHENTICATED,
        status: 401,
        detail: '请重新登录控制台',
        payload: payload,
      });
    }
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

  const target = API_BASE + path + buildQuery(opts.query);
  let response;
  try {
    response = await fetch(target, {
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

  return finalize(response, method, target, opts.raw, opts);
}

/**
 * 表单（multipart/form-data）POST：仅用于文件上传类端点，例如 POST /restore。
 * 自定义头与 CSRF 头照旧带上；Content-Type 交给浏览器自己带 boundary。
 */
export async function postForm(path, formData, opts = {}) {
  const headers = { Accept: 'application/json' };
  headers[CONSOLE_HEADER] = '1';
  const token = csrfToken();
  if (token) headers[CSRF_HEADER] = token;

  const target = API_BASE + path + buildQuery(opts.query);
  let response;
  try {
    response = await fetch(target, {
      method: 'POST',
      headers: headers,
      body: formData,
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch (err) {
    throw new ApiError('无法连接控制台后端（' + (err && err.message ? err.message : '网络错误') + '）', {
      code: ErrorCode.NETWORK,
      status: 0,
    });
  }
  return finalize(response, 'POST', target, false, opts);
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
  // 登录接口的 401 必须留在登录页里显示（skipUnauthorized），否则会被当成会话过期整屏重绘。
  login: (credentials) => request('/login', { method: 'POST', body: credentials, skipUnauthorized: true }),
  logout: () => request('/logout', { method: 'POST' }),
  changePassword: (body) => request('/password', { method: 'POST', body: body }),
  enrollTotp: (body) => request('/totp/enroll', { method: 'POST', body: body || {} }),

  /* 引擎热参数（模式 / 阈值 / 命中即封禁）：整份 PUT /config 被后端有意拒绝，改这些走专用端点 */
  engine: () => request('/engine'),
  setEngine: (body) => request('/engine', { method: 'PUT', body: body }),

  /* 门槛 */

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
  // 刻意没有 putConfig：后端**有意拒绝**整份写配置（大部分项改了必须重启，
  // 静默忽略会让人以为改生效了），它会回 405 并指路到各专用端点。
  // 能热改的走 PUT /engine、PUT /ratelimit、PUT /block-page、POST /rulesets/reload。
  configDiff: () => request('/config/diff'),
  reloadConfig: () => request('/config/reload', { method: 'POST' }),

  /* 备份与通知 */
  restore: (formData, opts) => postForm('/restore', formData, opts),
  notify: () => request('/notify'),
  putNotify: (body) => request('/notify', { method: 'PUT', body: body }),
  testNotify: (body) => request('/notify/test', { method: 'POST', body: body || {} }),

  /* 操作审计 */
  consoleAudit: (params) => request('/console-audit', { query: params }),
};
