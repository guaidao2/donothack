// web/assets/store.js
// 职责：手写极简响应式状态（对象 + 订阅）与异步资源状态机（idle/loading/ready/error/unauthenticated）。
// 约束：不引框架、不引第三方库；状态只存数据，DOM 由视图负责。

/** 资源加载状态。unauthenticated 单独成态，页面必须显示"需要认证"而不是假装有数据。 */
export const Status = Object.freeze({
  IDLE: 'idle',
  LOADING: 'loading',
  READY: 'ready',
  ERROR: 'error',
  UNAUTHENTICATED: 'unauthenticated',
});

/**
 * 极简 store：get / set / subscribe。
 * set 接受对象补丁或 (prev) => next。
 */
export function createStore(initial = {}) {
  let state = initial;
  const listeners = new Set();

  return {
    get() {
      return state;
    },
    set(patch) {
      const next = typeof patch === 'function' ? patch(state) : Object.assign({}, state, patch);
      if (next === state) return state;
      state = next;
      for (const fn of Array.from(listeners)) {
        try {
          fn(state);
        } catch (err) {
          // 单个订阅者出错不拖垮其他订阅者，也不静默吞掉：交给全局错误处理器。
          reportInternalError(err);
        }
      }
      return state;
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

function reportInternalError(err) {
  const handler = globalThis.__DONOTHACK_ON_ERROR__;
  if (typeof handler === 'function') handler(err);
  else if (globalThis.console) globalThis.console.error('[store] 订阅回调异常', err);
}

/**
 * 异步资源：把"取数"这件事的四种状态收进一个对象，视图只需按状态渲染。
 * 并发加载用序号守卫，旧请求的结果不会覆盖新请求。
 */
export function createResource(loader, options = {}) {
  const store = createStore({
    status: Status.IDLE,
    data: Object.prototype.hasOwnProperty.call(options, 'initial') ? options.initial : null,
    error: null,
    loadedAt: null,
  });
  let seq = 0;

  async function load(params) {
    const mine = ++seq;
    store.set((prev) => Object.assign({}, prev, { status: Status.LOADING, error: null }));
    try {
      const data = await loader(params);
      if (mine !== seq) return store.get();
      const next = { status: Status.READY, data, error: null, loadedAt: Date.now() };
      store.set(next);
      return next;
    } catch (err) {
      if (mine !== seq) return store.get();
      const code = err && err.code;
      const unauthorized = code === 'unauthenticated' || (err && err.status === 401);
      store.set((prev) => ({
        status: unauthorized ? Status.UNAUTHENTICATED : Status.ERROR,
        data: unauthorized ? null : prev.data,
        error: err,
        loadedAt: null,
      }));
      return store.get();
    }
  }

  function reset() {
    seq++;
    store.set({
      status: Status.IDLE,
      data: Object.prototype.hasOwnProperty.call(options, 'initial') ? options.initial : null,
      error: null,
      loadedAt: null,
    });
  }

  return {
    load,
    reload: load,
    reset,
    get: store.get,
    subscribe: store.subscribe,
    store,
  };
}

/** 会话状态：全站唯一，决定显示控制台还是登录页。 */
export const session = createStore({
  status: 'unknown', // unknown | unauthenticated | authenticated
  actor: '',
  totpEnabled: false,
  idleTimeoutS: null,
  error: null,
});

/** 全局界面状态：当前路由、页面标题、侧栏高亮、概览时间范围。 */
export const ui = createStore({
  path: '/',
  routeName: '',
  title: '概览',
  range: '1h',
  streamEnabled: false,
});

/** 会话是否已认证。 */
export function isAuthenticated() {
  return session.get().status === 'authenticated';
}

/** 表单输入防抖（过滤框用）。 */
export function debounce(fn, wait = 250) {
  let timer = null;
  return function debounced(...args) {
    if (timer !== null) globalThis.clearTimeout(timer);
    timer = globalThis.setTimeout(() => {
      timer = null;
      fn.apply(null, args);
    }, wait);
  };
}
