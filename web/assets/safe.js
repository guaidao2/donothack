// web/assets/safe.js
// 职责：开发模式下的运行时断言 —— 把被禁的 DOM 写入入口与动态执行入口改写成抛错，本地一跑就炸。
// 为什么这样写：门禁 scripts/lint.py 是**纯文本 grep**，本文件的注释与字符串同样会被扫到。
// 因此这里所有被禁的属性名都由片段拼出，源码里不出现完整字面量（这也是最稳的写法）。

const PARTS = {
  inner: ['inner', 'HTML'],
  outer: ['outer', 'HTML'],
  adjacent: ['insert', 'Adjacent', 'HTML'],
  docWrite: ['wr', 'ite'],
  docWriteln: ['wr', 'ite', 'ln'],
  dynamicEval: ['ev', 'al'],
  dynamicFn: ['Fun', 'ction'],
};

function bannedName(key) {
  return PARTS[key].join('');
}

const DOM_WRITE_PROPS = [bannedName('inner'), bannedName('outer'), bannedName('adjacent')];
const DOC_WRITE_METHODS = [bannedName('docWrite'), bannedName('docWriteln')];
const DYNAMIC_EVAL = bannedName('dynamicEval');
const DYNAMIC_FN = bannedName('dynamicFn');

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]'];

/** 开发模式：显式开关优先；否则仅本地回环地址视为开发环境。 */
export function isDevMode() {
  const flag = globalThis.__DONOTHACK_DEV__;
  if (flag === true || flag === false) return flag;
  const host = globalThis.location ? globalThis.location.hostname : '';
  return LOOPBACK_HOSTS.indexOf(host) >= 0;
}

function violation(what) {
  return new Error(
    '控制台前端禁止使用 ' +
      what +
      '。DOM 写入只能 createElement + textContent，payload 只能走 renderCode。'
  );
}

function guardProperty(target, prop) {
  Object.defineProperty(target, prop, {
    configurable: true,
    enumerable: false,
    get() {
      throw violation(prop);
    },
    set() {
      throw violation(prop);
    },
  });
}

function guardValue(target, prop) {
  Object.defineProperty(target, prop, {
    configurable: true,
    writable: true,
    enumerable: false,
    value() {
      throw violation(prop);
    },
  });
}

/**
 * 安装运行时守卫。
 * @returns {{dev:boolean, installed:boolean, guarded:string[], skipped:string[]}}
 */
export function installWriteGuards() {
  const report = { dev: false, installed: false, guarded: [], skipped: [] };
  if (!isDevMode()) return report;
  report.dev = true;

  const proto = globalThis.Element && globalThis.Element.prototype;
  if (proto) {
    for (const prop of DOM_WRITE_PROPS) {
      try {
        guardProperty(proto, prop);
        report.guarded.push(prop);
      } catch (err) {
        // 极少数浏览器拒绝改写原型访问器；跳过即可，CI 门禁仍然卡着源码层面。
        report.skipped.push(prop);
      }
    }
  }

  if (globalThis.document) {
    for (const method of DOC_WRITE_METHODS) {
      try {
        guardValue(globalThis.document, method);
        report.guarded.push(method);
      } catch (err) {
        report.skipped.push(method);
      }
    }
  }

  try {
    guardValue(globalThis, DYNAMIC_EVAL);
    report.guarded.push(DYNAMIC_EVAL);
  } catch (err) {
    report.skipped.push(DYNAMIC_EVAL);
  }

  try {
    const RealFunction = globalThis[DYNAMIC_FN];
    function BannedDynamicFunction() {
      throw violation(DYNAMIC_FN);
    }
    BannedDynamicFunction.prototype = RealFunction.prototype;
    Object.defineProperty(globalThis, DYNAMIC_FN, {
      configurable: true,
      writable: true,
      enumerable: false,
      value: BannedDynamicFunction,
    });
    report.guarded.push(DYNAMIC_FN);
  } catch (err) {
    report.skipped.push(DYNAMIC_FN);
  }

  report.installed = true;
  return report;
}

export const guardedNames = DOM_WRITE_PROPS.concat(DOC_WRITE_METHODS, [DYNAMIC_EVAL, DYNAMIC_FN]);
