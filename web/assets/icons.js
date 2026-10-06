// web/assets/icons.js
// 职责：内联 SVG 图标。**不引图标字体、不引图片文件**（CSP 与"单二进制"两条约束都在）。
// 约定：全部用 currentColor 描边，尺寸随 size 参数；颜色交给外层 CSS。
// 品牌标记的渐变定义在 index.html 的 <defs> 里（只定义一次，避免多个实例 ID 冲突）。

import { svgEl } from './dom.js';

const STROKE = {
  fill: 'none',
  stroke: 'currentColor',
  'stroke-width': '1.7',
  'stroke-linecap': 'round',
  'stroke-linejoin': 'round',
};

// 每个导航项一个图标：形状尽量表达语义，而不是套通用图标。
const NAV_ICONS = {
  // 概览：四格仪表盘
  dashboard: (s) => [
    svgEl('rect', { attrs: { x: '3.5', y: '3.5', width: '7', height: '7', rx: '1.6', ...s } }),
    svgEl('rect', { attrs: { x: '13.5', y: '3.5', width: '7', height: '4.5', rx: '1.6', ...s } }),
    svgEl('rect', { attrs: { x: '3.5', y: '13.5', width: '7', height: '7', rx: '1.6', ...s } }),
    svgEl('rect', { attrs: { x: '13.5', y: '11', width: '7', height: '9.5', rx: '1.6', ...s } }),
  ],
  // 攻击事件：一条跳动的活动线
  activity: (s) => [
    svgEl('path', { attrs: { d: 'M3 12.5h3.6l2.2-6 3.2 12 2.4-6H21', ...s } }),
  ],
  // 规则管理：三条带滑块的推子
  sliders: (s) => [
    svgEl('path', { attrs: { d: 'M4 7h16', ...s } }),
    svgEl('circle', { attrs: { cx: '9', cy: '7', r: '2.2', ...s } }),
    svgEl('path', { attrs: { d: 'M4 12.5h16', ...s } }),
    svgEl('circle', { attrs: { cx: '15.5', cy: '12.5', r: '2.2', ...s } }),
    svgEl('path', { attrs: { d: 'M4 18h16', ...s } }),
    svgEl('circle', { attrs: { cx: '7.5', cy: '18', r: '2.2', ...s } }),
  ],
  // 规则测试台：烧杯
  beaker: (s) => [
    svgEl('path', { attrs: { d: 'M9 3v6.2L4.9 18.4A1.8 1.8 0 0 0 6.5 21h11a1.8 1.8 0 0 0 1.6-2.6L15 9.2V3', ...s } }),
    svgEl('path', { attrs: { d: 'M7.8 3h8.4', ...s } }),
    svgEl('path', { attrs: { d: 'M7 14.5h10', ...s } }),
  ],
  // 例外与白名单：漏斗（筛掉）
  funnel: (s) => [
    svgEl('path', { attrs: { d: 'M4 5h16l-6.2 7.2V20l-3.6-2v-5.8L4 5Z', ...s } }),
  ],
  // CC 防护与限速：仪表盘
  gauge: (s) => [
    svgEl('path', { attrs: { d: 'M3.8 17.5a8.5 8.5 0 1 1 16.4 0', ...s } }),
    svgEl('path', { attrs: { d: 'M12 17.5l4.3-5.2', ...s } }),
  ],
  // 系统设置：齿轮（中心圆 + 八根齿）
  gear: (s) => [
    svgEl('circle', { attrs: { cx: '12', cy: '12', r: '3', ...s } }),
    svgEl('path', { attrs: { d: 'M12 2.8v2.6M12 18.6v2.6M4.7 4.7l1.9 1.9M17.4 17.4l1.9 1.9M2.8 12h2.6M18.6 12h2.6M4.7 19.3l1.9-1.9M17.4 6.6l1.9-1.9', ...s } }),
  ],
  // 操作审计：带夹子的记录板
  clipboard: (s) => [
    svgEl('path', { attrs: { d: 'M9 4.5h6v2.2H9z', ...s } }),
    svgEl('rect', { attrs: { x: '5', y: '5.5', width: '14', height: '15.5', rx: '2.2', ...s } }),
    svgEl('path', { attrs: { d: 'M9 12h6M9 16h4', ...s } }),
  ],
};

// 路由 → 图标名。放在这里而不是散在 app.js，是为了让"加了导航却忘了图标"一眼可见。
const ROUTE_ICON = {
  '/': 'dashboard',
  '/events': 'activity',
  '/rules': 'sliders',
  '/ruletest': 'beaker',
  '/exceptions': 'funnel',
  '/ratelimit': 'gauge',
  '/settings': 'gear',
  '/audit': 'clipboard',
};

/** navIcon 返回某个路由的图标；没有对应图标时返回 null（外层回退到圆点）。 */
export function navIcon(route, size = 16) {
  const name = ROUTE_ICON[route];
  if (!name) return null;
  const svg = svgEl('svg', {
    attrs: {
      class: 'nav__icon',
      width: size,
      height: size,
      viewBox: '0 0 24 24',
      'aria-hidden': 'true',
      focusable: 'false',
    },
  });
  for (const child of NAV_ICONS[name](STROKE)) svg.appendChild(child);
  return svg;
}

/** brandMark 是侧栏与登录页共用的品牌标记：盾牌 + 一道斜杠（拦截）。 */
export function brandMark(size = 26) {
  const svg = svgEl('svg', {
    attrs: {
      class: 'brand-mark',
      width: size,
      height: size,
      viewBox: '0 0 24 24',
      'aria-hidden': 'true',
      focusable: 'false',
    },
  });
  // 盾牌本体：渐变填充（渐变在 index.html 的 <defs> 里定义）
  svg.appendChild(
    svgEl('path', {
      attrs: {
        d: 'M12 2.2 4.3 5.3v6.3c0 4.7 3.2 8.5 7.7 10.2 4.5-1.7 7.7-5.5 7.7-10.2V5.3L12 2.2Z',
        fill: 'url(#dn-mark)',
      },
    })
  );
  // 内层细描边：给平涂的盾牌一点厚度
  svg.appendChild(
    svgEl('path', {
      attrs: {
        d: 'M12 4.7 6.5 7v4.6c0 3.5 2.2 6.4 5.5 7.8 3.3-1.4 5.5-4.3 5.5-7.8V7L12 4.7Z',
        fill: 'none',
        stroke: 'rgba(255,255,255,0.32)',
        'stroke-width': '0.9',
      },
    })
  );
  // 中间那道斜杠：一眼看出是"拦下来"
  svg.appendChild(
    svgEl('path', {
      attrs: {
        d: 'M9.5 14.6 14.5 9.4',
        stroke: 'rgba(255,255,255,0.95)',
        'stroke-width': '1.8',
        'stroke-linecap': 'round',
      },
    })
  );
  return svg;
}
