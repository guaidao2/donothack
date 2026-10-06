// web/assets/components/chart.js
// 职责：手写 SVG 图表 —— 折线（带十字准星读数）、柱状。**不引任何第三方图表库**。
// 说明： 原本写的是 vendored uPlot，本轮按任务要求改为自绘 SVG，
//       因为离线环境无法取得 uPlot 源码，且"不引第三方库"是硬约束。配色用 CSS 类（SVG 属性里不支持 var()）。
// 约束：不用行内 style；图形几何走 SVG 属性，宽度按容器实测像素渲染（避免文字被拉伸）。

import { el, svgEl, clear, fmtCompact, fmtInt, fmtTime } from '../dom.js';

const TONES = 6;

function lineToneClass(tone) {
  return 'chart__line chart__line--' + (((tone || 1) - 1) % TONES + 1);
}

function barToneClass(tone) {
  return 'chart__bar chart__bar--' + (((tone || 1) - 1) % TONES + 1);
}

function niceMax(value) {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const exp = Math.floor(Math.log10(value));
  const base = Math.pow(10, exp);
  const norm = value / base;
  const step = norm <= 1 ? 1 : norm <= 1.5 ? 1.5 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10;
  return step * base;
}

function chartEmpty(spec) {
  const hint = (spec.empty && spec.empty.hint) || '没有可绘制的数据点。';
  const title = (spec.empty && spec.empty.title) || '暂无数据';
  return el('div', { class: 'chart__empty' }, el('div', { class: 'strong', text: title }), el('div', { text: hint }));
}

function defaultFormatX(value, spanMs) {
  if (spanMs > 1000 * 3600 * 36) return fmtTime(value).slice(5, 16);
  if (spanMs > 1000 * 3600 * 2) return fmtTime(value).slice(11, 16);
  return fmtTime(value).slice(11, 19);
}

function defaultFormatY(value) {
  return fmtCompact(value);
}

/**
 * 折线图。
 * @param {{series:Array<{name:string,tone?:number,points:Array<{x:number,y:number}>}>,
 *          height?:number, formatX?:Function, formatY?:Function, empty?:object}} spec
 */
export function lineChart(spec) {
  const host = el('div', { class: 'chart' });
  const frame = el('div', { class: 'chart__frame' });
  host.appendChild(frame);
  let observer = null;

  const series = (spec.series || []).filter((s) => s && Array.isArray(s.points) && s.points.length > 0);
  const totalPoints = series.reduce((acc, s) => acc + s.points.length, 0);
  if (totalPoints === 0) {
    frame.appendChild(chartEmpty(spec));
    host.destroy = () => {};
    return host;
  }

  function draw() {
    const width = Math.max(280, Math.round(frame.clientWidth || 640));
    const height = Math.max(120, Math.round(spec.height || 180));
    clear(frame);

    const padL = 52;
    const padR = 12;
    const padT = 12;
    const padB = 22;

    let xMin = Infinity;
    let xMax = -Infinity;
    let yMax = 0;
    for (const s of series) {
      for (const p of s.points) {
        const x = Number(p.x);
        const y = Number(p.y) || 0;
        if (!Number.isFinite(x)) continue;
        if (x < xMin) xMin = x;
        if (x > xMax) xMax = x;
        if (y > yMax) yMax = y;
      }
    }
    if (!Number.isFinite(xMin)) {
      frame.appendChild(chartEmpty(spec));
      return;
    }
    if (xMax === xMin) xMax = xMin + 60000;
    const span = xMax - xMin;
    const top = niceMax(yMax);

    const sx = (x) => padL + ((x - xMin) / span) * (width - padL - padR);
    const sy = (y) => height - padB - (Math.max(0, Math.min(y, top)) / top) * (height - padT - padB);

    const formatX = spec.formatX || ((value) => defaultFormatX(value, span));
    const formatY = spec.formatY || defaultFormatY;

    const svg = svgEl('svg', {
      attrs: {
        class: 'chart__svg',
        viewBox: '0 0 ' + width + ' ' + height,
        width: String(width),
        height: String(height),
        role: 'img',
        'aria-label': spec.ariaLabel || '时间序列曲线',
      },
    });

    for (let i = 0; i <= 4; i++) {
      const y = padT + ((height - padT - padB) * i) / 4;
      svg.appendChild(svgEl('line', { attrs: { class: 'chart__grid', x1: padL, x2: width - padR, y1: y, y2: y } }));
      svg.appendChild(
        svgEl('text', {
          attrs: { class: 'chart__tick', x: padL - 6, y: y + 3, 'text-anchor': 'end' },
          text: formatY(top - (top * i) / 4),
        })
      );
    }

    svg.appendChild(
      svgEl('line', {
        attrs: { class: 'chart__axis', x1: padL, x2: padL, y1: padT, y2: height - padB },
      })
    );

    for (let i = 0; i <= 3; i++) {
      const x = padL + ((width - padL - padR) * i) / 3;
      const value = xMin + (span * i) / 3;
      svg.appendChild(
        svgEl('text', {
          attrs: {
            class: 'chart__tick',
            x: x,
            y: height - padB + 13,
            'text-anchor': i === 0 ? 'start' : i === 3 ? 'end' : 'middle',
          },
          text: formatX(value),
        })
      );
    }

    const guide = svgEl('line', {
      attrs: {
        class: 'chart__guide',
        x1: padL,
        x2: padL,
        y1: padT,
        y2: height - padB,
      },
    });
    guide.classList.add('hidden');

    for (const s of series) {
      const d = s.points
        .map((p, index) => (index === 0 ? 'M' : 'L') + sx(Number(p.x)).toFixed(1) + ' ' + sy(Number(p.y) || 0).toFixed(1))
        .join(' ');
      const path = svgEl('path', { attrs: { class: lineToneClass(s.tone), d: d } });
      path.appendChild(svgEl('title', { text: s.name + '：' + s.points.length + ' 个点' }));
      svg.appendChild(path);
    }
    svg.appendChild(guide);

    const caption = el('div', { class: 'chart__caption xs muted', text: '把鼠标移到曲线上查看具体数值' });

    const xValues = series[0].points.map((p) => Number(p.x));
    const maps = series.map((s) => {
      const map = new Map();
      for (const p of s.points) map.set(String(Number(p.x)), Number(p.y) || 0);
      return { series: s, map: map };
    });

    svg.addEventListener('mousemove', (event) => {
      const rect = svg.getBoundingClientRect();
      if (!rect.width) return;
      const ratio = (event.clientX - rect.left) / rect.width;
      const plotRatio = Math.max(0, Math.min(1, (ratio * width - padL) / (width - padL - padR)));
      const targetX = xMin + plotRatio * span;
      let nearest = 0;
      let best = Infinity;
      for (let i = 0; i < xValues.length; i++) {
        const dist = Math.abs(xValues[i] - targetX);
        if (dist < best) {
          best = dist;
          nearest = i;
        }
      }
      const x = xValues[nearest];
      guide.classList.remove('hidden');
      guide.setAttribute('x1', String(sx(x).toFixed(1)));
      guide.setAttribute('x2', String(sx(x).toFixed(1)));
      const parts = [formatX(x)];
      for (const entry of maps) {
        const value = entry.map.get(String(x));
        parts.push(entry.series.name + ' ' + fmtInt(value === undefined ? 0 : value));
      }
      caption.textContent = parts.join('   ·   ');
    });

    svg.addEventListener('mouseleave', () => {
      guide.classList.add('hidden');
      caption.textContent = '把鼠标移到曲线上查看具体数值';
    });

    frame.appendChild(svg);
    frame.appendChild(caption);
  }

  draw();
  if (globalThis.ResizeObserver) {
    let lastWidth = 0;
    observer = new ResizeObserver((entries) => {
      const width = Math.round(entries[0].contentRect.width);
      if (Math.abs(width - lastWidth) > 24) {
        lastWidth = width;
        draw();
      }
    });
    observer.observe(frame);
  }

  const legend = el('div', { class: 'chart__legend' });
  for (const s of series) {
    legend.appendChild(
      el(
        'span',
        { class: 'chart__legend-item' },
        el('span', { class: 'chart__swatch chart__swatch--' + (((s.tone || 1) - 1) % TONES + 1) }),
        el('span', { text: s.name })
      )
    );
  }
  host.appendChild(legend);

  host.destroy = () => {
    if (observer) observer.disconnect();
  };
  return host;
}

/**
 * 柱状图（类目分布等短标签场景）。
 * @param {{items:Array<{label:string,value:number,tone?:number}>, height?:number, formatValue?:Function, empty?:object}} spec
 */
export function barChart(spec) {
  const host = el('div', { class: 'chart' });
  const frame = el('div', { class: 'chart__frame' });
  host.appendChild(frame);
  const items = (spec.items || []).filter((item) => item && item.label !== undefined);
  let observer = null;

  if (items.length === 0) {
    frame.appendChild(chartEmpty(spec));
    host.destroy = () => {};
    return host;
  }

  const formatValue = spec.formatValue || fmtInt;

  function draw() {
    const width = Math.max(260, Math.round(frame.clientWidth || 480));
    const height = Math.max(120, Math.round(spec.height || 170));
    clear(frame);

    const padL = 8;
    const padR = 8;
    const padT = 14;
    const padB = 30;
    const max = niceMax(items.reduce((acc, item) => Math.max(acc, Number(item.value) || 0), 0));
    const slot = (width - padL - padR) / items.length;
    const barWidth = Math.max(6, Math.min(46, slot * 0.62));

    const svg = svgEl('svg', {
      attrs: {
        class: 'chart__svg',
        viewBox: '0 0 ' + width + ' ' + height,
        width: String(width),
        height: String(height),
        role: 'img',
        'aria-label': spec.ariaLabel || '分布柱状图',
      },
    });
    svg.appendChild(
      svgEl('line', {
        attrs: { class: 'chart__axis', x1: padL, x2: width - padR, y1: height - padB, y2: height - padB },
      })
    );

    items.forEach((item, index) => {
      const value = Number(item.value) || 0;
      const barHeight = max > 0 ? (value / max) * (height - padT - padB) : 0;
      const x = padL + slot * index + (slot - barWidth) / 2;
      const y = height - padB - barHeight;
      const rect = svgEl('rect', {
        attrs: {
          class: barToneClass(item.tone || index + 1),
          x: x.toFixed(1),
          y: y.toFixed(1),
          width: barWidth.toFixed(1),
          height: Math.max(1, barHeight).toFixed(1),
          rx: 2,
        },
      });
      rect.appendChild(svgEl('title', { text: item.label + '：' + formatValue(value) }));
      svg.appendChild(rect);
      if (value > 0) {
        svg.appendChild(
          svgEl('text', {
            attrs: { class: 'chart__tick', x: (x + barWidth / 2).toFixed(1), y: (y - 3).toFixed(1), 'text-anchor': 'middle' },
            text: formatValue(value),
          })
        );
      }
      const label = String(item.label);
      svg.appendChild(
        svgEl('text', {
          attrs: {
            class: 'chart__tick',
            x: (x + barWidth / 2).toFixed(1),
            y: height - padB + 13,
            'text-anchor': 'middle',
          },
          text: label.length > 8 ? label.slice(0, 7) + '…' : label,
        })
      );
    });

    frame.appendChild(svg);
  }

  draw();
  if (globalThis.ResizeObserver) {
    let lastWidth = 0;
    observer = new ResizeObserver((entries) => {
      const width = Math.round(entries[0].contentRect.width);
      if (Math.abs(width - lastWidth) > 24) {
        lastWidth = width;
        draw();
      }
    });
    observer.observe(frame);
  }

  host.destroy = () => {
    if (observer) observer.disconnect();
  };
  return host;
}
