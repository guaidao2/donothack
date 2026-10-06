// web/assets/md.js
// 职责：极小 markdown 子集渲染器 —— **只支持**围栏代码块、表格、粗体、换行四种结构。
// 不支持：链接、图片、raw 结构、内联事件、标题、列表。任何未识别的行都按纯文本展示。
// 安全：全部节点由 createElement 生成，文本一律 textContent；代码块强制走 dom.renderCode（唯一原语）。

import { el, renderCode } from './dom.js';

const FENCE_RE = /^\s*```(.*)$/;
const TABLE_SEP_RE = /^\s*\|?[\s:|-]+\|[\s:|-]*$/;

function isFenceStart(line) {
  return FENCE_RE.test(line);
}

function isTableStart(lines, index) {
  if (!/^\s*\|/.test(lines[index] || '')) return false;
  const next = lines[index + 1];
  if (next === undefined) return false;
  return TABLE_SEP_RE.test(next) && next.indexOf('|') >= 0;
}

function splitRow(line) {
  let text = line.trim();
  if (text.startsWith('|')) text = text.slice(1);
  if (text.endsWith('|')) text = text.slice(0, -1);
  return text.split('|').map((cell) => cell.trim());
}

function alignmentOf(separator) {
  return splitRow(separator).map((cell) => {
    const left = cell.startsWith(':');
    const right = cell.endsWith(':');
    if (left && right) return 'center';
    if (right) return 'right';
    return 'left';
  });
}

/** 行内只处理粗体（**x**），其余字符原样作为文本。 */
function inlineInto(parent, text) {
  const parts = String(text).split(/(\*\*[^*]+\*\*)/g);
  for (const part of parts) {
    if (!part) continue;
    if (part.length > 4 && part.startsWith('**') && part.endsWith('**')) {
      parent.appendChild(el('strong', { text: part.slice(2, -2) }));
    } else {
      parent.appendChild(document.createTextNode(part));
    }
  }
}

function paragraph(lines) {
  const node = el('p');
  lines.forEach((line, index) => {
    if (index > 0) node.appendChild(el('br'));
    inlineInto(node, line);
  });
  return node;
}

function tableNode(header, separator, rows) {
  const align = alignmentOf(separator);
  const thead = el('thead');
  const headRow = el('tr');
  header.forEach((cell, index) => {
    const th = el('th', { attrs: { class: align[index] === 'right' ? 'col-num' : 'is-wrap' } });
    inlineInto(th, cell);
    headRow.appendChild(th);
  });
  thead.appendChild(headRow);

  const tbody = el('tbody');
  for (const row of rows) {
    const tr = el('tr');
    for (let i = 0; i < header.length; i++) {
      const td = el('td', { attrs: { class: align[i] === 'right' ? 'col-num' : 'is-wrap' } });
      inlineInto(td, row[i] === undefined ? '' : row[i]);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  return el('div', { class: 'table-wrap' }, el('table', { class: 'table' }, thead, tbody));
}

/**
 * 渲染 markdown 子集。
 * @param {string} source
 * @returns {DocumentFragment}
 */
export function renderMarkdown(source) {
  const frag = document.createDocumentFragment();
  const lines = String(source === null || source === undefined ? '' : source).split(/\r?\n/);
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    const fence = FENCE_RE.exec(line);
    if (fence) {
      const label = (fence[1] || '').trim() || 'code';
      const body = [];
      i++;
      while (i < lines.length && !isFenceStart(lines[i])) {
        body.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++; // 跳过收尾围栏
      frag.appendChild(renderCode(body.join('\n'), { label: label, meta: body.length + ' 行' }));
      continue;
    }

    if (line.trim() === '') {
      i++;
      continue;
    }

    if (isTableStart(lines, i)) {
      const header = splitRow(lines[i]);
      const separator = lines[i + 1];
      const rows = [];
      i += 2;
      while (i < lines.length && /^\s*\|/.test(lines[i]) && lines[i].trim() !== '') {
        rows.push(splitRow(lines[i]));
        i++;
      }
      frag.appendChild(tableNode(header, separator, rows));
      continue;
    }

    const para = [];
    while (i < lines.length && lines[i].trim() !== '' && !isFenceStart(lines[i]) && !isTableStart(lines, i)) {
      para.push(lines[i]);
      i++;
    }
    frag.appendChild(paragraph(para));
  }

  return frag;
}

/** 只取纯文本（用于 title 属性、日志等场景，不生成任何节点）。 */
export function markdownToPlainText(source) {
  return String(source === null || source === undefined ? '' : source)
    .replace(/^\s*```.*$/gm, '')
    .replace(/\*\*/g, '')
    .replace(/\s*\|\s*/g, ' | ')
    .trim();
}
