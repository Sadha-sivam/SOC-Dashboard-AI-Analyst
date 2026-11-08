import { Fragment, type ReactNode } from 'react';

/**
 * Small, dependency-free Markdown renderer for AI answers.
 * Produces React elements only (never raw HTML), so model output cannot inject markup.
 * Supports: headings, paragraphs, bullet/numbered lists, bold, italic, inline code, code fences, tables, rules.
 */

function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(__[^_]+__)|(\*[^*\s][^*]*\*)|((?<![A-Za-z0-9])_[^_\s][^_]*_(?![A-Za-z0-9]))/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let i = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const tok = m[0];
    const key = `${keyBase}-${i++}`;
    if (tok.startsWith('`')) {
      out.push(<code key={key} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[0.85em] text-sky-200">{tok.slice(1, -1)}</code>);
    } else if (tok.startsWith('**') || tok.startsWith('__')) {
      out.push(<strong key={key} className="font-semibold text-white">{tok.slice(2, -2)}</strong>);
    } else {
      out.push(<em key={key}>{tok.slice(1, -1)}</em>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

const isTableSep = (l: string) => /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l);
const splitRow = (l: string) => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());

export function Markdown({ text }: { text: string }) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  const blocks: ReactNode[] = [];
  let i = 0;
  let k = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (/^\s*```/.test(line)) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      blocks.push(<pre key={k++} className="my-3 overflow-x-auto rounded-lg border border-slate-800 bg-black p-3 text-xs leading-5 text-slate-300"><code>{buf.join('\n')}</code></pre>);
      continue;
    }

    const h = /^(#{1,4})\s+(.*)$/.exec(line);
    if (h) {
      const level = h[1].length;
      const cls =
        level <= 2
          ? 'mt-5 mb-2 border-b border-slate-800 pb-1 text-base font-semibold text-white first:mt-0'
          : 'mt-4 mb-1.5 text-sm font-semibold text-slate-100';
      blocks.push(<div key={k++} role="heading" aria-level={level} className={cls}>{inline(h[2], `h${k}`)}</div>);
      i++;
      continue;
    }

    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) {
      blocks.push(<hr key={k++} className="my-4 border-slate-800" />);
      i++;
      continue;
    }

    if (line.includes('|') && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) rows.push(splitRow(lines[i++]));
      blocks.push(
        <div key={k++} className="my-3 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400"><tr>{head.map((c, j) => <th key={j} className="px-3 py-2 font-medium">{inline(c, `th${k}${j}`)}</th>)}</tr></thead>
            <tbody className="divide-y divide-slate-800">{rows.map((r, ri) => <tr key={ri}>{r.map((c, j) => <td key={j} className="px-3 py-2 align-top text-slate-300">{inline(c, `td${k}${ri}${j}`)}</td>)}</tr>)}</tbody>
          </table>
        </div>,
      );
      continue;
    }

    const li = /^(\s*)([-*•]|\d+[.)])\s+(.*)$/.exec(line);
    if (li) {
      const ordered = /\d/.test(li[2]);
      const items: ReactNode[] = [];
      while (i < lines.length) {
        const m = /^(\s*)([-*•]|\d+[.)])\s+(.*)$/.exec(lines[i]);
        if (!m || /\d/.test(m[2]) !== ordered) break;
        const indent = m[1].length >= 2;
        items.push(<li key={items.length} className={indent ? 'ml-5 list-[circle]' : ''}>{inline(m[3], `li${k}${items.length}`)}</li>);
        i++;
      }
      const Tag = ordered ? 'ol' : 'ul';
      blocks.push(<Tag key={k++} className={`my-2 space-y-1 pl-5 ${ordered ? 'list-decimal' : 'list-disc'} marker:text-slate-500`}>{items}</Tag>);
      continue;
    }

    if (!line.trim()) {
      i++;
      continue;
    }

    const para: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() &&
      !/^\s*```/.test(lines[i]) &&
      !/^(#{1,4})\s+/.test(lines[i]) &&
      !/^(\s*)([-*•]|\d+[.)])\s+/.test(lines[i]) &&
      !(lines[i].includes('|') && i + 1 < lines.length && isTableSep(lines[i + 1]))
    ) {
      para.push(lines[i++]);
    }
    blocks.push(
      <p key={k++} className="my-2 leading-7">
        {para.map((p, j) => <Fragment key={j}>{j > 0 && <br />}{inline(p, `p${k}${j}`)}</Fragment>)}
      </p>,
    );
  }

  return <div className="text-[15px] text-slate-200">{blocks}</div>;
}
