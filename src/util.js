import { readFileSync } from 'node:fs';

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
export const SEVERITY_WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 1 };

export function severityAtLeast(sev, threshold) {
  return SEVERITIES.indexOf(sev) >= SEVERITIES.indexOf(threshold);
}

export function readText(absPath) {
  return readFileSync(absPath, 'utf8');
}

export function lineColFromIndex(text, index) {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === '\n') {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, column: index - lineStart + 1 };
}

export function snippetAt(text, index, length = 1) {
  const start = text.lastIndexOf('\n', index) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  let snip = text.slice(start, end).replace(/\s+$/, '');
  if (snip.length > 200) {
    const offset = Math.max(0, Math.min(index - start, snip.length - 120));
    snip = '…' + snip.slice(offset, offset + 160) + '…';
  }
  return snip;
}

/**
 * Replace comment characters with spaces (string literals preserved, newlines
 * kept) so match indices and line/column positions stay valid against the
 * original text. Used to keep commented-out code out of pattern rules.
 */
export function maskComments(text, { isPython = false } = {}) {
  const out = text.split('');
  const blank = (i) => { if (text[i] !== '\n') out[i] = ' '; };
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === '"' || c === "'" || (!isPython && c === '`')) {
      let j = i + 1;
      while (j < n) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === c) { j++; break; }
        if (text[j] === '\n' && c !== '`') { j++; break; }
        j++;
      }
      i = j;
      continue;
    }
    if (c === '#' && isPython) {
      while (i < n && text[i] !== '\n') { blank(i); i++; }
      continue;
    }
    if (!isPython && c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') { blank(i); i++; }
      continue;
    }
    if (!isPython && c === '/' && text[i + 1] === '*') {
      let j = i + 2;
      while (j < n && !(text[j] === '*' && text[j + 1] === '/')) { blank(j); j++; }
      if (j < n) { blank(j); blank(j + 1); j += 2; }
      i = j;
      continue;
    }
    i++;
  }
  return out.join('');
}

/**
 * Scan `text` for every match of `regex` (must be global).
 * Returns [{ index, match }] where match is the last capture group if present,
 * otherwise the full match.
 */
export function allMatches(text, regex) {
  const out = [];
  regex.lastIndex = 0;
  let m;
  while ((m = regex.exec(text)) !== null) {
    if (m[0].length === 0) { regex.lastIndex++; continue; }
    out.push({ index: m.index, match: m[m.length - 1] ?? m[0], full: m[0], groups: m });
  }
  return out;
}

/**
 * Find `needle` matches that occur within `window` characters of any
 * `anchor` match — used to link "reads secrets" with "talks to network".
 */
export function proximity(anchors, needles, window = 500) {
  const hits = new Map();
  for (const n of needles) {
    for (const a of anchors) {
      if (Math.abs(n.index - a.index) <= window) {
        if (!hits.has(n.index)) hits.set(n.index, { needle: n, anchor: a });
        break;
      }
    }
  }
  return [...hits.values()];
}

const B64_RE = /(?:[A-Za-z0-9+/]{4}){12,}={0,2}/g;

export function base64Blobs(text) {
  const blobs = [];
  for (const hit of allMatches(text, B64_RE)) {
    const raw = hit.full;
    try {
      const decoded = Buffer.from(raw, 'base64').toString('utf8');
      if (/^[\x09\x0a\x0d\x20-\x7e\u4e00-\u9fff]{20,}$/.test(decoded)) {
        blobs.push({ index: hit.index, encoded: raw, decoded });
      }
    } catch { /* not valid payload, ignore */ }
  }
  return blobs;
}

export function escapeXml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

export function visibleUnicode(s) {
  return [...s]
    .map((ch) => (ch.codePointAt(0) < 0x20 || /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/.test(ch)
      ? `\\u${ch.codePointAt(0).toString(16).padStart(4, '0')}`
      : ch))
    .join('');
}
