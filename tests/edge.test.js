import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseConfig, parseSimpleYaml, defaultConfig,
} from '../src/config.js';
import {
  severityAtLeast, SEVERITIES, lineColFromIndex, snippetAt, maskComments,
  allMatches, proximity, base64Blobs, escapeXml, visibleUnicode,
} from '../src/util.js';

// ---------------------------------------------------------------------------
// config.js
// ---------------------------------------------------------------------------

test('parseSimpleYaml: scalar, number, boolean coercion', () => {
  const out = parseSimpleYaml('format: json\nfail-on: 2\nflag: true\nname: "x"');
  assert.equal(out.format, 'json');
  assert.equal(out['fail-on'], 2);
  assert.equal(out.flag, true);
  assert.equal(out.name, 'x');
});

test('parseSimpleYaml: block list parsing', () => {
  const out = parseSimpleYaml('ignore:\n  - node_modules\n  - dist\nformat: json');
  assert.deepEqual(out.ignore, ['node_modules', 'dist']);
  assert.equal(out.format, 'json');
});

test('parseSimpleYaml: comments and blank lines are skipped', () => {
  const out = parseSimpleYaml('# header\n\nkey: v   # trailing\n');
  assert.deepEqual(out, { key: 'v' });
});

test('parseSimpleYaml: quoted list items keep their content', () => {
  const out = parseSimpleYaml('ignore:\n  - "a/b"\n  - \'c d\'');
  assert.deepEqual(out.ignore, ['a/b', 'c d']);
});

test('parseConfig: JSON path decodes JSON', () => {
  const out = parseConfig('{"format":"sarif","include-all-md":true}', '.agent-scan.json');
  assert.equal(out.format, 'sarif');
  assert.equal(out['include-all-md'], true);
});

test('parseConfig: YAML is the default', () => {
  const out = parseConfig('format: md', '.agent-scan.yml');
  assert.equal(out.format, 'md');
});

test('defaultConfig: has the documented defaults', () => {
  const d = defaultConfig();
  assert.equal(d.failOn, 'critical');
  assert.equal(d.format, 'terminal');
  assert.deepEqual(d.ignore, []);
  assert.equal(d.includeAllMd, false);
});

// ---------------------------------------------------------------------------
// util.js
// ---------------------------------------------------------------------------

test('severityAtLeast: ordering and boundaries', () => {
  assert.equal(severityAtLeast('critical', 'critical'), true);
  assert.equal(severityAtLeast('high', 'critical'), false);
  assert.equal(severityAtLeast('critical', 'info'), true);
  assert.equal(SEVERITIES.length, 5);
});

test('lineColFromIndex: counts lines and columns', () => {
  const t = 'ab\ncd\nef';
  assert.deepEqual(lineColFromIndex(t, 0), { line: 1, column: 1 });
  assert.deepEqual(lineColFromIndex(t, 1), { line: 1, column: 2 });
  assert.deepEqual(lineColFromIndex(t, 3), { line: 2, column: 1 }); // start of "cd"
  assert.deepEqual(lineColFromIndex(t, 4), { line: 2, column: 2 });
});

test('snippetAt: returns the line containing the index', () => {
  const t = 'first line\nSECRET here\nlast line';
  const idx = t.indexOf('SECRET');
  const snip = snippetAt(t, idx);
  assert.ok(snip.includes('SECRET here'));
  assert.ok(!snip.includes('first line'));
});

test('maskComments: JS line comments become spaces, code preserved', () => {
  const masked = maskComments('a = 1 // comment');
  assert.equal(masked.replace(/\s+$/, ''), 'a = 1');
  assert.equal(masked.indexOf('comment'), -1);
});

test('maskComments: block comments removed, newlines kept', () => {
  const masked = maskComments('x /* block\n still block */ y');
  assert.equal(masked[0], 'x');
  assert.equal(masked[masked.length - 1], 'y');
  assert.ok(masked.includes('\n')); // newline preserved
  assert.equal(masked.indexOf('block'), -1);
});

test('maskComments: string literals are not treated as comments', () => {
  const masked = maskComments("u = 'http://example.com' // not in string");
  assert.ok(masked.includes('http://example.com'));
  assert.equal(masked.indexOf('not in string'), -1);
});

test('maskComments: python hash comments', () => {
  const masked = maskComments('x = 1 # py comment', { isPython: true });
  assert.equal(masked.replace(/\s+$/, ''), 'x = 1');
  assert.equal(masked.indexOf('py comment'), -1);
});

test('allMatches: returns indices and last capture group', () => {
  const re = /(\d+)/g;
  const hits = allMatches('a12b345', re);
  assert.equal(hits.length, 2);
  assert.equal(hits[0].match, '12');
  assert.equal(hits[0].index, 1);
  assert.equal(hits[1].match, '345');
});

test('allMatches: zero-length match advances to avoid infinite loop', () => {
  const re = /a*/g;
  const hits = allMatches('aabaa', re);
  assert.ok(Array.isArray(hits));
});

test('proximity: needle within window links to anchor', () => {
  const anchors = [{ index: 100 }];
  const needles = [{ index: 200 }, { index: 900 }];
  const hits = proximity(anchors, needles, 500);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].needle.index, 200);
});

test('proximity: needle outside window is not linked', () => {
  const anchors = [{ index: 100 }];
  const needles = [{ index: 900 }];
  assert.equal(proximity(anchors, needles, 500).length, 0);
});

test('base64Blobs: long printable base64 is decoded', () => {
  // 48+ char base64 of an ASCII string
  const payload = Buffer.from('x'.repeat(40) + ' visible text payload here').toString('base64');
  const blobs = base64Blobs(`prefix ${payload} suffix`);
  assert.ok(blobs.length >= 1);
  assert.ok(blobs[0].decoded.includes('visible text'));
});

test('base64Blobs: short base64 is ignored (below length threshold)', () => {
  const blobs = base64Blobs('abcd efgh');
  assert.equal(blobs.length, 0);
});

test('escapeXml: escapes the five XML special characters', () => {
  const e = escapeXml('<a "b" & \'c\' >');
  assert.equal(e, '&lt;a &quot;b&quot; &amp; &apos;c&apos; &gt;');
});

test('visibleUnicode: zero-width chars are rendered as escapes', () => {
  const out = visibleUnicode('a​b'); // contains U+200B between a and b
  assert.ok(out.includes('\\u200b'));
  assert.ok(out.startsWith('a'));
  assert.ok(out.endsWith('b'));
});
