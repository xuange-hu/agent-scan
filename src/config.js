import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Optional project config: `.agent-scan.yml` / `.agent-scan.yaml` / `.agent-scan.json`
// at the scan root. Carries defaults for ignore globs, the CI fail threshold,
// the default output format and whether to scan every *.md. Flags on the command
// line always win over the file. The parser is intentionally tiny (no dependency):
// it supports top-level scalars and one level of `- item` lists, which is all the
// documented schema needs.

const CONFIG_NAMES = ['.agent-scan.yml', '.agent-scan.yaml', '.agent-scan.json'];

const VALID_FORMATS = new Set(['terminal', 'json', 'sarif', 'md']);

export function defaultConfig() {
  return { source: null, ignore: [], failOn: 'critical', format: 'terminal', includeAllMd: false };
}

export function loadConfig(rootPath) {
  const root = resolve(rootPath);
  for (const name of CONFIG_NAMES) {
    const p = join(root, name);
    if (!existsSync(p)) continue;
    try {
      const parsed = parseConfig(readFileSync(p, 'utf8'), name);
      return { ...defaultConfig(), source: p, ...normalize(parsed) };
    } catch (err) {
      return { ...defaultConfig(), source: p, error: err.message };
    }
  }
  return defaultConfig();
}

export function parseConfig(text, name = '.agent-scan.yml') {
  if (name.endsWith('.json')) return JSON.parse(text);
  return parseSimpleYaml(text);
}

/** Coerce a YAML scalar / list item to boolean | number | string. */
function coerce(v) {
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (v !== '' && !/[^0-9.\-]/.test(v) && !Number.isNaN(Number(v))) return Number(v);
  return v.replace(/^["']|["']$/g, '');
}

/**
 * Minimal YAML: top-level `key: scalar` and `key:` followed by `- item` block
 * lists. Comments (`#`) and blank lines are skipped. Good enough for the
 * documented schema and keeps the package dependency-free.
 */
export function parseSimpleYaml(text) {
  const root = {};
  let listKey = null;
  let listArr = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '');
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (/^-\s+/.test(trimmed) && listKey !== null) {
      listArr.push(coerce(trimmed.slice(1).trim()));
      continue;
    }
    const m = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    const val = m[2].trim();
    if (val === '') {
      listKey = key;
      listArr = [];
      root[key] = listArr;
    } else {
      root[key] = coerce(val);
      listKey = null;
      listArr = null;
    }
  }
  return root;
}

function normalize(c) {
  if (!c || typeof c !== 'object') return {};
  const ignore = Array.isArray(c.ignore) ? c.ignore.map(String).filter(Boolean) : [];
  const failOn = c['fail-on'] ?? c.failOn ?? c['severity-threshold'] ?? 'critical';
  const format = VALID_FORMATS.has(c.format) ? c.format : 'terminal';
  const includeAllMd = !!(c['include-all-md'] ?? c.includeAllMd);
  return { ignore, failOn, format, includeAllMd };
}
