import { lineColFromIndex, snippetAt } from '../util.js';

const SERVERS_KEYS = ['mcpServers', 'servers', 'mcp'];
const LAUNCHERS = new Set(['npx', 'pipx', 'uvx', 'npm']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'cmd', 'powershell', 'pwsh', '/bin/sh', '/bin/bash']);
const SHELL_FLAGS = new Set(['-c', '-command', '/c', '/C']);
const AUTO_APPROVE_KEYS = ['autoApprove', 'yolo', 'dangerouslySkipPermissions', 'skipPermissions', 'approveAll', 'trust'];
const SECRET_NAME_RE = /(API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)$/i;
const SECRET_VALUE_RE = /(^|[^A-Za-z0-9])(sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})/;
const PLACEHOLDER_RE = /^(?:\$\{?[A-Z0-9_]+\}?|<[^>]+>|your[-_].*|xxx+|changeme|placeholder|dummy|example|sk-\*+\*|\{\{.+%\}\}|%[A-Z_]+%)$/i;

function finding(ruleId, text, index, message) {
  const { line, column } = lineColFromIndex(text, index);
  return { ruleId, line, column, message, snippet: snippetAt(text, index) };
}

/** First index of `"key":` at or after `start`, else the key anywhere, else 0. */
function keyIndex(text, key, start = 0) {
  const from = text.indexOf(`"${key}"`, start);
  const any = from >= 0 ? from : text.indexOf(`"${key}"`);
  return any >= 0 ? any : 0;
}

function isPinnedNpxPackage(args) {
  // args like ["-y", "some-pkg"] with no "@version"
  const pkg = args.find((a) => typeof a === 'string' && /^[a-z@][a-z0-9@/_-]*$/i.test(a) && !a.startsWith('-'));
  if (!pkg) return { unpinned: false };
  const scoped = pkg.startsWith('@');
  const pinned = scoped ? /@[^@\/]+$/.test(pkg) : /@/.test(pkg) && !pkg.startsWith('@');
  const pinnedExact = /^\d+\.\d+\.\d+/.test(pkg.split('@').pop());
  const hasVersion = pinned && pinnedExact;
  const isLocal = pkg.startsWith('.') || pkg.startsWith('/');
  return { pkg, hasVersion, isLocal };
}

function scanServerEntry(ctx, name, entry, text) {
  const out = [];
  if (!entry || typeof entry !== 'object') return out;
  const cmd = typeof entry.command === 'string' ? entry.command : '';
  const args = Array.isArray(entry.args) ? entry.args.filter((a) => typeof a === 'string') : [];
  const entryStart = text.indexOf(`"${name}"`);
  const idxCommand = keyIndex(text, 'command', entryStart);

  // npx / pipx / uvx without exact pin
  const baseCmd = cmd.split(/[\\/]/).pop().toLowerCase();
  if (LAUNCHERS.has(baseCmd)) {
    const { pkg, hasVersion, isLocal } = isPinnedNpxPackage(args);
    if (pkg && !isLocal && !hasVersion) {
      out.push(finding('AS-M001', text, idxCommand,
        `Server "${name}" launches "${pkg}" via ${baseCmd} without an exact version pin — every start runs whatever the registry serves that day`));
    }
  }

  // shell -c inline payload
  if (SHELLS.has(baseCmd.split('/').pop())) {
    const inline = args.some((a, i) => SHELL_FLAGS.has(a.toLowerCase()) && args[i + 1]);
    if (inline) {
      out.push(finding('AS-M002', text, idxCommand,
        `Server "${name}" executes an inline shell payload (${cmd} ${args.find((a) => SHELL_FLAGS.has(a.toLowerCase()))} …) embedded in configuration`));
    }
  }
  for (const a of args) {
    if (/\|\s*(?:sudo\s+)?(?:ba)?sh\b/.test(a) || /\bcurl\b.*\|\s*(?:ba)?sh/.test(a)) {
      out.push(finding('AS-M002', text, idxCommand,
        `Server "${name}" argument contains remote-pipe execution: "${a.slice(0, 100)}"`));
      break;
    }
  }

  // insecure URL
  const url = typeof entry.url === 'string' ? entry.url : '';
  if (/^http:\/\//i.test(url)) {
    const idxUrl = keyIndex(text, 'url', entryStart);
    out.push(finding('AS-M003', text, idxUrl,
      `Server "${name}" uses a cleartext http endpoint: ${url}`));
  }

  // secrets in env / headers
  for (const [bag, label] of [[entry.env, 'env'], [entry.headers, 'headers'], [entry.authorization, 'authorization']]) {
    if (!bag) continue;
    const pairs = typeof bag === 'object' ? Object.entries(bag) : [[label, bag]];
    for (const [k, v] of pairs) {
      if (typeof v !== 'string') continue;
      const secretish = SECRET_NAME_RE.test(k) || SECRET_VALUE_RE.test(v);
      if (secretish && !PLACEHOLDER_RE.test(v.trim())) {
        const idx = keyIndex(text, k, entryStart);
        out.push(finding('AS-M004', text, idx >= 0 ? idx : 0,
          `Server "${name}" embeds what looks like a live credential in ${label}.${k}`));
      }
    }
  }

  // auto-approve
  for (const key of AUTO_APPROVE_KEYS) {
    const val = entry[key];
    const truthy = val === true || (Array.isArray(val) && val.length > 0) || (typeof val === 'string' && val.toLowerCase() === 'all');
    if (truthy) {
      const idx = keyIndex(text, key, entryStart);
      out.push(finding('AS-M005', text, idx,
        `Server "${name}" sets "${key}" — tool calls run without human approval`));
    }
  }

  return out;
}

export function analyzeMcpConfig(ctx) {
  const { text } = ctx;
  let data;
  try {
    data = JSON.parse(stripJsonc(text));
  } catch {
    return [];
  }
  const findings = [];
  const roots = [];
  if (data && typeof data === 'object') {
    for (const key of SERVERS_KEYS) {
      if (data[key] && typeof data[key] === 'object') roots.push([key, data[key]]);
    }
    // some clients nest: { mcp: { servers: {...} } }
    for (const [, v] of roots) {
      for (const key of SERVERS_KEYS) {
        if (v[key] && typeof v[key] === 'object') roots.push([`${key} (nested)`, v[key]]);
      }
    }
  }
  for (const [, map] of roots) {
    for (const [name, entry] of Object.entries(map)) {
      if (entry && typeof entry === 'object') findings.push(...scanServerEntry(ctx, name, entry, text));
    }
  }
  return findings;
}

function stripJsonc(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
