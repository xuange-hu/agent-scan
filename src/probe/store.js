import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

// Persistent probe store: each distinct launch command keeps its last 10
// captures so repeated probes can be diffed (rug-pull detection, AS-T008).

const KEEP = 10;

export function defaultStoreDir() {
  return join(homedir(), '.agent-scan', 'probes');
}

export function captureKey(command, args) {
  return createHash('sha1').update(JSON.stringify([command, ...args])).digest('hex').slice(0, 16);
}

function storePath(dir, key) {
  return join(dir, `${key}.json`);
}

function readHistory(dir, key) {
  try {
    const data = JSON.parse(readFileSync(storePath(dir, key), 'utf8'));
    return Array.isArray(data.captures) ? data : null;
  } catch {
    return null;
  }
}

/** Most recent saved capture for this command, or null. */
export function loadPrevious(dir, command, args) {
  const history = readHistory(dir, captureKey(command, args));
  return history?.captures?.[0] ?? null;
}

/** Append a capture (keeps the newest KEEP). */
export function saveCapture(dir, command, args, capture) {
  const key = captureKey(command, args);
  const history = readHistory(dir, key) ?? { command, args, captures: [] };
  history.captures.unshift(capture);
  history.captures = history.captures.slice(0, KEEP);
  mkdirSync(dir, { recursive: true });
  writeFileSync(storePath(dir, key), JSON.stringify(history, null, 2));
  return key;
}

function fingerprint(tool) {
  return createHash('sha1')
    .update(JSON.stringify({ t: tool.title ?? null, d: tool.description ?? null, s: tool.inputSchema ?? null }))
    .digest('hex').slice(0, 10);
}

function fieldChanges(prev, next) {
  const changed = [];
  if ((prev.title ?? null) !== (next.title ?? null)) changed.push('title');
  if ((prev.description ?? null) !== (next.description ?? null)) changed.push('description');
  if (JSON.stringify(prev.inputSchema ?? null) !== JSON.stringify(next.inputSchema ?? null)) changed.push('inputSchema');
  return changed;
}

/**
 * Compare two captures. Returns [{ kind, name, detail, prevFp, nextFp }]
 * for tools added/removed or whose advertised surface changed.
 */
export function diffCaptures(prev, next) {
  const changes = [];
  const prevTools = new Map((prev.tools ?? []).map((t) => [t.name, t]));
  const nextTools = new Map((next.tools ?? []).map((t) => [t.name, t]));

  for (const [name, t] of nextTools) {
    if (!prevTools.has(name)) {
      changes.push({ kind: 'added', name, detail: 'new tool appeared in tools/list', nextFp: fingerprint(t) });
    }
  }
  for (const [name, t] of prevTools) {
    if (!nextTools.has(name)) {
      changes.push({ kind: 'removed', name, detail: 'tool no longer advertised', prevFp: fingerprint(t) });
    }
  }
  for (const [name, nt] of nextTools) {
    const pt = prevTools.get(name);
    if (!pt) continue;
    const fields = fieldChanges(pt, nt);
    if (fields.length) {
      changes.push({
        kind: 'changed',
        name,
        detail: `${fields.join(', ')} ${fingerprint(pt)} → ${fingerprint(nt)}: ${fields.map((f) => f === 'inputSchema' ? 'schema' : `${f} now "${String(nt[f] ?? '').slice(0, 70)}"`).join('; ')}`,
        prevFp: fingerprint(pt),
        nextFp: fingerprint(nt),
      });
    }
  }
  return changes;
}
