import { readdirSync, statSync } from 'node:fs';
import { join, posix } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'target', 'vendor', '.venv', 'venv', '__pycache__', '.next', '.cache', 'coverage']);
const MAX_FILE_BYTES = 1024 * 1024; // 1 MiB per file

const MARKDOWN_RES = [
  /(^|\/)SKILL\.md$/i,
  /(^|\/)AGENTS\.md$/i,
  /(^|\/)CLAUDE\.md$/i,
  /(^|\/)GEMINI\.md$/i,
  /\.mdc$/i,
  /(^|\/)\.cursorrules$/i,
  /(^|\/)\.rules$/i,
  /(^|\/)prompts?\//i,
  /\.prompt\.md$/i,
  /\.md$/i,
];
const MCP_CONFIG_RES = [/(^|\/)\.mcp\.json$/i, /mcp[\w.-]*\.json$/i, /(^|\/)claude_desktop_config\.json$/i];
const SOURCE_RES = [/\.(?:js|mjs|cjs|ts|tsx|py|sh|rb|go)$/i];

/** Classify a relative path into zero or more analyzer kinds. */
export function classify(relPath) {
  const p = relPath.split('\\').join('/');
  const kinds = [];
  const base = p.split('/').pop();
  if (base === 'package.json') kinds.push('npm');
  if (MCP_CONFIG_RES.some((re) => re.test(p)) && base !== 'package.json') kinds.push('mcpConfig');
  if (MARKDOWN_RES.some((re) => re.test(p))) kinds.push('markdown');
  if (SOURCE_RES.some((re) => re.test(p))) kinds.push('source');
  return kinds;
}

export function discover(rootDir, { includeAllMarkdown = false, ignore = [] } = {}) {
  const files = [];
  const ignoreRes = ignore.map((g) => globToRe(g));

  const walk = (dir, rel) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      const childRel = rel ? `${rel}/${ent.name}` : ent.name;
      if (ignoreRes.some((re) => re.test(childRel))) continue;
      const childAbs = join(dir, ent.name);
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        walk(childAbs, childRel);
      } else if (ent.isFile()) {
        let kind;
        try {
          kind = statSync(childAbs);
        } catch {
          continue;
        }
        if (kind.size > MAX_FILE_BYTES || kind.size === 0) continue;
        const kinds = classify(childRel);
        if (kinds.length === 0) continue;
        if (kinds.includes('markdown') && !includeAllMarkdown && /\.md$/i.test(childRel) && !isPriorityDoc(childRel)) {
          const rest = kinds.filter((k) => k !== 'markdown');
          if (rest.length === 0) continue;
          files.push({ abs: childAbs, rel: childRel, kinds: rest });
          continue;
        }
        files.push({ abs: childAbs, rel: childRel, kinds });
      }
    }
  };

  const rootStat = statSync(rootDir);
  if (rootStat.isFile()) {
    const kinds = classify(rootDir);
    return [{ abs: rootDir, rel: rootDir.split(/[\\/]/).pop(), kinds: kinds.length ? kinds : ['markdown', 'source'] }];
  }
  walk(rootDir, '');
  return files;
}

function isPriorityDoc(rel) {
  return /(^|\/)(SKILL|AGENTS|CLAUDE|GEMINI)\.md$/i.test(rel)
    || /\.prompt\.md$/i.test(rel)
    || /(^|\/)prompts?\//i.test(rel)
    || /\.mdc$/i.test(rel)
    || /(^|\/)\.cursorrules$/i.test(rel);
}

function globToRe(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`);
}
