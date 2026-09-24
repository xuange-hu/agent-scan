import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { discover } from './discover.js';
import { analyzeMarkdown } from './analyzers/markdown.js';
import { analyzeMcpConfig } from './analyzers/mcpConfig.js';
import { analyzeSource } from './analyzers/source.js';
import { analyzeNpmPackage } from './analyzers/npmPackage.js';
import { RULES } from './rules.js';
import { SEVERITY_WEIGHT, TOOL_VERSION, severityAtLeast } from './util.js';

const ANALYZERS = {
  markdown: analyzeMarkdown,
  mcpConfig: analyzeMcpConfig,
  source: analyzeSource,
  npm: analyzeNpmPackage,
};

export function scan(rootPath, { includeAllMd = false, ignore = [] } = {}) {
  const root = resolve(rootPath);
  const allIgnores = [...ignore, ...loadIgnoreFile(root)];
  const files = discover(root, { includeAllMarkdown: includeAllMd, ignore: allIgnores });
  const findings = [];
  const scanned = [];
  const skipped = [];

  for (const file of files) {
    let text;
    try {
      text = readFileSync(file.abs, 'utf8');
    } catch (err) {
      skipped.push({ file: file.rel, reason: err.message });
      continue;
    }
    if (text.includes('\u0000')) {
      skipped.push({ file: file.rel, reason: 'binary' });
      continue;
    }
    scanned.push(file.rel);
    const ctx = { text, rel: file.rel, abs: file.abs, isPython: /\.py$/i.test(file.rel) };
    for (const kind of file.kinds) {
      const analyze = ANALYZERS[kind];
      let raw = [];
      try {
        raw = analyze(ctx) ?? [];
      } catch (err) {
        skipped.push({ file: file.rel, reason: `${kind} analyzer error: ${err.message}` });
        continue;
      }
      for (const f of raw) {
        const rule = RULES[f.ruleId];
        findings.push({
          ruleId: f.ruleId,
          severity: f.severity ?? rule?.severity ?? 'low',
          category: rule?.category ?? 'unknown',
          title: rule?.title ?? f.ruleId,
          message: f.message,
          file: file.rel,
          line: f.line ?? 1,
          column: f.column ?? 1,
          snippet: f.snippet ?? '',
        });
      }
    }
  }

  return finalize(findings, { root, scanned, skipped });
}

function loadIgnoreFile(root) {
  const p = join(root, '.agent-scanignore');
  if (!existsSync(p)) return [];
  return readFileSync(p, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

export function finalize(rawFindings, meta) {
  const seen = new Set();
  const findings = [];
  for (const f of rawFindings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line)) {
    const key = `${f.ruleId}:${f.file}:${f.line}:${f.column}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(f);
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let score = 0;
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    score += SEVERITY_WEIGHT[f.severity] ?? 1;
  }

  return {
    tool: 'agent-scan',
    version: TOOL_VERSION,
    root: meta.root,
    findings,
    counts,
    riskScore: Math.min(100, score),
    filesScanned: meta.scanned.length,
    scanned: meta.scanned,
    skipped: meta.skipped,
    rulesLoaded: Object.keys(RULES).length,
  };
}

export function worstSeverity(findings) {
  const order = ['info', 'low', 'medium', 'high', 'critical'];
  let worst = null;
  for (const f of findings) {
    if (!worst || order.indexOf(f.severity) > order.indexOf(worst)) worst = f.severity;
  }
  return worst;
}

export function shouldFail(result, failOn) {
  if (!failOn || failOn === 'none') return false;
  return result.findings.some((f) => severityAtLeast(f.severity, failOn));
}
