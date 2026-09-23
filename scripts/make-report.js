#!/usr/bin/env node
/**
 * Render .scan-cache/results.json into a markdown report skeleton.
 * The skeleton is deliberately data-only: narrative + manual verification
 * of headline findings happens before publishing (see SECURITY.md ethics note).
 *
 * Usage: node scripts/make-report.js > .scan-cache/report-draft.md
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RULES } from '../src/rules.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const data = JSON.parse(readFileSync(join(ROOT, '.scan-cache', 'results.json'), 'utf8'));

const ok = data.results.filter((r) => !r.error);
const pct = (n) => `${Math.round((n / ok.length) * 100)}%`;

const sevOf = (r) => (r.counts?.critical ? 'critical' : r.counts?.high ? 'high' : r.counts?.medium ? 'medium' : r.counts?.low ? 'low' : 'none');
const byRisk = [...ok].filter((r) => r.findings.length > 0).sort((a, b) => b.riskScore - a.riskScore || b.downloads - a.downloads);
const withCritical = ok.filter((r) => r.counts.critical > 0);
const withHigh = ok.filter((r) => r.counts.high > 0 && !r.counts.critical);

const lines = [];
lines.push(`# State of MCP Security — ${new Date(data.generatedAt).toISOString().slice(0, 10)}`);
lines.push('');
lines.push(`*Method: downloaded the top ${ok.length} MCP-related npm packages by last-week downloads and scanned each with [agent-scan](../README.md) v0.1.0 (23 static rules). Pattern-based signals for human review — not confirmed vulnerabilities; every headline finding below was manually verified before publishing.*`);
lines.push('');
lines.push('## Headline numbers');
lines.push('');
lines.push(`| Metric | Value |`);
lines.push(`|---|---|`);
lines.push(`| Packages scanned | ${ok.length} |`);
lines.push(`| ≥1 signal | ${data.withFindings} (${pct(data.withFindings)}) |`);
lines.push(`| ≥1 CRITICAL signal | ${withCritical.length} (${pct(withCritical.length)}) |`);
lines.push(`| ≥1 HIGH signal (no critical) | ${withHigh.length} (${pct(withHigh.length)}) |`);
lines.push(`| Total signals | ${ok.reduce((s, r) => s + r.findings.length, 0)} |`);
lines.push('');
lines.push('## Signals by rule group');
lines.push('');
lines.push('| Group | Meaning | Signals |');
lines.push('|---|---|---|');
const groupDesc = { P: 'prompt injection / hidden instructions', M: 'MCP config dangers', S: 'tool-code vulnerabilities', N: 'npm supply chain' };
for (const [g, n] of Object.entries(data.groupCounts)) {
  lines.push(`| AS-${g}xxx | ${groupDesc[g]} | ${n} |`);
}
lines.push('');
lines.push('## Rule histogram');
lines.push('');
lines.push('| Rule | Title | Severity | Hits |');
lines.push('|---|---|---|---|');
for (const [ruleId, hits] of Object.entries(data.ruleCounts).sort((a, b) => b[1] - a[1])) {
  const r = RULES[ruleId] ?? {};
  lines.push(`| [${ruleId}](docs/rules.md#${ruleId.toLowerCase()}) | ${r.title ?? ''} | ${r.severity ?? ''} | ${hits} |`);
}
lines.push('');
lines.push('## Highest-signal packages (verify before publishing any claim)');
lines.push('');
lines.push('| Package | Weekly DLs | Risk | C | H | M | L | Top signal |');
lines.push('|---|---|---|---|---|---|---|---|');
for (const r of byRisk.slice(0, 30)) {
  const top = [...r.findings].sort((a, b) => sevRank(b.severity) - sevRank(a.severity))[0];
  lines.push(`| \`${r.name}@${r.version}\` | ${r.downloads.toLocaleString()} | ${r.riskScore} | ${r.counts.critical} | ${r.counts.high} | ${r.counts.medium} | ${r.counts.low} | ${top.ruleId} ${top.file}:${top.line} |`);
}
lines.push('');
lines.push('## Verification checklist (before publishing)');
lines.push('');
lines.push('- [ ] Manually read every CRITICAL finding listed above; classify true-positive vs false-positive');
lines.push('- [ ] Re-word report claims to match verified findings only');
lines.push('- [ ] Responsible disclosure: open private advisories/issues for confirmed problems ≥14 days before publishing');
lines.push('- [ ] Publish methodology so anyone can rerun: `node scripts/scan-top100.js && node scripts/make-report.js`');

function sevRank(s) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0;
}

console.log(lines.join('\n'));
