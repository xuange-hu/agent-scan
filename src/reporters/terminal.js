const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m', gray: '\x1b[90m',
};
const SEV_COLOR = { critical: C.red, high: C.yellow, medium: C.magenta, low: C.cyan, info: C.gray };
const useColor = (noColor) => !noColor && process.stdout.isTTY;

export function reportTerminal(result, { noColor = false } = {}) {
  const col = useColor(noColor);
  const paint = (s, c) => (col ? `${c}${s}${C.reset}` : s);
  const lines = [];

  lines.push('');
  lines.push(paint(`agent-scan — AI agent supply-chain & prompt-injection security scan`, C.bold));
  lines.push(paint(`  scanning ${result.root}  ·  ${result.filesScanned} files  ·  ${result.rulesLoaded} rules`, C.dim));
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(paint('  ✔ No findings. This repo looks clean for the patterns agent-scan knows.', C.green));
    lines.push(paint('    (Absence of detections ≠ absence of attack — review anything it flags elsewhere.)', C.dim));
  } else {
    let currentFile = null;
    for (const f of result.findings) {
      if (f.file !== currentFile) {
        currentFile = f.file;
        lines.push(paint(`  ${currentFile}`, C.bold + C.blue));
      }
      const sev = f.severity.toUpperCase().padEnd(8);
      lines.push(`    ${paint(sev, SEV_COLOR[f.severity] ?? C.gray)} ${paint(`${f.ruleId}`, C.dim)}  ${f.message.replace(/\s+/g, ' ')}`);
      lines.push(`    ${' '.repeat(8)} ${paint(`${f.line}:${f.column}  ${f.snippet.trim().slice(0, 140)}`, C.dim)}`);
    }
  }

  const score = result.riskScore;
  const verdict = score >= 60 ? paint('HIGH RISK', C.red) : score >= 25 ? paint('ELEVATED RISK', C.yellow) : paint('LOW RISK', C.green);
  lines.push('');
  lines.push(`  ${paint('Risk score', C.bold)}: ${score}/100 → ${verdict}`);
  const parts = ['critical', 'high', 'medium', 'low']
    .filter((s) => result.counts[s])
    .map((s) => paint(`${result.counts[s]} ${s}`, SEV_COLOR[s]));
  lines.push(`  ${parts.length ? parts.join(paint(' · ', C.dim)) : '0 findings'}`);
  if (result.skipped.length) {
    lines.push(paint(`  ${result.skipped.length} file(s) skipped (binary/oversized/analyzer error)`, C.dim));
  }
  lines.push('');
  return lines.join('\n');
}
