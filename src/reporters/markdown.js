import { RULES } from '../rules.js';

export function reportMarkdown(result) {
  const lines = [];
  lines.push(`# agent-scan report`);
  lines.push('');
  lines.push(`- **Target**: \`${result.root}\``);
  lines.push(`- **Files scanned**: ${result.filesScanned}`);
  lines.push(`- **Risk score**: ${result.riskScore}/100`);
  lines.push(`- **Findings**: ${result.counts.critical} critical · ${result.counts.high} high · ${result.counts.medium} medium · ${result.counts.low} low`);
  lines.push('');
  if (result.findings.length === 0) {
    lines.push('No findings.');
    return lines.join('\n');
  }
  lines.push('| Severity | Rule | File | Line | Detail |');
  lines.push('|---|---|---|---|---|');
  for (const f of result.findings) {
    const title = RULES[f.ruleId]?.title ?? '';
    const detail = f.message.replace(/\s+/g, ' ').replaceAll('|', '\\|');
    lines.push(`| ${f.severity} | [${f.ruleId}](docs/rules.md#${f.ruleId.toLowerCase()}) · ${title} | \`${f.file}\` | ${f.line} | ${detail} |`);
  }
  return lines.join('\n');
}
