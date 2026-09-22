import { RULES } from '../rules.js';

export function reportJson(result) {
  return JSON.stringify(
    {
      tool: result.tool,
      version: result.version,
      root: result.root,
      riskScore: result.riskScore,
      counts: result.counts,
      filesScanned: result.filesScanned,
      findings: result.findings,
      skipped: result.skipped,
    },
    null,
    2
  );
}

export function reportSarif(result) {
  const usedRules = [...new Set(result.findings.map((f) => f.ruleId))];
  const ruleIndex = new Map(usedRules.map((id, i) => [id, i]));
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'agent-scan',
              version: result.version,
              informationUri: 'https://github.com/agent-scan/agent-scan',
              rules: usedRules.map((id) => {
                const r = RULES[id] ?? { title: id, severity: 'low', description: id, references: [] };
                return {
                  id,
                  name: r.title,
                  shortDescription: { text: r.title },
                  fullDescription: { text: r.description ?? r.title },
                  help: { text: r.remediation ?? '' },
                  defaultConfiguration: { level: sarifLevel(r.severity ?? 'low') },
                  properties: { tags: ['ai-agent-security', r.category, ...(r.references ?? [])] },
                };
              }),
            },
          },
          results: result.findings.map((f) => ({
            ruleId: f.ruleId,
            ruleIndex: ruleIndex.get(f.ruleId),
            level: sarifLevel(f.severity),
            message: { text: f.message },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file.replaceAll('\\', '/'), uriBaseId: '%SRCROOT%' },
                  region: { startLine: f.line, startColumn: f.column, snippet: { text: f.snippet } },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2
  );
}

function sarifLevel(severity) {
  return { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }[severity] ?? 'note';
}
