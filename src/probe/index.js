import { captureMcpMetadata } from './mcpClient.js';
import { analyzeProbe } from '../analyzers/toolPoisoning.js';
import { finalize } from '../engine.js';
import { RULES } from '../rules.js';

/**
 * Dynamic tool-poisoning probe: launch an MCP server locally, capture its
 * advertised metadata, and run the AS-T rules over every text field.
 * Resolves to a scan-shaped result (findings/counts/riskScore) plus `capture`.
 */
export async function probeScan(command, args = [], { timeoutMs = 15000 } = {}) {
  const capture = await captureMcpMetadata(command, args, { timeoutMs });
  const raw = analyzeProbe(capture).map((f) => {
    const rule = RULES[f.ruleId];
    return {
      ruleId: f.ruleId,
      severity: f.severity ?? rule?.severity ?? 'low',
      category: rule?.category ?? 'unknown',
      title: rule?.title ?? f.ruleId,
      message: f.message,
      file: f.file,
      line: f.line ?? 1,
      column: f.column ?? 1,
      snippet: f.snippet ?? '',
    };
  });

  const scanned = [
    ...capture.tools.map((t) => `tool:${t.name}`),
    ...capture.prompts.map((p) => `prompt:${p.name}`),
    ...capture.resources.map((r) => `resource:${r.name ?? r.uri}`),
  ];
  const result = finalize(raw, { root: `mcp://${capture.serverInfo?.name ?? command}`, scanned, skipped: [] });
  return { ...result, mode: 'probe', serverInfo: capture.serverInfo, capture };
}
