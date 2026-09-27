import { captureMcpMetadata } from './mcpClient.js';
import { analyzeProbe } from '../analyzers/toolPoisoning.js';
import { defaultStoreDir, loadPrevious, saveCapture, diffCaptures } from './store.js';
import { finalize } from '../engine.js';
import { RULES } from '../rules.js';

/**
 * Dynamic tool-poisoning probe: launch an MCP server locally, capture its
 * advertised metadata, and run the AS-T rules over every text field.
 * With `save`, also keep the capture in the probe store (default
 * ~/.agent-scan/probes) and report AS-T008 drift vs. the previous saved
 * capture for the same launch command.
 * Resolves to a scan-shaped result (findings/counts/riskScore) plus `capture`.
 */
export async function probeScan(command, args = [], { timeoutMs = 15000, save = false, storeDir } = {}) {
  const capture = await captureMcpMetadata(command, args, { timeoutMs });

  let drift = null;
  if (save) {
    const dir = storeDir ?? defaultStoreDir();
    const prev = loadPrevious(dir, command, args);
    if (prev) {
      const changes = diffCaptures(prev, capture);
      drift = { from: prev.capturedAt ?? '?', changes };
    }
    saveCapture(dir, command, args, {
      capturedAt: new Date().toISOString(),
      serverInfo: capture.serverInfo,
      tools: capture.tools,
      prompts: capture.prompts,
      resources: capture.resources,
    });
  }

  const server = capture.serverInfo?.name || 'server';
  const raw = [...analyzeProbe(capture), ...driftFindings(server, drift)].map((f) => {
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
  return { ...result, mode: 'probe', serverInfo: capture.serverInfo, capture, drift };
}

function driftFindings(server, drift) {
  if (!drift) return [];
  return drift.changes.map((c) => ({
    ruleId: 'AS-T008',
    file: `mcp://${server}/tool/${c.name}#drift`,
    line: 1,
    column: 1,
    message: `Tool "${c.name}" ${c.kind === 'added' ? 'was added' : c.kind === 'removed' ? 'was removed' : 'changed'} since the ${drift.from} probe — ${c.detail}`,
    snippet: '',
  }));
}
