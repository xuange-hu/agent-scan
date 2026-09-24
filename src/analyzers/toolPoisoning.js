import { allMatches, lineColFromIndex, snippetAt, visibleUnicode } from '../util.js';
import { PATTERNS } from './markdown.js';

// Tool poisoning: the attack carrier is the MCP server's own metadata
// (tool name/description/inputSchema), which is injected into the agent's
// context at discovery time. Same injection signatures as AS-P rules,
// different carrier — and one the static file scan can never see, because
// many poisoned descriptions are served dynamically.

const FIELD_LABELS = { name: 'tool name', title: 'tool title', description: 'description' };

// Agent-directed imperatives and server-supplied values inside schemas (AS-T007)
const SCHEMA_DIRECTIVE_RE = /\b(?:you\s+must|always\s+(?:call|run|execute|use|pass)|must\s+(?:be\s+)?(?:called|run|executed)|do\s+not\s+(?:change|modify|mention|tell|reveal))\b|(?:必须|务必|不要更改|不要告诉)/gi;
const SCHEMA_VALUE_RE = /https?:\/\/|(?:(?:curl|wget)\b[^\n|]{0,60}\|\s*(?:sudo\s+)?(?:ba)?sh)|[A-Za-z0-9+/]{40,}={0,2}|\$\{|\beval\b|ignore\s+previous/gi;

function joinAlt(regexes) {
  return new RegExp(regexes.map((r) => r.source).join('|'), 'gi');
}

function pushAt(findings, ruleId, file, text, index, message) {
  const { line, column } = lineColFromIndex(text, index);
  findings.push({
    ruleId,
    file,
    line,
    column,
    message,
    snippet: snippetAt(text, index),
  });
}

/** Run every injection signature over one free-text metadata field. */
function checkField(findings, file, label, text) {
  if (!text) return;

  for (const hit of allMatches(text, PATTERNS.hiddenUnicode)) {
    const cp = hit.full.codePointAt(0).toString(16).padStart(4, '0');
    pushAt(findings, 'AS-T001', file, text, hit.index,
      `${label} contains invisible character U+${cp} (${visibleUnicode(hit.full)})`);
  }

  for (const [res, rule, why] of [
    [PATTERNS.override, 'AS-T002', 'instruction-override phrasing'],
    [PATTERNS.conceal, 'AS-T003', 'concealment directive toward the user'],
    [PATTERNS.sysprompt, 'AS-T004', 'system-prompt exfiltration request'],
    [PATTERNS.jailbreak, 'AS-T004', 'jailbreak framing'],
    [PATTERNS.dangerousCmd, 'AS-T006', 'dangerous shell bootstrap'],
  ]) {
    for (const r of res) {
      for (const hit of allMatches(text, r)) {
        pushAt(findings, rule, file, text, hit.index,
          `${label} contains ${why}: "${hit.full.trim().slice(0, 90)}"`);
      }
    }
  }

  // exfiltration sentence: secret + network destination + transmission intent, same sentence
  for (const lm of text.matchAll(/[^\n]+/g)) {
    let offset = 0;
    for (const sentence of lm[0].split(/(?<=[.!?。！？])(?=\s|$)/)) {
      const at = lm.index + offset;
      offset += sentence.length + 1;
      const secret = sentence.match(joinAlt(PATTERNS.secret));
      if (!secret) continue;
      const net = sentence.match(joinAlt(PATTERNS.network));
      if (!net) continue;
      const intent = sentence.match(PATTERNS.intent);
      if (!intent) continue;
      pushAt(findings, 'AS-T005', file, text, at + sentence.indexOf(secret[0]),
        `${label} pairs credential "${secret[0].trim()}" with network destination "${net[0].trim().slice(0, 60)}" and transmission intent "${intent[0]}" in one sentence`);
    }
  }
}

/** Walk an inputSchema collecting per-parameter findings (AS-T007). */
function checkSchema(findings, file, schema, path = 'args') {
  if (!schema || typeof schema !== 'object') return;

  if (typeof schema.description === 'string') {
    const dir = schema.description.match(SCHEMA_DIRECTIVE_RE);
    if (dir) {
      pushAt(findings, 'AS-T007', file, schema.description, schema.description.indexOf(dir[0]),
        `Parameter "${path}" description directs the agent: "${dir[0]}" — schema docs should describe data, not issue instructions`);
    }
    checkField(findings, file, `parameter "${path}" description`, schema.description);
  }

  for (const key of ['default', 'const']) {
    const v = schema[key];
    if (typeof v === 'string') {
      const bad = v.match(SCHEMA_VALUE_RE);
      if (bad) {
        pushAt(findings, 'AS-T007', file, v, v.indexOf(bad[0]),
          `Parameter "${path}" has a server-supplied ${key} containing "${bad[0].slice(0, 60)}" — agents tend to send it off untouched`);
      }
    }
  }

  if (Array.isArray(schema.enum)) {
    for (const [i, v] of schema.enum.entries()) {
      if (typeof v === 'string') checkField(findings, file, `enum value ${i} of "${path}"`, v);
    }
  }

  if (schema.properties && typeof schema.properties === 'object') {
    for (const [name, sub] of Object.entries(schema.properties)) {
      checkSchema(findings, file, sub, `${path}.${name}`);
    }
  }
  checkSchema(findings, file, schema.items, `${path}[]`);
  if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
    checkSchema(findings, file, schema.additionalProperties, `${path}.{extra}`);
  }
}

/**
 * Analyze a live metadata capture:
 * { serverInfo, tools: [{name,title,description,inputSchema}], prompts, resources }
 * Returns engine-shaped findings (file = mcp://<server>/…).
 */
export function analyzeProbe(capture) {
  const findings = [];
  const server = capture.serverInfo?.name || 'server';
  const ref = (kind, name, field) => `mcp://${server}/${kind}/${name}${field ? '#' + field : ''}`;

  for (const tool of capture.tools ?? []) {
    const descFile = ref('tool', tool.name, 'description');
    checkField(findings, descFile, `Tool "${tool.name}" ${FIELD_LABELS.description}`, tool.description);
    // name and title carry the same attack surface (hidden unicode / overrides)
    checkField(findings, ref('tool', tool.name, 'name'), `Tool name "${tool.name}"`, tool.name);
    checkField(findings, ref('tool', tool.name, 'title'), `Title of tool "${tool.name}"`, tool.title);
    checkSchema(findings, ref('tool', tool.name, 'schema'), tool.inputSchema);
  }

  for (const p of capture.prompts ?? []) {
    checkField(findings, ref('prompt', p.name, 'description'), `Prompt "${p.name}" description`, p.description);
  }
  for (const r of capture.resources ?? []) {
    checkField(findings, ref('resource', r.name ?? r.uri, 'description'), `Resource "${r.name ?? r.uri}" description`, r.description);
    if (typeof r.text === 'string') {
      checkField(findings, ref('resource', r.name ?? r.uri, 'text'), `Resource "${r.name ?? r.uri}" content`, r.text);
    }
  }

  return findings.map((f) => ({ ...f, source: 'probe' }));
}
