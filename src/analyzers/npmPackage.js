import { lineColFromIndex, snippetAt } from '../util.js';

const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall', 'prepare'];
const REMOTE_EXEC_RES = /\b(?:curl|wget)\b[^"&|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b|\bnpm\s+(?:i|install|add)\s+\S*(?:https?:\/\/|git[+@]?:\/\/|github:)/i;
const MUTABLE_RANGE_RES = /^(?:\*|latest|x|\d+\.x|\d+\.\d+\.x)$/i;

function at(text, key, message, ruleId) {
  const idx = text.indexOf(`"${key}"`);
  const pos = lineColFromIndex(text, idx >= 0 ? idx : 0);
  return { ruleId, ...pos, message, snippet: snippetAt(text, idx >= 0 ? idx : 0) };
}

export function analyzeNpmPackage(ctx) {
  const { text } = ctx;
  let data;
  try {
    data = JSON.parse(text.replace(/^\uFEFF/, ''));
  } catch {
    return [];
  }
  const findings = [];

  const scripts = data.scripts && typeof data.scripts === 'object' ? data.scripts : {};
  for (const [name, cmd] of Object.entries(scripts)) {
    if (typeof cmd !== 'string') continue;
    if (LIFECYCLE_HOOKS.includes(name)) {
      findings.push(at(text, name, `Lifecycle hook "${name}" executes code at install time: ${cmd.slice(0, 100)}`, 'AS-N001'));
    }
    if (REMOTE_EXEC_RES.test(cmd)) {
      findings.push(at(text, name, `Script "${name}" downloads and executes remote code: ${cmd.slice(0, 100)}`, 'AS-N004'));
    }
  }

  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    const deps = data[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [dep, range] of Object.entries(deps)) {
      if (typeof range !== 'string') continue;
      if (/^(?:git\+|github:|git:|https?:|file:|workspace:)/i.test(range) || /#(?:main|master|develop|HEAD)$/.test(range)) {
        findings.push(at(text, dep, `Dependency "${dep}" resolves from a mutable non-registry source: ${range}`, 'AS-N002'));
      } else if (MUTABLE_RANGE_RES.test(range.trim())) {
        findings.push(at(text, dep, `Dependency "${dep}" uses open range "${range}" — any registry publish lands automatically`, 'AS-N003'));
      }
    }
  }

  return findings;
}
