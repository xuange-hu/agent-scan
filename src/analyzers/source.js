import { allMatches, base64Blobs, lineColFromIndex, maskComments, proximity, snippetAt } from '../util.js';

// exec("...${var}...") / exec('a' + b) / os.system(f"...{x}") / f-string into subprocess
// (?<![\w.$]) keeps regex.exec(), obj.eval-style method calls from matching
const COMMAND_INJECTION_RES = [
  // JS template literal or concatenation inside shell-capable calls
  new RegExp(`(?<![\\w.$])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\\s*\\(\\s*(?:[A-Za-z_$][\\w$]*\\s*\\+|["'\`][^"'\\n]*\\$\\{)`, 'g'),
  new RegExp(`(?<![\\w.$])(?:exec|execSync|spawn)\\s*\\(\\s*[A-Za-z_$][\\w$.]*\\s*\\)`, 'g'), // exec(variable)
  // Python f-string / format / + into os.system & subprocess with shell=True
  new RegExp(`(?<![\\w.$])os\\.(?:system|popen)\\s*\\(\\s*(?:f["']|["'][^"']*%|.*\\+)`, 'g'),
  new RegExp(`(?<![\\w.$])subprocess\\.(?:run|call|Popen|check_output|check_call)\\s*\\([^)]{0,120}shell\\s*=\\s*True`, 'g'),
  new RegExp(`(?<![\\w.$])subprocess\\.(?:run|call|Popen|check_output)\\s*\\(\\s*f["']`, 'g'),
];

const EVAL_RES = [
  // eval(<anything that is not a single simple string literal>)
  /(?<![\w.$])eval\s*\((?!\s*(?:["'][^"'\\\n]*["']\s*\)))/g,
  /(?<![\w.$])new\s+Function\s*\(/g,
  /(?<![\w.$])exec\s*\(\s*(?:compile|code|source|payload|__import__)/g,
  /(?<![\w.$])os\.system\s*\(\s*["']?(?:bash|sh)\s+-c/gi,
];

const OBfuscATION_RES = [
  /\batob\s*\(\s*["'][A-Za-z0-9+/=]{24,}/g,
  /\bBuffer\.from\s*\(\s*["'][A-Za-z0-9+/=]{24,}\s*["']\s*,\s*["']base64/g,
  /\beval\s*\(\s*(?:atob|Buffer\.from|unhexify|codecs\.)/g,
  /(?:\\x[0-9a-f]{2}){10,}/g,
  /\bString\.fromCharCode\s*\((?:\d+\s*,\s*){10,}/g,
  /\bbase64\.b64decode\s*\(\s*["'][A-Za-z0-9+/=]{24,}/g,
  /\b__import__\s*\(\s*chr\s*\(/g,
];

const SECRET_SOURCE_RES = [
  /\b(?:process\.env|os\.environ|os\.getenv)\s*(?:\[[^\]]+\]|\(\s*["'][^"']*["']\s*\)|\b(?!\())/g,
  /["']~?\/?\.ssh\/[^"']+["']/g,
  /\breadFileSync?\s*\([^)]*(?:id_rsa|\.env|credentials|\.netrc|\.npmrc|keychain)/gi,
  /\bopen\s*\([^)]*(?:id_rsa|\.env|credentials|\.netrc)/gi,
  /["'][^"']*(?:AWS_SECRET|API_TOKEN|PRIVATE_KEY|DATABASE_URL)[^"']*["']/g,
];

const NETWORK_SOURCE_RES = [
  /\bfetch\s*\(/g,
  /\baxios\.(?:get|post|put|delete|request)\s*\(/g,
  /\brequests\.(?:get|post|put|request)\s*\(/g,
  /\burllib\.request\b/g,
  /\bhttp\.(?:get|request|post|https)\s*\(/g,
  /\bcurl\b/g,
  /\bnet\.HTTP\b/g,
  /\bWebSocket\b/g,
];

const PATH_TRAVERSAL_RES = [
  // fs read/write joining a parameter without a normalize/startsWith guard nearby
  /\bfs\.(?:readFileSync|writeFileSync|createReadStream|promises\.readFile)\s*\(\s*(?:path\.join\s*\(|[^)]*\b(?:req|request|params|args|input|user|event)\b[^)]*\+)/g,
  /\bopen\s*\([^)]*(?:\+|%|\.format\(|f["'])[^)]*(?:req|params|args|input|user|filename|file_path|path)/g,
  /\bpath\.(?:join|resolve)\s*\([^)]*(?:req\.|params\[|args\[|user_input|userInput)/g,
];

const SSRF_RES = [
  /\bfetch\s*\(\s*(?:req|request|params|args|input|user|event|payload|data)[\w$]*/gi,
  /\baxios\.get\s*\(\s*(?:req|request|params|args|url|target)[\w$]*/gi,
  /\brequests\.(?:get|post)\s*\(\s*(?:url|target|endpoint|req|args)[\w$]*/gi,
  /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google)/g,
];

// AS-S007 — hardcoded exfiltration / callback sinks in tool source
const EXFIL_ENDPOINT_RES = [
  /\bhttps?:\/\/(?:webhook\.site|requestbin\.(?:com|net)|hookbin\.com|pipedream\.net|(?:[\w-]+\.)?interact\.sh|(?:[\w-]+\.)?ngrok\.(?:io|app|free)|pastebin\.com|discord\.com\/api\/webhooks)\b/gi,
];

// AS-S009 — literal credentials embedded in tool source
const SOURCE_SECRET_RES = /(["'])(sk-[A-Za-z0-9]{12,}|gh[pousr]_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[A-Za-z0-9-]{8,}|eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,})\1/g;

// AS-S008 — read-only-declared tool performs writes
const READ_ONLY_NAME_RE = /^(?:read|get|list|show|view|fetch|describe|load|print)/i;
const WRITE_PRIMITIVE_RES = [
  /\bfs\.(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|rmSync|rm|rmdirSync|rmdir|unlinkSync|unlink|renameSync|symlinkSync)\b/,
  /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(/,
  /\bchild_process\b/,
  /\brimraf\b/,
  /\brm\s+-[a-z]*r[a-z]*f\b/,
  /\bDROP\s+TABLE\b/,
  /\bTRUNCATE\b/,
  /\bDELETE\s+FROM\b/,
  /\bUPDATE\s+\w+\s+SET\b/,
  /\bcurl\b[^\n|]{0,80}\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
];

// AS-S010 — destructive op without a confirmation gate
const DESTRUCTIVE_RES = [
  /\bfs\.(?:rmSync|rm|rmdirSync|rmdir|unlinkSync|unlink)\b/,
  /\brimraf\b/,
  /\brm\s+-[a-z]*r[a-z]*f\b/,
  /\bDROP\s+TABLE\b/,
  /\bTRUNCATE\s+TABLE\b/,
  /\bTRUNCATE\b/,
  /\bDELETE\s+FROM\b/,
];
const CONFIRM_TOKEN_RE = /\b(?:confirm|dryRun|dry-run|readOnly|read-only|requiresConfirmation|approve|approval|interactive|askUser|force\s*[:=]\s*true)\b/i;

function locateFindings(ruleId, text, hits, mk) {
  const out = [];
  for (const h of hits) {
    const { line, column } = lineColFromIndex(text, h.index);
    out.push({ ruleId, line, column, message: mk(h), snippet: snippetAt(text, h.index) });
  }
  return out;
}

export function analyzeSource(ctx) {
  const { text, isPython } = ctx;
  const findings = [];
  // commented-out code must not light up eval/obfuscation rules; masking keeps
  // every index aligned with the original text so positions/snippets still work
  const masked = maskComments(text, { isPython });

  const execHits = allMatches(text, join(COMMAND_INJECTION_RES));
  findings.push(...locateFindings('AS-S001', text, execHits, (h) =>
    `Shell execution with interpolated value: ${collapse(h.full)}`));

  const evalHits = allMatches(masked, join(EVAL_RES));
  findings.push(...locateFindings('AS-S002', text, evalHits, (h) =>
    `Dynamic evaluation of non-literal input: ${collapse(h.full)}`));

  const obfHits = allMatches(masked, join(OBfuscATION_RES));
  findings.push(...locateFindings('AS-S006', text, obfHits, (h) =>
    `Obfuscation construct: ${collapse(h.full.slice(0, 60))}…`));

  // encoded payload that decodes to text mentioning execution or secrets
  for (const blob of base64Blobs(text)) {
    if (/curl|wget|http|token|secret|password|key|exec|eval/i.test(blob.decoded)) {
      findings.push(...locateFindings('AS-S006', text, [{ index: blob.index, full: blob.encoded }], () =>
        `Base64 blob decodes to: "${blob.decoded.slice(0, 80)}"`));
    }
  }

  // secrets near network calls (proximity returns needle=net match, anchor=secret match)
  // run on masked text so commented-out code/docs don't produce false positives
  const secrets = allMatches(masked, join(SECRET_SOURCE_RES));
  const net = allMatches(masked, join(NETWORK_SOURCE_RES));
  for (const { needle, anchor } of proximity(secrets, net, 300)) {
    findings.push(...locateFindings('AS-S003', text, [anchor], () =>
      `Secret access ${collapse(anchor.full)} within 300 chars of network call ${collapse(needle.full)}`));
  }

  const pathHits = allMatches(text, join(PATH_TRAVERSAL_RES));
  findings.push(...locateFindings('AS-S004', text, pathHits, (h) =>
    `File path built from request/parameter input without visible containment: ${collapse(h.full)}`));

  const ssrfHits = allMatches(masked, join(SSRF_RES));
  const ssrfFindings = locateFindings('AS-S005', text, ssrfHits, (h) =>
    `Network destination derived from external input: ${collapse(h.full)}`);
  // bundled/minified code matches these patterns without any taint context;
  // keep the signal but demote noise (144/100-package hits were mostly this)
  const isBundled = /\.min\.[cm]?js$|(?:^|[/\\])(?:bundle|dist)[/\\]/i.test(ctx.rel ?? '')
    || (text.length > 20_000 && text.length / (text.split('\n').length || 1) > 200);
  if (isBundled) {
    for (const f of ssrfFindings) {
      f.severity = 'low';
      f.message += ' (in bundled/minified code — no taint context available)';
    }
  }
  findings.push(...ssrfFindings);

  // AS-S007 — hardcoded exfiltration / callback sink in tool source
  const exfilHits = allMatches(masked, join(EXFIL_ENDPOINT_RES));
  findings.push(...locateFindings('AS-S007', text, exfilHits, (h) =>
    `Hardcoded exfiltration/callback endpoint in tool code: ${collapse(h.full)}`));

  // AS-S009 — literal credential embedded in source
  const secretHits = allMatches(masked, SOURCE_SECRET_RES);
  findings.push(...locateFindings('AS-S009', text, secretHits, (h) =>
    `Hardcoded secret/token literal in source: ${collapse(h.full)}`));

  // AS-S008 — read-only-declared tool actually mutates state
  for (const { name, index, body } of readOnlyFunctionBodies(masked)) {
    if (WRITE_PRIMITIVE_RES.some((re) => re.test(body))) {
      findings.push(...locateFindings('AS-S008', text, [{ index, full: name }], () =>
        `Tool "${name}" is named read-only but its body performs a write/mutation`));
    }
  }

  // AS-S010 — destructive op with no confirmation / dry-run guard anywhere
  if (DESTRUCTIVE_RES.some((re) => re.test(masked)) && !CONFIRM_TOKEN_RE.test(masked)) {
    const first = DESTRUCTIVE_RES.map((re) => re.exec(masked)).find(Boolean);
    if (first) {
      findings.push(...locateFindings('AS-S010', text, [{ index: first.index, full: first[0] }], (h) =>
        `Destructive operation "${collapse(h.full)}" with no confirmation/dry-run guard in the file`));
    }
  }

  return findings;
}

/** Walk brace-balanced function bodies whose name promises read-only behavior. */
function readOnlyFunctionBodies(text) {
  const out = [];
  const fnHeaderRe = new RegExp(
    [
      '(?:function\\s+([A-Za-z_$][\\w$]*)\\s*\\([^)]*\\)\\s*\\{)',
      '(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(?:async\\s*)?(?:function\\s*)?\\([^)]*\\)\\s*=>\\s*\\{',
      '\\b([A-Za-z_$][\\w$]*)\\s*\\([^)]*\\)\\s*\\{',
    ].join('|'),
    'g'
  );
  let m;
  while ((m = fnHeaderRe.exec(text)) !== null) {
    if (m[0].length === 0) { fnHeaderRe.lastIndex++; continue; }
    const name = m[1] || m[2] || m[3];
    if (!READ_ONLY_NAME_RE.test(name)) continue;
    // the '{' is the last char of the match
    const open = m.index + m[0].length - 1;
    const close = matchBrace(text, open);
    if (close === -1) continue;
    out.push({ name, index: m.index, body: text.slice(open + 1, close) });
  }
  return out;
}

/** Return the index just past the matching '}' for an opening brace, or -1. */
function matchBrace(text, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < text.length; i++) {
    const c = text[i];
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function join(regexes) {
  return new RegExp(regexes.map((r) => r.source).join('|'), 'g');
}

function collapse(s) {
  return s.replace(/\s+/g, ' ').trim().slice(0, 90);
}
