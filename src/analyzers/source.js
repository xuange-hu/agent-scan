import { allMatches, base64Blobs, lineColFromIndex, proximity, snippetAt } from '../util.js';

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

  const execHits = allMatches(text, join(COMMAND_INJECTION_RES));
  findings.push(...locateFindings('AS-S001', text, execHits, (h) =>
    `Shell execution with interpolated value: ${collapse(h.full)}`));

  const evalHits = allMatches(text, join(EVAL_RES));
  findings.push(...locateFindings('AS-S002', text, evalHits, (h) =>
    `Dynamic evaluation of non-literal input: ${collapse(h.full)}`));

  const obfHits = allMatches(text, join(OBfuscATION_RES));
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
  const secrets = allMatches(text, join(SECRET_SOURCE_RES));
  const net = allMatches(text, join(NETWORK_SOURCE_RES));
  for (const { needle, anchor } of proximity(secrets, net, 300)) {
    findings.push(...locateFindings('AS-S003', text, [anchor], () =>
      `Secret access ${collapse(anchor.full)} within 300 chars of network call ${collapse(needle.full)}`));
  }

  const pathHits = allMatches(text, join(PATH_TRAVERSAL_RES));
  findings.push(...locateFindings('AS-S004', text, pathHits, (h) =>
    `File path built from request/parameter input without visible containment: ${collapse(h.full)}`));

  const ssrfHits = allMatches(text, join(SSRF_RES));
  findings.push(...locateFindings('AS-S005', text, ssrfHits, (h) =>
    `Network destination derived from external input: ${collapse(h.full)}`));

  return findings;
}

function join(regexes) {
  return new RegExp(regexes.map((r) => r.source).join('|'), 'g');
}

function collapse(s) {
  return s.replace(/\s+/g, ' ').trim().slice(0, 90);
}
