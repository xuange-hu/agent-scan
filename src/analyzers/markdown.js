import { allMatches, base64Blobs, lineColFromIndex, snippetAt, visibleUnicode } from '../util.js';

const OVERRIDE_RES = [
  /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|directives?|context)/gi,
  /disregard\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|rules?|guidelines?|prompts?)/gi,
  /forget\s+(?:all\s+|everything\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?|training)/gi,
  /override\s+(?:all\s+)?(?:previous|system|safety)\s+(?:instructions?|rules?|prompts?)/gi,
  /忽略(?:以上|之前|上述|所有|先前)[^\n]{0,8}?(指令|规则|提示|说明)/g,
  /无视(?:以上|之前|上述|所有)[^\n]{0,8}?(指令|规则|要求)/g,
  /new\s+instructions?\s*[:：]/gi,
];

const CONCEAL_RES = [
  /do\s*not\s+(?:tell|inform|notify|reveal\s+to|mention\s+to)\s+(?:the\s+)?user/gi,
  /don'?t\s+(?:tell|mention|inform)\s+(?:the\s+)?user/gi,
  /without\s+(?:telling|informing|mentioning(?:\s+to)?)\s+(?:the\s+)?user/gi,
  /hide\s+(?:this|these|that|the\s+(?:result|output|step|file))\s+from\s+(?:the\s+)?user/gi,
  /keep\s+this\s+(?:file|instruction|step|section)\s+(?:secret|private|hidden)/gi,
  /(?:never|don'?t)\s+(?:log|record)\s+th(?:is|e)\b/gi,
  /不要(?:告诉|通知|告知|让)用户/g,
  /对用户(?:隐瞒|保密)/g,
];

const SYSPROMPT_RES = [
  /(?:reveal|print|repeat|show|output|dump|display|translate)\s+(?:me\s+)?(?:your|the)\s+system\s+prompt/gi,
  /(?:your|the)\s+(?:initial|original|hidden)\s+instructions?\s+(?:above|verbatim)/gi,
  /expose\s+(?:your|the)\s+(?:system\s+prompt|guardrails?|safety\s+rules)/gi,
  /输出(?:你的|系统的)?(?:初始)?提示词/g,
];

const JAILBREAK_RES = [
  /you\s+are\s+now\s+(?:in\s+)?(?:developer|god|dan|jailbreak|unrestricted)\s*mode/gi,
  /(?:pretend|act\s+as\s+if\s+you|imagine)\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:unrestricted|unfiltered|rule[- ]free|amoral)/gi,
  /(?:no|without)\s+(?:any\s+)?(?:rules?|restrictions?|limitations?|filters?)\s+(?:apply|anymore|now|here)/gi,
  /enable\s+(?:developer|admin|root|god)\s+mode/gi,
  /you\s+(?:now\s+)?have\s+no\s+(?:safety|content)\s+(?:guidelines?|restrictions?|policies)/gi,
];

const SECRET_RES = [
  /\.ssh[\\/](?:id_[a-z0-9]+|config|authorized_keys)/gi,
  /(?:^|[\s"'`(])\.env\b/gi,
  /\bcredentials?\b[^.\n]{0,40}\b(?:file|json|dir)/gi,
  /\bAPI[_ -]?KEYS?\b/gi,
  /\bsecret[_ -]?(?:keys?|tokens?)\b/gi,
  /\b(?:process\.env|os\.environ|ENV)\b/gi,
  /browser[^.\n]{0,20}(?:cookie|password|session)s?/gi,
  /wallet[^.\n]{0,20}(?:seed|private\s+key|mnemonic)/gi,
  /(?:读取|获取|收集)[^\n]{0,20}(?:密钥|凭证|密码|环境变量|token)/g,
];

const NETWORK_RES = [
  /\bcurl\b[^\n]{0,120}\b(?:-X\s*POST|--data|-d\s|--upload|-T\s)/gi,
  /\b(?:wget|curl)\b[^\n]{0,80}\bhttps?:\/\//gi,
  /\b(?:fetch|axios|request|http\.post|urllib|requests\.)\b/gi,
  /\b(?:POST|upload|send|exfiltrate|forward|transmit|提交|上传|发送)[^\n]{0,60}\b(?:to|至|到)\s*https?\:\/\//gi,
  /\bhttps?:\/\/(?!(?:localhost|127\.0\.0\.1|(?:[\w-]+\.)?(?:example\.com|example\.org)))[\w.-]+\.[a-z]{2,}[^\s"'`)<>]*/gi,
  /\b(?:webhook|pastebin|ngrok|requestbin|discord\.com\/api\/webhooks)\b/gi,
];

const DANGEROUS_CMD_RES = [
  /\b(?:curl|wget)\b[^\n|]{0,80}\|\s*(?:sudo\s+)?(?:ba)?sh\b/gi,
  /\brm\s+-[a-z]*r[a-z]*f\s+\/(?:\s|$)/gi,
  /\bmkfs\./gi,
  /\bdd\s+if=[^\n]{0,30}of=\/dev\//gi,
  /\bchmod\s+777\s+\//gi,
  /\b(?:rm|delete)\s+[^\n]{0,30}(?:entire|all)\s+(?:files?|directories|data)\b/gi,
  /\bsudo\s+(?:rm|dd|mkfs|chmod|chown)\b/gi,
  /curl[^\n]{0,60}\|[^\n]{0,10}(?:bash|sh)/g,
];

const HIDDEN_UNICODE_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]/g;

function check(regexes, ruleId, findings, text, mkMessage) {
  for (const re of regexes) {
    for (const hit of allMatches(text, re)) {
      const { line, column } = lineColFromIndex(text, hit.index);
      findings.push({
        ruleId,
        line,
        column,
        message: mkMessage ? mkMessage(hit) : `${ruleId} matched: "${hit.full.slice(0, 80)}"`,
        snippet: snippetAt(text, hit.index),
      });
    }
  }
}

export function analyzeMarkdown(ctx) {
  const { text } = ctx;
  const findings = [];

  check(OVERRIDE_RES, 'AS-P001', findings, text, (h) => `Instruction-override phrasing: "${h.full.trim()}"`);
  check(CONCEAL_RES, 'AS-P003', findings, text, (h) => `Asks the agent to conceal actions from the user: "${h.full.trim()}"`);
  check(SYSPROMPT_RES, 'AS-P004', findings, text, (h) => `Attempts to surface the system prompt: "${h.full.trim()}"`);
  check(JAILBREAK_RES, 'AS-P006', findings, text, (h) => `Jailbreak framing: "${h.full.trim()}"`);
  check(DANGEROUS_CMD_RES, 'AS-P008', findings, text, (h) => `Dangerous bootstrap command documented: "${h.full.trim()}"`);

  // Hidden unicode, one finding per occurrence (dedupe by line handled by engine)
  for (const hit of allMatches(text, HIDDEN_UNICODE_RE)) {
    const { line, column } = lineColFromIndex(text, hit.index);
    const cp = hit.full.codePointAt(0).toString(16).padStart(4, '0');
    findings.push({
      ruleId: 'AS-P002',
      line,
      column,
      message: `Invisible character U+${cp} (${visibleUnicode(hit.full)}) hidden in text`,
      snippet: snippetAt(text, hit.index),
    });
  }

  // Secrets mentioned near network transmission. The old 500-char proximity
  // window was 6/6 false positives on legitimate docs (a credential and a URL
  // merely co-occurring); require both plus an explicit transmission intent
  // verb inside the same sentence.
  const INTENT_RE = /\b(?:send|post|upload|transmit|exfiltrate|forward|leak|share|email|report|submit|pipe|dump)\b|(?:发送|上传|提交|外传|回传|报告给)/i;
  for (const lm of text.matchAll(/[^\n]+/g)) {
    let offset = 0;
    // sentence = run of text ending at .!?。！ followed by space/EOL
    // (dots inside URLs like "...tokens.io/api" must not split)
    for (const sentence of lm[0].split(/(?<=[.!?。！？])(?=\s|$)/)) {
      const at = lm.index + offset;
      offset += sentence.length + 1;
      const secret = sentence.match(joinAlt(SECRET_RES));
      if (!secret) continue;
      const net = sentence.match(joinAlt(NETWORK_RES));
      if (!net) continue;
      const intent = sentence.match(INTENT_RE);
      if (!intent) continue;
      const { line, column } = lineColFromIndex(text, at + sentence.indexOf(secret[0]));
      findings.push({
        ruleId: 'AS-P007',
        line,
        column,
        message: `Credential "${secret[0].trim()}" and network destination "${net[0].trim().slice(0, 60)}" co-occur with transmission intent "${intent[0]}" in one sentence`,
        snippet: snippetAt(text, at + sentence.indexOf(secret[0])),
      });
    }
  }

  // Encoded payloads that decode to injection text
  for (const blob of base64Blobs(text)) {
    const decodedLow = blob.decoded.toLowerCase();
    const suspicious =
      /ignore|instruction|system prompt|password|token|secret|api key|curl|wget|http|忽略|密码|密钥|指令/.test(decodedLow);
    if (suspicious) {
      const { line, column } = lineColFromIndex(text, blob.index);
      findings.push({
        ruleId: 'AS-P005',
        line,
        column,
        message: `Base64 blob decodes to suspicious instructions: "${blob.decoded.slice(0, 100)}"`,
        snippet: snippetAt(text, blob.index),
      });
    }
  }

  return findings;
}

function joinAlt(regexes) {
  return new RegExp(regexes.map((r) => r.source).join('|'), 'gi');
}
