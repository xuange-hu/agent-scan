/**
 * Rule catalog for agent-scan. Every finding references one rule id.
 *
 * Categories:
 *   P = prompt injection & hidden instructions (skills, AGENTS.md, rule/prompt files)
 *   M = MCP server configuration risks
 *   S = agent tool source-code vulnerabilities
 *   N = npm / supply-chain risks
 */
export const RULES = {
  'AS-P001': {
    title: 'Instruction-override pattern',
    severity: 'critical',
    category: 'prompt-injection',
    description:
      'Text contains phrasing designed to make an LLM ignore its prior instructions ("ignore all previous instructions", "忽略以上指令"…). This is the classic prompt-injection signature, and it has no legitimate place in a skill or config you did not write.',
    remediation:
      'Remove the phrase. If you legitimately need to override behavior, do it in your own top-level prompt, not in third-party content.',
    references: ['OWASP LLM01:2025 Prompt Injection', 'CWE-1426'],
  },
  'AS-P002': {
    title: 'Invisible / bidi-override Unicode characters',
    severity: 'critical',
    category: 'prompt-injection',
    description:
      'Zero-width and bidirectional-override code points (U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+FEFF) can hide instructions from human reviewers while remaining visible to tokenizers. Used in real skill-marketplace attacks.',
    remediation:
      'Delete the hidden characters. Inspect the file with a hex editor or `agent-scan --show-unicode` to locate them.',
    references: ['CWE-1426', 'OSCPs: invisible instruction smuggling'],
  },
  'AS-P003': {
    title: 'Concealment instruction toward the user',
    severity: 'critical',
    category: 'prompt-injection',
    description:
      'Content instructs the agent to hide its actions from the user, avoid mentioning a file/tool, or not log something ("do not tell the user", "without mentioning this file"). A trustworthy instruction never asks an agent to deceive its operator.',
    remediation: 'Remove the instruction and audit anything the agent ran while it was loaded.',
    references: ['OWASP LLM01:2025 Prompt Injection'],
  },
  'AS-P004': {
    title: 'System-prompt exfiltration attempt',
    severity: 'high',
    category: 'prompt-injection',
    description:
      'Content asks the agent to reveal, print, repeat, or translate its system prompt or initial instructions — a common probe to map guardrails before a deeper attack.',
    remediation: 'Remove the request; system prompts should never be dumped into user-facing content.',
    references: ['OWASP LLM07:2025 System Prompt Leakage'],
  },
  'AS-P005': {
    title: 'Encoded payload contains hidden instructions',
    severity: 'critical',
    category: 'prompt-injection',
    description:
      'A base64/hex blob decodes to natural-language text matching injection patterns. Encoding is used to slip malicious instructions past naive keyword filters and human review.',
    remediation: 'Remove the encoded blob. Legitimate assets do not need obfuscated natural-language payloads.',
    references: ['CWE-1426', 'OWASP LLM01:2025 Prompt Injection'],
  },
  'AS-P006': {
    title: 'Jailbreak role-play framing',
    severity: 'medium',
    category: 'prompt-injection',
    description:
      'Content uses jailbreak scaffolding ("pretend you are", "you are now DAN", "unrestricted mode", "no rules apply") to weaken model guardrails.',
    remediation: 'Remove role-play framing that disables safety or policy behavior.',
    references: ['OWASP LLM01:2025 Prompt Injection'],
  },
  'AS-P007': {
    title: 'Secret-reading paired with network transmission',
    severity: 'critical',
    category: 'data-exfiltration',
    description:
      'Within a single sentence, content both touches credentials (~/.ssh, .env, API keys, browser cookies, process.env) and pairs a network destination with a transmission verb (send/POST/upload/发送/上传). This is the exfiltration signature of a malicious skill.',
    remediation:
      'Split the two behaviors or remove them. Nothing an agent reads locally should silently leave the machine.',
    references: ['OWASP LLM02:2025 Insecure Output Handling', 'CWE-200'],
  },
  'AS-P008': {
    title: 'Dangerous shell bootstrap in instructions',
    severity: 'high',
    category: 'dangerous-execution',
    description:
      'Documentation instructs piping a remote script straight into a shell (curl … | bash), running with sudo, or destructive deletes (rm -rf /, mkfs, dd of=/dev/…). Agents following docs execute these verbatim.',
    remediation:
      'Pin and verify artifacts (checksums, signed releases, version-pinned scripts reviewed locally) instead of remote-pipe execution.',
    references: ['CWE-829', 'OWASP LLM05:2025 Improper Output Handling'],
  },
  'AS-M001': {
    title: 'Unpinned package executed at launch',
    severity: 'medium',
    category: 'supply-chain',
    description:
      'The MCP server is started with `npx <pkg>` (or pipx/uvx) without an exact version, so every launch silently runs whatever is latest on the registry — a one-time account takeover away from running attacker code.',
    remediation: 'Pin the exact version: `npx pkg@1.2.3`, ideally with integrity hashes or a lockfile.',
    references: ['OWASP LLM03:2025 Training Data Poisoning (supply chain)', 'CWE-1357'],
  },
  'AS-M002': {
    title: 'Inline shell command in MCP config',
    severity: 'high',
    category: 'dangerous-execution',
    description:
      'A server entry runs `sh`/`bash`/`cmd`/`powershell` with an inline `-c` payload. Config-carried shell one-liners are a staple of malicious "setup" instructions and bypass process-level review.',
    remediation: 'Ship a real, versioned script file that can be reviewed and hashed; do not embed shell in config.',
    references: ['CWE-829'],
  },
  'AS-M003': {
    title: 'Remote MCP endpoint without TLS',
    severity: 'medium',
    category: 'transport-security',
    description:
      'A remote MCP server URL uses plain http:// — tool calls, arguments and results traverse the network in cleartext and are trivially tampered with on path.',
    remediation: 'Use https:// (or an authenticated tunnel/VPN).',
    references: ['CWE-319'],
  },
  'AS-M004': {
    title: 'Live secret embedded in configuration file',
    severity: 'medium',
    category: 'secrets',
    description:
      'An env/header value in the config looks like a real credential (sk-, ghp_, AKIA, long high-entropy token) rather than a placeholder. Config files get committed, synced and screenshotted.',
    remediation:
      'Move secrets to a secret manager or shell expansion, and rotate anything already written to disk.',
    references: ['CWE-798'],
  },
  'AS-M005': {
    title: 'Auto-approval of tool calls enabled',
    severity: 'medium',
    category: 'excessive-agency',
    description:
      'The configuration enables automatic approval / yolo / skip-permissions for tool execution, removing the human gate that contains prompt-injection damage.',
    remediation: 'Keep approvals on; whitelist narrow read-only actions instead of global auto-approve.',
    references: ['OWASP LLM08:2025 Excessive Agency'],
  },
  'AS-S001': {
    title: 'Command injection in tool implementation',
    severity: 'critical',
    category: 'injection',
    description:
      'A shell execution call (exec, child_process, os.system, subprocess with shell=True) interpolates a variable or template expression — attacker- or model-controlled text reaches a shell unsanitized.',
    remediation:
      'Use execve-style APIs with an argument array, validate against an allowlist, and never build command strings from model output.',
    references: ['CWE-78', 'OWASP LLM05:2025 Improper Output Handling'],
  },
  'AS-S002': {
    title: 'Dynamic code evaluation',
    severity: 'critical',
    category: 'injection',
    description:
      'eval / new Function / exec-python style dynamic evaluation is applied to non-literal input, giving arbitrary code execution to anything that can influence the string (including a prompt-injected model).',
    remediation: 'Replace with a safe parser or an explicit allowlist of operations.',
    references: ['CWE-95'],
  },
  'AS-S003': {
    title: 'Secrets read near a network call',
    severity: 'high',
    category: 'data-exfiltration',
    description:
      'Source code accesses credentials (process.env bulk reads, ~/.ssh, keychain, .env parsing) within close proximity of a network request — the shape of exfiltration logic, whether intentional or a leaky telemetry add-on.',
    remediation:
      'Send only specific, documented fields over TLS endpoints; never enumerate the environment wholesale.',
    references: ['CWE-200', 'OWASP LLM02:2025'],
  },
  'AS-S004': {
    title: 'Path traversal in file-handling tool',
    severity: 'high',
    category: 'injection',
    description:
      'A filesystem read/write composes a path from a request/tool parameter without containment checks (no path.resolve + prefix verification), letting `../` escape the sandbox directory.',
    remediation:
      'Resolve the absolute path and verify it starts with the intended base directory before I/O.',
    references: ['CWE-22'],
  },
  'AS-S005': {
    title: 'SSRF: agent-controlled URL fetched',
    severity: 'medium',
    category: 'ssrf',
    description:
      'The tool fetches a URL taken from tool arguments or model output without an allowlist — enabling internal-network pivoting (169.254.169.254, localhost, metadata endpoints).',
    remediation: 'Validate scheme/host against an allowlist; block private ranges and link-local addresses.',
    references: ['CWE-918'],
  },
  'AS-S006': {
    title: 'Obfuscated code construct',
    severity: 'high',
    category: 'obfuscation',
    description:
      'Heavily encoded or packed code detected (long base64/hex decoded to text, String.fromCharCode chains, \\x escapes, eval(atob(...))). Obfuscation in an agent tool is a deliberate evasion signal.',
    remediation: 'Refuse the dependency until the payload is decoded and reviewed.',
    references: ['CWE-94'],
  },
  'AS-N001': {
    title: 'Lifecycle install scripts',
    severity: 'high',
    category: 'supply-chain',
    description:
      'package.json defines pre/post install/upgrade/uninstall hooks, which execute arbitrary code at install time and are the single most abused npm attack surface.',
    remediation:
      'Avoid packages needing install hooks; if required, pin exactly, audit the hook, and install with --ignore-scripts where feasible.',
    references: ['CWE-829', 'npm attack history: event-stream, uwebsockets.js…'],
  },
  'AS-N002': {
    title: 'Dependency resolved from a git/URL source',
    severity: 'medium',
    category: 'supply-chain',
    description:
      'A dependency points at a git URL, branch, or direct tarball instead of the registry — no public audit trail, no deprecation signal, mutable targets.',
    remediation: 'Publish/consume through the registry with pinned versions.',
    references: ['CWE-829'],
  },
  'AS-N003': {
    title: 'Wildcard or latest dependency range',
    severity: 'low',
    category: 'supply-chain',
    description:
      'A dependency uses `*`, `latest`, or an open `x` range, so any registry-side compromise lands in your install immediately.',
    remediation: 'Pin exact versions and update deliberately via automated dependency tooling.',
    references: ['CWE-1357'],
  },
  'AS-N004': {
    title: 'Script downloads and executes remote code',
    severity: 'critical',
    category: 'supply-chain',
    description:
      'A package.json script pipes a download into a shell or installs from an unreviewed remote URL (curl … | sh, npm i <url>).',
    remediation: 'Vendor the dependency or install from a pinned registry version with integrity checks.',
    references: ['CWE-829'],
  },
  'AS-T001': {
    title: 'Invisible Unicode in live MCP metadata',
    severity: 'critical',
    category: 'tool-poisoning',
    description:
      'A running MCP server advertises a tool name, title, description, or schema containing zero-width or bidi-override characters — hidden instructions that reach the model but not the human reviewer. Detected only at runtime; the static file scan cannot see dynamically-served metadata.',
    remediation: 'Do not register the server. Report it upstream; metadata strings should be plain printable text.',
    references: ['OWASP LLM01:2025 Prompt Injection', 'tool poisoning attacks (Invariant Labs, 2025)'],
  },
  'AS-T002': {
    title: 'Instruction override in live MCP metadata',
    severity: 'critical',
    category: 'tool-poisoning',
    description:
      'A live tool description or prompt/resource text contains instruction-override phrasing ("ignore all previous instructions"…). Tool descriptions are auto-injected into agent context, making this a direct channel into the model.',
    remediation: 'Refuse the server until the description is cleaned; audit sessions where it was enabled.',
    references: ['OWASP LLM01:2025 Prompt Injection'],
  },
  'AS-T003': {
    title: 'Concealment directive in live MCP metadata',
    severity: 'critical',
    category: 'tool-poisoning',
    description:
      'A live tool description instructs the agent to hide its actions from the user ("do not tell the user", "without mentioning this tool"). Legitimate tools never ask the agent to deceive its operator.',
    remediation: 'Uninstall the server and review what it did in past sessions.',
    references: ['OWASP LLM01:2025 Prompt Injection'],
  },
  'AS-T004': {
    title: 'System-prompt or jailbreak framing in live MCP metadata',
    severity: 'high',
    category: 'tool-poisoning',
    description:
      'A live tool/prompt metadata field tries to surface the system prompt or move the agent into an unrestricted mode. These phrases have no functional purpose in tool documentation.',
    remediation: 'Remove the server; escalate to its registry listing.',
    references: ['OWASP LLM07:2025 System Prompt Leakage'],
  },
  'AS-T005': {
    title: 'Credential exfiltration sentence in live MCP metadata',
    severity: 'high',
    category: 'tool-poisoning',
    description:
      'A single sentence in live MCP metadata pairs a credential source (env vars, .ssh, API keys) with a network destination and a transmission verb — an embedded exfiltration instruction aimed at the agent.',
    remediation: 'Treat the server as hostile; capture the full tools/list payload and report it.',
    references: ['OWASP LLM01:2025 Prompt Injection'],
  },
  'AS-T006': {
    title: 'Dangerous bootstrap command in live MCP metadata',
    severity: 'medium',
    category: 'tool-poisoning',
    description:
      'A live tool description documents piping a remote script into a shell (curl … | sh) or other destructive commands, steering the agent (or user following the docs) into running them.',
    remediation: 'Download, inspect, and pin scripts before executing; never let an agent run doc-suggested curl|sh.',
    references: ['CWE-829'],
  },
  'AS-T007': {
    title: 'Suspicious directive or payload in tool input schema',
    severity: 'medium',
    category: 'tool-poisoning',
    description:
      'An input-schema parameter description issues agent-directed commands ("you must call…", "do not change…") or a server-supplied default/const embeds URLs, remote-exec one-liners, long encoded blobs, or template placeholders. Agents typically send such defaults untouched.',
    remediation: 'Inspect every schema default manually before first call; reject servers that ship instructions in data fields.',
    references: ['schema shading / tool poisoning attacks'],
  },
};

export function ruleMeta(ruleId) {
  return RULES[ruleId];
}
