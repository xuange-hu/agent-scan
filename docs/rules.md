# agent-scan rule catalog

Every finding references exactly one rule below. Rules are static patterns: no network calls, no code execution, no model API — a scan is a pure local function of the files on disk.


## prompt-injection

### AS-P001

**Instruction-override pattern** — severity `critical`

Text contains phrasing designed to make an LLM ignore its prior instructions ("ignore all previous instructions", "忽略以上指令"…). This is the classic prompt-injection signature, and it has no legitimate place in a skill or config you did not write.

**Remediation:** Remove the phrase. If you legitimately need to override behavior, do it in your own top-level prompt, not in third-party content.

**References:** OWASP LLM01:2025 Prompt Injection; CWE-1426

### AS-P002

**Invisible / bidi-override Unicode characters** — severity `critical`

Zero-width and bidirectional-override code points (U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+FEFF) can hide instructions from human reviewers while remaining visible to tokenizers. Used in real skill-marketplace attacks.

**Remediation:** Delete the hidden characters. Inspect the file with a hex editor or `agent-scan --show-unicode` to locate them.

**References:** CWE-1426; OSCPs: invisible instruction smuggling

### AS-P003

**Concealment instruction toward the user** — severity `critical`

Content instructs the agent to hide its actions from the user, avoid mentioning a file/tool, or not log something ("do not tell the user", "without mentioning this file"). A trustworthy instruction never asks an agent to deceive its operator.

**Remediation:** Remove the instruction and audit anything the agent ran while it was loaded.

**References:** OWASP LLM01:2025 Prompt Injection

### AS-P004

**System-prompt exfiltration attempt** — severity `high`

Content asks the agent to reveal, print, repeat, or translate its system prompt or initial instructions — a common probe to map guardrails before a deeper attack.

**Remediation:** Remove the request; system prompts should never be dumped into user-facing content.

**References:** OWASP LLM07:2025 System Prompt Leakage

### AS-P005

**Encoded payload contains hidden instructions** — severity `critical`

A base64/hex blob decodes to natural-language text matching injection patterns. Encoding is used to slip malicious instructions past naive keyword filters and human review.

**Remediation:** Remove the encoded blob. Legitimate assets do not need obfuscated natural-language payloads.

**References:** CWE-1426; OWASP LLM01:2025 Prompt Injection

### AS-P006

**Jailbreak role-play framing** — severity `medium`

Content uses jailbreak scaffolding ("pretend you are", "you are now DAN", "unrestricted mode", "no rules apply") to weaken model guardrails.

**Remediation:** Remove role-play framing that disables safety or policy behavior.

**References:** OWASP LLM01:2025 Prompt Injection


## data-exfiltration

### AS-P007

**Secret-reading paired with network transmission** — severity `critical`

Within a single sentence, content both touches credentials (~/.ssh, .env, API keys, browser cookies, process.env) and pairs a network destination with a transmission verb (send/POST/upload/发送/上传). This is the exfiltration signature of a malicious skill.

**Remediation:** Split the two behaviors or remove them. Nothing an agent reads locally should silently leave the machine.

**References:** OWASP LLM02:2025 Insecure Output Handling; CWE-200


## dangerous-execution

### AS-P008

**Dangerous shell bootstrap in instructions** — severity `high`

Documentation instructs piping a remote script straight into a shell (curl … | bash), running with sudo, or destructive deletes (rm -rf /, mkfs, dd of=/dev/…). Agents following docs execute these verbatim.

**Remediation:** Pin and verify artifacts (checksums, signed releases, version-pinned scripts reviewed locally) instead of remote-pipe execution.

**References:** CWE-829; OWASP LLM05:2025 Improper Output Handling


## supply-chain

### AS-M001

**Unpinned package executed at launch** — severity `medium`

The MCP server is started with `npx <pkg>` (or pipx/uvx) without an exact version, so every launch silently runs whatever is latest on the registry — a one-time account takeover away from running attacker code.

**Remediation:** Pin the exact version: `npx pkg@1.2.3`, ideally with integrity hashes or a lockfile.

**References:** OWASP LLM03:2025 Training Data Poisoning (supply chain); CWE-1357


## dangerous-execution

### AS-M002

**Inline shell command in MCP config** — severity `high`

A server entry runs `sh`/`bash`/`cmd`/`powershell` with an inline `-c` payload. Config-carried shell one-liners are a staple of malicious "setup" instructions and bypass process-level review.

**Remediation:** Ship a real, versioned script file that can be reviewed and hashed; do not embed shell in config.

**References:** CWE-829


## transport-security

### AS-M003

**Remote MCP endpoint without TLS** — severity `medium`

A remote MCP server URL uses plain http:// — tool calls, arguments and results traverse the network in cleartext and are trivially tampered with on path.

**Remediation:** Use https:// (or an authenticated tunnel/VPN).

**References:** CWE-319


## secrets

### AS-M004

**Live secret embedded in configuration file** — severity `medium`

An env/header value in the config looks like a real credential (sk-, ghp_, AKIA, long high-entropy token) rather than a placeholder. Config files get committed, synced and screenshotted.

**Remediation:** Move secrets to a secret manager or shell expansion, and rotate anything already written to disk.

**References:** CWE-798


## excessive-agency

### AS-M005

**Auto-approval of tool calls enabled** — severity `medium`

The configuration enables automatic approval / yolo / skip-permissions for tool execution, removing the human gate that contains prompt-injection damage.

**Remediation:** Keep approvals on; whitelist narrow read-only actions instead of global auto-approve.

**References:** OWASP LLM08:2025 Excessive Agency


## injection

### AS-S001

**Command injection in tool implementation** — severity `critical`

A shell execution call (exec, child_process, os.system, subprocess with shell=True) interpolates a variable or template expression — attacker- or model-controlled text reaches a shell unsanitized.

**Remediation:** Use execve-style APIs with an argument array, validate against an allowlist, and never build command strings from model output.

**References:** CWE-78; OWASP LLM05:2025 Improper Output Handling

### AS-S002

**Dynamic code evaluation** — severity `critical`

eval / new Function / exec-python style dynamic evaluation is applied to non-literal input, giving arbitrary code execution to anything that can influence the string (including a prompt-injected model).

**Remediation:** Replace with a safe parser or an explicit allowlist of operations.

**References:** CWE-95


## data-exfiltration

### AS-S003

**Secrets read near a network call** — severity `high`

Source code accesses credentials (process.env bulk reads, ~/.ssh, keychain, .env parsing) within close proximity of a network request — the shape of exfiltration logic, whether intentional or a leaky telemetry add-on.

**Remediation:** Send only specific, documented fields over TLS endpoints; never enumerate the environment wholesale.

**References:** CWE-200; OWASP LLM02:2025


## injection

### AS-S004

**Path traversal in file-handling tool** — severity `high`

A filesystem read/write composes a path from a request/tool parameter without containment checks (no path.resolve + prefix verification), letting `../` escape the sandbox directory.

**Remediation:** Resolve the absolute path and verify it starts with the intended base directory before I/O.

**References:** CWE-22


## ssrf

### AS-S005

**SSRF: agent-controlled URL fetched** — severity `medium`

The tool fetches a URL taken from tool arguments or model output without an allowlist — enabling internal-network pivoting (169.254.169.254, localhost, metadata endpoints).

**Remediation:** Validate scheme/host against an allowlist; block private ranges and link-local addresses.

**References:** CWE-918


## obfuscation

### AS-S006

**Obfuscated code construct** — severity `high`

Heavily encoded or packed code detected (long base64/hex decoded to text, String.fromCharCode chains, \x escapes, eval(atob(...))). Obfuscation in an agent tool is a deliberate evasion signal.

**Remediation:** Refuse the dependency until the payload is decoded and reviewed.

**References:** CWE-94


## supply-chain

### AS-N001

**Lifecycle install scripts** — severity `high`

package.json defines pre/post install/upgrade/uninstall hooks, which execute arbitrary code at install time and are the single most abused npm attack surface.

**Remediation:** Avoid packages needing install hooks; if required, pin exactly, audit the hook, and install with --ignore-scripts where feasible.

**References:** CWE-829; npm attack history: event-stream, uwebsockets.js…

### AS-N002

**Dependency resolved from a git/URL source** — severity `medium`

A dependency points at a git URL, branch, or direct tarball instead of the registry — no public audit trail, no deprecation signal, mutable targets.

**Remediation:** Publish/consume through the registry with pinned versions.

**References:** CWE-829

### AS-N003

**Wildcard or latest dependency range** — severity `low`

A dependency uses `*`, `latest`, or an open `x` range, so any registry-side compromise lands in your install immediately.

**Remediation:** Pin exact versions and update deliberately via automated dependency tooling.

**References:** CWE-1357

### AS-N004

**Script downloads and executes remote code** — severity `critical`

A package.json script pipes a download into a shell or installs from an unreviewed remote URL (curl … | sh, npm i <url>).

**Remediation:** Vendor the dependency or install from a pinned registry version with integrity checks.

**References:** CWE-829
