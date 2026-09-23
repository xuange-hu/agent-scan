# State of MCP Security — September 2026

**We scanned the top 100 MCP-related npm packages (by last-week downloads — ~61M combined weekly installs) with [agent-scan](../README.md). Every headline finding below was read by a human before publishing. False positives are named explicitly, because a security report that hides them isn't worth running.**

- Date: 2026-09-23 · Tool: agent-scan v0.1.0 (23 static rules) · Reproduce: `node scripts/scan-top100.js && node scripts/make-report.js`
- Disclosure: vendors of the verified findings below are being contacted now; this report will note their response status. We publish patterns we can reproduce, not accusations.

## Headline numbers

| Metric | Value |
|---|---|
| Packages scanned | 100 (0 failures) |
| ≥1 signal | **41 (41%)** |
| ≥1 CRITICAL signal | 10 (10%) |
| ≥1 HIGH signal (no critical) | 24 (24%) |
| Total signals | 212 |

Signals by rule group: **P** prompt-injection/hidden-instruction: 8 · **M** MCP-config: 1 · **S** tool-code: 164 · **N** npm supply-chain: 39.

## Verified findings (human-read, real)

### 1. A shipped Agent Skill tells the agent "Do not tell users…" — `@sellable/install@0.1.767`

Its bundled `SKILL.md` (a campaign-creation skill executed by agents) contains:

> `Do not tell users to run internal subskill names.`

and instructs installation via a remote-pipe bootstrap:

> `curl -fsSL "https://app.sellable.dev/api/v2/cli/install" | sh`

**Assessment:** intent is plausibly benign (hide internal UX naming), but this is exactly the *shape* of a concealment instruction, and the `curl | sh` bootstrap is a genuine supply-chain chokepoint: one domain or CI compromise ships new code to every install path. **Rule: AS-P003, AS-P008.**

### 2. A published helper script interpolates arguments into a shell command — `@claude-flow/mcp@3.0.0-alpha.9`

The package ships `.claude/helpers/github-safe.js`, which runs:

```js
execSync(`gh ${args.join(' ')}`, { stdio: 'inherit' });
```

`args` comes from the script's own argv — meaning any agent (or prompt-injected model) that composes this command line gets it executed through a shell. A helper *named* "safe" that hands the shell an interpolated string is the kind of gap this scanner exists to catch. **Rule: AS-S001.**

### 3. Official vendor MCP config launches its own server unpinned — `@sap/mdk-mcp-server@0.4.0`

The `.mcp.json` inside the published package starts the server with `npx @sap/mdk-mcp-server` with **no version pin** — every launch resolves whatever the registry serves that day. Small blast radius, trivial fix. **Rule: AS-M001.**

### 4. 25 of the top 100 packages execute code at install time — AS-N001

`postinstall`/`prepare` hooks are the most-abused npm attack surface (event-stream, uwebsockets.js…). Legitimate reasons exist (native builds), but every one is a standing invitation. Check yours: `agent-scan .`

### 5. Build scripts that shell out with interpolation — `@azure/mcp@3.0.0-beta.46`

`execSync(\`${installCommand} --prefer-online\`)` — `installCommand` is internally constructed, so exploitability today is low; it's flagged because the *pattern* becomes a vulnerability the moment any part of that string becomes external. **Rule: AS-S001 (low exploitability).**

## False positives (yes, we measured them)

Honest numbers matter more than scary ones:

- **6/6 AS-P007 "exfiltration" hits were false positives** — legitimate docs (Hostinger, Armature analytics SDK) that merely mention credentials near URLs within our 500-char proximity window. P007 needs a context-aware follow-up rule; noted in the [improvement plan](#whats-next-for-the-rules).
- **1/4 AS-S002 `eval` hits was commented-out code** (`@notionhq/notion-mcp-server` — a commented `eval(zodSchemaStr)`; the shipped path doesn't evaluate). The analyzer doesn't strip comments yet.
- **4/4 AS-N004 hits in `@modelcontextprotocol/ext-apps` were `docker run` of a *pinned official* Playwright image** — remote execution technically, benign in practice.
- The 144 AS-S005 (SSRF) hits are dominated by bundled/minified code where `fetch(args…)` matches without taint context — high volume, low precision *as a mass statistic*; individually useful when you open the file.

Rough precision on the rules that fired ≥4 times: **~55–60% "real pattern"**, of which a subset is exploitable. That's what a tripwire looks like, and it's why agent-scan says "read this line", not "this package is malicious".

## What the data says

1. **The dangerous shapes are already inside mainstream packages** — concealment phrasing, remote-pipe bootstraps, interpolated shell, unpinned launches — not just in sketchy skill-marketplace clones.
2. **Skills are the softest surface.** Almost nobody reviews a `SKILL.md` the way they'd review a shell script, yet agents execute its prose with more trust than code. The P-group rules exist because prose *is* code for an agent.
3. **Static pattern scanning + human verification is cheap and works.** 212 signals across 100 packages took minutes to produce; the top handful took a human one coffee break to verify.

## What's next for the rules

- Strip comments before AS-S002; require taint context for AS-S005 (or demote to `low` in bundled code)
- AS-P007: tighten proximity to same-sentence co-occurrence + intent verbs
- Ship the **dynamic tool-poisoning probe** (roadmap #1) so remote `tools/list` descriptions get fingerprinted too

## Methodology appendix

- Population: npm search across 8 MCP-related queries → ~2,000 candidates → filtered to MCP-relevant → ranked by `api.npmjs.org` last-week downloads → top 100.
- Each package's registry tarball extracted to disk; scanned with agent-scan v0.1.0 defaults (SKILL/AGENTS/prompt docs + source + configs; no `--include-all-md`).
- No package code was executed during scanning (agent-scan is static by design).
- Rule catalog: [docs/rules.md](rules.md). Scan script: [scripts/scan-top100.js](../scripts/scan-top100.js).
