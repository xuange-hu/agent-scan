# Security Policy

## Reporting a vulnerability in agent-scan

Open a [GitHub security advisory](https://github.com/agent-scan/agent-scan/security/advisories/new) rather than a public issue. We aim to respond within 72 hours.

Threat model note: agent-scan is a **static** scanner. It never executes the code or scripts it finds, and parsed JSON never reaches `eval`. If you believe a crafted file can turn agent-scan itself into an execution vector (e.g. via ReDoS), that is a vulnerability — please report it.

## Reporting a malicious skill / MCP server you found in the wild

1. Do **not** install or start it; keep the on-disk artifacts.
2. Run `agent-scan <path> --format md > report.md` and attach the findings to the registry's abuse report (the marketplace where you found it).
3. Optional: share the anonymized shape with us via an issue — new attack shapes become new rules.
