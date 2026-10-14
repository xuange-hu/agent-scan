# Changelog

All notable changes to **agent-scan** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0] - 2026-10-14

### Added
- 6 new detection rules (catalog now 37):
  - **AS-S007** suspicious outbound / webhook endpoint in tool source (data-exfiltration)
  - **AS-S008** read-only-declared tool that performs writes (excessive-agency)
  - **AS-S009** hardcoded secret / token in tool source (secrets)
  - **AS-S010** destructive operation without a confirmation gate (excessive-agency)
  - **AS-M006** overly broad wildcard resource scope in MCP config (excessive-agency)
  - **AS-M007** global write permission / root filesystem granted (excessive-agency)
- Project config file `.agent-scan.yml` / `.agent-scan.yaml` / `.agent-scan.json`
  (ignore globs, `fail-on` threshold, default `format`, `include-all-md`). Flags win.
- `agent-scan probe` HTTP transport (Streamable HTTP) — the E2E suite launches a
  real Node `http` MCP server and asserts findings / no-findings.
- JSON report schema + SARIF 2.1.0 structure tests.
- `docs/rules.md` catalog expanded with the new rules; README architecture + config sections.
- `probeScanHttp` exported from the package entry point.

### Fixed
- Source SSRF / secret-near-network heuristics now run on comment-masked text,
  removing false positives from URLs mentioned in comments.

## [0.3.0] - 2026-10-09

- Registry-completeness property test (`tests/registry.test.js`) asserting every rule is
  registered, well-formed and carries required fields.
- Bilingual README (English + 简体中文) with CI / version / download badges.
- Expanded `docs/rules.md` detection catalog.

## [0.2.0] - 2026-09-24

- Published to npm as `@yoshine2007/agent-scan`.
- Static security scanner for MCP servers / AI agent ecosystems.
- 31 built-in rules covering common MCP/Agent attack surfaces.

## [0.1.0] - 2026-09-22

- Initial public release.
