# Contributing to agent-scan

Small, reviewable, test-backed — like the tool itself.

## Adding or fixing a rule

1. Add the pattern to the relevant analyzer in `src/analyzers/`.
2. Register metadata (id, severity, description, remediation, references) in `src/rules.js`.
3. Add at least one *positive* fixture and one *negative* (must-not-fire) case in `tests/agent-scan.test.js`. False-positive tests are as valuable as detection tests.
4. Regenerate the catalog doc: the `### AS-xxx` sections in `docs/rules.md` mirror `src/rules.js`.
5. `npm test` green, then open a PR explaining the real-world attack shape the rule catches.

## Layout

```
bin/agent-scan.js      CLI entry
src/cli.js             arg parsing, exit codes
src/engine.js          orchestration, scoring, dedupe
src/discover.js        file walk + classification
src/analyzers/         one module per target type
src/rules.js           rule catalog (single source of truth)
src/reporters/         terminal / json+sarif / markdown
tests/                 node:test suite with inline fixtures
examples/              demo attack fixtures
```

## House rules

- Zero runtime dependencies. This is a feature, protect it.
- Analyzers must be pure functions of `ctx.text` — no fs, no network, no child_process.
- Every finding needs file, line, column and a message that tells a human *what* matched and *why it matters*.
