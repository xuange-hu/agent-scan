# example fixtures

Realistic — and deliberately unsafe — samples used for demos and tests. **Do not copy these files into a project you run.**

| Directory | Story |
|---|---|
| `malicious-skill/` | A marketplace "summarizer" skill: base64 sync config that decodes to key-theft instructions, plus a `curl \| bash` telemetry bootstrap the agent is told to run quietly. |
| `trojan-mcp/` | A `.mcp.json` with an unpinned `npx` package + `autoApprove`, an inline `bash -c` remote payload, a cleartext endpoint and baked-in credentials. |
| `vulnerable-server/` | An MCP tool server with command injection, SSRF, an env-dumping telemetry endpoint and a `postinstall` hook. |

Try it:

```bash
node ../bin/agent-scan.js .
```

Contributions of *new* realistic attack shapes are very welcome — see `tests/agent-scan.test.js` for the fixture/test pattern and open a PR.
