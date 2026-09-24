import { writeFileSync } from 'node:fs';
import { scan, shouldFail } from './engine.js';
import { probeScan } from './probe/index.js';
import { RULES } from './rules.js';
import { reportTerminal } from './reporters/terminal.js';
import { reportJson, reportSarif } from './reporters/json.js';
import { reportMarkdown } from './reporters/markdown.js';
import { SEVERITIES, TOOL_VERSION } from './util.js';

const HELP = `agent-scan — security scanner for the AI agent ecosystem
(npm audit for MCP servers, Agent Skills, AGENTS.md and agent tool code)

USAGE
  agent-scan [path]                    Scan a repo/dir/file (default: .)
  agent-scan --format json -o r.json   Machine-readable output
  agent-scan --sarif -o results.sarif  Upload to GitHub code scanning
  agent-scan --fail-on high            CI gate: exit 1 on high+ findings
  agent-scan --rules                   Print the rule catalog
  agent-scan probe <cmd> [args…]       Dynamic tool-poisoning probe: launch an
                                       MCP server locally, capture its live
                                       metadata and scan it. Tools are NEVER
                                       executed — metadata capture only.
                                       e.g. agent-scan probe npx -y some-mcp

PROBE OPTIONS (before the server command)
      --timeout <ms>                  Handshake/capture deadline (default: 15000)
  Anything after the server command is passed through to that command.

OPTIONS
  -f, --format <terminal|json|sarif|md>   Output format (default: terminal)
  -o, --output <file>                     Write report to file instead of stdout
      --fail-on <severity|none>           Exit code 1 when findings reach severity (default: critical)
      --ignore <glob>                     Extra ignore patterns (repeatable)
      --include-all-md                    Also scan every *.md (default: only SKILL/AGENTS/prompt docs)
      --no-color                          Disable ANSI colors
  -q, --quiet                             Only print the summary line
  -h, --help                              Show help
  -V, --version                           Show version

EXIT CODES
  0  clean (or below --fail-on threshold)
  1  findings at or above the threshold
  2  usage error

GitHub Action:  see action.yml — uploads SARIF to code scanning automatically.
`;

export function main(argv) {
  if (argv[0] === 'probe') return mainProbe(argv.slice(1));
  const opts = { path: '.', format: 'terminal', failOn: 'critical', ignore: [], color: true, quiet: false, includeAllMd: false };
  let showRules = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': process.stdout.write(HELP); return 0;
      case '-V': case '--version': process.stdout.write(`agent-scan ${TOOL_VERSION}\n`); return 0;
      case '--rules': showRules = true; break;
      case '-f': case '--format': opts.format = argv[++i]; break;
      case '--json': opts.format = 'json'; break;
      case '--sarif': opts.format = 'sarif'; break;
      case '-o': case '--output': opts.output = argv[++i]; break;
      case '--fail-on': opts.failOn = argv[++i]; break;
      case '--ignore': opts.ignore.push(argv[++i]); break;
      case '--include-all-md': opts.includeAllMd = true; break;
      case '--no-color': opts.color = false; break;
      case '-q': case '--quiet': opts.quiet = true; break;
      default:
        if (a.startsWith('-')) {
          process.stderr.write(`agent-scan: unknown option ${a}\n\n${HELP}`);
          return 2;
        }
        opts.path = a;
    }
  }

  if (showRules) return printRules(opts);
  if (!['terminal', 'json', 'sarif', 'md'].includes(opts.format)) {
    process.stderr.write(`agent-scan: bad --format "${opts.format}"\n`);
    return 2;
  }
  if (opts.failOn !== 'none' && !SEVERITIES.includes(opts.failOn)) {
    process.stderr.write(`agent-scan: bad --fail-on "${opts.failOn}" (use: ${SEVERITIES.join('|')}|none)\n`);
    return 2;
  }

  const result = scan(opts.path, { includeAllMd: opts.includeAllMd, ignore: opts.ignore });

  let body =
    opts.format === 'json' ? reportJson(result)
      : opts.format === 'sarif' ? reportSarif(result)
        : opts.format === 'md' ? reportMarkdown(result)
          : reportTerminal(result, { noColor: !opts.color });

  if (opts.quiet && opts.format === 'terminal') {
    const c = result.counts;
    body = `agent-scan ${result.root}: risk ${result.riskScore}/100 · ${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low`;
  }

  if (opts.output) {
    writeFileSync(opts.output, body + '\n');
    if (opts.format === 'terminal') process.stdout.write(body + '\n');
    else process.stderr.write(`agent-scan: wrote ${opts.format} report to ${opts.output}\n`);
  } else {
    process.stdout.write(body + '\n');
  }

  const failed = shouldFail(result, opts.failOn);
  if (failed) {
    process.stderr.write(`agent-scan: failing as instructed — findings at or above "${opts.failOn}"\n`);
  }
  return failed ? 1 : 0;
}

function printRules(opts) {
  const rows = Object.entries(RULES).map(([id, r]) =>
    `${id}  ${r.severity.toUpperCase().padEnd(8)} ${r.category.padEnd(22)} ${r.title}`);
  const body = [`agent-scan rule catalog (${rows.length} rules)`, '', ...rows].join('\n');
  if (opts.output) writeFileSync(opts.output, body + '\n');
  else process.stdout.write(body + '\n');
  return 0;
}

function mainProbe(rest) {
  const opts = { format: 'terminal', failOn: 'critical', timeout: 15000, color: true, quiet: false };
  const server = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (server.length) { server.push(a); continue; } // everything after the command belongs to the server
    switch (a) {
      case '-h': case '--help': process.stdout.write(HELP); return Promise.resolve(0);
      case '-f': case '--format': opts.format = rest[++i]; break;
      case '--json': opts.format = 'json'; break;
      case '--sarif': opts.format = 'sarif'; break;
      case '-o': case '--output': opts.output = rest[++i]; break;
      case '--fail-on': opts.failOn = rest[++i]; break;
      case '--timeout': opts.timeout = Number(rest[++i]) || 15000; break;
      case '--no-color': opts.color = false; break;
      case '-q': case '--quiet': opts.quiet = true; break;
      default:
        if (a.startsWith('-')) {
          process.stderr.write(`agent-scan probe: unknown option ${a} (server args must come after the command)\n`);
          return Promise.resolve(2);
        }
        server.push(a);
    }
  }
  if (!server.length) {
    process.stderr.write('agent-scan probe: usage: agent-scan probe [options] <command> [server args…]\n');
    return Promise.resolve(2);
  }
  if (!['terminal', 'json', 'sarif', 'md'].includes(opts.format)) {
    process.stderr.write(`agent-scan: bad --format "${opts.format}"\n`);
    return Promise.resolve(2);
  }

  const [cmd, ...cmdArgs] = server;
  process.stderr.write(
    `agent-scan probe: launching "${cmd}${cmdArgs.length ? ' ' + cmdArgs.join(' ') : ''}" locally for metadata capture only ` +
    '(initialize + tools/prompts/resources listing — no tool will ever be executed by this probe)\n');

  return probeScan(cmd, cmdArgs, { timeoutMs: opts.timeout }).then((result) => {
    const c = result.counts;
    let header = `probe target ${result.root} · ${result.capture.tools.length} tools · ` +
      `${result.capture.prompts.length} prompts · ${result.capture.resources.length} resources captured`;

    let body;
    if (opts.quiet && opts.format === 'terminal') {
      body = `${header}\nrisk ${result.riskScore}/100 · ${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low`;
    } else if (opts.format === 'json') {
      body = reportJson(result);
    } else if (opts.format === 'sarif') {
      body = reportSarif(result);
    } else if (opts.format === 'md') {
      body = reportMarkdown(result);
    } else {
      body = `${header}\n\n${reportTerminal(result, { noColor: !opts.color })}`;
    }

    if (opts.output) {
      writeFileSync(opts.output, body + '\n');
      if (opts.format === 'terminal') process.stdout.write(body + '\n');
      else process.stderr.write(`agent-scan: wrote ${opts.format} report to ${opts.output}\n`);
    } else {
      process.stdout.write(body + '\n');
    }

    const failed = shouldFail(result, opts.failOn);
    if (failed) {
      process.stderr.write(`agent-scan: failing as instructed — findings at or above "${opts.failOn}"\n`);
    }
    return failed ? 1 : 0;
  }).catch((err) => {
    process.stderr.write(`agent-scan probe failed: ${err.message}\n`);
    return 2;
  });
}
