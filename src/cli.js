import { writeFileSync } from 'node:fs';
import { scan, shouldFail } from './engine.js';
import { RULES } from './rules.js';
import { reportTerminal } from './reporters/terminal.js';
import { reportJson, reportSarif } from './reporters/json.js';
import { reportMarkdown } from './reporters/markdown.js';
import { SEVERITIES } from './util.js';

const HELP = `agent-scan — security scanner for the AI agent ecosystem
(npm audit for MCP servers, Agent Skills, AGENTS.md and agent tool code)

USAGE
  agent-scan [path]                    Scan a repo/dir/file (default: .)
  agent-scan --format json -o r.json   Machine-readable output
  agent-scan --sarif -o results.sarif  Upload to GitHub code scanning
  agent-scan --fail-on high            CI gate: exit 1 on high+ findings
  agent-scan --rules                   Print the rule catalog

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
  const opts = { path: '.', format: 'terminal', failOn: 'critical', ignore: [], color: true, quiet: false, includeAllMd: false };
  let showRules = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': process.stdout.write(HELP); return 0;
      case '-V': case '--version': process.stdout.write('agent-scan 0.1.0\n'); return 0;
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
