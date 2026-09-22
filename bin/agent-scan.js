#!/usr/bin/env node
import { main } from '../src/cli.js';

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  process.stderr.write(`agent-scan: ${err.stack ?? err.message}\n`);
  process.exitCode = 2;
}
