#!/usr/bin/env node
import { main } from '../src/cli.js';

Promise.resolve()
  .then(() => main(process.argv.slice(2)))
  .then((code) => {
    if (code !== undefined) process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`agent-scan: ${err.stack ?? err.message}\n`);
    process.exitCode = 2;
  });
