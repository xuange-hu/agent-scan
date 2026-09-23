#!/usr/bin/env node
/**
 * Top-100 MCP package security scan.
 *
 * Pipeline: npm search (mcp) -> rank by last-week downloads -> download
 * tarballs -> extract -> scan each with agent-scan -> aggregate stats.
 *
 * Output: .scan-cache/results.json + printed summary.
 * Usage:  node scripts/scan-top100.js [--limit 100] [--concurrency 8]
 *
 * Honest-by-design: results are pattern-based signals for human review,
 * not vulnerability disclosures. The report generator filters/verifies.
 */
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { scan } from '../src/engine.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CACHE = join(ROOT, '.scan-cache');
const PKGS = join(CACHE, 'packages');

const args = process.argv.slice(2);
const argVal = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? Number(args[i + 1]) : dflt;
};
const LIMIT = argVal('--limit', 100);
const CONCURRENCY = argVal('--concurrency', 8);

mkdirSync(PKGS, { recursive: true });

async function getJson(url, tries = 3) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url);
      if (res.status === 429) {
        await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
        continue;
      }
      if (!res.ok) throw new Error(`${res.status} ${url}`);
      return await res.json();
    } catch (e) {
      if (i === tries - 1) throw e;
      await new Promise((r) => setTimeout(r, 500 * (i + 1)));
    }
  }
}

async function searchMcpPackages() {
  const seen = new Map();
  for (const term of ['mcp', 'modelcontextprotocol', 'mcp server', 'mcp-server', 'mcp tools', 'claude mcp', 'mcp client', 'mcp bridge']) {
    const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(term)}&size=250`;
    try {
      const data = await getJson(url);
      for (const obj of data.objects) {
        const name = obj.package.name;
        if (seen.has(name)) continue;
        const desc = `${obj.package.description ?? ''} ${name}`.toLowerCase();
        if (!/\bmcp\b|modelcontextprotocol/.test(desc)) continue;
        seen.set(name, { name, version: obj.package.version, publisher: obj.package.publisher?.username ?? '', date: obj.package.date });
      }
    } catch (e) {
      console.error(`search "${term}" failed: ${e.message}`);
    }
  }
  return [...seen.values()];
}

async function weeklyDownloads(name) {
  try {
    const data = await getJson(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`);
    return data.downloads ?? 0;
  } catch {
    return 0;
  }
}

async function mapPool(items, size, fn) {
  const out = [];
  let i = 0;
  const workers = Array.from({ length: size }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}

async function downloadAndScan(meta) {
  const slug = meta.name.replace(/[/@]/g, '_');
  const dir = join(PKGS, slug);
  const tgz = dir + '.tgz';
  try {
    if (!existsSync(tgz)) {
      const full = await getJson(`https://registry.npmjs.org/${encodeURIComponent(meta.name)}/${meta.version}`);
      const res = await fetch(full.dist.tarball);
      if (!res.ok) throw new Error(`tarball ${res.status}`);
      await pipeline(res.body, createWriteStream(tgz));
    }
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    // relative paths + cwd: Git-Bash GNU tar treats "C:\..." as host:C: remote archive
    execFileSync('tar', ['-xzf', `${slug}.tgz`, '--strip-components=1', '-C', slug], { cwd: PKGS, stdio: 'ignore' });
    const result = scan(dir);
    return {
      name: meta.name,
      version: meta.version,
      downloads: meta.downloads,
      filesScanned: result.filesScanned,
      riskScore: result.riskScore,
      counts: result.counts,
      findings: result.findings.map((f) => ({ ...f, file: f.file })),
    };
  } catch (err) {
    return { name: meta.name, version: meta.version, downloads: meta.downloads, error: String(err.message ?? err) };
  }
}

console.log('searching npm for MCP packages…');
let candidates = await searchMcpPackages();
console.log(`${candidates.length} unique MCP-related packages`);

console.log('fetching weekly download counts…');
await mapPool(candidates, 16, async (c) => { c.downloads = await weeklyDownloads(c.name); });
candidates = candidates.filter((c) => c.downloads > 0);
candidates.sort((a, b) => b.downloads - a.downloads);
const top = candidates.slice(0, LIMIT);
console.log(`scanning top ${top.length} by last-week downloads…`);

const results = [];
let done = 0;
await mapPool(top, CONCURRENCY, async (meta) => {
  const r = await downloadAndScan(meta);
  results.push(r);
  done++;
  if (done % 10 === 0) console.log(`  ${done}/${top.length}`);
});

results.sort((a, b) => b.downloads - a.downloads);
const summary = {
  generatedAt: new Date().toISOString(),
  scanned: results.filter((r) => !r.error).length,
  failed: results.filter((r) => r.error).length,
  withFindings: results.filter((r) => !r.error && r.findings.length > 0).length,
  ruleCounts: {},
  groupCounts: { P: 0, M: 0, S: 0, N: 0 },
  results,
};
for (const r of summary.results) {
  for (const f of r.findings ?? []) {
    summary.ruleCounts[f.ruleId] = (summary.ruleCounts[f.ruleId] ?? 0) + 1;
    const g = f.ruleId.slice(3, 4);
    if (summary.groupCounts[g] != null) summary.groupCounts[g]++;
  }
}

const { writeFileSync } = await import('node:fs');
writeFileSync(join(CACHE, 'results.json'), JSON.stringify(summary, null, 2));
console.log(`\nwrote .scan-cache/results.json`);
console.log(`scanned: ${summary.scanned} ok, ${summary.failed} failed`);
console.log(`packages with >=1 signal: ${summary.withFindings} (${Math.round((summary.withFindings / summary.scanned) * 100)}%)`);
console.log('rule histogram:', Object.entries(summary.ruleCounts).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}:${v}`).join(' '));
