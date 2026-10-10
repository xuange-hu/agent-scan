/**
 * Rule-registry integrity tests.
 *
 * These guarantee the catalog stays internally consistent as rules are added
 * or renamed — a broken id would otherwise fail silently at report time.
 * Run with: node --test tests/registry.test.js
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RULES, ruleMeta } from '../src/rules.js';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const CATEGORIES = new Set([
  'prompt-injection',
  'injection',
  'data-exfiltration',
  'dangerous-execution',
  'excessive-agency',
  'obfuscation',
  'secrets',
  'ssrf',
  'supply-chain',
  'tool-poisoning',
  'transport-security',
]);

test('RULES is a non-empty catalog', () => {
  const ids = Object.keys(RULES);
  assert.ok(ids.length >= 30, `expected >=30 rules, got ${ids.length}`);
});

test('every rule id is unique, well-formed and lookupable', () => {
  const seen = new Set();
  for (const id of Object.keys(RULES)) {
    assert.match(id, /^AS-[PMSTN]\d{3}$/, `rule id shape: ${id}`);
    assert.ok(!seen.has(id), `duplicate rule id: ${id}`);
    seen.add(id);
    // ruleMeta must round-trip
    assert.equal(ruleMeta(id).title, RULES[id].title);
  }
});

test('every rule carries the required fields', () => {
  for (const [id, r] of Object.entries(RULES)) {
    assert.ok(r.title, `${id} missing title`);
    assert.ok(r.description, `${id} missing description`);
    assert.ok(r.remediation, `${id} missing remediation`);
    assert.ok(SEVERITIES.has(r.severity), `${id} bad severity: ${r.severity}`);
    assert.ok(CATEGORIES.has(r.category), `${id} bad category: ${r.category}`);
  }
});

test('severity distribution is sane (not everything critical)', () => {
  const counts = {};
  for (const r of Object.values(RULES)) {
    counts[r.severity] = (counts[r.severity] || 0) + 1;
  }
  assert.ok((counts.critical || 0) < Object.keys(RULES).length, 'every rule is critical?');
  assert.ok((counts.low || 0) + (counts.info || 0) > 0, 'no low/info rules');
});
