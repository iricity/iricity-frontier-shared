import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { runConformance } from '../conformance/run.js';

test('reference implementation passes the published conformance vectors', () => {
  const report = runConformance();
  const failures = report.results.filter((r) => r.status !== 'passed');
  assert.equal(report.failed, 0, JSON.stringify(failures, null, 2));
  assert.equal(report.skipped, 0, JSON.stringify(failures, null, 2));
  assert.equal(report.conformant, true);
  assert.ok(report.passed >= 20);
});

test('a partial implementation is reported as skipped, a wrong one as failed', () => {
  const partial = runConformance({ canonicalJson: (v) => JSON.stringify(v) });
  assert.ok(partial.skipped > 0);
  assert.ok(partial.failed > 0, 'JSON.stringify without key sorting must fail the sorting vectors');
  assert.equal(partial.conformant, false);
});

test('the published vectors match their lock file byte for byte', () => {
  const CR = String.fromCharCode(13);
  const LF = String.fromCharCode(10);
  const text = fs
    .readFileSync(new URL('../conformance/vectors.json', import.meta.url), 'utf8')
    .split(CR + LF)
    .join(LF);
  const lock = JSON.parse(fs.readFileSync(new URL('../conformance/vectors.lock.json', import.meta.url), 'utf8'));
  assert.equal(
    createHash('sha256').update(text).digest('hex'),
    lock.sha256,
    'conformance/vectors.json changed without a new vectors version; run npm run conformance:build only for a new version'
  );
  assert.equal(JSON.parse(text).vectors_version, lock.vectors_version);
});
