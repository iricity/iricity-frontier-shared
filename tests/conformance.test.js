import test from 'node:test';
import assert from 'node:assert/strict';
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
