#!/usr/bin/env node
/**
 * Conformance runner.
 *
 * Any implementation can prove compatibility by passing these vectors. Supply an
 * object with the functions below (all optional; missing ones are reported as
 * skipped), or run with no arguments to check the reference implementation.
 *
 *   canonicalJson(value) -> string
 *   hashPayload(value) -> "sha256:<hex>"
 *   base58Encode(bytes) -> string
 *   didFromPublicKeyBytes(bytes) -> "did:key:z6Mk…"
 *   signBytes(messageBytes, { private_key_seed_hex }) -> bytes
 *   createEnvelope({ payload, payload_type, signer, created_at, previous_envelope_hash }) -> envelope
 *   verifyEnvelope(envelope) -> { verified }
 *   createReceiptRecord({ record, previous_hash, issuer, timestamp }) -> receipt
 *   verifyReceiptRecord(receipt) -> { verified }
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as reference from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export function loadVectors() {
  return JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8'));
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

export function runConformance(impl = reference, vectors = loadVectors()) {
  const results = [];
  const record = (suite, id, status, detail = null) => {
    results.push({ suite, id, status, ...(detail ? { detail } : {}) });
  };
  const check = (suite, id, fn) => {
    try {
      const outcome = fn();
      if (outcome === 'skipped') record(suite, id, 'skipped');
      else if (outcome === true) record(suite, id, 'passed');
      else record(suite, id, 'failed', typeof outcome === 'string' ? outcome : 'mismatch');
    } catch (error) {
      record(suite, id, 'failed', error?.message || String(error));
    }
  };

  for (const v of vectors.canonical_json) {
    check('canonical_json', v.id, () => {
      if (!impl.canonicalJson) return 'skipped';
      const actual = impl.canonicalJson(v.input);
      if (actual !== v.expected_canonical) return `expected ${v.expected_canonical} got ${actual}`;
      if (impl.hashPayload && impl.hashPayload(v.input) !== v.expected_hash) return 'hash mismatch';
      return true;
    });
  }

  for (const v of vectors.base58btc) {
    check('base58btc', v.input_hex || 'empty', () => {
      if (!impl.base58Encode) return 'skipped';
      const actual = impl.base58Encode(Buffer.from(v.input_hex, 'hex'));
      return actual === v.expected ? true : `expected ${v.expected} got ${actual}`;
    });
  }

  for (const v of vectors.did_key) {
    check('did_key', v.expected_did, () => {
      if (!impl.didFromPublicKeyBytes) return 'skipped';
      const actual = impl.didFromPublicKeyBytes(Buffer.from(v.public_key_hex, 'hex'));
      return actual === v.expected_did ? true : `expected ${v.expected_did} got ${actual}`;
    });
  }

  for (const v of vectors.ed25519) {
    check('ed25519', v.id, () => {
      if (!impl.signBytes) return 'skipped';
      const signature = impl.signBytes(Buffer.from(v.message_hex, 'hex'), { private_key_seed_hex: v.seed_hex });
      const actual = hex(signature);
      return actual === v.expected_signature_hex ? true : `signature mismatch: ${actual}`;
    });
  }

  for (const v of vectors.envelope) {
    check('envelope', v.id, () => {
      if (!impl.createEnvelope) return 'skipped';
      const env = impl.createEnvelope({
        payload: v.payload,
        payload_type: v.payload_type,
        signer: { private_key_seed_hex: v.signer_seed_hex },
        created_at: v.created_at,
        previous_envelope_hash: v.previous_envelope_hash
      });
      const e = v.expected;
      if (env.signer !== e.signer) return `signer ${env.signer}`;
      if (env.payload_hash !== e.payload_hash) return `payload_hash ${env.payload_hash}`;
      if (env.envelope_hash !== e.envelope_hash) return `envelope_hash ${env.envelope_hash}`;
      if (env.envelope_id !== e.envelope_id) return `envelope_id ${env.envelope_id}`;
      if (env.signature?.value !== e.signature_value) return `signature ${env.signature?.value}`;
      if (impl.verifyEnvelope && !impl.verifyEnvelope(env).verified) return 'self-verification failed';
      return true;
    });
  }

  for (const v of vectors.receipt) {
    check('receipt', v.id, () => {
      if (!impl.createReceiptRecord) return 'skipped';
      const receipt = impl.createReceiptRecord({
        record: v.record,
        previous_hash: v.previous_hash,
        issuer: v.signer_seed_hex ? { private_key_seed_hex: v.signer_seed_hex } : v.issuer,
        timestamp: v.timestamp
      });
      const e = v.expected;
      for (const field of ['receipt_id', 'record_hash', 'previous_hash', 'receipt_hash', 'issuer', 'signature', 'signature_algorithm']) {
        if (receipt[field] !== e[field]) return `${field}: expected ${e[field]} got ${receipt[field]}`;
      }
      if (impl.verifyReceiptRecord && !impl.verifyReceiptRecord(receipt, { record: v.record }).verified) {
        return 'self-verification failed';
      }
      return true;
    });
  }

  const passed = results.filter((r) => r.status === 'passed').length;
  const failed = results.filter((r) => r.status === 'failed').length;
  const skipped = results.filter((r) => r.status === 'skipped').length;

  return {
    vectors_version: vectors.vectors_version,
    conformant: failed === 0 && passed > 0,
    passed,
    failed,
    skipped,
    results
  };
}

function formatReport(report) {
  const lines = [`conformance vectors ${report.vectors_version}: ${report.passed} passed, ${report.failed} failed, ${report.skipped} skipped`];
  for (const r of report.results) {
    if (r.status !== 'passed') lines.push(`  [${r.status}] ${r.suite}/${r.id}${r.detail ? `: ${r.detail}` : ''}`);
  }
  lines.push(report.conformant ? 'RESULT: conformant' : 'RESULT: not conformant');
  return lines.join('\n');
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  const report = runConformance();
  process.stdout.write(`${formatReport(report)}\n`);
  process.exit(report.conformant ? 0 : 1);
}
