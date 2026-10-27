#!/usr/bin/env node
/**
 * Conformance runner.
 *
 * An implementation conforms when every suite passes and none is skipped. Supply an
 * object with the functions below, or run with no arguments to check the reference.
 *
 *   canonicalJson(value) -> string
 *   hashPayload(value) -> "sha256:<hex>"
 *   base58Encode(bytes) -> string
 *   base58Decode(text) -> bytes
 *   didFromPublicKeyBytes(bytes) -> "did:key:z6Mk…"
 *   publicKeyBytesFromDid(did) -> bytes
 *   signBytes(messageBytes, { private_key_seed_hex }) -> bytes
 *   createEnvelope({ payload, payload_type, signer, created_at, previous_envelope_hash, detached }) -> envelope
 *   verifyEnvelope(envelope, options) -> { verified }
 *   createReceiptRecord({ record, previous_hash, issuer, timestamp }) -> receipt
 *   verifyReceiptRecord(receipt, options) -> { verified }
 *   issueAuthorizationCredential({ authorization, issuer, created, id }) -> credential
 *   verifyCredential(credential, { at, expected_issuer }) -> { verified }
 *   credentialHashData(credential, proof) -> bytes
 *   verifyAuthorizationCredential(record, { at }) -> { verified, issuer }
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as reference from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));

export const SUITES = ['canonical_json', 'hash_payload', 'base58btc', 'did_key', 'ed25519', 'envelope', 'receipt', 'credential', 'rejections'];

export function loadVectors() {
  return JSON.parse(fs.readFileSync(path.join(here, 'vectors.json'), 'utf8'));
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function signerFor(v) {
  return { private_key_seed_hex: v.signer_seed_hex };
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
  const suite = (name) => {
    const cases = vectors[name];
    if (!Array.isArray(cases) || cases.length === 0) {
      record(name, '*', 'failed', `vectors file has no "${name}" suite`);
      return [];
    }
    return cases;
  };

  for (const v of suite('canonical_json')) {
    check('canonical_json', v.id, () => {
      if (!impl.canonicalJson) return 'skipped';
      const actual = impl.canonicalJson(v.input);
      if (actual !== v.expected_canonical) return `expected ${v.expected_canonical} got ${actual}`;
      if (!impl.hashPayload) return 'skipped';
      const hash = impl.hashPayload(v.input);
      return hash === v.expected_hash ? true : `hash mismatch: ${hash}`;
    });
  }

  for (const v of suite('hash_payload')) {
    check('hash_payload', v.id, () => {
      if (!impl.hashPayload) return 'skipped';
      const actual = impl.hashPayload(v.input);
      return actual === v.expected_hash ? true : `expected ${v.expected_hash} got ${actual}`;
    });
  }

  for (const v of suite('base58btc')) {
    check('base58btc', v.id, () => {
      if (!impl.base58Encode) return 'skipped';
      const encoded = impl.base58Encode(Buffer.from(v.input_hex, 'hex'));
      if (encoded !== v.expected) return `encode: expected ${v.expected} got ${encoded}`;
      if (!impl.base58Decode) return 'skipped';
      const decoded = hex(impl.base58Decode(v.expected));
      return decoded === v.input_hex ? true : `decode: expected ${v.input_hex} got ${decoded}`;
    });
  }

  for (const v of suite('did_key')) {
    check('did_key', v.expected_did, () => {
      if (!impl.didFromPublicKeyBytes) return 'skipped';
      const did = impl.didFromPublicKeyBytes(Buffer.from(v.public_key_hex, 'hex'));
      if (did !== v.expected_did) return `encode: expected ${v.expected_did} got ${did}`;
      if (!impl.publicKeyBytesFromDid) return 'skipped';
      const raw = hex(impl.publicKeyBytesFromDid(v.expected_did));
      return raw === v.public_key_hex ? true : `decode: expected ${v.public_key_hex} got ${raw}`;
    });
  }

  for (const v of suite('ed25519')) {
    check('ed25519', v.id, () => {
      if (!impl.signBytes) return 'skipped';
      const signature = impl.signBytes(Buffer.from(v.message_hex, 'hex'), { private_key_seed_hex: v.seed_hex });
      const actual = hex(signature);
      return actual === v.expected_signature_hex ? true : `signature mismatch: ${actual}`;
    });
  }

  for (const v of suite('envelope')) {
    check('envelope', v.id, () => {
      if (!impl.createEnvelope || !impl.verifyEnvelope) return 'skipped';
      const env = impl.createEnvelope({
        payload: v.payload,
        payload_type: v.payload_type,
        signer: signerFor(v),
        created_at: v.created_at,
        previous_envelope_hash: v.previous_envelope_hash,
        detached: Boolean(v.detached)
      });
      const e = v.expected;
      for (const field of ['signer', 'payload_hash', 'envelope_hash', 'envelope_id']) {
        if (env[field] !== e[field]) return `${field}: expected ${e[field]} got ${env[field]}`;
      }
      if (env.signature?.value !== e.signature_value) return `signature ${env.signature?.value}`;
      if (v.detached && env.payload !== undefined) return 'detached envelope must not carry a payload';
      const verification = v.detached ? impl.verifyEnvelope(env, { payload: v.payload }) : impl.verifyEnvelope(env);
      if (!verification.verified) return `self-verification failed: ${(verification.errors || []).join('; ')}`;
      if (v.detached && impl.verifyEnvelope(env).verified !== true) return 'detached envelope must verify without its payload';
      return true;
    });
  }

  for (const v of suite('receipt')) {
    check('receipt', v.id, () => {
      if (!impl.createReceiptRecord || !impl.verifyReceiptRecord) return 'skipped';
      if (v.legacy) {
        const verification = impl.verifyReceiptRecord(v.receipt, { record: v.record });
        return verification.verified === v.expected.verified ? true : `legacy: expected verified=${v.expected.verified} got ${verification.verified}: ${(verification.errors || []).join('; ')}`;
      }
      const receipt = impl.createReceiptRecord({
        record: v.record,
        previous_hash: v.previous_hash,
        issuer: v.signer_seed_hex ? signerFor(v) : v.issuer,
        timestamp: v.timestamp
      });
      const e = v.expected;
      for (const field of ['receipt_id', 'record_hash', 'previous_hash', 'receipt_hash', 'issuer', 'signature', 'signature_algorithm', 'verification_status']) {
        if (receipt[field] !== e[field]) return `${field}: expected ${e[field]} got ${receipt[field]}`;
      }
      const verification = impl.verifyReceiptRecord(receipt, { record: v.record });
      return verification.verified ? true : `self-verification failed: ${(verification.errors || []).join('; ')}`;
    });
  }

  for (const v of suite('credential')) {
    check('credential', v.id, () => {
      if (v.authorization_record) {
        if (!impl.verifyAuthorizationCredential) return 'skipped';
        const bound = impl.verifyAuthorizationCredential(v.authorization_record, { at: v.at });
        if (bound.verified !== v.expected.verified) return `expected verified=${v.expected.verified}: ${(bound.errors || []).join('; ')}`;
        if (bound.issuer !== v.expected.issuer) return `issuer: expected ${v.expected.issuer} got ${bound.issuer}`;
        return true;
      }
      if (!impl.issueAuthorizationCredential || !impl.verifyCredential || !impl.credentialHashData) return 'skipped';
      const credential = impl.issueAuthorizationCredential({ authorization: v.authorization, issuer: signerFor(v), created: v.created, id: v.credential_id });
      const e = v.expected;
      if (credential.id !== e.id) return `id: expected ${e.id} got ${credential.id}`;
      if (credential.issuer !== e.issuer) return `issuer: expected ${e.issuer} got ${credential.issuer}`;
      if (credential.proof?.verificationMethod !== e.verification_method) return `verificationMethod: ${credential.proof?.verificationMethod}`;
      if (credential.proof?.proofValue !== e.proof_value) return `proofValue: expected ${e.proof_value} got ${credential.proof?.proofValue}`;
      const hashData = hex(impl.credentialHashData(credential, credential.proof));
      if (hashData !== e.hash_data_hex) return `hash_data: expected ${e.hash_data_hex} got ${hashData}`;
      const canon = impl.canonicalJson || JSON.stringify;
      if (canon(credential.credentialSubject) !== canon(e.credential_subject)) return 'credentialSubject differs';
      const verification = impl.verifyCredential(credential, { at: v.at });
      return verification.verified ? true : `self-verification failed: ${(verification.errors || []).join('; ')}`;
    });
  }

  for (const v of suite('rejections')) {
    check('rejections', v.id, () => {
      if (v.kind === 'credential') {
        if (!impl.verifyCredential) return 'skipped';
        const verification = impl.verifyCredential(v.object, v.options || {});
        return verification.verified === false ? true : 'tampered credential was accepted';
      }
      if (v.kind === 'authorization') {
        if (!impl.verifyAuthorizationCredential) return 'skipped';
        const verification = impl.verifyAuthorizationCredential(v.object, v.options || {});
        return verification.verified === false ? true : 'unbound authorization was accepted';
      }
      if (v.kind === 'envelope') {
        if (!impl.verifyEnvelope) return 'skipped';
        const verification = impl.verifyEnvelope(v.object, v.options || {});
        return verification.verified === false ? true : 'tampered envelope was accepted';
      }
      if (v.kind === 'receipt') {
        if (!impl.verifyReceiptRecord) return 'skipped';
        const verification = impl.verifyReceiptRecord(v.object, v.options || {});
        return verification.verified === false ? true : 'tampered receipt was accepted';
      }
      return `unknown rejection kind ${v.kind}`;
    });
  }

  const passed = results.filter((r) => r.status === 'passed').length;
  const failed = results.filter((r) => r.status === 'failed').length;
  const skipped = results.filter((r) => r.status === 'skipped').length;

  return {
    vectors_version: vectors.vectors_version,
    conformant: failed === 0 && skipped === 0 && passed > 0,
    passed,
    failed,
    skipped,
    results
  };
}

export function formatReport(report) {
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
