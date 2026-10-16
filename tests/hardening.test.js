import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_DEPTH,
  canonicalJson,
  createEnvelope,
  createReceiptRecord,
  generateEd25519KeyPair,
  hashPayload,
  hashRecord,
  hashText,
  resolveSigner,
  verifyEnvelope,
  verifyReceiptChain,
  verifyReceiptRecord
} from '../src/index.js';

const record = { record_type: 'entity', entity_id: 'NODE-1', entity_type: 'node', created_at: '2026-01-01T00:00:00Z' };

test('hash references always cover canonical JSON', () => {
  assert.notEqual(hashPayload('hello'), hashText('hello'));
  assert.notEqual(hashPayload('{"a":1}'), hashPayload({ a: 1 }));
  assert.equal(hashRecord({ a: 1 }), hashPayload({ a: 1 }));
  assert.throws(() => hashPayload(Buffer.from([1, 2])), /binary/);
  assert.throws(() => canonicalJson(new Map()), /collections/);
  let nested = [];
  const root = nested;
  for (let i = 0; i < MAX_DEPTH + 5; i += 1) {
    const inner = [];
    nested.push(inner);
    nested = inner;
  }
  assert.throws(() => canonicalJson(root), /nesting deeper/);
});

test('verifiers never throw and reject every tampered form', () => {
  const pair = generateEd25519KeyPair();
  const payload = { a: 1 };
  const envelope = createEnvelope({ payload, payload_type: 'opaque.json/1', signer: pair });

  for (const bad of [null, 'text', 42, [], { ...envelope, signature: 'abc' }, { ...envelope, signature: ['x'] }]) {
    assert.equal(verifyEnvelope(bad).verified, false);
  }
  assert.equal(verifyEnvelope({ ...envelope, signature: { ...envelope.signature, value: `${envelope.signature.value}==` } }).verified, false);
  assert.equal(verifyEnvelope({ ...envelope, created_at: '2026-01-01T00:00:00+05:30' }).verified, false);
  assert.equal(verifyEnvelope({ ...envelope, envelope_id: `env_${'0'.repeat(24)}` }).verified, false);
  assert.equal(verifyEnvelope(envelope, { allowed_payload_types: 'opaque.json/1' }).verified, false);
  const noHash = { ...envelope };
  delete noHash.envelope_hash;
  assert.equal(verifyEnvelope(noHash).verified, false);
  assert.ok(verifyEnvelope(envelope).checks.includes('envelope_id_match'));

  const receipt = createReceiptRecord({ record, issuer: pair, timestamp: '2026-01-01T00:00:01Z' });
  for (const bad of [null, 'text', [], { ...receipt, receipt_version: 'state-receipt/9' }, { ...receipt, receipt_id: `rcp_${'0'.repeat(24)}` }]) {
    assert.equal(verifyReceiptRecord(bad).verified, false);
  }
  assert.equal(verifyReceiptRecord(receipt, { previous_receipt: 'x' }).verified, false);
  const stripped = { ...receipt, signature: null, signature_algorithm: 'none', key_id: null, verification_status: 'unsigned' };
  assert.equal(verifyReceiptRecord(stripped).verified, false, 'an unsigned receipt may not claim a did:key issuer');
  const noHashReceipt = { ...receipt };
  delete noHashReceipt.receipt_hash;
  assert.equal(verifyReceiptRecord(noHashReceipt).verified, false);
  assert.ok(verifyReceiptRecord(receipt, { record }).checks.includes('receipt_id_match'));
});

test('receipt creation refuses identities it cannot sign for and bad timestamps', () => {
  const pair = generateEd25519KeyPair();
  assert.throws(() => createReceiptRecord({ record, issuer: pair.did }), /did:key issuer/);
  assert.throws(() => createReceiptRecord({ record, issuer: pair, timestamp: 'yesterday' }), /timestamp/);
  assert.throws(() => createEnvelope({ payload: {}, payload_type: 'opaque.json/1', signer: pair, created_at: '2026-01-01T00:00:00+05:30' }), /created_at/);
  const unsigned = createReceiptRecord({ record, issuer: 'registry', timestamp: '2026-01-01T00:00:01Z' });
  assert.equal(verifyReceiptRecord({ ...unsigned, verification_status: 'issued' }).verified, false);
  assert.equal(verifyReceiptChain([unsigned], { expected_issuer: pair.did }).verified, false);
});

test('a hex seed string is accepted as a signer', () => {
  const pair = generateEd25519KeyPair();
  assert.equal(resolveSigner(pair.private_key_seed_hex).did, pair.did);
  assert.throws(() => resolveSigner('not a key'), /PEM|unsupported|key/i);
});
