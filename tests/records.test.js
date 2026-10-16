import test from 'node:test';
import assert from 'node:assert/strict';
import {
  authorizationIsCurrent,
  buildStateBridgeArtifact,
  createAuthorizationRecord,
  createIdentityRecord,
  createReceiptRecord,
  generateEd25519KeyPair,
  hashRecord,
  sha256Hex,
  verifyReceiptChain,
  verifyReceiptRecord
} from '../src/index.js';

const record = { record_type: 'entity', entity_id: 'NODE-1', entity_type: 'node', created_at: '2026-01-01T00:00:00Z' };

test('signed receipts verify, chain, and detect tampering', () => {
  const issuer = generateEd25519KeyPair();
  const first = createReceiptRecord({ record, issuer, timestamp: '2026-01-01T00:00:01Z' });
  assert.equal(first.signature_algorithm, 'ed25519');
  assert.equal(first.issuer, issuer.did);
  assert.equal(first.record_hash, hashRecord(record));
  assert.equal(first.previous_hash, null);
  assert.equal(first.verification_status, 'issued');

  const ok = verifyReceiptRecord(first, { record });
  assert.equal(ok.verified, true, ok.errors.join(', '));
  assert.ok(ok.checks.includes('signature_valid'));
  assert.ok(ok.checks.includes('record_hash_match'));

  const second = createReceiptRecord({ record: { ...record, status: 'active' }, previous_hash: first.receipt_hash, issuer, timestamp: '2026-01-01T00:00:02Z' });
  const chain = verifyReceiptChain([first, second], { require_genesis: true, expected_issuer: issuer.did });
  assert.equal(chain.verified, true, chain.errors.join(', '));
  assert.equal(chain.head, second.receipt_hash);

  const broken = verifyReceiptChain([second, first]);
  assert.equal(broken.verified, false);

  const tampered = { ...first, record_hash: hashRecord({ ...record, entity_id: 'NODE-2' }) };
  assert.equal(verifyReceiptRecord(tampered).verified, false);

  const impostor = { ...first, issuer: generateEd25519KeyPair().did, key_id: undefined };
  assert.equal(verifyReceiptRecord(impostor).verified, false);
});

test('unsigned receipts are explicit about carrying no identity', () => {
  const receipt = createReceiptRecord({ record, issuer: 'iricity-state-stack', timestamp: '2026-01-01T00:00:01Z' });
  assert.equal(receipt.signature_algorithm, 'none');
  assert.equal(receipt.verification_status, 'unsigned');
  const result = verifyReceiptRecord(receipt, { record });
  assert.equal(result.verified, true);
  assert.equal(result.identity_bound, false);
});

test('legacy sha256 chain receipts still verify', () => {
  const legacy = {
    record_type: 'receipt',
    receipt_id: 'rcp_legacy',
    record_hash: hashRecord(record),
    previous_hash: null,
    timestamp: '2026-01-01T00:00:00Z',
    issuer: 'iricity-state-stack',
    signature: null,
    signature_algorithm: 'sha256_chain_legacy'
  };
  legacy.signature = sha256Hex([legacy.record_hash, '', legacy.issuer, legacy.timestamp].join('|'));
  const result = verifyReceiptRecord(legacy);
  assert.equal(result.verified, true, result.errors.join(', '));
  assert.ok(result.checks.includes('legacy_chain_digest_match'));
});

test('identity records derive the public key from the did', () => {
  const pair = generateEd25519KeyPair();
  const identity = createIdentityRecord({
    entity_id: 'node_zone_001_delhi',
    identity_type: 'node',
    did: pair.did,
    controller_id: 'org_example',
    created_at: '2026-01-01T00:00:00Z'
  });
  assert.equal(identity.record_type, 'entity');
  assert.equal(identity.entity_type, 'node');
  assert.equal(identity.public_key_multibase, pair.public_key_multibase);
  assert.throws(() => createIdentityRecord({ entity_id: 'x', identity_type: 'spaceship' }), /identity_type/);
  assert.throws(() => createIdentityRecord({ entity_id: 'x', identity_type: 'node', did: 'did:web:example.com' }), /did:key/);
});

test('authorization records enforce the license-shaped fields', () => {
  const receiveOnly = createAuthorizationRecord({
    subject_id: 'node_zone_001_delhi',
    controller_id: 'org_example',
    capability: 'receive',
    jurisdiction: 'IN',
    location: { latitude: 28.6139, longitude: 77.209, radius_km: 25 },
    valid_from: '2026-01-01T00:00:00Z'
  });
  assert.equal(receiveOnly.record_type, 'authorization');
  assert.equal(receiveOnly.profile, 'self_declared');
  assert.match(receiveOnly.authorization_id, /^auth_[0-9a-f]{24}$/);
  assert.equal(authorizationIsCurrent(receiveOnly, '2026-06-01T00:00:00Z'), true);
  assert.equal(authorizationIsCurrent({ ...receiveOnly, revoked: true }), false);
  assert.equal(authorizationIsCurrent({ ...receiveOnly, valid_until: '2026-02-01T00:00:00Z' }, '2026-06-01T00:00:00Z'), false);

  assert.throws(() => createAuthorizationRecord({ subject_id: 'n', controller_id: 'o', capability: 'transmit', jurisdiction: 'IN' }), /band/);
  assert.throws(() => createAuthorizationRecord({ subject_id: 'n', controller_id: 'o', capability: 'receive', jurisdiction: 'India' }), /ISO 3166/);
  assert.throws(() => createAuthorizationRecord({ subject_id: 'n', controller_id: 'o', capability: 'fly' }), /capability/);

  const amateur = createAuthorizationRecord({
    subject_id: 'node_zone_001_delhi',
    controller_id: 'org_example',
    capability: 'transmit',
    profile: 'regulator_issued',
    jurisdiction: 'IN',
    bands: [{ lower_hz: 144e6, upper_hz: 146e6, service: 'amateur' }],
    max_eirp_dbw: 10,
    license_reference: 'callsign-placeholder'
  });
  assert.equal(amateur.bands.length, 1);
});

test('bridge artifacts carry a protocol receipt, signed when a signer is given', () => {
  const event = {
    event_id: 'evt_1',
    source: 'mock',
    event_type: 'space_observation',
    timestamp: '2026-01-01T00:00:00Z',
    payload: { hello: 'world' },
    payload_hash: 'sha256:abc'
  };
  const unsigned = buildStateBridgeArtifact({ event, analysis: { analysis_id: 'ana_1' }, receipt: { receipt_id: 'rcp_1', receipt_hash: 'prev' }, run: { completed_at: '2026-01-01T00:00:01Z' } });
  assert.equal(unsigned.receipt.signature_algorithm, 'none');
  assert.equal(unsigned.receipt.previous_hash, null);
  assert.equal(unsigned.receipt.linked_receipt_id, 'rcp_1');
  assert.equal(verifyReceiptRecord(unsigned.receipt, { record: unsigned.conversion_record }).verified, true);

  const signer = generateEd25519KeyPair();
  const signed = buildStateBridgeArtifact({ event, analysis: null, receipt: null, run: { completed_at: '2026-01-01T00:00:01Z' }, signer });
  assert.equal(signed.receipt.signature_algorithm, 'ed25519');
  assert.equal(signed.receipt.issuer, signer.did);
  assert.equal(verifyReceiptRecord(signed.receipt, { record: signed.conversion_record }).verified, true);
});
