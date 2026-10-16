import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalJson,
  createEnvelope,
  didFromPublicKeyBytes,
  fingerprintDid,
  generateEd25519KeyPair,
  hashPayload,
  isDidKey,
  keyPairFromPrivateKeyPem,
  keyPairFromSeed,
  publicKeyBytesFromDid,
  resolveSigner,
  signBytes,
  verifyBytes,
  verifyEnvelope
} from '../src/index.js';

test('canonicalJson is RFC 8785 compatible and rejects non-JSON numbers', () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'x'] }), '{"a":[true,null,"x"],"b":1}');
  assert.equal(canonicalJson({ a: 1e21, b: -0, c: 0.1 }), '{"a":1e+21,"b":0,"c":0.1}');
  assert.equal(canonicalJson({ drop: undefined, keep: [undefined] }), '{"keep":[null]}');
  assert.equal(canonicalJson(new Date('2026-01-01T00:00:00Z')), '"2026-01-01T00:00:00.000Z"');
  assert.throws(() => canonicalJson({ n: Number.NaN }), /non-finite/);
  assert.throws(() => canonicalJson({ n: 10n }), /BigInt/);
});

test('key pairs round-trip through seed, PEM and did:key', () => {
  const pair = generateEd25519KeyPair();
  assert.ok(isDidKey(pair.did));
  assert.equal(keyPairFromSeed(pair.private_key_seed_hex).did, pair.did);
  assert.equal(keyPairFromPrivateKeyPem(pair.private_key_pem).did, pair.did);
  assert.equal(publicKeyBytesFromDid(pair.did).toString('hex'), pair.public_key_hex);
  assert.equal(didFromPublicKeyBytes(pair.public_key_hex), pair.did);
  assert.match(fingerprintDid(pair.did), /^fp_[0-9a-f]{20}$/);
});

test('resolveSigner accepts the supported shapes and rejects mismatched dids', () => {
  const pair = generateEd25519KeyPair();
  assert.equal(resolveSigner(pair).did, pair.did);
  assert.equal(resolveSigner({ private_key_seed_hex: pair.private_key_seed_hex }).did, pair.did);
  assert.equal(resolveSigner({ private_key_pem: pair.private_key_pem }).did, pair.did);
  assert.equal(resolveSigner(pair.private_key_pem).did, pair.did);
  const other = generateEd25519KeyPair();
  assert.throws(() => resolveSigner({ did: other.did, private_key: pair.private_key }), /does not match/);
});

test('signBytes and verifyBytes agree and reject tampering', () => {
  const pair = generateEd25519KeyPair();
  const signature = signBytes('hello', pair);
  assert.equal(verifyBytes('hello', signature, pair.did), true);
  assert.equal(verifyBytes('hellp', signature, pair.did), false);
  assert.equal(verifyBytes('hello', signature, generateEd25519KeyPair().did), false);
});

test('envelopes verify self-contained, detached, and detect tampering', () => {
  const pair = generateEd25519KeyPair();
  const payload = { NORAD_CAT_ID: 25544, EPOCH: '2026-01-01T00:00:00' };
  const envelope = createEnvelope({ payload, payload_type: 'ccsds.omm.json/1', signer: pair });

  assert.equal(envelope.signer, pair.did);
  assert.equal(envelope.payload_hash, hashPayload(payload));
  assert.deepEqual(envelope.payload, payload);

  const ok = verifyEnvelope(envelope);
  assert.equal(ok.verified, true, ok.errors.join(', '));
  assert.ok(ok.checks.includes('signature_valid'));

  const detached = createEnvelope({ payload, payload_type: 'ccsds.omm.json/1', signer: pair, detached: true });
  assert.equal(detached.payload, undefined);
  assert.equal(verifyEnvelope(detached).verified, true);
  assert.equal(verifyEnvelope(detached, { payload }).verified, true);
  assert.equal(verifyEnvelope(detached, { payload: { ...payload, EPOCH: 'x' } }).verified, false);

  const tampered = { ...envelope, payload: { ...payload, NORAD_CAT_ID: 1 } };
  assert.equal(verifyEnvelope(tampered).verified, false);

  const resigned = { ...envelope, signer: generateEd25519KeyPair().did };
  assert.equal(verifyEnvelope(resigned).verified, false);

  assert.equal(verifyEnvelope(envelope, { expected_signer: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' }).verified, false);
  assert.equal(verifyEnvelope(envelope, { allowed_payload_types: ['opaque.json/1'] }).verified, false);
});

test('envelope chaining references the previous envelope hash', () => {
  const pair = generateEd25519KeyPair();
  const first = createEnvelope({ payload: { n: 1 }, payload_type: 'opaque.json/1', signer: pair });
  const second = createEnvelope({ payload: { n: 2 }, payload_type: 'opaque.json/1', signer: pair, previous_envelope_hash: first.envelope_hash });
  assert.equal(second.previous_envelope_hash, first.envelope_hash);
  assert.equal(verifyEnvelope(second).verified, true);
  assert.throws(() => createEnvelope({ payload: {}, payload_type: 'opaque.json/1', signer: pair, previous_envelope_hash: 'nope' }), /sha256/);
});
