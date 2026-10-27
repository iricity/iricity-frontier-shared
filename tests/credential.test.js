import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  canonicalJson,
  createAuthorizationRecord,
  createRegulatorIssuedAuthorization,
  credentialHashData,
  generateEd25519KeyPair,
  issueAuthorizationCredential,
  keyPairFromSeed,
  verifyAuthorizationCredential,
  verifyCredential
} from '../src/index.js';

const REGULATOR = keyPairFromSeed('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const LICENCE = {
  subject_id: 'station_vu2abc',
  capability: 'transmit',
  scope: 'amateur_general_grade',
  jurisdiction: 'IN',
  bands: [{ lower_hz: 144000000, upper_hz: 146000000, service: 'amateur' }, { lower_hz: 434000000, upper_hz: 438000000, service: 'amateur' }],
  max_eirp_dbw: 20,
  location: { latitude: 28.6139, longitude: 77.209, radius_km: 1 },
  license_reference: 'ASOC/EXAMPLE/0001',
  valid_from: '2026-01-01T00:00:00.000Z',
  valid_until: '2031-01-01T00:00:00.000Z'
};

test('a credential is a VC 2.0 document with an eddsa-jcs-2022 Data Integrity proof over JCS canonical form', () => {
  const credential = issueAuthorizationCredential({ authorization: LICENCE, issuer: REGULATOR, created: '2026-01-01T00:00:00.000Z' });
  assert.deepEqual(credential['@context'], ['https://www.w3.org/ns/credentials/v2', { '@vocab': 'urn:frontier-state-protocol:vocab:authorization#' }]);
  assert.deepEqual(credential.type, ['VerifiableCredential', 'SpectrumAuthorizationCredential']);
  assert.equal(credential.issuer, REGULATOR.did);
  assert.match(credential.id, /^urn:frontier-state-protocol:credential:[0-9a-f]{32}$/);
  assert.equal(credential.credentialSubject.id, 'station_vu2abc');
  assert.deepEqual(credential.credentialSubject.bands, LICENCE.bands);
  assert.equal(credential.validFrom, LICENCE.valid_from);
  assert.equal(credential.validUntil, LICENCE.valid_until);
  assert.equal(credential.proof.type, 'DataIntegrityProof');
  assert.equal(credential.proof.cryptosuite, 'eddsa-jcs-2022');
  assert.equal(credential.proof.proofPurpose, 'assertionMethod');
  assert.equal(credential.proof.verificationMethod, `${REGULATOR.did}#${REGULATOR.did.slice(8)}`);
  assert.match(credential.proof.proofValue, /^z[1-9A-HJ-NP-Za-km-z]{80,96}$/);

  // The hash input is the cryptosuite's: sha256(proof config with the document context) || sha256(unsecured document).
  const { proof, ...unsecured } = credential;
  const { proofValue, ...config } = proof;
  const expected = Buffer.concat([
    createHash('sha256').update(canonicalJson({ ...config, '@context': unsecured['@context'] })).digest(),
    createHash('sha256').update(canonicalJson(unsecured)).digest()
  ]);
  assert.equal(credentialHashData(credential, proof).toString('hex'), expected.toString('hex'));

  // Deterministic for a fixed creation time and fixed key.
  const again = issueAuthorizationCredential({ authorization: LICENCE, issuer: REGULATOR, created: '2026-01-01T00:00:00.000Z' });
  assert.deepEqual(again, credential);
});

test('credentials verify, and every tampering or substitution is refused without throwing', () => {
  const credential = issueAuthorizationCredential({ authorization: LICENCE, issuer: REGULATOR, created: '2026-01-01T00:00:00.000Z' });
  const ok = verifyCredential(credential, { at: '2027-06-01T00:00:00Z', expected_issuer: REGULATOR.did });
  assert.equal(ok.verified, true, ok.errors.join('; '));
  assert.deepEqual(ok.checks, ['context_v2', 'type_verifiable_credential', 'issuer_did_key', 'issuer_match', 'subject_present', 'verification_method_bound', 'proof_value_decoded', 'signature_valid', 'within_validity']);

  const cases = [
    [{ ...credential, credentialSubject: { ...credential.credentialSubject, max_eirp_dbw: 30 } }, /signature does not verify/],
    [{ ...credential, issuer: generateEd25519KeyPair().did }, /verificationMethod/],
    [{ ...credential, proof: { ...credential.proof, proofValue: 'z' + credential.proof.proofValue.slice(2) } }, /not an ed25519 signature|does not verify/],
    [{ ...credential, proof: { ...credential.proof, cryptosuite: 'eddsa-rdfc-2022' } }, /cryptosuite/],
    [{ ...credential, proof: { ...credential.proof, proofPurpose: 'authentication' } }, /proofPurpose/],
    [{ ...credential, proof: { ...credential.proof, created: '2026-01-01T00:00:00+05:30' } }, /proof.created/],
    [{ ...credential, '@context': ['https://www.w3.org/2018/credentials/v1'] }, /@context/],
    [{ ...credential, type: ['SpectrumAuthorizationCredential'] }, /VerifiableCredential/],
    [{ ...credential, proof: undefined }, /proof is required/],
    ['text', /must be an object/],
    [null, /must be an object/]
  ];
  for (const [input, pattern] of cases) {
    const result = verifyCredential(input, { at: '2027-06-01T00:00:00Z' });
    assert.equal(result.verified, false);
    assert.ok(result.errors.some((e) => pattern.test(e)), `${pattern}: ${result.errors.join('; ')}`);
  }

  assert.match(verifyCredential(credential, { at: '2025-12-31T00:00:00Z' }).errors[0], /not valid before/);
  assert.match(verifyCredential(credential, { at: '2031-01-02T00:00:00Z' }).errors[0], /expired/);
  assert.match(verifyCredential(credential, { at: '2027-01-01T00:00:00Z', expected_issuer: generateEd25519KeyPair().did }).errors[0], /not the expected/);
  assert.throws(() => issueAuthorizationCredential({ authorization: LICENCE, issuer: REGULATOR, created: '2026-01-01T00:00:00+05:30' }), /Z suffix/);
  assert.throws(() => issueAuthorizationCredential({ authorization: { capability: 'transmit' }, issuer: REGULATOR }), /subject_id/);
});

test('a regulator-issued authorization binds the record to its credential: same issuer, same subject, same fields', () => {
  const record = createRegulatorIssuedAuthorization({ ...LICENCE, regulator: REGULATOR, created: '2026-01-01T00:00:00.000Z' });
  assert.equal(record.record_type, 'authorization');
  assert.equal(record.profile, 'regulator_issued');
  assert.equal(record.controller_id, REGULATOR.did);
  assert.match(record.authorization_id, /^auth_[0-9a-f]{24}$/);
  assert.equal(record.proof.credentialSubject.id, 'station_vu2abc');

  const ok = verifyAuthorizationCredential(record, { at: '2028-01-01T00:00:00Z' });
  assert.equal(ok.verified, true, ok.errors.join('; '));
  assert.ok(ok.checks.includes('controller_is_issuer'));
  assert.ok(ok.checks.includes('fields_match'));
  assert.equal(ok.issuer, REGULATOR.did);

  // Changing the record after issue breaks the binding, in either direction.
  assert.match(verifyAuthorizationCredential({ ...record, bands: [record.bands[0]] }).errors.join('; '), /bands does not match/);
  assert.match(verifyAuthorizationCredential({ ...record, subject_id: 'station_other' }).errors.join('; '), /not the authorization subject/);
  assert.match(verifyAuthorizationCredential({ ...record, controller_id: generateEd25519KeyPair().did }).errors.join('; '), /not the expected/);
  assert.match(verifyAuthorizationCredential({ ...record, controller_id: 'regulator_name' }).errors.join('; '), /controller_id must be the issuing authority/);
  assert.match(verifyAuthorizationCredential({ ...record, valid_until: '2032-01-01T00:00:00.000Z' }).errors.join('; '), /validUntil/);
  const revoked = verifyAuthorizationCredential({ ...record, revoked: true }, { at: '2028-01-01T00:00:00Z' });
  assert.equal(revoked.verified, true, 'a revoked licence still carries an authentic credential');
  assert.equal(revoked.revoked, true);
  assert.equal(ok.revoked, false);
  assert.match(verifyAuthorizationCredential({ ...record, proof: { ...record.proof, credentialSubject: { ...record.proof.credentialSubject, max_eirp_dbw: 40 } } }).errors.join('; '), /does not verify/);

  // A self-declared record has no credential to verify, and says so without throwing.
  const selfDeclared = createAuthorizationRecord({ subject_id: 's', controller_id: 'c', capability: 'receive' });
  assert.match(verifyAuthorizationCredential(selfDeclared).errors[0], /must carry a verifiable credential/);
  assert.equal(verifyAuthorizationCredential(null).verified, false);

  // A credential can also be issued from an existing record and attached by hand.
  const fields = { subject_id: 'station_vu2xyz', capability: 'receive', jurisdiction: 'IN', valid_from: '2026-01-01T00:00:00.000Z' };
  const credential = issueAuthorizationCredential({ authorization: fields, issuer: REGULATOR, created: '2026-01-01T00:00:00.000Z' });
  const attached = createAuthorizationRecord({ ...fields, controller_id: REGULATOR.did, profile: 'regulator_issued', proof: credential });
  assert.equal(verifyAuthorizationCredential(attached, { at: '2026-06-01T00:00:00Z' }).verified, true);
});
