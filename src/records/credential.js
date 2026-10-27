/**
 * Regulator-issued authorizations: a W3C Verifiable Credential (Data Model 2.0)
 * carried in the authorization record's `proof`, secured with a Data Integrity
 * proof using the `eddsa-jcs-2022` cryptosuite.
 *
 * That cryptosuite canonicalises with JCS (RFC 8785), which is the protocol's own
 * canonical form, so no RDF or JSON-LD processing is needed to issue or verify:
 *
 *   hashData   = sha256(canonical(proofConfig)) || sha256(canonical(document without proof))
 *   proofValue = multibase base58btc of ed25519(hashData)
 *
 * The issuer is a did:key; the verification method is that DID with its own key
 * fragment. Verification never throws: it returns a result with errors and checks.
 */

import { createHash } from 'node:crypto';
import { canonicalJson } from '../utils/canonicalJson.js';
import { hashPayload } from '../utils/hash.js';
import { multibaseDecodeBase58btc, multibaseEncodeBase58btc } from '../utils/base58.js';
import { isDidKey, resolveSigner, signBytes, verifyBytes } from '../crypto/keys.js';
import { TIMESTAMP_PATTERN } from '../crypto/envelope.js';

export const CREDENTIAL_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';
export const AUTHORIZATION_VOCAB = 'urn:frontier-state-protocol:vocab:authorization#';
export const AUTHORIZATION_CREDENTIAL_TYPE = 'SpectrumAuthorizationCredential';
export const DATA_INTEGRITY_PROOF = 'DataIntegrityProof';
export const CRYPTOSUITE = 'eddsa-jcs-2022';
export const PROOF_PURPOSE = 'assertionMethod';

/** The authorization fields a credential attests, in the order they are compared. */
export const CREDENTIAL_SUBJECT_FIELDS = ['capability', 'scope', 'jurisdiction', 'bands', 'max_eirp_dbw', 'location', 'license_reference'];

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** The Data Integrity hash input for eddsa-jcs-2022: proof-config hash followed by document hash. */
export function credentialHashData(document, proofConfig) {
  const { proof, ...unsecured } = document;
  const config = { ...proofConfig };
  delete config.proofValue;
  if (unsecured['@context'] !== undefined) config['@context'] = unsecured['@context'];
  return Buffer.concat([
    sha256(Buffer.from(canonicalJson(config), 'utf8')),
    sha256(Buffer.from(canonicalJson(unsecured), 'utf8'))
  ]);
}

function verificationMethodFor(did) {
  return `${did}#${did.slice('did:key:'.length)}`;
}

/** Build the credential subject from an authorization's attested fields. */
export function credentialSubjectFromAuthorization(authorization) {
  const subject = { id: authorization.subject_id };
  for (const field of CREDENTIAL_SUBJECT_FIELDS) {
    if (!isEmpty(authorization[field])) subject[field] = authorization[field];
  }
  return subject;
}

/**
 * Issue a credential over an authorization's attested fields, signed by the issuer.
 * @param {object} args
 * @param {object} args.authorization   the fields (subject_id, capability, bands, …); a full record or the inputs to one
 * @param {object|string} args.issuer   the regulator's key material (PEM, seed hex or key pair)
 * @param {string} [args.id]            credential id; derived from the content when absent
 * @param {string} [args.validFrom]     defaults to authorization.valid_from
 * @param {string} [args.validUntil]    defaults to authorization.valid_until
 * @param {string} [args.created]       proof creation time, defaults to now
 */
export function issueAuthorizationCredential({ authorization, issuer, id, validFrom, validUntil, created } = {}) {
  if (!isPlainObject(authorization) || !authorization.subject_id) throw new TypeError('authorization with subject_id is required');
  const signer = resolveSigner(issuer);
  const from = validFrom ?? authorization.valid_from ?? new Date().toISOString();
  const until = validUntil ?? authorization.valid_until ?? null;
  const createdAt = created ?? new Date().toISOString();
  for (const [label, value] of [['validFrom', from], ['created', createdAt], ['validUntil', until]]) {
    if (value !== null && !TIMESTAMP_PATTERN.test(value)) throw new TypeError(`${label} must be an ISO-8601 UTC timestamp with a Z suffix`);
  }

  const unsecured = {
    '@context': [CREDENTIAL_CONTEXT_V2, { '@vocab': AUTHORIZATION_VOCAB }],
    type: ['VerifiableCredential', AUTHORIZATION_CREDENTIAL_TYPE],
    issuer: signer.did,
    validFrom: from,
    ...(until ? { validUntil: until } : {}),
    credentialSubject: credentialSubjectFromAuthorization(authorization)
  };
  unsecured.id = id ?? `urn:frontier-state-protocol:credential:${hashPayload(unsecured).slice(7, 39)}`;

  const proofConfig = {
    type: DATA_INTEGRITY_PROOF,
    cryptosuite: CRYPTOSUITE,
    created: createdAt,
    verificationMethod: verificationMethodFor(signer.did),
    proofPurpose: PROOF_PURPOSE
  };
  const signature = signBytes(credentialHashData(unsecured, proofConfig), signer);
  return { ...unsecured, proof: { ...proofConfig, proofValue: multibaseEncodeBase58btc(signature) } };
}

/**
 * Verify a credential's structure, proof and validity window.
 * @param {object} credential
 * @param {object} [options]
 * @param {string} [options.expected_issuer]  a did:key the issuer must equal
 * @param {Date|string} [options.at]          instant the credential must be valid at (default: now)
 */
export function verifyCredential(credential, { expected_issuer, at = new Date() } = {}) {
  const errors = [];
  const checks = [];
  const result = (extra = {}) => ({ verified: errors.length === 0, errors, checks, issuer: credential?.issuer ?? null, subject: credential?.credentialSubject ?? null, ...extra });

  if (!isPlainObject(credential)) {
    errors.push('credential must be an object');
    return result();
  }
  const context = Array.isArray(credential['@context']) ? credential['@context'] : [credential['@context']];
  if (context[0] !== CREDENTIAL_CONTEXT_V2) errors.push(`@context must start with ${CREDENTIAL_CONTEXT_V2}`);
  else checks.push('context_v2');
  const types = Array.isArray(credential.type) ? credential.type : [credential.type];
  if (!types.includes('VerifiableCredential')) errors.push('type must include VerifiableCredential');
  else checks.push('type_verifiable_credential');
  if (!isDidKey(credential.issuer)) errors.push('issuer must be an ed25519 did:key');
  else checks.push('issuer_did_key');
  if (expected_issuer !== undefined && credential.issuer !== expected_issuer) errors.push(`issuer ${credential.issuer} is not the expected ${expected_issuer}`);
  else if (expected_issuer !== undefined) checks.push('issuer_match');
  if (!isPlainObject(credential.credentialSubject) || typeof credential.credentialSubject.id !== 'string') errors.push('credentialSubject with an id is required');
  else checks.push('subject_present');
  if (!TIMESTAMP_PATTERN.test(credential.validFrom ?? '')) errors.push('validFrom must be an ISO-8601 UTC timestamp');
  if (credential.validUntil !== undefined && !TIMESTAMP_PATTERN.test(credential.validUntil ?? '')) errors.push('validUntil must be an ISO-8601 UTC timestamp');

  const proof = credential.proof;
  if (!isPlainObject(proof)) {
    errors.push('proof is required');
    return result();
  }
  if (proof.type !== DATA_INTEGRITY_PROOF) errors.push(`proof.type must be ${DATA_INTEGRITY_PROOF}`);
  if (proof.cryptosuite !== CRYPTOSUITE) errors.push(`proof.cryptosuite must be ${CRYPTOSUITE}`);
  if (proof.proofPurpose !== PROOF_PURPOSE) errors.push(`proof.proofPurpose must be ${PROOF_PURPOSE}`);
  if (!TIMESTAMP_PATTERN.test(proof.created ?? '')) errors.push('proof.created must be an ISO-8601 UTC timestamp');
  if (isDidKey(credential.issuer) && proof.verificationMethod !== verificationMethodFor(credential.issuer)) {
    errors.push('proof.verificationMethod must be the issuer did:key with its own key fragment');
  } else if (isDidKey(credential.issuer)) {
    checks.push('verification_method_bound');
  }
  if (errors.length) return result();

  let signature;
  try {
    if (typeof proof.proofValue !== 'string' || !proof.proofValue.startsWith('z')) throw new Error('not multibase base58btc');
    signature = multibaseDecodeBase58btc(proof.proofValue);
    if (signature.length !== 64) throw new Error('not 64 bytes');
  } catch (error) {
    errors.push(`proof.proofValue is not an ed25519 signature: ${error.message}`);
    return result();
  }
  checks.push('proof_value_decoded');

  let hashData;
  try {
    hashData = credentialHashData(credential, proof);
  } catch (error) {
    errors.push(`credential cannot be canonicalised: ${error.message}`);
    return result();
  }
  if (!verifyBytes(hashData, signature, credential.issuer)) errors.push('proof signature does not verify against the issuer');
  else checks.push('signature_valid');

  const instant = at instanceof Date ? at : new Date(at);
  if (Number.isNaN(instant.getTime())) errors.push('at must be a valid instant');
  else {
    if (new Date(credential.validFrom) > instant) errors.push(`credential is not valid before ${credential.validFrom}`);
    else if (credential.validUntil && new Date(credential.validUntil) < instant) errors.push(`credential expired at ${credential.validUntil}`);
    else checks.push('within_validity');
  }
  return result();
}

function isEmpty(value) {
  return value === undefined || value === null || (Array.isArray(value) && value.length === 0);
}

function sameValue(a, b) {
  // Absent, null and an empty band list all mean "nothing attested".
  const left = isEmpty(a) ? null : a;
  const right = isEmpty(b) ? null : b;
  if (left === null && right === null) return true;
  if (left === null || right === null) return false;
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

/**
 * Verify that an authorization record's `proof` is a credential that verifies at
 * `at` (default now), was issued by the record's controller, and attests exactly the
 * record's fields. Revocation is reported, not treated as a verification failure.
 */
export function verifyAuthorizationCredential(authorization, { at = new Date() } = {}) {
  const errors = [];
  const checks = [];
  if (!isPlainObject(authorization) || authorization.record_type !== 'authorization') {
    return { verified: false, errors: ['an authorization record is required'], checks, issuer: null };
  }
  if (!isPlainObject(authorization.proof)) {
    return { verified: false, errors: ['authorization.proof must carry a verifiable credential'], checks, issuer: null };
  }

  const credential = verifyCredential(authorization.proof, { expected_issuer: isDidKey(authorization.controller_id) ? authorization.controller_id : undefined, at });
  errors.push(...credential.errors);
  checks.push(...credential.checks);
  if (!isDidKey(authorization.controller_id)) errors.push('controller_id must be the issuing authority did:key');
  else if (credential.issuer === authorization.controller_id) checks.push('controller_is_issuer');

  const subject = authorization.proof.credentialSubject ?? {};
  if (subject.id !== authorization.subject_id) errors.push(`credential subject ${subject.id} is not the authorization subject ${authorization.subject_id}`);
  else checks.push('subject_match');
  for (const field of CREDENTIAL_SUBJECT_FIELDS) {
    if (!sameValue(subject[field], authorization[field])) errors.push(`credential ${field} does not match the authorization`);
  }
  if (errors.filter((e) => e.includes('does not match the authorization')).length === 0) checks.push('fields_match');
  if (!sameValue(authorization.proof.validFrom, authorization.valid_from)) errors.push('credential validFrom does not match valid_from');
  if (!sameValue(authorization.proof.validUntil ?? null, authorization.valid_until ?? null)) errors.push('credential validUntil does not match valid_until');
  // Revocation and currentness are states of the record, not defects of the proof:
  // a revoked licence still carries an authentic credential. See authorizationIsCurrent.
  return { verified: errors.length === 0, errors, checks, issuer: credential.issuer, revoked: authorization.revoked === true };
}
