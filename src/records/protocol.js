/**
 * Constructors for the core protocol records: identity (entity), authorization,
 * and the payload profiles that identify standard payloads wrapped unchanged.
 *
 * These produce plain records in the canonical state-record vocabulary.
 * Schema validation lives in the state stack; this module guarantees shape
 * and derived fields only.
 */

import { hashPayload } from '../utils/hash.js';
import { isDidKey, publicKeyMultibaseFromDid, resolveSigner } from '../crypto/keys.js';
import { issueAuthorizationCredential } from './credential.js';

export const IDENTITY_TYPES = [
  'organization',
  'operator',
  'node',
  'ground_station',
  'satellite',
  'sensor',
  'agent',
  'service'
];

export const AUTHORIZATION_PROFILES = ['self_declared', 'operator_attested', 'regulator_issued'];

export const AUTHORIZATION_CAPABILITIES = ['receive', 'transmit', 'command', 'schedule', 'publish_data', 'relay'];

/** Payload profiles: a stable id for each standard payload the protocol wraps unchanged. */
export const PAYLOAD_PROFILES = Object.freeze({
  CCSDS_OMM_JSON: 'ccsds.omm.json/1',
  SATNOGS_OBSERVATION: 'satnogs.observation.json/1',
  STAC_ITEM: 'stac.item.json/1',
  PASS_PREDICTION: 'pass-prediction.json/1',
  STATE_RECORD: 'state-record.json/1',
  OPAQUE_JSON: 'opaque.json/1',
  NODE_DESCRIPTOR: 'node-descriptor.json/1',
  CHAIN_HEAD: 'chain-head.json/1'
});

function nowIso() {
  return new Date().toISOString();
}

export function createIdentityRecord({
  entity_id,
  identity_type,
  did,
  controller_id,
  display_name = null,
  status = 'active',
  created_at = nowIso(),
  metadata = {}
}) {
  if (!entity_id) throw new TypeError('entity_id is required');
  if (!IDENTITY_TYPES.includes(identity_type)) {
    throw new TypeError(`identity_type must be one of ${IDENTITY_TYPES.join(', ')}`);
  }
  if (did !== undefined && did !== null && !isDidKey(did)) {
    throw new TypeError('did must be an ed25519 did:key');
  }

  return {
    record_type: 'entity',
    entity_id,
    entity_type: identity_type,
    identity_type,
    did: did ?? null,
    public_key_multibase: did ? publicKeyMultibaseFromDid(did) : null,
    controller_id: controller_id ?? entity_id,
    display_name,
    status,
    created_at,
    metadata_hash: hashPayload(metadata)
  };
}

/**
 * Machine-readable authorization. Self-declared by default; `profile` says who
 * stands behind it and `proof` can carry a verifiable credential or document hash.
 */
export function createAuthorizationRecord({
  authorization_id,
  subject_id,
  controller_id,
  capability,
  scope = null,
  profile = 'self_declared',
  jurisdiction = null,
  bands = [],
  max_eirp_dbw = null,
  location = null,
  valid_from = nowIso(),
  valid_until = null,
  revoked = false,
  license_reference = null,
  proof = null
}) {
  if (!subject_id) throw new TypeError('subject_id is required');
  if (!controller_id) throw new TypeError('controller_id (issuer) is required');
  if (!AUTHORIZATION_CAPABILITIES.includes(capability)) {
    throw new TypeError(`capability must be one of ${AUTHORIZATION_CAPABILITIES.join(', ')}`);
  }
  if (!AUTHORIZATION_PROFILES.includes(profile)) {
    throw new TypeError(`profile must be one of ${AUTHORIZATION_PROFILES.join(', ')}`);
  }
  if (jurisdiction !== null && !/^[A-Z]{2}$/.test(jurisdiction)) {
    throw new TypeError('jurisdiction must be an ISO 3166-1 alpha-2 code');
  }
  for (const band of bands) {
    if (!(Number.isFinite(band?.lower_hz) && Number.isFinite(band?.upper_hz) && band.lower_hz < band.upper_hz)) {
      throw new TypeError('each band needs numeric lower_hz < upper_hz');
    }
  }
  if (location !== null && !(Number.isFinite(location?.latitude) && Number.isFinite(location?.longitude))) {
    throw new TypeError('location needs numeric latitude and longitude');
  }
  if (capability === 'transmit' && bands.length === 0) {
    throw new TypeError('a transmit authorization must declare at least one band');
  }

  const record = {
    record_type: 'authorization',
    subject_id,
    controller_id,
    capability,
    scope,
    profile,
    jurisdiction,
    bands,
    max_eirp_dbw,
    location,
    valid_from,
    valid_until,
    revoked,
    license_reference,
    proof
  };

  return {
    authorization_id: authorization_id ?? `auth_${hashPayload(record).slice(7, 31)}`,
    ...record
  };
}

/** Is this authorization usable at `at` (ISO string or Date)? */
/**
 * A regulator-issued authorization: the regulator signs a verifiable credential over
 * the attested fields, and the record names the regulator's did:key as controller.
 * @param {object} args  the authorization fields plus `regulator` (key material) and optional `created`, `credential_id`
 */
export function createRegulatorIssuedAuthorization({ regulator, created, credential_id, ...fields }) {
  if (!regulator) throw new TypeError('regulator key material is required');
  const signer = resolveSigner(regulator);
  const valid_from = fields.valid_from ?? nowIso();
  const attested = { ...fields, valid_from, valid_until: fields.valid_until ?? null };
  const proof = issueAuthorizationCredential({ authorization: attested, issuer: signer, created, id: credential_id });
  return createAuthorizationRecord({ ...attested, controller_id: signer.did, profile: 'regulator_issued', proof });
}

export function authorizationIsCurrent(authorization, at = new Date()) {
  if (!authorization || authorization.revoked) return false;
  const time = new Date(at).getTime();
  if (authorization.valid_from && time < new Date(authorization.valid_from).getTime()) return false;
  if (authorization.valid_until && time > new Date(authorization.valid_until).getTime()) return false;
  return true;
}
