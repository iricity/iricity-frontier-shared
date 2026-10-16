/**
 * Signed envelope: the protocol's one way of attaching an identity to any payload.
 *
 * The signature covers the canonical JSON of the envelope header
 * (version, payload type, payload hash, signer, creation time, previous link),
 * prefixed with a domain tag. The payload itself travels by hash, so an envelope
 * can be verified with or without the payload body attached (detached mode).
 */

import { canonicalJson } from '../utils/canonicalJson.js';
import { hashPayload, isHashRef, sha256Hex } from '../utils/hash.js';
import { encodeSignature, isDidKey, resolveSigner, signBytes, verifyBytes } from './keys.js';

export const ENVELOPE_VERSION = 'state-envelope/1';
export const ENVELOPE_DOMAIN_TAG = 'state-envelope/1:';

function nowIso() {
  return new Date().toISOString();
}

export function envelopeHeader(envelope) {
  return {
    envelope_version: envelope.envelope_version,
    payload_type: envelope.payload_type,
    payload_hash: envelope.payload_hash,
    signer: envelope.signer,
    created_at: envelope.created_at,
    previous_envelope_hash: envelope.previous_envelope_hash ?? null
  };
}

export function envelopeSigningInput(envelope) {
  return `${ENVELOPE_DOMAIN_TAG}${canonicalJson(envelopeHeader(envelope))}`;
}

export function envelopeHash(envelope) {
  return `sha256:${sha256Hex(envelopeSigningInput(envelope))}`;
}

/**
 * @param {object} args
 * @param {any} args.payload              the payload object (left untouched)
 * @param {string} args.payload_type      profile identifier, e.g. "ccsds.omm.json/1"
 * @param {object|string} args.signer     see resolveSigner()
 * @param {string} [args.created_at]
 * @param {string|null} [args.previous_envelope_hash]
 * @param {boolean} [args.detached]       omit the payload body from the envelope
 */
export function createEnvelope({
  payload,
  payload_type,
  signer,
  created_at = nowIso(),
  previous_envelope_hash = null,
  detached = false
}) {
  if (!payload_type || typeof payload_type !== 'string') {
    throw new TypeError('payload_type is required');
  }
  if (payload === undefined) throw new TypeError('payload is required');
  if (previous_envelope_hash !== null && !isHashRef(previous_envelope_hash)) {
    throw new TypeError('previous_envelope_hash must be a sha256: reference or null');
  }

  const resolved = resolveSigner(signer);
  const header = {
    envelope_version: ENVELOPE_VERSION,
    payload_type,
    payload_hash: hashPayload(payload),
    signer: resolved.did,
    created_at,
    previous_envelope_hash
  };
  const signingInput = `${ENVELOPE_DOMAIN_TAG}${canonicalJson(header)}`;
  const signature = signBytes(signingInput, resolved);
  const hash = `sha256:${sha256Hex(signingInput)}`;

  return {
    ...header,
    envelope_hash: hash,
    envelope_id: `env_${hash.slice(7, 31)}`,
    ...(detached ? {} : { payload }),
    signature: {
      algorithm: 'ed25519',
      key_id: resolved.did,
      value: encodeSignature(signature)
    }
  };
}

/**
 * Verify an envelope. Self-contained: the signer DID carries the public key.
 * @param {object} envelope
 * @param {object} [options]
 * @param {any} [options.payload]           payload body for detached envelopes
 * @param {string} [options.expected_signer] require this DID
 * @param {string[]} [options.allowed_payload_types]
 */
export function verifyEnvelope(envelope, options = {}) {
  const checks = [];
  const errors = [];

  if (!envelope || typeof envelope !== 'object') {
    return { verified: false, checks, errors: ['envelope must be an object'] };
  }

  if (envelope.envelope_version !== ENVELOPE_VERSION) {
    errors.push(`unsupported envelope_version: ${envelope.envelope_version}`);
  } else {
    checks.push('version_supported');
  }

  if (!isDidKey(envelope.signer)) {
    errors.push('signer must be an ed25519 did:key');
  } else {
    checks.push('signer_is_did_key');
  }

  if (options.expected_signer && envelope.signer !== options.expected_signer) {
    errors.push('signer does not match expected_signer');
  }

  if (Array.isArray(options.allowed_payload_types) && !options.allowed_payload_types.includes(envelope.payload_type)) {
    errors.push(`payload_type not allowed: ${envelope.payload_type}`);
  }

  const payload = options.payload !== undefined ? options.payload : envelope.payload;
  if (payload !== undefined) {
    if (hashPayload(payload) === envelope.payload_hash) {
      checks.push('payload_hash_match');
    } else {
      errors.push('payload hash mismatch');
    }
  } else {
    checks.push('payload_detached_hash_only');
  }

  if (errors.length === 0) {
    const expectedHash = envelopeHash(envelope);
    if (envelope.envelope_hash && envelope.envelope_hash !== expectedHash) {
      errors.push('envelope hash mismatch');
    } else {
      checks.push('envelope_hash_match');
    }
  }

  if (errors.length === 0) {
    const signature = envelope.signature || {};
    if (signature.algorithm !== 'ed25519') {
      errors.push(`unsupported signature algorithm: ${signature.algorithm}`);
    } else if (signature.key_id && signature.key_id !== envelope.signer) {
      errors.push('signature key_id does not match signer');
    } else if (verifyBytes(envelopeSigningInput(envelope), signature.value, envelope.signer)) {
      checks.push('signature_valid');
    } else {
      errors.push('signature invalid');
    }
  }

  return {
    verified: errors.length === 0,
    signer: envelope.signer ?? null,
    payload_type: envelope.payload_type ?? null,
    payload_hash: envelope.payload_hash ?? null,
    envelope_hash: envelope.envelope_hash ?? null,
    checks,
    errors
  };
}
