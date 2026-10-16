import { createHash } from 'node:crypto';
import { canonicalJson } from './canonicalJson.js';

export const HASH_PREFIX = 'sha256:';

/** Hex SHA-256 of a UTF-8 string (or the string form of the input). */
export function sha256Hex(input) {
  return createHash('sha256').update(String(input), 'utf8').digest('hex');
}

/** Hex SHA-256 of raw bytes. */
export function sha256HexBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Prefixed digest of a payload.
 * Strings are hashed as-is; everything else is hashed in canonical JSON form.
 */
export function hashPayload(payload) {
  const value = typeof payload === 'string' ? payload : canonicalJson(payload);
  return `${HASH_PREFIX}${sha256Hex(value)}`;
}

/** Prefixed digest of raw bytes. */
export function hashBytes(bytes) {
  return `${HASH_PREFIX}${sha256HexBytes(bytes)}`;
}

/** Prefixed digest of a record's canonical JSON form. */
export function hashRecord(record) {
  return hashPayload(canonicalJson(record));
}

export function isHashRef(value) {
  return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}
