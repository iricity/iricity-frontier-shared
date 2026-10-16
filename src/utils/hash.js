import { createHash } from 'node:crypto';
import { canonicalJson } from './canonicalJson.js';

export const HASH_PREFIX = 'sha256:';
const HASH_REF = /^sha256:[0-9a-f]{64}$/;

/** Hex SHA-256 of a UTF-8 string (or the string form of the input). */
export function sha256Hex(input) {
  return createHash('sha256').update(String(input), 'utf8').digest('hex');
}

/** Hex SHA-256 of raw bytes. */
export function sha256HexBytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Hash reference of any JSON value, always over its canonical JSON form.
 * A string payload is therefore hashed as the JSON string (quoted), never as raw
 * text, so an object and the text of that object can never share a reference.
 */
export function hashPayload(payload) {
  return `${HASH_PREFIX}${sha256Hex(canonicalJson(payload))}`;
}

/** Hash reference of raw UTF-8 text (not JSON-encoded). */
export function hashText(text) {
  if (typeof text !== 'string') throw new TypeError('hashText expects a string');
  return `${HASH_PREFIX}${sha256Hex(text)}`;
}

/** Hash reference of raw bytes. */
export function hashBytes(bytes) {
  return `${HASH_PREFIX}${sha256HexBytes(bytes)}`;
}

/** Hash reference of a record: identical to hashPayload, kept for readability. */
export function hashRecord(record) {
  return hashPayload(record);
}

export function isHashRef(value) {
  return typeof value === 'string' && HASH_REF.test(value);
}
