import { createHash } from 'node:crypto';
import { canonicalJson } from './canonicalJson.js';

export function sha256Hex(input) {
  return createHash('sha256').update(String(input)).digest('hex');
}

export function hashPayload(payload) {
  const value = typeof payload === 'string' ? payload : canonicalJson(payload);
  return `sha256:${sha256Hex(value)}`;
}

export function hashRecord(record) {
  return hashPayload(canonicalJson(record));
}
