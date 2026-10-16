/**
 * Canonical JSON serialization.
 *
 * Follows RFC 8785 (JSON Canonicalization Scheme) for all JSON-native values:
 * - object members sorted by UTF-16 code units of their names
 * - numbers serialized with the ECMAScript Number-to-string algorithm
 * - strings escaped exactly as JSON.stringify escapes them
 * - no insignificant whitespace
 *
 * Two explicit, documented extensions for JavaScript callers:
 * - Date instances serialize as their ISO-8601 string
 * - undefined / function / symbol members are omitted from objects (as JSON.stringify
 *   does) and become null inside arrays (as JSON.stringify does)
 *
 * Rejected, because a canonical form must be unambiguous: non-finite numbers, BigInt,
 * and values that are not plain JSON containers (Buffer, typed arrays, Map, Set).
 */

function compareCodeUnits(a, b) {
  // Default string comparison in JavaScript compares UTF-16 code units, which is
  // exactly the ordering RFC 8785 requires.
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function isOmitted(value) {
  const type = typeof value;
  return value === undefined || type === 'function' || type === 'symbol';
}

function isBinaryOrCollection(value) {
  return (
    ArrayBuffer.isView(value) ||
    value instanceof ArrayBuffer ||
    value instanceof Map ||
    value instanceof Set ||
    value instanceof WeakMap ||
    value instanceof WeakSet
  );
}

/** Nesting beyond this depth is rejected rather than risking a stack overflow on hostile input. */
export const MAX_DEPTH = 256;

function serialize(value, path, depth = 0) {
  if (depth > MAX_DEPTH) throw new TypeError(`canonicalJson: nesting deeper than ${MAX_DEPTH} at ${path}`);
  if (value === null) return 'null';
  if (value instanceof Date) {
    const time = value.getTime();
    if (!Number.isFinite(time)) throw new TypeError(`canonicalJson: invalid Date at ${path}`);
    return JSON.stringify(value.toISOString());
  }

  const type = typeof value;
  if (type === 'string') return JSON.stringify(value);
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`canonicalJson: non-finite number at ${path}`);
    }
    return JSON.stringify(value);
  }
  if (type === 'bigint') {
    throw new TypeError(`canonicalJson: BigInt is not representable in JSON at ${path}`);
  }
  if (isOmitted(value)) {
    throw new TypeError(`canonicalJson: ${type} is not representable in JSON at ${path}`);
  }

  if (Array.isArray(value)) {
    const items = value.map((item, index) =>
      isOmitted(item) ? 'null' : serialize(item, `${path}[${index}]`, depth + 1)
    );
    return `[${items.join(',')}]`;
  }

  if (type === 'object') {
    if (isBinaryOrCollection(value)) {
      throw new TypeError(`canonicalJson: binary data and collections are not JSON values at ${path}; use hashBytes for bytes`);
    }
    const keys = Object.keys(value)
      .filter((key) => !isOmitted(value[key]))
      .sort(compareCodeUnits);
    const members = keys.map(
      (key) => `${JSON.stringify(key)}:${serialize(value[key], `${path}.${key}`, depth + 1)}`
    );
    return `{${members.join(',')}}`;
  }

  throw new TypeError(`canonicalJson: unsupported value at ${path}`);
}

export function canonicalJson(value) {
  return serialize(value, '$');
}
