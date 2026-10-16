/**
 * Signed receipt chain.
 *
 * A receipt proves that a specific record (by canonical hash) was accepted by a
 * specific issuer at a specific time, and links to the previous receipt so a
 * sequence can be replayed and audited. Receipts are append-only.
 *
 * signature_algorithm:
 *   - "ed25519"             issuer is a did:key, signature is verifiable by anyone
 *   - "sha256_chain_legacy" pre-signature chain digest, integrity only, no identity
 *   - "none"                hash only, no integrity claim beyond the record hash
 *
 * An issuer that is a did:key must sign: unsigned receipts may not borrow an identity.
 */

import { canonicalJson } from '../utils/canonicalJson.js';
import { hashPayload, hashRecord, isHashRef, sha256Hex } from '../utils/hash.js';
import { encodeSignature, isDidKey, isValidSignatureText, resolveSigner, signBytes, verifyBytes } from '../crypto/keys.js';
import { isTimestamp } from '../crypto/envelope.js';

export const RECEIPT_VERSION = 'state-receipt/1';
export const RECEIPT_DOMAIN_TAG = 'state-receipt/1:';
export const RECEIPT_SIGNATURE_ALGORITHMS = ['ed25519', 'sha256_chain_legacy', 'none'];
export const CORE_FIELDS = ['receipt_id', 'record_hash', 'previous_hash', 'timestamp', 'issuer'];

function nowIso() {
  return new Date().toISOString();
}

/** The five fields every receipt commits to, each present (null when absent). */
export function receiptCore(receipt) {
  return {
    receipt_id: receipt.receipt_id ?? null,
    record_hash: receipt.record_hash ?? null,
    previous_hash: receipt.previous_hash ?? null,
    timestamp: receipt.timestamp ?? null,
    issuer: receipt.issuer ?? null
  };
}

export function receiptSigningInput(receipt) {
  return `${RECEIPT_DOMAIN_TAG}${canonicalJson(receiptCore(receipt))}`;
}

export function computeReceiptHash(receipt) {
  return hashPayload(receiptCore(receipt));
}

export function deriveReceiptId({ record_hash, previous_hash, timestamp, issuer }) {
  return `rcp_${sha256Hex(canonicalJson({ record_hash, previous_hash: previous_hash ?? null, timestamp, issuer })).slice(0, 24)}`;
}

/**
 * Create a receipt for a record.
 * @param {object} args
 * @param {object} [args.record]          the record (hashed canonically), or
 * @param {string} [args.record_hash]     its precomputed hash
 * @param {string|null} [args.previous_hash]  previous receipt's receipt_hash
 * @param {object|string} [args.issuer]   a signer (see resolveSigner) for ed25519 receipts,
 *                                        or a plain name for unsigned receipts; a did:key
 *                                        string is rejected because it cannot sign
 * @param {string} [args.timestamp]       ISO-8601 UTC; defaults to now
 */
export function createReceiptRecord({ record, record_hash, previous_hash = null, issuer, timestamp = nowIso() }) {
  const recordHash = record_hash ?? (record !== undefined ? hashRecord(record) : null);
  if (!isHashRef(recordHash)) throw new TypeError('record or record_hash (sha256:) is required');
  if (previous_hash !== null && !isHashRef(previous_hash)) {
    throw new TypeError('previous_hash must be a sha256: reference or null');
  }
  if (!isTimestamp(timestamp)) throw new TypeError('timestamp must be ISO-8601 UTC with a Z suffix');
  if (typeof issuer === 'string' && isDidKey(issuer)) {
    throw new TypeError('a did:key issuer must be given as a signer with its private key');
  }

  const signer = issuer && typeof issuer !== 'string' ? resolveSigner(issuer) : null;
  const issuerId = signer ? signer.did : (issuer || 'unsigned');
  const core = {
    receipt_id: deriveReceiptId({ record_hash: recordHash, previous_hash, timestamp, issuer: issuerId }),
    record_hash: recordHash,
    previous_hash,
    timestamp,
    issuer: issuerId
  };

  const receipt = {
    record_type: 'receipt',
    receipt_version: RECEIPT_VERSION,
    ...core,
    receipt_hash: hashPayload(core)
  };

  if (signer) {
    receipt.signature = encodeSignature(signBytes(`${RECEIPT_DOMAIN_TAG}${canonicalJson(core)}`, signer));
    receipt.signature_algorithm = 'ed25519';
    receipt.key_id = signer.did;
    receipt.verification_status = 'issued';
  } else {
    receipt.signature = null;
    receipt.signature_algorithm = 'none';
    receipt.key_id = null;
    receipt.verification_status = 'unsigned';
  }

  return receipt;
}

/**
 * Verify one receipt. Never throws on malformed input.
 * @param {object} receipt
 * @param {object} [options]
 * @param {object} [options.record]            recompute and compare the record hash
 * @param {object} [options.previous_receipt]  check the chain link
 * @param {string} [options.expected_issuer]
 */
export function verifyReceiptRecord(receipt, options = {}) {
  const checks = [];
  const errors = [];
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    return { verified: false, receipt_id: null, issuer: null, signature_algorithm: null, identity_bound: false, checks, errors: ['receipt must be an object'] };
  }

  const algorithm = receipt.signature_algorithm ?? (receipt.signature ? 'sha256_chain_legacy' : 'none');
  const legacy = algorithm === 'sha256_chain_legacy';

  if (receipt.record_type !== undefined && receipt.record_type !== 'receipt') {
    errors.push('record_type must be "receipt"');
  }
  if (!legacy && receipt.receipt_version !== RECEIPT_VERSION) {
    errors.push(`unsupported receipt_version: ${receipt.receipt_version}`);
  } else if (!legacy) {
    checks.push('version_supported');
  }

  for (const field of CORE_FIELDS) {
    if (field === 'previous_hash') {
      if (!('previous_hash' in receipt)) errors.push('missing core field: previous_hash');
    } else if (receipt[field] === undefined || receipt[field] === null) {
      errors.push(`missing core field: ${field}`);
    }
  }
  if (errors.length === 0) checks.push('core_complete');

  if (!isHashRef(receipt.record_hash)) errors.push('record_hash must be a sha256: reference');
  if (receipt.previous_hash != null && !isHashRef(receipt.previous_hash)) {
    errors.push('previous_hash must be a sha256: reference or null');
  }
  if (!isTimestamp(receipt.timestamp)) {
    errors.push('timestamp must be ISO-8601 UTC with a Z suffix');
  } else {
    checks.push('timestamp_format');
  }
  if (typeof receipt.issuer !== 'string' || receipt.issuer.length === 0) errors.push('issuer must be a non-empty string');

  if (errors.length === 0) {
    if (!legacy) {
      const expectedId = deriveReceiptId(receipt);
      if (receipt.receipt_id === expectedId) checks.push('receipt_id_match');
      else errors.push('receipt_id does not match its derivation');
    }
    const expectedReceiptHash = computeReceiptHash(receipt);
    if (!isHashRef(receipt.receipt_hash)) {
      if (legacy && receipt.receipt_hash === undefined) checks.push('legacy_receipt_without_hash');
      else errors.push('receipt_hash must be a sha256: reference');
    } else if (receipt.receipt_hash === expectedReceiptHash) {
      checks.push('receipt_hash_match');
    } else {
      errors.push('receipt hash mismatch');
    }
  }

  if (options.record !== undefined) {
    let recordHash = null;
    try {
      recordHash = hashRecord(options.record);
    } catch (error) {
      errors.push(`record is not canonicalizable: ${error.message}`);
    }
    if (recordHash !== null) {
      if (recordHash === receipt.record_hash) checks.push('record_hash_match');
      else errors.push('record hash mismatch');
    }
  }

  if (options.previous_receipt !== undefined) {
    const previous = options.previous_receipt;
    if (!previous || typeof previous !== 'object' || Array.isArray(previous)) {
      errors.push('previous_receipt must be an object');
    } else {
      const previousHash = isHashRef(previous.receipt_hash) ? previous.receipt_hash : computeReceiptHash(previous);
      if (previousHash === receipt.previous_hash) checks.push('previous_link_match');
      else errors.push('previous_hash does not match previous receipt');
    }
  }

  if (options.expected_issuer !== undefined && receipt.issuer !== options.expected_issuer) {
    errors.push('issuer does not match expected_issuer');
  }

  if (algorithm === 'ed25519') {
    if (!isDidKey(receipt.issuer)) {
      errors.push('ed25519 receipts require a did:key issuer');
    } else if (receipt.key_id !== undefined && receipt.key_id !== null && receipt.key_id !== receipt.issuer) {
      errors.push('key_id does not match issuer');
    } else if (receipt.verification_status !== undefined && receipt.verification_status !== 'issued') {
      errors.push(`verification_status must be "issued" for signed receipts, got ${receipt.verification_status}`);
    } else if (!isValidSignatureText(receipt.signature)) {
      errors.push('signature must be 64 bytes as unpadded base64url');
    } else if (errors.length === 0 && verifyBytes(receiptSigningInput(receipt), receipt.signature, receipt.issuer)) {
      checks.push('signature_valid');
    } else if (errors.length === 0) {
      errors.push('signature invalid');
    }
  } else if (legacy) {
    if (isDidKey(receipt.issuer)) {
      errors.push('a did:key issuer requires an ed25519 signature');
    } else {
      const digest = sha256Hex([receipt.record_hash, receipt.previous_hash ?? '', receipt.issuer, receipt.timestamp].join('|'));
      if (digest === receipt.signature) checks.push('legacy_chain_digest_match');
      else errors.push('legacy chain digest mismatch');
    }
  } else if (algorithm === 'none') {
    if (isDidKey(receipt.issuer)) {
      errors.push('a did:key issuer requires an ed25519 signature');
    } else if (receipt.verification_status !== undefined && receipt.verification_status !== 'unsigned') {
      errors.push(`verification_status must be "unsigned" for unsigned receipts, got ${receipt.verification_status}`);
    } else if (receipt.signature !== undefined && receipt.signature !== null) {
      errors.push('unsigned receipts must not carry a signature');
    } else {
      checks.push('unsigned_receipt');
    }
  } else {
    errors.push(`unsupported signature_algorithm: ${algorithm}`);
  }

  return {
    verified: errors.length === 0,
    receipt_id: receipt.receipt_id ?? null,
    issuer: receipt.issuer ?? null,
    signature_algorithm: algorithm,
    identity_bound: errors.length === 0 && algorithm === 'ed25519',
    checks,
    errors
  };
}

/** Verify an ordered chain (oldest first). Each receipt must link to the one before it. */
export function verifyReceiptChain(receipts, options = {}) {
  const results = [];
  const errors = [];
  if (!Array.isArray(receipts) || receipts.length === 0) {
    return { verified: false, length: 0, head: null, results, errors: ['chain is empty'] };
  }

  receipts.forEach((receipt, index) => {
    const result = verifyReceiptRecord(receipt, {
      previous_receipt: index > 0 ? receipts[index - 1] : undefined,
      expected_issuer: options.expected_issuer
    });
    if (index === 0 && options.require_genesis && receipt?.previous_hash != null) {
      result.errors.push('first receipt must have previous_hash null');
      result.verified = false;
    }
    results.push(result);
    if (!result.verified) {
      errors.push(`receipt ${index} (${receipt?.receipt_id ?? 'unknown'}): ${result.errors.join('; ')}`);
    }
  });

  return {
    verified: errors.length === 0,
    length: receipts.length,
    head: receipts[receipts.length - 1]?.receipt_hash ?? null,
    results,
    errors
  };
}
