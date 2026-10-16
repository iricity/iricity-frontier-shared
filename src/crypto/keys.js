/**
 * Ed25519 identity primitives.
 *
 * Identities are expressed as `did:key` identifiers (W3C DID Core, did:key method):
 *   did:key:z<base58btc(0xed 0x01 || 32-byte public key)>
 * The multicodec code for ed25519-pub is 0xed, varint-encoded as the two bytes ed 01.
 *
 * Private key material is handled as Node KeyObjects, PKCS#8 PEM, or the raw 32-byte
 * seed in hex. Nothing here persists keys; custody belongs to the caller.
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  KeyObject
} from 'node:crypto';
import { multibaseDecodeBase58btc, multibaseEncodeBase58btc } from '../utils/base58.js';
import { sha256HexBytes } from '../utils/hash.js';

export const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const DID_KEY_PREFIX = 'did:key:';

function toBuffer(value, label) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string' && /^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
    return Buffer.from(value, 'hex');
  }
  throw new TypeError(`${label}: expected bytes or hex`);
}

function normalizePem(pem) {
  return String(pem).replace(/\\n/g, '\n').trim();
}

export function publicKeyBytesFromKeyObject(publicKey) {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return Buffer.from(der.subarray(der.length - 32));
}

export function seedFromPrivateKeyObject(privateKey) {
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  return Buffer.from(der.subarray(der.length - 32));
}

export function publicKeyFromBytes(raw) {
  const bytes = toBuffer(raw, 'publicKeyFromBytes');
  if (bytes.length !== 32) throw new TypeError('ed25519 public key must be 32 bytes');
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]),
    format: 'der',
    type: 'spki'
  });
}

export function privateKeyFromSeed(seed) {
  const bytes = toBuffer(seed, 'privateKeyFromSeed');
  if (bytes.length !== 32) throw new TypeError('ed25519 seed must be 32 bytes');
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, bytes]),
    format: 'der',
    type: 'pkcs8'
  });
}

export function didFromPublicKeyBytes(raw) {
  const bytes = toBuffer(raw, 'didFromPublicKeyBytes');
  if (bytes.length !== 32) throw new TypeError('ed25519 public key must be 32 bytes');
  return `${DID_KEY_PREFIX}${multibaseEncodeBase58btc(Buffer.concat([ED25519_MULTICODEC_PREFIX, bytes]))}`;
}

export function isDidKey(value) {
  return typeof value === 'string' && value.startsWith(`${DID_KEY_PREFIX}z6Mk`);
}

export function publicKeyBytesFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith(DID_KEY_PREFIX)) {
    throw new TypeError('expected a did:key identifier');
  }
  const decoded = multibaseDecodeBase58btc(did.slice(DID_KEY_PREFIX.length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new TypeError('did:key is not an ed25519 public key');
  }
  return Buffer.from(decoded.subarray(2));
}

export function publicKeyFromDid(did) {
  return publicKeyFromBytes(publicKeyBytesFromDid(did));
}

export function publicKeyMultibaseFromDid(did) {
  return did.slice(DID_KEY_PREFIX.length);
}

/** Short, stable fingerprint of a DID's public key, for logs and key_id fields. */
export function fingerprintDid(did) {
  return `fp_${sha256HexBytes(publicKeyBytesFromDid(did)).slice(0, 20)}`;
}

function describeKeyPair(privateKey, publicKey) {
  const publicBytes = publicKeyBytesFromKeyObject(publicKey);
  const did = didFromPublicKeyBytes(publicBytes);
  return {
    did,
    key_id: did,
    algorithm: 'ed25519',
    public_key_multibase: publicKeyMultibaseFromDid(did),
    public_key_hex: publicBytes.toString('hex'),
    public_key_pem: publicKey.export({ format: 'pem', type: 'spki' }),
    private_key_seed_hex: seedFromPrivateKeyObject(privateKey).toString('hex'),
    private_key_pem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
    private_key: privateKey,
    public_key: publicKey
  };
}

export function generateEd25519KeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return describeKeyPair(privateKey, publicKey);
}

export function keyPairFromSeed(seed) {
  const privateKey = privateKeyFromSeed(seed);
  const publicKey = createPublicKey(privateKey);
  return describeKeyPair(privateKey, publicKey);
}

export function keyPairFromPrivateKeyPem(pem) {
  const privateKey = createPrivateKey(normalizePem(pem));
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('private key is not ed25519');
  }
  const publicKey = createPublicKey(privateKey);
  return describeKeyPair(privateKey, publicKey);
}

/**
 * Normalize the many ways a caller may hand over a signer into
 * `{ did, private_key: KeyObject }`.
 * Accepts a key pair from this module, `{ did, private_key }`, `{ private_key_pem }`,
 * `{ private_key_seed_hex }`, or a bare PEM string.
 */
export function resolveSigner(signer) {
  if (!signer) throw new TypeError('signer is required');
  if (typeof signer === 'string') return resolveSigner(keyPairFromPrivateKeyPem(signer));

  let privateKey = signer.private_key;
  if (privateKey && !(privateKey instanceof KeyObject)) {
    privateKey = typeof privateKey === 'string' && privateKey.includes('PRIVATE KEY')
      ? createPrivateKey(normalizePem(privateKey))
      : privateKeyFromSeed(privateKey);
  }
  if (!privateKey && signer.private_key_pem) privateKey = createPrivateKey(normalizePem(signer.private_key_pem));
  if (!privateKey && signer.private_key_seed_hex) privateKey = privateKeyFromSeed(signer.private_key_seed_hex);
  if (!privateKey) throw new TypeError('signer has no private key material');
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError('signer key is not ed25519');

  const publicKey = createPublicKey(privateKey);
  const derivedDid = didFromPublicKeyBytes(publicKeyBytesFromKeyObject(publicKey));
  if (signer.did && signer.did !== derivedDid) {
    throw new TypeError('signer.did does not match the private key');
  }
  return { did: derivedDid, private_key: privateKey };
}

function messageBytes(message) {
  return Buffer.isBuffer(message) ? message : Buffer.from(message, 'utf8');
}

export function signBytes(message, signer) {
  const { private_key } = resolveSigner(signer);
  return cryptoSign(null, messageBytes(message), private_key);
}

export function verifyBytes(message, signature, verifier) {
  let publicKey;
  try {
    if (verifier instanceof KeyObject) publicKey = verifier;
    else if (isDidKey(verifier)) publicKey = publicKeyFromDid(verifier);
    else if (verifier && verifier.did) publicKey = publicKeyFromDid(verifier.did);
    else publicKey = publicKeyFromBytes(verifier);

    const signatureBytes = Buffer.isBuffer(signature) ? signature : decodeSignature(signature);
    return cryptoVerify(null, messageBytes(message), publicKey, signatureBytes);
  } catch {
    return false;
  }
}

export function encodeSignature(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

export function decodeSignature(text) {
  if (typeof text !== 'string') throw new TypeError('signature must be a string');
  return Buffer.from(text, 'base64url');
}
