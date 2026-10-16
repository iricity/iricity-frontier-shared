// Canonical form and hashing
export { canonicalJson } from './utils/canonicalJson.js';
export {
  HASH_PREFIX,
  sha256Hex,
  sha256HexBytes,
  hashPayload,
  hashBytes,
  hashRecord,
  isHashRef
} from './utils/hash.js';
export {
  base58Encode,
  base58Decode,
  multibaseEncodeBase58btc,
  multibaseDecodeBase58btc
} from './utils/base58.js';

// Identity and signatures
export {
  ED25519_MULTICODEC_PREFIX,
  generateEd25519KeyPair,
  keyPairFromSeed,
  keyPairFromPrivateKeyPem,
  resolveSigner,
  didFromPublicKeyBytes,
  isDidKey,
  publicKeyBytesFromDid,
  publicKeyFromDid,
  publicKeyMultibaseFromDid,
  publicKeyFromBytes,
  privateKeyFromSeed,
  fingerprintDid,
  signBytes,
  verifyBytes,
  encodeSignature,
  decodeSignature
} from './crypto/keys.js';
export {
  ENVELOPE_VERSION,
  ENVELOPE_DOMAIN_TAG,
  createEnvelope,
  verifyEnvelope,
  envelopeHeader,
  envelopeHash,
  envelopeSigningInput
} from './crypto/envelope.js';

// Protocol records
export {
  RECEIPT_VERSION,
  RECEIPT_DOMAIN_TAG,
  RECEIPT_SIGNATURE_ALGORITHMS,
  createReceiptRecord,
  verifyReceiptRecord,
  verifyReceiptChain,
  receiptCore,
  receiptSigningInput,
  computeReceiptHash
} from './records/receipt.js';
export {
  IDENTITY_TYPES,
  AUTHORIZATION_PROFILES,
  AUTHORIZATION_CAPABILITIES,
  PAYLOAD_PROFILES,
  createIdentityRecord,
  createAuthorizationRecord,
  authorizationIsCurrent
} from './records/protocol.js';

// State-record helpers and the applied-stack bridge (0.1.x compatible)
export {
  CANONICAL_STATE_RECORD_TYPES,
  canonicalReceiptPayload,
  buildReceiptSignatureStatus,
  buildReceiptVerificationResponse,
  buildStateBridgeSummary,
  toStateEntityRecord,
  toStateNavigationRecord,
  toStateMeasurementRecord,
  toStateCommunicationRecord,
  normalizeSpaceEventToStateRecord,
  buildStateBridgeArtifact
} from './state/bridge.js';
