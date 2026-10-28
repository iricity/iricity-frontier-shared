# frontier-shared

Reference primitives for the Frontier State Protocol (FSP): canonical JSON, hashing, ed25519 identity as `did:key`, signed envelopes, signed receipt chains, and the record constructors that applied stacks use to talk to the state stack.

Everything here is deterministic and dependency-free (Node 20+, built-in `crypto` only). Published conformance vectors let any other implementation, in any language, prove it produces the same bytes.

```
npm install @iricity/frontier-shared
```

The Python implementation, `iricity-frontier-shared` on PyPI, passes the same vectors.

## What it provides

| Area | Exports | Standard it follows |
| --- | --- | --- |
| Canonical form | `canonicalJson` | RFC 8785 (JSON Canonicalization Scheme) |
| Hashing | `hashPayload`, `hashRecord`, `hashBytes`, `sha256Hex` | SHA-256, `sha256:` prefixed hex |
| Identity | `generateEd25519KeyPair`, `keyPairFromSeed`, `didFromPublicKeyBytes`, `publicKeyFromDid` | W3C DID Core, `did:key` method, multicodec `ed25519-pub` |
| Signatures | `signBytes`, `verifyBytes` | RFC 8032 Ed25519 |
| Envelopes | `createEnvelope`, `verifyEnvelope` | `state-envelope/1` (this project) |
| Receipts | `createReceiptRecord`, `verifyReceiptRecord`, `verifyReceiptChain` | `state-receipt/1` (this project) |
| Records | `createIdentityRecord`, `createAuthorizationRecord`, `PAYLOAD_PROFILES` | canonical state-record vocabulary |
| Bridge | `buildStateBridgeArtifact` and the `toState*Record` helpers | applied-stack to state-stack handoff |

## The two protocol objects

**Envelope.** Attaches an identity to any payload without changing the payload. The signature covers the canonical header (version, payload type, payload hash, signer, time, previous link), so an envelope verifies with or without the payload body attached.

```js
import { generateEd25519KeyPair, createEnvelope, verifyEnvelope } from '@iricity/frontier-shared';

const node = generateEd25519KeyPair();
const envelope = createEnvelope({ payload: omm, payload_type: 'ccsds.omm.json/1', signer: node });
verifyEnvelope(envelope);            // { verified: true, signer: 'did:key:z6Mk…', checks: [...] }
```

**Receipt.** Proves a record (by canonical hash) was accepted by an issuer at a time, linked to the previous receipt. Receipts are append-only and replayable.

```js
import { createReceiptRecord, verifyReceiptChain } from '@iricity/frontier-shared';

const first = createReceiptRecord({ record, issuer: node });
const second = createReceiptRecord({ record: next, previous_hash: first.receipt_hash, issuer: node });
verifyReceiptChain([first, second], { require_genesis: true });   // { verified: true, head: '…' }
```

Signers are `did:key` identifiers, so verification needs nothing but the object itself. Verifiers never throw on malformed input and check every field the specification fixes: header and core completeness, version tags, derived ids and hashes, UTC timestamps, and the exact signature encoding. A receipt created with a plain string issuer is explicitly `signature_algorithm: "none"`, `verification_status: "unsigned"`; an unsigned receipt may never name a `did:key` as issuer, and the library never dresses a hash up as a signature.

## Regulator-issued authorizations

An authorization record's `proof` can carry a W3C Verifiable Credential (Data Model 2.0) issued by a regulator over the record's attested fields, secured with a Data Integrity proof using the `eddsa-jcs-2022` cryptosuite. That suite canonicalises with JCS, the protocol's own canonical form, so issuing and verifying need SHA-256 and Ed25519 only, no JSON-LD processing.

```js
import { createRegulatorIssuedAuthorization, verifyAuthorizationCredential } from '@iricity/frontier-shared';

const licence = createRegulatorIssuedAuthorization({
  subject_id: 'station_vu2abc',
  capability: 'transmit',
  jurisdiction: 'IN',
  bands: [{ lower_hz: 144e6, upper_hz: 146e6, service: 'amateur' }],
  max_eirp_dbw: 20,
  license_reference: 'ASOC/EXAMPLE/0001',
  valid_from: '2026-01-01T00:00:00.000Z',
  valid_until: '2031-01-01T00:00:00.000Z',
  regulator: regulatorKeyPair
});
verifyAuthorizationCredential(licence);   // { verified: true, issuer: 'did:key:z6Mk…', checks: [...] }
```

The record names the regulator's `did:key` as `controller_id`; verification binds the credential to that issuer and to every attested field of the record, so neither can be changed after issue. `issueAuthorizationCredential` and `verifyCredential` expose the credential layer on its own. The `credential` suite of the conformance vectors (version 3) pins issued credentials byte for byte, and the Python implementation passes it.

## Conformance

```
npm run conformance          # check this implementation
node conformance/run.js      # same, as a CLI (exit code 1 on failure)
```

`conformance/vectors.json` (version 3, 75 cases) holds the fixed inputs and expected outputs across nine suites: canonical JSON, hash references, base58btc in both directions, did:key in both directions, Ed25519, envelopes (plain, chained, detached), receipts (signed, unsigned, legacy), credentials (issued byte for byte, and an authorization bound to its credential) and rejections that a verifier must refuse. Its external anchors are the RFC 8785 sample, RFC 8032 Ed25519 tests 1 and 2, the base58btc "Hello World!" vector, and the did:key specification's Ed25519 example identifier. Signatures are deterministic, so a second implementation must reproduce them byte for byte. An implementation conforms only when every suite passes and none is skipped; `conformance/vectors.lock.json` pins the file's hash.

To test another implementation from JavaScript:

```js
import { runConformance } from '@iricity/frontier-shared/conformance';
const report = runConformance(myImplementation);   // { conformant, passed, failed, skipped, results }
```

Regenerate the vectors only when the protocol version changes: `npm run conformance:build` refuses to write vectors that disagree with the external anchors.

## Canonical JSON notes

`canonicalJson` is RFC 8785 for all JSON values. Two JavaScript conveniences are documented as extensions and covered by unit tests (they cannot appear in JSON vectors): `Date` serializes as its ISO-8601 string, and `undefined` members are omitted (null inside arrays), exactly as `JSON.stringify` behaves. Non-finite numbers, `BigInt`, binary data, collections and nesting deeper than 256 levels throw, because a canonical form must be unambiguous and a verifier must not be crashable.

`hashPayload` always hashes canonical JSON, so a string payload is hashed as the JSON string. Use `hashText` for raw text and `hashBytes` for bytes.

## Scope and non-goals

This package holds primitives only. It does not persist keys, run servers, or know about any product. Schemas and validation live in the state stack; nodes and services live in the applied stacks.

## Releasing

See [docs/RELEASE_PLAYBOOK.md](docs/RELEASE_PLAYBOOK.md): the 0.1 freeze checklist, the 0.1 freeze checklist, trusted publishing through GitHub Actions (every release is a `v<version>` tag), and the Python implementation that proves the vectors are portable.

## License

Apache-2.0. See `LICENSE`.
