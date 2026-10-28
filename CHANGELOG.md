# Changelog

## 0.5.1 - 2026-10-28

- First release through the trusted publisher: published from GitHub Actions with provenance. README: install line, the Python implementation on PyPI, credential vectors are in version 3. No code change.

## 0.5.0 - 2026-10-27

- Conformance vectors version 3 (75 cases, nine suites): a `credential` suite pins issued credentials byte for byte (ids, verification methods, proof values, hash inputs) and binds a regulator-issued authorization to its credential; twelve new rejections cover tampered subjects, swapped issuers, corrupted proof values, unknown cryptosuites, offsets in proof timestamps, expiry, premature use, widened bands, foreign controllers and missing proofs. The runner accepts `issueAuthorizationCredential`, `verifyCredential`, `credentialHashData` and `verifyAuthorizationCredential` from an implementation under test.
- Two payload profile ids for the discovery and federation drafts: `node-descriptor.json/1` (a node's signed self-description) and `chain-head.json/1` (a registry's signed chain head).
- No change to any signed object format. 0.4.0 objects verify unchanged.

## 0.4.0 - 2026-10-27

- Regulator-issued authorizations: `issueAuthorizationCredential` and `verifyCredential` implement a W3C Verifiable Credential (Data Model 2.0) with a Data Integrity proof, cryptosuite `eddsa-jcs-2022` (JCS canonical form, SHA-256, Ed25519, multibase base58btc proof value, `did:key` verification method). `verifyAuthorizationCredential` binds a record's `proof` to its `controller_id` (the issuer DID), its `subject_id` and every attested field; `createRegulatorIssuedAuthorization` builds such a record in one call. Verification never throws.
- No change to envelopes, receipts, hashes or the version 2 conformance vectors; credential vectors arrive with vector version 3 alongside the Python implementation.

## 0.3.0 - 2026-10-17

Hardening after an independent review. Signed objects produced by 0.2.0 still verify; the changes reject malformed and forged objects that 0.2.0 let through.

- hashPayload always hashes canonical JSON: a string payload is hashed as the JSON string, never as raw text, so an object and the text of that object can no longer share a reference. hashText and hashBytes cover raw text and bytes. Record hashes are unchanged.
- canonicalJson rejects binary data, Map, Set and nesting deeper than 256 levels, so verifiers cannot be crashed by hostile input.
- Envelope header and receipt core are total: every field is serialized (null when absent) and verifiers require all of them. Verifiers check the version tags, recompute envelope_id and receipt_id, require envelope_hash and receipt_hash, validate ISO-8601 UTC timestamps, and accept only the exact 86-character unpadded base64url signature encoding.
- An unsigned receipt may not name a did:key as issuer; verification_status must agree with the algorithm; the receipt_id override was removed because the id is derived.
- resolveSigner accepts a 64-hex seed string as well as PEM.
- Bridge summaries describe the bridge receipt (issuer, algorithm, status), link the applied stack's receipt separately, and are derivable from the records alone (source event, analysis and run ids fall back to the conversion record), so a registry recomputes the same summary without trusting the submitted one; recordSubjectId gives one subject precedence for registries.
- Conformance vectors version 2 (60 cases, 8 suites): hash references, both base58 and did:key directions, chained and detached envelopes, a legacy receipt, and 26 rejections a verifier must refuse. An implementation conforms only with zero skipped suites.
- Package ships CHANGELOG.md and omits the vector generator; the tag-creating release workflow was removed because tags it created could not trigger publishing.

## 0.2.0 - 2026-10-16

- canonicalJson follows RFC 8785 exactly; non-finite numbers and BigInt are rejected.
- ed25519 identity as did:key, key pair helpers, resolveSigner.
- state-envelope/1: signed, chainable, detachable envelope over any payload.
- state-receipt/1: signed append-only receipt chain; legacy and unsigned modes are labelled.
- identity and authorization record constructors; payload profile ids.
- Bridge artifacts carry a real protocol receipt.
- Conformance vectors (version 1) anchored to RFC 8785, RFC 8032 and the did:key specification, with a runner for other implementations.
- Apache-2.0 license, README, release playbook, publish workflow.

## 0.1.0

- Canonical JSON and hashing helpers, receipt payload helpers, state-record constructors and the applied-stack bridge artifact.
