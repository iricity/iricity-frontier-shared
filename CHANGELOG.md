# Changelog

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
