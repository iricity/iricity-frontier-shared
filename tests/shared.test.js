import test from "node:test";
import assert from "node:assert/strict";
import {
  CANONICAL_STATE_RECORD_TYPES,
  canonicalReceiptPayload,
  buildReceiptSignatureStatus,
  buildReceiptVerificationResponse,
  hashPayload,
  normalizeSpaceEventToStateRecord,
  buildStateBridgeArtifact
} from "../src/index.js";

test("exposes canonical state record types", () => {
  assert.ok(CANONICAL_STATE_RECORD_TYPES.includes("entity"));
  assert.ok(CANONICAL_STATE_RECORD_TYPES.includes("receipt"));
});

test("hashPayload is deterministic for structured input", () => {
  const a = hashPayload({ b: 2, a: 1 });
  const b = hashPayload({ a: 1, b: 2 });

  assert.equal(a, b);
  assert.match(a, /^sha256:/);
});

test("canonicalReceiptPayload preserves the verification fields", () => {
  const payload = canonicalReceiptPayload({
    receipt_id: "rcp_1",
    event_id: "evt_1",
    action: "process",
    payload_hash: "sha256:abc",
    prev_receipt_hash: "sha256:def",
    timestamp: "2026-01-01T00:00:00Z",
    status: "issued",
    extra: "ignored"
  });

  assert.deepEqual(payload, {
    receipt_id: "rcp_1",
    event_id: "evt_1",
    action: "process",
    payload_hash: "sha256:abc",
    prev_receipt_hash: "sha256:def",
    timestamp: "2026-01-01T00:00:00Z",
    status: "issued"
  });
});

test("buildReceiptSignatureStatus maps receipt metadata", () => {
  const status = buildReceiptSignatureStatus(
    {
      receipt_signature_key_id: "key-1",
      receipt_signature_algorithm: "ed25519"
    },
    {
      public_verifiability: "portable_public_key_verification",
      production_grade: "asymmetric_production_ready"
    },
    true
  );

  assert.deepEqual(status, {
    verified: true,
    key_id: "key-1",
    algorithm: "ed25519",
    verification_material: "public_key",
    public_verifiability: "portable_public_key_verification",
    production_grade: "asymmetric_production_ready"
  });
});

test("buildReceiptVerificationResponse can include or omit signature details", () => {
  const withSignature = buildReceiptVerificationResponse({
    receipt: {
      receipt_id: "rcp_1",
      action: "process",
      receipt_signature_key_id: "key-1",
      receipt_signature_algorithm: "ed25519"
    },
    signingProfile: {
      public_verifiability: "portable_public_key_verification",
      production_grade: "asymmetric_production_ready"
    },
    verified: true,
    errors: [],
    checks: ["hash_match"]
  });

  const withoutSignature = buildReceiptVerificationResponse({
    receipt: {
      receipt_id: "rcp_1",
      action: "process"
    },
    signingProfile: {
      public_verifiability: "portable_public_key_verification",
      production_grade: "asymmetric_production_ready"
    },
    verified: false,
    errors: ["Receipt hash mismatch"],
    checks: ["hash_match"],
    includeSignature: false
  });

  assert.equal(withSignature.signature.algorithm, "ed25519");
  assert.equal(withSignature.verified, true);
  assert.equal(withoutSignature.signature, undefined);
  assert.equal(withoutSignature.verified, false);
});

test("normalizes a space event into a state record", () => {
  const record = normalizeSpaceEventToStateRecord({
    event_id: "evt_1",
    source: "mock",
    event_type: "space_observation",
    timestamp: "2026-01-01T00:00:00Z",
    payload: { hello: "world" }
  });

  assert.equal(record.record_type, "entity");
  assert.equal(record.entity_id, "evt_1");
});

test("builds a bridge artifact", () => {
  const artifact = buildStateBridgeArtifact({
    event: {
      event_id: "evt_1",
      source: "mock",
      event_type: "space_observation",
      timestamp: "2026-01-01T00:00:00Z",
      payload: { hello: "world" },
      payload_hash: "sha256:abc"
    },
    analysis: { analysis_id: "ana_1" },
    receipt: { receipt_id: "rcp_1", receipt_hash: "prev" },
    run: { completed_at: "2026-01-01T00:00:01Z" }
  });

  assert.equal(artifact.bridge_type, "state_stack_conversion");
  assert.equal(artifact.conversion_record.record_type, "conversion");
  assert.equal(artifact.receipt.record_type, "receipt");
});
