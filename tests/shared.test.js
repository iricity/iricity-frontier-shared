import test from "node:test";
import assert from "node:assert/strict";
import {
  CANONICAL_STATE_RECORD_TYPES,
  normalizeSpaceEventToStateRecord,
  buildStateBridgeArtifact
} from "../src/index.js";

test("exposes canonical state record types", () => {
  assert.ok(CANONICAL_STATE_RECORD_TYPES.includes("entity"));
  assert.ok(CANONICAL_STATE_RECORD_TYPES.includes("receipt"));
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

