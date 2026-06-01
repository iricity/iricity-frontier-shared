import { createHash } from "node:crypto";

export const CANONICAL_STATE_RECORD_TYPES = [
  "entity",
  "authorization",
  "time",
  "navigation",
  "measurement",
  "communication",
  "command",
  "resource",
  "constraint",
  "conversion",
  "transition",
  "receipt"
];

function nowIso() {
  return new Date().toISOString();
}

function sha256Hex(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}

export function toStateEntityRecord(event, options = {}) {
  return {
    record_type: "entity",
    entity_id: options.entity_id || event.event_id,
    entity_type: options.entity_type || "space_event",
    controller_id: options.controller_id || event.source || "mock",
    status: event.status || "processed",
    created_at: event.timestamp || nowIso(),
    metadata_hash: options.metadata_hash || sha256Hex(event.payload ?? event)
  };
}

export function toStateNavigationRecord(event, options = {}) {
  return {
    record_type: "navigation",
    entity_id: options.entity_id || event.entity_id || event.event_id || event.source || "unknown",
    reference_frame: options.reference_frame || "earth-fixed",
    latitude: options.latitude ?? event.payload?.latitude ?? null,
    longitude: options.longitude ?? event.payload?.longitude ?? null,
    altitude: options.altitude ?? event.payload?.altitude ?? null,
    velocity: options.velocity ?? event.payload?.velocity ?? null,
    heading: options.heading ?? event.payload?.heading ?? null,
    attitude: options.attitude ?? event.payload?.attitude ?? null,
    uncertainty: options.uncertainty ?? event.payload?.uncertainty ?? null,
    sensor_source: options.sensor_source || event.source || "mock",
    timestamp: event.timestamp || nowIso()
  };
}

export function toStateMeasurementRecord(event, options = {}) {
  return {
    record_type: "measurement",
    sensor_id: options.sensor_id || event.source || "mock",
    measurement_type: options.measurement_type || event.event_type || "space_observation",
    value: options.value ?? event.payload ?? event,
    unit: options.unit || "opaque",
    uncertainty: options.uncertainty ?? null,
    calibration_id: options.calibration_id || null,
    timestamp: event.timestamp || nowIso(),
    source: event.source || "mock"
  };
}

export function toStateCommunicationRecord(event, options = {}) {
  return {
    record_type: "communication",
    message_id: options.message_id || event.event_id,
    source_node: options.source_node || event.source || "mock",
    destination_node: options.destination_node || "unknown",
    payload_hash: options.payload_hash || sha256Hex(event.payload ?? event),
    route: options.route || "space-stack",
    timestamp: event.timestamp || nowIso(),
    delivery_status: options.delivery_status || "recorded",
    security_profile: options.security_profile || "baseline"
  };
}

export function normalizeSpaceEventToStateRecord(event, options = {}) {
  const kind = String(options.kind || event.event_type || "entity");
  if (kind.includes("communication")) return toStateCommunicationRecord(event, options);
  if (kind.includes("measure") || kind.includes("sensor")) return toStateMeasurementRecord(event, options);
  if (kind.includes("nav") || kind.includes("orbit") || kind.includes("position")) return toStateNavigationRecord(event, options);
  return toStateEntityRecord(event, options);
}

export function buildStateBridgeArtifact({ event, analysis, receipt, run }) {
  const timestamp = run?.completed_at || nowIso();
  const normalizedRecord = normalizeSpaceEventToStateRecord(event, {
    kind: event?.event_type || "entity",
    entity_id: event?.event_id,
    controller_id: event?.source || "mock",
    metadata_hash: sha256Hex(event?.payload ?? event)
  });

  const conversionRecord = {
    record_type: "conversion",
    source_system: event?.source || "mock",
    source_format: "space_stack_event",
    raw_record_hash: event?.payload_hash || sha256Hex(event?.payload ?? event),
    adapter_name: "iricity-space-stack-state-bridge",
    adapter_version: "0.1.0",
    normalized_record_hash: sha256Hex(normalizedRecord),
    conversion_rule: "space_event_to_state_entity",
    ingested_at: timestamp,
    receipt_id: receipt?.receipt_id || null,
    source_event_id: event?.event_id || null,
    source_analysis_id: analysis?.analysis_id || null
  };

  const recordHash = sha256Hex(conversionRecord);

  return {
    bridge_type: "state_stack_conversion",
    normalized_record: normalizedRecord,
    conversion_record: conversionRecord,
    receipt: {
      record_type: "receipt",
      receipt_id: `rcp_${recordHash.slice(0, 16)}`,
      record_hash: recordHash,
      previous_hash: receipt?.receipt_hash || null,
      timestamp,
      issuer: "iricity-space-stack",
      signature: sha256Hex({
        record_hash: recordHash,
        issuer: "iricity-space-stack",
        timestamp
      }),
      verification_status: "issued"
    }
  };
}
