import { hashPayload } from './utils/hash.js';

export { canonicalJson } from './utils/canonicalJson.js';
export { sha256Hex, hashPayload, hashRecord } from './utils/hash.js';

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

export function canonicalReceiptPayload(receipt) {
  return {
    receipt_id: receipt.receipt_id,
    event_id: receipt.event_id,
    action: receipt.action,
    payload_hash: receipt.payload_hash,
    prev_receipt_hash: receipt.prev_receipt_hash,
    timestamp: receipt.timestamp,
    status: receipt.status
  };
}

export function buildReceiptSignatureStatus(receipt, signingProfile, verified) {
  const algorithm = receipt.receipt_signature_algorithm || null;
  return {
    verified,
    key_id: receipt.receipt_signature_key_id || null,
    algorithm,
    verification_material: algorithm === "ed25519" ? "public_key" : "shared_secret",
    public_verifiability: signingProfile.public_verifiability,
    production_grade: signingProfile.production_grade
  };
}

export function buildReceiptVerificationResponse({
  receipt,
  signingProfile,
  verified,
  errors = [],
  checks = [],
  includeSignature = true
}) {
  const response = {
    verified,
    receipt_id: receipt.receipt_id,
    action: receipt.action,
    errors,
    checks
  };

  if (includeSignature) {
    response.signature = buildReceiptSignatureStatus(receipt, signingProfile, verified);
  }

  return response;
}

export function buildStateBridgeSummary({
  event,
  analysis,
  receipt,
  run,
  normalizedRecord,
  conversionRecord,
  bridgeType = "state_stack_conversion"
}) {
  const sourceSystem = event?.source || conversionRecord?.source_system || "mock";
  const sourceEventId = event?.event_id || null;
  const sourceAnalysisId = analysis?.analysis_id || null;
  const normalizedRecordType = normalizedRecord?.record_type || null;
  const normalizedSubjectId =
    normalizedRecord?.subject_id ||
    normalizedRecord?.entity_id ||
    normalizedRecord?.message_id ||
    normalizedRecord?.sensor_id ||
    normalizedRecord?.command_id ||
    normalizedRecord?.resource_type ||
    normalizedRecord?.transition_id ||
    null;
  const normalizedRecordHash = normalizedRecord ? hashPayload(normalizedRecord) : null;
  const conversionRecordHash = conversionRecord ? hashPayload(conversionRecord) : null;
  const issuedAt = receipt?.timestamp || conversionRecord?.ingested_at || run?.completed_at || null;
  const bridgeId = `bridge_${hashPayload({
    bridge_type: bridgeType,
    source_system: sourceSystem,
    source_event_id: sourceEventId,
    source_analysis_id: sourceAnalysisId,
    run_id: run?.run_id || null,
    normalized_record_hash: normalizedRecordHash,
    conversion_record_hash: conversionRecordHash,
    receipt_id: receipt?.receipt_id || null,
    issued_at: issuedAt
  }).slice(0, 16)}`;

  return {
    bridge_id: bridgeId,
    bridge_type: bridgeType,
    source_system: sourceSystem,
    source_event_id: sourceEventId,
    source_analysis_id: sourceAnalysisId,
    run_id: run?.run_id || null,
    normalized_record_type: normalizedRecordType,
    normalized_subject_id: normalizedSubjectId,
    normalized_record_hash: normalizedRecordHash,
    conversion_record_hash: conversionRecordHash,
    receipt_id: receipt?.receipt_id || null,
    conversion_rule: conversionRecord?.conversion_rule || null,
    issued_at: issuedAt,
    status: receipt?.verification_status || "issued"
  };
}

export function toStateEntityRecord(event, options = {}) {
  return {
    record_type: "entity",
    entity_id: options.entity_id || event.event_id,
    entity_type: options.entity_type || "space_event",
    controller_id: options.controller_id || event.source || "mock",
    status: event.status || "processed",
    created_at: event.timestamp || nowIso(),
    metadata_hash: options.metadata_hash || hashPayload(event.payload ?? event)
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
    payload_hash: options.payload_hash || hashPayload(event.payload ?? event),
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
    metadata_hash: hashPayload(event?.payload ?? event)
  });

  const conversionRecord = {
    record_type: "conversion",
    source_system: event?.source || "mock",
    source_format: "space_stack_event",
    raw_record_hash: event?.payload_hash || hashPayload(event?.payload ?? event),
    adapter_name: "iricity-space-stack-state-bridge",
    adapter_version: "0.1.0",
    normalized_record_hash: hashPayload(normalizedRecord),
    conversion_rule: "space_event_to_state_entity",
    ingested_at: timestamp,
    receipt_id: receipt?.receipt_id || null,
    source_event_id: event?.event_id || null,
    source_analysis_id: analysis?.analysis_id || null
  };

  const recordHash = hashPayload(conversionRecord);
  const summary = buildStateBridgeSummary({
    event,
    analysis,
    receipt,
    run,
    normalizedRecord,
    conversionRecord
  });

  return {
    bridge_type: "state_stack_conversion",
    summary,
    normalized_record: normalizedRecord,
    conversion_record: conversionRecord,
    receipt: {
      record_type: "receipt",
      receipt_id: `rcp_${recordHash.slice(0, 16)}`,
      record_hash: recordHash,
      previous_hash: receipt?.receipt_hash || null,
      timestamp,
      issuer: "iricity-space-stack",
      signature: hashPayload({
        record_hash: recordHash,
        issuer: "iricity-space-stack",
        timestamp
      }),
      verification_status: "issued"
    }
  };
}
