/**
 * State-record constructors and the bridge artifact that applied stacks hand to the
 * state stack. The embedded receipt is a real protocol receipt, signed when a signer
 * is supplied, and the summary always describes that receipt (never the applied
 * stack's own receipt, which is kept as a link).
 */

import { hashPayload, isHashRef } from '../utils/hash.js';
import { createReceiptRecord } from '../records/receipt.js';

export const CANONICAL_STATE_RECORD_TYPES = [
  'entity',
  'authorization',
  'time',
  'navigation',
  'measurement',
  'communication',
  'command',
  'resource',
  'constraint',
  'conversion',
  'transition',
  'receipt'
];

const BRIDGE_ADAPTER_VERSION = '0.3.0';

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
    verification_material: algorithm === 'ed25519' ? 'public_key' : 'shared_secret',
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

/** The subject a normalized record is about; one precedence order shared with registries. */
export function recordSubjectId(record) {
  if (!record || typeof record !== 'object') return null;
  return (
    record.subject_id ??
    record.entity_id ??
    record.message_id ??
    record.command_id ??
    record.transition_id ??
    record.sensor_id ??
    record.receipt_id ??
    record.source_node ??
    record.resource_type ??
    null
  );
}

/**
 * Summary of a bridge. `receipt` is the bridge receipt (the protocol receipt over the
 * conversion record); `linkedReceipt` is the applied stack's own receipt, if any.
 */
export function buildStateBridgeSummary({
  event,
  analysis,
  receipt,
  linkedReceipt = null,
  run,
  normalizedRecord,
  conversionRecord,
  bridgeType = 'state_stack_conversion'
}) {
  // Everything the summary names must be derivable from the records alone, so a
  // registry recomputes the same summary without trusting the submitted one.
  const sourceSystem = event?.source || conversionRecord?.source_system || 'mock';
  const sourceEventId = event?.event_id || conversionRecord?.source_event_id || null;
  const sourceAnalysisId = analysis?.analysis_id || conversionRecord?.source_analysis_id || null;
  const runId = run?.run_id || conversionRecord?.run_id || null;
  const normalizedRecordType = normalizedRecord?.record_type || null;
  const normalizedSubjectId = recordSubjectId(normalizedRecord);
  const normalizedRecordHash = normalizedRecord ? hashPayload(normalizedRecord) : null;
  const conversionRecordHash = conversionRecord ? hashPayload(conversionRecord) : null;
  const issuedAt = receipt?.timestamp || conversionRecord?.ingested_at || run?.completed_at || null;
  const bridgeId = `bridge_${hashPayload({
    bridge_type: bridgeType,
    source_system: sourceSystem,
    source_event_id: sourceEventId,
    source_analysis_id: sourceAnalysisId,
    run_id: runId,
    normalized_record_hash: normalizedRecordHash,
    conversion_record_hash: conversionRecordHash,
    receipt_id: receipt?.receipt_id || null,
    issued_at: issuedAt
  }).slice(7, 23)}`;

  return {
    bridge_id: bridgeId,
    bridge_type: bridgeType,
    source_system: sourceSystem,
    source_event_id: sourceEventId,
    source_analysis_id: sourceAnalysisId,
    run_id: runId,
    normalized_record_type: normalizedRecordType,
    normalized_subject_id: normalizedSubjectId,
    normalized_record_hash: normalizedRecordHash,
    conversion_record_hash: conversionRecordHash,
    receipt_id: receipt?.receipt_id || null,
    receipt_issuer: receipt?.issuer || null,
    receipt_signature_algorithm: receipt?.signature_algorithm || null,
    linked_receipt_id: linkedReceipt?.receipt_id || null,
    conversion_rule: conversionRecord?.conversion_rule || null,
    issued_at: issuedAt,
    status: receipt?.verification_status || 'unsigned'
  };
}

export function toStateEntityRecord(event, options = {}) {
  return {
    record_type: 'entity',
    entity_id: options.entity_id || event.event_id,
    entity_type: options.entity_type || 'space_event',
    controller_id: options.controller_id || event.source || 'mock',
    status: event.status || 'processed',
    created_at: event.timestamp || nowIso(),
    metadata_hash: options.metadata_hash || hashPayload(event.payload ?? event)
  };
}

export function toStateNavigationRecord(event, options = {}) {
  return {
    record_type: 'navigation',
    entity_id: options.entity_id || event.entity_id || event.event_id || event.source || 'unknown',
    reference_frame: options.reference_frame || 'earth-fixed',
    latitude: options.latitude ?? event.payload?.latitude ?? null,
    longitude: options.longitude ?? event.payload?.longitude ?? null,
    altitude: options.altitude ?? event.payload?.altitude ?? null,
    velocity: options.velocity ?? event.payload?.velocity ?? null,
    heading: options.heading ?? event.payload?.heading ?? null,
    attitude: options.attitude ?? event.payload?.attitude ?? null,
    uncertainty: options.uncertainty ?? event.payload?.uncertainty ?? null,
    sensor_source: options.sensor_source || event.source || 'mock',
    timestamp: event.timestamp || nowIso()
  };
}

export function toStateMeasurementRecord(event, options = {}) {
  return {
    record_type: 'measurement',
    sensor_id: options.sensor_id || event.source || 'mock',
    measurement_type: options.measurement_type || event.event_type || 'space_observation',
    value: options.value ?? event.payload ?? event,
    unit: options.unit || 'opaque',
    uncertainty: options.uncertainty ?? null,
    calibration_id: options.calibration_id || null,
    timestamp: event.timestamp || nowIso(),
    source: event.source || 'mock'
  };
}

export function toStateCommunicationRecord(event, options = {}) {
  return {
    record_type: 'communication',
    message_id: options.message_id || event.event_id,
    source_node: options.source_node || event.source || 'mock',
    destination_node: options.destination_node || 'unknown',
    payload_hash: options.payload_hash || hashPayload(event.payload ?? event),
    route: options.route || 'space-stack',
    timestamp: event.timestamp || nowIso(),
    delivery_status: options.delivery_status || 'recorded',
    security_profile: options.security_profile || 'baseline'
  };
}

export function normalizeSpaceEventToStateRecord(event, options = {}) {
  const kind = String(options.kind || event.event_type || 'entity');
  if (kind.includes('communication')) return toStateCommunicationRecord(event, options);
  if (kind.includes('measure') || kind.includes('sensor')) return toStateMeasurementRecord(event, options);
  if (kind.includes('nav') || kind.includes('orbit') || kind.includes('position')) return toStateNavigationRecord(event, options);
  return toStateEntityRecord(event, options);
}

/**
 * Build the artifact an applied stack hands to the state stack.
 * @param {object} args
 * @param {object} args.event
 * @param {object} [args.analysis]
 * @param {object} [args.receipt]   the applied stack's own receipt (linked, not re-signed)
 * @param {object} [args.run]
 * @param {object|string} [args.signer]  when given, the bridge receipt is ed25519-signed
 */
export function buildStateBridgeArtifact({ event, analysis, receipt, run, signer = null }) {
  const timestamp = run?.completed_at || nowIso();
  const normalizedRecord = normalizeSpaceEventToStateRecord(event, {
    kind: event?.event_type || 'entity',
    entity_id: event?.event_id,
    controller_id: event?.source || 'mock',
    metadata_hash: hashPayload(event?.payload ?? event)
  });

  const conversionRecord = {
    record_type: 'conversion',
    source_system: event?.source || 'mock',
    source_format: 'space_stack_event',
    raw_record_hash: isHashRef(event?.payload_hash) ? event.payload_hash : hashPayload(event?.payload ?? event),
    adapter_name: 'iricity-space-stack-state-bridge',
    adapter_version: BRIDGE_ADAPTER_VERSION,
    normalized_record_hash: hashPayload(normalizedRecord),
    conversion_rule: 'space_event_to_state_entity',
    ingested_at: timestamp,
    receipt_id: receipt?.receipt_id || null,
    source_event_id: event?.event_id || null,
    source_analysis_id: analysis?.analysis_id || null,
    run_id: run?.run_id || null
  };

  const linkedReceiptHash = receipt?.receipt_hash;
  const bridgeReceipt = createReceiptRecord({
    record: conversionRecord,
    previous_hash: isHashRef(linkedReceiptHash) ? linkedReceiptHash : null,
    issuer: signer || 'iricity-space-stack',
    timestamp
  });
  if (receipt?.receipt_id) bridgeReceipt.linked_receipt_id = receipt.receipt_id;

  const summary = buildStateBridgeSummary({
    event,
    analysis,
    receipt: bridgeReceipt,
    linkedReceipt: receipt || null,
    run,
    normalizedRecord,
    conversionRecord
  });

  return {
    bridge_type: 'state_stack_conversion',
    summary,
    normalized_record: normalizedRecord,
    conversion_record: conversionRecord,
    receipt: bridgeReceipt
  };
}
