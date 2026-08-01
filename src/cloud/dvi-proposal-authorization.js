import {
  authorizationBindingFor,
  logicalAuthorityKeyFor
} from "./authority-identity.js";
import { normalizedDviAuthorizationFor } from "./authority-store.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const ACTION_KIND = "dispatch_rescue_unit";
const INPUT_FIELDS = Object.freeze([
  "expectedIncidentId",
  "expectedRunId",
  "logicalAction",
  "requestedSelectedEvidenceDigest",
  "requestedSelectedEvidenceId",
  "retrievalId",
  "tenantId"
]);
const LOGICAL_ACTION_FIELDS = Object.freeze([
  "actionKind",
  "agency",
  "incidentId",
  "payload",
  "resourceId",
  "tenantId"
]);

export const DVI_PROPOSAL_AUTHORIZATION_SQL = `
  SELECT *
  FROM tp_api.g1_authorize_dvi_proposal_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::UUID,
    $6, $7, $8, $9, $10::JSONB
  )
`;

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactObject(value, fields, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      JSON.stringify(Object.keys(value).sort()) ===
        JSON.stringify([...fields].sort()),
    code
  );
  return value;
}

function text(value, name, maximum) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    value.trim() !== value
  ) {
    throw new TypeError(`${name} must be bounded canonical text`);
  }
  return value;
}

function uuid(value, name) {
  const accepted = text(value, name, 36).toLowerCase();
  if (!UUID.test(accepted)) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return accepted;
}

function sha256(value, name) {
  const accepted = text(value, name, 64);
  if (!SHA256.test(accepted)) {
    throw new TypeError(`${name} must be lowercase SHA-256 hex`);
  }
  return accepted;
}

function jsonObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
  return JSON.parse(JSON.stringify(value));
}

function timestamp(value, name) {
  if (typeof value !== "string" && !(value instanceof Date)) {
    throw new TypeError(`${name} must be a database timestamp`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    throw new TypeError(`${name} must be a database timestamp`);
  }
  return parsed.toISOString();
}

function epoch(value) {
  const accepted = Number(value);
  if (
    !Number.isSafeInteger(accepted) ||
    accepted < 1 ||
    String(accepted) !== String(value)
  ) {
    throw new TypeError("database authorization epoch outside policy");
  }
  return accepted;
}

function normalizeInput(input) {
  exactObject(input, INPUT_FIELDS, "DVI_PROPOSAL_AUTHORIZATION_INPUT_SHAPE");
  const logicalAction = exactObject(
    input.logicalAction,
    LOGICAL_ACTION_FIELDS,
    "DVI_PROPOSAL_LOGICAL_ACTION_SHAPE"
  );
  const tenantId = uuid(input.tenantId, "tenantId");
  const expectedRunId = uuid(input.expectedRunId, "expectedRunId");
  const expectedIncidentId = uuid(
    input.expectedIncidentId,
    "expectedIncidentId"
  );
  const normalizedAction = {
    tenantId: uuid(logicalAction.tenantId, "logicalAction.tenantId"),
    incidentId: uuid(
      logicalAction.incidentId,
      "logicalAction.incidentId"
    ),
    resourceId: text(logicalAction.resourceId, "resourceId", 256),
    agency: text(logicalAction.agency, "agency", 128),
    actionKind: text(logicalAction.actionKind, "actionKind", 64),
    payload: jsonObject(logicalAction.payload, "payload")
  };
  assert(
    normalizedAction.actionKind === ACTION_KIND,
    "DVI_PROPOSAL_ACTION_KIND_UNSUPPORTED"
  );
  assert(
    normalizedAction.tenantId === tenantId &&
      normalizedAction.incidentId === expectedIncidentId,
    "DVI_PROPOSAL_LOGICAL_ACTION_CONTEXT_MISMATCH"
  );
  return {
    tenantId,
    retrievalId: uuid(input.retrievalId, "retrievalId"),
    expectedRunId,
    expectedIncidentId,
    requestedSelectedEvidenceId: uuid(
      input.requestedSelectedEvidenceId,
      "requestedSelectedEvidenceId"
    ),
    requestedSelectedEvidenceDigest: sha256(
      input.requestedSelectedEvidenceDigest,
      "requestedSelectedEvidenceDigest"
    ),
    logicalAction: normalizedAction
  };
}

function denial(row, databaseNow) {
  assert(
    row.decision_outcome === "proposal_authorization_denied" &&
      typeof row.decision_reason === "string" &&
      row.decision_reason.length > 0 &&
      row.decision_authority_current === false,
    "DVI_PROPOSAL_DENIAL_INVALID"
  );
  return Object.freeze({
    outcome: row.decision_outcome,
    reason: row.decision_reason,
    authorizationCurrent: false,
    databaseNow
  });
}

export async function authorizeDviProposalWithClient(client, input) {
  assert(client && typeof client.query === "function", "DVI_PROPOSAL_CLIENT_REQUIRED");
  const accepted = normalizeInput(input);
  const result = await client.query(DVI_PROPOSAL_AUTHORIZATION_SQL, [
    accepted.tenantId,
    accepted.retrievalId,
    accepted.expectedRunId,
    accepted.expectedIncidentId,
    accepted.requestedSelectedEvidenceId,
    accepted.requestedSelectedEvidenceDigest,
    accepted.logicalAction.resourceId,
    accepted.logicalAction.agency,
    accepted.logicalAction.actionKind,
    JSON.stringify(accepted.logicalAction.payload)
  ]);
  assert(
    result?.rowCount === 1 && Array.isArray(result.rows),
    "DVI_PROPOSAL_AUTHORIZATION_RESULT_INVALID"
  );
  const row = result.rows[0];
  const databaseNow = timestamp(
    row.decision_database_now,
    "decision_database_now"
  );
  if (row.decision_outcome === "proposal_authorization_denied") {
    return denial(row, databaseNow);
  }
  assert(
    ["proposal_authorized", "proposal_authorization_replay"].includes(
      row.decision_outcome
    ) && row.decision_reason === null,
    "DVI_PROPOSAL_AUTHORIZATION_OUTCOME_INVALID"
  );
  const authorizationEpoch = epoch(row.decision_authorization_epoch);
  const dviAuthorization = {
    dviProposal: {
      tenantId: accepted.tenantId,
      runId: uuid(row.decision_run_id, "decision_run_id"),
      incidentId: uuid(row.decision_incident_id, "decision_incident_id"),
      retrievalId: accepted.retrievalId,
      authorityEvidenceBindingSha256: sha256(
        row.decision_authority_evidence_binding_sha256,
        "decision_authority_evidence_binding_sha256"
      ),
      selectedEvidenceId: uuid(
        row.decision_selected_evidence_id,
        "decision_selected_evidence_id"
      ),
      selectedEvidenceDigest: sha256(
        row.decision_selected_evidence_digest,
        "decision_selected_evidence_digest"
      ),
      policyVersion: text(
        row.decision_policy_version,
        "decision_policy_version",
        128
      ),
      selectedRank: Number(row.decision_selected_rank),
      admittedAt: timestamp(row.decision_admitted_at, "decision_admitted_at"),
      expiresAt: timestamp(row.decision_expires_at, "decision_expires_at")
    },
    selectedEvidenceId: accepted.requestedSelectedEvidenceId,
    selectedEvidenceDigest: accepted.requestedSelectedEvidenceDigest
  };
  const normalized = normalizedDviAuthorizationFor({
    ...dviAuthorization,
    logicalAction: accepted.logicalAction
  });
  assert(
    normalized.dviProposal.runId === accepted.expectedRunId &&
      normalized.dviProposal.incidentId === accepted.expectedIncidentId &&
      normalized.selectedEvidenceId === accepted.requestedSelectedEvidenceId &&
      normalized.selectedEvidenceDigest ===
        accepted.requestedSelectedEvidenceDigest &&
      normalized.logicalActionDigest === row.decision_logical_action_digest &&
      normalized.proposalDigest === row.decision_proposal_digest &&
      normalized.logicalAction.payloadDigest === row.decision_payload_digest,
    "DVI_PROPOSAL_DATABASE_IDENTITY_MISMATCH"
  );
  const logicalAuthority = logicalAuthorityKeyFor({
    logicalActionDigest: normalized.logicalActionDigest,
    authorizationEpoch
  });
  const binding = authorizationBindingFor({
    logicalActionDigest: normalized.logicalActionDigest,
    proposalDigest: normalized.proposalDigest,
    authorizationEpoch
  });
  assert(
    logicalAuthority.logicalAuthorityKeySha256 ===
      row.decision_logical_authority_key_sha256 &&
      binding.authorizationBindingSha256 ===
        row.decision_authorization_binding_sha256 &&
      typeof row.decision_authority_current === "boolean" &&
      (row.decision_outcome !== "proposal_authorized" ||
        row.decision_authority_current === true),
    "DVI_PROPOSAL_DATABASE_BINDING_MISMATCH"
  );
  return Object.freeze({
    outcome: row.decision_outcome,
    reason: null,
    dviAuthorization: Object.freeze(dviAuthorization),
    identity: Object.freeze({
      proposalDigest: normalized.proposalDigest,
      logicalActionDigest: normalized.logicalActionDigest,
      authorizationEpoch,
      logicalAuthorityKeySha256:
        logicalAuthority.logicalAuthorityKeySha256,
      authorizationBindingSha256: binding.authorizationBindingSha256
    }),
    authorizationCurrent: row.decision_authority_current,
    authorizedAt: timestamp(row.decision_authorized_at, "decision_authorized_at"),
    databaseNow
  });
}

export const __test = Object.freeze({ normalizeInput });
