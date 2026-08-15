import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from "node:crypto";
import { Client, Pool } from "pg";
import {
  bootstrapDatabaseConfig,
  connectionStringForExactDatabase,
  runtimeDatabaseConfig
} from "./database-runtime.js";
import {
  committedDatabaseResult,
  databaseTimestampFromDriver,
  nonDurableDatabaseResult,
  unknownDatabaseResult
} from "./database-commit-result.js";
import {
  authorizationBindingFor,
  dispatchPayloadFor,
  dviProposalIdentityDigestFor,
  dviProposalIdentityFor,
  logicalActionDigestFor,
  logicalAuthorityKeyFor
} from "./authority-identity.js";
import { canonicalJson } from "./canonical-json.js";
import {
  dviSelectionBindingSha256For,
  dviSelectionReceiptFor
} from "./dvi-selection.js";

const RETRYABLE_TRANSACTION_CODE = "40001";
const AMBIGUOUS_TRANSACTION_CODE = "40003";
const DEFAULT_MAX_RETRIES = 20;
const DEFAULT_RETRY_DEADLINE_MS = 30_000;
const MIN_LEASE_MS = 1_000;
const MAX_LEASE_MS = 10 * 60_000;
const POLICY_VERSION = "gate1-policy-v2";
const ACTION_KIND = "dispatch_rescue_unit";
const DVI_PROPOSAL_INPUT_FIELDS = Object.freeze([
  "tenantId",
  "runId",
  "incidentId",
  "retrievalId",
  "authorityEvidenceBindingSha256",
  "selectedEvidenceId",
  "selectedEvidenceDigest",
  "policyVersion",
  "selectedRank",
  "admittedAt",
  "expiresAt"
]);
const DVI_AUTHORIZATION_FIELDS = Object.freeze([
  "dviProposal",
  "selectedEvidenceId",
  "selectedEvidenceDigest",
  "logicalAction"
]);
const REQUEST_DVI_AUTHORIZATION_FIELDS = Object.freeze([
  "dviProposal",
  "selectedEvidenceId",
  "selectedEvidenceDigest"
]);
const LOGICAL_ACTION_INPUT_FIELDS = Object.freeze([
  "tenantId",
  "incidentId",
  "resourceId",
  "agency",
  "actionKind",
  "payload"
]);

function requireExactObject(value, fields, code) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    JSON.stringify(Object.keys(value).sort()) !==
      JSON.stringify([...fields].sort())
  ) {
    throw new TypeError(code);
  }
  return value;
}

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function requireUuid(value, name) {
  const text = requireText(value, name);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      text
    )
  ) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text.toLowerCase();
}

function requireSha256(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(text)) {
    throw new TypeError(`${name} must be a lowercase SHA-256 hex digest`);
  }
  return text;
}

function requireLeaseMs(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_LEASE_MS ||
    value > MAX_LEASE_MS
  ) {
    throw new RangeError(
      `leaseMs must be an integer from ${MIN_LEASE_MS} through ${MAX_LEASE_MS}`
    );
  }
  return value;
}

function requireTimestamp(value, name) {
  const text = requireText(value, name);
  if (!Number.isFinite(Date.parse(text))) {
    throw new TypeError(`${name} must be an ISO-compatible timestamp`);
  }
  return new Date(text).toISOString();
}

function requireEmbedding(value) {
  if (
    !Array.isArray(value) ||
    value.length !== 3 ||
    value.some((entry) => !Number.isFinite(entry))
  ) {
    throw new TypeError("embedding must contain exactly three finite numbers");
  }
  return `[${value.join(",")}]`;
}

function requireBase64(value, name) {
  const text = requireText(value, name);
  const bytes = Buffer.from(text, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== text) {
    throw new TypeError(`${name} must be canonical base64`);
  }
  return { text, bytes };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function connectionStringForDatabase(connectionString, databaseName) {
  return connectionStringForExactDatabase(connectionString, databaseName);
}

function normalizeLogicalActionInput(input) {
  requireExactObject(
    input,
    LOGICAL_ACTION_INPUT_FIELDS,
    "AUTHORITY_LOGICAL_ACTION_INPUT_SHAPE"
  );
  const payload = dispatchPayloadFor(input.payload);
  const actionKind = requireText(input.actionKind, "logicalAction.actionKind");
  if (actionKind !== ACTION_KIND) {
    throw new TypeError("AUTHORITY_ACTION_KIND_UNSUPPORTED");
  }
  const logicalAction = {
    tenantId: requireUuid(input.tenantId, "logicalAction.tenantId"),
    incidentId: requireUuid(input.incidentId, "logicalAction.incidentId"),
    resourceId: requireText(input.resourceId, "logicalAction.resourceId"),
    agency: requireText(input.agency, "logicalAction.agency"),
    actionKind,
    payload,
    payloadDigest: sha256(canonicalJson(payload))
  };
  return {
    ...logicalAction,
    logicalActionDigest: logicalActionDigestFor({
      tenantId: logicalAction.tenantId,
      incidentId: logicalAction.incidentId,
      resourceId: logicalAction.resourceId,
      agency: logicalAction.agency,
      actionKind: logicalAction.actionKind,
      payloadDigest: logicalAction.payloadDigest
    })
  };
}

function normalizeProposalInput(input, logicalAction) {
  requireExactObject(
    input,
    DVI_PROPOSAL_INPUT_FIELDS,
    "AUTHORITY_DVI_PROPOSAL_INPUT_SHAPE"
  );
  const proposalInput = {
    tenantId: requireUuid(input.tenantId, "dviProposal.tenantId"),
    runId: requireUuid(input.runId, "dviProposal.runId"),
    incidentId: requireUuid(input.incidentId, "dviProposal.incidentId"),
    retrievalId: requireUuid(input.retrievalId, "dviProposal.retrievalId"),
    logicalActionDigest: logicalAction.logicalActionDigest,
    authorityEvidenceBindingSha256: requireSha256(
      input.authorityEvidenceBindingSha256,
      "dviProposal.authorityEvidenceBindingSha256"
    ),
    selectedEvidenceId: requireUuid(
      input.selectedEvidenceId,
      "dviProposal.selectedEvidenceId"
    ),
    selectedEvidenceDigest: requireSha256(
      input.selectedEvidenceDigest,
      "dviProposal.selectedEvidenceDigest"
    ),
    policyVersion: requireText(
      input.policyVersion,
      "dviProposal.policyVersion"
    ),
    selectedRank: input.selectedRank,
    admittedAt: requireTimestamp(input.admittedAt, "dviProposal.admittedAt"),
    expiresAt: requireTimestamp(input.expiresAt, "dviProposal.expiresAt")
  };
  if (
    proposalInput.tenantId !== logicalAction.tenantId ||
    proposalInput.incidentId !== logicalAction.incidentId
  ) {
    throw new TypeError("AUTHORITY_PROPOSAL_REQUEST_MISMATCH");
  }
  return {
    dviProposal: dviProposalIdentityFor(proposalInput),
    proposalDigest: dviProposalIdentityDigestFor(proposalInput)
  };
}

export function normalizedDviAuthorizationFor(input) {
  requireExactObject(
    input,
    DVI_AUTHORIZATION_FIELDS,
    "AUTHORITY_DVI_AUTHORIZATION_SHAPE"
  );
  if (
    input.authorizationEpoch !== undefined ||
    input.logicalAuthorityKeySha256 !== undefined
  ) {
    throw new TypeError("AUTHORITY_DATABASE_OWNED_IDENTITY");
  }
  const logicalAction = normalizeLogicalActionInput(input.logicalAction);
  const proposal = normalizeProposalInput(input.dviProposal, logicalAction);
  const selectedEvidenceId = requireUuid(
    input.selectedEvidenceId,
    "selectedEvidenceId"
  );
  const selectedEvidenceDigest = requireSha256(
    input.selectedEvidenceDigest,
    "selectedEvidenceDigest"
  );
  if (
    proposal.dviProposal.selectedEvidenceId !== selectedEvidenceId ||
    proposal.dviProposal.selectedEvidenceDigest !== selectedEvidenceDigest
  ) {
    throw new TypeError("AUTHORITY_DVI_SELECTION_MISMATCH");
  }
  return Object.freeze({
    logicalAction,
    logicalActionDigest: logicalAction.logicalActionDigest,
    dviProposal: proposal.dviProposal,
    proposalDigest: proposal.proposalDigest,
    selectedEvidenceId,
    selectedEvidenceDigest
  });
}

function authorizationEpochFromRow(value) {
  const epoch = Number(value);
  if (
    !Number.isSafeInteger(epoch) ||
    epoch < 1 ||
    String(epoch) !== String(value)
  ) {
    throw new InvariantViolationError(
      "database authorization epoch is outside the runtime identity contract"
    );
  }
  return epoch;
}

function proposalReceiptMatches(row, authorization) {
  if (!row) {
    return false;
  }
  const epoch = authorizationEpochFromRow(row.authorization_epoch);
  const logicalAuthority = logicalAuthorityKeyFor({
    logicalActionDigest: authorization.logicalActionDigest,
    authorizationEpoch: epoch
  });
  const binding = authorizationBindingFor({
    logicalActionDigest: authorization.logicalActionDigest,
    proposalDigest: authorization.proposalDigest,
    authorizationEpoch: epoch
  });
  return (
    row.tenant_id === authorization.logicalAction.tenantId &&
    row.proposal_digest === authorization.proposalDigest &&
    row.logical_action_digest === authorization.logicalActionDigest &&
    row.resource_id === authorization.logicalAction.resourceId &&
    row.agency === authorization.logicalAction.agency &&
    row.action_kind === authorization.logicalAction.actionKind &&
    row.payload_digest === authorization.logicalAction.payloadDigest &&
    row.payload_canonical === canonicalJson(authorization.logicalAction.payload) &&
    canonicalJson(row.payload) ===
      canonicalJson(authorization.logicalAction.payload) &&
    row.retrieval_id === authorization.dviProposal.retrievalId &&
    row.run_id === authorization.dviProposal.runId &&
    row.incident_id === authorization.dviProposal.incidentId &&
    row.authority_evidence_binding_sha256 ===
      authorization.dviProposal.authorityEvidenceBindingSha256 &&
    row.policy_version === authorization.dviProposal.policyVersion &&
    Number(row.selected_rank) === authorization.dviProposal.selectedRank &&
    row.selected_evidence_id === authorization.selectedEvidenceId &&
    row.selected_evidence_digest === authorization.selectedEvidenceDigest &&
    new Date(row.admitted_at).toISOString() ===
      authorization.dviProposal.admittedAt &&
    new Date(row.expires_at).toISOString() ===
      authorization.dviProposal.expiresAt &&
    row.logical_authority_key_sha256 ===
      logicalAuthority.logicalAuthorityKeySha256 &&
    row.authorization_binding_sha256 ===
      binding.authorizationBindingSha256
  );
}

function dviSelectionReceiptInputFromRow(row) {
  return {
    sourceCommit: row.source_commit,
    treeDigest: row.tree_digest,
    specSha256: row.spec_sha256,
    runId: row.run_id,
    tenantId: row.tenant_id,
    incidentId: row.incident_id,
    retrievalId: row.retrieval_id,
    agency: row.agency,
    policyVersion: row.policy_version,
    admittedAt: new Date(row.admitted_at).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
    rankedSequenceSha256: row.ranked_sequence_sha256,
    queryEmbeddingSha256: row.query_embedding_sha256,
    resultLimit: Number(row.result_limit),
    selectedRank: Number(row.selected_rank),
    selectedEvidenceId: row.selected_evidence_id,
    selectedEvidenceDigest: row.selected_evidence_digest
  };
}

function dviSelectionReceiptMatches(row, authorization) {
  if (!row) {
    return false;
  }
  const receiptInput = dviSelectionReceiptInputFromRow(row);
  return (
    row.authority_evidence_binding_sha256 ===
      authorization.dviProposal.authorityEvidenceBindingSha256 &&
    dviSelectionBindingSha256For(receiptInput) ===
      authorization.dviProposal.authorityEvidenceBindingSha256 &&
    receiptInput.tenantId === authorization.logicalAction.tenantId &&
    receiptInput.runId === authorization.dviProposal.runId &&
    receiptInput.incidentId === authorization.logicalAction.incidentId &&
    receiptInput.retrievalId === authorization.dviProposal.retrievalId &&
    receiptInput.agency === authorization.logicalAction.agency &&
    receiptInput.policyVersion === authorization.dviProposal.policyVersion &&
    receiptInput.admittedAt === authorization.dviProposal.admittedAt &&
    receiptInput.expiresAt === authorization.dviProposal.expiresAt &&
    receiptInput.selectedRank === authorization.dviProposal.selectedRank &&
    receiptInput.selectedEvidenceId === authorization.selectedEvidenceId &&
    receiptInput.selectedEvidenceDigest ===
      authorization.selectedEvidenceDigest
  );
}

function normalizeRequest(input) {
  if (
    input.at !== undefined ||
    input.authorizationTime !== undefined ||
    input.clientNow !== undefined ||
    input.now !== undefined ||
    input.leaseExpiresAt !== undefined
  ) {
    throw new TypeError(
      "authorization and lease time are database-controlled"
    );
  }
  const payload = dispatchPayloadFor(
    Object.hasOwn(input, "payload")
      ? input.payload
      : {
          scenario: "synthetic-highwater",
          action: ACTION_KIND
        }
  );
  const dviAuthorization = requireExactObject(
    input.dviAuthorization,
    REQUEST_DVI_AUTHORIZATION_FIELDS,
    "AUTHORITY_DVI_AUTHORIZATION_SHAPE"
  );
  const normalized = {
    digestVersion: 2,
    tenantId: requireUuid(input.tenantId, "tenantId"),
    runId: requireUuid(input.runId, "runId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    resourceId: requireText(input.resourceId, "resourceId"),
    operationId: requireUuid(input.operationId, "operationId"),
    agentId: requireText(input.agentId, "agentId"),
    agency: requireText(input.agency, "agency"),
    evidenceId: requireUuid(input.evidenceId, "evidenceId"),
    intentNonce: requireUuid(input.intentNonce, "intentNonce"),
    effectKey: requireUuid(input.effectKey, "effectKey"),
    leaseMs: requireLeaseMs(input.leaseMs ?? 300_000),
    policyVersion: POLICY_VERSION,
    actionKind: ACTION_KIND,
    payload,
    payloadDigest: sha256(canonicalJson(payload))
  };
  const logicalAction = normalizeLogicalActionInput({
    tenantId: normalized.tenantId,
    incidentId: normalized.incidentId,
    resourceId: normalized.resourceId,
    agency: normalized.agency,
    actionKind: normalized.actionKind,
    payload: normalized.payload
  });
  const proposal = normalizeProposalInput(
    dviAuthorization.dviProposal,
    logicalAction
  );
  if (
    proposal.dviProposal.runId !== normalized.runId ||
    proposal.dviProposal.tenantId !== normalized.tenantId ||
    proposal.dviProposal.incidentId !== normalized.incidentId
  ) {
    throw new TypeError("AUTHORITY_PROPOSAL_REQUEST_MISMATCH");
  }
  const selectedEvidenceId = requireUuid(
    dviAuthorization.selectedEvidenceId,
    "dviAuthorization.selectedEvidenceId"
  );
  if (selectedEvidenceId !== normalized.evidenceId) {
    throw new TypeError("AUTHORITY_SELECTED_EVIDENCE_MISMATCH");
  }
  const selectedEvidenceDigest = requireSha256(
    dviAuthorization.selectedEvidenceDigest,
    "dviAuthorization.selectedEvidenceDigest"
  );
  if (
    proposal.dviProposal.selectedEvidenceId !== selectedEvidenceId ||
    proposal.dviProposal.selectedEvidenceDigest !== selectedEvidenceDigest
  ) {
    throw new TypeError("AUTHORITY_DVI_SELECTION_MISMATCH");
  }
  const semanticPayload = {
    digestVersion: normalized.digestVersion,
    tenantId: normalized.tenantId,
    runId: normalized.runId,
    incidentId: normalized.incidentId,
    resourceId: normalized.resourceId,
    agentId: normalized.agentId,
    agency: normalized.agency,
    evidenceId: normalized.evidenceId,
    intentNonce: normalized.intentNonce,
    effectKey: normalized.effectKey,
    leaseMs: normalized.leaseMs,
    policyVersion: normalized.policyVersion,
    actionKind: normalized.actionKind,
    payloadDigest: normalized.payloadDigest,
    logicalActionDigest: logicalAction.logicalActionDigest,
    proposalDigest: proposal.proposalDigest,
    selectedEvidenceId,
    selectedEvidenceDigest
  };
  return {
    ...normalized,
    logicalActionDigest: logicalAction.logicalActionDigest,
    dviProposal: proposal.dviProposal,
    proposalDigest: proposal.proposalDigest,
    selectedEvidenceId,
    selectedEvidenceDigest,
    requestPayload: semanticPayload,
    requestDigest: sha256(canonicalJson(semanticPayload))
  };
}

function dviAuthorizationFromRequest(request) {
  return {
    logicalAction: {
      tenantId: request.tenantId,
      incidentId: request.incidentId,
      resourceId: request.resourceId,
      agency: request.agency,
      actionKind: request.actionKind,
      payload: request.payload,
      payloadDigest: request.payloadDigest,
      logicalActionDigest: request.logicalActionDigest
    },
    logicalActionDigest: request.logicalActionDigest,
    dviProposal: request.dviProposal,
    proposalDigest: request.proposalDigest,
    selectedEvidenceId: request.selectedEvidenceId,
    selectedEvidenceDigest: request.selectedEvidenceDigest
  };
}

export function requestDigestFor(input) {
  return normalizeRequest(input).requestDigest;
}

export function normalizedAuthorityRequestFor(input) {
  return normalizeRequest(input);
}

export function isRetryableTransactionError(error) {
  return error?.code === RETRYABLE_TRANSACTION_CODE;
}

export function isAmbiguousTransactionError(error) {
  return error?.code === AMBIGUOUS_TRANSACTION_CODE;
}

export function databaseFailureRequiresReconciliation(
  error,
  { commitDispatched = false } = {}
) {
  return commitDispatched || isAmbiguousTransactionError(error);
}

export function normalizeAuthorityReconciliationRow(row, request) {
  const replayKind = row?.reconciliation_kind;
  const allowedOutcomes = new Set([
    "authorization_denied",
    "resource_held_denied",
    "resource_reserved"
  ]);
  const requestPayload = row?.request_payload;
  const requestPayloadKeys = request?.requestPayload
    ? Object.keys(request.requestPayload).sort()
    : [];
  const sameRequestPayloadShape =
    requestPayload &&
    typeof requestPayload === "object" &&
    !Array.isArray(requestPayload) &&
    JSON.stringify(Object.keys(requestPayload).sort()) ===
      JSON.stringify(requestPayloadKeys);
  const proposalSelectedEvidenceId =
    row?.receipt_proposal_selected_evidence_id;
  const proposalSelectedEvidenceDigest =
    row?.receipt_proposal_selected_evidence_digest;
  if (
    !row ||
    !allowedOutcomes.has(row.outcome) ||
    ![
      "operation_replay",
      "semantic_replay",
      "logical_authority_replay"
    ].includes(replayKind) ||
    !sameRequestPayloadShape ||
    sha256(canonicalJson(requestPayload)) !== row.request_digest ||
    requestPayload.digestVersion !== 2 ||
    requestPayload.tenantId !== row.tenant_id ||
    requestPayload.runId !== row.run_id ||
    requestPayload.incidentId !== row.incident_id ||
    requestPayload.resourceId !== row.resource_id ||
    requestPayload.agentId !== row.agent_id ||
    requestPayload.agency !== row.agency ||
    requestPayload.evidenceId !== row.evidence_id ||
    requestPayload.selectedEvidenceId !== row.evidence_id ||
    requestPayload.selectedEvidenceId !== proposalSelectedEvidenceId ||
    requestPayload.selectedEvidenceDigest !==
      proposalSelectedEvidenceDigest ||
    requestPayload.effectKey !== row.effect_key ||
    requestPayload.payloadDigest !== row.payload_digest ||
    requestPayload.policyVersion !== row.policy_version ||
    requestPayload.logicalActionDigest !== row.logical_action_digest ||
    requestPayload.proposalDigest !== row.proposal_digest ||
    requestPayload.actionKind !== ACTION_KIND ||
    !Number.isSafeInteger(requestPayload.leaseMs) ||
    requestPayload.leaseMs < MIN_LEASE_MS ||
    requestPayload.leaseMs > MAX_LEASE_MS ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      requestPayload.intentNonce ?? ""
    ) ||
    row.logical_action_digest !== request.logicalActionDigest
  ) {
    throw new InvariantViolationError(
      "authority reconciliation receipt binding mismatch"
    );
  }

  const storedEpoch = authorizationEpochFromRow(row.authorization_epoch);
  const storedLogicalAuthority = logicalAuthorityKeyFor({
    logicalActionDigest: row.logical_action_digest,
    authorizationEpoch: storedEpoch
  });
  const storedAuthorizationBinding = authorizationBindingFor({
    logicalActionDigest: row.logical_action_digest,
    proposalDigest: row.proposal_digest,
    authorizationEpoch: storedEpoch
  });
  let proposalExpiresAt;
  try {
    const proposalPayload = dispatchPayloadFor(
      row.receipt_proposal_payload
    );
    const proposalPayloadDigest = requireSha256(
      row.receipt_proposal_payload_digest,
      "receiptProposal.payloadDigest"
    );
    const proposalInput = {
      tenantId: requireUuid(
        row.receipt_proposal_tenant_id,
        "receiptProposal.tenantId"
      ),
      runId: requireUuid(
        row.receipt_proposal_run_id,
        "receiptProposal.runId"
      ),
      incidentId: requireUuid(
        row.receipt_proposal_incident_id,
        "receiptProposal.incidentId"
      ),
      retrievalId: requireUuid(
        row.receipt_proposal_retrieval_id,
        "receiptProposal.retrievalId"
      ),
      logicalActionDigest: requireSha256(
        row.receipt_proposal_logical_action_digest,
        "receiptProposal.logicalActionDigest"
      ),
      authorityEvidenceBindingSha256: requireSha256(
        row.receipt_proposal_authority_evidence_binding_sha256,
        "receiptProposal.authorityEvidenceBindingSha256"
      ),
      selectedEvidenceId: requireUuid(
        proposalSelectedEvidenceId,
        "receiptProposal.selectedEvidenceId"
      ),
      selectedEvidenceDigest: requireSha256(
        proposalSelectedEvidenceDigest,
        "receiptProposal.selectedEvidenceDigest"
      ),
      policyVersion: requireText(
        row.receipt_proposal_policy_version,
        "receiptProposal.policyVersion"
      ),
      selectedRank: Number(row.receipt_proposal_selected_rank),
      admittedAt: databaseTimestampFromDriver(
        row.receipt_proposal_admitted_at,
        "receiptProposal.admittedAt"
      ),
      expiresAt: databaseTimestampFromDriver(
        row.receipt_proposal_expires_at,
        "receiptProposal.expiresAt"
      )
    };
    const proposalEpoch = authorizationEpochFromRow(
      row.receipt_proposal_authorization_epoch
    );
    const proposalLogicalActionDigest = logicalActionDigestFor({
      tenantId: proposalInput.tenantId,
      incidentId: proposalInput.incidentId,
      resourceId: row.receipt_proposal_resource_id,
      agency: row.receipt_proposal_agency,
      actionKind: row.receipt_proposal_action_kind,
      payloadDigest: proposalPayloadDigest
    });
    if (
      proposalInput.tenantId !== request.tenantId ||
      row.receipt_proposal_digest !== row.proposal_digest ||
      proposalInput.logicalActionDigest !== row.logical_action_digest ||
      proposalLogicalActionDigest !== row.logical_action_digest ||
      row.receipt_proposal_resource_id !== row.resource_id ||
      row.receipt_proposal_agency !== row.agency ||
      row.receipt_proposal_action_kind !== ACTION_KIND ||
      canonicalJson(proposalPayload) !==
        row.receipt_proposal_payload_canonical ||
      sha256(canonicalJson(proposalPayload)) !== proposalPayloadDigest ||
      proposalPayloadDigest !== row.payload_digest ||
      proposalInput.runId !== row.run_id ||
      proposalInput.incidentId !== row.incident_id ||
      proposalInput.selectedEvidenceId !== row.evidence_id ||
      dviProposalIdentityDigestFor(proposalInput) !== row.proposal_digest ||
      proposalEpoch !== storedEpoch ||
      row.receipt_proposal_logical_authority_key_sha256 !==
        storedLogicalAuthority.logicalAuthorityKeySha256 ||
      row.receipt_proposal_authorization_binding_sha256 !==
        storedAuthorizationBinding.authorizationBindingSha256
    ) {
      throw new Error("receipt proposal identity mismatch");
    }
    proposalExpiresAt = new Date(proposalInput.expiresAt).getTime();
  } catch {
    throw new InvariantViolationError(
      "authority reconciliation proposal binding mismatch"
    );
  }
  const exactRequestReplay = replayKind !== "logical_authority_replay";
  if (
    row.logical_authority_key_sha256 !==
      storedLogicalAuthority.logicalAuthorityKeySha256 ||
    row.authorization_binding_sha256 !==
      storedAuthorizationBinding.authorizationBindingSha256 ||
    (exactRequestReplay &&
      (row.request_digest !== request.requestDigest ||
        row.proposal_digest !== request.proposalDigest ||
        storedEpoch !== request.authorizationEpoch ||
        canonicalJson(requestPayload) !==
          canonicalJson(request.requestPayload))) ||
    (replayKind === "operation_replay" &&
      row.operation_id !== request.operationId) ||
    (replayKind === "logical_authority_replay" &&
      row.outcome !== "resource_reserved")
  ) {
    throw new InvariantViolationError(
      "authority reconciliation identity mismatch"
    );
  }

  const reason = row.reason ?? null;
  const fence =
    row.fencing_token === null || row.fencing_token === undefined
      ? null
      : String(row.fencing_token);
  const leaseExpiresAt =
    row.lease_expires_at === null || row.lease_expires_at === undefined
      ? null
      : new Date(row.lease_expires_at).getTime();
  const databaseNow = new Date(row.database_now).getTime();
  const resourceLeaseExpiresAt =
    row.resource_lease_expires_at === null ||
    row.resource_lease_expires_at === undefined
      ? null
      : new Date(row.resource_lease_expires_at).getTime();
  const observedFence =
    row.observed_fence === null || row.observed_fence === undefined
      ? null
      : String(row.observed_fence);
  const observedHolderOperationId =
    row.observed_holder_operation_id ?? null;
  const outboxFence =
    row.outbox_fencing_token === null ||
    row.outbox_fencing_token === undefined
      ? null
      : String(row.outbox_fencing_token);
  const winning = row.outcome === "resource_reserved";
  const hasOutboxState = [
    row.intent_id,
    row.outbox_operation_id,
    row.outbox_request_digest,
    row.outbox_proposal_digest,
    row.outbox_logical_action_digest,
    row.outbox_authorization_epoch,
    row.outbox_logical_authority_key_sha256,
    row.outbox_authorization_binding_sha256,
    row.outbox_run_id,
    row.outbox_incident_id,
    row.outbox_resource_id,
    row.outbox_effect_key,
    row.outbox_intent_kind,
    row.outbox_payload,
    row.outbox_payload_digest,
    row.outbox_fencing_token
  ].some((value) => value !== null && value !== undefined);
  const exactOutbox =
    row.intent_id &&
    row.outbox_operation_id === row.operation_id &&
    row.outbox_request_digest === row.request_digest &&
    row.outbox_proposal_digest === row.proposal_digest &&
    row.outbox_logical_action_digest === row.logical_action_digest &&
    authorizationEpochFromRow(row.outbox_authorization_epoch) ===
      storedEpoch &&
    row.outbox_logical_authority_key_sha256 ===
      row.logical_authority_key_sha256 &&
    row.outbox_authorization_binding_sha256 ===
      row.authorization_binding_sha256 &&
    row.outbox_run_id === row.run_id &&
    row.outbox_incident_id === row.incident_id &&
    row.outbox_resource_id === row.resource_id &&
    row.outbox_effect_key === row.effect_key &&
    row.outbox_intent_kind === ACTION_KIND &&
    row.outbox_payload &&
    typeof row.outbox_payload === "object" &&
    !Array.isArray(row.outbox_payload) &&
    row.receipt_proposal_payload &&
    typeof row.receipt_proposal_payload === "object" &&
    !Array.isArray(row.receipt_proposal_payload) &&
    canonicalJson(row.outbox_payload) ===
      canonicalJson(row.receipt_proposal_payload) &&
    canonicalJson(row.outbox_payload) === canonicalJson(request.payload) &&
    sha256(canonicalJson(row.outbox_payload)) ===
      row.outbox_payload_digest &&
    row.outbox_payload_digest === row.payload_digest &&
    outboxFence === fence;
  const selectedEvidenceMatches =
    row.evidence_id === proposalSelectedEvidenceId &&
    row.evidence_digest === proposalSelectedEvidenceDigest;
  if (
    !Number.isFinite(databaseNow) ||
    (winning &&
      (!exactOutbox ||
        !selectedEvidenceMatches ||
        reason !== null ||
        fence === null ||
        !/^[1-9][0-9]*$/.test(fence) ||
        !Number.isFinite(leaseExpiresAt) ||
        !Number.isFinite(resourceLeaseExpiresAt) ||
        !Number.isFinite(proposalExpiresAt))) ||
    (!winning &&
      (hasOutboxState ||
        typeof reason !== "string" ||
        reason.length === 0 ||
        fence !== null ||
        leaseExpiresAt !== null)) ||
    (row.outcome === "resource_held_denied" &&
      (reason !== "active_holder" ||
        !selectedEvidenceMatches ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          observedHolderOperationId ?? ""
        ) ||
        !/^[1-9][0-9]*$/.test(observedFence ?? ""))) ||
    (row.outcome === "authorization_denied" &&
      (reason === "active_holder" ||
        observedHolderOperationId !== null ||
        observedFence !== null)) ||
    (winning &&
      (observedHolderOperationId !== null || observedFence !== null)) ||
    (reason === "selected_evidence_digest_mismatch" &&
      (row.evidence_digest === null || selectedEvidenceMatches)) ||
    (reason === "evidence_missing" && row.evidence_digest !== null)
  ) {
    throw new InvariantViolationError(
      "authority reconciliation terminal state mismatch"
    );
  }

  const authorityStillCurrent =
    winning &&
    fence === String(row.current_fence) &&
    row.operation_id === row.holder_operation_id &&
    row.run_id === row.active_run_id &&
    row.proposal_digest === row.holder_proposal_digest &&
    row.logical_authority_key_sha256 ===
      row.holder_logical_authority_key_sha256 &&
    leaseExpiresAt > databaseNow &&
    resourceLeaseExpiresAt > databaseNow &&
    proposalExpiresAt > databaseNow;
  return {
    authorityStillCurrent,
    committedOutcome: row.outcome,
    storedEpoch
  };
}

function isTransportError(error) {
  return (
    ["ECONNRESET", "EPIPE", "ETIMEDOUT", "57P01", "57P02", "57P03"].includes(
      error?.code
    ) ||
    /connection (?:terminated|closed|lost)|socket|timeout/i.test(
      error?.message ?? ""
    )
  );
}

function evidenceDigestFor(row) {
  return sha256(
    canonicalJson({
      tenantId: row.tenant_id,
      evidenceId: row.evidence_id,
      incidentId: row.incident_id,
      issuer: row.issuer,
      agencyScope: row.agency_scope,
      claimKey: row.claim_key,
      claimValue: row.claim_value,
      verificationKeyId: row.verification_key_id,
      verifierVersion: row.verifier_version,
      signedPayloadDigest: row.signed_payload_digest,
      signatureDigest: row.signature_digest,
      observedAt: new Date(row.observed_at).toISOString(),
      validFrom: new Date(row.valid_from).toISOString(),
      validUntil: new Date(row.valid_until).toISOString(),
      provenanceStatus: row.provenance_status,
      conflictStatus: row.conflict_status,
      assertion: row.assertion,
      embedding: row.embedding
    })
  );
}

function normalizeEvidence(input) {
  return {
    tenantId: requireUuid(input.tenantId, "tenantId"),
    evidenceId: requireUuid(input.evidenceId, "evidenceId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    issuer: requireText(input.issuer, "issuer"),
    agencyScope: requireText(input.agencyScope, "agencyScope"),
    claimKey: requireText(input.claimKey, "claimKey"),
    claimValue: requireText(input.claimValue, "claimValue"),
    observedAt: requireTimestamp(input.observedAt, "observedAt"),
    validFrom: requireTimestamp(input.validFrom, "validFrom"),
    validUntil: requireTimestamp(input.validUntil, "validUntil"),
    conflictStatus: requireText(input.conflictStatus, "conflictStatus"),
    assertion: requireText(input.assertion, "assertion"),
    embedding: requireEmbedding(input.embedding)
  };
}

function signedEvidencePayloadFromNormalized(evidence) {
  return canonicalJson({
    digestVersion: 1,
    tenantId: evidence.tenantId,
    evidenceId: evidence.evidenceId,
    incidentId: evidence.incidentId,
    issuer: evidence.issuer,
    agencyScope: evidence.agencyScope,
    claimKey: evidence.claimKey,
    claimValue: evidence.claimValue,
    observedAt: evidence.observedAt,
    validFrom: evidence.validFrom,
    validUntil: evidence.validUntil,
    conflictStatus: evidence.conflictStatus,
    assertion: evidence.assertion,
    embedding: evidence.embedding
  });
}

export function signedEvidencePayloadFor(input) {
  return signedEvidencePayloadFromNormalized(normalizeEvidence(input));
}

export function signedEvidenceDigestFor(input) {
  return sha256(signedEvidencePayloadFor(input));
}

export function signedEvidenceEnvelopeFor(input) {
  const evidence = normalizeEvidence(input);
  const verificationKeyId = requireText(
    input.verificationKeyId,
    "verificationKeyId"
  );
  const verifierVersion = requireText(
    input.verifierVersion,
    "verifierVersion"
  );
  const signature = requireBase64(input.signatureBase64, "signatureBase64");
  const signedPayload = signedEvidencePayloadFromNormalized(evidence);
  const signedPayloadDigest = sha256(signedPayload);
  const signatureDigest = sha256(signature.bytes);
  const verificationRequestDigest = sha256(
    canonicalJson({
      digestVersion: 1,
      tenantId: evidence.tenantId,
      evidenceId: evidence.evidenceId,
      verificationKeyId,
      verifierVersion,
      signedPayloadDigest,
      signatureDigest
    })
  );
  const evidenceDigest = evidenceDigestFor({
    tenant_id: evidence.tenantId,
    evidence_id: evidence.evidenceId,
    incident_id: evidence.incidentId,
    issuer: evidence.issuer,
    agency_scope: evidence.agencyScope,
    claim_key: evidence.claimKey,
    claim_value: evidence.claimValue,
    verification_key_id: verificationKeyId,
    verifier_version: verifierVersion,
    signed_payload_digest: signedPayloadDigest,
    signature_digest: signatureDigest,
    observed_at: evidence.observedAt,
    valid_from: evidence.validFrom,
    valid_until: evidence.validUntil,
    provenance_status: "verified",
    conflict_status: evidence.conflictStatus,
    assertion: evidence.assertion,
    embedding: evidence.embedding
  });
  return {
    ...evidence,
    verificationKeyId,
    verifierVersion,
    signatureBase64: signature.text,
    signatureBytes: signature.bytes,
    signedPayload,
    signedPayloadDigest,
    signatureDigest,
    verificationRequestDigest,
    evidenceDigest
  };
}

function backoffMs(attempt) {
  const ceiling = Math.min(1_000, 25 * 2 ** attempt);
  return Math.floor(Math.random() * (ceiling + 1));
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Broken or already-resolved sessions may not accept ROLLBACK.
  }
}

function observeCommitDispatch(client, observer) {
  if (typeof observer !== "function") {
    return () => {};
  }
  const stream = client.connection?.stream;
  if (!stream || typeof stream.write !== "function") {
    throw new InvariantViolationError(
      "pg connection stream is unavailable for COMMIT dispatch observation"
    );
  }
  const originalWrite = stream.write;
  let observed = false;
  stream.write = function observedWrite(chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk, typeof encoding === "string" ? encoding : undefined);
    const isCommit = bytes.includes(Buffer.from("COMMIT\u0000"));
    if (!isCommit) {
      return originalWrite.apply(this, arguments);
    }

    const suppliedCallback =
      typeof encoding === "function" ? encoding : callback;
    const wrappedCallback = (...callbackArguments) => {
      suppliedCallback?.(...callbackArguments);
      if (!observed) {
        observed = true;
        observer();
      }
    };
    if (typeof encoding === "function" || encoding === undefined) {
      return originalWrite.call(this, chunk, wrappedCallback);
    }
    return originalWrite.call(this, chunk, encoding, wrappedCallback);
  };
  return () => {
    stream.write = originalWrite;
  };
}

export class AmbiguousCommitError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = "AmbiguousCommitError";
    this.code = "AMBIGUOUS_COMMIT";
  }
}

export class OperationDigestMismatchError extends Error {
  constructor(operationId) {
    super(`Operation ${operationId} was previously used with different input.`);
    this.name = "OperationDigestMismatchError";
    this.code = "OPERATION_DIGEST_MISMATCH";
  }
}

export class InvariantViolationError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvariantViolationError";
    this.code = "INVARIANT_VIOLATION";
  }
}

export class EffectKeyMismatchError extends Error {
  constructor(effectKey) {
    super(`Effect key ${effectKey} was previously used with different input.`);
    this.name = "EffectKeyMismatchError";
    this.code = "EFFECT_KEY_MISMATCH";
  }
}

export class EvidenceVerificationMismatchError extends Error {
  constructor(evidenceId) {
    super(
      `Evidence ${evidenceId} was previously verified with different input.`
    );
    this.name = "EvidenceVerificationMismatchError";
    this.code = "EVIDENCE_VERIFICATION_MISMATCH";
  }
}

export class AuthorityStore {
  #connectionString;
  #pool;

  constructor({
    connectionString,
    databaseName = "tideproof",
    maxConnections = 64
  } = {}) {
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#connectionString = connectionStringForDatabase(
      connectionString,
      databaseName
    );
    this.#pool = new Pool(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: maxConnections,
      idleTimeoutMillis: 10_000,
      applicationName: "tideproof-authority-runtime"
    }));
  }

  async close() {
    await this.#pool.end();
  }

  async migrate() {
    const bootstrapPool = new Pool(bootstrapDatabaseConfig({
      connectionString: this.#connectionString,
      max: 2,
      applicationName: "tideproof-authority-migrate"
    }));
    try {
    await bootstrapPool.query("CREATE SCHEMA IF NOT EXISTS tp_private");
    await bootstrapPool.query("CREATE SCHEMA IF NOT EXISTS tp_ledger");
    await bootstrapPool.query("CREATE SCHEMA IF NOT EXISTS tp_api");

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_evidence (
        tenant_id UUID NOT NULL,
        evidence_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        issuer STRING NOT NULL,
        agency_scope STRING NOT NULL,
        claim_key STRING NULL,
        claim_value STRING NULL,
        verification_key_id STRING NULL,
        verifier_version STRING NULL,
        signed_payload_digest STRING(64) NULL,
        signature_digest STRING(64) NULL,
        evidence_digest STRING(64) NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL,
        valid_until TIMESTAMPTZ NOT NULL,
        provenance_status STRING NOT NULL,
        conflict_status STRING NOT NULL,
        assertion STRING NOT NULL,
        embedding VECTOR(3) NOT NULL,
        ingested_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, evidence_id),
        CHECK (valid_until > valid_from),
        CHECK (provenance_status IN ('verified', 'invalid', 'revoked')),
        CHECK (conflict_status IN ('none', 'unresolved', 'resolved')),
        CHECK (
          signed_payload_digest IS NULL
          OR length(signed_payload_digest) = 64
        ),
        CHECK (signature_digest IS NULL OR length(signature_digest) = 64),
        CHECK (evidence_digest IS NULL OR length(evidence_digest) = 64)
      )
    `);
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS claim_key STRING NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS claim_value STRING NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS verification_key_id STRING NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS verifier_version STRING NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS signed_payload_digest STRING(64) NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS signature_digest STRING(64) NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS evidence_digest STRING(64) NULL"
    );

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_verification_keys (
        tenant_id UUID NOT NULL,
        verification_key_id STRING NOT NULL,
        issuer STRING NOT NULL,
        algorithm STRING NOT NULL,
        public_key_spki_base64 STRING NOT NULL,
        public_key_digest STRING(64) NOT NULL,
        status STRING NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL,
        valid_until TIMESTAMPTZ NOT NULL,
        registered_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        revoked_at TIMESTAMPTZ NULL,
        PRIMARY KEY (tenant_id, verification_key_id),
        CHECK (algorithm = 'ed25519'),
        CHECK (length(public_key_digest) = 64),
        CHECK (status IN ('active', 'revoked')),
        CHECK (valid_until > valid_from),
        CHECK (
          (status = 'active' AND revoked_at IS NULL)
          OR (status = 'revoked' AND revoked_at IS NOT NULL)
        )
      )
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_evidence_verification_receipts (
        tenant_id UUID NOT NULL,
        evidence_id UUID NOT NULL,
        verification_request_digest STRING(64) NOT NULL,
        incident_id UUID NOT NULL,
        issuer STRING NOT NULL,
        verification_key_id STRING NOT NULL,
        verifier_version STRING NOT NULL,
        signed_payload_digest STRING(64) NOT NULL,
        signature_digest STRING(64) NOT NULL,
        public_key_digest STRING(64) NULL,
        outcome STRING NOT NULL,
        reason STRING NULL,
        verified_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, evidence_id),
        UNIQUE (tenant_id, verification_request_digest),
        CHECK (length(verification_request_digest) = 64),
        CHECK (length(signed_payload_digest) = 64),
        CHECK (length(signature_digest) = 64),
        CHECK (
          public_key_digest IS NULL
          OR length(public_key_digest) = 64
        ),
        CHECK (outcome IN ('verified', 'rejected')),
        CHECK (
          (outcome = 'verified' AND reason IS NULL
            AND public_key_digest IS NOT NULL)
          OR (outcome = 'rejected' AND reason IS NOT NULL)
        )
      )
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_vector_retrieval_sets (
        tenant_id UUID NOT NULL,
        retrieval_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        agency STRING NOT NULL,
        policy_version STRING NOT NULL,
        admitted_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        cleaned_at TIMESTAMPTZ NULL,
        candidate_count INT8 NOT NULL,
        PRIMARY KEY (tenant_id, retrieval_id),
        CHECK (policy_version = 'g1-admissibility-v2'),
        CHECK (expires_at > admitted_at),
        CHECK (cleaned_at IS NULL OR cleaned_at >= admitted_at),
        CHECK (candidate_count >= 0 AND candidate_count <= 10000)
      )
    `);
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_vector_retrieval_sets ADD COLUMN IF NOT EXISTS cleaned_at TIMESTAMPTZ NULL"
    );
    await bootstrapPool.query(`
      CREATE INDEX IF NOT EXISTS g1_vector_retrieval_sets_expiry_idx
      ON tp_private.g1_vector_retrieval_sets (tenant_id, expires_at)
      STORING (retrieval_id, cleaned_at)
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_vector_candidates (
        tenant_id UUID NOT NULL,
        retrieval_id UUID NOT NULL,
        evidence_id UUID NOT NULL,
        evidence_digest STRING(64) NOT NULL,
        assertion STRING NOT NULL,
        embedding VECTOR(3) NOT NULL,
        PRIMARY KEY (tenant_id, retrieval_id, evidence_id),
        CHECK (length(evidence_digest) = 64),
        CHECK (octet_length(assertion) BETWEEN 1 AND 4096)
      )
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_vector_exclusions (
        tenant_id UUID NOT NULL,
        retrieval_id UUID NOT NULL,
        evidence_id UUID NOT NULL,
        evidence_digest STRING(64) NULL,
        admissibility STRING NOT NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (tenant_id, retrieval_id, evidence_id),
        FOREIGN KEY (tenant_id, retrieval_id)
          REFERENCES tp_private.g1_vector_retrieval_sets (
            tenant_id,
            retrieval_id
          ),
        CHECK (
          evidence_digest IS NULL
          OR length(evidence_digest) = 64
        ),
        CHECK (octet_length(admissibility) BETWEEN 1 AND 128),
        CHECK (admissibility <> 'admissible')
      )
    `);

    await bootstrapPool.query(`
      CREATE VECTOR INDEX IF NOT EXISTS
        g1_vector_candidates_embedding_idx
      ON tp_private.g1_vector_candidates
        (tenant_id, retrieval_id, embedding vector_cosine_ops)
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_resources (
        tenant_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        current_fence INT8 NOT NULL DEFAULT 0,
        active_run_id UUID NOT NULL,
        holder_incident_id UUID NULL,
        holder_operation_id UUID NULL,
        holder_agent_id STRING NULL,
        holder_proposal_digest STRING(64) NULL,
        holder_logical_authority_key_sha256 STRING(64) NULL,
        lease_expires_at TIMESTAMPTZ NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, resource_id),
        CHECK (current_fence >= 0),
        CHECK (
          (
            holder_incident_id IS NULL
            AND holder_operation_id IS NULL
            AND holder_agent_id IS NULL
            AND holder_proposal_digest IS NULL
            AND holder_logical_authority_key_sha256 IS NULL
            AND lease_expires_at IS NULL
          )
          OR
          (
            holder_incident_id IS NOT NULL
            AND holder_operation_id IS NOT NULL
            AND holder_agent_id IS NOT NULL
            AND holder_proposal_digest IS NOT NULL
            AND holder_logical_authority_key_sha256 IS NOT NULL
            AND lease_expires_at IS NOT NULL
          )
        )
      )
    `);

    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_resources ADD COLUMN IF NOT EXISTS holder_proposal_digest STRING(64) NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_private.g1_resources ADD COLUMN IF NOT EXISTS holder_logical_authority_key_sha256 STRING(64) NULL"
    );

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_retry_probes (
        tenant_id UUID NOT NULL,
        probe_id UUID NOT NULL,
        value INT8 NOT NULL,
        PRIMARY KEY (tenant_id, probe_id),
        CHECK (value >= 0)
      )
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_logical_authority_epochs (
        tenant_id UUID NOT NULL,
        logical_action_digest STRING(64) NOT NULL,
        current_epoch INT8 NOT NULL DEFAULT 0,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, logical_action_digest),
        CHECK (length(logical_action_digest) = 64),
        CHECK (current_epoch >= 0 AND current_epoch < 9223372036854775807)
      )
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_dvi_selection_receipts (
        tenant_id UUID NOT NULL,
        retrieval_id UUID NOT NULL,
        authority_evidence_binding_sha256 STRING(64) NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        agency STRING NOT NULL,
        policy_version STRING NOT NULL,
        source_commit STRING(40) NOT NULL,
        tree_digest STRING(40) NOT NULL,
        spec_sha256 STRING(64) NOT NULL,
        admitted_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        ranked_sequence_sha256 STRING(64) NOT NULL,
        query_embedding_sha256 STRING(64) NOT NULL,
        result_limit INT8 NOT NULL,
        selected_rank INT8 NOT NULL,
        selected_evidence_id UUID NOT NULL,
        selected_evidence_digest STRING(64) NOT NULL,
        committed_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, retrieval_id),
        UNIQUE (tenant_id, authority_evidence_binding_sha256),
        CHECK (policy_version = 'g1-admissibility-v2'),
        CHECK (length(source_commit) = 40),
        CHECK (length(tree_digest) = 40),
        CHECK (length(spec_sha256) = 64),
        CHECK (length(authority_evidence_binding_sha256) = 64),
        CHECK (length(ranked_sequence_sha256) = 64),
        CHECK (length(query_embedding_sha256) = 64),
        CHECK (result_limit >= 1 AND result_limit <= 100),
        CHECK (length(selected_evidence_digest) = 64),
        CHECK (selected_rank = 1),
        CHECK (expires_at > admitted_at)
      )
    `);
    await bootstrapPool.query(
      "ALTER TABLE tp_ledger.g1_dvi_selection_receipts ADD COLUMN IF NOT EXISTS query_embedding_sha256 STRING(64) NULL"
    );
    await bootstrapPool.query(
      "ALTER TABLE tp_ledger.g1_dvi_selection_receipts ADD COLUMN IF NOT EXISTS result_limit INT8 NULL"
    );

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_dvi_proposal_receipts (
        tenant_id UUID NOT NULL,
        proposal_digest STRING(64) NOT NULL,
        logical_action_digest STRING(64) NOT NULL,
        resource_id STRING NOT NULL,
        agency STRING NOT NULL,
        action_kind STRING NOT NULL,
        payload JSONB NOT NULL,
        payload_canonical STRING NOT NULL,
        payload_digest STRING(64) NOT NULL,
        retrieval_id UUID NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        authority_evidence_binding_sha256 STRING(64) NOT NULL,
        policy_version STRING NOT NULL,
        selected_rank INT8 NOT NULL,
        selected_evidence_id UUID NOT NULL,
        selected_evidence_digest STRING(64) NOT NULL,
        admitted_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        authorization_epoch INT8 NOT NULL,
        logical_authority_key_sha256 STRING(64) NOT NULL,
        authorization_binding_sha256 STRING(64) NOT NULL,
        authorized_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, proposal_digest),
        CHECK (length(proposal_digest) = 64),
        CHECK (length(logical_action_digest) = 64),
        CHECK (action_kind = 'dispatch_rescue_unit'),
        CHECK (jsonb_typeof(payload) = 'object'),
        CHECK (length(payload_canonical) > 1),
        CHECK (length(payload_digest) = 64),
        CHECK (length(authority_evidence_binding_sha256) = 64),
        CHECK (length(selected_evidence_digest) = 64),
        CHECK (length(logical_authority_key_sha256) = 64),
        CHECK (length(authorization_binding_sha256) = 64),
        CHECK (selected_rank = 1),
        CHECK (expires_at > admitted_at),
        CHECK (authorization_epoch > 0)
      )
    `);
    await bootstrapPool.query(`
      ALTER TABLE tp_ledger.g1_dvi_proposal_receipts
      DROP CONSTRAINT IF EXISTS
        g1_dvi_proposal_receipts_tenant_id_logical_action_digest_authorization_epoch_key
    `);
    await bootstrapPool.query(`
      ALTER TABLE tp_ledger.g1_dvi_proposal_receipts
      DROP CONSTRAINT IF EXISTS
        g1_dvi_proposal_receipts_tenant_id_logical_authority_key_sha256_key
    `);
    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
        g1_dvi_proposal_receipts_logical_epoch_idx
      ON tp_ledger.g1_dvi_proposal_receipts (
        tenant_id,
        logical_action_digest,
        authorization_epoch
      )
    `);
    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
        g1_dvi_proposal_receipts_logical_authority_key_idx
      ON tp_ledger.g1_dvi_proposal_receipts (
        tenant_id,
        logical_authority_key_sha256
      )
    `);
    for (const [column, definition] of [
      ["resource_id", "STRING NULL"],
      ["agency", "STRING NULL"],
      ["action_kind", "STRING NULL"],
      ["payload", "JSONB NULL"],
      ["payload_canonical", "STRING NULL"],
      ["payload_digest", "STRING(64) NULL"]
    ]) {
      await bootstrapPool.query(
        `ALTER TABLE tp_ledger.g1_dvi_proposal_receipts ADD COLUMN IF NOT EXISTS ${column} ${definition}`
      );
    }

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_authority_receipts (
        tenant_id UUID NOT NULL,
        operation_id UUID NOT NULL,
        request_digest STRING(64) NOT NULL,
        request_payload JSONB NOT NULL,
        proposal_digest STRING(64) NOT NULL,
        logical_action_digest STRING(64) NOT NULL,
        authorization_epoch INT8 NOT NULL,
        logical_authority_key_sha256 STRING(64) NOT NULL,
        authorization_binding_sha256 STRING(64) NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        agent_id STRING NOT NULL,
        agency STRING NOT NULL,
        evidence_id UUID NOT NULL,
        evidence_digest STRING(64) NULL,
        effect_key UUID NOT NULL,
        payload_digest STRING(64) NOT NULL,
        policy_version STRING NOT NULL,
        outcome STRING NOT NULL,
        reason STRING NULL,
        fencing_token INT8 NULL,
        observed_holder_operation_id UUID NULL,
        observed_fence INT8 NULL,
        lease_expires_at TIMESTAMPTZ NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, operation_id),
        UNIQUE (tenant_id, request_digest),
        CHECK (length(proposal_digest) = 64),
        CHECK (length(logical_action_digest) = 64),
        CHECK (authorization_epoch > 0),
        CHECK (length(logical_authority_key_sha256) = 64),
        CHECK (length(authorization_binding_sha256) = 64),
        CHECK (outcome IN (
          'pending',
          'resource_reserved',
          'resource_held_denied',
          'authorization_denied'
        )),
        CHECK (
          (
            outcome = 'resource_reserved'
            AND evidence_digest IS NOT NULL
            AND fencing_token IS NOT NULL
            AND fencing_token > 0
            AND lease_expires_at IS NOT NULL
          )
          OR outcome <> 'resource_reserved'
        )
      )
    `);
    for (const [column, definition] of [
      ["proposal_digest", "STRING(64) NULL"],
      ["logical_action_digest", "STRING(64) NULL"],
      ["authorization_epoch", "INT8 NULL"],
      ["logical_authority_key_sha256", "STRING(64) NULL"],
      ["authorization_binding_sha256", "STRING(64) NULL"]
    ]) {
      await bootstrapPool.query(
        `ALTER TABLE tp_ledger.g1_authority_receipts ADD COLUMN IF NOT EXISTS ${column} ${definition}`
      );
    }

    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_authority_spend
      ON tp_ledger.g1_authority_receipts (
        tenant_id,
        logical_authority_key_sha256
      )
      WHERE outcome = 'resource_reserved'
    `);

    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_action_spend
      ON tp_ledger.g1_authority_receipts (
        tenant_id,
        logical_action_digest
      )
      WHERE outcome = 'resource_reserved'
    `);

    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_winning_fence
      ON tp_ledger.g1_authority_receipts (
        tenant_id,
        resource_id,
        fencing_token
      )
      WHERE outcome = 'resource_reserved'
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_outbox_intents (
        tenant_id UUID NOT NULL,
        intent_id UUID NOT NULL DEFAULT gen_random_uuid(),
        operation_id UUID NOT NULL,
        request_digest STRING(64) NOT NULL,
        proposal_digest STRING(64) NOT NULL,
        logical_action_digest STRING(64) NOT NULL,
        authorization_epoch INT8 NOT NULL,
        logical_authority_key_sha256 STRING(64) NOT NULL,
        authorization_binding_sha256 STRING(64) NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        fencing_token INT8 NOT NULL,
        effect_key UUID NOT NULL,
        intent_kind STRING NOT NULL,
        payload JSONB NOT NULL,
        payload_digest STRING(64) NOT NULL,
        state STRING NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, intent_id),
        UNIQUE (tenant_id, operation_id),
        UNIQUE (tenant_id, effect_key),
        UNIQUE (tenant_id, logical_authority_key_sha256),
        CHECK (length(proposal_digest) = 64),
        CHECK (length(logical_action_digest) = 64),
        CHECK (authorization_epoch > 0),
        CHECK (length(logical_authority_key_sha256) = 64),
        CHECK (length(authorization_binding_sha256) = 64),
        CHECK (fencing_token > 0),
        CHECK (intent_kind = 'dispatch_rescue_unit'),
        CHECK (state IN ('pending', 'delivering', 'delivered', 'failed'))
      )
    `);
    for (const [column, definition] of [
      ["proposal_digest", "STRING(64) NULL"],
      ["logical_action_digest", "STRING(64) NULL"],
      ["authorization_epoch", "INT8 NULL"],
      ["logical_authority_key_sha256", "STRING(64) NULL"],
      ["authorization_binding_sha256", "STRING(64) NULL"]
    ]) {
      await bootstrapPool.query(
        `ALTER TABLE tp_ledger.g1_outbox_intents ADD COLUMN IF NOT EXISTS ${column} ${definition}`
      );
    }
    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_action_outbox
      ON tp_ledger.g1_outbox_intents (
        tenant_id,
        logical_action_digest
      )
    `);

    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_protected_effects (
        tenant_id UUID NOT NULL,
        effect_key UUID NOT NULL,
        operation_id UUID NOT NULL,
        request_digest STRING(64) NOT NULL,
        proposal_digest STRING(64) NOT NULL,
        logical_action_digest STRING(64) NOT NULL,
        authorization_epoch INT8 NOT NULL,
        logical_authority_key_sha256 STRING(64) NOT NULL,
        authorization_binding_sha256 STRING(64) NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        agent_id STRING NOT NULL,
        fencing_token INT8 NOT NULL,
        payload_digest STRING(64) NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, effect_key),
        UNIQUE (tenant_id, operation_id),
        UNIQUE (tenant_id, logical_authority_key_sha256),
        CHECK (length(proposal_digest) = 64),
        CHECK (length(logical_action_digest) = 64),
        CHECK (authorization_epoch > 0),
        CHECK (length(logical_authority_key_sha256) = 64),
        CHECK (length(authorization_binding_sha256) = 64),
        CHECK (fencing_token > 0)
      )
    `);
    for (const [column, definition] of [
      ["proposal_digest", "STRING(64) NULL"],
      ["logical_action_digest", "STRING(64) NULL"],
      ["authorization_epoch", "INT8 NULL"],
      ["logical_authority_key_sha256", "STRING(64) NULL"],
      ["authorization_binding_sha256", "STRING(64) NULL"]
    ]) {
      await bootstrapPool.query(
        `ALTER TABLE tp_ledger.g1_protected_effects ADD COLUMN IF NOT EXISTS ${column} ${definition}`
      );
    }
    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_logical_action_effect
      ON tp_ledger.g1_protected_effects (
        tenant_id,
        logical_action_digest
      )
    `);

    const legacyIdentityRows = await bootstrapPool.query(`
      SELECT
        (
          SELECT count(*)
          FROM tp_ledger.g1_authority_receipts
          WHERE proposal_digest IS NULL
            OR logical_action_digest IS NULL
            OR authorization_epoch IS NULL
            OR logical_authority_key_sha256 IS NULL
            OR authorization_binding_sha256 IS NULL
        ) + (
          SELECT count(*)
          FROM tp_ledger.g1_outbox_intents
          WHERE proposal_digest IS NULL
            OR logical_action_digest IS NULL
            OR authorization_epoch IS NULL
            OR logical_authority_key_sha256 IS NULL
            OR authorization_binding_sha256 IS NULL
        ) + (
          SELECT count(*)
          FROM tp_ledger.g1_protected_effects
          WHERE proposal_digest IS NULL
            OR logical_action_digest IS NULL
            OR authorization_epoch IS NULL
            OR logical_authority_key_sha256 IS NULL
            OR authorization_binding_sha256 IS NULL
        ) + (
          SELECT count(*)
          FROM tp_ledger.g1_dvi_proposal_receipts
          WHERE resource_id IS NULL
            OR agency IS NULL
            OR action_kind IS NULL
            OR payload IS NULL
            OR payload_canonical IS NULL
            OR payload_digest IS NULL
        ) + (
          SELECT count(*)
          FROM tp_private.g1_resources
          WHERE holder_operation_id IS NOT NULL
            AND (
              holder_proposal_digest IS NULL
              OR holder_logical_authority_key_sha256 IS NULL
            )
        ) AS legacy_rows
    `);
    if (Number(legacyIdentityRows.rows[0]?.legacy_rows ?? -1) !== 0) {
      throw new Error(
        "AUTHORITY_IDENTITY_LEGACY_ROWS_REQUIRE_DISPOSABLE_REBUILD"
      );
    }

    await bootstrapPool.query(`
      CREATE OR REPLACE VIEW tp_api.g1_recovery_bundle_v1 AS
      SELECT
        receipt.operation_id AS recovery_session_id,
        1::INT8 AS schema_version,
        receipt.recorded_at AS source_commit_ts,
        receipt.request_digest AS source_digest,
        receipt.policy_version,
        receipt.tenant_id,
        receipt.run_id,
        receipt.incident_id,
        receipt.resource_id,
        receipt.agent_id AS failed_agent_id,
        receipt.outcome,
        receipt.reason,
        receipt.evidence_digest,
        receipt.fencing_token AS committed_fencing_token,
        resource.current_fence,
        resource.holder_operation_id,
        resource.holder_agent_id,
        resource.lease_expires_at,
        outbox.intent_id,
        outbox.intent_kind,
        false AS authority_transferred,
        true AS requires_fresh_authorization,
        receipt.proposal_digest,
        receipt.logical_action_digest,
        receipt.authorization_epoch,
        receipt.logical_authority_key_sha256,
        receipt.authorization_binding_sha256
      FROM tp_ledger.g1_authority_receipts AS receipt
      LEFT JOIN tp_private.g1_resources AS resource
        ON resource.tenant_id = receipt.tenant_id
       AND resource.resource_id = receipt.resource_id
      LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = receipt.tenant_id
       AND outbox.operation_id = receipt.operation_id
    `);
    } finally {
      await bootstrapPool.end().catch(() => {});
    }
  }

  async registerVerificationKey(input) {
    const tenantId = requireUuid(input.tenantId, "tenantId");
    const verificationKeyId = requireText(
      input.verificationKeyId,
      "verificationKeyId"
    );
    const issuer = requireText(input.issuer, "issuer");
    const algorithm = requireText(
      input.algorithm ?? "ed25519",
      "algorithm"
    ).toLowerCase();
    if (algorithm !== "ed25519") {
      throw new TypeError("algorithm must be ed25519");
    }
    const publicKey = requireBase64(
      input.publicKeySpkiBase64,
      "publicKeySpkiBase64"
    );
    const parsedKey = createPublicKey({
      key: publicKey.bytes,
      format: "der",
      type: "spki"
    });
    if (parsedKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("publicKeySpkiBase64 must contain an Ed25519 key");
    }
    const publicKeyDigest = sha256(publicKey.bytes);
    const validFrom = requireTimestamp(input.validFrom, "validFrom");
    const validUntil = requireTimestamp(input.validUntil, "validUntil");
    if (Date.parse(validUntil) <= Date.parse(validFrom)) {
      throw new RangeError("verification key validUntil must follow validFrom");
    }

    return this.#runSerializable(async (client) => {
      const inserted = await client.query(
        `
          INSERT INTO tp_private.g1_verification_keys (
            tenant_id,
            verification_key_id,
            issuer,
            algorithm,
            public_key_spki_base64,
            public_key_digest,
            status,
            valid_from,
            valid_until
          )
          VALUES (
            $1::UUID,
            $2,
            $3,
            'ed25519',
            $4,
            $5,
            'active',
            $6::TIMESTAMPTZ,
            $7::TIMESTAMPTZ
          )
          ON CONFLICT DO NOTHING
          RETURNING *
        `,
        [
          tenantId,
          verificationKeyId,
          issuer,
          publicKey.text,
          publicKeyDigest,
          validFrom,
          validUntil
        ]
      );
      if (inserted.rowCount === 1) {
        return { outcome: "verification_key_registered", key: inserted.rows[0] };
      }
      const existing = await client.query(
        `
          SELECT *
          FROM tp_private.g1_verification_keys
          WHERE tenant_id = $1::UUID
            AND verification_key_id = $2
        `,
        [tenantId, verificationKeyId]
      );
      if (existing.rowCount !== 1) {
        throw new InvariantViolationError(
          "verification key conflict was not observable"
        );
      }
      const row = existing.rows[0];
      if (
        row.issuer !== issuer ||
        row.algorithm !== algorithm ||
        row.public_key_spki_base64 !== publicKey.text ||
        row.public_key_digest !== publicKeyDigest ||
        new Date(row.valid_from).toISOString() !== validFrom ||
        new Date(row.valid_until).toISOString() !== validUntil
      ) {
        throw new EvidenceVerificationMismatchError(verificationKeyId);
      }
      return { outcome: "verification_key_replay", key: row };
    });
  }

  async revokeVerificationKey({ tenantId, verificationKeyId }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const keyId = requireText(verificationKeyId, "verificationKeyId");
    return this.#runSerializable(async (client) => {
      const updated = await client.query(
        `
          UPDATE tp_private.g1_verification_keys
          SET status = 'revoked',
              revoked_at = COALESCE(revoked_at, transaction_timestamp())
          WHERE tenant_id = $1::UUID
            AND verification_key_id = $2
          RETURNING *
        `,
        [tenant, keyId]
      );
      if (updated.rowCount !== 1) {
        throw new InvariantViolationError("verification key does not exist");
      }
      return { outcome: "verification_key_revoked", key: updated.rows[0] };
    });
  }

  async appendSignedEvidence(input) {
    const evidence = signedEvidenceEnvelopeFor(input);
    const {
      verificationKeyId,
      verifierVersion,
      signedPayload,
      signedPayloadDigest,
      signatureDigest,
      verificationRequestDigest
    } = evidence;

    return this.#runSerializable(async (client) => {
      const byEvidence = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_evidence_verification_receipts
          WHERE tenant_id = $1::UUID
            AND evidence_id = $2::UUID
        `,
        [evidence.tenantId, evidence.evidenceId]
      );
      const byDigest = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_evidence_verification_receipts
          WHERE tenant_id = $1::UUID
            AND verification_request_digest = $2
        `,
        [evidence.tenantId, verificationRequestDigest]
      );
      const existingRows = [...byEvidence.rows];
      if (
        byDigest.rowCount === 1 &&
        !existingRows.some(
          ({ evidence_id }) => evidence_id === byDigest.rows[0].evidence_id
        )
      ) {
        existingRows.push(byDigest.rows[0]);
      }
      if (existingRows.length > 0) {
        if (
          existingRows.length !== 1 ||
          existingRows[0].verification_request_digest !==
            verificationRequestDigest
        ) {
          throw new EvidenceVerificationMismatchError(evidence.evidenceId);
        }
        return {
          outcome: "evidence_verification_replay",
          verification: existingRows[0]
        };
      }

      const keyResult = await client.query(
        `
          SELECT *, transaction_timestamp() AS database_now
          FROM tp_private.g1_verification_keys
          WHERE tenant_id = $1::UUID
            AND verification_key_id = $2
        `,
        [evidence.tenantId, verificationKeyId]
      );
      let reason = null;
      let publicKeyDigest = null;
      if (keyResult.rowCount !== 1) {
        reason = "verification_key_unknown";
      } else {
        const key = keyResult.rows[0];
        publicKeyDigest = key.public_key_digest;
        if (key.issuer !== evidence.issuer) {
          reason = "verification_issuer_mismatch";
        } else if (key.status !== "active") {
          reason = "verification_key_revoked";
        } else if (
          Date.parse(evidence.observedAt) < Date.parse(key.valid_from) ||
          Date.parse(evidence.observedAt) >= Date.parse(key.valid_until)
        ) {
          reason = "verification_key_not_valid_at_observation";
        } else {
          try {
            const publicKey = createPublicKey({
              key: Buffer.from(key.public_key_spki_base64, "base64"),
              format: "der",
              type: "spki"
            });
            if (
              publicKey.asymmetricKeyType !== "ed25519" ||
              !verifySignature(
                null,
                Buffer.from(signedPayload, "utf8"),
                publicKey,
                evidence.signatureBytes
              )
            ) {
              reason = "signature_invalid";
            }
          } catch {
            reason = "verification_key_invalid";
          }
        }
      }

      const outcome = reason ? "rejected" : "verified";
      const verification = await client.query(
        `
          INSERT INTO tp_ledger.g1_evidence_verification_receipts (
            tenant_id,
            evidence_id,
            verification_request_digest,
            incident_id,
            issuer,
            verification_key_id,
            verifier_version,
            signed_payload_digest,
            signature_digest,
            public_key_digest,
            outcome,
            reason
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3,
            $4::UUID,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12
          )
          RETURNING *
        `,
        [
          evidence.tenantId,
          evidence.evidenceId,
          verificationRequestDigest,
          evidence.incidentId,
          evidence.issuer,
          verificationKeyId,
          verifierVersion,
          signedPayloadDigest,
          signatureDigest,
          publicKeyDigest,
          outcome,
          reason
        ]
      );
      if (reason) {
        return {
          outcome: "evidence_rejected",
          reason,
          verification: verification.rows[0]
        };
      }

      const evidenceDigest = evidence.evidenceDigest;
      const inserted = await client.query(
        `
          INSERT INTO tp_private.g1_evidence (
            tenant_id,
            evidence_id,
            incident_id,
            issuer,
            agency_scope,
            claim_key,
            claim_value,
            verification_key_id,
            verifier_version,
            signed_payload_digest,
            signature_digest,
            evidence_digest,
            observed_at,
            valid_from,
            valid_until,
            provenance_status,
            conflict_status,
            assertion,
            embedding
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12,
            $13::TIMESTAMPTZ,
            $14::TIMESTAMPTZ,
            $15::TIMESTAMPTZ,
            'verified',
            $16,
            $17,
            $18::VECTOR(3)
          )
          RETURNING *
        `,
        [
          evidence.tenantId,
          evidence.evidenceId,
          evidence.incidentId,
          evidence.issuer,
          evidence.agencyScope,
          evidence.claimKey,
          evidence.claimValue,
          verificationKeyId,
          verifierVersion,
          signedPayloadDigest,
          signatureDigest,
          evidenceDigest,
          evidence.observedAt,
          evidence.validFrom,
          evidence.validUntil,
          evidence.conflictStatus,
          evidence.assertion,
          evidence.embedding
        ]
      );
      return {
        outcome: "evidence_verified",
        verification: verification.rows[0],
        evidence: inserted.rows[0]
      };
    });
  }

  async verificationSnapshot({ tenantId, evidenceId }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const evidence = requireUuid(evidenceId, "evidenceId");
    const client = await this.#pool.connect();
    try {
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
      );
      const verification = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_evidence_verification_receipts
          WHERE tenant_id = $1::UUID
            AND evidence_id = $2::UUID
        `,
        [tenant, evidence]
      );
      const admittedEvidence = await client.query(
        `
          SELECT *
          FROM tp_private.g1_evidence
          WHERE tenant_id = $1::UUID
            AND evidence_id = $2::UUID
        `,
        [tenant, evidence]
      );
      await client.query("COMMIT");
      return {
        verification: verification.rows[0] ?? null,
        evidence: admittedEvidence.rows[0] ?? null
      };
    } catch (error) {
      await rollbackQuietly(client);
      throw error;
    } finally {
      client.release();
    }
  }

  async auditEvidenceStatusAt({
    tenantId,
    evidenceId,
    incidentId,
    agency,
    at
  }) {
    const values = [
      requireUuid(tenantId, "tenantId"),
      requireUuid(evidenceId, "evidenceId"),
      requireUuid(incidentId, "incidentId"),
      requireText(agency, "agency"),
      requireTimestamp(at, "at")
    ];
    const result = await this.#pool.query(
      `
        SELECT
          evidence.evidence_id,
          $5::TIMESTAMPTZ AS audit_time,
          CASE
            WHEN verification.evidence_id IS NULL
              OR verification.outcome <> 'verified'
              THEN 'verification_not_valid'
            WHEN verification_key.verification_key_id IS NULL
              OR verification_key.status <> 'active'
              OR verification_key.public_key_digest <>
                verification.public_key_digest
              THEN 'verification_key_not_valid'
            WHEN evidence.claim_key IS NULL
              OR evidence.claim_value IS NULL
              THEN 'claim_binding_missing'
            WHEN evidence.observed_at >
              $5::TIMESTAMPTZ + INTERVAL '5 minutes'
              THEN 'future_observation'
            WHEN evidence.valid_from > $5::TIMESTAMPTZ
              THEN 'not_yet_valid'
            WHEN evidence.valid_until <= $5::TIMESTAMPTZ
              THEN 'expired'
            WHEN evidence.agency_scope NOT IN ($4, '*')
              THEN 'out_of_scope'
            WHEN evidence.conflict_status = 'unresolved'
              THEN 'unresolved_conflict'
            WHEN EXISTS (
              SELECT 1
              FROM tp_private.g1_evidence AS other
              JOIN tp_ledger.g1_evidence_verification_receipts
                AS other_verification
                ON other_verification.tenant_id = other.tenant_id
               AND other_verification.evidence_id = other.evidence_id
              JOIN tp_private.g1_verification_keys AS other_key
                ON other_key.tenant_id = other.tenant_id
               AND other_key.verification_key_id =
                 other.verification_key_id
              WHERE other.tenant_id = evidence.tenant_id
                AND other.incident_id = evidence.incident_id
                AND other.evidence_id <> evidence.evidence_id
                AND other.claim_key = evidence.claim_key
                AND other.claim_value <> evidence.claim_value
                AND other.provenance_status = 'verified'
                AND other_verification.outcome = 'verified'
                AND other_verification.incident_id = other.incident_id
                AND other_verification.issuer = other.issuer
                AND other_verification.verification_key_id =
                  other.verification_key_id
                AND other_verification.verifier_version =
                  other.verifier_version
                AND other_verification.signed_payload_digest =
                  other.signed_payload_digest
                AND other_verification.signature_digest =
                  other.signature_digest
                AND other_key.status = 'active'
                AND other_key.issuer = other.issuer
                AND other_key.public_key_digest =
                  other_verification.public_key_digest
                AND other.observed_at >= other_key.valid_from
                AND other.observed_at < other_key.valid_until
                AND other.observed_at <=
                  $5::TIMESTAMPTZ + INTERVAL '5 minutes'
                AND other.valid_from <= $5::TIMESTAMPTZ
                AND other.valid_until > $5::TIMESTAMPTZ
                AND other.agency_scope IN ($4, '*')
            )
              THEN 'unresolved_conflict'
            ELSE 'admissible'
          END AS status
        FROM tp_private.g1_evidence AS evidence
        LEFT JOIN tp_ledger.g1_evidence_verification_receipts
          AS verification
          ON verification.tenant_id = evidence.tenant_id
         AND verification.evidence_id = evidence.evidence_id
        LEFT JOIN tp_private.g1_verification_keys AS verification_key
          ON verification_key.tenant_id = evidence.tenant_id
         AND verification_key.verification_key_id =
           evidence.verification_key_id
        WHERE evidence.tenant_id = $1::UUID
          AND evidence.evidence_id = $2::UUID
          AND evidence.incident_id = $3::UUID
      `,
      values
    );
    if (result.rowCount !== 1) {
      return { status: "evidence_missing", auditTime: values[4] };
    }
    return {
      status: result.rows[0].status,
      auditTime: new Date(result.rows[0].audit_time).toISOString()
    };
  }

  async appendEvidence(input) {
    const evidence = {
      ...normalizeEvidence(input),
      provenanceStatus: requireText(
        input.provenanceStatus,
        "provenanceStatus"
      )
    };
    const signedPayloadDigest = requireSha256(
      input.signedPayloadDigest ??
        sha256(
          canonicalJson({
            tenantId: evidence.tenantId,
            evidenceId: evidence.evidenceId,
            incidentId: evidence.incidentId,
            issuer: evidence.issuer,
            agencyScope: evidence.agencyScope,
            observedAt: evidence.observedAt,
            validFrom: evidence.validFrom,
            validUntil: evidence.validUntil,
            assertion: evidence.assertion
          })
        ),
      "signedPayloadDigest"
    );
    const verificationKeyId = requireText(
      input.verificationKeyId ?? "gate1-synthetic-key-v1",
      "verificationKeyId"
    );
    const verifierVersion = requireText(
      input.verifierVersion ?? "gate1-verifier-v1",
      "verifierVersion"
    );
    const signatureDigest = requireSha256(
      input.signatureDigest ??
        sha256(`gate1-test-signature:${signedPayloadDigest}`),
      "signatureDigest"
    );
    const evidenceDigest = evidenceDigestFor({
      tenant_id: evidence.tenantId,
      evidence_id: evidence.evidenceId,
      incident_id: evidence.incidentId,
      issuer: evidence.issuer,
      agency_scope: evidence.agencyScope,
      claim_key: evidence.claimKey,
      claim_value: evidence.claimValue,
      verification_key_id: verificationKeyId,
      verifier_version: verifierVersion,
      signed_payload_digest: signedPayloadDigest,
      signature_digest: signatureDigest,
      observed_at: evidence.observedAt,
      valid_from: evidence.validFrom,
      valid_until: evidence.validUntil,
      provenance_status: evidence.provenanceStatus,
      conflict_status: evidence.conflictStatus,
      assertion: evidence.assertion,
      embedding: evidence.embedding
    });
    const result = await this.#pool.query(
      `
        INSERT INTO tp_private.g1_evidence (
          tenant_id,
          evidence_id,
          incident_id,
          issuer,
          agency_scope,
          claim_key,
          claim_value,
          verification_key_id,
          verifier_version,
          signed_payload_digest,
          signature_digest,
          evidence_digest,
          observed_at,
          valid_from,
          valid_until,
          provenance_status,
          conflict_status,
          assertion,
          embedding
        )
        VALUES (
          $1::UUID,
          $2::UUID,
          $3::UUID,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10,
          $11,
          $12,
          $13::TIMESTAMPTZ,
          $14::TIMESTAMPTZ,
          $15::TIMESTAMPTZ,
          $16,
          $17,
          $18,
          $19::VECTOR(3)
        )
        RETURNING *
      `,
      [
        evidence.tenantId,
        evidence.evidenceId,
        evidence.incidentId,
        evidence.issuer,
        evidence.agencyScope,
        evidence.claimKey,
        evidence.claimValue,
        verificationKeyId,
        verifierVersion,
        signedPayloadDigest,
        signatureDigest,
        evidenceDigest,
        evidence.observedAt,
        evidence.validFrom,
        evidence.validUntil,
        evidence.provenanceStatus,
        evidence.conflictStatus,
        evidence.assertion,
        evidence.embedding
      ]
    );
    return result.rows[0];
  }

  async prepareResource({ tenantId, runId, resourceId }) {
    const result = await this.#pool.query(
      `
        INSERT INTO tp_private.g1_resources (
          tenant_id,
          resource_id,
          active_run_id
        )
        VALUES ($1::UUID, $2, $3::UUID)
        RETURNING *
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireText(resourceId, "resourceId"),
        requireUuid(runId, "runId")
      ]
    );
    return result.rows[0];
  }

  async recordDviSelectionReceiptForTest(input) {
    const receipt = dviSelectionReceiptFor(input);
    const binding = dviSelectionBindingSha256For(input);
    const result = await this.#pool.query(
      `
        INSERT INTO tp_ledger.g1_dvi_selection_receipts (
          tenant_id,
          retrieval_id,
          authority_evidence_binding_sha256,
          run_id,
          incident_id,
          agency,
          policy_version,
          source_commit,
          tree_digest,
          spec_sha256,
          admitted_at,
          expires_at,
          ranked_sequence_sha256,
          query_embedding_sha256,
          result_limit,
          selected_rank,
          selected_evidence_id,
          selected_evidence_digest
        )
        VALUES (
          $1::UUID, $2::UUID, $3, $4::UUID, $5::UUID, $6, $7, $8, $9,
          $10, $11::TIMESTAMPTZ, $12::TIMESTAMPTZ, $13, $14, $15::INT8,
          $16::INT8, $17::UUID, $18
        )
        ON CONFLICT DO NOTHING
        RETURNING *
      `,
      [
        receipt.tenantId,
        receipt.retrievalId,
        binding,
        receipt.runId,
        receipt.incidentId,
        receipt.agency,
        receipt.policyVersion,
        receipt.sourceCommit,
        receipt.treeDigest,
        receipt.specSha256,
        receipt.snapshot.admittedAt,
        receipt.snapshot.expiresAt,
        receipt.rankedSequenceSha256,
        receipt.queryEmbeddingSha256,
        receipt.resultLimit,
        receipt.selected.rank,
        receipt.selected.evidenceId,
        receipt.selected.evidenceDigest
      ]
    );
    const observed = result.rowCount === 1
      ? result
      : await this.#pool.query(
          `
            SELECT *
            FROM tp_ledger.g1_dvi_selection_receipts
            WHERE tenant_id = $1::UUID
              AND retrieval_id = $2::UUID
          `,
          [receipt.tenantId, receipt.retrievalId]
        );
    if (
      observed.rowCount !== 1 ||
      dviSelectionBindingSha256For(
        dviSelectionReceiptInputFromRow(observed.rows[0])
      ) !== binding ||
      observed.rows[0].authority_evidence_binding_sha256 !== binding
    ) {
      throw new InvariantViolationError(
        "synthetic DVI selection receipt conflicted with durable state"
      );
    }
    return observed.rows[0];
  }

  async authorizeDviProposal(input) {
    const authorization = normalizedDviAuthorizationFor(input);
    return this.#runSerializable(async (client) => {
      const findExisting = async () => client.query(
        `
          SELECT *, statement_timestamp() AS database_now
          FROM tp_ledger.g1_dvi_proposal_receipts
          WHERE tenant_id = $1::UUID
            AND proposal_digest = $2
        `,
        [authorization.logicalAction.tenantId, authorization.proposalDigest]
      );
      const replayDecision = async (proposal) => {
        const priorSpend = await client.query(
          `
            SELECT count(*)::INT8 AS count
            FROM tp_ledger.g1_authority_receipts AS receipt
            WHERE receipt.tenant_id = $1::UUID
              AND receipt.logical_action_digest = $2
              AND receipt.outcome = 'resource_reserved'
          `,
          [authorization.logicalAction.tenantId, authorization.logicalActionDigest]
        );
        const priorSpendCount = Number(priorSpend.rows[0]?.count ?? -1);
        if (
          priorSpend.rowCount !== 1 ||
          !Number.isSafeInteger(priorSpendCount) ||
          priorSpendCount < 0
        ) {
          throw new InvariantViolationError(
            "logical authority spend census was not singular"
          );
        }
        if (priorSpendCount > 0) {
          return {
            outcome: "proposal_authorization_denied",
            reason: "logical_authority_already_spent",
            proposal,
            authorityCurrent: false,
            requiresFreshAuthorization: true
          };
        }
        const databaseNow = new Date(proposal.database_now).getTime();
        if (!Number.isFinite(databaseNow)) {
          throw new InvariantViolationError(
            "proposal replay database time was invalid"
          );
        }
        if (new Date(proposal.expires_at).getTime() <= databaseNow) {
          return {
            outcome: "proposal_authorization_denied",
            reason: "explicit_new_authorization_required",
            proposal,
            authorityCurrent: false,
            requiresFreshAuthorization: true
          };
        }
        return {
          outcome: "proposal_authorization_replay",
          proposal,
          authorityCurrent: true,
          requiresFreshAuthorization: false
        };
      };
      const existing = await findExisting();
      if (existing.rowCount === 1) {
        if (!proposalReceiptMatches(existing.rows[0], authorization)) {
          throw new InvariantViolationError(
            "proposal digest matched a different durable authorization"
          );
        }
        return replayDecision(existing.rows[0]);
      }
      if (existing.rowCount !== 0) {
        throw new InvariantViolationError(
          "proposal digest matched multiple durable authorizations"
        );
      }

      const selectionReceipt = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_dvi_selection_receipts
          WHERE tenant_id = $1::UUID
            AND authority_evidence_binding_sha256 = $2
        `,
        [
          authorization.logicalAction.tenantId,
          authorization.dviProposal.authorityEvidenceBindingSha256
        ]
      );
      if (selectionReceipt.rowCount !== 1) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "dvi_selection_receipt_missing"
        };
      }
      if (!dviSelectionReceiptMatches(selectionReceipt.rows[0], authorization)) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "dvi_selection_receipt_mismatch"
        };
      }

      const evidence = await client.query(
        `
          SELECT evidence.*, statement_timestamp() AS database_now
          FROM tp_private.g1_evidence AS evidence
          WHERE evidence.tenant_id = $1::UUID
            AND evidence.evidence_id = $2::UUID
            AND evidence.incident_id = $3::UUID
        `,
        [
          authorization.logicalAction.tenantId,
          authorization.selectedEvidenceId,
          authorization.logicalAction.incidentId
        ]
      );
      if (evidence.rowCount !== 1) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "selected_evidence_missing"
        };
      }
      const evidenceRow = evidence.rows[0];
      if (
        evidenceRow.evidence_digest !== authorization.selectedEvidenceDigest ||
        evidenceDigestFor(evidenceRow) !== authorization.selectedEvidenceDigest
      ) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "selected_evidence_digest_mismatch"
        };
      }
      if (
        Date.parse(authorization.dviProposal.expiresAt) <=
        new Date(evidenceRow.database_now).getTime()
      ) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "proposal_expired"
        };
      }
      if (
        Date.parse(authorization.dviProposal.admittedAt) >
        new Date(evidenceRow.database_now).getTime()
      ) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "proposal_not_yet_admitted"
        };
      }

      await client.query(
        `
          INSERT INTO tp_ledger.g1_logical_authority_epochs (
            tenant_id,
            logical_action_digest,
            current_epoch
          )
          VALUES ($1::UUID, $2, 0)
          ON CONFLICT DO NOTHING
        `,
        [authorization.logicalAction.tenantId, authorization.logicalActionDigest]
      );
      const lockedEpoch = await client.query(
        `
          SELECT current_epoch
          FROM tp_ledger.g1_logical_authority_epochs
          WHERE tenant_id = $1::UUID
            AND logical_action_digest = $2
          FOR UPDATE
        `,
        [authorization.logicalAction.tenantId, authorization.logicalActionDigest]
      );
      if (lockedEpoch.rowCount !== 1) {
        throw new InvariantViolationError(
          "database authorization epoch row was not locked exactly once"
        );
      }

      const postLockClock = await client.query(
        "SELECT statement_timestamp() AS database_now"
      );
      const postLockDatabaseNow = new Date(
        postLockClock.rows[0]?.database_now
      ).getTime();
      if (!Number.isFinite(postLockDatabaseNow)) {
        throw new InvariantViolationError(
          "post-lock proposal authorization database time was invalid"
        );
      }
      if (
        Date.parse(authorization.dviProposal.expiresAt) <=
        postLockDatabaseNow
      ) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "proposal_expired",
          authorityCurrent: false,
          requiresFreshAuthorization: true
        };
      }

      const racedExisting = await findExisting();
      if (racedExisting.rowCount === 1) {
        if (!proposalReceiptMatches(racedExisting.rows[0], authorization)) {
          throw new InvariantViolationError(
            "proposal digest raced with a different durable authorization"
          );
        }
        return replayDecision(racedExisting.rows[0]);
      }
      if (racedExisting.rowCount !== 0) {
        throw new InvariantViolationError(
          "proposal digest race was not singular"
        );
      }

      const priorSpend = await client.query(
        `
          SELECT count(*)::INT8 AS count
          FROM tp_ledger.g1_authority_receipts AS receipt
          WHERE receipt.tenant_id = $1::UUID
            AND receipt.logical_action_digest = $2
            AND receipt.outcome = 'resource_reserved'
        `,
        [authorization.logicalAction.tenantId, authorization.logicalActionDigest]
      );
      if (Number(priorSpend.rows[0]?.count ?? -1) > 0) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "logical_authority_already_spent"
        };
      }
      if (Number(priorSpend.rows[0]?.count ?? -1) !== 0) {
        throw new InvariantViolationError(
          "logical authority spend census was not singular"
        );
      }

      let authorizationEpoch = Number(lockedEpoch.rows[0].current_epoch);
      if (authorizationEpoch === 1) {
        return {
          outcome: "proposal_authorization_denied",
          reason: "explicit_new_authorization_required"
        };
      }
      if (authorizationEpoch !== 0) {
        throw new InvariantViolationError(
          "authorization epoch advancement requires an explicit new-authorization receipt"
        );
      }
      const initializedEpoch = await client.query(
        `
          UPDATE tp_ledger.g1_logical_authority_epochs
          SET current_epoch = 1,
              updated_at = statement_timestamp()
          WHERE tenant_id = $1::UUID
            AND logical_action_digest = $2
            AND current_epoch = 0
          RETURNING current_epoch
        `,
        [
          authorization.logicalAction.tenantId,
          authorization.logicalActionDigest
        ]
      );
      if (initializedEpoch.rowCount !== 1) {
        throw new InvariantViolationError(
          "database authorization epoch could not initialize exactly once"
        );
      }
      authorizationEpoch = Number(initializedEpoch.rows[0].current_epoch);
      if (authorizationEpoch !== 1) {
        throw new InvariantViolationError(
          "database authorization epoch initialized outside the frozen contract"
        );
      }
      authorizationEpoch = authorizationEpochFromRow(authorizationEpoch);
      const expectedLogicalAuthority = logicalAuthorityKeyFor({
        logicalActionDigest: authorization.logicalActionDigest,
        authorizationEpoch
      });
      const expectedBinding = authorizationBindingFor({
        logicalActionDigest: authorization.logicalActionDigest,
        proposalDigest: authorization.proposalDigest,
        authorizationEpoch
      });
      const databaseIdentity = await client.query(
        `
          WITH authority_key AS (
            SELECT encode(
              sha256((
                '{"authorizationEpoch":' || $3::STRING ||
                ',"logicalActionDigest":"' || $1 ||
                '","schemaVersion":"tideproof.authority.logical-authority-key.v1"}'
              )::BYTES),
              'hex'
            ) AS logical_authority_key_sha256
          )
          SELECT
            authority_key.logical_authority_key_sha256,
            encode(
              sha256((
                '{"authorizationEpoch":' || $3::STRING ||
                ',"logicalActionDigest":"' || $1 ||
                '","logicalAuthorityKeySha256":"' ||
                authority_key.logical_authority_key_sha256 ||
                '","proposalDigest":"' || $2 ||
                '","schemaVersion":"tideproof.authority.authorization-binding.v1"}'
              )::BYTES),
              'hex'
            ) AS authorization_binding_sha256
          FROM authority_key
        `,
        [
          authorization.logicalActionDigest,
          authorization.proposalDigest,
          authorizationEpoch
        ]
      );
      if (
        databaseIdentity.rowCount !== 1 ||
        databaseIdentity.rows[0].logical_authority_key_sha256 !==
          expectedLogicalAuthority.logicalAuthorityKeySha256 ||
        databaseIdentity.rows[0].authorization_binding_sha256 !==
          expectedBinding.authorizationBindingSha256
      ) {
        throw new InvariantViolationError(
          "database-derived authorization identity diverged from the frozen contract"
        );
      }
      const logicalAuthorityKeySha256 =
        databaseIdentity.rows[0].logical_authority_key_sha256;
      const authorizationBindingSha256 =
        databaseIdentity.rows[0].authorization_binding_sha256;
      const inserted = await client.query(
        `
          INSERT INTO tp_ledger.g1_dvi_proposal_receipts (
            tenant_id,
            proposal_digest,
            logical_action_digest,
            resource_id,
            agency,
            action_kind,
            payload,
            payload_canonical,
            payload_digest,
            retrieval_id,
            run_id,
            incident_id,
            authority_evidence_binding_sha256,
            policy_version,
            selected_rank,
            selected_evidence_id,
            selected_evidence_digest,
            admitted_at,
            expires_at,
            authorization_epoch,
            logical_authority_key_sha256,
            authorization_binding_sha256
          )
          VALUES (
            $1::UUID, $2, $3, $4, $5, $6, $7::JSONB, $8, $9,
            $10::UUID, $11::UUID, $12::UUID, $13, $14,
            $15::INT8, $16::UUID, $17, $18::TIMESTAMPTZ, $19::TIMESTAMPTZ,
            $20::INT8, $21, $22
          )
          RETURNING *
        `,
        [
          authorization.logicalAction.tenantId,
          authorization.proposalDigest,
          authorization.logicalActionDigest,
          authorization.logicalAction.resourceId,
          authorization.logicalAction.agency,
          authorization.logicalAction.actionKind,
          JSON.stringify(authorization.logicalAction.payload),
          canonicalJson(authorization.logicalAction.payload),
          authorization.logicalAction.payloadDigest,
          authorization.dviProposal.retrievalId,
          authorization.dviProposal.runId,
          authorization.dviProposal.incidentId,
          authorization.dviProposal.authorityEvidenceBindingSha256,
          authorization.dviProposal.policyVersion,
          authorization.dviProposal.selectedRank,
          authorization.selectedEvidenceId,
          authorization.selectedEvidenceDigest,
          authorization.dviProposal.admittedAt,
          authorization.dviProposal.expiresAt,
          authorizationEpoch,
          logicalAuthorityKeySha256,
          authorizationBindingSha256
        ]
      );
      if (
        inserted.rowCount !== 1 ||
        !proposalReceiptMatches(inserted.rows[0], authorization)
      ) {
        throw new InvariantViolationError(
          "durable proposal authorization binding was not observable"
        );
      }
      const finalCurrent = await client.query(
        `
          SELECT expires_at > statement_timestamp() AS authority_current
          FROM tp_ledger.g1_dvi_proposal_receipts
          WHERE tenant_id = $1::UUID
            AND proposal_digest = $2
        `,
        [authorization.logicalAction.tenantId, authorization.proposalDigest]
      );
      if (
        finalCurrent.rowCount !== 1 ||
        finalCurrent.rows[0].authority_current !== true
      ) {
        await client.query(
          `
            DELETE FROM tp_ledger.g1_dvi_proposal_receipts
            WHERE tenant_id = $1::UUID
              AND proposal_digest = $2
          `,
          [authorization.logicalAction.tenantId, authorization.proposalDigest]
        );
        const restoredEpoch = await client.query(
          `
            UPDATE tp_ledger.g1_logical_authority_epochs
            SET current_epoch = 0,
                updated_at = statement_timestamp()
            WHERE tenant_id = $1::UUID
              AND logical_action_digest = $2
              AND current_epoch = 1
            RETURNING current_epoch
          `,
          [
            authorization.logicalAction.tenantId,
            authorization.logicalActionDigest
          ]
        );
        if (restoredEpoch.rowCount !== 1) {
          throw new InvariantViolationError(
            "expired proposal authorization epoch could not be restored"
          );
        }
        return {
          outcome: "proposal_authorization_denied",
          reason: "proposal_expired",
          authorityCurrent: false,
          requiresFreshAuthorization: true
        };
      }
      return {
        outcome: "proposal_authorized",
        proposal: inserted.rows[0],
        authorityCurrent: true,
        requiresFreshAuthorization: false
      };
    });
  }

  async authorityIdentityStateForTest({ tenantId, resourceId }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const resource = requireText(resourceId, "resourceId");
    const result = await this.#pool.query(
      `
        SELECT
          resource.current_fence,
          (
            SELECT count(*)::INT8
            FROM tp_ledger.g1_dvi_selection_receipts
            WHERE tenant_id = $1::UUID
          ) AS selection_receipt_count,
          (
            SELECT count(*)::INT8
            FROM tp_ledger.g1_dvi_proposal_receipts
            WHERE tenant_id = $1::UUID
          ) AS proposal_receipt_count,
          (
            SELECT count(*)::INT8
            FROM tp_ledger.g1_logical_authority_epochs
            WHERE tenant_id = $1::UUID
          ) AS epoch_count,
          (
            SELECT coalesce(max(current_epoch), 0)::INT8
            FROM tp_ledger.g1_logical_authority_epochs
            WHERE tenant_id = $1::UUID
          ) AS maximum_epoch,
          (
            SELECT count(*)::INT8
            FROM tp_ledger.g1_authority_receipts
            WHERE tenant_id = $1::UUID
          ) AS authority_receipt_count,
          (
            SELECT count(*)::INT8
            FROM tp_ledger.g1_outbox_intents
            WHERE tenant_id = $1::UUID
          ) AS outbox_count,
          (
            SELECT count(*)::INT8
            FROM tp_ledger.g1_protected_effects
            WHERE tenant_id = $1::UUID
          ) AS protected_effect_count
        FROM tp_private.g1_resources AS resource
        WHERE resource.tenant_id = $1::UUID
          AND resource.resource_id = $2
      `,
      [tenant, resource]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError(
        "authority identity test state was not singular"
      );
    }
    return result.rows[0];
  }

  async expireLeaseForTest({ tenantId, resourceId }) {
    const result = await this.#pool.query(
      `
        UPDATE tp_private.g1_resources
        SET lease_expires_at = transaction_timestamp() - INTERVAL '1 microsecond',
            updated_at = transaction_timestamp()
        WHERE tenant_id = $1::UUID
          AND resource_id = $2
        RETURNING current_fence
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireText(resourceId, "resourceId")
      ]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError("resource missing during lease expiry");
    }
    return result.rows[0];
  }

  async expireLeaseAtDatabaseNowForTest({ tenantId, resourceId }) {
    const result = await this.#pool.query(
      `
        UPDATE tp_private.g1_resources
        SET lease_expires_at = transaction_timestamp(),
            updated_at = transaction_timestamp()
        WHERE tenant_id = $1::UUID
          AND resource_id = $2
        RETURNING
          current_fence,
          lease_expires_at,
          transaction_timestamp() AS database_now,
          lease_expires_at = transaction_timestamp() AS exact_boundary
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireText(resourceId, "resourceId")
      ]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError("resource missing during lease expiry");
    }
    return result.rows[0];
  }

  async expireProposalAtDatabaseNowForTest({ tenantId, proposalDigest }) {
    const result = await this.#pool.query(
      `
        UPDATE tp_ledger.g1_dvi_proposal_receipts
        SET expires_at = transaction_timestamp()
        WHERE tenant_id = $1::UUID
          AND proposal_digest = $2
        RETURNING
          proposal_digest,
          expires_at,
          transaction_timestamp() AS database_now,
          expires_at = transaction_timestamp() AS exact_boundary
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireSha256(proposalDigest, "proposalDigest")
      ]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError(
        "proposal missing during exact-boundary expiry"
      );
    }
    return result.rows[0];
  }

  async setProposalExpiryAfterMsForTest({
    tenantId,
    proposalDigest,
    delayMs
  }) {
    if (!Number.isSafeInteger(delayMs) || delayMs < 100 || delayMs > 10_000) {
      throw new TypeError("delayMs must be an integer from 100 through 10000");
    }
    const result = await this.#pool.query(
      `
        UPDATE tp_ledger.g1_dvi_proposal_receipts
        SET expires_at = LEAST(
          expires_at,
          statement_timestamp() +
            ($3::INT8 * INTERVAL '1 millisecond')
        )
        WHERE tenant_id = $1::UUID
          AND proposal_digest = $2
          AND expires_at > statement_timestamp()
        RETURNING
          proposal_digest,
          expires_at,
          statement_timestamp() AS database_now
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireSha256(proposalDigest, "proposalDigest"),
        delayMs
      ]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError(
        "proposal missing while scheduling held-transaction expiry"
      );
    }
    return result.rows[0];
  }

  async waitForProposalExpiryForTest({
    tenantId,
    proposalDigest,
    timeoutMs = 10_000
  }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const proposal = requireSha256(proposalDigest, "proposalDigest");
    if (
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 100 ||
      timeoutMs > 30_000
    ) {
      throw new TypeError("timeoutMs must be an integer from 100 through 30000");
    }
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const result = await this.#pool.query(
        `
          SELECT
            proposal_digest,
            expires_at,
            statement_timestamp() AS database_now,
            expires_at <= statement_timestamp() AS expired
          FROM tp_ledger.g1_dvi_proposal_receipts
          WHERE tenant_id = $1::UUID
            AND proposal_digest = $2
        `,
        [tenant, proposal]
      );
      if (result.rowCount !== 1) {
        throw new InvariantViolationError(
          "proposal missing while awaiting held-transaction expiry"
        );
      }
      if (result.rows[0].expired === true) {
        return result.rows[0];
      }
      await sleepTimer(25);
    }
    throw new InvariantViolationError(
      "proposal did not expire before held-transaction timeout"
    );
  }

  async #runSerializable(
    work,
    {
      barrier,
      commitDispatchObserver,
      afterCommitObserver,
      maxRetries = DEFAULT_MAX_RETRIES,
      retryDeadlineMs = DEFAULT_RETRY_DEADLINE_MS
    } = {}
  ) {
    const startedAt = Date.now();
    const retryCodes = [];
    const backendIds = [];
    let initialBackendId = null;

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      const client = await this.#pool.connect();
      let commitDispatched = false;
      let committed = false;
      let releaseError = null;
      try {
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
        const isolation = await client.query(
          "SHOW TRANSACTION ISOLATION LEVEL"
        );
        const backend = await client.query(
          "SELECT pg_backend_pid()::STRING AS backend_id"
        );
        const backendId = backend.rows[0].backend_id;
        initialBackendId ??= backendId;
        backendIds.push(backendId);
        const result = await work(client, {
          attempt,
          barrier: attempt === 0 ? barrier : null
        });
        const databaseClock = await client.query(
          "SELECT statement_timestamp() AS database_now"
        );
        const restoreCommitObserver = observeCommitDispatch(
          client,
          commitDispatchObserver
        );
        commitDispatched = true;
        try {
          await client.query("COMMIT");
        } finally {
          restoreCommitObserver();
        }
        committed = true;
        afterCommitObserver?.();
        return {
          ...result,
          transaction: {
            isolation: isolation.rows[0].transaction_isolation,
            backendId,
            initialBackendId,
            backendIds: [...backendIds],
            serializableRetries: attempt,
            retryCodes,
            databaseNow: new Date(
              databaseClock.rows[0].database_now
            ).toISOString()
          }
        };
      } catch (error) {
        if (!committed && !commitDispatched) {
          await rollbackQuietly(client);
        }

        if (
          !commitDispatched &&
          isRetryableTransactionError(error) &&
          attempt < maxRetries &&
          Date.now() - startedAt < retryDeadlineMs
        ) {
          retryCodes.push(error.code);
          await rollbackQuietly(client);
          await new Promise((resolve) =>
            setTimeout(resolve, backoffMs(attempt))
          );
          continue;
        }

        if (databaseFailureRequiresReconciliation(error, {
          commitDispatched
        })) {
          releaseError = error;
          throw new AmbiguousCommitError(
            "COMMIT outcome is unknown; reconcile by exact request digest.",
            error
          );
        }

        if (isTransportError(error)) {
          releaseError = error;
        }
        throw error;
      } finally {
        client.release(releaseError ?? undefined);
      }
    }
    throw new Error("serializable retry loop exhausted");
  }

  async #boundProposal(client, request, { requireCurrent = true } = {}) {
    const result = await client.query(
      `
        SELECT proposal.*, statement_timestamp() AS database_now
        FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
        WHERE proposal.tenant_id = $1::UUID
          AND proposal.proposal_digest = $2
      `,
      [request.tenantId, request.proposalDigest]
    );
    if (result.rowCount !== 1) {
      return {
        ok: false,
        reason:
          result.rowCount === 0
            ? "proposal_authorization_missing"
            : "proposal_authorization_ambiguous"
      };
    }
    const row = result.rows[0];
    if (!proposalReceiptMatches(row, dviAuthorizationFromRequest(request))) {
      return { ok: false, reason: "proposal_authorization_binding_mismatch" };
    }
    if (
      row.selected_evidence_id !== request.evidenceId ||
      row.selected_evidence_digest !== request.selectedEvidenceDigest
    ) {
      return { ok: false, reason: "selected_evidence_binding_mismatch" };
    }
    if (
      requireCurrent &&
      new Date(row.expires_at).getTime() <= new Date(row.database_now).getTime()
    ) {
      return { ok: false, reason: "proposal_authorization_expired" };
    }
    return {
      ok: true,
      current:
        new Date(row.expires_at).getTime() >
        new Date(row.database_now).getTime(),
      proposal: row,
      authorizationEpoch: authorizationEpochFromRow(row.authorization_epoch),
      logicalAuthorityKeySha256: row.logical_authority_key_sha256,
      authorizationBindingSha256: row.authorization_binding_sha256
    };
  }

  async #receiptAuthorityCurrent(client, receipt) {
    if (receipt.outcome !== "resource_reserved") {
      return false;
    }
    const result = await client.query(
      `
        SELECT
          resource.current_fence,
          resource.active_run_id,
          resource.holder_operation_id,
          resource.holder_proposal_digest,
          resource.holder_logical_authority_key_sha256,
          resource.lease_expires_at AS resource_lease_expires_at,
          outbox.intent_id AS outbox_intent_id,
          outbox.request_digest AS outbox_request_digest,
          outbox.proposal_digest AS outbox_proposal_digest,
          outbox.logical_action_digest AS outbox_logical_action_digest,
          outbox.authorization_epoch AS outbox_authorization_epoch,
          outbox.logical_authority_key_sha256 AS
            outbox_logical_authority_key_sha256,
          outbox.authorization_binding_sha256 AS
            outbox_authorization_binding_sha256,
          outbox.run_id AS outbox_run_id,
          outbox.incident_id AS outbox_incident_id,
          outbox.resource_id AS outbox_resource_id,
          outbox.fencing_token AS outbox_fencing_token,
          outbox.effect_key AS outbox_effect_key,
          outbox.intent_kind AS outbox_intent_kind,
          outbox.payload AS outbox_payload,
          outbox.payload_digest AS outbox_payload_digest,
          proposal.payload AS proposal_payload,
          proposal.payload_digest AS proposal_payload_digest,
          proposal.expires_at AS proposal_expires_at,
          statement_timestamp() AS database_now
        FROM tp_private.g1_resources AS resource
        JOIN tp_ledger.g1_outbox_intents AS outbox
          ON outbox.tenant_id = resource.tenant_id
         AND outbox.operation_id = $4::UUID
        JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
          ON proposal.tenant_id = resource.tenant_id
         AND proposal.proposal_digest = $3
        WHERE resource.tenant_id = $1::UUID
          AND resource.resource_id = $2
      `,
      [
        receipt.tenant_id,
        receipt.resource_id,
        receipt.proposal_digest,
        receipt.operation_id
      ]
    );
    if (result.rowCount !== 1) {
      return false;
    }
    const state = result.rows[0];
    const databaseNow = new Date(state.database_now).getTime();
    const exactOutbox =
      state.outbox_intent_id &&
      state.outbox_request_digest === receipt.request_digest &&
      state.outbox_proposal_digest === receipt.proposal_digest &&
      state.outbox_logical_action_digest === receipt.logical_action_digest &&
      authorizationEpochFromRow(state.outbox_authorization_epoch) ===
        authorizationEpochFromRow(receipt.authorization_epoch) &&
      state.outbox_logical_authority_key_sha256 ===
        receipt.logical_authority_key_sha256 &&
      state.outbox_authorization_binding_sha256 ===
        receipt.authorization_binding_sha256 &&
      state.outbox_run_id === receipt.run_id &&
      state.outbox_incident_id === receipt.incident_id &&
      state.outbox_resource_id === receipt.resource_id &&
      state.outbox_fencing_token === receipt.fencing_token &&
      state.outbox_effect_key === receipt.effect_key &&
      state.outbox_intent_kind === ACTION_KIND &&
      state.outbox_payload_digest === receipt.payload_digest &&
      state.proposal_payload_digest === receipt.payload_digest &&
      canonicalJson(state.outbox_payload) ===
        canonicalJson(state.proposal_payload) &&
      sha256(canonicalJson(state.outbox_payload)) ===
        state.outbox_payload_digest;
    return (
      exactOutbox &&
      receipt.fencing_token === state.current_fence &&
      receipt.run_id === state.active_run_id &&
      receipt.operation_id === state.holder_operation_id &&
      receipt.proposal_digest === state.holder_proposal_digest &&
      receipt.logical_authority_key_sha256 ===
        state.holder_logical_authority_key_sha256 &&
      new Date(receipt.lease_expires_at).getTime() > databaseNow &&
      new Date(state.resource_lease_expires_at).getTime() > databaseNow &&
      new Date(state.proposal_expires_at).getTime() > databaseNow
    );
  }

  async #existingReceipt(client, request) {
    const replay = async (receipt, replayKind) => {
      if (receipt.outcome !== "resource_reserved") {
        return {
          outcome: "authorization_denied",
          reason:
            receipt.reason ?? "explicit_new_authorization_required",
          replayKind,
          receipt,
          authorityCurrent: false,
          requiresFreshAuthorization: true
        };
      }
      const authorityCurrent = await this.#receiptAuthorityCurrent(
        client,
        receipt
      );
      return {
        outcome: replayKind,
        receipt,
        authorityCurrent,
        requiresFreshAuthorization: !authorityCurrent
      };
    };
    const byOperation = await client.query(
      `
        SELECT *
        FROM tp_ledger.g1_authority_receipts
        WHERE tenant_id = $1::UUID
          AND operation_id = $2::UUID
      `,
      [request.tenantId, request.operationId]
    );
    if (byOperation.rowCount > 1) {
      throw new InvariantViolationError(
        "operation ID matched multiple authority receipts"
      );
    }
    if (byOperation.rowCount === 1) {
      const receipt = byOperation.rows[0];
      if (receipt.request_digest !== request.requestDigest) {
        throw new OperationDigestMismatchError(request.operationId);
      }
      if (receipt.outcome === "pending") {
        throw new InvariantViolationError("committed pending receipt found");
      }
      return replay(receipt, "operation_replay");
    }

    const byLogicalAuthority = await client.query(
      `
        SELECT *
        FROM tp_ledger.g1_authority_receipts
        WHERE tenant_id = $1::UUID
          AND logical_action_digest = $2
          AND outcome = 'resource_reserved'
      `,
      [request.tenantId, request.logicalActionDigest]
    );
    if (byLogicalAuthority.rowCount > 1) {
      throw new InvariantViolationError(
        "logical action matched multiple positive receipts"
      );
    }
    if (byLogicalAuthority.rowCount === 1) {
      const receipt = byLogicalAuthority.rows[0];
      return replay(receipt, "logical_authority_replay");
    }

    const byDigest = await client.query(
      `
        SELECT *
        FROM tp_ledger.g1_authority_receipts
        WHERE tenant_id = $1::UUID
          AND request_digest = $2
      `,
      [request.tenantId, request.requestDigest]
    );
    if (byDigest.rowCount === 0) {
      return null;
    }
    if (byDigest.rowCount !== 1) {
      throw new InvariantViolationError(
        "semantic digest matched multiple authority receipts"
      );
    }
    const receipt = byDigest.rows[0];
    if (receipt.outcome === "pending") {
      throw new InvariantViolationError("committed pending receipt found");
    }
    return replay(receipt, "semantic_replay");
  }

  async spendAuthority(
    input,
    {
      afterEpochLockObserver,
      barrier,
      beforeCommitObserver,
      commitDispatchObserver,
      afterCommitObserver
    } = {}
  ) {
    const unboundRequest = normalizeRequest(input);

    const result = await this.#runSerializable(
      async (client, transactionContext) => {
        const boundProposal = await this.#boundProposal(client, unboundRequest, {
          requireCurrent: false
        });
        if (!boundProposal.ok) {
          return {
            outcome: "authorization_denied",
            reason: boundProposal.reason,
            requestDigest: unboundRequest.requestDigest,
            proposalDigest: unboundRequest.proposalDigest,
            authorityCurrent: false,
            durableMutation: false
          };
        }
        const request = {
          ...unboundRequest,
          authorizationEpoch: boundProposal.authorizationEpoch,
          logicalAuthorityKeySha256:
            boundProposal.logicalAuthorityKeySha256,
          authorizationBindingSha256:
            boundProposal.authorizationBindingSha256
        };
        const epochLock = await client.query(
          `
            SELECT current_epoch
            FROM tp_ledger.g1_logical_authority_epochs
            WHERE tenant_id = $1::UUID
              AND logical_action_digest = $2
            FOR UPDATE
          `,
          [request.tenantId, request.logicalActionDigest]
        );
        if (epochLock.rowCount !== 1) {
          throw new InvariantViolationError(
            "logical authority epoch lock was not singular"
          );
        }
        await afterEpochLockObserver?.();
        const existing = await this.#existingReceipt(client, request);
        if (existing) {
          return {
            ...existing,
            requestDigest: request.requestDigest
          };
        }
        if (
          String(epochLock.rows[0].current_epoch) !==
          String(request.authorizationEpoch)
        ) {
          return {
            outcome: "authorization_denied",
            reason: "proposal_authorization_superseded",
            requestDigest: request.requestDigest,
            proposalDigest: request.proposalDigest,
            authorizationEpoch: request.authorizationEpoch,
            logicalAuthorityKeySha256: request.logicalAuthorityKeySha256,
            authorizationBindingSha256: request.authorizationBindingSha256,
            authorityCurrent: false,
            durableMutation: false
          };
        }
        if (!boundProposal.current) {
          return {
            outcome: "authorization_denied",
            reason: "proposal_authorization_expired",
            requestDigest: request.requestDigest,
            proposalDigest: request.proposalDigest,
            authorizationEpoch: request.authorizationEpoch,
            logicalAuthorityKeySha256: request.logicalAuthorityKeySha256,
            authorizationBindingSha256: request.authorizationBindingSha256,
            authorityCurrent: false,
            durableMutation: false
          };
        }

        const insertedPending = await client.query(
          `
            INSERT INTO tp_ledger.g1_authority_receipts (
              tenant_id,
              operation_id,
              request_digest,
              request_payload,
              proposal_digest,
              logical_action_digest,
              authorization_epoch,
              logical_authority_key_sha256,
              authorization_binding_sha256,
              run_id,
              incident_id,
              resource_id,
              agent_id,
              agency,
              evidence_id,
              effect_key,
              payload_digest,
              policy_version,
              outcome
            )
            VALUES (
              $1::UUID,
              $2::UUID,
              $3,
              $4::JSONB,
              $5,
              $6,
              $7::INT8,
              $8,
              $9,
              $10::UUID,
              $11::UUID,
              $12,
              $13,
              $14,
              $15::UUID,
              $16::UUID,
              $17,
              $18,
              'pending'
            )
            ON CONFLICT DO NOTHING
            RETURNING operation_id
          `,
          [
            request.tenantId,
            request.operationId,
            request.requestDigest,
            JSON.stringify(request.requestPayload),
            request.proposalDigest,
            request.logicalActionDigest,
            request.authorizationEpoch,
            request.logicalAuthorityKeySha256,
            request.authorizationBindingSha256,
            request.runId,
            request.incidentId,
            request.resourceId,
            request.agentId,
            request.agency,
            request.evidenceId,
            request.effectKey,
            request.payloadDigest,
            request.policyVersion
          ]
        );
        if (insertedPending.rowCount === 0) {
          const concurrentExisting = await this.#existingReceipt(
            client,
            request
          );
          if (!concurrentExisting) {
            throw new InvariantViolationError(
              "receipt conflict was not reconcilable by operation or digest"
            );
          }
          return {
            ...concurrentExisting,
            requestDigest: request.requestDigest
          };
        }

        const evidence = await client.query(
          `
            SELECT
              evidence.*,
              statement_timestamp() AS database_now,
              CASE
                WHEN evidence.verification_key_id IS NULL
                  OR evidence.verifier_version IS NULL
                  OR evidence.signed_payload_digest IS NULL
                  OR evidence.signature_digest IS NULL
                  OR evidence.evidence_digest IS NULL
                  THEN 'verification_receipt_missing'
                WHEN verification.evidence_id IS NULL
                  THEN 'verification_receipt_missing'
                WHEN verification.outcome <> 'verified'
                  THEN COALESCE(
                    verification.reason,
                    'verification_rejected'
                  )
                WHEN verification.incident_id <> evidence.incident_id
                  OR verification.issuer <> evidence.issuer
                  OR verification.verification_key_id <>
                    evidence.verification_key_id
                  OR verification.verifier_version <>
                    evidence.verifier_version
                  OR verification.signed_payload_digest <>
                    evidence.signed_payload_digest
                  OR verification.signature_digest <>
                    evidence.signature_digest
                  THEN 'verification_binding_mismatch'
                WHEN verification_key.verification_key_id IS NULL
                  THEN 'verification_key_unknown'
                WHEN verification_key.public_key_digest <>
                  verification.public_key_digest
                  THEN 'verification_key_digest_mismatch'
                WHEN verification_key.issuer <> evidence.issuer
                  THEN 'verification_issuer_mismatch'
                WHEN verification_key.status <> 'active'
                  THEN 'verification_key_revoked'
                WHEN evidence.observed_at < verification_key.valid_from
                  OR evidence.observed_at >= verification_key.valid_until
                  THEN 'verification_key_not_valid_at_observation'
                WHEN evidence.provenance_status <> 'verified'
                  THEN 'provenance_not_verified'
                WHEN evidence.claim_key IS NULL
                  OR evidence.claim_value IS NULL
                  THEN 'claim_binding_missing'
                WHEN evidence.observed_at >
                  statement_timestamp() + INTERVAL '5 minutes'
                  THEN 'future_observation'
                WHEN evidence.valid_from > statement_timestamp()
                  THEN 'not_yet_valid'
                WHEN evidence.valid_until <= statement_timestamp()
                  THEN 'expired'
                WHEN evidence.agency_scope NOT IN ($4, '*')
                  THEN 'out_of_scope'
                WHEN evidence.conflict_status = 'unresolved'
                  THEN 'unresolved_conflict'
                WHEN EXISTS (
                  SELECT 1
                  FROM tp_private.g1_evidence AS other
                  JOIN tp_ledger.g1_evidence_verification_receipts
                    AS other_verification
                    ON other_verification.tenant_id = other.tenant_id
                   AND other_verification.evidence_id = other.evidence_id
                  JOIN tp_private.g1_verification_keys AS other_key
                    ON other_key.tenant_id = other.tenant_id
                   AND other_key.verification_key_id =
                     other.verification_key_id
                  WHERE other.tenant_id = evidence.tenant_id
                    AND other.incident_id = evidence.incident_id
                    AND other.evidence_id <> evidence.evidence_id
                    AND other.claim_key = evidence.claim_key
                    AND other.claim_value <> evidence.claim_value
                    AND other.provenance_status = 'verified'
                    AND other_verification.outcome = 'verified'
                    AND other_verification.incident_id = other.incident_id
                    AND other_verification.issuer = other.issuer
                    AND other_verification.verification_key_id =
                      other.verification_key_id
                    AND other_verification.verifier_version =
                      other.verifier_version
                    AND other_verification.signed_payload_digest =
                      other.signed_payload_digest
                    AND other_verification.signature_digest =
                      other.signature_digest
                    AND other_key.status = 'active'
                    AND other_key.issuer = other.issuer
                    AND other_key.public_key_digest =
                      other_verification.public_key_digest
                    AND other.observed_at >= other_key.valid_from
                    AND other.observed_at < other_key.valid_until
                    AND other.observed_at <=
                      statement_timestamp() + INTERVAL '5 minutes'
                    AND other.valid_from <= statement_timestamp()
                    AND other.valid_until > statement_timestamp()
                    AND other.agency_scope IN ($4, '*')
                )
                  THEN 'unresolved_conflict'
                ELSE 'admissible'
              END AS admissibility
            FROM tp_private.g1_evidence AS evidence
            LEFT JOIN tp_ledger.g1_evidence_verification_receipts
              AS verification
              ON verification.tenant_id = evidence.tenant_id
             AND verification.evidence_id = evidence.evidence_id
            LEFT JOIN tp_private.g1_verification_keys AS verification_key
              ON verification_key.tenant_id = evidence.tenant_id
             AND verification_key.verification_key_id =
               evidence.verification_key_id
            WHERE evidence.tenant_id = $1::UUID
              AND evidence.evidence_id = $2::UUID
              AND evidence.incident_id = $3::UUID
          `,
          [
            request.tenantId,
            request.evidenceId,
            request.incidentId,
            request.agency
          ]
        );

        if (
          evidence.rowCount !== 1 ||
          evidence.rows[0].admissibility !== "admissible"
        ) {
          const reason =
            evidence.rowCount === 1
              ? evidence.rows[0].admissibility
              : "evidence_missing";
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = $3
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId, reason]
          );
          return {
            outcome: "authorization_denied",
            reason,
            requestDigest: request.requestDigest,
            authorityCurrent: false,
            receipt: denied.rows[0]
          };
        }

        const evidenceDigest = evidenceDigestFor(evidence.rows[0]);
        if (
          evidence.rows[0].evidence_digest !== evidenceDigest ||
          evidenceDigest !== request.selectedEvidenceDigest
        ) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = 'selected_evidence_digest_mismatch'
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId]
          );
          return {
            outcome: "authorization_denied",
            reason: "selected_evidence_digest_mismatch",
            requestDigest: request.requestDigest,
            authorityCurrent: false,
            receipt: denied.rows[0]
          };
        }
        if (transactionContext.barrier) {
          await transactionContext.barrier.wait();
        }

        const resource = await client.query(
          `
            SELECT *, statement_timestamp() AS database_now
            FROM tp_private.g1_resources
            WHERE tenant_id = $1::UUID
              AND resource_id = $2
            FOR UPDATE
          `,
          [request.tenantId, request.resourceId]
        );
        if (resource.rowCount !== 1) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = 'resource_missing',
                  evidence_digest = $3
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId, evidenceDigest]
          );
          return {
            outcome: "authorization_denied",
            reason: "resource_missing",
            requestDigest: request.requestDigest,
            authorityCurrent: false,
            receipt: denied.rows[0]
          };
        }
        const current = resource.rows[0];
        if (current.active_run_id !== request.runId) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = 'inactive_run',
                  evidence_digest = $3
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId, evidenceDigest]
          );
          return {
            outcome: "authorization_denied",
            reason: "inactive_run",
            requestDigest: request.requestDigest,
            authorityCurrent: false,
            receipt: denied.rows[0]
          };
        }

        if (
          current.holder_operation_id &&
          new Date(current.lease_expires_at).getTime() >
            new Date(current.database_now).getTime()
        ) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'resource_held_denied',
                  reason = 'active_holder',
                  evidence_digest = $3,
                  observed_holder_operation_id = $4::UUID,
                  observed_fence = $5::INT8
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [
              request.tenantId,
              request.operationId,
              evidenceDigest,
              current.holder_operation_id,
              current.current_fence
            ]
          );
          return {
            outcome: "resource_held_denied",
            requestDigest: request.requestDigest,
            authorityCurrent: false,
            receipt: denied.rows[0]
          };
        }

        const acquired = await client.query(
          `
            UPDATE tp_private.g1_resources
            SET current_fence = current_fence + 1,
                holder_incident_id = $3::UUID,
                holder_operation_id = $4::UUID,
                holder_agent_id = $5,
                holder_proposal_digest = $8,
                holder_logical_authority_key_sha256 = $9,
                lease_expires_at =
                  statement_timestamp() +
                  ($6::INT8 * INTERVAL '1 millisecond'),
                updated_at = statement_timestamp()
            WHERE tenant_id = $1::UUID
              AND resource_id = $2
              AND active_run_id = $7::UUID
              AND current_fence < 9223372036854775807
              AND (
                holder_operation_id IS NULL
                OR lease_expires_at <= statement_timestamp()
              )
              AND EXISTS (
                SELECT 1
                FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
                WHERE proposal.tenant_id = $1::UUID
                  AND proposal.proposal_digest = $8
                  AND proposal.logical_authority_key_sha256 = $9
                  AND proposal.expires_at > statement_timestamp()
              )
            RETURNING current_fence, lease_expires_at
          `,
          [
            request.tenantId,
            request.resourceId,
            request.incidentId,
            request.operationId,
            request.agentId,
            request.leaseMs,
            request.runId,
            request.proposalDigest,
            request.logicalAuthorityKeySha256
          ]
        );
        if (acquired.rowCount !== 1) {
          const currentProposal = await this.#boundProposal(client, request);
          if (
            !currentProposal.ok &&
            currentProposal.reason === "proposal_authorization_expired"
          ) {
            const denied = await client.query(
              `
                UPDATE tp_ledger.g1_authority_receipts
                SET outcome = 'authorization_denied',
                    reason = 'proposal_authorization_expired',
                    evidence_digest = $3
                WHERE tenant_id = $1::UUID
                  AND operation_id = $2::UUID
                RETURNING *
              `,
              [request.tenantId, request.operationId, evidenceDigest]
            );
            return {
              outcome: "authorization_denied",
              reason: "proposal_authorization_expired",
              requestDigest: request.requestDigest,
              authorityCurrent: false,
              receipt: denied.rows[0]
            };
          }
          throw new InvariantViolationError(
            "locked resource could not be acquired or denied deterministically"
          );
        }

        const fencingToken = acquired.rows[0].current_fence;
        const leaseExpiresAt = acquired.rows[0].lease_expires_at;
        const receipt = await client.query(
          `
            UPDATE tp_ledger.g1_authority_receipts
            SET outcome = 'resource_reserved',
                evidence_digest = $3,
                fencing_token = $4::INT8,
                lease_expires_at = $5::TIMESTAMPTZ
            WHERE tenant_id = $1::UUID
              AND operation_id = $2::UUID
            RETURNING *
          `,
          [
            request.tenantId,
            request.operationId,
            evidenceDigest,
            fencingToken,
            leaseExpiresAt
          ]
        );
        const outbox = await client.query(
          `
            INSERT INTO tp_ledger.g1_outbox_intents (
              tenant_id,
              operation_id,
              request_digest,
              proposal_digest,
              logical_action_digest,
              authorization_epoch,
              logical_authority_key_sha256,
              authorization_binding_sha256,
              run_id,
              incident_id,
              resource_id,
              fencing_token,
              effect_key,
              intent_kind,
              payload,
              payload_digest
            )
            VALUES (
              $1::UUID,
              $2::UUID,
              $3,
              $4,
              $5,
              $6::INT8,
              $7,
              $8,
              $9::UUID,
              $10::UUID,
              $11,
              $12::INT8,
              $13::UUID,
              'dispatch_rescue_unit',
              $14::JSONB,
              $15
            )
            RETURNING *
          `,
          [
            request.tenantId,
            request.operationId,
            request.requestDigest,
            request.proposalDigest,
            request.logicalActionDigest,
            request.authorizationEpoch,
            request.logicalAuthorityKeySha256,
            request.authorizationBindingSha256,
            request.runId,
            request.incidentId,
            request.resourceId,
            fencingToken,
            request.effectKey,
            JSON.stringify(request.payload),
            request.payloadDigest
          ]
        );

        await beforeCommitObserver?.();
        const finalAuthority = await client.query(
          `
            SELECT
              resource.lease_expires_at > statement_timestamp()
              AND proposal.expires_at > statement_timestamp()
                AS authority_current
            FROM tp_private.g1_resources AS resource
            JOIN tp_ledger.g1_authority_receipts AS final_receipt
              ON final_receipt.tenant_id = resource.tenant_id
             AND final_receipt.operation_id = resource.holder_operation_id
             AND final_receipt.outcome = 'resource_reserved'
            JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
              ON proposal.tenant_id = final_receipt.tenant_id
             AND proposal.proposal_digest = final_receipt.proposal_digest
             AND proposal.logical_action_digest =
               final_receipt.logical_action_digest
             AND proposal.authorization_epoch =
               final_receipt.authorization_epoch
             AND proposal.logical_authority_key_sha256 =
               final_receipt.logical_authority_key_sha256
             AND proposal.authorization_binding_sha256 =
               final_receipt.authorization_binding_sha256
            WHERE resource.tenant_id = $1::UUID
              AND resource.resource_id = $2
              AND resource.active_run_id = $3::UUID
              AND resource.holder_operation_id = $4::UUID
              AND resource.current_fence = $5::INT8
          `,
          [
            request.tenantId,
            request.resourceId,
            request.runId,
            request.operationId,
            fencingToken
          ]
        );
        const authorityCurrent =
          finalAuthority.rowCount === 1 &&
          finalAuthority.rows[0].authority_current === true;
        return {
          outcome: "resource_reserved",
          requestDigest: request.requestDigest,
          authorityCurrent,
          requiresFreshAuthorization: !authorityCurrent,
          receipt: receipt.rows[0],
          outbox: outbox.rows[0]
        };
      },
      { barrier, commitDispatchObserver, afterCommitObserver }
    );
    const committedOutcome = result.receipt?.outcome ?? result.outcome;
    const committedRequestDigest =
      result.receipt?.request_digest ??
      result.requestDigest ??
      unboundRequest.requestDigest;
    const authorityCurrent = result.authorityCurrent === true;
    const requiresFreshAuthorization =
      result.requiresFreshAuthorization === true ||
      result.authorityCurrent === false ||
      committedOutcome.includes("denied");
    const databaseNow = result.transaction.databaseNow;
    return {
      ...result,
      requiresFreshAuthorization,
      commit:
        result.durableMutation === false
          ? nonDurableDatabaseResult({
              operation: "authority",
              operationDigest: unboundRequest.requestDigest,
              observation: "direct_ack",
              databaseNow,
              outcome: committedOutcome,
              reason: result.reason
            })
          : committedDatabaseResult({
              operation: "authority",
              operationDigest: committedRequestDigest,
              observation: "direct_ack",
              databaseNow,
              outcome: committedOutcome,
              authorityCurrent,
              requiresFreshAuthorization,
              reason: result.reason ?? result.receipt?.reason ?? null
            })
    };
  }

  async proveSerializableRetry({ tenantId, probeId }, { barrier } = {}) {
    const tenant = requireUuid(tenantId, "tenantId");
    const probe = requireUuid(probeId, "probeId");
    await this.#pool.query(
      `
        INSERT INTO tp_private.g1_retry_probes
          (tenant_id, probe_id, value)
        VALUES ($1::UUID, $2::UUID, 0)
      `,
      [tenant, probe]
    );

    const contenders = await Promise.all(
      ["left", "right"].map((name) =>
        this.#runSerializable(
          async (client, transactionContext) => {
            const observed = await client.query(
              `
                SELECT value
                FROM tp_private.g1_retry_probes
                WHERE tenant_id = $1::UUID
                  AND probe_id = $2::UUID
              `,
              [tenant, probe]
            );
            if (transactionContext.barrier) {
              await transactionContext.barrier.wait();
            }
            const updated = await client.query(
              `
                UPDATE tp_private.g1_retry_probes
                SET value = $3::INT8
                WHERE tenant_id = $1::UUID
                  AND probe_id = $2::UUID
                RETURNING value
              `,
              [
                tenant,
                probe,
                (BigInt(observed.rows[0].value) + 1n).toString()
              ]
            );
            return {
              contender: name,
              observedValue: observed.rows[0].value,
              committedValue: updated.rows[0].value
            };
          },
          { barrier }
        )
      )
    );
    const final = await this.#pool.query(
      `
        SELECT value
        FROM tp_private.g1_retry_probes
        WHERE tenant_id = $1::UUID
          AND probe_id = $2::UUID
      `,
      [tenant, probe]
    );
    return {
      contenders,
      finalValue: final.rows[0].value,
      retryCodes: contenders.flatMap(
        ({ transaction }) => transaction.retryCodes
      )
    };
  }

  async reconcileRequest(input) {
    const unboundRequest = normalizeRequest(input);
    const unknown = (reason, details = {}) => ({
      status: "UNKNOWN_DO_NOT_ACT",
      requestDigest: unboundRequest.requestDigest,
      reason,
      ...details,
      commit: unknownDatabaseResult({
        operation: "authority",
        operationDigest: unboundRequest.requestDigest,
        reason,
        requiresFreshAuthorization: true
      })
    });
    const client = new Client(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: 1,
      applicationName: "tideproof-authority-reconcile"
    }));
    try {
      await client.connect();
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
      );
      const boundProposal = await this.#boundProposal(
        client,
        unboundRequest,
        { requireCurrent: false }
      );
      if (!boundProposal.ok) {
        await client.query("COMMIT");
        return unknown(boundProposal.reason);
      }
      const request = {
        ...unboundRequest,
        authorizationEpoch: boundProposal.authorizationEpoch,
        logicalAuthorityKeySha256:
          boundProposal.logicalAuthorityKeySha256,
        authorizationBindingSha256:
          boundProposal.authorizationBindingSha256
      };
      const result = await client.query(
        `
          WITH operation_candidate AS (
            SELECT receipt.*, 'operation_replay'::STRING AS reconciliation_kind
            FROM tp_ledger.g1_authority_receipts AS receipt
            WHERE receipt.tenant_id = $1::UUID
              AND receipt.operation_id = $2::UUID
            LIMIT 2
          ),
          logical_candidate AS (
            SELECT
              receipt.*,
              'logical_authority_replay'::STRING AS reconciliation_kind
            FROM tp_ledger.g1_authority_receipts AS receipt
            WHERE receipt.tenant_id = $1::UUID
              AND receipt.logical_action_digest = $4
              AND receipt.outcome = 'resource_reserved'
              AND NOT EXISTS (SELECT 1 FROM operation_candidate)
            LIMIT 2
          ),
          semantic_candidate AS (
            SELECT receipt.*, 'semantic_replay'::STRING AS reconciliation_kind
            FROM tp_ledger.g1_authority_receipts AS receipt
            WHERE receipt.tenant_id = $1::UUID
              AND receipt.request_digest = $3
              AND NOT EXISTS (SELECT 1 FROM operation_candidate)
              AND NOT EXISTS (SELECT 1 FROM logical_candidate)
            LIMIT 2
          ),
          selected_receipt AS (
            SELECT * FROM operation_candidate
            UNION ALL
            SELECT * FROM logical_candidate
            UNION ALL
            SELECT * FROM semantic_candidate
          )
          SELECT
            receipt.*,
            outbox.intent_id,
            outbox.operation_id AS outbox_operation_id,
            outbox.request_digest AS outbox_request_digest,
            outbox.proposal_digest AS outbox_proposal_digest,
            outbox.logical_action_digest AS outbox_logical_action_digest,
            outbox.authorization_epoch AS outbox_authorization_epoch,
            outbox.logical_authority_key_sha256 AS
              outbox_logical_authority_key_sha256,
            outbox.authorization_binding_sha256 AS
              outbox_authorization_binding_sha256,
            outbox.run_id AS outbox_run_id,
            outbox.incident_id AS outbox_incident_id,
            outbox.resource_id AS outbox_resource_id,
            outbox.effect_key AS outbox_effect_key,
            outbox.intent_kind AS outbox_intent_kind,
            outbox.payload AS outbox_payload,
            outbox.payload_digest AS outbox_payload_digest,
            outbox.fencing_token AS outbox_fencing_token,
            resource.current_fence,
            resource.active_run_id,
            resource.holder_operation_id,
            resource.holder_proposal_digest,
            resource.holder_logical_authority_key_sha256,
            resource.lease_expires_at AS resource_lease_expires_at,
            proposal.tenant_id AS receipt_proposal_tenant_id,
            proposal.proposal_digest AS receipt_proposal_digest,
            proposal.logical_action_digest AS
              receipt_proposal_logical_action_digest,
            proposal.resource_id AS receipt_proposal_resource_id,
            proposal.agency AS receipt_proposal_agency,
            proposal.action_kind AS receipt_proposal_action_kind,
            proposal.payload AS receipt_proposal_payload,
            proposal.payload_canonical AS receipt_proposal_payload_canonical,
            proposal.payload_digest AS receipt_proposal_payload_digest,
            proposal.retrieval_id AS receipt_proposal_retrieval_id,
            proposal.run_id AS receipt_proposal_run_id,
            proposal.incident_id AS receipt_proposal_incident_id,
            proposal.authority_evidence_binding_sha256 AS
              receipt_proposal_authority_evidence_binding_sha256,
            proposal.policy_version AS receipt_proposal_policy_version,
            proposal.selected_rank AS receipt_proposal_selected_rank,
            proposal.selected_evidence_id AS
              receipt_proposal_selected_evidence_id,
            proposal.selected_evidence_digest AS
              receipt_proposal_selected_evidence_digest,
            proposal.admitted_at AS receipt_proposal_admitted_at,
            proposal.expires_at AS receipt_proposal_expires_at,
            proposal.authorization_epoch AS
              receipt_proposal_authorization_epoch,
            proposal.logical_authority_key_sha256 AS
              receipt_proposal_logical_authority_key_sha256,
            proposal.authorization_binding_sha256 AS
              receipt_proposal_authorization_binding_sha256,
            statement_timestamp() AS database_now
          FROM selected_receipt AS receipt
          LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
            ON outbox.tenant_id = receipt.tenant_id
           AND outbox.operation_id = receipt.operation_id
          LEFT JOIN tp_private.g1_resources AS resource
            ON resource.tenant_id = receipt.tenant_id
           AND resource.resource_id = receipt.resource_id
          LEFT JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
            ON proposal.tenant_id = receipt.tenant_id
           AND proposal.proposal_digest = receipt.proposal_digest
          LIMIT 2
        `,
        [
          request.tenantId,
          request.operationId,
          request.requestDigest,
          request.logicalActionDigest
        ]
      );
      await client.query("COMMIT");

      if (result.rowCount !== 1) {
        return unknown(
          result.rowCount === 0
            ? "terminal_receipt_not_observed"
            : "multiple_receipts_observed"
        );
      }
      const row = result.rows[0];
      let normalized;
      try {
        normalized = normalizeAuthorityReconciliationRow(row, request);
      } catch {
        return unknown("partial_or_superseded_authority_state");
      }
      const { authorityStillCurrent, committedOutcome } = normalized;
      const requiresFreshAuthorization =
        !authorityStillCurrent || committedOutcome.includes("denied");
      const commit = committedDatabaseResult({
        operation: "authority",
        operationDigest: row.request_digest,
        observation: "read_reconciled",
        databaseNow: databaseTimestampFromDriver(row.database_now),
        outcome: committedOutcome,
        authorityCurrent: authorityStillCurrent,
        requiresFreshAuthorization,
        reason: row.reason ?? null
      });
      return {
        status: commit.status,
        requestDigest: request.requestDigest,
        committedRequestDigest: row.request_digest,
        replayKind: row.reconciliation_kind,
        receipt: row,
        requiresFreshAuthorization,
        commit
      };
    } catch (error) {
      await rollbackQuietly(client);
      return unknown("reconciliation_unavailable", {
        errorCode: error.code ?? error.name
      });
    } finally {
      await client.end().catch(() => {});
    }
  }

  async recordProtectedEffect(input, { authenticatedAgentId } = {}) {
    const unboundRequest = normalizeRequest(input);
    const authenticatedActor = requireText(
      authenticatedAgentId,
      "authenticatedAgentId"
    );
    if (authenticatedActor !== unboundRequest.agentId) {
      return { outcome: "stale_or_unauthorized_fence_denied" };
    }
    const fencingToken = requireText(
      String(input.fencingToken),
      "fencingToken"
    );
    if (!/^[1-9][0-9]*$/.test(fencingToken)) {
      throw new TypeError("fencingToken must be a positive INT8 value");
    }

    return this.#runSerializable(async (client) => {
      const boundProposal = await this.#boundProposal(
        client,
        unboundRequest
      );
      if (!boundProposal.ok) {
        return {
          outcome: "stale_or_unauthorized_fence_denied",
          reason: boundProposal.reason
        };
      }
      const request = {
        ...unboundRequest,
        authorizationEpoch: boundProposal.authorizationEpoch,
        logicalAuthorityKeySha256:
          boundProposal.logicalAuthorityKeySha256,
        authorizationBindingSha256:
          boundProposal.authorizationBindingSha256
      };
      const existing = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_protected_effects
          WHERE tenant_id = $1::UUID
            AND (
              effect_key = $2::UUID
              OR operation_id = $3::UUID
              OR logical_action_digest = $4
            )
          LIMIT 2
        `,
        [
          request.tenantId,
          request.effectKey,
          request.operationId,
          request.logicalActionDigest
        ]
      );
      if (existing.rowCount > 1) {
        throw new InvariantViolationError(
          "effect key and operation matched different effects"
        );
      }
      if (existing.rowCount === 1) {
        const effect = existing.rows[0];
        if (
          effect.logical_action_digest === request.logicalActionDigest &&
          effect.payload_digest === request.payloadDigest
        ) {
          return {
            outcome: "effect_already_recorded",
            replayKind:
              effect.operation_id === request.operationId
                ? "operation_replay"
                : "logical_authority_replay",
            effect
          };
        }
        if (
          effect.effect_key !== request.effectKey ||
          effect.operation_id !== request.operationId ||
          effect.request_digest !== request.requestDigest ||
          effect.fencing_token !== fencingToken ||
          effect.payload_digest !== request.payloadDigest
        ) {
          throw new EffectKeyMismatchError(request.effectKey);
        }
        return { outcome: "effect_already_recorded", effect };
      }

      const inserted = await client.query(
        `
          INSERT INTO tp_ledger.g1_protected_effects (
            tenant_id,
            effect_key,
            operation_id,
            request_digest,
            proposal_digest,
            logical_action_digest,
            authorization_epoch,
            logical_authority_key_sha256,
            authorization_binding_sha256,
            run_id,
            incident_id,
            resource_id,
            agent_id,
            fencing_token,
            payload_digest
          )
          SELECT
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5,
            $6,
            $7::INT8,
            $8,
            $9,
            $10::UUID,
            $11::UUID,
            $12,
            $13,
            $14::INT8,
            $15
          FROM tp_private.g1_resources AS resource
          JOIN tp_ledger.g1_outbox_intents AS outbox
            ON outbox.tenant_id = resource.tenant_id
           AND outbox.operation_id = $3::UUID
           AND outbox.request_digest = $4
           AND outbox.proposal_digest = $5
           AND outbox.logical_action_digest = $6
           AND outbox.authorization_epoch = $7::INT8
           AND outbox.logical_authority_key_sha256 = $8
           AND outbox.authorization_binding_sha256 = $9
           AND outbox.run_id = $10::UUID
           AND outbox.incident_id = $11::UUID
           AND outbox.resource_id = $12
           AND outbox.fencing_token = $14::INT8
           AND outbox.effect_key = $2::UUID
           AND outbox.payload_digest = $15
          JOIN tp_ledger.g1_authority_receipts AS receipt
           ON receipt.tenant_id = outbox.tenant_id
           AND receipt.operation_id = outbox.operation_id
           AND receipt.proposal_digest = $5
           AND receipt.logical_action_digest = $6
           AND receipt.authorization_epoch = $7::INT8
           AND receipt.logical_authority_key_sha256 = $8
           AND receipt.authorization_binding_sha256 = $9
           AND receipt.agent_id = $13
           AND receipt.outcome = 'resource_reserved'
          JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
           ON proposal.tenant_id = outbox.tenant_id
           AND proposal.proposal_digest = outbox.proposal_digest
           AND proposal.logical_action_digest = outbox.logical_action_digest
           AND proposal.authorization_epoch = outbox.authorization_epoch
           AND proposal.logical_authority_key_sha256 =
             outbox.logical_authority_key_sha256
           AND proposal.authorization_binding_sha256 =
             outbox.authorization_binding_sha256
           AND proposal.run_id = outbox.run_id
           AND proposal.incident_id = outbox.incident_id
           AND proposal.resource_id = outbox.resource_id
           AND proposal.payload = outbox.payload
           AND proposal.payload_digest = outbox.payload_digest
          WHERE resource.tenant_id = $1::UUID
            AND resource.resource_id = $12
            AND resource.active_run_id = $10::UUID
            AND resource.holder_incident_id = $11::UUID
            AND resource.holder_operation_id = $3::UUID
            AND resource.holder_agent_id = $13
            AND resource.holder_proposal_digest = $5
            AND resource.holder_logical_authority_key_sha256 = $8
            AND resource.current_fence = $14::INT8
            AND encode(
              sha256(proposal.payload_canonical::BYTES),
              'hex'
            ) = outbox.payload_digest
            AND resource.lease_expires_at > statement_timestamp()
            AND proposal.expires_at > statement_timestamp()
          ON CONFLICT DO NOTHING
          RETURNING *
        `,
        [
          request.tenantId,
          request.effectKey,
          request.operationId,
          request.requestDigest,
          request.proposalDigest,
          request.logicalActionDigest,
          request.authorizationEpoch,
          request.logicalAuthorityKeySha256,
          request.authorizationBindingSha256,
          request.runId,
          request.incidentId,
          request.resourceId,
          request.agentId,
          fencingToken,
          request.payloadDigest
        ]
      );
      if (inserted.rowCount !== 1) {
        const raced = await client.query(
          `
            SELECT *
            FROM tp_ledger.g1_protected_effects
            WHERE tenant_id = $1::UUID
              AND (
                effect_key = $2::UUID
                OR operation_id = $3::UUID
                OR logical_action_digest = $4
              )
            LIMIT 2
          `,
          [
            request.tenantId,
            request.effectKey,
            request.operationId,
            request.logicalActionDigest
          ]
        );
        if (raced.rowCount > 1) {
          throw new InvariantViolationError(
            "effect key and operation matched different effects"
          );
        }
        if (raced.rowCount === 1) {
          const effect = raced.rows[0];
          if (
            effect.logical_action_digest === request.logicalActionDigest &&
            effect.payload_digest === request.payloadDigest
          ) {
            return {
              outcome: "effect_already_recorded",
              replayKind: "logical_authority_replay",
              effect
            };
          }
          if (
            effect.effect_key !== request.effectKey ||
            effect.operation_id !== request.operationId ||
            effect.request_digest !== request.requestDigest ||
            effect.fencing_token !== fencingToken ||
            effect.payload_digest !== request.payloadDigest
          ) {
            throw new EffectKeyMismatchError(request.effectKey);
          }
          return { outcome: "effect_already_recorded", effect };
        }
        return { outcome: "stale_or_unauthorized_fence_denied" };
      }
      const finalCurrent = await client.query(
        `
          SELECT
            resource.lease_expires_at > statement_timestamp()
            AND proposal.expires_at > statement_timestamp()
              AS authority_current
          FROM tp_private.g1_resources AS resource
          JOIN tp_ledger.g1_authority_receipts AS receipt
            ON receipt.tenant_id = resource.tenant_id
           AND receipt.operation_id = resource.holder_operation_id
           AND receipt.outcome = 'resource_reserved'
          JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
            ON proposal.tenant_id = receipt.tenant_id
           AND proposal.proposal_digest = receipt.proposal_digest
           AND proposal.logical_action_digest = receipt.logical_action_digest
           AND proposal.authorization_epoch = receipt.authorization_epoch
           AND proposal.logical_authority_key_sha256 =
             receipt.logical_authority_key_sha256
           AND proposal.authorization_binding_sha256 =
             receipt.authorization_binding_sha256
          WHERE resource.tenant_id = $1::UUID
            AND resource.resource_id = $2
            AND resource.active_run_id = $3::UUID
            AND resource.holder_operation_id = $4::UUID
            AND resource.current_fence = $5::INT8
        `,
        [
          request.tenantId,
          request.resourceId,
          request.runId,
          request.operationId,
          fencingToken
        ]
      );
      if (
        finalCurrent.rowCount !== 1 ||
        finalCurrent.rows[0].authority_current !== true
      ) {
        const removed = await client.query(
          `
            DELETE FROM tp_ledger.g1_protected_effects
            WHERE tenant_id = $1::UUID
              AND effect_key = $2::UUID
              AND operation_id = $3::UUID
            RETURNING operation_id
          `,
          [request.tenantId, request.effectKey, request.operationId]
        );
        if (removed.rowCount !== 1) {
          throw new InvariantViolationError(
            "expired protected effect could not be removed before commit"
          );
        }
        return { outcome: "stale_or_unauthorized_fence_denied" };
      }
      return {
        outcome: "protected_effect_recorded",
        effect: inserted.rows[0]
      };
    });
  }

  async snapshot({ tenantId, resourceId }) {
    const values = [
      requireUuid(tenantId, "tenantId"),
      requireText(resourceId, "resourceId")
    ];
    const client = await this.#pool.connect();
    try {
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
      );
      const resource = await client.query(
        `
          SELECT *
          FROM tp_private.g1_resources
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
        `,
        values
      );
      const receipts = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_authority_receipts
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
          ORDER BY recorded_at, operation_id
        `,
        values
      );
      const proposals = await client.query(
        `
          SELECT DISTINCT proposal.*
          FROM tp_ledger.g1_dvi_proposal_receipts AS proposal
          JOIN tp_ledger.g1_authority_receipts AS receipt
            ON receipt.tenant_id = proposal.tenant_id
           AND receipt.proposal_digest = proposal.proposal_digest
           AND receipt.logical_action_digest = proposal.logical_action_digest
           AND receipt.authorization_epoch = proposal.authorization_epoch
           AND receipt.logical_authority_key_sha256 =
             proposal.logical_authority_key_sha256
           AND receipt.authorization_binding_sha256 =
             proposal.authorization_binding_sha256
          WHERE receipt.tenant_id = $1::UUID
            AND receipt.resource_id = $2
          ORDER BY proposal.authorization_epoch, proposal.proposal_digest
        `,
        values
      );
      const outbox = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_outbox_intents
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
          ORDER BY created_at, operation_id
        `,
        values
      );
      const effects = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_protected_effects
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
          ORDER BY recorded_at, operation_id
        `,
        values
      );
      await client.query("COMMIT");
      return {
        resource: resource.rows[0] ?? null,
        proposals: proposals.rows,
        receipts: receipts.rows,
        outbox: outbox.rows,
        effects: effects.rows
      };
    } catch (error) {
      await rollbackQuietly(client);
      throw error;
    } finally {
      client.release();
    }
  }
}
