import crypto from "node:crypto";
import { Client, Pool } from "pg";

import {
  admissibleVectorAuditorPoolConfig,
  admissibleVectorPoolConfig,
  proveFreshAdmissibleVectorSnapshot
} from "../src/cloud/admissible-vector-retrieval.js";
import {
  AuthorityStore,
  normalizedAuthorityRequestFor
} from "../src/cloud/authority-store.js";
import { authorizeDviProposalWithClient } from
  "../src/cloud/dvi-proposal-authorization.js";
import { connectionStringForUser } from "../src/cloud/primary-security.js";
import { createSyntheticEvidenceSigner } from
  "./lib/synthetic-evidence.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const CONTENDER_COUNT = 2;
const DVI_LIMIT = 10;
const DVI_CANDIDATE_COUNT = DVI_LIMIT + 1;
const DVI_TTL_MS = 30 * 60_000;
const AUTHORITY_LEASE_MS = 30 * 60_000;
const MINIMUM_RECOVERY_RESIDUAL_MS = 10 * 60_000;
const QUERY_EMBEDDING = Object.freeze([1, 0, 0]);
const G1_SPEND_RESULT_COLUMNS = Object.freeze([
  "decision_authority_current",
  "decision_authorization_binding_sha256",
  "decision_authorization_epoch",
  "decision_database_now",
  "decision_fencing_token",
  "decision_lease_expires_at",
  "decision_logical_action_digest",
  "decision_logical_authority_key_sha256",
  "decision_operation_id",
  "decision_outcome",
  "decision_proposal_digest",
  "decision_reason",
  "decision_replay_kind",
  "decision_request_digest"
]);
const SPEND_AUTHORITY_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID, $2::UUID, $3, $4::JSONB, $5, $6, $7,
    $8::UUID, $9::UUID, $10, $11, $12, $13::UUID, $14::UUID,
    $15::JSONB, $16, $17, $18::INT8
  )
`;
const RECOVERY_RESIDUAL_SQL = `
  WITH observed_clock AS (
    SELECT clock_timestamp() AS database_now
  )
  SELECT
    observed_clock.database_now,
    receipt.operation_id,
    receipt.request_digest,
    receipt.outcome,
    receipt.fencing_token,
    receipt.evidence_id,
    receipt.evidence_digest,
    receipt.lease_expires_at AS receipt_lease_expires_at,
    resource.holder_operation_id,
    resource.current_fence,
    resource.lease_expires_at AS resource_lease_expires_at,
    proposal.authority_evidence_binding_sha256,
    proposal.selected_evidence_id AS proposal_selected_evidence_id,
    proposal.selected_evidence_digest AS proposal_selected_evidence_digest,
    proposal.expires_at AS proposal_expires_at,
    evidence.valid_until AS evidence_valid_until,
    floor(extract(epoch FROM (
      least(
        receipt.lease_expires_at,
        resource.lease_expires_at,
        proposal.expires_at,
        evidence.valid_until
      ) - observed_clock.database_now
    )) * 1000)::INT8 AS minimum_residual_ms
  FROM tp_ledger.g1_authority_receipts AS receipt
  JOIN tp_private.g1_resources AS resource
    ON resource.tenant_id = receipt.tenant_id
   AND resource.resource_id = receipt.resource_id
   AND resource.active_run_id = receipt.run_id
   AND resource.holder_operation_id = receipt.operation_id
   AND resource.current_fence = receipt.fencing_token
  JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
    ON proposal.tenant_id = receipt.tenant_id
   AND proposal.proposal_digest = receipt.proposal_digest
   AND proposal.logical_action_digest = receipt.logical_action_digest
   AND proposal.authorization_epoch = receipt.authorization_epoch
   AND proposal.logical_authority_key_sha256 =
     receipt.logical_authority_key_sha256
   AND proposal.authorization_binding_sha256 =
     receipt.authorization_binding_sha256
   AND proposal.selected_evidence_id = receipt.evidence_id
   AND proposal.selected_evidence_digest = receipt.evidence_digest
  JOIN tp_ledger.g1_dvi_selection_receipts AS selection
    ON selection.tenant_id = proposal.tenant_id
   AND selection.retrieval_id = proposal.retrieval_id
   AND selection.authority_evidence_binding_sha256 =
     proposal.authority_evidence_binding_sha256
   AND selection.run_id = proposal.run_id
   AND selection.incident_id = proposal.incident_id
   AND selection.selected_evidence_id = proposal.selected_evidence_id
   AND selection.selected_evidence_digest = proposal.selected_evidence_digest
   AND selection.admitted_at = proposal.admitted_at
   AND selection.expires_at = proposal.expires_at
  JOIN tp_private.g1_evidence AS evidence
    ON evidence.tenant_id = receipt.tenant_id
   AND evidence.evidence_id = receipt.evidence_id
   AND evidence.evidence_digest = receipt.evidence_digest
  CROSS JOIN observed_clock
  WHERE receipt.tenant_id = $1::UUID
    AND receipt.resource_id = $2
    AND receipt.operation_id = $3::UUID
    AND receipt.evidence_id = $4::UUID
    AND receipt.request_digest = $5
    AND receipt.outcome = 'resource_reserved'
`;
const DVI_RESIDUAL_SQL = `
  WITH observed_clock AS (
    SELECT clock_timestamp() AS database_now
  )
  SELECT
    selection.admitted_at,
    selection.expires_at,
    observed_clock.database_now,
    floor(extract(epoch FROM (
      selection.expires_at - observed_clock.database_now
    )) * 1000)::INT8 AS minimum_residual_ms
  FROM tp_ledger.g1_dvi_selection_receipts AS selection
  CROSS JOIN observed_clock
  WHERE selection.tenant_id = $1::UUID
    AND selection.retrieval_id = $2::UUID
    AND selection.authority_evidence_binding_sha256 = $3
    AND selection.selected_evidence_id = $4::UUID
    AND selection.selected_evidence_digest = $5
`;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && [Object.prototype, null].includes(
      Object.getPrototypeOf(value)
    );
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function derivedUuid(operationId, sourceCommit, treeDigest, label) {
  requireCondition(UUID.test(operationId ?? "") &&
    HEX_40.test(sourceCommit ?? "") && HEX_40.test(treeDigest ?? "") &&
    /^[a-z][a-z0-9-]{0,62}$/u.test(label),
  "FRESH_RECOVERY_SOURCE_IDENTITY_REJECTED");
  const bytes = crypto.createHash("sha256")
    .update(
      "prooftoact-fresh-recovery-source-v2\n" +
      `${operationId}\n${sourceCommit}\n${treeDigest}\n${label}\n`
    )
    .digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  return [
    bytes.subarray(0, 4).toString("hex"),
    bytes.subarray(4, 6).toString("hex"),
    bytes.subarray(6, 8).toString("hex"),
    bytes.subarray(8, 10).toString("hex"),
    bytes.subarray(10, 16).toString("hex")
  ].join("-");
}

export function freshRecoverySourceIdentity(
  operationId,
  sourceCommit,
  treeDigest
) {
  const candidateEvidenceIds = Object.freeze(Array.from(
    { length: DVI_CANDIDATE_COUNT },
    (_, index) => derivedUuid(
      operationId,
      sourceCommit,
      treeDigest,
      `candidate-${index + 1}`
    )
  ));
  const contenders = Object.freeze(Array.from(
    { length: CONTENDER_COUNT },
    (_, index) => Object.freeze({
      operationId: derivedUuid(
        operationId, sourceCommit, treeDigest, `authority-operation-${index + 1}`
      ),
      effectKey: derivedUuid(
        operationId, sourceCommit, treeDigest, `effect-${index + 1}`
      ),
      intentNonce: derivedUuid(
        operationId, sourceCommit, treeDigest, `intent-${index + 1}`
      )
    })
  ));
  return Object.freeze({
    tenantId: derivedUuid(operationId, sourceCommit, treeDigest, "tenant"),
    runId: derivedUuid(operationId, sourceCommit, treeDigest, "run"),
    incidentId: derivedUuid(operationId, sourceCommit, treeDigest, "incident"),
    evidenceId: candidateEvidenceIds[0],
    candidateEvidenceIds,
    excludedEvidenceId: derivedUuid(
      operationId, sourceCommit, treeDigest, "excluded-nearest"
    ),
    retrievalId: derivedUuid(
      operationId, sourceCommit, treeDigest, "retrieval"
    ),
    contenders,
    resourceId: `prooftoact-fresh-recovery-${operationId}`
  });
}

function identifierSetDigest(values) {
  requireCondition(Array.isArray(values) && values.length > 0 &&
    values.every((value) => UUID.test(value)) &&
    new Set(values).size === values.length,
  "FRESH_RECOVERY_SOURCE_CANDIDATE_SET_REJECTED");
  return sha256(`${[...values].sort().join("\n")}\n`);
}

function spendValues(request) {
  return [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.proposalDigest,
    request.logicalActionDigest,
    request.selectedEvidenceDigest,
    request.runId,
    request.incidentId,
    request.resourceId,
    request.agentId,
    request.agency,
    request.evidenceId,
    request.effectKey,
    JSON.stringify(request.payload),
    request.payloadDigest,
    request.policyVersion,
    request.leaseMs
  ];
}

async function withClient(connectionString, operation, applicationName) {
  const client = new Client({
    application_name: applicationName,
    connectionString,
    connectionTimeoutMillis: 10_000,
    query_timeout: 20_000,
    statement_timeout: 20_000
  });
  try {
    await client.connect();
    return await operation(client);
  } finally {
    await client.end().catch(() => {});
  }
}

class Barrier {
  #arrived = 0;
  #reject;
  #resolve;
  #settled = false;
  #wait;

  constructor(expected) {
    this.expected = expected;
    this.#wait = new Promise((resolve, rejectPromise) => {
      this.#resolve = resolve;
      this.#reject = rejectPromise;
    });
  }

  fail(cause) {
    if (this.#settled) return;
    this.#settled = true;
    this.#reject(cause);
  }

  async wait() {
    requireCondition(!this.#settled,
      "FRESH_RECOVERY_SOURCE_RACE_BARRIER_REJECTED");
    this.#arrived += 1;
    if (this.#arrived === this.expected) {
      this.#settled = true;
      this.#resolve();
    }
    await this.#wait;
  }
}

async function spendWithRetries(authorizerUrl, request, barrier = null) {
  const retryCodes = [];
  const backendIds = [];
  for (let attempt = 0; attempt <= 20; attempt += 1) {
    const client = new Client({
      application_name: "prooftoact-fresh-recovery-race",
      connectionString: authorizerUrl,
      connectionTimeoutMillis: 10_000,
      query_timeout: 20_000,
      statement_timeout: 20_000
    });
    let reachedBarrier = false;
    try {
      await client.connect();
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const isolation = await client.query("SHOW TRANSACTION ISOLATION LEVEL");
      const backend = await client.query(
        "SELECT pg_backend_pid()::STRING AS backend_id"
      );
      const backendId = String(backend.rows?.[0]?.backend_id ?? "");
      requireCondition(backendId.length > 0,
        "FRESH_RECOVERY_SOURCE_SPEND_SESSION_REJECTED");
      backendIds.push(backendId);
      if (attempt === 0 && barrier) {
        reachedBarrier = true;
        await barrier.wait();
      }
      const result = await client.query(SPEND_AUTHORITY_SQL,
        spendValues(request));
      await client.query("COMMIT");
      requireCondition(result.rowCount === 1 && Array.isArray(result.rows),
        "FRESH_RECOVERY_SOURCE_SPEND_RESULT_REJECTED");
      return Object.freeze({
        row: Object.freeze({ ...result.rows[0] }),
        transaction: Object.freeze({
          backendIds: Object.freeze([...backendIds]),
          initialBackendId: backendIds[0],
          isolation: isolation.rows?.[0]?.transaction_isolation,
          retryCodes: Object.freeze([...retryCodes]),
          serializableRetries: attempt
        })
      });
    } catch (cause) {
      await client.query("ROLLBACK").catch(() => {});
      if (attempt === 0 && barrier && !reachedBarrier) barrier.fail(cause);
      if (cause?.code === "40001" && attempt < 20) {
        retryCodes.push(cause.code);
        continue;
      }
      throw cause;
    } finally {
      await client.end().catch(() => {});
    }
  }
  reject("FRESH_RECOVERY_SOURCE_SERIALIZABLE_RETRY_EXHAUSTED");
}

async function assertChangedInputDeniedDefault(authorizerUrl, request) {
  try {
    await spendWithRetries(authorizerUrl, request);
  } catch (cause) {
    requireCondition(
      changedInputMismatchError(cause),
      "FRESH_RECOVERY_SOURCE_CHANGED_INPUT_UNEXPECTED_ERROR"
    );
    return Object.freeze({
      denied: true,
      reason: "operation_digest_mismatch"
    });
  }
  reject("FRESH_RECOVERY_SOURCE_CHANGED_INPUT_NOT_DENIED");
}

function changedInputMismatchError(cause) {
  return cause?.code === "22000" &&
    cause?.message === "operation digest mismatch";
}

function defaultDependencies(adminConnectionString, credentialBundle) {
  const authorizerUrl = connectionStringForUser(
    adminConnectionString,
    "tp_authorizer_user",
    credentialBundle.passwords.tp_authorizer_user
  );
  return Object.freeze({
    assertChangedInputDenied: (request) =>
      assertChangedInputDeniedDefault(authorizerUrl, request),
    async authorizeContenders(inputs) {
      return Promise.all(inputs.map((input) => withClient(
        authorizerUrl,
        async (client) => {
          const backend = await client.query(
            "SELECT pg_backend_pid()::STRING AS backend_id"
          );
          return Object.freeze({
            authorization: await authorizeDviProposalWithClient(client, input),
            backendId: String(backend.rows?.[0]?.backend_id ?? "")
          });
        },
        "prooftoact-fresh-recovery-proposal"
      )));
    },
    createSigner: createSyntheticEvidenceSigner,
    createStore: () => new AuthorityStore({
      connectionString: adminConnectionString,
      databaseName: "tideproof",
      maxConnections: 4
    }),
    async proveDviSelection(spec, sourceCommit, treeDigest) {
      const authorizerPool = new Pool(admissibleVectorPoolConfig(authorizerUrl));
      const auditorPool = new Pool(admissibleVectorAuditorPoolConfig(
        adminConnectionString
      ));
      try {
        return await proveFreshAdmissibleVectorSnapshot({
          authorizerPool,
          auditorPool,
          spec,
          sourceCommit,
          treeDigest
        });
      } finally {
        await Promise.allSettled([authorizerPool.end(), auditorPool.end()]);
      }
    },
    async raceAuthority(requests) {
      const barrier = new Barrier(requests.length);
      const settled = await Promise.allSettled(requests.map((request) =>
        spendWithRetries(authorizerUrl, request, barrier)));
      return settled;
    },
    readRecoveryResidual: (binding) => withClient(
      adminConnectionString,
      (client) => client.query(RECOVERY_RESIDUAL_SQL, [
        binding.tenantId,
        binding.resourceId,
        binding.operationId,
        binding.evidenceId,
        binding.requestDigest
      ]),
      "prooftoact-fresh-recovery-residual"
    ),
    readDviResidual: (selection) => withClient(
      adminConnectionString,
      (client) => client.query(DVI_RESIDUAL_SQL, [
        selection.dviProposal.tenantId,
        selection.dviProposal.retrievalId,
        selection.dviProposal.authorityEvidenceBindingSha256,
        selection.selectedEvidenceId,
        selection.selectedEvidenceDigest
      ]),
      "prooftoact-fresh-recovery-dvi-residual"
    ),
    replayAuthority: (request) => spendWithRetries(authorizerUrl, request)
  });
}

function validateDependencies(value) {
  const expected = [
    "assertChangedInputDenied",
    "authorizeContenders",
    "createSigner",
    "createStore",
    "proveDviSelection",
    "readDviResidual",
    "raceAuthority",
    "readRecoveryResidual",
    "replayAuthority"
  ];
  requireCondition(exactKeys(value, expected) && expected.every((name) =>
    typeof value[name] === "function"),
  "FRESH_RECOVERY_SOURCE_DEPENDENCIES_REJECTED");
  return value;
}

function candidateEmbedding(index) {
  return [0.92 - index * 0.02, 0.08 + index * 0.02, 0];
}

function logicalActionFor(request) {
  return Object.freeze({
    tenantId: request.tenantId,
    incidentId: request.incidentId,
    resourceId: request.resourceId,
    agency: request.agency,
    actionKind: "dispatch_rescue_unit",
    payload: request.payload
  });
}

function proposalInputFor(request, selection) {
  return Object.freeze({
    tenantId: request.tenantId,
    retrievalId: selection.dviProposal.retrievalId,
    expectedRunId: request.runId,
    expectedIncidentId: request.incidentId,
    requestedSelectedEvidenceId: selection.selectedEvidenceId,
    requestedSelectedEvidenceDigest: selection.selectedEvidenceDigest,
    logicalAction: logicalActionFor(request)
  });
}

function validG1SpendRow(row, request) {
  const isWinner = row?.decision_outcome === "resource_reserved";
  const isDenial = row?.decision_outcome === "resource_held_denied";
  const epoch = Number(row?.decision_authorization_epoch);
  const observedAt = Date.parse(row?.decision_database_now);
  const leaseExpiresAt = row?.decision_lease_expires_at === null
    ? NaN
    : Date.parse(row?.decision_lease_expires_at);
  return exactKeys(row, G1_SPEND_RESULT_COLUMNS) &&
    (isWinner || isDenial) &&
    row.decision_operation_id === request.operationId &&
    row.decision_request_digest === request.requestDigest &&
    row.decision_proposal_digest === request.proposalDigest &&
    row.decision_logical_action_digest === request.logicalActionDigest &&
    Number.isSafeInteger(epoch) && epoch >= 1 &&
    HEX_64.test(row.decision_logical_authority_key_sha256 ?? "") &&
    HEX_64.test(row.decision_authorization_binding_sha256 ?? "") &&
    Number.isFinite(observedAt) &&
    row.decision_replay_kind === null &&
    (
      isWinner
        ? row.decision_reason === null &&
          String(row.decision_fencing_token) === "1" &&
          Number.isFinite(leaseExpiresAt) &&
          row.decision_authority_current === true
        : row.decision_reason === "active_holder" &&
          row.decision_fencing_token === null &&
          row.decision_lease_expires_at === null &&
          row.decision_authority_current === false
    );
}

function validatedRace(settled, requests, snapshot) {
  requireCondition(Array.isArray(settled) && settled.length === CONTENDER_COUNT &&
    settled.every((entry) => entry?.status === "fulfilled"),
  "FRESH_RECOVERY_SOURCE_RACE_SETTLEMENT_REJECTED");
  const attempts = settled.map(({ value }) => value);
  requireCondition(attempts.every(({ row, transaction }) => {
    const request = requests.find(({ operationId }) =>
      operationId === row?.decision_operation_id);
    return request !== undefined && validG1SpendRow(row, request) &&
      transaction?.isolation === "serializable" &&
      typeof transaction.initialBackendId === "string" &&
      transaction.initialBackendId.length > 0;
  }), "FRESH_RECOVERY_SOURCE_G1_SPEND_SHAPE_REJECTED");
  const winners = attempts.filter(({ row }) =>
    row.decision_outcome === "resource_reserved");
  const denials = attempts.filter(({ row }) =>
    row.decision_outcome === "resource_held_denied");
  requireCondition(winners.length === 1 &&
    denials.length === CONTENDER_COUNT - 1 &&
    attempts.every(({ transaction }) =>
      transaction.isolation === "serializable") &&
    new Set(attempts.map(({ transaction }) =>
      transaction.initialBackendId)).size === CONTENDER_COUNT,
  "FRESH_RECOVERY_SOURCE_RACE_OUTCOME_REJECTED");
  const winner = winners[0];
  const winnerIndex = requests.findIndex(({ operationId }) =>
    operationId === winner.row.decision_operation_id);
  const loserIndex = requests.findIndex(({ operationId }) =>
    operationId === denials[0].row.decision_operation_id);
  const receiptOperationIds = snapshot?.receipts?.map(({ operation_id }) =>
    operation_id);
  requireCondition(winnerIndex >= 0 && loserIndex >= 0 && winnerIndex !== loserIndex &&
    snapshot?.receipts?.length === CONTENDER_COUNT &&
    new Set(receiptOperationIds).size === CONTENDER_COUNT &&
    requests.every(({ operationId, requestDigest }) =>
      snapshot.receipts.some((receipt) =>
        receipt.operation_id === operationId &&
        receipt.request_digest === requestDigest)) &&
    snapshot.receipts.filter(({ outcome }) =>
      outcome === "resource_reserved").length === 1 &&
    snapshot.receipts.filter(({ outcome }) =>
      outcome === "resource_held_denied").length === CONTENDER_COUNT - 1 &&
    snapshot.outbox?.length === 1 &&
    snapshot.outbox[0]?.operation_id === winner.row.decision_operation_id &&
    snapshot.effects?.length === 0 &&
    String(snapshot.resource?.current_fence) === "1" &&
    snapshot.resource?.holder_operation_id ===
      winner.row.decision_operation_id &&
    String(winner.row.decision_fencing_token) === "1",
  "FRESH_RECOVERY_SOURCE_DURABLE_RACE_REJECTED");
  return Object.freeze({ attempts, denials, loserIndex, winner, winnerIndex });
}

function validatedResidual(value, binding) {
  const row = value?.rows?.[0];
  const residual = Number(row?.minimum_residual_ms);
  requireCondition(value?.rowCount === 1 &&
    row?.operation_id === binding.operationId &&
    row?.request_digest === binding.requestDigest &&
    row?.evidence_id === binding.evidenceId &&
    row?.proposal_selected_evidence_id === binding.evidenceId &&
    row?.evidence_digest === row?.proposal_selected_evidence_digest &&
    row?.authority_evidence_binding_sha256 ===
      binding.authorityEvidenceBindingSha256 &&
    row?.holder_operation_id === binding.operationId &&
    row?.outcome === "resource_reserved" &&
    String(row?.fencing_token) === "1" &&
    String(row?.current_fence) === "1" &&
    Number.isSafeInteger(residual) && residual >= MINIMUM_RECOVERY_RESIDUAL_MS &&
    Number.isFinite(Date.parse(row.database_now)),
  "FRESH_RECOVERY_SOURCE_RESIDUAL_TTL_REJECTED");
  return Object.freeze({
    databaseObservedAt: new Date(row.database_now).toISOString(),
    minimumRequiredMs: MINIMUM_RECOVERY_RESIDUAL_MS,
    minimumResidualMs: residual,
    source: "COCKROACHDB_CLOCK"
  });
}

function validatedDviResidual(value, dviReceipt) {
  const row = value?.rows?.[0];
  const admittedAt = new Date(row?.admitted_at);
  const expiresAt = new Date(row?.expires_at);
  const databaseNow = new Date(row?.database_now);
  const residual = Number(row?.minimum_residual_ms);
  requireCondition(value?.rowCount === 1 &&
    [admittedAt, expiresAt, databaseNow].every((item) =>
      Number.isFinite(item.getTime())) &&
    admittedAt.toISOString() === dviReceipt.snapshot.admittedAt &&
    expiresAt.toISOString() === dviReceipt.snapshot.expiresAt &&
    Number.isSafeInteger(residual) && residual >= MINIMUM_RECOVERY_RESIDUAL_MS,
  "FRESH_RECOVERY_SOURCE_DVI_RESIDUAL_TTL_REJECTED");
  return Object.freeze({
    admittedAt: admittedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    databaseObservedAt: databaseNow.toISOString(),
    minimumRequiredMs: MINIMUM_RECOVERY_RESIDUAL_MS,
    minimumResidualMs: residual,
    source: "COCKROACHDB_CLOCK"
  });
}

export async function produceFreshRecoverySource({
  adminConnectionString,
  clock = Date.now,
  credentialBundle,
  dependencies,
  operationId,
  sourceCommit,
  treeDigest
}) {
  requireCondition(typeof adminConnectionString === "string" &&
    adminConnectionString.length > 0 && plainObject(credentialBundle) &&
    plainObject(credentialBundle.passwords) && UUID.test(operationId ?? "") &&
    HEX_40.test(sourceCommit ?? "") && HEX_40.test(treeDigest ?? "") &&
    typeof clock === "function",
  "FRESH_RECOVERY_SOURCE_CONFIGURATION_REJECTED");
  const resolved = validateDependencies(dependencies ??
    defaultDependencies(adminConnectionString, credentialBundle));
  const identity = freshRecoverySourceIdentity(
    operationId,
    sourceCommit,
    treeDigest
  );
  const now = clock();
  requireCondition(Number.isFinite(now), "FRESH_RECOVERY_SOURCE_CLOCK_REJECTED");
  const observedAt = new Date(now - 60_000).toISOString();
  const validFrom = new Date(now - 120_000).toISOString();
  const validUntil = new Date(now + 30 * 60_000).toISOString();
  const store = resolved.createStore();
  requireCondition(store && [
    "appendSignedEvidence", "close", "prepareResource",
    "registerVerificationKey", "snapshot", "verificationSnapshot"
  ].every((name) => typeof store[name] === "function"),
  "FRESH_RECOVERY_SOURCE_STORE_REJECTED");
  try {
    const signer = resolved.createSigner();
    requireCondition(signer && typeof signer.register === "function" &&
      typeof signer.append === "function",
    "FRESH_RECOVERY_SOURCE_SIGNER_REJECTED");
    const registered = await signer.register(store, identity.tenantId);
    requireCondition(["verification_key_registered", "verification_key_replay"]
      .includes(registered?.outcome),
    "FRESH_RECOVERY_SOURCE_KEY_REJECTED");

    for (let index = 0; index < identity.candidateEvidenceIds.length; index += 1) {
      const appended = await signer.append(store, {
        tenantId: identity.tenantId,
        evidenceId: identity.candidateEvidenceIds[index],
        incidentId: identity.incidentId,
        agencyScope: "rescue",
        claimKey: "rescue_unit_status",
        claimValue: "available",
        observedAt,
        validFrom,
        validUntil,
        conflictStatus: "none",
        assertion: `Fresh recovery admitted candidate ${index + 1}.`,
        embedding: candidateEmbedding(index)
      });
      requireCondition(["evidence_verified", "evidence_verification_replay"]
        .includes(appended?.outcome),
      "FRESH_RECOVERY_SOURCE_EVIDENCE_REJECTED");
    }
    const excluded = await signer.append(store, {
      tenantId: identity.tenantId,
      evidenceId: identity.excludedEvidenceId,
      incidentId: identity.incidentId,
      agencyScope: "fire",
      claimKey: "rescue_unit_status",
      claimValue: "available",
      observedAt,
      validFrom,
      validUntil,
      conflictStatus: "none",
      assertion: "Semantically closest evidence is outside the rescue scope.",
      embedding: QUERY_EMBEDDING
    });
    requireCondition(["evidence_verified", "evidence_verification_replay"]
      .includes(excluded?.outcome),
    "FRESH_RECOVERY_SOURCE_EXCLUSION_REJECTED");

    const snapshot = await store.verificationSnapshot({
      tenantId: identity.tenantId,
      evidenceId: identity.evidenceId
    });
    requireCondition(snapshot?.verification?.outcome === "verified" &&
      HEX_64.test(snapshot?.evidence?.evidence_digest ?? ""),
    "FRESH_RECOVERY_SOURCE_EVIDENCE_READBACK_REJECTED");

    const dvi = await resolved.proveDviSelection(Object.freeze({
      tenantId: identity.tenantId,
      runId: identity.runId,
      retrievalId: identity.retrievalId,
      incidentId: identity.incidentId,
      agency: "rescue",
      queryEmbedding: QUERY_EMBEDDING,
      expectedCandidateCount: DVI_CANDIDATE_COUNT,
      expectedCandidateSetSha256:
        identifierSetDigest(identity.candidateEvidenceIds),
      exclusionCases: Object.freeze([Object.freeze({
        evidenceId: identity.excludedEvidenceId,
        reason: "out_of_scope"
      })]),
      nearestExcludedEvidenceId: identity.excludedEvidenceId,
      limit: DVI_LIMIT,
      ttlMs: DVI_TTL_MS
    }), sourceCommit, treeDigest);
    requireCondition(dvi?.receipt?.status === "PASS" &&
      dvi.receipt?.drill?.durableSelectionCommitted === true &&
      dvi.receipt?.ranking?.directDviResultValidated === true &&
      dvi.receipt?.ranking?.commitValidatorSequenceMatchedDirectDvi === true &&
      dvi.receipt?.ranking?.vectorSearchUsed === true &&
      dvi.receipt?.ranking?.exactPrefixSpansUsed === true &&
      dvi.receipt?.cleanup?.snapshotRetired === true &&
      dvi?.privateSelection?.selectedEvidenceId === identity.evidenceId &&
      HEX_64.test(dvi.privateSelection?.selectedEvidenceDigest ?? ""),
    "FRESH_RECOVERY_SOURCE_DVI_REJECTED");

    const beforeAuthorization = validatedDviResidual(
      await resolved.readDviResidual(dvi.privateSelection),
      dvi.receipt
    );

    await store.prepareResource(identity);
    const rawRequests = identity.contenders.map((contender, index) =>
      Object.freeze({
        tenantId: identity.tenantId,
        runId: identity.runId,
        incidentId: identity.incidentId,
        evidenceId: dvi.privateSelection.selectedEvidenceId,
        resourceId: identity.resourceId,
        operationId: contender.operationId,
        effectKey: contender.effectKey,
        intentNonce: contender.intentNonce,
        agentId: `prooftoact-fresh-recovery-contender-${index + 1}`,
        agency: "rescue",
        leaseMs: AUTHORITY_LEASE_MS,
        payload: Object.freeze({
          action: "dispatch_rescue_unit",
          destination: `synthetic-zone-fresh-recovery-${index + 1}`,
          scenario: `synthetic-highwater-contender-${index + 1}`
        })
      }));
    const authorized = await resolved.authorizeContenders(rawRequests.map(
      (request) => proposalInputFor(request, dvi.privateSelection)
    ));
    requireCondition(Array.isArray(authorized) &&
      authorized.length === CONTENDER_COUNT &&
      new Set(authorized.map(({ backendId }) => backendId)).size ===
        CONTENDER_COUNT &&
      authorized.every(({ authorization, backendId }) =>
        typeof backendId === "string" && backendId.length > 0 &&
        authorization?.outcome === "proposal_authorized" &&
        authorization?.authorizationCurrent === true &&
        authorization?.dviAuthorization?.dviProposal?.
          authorityEvidenceBindingSha256 ===
            dvi.privateSelection.dviProposal.authorityEvidenceBindingSha256),
    "FRESH_RECOVERY_SOURCE_CONTENDER_AUTHORIZATION_REJECTED");
    const requests = rawRequests.map((request, index) =>
      normalizedAuthorityRequestFor({
        ...request,
        dviAuthorization: authorized[index].authorization.dviAuthorization
      }));
    requireCondition(new Set(requests.map(({ operationId }) => operationId)).size ===
        CONTENDER_COUNT &&
      new Set(requests.map(({ effectKey }) => effectKey)).size === CONTENDER_COUNT &&
      new Set(requests.map(({ intentNonce }) => intentNonce)).size ===
        CONTENDER_COUNT &&
      new Set(requests.map(({ logicalActionDigest }) =>
        logicalActionDigest)).size === CONTENDER_COUNT &&
      new Set(requests.map(({ proposalDigest }) => proposalDigest)).size ===
        CONTENDER_COUNT,
    "FRESH_RECOVERY_SOURCE_CONTENDER_IDENTITY_REJECTED");

    const beforeSpend = validatedDviResidual(
      await resolved.readDviResidual(dvi.privateSelection),
      dvi.receipt
    );

    const raceSettled = await resolved.raceAuthority(requests);
    const raceSnapshot = await store.snapshot(identity);
    const race = validatedRace(raceSettled, requests, raceSnapshot);
    const winnerRequest = requests[race.winnerIndex];
    const loserRequest = requests[race.loserIndex];
    const deniedReplay = await resolved.replayAuthority(loserRequest);
    requireCondition(deniedReplay?.row?.decision_replay_kind ===
        "operation_replay" &&
      deniedReplay.row.decision_outcome === "resource_held_denied" &&
      deniedReplay.row.decision_operation_id === loserRequest.operationId,
    "FRESH_RECOVERY_SOURCE_DENIED_REPLAY_REJECTED");
    const changedRaw = {
      ...rawRequests[race.loserIndex],
      agentId: `${rawRequests[race.loserIndex].agentId}-changed`,
      dviAuthorization:
        authorized[race.loserIndex].authorization.dviAuthorization
    };
    const changedInput = await resolved.assertChangedInputDenied(
      normalizedAuthorityRequestFor(changedRaw)
    );
    requireCondition(changedInput?.denied === true &&
      changedInput.reason === "operation_digest_mismatch",
    "FRESH_RECOVERY_SOURCE_CHANGED_INPUT_REJECTED");
    const finalSnapshot = await store.snapshot(identity);
    requireCondition(finalSnapshot.receipts?.length === CONTENDER_COUNT &&
      finalSnapshot.outbox?.length === 1 && finalSnapshot.effects?.length === 0 &&
      String(finalSnapshot.resource?.current_fence) === "1" &&
      finalSnapshot.resource?.holder_operation_id === winnerRequest.operationId,
    "FRESH_RECOVERY_SOURCE_REPLAY_STATE_REJECTED");

    const sourceBinding = Object.freeze({
      authorityEvidenceBindingSha256:
        dvi.privateSelection.dviProposal.authorityEvidenceBindingSha256,
      evidenceId: dvi.privateSelection.selectedEvidenceId,
      incidentId: identity.incidentId,
      operationId: winnerRequest.operationId,
      requestDigest: winnerRequest.requestDigest,
      resourceId: identity.resourceId,
      runId: identity.runId,
      selectedEvidenceBindingSha256: sha256(canonicalJson({
        evidenceId: dvi.privateSelection.selectedEvidenceId,
        evidenceDigest: dvi.privateSelection.selectedEvidenceDigest
      })),
      tenantId: identity.tenantId
    });
    const residualAuthority = validatedResidual(
      await resolved.readRecoveryResidual(sourceBinding),
      sourceBinding
    );
    const contenderIdentitySetSha256 = sha256(`${requests
      .map(({ effectKey, intentNonce, operationId }) =>
        `${operationId}:${effectKey}:${intentNonce}`)
      .sort().join("\n")}\n`);
    const raceProof = Object.freeze({
      schemaVersion: "prooftoact.fresh-recovery-authority-race.v1",
      status: "PASS",
      contenderCount: CONTENDER_COUNT,
      contenderIdentitySetSha256,
      deterministicOuterSourceBindingSha256: sha256(canonicalJson({
        operationId,
        sourceCommit,
        treeDigest
      })),
      distinctAuthorizationSessionCount: CONTENDER_COUNT,
      distinctLogicalActionCount: CONTENDER_COUNT,
      distinctSpendSessionCount: CONTENDER_COUNT,
      durableReceiptCount: finalSnapshot.receipts.length,
      durableDenialCount: CONTENDER_COUNT - 1,
      outboxCount: finalSnapshot.outbox.length,
      protectedEffectCount: finalSnapshot.effects.length,
      winnerFence: "1",
      winnerOperationIdSha256: sha256(winnerRequest.operationId),
      winnerRequestDigest: winnerRequest.requestDigest,
      deniedReplayOutcome: deniedReplay.row.decision_outcome,
      deniedReplayKind: deniedReplay.row.decision_replay_kind,
      changedInputMismatchDenied: true,
      serializable: true,
      promiseAllSettled: true
    });
    const recoverySemantics = Object.freeze({
      outerReleaseOperationIdSha256: sha256(operationId),
      winnerAuthorityOperationIdSha256: sha256(winnerRequest.operationId),
      signedRecoveryMustBindExactWinner: true,
      crossRunRecoveryScope: "CLEANUP_ONLY",
      successfulPhaseContinuation: false,
      boundedOneShotAvailabilityRiskPresent: true,
      safetyPreservedByFreshAuthorityRequirement: true
    });
    return Object.freeze({
      schemaVersion: "prooftoact.fresh-recovery-source-receipt.v2",
      status: "PASS",
      operationId,
      sourceCommit,
      treeDigest,
      authorityOutcome: race.winner.row.decision_outcome,
      dviPolicyVersion: "g1-admissibility-v2",
      dviProof: dvi.receipt,
      dviProofSha256: sha256(`${canonicalJson(dvi.receipt)}\n`),
      dviAuthorityWindow: Object.freeze({ beforeAuthorization, beforeSpend }),
      durableAuthorityReceipt: true,
      evidenceDigest: dvi.privateSelection.selectedEvidenceDigest,
      evidenceVerified: true,
      raceProof,
      raceProofSha256: sha256(`${canonicalJson(raceProof)}\n`),
      recoverySemantics,
      residualAuthority,
      sourceBinding,
      sourceBindingSha256: sha256(`${canonicalJson(sourceBinding)}\n`)
    });
  } finally {
    await store.close().catch(() => {});
  }
}

export const __test = Object.freeze({
  AUTHORITY_LEASE_MS,
  CONTENDER_COUNT,
  DVI_CANDIDATE_COUNT,
  DVI_LIMIT,
  DVI_RESIDUAL_SQL,
  DVI_TTL_MS,
  MINIMUM_RECOVERY_RESIDUAL_MS,
  QUERY_EMBEDDING,
  RECOVERY_RESIDUAL_SQL,
  SPEND_AUTHORITY_SQL,
  canonicalJson,
  changedInputMismatchError,
  derivedUuid,
  identifierSetDigest,
  sha256,
  spendValues,
  validG1SpendRow
});
