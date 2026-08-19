import crypto from "node:crypto";
import { Pool } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import { canonicalJson } from "./canonical-json.js";
import { runtimeDatabaseConfig } from "./database-runtime.js";
import {
  committedDatabaseResult,
  databaseTimestampFromDriver
} from "./database-commit-result.js";
import {
  dviRankedSequenceSha256For,
  dviSelectionBindingSha256For
} from "./dvi-selection.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_OBJECT_ID = /^[0-9a-f]{40}$/;
const POLICY_VERSION = "g1-admissibility-v2";
const VECTOR_INDEX_NAME = "g1_vector_candidates_embedding_idx";
const PROOF_SCHEMA = "tideproof.gate1.admissible-vector-proof.v2";
const PROOF_CANDIDATE_COUNT = 10_000;
const PROOF_LIMIT = 10;
const PROOF_TTL_MS = 60_000;
const FRESH_PROOF_SCHEMA =
  "prooftoact.fresh-recovery-admissible-vector-proof.v1";
const FRESH_PROOF_CANDIDATE_COUNT = PROOF_LIMIT + 1;
const FRESH_PROOF_TTL_MS = 30 * 60_000;
const FRESH_PROOF_EXCLUSION_REASON = "out_of_scope";
const REQUIRED_EXCLUSION_REASONS = Object.freeze([
  "expired",
  "future_observation",
  "not_yet_valid",
  "out_of_scope",
  "unresolved_conflict",
  "verification_binding_mismatch",
  "verification_key_revoked"
]);

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, expected, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      JSON.stringify(Object.keys(value).sort()) ===
        JSON.stringify([...expected].sort()),
    code
  );
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function identifierSetDigest(values, code) {
  const normalized = values.map((value) => requireUuid(value, code));
  assert(new Set(normalized).size === normalized.length, `${code}_DUPLICATE`);
  return sha256(`${[...normalized].sort().join("\n")}\n`);
}

function requireText(value, name, maximum = 128) {
  if (
    typeof value !== "string" ||
    value.trim() === "" ||
    value.length > maximum
  ) {
    throw new TypeError(`${name} must be bounded non-empty text`);
  }
  return value.trim();
}

function requireUuid(value, name) {
  const text = requireText(value, name, 36).toLowerCase();
  if (!UUID.test(text)) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text;
}

function requireInteger(value, name, minimum, maximum) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new RangeError(`${name} outside policy`);
  }
  return value;
}

function requireEmbedding(value) {
  if (
    !Array.isArray(value) ||
    value.length !== 3 ||
    value.some((entry) => !Number.isFinite(entry))
  ) {
    throw new TypeError("queryEmbedding must contain three finite numbers");
  }
  return `[${value.join(",")}]`;
}

function validateProofSpec(value, boundary = "fixed") {
  exactKeys(
    value,
    [
      "agency",
      "exclusionCases",
      "expectedCandidateCount",
      "expectedCandidateSetSha256",
      "incidentId",
      "limit",
      "nearestExcludedEvidenceId",
      "queryEmbedding",
      "retrievalId",
      "runId",
      "tenantId",
      "ttlMs"
    ],
    "ADMISSIBLE_VECTOR_PROOF_SPEC_SHAPE"
  );
  const tenantId = requireUuid(value.tenantId, "tenantId");
  const runId = requireUuid(value.runId, "runId");
  const retrievalId = requireUuid(value.retrievalId, "retrievalId");
  const incidentId = requireUuid(value.incidentId, "incidentId");
  const agency = requireText(value.agency, "agency");
  const vector = requireEmbedding(value.queryEmbedding);
  const fresh = boundary === "fresh";
  assert(
    ["fixed", "fresh"].includes(boundary) &&
      value.expectedCandidateCount === (fresh
        ? FRESH_PROOF_CANDIDATE_COUNT
        : PROOF_CANDIDATE_COUNT) &&
      value.limit === PROOF_LIMIT &&
      value.ttlMs === (fresh ? FRESH_PROOF_TTL_MS : PROOF_TTL_MS) &&
      SHA256.test(value.expectedCandidateSetSha256),
    "ADMISSIBLE_VECTOR_PROOF_SPEC_BOUNDARY"
  );
  assert(
    Array.isArray(value.exclusionCases) &&
      value.exclusionCases.length === (fresh
        ? 1
        : REQUIRED_EXCLUSION_REASONS.length),
    "ADMISSIBLE_VECTOR_PROOF_EXCLUSIONS"
  );
  const exclusionCases = value.exclusionCases.map((entry) => {
    exactKeys(
      entry,
      ["evidenceId", "reason"],
      "ADMISSIBLE_VECTOR_PROOF_EXCLUSION_SHAPE"
    );
    return {
      evidenceId: requireUuid(entry.evidenceId, "evidenceId"),
      reason: requireText(entry.reason, "reason")
    };
  });
  assert(
    new Set(exclusionCases.map(({ evidenceId }) => evidenceId)).size ===
      exclusionCases.length &&
      JSON.stringify(
        [...exclusionCases.map(({ reason }) => reason)].sort()
      ) === JSON.stringify(fresh
        ? [FRESH_PROOF_EXCLUSION_REASON]
        : REQUIRED_EXCLUSION_REASONS),
    "ADMISSIBLE_VECTOR_PROOF_EXCLUSIONS"
  );
  const nearestExcludedEvidenceId = requireUuid(
    value.nearestExcludedEvidenceId,
    "nearestExcludedEvidenceId"
  );
  assert(
    exclusionCases.some(
      ({ evidenceId }) => evidenceId === nearestExcludedEvidenceId
    ),
    "ADMISSIBLE_VECTOR_PROOF_NEAREST_EXCLUSION"
  );
  return {
    tenantId,
    runId,
    retrievalId,
    incidentId,
    agency,
    queryEmbedding: [...value.queryEmbedding],
    vector,
    expectedCandidateCount: fresh
      ? FRESH_PROOF_CANDIDATE_COUNT
      : PROOF_CANDIDATE_COUNT,
    expectedCandidateSetSha256: value.expectedCandidateSetSha256,
    exclusionCases: [...exclusionCases].sort((left, right) =>
      left.reason.localeCompare(right.reason)
    ),
    nearestExcludedEvidenceId,
    limit: PROOF_LIMIT,
    ttlMs: fresh ? FRESH_PROOF_TTL_MS : PROOF_TTL_MS
  };
}

function authorityEvidenceBindingDigest({
  accepted,
  preparedTiming,
  queryEmbeddingSha256,
  rankedSequenceSha256,
  selected,
  sourceCommit,
  specSha256,
  treeDigest
}) {
  return dviSelectionBindingSha256For({
    sourceCommit,
    treeDigest,
    specSha256,
    runId: accepted.runId,
    tenantId: accepted.tenantId,
    incidentId: accepted.incidentId,
    retrievalId: accepted.retrievalId,
    agency: accepted.agency,
    policyVersion: POLICY_VERSION,
    admittedAt: preparedTiming.admittedAt,
    expiresAt: preparedTiming.expiresAt,
    rankedSequenceSha256,
    queryEmbeddingSha256,
    resultLimit: accepted.limit,
    selectedRank: 1,
    selectedEvidenceId: selected.evidenceId,
    selectedEvidenceDigest: selected.evidenceDigest
  });
}

function integerFromRow(value, name, maximum = Number.MAX_SAFE_INTEGER) {
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    (typeof value === "string" && !/^(?:0|[1-9][0-9]*)$/.test(value))
  ) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  return parsed;
}

function distanceFromRow(value, name = "distance") {
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    (typeof value === "string" &&
      (value === "" || value.trim() !== value))
  ) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 2) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  return parsed;
}

function timestampFromRow(value, name) {
  if (typeof value !== "string" && !(value instanceof Date)) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  return parsed;
}

function rankedResult(row) {
  const distance = distanceFromRow(row?.distance, "result");
  if (
    !UUID.test(row?.evidence_id ?? "") ||
    !SHA256.test(row?.evidence_digest ?? "") ||
    typeof row?.assertion !== "string" ||
    Buffer.byteLength(row.assertion, "utf8") < 1 ||
    Buffer.byteLength(row.assertion, "utf8") > 4096
  ) {
    throw new Error("ADMISSIBLE_VECTOR_RESULT_INVALID");
  }
  return {
    evidenceId: row.evidence_id,
    evidenceDigest: row.evidence_digest,
    assertion: row.assertion,
    distance
  };
}

function validatedRankedResults(rows) {
  const results = rows.map(rankedResult);
  const seen = new Set();
  for (let index = 0; index < results.length; index += 1) {
    const result = results[index];
    if (seen.has(result.evidenceId)) {
      throw new Error("ADMISSIBLE_VECTOR_RESULT_DUPLICATE");
    }
    seen.add(result.evidenceId);
    if (
      index > 0 &&
      result.distance < results[index - 1].distance
    ) {
      throw new Error("ADMISSIBLE_VECTOR_RESULT_ORDER_INVALID");
    }
  }
  return results;
}

function preparedSnapshot(row, retrievalId, ttlMs) {
  if (row?.retrieval_id !== retrievalId) {
    throw new Error("ADMISSIBLE_VECTOR_PREPARE_BINDING_INVALID");
  }
  const admittedAtMs = timestampFromRow(row.admitted_at, "admitted_at");
  const expiresAtMs = timestampFromRow(row.expires_at, "expires_at");
  if (
    !Number.isFinite(admittedAtMs) ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= admittedAtMs ||
    expiresAtMs - admittedAtMs !== ttlMs
  ) {
    throw new Error("ADMISSIBLE_VECTOR_PREPARE_TIME_INVALID");
  }
  return {
    admittedAt: new Date(admittedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString()
  };
}

function preparationDigestFor({
  tenantId,
  retrievalId,
  incidentId,
  agency,
  ttlMs
}) {
  return sha256(canonicalJson({
    agency,
    incidentId,
    policyVersion: POLICY_VERSION,
    retrievalId,
    schemaVersion: "tideproof.dvi.preparation-request.v1",
    tenantId,
    ttlMs
  }));
}

function preparationCommitFor(row, input, observation) {
  const snapshot = preparedSnapshot(row, input.retrievalId, input.ttlMs);
  return committedDatabaseResult({
    operation: "dvi_preparation",
    operationDigest: preparationDigestFor(input),
    observation,
    databaseNow:
      observation === "direct_ack"
        ? snapshot.admittedAt
        : databaseTimestampFromDriver(row.database_now),
    outcome: "dvi_snapshot_prepared",
    authorityCurrent: null,
    requiresFreshAuthorization: true
  });
}

async function resolveVectorPreparation(client, input) {
  return client.query(
    `
      SELECT *
      FROM tp_api.g1_resolve_vector_set_v1(
        $1::UUID, $2::UUID, $3::UUID, $4, $5, $6::INT8
      )
    `,
    [
      input.tenantId,
      input.retrievalId,
      input.incidentId,
      input.agency,
      POLICY_VERSION,
      input.ttlMs
    ]
  );
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original database failure remains authoritative.
  }
}

function preparationCommitUnknown(cause) {
  const error = new Error(
    "ADMISSIBLE_VECTOR_PREPARE_COMMIT_UNKNOWN",
    { cause }
  );
  error.code = "ADMISSIBLE_VECTOR_PREPARE_COMMIT_UNKNOWN";
  error.commitOutcomeUnknown = true;
  return error;
}

async function executeVectorPreparation(client, input) {
  let commitDispatched = false;
  try {
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    const prepared = await client.query(
      `
        SELECT *
        FROM tp_api.g1_prepare_vector_set_v1(
          $1::UUID, $2::UUID, $3::UUID, $4, $5, $6::INT8
        )
      `,
      [
        input.tenantId,
        input.retrievalId,
        input.incidentId,
        input.agency,
        POLICY_VERSION,
        input.ttlMs
      ]
    );
    commitDispatched = true;
    await client.query("COMMIT");
    return prepared;
  } catch (error) {
    if (!commitDispatched) {
      await rollbackQuietly(client);
      throw error;
    }
    throw preparationCommitUnknown(error);
  }
}

export function admissibleVectorPoolConfig(
  connectionString,
  environment = process.env
) {
  return runtimeDatabaseConfig({
    connectionString: connectionStringForDatabase(
      connectionString,
      "tideproof"
    ),
    max: 4,
    idleTimeoutMillis: 5_000,
    applicationName: "tideproof-admissible-vector",
    environment
  });
}

export function admissibleVectorAuditorPoolConfig(
  connectionString,
  environment = process.env
) {
  return runtimeDatabaseConfig({
    connectionString: connectionStringForDatabase(
      connectionString,
      "tideproof"
    ),
    max: 1,
    idleTimeoutMillis: 5_000,
    applicationName: "tideproof-vector-auditor",
    environment
  });
}

async function databaseIdentity(client, expectedAuthorizer) {
  const result = await client.query(`
    SELECT
      current_database() AS database_name,
      current_user AS current_user_name,
      session_user AS session_user_name,
      crdb_internal.cluster_id()::STRING AS cluster_id,
      version() AS database_version
  `);
  assert(
    result.rowCount === 1 &&
      result.rows[0]?.database_name === "tideproof" &&
      typeof result.rows[0]?.current_user_name === "string" &&
      typeof result.rows[0]?.session_user_name === "string" &&
      UUID.test(result.rows[0]?.cluster_id ?? "") &&
      typeof result.rows[0]?.database_version === "string" &&
      result.rows[0].database_version.includes("CockroachDB"),
    "ADMISSIBLE_VECTOR_DATABASE_IDENTITY_INVALID"
  );
  const row = result.rows[0];
  if (expectedAuthorizer) {
    assert(
      row.current_user_name === "tp_authorizer_user" &&
        row.session_user_name === "tp_authorizer_user",
      "ADMISSIBLE_VECTOR_AUTHORIZER_IDENTITY_INVALID"
    );
  } else {
    assert(
      row.current_user_name === row.session_user_name &&
        ![
          "tp_authorizer_user",
          "tp_gate2_authorizer_user",
          "tp_recovery_reader_user"
        ].includes(row.session_user_name),
      "ADMISSIBLE_VECTOR_AUDITOR_IDENTITY_INVALID"
    );
  }
  return {
    databaseName: row.database_name,
    clusterId: row.cluster_id.toLowerCase(),
    databaseVersionSha256: sha256(row.database_version),
    sessionSha256: sha256(
      `${row.database_name}\0${row.current_user_name}\0${row.session_user_name}`
    )
  };
}

function explainText(result) {
  assert(
    result && Array.isArray(result.rows) && result.rows.length > 0,
    "ADMISSIBLE_VECTOR_PLAN_EMPTY"
  );
  const plan = result.rows
    .map((row) => Object.values(row).join(" "))
    .join("\n");
  assert(
    Buffer.byteLength(plan, "utf8") > 0 &&
      Buffer.byteLength(plan, "utf8") <= 1024 * 1024,
    "ADMISSIBLE_VECTOR_PLAN_SIZE_INVALID"
  );
  return plan;
}

function forcedIndexRankSql({ explain = false } = {}) {
  return `
    ${explain ? "EXPLAIN (VERBOSE)" : ""}
    WITH ann AS MATERIALIZED (
      SELECT
        evidence_id,
        evidence_digest,
        assertion,
        embedding <=> $3::VECTOR(3) AS distance
      FROM tp_private.g1_vector_candidates@{
        FORCE_INDEX=${VECTOR_INDEX_NAME}
      }
      WHERE tenant_id = $1::UUID
        AND retrieval_id = $2::UUID
      ORDER BY embedding <=> $3::VECTOR(3)
      LIMIT 10
    )
    SELECT evidence_id, evidence_digest, assertion, distance
    FROM ann
    ORDER BY distance, evidence_id
  `;
}

function naturalRankSql({ explain = false } = {}) {
  return `
    ${explain ? "EXPLAIN (VERBOSE)" : ""}
    SELECT
      evidence_id,
      evidence_digest,
      assertion,
      embedding <=> $3::VECTOR(3) AS distance
    FROM tp_private.g1_vector_candidates
    WHERE tenant_id = $1::UUID
      AND retrieval_id = $2::UUID
    ORDER BY embedding <=> $3::VECTOR(3), evidence_id
    LIMIT $4::INT8
  `;
}

function proofPlan(plan, spec, mode = "fixed") {
  const normalized = plan.toLowerCase();
  if (mode === "fixed") {
    assert(
      normalized.includes("vector search") &&
        normalized.includes(VECTOR_INDEX_NAME) &&
        normalized.includes("prefix spans") &&
        normalized.includes(spec.tenantId) &&
        normalized.includes(spec.retrievalId),
      "ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING"
    );
    return {
      indexName: VECTOR_INDEX_NAME,
      planSha256: sha256(plan),
      vectorSearchUsed: true,
      exactPrefixSpansUsed: true
    };
  }
  assert(mode === "fresh", "ADMISSIBLE_VECTOR_PLAN_MODE_INVALID");
  const lines = normalized.split(/\r?\n/u).map((line) => line.trim());
  const vectorSearch = lines.some((line) => line.includes("vector search"));
  const indexedTable = lines.some((line) =>
    line.includes("table:") &&
      line.includes(`@${VECTOR_INDEX_NAME}`)
  );
  const prefixIndex = lines.findIndex((line) => line.includes("prefix spans"));
  const prefixSpan = prefixIndex < 0
    ? ""
    : lines.slice(prefixIndex, prefixIndex + 3).join(" ");
  assert(
    vectorSearch && indexedTable && prefixIndex >= 0 &&
      prefixSpan.includes(spec.tenantId.toLowerCase()) &&
      prefixSpan.includes(spec.retrievalId.toLowerCase()),
    "ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING"
  );
  return {
    indexName: VECTOR_INDEX_NAME,
    planSha256: sha256(plan),
    vectorSearchUsed: true,
    exactPrefixSpansUsed: true
  };
}

async function proveAdmissibleVectorSnapshotWithBoundary({
  authorizerPool,
  auditorPool,
  spec,
  sourceCommit,
  treeDigest
} = {}, proofBoundary) {
  assert(
    authorizerPool && typeof authorizerPool.connect === "function",
    "ADMISSIBLE_VECTOR_AUTHORIZER_POOL_REQUIRED"
  );
  assert(
    auditorPool && typeof auditorPool.connect === "function",
    "ADMISSIBLE_VECTOR_AUDITOR_POOL_REQUIRED"
  );
  assert(
    GIT_OBJECT_ID.test(sourceCommit) && GIT_OBJECT_ID.test(treeDigest),
    "ADMISSIBLE_VECTOR_SOURCE_BINDING_INVALID"
  );
  assert(
    proofBoundary &&
      ["fixed", "fresh"].includes(proofBoundary.mode) &&
      Number.isSafeInteger(proofBoundary.candidateMaximum) &&
      proofBoundary.candidateMaximum >= PROOF_LIMIT + 1 &&
      typeof proofBoundary.claimBoundary === "string" &&
      typeof proofBoundary.schema === "string",
    "ADMISSIBLE_VECTOR_PROOF_BOUNDARY_INVALID"
  );
  const accepted = validateProofSpec(spec, proofBoundary.mode);
  const { vector: _vector, ...canonicalSpec } = accepted;
  const specSha256 = sha256(canonicalJson(canonicalSpec));
  let authorizer;
  let auditor;
  let prepared = false;
  let preparedCandidateCount = null;
  let preparedTiming = null;
  let primaryError = null;
  let cleanupError = null;
  let receipt;
  let privateSelection;
  try {
    authorizer = await authorizerPool.connect();
    auditor = await auditorPool.connect();
    const authorizerIdentity = await databaseIdentity(authorizer, true);
    const auditorIdentity = await databaseIdentity(auditor, false);
    assert(
      authorizerIdentity.clusterId === auditorIdentity.clusterId &&
        authorizerIdentity.databaseVersionSha256 ===
          auditorIdentity.databaseVersionSha256 &&
        authorizerIdentity.sessionSha256 !== auditorIdentity.sessionSha256,
      "ADMISSIBLE_VECTOR_DATABASE_IDENTITY_MISMATCH"
    );

    const preparationInput = {
      tenantId: accepted.tenantId,
      retrievalId: accepted.retrievalId,
      incidentId: accepted.incidentId,
      agency: accepted.agency,
      ttlMs: accepted.ttlMs
    };
    let preparationObservation = "direct_ack";
    let preparedResult;
    try {
      preparedResult = await executeVectorPreparation(
        authorizer,
        preparationInput
      );
    } catch (error) {
      if (error.commitOutcomeUnknown !== true) {
        throw error;
      }
      authorizer.release(error.cause ?? error);
      authorizer = await authorizerPool.connect();
      const replacementIdentity = await databaseIdentity(authorizer, true);
      assert(
        replacementIdentity.clusterId === authorizerIdentity.clusterId &&
          replacementIdentity.databaseVersionSha256 ===
            authorizerIdentity.databaseVersionSha256 &&
          replacementIdentity.sessionSha256 ===
            authorizerIdentity.sessionSha256,
        "ADMISSIBLE_VECTOR_RECONCILIATION_IDENTITY_MISMATCH"
      );
      preparedResult = await resolveVectorPreparation(
        authorizer,
        preparationInput
      );
      if (preparedResult.rowCount !== 1) {
        throw error;
      }
      preparationObservation = "read_reconciled";
    }
    assert(
      preparedResult.rowCount === 1,
      "ADMISSIBLE_VECTOR_PREPARE_INVALID"
    );
    preparedCandidateCount = integerFromRow(
      preparedResult.rows[0]?.candidate_count,
      "candidate_count",
      proofBoundary.candidateMaximum
    );
    assert(
      preparedCandidateCount === accepted.expectedCandidateCount,
      "ADMISSIBLE_VECTOR_PROOF_CANDIDATE_COUNT"
    );
    preparedTiming = preparedSnapshot(
      preparedResult.rows[0],
      accepted.retrievalId,
      accepted.ttlMs
    );
    prepared = true;

    const candidateResult = await auditor.query(
      `
        SELECT evidence_id::STRING AS evidence_id
        FROM tp_private.g1_vector_candidates
        WHERE tenant_id = $1::UUID
          AND retrieval_id = $2::UUID
        ORDER BY evidence_id
      `,
      [accepted.tenantId, accepted.retrievalId]
    );
    assert(
      candidateResult.rowCount === accepted.expectedCandidateCount &&
        Array.isArray(candidateResult.rows) &&
        candidateResult.rows.length === accepted.expectedCandidateCount,
      "ADMISSIBLE_VECTOR_PROOF_CANDIDATE_ROWS"
    );
    const candidateIds = candidateResult.rows.map(({ evidence_id }) =>
      requireUuid(evidence_id, "candidateEvidenceId")
    );
    const candidateSetSha256 = identifierSetDigest(
      candidateIds,
      "candidateEvidenceId"
    );
    assert(
      candidateSetSha256 === accepted.expectedCandidateSetSha256,
      "ADMISSIBLE_VECTOR_PROOF_CANDIDATE_DIGEST"
    );
    const candidateSet = new Set(candidateIds);
    assert(
      accepted.exclusionCases.every(
        ({ evidenceId }) => !candidateSet.has(evidenceId)
      ),
      "ADMISSIBLE_VECTOR_PROOF_EXCLUDED_CANDIDATE_PRESENT"
    );
    if (proofBoundary.mode === "fresh") {
      const exclusionCount = await auditor.query(
        `
          SELECT count(*)::INT8 AS exclusion_count
          FROM tp_private.g1_vector_exclusions
          WHERE tenant_id = $1::UUID
            AND retrieval_id = $2::UUID
        `,
        [accepted.tenantId, accepted.retrievalId]
      );
      assert(
        exclusionCount.rowCount === 1 &&
          integerFromRow(
            exclusionCount.rows[0]?.exclusion_count,
            "exclusion_count",
            10_000
          ) === accepted.exclusionCases.length,
        "ADMISSIBLE_VECTOR_PROOF_EXCLUSION_COUNT"
      );
    }

    const exclusionReasons = {};
    const exclusionObservations = [];
    for (const exclusion of accepted.exclusionCases) {
      const observed = await authorizer.query(
        `
          SELECT *
          FROM tp_api.g1_observe_vector_exclusion_v1(
            $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5, $6
          )
        `,
        [
          accepted.tenantId,
          accepted.retrievalId,
          exclusion.evidenceId,
          accepted.incidentId,
          accepted.agency,
          POLICY_VERSION
        ]
      );
      const snapshotAdmittedAt = new Date(
        timestampFromRow(
          observed.rows[0]?.snapshot_admitted_at,
          "snapshot_admitted_at"
        )
      ).toISOString();
      assert(
        observed.rowCount === 1 &&
          observed.rows[0]?.admissibility === exclusion.reason &&
          typeof observed.rows[0]?.evidence_digest === "string" &&
          SHA256.test(observed.rows[0].evidence_digest) &&
          snapshotAdmittedAt === preparedTiming.admittedAt,
        "ADMISSIBLE_VECTOR_PROOF_EXCLUSION_REASON"
      );
      exclusionReasons[exclusion.reason] =
        (exclusionReasons[exclusion.reason] ?? 0) + 1;
      exclusionObservations.push({
        evidenceId: exclusion.evidenceId,
        evidenceDigest: observed.rows[0].evidence_digest,
        reason: exclusion.reason,
        snapshotAdmittedAt
      });
    }
    const requiredExclusionObservationsSha256 = sha256(canonicalJson(
      exclusionObservations.sort((left, right) =>
        left.evidenceId < right.evidenceId
          ? -1
          : left.evidenceId > right.evidenceId
            ? 1
            : 0
      )
    ));

    const rankValues = [
      accepted.tenantId,
      accepted.retrievalId,
      accepted.vector,
      accepted.limit
    ];
    const directDviValues = rankValues.slice(0, 3);
    const planResult = await auditor.query(
      (proofBoundary.mode === "fresh"
        ? forcedIndexRankSql({ explain: true })
        : naturalRankSql({ explain: true })),
      proofBoundary.mode === "fresh" ? directDviValues : rankValues
    );
    const plan = proofPlan(
      explainText(planResult),
      accepted,
      proofBoundary.mode
    );

    const rankedResult = proofBoundary.mode === "fresh"
      ? await auditor.query(forcedIndexRankSql(), directDviValues)
      : await authorizer.query(
        `
          SELECT *
          FROM tp_api.g1_rank_vector_set_v1(
            $1::UUID, $2::UUID, $3::UUID, $4, $5, $6, $7::INT8
          )
        `,
        [
          accepted.tenantId,
          accepted.retrievalId,
          accepted.incidentId,
          accepted.agency,
          POLICY_VERSION,
          accepted.vector,
          accepted.limit
        ]
      );
    assert(
      rankedResult.rowCount === accepted.limit &&
        Array.isArray(rankedResult.rows) &&
        rankedResult.rows.length === accepted.limit,
      "ADMISSIBLE_VECTOR_PROOF_RANKED_COUNT"
    );
    const ranked = validatedRankedResults(rankedResult.rows);
    if (proofBoundary.mode === "fresh") {
      assert(new Set(ranked.map(({ distance }) => distance)).size ===
        ranked.length, "ADMISSIBLE_VECTOR_PROOF_DISTANCE_TIE");
    }
    assert(
      ranked.every(({ evidenceId }) => candidateSet.has(evidenceId)),
      "ADMISSIBLE_VECTOR_PROOF_RANKED_OUTSIDE_SNAPSHOT"
    );
    if (proofBoundary.mode === "fixed") {
      const auditorRankedResult = await auditor.query(
        naturalRankSql(), rankValues
      );
      assert(
        auditorRankedResult.rowCount === accepted.limit &&
          Array.isArray(auditorRankedResult.rows) &&
          auditorRankedResult.rows.length === accepted.limit,
        "ADMISSIBLE_VECTOR_PROOF_AUDITOR_RANKED_COUNT"
      );
      const auditorRanked = validatedRankedResults(auditorRankedResult.rows);
      assert(
        canonicalJson(auditorRanked) === canonicalJson(ranked),
        "ADMISSIBLE_VECTOR_PROOF_RANKED_RESULT_MISMATCH"
      );
    }

    const nearestExcluded = await auditor.query(
      `
        SELECT
          evidence_id::STRING AS evidence_id,
          embedding <=> $4::VECTOR(3) AS distance
        FROM tp_private.g1_evidence
        WHERE tenant_id = $1::UUID
          AND evidence_id = $2::UUID
          AND incident_id = $3::UUID
      `,
      [
        accepted.tenantId,
        accepted.nearestExcludedEvidenceId,
        accepted.incidentId,
        accepted.vector
      ]
    );
    assert(
      nearestExcluded.rowCount === 1 &&
        Array.isArray(nearestExcluded.rows) &&
        nearestExcluded.rows.length === 1 &&
        nearestExcluded.rows[0]?.evidence_id ===
          accepted.nearestExcludedEvidenceId,
      "ADMISSIBLE_VECTOR_PROOF_NEAREST_EXCLUSION_MISSING"
    );
    const excludedDistance = distanceFromRow(
      nearestExcluded.rows[0].distance,
      "excluded_distance"
    );
    assert(
      excludedDistance < ranked[0].distance,
      "ADMISSIBLE_VECTOR_PROOF_NEAREST_EXCLUSION_NOT_CLOSER"
    );

    const rankedSetSha256 = identifierSetDigest(
      ranked.map(({ evidenceId }) => evidenceId),
      "rankedEvidenceId"
    );
    const rankedSequenceSha256 = dviRankedSequenceSha256For(
      ranked.map(({ evidenceId, evidenceDigest }) => ({
        evidenceId,
        evidenceDigest
      }))
    );
    const queryEmbeddingSha256 = sha256(accepted.vector);
    const authorityEvidenceBindingSha256 =
      authorityEvidenceBindingDigest({
        accepted,
        preparedTiming,
        queryEmbeddingSha256,
        rankedSequenceSha256,
        selected: ranked[0],
        sourceCommit,
        specSha256,
        treeDigest
      });
    const selectedEvidenceBindingSha256 = sha256(canonicalJson({
      evidenceId: ranked[0].evidenceId,
      evidenceDigest: ranked[0].evidenceDigest
    }));
    const committedSelection = await authorizer.query(
      `
        SELECT *
        FROM tp_api.g1_commit_dvi_selection_v1(
          $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5, $6, $7, $8,
          $9, $10, $11::INT8, $12
        )
      `,
      [
        accepted.tenantId,
        accepted.retrievalId,
        accepted.runId,
        accepted.incidentId,
        accepted.agency,
        POLICY_VERSION,
        sourceCommit,
        treeDigest,
        specSha256,
        accepted.vector,
        accepted.limit,
        authorityEvidenceBindingSha256
      ]
    );
    assert(
      committedSelection.rowCount === 1 &&
        committedSelection.rows[0]?.authority_evidence_binding_sha256 ===
          authorityEvidenceBindingSha256 &&
        committedSelection.rows[0]?.ranked_sequence_sha256 ===
          rankedSequenceSha256 &&
        committedSelection.rows[0]?.query_embedding_sha256 ===
          queryEmbeddingSha256 &&
        integerFromRow(
          committedSelection.rows[0]?.result_limit,
          "result_limit",
          100
        ) === accepted.limit &&
        committedSelection.rows[0]?.selected_evidence_id ===
          ranked[0].evidenceId &&
        committedSelection.rows[0]?.selected_evidence_digest ===
          ranked[0].evidenceDigest &&
        new Date(committedSelection.rows[0]?.admitted_at).toISOString() ===
          preparedTiming.admittedAt &&
        new Date(committedSelection.rows[0]?.expires_at).toISOString() ===
          preparedTiming.expiresAt,
      "ADMISSIBLE_VECTOR_SELECTION_COMMIT_INVALID"
    );
    privateSelection = Object.freeze({
      dviProposal: Object.freeze({
        tenantId: accepted.tenantId,
        runId: accepted.runId,
        incidentId: accepted.incidentId,
        retrievalId: accepted.retrievalId,
        authorityEvidenceBindingSha256,
        selectedEvidenceId: ranked[0].evidenceId,
        selectedEvidenceDigest: ranked[0].evidenceDigest,
        policyVersion: POLICY_VERSION,
        selectedRank: 1,
        admittedAt: preparedTiming.admittedAt,
        expiresAt: preparedTiming.expiresAt
      }),
      selectedEvidenceId: ranked[0].evidenceId,
      selectedEvidenceDigest: ranked[0].evidenceDigest,
      ranked: Object.freeze(ranked.map((item) => Object.freeze({ ...item })))
    });

    receipt = {
      schemaVersion: proofBoundary.schema,
      status: "PASS",
      sourceCommit,
      treeDigest,
      drill: {
        runId: accepted.runId,
        selectedRank: 1,
        queryEmbeddingSha256,
        resultLimit: accepted.limit,
        authorityEvidenceBindingSha256,
        selectedEvidenceBindingSha256,
        durableSelectionCommitted: true
      },
      database: {
        name: authorizerIdentity.databaseName,
        clusterIdSha256: sha256(authorizerIdentity.clusterId),
        versionSha256: authorizerIdentity.databaseVersionSha256,
        authorizerSessionSha256: authorizerIdentity.sessionSha256,
        auditorSessionSha256: auditorIdentity.sessionSha256
      },
      fixture: {
        specSha256,
        candidateCount: accepted.expectedCandidateCount,
        candidateSetSha256,
        exclusionCaseCount: accepted.exclusionCases.length,
        exclusionReasons,
        requiredExclusionObservationsSha256,
        requiredExclusionsBoundToSnapshot: true,
        nearestExcludedCloserThanRanked: true
      },
      snapshot: {
        ...preparedTiming,
        ttlMs: accepted.ttlMs,
        commit: preparationCommitFor(
          preparedResult.rows[0],
          preparationInput,
          preparationObservation
        )
      },
      ranking: {
        ...plan,
        ...(proofBoundary.mode === "fresh"
          ? {
              directDviQueryForcedIndex: true,
              directDviResultValidated: true,
              commitValidatorSequenceMatchedDirectDvi: true
            }
          : { auditorRankMatchesAuthorizer: true }),
        rankedCount: ranked.length,
        rankedSetSha256,
        rankedSequenceSha256,
        approximateNearestNeighbor: true,
        authorizationRecheckRequired: true
      },
      cleanup: null,
      claimBoundary: proofBoundary.claimBoundary
    };
  } catch (error) {
    primaryError = error;
  } finally {
    if (prepared) {
      try {
        const cleaned = await authorizer.query(
          `
            SELECT *
            FROM tp_api.g1_delete_vector_set_v1($1::UUID, $2::UUID)
          `,
          [accepted.tenantId, accepted.retrievalId]
        );
        const deletedCandidateCount = integerFromRow(
          cleaned.rows[0]?.deleted_candidates,
          "deleted_candidates",
          proofBoundary.candidateMaximum
        );
        const retiredSetCount = integerFromRow(
          cleaned.rows[0]?.retired_sets,
          "retired_sets",
          1
        );
        assert(
          cleaned.rowCount === 1 &&
            (prepared
              ? retiredSetCount === 1 &&
                (preparedCandidateCount === null ||
                  deletedCandidateCount === preparedCandidateCount)
              : (retiredSetCount === 0 && deletedCandidateCount === 0) ||
                retiredSetCount === 1),
          "ADMISSIBLE_VECTOR_PROOF_CLEANUP_INVALID"
        );
        let cleanedAt = null;
        if (retiredSetCount === 1) {
          const retired = await auditor.query(
            `
              SELECT
                retrieval.candidate_count,
                retrieval.cleaned_at,
                (
                  SELECT count(*)::INT8
                  FROM tp_private.g1_vector_candidates AS candidate
                  WHERE candidate.tenant_id = retrieval.tenant_id
                    AND candidate.retrieval_id = retrieval.retrieval_id
                ) AS remaining_candidates
                ,(
                  SELECT count(*)::INT8
                  FROM tp_private.g1_vector_exclusions AS exclusion
                  WHERE exclusion.tenant_id = retrieval.tenant_id
                    AND exclusion.retrieval_id = retrieval.retrieval_id
                ) AS remaining_exclusions
              FROM tp_private.g1_vector_retrieval_sets AS retrieval
              WHERE retrieval.tenant_id = $1::UUID
                AND retrieval.retrieval_id = $2::UUID
            `,
            [accepted.tenantId, accepted.retrievalId]
          );
          const cleanedAtMs = timestampFromRow(
            retired.rows[0]?.cleaned_at,
            "cleaned_at"
          );
          assert(
            retired.rowCount === 1 &&
              integerFromRow(
                retired.rows[0]?.candidate_count,
                "candidate_count",
                proofBoundary.candidateMaximum
              ) === deletedCandidateCount &&
              (!preparedTiming ||
                cleanedAtMs >= Date.parse(preparedTiming.admittedAt)) &&
              integerFromRow(
                retired.rows[0]?.remaining_candidates,
                "remaining_candidates",
                proofBoundary.candidateMaximum
              ) === 0 &&
              integerFromRow(
                retired.rows[0]?.remaining_exclusions,
                "remaining_exclusions",
                10_000
              ) === 0,
            "ADMISSIBLE_VECTOR_PROOF_RETIREMENT_INVALID"
          );
          cleanedAt = new Date(cleanedAtMs).toISOString();
        }
        if (receipt) {
          receipt.cleanup = {
            deletedCandidateCount,
            retiredSetCount,
            remainingCandidateCount: 0,
            remainingExclusionCount: 0,
            snapshotRetired: true,
            cleanedAt
          };
        }
      } catch (error) {
        cleanupError = error;
      }
    }
    authorizer?.release(primaryError ?? cleanupError ?? undefined);
    auditor?.release(primaryError ?? cleanupError ?? undefined);
  }
  if (primaryError && cleanupError) {
    throw new AggregateError(
      [primaryError, cleanupError],
      "ADMISSIBLE_VECTOR_OPERATION_AND_CLEANUP_FAILED"
    );
  }
  if (primaryError) {
    throw primaryError;
  }
  if (cleanupError) {
    throw cleanupError;
  }
  assert(receipt?.cleanup?.snapshotRetired, "ADMISSIBLE_VECTOR_PROOF_INCOMPLETE");
  return proofBoundary.mode === "fresh"
    ? Object.freeze({
        receipt: Object.freeze(receipt),
        privateSelection
      })
    : receipt;
}

const FIXED_PROOF_BOUNDARY = Object.freeze({
  candidateMaximum: PROOF_CANDIDATE_COUNT,
  claimBoundary:
    "This sanitized provider-backed receipt records one exact clean-source integrated admissibility-snapshot run, its synthetic drill identity, non-reversible bindings from the top-ranked admissible evidence to the exact source, spec, snapshot, ranked sequence, and selected evidence, the persisted snapshot-bound adversarial exclusions, the named DVI with exact tenant/retrieval prefix spans, ranked-set containment, and snapshot retirement. It requires independent acceptance review and does not prove that AWS consumed the binding, authorization, the +1 integrated live drill, production suitability, or final release readiness.",
  mode: "fixed",
  schema: PROOF_SCHEMA
});

const FRESH_PROOF_BOUNDARY = Object.freeze({
  candidateMaximum: FRESH_PROOF_CANDIDATE_COUNT,
  claimBoundary:
    "This sanitized receipt proves one bounded fresh-recovery DVI snapshot with limit-plus-one admitted contenders, one semantically closer excluded row, one forced direct DVI query through the private admin auditor session, an independently recomputed unhinted commit-validator sequence, a durable selection, and complete snapshot retirement. Non-selected candidate and ranked-set identities remain private; the selected synthetic identity is carried only in the private source binding. It does not prove provider-key revocation, successful cross-run phase continuation, public availability, or final release acceptance.",
  mode: "fresh",
  schema: FRESH_PROOF_SCHEMA
});

export function proveAdmissibleVectorSnapshot(input) {
  return proveAdmissibleVectorSnapshotWithBoundary(input, FIXED_PROOF_BOUNDARY);
}

export function proveFreshAdmissibleVectorSnapshot(input) {
  return proveAdmissibleVectorSnapshotWithBoundary(input, FRESH_PROOF_BOUNDARY);
}

export class AdmissibleVectorRetriever {
  #ownsPool;
  #pool;
  #reconcilePreparation;

  constructor({ connectionString, pool, reconcilePreparation = null } = {}) {
    if (pool) {
      if (typeof pool.connect !== "function") {
        throw new TypeError("pool must expose connect()");
      }
      this.#pool = pool;
      this.#ownsPool = false;
      this.#reconcilePreparation = reconcilePreparation;
      return;
    }
    if (typeof connectionString !== "string" || connectionString === "") {
      throw new TypeError("connectionString is required");
    }
    this.#pool = new Pool(admissibleVectorPoolConfig(connectionString));
    this.#ownsPool = true;
    this.#reconcilePreparation = reconcilePreparation;
  }

  async close() {
    if (this.#ownsPool) {
      await this.#pool.end();
    }
  }

  async #resolvePreparation(input) {
    if (typeof this.#reconcilePreparation === "function") {
      return this.#reconcilePreparation(input);
    }
    const client = await this.#pool.connect();
    try {
      return await resolveVectorPreparation(client, input);
    } finally {
      client.release();
    }
  }

  async retrieve({
    tenantId,
    retrievalId,
    incidentId,
    agency,
    queryEmbedding,
    limit = 10,
    ttlMs = 60_000
  }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const retrieval = requireUuid(retrievalId, "retrievalId");
    const incident = requireUuid(incidentId, "incidentId");
    const requester = requireText(agency, "agency");
    const vector = requireEmbedding(queryEmbedding);
    const acceptedLimit = requireInteger(limit, "limit", 1, 100);
    const acceptedTtl = requireInteger(ttlMs, "ttlMs", 1_000, 300_000);
    let client = await this.#pool.connect();
    let prepared = false;
    let preparationObservation = "direct_ack";
    let output;
    let preparedCandidateCount = null;
    let primaryError = null;
    let cleanupError = null;
    try {
      const preparationInput = {
        tenantId: tenant,
        retrievalId: retrieval,
        incidentId: incident,
        agency: requester,
        ttlMs: acceptedTtl
      };
      let preparedResult;
      try {
        preparedResult = await executeVectorPreparation(
          client,
          preparationInput
        );
      } catch (error) {
        if (error.commitOutcomeUnknown !== true) {
          throw error;
        }
        client.release(error.cause ?? error);
        client = null;
        preparedResult = await this.#resolvePreparation(preparationInput);
        if (preparedResult?.rowCount !== 1) {
          throw error;
        }
        preparationObservation = "read_reconciled";
        client = await this.#pool.connect();
      }
      if (preparedResult.rowCount !== 1) {
        throw new Error("ADMISSIBLE_VECTOR_PREPARE_INVALID");
      }
      const preparedRow = preparedResult.rows[0];
      const candidateCount = integerFromRow(
        preparedRow.candidate_count,
        "candidate_count",
        10_000
      );
      preparedCandidateCount = candidateCount;
      const snapshot = preparedSnapshot(
        preparedRow,
        retrieval,
        acceptedTtl
      );
      prepared = true;
      const ranked = await client.query(
        `
          SELECT *
          FROM tp_api.g1_rank_vector_set_v1(
            $1::UUID, $2::UUID, $3::UUID, $4, $5, $6, $7::INT8
          )
        `,
        [
          tenant,
          retrieval,
          incident,
          requester,
          POLICY_VERSION,
          vector,
          acceptedLimit
        ]
      );
      if (ranked.rowCount > acceptedLimit || ranked.rowCount > candidateCount) {
        throw new Error("ADMISSIBLE_VECTOR_CARDINALITY_INVALID");
      }
      const results = validatedRankedResults(ranked.rows);
      output = {
        retrievalId: retrieval,
        candidateCount,
        admittedAt: snapshot.admittedAt,
        expiresAt: snapshot.expiresAt,
        approximateNearestNeighbor: true,
        authorizationRecheckRequired: true,
        preparationCommit: preparationCommitFor(
          preparedRow,
          preparationInput,
          preparationObservation
        ),
        results
      };
    } catch (error) {
      primaryError = error;
    } finally {
      if (prepared) {
        try {
          const cleaned = await client.query(
            `
              SELECT *
              FROM tp_api.g1_delete_vector_set_v1($1::UUID, $2::UUID)
            `,
            [tenant, retrieval]
          );
          if (
            cleaned.rowCount !== 1 ||
            integerFromRow(
              cleaned.rows[0].deleted_candidates,
              "deleted_candidates",
              10_000
            ) !== preparedCandidateCount ||
            integerFromRow(
              cleaned.rows[0].retired_sets,
              "retired_sets",
              1
            ) !== 1
          ) {
            throw new Error("ADMISSIBLE_VECTOR_CLEANUP_INVALID");
          }
        } catch (error) {
          cleanupError = error;
        }
      }
      client?.release(primaryError ?? cleanupError ?? undefined);
    }
    if (primaryError && cleanupError) {
      throw new AggregateError(
        [primaryError, cleanupError],
        "ADMISSIBLE_VECTOR_OPERATION_AND_CLEANUP_FAILED"
      );
    }
    if (primaryError) {
      throw primaryError;
    }
    if (cleanupError) {
      throw cleanupError;
    }
    return output;
  }

  async purgeExpired({ tenantId, limit = 100 }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const acceptedLimit = requireInteger(limit, "limit", 1, 1000);
    const result = await this.#pool.query(
      `
        SELECT *
        FROM tp_api.g1_purge_expired_vector_sets_v1($1::UUID, $2::INT8)
      `,
      [tenant, acceptedLimit]
    );
    if (result.rowCount !== 1) {
      throw new Error("ADMISSIBLE_VECTOR_PURGE_INVALID");
    }
    return {
      deletedCandidates: integerFromRow(
        result.rows[0].deleted_candidates,
        "deleted_candidates"
      ),
      retiredSets: integerFromRow(
        result.rows[0].retired_sets,
        "retired_sets",
        acceptedLimit
      )
    };
  }
}

export const __test = Object.freeze({
  FRESH_PROOF_CANDIDATE_COUNT,
  FRESH_PROOF_SCHEMA,
  FRESH_PROOF_TTL_MS,
  POLICY_VERSION,
  PROOF_CANDIDATE_COUNT,
  PROOF_LIMIT,
  PROOF_SCHEMA,
  PROOF_TTL_MS,
  REQUIRED_EXCLUSION_REASONS,
  VECTOR_INDEX_NAME,
  authorityEvidenceBindingDigest,
  executeVectorPreparation,
  forcedIndexRankSql,
  identifierSetDigest,
  naturalRankSql,
  proofPlan,
  preparedSnapshot,
  validateProofSpec,
  validatedRankedResults
});
