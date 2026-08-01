import crypto from "node:crypto";
import { Pool } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import { runtimeDatabaseConfig } from "./database-runtime.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_OBJECT_ID = /^[0-9a-f]{40}$/;
const POLICY_VERSION = "g1-admissibility-v2";
const VECTOR_INDEX_NAME = "g1_vector_candidates_embedding_idx";
const PROOF_SCHEMA = "tideproof.gate1.admissible-vector-proof.v2";
const AUTHORITY_EVIDENCE_BINDING_SCHEMA =
  "tideproof.gate1.admissible-vector-authority-binding.v1";
const PROOF_CANDIDATE_COUNT = 10_000;
const PROOF_LIMIT = 10;
const PROOF_TTL_MS = 60_000;
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

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(
        ([key, nested]) =>
          `${JSON.stringify(key)}:${canonicalJson(nested)}`
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
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

function validateProofSpec(value) {
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
  assert(
    value.expectedCandidateCount === PROOF_CANDIDATE_COUNT &&
      value.limit === PROOF_LIMIT &&
      value.ttlMs === PROOF_TTL_MS &&
      SHA256.test(value.expectedCandidateSetSha256),
    "ADMISSIBLE_VECTOR_PROOF_SPEC_BOUNDARY"
  );
  assert(
    Array.isArray(value.exclusionCases) &&
      value.exclusionCases.length === REQUIRED_EXCLUSION_REASONS.length,
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
      ) === JSON.stringify(REQUIRED_EXCLUSION_REASONS),
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
    expectedCandidateCount: PROOF_CANDIDATE_COUNT,
    expectedCandidateSetSha256: value.expectedCandidateSetSha256,
    exclusionCases: [...exclusionCases].sort((left, right) =>
      left.reason.localeCompare(right.reason)
    ),
    nearestExcludedEvidenceId,
    limit: PROOF_LIMIT,
    ttlMs: PROOF_TTL_MS
  };
}

function authorityEvidenceBindingDigest({
  accepted,
  preparedTiming,
  rankedSequenceSha256,
  selected,
  sourceCommit,
  specSha256,
  treeDigest
}) {
  return sha256(
    canonicalJson({
      schemaVersion: AUTHORITY_EVIDENCE_BINDING_SCHEMA,
      sourceCommit,
      treeDigest,
      specSha256,
      runId: accepted.runId,
      tenantId: accepted.tenantId,
      incidentId: accepted.incidentId,
      retrievalId: accepted.retrievalId,
      snapshot: preparedTiming,
      rankedSequenceSha256,
      selected: {
        rank: 1,
        evidenceId: selected.evidenceId,
        evidenceDigest: selected.evidenceDigest
      }
    })
  );
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

function proofPlan(plan, spec) {
  const normalized = plan.toLowerCase();
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

export async function proveAdmissibleVectorSnapshot({
  authorizerPool,
  auditorPool,
  spec,
  sourceCommit,
  treeDigest
} = {}) {
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
  const accepted = validateProofSpec(spec);
  const { vector: _vector, ...canonicalSpec } = accepted;
  const specSha256 = sha256(canonicalJson(canonicalSpec));
  let authorizer;
  let auditor;
  let prepareAttempted = false;
  let prepared = false;
  let preparedCandidateCount = null;
  let preparedTiming = null;
  let primaryError = null;
  let cleanupError = null;
  let receipt;
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

    prepareAttempted = true;
    const preparedResult = await authorizer.query(
      `
        SELECT *
        FROM tp_api.g1_prepare_vector_set_v1(
          $1::UUID, $2::UUID, $3::UUID, $4, $5, $6::INT8
        )
      `,
      [
        accepted.tenantId,
        accepted.retrievalId,
        accepted.incidentId,
        accepted.agency,
        POLICY_VERSION,
        accepted.ttlMs
      ]
    );
    assert(
      preparedResult.rowCount === 1,
      "ADMISSIBLE_VECTOR_PREPARE_INVALID"
    );
    prepared = true;
    preparedCandidateCount = integerFromRow(
      preparedResult.rows[0]?.candidate_count,
      "candidate_count",
      PROOF_CANDIDATE_COUNT
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

    const exclusionReasons = {};
    for (const exclusion of accepted.exclusionCases) {
      const observed = await authorizer.query(
        `
          SELECT *
          FROM tp_api.g1_observe_admissibility_v2(
            $1::UUID, $2::UUID, $3::UUID, $4
          )
        `,
        [
          accepted.tenantId,
          exclusion.evidenceId,
          accepted.incidentId,
          accepted.agency
        ]
      );
      assert(
        observed.rowCount === 1 &&
          observed.rows[0]?.admissibility === exclusion.reason &&
          typeof observed.rows[0]?.evidence_digest === "string" &&
          SHA256.test(observed.rows[0].evidence_digest),
        "ADMISSIBLE_VECTOR_PROOF_EXCLUSION_REASON"
      );
      exclusionReasons[exclusion.reason] =
        (exclusionReasons[exclusion.reason] ?? 0) + 1;
    }

    const planResult = await auditor.query(
      `
        EXPLAIN (VERBOSE)
        SELECT
          evidence_id,
          evidence_digest,
          assertion,
          embedding <=> $3::VECTOR(3) AS distance
        FROM tp_private.g1_vector_candidates
        WHERE tenant_id = $1::UUID
          AND retrieval_id = $2::UUID
        ORDER BY embedding <=> $3::VECTOR(3)
        LIMIT $4::INT8
      `,
      [
        accepted.tenantId,
        accepted.retrievalId,
        accepted.vector,
        accepted.limit
      ]
    );
    const plan = proofPlan(explainText(planResult), accepted);

    const rankedResult = await authorizer.query(
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
    assert(
      ranked.every(({ evidenceId }) => candidateSet.has(evidenceId)),
      "ADMISSIBLE_VECTOR_PROOF_RANKED_OUTSIDE_SNAPSHOT"
    );
    const auditorRankedResult = await auditor.query(
      `
        SELECT
          evidence_id,
          evidence_digest,
          assertion,
          embedding <=> $3::VECTOR(3) AS distance
        FROM tp_private.g1_vector_candidates
        WHERE tenant_id = $1::UUID
          AND retrieval_id = $2::UUID
        ORDER BY embedding <=> $3::VECTOR(3)
        LIMIT $4::INT8
      `,
      [
        accepted.tenantId,
        accepted.retrievalId,
        accepted.vector,
        accepted.limit
      ]
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
    const rankedSequenceSha256 = sha256(
      canonicalJson(
        ranked.map(({ evidenceId, evidenceDigest, distance }) => ({
          evidenceId,
          evidenceDigest,
          distance
        }))
      )
    );
    const authorityEvidenceBindingSha256 =
      authorityEvidenceBindingDigest({
        accepted,
        preparedTiming,
        rankedSequenceSha256,
        selected: ranked[0],
        sourceCommit,
        specSha256,
        treeDigest
      });

    receipt = {
      schemaVersion: PROOF_SCHEMA,
      status: "PASS",
      sourceCommit,
      treeDigest,
      drill: {
        runId: accepted.runId,
        selectedRank: 1,
        authorityEvidenceBindingSha256
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
        nearestExcludedCloserThanRanked: true
      },
      snapshot: {
        ...preparedTiming,
        ttlMs: accepted.ttlMs
      },
      ranking: {
        ...plan,
        rankedCount: ranked.length,
        rankedSetSha256,
        rankedSequenceSha256,
        auditorRankMatchesAuthorizer: true,
        approximateNearestNeighbor: true,
        authorizationRecheckRequired: true
      },
      cleanup: null,
      claimBoundary:
        "This sanitized provider-backed receipt records one exact clean-source integrated admissibility-snapshot run, its synthetic drill identity, a non-reversible binding from the top-ranked admissible evidence to the exact source, spec, snapshot, and ranked sequence, the required adversarial exclusions, the named DVI with exact tenant/retrieval prefix spans, ranked-set containment, and snapshot retirement. It requires independent acceptance review and does not prove that AWS consumed the binding, authorization, the 100-drill batch, production suitability, or final release readiness."
    };
  } catch (error) {
    primaryError = error;
  } finally {
    if (prepareAttempted) {
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
          PROOF_CANDIDATE_COUNT
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
                PROOF_CANDIDATE_COUNT
              ) === deletedCandidateCount &&
              (!preparedTiming ||
                cleanedAtMs >= Date.parse(preparedTiming.admittedAt)) &&
              integerFromRow(
                retired.rows[0]?.remaining_candidates,
                "remaining_candidates",
                PROOF_CANDIDATE_COUNT
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
  return receipt;
}

export class AdmissibleVectorRetriever {
  #ownsPool;
  #pool;

  constructor({ connectionString, pool } = {}) {
    if (pool) {
      if (typeof pool.connect !== "function") {
        throw new TypeError("pool must expose connect()");
      }
      this.#pool = pool;
      this.#ownsPool = false;
      return;
    }
    if (typeof connectionString !== "string" || connectionString === "") {
      throw new TypeError("connectionString is required");
    }
    this.#pool = new Pool(admissibleVectorPoolConfig(connectionString));
    this.#ownsPool = true;
  }

  async close() {
    if (this.#ownsPool) {
      await this.#pool.end();
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
    const client = await this.#pool.connect();
    let prepared = false;
    let output;
    let preparedCandidateCount = null;
    let primaryError = null;
    let cleanupError = null;
    try {
      const preparedResult = await client.query(
        `
          SELECT *
          FROM tp_api.g1_prepare_vector_set_v1(
            $1::UUID, $2::UUID, $3::UUID, $4, $5, $6::INT8
          )
        `,
        [
          tenant,
          retrieval,
          incident,
          requester,
          POLICY_VERSION,
          acceptedTtl
        ]
      );
      if (preparedResult.rowCount !== 1) {
        throw new Error("ADMISSIBLE_VECTOR_PREPARE_INVALID");
      }
      prepared = true;
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
      client.release(primaryError ?? cleanupError ?? undefined);
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
  AUTHORITY_EVIDENCE_BINDING_SCHEMA,
  POLICY_VERSION,
  PROOF_CANDIDATE_COUNT,
  PROOF_LIMIT,
  PROOF_SCHEMA,
  PROOF_TTL_MS,
  REQUIRED_EXCLUSION_REASONS,
  VECTOR_INDEX_NAME,
  authorityEvidenceBindingDigest,
  identifierSetDigest,
  preparedSnapshot,
  validateProofSpec,
  validatedRankedResults
});
