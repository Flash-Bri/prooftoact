import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  AdmissibleVectorRetriever,
  admissibleVectorAuditorPoolConfig,
  admissibleVectorPoolConfig,
  proveAdmissibleVectorSnapshot,
  __test
} from "../src/cloud/admissible-vector-retrieval.js";
import { safeAdmissibleVectorFailureCode } from "../scripts/gate1-admissible-vector.js";
import { dviRankedSequenceSha256For } from "../src/cloud/dvi-selection.js";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

const CONNECTION_STRING =
  "postgresql://u:p@example.invalid/defaultdb?sslmode=verify-full";

const INPUT = Object.freeze({
  tenantId: "11111111-1111-4111-8111-111111111111",
  retrievalId: "22222222-2222-4222-8222-222222222222",
  incidentId: "33333333-3333-4333-8333-333333333333",
  agency: "rescue",
  queryEmbedding: [1, 0, 0],
  limit: 5,
  ttlMs: 30_000
});

function fakePool({
  rankError,
  cleanupError,
  prepareCommitError,
  preparedRow,
  rankedRows
} = {}) {
  const calls = [];
  let releasedWith;
  const releases = [];
  let prepareCommitFailed = false;
  const client = {
    async query(text, values) {
      calls.push({ text, values });
      if (
        text === "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE" ||
        text === "ROLLBACK"
      ) {
        return { rowCount: 0, rows: [] };
      }
      if (text === "COMMIT") {
        if (prepareCommitError && !prepareCommitFailed) {
          prepareCommitFailed = true;
          throw prepareCommitError;
        }
        return { rowCount: 0, rows: [] };
      }
      if (text.includes("g1_prepare_vector_set_v1")) {
        return {
          rowCount: 1,
          rows: [preparedRow ?? {
            retrieval_id: INPUT.retrievalId,
            candidate_count: "2",
            admitted_at: "2026-08-01T12:00:00.000Z",
            expires_at: "2026-08-01T12:00:30.000Z"
          }]
        };
      }
      if (text.includes("g1_rank_vector_set_v1")) {
        if (rankError) throw rankError;
        return {
          rowCount: rankedRows?.length ?? 1,
          rows: rankedRows ?? [{
            evidence_id: "44444444-4444-4444-8444-444444444444",
            evidence_digest: "a".repeat(64),
            assertion: "Synthetic admissible evidence.",
            distance: "0.125"
          }]
        };
      }
      if (text.includes("g1_commit_dvi_selection_v1")) {
        const selectedRows = rankedRows ?? [{
          evidence_id: "44444444-4444-4444-8444-444444444444",
          evidence_digest: "a".repeat(64)
        }];
        return {
          rowCount: 1,
          rows: [{
            authority_evidence_binding_sha256: values[11],
            admitted_at: "2026-08-01T12:00:00.000Z",
            expires_at: "2026-08-01T12:01:00.000Z",
            ranked_sequence_sha256: dviRankedSequenceSha256For(
              selectedRows.map(({ evidence_id, evidence_digest }) => ({
                evidenceId: evidence_id,
                evidenceDigest: evidence_digest
              }))
            ),
            query_embedding_sha256: sha256(values[9]),
            result_limit: String(values[10]),
            selected_evidence_id: selectedRows[0].evidence_id,
            selected_evidence_digest: selectedRows[0].evidence_digest
          }]
        };
      }
      if (text.includes("g1_delete_vector_set_v1")) {
        if (cleanupError) throw cleanupError;
        return {
          rowCount: 1,
          rows: [{ deleted_candidates: "2", retired_sets: "1" }]
        };
      }
      throw new Error("unexpected query");
    },
    release(error) {
      releasedWith = error;
      releases.push(error);
    }
  };
  return {
    calls,
    client,
    async connect() {
      return client;
    },
    get releasedWith() {
      return releasedWith;
    },
    get releases() {
      return releases;
    }
  };
}

test("integrated retrieval prepares, ranks, and retires one immutable snapshot", async () => {
  const pool = fakePool();
  const retriever = new AdmissibleVectorRetriever({ pool });
  const result = await retriever.retrieve(INPUT);
  assert.deepEqual(
    pool.calls.map(({ text }) =>
      /g1_(prepare|rank|delete)_vector_set_v1/.exec(text)?.[1]
    ).filter(Boolean),
    ["prepare", "rank", "delete"]
  );
  assert.equal(result.candidateCount, 2);
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].distance, 0.125);
  assert.equal(result.approximateNearestNeighbor, true);
  assert.equal(result.authorizationRecheckRequired, true);
  assert.equal(result.preparationCommit.observation, "direct_ack");
  assert.equal(pool.releasedWith, undefined);
});

test("integrated retrieval reconciles exact DVI preparation after ACK loss", async () => {
  const released = [];
  const events = [];
  let connections = 0;
  const broken = {
    async query(text) {
      if (text === "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE") {
        return { rowCount: 0, rows: [] };
      }
      if (text.includes("g1_prepare_vector_set_v1")) {
        return {
          rowCount: 1,
          rows: [{
            retrieval_id: INPUT.retrievalId,
            candidate_count: "2",
            admitted_at: "2026-08-01T12:00:00.000Z",
            expires_at: "2026-08-01T12:00:30.000Z"
          }]
        };
      }
      if (text === "COMMIT") {
        throw Object.assign(new Error("synthetic prepare ACK loss"), {
          code: "XX000"
        });
      }
      throw new Error("unexpected broken-client query");
    },
    release(error) {
      released.push(error);
      events.push("broken_released");
    }
  };
  const live = {
    async query(text) {
      if (text.includes("g1_rank_vector_set_v1")) {
        return {
          rowCount: 1,
          rows: [{
            evidence_id: "44444444-4444-4444-8444-444444444444",
            evidence_digest: "a".repeat(64),
            assertion: "Synthetic admissible evidence.",
            distance: "0.125"
          }]
        };
      }
      if (text.includes("g1_delete_vector_set_v1")) {
        return {
          rowCount: 1,
          rows: [{ deleted_candidates: "2", retired_sets: "1" }]
        };
      }
      throw new Error("unexpected live-client query");
    },
    release(error) { released.push(error); }
  };
  const pool = {
    async connect() {
      connections += 1;
      return connections === 1 ? broken : live;
    }
  };
  const retriever = new AdmissibleVectorRetriever({
    pool,
    reconcilePreparation: async () => {
      events.push("reconciliation_started");
      return {
        rowCount: 1,
        rows: [{
          retrieval_id: INPUT.retrievalId,
          candidate_count: "2",
          admitted_at: "2026-08-01T12:00:00.000Z",
          expires_at: "2026-08-01T12:00:30.000Z",
          database_now: new Date("2026-08-01T12:00:01.000Z")
        }]
      };
    }
  });

  const result = await retriever.retrieve(INPUT);
  assert.equal(result.preparationCommit.status, "COMMITTED");
  assert.equal(result.preparationCommit.observation, "read_reconciled");
  assert.equal(connections, 2);
  assert.equal(released.length, 2);
  assert.deepEqual(events, ["broken_released", "reconciliation_started"]);
});

test("integrated retrieval fails closed on zero, multiple, or drifted preparation receipts", async () => {
  const validRow = {
    retrieval_id: INPUT.retrievalId,
    candidate_count: "2",
    admitted_at: "2026-08-01T12:00:00.000Z",
    expires_at: "2026-08-01T12:00:30.000Z",
    database_now: new Date("2026-08-01T12:00:01.000Z")
  };
  for (const rows of [
    [],
    [validRow, { ...validRow }],
    [{
      ...validRow,
      retrieval_id: "99999999-9999-4999-8999-999999999999"
    }]
  ]) {
    const commitError = Object.assign(
      new Error("synthetic unclassified post-COMMIT failure"),
      { code: "XX000" }
    );
    const pool = fakePool({ prepareCommitError: commitError });
    const retriever = new AdmissibleVectorRetriever({
      pool,
      reconcilePreparation: async () => ({
        rowCount: rows.length,
        rows
      })
    });
    await assert.rejects(
      retriever.retrieve(INPUT),
      /ADMISSIBLE_VECTOR_(?:PREPARE_COMMIT_UNKNOWN|PREPARE_BINDING_INVALID)/u
    );
    assert.equal(pool.releases[0], commitError);
    assert.equal(
      pool.calls.some(({ text }) => text.includes("g1_delete_vector_set_v1")),
      false
    );
  }
});

test("integrated retrieval retires its snapshot when ranking fails", async () => {
  const rankError = new Error("rank failed");
  const pool = fakePool({ rankError });
  const retriever = new AdmissibleVectorRetriever({ pool });
  await assert.rejects(retriever.retrieve(INPUT), /rank failed/);
  assert.equal(
    pool.calls.some(({ text }) => text.includes("g1_delete_vector_set_v1")),
    true
  );
  assert.equal(pool.releasedWith, rankError);
});

test("integrated retrieval fails closed if both ranking and cleanup fail", async () => {
  const pool = fakePool({
    rankError: new Error("rank failed"),
    cleanupError: new Error("cleanup failed")
  });
  const retriever = new AdmissibleVectorRetriever({ pool });
  await assert.rejects(
    retriever.retrieve(INPUT),
    /ADMISSIBLE_VECTOR_OPERATION_AND_CLEANUP_FAILED/
  );
});

test("integrated retrieval error output never exposes database details", () => {
  assert.equal(
    safeAdmissibleVectorFailureCode(
      new Error("ADMISSIBLE_VECTOR_WORKTREE_DIRTY")
    ),
    "ADMISSIBLE_VECTOR_WORKTREE_DIRTY"
  );
  assert.equal(
    safeAdmissibleVectorFailureCode(
      new Error("password failed for postgresql://secret@example.invalid")
    ),
    "ADMISSIBLE_VECTOR_UNKNOWN"
  );
});

test("integrated retrieval pins the exact database and timeout profile", () => {
  const config = admissibleVectorPoolConfig(CONNECTION_STRING, {});
  assert.equal(new URL(config.connectionString).pathname, "/tideproof");
  assert.equal(config.statement_timeout, 4_000);
  assert.equal(config.query_timeout, 4_500);

  const auditor = admissibleVectorAuditorPoolConfig(CONNECTION_STRING, {});
  assert.equal(new URL(auditor.connectionString).pathname, "/tideproof");
  assert.equal(auditor.application_name, "tideproof-vector-auditor");
});

test("integrated retrieval rejects changed prepare bindings and TTL", async () => {
  for (const preparedRow of [
    {
      retrieval_id: "99999999-9999-4999-8999-999999999999",
      candidate_count: "2",
      admitted_at: "2026-08-01T12:00:00.000Z",
      expires_at: "2026-08-01T12:00:30.000Z"
    },
    {
      retrieval_id: INPUT.retrievalId,
      candidate_count: "2",
      admitted_at: "2026-08-01T12:00:00.000Z",
      expires_at: "2026-08-01T12:00:29.999Z"
    }
  ]) {
    const retriever = new AdmissibleVectorRetriever({
      pool: fakePool({ preparedRow })
    });
    await assert.rejects(
      retriever.retrieve(INPUT),
      /ADMISSIBLE_VECTOR_PREPARE_(BINDING|TIME)_INVALID/u
    );
  }
});

test("integrated retrieval rejects duplicate, unordered, and invalid distances", () => {
  const base = {
    evidenceId: "44444444-4444-4444-8444-444444444444",
    evidenceDigest: "a".repeat(64),
    assertion: "Synthetic admissible evidence."
  };
  const row = (overrides = {}) => ({
    evidence_id: base.evidenceId,
    evidence_digest: base.evidenceDigest,
    assertion: base.assertion,
    distance: "0.125",
    ...overrides
  });
  assert.throws(
    () => __test.validatedRankedResults([row(), row()]),
    /RESULT_DUPLICATE/u
  );
  assert.throws(
    () => __test.validatedRankedResults([
      row({ distance: "0.5" }),
      row({
        evidence_id: "55555555-5555-4555-8555-555555555555",
        distance: "0.25"
      })
    ]),
    /RESULT_ORDER_INVALID/u
  );
  assert.throws(
    () => __test.validatedRankedResults([row({ distance: "2.01" })]),
    /RESULT_INVALID/u
  );
  assert.throws(
    () => __test.validatedRankedResults([row({ distance: null })]),
    /RESULT_INVALID/u
  );
});

function proofUuid(ordinal) {
  return `aaaaaaaa-aaaa-4aaa-8aaa-${ordinal
    .toString(16)
    .padStart(12, "0")}`;
}

const PROOF_CANDIDATE_IDS = Object.freeze(
  Array.from(
    { length: __test.PROOF_CANDIDATE_COUNT },
    (_, index) => proofUuid(index + 1)
  )
);
const PROOF_EXCLUSIONS = Object.freeze(
  __test.REQUIRED_EXCLUSION_REASONS.map((reason, index) =>
    Object.freeze({ evidenceId: proofUuid(20_001 + index), reason })
  )
);

function proofSpec(overrides = {}) {
  return {
    tenantId: "11111111-1111-4111-8111-111111111111",
    runId: "99999999-9999-4999-8999-999999999999",
    retrievalId: "22222222-2222-4222-8222-222222222222",
    incidentId: "33333333-3333-4333-8333-333333333333",
    agency: "rescue",
    queryEmbedding: [1, 0, 0],
    expectedCandidateCount: __test.PROOF_CANDIDATE_COUNT,
    expectedCandidateSetSha256: __test.identifierSetDigest(
      PROOF_CANDIDATE_IDS,
      "candidateEvidenceId"
    ),
    exclusionCases: PROOF_EXCLUSIONS.map((entry) => ({ ...entry })),
    nearestExcludedEvidenceId: PROOF_EXCLUSIONS[0].evidenceId,
    limit: __test.PROOF_LIMIT,
    ttlMs: __test.PROOF_TTL_MS,
    ...overrides
  };
}

function proofPools({
  planUsesVectorIndex = true,
  nearestExcludedDistance = 0.001,
  changedExclusionReason = null,
  missingExclusionDigest = false,
  changedExclusionSnapshotTime = null,
  candidateIds = PROOF_CANDIDATE_IDS,
  prepareError = null,
  prepareCommitError = null,
  resolvedPreparationRows = null,
  cleanupError = null,
  auditorRankDrift = false,
  authorizerClusterId = "77777777-7777-4777-8777-777777777777",
  auditorClusterId = authorizerClusterId
} = {}) {
  const spec = proofSpec();
  const authorizerCalls = [];
  const auditorCalls = [];
  let authorizerConnections = 0;
  let authorizerReleasedWith;
  const authorizerReleases = [];
  let prepareCommitFailed = false;
  let auditorReleasedWith;
  const authorizer = {
    async query(text, values) {
      authorizerCalls.push({ text, values });
      if (
        text === "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE" ||
        text === "ROLLBACK"
      ) {
        return { rowCount: 0, rows: [] };
      }
      if (text === "COMMIT") {
        if (prepareCommitError && !prepareCommitFailed) {
          prepareCommitFailed = true;
          throw prepareCommitError;
        }
        return { rowCount: 0, rows: [] };
      }
      if (text.includes("current_database()")) {
        return {
          rowCount: 1,
          rows: [{
            database_name: "tideproof",
            current_user_name: "tp_authorizer_user",
            session_user_name: "tp_authorizer_user",
            cluster_id: authorizerClusterId,
            database_version: "CockroachDB CCL v26.2.1"
          }]
        };
      }
      if (text.includes("g1_prepare_vector_set_v1")) {
        if (prepareError) throw prepareError;
        return {
          rowCount: 1,
          rows: [{
            retrieval_id: spec.retrievalId,
            candidate_count: String(__test.PROOF_CANDIDATE_COUNT),
            admitted_at: "2026-08-01T12:00:00.000Z",
            expires_at: "2026-08-01T12:01:00.000Z"
          }]
        };
      }
      if (text.includes("g1_resolve_vector_set_v1")) {
        const rows = resolvedPreparationRows ?? [{
          retrieval_id: spec.retrievalId,
          candidate_count: String(__test.PROOF_CANDIDATE_COUNT),
          admitted_at: "2026-08-01T12:00:00.000Z",
          expires_at: "2026-08-01T12:01:00.000Z",
          database_now: new Date("2026-08-01T12:00:01.000Z")
        }];
        return {
          rowCount: rows.length,
          rows
        };
      }
      if (text.includes("g1_observe_vector_exclusion_v1")) {
        const exactBinding =
          values[0] === spec.tenantId &&
          values[1] === spec.retrievalId &&
          values[3] === spec.incidentId &&
          values[4] === spec.agency &&
          values[5] === "g1-admissibility-v2";
        const exclusion = PROOF_EXCLUSIONS.find(
          ({ evidenceId }) => evidenceId === values[2]
        );
        if (!exactBinding || !exclusion) return { rowCount: 0, rows: [] };
        return {
          rowCount: 1,
          rows: [{
            admissibility:
              changedExclusionReason ?? exclusion?.reason ?? "admissible",
            evidence_digest: missingExclusionDigest ? null : "e".repeat(64),
            snapshot_admitted_at:
              changedExclusionSnapshotTime ??
              new Date("2026-08-01T12:00:00.000Z")
          }]
        };
      }
      if (text.includes("g1_rank_vector_set_v1")) {
        return {
          rowCount: __test.PROOF_LIMIT,
          rows: PROOF_CANDIDATE_IDS.slice(0, __test.PROOF_LIMIT).map(
            (evidenceId, index) => ({
              evidence_id: evidenceId,
              evidence_digest: (index + 1).toString(16).repeat(64),
              assertion: `Synthetic admissible evidence ${index + 1}.`,
              distance: String(0.1 + index / 100)
            })
          )
        };
      }
      if (text.includes("g1_commit_dvi_selection_v1")) {
        const selectedRows = PROOF_CANDIDATE_IDS.slice(
          0,
          __test.PROOF_LIMIT
        ).map((evidenceId, index) => ({
          evidence_id: evidenceId,
          evidence_digest: (index + 1).toString(16).repeat(64)
        }));
        return {
          rowCount: 1,
          rows: [{
            authority_evidence_binding_sha256: values[11],
            admitted_at: "2026-08-01T12:00:00.000Z",
            expires_at: "2026-08-01T12:01:00.000Z",
            ranked_sequence_sha256: dviRankedSequenceSha256For(
              selectedRows.map(({ evidence_id, evidence_digest }) => ({
                evidenceId: evidence_id,
                evidenceDigest: evidence_digest
              }))
            ),
            query_embedding_sha256: sha256(values[9]),
            result_limit: String(values[10]),
            selected_evidence_id: selectedRows[0].evidence_id,
            selected_evidence_digest: selectedRows[0].evidence_digest
          }]
        };
      }
      if (text.includes("g1_delete_vector_set_v1")) {
        if (cleanupError) throw cleanupError;
        return {
          rowCount: 1,
          rows: [{
            deleted_candidates: String(__test.PROOF_CANDIDATE_COUNT),
            retired_sets: "1"
          }]
        };
      }
      throw new Error("unexpected authorizer query");
    },
    release(error) {
      authorizerReleasedWith = error;
      authorizerReleases.push(error);
    }
  };
  const auditor = {
    async query(text) {
      auditorCalls.push(text);
      if (text.includes("current_database()")) {
        return {
          rowCount: 1,
          rows: [{
            database_name: "tideproof",
            current_user_name: "proof_owner",
            session_user_name: "proof_owner",
            cluster_id: auditorClusterId,
            database_version: "CockroachDB CCL v26.2.1"
          }]
        };
      }
      if (text.includes("EXPLAIN (VERBOSE)")) {
        const operator = planUsesVectorIndex
          ? `vector search ${__test.VECTOR_INDEX_NAME}`
          : "scan g1_vector_candidates_pkey";
        return {
          rowCount: 3,
          rows: [
            { info: operator },
            { info: `prefix spans: ${spec.tenantId}` },
            { info: `retrieval: ${spec.retrievalId}` }
          ]
        };
      }
      if (
        text.includes("FROM tp_private.g1_vector_candidates") &&
        text.includes("AS distance")
      ) {
        return {
          rowCount: __test.PROOF_LIMIT,
          rows: PROOF_CANDIDATE_IDS.slice(0, __test.PROOF_LIMIT).map(
            (evidenceId, index) => ({
              evidence_id: evidenceId,
              evidence_digest: (index + 1).toString(16).repeat(64),
              assertion: `Synthetic admissible evidence ${index + 1}.`,
              distance: String(
                0.1 + index / 100 +
                  (auditorRankDrift && index === 0 ? 0.001 : 0)
              )
            })
          )
        };
      }
      if (text.includes("FROM tp_private.g1_evidence")) {
        return {
          rowCount: 1,
          rows: [{
            evidence_id: spec.nearestExcludedEvidenceId,
            distance: String(nearestExcludedDistance)
          }]
        };
      }
      if (text.includes("remaining_candidates")) {
        return {
          rowCount: 1,
          rows: [{
            candidate_count: String(__test.PROOF_CANDIDATE_COUNT),
            cleaned_at: "2026-08-01T12:00:02.000Z",
            remaining_candidates: "0",
            remaining_exclusions: "0"
          }]
        };
      }
      if (text.includes("evidence_id::STRING AS evidence_id")) {
        return {
          rowCount: candidateIds.length,
          rows: candidateIds.map((evidenceId) => ({ evidence_id: evidenceId }))
        };
      }
      throw new Error("unexpected auditor query");
    },
    release(error) {
      auditorReleasedWith = error;
    }
  };
  return {
    authorizerCalls,
    auditorCalls,
    authorizerPool: {
      async connect() {
        authorizerConnections += 1;
        return authorizer;
      }
    },
    auditorPool: { async connect() { return auditor; } },
    get authorizerReleasedWith() { return authorizerReleasedWith; },
    get authorizerConnections() { return authorizerConnections; },
    get authorizerReleases() { return authorizerReleases; },
    get auditorReleasedWith() { return auditorReleasedWith; }
  };
}

async function runProof(pools, spec = proofSpec()) {
  return proveAdmissibleVectorSnapshot({
    authorizerPool: pools.authorizerPool,
    auditorPool: pools.auditorPool,
    spec,
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40)
  });
}

test("integrated DVI proof binds exclusions, physical plan, ranking, and cleanup", async () => {
  const pools = proofPools();
  const receipt = await runProof(pools);
  assert.equal(receipt.schemaVersion, __test.PROOF_SCHEMA);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.drill.runId, proofSpec().runId);
  assert.equal(receipt.drill.selectedRank, 1);
  assert.equal(receipt.drill.durableSelectionCommitted, true);
  assert.match(
    receipt.drill.authorityEvidenceBindingSha256,
    /^[0-9a-f]{64}$/u
  );
  assert.match(
    receipt.drill.selectedEvidenceBindingSha256,
    /^[0-9a-f]{64}$/u
  );
  assert.equal(receipt.fixture.candidateCount, 10_000);
  assert.equal(receipt.fixture.exclusionCaseCount, 7);
  assert.equal(receipt.fixture.nearestExcludedCloserThanRanked, true);
  assert.match(receipt.database.clusterIdSha256, /^[0-9a-f]{64}$/u);
  assert.equal(receipt.snapshot.ttlMs, 60_000);
  assert.equal(receipt.snapshot.commit.observation, "direct_ack");
  assert.equal(receipt.snapshot.admittedAt, "2026-08-01T12:00:00.000Z");
  assert.deepEqual(
    Object.keys(receipt.fixture.exclusionReasons).sort(),
    [...__test.REQUIRED_EXCLUSION_REASONS]
  );
  assert.match(
    receipt.fixture.requiredExclusionObservationsSha256,
    /^[0-9a-f]{64}$/u
  );
  assert.equal(receipt.fixture.requiredExclusionsBoundToSnapshot, true);
  assert.equal(receipt.ranking.indexName, __test.VECTOR_INDEX_NAME);
  assert.equal(receipt.ranking.vectorSearchUsed, true);
  assert.equal(receipt.ranking.exactPrefixSpansUsed, true);
  assert.equal(receipt.ranking.rankedCount, 10);
  assert.match(receipt.ranking.rankedSequenceSha256, /^[0-9a-f]{64}$/u);
  assert.equal(receipt.ranking.auditorRankMatchesAuthorizer, true);
  assert.equal(receipt.cleanup.deletedCandidateCount, 10_000);
  assert.equal(receipt.cleanup.remainingExclusionCount, 0);
  assert.equal(receipt.cleanup.snapshotRetired, true);
  assert.equal(receipt.cleanup.cleanedAt, "2026-08-01T12:00:02.000Z");
  const publicReceipt = JSON.stringify(receipt);
  assert.equal(publicReceipt.includes(proofSpec().tenantId), false);
  assert.equal(publicReceipt.includes(proofSpec().incidentId), false);
  assert.equal(publicReceipt.includes(proofSpec().retrievalId), false);
  assert.equal(publicReceipt.includes(PROOF_CANDIDATE_IDS[0]), false);
  assert.equal(pools.authorizerReleasedWith, undefined);
  assert.equal(pools.auditorReleasedWith, undefined);
  assert.equal(
    pools.authorizerCalls.some(({ text }) =>
      text.includes("g1_observe_admissibility_v2")
    ),
    false
  );
  const exclusionCalls = pools.authorizerCalls.filter(({ text }) =>
    text.includes("g1_observe_vector_exclusion_v1")
  );
  assert.equal(exclusionCalls.length, 7);
  assert.deepEqual(
    exclusionCalls.map(({ values }) => values),
    PROOF_EXCLUSIONS.map(({ evidenceId }) => [
      proofSpec().tenantId,
      proofSpec().retrievalId,
      evidenceId,
      proofSpec().incidentId,
      proofSpec().agency,
      "g1-admissibility-v2"
    ])
  );
});

test("integrated DVI proof reconciles exact preparation after ACK loss", async () => {
  const prepareCommitError = Object.assign(
    new Error("synthetic provider prepare ACK loss"),
    { code: "XX000" }
  );
  const pools = proofPools({ prepareCommitError });
  const receipt = await runProof(pools);

  assert.equal(receipt.snapshot.commit.status, "COMMITTED");
  assert.equal(receipt.snapshot.commit.observation, "read_reconciled");
  assert.equal(pools.authorizerConnections, 2);
  assert.equal(pools.authorizerReleases[0], prepareCommitError);
  assert.equal(pools.authorizerReleases[1], undefined);
});

test("integrated DVI proof fails closed on zero, multiple, or drifted preparation receipts", async () => {
  const validRow = {
    retrieval_id: proofSpec().retrievalId,
    candidate_count: String(__test.PROOF_CANDIDATE_COUNT),
    admitted_at: "2026-08-01T12:00:00.000Z",
    expires_at: "2026-08-01T12:01:00.000Z",
    database_now: new Date("2026-08-01T12:00:01.000Z")
  };
  for (const rows of [
    [],
    [validRow, { ...validRow }],
    [{
      ...validRow,
      retrieval_id: "99999999-9999-4999-8999-999999999999"
    }]
  ]) {
    const commitError = Object.assign(
      new Error("synthetic unclassified provider post-COMMIT failure"),
      { code: "XX000" }
    );
    const pools = proofPools({
      prepareCommitError: commitError,
      resolvedPreparationRows: rows
    });
    await assert.rejects(
      runProof(pools),
      /ADMISSIBLE_VECTOR_(?:PREPARE_COMMIT_UNKNOWN|PREPARE_BINDING_INVALID)/u
    );
    assert.equal(pools.authorizerReleases[0], commitError);
    assert.equal(
      pools.authorizerCalls.some(({ text }) =>
        text.includes("g1_delete_vector_set_v1")
      ),
      false
    );
  }
});

test("integrated DVI proof binding changes with the run and selected evidence", () => {
  const accepted = __test.validateProofSpec(proofSpec());
  const base = {
    accepted,
    preparedTiming: {
      admittedAt: "2026-08-01T12:00:00.000Z",
      expiresAt: "2026-08-01T12:01:00.000Z"
    },
    rankedSequenceSha256: "c".repeat(64),
    queryEmbeddingSha256: "f".repeat(64),
    selected: {
      evidenceId: PROOF_CANDIDATE_IDS[0],
      evidenceDigest: "d".repeat(64)
    },
    sourceCommit: "a".repeat(40),
    specSha256: "e".repeat(64),
    treeDigest: "b".repeat(40)
  };
  const digest = __test.authorityEvidenceBindingDigest(base);
  assert.match(digest, /^[0-9a-f]{64}$/u);
  assert.notEqual(
    digest,
    __test.authorityEvidenceBindingDigest({
      ...base,
      accepted: {
        ...accepted,
        runId: "88888888-8888-4888-8888-888888888888"
      }
    })
  );
  assert.notEqual(
    digest,
    __test.authorityEvidenceBindingDigest({
      ...base,
      selected: {
        evidenceId: PROOF_CANDIDATE_IDS[1],
        evidenceDigest: "f".repeat(64)
      }
    })
  );
});

test("integrated DVI proof rejects a non-vector plan and still retires the snapshot", async () => {
  const pools = proofPools({ planUsesVectorIndex: false });
  await assert.rejects(
    runProof(pools),
    /ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING/
  );
  assert.equal(
    pools.authorizerCalls.some(({ text }) =>
      text.includes("g1_delete_vector_set_v1")
    ),
    true
  );
  assert.match(
    pools.authorizerReleasedWith.message,
    /ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING/
  );
});

test("integrated DVI proof rejects changed exclusions and a non-closer adversary", async () => {
  await assert.rejects(
    runProof(proofPools({ missingExclusionDigest: true })),
    /ADMISSIBLE_VECTOR_PROOF_EXCLUSION_REASON/
  );
  await assert.rejects(
    runProof(proofPools({ changedExclusionReason: "admissible" })),
    /ADMISSIBLE_VECTOR_PROOF_EXCLUSION_REASON/
  );
  await assert.rejects(
    runProof(proofPools({ nearestExcludedDistance: 0.5 })),
    /ADMISSIBLE_VECTOR_PROOF_NEAREST_EXCLUSION_NOT_CLOSER/
  );
  await assert.rejects(
    runProof(proofPools({
      changedExclusionSnapshotTime: new Date("2026-08-01T11:59:59.000Z")
    })),
    /ADMISSIBLE_VECTOR_PROOF_EXCLUSION_REASON/
  );
});

test("integrated DVI proof rejects candidate-set drift before ranking", async () => {
  const changed = [...PROOF_CANDIDATE_IDS];
  changed[0] = proofUuid(30_001);
  await assert.rejects(
    runProof(proofPools({ candidateIds: changed })),
    /ADMISSIBLE_VECTOR_PROOF_CANDIDATE_DIGEST/
  );
});

test("integrated DVI proof rejects authorizer and auditor rank drift", async () => {
  const pools = proofPools({ auditorRankDrift: true });
  await assert.rejects(
    runProof(pools),
    /ADMISSIBLE_VECTOR_PROOF_RANKED_RESULT_MISMATCH/u
  );
  assert.equal(
    pools.authorizerCalls.some(({ text }) =>
      text.includes("g1_delete_vector_set_v1")
    ),
    true
  );
});

test("integrated DVI proof binds both sessions to one CockroachDB cluster", async () => {
  await assert.rejects(
    runProof(proofPools({
      auditorClusterId: "88888888-8888-4888-8888-888888888888"
    })),
    /ADMISSIBLE_VECTOR_DATABASE_IDENTITY_MISMATCH/u
  );
});

test("integrated DVI proof never retires after a pre-COMMIT prepare failure", async () => {
  const prepareError = new Error("prepare response uncertain");
  const pools = proofPools({ prepareError });
  await assert.rejects(runProof(pools), /prepare response uncertain/u);
  assert.equal(
    pools.authorizerCalls.some(({ text }) =>
      text.includes("g1_delete_vector_set_v1")
    ),
    false
  );
  assert.equal(pools.authorizerReleasedWith, prepareError);
});

test("integrated DVI proof preserves operation and cleanup failures", async () => {
  const prepareError = new Error("synthetic plan failure");
  const cleanupError = new Error("cleanup response uncertain");
  const pools = proofPools({ planUsesVectorIndex: false, cleanupError });
  await assert.rejects(runProof(pools), (error) => {
    assert.equal(
      error.message,
      "ADMISSIBLE_VECTOR_OPERATION_AND_CLEANUP_FAILED"
    );
    assert.match(error.errors[0].message, /ADMISSIBLE_VECTOR_PLAN_INDEX_MISSING/);
    assert.equal(error.errors[1], cleanupError);
    return true;
  });
});

test("integrated DVI proof spec requires all seven exact exclusion classes", () => {
  assert.equal(
    __test.validateProofSpec(proofSpec()).expectedCandidateCount,
    10_000
  );
  const missing = proofSpec({
    exclusionCases: PROOF_EXCLUSIONS.slice(1).map((entry) => ({ ...entry }))
  });
  assert.throws(
    () => __test.validateProofSpec(missing),
    /ADMISSIBLE_VECTOR_PROOF_EXCLUSIONS/
  );
  const { runId: _runId, ...missingRun } = proofSpec();
  assert.throws(
    () => __test.validateProofSpec(missingRun),
    /ADMISSIBLE_VECTOR_PROOF_SPEC_SHAPE/
  );
  assert.throws(
    () => __test.validateProofSpec(proofSpec({ runId: "not-a-uuid" })),
    /runId must be a UUID/
  );
});
