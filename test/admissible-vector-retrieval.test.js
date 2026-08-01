import assert from "node:assert/strict";
import test from "node:test";

import {
  AdmissibleVectorRetriever,
  admissibleVectorPoolConfig,
  __test
} from "../src/cloud/admissible-vector-retrieval.js";
import { safeAdmissibleVectorFailureCode } from "../scripts/gate1-admissible-vector.js";

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
  preparedRow,
  rankedRows
} = {}) {
  const calls = [];
  let releasedWith;
  const client = {
    async query(text, values) {
      calls.push({ text, values });
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
    ),
    ["prepare", "rank", "delete"]
  );
  assert.equal(result.candidateCount, 2);
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].distance, 0.125);
  assert.equal(result.approximateNearestNeighbor, true);
  assert.equal(result.authorizationRecheckRequired, true);
  assert.equal(pool.releasedWith, undefined);
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
  const config = admissibleVectorPoolConfig(
    "postgresql://u:p@example.invalid/defaultdb?sslmode=verify-full",
    {}
  );
  assert.equal(new URL(config.connectionString).pathname, "/tideproof");
  assert.equal(config.statement_timeout, 4_000);
  assert.equal(config.query_timeout, 4_500);
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
});
