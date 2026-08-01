import { Pool } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import { runtimeDatabaseConfig } from "./database-runtime.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const POLICY_VERSION = "g1-admissibility-v2";

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

function integerFromRow(value, name, maximum = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error(`ADMISSIBLE_VECTOR_${name.toUpperCase()}_INVALID`);
  }
  return parsed;
}

function rankedResult(row) {
  const distance = Number(row?.distance);
  if (
    !UUID.test(row?.evidence_id ?? "") ||
    !SHA256.test(row?.evidence_digest ?? "") ||
    typeof row?.assertion !== "string" ||
    Buffer.byteLength(row.assertion, "utf8") < 1 ||
    Buffer.byteLength(row.assertion, "utf8") > 4096 ||
    !Number.isFinite(distance) ||
    distance < 0 ||
    distance > 2
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
  const admittedAtMs = Date.parse(row.admitted_at);
  const expiresAtMs = Date.parse(row.expires_at);
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
  POLICY_VERSION,
  preparedSnapshot,
  validatedRankedResults
});
