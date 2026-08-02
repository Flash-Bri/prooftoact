import { createPublicKey, verify } from "node:crypto";
import { Client, Pool } from "pg";
import {
  connectionStringForDatabase,
  signedEvidenceEnvelopeFor
} from "./authority-store.js";
import {
  databaseClientMustBeDiscarded,
  runtimeDatabaseConfig
} from "./database-runtime.js";
import {
  committedDatabaseResult,
  databaseTimestampFromDriver
} from "./database-commit-result.js";

const APPEND_SQL = `
  SELECT tp_api.g1_append_verified_evidence_v2(
    $1::UUID, $2::UUID, $3::UUID, $4, $5, $6, $7, $8, $9, $10,
    $11, $12, $13, $14::TIMESTAMPTZ, $15::TIMESTAMPTZ,
    $16::TIMESTAMPTZ, $17, $18, $19
  ) AS evidence_id
`;

const RESOLVE_SQL = `
  SELECT *
  FROM tp_api.g1_resolve_verified_evidence_v1(
    $1::UUID, $2::UUID, $3, $4
  )
`;

function committedEvidence(row, evidence, observation) {
  if (
    !row ||
    row.evidence_id !== evidence.evidenceId ||
    (row.verification_request_digest !== undefined &&
      row.verification_request_digest !== evidence.verificationRequestDigest) ||
    (row.evidence_digest !== undefined &&
      row.evidence_digest !== evidence.evidenceDigest) ||
    (row.outcome !== undefined && row.outcome !== "evidence_verified")
  ) {
    throw new Error("SIGNED_INGEST_RECONCILIATION_MISMATCH");
  }
  return {
    outcome: "evidence_verified",
    evidenceId: evidence.evidenceId,
    verificationRequestDigest: evidence.verificationRequestDigest,
    signedPayloadDigest: evidence.signedPayloadDigest,
    signatureDigest: evidence.signatureDigest,
    evidenceDigest: evidence.evidenceDigest,
    commit: committedDatabaseResult({
      operation: "signed_ingest",
      operationDigest: evidence.verificationRequestDigest,
      observation,
      databaseNow: databaseTimestampFromDriver(row.database_now),
      outcome: "evidence_verified"
    })
  };
}

export class SignedEvidenceIngest {
  #connectionString;
  #ownsPool;
  #pool;
  #reconcile;

  constructor({
    connectionString,
    databaseName = "tideproof",
    pool,
    reconcile = null
  } = {}) {
    if (pool) {
      if (typeof pool.connect !== "function") {
        throw new TypeError("pool must expose connect()");
      }
      this.#pool = pool;
      this.#ownsPool = false;
      this.#reconcile = reconcile;
      return;
    }
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#connectionString = connectionStringForDatabase(
      connectionString,
      databaseName
    );
    this.#pool = new Pool(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: 4,
      idleTimeoutMillis: 10_000,
      applicationName: "tideproof-signed-ingest"
    }));
    this.#ownsPool = true;
    this.#reconcile = reconcile;
  }

  async close() {
    if (this.#ownsPool) {
      await this.#pool.end();
    }
  }

  async #resolve(evidence) {
    if (typeof this.#reconcile === "function") {
      return this.#reconcile(evidence);
    }
    if (!this.#connectionString) {
      throw new Error("SIGNED_INGEST_RECONCILIATION_UNAVAILABLE");
    }
    const client = new Client(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: 1,
      applicationName: "tideproof-signed-ingest-reconcile"
    }));
    try {
      await client.connect();
      return await client.query(RESOLVE_SQL, [
        evidence.tenantId,
        evidence.evidenceId,
        evidence.verificationRequestDigest,
        evidence.evidenceDigest
      ]);
    } finally {
      await client.end().catch(() => {});
    }
  }

  async appendVerified(input) {
    const evidence = signedEvidenceEnvelopeFor(input);
    const client = await this.#pool.connect();
    let releaseError;
    let discardClient = false;
    let commitDispatched = false;
    let clientReleased = false;
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const keyResult = await client.query(
        `
          SELECT *
          FROM tp_api.g1_get_verification_key_v1($1::UUID, $2)
        `,
        [evidence.tenantId, evidence.verificationKeyId]
      );
      if (keyResult.rowCount !== 1) {
        throw new Error("VERIFICATION_KEY_UNKNOWN");
      }
      const key = keyResult.rows[0];
      if (
        key.status !== "active" ||
        key.algorithm !== "ed25519" ||
        key.issuer !== evidence.issuer ||
        Date.parse(evidence.observedAt) < Date.parse(key.valid_from) ||
        Date.parse(evidence.observedAt) >= Date.parse(key.valid_until)
      ) {
        throw new Error("VERIFICATION_KEY_NOT_ADMISSIBLE");
      }
      const publicKey = createPublicKey({
        key: Buffer.from(key.public_key_spki_base64, "base64"),
        format: "der",
        type: "spki"
      });
      if (
        publicKey.asymmetricKeyType !== "ed25519" ||
        !verify(
          null,
          Buffer.from(evidence.signedPayload, "utf8"),
          publicKey,
          evidence.signatureBytes
        )
      ) {
        throw new Error("SIGNATURE_INVALID");
      }

      const result = await client.query(APPEND_SQL, [
        evidence.tenantId,
        evidence.evidenceId,
        evidence.incidentId,
        evidence.issuer,
        evidence.agencyScope,
        evidence.claimKey,
        evidence.claimValue,
        evidence.verificationKeyId,
        evidence.verifierVersion,
        evidence.verificationRequestDigest,
        evidence.signedPayloadDigest,
        evidence.signatureDigest,
        evidence.evidenceDigest,
        evidence.observedAt,
        evidence.validFrom,
        evidence.validUntil,
        evidence.conflictStatus,
        evidence.assertion,
        evidence.embedding
      ]);
      const clock = await client.query(
        "SELECT transaction_timestamp() AS database_now"
      );
      commitDispatched = true;
      await client.query("COMMIT");
      return committedEvidence(
        {
          ...result.rows[0],
          database_now: clock.rows[0].database_now
        },
        evidence,
        "direct_ack"
      );
    } catch (error) {
      releaseError = error;
      const commitDefinitivelyAborted =
        commitDispatched && error?.code === "40001";
      discardClient =
        databaseClientMustBeDiscarded(error) ||
        (commitDispatched && !commitDefinitivelyAborted);
      if (commitDispatched && !commitDefinitivelyAborted) {
        client.release(releaseError);
        clientReleased = true;
        const resolved = await this.#resolve(evidence);
        if (resolved?.rowCount === 1) {
          return committedEvidence(
            resolved.rows[0],
            evidence,
            "read_reconciled"
          );
        }
      }
      if (!discardClient) {
        try {
          await client.query("ROLLBACK");
        } catch (rollbackError) {
          releaseError = rollbackError;
          discardClient = true;
          throw new AggregateError(
            [error, rollbackError],
            "SIGNED_INGEST_ROLLBACK_FAILED"
          );
        }
      }
      throw error;
    } finally {
      if (!clientReleased) {
        client.release(discardClient ? releaseError : undefined);
      }
    }
  }
}
