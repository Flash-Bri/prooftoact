import { createPublicKey, verify } from "node:crypto";
import { Pool } from "pg";
import {
  connectionStringForDatabase,
  signedEvidenceEnvelopeFor
} from "./authority-store.js";
import {
  databaseClientMustBeDiscarded,
  runtimeDatabaseConfig
} from "./database-runtime.js";

const APPEND_SQL = `
  SELECT tp_api.g1_append_verified_evidence_v2(
    $1::UUID, $2::UUID, $3::UUID, $4, $5, $6, $7, $8, $9, $10,
    $11, $12, $13, $14::TIMESTAMPTZ, $15::TIMESTAMPTZ,
    $16::TIMESTAMPTZ, $17, $18, $19
  ) AS evidence_id
`;

export class SignedEvidenceIngest {
  #pool;

  constructor({ connectionString, databaseName = "tideproof" } = {}) {
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#pool = new Pool(runtimeDatabaseConfig({
      connectionString: connectionStringForDatabase(
        connectionString,
        databaseName
      ),
      max: 4,
      idleTimeoutMillis: 10_000,
      applicationName: "tideproof-signed-ingest"
    }));
  }

  async close() {
    await this.#pool.end();
  }

  async appendVerified(input) {
    const evidence = signedEvidenceEnvelopeFor(input);
    const client = await this.#pool.connect();
    let releaseError;
    let discardClient = false;
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
      await client.query("COMMIT");
      return {
        outcome: "evidence_verified",
        evidenceId: result.rows[0].evidence_id,
        verificationRequestDigest: evidence.verificationRequestDigest,
        signedPayloadDigest: evidence.signedPayloadDigest,
        signatureDigest: evidence.signatureDigest,
        evidenceDigest: evidence.evidenceDigest
      };
    } catch (error) {
      releaseError = error;
      discardClient = databaseClientMustBeDiscarded(error);
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
      client.release(discardClient ? releaseError : undefined);
    }
  }
}
