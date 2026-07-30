import { Client } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import {
  normalizedRecoveryBundleFor,
  RECOVERY_PUBLISHER_VERSION,
  RECOVERY_SIGNATURE_ALGORITHM,
  RecoveryBundleMismatchError
} from "./recovery-store.js";

export const RECOVERY_PUBLISHER_ROLE = "tp_recovery_publisher_role";
export const RECOVERY_PUBLISHER_USER = "tp_recovery_publisher_user";

const APPEND_SIGNATURE =
  "mcp_api.append_recovery_bundle_v2(UUID, UUID, STRING, INT8, INT8, UUID, TIMESTAMPTZ, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, JSONB, JSONB, JSONB, JSONB, TIMESTAMPTZ)";

const APPEND_SQL = `
  SELECT *
  FROM mcp_api.append_recovery_bundle_v2(
    $1::UUID, $2::UUID, $3, $4::INT8, $5::INT8, $6::UUID,
    $7::TIMESTAMPTZ, $8, $9, $10, $11, $12, $13, $14, $15,
    $16::JSONB, $17::JSONB, $18::JSONB, $19::JSONB,
    $20::TIMESTAMPTZ
  )
`;

function requireStrongPassword(value) {
  if (typeof value !== "string" || value.length < 24) {
    throw new Error(`${RECOVERY_PUBLISHER_USER} requires a strong password`);
  }
  return value;
}

export function connectionStringForRecoveryUser(
  adminConnectionString,
  user,
  password
) {
  const url = new URL(
    connectionStringForDatabase(adminConnectionString, "tideproof_recovery")
  );
  url.username = user;
  url.password = password;
  return url.toString();
}

export function recoveryBundleValues(bundle) {
  return [
    bundle.tenantId,
    bundle.recoverySessionId,
    bundle.subjectBindingHash,
    bundle.schemaVersion,
    bundle.snapshotVersion,
    bundle.sourceClusterId,
    bundle.sourceCommitTs,
    bundle.sourceDigest,
    bundle.bundleDigest,
    bundle.policyVersion,
    bundle.publisherKeyId,
    bundle.publisherVersion,
    bundle.signatureAlgorithm,
    bundle.sourceSignatureBase64,
    bundle.signatureDigest,
    JSON.stringify(bundle.checkpointSummary),
    JSON.stringify(bundle.evidenceSummary),
    JSON.stringify(bundle.conflictSummary),
    JSON.stringify(bundle.receiptSummary),
    bundle.expiresAt
  ];
}

export async function bootstrapRecoverySecurity({
  adminConnectionString,
  publisherPassword
}) {
  const password = requireStrongPassword(publisherPassword);
  const client = new Client({
    connectionString: connectionStringForDatabase(
      adminConnectionString,
      "tideproof_recovery"
    )
  });
  try {
    await client.connect();
    await client.query("CREATE ROLE IF NOT EXISTS tp_recovery_owner");
    await client.query(
      `CREATE ROLE IF NOT EXISTS ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(`CREATE USER IF NOT EXISTS ${RECOVERY_PUBLISHER_USER}`);
    await client.query(
      `ALTER USER ${RECOVERY_PUBLISHER_USER} WITH PASSWORD $1`,
      [password]
    );
    await client.query(
      `GRANT ${RECOVERY_PUBLISHER_ROLE} TO ${RECOVERY_PUBLISHER_USER}`
    );
    await client.query(
      "GRANT ALL ON DATABASE tideproof_recovery TO tp_recovery_owner"
    );
    await client.query(
      "GRANT ALL ON SCHEMA mcp_private, mcp_public, mcp_api TO tp_recovery_owner"
    );
    await client.query(
      "GRANT ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public TO tp_recovery_owner"
    );

    await client.query(`
      CREATE OR REPLACE FUNCTION mcp_api.append_recovery_bundle_v2(
        p_tenant_id UUID,
        p_recovery_session_id UUID,
        p_subject_binding_hash STRING,
        p_schema_version INT8,
        p_snapshot_version INT8,
        p_source_cluster_id UUID,
        p_source_commit_ts TIMESTAMPTZ,
        p_source_digest STRING,
        p_bundle_digest STRING,
        p_policy_version STRING,
        p_publisher_key_id STRING,
        p_publisher_version STRING,
        p_signature_algorithm STRING,
        p_source_signature_base64 STRING,
        p_signature_digest STRING,
        p_checkpoint_summary JSONB,
        p_evidence_summary JSONB,
        p_conflict_summary JSONB,
        p_receipt_summary JSONB,
        p_expires_at TIMESTAMPTZ
      )
      RETURNS TABLE(bundle_digest STRING, outcome STRING)
      LANGUAGE PLpgSQL
      SECURITY DEFINER
      AS $$
      DECLARE
        v_existing_count INT8;
        v_existing_digest STRING;
      BEGIN
        IF p_schema_version <> 2
          OR p_publisher_version <> '${RECOVERY_PUBLISHER_VERSION}'
          OR p_signature_algorithm <> '${RECOVERY_SIGNATURE_ALGORITHM}'
          OR length(p_subject_binding_hash) <> 64
          OR length(p_source_digest) <> 64
          OR length(p_bundle_digest) <> 64
          OR length(p_signature_digest) <> 64
          OR p_snapshot_version < 1
          OR p_expires_at <= p_source_commit_ts
          OR p_expires_at > p_source_commit_ts + INTERVAL '24 hours'
        THEN
          RAISE EXCEPTION 'invalid signed recovery bundle'
            USING ERRCODE = '22023';
        END IF;

        SELECT count(*)::INT8, min(bundle.bundle_digest)
        INTO v_existing_count, v_existing_digest
        FROM mcp_private.recovery_bundles_v2 AS bundle
        WHERE (
          bundle.tenant_id = p_tenant_id
          AND bundle.recovery_session_id = p_recovery_session_id
          AND bundle.snapshot_version = p_snapshot_version
        )
        OR bundle.bundle_digest = p_bundle_digest;

        IF v_existing_count > 1
          OR (v_existing_count = 1 AND v_existing_digest <> p_bundle_digest)
        THEN
          RAISE EXCEPTION 'recovery bundle idempotency mismatch'
            USING ERRCODE = '23505';
        END IF;

        IF v_existing_count = 1 THEN
          RETURN QUERY SELECT p_bundle_digest, 'bundle_replay'::STRING;
          RETURN;
        END IF;

        INSERT INTO mcp_private.recovery_bundles_v2 (
          tenant_id,
          recovery_session_id,
          subject_binding_hash,
          schema_version,
          snapshot_version,
          source_cluster_id,
          source_commit_ts,
          source_digest,
          bundle_digest,
          policy_version,
          publisher_key_id,
          publisher_version,
          signature_algorithm,
          source_signature_base64,
          signature_digest,
          checkpoint_summary,
          evidence_summary,
          conflict_summary,
          receipt_summary,
          authority_transferred,
          requires_fresh_authorization,
          expires_at
        )
        VALUES (
          p_tenant_id,
          p_recovery_session_id,
          p_subject_binding_hash,
          p_schema_version,
          p_snapshot_version,
          p_source_cluster_id,
          p_source_commit_ts,
          p_source_digest,
          p_bundle_digest,
          p_policy_version,
          p_publisher_key_id,
          p_publisher_version,
          p_signature_algorithm,
          p_source_signature_base64,
          p_signature_digest,
          p_checkpoint_summary,
          p_evidence_summary,
          p_conflict_summary,
          p_receipt_summary,
          false,
          true,
          p_expires_at
        );

        RETURN QUERY SELECT p_bundle_digest, 'bundle_appended'::STRING;
      END
      $$
    `);

    for (const object of [
      "mcp_private.recovery_bundles_v2"
    ]) {
      await client.query(`ALTER TABLE ${object} OWNER TO tp_recovery_owner`);
    }
    await client.query(
      "ALTER VIEW mcp_public.recovery_bundle_v2 OWNER TO tp_recovery_owner"
    );
    await client.query(
      `ALTER FUNCTION ${APPEND_SIGNATURE} OWNER TO tp_recovery_owner`
    );

    await client.query("REVOKE ALL ON DATABASE tideproof_recovery FROM public");
    await client.query("REVOKE CREATE ON SCHEMA public FROM public");
    await client.query(
      "REVOKE ALL ON SCHEMA mcp_private, mcp_public, mcp_api FROM public"
    );
    await client.query(
      "REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public FROM public"
    );
    await client.query(`REVOKE ALL ON FUNCTION ${APPEND_SIGNATURE} FROM public`);
    await client.query(
      `GRANT CONNECT ON DATABASE tideproof_recovery TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `GRANT USAGE ON SCHEMA mcp_api, mcp_private TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `GRANT EXECUTE ON FUNCTION ${APPEND_SIGNATURE} TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public FROM ${RECOVERY_PUBLISHER_ROLE}`
    );
    for (const owner of ["bc", "tp_recovery_owner"]) {
      for (const schema of ["mcp_private", "mcp_public", "mcp_api"]) {
        await client.query(
          `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON TABLES FROM public`
        );
        await client.query(
          `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE EXECUTE ON FUNCTIONS FROM public`
        );
      }
    }

    const roles = await client.query(`
      SELECT username, options
      FROM [SHOW USERS]
      WHERE username IN (
        'tp_recovery_owner',
        '${RECOVERY_PUBLISHER_ROLE}',
        '${RECOVERY_PUBLISHER_USER}'
      )
      ORDER BY username
    `);
    return { roles: roles.rows };
  } finally {
    await client.end().catch(() => {});
  }
}

export class RecoveryPublisher {
  #connectionString;

  constructor({ connectionString } = {}) {
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#connectionString = connectionStringForDatabase(
      connectionString,
      "tideproof_recovery"
    );
  }

  async appendSignedBundle(input) {
    const bundle = normalizedRecoveryBundleFor(input);
    const client = new Client({ connectionString: this.#connectionString });
    try {
      await client.connect();
      for (let attempt = 0; attempt < 10; attempt += 1) {
        try {
          await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
          const result = await client.query(
            APPEND_SQL,
            recoveryBundleValues(bundle)
          );
          await client.query("COMMIT");
          if (
            result.rowCount !== 1 ||
            result.rows[0].bundle_digest !== bundle.bundleDigest
          ) {
            throw new RecoveryBundleMismatchError();
          }
          return {
            outcome: result.rows[0].outcome,
            bundleDigest: bundle.bundleDigest
          };
        } catch (error) {
          await client.query("ROLLBACK").catch(() => {});
          if (error.code === "40001" && attempt < 9) {
            continue;
          }
          throw error;
        }
      }
      throw new Error("recovery publisher retry loop exhausted");
    } finally {
      await client.end().catch(() => {});
    }
  }
}
