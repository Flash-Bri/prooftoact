import { Client } from "pg";
import { performance } from "node:perf_hooks";
import { setTimeout as sleepTimer } from "node:timers/promises";
import { connectionStringForDatabase } from "./authority-store.js";
import {
  bootstrapDatabaseConfig,
  databaseClientMustBeDiscarded,
  runtimeDatabaseConfig
} from "./database-runtime.js";
import {
  collectClusterManagedGrantPosture,
  collectDatabaseSecurityPosture,
  quoteIdentifier,
  validateDatabaseSecurityPosture
} from "./database-security-posture.js";
import {
  normalizedRecoveryBundleFor,
  RECOVERY_PUBLISHER_VERSION,
  RECOVERY_SIGNATURE_ALGORITHM,
  RecoveryStore,
  RecoveryBundleMismatchError
} from "./recovery-store.js";

export const RECOVERY_PUBLISHER_ROLE = "tp_recovery_publisher_role";
export const RECOVERY_PUBLISHER_USER = "tp_recovery_publisher_user";
const RECOVERY_ROLE_BINDINGS = [
  [RECOVERY_PUBLISHER_ROLE, RECOVERY_PUBLISHER_USER]
];
const RECOVERY_ROLES = ["tp_recovery_owner", RECOVERY_PUBLISHER_ROLE];
const RECOVERY_USERS = [RECOVERY_PUBLISHER_USER];
const PRIMARY_SIBLING_ROLES = [
  "tp_owner",
  "tp_ingest_role",
  "tp_authorizer_role",
  "tp_gate2_authorizer_role",
  "tp_dispatch_role",
  "tp_recovery_audit_role",
  "tp_audit_role"
];
const PRIMARY_SIBLING_USERS = [
  "tp_ingest_user",
  "tp_authorizer_user",
  "tp_gate2_authorizer_user",
  "tp_dispatch_user",
  "tp_recovery_audit_user",
  "tp_audit_user"
];
const PRIMARY_SIBLING_BINDINGS = PRIMARY_SIBLING_ROLES
  .slice(1)
  .map((role, index) => [role, PRIMARY_SIBLING_USERS[index]]);
const CLUSTER_PRINCIPAL_DATABASES = Object.freeze(Object.fromEntries([
  ...PRIMARY_SIBLING_ROLES.map((principal) => [principal, "tideproof"]),
  ...PRIMARY_SIBLING_USERS.map((principal) => [principal, "tideproof"]),
  ...RECOVERY_ROLES.map((principal) => [
    principal,
    "tideproof_recovery"
  ]),
  ...RECOVERY_USERS.map((principal) => [
    principal,
    "tideproof_recovery"
  ])
]));
const RECOVERY_POSTURE_SPEC = Object.freeze({
  databaseName: "tideproof_recovery",
  managedSchemas: ["mcp_private", "mcp_public", "mcp_api"],
  managedPrefixes: ["tp_"],
  apiSchema: "mcp_api",
  ownerRoles: ["tp_recovery_owner"],
  roleGrantPolicies: Object.freeze({
    [RECOVERY_PUBLISHER_ROLE]: Object.freeze({
      functions: Object.freeze([
        "append_recovery_bundle_v2(UUID, UUID, STRING, INT8, INT8, UUID, TIMESTAMPTZ, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, JSONB, JSONB, JSONB, JSONB, TIMESTAMPTZ)"
      ])
    })
  }),
  roles: RECOVERY_ROLES,
  users: RECOVERY_USERS,
  bindings: RECOVERY_ROLE_BINDINGS,
  optionalRoles: PRIMARY_SIBLING_ROLES,
  optionalUsers: PRIMARY_SIBLING_USERS,
  optionalBindings: PRIMARY_SIBLING_BINDINGS
});

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

const RECOVERY_PUBLISH_MAX_ATTEMPTS = 10;
const RECOVERY_PUBLISH_RETRY_DEADLINE_MS = 10_000;
const RECOVERY_PUBLISH_MAX_BACKOFF_MS = 500;

function stablePublisherError(code, cause) {
  const error = new Error(code, cause ? { cause } : undefined);
  error.code = code;
  return error;
}

function retryBackoffMs(attempt) {
  return Math.min(
    RECOVERY_PUBLISH_MAX_BACKOFF_MS,
    25 * (2 ** attempt)
  );
}

function requireStrongPassword(value) {
  if (typeof value !== "string" || value.length < 24) {
    throw new Error(`${RECOVERY_PUBLISHER_USER} requires a strong password`);
  }
  return value;
}

async function collectValidatedRecoveryPosture(
  client,
  options,
  { attempts = 1, delayMs = 0 } = {}
) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const posture = await collectDatabaseSecurityPosture(client);
      const summary = validateDatabaseSecurityPosture(
        posture,
        RECOVERY_POSTURE_SPEC,
        options
      );
      return { posture, summary };
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) {
        await sleepTimer(delayMs);
      }
    }
  }
  throw lastError;
}

async function scrubRecoveryPrivileges(client) {
  for (const principal of [RECOVERY_PUBLISHER_ROLE, RECOVERY_PUBLISHER_USER]) {
    await client.query(
      `REVOKE ALL ON DATABASE tideproof_recovery FROM ${principal}`
    );
    await client.query(
      `REVOKE ALL ON SCHEMA mcp_private, mcp_public, mcp_api FROM ${principal}`
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public, mcp_api FROM ${principal}`
    );
    await client.query(
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcp_private, mcp_public, mcp_api FROM ${principal}`
    );
  }
}

async function lockInitialRecoveryPublicCapability(client, bootstrapOwner) {
  await client.query(
    "REVOKE ALL ON DATABASE tideproof_recovery FROM public"
  );
  await client.query("REVOKE CREATE ON SCHEMA public FROM public");
  await lockRecoveryPublicRoutineDefaults(client, [bootstrapOwner]);
}

async function lockRecoveryPublicRoutineDefaults(
  client,
  principals,
  schemas = []
) {
  const scopes = [
    "FOR ALL ROLES",
    ...principals.map((principal) =>
      `FOR ROLE ${quoteIdentifier(principal)}`
    )
  ];
  for (const scope of scopes) {
    await client.query(
      `ALTER DEFAULT PRIVILEGES ${scope} REVOKE EXECUTE ON FUNCTIONS FROM public`
    );
    for (const schema of schemas) {
      await client.query(
        `ALTER DEFAULT PRIVILEGES ${scope} IN SCHEMA ${quoteIdentifier(
          schema
        )} REVOKE EXECUTE ON FUNCTIONS FROM public`
      );
    }
  }
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
  const client = new Client(bootstrapDatabaseConfig({
    connectionString: connectionStringForDatabase(
      adminConnectionString,
      "tideproof_recovery"
    ),
    max: 1,
    applicationName: "tideproof-recovery-security"
  }));
  try {
    await client.connect();
    const preflight = await collectValidatedRecoveryPosture(
      client,
      {
        allowMissingPrincipals: true,
        allowMissingExpectedCapabilities: true,
        allowBootstrapDefaults: true
      }
    );
    const clusterPreflight = await collectClusterManagedGrantPosture({
      adminConnectionString,
      principalDatabases: CLUSTER_PRINCIPAL_DATABASES
    });
    const bootstrapOwner =
      preflight.posture.session[0].session_user_name;
    await lockInitialRecoveryPublicCapability(client, bootstrapOwner);
    await client.query("CREATE ROLE IF NOT EXISTS tp_recovery_owner");
    await client.query(
      `CREATE ROLE IF NOT EXISTS ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(`CREATE USER IF NOT EXISTS ${RECOVERY_PUBLISHER_USER}`);
    const existingOptionalPrincipals = preflight.posture.principals
      .map((row) => row.username)
      .filter((name) => [
        ...PRIMARY_SIBLING_ROLES,
        ...PRIMARY_SIBLING_USERS
      ].includes(name));
    await lockRecoveryPublicRoutineDefaults(client, [
      ...RECOVERY_ROLES,
      ...RECOVERY_USERS,
      ...existingOptionalPrincipals
    ]);
    await collectValidatedRecoveryPosture(
      client,
      {
        allowMissingPrincipals: false,
        allowMissingExpectedCapabilities: true,
        allowBootstrapDefaults: false
      }
    );
    const migrationStore = new RecoveryStore({
      connectionString: adminConnectionString,
      databaseName: "tideproof_recovery",
      maxConnections: 1
    });
    try {
      await migrationStore.migrate();
    } finally {
      await migrationStore.close().catch(() => {});
    }
    await lockRecoveryPublicRoutineDefaults(
      client,
      [bootstrapOwner, ...RECOVERY_ROLES, ...RECOVERY_USERS],
      ["mcp_private", "mcp_public", "mcp_api"]
    );
    await client.query(
      `REVOKE ${RECOVERY_PUBLISHER_ROLE} FROM ${RECOVERY_PUBLISHER_USER}`
    );
    await scrubRecoveryPrivileges(client);
    for (const role of RECOVERY_ROLES) {
      await client.query(`ALTER ROLE ${role} WITH NOLOGIN`);
      await client.query(`ALTER ROLE ${role} WITH PASSWORD NULL`);
    }
    await client.query(
      `ALTER USER ${RECOVERY_PUBLISHER_USER} WITH PASSWORD $1`,
      [password]
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
        IF session_user <> '${RECOVERY_PUBLISHER_USER}' THEN
          RAISE EXCEPTION 'recovery publisher database session required'
            USING ERRCODE = '42501';
        END IF;
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
      "REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public, mcp_api FROM public"
    );
    await client.query(
      "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcp_private, mcp_public, mcp_api FROM public"
    );
    await lockRecoveryPublicRoutineDefaults(
      client,
      [bootstrapOwner, ...RECOVERY_ROLES, ...RECOVERY_USERS],
      ["mcp_private", "mcp_public", "mcp_api"]
    );
    await scrubRecoveryPrivileges(client);
    await client.query(
      `GRANT CONNECT ON DATABASE tideproof_recovery TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `GRANT USAGE ON SCHEMA mcp_api TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `GRANT EXECUTE ON FUNCTION ${APPEND_SIGNATURE} TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public FROM ${RECOVERY_PUBLISHER_ROLE}`
    );
    for (const owner of [
      quoteIdentifier(bootstrapOwner),
      "tp_recovery_owner"
    ]) {
      for (const schema of ["mcp_private", "mcp_public", "mcp_api"]) {
        await client.query(
          `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON TABLES FROM public`
        );
        await client.query(
          `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE EXECUTE ON FUNCTIONS FROM public`
        );
      }
    }
    await client.query(
      `GRANT ${RECOVERY_PUBLISHER_ROLE} TO ${RECOVERY_PUBLISHER_USER}`
    );
    const attested = await collectValidatedRecoveryPosture(
      client,
      {
        allowMissingPrincipals: false,
        allowMissingExpectedCapabilities: false,
        allowBootstrapDefaults: false
      },
      { attempts: 30, delayMs: 2_000 }
    );
    const clusterAttested = await collectClusterManagedGrantPosture({
      adminConnectionString,
      principalDatabases: CLUSTER_PRINCIPAL_DATABASES
    });
    return {
      roles: attested.posture.principals.filter((row) =>
        [...RECOVERY_ROLES, ...RECOVERY_USERS].includes(row.username)
      ),
      preflightPostureDigest: preflight.summary.postureDigest,
      finalPostureDigest: attested.summary.postureDigest,
      clusterPreflightPostureDigest: clusterPreflight.postureDigest,
      clusterFinalPostureDigest: clusterAttested.postureDigest
    };
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
    const client = new Client(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: 1,
      applicationName: "tideproof-recovery-publisher"
    }));
    try {
      await client.connect();
      return await appendRecoveryBundleWithClient(client, bundle);
    } finally {
      await client.end().catch(() => {});
    }
  }
}

export async function appendRecoveryBundleWithClient(
  client,
  bundle,
  {
    now = () => performance.now(),
    sleep = (delayMs) => sleepTimer(delayMs),
    maxAttempts = RECOVERY_PUBLISH_MAX_ATTEMPTS,
    retryDeadlineMs = RECOVERY_PUBLISH_RETRY_DEADLINE_MS
  } = {}
) {
  if (typeof client?.query !== "function") {
    throw new TypeError("RECOVERY_PUBLISH_CLIENT_REQUIRED");
  }
  if (
    !Number.isSafeInteger(maxAttempts) ||
    maxAttempts < 1 ||
    maxAttempts > RECOVERY_PUBLISH_MAX_ATTEMPTS ||
    !Number.isSafeInteger(retryDeadlineMs) ||
    retryDeadlineMs < 1 ||
    retryDeadlineMs > RECOVERY_PUBLISH_RETRY_DEADLINE_MS
  ) {
    throw new RangeError("RECOVERY_PUBLISH_RETRY_POLICY_INVALID");
  }
  const startedAt = now();
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (now() - startedAt >= retryDeadlineMs) {
      throw stablePublisherError(
        "RECOVERY_PUBLISH_RETRY_DEADLINE_EXCEEDED"
      );
    }
    let transactionStarted = false;
    let committed = false;
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      const result = await client.query(
        APPEND_SQL,
        recoveryBundleValues(bundle)
      );
      await client.query("COMMIT");
      committed = true;
      transactionStarted = false;
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
      const unsafeConnection = databaseClientMustBeDiscarded(error);
      if (transactionStarted && !committed && !unsafeConnection) {
        try {
          await client.query("ROLLBACK");
        } catch (rollbackError) {
          throw stablePublisherError(
            "RECOVERY_PUBLISH_ROLLBACK_FAILED",
            new AggregateError([error, rollbackError])
          );
        }
      }
      if (error?.code !== "40001") {
        throw error;
      }
      if (attempt + 1 >= maxAttempts) {
        throw stablePublisherError(
          "RECOVERY_PUBLISH_RETRY_LIMIT_EXCEEDED",
          error
        );
      }
      const delayMs = retryBackoffMs(attempt);
      if (now() - startedAt + delayMs >= retryDeadlineMs) {
        throw stablePublisherError(
          "RECOVERY_PUBLISH_RETRY_DEADLINE_EXCEEDED",
          error
        );
      }
      await sleep(delayMs);
    }
  }
  throw stablePublisherError("RECOVERY_PUBLISH_RETRY_LIMIT_EXCEEDED");
}

export const __test = Object.freeze({
  APPEND_SQL,
  RECOVERY_PUBLISH_MAX_ATTEMPTS,
  RECOVERY_PUBLISH_RETRY_DEADLINE_MS,
  retryBackoffMs
});
