import { createHash, randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import { setTimeout as sleepTimer } from "node:timers/promises";
import { Client } from "pg";
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
import {
  committedDatabaseResult,
  databaseTimestampFromDriver
} from "./database-commit-result.js";

export const RECOVERY_PUBLISHER_ROLE = "tp_recovery_publisher_role";
export const RECOVERY_PUBLISHER_USER = "tp_recovery_publisher_user";
export const RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION =
  "REPAIR_TP_RECOVERY_PUBLISHER_PRIVATE_SCHEMA_USAGE_V1";
export const RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CLUSTER_ID =
  "24f93c44-fa61-467c-bd3f-a1153618c309";
export const RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL =
  `GRANT USAGE ON SCHEMA mcp_private TO ${RECOVERY_PUBLISHER_ROLE}`;
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
const RECOVERY_PUBLISHER_FUNCTIONS = Object.freeze([
  "append_recovery_bundle_v2(UUID, UUID, STRING, INT8, INT8, UUID, TIMESTAMPTZ, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, JSONB, JSONB, JSONB, JSONB, TIMESTAMPTZ)",
  "resolve_recovery_bundle_v1(UUID, UUID, INT8, STRING)"
]);

function recoveryPostureSpec(publisherSchemas) {
  return Object.freeze({
    databaseName: "tideproof_recovery",
    managedSchemas: ["mcp_private", "mcp_public", "mcp_api"],
    managedPrefixes: ["tp_"],
    apiSchema: "mcp_api",
    ownerRoles: ["tp_recovery_owner"],
    roleGrantPolicies: Object.freeze({
      [RECOVERY_PUBLISHER_ROLE]: Object.freeze({
        schemas: Object.freeze([...publisherSchemas]),
        functions: RECOVERY_PUBLISHER_FUNCTIONS
      })
    }),
    roles: RECOVERY_ROLES,
    users: RECOVERY_USERS,
    bindings: RECOVERY_ROLE_BINDINGS,
    optionalRoles: PRIMARY_SIBLING_ROLES,
    optionalUsers: PRIMARY_SIBLING_USERS,
    optionalBindings: PRIMARY_SIBLING_BINDINGS
  });
}

const LEGACY_RECOVERY_POSTURE_SPEC = recoveryPostureSpec(["mcp_api"]);
export const RECOVERY_POSTURE_SPEC = recoveryPostureSpec([
  "mcp_api",
  "mcp_private"
]);

const APPEND_SIGNATURE =
  "mcp_api.append_recovery_bundle_v2(UUID, UUID, STRING, INT8, INT8, UUID, TIMESTAMPTZ, STRING, STRING, STRING, STRING, STRING, STRING, STRING, STRING, JSONB, JSONB, JSONB, JSONB, TIMESTAMPTZ)";
const RESOLVE_SIGNATURE =
  "mcp_api.resolve_recovery_bundle_v1(UUID, UUID, INT8, STRING)";
const RECOVERY_FUNCTION_DEFINITION_QUERIES = Object.freeze([
  Object.freeze({
    id: "append_recovery_bundle_v2",
    query: `SHOW CREATE FUNCTION ${APPEND_SIGNATURE}`,
    requiredFragments: Object.freeze([
      "security definer",
      "session_user",
      RECOVERY_PUBLISHER_USER,
      "mcp_private.recovery_bundles_v2",
      "insert into"
    ])
  }),
  Object.freeze({
    id: "resolve_recovery_bundle_v1",
    query: `SHOW CREATE FUNCTION ${RESOLVE_SIGNATURE}`,
    requiredFragments: Object.freeze([
      "security definer",
      "session_user",
      RECOVERY_PUBLISHER_USER,
      "mcp_private.recovery_bundles_v2"
    ])
  })
]);

const APPEND_SQL = `
  SELECT *
  FROM mcp_api.append_recovery_bundle_v2(
    $1::UUID, $2::UUID, $3, $4::INT8, $5::INT8, $6::UUID,
    $7::TIMESTAMPTZ, $8, $9, $10, $11, $12, $13, $14, $15,
    $16::JSONB, $17::JSONB, $18::JSONB, $19::JSONB,
    $20::TIMESTAMPTZ
  )
`;

const RESOLVE_SQL = `
  SELECT *
  FROM mcp_api.resolve_recovery_bundle_v1(
    $1::UUID, $2::UUID, $3::INT8, $4
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

function committedBundleResult(row, bundle, observation) {
  if (
    !row ||
    row.bundle_digest !== bundle.bundleDigest ||
    !["bundle_appended", "bundle_replay", "bundle_present"].includes(
      row.outcome
    )
  ) {
    throw new RecoveryBundleMismatchError();
  }
  return {
    outcome: row.outcome,
    bundleDigest: bundle.bundleDigest,
    commit: committedDatabaseResult({
      operation: "recovery_publication",
      operationDigest: bundle.bundleDigest,
      observation,
      databaseNow: databaseTimestampFromDriver(row.database_now),
      outcome: "bundle_present",
      authorityCurrent: null,
      requiresFreshAuthorization: true
    })
  };
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
      const summary = validateRecoverySecurityPosture(posture, options);
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

export function validateRecoverySecurityPosture(posture, options = {}) {
  return validateDatabaseSecurityPosture(
    posture,
    RECOVERY_POSTURE_SPEC,
    options
  );
}

function validateLegacyRecoverySecurityPosture(posture, options = {}) {
  return validateDatabaseSecurityPosture(
    posture,
    LEGACY_RECOVERY_POSTURE_SPEC,
    options
  );
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requiredSha256(value, code) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw stablePublisherError(code);
  }
  return value;
}

function requiredGitObjectId(value, code) {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
    throw stablePublisherError(code);
  }
  return value;
}

function validateSchemaRepairBinding({
  expectedRecoveryClusterId,
  expectedPreflightPostureDigest,
  expectedClusterPreflightPostureDigest,
  sourceCommit,
  sourceTree
}) {
  if (
    expectedRecoveryClusterId !==
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CLUSTER_ID
  ) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_CLUSTER_ID_INVALID");
  }
  return Object.freeze({
    clusterId: expectedRecoveryClusterId,
    expectedPreflightPostureDigest: requiredSha256(
      expectedPreflightPostureDigest,
      "RECOVERY_SCHEMA_REPAIR_PREFLIGHT_DIGEST_INVALID"
    ),
    expectedClusterPreflightPostureDigest: requiredSha256(
      expectedClusterPreflightPostureDigest,
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST_INVALID"
    ),
    sourceCommit: requiredGitObjectId(
      sourceCommit,
      "RECOVERY_SCHEMA_REPAIR_SOURCE_COMMIT_INVALID"
    ),
    sourceTree: requiredGitObjectId(
      sourceTree,
      "RECOVERY_SCHEMA_REPAIR_SOURCE_TREE_INVALID"
    )
  });
}

function classifyRecoverySchemaRepairPosture(posture) {
  let finalError;
  try {
    return Object.freeze({
      state: "PRESENT",
      summary: validateRecoverySecurityPosture(posture)
    });
  } catch (error) {
    finalError = error;
  }
  try {
    return Object.freeze({
      state: "ABSENT",
      summary: validateLegacyRecoverySecurityPosture(posture)
    });
  } catch (legacyError) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_POSTURE_UNRESOLVED",
      new AggregateError([finalError, legacyError])
    );
  }
}

function normalizedFunctionDefinition(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > 262_144 ||
    value.includes("\0")
  ) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_INVALID"
    );
  }
  return value.replaceAll("\r\n", "\n");
}

export async function collectRecoveryPublisherFunctionDefinitions(client) {
  if (typeof client?.query !== "function") {
    throw new TypeError("RECOVERY_SCHEMA_REPAIR_ADMIN_CLIENT_REQUIRED");
  }
  const definitions = [];
  for (const contract of RECOVERY_FUNCTION_DEFINITION_QUERIES) {
    const result = await client.query(contract.query);
    if (!Array.isArray(result?.rows) || result.rows.length !== 1) {
      throw stablePublisherError(
        "RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_INVALID"
      );
    }
    const definition = normalizedFunctionDefinition(
      result.rows[0]?.create_statement ?? result.rows[0]?.createStatement
    );
    const searchable = definition.toLowerCase().replaceAll('"', "");
    if (
      !searchable.includes(`function mcp_api.${contract.id}`) ||
      contract.requiredFragments.some(
        (fragment) => !searchable.includes(fragment.toLowerCase())
      ) ||
      (contract.id === "resolve_recovery_bundle_v1" &&
        searchable.includes("insert into"))
    ) {
      throw stablePublisherError(
        "RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_INVALID"
      );
    }
    definitions.push(Object.freeze({
      id: contract.id,
      createStatementSha256: sha256(definition),
      byteLength: Buffer.byteLength(definition, "utf8")
    }));
  }
  return Object.freeze({
    schemaVersion: "tideproof.recovery-function-definition-binding.v1",
    definitions: Object.freeze(definitions),
    bindingSha256: sha256(JSON.stringify(definitions))
  });
}

function recoveryConnectionTarget(
  connectionString,
  expectedHostname,
  { publisher = false } = {}
) {
  if (
    typeof connectionString !== "string" ||
    typeof expectedHostname !== "string" ||
    expectedHostname.trim() === ""
  ) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_TARGET_INVALID");
  }
  let url;
  try {
    url = new URL(connectionString);
  } catch (error) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_TARGET_INVALID", error);
  }
  let databaseName;
  let username;
  try {
    databaseName = decodeURIComponent(url.pathname.replace(/^\//u, ""));
    username = decodeURIComponent(url.username);
  } catch (error) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_TARGET_INVALID", error);
  }
  const query = [...url.searchParams.entries()];
  if (
    !["postgres:", "postgresql:"].includes(url.protocol) ||
    url.hostname.toLowerCase() !== expectedHostname.trim().toLowerCase() ||
    url.port !== "26257" ||
    databaseName !== "tideproof_recovery" ||
    url.hash !== "" ||
    query.length !== 1 ||
    query[0][0] !== "sslmode" ||
    query[0][1] !== "verify-full" ||
    username === "" ||
    (publisher && username !== RECOVERY_PUBLISHER_USER) ||
    (!publisher && [RECOVERY_PUBLISHER_ROLE, RECOVERY_PUBLISHER_USER]
      .includes(username))
  ) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_TARGET_INVALID");
  }
  return {
    databaseName,
    hostname: url.hostname.toLowerCase(),
    port: url.port,
    username
  };
}

function publisherProbeBundle(databaseNow) {
  const sourceCommitTime = new Date(databaseNow);
  if (!Number.isFinite(sourceCommitTime.getTime())) {
    throw stablePublisherError("RECOVERY_PUBLISHER_PROBE_TIME_INVALID");
  }
  const probeId = randomUUID();
  const probeDigest = (label) => sha256(`${label}\0${probeId}`);
  return {
    tenantId: randomUUID(),
    recoverySessionId: randomUUID(),
    subjectBindingHash: probeDigest("subject"),
    schemaVersion: 2,
    snapshotVersion: sourceCommitTime.getTime(),
    sourceClusterId: randomUUID(),
    sourceCommitTs: sourceCommitTime.toISOString(),
    sourceDigest: probeDigest("source"),
    bundleDigest: probeDigest("bundle"),
    policyVersion: "recovery-private-schema-repair-probe-v1",
    publisherKeyId: "rollback-only-probe",
    publisherVersion: RECOVERY_PUBLISHER_VERSION,
    signatureAlgorithm: RECOVERY_SIGNATURE_ALGORITHM,
    sourceSignatureBase64: Buffer.alloc(64, 1).toString("base64"),
    signatureDigest: probeDigest("signature"),
    checkpointSummary: { probe: true },
    evidenceSummary: { probe: true },
    conflictSummary: { probe: true },
    receiptSummary: { probe: true },
    expiresAt: new Date(sourceCommitTime.getTime() + 5 * 60_000).toISOString()
  };
}

async function expectDirectRecoveryTablePrivilegeDenied(client, operation, sql) {
  await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  let queryError = null;
  try {
    await client.query(sql);
  } catch (error) {
    queryError = error;
  }
  try {
    await client.query("ROLLBACK");
  } catch (rollbackError) {
    throw stablePublisherError(
      "RECOVERY_PUBLISHER_PROBE_ROLLBACK_FAILED",
      queryError
        ? new AggregateError([queryError, rollbackError])
        : rollbackError
    );
  }
  if (queryError?.code !== "42501") {
    throw stablePublisherError(
      `RECOVERY_PUBLISHER_DIRECT_${operation}_NOT_DENIED`,
      queryError
    );
  }
  return { denied: true, sqlstate: queryError.code };
}

export async function collectRecoveryPublisherCapabilityPosture(client) {
  if (typeof client?.query !== "function") {
    throw new TypeError("RECOVERY_PUBLISHER_PROBE_CLIENT_REQUIRED");
  }
  const sessionResult = await client.query(`
    SELECT
      current_database() AS database_name,
      current_user AS current_user_name,
      session_user AS session_user_name,
      version() AS database_version,
      statement_timestamp() AS database_now
  `);
  const session = sessionResult.rows?.[0];
  if (
    sessionResult.rowCount !== 1 ||
    session?.database_name !== "tideproof_recovery" ||
    session?.current_user_name !== RECOVERY_PUBLISHER_USER ||
    session?.session_user_name !== RECOVERY_PUBLISHER_USER ||
    !/\bCockroachDB(?: CCL)? v26\.2(?:\.\d+)?\b/u.test(
      session?.database_version ?? ""
    )
  ) {
    throw stablePublisherError("RECOVERY_PUBLISHER_PROBE_SESSION_INVALID");
  }
  const databaseNow = databaseTimestampFromDriver(session.database_now);
  const bundle = publisherProbeBundle(databaseNow);
  let transactionStarted = false;
  let appendResult;
  let resolveResult;
  try {
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    transactionStarted = true;
    appendResult = await client.query(
      APPEND_SQL,
      recoveryBundleValues(bundle)
    );
    resolveResult = await client.query(RESOLVE_SQL, [
      bundle.tenantId,
      bundle.recoverySessionId,
      bundle.snapshotVersion,
      bundle.bundleDigest
    ]);
    await client.query("ROLLBACK");
    transactionStarted = false;
  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query("ROLLBACK");
      } catch (rollbackError) {
        throw stablePublisherError(
          "RECOVERY_PUBLISHER_PROBE_ROLLBACK_FAILED",
          new AggregateError([error, rollbackError])
        );
      }
    }
    throw stablePublisherError(
      "RECOVERY_PUBLISHER_FUNCTION_PROBE_FAILED",
      error
    );
  }
  if (
    appendResult?.rowCount !== 1 ||
    appendResult.rows?.[0]?.bundle_digest !== bundle.bundleDigest ||
    appendResult.rows?.[0]?.outcome !== "bundle_appended" ||
    resolveResult?.rowCount !== 1 ||
    resolveResult.rows?.[0]?.bundle_digest !== bundle.bundleDigest ||
    resolveResult.rows?.[0]?.outcome !== "bundle_present"
  ) {
    throw stablePublisherError("RECOVERY_PUBLISHER_FUNCTION_PROBE_INVALID");
  }
  const rollbackReadback = await client.query(RESOLVE_SQL, [
    bundle.tenantId,
    bundle.recoverySessionId,
    bundle.snapshotVersion,
    bundle.bundleDigest
  ]);
  if (rollbackReadback?.rowCount !== 0) {
    throw stablePublisherError("RECOVERY_PUBLISHER_PROBE_ROLLBACK_UNPROVEN");
  }
  const directTableDenials = {};
  for (const [operation, sql] of [
    ["SELECT", "SELECT 1 FROM mcp_private.recovery_bundles_v2 LIMIT 0"],
    ["INSERT", "INSERT INTO mcp_private.recovery_bundles_v2 DEFAULT VALUES"],
    ["UPDATE", "UPDATE mcp_private.recovery_bundles_v2 SET policy_version = policy_version WHERE false"],
    ["DELETE", "DELETE FROM mcp_private.recovery_bundles_v2 WHERE false"]
  ]) {
    directTableDenials[operation.toLowerCase()] =
      await expectDirectRecoveryTablePrivilegeDenied(client, operation, sql);
  }
  return {
    schemaVersion: "tideproof.recovery-publisher-capability-posture.v1",
    databaseName: session.database_name,
    principal: session.session_user_name,
    databaseVersionSha256: sha256(session.database_version),
    databaseObservedAt: databaseNow,
    functionProbe: {
      appendOutcome: appendResult.rows[0].outcome,
      resolveOutcome: resolveResult.rows[0].outcome,
      rollbackVerified: true,
      probeBundleDigest: bundle.bundleDigest
    },
    directTableDenials
  };
}

export function recoveryPublisherPrivateSchemaRepairPlan() {
  return Object.freeze({
    schemaVersion: "tideproof.recovery-publisher-private-schema-repair.v2",
    databaseName: "tideproof_recovery",
    clusterId: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CLUSTER_ID,
    principal: RECOVERY_PUBLISHER_ROLE,
    statement: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL,
    statementSha256: sha256(RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL),
    expectedAddedCapability: "SCHEMA:mcp_private:USAGE",
    forbiddenDirectTablePrivileges: Object.freeze([
      "SELECT",
      "INSERT",
      "UPDATE",
      "DELETE"
    ]),
    confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
    mutationCount: 1
  });
}

function schemaRepairTargetReceipt(
  adminTarget,
  publisherTarget,
  binding
) {
  return Object.freeze({
    clusterId: binding.clusterId,
    clusterIdSha256: sha256(binding.clusterId),
    databaseName: adminTarget.databaseName,
    hostnameSha256: sha256(adminTarget.hostname),
    adminPrincipalSha256: sha256(adminTarget.username),
    publisherPrincipal: publisherTarget.username
  });
}

function schemaRepairSourceReceipt(binding) {
  return Object.freeze({
    commit: binding.sourceCommit,
    tree: binding.sourceTree
  });
}

function schemaRepairReconciliationError(code, reconciliation, cause) {
  const error = stablePublisherError(code, cause);
  error.reconciliation = reconciliation;
  return error;
}

export async function verifyRecoveryPublisherPrivateSchemaUsage({
  adminConnectionString,
  publisherConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryClusterId,
  expectedPreflightPostureDigest,
  expectedClusterPreflightPostureDigest,
  sourceCommit,
  sourceTree,
  observation = "read_only_verification",
  createAdminClient = () => new Client(bootstrapDatabaseConfig({
    connectionString: adminConnectionString,
    max: 1,
    applicationName: "tideproof-recovery-schema-repair-reconciler"
  })),
  createPublisherClient = () => new Client(runtimeDatabaseConfig({
    connectionString: publisherConnectionString,
    max: 1,
    applicationName: "tideproof-recovery-schema-repair-verifier"
  })),
  collectClusterPosture = (options) =>
    collectClusterManagedGrantPosture(options)
}) {
  if (![
    "read_only_verification",
    "read_reconciled",
    "direct_ack"
  ].includes(observation)) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_OBSERVATION_INVALID"
    );
  }
  const binding = validateSchemaRepairBinding({
    expectedRecoveryClusterId,
    expectedPreflightPostureDigest,
    expectedClusterPreflightPostureDigest,
    sourceCommit,
    sourceTree
  });
  const adminTarget = recoveryConnectionTarget(
    adminConnectionString,
    expectedRecoveryHostname
  );
  const publisherTarget = recoveryConnectionTarget(
    publisherConnectionString,
    expectedRecoveryHostname,
    { publisher: true }
  );
  if (adminTarget.hostname !== publisherTarget.hostname) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_TARGET_INVALID");
  }

  let classified;
  let clusterObserved;
  let functionDefinitions;
  const admin = createAdminClient();
  try {
    await admin.connect();
    classified = classifyRecoverySchemaRepairPosture(
      await collectDatabaseSecurityPosture(admin)
    );
    functionDefinitions =
      await collectRecoveryPublisherFunctionDefinitions(admin);
    clusterObserved = await collectClusterPosture({
      adminConnectionString,
      principalDatabases: CLUSTER_PRINCIPAL_DATABASES
    });
    requiredSha256(
      clusterObserved?.postureDigest,
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_INVALID"
    );
  } catch (error) {
    if (error?.code === "RECOVERY_SCHEMA_REPAIR_POSTURE_UNRESOLVED") {
      throw error;
    }
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_RECONCILIATION_UNRESOLVED",
      error
    );
  } finally {
    await admin.end().catch(() => {});
  }

  const baseReceipt = {
    ...recoveryPublisherPrivateSchemaRepairPlan(),
    mode: "VERIFY_APPLIED_READ_ONLY",
    mutationCount: 0,
    mutationCountObserved: 0,
    observation,
    target: schemaRepairTargetReceipt(
      adminTarget,
      publisherTarget,
      binding
    ),
    source: schemaRepairSourceReceipt(binding),
    expectedPreflightPostureDigest:
      binding.expectedPreflightPostureDigest,
    expectedClusterPreflightPostureDigest:
      binding.expectedClusterPreflightPostureDigest,
    expectedPreflightObservation:
      "CALLER_SUPPLIED_BINDING_NOT_REOBSERVED",
    observedPostureDigest: classified.summary.postureDigest,
    observedClusterPostureDigest: clusterObserved.postureDigest,
    functionDefinitions,
    concurrentAdministratorRequirement:
      "NO_CONCURRENT_ADMINISTRATOR_MUTATION_REQUIRED_NOT_VERIFIED"
  };
  if (classified.state === "ABSENT") {
    return Object.freeze({
      ...baseReceipt,
      status: "CONFIRMED_ABSENT",
      applied: false,
      claimBoundary:
        "Read-only verification found the exact pre-repair posture. It performed no mutation and grants no retry, deployment, or release authority."
    });
  }

  let capabilityPosture;
  const publisher = createPublisherClient();
  try {
    await publisher.connect();
    capabilityPosture = await collectRecoveryPublisherCapabilityPosture(
      publisher
    );
  } catch (error) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_RECONCILIATION_UNRESOLVED",
      error
    );
  } finally {
    await publisher.end().catch(() => {});
  }
  return Object.freeze({
    ...baseReceipt,
    status: "CONFIRMED_PRESENT",
    applied: true,
    capabilityPosture,
    claimBoundary:
      "Read-only verification confirms the exact schema-USAGE posture, stored-function definition hashes, rollback-safe function probes, and direct-table denials. It proves no deployment or release authority."
  });
}

export async function repairRecoveryPublisherPrivateSchemaUsage({
  adminConnectionString,
  publisherConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryClusterId,
  expectedPreflightPostureDigest,
  expectedClusterPreflightPostureDigest,
  sourceCommit,
  sourceTree,
  confirmation,
  createAdminClient = () => new Client(bootstrapDatabaseConfig({
    connectionString: adminConnectionString,
    max: 1,
    applicationName: "tideproof-recovery-schema-repair"
  })),
  createReconciliationAdminClient = createAdminClient,
  createReconciliationPublisherClient = () => new Client(
    runtimeDatabaseConfig({
      connectionString: publisherConnectionString,
      max: 1,
      applicationName: "tideproof-recovery-schema-repair-verifier"
    })
  ),
  collectClusterPosture = (options) =>
    collectClusterManagedGrantPosture(options)
}) {
  if (confirmation !== RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED");
  }
  const binding = validateSchemaRepairBinding({
    expectedRecoveryClusterId,
    expectedPreflightPostureDigest,
    expectedClusterPreflightPostureDigest,
    sourceCommit,
    sourceTree
  });
  const adminTarget = recoveryConnectionTarget(
    adminConnectionString,
    expectedRecoveryHostname
  );
  const publisherTarget = recoveryConnectionTarget(
    publisherConnectionString,
    expectedRecoveryHostname,
    { publisher: true }
  );
  if (adminTarget.hostname !== publisherTarget.hostname) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_TARGET_INVALID");
  }

  const admin = createAdminClient();
  let preflight;
  let clusterPreflight;
  let preflightFunctionDefinitions;
  let commitAcknowledged = false;
  let commitError = null;
  try {
    await admin.connect();
    const classified = classifyRecoverySchemaRepairPosture(
      await collectDatabaseSecurityPosture(admin)
    );
    if (classified.state === "PRESENT") {
      throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_ALREADY_APPLIED");
    }
    preflight = classified.summary;
    if (preflight.postureDigest !== binding.expectedPreflightPostureDigest) {
      throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_PREFLIGHT_MISMATCH");
    }
    preflightFunctionDefinitions =
      await collectRecoveryPublisherFunctionDefinitions(admin);
    clusterPreflight = await collectClusterPosture({
      adminConnectionString,
      principalDatabases: CLUSTER_PRINCIPAL_DATABASES
    });
    requiredSha256(
      clusterPreflight?.postureDigest,
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_PREFLIGHT_INVALID"
    );
    if (
      clusterPreflight.postureDigest !==
        binding.expectedClusterPreflightPostureDigest
    ) {
      throw stablePublisherError(
        "RECOVERY_SCHEMA_REPAIR_CLUSTER_PREFLIGHT_MISMATCH"
      );
    }

    let transactionStarted = false;
    let commitDispatched = false;
    try {
      await admin.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      await admin.query(RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL);
      commitDispatched = true;
      await admin.query("COMMIT");
      transactionStarted = false;
      commitAcknowledged = true;
    } catch (error) {
      if (!commitDispatched) {
        if (transactionStarted) {
          try {
            await admin.query("ROLLBACK");
          } catch (rollbackError) {
            throw stablePublisherError(
              "RECOVERY_SCHEMA_REPAIR_ROLLBACK_FAILED",
              new AggregateError([error, rollbackError])
            );
          }
        }
        throw stablePublisherError(
          "RECOVERY_SCHEMA_REPAIR_NOT_APPLIED",
          error
        );
      }
      commitError = error;
    }
  } finally {
    await admin.end().catch(() => {});
  }

  let verification;
  try {
    verification = await verifyRecoveryPublisherPrivateSchemaUsage({
      adminConnectionString,
      publisherConnectionString,
      expectedRecoveryHostname,
      expectedRecoveryClusterId: binding.clusterId,
      expectedPreflightPostureDigest:
        binding.expectedPreflightPostureDigest,
      expectedClusterPreflightPostureDigest:
        binding.expectedClusterPreflightPostureDigest,
      sourceCommit: binding.sourceCommit,
      sourceTree: binding.sourceTree,
      observation: commitAcknowledged ? "direct_ack" : "read_reconciled",
      createAdminClient: createReconciliationAdminClient,
      createPublisherClient: createReconciliationPublisherClient,
      collectClusterPosture
    });
  } catch (error) {
    throw schemaRepairReconciliationError(
      commitAcknowledged
        ? "RECOVERY_SCHEMA_REPAIR_POSTCOMMIT_VERIFICATION_UNRESOLVED"
        : "RECOVERY_SCHEMA_REPAIR_RECONCILIATION_UNRESOLVED",
      null,
      new AggregateError(
        [commitError, error].filter(Boolean)
      )
    );
  }
  const receipt = Object.freeze({
    ...verification,
    mode: "APPLY_EXACTLY_ONCE",
    mutationCount: 1,
    mutationDispatchCount: 1,
    preflightPostureDigest: preflight.postureDigest,
    clusterPreflightPostureDigest: clusterPreflight.postureDigest,
    preflightFunctionDefinitions,
    commitAcknowledged,
    claimBoundary:
      "This records one dispatched schema-USAGE repair followed by fresh-connection read-only verification. It grants no direct table privilege, cross-database capability, deployment authority, or release authority."
  });
  if (
    verification.status === "CONFIRMED_ABSENT" ||
    !verification.applied
  ) {
    throw schemaRepairReconciliationError(
      "RECOVERY_SCHEMA_REPAIR_CONFIRMED_ABSENT",
      receipt,
      commitError
    );
  }
  if (
    preflightFunctionDefinitions.bindingSha256 !==
      verification.functionDefinitions.bindingSha256
  ) {
    throw schemaRepairReconciliationError(
      "RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_DRIFT",
      receipt
    );
  }
  return receipt;
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

    await client.query(`DROP FUNCTION IF EXISTS ${APPEND_SIGNATURE}`);
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
      RETURNS TABLE(
        bundle_digest STRING,
        outcome STRING,
        database_now TIMESTAMPTZ
      )
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
          OR p_source_commit_ts < statement_timestamp() - INTERVAL '1 hour'
          OR p_source_commit_ts > statement_timestamp() + INTERVAL '1 minute'
          OR p_expires_at <= statement_timestamp()
          OR p_expires_at > statement_timestamp() + INTERVAL '24 hours'
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
          RETURN QUERY SELECT
            p_bundle_digest,
            'bundle_replay'::STRING,
            transaction_timestamp();
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

        RETURN QUERY SELECT
          p_bundle_digest,
          'bundle_appended'::STRING,
          transaction_timestamp();
      END
      $$
    `);

    await client.query(`
      CREATE OR REPLACE FUNCTION mcp_api.resolve_recovery_bundle_v1(
        p_tenant_id UUID,
        p_recovery_session_id UUID,
        p_snapshot_version INT8,
        p_bundle_digest STRING
      )
      RETURNS TABLE(
        bundle_digest STRING,
        outcome STRING,
        database_now TIMESTAMPTZ
      )
      LANGUAGE SQL
      SECURITY DEFINER
      AS $$
        SELECT
          bundle.bundle_digest,
          'bundle_present'::STRING,
          transaction_timestamp()
        FROM mcp_private.recovery_bundles_v2 AS bundle
        WHERE session_user = '${RECOVERY_PUBLISHER_USER}'
          AND bundle.tenant_id = p_tenant_id
          AND bundle.recovery_session_id = p_recovery_session_id
          AND bundle.snapshot_version = p_snapshot_version
          AND bundle.bundle_digest = p_bundle_digest
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
    await client.query(
      `ALTER FUNCTION ${RESOLVE_SIGNATURE} OWNER TO tp_recovery_owner`
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
      `GRANT USAGE ON SCHEMA mcp_api, mcp_private TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `GRANT EXECUTE ON FUNCTION ${APPEND_SIGNATURE} TO ${RECOVERY_PUBLISHER_ROLE}`
    );
    await client.query(
      `GRANT EXECUTE ON FUNCTION ${RESOLVE_SIGNATURE} TO ${RECOVERY_PUBLISHER_ROLE}`
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
    let clientClosed = false;
    const closeOriginal = async () => {
      if (!clientClosed) {
        clientClosed = true;
        await client.end().catch(() => {});
      }
    };
    try {
      await client.connect();
      return await appendRecoveryBundleWithClient(client, bundle, {
        beforeReconcile: closeOriginal,
        reconcile: async () => {
          const reconciler = new Client(runtimeDatabaseConfig({
            connectionString: this.#connectionString,
            max: 1,
            applicationName: "tideproof-recovery-publisher-reconcile"
          }));
          try {
            await reconciler.connect();
            return await reconciler.query(RESOLVE_SQL, [
              bundle.tenantId,
              bundle.recoverySessionId,
              bundle.snapshotVersion,
              bundle.bundleDigest
            ]);
          } finally {
            await reconciler.end().catch(() => {});
          }
        }
      });
    } finally {
      await closeOriginal();
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
    retryDeadlineMs = RECOVERY_PUBLISH_RETRY_DEADLINE_MS,
    beforeReconcile = null,
    reconcile = null
  } = {}
) {
  if (typeof client?.query !== "function") {
    throw new TypeError("RECOVERY_PUBLISH_CLIENT_REQUIRED");
  }
  if (
    beforeReconcile !== null &&
    typeof beforeReconcile !== "function"
  ) {
    throw new TypeError("RECOVERY_PUBLISH_CLOSE_HOOK_INVALID");
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
    let commitDispatched = false;
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      const result = await client.query(
        APPEND_SQL,
        recoveryBundleValues(bundle)
      );
      commitDispatched = true;
      await client.query("COMMIT");
      committed = true;
      transactionStarted = false;
      if (result.rowCount !== 1) {
        throw new RecoveryBundleMismatchError();
      }
      return committedBundleResult(result.rows[0], bundle, "direct_ack");
    } catch (error) {
      const unsafeConnection = databaseClientMustBeDiscarded(error);
      const commitDefinitivelyAborted =
        commitDispatched && error?.code === "40001";
      if (
        commitDispatched &&
        !commitDefinitivelyAborted &&
        typeof reconcile === "function"
      ) {
        if (beforeReconcile) {
          await beforeReconcile();
        }
        const resolved = await reconcile(bundle);
        if (resolved?.rowCount === 1) {
          return committedBundleResult(
            resolved.rows[0],
            bundle,
            "read_reconciled"
          );
        }
      }
      if (
        transactionStarted &&
        !committed &&
        (!commitDispatched || commitDefinitivelyAborted) &&
        !unsafeConnection
      ) {
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
  CLUSTER_PRINCIPAL_DATABASES,
  LEGACY_RECOVERY_POSTURE_SPEC,
  RESOLVE_SQL,
  RECOVERY_PUBLISH_MAX_ATTEMPTS,
  RECOVERY_PUBLISH_RETRY_DEADLINE_MS,
  retryBackoffMs
});
