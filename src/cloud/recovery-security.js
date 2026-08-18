import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as sleepTimer } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Client } from "pg";
import { assertCleanExactGitCheckout } from
  "../../scripts/lib/exact-git-source.js";
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
export const RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID =
  "24f93c44-fa61-467c-bd3f-a1153618c309";
export const RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID =
  "9fad7a1e-e440-4989-383b-6a191b947e6e";
export const RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL =
  `GRANT USAGE ON SCHEMA mcp_private TO ${RECOVERY_PUBLISHER_ROLE}`;
export const MANAGED_MCP_RECOVERY_PRINCIPAL = "managed-mcp";
export const MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION =
  "GRANT_MANAGED_MCP_RECOVERY_PRIVATE_SCHEMA_USAGE_V2";
export const MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION =
  "DISABLE_MANAGED_MCP_RECOVERY_PRIVATE_SCHEMA_USAGE_V2";
export const MANAGED_MCP_RECOVERY_GRANT_PROVIDER_CLUSTER_ID =
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID;
export const MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID =
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID;
export const MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256 =
  "f71728df77547de0160a1bbc6766309b4d1ce02e140876cffe14bfa6c00b148c";
export const MANAGED_MCP_RECOVERY_GRANT_SQL = Object.freeze([
  'REVOKE USAGE ON SCHEMA mcp_public FROM "managed-mcp"',
  'GRANT USAGE ON SCHEMA mcp_private TO "managed-mcp"',
  'GRANT USAGE ON SCHEMA mcp_public TO "managed-mcp"'
]);
export const MANAGED_MCP_RECOVERY_ROLLBACK_SQL = Object.freeze([
  'REVOKE USAGE ON SCHEMA mcp_public FROM "managed-mcp"',
  'REVOKE USAGE ON SCHEMA mcp_private FROM "managed-mcp"',
  'GRANT USAGE ON SCHEMA mcp_public TO "managed-mcp"'
]);
export const MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL = Object.freeze([
  'GRANT SELECT ON TABLE mcp_public.recovery_bundle_v2 TO "managed-mcp"',
  'GRANT USAGE ON SCHEMA mcp_private TO "managed-mcp"',
  'GRANT USAGE ON SCHEMA mcp_public TO "managed-mcp"'
]);
const RECOVERY_SECURITY_SOURCE_ROOT = path.resolve(
  fileURLToPath(new URL("../../", import.meta.url))
);
const LOWERCASE_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
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
    directPrincipalGrantPolicies: Object.freeze({
      [MANAGED_MCP_RECOVERY_PRINCIPAL]: Object.freeze({
        allowAbsent: true,
        databaseConnect: false,
        schemas: Object.freeze(["mcp_private", "mcp_public"]),
        relationGrants: Object.freeze([Object.freeze({
          schema: "mcp_public",
          name: "recovery_bundle_v2"
        })])
      })
    }),
    roles: RECOVERY_ROLES,
    users: RECOVERY_USERS,
    bindings: RECOVERY_ROLE_BINDINGS,
    optionalRoles: Object.freeze([
      ...PRIMARY_SIBLING_ROLES,
      MANAGED_MCP_RECOVERY_PRINCIPAL
    ]),
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

async function scrubRecoveryPrivileges(
  client,
  { managedMcpPrincipalPresent = false } = {}
) {
  for (const principal of [
    RECOVERY_PUBLISHER_ROLE,
    RECOVERY_PUBLISHER_USER,
    ...(managedMcpPrincipalPresent ? [MANAGED_MCP_RECOVERY_PRINCIPAL] : [])
  ]) {
    const quotedPrincipal = principal === MANAGED_MCP_RECOVERY_PRINCIPAL
      ? quoteIdentifier(principal)
      : principal;
    await client.query(
      `REVOKE ALL ON DATABASE tideproof_recovery FROM ${quotedPrincipal}`
    );
    await client.query(
      `REVOKE ALL ON SCHEMA mcp_private, mcp_public, mcp_api FROM ${quotedPrincipal}`
    );
    await client.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA mcp_private, mcp_public, mcp_api FROM ${quotedPrincipal}`
    );
    await client.query(
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mcp_private, mcp_public, mcp_api FROM ${quotedPrincipal}`
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
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedPreflightPostureDigest,
  expectedClusterPreflightPostureDigest,
  expectedAppendFunctionDefinitionSha256,
  expectedResolveFunctionDefinitionSha256,
  sourceCommit,
  sourceTree,
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  if (
    expectedRecoveryProviderClusterId !==
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID
  ) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID_INVALID"
    );
  }
  if (
    expectedRecoverySqlClusterId !==
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
  ) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_SQL_CLUSTER_ID_INVALID"
    );
  }
  const checkedSourceCommit = requiredGitObjectId(
    sourceCommit,
    "RECOVERY_SCHEMA_REPAIR_SOURCE_COMMIT_INVALID"
  );
  const checkedSourceTree = requiredGitObjectId(
    sourceTree,
    "RECOVERY_SCHEMA_REPAIR_SOURCE_TREE_INVALID"
  );
  if (typeof verifySourceCheckout !== "function") {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID"
    );
  }
  let verifiedSource;
  try {
    verifiedSource = verifySourceCheckout({
      rootDir: RECOVERY_SECURITY_SOURCE_ROOT,
      sourceCommit: checkedSourceCommit,
      treeDigest: checkedSourceTree
    });
  } catch (error) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID",
      error
    );
  }
  if (
    verifiedSource?.sourceCommit !== checkedSourceCommit ||
    verifiedSource?.treeDigest !== checkedSourceTree
  ) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID"
    );
  }
  return Object.freeze({
    providerClusterId: expectedRecoveryProviderClusterId,
    sqlClusterId: expectedRecoverySqlClusterId,
    expectedPreflightPostureDigest: requiredSha256(
      expectedPreflightPostureDigest,
      "RECOVERY_SCHEMA_REPAIR_PREFLIGHT_DIGEST_INVALID"
    ),
    expectedClusterPreflightPostureDigest: requiredSha256(
      expectedClusterPreflightPostureDigest,
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST_INVALID"
    ),
    expectedFunctionDefinitionDigests: Object.freeze({
      appendRecoveryBundleV2: requiredSha256(
        expectedAppendFunctionDefinitionSha256,
        "RECOVERY_SCHEMA_REPAIR_APPEND_FUNCTION_DIGEST_INVALID"
      ),
      resolveRecoveryBundleV1: requiredSha256(
        expectedResolveFunctionDefinitionSha256,
        "RECOVERY_SCHEMA_REPAIR_RESOLVE_FUNCTION_DIGEST_INVALID"
      )
    }),
    sourceCommit: checkedSourceCommit,
    sourceTree: checkedSourceTree
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

function validateRecoveryPublisherFunctionDefinitionBinding(
  observed,
  expected
) {
  if (
    observed?.definitions?.length !== 2 ||
    observed.definitions[0]?.id !== "append_recovery_bundle_v2" ||
    observed.definitions[1]?.id !== "resolve_recovery_bundle_v1" ||
    observed.definitions[0].createStatementSha256 !==
      expected.appendRecoveryBundleV2 ||
    observed.definitions[1].createStatementSha256 !==
      expected.resolveRecoveryBundleV1
  ) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_MISMATCH"
    );
  }
  return observed;
}

async function collectObservedRecoveryClusterId(client) {
  if (typeof client?.query !== "function") {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_INVALID"
    );
  }
  const result = await client.query(`
    SELECT crdb_internal.cluster_id()::STRING AS cluster_id
  `);
  const clusterId = result?.rows?.[0]?.cluster_id;
  if (
    result?.rowCount !== 1 ||
    !Array.isArray(result.rows) ||
    result.rows.length !== 1 ||
    typeof clusterId !== "string" ||
    !LOWERCASE_UUID.test(clusterId)
  ) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_INVALID"
    );
  }
  return clusterId;
}

function requireObservedRecoveryClusterId(clusterId, expectedClusterId) {
  if (clusterId !== expectedClusterId) {
    throw stablePublisherError(
      "RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_MISMATCH"
    );
  }
  return clusterId;
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

export async function collectRecoveryPublisherCapabilityPosture(
  client,
  options = undefined
) {
  if (typeof client?.query !== "function") {
    throw new TypeError("RECOVERY_PUBLISHER_PROBE_CLIENT_REQUIRED");
  }
  if (options !== undefined) {
    throw new TypeError("RECOVERY_PUBLISHER_PROBE_OPTIONS_REJECTED");
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
    schemaVersion: "tideproof.recovery-publisher-capability-posture.v3",
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
    schemaVersion: "tideproof.recovery-publisher-private-schema-repair.v4",
    databaseName: "tideproof_recovery",
    providerClusterId:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID,
    sqlClusterId:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID,
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
    providerClusterId: binding.providerClusterId,
    providerClusterIdSha256: sha256(binding.providerClusterId),
    sqlClusterId: binding.sqlClusterId,
    sqlClusterIdSha256: sha256(binding.sqlClusterId),
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
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedPreflightPostureDigest,
  expectedClusterPreflightPostureDigest,
  expectedAppendFunctionDefinitionSha256,
  expectedResolveFunctionDefinitionSha256,
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
    collectClusterManagedGrantPosture(options),
  verifySourceCheckout = assertCleanExactGitCheckout
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
    expectedRecoveryProviderClusterId,
    expectedRecoverySqlClusterId,
    expectedPreflightPostureDigest,
    expectedClusterPreflightPostureDigest,
    expectedAppendFunctionDefinitionSha256,
    expectedResolveFunctionDefinitionSha256,
    sourceCommit,
    sourceTree,
    verifySourceCheckout
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
  let adminObservedRecoverySqlClusterId;
  const admin = createAdminClient();
  try {
    await admin.connect();
    adminObservedRecoverySqlClusterId = requireObservedRecoveryClusterId(
      await collectObservedRecoveryClusterId(admin),
      binding.sqlClusterId
    );
    classified = classifyRecoverySchemaRepairPosture(
      await collectDatabaseSecurityPosture(admin)
    );
    functionDefinitions = validateRecoveryPublisherFunctionDefinitionBinding(
      await collectRecoveryPublisherFunctionDefinitions(admin),
      binding.expectedFunctionDefinitionDigests
    );
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
    observedRecoverySqlClusterId: adminObservedRecoverySqlClusterId,
    expectedFunctionDefinitionDigests:
      binding.expectedFunctionDefinitionDigests,
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
      "Read-only verification confirms SQL cluster identity through the admin connection, the exact schema-USAGE posture, stored-function definition hashes, rollback-safe publisher function probes, and direct-table denials. The least-privilege publisher is not required or granted access to internal cluster metadata. It proves no deployment or release authority."
  });
}

export async function repairRecoveryPublisherPrivateSchemaUsage({
  adminConnectionString,
  publisherConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedPreflightPostureDigest,
  expectedClusterPreflightPostureDigest,
  expectedAppendFunctionDefinitionSha256,
  expectedResolveFunctionDefinitionSha256,
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
    collectClusterManagedGrantPosture(options),
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  if (confirmation !== RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION) {
    throw stablePublisherError("RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED");
  }
  const binding = validateSchemaRepairBinding({
    expectedRecoveryProviderClusterId,
    expectedRecoverySqlClusterId,
    expectedPreflightPostureDigest,
    expectedClusterPreflightPostureDigest,
    expectedAppendFunctionDefinitionSha256,
    expectedResolveFunctionDefinitionSha256,
    sourceCommit,
    sourceTree,
    verifySourceCheckout
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
  let preflightObservedRecoverySqlClusterId;
  let commitAcknowledged = false;
  let commitError = null;
  try {
    await admin.connect();
    preflightObservedRecoverySqlClusterId = requireObservedRecoveryClusterId(
      await collectObservedRecoveryClusterId(admin),
      binding.sqlClusterId
    );
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
      validateRecoveryPublisherFunctionDefinitionBinding(
        await collectRecoveryPublisherFunctionDefinitions(admin),
        binding.expectedFunctionDefinitionDigests
      );
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
      expectedRecoveryProviderClusterId: binding.providerClusterId,
      expectedRecoverySqlClusterId: binding.sqlClusterId,
      expectedPreflightPostureDigest:
        binding.expectedPreflightPostureDigest,
      expectedClusterPreflightPostureDigest:
        binding.expectedClusterPreflightPostureDigest,
      expectedAppendFunctionDefinitionSha256:
        binding.expectedFunctionDefinitionDigests.appendRecoveryBundleV2,
      expectedResolveFunctionDefinitionSha256:
        binding.expectedFunctionDefinitionDigests.resolveRecoveryBundleV1,
      sourceCommit: binding.sourceCommit,
      sourceTree: binding.sourceTree,
      observation: commitAcknowledged ? "direct_ack" : "read_reconciled",
      createAdminClient: createReconciliationAdminClient,
      createPublisherClient: createReconciliationPublisherClient,
      collectClusterPosture,
      verifySourceCheckout
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
    preflightObservedRecoverySqlClusterId,
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

function normalizeManagedMcpRecoveryGrant(row) {
  return Object.freeze({
    databaseName: row?.database_name ?? "",
    schemaName: row?.schema_name ?? "",
    objectName: row?.object_name ?? "",
    objectType: String(row?.object_type ?? "").toLowerCase(),
    grantee: row?.grantee ?? "",
    privilegeType: String(row?.privilege_type ?? "").toUpperCase(),
    isGrantable: row?.is_grantable === true
  });
}

const MANAGED_MCP_RECOVERY_EXPECTED_GRANTS = Object.freeze([
  Object.freeze({
    databaseName: "tideproof_recovery",
    schemaName: "mcp_private",
    objectName: "",
    objectType: "schema",
    grantee: MANAGED_MCP_RECOVERY_PRINCIPAL,
    privilegeType: "USAGE",
    isGrantable: false
  }),
  Object.freeze({
    databaseName: "tideproof_recovery",
    schemaName: "mcp_public",
    objectName: "",
    objectType: "schema",
    grantee: MANAGED_MCP_RECOVERY_PRINCIPAL,
    privilegeType: "USAGE",
    isGrantable: false
  }),
  Object.freeze({
    databaseName: "tideproof_recovery",
    schemaName: "mcp_public",
    objectName: "recovery_bundle_v2",
    objectType: "table",
    grantee: MANAGED_MCP_RECOVERY_PRINCIPAL,
    privilegeType: "SELECT",
    isGrantable: false
  })
]);

function sortedManagedMcpRecoveryGrants(rows) {
  if (!Array.isArray(rows)) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_GRANT_CENSUS_INVALID");
  }
  return rows
    .map(normalizeManagedMcpRecoveryGrant)
    .sort((left, right) => JSON.stringify(left).localeCompare(
      JSON.stringify(right)
    ));
}

function classifyManagedMcpRecoveryGrants(rows) {
  const observed = sortedManagedMcpRecoveryGrants(rows);
  if (observed.length === 0) {
    return Object.freeze({ state: "ABSENT", grants: Object.freeze([]) });
  }
  const expected = sortedManagedMcpRecoveryGrants(
    MANAGED_MCP_RECOVERY_EXPECTED_GRANTS.map((grant) => ({
      database_name: grant.databaseName,
      schema_name: grant.schemaName || null,
      object_name: grant.objectName || null,
      object_type: grant.objectType,
      grantee: grant.grantee,
      privilege_type: grant.privilegeType,
      is_grantable: grant.isGrantable
    }))
  );
  if (JSON.stringify(observed) === JSON.stringify(expected)) {
    return Object.freeze({
      state: "PRESENT",
      grants: Object.freeze(observed)
    });
  }
  const expectedKeys = new Map(expected.map((grant) => [
    JSON.stringify(grant),
    grant.schemaName === "mcp_private"
      ? "PRIVATE_USAGE"
      : grant.privilegeType === "SELECT"
        ? "VIEW_SELECT"
        : "PUBLIC_USAGE"
  ]));
  const observedCapabilities = observed.map((grant) =>
    expectedKeys.get(JSON.stringify(grant))
  );
  if (observedCapabilities.some((capability) => !capability)) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_GRANT_POSTURE_UNRESOLVED"
    );
  }
  const stateByCapabilities = new Map([
    ["VIEW_SELECT", "SELECT_ONLY"],
    ["PUBLIC_USAGE", "PUBLIC_SCHEMA_ONLY"],
    ["PRIVATE_USAGE", "PRIVATE_SCHEMA_ONLY"],
    ["PUBLIC_USAGE,VIEW_SELECT", "PUBLIC_VIEW_READY"],
    ["PRIVATE_USAGE,VIEW_SELECT", "PRIVATE_USAGE_AND_SELECT"],
    ["PRIVATE_USAGE,PUBLIC_USAGE", "PRIVATE_AND_PUBLIC_SCHEMA_USAGE"]
  ]);
  const state = stateByCapabilities.get(
    observedCapabilities.sort().join(",")
  );
  if (!state) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_GRANT_POSTURE_UNRESOLVED"
    );
  }
  return Object.freeze({ state, grants: Object.freeze(observed) });
}

function validateManagedMcpRecoveryTargetBinding({
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedViewDefinitionSha256,
  sourceCommit,
  sourceTree,
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  if (
    expectedRecoveryProviderClusterId !==
      MANAGED_MCP_RECOVERY_GRANT_PROVIDER_CLUSTER_ID
  ) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_PROVIDER_CLUSTER_ID_INVALID"
    );
  }
  if (
    expectedRecoverySqlClusterId !==
      MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID
  ) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_SQL_CLUSTER_ID_INVALID"
    );
  }
  if (
    expectedViewDefinitionSha256 !==
      MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256
  ) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_VIEW_DIGEST_INVALID");
  }
  const checkedSourceCommit = requiredGitObjectId(
    sourceCommit,
    "MANAGED_MCP_RECOVERY_SOURCE_COMMIT_INVALID"
  );
  const checkedSourceTree = requiredGitObjectId(
    sourceTree,
    "MANAGED_MCP_RECOVERY_SOURCE_TREE_INVALID"
  );
  if (typeof verifySourceCheckout !== "function") {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_SOURCE_CHECKOUT_INVALID");
  }
  let verifiedSource;
  try {
    verifiedSource = verifySourceCheckout({
      rootDir: RECOVERY_SECURITY_SOURCE_ROOT,
      sourceCommit: checkedSourceCommit,
      treeDigest: checkedSourceTree
    });
  } catch (error) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_SOURCE_CHECKOUT_INVALID",
      error
    );
  }
  if (
    verifiedSource?.sourceCommit !== checkedSourceCommit ||
    verifiedSource?.treeDigest !== checkedSourceTree
  ) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_SOURCE_CHECKOUT_INVALID");
  }
  return Object.freeze({
    providerClusterId: expectedRecoveryProviderClusterId,
    sqlClusterId: expectedRecoverySqlClusterId,
    expectedViewDefinitionSha256,
    sourceCommit: checkedSourceCommit,
    sourceTree: checkedSourceTree
  });
}

function validateManagedMcpRecoveryGrantBinding({
  expectedPreflightPostureDigest,
  ...options
}) {
  const binding = validateManagedMcpRecoveryTargetBinding(options);
  return Object.freeze({
    ...binding,
    expectedPreflightPostureDigest: requiredSha256(
      expectedPreflightPostureDigest,
      "MANAGED_MCP_RECOVERY_PREFLIGHT_DIGEST_INVALID"
    )
  });
}

function validatedManagedMcpRecoveryViewDefinition(result, expectedSha256) {
  if (!Array.isArray(result?.rows) || result.rows.length !== 1) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_VIEW_DEFINITION_INVALID");
  }
  const statement = normalizedFunctionDefinition(
    result.rows[0]?.create_statement ?? result.rows[0]?.createStatement
  );
  const searchable = statement
    .toLowerCase()
    .replaceAll('"', "")
    .replaceAll(/\s+/gu, " ");
  if (
    !searchable.includes("view mcp_public.recovery_bundle_v2") ||
    !searchable.includes(
      "from tideproof_recovery.mcp_private.recovery_bundles_v2"
    ) ||
    !searchable.includes("authority_transferred") ||
    !searchable.includes("requires_fresh_authorization") ||
    searchable.includes("security_invoker") ||
    sha256(statement) !== expectedSha256
  ) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_VIEW_DEFINITION_INVALID");
  }
  return Object.freeze({
    createStatementSha256: sha256(statement),
    byteLength: Buffer.byteLength(statement, "utf8"),
    securityInvoker: false
  });
}

export async function collectManagedMcpRecoveryGrantPosture(
  client,
  {
    expectedRecoverySqlClusterId,
    expectedViewDefinitionSha256
  }
) {
  if (typeof client?.query !== "function") {
    throw new TypeError("MANAGED_MCP_RECOVERY_ADMIN_CLIENT_REQUIRED");
  }
  if (
    expectedRecoverySqlClusterId !== MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID
  ) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_SQL_CLUSTER_ID_INVALID");
  }
  if (
    expectedViewDefinitionSha256 !==
      MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256
  ) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_VIEW_DIGEST_INVALID");
  }
  let transactionStarted = false;
  try {
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    transactionStarted = true;
    const sessionResult = await client.query(`
      SELECT
        current_database() AS database_name,
        current_user AS current_user_name,
        session_user AS session_user_name,
        version() AS database_version,
        crdb_internal.cluster_id()::STRING AS cluster_id
    `);
    const userResult = await client.query(`
      SELECT username, options
      FROM [SHOW USERS]
      ORDER BY username
    `);
    const principalResult = await client.query(`
      SELECT username, "isRole" AS is_role
      FROM system.users
      WHERE username = 'managed-mcp'
    `);
    const membershipResult = await client.query(`
      SELECT role_name, member, is_admin
      FROM [SHOW GRANTS ON ROLE]
      ORDER BY role_name, member
    `);
    const systemGrantResult = await client.query(`
      SELECT grantee, privilege_type, is_grantable
      FROM [SHOW SYSTEM GRANTS]
      ORDER BY grantee, privilege_type, is_grantable
    `);
    const objectGrantResult = await client.query(`
      SELECT
        database_name,
        schema_name,
        object_name,
        object_type,
        grantee,
        privilege_type,
        is_grantable
      FROM [SHOW GRANTS]
      WHERE database_name = current_database()
        AND (
          schema_name IS NULL
          OR schema_name NOT IN (
            'crdb_internal',
            'information_schema',
            'pg_catalog',
            'pg_extension'
          )
        )
      ORDER BY
        database_name,
        schema_name,
        object_name,
        object_type,
        privilege_type,
        is_grantable
    `);
    const defaultGrantResult = await client.query(`
      SELECT
        current_database() AS database_name,
        NULL::STRING AS schema_name,
        role,
        for_all_roles,
        object_type,
        grantee,
        privilege_type,
        is_grantable
      FROM [SHOW DEFAULT PRIVILEGES]
      ORDER BY role, object_type, grantee, privilege_type, is_grantable
    `);
    const viewOwnerResult = await client.query(`
      SELECT table_name, owner
      FROM [SHOW TABLES FROM mcp_public]
      WHERE table_name = 'recovery_bundle_v2'
    `);
    const viewDefinitionResult = await client.query(
      "SHOW CREATE VIEW mcp_public.recovery_bundle_v2"
    );
    await client.query("COMMIT");
    transactionStarted = false;

    const session = sessionResult.rows?.[0];
    const managedMcpUserRows = userResult.rows?.filter((row) =>
      row?.username === MANAGED_MCP_RECOVERY_PRINCIPAL
    );
    if (
      sessionResult.rowCount !== 1 ||
      session?.database_name !== "tideproof_recovery" ||
      typeof session?.current_user_name !== "string" ||
      session.current_user_name === "" ||
      session.current_user_name !== session?.session_user_name ||
      !/\bCockroachDB(?: CCL)? v26\.2(?:\.\d+)?\b/u.test(
        session?.database_version ?? ""
      ) ||
      session?.cluster_id !== expectedRecoverySqlClusterId
    ) {
      throw stablePublisherError("MANAGED_MCP_RECOVERY_SESSION_INVALID");
    }
    if (
      principalResult.rowCount !== 1 ||
      principalResult.rows?.[0]?.username !== MANAGED_MCP_RECOVERY_PRINCIPAL ||
      principalResult.rows?.[0]?.is_role !== false ||
      managedMcpUserRows?.length !== 1 ||
      !Array.isArray(managedMcpUserRows[0]?.options) ||
      managedMcpUserRows[0].options.length !== 1 ||
      managedMcpUserRows[0].options[0] !== "NOLOGIN" ||
      membershipResult.rows?.some((row) =>
        row?.role_name === MANAGED_MCP_RECOVERY_PRINCIPAL ||
        row?.member === MANAGED_MCP_RECOVERY_PRINCIPAL
      ) ||
      systemGrantResult.rows?.some((row) =>
        row?.grantee === MANAGED_MCP_RECOVERY_PRINCIPAL
      ) ||
      defaultGrantResult.rows?.some((row) =>
        row?.role === MANAGED_MCP_RECOVERY_PRINCIPAL ||
        row?.grantee === MANAGED_MCP_RECOVERY_PRINCIPAL
      )
    ) {
      throw stablePublisherError("MANAGED_MCP_RECOVERY_PRINCIPAL_UNSAFE");
    }
    if (
      viewOwnerResult.rowCount !== 1 ||
      viewOwnerResult.rows?.[0]?.table_name !== "recovery_bundle_v2" ||
      viewOwnerResult.rows?.[0]?.owner !== "tp_recovery_owner"
    ) {
      throw stablePublisherError("MANAGED_MCP_RECOVERY_VIEW_OWNER_INVALID");
    }
    const viewDefinition = validatedManagedMcpRecoveryViewDefinition(
      viewDefinitionResult,
      expectedViewDefinitionSha256
    );
    const managedMcpObjectGrants = objectGrantResult.rows.filter((row) =>
      row?.grantee === MANAGED_MCP_RECOVERY_PRINCIPAL
    );
    const baselinePosture = {
      session: [{
        database_name: session.database_name,
        current_user_name: session.current_user_name,
        session_user_name: session.session_user_name,
        database_version: session.database_version
      }],
      principals: userResult.rows,
      memberships: membershipResult.rows,
      systemGrants: systemGrantResult.rows,
      objectGrants: objectGrantResult.rows.filter((row) =>
        row?.grantee !== MANAGED_MCP_RECOVERY_PRINCIPAL
      ),
      defaultGrants: defaultGrantResult.rows
    };
    const baselineRecoveryPosture = validateRecoverySecurityPosture(
      baselinePosture
    );
    const ownerPrivateTableGrant = objectGrantResult.rows.filter((row) =>
      row?.database_name === "tideproof_recovery" &&
      row?.schema_name === "mcp_private" &&
      row?.object_name === "recovery_bundles_v2" &&
      ["table", "TABLE"].includes(row?.object_type) &&
      row?.grantee === "tp_recovery_owner" &&
      row?.privilege_type === "ALL" &&
      row?.is_grantable === true
    );
    if (ownerPrivateTableGrant.length !== 1) {
      throw stablePublisherError(
        "MANAGED_MCP_RECOVERY_VIEW_OWNER_CAPABILITY_INVALID"
      );
    }
    const classified = classifyManagedMcpRecoveryGrants(
      managedMcpObjectGrants
    );
    const summary = Object.freeze({
      databaseName: session.database_name,
      databaseVersionSha256: sha256(session.database_version),
      sqlClusterId: session.cluster_id,
      principal: MANAGED_MCP_RECOVERY_PRINCIPAL,
      principalType: "USER",
      membershipCount: 0,
      systemGrantCount: 0,
      defaultGrantCount: 0,
      viewOwner: "tp_recovery_owner",
      viewOwnerPrivateTableCapability: "ALL_WITH_GRANT_OPTION",
      viewDefinition,
      baselineRecoveryPostureDigest:
        baselineRecoveryPosture.postureDigest,
      state: classified.state,
      grants: classified.grants
    });
    return Object.freeze({
      schemaVersion: "tideproof.managed-mcp-recovery-grant-posture.v2",
      ...summary,
      postureDigest: sha256(JSON.stringify(summary))
    });
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK").catch(() => {});
    }
    throw error;
  }
}

export function managedMcpRecoveryGrantPlan() {
  return Object.freeze({
    schemaVersion: "tideproof.managed-mcp-recovery-grant-repair.v2",
    databaseName: "tideproof_recovery",
    providerClusterId: MANAGED_MCP_RECOVERY_GRANT_PROVIDER_CLUSTER_ID,
    sqlClusterId: MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID,
    principal: MANAGED_MCP_RECOVERY_PRINCIPAL,
    statements: MANAGED_MCP_RECOVERY_GRANT_SQL,
    statementDigests: Object.freeze(
      MANAGED_MCP_RECOVERY_GRANT_SQL.map(sha256)
    ),
    rollbackStatements: MANAGED_MCP_RECOVERY_ROLLBACK_SQL,
    rollbackStatementDigests: Object.freeze(
      MANAGED_MCP_RECOVERY_ROLLBACK_SQL.map(sha256)
    ),
    freshBootstrapStatements: MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL,
    freshBootstrapStatementDigests: Object.freeze(
      MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL.map(sha256)
    ),
    requiredPreexistingCapabilities: Object.freeze([
      "SCHEMA:mcp_public:USAGE",
      "VIEW:mcp_public.recovery_bundle_v2:SELECT"
    ]),
    expectedAddedCapabilities: Object.freeze([
      "SCHEMA:mcp_private:USAGE"
    ]),
    forbiddenCapabilities: Object.freeze([
      "DATABASE_WIDE_SELECT",
      "SCHEMA:mcp_private:CREATE",
      "SCHEMA:mcp_api:*",
      "RELATION:mcp_private:*",
      "FUNCTION:mcp_private:*",
      "GRANT_OPTION",
      "ROLE_MEMBERSHIP",
      "SYSTEM_GRANT"
    ]),
    confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
    disableConfirmation: MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION,
    mutationStatementCount: 3,
    mutationTransactionCount: 3,
    dispatchOrder: Object.freeze([
      "REVOKE_PUBLIC_SCHEMA_USAGE_DEACTIVATES_VIEW",
      "GRANT_PRIVATE_SCHEMA_USAGE_WHILE_VIEW_INACTIVE",
      "REGRANT_PUBLIC_SCHEMA_USAGE_ACTIVATES_VIEW"
    ]),
    requiredPreflightState: "PUBLIC_VIEW_READY",
    rollbackRestoresExactPreflight: true,
    reconciliationRequiredAfterEachDispatch: true,
    explicitMultiStatementTransactionForbidden: true,
    exclusiveTargetReservationRequired: true,
    externalMutatorExclusionRequired: true
  });
}

async function reserveManagedMcpRecoveryTarget({
  binding,
  target,
  operationId,
  journalIntent
}) {
  if (typeof journalIntent?.reserveTarget !== "function") {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_TARGET_RESERVATION_REQUIRED"
    );
  }
  const targetBinding = Object.freeze({
    schemaVersion: "tideproof.managed-mcp-recovery-target-binding.v1",
    providerClusterIdSha256: sha256(binding.providerClusterId),
    sqlClusterIdSha256: sha256(binding.sqlClusterId),
    databaseName: target.databaseName,
    hostnameSha256: sha256(target.hostname),
    adminPrincipalSha256: sha256(target.username),
    managedPrincipal: MANAGED_MCP_RECOVERY_PRINCIPAL
  });
  const targetBindingSha256 = sha256(JSON.stringify(targetBinding));
  const reservation = await journalIntent.reserveTarget(Object.freeze({
    schemaVersion: "tideproof.managed-mcp-recovery-target-reservation.v1",
    operationId,
    targetBinding,
    targetBindingSha256
  }));
  if (
    reservation?.operationId !== operationId ||
    reservation?.reservation !== "TARGET_UNIQUE_RESERVED" ||
    reservation?.targetBindingSha256 !== targetBindingSha256
  ) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_TARGET_RESERVATION_INVALID"
    );
  }
  return Object.freeze({
    operationId,
    reservation: "TARGET_UNIQUE_RESERVED",
    targetBindingSha256,
    reservationDigest: requiredSha256(
      reservation?.reservationDigest,
      "MANAGED_MCP_RECOVERY_TARGET_RESERVATION_INVALID"
    )
  });
}

export async function preflightManagedMcpRecoveryGrants({
  adminConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedViewDefinitionSha256,
  sourceCommit,
  sourceTree,
  createAdminClient = () => new Client(bootstrapDatabaseConfig({
    connectionString: adminConnectionString,
    max: 1,
    applicationName: "tideproof-managed-mcp-recovery-grant-preflight"
  })),
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  const binding = validateManagedMcpRecoveryTargetBinding({
    expectedRecoveryProviderClusterId,
    expectedRecoverySqlClusterId,
    expectedViewDefinitionSha256,
    sourceCommit,
    sourceTree,
    verifySourceCheckout
  });
  const target = recoveryConnectionTarget(
    adminConnectionString,
    expectedRecoveryHostname
  );
  const admin = createAdminClient();
  let posture;
  try {
    await admin.connect();
    posture = await collectManagedMcpRecoveryGrantPosture(admin, {
      expectedRecoverySqlClusterId: binding.sqlClusterId,
      expectedViewDefinitionSha256: binding.expectedViewDefinitionSha256
    });
  } finally {
    await admin.end().catch(() => {});
  }
  return Object.freeze({
    ...managedMcpRecoveryGrantPlan(),
    mode: "PREFLIGHT_READ_ONLY",
    applied: posture.state === "PRESENT",
    status: posture.state === "PRESENT"
      ? "CONFIRMED_PRESENT"
      : posture.state === "PUBLIC_VIEW_READY"
        ? "READY_FOR_PRIVATE_SCHEMA_USAGE"
        : `HOLD_${posture.state}`,
    mutationStatementCount: 0,
    mutationTransactionCount: 0,
    source: Object.freeze({
      commit: binding.sourceCommit,
      tree: binding.sourceTree
    }),
    target: Object.freeze({
      providerClusterId: binding.providerClusterId,
      providerClusterIdSha256: sha256(binding.providerClusterId),
      sqlClusterId: binding.sqlClusterId,
      sqlClusterIdSha256: sha256(binding.sqlClusterId),
      databaseName: target.databaseName,
      hostnameSha256: sha256(target.hostname),
      adminPrincipalSha256: sha256(target.username)
    }),
    preflightPostureDigest: posture.postureDigest,
    posture,
    claimBoundary:
      "This read-only preflight source-binds the exact target, view, principal, full recovery posture, and the already-present public-schema USAGE plus public-view SELECT baseline before a separately confirmed private-schema traversal grant. It grants no capability or execution authority."
  });
}

export async function verifyManagedMcpRecoveryGrants({
  adminConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedPreflightPostureDigest,
  expectedViewDefinitionSha256,
  sourceCommit,
  sourceTree,
  observation = "read_only_verification",
  createAdminClient = () => new Client(bootstrapDatabaseConfig({
    connectionString: adminConnectionString,
    max: 1,
    applicationName: "tideproof-managed-mcp-recovery-grant-verifier"
  })),
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  if (![
    "read_only_verification",
    "direct_ack",
    "read_reconciled"
  ].includes(observation)) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_OBSERVATION_INVALID");
  }
  const binding = validateManagedMcpRecoveryGrantBinding({
    expectedRecoveryProviderClusterId,
    expectedRecoverySqlClusterId,
    expectedPreflightPostureDigest,
    expectedViewDefinitionSha256,
    sourceCommit,
    sourceTree,
    verifySourceCheckout
  });
  const target = recoveryConnectionTarget(
    adminConnectionString,
    expectedRecoveryHostname
  );
  const admin = createAdminClient();
  let posture;
  try {
    await admin.connect();
    posture = await collectManagedMcpRecoveryGrantPosture(admin, {
      expectedRecoverySqlClusterId: binding.sqlClusterId,
      expectedViewDefinitionSha256: binding.expectedViewDefinitionSha256
    });
  } finally {
    await admin.end().catch(() => {});
  }
  return Object.freeze({
    ...managedMcpRecoveryGrantPlan(),
    mode: "VERIFY_READ_ONLY",
    observation,
    applied: posture.state === "PRESENT",
    status: posture.state === "PRESENT"
      ? "CONFIRMED_PRESENT"
      : posture.state === "PUBLIC_VIEW_READY"
        ? "CONFIRMED_PRE_REPAIR_BASELINE"
        : `HOLD_${posture.state}`,
    mutationStatementCount: 0,
    mutationTransactionCount: 0,
    source: Object.freeze({
      commit: binding.sourceCommit,
      tree: binding.sourceTree
    }),
    target: Object.freeze({
      providerClusterId: binding.providerClusterId,
      providerClusterIdSha256: sha256(binding.providerClusterId),
      sqlClusterId: binding.sqlClusterId,
      sqlClusterIdSha256: sha256(binding.sqlClusterId),
      databaseName: target.databaseName,
      hostnameSha256: sha256(target.hostname),
      adminPrincipalSha256: sha256(target.username)
    }),
    expectedPreflightPostureDigest:
      binding.expectedPreflightPostureDigest,
    posture,
    claimBoundary:
      "This read-only receipt classifies only the managed-mcp user's exact public-view access and non-grantable schema traversal. It proves no private-relation, function, API-schema, role, system, execution, deployment, or release authority."
  });
}

export async function repairManagedMcpRecoveryGrants({
  adminConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedPreflightPostureDigest,
  expectedViewDefinitionSha256,
  sourceCommit,
  sourceTree,
  confirmation,
  operationId,
  journalIntent,
  createAdminClient = () => new Client(bootstrapDatabaseConfig({
    connectionString: adminConnectionString,
    max: 1,
    applicationName: "tideproof-managed-mcp-recovery-grant-repair"
  })),
  createReconciliationAdminClient = createAdminClient,
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  if (confirmation !== MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_CONFIRMATION_REQUIRED");
  }
  if (typeof journalIntent !== "function") {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_JOURNAL_REQUIRED");
  }
  if (typeof operationId !== "string" || !LOWERCASE_UUID.test(operationId)) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_OPERATION_ID_INVALID");
  }
  const binding = validateManagedMcpRecoveryGrantBinding({
    expectedRecoveryProviderClusterId,
    expectedRecoverySqlClusterId,
    expectedPreflightPostureDigest,
    expectedViewDefinitionSha256,
    sourceCommit,
    sourceTree,
    verifySourceCheckout
  });
  const target = recoveryConnectionTarget(
    adminConnectionString,
    expectedRecoveryHostname
  );

  const verificationOptions = (observation, createClient) => ({
      adminConnectionString,
      expectedRecoveryHostname,
      expectedRecoveryProviderClusterId: binding.providerClusterId,
      expectedRecoverySqlClusterId: binding.sqlClusterId,
      expectedPreflightPostureDigest:
        binding.expectedPreflightPostureDigest,
      expectedViewDefinitionSha256: binding.expectedViewDefinitionSha256,
      sourceCommit: binding.sourceCommit,
      sourceTree: binding.sourceTree,
      observation,
      createAdminClient: createClient,
      verifySourceCheckout
  });
  const preflight = await verifyManagedMcpRecoveryGrants(
    verificationOptions("read_only_verification", createReconciliationAdminClient)
  );
  if (preflight.posture.state === "PRESENT") {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_ALREADY_APPLIED");
  }
  if (preflight.posture.state !== "PUBLIC_VIEW_READY") {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_PUBLIC_VIEW_BASELINE_REQUIRED"
    );
  }
  if (
    preflight.posture.postureDigest !== binding.expectedPreflightPostureDigest
  ) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_PREFLIGHT_MISMATCH");
  }
  const expectedBaselineRecoveryPostureDigest = requiredSha256(
    preflight.posture.baselineRecoveryPostureDigest,
    "MANAGED_MCP_RECOVERY_BASELINE_DIGEST_INVALID"
  );
  const targetReservation = await reserveManagedMcpRecoveryTarget({
    binding,
    target,
    operationId,
    journalIntent
  });

  const dispatches = [];
  const steps = [
    Object.freeze({
      id: "REVOKE_PUBLIC_SCHEMA_USAGE_DEACTIVATE",
      statement: MANAGED_MCP_RECOVERY_GRANT_SQL[0],
      beforeState: "PUBLIC_VIEW_READY",
      afterState: "SELECT_ONLY"
    }),
    Object.freeze({
      id: "GRANT_PRIVATE_SCHEMA_USAGE_INACTIVE",
      statement: MANAGED_MCP_RECOVERY_GRANT_SQL[1],
      beforeState: "SELECT_ONLY",
      afterState: "PRIVATE_USAGE_AND_SELECT"
    }),
    Object.freeze({
      id: "GRANT_PUBLIC_SCHEMA_USAGE_REACTIVATE",
      statement: MANAGED_MCP_RECOVERY_GRANT_SQL[2],
      beforeState: "PRIVATE_USAGE_AND_SELECT",
      afterState: "PRESENT"
    })
  ];
  const emergencyDisable = async (cause) => {
    try {
      return await disableManagedMcpRecoveryGrants({
        adminConnectionString,
        expectedRecoveryHostname,
        expectedRecoveryProviderClusterId: binding.providerClusterId,
        expectedRecoverySqlClusterId: binding.sqlClusterId,
        expectedPreflightPostureDigest:
          binding.expectedPreflightPostureDigest,
        expectedViewDefinitionSha256:
          binding.expectedViewDefinitionSha256,
        sourceCommit: binding.sourceCommit,
        sourceTree: binding.sourceTree,
        confirmation: MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION,
        operationId,
        journalIntent,
        createAdminClient,
        createReconciliationAdminClient,
        verifySourceCheckout
      });
    } catch (disableError) {
      throw stablePublisherError(
        "MANAGED_MCP_RECOVERY_EMERGENCY_HOLD",
        new AggregateError([cause, disableError].filter(Boolean))
      );
    }
  };
  let currentState = preflight.posture.state;
  let finalVerification = preflight;
  for (const [index, step] of steps.entries()) {
    if (currentState !== step.beforeState) {
      throw stablePublisherError("MANAGED_MCP_RECOVERY_STEP_STATE_INVALID");
    }
    const intent = Object.freeze({
      schemaVersion: "tideproof.managed-mcp-recovery-grant-intent.v2",
      step: index + 1,
      stepId: step.id,
      operationId,
      statementSha256: sha256(step.statement),
      expectedBeforeState: step.beforeState,
      expectedAfterState: step.afterState,
      sourceCommit: binding.sourceCommit,
      sourceTree: binding.sourceTree,
      expectedPreflightPostureDigest:
        binding.expectedPreflightPostureDigest,
      expectedViewDefinitionSha256:
        binding.expectedViewDefinitionSha256,
      providerClusterIdSha256: sha256(binding.providerClusterId),
      sqlClusterIdSha256: sha256(binding.sqlClusterId),
      databaseName: target.databaseName,
      hostnameSha256: sha256(target.hostname),
      adminPrincipalSha256: sha256(target.username),
      targetReservationDigest: targetReservation.reservationDigest
    });
    const journal = await journalIntent(intent);
    const intentSha256 = sha256(JSON.stringify(intent));
    if (
      journal?.operationId !== operationId ||
      journal?.intentSha256 !== intentSha256 ||
      journal?.reservation !== "UNIQUE_RESERVED" ||
      journal?.targetReservationDigest !== targetReservation.reservationDigest
    ) {
      throw stablePublisherError("MANAGED_MCP_RECOVERY_JOURNAL_INVALID");
    }
    const journalDigest = requiredSha256(
      journal?.journalDigest,
      "MANAGED_MCP_RECOVERY_JOURNAL_INVALID"
    );

    const admin = createAdminClient(index);
    let acknowledged = false;
    let dispatchError = null;
    try {
      await admin.connect();
      await admin.query(step.statement);
      acknowledged = true;
    } catch (error) {
      dispatchError = error;
    } finally {
      await admin.end().catch(() => {});
    }

    try {
      finalVerification = await verifyManagedMcpRecoveryGrants(
        verificationOptions(
          acknowledged ? "direct_ack" : "read_reconciled",
          () => createReconciliationAdminClient(index)
        )
      );
    } catch (error) {
      const emergencyDisableReceipt = await emergencyDisable(
        new AggregateError([dispatchError, error].filter(Boolean))
      );
      const reconciliationError = stablePublisherError(
        "MANAGED_MCP_RECOVERY_RECONCILIATION_UNRESOLVED",
        new AggregateError([dispatchError, error].filter(Boolean))
      );
      reconciliationError.emergencyDisable = emergencyDisableReceipt;
      throw reconciliationError;
    }
    currentState = finalVerification.posture.state;
    dispatches.push(Object.freeze({
      step: index + 1,
      stepId: step.id,
      statementSha256: sha256(step.statement),
      intentSha256,
      journalDigest,
      acknowledged,
      observation: acknowledged ? "direct_ack" : "read_reconciled",
      observedState: currentState,
      observedPostureDigest: finalVerification.posture.postureDigest
    }));
    if (
      finalVerification.posture.baselineRecoveryPostureDigest !==
        expectedBaselineRecoveryPostureDigest
    ) {
      const emergencyDisableReceipt = await emergencyDisable(
        stablePublisherError("MANAGED_MCP_RECOVERY_BASELINE_DRIFT")
      );
      const error = stablePublisherError(
        "MANAGED_MCP_RECOVERY_BASELINE_DRIFT"
      );
      error.reconciliation = finalVerification;
      error.emergencyDisable = emergencyDisableReceipt;
      throw error;
    }
    if (currentState !== step.afterState) {
      let emergencyDisableReceipt = null;
      if (currentState !== "PUBLIC_VIEW_READY") {
        emergencyDisableReceipt = await emergencyDisable(dispatchError);
      }
      const error = stablePublisherError(
        currentState === step.beforeState
          ? "MANAGED_MCP_RECOVERY_DISPATCH_CONFIRMED_ABSENT"
          : "MANAGED_MCP_RECOVERY_DISPATCH_STATE_UNRESOLVED",
        dispatchError
      );
      error.reconciliation = finalVerification;
      if (emergencyDisableReceipt) {
        error.emergencyDisable = emergencyDisableReceipt;
      }
      throw error;
    }
  }

  return Object.freeze({
    ...finalVerification,
    mode: "APPLY_JOURNALED_RECONCILED",
    mutationStatementCount: 3,
    mutationDispatchCount: dispatches.length,
    mutationTransactionCount: 3,
    explicitMultiStatementTransactionUsed: false,
    preflightPostureDigest: preflight.posture.postureDigest,
    targetReservation,
    dispatches: Object.freeze(dispatches),
    claimBoundary:
      "This records three journaled implicit grant transactions with fresh-connection readback after each. It first revokes public-schema USAGE to deactivate the view, adds only non-grantable mcp_private schema USAGE while the view remains inactive, and regrants public-schema USAGE last to activate the exact preexisting public-view SELECT. It grants no private-relation, function, API-schema, database-wide, role, system, deployment, or release authority."
  });
}

export async function disableManagedMcpRecoveryGrants({
  adminConnectionString,
  expectedRecoveryHostname,
  expectedRecoveryProviderClusterId,
  expectedRecoverySqlClusterId,
  expectedPreflightPostureDigest,
  expectedViewDefinitionSha256,
  sourceCommit,
  sourceTree,
  confirmation,
  operationId,
  journalIntent,
  createAdminClient = () => new Client(bootstrapDatabaseConfig({
    connectionString: adminConnectionString,
    max: 1,
    applicationName: "tideproof-managed-mcp-recovery-grant-disable"
  })),
  createReconciliationAdminClient = createAdminClient,
  verifySourceCheckout = assertCleanExactGitCheckout
}) {
  if (confirmation !== MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION) {
    throw stablePublisherError(
      "MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION_REQUIRED"
    );
  }
  if (typeof journalIntent !== "function") {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_JOURNAL_REQUIRED");
  }
  if (typeof operationId !== "string" || !LOWERCASE_UUID.test(operationId)) {
    throw stablePublisherError("MANAGED_MCP_RECOVERY_OPERATION_ID_INVALID");
  }
  const binding = validateManagedMcpRecoveryGrantBinding({
    expectedRecoveryProviderClusterId,
    expectedRecoverySqlClusterId,
    expectedPreflightPostureDigest,
    expectedViewDefinitionSha256,
    sourceCommit,
    sourceTree,
    verifySourceCheckout
  });
  const target = recoveryConnectionTarget(
    adminConnectionString,
    expectedRecoveryHostname
  );
  const targetReservation = await reserveManagedMcpRecoveryTarget({
    binding,
    target,
    operationId,
    journalIntent
  });
  const verificationOptions = (observation, createClient) => ({
    adminConnectionString,
    expectedRecoveryHostname,
    expectedRecoveryProviderClusterId: binding.providerClusterId,
    expectedRecoverySqlClusterId: binding.sqlClusterId,
    expectedPreflightPostureDigest:
      binding.expectedPreflightPostureDigest,
    expectedViewDefinitionSha256: binding.expectedViewDefinitionSha256,
    sourceCommit: binding.sourceCommit,
    sourceTree: binding.sourceTree,
    observation,
    createAdminClient: createClient,
    verifySourceCheckout
  });
  const dispatches = [];
  let finalVerification = null;
  for (const [index, statement] of
    MANAGED_MCP_RECOVERY_ROLLBACK_SQL.entries()) {
    const intent = Object.freeze({
      schemaVersion: "tideproof.managed-mcp-recovery-disable-intent.v2",
      step: index + 1,
      operationId,
      stepId: [
        "REVOKE_PUBLIC_SCHEMA_USAGE_DEACTIVATE",
        "REVOKE_PRIVATE_SCHEMA_USAGE_CLEANUP",
        "GRANT_PUBLIC_SCHEMA_USAGE_RESTORE_BASELINE"
      ][index],
      statementSha256: sha256(statement),
      sourceCommit: binding.sourceCommit,
      sourceTree: binding.sourceTree,
      expectedPreflightPostureDigest:
        binding.expectedPreflightPostureDigest,
      expectedViewDefinitionSha256:
        binding.expectedViewDefinitionSha256,
      providerClusterIdSha256: sha256(binding.providerClusterId),
      sqlClusterIdSha256: sha256(binding.sqlClusterId),
      databaseName: target.databaseName,
      hostnameSha256: sha256(target.hostname),
      adminPrincipalSha256: sha256(target.username),
      targetReservationDigest: targetReservation.reservationDigest
    });
    const journal = await journalIntent(intent);
    const intentSha256 = sha256(JSON.stringify(intent));
    if (
      journal?.operationId !== operationId ||
      journal?.intentSha256 !== intentSha256 ||
      journal?.reservation !== "UNIQUE_RESERVED" ||
      journal?.targetReservationDigest !== targetReservation.reservationDigest
    ) {
      throw stablePublisherError("MANAGED_MCP_RECOVERY_JOURNAL_INVALID");
    }
    const journalDigest = requiredSha256(
      journal?.journalDigest,
      "MANAGED_MCP_RECOVERY_JOURNAL_INVALID"
    );
    const admin = createAdminClient(index);
    let acknowledged = false;
    let dispatchError = null;
    try {
      await admin.connect();
      await admin.query(statement);
      acknowledged = true;
    } catch (error) {
      dispatchError = error;
    } finally {
      await admin.end().catch(() => {});
    }
    try {
      finalVerification = await verifyManagedMcpRecoveryGrants(
        verificationOptions(
          acknowledged ? "direct_ack" : "read_reconciled",
          () => createReconciliationAdminClient(index)
        )
      );
    } catch (error) {
      const hold = stablePublisherError(
        "MANAGED_MCP_RECOVERY_EMERGENCY_HOLD",
        new AggregateError([dispatchError, error].filter(Boolean))
      );
      hold.disableDispatches = Object.freeze(dispatches);
      throw hold;
    }
    const acceptableStates = [
      new Set([
        "ABSENT",
        "SELECT_ONLY",
        "PRIVATE_SCHEMA_ONLY",
        "PRIVATE_USAGE_AND_SELECT"
      ]),
      new Set(["ABSENT", "SELECT_ONLY"]),
      new Set(["PUBLIC_SCHEMA_ONLY", "PUBLIC_VIEW_READY"])
    ][index];
    const acceptableState = acceptableStates.has(
      finalVerification.posture.state
    );
    dispatches.push(Object.freeze({
      step: index + 1,
      statementSha256: sha256(statement),
      intentSha256,
      journalDigest,
      acknowledged,
      observation: acknowledged ? "direct_ack" : "read_reconciled",
      observedState: finalVerification.posture.state,
      observedPostureDigest: finalVerification.posture.postureDigest
    }));
    if (!acceptableState) {
      const hold = stablePublisherError(
        "MANAGED_MCP_RECOVERY_EMERGENCY_HOLD",
        dispatchError
      );
      hold.reconciliation = finalVerification;
      hold.disableDispatches = Object.freeze(dispatches);
      throw hold;
    }
  }
  if (
    finalVerification.posture.postureDigest !==
      binding.expectedPreflightPostureDigest
  ) {
    const hold = stablePublisherError(
      "MANAGED_MCP_RECOVERY_EMERGENCY_HOLD"
    );
    hold.reconciliation = finalVerification;
    hold.disableDispatches = Object.freeze(dispatches);
    throw hold;
  }
  return Object.freeze({
    ...finalVerification,
    mode: "DISABLE_JOURNALED_RECONCILED",
    mutationStatementCount: 3,
    mutationDispatchCount: dispatches.length,
    mutationTransactionCount: 3,
    explicitMultiStatementTransactionUsed: false,
    targetReservation,
    dispatches: Object.freeze(dispatches),
    claimBoundary:
      "This records three-step capability-first restoration: public-schema USAGE is revoked first to deactivate the view, private-schema USAGE is removed while inactive, and public-schema USAGE is restored last. Fresh readback follows every step and the exact pre-repair public-view posture digest must be reproduced; no private-relation or function grant is introduced."
  });
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
    const managedMcpPrincipalPresent = preflight.posture.principals.some(
      (row) => row?.username === MANAGED_MCP_RECOVERY_PRINCIPAL
    );
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
    await scrubRecoveryPrivileges(client, { managedMcpPrincipalPresent });
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
    await scrubRecoveryPrivileges(client, { managedMcpPrincipalPresent });
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
    if (managedMcpPrincipalPresent) {
      for (const statement of MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL) {
        await client.query(statement);
      }
    }
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
