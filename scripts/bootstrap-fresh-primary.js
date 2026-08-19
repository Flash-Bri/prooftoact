import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OFFICIAL_REMOTE = "https://github.com/Flash-Bri/prooftoact.git";
const DATABASE_NAME = "tideproof";
const FRESH_BOOTSTRAP_USERNAME = "prooftoact_bootstrap_admin";
const FRESH_SQL_PORT = "26257";
const TRUSTED_GIT = "/usr/bin/git";
const FRESH_DATABASES = Object.freeze(["defaultdb", "postgres", "system"]);
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COCKROACH_SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const STATEFUL_TRANSITION_JOURNAL = Symbol(
  "prooftoact.stateful-transition-journal"
);
const PREIMPORT_BOUND_FILES = Object.freeze([
  "package-lock.json",
  "package.json",
  "scripts/bootstrap-fresh-primary.js",
  "scripts/fresh-cluster-aws-provider.js",
  "scripts/fresh-cluster-aws-runtime.js",
  "scripts/fresh-cluster-cloud-controller.js",
  "scripts/fresh-cluster-execution-runtime.js",
  "scripts/fresh-cluster-provider-controller.js",
  "scripts/fresh-primary-aws-provider.js",
  "scripts/fresh-primary-aws-runtime.js",
  "scripts/fresh-primary-provider-controller.js",
  "scripts/run-fresh-primary-provider.js",
  "scripts/run-fresh-cluster-provider.js",
  "scripts/lib/fresh-recovery-publisher-key.js",
  "scripts/gate2-aws-readiness.js",
  "scripts/lib/dependency-snapshot.js",
  "scripts/lib/exact-git-source.js",
  "scripts/lib/official-node-runtime.js",
  "src/cloud/atomic-create-only-file.js",
  "src/cloud/database-runtime.js",
  "src/cloud/primary-security.js"
]);

export const FRESH_PRIMARY_RUNTIME_USERS = Object.freeze([
  "tp_ingest_user",
  "tp_authorizer_user",
  "tp_gate2_authorizer_user",
  "tp_dispatch_user",
  "tp_recovery_source_user",
  "tp_recovery_audit_user",
  "tp_provider_claim_user",
  "tp_provider_begin_user",
  "tp_provider_redeem_user",
  "tp_provider_activate_user",
  "tp_provider_finalize_user",
  "tp_provider_terminalize_user",
  "tp_provider_reconcile_user",
  "tp_audit_user"
]);

const MANAGED_PRINCIPALS = Object.freeze([
  "tp_owner",
  ...FRESH_PRIMARY_RUNTIME_USERS,
  ...FRESH_PRIMARY_RUNTIME_USERS.map((name) => name.replace(/_user$/u, "_role"))
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
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
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function assertPrivateDirectory(directoryPath, code) {
  requireCondition(path.isAbsolute(directoryPath), code);
  const resolved = fs.realpathSync(directoryPath);
  const stat = fs.lstatSync(resolved);
  requireCondition(
    resolved === directoryPath &&
      stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === process.getuid() &&
      (stat.mode & 0o077) === 0,
    code
  );
  return resolved;
}

function readPrivateFile(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  const parent = assertPrivateDirectory(path.dirname(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() &&
        !before.isSymbolicLink() &&
        before.nlink === 1 &&
        before.uid === process.getuid() &&
        (before.mode & 0o077) === 0 &&
        before.size > 0 &&
        before.size <= maximumBytes &&
        path.dirname(filePath) === parent,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      bytes.length === before.size &&
        before.dev === after.dev &&
        before.ino === after.ino &&
        before.mode === after.mode &&
        before.size === after.size &&
        named.isFile() &&
        !named.isSymbolicLink() &&
        named.nlink === 1 &&
        named.dev === after.dev &&
        named.ino === after.ino &&
        named.mode === after.mode &&
        named.size === after.size,
      code
    );
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export function validateFreshPrimaryCredentialBundle(value) {
  const code = "FRESH_PRIMARY_CREDENTIAL_BUNDLE_REJECTED";
  requireCondition(
    exactKeys(value, [
      "passwords",
      "schemaVersion"
    ]) &&
      value.schemaVersion === "prooftoact.fresh-primary-credentials.v2" &&
      exactKeys(value.passwords, FRESH_PRIMARY_RUNTIME_USERS),
    code
  );
  const passwords = Object.values(value.passwords);
  requireCondition(
    passwords.every((password) =>
      typeof password === "string" &&
        password.length >= 32 &&
        password.length <= 256 &&
        !/[\u0000\r\n]/u.test(password)
    ) && new Set(passwords).size === passwords.length,
    code
  );
  return Object.freeze({
    schemaVersion: value.schemaVersion,
    passwords: Object.freeze({ ...value.passwords })
  });
}

export function validateFreshPrimaryCredentialSeal(value, binding) {
  const code = "FRESH_PRIMARY_CREDENTIAL_SEAL_REJECTED";
  requireCondition(
    exactKeys(value, [
      "credentialBundleRawSha256",
      "credentialBundleSha256",
      "immutableVersion",
      "operationId",
      "provider",
      "providerBacked",
      "runtimePolicySha256",
      "schemaVersion",
      "sealedAt",
      "secretArnSha256",
      "secretVersionIdSha256",
      "sourceCommit",
      "status",
      "treeDigest"
    ]) &&
      exactKeys(binding, [
        "credentialBundleRawSha256",
        "credentialBundleSha256",
        "operationId",
        "sourceCommit",
        "treeDigest"
      ]) &&
      value.schemaVersion === "prooftoact.fresh-primary-credential-seal.v1" &&
      value.status === "SEALED" &&
      value.provider === "AWS_SECRETS_MANAGER" &&
      value.providerBacked === true &&
      value.immutableVersion === true &&
      value.operationId === binding.operationId &&
      value.sourceCommit === binding.sourceCommit &&
      value.treeDigest === binding.treeDigest &&
      value.credentialBundleRawSha256 ===
        binding.credentialBundleRawSha256 &&
      value.credentialBundleSha256 === binding.credentialBundleSha256 &&
      [
        value.credentialBundleRawSha256,
        value.credentialBundleSha256,
        value.runtimePolicySha256,
        value.secretArnSha256,
        value.secretVersionIdSha256
      ].every((digest) => HEX_64.test(digest ?? "")) &&
      typeof value.sealedAt === "string" &&
      Number.isFinite(Date.parse(value.sealedAt)),
    code
  );
  return Object.freeze({ ...value });
}

export function validateFreshPrimaryApproval(value, binding, now = Date.now()) {
  const code = "FRESH_PRIMARY_APPROVAL_REJECTED";
  requireCondition(
    exactKeys(value, [
      "action",
      "approvalId",
      "approvedAt",
      "approvedBy",
      "clusterHostSha256",
      "credentialDisposition",
      "credentialSealReceiptSha256",
      "database",
      "expectedClusterId",
      "expiresAt",
      "maximumReservedExecutionMinutes",
      "maximumProjectedTotalUsd",
      "oneShot",
      "operationId",
      "outerApprovalExpiresAt",
      "outerAuthenticationReceiptSha256",
      "outerCommandSha256",
      "outerReservedAt",
      "outerReservationAcknowledgedAt",
      "outerReservationReceiptSha256",
      "partialFailureDisposition",
      "schemaVersion",
      "sourceCommit",
      "status",
      "treeDigest"
    ]) &&
      exactKeys(binding, [
        "clusterHostSha256",
        "credentialSealReceiptSha256",
        "operationId",
        "outerAuthenticationReceiptSha256",
        "outerCommandSha256",
        "outerReservedAt",
        "outerReservationAcknowledgedAt",
        "outerReservationReceiptSha256",
        "sourceCommit",
        "treeDigest"
      ]) &&
      value.schemaVersion === "prooftoact.fresh-primary-approval.v2" &&
      value.status === "APPROVED" &&
      value.action === "BOOTSTRAP_ONE_BOUND_FRESH_PRIMARY" &&
      value.approvedBy === "BRIAN_SMITH" &&
      value.oneShot === true &&
      value.database === DATABASE_NAME &&
      value.operationId === binding.operationId &&
      value.sourceCommit === binding.sourceCommit &&
      value.treeDigest === binding.treeDigest &&
      value.clusterHostSha256 === binding.clusterHostSha256 &&
      value.credentialSealReceiptSha256 ===
        binding.credentialSealReceiptSha256 &&
      value.outerReservationReceiptSha256 ===
        binding.outerReservationReceiptSha256 &&
      value.outerAuthenticationReceiptSha256 ===
        binding.outerAuthenticationReceiptSha256 &&
      value.outerCommandSha256 === binding.outerCommandSha256 &&
      value.outerReservedAt === binding.outerReservedAt &&
      value.outerReservationAcknowledgedAt ===
        binding.outerReservationAcknowledgedAt &&
      UUID.test(value.approvalId ?? "") &&
      COCKROACH_SQL_CLUSTER_ID.test(value.expectedClusterId ?? "") &&
      HEX_64.test(value.clusterHostSha256 ?? "") &&
      HEX_64.test(value.credentialSealReceiptSha256 ?? "") &&
      HEX_64.test(value.outerReservationReceiptSha256 ?? "") &&
      HEX_64.test(value.outerAuthenticationReceiptSha256 ?? "") &&
      HEX_64.test(value.outerCommandSha256 ?? "") &&
      value.maximumReservedExecutionMinutes === 45 &&
      Number.isFinite(value.maximumProjectedTotalUsd) &&
      value.maximumProjectedTotalUsd >= 0 &&
      value.maximumProjectedTotalUsd <= 12 &&
      value.credentialDisposition ===
        "REQUIRE_PROVIDER_SEAL_THEN_UNLINK_LOCAL_COPY_BEFORE_MUTATION" &&
      value.partialFailureDisposition ===
        "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD" &&
      typeof value.approvedAt === "string" &&
      typeof value.expiresAt === "string" &&
      typeof value.outerApprovalExpiresAt === "string",
    code
  );
  const approvedAt = Date.parse(value.approvedAt);
  const expiresAt = Date.parse(value.expiresAt);
  const outerApprovalExpiresAt = Date.parse(value.outerApprovalExpiresAt);
  const outerReservationAcknowledgedAt = Date.parse(
    value.outerReservationAcknowledgedAt
  );
  requireCondition(
    Number.isFinite(now) &&
      Number.isFinite(approvedAt) &&
      Number.isFinite(expiresAt) &&
      Number.isFinite(outerApprovalExpiresAt) &&
      Number.isFinite(outerReservationAcknowledgedAt) &&
      value.approvedAt === new Date(approvedAt).toISOString() &&
      value.expiresAt === new Date(expiresAt).toISOString() &&
      value.outerApprovalExpiresAt ===
        new Date(outerApprovalExpiresAt).toISOString() &&
      value.outerReservedAt === value.approvedAt &&
      value.outerReservationAcknowledgedAt ===
        new Date(outerReservationAcknowledgedAt).toISOString() &&
      approvedAt <= outerReservationAcknowledgedAt &&
      outerReservationAcknowledgedAt < outerApprovalExpiresAt &&
      approvedAt < outerApprovalExpiresAt &&
      approvedAt <= now &&
      now < expiresAt &&
      expiresAt - approvedAt === 45 * 60 * 1000,
    code
  );
  return Object.freeze({ ...value });
}

export function validateFreshClusterAdminConnectionString(value) {
  const code = "FRESH_PRIMARY_ADMIN_URL_REJECTED";
  let parsed;
  try {
    parsed = new URL(value);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    ["postgres:", "postgresql:"].includes(parsed.protocol) &&
      decodeURIComponent(parsed.username) === FRESH_BOOTSTRAP_USERNAME &&
      parsed.password.length > 0 &&
      parsed.hostname.endsWith(".cockroachlabs.cloud") &&
      parsed.port === FRESH_SQL_PORT &&
      ["/defaultdb", "/postgres"].includes(parsed.pathname) &&
      parsed.hash === "" &&
      [...parsed.searchParams.keys()].join("\n") === "sslmode" &&
      parsed.searchParams.get("sslmode") === "verify-full",
    code
  );
  return Object.freeze({
    connectionString: parsed.toString(),
    hostSha256: sha256(parsed.hostname),
    username: decodeURIComponent(parsed.username),
    usernameSha256: sha256(decodeURIComponent(parsed.username)),
    port: parsed.port,
    sourceDatabase: parsed.pathname.slice(1)
  });
}

function rowValue(row, names) {
  for (const name of names) {
    if (typeof row?.[name] === "string") return row[name];
  }
  return null;
}

function normalizedShowUsersArray(value) {
  let items;
  if (Array.isArray(value)) {
    items = value;
  } else if (value === "{}") {
    items = [];
  } else if (typeof value === "string" && /^\{[^{}]*\}$/u.test(value)) {
    items = value.slice(1, -1).split(",").filter((item) => item !== "");
  } else {
    reject("FRESH_PRIMARY_SHOW_USERS_POSTURE_REJECTED");
  }
  requireCondition(items.every((item) => typeof item === "string" &&
    /^[A-Za-z_][A-Za-z0-9_=-]{0,127}$/u.test(item)) &&
    new Set(items).size === items.length,
  "FRESH_PRIMARY_SHOW_USERS_POSTURE_REJECTED");
  return Object.freeze([...items].sort());
}

function validateFreshPreflightPrincipalPosture(rows, bootstrapPrincipal) {
  const posture = rows.map((row) => Object.freeze({
    roleName: rowValue(row, ["username", "user_name", "name"]),
    options: normalizedShowUsersArray(row.options),
    memberOf: normalizedShowUsersArray(row.member_of)
  })).sort((left, right) => left.roleName.localeCompare(right.roleName));
  const expectedNames = ["admin", bootstrapPrincipal, "root"].sort();
  const byName = new Map(posture.map((row) => [row.roleName, row]));
  requireCondition(
    posture.length === expectedNames.length &&
      JSON.stringify(posture.map(({ roleName }) => roleName)) ===
        JSON.stringify(expectedNames) &&
      JSON.stringify(byName.get("admin")?.options) === JSON.stringify([]) &&
      JSON.stringify(byName.get("admin")?.memberOf) === JSON.stringify([]) &&
      JSON.stringify(byName.get("root")?.options) === JSON.stringify([]) &&
      JSON.stringify(byName.get("root")?.memberOf) ===
        JSON.stringify(["admin"]) &&
      JSON.stringify(byName.get(bootstrapPrincipal)?.options) ===
        JSON.stringify([]) &&
      JSON.stringify(byName.get(bootstrapPrincipal)?.memberOf) ===
        JSON.stringify(["admin"]),
    "FRESH_PRIMARY_SHOW_USERS_POSTURE_REJECTED"
  );
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-primary-preflight-principal-posture.v1",
    status: "EXACT_SHOW_USERS_PRESTATE",
    builtinAdminRolePresent: true,
    exactPrincipalCount: posture.length,
    fullPrincipalCensusSha256: sha256(canonicalBytes(posture)),
    rootCanLogin: true,
    rootOptions: Object.freeze([]),
    rootOptionsSha256: sha256(canonicalBytes([]))
  });
}

export function freshPrimaryIntent({
  approvalId,
  expectedClusterId,
  operationId,
  sourceCommit,
  treeDigest,
  hostSha256
}) {
  requireCondition(
    UUID.test(approvalId ?? "") &&
      COCKROACH_SQL_CLUSTER_ID.test(expectedClusterId ?? "") &&
      UUID.test(operationId ?? "") &&
      HEX_40.test(sourceCommit ?? "") &&
      HEX_40.test(treeDigest ?? "") &&
      HEX_64.test(hostSha256 ?? ""),
    "FRESH_PRIMARY_INTENT_REJECTED"
  );
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-primary-bootstrap-intent.v1",
    approvalId,
    operationId,
    sourceCommit,
    treeDigest,
    target: Object.freeze({
      database: DATABASE_NAME,
      clusterHostSha256: hostSha256,
      expectedClusterId,
      exactFreshDatabases: FRESH_DATABASES,
      requireDatabaseAbsent: true,
      requireManagedPrincipalsAbsent: true,
      requireNoUserTables: true
    }),
    mutationBoundary:
      "Create one fresh ProofToAct database and its fixed managed principals only after exact cluster identity, database, principal, and user-table census checks pass under a one-shot approval. Never migrate, overwrite, reuse, or blindly retry. Any dispatched partial or ambiguous run is UNKNOWN_DO_NOT_RETRY until independently reconciled or the dedicated cluster is discarded."
  });
}

function exactStringSet(values, expected) {
  return Array.isArray(values) &&
    values.every((value) => typeof value === "string") &&
    new Set(values).size === values.length &&
    JSON.stringify([...values].sort()) === JSON.stringify([...expected].sort());
}

function validateManagedRoleResult(roles) {
  const usernames = Array.isArray(roles)
    ? roles.map((row) => rowValue(row, ["username"]))
    : null;
  requireCondition(
    exactStringSet(usernames, MANAGED_PRINCIPALS),
    "FRESH_PRIMARY_BOOTSTRAP_MANAGED_ROLE_SET_REJECTED"
  );
  return usernames;
}

function partialFailure(cause, phase, clusterId) {
  const error = new Error(
    "FRESH_PRIMARY_PARTIAL_FAILURE_UNKNOWN_DO_NOT_RETRY",
    { cause }
  );
  error.disposition = Object.freeze({
    clusterIdSha256: typeof clusterId === "string" ? sha256(clusterId) : null,
    phase,
    retryAllowed: false,
    status: "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD"
  });
  return error;
}

async function runFreshPrimaryBootstrap({
  adminConnectionString,
  approval,
  approvalNow = Date.now(),
  bootstrap,
  bootstrapDatabaseConfig,
  clientFactory,
  connectionStringForUser,
  credentialBundle,
  credentialBundleRawSha256,
  credentialBundleSha256,
  credentialSeal,
  databaseEnvironment = process.env,
  discardAdminCredential,
  localCredentialDiscarded,
  operationId,
  recoveryPublisherTrustRoot,
  runtimeDatabaseConfig,
  sourceCommit,
  transitionJournal,
  treeDigest
}) {
  requireCondition(
    typeof bootstrap === "function" &&
      typeof bootstrapDatabaseConfig === "function" &&
      typeof clientFactory === "function" &&
      typeof connectionStringForUser === "function" &&
      typeof discardAdminCredential === "function" &&
      typeof runtimeDatabaseConfig === "function" &&
      transitionJournal?.[STATEFUL_TRANSITION_JOURNAL] === true &&
      typeof transitionJournal.record === "function" &&
      localCredentialDiscarded === true,
    "FRESH_PRIMARY_BOUND_DEPENDENCIES_REJECTED"
  );
  const bundle = validateFreshPrimaryCredentialBundle(credentialBundle);
  requireCondition(
    exactKeys(recoveryPublisherTrustRoot, [
      "publisherKeyIdSha256",
      "publisherKeySetDigest",
      "signerSecretArnSha256",
      "signerSecretSealReceiptSha256",
      "signerSecretValueSha256",
      "signerSecretVersionIdSha256",
      "trustRootCommitment",
      "trustRootJsonSha256"
    ]) && Object.values(recoveryPublisherTrustRoot).every((value) =>
      HEX_64.test(value ?? "")),
    "FRESH_PRIMARY_RECOVERY_PUBLISHER_TRUST_ROOT_REJECTED"
  );
  requireCondition(
    HEX_64.test(credentialBundleRawSha256 ?? "") &&
      HEX_64.test(credentialBundleSha256 ?? "") &&
      credentialBundleSha256 === sha256(canonicalBytes(bundle)),
    "FRESH_PRIMARY_CREDENTIAL_DIGEST_REJECTED"
  );
  const admin = validateFreshClusterAdminConnectionString(
    adminConnectionString
  );
  const seal = validateFreshPrimaryCredentialSeal(credentialSeal, {
    credentialBundleRawSha256,
    credentialBundleSha256,
    operationId,
    sourceCommit,
    treeDigest
  });
  const acceptedApproval = validateFreshPrimaryApproval(approval, {
    clusterHostSha256: admin.hostSha256,
    credentialSealReceiptSha256: sha256(canonicalBytes(seal)),
    operationId,
    outerAuthenticationReceiptSha256:
      approval?.outerAuthenticationReceiptSha256,
    outerCommandSha256: approval?.outerCommandSha256,
    outerReservedAt: approval?.outerReservedAt,
    outerReservationAcknowledgedAt:
      approval?.outerReservationAcknowledgedAt,
    outerReservationReceiptSha256:
      approval?.outerReservationReceiptSha256,
    sourceCommit,
    treeDigest
  }, approvalNow);
  const intent = freshPrimaryIntent({
    approvalId: acceptedApproval.approvalId,
    expectedClusterId: acceptedApproval.expectedClusterId,
    operationId,
    sourceCommit,
    treeDigest,
    hostSha256: admin.hostSha256
  });
  const intentBytes = canonicalBytes(intent);
  const adminClient = clientFactory(bootstrapDatabaseConfig({
    connectionString: admin.connectionString,
    max: 1,
    applicationName: "prooftoact-fresh-primary-preflight",
    environment: databaseEnvironment
  }), "admin");
  let mutationDispatched = false;
  let phase = "PREFLIGHT_NOT_STARTED";
  let clusterId;
  let serverVersion;
  let preflightPrincipalPosture;
  let adminCredentialDiscarded = false;
  const transition = (phaseName, payload) =>
    transitionJournal.record(phaseName, payload);
  try {
    phase = "PREFLIGHT_STARTED";
    await transition(phase, { mutationDispatched: false });
    await adminClient.connect();
    const versionResult = await adminClient.query(
      "SELECT version() AS server_version"
    );
    serverVersion = rowValue(versionResult.rows?.[0], ["server_version"]);
    requireCondition(
      typeof serverVersion === "string" &&
        /^CockroachDB CCL v26\.2(?:\.[0-9]+)?\b/u.test(serverVersion),
      "FRESH_PRIMARY_SERVER_VERSION_REJECTED"
    );
    const identityResult = await adminClient.query(`
      SELECT
        crdb_internal.cluster_id()::STRING AS cluster_id,
        current_user::STRING AS current_user_name,
        current_database()::STRING AS database_name
    `);
    const adminIdentity = identityResult.rows?.[0];
    clusterId = adminIdentity?.cluster_id;
    requireCondition(
      clusterId === acceptedApproval.expectedClusterId &&
        adminIdentity?.current_user_name === admin.username &&
        adminIdentity?.database_name === admin.sourceDatabase,
      "FRESH_PRIMARY_CLUSTER_IDENTITY_REJECTED"
    );

    const databaseResult = await adminClient.query("SHOW DATABASES");
    const databases = databaseResult.rows.map((row) =>
      rowValue(row, ["database_name", "database"])
    );
    requireCondition(
      exactStringSet(databases, FRESH_DATABASES),
      "FRESH_PRIMARY_DATABASE_CENSUS_REJECTED"
    );

    const usersResult = await adminClient.query("SHOW USERS");
    preflightPrincipalPosture = validateFreshPreflightPrincipalPosture(
      usersResult.rows,
      admin.username
    );

    for (const database of ["defaultdb", "postgres"]) {
      const tableResult = await adminClient.query(`SHOW TABLES FROM ${database}`);
      requireCondition(
        Array.isArray(tableResult.rows) && tableResult.rows.length === 0,
        "FRESH_PRIMARY_USER_TABLE_CENSUS_REJECTED"
      );
    }
    phase = "PREFLIGHT_ACCEPTED";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      databaseCensusSha256: sha256(canonicalBytes(databases.sort())),
      mutationDispatched: false,
      principalCensusSha256:
        preflightPrincipalPosture.fullPrincipalCensusSha256,
      preflightPrincipalPostureSha256:
        sha256(canonicalBytes(preflightPrincipalPosture))
    });

    phase = "ADMIN_CREDENTIAL_DISCARDING";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      mutationDispatched: false
    });
    adminCredentialDiscarded = await discardAdminCredential() === true;
    requireCondition(
      adminCredentialDiscarded,
      "FRESH_PRIMARY_ADMIN_CREDENTIAL_DISCARD_FAILED"
    );
    phase = "ADMIN_CREDENTIAL_DISCARDED";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      localAdminUrlFileRetained: false,
      mutationDispatched: false
    });

    phase = "CREATE_DATABASE_DISPATCHING";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      mutationDispatched: true
    });
    mutationDispatched = true;
    await adminClient.query(`CREATE DATABASE ${DATABASE_NAME}`);
    phase = "DATABASE_CREATED";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      mutationDispatched: true
    });
  } catch (cause) {
    if (mutationDispatched) throw partialFailure(cause, phase, clusterId);
    throw cause;
  } finally {
    await adminClient.end().catch(() => {});
  }

  let bootstrapResult;
  try {
    phase = "SECURITY_BOOTSTRAP_DISPATCHING";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      mutationDispatched: true
    });
    bootstrapResult = await bootstrap({
      adminConnectionString: admin.connectionString,
      passwords: bundle.passwords,
      recoveryPublisherTrustRootCommitment:
        recoveryPublisherTrustRoot.trustRootCommitment,
      recoveryPublisherKeySetDigest:
        recoveryPublisherTrustRoot.publisherKeySetDigest
    });
    requireCondition(
      exactKeys(bootstrapResult, [
        "clusterFinalPostureDigest",
        "clusterPreflightPostureDigest",
        "finalPostureDigest",
        "principalLoginPosture",
        "preflightPostureDigest",
        "roles"
      ]) &&
        [
          bootstrapResult.clusterFinalPostureDigest,
          bootstrapResult.clusterPreflightPostureDigest,
          bootstrapResult.finalPostureDigest,
          bootstrapResult.preflightPostureDigest
        ].every((digest) => HEX_64.test(digest ?? "")),
      "FRESH_PRIMARY_BOOTSTRAP_RESULT_REJECTED"
    );
    requireCondition(exactKeys(bootstrapResult.principalLoginPosture, [
      "builtinAdminOptionsSha256", "builtinAdminRolePresent",
      "bootstrapPrincipal",
      "bootstrapPrincipalCanLogin", "bootstrapPrincipalOptionsSha256",
      "capabilityNoLoginCount", "databaseObservedAt", "exactPrincipalCount",
      "fullPrincipalCensusSha256", "immutableBuiltinAdminRoleExceptionPresent",
      "rootCanLogin", "rootMemberOfSha256", "rootNoLoginProvedFromShowUsers",
      "rootOptions", "rootOptionsSha256", "runtimeLoginCount",
      "schemaVersion", "status"
    ]) && bootstrapResult.principalLoginPosture.schemaVersion ===
        "prooftoact.primary-principal-login-posture.v2" &&
      bootstrapResult.principalLoginPosture.status ===
        "EXACT_COMPLETE_SHOW_USERS_LOGIN_POSTURE" &&
      bootstrapResult.principalLoginPosture.bootstrapPrincipal ===
        admin.username &&
      bootstrapResult.principalLoginPosture.bootstrapPrincipalCanLogin ===
        true && bootstrapResult.principalLoginPosture.rootCanLogin === false &&
      bootstrapResult.principalLoginPosture.rootNoLoginProvedFromShowUsers ===
        true &&
      bootstrapResult.principalLoginPosture.builtinAdminRolePresent === true &&
      bootstrapResult.principalLoginPosture
        .immutableBuiltinAdminRoleExceptionPresent === true &&
      JSON.stringify(bootstrapResult.principalLoginPosture.rootOptions) ===
        JSON.stringify(["NOLOGIN"]) &&
      bootstrapResult.principalLoginPosture.runtimeLoginCount ===
        FRESH_PRIMARY_RUNTIME_USERS.length &&
      bootstrapResult.principalLoginPosture.capabilityNoLoginCount === 15 &&
      bootstrapResult.principalLoginPosture.exactPrincipalCount === 32 &&
      [
        bootstrapResult.principalLoginPosture.builtinAdminOptionsSha256,
        bootstrapResult.principalLoginPosture.bootstrapPrincipalOptionsSha256,
        bootstrapResult.principalLoginPosture.fullPrincipalCensusSha256,
        bootstrapResult.principalLoginPosture.rootMemberOfSha256,
        bootstrapResult.principalLoginPosture.rootOptionsSha256
      ].every((value) => HEX_64.test(value ?? "")) &&
      Number.isFinite(Date.parse(
        bootstrapResult.principalLoginPosture.databaseObservedAt)),
    "FRESH_PRIMARY_LOGIN_POSTURE_REJECTED");
    validateManagedRoleResult(bootstrapResult.roles);
    phase = "SECURITY_BOOTSTRAPPED";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      finalPostureDigest: bootstrapResult.finalPostureDigest,
      mutationDispatched: true
    });
  } catch (cause) {
    throw partialFailure(cause, phase, clusterId);
  }

  const gate2ConnectionString = connectionStringForUser(
    admin.connectionString,
    "tp_gate2_authorizer_user",
    bundle.passwords.tp_gate2_authorizer_user,
    DATABASE_NAME
  );
  const gate2Client = clientFactory(runtimeDatabaseConfig({
    connectionString: gate2ConnectionString,
    max: 1,
    idleTimeoutMillis: 5_000,
    applicationName: "prooftoact-fresh-primary-postflight",
    environment: databaseEnvironment
  }), "gate2");
  let identity;
  let directTableDenied = false;
  try {
    phase = "POSTFLIGHT_STARTED";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      mutationDispatched: true
    });
    await gate2Client.connect();
    const identityResult = await gate2Client.query(`
      SELECT
        session_user::STRING AS session_user_name,
        current_user::STRING AS current_user_name,
        current_database()::STRING AS database_name,
        crdb_internal.cluster_id()::STRING AS cluster_id,
        clock_timestamp()::STRING AS database_now
    `);
    identity = identityResult.rows?.[0];
    requireCondition(
      identity?.session_user_name === "tp_gate2_authorizer_user" &&
        identity?.current_user_name === "tp_gate2_authorizer_user" &&
        identity?.database_name === DATABASE_NAME &&
        identity?.cluster_id === clusterId &&
        typeof identity?.database_now === "string" &&
        Number.isFinite(Date.parse(identity.database_now)),
      "FRESH_PRIMARY_RUNTIME_IDENTITY_REJECTED"
    );
    try {
      await gate2Client.query(
        "SELECT tenant_id FROM tp_private.g1_evidence LIMIT 1"
      );
    } catch (error) {
      directTableDenied = error?.code === "42501";
    }
    requireCondition(
      directTableDenied,
      "FRESH_PRIMARY_DIRECT_TABLE_ACCESS_NOT_DENIED"
    );
    phase = "ACCEPTED";
    await transition(phase, {
      clusterIdSha256: sha256(clusterId),
      mutationDispatched: true,
      runtimeIdentitySha256: sha256(identity.session_user_name)
    });
  } catch (cause) {
    throw partialFailure(cause, phase, clusterId);
  } finally {
    await gate2Client.end().catch(() => {});
  }

  return Object.freeze({
    schemaVersion: "prooftoact.fresh-primary-bootstrap-receipt.v3",
    status: "PASS",
    approvalId: acceptedApproval.approvalId,
    operationId,
    sourceCommit,
    treeDigest,
    intentSha256: sha256(intentBytes),
    credentialLifecycle: Object.freeze({
      adminUrlLocalCopyDiscardedBeforeMutation: adminCredentialDiscarded,
      credentialBundleRawSha256,
      credentialBundleSha256,
      localCopyDiscardedBeforeMutation: true,
      callerSuppliedSealReceiptSha256: sha256(canonicalBytes(seal)),
      recoveryPublisher: Object.freeze({ ...recoveryPublisherTrustRoot }),
      providerReadbackAuthenticatedByThisModule: false,
      providerRevocationValidatedByThisModule: false,
      rootCredentialLifecycle: Object.freeze({
        connectionStringCreated: false,
        connectionStringUsed: false,
        passwordCreated: false,
        secretStored: false
      })
    }),
    provider: Object.freeze({
      database: DATABASE_NAME,
      clusterHostSha256: admin.hostSha256,
      clusterIdSha256: sha256(clusterId),
      serverVersion,
      serverVersionSha256: sha256(serverVersion)
    }),
    preflight: Object.freeze({
      exactDatabaseCensus: FRESH_DATABASES,
      managedPrincipalCount: 0,
      principalPosture: preflightPrincipalPosture,
      principalPostureSha256: sha256(canonicalBytes(
        preflightPrincipalPosture
      )),
      userTableCount: 0
    }),
    bootstrap: Object.freeze({
      preflightPostureDigest: bootstrapResult.preflightPostureDigest,
      finalPostureDigest: bootstrapResult.finalPostureDigest,
      clusterPreflightPostureDigest:
        bootstrapResult.clusterPreflightPostureDigest,
      clusterFinalPostureDigest: bootstrapResult.clusterFinalPostureDigest,
      managedRoleCount: bootstrapResult.roles.length,
      managedRoleSetSha256: sha256(canonicalBytes([...MANAGED_PRINCIPALS].sort())),
      principalLoginPosture: bootstrapResult.principalLoginPosture,
      principalLoginPostureSha256:
        sha256(canonicalBytes(bootstrapResult.principalLoginPosture))
    }),
    postflight: Object.freeze({
      databaseTime: identity.database_now,
      directPrivateTableAccessDenied: true,
      runtimeDatabase: identity.database_name,
      runtimeIdentity: identity.session_user_name
    }),
    partialFailureDisposition:
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD",
    claimBoundary:
      "This receipt proves one caller-supplied fresh-cluster census, the exact complete SHOW USERS prestate, one exact 32-row SHOW USERS post-bootstrap posture with root plus 15 ProofToAct capability roles set NOLOGIN and 14 runtime users LOGIN, no ProofToAct root password, secret, or connection string created or used, local credential-file discard, a separately sealed fresh recovery-publisher trust-root binding, and one least-privilege Gate Two runtime identity check for the bound source and dependency closure. CockroachDB's immutable built-in admin role remains a provider-managed exception; the claim is no application-retained SQL administrator after the nested controller deletes the bootstrap principal, not no administrative control path. The nested provider controller independently authenticates the exact Secrets Manager versions and fresh signer seal. This receipt does not prove DVI execution, Lambda deployment or overlap, Managed MCP, an integrated live drill, public availability, teardown, provider-key revocation, or final release acceptance."
  });
}

function createProviderTransitionJournal(recordTransition) {
  requireCondition(
    typeof recordTransition === "function",
    "FRESH_PRIMARY_PROVIDER_TRANSITION_REJECTED"
  );
  return Object.freeze({
    [STATEFUL_TRANSITION_JOURNAL]: true,
    record: recordTransition
  });
}

async function runFreshPrimaryProviderControlledBootstrapWithRuntime({
  adminConnectionString,
  approval,
  approvalNow = Date.now(),
  clock = Date.now,
  command,
  credentialBundle,
  credentialBundleRawSha256,
  credentialBundleSha256,
  credentialSeal,
  databaseEnvironment = process.env,
  discardAdminCredential,
  localCredentialDiscarded,
  operationId,
  provider,
  recoveryPublisherSecret,
  runtime,
  sourceCommit,
  treeDigest
}) {
  requireCondition(
    command?.sourceCommit === sourceCommit &&
      command?.treeDigest === treeDigest &&
      command?.operationId === operationId &&
      command?.approvalId === approval?.approvalId &&
      command?.sqlClusterId === approval?.expectedClusterId &&
      command?.approvalSha256 === sha256(canonicalBytes(approval)) &&
      command?.outerAuthenticationReceiptSha256 ===
        approval?.outerAuthenticationReceiptSha256 &&
      command?.outerCommandSha256 === approval?.outerCommandSha256 &&
      command?.outerReservedAt === approval?.outerReservedAt &&
      command?.outerReservationAcknowledgedAt ===
        approval?.outerReservationAcknowledgedAt &&
      command?.outerReservationReceiptSha256 ===
        approval?.outerReservationReceiptSha256 &&
      command?.adminSecretValueSha256 === sha256(adminConnectionString) &&
      command?.credentialBundleRawSha256 === credentialBundleRawSha256 &&
      command?.credentialBundleSha256 === credentialBundleSha256 &&
      command?.credentialBundleSha256 ===
        sha256(canonicalBytes(credentialBundle)) &&
      command?.credentialSealReceiptSha256 ===
        sha256(canonicalBytes(credentialSeal)) &&
      command?.credentialSecretArnSha256 === credentialSeal?.secretArnSha256 &&
      command?.credentialSecretVersionIdSha256 ===
        credentialSeal?.secretVersionIdSha256 &&
      command?.credentialBundleRawSha256 ===
        credentialSeal?.credentialBundleRawSha256 &&
      command?.credentialBundleSha256 ===
        credentialSeal?.credentialBundleSha256 &&
      recoveryPublisherSecret?.secretBytesSha256 ===
        command?.signerSecretValueSha256 &&
      recoveryPublisherSecret?.trustRootJsonSha256 ===
        command?.trustRootJsonSha256 &&
      recoveryPublisherSecret?.trustRootCommitment ===
        command?.recoveryPublisherTrustRootCommitment &&
      recoveryPublisherSecret?.publisherKeySetDigest ===
        command?.recoveryPublisherKeySetDigest &&
      typeof provider?.sealRecoveryPublisherSecret === "function" &&
      runtime && [
        "bootstrap",
        "bootstrapDatabaseConfig",
        "clientFactory",
        "connectionStringForUser",
        "runtimeDatabaseConfig"
      ].every((name) => typeof runtime[name] === "function"),
    "FRESH_PRIMARY_PROVIDER_BINDING_REJECTED"
  );
  // This controller is imported only after the public entry point has bound
  // its exact bytes with the rest of the pre-import helper closure. Tests use
  // the same path with injected non-provider dependencies.
  const { runFreshPrimaryProviderController } = await import(
    "./fresh-primary-provider-controller.js"
  );
  return runFreshPrimaryProviderController({
    clock,
    command,
    provider,
    dispatch: async ({ recordTransition }) => {
      await recordTransition("SIGNER_SECRET_DISPATCHING", {
        mutationDispatched: true,
        signerSecretArnSha256: command.signerSecretArnSha256,
        signerSecretVersionIdSha256: command.signerSecretVersionIdSha256
      });
      const signerSeal = await provider.sealRecoveryPublisherSecret({
        command,
        secret: recoveryPublisherSecret
      });
      requireCondition(
        exactKeys(signerSeal, [
          "createdAt",
          "immutableVersion",
          "provider",
          "providerBacked",
          "schemaVersion",
          "secretArnSha256",
          "secretValueSha256",
          "secretVersionIdSha256",
          "status"
        ]) &&
          signerSeal.schemaVersion ===
            "prooftoact.fresh-recovery-publisher-secret-seal.v1" &&
          signerSeal.status === "SEALED" &&
          signerSeal.provider === "AWS_SECRETS_MANAGER" &&
          signerSeal.providerBacked === true &&
          signerSeal.immutableVersion === true &&
          signerSeal.secretArnSha256 === command.signerSecretArnSha256 &&
          signerSeal.secretVersionIdSha256 ===
            command.signerSecretVersionIdSha256 &&
          signerSeal.secretValueSha256 === command.signerSecretValueSha256,
        "FRESH_PRIMARY_RECOVERY_PUBLISHER_SEAL_REJECTED"
      );
      const signerSecretSealReceiptSha256 = sha256(canonicalBytes(signerSeal));
      await recordTransition("SIGNER_SECRET_SEALED", {
        mutationDispatched: true,
        signerSecretSealReceiptSha256
      });
      return runFreshPrimaryBootstrap({
        adminConnectionString,
        approval,
        approvalNow,
        bootstrap: runtime.bootstrap,
        bootstrapDatabaseConfig: runtime.bootstrapDatabaseConfig,
        clientFactory: runtime.clientFactory,
        connectionStringForUser: runtime.connectionStringForUser,
        credentialBundle,
        credentialBundleRawSha256,
        credentialBundleSha256,
        credentialSeal,
        databaseEnvironment,
        discardAdminCredential,
        localCredentialDiscarded,
        operationId,
        recoveryPublisherTrustRoot: {
          publisherKeyIdSha256: sha256(recoveryPublisherSecret.publisherKeyId),
          publisherKeySetDigest:
            recoveryPublisherSecret.publisherKeySetDigest,
          signerSecretArnSha256: command.signerSecretArnSha256,
          signerSecretSealReceiptSha256,
          signerSecretValueSha256: command.signerSecretValueSha256,
          signerSecretVersionIdSha256: command.signerSecretVersionIdSha256,
          trustRootCommitment:
            recoveryPublisherSecret.trustRootCommitment,
          trustRootJsonSha256: recoveryPublisherSecret.trustRootJsonSha256
        },
        runtimeDatabaseConfig: runtime.runtimeDatabaseConfig,
        sourceCommit,
        transitionJournal: createProviderTransitionJournal(recordTransition),
        treeDigest
      });
    }
  });
}

export async function runFreshPrimaryProviderControlledBootstrap({
  buildReceipt,
  expectedCommit,
  expectedTree,
  ...input
}) {
  const source = preliminaryExactSourceBinding(expectedCommit, expectedTree);
  const runtime = await loadBoundRuntime({ buildReceipt, source });
  return runFreshPrimaryProviderControlledBootstrapWithRuntime({
    ...input,
    runtime,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
}

export async function verifyFreshPrimaryProviderPrerequisites({
  buildReceipt,
  expectedCommit,
  expectedTree
}) {
  const source = preliminaryExactSourceBinding(expectedCommit, expectedTree);
  const runtime = await loadBoundRuntime({ buildReceipt, source });
  return Object.freeze({
    dependencyTreeSha256: runtime.dependencyTreeSha256,
    packageLockSha256: runtime.packageLockSha256,
    preImportHelperBytesSha256: runtime.preImportHelperBytesSha256,
    runtimeNodeSha256: runtime.runtimeNodeSha256,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
}

function parseArguments(args) {
  const accepted = new Set([
    "--admin-url-file",
    "--approval-file",
    "--build-receipt",
    "--credential-bundle-file",
    "--credential-seal-receipt-file",
    "--expected-commit",
    "--expected-tree",
    "--operation-id",
    "--operation-directory"
  ]);
  requireCondition(
    args.length === accepted.size * 2,
    "FRESH_PRIMARY_ARGUMENTS_REJECTED"
  );
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    requireCondition(
      accepted.has(name) &&
        !Object.hasOwn(values, name) &&
        typeof args[index + 1] === "string" &&
        args[index + 1] !== "",
      "FRESH_PRIMARY_ARGUMENTS_REJECTED"
    );
    values[name] = args[index + 1];
  }
  return values;
}

function gitValue(args, cwd = ROOT) {
  return execFileSync(
    TRUSTED_GIT,
    [
      "-c", "core.askPass=",
      "-c", "credential.helper=",
      "-c", "credential.interactive=never",
      "-c", "http.extraHeader=",
      "-c", "http.proxy=",
      "-c", "http.sslVerify=true",
      ...args
    ],
    {
      cwd,
      encoding: "utf8",
      env: {
        GIT_CONFIG_COUNT: "0",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_NO_LAZY_FETCH: "1",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin",
        XDG_CONFIG_HOME: "/dev/null"
      },
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000
    }
  ).trim();
}

function gitBytes(args, cwd = ROOT) {
  return execFileSync(
    TRUSTED_GIT,
    [
      "-c", "core.askPass=",
      "-c", "credential.helper=",
      "-c", "credential.interactive=never",
      "-c", "http.extraHeader=",
      "-c", "http.proxy=",
      "-c", "http.sslVerify=true",
      ...args
    ],
    {
      cwd,
      encoding: "buffer",
      env: {
        GIT_CONFIG_COUNT: "0",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_NO_LAZY_FETCH: "1",
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin",
        XDG_CONFIG_HOME: "/dev/null"
      },
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000
    }
  );
}

function validateIndexVisibilityOutput(value) {
  const lines = typeof value === "string"
    ? value.split("\n").filter((line) => line !== "")
    : [];
  requireCondition(
    lines.length > 0 && lines.every((line) => /^H /u.test(line)),
    "FRESH_PRIMARY_INDEX_VISIBILITY_REJECTED"
  );
  return lines.length;
}

function bindPreImportHelperBytes(sourceCommit) {
  const inventory = PREIMPORT_BOUND_FILES.map((relativePath) => {
    requireCondition(
      /^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,255}$/u.test(relativePath) &&
        !relativePath.includes(".."),
      "FRESH_PRIMARY_PREIMPORT_HELPER_BINDING_REJECTED"
    );
    const filePath = path.join(ROOT, relativePath);
    const stat = fs.lstatSync(filePath);
    requireCondition(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.nlink === 1 &&
        fs.realpathSync(filePath) === filePath,
      "FRESH_PRIMARY_PREIMPORT_HELPER_BINDING_REJECTED"
    );
    const workingBytes = fs.readFileSync(filePath);
    const committedBytes = gitBytes([
      "cat-file", "blob", `${sourceCommit}:${relativePath}`
    ]);
    requireCondition(
      workingBytes.equals(committedBytes),
      "FRESH_PRIMARY_PREIMPORT_HELPER_BINDING_REJECTED"
    );
    return Object.freeze({
      path: relativePath,
      sha256: sha256(workingBytes)
    });
  });
  return sha256(canonicalBytes(inventory));
}

function preliminaryExactSourceBinding(expectedCommit, expectedTree) {
  requireCondition(
    HEX_40.test(expectedCommit) && HEX_40.test(expectedTree),
    "FRESH_PRIMARY_SOURCE_ARGUMENT_REJECTED"
  );
  const gitStat = fs.lstatSync(TRUSTED_GIT);
  requireCondition(
    fs.realpathSync(TRUSTED_GIT) === TRUSTED_GIT &&
      gitStat.isFile() &&
      !gitStat.isSymbolicLink(),
    "FRESH_PRIMARY_PREIMPORT_GIT_REJECTED"
  );
  const remote = gitValue(["remote", "get-url", "origin"]);
  const sourceCommit = gitValue(["rev-parse", "HEAD"]);
  const treeDigest = gitValue(["rev-parse", "HEAD^{tree}"]);
  requireCondition(
    [OFFICIAL_REMOTE, OFFICIAL_REMOTE.slice(0, -4)].includes(remote) &&
      sourceCommit === expectedCommit &&
      treeDigest === expectedTree &&
      gitValue(["rev-parse", "--show-toplevel"]) === ROOT &&
      gitValue(["rev-parse", "--is-shallow-repository"]) === "false" &&
      gitValue([
        "for-each-ref", "--format=%(refname)", "refs/replace/"
      ]) === "" &&
      gitValue(["status", "--porcelain=v1", "--untracked-files=all"]) === "",
    "FRESH_PRIMARY_PREIMPORT_SOURCE_BINDING_REJECTED"
  );
  validateIndexVisibilityOutput(gitValue(["ls-files", "-v"]));
  validateIndexVisibilityOutput(gitValue(["ls-files", "-t"]));
  const preImportHelperBytesSha256 = bindPreImportHelperBytes(sourceCommit);
  if (process.env.GITHUB_ACTIONS === "true") {
    requireCondition(
      process.env.GITHUB_REPOSITORY === "Flash-Bri/prooftoact" &&
        process.env.GITHUB_REF === "refs/heads/main" &&
        process.env.GITHUB_SHA === sourceCommit,
      "FRESH_PRIMARY_GITHUB_CONTEXT_REJECTED"
    );
  }
  return Object.freeze({
    sourceCommit,
    treeDigest,
    preImportHelperBytesSha256
  });
}

async function loadBoundRuntime({ buildReceipt, source }) {
  const exactGit = await import("./lib/exact-git-source.js");
  exactGit.assertExactGitRepositoryLayout({ rootDir: ROOT });
  const clean = exactGit.assertCleanExactGitCheckout({
    rootDir: ROOT,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  requireCondition(
    clean.sourceCommit === source.sourceCommit &&
      clean.treeDigest === source.treeDigest,
    "FRESH_PRIMARY_SOURCE_BINDING_REJECTED"
  );
  const [runtimeModule, readinessModule, dependencyModule] = await Promise.all([
    import("./lib/official-node-runtime.js"),
    import("./gate2-aws-readiness.js"),
    import("./lib/dependency-snapshot.js")
  ]);
  const runtime = runtimeModule.readOfficialNodeRuntime();
  requireCondition(
    runtime.version === process.version,
    "FRESH_PRIMARY_NODE_RUNTIME_REJECTED"
  );
  const validatedBuild = readinessModule.validateBuildReceipt(buildReceipt, {
    projectRoot: ROOT,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  const liveDependencies = dependencyModule.createDependencySnapshot({
    dependencyRoot: path.join(ROOT, "node_modules"),
    packageJsonDigest: validatedBuild.packageJsonDigest,
    packageLockDigest: validatedBuild.packageLockDigest
  });
  requireCondition(
    canonicalJson(liveDependencies) ===
      canonicalJson(validatedBuild.dependencySnapshot) &&
      validatedBuild.toolchain.nodeVersion === process.version &&
      validatedBuild.toolchain.nodeExecutableSha256 === runtime.sha256,
    "FRESH_PRIMARY_DEPENDENCY_BINDING_REJECTED"
  );

  // Database-capable dependencies are intentionally imported only after the
  // exact source, official Node binary, build receipt, and installed
  // dependency tree have all been independently bound above.
  const [pgModule, securityModule, databaseModule, publicationModule] =
    await Promise.all([
      import("pg"),
      import("../src/cloud/primary-security.js"),
      import("../src/cloud/database-runtime.js"),
      import("../src/cloud/atomic-create-only-file.js")
    ]);
  return Object.freeze({
    bootstrap: securityModule.bootstrapPrimarySecurity,
    bootstrapDatabaseConfig: databaseModule.bootstrapDatabaseConfig,
    clientFactory: (configuration) => new pgModule.Client(configuration),
    connectionStringForUser: securityModule.connectionStringForUser,
    dependencyTreeSha256: liveDependencies.treeDigest,
    packageLockSha256: validatedBuild.packageLockDigest,
    publishOrReadExactOwnedFile:
      publicationModule.publishOrReadExactOwnedFile,
    preImportHelperBytesSha256: source.preImportHelperBytesSha256,
    runtimeDatabaseConfig: databaseModule.runtimeDatabaseConfig,
    runtimeNodeSha256: runtime.sha256
  });
}

function publishPrivateJson(filePath, value, code, publisher) {
  const rootPath = assertPrivateDirectory(path.dirname(filePath), code);
  const bytes = canonicalBytes(value);
  const publication = publisher({
    bytes,
    code,
    filePath,
    maximumBytes: 1024 * 1024,
    mode: 0o600,
    rootPath,
    assertRoot: () => assertPrivateDirectory(rootPath, code)
  });
  requireCondition(publication.bytes.equals(bytes), code);
  return Object.freeze({ bytes, created: publication.created });
}

function parseJsonBytes(bytes, code) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
}

function openFreshOperationJournal(directoryPath, publisher, binding) {
  const code = "FRESH_PRIMARY_OPERATION_JOURNAL_REJECTED";
  const rootPath = assertPrivateDirectory(directoryPath, code);
  requireCondition(
    typeof publisher === "function" &&
      exactKeys(binding, ["operationId", "sourceCommit", "treeDigest"]) &&
      UUID.test(binding.operationId ?? "") &&
      HEX_40.test(binding.sourceCommit ?? "") &&
      HEX_40.test(binding.treeDigest ?? "") &&
      fs.readdirSync(rootPath).length === 0,
    code
  );
  let sequence = 0;
  let previousEntrySha256 = "0".repeat(64);
  return Object.freeze({
    [STATEFUL_TRANSITION_JOURNAL]: true,
    record(phase, payload) {
      requireCondition(
        /^[A-Z][A-Z0-9_]{0,79}$/u.test(phase) &&
          payload !== null &&
          typeof payload === "object" &&
          !Array.isArray(payload),
        code
      );
      const entry = {
        schemaVersion: "prooftoact.fresh-primary-operation-journal.v1",
        sequence,
        phase,
        operationId: binding.operationId,
        sourceCommit: binding.sourceCommit,
        treeDigest: binding.treeDigest,
        previousEntrySha256,
        payload
      };
      const filename = `${String(sequence).padStart(2, "0")}-${phase.toLowerCase()}.json`;
      const publication = publishPrivateJson(
        path.join(rootPath, filename),
        entry,
        code,
        publisher
      );
      requireCondition(publication.created, code);
      previousEntrySha256 = sha256(publication.bytes);
      sequence += 1;
      return previousEntrySha256;
    },
    rootPath
  });
}

function createStatefulTestTransitionJournal(observer = async () => {}) {
  requireCondition(
    typeof observer === "function",
    "FRESH_PRIMARY_BOUND_DEPENDENCIES_REJECTED"
  );
  let sequence = 0;
  let previousEntrySha256 = "0".repeat(64);
  return Object.freeze({
    [STATEFUL_TRANSITION_JOURNAL]: true,
    async record(phase, payload) {
      requireCondition(
        /^[A-Z][A-Z0-9_]{0,79}$/u.test(phase) &&
          payload !== null &&
          typeof payload === "object" &&
          !Array.isArray(payload),
        "FRESH_PRIMARY_OPERATION_JOURNAL_REJECTED"
      );
      const entry = {
        sequence,
        phase,
        previousEntrySha256,
        payload
      };
      previousEntrySha256 = sha256(canonicalBytes(entry));
      sequence += 1;
      await observer(phase, payload);
      return previousEntrySha256;
    }
  });
}

function unlinkExactPrivateFile(filePath, expectedBytes, code) {
  requireCondition(
    Buffer.isBuffer(expectedBytes) && expectedBytes.length > 0,
    code
  );
  const rootPath = assertPrivateDirectory(path.dirname(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      before.isFile() &&
        !before.isSymbolicLink() &&
        before.nlink === 1 &&
        before.uid === process.getuid() &&
        (before.mode & 0o077) === 0 &&
        before.size === expectedBytes.length &&
        named.isFile() &&
        !named.isSymbolicLink() &&
        named.dev === before.dev &&
        named.ino === before.ino &&
        fs.readFileSync(descriptor).equals(expectedBytes),
      code
    );
    fs.unlinkSync(filePath);
    const after = fs.fstatSync(descriptor);
    requireCondition(
      after.dev === before.dev &&
        after.ino === before.ino &&
        after.nlink === 0 &&
        !fs.existsSync(filePath),
      code
    );
    const directoryDescriptor = fs.openSync(
      rootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW |
        (fs.constants.O_DIRECTORY ?? 0)
    );
    try {
      fs.fsyncSync(directoryDescriptor);
    } finally {
      fs.closeSync(directoryDescriptor);
    }
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  // No caller-selected local directory can prove global one-shot approval
  // consumption. Keep this CLI unusable until the separate provider controller
  // owns an authoritative namespace and durable reconciliation contract.
  reject("FRESH_PRIMARY_PROVIDER_CONTROLLER_REQUIRED");
  const source = preliminaryExactSourceBinding(
    parsed["--expected-commit"],
    parsed["--expected-tree"]
  );
  const buildReceiptBytes = readPrivateFile(
    parsed["--build-receipt"],
    16 * 1024 * 1024,
    "FRESH_PRIMARY_BUILD_RECEIPT_FILE_REJECTED"
  );
  const buildReceipt = parseJsonBytes(
    buildReceiptBytes,
    "FRESH_PRIMARY_BUILD_RECEIPT_JSON_REJECTED"
  );
  const runtime = await loadBoundRuntime({ buildReceipt, source });
  const adminUrlBytes = readPrivateFile(
    parsed["--admin-url-file"],
    16 * 1024,
    "FRESH_PRIMARY_ADMIN_URL_FILE_REJECTED"
  );
  const bundleBytes = readPrivateFile(
    parsed["--credential-bundle-file"],
    64 * 1024,
    "FRESH_PRIMARY_CREDENTIAL_FILE_REJECTED"
  );
  const credentialBundle = parseJsonBytes(
    bundleBytes,
    "FRESH_PRIMARY_CREDENTIAL_JSON_REJECTED"
  );
  const acceptedCredentialBundle = validateFreshPrimaryCredentialBundle(
    credentialBundle
  );
  const credentialBundleRawSha256 = sha256(bundleBytes);
  const credentialBundleSha256 = sha256(
    canonicalBytes(acceptedCredentialBundle)
  );
  const sealBytes = readPrivateFile(
    parsed["--credential-seal-receipt-file"],
    64 * 1024,
    "FRESH_PRIMARY_CREDENTIAL_SEAL_FILE_REJECTED"
  );
  const credentialSeal = parseJsonBytes(
    sealBytes,
    "FRESH_PRIMARY_CREDENTIAL_SEAL_JSON_REJECTED"
  );
  const approvalBytes = readPrivateFile(
    parsed["--approval-file"],
    64 * 1024,
    "FRESH_PRIMARY_APPROVAL_FILE_REJECTED"
  );
  const approval = parseJsonBytes(
    approvalBytes,
    "FRESH_PRIMARY_APPROVAL_JSON_REJECTED"
  );
  const admin = validateFreshClusterAdminConnectionString(
    adminUrlBytes.toString("utf8").trim()
  );
  const acceptedSeal = validateFreshPrimaryCredentialSeal(credentialSeal, {
    credentialBundleRawSha256,
    credentialBundleSha256,
    operationId: parsed["--operation-id"],
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  const acceptedApproval = validateFreshPrimaryApproval(approval, {
    clusterHostSha256: admin.hostSha256,
    credentialSealReceiptSha256: sha256(canonicalBytes(acceptedSeal)),
    operationId: parsed["--operation-id"],
    outerAuthenticationReceiptSha256:
      approval?.outerAuthenticationReceiptSha256,
    outerCommandSha256: approval?.outerCommandSha256,
    outerReservedAt: approval?.outerReservedAt,
    outerReservationAcknowledgedAt:
      approval?.outerReservationAcknowledgedAt,
    outerReservationReceiptSha256:
      approval?.outerReservationReceiptSha256,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  const intent = freshPrimaryIntent({
    approvalId: acceptedApproval.approvalId,
    expectedClusterId: acceptedApproval.expectedClusterId,
    operationId: parsed["--operation-id"],
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest,
    hostSha256: admin.hostSha256
  });
  const journal = openFreshOperationJournal(
    parsed["--operation-directory"],
    runtime.publishOrReadExactOwnedFile,
    {
      operationId: parsed["--operation-id"],
      sourceCommit: source.sourceCommit,
      treeDigest: source.treeDigest
    }
  );
  journal.record("INTENT_SEALED", {
    approvalId: acceptedApproval.approvalId,
    intentSha256: sha256(canonicalBytes(intent)),
    retryAllowed: false
  });
  journal.record("APPROVAL_CONSUMED", {
    approvalSha256: sha256(approvalBytes),
    credentialSealReceiptSha256: sha256(sealBytes),
    expiresAt: acceptedApproval.expiresAt,
    oneShot: true
  });
  journal.record("RUNTIME_BOUND", {
    dependencyTreeSha256: runtime.dependencyTreeSha256,
    packageLockSha256: runtime.packageLockSha256,
    preImportHelperBytesSha256: runtime.preImportHelperBytesSha256,
    runtimeNodeSha256: runtime.runtimeNodeSha256
  });
  unlinkExactPrivateFile(
    parsed["--credential-bundle-file"],
    bundleBytes,
    "FRESH_PRIMARY_CREDENTIAL_DISCARD_FAILED"
  );
  journal.record("LOCAL_CREDENTIAL_COPY_DISCARDED", {
    credentialBundleRawSha256,
    credentialBundleSha256,
    callerSuppliedSealReceiptSha256: sha256(canonicalBytes(acceptedSeal)),
    localPathRetained: false
  });

  let receipt;
  try {
    receipt = await runFreshPrimaryBootstrap({
      adminConnectionString: admin.connectionString,
      approval: acceptedApproval,
      bootstrap: runtime.bootstrap,
      bootstrapDatabaseConfig: runtime.bootstrapDatabaseConfig,
      clientFactory: (configuration, kind) =>
        runtime.clientFactory(configuration, kind),
      connectionStringForUser: runtime.connectionStringForUser,
      credentialBundle: acceptedCredentialBundle,
      credentialBundleRawSha256,
      credentialBundleSha256,
      credentialSeal: acceptedSeal,
      discardAdminCredential: async () => {
        unlinkExactPrivateFile(
          parsed["--admin-url-file"],
          adminUrlBytes,
          "FRESH_PRIMARY_ADMIN_CREDENTIAL_DISCARD_FAILED"
        );
        adminUrlBytes.fill(0);
        return true;
      },
      localCredentialDiscarded: true,
      operationId: parsed["--operation-id"],
      runtimeDatabaseConfig: runtime.runtimeDatabaseConfig,
      sourceCommit: source.sourceCommit,
      transitionJournal: journal,
      treeDigest: source.treeDigest
    });
  } catch (cause) {
    const disposition = cause?.disposition ?? {
      clusterIdSha256: null,
      phase: "BEFORE_PROVIDER_MUTATION_OR_UNCLASSIFIED",
      retryAllowed: false,
      status: "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD"
    };
    journal.record("SEALED_PARTIAL_UNKNOWN", {
      causeCode: /^FRESH_PRIMARY_[A-Z0-9_]{1,100}$/u.test(
        String(cause?.message ?? "")
      ) ? cause.message : "FRESH_PRIMARY_UNKNOWN",
      ...disposition
    });
    throw cause;
  }
  const receiptSha256 = journal.record("PASS_RECEIPT", {
    receipt,
    status: "PASS"
  });
  process.stdout.write(`FRESH_PRIMARY_BOOTSTRAP_PASS:${receiptSha256}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^FRESH_PRIMARY_[A-Z0-9_]{1,100}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "FRESH_PRIMARY_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  DATABASE_NAME,
  FRESH_DATABASES,
  MANAGED_PRINCIPALS,
  PREIMPORT_BOUND_FILES,
  canonicalBytes,
  exactKeys,
  sha256,
  validateIndexVisibilityOutput,
  ...(typeof process.env.NODE_TEST_CONTEXT === "string" &&
    process.env.NODE_TEST_CONTEXT !== "" ? {
      createStatefulTestTransitionJournal,
      openFreshOperationJournal,
      runFreshPrimaryProviderControlledBootstrapWithRuntime,
      runFreshPrimaryBootstrap
    } : {})
});
