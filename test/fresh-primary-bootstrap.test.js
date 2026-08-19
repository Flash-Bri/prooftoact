import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  FRESH_PRIMARY_RUNTIME_USERS,
  __test,
  freshPrimaryIntent,
  main,
  validateFreshClusterAdminConnectionString,
  validateFreshPrimaryApproval,
  validateFreshPrimaryCredentialBundle,
  validateFreshPrimaryCredentialSeal
} from "../scripts/bootstrap-fresh-primary.js";
import { buildFreshPrimaryProviderCommand } from
  "../scripts/fresh-primary-provider-controller.js";
import { __test as freshClusterControllerContract } from
  "../scripts/fresh-cluster-provider-controller.js";
import { __test as primarySecurityContract } from
  "../src/cloud/primary-security.js";

const runFreshPrimaryBootstrap = __test.runFreshPrimaryBootstrap;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE_COMMIT = "1".repeat(40);
const TREE_DIGEST = "2".repeat(40);
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const CLUSTER_ID = "323e4567-e89b-42d3-a456-426614174002";
const NOW = Date.parse("2026-08-17T18:00:00.000Z");
const ADMIN_URL =
  "postgresql://prooftoact_bootstrap_admin:private-password" +
  "@blue-moon-1234.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full";

function credentialBundle() {
  return {
    schemaVersion: "prooftoact.fresh-primary-credentials.v2",
    passwords: Object.fromEntries(
      FRESH_PRIMARY_RUNTIME_USERS.map((name, index) => [
        name,
        `credential-${String(index).padStart(2, "0")}-${"x".repeat(32)}`
      ])
    )
  };
}

function recoveryPublisherSecret() {
  return {
    publisherKeyId: `prooftoact-gate2-${OPERATION_ID}`,
    publisherKeySetDigest: "3".repeat(64),
    secretBytesSha256: "4".repeat(64),
    trustRootCommitment: "5".repeat(64),
    trustRootJsonSha256: "6".repeat(64)
  };
}

function recoveryPublisherTrustRoot() {
  const signer = recoveryPublisherSecret();
  return {
    publisherKeyIdSha256: __test.sha256(signer.publisherKeyId),
    publisherKeySetDigest: signer.publisherKeySetDigest,
    signerSecretArnSha256: "7".repeat(64),
    signerSecretSealReceiptSha256: "8".repeat(64),
    signerSecretValueSha256: signer.secretBytesSha256,
    signerSecretVersionIdSha256: "9".repeat(64),
    trustRootCommitment: signer.trustRootCommitment,
    trustRootJsonSha256: signer.trustRootJsonSha256
  };
}

function bundleDigest(bundle = credentialBundle()) {
  return __test.sha256(__test.canonicalBytes(bundle));
}

function bundleRawDigest(bundle = credentialBundle()) {
  return __test.sha256(__test.canonicalBytes(bundle));
}

function credentialSeal(bundle = credentialBundle()) {
  return {
    schemaVersion: "prooftoact.fresh-primary-credential-seal.v1",
    status: "SEALED",
    provider: "AWS_SECRETS_MANAGER",
    providerBacked: true,
    immutableVersion: true,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    credentialBundleRawSha256: bundleRawDigest(bundle),
    credentialBundleSha256: bundleDigest(bundle),
    secretArnSha256: "5".repeat(64),
    secretVersionIdSha256: "6".repeat(64),
    runtimePolicySha256: "7".repeat(64),
    sealedAt: "2026-08-17T17:50:00.000Z"
  };
}

function approval(seal = credentialSeal()) {
  const admin = validateFreshClusterAdminConnectionString(ADMIN_URL);
  return {
    schemaVersion: "prooftoact.fresh-primary-approval.v2",
    status: "APPROVED",
    action: "BOOTSTRAP_ONE_BOUND_FRESH_PRIMARY",
    approvalId: APPROVAL_ID,
    approvedBy: "BRIAN_SMITH",
    approvedAt: "2026-08-17T17:55:00.000Z",
    expiresAt: "2026-08-17T18:40:00.000Z",
    oneShot: true,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    clusterHostSha256: admin.hostSha256,
    expectedClusterId: CLUSTER_ID,
    database: "tideproof",
    maximumReservedExecutionMinutes: 45,
    maximumProjectedTotalUsd: 1.5,
    outerApprovalExpiresAt: "2026-08-17T18:25:00.000Z",
    outerAuthenticationReceiptSha256: "8".repeat(64),
    outerCommandSha256: "9".repeat(64),
    outerReservedAt: "2026-08-17T17:55:00.000Z",
    outerReservationAcknowledgedAt: "2026-08-17T17:55:01.000Z",
    outerReservationReceiptSha256: "a".repeat(64),
    credentialSealReceiptSha256:
      __test.sha256(__test.canonicalBytes(seal)),
    credentialDisposition:
      "REQUIRE_PROVIDER_SEAL_THEN_UNLINK_LOCAL_COPY_BEFORE_MUTATION",
    partialFailureDisposition:
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD"
  };
}

function approvalBinding(value, seal = credentialSeal()) {
  return {
    clusterHostSha256: value.clusterHostSha256,
    credentialSealReceiptSha256:
      __test.sha256(__test.canonicalBytes(seal)),
    operationId: OPERATION_ID,
    outerAuthenticationReceiptSha256:
      value.outerAuthenticationReceiptSha256,
    outerCommandSha256: value.outerCommandSha256,
    outerReservedAt: value.outerReservedAt,
    outerReservationAcknowledgedAt:
      value.outerReservationAcknowledgedAt,
    outerReservationReceiptSha256: value.outerReservationReceiptSha256,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  };
}

function bootstrapReceipt(roleNames = __test.MANAGED_PRINCIPALS) {
  return {
    roles: roleNames.map((username) => ({ username })),
    preflightPostureDigest: "8".repeat(64),
    finalPostureDigest: "9".repeat(64),
    clusterPreflightPostureDigest: "a".repeat(64),
    clusterFinalPostureDigest: "b".repeat(64),
    principalLoginPosture: {
      schemaVersion: "prooftoact.primary-principal-login-posture.v2",
      status: "EXACT_COMPLETE_SHOW_USERS_LOGIN_POSTURE",
      builtinAdminOptionsSha256:
        __test.sha256(__test.canonicalBytes([])),
      builtinAdminRolePresent: true,
      bootstrapPrincipal: "prooftoact_bootstrap_admin",
      bootstrapPrincipalCanLogin: true,
      bootstrapPrincipalOptionsSha256:
        __test.sha256(__test.canonicalBytes([])),
      capabilityNoLoginCount: 15,
      databaseObservedAt: "2026-08-19T08:00:14.000Z",
      exactPrincipalCount: 32,
      fullPrincipalCensusSha256: "c".repeat(64),
      immutableBuiltinAdminRoleExceptionPresent: true,
      rootCanLogin: false,
      rootMemberOfSha256:
        __test.sha256(__test.canonicalBytes(["admin"])),
      rootNoLoginProvedFromShowUsers: true,
      rootOptions: ["NOLOGIN"],
      rootOptionsSha256:
        __test.sha256(__test.canonicalBytes(["NOLOGIN"])),
      runtimeLoginCount: 14
    }
  };
}

function completeShowUsersRows() {
  const databaseNow = "2026-08-19T08:00:14.000Z";
  return [
    { username: "admin", options: [], member_of: [], database_now: databaseNow },
    {
      username: "prooftoact_bootstrap_admin",
      options: [],
      member_of: ["admin"],
      database_now: databaseNow
    },
    {
      username: "root",
      options: ["NOLOGIN"],
      member_of: ["admin"],
      database_now: databaseNow
    },
    ...__test.MANAGED_PRINCIPALS.map((username) => ({
      username,
      options: username.endsWith("_user") ? [] : ["NOLOGIN"],
      member_of: username.endsWith("_user")
        ? [username.replace(/_user$/u, "_role")]
        : [],
      database_now: databaseNow
    }))
  ];
}

function clients({
  clusterId = CLUSTER_ID,
  databases = ["defaultdb", "postgres", "system"],
  users = ["admin", "prooftoact_bootstrap_admin", "root"],
  defaultTables = [],
  postgresTables = [],
  directTableDenied = true
} = {}) {
  const calls = [];
  const admin = {
    async connect() { calls.push("admin:connect"); },
    async end() { calls.push("admin:end"); },
    async query(sql) {
      const normalized = sql.replace(/\s+/gu, " ").trim();
      calls.push(`admin:${normalized}`);
      if (normalized === "SELECT version() AS server_version") {
        return {
          rows: [{
            server_version:
              "CockroachDB CCL v26.2.0 (x86_64-unknown-linux-gnu)"
          }]
        };
      }
      if (normalized.includes("crdb_internal.cluster_id()") &&
        normalized.includes("current_user::STRING")) {
        return {
          rows: [{
            cluster_id: clusterId,
            current_user_name: "prooftoact_bootstrap_admin",
            database_name: "defaultdb"
          }]
        };
      }
      if (normalized === "SHOW DATABASES") {
        return { rows: databases.map((database_name) => ({ database_name })) };
      }
      if (normalized === "SHOW USERS") {
        return { rows: users.map((username) => ({
          username,
          options: [],
          member_of: username === "admin" ? [] : ["admin"]
        })) };
      }
      if (normalized === "SHOW TABLES FROM defaultdb") {
        return { rows: defaultTables };
      }
      if (normalized === "SHOW TABLES FROM postgres") {
        return { rows: postgresTables };
      }
      if (normalized === "CREATE DATABASE tideproof") return { rows: [] };
      throw new Error(`unexpected admin query: ${normalized}`);
    }
  };
  const gate2 = {
    async connect() { calls.push("gate2:connect"); },
    async end() { calls.push("gate2:end"); },
    async query(sql) {
      const normalized = sql.replace(/\s+/gu, " ").trim();
      calls.push(`gate2:${normalized}`);
      if (normalized.includes("session_user::STRING")) {
        return {
          rows: [{
            session_user_name: "tp_gate2_authorizer_user",
            current_user_name: "tp_gate2_authorizer_user",
            database_name: "tideproof",
            cluster_id: clusterId,
            database_now: "2026-08-17T18:00:00.000Z"
          }]
        };
      }
      if (normalized.startsWith("SELECT tenant_id FROM tp_private")) {
        if (directTableDenied) {
          throw Object.assign(new Error("insufficient privilege"), {
            code: "42501"
          });
        }
        return { rows: [] };
      }
      throw new Error(`unexpected gate2 query: ${normalized}`);
    }
  };
  return {
    calls,
    factory(_configuration, kind) {
      return kind === "admin" ? admin : gate2;
    }
  };
}

function runInput(state = clients(), overrides = {}) {
  const bundle = credentialBundle();
  const seal = credentialSeal(bundle);
  return {
    adminConnectionString: ADMIN_URL,
    approval: approval(seal),
    approvalNow: NOW,
    bootstrap: async () => bootstrapReceipt(),
    bootstrapDatabaseConfig: (value) => value,
    clientFactory: state.factory,
    connectionStringForUser: (value) => value,
    credentialBundle: bundle,
    credentialBundleRawSha256: bundleRawDigest(bundle),
    credentialBundleSha256: bundleDigest(bundle),
    credentialSeal: seal,
    databaseEnvironment: {},
    discardAdminCredential: async () => {
      state.calls.push("local:admin-credential-discarded");
      return true;
    },
    localCredentialDiscarded: true,
    operationId: OPERATION_ID,
    recoveryPublisherTrustRoot: recoveryPublisherTrustRoot(),
    runtimeDatabaseConfig: (value) => value,
    sourceCommit: SOURCE_COMMIT,
    transitionJournal: __test.createStatefulTestTransitionJournal(),
    treeDigest: TREE_DIGEST,
    ...overrides
  };
}

function providerControlledInput(state = clients()) {
  const input = runInput(state);
  const signer = recoveryPublisherSecret();
  const command = buildFreshPrimaryProviderCommand({
    adminSecretArnSha256: "c".repeat(64),
    adminSecretVersionIdSha256: "d".repeat(64),
    adminSecretValueSha256: __test.sha256(input.adminConnectionString),
    approvalId: input.approval.approvalId,
    approvalSha256: __test.sha256(__test.canonicalBytes(input.approval)),
    cloudApiSecretArnSha256: "e".repeat(64),
    cloudApiSecretVersionIdSha256: "f".repeat(64),
    cloudApiSecretValueSha256: "a".repeat(64),
    controllerTableArn:
      "arn:aws:dynamodb:us-east-1:111111111111:table/" +
      "prooftoact-release-controller",
    credentialSecretArnSha256: input.credentialSeal.secretArnSha256,
    credentialSecretVersionIdSha256:
      input.credentialSeal.secretVersionIdSha256,
    credentialBundleRawSha256: input.credentialBundleRawSha256,
    credentialBundleSha256: input.credentialBundleSha256,
    credentialSealReceiptSha256:
      __test.sha256(__test.canonicalBytes(input.credentialSeal)),
    operationId: input.operationId,
    outerAuthenticationReceiptSha256:
      input.approval.outerAuthenticationReceiptSha256,
    outerCommandSha256: input.approval.outerCommandSha256,
    outerReservedAt: input.approval.outerReservedAt,
    outerReservationAcknowledgedAt:
      input.approval.outerReservationAcknowledgedAt,
    outerReservationReceiptSha256:
      input.approval.outerReservationReceiptSha256,
    providerClusterId: "523e4567-e89b-42d3-a456-426614174004",
    recoveryPublisherKeySetDigest: signer.publisherKeySetDigest,
    recoveryPublisherTrustRootCommitment: signer.trustRootCommitment,
    recoverySecurityPostureReceiptSha256: "9".repeat(64),
    signerSecretArnSha256: "7".repeat(64),
    signerSecretValueSha256: signer.secretBytesSha256,
    signerSecretVersionIdSha256: "9".repeat(64),
    sourceCommit: input.sourceCommit,
    sqlClusterId: input.approval.expectedClusterId,
    treeDigest: input.treeDigest,
    trustRootJsonSha256: signer.trustRootJsonSha256
  });
  let version = 0;
  const provider = {
    async authenticate() {
      return {
        schemaVersion:
          "prooftoact.fresh-primary-provider-authentication.v3",
        status: "AUTHENTICATED_PROVIDER_READBACK",
        callerIdentitySha256: "0".repeat(64),
        cloud: command.cloud,
        clusterInventorySha256: "1".repeat(64),
        namespaceArn: command.controllerTableArn,
        observedAt: new Date(NOW).toISOString(),
        providerBacked: true,
        providerClusterId: command.providerClusterId,
        readOnly: true,
        region: command.region,
        secretReadbacks: {
          admin: {
            immutableVersion: true,
            secretArnSha256: command.adminSecretArnSha256,
            secretValueSha256: command.adminSecretValueSha256,
            secretVersionIdSha256: command.adminSecretVersionIdSha256,
            versionStage: "AWSCURRENT"
          },
          cloudApi: {
            immutableVersion: true,
            secretArnSha256: command.cloudApiSecretArnSha256,
            secretValueSha256: command.cloudApiSecretValueSha256,
            secretVersionIdSha256: command.cloudApiSecretVersionIdSha256,
            versionStage: "AWSCURRENT"
          },
          credential: {
            immutableVersion: true,
            secretArnSha256: command.credentialSecretArnSha256,
            secretValueSha256: command.credentialBundleRawSha256,
            secretVersionIdSha256: command.credentialSecretVersionIdSha256,
            versionStage: "AWSCURRENT"
          },
          recoverySigner: {
            secretArnSha256: command.signerSecretArnSha256,
            targetVersionAbsent: true,
            targetVersionIdSha256: command.signerSecretVersionIdSha256
          }
        },
        stronglyConsistent: true
      };
    },
    async authenticateRecovery() {
      return this.authenticate();
    },
    async readStrong() { return null; },
    async consumeOnce() {
      version = 1;
      return {
        schemaVersion: "prooftoact.fresh-primary-provider-consumption.v1",
        status: "CONSUMED",
        approvalId: command.approvalId,
        commandSha256: command.commandSha256,
        consumedAt: new Date(NOW).toISOString(),
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: command.controllerTableArn,
        oneShot: true,
        operationId: command.operationId,
        version
      };
    },
    async appendIntent({ authentication, consumption }) {
      version = 2;
      return {
        schemaVersion: "prooftoact.fresh-primary-provider-intent.v3",
        status: "DURABLE",
        commandSha256: command.commandSha256,
        durable: true,
        event: "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH",
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: command.controllerTableArn,
        operationId: command.operationId,
        previousReceiptSha256:
          __test.sha256(__test.canonicalBytes(consumption)),
        providerAuthenticationReceiptSha256:
          __test.sha256(__test.canonicalBytes(authentication)),
        version
      };
    },
    async appendTransition({ transition }) {
      version = transition.version;
      return transition;
    },
    async sealRecoveryPublisherSecret() {
      return {
        schemaVersion:
          "prooftoact.fresh-recovery-publisher-secret-seal.v1",
        status: "SEALED",
        provider: "AWS_SECRETS_MANAGER",
        providerBacked: true,
        immutableVersion: true,
        createdAt: new Date(NOW).toISOString(),
        secretArnSha256: command.signerSecretArnSha256,
        secretValueSha256: command.signerSecretValueSha256,
        secretVersionIdSha256: command.signerSecretVersionIdSha256
      };
    },
    async finalize({ outcome, previousReceiptSha256, transitionCount }) {
      version += 1;
      return {
        schemaVersion: "prooftoact.fresh-primary-provider-terminal.v1",
        status: "TERMINAL",
        commandSha256: command.commandSha256,
        operationId: command.operationId,
        namespaceArn: command.controllerTableArn,
        outcomeSha256: __test.sha256(__test.canonicalBytes(outcome)),
        previousReceiptSha256,
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        transitionCount,
        version
      };
    }
  };
  return {
    ...input,
    clock: () => NOW,
    command,
    provider,
    recoveryPublisherSecret: signer,
    runtime: {
      bootstrap: input.bootstrap,
      bootstrapDatabaseConfig: input.bootstrapDatabaseConfig,
      clientFactory: input.clientFactory,
      connectionStringForUser: input.connectionStringForUser,
      runtimeDatabaseConfig: input.runtimeDatabaseConfig
    }
  };
}

function cliArgs(operationDirectory) {
  return [
    "--admin-url-file", "/private/admin-url",
    "--approval-file", "/private/one-approval.json",
    "--build-receipt", "/private/build.json",
    "--credential-bundle-file", "/private/credentials.json",
    "--credential-seal-receipt-file", "/private/seal.json",
    "--expected-commit", SOURCE_COMMIT,
    "--expected-tree", TREE_DIGEST,
    "--operation-id", OPERATION_ID,
    "--operation-directory", operationDirectory
  ];
}

test("fresh-primary credentials require every distinct runtime password", () => {
  const accepted = validateFreshPrimaryCredentialBundle(credentialBundle());
  assert.deepEqual(
    Object.keys(accepted.passwords).sort(),
    [...FRESH_PRIMARY_RUNTIME_USERS].sort()
  );
  const missing = credentialBundle();
  delete missing.passwords.tp_gate2_authorizer_user;
  assert.throws(
    () => validateFreshPrimaryCredentialBundle(missing),
    /FRESH_PRIMARY_CREDENTIAL_BUNDLE_REJECTED/u
  );
  const duplicate = credentialBundle();
  duplicate.passwords.tp_authorizer_user =
    duplicate.passwords.tp_gate2_authorizer_user;
  assert.throws(
    () => validateFreshPrimaryCredentialBundle(duplicate),
    /FRESH_PRIMARY_CREDENTIAL_BUNDLE_REJECTED/u
  );
});

test("fresh-primary admin URL is a verify-full Cockroach Cloud admin route", () => {
  const accepted = validateFreshClusterAdminConnectionString(ADMIN_URL);
  assert.equal(accepted.sourceDatabase, "defaultdb");
  assert.equal(accepted.username, "prooftoact_bootstrap_admin");
  assert.equal(accepted.port, "26257");
  for (const rejected of [
    ADMIN_URL.replace("verify-full", "require"),
    ADMIN_URL.replace(".cockroachlabs.cloud", ".example.test"),
    ADMIN_URL.replace("/defaultdb", "/tideproof"),
    `${ADMIN_URL}&options=unsafe`
  ]) {
    assert.throws(
      () => validateFreshClusterAdminConnectionString(rejected),
      /FRESH_PRIMARY_ADMIN_URL_REJECTED/u
    );
  }
});

test("credential seal and one-shot approval bind source, cluster, cost, and expiry", () => {
  const seal = credentialSeal();
  assert.equal(validateFreshPrimaryCredentialSeal(seal, {
    credentialBundleRawSha256: seal.credentialBundleRawSha256,
    credentialBundleSha256: seal.credentialBundleSha256,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }).status, "SEALED");
  const acceptedApproval = approval(seal);
  const binding = approvalBinding(acceptedApproval, seal);
  assert.equal(validateFreshPrimaryApproval(
    acceptedApproval,
    binding,
    NOW
  ).oneShot, true);
  assert.throws(
    () => validateFreshPrimaryApproval(acceptedApproval, {
      ...binding,
      clusterHostSha256: "0".repeat(64)
    }, NOW),
    /FRESH_PRIMARY_APPROVAL_REJECTED/u
  );
  assert.throws(
    () => validateFreshPrimaryApproval(
      acceptedApproval,
      binding,
      Date.parse("2026-08-17T18:40:00.000Z")
    ),
    /FRESH_PRIMARY_APPROVAL_REJECTED/u
  );
  assert.equal(validateFreshPrimaryApproval(
    acceptedApproval,
    binding,
    Date.parse("2026-08-17T18:39:59.999Z")
  ).status, "APPROVED");
  assert.equal(validateFreshPrimaryApproval(
    acceptedApproval,
    binding,
    Date.parse(acceptedApproval.outerApprovalExpiresAt)
  ).status, "APPROVED");
  for (const field of [
    "outerAuthenticationReceiptSha256",
    "outerCommandSha256",
    "outerReservationReceiptSha256"
  ]) {
    assert.throws(() => validateFreshPrimaryApproval({
      ...acceptedApproval,
      [field]: "0".repeat(64)
    }, binding, NOW), /FRESH_PRIMARY_APPROVAL_REJECTED/u, field);
  }
  for (const field of [
    "outerReservedAt",
    "outerReservationAcknowledgedAt"
  ]) {
    assert.throws(() => validateFreshPrimaryApproval({
      ...acceptedApproval,
      [field]: "2026-08-17T17:56:00.000Z"
    }, binding, NOW), /FRESH_PRIMARY_APPROVAL_REJECTED/u, field);
  }
  for (const hostile of [
    { ...acceptedApproval, schemaVersion: "prooftoact.fresh-primary-approval.v1" },
    { ...acceptedApproval, maximumReservedExecutionMinutes: 44 },
    {
      ...acceptedApproval,
      approvedAt: "2026-08-17T17:55:00Z",
      outerReservedAt: "2026-08-17T17:55:00Z"
    },
    {
      ...acceptedApproval,
      outerReservationAcknowledgedAt: "2026-08-17T17:54:59.999Z"
    },
    {
      ...acceptedApproval,
      outerReservationAcknowledgedAt:
        acceptedApproval.outerApprovalExpiresAt
    }
  ]) {
    assert.throws(() => validateFreshPrimaryApproval(
      hostile,
      approvalBinding(hostile, seal),
      NOW
    ), /FRESH_PRIMARY_APPROVAL_REJECTED/u);
  }
  const missingOuter = { ...acceptedApproval };
  delete missingOuter.outerCommandSha256;
  assert.throws(() => validateFreshPrimaryApproval(
    missingOuter,
    binding,
    NOW
  ), /FRESH_PRIMARY_APPROVAL_REJECTED/u);
  assert.throws(() => validateFreshPrimaryApproval({
    ...acceptedApproval,
    unexpectedOuterCoordinate: "0".repeat(64)
  }, binding, NOW), /FRESH_PRIMARY_APPROVAL_REJECTED/u);
});

test("fresh-primary intent binds exact fresh census and one-shot approval", () => {
  const intent = freshPrimaryIntent({
    approvalId: APPROVAL_ID,
    expectedClusterId: CLUSTER_ID,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    hostSha256: "9".repeat(64)
  });
  assert.deepEqual(intent.target.exactFreshDatabases,
    ["defaultdb", "postgres", "system"]);
  assert.equal(intent.target.requireNoUserTables, true);
  assert.equal(intent.approvalId, APPROVAL_ID);
});

test("approval absence, mismatch, or missing bound dependencies fails before connect", async () => {
  for (const overrides of [
    { approval: undefined },
    { localCredentialDiscarded: false },
    { bootstrap: undefined },
    { discardAdminCredential: undefined },
    { transitionJournal: undefined }
  ]) {
    const state = clients();
    await assert.rejects(
      runFreshPrimaryBootstrap(runInput(state, overrides)),
      /FRESH_PRIMARY_(?:APPROVAL|BOUND_DEPENDENCIES)_REJECTED/u
    );
    assert.equal(state.calls.length, 0);
  }
});

test("low-level no-op transition is rejected before client construction", async () => {
  const state = clients();
  let constructed = 0;
  const unsafe = runInput(state, {
    clientFactory(...args) {
      constructed += 1;
      return state.factory(...args);
    },
    transition: async () => {},
    transitionJournal: undefined
  });
  await assert.rejects(
    runFreshPrimaryBootstrap(unsafe),
    /FRESH_PRIMARY_BOUND_DEPENDENCIES_REJECTED/u
  );
  assert.equal(constructed, 0);
  assert.equal(state.calls.length, 0);
});

test("low-level bootstrap and journal mint are not exported outside node:test", () => {
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  const moduleUrl = new URL(
    "../scripts/bootstrap-fresh-primary.js",
    import.meta.url
  ).href;
  const output = execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      `const {__test}=await import(${JSON.stringify(moduleUrl)});` +
        "process.stdout.write(JSON.stringify({" +
        "run:typeof __test.runFreshPrimaryBootstrap," +
        "mint:typeof __test.createStatefulTestTransitionJournal," +
        "journal:typeof __test.openFreshOperationJournal" +
        "}));"
    ],
    {
      cwd: ROOT,
      encoding: "utf8",
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000
    }
  );
  assert.deepEqual(JSON.parse(output), {
    run: "undefined",
    mint: "undefined",
    journal: "undefined"
  });
});

test("CLI holds same approval across relocated, symlinked, or drifted directories", async () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "pta-controller-hold-"));
  const first = path.join(parent, "first");
  const second = path.join(parent, "second");
  const drifted = path.join(parent, "..", path.basename(parent), "second");
  const linked = path.join(parent, "linked");
  fs.mkdirSync(first, { mode: 0o700 });
  fs.mkdirSync(second, { mode: 0o700 });
  fs.symlinkSync(first, linked);
  try {
    for (const operationDirectory of [first, second, drifted, linked]) {
      await assert.rejects(
        main(cliArgs(operationDirectory)),
        /FRESH_PRIMARY_PROVIDER_CONTROLLER_REQUIRED/u
      );
    }
    assert.deepEqual(fs.readdirSync(first), []);
    assert.deepEqual(fs.readdirSync(second), []);
  } finally {
    fs.rmSync(parent, { force: true, recursive: true });
  }
});

test("fresh-primary exact census rejects extra database, user, or table before mutation", async () => {
  for (const [state, code] of [
    [clients({ databases: ["defaultdb", "postgres", "system", "customer-prod"] }),
      "FRESH_PRIMARY_DATABASE_CENSUS_REJECTED"],
    [clients({
      users: ["admin", "prooftoact_bootstrap_admin", "root", "alice"]
    }), "FRESH_PRIMARY_SHOW_USERS_POSTURE_REJECTED"],
    [clients({ defaultTables: [{ schema_name: "public", table_name: "orders" }] }),
      "FRESH_PRIMARY_USER_TABLE_CENSUS_REJECTED"]
  ]) {
    await assert.rejects(
      runFreshPrimaryBootstrap(runInput(state)),
      new RegExp(code, "u")
    );
    assert.equal(
      state.calls.some((call) => call.includes("CREATE DATABASE")),
      false
    );
  }
});

test("fresh-primary rejects wrong cluster identity before mutation", async () => {
  const state = clients({
    clusterId: "423e4567-e89b-42d3-a456-426614174003"
  });
  await assert.rejects(
    runFreshPrimaryBootstrap(runInput(state)),
    /FRESH_PRIMARY_CLUSTER_IDENTITY_REJECTED/u
  );
  assert.equal(state.calls.some((call) => call.includes("CREATE DATABASE")), false);
});

test("fresh-primary bootstrap creates one database and validates exact roles", async () => {
  const state = clients();
  const transitions = [];
  const receipt = await runFreshPrimaryBootstrap(runInput(state, {
    transitionJournal: __test.createStatefulTestTransitionJournal(
      async (phase) => transitions.push(phase)
    )
  }));
  assert.equal(
    state.calls.filter((call) => call === "admin:CREATE DATABASE tideproof").length,
    1
  );
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.bootstrap.managedRoleCount,
    __test.MANAGED_PRINCIPALS.length);
  assert.equal(receipt.credentialLifecycle.localCopyDiscardedBeforeMutation,
    true);
  assert.equal(
    receipt.credentialLifecycle.adminUrlLocalCopyDiscardedBeforeMutation,
    true
  );
  assert.equal(
    receipt.credentialLifecycle.providerReadbackAuthenticatedByThisModule,
    false
  );
  assert.equal(
    state.calls.indexOf("local:admin-credential-discarded") <
      state.calls.indexOf("admin:CREATE DATABASE tideproof"),
    true
  );
  assert.deepEqual(transitions, [
    "PREFLIGHT_STARTED",
    "PREFLIGHT_ACCEPTED",
    "ADMIN_CREDENTIAL_DISCARDING",
    "ADMIN_CREDENTIAL_DISCARDED",
    "CREATE_DATABASE_DISPATCHING",
    "DATABASE_CREATED",
    "SECURITY_BOOTSTRAP_DISPATCHING",
    "SECURITY_BOOTSTRAPPED",
    "POSTFLIGHT_STARTED",
    "ACCEPTED"
  ]);
});

test("real SHOW USERS collector output passes both bootstrap receipt validators", async () => {
  const rows = completeShowUsersRows();
  const principalLoginPosture = await primarySecurityContract
    .collectPrincipalLoginPosture({
      async query(sql) {
        assert.match(sql, /FROM \[SHOW USERS\]/u);
        return { rows, rowCount: rows.length };
      }
    }, "prooftoact_bootstrap_admin");
  assert.equal(
    principalLoginPosture.rootOptionsSha256,
    freshClusterControllerContract.digest(["NOLOGIN"])
  );
  const state = clients();
  const receipt = await runFreshPrimaryBootstrap(runInput(state, {
    bootstrap: async () => ({
      ...bootstrapReceipt(),
      principalLoginPosture
    })
  }));
  assert.equal(freshClusterControllerContract.validateBootstrapReceipt(
    receipt,
    {
      approvalId: APPROVAL_ID,
      operationId: OPERATION_ID,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    },
    {},
    { secretValueSha256: "f".repeat(64) },
    { sqlClusterId: CLUSTER_ID }
  ), receipt);
});

test("provider controller wraps the real bootstrap core in durable global transitions", async () => {
  const state = clients();
  const receipt = await __test
    .runFreshPrimaryProviderControlledBootstrapWithRuntime(
      providerControlledInput(state)
    );
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.globallyAuthoritativeOneShot, true);
  assert.equal(receipt.providerClusterId,
    "523e4567-e89b-42d3-a456-426614174004");
  assert.equal(receipt.sqlClusterId, CLUSTER_ID);
  assert.equal(receipt.transitionCount, 12);
  assert.equal(
    state.calls.filter((call) => call === "admin:CREATE DATABASE tideproof")
      .length,
    1
  );
});

test("provider controller binds authenticated secret values to bootstrap inputs", async () => {
  for (const drift of [
    { adminConnectionString: ADMIN_URL.replace("private-password", "drifted") },
    {
      recoveryPublisherSecret: {
        ...recoveryPublisherSecret(),
        secretBytesSha256: "0".repeat(64)
      }
    }
  ]) {
    const state = clients();
    await assert.rejects(
      __test.runFreshPrimaryProviderControlledBootstrapWithRuntime({
        ...providerControlledInput(state),
        ...drift
      }),
      /FRESH_PRIMARY_PROVIDER_BINDING_REJECTED/u
    );
    assert.equal(state.calls.length, 0);
  }
});

test("provider wrapper rejects outer approval coordinate drift before dispatch", async () => {
  for (const field of [
    "outerAuthenticationReceiptSha256",
    "outerCommandSha256",
    "outerReservationReceiptSha256"
  ]) {
    const state = clients();
    const input = providerControlledInput(state);
    const unsigned = { ...input.command };
    for (const name of [
      "action",
      "cloud",
      "commandSha256",
      "effectIdentitySha256",
      "globalKeySha256",
      "region",
      "schemaVersion",
      "status"
    ]) delete unsigned[name];
    const driftedCommand = buildFreshPrimaryProviderCommand({
      ...unsigned,
      [field]: "0".repeat(64)
    });
    await assert.rejects(
      __test.runFreshPrimaryProviderControlledBootstrapWithRuntime({
        ...input,
        command: driftedCommand
      }),
      /FRESH_PRIMARY_PROVIDER_BINDING_REJECTED/u,
      field
    );
    assert.equal(state.calls.length, 0);
  }
});

test("fresh-primary recomputes canonical credential digest before connect", async () => {
  const state = clients();
  await assert.rejects(
    runFreshPrimaryBootstrap(runInput(state, {
      credentialBundleSha256: "0".repeat(64)
    })),
    /FRESH_PRIMARY_CREDENTIAL_DIGEST_REJECTED/u
  );
  assert.equal(state.calls.length, 0);

  const rawState = clients();
  await assert.rejects(
    runFreshPrimaryBootstrap(runInput(rawState, {
      credentialBundleRawSha256: "0".repeat(64)
    })),
    /FRESH_PRIMARY_CREDENTIAL_SEAL_REJECTED/u
  );
  assert.equal(rawState.calls.length, 0);
});

test("admin credential discard must complete before the first mutation", async () => {
  const state = clients();
  const transitions = [];
  await assert.rejects(
    runFreshPrimaryBootstrap(runInput(state, {
      discardAdminCredential: async () => false,
      transitionJournal: __test.createStatefulTestTransitionJournal(
        async (phase) => transitions.push(phase)
      )
    })),
    /FRESH_PRIMARY_ADMIN_CREDENTIAL_DISCARD_FAILED/u
  );
  assert.equal(
    state.calls.some((call) => call.includes("CREATE DATABASE")),
    false
  );
  assert.equal(transitions.includes("ADMIN_CREDENTIAL_DISCARDING"), true);
  assert.equal(transitions.includes("CREATE_DATABASE_DISPATCHING"), false);
});

test("fresh-primary rejects missing, extra, duplicate, or wrong managed role as sealed partial", async () => {
  const exact = [...__test.MANAGED_PRINCIPALS];
  const variants = [
    exact.slice(1),
    [...exact, "tp_extra_role"],
    [...exact.slice(0, -1), exact[0]],
    exact.map((name, index) => index === 0 ? "tp_wrong_role" : name)
  ];
  for (const roleNames of variants) {
    const state = clients();
    await assert.rejects(
      runFreshPrimaryBootstrap(runInput(state, {
        bootstrap: async () => bootstrapReceipt(roleNames)
      })),
      (error) =>
        error.message ===
          "FRESH_PRIMARY_PARTIAL_FAILURE_UNKNOWN_DO_NOT_RETRY" &&
        error.cause?.message ===
          "FRESH_PRIMARY_BOOTSTRAP_MANAGED_ROLE_SET_REJECTED" &&
        error.disposition?.retryAllowed === false
    );
  }
});

test("post-CREATE failure is classified UNKNOWN and cannot be represented as PASS", async () => {
  const state = clients({ directTableDenied: false });
  const transitions = [];
  await assert.rejects(
    runFreshPrimaryBootstrap(runInput(state, {
      transitionJournal: __test.createStatefulTestTransitionJournal(
        async (phase) => transitions.push(phase)
      )
    })),
    (error) =>
      error.message === "FRESH_PRIMARY_PARTIAL_FAILURE_UNKNOWN_DO_NOT_RETRY" &&
      error.disposition?.status ===
        "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD" &&
      error.disposition?.retryAllowed === false
  );
  assert.equal(transitions.includes("CREATE_DATABASE_DISPATCHING"), true);
  assert.equal(transitions.includes("ACCEPTED"), false);
});

test("operation journal is create-only and blocks approval reuse after any entry", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "pta-fresh-journal-"));
  const root = path.join(parent, "operation");
  fs.mkdirSync(root, { mode: 0o700 });
  const publisher = ({ bytes, filePath, mode }) => {
    const descriptor = fs.openSync(
      filePath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      mode
    );
    try {
      fs.writeFileSync(descriptor, bytes);
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    return { bytes, created: true };
  };
  try {
    const journal = __test.openFreshOperationJournal(root, publisher, {
      operationId: OPERATION_ID,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    });
    journal.record("INTENT_SEALED", { retryAllowed: false });
    assert.throws(
      () => __test.openFreshOperationJournal(root, publisher, {
        operationId: OPERATION_ID,
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      }),
      /FRESH_PRIMARY_OPERATION_JOURNAL_REJECTED/u
    );
  } finally {
    fs.rmSync(parent, { force: true, recursive: true });
  }
});

test("database-capable imports occur only after exact runtime/dependency binding", () => {
  assert.deepEqual(__test.PREIMPORT_BOUND_FILES, [
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
  const source = fs.readFileSync(
    path.join(ROOT, "scripts/bootstrap-fresh-primary.js"),
    "utf8"
  );
  assert.doesNotMatch(source, /^import .* from "pg";/mu);
  assert.doesNotMatch(source, /^import .*primary-security\.js";/mu);
  const dependencyGate = source.indexOf(
    '"FRESH_PRIMARY_DEPENDENCY_BINDING_REJECTED"'
  );
  const helperBinding = source.indexOf(
    "const preImportHelperBytesSha256 = bindPreImportHelperBytes(sourceCommit)"
  );
  const exactGitImport = source.indexOf(
    'import("./lib/exact-git-source.js")'
  );
  const pgImport = source.indexOf('import("pg")');
  const securityImport = source.indexOf(
    'import("../src/cloud/primary-security.js")'
  );
  assert.equal(dependencyGate > 0, true);
  assert.equal(helperBinding > 0, true);
  assert.equal(exactGitImport > helperBinding, true);
  assert.equal(pgImport > dependencyGate, true);
  assert.equal(securityImport > dependencyGate, true);
});

test("assume-unchanged and skip-worktree index flags are rejected", () => {
  assert.equal(
    __test.validateIndexVisibilityOutput("H package.json\nH package-lock.json"),
    2
  );
  for (const unsafe of [
    "h package.json\nH package-lock.json",
    "S package.json\nH package-lock.json",
    ""
  ]) {
    assert.throws(
      () => __test.validateIndexVisibilityOutput(unsafe),
      /FRESH_PRIMARY_INDEX_VISIBILITY_REJECTED/u
    );
  }
});
