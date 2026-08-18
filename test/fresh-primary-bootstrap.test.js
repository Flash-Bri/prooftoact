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

const runFreshPrimaryBootstrap = __test.runFreshPrimaryBootstrap;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE_COMMIT = "1".repeat(40);
const TREE_DIGEST = "2".repeat(40);
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const CLUSTER_ID = "323e4567-e89b-42d3-a456-426614174002";
const NOW = Date.parse("2026-08-17T18:00:00.000Z");
const ADMIN_URL =
  "postgresql://bootstrap-admin:private-password@blue-moon-1234.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full";

function credentialBundle() {
  return {
    schemaVersion: "prooftoact.fresh-primary-credentials.v1",
    passwords: Object.fromEntries(
      FRESH_PRIMARY_RUNTIME_USERS.map((name, index) => [
        name,
        `credential-${String(index).padStart(2, "0")}-${"x".repeat(32)}`
      ])
    ),
    recoveryPublisherKeySetDigest: "3".repeat(64),
    recoveryPublisherTrustRootCommitment: "4".repeat(64)
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
    schemaVersion: "prooftoact.fresh-primary-approval.v1",
    status: "APPROVED",
    action: "CREATE_ONE_FRESH_PRIMARY",
    approvalId: APPROVAL_ID,
    approvedBy: "BRIAN_SMITH",
    approvedAt: "2026-08-17T17:55:00.000Z",
    expiresAt: "2026-08-17T18:25:00.000Z",
    oneShot: true,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    clusterHostSha256: admin.hostSha256,
    expectedClusterId: CLUSTER_ID,
    database: "tideproof",
    maximumProjectedTotalUsd: 12,
    credentialSealReceiptSha256:
      __test.sha256(__test.canonicalBytes(seal)),
    credentialDisposition:
      "REQUIRE_PROVIDER_SEAL_THEN_UNLINK_LOCAL_COPY_BEFORE_MUTATION",
    partialFailureDisposition:
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD"
  };
}

function bootstrapReceipt(roleNames = __test.MANAGED_PRINCIPALS) {
  return {
    roles: roleNames.map((username) => ({ username })),
    preflightPostureDigest: "8".repeat(64),
    finalPostureDigest: "9".repeat(64),
    clusterPreflightPostureDigest: "a".repeat(64),
    clusterFinalPostureDigest: "b".repeat(64)
  };
}

function clients({
  clusterId = CLUSTER_ID,
  databases = ["defaultdb", "postgres", "system"],
  users = ["bootstrap-admin", "root"],
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
            current_user_name: "bootstrap-admin",
            database_name: "defaultdb"
          }]
        };
      }
      if (normalized === "SHOW DATABASES") {
        return { rows: databases.map((database_name) => ({ database_name })) };
      }
      if (normalized === "SHOW USERS") {
        return { rows: users.map((username) => ({ username })) };
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
    runtimeDatabaseConfig: (value) => value,
    sourceCommit: SOURCE_COMMIT,
    transitionJournal: __test.createStatefulTestTransitionJournal(),
    treeDigest: TREE_DIGEST,
    ...overrides
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
  assert.equal(accepted.username, "bootstrap-admin");
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
  assert.equal(validateFreshPrimaryApproval(acceptedApproval, {
    clusterHostSha256:
      validateFreshClusterAdminConnectionString(ADMIN_URL).hostSha256,
    credentialSealReceiptSha256:
      __test.sha256(__test.canonicalBytes(seal)),
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, NOW).oneShot, true);
  assert.throws(
    () => validateFreshPrimaryApproval(acceptedApproval, {
      clusterHostSha256: "0".repeat(64),
      credentialSealReceiptSha256:
        __test.sha256(__test.canonicalBytes(seal)),
      operationId: OPERATION_ID,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    }, NOW),
    /FRESH_PRIMARY_APPROVAL_REJECTED/u
  );
  assert.throws(
    () => validateFreshPrimaryApproval(acceptedApproval, {
      clusterHostSha256: acceptedApproval.clusterHostSha256,
      credentialSealReceiptSha256:
        __test.sha256(__test.canonicalBytes(seal)),
      operationId: OPERATION_ID,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    }, Date.parse("2026-08-17T18:25:00.000Z")),
    /FRESH_PRIMARY_APPROVAL_REJECTED/u
  );
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
    [clients({ users: ["bootstrap-admin", "root", "alice"] }),
      "FRESH_PRIMARY_PRINCIPAL_CENSUS_REJECTED"],
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
