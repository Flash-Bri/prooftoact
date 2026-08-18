import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  __test as recoverySecurityContract,
  appendRecoveryBundleWithClient,
  collectRecoveryPublisherFunctionDefinitions,
  collectRecoveryPublisherCapabilityPosture,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID,
  repairRecoveryPublisherPrivateSchemaUsage,
  verifyRecoveryPublisherPrivateSchemaUsage
} from "../src/cloud/recovery-security.js";
import { main as repairCliMain } from
  "../scripts/repair-recovery-publisher-private-schema-usage.js";
import {
  validateDatabaseSecurityPosture
} from "../src/cloud/database-security-posture.js";

const BUNDLE = Object.freeze({
  tenantId: "11111111-1111-4111-8111-111111111111",
  recoverySessionId: "22222222-2222-4222-8222-222222222222",
  subjectBindingHash: "a".repeat(64),
  schemaVersion: 2,
  snapshotVersion: 1,
  sourceClusterId: "33333333-3333-4333-8333-333333333333",
  sourceCommitTs: "2026-08-01T00:00:00.000Z",
  sourceDigest: "b".repeat(64),
  bundleDigest: "c".repeat(64),
  policyVersion: "gate1-policy-v2",
  publisherKeyId: "synthetic-key",
  publisherVersion: "tideproof-recovery-publisher-v2",
  signatureAlgorithm: "ecdsa-p256-sha256",
  sourceSignatureBase64: Buffer.alloc(64, 1).toString("base64"),
  signatureDigest: "d".repeat(64),
  checkpointSummary: { checkpointVersion: 1 },
  evidenceSummary: { admittedCount: 1 },
  conflictSummary: { unresolvedCount: 0 },
  receiptSummary: { outcome: "resource_reserved" },
  expiresAt: "2026-08-01T01:00:00.000Z"
});
function result() {
  return {
    rowCount: 1,
    rows: [{
      bundle_digest: BUNDLE.bundleDigest,
      outcome: "bundle_appended",
      database_now: new Date("2026-08-01T00:00:01.000Z")
    }]
  };
}

function sqlState(code, message = code) {
  return Object.assign(new Error(message), { code });
}

function publisherProbeClient({
  directOperationAllowed = null,
  functionProbeError = null,
  clusterId = RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
} = {}) {
  let appendedBundleDigest = null;
  let appendTransactionActive = false;
  const calls = [];
  return {
    calls,
    async connect() {},
    async end() {},
    async query(text, values = []) {
      const sql = text.trim();
      calls.push(sql);
      if (sql.includes("crdb_internal.cluster_id()")) {
        return { rowCount: 1, rows: [{ cluster_id: clusterId }] };
      }
      if (sql.includes("statement_timestamp() AS database_now")) {
        return {
          rowCount: 1,
          rows: [{
            database_name: "tideproof_recovery",
            current_user_name: "tp_recovery_publisher_user",
            session_user_name: "tp_recovery_publisher_user",
            database_version: "CockroachDB CCL v26.2.5",
            database_now: new Date("2026-08-18T13:00:00.000Z")
          }]
        };
      }
      if (sql.startsWith("BEGIN TRANSACTION")) {
        appendTransactionActive = true;
        return {};
      }
      if (sql === "ROLLBACK") {
        appendTransactionActive = false;
        return {};
      }
      if (sql.includes("mcp_api.append_recovery_bundle_v2")) {
        if (functionProbeError) throw functionProbeError;
        appendedBundleDigest = values[8];
        return {
          rowCount: 1,
          rows: [{
            bundle_digest: appendedBundleDigest,
            outcome: "bundle_appended",
            database_now: new Date("2026-08-18T13:00:01.000Z")
          }]
        };
      }
      if (sql.includes("mcp_api.resolve_recovery_bundle_v1")) {
        return appendTransactionActive && appendedBundleDigest === values[3]
          ? {
              rowCount: 1,
              rows: [{
                bundle_digest: appendedBundleDigest,
                outcome: "bundle_present",
                database_now: new Date("2026-08-18T13:00:01.000Z")
              }]
            }
          : { rowCount: 0, rows: [] };
      }
      const operation = sql.split(/\s+/u)[0];
      if (
        sql.includes("mcp_private.recovery_bundles_v2") &&
        ["SELECT", "INSERT", "UPDATE", "DELETE"].includes(operation)
      ) {
        if (directOperationAllowed === operation) return { rowCount: 0, rows: [] };
        throw sqlState("42501", `${operation} denied`);
      }
      return {};
    }
  };
}

function recoveryAdminPosture({ privateUsage = false, extraGrants = [] } = {}) {
  const functionNames = [
    "append_recovery_bundle_v2(uuid,uuid,text,int8,int8,uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,jsonb,jsonb,jsonb,timestamptz)",
    "resolve_recovery_bundle_v1(uuid,uuid,int8,text)"
  ];
  return {
    session: [{
      database_name: "tideproof_recovery",
      current_user_name: "cluster_admin",
      session_user_name: "cluster_admin",
      database_version: "CockroachDB CCL v26.2.5"
    }],
    principals: [
      { username: "cluster_admin", options: [] },
      { username: "tp_recovery_owner", options: ["NOLOGIN"] },
      { username: "tp_recovery_publisher_role", options: ["NOLOGIN"] },
      { username: "tp_recovery_publisher_user", options: [] }
    ],
    memberships: [
      { role_name: "admin", member: "cluster_admin", is_admin: false },
      {
        role_name: "tp_recovery_publisher_role",
        member: "tp_recovery_publisher_user",
        is_admin: false
      }
    ],
    systemGrants: [],
    objectGrants: [
      {
        database_name: "tideproof_recovery",
        schema_name: null,
        object_name: null,
        object_type: "database",
        grantee: "tp_recovery_publisher_role",
        privilege_type: "CONNECT",
        is_grantable: false
      },
      {
        database_name: "tideproof_recovery",
        schema_name: "mcp_api",
        object_name: null,
        object_type: "schema",
        grantee: "tp_recovery_publisher_role",
        privilege_type: "USAGE",
        is_grantable: false
      },
      ...(privateUsage ? [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_private",
        object_name: null,
        object_type: "schema",
        grantee: "tp_recovery_publisher_role",
        privilege_type: "USAGE",
        is_grantable: false
      }] : []),
      ...functionNames.map((objectName) => ({
        database_name: "tideproof_recovery",
        schema_name: "mcp_api",
        object_name: objectName,
        object_type: "function",
        grantee: "tp_recovery_publisher_role",
        privilege_type: "EXECUTE",
        is_grantable: false
      })),
      ...extraGrants
    ],
    defaultGrants: []
  };
}

const RECOVERY_FUNCTION_DEFINITIONS = Object.freeze({
  append: `CREATE OR REPLACE FUNCTION mcp_api.append_recovery_bundle_v2()
    RETURNS TABLE(bundle_digest STRING)
    LANGUAGE PLpgSQL SECURITY DEFINER AS $$
    BEGIN
      IF session_user <> 'tp_recovery_publisher_user' THEN RAISE EXCEPTION 'denied'; END IF;
      SELECT count(*) FROM mcp_private.recovery_bundles_v2;
      INSERT INTO mcp_private.recovery_bundles_v2 DEFAULT VALUES;
    END $$`,
  resolve: `CREATE OR REPLACE FUNCTION mcp_api.resolve_recovery_bundle_v1()
    RETURNS TABLE(bundle_digest STRING)
    LANGUAGE SQL SECURITY DEFINER AS $$
    SELECT bundle_digest FROM mcp_private.recovery_bundles_v2
    WHERE session_user = 'tp_recovery_publisher_user' $$`
});

function recoveryAdminState(options = {}) {
  return {
    repaired: options.privateUsage ?? false,
    extraGrants: options.extraGrants ?? [],
    commitApplies: options.commitApplies ?? true,
    commitError: options.commitError ?? null,
    grantError: options.grantError ?? null,
    rollbackError: options.rollbackError ?? null,
    definitionDrift: options.definitionDrift ?? false,
    clusterId: options.clusterId ??
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID,
    afterCommitDefinitionDrift:
      options.afterCommitDefinitionDrift ?? false,
    afterCommitClusterId: options.afterCommitClusterId ?? null,
    afterCommitExtraGrants: options.afterCommitExtraGrants ?? null
  };
}

function recoveryAdminClient(options = {}) {
  const state = options.state ?? recoveryAdminState(options);
  const calls = [];
  let grantPending = false;
  return {
    calls,
    state,
    async connect() {},
    async end() {},
    async query(sql) {
      calls.push(sql.trim());
      if (sql.includes("crdb_internal.cluster_id()")) {
        return {
          rowCount: 1,
          rows: [{ cluster_id: state.clusterId }]
        };
      }
      if (sql.startsWith("SHOW CREATE FUNCTION")) {
        const append = sql.includes("append_recovery_bundle_v2");
        return {
          rowCount: 1,
          rows: [{
            create_statement: append
              ? `${RECOVERY_FUNCTION_DEFINITIONS.append}${
                state.definitionDrift ? "\n-- drift" : ""
              }`
              : RECOVERY_FUNCTION_DEFINITIONS.resolve
          }]
        };
      }
      if (sql.includes("FROM [SHOW USERS]")) {
        return { rows: recoveryAdminPosture({
          privateUsage: state.repaired,
          extraGrants: state.extraGrants
        }).principals };
      }
      if (sql.includes("FROM [SHOW GRANTS ON ROLE]")) {
        return { rows: recoveryAdminPosture({
          privateUsage: state.repaired,
          extraGrants: state.extraGrants
        }).memberships };
      }
      if (sql.includes("FROM [SHOW SYSTEM GRANTS]")) return { rows: [] };
      if (sql.includes("FROM [SHOW GRANTS]")) {
        return { rows: recoveryAdminPosture({
          privateUsage: state.repaired,
          extraGrants: state.extraGrants
        }).objectGrants };
      }
      if (sql.includes("FROM [SHOW DEFAULT PRIVILEGES]")) return { rows: [] };
      if (sql.includes("current_database() AS database_name")) {
        return { rows: recoveryAdminPosture({
          privateUsage: state.repaired,
          extraGrants: state.extraGrants
        }).session };
      }
      if (sql === "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role") {
        if (state.grantError) throw state.grantError;
        grantPending = true;
      }
      if (sql.trim() === "COMMIT" && grantPending) {
        if (state.commitApplies) state.repaired = true;
        if (state.afterCommitExtraGrants) {
          state.extraGrants = state.afterCommitExtraGrants;
        }
        if (state.afterCommitDefinitionDrift) {
          state.definitionDrift = true;
        }
        if (state.afterCommitClusterId) {
          state.clusterId = state.afterCommitClusterId;
        }
        grantPending = false;
        if (state.commitError) throw state.commitError;
      }
      if (sql.trim() === "ROLLBACK") {
        grantPending = false;
        if (state.rollbackError) throw state.rollbackError;
      }
      return { rows: [] };
    }
  };
}

const SCHEMA_REPAIR_SOURCE_COMMIT = "1".repeat(40);
const SCHEMA_REPAIR_SOURCE_TREE = "2".repeat(40);
const SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST = "b".repeat(64);
const functionDefinitionDigest = (value) =>
  createHash("sha256").update(value).digest("hex");
const SCHEMA_REPAIR_APPEND_FUNCTION_DIGEST =
  functionDefinitionDigest(RECOVERY_FUNCTION_DEFINITIONS.append);
const SCHEMA_REPAIR_RESOLVE_FUNCTION_DIGEST =
  functionDefinitionDigest(RECOVERY_FUNCTION_DEFINITIONS.resolve);
const verifiedSourceCheckout = ({ sourceCommit, treeDigest }) => ({
  sourceCommit,
  treeDigest
});

function repairArguments(overrides = {}) {
  const legacySummary = validateDatabaseSecurityPosture(
    recoveryAdminPosture(),
    recoverySecurityContract.LEGACY_RECOVERY_POSTURE_SPEC
  );
  return {
    adminConnectionString:
      "postgresql://cluster_admin:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    publisherConnectionString:
      "postgresql://tp_recovery_publisher_user:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    expectedRecoveryHostname: "recovery.example",
    expectedRecoveryProviderClusterId:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID,
    expectedRecoverySqlClusterId:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID,
    expectedPreflightPostureDigest: legacySummary.postureDigest,
    expectedClusterPreflightPostureDigest:
      SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST,
    expectedAppendFunctionDefinitionSha256:
      SCHEMA_REPAIR_APPEND_FUNCTION_DIGEST,
    expectedResolveFunctionDefinitionSha256:
      SCHEMA_REPAIR_RESOLVE_FUNCTION_DIGEST,
    sourceCommit: SCHEMA_REPAIR_SOURCE_COMMIT,
    sourceTree: SCHEMA_REPAIR_SOURCE_TREE,
    verifySourceCheckout: verifiedSourceCheckout,
    ...overrides
  };
}

test("publisher capability collector executes functions only in a rolled-back probe", async () => {
  const client = publisherProbeClient();
  const result = await collectRecoveryPublisherCapabilityPosture(client, {
    expectedRecoverySqlClusterId:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
  });
  assert.equal(result.functionProbe.appendOutcome, "bundle_appended");
  assert.equal(result.functionProbe.resolveOutcome, "bundle_present");
  assert.equal(result.functionProbe.rollbackVerified, true);
  assert.deepEqual(
    Object.keys(result.directTableDenials),
    ["select", "insert", "update", "delete"]
  );
  assert.equal(
    Object.values(result.directTableDenials).every(
      (entry) => entry.denied && entry.sqlstate === "42501"
    ),
    true
  );
  assert.equal(
    client.calls.filter((sql) => sql === "ROLLBACK").length,
    5
  );
  assert.equal(client.calls.includes("COMMIT"), false);
  assert.equal(
    result.sqlClusterId,
    RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
  );
});

test("publisher capability collector rejects any direct private-table operation", async () => {
  for (const operation of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
    await assert.rejects(
      collectRecoveryPublisherCapabilityPosture(
        publisherProbeClient({ directOperationAllowed: operation }),
        {
          expectedRecoverySqlClusterId:
            RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
        }
      ),
      new RegExp(`RECOVERY_PUBLISHER_DIRECT_${operation}_NOT_DENIED`, "u")
    );
  }
});

test("publisher capability collector byte-compares its observed cluster UUID", async () => {
  const client = publisherProbeClient({
    clusterId: "11111111-1111-4111-8111-111111111111"
  });
  await assert.rejects(
    collectRecoveryPublisherCapabilityPosture(client, {
      expectedRecoverySqlClusterId:
        RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
    }),
    /RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_MISMATCH/u
  );
  assert.equal(
    client.calls.some((sql) => sql.startsWith("BEGIN TRANSACTION")),
    false
  );
});

test("stored recovery function definitions are read and digest-bound", async () => {
  const result = await collectRecoveryPublisherFunctionDefinitions(
    recoveryAdminClient()
  );
  assert.equal(result.definitions.length, 2);
  assert.match(result.bindingSha256, /^[0-9a-f]{64}$/u);
  await assert.rejects(
    collectRecoveryPublisherFunctionDefinitions({
      async query() {
        return { rows: [{ create_statement: "CREATE FUNCTION unsafe()" }] };
      }
    }),
    /RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_INVALID/u
  );
});

test("read-only repair verification distinguishes exact absent and present state", async () => {
  for (const [privateUsage, expectedStatus] of [
    [false, "CONFIRMED_ABSENT"],
    [true, "CONFIRMED_PRESENT"]
  ]) {
    const admin = recoveryAdminClient({ privateUsage });
    const result = await verifyRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments(),
      createAdminClient: () => admin,
      createPublisherClient: () => publisherProbeClient(),
      collectClusterPosture: async () => ({ postureDigest: "c".repeat(64) })
    });
    assert.equal(result.status, expectedStatus);
    assert.equal(result.mode, "VERIFY_APPLIED_READ_ONLY");
    assert.equal(result.mutationCount, 0);
    assert.equal(result.target.providerClusterId,
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID);
    assert.equal(result.target.sqlClusterId,
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID);
    assert.equal(result.source.commit, SCHEMA_REPAIR_SOURCE_COMMIT);
    assert.equal(result.source.tree, SCHEMA_REPAIR_SOURCE_TREE);
    assert.equal(
      result.observedRecoverySqlClusterId,
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
    );
    assert.deepEqual(result.expectedFunctionDefinitionDigests, {
      appendRecoveryBundleV2: SCHEMA_REPAIR_APPEND_FUNCTION_DIGEST,
      resolveRecoveryBundleV1: SCHEMA_REPAIR_RESOLVE_FUNCTION_DIGEST
    });
    assert.equal(
      result.concurrentAdministratorRequirement,
      "NO_CONCURRENT_ADMINISTRATOR_MUTATION_REQUIRED_NOT_VERIFIED"
    );
    assert.equal(
      admin.calls.some((sql) => sql.startsWith("GRANT ")),
      false
    );
  }
});

test("existing-cluster repair binds exact preflight and verifies through a fresh client", async () => {
  const state = recoveryAdminState();
  const clients = [];
  let clusterReads = 0;
  const result = await repairRecoveryPublisherPrivateSchemaUsage({
    ...repairArguments(),
    confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
    createAdminClient: () => {
      const client = recoveryAdminClient({ state });
      clients.push(client);
      return client;
    },
    createReconciliationAdminClient: () => {
      const client = recoveryAdminClient({ state });
      clients.push(client);
      return client;
    },
    createReconciliationPublisherClient: () => publisherProbeClient(),
    collectClusterPosture: async () => ({
      postureDigest: ++clusterReads === 1
        ? SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
        : "c".repeat(64)
    })
  });
  assert.equal(result.status, "CONFIRMED_PRESENT");
  assert.equal(result.observation, "direct_ack");
  assert.equal(result.preflightPostureDigest,
    repairArguments().expectedPreflightPostureDigest);
  assert.equal(result.clusterPreflightPostureDigest,
    SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST);
  assert.equal(result.capabilityPosture.functionProbe.rollbackVerified, true);
  assert.equal(
    result.preflightObservedRecoverySqlClusterId,
    RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
  );
  assert.equal(
    result.capabilityPosture.sqlClusterId,
    RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID
  );
  assert.equal(clients.length, 2);
  assert.equal(
    clients.flatMap((client) => client.calls).filter((sql) =>
      sql === "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
    ).length,
    1
  );
});

test("repair reconciles COMMIT ACK loss as present without retry", async () => {
  const state = recoveryAdminState({
    commitError: sqlState("ECONNRESET")
  });
  const clients = [];
  let clusterReads = 0;
  const result = await repairRecoveryPublisherPrivateSchemaUsage({
    ...repairArguments(),
    confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
    createAdminClient: () => {
      const client = recoveryAdminClient({ state });
      clients.push(client);
      return client;
    },
    createReconciliationAdminClient: () => {
      const client = recoveryAdminClient({ state });
      clients.push(client);
      return client;
    },
    createReconciliationPublisherClient: () => publisherProbeClient(),
    collectClusterPosture: async () => ({
      postureDigest: ++clusterReads === 1
        ? SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
        : "c".repeat(64)
    })
  });
  assert.equal(result.status, "CONFIRMED_PRESENT");
  assert.equal(result.observation, "read_reconciled");
  assert.equal(result.commitAcknowledged, false);
  assert.equal(
    clients.flatMap((client) => client.calls).filter((sql) =>
      sql === "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
    ).length,
    1
  );
});

test("repair reconciles COMMIT ACK loss as absent and never retries", async () => {
  const state = recoveryAdminState({
    commitApplies: false,
    commitError: sqlState("ECONNRESET")
  });
  const clients = [];
  let clusterReads = 0;
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments(),
      confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
      createAdminClient: () => {
        const client = recoveryAdminClient({ state });
        clients.push(client);
        return client;
      },
      createReconciliationAdminClient: () => {
        const client = recoveryAdminClient({ state });
        clients.push(client);
        return client;
      },
      createReconciliationPublisherClient: () => publisherProbeClient(),
      collectClusterPosture: async () => ({
        postureDigest: ++clusterReads === 1
          ? SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
          : "c".repeat(64)
      })
    }),
    (error) => {
      assert.equal(error.code, "RECOVERY_SCHEMA_REPAIR_CONFIRMED_ABSENT");
      assert.equal(error.reconciliation.status, "CONFIRMED_ABSENT");
      assert.equal(error.reconciliation.observation, "read_reconciled");
      return true;
    }
  );
  assert.equal(
    clients.flatMap((client) => client.calls).filter((sql) =>
      sql === "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
    ).length,
    1
  );
});

test("repair marks contradictory ACK-loss readback unresolved", async () => {
  const state = recoveryAdminState({
    commitError: sqlState("ECONNRESET"),
    afterCommitExtraGrants: [{
      database_name: "tideproof_recovery",
      schema_name: "mcp_private",
      object_name: "recovery_bundles_v2",
      object_type: "table",
      grantee: "tp_recovery_publisher_role",
      privilege_type: "SELECT",
      is_grantable: false
    }]
  });
  let clusterReads = 0;
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments(),
      confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
      createAdminClient: () => recoveryAdminClient({ state }),
      createReconciliationAdminClient: () => recoveryAdminClient({ state }),
      createReconciliationPublisherClient: () => publisherProbeClient(),
      collectClusterPosture: async () => ({
        postureDigest: ++clusterReads === 1
          ? SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
          : "c".repeat(64)
      })
    }),
    ({ code }) =>
      code === "RECOVERY_SCHEMA_REPAIR_RECONCILIATION_UNRESOLVED"
  );
});

test("post-COMMIT verification failure is recoverable only by read-only verification", async () => {
  const state = recoveryAdminState();
  let clusterReads = 0;
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments(),
      confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
      createAdminClient: () => recoveryAdminClient({ state }),
      createReconciliationAdminClient: () => recoveryAdminClient({ state }),
      createReconciliationPublisherClient: () => publisherProbeClient({
        functionProbeError: sqlState("42501")
      }),
      collectClusterPosture: async () => ({
        postureDigest: ++clusterReads === 1
          ? SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
          : "c".repeat(64)
      })
    }),
    ({ code }) =>
      code === "RECOVERY_SCHEMA_REPAIR_POSTCOMMIT_VERIFICATION_UNRESOLVED"
  );
  const reconciled = await verifyRecoveryPublisherPrivateSchemaUsage({
    ...repairArguments(),
    createAdminClient: () => recoveryAdminClient({ state }),
    createPublisherClient: () => publisherProbeClient(),
    collectClusterPosture: async () => ({ postureDigest: "c".repeat(64) })
  });
  assert.equal(reconciled.status, "CONFIRMED_PRESENT");
  assert.equal(reconciled.observation, "read_only_verification");
});

test("post-COMMIT function or cluster drift remains unresolved without retry", async () => {
  for (const stateOptions of [
    { afterCommitDefinitionDrift: true },
    { afterCommitClusterId: "11111111-1111-4111-8111-111111111111" }
  ]) {
    const state = recoveryAdminState(stateOptions);
    const clients = [];
    let clusterReads = 0;
    await assert.rejects(
      repairRecoveryPublisherPrivateSchemaUsage({
        ...repairArguments(),
        confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
        createAdminClient: () => {
          const client = recoveryAdminClient({ state });
          clients.push(client);
          return client;
        },
        createReconciliationAdminClient: () => {
          const client = recoveryAdminClient({ state });
          clients.push(client);
          return client;
        },
        createReconciliationPublisherClient: () => publisherProbeClient(),
        collectClusterPosture: async () => ({
          postureDigest: ++clusterReads === 1
            ? SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
            : "c".repeat(64)
        })
      }),
      ({ code }) =>
        code === "RECOVERY_SCHEMA_REPAIR_POSTCOMMIT_VERIFICATION_UNRESOLVED"
    );
    assert.equal(
      clients.flatMap((client) => client.calls).filter((sql) =>
        sql ===
          "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
      ).length,
      1
    );
  }
});

test("repair stops on rollback failure before dispatching COMMIT", async () => {
  const state = recoveryAdminState({
    grantError: sqlState("40001"),
    rollbackError: new Error("synthetic rollback failure")
  });
  const admin = recoveryAdminClient({ state });
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments(),
      confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
      createAdminClient: () => admin,
      collectClusterPosture: async () => ({
        postureDigest: SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
      })
    }),
    ({ code }) => code === "RECOVERY_SCHEMA_REPAIR_ROLLBACK_FAILED"
  );
  const grantIndex = admin.calls.indexOf(
    "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
  );
  assert.equal(
    admin.calls.slice(grantIndex + 1).includes("COMMIT"),
    false
  );
});

test("existing-cluster repair fails closed on identity, digest, and posture drift", async () => {
  const common = {
    ...repairArguments(),
    confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
    createReconciliationPublisherClient: () => publisherProbeClient(),
    collectClusterPosture: async () => ({
      postureDigest: SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST
    })
  };
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      createAdminClient: () => recoveryAdminClient({
        clusterId: "11111111-1111-4111-8111-111111111111"
      })
    }),
    /RECOVERY_SCHEMA_REPAIR_CLUSTER_OBSERVATION_MISMATCH/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      expectedAppendFunctionDefinitionSha256: "f".repeat(64),
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_FUNCTION_DEFINITION_MISMATCH/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      expectedRecoveryProviderClusterId:
        "00000000-0000-0000-0000-000000000000",
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID_INVALID/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      expectedRecoverySqlClusterId:
        "00000000-0000-0000-0000-000000000000",
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_SQL_CLUSTER_ID_INVALID/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      expectedClusterPreflightPostureDigest: "d".repeat(64),
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_CLUSTER_PREFLIGHT_MISMATCH/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      createAdminClient: () => recoveryAdminClient({ privateUsage: true })
    }),
    /RECOVERY_SCHEMA_REPAIR_ALREADY_APPLIED/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      createAdminClient: () => recoveryAdminClient({
        extraGrants: [{
          database_name: "tideproof_recovery",
          schema_name: "mcp_private",
          object_name: "recovery_bundles_v2",
          object_type: "table",
          grantee: "tp_recovery_publisher_role",
          privilege_type: "SELECT",
          is_grantable: false
        }]
      })
    }),
    /RECOVERY_SCHEMA_REPAIR_POSTURE_UNRESOLVED/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      confirmation: "not-authorized",
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED/u
  );
});

test("repair requires the executing standalone exact-Git checkout identity", async () => {
  for (const exactGitCode of [
    "EXACT_GIT_SOURCE_WORKTREE_CONFIG",
    "EXACT_GIT_SOURCE_DIRTY",
    "EXACT_GIT_SOURCE_ROOT",
    "EXACT_GIT_SOURCE_OBJECT_PATH"
  ]) {
    let adminCreated = false;
    await assert.rejects(
      repairRecoveryPublisherPrivateSchemaUsage({
        ...repairArguments({
          verifySourceCheckout() {
            throw new Error(exactGitCode);
          }
        }),
        confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
        createAdminClient: () => {
          adminCreated = true;
          return recoveryAdminClient();
        }
      }),
      ({ code, cause }) =>
        code === "RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID" &&
        cause?.message === exactGitCode
    );
    assert.equal(adminCreated, false);
  }

  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments({
        verifySourceCheckout: () => ({
          sourceCommit: "a".repeat(40),
          treeDigest: SCHEMA_REPAIR_SOURCE_TREE
        })
      }),
      confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
      createAdminClient: () => assert.fail("identity mismatch must stop first")
    }),
    /RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID/u
  );

  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...repairArguments({ verifySourceCheckout: undefined }),
      confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
      createAdminClient: () => assert.fail("unverified source must stop first")
    }),
    /RECOVERY_SCHEMA_REPAIR_SOURCE_CHECKOUT_INVALID/u
  );
});

test("repair CLI gates apply and exposes only a read-only verify mode", async () => {
  const environment = {
    RECOVERY_ADMIN_DATABASE_URL: repairArguments().adminConnectionString,
    RECOVERY_PUBLISHER_DATABASE_URL:
      repairArguments().publisherConnectionString,
    EXPECTED_RECOVERY_HOSTNAME: "recovery.example",
    EXPECTED_RECOVERY_CLUSTER_ID:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID,
    EXPECTED_RECOVERY_SQL_CLUSTER_ID:
      RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID,
    EXPECTED_RECOVERY_PRE_REPAIR_POSTURE_SHA256:
      repairArguments().expectedPreflightPostureDigest,
    EXPECTED_RECOVERY_CLUSTER_PRE_REPAIR_POSTURE_SHA256:
      SCHEMA_REPAIR_CLUSTER_PREFLIGHT_DIGEST,
    EXPECTED_RECOVERY_APPEND_FUNCTION_DEFINITION_SHA256:
      SCHEMA_REPAIR_APPEND_FUNCTION_DIGEST,
    EXPECTED_RECOVERY_RESOLVE_FUNCTION_DEFINITION_SHA256:
      SCHEMA_REPAIR_RESOLVE_FUNCTION_DIGEST,
    RECOVERY_SCHEMA_REPAIR_SOURCE_COMMIT: SCHEMA_REPAIR_SOURCE_COMMIT,
    RECOVERY_SCHEMA_REPAIR_SOURCE_TREE: SCHEMA_REPAIR_SOURCE_TREE
  };
  const written = [];
  await repairCliMain(["--verify-applied"], environment, {
    write: (value) => written.push(value),
    verifyRepair: async (options) => ({
      status: "CONFIRMED_PRESENT",
      applied: true,
      options
    })
  });
  assert.equal(written[0].options.confirmation, undefined);
  await assert.rejects(
    repairCliMain(["--apply"], environment, {
      write() {},
      applyRepair: async () => assert.fail("apply must remain gated")
    }),
    /RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION_REQUIRED/u
  );
  await assert.rejects(
    repairCliMain(["--verify-applied", "extra"], environment),
    /RECOVERY_SCHEMA_REPAIR_MODE_REQUIRED/u
  );
  await assert.rejects(
    repairCliMain(["--verify-applied"], {}, {
      write() {},
      verifyRepair: async () => assert.fail("missing binding must stop first")
    }),
    /RECOVERY_ADMIN_DATABASE_URL_REQUIRED/u
  );
});

test("recovery publisher succeeds without retry", async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u).slice(0, 2).join(" "));
      return text.includes("append_recovery_bundle_v2") ? result() : {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE);
  assert.equal(output.outcome, "bundle_appended");
  assert.equal(output.commit.observation, "direct_ack");
  assert.equal(output.commit.outcome, "bundle_present");
  assert.deepEqual(calls, ["BEGIN TRANSACTION", "SELECT *", "COMMIT"]);
});

test("recovery publisher resolves an exact receipt after COMMIT ACK loss", async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u).slice(0, 2).join(" "));
      if (text.includes("append_recovery_bundle_v2")) return result();
      if (text.trim() === "COMMIT") throw sqlState("ECONNRESET");
      return {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE, {
    reconcile: async () => ({
      rowCount: 1,
      rows: [{
        bundle_digest: BUNDLE.bundleDigest,
        outcome: "bundle_present",
        database_now: new Date("2026-08-01T00:00:02.000Z")
      }]
    })
  });

  assert.equal(output.outcome, "bundle_present");
  assert.equal(output.commit.status, "COMMITTED");
  assert.equal(output.commit.observation, "read_reconciled");
  assert.equal(output.commit.outcome, "bundle_present");
  assert.notEqual(output.outcome, "bundle_appended");
  assert.notEqual(output.outcome, "bundle_replay");
  assert.deepEqual(calls, ["BEGIN TRANSACTION", "SELECT *", "COMMIT"]);
});

test("recovery publisher never rolls back an unclassified post-COMMIT error", async () => {
  const calls = [];
  const events = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u)[0]);
      if (text.includes("append_recovery_bundle_v2")) return result();
      if (text.trim() === "COMMIT") throw sqlState("XX000");
      return {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE, {
    beforeReconcile: async () => events.push("ambiguous_closed"),
    reconcile: async () => {
      events.push("reconciliation_started");
      return {
        rowCount: 1,
        rows: [{
          bundle_digest: BUNDLE.bundleDigest,
          outcome: "bundle_present",
          database_now: new Date("2026-08-01T00:00:02.000Z")
        }]
      };
    }
  });

  assert.equal(output.commit.observation, "read_reconciled");
  assert.equal(calls.includes("ROLLBACK"), false);
  assert.deepEqual(events, ["ambiguous_closed", "reconciliation_started"]);
});

test("recovery publisher retries only a rolled-back serialization failure", async () => {
  const calls = [];
  const sleeps = [];
  let appendCalls = 0;
  const client = {
    async query(text) {
      const operation = text.trim().split(/\s+/u).slice(0, 2).join(" ");
      calls.push(operation);
      if (text.includes("append_recovery_bundle_v2")) {
        appendCalls += 1;
        if (appendCalls === 1) throw sqlState("40001");
        return result();
      }
      return {};
    }
  };
  await appendRecoveryBundleWithClient(client, BUNDLE, {
    now: () => 0,
    sleep: async (delay) => sleeps.push(delay)
  });
  assert.deepEqual(calls, [
    "BEGIN TRANSACTION",
    "SELECT *",
    "ROLLBACK",
    "BEGIN TRANSACTION",
    "SELECT *",
    "COMMIT"
  ]);
  assert.deepEqual(sleeps, [25]);
});

test("recovery publisher retries a serialization failure returned by COMMIT", async () => {
  const calls = [];
  let commitCalls = 0;
  const client = {
    async query(text) {
      const operation = text.trim().split(/\s+/u).slice(0, 2).join(" ");
      calls.push(operation);
      if (text.includes("append_recovery_bundle_v2")) return result();
      if (text.trim() === "COMMIT") {
        commitCalls += 1;
        if (commitCalls === 1) throw sqlState("40001");
      }
      return {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE, {
    now: () => 0,
    sleep: async () => {}
  });
  assert.equal(output.outcome, "bundle_appended");
  assert.equal(calls.includes("ROLLBACK"), true);
  assert.equal(commitCalls, 2);
});

test("recovery publisher bounds its retry deadline and attempts", async () => {
  const alwaysConflict = {
    async query(text) {
      if (text.includes("append_recovery_bundle_v2")) {
        throw sqlState("40001");
      }
      return {};
    }
  };
  let clock = 0;
  await assert.rejects(
    appendRecoveryBundleWithClient(alwaysConflict, BUNDLE, {
      now: () => clock,
      sleep: async (delay) => { clock += delay; },
      retryDeadlineMs: 25
    }),
    ({ code }) => code === "RECOVERY_PUBLISH_RETRY_DEADLINE_EXCEEDED"
  );
  await assert.rejects(
    appendRecoveryBundleWithClient(alwaysConflict, BUNDLE, {
      now: () => 0,
      sleep: async () => {},
      maxAttempts: 2
    }),
    ({ code }) => code === "RECOVERY_PUBLISH_RETRY_LIMIT_EXCEEDED"
  );
});

test("recovery publisher never retries or rolls back ambiguous transport errors", async () => {
  for (const error of [
    sqlState("40003"),
    sqlState("ECONNRESET"),
    new Error("Query read timeout")
  ]) {
    const calls = [];
    const client = {
      async query(text) {
        calls.push(text.trim().split(/\s+/u)[0]);
        if (text.includes("append_recovery_bundle_v2")) throw error;
        return {};
      }
    };
    await assert.rejects(
      appendRecoveryBundleWithClient(client, BUNDLE),
      error
    );
    assert.deepEqual(calls, ["BEGIN", "SELECT"]);
  }
});

test("database freshness rejection rolls back before canonical commit", async () => {
  const calls = [];
  const rejection = sqlState("22023", "recovery bundle is not current");
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u)[0]);
      if (text.includes("append_recovery_bundle_v2")) throw rejection;
      return {};
    }
  };
  await assert.rejects(
    appendRecoveryBundleWithClient(client, BUNDLE),
    rejection
  );
  assert.deepEqual(calls, ["BEGIN", "SELECT", "ROLLBACK"]);
});

test("recovery publisher stops when rollback fails", async () => {
  const client = {
    async query(text) {
      if (text.includes("append_recovery_bundle_v2")) {
        throw sqlState("40001");
      }
      if (text.trim() === "ROLLBACK") {
        throw new Error("synthetic rollback failure");
      }
      return {};
    }
  };
  await assert.rejects(
    appendRecoveryBundleWithClient(client, BUNDLE),
    ({ code }) => code === "RECOVERY_PUBLISH_ROLLBACK_FAILED"
  );
});

test("recovery publisher does not roll back a committed receipt mismatch", async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u)[0]);
      if (text.includes("append_recovery_bundle_v2")) {
        return {
          rowCount: 1,
          rows: [{ bundle_digest: "f".repeat(64), outcome: "bundle_appended" }]
        };
      }
      return {};
    }
  };
  await assert.rejects(
    appendRecoveryBundleWithClient(client, BUNDLE),
    /previously used with different input/u
  );
  assert.deepEqual(calls, ["BEGIN", "SELECT", "COMMIT"]);
});
