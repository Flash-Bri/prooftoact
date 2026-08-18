import assert from "node:assert/strict";
import test from "node:test";

import {
  __test as recoverySecurityContract,
  appendRecoveryBundleWithClient,
  collectRecoveryPublisherCapabilityPosture,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
  repairRecoveryPublisherPrivateSchemaUsage
} from "../src/cloud/recovery-security.js";
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

function publisherProbeClient({ directOperationAllowed = null } = {}) {
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

function recoveryAdminClient(options = {}) {
  let repaired = options.privateUsage ?? false;
  const calls = [];
  return {
    calls,
    async connect() {},
    async end() {},
    async query(sql) {
      calls.push(sql.trim());
      if (sql.includes("FROM [SHOW USERS]")) {
        return { rows: recoveryAdminPosture({
          privateUsage: repaired,
          extraGrants: options.extraGrants
        }).principals };
      }
      if (sql.includes("FROM [SHOW GRANTS ON ROLE]")) {
        return { rows: recoveryAdminPosture({
          privateUsage: repaired,
          extraGrants: options.extraGrants
        }).memberships };
      }
      if (sql.includes("FROM [SHOW SYSTEM GRANTS]")) return { rows: [] };
      if (sql.includes("FROM [SHOW GRANTS]")) {
        return { rows: recoveryAdminPosture({
          privateUsage: repaired,
          extraGrants: options.extraGrants
        }).objectGrants };
      }
      if (sql.includes("FROM [SHOW DEFAULT PRIVILEGES]")) return { rows: [] };
      if (sql.includes("current_database() AS database_name")) {
        return { rows: recoveryAdminPosture({
          privateUsage: repaired,
          extraGrants: options.extraGrants
        }).session };
      }
      if (sql === "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role") {
        repaired = true;
      }
      return { rows: [] };
    }
  };
}

test("publisher capability collector executes functions only in a rolled-back probe", async () => {
  const client = publisherProbeClient();
  const result = await collectRecoveryPublisherCapabilityPosture(client);
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
});

test("publisher capability collector rejects any direct private-table operation", async () => {
  for (const operation of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
    await assert.rejects(
      collectRecoveryPublisherCapabilityPosture(
        publisherProbeClient({ directOperationAllowed: operation })
      ),
      new RegExp(`RECOVERY_PUBLISHER_DIRECT_${operation}_NOT_DENIED`, "u")
    );
  }
});

test("existing-cluster repair accepts only exact legacy posture and verifies the result", async () => {
  const admin = recoveryAdminClient();
  const legacySummary = validateDatabaseSecurityPosture(
    recoveryAdminPosture(),
    recoverySecurityContract.LEGACY_RECOVERY_POSTURE_SPEC
  );
  let clusterReads = 0;
  const result = await repairRecoveryPublisherPrivateSchemaUsage({
    adminConnectionString:
      "postgresql://cluster_admin:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    publisherConnectionString:
      "postgresql://tp_recovery_publisher_user:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    expectedRecoveryHostname: "recovery.example",
    expectedPreflightPostureDigest: legacySummary.postureDigest,
    confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
    createAdminClient: () => admin,
    createPublisherClient: () => publisherProbeClient(),
    collectClusterPosture: async () => ({
      postureDigest: `${++clusterReads}`.repeat(64)
    })
  });
  assert.equal(result.status, "CONFIRMED_APPLIED");
  assert.equal(result.preflightPostureDigest, legacySummary.postureDigest);
  assert.notEqual(result.finalPostureDigest, result.preflightPostureDigest);
  assert.equal(result.capabilityPosture.functionProbe.rollbackVerified, true);
  assert.equal(clusterReads, 2);
  assert.equal(
    admin.calls.filter((sql) =>
      sql === "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
    ).length,
    1
  );
});

test("existing-cluster repair fails closed on already-repaired or drifted posture", async () => {
  const common = {
    adminConnectionString:
      "postgresql://cluster_admin:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    publisherConnectionString:
      "postgresql://tp_recovery_publisher_user:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    expectedRecoveryHostname: "recovery.example",
    expectedPreflightPostureDigest: "a".repeat(64),
    confirmation: RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
    createPublisherClient: () => publisherProbeClient(),
    collectClusterPosture: async () => ({ postureDigest: "b".repeat(64) })
  };
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
    /DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      publisherConnectionString:
        "postgresql://tp_recovery_publisher_user:secret@recovery.example:26257/tideproof_recovery?sslmode=require",
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_TARGET_INVALID/u
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      confirmation: "not-authorized",
      createAdminClient: () => recoveryAdminClient()
    }),
    /RECOVERY_SCHEMA_REPAIR_CONFIRMATION_REQUIRED/u
  );
  const clusterInvalidAdmin = recoveryAdminClient();
  const legacySummary = validateDatabaseSecurityPosture(
    recoveryAdminPosture(),
    recoverySecurityContract.LEGACY_RECOVERY_POSTURE_SPEC
  );
  await assert.rejects(
    repairRecoveryPublisherPrivateSchemaUsage({
      ...common,
      expectedPreflightPostureDigest: legacySummary.postureDigest,
      createAdminClient: () => clusterInvalidAdmin,
      collectClusterPosture: async () => ({})
    }),
    /RECOVERY_SCHEMA_REPAIR_CLUSTER_PREFLIGHT_INVALID/u
  );
  assert.equal(
    clusterInvalidAdmin.calls.includes(
      "GRANT USAGE ON SCHEMA mcp_private TO tp_recovery_publisher_role"
    ),
    false
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
