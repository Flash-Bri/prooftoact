import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  __test as recoverySecurityContract,
  appendRecoveryBundleWithClient,
  collectRecoveryPublisherFunctionDefinitions,
  collectRecoveryPublisherCapabilityPosture,
  collectManagedMcpRecoveryGrantPosture,
  disableManagedMcpRecoveryGrants,
  managedMcpRecoveryGrantPlan,
  MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION,
  MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL,
  MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
  MANAGED_MCP_RECOVERY_GRANT_PROVIDER_CLUSTER_ID,
  MANAGED_MCP_RECOVERY_GRANT_SQL,
  MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID,
  MANAGED_MCP_RECOVERY_ROLLBACK_SQL,
  MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256,
  preflightManagedMcpRecoveryGrants,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_CONFIRMATION,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_PROVIDER_CLUSTER_ID,
  RECOVERY_PUBLISHER_PRIVATE_SCHEMA_REPAIR_SQL_CLUSTER_ID,
  repairManagedMcpRecoveryGrants,
  repairRecoveryPublisherPrivateSchemaUsage,
  validateRecoverySecurityPosture,
  verifyManagedMcpRecoveryGrants,
  verifyRecoveryPublisherPrivateSchemaUsage
} from "../src/cloud/recovery-security.js";
import {
  createExclusiveManagedMcpJournal,
  main as managedMcpRepairCliMain
} from "../scripts/repair-managed-mcp-recovery-grants.js";
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
  functionProbeError = null
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
        throw sqlState("42501", "cluster metadata denied");
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

function recoveryAdminPosture({
  privateUsage = false,
  managedMcpState = "ABSENT",
  extraGrants = []
} = {}) {
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
      { username: "tp_recovery_publisher_user", options: [] },
      { username: "managed-mcp", options: ["NOLOGIN"] }
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
      ...([
        "SELECT_ONLY",
        "PUBLIC_VIEW_READY",
        "PRIVATE_USAGE_AND_SELECT",
        "PRESENT"
      ].includes(managedMcpState) ? [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_public",
        object_name: "recovery_bundle_v2",
        object_type: "table",
        grantee: "managed-mcp",
        privilege_type: "SELECT",
        is_grantable: false
      }] : []),
      ...([
        "PUBLIC_SCHEMA_ONLY",
        "PUBLIC_VIEW_READY",
        "PRIVATE_AND_PUBLIC_SCHEMA_USAGE",
        "PRESENT"
      ].includes(managedMcpState) ? [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_public",
        object_name: null,
        object_type: "schema",
        grantee: "managed-mcp",
        privilege_type: "USAGE",
        is_grantable: false
      }] : []),
      ...([
        "PRIVATE_SCHEMA_ONLY",
        "PRIVATE_USAGE_AND_SELECT",
        "PRIVATE_AND_PUBLIC_SCHEMA_USAGE",
        "PRESENT"
      ].includes(managedMcpState) ? [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_private",
        object_name: null,
        object_type: "schema",
        grantee: "managed-mcp",
        privilege_type: "USAGE",
        is_grantable: false
      }] : []),
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

const MANAGED_MCP_VIEW_DEFINITION = `CREATE VIEW mcp_public.recovery_bundle_v2 (
\ttenant_id,
\trecovery_session_id,
\tsubject_binding_hash,
\tschema_version,
\tsnapshot_version,
\tsource_cluster_id,
\tsource_commit_ts,
\tsource_digest,
\tbundle_digest,
\tpolicy_version,
\tpublisher_key_id,
\tpublisher_version,
\tsignature_algorithm,
\tsource_signature_base64,
\tsignature_digest,
\tcheckpoint_summary,
\tevidence_summary,
\tconflict_summary,
\treceipt_summary,
\tauthority_transferred,
\trequires_fresh_authorization,
\texpires_at
) AS SELECT
\t\ttenant_id,
\t\trecovery_session_id,
\t\tsubject_binding_hash,
\t\tschema_version,
\t\tsnapshot_version,
\t\tsource_cluster_id,
\t\tsource_commit_ts,
\t\tsource_digest,
\t\tbundle_digest,
\t\tpolicy_version,
\t\tpublisher_key_id,
\t\tpublisher_version,
\t\tsignature_algorithm,
\t\tsource_signature_base64,
\t\tsignature_digest,
\t\tcheckpoint_summary,
\t\tevidence_summary,
\t\tconflict_summary,
\t\treceipt_summary,
\t\tauthority_transferred,
\t\trequires_fresh_authorization,
\t\texpires_at
\tFROM
\t\ttideproof_recovery.mcp_private.recovery_bundles_v2;`;
const MANAGED_MCP_VIEW_DEFINITION_DIGEST =
  functionDefinitionDigest(MANAGED_MCP_VIEW_DEFINITION);
const MANAGED_MCP_OPERATION_ID =
  "44444444-4444-4444-8444-444444444444";
assert.equal(
  MANAGED_MCP_VIEW_DEFINITION_DIGEST,
  MANAGED_MCP_RECOVERY_VIEW_DEFINITION_SHA256
);

function managedMcpAdminState({
  grantState = "PUBLIC_VIEW_READY",
  dispatchErrors = new Map(),
  dispatchApplies = new Map(),
  viewDefinition = MANAGED_MCP_VIEW_DEFINITION,
  viewOwner = "tp_recovery_owner",
  clusterId = MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID,
  databaseVersion = "CockroachDB CCL v26.2.5",
  memberships = [{
    role_name: "admin",
    member: "cluster_admin",
    is_admin: false
  }, {
    role_name: "tp_recovery_publisher_role",
    member: "tp_recovery_publisher_user",
    is_admin: false
  }],
  systemGrants = [],
  defaultGrants = [],
  principal = { username: "managed-mcp", is_role: false },
  userOptions = ["NOLOGIN"],
  extraGrants = []
} = {}) {
  return {
    grantState,
    dispatchErrors,
    dispatchApplies,
    viewDefinition,
    viewOwner,
    clusterId,
    databaseVersion,
    memberships,
    systemGrants,
    defaultGrants,
    principal,
    userOptions,
    extraGrants
  };
}

const MANAGED_MCP_STATE_CAPABILITIES = Object.freeze({
  ABSENT: Object.freeze([]),
  SELECT_ONLY: Object.freeze(["VIEW_SELECT"]),
  PUBLIC_SCHEMA_ONLY: Object.freeze(["PUBLIC_USAGE"]),
  PRIVATE_SCHEMA_ONLY: Object.freeze(["PRIVATE_USAGE"]),
  PUBLIC_VIEW_READY: Object.freeze(["PUBLIC_USAGE", "VIEW_SELECT"]),
  PRIVATE_USAGE_AND_SELECT: Object.freeze(["PRIVATE_USAGE", "VIEW_SELECT"]),
  PRIVATE_AND_PUBLIC_SCHEMA_USAGE: Object.freeze([
    "PRIVATE_USAGE",
    "PUBLIC_USAGE"
  ]),
  PRESENT: Object.freeze([
    "PRIVATE_USAGE",
    "PUBLIC_USAGE",
    "VIEW_SELECT"
  ])
});

function managedMcpStateAfter(state, capability, present) {
  const capabilities = new Set(MANAGED_MCP_STATE_CAPABILITIES[state]);
  if (present) capabilities.add(capability);
  else capabilities.delete(capability);
  const serialized = [...capabilities].sort().join(",");
  const match = Object.entries(MANAGED_MCP_STATE_CAPABILITIES).find(
    ([, expected]) => [...expected].sort().join(",") === serialized
  );
  assert.ok(match, `unclassified Managed MCP state: ${serialized}`);
  return match[0];
}

function managedMcpAdminClient(state = managedMcpAdminState()) {
  const calls = [];
  return {
    calls,
    async connect() {},
    async end() {},
    async query(text) {
      const sql = text.trim();
      calls.push(sql);
      if (sql.includes("crdb_internal.cluster_id()")) {
        return {
          rowCount: 1,
          rows: [{
            database_name: "tideproof_recovery",
            current_user_name: "cluster_admin",
            session_user_name: "cluster_admin",
            database_version: state.databaseVersion,
            cluster_id: state.clusterId
          }]
        };
      }
      if (sql.includes("FROM system.users")) {
        return { rowCount: 1, rows: [state.principal] };
      }
      if (sql.includes("FROM [SHOW USERS]")) {
        return {
          rows: [
            ...recoveryAdminPosture({ privateUsage: true }).principals.filter(
              (row) => row.username !== "managed-mcp"
            ),
            { username: "managed-mcp", options: state.userOptions }
          ]
        };
      }
      if (sql.includes("FROM [SHOW GRANTS ON ROLE]")) {
        return { rows: state.memberships };
      }
      if (sql.includes("FROM [SHOW SYSTEM GRANTS]")) {
        return { rows: state.systemGrants };
      }
      if (sql.includes("FROM [SHOW GRANTS]")) {
        const all = recoveryAdminPosture({
          privateUsage: true,
          managedMcpState: state.grantState,
          extraGrants: state.extraGrants
        }).objectGrants;
        return { rows: [
          ...all,
          {
            database_name: "tideproof_recovery",
            schema_name: "mcp_private",
            object_name: "recovery_bundles_v2",
            object_type: "table",
            grantee: "tp_recovery_owner",
            privilege_type: "ALL",
            is_grantable: true
          }
        ] };
      }
      if (sql.includes("FROM [SHOW DEFAULT PRIVILEGES]")) {
        return { rows: state.defaultGrants };
      }
      if (sql.includes("FROM [SHOW TABLES FROM mcp_public]")) {
        return {
          rowCount: 1,
          rows: [{
            table_name: "recovery_bundle_v2",
            owner: state.viewOwner
          }]
        };
      }
      if (sql === "SHOW CREATE VIEW mcp_public.recovery_bundle_v2") {
        return {
          rowCount: 1,
          rows: [{ create_statement: state.viewDefinition }]
        };
      }
      if (sql === MANAGED_MCP_RECOVERY_GRANT_SQL[0]) {
        if (state.dispatchApplies.get(0) !== false) {
          state.grantState = managedMcpStateAfter(
            state.grantState,
            "PUBLIC_USAGE",
            false
          );
        }
        const error = state.dispatchErrors.get(0);
        if (error) throw error;
        return {};
      }
      if (sql === MANAGED_MCP_RECOVERY_GRANT_SQL[1]) {
        if (state.dispatchApplies.get(1) !== false) {
          state.grantState = managedMcpStateAfter(
            state.grantState,
            "PRIVATE_USAGE",
            true
          );
        }
        const error = state.dispatchErrors.get(1);
        if (error) throw error;
        return {};
      }
      if (sql === MANAGED_MCP_RECOVERY_GRANT_SQL[2]) {
        if (state.dispatchApplies.get(2) !== false) {
          state.grantState = managedMcpStateAfter(
            state.grantState,
            "PUBLIC_USAGE",
            true
          );
        }
        const error = state.dispatchErrors.get(2);
        if (error) throw error;
        return {};
      }
      if (sql === MANAGED_MCP_RECOVERY_ROLLBACK_SQL[1]) {
        state.grantState = managedMcpStateAfter(
          state.grantState,
          "PRIVATE_USAGE",
          false
        );
        const error = state.dispatchErrors.get(3);
        if (error) throw error;
        return {};
      }
      return {};
    }
  };
}

function managedMcpArguments(expectedPreflightPostureDigest, overrides = {}) {
  return {
    adminConnectionString:
      "postgresql://cluster_admin:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    expectedRecoveryHostname: "recovery.example",
    expectedRecoveryProviderClusterId:
      MANAGED_MCP_RECOVERY_GRANT_PROVIDER_CLUSTER_ID,
    expectedRecoverySqlClusterId:
      MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID,
    expectedPreflightPostureDigest,
    expectedViewDefinitionSha256: MANAGED_MCP_VIEW_DEFINITION_DIGEST,
    sourceCommit: SCHEMA_REPAIR_SOURCE_COMMIT,
    sourceTree: SCHEMA_REPAIR_SOURCE_TREE,
    operationId: MANAGED_MCP_OPERATION_ID,
    verifySourceCheckout: verifiedSourceCheckout,
    ...overrides
  };
}

async function managedMcpJournalReceipt(intent) {
  const intentSha256 = functionDefinitionDigest(JSON.stringify(intent));
  return {
    operationId: intent.operationId,
    intentSha256,
    reservation: "UNIQUE_RESERVED",
    targetReservationDigest: intent.targetReservationDigest,
    journalDigest: functionDefinitionDigest(`journal\0${intentSha256}`)
  };
}

managedMcpJournalReceipt.reserveTarget = async (intent) => {
  assert.equal(
    intent.targetBindingSha256,
    functionDefinitionDigest(JSON.stringify(intent.targetBinding))
  );
  return {
    operationId: intent.operationId,
    reservation: "TARGET_UNIQUE_RESERVED",
    targetBindingSha256: intent.targetBindingSha256,
    reservationDigest: functionDefinitionDigest(
      `target-reservation\0${intent.targetBindingSha256}`
    )
  };
};

function managedMcpCliEnvironment(overrides = {}) {
  return {
    RECOVERY_ADMIN_DATABASE_URL:
      "postgresql://cluster_admin:secret@recovery.example:26257/tideproof_recovery?sslmode=verify-full",
    EXPECTED_RECOVERY_HOSTNAME: "recovery.example",
    EXPECTED_RECOVERY_CLUSTER_ID:
      MANAGED_MCP_RECOVERY_GRANT_PROVIDER_CLUSTER_ID,
    EXPECTED_RECOVERY_SQL_CLUSTER_ID:
      MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID,
    EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256: "a".repeat(64),
    MANAGED_MCP_RECOVERY_REPAIR_SOURCE_COMMIT: SCHEMA_REPAIR_SOURCE_COMMIT,
    MANAGED_MCP_RECOVERY_REPAIR_SOURCE_TREE: SCHEMA_REPAIR_SOURCE_TREE,
    MANAGED_MCP_RECOVERY_OPERATION_ID: MANAGED_MCP_OPERATION_ID,
    MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY: "/private/journal",
    ...overrides
  };
}

function managedMcpTargetReservationIntent(
  operationId = MANAGED_MCP_OPERATION_ID
) {
  const targetBinding = {
    schemaVersion: "tideproof.managed-mcp-recovery-target-binding.v1",
    providerClusterIdSha256: "1".repeat(64),
    sqlClusterIdSha256: "2".repeat(64),
    databaseName: "tideproof_recovery",
    hostnameSha256: "3".repeat(64),
    adminPrincipalSha256: "4".repeat(64),
    managedPrincipal: "managed-mcp"
  };
  return {
    schemaVersion: "tideproof.managed-mcp-recovery-target-reservation.v1",
    operationId,
    targetBinding,
    targetBindingSha256: functionDefinitionDigest(
      JSON.stringify(targetBinding)
    )
  };
}

async function managedMcpPosture(state) {
  return collectManagedMcpRecoveryGrantPosture(
    managedMcpAdminClient(state),
    {
      expectedRecoverySqlClusterId:
        MANAGED_MCP_RECOVERY_GRANT_SQL_CLUSTER_ID,
      expectedViewDefinitionSha256: MANAGED_MCP_VIEW_DEFINITION_DIGEST
    }
  );
}

test("Managed MCP recovery plan deactivates the public view before private schema traversal and reactivates last", () => {
  const plan = managedMcpRecoveryGrantPlan();
  assert.deepEqual(plan.statements, [
    'REVOKE USAGE ON SCHEMA mcp_public FROM "managed-mcp"',
    'GRANT USAGE ON SCHEMA mcp_private TO "managed-mcp"',
    'GRANT USAGE ON SCHEMA mcp_public TO "managed-mcp"'
  ]);
  assert.deepEqual(plan.rollbackStatements, [
    'REVOKE USAGE ON SCHEMA mcp_public FROM "managed-mcp"',
    'REVOKE USAGE ON SCHEMA mcp_private FROM "managed-mcp"',
    'GRANT USAGE ON SCHEMA mcp_public TO "managed-mcp"'
  ]);
  assert.deepEqual(plan.requiredPreexistingCapabilities, [
    "SCHEMA:mcp_public:USAGE",
    "VIEW:mcp_public.recovery_bundle_v2:SELECT"
  ]);
  assert.deepEqual(plan.expectedAddedCapabilities, [
    "SCHEMA:mcp_private:USAGE"
  ]);
  assert.deepEqual(plan.freshBootstrapStatements, [
    'GRANT SELECT ON TABLE mcp_public.recovery_bundle_v2 TO "managed-mcp"',
    'GRANT USAGE ON SCHEMA mcp_private TO "managed-mcp"',
    'GRANT USAGE ON SCHEMA mcp_public TO "managed-mcp"'
  ]);
  assert.deepEqual(
    plan.freshBootstrapStatements,
    MANAGED_MCP_RECOVERY_FRESH_BOOTSTRAP_SQL
  );
  assert.equal(plan.explicitMultiStatementTransactionForbidden, true);
  assert.equal(plan.reconciliationRequiredAfterEachDispatch, true);
});

test("recovery posture accepts exact absent or present Managed MCP capability and rejects partial or private access", () => {
  for (const managedMcpState of ["ABSENT", "PRESENT"]) {
    const result = validateRecoverySecurityPosture(recoveryAdminPosture({
      privateUsage: true,
      managedMcpState
    }));
    assert.match(result.postureDigest, /^[0-9a-f]{64}$/u);
  }
  for (const managedMcpState of [
    "SELECT_ONLY",
    "PUBLIC_SCHEMA_ONLY",
    "PRIVATE_SCHEMA_ONLY",
    "PUBLIC_VIEW_READY",
    "PRIVATE_USAGE_AND_SELECT",
    "PRIVATE_AND_PUBLIC_SCHEMA_USAGE"
  ]) {
    assert.throws(
      () => validateRecoverySecurityPosture(recoveryAdminPosture({
        privateUsage: true,
        managedMcpState
      })),
      /DATABASE_POSTURE_MANAGED_GRANT_MISSING/u
    );
  }
  assert.throws(
    () => validateRecoverySecurityPosture(recoveryAdminPosture({
      privateUsage: true,
      managedMcpState: "PRESENT",
      extraGrants: [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_private",
        object_name: "recovery_bundles_v2",
        object_type: "table",
        grantee: "managed-mcp",
        privilege_type: "SELECT",
        is_grantable: false
      }]
    })),
    /DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED/u
  );
});

test("Managed MCP recovery collector names every exact zero, one, two, and three grant state", async () => {
  for (const expectedState of [
    "ABSENT",
    "SELECT_ONLY",
    "PUBLIC_SCHEMA_ONLY",
    "PRIVATE_SCHEMA_ONLY",
    "PUBLIC_VIEW_READY",
    "PRIVATE_USAGE_AND_SELECT",
    "PRIVATE_AND_PUBLIC_SCHEMA_USAGE",
    "PRESENT"
  ]) {
    const result = await managedMcpPosture(managedMcpAdminState({
      grantState: expectedState
    }));
    assert.equal(result.state, expectedState);
    assert.equal(result.principal, "managed-mcp");
    assert.equal(result.viewOwner, "tp_recovery_owner");
    assert.equal(result.viewDefinition.securityInvoker, false);
    assert.match(result.postureDigest, /^[0-9a-f]{64}$/u);
  }
});

test("Managed MCP recovery collector rejects identity, owner, view, membership, system, default, and extra-grant drift", async () => {
  for (const state of [
    managedMcpAdminState({
      clusterId: "00000000-0000-0000-0000-000000000000"
    }),
    managedMcpAdminState({ viewOwner: "root" }),
    managedMcpAdminState({ userOptions: ["NOLOGIN", "CREATEROLE"] }),
    managedMcpAdminState({
      viewDefinition: `${MANAGED_MCP_VIEW_DEFINITION} WITH (security_invoker=true)`
    }),
    managedMcpAdminState({
      memberships: [{ role_name: "admin", member: "managed-mcp" }]
    }),
    managedMcpAdminState({
      systemGrants: [{ grantee: "managed-mcp", privilege_type: "VIEWACTIVITY" }]
    }),
    managedMcpAdminState({
      defaultGrants: [{ role: "managed-mcp", grantee: "managed-mcp" }]
    }),
    managedMcpAdminState({
      extraGrants: [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_private",
        object_name: "recovery_bundles_v2",
        object_type: "table",
        grantee: "managed-mcp",
        privilege_type: "SELECT",
        is_grantable: false
      }]
    }),
    managedMcpAdminState({
      extraGrants: [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_private",
        object_name: "unsafe_probe()",
        object_type: "function",
        grantee: "managed-mcp",
        privilege_type: "EXECUTE",
        is_grantable: false
      }]
    }),
    managedMcpAdminState({
      extraGrants: [{
        database_name: "tideproof_recovery",
        schema_name: "mcp_private",
        object_name: null,
        object_type: "schema",
        grantee: "managed-mcp",
        privilege_type: "USAGE",
        is_grantable: true
      }]
    })
  ]) {
    await assert.rejects(managedMcpPosture(state));
  }
});

test("Managed MCP preflight discovers the exact posture digest after source binding and needs no prior digest", async () => {
  const state = managedMcpAdminState();
  const {
    expectedPreflightPostureDigest: ignoredDigest,
    operationId: ignoredOperationId,
    ...targetOptions
  } = managedMcpArguments("a".repeat(64));
  assert.equal(ignoredDigest, "a".repeat(64));
  assert.equal(ignoredOperationId, MANAGED_MCP_OPERATION_ID);
  let sourceChecked = false;
  const receipt = await preflightManagedMcpRecoveryGrants({
    ...targetOptions,
    verifySourceCheckout(options) {
      sourceChecked = true;
      return verifiedSourceCheckout(options);
    },
    createAdminClient() {
      assert.equal(sourceChecked, true);
      return managedMcpAdminClient(state);
    }
  });
  assert.equal(receipt.mode, "PREFLIGHT_READ_ONLY");
  assert.equal(receipt.status, "READY_FOR_PRIVATE_SCHEMA_USAGE");
  assert.equal(receipt.preflightPostureDigest, receipt.posture.postureDigest);
  await assert.rejects(
    preflightManagedMcpRecoveryGrants({
      ...targetOptions,
      verifySourceCheckout() {
        throw new Error("EXACT_GIT_SOURCE_DIRTY");
      },
      createAdminClient: () => assert.fail("source must stop provider access")
    }),
    /MANAGED_MCP_RECOVERY_SOURCE_CHECKOUT_INVALID/u
  );
});

test("Managed MCP repair accepts only the exact live public-view baseline and refuses every other state before mutation", async () => {
  for (const stateName of [
    "ABSENT",
    "SELECT_ONLY",
    "PUBLIC_SCHEMA_ONLY",
    "PRIVATE_SCHEMA_ONLY",
    "PRIVATE_USAGE_AND_SELECT",
    "PRIVATE_AND_PUBLIC_SCHEMA_USAGE"
  ]) {
    const state = managedMcpAdminState({ grantState: stateName });
    const posture = await managedMcpPosture(state);
    let mutationClients = 0;
    await assert.rejects(
      repairManagedMcpRecoveryGrants({
        ...managedMcpArguments(posture.postureDigest),
        confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
        journalIntent: managedMcpJournalReceipt,
        createAdminClient: () => {
          mutationClients += 1;
          return managedMcpAdminClient(state);
        },
        createReconciliationAdminClient: () => managedMcpAdminClient(state)
      }),
      /MANAGED_MCP_RECOVERY_PUBLIC_VIEW_BASELINE_REQUIRED/u
    );
    assert.equal(mutationClients, 0);
  }
  const present = managedMcpAdminState({ grantState: "PRESENT" });
  const presentPosture = await managedMcpPosture(present);
  await assert.rejects(
    repairManagedMcpRecoveryGrants({
      ...managedMcpArguments(presentPosture.postureDigest),
      confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
      journalIntent: managedMcpJournalReceipt,
      createAdminClient: () => assert.fail("present state must not mutate"),
      createReconciliationAdminClient: () => managedMcpAdminClient(present)
    }),
    /MANAGED_MCP_RECOVERY_ALREADY_APPLIED/u
  );
});

test("Managed MCP repair journals and reconciles each implicit grant without a multi-statement transaction", async () => {
  const state = managedMcpAdminState();
  const preflight = await managedMcpPosture(state);
  const mutationClients = [];
  const reconciliationClients = [];
  const journals = [];
  const journalIntent = async (intent) => {
    journals.push(intent);
    return managedMcpJournalReceipt(intent);
  };
  journalIntent.reserveTarget = managedMcpJournalReceipt.reserveTarget;
  const receipt = await repairManagedMcpRecoveryGrants({
    ...managedMcpArguments(preflight.postureDigest),
    confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
    journalIntent,
    createAdminClient: () => {
      const client = managedMcpAdminClient(state);
      mutationClients.push(client);
      return client;
    },
    createReconciliationAdminClient: () => {
      const client = managedMcpAdminClient(state);
      reconciliationClients.push(client);
      return client;
    }
  });
  assert.equal(receipt.status, "CONFIRMED_PRESENT");
  assert.equal(receipt.posture.state, "PRESENT");
  assert.equal(receipt.mutationDispatchCount, 3);
  assert.equal(receipt.mutationTransactionCount, 3);
  assert.equal(receipt.explicitMultiStatementTransactionUsed, false);
  assert.deepEqual(
    receipt.dispatches.map((entry) => entry.observedState),
    ["SELECT_ONLY", "PRIVATE_USAGE_AND_SELECT", "PRESENT"]
  );
  assert.equal(journals.length, 3);
  assert.deepEqual(
    journals.map((entry) => [
      entry.stepId,
      entry.expectedBeforeState,
      entry.expectedAfterState
    ]),
    [
      [
        "REVOKE_PUBLIC_SCHEMA_USAGE_DEACTIVATE",
        "PUBLIC_VIEW_READY",
        "SELECT_ONLY"
      ],
      [
        "GRANT_PRIVATE_SCHEMA_USAGE_INACTIVE",
        "SELECT_ONLY",
        "PRIVATE_USAGE_AND_SELECT"
      ],
      [
        "GRANT_PUBLIC_SCHEMA_USAGE_REACTIVATE",
        "PRIVATE_USAGE_AND_SELECT",
        "PRESENT"
      ]
    ]
  );
  assert.equal(reconciliationClients.length, 4);
  assert.equal(
    mutationClients.flatMap((client) => client.calls).some((sql) =>
      sql.startsWith("BEGIN TRANSACTION") || sql === "COMMIT"
    ),
    false
  );
});

test("Managed MCP repair reconciles acknowledgement loss without retry and stops on confirmed absence", async () => {
  const ackLossState = managedMcpAdminState({
    dispatchErrors: new Map([[0, sqlState("ECONNRESET")]])
  });
  const ackLossPreflight = await managedMcpPosture(ackLossState);
  const receipt = await repairManagedMcpRecoveryGrants({
    ...managedMcpArguments(ackLossPreflight.postureDigest),
    confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
    journalIntent: managedMcpJournalReceipt,
    createAdminClient: () => managedMcpAdminClient(ackLossState),
    createReconciliationAdminClient: () =>
      managedMcpAdminClient(ackLossState)
  });
  assert.equal(receipt.dispatches[0].acknowledged, false);
  assert.equal(receipt.dispatches[0].observation, "read_reconciled");
  assert.equal(receipt.status, "CONFIRMED_PRESENT");

  const absentState = managedMcpAdminState();
  const absentPreflight = await managedMcpPosture(absentState);
  let mutationCalls = 0;
  await assert.rejects(
    repairManagedMcpRecoveryGrants({
      ...managedMcpArguments(absentPreflight.postureDigest),
      confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
      journalIntent: managedMcpJournalReceipt,
      createAdminClient: () => ({
        async connect() {},
        async end() {},
        async query() {
          mutationCalls += 1;
          throw sqlState("42501");
        }
      }),
      createReconciliationAdminClient: () =>
        managedMcpAdminClient(absentState)
    }),
    /MANAGED_MCP_RECOVERY_DISPATCH_CONFIRMED_ABSENT/u
  );
  assert.equal(mutationCalls, 1);
});

test("Managed MCP disable deactivates first and restores the exact public-view baseline", async () => {
  const state = managedMcpAdminState({ grantState: "PRESENT" });
  const originalBaseline = await managedMcpPosture(managedMcpAdminState());
  const mutationClients = [];
  const receipt = await disableManagedMcpRecoveryGrants({
    ...managedMcpArguments(originalBaseline.postureDigest),
    confirmation: MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION,
    journalIntent: managedMcpJournalReceipt,
    createAdminClient: () => {
      const client = managedMcpAdminClient(state);
      mutationClients.push(client);
      return client;
    },
    createReconciliationAdminClient: () => managedMcpAdminClient(state)
  });
  assert.equal(receipt.status, "CONFIRMED_PRE_REPAIR_BASELINE");
  assert.equal(receipt.posture.state, "PUBLIC_VIEW_READY");
  assert.deepEqual(
    receipt.dispatches.map((entry) => entry.observedState),
    ["PRIVATE_USAGE_AND_SELECT", "SELECT_ONLY", "PUBLIC_VIEW_READY"]
  );
  assert.deepEqual(
    mutationClients.flatMap((client) => client.calls).filter((sql) =>
      MANAGED_MCP_RECOVERY_ROLLBACK_SQL.includes(sql)
    ),
    MANAGED_MCP_RECOVERY_ROLLBACK_SQL
  );
});

test("Managed MCP repair restores the exact public-view baseline after a denied private grant", async () => {
  const state = managedMcpAdminState({
    dispatchErrors: new Map([[1, sqlState("42501")]]),
    dispatchApplies: new Map([[1, false]])
  });
  const preflight = await managedMcpPosture(state);
  await assert.rejects(
    repairManagedMcpRecoveryGrants({
      ...managedMcpArguments(preflight.postureDigest),
      confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
      journalIntent: managedMcpJournalReceipt,
      createAdminClient: () => managedMcpAdminClient(state),
      createReconciliationAdminClient: () => managedMcpAdminClient(state)
    }),
    (error) => {
      assert.equal(
        error.code,
        "MANAGED_MCP_RECOVERY_DISPATCH_CONFIRMED_ABSENT"
      );
      assert.equal(
        error.emergencyDisable.status,
        "CONFIRMED_PRE_REPAIR_BASELINE"
      );
      return true;
    }
  );
  assert.equal(state.grantState, "PUBLIC_VIEW_READY");
});

test("Managed MCP repair disables an activated capability when post-activation verification fails", async () => {
  const state = managedMcpAdminState();
  const preflight = await managedMcpPosture(state);
  let reconciliationCount = 0;
  await assert.rejects(
    repairManagedMcpRecoveryGrants({
      ...managedMcpArguments(preflight.postureDigest),
      confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
      journalIntent: managedMcpJournalReceipt,
      createAdminClient: () => managedMcpAdminClient(state),
      createReconciliationAdminClient: () => {
        reconciliationCount += 1;
        if (reconciliationCount === 4) {
          return {
            async connect() {},
            async end() {},
            async query() {
              throw sqlState("ECONNRESET");
            }
          };
        }
        return managedMcpAdminClient(state);
      }
    }),
    (error) => {
      assert.equal(
        error.code,
        "MANAGED_MCP_RECOVERY_RECONCILIATION_UNRESOLVED"
      );
      assert.equal(
        error.emergencyDisable.status,
        "CONFIRMED_PRE_REPAIR_BASELINE"
      );
      return true;
    }
  );
  assert.equal(state.grantState, "PUBLIC_VIEW_READY");
});

test("Managed MCP repair disables schema usage observed concurrently after the inert first step", async () => {
  const state = managedMcpAdminState();
  const preflight = await managedMcpPosture(state);
  let reconciliationCount = 0;
  await assert.rejects(
    repairManagedMcpRecoveryGrants({
      ...managedMcpArguments(preflight.postureDigest),
      confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
      journalIntent: managedMcpJournalReceipt,
      createAdminClient: () => managedMcpAdminClient(state),
      createReconciliationAdminClient: () => {
        reconciliationCount += 1;
        if (reconciliationCount === 2) state.grantState = "PRESENT";
        return managedMcpAdminClient(state);
      }
    }),
    (error) => {
      assert.equal(
        error.code,
        "MANAGED_MCP_RECOVERY_DISPATCH_STATE_UNRESOLVED"
      );
      assert.equal(
        error.emergencyDisable.status,
        "CONFIRMED_PRE_REPAIR_BASELINE"
      );
      return true;
    }
  );
  assert.equal(state.grantState, "PUBLIC_VIEW_READY");
});

test("Managed MCP disable proves exact baseline restoration rather than capability removal alone", async () => {
  const state = managedMcpAdminState({ grantState: "PRESENT" });
  const originalBaseline = await managedMcpPosture(managedMcpAdminState());
  let reconciliationCount = 0;
  await assert.rejects(
    disableManagedMcpRecoveryGrants({
      ...managedMcpArguments(originalBaseline.postureDigest),
      confirmation: MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION,
      journalIntent: managedMcpJournalReceipt,
      createAdminClient: () => managedMcpAdminClient(state),
      createReconciliationAdminClient: () => {
        reconciliationCount += 1;
        if (reconciliationCount === 2) {
          state.databaseVersion = "CockroachDB CCL v26.2.6";
        }
        return managedMcpAdminClient(state);
      }
    }),
    (error) => {
      assert.equal(error.code, "MANAGED_MCP_RECOVERY_EMERGENCY_HOLD");
      assert.equal(error.reconciliation.posture.state, "PUBLIC_VIEW_READY");
      return true;
    }
  );
  assert.equal(state.grantState, "PUBLIC_VIEW_READY");
});

test("Managed MCP CLI exposes exact modes and gates apply and disable confirmations", async () => {
  const writes = [];
  const plan = await managedMcpRepairCliMain(["--plan"], {}, {
    write: (value) => writes.push(value)
  });
  assert.equal(plan.mode, "PLAN_ONLY");
  assert.ok(plan.requiredPreflightEnvironment.includes(
    "MANAGED_MCP_RECOVERY_REPAIR_SOURCE_COMMIT"
  ));
  assert.ok(!plan.requiredPreflightEnvironment.includes(
    "EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256"
  ));
  assert.ok(plan.requiredVerifyEnvironment.includes(
    "EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256"
  ));
  assert.equal(
    plan.operationIdGenerationCommand,
    "uuidgen | tr '[:upper:]' '[:lower:]'"
  );

  const environment = managedMcpCliEnvironment();
  let preflightOptions;
  const preflightReceipt = await managedMcpRepairCliMain(
    ["--preflight"],
    environment,
    {
      write: (value) => writes.push(value),
      preflightRepair: async (options) => {
        preflightOptions = options;
        return { mode: "PREFLIGHT_READ_ONLY" };
      }
    }
  );
  assert.equal(preflightReceipt.mode, "PREFLIGHT_READ_ONLY");
  assert.equal(
    "expectedPreflightPostureDigest" in preflightOptions,
    false
  );

  let verifyOptions;
  await managedMcpRepairCliMain(["--verify"], environment, {
    write: (value) => writes.push(value),
    verifyRepair: async (options) => {
      verifyOptions = options;
      return { mode: "VERIFY_READ_ONLY" };
    }
  });
  assert.equal(
    verifyOptions.expectedPreflightPostureDigest,
    environment.EXPECTED_MANAGED_MCP_PRE_REPAIR_POSTURE_SHA256
  );

  let mutationCalls = 0;
  await assert.rejects(
    managedMcpRepairCliMain(["--apply"], environment, {
      write: () => {},
      createJournal: () => managedMcpJournalReceipt,
      applyRepair: async () => {
        mutationCalls += 1;
      }
    }),
    /MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION_REQUIRED/u
  );
  assert.equal(mutationCalls, 0);

  let applyOptions;
  await managedMcpRepairCliMain(["--apply"], {
    ...environment,
    MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION:
      MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION
  }, {
    write: (value) => writes.push(value),
    createJournal: () => managedMcpJournalReceipt,
    applyRepair: async (options) => {
      applyOptions = options;
      return { mode: "APPLY_JOURNALED_RECONCILED" };
    }
  });
  assert.equal(applyOptions.operationId, MANAGED_MCP_OPERATION_ID);
  assert.equal(applyOptions.journalIntent, managedMcpJournalReceipt);

  let disableOptions;
  await managedMcpRepairCliMain(["--disable"], {
    ...environment,
    MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION:
      MANAGED_MCP_RECOVERY_DISABLE_CONFIRMATION
  }, {
    write: (value) => writes.push(value),
    createJournal: () => managedMcpJournalReceipt,
    disableRepair: async (options) => {
      disableOptions = options;
      return { mode: "DISABLE_JOURNALED_RECONCILED" };
    }
  });
  assert.equal(disableOptions.operationId, MANAGED_MCP_OPERATION_ID);
  assert.equal(
    JSON.stringify(writes).includes(environment.RECOVERY_ADMIN_DATABASE_URL),
    false
  );
});

test("Managed MCP local journal reserves one target durably and excludes other operations", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pta-mcp-journal-"));
  fs.chmodSync(root, 0o700);
  try {
    const reservationIntent = managedMcpTargetReservationIntent();
    const journal = createExclusiveManagedMcpJournal(root);
    const reservation = await journal.reserveTarget(reservationIntent);
    assert.equal(reservation.reservation, "TARGET_UNIQUE_RESERVED");
    assert.deepEqual(
      await journal.reserveTarget(reservationIntent),
      reservation
    );
    const intent = {
      schemaVersion: "tideproof.managed-mcp-recovery-grant-intent.v2",
      operationId: MANAGED_MCP_OPERATION_ID,
      step: 1,
      targetReservationDigest: reservation.reservationDigest,
      statementSha256: "5".repeat(64)
    };
    const stepReceipt = await journal(intent);
    assert.equal(
      stepReceipt.targetReservationDigest,
      reservation.reservationDigest
    );
    const files = fs.readdirSync(root);
    assert.equal(files.length, 2);
    for (const file of files) {
      assert.equal(fs.lstatSync(path.join(root, file)).mode & 0o777, 0o600);
      const body = fs.readFileSync(path.join(root, file), "utf8");
      assert.equal(body.includes("postgresql://"), false);
      assert.equal(body.includes("secret"), false);
    }

    const resumed = createExclusiveManagedMcpJournal(root);
    assert.deepEqual(
      await resumed.reserveTarget(reservationIntent),
      reservation
    );
    await assert.rejects(
      resumed(intent),
      /MANAGED_MCP_RECOVERY_JOURNAL_ALREADY_RESERVED/u
    );
    const differentOperation = createExclusiveManagedMcpJournal(root);
    await assert.rejects(
      differentOperation.reserveTarget(managedMcpTargetReservationIntent(
        "55555555-5555-4555-8555-555555555555"
      )),
      /MANAGED_MCP_RECOVERY_TARGET_ALREADY_RESERVED/u
    );

    const badMode = path.join(root, "bad-mode");
    fs.mkdirSync(badMode, { mode: 0o755 });
    fs.chmodSync(badMode, 0o755);
    assert.throws(
      () => createExclusiveManagedMcpJournal(badMode),
      /MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY_INVALID/u
    );
    const real = path.join(root, "real");
    const link = path.join(root, "link");
    fs.mkdirSync(real, { mode: 0o700 });
    fs.symlinkSync(real, link);
    assert.throws(
      () => createExclusiveManagedMcpJournal(link),
      /MANAGED_MCP_RECOVERY_JOURNAL_DIRECTORY_INVALID/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Managed MCP journal durability failure stops before any grant dispatch", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pta-mcp-fsync-"));
  fs.chmodSync(root, 0o700);
  const state = managedMcpAdminState();
  const preflight = await managedMcpPosture(state);
  const journalIntent = createExclusiveManagedMcpJournal(root);
  const originalFsync = fs.fsyncSync;
  let mutationClients = 0;
  fs.fsyncSync = () => {
    throw sqlState("EIO");
  };
  try {
    await assert.rejects(
      repairManagedMcpRecoveryGrants({
        ...managedMcpArguments(preflight.postureDigest),
        confirmation: MANAGED_MCP_RECOVERY_GRANT_CONFIRMATION,
        journalIntent,
        createAdminClient: () => {
          mutationClients += 1;
          return managedMcpAdminClient(state);
        },
        createReconciliationAdminClient: () => managedMcpAdminClient(state)
      }),
      /MANAGED_MCP_RECOVERY_JOURNAL_WRITE_FAILED/u
    );
  } finally {
    fs.fsyncSync = originalFsync;
    fs.rmSync(root, { recursive: true, force: true });
  }
  assert.equal(mutationClients, 0);
  assert.equal(state.grantState, "PUBLIC_VIEW_READY");
});

test("Managed MCP verification binds exact source and exposes partial state only as HOLD", async () => {
  const absent = await managedMcpPosture(managedMcpAdminState());
  const partialState = managedMcpAdminState({ grantState: "SELECT_ONLY" });
  const receipt = await verifyManagedMcpRecoveryGrants({
    ...managedMcpArguments(absent.postureDigest),
    createAdminClient: () => managedMcpAdminClient(partialState)
  });
  assert.equal(receipt.status, "HOLD_SELECT_ONLY");
  assert.equal(receipt.applied, false);
  await assert.rejects(
    verifyManagedMcpRecoveryGrants({
      ...managedMcpArguments(absent.postureDigest, {
        verifySourceCheckout() {
          throw new Error("EXACT_GIT_SOURCE_DIRTY");
        }
      }),
      createAdminClient: () => assert.fail("source must stop first")
    }),
    /MANAGED_MCP_RECOVERY_SOURCE_CHECKOUT_INVALID/u
  );
});

test("publisher capability collector executes functions only in a rolled-back probe without internal cluster metadata", async () => {
  const client = publisherProbeClient();
  await assert.rejects(
    collectRecoveryPublisherCapabilityPosture(client, {}),
    /RECOVERY_PUBLISHER_PROBE_OPTIONS_REJECTED/u
  );
  assert.equal(client.calls.length, 0);
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
  assert.equal(
    client.calls.some((sql) => sql.includes("crdb_internal.cluster_id()")),
    false
  );
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
