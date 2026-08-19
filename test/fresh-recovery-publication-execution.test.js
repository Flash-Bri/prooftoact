import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { FRESH_PRIMARY_RUNTIME_USERS } from
  "../scripts/bootstrap-fresh-primary.js";
import {
  generateFreshRecoveryPublisherSecret,
  freshRecoveryPublisherSecretBytes
} from "../scripts/lib/fresh-recovery-publisher-key.js";
import {
  __test,
  createFreshRecoveryPublicationExecution,
  executeFreshPublicationProviderAction,
  freshRecoveryPublicationProviderBinding,
  validateFreshPublicationDatabaseClock
} from "../scripts/fresh-recovery-publication-execution.js";
import { managedMcpLogicalRequest } from
  "../src/cloud/managed-mcp-client.js";
import { canonicalRecoveryAttempt } from
  "../src/cloud/recovery-broker.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const RUN_ID = "223e4567-e89b-42d3-a456-426614174001";
const TENANT_ID = "323e4567-e89b-42d3-a456-426614174002";
const INCIDENT_ID = "423e4567-e89b-42d3-a456-426614174003";
const EVIDENCE_ID = "523e4567-e89b-42d3-a456-426614174004";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function secretReadback(secretValue, offset) {
  return {
    createdAt: `2026-08-19T08:00:0${offset}.000Z`,
    secretArnSha256: String(offset).repeat(64),
    secretValue,
    secretValueSha256: sha256(Buffer.from(secretValue, "utf8")),
    secretVersionIdSha256: String(offset + 4).repeat(64)
  };
}

function credentialBundle() {
  return {
    schemaVersion: "prooftoact.fresh-primary-credentials.v2",
    passwords: Object.fromEntries(FRESH_PRIMARY_RUNTIME_USERS.map(
      (name, index) => [
        name,
        `${String(index).padStart(2, "0")}-${"x".repeat(32)}`
      ]
    ))
  };
}

function recoveryRow(bundle) {
  return {
    tenant_id: bundle.tenantId,
    recovery_session_id: bundle.recoverySessionId,
    subject_binding_hash: bundle.subjectBindingHash,
    schema_version: bundle.schemaVersion,
    snapshot_version: bundle.snapshotVersion,
    source_cluster_id: bundle.sourceClusterId,
    source_commit_ts: bundle.sourceCommitTs,
    source_digest: bundle.sourceDigest,
    bundle_digest: bundle.bundleDigest,
    policy_version: bundle.policyVersion,
    publisher_key_id: bundle.publisherKeyId,
    publisher_version: bundle.publisherVersion,
    signature_algorithm: bundle.signatureAlgorithm,
    source_signature_base64: bundle.sourceSignatureBase64,
    signature_digest: bundle.signatureDigest,
    checkpoint_summary: bundle.checkpointSummary,
    evidence_summary: bundle.evidenceSummary,
    conflict_summary: bundle.conflictSummary,
    receipt_summary: bundle.receiptSummary,
    authority_transferred: bundle.authorityTransferred,
    requires_fresh_authorization: bundle.requiresFreshAuthorization,
    expires_at: bundle.expiresAt
  };
}

test("fresh recovery publishes, replays, and strongly guards exact Managed MCP", async () => {
  const signer = generateFreshRecoveryPublisherSecret({
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
  const signerValue = freshRecoveryPublisherSecretBytes(signer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }).toString("utf8");
  const credentialValue = JSON.stringify(credentialBundle());
  const publisherValue =
    "postgresql://tp_recovery_publisher_user:" +
    `${"p".repeat(32)}@` +
    "tideproof-recovery-30570.j77.aws-us-east-1.cockroachlabs.cloud:" +
    "26257/tideproof_recovery?sslmode=verify-full";
  const mcpValue = "synthetic-managed-mcp-key-long-enough";
  const material = {
    credential: secretReadback(credentialValue, 1),
    signer: secretReadback(signerValue, 2),
    publisher: secretReadback(publisherValue, 3),
    mcp: secretReadback(mcpValue, 4)
  };
  const sourceBinding = {
    authorityEvidenceBindingSha256: "1".repeat(64),
    evidenceId: EVIDENCE_ID,
    incidentId: INCIDENT_ID,
    operationId: OPERATION_ID,
    requestDigest: "2".repeat(64),
    resourceId: "synthetic-fresh-recovery-resource",
    runId: RUN_ID,
    selectedEvidenceBindingSha256: "3".repeat(64),
    tenantId: TENANT_ID
  };
  const provider = freshRecoveryPublicationProviderBinding();
  const primaryClusterMappingBody = {
    schemaVersion: "prooftoact.primary-provider-sql-mapping.v1",
    status: "PROVIDER_READBACK_BOUND",
    cloud: "COCKROACHDB_CLOUD_ON_AWS",
    clusterInventorySha256: "5".repeat(64),
    cockroachVersion: "v26.2.1",
    host: __test.PRIMARY_HOST,
    manualClusterReceiptSha256: "6".repeat(64),
    observedAt: "2026-08-19T08:00:00.000Z",
    providerClusterId: provider.primaryProviderClusterId,
    sourceBindingSha256: sha256(__test.canonicalBytes({
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    })),
    sourceCommit: SOURCE_COMMIT,
    sqlClusterId: provider.primarySqlClusterId,
    treeDigest: TREE_DIGEST
  };
  const primaryClusterMapping = {
    ...primaryClusterMappingBody,
    receiptSha256: sha256(__test.canonicalBytes(primaryClusterMappingBody))
  };
  const binding = {
    billingAuthorizationSha256: "7".repeat(64),
    credentialSecretValueSha256: material.credential.secretValueSha256,
    mcpSecretValueSha256: material.mcp.secretValueSha256,
    operationId: OPERATION_ID,
    primaryClusterMapping,
    primaryClusterMappingReceiptSha256:
      primaryClusterMapping.receiptSha256,
    primaryProviderClusterId: provider.primaryProviderClusterId,
    primarySqlClusterId: provider.primarySqlClusterId,
    publisherSecretValueSha256: material.publisher.secretValueSha256,
    recoveryProviderClusterId: provider.recoveryProviderClusterId,
    recoverySecurityReceiptSha256: "4".repeat(64),
    recoverySqlClusterId: provider.recoverySqlClusterId,
    signerSecretValueSha256: material.signer.secretValueSha256,
    sourceBinding,
    sourceBindingSha256: sha256(__test.canonicalBytes(sourceBinding)),
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  };
  const sourceCommitMs = Date.now() - 1_000;
  const rawSourceReceipt = {
    admissibility: "admissible",
    admittedCount: 1,
    agent_id: "prooftoact-fresh-recovery-producer",
    authorization_binding_sha256: "5".repeat(64),
    authorization_epoch: 1,
    authority_evidence_binding_sha256:
      sourceBinding.authorityEvidenceBindingSha256,
    evidence_digest: "6".repeat(64),
    evidence_id: EVIDENCE_ID,
    has_durable_intent: true,
    incident_id: INCIDENT_ID,
    logical_action_digest: "7".repeat(64),
    logical_authority_key_sha256: "8".repeat(64),
    operation_id: OPERATION_ID,
    outcome: "resource_reserved",
    policy_version: "g1-admissibility-v2",
    proposal_digest: "9".repeat(64),
    reason: null,
    recorded_at: new Date(sourceCommitMs).toISOString(),
    database_now: new Date(sourceCommitMs + 500).toISOString(),
    request_digest: sourceBinding.requestDigest,
    resource_id: sourceBinding.resourceId,
    run_id: RUN_ID,
    selected_evidence_binding_sha256:
      sourceBinding.selectedEvidenceBindingSha256,
    tenant_id: TENANT_ID,
    unresolvedCount: 0
  };
  let persistedBundle;
  let appendCount = 0;
  let semanticEvidence;
  let databaseClockIndex = 0;
  const sessionDigest = "a".repeat(64);
  const dependencies = {
    async assertRecoveryPublisherTrustRootWriteDenied() {
      return { denied: true, sqlstate: "42501" };
    },
    async assertRecoveryRunnerBaseTableReadsDenied() {
      return { denied: true, sqlstate: "42501" };
    },
    assertSeparatedDatabaseEndpoints() {},
    createManagedMcpClient() {
      return {
        async selectQuery({
          beforeExternalAction,
          clusterId,
          database,
          query
        }) {
          assert.equal(clusterId, provider.recoveryProviderClusterId);
          assert.equal(database, "tideproof_recovery");
          await beforeExternalAction("MCP_INITIALIZE");
          await beforeExternalAction("MCP_INITIALIZED_NOTIFICATION");
          await beforeExternalAction("MCP_TOOLS_CALL");
          const logicalRequest = managedMcpLogicalRequest({ clusterId, query });
          semanticEvidence = {
            clusterId,
            database,
            logicalMcpRequestSha256:
              sha256(__test.canonicalJson(logicalRequest)),
            query,
            toolName: "select_query"
          };
          return { rows: [recoveryRow(persistedBundle)] };
        },
        async close({ beforeExternalAction }) {
          await beforeExternalAction("MCP_SESSION_DELETE");
        },
        semanticRequestEvidence() {
          return semanticEvidence;
        },
        transportEvidence() {
          return {
            rpcCalls: [{ method: "initialize" }, { method: "tools/call" }],
            notifications: [{ method: "notifications/initialized" }],
            close: {
              attempted: true,
              httpStatus: 200,
              outboundSessionIdSha256: sessionDigest,
              responseSessionIdSha256: sessionDigest,
              sessionContinuous: true
            }
          };
        }
      };
    },
    createPublisher() {
      return {
        async databaseNow() {
          databaseClockIndex += 1;
          return new Date(sourceCommitMs + databaseClockIndex * 1_000)
            .toISOString();
        },
        async appendSignedBundle(bundle) {
          assert.equal(bundle.bundleDigest, persistedBundle.bundleDigest);
          appendCount += 1;
          return {
            bundleDigest: bundle.bundleDigest,
            commit: { synthetic: true },
            outcome: appendCount === 1 ? "bundle_appended" : "bundle_replay"
          };
        }
      };
    },
    persistBundle({ signedBundle }) {
      persistedBundle = signedBundle;
      return {
        bundle: signedBundle,
        receipt: { schemaVersion: "synthetic.persistence.v1", status: "PASS" }
      };
    },
    async resolveCommittedRecoveryPublisherTrustRoot() {
      return { status: "COMMITTED" };
    },
    async resolveCommittedRecoverySourceReceipt() {
      return rawSourceReceipt;
    }
  };
  const execution = createFreshRecoveryPublicationExecution({
    binding,
    bundlePath: `/private/${RUN_ID}.signed-recovery-bundle.json`,
    dependencies,
    evidenceRootPath: "/private",
    forbiddenRootPath: "/checkout",
    material,
    spec: {
      operationId: OPERATION_ID,
      runId: RUN_ID,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    }
  });
  const preparation = await execution.prepare();
  assert.equal(preparation.status, "PREPARED");
  assert.equal(Date.parse(preparation.expiresAt) - sourceCommitMs,
    45 * 60 * 1_000);
  assert.equal(preparation.expiryPolicy.freshPublicationTtlMs,
    45 * 60 * 1_000);
  assert.equal(preparation.expiryPolicy.canonicalRecoveryTtlMs,
    30 * 60 * 1_000);
  assert.match(preparation.expiryPolicySha256, /^[0-9a-f]{64}$/u);
  const canonical = canonicalRecoveryAttempt({
    tenantId: TENANT_ID,
    subjectBindingHash: persistedBundle.subjectBindingHash,
    sourceDigest: persistedBundle.sourceDigest,
    sourceCommitTs: persistedBundle.sourceCommitTs
  });
  assert.equal(Date.parse(canonical.expiresAt) - sourceCommitMs,
    30 * 60 * 1_000);
  assert.equal(preparation.privateRecoveryQueryBinding.expectedBundleDigest,
    preparation.bundleDigest);
  assert.equal(preparation.privateRecoveryQueryBinding.
    primaryClusterMappingReceiptSha256, primaryClusterMapping.receiptSha256);
  assert.equal(preparation.privateRecoveryQueryBindingSha256,
    preparation.privateRecoveryQueryBinding.bindingSha256);
  assert.equal(JSON.stringify(preparation.privateRecoveryQueryBinding)
    .includes("secret"), false);
  const appended = await execution.append();
  assert.equal(appended.outcome, "bundle_appended");
  assert.equal(appended.expiryPolicySha256,
    preparation.expiryPolicySha256);
  const replayed = await execution.replay();
  assert.equal(replayed.outcome, "bundle_replay");
  const plan = execution.planManagedMcp();
  const plannedRequestSha256 = sha256(__test.canonicalBytes(plan));
  const guards = [];
  const proof = await execution.verifyManagedMcp({
    durablePlanReadbackSha256: "b".repeat(64),
    plannedRequestSha256,
    async beforeExternalAction({ externalAction }) {
      guards.push(externalAction);
      return {
        schemaVersion: "prooftoact.fresh-recovery-mcp-dispatch-guard.v1",
        status: "DURABLE_PLAN_STRONGLY_RECONCILED",
        externalAction,
        planTransitionSha256: "c".repeat(64),
        plannedRequestSha256,
        strongReadbackSha256: "d".repeat(64)
      };
    }
  });
  assert.equal(proof.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(proof.authorityTransferred, false);
  assert.equal(proof.requiresFreshAuthorization, true);
  assert.equal(proof.expiryPolicySha256,
    preparation.expiryPolicySha256);
  assert.deepEqual(guards, [
    "MCP_INITIALIZE",
    "MCP_INITIALIZED_NOTIFICATION",
    "MCP_TOOLS_CALL",
    "MCP_SESSION_DELETE"
  ]);
  assert.equal(appendCount, 2);
  assert.equal(databaseClockIndex, 3);
});

test("fresh publication clocks enforce exact five-minute provider boundary", () => {
  const sourceCommitTs = "2026-08-19T08:00:00.000Z";
  const attempt = {
    bindingSha256: "a".repeat(64),
    expiresAt: "2026-08-19T08:45:00.000Z",
    recoverySessionId: RUN_ID,
    snapshotVersion: Date.parse(sourceCommitTs),
    sourceCommitTs
  };
  assert.equal(validateFreshPublicationDatabaseClock({
    attempt,
    databaseNow: "2026-08-19T08:40:00.000Z",
    minimumRemainingMs: 5 * 60 * 1_000
  }).remainingWindowMs, 5 * 60 * 1_000);
  for (const databaseNow of [
    "2026-08-19T08:40:00.001Z",
    "2026-08-19T07:59:59.999Z",
    "2026-08-19T08:39:00Z",
    null
  ]) {
    assert.throws(() => validateFreshPublicationDatabaseClock({
      attempt,
      databaseNow,
      minimumRemainingMs: 5 * 60 * 1_000
    }), /FRESH_RECOVERY_PUBLICATION_DATABASE_CLOCK_REJECTED/u);
  }
  assert.throws(() => validateFreshPublicationDatabaseClock({
    attempt: { ...attempt, expiresAt: "2026-08-19T08:30:00.000Z" },
    databaseNow: "2026-08-19T08:20:00.000Z",
    minimumRemainingMs: 5 * 60 * 1_000
  }), /FRESH_RECOVERY_PUBLICATION_DATABASE_CLOCK_REJECTED/u);
});

test("primary publication clock enforces just-above, exact, and just-below ten-minute boundary", () => {
  const attempt = {
    bindingSha256: "a".repeat(64),
    expiresAt: "2026-08-19T08:45:00.000Z",
    recoverySessionId: RUN_ID,
    snapshotVersion: Date.parse("2026-08-19T08:00:00.000Z"),
    sourceCommitTs: "2026-08-19T08:00:00.000Z"
  };
  assert.equal(validateFreshPublicationDatabaseClock({
    attempt,
    databaseNow: "2026-08-19T08:34:59.999Z",
    minimumRemainingMs: 10 * 60 * 1_000
  }).remainingWindowMs, 10 * 60 * 1_000 + 1);
  assert.equal(validateFreshPublicationDatabaseClock({
    attempt,
    databaseNow: "2026-08-19T08:35:00.000Z",
    minimumRemainingMs: 10 * 60 * 1_000
  }).remainingWindowMs, 10 * 60 * 1_000);
  assert.throws(() => validateFreshPublicationDatabaseClock({
    attempt,
    databaseNow: "2026-08-19T08:35:00.001Z",
    minimumRemainingMs: 10 * 60 * 1_000
  }), /FRESH_RECOVERY_PUBLICATION_DATABASE_CLOCK_REJECTED/u);
});

test("backward database clock rejects before provider candidate dispatch", async () => {
  let dispatched = false;
  await assert.rejects(executeFreshPublicationProviderAction({
    attempt: {
      bindingSha256: "a".repeat(64),
      expiresAt: "2026-08-19T08:45:00.000Z",
      recoverySessionId: RUN_ID,
      snapshotVersion: Date.parse("2026-08-19T08:00:00.000Z"),
      sourceCommitTs: "2026-08-19T08:00:00.000Z"
    },
    async dispatch() {
      dispatched = true;
      return { outcome: "unsafe" };
    },
    previousDatabaseNow: "2026-08-19T08:20:00.000Z",
    async readDatabaseNow() {
      return "2026-08-19T08:19:59.999Z";
    }
  }), /FRESH_RECOVERY_PUBLICATION_DATABASE_CLOCK_REJECTED/u);
  assert.equal(dispatched, false);
});

test("expired provider clock prevents publication dispatch", async () => {
  let dispatched = false;
  await assert.rejects(executeFreshPublicationProviderAction({
    attempt: {
      bindingSha256: "a".repeat(64),
      expiresAt: "2026-08-19T08:45:00.000Z",
      recoverySessionId: RUN_ID,
      snapshotVersion: Date.parse("2026-08-19T08:00:00.000Z"),
      sourceCommitTs: "2026-08-19T08:00:00.000Z"
    },
    async dispatch() {
      dispatched = true;
      return { outcome: "unsafe" };
    },
    async readDatabaseNow() {
      return "2026-08-19T08:40:00.001Z";
    }
  }), /FRESH_RECOVERY_PUBLICATION_DATABASE_CLOCK_REJECTED/u);
  assert.equal(dispatched, false);
});
