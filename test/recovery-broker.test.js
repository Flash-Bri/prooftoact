import assert from "node:assert/strict";
import test from "node:test";
import {
  DeterministicRecoveryBroker,
  principalBindingHash
} from "../src/cloud/recovery-broker.js";
import { normalizedRecoveryBundleFor } from "../src/cloud/recovery-store.js";
import { createSyntheticRecoverySigner } from "../scripts/lib/synthetic-recovery-signer.js";

const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const PRIMARY_CLUSTER_ID = "33333333-3333-4333-8333-333333333333";
const RECOVERY_CLUSTER_ID = "44444444-4444-4444-8444-444444444444";
const PRINCIPAL = "principal://synthetic-successor-a";
const BUILD_IDENTITY = "synthetic-test-build-identity";

function fixture() {
  const signer = createSyntheticRecoverySigner();
  const now = Date.now();
  const signed = signer.sign({
    tenantId: TENANT_ID,
    recoverySessionId: SESSION_ID,
    subjectBindingHash: principalBindingHash(PRINCIPAL),
    schemaVersion: 2,
    snapshotVersion: now,
    sourceClusterId: PRIMARY_CLUSTER_ID,
    sourceCommitTs: new Date(now - 60_000).toISOString(),
    sourceDigest: "a".repeat(64),
    policyVersion: "gate1-policy-v2",
    checkpointSummary: {
      checkpointVersion: 1,
      failedAgent: "synthetic-agent-a",
      phase: "successor-context-recovery",
      scenario: "synthetic-highwater"
    },
    evidenceSummary: {
      admittedCount: 1,
      classification: "synthetic",
      evidenceDigest: "c".repeat(64)
    },
    conflictSummary: { status: "none", unresolvedCount: 0 },
    receiptSummary: {
      durableIntentPresent: true,
      outcome: "resource_reserved",
      reason: null,
      resourceLabel: "synthetic-rescue-unit"
    },
    expiresAt: new Date(now + 30 * 60_000).toISOString()
  });
  const bundle = normalizedRecoveryBundleFor(signed);
  return {
    signer,
    row: {
      tenant_id: bundle.tenantId,
      recovery_session_id: bundle.recoverySessionId,
      subject_binding_hash: bundle.subjectBindingHash,
      schema_version: String(bundle.schemaVersion),
      snapshot_version: String(bundle.snapshotVersion),
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
      authority_transferred: false,
      requires_fresh_authorization: true,
      expires_at: bundle.expiresAt
    }
  };
}

function brokerFor({
  row,
  signer,
  mcpError = null,
  auditError = null,
  auditFailureAt = null,
  trace = [],
  bindingHash = principalBindingHash(PRINCIPAL)
}) {
  const mcpCalls = [];
  const auditEvents = [];
  const broker = new DeterministicRecoveryBroker({
    buildIdentity: BUILD_IDENTITY,
    recoveryClusterId: RECOVERY_CLUSTER_ID,
    expectedSourceClusterId: PRIMARY_CLUSTER_ID,
    trustedPublisherKeys: {
      [signer.publisherKeyId]: signer.publicKeySpkiBase64
    },
    sessionResolver: {
      async resolve() {
        return {
          tenantId: TENANT_ID,
          recoverySessionId: SESSION_ID,
          subjectBindingHash: bindingHash
        };
      }
    },
    mcpClient: {
      async selectQuery(input) {
        trace.push("mcp");
        mcpCalls.push(input);
        if (mcpError) {
          throw mcpError;
        }
        return { rows: [row] };
      }
    },
    auditSink: {
      async append(event) {
        auditEvents.push(event);
        trace.push(`audit:${event.phase}`);
        const shouldFail =
          auditFailureAt === null
            ? auditError !== null
            : auditEvents.length === auditFailureAt;
        if (shouldFail) {
          throw auditError ?? new Error("synthetic audit outage");
        }
        return { auditId: event.auditId };
      }
    }
  });
  return { broker, mcpCalls, auditEvents };
}

test("deterministic broker releases signed context and records audit", async () => {
  const { row, signer } = fixture();
  const trace = [];
  const { broker, mcpCalls, auditEvents } = brokerFor({
    row,
    signer,
    trace
  });
  const result = await broker.recover({ authenticatedPrincipal: PRINCIPAL });
  trace.push("return");
  assert.equal(result.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(result.authorityTransferred, false);
  assert.equal(result.requiresFreshAuthorization, true);
  assert.equal(result.context.receipt.outcome, "resource_reserved");
  assert.equal(mcpCalls.length, 1);
  assert.equal(mcpCalls[0].clusterId, RECOVERY_CLUSTER_ID);
  assert.equal(mcpCalls[0].database, "tideproof_recovery");
  assert.equal(auditEvents.length, 2);
  assert.deepEqual(
    auditEvents.map(({ phase, outcome }) => ({ phase, outcome })),
    [
      { phase: "pre_read", outcome: "read_authorized" },
      { phase: "terminal", outcome: "recovered_context_only" }
    ]
  );
  assert.equal(auditEvents[0].resultDigest, null);
  assert.equal(typeof auditEvents[1].resultDigest, "string");
  assert.equal("fencingToken" in result, false);
  assert.deepEqual(trace, [
    "audit:pre_read",
    "mcp",
    "audit:terminal",
    "return"
  ]);
});

test("broker derives session from principal and rejects cross-principal access", async () => {
  const { row, signer } = fixture();
  const { broker, mcpCalls, auditEvents } = brokerFor({
    row,
    signer,
    bindingHash: principalBindingHash("principal://someone-else")
  });
  const result = await broker.recover({ authenticatedPrincipal: PRINCIPAL });
  assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.reason, "RECOVERY_PRINCIPAL_BINDING_MISMATCH");
  assert.equal(mcpCalls.length, 0);
  assert.equal(auditEvents.length, 0);
});

test("broker fails closed on MCP outage", async () => {
  const { row, signer } = fixture();
  const { broker, auditEvents } = brokerFor({
    row,
    signer,
    mcpError: new Error("synthetic outage")
  });
  const result = await broker.recover({ authenticatedPrincipal: PRINCIPAL });
  assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.authorityTransferred, false);
  assert.equal(auditEvents.length, 2);
  assert.equal(auditEvents[0].outcome, "read_authorized");
  assert.equal(auditEvents[1].outcome, "unknown_do_not_act");
});

test("broker binds a validation failure to the observed MCP row", async () => {
  const { row, signer } = fixture();
  const tamperedRow = {
    ...row,
    source_signature_base64: Buffer.alloc(72).toString("base64")
  };
  const { broker, auditEvents } = brokerFor({
    row: tamperedRow,
    signer
  });
  const result = await broker.recover({ authenticatedPrincipal: PRINCIPAL });
  assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(auditEvents.length, 2);
  assert.equal(auditEvents[1].phase, "terminal");
  assert.equal(auditEvents[1].outcome, "unknown_do_not_act");
  assert.match(auditEvents[1].resultDigest, /^[a-f0-9]{64}$/u);
  assert.equal(
    new Date(auditEvents[1].sourceWatermark).toISOString(),
    new Date(row.source_commit_ts).toISOString()
  );
  assert.equal("context" in result, false);
});

test("broker withholds valid context when required audit cannot commit", async () => {
  const { row, signer } = fixture();
  const { broker, mcpCalls } = brokerFor({
    row,
    signer,
    auditError: new Error("synthetic audit outage")
  });
  const result = await broker.recover({ authenticatedPrincipal: PRINCIPAL });
  assert.deepEqual(result, {
    status: "UNKNOWN_DO_NOT_ACT",
    reason: "recovery_audit_unavailable",
    authorityTransferred: false,
    requiresFreshAuthorization: true
  });
  assert.equal(mcpCalls.length, 0);
});

test("broker withholds context when only the terminal audit append fails", async () => {
  const { row, signer } = fixture();
  const { broker, mcpCalls, auditEvents } = brokerFor({
    row,
    signer,
    auditError: new Error("synthetic terminal audit outage"),
    auditFailureAt: 2
  });
  const result = await broker.recover({ authenticatedPrincipal: PRINCIPAL });
  assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.authorityTransferred, false);
  assert.equal(result.requiresFreshAuthorization, true);
  assert.equal(mcpCalls.length, 1);
  assert.equal(auditEvents[0].phase, "pre_read");
  assert.equal(auditEvents.some(({ phase }) => phase === "terminal"), true);
  assert.equal("context" in result, false);
});

test("broker fails closed for absent and null input", async () => {
  const { row, signer } = fixture();
  const { broker, mcpCalls } = brokerFor({ row, signer });
  for (const input of [undefined, null]) {
    const result = await broker.recover(input);
    assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
    assert.equal(result.authorityTransferred, false);
    assert.equal(result.requiresFreshAuthorization, true);
  }
  assert.equal(mcpCalls.length, 0);
});

test("broker fails closed instead of throwing on malformed resolver bindings", async () => {
  const { row, signer } = fixture();
  const { mcpCalls } = brokerFor({ row, signer });
  const malformedBroker = new DeterministicRecoveryBroker({
    buildIdentity: BUILD_IDENTITY,
    recoveryClusterId: RECOVERY_CLUSTER_ID,
    expectedSourceClusterId: PRIMARY_CLUSTER_ID,
    trustedPublisherKeys: {
      [signer.publisherKeyId]: signer.publicKeySpkiBase64
    },
    sessionResolver: {
      async resolve() {
        return {
          tenantId: "not-a-uuid",
          recoverySessionId: SESSION_ID,
          subjectBindingHash: principalBindingHash(PRINCIPAL)
        };
      }
    },
    mcpClient: {
      async selectQuery(input) {
        mcpCalls.push(input);
        return { rows: [row] };
      }
    },
    auditSink: {
      async append() {
        throw new Error("malformed binding cannot be audited");
      }
    }
  });
  const result = await malformedBroker.recover({
    authenticatedPrincipal: PRINCIPAL
  });
  assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
  assert.match(result.reason, /BINDING_TENANTID_MUST_BE_A_UUID/);
  assert.equal(result.authorityTransferred, false);
  assert.equal(result.requiresFreshAuthorization, true);
  assert.equal(mcpCalls.length, 0);
});
