import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildIntegratedLiveDrillReceipt,
  INTEGRATED_LIVE_DRILL_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity,
  selectedEvidenceBindingSha256
} from "../src/cloud/integrated-live-drill.js";
import {
  runIntegratedLiveDrill,
  safeIntegratedLiveDrillFailureCode
} from "../scripts/gate2-integrated-live-drill.js";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);
const treeDigest = "b".repeat(40);
const configDigest = "c".repeat(64);
const runId = "11111111-1111-4111-8111-111111111111";
const raceId = "22222222-2222-4222-8222-222222222222";
const evidenceId = "33333333-3333-4333-8333-333333333333";
const evidenceDigest = "d".repeat(64);
const authorityBinding = "e".repeat(64);
const operationId = "44444444-4444-4444-8444-444444444444";
const requestDigest = "f".repeat(64);

const specWithoutIdentity = {
  schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  sourceCommit,
  treeDigest,
  configDigest,
  packageLockDigest: "1".repeat(64),
  authoritySourceDigest: "2".repeat(64),
  authorityArtifactDigest: "3".repeat(64),
  functionArn:
    "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-authority:7",
  raceId,
  runId,
  maximumAwsCostUsd: "0.02"
};
const spec = Object.freeze({
  ...specWithoutIdentity,
  sourceBuildIdentity: integratedSourceBuildIdentity(specWithoutIdentity)
});

function components() {
  const selectedBinding = selectedEvidenceBindingSha256(
    evidenceId,
    evidenceDigest
  );
  const dvi = {
    schemaVersion: "tideproof.gate1.admissible-vector-proof.v2",
    status: "PASS",
    sourceCommit,
    treeDigest,
    drill: {
      runId,
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding,
      durableSelectionCommitted: true
    },
    fixture: {
      requiredExclusionsBoundToSnapshot: true,
      nearestExcludedCloserThanRanked: true
    },
    ranking: {
      vectorSearchUsed: true,
      exactPrefixSpansUsed: true
    },
    cleanup: {
      snapshotRetired: true,
      remainingCandidateCount: 0,
      remainingExclusionCount: 0
    }
  };
  const race = {
    schemaVersion: "tideproof.aws-authority-race-receipt.v7",
    status: "PASS",
    sourceCommit,
    treeDigest,
    packageLockDigest: spec.packageLockDigest,
    authoritySourceDigest: spec.authoritySourceDigest,
    authorityArtifactDigest: spec.authorityArtifactDigest,
    configDigest,
    raceId,
    runId,
    dvi: {
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding
    },
    functionArnDigest: sha(spec.functionArn),
    functionVersion: "7",
    callerBinding: {
      bindingDigest: "4".repeat(64),
      callerIdentityDigest: "5".repeat(64),
      contextDigest: "6".repeat(64),
      expectedIdentityDigest: "5".repeat(64),
      expectedPrincipalDigest: "7".repeat(64),
      principalType: "assumed-role"
    },
    contenders: 2,
    serializableTransactions: true,
    overlappingDatabaseIntervals: true,
    distinctDatabaseSessions: true,
    distinctLogicalActions: true,
    distinctProposals: true,
    databaseInterval: {
      startedAt: "2026-08-06T12:00:00.000Z",
      completedAt: "2026-08-06T12:00:02.000Z"
    },
    invocationRequestDigests: {
      alpha: "4".repeat(64),
      bravo: "5".repeat(64),
      changedInput: "6".repeat(64),
      proof: "7".repeat(64),
      replay: "8".repeat(64)
    },
    awsInvokeRequestDigests: {
      alpha: "9".repeat(64),
      bravo: "a".repeat(64),
      changedInput: "b".repeat(64),
      proof: "c".repeat(64),
      replay: "d".repeat(64)
    },
    providerOperations: { lambdaInvocations: 5 },
    durableStateVerified: true,
    durableState: {
      receiptCount: 2,
      resourceReceiptCount: 2,
      outboxCount: 1,
      protectedEffectCount: 0,
      holderOperationId: operationId,
      outboxOperationId: operationId,
      denialObservedHolderOperationId: operationId,
      denialObservedFence: "1"
    },
    protectedEffectExecuted: false,
    authorityTransferredByModel: false,
    winner: {
      contender: "alpha",
      operationId,
      requestDigest,
      fencingToken: "1"
    },
    denial: {
      contender: "bravo",
      operationId: "77777777-7777-4777-8777-777777777777",
      requestDigest: "e".repeat(64),
      reason: "active_holder"
    },
    replay: {
      contender: "alpha",
      operationId,
      requestDigest,
      outcome: "resource_reserved",
      fencingToken: "1",
      replayKind: "operation_replay",
      exactDecisionReturned: true
    },
    changedInputDenial: {
      contender: "alpha",
      operationId,
      changedRequestDigest: "0".repeat(64),
      code: "OPERATION_DIGEST_MISMATCH",
      denied: true
    }
  };
  const recovery = {
    gate: "noninteractive Managed MCP deterministic recovery broker",
    passed: true,
    sourceBuildIdentity: spec.sourceBuildIdentity,
    winnerOperationBindingSha256: sha(JSON.stringify({
      operationId,
      requestDigest
    })),
    dvi: race.dvi,
    endpointSeparation: {
      distinctHostnames: true,
      distinctClusterIds: true
    },
    replayOutcome: "bundle_replay",
    mcpTool: "select_query",
    mcpCallCount: 1,
    mcpProviderEvidence: {
      schemaVersion: "tideproof.managed-mcp-transport-evidence.v1",
      endpointSha256: "1".repeat(64),
      endpointAuthority: "cockroachlabs.cloud",
      clusterIdSha256: "2".repeat(64),
      protocolVersion: "2025-03-26",
      rpcCalls: [
        {
          method: "initialize",
          requestIdSha256: "3".repeat(64),
          responseIdSha256: "3".repeat(64),
          responseCorrelated: true,
          httpStatus: 200,
          contentType: "application/json",
          sessionIdSha256: "4".repeat(64)
        },
        {
          method: "tools/call",
          requestIdSha256: "5".repeat(64),
          responseIdSha256: "5".repeat(64),
          responseCorrelated: true,
          httpStatus: 200,
          contentType: "text/event-stream",
          sessionIdSha256: "4".repeat(64)
        }
      ],
      notificationCount: 1,
      closeAttempted: true,
      redirectPolicy: "error",
      boundedResponseBytes: 256 * 1024
    },
    recoveryStatus: "RECOVERED_CONTEXT_ONLY",
    unauthorizedStatus: "UNKNOWN_DO_NOT_ACT",
    preReadAuditCommitted: true,
    terminalAuditCommitted: true,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    operationalCapabilitiesReturned: false,
    runnerCredentialDenials: {
      sourceTrustRootWrite: { denied: true },
      auditTrustRootWrite: { denied: true },
      sourceBaseTableReads: { denied: true },
      auditBaseTableReads: { denied: true }
    }
  };
  return { dvi, race, recovery };
}

test("one provider drill binds DVI, overlap, negatives, recovery, and cleanup", () => {
  const receipt = buildIntegratedLiveDrillReceipt({
    spec,
    ...components(),
    authorityEvidenceId: evidenceId,
    authoritySelectedEvidenceDigest: evidenceDigest
  });
  assert.equal(receipt.schemaVersion, INTEGRATED_LIVE_DRILL_SCHEMA);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.providerBacked, true);
  assert.equal(receipt.invariantCount, 21);
  assert.equal(receipt.invariantViolations, 0);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/u);
  const publicReceipt = JSON.stringify(receipt);
  assert.equal(publicReceipt.includes(evidenceId), false);
  assert.equal(publicReceipt.includes(spec.functionArn), false);
  assert.equal(
    receipt.sourceBuildIdentitySha256,
    sha(spec.sourceBuildIdentity)
  );
});

test("integrated receipt fails closed on every cross-act boundary", () => {
  for (const mutate of [
    (value) => { value.dvi.cleanup.snapshotRetired = false; },
    (value) => { value.race.overlappingDatabaseIntervals = false; },
    (value) => { value.race.replay.exactDecisionReturned = false; },
    (value) => { value.race.changedInputDenial.denied = false; },
    (value) => { value.recovery.mcpCallCount = 2; },
    (value) => { value.recovery.terminalAuditCommitted = false; },
    (value) => { value.recovery.dvi.selectedEvidenceBindingSha256 = "0".repeat(64); }
  ]) {
    const value = structuredClone(components());
    mutate(value);
    assert.throws(
      () => buildIntegratedLiveDrillReceipt({
        spec,
        ...value,
        authorityEvidenceId: evidenceId,
        authoritySelectedEvidenceDigest: evidenceDigest
      }),
      /INTEGRATED_LIVE_DRILL_COMPONENT_REJECTED/u
    );
  }
});

test("orchestrator executes exactly DVI, race, then exact-winner recovery", async () => {
  const values = components();
  const calls = [];
  const environment = {
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: JSON.stringify(spec),
    DATABASE_URL: "postgresql://authorizer.invalid/db",
    TIDEPROOF_AUDITOR_DATABASE_URL: "postgresql://auditor.invalid/db",
    TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC: "{}",
    AUTHORITY_EVIDENCE_ID: evidenceId,
    AUTHORITY_SELECTED_EVIDENCE_DIGEST: evidenceDigest,
    AUTHORITY_ALPHA_PROPOSAL_DIGEST: "1".repeat(64),
    AUTHORITY_BRAVO_PROPOSAL_DIGEST: "2".repeat(64),
    AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST: "3".repeat(64),
    AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST: "4".repeat(64),
    AUTHORITY_TENANT_ID: "55555555-5555-4555-8555-555555555555",
    AUTHORITY_INCIDENT_ID: "66666666-6666-4666-8666-666666666666",
    AUTHORITY_RESOURCE_ID: "synthetic-resource",
    AWS_ACCESS_KEY_ID: "ASIAEXAMPLE12345678",
    AWS_SECRET_ACCESS_KEY: "secret-example-value",
    AWS_SESSION_TOKEN: "session-example-value",
    AWS_EVIDENCE_EXPECTED_ACCOUNT_ID: "111111111111",
    AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_ARN:
      "arn:aws:sts::111111111111:assumed-role/test/session",
    AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_USER_ID:
      "AROATESTEXAMPLE123:session",
    PRIMARY_RECOVERY_SOURCE_DATABASE_URL: "postgresql://source.invalid/db",
    RECOVERY_PUBLISHER_DATABASE_URL: "postgresql://publisher.invalid/db",
    PRIMARY_AUDIT_DATABASE_URL: "postgresql://audit.invalid/db",
    PRIMARY_CLUSTER_ID: "88888888-8888-4888-8888-888888888888",
    RECOVERY_CLUSTER_ID: "99999999-9999-4999-8999-999999999999",
    MCP_API_KEY: "mcp-secret-example-value-123456",
    EXPECTED_PRIMARY_HOSTNAME: "primary.invalid",
    EXPECTED_RECOVERY_HOSTNAME: "recovery.invalid",
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT: "trust-root",
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT: "5".repeat(64),
    RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64: "private-key",
    LEAK_SENTINEL: "must-not-reach-any-child",
    SOURCE_COMMIT: sourceCommit,
    CONFIG_DIGEST: configDigest
  };
  const outputs = [values.dvi, values.race, values.recovery];
  const receipt = await runIntegratedLiveDrill({
    environment,
    rootDir: "/repo",
    verifyRelease: async () => ({
      sourceCommit,
      treeDigest,
      packageLockDigest: spec.packageLockDigest
    }),
    runComponent: async (script, args, childEnvironment) => {
      calls.push({ script, args, environment: childEnvironment });
      return outputs[calls.length - 1];
    }
  });
  assert.equal(receipt.status, "PASS");
  assert.equal(calls.length, 3);
  assert.match(calls[0].script, /gate1-admissible-vector\.js$/u);
  assert.match(calls[1].script, /gate2-authority-race\.js$/u);
  assert.match(calls[2].script, /gate1-recovery-broker\.js$/u);
  assert.equal(
    calls[2].environment.RECOVERY_SOURCE_OPERATION_ID,
    operationId
  );
  assert.equal(
    calls[2].environment.RECOVERY_SOURCE_REQUEST_DIGEST,
    requestDigest
  );
  assert.equal(
    calls[2].environment.RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256,
    authorityBinding
  );
  assert.equal(calls.every(({ environment: child }) =>
    !("LEAK_SENTINEL" in child)), true);
  assert.equal("AWS_ACCESS_KEY_ID" in calls[0].environment, false);
  assert.equal("MCP_API_KEY" in calls[0].environment, false);
  assert.equal("DATABASE_URL" in calls[1].environment, false);
  assert.equal("MCP_API_KEY" in calls[1].environment, false);
  assert.equal("AWS_ACCESS_KEY_ID" in calls[2].environment, false);
  assert.equal(
    "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64" in
      calls[0].environment,
    false
  );
});

test("integrated drill errors disclose only bounded failure codes", () => {
  assert.equal(
    safeIntegratedLiveDrillFailureCode(
      new Error("INTEGRATED_LIVE_DRILL_COMPONENT_REJECTED")
    ),
    "INTEGRATED_LIVE_DRILL_COMPONENT_REJECTED"
  );
  assert.equal(
    safeIntegratedLiveDrillFailureCode(
      new Error("secret postgres://credential")
    ),
    "INTEGRATED_LIVE_DRILL_UNKNOWN"
  );
});
