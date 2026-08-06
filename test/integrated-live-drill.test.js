import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildIntegratedLiveDrillReceipt,
  INTEGRATED_LIVE_DRILL_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
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

const spec = Object.freeze({
  schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  sourceCommit,
  configDigest,
  functionArn:
    "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-authority:7",
  raceId,
  runId,
  sourceBuildIdentity: "exact-build-identity"
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
    configDigest,
    raceId,
    runId,
    dvi: {
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding
    },
    contenders: 2,
    overlappingDatabaseIntervals: true,
    distinctDatabaseSessions: true,
    durableStateVerified: true,
    durableState: {
      receiptCount: 2,
      outboxCount: 1,
      protectedEffectCount: 0
    },
    protectedEffectExecuted: false,
    authorityTransferredByModel: false,
    winner: { operationId, requestDigest },
    replay: {
      operationId,
      requestDigest,
      outcome: "resource_reserved",
      replayKind: "operation_replay",
      exactDecisionReturned: true
    },
    changedInputDenial: {
      operationId,
      code: "OPERATION_DIGEST_MISMATCH",
      denied: true
    }
  };
  const recovery = {
    gate: "noninteractive Managed MCP deterministic recovery broker",
    passed: true,
    sourceBuildIdentity: spec.sourceBuildIdentity,
    dvi: race.dvi,
    endpointSeparation: {
      distinctHostnames: true,
      distinctClusterIds: true
    },
    replayOutcome: "bundle_replay",
    mcpTool: "select_query",
    mcpCallCount: 1,
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
  assert.equal(receipt.invariantCount, 16);
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
    AUTHORITY_EVIDENCE_ID: evidenceId,
    AUTHORITY_SELECTED_EVIDENCE_DIGEST: evidenceDigest,
    AUTHORITY_RUN_ID: runId,
    AUTHORITY_RACE_ID: raceId,
    AUTHORITY_TENANT_ID: "55555555-5555-4555-8555-555555555555",
    AUTHORITY_INCIDENT_ID: "66666666-6666-4666-8666-666666666666",
    AUTHORITY_RESOURCE_ID: "synthetic-resource",
    SOURCE_COMMIT: sourceCommit,
    CONFIG_DIGEST: configDigest
  };
  const outputs = [values.dvi, values.race, values.recovery];
  const receipt = await runIntegratedLiveDrill({
    environment,
    rootDir: "/repo",
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
