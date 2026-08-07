import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  appendIntegratedLiveDrillJournal,
  buildIntegratedLiveDrillCandidateReceipt,
  INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA,
  INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA_V1,
  INTEGRATED_LIVE_DRILL_JOURNAL_RECEIPT_SCHEMA,
  INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_RECEIPT_SCHEMA,
  INTEGRATED_LIVE_DRILL_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity,
  persistIntegratedLiveDrillPrivateEvidence,
  selectedEvidenceBindingSha256,
  startIntegratedLiveDrillJournal,
  verifyIntegratedLiveDrillJournal,
  verifyIntegratedLiveDrillPrivateEvidence
} from "../src/cloud/integrated-live-drill.js";
import {
  runIntegratedLiveDrill,
  safeIntegratedLiveDrillFailureCode
} from "../scripts/gate2-integrated-live-drill.js";
import { canonicalRecoveryAttempt } from "../src/cloud/recovery-broker.js";

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
const journalIntentBindingSha256 = "6".repeat(64);

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
const postRelease = Object.freeze({
  sourceCommit,
  treeDigest,
  packageLockDigest: spec.packageLockDigest
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
      principalIdDigest: "8".repeat(64),
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
    providerOperations: {
      cloudFormationDescribeStackResourceRequests: 1,
      lambdaInvokeRequests: 5,
      stsGetCallerIdentityRequests: 1
    },
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
    mcpResultSha256: "9".repeat(64),
    mcpProviderEvidence: {
      schemaVersion: "tideproof.managed-mcp-transport-evidence.v2",
      endpointSha256: "1".repeat(64),
      endpointAuthority: "cockroachlabs.cloud",
      clusterIdSha256: "2".repeat(64),
      sessionIdSha256: "4".repeat(64),
      protocolVersion: "2025-03-26",
      rpcCalls: [
        {
          method: "initialize",
          requestIdSha256: "3".repeat(64),
          responseIdSha256: "3".repeat(64),
          requestBytes: 100,
          responseBytes: 101,
          requestPayloadSha256: "6".repeat(64),
          responsePayloadSha256: "7".repeat(64),
          resultSha256: "8".repeat(64),
          responseCorrelated: true,
          httpStatus: 200,
          contentType: "application/json",
          sessionIdSha256: "4".repeat(64),
          outboundSessionIdSha256: null,
          responseSessionIdSha256: "4".repeat(64),
          sessionContinuous: true
        },
        {
          method: "tools/call",
          requestIdSha256: "5".repeat(64),
          responseIdSha256: "5".repeat(64),
          requestBytes: 102,
          responseBytes: 103,
          requestPayloadSha256: "a".repeat(64),
          responsePayloadSha256: "b".repeat(64),
          resultSha256: "9".repeat(64),
          responseCorrelated: true,
          httpStatus: 200,
          contentType: "text/event-stream",
          sessionIdSha256: "4".repeat(64),
          outboundSessionIdSha256: "4".repeat(64),
          responseSessionIdSha256: null,
          sessionContinuous: true
        }
      ],
      notifications: [{
        method: "notifications/initialized",
        requestBytes: 80,
        requestPayloadSha256: "c".repeat(64),
        httpStatus: 202,
        outboundSessionIdSha256: "4".repeat(64),
        responseSessionIdSha256: null,
        sessionContinuous: true
      }],
      close: {
        attempted: true,
        httpStatus: 200,
        outboundSessionIdSha256: "4".repeat(64),
        responseSessionIdSha256: null,
        sessionContinuous: true
      },
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
  recovery.tenantId = "88888888-8888-4888-8888-888888888888";
  recovery.callerSubjectBindingSha256 = "6".repeat(64);
  recovery.sourceDigest = "7".repeat(64);
  recovery.bundleDigest = "8".repeat(64);
  recovery.canonicalRecovery = {
    ...canonicalRecoveryAttempt({
      tenantId: recovery.tenantId,
      subjectBindingHash: recovery.callerSubjectBindingSha256,
      sourceDigest: recovery.sourceDigest,
      sourceCommitTs: "2026-08-06T12:00:03.000Z"
    }),
    bundleDigest: recovery.bundleDigest,
    replayMatched: true
  };
  recovery.recoverySessionId =
    recovery.canonicalRecovery.recoverySessionId;
  return { dvi, race, recovery };
}

function privateEvidenceDirectory() {
  const directory = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-live-evidence-")
  );
  fs.chmodSync(directory, 0o700);
  return fs.realpathSync(directory);
}

function persistPrivateEvidence(values = components()) {
  const directory = privateEvidenceDirectory();
  const journalPath = path.join(directory, `${runId}.journal`);
  const journalArguments = {
    journalPath,
    evidenceRootPath: directory,
    forbiddenRootPath: fs.realpathSync(process.cwd()),
    spec
  };
  startIntegratedLiveDrillJournal({
    ...journalArguments,
    intentBindingSha256: journalIntentBindingSha256
  });
  for (const [phase, payload] of [
    ["DVI_RESULT", values.dvi],
    ["AUTHORITY_RACE_RESULT", values.race],
    ["RECOVERY_RESULT", values.recovery]
  ]) {
    appendIntegratedLiveDrillJournal({
      ...journalArguments,
      phase,
      payload
    });
  }
  const destinationPath = path.join(
    directory,
    `${runId}.private-evidence.json`
  );
  const receipt = persistIntegratedLiveDrillPrivateEvidence({
    destinationPath,
    evidenceRootPath: directory,
    forbiddenRootPath: fs.realpathSync(process.cwd()),
    spec,
    ...values,
    authorityEvidenceId: evidenceId,
    authoritySelectedEvidenceDigest: evidenceDigest
  });
  appendIntegratedLiveDrillJournal({
    ...journalArguments,
    phase: "PRIVATE_EVIDENCE_RESULT",
    payload: receipt
  });
  const journalReceipt = appendIntegratedLiveDrillJournal({
    ...journalArguments,
    phase: "POST_RELEASE_VERIFICATION",
    payload: postRelease
  });
  return {
    directory,
    destinationPath,
    receipt,
    journalPath,
    journalReceipt
  };
}

test("private evidence source control binds current bytes before candidate composition", () => {
  const directory = privateEvidenceDirectory();
  const destinationPath = path.join(
    directory,
    `${runId}.private-evidence.json`
  );
  try {
    const values = components();
    const persistence = persistIntegratedLiveDrillPrivateEvidence({
      destinationPath,
      evidenceRootPath: directory,
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      spec,
      ...values,
      authorityEvidenceId: evidenceId,
      authoritySelectedEvidenceDigest: evidenceDigest
    });
    assert.equal(
      persistence.schemaVersion,
      INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_RECEIPT_SCHEMA
    );
    assert.equal(persistence.atomicCreateOnly, true);
    assert.equal(persistence.rereadVerified, true);
    assert.equal(persistence.fileMode, "0600");
    assert.equal(persistence.parentDirectoryMode, "0700");
    assert.equal(fs.statSync(destinationPath).mode & 0o777, 0o600);
    const privateBundle = JSON.parse(fs.readFileSync(destinationPath, "utf8"));
    assert.equal(privateBundle.authorityEvidenceId, evidenceId);
    assert.equal(privateBundle.components.authorityRace.raceId, raceId);
    assert.equal(privateBundle.bundleSha256, persistence.bundleSha256);
    assert.throws(
      () => persistIntegratedLiveDrillPrivateEvidence({
        destinationPath,
        evidenceRootPath: directory,
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        spec,
        ...values,
        authorityEvidenceId: evidenceId,
        authoritySelectedEvidenceDigest: evidenceDigest
      }),
      /INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_WRITE_REJECTED/u
    );
    assert.equal(
      JSON.parse(fs.readFileSync(destinationPath, "utf8")).bundleSha256,
      persistence.bundleSha256
    );
    fs.appendFileSync(destinationPath, " ");
    assert.throws(
      () => verifyIntegratedLiveDrillPrivateEvidence({
        destinationPath,
        evidenceRootPath: directory,
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        receipt: persistence,
        spec,
        ...values,
        authorityEvidenceId: evidenceId,
        authoritySelectedEvidenceDigest: evidenceDigest
      }),
      /INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED/u
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("private evidence rejects non-canonical or permissive destinations", () => {
  const directory = privateEvidenceDirectory();
  const permissive = path.join(directory, "permissive");
  fs.mkdirSync(permissive, { mode: 0o755 });
  fs.chmodSync(permissive, 0o755);
  try {
    assert.throws(
      () => persistIntegratedLiveDrillPrivateEvidence({
        destinationPath: path.join(
          permissive,
          `${runId}.private-evidence.json`
        ),
        evidenceRootPath: permissive,
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        spec,
        ...components(),
        authorityEvidenceId: evidenceId,
        authoritySelectedEvidenceDigest: evidenceDigest
      }),
      /INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_REJECTED/u
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
  assert.throws(
    () => persistIntegratedLiveDrillPrivateEvidence({
      destinationPath: path.join(
        fs.realpathSync(process.cwd()),
        `${runId}.private-evidence.json`
      ),
      evidenceRootPath: fs.realpathSync(process.cwd()),
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      spec,
      ...components(),
      authorityEvidenceId: evidenceId,
      authoritySelectedEvidenceDigest: evidenceDigest
    }),
    /INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT_REJECTED/u
  );
});

test("pre-provider journal is create-only, chained, synced, and tamper evident", () => {
  const persisted = persistPrivateEvidence();
  try {
    const verified = verifyIntegratedLiveDrillJournal({
      journalPath: persisted.journalPath,
      evidenceRootPath: persisted.directory,
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      spec,
      receipt: persisted.journalReceipt,
      requireComplete: true
    });
    assert.equal(
      verified.schemaVersion,
      INTEGRATED_LIVE_DRILL_JOURNAL_RECEIPT_SCHEMA
    );
    assert.equal(verified.entryCount, 6);
    assert.equal(verified.preProviderIntentDurableBeforeReturn, true);
    assert.equal(verified.entryFilesCreateOnly, true);
    assert.equal(verified.entryFilesSynced, true);
    assert.equal(verified.directoryEntriesSynced, true);
    assert.equal(verified.hashChainVerified, true);
    assert.throws(
      () => appendIntegratedLiveDrillJournal({
        journalPath: persisted.journalPath,
        evidenceRootPath: persisted.directory,
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        spec,
        phase: "DVI_RESULT",
        payload: components().dvi
      }),
      /INTEGRATED_LIVE_DRILL_JOURNAL_SEQUENCE_REJECTED/u
    );
    fs.appendFileSync(path.join(
      persisted.journalPath,
      "02-authority-race-result.json"
    ), " ");
    assert.throws(
      () => verifyIntegratedLiveDrillJournal({
        journalPath: persisted.journalPath,
        evidenceRootPath: persisted.directory,
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        spec,
        receipt: persisted.journalReceipt,
        requireComplete: true
      }),
      /INTEGRATED_LIVE_DRILL_(?:JOURNAL|PRIVATE_EVIDENCE)_/u
    );
  } finally {
    fs.rmSync(persisted.directory, { recursive: true, force: true });
  }
});

test("unattested provider components remain a non-accepting candidate", () => {
  const values = components();
  const persisted = persistPrivateEvidence(values);
  const receipt = (() => {
    try {
      return buildIntegratedLiveDrillCandidateReceipt({
        spec,
        ...values,
        journalPath: persisted.journalPath,
        journalRootPath: persisted.directory,
        journalReceipt: persisted.journalReceipt,
        journalIntentBindingSha256,
        postRelease,
        privateEvidencePath: persisted.destinationPath,
        privateEvidenceRootPath: persisted.directory,
        forbiddenPrivateEvidenceRootPath: fs.realpathSync(process.cwd()),
        privateEvidenceReceipt: persisted.receipt,
        authorityEvidenceId: evidenceId,
        authoritySelectedEvidenceDigest: evidenceDigest
      });
    } finally {
      fs.rmSync(persisted.directory, { recursive: true, force: true });
    }
  })();
  assert.equal(
    receipt.schemaVersion,
    INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA
  );
  assert.notEqual(
    receipt.schemaVersion,
    INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA_V1
  );
  assert.notEqual(receipt.schemaVersion, INTEGRATED_LIVE_DRILL_SCHEMA);
  assert.equal(receipt.status, "INCOMPLETE_LIVE_GATES_PENDING");
  assert.equal(receipt.acceptance.accepted, false);
  assert.equal(receipt.acceptance.deploymentAttestationBound, false);
  assert.equal(receipt.acceptance.preProviderJournalPersisted, false);
  assert.equal(receipt.acceptance.privateEvidencePersisted, false);
  assert.equal(receipt.acceptance.crashSafeRecoveryProven, false);
  assert.equal(receipt.recovery.restartStableSignedBundleReuseProven, false);
  assert.equal(
    receipt.acceptance.blockers.includes(
      "RESTART_STABLE_SIGNED_BUNDLE_REUSE_NOT_PROVEN"
    ),
    true
  );
  assert.equal(receipt.providerBacked, false);
  assert.match(
    receipt.claimBoundary,
    /does not independently establish that any component receipt came from a provider/
  );
  assert.match(
    receipt.claimBoundary,
    /restart-stable reuse of those exact signed bytes is not proven/
  );
  assert.equal(receipt.invariantCount, 24);
  assert.equal(receipt.invariantViolations, 0);
  assert.deepEqual(receipt.providerOperations.aws, {
    cloudFormationDescribeStackResourceRequests: 1,
    lambdaInvokeRequests: 5,
    stsGetCallerIdentityRequests: 1
  });
  assert.equal(receipt.costControl.completeProviderRequestAccounting, false);
  assert.equal(receipt.costControl.providerPricingVerified, false);
  assert.equal(receipt.costControl.actualAwsSpendVerified, false);
  assert.equal(receipt.costControl.spendAuthorizationProvenByReceipt, false);
  assert.equal(receipt.preProviderJournal.entryCount, 6);
  assert.equal(receipt.preProviderJournal.currentBytesBound, true);
  assert.equal(receipt.preProviderJournal.independentlyAttested, false);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/u);
  const publicReceipt = JSON.stringify(receipt);
  assert.equal(publicReceipt.includes(evidenceId), false);
  assert.equal(publicReceipt.includes(spec.functionArn), false);
  assert.equal(publicReceipt.includes("private-evidence.json"), false);
  assert.equal(
    receipt.sourceBuildIdentitySha256,
    sha(spec.sourceBuildIdentity)
  );
});

test("integrated receipt fails closed on every cross-act boundary", () => {
  const persistence = persistPrivateEvidence();
  try {
    for (const mutate of [
    (value) => { value.dvi.cleanup.snapshotRetired = false; },
    (value) => { value.race.overlappingDatabaseIntervals = false; },
    (value) => { value.race.replay.exactDecisionReturned = false; },
    (value) => { value.race.changedInputDenial.denied = false; },
    (value) => { value.race.providerOperations.stsGetCallerIdentityRequests = 2; },
    (value) => { value.recovery.mcpCallCount = 2; },
    (value) => { value.recovery.terminalAuditCommitted = false; },
    (value) => { value.recovery.dvi.selectedEvidenceBindingSha256 = "0".repeat(64); },
    (value) => { value.recovery.canonicalRecovery.bundleDigest = "0".repeat(64); },
    (value) => { value.recovery.mcpProviderEvidence.rpcCalls[1].sessionContinuous = false; },
    (value) => { value.recovery.mcpProviderEvidence.rpcCalls[1].resultSha256 = "0".repeat(64); },
    (value) => { value.recovery.mcpProviderEvidence.close.httpStatus = 500; }
    ]) {
      const value = structuredClone(components());
      mutate(value);
      assert.throws(
        () => buildIntegratedLiveDrillCandidateReceipt({
          spec,
          ...value,
          journalPath: persistence.journalPath,
          journalRootPath: persistence.directory,
          journalReceipt: persistence.journalReceipt,
          journalIntentBindingSha256,
          postRelease,
          privateEvidencePath: persistence.destinationPath,
          privateEvidenceRootPath: persistence.directory,
          forbiddenPrivateEvidenceRootPath: fs.realpathSync(process.cwd()),
          privateEvidenceReceipt: persistence.receipt,
          authorityEvidenceId: evidenceId,
          authoritySelectedEvidenceDigest: evidenceDigest
        }),
        /INTEGRATED_LIVE_DRILL_(?:COMPONENT|PRIVATE_EVIDENCE)_/u
      );
    }
  } finally {
    fs.rmSync(persistence.directory, { recursive: true, force: true });
  }
});

test("orchestrator executes exactly DVI, race, then exact-winner recovery", async (t) => {
  const values = components();
  const calls = [];
  const privateDirectory = privateEvidenceDirectory();
  t.after(() => fs.rmSync(privateDirectory, { recursive: true, force: true }));
  const environment = {
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: JSON.stringify(spec),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH: path.join(
      privateDirectory,
      `${runId}.private-evidence.json`
    ),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT:
      privateDirectory,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH: path.join(
      privateDirectory,
      `${runId}.journal`
    ),
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
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => ({
      sourceCommit,
      treeDigest,
      packageLockDigest: spec.packageLockDigest
    }),
    runComponent: async (script, args, childEnvironment) => {
      calls.push({ script, args, environment: childEnvironment });
      if (calls.length === 1) {
        const journalNames = fs.readdirSync(
          environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH
        );
        assert.deepEqual(journalNames, [
          "00-pre-provider-intent.json"
        ]);
        const intent = JSON.parse(fs.readFileSync(path.join(
          environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH,
          journalNames[0]
        ), "utf8"));
        assert.equal(intent.phase, "PRE_PROVIDER_INTENT");
      }
      return outputs[calls.length - 1];
    }
  });
  assert.equal(receipt.status, "INCOMPLETE_LIVE_GATES_PENDING");
  assert.equal(receipt.acceptance.accepted, false);
  assert.equal(receipt.acceptance.privateEvidencePersisted, false);
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
  assert.equal(
    fs.statSync(
      environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH
    ).mode & 0o777,
    0o600
  );
  assert.equal(
    fs.statSync(
      environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH
    ).mode & 0o777,
    0o700
  );
  assert.equal(
    fs.readdirSync(
      environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH
    ).length,
    6
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
