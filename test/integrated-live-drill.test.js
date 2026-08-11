import assert from "node:assert/strict";
import {
  createHash,
  createPrivateKey
} from "node:crypto";
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
  INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA,
  INTEGRATED_LIVE_DRILL_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity,
  persistIntegratedLiveDrillPrivateEvidence,
  selectedEvidenceBindingSha256,
  startIntegratedLiveDrillJournal,
  verifyIntegratedLiveDrillJournal,
  verifyIntegratedLiveDrillPrivateEvidence
} from "../src/cloud/integrated-live-drill.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  __test as integratedLiveDrillRunnerTest,
  runIntegratedLiveDrill,
  safeIntegratedLiveDrillFailureCode
} from "../scripts/gate2-integrated-live-drill.js";
import { canonicalRecoveryAttempt } from "../src/cloud/recovery-broker.js";
import {
  signIntegratedLiveDrillEvidence,
  integratedLiveDrillAuthorizedExpectation,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillSha256,
  INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES,
  INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
  INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  integratedLiveDrillAuthorizationLedgerRootDigest,
  integratedLiveDrillHumanAuthorizationTrustRootCommitment,
  integratedLiveDrillRunnerIdentityDigest,
  integratedLiveDrillAcceptanceCore,
  integratedLiveDrillTypedEvidenceSubjects,
  INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SCHEMA,
  INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE,
  validateIntegratedLiveDrillRunAuthorization
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  __test as deploymentAttestationTest,
  signDeploymentAttestationReceipt,
  validateDeploymentAttestationPair
} from "../src/cloud/aws-deployment-attestation.js";
import { validateAwsEvidenceCaller } from
  "../src/cloud/aws-evidence-identity.js";
import { trustedPublisherKeysDigest } from
  "../src/cloud/recovery-publisher-trust.js";
import {
  generateSyntheticTestOnlyEd25519Key,
  generateSyntheticTestOnlyP256PublicKey
} from "./helpers/synthetic-test-signing-keys.js";
import {
  authorizeOrVerifyIntegratedLiveDrillChildLaunch,
  authorizeIntegratedLiveDrillChildLaunch,
  parseIntegratedLiveDrillChildAuthorization
} from "../src/cloud/integrated-live-drill-child-authorization.js";
import { validateIntegratedLiveDrillConsumedControlLedger } from
  "../src/cloud/integrated-live-drill-control-ledger.js";
import {
  INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER
} from "../src/cloud/integrated-live-drill-finalizer.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES,
  INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_COMPLETION_SCHEMA,
  INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";
import {
  INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_SCHEMA,
  INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_SCHEMA,
  loadIntegratedLiveDrillPacketAFinalizerTrustedContext,
  runIntegratedLiveDrillPacketAFinalizer
} from "../scripts/gate2-integrated-live-drill-finalizer.js";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const sourceCommit = "a".repeat(40);
const treeDigest = "b".repeat(40);
const preAttestationFixture = JSON.parse(fs.readFileSync(new URL(
  "./fixtures/integrated-live-drill-pre-attestation.json",
  import.meta.url
), "utf8"));
const configDigest = preAttestationFixture.expectation.configDigest;
const runId = "11111111-1111-4111-8111-111111111111";
const raceId = "22222222-2222-4222-8222-222222222222";
const evidenceId = "33333333-3333-4333-8333-333333333333";
const evidenceDigest = "d".repeat(64);
const authorityBinding = "e".repeat(64);
const operationId = "44444444-4444-4444-8444-444444444444";
const requestDigest = "f".repeat(64);
const journalIntentBindingSha256 = "6".repeat(64);
const runnerIdentity = "synthetic-test-runner-2026-08-10";

const specWithoutIdentity = {
  schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  sourceCommit,
  treeDigest,
  configDigest,
  packageLockDigest: "1".repeat(64),
  authoritySourceDigest: "2".repeat(64),
  authorityArtifactDigest: "3".repeat(64),
  functionArn: preAttestationFixture.expectation.functions.authority
    .numericVersionArn,
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

function integratedLaunchEvidence(ledgerRootPath) {
  const expectation = structuredClone(preAttestationFixture.expectation);
  const postReceiptKey = generateSyntheticTestOnlyEd25519Key();
  const alternateDenialReceiptKey = generateSyntheticTestOnlyEd25519Key();
  expectation.receiptPublicKeys.post =
    postReceiptKey.publicKey.publicKeySpkiDerBase64;
  expectation.receiptPublicKeys.alternateDenial =
    alternateDenialReceiptKey.publicKey.publicKeySpkiDerBase64;
  const prePrivateKey = createPrivateKey(
    preAttestationFixture.syntheticTestOnlyPrePrivateKeyPem
  );
  const prePrivateKeyPkcs8DerBase64 = prePrivateKey
    .export({ format: "der", type: "pkcs8" })
    .toString("base64");
  const evidenceKeys = Object.freeze(Object.fromEntries(
    INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name) => [
      name,
      generateSyntheticTestOnlyEd25519Key()
    ])
  ));
  const human = generateSyntheticTestOnlyEd25519Key();
  const childLaunch = generateSyntheticTestOnlyEd25519Key();
  const humanAuthorizationTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
    authorityId: "PROOFTOACT_OWNER",
    custody: "HUMAN_CONTROLLED_OFFLINE",
    ...human.publicKey
  });
  const publisherKeyId = "gate1-recovery-publisher-p256-v1";
  const publicKeySpkiBase64 = generateSyntheticTestOnlyP256PublicKey();
  const trustRoot = {
    schemaVersion: "tideproof.recovery-publisher-trust-root.v1",
    publisherKeyId,
    publicKeySpkiBase64
  };
  const trustRootJson = JSON.stringify(trustRoot);
  const trustRootCommitment = sha(
    `tideproof-recovery-publisher-trust-root-commitment-v1\n${trustRootJson}`
  );
  const trustedPublisherKeys = {
    [publisherKeyId]: publicKeySpkiBase64
  };
  const authorizationPayload = {
    schemaVersion: INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
    authorizationLedgerRootSha256:
      integratedLiveDrillAuthorizationLedgerRootDigest(ledgerRootPath),
    authorizationClaimAuthority: {
      schemaVersion: INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
      authorizationLedgerRootSha256:
        integratedLiveDrillAuthorizationLedgerRootDigest(ledgerRootPath),
      crossHostStrongConsistencyProven: false,
      durabilityScope: "SINGLE_AUTHORITATIVE_LEDGER_ROOT",
      runnerIdentitySha256: integratedLiveDrillRunnerIdentityDigest(
        runnerIdentity
      )
    },
    authorityNumericVersionArnSha256:
      integratedLiveDrillSha256(spec.functionArn),
    authorizationId: "99999999-9999-4999-8999-999999999999",
    childLaunchPublicKey: childLaunch.publicKey,
    evidencePublicKeys: Object.fromEntries(
      Object.entries(evidenceKeys).map(([name, value]) => [
        name,
        value.publicKey
      ])
    ),
    expectationSha256: integratedLiveDrillCanonicalSha256(
      integratedLiveDrillAuthorizedExpectation(expectation)
    ),
    humanAuthorizationTrustRootCommitment:
      integratedLiveDrillHumanAuthorizationTrustRootCommitment(
        humanAuthorizationTrustRoot
      ),
    expiresAt: "2026-08-09T17:00:00.000Z",
    issuedAt: "2026-08-09T16:00:00.000Z",
    maximumAwsCostUsd: "0.020000",
    maximumRecoverySourceAgeSeconds: 3600,
    publisherKeySetDigest:
      trustedPublisherKeysDigest(trustedPublisherKeys),
    recoveryPublisherTrustRootCommitment: trustRootCommitment,
    requiredManagedMcpToolCallCount: 1,
    requiredRecoveryFailpoints: INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
    requiredRecoveryJournalEntryCount: 17,
    requiredRecoveryWorkers: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
    spendAuthorization: {
      schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
      currency: "USD",
      maximumCumulativeExposureUsd: "0.020000",
      scopes: INTEGRATED_LIVE_DRILL_SPEND_SCOPES.map((scope, index) => ({
        ...scope,
        maximumExposureUsd: index === 1 ? "0.020000" : "0.000000"
      }))
    },
    runId: spec.runId,
    sourceCommit: spec.sourceCommit,
    specSha256: integratedLiveDrillCanonicalSha256(spec),
    treeDigest: spec.treeDigest,
    configDigest: spec.configDigest
  };
  const authorizationAttestation = signIntegratedLiveDrillEvidence(
    authorizationPayload,
    human.privateKeyPkcs8DerBase64,
    human.publicKey
  );
  expectation.integratedLiveDrillAuthorizationAttestationSha256 =
    integratedLiveDrillAuthorizationAttestationDigest(
      authorizationAttestation
    );
  const preUnsigned = structuredClone(preAttestationFixture.preReceipt);
  delete preUnsigned.signature;
  preUnsigned.integratedLiveDrillAuthorizationAttestationSha256 =
    expectation.integratedLiveDrillAuthorizationAttestationSha256;
  preUnsigned.expectationDigest = deploymentAttestationTest.sha256(
    expectation
  );
  preUnsigned.snapshotDigest = deploymentAttestationTest.sha256(
    deploymentAttestationTest.snapshotReceiptPayload(preUnsigned)
  );
  const preAttestation = signDeploymentAttestationReceipt(
    preUnsigned,
    preAttestationFixture.syntheticTestOnlyPrePrivateKeyPem,
    expectation.receiptPublicKeys.pre
  );
  return Object.freeze({
    alternateDenialReceiptKey,
    authorizationAttestation,
    childLaunchPrivateKeyPkcs8DerBase64:
      childLaunch.privateKeyPkcs8DerBase64,
    expectation,
    checkedAt: Date.parse("2026-08-09T16:02:30.000Z"),
    committedTrustRoot: Object.freeze({
      schemaVersion:
        INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
      trustRootCommitment,
      publisherKeySetDigest: trustedPublisherKeysDigest(
        trustedPublisherKeys
      ),
      trustedPublisherKeys: Object.freeze({ ...trustedPublisherKeys })
    }),
    evidenceKeys,
    humanAuthorizationTrustRoot,
    ledgerRootPath,
    postReceiptKey,
    preAttestation,
    trustRootCommitment,
    trustRootJson
  });
}

function deploymentCallerBindingFor(binding, context) {
  const contextDigest = deploymentAttestationTest.callerContextDigest(context);
  return {
    ...binding,
    contextDigest,
    bindingDigest: deploymentAttestationTest.sha256([
      "tideproof.aws-evidence-caller-binding.v2",
      binding.callerIdentityDigest,
      binding.expectedIdentityDigest,
      binding.expectedPrincipalDigest,
      binding.principalIdDigest,
      contextDigest
    ].join("\0"))
  };
}

function signedSyntheticDeploymentPair(launch) {
  const expectation = launch.expectation;
  const postStartedAt = "2026-08-09T16:19:59.000Z";
  const postObservedAt = "2026-08-09T16:20:00.000Z";
  const postUnsigned = structuredClone(launch.preAttestation);
  delete postUnsigned.signature;
  postUnsigned.phase = "post";
  postUnsigned.status = "POST_ATTESTATION_PASS";
  postUnsigned.observationStartedAt = postStartedAt;
  postUnsigned.observedAt = postObservedAt;
  postUnsigned.callerBinding = deploymentCallerBindingFor(
    postUnsigned.callerBinding,
    {
      purpose: "gate2-deployment-post-attestation",
      sourceCommit: expectation.sourceCommit,
      treeDigest: expectation.treeDigest,
      configDigest: expectation.configDigest,
      stackId: expectation.stackId,
      observedAt: postObservedAt
    }
  );
  postUnsigned.snapshotDigest = deploymentAttestationTest.sha256(
    deploymentAttestationTest.snapshotReceiptPayload(postUnsigned)
  );
  const postReceipt = signDeploymentAttestationReceipt(
    postUnsigned,
    launch.postReceiptKey.privateKeyPkcs8Pem,
    expectation.receiptPublicKeys.post
  );

  const alternateObservedAt = "2026-08-09T16:10:00.000Z";
  const accountId = expectation.accountId;
  const alternateCallerArn =
    `arn:aws:sts::${accountId}:assumed-role/` +
    "prooftoact-gate2-evidence-alternate/negative-control";
  const alternateCallerBinding = validateAwsEvidenceCaller(
    {
      Account: accountId,
      Arn: alternateCallerArn,
      UserId: "AROATIDEPROOFALTERNATE:negative-control"
    },
    {
      expectedAccountId: accountId,
      expectedPrincipalArn: expectation.alternatePrincipal.roleArn,
      expectedCallerArn: alternateCallerArn,
      expectedCallerUserId:
        "AROATIDEPROOFALTERNATE:negative-control",
      bindingContext: {
        purpose: "gate2-evidence-role-alternate-denial",
        sourceCommit: expectation.sourceCommit,
        treeDigest: expectation.treeDigest,
        configDigest: expectation.configDigest,
        stackId: expectation.stackId,
        targetRoleArn: expectation.evidenceOperator.roleArn,
        observedAt: alternateObservedAt
      }
    }
  );
  const alternateUnsigned = {
    schemaVersion: deploymentAttestationTest.ALTERNATE_DENIAL_SCHEMA,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest,
    configDigest: expectation.configDigest,
    alternatePrincipalArn: expectation.alternatePrincipal.roleArn,
    alternatePrincipalDigest: deploymentAttestationTest.sha256(
      expectation.alternatePrincipal.roleArn
    ),
    callerBinding: alternateCallerBinding,
    errorCode: "AccessDenied",
    expectationDigest: deploymentAttestationTest.sha256(expectation),
    observedAt: alternateObservedAt,
    outcome: "DENIED",
    providerDependencyTreeDigest:
      expectation.basis.providerDependencyTreeDigest,
    providerRuntimeSha256: expectation.basis.providerRuntimeSha256,
    requestIdDigest: "9".repeat(64),
    targetRoleArn: expectation.evidenceOperator.roleArn
  };
  const alternateDenial = signDeploymentAttestationReceipt(
    alternateUnsigned,
    launch.alternateDenialReceiptKey.privateKeyPkcs8Pem,
    expectation.receiptPublicKeys.alternateDenial
  );
  const unsignedPair = validateDeploymentAttestationPair({
    alternateDenial,
    expectation,
    postReceipt,
    preReceipt: launch.preAttestation
  });
  return signDeploymentAttestationReceipt(
    unsignedPair,
    launch.postReceiptKey.privateKeyPkcs8Pem,
    expectation.receiptPublicKeys.post
  );
}

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
    functionVersion: spec.functionArn.split(":").at(-1),
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
  const signedBundlePersistence = {
    schemaVersion: INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA,
    sourceCommit,
    treeDigest,
    runId,
    configDigest,
    sourceBuildIdentitySha256: sha(spec.sourceBuildIdentity),
    bundleDigest: recovery.bundleDigest,
    signatureDigest: "a".repeat(64),
    signedBundleSha256: "b".repeat(64),
    fileByteLength: 2048,
    pathSha256: "c".repeat(64),
    creationProtocolObserved: true,
    atomicCreateOnly: true,
    fileMode: "0600",
    parentDirectoryMode: "0700",
    sameFilesystemAtomicLink: true,
    fileDataSynced: true,
    directoryEntrySynced: true,
    rereadVerified: true,
    reusedExisting: false
  };
  recovery.signedBundlePersistence = {
    ...signedBundlePersistence,
    receiptSha256: sha(canonicalJson(signedBundlePersistence))
  };
  return { dvi, race, recovery };
}

const privateEvidenceGuardDirectories = new Set();

test.after(() => {
  for (const guardDirectory of privateEvidenceGuardDirectories) {
    fs.rmSync(guardDirectory, { recursive: true, force: true });
  }
});

function privateEvidenceDirectory() {
  const guardDirectory = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-live-evidence-guard-")
  );
  fs.chmodSync(guardDirectory, 0o700);
  privateEvidenceGuardDirectories.add(guardDirectory);
  const directory = path.join(guardDirectory, "evidence");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return fs.realpathSync(directory);
}

function authorizationLedgerDirectory(privateDirectory) {
  const directory = path.join(privateDirectory, "authorization-ledger");
  fs.mkdirSync(directory, { mode: 0o700 });
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

function orchestratorEnvironment(privateDirectory, launch) {
  return {
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: JSON.stringify(spec),
    TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION:
      JSON.stringify(launch.expectation),
    TIDEPROOF_GATE2_PRE_DEPLOYMENT_ATTESTATION:
      JSON.stringify(launch.preAttestation),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION:
      JSON.stringify(launch.authorizationAttestation),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT:
      JSON.stringify(launch.humanAuthorizationTrustRoot),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT:
      launch.ledgerRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY: runnerIdentity,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64:
      launch.childLaunchPrivateKeyPkcs8DerBase64,
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
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT: launch.trustRootJson,
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT:
      launch.trustRootCommitment,
    RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64: "private-key",
    LEAK_SENTINEL: "must-not-reach-any-child",
    SOURCE_COMMIT: sourceCommit,
    CONFIG_DIGEST: configDigest
  };
}

function orchestrationReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

function providerSupervisorPreparation() {
  const authorizationId = "99999999-9999-4999-8999-999999999999";
  const signingPayload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA,
    auditTargetIdentitySha256: "a".repeat(64),
    authorityStatement: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
    authorizationAttestationSha256: "1".repeat(64),
    authorizationId,
    childAuthorizationIssuedAt: "2026-08-10T15:59:00.000Z",
    expiresAt: "2026-08-10T16:05:00.000Z",
    issuedAt: "2026-08-10T16:00:00.000Z",
    logicalMcpRequestSha256: "2".repeat(64),
    maximumInitializeCount: 1,
    maximumInitializedNotificationCount: 1,
    maximumManagedMcpToolCallCount: 1,
    preCallIntentSha256: "3".repeat(64),
    recoveryBrokerConfigDigest: "4".repeat(64),
    requiredSessionCloseCount: 1,
    requiredToolsCallCount: 1,
    runId
  });
  return orchestrationReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId,
    authorizationAttestationSha256:
      signingPayload.authorizationAttestationSha256,
    finalReleaseReady: false,
    logicalMcpRequestSha256: signingPayload.logicalMcpRequestSha256,
    preCallIntentSha256: signingPayload.preCallIntentSha256,
    preparationContextSha256: "5".repeat(64),
    preparationReceiptSha256: "6".repeat(64),
    providerBacked: false,
    recoveryBrokerConfigDigest: signingPayload.recoveryBrokerConfigDigest,
    runId,
    signingPayload,
    signingPayloadSha256:
      integratedLiveDrillCanonicalSha256(signingPayload),
    stateHistory: [
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
        .RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION
    ],
    status: "AWAITING_AUTHORIZATION"
  }));
}

function providerSupervisorCompletion(preparation) {
  return orchestrationReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_COMPLETION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId: preparation.authorizationId,
    finalReleaseReady: false,
    finalizationReceiptSha256: "a".repeat(64),
    observedInitializeCount: 1,
    observedInitializedNotificationCount: 1,
    observedSessionCloseCount: 1,
    observedToolsCallCount: 1,
    preCallIntentSha256: preparation.preCallIntentSha256,
    providerBacked: false,
    providerHandoffReceiptSha256: "b".repeat(64),
    recoveryReceiptSha256: "c".repeat(64),
    runId,
    stateHistory: [
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
        .DISPATCH_AUTHORIZATION_ACCEPTED,
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
        .PROVIDER_WORKER_HANDOFF_DURABLE,
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
        .PROVIDER_FINALIZATION_DURABLE
    ],
    status: "LOCAL_PROVIDER_SUPERVISOR_COMPLETED_NOT_RELEASED"
  }));
}

const providerResumeVerification = Object.freeze({
  verifyProviderDispatchAuthorization: async () => Object.freeze({
    attestationSha256: "d".repeat(64)
  }),
  verifyProviderPreparationEvidence: async ({
    decisionRootPath,
    gate1Preparation
  }) => Object.freeze({
    gate1Preparation,
    supervisorEvidence: Object.freeze({
      context: Object.freeze({ ledgerRootPath: decisionRootPath })
    })
  })
});

async function preparedProviderOrchestrationCase() {
  const values = components();
  const preparation = providerSupervisorPreparation();
  const privateDirectory = privateEvidenceDirectory();
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  const environment = orchestratorEnvironment(privateDirectory, launch);
  const outputs = [values.dvi, values.race, preparation];
  await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment: {
      ...environment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => postRelease,
    runComponent: async () => outputs.shift()
  });
  return Object.freeze({
    environment,
    launch,
    preparation,
    privateDirectory
  });
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
    /current file bytes are bound, but actual restart reuse and crash continuity are not proven/
  );
  assert.equal(receipt.invariantCount, 25);
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
  assert.equal(receipt.recovery.signedBundleCurrentBytesBound, true);
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
    (value) => {
      value.race.invocationRequestDigests.changedInput =
        value.race.invocationRequestDigests.replay;
    },
    (value) => {
      value.race.awsInvokeRequestDigests.changedInput =
        value.race.awsInvokeRequestDigests.replay;
    },
    (value) => { value.race.providerOperations.stsGetCallerIdentityRequests = 2; },
    (value) => { value.recovery.mcpCallCount = 2; },
    (value) => { value.recovery.terminalAuditCommitted = false; },
    (value) => { value.recovery.signedBundlePersistence.bundleDigest = "0".repeat(64); },
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
  const childAuthorizations = [];
  const privateDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(privateDirectory)
  );
  t.after(() => fs.rmSync(privateDirectory, { recursive: true, force: true }));
  const environment = orchestratorEnvironment(privateDirectory, launch);
  const outputs = [values.dvi, values.race, values.recovery];
  const receipt = await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment,
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => ({
      sourceCommit,
      treeDigest,
      packageLockDigest: spec.packageLockDigest
    }),
    runComponent: async (script, args, childEnvironment) => {
      const scopeId = [
        "DVI_PROOF",
        "AWS_AUTHORITY_RACE",
        "MANAGED_MCP_RECOVERY"
      ][calls.length];
      const authorizeChild = scopeId === "MANAGED_MCP_RECOVERY"
        ? authorizeOrVerifyIntegratedLiveDrillChildLaunch
        : authorizeIntegratedLiveDrillChildLaunch;
      childAuthorizations.push(authorizeChild(
        childEnvironment,
        scopeId,
        {
          now: launch.checkedAt,
          forbiddenRootPath: fs.realpathSync(process.cwd())
        }
      ));
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
  assert.deepEqual(receipt.acceptance.blockers, [
    "SIGNED_PRE_POST_DEPLOYMENT_ATTESTATION_NOT_BOUND",
    "PRIVATE_RAW_EVIDENCE_NOT_INDEPENDENTLY_ATTESTED",
    "RESTART_STABLE_SIGNED_BUNDLE_REUSE_NOT_PROVEN",
    "CRASH_SAFE_RECOVERY_NOT_PROVEN",
    "CROSS_HOST_STRONGLY_CONSISTENT_AUTHORIZATION_CLAIM_AUTHORITY_NOT_PROVEN",
    "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN",
    "PROVIDER_PRICING_AND_BILLING_NOT_PROVEN"
  ]);
  assert.equal(calls.length, 3);
  assert.match(calls[0].script, /gate1-admissible-vector\.js$/u);
  assert.match(calls[1].script, /gate2-authority-race\.js$/u);
  assert.match(calls[2].script, /gate1-recovery-broker\.js$/u);
  for (const [index, scope] of [
    "DVI_PROOF",
    "AWS_AUTHORITY_RACE",
    "MANAGED_MCP_RECOVERY"
  ].entries()) {
    const childAuthorization = parseIntegratedLiveDrillChildAuthorization(
      calls[index].environment,
      scope,
      { now: launch.checkedAt }
    );
    assert.equal(childAuthorization.value.runId, spec.runId);
    assert.equal(childAuthorization.value.scope.sequence, index + 1);
    assert.equal(
      childAuthorizations[index].launchReceipt.sequence,
      index + 1
    );
    if (scope === "MANAGED_MCP_RECOVERY") {
      assert.equal(childAuthorizations[index].launchConsumedNow, true);
      const resumedChildAuthorization =
        authorizeOrVerifyIntegratedLiveDrillChildLaunch(
          calls[index].environment,
          scope,
          {
            now: launch.checkedAt,
            forbiddenRootPath: fs.realpathSync(process.cwd())
          }
        );
      assert.equal(resumedChildAuthorization.launchConsumedNow, false);
      assert.equal(
        resumedChildAuthorization.launchReceipt.receiptSha256,
        childAuthorizations[index].launchReceipt.receiptSha256
      );
    }
    assert.throws(
      () => authorizeIntegratedLiveDrillChildLaunch(
        calls[index].environment,
        scope,
        {
          now: launch.checkedAt,
          forbiddenRootPath: fs.realpathSync(process.cwd())
        }
      ),
      /INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ALREADY_CONSUMED/u
    );
  }
  const tamperedChildEnvironment = { ...calls[0].environment };
  const tamperedLaunchToken = JSON.parse(
    tamperedChildEnvironment
      .TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION
  );
  tamperedLaunchToken.payload.nonceSha256 = "0".repeat(64);
  tamperedChildEnvironment
    .TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION =
      canonicalJson(tamperedLaunchToken);
  assert.throws(
    () => authorizeIntegratedLiveDrillChildLaunch(
      tamperedChildEnvironment,
      "DVI_PROOF",
      {
        now: launch.checkedAt,
        forbiddenRootPath: fs.realpathSync(process.cwd())
      }
    ),
    /INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SIGNATURE_REJECTED/u
  );
  assert.equal(
    calls[2].environment.RECOVERY_SOURCE_OPERATION_ID,
    operationId
  );
  assert.equal(
    calls[2].environment.RECOVERY_SOURCE_REQUEST_DIGEST,
    requestDigest
  );
  assert.equal(
    calls[2].environment
      .TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH,
    path.join(
      privateDirectory,
      `${runId}.signed-recovery-bundle.json`
    )
  );
  assert.equal(
    calls[2].environment
      .TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT,
    privateDirectory
  );
  assert.deepEqual(
    JSON.parse(
      calls[2].environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC
    ),
    spec
  );
  assert.equal(
    calls[2].environment.RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256,
    authorityBinding
  );
  assert.equal(calls.every(({ environment: child }) =>
    !("LEAK_SENTINEL" in child)), true);
  assert.equal(calls.every(({ environment: child }) =>
    !("TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64" in
      child)), true);
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

  const finalizerNow = Date.parse("2026-08-09T16:30:00.000Z");
  const authorization = validateIntegratedLiveDrillRunAuthorization(
    launch.authorizationAttestation,
    {
      spec,
      expectation: launch.expectation,
      committedTrustRoot: launch.committedTrustRoot,
      humanAuthorizationTrustRoot: launch.humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: launch.ledgerRootPath,
      now: finalizerNow
    }
  );
  const ledger = validateIntegratedLiveDrillConsumedControlLedger({
    authorization,
    ledgerRootPath: launch.ledgerRootPath,
    forbiddenRootPath: fs.realpathSync(process.cwd())
  });
  assert.equal(
    ledger.controlLedgerReceipt.receiptSha256,
    receipt.costControl.authorizationControlLedgerReceiptSha256
  );
  // Packet B1 continuity is intentionally non-circular and must be created
  // before the real recovery call. This orchestrator remains the existing
  // post-call candidate path, so it must not fabricate a local continuity
  // journal from the completed candidate.
  const deploymentAttestationPair = signedSyntheticDeploymentPair(launch);
  const subjects = integratedLiveDrillTypedEvidenceSubjects({
    authorization,
    candidateReceipt: receipt,
    controlLedgerReceipt: ledger.controlLedgerReceipt,
    deploymentAttestationPair,
    expectation: launch.expectation
  });
  const evidenceAttestations = Object.freeze(Object.fromEntries(
    INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name, index) => {
      const subject = subjects[name];
      const payload = Object.freeze({
        schemaVersion: INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE[name].schemaVersion,
        authorizationAttestationSha256:
          integratedLiveDrillAuthorizationAttestationDigest(
            launch.authorizationAttestation
          ),
        authorizationId: authorization.payload.authorizationId,
        candidateReceiptSha256: receipt.receiptSha256,
        configDigest: spec.configDigest,
        observedAt: new Date(
          Date.parse("2026-08-09T16:21:00.000Z") + (index * 60_000)
        ).toISOString(),
        runId: spec.runId,
        sourceCommit: spec.sourceCommit,
        status: INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE[name].status,
        subject,
        subjectSha256: integratedLiveDrillCanonicalSha256(subject),
        treeDigest: spec.treeDigest
      });
      return [name, signIntegratedLiveDrillEvidence(
        payload,
        launch.evidenceKeys[name].privateKeyPkcs8DerBase64,
        launch.evidenceKeys[name].publicKey
      )];
    })
  ));
  const evidenceDigests = Object.freeze({
    acceptedReceipt: integratedLiveDrillCanonicalSha256(
      evidenceAttestations.acceptedReceipt
    ),
    billingSettlement: integratedLiveDrillCanonicalSha256(
      evidenceAttestations.billingSettlement
    ),
    costUpperBound: integratedLiveDrillCanonicalSha256(
      evidenceAttestations.costUpperBound
    ),
    deploymentPair: integratedLiveDrillCanonicalSha256(
      deploymentAttestationPair
    ),
    latestObservedAt: Date.parse("2026-08-09T16:25:00.000Z"),
    privateEvidence: integratedLiveDrillCanonicalSha256(
      evidenceAttestations.privateEvidence
    ),
    recoveryContinuity: integratedLiveDrillCanonicalSha256(
      evidenceAttestations.recoveryContinuity
    )
  });
  const finalizationPayload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SCHEMA,
    statementId: "77777777-7777-4777-8777-777777777777",
    authorizationId: authorization.payload.authorizationId,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        launch.authorizationAttestation
      ),
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    configDigest: spec.configDigest,
    runId: spec.runId,
    candidateReceiptSha256: receipt.receiptSha256,
    acceptedReceiptAttestationSha256: evidenceDigests.acceptedReceipt,
    billingStatus: "PENDING",
    billingSettlementAttestationSha256:
      evidenceDigests.billingSettlement,
    privateEvidenceAttestationSha256: evidenceDigests.privateEvidence,
    recoveryContinuityAttestationSha256:
      evidenceDigests.recoveryContinuity,
    costUpperBoundAttestationSha256: evidenceDigests.costUpperBound,
    deploymentAttestationPairSha256: evidenceDigests.deploymentPair,
    acceptanceCoreSha256: integratedLiveDrillCanonicalSha256(
      integratedLiveDrillAcceptanceCore({
        authorization,
        evidenceDigests,
        candidateReceiptSha256: receipt.receiptSha256
      })
    ),
    issuedAt: "2026-08-09T16:27:00.000Z"
  });
  const finalizationStatement = signIntegratedLiveDrillEvidence(
    finalizationPayload,
    launch.postReceiptKey.privateKeyPkcs8DerBase64,
    launch.postReceiptKey.publicKey
  );
  const finalizerInput = {
    schemaVersion: INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_SCHEMA,
    authorizationAttestation: launch.authorizationAttestation,
    candidateReceipt: receipt,
    deploymentAttestationPair,
    evidenceAttestations,
    expectation: launch.expectation,
    finalizationStatement
  };
  const finalizerTrustedContext = {
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PACKET_A_TRUSTED_CONTEXT_SCHEMA,
    committedTrustRoot: launch.committedTrustRoot,
    forbiddenRootPath: fs.realpathSync(process.cwd()),
    humanAuthorizationTrustRoot: launch.humanAuthorizationTrustRoot,
    ledgerRootPath: launch.ledgerRootPath,
    runnerIdentity,
    spec
  };
  const finalizerEnvironment = orchestratorEnvironment(
    privateDirectory,
    launch
  );
  finalizerEnvironment.TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC =
    canonicalJson(spec);
  finalizerEnvironment
    .TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT =
      canonicalJson(launch.humanAuthorizationTrustRoot);
  const loadedFinalizerTrustedContext =
    loadIntegratedLiveDrillPacketAFinalizerTrustedContext(
      finalizerEnvironment
    );
  assert.equal(
    loadedFinalizerTrustedContext.forbiddenRootPath,
    fs.realpathSync(process.cwd())
  );
  assert.deepEqual(
    loadedFinalizerTrustedContext.committedTrustRoot,
    launch.committedTrustRoot
  );
  assert.deepEqual(
    loadedFinalizerTrustedContext.humanAuthorizationTrustRoot,
    launch.humanAuthorizationTrustRoot
  );
  assert.equal(loadedFinalizerTrustedContext.ledgerRootPath, launch.ledgerRootPath);
  assert.equal(loadedFinalizerTrustedContext.runnerIdentity, runnerIdentity);
  assert.deepEqual(loadedFinalizerTrustedContext.spec, spec);
  const packetA = runIntegratedLiveDrillPacketAFinalizer(
    finalizerInput,
    finalizerTrustedContext,
    { now: finalizerNow }
  );
  assert.equal(packetA.accepted, false);
  assert.equal(packetA.finalReleaseReady, false);
  assert.equal(packetA.providerBacked, false);
  assert.equal(packetA.liveProviderBoundW1W5ContinuityProven, false);
  assert.equal(packetA.localSameHostScaffoldValidated, false);
  assert.equal(
    packetA.status,
    "PACKET_B_PROVIDER_ACCEPTANCE_PENDING"
  );
  assert.equal(
    packetA.recoveryContinuityDisposition,
    "NOT_PROVEN"
  );
  assert.equal(packetA.recoveryContinuityJournalReceiptSha256, null);
  assert.deepEqual(packetA.packetBBlockers, [
    INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER
  ]);
  assert.match(packetA.claimBoundary, /Packet B must independently prove/u);
  assert.match(
    packetA.claimBoundary,
    /durable exact-one Managed MCP behavior/u
  );
  assert.deepEqual(packetA.packetABoundaryBlockers, [
    "CROSS_HOST_STRONGLY_CONSISTENT_AUTHORIZATION_CLAIM_AUTHORITY_NOT_PROVEN"
  ]);
  assert.equal(
    packetA.authorizationControlLedgerReceiptSha256,
    ledger.controlLedgerReceipt.receiptSha256
  );
  for (const [field, value] of Object.entries({
    committedTrustRoot: launch.committedTrustRoot,
    forbiddenRootPath: privateDirectory,
    humanAuthorizationTrustRoot: launch.humanAuthorizationTrustRoot,
    ledgerRootPath: launch.ledgerRootPath,
    runnerIdentity,
    spec
  })) {
    assert.throws(
      () => runIntegratedLiveDrillPacketAFinalizer(
        { ...finalizerInput, [field]: value },
        finalizerTrustedContext,
        { now: finalizerNow }
      ),
      /INTEGRATED_LIVE_DRILL_PACKET_A_INPUT_REJECTED/u,
      `untrusted packet field ${field}`
    );
  }
  const mutatedAuthorizationInput = structuredClone(finalizerInput);
  mutatedAuthorizationInput.authorizationAttestation.payload
    .maximumAwsCostUsd = "0.010000";
  assert.throws(
    () => runIntegratedLiveDrillPacketAFinalizer(
      mutatedAuthorizationInput,
      finalizerTrustedContext,
      { now: finalizerNow }
    ),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_SIGNATURE_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillPacketAFinalizer(
      finalizerInput,
      {
        ...finalizerTrustedContext,
        runnerIdentity: `${runnerIdentity}-substituted`
      },
      { now: finalizerNow }
    ),
    /INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY_REJECTED/u
  );
  const substitutedHuman = generateSyntheticTestOnlyEd25519Key();
  assert.throws(
    () => runIntegratedLiveDrillPacketAFinalizer(
      finalizerInput,
      {
        ...finalizerTrustedContext,
        humanAuthorizationTrustRoot: {
          ...launch.humanAuthorizationTrustRoot,
          ...substitutedHuman.publicKey
        }
      },
      { now: finalizerNow }
    ),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_SIGNATURE_REJECTED/u
  );
  const substitutedPublisherKeys = {
    substituted: generateSyntheticTestOnlyP256PublicKey()
  };
  assert.throws(
    () => runIntegratedLiveDrillPacketAFinalizer(
      finalizerInput,
      {
        ...finalizerTrustedContext,
        committedTrustRoot: {
          ...finalizerTrustedContext.committedTrustRoot,
          publisherKeySetDigest: trustedPublisherKeysDigest(
            substitutedPublisherKeys
          ),
          trustedPublisherKeys: substitutedPublisherKeys
        }
      },
      { now: finalizerNow }
    ),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillPacketAFinalizer(
      finalizerInput,
      {
        ...finalizerTrustedContext,
        forbiddenRootPath: privateDirectory
      },
      { now: finalizerNow }
    ),
    /INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_ROOT_REJECTED/u
  );
});

test("provider orchestration PREPARE holds after durable DVI/race and RESUME does not rerun them", async (t) => {
  const values = components();
  const preparation = providerSupervisorPreparation();
  const privateDirectory = privateEvidenceDirectory();
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const baseEnvironment = orchestratorEnvironment(privateDirectory, launch);
  const prepareCalls = [];
  let prepareReleaseChecks = 0;
  const hold = await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => {
      prepareReleaseChecks += 1;
      return {
        sourceCommit,
        treeDigest,
        packageLockDigest: spec.packageLockDigest
      };
    },
    runComponent: async (script, args, childEnvironment) => {
      prepareCalls.push({ args, childEnvironment, script });
      return [values.dvi, values.race, preparation][prepareCalls.length - 1];
    }
  });
  assert.equal(
    hold.status,
    "HOLD_AWAITING_EXACT_PROVIDER_DISPATCH_AUTHORIZATION"
  );
  assert.equal(hold.accepted, false);
  assert.equal(hold.providerBacked, false);
  assert.equal(hold.finalReleaseReady, false);
  assert.equal(prepareCalls.length, 3);
  assert.equal(prepareReleaseChecks, 5);
  assert.match(prepareCalls[0].script, /gate1-admissible-vector\.js$/u);
  assert.match(prepareCalls[1].script, /gate2-authority-race\.js$/u);
  assert.match(
    prepareCalls[2].script,
    /gate1-integrated-live-drill-provider-supervisor\.js$/u
  );
  assert.equal("MCP_API_KEY" in prepareCalls[2].childEnvironment, false);
  assert.equal("AWS_ACCESS_KEY_ID" in prepareCalls[2].childEnvironment, false);
  assert.equal("LEAK_SENTINEL" in prepareCalls[2].childEnvironment, false);
  assert.equal(
    prepareCalls[2].childEnvironment
      .TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE,
    "PREPARE"
  );
  const journalNames = fs.readdirSync(
    baseEnvironment.TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH
  );
  assert.equal(journalNames.length, 3);
  assert.equal(
    journalNames.some((name) => name.includes("recovery-result")),
    false
  );
  assert.equal(
    fs.existsSync(baseEnvironment.TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH),
    false
  );

  const resumeCalls = [];
  const completion = providerSupervisorCompletion(preparation);
  const completed = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => ({
      sourceCommit,
      treeDigest,
      packageLockDigest: spec.packageLockDigest
    }),
    runComponent: async (script, args, childEnvironment) => {
      resumeCalls.push({ args, childEnvironment, script });
      return completion;
    }
  });
  assert.equal(
    completed.status,
    "LOCAL_PROVIDER_ORCHESTRATION_COMPLETED_NOT_RELEASED"
  );
  assert.equal(completed.accepted, false);
  assert.equal(completed.providerBacked, false);
  assert.equal(completed.finalReleaseReady, false);
  assert.equal(resumeCalls.length, 1);
  assert.match(
    resumeCalls[0].script,
    /gate1-integrated-live-drill-provider-supervisor\.js$/u
  );
  assert.equal(resumeCalls[0].childEnvironment.MCP_API_KEY,
    baseEnvironment.MCP_API_KEY);
  assert.equal(
    resumeCalls[0].childEnvironment.PRIMARY_AUDIT_DATABASE_URL,
    baseEnvironment.PRIMARY_AUDIT_DATABASE_URL
  );
  for (const name of [
    "AWS_ACCESS_KEY_ID",
    "HOME",
    "NODE_OPTIONS",
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
    "RECOVERY_PUBLISHER_DATABASE_URL",
    "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64"
  ]) {
    assert.equal(name in resumeCalls[0].childEnvironment, false, name);
  }

  let idempotentResumeCalls = 0;
  const replayedCompletion = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => {
      throw new Error("idempotent completion must not reverify release");
    },
    runComponent: async () => {
      idempotentResumeCalls += 1;
      throw new Error("idempotent completion must not respawn supervisor");
    }
  });
  assert.deepEqual(replayedCompletion, completed);
  assert.equal(idempotentResumeCalls, 0);

  const legacyStopPath = path.join(
    launch.ledgerRootPath,
    `${runId}.provider-orchestration-stop.json`
  );
  fs.writeFileSync(legacyStopPath, "{}\n", { mode: 0o600 });
  const replayWithLegacyNoise = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    runComponent: async () => completion,
    verifyRelease: async () => postRelease
  });
  assert.deepEqual(replayWithLegacyNoise, completed);
});

test("provider orchestration mode/environment accessors fail before execution", async () => {
  let getterRuns = 0;
  const environment = {};
  Object.defineProperty(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE",
    {
      enumerable: true,
      get() {
        getterRuns += 1;
        return "PREPARE";
      }
    }
  );
  await assert.rejects(
    () => runIntegratedLiveDrill({ environment }),
    /INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED/u
  );
  assert.equal(getterRuns, 0);
});

test("concurrent RESUMEs atomically choose stop or admission without provider overlap", async () => {
  const stopWinsCase = await preparedProviderOrchestrationCase();
  let releaseBlockedVerifier;
  let signalBlockedVerifier;
  const blockedVerifierReached = new Promise((resolve) => {
    signalBlockedVerifier = resolve;
  });
  const unblockVerifier = new Promise((resolve) => {
    releaseBlockedVerifier = resolve;
  });
  let blockedReleaseChecks = 0;
  let providerCalls = 0;
  const blockedResume = runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...stopWinsCase.environment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => {
      blockedReleaseChecks += 1;
      if (blockedReleaseChecks === 1) {
        signalBlockedVerifier();
        await unblockVerifier;
      }
      return postRelease;
    },
    runComponent: async () => {
      providerCalls += 1;
      return providerSupervisorCompletion(stopWinsCase.preparation);
    }
  });
  await blockedVerifierReached;
  const stopWinner = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    verifyProviderDispatchAuthorization: async () => {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_UNKNOWN_DO_NOT_ACT"
      );
    },
    environment: {
      ...stopWinsCase.environment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async () => {
      providerCalls += 1;
      return providerSupervisorCompletion(stopWinsCase.preparation);
    }
  });
  releaseBlockedVerifier();
  const stopObservedByBlockedResume = await blockedResume;
  assert.equal(stopWinner.decision, "STOPPED_BEFORE_PROVIDER_ADMISSION");
  assert.deepEqual(stopObservedByBlockedResume, stopWinner);
  assert.equal(providerCalls, 0);

  const admissionWinsCase = await preparedProviderOrchestrationCase();
  let releaseProvider;
  let signalProvider;
  const providerReached = new Promise((resolve) => {
    signalProvider = resolve;
  });
  const unblockProvider = new Promise((resolve) => {
    releaseProvider = resolve;
  });
  let ownerCalls = 0;
  let contenderCalls = 0;
  const admissionOwner = runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...admissionWinsCase.environment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async () => {
      ownerCalls += 1;
      signalProvider();
      await unblockProvider;
      return providerSupervisorCompletion(admissionWinsCase.preparation);
    }
  });
  await providerReached;
  const admissionObservedByContender = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...admissionWinsCase.environment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async () => {
      contenderCalls += 1;
      return providerSupervisorCompletion(admissionWinsCase.preparation);
    }
  });
  assert.equal(admissionObservedByContender.decision, "PROVIDER_ADMITTED");
  releaseProvider();
  const admissionCompletion = await admissionOwner;
  assert.equal(
    admissionCompletion.status,
    "LOCAL_PROVIDER_ORCHESTRATION_COMPLETED_NOT_RELEASED"
  );
  assert.equal(ownerCalls, 1);
  assert.equal(contenderCalls, 0);
});

test("RESUME catch path never returns a mismatched admitted decision", async () => {
  const prepared = await preparedProviderOrchestrationCase();
  const decisionPath = path.join(
    prepared.launch.ledgerRootPath,
    `${runId}.provider-orchestration-decision.json`
  );
  let componentCalls = 0;
  await assert.rejects(
    () => runIntegratedLiveDrill({
      ...providerResumeVerification,
      environment: {
        ...prepared.environment,
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
      },
      rootDir: fs.realpathSync(process.cwd()),
      verifyRelease: async () => postRelease,
      runComponent: async () => {
        componentCalls += 1;
        const changed = JSON.parse(fs.readFileSync(decisionPath, "utf8"));
        changed.preparationReceiptSha256 = "e".repeat(64);
        delete changed.receiptSha256;
        changed.receiptSha256 = integratedLiveDrillCanonicalSha256(changed);
        fs.writeFileSync(decisionPath, `${canonicalJson(changed)}\n`, {
          mode: 0o600
        });
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_UNKNOWN_DO_NOT_ACT"
        );
      }
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATE_CONFLICT/u
  );
  assert.equal(componentCalls, 1);
});

test("RESUME rejects authorization-ledger substitution before provider admission", async () => {
  const prepared = await preparedProviderOrchestrationCase();
  const substitutedLedgerParent = privateEvidenceDirectory();
  const substitutedLedger = authorizationLedgerDirectory(
    substitutedLedgerParent
  );
  let dispatchChecks = 0;
  let providerCalls = 0;
  await assert.rejects(
    () => runIntegratedLiveDrill({
      ...providerResumeVerification,
      verifyProviderDispatchAuthorization: async () => {
        dispatchChecks += 1;
        return { attestationSha256: "d".repeat(64) };
      },
      environment: {
        ...prepared.environment,
        TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT:
          substitutedLedger,
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
      },
      rootDir: fs.realpathSync(process.cwd()),
      verifyRelease: async () => postRelease,
      runComponent: async () => {
        providerCalls += 1;
        return providerSupervisorCompletion(prepared.preparation);
      }
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED/u
  );
  assert.equal(dispatchChecks, 0);
  assert.equal(providerCalls, 0);
});

test("RESUME rebind and terminal path anomalies fail before provider admission", async () => {
  const substitutedCase = await preparedProviderOrchestrationCase();
  let dispatchChecks = 0;
  let providerCalls = 0;
  const substituted = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    verifyProviderPreparationEvidence: async ({ gate1Preparation }) => ({
      gate1Preparation: { ...gate1Preparation, status: "SUBSTITUTED" }
    }),
    verifyProviderDispatchAuthorization: async () => {
      dispatchChecks += 1;
      return { attestationSha256: "d".repeat(64) };
    },
    environment: {
      ...substitutedCase.environment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async () => {
      providerCalls += 1;
      return providerSupervisorCompletion(substitutedCase.preparation);
    }
  });
  assert.equal(substituted.decision, "STOPPED_BEFORE_PROVIDER_ADMISSION");
  assert.equal(dispatchChecks, 0);
  assert.equal(providerCalls, 0);

  for (const terminal of ["decision", "completion"]) {
    const anomalousCase = await preparedProviderOrchestrationCase();
    const anomalousPath = terminal === "decision"
      ? path.join(
        anomalousCase.launch.ledgerRootPath,
        `${runId}.provider-orchestration-decision.json`
      )
      : path.join(
        anomalousCase.privateDirectory,
        `${runId}.provider-orchestration-completion.json`
      );
    fs.symlinkSync(`${anomalousPath}.missing`, anomalousPath);
    let anomalousProviderCalls = 0;
    await assert.rejects(
      () => runIntegratedLiveDrill({
        ...providerResumeVerification,
        environment: {
          ...anomalousCase.environment,
          TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION:
            "{}",
          TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
        },
        rootDir: fs.realpathSync(process.cwd()),
        verifyRelease: async () => postRelease,
        runComponent: async () => {
          anomalousProviderCalls += 1;
          return providerSupervisorCompletion(anomalousCase.preparation);
        }
      }),
      /INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_(?:DECISION|STATE_CONFLICT)/u,
      terminal
    );
    assert.equal(anomalousProviderCalls, 0, terminal);
  }
});

test("checkpoint root swap after atomic admission remains durably admitted", async (t) => {
  const values = components();
  const preparation = providerSupervisorPreparation();
  const privateDirectory = privateEvidenceDirectory();
  const movedDirectory = `${privateDirectory}.moved`;
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(movedDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const baseEnvironment = orchestratorEnvironment(privateDirectory, launch);
  const prepareOutputs = [values.dvi, values.race, preparation];
  await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => postRelease,
    runComponent: async () => prepareOutputs.shift()
  });
  let call = 0;
  const decision = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async () => {
      call += 1;
      fs.renameSync(privateDirectory, movedDirectory);
      fs.mkdirSync(privateDirectory, { mode: 0o700 });
      return providerSupervisorCompletion(preparation);
    }
  });
  assert.equal(call, 1);
  assert.equal(decision.state, "PROVIDER_ADMITTED");
  assert.equal(decision.retryPermitted, false);
  const durableDecisionPath = path.join(
    launch.ledgerRootPath,
    `${runId}.provider-orchestration-decision.json`
  );
  assert.equal(fs.existsSync(durableDecisionPath), true);
  fs.rmSync(privateDirectory, { recursive: true, force: true });
  fs.renameSync(movedDirectory, privateDirectory);
});

test("checkpoint root swap during completion cannot contradict admission", async (t) => {
  const values = components();
  const preparation = providerSupervisorPreparation();
  const privateDirectory = privateEvidenceDirectory();
  const movedDirectory = `${privateDirectory}.moved`;
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(movedDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const baseEnvironment = orchestratorEnvironment(privateDirectory, launch);
  const prepareOutputs = [values.dvi, values.race, preparation];
  await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => postRelease,
    runComponent: async () => prepareOutputs.shift()
  });
  let releaseChecks = 0;
  const decision = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => {
      releaseChecks += 1;
      if (releaseChecks === 2) {
        fs.renameSync(privateDirectory, movedDirectory);
        fs.mkdirSync(privateDirectory, { mode: 0o700 });
      }
      return postRelease;
    },
    runComponent: async () => providerSupervisorCompletion(preparation)
  });
  assert.equal(releaseChecks, 2);
  assert.equal(decision.state, "PROVIDER_ADMITTED");
  assert.equal(decision.retryPermitted, false);
  assert.equal(
    fs.existsSync(path.join(
      launch.ledgerRootPath,
      `${runId}.provider-orchestration-decision.json`
    )),
    true
  );
  fs.rmSync(privateDirectory, { recursive: true, force: true });
  fs.renameSync(movedDirectory, privateDirectory);
});

test("transient root swap-out after admission cannot create a stop", async (t) => {
  const values = components();
  const preparation = providerSupervisorPreparation();
  const privateDirectory = privateEvidenceDirectory();
  const movedDirectory = `${privateDirectory}.moved`;
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(movedDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const baseEnvironment = orchestratorEnvironment(privateDirectory, launch);
  const prepareOutputs = [values.dvi, values.race, preparation];
  await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => postRelease,
    runComponent: async () => prepareOutputs.shift()
  });
  let calls = 0;
  const decision = await runIntegratedLiveDrill({
    ...providerResumeVerification,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async (_script, _args, _environment, boundary) => {
      calls += 1;
      assert.equal(boundary.capabilityRootPath, privateDirectory);
      assert.equal(Number.isInteger(boundary.rootDescriptor), true);
      fs.renameSync(privateDirectory, movedDirectory);
      fs.mkdirSync(privateDirectory, { mode: 0o700 });
      fs.writeFileSync(path.join(privateDirectory, "replacement.json"), "{}\n", {
        mode: 0o600
      });
      fs.rmSync(privateDirectory, { recursive: true, force: true });
      fs.renameSync(movedDirectory, privateDirectory);
      return providerSupervisorCompletion(preparation);
    }
  });
  assert.equal(calls, 1);
  assert.equal(decision.state, "PROVIDER_ADMITTED");
  assert.equal(decision.retryPermitted, false);
  assert.equal(
    fs.existsSync(path.join(
      privateDirectory,
      `${runId}.provider-orchestration-completion.json`
    )),
    false
  );
});

test("synthetic crash codes escape only under test and one-use admission prevents production redispatch", async (t) => {
  const makePreparedCase = async (prefix) => {
    const values = components();
    const preparation = providerSupervisorPreparation();
    const privateDirectory = privateEvidenceDirectory();
    const ledgerDirectory = privateEvidenceDirectory();
    const launch = integratedLaunchEvidence(
      authorizationLedgerDirectory(ledgerDirectory)
    );
    t.after(() => {
      fs.rmSync(privateDirectory, { recursive: true, force: true });
      fs.rmSync(ledgerDirectory, { recursive: true, force: true });
    });
    const environment = orchestratorEnvironment(privateDirectory, launch);
    const outputs = [values.dvi, values.race, preparation];
    await runIntegratedLiveDrill({
      clock: () => launch.checkedAt,
      environment: {
        ...environment,
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
      },
      rootDir: fs.realpathSync(process.cwd()),
      verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
        gate1Preparation
      }),
      verifyRelease: async () => postRelease,
      runComponent: async () => outputs.shift()
    });
    return { environment, launch, preparation, prefix };
  };
  const crashCode =
    "INTEGRATED_LIVE_DRILL_SYNTHETIC_CRASH_AFTER_PROVIDER_EVIDENCE_DURABLE";

  const testCase = await makePreparedCase("test");
  await assert.rejects(
    () => runIntegratedLiveDrill({
      ...providerResumeVerification,
      environment: {
        ...testCase.environment,
        NODE_ENV: "test",
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
      },
      rootDir: fs.realpathSync(process.cwd()),
      verifyRelease: async () => postRelease,
      runComponent: async () => { throw new Error(crashCode); }
    }),
    new RegExp(crashCode, "u")
  );
  assert.equal(
    fs.existsSync(path.join(
      testCase.launch.ledgerRootPath,
      `${runId}.provider-orchestration-decision.json`
    )),
    true
  );

  for (const productionCrashCode of [
    "INTEGRATED_LIVE_DRILL_SYNTHETIC_CRASH_AFTER_PRE_READ_AUDIT_COMMIT",
    crashCode,
    "INTEGRATED_LIVE_DRILL_SYNTHETIC_CRASH_AFTER_TERMINAL_AUDIT_COMMIT"
  ]) {
    const productionCase = await makePreparedCase(productionCrashCode);
    let productionCalls = 0;
    const resumeProduction = () => runIntegratedLiveDrill({
      ...providerResumeVerification,
      environment: {
        ...productionCase.environment,
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
      },
      rootDir: fs.realpathSync(process.cwd()),
      verifyRelease: async () => postRelease,
      runComponent: async () => {
        productionCalls += 1;
        throw new Error(productionCrashCode);
      }
    });
    const first = await resumeProduction();
    assert.equal(first.state, "PROVIDER_ADMITTED");
    assert.equal(first.retryPermitted, false);
    assert.equal(productionCalls, 1);
    const second = await resumeProduction();
    assert.deepEqual(second, first);
    assert.equal(productionCalls, 1);
  }
});

test("pre-admission expiry persists a fresh-audit-authority stop and never runs", async (t) => {
  const values = components();
  const preparation = providerSupervisorPreparation();
  const privateDirectory = privateEvidenceDirectory();
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const baseEnvironment = orchestratorEnvironment(privateDirectory, launch);
  const prepareOutputs = [values.dvi, values.race, preparation];
  await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => postRelease,
    runComponent: async () => prepareOutputs.shift()
  });
  let componentCalls = 0;
  const resume = () => runIntegratedLiveDrill({
    ...providerResumeVerification,
    verifyProviderDispatchAuthorization: async () => {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED"
      );
    },
    environment: {
      ...baseEnvironment,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION: "{}",
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "RESUME"
    },
    rootDir: fs.realpathSync(process.cwd()),
    verifyRelease: async () => postRelease,
    runComponent: async () => {
      componentCalls += 1;
      return providerSupervisorCompletion(preparation);
    }
  });
  const first = await resume();
  assert.equal(first.state, "EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED");
  assert.equal(first.retryPermitted, false);
  assert.equal(componentCalls, 0);
  const second = await resume();
  assert.deepEqual(second, first);
  assert.equal(componentCalls, 0);
});

test("Gate2 preserves one exact bounded child stop code without stderr detail", (t) => {
  const directory = privateEvidenceDirectory();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const script = path.join(directory, "fail-closed-child.js");
  fs.writeFileSync(
    script,
    "process.stderr.write('INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED\\n'); process.exitCode = 1;\n",
    { mode: 0o600 }
  );
  assert.throws(
    () => integratedLiveDrillRunnerTest.defaultRunComponent(
      script,
      [],
      {},
      fs.realpathSync(process.cwd())
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED/u
  );
});

test("orchestrator rejects authorization expiry between provider components", async (t) => {
  const values = components();
  const calls = [];
  const privateDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(privateDirectory)
  );
  t.after(() => fs.rmSync(privateDirectory, { recursive: true, force: true }));
  const clockValues = [
    launch.checkedAt,
    launch.checkedAt + 1,
    launch.checkedAt + 2,
    launch.checkedAt + 3,
    launch.checkedAt + 4,
    Date.parse("2026-08-09T17:00:00.001Z")
  ];

  await assert.rejects(
    runIntegratedLiveDrill({
      clock: () => clockValues.shift(),
      environment: orchestratorEnvironment(privateDirectory, launch),
      rootDir: fs.realpathSync(process.cwd()),
      verifyRelease: async () => ({
        sourceCommit,
        treeDigest,
        packageLockDigest: spec.packageLockDigest
      }),
      runComponent: async (script) => {
        calls.push(script);
        return values.dvi;
      }
    }),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED/u
  );
  assert.equal(calls.length, 1);
  assert.match(calls[0], /gate1-admissible-vector\.js$/u);
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
