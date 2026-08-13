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
  safeIntegratedLiveDrillFailureCode,
  systemdIntegratedLiveDrillEnvironment
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
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
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
  runtimeBundleManifestSha256: "7".repeat(64),
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

function systemdOrchestratorInput(t, mode, environment) {
  const directory = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-systemd-orchestrator-input-"
  ));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const credentialPath = path.join(directory, "orchestrator-input");
  fs.writeFileSync(credentialPath, canonicalJson({
    environment,
    schemaVersion:
      integratedLiveDrillRunnerTest.SYSTEMD_ORCHESTRATOR_INPUT_SCHEMA
  }), { mode: 0o600 });
  fs.chmodSync(credentialPath, 0o600);
  return Object.freeze({
    CREDENTIALS_DIRECTORY: fs.realpathSync(directory),
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: "/usr/bin:/bin",
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY:
      mode === "PREPARE" ? "prepare-v1" : "resume-v1",
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_INSTANCE: runId
  });
}

function exactSystemdPrepareInput(privateDirectory, launch) {
  const source = orchestratorEnvironment(privateDirectory, launch);
  return Object.freeze(Object.fromEntries(
    integratedLiveDrillRunnerTest.systemdPrepareInputNames.map((name) => [
      name,
      source[name]
    ])
  ));
}

function exactSystemdResumeInput(dispatchAuthorization = "{}") {
  return Object.freeze({
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION:
      dispatchAuthorization,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: JSON.stringify(spec)
  });
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

function providerReconciliationReceipt(preparation, state = "CONSUMED") {
  return orchestrationReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
    accepted: false,
    authorizationId: preparation.authorizationId,
    controlBindingSha256: "9".repeat(64),
    databaseNow: "2026-08-10T16:01:00.000Z",
    finalReleaseReady: false,
    mcpResultSha256: null,
    providerCompletion: null,
    providerApiCredentialPresent: false,
    providerBacked: false,
    runId,
    sessionCloseSha256: null,
    state,
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: "RESOLVED"
  }));
}

function completedProviderReconciliationReceipt(preparation) {
  const completion = providerSupervisorCompletion(preparation);
  return orchestrationReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
    accepted: false,
    authorizationId: preparation.authorizationId,
    controlBindingSha256: "9".repeat(64),
    databaseNow: "2026-08-10T16:01:00.000Z",
    finalReleaseReady: false,
    mcpResultSha256: "e".repeat(64),
    providerCompletion: completion,
    providerApiCredentialPresent: false,
    providerBacked: false,
    runId,
    sessionCloseSha256: "f".repeat(64),
    state: "COMPLETED",
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: "COMPLETED"
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

test("systemd orchestrator input admits exact provider-free PREPARE and RESUME payloads", (t) => {
  const privateDirectory = privateEvidenceDirectory();
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const prepareInput = exactSystemdPrepareInput(privateDirectory, launch);
  const prepareProcess = systemdOrchestratorInput(t, "PREPARE", prepareInput);
  const prepared = systemdIntegratedLiveDrillEnvironment(prepareProcess);
  assert.equal(
    prepared.TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE,
    "PREPARE"
  );
  assert.equal(
    prepared.TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT,
    `/var/lib/prooftoact/evidence/${runId}`
  );
  assert.equal(
    prepared.TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT,
    `/var/lib/prooftoact/authorization/${runId}`
  );
  assert.equal(
    prepared.TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_REQUEST_PATH,
    `/var/lib/prooftoact/evidence/${runId}/dispatch-request.json`
  );
  for (const name of [
    "MCP_API_KEY",
    "PRIMARY_PROVIDER_CLAIM_DATABASE_URL",
    "PRIMARY_PROVIDER_BEGIN_DATABASE_URL",
    "PRIMARY_PROVIDER_FINALIZE_DATABASE_URL",
    "LD_PRELOAD",
    "PERL5OPT"
  ]) {
    assert.equal(Object.hasOwn(prepared, name), false, name);
  }

  const resumeInput = exactSystemdResumeInput();
  const resumed = systemdIntegratedLiveDrillEnvironment(
    systemdOrchestratorInput(t, "RESUME", resumeInput)
  );
  assert.equal(
    resumed.TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE,
    "RESUME"
  );
  assert.equal(
    resumed.TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION,
    "{}"
  );
  assert.deepEqual(
    Object.keys(resumeInput).sort(),
    [...integratedLiveDrillRunnerTest.systemdResumeInputNames].sort()
  );
  assert.equal(Object.hasOwn(resumed, "MCP_API_KEY"), false);
});

test("systemd orchestrator input rejects extra, missing, ambient, and substituted capability data", (t) => {
  const privateDirectory = privateEvidenceDirectory();
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
  const exact = exactSystemdPrepareInput(privateDirectory, launch);
  const first = integratedLiveDrillRunnerTest.systemdPrepareInputNames[0];
  for (const changed of [
    Object.fromEntries(Object.entries(exact).filter(([name]) => name !== first)),
    { ...exact, MCP_API_KEY: "forbidden-provider-bearer" },
    { ...exact, LD_PRELOAD: "/tmp/forbidden.so" },
    {
      ...exact,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT: "/tmp/substitute"
    }
  ]) {
    assert.throws(
      () => systemdIntegratedLiveDrillEnvironment(
        systemdOrchestratorInput(t, "PREPARE", changed)
      ),
      /INTEGRATED_LIVE_DRILL_SYSTEMD_INPUT_REJECTED/u
    );
  }
  assert.throws(
    () => systemdIntegratedLiveDrillEnvironment({
      ...systemdOrchestratorInput(t, "RESUME", exactSystemdResumeInput()),
      MCP_API_KEY: "ambient-provider-bearer"
    }),
    /INTEGRATED_LIVE_DRILL_SYSTEMD_INPUT_REJECTED/u
  );
  assert.throws(
    () => systemdIntegratedLiveDrillEnvironment({
      ...systemdOrchestratorInput(t, "PREPARE", exact),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_INSTANCE:
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    }),
    /INTEGRATED_LIVE_DRILL_SYSTEMD_INPUT_REJECTED/u
  );
});

test("PREPARE executes only DVI, authority race, and provider-free preparation", async (t) => {
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
  const environment = {
    ...orchestratorEnvironment(privateDirectory, launch),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
  };
  const calls = [];
  let releaseChecks = 0;
  const hold = await runIntegratedLiveDrill({
    clock: () => launch.checkedAt,
    environment,
    rootDir: fs.realpathSync(process.cwd()),
    verifyProviderPreparationEvidence: ({ gate1Preparation }) => ({
      gate1Preparation
    }),
    verifyRelease: async () => {
      releaseChecks += 1;
      return postRelease;
    },
    runComponent: async (script, args, childEnvironment) => {
      calls.push({ args, childEnvironment, script });
      return [values.dvi, values.race, preparation][calls.length - 1];
    }
  });
  assert.equal(
    hold.status,
    "HOLD_AWAITING_EXACT_PROVIDER_DISPATCH_AUTHORIZATION"
  );
  assert.equal(hold.accepted, false);
  assert.equal(hold.providerBacked, false);
  assert.equal(hold.finalReleaseReady, false);
  assert.equal(calls.length, 3);
  assert.equal(releaseChecks, 5);
  assert.match(calls[0].script, /gate1-admissible-vector\.js$/u);
  assert.match(calls[1].script, /gate2-authority-race\.js$/u);
  assert.match(
    calls[2].script,
    /gate1-integrated-live-drill-provider-supervisor\.js$/u
  );
  for (const { childEnvironment } of calls) {
    for (const name of [
      "MCP_API_KEY",
      "PRIMARY_PROVIDER_CLAIM_DATABASE_URL",
      "PRIMARY_PROVIDER_BEGIN_DATABASE_URL",
      "PRIMARY_PROVIDER_FINALIZE_DATABASE_URL",
      "LEAK_SENTINEL"
    ]) {
      assert.equal(Object.hasOwn(childEnvironment, name), false, name);
    }
  }
  assert.equal(
    calls[2].childEnvironment
      .TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE,
    "PREPARE"
  );
  assert.equal(
    fs.existsSync(
      environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH
    ),
    false
  );
});

test("direct non-systemd launch fails before any component or provider capability use", async (t) => {
  const privateDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(privateDirectory)
  );
  t.after(() => fs.rmSync(privateDirectory, { recursive: true, force: true }));
  let componentCalls = 0;
  await assert.rejects(
    () => runIntegratedLiveDrill({
      environment: orchestratorEnvironment(privateDirectory, launch),
      rootDir: fs.realpathSync(process.cwd()),
      runComponent: async () => {
        componentCalls += 1;
      }
    }),
    /INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED/u
  );
  assert.equal(componentCalls, 0);
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

test("an admitted-but-incomplete CLI result is a nonzero checkpoint", () => {
  assert.equal(
    integratedLiveDrillRunnerTest.integratedLiveDrillCliExitCode({
      accepted: false,
      status: "HOLD_AWAITING_GLOBAL_PROVIDER_DISPATCH"
    }),
    3
  );
  assert.equal(
    integratedLiveDrillRunnerTest.integratedLiveDrillCliExitCode({
      accepted: false,
      status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED"
    }),
    3
  );
  assert.equal(
    integratedLiveDrillRunnerTest.integratedLiveDrillCliExitCode({
      decision: "PROVIDER_COMPLETED",
      status: "PROVIDER_COMPLETED"
    }),
    0
  );
});

test("Gate2 refuses mutable source-path child execution", (t) => {
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
    /INTEGRATED_LIVE_DRILL_RUNTIME_REJECTED/u
  );
});

test("orchestrator rejects authorization expiry between provider components", async (t) => {
  const values = components();
  const calls = [];
  const privateDirectory = privateEvidenceDirectory();
  const ledgerDirectory = privateEvidenceDirectory();
  const launch = integratedLaunchEvidence(
    authorizationLedgerDirectory(ledgerDirectory)
  );
  t.after(() => {
    fs.rmSync(privateDirectory, { recursive: true, force: true });
    fs.rmSync(ledgerDirectory, { recursive: true, force: true });
  });
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
      environment: {
        ...orchestratorEnvironment(privateDirectory, launch),
        TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE: "PREPARE"
      },
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
