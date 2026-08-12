import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { canonicalJson } from "../../src/cloud/canonical-json.js";
import { committedDatabaseResult } from
  "../../src/cloud/database-commit-result.js";

import {
  INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
  INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES,
  INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillAuthorizationLedgerRootDigest,
  integratedLiveDrillAuthorizedExpectation,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillHumanAuthorizationTrustRootCommitment,
  integratedLiveDrillRunnerIdentityDigest,
  integratedLiveDrillSha256,
  signIntegratedLiveDrillEvidence
} from "../../src/cloud/integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT,
  integratedLiveDrillChildAuthorizationContext
} from "../../src/cloud/integrated-live-drill-child-authorization.js";
import {
  consumeIntegratedLiveDrillChildLaunch,
  consumeIntegratedLiveDrillRunAuthorization,
  finalizeIntegratedLiveDrillControlLedger,
  reserveIntegratedLiveDrillSpend
} from "../../src/cloud/integrated-live-drill-control-ledger.js";
import {
  integratedLiveDrillRecoveryContinuityPreCallIntent
} from "../../src/cloud/integrated-live-drill-recovery-continuity.js";
import {
  acquireIntegratedLiveDrillPrivateRootLease,
  integratedLiveDrillPrivateRootBinding,
  secureIntegratedLiveDrillPrivateRoot
} from "../../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  buildIntegratedLiveDrillProviderOrchestrationPreparation,
  persistIntegratedLiveDrillProviderOrchestrationAdmission,
  persistIntegratedLiveDrillProviderOrchestrationPreparation,
  readIntegratedLiveDrillProviderOrchestrationPreparation
} from "../../src/cloud/integrated-live-drill-provider-orchestration.js";
import {
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity,
  persistOrReuseIntegratedLiveDrillRecoveryBundle,
  selectedEvidenceBindingSha256
} from "../../src/cloud/integrated-live-drill.js";
import {
  canonicalRecoveryAttempt,
  recoveryAuditTargetIdentity,
  recoveryBrokerConfigDigest,
  recoverySourceBindingDigestFor
} from "../../src/cloud/recovery-continuity-identity.js";
import { trustedPublisherKeysDigest } from
  "../../src/cloud/recovery-publisher-trust.js";
import { createSyntheticRecoverySigner } from
  "../../scripts/lib/synthetic-recovery-signer.js";
import {
  generateSyntheticTestOnlyEd25519Key,
  syntheticTestDeploymentExpectation
} from "./synthetic-test-signing-keys.js";
import {
  persistIntegratedLiveDrillProviderSupervisorPreparation
} from "../../scripts/gate1-integrated-live-drill-provider-supervisor.js";

export const RECOVERY_CONTINUITY_FORBIDDEN_ROOT =
  fs.realpathSync(process.cwd());

function privateDirectory(prefix) {
  const guardPath = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), `${prefix}guard-`)
  );
  fs.chmodSync(guardPath, 0o700);
  const rootPath = path.join(guardPath, "root");
  fs.mkdirSync(rootPath, { mode: 0o700 });
  fs.chmodSync(rootPath, 0o700);
  return Object.freeze({
    guardPath: fs.realpathSync(guardPath),
    rootPath: fs.realpathSync(rootPath)
  });
}

function syntheticProviderOrchestrationComponents(spec) {
  const authorityEvidenceId =
    "44444444-4444-4444-8444-444444444444";
  const authoritySelectedEvidenceDigest = "d".repeat(64);
  const authorityBinding = "e".repeat(64);
  const operationId = "55555555-5555-4555-8555-555555555555";
  const requestDigest = "f".repeat(64);
  const selectedBinding = selectedEvidenceBindingSha256(
    authorityEvidenceId,
    authoritySelectedEvidenceDigest
  );
  const dvi = Object.freeze({
    schemaVersion: "tideproof.gate1.admissible-vector-proof.v2",
    status: "PASS",
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    drill: Object.freeze({
      runId: spec.runId,
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding,
      durableSelectionCommitted: true
    }),
    fixture: Object.freeze({
      requiredExclusionsBoundToSnapshot: true,
      nearestExcludedCloserThanRanked: true
    }),
    ranking: Object.freeze({
      vectorSearchUsed: true,
      exactPrefixSpansUsed: true
    }),
    cleanup: Object.freeze({
      snapshotRetired: true,
      remainingCandidateCount: 0,
      remainingExclusionCount: 0
    })
  });
  const race = Object.freeze({
    schemaVersion: "tideproof.aws-authority-race-receipt.v7",
    status: "PASS",
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    packageLockDigest: spec.packageLockDigest,
    authoritySourceDigest: spec.authoritySourceDigest,
    authorityArtifactDigest: spec.authorityArtifactDigest,
    configDigest: spec.configDigest,
    raceId: spec.raceId,
    runId: spec.runId,
    dvi: Object.freeze({
      authorityEvidenceBindingSha256: authorityBinding,
      selectedEvidenceBindingSha256: selectedBinding
    }),
    functionArnDigest: integratedLiveDrillSha256(spec.functionArn),
    functionVersion: spec.functionArn.split(":").at(-1),
    callerBinding: Object.freeze({
      bindingDigest: "4".repeat(64),
      callerIdentityDigest: "5".repeat(64),
      contextDigest: "6".repeat(64),
      expectedIdentityDigest: "5".repeat(64),
      expectedPrincipalDigest: "7".repeat(64),
      principalIdDigest: "8".repeat(64),
      principalType: "assumed-role"
    }),
    contenders: 2,
    serializableTransactions: true,
    overlappingDatabaseIntervals: true,
    distinctDatabaseSessions: true,
    distinctLogicalActions: true,
    distinctProposals: true,
    databaseInterval: Object.freeze({
      startedAt: "2026-08-06T12:00:00.000Z",
      completedAt: "2026-08-06T12:00:02.000Z"
    }),
    invocationRequestDigests: Object.freeze({
      alpha: "4".repeat(64),
      bravo: "5".repeat(64),
      changedInput: "6".repeat(64),
      proof: "7".repeat(64),
      replay: "8".repeat(64)
    }),
    awsInvokeRequestDigests: Object.freeze({
      alpha: "9".repeat(64),
      bravo: "a".repeat(64),
      changedInput: "b".repeat(64),
      proof: "c".repeat(64),
      replay: "d".repeat(64)
    }),
    providerOperations: Object.freeze({
      cloudFormationDescribeStackResourceRequests: 1,
      lambdaInvokeRequests: 5,
      stsGetCallerIdentityRequests: 1
    }),
    durableStateVerified: true,
    durableState: Object.freeze({
      receiptCount: 2,
      resourceReceiptCount: 2,
      outboxCount: 1,
      protectedEffectCount: 0,
      holderOperationId: operationId,
      outboxOperationId: operationId,
      denialObservedHolderOperationId: operationId,
      denialObservedFence: "1"
    }),
    protectedEffectExecuted: false,
    authorityTransferredByModel: false,
    winner: Object.freeze({
      contender: "alpha",
      operationId,
      requestDigest,
      fencingToken: "1"
    }),
    denial: Object.freeze({
      contender: "bravo",
      operationId: "66666666-6666-4666-8666-666666666666",
      requestDigest: "e".repeat(64),
      reason: "active_holder"
    }),
    replay: Object.freeze({
      contender: "alpha",
      operationId,
      requestDigest,
      outcome: "resource_reserved",
      fencingToken: "1",
      replayKind: "operation_replay",
      exactDecisionReturned: true
    }),
    changedInputDenial: Object.freeze({
      contender: "alpha",
      operationId,
      changedRequestDigest: "0".repeat(64),
      code: "OPERATION_DIGEST_MISMATCH",
      denied: true
    })
  });
  return Object.freeze({
    authorityEvidenceId,
    authoritySelectedEvidenceDigest,
    dvi,
    race
  });
}

export function persistFixtureProviderOrchestrationAdmission(t, {
  context,
  dispatchAuthorization,
  dispatchPreparation,
  gate1Preparation = null
}) {
  const {
    providerDispatchAuthorization: _providerDispatchAuthorization,
    ...preparationContext
  } = context;
  const spec = preparationContext.trustedRunContext.spec;
  const acceptedGate1Preparation = gate1Preparation ??
    persistIntegratedLiveDrillProviderSupervisorPreparation({
      context: preparationContext,
      contextPath: path.join(
        preparationContext.recoveryEvidenceRootPath,
        `${spec.runId}.provider-supervisor-context.json`
      ),
      expiresAt: dispatchPreparation.signingPayload.expiresAt,
      forbiddenRootPath: preparationContext.forbiddenRootPath,
      issuedAt: dispatchPreparation.signingPayload.issuedAt,
      rootPath: preparationContext.recoveryEvidenceRootPath
    });
  if (
    canonicalJson(acceptedGate1Preparation.signingPayload) !==
      canonicalJson(dispatchPreparation.signingPayload)
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_TEST_ORCHESTRATION_PREPARATION_REJECTED"
    );
  }
  const evidenceRootLease = acquireIntegratedLiveDrillPrivateRootLease({
    binding: preparationContext.evidenceRootBinding,
    forbiddenRootPath: preparationContext.forbiddenRootPath,
    rootPath: preparationContext.recoveryEvidenceRootPath
  });
  const decisionRootLease = acquireIntegratedLiveDrillPrivateRootLease({
    forbiddenRootPath: preparationContext.forbiddenRootPath,
    rootPath: preparationContext.ledgerRootPath
  });
  t.after(() => {
    decisionRootLease.release();
    evidenceRootLease.release();
  });
  const decisionPath = path.join(
    preparationContext.ledgerRootPath,
    `${preparationContext.preCallIntent.runId}.provider-orchestration-decision.json`
  );
  const checkpointPath = path.join(
    preparationContext.recoveryEvidenceRootPath,
    `${spec.runId}.provider-orchestration-preparation.json`
  );
  const components = syntheticProviderOrchestrationComponents(spec);
  const builtPreparation =
    buildIntegratedLiveDrillProviderOrchestrationPreparation({
      ...components,
      decisionPathSha256: integratedLiveDrillCanonicalSha256(decisionPath),
      decisionRootBinding: decisionRootLease.binding,
      decisionRootPathSha256: integratedLiveDrillCanonicalSha256(
        preparationContext.ledgerRootPath
      ),
      evidenceRootBinding: evidenceRootLease.binding,
      gate1Preparation: acceptedGate1Preparation,
      journalIntentBindingSha256: integratedLiveDrillCanonicalSha256(
        "synthetic-provider-orchestration-journal-intent"
      ),
      journalPathSha256: integratedLiveDrillCanonicalSha256(
        "synthetic-provider-orchestration-journal-path"
      ),
      spec
    });
  persistIntegratedLiveDrillProviderOrchestrationPreparation({
    checkpointPath,
    forbiddenRootPath: preparationContext.forbiddenRootPath,
    preparation: builtPreparation,
    rootPath: preparationContext.recoveryEvidenceRootPath,
    spec
  });
  const checkpoint = readIntegratedLiveDrillProviderOrchestrationPreparation({
    checkpointPath,
    forbiddenRootPath: preparationContext.forbiddenRootPath,
    rootPath: preparationContext.recoveryEvidenceRootPath,
    spec
  });
  const admission = persistIntegratedLiveDrillProviderOrchestrationAdmission({
    decisionPath,
    dispatchAuthorizationSha256:
      integratedLiveDrillCanonicalSha256(dispatchAuthorization),
    forbiddenRootPath: preparationContext.forbiddenRootPath,
    persistence: checkpoint.persistence,
    preparation: checkpoint.preparation,
    rootPath: preparationContext.ledgerRootPath
  });
  return Object.freeze({
    admission,
    checkpoint,
    decisionRootLease,
    evidenceRootLease,
    gate1Preparation: acceptedGate1Preparation
  });
}

export function createRecoveryContinuityFixture(
  t,
  {
    prefix = "prooftoact-provider-continuity-",
    fakeDelayMs = 0,
    expiresAfterMs = 60 * 60 * 1_000,
    auditStartOffsetMs = 0,
    subjectBindingSha256 = "b".repeat(64)
  } = {}
) {
  const ledgerDirectory = privateDirectory(`${prefix}ledger-`);
  const recoveryEvidenceDirectory = privateDirectory(`${prefix}evidence-`);
  const ledgerRootPath = ledgerDirectory.rootPath;
  const recoveryEvidenceRootPath = recoveryEvidenceDirectory.rootPath;
  t.after(() => {
    fs.rmSync(ledgerDirectory.guardPath, { recursive: true, force: true });
    fs.rmSync(recoveryEvidenceDirectory.guardPath, {
      recursive: true,
      force: true
    });
  });
  const now = Date.now();
  const issuedAt = new Date(now - 2_000).toISOString();
  const expiresAt = new Date(now + expiresAfterMs).toISOString();
  const runnerIdentity = "synthetic-provider-continuity-runner";
  const pre = generateSyntheticTestOnlyEd25519Key();
  const post = generateSyntheticTestOnlyEd25519Key();
  const alternateDenial = generateSyntheticTestOnlyEd25519Key();
  const human = generateSyntheticTestOnlyEd25519Key();
  const childLaunch = generateSyntheticTestOnlyEd25519Key();
  const evidenceKeys = Object.fromEntries(
    INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name) => [
      name,
      generateSyntheticTestOnlyEd25519Key()
    ])
  );
  const humanAuthorizationTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
    authorityId: "PROOFTOACT_OWNER",
    custody: "HUMAN_CONTROLLED_OFFLINE",
    ...human.publicKey
  });
  const recoverySigner = createSyntheticRecoverySigner();
  const trustedPublisherKeys = Object.freeze({
    [recoverySigner.publisherKeyId]: recoverySigner.publicKeySpkiBase64
  });
  const committedTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
    trustRootCommitment: "4".repeat(64),
    publisherKeySetDigest: trustedPublisherKeysDigest(trustedPublisherKeys),
    trustedPublisherKeys
  });
  const expectationTemplate = syntheticTestDeploymentExpectation({
    alternateDenialPublicKey:
      alternateDenial.publicKey.publicKeySpkiDerBase64,
    postPublicKey: post.publicKey.publicKeySpkiDerBase64,
    prePublicKey: pre.publicKey.publicKeySpkiDerBase64
  });
  const specWithoutIdentity = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
    sourceCommit: expectationTemplate.sourceCommit,
    treeDigest: expectationTemplate.treeDigest,
    configDigest: expectationTemplate.configDigest,
    packageLockDigest: "d".repeat(64),
    authoritySourceDigest: "e".repeat(64),
    authorityArtifactDigest: "f".repeat(64),
    runtimeBundleManifestSha256: "6".repeat(64),
    functionArn: expectationTemplate.functions.authority.numericVersionArn,
    raceId: "11111111-1111-4111-8111-111111111111",
    runId: "22222222-2222-4222-8222-222222222222",
    maximumAwsCostUsd: "0.02"
  });
  const spec = Object.freeze({
    ...specWithoutIdentity,
    sourceBuildIdentity: integratedSourceBuildIdentity(specWithoutIdentity)
  });
  const authorizationPayload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
    authorizationLedgerRootSha256:
      integratedLiveDrillAuthorizationLedgerRootDigest(ledgerRootPath),
    authorizationClaimAuthority: Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
      authorizationLedgerRootSha256:
        integratedLiveDrillAuthorizationLedgerRootDigest(ledgerRootPath),
      crossHostStrongConsistencyProven: false,
      durabilityScope: "SINGLE_AUTHORITATIVE_LEDGER_ROOT",
      runnerIdentitySha256:
        integratedLiveDrillRunnerIdentityDigest(runnerIdentity)
    }),
    authorityNumericVersionArnSha256: integratedLiveDrillSha256(
      spec.functionArn
    ),
    authorizationId: "33333333-3333-4333-8333-333333333333",
    childLaunchPublicKey: childLaunch.publicKey,
    configDigest: spec.configDigest,
    evidencePublicKeys: Object.fromEntries(
      Object.entries(evidenceKeys).map(([name, key]) => [name, key.publicKey])
    ),
    expectationSha256: integratedLiveDrillCanonicalSha256(
      integratedLiveDrillAuthorizedExpectation(expectationTemplate)
    ),
    expiresAt,
    humanAuthorizationTrustRootCommitment:
      integratedLiveDrillHumanAuthorizationTrustRootCommitment(
        humanAuthorizationTrustRoot
      ),
    issuedAt,
    maximumAwsCostUsd: "0.020000",
    maximumRecoverySourceAgeSeconds: 3600,
    publisherKeySetDigest: committedTrustRoot.publisherKeySetDigest,
    recoveryPublisherTrustRootCommitment:
      committedTrustRoot.trustRootCommitment,
    requiredManagedMcpToolCallCount: 1,
    requiredRecoveryFailpoints: INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
    requiredRecoveryJournalEntryCount: 17,
    requiredRecoveryWorkers: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
    runId: spec.runId,
    sourceCommit: spec.sourceCommit,
    specSha256: integratedLiveDrillCanonicalSha256(spec),
    spendAuthorization: Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
      currency: "USD",
      maximumCumulativeExposureUsd: "0.020000",
      scopes: INTEGRATED_LIVE_DRILL_SPEND_SCOPES.map((scope, index) =>
        Object.freeze({
          ...scope,
          maximumExposureUsd: index === 1 ? "0.020000" : "0.000000"
        })
      )
    }),
    treeDigest: spec.treeDigest
  });
  const attestation = signIntegratedLiveDrillEvidence(
    authorizationPayload,
    human.privateKeyPkcs8DerBase64,
    human.publicKey
  );
  const expectation = Object.freeze({
    ...expectationTemplate,
    integratedLiveDrillAuthorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(attestation)
  });
  const consumed = consumeIntegratedLiveDrillRunAuthorization(attestation, {
    spec,
    expectation,
    committedTrustRoot,
    humanAuthorizationTrustRoot,
    ledgerRootPath,
    forbiddenRootPath: RECOVERY_CONTINUITY_FORBIDDEN_ROOT,
    now
  });
  const controlArgs = Object.freeze({
    authorization: consumed.authorization,
    claim: consumed.claim,
    ledgerRootPath,
    forbiddenRootPath: RECOVERY_CONTINUITY_FORBIDDEN_ROOT
  });
  const reservations = [];
  const launches = [];
  let consumedChildAuthorization;
  for (const [index, scope] of INTEGRATED_LIVE_DRILL_SPEND_SCOPES.entries()) {
    const stepNow = now + index + 1;
    const reservation = reserveIntegratedLiveDrillSpend({
      ...controlArgs,
      scopeId: scope.scopeId,
      now: stepNow
    });
    const tokenId = `00000000-0000-4000-8000-00000000000${index + 1}`;
    if (scope.scopeId === "MANAGED_MCP_RECOVERY") {
      consumedChildAuthorization = Object.freeze({
        attestation: integratedLiveDrillChildAuthorizationContext({
          authorization: consumed.authorization,
          claim: consumed.claim,
          expectation,
          privateKeyPkcs8DerBase64: childLaunch.privateKeyPkcs8DerBase64,
          reservation,
          spec,
          now: stepNow,
          tokenId
        })
      });
    }
    reservations.push(reservation);
    launches.push(consumeIntegratedLiveDrillChildLaunch({
      ...controlArgs,
      reservation,
      tokenId,
      now: stepNow
    }));
  }
  const controlLedgerReceipt = finalizeIntegratedLiveDrillControlLedger({
    ...controlArgs,
    reservations
  });
  const sourceRecordedAt = new Date(now - 1_000).toISOString();
  const recoverySourceReceipt = Object.freeze({
    admissibility: "admissible",
    authorization_binding_sha256: "1".repeat(64),
    authorization_epoch: 1,
    authority_evidence_binding_sha256: "2".repeat(64),
    evidence_digest: "3".repeat(64),
    evidence_id: "44444444-4444-4444-8444-444444444444",
    has_durable_intent: true,
    incident_id: "55555555-5555-4555-8555-555555555555",
    logical_action_digest: "6".repeat(64),
    logical_authority_key_sha256: "7".repeat(64),
    operation_id: "66666666-6666-4666-8666-666666666666",
    outcome: "resource_reserved",
    proposal_digest: "8".repeat(64),
    recorded_at: sourceRecordedAt,
    request_digest: "9".repeat(64),
    resource_id: "synthetic-provider-continuity-resource",
    run_id: spec.runId,
    selected_evidence_binding_sha256: "a".repeat(64),
    tenant_id: "77777777-7777-4777-8777-777777777777"
  });
  const sourceDigest = recoverySourceBindingDigestFor({
    tenantId: recoverySourceReceipt.tenant_id,
    runId: recoverySourceReceipt.run_id,
    incidentId: recoverySourceReceipt.incident_id,
    evidenceDigest: recoverySourceReceipt.evidence_digest,
    resourceId: recoverySourceReceipt.resource_id,
    operationId: recoverySourceReceipt.operation_id,
    requestDigest: recoverySourceReceipt.request_digest,
    proposalDigest: recoverySourceReceipt.proposal_digest,
    logicalActionDigest: recoverySourceReceipt.logical_action_digest,
    authorizationEpoch: recoverySourceReceipt.authorization_epoch,
    logicalAuthorityKeySha256:
      recoverySourceReceipt.logical_authority_key_sha256,
    authorizationBindingSha256:
      recoverySourceReceipt.authorization_binding_sha256,
    authorityEvidenceBindingSha256:
      recoverySourceReceipt.authority_evidence_binding_sha256,
    selectedEvidenceBindingSha256:
      recoverySourceReceipt.selected_evidence_binding_sha256,
    outcome: recoverySourceReceipt.outcome
  });
  const attempt = canonicalRecoveryAttempt({
    tenantId: recoverySourceReceipt.tenant_id,
    subjectBindingHash: subjectBindingSha256,
    sourceDigest,
    sourceCommitTs: sourceRecordedAt
  });
  const recoveryBinding = Object.freeze({
    recoveryClusterId: "88888888-8888-4888-8888-888888888888",
    recoverySessionId: attempt.recoverySessionId,
    subjectBindingSha256,
    tenantId: recoverySourceReceipt.tenant_id
  });
  const expectedSourceClusterId =
    "77777777-7777-4777-8777-777777777777";
  const unsignedBundle = Object.freeze({
    tenantId: recoveryBinding.tenantId,
    recoverySessionId: recoveryBinding.recoverySessionId,
    subjectBindingHash: recoveryBinding.subjectBindingSha256,
    schemaVersion: 2,
    snapshotVersion: attempt.snapshotVersion,
    sourceClusterId: expectedSourceClusterId,
    sourceCommitTs: attempt.sourceCommitTs,
    sourceDigest,
    policyVersion: "gate1-policy-v2",
    checkpointSummary: Object.freeze({
      checkpointVersion: 1,
      failedAgent: "synthetic-agent-a",
      phase: "successor-context-recovery",
      scenario: "synthetic-highwater"
    }),
    evidenceSummary: Object.freeze({
      admittedCount: 1,
      classification: "synthetic",
      evidenceDigest: recoverySourceReceipt.evidence_digest
    }),
    conflictSummary: Object.freeze({ status: "none", unresolvedCount: 0 }),
    receiptSummary: Object.freeze({
      durableIntentPresent: true,
      outcome: "resource_reserved",
      reason: null,
      resourceLabel: recoverySourceReceipt.resource_id
    }),
    expiresAt: attempt.expiresAt
  });
  const signedBundlePath = path.join(
    recoveryEvidenceRootPath,
    `${spec.runId}.signed-recovery-bundle.json`
  );
  const persistedBundle = persistOrReuseIntegratedLiveDrillRecoveryBundle({
    destinationPath: signedBundlePath,
    evidenceRootPath: recoveryEvidenceRootPath,
    forbiddenRootPath: RECOVERY_CONTINUITY_FORBIDDEN_ROOT,
    spec,
    signedBundle: recoverySigner.sign(unsignedBundle),
    trustedPublisherKeys
  });
  const recoveryPublicationReceipt = (outcome, offsetMs) => Object.freeze({
    outcome,
    bundleDigest: persistedBundle.bundle.bundleDigest,
    commit: committedDatabaseResult({
      operation: "recovery_publication",
      operationDigest: persistedBundle.bundle.bundleDigest,
      observation: "direct_ack",
      databaseNow: new Date(now + offsetMs).toISOString(),
      outcome: "bundle_present",
      authorityCurrent: null,
      requiresFreshAuthorization: true
    })
  });
  const recoveryAppendReceipt = recoveryPublicationReceipt(
    "bundle_appended",
    10
  );
  const recoveryReplayReceipt = recoveryPublicationReceipt(
    "bundle_replay",
    20
  );
  const audit = Object.freeze({
    interactionId: "99999999-9999-4999-8999-999999999999",
    preReadAuditEventId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    startedAt: new Date(now + auditStartOffsetMs).toISOString(),
    terminalAuditEventId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
  });
  const recoveryBrokerConfiguration = Object.freeze({
    auditTargetIdentity: recoveryAuditTargetIdentity({
      connectionString: "postgresql://audit.invalid/tideproof",
      primaryClusterId: expectedSourceClusterId
    }),
    expectedSourceClusterId,
    recoveryBrokerConfigDigest: recoveryBrokerConfigDigest({
      recoveryClusterId: recoveryBinding.recoveryClusterId,
      expectedSourceClusterId,
      buildIdentity: spec.sourceBuildIdentity,
      trustedPublisherKeys,
      auditTargetIdentity: recoveryAuditTargetIdentity({
        connectionString: "postgresql://audit.invalid/tideproof",
        primaryClusterId: expectedSourceClusterId
      })
    }),
    recoveryClusterId: recoveryBinding.recoveryClusterId
  });
  const trustedRunContext = Object.freeze({
    committedTrustRoot,
    expectation,
    humanAuthorizationTrustRoot,
    recoveryBrokerConfiguration,
    runnerIdentity,
    spec
  });
  const preCallInputs = Object.freeze({
    audit,
    claim: consumed.claim,
    consumedChildAuthorization,
    consumedManagedMcpLaunch: launches[2],
    controlLedgerReceipt,
    managedMcpReservation: reservations[2],
    recoveryBinding,
    recoveryAppendReceipt,
    recoveryReplayReceipt,
    recoverySourceReceipt,
    signedBundlePersistenceReceipt: persistedBundle.receipt
  });
  const preCallIntent = integratedLiveDrillRecoveryContinuityPreCallIntent({
    ...preCallInputs,
    authorization: consumed.authorization,
    ledgerRootPath,
    forbiddenRootPath: RECOVERY_CONTINUITY_FORBIDDEN_ROOT,
    recoveryEvidenceRootPath,
    trustedRunContext,
    now: now + 30
  });
  const context = Object.freeze({
    authorization: consumed.authorization,
    controlLedgerReceipt,
    evidenceRootBinding: integratedLiveDrillPrivateRootBinding(
      secureIntegratedLiveDrillPrivateRoot(
        recoveryEvidenceRootPath,
        RECOVERY_CONTINUITY_FORBIDDEN_ROOT
      )
    ),
    forbiddenRootPath: RECOVERY_CONTINUITY_FORBIDDEN_ROOT,
    ledgerRootPath,
    preCallInputs,
    preCallIntent,
    recoveryEvidenceRootPath,
    trustedRunContext
  });
  const childEnvironment = Object.freeze({
    [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]:
      canonicalJson(consumedChildAuthorization.attestation),
    [INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT]:
      canonicalJson(committedTrustRoot),
    TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION: canonicalJson(expectation),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT:
      ledgerRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT:
      canonicalJson(humanAuthorizationTrustRoot),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION:
      canonicalJson(attestation),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY: runnerIdentity,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: canonicalJson(spec)
  });
  const value = Object.freeze({
    context,
    counterPath: path.join(ledgerRootPath, "fake-mcp-call-count.txt"),
    fakeDelayMs,
    logicalMcpRequestSha256: preCallIntent.logicalMcpRequestSha256,
    now: now + 100
  });
  const fixturePath = path.join(ledgerRootPath, "worker-fixture.json");
  fs.writeFileSync(fixturePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  return Object.freeze({
    ...value,
    fixturePath,
    persistedBundle,
    signedBundlePath,
    testOnly: Object.freeze({
      childLaunch,
      childEnvironment,
      human,
      now,
      recoverySigner
    })
  });
}
