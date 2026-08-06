import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";
import { canonicalRecoveryAttempt } from "./recovery-broker.js";

export const INTEGRATED_LIVE_DRILL_SCHEMA =
  "tideproof.highwater-drill-live.v1";
export const INTEGRATED_LIVE_DRILL_SPEC_SCHEMA =
  "tideproof.highwater-drill-live-spec.v1";

const SHA256 = /^[0-9a-f]{64}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

export function parseIntegratedLiveDrillSpec(value) {
  if (
    !exactKeys(value, [
      "authorityArtifactDigest",
      "authoritySourceDigest",
      "configDigest",
      "functionArn",
      "maximumAwsCostUsd",
      "packageLockDigest",
      "raceId",
      "runId",
      "schemaVersion",
      "sourceBuildIdentity",
      "sourceCommit",
      "treeDigest"
    ]) ||
    value.schemaVersion !== INTEGRATED_LIVE_DRILL_SPEC_SCHEMA ||
    !SHA256.test(value.configDigest) ||
    !SHA256.test(value.packageLockDigest) ||
    !SHA256.test(value.authoritySourceDigest) ||
    !SHA256.test(value.authorityArtifactDigest) ||
    !SHA1.test(value.sourceCommit) ||
    !SHA1.test(value.treeDigest) ||
    !UUID.test(value.raceId) ||
    !UUID.test(value.runId) ||
    !SHA256.test(value.sourceBuildIdentity ?? "") ||
    value.maximumAwsCostUsd !== "0.02" ||
    !/^arn:aws[a-zA-Z-]*:lambda:us-east-1:\d{12}:function:[A-Za-z0-9-_]{1,64}:[1-9][0-9]*$/.test(
      value.functionArn
    ) ||
    value.sourceBuildIdentity !== integratedSourceBuildIdentity(value)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_SPEC_REJECTED");
  }
  return Object.freeze({ ...value });
}

export function integratedSourceBuildIdentity(value) {
  return sha256(canonicalJson({
    schemaVersion: "tideproof.integrated-source-build-identity.v1",
    sourceCommit: value?.sourceCommit,
    treeDigest: value?.treeDigest,
    configDigest: value?.configDigest,
    packageLockDigest: value?.packageLockDigest,
    authoritySourceDigest: value?.authoritySourceDigest,
    authorityArtifactDigest: value?.authorityArtifactDigest,
    functionArn: value?.functionArn
  }));
}

export function selectedEvidenceBindingSha256(evidenceId, evidenceDigest) {
  if (!UUID.test(evidenceId ?? "") || !SHA256.test(evidenceDigest ?? "")) {
    throw new Error("INTEGRATED_LIVE_DRILL_EVIDENCE_REJECTED");
  }
  return sha256(canonicalJson({ evidenceId, evidenceDigest }));
}

function acceptedDvi(dvi, spec, selectedBinding) {
  return (
    dvi?.schemaVersion === "tideproof.gate1.admissible-vector-proof.v2" &&
    dvi.status === "PASS" &&
    dvi.sourceCommit === spec.sourceCommit &&
    dvi.treeDigest === spec.treeDigest &&
    dvi.drill?.runId === spec.runId &&
    SHA256.test(dvi.drill?.authorityEvidenceBindingSha256 ?? "") &&
    dvi.drill?.selectedEvidenceBindingSha256 === selectedBinding &&
    dvi.drill?.durableSelectionCommitted === true &&
    dvi.fixture?.requiredExclusionsBoundToSnapshot === true &&
    dvi.fixture?.nearestExcludedCloserThanRanked === true &&
    dvi.ranking?.vectorSearchUsed === true &&
    dvi.ranking?.exactPrefixSpansUsed === true &&
    dvi.cleanup?.snapshotRetired === true &&
    dvi.cleanup?.remainingCandidateCount === 0 &&
    dvi.cleanup?.remainingExclusionCount === 0
  );
}

function acceptedRace(race, spec, dvi) {
  const functionVersion = spec.functionArn.split(":").at(-1);
  const invocationKeys = [
    "alpha",
    "bravo",
    "changedInput",
    "proof",
    "replay"
  ];
  const invocationDigests = race?.invocationRequestDigests;
  const awsInvocationDigests = race?.awsInvokeRequestDigests;
  const digestMapAccepted = (value) =>
    exactKeys(value, invocationKeys) &&
    Object.values(value).every((entry) => SHA256.test(entry ?? "")) &&
    new Set(Object.values(value)).size === invocationKeys.length;
  const caller = race?.callerBinding;
  const intervalStart = Date.parse(race?.databaseInterval?.startedAt);
  const intervalEnd = Date.parse(race?.databaseInterval?.completedAt);
  return (
    race?.schemaVersion === "tideproof.aws-authority-race-receipt.v7" &&
    race.status === "PASS" &&
    race.sourceCommit === spec.sourceCommit &&
    race.treeDigest === spec.treeDigest &&
    race.treeDigest === dvi.treeDigest &&
    race.packageLockDigest === spec.packageLockDigest &&
    race.authoritySourceDigest === spec.authoritySourceDigest &&
    race.authorityArtifactDigest === spec.authorityArtifactDigest &&
    race.configDigest === spec.configDigest &&
    race.raceId === spec.raceId &&
    race.runId === spec.runId &&
    race.functionArnDigest === sha256(spec.functionArn) &&
    race.functionVersion === functionVersion &&
    exactKeys(caller, [
      "bindingDigest",
      "callerIdentityDigest",
      "contextDigest",
      "expectedIdentityDigest",
      "expectedPrincipalDigest",
      "principalType"
    ]) &&
    caller.principalType === "assumed-role" &&
    caller.expectedIdentityDigest === caller.callerIdentityDigest &&
    [
      caller.bindingDigest,
      caller.callerIdentityDigest,
      caller.contextDigest,
      caller.expectedIdentityDigest,
      caller.expectedPrincipalDigest
    ].every((entry) => SHA256.test(entry ?? "")) &&
    race.dvi?.authorityEvidenceBindingSha256 ===
      dvi.drill.authorityEvidenceBindingSha256 &&
    race.dvi?.selectedEvidenceBindingSha256 ===
      dvi.drill.selectedEvidenceBindingSha256 &&
    race.contenders === 2 &&
    race.serializableTransactions === true &&
    race.overlappingDatabaseIntervals === true &&
    race.distinctDatabaseSessions === true &&
    race.distinctLogicalActions === true &&
    race.distinctProposals === true &&
    Number.isFinite(intervalStart) &&
    Number.isFinite(intervalEnd) &&
    intervalStart < intervalEnd &&
    digestMapAccepted(invocationDigests) &&
    digestMapAccepted(awsInvocationDigests) &&
    race.providerOperations?.lambdaInvocations === 5 &&
    race.durableStateVerified === true &&
    race.durableState?.receiptCount === 2 &&
    race.durableState?.resourceReceiptCount === 2 &&
    race.durableState?.outboxCount === 1 &&
    race.durableState?.protectedEffectCount === 0 &&
    race.durableState?.holderOperationId === race.winner?.operationId &&
    race.durableState?.outboxOperationId === race.winner?.operationId &&
    race.durableState?.denialObservedHolderOperationId ===
      race.winner?.operationId &&
    race.durableState?.denialObservedFence ===
      race.winner?.fencingToken &&
    race.protectedEffectExecuted === false &&
    race.authorityTransferredByModel === false &&
    ["alpha", "bravo"].includes(race.winner?.contender) &&
    ["alpha", "bravo"].includes(race.denial?.contender) &&
    race.winner?.contender !== race.denial?.contender &&
    UUID.test(race.winner?.operationId ?? "") &&
    SHA256.test(race.winner?.requestDigest ?? "") &&
    race.winner?.fencingToken === "1" &&
    UUID.test(race.denial?.operationId ?? "") &&
    SHA256.test(race.denial?.requestDigest ?? "") &&
    race.denial?.reason === "active_holder" &&
    race.replay?.contender === race.winner?.contender &&
    race.replay?.operationId === race.winner?.operationId &&
    race.replay?.requestDigest === race.winner?.requestDigest &&
    race.replay?.outcome === "resource_reserved" &&
    race.replay?.fencingToken === race.winner?.fencingToken &&
    race.replay?.replayKind === "operation_replay" &&
    race.replay?.exactDecisionReturned === true &&
    race.changedInputDenial?.contender === race.winner?.contender &&
    race.changedInputDenial?.operationId === race.winner?.operationId &&
    SHA256.test(race.changedInputDenial?.changedRequestDigest ?? "") &&
    race.changedInputDenial?.changedRequestDigest !==
      race.winner?.requestDigest &&
    race.changedInputDenial?.code === "OPERATION_DIGEST_MISMATCH" &&
    race.changedInputDenial?.denied === true
  );
}

function acceptedRecovery(recovery, spec, race) {
  const denials = recovery?.runnerCredentialDenials;
  const provider = recovery?.mcpProviderEvidence;
  const rpcCalls = provider?.rpcCalls;
  const notifications = provider?.notifications;
  const close = provider?.close;
  const expectedWinnerBinding = sha256(canonicalJson({
    operationId: race?.winner?.operationId,
    requestDigest: race?.winner?.requestDigest
  }));
  let expectedCanonicalRecovery = null;
  try {
    expectedCanonicalRecovery = canonicalRecoveryAttempt({
      tenantId: recovery?.tenantId,
      subjectBindingHash: recovery?.callerSubjectBindingSha256,
      sourceDigest: recovery?.sourceDigest,
      sourceCommitTs: recovery?.canonicalRecovery?.sourceCommitTs
    });
  } catch {
    return false;
  }
  return (
    recovery?.gate ===
      "noninteractive Managed MCP deterministic recovery broker" &&
    recovery.passed === true &&
    recovery.sourceBuildIdentity === spec.sourceBuildIdentity &&
    recovery.recoverySessionId ===
      expectedCanonicalRecovery.recoverySessionId &&
    exactKeys(recovery.canonicalRecovery, [
      "bindingSha256",
      "bundleDigest",
      "expiresAt",
      "recoverySessionId",
      "replayMatched",
      "snapshotVersion",
      "sourceCommitTs"
    ]) &&
    recovery.canonicalRecovery.recoverySessionId ===
      expectedCanonicalRecovery.recoverySessionId &&
    recovery.canonicalRecovery.snapshotVersion ===
      expectedCanonicalRecovery.snapshotVersion &&
    recovery.canonicalRecovery.sourceCommitTs ===
      expectedCanonicalRecovery.sourceCommitTs &&
    recovery.canonicalRecovery.expiresAt ===
      expectedCanonicalRecovery.expiresAt &&
    recovery.canonicalRecovery.bindingSha256 ===
      expectedCanonicalRecovery.bindingSha256 &&
    recovery.canonicalRecovery.bundleDigest === recovery.bundleDigest &&
    recovery.canonicalRecovery.replayMatched === true &&
    recovery.winnerOperationBindingSha256 === expectedWinnerBinding &&
    recovery.dvi?.authorityEvidenceBindingSha256 ===
      race.dvi.authorityEvidenceBindingSha256 &&
    recovery.dvi?.selectedEvidenceBindingSha256 ===
      race.dvi.selectedEvidenceBindingSha256 &&
    recovery.endpointSeparation?.distinctHostnames === true &&
    recovery.endpointSeparation?.distinctClusterIds === true &&
    recovery.replayOutcome === "bundle_replay" &&
    recovery.mcpTool === "select_query" &&
    recovery.mcpCallCount === 1 &&
    provider?.schemaVersion ===
      "tideproof.managed-mcp-transport-evidence.v2" &&
    SHA256.test(provider.endpointSha256 ?? "") &&
    provider.endpointAuthority === "cockroachlabs.cloud" &&
    SHA256.test(provider.clusterIdSha256 ?? "") &&
    SHA256.test(provider.sessionIdSha256 ?? "") &&
    provider.protocolVersion === "2025-03-26" &&
    provider.redirectPolicy === "error" &&
    provider.boundedResponseBytes === 256 * 1024 &&
    Array.isArray(notifications) &&
    notifications.length === 1 &&
    exactKeys(notifications[0], [
      "httpStatus",
      "method",
      "outboundSessionIdSha256",
      "requestBytes",
      "requestPayloadSha256",
      "responseSessionIdSha256",
      "sessionContinuous"
    ]) &&
    notifications[0].method === "notifications/initialized" &&
    [200, 202].includes(notifications[0].httpStatus) &&
    Number.isSafeInteger(notifications[0].requestBytes) &&
    notifications[0].requestBytes > 0 &&
    SHA256.test(notifications[0].requestPayloadSha256 ?? "") &&
    notifications[0].outboundSessionIdSha256 ===
      provider.sessionIdSha256 &&
    (notifications[0].responseSessionIdSha256 === null ||
      notifications[0].responseSessionIdSha256 ===
        provider.sessionIdSha256) &&
    notifications[0].sessionContinuous === true &&
    exactKeys(close, [
      "attempted",
      "httpStatus",
      "outboundSessionIdSha256",
      "responseSessionIdSha256",
      "sessionContinuous"
    ]) &&
    close.attempted === true &&
    Number.isInteger(close.httpStatus) &&
    close.httpStatus >= 200 &&
    close.httpStatus < 300 &&
    close.outboundSessionIdSha256 === provider.sessionIdSha256 &&
    (close.responseSessionIdSha256 === null ||
      close.responseSessionIdSha256 === provider.sessionIdSha256) &&
    close.sessionContinuous === true &&
    Array.isArray(rpcCalls) &&
    rpcCalls.length === 2 &&
    rpcCalls[0]?.method === "initialize" &&
    rpcCalls[1]?.method === "tools/call" &&
    rpcCalls.every((call) =>
      exactKeys(call, [
        "contentType",
        "httpStatus",
        "method",
        "outboundSessionIdSha256",
        "requestBytes",
        "requestIdSha256",
        "requestPayloadSha256",
        "responseBytes",
        "responseCorrelated",
        "responseIdSha256",
        "responsePayloadSha256",
        "responseSessionIdSha256",
        "resultSha256",
        "sessionContinuous",
        "sessionIdSha256"
      ]) &&
      call.httpStatus === 200 &&
      call.responseCorrelated === true &&
      call.requestIdSha256 === call.responseIdSha256 &&
      SHA256.test(call.requestIdSha256 ?? "") &&
      SHA256.test(call.requestPayloadSha256 ?? "") &&
      SHA256.test(call.responsePayloadSha256 ?? "") &&
      SHA256.test(call.resultSha256 ?? "") &&
      call.sessionIdSha256 === provider.sessionIdSha256 &&
      Number.isSafeInteger(call.requestBytes) &&
      call.requestBytes > 0 &&
      Number.isSafeInteger(call.responseBytes) &&
      call.responseBytes > 0 &&
      call.sessionContinuous === true &&
      ["application/json", "text/event-stream"].includes(call.contentType)
    ) &&
    rpcCalls[0].outboundSessionIdSha256 === null &&
    rpcCalls[0].responseSessionIdSha256 === provider.sessionIdSha256 &&
    rpcCalls[1].outboundSessionIdSha256 === provider.sessionIdSha256 &&
    (rpcCalls[1].responseSessionIdSha256 === null ||
      rpcCalls[1].responseSessionIdSha256 ===
        provider.sessionIdSha256) &&
    rpcCalls[1].resultSha256 === recovery.mcpResultSha256 &&
    recovery.recoveryStatus === "RECOVERED_CONTEXT_ONLY" &&
    recovery.unauthorizedStatus === "UNKNOWN_DO_NOT_ACT" &&
    recovery.preReadAuditCommitted === true &&
    recovery.terminalAuditCommitted === true &&
    recovery.authorityTransferred === false &&
    recovery.requiresFreshAuthorization === true &&
    recovery.operationalCapabilitiesReturned === false &&
    denials &&
    exactKeys(denials, [
      "auditBaseTableReads",
      "auditTrustRootWrite",
      "sourceBaseTableReads",
      "sourceTrustRootWrite"
    ]) &&
    Object.values(denials).every((denial) => denial?.denied === true)
  );
}

export function buildIntegratedLiveDrillReceipt({
  spec,
  dvi,
  race,
  recovery,
  authorityEvidenceId,
  authoritySelectedEvidenceDigest
}) {
  const acceptedSpec = parseIntegratedLiveDrillSpec(spec);
  const selectedBinding = selectedEvidenceBindingSha256(
    authorityEvidenceId,
    authoritySelectedEvidenceDigest
  );
  if (
    !acceptedDvi(dvi, acceptedSpec, selectedBinding) ||
    !acceptedRace(race, acceptedSpec, dvi) ||
    !acceptedRecovery(recovery, acceptedSpec, race)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_COMPONENT_REJECTED");
  }
  const invariants = Object.freeze({
    exactReleaseSource: true,
    exactNumericLambdaVersion: true,
    exactAwsCallerBound: true,
    fiveAwsInvocationReceiptsBound: true,
    oneDatabaseProducedDviSnapshot: true,
    snapshotExclusionsBoundAndCleaned: true,
    selectedEvidenceBoundAcrossActs: true,
    twoLambdaTransactionsOverlapped: true,
    exactlyOneAuthorityWinner: true,
    exactlyOneDurableDenial: true,
    protectedEffectsZero: true,
    exactReplayReturnedOriginalDecision: true,
    changedInputUnderOperationDenied: true,
    exactWinnerRecoveryBound: true,
    oneCanonicalRecoveryBundle: true,
    managedMcpTransportReceiptBound: true,
    managedMcpSessionContinuous: true,
    managedMcpPayloadDigestsBound: true,
    managedMcpCalledExactlyOnce: true,
    unboundPrincipalDeniedBeforeMcp: true,
    bothRecoveryAuditsCommitted: true,
    fixedProviderOperationCostBound: true,
    operationalCapabilityReturned: false,
    authorityTransferredByModelOrRecovery: false
  });
  const componentDigests = {
    dvi: sha256(canonicalJson(dvi)),
    authorityRace: sha256(canonicalJson(race)),
    recovery: sha256(canonicalJson(recovery))
  };
  const receipt = {
    schemaVersion: INTEGRATED_LIVE_DRILL_SCHEMA,
    status: "PASS",
    sourceCommit: acceptedSpec.sourceCommit,
    treeDigest: dvi.treeDigest,
    runId: acceptedSpec.runId,
    configDigest: acceptedSpec.configDigest,
    sourceBuildIdentitySha256: sha256(acceptedSpec.sourceBuildIdentity),
    componentDigests,
    dvi: {
      authorityEvidenceBindingSha256:
        dvi.drill.authorityEvidenceBindingSha256,
      selectedEvidenceBindingSha256: selectedBinding
    },
    authority: {
      contenders: 2,
      winnerOperationBindingSha256: sha256(canonicalJson({
        operationId: race.winner.operationId,
        requestDigest: race.winner.requestDigest
      })),
      replayVerified: true,
      changedInputDenied: true,
      protectedEffectCount: 0
    },
    recovery: {
      exactWinnerBound: true,
      managedMcpCallCount: 1,
      unauthorizedPrincipalDenied: true,
      auditsCommitted: 2,
      operationalCapabilitiesReturned: false
    },
    providerOperations: {
      dviProofRuns: 1,
      lambdaInvocations: 5,
      managedMcpToolCalls: 1,
      cloudResourcesCreatedByDrill: 0
    },
    costControl: {
      maximumAwsCostUsd: acceptedSpec.maximumAwsCostUsd,
      fixedInvocationBound: true,
      actualProviderBillingReceiptRequiredSeparately: true
    },
    invariants,
    invariantCount: Object.keys(invariants).length,
    invariantViolations: 0,
    providerBacked: true,
    claimBoundary:
      "This sanitized receipt proves one exact-release provider-backed integrated synthetic drill whose CockroachDB DVI selection, five receipt-bound numeric-version Lambda invocations, overlapping authority race, replay and changed-input controls, and exact-winner canonical-bundle Managed MCP recovery share one binding with zero declared invariant violations. The Managed MCP receipt binds one continuous negotiated session plus request, response, and result digests; it is not an independent provider signature. Its fixed operation count is constrained by a $0.02 AWS ceiling, but the actual provider billing receipt remains separately required. It must be accepted together with the separately verified 100-run deterministic offline receipt. It does not prove a real-world external effect, production suitability, availability, administrator exclusion, or authorize deployment, publication, or submission."
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: sha256(canonicalJson(receipt))
  });
}
