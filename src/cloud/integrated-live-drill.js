import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "./canonical-json.js";
import { INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER } from
  "./integrated-live-drill-authorization.js";
import { canonicalRecoveryAttempt } from "./recovery-broker.js";
import { verifyRecoveryBundleSourceSignature } from "./recovery-store.js";
import { INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_RECEIPT_SCHEMA } from
  "./integrated-live-drill-control-ledger.js";

export const INTEGRATED_LIVE_DRILL_SCHEMA =
  "tideproof.highwater-drill-live.v1";
export const INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA_V1 =
  "tideproof.highwater-drill-live-candidate.v1";
export const INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA =
  "tideproof.highwater-drill-live-candidate.v2";
export const INTEGRATED_LIVE_DRILL_SPEC_SCHEMA =
  "tideproof.highwater-drill-live-spec.v1";
export const INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_SCHEMA =
  "tideproof.highwater-drill-live-private-evidence.v1";
export const INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-live-private-evidence-persistence.v1";
export const INTEGRATED_LIVE_DRILL_JOURNAL_ENTRY_SCHEMA =
  "tideproof.highwater-drill-live-journal-entry.v1";
export const INTEGRATED_LIVE_DRILL_JOURNAL_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-live-journal-receipt.v1";
export const INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-live-recovery-bundle-persistence.v1";

const SHA256 = /^[0-9a-f]{64}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRIVATE_EVIDENCE_MAX_BYTES = 8 * 1024 * 1024;
const RECOVERY_BUNDLE_MAX_BYTES = 64 * 1024;
const JOURNAL_PHASES = Object.freeze([
  "PRE_PROVIDER_INTENT",
  "DVI_RESULT",
  "AUTHORITY_RACE_RESULT",
  "RECOVERY_RESULT",
  "PRIVATE_EVIDENCE_RESULT",
  "POST_RELEASE_VERIFICATION"
]);

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

export function acceptedIntegratedLiveDrillDvi(dvi, spec, selectedBinding) {
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

export function acceptedIntegratedLiveDrillRace(race, spec, dvi) {
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
      "principalIdDigest",
      "principalType"
    ]) &&
    caller.principalType === "assumed-role" &&
    caller.expectedIdentityDigest === caller.callerIdentityDigest &&
    [
      caller.bindingDigest,
      caller.callerIdentityDigest,
      caller.contextDigest,
      caller.expectedIdentityDigest,
      caller.expectedPrincipalDigest,
      caller.principalIdDigest
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
    exactKeys(race.providerOperations, [
      "cloudFormationDescribeStackResourceRequests",
      "lambdaInvokeRequests",
      "stsGetCallerIdentityRequests"
    ]) &&
    race.providerOperations.cloudFormationDescribeStackResourceRequests === 1 &&
    race.providerOperations.lambdaInvokeRequests === 5 &&
    race.providerOperations.stsGetCallerIdentityRequests === 1 &&
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
  const signedBundlePersistence = recovery?.signedBundlePersistence;
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
    exactKeys(signedBundlePersistence, [
      "atomicCreateOnly",
      "bundleDigest",
      "configDigest",
      "creationProtocolObserved",
      "directoryEntrySynced",
      "fileDataSynced",
      "fileByteLength",
      "fileMode",
      "parentDirectoryMode",
      "pathSha256",
      "receiptSha256",
      "rereadVerified",
      "reusedExisting",
      "runId",
      "sameFilesystemAtomicLink",
      "schemaVersion",
      "signatureDigest",
      "signedBundleSha256",
      "sourceBuildIdentitySha256",
      "sourceCommit",
      "treeDigest"
    ]) &&
    signedBundlePersistence.schemaVersion ===
      INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA &&
    signedBundlePersistence.sourceCommit === spec.sourceCommit &&
    signedBundlePersistence.treeDigest === spec.treeDigest &&
    signedBundlePersistence.runId === spec.runId &&
    signedBundlePersistence.configDigest === spec.configDigest &&
    signedBundlePersistence.sourceBuildIdentitySha256 ===
      sha256(spec.sourceBuildIdentity) &&
    signedBundlePersistence.bundleDigest === recovery.bundleDigest &&
    SHA256.test(signedBundlePersistence.signatureDigest ?? "") &&
    SHA256.test(signedBundlePersistence.signedBundleSha256 ?? "") &&
    SHA256.test(signedBundlePersistence.pathSha256 ?? "") &&
    Number.isSafeInteger(signedBundlePersistence.fileByteLength) &&
    signedBundlePersistence.fileByteLength > 0 &&
    signedBundlePersistence.fileByteLength <= RECOVERY_BUNDLE_MAX_BYTES &&
    signedBundlePersistence.fileMode === "0600" &&
    signedBundlePersistence.parentDirectoryMode === "0700" &&
    signedBundlePersistence.directoryEntrySynced === true &&
    signedBundlePersistence.fileDataSynced === true &&
    signedBundlePersistence.rereadVerified === true &&
    typeof signedBundlePersistence.reusedExisting === "boolean" &&
    signedBundlePersistence.creationProtocolObserved ===
      !signedBundlePersistence.reusedExisting &&
    signedBundlePersistence.atomicCreateOnly ===
      !signedBundlePersistence.reusedExisting &&
    signedBundlePersistence.sameFilesystemAtomicLink ===
      !signedBundlePersistence.reusedExisting &&
    signedBundlePersistence.receiptSha256 === sha256(canonicalJson(
      Object.fromEntries(Object.entries(signedBundlePersistence).filter(
        ([key]) => key !== "receiptSha256"
      ))
    )) &&
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

function componentDigestsFor({ dvi, race, recovery }) {
  return Object.freeze({
    dvi: sha256(canonicalJson(dvi)),
    authorityRace: sha256(canonicalJson(race)),
    recovery: sha256(canonicalJson(recovery))
  });
}

function pathIsWithin(candidatePath, rootPath) {
  const relative = path.relative(rootPath, candidatePath);
  return relative === "" || (
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function assertSamePrivateEvidenceParent(parentPath, expectedStat) {
  let current;
  try {
    current = fs.lstatSync(parentPath);
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_DRIFT");
  }
  if (
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    current.dev !== expectedStat.dev ||
    current.ino !== expectedStat.ino ||
    current.uid !== expectedStat.uid ||
    (current.mode & 0o777) !== 0o700 ||
    fs.realpathSync(parentPath) !== parentPath
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_DRIFT");
  }
}

function securePrivateEvidenceParent(
  destinationPath,
  evidenceRootPath,
  forbiddenRootPath
) {
  if (
    typeof destinationPath !== "string" ||
    destinationPath.length === 0 ||
    destinationPath.length > 4096 ||
    /[\0\r\n]/.test(destinationPath) ||
    !path.isAbsolute(destinationPath) ||
    path.resolve(destinationPath) !== destinationPath
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH_REJECTED");
  }
  if (
    typeof evidenceRootPath !== "string" ||
    typeof forbiddenRootPath !== "string" ||
    !path.isAbsolute(evidenceRootPath) ||
    !path.isAbsolute(forbiddenRootPath) ||
    path.resolve(evidenceRootPath) !== evidenceRootPath ||
    path.resolve(forbiddenRootPath) !== forbiddenRootPath
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT_REJECTED");
  }
  const parentPath = path.dirname(destinationPath);
  let canonicalForbiddenRoot;
  try {
    canonicalForbiddenRoot = fs.realpathSync(forbiddenRootPath);
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT_REJECTED");
  }
  if (
    parentPath !== evidenceRootPath ||
    pathIsWithin(evidenceRootPath, canonicalForbiddenRoot) ||
    pathIsWithin(destinationPath, canonicalForbiddenRoot)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT_REJECTED");
  }
  let parentStat;
  try {
    parentStat = fs.lstatSync(parentPath);
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_REJECTED");
  }
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : parentStat.uid;
  if (
    !parentStat.isDirectory() ||
    parentStat.isSymbolicLink() ||
    (parentStat.mode & 0o777) !== 0o700 ||
    parentStat.uid !== expectedUid
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_REJECTED");
  }
  let canonicalParent;
  try {
    canonicalParent = fs.realpathSync(parentPath);
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_REJECTED");
  }
  if (canonicalParent !== parentPath) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_REJECTED");
  }
  return Object.freeze({ parentPath, parentStat, expectedUid });
}

function syncDirectory(directoryPath, expectedStat) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      directoryPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const opened = fs.fstatSync(descriptor);
    if (
      opened.dev !== expectedStat.dev ||
      opened.ino !== expectedStat.ino ||
      opened.uid !== expectedStat.uid ||
      (opened.mode & 0o777) !== 0o700
    ) {
      throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PARENT_DRIFT");
    }
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

function rereadPrivateEvidence({
  destinationPath,
  expectedBytes = null,
  expectedUid,
  parentPath,
  parentStat,
  syncDurability = false
}) {
  assertSamePrivateEvidenceParent(parentPath, parentStat);
  let descriptor;
  try {
    descriptor = fs.openSync(
      destinationPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    if (
      !before.isFile() ||
      (before.mode & 0o777) !== 0o600 ||
      before.uid !== expectedUid ||
      before.nlink !== 1 ||
      (expectedBytes !== null && before.size !== expectedBytes.length) ||
      before.size < 1 ||
      before.size > PRIVATE_EVIDENCE_MAX_BYTES
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_FILE_REJECTED"
      );
    }
    const reread = fs.readFileSync(descriptor);
    if (syncDurability) {
      fs.fsyncSync(descriptor);
    }
    const after = fs.fstatSync(descriptor);
    assertSamePrivateEvidenceParent(parentPath, parentStat);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      (expectedBytes !== null && !reread.equals(expectedBytes))
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED"
      );
    }
    const assertPathStillNamesOpenedFile = () => {
      let currentPath;
      try {
        currentPath = fs.lstatSync(destinationPath);
      } catch {
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED"
        );
      }
      if (
        !currentPath.isFile() ||
        currentPath.isSymbolicLink() ||
        currentPath.dev !== after.dev ||
        currentPath.ino !== after.ino ||
        currentPath.uid !== expectedUid ||
        (currentPath.mode & 0o777) !== 0o600 ||
        currentPath.nlink !== 1 ||
        currentPath.size !== after.size
      ) {
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED"
        );
      }
    };
    assertPathStillNamesOpenedFile();
    if (syncDurability) {
      syncDirectory(parentPath, parentStat);
      assertSamePrivateEvidenceParent(parentPath, parentStat);
      assertPathStillNamesOpenedFile();
    }
    return Object.freeze({
      byteLength: before.size,
      bytes: reread,
      device: String(before.dev),
      inode: String(before.ino)
    });
  } finally {
    if (descriptor !== undefined) {
      fs.closeSync(descriptor);
    }
  }
}

function recoveryBundlePersistenceReceipt({
  spec,
  destinationPath,
  envelope,
  fileByteLength,
  reusedExisting
}) {
  const receipt = {
    schemaVersion: INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA,
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    runId: spec.runId,
    configDigest: spec.configDigest,
    sourceBuildIdentitySha256: sha256(spec.sourceBuildIdentity),
    bundleDigest: envelope.signedBundle.bundleDigest,
    signatureDigest: envelope.signedBundle.signatureDigest,
    signedBundleSha256: envelope.signedBundleSha256,
    fileByteLength,
    pathSha256: sha256(destinationPath),
    creationProtocolObserved: !reusedExisting,
    atomicCreateOnly: !reusedExisting,
    fileMode: "0600",
    parentDirectoryMode: "0700",
    sameFilesystemAtomicLink: !reusedExisting,
    fileDataSynced: true,
    directoryEntrySynced: true,
    rereadVerified: true,
    reusedExisting
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: sha256(canonicalJson(receipt))
  });
}

function readIntegratedLiveDrillRecoveryBundle({
  destinationPath,
  secure,
  spec,
  candidateBundle,
  trustedPublisherKeys,
  reusedExisting
}) {
  let reread;
  try {
    reread = rereadPrivateEvidence({
      destinationPath,
      expectedUid: secure.expectedUid,
      parentPath: secure.parentPath,
      parentStat: secure.parentStat,
      syncDurability: true
    });
  } catch (cause) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED", {
      cause
    });
  }
  if (
    reread.byteLength < 1 ||
    reread.byteLength > RECOVERY_BUNDLE_MAX_BYTES
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED");
  }
  let parsed;
  try {
    parsed = JSON.parse(reread.bytes.toString("utf8"));
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED");
  }
  if (
    !exactKeys(parsed, [
      "configDigest",
      "runId",
      "schemaVersion",
      "signedBundle",
      "signedBundleSha256",
      "sourceBuildIdentitySha256",
      "sourceCommit",
      "treeDigest"
    ]) ||
    parsed.schemaVersion !==
      "tideproof.highwater-drill-live-signed-recovery-bundle.v1" ||
    parsed.sourceCommit !== spec.sourceCommit ||
    parsed.treeDigest !== spec.treeDigest ||
    parsed.runId !== spec.runId ||
    parsed.configDigest !== spec.configDigest ||
    parsed.sourceBuildIdentitySha256 !== sha256(spec.sourceBuildIdentity) ||
    !SHA256.test(parsed.signedBundleSha256 ?? "") ||
    parsed.signedBundleSha256 !==
      sha256(canonicalJson(parsed.signedBundle)) ||
    reread.bytes.toString("utf8") !== `${canonicalJson(parsed)}\n`
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED");
  }
  let persistedBundle;
  try {
    persistedBundle = verifyRecoveryBundleSourceSignature(
      parsed.signedBundle,
      trustedPublisherKeys
    );
  } catch (cause) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED", {
      cause
    });
  }
  if (
    canonicalJson(parsed.signedBundle) !== canonicalJson(persistedBundle)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED");
  }
  if (persistedBundle.bundleDigest !== candidateBundle.bundleDigest) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_MISMATCH");
  }
  const envelope = Object.freeze({
    ...parsed,
    signedBundle: Object.freeze(persistedBundle)
  });
  return Object.freeze({
    bundle: envelope.signedBundle,
    receipt: recoveryBundlePersistenceReceipt({
      spec,
      destinationPath,
      envelope,
      fileByteLength: reread.byteLength,
      reusedExisting
    })
  });
}

export function persistOrReuseIntegratedLiveDrillRecoveryBundle({
  destinationPath,
  evidenceRootPath,
  forbiddenRootPath,
  spec,
  signedBundle,
  trustedPublisherKeys
}) {
  const acceptedSpec = parseIntegratedLiveDrillSpec(spec);
  if (
    typeof destinationPath !== "string" ||
    path.basename(destinationPath) !==
      `${acceptedSpec.runId}.signed-recovery-bundle.json`
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED");
  }
  const secure = securePrivateEvidenceParent(
    destinationPath,
    evidenceRootPath,
    forbiddenRootPath
  );
  let candidateBundle;
  try {
    candidateBundle = verifyRecoveryBundleSourceSignature(
      signedBundle,
      trustedPublisherKeys
    );
  } catch (cause) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED", {
      cause
    });
  }
  if (fs.existsSync(destinationPath)) {
    return readIntegratedLiveDrillRecoveryBundle({
      destinationPath,
      secure,
      spec: acceptedSpec,
      candidateBundle,
      trustedPublisherKeys,
      reusedExisting: true
    });
  }
  const envelope = Object.freeze({
    schemaVersion:
      "tideproof.highwater-drill-live-signed-recovery-bundle.v1",
    sourceCommit: acceptedSpec.sourceCommit,
    treeDigest: acceptedSpec.treeDigest,
    runId: acceptedSpec.runId,
    configDigest: acceptedSpec.configDigest,
    sourceBuildIdentitySha256: sha256(acceptedSpec.sourceBuildIdentity),
    signedBundle: Object.freeze(candidateBundle),
    signedBundleSha256: sha256(canonicalJson(candidateBundle))
  });
  const serialized = Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
  if (
    serialized.length < 1 ||
    serialized.length > RECOVERY_BUNDLE_MAX_BYTES
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED");
  }
  const temporaryPath = path.join(
    secure.parentPath,
    `.${path.basename(destinationPath)}.${process.pid}.` +
      `${randomBytes(16).toString("hex")}.tmp`
  );
  let descriptor;
  let linked = false;
  try {
    assertSamePrivateEvidenceParent(secure.parentPath, secure.parentStat);
    descriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    assertSamePrivateEvidenceParent(secure.parentPath, secure.parentStat);
    fs.linkSync(temporaryPath, destinationPath);
    linked = true;
    fs.unlinkSync(temporaryPath);
    assertSamePrivateEvidenceParent(secure.parentPath, secure.parentStat);
    syncDirectory(secure.parentPath, secure.parentStat);
  } catch (cause) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the first fail-closed error.
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch {
      // The temporary file may not have been created or may be unlinked.
    }
    if (!linked && cause?.code === "EEXIST") {
      return readIntegratedLiveDrillRecoveryBundle({
        destinationPath,
        secure,
        spec: acceptedSpec,
        candidateBundle,
        trustedPublisherKeys,
        reusedExisting: true
      });
    }
    throw new Error("INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_WRITE_REJECTED", {
      cause,
      linked
    });
  }
  return readIntegratedLiveDrillRecoveryBundle({
    destinationPath,
    secure,
    spec: acceptedSpec,
    candidateBundle,
    trustedPublisherKeys,
    reusedExisting: false
  });
}

function privateEvidencePersistenceReceipt({
  spec,
  selectedBinding,
  componentDigests,
  bundleSha256,
  destinationPath,
  fileByteLength
}) {
  const receipt = {
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_RECEIPT_SCHEMA,
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    runId: spec.runId,
    configDigest: spec.configDigest,
    sourceBuildIdentitySha256: sha256(spec.sourceBuildIdentity),
    selectedEvidenceBindingSha256: selectedBinding,
    componentDigests,
    bundleSha256,
    fileByteLength,
    pathSha256: sha256(destinationPath),
    atomicCreateOnly: true,
    fileMode: "0600",
    parentDirectoryMode: "0700",
    sameFilesystemAtomicLink: true,
    directoryEntrySynced: true,
    rereadVerified: true
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: sha256(canonicalJson(receipt))
  });
}

export function persistIntegratedLiveDrillPrivateEvidence({
  destinationPath,
  evidenceRootPath,
  forbiddenRootPath,
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
    typeof destinationPath !== "string" ||
    path.basename(destinationPath) !==
      `${acceptedSpec.runId}.private-evidence.json` ||
    !acceptedIntegratedLiveDrillDvi(dvi, acceptedSpec, selectedBinding) ||
    !acceptedIntegratedLiveDrillRace(race, acceptedSpec, dvi) ||
    !acceptedRecovery(recovery, acceptedSpec, race)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REJECTED");
  }
  const { parentPath, parentStat, expectedUid } =
    securePrivateEvidenceParent(
      destinationPath,
      evidenceRootPath,
      forbiddenRootPath
    );
  const componentDigests = componentDigestsFor({ dvi, race, recovery });
  const body = {
    schemaVersion: INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_SCHEMA,
    sourceCommit: acceptedSpec.sourceCommit,
    treeDigest: acceptedSpec.treeDigest,
    runId: acceptedSpec.runId,
    configDigest: acceptedSpec.configDigest,
    sourceBuildIdentity: acceptedSpec.sourceBuildIdentity,
    authorityEvidenceId,
    authoritySelectedEvidenceDigest,
    selectedEvidenceBindingSha256: selectedBinding,
    componentDigests,
    components: { dvi, authorityRace: race, recovery },
    spec: acceptedSpec
  };
  const bundle = Object.freeze({
    ...body,
    bundleSha256: sha256(canonicalJson(body))
  });
  const serialized = Buffer.from(`${canonicalJson(bundle)}\n`, "utf8");
  if (
    serialized.length < 1 ||
    serialized.length > PRIVATE_EVIDENCE_MAX_BYTES
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_SIZE_REJECTED");
  }
  const temporaryPath = path.join(
    parentPath,
    `.${path.basename(destinationPath)}.${process.pid}.` +
      `${randomBytes(16).toString("hex")}.tmp`
  );
  let descriptor;
  let linked = false;
  try {
    assertSamePrivateEvidenceParent(parentPath, parentStat);
    descriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    assertSamePrivateEvidenceParent(parentPath, parentStat);
    fs.linkSync(temporaryPath, destinationPath);
    linked = true;
    assertSamePrivateEvidenceParent(parentPath, parentStat);
    fs.unlinkSync(temporaryPath);
    assertSamePrivateEvidenceParent(parentPath, parentStat);
    syncDirectory(parentPath, parentStat);
    assertSamePrivateEvidenceParent(parentPath, parentStat);
  } catch (cause) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the first fail-closed error.
      }
    }
    if (!linked) {
      try {
        fs.unlinkSync(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
    }
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_WRITE_REJECTED",
      { cause }
    );
  }
  const reread = rereadPrivateEvidence({
    destinationPath,
    expectedBytes: serialized,
    expectedUid,
    parentPath,
    parentStat
  });
  let parsed;
  try {
    parsed = JSON.parse(reread.bytes.toString("utf8"));
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED");
  }
  if (
    parsed.bundleSha256 !== bundle.bundleSha256 ||
    canonicalJson(parsed) !== canonicalJson(bundle)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED");
  }
  return privateEvidencePersistenceReceipt({
    spec: acceptedSpec,
    selectedBinding,
    componentDigests,
    bundleSha256: bundle.bundleSha256,
    destinationPath,
    fileByteLength: reread.byteLength
  });
}

export function verifyIntegratedLiveDrillPrivateEvidence({
  destinationPath,
  evidenceRootPath,
  forbiddenRootPath,
  receipt,
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
    typeof destinationPath !== "string" ||
    path.basename(destinationPath) !==
      `${acceptedSpec.runId}.private-evidence.json`
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REJECTED");
  }
  const { parentPath, parentStat, expectedUid } =
    securePrivateEvidenceParent(
      destinationPath,
      evidenceRootPath,
      forbiddenRootPath
    );
  const reread = rereadPrivateEvidence({
    destinationPath,
    expectedUid,
    parentPath,
    parentStat
  });
  let parsed;
  try {
    parsed = JSON.parse(reread.bytes.toString("utf8"));
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED");
  }
  const expectedDigests = componentDigestsFor({ dvi, race, recovery });
  const { bundleSha256, ...body } = parsed ?? {};
  if (
    !exactKeys(parsed, [
      "authorityEvidenceId",
      "authoritySelectedEvidenceDigest",
      "bundleSha256",
      "componentDigests",
      "components",
      "configDigest",
      "runId",
      "schemaVersion",
      "selectedEvidenceBindingSha256",
      "sourceBuildIdentity",
      "sourceCommit",
      "spec",
      "treeDigest"
    ]) ||
    parsed.schemaVersion !== INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_SCHEMA ||
    parsed.sourceCommit !== acceptedSpec.sourceCommit ||
    parsed.treeDigest !== acceptedSpec.treeDigest ||
    parsed.runId !== acceptedSpec.runId ||
    parsed.configDigest !== acceptedSpec.configDigest ||
    parsed.sourceBuildIdentity !== acceptedSpec.sourceBuildIdentity ||
    parsed.authorityEvidenceId !== authorityEvidenceId ||
    parsed.authoritySelectedEvidenceDigest !==
      authoritySelectedEvidenceDigest ||
    parsed.selectedEvidenceBindingSha256 !== selectedBinding ||
    canonicalJson(parsed.spec) !== canonicalJson(acceptedSpec) ||
    canonicalJson(parsed.componentDigests) !== canonicalJson(expectedDigests) ||
    canonicalJson(parsed.components) !== canonicalJson({
      dvi,
      authorityRace: race,
      recovery
    }) ||
    !SHA256.test(bundleSha256 ?? "") ||
    bundleSha256 !== sha256(canonicalJson(body)) ||
    reread.bytes.toString("utf8") !== `${canonicalJson(parsed)}\n`
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_REREAD_REJECTED");
  }
  const recomputed = privateEvidencePersistenceReceipt({
    spec: acceptedSpec,
    selectedBinding,
    componentDigests: expectedDigests,
    bundleSha256,
    destinationPath,
    fileByteLength: reread.byteLength
  });
  if (canonicalJson(receipt) !== canonicalJson(recomputed)) {
    throw new Error("INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_RECEIPT_REJECTED");
  }
  return recomputed;
}

function journalEntryFileName(index, phase) {
  return `${String(index).padStart(2, "0")}-${phase.toLowerCase().replaceAll("_", "-")}.json`;
}

function secureJournalDirectory({
  journalPath,
  evidenceRootPath,
  forbiddenRootPath,
  create = false
}) {
  const root = securePrivateEvidenceParent(
    journalPath,
    evidenceRootPath,
    forbiddenRootPath
  );
  if (create) {
    try {
      fs.mkdirSync(journalPath, { mode: 0o700 });
      syncDirectory(root.parentPath, root.parentStat);
    } catch (cause) {
      throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_CREATE_REJECTED", {
        cause
      });
    }
  }
  let journalStat;
  try {
    journalStat = fs.lstatSync(journalPath);
  } catch {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
  }
  if (
    !journalStat.isDirectory() ||
    journalStat.isSymbolicLink() ||
    journalStat.uid !== root.expectedUid ||
    (journalStat.mode & 0o777) !== 0o700 ||
    fs.realpathSync(journalPath) !== journalPath
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
  }
  assertSamePrivateEvidenceParent(root.parentPath, root.parentStat);
  return Object.freeze({ ...root, journalStat });
}

function readIntegratedLiveDrillJournal({
  journalPath,
  evidenceRootPath,
  forbiddenRootPath,
  spec
}) {
  const acceptedSpec = parseIntegratedLiveDrillSpec(spec);
  if (
    typeof journalPath !== "string" ||
    path.basename(journalPath) !== `${acceptedSpec.runId}.journal`
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
  }
  const secure = secureJournalDirectory({
    journalPath,
    evidenceRootPath,
    forbiddenRootPath
  });
  assertSamePrivateEvidenceParent(journalPath, secure.journalStat);
  const names = fs.readdirSync(journalPath).sort();
  if (
    names.length > JOURNAL_PHASES.length ||
    names.some((name, index) =>
      name !== journalEntryFileName(index, JOURNAL_PHASES[index]))
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
  }
  const entries = [];
  let previousEntrySha256 = null;
  for (const [index, name] of names.entries()) {
    const reread = rereadPrivateEvidence({
      destinationPath: path.join(journalPath, name),
      expectedUid: secure.expectedUid,
      parentPath: journalPath,
      parentStat: secure.journalStat
    });
    let parsed;
    try {
      parsed = JSON.parse(reread.bytes.toString("utf8"));
    } catch {
      throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
    }
    const { entrySha256, ...body } = parsed ?? {};
    if (
      !exactKeys(parsed, [
        "configDigest",
        "entrySha256",
        "index",
        "payloadSha256",
        "phase",
        "previousEntrySha256",
        "runId",
        "schemaVersion",
        "sourceBuildIdentitySha256",
        "sourceCommit",
        "treeDigest"
      ]) ||
      parsed.schemaVersion !== INTEGRATED_LIVE_DRILL_JOURNAL_ENTRY_SCHEMA ||
      parsed.index !== index ||
      parsed.phase !== JOURNAL_PHASES[index] ||
      parsed.sourceCommit !== acceptedSpec.sourceCommit ||
      parsed.treeDigest !== acceptedSpec.treeDigest ||
      parsed.runId !== acceptedSpec.runId ||
      parsed.configDigest !== acceptedSpec.configDigest ||
      parsed.sourceBuildIdentitySha256 !==
        sha256(acceptedSpec.sourceBuildIdentity) ||
      parsed.previousEntrySha256 !== previousEntrySha256 ||
      !SHA256.test(parsed.payloadSha256 ?? "") ||
      !SHA256.test(entrySha256 ?? "") ||
      entrySha256 !== sha256(canonicalJson(body)) ||
      reread.bytes.toString("utf8") !== `${canonicalJson(parsed)}\n`
    ) {
      throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
    }
    entries.push(parsed);
    previousEntrySha256 = entrySha256;
  }
  assertSamePrivateEvidenceParent(journalPath, secure.journalStat);
  return Object.freeze({
    acceptedSpec,
    entries: Object.freeze(entries),
    secure
  });
}

function integratedLiveDrillJournalReceipt({
  journalPath,
  acceptedSpec,
  entries
}) {
  const phasePayloadSha256 = Object.freeze(Object.fromEntries(
    entries.map((entry) => [entry.phase, entry.payloadSha256])
  ));
  const receipt = {
    schemaVersion: INTEGRATED_LIVE_DRILL_JOURNAL_RECEIPT_SCHEMA,
    sourceCommit: acceptedSpec.sourceCommit,
    treeDigest: acceptedSpec.treeDigest,
    runId: acceptedSpec.runId,
    configDigest: acceptedSpec.configDigest,
    sourceBuildIdentitySha256: sha256(acceptedSpec.sourceBuildIdentity),
    journalPathSha256: sha256(journalPath),
    entryCount: entries.length,
    firstEntrySha256: entries[0]?.entrySha256 ?? null,
    lastEntrySha256: entries.at(-1)?.entrySha256 ?? null,
    phasePayloadSha256,
    preProviderIntentDurableBeforeReturn: entries.length > 0,
    entryFilesCreateOnly: true,
    entryFilesSynced: true,
    directoryEntriesSynced: true,
    hashChainVerified: true,
    journalDirectoryMode: "0700",
    entryFileMode: "0600"
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: sha256(canonicalJson(receipt))
  });
}

function createJournalEntry({
  journalPath,
  secure,
  acceptedSpec,
  index,
  payloadSha256
}) {
  const phase = JOURNAL_PHASES[index];
  if (!phase || !SHA256.test(payloadSha256 ?? "")) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_ENTRY_REJECTED");
  }
  const existing = readIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: secure.parentPath,
    forbiddenRootPath: secure.forbiddenRootPath,
    spec: acceptedSpec
  });
  if (existing.entries.length !== index) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_SEQUENCE_REJECTED");
  }
  const body = {
    schemaVersion: INTEGRATED_LIVE_DRILL_JOURNAL_ENTRY_SCHEMA,
    index,
    phase,
    sourceCommit: acceptedSpec.sourceCommit,
    treeDigest: acceptedSpec.treeDigest,
    runId: acceptedSpec.runId,
    configDigest: acceptedSpec.configDigest,
    sourceBuildIdentitySha256: sha256(acceptedSpec.sourceBuildIdentity),
    previousEntrySha256:
      existing.entries.at(-1)?.entrySha256 ?? null,
    payloadSha256
  };
  const entry = Object.freeze({
    ...body,
    entrySha256: sha256(canonicalJson(body))
  });
  const serialized = Buffer.from(`${canonicalJson(entry)}\n`, "utf8");
  const temporaryPath = path.join(
    secure.parentPath,
    `.${acceptedSpec.runId}.journal-${index}.${process.pid}.` +
      `${randomBytes(16).toString("hex")}.tmp`
  );
  const destinationPath = path.join(
    journalPath,
    journalEntryFileName(index, phase)
  );
  let descriptor;
  let linked = false;
  try {
    assertSamePrivateEvidenceParent(secure.parentPath, secure.parentStat);
    assertSamePrivateEvidenceParent(journalPath, secure.journalStat);
    descriptor = fs.openSync(
      temporaryPath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    assertSamePrivateEvidenceParent(journalPath, secure.journalStat);
    fs.linkSync(temporaryPath, destinationPath);
    linked = true;
    fs.unlinkSync(temporaryPath);
    syncDirectory(journalPath, secure.journalStat);
    syncDirectory(secure.parentPath, secure.parentStat);
  } catch (cause) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the first fail-closed error.
      }
    }
    try {
      fs.unlinkSync(temporaryPath);
    } catch {
      // The temporary link may already be gone.
    }
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_WRITE_REJECTED", {
      cause,
      linked
    });
  }
  return entry;
}

export function startIntegratedLiveDrillJournal({
  journalPath,
  evidenceRootPath,
  forbiddenRootPath,
  spec,
  intentBindingSha256
}) {
  const acceptedSpec = parseIntegratedLiveDrillSpec(spec);
  if (
    path.basename(journalPath ?? "") !== `${acceptedSpec.runId}.journal` ||
    !SHA256.test(intentBindingSha256 ?? "")
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
  }
  const secure = secureJournalDirectory({
    journalPath,
    evidenceRootPath,
    forbiddenRootPath,
    create: true
  });
  createJournalEntry({
    journalPath,
    secure: Object.freeze({
      ...secure,
      forbiddenRootPath
    }),
    acceptedSpec,
    index: 0,
    payloadSha256: intentBindingSha256
  });
  return verifyIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath,
    forbiddenRootPath,
    spec: acceptedSpec,
    expectedPhasePayloadSha256: {
      PRE_PROVIDER_INTENT: intentBindingSha256
    }
  });
}

export function appendIntegratedLiveDrillJournal({
  journalPath,
  evidenceRootPath,
  forbiddenRootPath,
  spec,
  phase,
  payload
}) {
  const current = readIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath,
    forbiddenRootPath,
    spec
  });
  const index = current.entries.length;
  if (phase !== JOURNAL_PHASES[index] || payload === undefined) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_SEQUENCE_REJECTED");
  }
  createJournalEntry({
    journalPath,
    secure: Object.freeze({
      ...current.secure,
      forbiddenRootPath
    }),
    acceptedSpec: current.acceptedSpec,
    index,
    payloadSha256: sha256(canonicalJson(payload))
  });
  return verifyIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath,
    forbiddenRootPath,
    spec: current.acceptedSpec
  });
}

export function verifyIntegratedLiveDrillJournal({
  journalPath,
  evidenceRootPath,
  forbiddenRootPath,
  spec,
  receipt = null,
  expectedPhasePayloadSha256 = null,
  requireComplete = false
}) {
  const current = readIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath,
    forbiddenRootPath,
    spec
  });
  if (
    (requireComplete && current.entries.length !== JOURNAL_PHASES.length) ||
    (expectedPhasePayloadSha256 !== null &&
      Object.entries(expectedPhasePayloadSha256).some(([phase, digest]) =>
        !SHA256.test(digest ?? "") ||
        current.entries.find((entry) => entry.phase === phase)
          ?.payloadSha256 !== digest))
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_REJECTED");
  }
  const recomputed = integratedLiveDrillJournalReceipt({
    journalPath,
    acceptedSpec: current.acceptedSpec,
    entries: current.entries
  });
  if (receipt !== null && canonicalJson(receipt) !== canonicalJson(recomputed)) {
    throw new Error("INTEGRATED_LIVE_DRILL_JOURNAL_RECEIPT_REJECTED");
  }
  return recomputed;
}

function acceptedPrivateEvidence(receipt, spec, selectedBinding, digests) {
  if (
    !exactKeys(receipt, [
      "atomicCreateOnly",
      "bundleSha256",
      "componentDigests",
      "configDigest",
      "directoryEntrySynced",
      "fileByteLength",
      "fileMode",
      "parentDirectoryMode",
      "pathSha256",
      "receiptSha256",
      "rereadVerified",
      "runId",
      "sameFilesystemAtomicLink",
      "schemaVersion",
      "selectedEvidenceBindingSha256",
      "sourceBuildIdentitySha256",
      "sourceCommit",
      "treeDigest"
    ]) ||
    receipt.schemaVersion !==
      INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_RECEIPT_SCHEMA ||
    receipt.sourceCommit !== spec.sourceCommit ||
    receipt.treeDigest !== spec.treeDigest ||
    receipt.runId !== spec.runId ||
    receipt.configDigest !== spec.configDigest ||
    receipt.sourceBuildIdentitySha256 !== sha256(spec.sourceBuildIdentity) ||
    receipt.selectedEvidenceBindingSha256 !== selectedBinding ||
    canonicalJson(receipt.componentDigests) !== canonicalJson(digests) ||
    !SHA256.test(receipt.bundleSha256 ?? "") ||
    !SHA256.test(receipt.pathSha256 ?? "") ||
    !Number.isSafeInteger(receipt.fileByteLength) ||
    receipt.fileByteLength < 1 ||
    receipt.fileByteLength > PRIVATE_EVIDENCE_MAX_BYTES ||
    receipt.atomicCreateOnly !== true ||
    receipt.fileMode !== "0600" ||
    receipt.parentDirectoryMode !== "0700" ||
    receipt.sameFilesystemAtomicLink !== true ||
    receipt.directoryEntrySynced !== true ||
    receipt.rereadVerified !== true
  ) {
    return false;
  }
  const { receiptSha256, ...unsigned } = receipt;
  return receiptSha256 === sha256(canonicalJson(unsigned));
}

function acceptedControlLedger(receipt, spec) {
  if (
    !exactKeys(receipt, [
      "authorizationAttestationSha256",
      "authorizationClaimSha256",
      "authorizationId",
      "authorizedMaximumCumulativeExposureUsd",
      "childLaunchDigests",
      "exactChildLaunchCount",
      "exactScopeCount",
      "receiptSha256",
      "reservationDigests",
      "reservedCumulativeExposureUsd",
      "runId",
      "schemaVersion",
      "spendAuthorizationSha256"
    ]) ||
    receipt.schemaVersion !==
      INTEGRATED_LIVE_DRILL_CONTROL_LEDGER_RECEIPT_SCHEMA ||
    receipt.runId !== spec.runId ||
    receipt.authorizedMaximumCumulativeExposureUsd !== "0.020000" ||
    receipt.exactChildLaunchCount !== 3 ||
    receipt.exactScopeCount !== 3 ||
    !Array.isArray(receipt.childLaunchDigests) ||
    receipt.childLaunchDigests.length !== 3 ||
    !Array.isArray(receipt.reservationDigests) ||
    receipt.reservationDigests.length !== 3 ||
    ![
      receipt.authorizationAttestationSha256,
      receipt.authorizationClaimSha256,
      receipt.receiptSha256,
      receipt.spendAuthorizationSha256,
      ...receipt.childLaunchDigests,
      ...receipt.reservationDigests
    ].every((value) => SHA256.test(value ?? "")) ||
    !/^0\.[0-9]{6}$/u.test(receipt.reservedCumulativeExposureUsd ?? "")
  ) {
    return false;
  }
  const { receiptSha256, ...unsigned } = receipt;
  return receiptSha256 === sha256(canonicalJson(unsigned));
}

export function buildIntegratedLiveDrillCandidateReceipt({
  spec,
  dvi,
  race,
  recovery,
  journalPath,
  journalRootPath,
  journalReceipt,
  journalIntentBindingSha256,
  postRelease,
  privateEvidencePath,
  privateEvidenceRootPath,
  forbiddenPrivateEvidenceRootPath,
  privateEvidenceReceipt,
  controlLedgerReceipt = null,
  authorityEvidenceId,
  authoritySelectedEvidenceDigest
}) {
  const acceptedSpec = parseIntegratedLiveDrillSpec(spec);
  const selectedBinding = selectedEvidenceBindingSha256(
    authorityEvidenceId,
    authoritySelectedEvidenceDigest
  );
  const componentDigests = componentDigestsFor({ dvi, race, recovery });
  const spendAuthorizationProven = acceptedControlLedger(
    controlLedgerReceipt,
    acceptedSpec
  );
  const verifiedPrivateEvidenceReceipt =
    verifyIntegratedLiveDrillPrivateEvidence({
      destinationPath: privateEvidencePath,
      evidenceRootPath: privateEvidenceRootPath,
      forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
      receipt: privateEvidenceReceipt,
      spec: acceptedSpec,
      dvi,
      race,
      recovery,
      authorityEvidenceId,
      authoritySelectedEvidenceDigest
    });
  const verifiedJournalReceipt = verifyIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: journalRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    receipt: journalReceipt,
    spec: acceptedSpec,
    requireComplete: true,
    expectedPhasePayloadSha256: {
      PRE_PROVIDER_INTENT: journalIntentBindingSha256,
      DVI_RESULT: componentDigests.dvi,
      AUTHORITY_RACE_RESULT: componentDigests.authorityRace,
      RECOVERY_RESULT: componentDigests.recovery,
      PRIVATE_EVIDENCE_RESULT: sha256(canonicalJson(
        verifiedPrivateEvidenceReceipt
      )),
      POST_RELEASE_VERIFICATION: sha256(canonicalJson(postRelease))
    }
  });
  if (
    !acceptedIntegratedLiveDrillDvi(dvi, acceptedSpec, selectedBinding) ||
    !acceptedIntegratedLiveDrillRace(race, acceptedSpec, dvi) ||
    !acceptedRecovery(recovery, acceptedSpec, race) ||
    !acceptedPrivateEvidence(
      verifiedPrivateEvidenceReceipt,
      acceptedSpec,
      selectedBinding,
      componentDigests
    )
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_COMPONENT_REJECTED");
  }
  const invariants = Object.freeze({
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
    preProviderJournalCurrentBytesBound: true,
    privateEvidenceCurrentBytesBound: true,
    signedRecoveryBundleCurrentBytesBound: true,
    fixedTopLevelProviderOperationCount: true,
    operationalCapabilityReturned: false,
    authorityTransferredByModelOrRecovery: false
  });
  const receipt = {
    schemaVersion: INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA,
    status: "INCOMPLETE_LIVE_GATES_PENDING",
    sourceCommit: acceptedSpec.sourceCommit,
    treeDigest: dvi.treeDigest,
    runId: acceptedSpec.runId,
    configDigest: acceptedSpec.configDigest,
    sourceBuildIdentitySha256: sha256(acceptedSpec.sourceBuildIdentity),
    componentDigests,
    privateEvidence: {
      bundleSha256: verifiedPrivateEvidenceReceipt.bundleSha256,
      sourceControlReceiptSha256:
        verifiedPrivateEvidenceReceipt.receiptSha256,
      currentBytesBound: true
    },
    preProviderJournal: {
      firstEntrySha256: verifiedJournalReceipt.firstEntrySha256,
      lastEntrySha256: verifiedJournalReceipt.lastEntrySha256,
      sourceControlReceiptSha256: verifiedJournalReceipt.receiptSha256,
      entryCount: verifiedJournalReceipt.entryCount,
      currentBytesBound: true,
      independentlyAttested: false
    },
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
      managedMcpRequestPayloadSha256:
        recovery.mcpProviderEvidence.rpcCalls[1].requestPayloadSha256,
      unauthorizedPrincipalDenied: true,
      auditsCommitted: 2,
      operationalCapabilitiesReturned: false,
      signedBundleCurrentBytesBound: true,
      signedBundleSourceControlReceiptSha256:
        recovery.signedBundlePersistence.receiptSha256,
      restartStableSignedBundleReuseProven: false
    },
    providerOperations: {
      aws: {
        cloudFormationDescribeStackResourceRequests: 1,
        lambdaInvokeRequests: 5,
        stsGetCallerIdentityRequests: 1
      },
      cockroachDb: {
        dviProofRuns: 1,
        authorityRaceRuns: 1,
        recoveryBrokerRuns: 1
      },
      managedMcp: {
        closeRequests: 1,
        initializeRequests: 1,
        initializedNotifications: 1,
        toolCallRequests: 1
      },
      cloudResourcesCreatedByDrill: 0
    },
    costControl: {
      operatorDeclaredMaximumAwsCostUsd: acceptedSpec.maximumAwsCostUsd,
      fixedTopLevelProviderOperationCount: true,
      completeProviderRequestAccounting: false,
      providerPricingVerified: false,
      actualAwsSpendVerified: false,
      spendAuthorizationProvenByReceipt: spendAuthorizationProven,
      authorizationControlLedgerReceiptSha256:
        spendAuthorizationProven ? controlLedgerReceipt.receiptSha256 : null,
      actualProviderBillingReceiptRequiredSeparately: true
    },
    acceptance: {
      accepted: false,
      finalReceiptSchema: INTEGRATED_LIVE_DRILL_SCHEMA,
      deploymentAttestationBound: false,
      preProviderJournalPersisted: false,
      privateEvidencePersisted: false,
      crashSafeRecoveryProven: false,
      blockers: [
        "SIGNED_PRE_POST_DEPLOYMENT_ATTESTATION_NOT_BOUND",
        "PRIVATE_RAW_EVIDENCE_NOT_INDEPENDENTLY_ATTESTED",
        "RESTART_STABLE_SIGNED_BUNDLE_REUSE_NOT_PROVEN",
        "CRASH_SAFE_RECOVERY_NOT_PROVEN",
        INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER,
        "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN",
        "PROVIDER_PRICING_AND_BILLING_NOT_PROVEN"
      ]
    },
    invariants,
    invariantCount: Object.keys(invariants).length,
    invariantViolations: 0,
    providerBacked: false,
    claimBoundary:
      "This sanitized candidate summarizes one runner-observed integrated synthetic component result whose claimed CockroachDB DVI selection, five claimed numeric-version Lambda invocations, overlapping authority race, replay and changed-input controls, and exact-winner canonical-bundle Managed MCP recovery share one binding with zero declared component-invariant violations. The candidate does not independently establish that any component receipt came from a provider, so providerBacked remains false. Before publication, the recovery runner create-only persists and rereads an owner-only canonical envelope containing the exact signed recovery bundle; a later invocation with the same unsigned bundle must reuse those first signature bytes. Reuse resyncs the validated file and parent and proves the current pathname, while its receipt marks the original create/link protocol unobserved. The current file bytes are bound, but actual restart reuse and crash continuity are not proven. Before the first component, a source-local owner-only journal durably records the run-intent digest; later create-only, fsynced entries hash-chain the currently observed component, private-evidence, and post-release digests. A source-local helper also writes a raw private component bundle outside the Git checkout. The candidate binds the currently reread journal, signed-bundle, and private-bundle bytes plus unkeyed source-control receipt digests. Those present-state checks are not independent evidence of the historical write protocol, durable retention, or crash continuity. The authorization ledger and signed one-use child tokens are atomic and restart-durable only on the exact declared authoritative root; cross-host strongly consistent claim authority and protection against an independently copied pre-launch ledger are not proven. This is not the accepted +1 receipt: no signed pre/post deployment attestation binds the invoked numeric version to exact release code, configuration, execution role, revisions, or alias target; independent journal attestation and a private-evidence finalizer remain mandatory; provider-backed restart-stable signed-bundle reuse and crash-safe single-call recovery are not yet proven; durable exact-one Managed MCP reconciliation across crash, restart, and ambiguous provider results is not proven; and provider pricing and billing remain separate fail-closed gates. The Managed MCP receipt binds one continuous negotiated session plus request, response, and result digests, but is not an independent provider signature. This candidate does not prove an exact release, provider execution, a real-world external effect, production suitability, availability, administrator exclusion, or authorize deployment, publication, or submission."
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: sha256(canonicalJson(receipt))
  });
}
