import { createHash } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";

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
      "configDigest",
      "functionArn",
      "raceId",
      "runId",
      "schemaVersion",
      "sourceBuildIdentity",
      "sourceCommit"
    ]) ||
    value.schemaVersion !== INTEGRATED_LIVE_DRILL_SPEC_SCHEMA ||
    !SHA256.test(value.configDigest) ||
    !SHA1.test(value.sourceCommit) ||
    !UUID.test(value.raceId) ||
    !UUID.test(value.runId) ||
    typeof value.sourceBuildIdentity !== "string" ||
    value.sourceBuildIdentity.length < 8 ||
    value.sourceBuildIdentity.length > 256 ||
    !/^arn:aws[a-zA-Z-]*:lambda:us-east-1:\d{12}:function:[A-Za-z0-9-_]{1,64}:[1-9][0-9]*$/.test(
      value.functionArn
    )
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_SPEC_REJECTED");
  }
  return Object.freeze({ ...value });
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
    SHA1.test(dvi.treeDigest ?? "") &&
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
  return (
    race?.schemaVersion === "tideproof.aws-authority-race-receipt.v7" &&
    race.status === "PASS" &&
    race.sourceCommit === spec.sourceCommit &&
    race.treeDigest === dvi.treeDigest &&
    race.configDigest === spec.configDigest &&
    race.raceId === spec.raceId &&
    race.runId === spec.runId &&
    race.dvi?.authorityEvidenceBindingSha256 ===
      dvi.drill.authorityEvidenceBindingSha256 &&
    race.dvi?.selectedEvidenceBindingSha256 ===
      dvi.drill.selectedEvidenceBindingSha256 &&
    race.contenders === 2 &&
    race.overlappingDatabaseIntervals === true &&
    race.distinctDatabaseSessions === true &&
    race.durableStateVerified === true &&
    race.durableState?.receiptCount === 2 &&
    race.durableState?.outboxCount === 1 &&
    race.durableState?.protectedEffectCount === 0 &&
    race.protectedEffectExecuted === false &&
    race.authorityTransferredByModel === false &&
    race.replay?.operationId === race.winner?.operationId &&
    race.replay?.requestDigest === race.winner?.requestDigest &&
    race.replay?.outcome === "resource_reserved" &&
    race.replay?.replayKind === "operation_replay" &&
    race.replay?.exactDecisionReturned === true &&
    race.changedInputDenial?.operationId === race.winner?.operationId &&
    race.changedInputDenial?.code === "OPERATION_DIGEST_MISMATCH" &&
    race.changedInputDenial?.denied === true
  );
}

function acceptedRecovery(recovery, spec, race) {
  const denials = recovery?.runnerCredentialDenials;
  return (
    recovery?.gate ===
      "noninteractive Managed MCP deterministic recovery broker" &&
    recovery.passed === true &&
    recovery.sourceBuildIdentity === spec.sourceBuildIdentity &&
    recovery.dvi?.authorityEvidenceBindingSha256 ===
      race.dvi.authorityEvidenceBindingSha256 &&
    recovery.dvi?.selectedEvidenceBindingSha256 ===
      race.dvi.selectedEvidenceBindingSha256 &&
    recovery.endpointSeparation?.distinctHostnames === true &&
    recovery.endpointSeparation?.distinctClusterIds === true &&
    recovery.replayOutcome === "bundle_replay" &&
    recovery.mcpTool === "select_query" &&
    recovery.mcpCallCount === 1 &&
    recovery.recoveryStatus === "RECOVERED_CONTEXT_ONLY" &&
    recovery.unauthorizedStatus === "UNKNOWN_DO_NOT_ACT" &&
    recovery.preReadAuditCommitted === true &&
    recovery.terminalAuditCommitted === true &&
    recovery.authorityTransferred === false &&
    recovery.requiresFreshAuthorization === true &&
    recovery.operationalCapabilitiesReturned === false &&
    denials &&
    Object.values(denials).length === 4 &&
    Object.values(denials).every(Boolean)
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
    managedMcpCalledExactlyOnce: true,
    unboundPrincipalDeniedBeforeMcp: true,
    bothRecoveryAuditsCommitted: true,
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
    invariants,
    invariantCount: Object.keys(invariants).length,
    invariantViolations: 0,
    providerBacked: true,
    claimBoundary:
      "This sanitized receipt proves one exact-release provider-backed integrated synthetic drill whose CockroachDB DVI selection, overlapping two-Lambda authority race, replay and changed-input controls, and exact-winner Managed MCP recovery share one binding with zero declared invariant violations. It must be accepted together with the separately verified 100-run deterministic offline receipt. It does not prove a real-world external effect, production suitability, availability, administrator exclusion, or authorize deployment, publication, or submission."
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: sha256(canonicalJson(receipt))
  });
}
