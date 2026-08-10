import {
  integratedLiveDrillAcceptanceCore,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillRunnerIdentityDigest,
  INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER,
  validateIntegratedLiveDrillEvidenceSet,
  validateIntegratedLiveDrillFinalizationStatement,
  validateIntegratedLiveDrillRunAuthorization
} from "./integrated-live-drill-authorization.js";
import { validateIntegratedLiveDrillConsumedControlLedger } from
  "./integrated-live-drill-control-ledger.js";
import {
  INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA,
  INTEGRATED_LIVE_DRILL_SCHEMA
} from "./integrated-live-drill.js";

export const INTEGRATED_LIVE_DRILL_PACKET_A_FINALIZATION_SCHEMA =
  "tideproof.highwater-drill-packet-a-finalization-validation.v1";
export const INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER =
  "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function validateCandidateReceipt(candidateReceipt, authorization) {
  const code = "INTEGRATED_LIVE_DRILL_PACKET_A_CANDIDATE_REJECTED";
  requireCondition(
    exactKeys(candidateReceipt, [
      "acceptance",
      "authority",
      "claimBoundary",
      "componentDigests",
      "configDigest",
      "costControl",
      "dvi",
      "invariantCount",
      "invariantViolations",
      "invariants",
      "preProviderJournal",
      "privateEvidence",
      "providerBacked",
      "providerOperations",
      "receiptSha256",
      "recovery",
      "runId",
      "schemaVersion",
      "sourceBuildIdentitySha256",
      "sourceCommit",
      "status",
      "treeDigest"
    ]) &&
      candidateReceipt.schemaVersion ===
        INTEGRATED_LIVE_DRILL_CANDIDATE_SCHEMA &&
      candidateReceipt.status === "INCOMPLETE_LIVE_GATES_PENDING" &&
      candidateReceipt.sourceCommit === authorization.payload.sourceCommit &&
      candidateReceipt.treeDigest === authorization.payload.treeDigest &&
      candidateReceipt.configDigest === authorization.payload.configDigest &&
      candidateReceipt.runId === authorization.payload.runId &&
      HEX_40.test(candidateReceipt.sourceCommit ?? "") &&
      HEX_40.test(candidateReceipt.treeDigest ?? "") &&
      HEX_64.test(candidateReceipt.configDigest ?? "") &&
      HEX_64.test(candidateReceipt.sourceBuildIdentitySha256 ?? "") &&
      UUID.test(candidateReceipt.runId ?? "") &&
      HEX_64.test(candidateReceipt.receiptSha256 ?? "") &&
      candidateReceipt.providerBacked === false &&
      candidateReceipt.invariantViolations === 0 &&
      candidateReceipt.acceptance?.accepted === false &&
      candidateReceipt.acceptance?.finalReceiptSchema ===
        INTEGRATED_LIVE_DRILL_SCHEMA &&
      Array.isArray(candidateReceipt.acceptance?.blockers) &&
      candidateReceipt.acceptance.blockers.includes(
        INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER
      ) &&
      candidateReceipt.acceptance.blockers.includes(
        INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER
      ) &&
      candidateReceipt.costControl?.spendAuthorizationProvenByReceipt ===
        true &&
      HEX_64.test(
        candidateReceipt.costControl
          ?.authorizationControlLedgerReceiptSha256 ?? ""
      ) &&
      candidateReceipt.recovery?.managedMcpCallCount === 1 &&
      candidateReceipt.recovery?.restartStableSignedBundleReuseProven ===
        false,
    code
  );
  const { receiptSha256, ...body } = candidateReceipt;
  requireCondition(
    receiptSha256 === integratedLiveDrillCanonicalSha256(body),
    code
  );
  return receiptSha256;
}

function packetAFinalizationDisposition({
  authorization,
  candidateReceiptSha256,
  controlLedgerReceipt,
  evidenceDigests,
  finalization
}) {
  const acceptanceCoreSha256 = integratedLiveDrillCanonicalSha256(
    integratedLiveDrillAcceptanceCore({
      authorization,
      evidenceDigests,
      candidateReceiptSha256
    })
  );
  requireCondition(
    finalization?.payload?.candidateReceiptSha256 ===
        candidateReceiptSha256 &&
      finalization.payload.acceptanceCoreSha256 === acceptanceCoreSha256,
    "INTEGRATED_LIVE_DRILL_PACKET_A_FINALIZATION_REJECTED"
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PACKET_A_FINALIZATION_SCHEMA,
    status: "PACKET_B_PROVIDER_ACCEPTANCE_PENDING",
    accepted: false,
    finalReleaseReady: false,
    acceptanceCoreSha256,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationId: authorization.payload.authorizationId,
    authorizationControlLedgerReceiptSha256:
      controlLedgerReceipt.receiptSha256,
    candidateReceiptSha256,
    configDigest: authorization.payload.configDigest,
    evidenceSetSha256: integratedLiveDrillCanonicalSha256(evidenceDigests),
    finalizationStatementSha256: integratedLiveDrillCanonicalSha256(
      finalization.attestation
    ),
    expectationSha256: authorization.payload.expectationSha256,
    packetBBlockers: Object.freeze([
      INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER
    ]),
    packetABoundaryBlockers: Object.freeze([
      INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER
    ]),
    runId: authorization.payload.runId,
    sourceCommit: authorization.payload.sourceCommit,
    treeDigest: authorization.payload.treeDigest,
    claimBoundary:
      "This receipt validates the Packet A candidate, typed signed evidence, signed deployment pair, and signed finalization bindings supplied to this function. It deliberately does not accept the integrated drill or the release. The exact-root authorization ledger is not a strongly consistent cross-host claim authority and remains an explicit Packet A boundary blocker. Packet B must independently prove durable exact-one Managed MCP behavior across crash, restart, and ambiguous provider results before any accepted receipt, release-ready claim, deployment claim, publication, or submission."
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export function validateIntegratedLiveDrillPacketAFinalization({
  authorizationAttestation,
  candidateReceipt,
  committedTrustRoot,
  deploymentAttestationPair,
  evidenceAttestations,
  expectation,
  finalizationStatement,
  forbiddenRootPath,
  humanAuthorizationTrustRoot,
  ledgerRootPath,
  runnerIdentity,
  spec,
  now = Date.now()
}) {
  const authorization = validateIntegratedLiveDrillRunAuthorization(
    authorizationAttestation,
    {
      spec,
      expectation,
      committedTrustRoot,
      humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: ledgerRootPath,
      now
    }
  );
  requireCondition(
    authorization.payload.authorizationClaimAuthority.runnerIdentitySha256 ===
      integratedLiveDrillRunnerIdentityDigest(runnerIdentity),
    "INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY_REJECTED"
  );
  const ledger = validateIntegratedLiveDrillConsumedControlLedger({
    authorization,
    ledgerRootPath,
    forbiddenRootPath
  });
  const candidateReceiptSha256 = validateCandidateReceipt(
    candidateReceipt,
    authorization
  );
  const evidenceDigests = validateIntegratedLiveDrillEvidenceSet(
    evidenceAttestations,
    deploymentAttestationPair,
    {
      authorization,
      candidateReceipt,
      controlLedgerReceipt: ledger.controlLedgerReceipt,
      expectation,
      now
    }
  );
  const finalization = validateIntegratedLiveDrillFinalizationStatement(
    finalizationStatement,
    {
      expectation,
      authorization,
      evidenceDigests,
      candidateReceiptSha256,
      now
    }
  );
  return packetAFinalizationDisposition({
    authorization,
    candidateReceiptSha256,
    controlLedgerReceipt: ledger.controlLedgerReceipt,
    evidenceDigests,
    finalization
  });
}

export const __test = Object.freeze({
  packetAFinalizationDisposition,
  validateCandidateReceipt
});
