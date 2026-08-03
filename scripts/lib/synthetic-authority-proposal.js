import { createHash, randomUUID } from "node:crypto";
import { canonicalJson } from "../../src/cloud/canonical-json.js";
import {
  dviRankedSequenceSha256For,
  dviSelectionBindingSha256For
} from "../../src/cloud/dvi-selection.js";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export async function authorizeSyntheticProposal(
  store,
  request,
  {
    evidenceDigest,
    retrievalId = randomUUID(),
    admittedAt = new Date(Date.now() - 1_000).toISOString(),
    expiresAt = new Date(Date.now() + 5 * 60_000).toISOString(),
    allowDenied = false,
    proposalAuthorizer = null,
    requestedSelectedEvidenceId = request.evidenceId,
    requestedSelectedEvidenceDigest = null
  } = {}
) {
  const snapshot = evidenceDigest
    ? null
    : await store.verificationSnapshot({
        tenantId: request.tenantId,
        evidenceId: request.evidenceId
      });
  const selectedEvidenceDigest =
    evidenceDigest ?? snapshot?.evidence?.evidence_digest;
  if (!/^[0-9a-f]{64}$/u.test(selectedEvidenceDigest ?? "")) {
    throw new Error("SYNTHETIC_PROPOSAL_EVIDENCE_DIGEST_MISSING");
  }
  const selection = {
    sourceCommit: "0".repeat(40),
    treeDigest: "1".repeat(40),
    specSha256: sha256(canonicalJson({
      schemaVersion: "tideproof.synthetic-dvi-spec.v1",
      tenantId: request.tenantId,
      runId: request.runId,
      incidentId: request.incidentId,
      retrievalId
    })),
    tenantId: request.tenantId,
    runId: request.runId,
    incidentId: request.incidentId,
    retrievalId,
    agency: request.agency,
    policyVersion: "g1-admissibility-v2",
    admittedAt,
    expiresAt,
    rankedSequenceSha256: dviRankedSequenceSha256For([{
      evidenceId: request.evidenceId,
      evidenceDigest: selectedEvidenceDigest
    }]),
    queryEmbeddingSha256: sha256("[0.78,0.14,0.08]"),
    resultLimit: 1,
    selectedRank: 1,
    selectedEvidenceId: request.evidenceId,
    selectedEvidenceDigest
  };
  const authorityEvidenceBindingSha256 =
    dviSelectionBindingSha256For(selection);
  await store.recordDviSelectionReceiptForTest(selection);
  const dviAuthorization = {
    dviProposal: {
      tenantId: request.tenantId,
      runId: request.runId,
      incidentId: request.incidentId,
      retrievalId,
      authorityEvidenceBindingSha256,
      selectedEvidenceId: request.evidenceId,
      selectedEvidenceDigest,
      policyVersion: "g1-admissibility-v2",
      selectedRank: 1,
      admittedAt,
      expiresAt
    },
    selectedEvidenceId: request.evidenceId,
    selectedEvidenceDigest
  };
  const logicalAction = {
    tenantId: request.tenantId,
    incidentId: request.incidentId,
    resourceId: request.resourceId,
    agency: request.agency,
    actionKind: "dispatch_rescue_unit",
    payload: request.payload
  };
  const result = proposalAuthorizer === null
    ? await store.authorizeDviProposal({
        ...dviAuthorization,
        logicalAction
      })
    : await proposalAuthorizer({
      tenantId: request.tenantId,
      retrievalId,
      expectedRunId: request.runId,
      expectedIncidentId: request.incidentId,
      requestedSelectedEvidenceId,
      requestedSelectedEvidenceDigest:
        requestedSelectedEvidenceDigest ?? selectedEvidenceDigest,
      logicalAction
    });
  const acceptedOutcome = [
    "proposal_authorized",
    "proposal_authorization_replay"
  ].includes(result.outcome);
  const authorityCurrent =
    result.authorizationCurrent ?? result.authorityCurrent ?? null;
  const authorizationAccepted = acceptedOutcome && authorityCurrent === true;
  if (!allowDenied && !authorizationAccepted) {
    throw new Error(
      `SYNTHETIC_PROPOSAL_AUTHORIZATION_FAILED:${result.reason ?? "unknown"}`
    );
  }
  if (!authorizationAccepted) {
    const authorization = { ...result };
    for (const field of ["dviAuthorization", "proposal", "identity"]) {
      delete authorization[field];
    }
    return { authorization };
  }
  return {
    dviAuthorization: result.dviAuthorization ?? dviAuthorization,
    proposal: result.proposal ?? result.identity ?? null,
    authorization: result
  };
}

export async function authorizeSyntheticContenders(store, requests, options) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new TypeError("requests must contain at least one contender");
  }
  const contenders = [];
  for (let index = 0; index < requests.length; index += 1) {
    const request = {
      ...requests[index],
      payload: {
        ...requests[index].payload,
        logicalDispatch: `contender-${String(index + 1).padStart(3, "0")}`
      }
    };
    const authorized = await authorizeSyntheticProposal(
      store,
      request,
      options
    );
    contenders.push({
      ...request,
      dviAuthorization: authorized.dviAuthorization
    });
  }
  return contenders;
}

export const __test = Object.freeze({ canonicalJson, sha256 });
