import { randomUUID } from "node:crypto";
import {
  AuthorityStore,
  OperationDigestMismatchError
} from "../src/cloud/authority-store.js";
import {
  authorizeSyntheticContenders,
  authorizeSyntheticProposal
} from "./lib/synthetic-authority-proposal.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

const SYNTHETIC_SIGNER = createSyntheticEvidenceSigner();

function positiveInteger(value, fallback, name) {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return parsed;
}

function requireDatabaseUrl() {
  const value = process.env.DATABASE_URL;
  if (!value) {
    throw new Error("DATABASE_URL is required");
  }
  return value;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function isoFromNow(offsetMs) {
  return new Date(Date.now() + offsetMs).toISOString();
}

class Barrier {
  #arrived = 0;
  #expected;
  #release;
  #released;
  #timer;

  constructor(expected, timeoutMs = 30_000) {
    this.#expected = expected;
    this.#released = new Promise((resolve, reject) => {
      this.#release = resolve;
      this.#timer = setTimeout(
        () =>
          reject(
            new Error(
              `barrier timed out after ${this.#arrived}/${this.#expected} arrivals`
            )
          ),
        timeoutMs
      );
    });
  }

  async wait() {
    this.#arrived += 1;
    if (this.#arrived === this.#expected) {
      clearTimeout(this.#timer);
      this.#release();
    }
    await this.#released;
  }
}

function baseRequest({
  tenantId,
  runId,
  incidentId,
  resourceId,
  evidenceId,
  index
}) {
  return {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    operationId: randomUUID(),
    agentId: `synthetic-agent-${String(index).padStart(2, "0")}`,
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-highwater",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-delta"
    }
  };
}

async function prepareAdmissibleFixture(store, {
  tenantId,
  runId,
  incidentId,
  resourceId,
  evidenceId
}) {
  await SYNTHETIC_SIGNER.register(store, tenantId);
  const appended = await SYNTHETIC_SIGNER.append(store, {
    tenantId,
    evidenceId,
    incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt: isoFromNow(-60_000),
    validFrom: isoFromNow(-120_000),
    validUntil: isoFromNow(30 * 60_000),
    conflictStatus: "none",
    assertion: "Synthetic rescue unit is eligible for the Highwater drill.",
    embedding: [0.82, 0.11, 0.07]
  });
  assert(appended.outcome === "evidence_verified", "evidence was not verified");
  await store.prepareResource({ tenantId, runId, resourceId });
}

async function recordContextMismatch(store, input, authenticatedAgentId) {
  try {
    const result = await store.recordProtectedEffect(input, {
      authenticatedAgentId
    });
    if (
      result.outcome === "stale_or_unauthorized_fence_denied" &&
      /^proposal_authorization_/u.test(result.reason ?? "")
    ) {
      return { outcome: "identity_binding_rejected" };
    }
  } catch (error) {
    if (
      error instanceof TypeError &&
      /AUTHORITY_(?:PROPOSAL_REQUEST|SELECTED_EVIDENCE)_MISMATCH/u.test(
        error.message
      )
    ) {
      return { outcome: "identity_binding_rejected" };
    }
    throw error;
  }
  throw new Error("changed authority context reached database mutation");
}

async function runRace(store, { proofLabel, runNumber, contenderCount }) {
  const tenantId = randomUUID();
  const runId = randomUUID();
  const incidentId = randomUUID();
  const evidenceId = randomUUID();
  const resourceId = `${proofLabel}-race-${String(runNumber).padStart(3, "0")}`;
  await prepareAdmissibleFixture(store, {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId
  });

  const requests = await authorizeSyntheticContenders(
    store,
    Array.from({ length: contenderCount }, (_, index) =>
      baseRequest({
        tenantId,
        runId,
        incidentId,
        resourceId,
        evidenceId,
        index: index + 1
      })
    )
  );
  const barrier = new Barrier(contenderCount);
  const settled = await Promise.allSettled(
    requests.map((request) => store.spendAuthority(request, { barrier }))
  );
  const rejected = settled.filter(({ status }) => status === "rejected");
  if (rejected.length > 0) {
    throw rejected[0].reason;
  }
  const attempts = settled.map(({ value }) => value);
  const winners = attempts.filter(
    ({ outcome }) => outcome === "resource_reserved"
  );
  const denials = attempts.filter(
    ({ outcome }) => outcome === "resource_held_denied"
  );
  const snapshot = await store.snapshot({ tenantId, resourceId });

  assert(winners.length === 1, `expected one winner; found ${winners.length}`);
  assert(
    denials.length === contenderCount - 1,
    `expected ${contenderCount - 1} held denials; found ${denials.length}`
  );
  assert(
    snapshot.receipts.length === contenderCount,
    "every contender must have one durable terminal receipt"
  );
  assert(
    snapshot.receipts.filter(({ outcome }) => outcome === "resource_reserved")
      .length === 1,
    "expected one durable reserved receipt"
  );
  assert(
    snapshot.receipts.filter(
      ({ outcome }) => outcome === "resource_held_denied"
    ).length === contenderCount - 1,
    "expected one durable held-denial receipt per non-winner"
  );
  assert(snapshot.outbox.length === 1, "expected one durable outbox intent");
  assert(snapshot.effects.length === 0, "race must not execute an effect");
  assert(
    snapshot.resource.current_fence === "1",
    `expected first fence 1; got ${snapshot.resource.current_fence}`
  );
  assert(
    snapshot.resource.holder_operation_id ===
      winners[0].receipt.operation_id,
    "resource holder does not match the winner"
  );
  assert(
    attempts.every(
      ({ transaction }) => transaction.isolation === "serializable"
    ),
    "a contender did not report serializable isolation"
  );

  const backendIds = new Set(
    attempts.map(({ transaction }) => transaction.initialBackendId)
  );
  assert(
    backendIds.size === contenderCount,
    `expected ${contenderCount} distinct database sessions; found ${backendIds.size}`
  );

  const loserIndex = attempts.findIndex(
    ({ outcome }) => outcome === "resource_held_denied"
  );
  await store.expireLeaseForTest({ tenantId, resourceId });
  const deniedReplay = await store.spendAuthority(requests[loserIndex]);
  const replaySnapshot = await store.snapshot({ tenantId, resourceId });
  assert(
    deniedReplay.outcome === "operation_replay",
    "a previously denied operation did not replay its denial"
  );
  assert(
    deniedReplay.receipt.outcome === "resource_held_denied",
    "a denied operation changed outcome after lease expiry"
  );
  assert(
    replaySnapshot.receipts.length === contenderCount &&
      replaySnapshot.outbox.length === 1 &&
      replaySnapshot.resource.current_fence === "1",
    "denied replay changed durable authority state"
  );

  const semanticReplayRequest = {
    ...requests[loserIndex],
    operationId: randomUUID()
  };
  const semanticReplay = await store.spendAuthority(semanticReplayRequest);
  assert(
    semanticReplay.outcome === "logical_authority_replay" &&
      semanticReplay.receipt.outcome === "resource_reserved",
    "replacement transport did not reconcile to the positive logical act"
  );

  let digestMismatch = false;
  try {
    await store.spendAuthority({
      ...requests[loserIndex],
      agentId: `${requests[loserIndex].agentId}-changed`
    });
  } catch (error) {
    digestMismatch = error instanceof OperationDigestMismatchError;
  }
  assert(digestMismatch, "operation ID reuse with changed input was not denied");

  return {
    tenantId,
    runId,
    incidentId,
    resourceId,
    winnerAgentId: winners[0].receipt.agent_id,
    winnerOperationId: winners[0].receipt.operation_id,
    fencingToken: winners[0].receipt.fencing_token,
    durableReceiptCount: snapshot.receipts.length,
    durableDenialCount: denials.length,
    outboxCount: snapshot.outbox.length,
    distinctBackendCount: backendIds.size,
    serializableRetryCount: attempts.reduce(
      (sum, { transaction }) =>
        sum + transaction.serializableRetries,
      0
    ),
    retryCodes: attempts.flatMap(
      ({ transaction }) => transaction.retryCodes
    ),
    deniedReplayOutcome: deniedReplay.receipt.outcome,
    semanticReplayOutcome: semanticReplay.outcome,
    changedRequestDenied: digestMismatch
  };
}

async function runConcurrentReplayProof(store, proofLabel, contenderCount) {
  const runCase = async (label, varyOperationId) => {
    const tenantId = randomUUID();
    const runId = randomUUID();
    const incidentId = randomUUID();
    const evidenceId = randomUUID();
    const resourceId = `${proofLabel}-replay-${label}`;
    await prepareAdmissibleFixture(store, {
      tenantId,
      runId,
      incidentId,
      resourceId,
      evidenceId
    });
    const rawBase = baseRequest({
      tenantId,
      runId,
      incidentId,
      resourceId,
      evidenceId,
      index: label === "operation" ? 401 : 402
    });
    const authorized = await authorizeSyntheticProposal(store, rawBase);
    const base = {
      ...rawBase,
      dviAuthorization: authorized.dviAuthorization
    };
    const requests = Array.from(
      { length: contenderCount },
      () =>
        varyOperationId
          ? { ...base, operationId: randomUUID() }
          : { ...base }
    );
    const settled = await Promise.allSettled(
      requests.map((request) => store.spendAuthority(request))
    );
    const rejected = settled.filter(({ status }) => status === "rejected");
    if (rejected.length > 0) {
      throw rejected[0].reason;
    }
    const results = settled.map(({ value }) => value);
    const winnerIndex = results.findIndex(
      ({ outcome }) => outcome === "resource_reserved"
    );
    const replayKind = varyOperationId
      ? "logical_authority_replay"
      : "operation_replay";
    const replayCount = results.filter(
      ({ outcome }) => outcome === replayKind
    ).length;
    const snapshot = await store.snapshot({ tenantId, resourceId });
    assert(winnerIndex >= 0, `${label} replay race had no winner`);
    assert(
      results.filter(({ outcome }) => outcome === "resource_reserved")
        .length === 1,
      `${label} replay race had multiple winners`
    );
    assert(
      replayCount === contenderCount - 1,
      `${label} replay race did not reconcile every duplicate`
    );
    assert(
      snapshot.receipts.length === 1 &&
        snapshot.outbox.length === 1 &&
        snapshot.effects.length === 0 &&
        snapshot.resource.current_fence === "1",
      `${label} replay race changed durable authority more than once`
    );
    return {
      contenders: contenderCount,
      reserved: 1,
      replayKind,
      replayCount,
      durableReceiptCount: snapshot.receipts.length,
      outboxCount: snapshot.outbox.length,
      protectedEffectCount: snapshot.effects.length,
      fenceAfter: snapshot.resource.current_fence,
      winningRequest: requests[winnerIndex]
    };
  };

  const operation = await runCase("operation", false);
  const semantic = await runCase("semantic", true);
  const exactWinnerReplay = await store.spendAuthority(
    operation.winningRequest
  );
  assert(
    exactWinnerReplay.outcome === "operation_replay" &&
      exactWinnerReplay.receipt.outcome === "resource_reserved",
    "winner did not replay its committed receipt"
  );

  const changedFields = [
    {
      field: "agentId",
      input: {
        ...operation.winningRequest,
        agentId: `${operation.winningRequest.agentId}-changed`
      }
    },
    {
      field: "effectKey",
      input: {
        ...operation.winningRequest,
        effectKey: randomUUID()
      }
    },
    {
      field: "payload",
      input: {
        ...operation.winningRequest,
        payload: {
          ...operation.winningRequest.payload,
          destination: "synthetic-zone-changed"
        }
      }
    }
  ];
  const changedRequestDenials = [];
  for (const changed of changedFields) {
    let denied = false;
    try {
      const result = await store.spendAuthority(changed.input);
      denied =
        result.outcome === "authorization_denied" &&
        /^proposal_authorization_/u.test(result.reason ?? "");
    } catch (error) {
      denied = error instanceof OperationDigestMismatchError;
    }
    assert(denied, `${changed.field} mutation reused an operation ID`);
    changedRequestDenials.push({ field: changed.field, denied });
  }

  const publicResult = ({ winningRequest, ...result }) => result;
  return {
    operation: publicResult(operation),
    semantic: publicResult(semantic),
    exactWinnerReplayOutcome: exactWinnerReplay.outcome,
    changedRequestDenials
  };
}

async function runRuntimeIdentityNegativeProof(store, proofLabel) {
  const mismatchTenantId = randomUUID();
  const mismatchRunId = randomUUID();
  const mismatchIncidentId = randomUUID();
  const mismatchEvidenceId = randomUUID();
  const mismatchResourceId = `${proofLabel}-identity-mismatch`;
  await prepareAdmissibleFixture(store, {
    tenantId: mismatchTenantId,
    runId: mismatchRunId,
    incidentId: mismatchIncidentId,
    resourceId: mismatchResourceId,
    evidenceId: mismatchEvidenceId
  });
  const rawMismatchRequest = baseRequest({
    tenantId: mismatchTenantId,
    runId: mismatchRunId,
    incidentId: mismatchIncidentId,
    resourceId: mismatchResourceId,
    evidenceId: mismatchEvidenceId,
    index: 151
  });
  const mismatchAuthorization = await authorizeSyntheticProposal(
    store,
    rawMismatchRequest
  );
  const forgedEvidenceId = randomUUID();
  await SYNTHETIC_SIGNER.append(store, {
    tenantId: mismatchTenantId,
    evidenceId: forgedEvidenceId,
    incidentId: mismatchIncidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt: isoFromNow(-60_000),
    validFrom: isoFromNow(-120_000),
    validUntil: isoFromNow(30 * 60_000),
    conflictStatus: "none",
    assertion: "Synthetic forged-selection evidence B.",
    embedding: [0.81, 0.12, 0.07]
  });
  const forgedEvidence = await store.verificationSnapshot({
    tenantId: mismatchTenantId,
    evidenceId: forgedEvidenceId
  });
  const beforeForgedSelection = await store.authorityIdentityStateForTest({
    tenantId: mismatchTenantId,
    resourceId: mismatchResourceId
  });
  const forgedSelection = await store.authorizeDviProposal({
    dviProposal: {
      ...mismatchAuthorization.dviAuthorization.dviProposal,
      selectedEvidenceId: forgedEvidenceId,
      selectedEvidenceDigest: forgedEvidence.evidence.evidence_digest
    },
    selectedEvidenceId: forgedEvidenceId,
    selectedEvidenceDigest: forgedEvidence.evidence.evidence_digest,
    logicalAction: {
      tenantId: mismatchTenantId,
      incidentId: mismatchIncidentId,
      resourceId: mismatchResourceId,
      agency: rawMismatchRequest.agency,
      actionKind: "dispatch_rescue_unit",
      payload: rawMismatchRequest.payload
    }
  });
  const afterForgedSelection = await store.authorityIdentityStateForTest({
    tenantId: mismatchTenantId,
    resourceId: mismatchResourceId
  });
  assert(
    forgedSelection.outcome === "proposal_authorization_denied" &&
      forgedSelection.reason === "dvi_selection_receipt_mismatch",
    "DVI binding A authorized selected evidence B"
  );
  assert(
    JSON.stringify(afterForgedSelection) ===
      JSON.stringify(beforeForgedSelection),
    "forged DVI selection changed durable authority identity state"
  );
  const beforeMismatch = await store.snapshot({
    tenantId: mismatchTenantId,
    resourceId: mismatchResourceId
  });
  let mismatchRejected = false;
  try {
    await store.spendAuthority({
      ...rawMismatchRequest,
      evidenceId: randomUUID(),
      dviAuthorization: mismatchAuthorization.dviAuthorization
    });
  } catch (error) {
    mismatchRejected =
      error instanceof TypeError &&
      error.message === "AUTHORITY_SELECTED_EVIDENCE_MISMATCH";
  }
  const afterMismatch = await store.snapshot({
    tenantId: mismatchTenantId,
    resourceId: mismatchResourceId
  });
  assert(mismatchRejected, "DVI selection A authorized request B");
  assert(
    beforeMismatch.resource.current_fence ===
        afterMismatch.resource.current_fence &&
      beforeMismatch.receipts.length === afterMismatch.receipts.length &&
      beforeMismatch.outbox.length === afterMismatch.outbox.length &&
      beforeMismatch.effects.length === afterMismatch.effects.length,
    "DVI selection mismatch changed durable authority state"
  );

  const replacementTenantId = randomUUID();
  const replacementRunId = randomUUID();
  const replacementIncidentId = randomUUID();
  const replacementEvidenceId = randomUUID();
  const replacementResourceId = `${proofLabel}-identity-replacement`;
  await prepareAdmissibleFixture(store, {
    tenantId: replacementTenantId,
    runId: replacementRunId,
    incidentId: replacementIncidentId,
    resourceId: replacementResourceId,
    evidenceId: replacementEvidenceId
  });
  const rawOriginal = baseRequest({
    tenantId: replacementTenantId,
    runId: replacementRunId,
    incidentId: replacementIncidentId,
    resourceId: replacementResourceId,
    evidenceId: replacementEvidenceId,
    index: 152
  });
  const originalAuthorization = await authorizeSyntheticProposal(
    store,
    rawOriginal
  );
  const originalRequest = {
    ...rawOriginal,
    dviAuthorization: originalAuthorization.dviAuthorization
  };
  const originalDecision = await store.spendAuthority(originalRequest);
  assert(
    originalDecision.outcome === "resource_reserved",
    "original logical authority was not reserved"
  );
  const originalEffect = await store.recordProtectedEffect(
    {
      ...originalRequest,
      fencingToken: originalDecision.receipt.fencing_token
    },
    { authenticatedAgentId: originalRequest.agentId }
  );
  assert(
    originalEffect.outcome === "protected_effect_recorded",
    "original logical effect was not recorded"
  );
  await store.expireLeaseForTest({
    tenantId: replacementTenantId,
    resourceId: replacementResourceId
  });

  const replacementRequest = {
    ...baseRequest({
      tenantId: replacementTenantId,
      runId: replacementRunId,
      incidentId: replacementIncidentId,
      resourceId: replacementResourceId,
      evidenceId: replacementEvidenceId,
      index: 153
    }),
    leaseMs: 60_000,
    dviAuthorization: originalAuthorization.dviAuthorization
  };
  assert(
    replacementRequest.operationId !== originalRequest.operationId &&
      replacementRequest.agentId !== originalRequest.agentId &&
      replacementRequest.intentNonce !== originalRequest.intentNonce &&
      replacementRequest.effectKey !== originalRequest.effectKey &&
      replacementRequest.leaseMs !== originalRequest.leaseMs,
    "replacement did not change every transport identity field"
  );
  const replacementDecision = await store.spendAuthority(
    replacementRequest
  );
  assert(
    replacementDecision.outcome === "logical_authority_replay" &&
      replacementDecision.receipt.operation_id ===
        originalDecision.receipt.operation_id,
    "expired-lease replacement reminted logical authority"
  );
  const replacementEffect = await store.recordProtectedEffect(
    {
      ...replacementRequest,
      fencingToken: originalDecision.receipt.fencing_token
    },
    { authenticatedAgentId: replacementRequest.agentId }
  );
  const replacementSnapshot = await store.snapshot({
    tenantId: replacementTenantId,
    resourceId: replacementResourceId
  });
  assert(
    replacementEffect.outcome === "effect_already_recorded" &&
      replacementEffect.replayKind === "logical_authority_replay",
    "expired-lease replacement reminted the protected effect"
  );
  assert(
    replacementSnapshot.receipts.length === 1 &&
      replacementSnapshot.outbox.length === 1 &&
      replacementSnapshot.effects.length === 1 &&
      replacementSnapshot.resource.current_fence === "1",
    "expired-lease replacement changed durable logical effect state"
  );
  const beforeNewRetrieval = await store.authorityIdentityStateForTest({
    tenantId: replacementTenantId,
    resourceId: replacementResourceId
  });
  const newRetrieval = await authorizeSyntheticProposal(store, rawOriginal, {
    retrievalId: randomUUID(),
    allowDenied: true
  });
  const afterNewRetrieval = await store.authorityIdentityStateForTest({
    tenantId: replacementTenantId,
    resourceId: replacementResourceId
  });
  assert(
    newRetrieval.authorization.outcome ===
        "proposal_authorization_denied" &&
      newRetrieval.authorization.reason ===
        "logical_authority_already_spent",
    "new retrieval reminted an already-spent logical authority"
  );
  for (const field of [
    "proposal_receipt_count",
    "epoch_count",
    "maximum_epoch",
    "authority_receipt_count",
    "outbox_count",
    "protected_effect_count",
    "current_fence"
  ]) {
    assert(
      afterNewRetrieval[field] === beforeNewRetrieval[field],
      `new retrieval changed ${field}`
    );
  }

  return {
    selectedEvidenceMismatch: {
      forgedBindingRejected: true,
      rejectedBeforeSpend: mismatchRejected,
      receiptCount: afterMismatch.receipts.length,
      outboxCount: afterMismatch.outbox.length,
      protectedEffectCount: afterMismatch.effects.length,
      fenceAfter: afterMismatch.resource.current_fence
    },
    expiredLeaseReplacement: {
      decisionOutcome: replacementDecision.outcome,
      effectOutcome: replacementEffect.outcome,
      replayKind: replacementEffect.replayKind,
      durableReceiptCount: replacementSnapshot.receipts.length,
      outboxCount: replacementSnapshot.outbox.length,
      protectedEffectCount: replacementSnapshot.effects.length,
      fenceAfter: replacementSnapshot.resource.current_fence,
      newRetrievalOutcome: newRetrieval.authorization.outcome,
      newRetrievalReason: newRetrieval.authorization.reason,
      authorizationEpoch: afterNewRetrieval.maximum_epoch
    }
  };
}

async function runExpiredUnspentReplacementProof(store, proofLabel) {
  const tenantId = randomUUID();
  const runId = randomUUID();
  const incidentId = randomUUID();
  const evidenceId = randomUUID();
  const resourceId = `${proofLabel}-expired-unspent-replacement`;
  await prepareAdmissibleFixture(store, {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId
  });
  const request = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 154
  });
  const original = await authorizeSyntheticProposal(store, request);
  const proposalBoundary = await store.expireProposalAtDatabaseNowForTest({
    tenantId,
    proposalDigest: original.proposal.proposal_digest
  });
  assert(
    proposalBoundary.exact_boundary === true,
    "unspent proposal did not reach the exact database-time expiry boundary"
  );
  const expiredSpend = await store.spendAuthority({
    ...request,
    dviAuthorization: original.dviAuthorization
  });
  assert(
    expiredSpend.outcome === "authorization_denied" &&
      expiredSpend.reason === "proposal_authorization_expired" &&
      expiredSpend.durableMutation === false,
    "exact-boundary proposal expiry remained spendable"
  );
  const beforeReplacement = await store.authorityIdentityStateForTest({
    tenantId,
    resourceId
  });
  const replacement = await authorizeSyntheticProposal(store, request, {
    retrievalId: randomUUID(),
    allowDenied: true
  });
  const afterReplacement = await store.authorityIdentityStateForTest({
    tenantId,
    resourceId
  });
  assert(
    replacement.authorization.outcome ===
        "proposal_authorization_denied" &&
      replacement.authorization.reason ===
        "explicit_new_authorization_required",
    "expired unspent proposal implicitly minted a replacement epoch"
  );
  for (const field of [
    "proposal_receipt_count",
    "epoch_count",
    "maximum_epoch",
    "authority_receipt_count",
    "outbox_count",
    "protected_effect_count",
    "current_fence"
  ]) {
    assert(
      afterReplacement[field] === beforeReplacement[field],
      `expired unspent replacement changed ${field}`
    );
  }
  assert(
    afterReplacement.proposal_receipt_count === "1" &&
      afterReplacement.maximum_epoch === "1" &&
      afterReplacement.authority_receipt_count === "0" &&
      afterReplacement.outbox_count === "0" &&
      afterReplacement.protected_effect_count === "0" &&
      afterReplacement.current_fence === "0",
    "expired unspent replacement changed durable authority state"
  );
  return {
    expiredSpendOutcome: expiredSpend.outcome,
    expiredSpendReason: expiredSpend.reason,
    expiredSpendDurableMutation: expiredSpend.durableMutation,
    replacementOutcome: replacement.authorization.outcome,
    replacementReason: replacement.authorization.reason,
    proposalReceiptCount: afterReplacement.proposal_receipt_count,
    maximumEpoch: afterReplacement.maximum_epoch,
    authorityReceiptCount: afterReplacement.authority_receipt_count,
    outboxCount: afterReplacement.outbox_count,
    protectedEffectCount: afterReplacement.protected_effect_count,
    fenceAfter: afterReplacement.current_fence
  };
}

async function runHeldTransactionExpiryProof(store, proofLabel) {
  const tenantId = randomUUID();
  const runId = randomUUID();
  const incidentId = randomUUID();
  const evidenceId = randomUUID();
  const resourceId = `${proofLabel}-held-transaction-expiry`;
  await prepareAdmissibleFixture(store, {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId
  });
  const request = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 155
  });
  const authorization = await authorizeSyntheticProposal(store, request);
  await store.setProposalExpiryAfterMsForTest({
    tenantId,
    proposalDigest: authorization.proposal.proposal_digest,
    delayMs: 750
  });
  let barrierCalls = 0;
  const decision = await store.spendAuthority(
    {
      ...request,
      dviAuthorization: authorization.dviAuthorization
    },
    {
      barrier: {
        async wait() {
          barrierCalls += 1;
          await store.waitForProposalExpiryForTest({
            tenantId,
            proposalDigest: authorization.proposal.proposal_digest
          });
        }
      }
    }
  );
  const snapshot = await store.snapshot({ tenantId, resourceId });
  assert(
    barrierCalls === 1,
    "held-transaction expiry barrier did not run exactly once"
  );
  assert(
    decision.outcome === "authorization_denied" &&
      decision.reason === "proposal_authorization_expired" &&
      decision.authorityCurrent === false,
    "transaction held past proposal expiry retained authority"
  );
  assert(
    snapshot.receipts.length === 1 &&
      snapshot.receipts[0].outcome === "authorization_denied" &&
      snapshot.outbox.length === 0 &&
      snapshot.effects.length === 0 &&
      snapshot.resource.current_fence === "0",
    "held-transaction expiry changed protected authority state"
  );
  return {
    barrierCalls,
    decisionOutcome: decision.outcome,
    decisionReason: decision.reason,
    authorityCurrent: decision.authorityCurrent,
    authorityReceiptCount: snapshot.receipts.length,
    outboxCount: snapshot.outbox.length,
    protectedEffectCount: snapshot.effects.length,
    currentFence: snapshot.resource.current_fence
  };
}

async function runFencingProof(store, proofLabel) {
  const tenantId = randomUUID();
  const runId = randomUUID();
  const incidentId = randomUUID();
  const evidenceId = randomUUID();
  const resourceId = `${proofLabel}-fencing`;
  await prepareAdmissibleFixture(store, {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId
  });

  const rawFirstRequest = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 201
  });
  const firstAuthorization = await authorizeSyntheticProposal(
    store,
    rawFirstRequest
  );
  const firstRequest = {
    ...rawFirstRequest,
    dviAuthorization: firstAuthorization.dviAuthorization
  };
  const first = await store.spendAuthority(firstRequest);
  await store.expireLeaseForTest({ tenantId, resourceId });

  const rawSecondBase = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 202
  });
  const rawSecondRequest = {
    ...rawSecondBase,
    payload: {
      ...rawSecondBase.payload,
      destination: "synthetic-zone-fencing-successor"
    }
  };
  const secondAuthorization = await authorizeSyntheticProposal(
    store,
    rawSecondRequest
  );
  const secondRequest = {
    ...rawSecondRequest,
    dviAuthorization: secondAuthorization.dviAuthorization
  };
  const second = await store.spendAuthority(secondRequest);
  assert(first.receipt.fencing_token === "1", "first fence was not 1");
  assert(second.receipt.fencing_token === "2", "second fence was not 2");

  const stale = await store.recordProtectedEffect(
    {
      ...firstRequest,
      fencingToken: first.receipt.fencing_token
    },
    { authenticatedAgentId: firstRequest.agentId }
  );
  const future = await store.recordProtectedEffect(
    {
      ...secondRequest,
      fencingToken: "3"
    },
    { authenticatedAgentId: secondRequest.agentId }
  );
  const wrongAgent = await store.recordProtectedEffect(
    {
      ...secondRequest,
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: "synthetic-agent-impostor" }
  );
  const wrongTenant = await recordContextMismatch(
    store,
    {
      ...secondRequest,
      tenantId: randomUUID(),
      fencingToken: second.receipt.fencing_token
    },
    secondRequest.agentId
  );
  const wrongIncident = await recordContextMismatch(
    store,
    {
      ...secondRequest,
      incidentId: randomUUID(),
      fencingToken: second.receipt.fencing_token
    },
    secondRequest.agentId
  );
  const wrongResource = await recordContextMismatch(
    store,
    {
      ...secondRequest,
      resourceId: `${resourceId}-other`,
      fencingToken: second.receipt.fencing_token
    },
    secondRequest.agentId
  );
  const wrongRun = await recordContextMismatch(
    store,
    {
      ...secondRequest,
      runId: randomUUID(),
      fencingToken: second.receipt.fencing_token
    },
    secondRequest.agentId
  );
  const current = await store.recordProtectedEffect(
    {
      ...secondRequest,
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: secondRequest.agentId }
  );
  const replay = await store.recordProtectedEffect(
    {
      ...secondRequest,
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: secondRequest.agentId }
  );
  const snapshot = await store.snapshot({ tenantId, resourceId });

  assert(
    stale.outcome === "stale_or_unauthorized_fence_denied",
    "stale fence was accepted"
  );
  assert(
    future.outcome === "stale_or_unauthorized_fence_denied",
    "future fence was accepted"
  );
  assert(
    wrongAgent.outcome === "stale_or_unauthorized_fence_denied",
    "wrong actor was accepted"
  );
  for (const [label, result] of [
    ["tenant", wrongTenant],
    ["incident", wrongIncident],
    ["resource", wrongResource],
    ["run", wrongRun]
  ]) {
    assert(
      result.outcome === "identity_binding_rejected",
      `wrong ${label} was accepted`
    );
  }
  assert(
    current.outcome === "protected_effect_recorded",
    "current authority was rejected"
  );
  assert(
    replay.outcome === "effect_already_recorded",
    "effect replay was not idempotent"
  );
  assert(snapshot.effects.length === 1, "expected exactly one protected effect");

  const expiredTenantId = randomUUID();
  const expiredRunId = randomUUID();
  const expiredIncidentId = randomUUID();
  const expiredEvidenceId = randomUUID();
  const expiredResourceId = `${proofLabel}-fencing-expired`;
  await prepareAdmissibleFixture(store, {
    tenantId: expiredTenantId,
    runId: expiredRunId,
    incidentId: expiredIncidentId,
    resourceId: expiredResourceId,
    evidenceId: expiredEvidenceId
  });
  const rawExpiredRequest = baseRequest({
    tenantId: expiredTenantId,
    runId: expiredRunId,
    incidentId: expiredIncidentId,
    resourceId: expiredResourceId,
    evidenceId: expiredEvidenceId,
    index: 203
  });
  const expiredAuthorization = await authorizeSyntheticProposal(
    store,
    rawExpiredRequest
  );
  const expiredRequest = {
    ...rawExpiredRequest,
    dviAuthorization: expiredAuthorization.dviAuthorization
  };
  const expiredAuthority = await store.spendAuthority(expiredRequest);
  await store.expireLeaseAtDatabaseNowForTest({
    tenantId: expiredTenantId,
    resourceId: expiredResourceId
  });
  const expired = await store.recordProtectedEffect(
    {
      ...expiredRequest,
      fencingToken: expiredAuthority.receipt.fencing_token
    },
    { authenticatedAgentId: expiredRequest.agentId }
  );
  assert(
    expired.outcome === "stale_or_unauthorized_fence_denied",
    "expired current fence was accepted"
  );

  const proposalExpiredTenantId = randomUUID();
  const proposalExpiredRunId = randomUUID();
  const proposalExpiredIncidentId = randomUUID();
  const proposalExpiredEvidenceId = randomUUID();
  const proposalExpiredResourceId = `${proofLabel}-proposal-expired`;
  await prepareAdmissibleFixture(store, {
    tenantId: proposalExpiredTenantId,
    runId: proposalExpiredRunId,
    incidentId: proposalExpiredIncidentId,
    resourceId: proposalExpiredResourceId,
    evidenceId: proposalExpiredEvidenceId
  });
  const rawProposalExpiredRequest = baseRequest({
    tenantId: proposalExpiredTenantId,
    runId: proposalExpiredRunId,
    incidentId: proposalExpiredIncidentId,
    resourceId: proposalExpiredResourceId,
    evidenceId: proposalExpiredEvidenceId,
    index: 204
  });
  const proposalExpiredAuthorization = await authorizeSyntheticProposal(
    store,
    rawProposalExpiredRequest
  );
  const proposalExpiredRequest = {
    ...rawProposalExpiredRequest,
    dviAuthorization: proposalExpiredAuthorization.dviAuthorization
  };
  const proposalExpiredAuthority = await store.spendAuthority(
    proposalExpiredRequest
  );
  const proposalBoundary = await store.expireProposalAtDatabaseNowForTest({
    tenantId: proposalExpiredTenantId,
    proposalDigest: proposalExpiredAuthorization.proposal.proposal_digest
  });
  assert(
    proposalBoundary.exact_boundary === true,
    "proposal did not reach the exact database-time expiry boundary"
  );
  const proposalExpiredEffect = await store.recordProtectedEffect(
    {
      ...proposalExpiredRequest,
      fencingToken: proposalExpiredAuthority.receipt.fencing_token
    },
    { authenticatedAgentId: proposalExpiredRequest.agentId }
  );
  const proposalExpiredSnapshot = await store.snapshot({
    tenantId: proposalExpiredTenantId,
    resourceId: proposalExpiredResourceId
  });
  assert(
    proposalExpiredEffect.outcome ===
        "stale_or_unauthorized_fence_denied" &&
      proposalExpiredSnapshot.effects.length === 0,
    "exact-boundary proposal expiry allowed a protected effect"
  );

  const concurrentTenantId = randomUUID();
  const concurrentRunId = randomUUID();
  const concurrentIncidentId = randomUUID();
  const concurrentEvidenceId = randomUUID();
  const concurrentResourceId = `${proofLabel}-fencing-concurrent`;
  await prepareAdmissibleFixture(store, {
    tenantId: concurrentTenantId,
    runId: concurrentRunId,
    incidentId: concurrentIncidentId,
    resourceId: concurrentResourceId,
    evidenceId: concurrentEvidenceId
  });
  const rawConcurrentRequest = baseRequest({
    tenantId: concurrentTenantId,
    runId: concurrentRunId,
    incidentId: concurrentIncidentId,
    resourceId: concurrentResourceId,
    evidenceId: concurrentEvidenceId,
    index: 205
  });
  const concurrentAuthorization = await authorizeSyntheticProposal(
    store,
    rawConcurrentRequest
  );
  const concurrentRequest = {
    ...rawConcurrentRequest,
    dviAuthorization: concurrentAuthorization.dviAuthorization
  };
  const concurrentAuthority = await store.spendAuthority(concurrentRequest);
  const effectSettled = await Promise.allSettled(
    Array.from({ length: 50 }, () =>
      store.recordProtectedEffect(
        {
          ...concurrentRequest,
          fencingToken: concurrentAuthority.receipt.fencing_token
        },
        { authenticatedAgentId: concurrentRequest.agentId }
      )
    )
  );
  const effectFailures = effectSettled.filter(
    ({ status }) => status === "rejected"
  );
  if (effectFailures.length > 0) {
    throw effectFailures[0].reason;
  }
  const effectResults = effectSettled.map(({ value }) => value);
  const concurrentRecorded = effectResults.filter(
    ({ outcome }) => outcome === "protected_effect_recorded"
  ).length;
  const concurrentReplays = effectResults.filter(
    ({ outcome }) => outcome === "effect_already_recorded"
  ).length;
  const concurrentSnapshot = await store.snapshot({
    tenantId: concurrentTenantId,
    resourceId: concurrentResourceId
  });
  assert(
    concurrentRecorded === 1 &&
      concurrentReplays === 49 &&
      concurrentSnapshot.effects.length === 1,
    "concurrent protected-effect replay was not idempotent"
  );

  return {
    firstFence: first.receipt.fencing_token,
    secondFence: second.receipt.fencing_token,
    staleOutcome: stale.outcome,
    futureOutcome: future.outcome,
    wrongActorOutcome: wrongAgent.outcome,
    wrongTenantOutcome: wrongTenant.outcome,
    wrongIncidentOutcome: wrongIncident.outcome,
    wrongResourceOutcome: wrongResource.outcome,
    wrongRunOutcome: wrongRun.outcome,
    expiredCurrentOutcome: expired.outcome,
    proposalExpiredOutcome: proposalExpiredEffect.outcome,
    proposalExpiredEffectCount: proposalExpiredSnapshot.effects.length,
    currentOutcome: current.outcome,
    replayOutcome: replay.outcome,
    protectedEffectCount: snapshot.effects.length,
    concurrentReplay: {
      contenders: 50,
      recorded: concurrentRecorded,
      replays: concurrentReplays,
      protectedEffectCount: concurrentSnapshot.effects.length
    }
  };
}

async function runAdmissibilityProof(store, proofLabel) {
  const cases = [
    {
      name: "invalid-provenance",
      provenanceStatus: "invalid",
      expected: "verification_receipt_missing"
    },
    {
      name: "unresolved-conflict",
      conflictStatus: "unresolved",
      expected: "unresolved_conflict"
    },
    {
      name: "future-observation",
      observedAt: isoFromNow(10 * 60_000),
      expected: "future_observation"
    },
    {
      name: "expired",
      validFrom: isoFromNow(-10 * 60_000),
      validUntil: isoFromNow(-1),
      expected: "expired"
    },
    {
      name: "out-of-scope",
      agencyScope: "medical",
      expected: "out_of_scope"
    }
  ];
  const results = [];

  for (const testCase of cases) {
    const tenantId = randomUUID();
    const runId = randomUUID();
    const incidentId = randomUUID();
    const evidenceId = randomUUID();
    const resourceId = `${proofLabel}-admissibility-${testCase.name}`;
    if (testCase.provenanceStatus === "invalid") {
      await store.appendEvidence({
        tenantId,
        evidenceId,
        incidentId,
        issuer: "synthetic-county-sensor",
        agencyScope: testCase.agencyScope ?? "rescue",
        claimKey: "rescue_unit_status",
        claimValue: "available",
        observedAt: testCase.observedAt ?? isoFromNow(-60_000),
        validFrom: testCase.validFrom ?? isoFromNow(-120_000),
        validUntil: testCase.validUntil ?? isoFromNow(30 * 60_000),
        provenanceStatus: "invalid",
        conflictStatus: testCase.conflictStatus ?? "none",
        assertion: `Synthetic ${testCase.name} evidence.`,
        embedding: [0.82, 0.11, 0.07]
      });
    } else {
      await SYNTHETIC_SIGNER.register(store, tenantId);
      const appended = await SYNTHETIC_SIGNER.append(store, {
        tenantId,
        evidenceId,
        incidentId,
        agencyScope: testCase.agencyScope ?? "rescue",
        claimKey: "rescue_unit_status",
        claimValue: "available",
        observedAt: testCase.observedAt ?? isoFromNow(-60_000),
        validFrom: testCase.validFrom ?? isoFromNow(-120_000),
        validUntil: testCase.validUntil ?? isoFromNow(30 * 60_000),
        conflictStatus: testCase.conflictStatus ?? "none",
        assertion: `Synthetic ${testCase.name} evidence.`,
        embedding: [0.82, 0.11, 0.07]
      });
      assert(
        appended.outcome === "evidence_verified",
        `${testCase.name} signature did not verify`
      );
    }
    await store.prepareResource({ tenantId, runId, resourceId });
    const rawRequest = baseRequest({
      tenantId,
      runId,
      incidentId,
      resourceId,
      evidenceId,
      index: 301
    });
    const authorization = await authorizeSyntheticProposal(store, rawRequest);
    const request = {
      ...rawRequest,
      dviAuthorization: authorization.dviAuthorization
    };
    const decision = await store.spendAuthority(request);
    const snapshot = await store.snapshot({ tenantId, resourceId });

    assert(
      decision.outcome === "authorization_denied" &&
        decision.reason === testCase.expected,
      `${testCase.name} was not denied for ${testCase.expected}`
    );
    assert(
      snapshot.resource.current_fence === "0" &&
        snapshot.outbox.length === 0 &&
        snapshot.receipts.length === 1,
      `${testCase.name} changed authority state`
    );
    results.push({
      case: testCase.name,
      outcome: decision.outcome,
      reason: decision.reason,
      fencingTokenAfter: snapshot.resource.current_fence,
      receiptCount: snapshot.receipts.length,
      outboxCount: snapshot.outbox.length
    });
  }
  return results;
}

async function runRetryProof(store) {
  const result = await store.proveSerializableRetry(
    {
      tenantId: randomUUID(),
      probeId: randomUUID()
    },
    { barrier: new Barrier(2) }
  );
  assert(result.finalValue === "2", "retry probe lost a committed increment");
  assert(
    result.retryCodes.includes("40001"),
    "retry probe did not observe a real CockroachDB 40001"
  );
  assert(
    result.contenders.some(
      ({ transaction }) => transaction.serializableRetries > 0
    ),
    "retry wrapper did not replay a transaction"
  );
  return result;
}

async function runCrossEpochRaceProof(store, proofLabel) {
  const tenantId = randomUUID();
  const runId = randomUUID();
  const incidentId = randomUUID();
  const evidenceId = randomUUID();
  const resourceId = `${proofLabel}-cross-epoch-race`;
  await prepareAdmissibleFixture(store, {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId
  });
  const rawRequest = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 401
  });
  const expiresAt = new Date(Date.now() + 750).toISOString();
  const firstAuthorization = await authorizeSyntheticProposal(
    store,
    rawRequest,
    { expiresAt }
  );
  const firstRequest = {
    ...rawRequest,
    dviAuthorization: firstAuthorization.dviAuthorization
  };
  let releaseEpochLock;
  let observeEpochLock;
  const epochLocked = new Promise((resolve) => {
    observeEpochLock = resolve;
  });
  const epochRelease = new Promise((resolve) => {
    releaseEpochLock = resolve;
  });
  const firstSpend = store.spendAuthority(firstRequest, {
    afterEpochLockObserver: async () => {
      observeEpochLock();
      await epochRelease;
    }
  });
  await epochLocked;
  const remainingMs = Date.parse(expiresAt) - Date.now();
  if (remainingMs >= 0) {
    await new Promise((resolve) => setTimeout(resolve, remainingMs + 25));
  }
  const freshAuthorization = authorizeSyntheticProposal(store, rawRequest, {
    retrievalId: randomUUID(),
    allowDenied: true
  });
  await new Promise((resolve) => setImmediate(resolve));
  releaseEpochLock();
  const [firstDecision, freshResult] = await Promise.all([
    firstSpend,
    freshAuthorization
  ]);
  const snapshot = await store.snapshot({ tenantId, resourceId });
  const identityState = await store.authorityIdentityStateForTest({
    tenantId,
    resourceId
  });
  assert(
    firstDecision.outcome === "resource_reserved",
    "pre-expiry spend did not retain its serialized authority"
  );
  assert(
    freshResult.authorization.outcome ===
        "proposal_authorization_denied" &&
      freshResult.authorization.reason === "logical_authority_already_spent",
    "post-expiry authorization raced into a second spendable epoch"
  );
  assert(
    snapshot.receipts.length === 1 &&
      snapshot.outbox.length === 1 &&
      snapshot.effects.length === 0 &&
      identityState.maximum_epoch === "1",
    "cross-epoch race changed the singular logical-authority state"
  );
  return {
    firstOutcome: firstDecision.outcome,
    freshOutcome: freshResult.authorization.outcome,
    freshReason: freshResult.authorization.reason,
    authorityReceiptCount: snapshot.receipts.length,
    outboxCount: snapshot.outbox.length,
    protectedEffectCount: snapshot.effects.length,
    maximumEpoch: identityState.maximum_epoch
  };
}

async function main() {
  const raceRuns = positiveInteger(process.env.RACE_RUNS, 3, "RACE_RUNS");
  const contenderCount = positiveInteger(
    process.env.CONTENDERS,
    50,
    "CONTENDERS"
  );
  const proofLabel = `gate1-${randomUUID()}`;
  const store = new AuthorityStore({
    connectionString: requireDatabaseUrl(),
    databaseName: "tideproof",
    maxConnections: contenderCount + 8
  });

  try {
    await store.migrate();
    const races = [];
    for (let run = 1; run <= raceRuns; run += 1) {
      races.push(
        await runRace(store, {
          proofLabel,
          runNumber: run,
          contenderCount
        })
      );
    }
    const replay = await runConcurrentReplayProof(
      store,
      proofLabel,
      contenderCount
    );
    const runtimeIdentityNegatives =
      await runRuntimeIdentityNegativeProof(store, proofLabel);
    const expiredUnspentReplacement =
      await runExpiredUnspentReplacementProof(store, proofLabel);
    const heldTransactionExpiry =
      await runHeldTransactionExpiryProof(store, proofLabel);
    const fencing = await runFencingProof(store, proofLabel);
    const crossEpochRace = await runCrossEpochRaceProof(store, proofLabel);
    const admissibility = await runAdmissibilityProof(store, proofLabel);
    const retryProof = await runRetryProof(store);

    console.log(
      JSON.stringify(
        {
          gate: "serializable-authority-core",
          passed: true,
          proofLabel,
          database: "tideproof",
          raceRuns,
          contenderCount,
          totalContenders: raceRuns * contenderCount,
          raceInvariantViolations: 0,
          races,
          replay,
          runtimeIdentityNegatives,
          expiredUnspentReplacement,
          heldTransactionExpiry,
          fencing,
          crossEpochRace,
          admissibility,
          retryProof,
          ambiguityBoundary:
            "Not claimed by this command; COMMIT-dispatch loss proof is separate."
        },
        null,
        2
      )
    );
  } finally {
    await store.close();
  }
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "serializable-authority-core",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
