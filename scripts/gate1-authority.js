import { randomUUID } from "node:crypto";
import {
  AuthorityStore,
  OperationDigestMismatchError
} from "../src/cloud/authority-store.js";
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

  const requests = Array.from({ length: contenderCount }, (_, index) =>
    baseRequest({
      tenantId,
      runId,
      incidentId,
      resourceId,
      evidenceId,
      index: index + 1
    })
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
    semanticReplay.outcome === "semantic_replay",
    "same semantic request with a new operation ID was not deduplicated"
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
    const base = baseRequest({
      tenantId,
      runId,
      incidentId,
      resourceId,
      evidenceId,
      index: label === "operation" ? 401 : 402
    });
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
      ? "semantic_replay"
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
      await store.spendAuthority(changed.input);
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

  const firstRequest = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 201
  });
  const first = await store.spendAuthority(firstRequest);
  await store.expireLeaseForTest({ tenantId, resourceId });

  const secondRequest = baseRequest({
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    index: 202
  });
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
  const wrongTenant = await store.recordProtectedEffect(
    {
      ...secondRequest,
      tenantId: randomUUID(),
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: secondRequest.agentId }
  );
  const wrongIncident = await store.recordProtectedEffect(
    {
      ...secondRequest,
      incidentId: randomUUID(),
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: secondRequest.agentId }
  );
  const wrongResource = await store.recordProtectedEffect(
    {
      ...secondRequest,
      resourceId: `${resourceId}-other`,
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: secondRequest.agentId }
  );
  const wrongRun = await store.recordProtectedEffect(
    {
      ...secondRequest,
      runId: randomUUID(),
      fencingToken: second.receipt.fencing_token
    },
    { authenticatedAgentId: secondRequest.agentId }
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
      result.outcome === "stale_or_unauthorized_fence_denied",
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
  const expiredRequest = baseRequest({
    tenantId: expiredTenantId,
    runId: expiredRunId,
    incidentId: expiredIncidentId,
    resourceId: expiredResourceId,
    evidenceId: expiredEvidenceId,
    index: 203
  });
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
  const concurrentRequest = baseRequest({
    tenantId: concurrentTenantId,
    runId: concurrentRunId,
    incidentId: concurrentIncidentId,
    resourceId: concurrentResourceId,
    evidenceId: concurrentEvidenceId,
    index: 204
  });
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
    const request = baseRequest({
      tenantId,
      runId,
      incidentId,
      resourceId,
      evidenceId,
      index: 301
    });
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
    const fencing = await runFencingProof(store, proofLabel);
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
          fencing,
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
