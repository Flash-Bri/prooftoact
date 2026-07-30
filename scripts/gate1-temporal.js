import { randomUUID } from "node:crypto";
import { AuthorityStore } from "../src/cloud/authority-store.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

function requiredDatabaseUrl() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is required");
  }
  return process.env.DATABASE_URL;
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function iso(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function requestFor({ tenantId, runId, incidentId, resourceId, evidenceId }) {
  return {
    tenantId,
    runId,
    incidentId,
    resourceId,
    evidenceId,
    operationId: randomUUID(),
    agentId: "synthetic-temporal-agent",
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-highwater",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-temporal"
    }
  };
}

async function runInsertionOrder(store, signer, order) {
  const tenantId = randomUUID();
  const incidentId = randomUUID();
  const evidenceA = randomUUID();
  const evidenceB = randomUUID();
  const base = Math.floor((Date.now() - 60 * 60_000) / 1_000) * 1_000;
  const times = {
    t0: iso(base + 10 * 60_000),
    t1: iso(base + 20 * 60_000),
    t2: iso(base + 30 * 60_000),
    t2Before: iso(base + 30 * 60_000 - 1),
    t3: iso(base + 40 * 60_000),
    observed: iso(base + 9 * 60_000)
  };
  const fixtures = {
    A: {
      tenantId,
      evidenceId: evidenceA,
      incidentId,
      agencyScope: "rescue",
      claimKey: "synthetic_bridge_status",
      claimValue: "open",
      observedAt: times.observed,
      validFrom: times.t0,
      validUntil: times.t3,
      conflictStatus: "none",
      assertion: "Synthetic bridge is open.",
      embedding: [0.83, 0.1, 0.07]
    },
    B: {
      tenantId,
      evidenceId: evidenceB,
      incidentId,
      agencyScope: "rescue",
      claimKey: "synthetic_bridge_status",
      claimValue: "closed",
      observedAt: times.observed,
      validFrom: times.t1,
      validUntil: times.t2,
      conflictStatus: "none",
      assertion: "Synthetic bridge is closed.",
      embedding: [0.81, 0.12, 0.07]
    }
  };

  await signer.register(store, tenantId);
  for (const label of order) {
    const appended = await signer.append(store, fixtures[label]);
    assert(
      appended.outcome === "evidence_verified",
      `${label} did not verify in ${order.join("")} order`
    );
  }

  const status = async (label, at) =>
    (
      await store.auditEvidenceStatusAt({
        tenantId,
        evidenceId: fixtures[label].evidenceId,
        incidentId,
        agency: "rescue",
        at
      })
    ).status;
  const matrix = {
    aAtT0: await status("A", times.t0),
    bAtT0: await status("B", times.t0),
    aAtT1: await status("A", times.t1),
    bAtT1: await status("B", times.t1),
    aJustBeforeT2: await status("A", times.t2Before),
    bJustBeforeT2: await status("B", times.t2Before),
    aAtT2: await status("A", times.t2),
    bAtT2: await status("B", times.t2),
    aAtT3: await status("A", times.t3)
  };
  assert(matrix.aAtT0 === "admissible", "A was not admitted at T0");
  assert(matrix.bAtT0 === "not_yet_valid", "B was not future at T0");
  for (const key of ["aAtT1", "bAtT1", "aJustBeforeT2", "bJustBeforeT2"]) {
    assert(matrix[key] === "unresolved_conflict", `${key} was not conflicted`);
  }
  assert(matrix.aAtT2 === "admissible", "A was not admitted exactly at T2");
  assert(matrix.bAtT2 === "expired", "B was not expired exactly at T2");
  assert(matrix.aAtT3 === "expired", "A was not expired exactly at T3");

  return { tenantId, incidentId, evidenceA, times, matrix };
}

async function main() {
  const store = new AuthorityStore({
    connectionString: requiredDatabaseUrl(),
    databaseName: "tideproof",
    maxConnections: 8
  });
  const signer = createSyntheticEvidenceSigner();
  try {
    await store.migrate();
    const forward = await runInsertionOrder(store, signer, ["A", "B"]);
    const reverse = await runInsertionOrder(store, signer, ["B", "A"]);
    assert(
      JSON.stringify(forward.matrix) === JSON.stringify(reverse.matrix),
      "temporal conflict result depended on insertion order"
    );

    const runId = randomUUID();
    const resourceId = `gate1-temporal-${randomUUID()}`;
    await store.prepareResource({
      tenantId: forward.tenantId,
      runId,
      resourceId
    });
    const request = requestFor({
      tenantId: forward.tenantId,
      runId,
      incidentId: forward.incidentId,
      resourceId,
      evidenceId: forward.evidenceA
    });
    let historicalAuthorizationRejected = false;
    try {
      await store.spendAuthority({ ...request, at: forward.times.t1 });
    } catch (error) {
      historicalAuthorizationRejected =
        error instanceof TypeError &&
        /database-controlled/.test(error.message);
    }
    assert(
      historicalAuthorizationRejected,
      "authorization accepted a caller-selected historical time"
    );
    const currentDecision = await store.spendAuthority(request);
    const snapshot = await store.snapshot({
      tenantId: forward.tenantId,
      resourceId
    });
    assert(
      currentDecision.outcome === "authorization_denied" &&
        currentDecision.reason === "expired",
      "current authorization did not use database time"
    );
    assert(
      snapshot.resource.current_fence === "0" &&
        snapshot.outbox.length === 0,
      "historical audit state changed current authority"
    );

    console.log(
      JSON.stringify(
        {
          gate: "bitemporal-conflict-boundaries",
          passed: true,
          insertionOrderForward: forward.matrix,
          insertionOrderReverse: reverse.matrix,
          identicalAcrossInsertionOrder: true,
          historicalAuthorizationRejected,
          currentAuthorization: {
            outcome: currentDecision.outcome,
            reason: currentDecision.reason,
            fenceAfter: snapshot.resource.current_fence,
            outboxCount: snapshot.outbox.length
          },
          boundarySemantics: "[valid_from, valid_until)",
          invariantViolations: 0
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
      gate: "bitemporal-conflict-boundaries",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
