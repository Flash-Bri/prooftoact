import { randomUUID } from "node:crypto";
import { AuthorityStore } from "../src/cloud/authority-store.js";
import {
  authorizeSyntheticContenders,
  authorizeSyntheticProposal
} from "./lib/synthetic-authority-proposal.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

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
              `barrier timed out after ${this.#arrived}/${this.#expected}`
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

function requestFor(fixture, index, extra = {}) {
  return {
    tenantId: fixture.tenantId,
    runId: fixture.runId,
    incidentId: fixture.incidentId,
    resourceId: fixture.resourceId,
    evidenceId: fixture.evidenceId,
    operationId: randomUUID(),
    agentId: `synthetic-lease-agent-${index}`,
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-highwater",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-lease"
    },
    ...extra
  };
}

async function prepareFixture(store, signer, resourceId = `lease-${randomUUID()}`) {
  const fixture = {
    tenantId: randomUUID(),
    runId: randomUUID(),
    incidentId: randomUUID(),
    evidenceId: randomUUID(),
    resourceId
  };
  await signer.register(store, fixture.tenantId);
  const evidence = await signer.append(store, {
    tenantId: fixture.tenantId,
    evidenceId: fixture.evidenceId,
    incidentId: fixture.incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt: new Date(Date.now() - 60_000).toISOString(),
    validFrom: new Date(Date.now() - 120_000).toISOString(),
    validUntil: new Date(Date.now() + 30 * 60_000).toISOString(),
    conflictStatus: "none",
    assertion: "Synthetic unit is available for lease testing.",
    embedding: [0.84, 0.1, 0.06]
  });
  assert(evidence.outcome === "evidence_verified", "fixture did not verify");
  await store.prepareResource(fixture);
  return fixture;
}

async function main() {
  const store = new AuthorityStore({
    connectionString: requiredDatabaseUrl(),
    databaseName: "tideproof",
    maxConnections: 64
  });
  const signer = createSyntheticEvidenceSigner();
  try {
    await store.migrate();
    const invalidFixture = await prepareFixture(store, signer);
    const invalidCases = [
      ["zero", 0],
      ["negative", -1],
      ["non-integer", 1_000.5],
      ["over-max", 600_001]
    ];
    const invalidLeaseResults = [];
    for (const [label, leaseMs] of invalidCases) {
      let rejected = false;
      try {
        await store.spendAuthority(
          requestFor(invalidFixture, label, { leaseMs })
        );
      } catch (error) {
        rejected = /leaseMs must be an integer/.test(error.message);
      }
      assert(rejected, `${label} lease was accepted`);
      const snapshot = await store.snapshot(invalidFixture);
      assert(
        snapshot.receipts.length === 0 &&
          snapshot.outbox.length === 0 &&
          snapshot.resource.current_fence === "0",
        `${label} lease changed state`
      );
      invalidLeaseResults.push({ label, rejected, fenceAfter: "0" });
    }

    const missing = await prepareFixture(store, signer);
    const missingResourceId = `missing-${randomUUID()}`;
    const rawMissingRequest = {
      ...requestFor(missing, "missing"),
      resourceId: missingResourceId
    };
    const missingAuthorization = await authorizeSyntheticProposal(
      store,
      rawMissingRequest
    );
    const missingDecision = await store.spendAuthority({
      ...rawMissingRequest,
      dviAuthorization: missingAuthorization.dviAuthorization
    });
    const missingSnapshot = await store.snapshot({
      tenantId: missing.tenantId,
      resourceId: missingResourceId
    });
    assert(
      missingDecision.outcome === "authorization_denied" &&
        missingDecision.reason === "resource_missing",
      "missing resource was not distinctly denied"
    );
    assert(
      missingSnapshot.resource === null &&
        missingSnapshot.receipts.length === 1 &&
        missingSnapshot.outbox.length === 0,
      "missing resource denial was incomplete"
    );

    const fixture = await prepareFixture(store, signer);
    const rawOriginalRequest = requestFor(fixture, "original");
    const originalAuthorization = await authorizeSyntheticProposal(
      store,
      rawOriginalRequest
    );
    const originalRequest = {
      ...rawOriginalRequest,
      dviAuthorization: originalAuthorization.dviAuthorization
    };
    const original = await store.spendAuthority(originalRequest);
    assert(original.receipt.fencing_token === "1", "first fence was not 1");
    const boundary = await store.expireLeaseAtDatabaseNowForTest(fixture);
    assert(boundary.exact_boundary === true, "expiry was not set at DB now");

    const contenders = await authorizeSyntheticContenders(
      store,
      Array.from({ length: 50 }, (_, index) =>
        requestFor(fixture, index + 1, {
          payload: {
            scenario: "synthetic-highwater",
            action: "dispatch_rescue_unit",
            destination: "synthetic-zone-expiry-race"
          }
        })
      )
    );
    const expiryBarrier = new Barrier(50);
    const settled = await Promise.allSettled(
      contenders.map((request) =>
        store.spendAuthority(request, { barrier: expiryBarrier })
      )
    );
    const failures = settled.filter(({ status }) => status === "rejected");
    assert(failures.length === 0, "expiry race produced a transaction failure");
    const results = settled.map(({ value }) => value);
    const winners = results.filter(
      ({ outcome }) => outcome === "resource_reserved"
    );
    const denials = results.filter(
      ({ outcome }) => outcome === "resource_held_denied"
    );
    assert(winners.length === 1, "expiry race did not have one winner");
    assert(denials.length === 49, "expiry race did not have 49 denials");
    assert(
      winners[0].receipt.fencing_token === "2",
      "expiry race winner did not receive fence 2"
    );
    const afterRace = await store.snapshot(fixture);
    assert(
      afterRace.receipts.length === 51 &&
        afterRace.outbox.length === 2 &&
        afterRace.resource.current_fence === "2",
      "expiry race durable state was incorrect"
    );

    const deniedIndex = results.findIndex(
      ({ outcome }) => outcome === "resource_held_denied"
    );
    await store.expireLeaseAtDatabaseNowForTest(fixture);
    const deniedReplay = await store.spendAuthority(contenders[deniedIndex]);
    assert(
      deniedReplay.outcome === "operation_replay" &&
        deniedReplay.receipt.outcome === "resource_held_denied",
      "denied request changed outcome after expiry"
    );
    const rawFresh = requestFor(fixture, "fresh-after-expiry", {
      payload: {
        scenario: "synthetic-highwater",
        action: "dispatch_rescue_unit",
        destination: "synthetic-zone-fresh-after-expiry"
      }
    });
    const freshAuthorization = await authorizeSyntheticProposal(
      store,
      rawFresh
    );
    const fresh = await store.spendAuthority({
      ...rawFresh,
      dviAuthorization: freshAuthorization.dviAuthorization
    });
    assert(
      fresh.outcome === "resource_reserved" &&
        fresh.receipt.fencing_token === "3",
      "fresh operation after expiry did not receive a higher fence"
    );

    let clientClockRejected = false;
    try {
      await store.spendAuthority(
        requestFor(fixture, "client-clock", {
          clientNow: new Date(Date.now() + 24 * 60 * 60_000).toISOString()
        })
      );
    } catch (error) {
      clientClockRejected = /database-controlled/.test(error.message);
    }
    assert(clientClockRejected, "client clock influenced lease authority");

    console.log(
      JSON.stringify(
        {
          gate: "lease-edge-cases",
          passed: true,
          invalidLeaseResults,
          missingResource: {
            outcome: missingDecision.outcome,
            reason: missingDecision.reason,
            receiptCount: missingSnapshot.receipts.length,
            outboxCount: missingSnapshot.outbox.length
          },
          exactExpiryBoundary: {
            leaseExpiresAt: boundary.lease_expires_at,
            databaseNow: boundary.database_now,
            exact: boundary.exact_boundary
          },
          expiryRace: {
            contenders: 50,
            winners: winners.length,
            durableDenials: denials.length,
            winningFence: winners[0].receipt.fencing_token,
            finalFence: afterRace.resource.current_fence
          },
          deniedReplayOutcome: deniedReplay.receipt.outcome,
          freshFenceAfterExpiry: fresh.receipt.fencing_token,
          clientClockRejected,
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
      gate: "lease-edge-cases",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
