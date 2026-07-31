import { randomUUID } from "node:crypto";
import { Client } from "pg";
import {
  AuthorityStore,
  normalizedAuthorityRequestFor
} from "../src/cloud/authority-store.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

const CONTENDERS = 50;
const SPEND_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID, $2::UUID, $3, $4::JSONB,
    $5::UUID, $6::UUID, $7, $8, $9,
    $10::UUID, $11::UUID, $12::JSONB, $13, $14, $15::INT8
  )
`;

class Barrier {
  #arrived = 0;
  #release;
  #released;
  #timer;

  constructor(expected, timeoutMs = 30_000) {
    this.expected = expected;
    this.#released = new Promise((resolve, reject) => {
      this.#release = resolve;
      this.#timer = setTimeout(
        () =>
          reject(
            new Error(`barrier timed out after ${this.#arrived}/${expected}`)
          ),
        timeoutMs
      );
    });
  }

  async wait() {
    this.#arrived += 1;
    if (this.#arrived === this.expected) {
      clearTimeout(this.#timer);
      this.#release();
    }
    await this.#released;
  }
}

function requiredEnvironment(name) {
  if (!process.env[name]) {
    throw new Error(`${name} is required`);
  }
  return process.env[name];
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function valuesFor(request) {
  return [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.runId,
    request.incidentId,
    request.resourceId,
    request.agentId,
    request.agency,
    request.evidenceId,
    request.effectKey,
    JSON.stringify(request.payload),
    request.payloadDigest,
    request.policyVersion,
    request.leaseMs
  ];
}

async function callCapability(connectionString, request, barrier) {
  const retryCodes = [];
  const backendIds = [];
  for (let attempt = 0; attempt <= 20; attempt += 1) {
    const client = new Client({ connectionString });
    try {
      await client.connect();
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const isolation = await client.query(
        "SHOW TRANSACTION ISOLATION LEVEL"
      );
      const backend = await client.query(
        "SELECT pg_backend_pid()::STRING AS backend_id"
      );
      backendIds.push(backend.rows[0].backend_id);
      if (attempt === 0) {
        await barrier.wait();
      }
      const result = await client.query(SPEND_SQL, valuesFor(request));
      await client.query("COMMIT");
      return {
        ...result.rows[0],
        transaction: {
          isolation: isolation.rows[0].transaction_isolation,
          backendIds,
          serializableRetries: attempt,
          retryCodes
        }
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      if (error.code === "40001" && attempt < 20) {
        retryCodes.push(error.code);
        continue;
      }
      throw error;
    } finally {
      await client.end().catch(() => {});
    }
  }
  throw new Error("capability retry loop exhausted");
}

async function main() {
  const adminUrl = requiredEnvironment("DATABASE_URL");
  const authorizerUrl = requiredEnvironment("AUTHORIZER_DATABASE_URL");
  const store = new AuthorityStore({
    connectionString: adminUrl,
    databaseName: "tideproof",
    maxConnections: 8
  });
  const signer = createSyntheticEvidenceSigner();
  try {
    await store.migrate();
    const fixture = {
      tenantId: randomUUID(),
      runId: randomUUID(),
      incidentId: randomUUID(),
      evidenceId: randomUUID(),
      resourceId: `capability-race-${randomUUID()}`
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
      assertion: "Synthetic capability race evidence.",
      embedding: [0.86, 0.08, 0.06]
    });
    assert(evidence.outcome === "evidence_verified", "evidence did not verify");
    await store.prepareResource(fixture);

    const requests = Array.from({ length: CONTENDERS }, (_, index) =>
      normalizedAuthorityRequestFor({
        ...fixture,
        operationId: randomUUID(),
        agentId: `capability-agent-${String(index + 1).padStart(2, "0")}`,
        agency: "rescue",
        intentNonce: randomUUID(),
        effectKey: randomUUID(),
        leaseMs: 300_000,
        payload: {
          scenario: "synthetic-highwater",
          action: "dispatch_rescue_unit",
          destination: "synthetic-zone-capability-race"
        }
      })
    );
    const barrier = new Barrier(CONTENDERS);
    const settled = await Promise.allSettled(
      requests.map((request) =>
        callCapability(authorizerUrl, request, barrier)
      )
    );
    const failed = settled.filter(({ status }) => status === "rejected");
    assert(failed.length === 0, "a capability contender failed");
    const results = settled.map(({ value }) => value);
    const winners = results.filter(
      ({ decision_outcome }) => decision_outcome === "resource_reserved"
    );
    const denials = results.filter(
      ({ decision_outcome }) => decision_outcome === "resource_held_denied"
    );
    const snapshot = await store.snapshot(fixture);
    assert(winners.length === 1, "capability race did not have one winner");
    assert(denials.length === 49, "capability race did not have 49 denials");
    assert(
      snapshot.receipts.length === 50 &&
        snapshot.outbox.length === 1 &&
        snapshot.effects.length === 0 &&
        snapshot.resource.current_fence === "1",
      "capability race durable state was incorrect"
    );
    const initialBackends = new Set(
      results.map(({ transaction }) => transaction.backendIds[0])
    );
    assert(initialBackends.size === 50, "contenders did not use 50 sessions");
    assert(
      results.every(
        ({ transaction }) => transaction.isolation === "serializable"
      ),
      "a capability contender was not SERIALIZABLE"
    );

    const probe = new Client({ connectionString: authorizerUrl });
    await probe.connect();
    let directReadDenied = false;
    try {
      await probe.query(
        "SELECT * FROM tp_ledger.g1_authority_receipts LIMIT 1"
      );
    } catch (error) {
      directReadDenied = error.code === "42501";
    } finally {
      await probe.end();
    }
    assert(directReadDenied, "authorizer could read the base ledger directly");

    console.log(
      JSON.stringify(
        {
          gate: "least-privilege-capability-race",
          passed: true,
          contenders: CONTENDERS,
          distinctInitialSessions: initialBackends.size,
          winners: winners.length,
          durableDenials: denials.length,
          receiptCount: snapshot.receipts.length,
          outboxCount: snapshot.outbox.length,
          effectCount: snapshot.effects.length,
          fence: snapshot.resource.current_fence,
          serializableRetries: results.reduce(
            (sum, { transaction }) =>
              sum + transaction.serializableRetries,
            0
          ),
          retryCodes: results.flatMap(
            ({ transaction }) => transaction.retryCodes
          ),
          directBaseLedgerReadDenied: directReadDenied,
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
      gate: "least-privilege-capability-race",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
