import assert from "node:assert/strict";
import test from "node:test";
import {
  connectionStringForDatabase,
  isRetryableTransactionError,
  requestDigestFor,
  signedEvidenceDigestFor
} from "../src/cloud/authority-store.js";

const REQUEST = {
  tenantId: "33333333-3333-4333-8333-333333333333",
  runId: "99999999-9999-4999-8999-999999999999",
  incidentId: "44444444-4444-4444-8444-444444444444",
  resourceId: "synthetic-rescue-unit-7",
  operationId: "55555555-5555-4555-8555-555555555555",
  agentId: "synthetic-agent-alpha",
  agency: "rescue",
  evidenceId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  intentNonce: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  effectKey: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  leaseMs: 300_000,
  payload: {
    scenario: "synthetic-highwater",
    action: "dispatch_rescue_unit"
  }
};

test("request digests are deterministic and bind every authority input", () => {
  const first = requestDigestFor(REQUEST);
  const reordered = requestDigestFor({
    payload: REQUEST.payload,
    leaseMs: REQUEST.leaseMs,
    effectKey: REQUEST.effectKey,
    intentNonce: REQUEST.intentNonce,
    evidenceId: REQUEST.evidenceId,
    agency: REQUEST.agency,
    agentId: REQUEST.agentId,
    operationId: REQUEST.operationId,
    resourceId: REQUEST.resourceId,
    incidentId: REQUEST.incidentId,
    runId: REQUEST.runId,
    tenantId: REQUEST.tenantId
  });

  assert.equal(first, reordered);
  assert.match(first, /^[a-f0-9]{64}$/);

  const changedRequests = [
    { ...REQUEST, tenantId: "66666666-6666-4666-8666-666666666666" },
    { ...REQUEST, runId: "77777777-7777-4777-8777-777777777777" },
    { ...REQUEST, incidentId: "88888888-8888-4888-8888-888888888888" },
    { ...REQUEST, resourceId: `${REQUEST.resourceId}-changed` },
    { ...REQUEST, agentId: `${REQUEST.agentId}-changed` },
    { ...REQUEST, agency: "medical" },
    { ...REQUEST, evidenceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
    { ...REQUEST, intentNonce: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" },
    { ...REQUEST, effectKey: "ffffffff-ffff-4fff-8fff-ffffffffffff" },
    { ...REQUEST, leaseMs: 299_999 },
    { ...REQUEST, payload: { ...REQUEST.payload, destination: "zone-bravo" } }
  ];
  for (const changed of changedRequests) {
    assert.notEqual(requestDigestFor(changed), first);
  }

  assert.equal(
    requestDigestFor({
      ...REQUEST,
      operationId: "88888888-8888-4888-8888-888888888888"
    }),
    first,
    "operation ID must not bypass semantic deduplication"
  );
});

test("only CockroachDB serialization failures are transaction-retryable", () => {
  assert.equal(isRetryableTransactionError({ code: "40001" }), true);
  assert.equal(isRetryableTransactionError({ code: "23505" }), false);
  assert.equal(isRetryableTransactionError(new Error("connection reset")), false);
});

test("authority connections are pinned to the requested database", () => {
  const result = connectionStringForDatabase(
    "postgresql://example.invalid/defaultdb?sslmode=verify-full",
    "tideproof"
  );
  const parsed = new URL(result);

  assert.equal(parsed.pathname, "/tideproof");
  assert.equal(parsed.searchParams.get("sslmode"), "verify-full");
});

test("authority payloads reject values that JSON would silently alter", () => {
  assert.throws(
    () =>
      requestDigestFor({
        ...REQUEST,
        payload: { ...REQUEST.payload, unsafe: undefined }
      }),
    /not JSON-safe/
  );
  assert.throws(
    () =>
      requestDigestFor({
        ...REQUEST,
        payload: { ...REQUEST.payload, unsafe: Number.NaN }
      }),
    /must be finite/
  );
  const cyclic = { ...REQUEST.payload };
  cyclic.self = cyclic;
  assert.throws(
    () => requestDigestFor({ ...REQUEST, payload: cyclic }),
    /must not contain a cycle/
  );
  assert.throws(
    () =>
      requestDigestFor({
        ...REQUEST,
        at: "2026-07-29T20:00:00.000Z"
      }),
    /database-controlled/
  );
  assert.throws(
    () =>
      requestDigestFor({
        ...REQUEST,
        clientNow: "2026-07-30T20:00:00.000Z"
      }),
    /database-controlled/
  );
});

test("signed evidence digests bind provenance-bearing content", () => {
  const evidence = {
    tenantId: REQUEST.tenantId,
    evidenceId: REQUEST.evidenceId,
    incidentId: REQUEST.incidentId,
    issuer: "synthetic-county-sensor",
    agencyScope: "rescue",
    claimKey: "bridge_status",
    claimValue: "open",
    observedAt: "2026-07-29T20:00:00.000Z",
    validFrom: "2026-07-29T19:55:00.000Z",
    validUntil: "2026-07-29T21:00:00.000Z",
    conflictStatus: "none",
    assertion: "Synthetic bridge is open.",
    embedding: [0.8, 0.1, 0.1]
  };
  const digest = signedEvidenceDigestFor(evidence);
  assert.match(digest, /^[a-f0-9]{64}$/);
  for (const changed of [
    { ...evidence, issuer: "synthetic-other-sensor" },
    { ...evidence, agencyScope: "medical" },
    { ...evidence, claimValue: "closed" },
    { ...evidence, validUntil: "2026-07-29T21:00:00.001Z" },
    { ...evidence, conflictStatus: "unresolved" },
    { ...evidence, assertion: "Synthetic bridge is closed." },
    { ...evidence, embedding: [0.7, 0.2, 0.1] }
  ]) {
    assert.notEqual(signedEvidenceDigestFor(changed), digest);
  }
});
