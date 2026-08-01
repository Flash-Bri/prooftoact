import assert from "node:assert/strict";
import test from "node:test";
import {
  connectionStringForDatabase,
  isRetryableTransactionError,
  requestDigestFor,
  signedEvidenceDigestFor
} from "../src/cloud/authority-store.js";

function dviAuthorization({
  tenantId,
  runId,
  incidentId,
  evidenceId
}) {
  return {
    dviProposal: {
      tenantId,
      runId,
      incidentId,
      retrievalId: "12121212-1212-4212-8212-121212121212",
      authorityEvidenceBindingSha256: "1".repeat(64),
      selectedEvidenceId: evidenceId,
      selectedEvidenceDigest: "2".repeat(64),
      policyVersion: "g1-admissibility-v2",
      selectedRank: 1,
      admittedAt: "2026-08-01T18:00:00.000Z",
      expiresAt: "2026-08-01T18:05:00.000Z"
    },
    selectedEvidenceId: evidenceId,
    selectedEvidenceDigest: "2".repeat(64)
  };
}

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
  },
  dviAuthorization: dviAuthorization({
    tenantId: "33333333-3333-4333-8333-333333333333",
    runId: "99999999-9999-4999-8999-999999999999",
    incidentId: "44444444-4444-4444-8444-444444444444",
    evidenceId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  })
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
    tenantId: REQUEST.tenantId,
    dviAuthorization: REQUEST.dviAuthorization
  });

  assert.equal(first, reordered);
  assert.match(first, /^[a-f0-9]{64}$/);

  const changedRequests = [
    {
      ...REQUEST,
      tenantId: "66666666-6666-4666-8666-666666666666",
      dviAuthorization: dviAuthorization({
        tenantId: "66666666-6666-4666-8666-666666666666",
        runId: REQUEST.runId,
        incidentId: REQUEST.incidentId,
        evidenceId: REQUEST.evidenceId
      })
    },
    {
      ...REQUEST,
      runId: "77777777-7777-4777-8777-777777777777",
      dviAuthorization: dviAuthorization({
        tenantId: REQUEST.tenantId,
        runId: "77777777-7777-4777-8777-777777777777",
        incidentId: REQUEST.incidentId,
        evidenceId: REQUEST.evidenceId
      })
    },
    {
      ...REQUEST,
      incidentId: "88888888-8888-4888-8888-888888888888",
      dviAuthorization: dviAuthorization({
        tenantId: REQUEST.tenantId,
        runId: REQUEST.runId,
        incidentId: "88888888-8888-4888-8888-888888888888",
        evidenceId: REQUEST.evidenceId
      })
    },
    { ...REQUEST, resourceId: `${REQUEST.resourceId}-changed` },
    { ...REQUEST, agentId: `${REQUEST.agentId}-changed` },
    { ...REQUEST, agency: "medical" },
    {
      ...REQUEST,
      evidenceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      dviAuthorization: dviAuthorization({
        tenantId: REQUEST.tenantId,
        runId: REQUEST.runId,
        incidentId: REQUEST.incidentId,
        evidenceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
      })
    },
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
