import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  connectionStringForDatabase,
  databaseFailureRequiresReconciliation,
  isRetryableTransactionError,
  normalizeAuthorityReconciliationRow,
  normalizedAuthorityRequestFor,
  requestDigestFor,
  signedEvidenceDigestFor
} from "../src/cloud/authority-store.js";
import {
  authorizationBindingFor,
  logicalAuthorityKeyFor
} from "../src/cloud/authority-identity.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";

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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function reconciliationFixture(overrides = {}) {
  const request = normalizedAuthorityRequestFor(REQUEST);
  const authorizationEpoch = 1;
  const logicalAuthority = logicalAuthorityKeyFor({
    logicalActionDigest: request.logicalActionDigest,
    authorizationEpoch
  });
  const authorizationBinding = authorizationBindingFor({
    logicalActionDigest: request.logicalActionDigest,
    proposalDigest: request.proposalDigest,
    authorizationEpoch
  });
  const databaseNow = "2026-08-01T18:01:00.000Z";
  const leaseExpiresAt = "2026-08-01T18:04:00.000Z";
  return {
    request,
    row: {
      tenant_id: request.tenantId,
      operation_id: request.operationId,
      request_digest: request.requestDigest,
      request_payload: structuredClone(request.requestPayload),
      proposal_digest: request.proposalDigest,
      logical_action_digest: request.logicalActionDigest,
      authorization_epoch: String(authorizationEpoch),
      logical_authority_key_sha256:
        logicalAuthority.logicalAuthorityKeySha256,
      authorization_binding_sha256:
        authorizationBinding.authorizationBindingSha256,
      run_id: request.runId,
      incident_id: request.incidentId,
      resource_id: request.resourceId,
      agent_id: request.agentId,
      agency: request.agency,
      evidence_id: request.evidenceId,
      evidence_digest: request.selectedEvidenceDigest,
      effect_key: request.effectKey,
      payload_digest: request.payloadDigest,
      policy_version: request.policyVersion,
      outcome: "resource_reserved",
      reason: null,
      fencing_token: "1",
      lease_expires_at: leaseExpiresAt,
      observed_holder_operation_id: null,
      observed_fence: null,
      reconciliation_kind: "operation_replay",
      intent_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
      outbox_operation_id: request.operationId,
      outbox_request_digest: request.requestDigest,
      outbox_proposal_digest: request.proposalDigest,
      outbox_logical_action_digest: request.logicalActionDigest,
      outbox_authorization_epoch: String(authorizationEpoch),
      outbox_logical_authority_key_sha256:
        logicalAuthority.logicalAuthorityKeySha256,
      outbox_authorization_binding_sha256:
        authorizationBinding.authorizationBindingSha256,
      outbox_run_id: request.runId,
      outbox_incident_id: request.incidentId,
      outbox_resource_id: request.resourceId,
      outbox_effect_key: request.effectKey,
      outbox_intent_kind: "dispatch_rescue_unit",
      outbox_payload: structuredClone(request.payload),
      outbox_payload_digest: request.payloadDigest,
      outbox_fencing_token: "1",
      current_fence: "1",
      active_run_id: request.runId,
      holder_operation_id: request.operationId,
      holder_proposal_digest: request.proposalDigest,
      holder_logical_authority_key_sha256:
        logicalAuthority.logicalAuthorityKeySha256,
      resource_lease_expires_at: leaseExpiresAt,
      receipt_proposal_tenant_id: request.tenantId,
      receipt_proposal_digest: request.proposalDigest,
      receipt_proposal_logical_action_digest:
        request.logicalActionDigest,
      receipt_proposal_resource_id: request.resourceId,
      receipt_proposal_agency: request.agency,
      receipt_proposal_action_kind: request.actionKind,
      receipt_proposal_payload: structuredClone(request.payload),
      receipt_proposal_payload_canonical: canonicalJson(request.payload),
      receipt_proposal_payload_digest: request.payloadDigest,
      receipt_proposal_retrieval_id: request.dviProposal.retrievalId,
      receipt_proposal_run_id: request.dviProposal.runId,
      receipt_proposal_incident_id: request.dviProposal.incidentId,
      receipt_proposal_authority_evidence_binding_sha256:
        request.dviProposal.authorityEvidenceBindingSha256,
      receipt_proposal_policy_version: request.dviProposal.policyVersion,
      receipt_proposal_selected_rank: String(
        request.dviProposal.selectedRank
      ),
      receipt_proposal_selected_evidence_id: request.evidenceId,
      receipt_proposal_selected_evidence_digest:
        request.selectedEvidenceDigest,
      receipt_proposal_admitted_at: request.dviProposal.admittedAt,
      receipt_proposal_expires_at: request.dviProposal.expiresAt,
      receipt_proposal_authorization_epoch: String(authorizationEpoch),
      receipt_proposal_logical_authority_key_sha256:
        logicalAuthority.logicalAuthorityKeySha256,
      receipt_proposal_authorization_binding_sha256:
        authorizationBinding.authorizationBindingSha256,
      database_now: databaseNow,
      ...overrides
    }
  };
}

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

test("extended authority lease is reserved for one exact 30-minute DVI window", () => {
  const exactExtended = structuredClone(REQUEST);
  exactExtended.leaseMs = 30 * 60_000;
  exactExtended.dviAuthorization.dviProposal.expiresAt =
    "2026-08-01T18:30:00.000Z";
  assert.equal(
    normalizedAuthorityRequestFor(exactExtended).requestPayload.leaseMs,
    30 * 60_000
  );

  for (const changed of [
    { ...exactExtended, leaseMs: 10 * 60_000 + 1 },
    {
      ...exactExtended,
      dviAuthorization: {
        ...exactExtended.dviAuthorization,
        dviProposal: {
          ...exactExtended.dviAuthorization.dviProposal,
          expiresAt: "2026-08-01T18:29:59.999Z"
        }
      }
    }
  ]) {
    assert.throws(
      () => normalizedAuthorityRequestFor(changed),
      /extended lease is reserved for the exact fresh recovery window/u
    );
  }
});

test("only CockroachDB serialization failures are transaction-retryable", () => {
  assert.equal(isRetryableTransactionError({ code: "40001" }), true);
  assert.equal(isRetryableTransactionError({ code: "23505" }), false);
  assert.equal(isRetryableTransactionError(new Error("connection reset")), false);
});

test("every post-COMMIT authority failure requires exact reconciliation", () => {
  assert.equal(
    databaseFailureRequiresReconciliation(
      { code: "XX000" },
      { commitDispatched: true }
    ),
    true
  );
  assert.equal(
    databaseFailureRequiresReconciliation(
      { code: "40001" },
      { commitDispatched: false }
    ),
    false
  );
  assert.equal(
    databaseFailureRequiresReconciliation(
      { code: "40003" },
      { commitDispatched: false }
    ),
    true
  );
});

test("authority reconciliation accepts one fully bound terminal receipt", () => {
  const { row, request } = reconciliationFixture();
  assert.deepEqual(normalizeAuthorityReconciliationRow(row, {
    ...request,
    authorizationEpoch: 1
  }), {
    authorityStillCurrent: true,
    committedOutcome: "resource_reserved",
    storedEpoch: 1
  });
});

test("authority reconciliation rejects per-field receipt and outbox drift", () => {
  const mutations = [
    (row) => ({
      ...row,
      request_payload: { ...row.request_payload, agentId: "changed-agent" }
    }),
    (row) => ({ ...row, request_digest: "f".repeat(64) }),
    (row) => ({
      ...row,
      operation_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    }),
    (row) => ({ ...row, reason: "invented_positive_reason" }),
    (row) => ({ ...row, fencing_token: null }),
    (row) => ({ ...row, lease_expires_at: null }),
    (row) => ({ ...row, proposal_digest: "e".repeat(64) }),
    (row) => ({
      ...row,
      outbox_operation_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    }),
    (row) => ({ ...row, outbox_request_digest: "e".repeat(64) }),
    (row) => ({ ...row, outbox_payload_digest: "e".repeat(64) }),
    (row) => ({ ...row, receipt_proposal_payload: { action: "changed" } }),
    (row) => ({
      ...row,
      receipt_proposal_selected_evidence_digest: "e".repeat(64)
    }),
    (row) => ({ ...row, receipt_proposal_digest: "e".repeat(64) }),
    (row) => ({
      ...row,
      receipt_proposal_logical_action_digest: "e".repeat(64)
    }),
    (row) => ({ ...row, receipt_proposal_run_id: REQUEST.operationId }),
    (row) => ({ ...row, receipt_proposal_incident_id: REQUEST.operationId }),
    (row) => ({ ...row, receipt_proposal_resource_id: "changed-resource" }),
    (row) => ({ ...row, receipt_proposal_agency: "changed-agency" }),
    (row) => ({
      ...row,
      receipt_proposal_authority_evidence_binding_sha256: "e".repeat(64)
    }),
    (row) => ({ ...row, receipt_proposal_policy_version: "changed-policy" }),
    (row) => ({ ...row, receipt_proposal_selected_rank: "2" }),
    (row) => ({ ...row, receipt_proposal_admitted_at: row.database_now }),
    (row) => ({ ...row, receipt_proposal_authorization_epoch: "2" }),
    (row) => ({
      ...row,
      receipt_proposal_authorization_binding_sha256: "e".repeat(64)
    }),
    (row) => {
      const requestPayload = {
        ...row.request_payload,
        selectedEvidenceDigest: "9".repeat(64)
      };
      return {
        ...row,
        receipt_proposal_selected_evidence_digest: "9".repeat(64),
        evidence_digest: "9".repeat(64),
        request_payload: requestPayload,
        request_digest: sha256(canonicalJson(requestPayload))
      };
    }
  ];

  for (const mutate of mutations) {
    const { row, request } = reconciliationFixture();
    assert.throws(
      () => normalizeAuthorityReconciliationRow(mutate(row), {
        ...request,
        authorizationEpoch: 1
      }),
      /authority reconciliation/u
    );
  }
});

test("authority reconciliation binds held-denial observation fields", () => {
  const { row, request } = reconciliationFixture({
    outcome: "resource_held_denied",
    reason: "active_holder",
    fencing_token: null,
    lease_expires_at: null,
    observed_holder_operation_id:
      "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    observed_fence: "1",
    intent_id: null,
    outbox_operation_id: null,
    outbox_request_digest: null,
    outbox_proposal_digest: null,
    outbox_logical_action_digest: null,
    outbox_authorization_epoch: null,
    outbox_logical_authority_key_sha256: null,
    outbox_authorization_binding_sha256: null,
    outbox_run_id: null,
    outbox_incident_id: null,
    outbox_resource_id: null,
    outbox_effect_key: null,
    outbox_intent_kind: null,
    outbox_payload: null,
    outbox_payload_digest: null,
    outbox_fencing_token: null
  });
  assert.equal(
    normalizeAuthorityReconciliationRow(row, {
      ...request,
      authorizationEpoch: 1
    }).authorityStillCurrent,
    false
  );
  for (const changes of [
    { observed_holder_operation_id: null },
    { observed_fence: null },
    { observed_fence: "0" }
  ]) {
    assert.throws(
      () => normalizeAuthorityReconciliationRow({ ...row, ...changes }, {
        ...request,
        authorizationEpoch: 1
      }),
      /terminal state mismatch/u
    );
  }
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

test("authority payloads reject values outside the exact dispatch schema", () => {
  for (const payload of [null, undefined]) {
    assert.throws(
      () => requestDigestFor({ ...REQUEST, payload }),
      /AUTHORITY_DISPATCH_PAYLOAD_SHAPE/
    );
  }
  assert.throws(
    () =>
      requestDigestFor({
        ...REQUEST,
        payload: { ...REQUEST.payload, unsafe: undefined }
      }),
    /AUTHORITY_DISPATCH_PAYLOAD_SHAPE/
  );
  assert.throws(
    () =>
      requestDigestFor({
        ...REQUEST,
        payload: { ...REQUEST.payload, unsafe: Number.NaN }
      }),
    /AUTHORITY_DISPATCH_PAYLOAD_SHAPE/
  );
  const cyclic = { ...REQUEST.payload };
  cyclic.self = cyclic;
  assert.throws(
    () => requestDigestFor({ ...REQUEST, payload: cyclic }),
    /AUTHORITY_DISPATCH_PAYLOAD_SHAPE/
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
