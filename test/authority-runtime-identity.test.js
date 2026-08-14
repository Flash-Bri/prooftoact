import assert from "node:assert/strict";
import test from "node:test";

import {
  normalizedAuthorityRequestFor,
  normalizedDviAuthorizationFor
} from "../src/cloud/authority-store.js";

const IDS = Object.freeze({
  tenant: "11111111-1111-4111-8111-111111111111",
  run: "22222222-2222-4222-8222-222222222222",
  incident: "33333333-3333-4333-8333-333333333333",
  retrieval: "44444444-4444-4444-8444-444444444444",
  evidence: "55555555-5555-4555-8555-555555555555",
  operation: "66666666-6666-4666-8666-666666666666",
  nonce: "77777777-7777-4777-8777-777777777777",
  effect: "88888888-8888-4888-8888-888888888888"
});

const PAYLOAD = Object.freeze({
  scenario: "synthetic-highwater",
  action: "dispatch_rescue_unit",
  destination: "synthetic-zone-delta"
});

function authorization(overrides = {}) {
  return {
    dviProposal: {
      tenantId: IDS.tenant,
      runId: IDS.run,
      incidentId: IDS.incident,
      retrievalId: IDS.retrieval,
      authorityEvidenceBindingSha256: "a".repeat(64),
      selectedEvidenceId: IDS.evidence,
      selectedEvidenceDigest: "b".repeat(64),
      policyVersion: "g1-admissibility-v2",
      selectedRank: 1,
      admittedAt: "2026-08-01T18:00:00.000Z",
      expiresAt: "2026-08-01T18:05:00.000Z"
    },
    selectedEvidenceId: IDS.evidence,
    selectedEvidenceDigest: "b".repeat(64),
    logicalAction: {
      tenantId: IDS.tenant,
      incidentId: IDS.incident,
      resourceId: "synthetic-rescue-unit-7",
      agency: "rescue",
      actionKind: "dispatch_rescue_unit",
      payload: PAYLOAD
    },
    ...overrides
  };
}

function request(overrides = {}) {
  const proposal = authorization();
  return {
    tenantId: IDS.tenant,
    runId: IDS.run,
    incidentId: IDS.incident,
    resourceId: "synthetic-rescue-unit-7",
    operationId: IDS.operation,
    agentId: "synthetic-agent-alpha",
    agency: "rescue",
    evidenceId: IDS.evidence,
    intentNonce: IDS.nonce,
    effectKey: IDS.effect,
    leaseMs: 300_000,
    payload: PAYLOAD,
    dviAuthorization: {
      dviProposal: proposal.dviProposal,
      selectedEvidenceId: proposal.selectedEvidenceId,
      selectedEvidenceDigest: proposal.selectedEvidenceDigest
    },
    ...overrides
  };
}

test("runtime proposal authorization derives all identity digests without a client epoch", () => {
  const normalized = normalizedDviAuthorizationFor(authorization());
  assert.match(normalized.logicalActionDigest, /^[0-9a-f]{64}$/u);
  assert.match(normalized.proposalDigest, /^[0-9a-f]{64}$/u);
  assert.equal(normalized.selectedEvidenceId, IDS.evidence);
  assert.equal(normalized.selectedEvidenceDigest, "b".repeat(64));
  assert.equal("authorizationEpoch" in normalized, false);
  assert.equal("logicalAuthorityKeySha256" in normalized, false);
});

test("authority request binds one exact proposal and selected evidence", () => {
  const prepared = normalizedDviAuthorizationFor(authorization());
  const normalized = normalizedAuthorityRequestFor(request());
  assert.equal(normalized.logicalActionDigest, prepared.logicalActionDigest);
  assert.equal(normalized.proposalDigest, prepared.proposalDigest);
  assert.equal(normalized.evidenceId, prepared.selectedEvidenceId);
  assert.equal(normalized.requestPayload.logicalActionDigest, prepared.logicalActionDigest);
  assert.equal(normalized.requestPayload.proposalDigest, prepared.proposalDigest);
});

test("transport replacement cannot remint logical action or proposal identity", () => {
  const first = normalizedAuthorityRequestFor(request());
  const replacement = normalizedAuthorityRequestFor(request({
    operationId: "99999999-9999-4999-8999-999999999999",
    agentId: "synthetic-agent-replacement",
    intentNonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    effectKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    leaseMs: 60_000
  }));
  assert.equal(replacement.logicalActionDigest, first.logicalActionDigest);
  assert.equal(replacement.proposalDigest, first.proposalDigest);
  assert.notEqual(replacement.requestDigest, first.requestDigest);
});

test("authority dispatch identity is independent of allowed-key insertion order", () => {
  const firstPayload = {
    scenario: "synthetic-highwater",
    action: "dispatch_rescue_unit",
    destination: "synthetic-zone-delta",
    logicalDispatch: "contender-001"
  };
  const secondPayload = {
    logicalDispatch: "contender-001",
    destination: "synthetic-zone-delta",
    action: "dispatch_rescue_unit",
    scenario: "synthetic-highwater"
  };
  const first = normalizedAuthorityRequestFor(
    request({ payload: firstPayload })
  );
  const second = normalizedAuthorityRequestFor(
    request({ payload: secondPayload })
  );
  assert.equal(second.payloadDigest, first.payloadDigest);
  assert.equal(second.logicalActionDigest, first.logicalActionDigest);
  assert.equal(second.proposalDigest, first.proposalDigest);
  assert.equal(second.requestDigest, first.requestDigest);
});

test("authority dispatch identity rejects fields outside the domain schema", () => {
  assert.throws(
    () => normalizedAuthorityRequestFor(request({
      payload: { ...PAYLOAD, alternateIdentity: "forbidden" }
    })),
    /AUTHORITY_DISPATCH_PAYLOAD_SHAPE/u
  );
});

test("proposal and request context mismatches fail before database use", () => {
  assert.throws(
    () => normalizedDviAuthorizationFor(authorization({
      selectedEvidenceId: IDS.operation
    })),
    /AUTHORITY_DVI_SELECTION_MISMATCH/u
  );
  assert.throws(
    () => normalizedAuthorityRequestFor(request({ evidenceId: IDS.operation })),
    /AUTHORITY_SELECTED_EVIDENCE_MISMATCH/u
  );
  assert.throws(
    () => normalizedAuthorityRequestFor(request({ runId: IDS.incident })),
    /AUTHORITY_PROPOSAL_REQUEST_MISMATCH/u
  );
});
