import assert from "node:assert/strict";
import test from "node:test";

import {
  AUTHORITY_IDENTITY_CONTRACT,
  authorizationBindingFor,
  dviProposalIdentityDigestFor,
  logicalActionDigestFor,
  logicalActionIdentityFor,
  logicalAuthorityKeyFor
} from "../src/cloud/authority-identity.js";

const ACTION = Object.freeze({
  tenantId: "11111111-1111-4111-8111-111111111111",
  incidentId: "22222222-2222-4222-8222-222222222222",
  resourceId: "synthetic-rescue-unit-7",
  agency: "coastal-rescue",
  actionKind: "dispatch_rescue_unit",
  payloadDigest: "a".repeat(64)
});

function proposal(overrides = {}) {
  return {
    tenantId: ACTION.tenantId,
    runId: "33333333-3333-4333-8333-333333333333",
    incidentId: ACTION.incidentId,
    retrievalId: "44444444-4444-4444-8444-444444444444",
    logicalActionDigest: logicalActionDigestFor(ACTION),
    authorityEvidenceBindingSha256: "b".repeat(64),
    policyVersion: "g1-admissibility-v2",
    selectedRank: 1,
    admittedAt: "2026-08-01T12:00:00.000Z",
    expiresAt: "2026-08-01T12:01:00.000Z",
    ...overrides
  };
}

test("logical action identity has one strict canonical field set", () => {
  const identity = logicalActionIdentityFor({
    payloadDigest: ACTION.payloadDigest,
    actionKind: ACTION.actionKind,
    agency: ACTION.agency,
    resourceId: ACTION.resourceId,
    incidentId: ACTION.incidentId.toUpperCase(),
    tenantId: ACTION.tenantId.toUpperCase()
  });
  assert.equal(identity.schemaVersion, "tideproof.authority.logical-action.v1");
  assert.equal(identity.tenantId, ACTION.tenantId);
  assert.equal(identity.incidentId, ACTION.incidentId);
  assert.match(logicalActionDigestFor(ACTION), /^[0-9a-f]{64}$/u);
  assert.throws(
    () => logicalActionDigestFor({ ...ACTION, operationId: ACTION.incidentId }),
    /AUTHORITY_LOGICAL_ACTION_SHAPE/u
  );
});

test("every logical effect field is digest-bearing", () => {
  const original = logicalActionDigestFor(ACTION);
  for (const changed of [
    { tenantId: "99999999-9999-4999-8999-999999999999" },
    { incidentId: "88888888-8888-4888-8888-888888888888" },
    { resourceId: "synthetic-rescue-unit-8" },
    { agency: "mutual-aid" },
    { payloadDigest: "f".repeat(64) }
  ]) {
    assert.notEqual(logicalActionDigestFor({ ...ACTION, ...changed }), original);
  }
  assert.throws(
    () => logicalActionDigestFor({ ...ACTION, actionKind: "other" }),
    /AUTHORITY_ACTION_KIND_UNSUPPORTED/u
  );
});

test("attempt and proposal context cannot enter logical action identity", () => {
  assert.deepEqual(AUTHORITY_IDENTITY_CONTRACT.attemptOnlyFields, [
    "operationId",
    "agentId",
    "intentNonce",
    "effectKey",
    "leaseMs",
    "raceId",
    "callerSubjectHash"
  ]);
  assert.equal(
    AUTHORITY_IDENTITY_CONTRACT.attemptOnlyFields.some((field) =>
      AUTHORITY_IDENTITY_CONTRACT.logicalActionFields.includes(field)
    ),
    false
  );
  assert.equal(
    AUTHORITY_IDENTITY_CONTRACT.proposalContextOnlyFields.some((field) =>
      AUTHORITY_IDENTITY_CONTRACT.logicalActionFields.includes(field)
    ),
    false
  );
});

test("proposal identity binds every exact DVI selection field", () => {
  const original = dviProposalIdentityDigestFor(proposal());
  assert.match(original, /^[0-9a-f]{64}$/u);
  for (const changed of [
    { runId: "55555555-5555-4555-8555-555555555555" },
    { retrievalId: "66666666-6666-4666-8666-666666666666" },
    { logicalActionDigest: "c".repeat(64) },
    { authorityEvidenceBindingSha256: "d".repeat(64) },
    { policyVersion: "g1-admissibility-v3" },
    { admittedAt: "2026-08-01T12:00:01.000Z" },
    { expiresAt: "2026-08-01T12:01:01.000Z" }
  ]) {
    assert.notEqual(
      dviProposalIdentityDigestFor(proposal(changed)),
      original
    );
  }
});

test("proposal identity rejects rank, time, and schema ambiguity", () => {
  assert.throws(
    () => dviProposalIdentityDigestFor(proposal({ selectedRank: 2 })),
    /AUTHORITY_DVI_SELECTED_RANK/u
  );
  assert.throws(
    () =>
      dviProposalIdentityDigestFor(
        proposal({ expiresAt: "2026-08-01T12:00:00.000Z" })
      ),
    /AUTHORITY_DVI_PROPOSAL_TIME/u
  );
  assert.throws(
    () => dviProposalIdentityDigestFor({ ...proposal(), operationId: "x" }),
    /AUTHORITY_DVI_PROPOSAL_SHAPE/u
  );
});

test("only an explicit authorization epoch remints a logical authority key", () => {
  const logicalActionDigest = logicalActionDigestFor(ACTION);
  const first = logicalAuthorityKeyFor({
    logicalActionDigest,
    authorizationEpoch: 1
  });
  const replay = logicalAuthorityKeyFor({
    authorizationEpoch: 1,
    logicalActionDigest
  });
  const next = logicalAuthorityKeyFor({
    logicalActionDigest,
    authorizationEpoch: 2
  });
  assert.equal(
    first.logicalAuthorityKeySha256,
    replay.logicalAuthorityKeySha256
  );
  assert.notEqual(
    first.logicalAuthorityKeySha256,
    next.logicalAuthorityKeySha256
  );
  assert.throws(
    () => logicalAuthorityKeyFor({ logicalActionDigest, authorizationEpoch: 0 }),
    /authorizationEpoch outside policy/u
  );
});

test("a new proposal changes authorization binding but not the authority key", () => {
  const logicalActionDigest = logicalActionDigestFor(ACTION);
  const firstProposal = dviProposalIdentityDigestFor(proposal());
  const secondProposal = dviProposalIdentityDigestFor(
    proposal({
      retrievalId: "77777777-7777-4777-8777-777777777777",
      authorityEvidenceBindingSha256: "e".repeat(64)
    })
  );
  const first = authorizationBindingFor({
    logicalActionDigest,
    proposalDigest: firstProposal,
    authorizationEpoch: 1
  });
  const second = authorizationBindingFor({
    logicalActionDigest,
    proposalDigest: secondProposal,
    authorizationEpoch: 1
  });
  assert.equal(
    first.logicalAuthorityKeySha256,
    second.logicalAuthorityKeySha256
  );
  assert.notEqual(
    first.authorizationBindingSha256,
    second.authorizationBindingSha256
  );
});

test("identity inputs reject noncanonical text, digests, and timestamps", () => {
  assert.throws(
    () => logicalActionDigestFor({ ...ACTION, resourceId: " padded " }),
    /resourceId must be bounded canonical text/u
  );
  assert.throws(
    () => logicalActionDigestFor({ ...ACTION, payloadDigest: "A".repeat(64) }),
    /payloadDigest must be lowercase SHA-256 hex/u
  );
  assert.throws(
    () =>
      dviProposalIdentityDigestFor(
        proposal({ admittedAt: "2026-08-01T12:00:00Z" })
      ),
    /admittedAt must be canonical UTC milliseconds/u
  );
});
