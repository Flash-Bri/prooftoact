import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  freshRecoverySourceIdentity,
  produceFreshRecoverySource
} from "../scripts/fresh-recovery-source-execution.js";

const OPERATION_ID = "c0848ec9-ad19-4b4e-b291-7521f3e0b85e";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const EVIDENCE_DIGEST = "c".repeat(64);
const AUTHORITY_BINDING = "d".repeat(64);
const LOGICAL_AUTHORITY = "e".repeat(64);
const AUTHORIZATION_BINDING = "f".repeat(64);
const ADMITTED_AT = "2026-08-19T09:59:00.000Z";
const EXPIRES_AT = "2026-08-19T10:29:00.000Z";
const DATABASE_NOW = "2026-08-19T10:00:00.000Z";

function g1Row(request, outcome) {
  const winner = outcome === "resource_reserved";
  return {
    decision_outcome: outcome,
    decision_reason: winner ? null : "active_holder",
    decision_fencing_token: winner ? "1" : null,
    decision_lease_expires_at: winner ? EXPIRES_AT : null,
    decision_operation_id: request.operationId,
    decision_request_digest: request.requestDigest,
    decision_replay_kind: null,
    decision_proposal_digest: request.proposalDigest,
    decision_logical_action_digest: request.logicalActionDigest,
    decision_authorization_epoch: "1",
    decision_logical_authority_key_sha256: LOGICAL_AUTHORITY,
    decision_authorization_binding_sha256: AUTHORIZATION_BINDING,
    decision_authority_current: winner,
    decision_database_now: DATABASE_NOW
  };
}

function harness({ mutateRaceRow, mutateResidualRow } = {}) {
  const calls = [];
  const identity = freshRecoverySourceIdentity(
    OPERATION_ID,
    SOURCE_COMMIT,
    TREE_DIGEST
  );
  let raceRequests;
  const store = {
    async registerVerificationKey() {},
    async appendSignedEvidence() {},
    async close() { calls.push("close"); },
    async prepareResource(value) { calls.push(["prepareResource", value]); },
    async verificationSnapshot() {
      return {
        verification: { outcome: "verified" },
        evidence: { evidence_digest: EVIDENCE_DIGEST }
      };
    },
    async snapshot() {
      assert.equal(raceRequests.length, 2);
      return {
        resource: {
          current_fence: "1",
          holder_operation_id: raceRequests[0].operationId
        },
        proposals: [],
        receipts: raceRequests.map((request, index) => ({
          operation_id: request.operationId,
          request_digest: request.requestDigest,
          outcome: index === 0 ? "resource_reserved" : "resource_held_denied"
        })),
        outbox: [{ operation_id: raceRequests[0].operationId }],
        effects: []
      };
    }
  };
  const signer = {
    async register() {
      calls.push("register");
      return { outcome: "verification_key_registered" };
    },
    async append() {
      calls.push("append");
      return { outcome: "evidence_verified" };
    }
  };
  const dviProposal = Object.freeze({
    tenantId: identity.tenantId,
    runId: identity.runId,
    incidentId: identity.incidentId,
    retrievalId: identity.retrievalId,
    authorityEvidenceBindingSha256: AUTHORITY_BINDING,
    selectedEvidenceId: identity.evidenceId,
    selectedEvidenceDigest: EVIDENCE_DIGEST,
    policyVersion: "g1-admissibility-v2",
    selectedRank: 1,
    admittedAt: ADMITTED_AT,
    expiresAt: EXPIRES_AT
  });
  const dependencies = {
    async assertChangedInputDenied(request) {
      calls.push(["changedInput", request]);
      return { denied: true, reason: "operation_digest_mismatch" };
    },
    async authorizeContenders(inputs) {
      calls.push(["authorizeContenders", inputs]);
      return inputs.map(() => ({
        backendId: crypto.randomUUID(),
        authorization: {
          outcome: "proposal_authorized",
          authorizationCurrent: true,
          dviAuthorization: {
            dviProposal,
            selectedEvidenceId: identity.evidenceId,
            selectedEvidenceDigest: EVIDENCE_DIGEST
          }
        }
      }));
    },
    createSigner: () => signer,
    createStore: () => store,
    async proveDviSelection(spec, sourceCommit, treeDigest) {
      calls.push(["proveDviSelection", spec, sourceCommit, treeDigest]);
      return {
        receipt: {
          schemaVersion: "prooftoact.fresh-recovery-admissible-vector-proof.v1",
          status: "PASS",
          snapshot: { admittedAt: ADMITTED_AT, expiresAt: EXPIRES_AT },
          drill: { durableSelectionCommitted: true },
          ranking: {
            directDviResultValidated: true,
            commitValidatorSequenceMatchedDirectDvi: true,
            vectorSearchUsed: true,
            exactPrefixSpansUsed: true
          },
          cleanup: { snapshotRetired: true }
        },
        privateSelection: {
          selectedEvidenceId: identity.evidenceId,
          selectedEvidenceDigest: EVIDENCE_DIGEST,
          dviProposal
        }
      };
    },
    async raceAuthority(requests) {
      calls.push(["raceAuthority", requests]);
      raceRequests = requests;
      return requests.map((request, index) => ({
        status: "fulfilled",
        value: {
          row: mutateRaceRow?.(
            g1Row(request, index === 0
              ? "resource_reserved"
              : "resource_held_denied"),
            index
          ) ?? g1Row(request, index === 0
            ? "resource_reserved"
            : "resource_held_denied"),
          transaction: {
            backendIds: [`backend-${index + 1}`],
            initialBackendId: `backend-${index + 1}`,
            isolation: "serializable",
            retryCodes: [],
            serializableRetries: 0
          }
        }
      }));
    },
    async readDviResidual() {
      return {
        rowCount: 1,
        rows: [{
          admitted_at: ADMITTED_AT,
          expires_at: EXPIRES_AT,
          database_now: DATABASE_NOW,
          minimum_residual_ms: "1740000"
        }]
      };
    },
    async readRecoveryResidual(binding) {
      const row = {
        database_now: DATABASE_NOW,
        operation_id: binding.operationId,
        request_digest: binding.requestDigest,
        outcome: "resource_reserved",
        fencing_token: "1",
        evidence_id: binding.evidenceId,
        evidence_digest: EVIDENCE_DIGEST,
        proposal_selected_evidence_id: binding.evidenceId,
        proposal_selected_evidence_digest: EVIDENCE_DIGEST,
        authority_evidence_binding_sha256: AUTHORITY_BINDING,
        holder_operation_id: binding.operationId,
        current_fence: "1",
        minimum_residual_ms: "1740000"
      };
      return {
        rowCount: 1,
        rows: [mutateResidualRow?.(row) ?? row]
      };
    },
    async replayAuthority(request) {
      calls.push(["replayAuthority", request]);
      return {
        row: {
          ...g1Row(request, "resource_held_denied"),
          decision_replay_kind: "operation_replay"
        }
      };
    }
  };
  return { calls, dependencies, identity };
}

async function produce(dependencies) {
  return produceFreshRecoverySource({
    adminConnectionString:
      "postgresql://admin:password" +
      "@fresh.aws.cockroachlabs.cloud:26257/" +
      "defaultdb?sslmode=verify-full",
    clock: () => Date.parse(DATABASE_NOW),
    credentialBundle: { passwords: {} },
    dependencies,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
}

test("G1 spend binds exactly the 18 positional function arguments", () => {
  const request = {
    tenantId: "10000000-0000-4000-8000-000000000001",
    operationId: "10000000-0000-4000-8000-000000000002",
    requestDigest: "request-digest",
    requestPayload: { position: 4 },
    proposalDigest: "proposal-digest",
    logicalActionDigest: "logical-action-digest",
    selectedEvidenceDigest: "selected-evidence-digest",
    runId: "10000000-0000-4000-8000-000000000008",
    incidentId: "10000000-0000-4000-8000-000000000009",
    resourceId: "resource-id",
    agentId: "agent-id",
    agency: "agency",
    evidenceId: "10000000-0000-4000-8000-000000000013",
    effectKey: "10000000-0000-4000-8000-000000000014",
    payload: { position: 15 },
    payloadDigest: "payload-digest",
    policyVersion: "policy-version",
    leaseMs: 1_800_000
  };
  assert.deepEqual(
    __test.SPEND_AUTHORITY_SQL.match(/\$\d+/gu),
    Array.from({ length: 18 }, (_, index) => `$${index + 1}`)
  );
  assert.deepEqual(__test.spendValues(request), [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.proposalDigest,
    request.logicalActionDigest,
    request.selectedEvidenceDigest,
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
  ]);
});

test("fresh source proves bounded DVI and a durable two-contender G1 race", async () => {
  const value = harness();
  const receipt = await produce(value.dependencies);
  assert.equal(receipt.schemaVersion,
    "prooftoact.fresh-recovery-source-receipt.v2");
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.evidenceVerified, true);
  assert.equal(receipt.durableAuthorityReceipt, true);
  assert.equal(receipt.operationId, OPERATION_ID);
  assert.equal(receipt.sourceBinding.operationId,
    value.identity.contenders[0].operationId);
  assert.notEqual(receipt.sourceBinding.operationId, OPERATION_ID);
  assert.equal(receipt.raceProof.contenderCount, 2);
  assert.equal(receipt.raceProof.durableReceiptCount, 2);
  assert.equal(receipt.raceProof.durableDenialCount, 1);
  assert.equal(receipt.raceProof.outboxCount, 1);
  assert.equal(receipt.raceProof.protectedEffectCount, 0);
  const dviCall = value.calls.find((entry) => Array.isArray(entry) &&
    entry[0] === "proveDviSelection");
  assert.equal(dviCall[1].expectedCandidateCount, 11);
  assert.equal(dviCall[1].exclusionCases.length, 1);
  assert.equal(dviCall[1].exclusionCases[0].reason, "out_of_scope");
  assert.equal(dviCall[2], SOURCE_COMMIT);
  assert.equal(dviCall[3], TREE_DIGEST);
  assert.equal(value.calls.filter((entry) => entry === "append").length, 12);
  assert.equal(value.calls.at(-1), "close");
});

test("G1 spend result validation accepts exactly the live 14-column shape", () => {
  const value = harness();
  const request = {
    operationId: value.identity.contenders[0].operationId,
    requestDigest: "1".repeat(64),
    proposalDigest: "2".repeat(64),
    logicalActionDigest: "3".repeat(64)
  };
  const row = g1Row(request, "resource_reserved");
  assert.equal(__test.validG1SpendRow(row, request), true);
  assert.equal(__test.validG1SpendRow({
    ...row,
    decision_durable_receipt: true
  }, request), false);
});

test("fresh source rejects a G2-only synthetic durability column", async () => {
  const value = harness({
    mutateRaceRow: (row, index) => index === 0
      ? { ...row, decision_durable_receipt: true }
      : row
  });
  await assert.rejects(
    produce(value.dependencies),
    /FRESH_RECOVERY_SOURCE_G1_SPEND_SHAPE_REJECTED/u
  );
  assert.equal(value.calls.at(-1), "close");
});

test("fresh source rejects residual authority from unrelated evidence", async () => {
  const value = harness({
    mutateResidualRow: (row) => ({
      ...row,
      proposal_selected_evidence_id:
        "861bc544-35e6-475a-9140-51e7252b5f1d"
    })
  });
  await assert.rejects(
    produce(value.dependencies),
    /FRESH_RECOVERY_SOURCE_RESIDUAL_TTL_REJECTED/u
  );
  assert.equal(value.calls.at(-1), "close");
});

test("changed-input denial requires the exact reviewed SQLSTATE and message", () => {
  assert.equal(__test.changedInputMismatchError({
    code: "22000",
    message: "operation digest mismatch"
  }), true);
  assert.equal(__test.changedInputMismatchError({
    code: "P0001",
    message: "operation digest mismatch"
  }), false);
  assert.equal(__test.changedInputMismatchError({
    code: "22000",
    message: "prefix operation digest mismatch suffix"
  }), false);
});

test("operation identity is deterministic, source-bound, and domain-separated", () => {
  const first = freshRecoverySourceIdentity(
    OPERATION_ID,
    SOURCE_COMMIT,
    TREE_DIGEST
  );
  const second = freshRecoverySourceIdentity(
    OPERATION_ID,
    SOURCE_COMMIT,
    TREE_DIGEST
  );
  const changedTree = freshRecoverySourceIdentity(
    OPERATION_ID,
    SOURCE_COMMIT,
    "c".repeat(40)
  );
  assert.deepEqual(first, second);
  assert.notDeepEqual(first, changedTree);
  const ids = [
    first.tenantId,
    first.runId,
    first.incidentId,
    first.evidenceId,
    first.excludedEvidenceId,
    first.retrievalId,
    ...first.candidateEvidenceIds,
    ...first.contenders.flatMap(({ operationId, effectKey, intentNonce }) =>
      [operationId, effectKey, intentNonce])
  ];
  assert.equal(new Set(ids).size, ids.length - 1);
  assert.equal(first.evidenceId, first.candidateEvidenceIds[0]);
});
