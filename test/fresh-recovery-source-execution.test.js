import assert from "node:assert/strict";
import test from "node:test";

import { authorizeSyntheticProposal } from
  "../scripts/lib/synthetic-authority-proposal.js";
import {
  freshRecoverySourceIdentity,
  produceFreshRecoverySource
} from "../scripts/fresh-recovery-source-execution.js";

const OPERATION_ID = "c0848ec9-ad19-4b4e-b291-7521f3e0b85e";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const EVIDENCE_DIGEST = "c".repeat(64);

function harness() {
  const calls = [];
  const store = {
    async registerVerificationKey() {},
    async appendSignedEvidence() {},
    async close() { calls.push("close"); },
    async prepareResource(value) { calls.push(["prepareResource", value]); },
    async recordDviSelectionReceiptForTest(value) {
      calls.push(["recordDvi", value]);
    },
    async verificationSnapshot() {
      return {
        verification: { outcome: "verified" },
        evidence: { evidence_digest: EVIDENCE_DIGEST }
      };
    },
    async authorizeDviProposal(input) {
      calls.push(["authorizeDviProposal", input]);
      return {
        outcome: "proposal_authorized",
        authorizationCurrent: true,
        dviAuthorization: {
          dviProposal: input.dviProposal,
          selectedEvidenceId: input.selectedEvidenceId,
          selectedEvidenceDigest: input.selectedEvidenceDigest
        },
        identity: { proposalDigest: "d".repeat(64) }
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
  const dependencies = {
    authorizeProposal: (acceptedStore, request, options) =>
      authorizeSyntheticProposal(acceptedStore, request, options),
    createSigner: () => signer,
    createStore: () => store,
    async spendAuthority(request) {
      calls.push(["spendAuthority", request]);
      return {
        rowCount: 1,
        rows: [{
          decision_outcome: "resource_reserved",
          decision_fencing_token: "1",
          decision_authorization_binding_sha256: "e".repeat(64),
          decision_logical_authority_key_sha256: "f".repeat(64)
        }]
      };
    }
  };
  return { calls, dependencies };
}

test("fresh source commits signed evidence, exact-source DVI, and authority", async () => {
  const value = harness();
  const receipt = await produceFreshRecoverySource({
    adminConnectionString:
      "postgresql://admin:password" +
      "@fresh.aws.cockroachlabs.cloud:26257/" +
      "defaultdb?sslmode=verify-full",
    clock: () => Date.parse("2026-08-19T10:00:00.000Z"),
    credentialBundle: { passwords: {} },
    dependencies: value.dependencies,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.evidenceVerified, true);
  assert.equal(receipt.durableAuthorityReceipt, true);
  assert.equal(receipt.sourceBinding.operationId, OPERATION_ID);
  const dvi = value.calls.find((entry) => Array.isArray(entry) &&
    entry[0] === "recordDvi")[1];
  assert.equal(dvi.sourceCommit, SOURCE_COMMIT);
  assert.equal(dvi.treeDigest, TREE_DIGEST);
  assert.equal(value.calls.filter((entry) => Array.isArray(entry) &&
    entry[0] === "spendAuthority").length, 1);
  assert.equal(value.calls.at(-1), "close");
});

test("operation identity is deterministic and domain-separated", () => {
  const first = freshRecoverySourceIdentity(OPERATION_ID);
  const second = freshRecoverySourceIdentity(OPERATION_ID);
  assert.deepEqual(first, second);
  assert.equal(new Set([
    first.tenantId, first.runId, first.incidentId, first.evidenceId,
    first.retrievalId, first.effectKey, first.intentNonce
  ]).size, 7);
});
