import assert from "node:assert/strict";
import test from "node:test";

import {
  authorizationBindingFor,
  logicalAuthorityKeyFor
} from "../src/cloud/authority-identity.js";
import { normalizedDviAuthorizationFor } from "../src/cloud/authority-store.js";
import {
  authorizeDviProposalWithClient,
  DVI_PROPOSAL_AUTHORIZATION_SQL
} from "../src/cloud/dvi-proposal-authorization.js";

const IDS = Object.freeze({
  tenant: "11111111-1111-4111-8111-111111111111",
  run: "22222222-2222-4222-8222-222222222222",
  incident: "33333333-3333-4333-8333-333333333333",
  retrieval: "44444444-4444-4444-8444-444444444444",
  evidence: "55555555-5555-4555-8555-555555555555"
});

const PAYLOAD = Object.freeze({
  action: "dispatch_rescue_unit",
  destination: "synthetic-zone-delta",
  scenario: "synthetic-highwater"
});

function input(overrides = {}) {
  return {
    tenantId: IDS.tenant,
    retrievalId: IDS.retrieval,
    expectedRunId: IDS.run,
    expectedIncidentId: IDS.incident,
    requestedSelectedEvidenceId: IDS.evidence,
    requestedSelectedEvidenceDigest: "b".repeat(64),
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

function authorizedRow(overrides = {}) {
  const accepted = input();
  const dviAuthorization = {
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
    selectedEvidenceDigest: "b".repeat(64)
  };
  const normalized = normalizedDviAuthorizationFor({
    ...dviAuthorization,
    logicalAction: accepted.logicalAction
  });
  const authorizationEpoch = 1;
  const logicalAuthority = logicalAuthorityKeyFor({
    logicalActionDigest: normalized.logicalActionDigest,
    authorizationEpoch
  });
  const binding = authorizationBindingFor({
    logicalActionDigest: normalized.logicalActionDigest,
    proposalDigest: normalized.proposalDigest,
    authorizationEpoch
  });
  return {
    decision_outcome: "proposal_authorized",
    decision_reason: null,
    decision_proposal_digest: normalized.proposalDigest,
    decision_logical_action_digest: normalized.logicalActionDigest,
    decision_authorization_epoch: String(authorizationEpoch),
    decision_logical_authority_key_sha256:
      logicalAuthority.logicalAuthorityKeySha256,
    decision_authorization_binding_sha256:
      binding.authorizationBindingSha256,
    decision_authority_evidence_binding_sha256: "a".repeat(64),
    decision_run_id: IDS.run,
    decision_incident_id: IDS.incident,
    decision_policy_version: "g1-admissibility-v2",
    decision_selected_rank: "1",
    decision_selected_evidence_id: IDS.evidence,
    decision_selected_evidence_digest: "b".repeat(64),
    decision_admitted_at: new Date("2026-08-01T18:00:00.000Z"),
    decision_expires_at: new Date("2026-08-01T18:05:00.000Z"),
    decision_payload_digest: normalized.logicalAction.payloadDigest,
    decision_authorized_at: new Date("2026-08-01T18:00:01.000Z"),
    decision_authority_current: true,
    decision_database_now: new Date("2026-08-01T18:00:02.000Z"),
    ...overrides
  };
}

test("least-privilege runtime accepts only a database-derived proposal identity", async () => {
  let observed;
  const client = {
    async query(sql, values) {
      observed = { sql, values };
      return { rowCount: 1, rows: [authorizedRow()] };
    }
  };
  const result = await authorizeDviProposalWithClient(client, input());
  assert.equal(observed.sql, DVI_PROPOSAL_AUTHORIZATION_SQL);
  assert.deepEqual(observed.values.slice(0, 6), [
    IDS.tenant,
    IDS.retrieval,
    IDS.run,
    IDS.incident,
    IDS.evidence,
    "b".repeat(64)
  ]);
  assert.equal(result.outcome, "proposal_authorized");
  assert.equal(result.authorizationCurrent, true);
  assert.equal(result.identity.authorizationEpoch, 1);
  assert.equal(result.dviAuthorization.selectedEvidenceId, IDS.evidence);
});

test("selection mismatch returns no runtime authorization", async () => {
  const client = {
    async query() {
      return {
        rowCount: 1,
        rows: [{
          decision_outcome: "proposal_authorization_denied",
          decision_reason: "dvi_selection_request_mismatch",
          decision_authority_current: false,
          decision_database_now: new Date("2026-08-01T18:00:02.000Z")
        }]
      };
    }
  };
  const result = await authorizeDviProposalWithClient(client, input({
    requestedSelectedEvidenceId:
      "66666666-6666-4666-8666-666666666666"
  }));
  assert.deepEqual(result, {
    outcome: "proposal_authorization_denied",
    reason: "dvi_selection_request_mismatch",
    authorizationCurrent: false,
    databaseNow: "2026-08-01T18:00:02.000Z"
  });
  assert.equal("dviAuthorization" in result, false);
});

test("runtime rejects a database row with a forged logical binding", async () => {
  const client = {
    async query() {
      return {
        rowCount: 1,
        rows: [authorizedRow({
          decision_authorization_binding_sha256: "f".repeat(64)
        })]
      };
    }
  };
  await assert.rejects(
    authorizeDviProposalWithClient(client, input()),
    /DVI_PROPOSAL_DATABASE_BINDING_MISMATCH/u
  );
});
