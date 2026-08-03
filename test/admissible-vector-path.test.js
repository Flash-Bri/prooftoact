import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { authorizeSyntheticProposal } from
  "../scripts/lib/synthetic-authority-proposal.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const store = fs.readFileSync(
  path.join(root, "src/cloud/authority-store.js"),
  "utf8"
);
const security = fs.readFileSync(
  path.join(root, "src/cloud/primary-security.js"),
  "utf8"
);
const retrieval = fs.readFileSync(
  path.join(root, "src/cloud/admissible-vector-retrieval.js"),
  "utf8"
);
const syntheticProposal = fs.readFileSync(
  path.join(root, "scripts/lib/synthetic-authority-proposal.js"),
  "utf8"
);

function definition(name) {
  const start = security.indexOf(`CREATE OR REPLACE FUNCTION ${name}`);
  assert.notEqual(start, -1, `${name} definition missing`);
  const end = security.indexOf("  `);", start);
  assert.notEqual(end, -1, `${name} definition is unterminated`);
  return security.slice(start, end);
}

function tableDefinition(name) {
  const start = store.indexOf(`CREATE TABLE IF NOT EXISTS ${name}`);
  assert.notEqual(start, -1, `${name} definition missing`);
  const end = store.indexOf("    `);", start);
  assert.notEqual(end, -1, `${name} definition is unterminated`);
  return store.slice(start, end);
}

test("synthetic denied diagnostics omit reusable authorization material", async () => {
  const durableProposal = {
    proposal_digest: "b".repeat(64),
    authority_key: "synthetic-authority-key"
  };
  const denied = await authorizeSyntheticProposal(
    {
      recordDviSelectionReceiptForTest: async () => undefined
    },
    {
      tenantId: "00000000-0000-4000-8000-000000000001",
      runId: "00000000-0000-4000-8000-000000000002",
      incidentId: "00000000-0000-4000-8000-000000000003",
      resourceId: "synthetic-resource",
      evidenceId: "00000000-0000-4000-8000-000000000004",
      agency: "rescue",
      payload: { action: "dispatch_rescue_unit" }
    },
    {
      allowDenied: true,
      evidenceDigest: "a".repeat(64),
      retrievalId: "00000000-0000-4000-8000-000000000005",
      proposalAuthorizer: async () => ({
        outcome: "proposal_authorization_denied",
        reason: "logical_authority_already_spent",
        authorityCurrent: false,
        dviAuthorization: { reusable: true },
        proposal: durableProposal,
        identity: durableProposal
      })
    }
  );

  assert.equal(denied.authorization.outcome, "proposal_authorization_denied");
  for (const field of ["dviAuthorization", "proposal", "identity"]) {
    assert.equal(Object.hasOwn(denied, field), false);
    assert.equal(Object.hasOwn(denied.authorization, field), false);
  }
});

test("real admissibility produces a short-lived immutable DVI candidate set", () => {
  assert.match(
    store,
    /CREATE TABLE IF NOT EXISTS tp_private\.g1_vector_retrieval_sets/
  );
  assert.match(
    store,
    /CREATE TABLE IF NOT EXISTS tp_private\.g1_vector_candidates/
  );
  assert.match(
    store,
    /CREATE TABLE IF NOT EXISTS tp_private\.g1_vector_exclusions/
  );
  const candidates = tableDefinition("tp_private.g1_vector_candidates");
  assert.match(candidates, /evidence_digest STRING\(64\) NOT NULL/);
  assert.match(candidates, /CHECK \(length\(evidence_digest\) = 64\)/);

  const evidence = tableDefinition("tp_private.g1_evidence");
  assert.match(evidence, /evidence_digest STRING\(64\) NULL/);

  const exclusions = tableDefinition("tp_private.g1_vector_exclusions");
  assert.match(exclusions, /evidence_digest STRING\(64\) NULL/);
  assert.match(exclusions, /admissibility STRING NOT NULL/);
  assert.match(exclusions, /observed_at TIMESTAMPTZ NOT NULL/);
  assert.match(
    exclusions,
    /evidence_digest IS NULL[\s\S]*OR length\(evidence_digest\) = 64/
  );
  assert.match(exclusions, /CHECK \(admissibility <> 'admissible'\)/);
  assert.match(store, /cleaned_at TIMESTAMPTZ NULL/);
  assert.match(store, /g1_vector_retrieval_sets_expiry_idx/);
  assert.match(
    store,
    /CREATE VECTOR INDEX IF NOT EXISTS\s+g1_vector_candidates_embedding_idx\s+ON tp_private\.g1_vector_candidates\s+\(tenant_id, retrieval_id, embedding vector_cosine_ops\)/
  );
  assert.doesNotMatch(
    store,
    /CREATE VECTOR INDEX[^;`]+ON tp_private\.g1_evidence/
  );

  const internal = definition(
    "tp_private.g1_list_admissibility_internal_v1"
  );
  for (const gate of [
    "verification_binding_mismatch",
    "verification_key_revoked",
    "future_observation",
    "not_yet_valid",
    "expired",
    "out_of_scope",
    "unresolved_conflict"
  ]) {
    assert.match(internal, new RegExp(gate));
  }

  const observe = definition("tp_api.g1_observe_admissibility_v2");
  assert.match(
    observe,
    /FROM tp_private\.g1_list_admissibility_internal_v1/
  );
  assert.doesNotMatch(observe, /FROM tp_private\.g1_evidence/);

  const prepare = definition("tp_api.g1_prepare_vector_set_v1");
  assert.match(
    prepare,
    /FROM tp_private\.g1_list_admissibility_internal_v1[\s\S]*WHERE listed\.admissibility = 'admissible'/
  );
  assert.match(prepare, /v_candidate_count > 10000/);
  assert.match(prepare, /v_exclusion_count > 10000/);
  assert.match(prepare, /p_ttl_ms < 1000 OR p_ttl_ms > 300000/);
  assert.match(prepare, /retrieval identifier already used/);
  assert.match(prepare, /session_user <> 'tp_authorizer_user'/);
  assert.match(
    prepare,
    /INSERT INTO tp_private\.g1_vector_exclusions[\s\S]*listed\.admissibility <> 'admissible'/
  );
  assert.match(
    prepare,
    /listed\.evidence_digest,[\s\S]*listed\.admissibility,[\s\S]*v_admitted_at/
  );

  const observeSnapshot = definition(
    "tp_api.g1_observe_vector_exclusion_v1"
  );
  assert.match(observeSnapshot, /session_user <> 'tp_authorizer_user'/);
  assert.match(
    observeSnapshot,
    /FROM tp_private\.g1_vector_retrieval_sets AS retrieval[\s\S]*JOIN tp_private\.g1_vector_exclusions AS exclusion/
  );
  assert.match(
    observeSnapshot,
    /exclusion\.observed_at = retrieval\.admitted_at/
  );
  for (const binding of [
    /retrieval\.tenant_id = p_tenant_id/,
    /retrieval\.retrieval_id = p_retrieval_id/,
    /retrieval\.incident_id = p_incident_id/,
    /retrieval\.agency = p_agency/,
    /retrieval\.policy_version = p_policy_version/,
    /exclusion\.evidence_id = p_evidence_id/
  ]) {
    assert.match(observeSnapshot, binding);
  }
  assert.doesNotMatch(
    observeSnapshot,
    /g1_list_admissibility_internal_v1/
  );
});

test("DVI ranking is restricted to exact snapshot prefix columns", () => {
  const rank = definition("tp_api.g1_rank_vector_set_v1");
  assert.match(
    rank,
    /retrieval\.cleaned_at IS NULL[\s\S]*retrieval\.expires_at > transaction_timestamp\(\)/
  );
  assert.match(
    rank,
    /FROM tp_private\.g1_vector_candidates AS candidate[\s\S]*WHERE candidate\.tenant_id = p_tenant_id[\s\S]*AND candidate\.retrieval_id = p_retrieval_id[\s\S]*ORDER BY[\s\S]*candidate\.embedding <=> p_query_embedding::VECTOR\(3\),[\s\S]*candidate\.evidence_id/
  );
  assert.match(
    rank,
    /p_limit IS NULL OR p_limit < 1 OR p_limit > 100/
  );
  assert.match(rank, /p_query_embedding IS NULL/);
  assert.doesNotMatch(rank, /tp_private\.g1_evidence/);

  const cleanup = definition("tp_api.g1_delete_vector_set_v1");
  assert.match(cleanup, /DELETE FROM tp_private\.g1_vector_candidates/);
  assert.match(cleanup, /DELETE FROM tp_private\.g1_vector_exclusions/);
  assert.match(cleanup, /SET cleaned_at = COALESCE/);
  assert.doesNotMatch(
    cleanup,
    /DELETE FROM tp_private\.g1_vector_retrieval_sets/
  );
  const purge = definition("tp_api.g1_purge_expired_vector_sets_v1");
  assert.match(purge, /p_limit IS NULL OR p_limit < 1 OR p_limit > 1000/);
  assert.match(
    purge,
    /retrieval\.expires_at <= transaction_timestamp\(\)/
  );
  assert.match(purge, /LIMIT p_limit/);
  assert.match(purge, /SET cleaned_at = transaction_timestamp\(\)/);
  assert.match(purge, /DELETE FROM tp_private\.g1_vector_exclusions/);
});

test("snapshot retrieval stays private and cannot authorize by itself", () => {
  for (const object of [
    "tp_private.g1_vector_retrieval_sets",
    "tp_private.g1_vector_candidates",
    "tp_private.g1_vector_exclusions"
  ]) {
    assert.equal(security.includes(`"${object}"`), true);
  }
  assert.match(security, /ALTER TABLE \$\{object\} OWNER TO tp_owner/);
  assert.match(
    security,
    /GRANT EXECUTE ON FUNCTION[\s\S]*tp_api\.g1_prepare_vector_set_v1[\s\S]*tp_api\.g1_rank_vector_set_v1[\s\S]*tp_api\.g1_delete_vector_set_v1[\s\S]*TO tp_authorizer_role/
  );
  assert.match(
    security,
    /tp_api\.g1_purge_expired_vector_sets_v1\(UUID, INT8\)/
  );
  assert.match(
    security,
    /REVOKE EXECUTE ON FUNCTION[\s\S]*tp_api\.g1_prepare_vector_set_v1[\s\S]*tp_api\.g1_rank_vector_set_v1[\s\S]*tp_api\.g1_delete_vector_set_v1[\s\S]*FROM tp_gate2_authorizer_role/
  );
  assert.match(
    security,
    /FROM tp_api\.g1_observe_admissibility_v2\([\s\S]*IF v_admissibility <> 'admissible'/
  );
});

test("DVI selection becomes a durable source-bound authorization input", () => {
  assert.match(
    store,
    /CREATE TABLE IF NOT EXISTS tp_ledger\.g1_dvi_selection_receipts/
  );
  const commit = definition("tp_api.g1_commit_dvi_selection_v1");
  assert.match(commit, /session_user <> 'tp_authorizer_user'/);
  assert.match(
    commit,
    /retrieval\.cleaned_at IS NULL[\s\S]*retrieval\.expires_at > transaction_timestamp\(\)/
  );
  assert.doesNotMatch(commit, /p_selected_evidence_(?:id|digest)/);
  assert.match(
    commit,
    /row_number\(\) OVER \([\s\S]*candidate\.embedding <=> p_query_embedding::VECTOR\(3\),[\s\S]*candidate\.evidence_id[\s\S]*LIMIT p_limit/
  );
  assert.match(
    commit,
    /SELECT candidate\.evidence_id, candidate\.evidence_digest[\s\S]*ORDER BY[\s\S]*candidate\.embedding <=> p_query_embedding::VECTOR\(3\),[\s\S]*candidate\.evidence_id[\s\S]*LIMIT 1/
  );
  assert.match(commit, /v_query_embedding_sha256 := encode/);
  assert.match(commit, /DVI selection binding mismatch/);
  assert.match(commit, /query_embedding_sha256,[\s\S]*result_limit/);
  assert.match(commit, /INSERT INTO tp_ledger\.g1_dvi_selection_receipts/);
  assert.match(retrieval, /FROM tp_api\.g1_commit_dvi_selection_v1/);
  assert.match(retrieval, /durableSelectionCommitted: true/);
  assert.match(
    security,
    /GRANT EXECUTE ON FUNCTION[\s\S]*tp_api\.g1_commit_dvi_selection_v1[\s\S]*TO tp_authorizer_role/
  );
  assert.match(
    security,
    /REVOKE EXECUTE ON FUNCTION[\s\S]*tp_api\.g1_commit_dvi_selection_v1[\s\S]*FROM tp_gate2_authorizer_role/
  );

  const authorize = definition("tp_api.g1_authorize_dvi_proposal_v1");
  assert.match(authorize, /SECURITY DEFINER/);
  assert.match(authorize, /session_user <> 'tp_authorizer_user'/);
  assert.match(
    authorize,
    /FROM tp_ledger\.g1_dvi_selection_receipts AS selection[\s\S]*selection\.retrieval_id = p_retrieval_id/
  );
  assert.match(
    authorize,
    /selected_evidence_id IS DISTINCT FROM[\s\S]*p_requested_selected_evidence_id[\s\S]*dvi_selection_request_mismatch/
  );
  assert.ok(
    authorize.indexOf("dvi_selection_request_mismatch") <
      authorize.indexOf("INSERT INTO tp_ledger.g1_logical_authority_epochs"),
    "selection mismatch must precede every authority-state mutation"
  );
  assert.match(
    authorize,
    /FROM tp_private\.g1_list_admissibility_internal_v1\([\s\S]*v_evidence\.admissibility IS DISTINCT FROM 'admissible'/
  );
  assert.match(
    authorize,
    /tideproof\.authority\.logical-action\.v1[\s\S]*tideproof\.authority\.dvi-proposal-identity\.v1/
  );
  assert.match(
    authorize,
    /FROM tp_ledger\.g1_logical_authority_epochs AS epoch[\s\S]*FOR UPDATE/
  );
  assert.match(
    authorize,
    /logical_authority_already_spent[\s\S]*v_epoch\.current_epoch = 1[\s\S]*explicit_new_authorization_required[\s\S]*v_authorization_epoch := 1/
  );
  assert.equal(
    (authorize.match(/v_prior_spend_count > 0/g) ?? []).length,
    3,
    "every initial, raced, and new authorization path must deny prior spend"
  );
  assert.equal(
    (authorize.match(/v_existing\.expires_at <= v_database_now/g) ?? []).length,
    2,
    "both replay paths must deny expired durable history"
  );
  assert.equal(
    (store.match(/return replayDecision\(/g) ?? []).length,
    2,
    "local initial and raced replay paths must share one currentness decision"
  );
  assert.match(
    syntheticProposal,
    /acceptedOutcome && authorityCurrent === true/,
    "synthetic callers must reject every non-current authorization replay"
  );
  assert.doesNotMatch(
    authorize,
    /v_authorization_epoch := v_epoch\.current_epoch \+ 1/
  );
  assert.match(
    authorize,
    /INSERT INTO tp_ledger\.g1_dvi_proposal_receipts/
  );
  assert.match(
    security,
    /GRANT EXECUTE ON FUNCTION[\s\S]*tp_api\.g1_authorize_dvi_proposal_v1[\s\S]*TO tp_authorizer_role/
  );
  assert.match(
    security,
    /REVOKE EXECUTE ON FUNCTION[\s\S]*tp_api\.g1_authorize_dvi_proposal_v1[\s\S]*FROM tp_gate2_authorizer_role/
  );
});
