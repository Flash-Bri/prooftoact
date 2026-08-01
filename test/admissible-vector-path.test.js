import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const store = fs.readFileSync(
  path.join(root, "src/cloud/authority-store.js"),
  "utf8"
);
const security = fs.readFileSync(
  path.join(root, "src/cloud/primary-security.js"),
  "utf8"
);

function definition(name) {
  const start = security.indexOf(`CREATE OR REPLACE FUNCTION ${name}`);
  assert.notEqual(start, -1, `${name} definition missing`);
  const end = security.indexOf("  `);", start);
  assert.notEqual(end, -1, `${name} definition is unterminated`);
  return security.slice(start, end);
}

test("real admissibility produces a short-lived immutable DVI candidate set", () => {
  assert.match(
    store,
    /CREATE TABLE IF NOT EXISTS tp_private\.g1_vector_retrieval_sets/
  );
  assert.match(
    store,
    /CREATE TABLE IF NOT EXISTS tp_private\.g1_vector_candidates/
  );
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
  assert.match(prepare, /p_ttl_ms < 1000 OR p_ttl_ms > 300000/);
  assert.match(prepare, /retrieval identifier already used/);
  assert.match(prepare, /session_user <> 'tp_authorizer_user'/);
});

test("DVI ranking is restricted to exact snapshot prefix columns", () => {
  const rank = definition("tp_api.g1_rank_vector_set_v1");
  assert.match(
    rank,
    /retrieval\.cleaned_at IS NULL[\s\S]*retrieval\.expires_at > transaction_timestamp\(\)/
  );
  assert.match(
    rank,
    /FROM tp_private\.g1_vector_candidates AS candidate[\s\S]*WHERE candidate\.tenant_id = p_tenant_id[\s\S]*AND candidate\.retrieval_id = p_retrieval_id[\s\S]*ORDER BY candidate\.embedding <=> p_query_embedding::VECTOR\(3\)/
  );
  assert.match(
    rank,
    /p_limit IS NULL OR p_limit < 1 OR p_limit > 100/
  );
  assert.match(rank, /p_query_embedding IS NULL/);
  assert.doesNotMatch(rank, /tp_private\.g1_evidence/);

  const cleanup = definition("tp_api.g1_delete_vector_set_v1");
  assert.match(cleanup, /DELETE FROM tp_private\.g1_vector_candidates/);
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
});

test("snapshot retrieval stays private and cannot authorize by itself", () => {
  for (const object of [
    "tp_private.g1_vector_retrieval_sets",
    "tp_private.g1_vector_candidates"
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
