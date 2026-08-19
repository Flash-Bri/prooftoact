import assert from "node:assert/strict";
import test from "node:test";

import {
  JUDGE_PROOF_DATABASE,
  JUDGE_PROOF_PINNED_BINDING,
  JUDGE_PROOF_QUERY_TEMPLATE,
  judgeProofQueryBindingsFor,
  renderJudgeProofQuery,
  sanitizeJudgeProofMcpResult
} from "../src/cloud/judge-proof-query.js";

export function liveJudgeRow(overrides = {}) {
  return {
    tenant_id: JUDGE_PROOF_PINNED_BINDING.tenantId,
    recovery_session_id: JUDGE_PROOF_PINNED_BINDING.recoverySessionId,
    subject_binding_hash: JUDGE_PROOF_PINNED_BINDING.subjectBindingHash,
    schema_version: 2,
    snapshot_version: 1,
    source_cluster_id: JUDGE_PROOF_PINNED_BINDING.expectedSourceClusterId,
    source_commit_ts: "2026-08-19T13:37:22.051Z",
    source_digest: JUDGE_PROOF_PINNED_BINDING.sourceDigest,
    bundle_digest: JUDGE_PROOF_PINNED_BINDING.bundleDigest,
    policy_version: JUDGE_PROOF_PINNED_BINDING.policyVersion,
    publisher_key_id: JUDGE_PROOF_PINNED_BINDING.publisherKeyId,
    publisher_version: "tideproof-recovery-publisher-v2",
    signature_algorithm: "ecdsa-p256-sha256",
    source_signature_base64:
      "MEYCIQCn1J7aiBese+PJlQ8lS6LPjIrih8+E8MtU7yG8xFVEhAIhAI0y6TURX4eL0IfILvrPIvyFMi/X/Fs1iUGXVGBz0Jil",
    signature_digest: JUDGE_PROOF_PINNED_BINDING.signatureDigest,
    checkpoint_summary: {
      checkpointVersion: 1,
      failedAgent: "none-transport-proof",
      phase: "successor-context-recovery",
      scenario: "synthetic-highwater"
    },
    evidence_summary: {
      admittedCount: 0,
      classification: "synthetic",
      evidenceDigest:
        "a14760f48776a90aaa3cf8acb6e368d74887a03def13fd87e2cef6fa130b6e7f"
    },
    conflict_summary: { status: "none", unresolvedCount: 0 },
    receipt_summary: {
      durableIntentPresent: false,
      outcome: "authorization_denied",
      reason: "transport-proof-only",
      resourceLabel: "public-judge-live-read"
    },
    authority_transferred: false,
    requires_fresh_authorization: true,
    expires_at: "2026-08-20T12:37:22.051Z",
    ...overrides
  };
}

function result(rows, extra = {}) {
  return {
    content: [{ type: "text", text: JSON.stringify({ rows }) }],
    ...extra
  };
}

test("judge proof query is one no-argument exact recovery-view read", () => {
  const query = renderJudgeProofQuery();
  assert.equal(renderJudgeProofQuery.length, 0);
  assert.equal(JUDGE_PROOF_DATABASE, "tideproof_recovery");
  assert.equal(query.includes("mcp_public.recovery_bundle_v2"), true);
  assert.equal(query.includes(JUDGE_PROOF_PINNED_BINDING.bundleDigest), true);
  assert.equal(query.endsWith("LIMIT 2"), true);
  assert.equal(query.includes("statement_timestamp"), false);
  assert.equal(query.includes(";"), false);
  assert.deepEqual(judgeProofQueryBindingsFor(query), {
    bundleDigest: JUDGE_PROOF_PINNED_BINDING.bundleDigest,
    recoverySessionId: JUDGE_PROOF_PINNED_BINDING.recoverySessionId,
    sourceDigest: JUDGE_PROOF_PINNED_BINDING.sourceDigest,
    subjectBindingHash: JUDGE_PROOF_PINNED_BINDING.subjectBindingHash,
    tenantId: JUDGE_PROOF_PINNED_BINDING.tenantId
  });
  assert.equal(
    JUDGE_PROOF_QUERY_TEMPLATE.includes("__JUDGE_BUNDLE_DIGEST__"),
    true
  );
});

test("judge proof query rejects any text substitution", () => {
  const query = renderJudgeProofQuery();
  for (const changed of [
    query.replace("LIMIT 2", "LIMIT 200"),
    `${query}\nUNION SELECT 1`,
    query.replace("mcp_public", "mcp_private"),
    query.replace(JUDGE_PROOF_PINNED_BINDING.bundleDigest, "f".repeat(64))
  ]) {
    assert.throws(
      () => judgeProofQueryBindingsFor(changed),
      /JUDGE_PROOF_QUERY_REJECTED/u
    );
  }
});

test("judge proof sanitizer verifies the real pinned P-256 row", () => {
  const proof = sanitizeJudgeProofMcpResult(result([liveJudgeRow()]));
  assert.deepEqual(Object.keys(proof), [
    "schemaVersion",
    "receiptBoundary",
    "bundleDigest",
    "signatureDigest",
    "publisherKeySha256",
    "sourceClusterIdSha256",
    "sourceCommitTs",
    "sourceDigest",
    "expiresAt",
    "authorityTransferred",
    "requiresFreshAuthorization",
    "receiptReason",
    "bindingSha256"
  ]);
  assert.equal(
    proof.receiptBoundary,
    "HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY"
  );
  assert.equal(proof.bundleDigest, JUDGE_PROOF_PINNED_BINDING.bundleDigest);
  assert.equal(proof.authorityTransferred, false);
  assert.equal(proof.requiresFreshAuthorization, true);
  assert.equal(proof.receiptReason, "transport-proof-only");
  assert.equal(Object.isFrozen(proof), true);
});

test("judge proof sanitizer rejects ambiguity, drift, and signature tampering", () => {
  for (const candidate of [
    result([]),
    result([liveJudgeRow(), liveJudgeRow()]),
    result([liveJudgeRow({ source_digest: "b".repeat(64) })]),
    result([liveJudgeRow({ source_signature_base64: "QQ==" })]),
    result([liveJudgeRow({ receipt_summary: {
      ...liveJudgeRow().receipt_summary,
      reason: "authority-granted"
    } })]),
    result([liveJudgeRow({ unexpected: true })]),
    result([liveJudgeRow()], { isError: true }),
    { content: [{ type: "text", text: '{"rows":[],"rows":[]}' }] }
  ]) {
    assert.throws(
      () => sanitizeJudgeProofMcpResult(candidate),
      /JUDGE_PROOF_(?:MCP_RESULT|ROW)_REJECTED/u
    );
  }
});
