import { createHash, createPublicKey } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";
import { verifyRecoveryBundleSourceSignature } from
  "./recovery-bundle-signature.js";
import { parseStrictJson } from "./strict-json.js";

export const JUDGE_PROOF_DATABASE = "tideproof_recovery";
export const JUDGE_PROOF_RESPONSE_LIMIT_BYTES = 32 * 1024;
export const JUDGE_PROOF_STATUS = "LIVE_MANAGED_MCP_READ";
export const JUDGE_PROOF_RECEIPT_REASON = "transport-proof-only";

export const JUDGE_PROOF_PINNED_BINDING = Object.freeze({
  bundleDigest:
    "78ad7269424e13785711b5106083a2aac9fbf9f77996f70db4b9e13df869d991",
  expectedSourceClusterId: "24f93c44-fa61-467c-bd3f-a1153618c309",
  policyVersion: "prooftoact-judge-transport-proof-v1",
  publisherKeyId: "judge-transport-7f0146710b93767a9b1a",
  publisherPublicKeySha256:
    "7f0146710b93767a9b1ad87b5d6572164f0897b8d8bcf3f714fc0da4c3325f7c",
  publisherPublicKeySpkiBase64:
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEidQL1nIuux3hs102fvj758EGTNzaa3ArjQAjL+qkNCVLzz3JKxUFLEuYV5U5tJVzV5FjEjgir2T3zfVagvZR1g==",
  recoverySessionId: "1d1a2906-4cc5-401b-b5a7-e680a11d30a1",
  signatureDigest:
    "86315d12c864c4184176bb1d8a0ce071c80e7e14cdccc021f56d4b39eb178947",
  sourceDigest:
    "b4d2d6352ca2e780f6d9861ba22af4932cd5f6495deca052fea8913d97f96a3d",
  subjectBindingHash:
    "946167aa41f069f094a63de23c7bcd6f8290fe144731e050e0f9af49401fb6f0",
  tenantId: "235e791f-5cd4-4313-9591-76c0c34e54d8"
});

const SESSION_TOKEN = "__JUDGE_RECOVERY_SESSION_ID__";
const TENANT_TOKEN = "__JUDGE_TENANT_ID__";
const SUBJECT_TOKEN = "__JUDGE_SUBJECT_BINDING_SHA256__";
const SOURCE_TOKEN = "__JUDGE_SOURCE_DIGEST__";
const BUNDLE_TOKEN = "__JUDGE_BUNDLE_DIGEST__";
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const ROW_KEYS = Object.freeze([
  "authority_transferred",
  "bundle_digest",
  "checkpoint_summary",
  "conflict_summary",
  "evidence_summary",
  "expires_at",
  "policy_version",
  "publisher_key_id",
  "publisher_version",
  "receipt_summary",
  "recovery_session_id",
  "requires_fresh_authorization",
  "schema_version",
  "signature_algorithm",
  "signature_digest",
  "snapshot_version",
  "source_cluster_id",
  "source_commit_ts",
  "source_digest",
  "source_signature_base64",
  "subject_binding_hash",
  "tenant_id"
]);

export const JUDGE_PROOF_QUERY_TEMPLATE = `SELECT
  tenant_id,
  recovery_session_id,
  subject_binding_hash,
  schema_version,
  snapshot_version,
  source_cluster_id,
  source_commit_ts,
  source_digest,
  bundle_digest,
  policy_version,
  publisher_key_id,
  publisher_version,
  signature_algorithm,
  source_signature_base64,
  signature_digest,
  checkpoint_summary,
  evidence_summary,
  conflict_summary,
  receipt_summary,
  authority_transferred,
  requires_fresh_authorization,
  expires_at
FROM mcp_public.recovery_bundle_v2
WHERE recovery_session_id = '${SESSION_TOKEN}'::UUID
  AND tenant_id = '${TENANT_TOKEN}'::UUID
  AND subject_binding_hash = '${SUBJECT_TOKEN}'
  AND source_digest = '${SOURCE_TOKEN}'
  AND bundle_digest = '${BUNDLE_TOKEN}'
LIMIT 2`;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactKeys(value, expected) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validatePinnedBinding() {
  const value = JUDGE_PROOF_PINNED_BINDING;
  const bytes = Buffer.from(value.publisherPublicKeySpkiBase64, "base64");
  let key;
  try {
    key = createPublicKey({ key: bytes, format: "der", type: "spki" });
  } catch (cause) {
    reject("JUDGE_PROOF_PINNED_BINDING_REJECTED", cause);
  }
  if (
    !UUID.test(value.tenantId) ||
    !UUID.test(value.recoverySessionId) ||
    !UUID.test(value.expectedSourceClusterId) ||
    ![
      value.bundleDigest,
      value.publisherPublicKeySha256,
      value.signatureDigest,
      value.sourceDigest,
      value.subjectBindingHash
    ].every((entry) => HEX_64.test(entry)) ||
    bytes.toString("base64") !== value.publisherPublicKeySpkiBase64 ||
    sha256(bytes) !== value.publisherPublicKeySha256 ||
    key.asymmetricKeyType !== "ec" ||
    !["prime256v1", "P-256"].includes(key.asymmetricKeyDetails?.namedCurve) ||
    !key.export({ format: "der", type: "spki" }).equals(bytes)
  ) {
    reject("JUDGE_PROOF_PINNED_BINDING_REJECTED");
  }
  return value;
}

export function judgeProofQueryTemplateSha256() {
  return sha256(JUDGE_PROOF_QUERY_TEMPLATE);
}

export function renderJudgeProofQuery() {
  const value = validatePinnedBinding();
  return JUDGE_PROOF_QUERY_TEMPLATE
    .replace(SESSION_TOKEN, value.recoverySessionId)
    .replace(TENANT_TOKEN, value.tenantId)
    .replace(SUBJECT_TOKEN, value.subjectBindingHash)
    .replace(SOURCE_TOKEN, value.sourceDigest)
    .replace(BUNDLE_TOKEN, value.bundleDigest);
}

export function judgeProofQueryBindingsFor(query) {
  const code = "JUDGE_PROOF_QUERY_REJECTED";
  if (query !== renderJudgeProofQuery()) reject(code);
  const value = validatePinnedBinding();
  return Object.freeze({
    bundleDigest: value.bundleDigest,
    recoverySessionId: value.recoverySessionId,
    sourceDigest: value.sourceDigest,
    subjectBindingHash: value.subjectBindingHash,
    tenantId: value.tenantId
  });
}

function rowAsSignedBundle(row) {
  return {
    tenantId: row.tenant_id,
    recoverySessionId: row.recovery_session_id,
    subjectBindingHash: row.subject_binding_hash,
    schemaVersion: Number(row.schema_version),
    snapshotVersion: Number(row.snapshot_version),
    sourceClusterId: row.source_cluster_id,
    sourceCommitTs: row.source_commit_ts,
    sourceDigest: row.source_digest,
    bundleDigest: row.bundle_digest,
    policyVersion: row.policy_version,
    publisherKeyId: row.publisher_key_id,
    publisherVersion: row.publisher_version,
    signatureAlgorithm: row.signature_algorithm,
    sourceSignatureBase64: row.source_signature_base64,
    signatureDigest: row.signature_digest,
    checkpointSummary: row.checkpoint_summary,
    evidenceSummary: row.evidence_summary,
    conflictSummary: row.conflict_summary,
    receiptSummary: row.receipt_summary,
    authorityTransferred: row.authority_transferred,
    requiresFreshAuthorization: row.requires_fresh_authorization,
    expiresAt: row.expires_at
  };
}

function sanitizeJudgeProofRow(row) {
  const code = "JUDGE_PROOF_ROW_REJECTED";
  const expected = validatePinnedBinding();
  if (!exactKeys(row, ROW_KEYS)) reject(code);
  let bundle;
  try {
    bundle = verifyRecoveryBundleSourceSignature(rowAsSignedBundle(row), {
      [expected.publisherKeyId]: expected.publisherPublicKeySpkiBase64
    });
  } catch (cause) {
    reject(code, cause);
  }
  if (
    bundle.tenantId !== expected.tenantId ||
    bundle.recoverySessionId !== expected.recoverySessionId ||
    bundle.subjectBindingHash !== expected.subjectBindingHash ||
    bundle.sourceDigest !== expected.sourceDigest ||
    bundle.sourceClusterId !== expected.expectedSourceClusterId ||
    bundle.bundleDigest !== expected.bundleDigest ||
    bundle.signatureDigest !== expected.signatureDigest ||
    bundle.publisherKeyId !== expected.publisherKeyId ||
    bundle.policyVersion !== expected.policyVersion ||
    bundle.receiptSummary.reason !== JUDGE_PROOF_RECEIPT_REASON ||
    bundle.authorityTransferred !== false ||
    bundle.requiresFreshAuthorization !== true
  ) {
    reject(code);
  }
  return Object.freeze({
    schemaVersion: 1,
    receiptBoundary: "HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY",
    bundleDigest: bundle.bundleDigest,
    signatureDigest: bundle.signatureDigest,
    publisherKeySha256: expected.publisherPublicKeySha256,
    sourceClusterIdSha256: sha256(bundle.sourceClusterId),
    sourceCommitTs: bundle.sourceCommitTs,
    sourceDigest: bundle.sourceDigest,
    expiresAt: bundle.expiresAt,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    receiptReason: JUDGE_PROOF_RECEIPT_REASON,
    bindingSha256: sha256(canonicalJson({
      recoverySessionId: expected.recoverySessionId,
      subjectBindingHash: expected.subjectBindingHash,
      tenantId: expected.tenantId
    }))
  });
}

export function sanitizeJudgeProofMcpResult(result) {
  const code = "JUDGE_PROOF_MCP_RESULT_REJECTED";
  const resultKeys = result && typeof result === "object"
    ? Object.keys(result)
    : [];
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result) ||
    !resultKeys.every((key) => ["content", "isError"].includes(key)) ||
    !resultKeys.includes("content") ||
    result.isError === true ||
    (Object.hasOwn(result, "isError") && result.isError !== false) ||
    !Array.isArray(result.content) ||
    result.content.length !== 1 ||
    !exactKeys(result.content[0], ["text", "type"]) ||
    result.content[0].type !== "text" ||
    typeof result.content[0].text !== "string" ||
    Buffer.byteLength(result.content[0].text, "utf8") >
      JUDGE_PROOF_RESPONSE_LIMIT_BYTES
  ) {
    reject(code);
  }
  let parsed;
  try {
    parsed = parseStrictJson(result.content[0].text, {
      duplicateCode: code,
      invalidCode: code
    });
  } catch (cause) {
    reject(code, cause);
  }
  if (
    !exactKeys(parsed, ["rows"]) ||
    !Array.isArray(parsed.rows) ||
    parsed.rows.length !== 1
  ) {
    reject(code);
  }
  return sanitizeJudgeProofRow(parsed.rows[0]);
}

export function judgeProofResultSha256(value) {
  return sha256(canonicalJson(value));
}

export const __test = Object.freeze({
  exactKeys,
  rowAsSignedBundle,
  sanitizeJudgeProofRow,
  validatePinnedBinding
});
