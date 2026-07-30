import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import {
  bundleDigestFor,
  normalizedRecoveryBundleFor,
  RECOVERY_QUERY_TEMPLATE,
  recoverySignaturePayloadFor,
  recoveryQueryBindingsFor,
  recoveryQueryTemplateDigest,
  renderRecoveryQuery,
  validateRecoveryRow
} from "../src/cloud/recovery-store.js";
import { createSyntheticRecoverySigner } from "../scripts/lib/synthetic-recovery-signer.js";

const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const SOURCE_CLUSTER_ID = "33333333-3333-4333-8333-333333333333";
const SUBJECT_BINDING_HASH = "b".repeat(64);
const SIGNER = createSyntheticRecoverySigner();
const UNSIGNED_BUNDLE = {
  tenantId: TENANT_ID,
  recoverySessionId: SESSION_ID,
  subjectBindingHash: SUBJECT_BINDING_HASH,
  schemaVersion: 2,
  snapshotVersion: 7,
  sourceClusterId: SOURCE_CLUSTER_ID,
  sourceCommitTs: "2026-07-29T20:00:00.000Z",
  sourceDigest: "a".repeat(64),
  policyVersion: "gate1-policy-v2",
  checkpointSummary: {
    checkpointVersion: 1,
    failedAgent: "synthetic-agent-a",
    phase: "successor-context-recovery",
    scenario: "synthetic-highwater"
  },
  evidenceSummary: {
    admittedCount: 1,
    classification: "synthetic",
    evidenceDigest: "c".repeat(64)
  },
  conflictSummary: { status: "none", unresolvedCount: 0 },
  receiptSummary: {
    durableIntentPresent: true,
    outcome: "resource_reserved",
    reason: null,
    resourceLabel: "synthetic-rescue-unit"
  },
  expiresAt: "2026-07-30T20:00:00.000Z"
};
const BUNDLE = SIGNER.sign(UNSIGNED_BUNDLE);
const NORMALIZED = normalizedRecoveryBundleFor(BUNDLE);

function rowFor(bundle = NORMALIZED) {
  return {
    tenant_id: bundle.tenantId,
    recovery_session_id: bundle.recoverySessionId,
    subject_binding_hash: bundle.subjectBindingHash,
    schema_version: String(bundle.schemaVersion),
    snapshot_version: String(bundle.snapshotVersion),
    source_cluster_id: bundle.sourceClusterId,
    source_commit_ts: bundle.sourceCommitTs,
    source_digest: bundle.sourceDigest,
    bundle_digest: bundle.bundleDigest,
    policy_version: bundle.policyVersion,
    publisher_key_id: bundle.publisherKeyId,
    publisher_version: bundle.publisherVersion,
    signature_algorithm: bundle.signatureAlgorithm,
    source_signature_base64: bundle.sourceSignatureBase64,
    signature_digest: bundle.signatureDigest,
    checkpoint_summary: bundle.checkpointSummary,
    evidence_summary: bundle.evidenceSummary,
    conflict_summary: bundle.conflictSummary,
    receipt_summary: bundle.receiptSummary,
    authority_transferred: false,
    requires_fresh_authorization: true,
    expires_at: bundle.expiresAt
  };
}

function validationBinding(overrides = {}) {
  return {
    recoverySessionId: SESSION_ID,
    tenantId: TENANT_ID,
    subjectBindingHash: SUBJECT_BINDING_HASH,
    expectedSourceClusterId: SOURCE_CLUSTER_ID,
    trustedPublisherKeys: {
      [SIGNER.publisherKeyId]: SIGNER.publicKeySpkiBase64
    },
    ...overrides
  };
}

test("recovery bundle digest binds every typed safe field", () => {
  const first = bundleDigestFor(BUNDLE);
  const reordered = bundleDigestFor({
    expiresAt: BUNDLE.expiresAt,
    receiptSummary: BUNDLE.receiptSummary,
    conflictSummary: BUNDLE.conflictSummary,
    evidenceSummary: BUNDLE.evidenceSummary,
    checkpointSummary: BUNDLE.checkpointSummary,
    signatureAlgorithm: BUNDLE.signatureAlgorithm,
    publisherVersion: BUNDLE.publisherVersion,
    publisherKeyId: BUNDLE.publisherKeyId,
    policyVersion: BUNDLE.policyVersion,
    sourceDigest: BUNDLE.sourceDigest,
    sourceCommitTs: BUNDLE.sourceCommitTs,
    sourceClusterId: BUNDLE.sourceClusterId,
    snapshotVersion: BUNDLE.snapshotVersion,
    schemaVersion: BUNDLE.schemaVersion,
    subjectBindingHash: BUNDLE.subjectBindingHash,
    recoverySessionId: BUNDLE.recoverySessionId,
    tenantId: BUNDLE.tenantId
  });
  assert.equal(first, reordered);
  assert.match(first, /^[a-f0-9]{64}$/u);
  assert.notEqual(
    bundleDigestFor({
      ...BUNDLE,
      receiptSummary: {
        ...BUNDLE.receiptSummary,
        outcome: "authorization_denied"
      }
    }),
    first
  );
});

test("recovery summaries use exact typed allowlists", () => {
  assert.throws(
    () =>
      bundleDigestFor({
        ...BUNDLE,
        checkpointSummary: {
          ...BUNDLE.checkpointSummary,
          fencingToken: "7"
        }
      }),
    /unexpected shape/
  );
  assert.throws(
    () =>
      bundleDigestFor({
        ...BUNDLE,
        receiptSummary: {
          ...BUNDLE.receiptSummary,
          resourceLabel: "x".repeat(129)
        }
      }),
    /exceeds 128 bytes/
  );
});

test("fixed recovery query binds tenant, principal, and strict UUID", () => {
  const bindings = {
    recoverySessionId: SESSION_ID,
    tenantId: TENANT_ID,
    subjectBindingHash: SUBJECT_BINDING_HASH
  };
  const query = renderRecoveryQuery(bindings);
  assert.deepEqual(recoveryQueryBindingsFor(query), bindings);
  assert.equal(query.includes("__RECOVERY_SESSION_ID__"), false);
  assert.equal(query.includes("__TENANT_ID__"), false);
  assert.equal(query.includes("__SUBJECT_BINDING_HASH__"), false);
  assert.throws(
    () =>
      renderRecoveryQuery({
        ...bindings,
        recoverySessionId: `${SESSION_ID}' OR true --`
      }),
    /must be a UUID/
  );
  assert.throws(
    () => recoveryQueryBindingsFor(`${query} SELECT 1`),
    /TEMPLATE_MISMATCH/
  );
  assert.match(recoveryQueryTemplateDigest(), /^[a-f0-9]{64}$/u);
  assert.equal(RECOVERY_QUERY_TEMPLATE.includes("LIMIT 1"), true);
});

test("recovery row validation enforces signature and context-only state", () => {
  const row = rowFor();
  const result = validateRecoveryRow(
    row,
    validationBinding(),
    new Date("2026-07-29T20:30:00.000Z")
  );
  assert.equal(result.status, "RECOVERED_CONTEXT_ONLY");
  assert.equal(result.authorityTransferred, false);
  assert.equal(result.requiresFreshAuthorization, true);

  assert.throws(
    () =>
      validateRecoveryRow(
        { ...row, authority_transferred: true },
        validationBinding(),
        new Date("2026-07-29T20:30:00.000Z")
      ),
    /RECOVERY_AUTHORITY_INVARIANT_VIOLATION/
  );
  assert.throws(
    () =>
      validateRecoveryRow(
        { ...row, source_signature_base64: Buffer.alloc(72).toString("base64") },
        validationBinding(),
        new Date("2026-07-29T20:30:00.000Z")
      ),
    /SIGNATURE/
  );
  assert.throws(
    () =>
      validateRecoveryRow(
        row,
        validationBinding({
          subjectBindingHash: "d".repeat(64)
        }),
        new Date("2026-07-29T20:30:00.000Z")
      ),
    /RECOVERY_SUBJECT_BINDING_MISMATCH/
  );
});

test("recovery freshness rejects future, stale, and expired bundles", () => {
  const row = rowFor();
  assert.throws(
    () =>
      validateRecoveryRow(
        row,
        validationBinding(),
        new Date("2026-07-29T18:00:00.000Z")
      ),
    /RECOVERY_SOURCE_TIMESTAMP_IN_FUTURE/
  );
  assert.throws(
    () =>
      validateRecoveryRow(
        row,
        validationBinding(),
        new Date("2026-07-29T21:00:00.001Z")
      ),
    /RECOVERY_SOURCE_TOO_OLD/
  );
  assert.throws(
    () =>
      validateRecoveryRow(
        row,
        validationBinding(),
        new Date("2026-07-30T20:00:00.000Z")
      ),
    /RECOVERY_SOURCE_TOO_OLD|RECOVERY_BUNDLE_EXPIRED/
  );
});

test("recovery publisher labels cannot disguise a non-P-256 key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "secp384r1"
  });
  const unsigned = {
    ...UNSIGNED_BUNDLE,
    publisherKeyId: "synthetic-p384-disguised-as-p256",
    publisherVersion: BUNDLE.publisherVersion,
    signatureAlgorithm: BUNDLE.signatureAlgorithm
  };
  const sourceSignatureBase64 = sign(
    "sha256",
    Buffer.from(recoverySignaturePayloadFor(unsigned), "utf8"),
    privateKey
  ).toString("base64");
  const disguised = normalizedRecoveryBundleFor({
    ...unsigned,
    sourceSignatureBase64
  });

  assert.throws(
    () =>
      validateRecoveryRow(
        rowFor(disguised),
        validationBinding({
          trustedPublisherKeys: {
            [disguised.publisherKeyId]: publicKey
              .export({ type: "spki", format: "der" })
              .toString("base64")
          }
        }),
        new Date("2026-07-29T20:30:00.000Z")
      ),
    /RECOVERY_PUBLISHER_KEY_INVALID/
  );
});
