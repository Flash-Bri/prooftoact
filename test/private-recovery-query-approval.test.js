import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  generatePrivateRecoveryQueryApproval,
  __test as approvalInternals
} from "../scripts/generate-private-recovery-query-approval.js";
import { checkPrivateRecoveryQueryWindow } from
  "../scripts/check-private-recovery-query-window.js";
import {
  validatePrivateRecoveryQueryApproval,
  validatePrivateRecoveryQueryProviderBinding,
  __test as queryInternals
} from "../src/cloud/private-recovery-query.js";

const NOW = new Date("2026-08-19T02:05:00.000Z");

function fixture() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const sourceCommit = "a".repeat(40);
  const treeDigest = "b".repeat(40);
  const mappingBody = {
    schemaVersion: "prooftoact.primary-provider-sql-mapping.v1",
    status: "PROVIDER_READBACK_BOUND",
    cloud: "COCKROACHDB_CLOUD_ON_AWS",
    providerClusterId: "59294a51-f2d3-4275-b893-7ddb530829c7",
    sqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b",
    host: "prooftoact-fresh-primary.cockroachlabs.cloud",
    cockroachVersion: "CockroachDB CCL v26.2.5",
    clusterInventorySha256: "1".repeat(64),
    manualClusterReceiptSha256: null,
    sourceCommit,
    treeDigest,
    sourceBindingSha256: "2".repeat(64),
    observedAt: "2026-08-19T01:58:00.000Z"
  };
  const primaryClusterMapping = {
    ...mappingBody,
    receiptSha256: queryInternals.lineDigest(mappingBody)
  };
  const providerBody = {
    schemaVersion: "prooftoact.private-recovery-query-binding.v1",
    status: "SANITIZED_PROVIDER_BOUND",
    billingAuthorizationSha256: "3".repeat(64),
    expectedBundleDigest: "4".repeat(64),
    expectedSourceClusterId: mappingBody.providerClusterId,
    expectedSourceSqlClusterId: mappingBody.sqlClusterId,
    expiresAt: "2026-08-19T02:29:00.000Z",
    operationId: "55555555-5555-4555-8555-555555555555",
    primaryClusterMapping,
    primaryClusterMappingReceiptSha256: primaryClusterMapping.receiptSha256,
    publisherKeyId: "fresh-primary-recovery-key-v1",
    publisherPublicKeySpkiBase64: publicKey.export({
      format: "der",
      type: "spki"
    }).toString("base64"),
    recoveryClusterId: "66666666-6666-4666-8666-666666666666",
    recoverySessionId: "77777777-7777-4777-8777-777777777777",
    sourceCommit,
    sourceCommitTs: "2026-08-19T02:00:00.000Z",
    sourceDigest: "8".repeat(64),
    subjectBindingHash: "9".repeat(64),
    tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    treeDigest
  };
  const providerBinding = {
    ...providerBody,
    bindingSha256: queryInternals.lineDigest(providerBody)
  };
  const secretBody = {
    schemaVersion:
      "prooftoact.private-recovery-query-mcp-secret-binding.v1",
    status: "IMMUTABLE_AWSCURRENT_READBACK_BOUND",
    credentialSharingBoundary:
      "SAME_READ_ONLY_MANAGED_MCP_PROVIDER_KEY_TWO_ISOLATED_AWS_SECRETS",
    mcpSecretArnSha256: "b".repeat(64),
    mcpSecretValueSha256: "c".repeat(64),
    mcpSecretVersionIdSha256: "d".repeat(64),
    observedAt: "2026-08-19T02:04:00.000Z",
    operatorAuthorizationSha256: "1".repeat(64),
    sealApprovalSha256: "2".repeat(64),
    sourceCommit,
    sourceSecretArnSha256: "e".repeat(64),
    sourceSecretValueSha256: "f".repeat(64),
    sourceSecretVersionIdSha256: "0".repeat(64),
    treeDigest
  };
  const mcpSecretBinding = {
    ...secretBody,
    bindingSha256: approvalInternals.lineDigest(secretBody)
  };
  return { mcpSecretBinding, providerBinding };
}

test("generator copies the exact fresh provider binding with no overrides", () => {
  const value = fixture();
  const first = generatePrivateRecoveryQueryApproval({
    ...value,
    approvedAt: NOW.toISOString(),
    now: NOW
  });
  const second = generatePrivateRecoveryQueryApproval({
    ...value,
    approvedAt: NOW.toISOString(),
    now: NOW
  });
  assert.deepEqual(second, first);
  assert.equal(first.approval.providerBindingSha256,
    value.providerBinding.bindingSha256);
  assert.equal(first.approval.expectedSourceCommitTs,
    value.providerBinding.sourceCommitTs);
  assert.equal(first.approval.expiresAt, value.providerBinding.expiresAt);
  assert.equal(first.approval.mcpSecretValueSha256,
    value.mcpSecretBinding.mcpSecretValueSha256);
  assert.equal(first.receipt.providerBindingSha256,
    value.providerBinding.bindingSha256);
  validatePrivateRecoveryQueryProviderBinding(value.providerBinding, NOW);
  validatePrivateRecoveryQueryApproval(first.approval, NOW);
});

test("generator rejects provider self-hash and source timestamp substitution", () => {
  const value = fixture();
  assert.throws(() => generatePrivateRecoveryQueryApproval({
    ...value,
    approvedAt: NOW.toISOString(),
    now: NOW,
    providerBinding: {
      ...value.providerBinding,
      sourceCommitTs: "2026-08-19T01:59:59.000Z"
    }
  }), /PRIVATE_RECOVERY_QUERY_PROVIDER_BINDING_REJECTED/u);
});

test("generator rejects stale binding and secret readback source drift", () => {
  const value = fixture();
  assert.throws(() => generatePrivateRecoveryQueryApproval({
    ...value,
    approvedAt: "2026-08-19T02:29:00.000Z",
    now: new Date("2026-08-19T02:29:00.000Z")
  }), /PRIVATE_RECOVERY_QUERY_PROVIDER_BINDING_REJECTED|PRIVATE_RECOVERY_QUERY_APPROVAL_GENERATION_REJECTED/u);
  const secretBody = {
    ...value.mcpSecretBinding,
    sourceCommit: "e".repeat(40)
  };
  delete secretBody.bindingSha256;
  assert.throws(() => generatePrivateRecoveryQueryApproval({
    approvedAt: NOW.toISOString(),
    mcpSecretBinding: {
      ...secretBody,
      bindingSha256: approvalInternals.lineDigest(secretBody)
    },
    now: NOW,
    providerBinding: value.providerBinding
  }), /PRIVATE_RECOVERY_QUERY_APPROVAL_GENERATION_REJECTED/u);
});

test("deployment window check fails closed before the remaining margin", () => {
  const value = fixture();
  const { approval } = generatePrivateRecoveryQueryApproval({
    ...value,
    approvedAt: NOW.toISOString(),
    now: NOW
  });
  const accepted = checkPrivateRecoveryQueryWindow({
    approval,
    minimumRemainingSeconds: 24 * 60,
    now: NOW
  });
  assert.equal(accepted.status, "PASS");
  assert.equal(accepted.remainingSeconds, 24 * 60);
  assert.throws(() => checkPrivateRecoveryQueryWindow({
    approval,
    minimumRemainingSeconds: 25 * 60,
    now: NOW
  }), /PRIVATE_RECOVERY_QUERY_WINDOW_REJECTED/u);
});
