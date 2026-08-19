import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { FRESH_PRIMARY_RUNTIME_USERS } from
  "../scripts/bootstrap-fresh-primary.js";
import { __test } from "../scripts/run-fresh-cluster-provider.js";
import { buildSyntheticProofToActHumanAuthorization } from
  "./helpers/prooftoact-human-authorization-fixture.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const ACCOUNT = "111111111111";
const TABLE_ARN = `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
  "prooftoact-release-controller";
const CALLER_WORKFLOW_REF =
  "Flash-Bri/prooftoact/.github/workflows/" +
  "prooftoact-fresh-primary.yml@refs/heads/main";
const CALLER_WORKFLOW_SHA = "d".repeat(40);
const CONTROLLER_IMPORT_GRAPH_SHA256 = "e".repeat(64);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sharedHumanBinding(approval) {
  return buildSyntheticProofToActHumanAuthorization({
    dynamicInput: {
    a1ApprovalId: approval.approvalId,
    a1CallerWorkflowRef: approval.callerWorkflowRef,
    a1CallerWorkflowSha: approval.callerWorkflowSha,
    a1ControllerImportGraphSha256: approval.controllerImportGraphSha256,
    a1CredentialSha256: {
      adoptedAdminPassword: approval.adoptedAdminPasswordSha256,
      auditorTokenValue: approval.auditorTokenValueSha256,
      creatorTokenValue: approval.creatorTokenValueSha256
    },
    a1ProviderClusterId: approval.providerClusterId,
    a1ProviderReceiptSha256: {
      auditorAuthority: approval.auditorAuthorityReceiptSha256,
      creatorAuthority: approval.creatorAuthorityReceiptSha256,
      creatorProviderReadback:
        approval.creatorProviderReadbackReceiptSha256,
      manualCluster: approval.manualClusterReceiptSha256,
      pricingSource: "1".repeat(64)
    },
    a1ReservationDeadline: "2026-08-19T09:00:00.000Z",
    a1SqlClusterId: approval.sqlClusterId,
    accountId: approval.accountId,
    authorizationNotBefore: "2026-08-19T08:00:00.000Z",
    b0DispatchDeadline: "2026-08-19T09:00:00.000Z",
    b0PrivateRecoveryWorkflowCommits: {
      deployment: "2".repeat(40),
      secretSeal: "3".repeat(40)
    },
    b0RuntimeExecutionBindingSha256: "4".repeat(64),
    b0TargetTemplateSha256: {
      freshPrimaryBootstrapRole: "5".repeat(64),
      freshPrimaryCredentialCustody: "6".repeat(64),
      privateRecoveryQueryBootstrap: "7".repeat(64)
    },
    b0WriterValueSha256: {
      auditor: approval.auditorTokenValueSha256,
      cloudApi: approval.creatorTokenValueSha256,
      credential: "8".repeat(64),
      mcp: "9".repeat(64),
      publisher: "a".repeat(64)
    },
    cleanupRetentionDeadline: "2026-08-20T09:00:00.000Z",
    costAuthorization: {
      awsMonthlyResidualCeilingUsdCents: 350,
      cockroachMonthlySubCeilingUsdCents: 200,
      cockroachPaidWorstCaseMonthlyUsdCents: 150,
      combinedMonthlyCeilingUsdCents: 500,
      currency: "USD",
      freeBenefitsAssumed: false,
      maximumOneTimeUsdCents: 500,
      noAdditiveMonthlyCeilings: true,
      reconciliationReceiptSha256: "b".repeat(64)
    },
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
    },
    inboundAt: "2026-08-19T08:00:00.000Z",
    outboundAt: "2026-08-19T08:00:00.000Z"
  }).humanAuthorizationBinding;
}

function args() {
  return [
    "--admin-password-file", "/private/admin-password.txt",
    "--admin-secret-arn", "admin-arn",
    "--admin-secret-version-id", "1".repeat(32),
    "--approval-file", "/private/approval.json",
    "--approval-sha256", "f".repeat(64),
    "--auditor-secret-arn", "auditor-arn",
    "--auditor-secret-version-id", "2".repeat(32),
    "--build-receipt", "/private/build.json",
    "--cloud-api-secret-arn", "cloud-arn",
    "--cloud-api-secret-version-id", "3".repeat(32),
    "--caller-workflow-ref", CALLER_WORKFLOW_REF,
    "--caller-workflow-sha", CALLER_WORKFLOW_SHA,
    "--controller-table-arn", TABLE_ARN,
    "--credential-secret-arn", "credential-arn",
    "--credential-secret-version-id", "4".repeat(32),
    "--expected-commit", SOURCE_COMMIT,
    "--expected-tree", TREE_DIGEST,
    "--human-authorization-signer-sha256", "f".repeat(64),
    "--mcp-secret-arn", "mcp-arn",
    "--mcp-secret-version-id", "6".repeat(32),
    "--mode", "execute",
    "--operation-id", OPERATION_ID,
    "--publisher-secret-arn", "publisher-arn",
    "--publisher-secret-version-id", "7".repeat(32),
    "--receipt-output", "/private/receipt.json",
    "--release-control-runtime-receipt", "/private/release-control.json",
    "--recovery-security-receipt-sha256", "c".repeat(64),
    "--signer-secret-arn", "signer-arn",
    "--signer-secret-version-id", "5".repeat(32)
  ];
}

test("combined runner accepts one exact argument set and no duplicates", () => {
  const parsed = __test.parseArguments(args());
  assert.equal(parsed["--operation-id"], OPERATION_ID);
  assert.equal(parsed["--controller-table-arn"], TABLE_ARN);
  assert.equal(parsed["--mode"], "execute");
  const duplicate = args();
  duplicate[2] = "--admin-password-file";
  assert.throws(() => __test.parseArguments(duplicate),
    /FRESH_CLUSTER_RUNNER_ARGUMENTS_REJECTED/u);
});

test("combined runner accepts only execute or cleanup-only recovery mode", () => {
  const reconcile = args();
  reconcile[reconcile.indexOf("--mode") + 1] = "reconcile-only";
  assert.equal(__test.parseArguments(reconcile)["--mode"], "reconcile-only");
  const rejected = args();
  rejected[rejected.indexOf("--mode") + 1] = "resume";
  assert.throws(() => __test.parseArguments(rejected),
    /FRESH_CLUSTER_RUNNER_ARGUMENTS_REJECTED/u);
});

test("derived approval seal recomputes exact immutable credential bundle", () => {
  const credential = JSON.stringify({
    schemaVersion: "prooftoact.fresh-primary-credentials.v2",
    passwords: Object.fromEntries(FRESH_PRIMARY_RUNTIME_USERS.map(
      (name, index) => [name, `${String(index).padStart(2, "0")}-${"x".repeat(32)}`]
    ))
  });
  const result = __test.credentialSealForDerivedApproval({
    material: { credential: {
      createdAt: "2026-08-19T08:00:00.000Z",
      secretArnSha256: "d".repeat(64),
      secretValue: credential,
      secretVersionIdSha256: "e".repeat(64)
    } },
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
  assert.equal(result.credentialBundleRawSha256, sha256(credential));
  assert.match(result.credentialBundleSha256, /^[0-9a-f]{64}$/u);
  assert.match(result.credentialSealReceiptSha256, /^[0-9a-f]{64}$/u);
});

test("combined runner never accepts ambient long-lived AWS keys", () => {
  const accepted = __test.explicitAwsCredentials({
    AWS_ACCESS_KEY_ID: `ASIA${"A".repeat(16)}`,
    AWS_SECRET_ACCESS_KEY: "b".repeat(40),
    AWS_SESSION_TOKEN: "c".repeat(64)
  });
  assert.match(accepted.accessKeyId, /^ASIA/u);
  assert.throws(() => __test.explicitAwsCredentials({
    AWS_ACCESS_KEY_ID: `AKIA${"A".repeat(16)}`,
    AWS_SECRET_ACCESS_KEY: "b".repeat(40),
    AWS_SESSION_TOKEN: "c".repeat(64)
  }), /FRESH_CLUSTER_RUNNER_AWS_CREDENTIALS_REJECTED/u);
});

test("admin password custody unlinks the exact private inode and clears bytes", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pta-admin-"));
  fs.chmodSync(directory, 0o700);
  try {
    const filePath = path.join(directory, "admin-password.txt");
    fs.writeFileSync(filePath, "Z".repeat(32), { mode: 0o600 });
    const record = __test.readPrivateFileRecord(
      filePath,
      1024,
      "FRESH_CLUSTER_RUNNER_ADMIN_PASSWORD_REJECTED"
    );
    assert.equal(record.bytes.toString("utf8"), "Z".repeat(32));
    assert.equal(__test.discardPrivateFile(
      record,
      "FRESH_CLUSTER_RUNNER_ADMIN_PASSWORD_DISCARD_REJECTED"
    ), true);
    assert.equal(fs.existsSync(filePath), false);
    assert.equal(record.bytes.every((value) => value === 0), true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("executable adoption path is pinned to the reviewed manual receipt", () => {
  const baseApproval = {
    accountId: ACCOUNT,
    adoptedAdminPasswordSha256:
      __test.APPROVED_ADOPTION.adoptedAdminPasswordSha256,
    approvalId: "223e4567-e89b-42d3-a456-426614174001",
    billingAuthorization: {
      authorizationReceiptSha256: "8".repeat(64),
      authorizedMonthlyCeilingUsd: "2.00"
    },
    callerWorkflowRef: CALLER_WORKFLOW_REF,
    callerWorkflowSha: CALLER_WORKFLOW_SHA,
    auditorAuthorityReceiptSha256:
      __test.APPROVED_ADOPTION.auditorAuthorityReceiptSha256,
    auditorServiceAccountId:
      __test.APPROVED_ADOPTION.auditorServiceAccountId,
    auditorTokenValueSha256:
      __test.APPROVED_ADOPTION.auditorTokenValueSha256,
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    controllerImportGraphSha256: CONTROLLER_IMPORT_GRAPH_SHA256,
    creatorAuthorityReceiptSha256:
      __test.APPROVED_ADOPTION.creatorAuthorityReceiptSha256,
    creatorProviderReadbackReceiptSha256:
      __test.APPROVED_ADOPTION.creatorProviderReadbackReceiptSha256,
    creatorServiceAccountId:
      __test.APPROVED_ADOPTION.creatorServiceAccountId,
    creatorTokenValueSha256:
      __test.APPROVED_ADOPTION.creatorTokenValueSha256,
    manualClusterReceiptSha256:
      __test.APPROVED_ADOPTION.manualClusterReceiptSha256,
    operationId: OPERATION_ID,
    providerClusterId: __test.APPROVED_ADOPTION.providerClusterId,
    sourceCommit: SOURCE_COMMIT,
    sqlClusterId: __test.APPROVED_ADOPTION.sqlClusterId,
    treeDigest: TREE_DIGEST
  };
  const humanAuthorizationBinding = sharedHumanBinding(baseApproval);
  const approval = {
    ...baseApproval,
    billingAuthorization: {
      ...baseApproval.billingAuthorization,
      authorizationReceiptSha256:
        humanAuthorizationBinding.receiptBindingSha256
    },
    humanAuthorizationBinding,
    humanAuthorizationReceiptSha256:
      humanAuthorizationBinding.receiptBindingSha256,
    humanAuthorizedTextSha256:
      humanAuthorizationBinding.humanAuthorizedTextSha256
  };
  const authority = {
    approvalSha256: __test.sha256(__test.canonicalBytes(approval)),
    callerWorkflowRef: CALLER_WORKFLOW_REF,
    callerWorkflowSha: CALLER_WORKFLOW_SHA,
    controllerImportGraphSha256: CONTROLLER_IMPORT_GRAPH_SHA256,
    humanAuthorizationSignerSha256:
      humanAuthorizationBinding.dynamicIntent
        .humanAuthorizationSignerPublicKeySha256
  };
  assert.equal(__test.validateApprovedAdoption(approval, authority), approval);
  assert.throws(() => __test.validateApprovedAdoption(approval, {
    ...authority,
    humanAuthorizationSignerSha256: "0".repeat(64)
  }), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    clusterMode: "CREATE_NEW"
  }, authority), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    manualClusterReceiptSha256: "f".repeat(64)
  }, authority), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    providerClusterId: "223e4567-e89b-42d3-a456-426614174002"
  }, authority), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption(approval, {
    ...authority,
    approvalSha256: "0".repeat(64)
  }), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    callerWorkflowSha: "0".repeat(40)
  }, authority), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    humanAuthorizationReceiptSha256: "0".repeat(64)
  }, authority), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
});

test("wrong adopted admin password is rejected before provider setup", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pta-admin-bind-"));
  fs.chmodSync(directory, 0o700);
  try {
    const filePath = path.join(directory, "admin-password.txt");
    fs.writeFileSync(filePath, "wrong-".repeat(8), { mode: 0o600 });
    assert.throws(() => __test.readApprovedAdoptedAdminPassword(filePath, {
      adoptedAdminPasswordSha256:
        __test.APPROVED_ADOPTION.adoptedAdminPasswordSha256,
      clusterMode: "ADOPT_VERIFIED_EXISTING"
    }), /FRESH_CLUSTER_RUNNER_ADMIN_PASSWORD_REJECTED/u);
    const source = fs.readFileSync(path.join(
      process.cwd(), "scripts/run-fresh-cluster-provider.js"
    ), "utf8");
    assert.equal(source.indexOf("readApprovedAdoptedAdminPassword(") <
      source.indexOf("createFreshClusterAwsRuntime({"), true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("provider runner reports the unreconciled key-revocation hold", () => {
  const source = fs.readFileSync(path.join(
    process.cwd(), "scripts/run-fresh-cluster-provider.js"
  ), "utf8");
  assert.match(source,
    /FRESH_CLUSTER_PROVIDER_HOLD_PROVIDER_KEYS_REVOCATION_PENDING:/u);
  assert.doesNotMatch(source, /FRESH_CLUSTER_PROVIDER_PASS:/u);
});
