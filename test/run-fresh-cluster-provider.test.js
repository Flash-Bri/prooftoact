import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { FRESH_PRIMARY_RUNTIME_USERS } from
  "../scripts/bootstrap-fresh-primary.js";
import { __test } from "../scripts/run-fresh-cluster-provider.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const ACCOUNT = "111111111111";
const TABLE_ARN = `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
  "prooftoact-release-controller";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function args() {
  return [
    "--admin-password-file", "/private/admin-password.txt",
    "--admin-secret-arn", "admin-arn",
    "--admin-secret-version-id", "1".repeat(32),
    "--approval-file", "/private/approval.json",
    "--auditor-secret-arn", "auditor-arn",
    "--auditor-secret-version-id", "2".repeat(32),
    "--build-receipt", "/private/build.json",
    "--cloud-api-secret-arn", "cloud-arn",
    "--cloud-api-secret-version-id", "3".repeat(32),
    "--controller-table-arn", TABLE_ARN,
    "--credential-secret-arn", "credential-arn",
    "--credential-secret-version-id", "4".repeat(32),
    "--expected-commit", SOURCE_COMMIT,
    "--expected-tree", TREE_DIGEST,
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
  const approval = {
    adoptedAdminPasswordSha256:
      __test.APPROVED_ADOPTION.adoptedAdminPasswordSha256,
    billingAuthorization: {
      authorizationReceiptSha256:
        __test.APPROVED_ADOPTION.billingAuthorizationReceiptSha256,
      authorizedAt: __test.APPROVED_ADOPTION.billingAuthorizedAt,
      authorizedMonthlyCeilingUsd: "2.00"
    },
    auditorAuthorityReceiptSha256:
      __test.APPROVED_ADOPTION.auditorAuthorityReceiptSha256,
    auditorServiceAccountId:
      __test.APPROVED_ADOPTION.auditorServiceAccountId,
    auditorTokenValueSha256:
      __test.APPROVED_ADOPTION.auditorTokenValueSha256,
    clusterMode: "ADOPT_VERIFIED_EXISTING",
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
    providerClusterId: __test.APPROVED_ADOPTION.providerClusterId
  };
  assert.equal(__test.validateApprovedAdoption(approval), approval);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    clusterMode: "CREATE_NEW"
  }), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    manualClusterReceiptSha256: "f".repeat(64)
  }), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
  assert.throws(() => __test.validateApprovedAdoption({
    ...approval,
    providerClusterId: "223e4567-e89b-42d3-a456-426614174002"
  }), /FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED/u);
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
