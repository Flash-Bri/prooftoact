import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { __test } from "../scripts/run-fresh-primary-provider.js";

const ACCOUNT = "111111111111";
const BASE_ARGS = Object.freeze([
  "--admin-secret-arn",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/admin-Ab12Cd",
  "--admin-secret-version-id", "1".repeat(32),
  "--approval-file", "/private/approval.json",
  "--build-receipt", "/private/build.json",
  "--caller-workflow-sha", "d".repeat(40),
  "--cloud-api-secret-arn",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/cloud-api-Ef34Gh",
  "--cloud-api-secret-version-id", "2".repeat(32),
  "--controller-table-arn",
  `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
    "prooftoact-release-controller",
  "--credential-secret-arn",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/runtime-credentials-Ij56Kl",
  "--credential-secret-version-id", "3".repeat(32),
  "--expected-commit", "a".repeat(40),
  "--expected-tree", "b".repeat(40),
  "--operation-id", "123e4567-e89b-42d3-a456-426614174000",
  "--outer-authentication-receipt-sha256", "e".repeat(64),
  "--outer-command-sha256", "f".repeat(64),
  "--outer-reservation-receipt-sha256", "d".repeat(64),
  "--outer-reserved-at", "2026-08-19T08:00:00.000Z",
  "--outer-reservation-acknowledged-at", "2026-08-19T08:00:01.000Z",
  "--provider-cluster-id", "223e4567-e89b-42d3-a456-426614174001",
  "--recovery-security-receipt-sha256", "c".repeat(64),
  "--receipt-output", "/private/receipt.json",
  "--signer-secret-arn",
    `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/recovery-signer-" +
    "123e4567-e89b-42d3-a456-426614174000-Mn78Op",
  "--signer-secret-version-id", "4".repeat(32),
  "--sql-cluster-id", "323e4567-e89b-42d3-a456-426614174002"
]);

test("runner accepts one exact coordinate set and rejects duplicates or ID aliasing", () => {
  const parsed = __test.parseArguments([...BASE_ARGS]);
  assert.equal(parsed["--expected-commit"], "a".repeat(40));
  assert.equal(parsed["--caller-workflow-sha"], "d".repeat(40));
  assert.equal(parsed["--sql-cluster-id"],
    "323e4567-e89b-42d3-a456-426614174002");
  assert.throws(() => __test.parseArguments([
    ...BASE_ARGS.slice(0, -2),
    "--provider-cluster-id",
    "223e4567-e89b-42d3-a456-426614174001"
  ]), /FRESH_PRIMARY_RUNNER_ARGUMENTS_REJECTED/u);
  assert.throws(() => __test.parseArguments([
    ...BASE_ARGS.slice(0, -1),
    "223e4567-e89b-42d3-a456-426614174001"
  ]), /FRESH_PRIMARY_RUNNER_ARGUMENTS_REJECTED/u);
  const realSqlId = [...BASE_ARGS];
  realSqlId[realSqlId.indexOf("--sql-cluster-id") + 1] =
    "9fad7a1e-e440-4989-3823-04191b7f3f3b";
  assert.equal(__test.parseArguments(realSqlId)["--sql-cluster-id"],
    "9fad7a1e-e440-4989-3823-04191b7f3f3b");
});

test("runner accepts only explicit temporary AWS credentials", () => {
  const credentials = __test.explicitAwsCredentials({
    AWS_ACCESS_KEY_ID: `ASIA${"A".repeat(16)}`,
    AWS_SECRET_ACCESS_KEY: "b".repeat(40),
    AWS_SESSION_TOKEN: "c".repeat(64)
  });
  assert.equal(credentials.accessKeyId, `ASIA${"A".repeat(16)}`);
  assert.throws(() => __test.explicitAwsCredentials({
    AWS_ACCESS_KEY_ID: `AKIA${"A".repeat(16)}`,
    AWS_SECRET_ACCESS_KEY: "b".repeat(40),
    AWS_SESSION_TOKEN: "c".repeat(64)
  }), /FRESH_PRIMARY_RUNNER_AWS_CREDENTIALS_REJECTED/u);
});

test("receipt publication is create-only, canonical, and private", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pta-receipt-"));
  fs.chmodSync(directory, 0o700);
  try {
    const receiptPath = path.join(directory, "receipt.json");
    const receipt = { schemaVersion: "test.v1", status: "PASS" };
    const digest = __test.publishPrivateReceipt(receiptPath, receipt);
    assert.match(digest, /^[0-9a-f]{64}$/u);
    assert.deepEqual(
      fs.readFileSync(receiptPath),
      __test.canonicalBytes(receipt)
    );
    assert.equal(fs.statSync(receiptPath).mode & 0o077, 0);
    assert.throws(() => __test.publishPrivateReceipt(receiptPath, receipt),
      /FRESH_PRIMARY_RUNNER_RECEIPT_PUBLICATION_REJECTED/u);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime credential policy digest is fixed and non-secret", () => {
  assert.match(__test.runtimePolicySha256(), /^[0-9a-f]{64}$/u);
  assert.equal(__test.runtimePolicySha256(), __test.runtimePolicySha256());
});
