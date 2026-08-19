import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test as awsTest,
  createFreshPrimaryCredentialSealerAwsRuntime
} from "../scripts/fresh-primary-credential-sealer-aws-runtime.js";
import {
  __test as runnerTest
} from "../scripts/run-fresh-primary-credential-sealer.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ACCOUNT = "111111111111";
const OPERATION = "123e4567-e89b-42d3-a456-426614174000";
const ARNS = [
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-cluster/auditor-Aa11Bb",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/cloud-api-Cc22Dd",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/runtime-credentials-Ee33Ff",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/gate2/managed-mcp-Gg44Hh",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/gate2/recovery-publisher-Ii55Jj",
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    `prooftoact/fresh-primary/admin-${OPERATION}-Kk66Ll`,
  `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    `prooftoact/fresh-primary/recovery-signer-${OPERATION}-Mm77Nn`
];

test("AWS sealer runtime accepts only exact seven secret families and disables retries", async () => {
  const allowed = new Set(ARNS);
  assert.equal(awsTest.exactArn(ARNS[0], allowed), ARNS[0]);
  assert.throws(() => awsTest.exactArn(
    ARNS[0].replace("auditor", "unrelated"), allowed
  ), /FRESH_CREDENTIAL_AWS_ARN_REJECTED/u);
  assert.deepEqual(awsTest.fixedSdkOptions(), {
    maxAttempts: 1,
    region: "us-east-1"
  });
  await assert.rejects(createFreshPrimaryCredentialSealerAwsRuntime({
    secretArns: [...ARNS.slice(0, 6), ARNS[0]]
  }), /FRESH_CREDENTIAL_AWS_CONFIGURATION_REJECTED/u);
});

test("AWS runtime performs complete version listing and has no enumeration/log path", () => {
  const source = fs.readFileSync(path.join(
    ROOT, "scripts/fresh-primary-credential-sealer-aws-runtime.js"
  ), "utf8");
  assert.match(source, /ListSecretVersionIdsCommand/u);
  assert.match(source, /IncludeDeprecated: true/u);
  assert.match(source, /MaxResults: 100/u);
  assert.match(source, /maxAttempts: 1/u);
  assert.doesNotMatch(source, /ListSecretsCommand/u);
  assert.doesNotMatch(source, /console\./u);
});

test("runner CLI accepts only private file paths, never secret values", () => {
  const paths = Object.fromEntries(runnerTest.OPTIONS.map((option, index) =>
    [option, `/private/input-${index}`]));
  const argv = Object.entries(paths).flat();
  assert.deepEqual(runnerTest.parseArguments(argv), paths);
  assert.throws(() => runnerTest.parseArguments([
    ...argv.slice(0, -2),
    "--auditor-value",
    "private-token"
  ]), /FRESH_CREDENTIAL_RUNNER_ARGUMENTS_REJECTED/u);
  const source = fs.readFileSync(path.join(
    ROOT, "scripts/run-fresh-primary-credential-sealer.js"
  ), "utf8");
  assert.doesNotMatch(source, /process\.env/u);
  assert.doesNotMatch(source, /console\./u);
  assert.match(source, /buffer\.fill\(0\)/u);
});
