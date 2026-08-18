import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  createReleaseControlAwsRuntime
} from "../release-control/src/release-control-aws-runtime.js";

const CREDENTIALS = Object.freeze({
  accessKeyId: "ASIAEXPLICITFIXTURE1",
  secretAccessKey: "s".repeat(40),
  sessionToken: "t".repeat(32)
});

test("release-control AWS runtime accepts only explicit short-lived credentials", async () => {
  assert.deepEqual(__test.validateExplicitCredentials(CREDENTIALS), CREDENTIALS);
  for (const rejected of [
    null,
    { accessKeyId: CREDENTIALS.accessKeyId, secretAccessKey: "s".repeat(40) },
    { ...CREDENTIALS, accessKeyId: "AKIAEXPLICITFIXTURE1" },
    { ...CREDENTIALS, profile: "default" },
    { ...CREDENTIALS, sessionToken: "short" }
  ]) {
    assert.throws(
      () => __test.validateExplicitCredentials(rejected),
      /RELEASE_CONTROL_AWS_EXPLICIT_CREDENTIALS_REJECTED/u
    );
  }
  await assert.rejects(
    createReleaseControlAwsRuntime({
      credentials: CREDENTIALS,
      region: "us-west-2",
      tableArn: "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller"
    }),
    /RELEASE_CONTROL_AWS_REGION_REJECTED/u
  );
});

test("release-control AWS runtime fixes endpoints, signing, and one attempt", async () => {
  assert.deepEqual(__test.fixedSdkOptions(), {
    authSchemePreference: ["sigv4"],
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  });
  const runtime = await createReleaseControlAwsRuntime({
    credentials: CREDENTIALS,
    region: "us-east-1",
    tableArn: "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller"
  });
  assert.deepEqual(Object.keys(runtime), [
    "describeReleaseControlTable",
    "getReleaseControlItem",
    "getReleaseControlCallerIdentity",
    "listReleaseControlTags",
    "transactReleaseControlItems",
    "updateReleaseControlItem"
  ]);
  assert.throws(
    () => __test.requireExactTable({ TableName: "other" }),
    /RELEASE_CONTROL_AWS_TABLE_REJECTED/u
  );
  assert.throws(
    () => __test.requireExactTransaction({ TransactItems: [] }),
    /RELEASE_CONTROL_AWS_TRANSACTION_REJECTED/u
  );
});

test("release-control runtime normalizes only one exact assumed-role identity", () => {
  const normalized = __test.normalizeCallerIdentity({
    Account: "111111111111",
    Arn:
      "arn:aws:sts::111111111111:assumed-role/ProofToActReleaseExecution/GitHubActions",
    UserId: "AROA1234567890ABCDEF:GitHubActions",
    $metadata: { requestId: "not-republished" }
  });
  assert.deepEqual(normalized, {
    accountId: "111111111111",
    assumedRoleArn:
      "arn:aws:sts::111111111111:assumed-role/ProofToActReleaseExecution/GitHubActions",
    roleId: "AROA1234567890ABCDEF",
    roleName: "ProofToActReleaseExecution",
    sessionName: "GitHubActions"
  });
  assert.equal(Object.hasOwn(normalized, "$metadata"), false);
  assert.throws(
    () => __test.normalizeCallerIdentity({
      Account: "222222222222",
      Arn:
        "arn:aws:sts::111111111111:assumed-role/ProofToActReleaseExecution/GitHubActions",
      UserId: "AROA1234567890ABCDEF:GitHubActions"
    }),
    /RELEASE_CONTROL_AWS_CALLER_IDENTITY_REJECTED/u
  );
});

test("release-control runtime source has no credential-chain or OAuth fallback", async () => {
  const source = await import("node:fs").then(({ readFileSync }) =>
    readFileSync(new URL(
      "../release-control/src/release-control-aws-runtime.js",
      import.meta.url
    ), "utf8")
  );
  assert.doesNotMatch(source, /fromIni|defaultProvider|OPENAI|OPENCLAW|OAuth/iu);
  assert.match(source, /maxAttempts:\s*1/u);
  assert.match(source, /ignoreConfiguredEndpointUrls:\s*true/u);
});
