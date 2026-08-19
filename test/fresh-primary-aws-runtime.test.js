import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  createFreshPrimaryAwsRuntime
} from "../scripts/fresh-primary-aws-runtime.js";

const ACCOUNT = "111111111111";
const TABLE_ARN =
  `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
  "prooftoact-release-controller";
const CLUSTER_ID = "123e4567-e89b-42d3-a456-426614174000";
const SECRET_COORDINATES = Object.freeze({
  admin: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      `prooftoact/fresh-primary/admin-${CLUSTER_ID}-Ab12Cd`,
    versionId: "1".repeat(32)
  }),
  cloudApi: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
    "prooftoact/fresh-primary/cloud-api-Ef34Gh",
    versionId: "2".repeat(32)
  }),
  credential: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      "prooftoact/fresh-primary/runtime-credentials-Ij56Kl",
    versionId: "3".repeat(32)
  }),
  signer: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      `prooftoact/fresh-primary/recovery-signer-${CLUSTER_ID}-Mn78Op`,
    versionId: "4".repeat(32)
  })
});
const CREDENTIALS = Object.freeze({
  accessKeyId: `ASIA${"A".repeat(16)}`,
  secretAccessKey: "b".repeat(40),
  sessionToken: "c".repeat(64)
});
const DYNAMO_DB_RUNTIME = Object.freeze(Object.fromEntries([
  "describeReleaseControlTable",
  "getReleaseControlItem",
  "listReleaseControlTags",
  "putReleaseControlItem",
  "updateReleaseControlItem"
].map((name) => [name, async () => ({})])));

function jsonResponse(value, overrides = {}) {
  return new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    status: 200,
    ...overrides
  });
}

test("Cockroach Cloud reader uses one fixed HTTPS endpoint without redirects", async () => {
  const calls = [];
  const inventory = {
    id: CLUSTER_ID,
    cloud_provider: "AWS",
    state: "CREATED"
  };
  const runtime = await createFreshPrimaryAwsRuntime({
    credentials: CREDENTIALS,
    dynamoDbRuntime: DYNAMO_DB_RUNTIME,
    async fetchImpl(url, options) {
      calls.push({ url, options });
      const response = jsonResponse(inventory);
      Object.defineProperty(response, "url", { value: url });
      return response;
    },
    region: "us-east-1",
    secretCoordinates: SECRET_COORDINATES,
    tableArn: TABLE_ARN
  });
  const result = await runtime.readCockroachCluster({
    bearerToken: "token-with-more-than-twenty-characters",
    clusterId: CLUSTER_ID
  });
  assert.deepEqual(result, inventory);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url,
    `https://cockroachlabs.cloud/api/v1/clusters/${CLUSTER_ID}`);
  assert.equal(calls[0].options.method, "GET");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].options.headers.Accept, "application/json");
  assert.equal(calls[0].options.headers.Authorization,
    "Bear" + "er token-with-more-than-twenty-characters");
  assert.equal(calls[0].options.headers["Cc-Version"], "2024-09-16");
});

test("bounded cloud response rejects redirects, non-JSON, and oversized bodies", async () => {
  const redirect = jsonResponse({ ok: true });
  Object.defineProperty(redirect, "url", {
    value: "https://example.invalid/redirected"
  });
  await assert.rejects(__test.boundedJsonResponse(redirect),
    /FRESH_PRIMARY_COCKROACH_CLOUD_RESPONSE_REJECTED/u);

  const text = new Response("text", {
    headers: { "content-type": "text/plain" },
    status: 200
  });
  Object.defineProperty(text, "url", {
    value: `https://cockroachlabs.cloud/api/v1/clusters/${CLUSTER_ID}`
  });
  await assert.rejects(__test.boundedJsonResponse(text),
    /FRESH_PRIMARY_COCKROACH_CLOUD_RESPONSE_REJECTED/u);

  const oversized = jsonResponse({ ok: true });
  oversized.headers.set("content-length", String(512 * 1024 + 1));
  Object.defineProperty(oversized, "url", {
    value: `https://cockroachlabs.cloud/api/v1/clusters/${CLUSTER_ID}`
  });
  await assert.rejects(__test.boundedJsonResponse(oversized),
    /FRESH_PRIMARY_COCKROACH_CLOUD_RESPONSE_REJECTED/u);
});

test("runtime accepts only explicit temporary credentials and exact secret versions", () => {
  assert.deepEqual(__test.validateExplicitCredentials(CREDENTIALS), CREDENTIALS);
  for (const credentials of [
    { ...CREDENTIALS, accessKeyId: `AKIA${"A".repeat(16)}` },
    { ...CREDENTIALS, secretAccessKey: "short" },
    { ...CREDENTIALS, extra: "ambient" }
  ]) {
    assert.throws(() => __test.validateExplicitCredentials(credentials),
      /FRESH_PRIMARY_AWS_EXPLICIT_CREDENTIALS_REJECTED/u);
  }
  const allowed = new Set([
    `${SECRET_COORDINATES.admin.arn}\n${SECRET_COORDINATES.admin.versionId}`
  ]);
  assert.deepEqual(__test.requireSecret(SECRET_COORDINATES.admin, allowed), {
    SecretId: SECRET_COORDINATES.admin.arn,
    VersionId: SECRET_COORDINATES.admin.versionId,
    VersionStage: "AWSCURRENT"
  });
  assert.throws(() => __test.requireSecret({
    ...SECRET_COORDINATES.admin,
    versionId: "9".repeat(32)
  }, allowed), /FRESH_PRIMARY_AWS_RUNTIME_SECRET_REJECTED/u);
});

test("DynamoDB guard accepts only the fresh-primary key family", () => {
  const key = { pk: { S: `FRESH_PRIMARY#${"a".repeat(64)}` } };
  assert.doesNotThrow(() => __test.requireExactKey({
    ConsistentRead: true,
    Key: key,
    ReturnConsumedCapacity: "NONE",
    TableName: "prooftoact-release-controller"
  }));
  for (const pk of [
    `EFFECT#${"a".repeat(64)}`,
    `FRESH_PRIMARY#${"a".repeat(63)}`,
    "FRESH_PRIMARY#*"
  ]) {
    assert.throws(() => __test.requireExactKey({
      Key: { pk: { S: pk } },
      TableName: "prooftoact-release-controller"
    }), /FRESH_PRIMARY_AWS_RUNTIME_KEY_REJECTED/u);
  }
});
