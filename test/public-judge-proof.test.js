import assert from "node:assert/strict";
import test from "node:test";

import { __test as lambdaTest } from
  "../infra/aws/lambda/judge-proof.js";
import {
  JUDGE_PROOF_PINNED_BINDING,
  judgeProofResultSha256
} from
  "../src/cloud/judge-proof-query.js";
import {
  PUBLIC_JUDGE_PROOF_PATH,
  createPublicJudgeProofHandler
} from "../src/cloud/public-judge-proof.js";

const API_ID = "abc123def4";
const API_KEY = "synthetic-api-key-that-is-long-enough";
const CLUSTER_ID = "44444444-4444-4444-8444-444444444444";
const CLUSTER_SHA256 =
  "f1d11edf5c5cbe84bc60d6c543d0d5938a5bd3a833381499af7549ddc4933a23";
const SOURCE_COMMIT = "a".repeat(40);
const SECRET_ARN =
  "arn:aws:secretsmanager:us-east-1:123456789012:secret:prooftoact/judge-proof/managed-mcp-Ab1234";
const SECRET_VERSION = "v".repeat(32);

function binding() {
  return {
    expectedApiId: API_ID,
    mcpClusterId: CLUSTER_ID,
    mcpSecretArn: SECRET_ARN,
    mcpSecretVersionId: SECRET_VERSION,
    sourceCommit: SOURCE_COMMIT,
    lambdaVersion: "7"
  };
}

function secret(overrides = {}) {
  return {
    arn: SECRET_ARN,
    versionId: SECRET_VERSION,
    versionStages: ["AWSCURRENT"],
    secretString: JSON.stringify({ apiKey: API_KEY }),
    secretBinary: undefined,
    ...overrides
  };
}

function event(overrides = {}) {
  return {
    version: "2.0",
    rawPath: PUBLIC_JUDGE_PROOF_PATH,
    rawQueryString: "",
    requestContext: {
      apiId: API_ID,
      stage: "$default",
      routeKey: `GET ${PUBLIC_JUDGE_PROOF_PATH}`,
      http: { method: "GET" }
    },
    queryStringParameters: undefined,
    pathParameters: undefined,
    body: undefined,
    isBase64Encoded: false,
    ...overrides
  };
}

function proof() {
  return Object.freeze({
    schemaVersion: 1,
    receiptBoundary: "HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY",
    bundleDigest: JUDGE_PROOF_PINNED_BINDING.bundleDigest,
    signatureDigest: JUDGE_PROOF_PINNED_BINDING.signatureDigest,
    publisherKeySha256:
      JUDGE_PROOF_PINNED_BINDING.publisherPublicKeySha256,
    sourceClusterIdSha256:
      "14c5c7422eb048ace7a479f46db569680d46953426cc2fb541533a949361eeb6",
    sourceCommitTs: "2026-08-19T13:37:22.051Z",
    sourceDigest: JUDGE_PROOF_PINNED_BINDING.sourceDigest,
    expiresAt: "2026-08-20T12:37:22.051Z",
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    receiptReason: "transport-proof-only",
    bindingSha256: "8".repeat(64)
  });
}

function managedRead() {
  const acceptedProof = proof();
  return Object.freeze({
    schemaVersion: "prooftoact.public-judge-proof-read.v1",
    status: "LIVE_MANAGED_MCP_READ",
    observedAt: "2026-09-15T14:00:00.000Z",
    receiptExpiredContext: true,
    proof: acceptedProof,
    proofSha256: judgeProofResultSha256(acceptedProof),
    semanticRequestEvidenceSha256: "9".repeat(64),
    transport: Object.freeze({
      endpointAuthority: "cockroachlabs.cloud",
      protocolVersion: "2025-03-26",
      clusterIdSha256: CLUSTER_SHA256,
      boundedResponseBytes: 32 * 1024,
      redirectPolicy: "error",
      rpcCalls: [
        { method: "initialize", httpStatus: 200, responseCorrelated: true,
          sessionContinuous: true },
        { method: "tools/call", httpStatus: 200, responseCorrelated: true,
          sessionContinuous: true }
      ],
      notifications: [
        { method: "notifications/initialized", httpStatus: 202,
          sessionContinuous: true }
      ],
      close: { attempted: true, httpStatus: 204, sessionContinuous: true }
    })
  });
}

test("public judge proof accepts only exact parameter-free GET", async () => {
  let readCount = 0;
  let clientOptions;
  let readArguments;
  const handler = createPublicJudgeProofHandler({
    binding: binding(),
    readSecret: async () => {
      readCount += 1;
      return secret();
    },
    createMcpClient(options) {
      clientOptions = options;
      return {
        async readPinnedJudgeProof(...args) {
          readArguments = args;
          return managedRead();
        }
      };
    }
  });
  const first = await handler(event());
  const second = await handler(event());
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(readCount, 1);
  assert.deepEqual(clientOptions, {
    apiKey: API_KEY,
    clusterId: CLUSTER_ID
  });
  assert.deepEqual(readArguments, []);
  const body = JSON.parse(first.body);
  assert.equal(body.proof.bundleDigest, JUDGE_PROOF_PINNED_BINDING.bundleDigest);
  assert.equal(body.status, "LIVE_MANAGED_MCP_READ");
  assert.equal(body.lambdaVersion, "7");
  assert.equal(body.managedMcp.sessionClosed, true);
  assert.equal(
    first.headers["access-control-allow-origin"],
    "https://flash-bri.github.io"
  );
  assert.equal(first.headers.vary, "Origin");
  assert.equal(first.headers["access-control-allow-methods"], undefined);
});

test("browser CORS permits only the exact GitHub Pages origin", async () => {
  const handler = createPublicJudgeProofHandler({
    binding: binding(),
    readSecret: async () => secret(),
    createMcpClient: () => ({
      readPinnedJudgeProof: async () => managedRead()
    })
  });
  const response = await handler(event());
  assert.equal(response.statusCode, 200);
  assert.equal(
    response.headers["access-control-allow-origin"],
    "https://flash-bri.github.io"
  );
  assert.equal(response.headers["access-control-allow-origin"].includes("*"), false);
  assert.equal(response.headers["cross-origin-resource-policy"], "cross-origin");
  assert.equal(response.headers["access-control-allow-credentials"], undefined);
  assert.equal(response.headers["access-control-allow-methods"], undefined);
  assert.equal(response.headers.vary, "Origin");
});

test("public judge proof rejects body, query, route, and API substitution before secret read", async () => {
  let readCount = 0;
  const handler = createPublicJudgeProofHandler({
    binding: binding(),
    readSecret: async () => {
      readCount += 1;
      return secret();
    }
  });
  for (const changed of [
    event({ rawQueryString: "query=SELECT%201" }),
    event({ queryStringParameters: { database: "defaultdb" } }),
    event({ body: JSON.stringify({ clusterId: CLUSTER_ID }) }),
    event({ rawPath: "/api/other" }),
    event({ requestContext: {
      ...event().requestContext,
      apiId: "otherapi"
    } }),
    event({ requestContext: {
      ...event().requestContext,
      http: { method: "POST" }
    } })
  ]) {
    const response = await handler(changed);
    assert.equal(response.statusCode, 404);
    assert.deepEqual(JSON.parse(response.body), { error: "not_found" });
  }
  assert.equal(readCount, 0);
});

test("public judge proof validates the exact secret and hides failures", async () => {
  for (const changed of [
    secret({ versionId: "x".repeat(32) }),
    secret({ secretString: JSON.stringify({
      apiKey: API_KEY,
      clusterId: "55555555-5555-4555-8555-555555555555"
    }) }),
    secret({
      secretString: `{"apiKey":${JSON.stringify(API_KEY)},"apiKey":"leak"}`
    })
  ]) {
    const handler = createPublicJudgeProofHandler({
      binding: binding(),
      readSecret: async () => changed
    });
    const response = await handler(event());
    assert.equal(response.statusCode, 503);
    assert.deepEqual(JSON.parse(response.body), { error: "proof_unavailable" });
    assert.equal(response.body.includes(API_KEY), false);
    assert.equal(response.body.includes(CLUSTER_ID), false);
  }
});

test("public judge proof Lambda requires explicit Lambda credentials", () => {
  const credentials = lambdaTest.explicitCredentials({
    AWS_ACCESS_KEY_ID: `ASIA${"A".repeat(16)}`,
    AWS_SECRET_ACCESS_KEY: "s".repeat(40),
    AWS_SESSION_TOKEN: "t".repeat(32)
  });
  assert.equal(credentials.accessKeyId, `ASIA${"A".repeat(16)}`);
  assert.throws(
    () => lambdaTest.explicitCredentials({}),
    /PUBLIC_JUDGE_PROOF_AWS_CREDENTIALS_REJECTED/u
  );
});
