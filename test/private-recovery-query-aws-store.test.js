import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  createPrivateRecoveryQueryAwsStore,
  __test as storeInternals
} from "../src/cloud/private-recovery-query-aws-store.js";
import {
  buildPrivateRecoveryQueryCommand,
  __test as queryInternals
} from "../src/cloud/private-recovery-query.js";

function s(value) { return { S: value }; }
function n(value) { return { N: String(value) }; }
function b(value) { return { B: Buffer.from(canonicalJson(value), "utf8") }; }

function fixture() {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const secretArn =
    "arn:aws:secretsmanager:us-east-1:111111111111:secret:prooftoact/private-recovery-query/managed-mcp-A1b2C3";
  const version = "v".repeat(32);
  const mappingBody = {
    schemaVersion: "prooftoact.primary-provider-sql-mapping.v1",
    status: "PROVIDER_READBACK_BOUND",
    cloud: "COCKROACHDB_CLOUD_ON_AWS",
    providerClusterId: "33333333-3333-4333-8333-333333333333",
    sqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b",
    host: "prooftoact-fresh-primary.cockroachlabs.cloud",
    cockroachVersion: "CockroachDB CCL v26.2.5",
    clusterInventorySha256: "a".repeat(64),
    manualClusterReceiptSha256: "b".repeat(64),
    sourceCommit: "8".repeat(40),
    treeDigest: "c".repeat(40),
    sourceBindingSha256: "d".repeat(64),
    observedAt: "2026-08-19T01:54:00.000Z"
  };
  const primaryClusterMapping = {
    ...mappingBody,
    receiptSha256: queryInternals.lineDigest(mappingBody)
  };
  const approval = {
    schemaVersion: "prooftoact.private-recovery-query-approval.v1",
    approvedAt: "2026-08-19T01:55:00.000Z",
    billingAuthorizationSha256: "1".repeat(64),
    expectedBundleDigest: "2".repeat(64),
    expectedSourceClusterId: "33333333-3333-4333-8333-333333333333",
    expectedSourceCommitTs: "2026-08-19T01:59:00.000Z",
    expectedSourceSqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b",
    expiresAt: "2026-08-19T02:30:00.000Z",
    mcpSecretArnSha256: queryInternals.sha256(secretArn),
    mcpSecretValueSha256: "4".repeat(64),
    mcpSecretVersionIdSha256: queryInternals.sha256(version),
    operationId: "55555555-5555-4555-8555-555555555555",
    providerBindingSha256: "3".repeat(64),
    publisherKeyId: "synthetic-key",
    publisherPublicKeySpkiBase64: publicKey.export({
      type: "spki",
      format: "der"
    }).toString("base64"),
    primaryClusterMapping,
    recoveryClusterId: "66666666-6666-4666-8666-666666666666",
    recoverySessionId: "77777777-7777-4777-8777-777777777777",
    sourceCommit: "8".repeat(40),
    sourceClusterMappingReceiptSha256: primaryClusterMapping.receiptSha256,
    sourceDigest: "9".repeat(64),
    subjectBindingHash: "a".repeat(64),
    tenantId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    treeDigest: "c".repeat(40)
  };
  const command = buildPrivateRecoveryQueryCommand({
    approval,
    codeZipSha256: "d".repeat(64),
    configSha256: "e".repeat(64),
    functionArn:
      "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-private-recovery-query",
    functionVersion: "3",
    mcpSecretArn: secretArn,
    mcpSecretVersionId: version,
    releaseControlTableArn:
      "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller",
    now: new Date("2026-08-19T02:00:00.000Z")
  });
  return { command };
}

function fakeRuntime() {
  let item;
  const calls = [];
  let loseNextAck = false;
  const runtime = {
    calls,
    loseAck() { loseNextAck = true; },
    async getReleaseControlItem(input) {
      calls.push({ action: "get", input });
      return { Item: item };
    },
    async updateReleaseControlItem(input) {
      calls.push({ action: "update", input });
      const values = input.ExpressionAttributeValues;
      const status = values[":status"].S;
      if (status === "RESERVED") {
        item = {
          pk: input.Key.pk,
          schemaVersion: values[":schemaVersion"],
          status: values[":status"],
          command: values[":command"],
          commandSha256: values[":commandSha256"],
          operationId: values[":operationId"],
          version: values[":version"]
        };
      } else if (status === "DISPATCHING") {
        item = {
          ...item,
          status: values[":status"],
          dispatch: values[":dispatch"],
          version: values[":version"]
        };
      } else {
        item = {
          pk: item.pk,
          schemaVersion: item.schemaVersion,
          status: values[":status"],
          command: item.command,
          commandSha256: item.commandSha256,
          operationId: item.operationId,
          receipt: values[":receipt"],
          version: values[":version"]
        };
      }
      if (loseNextAck) {
        loseNextAck = false;
        throw new Error("synthetic acknowledgement loss");
      }
      return { Attributes: item };
    }
  };
  return runtime;
}

function receipt(command, status) {
  const body = status === "PASS" ? {
    schemaVersion: "prooftoact.private-recovery-query-receipt.v1",
    status,
    approvalSha256: command.approvalSha256,
    authorityTransferred: false,
    boundary: "RECOVERED_CONTEXT_ONLY",
    bundleDigest: "1".repeat(64),
    commandSha256: command.commandSha256,
    completedAt: "2026-08-19T02:00:00.000Z",
    functionArnSha256: "2".repeat(64),
    functionVersion: command.functionVersion,
    lambdaRequestIdSha256: "3".repeat(64),
    managedMcp: {
      closeHttpStatus: 204,
      endpointSha256: "4".repeat(64),
      notificationCount: 1,
      protocolVersion: "2025-03-26",
      rpcCallCount: 2,
      semanticEvidenceSha256: "5".repeat(64),
      sessionContinuous: true,
      toolCallCount: 1,
      transportEvidenceSha256: "6".repeat(64)
    },
    operationId: command.operationId,
    publisherKeyIdSha256: "7".repeat(64),
    providerBindingSha256: "0".repeat(64),
    recoverySessionIdSha256: "8".repeat(64),
    requiresFreshAuthorization: true,
    signatureDigest: "9".repeat(64),
    sourceClusterIdSha256: "a".repeat(64),
    sourceClusterMappingReceiptSha256: "e".repeat(64),
    sourceCommit: command.sourceCommit,
    sourceCommitTs: "2026-08-19T01:59:00.000Z",
    sourceDigest: "b".repeat(64),
    sourceSqlClusterIdSha256: "f".repeat(64),
    subjectBindingSha256: "c".repeat(64),
    tenantIdSha256: "d".repeat(64),
    treeDigest: command.treeDigest
  } : {
    schemaVersion: "prooftoact.private-recovery-query-receipt.v1",
    status,
    approvalSha256: command.approvalSha256,
    authorityTransferred: false,
    boundary: "RECOVERED_CONTEXT_ONLY",
    commandSha256: command.commandSha256,
    errorCode: "PRIVATE_RECOVERY_QUERY_SYNTHETIC_UNKNOWN",
    lambdaRequestIdSha256: "3".repeat(64),
    operationId: command.operationId,
    providerCallPossible: true,
    requiresFreshAuthorization: true,
    sourceCommit: command.sourceCommit,
    treeDigest: command.treeDigest
  };
  return {
    ...body,
    receiptSha256: queryInternals.digest(body)
  };
}

test("AWS store reserves, dispatches, and finalizes one exact item", async () => {
  const { command } = fixture();
  const runtime = fakeRuntime();
  const store = createPrivateRecoveryQueryAwsStore({ runtime });
  assert.equal((await store.reserve(command)).status, "RESERVED");
  const dispatch = {
    lambdaRequestIdSha256: "1".repeat(64),
    logicalRequestSha256: command.logicalRequestSha256,
    querySha256: command.querySha256,
    secretValueSha256: "2".repeat(64)
  };
  assert.equal((await store.markDispatch(command, dispatch)).status,
    "DISPATCHING");
  assert.equal((await store.finalize(command, dispatch, receipt(command, "PASS")))
    .status, "FINAL");
  assert.equal((await store.read(command)).receipt.status, "PASS");
  assert.equal(runtime.calls.filter(({ action }) => action === "update").length, 3);
  assert.equal(runtime.calls[0].input.ConditionExpression,
    "attribute_not_exists(#pk)");
  assert.deepEqual(runtime.calls[0].input.Key,
    { pk: s(storeInternals.stateKey(command)) });
});

test("conditional write acknowledgement loss converges by strong read only", async () => {
  const { command } = fixture();
  const runtime = fakeRuntime();
  const store = createPrivateRecoveryQueryAwsStore({ runtime });
  runtime.loseAck();
  assert.equal((await store.reserve(command)).status, "RESERVED");
  assert.deepEqual(runtime.calls.map(({ action }) => action), ["update", "get"]);
  assert.equal(runtime.calls[1].input.ConsistentRead, true);
});

test("unknown terminalization preserves no provider retry authority", async () => {
  const { command } = fixture();
  const runtime = fakeRuntime();
  const store = createPrivateRecoveryQueryAwsStore({ runtime });
  await store.reserve(command);
  const dispatch = {
    lambdaRequestIdSha256: "1".repeat(64),
    logicalRequestSha256: command.logicalRequestSha256,
    querySha256: command.querySha256,
    secretValueSha256: "2".repeat(64)
  };
  await store.markDispatch(command, dispatch);
  const terminal = await store.markUnknown(
    command,
    receipt(command, "UNKNOWN_DO_NOT_RETRY")
  );
  assert.equal(terminal.status, "UNKNOWN");
  assert.equal(terminal.receipt.providerCallPossible, true);
});
