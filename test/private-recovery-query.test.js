import assert from "node:assert/strict";
import crypto, { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { __test as lambdaTest } from
  "../infra/aws/lambda/private-recovery-query.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import { CockroachManagedMcpRecoveryClient } from
  "../src/cloud/managed-mcp-client.js";
import {
  bundleDigestFor,
  recoverySignaturePayloadFor
} from "../src/cloud/recovery-bundle-signature.js";
import {
  __test as privateRecoveryTest,
  buildPrivateRecoveryQueryCommand,
  reconcilePrivateRecoveryQuery,
  reservePrivateRecoveryQuery,
  runPrivateRecoveryQuery,
  validatePrivateRecoveryQueryReceipt
} from "../src/cloud/private-recovery-query.js";
import { executePrivateRecoveryQueryOnce } from
  "../src/cloud/private-recovery-query-operator.js";

const NOW = new Date("2026-08-19T02:00:00.000Z");
const FUNCTION_ARN =
  "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-private-recovery-query";
const TABLE_ARN =
  "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller";
const SECRET_ARN =
  "arn:aws:secretsmanager:us-east-1:111111111111:secret:prooftoact/private-recovery-query/managed-mcp-A1b2C3";
const SECRET_VERSION = "v".repeat(32);
const API_KEY = ["synthetic", "managed", "mcp", "credential", "fixture"]
  .join("-");
const HOSTILE_ACCOUNT_ID = ["222222", "222222"].join("");
const SECRET_VALUE = canonicalJson({ apiKey: API_KEY });

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const publisherKeyId = "fresh-primary-recovery-key-v1";
  const unsigned = {
    tenantId: "11111111-1111-4111-8111-111111111111",
    recoverySessionId: "22222222-2222-4222-8222-222222222222",
    subjectBindingHash: "3".repeat(64),
    schemaVersion: 2,
    snapshotVersion: NOW.getTime() - 60_000,
    sourceClusterId: "44444444-4444-4444-8444-444444444444",
    sourceCommitTs: "2026-08-19T01:59:00.000Z",
    sourceDigest: "5".repeat(64),
    policyVersion: "proof-to-act-v1",
    publisherKeyId,
    publisherVersion: "tideproof-recovery-publisher-v2",
    signatureAlgorithm: "ecdsa-p256-sha256",
    checkpointSummary: {
      checkpointVersion: 1,
      failedAgent: "synthetic-predecessor",
      phase: "successor-context-recovery",
      scenario: "synthetic-highwater"
    },
    evidenceSummary: {
      admittedCount: 2,
      classification: "synthetic",
      evidenceDigest: "6".repeat(64)
    },
    conflictSummary: { status: "none", unresolvedCount: 0 },
    receiptSummary: {
      durableIntentPresent: true,
      outcome: "resource_reserved",
      reason: null,
      resourceLabel: "synthetic-resource"
    },
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    expiresAt: "2026-08-19T02:29:00.000Z"
  };
  const bundleDigest = bundleDigestFor(unsigned);
  const signature = sign(
    "sha256",
    Buffer.from(recoverySignaturePayloadFor(unsigned), "utf8"),
    privateKey
  );
  const signed = {
    ...unsigned,
    bundleDigest,
    sourceSignatureBase64: signature.toString("base64"),
    signatureDigest: sha256(signature)
  };
  const row = {
    tenant_id: signed.tenantId,
    recovery_session_id: signed.recoverySessionId,
    subject_binding_hash: signed.subjectBindingHash,
    schema_version: String(signed.schemaVersion),
    snapshot_version: String(signed.snapshotVersion),
    source_cluster_id: signed.sourceClusterId,
    source_commit_ts: signed.sourceCommitTs,
    source_digest: signed.sourceDigest,
    bundle_digest: signed.bundleDigest,
    policy_version: signed.policyVersion,
    publisher_key_id: signed.publisherKeyId,
    publisher_version: signed.publisherVersion,
    signature_algorithm: signed.signatureAlgorithm,
    source_signature_base64: signed.sourceSignatureBase64,
    signature_digest: signed.signatureDigest,
    checkpoint_summary: signed.checkpointSummary,
    evidence_summary: signed.evidenceSummary,
    conflict_summary: signed.conflictSummary,
    receipt_summary: signed.receiptSummary,
    authority_transferred: false,
    requires_fresh_authorization: true,
    expires_at: signed.expiresAt
  };
  const mappingBody = {
    schemaVersion: "prooftoact.primary-provider-sql-mapping.v1",
    status: "PROVIDER_READBACK_BOUND",
    cloud: "COCKROACHDB_CLOUD_ON_AWS",
    providerClusterId: signed.sourceClusterId,
    sqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b",
    host: "prooftoact-fresh-primary.cockroachlabs.cloud",
    cockroachVersion: "CockroachDB CCL v26.2.5",
    clusterInventorySha256: "5".repeat(64),
    manualClusterReceiptSha256: "6".repeat(64),
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    sourceBindingSha256: "7".repeat(64),
    observedAt: "2026-08-19T01:54:00.000Z"
  };
  const primaryClusterMapping = {
    ...mappingBody,
    receiptSha256: sha256(`${canonicalJson(mappingBody)}\n`)
  };
  const approval = {
    schemaVersion: "prooftoact.private-recovery-query-approval.v1",
    approvedAt: "2026-08-19T01:55:00.000Z",
    billingAuthorizationSha256: "7".repeat(64),
    expectedBundleDigest: bundleDigest,
    expectedSourceClusterId: signed.sourceClusterId,
    expectedSourceCommitTs: signed.sourceCommitTs,
    expectedSourceSqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b",
    expiresAt: "2026-08-19T02:30:00.000Z",
    mcpSecretArnSha256: sha256(SECRET_ARN),
    mcpSecretValueSha256: sha256(SECRET_VALUE),
    mcpSecretVersionIdSha256: sha256(SECRET_VERSION),
    operationId: "88888888-8888-4888-8888-888888888888",
    providerBindingSha256: "8".repeat(64),
    publisherKeyId,
    publisherPublicKeySpkiBase64: publicKey.export({
      type: "spki",
      format: "der"
    }).toString("base64"),
    primaryClusterMapping,
    recoveryClusterId: "99999999-9999-4999-8999-999999999999",
    recoverySessionId: signed.recoverySessionId,
    sourceCommit: "a".repeat(40),
    sourceClusterMappingReceiptSha256: primaryClusterMapping.receiptSha256,
    sourceDigest: signed.sourceDigest,
    subjectBindingHash: signed.subjectBindingHash,
    tenantId: signed.tenantId,
    treeDigest: "b".repeat(40)
  };
  const command = buildPrivateRecoveryQueryCommand({
    approval,
    codeZipSha256: "c".repeat(64),
    configSha256: "d".repeat(64),
    functionArn: FUNCTION_ARN,
    functionVersion: "7",
    mcpSecretArn: SECRET_ARN,
    mcpSecretVersionId: SECRET_VERSION,
    releaseControlTableArn: TABLE_ARN,
    now: NOW
  });
  return { approval, command, row };
}

function memoryStore() {
  let state = null;
  const calls = [];
  return {
    calls,
    async reserve(command) {
      calls.push("reserve");
      state ??= {
        status: "RESERVED",
        commandSha256: command.commandSha256,
        operationId: command.operationId,
        version: 0
      };
      return state;
    },
    async read() {
      calls.push("read");
      if (state === null) throw new Error("absent");
      return state;
    },
    async markDispatch(command, dispatch) {
      calls.push("dispatch");
      assert.equal(state.status, "RESERVED");
      state = {
        status: "DISPATCHING",
        commandSha256: command.commandSha256,
        dispatch,
        operationId: command.operationId,
        version: 1
      };
      return state;
    },
    async finalize(command, dispatch, receipt) {
      calls.push("finalize");
      assert.deepEqual(state.dispatch, dispatch);
      state = {
        status: "FINAL",
        commandSha256: command.commandSha256,
        operationId: command.operationId,
        receipt,
        version: 2
      };
      return state;
    },
    async failBeforeDispatch(command, receipt) {
      calls.push("failed");
      state = {
        status: "FAILED",
        commandSha256: command.commandSha256,
        operationId: command.operationId,
        receipt,
        version: 2
      };
      return state;
    },
    async markUnknown(command, receipt) {
      calls.push("unknown");
      state = {
        status: "UNKNOWN",
        commandSha256: command.commandSha256,
        operationId: command.operationId,
        receipt,
        version: 2
      };
      return state;
    },
    state: () => state
  };
}

function mcpClientFor(row, calls, {
  failTools = false,
  failureMessage = "synthetic response acknowledgement loss"
} = {}) {
  const session = "synthetic-mcp-session";
  const fetchImpl = async (_url, options) => {
    const body = options.body === undefined ? null : JSON.parse(options.body);
    if (options.method === "DELETE") {
      calls.push("close");
      return new Response(null, {
        status: 204,
        headers: { "mcp-session-id": session }
      });
    }
    if (body?.method === "notifications/initialized") {
      calls.push("notification");
      return new Response(null, {
        status: 202,
        headers: { "mcp-session-id": session }
      });
    }
    if (body?.method === "initialize") {
      calls.push("initialize");
      return Response.json({
        jsonrpc: "2.0",
        id: body.id,
        result: { protocolVersion: "2025-03-26" }
      }, { headers: { "mcp-session-id": session } });
    }
    assert.equal(body?.method, "tools/call");
    calls.push("tools/call");
    if (failTools) throw new Error(failureMessage);
    return Response.json({
      jsonrpc: "2.0",
      id: body.id,
      result: { rows: [row] }
    }, { headers: { "mcp-session-id": session } });
  };
  return (options) => new CockroachManagedMcpRecoveryClient({
    ...options,
    fetchImpl
  });
}

function invocationOptions(overrides = {}) {
  const { approval, command, row } = fixture();
  const store = memoryStore();
  return {
    approval,
    clock: () => NOW,
    command,
    createMcpClient: mcpClientFor(row, []),
    lambdaContext: {
      awsRequestId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      functionVersion: "7",
      invokedFunctionArn: `${FUNCTION_ARN}:7`
    },
    row,
    secretReader: {
      async readExactVersion() {
        return {
          secretArnSha256: sha256(SECRET_ARN),
          secretValue: SECRET_VALUE,
          secretValueSha256: sha256(SECRET_VALUE),
          secretVersionIdSha256: sha256(SECRET_VERSION)
        };
      }
    },
    store,
    ...overrides
  };
}

test("private Lambda performs one fixed Managed MCP query and emits no row", async () => {
  const calls = [];
  const options = invocationOptions();
  options.createMcpClient = mcpClientFor(options.row, calls);
  await reservePrivateRecoveryQuery({
    command: options.command,
    store: options.store
  });
  const receipt = await runPrivateRecoveryQuery(options);
  assert.equal(receipt.status, "PASS", canonicalJson(receipt));
  assert.equal(receipt.boundary, "RECOVERED_CONTEXT_ONLY");
  assert.equal(receipt.authorityTransferred, false);
  assert.equal(receipt.requiresFreshAuthorization, true);
  assert.equal(receipt.managedMcp.toolCallCount, 1);
  assert.equal(receipt.sourceClusterMappingReceiptSha256,
    options.approval.primaryClusterMapping.receiptSha256);
  assert.equal(receipt.providerBindingSha256,
    options.approval.providerBindingSha256);
  assert.equal(receipt.sourceCommitTs,
    options.approval.expectedSourceCommitTs);
  assert.equal(receipt.sourceClusterIdSha256,
    sha256(options.approval.expectedSourceClusterId));
  assert.equal(receipt.sourceSqlClusterIdSha256,
    sha256(options.approval.expectedSourceSqlClusterId));
  assert.deepEqual(calls, ["initialize", "notification", "tools/call", "close"]);
  const serialized = canonicalJson(receipt);
  for (const forbidden of [
    API_KEY, "SELECT", "mcp-session-id", "checkpoint_summary",
    options.approval.recoverySessionId, options.approval.tenantId
  ]) {
    assert.equal(serialized.includes(forbidden), false);
  }
  validatePrivateRecoveryQueryReceipt(receipt);
});

test("transport evidence is bound to the exact endpoint cluster and protocol", () => {
  const { approval, command } = fixture();
  const query = command.querySha256;
  const logicalRequest = {
    recoveryClusterId: approval.recoveryClusterId
  };
  assert.throws(() => privateRecoveryTest.validateTransportEvidence({
    evidence: {
      semanticRequestEvidence: {},
      transportEvidence: {
        schemaVersion: "tideproof.managed-mcp-transport-evidence.v2",
        endpointAuthority: "cockroachlabs.cloud",
        endpointSha256: "0".repeat(64),
        clusterIdSha256: sha256(approval.recoveryClusterId),
        protocolVersion: "2025-03-26",
        redirectPolicy: "error",
        boundedResponseBytes: 256 * 1024,
        rpcCalls: [],
        notifications: [],
        close: null,
        sessionIdSha256: "1".repeat(64)
      }
    },
    logicalRequest,
    query
  }), /PRIVATE_RECOVERY_QUERY_TRANSPORT_EVIDENCE_REJECTED/u);
});

test("approval rejects provider and SQL cluster conflation or mapping drift", () => {
  const { approval } = fixture();
  assert.notEqual(approval.expectedSourceClusterId,
    approval.expectedSourceSqlClusterId);
  assert.throws(() => buildPrivateRecoveryQueryCommand({
    approval: {
      ...approval,
      expectedSourceSqlClusterId: approval.expectedSourceClusterId
    },
    codeZipSha256: "c".repeat(64),
    configSha256: "d".repeat(64),
    functionArn: FUNCTION_ARN,
    functionVersion: "7",
    mcpSecretArn: SECRET_ARN,
    mcpSecretVersionId: SECRET_VERSION,
    releaseControlTableArn: TABLE_ARN,
    now: NOW
  }), /PRIVATE_RECOVERY_QUERY_APPROVAL_REJECTED/u);
  assert.throws(() => buildPrivateRecoveryQueryCommand({
    approval: {
      ...approval,
      primaryClusterMapping: {
        ...approval.primaryClusterMapping,
        sqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3c"
      }
    },
    codeZipSha256: "c".repeat(64),
    configSha256: "d".repeat(64),
    functionArn: FUNCTION_ARN,
    functionVersion: "7",
    mcpSecretArn: SECRET_ARN,
    mcpSecretVersionId: SECRET_VERSION,
    releaseControlTableArn: TABLE_ARN,
    now: NOW
  }), /PRIVATE_RECOVERY_QUERY_CLUSTER_MAPPING_REJECTED/u);
});

test("completion timestamp and row freshness use a fresh post-close clock", async () => {
  const options = invocationOptions();
  const completedAt = new Date("2026-08-19T02:00:05.000Z");
  const observed = [NOW, completedAt];
  options.clock = () => observed.shift();
  options.createMcpClient = mcpClientFor(options.row, []);
  await reservePrivateRecoveryQuery({ command: options.command, store: options.store });
  const receipt = await runPrivateRecoveryQuery(options);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.completedAt, completedAt.toISOString());
  assert.equal(observed.length, 0);
});

test("provider-bound source commit timestamp rejects a different signed row", async () => {
  const original = fixture();
  const approval = {
    ...original.approval,
    expectedSourceCommitTs: "2026-08-19T01:58:00.000Z"
  };
  const command = buildPrivateRecoveryQueryCommand({
    approval,
    codeZipSha256: "c".repeat(64),
    configSha256: "d".repeat(64),
    functionArn: FUNCTION_ARN,
    functionVersion: "7",
    mcpSecretArn: SECRET_ARN,
    mcpSecretVersionId: SECRET_VERSION,
    releaseControlTableArn: TABLE_ARN,
    now: NOW
  });
  const options = invocationOptions({ approval, command, row: original.row });
  options.createMcpClient = mcpClientFor(original.row, []);
  await reservePrivateRecoveryQuery({ command, store: options.store });
  const receipt = await runPrivateRecoveryQuery(options);
  assert.equal(receipt.status, "UNKNOWN_DO_NOT_RETRY");
  assert.equal(receipt.providerCallPossible, true);
  assert.equal(receipt.errorCode,
    "PRIVATE_RECOVERY_QUERY_SIGNED_ROW_BINDING_REJECTED");
});

test("expired provider-bound approval fails before secret or provider dispatch", async () => {
  const options = invocationOptions();
  options.clock = () => new Date("2026-08-19T02:30:00.000Z");
  options.secretReader.readExactVersion = async () => {
    throw new Error("must not read an expired approval secret");
  };
  await reservePrivateRecoveryQuery({ command: options.command, store: options.store });
  const receipt = await runPrivateRecoveryQuery(options);
  assert.equal(receipt.status, "FAILED_NO_PROVIDER_CALL");
  assert.equal(receipt.providerCallPossible, false);
  assert.equal(options.store.calls.includes("dispatch"), false);
});

test("stored final receipt replays without another secret read or provider call", async () => {
  const calls = [];
  const options = invocationOptions();
  options.createMcpClient = mcpClientFor(options.row, calls);
  await reservePrivateRecoveryQuery({ command: options.command, store: options.store });
  const first = await runPrivateRecoveryQuery(options);
  options.secretReader.readExactVersion = async () => {
    throw new Error("must not read secret on replay");
  };
  const second = await runPrivateRecoveryQuery(options);
  assert.deepEqual(second, first);
  assert.equal(calls.filter((entry) => entry === "tools/call").length, 1);
});

test("tool acknowledgement loss becomes durable unknown and never retries", async () => {
  const calls = [];
  const options = invocationOptions();
  options.createMcpClient = mcpClientFor(options.row, calls, {
    failTools: true
  });
  await reservePrivateRecoveryQuery({ command: options.command, store: options.store });
  const first = await runPrivateRecoveryQuery(options);
  assert.equal(first.status, "UNKNOWN_DO_NOT_RETRY");
  assert.equal(first.providerCallPossible, true);
  const second = await runPrivateRecoveryQuery(options);
  assert.deepEqual(second, first);
  assert.equal(calls.filter((entry) => entry === "tools/call").length, 1);
});

test("hostile provider errors become fixed durable codes with no secret or identity leakage", async () => {
  const hostileRequestId = "deadbeef-dead-4eef-8ead-deadbeefdead";
  const hostileArn =
    `arn:aws:iam::${HOSTILE_ACCOUNT_ID}:role/hostile-provider-role`;
  const hostile = `${API_KEY} ${hostileArn} ${hostileRequestId}\nsecond-line`;
  const forbidden = [
    API_KEY,
    hostileArn,
    HOSTILE_ACCOUNT_ID,
    hostileRequestId,
    "second-line"
  ];

  const beforeDispatch = invocationOptions();
  await reservePrivateRecoveryQuery({
    command: beforeDispatch.command,
    store: beforeDispatch.store
  });
  beforeDispatch.store.read = async () => {
    throw new Error(hostile);
  };
  const failed = await runPrivateRecoveryQuery(beforeDispatch);
  assert.equal(failed.status, "FAILED_NO_PROVIDER_CALL");
  assert.equal(failed.errorCode, "PRIVATE_RECOVERY_QUERY_EXECUTION_FAILED");
  const failedText = canonicalJson(failed);
  assert.equal(failedText.includes("\n"), false);
  for (const value of forbidden) assert.equal(failedText.includes(value), false);

  const calls = [];
  const afterDispatch = invocationOptions();
  afterDispatch.createMcpClient = mcpClientFor(afterDispatch.row, calls, {
    failTools: true,
    failureMessage: hostile
  });
  await reservePrivateRecoveryQuery({
    command: afterDispatch.command,
    store: afterDispatch.store
  });
  const unknown = await runPrivateRecoveryQuery(afterDispatch);
  assert.equal(unknown.status, "UNKNOWN_DO_NOT_RETRY");
  assert.equal(unknown.errorCode, "PRIVATE_RECOVERY_QUERY_EXECUTION_FAILED");
  const unknownText = canonicalJson(unknown);
  assert.equal(unknownText.includes("\n"), false);
  for (const value of forbidden) assert.equal(unknownText.includes(value), false);
  assert.deepEqual(await runPrivateRecoveryQuery(afterDispatch), unknown);
  assert.equal(calls.filter((entry) => entry === "tools/call").length, 1);
});

test("top-level Lambda boundary emits only one fixed response code and no log", async () => {
  const hostile = `${API_KEY} arn:aws:iam::${HOSTILE_ACCOUNT_ID}:role/hostile ` +
    "deadbeef-dead-4eef-8ead-deadbeefdead\nsecond-line";
  const observedLogs = [];
  const originalError = console.error;
  console.error = (...values) => observedLogs.push(values.join(" "));
  try {
    const wrapped = lambdaTest.withTopLevelFailureBoundary(async () => {
      throw new Error(hostile);
    });
    await assert.rejects(wrapped(), (error) => {
      assert.equal(error.message, "PRIVATE_RECOVERY_QUERY_LAMBDA_HOLD");
      assert.equal(error.cause, undefined);
      assert.equal(String(error).includes(hostile), false);
      return true;
    });
  } finally {
    console.error = originalError;
  }
  assert.deepEqual(observedLogs, []);
  assert.equal(privateRecoveryTest.errorCodeFor(new Error(hostile)),
    "PRIVATE_RECOVERY_QUERY_EXECUTION_FAILED");
  assert.equal(privateRecoveryTest.errorCodeFor(Object.defineProperty({},
    "message", { get() { throw new Error(hostile); } })),
  "PRIVATE_RECOVERY_QUERY_EXECUTION_FAILED");
  assert.equal(privateRecoveryTest.errorCodeFor(new Error(
    "PRIVATE_RECOVERY_QUERY_CLOCK_REJECTED"
  )), "PRIVATE_RECOVERY_QUERY_CLOCK_REJECTED");
});

test("secret drift fails before any provider dispatch", async () => {
  const options = invocationOptions();
  options.secretReader.readExactVersion = async () => ({
    secretArnSha256: sha256(SECRET_ARN),
    secretValue: canonicalJson({ apiKey: `${API_KEY}-drift` }),
    secretValueSha256: sha256(canonicalJson({ apiKey: `${API_KEY}-drift` })),
    secretVersionIdSha256: sha256(SECRET_VERSION)
  });
  await reservePrivateRecoveryQuery({ command: options.command, store: options.store });
  const receipt = await runPrivateRecoveryQuery(options);
  assert.equal(receipt.status, "FAILED_NO_PROVIDER_CALL");
  assert.equal(receipt.providerCallPossible, false);
  assert.equal(options.store.calls.includes("dispatch"), false);
});

test("dispatch-store contract drift fails before creating an MCP client", async () => {
  const options = invocationOptions();
  let clientCreated = false;
  options.createMcpClient = () => {
    clientCreated = true;
    throw new Error("must not create client");
  };
  await reservePrivateRecoveryQuery({ command: options.command, store: options.store });
  options.store.markDispatch = async () => ({
    status: "RESERVED",
    commandSha256: options.command.commandSha256,
    operationId: options.command.operationId,
    version: 0
  });
  const receipt = await runPrivateRecoveryQuery(options);
  assert.equal(receipt.status, "FAILED_NO_PROVIDER_CALL");
  assert.equal(receipt.errorCode,
    "PRIVATE_RECOVERY_QUERY_DISPATCH_STATE_REJECTED");
  assert.equal(clientCreated, false);
});

test("operator reserves before invoke and independently reads stored final", async () => {
  const { approval, command, row } = fixture();
  const store = memoryStore();
  let invoked = 0;
  const invoker = {
    async invokeExactVersion() {
      invoked += 1;
      const options = invocationOptions({ approval, command, row, store });
      options.createMcpClient = mcpClientFor(row, []);
      return runPrivateRecoveryQuery(options);
    }
  };
  const receipt = await executePrivateRecoveryQueryOnce({
    approval,
    command,
    invoker,
    store
  });
  assert.equal(receipt.status, "PASS", canonicalJson(receipt));
  assert.equal(invoked, 1);
  assert.equal(store.calls[0], "reserve");
  assert.equal((await reconcilePrivateRecoveryQuery({ command, store })).status,
    "PASS");
});

test("operator never retries an invocation acknowledgement loss", async () => {
  const { approval, command } = fixture();
  const store = memoryStore();
  let invoked = 0;
  const result = await executePrivateRecoveryQueryOnce({
    approval,
    command,
    invoker: {
      async invokeExactVersion() {
        invoked += 1;
        throw new Error("synthetic invoke acknowledgement loss");
      }
    },
    store
  });
  assert.equal(result.status, "INVOCATION_ACK_UNKNOWN_WAIT");
  assert.equal(result.providerRetryAuthorized, false);
  assert.equal(invoked, 1);
});
