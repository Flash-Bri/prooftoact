import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { BrokeredProviderOperationClient } from
  "../src/cloud/brokered-provider-operation-client.js";
import {
  __test as operationTest,
  runIntegratedLiveDrillProviderOperationBroker,
  serveIntegratedLiveDrillProviderOperationBroker
} from "../src/cloud/integrated-live-drill-provider-operation-broker.js";
import {
  INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA
} from "../src/cloud/integrated-live-drill-dispatch-broker.js";
import {
  PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA
} from "../src/cloud/provider-dispatch-binding.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import { managedMcpLogicalRequest } from
  "../src/cloud/managed-mcp-client.js";
import { renderRecoveryQuery } from "../src/cloud/recovery-store.js";

const GRANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const EXECUTION_CAPABILITY = "a".repeat(64);
const OPERATION_NONCE = operationTest.derive(
  EXECUTION_CAPABILITY,
  GRANT_ID,
  "tideproof-provider-operation-nonce-v1"
);
const CLUSTER_ID = "55555555-5555-4555-8555-555555555555";
const QUERY = renderRecoveryQuery({
  recoverySessionId: "66666666-6666-4666-8666-666666666666",
  sourceDigest: "7".repeat(64),
  subjectBindingHash: "8".repeat(64),
  tenantId: "44444444-4444-4444-8444-444444444444"
});

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function binding() {
  const body = Object.freeze({
    authorizationId: "11111111-1111-4111-8111-111111111111",
    expiresAt: "2026-08-12T18:00:00.000Z",
    interactionId: "22222222-2222-4222-8222-222222222222",
    issuedAt: "2026-08-12T16:00:00.000Z",
    logicalMcpRequestSha256: sha256(canonicalJson(managedMcpLogicalRequest({
      clusterId: CLUSTER_ID,
      query: QUERY
    }))),
    providerDispatchAuthorizationSha256: "b".repeat(64),
    providerEffectKeySha256: "c".repeat(64),
    runId: "33333333-3333-4333-8333-333333333333",
    schemaVersion: PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
    sourceBuildIdentity: "d".repeat(64),
    sourceCommit: "e".repeat(40),
    tenantId: "44444444-4444-4444-8444-444444444444",
    treeDigest: "f".repeat(40)
  });
  return Object.freeze({
    ...body,
    controlBindingSha256: sha256(canonicalJson(body))
  });
}

function executionGrant(control) {
  const body = Object.freeze({
    authorizationId: control.authorizationId,
    controlBindingSha256: control.controlBindingSha256,
    executionCapabilitySha256: sha256(EXECUTION_CAPABILITY),
    grantId: GRANT_ID,
    operationNonceSha256: sha256(OPERATION_NONCE),
    requestSha256: "1".repeat(64),
    schemaVersion: INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA,
    state: "EXECUTING",
    workerSpecSha256: "2".repeat(64)
  });
  return Object.freeze({
    ...body,
    receiptSha256: sha256(canonicalJson(body))
  });
}

function response(id, result, sessionId = null) {
  const headers = new Headers({ "content-type": "application/json" });
  if (sessionId !== null) headers.set("mcp-session-id", sessionId);
  return new Response(JSON.stringify({ id, jsonrpc: "2.0", result }), {
    headers,
    status: 200
  });
}

function fakeProvider(counter) {
  const sessionId = "provider-operation-session";
  return async (_url, options) => {
    counter.calls += 1;
    if (options.method === "DELETE") {
      return new Response("", {
        headers: { "mcp-session-id": sessionId },
        status: 204
      });
    }
    const body = JSON.parse(options.body);
    if (body.method === "initialize") {
      return response(body.id, { protocolVersion: "2025-03-26" }, sessionId);
    }
    if (body.method === "notifications/initialized") {
      return new Response("", {
        headers: { "mcp-session-id": sessionId },
        status: 202
      });
    }
    return response(body.id, {
      content: [{ text: "synthetic exact result", type: "text" }],
      isError: false,
      structuredContent: {
        columns: ["source_commit_ts"],
        rows: [{ source_commit_ts: "2026-08-12T15:59:00.000Z" }]
      }
    }, sessionId);
  };
}

async function listen(server, socketPath) {
  if (server.listening) return;
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.once("listening", resolve);
  });
  assert.equal(fs.existsSync(socketPath), true);
}

async function close(server) {
  await new Promise((resolve) => server.close(resolve));
}

test("concurrent socket clients cause one redemption and one provider sequence", async (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-provider-operation-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const socketPath = path.join(temporaryRoot, "provider.sock");
  const control = binding();
  const grant = executionGrant(control);
  const counter = { calls: 0, redemptions: 0 };
  let state = "EXECUTING";
  const redeemControl = Object.freeze({
    async redeem(_binding, input) {
      counter.redemptions += 1;
      if (state === "EXECUTING") {
        state = "CREDENTIAL_REDEEMED";
        return {
          grantId: GRANT_ID,
          state,
          transitionOutcome: "CREDENTIAL_REDEEMED",
          workerSpecSha256: grant.workerSpecSha256
        };
      }
      return {
        grantId: GRANT_ID,
        state,
        transitionOutcome: "ALREADY_REDEEMED_DO_NOT_DELIVER",
        workerSpecSha256: grant.workerSpecSha256
      };
    }
  });
  const finalizeControl = Object.freeze({
    async complete(_binding, _completionGrant, terminal) {
      state = "COMPLETED";
      return {
        grantId: GRANT_ID,
        state,
        transitionOutcome: "COMPLETED",
        ...terminal
      };
    },
    async markUnknown() {
      state = "UNKNOWN_DO_NOT_ACT";
      return { grantId: GRANT_ID, state, transitionOutcome: "UNKNOWN_RECORDED" };
    }
  });
  const operation = (request) => runIntegratedLiveDrillProviderOperationBroker({
    apiKey: "synthetic-provider-key-value-0001",
    executionCapability: EXECUTION_CAPABILITY,
    fetchImpl: fakeProvider(counter),
    finalizeControl,
    grantId: GRANT_ID,
    request,
    rootPath: temporaryRoot,
    redeemControl
  });
  const server = serveIntegratedLiveDrillProviderOperationBroker({
    listen: { path: socketPath },
    operation
  });
  await listen(server, socketPath);
  const clients = [0, 1, 2, 3].map(() => new BrokeredProviderOperationClient({
    binding: control,
    clusterId: CLUSTER_ID,
    executionGrant: grant,
    operationNonce: OPERATION_NONCE,
    socketPath
  }));
  const results = await Promise.all(clients.map((client) => client.selectQuery({
    clusterId: CLUSTER_ID,
    database: "tideproof_recovery",
    query: QUERY
  })));
  assert.equal(new Set(results.map(canonicalJson)).size, 1);
  assert.equal(counter.redemptions, 1);
  assert.equal(counter.calls, 4);
  assert.equal(state, "CREDENTIAL_REDEEMED");
  await close(server);

  const restartedServer = serveIntegratedLiveDrillProviderOperationBroker({
    listen: { path: socketPath },
    operation
  });
  await listen(restartedServer, socketPath);
  const restarted = await clients[0].selectQuery({
    clusterId: CLUSTER_ID,
    database: "tideproof_recovery",
    query: QUERY
  });
  assert.equal(canonicalJson(restarted), canonicalJson(results[0]));
  assert.equal(counter.redemptions, 1);
  assert.equal(counter.calls, 4);
  await close(restartedServer);
});

test("restart after credential redemption without a transcript marks unknown and never calls provider", async (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-provider-redeemed-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const socketPath = path.join(temporaryRoot, "provider.sock");
  const control = binding();
  const grant = executionGrant(control);
  const counter = { calls: 0, redemptions: 0, unknowns: 0 };
  let state = "CREDENTIAL_REDEEMED";
  const redeemControl = Object.freeze({
    async redeem() {
      counter.redemptions += 1;
      return {
        grantId: GRANT_ID,
        state,
        transitionOutcome: "ALREADY_REDEEMED_DO_NOT_DELIVER",
        workerSpecSha256: grant.workerSpecSha256
      };
    }
  });
  const finalizeControl = Object.freeze({
    async complete() {
      throw new Error("completion must not run without a transcript");
    },
    async markUnknown() {
      counter.unknowns += 1;
      state = "UNKNOWN_DO_NOT_ACT";
      return { grantId: GRANT_ID, state, transitionOutcome: "UNKNOWN_RECORDED" };
    }
  });
  const operation = (request) => runIntegratedLiveDrillProviderOperationBroker({
    apiKey: "synthetic-provider-key-value-0001",
    executionCapability: EXECUTION_CAPABILITY,
    fetchImpl: fakeProvider(counter),
    finalizeControl,
    grantId: GRANT_ID,
    request,
    rootPath: temporaryRoot,
    redeemControl
  });
  const server = serveIntegratedLiveDrillProviderOperationBroker({
    listen: { path: socketPath },
    operation
  });
  await listen(server, socketPath);
  const client = new BrokeredProviderOperationClient({
    binding: control,
    clusterId: CLUSTER_ID,
    executionGrant: grant,
    operationNonce: OPERATION_NONCE,
    socketPath
  });
  await assert.rejects(
    () => client.selectQuery({
      clusterId: CLUSTER_ID,
      database: "tideproof_recovery",
      query: QUERY
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_ALREADY_REDEEMED/u
  );
  assert.equal(counter.redemptions, 1);
  assert.equal(counter.unknowns, 1);
  assert.equal(counter.calls, 0);
  assert.equal(state, "UNKNOWN_DO_NOT_ACT");
  assert.equal(
    fs.existsSync(path.join(temporaryRoot, operationTest.TRANSCRIPT_NAME)),
    false
  );
  await close(server);
});
