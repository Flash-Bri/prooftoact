import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  buildIntegratedLiveDrillProviderResult,
  buildIntegratedLiveDrillProviderReady,
  INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RECEIPT_SCHEMA,
  INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_SCHEMA,
  INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_SCHEMA
} from "../src/cloud/integrated-live-drill-provider-activation.js";
import {
  __test as brokerTest,
  createIntegratedLiveDrillProviderActivationCoordinator,
  runIntegratedLiveDrillProviderOperationBroker
} from "../src/cloud/integrated-live-drill-provider-operation-broker.js";
import {
  __test as exchangeTest,
  runIntegratedLiveDrillProviderExchange
} from "../src/cloud/integrated-live-drill-provider-exchange.js";
import {
  PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA
} from "../src/cloud/provider-dispatch-binding.js";
import { managedMcpLogicalRequest } from "../src/cloud/managed-mcp-client.js";
import { renderRecoveryQuery } from "../src/cloud/recovery-store.js";

const GRANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const CAPABILITY = "a".repeat(64);
const CLUSTER_ID = "55555555-5555-4555-8555-555555555555";
const QUERY = renderRecoveryQuery({
  recoverySessionId: "66666666-6666-4666-8666-666666666666",
  sourceDigest: "7".repeat(64),
  subjectBindingHash: "8".repeat(64),
  tenantId: "44444444-4444-4444-8444-444444444444"
});
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function binding() {
  const body = {
    authorizationId: "11111111-1111-4111-8111-111111111111",
    expiresAt: "2026-08-12T18:00:00.000Z",
    interactionId: "22222222-2222-4222-8222-222222222222",
    issuedAt: "2026-08-12T16:00:00.000Z",
    logicalMcpRequestSha256: sha256(canonicalJson(managedMcpLogicalRequest({
      clusterId: CLUSTER_ID, query: QUERY
    }))),
    providerDispatchAuthorizationSha256: "b".repeat(64),
    providerEffectKeySha256: "c".repeat(64),
    runId: "33333333-3333-4333-8333-333333333333",
    schemaVersion: PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
    sourceBuildIdentity: "d".repeat(64), sourceCommit: "e".repeat(40),
    tenantId: "44444444-4444-4444-8444-444444444444",
    treeDigest: "f".repeat(40)
  };
  return Object.freeze({ ...body, controlBindingSha256: sha256(canonicalJson(body)) });
}

function grant(control) {
  const nonce = brokerTest.derive(CAPABILITY, GRANT_ID,
    "tideproof-provider-operation-nonce-v1");
  const body = {
    authorizationId: control.authorizationId,
    controlBindingSha256: control.controlBindingSha256,
    executionCapabilitySha256: sha256(CAPABILITY), grantId: GRANT_ID,
    operationNonceSha256: sha256(nonce), requestSha256: "1".repeat(64),
    schemaVersion: "tideproof.integrated-live-drill-execution-grant.v1",
    state: "EXECUTING", workerSpecSha256: "2".repeat(64)
  };
  return { nonce, value: Object.freeze({ ...body, receiptSha256: sha256(canonicalJson(body)) }) };
}

function envelope(control) {
  const execution = grant(control);
  return Object.freeze({
    packageLockDigest: "9".repeat(64),
    request: Object.freeze({
      action: "EXECUTE", binding: control, executionGrant: execution.value,
      operationNonce: execution.nonce,
      payload: Object.freeze({ clusterId: CLUSTER_ID, database: "tideproof_recovery", query: QUERY }),
      schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_SCHEMA
    }),
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_SCHEMA
  });
}

function activationReceipt(input) {
  const body = {
    activatedAt: "2026-08-12T17:00:00.000Z",
    activationDisposition: "DELIVER_CREDENTIAL_ONCE",
    activationRequestSha256: sha256(canonicalJson(input)),
    authorizationId: input.request.binding.authorizationId,
    controlBindingSha256: input.request.binding.controlBindingSha256,
    databaseNow: "2026-08-12T17:00:00.000Z",
    expiresAt: input.request.binding.expiresAt, grantId: GRANT_ID,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RECEIPT_SCHEMA,
    state: "CREDENTIAL_REDEEMED", transitionOutcome: "ACTIVATION_GRANTED",
    workerSpecSha256: input.request.executionGrant.workerSpecSha256
  };
  return Object.freeze({ ...body, receiptSha256: sha256(canonicalJson(body)) });
}

const resultBody = Object.freeze({ rawResult: { ok: true },
  semanticRequestEvidence: { exact: true }, transportEvidence: { close: { ok: true } } });

test("READY before activation ACK blocks and then exactly one result resolves", async () => {
  const input = envelope(binding());
  const receipt = activationReceipt(input);
  let acknowledge;
  const coordinator = createIntegratedLiveDrillProviderActivationCoordinator({
    activationRpc: () => new Promise((resolve) => { acknowledge = resolve; }),
    activationTimeoutMilliseconds: 1000, timeoutMilliseconds: 1000
  });
  const operation = coordinator.activateExchange(input);
  const ready = coordinator.providerReady(buildIntegratedLiveDrillProviderReady(receipt));
  let proceeded = false;
  void ready.then(() => { proceeded = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(proceeded, false);
  acknowledge({ activationReceipt: receipt });
  assert.equal((await ready).disposition, "PROCEED_ONCE");
  const result = buildIntegratedLiveDrillProviderResult({ activationReceipt: receipt, result: resultBody });
  assert.deepEqual(await coordinator.providerResult(result), { accepted: true });
  assert.deepEqual((await operation).result, resultBody);
  await assert.rejects(() => coordinator.providerReady(buildIntegratedLiveDrillProviderReady(receipt)),
    /READY_UNSOLICITED/u);
});

test("result timeout removes pending state and refuses every late result", async () => {
  const input = envelope(binding());
  const receipt = activationReceipt(input);
  const coordinator = createIntegratedLiveDrillProviderActivationCoordinator({
    activationRpc: async () => ({ activationReceipt: receipt }),
    activationTimeoutMilliseconds: 100, timeoutMilliseconds: 5
  });
  const operation = coordinator.activateExchange(input);
  await coordinator.providerReady(buildIntegratedLiveDrillProviderReady(receipt));
  await assert.rejects(operation, /RESULT_TIMEOUT_DO_NOT_RETRY/u);
  const result = buildIntegratedLiveDrillProviderResult({ activationReceipt: receipt, result: resultBody });
  await assert.rejects(() => coordinator.providerResult(result), /RESULT_UNSOLICITED/u);
  const replay = coordinator.activateExchange(input);
  await coordinator.providerReady(buildIntegratedLiveDrillProviderReady(receipt));
  await coordinator.providerResult(result);
  assert.deepEqual((await replay).result, resultBody);
});

test("already redeemed duplicate never terminalizes beneath an activation receipt", async (t) => {
  const rootPath = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "pta-operation-"));
  fs.chmodSync(rootPath, 0o700);
  t.after(() => fs.rmSync(rootPath, { recursive: true, force: true }));
  const input = envelope(binding());
  let unknowns = 0;
  await assert.rejects(() => runIntegratedLiveDrillProviderOperationBroker({
    activateExchange: async () => { throw new Error("must not activate"); },
    executionCapability: CAPABILITY,
    finalizeControl: { async complete() {}, async markUnknown() { unknowns += 1; } },
    grantId: GRANT_ID, packageLockDigest: input.packageLockDigest,
    request: input.request, rootPath,
    redeemControl: { async redeem() { return { grantId: GRANT_ID,
      state: "CREDENTIAL_REDEEMED", transitionOutcome: "ALREADY_REDEEMED_DO_NOT_DELIVER",
      workerSpecSha256: input.request.executionGrant.workerSpecSha256 }; } }
  }), /ALREADY_REDEEMED/u);
  assert.equal(unknowns, 0);
});

function response(id, result, sessionId = null) {
  const headers = new Headers({ "content-type": "application/json" });
  if (sessionId !== null) headers.set("mcp-session-id", sessionId);
  return new Response(JSON.stringify({ id, jsonrpc: "2.0", result }), {
    headers, status: 200
  });
}

function fakeProvider(counter) {
  const sessionId = "isolated-provider-session";
  return async (_url, options) => {
    counter.calls += 1;
    if (options.method === "DELETE") {
      return new Response("", { headers: { "mcp-session-id": sessionId }, status: 204 });
    }
    const body = JSON.parse(options.body);
    if (body.method === "initialize") {
      return response(body.id, { protocolVersion: "2025-03-26" }, sessionId);
    }
    if (body.method === "notifications/initialized") {
      return new Response("", { headers: { "mcp-session-id": sessionId }, status: 202 });
    }
    return response(body.id, { content: [{ text: "exact", type: "text" }],
      isError: false, structuredContent: { columns: ["source_commit_ts"],
        rows: [{ source_commit_ts: "2026-08-12T16:59:00.000Z" }] } }, sessionId);
  };
}

function exchangeInput(input, receipt) {
  return Object.freeze({
    activationReceipt: receipt,
    providerRequest: Object.freeze({
      binding: input.request.binding, grantId: GRANT_ID,
      packageLockDigest: input.packageLockDigest,
      payload: input.request.payload,
      schemaVersion: "tideproof.provider-exchange-request.v1",
      workerSpecSha256: input.request.executionGrant.workerSpecSha256
    }),
    schemaVersion: "tideproof.provider-exchange-input.v1"
  });
}

test("PROCEED delayed past activation age creates no fence and makes no provider call", async (t) => {
  const input = envelope(binding());
  const receipt = activationReceipt(input);
  const rootPath = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "pta-exchange-expired-"));
  fs.chmodSync(rootPath, 0o700);
  t.after(() => fs.rmSync(rootPath, { recursive: true, force: true }));
  const times = [Date.parse(receipt.activatedAt) + 1, Date.parse(receipt.activatedAt) + 30_001];
  const counter = { calls: 0 };
  await assert.rejects(() => runIntegratedLiveDrillProviderExchange({
    apiKey: "synthetic-provider-key-value-0001",
    exchangeInput: exchangeInput(input, receipt), fetchImpl: fakeProvider(counter),
    now: () => times.shift(), proceed: async () => ({
      activationReceiptSha256: receipt.receiptSha256, disposition: "PROCEED_ONCE"
    }), rootPath
  }), /ACTIVATION_EXPIRED/u);
  assert.equal(counter.calls, 0);
  assert.equal(fs.existsSync(path.join(rootPath, exchangeTest.CONSUMPTION_FENCE)), false);
});

test("exchange durably publishes one result and create-only fence blocks restart", async (t) => {
  const input = envelope(binding());
  const receipt = activationReceipt(input);
  const rootPath = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "pta-exchange-once-"));
  fs.chmodSync(rootPath, 0o700);
  t.after(() => fs.rmSync(rootPath, { recursive: true, force: true }));
  const counter = { calls: 0 };
  const options = {
    apiKey: "synthetic-provider-key-value-0001",
    exchangeInput: exchangeInput(input, receipt), fetchImpl: fakeProvider(counter),
    now: () => Date.parse(receipt.activatedAt) + 1,
    proceed: async () => ({ activationReceiptSha256: receipt.receiptSha256,
      disposition: "PROCEED_ONCE" }), rootPath
  };
  await runIntegratedLiveDrillProviderExchange(options);
  assert.equal(fs.existsSync(path.join(rootPath, exchangeTest.RESULT_NAME)), true);
  const calls = counter.calls;
  await assert.rejects(() => runIntegratedLiveDrillProviderExchange(options),
    /ALREADY_CONSUMED/u);
  assert.equal(counter.calls, calls);
});
