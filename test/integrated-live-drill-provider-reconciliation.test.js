import assert from "node:assert/strict";
import test from "node:test";

import {
  integratedLiveDrillProviderReconciliationEnvironment,
  reconcileIntegratedLiveDrillProviderDispatchControl,
  validateIntegratedLiveDrillProviderReconciliationReceipt,
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
  runIntegratedLiveDrillProviderReconciliation
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
import {
  PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
  PROVIDER_DISPATCH_CONTROL_STATES,
  providerDispatchSha256
} from "../src/cloud/provider-dispatch-binding.js";
import {
  buildProviderDispatchReconciliationInput,
  providerDispatchReconciliationInputBytes,
  validateProviderDispatchReconciliationInput
} from "../src/cloud/provider-dispatch-reconciliation-input.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";

const AUTHORIZATION_ID = "11111111-1111-4111-8111-111111111111";
const RUN_ID = "22222222-2222-4222-8222-222222222222";
const GRANT_ID = "33333333-3333-4333-8333-333333333333";
const WORKER_SPEC = "e".repeat(64);

function binding() {
  const body = Object.freeze({
    authorizationId: AUTHORIZATION_ID,
    expiresAt: "2026-08-12T17:00:00.000Z",
    interactionId: "44444444-4444-4444-8444-444444444444",
    issuedAt: "2026-08-12T16:00:00.000Z",
    logicalMcpRequestSha256: "a".repeat(64),
    providerDispatchAuthorizationSha256: "b".repeat(64),
    providerEffectKeySha256: "c".repeat(64),
    runId: RUN_ID,
    schemaVersion: PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
    sourceBuildIdentity: "d".repeat(64),
    sourceCommit: "e".repeat(40),
    tenantId: "55555555-5555-4555-8555-555555555555",
    treeDigest: "f".repeat(40)
  });
  return Object.freeze({
    ...body,
    controlBindingSha256: providerDispatchSha256(canonicalJson(body))
  });
}

function input() {
  return buildProviderDispatchReconciliationInput({
    binding: binding(),
    grantId: GRANT_ID,
    packageLockDigest: "9".repeat(64),
    workerSpecSha256: WORKER_SPEC
  });
}

function receipt(state = PROVIDER_DISPATCH_CONTROL_STATES.GRANTED) {
  const completed = state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED;
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
    accepted: false,
    authorizationId: AUTHORIZATION_ID,
    controlBindingSha256: binding().controlBindingSha256,
    databaseNow: "2026-08-12T12:00:00.000Z",
    finalReleaseReady: false,
    mcpResultSha256: completed ? "6".repeat(64) : null,
    providerApiCredentialPresent: false,
    providerBacked: false,
    runId: RUN_ID,
    sessionCloseSha256: completed ? "7".repeat(64) : null,
    state,
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: state === PROVIDER_DISPATCH_CONTROL_STATES.ABSENT
      ? "RESOLVED_ABSENT"
      : "RESOLVED"
  });
  return Object.freeze({
    ...body,
    receiptSha256: providerDispatchSha256(canonicalJson(body))
  });
}

test("reconciliation environment carries only resolve authority", () => {
  const environment = integratedLiveDrillProviderReconciliationEnvironment({
    LANG: "C",
    MCP_API_KEY: "must-not-cross-boundary",
    PRIMARY_PROVIDER_RECONCILE_DATABASE_URL:
      "postgresql://reconcile.invalid/tideproof?sslmode=verify-full"
  });
  assert.equal(environment.LANG, "C");
  assert.match(environment.PRIMARY_PROVIDER_RECONCILE_DATABASE_URL, /reconcile/u);
  assert.equal("MCP_API_KEY" in environment, false);
});

test("sanitized reconciliation input is canonical, digest-bound, and secret-free", () => {
  const value = input();
  assert.deepEqual(validateProviderDispatchReconciliationInput(value), value);
  assert.equal(
    providerDispatchReconciliationInputBytes(value).toString("utf8"),
    `${canonicalJson(value)}\n`
  );
  for (const forbidden of [
    "context",
    "executionCapability",
    "executionCapabilitySha256",
    "operationNonce",
    "operationNonceSha256",
    "completionCapability",
    "rawResult",
    "providerCompletion"
  ]) {
    assert.equal(canonicalJson(value).includes(forbidden), false, forbidden);
  }
  for (const mutate of [
    (candidate) => { candidate.packageLockDigest = "8".repeat(64); },
    (candidate) => { candidate.admission.grantId = RUN_ID; },
    (candidate) => { candidate.context = { rawResult: "forbidden" }; }
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    assert.throws(
      () => validateProviderDispatchReconciliationInput(changed),
      /INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED/u
    );
  }
});

test("reconciliation receipt accepts every canonical resolver state", () => {
  for (const state of Object.values(PROVIDER_DISPATCH_CONTROL_STATES)) {
    const value = receipt(state);
    assert.deepEqual(
      validateIntegratedLiveDrillProviderReconciliationReceipt(value, {
        authorizationId: AUTHORIZATION_ID,
        runId: RUN_ID
      }),
      value,
      state
    );
  }
  const changed = structuredClone(receipt());
  changed.providerApiCredentialPresent = true;
  changed.receiptSha256 = providerDispatchSha256(canonicalJson(
    Object.fromEntries(Object.entries(changed).filter(([key]) =>
      key !== "receiptSha256"
    ))
  ));
  assert.throws(
    () => validateIntegratedLiveDrillProviderReconciliationReceipt(changed, {
      authorizationId: AUTHORIZATION_ID,
      runId: RUN_ID
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTPUT_REJECTED/u
  );
  for (const mutate of [
    (candidate) => { candidate.mcpResultSha256 = "1".repeat(64); },
    (candidate) => {
      candidate.state = "COMPLETED";
      candidate.transitionOutcome = "RESOLVED";
    },
    (candidate) => { candidate.transitionOutcome = "RESOLVED_ABSENT"; }
  ]) {
    const impossible = structuredClone(receipt());
    mutate(impossible);
    const { receiptSha256: _ignored, ...body } = impossible;
    impossible.receiptSha256 = providerDispatchSha256(canonicalJson(body));
    assert.throws(
      () => validateIntegratedLiveDrillProviderReconciliationReceipt(
        impossible,
        { authorizationId: AUTHORIZATION_ID, runId: RUN_ID }
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTPUT_REJECTED/u
    );
  }
});

test("audit-only reconciliation exposes no mutation surface", async () => {
  const calls = [];
  const resolved = Object.freeze({ state: "GRANTED" });
  const actual = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding: binding(),
    resolver: {
      async resolve(actualBinding) {
        calls.push(actualBinding);
        return resolved;
      }
    }
  });
  assert.equal(actual, resolved);
  assert.deepEqual(calls, [binding()]);
});

test("run reconciliation reports only database-observed state and digests", async () => {
  const value = input();
  const databaseRows = [{
    authorization_id: AUTHORIZATION_ID,
    control_binding_sha256: value.binding.controlBindingSha256,
    database_now: "2026-08-12T16:30:00.000Z",
    expires_at: value.binding.expiresAt,
    grant_id: GRANT_ID,
    mcp_result_sha256: "6".repeat(64),
    session_close_sha256: "7".repeat(64),
    state: "COMPLETED",
    transition_outcome: "RESOLVED",
    worker_spec_sha256: WORKER_SPEC
  }];
  const clientFactory = () => ({
    async connect() {},
    async end() {},
    async query() { return { rowCount: 1, rows: databaseRows }; }
  });
  const result = await runIntegratedLiveDrillProviderReconciliation({
    auditClientFactory: clientFactory,
    environment: Object.freeze({
      PRIMARY_PROVIDER_RECONCILE_DATABASE_URL:
        "postgresql://reconcile.invalid/tideproof?sslmode=verify-full"
    }),
    input: value
  });
  assert.equal(result.state, "COMPLETED");
  assert.equal(result.mcpResultSha256, "6".repeat(64));
  assert.equal(result.sessionCloseSha256, "7".repeat(64));
  assert.equal("providerCompletion" in result, false);
  assert.equal(result.providerBacked, false);
});
