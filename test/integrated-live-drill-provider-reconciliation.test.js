import assert from "node:assert/strict";
import test from "node:test";

import {
  integratedLiveDrillProviderReconciliationEnvironment,
  reconcileIntegratedLiveDrillProviderDispatchControl,
  validateIntegratedLiveDrillProviderReconciliationReceipt,
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
  runIntegratedLiveDrillProviderReconciliation
} from "../src/cloud/integrated-live-drill-provider-reconciliation.js";
import { integratedLiveDrillCanonicalSha256 } from
  "../src/cloud/integrated-live-drill-authorization.js";

const AUTHORIZATION_ID = "11111111-1111-4111-8111-111111111111";
const RUN_ID = "22222222-2222-4222-8222-222222222222";

function receipt() {
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
    accepted: false,
    authorizationId: AUTHORIZATION_ID,
    controlBindingSha256: "a".repeat(64),
    databaseNow: "2026-08-12T12:00:00.000Z",
    finalReleaseReady: false,
    mcpResultSha256: null,
    providerCompletion: null,
    providerApiCredentialPresent: false,
    providerBacked: false,
    runId: RUN_ID,
    sessionCloseSha256: null,
    state: "CONSUMED",
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: "RESOLVED"
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

test("reconciliation environment carries database authority without provider API authority", () => {
  const environment = integratedLiveDrillProviderReconciliationEnvironment({
    LANG: "C",
    MCP_API_KEY: "must-not-cross-boundary",
    PRIMARY_AUDIT_DATABASE_URL: "postgresql://audit.invalid/tideproof"
  }, {
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: "{}"
  });
  assert.equal(environment.LANG, "C");
  assert.deepEqual(
    environment.PRIMARY_AUDIT_DATABASE_URL,
    "postgresql://audit.invalid/tideproof"
  );
  assert.equal("MCP_API_KEY" in environment, false);
});

test("reconciliation receipt is exact, non-accepting, and capability-reduced", () => {
  const value = receipt();
  assert.deepEqual(
    validateIntegratedLiveDrillProviderReconciliationReceipt(value, {
      authorizationId: AUTHORIZATION_ID,
      runId: RUN_ID
    }),
    value
  );
  for (const mutate of [
    (candidate) => { candidate.providerApiCredentialPresent = true; },
    (candidate) => { candidate.accepted = true; },
    (candidate) => { candidate.state = "DISPATCH_GRANTED"; },
    (candidate) => { candidate.unbound = true; }
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    if (!Object.hasOwn(changed, "unbound")) {
      delete changed.receiptSha256;
      changed.receiptSha256 = integratedLiveDrillCanonicalSha256(changed);
    }
    assert.throws(
      () => validateIntegratedLiveDrillProviderReconciliationReceipt(
        changed,
        { authorizationId: AUTHORIZATION_ID, runId: RUN_ID }
      ),
      /INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTPUT_REJECTED/u
    );
  }
});

test("audit-only reconciliation observes but never consumes an undispatched authorization", async () => {
  const calls = [];
  const resolved = Object.freeze({
    mcpResultSha256: null,
    sessionCloseSha256: null,
    state: "CONSUMED"
  });
  const actual = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding: Object.freeze({ controlBindingSha256: "b".repeat(64) }),
    control: {
      async complete() {
        calls.push("complete");
        throw new Error("completion must not run without durable provider evidence");
      },
      async consume() {
        calls.push("consume");
        throw new Error("reconciliation must never consume dispatch authority");
      },
      async resolve() {
        calls.push("resolve");
        return resolved;
      }
    },
    durable: null
  });
  assert.equal(actual, resolved);
  assert.deepEqual(calls, ["resolve"]);
});

test("audit-only reconciliation completes a consumed row from the durable owner token", async () => {
  const calls = [];
  const binding = Object.freeze({ controlBindingSha256: "b".repeat(64) });
  const durable = Object.freeze({
    mcpResultSha256: "c".repeat(64),
    providerDispatchOwnerNonce: "33333333-3333-4333-8333-333333333333",
    sessionCloseSha256: "d".repeat(64)
  });
  const completed = Object.freeze({
    mcpResultSha256: durable.mcpResultSha256,
    sessionCloseSha256: durable.sessionCloseSha256,
    state: "COMPLETED"
  });
  const actual = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding,
    control: {
      async complete(actualBinding, terminal, ownerNonce) {
        calls.push(["complete", actualBinding, terminal, ownerNonce]);
        return completed;
      },
      async resolve(actualBinding) {
        calls.push(["resolve", actualBinding]);
        return Object.freeze({
          mcpResultSha256: null,
          sessionCloseSha256: null,
          state: "CONSUMED"
        });
      }
    },
    durable
  });
  assert.equal(actual, completed);
  assert.deepEqual(calls, [
    ["resolve", binding],
    [
      "complete",
      binding,
      {
        mcpResultSha256: durable.mcpResultSha256,
        sessionCloseSha256: durable.sessionCloseSha256
      },
      durable.providerDispatchOwnerNonce
    ]
  ]);
});
