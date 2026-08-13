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
import {
  INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA
} from "../src/cloud/integrated-live-drill-dispatch-broker.js";

const AUTHORIZATION_ID = "11111111-1111-4111-8111-111111111111";
const RUN_ID = "22222222-2222-4222-8222-222222222222";

function executionGrant() {
  const body = Object.freeze({
    authorizationId: AUTHORIZATION_ID,
    controlBindingSha256: "a".repeat(64),
    executionCapabilitySha256: "b".repeat(64),
    grantId: "33333333-3333-4333-8333-333333333333",
    operationNonceSha256: "c".repeat(64),
    requestSha256: "d".repeat(64),
    schemaVersion: INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA,
    state: "EXECUTING",
    workerSpecSha256: "e".repeat(64)
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

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
    state: "GRANTED",
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: "RESOLVED"
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

test("reconciliation environment carries resolve-only authority without provider API authority", () => {
  const environment = integratedLiveDrillProviderReconciliationEnvironment({
    LANG: "C",
    MCP_API_KEY: "must-not-cross-boundary",
    PRIMARY_PROVIDER_RECONCILE_DATABASE_URL:
      "postgresql://reconcile.invalid/tideproof"
  }, {});
  assert.equal(environment.LANG, "C");
  assert.deepEqual(
    environment.PRIMARY_PROVIDER_RECONCILE_DATABASE_URL,
    "postgresql://reconcile.invalid/tideproof"
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

test("audit-only reconciliation observes with a resolver that has no mutation surface", async () => {
  const calls = [];
  const resolved = Object.freeze({
    mcpResultSha256: null,
    sessionCloseSha256: null,
    state: "GRANTED"
  });
  const actual = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding: Object.freeze({ controlBindingSha256: "b".repeat(64) }),
    resolver: {
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

test("audit-only reconciliation never mutates an executing row with durable evidence", async () => {
  const calls = [];
  const binding = Object.freeze({ controlBindingSha256: "b".repeat(64) });
  const durable = Object.freeze({
    mcpResultSha256: "c".repeat(64),
    sessionCloseSha256: "d".repeat(64)
  });
  const actual = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding,
    resolver: {
      async resolve(actualBinding) {
        calls.push(["resolve", actualBinding]);
        return Object.freeze({
          mcpResultSha256: null,
          sessionCloseSha256: null,
          state: "EXECUTING"
        });
      }
    },
    durable
  });
  assert.equal(actual.state, "EXECUTING");
  assert.deepEqual(calls, [
    ["resolve", binding]
  ]);
});

test("reconciliation input accepts only an exact global EXECUTING grant", async () => {
  const { validateIntegratedLiveDrillProviderReconciliationInput } =
    await import("../src/cloud/integrated-live-drill-provider-reconciliation.js");
  const fixture = Object.freeze({
    context: Object.freeze({ marker: "invalid-context-is-checked-first" }),
    executionGrant: executionGrant(),
    schemaVersion: "tideproof.highwater-drill-provider-reconciliation-input.v2"
  });
  assert.throws(
    () => validateIntegratedLiveDrillProviderReconciliationInput(fixture),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED/u
  );
  const withLegacyLocalReceipt = Object.freeze({
    ...fixture,
    providerAdmissionReceiptSha256: "f".repeat(64)
  });
  assert.throws(
    () => validateIntegratedLiveDrillProviderReconciliationInput(
      withLegacyLocalReceipt
    ),
    /INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED/u
  );
});
