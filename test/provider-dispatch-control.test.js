import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { ProviderDispatchBeginControl } from
  "../src/cloud/provider-dispatch-begin-control.js";
import {
  buildProviderDispatchControlBinding,
  PROVIDER_DISPATCH_CONTROL_STATES
} from "../src/cloud/provider-dispatch-binding.js";
import { ProviderDispatchClaimControl } from
  "../src/cloud/provider-dispatch-claim-control.js";
import { ProviderDispatchFinalizeControl } from
  "../src/cloud/provider-dispatch-finalize-control.js";
import { ProviderDispatchRedeemControl } from
  "../src/cloud/provider-dispatch-redeem-control.js";
import { ProviderDispatchResolver } from
  "../src/cloud/provider-dispatch-resolver.js";

const NOW = Date.parse("2026-08-12T17:00:00.000Z");
const GRANT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GRANT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CAPABILITY_A = "a".repeat(64);
const CAPABILITY_B = "b".repeat(64);
const COMPLETION_CAPABILITY = "c".repeat(64);
const WORKER_SPEC = "f".repeat(64);

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function binding({
  authorizationId = "11111111-1111-4111-8111-111111111111",
  logicalMcpRequestSha256 = "a".repeat(64),
  issuedAt = NOW - 1_000,
  expiresAt = NOW + 60_000
} = {}) {
  return buildProviderDispatchControlBinding({
    context: {
      preCallIntent: {
        authorizationId,
        interactionId: "22222222-2222-4222-8222-222222222222",
        logicalMcpRequestSha256,
        recoveryClusterId: "33333333-3333-4333-8333-333333333333",
        runId: "44444444-4444-4444-8444-444444444444",
        tenantId: "55555555-5555-4555-8555-555555555555"
      },
      trustedRunContext: {
        spec: {
          sourceBuildIdentity: "b".repeat(64),
          sourceCommit: "c".repeat(40),
          treeDigest: "d".repeat(40)
        }
      }
    },
    dispatchAuthorizationSha256: "e".repeat(64),
    earliestControllingExpiry: expiresAt,
    latestControllingIssuedAt: issuedAt
  });
}

function result(row, transitionOutcome, databaseNow = NOW) {
  return {
    rowCount: 1,
    rows: [{
      authorization_id: row.authorizationId,
      control_binding_sha256: row.controlBindingSha256,
      database_now: new Date(databaseNow).toISOString(),
      expires_at: row.expiresAt,
      grant_id: row.grantId,
      mcp_result_sha256: row.mcpResultSha256,
      session_close_sha256: row.sessionCloseSha256,
      state: row.state,
      transition_outcome: transitionOutcome,
      worker_spec_sha256: row.workerSpecSha256
    }]
  };
}

function globalControlDatabase(initialNow = NOW) {
  const rows = new Map();
  let databaseNow = initialNow;
  let firstClaimSerializationFailure = false;
  const calls = [];
  const clientFactory = (applicationName) => ({
    async connect() {},
    async end() {},
    async query(sql, params) {
      calls.push({ applicationName, params: [...params], sql });
      if (
        applicationName === "tideproof-provider-dispatch-claim" &&
        firstClaimSerializationFailure
      ) {
        firstClaimSerializationFailure = false;
        throw Object.assign(new Error("restart transaction"), { code: "40001" });
      }
      if (applicationName === "tideproof-provider-dispatch-claim") {
        const [
          authorizationId, grantId, tenantId, runId, interactionId,
          controlBindingSha256, logicalMcpRequestSha256,
          providerEffectKeySha256, providerDispatchAuthorizationSha256,
          sourceCommit, treeDigest, sourceBuildIdentity, issuedAt, expiresAt,
          executionCapabilitySha256, workerSpecSha256
        ] = params;
        let row = rows.get(providerEffectKeySha256);
        if (row === undefined) {
          const current = databaseNow >= Date.parse(issuedAt) &&
            databaseNow < Date.parse(expiresAt);
          row = {
            authorizationId,
            controlBindingSha256,
            executionCapabilitySha256,
            expiresAt,
            grantId,
            interactionId,
            logicalMcpRequestSha256,
            mcpResultSha256: null,
            providerDispatchAuthorizationSha256,
            providerEffectKeySha256,
            runId,
            sessionCloseSha256: null,
            sourceBuildIdentity,
            sourceCommit,
            state: current
              ? PROVIDER_DISPATCH_CONTROL_STATES.GRANTED
              : PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED,
            tenantId,
            treeDigest,
            workerSpecSha256
          };
          rows.set(providerEffectKeySha256, row);
        }
        const won = row.grantId === grantId &&
          row.executionCapabilitySha256 === executionCapabilitySha256 &&
          row.state === PROVIDER_DISPATCH_CONTROL_STATES.GRANTED;
        return result(
          row,
          row.state === PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED
            ? "AUTHORITY_NOT_CURRENT"
            : won
              ? "DISPATCH_GRANTED"
              : "ALREADY_TERMINAL_OR_EXECUTING",
          databaseNow
        );
      }
      const authorizationId = params[0];
      const row = [...rows.values()].find((candidate) =>
        candidate.authorizationId === authorizationId
      );
      if (applicationName === "tideproof-provider-dispatch-resolve") {
        if (row === undefined) {
          return result({
            authorizationId,
            controlBindingSha256: params[1],
            expiresAt: null,
            grantId: null,
            mcpResultSha256: null,
            sessionCloseSha256: null,
            state: PROVIDER_DISPATCH_CONTROL_STATES.ABSENT,
            workerSpecSha256: null
          }, "RESOLVED_ABSENT", databaseNow);
        }
        return result(row, "RESOLVED", databaseNow);
      }
      assert.ok(row);
      assert.equal(params[1], row.grantId);
      assert.equal(params[2], row.controlBindingSha256);
      if (applicationName === "tideproof-provider-dispatch-begin") {
        assert.equal(sha256(params[3]), row.executionCapabilitySha256);
        assert.equal(params[4], row.workerSpecSha256);
        if (row.state === PROVIDER_DISPATCH_CONTROL_STATES.GRANTED) {
          row.state = PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING;
          return result(row, "EXECUTION_STARTED", databaseNow);
        }
        return result(row, "ALREADY_EXECUTING_DO_NOT_START", databaseNow);
      }
      if (applicationName === "tideproof-provider-dispatch-redeem") {
        assert.equal(sha256(params[3]), row.executionCapabilitySha256);
        assert.equal(params[5], row.workerSpecSha256);
        if (row.state === PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING) {
          row.completionCapabilitySha256 = params[4];
          row.state = PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED;
          return result(row, "CREDENTIAL_REDEEMED", databaseNow);
        }
        return result(row, "ALREADY_REDEEMED_DO_NOT_DELIVER", databaseNow);
      }
      if (applicationName === "tideproof-provider-dispatch-finalize") {
        assert.equal(sha256(params[3]), row.completionCapabilitySha256);
        if (sql.includes("g1_complete_provider_dispatch_v2")) {
          row.state = PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED;
          row.mcpResultSha256 = params[4];
          row.sessionCloseSha256 = params[5];
          return result(row, "COMPLETED", databaseNow);
        }
        row.state = PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT;
        return result(row, "UNKNOWN_RECORDED", databaseNow);
      }
      throw new Error("unexpected application identity");
    }
  });
  return {
    calls,
    clientFactory,
    failFirstClaimWithSerialization() { firstClaimSerializationFailure = true; },
    rows,
    setDatabaseNow(value) { databaseNow = value; }
  };
}

test("two independent claimants yield one global grant and no secret in results", async () => {
  const database = globalControlDatabase();
  const exactBinding = binding();
  const controls = [
    { executionCapability: CAPABILITY_A, grantId: GRANT_A },
    { executionCapability: CAPABILITY_B, grantId: GRANT_B }
  ].map((candidate) => ({
    candidate,
    control: new ProviderDispatchClaimControl({
      clientFactory: database.clientFactory
    })
  }));
  const results = await Promise.all(controls.map(({ candidate, control }) =>
    control.claim(exactBinding, {
      executionCapabilitySha256: sha256(candidate.executionCapability),
      grantId: candidate.grantId,
      workerSpecSha256: WORKER_SPEC
    })
  ));
  assert.equal(
    results.filter(({ transitionOutcome }) =>
      transitionOutcome === "DISPATCH_GRANTED"
    ).length,
    1
  );
  assert.equal(
    results.filter(({ transitionOutcome }) =>
      transitionOutcome === "ALREADY_TERMINAL_OR_EXECUTING"
    ).length,
    1
  );
  for (const current of results) {
    assert.equal("executionCapability" in current, false);
    assert.equal("executionCapabilitySha256" in current, false);
    assert.equal("ownerNonce" in current, false);
  }
});

test("claim, begin, redeem, and finalize use distinct least-privilege clients", async () => {
  const database = globalControlDatabase();
  database.failFirstClaimWithSerialization();
  const exactBinding = binding();
  const claim = new ProviderDispatchClaimControl({
    clientFactory: database.clientFactory
  });
  const granted = await claim.claim(exactBinding, {
    executionCapabilitySha256: sha256(CAPABILITY_A),
    grantId: GRANT_A,
    workerSpecSha256: WORKER_SPEC
  });
  assert.equal(granted.transitionOutcome, "DISPATCH_GRANTED");
  assert.equal(
    database.calls.filter(({ applicationName }) =>
      applicationName === "tideproof-provider-dispatch-claim"
    ).length,
    2
  );
  const begun = await new ProviderDispatchBeginControl({
    clientFactory: database.clientFactory
  }).begin(exactBinding, {
    executionCapability: CAPABILITY_A,
    grantId: GRANT_A,
    workerSpecSha256: WORKER_SPEC
  });
  assert.equal(begun.state, PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING);
  const redeemed = await new ProviderDispatchRedeemControl({
    clientFactory: database.clientFactory
  }).redeem(exactBinding, {
    completionCapabilitySha256: sha256(COMPLETION_CAPABILITY),
    executionCapability: CAPABILITY_A,
    grantId: GRANT_A,
    workerSpecSha256: WORKER_SPEC
  });
  assert.equal(
    redeemed.state,
    PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED
  );
  const terminal = {
    mcpResultSha256: "8".repeat(64),
    sessionCloseSha256: "9".repeat(64)
  };
  const completed = await new ProviderDispatchFinalizeControl({
    clientFactory: database.clientFactory
  }).complete(exactBinding, {
    completionCapability: COMPLETION_CAPABILITY,
    grantId: GRANT_A
  }, terminal);
  assert.equal(completed.state, PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED);
  assert.deepEqual(
    new Set(database.calls.map(({ applicationName }) => applicationName)),
    new Set([
      "tideproof-provider-dispatch-begin",
      "tideproof-provider-dispatch-claim",
      "tideproof-provider-dispatch-finalize",
      "tideproof-provider-dispatch-redeem"
    ])
  );
});

test("resolver observes absent and terminal states without a mutation method or secret", async () => {
  const database = globalControlDatabase();
  const absentBinding = binding({
    authorizationId: "66666666-6666-4666-8666-666666666666",
    logicalMcpRequestSha256: "6".repeat(64)
  });
  const resolver = new ProviderDispatchResolver({
    clientFactory: database.clientFactory
  });
  assert.equal(typeof resolver.resolve, "function");
  for (const forbidden of ["claim", "begin", "redeem", "complete", "markUnknown"] ) {
    assert.equal(typeof resolver[forbidden], "undefined", forbidden);
  }
  const absent = await resolver.resolve(absentBinding);
  assert.equal(absent.state, PROVIDER_DISPATCH_CONTROL_STATES.ABSENT);
  assert.equal(absent.grantId, null);
  assert.equal(absent.workerSpecSha256, null);
  assert.equal("ownerNonce" in absent, false);
  assert.equal("executionCapabilitySha256" in absent, false);
});

test("wrong execution capability cannot begin or finalize", async () => {
  const database = globalControlDatabase();
  const exactBinding = binding();
  await new ProviderDispatchClaimControl({
    clientFactory: database.clientFactory
  }).claim(exactBinding, {
    executionCapabilitySha256: sha256(CAPABILITY_A),
    grantId: GRANT_A,
    workerSpecSha256: WORKER_SPEC
  });
  await assert.rejects(
    new ProviderDispatchBeginControl({ clientFactory: database.clientFactory })
      .begin(exactBinding, {
        executionCapability: CAPABILITY_B,
        grantId: GRANT_A,
        workerSpecSha256: WORKER_SPEC
      })
  );
});
