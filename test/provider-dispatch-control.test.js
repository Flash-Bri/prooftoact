import assert from "node:assert/strict";
import test from "node:test";

import {
  buildProviderDispatchControlBinding,
  ProviderDispatchControl,
  PROVIDER_DISPATCH_CONTROL_STATES
} from "../src/cloud/provider-dispatch-control.js";

const OWNER_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const NOW = Date.parse("2026-08-11T22:00:00.000Z");

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

function globalControlDatabase(initialNow = NOW) {
  const rows = new Map();
  let databaseNow = initialNow;
  const clientFactory = () => ({
    async connect() {},
    async end() {},
    async query(_sql, params) {
      const [
        action,
        authorizationId,
        tenantId,
        runId,
        interactionId,
        ownerNonce,
        controlBindingSha256,
        logicalMcpRequestSha256,
        providerEffectKeySha256,
        providerDispatchAuthorizationSha256,
        sourceCommit,
        treeDigest,
        sourceBuildIdentity,
        issuedAt,
        expiresAt,
        mcpResultSha256,
        sessionCloseSha256
      ] = params;
      let row = rows.get(authorizationId);
      let transitionOutcome;
      if (row === undefined) {
        assert.equal(action, "CONSUME");
        const current = databaseNow;
        const currentState =
          current >= Date.parse(issuedAt) && current < Date.parse(expiresAt)
            ? PROVIDER_DISPATCH_CONTROL_STATES.CONSUMED
            : PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED;
        row = {
          authorization_id: authorizationId,
          tenant_id: tenantId,
          run_id: runId,
          interaction_id: interactionId,
          owner_nonce: ownerNonce,
          control_binding_sha256: controlBindingSha256,
          logical_mcp_request_sha256: logicalMcpRequestSha256,
          provider_effect_key_sha256: providerEffectKeySha256,
          provider_dispatch_authorization_sha256:
            providerDispatchAuthorizationSha256,
          source_commit: sourceCommit,
          tree_digest: treeDigest,
          source_build_identity: sourceBuildIdentity,
          issued_at: issuedAt,
          expires_at: expiresAt,
          state: currentState,
          mcp_result_sha256: null,
          session_close_sha256: null
        };
        rows.set(authorizationId, row);
        transitionOutcome = currentState ===
            PROVIDER_DISPATCH_CONTROL_STATES.CONSUMED
          ? "DISPATCH_GRANTED"
          : "AUTHORITY_NOT_CURRENT";
      } else {
        assert.equal(row.control_binding_sha256, controlBindingSha256);
        if (action === "CONSUME") {
          transitionOutcome = row.state ===
              PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED
            ? "AUTHORITY_NOT_CURRENT"
            : "ALREADY_TERMINAL_OR_CONSUMED";
        } else if (action === "COMPLETE") {
          assert.equal(ownerNonce, row.owner_nonce);
          assert.equal(
            row.state,
            PROVIDER_DISPATCH_CONTROL_STATES.CONSUMED
          );
          row.state = PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED;
          row.mcp_result_sha256 = mcpResultSha256;
          row.session_close_sha256 = sessionCloseSha256;
          transitionOutcome = "COMPLETED";
        } else if (action === "MARK_UNKNOWN") {
          assert.equal(ownerNonce, row.owner_nonce);
          if (row.state === PROVIDER_DISPATCH_CONTROL_STATES.CONSUMED) {
            row.state =
              PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT;
          }
          transitionOutcome = "UNKNOWN_RECORDED";
        } else {
          transitionOutcome = "RESOLVED";
        }
      }
      return {
        rowCount: 1,
        rows: [{
          ...row,
          database_now: new Date(databaseNow).toISOString(),
          transition_outcome: transitionOutcome
        }]
      };
    }
  });
  return {
    clientFactory,
    rows,
    setDatabaseNow(value) {
      databaseNow = value;
    }
  };
}

test("two independent hosts receive one global provider-dispatch grant", async () => {
  const database = globalControlDatabase();
  const exactBinding = binding();
  const controls = [OWNER_A, OWNER_B].map((ownerNonce) =>
    new ProviderDispatchControl({
      clientFactory: database.clientFactory,
      ownerNonce
    })
  );
  const results = await Promise.all(
    controls.map((control) => control.consume(exactBinding))
  );
  assert.equal(
    results.filter(({ transitionOutcome }) =>
      transitionOutcome === "DISPATCH_GRANTED"
    ).length,
    1
  );
  assert.equal(
    results.filter(({ transitionOutcome }) =>
      transitionOutcome === "ALREADY_TERMINAL_OR_CONSUMED"
    ).length,
    1
  );
  assert.equal(database.rows.size, 1);

  const winner = results.findIndex(({ transitionOutcome }) =>
    transitionOutcome === "DISPATCH_GRANTED"
  );
  const terminal = {
    mcpResultSha256: "f".repeat(64),
    sessionCloseSha256: "1".repeat(64)
  };
  const completed = await controls[winner].complete(exactBinding, terminal);
  assert.equal(completed.state, PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED);
  assert.equal(completed.mcpResultSha256, terminal.mcpResultSha256);
  assert.equal(completed.sessionCloseSha256, terminal.sessionCloseSha256);
});

test("a fresh process can complete from a durably recovered owner token", async () => {
  const database = globalControlDatabase();
  const exactBinding = binding({
    authorizationId: "77777777-7777-4777-8777-777777777777",
    logicalMcpRequestSha256: "7".repeat(64)
  });
  const firstProcess = new ProviderDispatchControl({
    clientFactory: database.clientFactory,
    ownerNonce: OWNER_A
  });
  const consumed = await firstProcess.consume(exactBinding);
  assert.equal(consumed.transitionOutcome, "DISPATCH_GRANTED");
  assert.equal(consumed.ownerNonce, OWNER_A);

  const restartedProcess = new ProviderDispatchControl({
    clientFactory: database.clientFactory
  });
  const terminal = {
    mcpResultSha256: "8".repeat(64),
    sessionCloseSha256: "9".repeat(64)
  };
  const completed = await restartedProcess.complete(
    exactBinding,
    terminal,
    consumed.ownerNonce
  );
  assert.equal(completed.state, PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED);
  assert.equal(completed.mcpResultSha256, terminal.mcpResultSha256);
  assert.equal(completed.sessionCloseSha256, terminal.sessionCloseSha256);
});

test("database-time expiry remains terminal after restart and clock rollback", async () => {
  const database = globalControlDatabase(NOW);
  const expiredBinding = binding({
    authorizationId: "66666666-6666-4666-8666-666666666666",
    logicalMcpRequestSha256: "2".repeat(64),
    issuedAt: NOW - 60_000,
    expiresAt: NOW - 1
  });
  const first = new ProviderDispatchControl({
    clientFactory: database.clientFactory,
    ownerNonce: OWNER_A
  });
  const expired = await first.consume(expiredBinding);
  assert.equal(expired.state, PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED);
  assert.equal(expired.transitionOutcome, "AUTHORITY_NOT_CURRENT");

  database.setDatabaseNow(NOW - 120_000);
  const restarted = new ProviderDispatchControl({
    clientFactory: database.clientFactory,
    ownerNonce: OWNER_B
  });
  const replay = await restarted.consume(expiredBinding);
  assert.equal(replay.state, PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED);
  assert.equal(replay.transitionOutcome, "AUTHORITY_NOT_CURRENT");
  assert.equal(database.rows.size, 1);
});
