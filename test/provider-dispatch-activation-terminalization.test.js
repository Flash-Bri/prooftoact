import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS,
  terminalizeIntegratedLiveDrillProviderDispatch
} from "../src/cloud/integrated-live-drill-provider-terminalization.js";
import {
  PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS,
  ProviderDispatchActivateControl
} from "../src/cloud/provider-dispatch-activate-control.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  buildProviderDispatchControlBinding
} from "../src/cloud/provider-dispatch-binding.js";
import { ProviderDispatchTerminalizeControl } from
  "../src/cloud/provider-dispatch-terminalize-control.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const NOW = Date.parse("2026-08-12T17:00:00.000Z");
const GRANT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const WORKER_SPEC = "b".repeat(64);
const ACTIVATION_REQUEST = "c".repeat(64);

function binding({
  issuedAt = NOW - 60_000,
  expiresAt = NOW + 60_000
} = {}) {
  return buildProviderDispatchControlBinding({
    context: {
      preCallIntent: {
        authorizationId: "11111111-1111-4111-8111-111111111111",
        interactionId: "22222222-2222-4222-8222-222222222222",
        logicalMcpRequestSha256: "d".repeat(64),
        recoveryClusterId: "33333333-3333-4333-8333-333333333333",
        runId: "44444444-4444-4444-8444-444444444444",
        tenantId: "55555555-5555-4555-8555-555555555555"
      },
      trustedRunContext: {
        spec: {
          sourceBuildIdentity: "e".repeat(64),
          sourceCommit: "f".repeat(40),
          treeDigest: "1".repeat(40)
        }
      }
    },
    dispatchAuthorizationSha256: "2".repeat(64),
    earliestControllingExpiry: expiresAt,
    latestControllingIssuedAt: issuedAt
  });
}

function databaseResult(control, {
  databaseNow = NOW,
  state,
  transitionOutcome
}) {
  const activationOutcome = [
    "ACTIVATION_GRANTED", "ACTIVATION_ALREADY_CONSUMED"
  ].includes(transitionOutcome) &&
    state === PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED;
  return {
    rowCount: 1,
    rows: [{
      activated_at: activationOutcome
        ? new Date(databaseNow).toISOString()
        : null,
      activation_request_sha256: activationOutcome
        ? ACTIVATION_REQUEST
        : null,
      authorization_id: control.authorizationId,
      control_binding_sha256: control.controlBindingSha256,
      database_now: new Date(databaseNow).toISOString(),
      expires_at: control.expiresAt,
      grant_id: GRANT_ID,
      mcp_result_sha256: state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED
        ? "3".repeat(64)
        : null,
      session_close_sha256: state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED
        ? "4".repeat(64)
        : null,
      state,
      transition_outcome: transitionOutcome,
      worker_spec_sha256: WORKER_SPEC
    }]
  };
}

function terminalizationDatabaseResult(control, options) {
  const result = databaseResult(control, options);
  delete result.rows[0].activated_at;
  delete result.rows[0].activation_request_sha256;
  return result;
}

function clientFactory({ handler }) {
  const calls = [];
  let clients = 0;
  return {
    calls,
    clientFactory(applicationName) {
      clients += 1;
      return {
        async connect() {},
        async end() {},
        async query(sql, params) {
          calls.push({ applicationName, client: clients, params, sql });
          return handler({ applicationName, client: clients, params, sql });
        }
      };
    }
  };
}

function activation(control, factory) {
  return new ProviderDispatchActivateControl({
    clientFactory: factory.clientFactory
  }).activate(control, {
    activationRequestSha256: ACTIVATION_REQUEST,
    grantId: GRANT_ID,
    workerSpecSha256: WORKER_SPEC
  });
}

function terminalize(control, factory) {
  return new ProviderDispatchTerminalizeControl({
    clientFactory: factory.clientFactory
  }).terminalize(control, {
    grantId: GRANT_ID,
    workerSpecSha256: WORKER_SPEC
  });
}

function localImportClosure(relativeRoots) {
  const imports =
    /\b(?:import|export)\s+(?:[^'";]*?\s+from\s+)?["']([^"']+)["']/gu;
  const pending = relativeRoots.map((entry) => path.join(ROOT, entry));
  const visited = new Set();
  while (pending.length > 0) {
    const filePath = pending.pop();
    if (visited.has(filePath)) continue;
    visited.add(filePath);
    const source = fs.readFileSync(filePath, "utf8");
    for (const match of source.matchAll(imports)) {
      const specifier = match[1];
      if (!specifier.startsWith(".")) continue;
      const resolved = path.resolve(path.dirname(filePath), specifier);
      pending.push(path.extname(resolved) === "" ? `${resolved}.js` : resolved);
    }
  }
  return [...visited].map((entry) => path.relative(ROOT, entry)).sort();
}

test("activation authorizes credential delivery only for one fresh database grant", async () => {
  const control = binding();
  const factory = clientFactory({
    handler: () => databaseResult(control, {
      state: PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED,
      transitionOutcome: "ACTIVATION_GRANTED"
    })
  });
  const result = await activation(control, factory);
  assert.equal(
    result.activationDisposition,
    PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DELIVER_CREDENTIAL_ONCE
  );
  assert.equal(result.databaseNow, new Date(NOW).toISOString());
  assert.equal(factory.calls.length, 1);
  assert.equal(
    factory.calls[0].applicationName,
    "tideproof-provider-dispatch-activate"
  );
  assert.deepEqual(
    Object.getOwnPropertyNames(Object.getPrototypeOf(
      new ProviderDispatchActivateControl({
        clientFactory: factory.clientFactory
      })
    )).sort(),
    ["activate", "constructor"]
  );
  assert.match(factory.calls[0].sql, /g1_activate_provider_dispatch_v2/u);
  assert.doesNotMatch(
    factory.calls[0].sql,
    /claim|begin|redeem|complete|unknown|terminalize/iu
  );
  assert.deepEqual(factory.calls[0].params, [
    control.authorizationId,
    GRANT_ID,
    control.controlBindingSha256,
    ACTIVATION_REQUEST
  ]);
});

test("same activation replay is exact-idempotent but cannot redeliver a credential", async () => {
  const control = binding();
  let calls = 0;
  const factory = clientFactory({
    handler: () => databaseResult(control, {
      state: PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED,
      transitionOutcome: calls++ === 0
        ? "ACTIVATION_GRANTED"
        : "ACTIVATION_ALREADY_CONSUMED"
    })
  });
  assert.equal(
    (await activation(control, factory)).activationDisposition,
    PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DELIVER_CREDENTIAL_ONCE
  );
  assert.equal(
    (await activation(control, factory)).activationDisposition,
    PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DO_NOT_DELIVER_CREDENTIAL
  );
  assert.equal(factory.calls.length, 2);
});

test("expired and terminal activation paths never authorize credential delivery", async () => {
  const control = binding();
  for (const state of [
    PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED,
    PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT,
    PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED
  ]) {
    const factory = clientFactory({
      handler: () => databaseResult(control, {
        databaseNow: NOW + 120_000,
        state,
        transitionOutcome: "ACTIVATION_NOT_AUTHORIZED"
      })
    });
    assert.equal(
      (await activation(control, factory)).activationDisposition,
      PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DO_NOT_DELIVER_CREDENTIAL,
      state
    );
  }
});

test("activation rejects incoherent database results and classifies ACK loss as unknown", async () => {
  const control = binding();
  const incoherent = clientFactory({
    handler: () => databaseResult(control, {
      databaseNow: NOW + 120_000,
      state: PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED,
      transitionOutcome: "ACTIVATION_GRANTED"
    })
  });
  await assert.rejects(
    activation(control, incoherent),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATION_UNKNOWN_DO_NOT_DELIVER/u
  );
  let attempts = 0;
  const ackLoss = clientFactory({
    handler: () => {
      attempts += 1;
      throw Object.assign(new Error("connection lost after commit"), {
        code: "08006"
      });
    }
  });
  await assert.rejects(
    activation(control, ackLoss),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATION_UNKNOWN_DO_NOT_DELIVER/u
  );
  assert.equal(attempts, 1);
});

test("effect-then-ACK-loss and conflicting activation replay can never deliver", async () => {
  const control = binding();
  let recordedRequest = null;
  let calls = 0;
  const factory = clientFactory({
    handler: ({ params }) => {
      calls += 1;
      const requestSha256 = params[3];
      if (recordedRequest === null) {
        recordedRequest = requestSha256;
        throw Object.assign(new Error("effect committed; acknowledgement lost"), {
          code: "08006"
        });
      }
      if (requestSha256 !== recordedRequest) {
        throw Object.assign(new Error("provider activation replay conflict"), {
          code: "22023"
        });
      }
      return databaseResult(control, {
        state: PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED,
        transitionOutcome: "ACTIVATION_ALREADY_CONSUMED"
      });
    }
  });
  await assert.rejects(
    activation(control, factory),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATION_UNKNOWN_DO_NOT_DELIVER/u
  );
  assert.equal(
    (await activation(control, factory)).activationDisposition,
    PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DO_NOT_DELIVER_CREDENTIAL
  );
  await assert.rejects(
    new ProviderDispatchActivateControl({
      clientFactory: factory.clientFactory
    }).activate(control, {
      activationRequestSha256: "9".repeat(64),
      grantId: GRANT_ID,
      workerSpecSha256: WORKER_SPEC
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED/u
  );
  assert.equal(calls, 3);
});

test("database time exactly at expiry cannot authorize credential delivery", async () => {
  const control = binding();
  const factory = clientFactory({
    handler: () => databaseResult(control, {
      databaseNow: Date.parse(control.expiresAt),
      state: PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED,
      transitionOutcome: "ACTIVATION_NOT_AUTHORIZED"
    })
  });
  assert.equal(
    (await activation(control, factory)).activationDisposition,
    PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DO_NOT_DELIVER_CREDENTIAL
  );
});

test("activation and terminalization clients reject authority-shaped extra inputs", async () => {
  const control = binding();
  const factory = clientFactory({
    handler: () => {
      throw new Error("database must not be reached");
    }
  });
  const activateControl = new ProviderDispatchActivateControl({
    clientFactory: factory.clientFactory
  });
  await assert.rejects(
    activateControl.activate(control, {
      activationRequestSha256: ACTIVATION_REQUEST,
      effectKey: "x",
      grantId: GRANT_ID,
      workerSpecSha256: WORKER_SPEC
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED/u
  );
  const terminalizeControl = new ProviderDispatchTerminalizeControl({
    clientFactory: factory.clientFactory
  });
  await assert.rejects(
    terminalizeControl.terminalize(control, {
      completionCapability: "5".repeat(64),
      grantId: GRANT_ID,
      workerSpecSha256: WORKER_SPEC
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED/u
  );
  assert.equal(factory.calls.length, 0);
});

test("database privilege policy gives activation and terminalization one routine each", () => {
  const source = fs.readFileSync(
    path.join(ROOT, "src/cloud/primary-security.js"),
    "utf8"
  );
  assert.match(
    source,
    /tp_provider_activate_role:\s*Object\.freeze\(\{\s*functions:\s*Object\.freeze\(\[\s*"g1_activate_provider_dispatch_v2\(UUID, UUID, STRING, STRING\)"\s*\]\)\s*\}\)/u
  );
  assert.match(
    source,
    /tp_provider_terminalize_role:\s*Object\.freeze\(\{\s*functions:\s*Object\.freeze\(\[\s*"g1_terminalize_provider_dispatch_v2\(UUID, UUID, STRING, STRING\)"\s*\]\)\s*\}\)/u
  );
  assert.match(
    source,
    /GRANT EXECUTE ON FUNCTION\s+tp_api\.g1_activate_provider_dispatch_v2\(\s*UUID, UUID, STRING, STRING\s*\)\s+TO tp_provider_activate_role/u
  );
  assert.match(
    source,
    /GRANT EXECUTE ON FUNCTION\s+tp_api\.g1_terminalize_provider_dispatch_v2\(\s*UUID, UUID, STRING, STRING\s*\)\s+TO tp_provider_terminalize_role/u
  );
});

test("database-time terminalization maps every nonterminal expiry boundary", async () => {
  const control = binding();
  const cases = [
    {
      databaseNow: Date.parse(control.expiresAt) - 1,
      disposition:
        INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS.NOT_DUE,
      state: PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING,
      transitionOutcome: "NOT_EXPIRED"
    },
    {
      databaseNow: Date.parse(control.expiresAt),
      disposition:
        INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
          .TERMINAL_EXPIRED,
      state: PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED,
      transitionOutcome: "EXPIRED_RECORDED"
    },
    {
      databaseNow: Date.parse(control.expiresAt),
      disposition:
        INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
          .TERMINAL_UNKNOWN_DO_NOT_ACT,
      state: PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT,
      transitionOutcome: "UNKNOWN_RECORDED"
    }
  ];
  for (const candidate of cases) {
    const factory = clientFactory({
      handler: () => terminalizationDatabaseResult(control, candidate)
    });
    const result = await terminalizeIntegratedLiveDrillProviderDispatch({
      input: {
        binding: control,
        grantId: GRANT_ID,
        workerSpecSha256: WORKER_SPEC
      },
      terminalizeControl: new ProviderDispatchTerminalizeControl({
        clientFactory: factory.clientFactory
      })
    });
    assert.equal(result.disposition, candidate.disposition);
    assert.equal(result.databaseNow, new Date(candidate.databaseNow).toISOString());
    assert.equal(factory.calls.length, 1);
    assert.equal(
      factory.calls[0].applicationName,
      "tideproof-provider-dispatch-terminalize"
    );
    assert.deepEqual(factory.calls[0].params, [
      control.authorizationId,
      GRANT_ID,
      control.controlBindingSha256,
      WORKER_SPEC
    ]);
    assert.match(factory.calls[0].sql, /g1_terminalize_provider_dispatch_v2/u);
  }
});

test("terminalization is exact-idempotent for immutable terminal states", async () => {
  const control = binding();
  for (const [state, disposition] of [
    [
      PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED,
      INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
        .TERMINAL_EXPIRED
    ],
    [
      PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT,
      INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
        .TERMINAL_UNKNOWN_DO_NOT_ACT
    ],
    [
      PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED,
      INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
        .TERMINAL_COMPLETED
    ]
  ]) {
    const factory = clientFactory({
      handler: () => terminalizationDatabaseResult(control, {
        databaseNow: NOW + 120_000,
        state,
        transitionOutcome: "ALREADY_TERMINAL"
      })
    });
    assert.equal(
      (await terminalizeIntegratedLiveDrillProviderDispatch({
        input: {
          binding: control,
          grantId: GRANT_ID,
          workerSpecSha256: WORKER_SPEC
        },
        terminalizeControl: new ProviderDispatchTerminalizeControl({
          clientFactory: factory.clientFactory
        })
      })).disposition,
      disposition,
      state
    );
  }
});

test("finalizer-winning race is observed as immutable COMPLETED", async () => {
  const control = binding();
  const terminalizeControl = Object.freeze({
    async terminalize() {
      return Object.freeze({
        authorizationId: control.authorizationId,
        controlBindingSha256: control.controlBindingSha256,
        databaseNow: new Date(Date.parse(control.expiresAt) + 1).toISOString(),
        expiresAt: control.expiresAt,
        grantId: GRANT_ID,
        mcpResultSha256: "3".repeat(64),
        sessionCloseSha256: "4".repeat(64),
        state: PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED,
        transitionOutcome: "ALREADY_TERMINAL",
        workerSpecSha256: WORKER_SPEC
      });
    }
  });
  const result = await terminalizeIntegratedLiveDrillProviderDispatch({
    input: {
      binding: control,
      grantId: GRANT_ID,
      workerSpecSha256: WORKER_SPEC
    },
    terminalizeControl
  });
  assert.equal(
    result.disposition,
    INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
      .TERMINAL_COMPLETED
  );
});

test("terminalizer retries transient database failure but rejects identity and SQL denials", async () => {
  const control = binding();
  let attempts = 0;
  const transient = clientFactory({
    handler: () => {
      attempts += 1;
      if (attempts === 1) {
        throw Object.assign(new Error("retry transaction"), { code: "40001" });
      }
      return terminalizationDatabaseResult(control, {
        databaseNow: NOW + 120_000,
        state: PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED,
        transitionOutcome: "EXPIRED_RECORDED"
      });
    }
  });
  assert.equal(
    (await terminalize(control, transient)).state,
    PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED
  );
  assert.equal(attempts, 2);

  const denied = clientFactory({
    handler: () => {
      throw Object.assign(new Error("wrong database role"), { code: "42501" });
    }
  });
  await assert.rejects(
    terminalize(control, denied),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED/u
  );

  const mismatched = clientFactory({
    handler: () => {
      const result = terminalizationDatabaseResult(control, {
        databaseNow: NOW + 120_000,
        state: PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED,
        transitionOutcome: "EXPIRED_RECORDED"
      });
      result.rows[0].grant_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
      return result;
    }
  });
  await assert.rejects(
    terminalize(control, mismatched),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED/u
  );

  let lostAcknowledgements = 0;
  const unavailable = clientFactory({
    handler: () => {
      lostAcknowledgements += 1;
      throw Object.assign(new Error("connection lost after terminalization"), {
        code: "08006"
      });
    }
  });
  await assert.rejects(
    terminalize(control, unavailable),
    /INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZATION_RETRY_REQUIRED/u
  );
  assert.equal(lostAcknowledgements, 3);
  assert.deepEqual(
    Object.getOwnPropertyNames(Object.getPrototypeOf(
      new ProviderDispatchTerminalizeControl({
        clientFactory: unavailable.clientFactory
      })
    )).sort(),
    ["constructor", "terminalize"]
  );
});

test("terminalization interface classifies unavailable acknowledgement as retry required", async () => {
  const control = binding();
  await assert.rejects(
    terminalizeIntegratedLiveDrillProviderDispatch({
      input: {
        binding: control,
        grantId: GRANT_ID,
        workerSpecSha256: WORKER_SPEC
      },
      terminalizeControl: {
        async terminalize() {
          throw new Error(
            "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZATION_RETRY_REQUIRED"
          );
        }
      }
    }),
    /INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_RETRY_REQUIRED/u
  );
});

test("activation and terminalization transitive import closures exclude provider and raw evidence code", () => {
  const closure = localImportClosure([
    "src/cloud/provider-dispatch-activate-control.js",
    "src/cloud/provider-dispatch-terminalize-control.js",
    "src/cloud/integrated-live-drill-provider-terminalization.js"
  ]);
  for (const modulePath of closure) {
    for (const forbidden of [
      "managed-mcp-client",
      "provider-dispatch-begin-control",
      "provider-dispatch-claim-control",
      "provider-dispatch-finalize-control",
      "provider-dispatch-redeem-control",
      "provider-operation-broker",
      "provider-recovery",
      "recovery-storage"
    ]) assert.equal(modulePath.includes(forbidden), false, `${modulePath}:${forbidden}`);
  }
  for (const forbiddenText of ["MCP_API_KEY", "rawResult"]) {
    assert.equal(closure.some((modulePath) =>
      fs.readFileSync(path.join(ROOT, modulePath), "utf8")
        .includes(forbiddenText)
    ), false, forbiddenText);
  }
});
