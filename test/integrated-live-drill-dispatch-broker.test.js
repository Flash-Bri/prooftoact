import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test as brokerTest,
  INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_SCHEMA,
  readIntegratedLiveDrillExecutionCapability,
  runIntegratedLiveDrillDispatchBroker,
  validateIntegratedLiveDrillExecutionGrant
} from "../src/cloud/integrated-live-drill-dispatch-broker.js";
import {
  PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
  providerDispatchSha256
} from "../src/cloud/provider-dispatch-binding.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CHILD = path.join(
  ROOT,
  "test/fixtures/provider-dispatch-broker-child.js"
);

function directory(root, name) {
  const value = path.join(root, name);
  fs.mkdirSync(value, { mode: 0o700 });
  fs.chmodSync(value, 0o700);
  return fs.realpathSync(value);
}

function binding() {
  const body = Object.freeze({
    authorizationId: "11111111-1111-4111-8111-111111111111",
    expiresAt: "2026-08-12T17:00:00.000Z",
    interactionId: "22222222-2222-4222-8222-222222222222",
    issuedAt: "2026-08-12T16:00:00.000Z",
    logicalMcpRequestSha256: "a".repeat(64),
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
    controlBindingSha256: providerDispatchSha256(canonicalJson(body))
  });
}

function runChild(environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CHILD], {
      cwd: ROOT,
      env: Object.freeze({
        LANG: "C",
        PATH: process.env.PATH,
        ...environment
      }),
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr, stdout }));
  });
}

test("two real broker processes publish one execution grant after one global begin", async (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-dispatch-broker-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const shared = directory(temporaryRoot, "shared");
  const request = Object.freeze({
    binding: binding(),
    packageLockDigest: "8".repeat(64),
    schemaVersion: INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_SCHEMA,
    workerInput: Object.freeze({
      authenticatedPrincipal: "synthetic-principal",
      context: Object.freeze({ marker: "provider-free-context" })
    }),
    workerSpecSha256: providerDispatchSha256(canonicalJson(Object.freeze({
      authenticatedPrincipal: "synthetic-principal",
      context: Object.freeze({ marker: "provider-free-context" })
    })))
  });
  const contenders = ["alpha", "bravo"].map((name) => {
    const privateRoot = directory(temporaryRoot, `${name}-private`);
    const grantRoot = directory(temporaryRoot, `${name}-grant`);
    return Object.freeze({
      grantPath: path.join(grantRoot, "execution-grant.json"),
      grantRoot,
      name,
      privateRoot
    });
  });
  const results = await Promise.all(contenders.map((contender) => runChild({
    BROKER_EXECUTION_GRANT_PATH: contender.grantPath,
    BROKER_EXECUTION_GRANT_ROOT: contender.grantRoot,
    BROKER_PRIVATE_ROOT: contender.privateRoot,
    BROKER_REQUEST_JSON: JSON.stringify(request),
    BROKER_SHARED_STATE_PATH: path.join(shared, "database-row.json")
  })));
  assert.deepEqual(results.map((result) => result.code), [0, 0], results
    .map((result) => result.stderr).join("\n"));
  const receipts = results.map((result) => JSON.parse(result.stdout));
  assert.equal(
    receipts.filter((receipt) => receipt.status === "EXECUTION_GRANTED").length,
    1
  );
  assert.equal(
    receipts.filter((receipt) => receipt.status === "NOT_SELECTED").length,
    1
  );
  assert.equal(receipts.some((receipt) => "executionCapability" in receipt), false);
  assert.equal(receipts.some((receipt) => "providerCredential" in receipt), false);
  const grants = contenders.filter((contender) => fs.existsSync(
    contender.grantPath
  ));
  assert.equal(grants.length, 1);
  const reconciliationInputs = contenders.filter((contender) => fs.existsSync(
    path.join(contender.grantRoot, "provider-reconciliation-input.json")
  ));
  assert.equal(reconciliationInputs.length, 1);
  const grant = validateIntegratedLiveDrillExecutionGrant(JSON.parse(
    fs.readFileSync(grants[0].grantPath, "utf8")
  ));
  const reconciliationInput = JSON.parse(fs.readFileSync(
    path.join(
      reconciliationInputs[0].grantRoot,
      "provider-reconciliation-input.json"
    ),
    "utf8"
  ));
  assert.deepEqual(reconciliationInput.binding, request.binding);
  assert.deepEqual(reconciliationInput.admission, {
    grantId: grant.grantId,
    workerSpecSha256: grant.workerSpecSha256
  });
  assert.equal(reconciliationInput.packageLockDigest, request.packageLockDigest);
  assert.equal("context" in reconciliationInput, false);
  assert.equal("executionGrant" in reconciliationInput, false);
  assert.equal("executionCapabilitySha256" in reconciliationInput, false);
  assert.equal("operationNonceSha256" in reconciliationInput, false);
  assert.equal(
    reconciliationInput.schemaVersion,
    "tideproof.highwater-drill-provider-reconciliation-input.v3"
  );
  const secret = readIntegratedLiveDrillExecutionCapability({
    authorizationId: request.binding.authorizationId,
    brokerRootPath: grants[0].privateRoot
  });
  assert.equal(
    providerDispatchSha256(secret.executionCapability),
    grant.executionCapabilitySha256
  );
  assert.equal(secret.grantId, grant.grantId);
  const databaseRow = JSON.parse(fs.readFileSync(
    path.join(shared, "database-row.json"),
    "utf8"
  ));
  assert.equal(databaseRow.state, "EXECUTING");
  assert.equal(databaseRow.grantId, grant.grantId);
});

test("claim retries surfaced 40001 before effect, but begin ambiguity is never retried", async (t) => {
  const temporaryRoot = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-dispatch-retry-")
  );
  fs.chmodSync(temporaryRoot, 0o700);
  t.after(() => fs.rmSync(temporaryRoot, { force: true, recursive: true }));
  const privateRoot = directory(temporaryRoot, "private");
  const grantRoot = directory(temporaryRoot, "grant");
  const workerInput = Object.freeze({
    authenticatedPrincipal: "synthetic-principal",
    context: Object.freeze({ marker: "provider-free-context" })
  });
  const request = Object.freeze({
    binding: binding(),
    packageLockDigest: "8".repeat(64),
    schemaVersion: INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_SCHEMA,
    workerInput,
    workerSpecSha256: providerDispatchSha256(canonicalJson(workerInput))
  });
  let claimCalls = 0;
  let beginCalls = 0;
  let claimedInput;
  const claimControl = Object.freeze({
    async claim(controlBinding, input) {
      claimCalls += 1;
      if (claimCalls === 1) {
        const error = new Error("synthetic serialization retry");
        error.code = "40001";
        throw error;
      }
      claimedInput = input;
      return Object.freeze({
        authorizationId: controlBinding.authorizationId,
        controlBindingSha256: controlBinding.controlBindingSha256,
        databaseNow: controlBinding.issuedAt,
        expiresAt: controlBinding.expiresAt,
        grantId: input.grantId,
        mcpResultSha256: null,
        sessionCloseSha256: null,
        state: "GRANTED",
        transitionOutcome: "DISPATCH_GRANTED",
        workerSpecSha256: input.workerSpecSha256
      });
    }
  });
  const beginControl = Object.freeze({
    async begin() {
      beginCalls += 1;
      const error = new Error("synthetic lost begin acknowledgement");
      error.code = "08006";
      throw error;
    }
  });
  await assert.rejects(
    () => runIntegratedLiveDrillDispatchBroker({
      beginControl,
      brokerRootPath: privateRoot,
      claimControl,
      executionGrantPath: path.join(grantRoot, "execution-grant.json"),
      executionGrantRootPath: grantRoot,
      request
    }),
    /INTEGRATED_LIVE_DRILL_DISPATCH_BEGIN_AMBIGUOUS/u
  );
  assert.equal(claimCalls, 2);
  assert.equal(beginCalls, 1);
  assert.equal(typeof claimedInput?.executionCapabilitySha256, "string");
  assert.equal(fs.existsSync(path.join(grantRoot, "execution-grant.json")), false);
  assert.equal(brokerTest.providerControlRetryable({ code: "40001" }), true);
  assert.equal(brokerTest.providerControlRetryable({ code: "42501" }), false);
});
