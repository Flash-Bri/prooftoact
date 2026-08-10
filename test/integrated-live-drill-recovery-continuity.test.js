import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  integratedLiveDrillCanonicalSha256
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN,
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
  inspectIntegratedLiveDrillRecoveryContinuity,
  runIntegratedLiveDrillRecoveryContinuityW5,
  validateIntegratedLiveDrillRecoveryContinuityJournal
} from "../src/cloud/integrated-live-drill-recovery-continuity.js";

const WORKER = new URL(
  "./helpers/integrated-live-drill-recovery-continuity-worker.js",
  import.meta.url
);
const BASE_NOW = Date.parse("2026-08-10T12:00:00.000Z");
const FORBIDDEN_ROOT = fs.realpathSync(process.cwd());

function privateDirectory(prefix) {
  const directory = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), prefix)
  );
  fs.chmodSync(directory, 0o700);
  return fs.realpathSync(directory);
}

function fixture(t, prefix = "prooftoact-packet-b-", fakeDelayMs = 0) {
  const ledgerRootPath = privateDirectory(prefix);
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const authorizationId = "11111111-1111-4111-8111-111111111111";
  const runId = "22222222-2222-4222-8222-222222222222";
  const authorization = Object.freeze({
    attestation: Object.freeze({
      schemaVersion: "synthetic-test-authorization",
      payload: Object.freeze({ authorizationId, runId }),
      signature: "synthetic-test-only"
    }),
    issuedAt: BASE_NOW,
    expiresAt: BASE_NOW + 60_000,
    payload: Object.freeze({
      authorizationId,
      configDigest: "c".repeat(64),
      requiredRecoveryFailpoints: INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
      requiredRecoveryJournalEntryCount: 17,
      requiredRecoveryWorkers: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
      runId,
      sourceCommit: "a".repeat(40),
      treeDigest: "b".repeat(40)
    })
  });
  const candidateBody = Object.freeze({
    configDigest: authorization.payload.configDigest,
    providerBacked: false,
    recovery: Object.freeze({
      managedMcpCallCount: 1,
      managedMcpRequestPayloadSha256: "7".repeat(64)
    }),
    runId,
    sourceCommit: authorization.payload.sourceCommit,
    treeDigest: authorization.payload.treeDigest
  });
  const candidateReceipt = Object.freeze({
    ...candidateBody,
    receiptSha256: integratedLiveDrillCanonicalSha256(candidateBody)
  });
  const ledgerBody = Object.freeze({
    authorizationClaimSha256: "6".repeat(64),
    authorizationId,
    runId,
    schemaVersion: "synthetic-test-control-ledger"
  });
  const controlLedgerReceipt = Object.freeze({
    ...ledgerBody,
    receiptSha256: integratedLiveDrillCanonicalSha256(ledgerBody)
  });
  const value = Object.freeze({
    context: Object.freeze({
      authorization,
      candidateReceipt,
      controlLedgerReceipt,
      forbiddenRootPath: FORBIDDEN_ROOT,
      ledgerRootPath,
      mcpRequestSha256:
        candidateReceipt.recovery.managedMcpRequestPayloadSha256
    }),
    counterPath: path.join(ledgerRootPath, "fake-mcp-call-count.txt"),
    fakeDelayMs,
    now: BASE_NOW + 1_000
  });
  const fixturePath = path.join(ledgerRootPath, "worker-fixture.json");
  fs.writeFileSync(fixturePath, `${canonicalJson(value)}\n`, { mode: 0o600 });
  return Object.freeze({ ...value, fixturePath });
}

function sanitizedEnvironment(extra = {}) {
  return Object.freeze({
    PATH: process.env.PATH,
    ...extra
  });
}

function runWorker(value, worker, ...args) {
  return spawnSync(
    process.execPath,
    [WORKER.pathname, "--fixture", value.fixturePath, "--worker", worker, ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: sanitizedEnvironment()
    }
  );
}

function runWorkerAsync(value, worker, ...args) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [WORKER.pathname, "--fixture", value.fixturePath, "--worker", worker, ...args],
      {
        cwd: process.cwd(),
        env: sanitizedEnvironment(),
        stdio: ["ignore", "pipe", "pipe"]
      }
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function releaseBarrier(directory, expectedWorkers) {
  const deadline = Date.now() + 10_000;
  while (
    fs.readdirSync(directory).filter((name) => name.endsWith(".ready")).length <
      expectedWorkers
  ) {
    if (Date.now() >= deadline) {
      throw new Error("TEST_RECOVERY_CONTINUITY_BARRIER_TIMEOUT");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  fs.writeFileSync(path.join(directory, "release"), "release\n", {
    flag: "wx",
    mode: 0o600
  });
}

function callCount(value) {
  if (!fs.existsSync(value.counterPath)) return 0;
  return fs.readFileSync(value.counterPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .length;
}

function journalCount(value) {
  return fs.readdirSync(value.context.ledgerRootPath)
    .filter((name) => name.includes(".recovery-continuity."))
    .length;
}

test("five subprocess workers resume four failpoints with exactly one fake MCP call", (t) => {
  const value = fixture(t);
  let child = runWorker(
    value,
    "W1",
    "--crash-after",
    "PRE_READ_CHECKPOINT"
  );
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /SYNTHETIC_CRASH_PRE_READ_CHECKPOINT/u);
  assert.equal(journalCount(value), 3);
  assert.equal(runWorker(value, "W1").status, 0);
  assert.equal(journalCount(value), 4);

  child = runWorker(
    value,
    "W2",
    "--crash-after",
    "MCP_RESULT_AND_CLOSE_DURABLE"
  );
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /SYNTHETIC_CRASH_MCP_RESULT_AND_CLOSE_DURABLE/u);
  assert.equal(callCount(value), 1);
  assert.equal(journalCount(value), 8);
  child = runWorker(value, "W2", "--no-client");
  assert.equal(child.status, 0, child.stderr);
  assert.equal(callCount(value), 1);
  assert.equal(journalCount(value), 9);

  child = runWorker(
    value,
    "W3",
    "--crash-after",
    "TERMINAL_AUDIT_ROW_VISIBLE_ACK_LOSS"
  );
  assert.notEqual(child.status, 0);
  assert.equal(journalCount(value), 11);
  assert.equal(runWorker(value, "W3").status, 0);
  assert.equal(journalCount(value), 12);

  child = runWorker(
    value,
    "W4",
    "--crash-after",
    "RECEIPT_DURABLE_PUBLICATION_LOSS"
  );
  assert.notEqual(child.status, 0);
  assert.equal(journalCount(value), 14);
  assert.equal(runWorker(value, "W4").status, 0);
  assert.equal(journalCount(value), 15);

  child = runWorker(value, "W5", "--no-client");
  assert.equal(child.status, 0, child.stderr);
  assert.equal(journalCount(value), 17);
  assert.equal(callCount(value), 1);
  const receipt = validateIntegratedLiveDrillRecoveryContinuityJournal(
    value.context
  );
  assert.equal(receipt.status, INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE);
  assert.equal(receipt.entryCount, 17);
  assert.equal(receipt.entryDigests.length, 17);
  assert.equal(receipt.exactMcpCallClaimCount, 1);
  assert.equal(receipt.exactMcpDispatchMarkerCount, 1);
  assert.equal(receipt.reconciledWithoutRetry, true);
  assert.equal(receipt.providerBacked, false);
  assert.equal(receipt.providerCallCountProven, false);
  assert.equal(receipt.liveProviderDispatchAuthorizationProven, false);
  assert.equal(receipt.liveProviderBoundW1W5ContinuityProven, false);
  assert.equal(receipt.localSameHostScaffoldValidated, true);
  assert.match(receipt.claimBoundary, /Local same-host scaffold only/u);
  assert.match(
    receipt.claimBoundary,
    /actual provider-bound W1-W5 continuity remains unproven/u
  );
  assert.match(
    receipt.claimBoundary,
    /not independently anchored against same-owner full-chain rewriting/u
  );
  assert.equal(receipt.mcpResultSha256, "9".repeat(64));
  assert.equal(receipt.sessionClosed, true);
  assert.deepEqual(
    INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.map(({ sequence }) => sequence),
    Array.from({ length: 17 }, (_, index) => index + 1)
  );
});

test("only the O_EXCL claim creator dispatches across synchronized subprocess races", async (t) => {
  const rounds = 5;
  const workerCount = 8;
  for (let round = 0; round < rounds; round += 1) {
    const value = fixture(
      t,
      `prooftoact-packet-b-race-${round}-`,
      100
    );
    assert.equal(runWorker(value, "W1").status, 0);
    const barrierDirectory = path.join(
      value.context.ledgerRootPath,
      "w2-start-barrier"
    );
    fs.mkdirSync(barrierDirectory, { mode: 0o700 });
    const attemptsPromise = Promise.all(Array.from(
      { length: workerCount },
      () => runWorkerAsync(
        value,
        "W2",
        "--barrier-directory",
        barrierDirectory
      )
    ));
    await releaseBarrier(barrierDirectory, workerCount);
    const attempts = await attemptsPromise;
    assert.equal(
      attempts.every(({ status }) => status === 0),
      true,
      attempts.map(({ stderr }) => stderr).join("\n")
    );
    const dispositions = attempts.map(({ stdout }) => JSON.parse(stdout).status);
    assert.equal(
      dispositions.every((status) => [
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
      ].includes(status)),
      true
    );
    assert.equal(
      dispositions.filter(
        (status) => status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
      ).length >= workerCount - 1,
      true
    );
    assert.equal(callCount(value), 1);
    const claim = JSON.parse(fs.readFileSync(
      path.join(
        value.context.ledgerRootPath,
        fs.readdirSync(value.context.ledgerRootPath).find((name) =>
          name.includes("06.mcp-call-claimed")
        )
      ),
      "utf8"
    ));
    const dispatch = JSON.parse(fs.readFileSync(
      path.join(
        value.context.ledgerRootPath,
        fs.readdirSync(value.context.ledgerRootPath).find((name) =>
          name.includes("07.mcp-dispatch-marker-durable")
        )
      ),
      "utf8"
    ));
    assert.match(claim.artifact.attemptOwnershipTokenSha256, /^[0-9a-f]{64}$/u);
    assert.equal(
      dispatch.artifact.attemptOwnershipTokenSha256,
      claim.artifact.attemptOwnershipTokenSha256
    );
    assert.equal(
      [
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
      ].includes(
        inspectIntegratedLiveDrillRecoveryContinuity(value.context).status
      ),
      true
    );
  }
});

test("claimed call without durable completion is permanently unknown and never retried", (t) => {
  const value = fixture(t, "prooftoact-packet-b-unknown-");
  assert.equal(runWorker(value, "W1").status, 0);
  const crashed = runWorker(
    value,
    "W2",
    "--crash-after",
    "MCP_CALL_CLAIMED"
  );
  assert.notEqual(crashed.status, 0);
  assert.equal(journalCount(value), 6);
  assert.equal(callCount(value), 0);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const reconciled = runWorker(value, "W2");
    assert.equal(reconciled.status, 0, reconciled.stderr);
    assert.equal(
      JSON.parse(reconciled.stdout).status,
      INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
    );
    assert.equal(callCount(value), 0);
    assert.equal(journalCount(value), 6);
  }
  assert.deepEqual(
    inspectIntegratedLiveDrillRecoveryContinuity(value.context),
    { status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
      retryPermitted: false }
  );
  assert.equal(
    fs.readdirSync(value.context.ledgerRootPath).some((name) =>
      name.endsWith("recovery-continuity-unknown-do-not-act.json")
    ),
    true
  );
  assert.throws(
    () => validateIntegratedLiveDrillRecoveryContinuityJournal(value.context),
    /RECOVERY_CONTINUITY_AMBIGUOUS/u
  );
  const w5 = runWorker(value, "W5", "--no-client");
  assert.notEqual(w5.status, 0);
  assert.match(w5.stderr, /W5_RECONCILIATION_REJECTED/u);
});

test("W5 makes no ambient-credential claim, rejects a provider client, and journals reject tampering", (t) => {
  const value = fixture(t, "prooftoact-packet-b-w5-");
  assert.equal(runWorker(value, "W1").status, 0);
  assert.equal(runWorker(value, "W2").status, 0);
  assert.equal(runWorker(value, "W3").status, 0);
  assert.equal(runWorker(value, "W4").status, 0);
  const credentialFile = path.join(
    value.context.ledgerRootPath,
    "synthetic-credentials"
  );
  fs.writeFileSync(credentialFile, "[test]\nkey=value\n", { mode: 0o600 });
  const ambientCredentialConfiguration = spawnSync(
    process.execPath,
    [
      WORKER.pathname,
      "--fixture",
      value.fixturePath,
      "--worker",
      "W5",
      "--no-client"
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: sanitizedEnvironment({
        AWS_PROFILE: "test",
        AWS_SHARED_CREDENTIALS_FILE: credentialFile,
        MCP_API_KEY: "synthetic-test-only"
      })
    }
  );
  assert.equal(
    ambientCredentialConfiguration.status,
    0,
    ambientCredentialConfiguration.stderr
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW5(
      value.context,
      { now: value.now, providerClient: Object.freeze({}) }
    ),
    /W5_PROVIDER_CLIENT_REJECTED/u
  );
  const receipt = validateIntegratedLiveDrillRecoveryContinuityJournal(
    value.context
  );
  assert.equal(receipt.providerBacked, false);
  assert.equal(receipt.providerCallCountProven, false);
  assert.equal(receipt.liveProviderDispatchAuthorizationProven, false);
  const entry = fs.readdirSync(value.context.ledgerRootPath)
    .find((name) => name.includes("08.mcp-result-and-close-durable"));
  const entryPath = path.join(value.context.ledgerRootPath, entry);
  const parsed = JSON.parse(fs.readFileSync(entryPath, "utf8"));
  parsed.artifact.mcpResultSha256 = "0".repeat(64);
  fs.writeFileSync(entryPath, `${canonicalJson(parsed)}\n`, { mode: 0o600 });
  assert.throws(
    () => validateIntegratedLiveDrillRecoveryContinuityJournal(value.context),
    /RECOVERY_CONTINUITY_AMBIGUOUS/u
  );
});
