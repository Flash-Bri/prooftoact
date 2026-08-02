import assert from "node:assert/strict";
import test from "node:test";

import {
  appendRecoveryBundleWithClient
} from "../src/cloud/recovery-security.js";

const BUNDLE = Object.freeze({
  tenantId: "11111111-1111-4111-8111-111111111111",
  recoverySessionId: "22222222-2222-4222-8222-222222222222",
  subjectBindingHash: "a".repeat(64),
  schemaVersion: 2,
  snapshotVersion: 1,
  sourceClusterId: "33333333-3333-4333-8333-333333333333",
  sourceCommitTs: "2026-08-01T00:00:00.000Z",
  sourceDigest: "b".repeat(64),
  bundleDigest: "c".repeat(64),
  policyVersion: "gate1-policy-v2",
  publisherKeyId: "synthetic-key",
  publisherVersion: "tideproof-recovery-publisher-v2",
  signatureAlgorithm: "ecdsa-p256-sha256",
  sourceSignatureBase64: Buffer.alloc(64, 1).toString("base64"),
  signatureDigest: "d".repeat(64),
  checkpointSummary: { checkpointVersion: 1 },
  evidenceSummary: { admittedCount: 1 },
  conflictSummary: { unresolvedCount: 0 },
  receiptSummary: { outcome: "resource_reserved" },
  expiresAt: "2026-08-01T01:00:00.000Z"
});
function result() {
  return {
    rowCount: 1,
    rows: [{
      bundle_digest: BUNDLE.bundleDigest,
      outcome: "bundle_appended",
      database_now: new Date("2026-08-01T00:00:01.000Z")
    }]
  };
}

function sqlState(code, message = code) {
  return Object.assign(new Error(message), { code });
}

test("recovery publisher succeeds without retry", async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u).slice(0, 2).join(" "));
      return text.includes("append_recovery_bundle_v2") ? result() : {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE);
  assert.equal(output.outcome, "bundle_appended");
  assert.equal(output.commit.observation, "direct_ack");
  assert.equal(output.commit.outcome, "bundle_present");
  assert.deepEqual(calls, ["BEGIN TRANSACTION", "SELECT *", "COMMIT"]);
});

test("recovery publisher resolves an exact receipt after COMMIT ACK loss", async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u).slice(0, 2).join(" "));
      if (text.includes("append_recovery_bundle_v2")) return result();
      if (text.trim() === "COMMIT") throw sqlState("ECONNRESET");
      return {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE, {
    reconcile: async () => ({
      rowCount: 1,
      rows: [{
        bundle_digest: BUNDLE.bundleDigest,
        outcome: "bundle_present",
        database_now: new Date("2026-08-01T00:00:02.000Z")
      }]
    })
  });

  assert.equal(output.outcome, "bundle_present");
  assert.equal(output.commit.status, "COMMITTED");
  assert.equal(output.commit.observation, "read_reconciled");
  assert.equal(output.commit.outcome, "bundle_present");
  assert.notEqual(output.outcome, "bundle_appended");
  assert.notEqual(output.outcome, "bundle_replay");
  assert.deepEqual(calls, ["BEGIN TRANSACTION", "SELECT *", "COMMIT"]);
});

test("recovery publisher never rolls back an unclassified post-COMMIT error", async () => {
  const calls = [];
  const events = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u)[0]);
      if (text.includes("append_recovery_bundle_v2")) return result();
      if (text.trim() === "COMMIT") throw sqlState("XX000");
      return {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE, {
    beforeReconcile: async () => events.push("ambiguous_closed"),
    reconcile: async () => {
      events.push("reconciliation_started");
      return {
        rowCount: 1,
        rows: [{
          bundle_digest: BUNDLE.bundleDigest,
          outcome: "bundle_present",
          database_now: new Date("2026-08-01T00:00:02.000Z")
        }]
      };
    }
  });

  assert.equal(output.commit.observation, "read_reconciled");
  assert.equal(calls.includes("ROLLBACK"), false);
  assert.deepEqual(events, ["ambiguous_closed", "reconciliation_started"]);
});

test("recovery publisher retries only a rolled-back serialization failure", async () => {
  const calls = [];
  const sleeps = [];
  let appendCalls = 0;
  const client = {
    async query(text) {
      const operation = text.trim().split(/\s+/u).slice(0, 2).join(" ");
      calls.push(operation);
      if (text.includes("append_recovery_bundle_v2")) {
        appendCalls += 1;
        if (appendCalls === 1) throw sqlState("40001");
        return result();
      }
      return {};
    }
  };
  await appendRecoveryBundleWithClient(client, BUNDLE, {
    now: () => 0,
    sleep: async (delay) => sleeps.push(delay)
  });
  assert.deepEqual(calls, [
    "BEGIN TRANSACTION",
    "SELECT *",
    "ROLLBACK",
    "BEGIN TRANSACTION",
    "SELECT *",
    "COMMIT"
  ]);
  assert.deepEqual(sleeps, [25]);
});

test("recovery publisher retries a serialization failure returned by COMMIT", async () => {
  const calls = [];
  let commitCalls = 0;
  const client = {
    async query(text) {
      const operation = text.trim().split(/\s+/u).slice(0, 2).join(" ");
      calls.push(operation);
      if (text.includes("append_recovery_bundle_v2")) return result();
      if (text.trim() === "COMMIT") {
        commitCalls += 1;
        if (commitCalls === 1) throw sqlState("40001");
      }
      return {};
    }
  };
  const output = await appendRecoveryBundleWithClient(client, BUNDLE, {
    now: () => 0,
    sleep: async () => {}
  });
  assert.equal(output.outcome, "bundle_appended");
  assert.equal(calls.includes("ROLLBACK"), true);
  assert.equal(commitCalls, 2);
});

test("recovery publisher bounds its retry deadline and attempts", async () => {
  const alwaysConflict = {
    async query(text) {
      if (text.includes("append_recovery_bundle_v2")) {
        throw sqlState("40001");
      }
      return {};
    }
  };
  let clock = 0;
  await assert.rejects(
    appendRecoveryBundleWithClient(alwaysConflict, BUNDLE, {
      now: () => clock,
      sleep: async (delay) => { clock += delay; },
      retryDeadlineMs: 25
    }),
    ({ code }) => code === "RECOVERY_PUBLISH_RETRY_DEADLINE_EXCEEDED"
  );
  await assert.rejects(
    appendRecoveryBundleWithClient(alwaysConflict, BUNDLE, {
      now: () => 0,
      sleep: async () => {},
      maxAttempts: 2
    }),
    ({ code }) => code === "RECOVERY_PUBLISH_RETRY_LIMIT_EXCEEDED"
  );
});

test("recovery publisher never retries or rolls back ambiguous transport errors", async () => {
  for (const error of [
    sqlState("40003"),
    sqlState("ECONNRESET"),
    new Error("Query read timeout")
  ]) {
    const calls = [];
    const client = {
      async query(text) {
        calls.push(text.trim().split(/\s+/u)[0]);
        if (text.includes("append_recovery_bundle_v2")) throw error;
        return {};
      }
    };
    await assert.rejects(
      appendRecoveryBundleWithClient(client, BUNDLE),
      error
    );
    assert.deepEqual(calls, ["BEGIN", "SELECT"]);
  }
});

test("recovery publisher stops when rollback fails", async () => {
  const client = {
    async query(text) {
      if (text.includes("append_recovery_bundle_v2")) {
        throw sqlState("40001");
      }
      if (text.trim() === "ROLLBACK") {
        throw new Error("synthetic rollback failure");
      }
      return {};
    }
  };
  await assert.rejects(
    appendRecoveryBundleWithClient(client, BUNDLE),
    ({ code }) => code === "RECOVERY_PUBLISH_ROLLBACK_FAILED"
  );
});

test("recovery publisher does not roll back a committed receipt mismatch", async () => {
  const calls = [];
  const client = {
    async query(text) {
      calls.push(text.trim().split(/\s+/u)[0]);
      if (text.includes("append_recovery_bundle_v2")) {
        return {
          rowCount: 1,
          rows: [{ bundle_digest: "f".repeat(64), outcome: "bundle_appended" }]
        };
      }
      return {};
    }
  };
  await assert.rejects(
    appendRecoveryBundleWithClient(client, BUNDLE),
    /previously used with different input/u
  );
  assert.deepEqual(calls, ["BEGIN", "SELECT", "COMMIT"]);
});
