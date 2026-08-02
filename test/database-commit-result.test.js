import assert from "node:assert/strict";
import test from "node:test";

import {
  committedDatabaseResult,
  databaseTimestampFromDriver,
  nonDurableDatabaseResult,
  unknownDatabaseResult
} from "../src/cloud/database-commit-result.js";

const DIGEST = "a".repeat(64);
const DATABASE_NOW = "2026-08-01T23:30:00.000Z";

test("direct ACK and read reconciliation share one exact commit schema", () => {
  const direct = committedDatabaseResult({
    operation: "authority",
    operationDigest: DIGEST,
    observation: "direct_ack",
    databaseNow: DATABASE_NOW,
    outcome: "resource_reserved",
    authorityCurrent: true,
    requiresFreshAuthorization: false
  });
  const reconciled = committedDatabaseResult({
    operation: "authority",
    operationDigest: DIGEST,
    observation: "read_reconciled",
    databaseNow: DATABASE_NOW,
    outcome: "resource_reserved",
    authorityCurrent: true,
    requiresFreshAuthorization: false
  });

  assert.deepEqual(Object.keys(reconciled), Object.keys(direct));
  assert.deepEqual(Object.keys(reconciled.authority), Object.keys(direct.authority));
  assert.equal(direct.schemaVersion, "tideproof.database-commit-result.v1");
  assert.equal(direct.status, "COMMITTED");
  assert.equal(reconciled.status, "COMMITTED");
  assert.equal(direct.observation, "direct_ack");
  assert.equal(reconciled.observation, "read_reconciled");
});

test("stale or denied durable history requires fresh authorization", () => {
  const stale = committedDatabaseResult({
    operation: "authority",
    operationDigest: DIGEST,
    observation: "read_reconciled",
    databaseNow: DATABASE_NOW,
    outcome: "resource_reserved",
    authorityCurrent: false,
    requiresFreshAuthorization: true
  });
  const denied = committedDatabaseResult({
    operation: "authority",
    operationDigest: DIGEST,
    observation: "direct_ack",
    databaseNow: DATABASE_NOW,
    outcome: "authorization_denied",
    authorityCurrent: false,
    requiresFreshAuthorization: true,
    reason: "proposal_expired"
  });

  assert.equal(stale.status, "COMMITTED_BUT_NO_LONGER_CURRENT");
  assert.equal(stale.authority.requiresFreshAuthorization, true);
  assert.equal(denied.status, "COMMITTED");
  assert.equal(denied.authority.requiresFreshAuthorization, true);
  assert.equal(denied.reason, "proposal_expired");
});

test("unknown reconciliation never invents database time or a commit", () => {
  const unknown = unknownDatabaseResult({
    operation: "signed_ingest",
    operationDigest: DIGEST,
    reason: "terminal_receipt_not_observed"
  });

  assert.deepEqual(unknown, {
    schemaVersion: "tideproof.database-commit-result.v1",
    status: "UNKNOWN_DO_NOT_ACT",
    operation: "signed_ingest",
    operationDigest: DIGEST,
    observation: "read_reconciled",
    databaseNow: null,
    outcome: null,
    authority: {
      current: null,
      requiresFreshAuthorization: true
    },
    reason: "terminal_receipt_not_observed"
  });
});

test("a direct non-durable denial never claims a committed receipt", () => {
  const denied = nonDurableDatabaseResult({
    operation: "authority",
    operationDigest: DIGEST,
    databaseNow: DATABASE_NOW,
    outcome: "authorization_denied",
    reason: "proposal_authorization_expired"
  });

  assert.deepEqual(Object.keys(denied), [
    "schemaVersion",
    "status",
    "operation",
    "operationDigest",
    "observation",
    "databaseNow",
    "outcome",
    "authority",
    "reason"
  ]);
  assert.equal(denied.status, "DENIED_NOT_DURABLE");
  assert.equal(denied.observation, "direct_ack");
  assert.equal(denied.authority.current, false);
  assert.equal(denied.authority.requiresFreshAuthorization, true);
  assert.equal("committedOperationId" in denied, false);
  assert.equal("committedRequestDigest" in denied, false);
});

test("non-durable results reject positive outcomes and reconciled claims", () => {
  assert.throws(
    () => nonDurableDatabaseResult({
      operation: "authority",
      operationDigest: DIGEST,
      databaseNow: DATABASE_NOW,
      outcome: "resource_reserved",
      reason: "not_durable"
    }),
    /DATABASE_COMMIT_OUTCOME_INVALID/u
  );
  assert.throws(
    () => nonDurableDatabaseResult({
      operation: "authority",
      operationDigest: DIGEST,
      observation: "read_reconciled",
      databaseNow: DATABASE_NOW,
      outcome: "authorization_denied",
      reason: "proposal_authorization_expired"
    }),
    /DATABASE_COMMIT_OBSERVATION_INVALID/u
  );
});

test("commit schema rejects client clocks and contradictory authority state", () => {
  assert.throws(
    () => committedDatabaseResult({
      operation: "authority",
      operationDigest: DIGEST,
      observation: "direct_ack",
      databaseNow: new Date(DATABASE_NOW),
      outcome: "resource_reserved",
      authorityCurrent: true,
      requiresFreshAuthorization: false
    }),
    /DATABASE_COMMIT_TIME_INVALID/u
  );
  assert.throws(
    () => committedDatabaseResult({
      operation: "authority",
      operationDigest: DIGEST,
      observation: "direct_ack",
      databaseNow: Date.now(),
      outcome: "resource_reserved",
      authorityCurrent: true,
      requiresFreshAuthorization: false
    }),
    /DATABASE_COMMIT_TIME_INVALID/u
  );
  assert.throws(
    () => committedDatabaseResult({
      operation: "authority",
      operationDigest: DIGEST,
      observation: "direct_ack",
      databaseNow: DATABASE_NOW,
      outcome: "authorization_denied",
      authorityCurrent: true,
      requiresFreshAuthorization: false
    }),
    /DATABASE_COMMIT_AUTHORITY_INVALID/u
  );
  assert.throws(
    () => committedDatabaseResult({
      operation: "signed_ingest",
      operationDigest: DIGEST,
      observation: "direct_ack",
      databaseNow: DATABASE_NOW,
      outcome: "evidence_verified",
      authorityCurrent: null,
      requiresFreshAuthorization: false
    }),
    /DATABASE_COMMIT_AUTHORITY_INVALID/u
  );
});

test("trusted pg TIMESTAMPTZ values normalize before commit construction", () => {
  const driverTime = new Date(DATABASE_NOW);
  assert.equal(databaseTimestampFromDriver(driverTime), DATABASE_NOW);
  assert.equal(databaseTimestampFromDriver(DATABASE_NOW), DATABASE_NOW);
  assert.throws(
    () => databaseTimestampFromDriver(Date.now()),
    /DATABASE_COMMIT_TIME_INVALID/u
  );
});
