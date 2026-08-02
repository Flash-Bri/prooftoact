import assert from "node:assert/strict";
import test from "node:test";

import {
  RecoveryAuditSink,
  recoveryAuditEventDigest
} from "../src/cloud/recovery-broker.js";

const EVENT = Object.freeze({
  eventId: "11111111-1111-4111-8111-111111111111",
  tenantId: "22222222-2222-4222-8222-222222222222",
  interactionId: "33333333-3333-4333-8333-333333333333",
  recoverySessionId: "44444444-4444-4444-8444-444444444444",
  callerSubjectHash: "a".repeat(64),
  phase: "pre_read",
  recoveryClusterId: "55555555-5555-4555-8555-555555555555",
  brokerConfigDigest: "b".repeat(64),
  queryTemplateDigest: "c".repeat(64),
  boundInputDigest: "d".repeat(64),
  resultDigest: null,
  sourceWatermark: null,
  outcome: "read_authorized",
  errorCode: null,
  startedAt: "2026-08-01T23:00:00.000Z",
  completedAt: "2026-08-01T23:00:00.100Z"
});

test("recovery audit resolves its exact event after COMMIT ACK loss", async () => {
  const eventDigest = recoveryAuditEventDigest(EVENT);
  const events = [];
  let clients = 0;
  const clientFactory = () => {
    clients += 1;
    const reconciliation = clients === 2;
    return {
      async connect() {},
      async end() {
        events.push(reconciliation ? "reconciliation_closed" : "broken_closed");
      },
      async query(text) {
        if (reconciliation) {
          if (text.includes("g1_resolve_recovery_audit_event_v1")) {
            events.push("reconciliation_started");
            return {
              rowCount: 1,
              rows: [{
                event_id: EVENT.eventId,
                event_digest: eventDigest,
                outcome: EVENT.outcome,
                database_now: new Date("2026-08-01T23:00:01.000Z")
              }]
            };
          }
          throw new Error("unexpected reconciliation query");
        }
        if (text.includes("g1_append_recovery_audit_event_v3")) {
          return { rowCount: 1, rows: [{ event_id: EVENT.eventId }] };
        }
        if (text.includes("transaction_timestamp")) {
          return {
            rowCount: 1,
            rows: [{
              database_now: new Date("2026-08-01T23:00:00.500Z")
            }]
          };
        }
        if (text.trim() === "COMMIT") {
          throw Object.assign(new Error("synthetic audit ACK loss"), {
            code: "ECONNRESET"
          });
        }
        return {};
      }
    };
  };
  const sink = new RecoveryAuditSink({ clientFactory });
  const result = await sink.append(EVENT);

  assert.equal(result.eventId, EVENT.eventId);
  assert.equal(result.commit.status, "COMMITTED");
  assert.equal(result.commit.observation, "read_reconciled");
  assert.equal(clients, 2);
  assert.deepEqual(events, [
    "broken_closed",
    "reconciliation_started",
    "reconciliation_closed"
  ]);
});

test("recovery audit reconciles an unclassified post-COMMIT error without rollback", async () => {
  const eventDigest = recoveryAuditEventDigest(EVENT);
  const calls = [];
  const events = [];
  let clients = 0;
  const clientFactory = () => {
    clients += 1;
    const reconciliation = clients === 2;
    return {
      async connect() {},
      async end() {
        events.push(reconciliation ? "reconciliation_closed" : "ambiguous_closed");
      },
      async query(text) {
        calls.push(text.trim().split(/\s+/u)[0]);
        if (reconciliation) {
          if (text.includes("g1_resolve_recovery_audit_event_v1")) {
            events.push("reconciliation_started");
            return {
              rowCount: 1,
              rows: [{
                event_id: EVENT.eventId,
                event_digest: eventDigest,
                outcome: EVENT.outcome,
                database_now: new Date("2026-08-01T23:00:01.000Z")
              }]
            };
          }
          throw new Error("unexpected reconciliation query");
        }
        if (text.includes("g1_append_recovery_audit_event_v3")) {
          return { rowCount: 1, rows: [{ event_id: EVENT.eventId }] };
        }
        if (text.includes("transaction_timestamp")) {
          return {
            rowCount: 1,
            rows: [{ database_now: new Date("2026-08-01T23:00:00.500Z") }]
          };
        }
        if (text.trim() === "COMMIT") {
          throw Object.assign(new Error("synthetic internal error"), {
            code: "XX000"
          });
        }
        return {};
      }
    };
  };
  const sink = new RecoveryAuditSink({ clientFactory });
  const output = await sink.append(EVENT);

  assert.equal(output.commit.observation, "read_reconciled");
  assert.equal(calls.includes("ROLLBACK"), false);
  assert.deepEqual(events, [
    "ambiguous_closed",
    "reconciliation_started",
    "reconciliation_closed"
  ]);
});
