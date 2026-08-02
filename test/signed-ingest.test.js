import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { signedEvidencePayloadFor } from "../src/cloud/authority-store.js";
import { SignedEvidenceIngest } from "../src/cloud/signed-ingest.js";

const INPUT = Object.freeze({
  tenantId: "11111111-1111-4111-8111-111111111111",
  evidenceId: "22222222-2222-4222-8222-222222222222",
  incidentId: "33333333-3333-4333-8333-333333333333",
  issuer: "synthetic-county-sensor",
  agencyScope: "rescue",
  claimKey: "bridge_status",
  claimValue: "open",
  observedAt: "2026-08-01T23:00:00.000Z",
  validFrom: "2026-08-01T22:55:00.000Z",
  validUntil: "2026-08-02T00:00:00.000Z",
  conflictStatus: "none",
  assertion: "Synthetic bridge is open.",
  embedding: [0.8, 0.1, 0.1],
  verificationKeyId: "synthetic-ed25519-v1",
  verifierVersion: "gate1-ed25519-verifier-v1"
});

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  const signatureBase64 = sign(
    null,
    Buffer.from(signedEvidencePayloadFor(INPUT), "utf8"),
    privateKey
  ).toString("base64");
  return { publicKeySpkiBase64, signatureBase64 };
}

test("signed ingest resolves its exact receipt after COMMIT ACK loss", async () => {
  const { publicKeySpkiBase64, signatureBase64 } = fixture();
  const calls = [];
  const events = [];
  const client = {
    async query(text, values) {
      calls.push(text.trim().split(/\s+/u).slice(0, 2).join(" "));
      if (text.includes("g1_get_verification_key_v1")) {
        return {
          rowCount: 1,
          rows: [{
            status: "active",
            algorithm: "ed25519",
            issuer: INPUT.issuer,
            valid_from: "2026-08-01T00:00:00.000Z",
            valid_until: "2026-08-03T00:00:00.000Z",
            public_key_spki_base64: publicKeySpkiBase64
          }]
        };
      }
      if (text.includes("g1_append_verified_evidence_v2")) {
        return { rowCount: 1, rows: [{ evidence_id: values[1] }] };
      }
      if (text.includes("transaction_timestamp")) {
        return {
          rowCount: 1,
          rows: [{ database_now: new Date("2026-08-01T23:00:01.000Z") }]
        };
      }
      if (text.trim() === "COMMIT") {
        throw Object.assign(new Error("synthetic ACK loss"), {
          code: "ECONNRESET"
        });
      }
      return {};
    },
    release() { events.push("broken_released"); }
  };
  const ingest = new SignedEvidenceIngest({
    pool: { async connect() { return client; }, async end() {} },
    reconcile: async (evidence) => {
      events.push("reconciliation_started");
      return {
        rowCount: 1,
        rows: [{
          evidence_id: evidence.evidenceId,
          verification_request_digest: evidence.verificationRequestDigest,
          evidence_digest: evidence.evidenceDigest,
          outcome: "evidence_verified",
          database_now: new Date("2026-08-01T23:00:02.000Z")
        }]
      };
    }
  });

  const result = await ingest.appendVerified({ ...INPUT, signatureBase64 });
  assert.equal(result.outcome, "evidence_verified");
  assert.equal(result.commit.status, "COMMITTED");
  assert.equal(result.commit.observation, "read_reconciled");
  assert.equal(calls.includes("ROLLBACK"), false);
  assert.deepEqual(events, ["broken_released", "reconciliation_started"]);
});

test("signed ingest reconciles an unclassified post-COMMIT error without rollback", async () => {
  const { publicKeySpkiBase64, signatureBase64 } = fixture();
  const calls = [];
  const events = [];
  const client = {
    async query(text, values) {
      calls.push(text.trim().split(/\s+/u).slice(0, 2).join(" "));
      if (text.includes("g1_get_verification_key_v1")) {
        return {
          rowCount: 1,
          rows: [{
            status: "active",
            algorithm: "ed25519",
            issuer: INPUT.issuer,
            valid_from: "2026-08-01T00:00:00.000Z",
            valid_until: "2026-08-03T00:00:00.000Z",
            public_key_spki_base64: publicKeySpkiBase64
          }]
        };
      }
      if (text.includes("g1_append_verified_evidence_v2")) {
        return { rowCount: 1, rows: [{ evidence_id: values[1] }] };
      }
      if (text.includes("transaction_timestamp")) {
        return {
          rowCount: 1,
          rows: [{ database_now: new Date("2026-08-01T23:00:01.000Z") }]
        };
      }
      if (text.trim() === "COMMIT") {
        throw Object.assign(new Error("synthetic internal error"), {
          code: "XX000"
        });
      }
      return {};
    },
    release() { events.push("ambiguous_released"); }
  };
  const ingest = new SignedEvidenceIngest({
    pool: { async connect() { return client; }, async end() {} },
    reconcile: async (evidence) => {
      events.push("reconciliation_started");
      return {
        rowCount: 1,
        rows: [{
          evidence_id: evidence.evidenceId,
          verification_request_digest: evidence.verificationRequestDigest,
          evidence_digest: evidence.evidenceDigest,
          outcome: "evidence_verified",
          database_now: new Date("2026-08-01T23:00:02.000Z")
        }]
      };
    }
  });

  const output = await ingest.appendVerified({ ...INPUT, signatureBase64 });
  assert.equal(output.commit.observation, "read_reconciled");
  assert.equal(calls.includes("ROLLBACK"), false);
  assert.deepEqual(events, ["ambiguous_released", "reconciliation_started"]);
});
