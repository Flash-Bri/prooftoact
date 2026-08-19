import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync
} from "node:crypto";
import test from "node:test";

import {
  createCommittedRecoveryPublisherSigner,
  loadCommittedRecoveryPublisherSigner
} from "../scripts/lib/recovery-publisher-key.js";
import {
  assertRecoveryPublisherTrustRootWriteDenied,
  assertRecoveryRunnerBaseTableReadsDenied,
  assertSeparatedDatabaseEndpoints,
  resolveCommittedRecoveryAuditEvent,
  resolveCommittedRecoveryPublisherTrustRoot,
  resolveCommittedRecoverySourceReceipt,
  trustedPublisherKeysDigest
} from "../src/cloud/recovery-broker.js";

const TRUST_ROOT_SCHEMA = "tideproof.recovery-publisher-trust-root.v1";
const COMMITMENT_DOMAIN =
  "tideproof-recovery-publisher-trust-root-commitment-v1\n";

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  const publisherKeyId = "gate1-recovery-publisher-p256-v1";
  const publicKeySpkiBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  const trustRootJson = JSON.stringify({
    schemaVersion: TRUST_ROOT_SCHEMA,
    publisherKeyId,
    publicKeySpkiBase64
  });
  const trustRootCommitment = createHash("sha256")
    .update(`${COMMITMENT_DOMAIN}${trustRootJson}`)
    .digest("hex");
  const privateKeyPkcs8Base64 = privateKey
    .export({ type: "pkcs8", format: "der" })
    .toString("base64");
  return {
    publisherKeyId,
    publicKeySpkiBase64,
    trustRootJson,
    trustRootCommitment,
    privateKeyPkcs8Base64
  };
}

test("recovery publisher requires an independently committed matching trust root", () => {
  const input = fixture();
  const signer = createCommittedRecoveryPublisherSigner(input);

  assert.equal(signer.publisherKeyId, input.publisherKeyId);
  assert.equal(signer.publicKeySpkiBase64, input.publicKeySpkiBase64);
  assert.equal(signer.trustRootCommitment, input.trustRootCommitment);
  assert.deepEqual(signer.trustedPublisherKeys, {
    [input.publisherKeyId]: input.publicKeySpkiBase64
  });
});

test("recovery publisher rejects a changed root after commitment", () => {
  const input = fixture();
  const changed = JSON.parse(input.trustRootJson);
  changed.publisherKeyId = "changed-recovery-publisher-p256-v1";

  assert.throws(
    () =>
      createCommittedRecoveryPublisherSigner({
        ...input,
        trustRootJson: JSON.stringify(changed)
      }),
    /RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT_MISMATCH/
  );
});

test("recovery publisher rejects a signing key outside the committed root", () => {
  const input = fixture();
  const replacement = fixture();

  assert.throws(
    () =>
      createCommittedRecoveryPublisherSigner({
        ...input,
        privateKeyPkcs8Base64: replacement.privateKeyPkcs8Base64
      }),
    /RECOVERY_PUBLISHER_SIGNING_KEY_MISMATCH/
  );
});

test("recovery publisher environment loader keeps commitment and key separate", () => {
  const input = fixture();
  const signer = loadCommittedRecoveryPublisherSigner({
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT: input.trustRootJson,
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT:
      input.trustRootCommitment,
    RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64:
      input.privateKeyPkcs8Base64
  });

  assert.equal(signer.trustRootCommitment, input.trustRootCommitment);
  assert.throws(
    () => loadCommittedRecoveryPublisherSigner({}),
    /RECOVERY_PUBLISHER_TRUST_ROOT_REQUIRED/
  );
});

test("recovery publisher rejects noncanonical PKCS8 base64 padding", () => {
  const input = fixture();
  assert.throws(
    () =>
      createCommittedRecoveryPublisherSigner({
        ...input,
        privateKeyPkcs8Base64: `${input.privateKeyPkcs8Base64}====`
      }),
    /RECOVERY_PUBLISHER_PRIVATE_KEY_REQUIRED/
  );
});

test("primary-ledger commitment rejects coordinated root commitment and key replacement", async () => {
  const committedSigner = createCommittedRecoveryPublisherSigner(fixture());
  const replacementSigner = createCommittedRecoveryPublisherSigner(fixture());
  const committedKeySetDigest = trustedPublisherKeysDigest(
    committedSigner.trustedPublisherKeys
  );
  const clientFactory = () => ({
    async connect() {},
    async end() {},
    async query(_text, values) {
      const matches =
        values[1] === committedSigner.trustRootCommitment &&
        values[2] === committedKeySetDigest;
      return matches
        ? {
            rowCount: 1,
            rows: [{
              trust_root_id: "gate1-recovery-publisher-v1",
              trust_root_commitment: committedSigner.trustRootCommitment,
              publisher_key_set_digest: committedKeySetDigest,
              committed_at: new Date("2026-08-03T05:00:00.000Z"),
              database_now: new Date("2026-08-03T05:01:00.000Z")
            }]
          }
        : { rowCount: 0, rows: [] };
    }
  });

  const committed = await resolveCommittedRecoveryPublisherTrustRoot({
    trustRootCommitment: committedSigner.trustRootCommitment,
    publisherKeySetDigest: committedKeySetDigest,
    clientFactory
  });
  assert.equal(committed.trustRootCommitment, committedSigner.trustRootCommitment);

  await assert.rejects(
    resolveCommittedRecoveryPublisherTrustRoot({
      trustRootCommitment: replacementSigner.trustRootCommitment,
      publisherKeySetDigest: trustedPublisherKeysDigest(
        replacementSigner.trustedPublisherKeys
      ),
      clientFactory
    }),
    /RECOVERY_PUBLISHER_TRUST_ROOT_NOT_COMMITTED/
  );
});

test("recovery source principal resolves one current exact authority receipt", async () => {
  const evidenceDigest = "f".repeat(64);
  const selectedEvidenceBindingSha256 = createHash("sha256")
    .update(JSON.stringify({
      evidenceDigest,
      evidenceId: "44444444-4444-4444-8444-444444444444"
    }))
    .digest("hex");
  const binding = {
    tenantId: "11111111-1111-4111-8111-111111111111",
    runId: "22222222-2222-4222-8222-222222222222",
    incidentId: "33333333-3333-4333-8333-333333333333",
    evidenceId: "44444444-4444-4444-8444-444444444444",
    resourceId: "synthetic-rescue-unit-7",
    operationId: "55555555-5555-4555-8555-555555555555",
    requestDigest: "a".repeat(64),
    authorityEvidenceBindingSha256: "9".repeat(64),
    selectedEvidenceBindingSha256
  };
  const row = {
    tenant_id: binding.tenantId,
    run_id: binding.runId,
    incident_id: binding.incidentId,
    evidence_id: binding.evidenceId,
    resource_id: binding.resourceId,
    operation_id: binding.operationId,
    request_digest: binding.requestDigest,
    proposal_digest: "b".repeat(64),
    logical_action_digest: "c".repeat(64),
    authorization_epoch: "1",
    logical_authority_key_sha256: "d".repeat(64),
    authorization_binding_sha256: "e".repeat(64),
    policy_version: "gate1-policy-v2",
    agent_id: "synthetic-agent",
    agency: "rescue",
    outcome: "resource_reserved",
    reason: "admissible",
    evidence_digest: evidenceDigest,
    authority_evidence_binding_sha256:
      binding.authorityEvidenceBindingSha256,
    has_durable_intent: true,
    admissibility: "admissible",
    recorded_at: new Date("2026-08-03T05:00:00.000Z"),
    database_now: new Date("2026-08-03T05:01:00.000Z"),
    minimum_residual_ms: "1200000"
  };
  const clientFactoryFor = (resolvedRow = row) => () => ({
    async connect() {},
    async end() {},
    async query(text, values) {
      assert.match(text, /g1_resolve_recovery_source_receipt_v3/u);
      assert.deepEqual(values, [
        binding.tenantId,
        binding.runId,
        binding.incidentId,
        binding.evidenceId,
        binding.resourceId,
        binding.operationId,
        binding.requestDigest
      ]);
      return { rowCount: 1, rows: [resolvedRow] };
    }
  });
  const clientFactory = clientFactoryFor();

  const resolved = await resolveCommittedRecoverySourceReceipt({
    binding,
    clientFactory
  });
  assert.equal(resolved.operation_id, binding.operationId);
  assert.equal(
    resolved.authority_evidence_binding_sha256,
    binding.authorityEvidenceBindingSha256
  );
  assert.equal(resolved.admittedCount, 1);
  assert.equal(resolved.unresolvedCount, 0);

  await assert.rejects(
    resolveCommittedRecoverySourceReceipt({
      binding: {
        ...binding,
        authorityEvidenceBindingSha256: "8".repeat(64)
      },
      clientFactory
    }),
    /RECOVERY_SOURCE_DVI_BINDING_INVALID/
  );
  await assert.rejects(
    resolveCommittedRecoverySourceReceipt({
      binding: {
        ...binding,
        selectedEvidenceBindingSha256: "7".repeat(64)
      },
      clientFactory
    }),
    /RECOVERY_SOURCE_DVI_BINDING_INVALID/
  );
  await assert.rejects(
    resolveCommittedRecoverySourceReceipt({
      binding,
      clientFactory: clientFactoryFor({
        ...row,
        policy_version: "g1-admissibility-v2"
      })
    }),
    /RECOVERY_SOURCE_RECEIPT_INVALID/
  );
});

test("every primary recovery runner credential must be denied trust-root writes", async () => {
  const queries = [];
  const denied = await assertRecoveryPublisherTrustRootWriteDenied({
    credentialLabel: "unit-source",
    clientFactory: () => ({
      async connect() {},
      async end() {},
      async query(text) {
        queries.push(text.trim());
        if (
          /(?:UPDATE|DELETE FROM|INSERT INTO) tp_ledger\.g1_recovery_publisher_trust_roots/u.test(
            text
          )
        ) {
          const error = new Error("denied");
          error.code = "42501";
          throw error;
        }
        return { rowCount: 0, rows: [] };
      }
    })
  });
  assert.deepEqual(denied, { denied: true, sqlstate: "42501" });
  assert.deepEqual(
    queries.filter((query) => query === "BEGIN"),
    ["BEGIN", "BEGIN", "BEGIN", "BEGIN", "BEGIN", "BEGIN"]
  );
  assert.deepEqual(
    queries.filter((query) => query === "ROLLBACK"),
    ["ROLLBACK", "ROLLBACK", "ROLLBACK", "ROLLBACK", "ROLLBACK", "ROLLBACK"]
  );
  const updates = queries.filter((query) => query.startsWith("UPDATE "));
  assert.equal(updates.length, 4);
  for (const query of updates) {
    assert.doesNotMatch(query, /\bWHERE\b/u);
    assert.doesNotMatch(query, /=\s*(?:trust_root_id|trust_root_commitment|publisher_key_set_digest|committed_at)\b/u);
  }
  const deletes = queries.filter((query) => query.startsWith("DELETE FROM "));
  assert.equal(deletes.length, 1);
  assert.doesNotMatch(deletes[0], /\bWHERE\b/u);
  assert.ok(queries.some((query) => query.startsWith("INSERT INTO ")));

  const writableQueries = [];
  await assert.rejects(
    assertRecoveryPublisherTrustRootWriteDenied({
      credentialLabel: "unit-writable",
      clientFactory: () => ({
        async connect() {},
        async end() {},
        async query(text) {
          writableQueries.push(text.trim());
          return { rowCount: 1, rows: [] };
        }
      })
    }),
    /RECOVERY_RUNNER_CAN_REWRITE_PUBLISHER_TRUST_ROOT/
  );
  assert.equal(writableQueries[0], "BEGIN");
  assert.match(writableQueries[1], /^UPDATE tp_ledger\./u);
  assert.equal(writableQueries[2], "ROLLBACK");
  assert.equal(writableQueries.includes("COMMIT"), false);

  await assert.rejects(
    assertRecoveryPublisherTrustRootWriteDenied({
      credentialLabel: "unit-write-only-without-select",
      clientFactory: () => ({
        async connect() {},
        async end() {},
        async query(text) {
          if (text === "BEGIN" || text === "ROLLBACK") {
            return { rowCount: 0, rows: [] };
          }
          if (/^\s*INSERT INTO/u.test(text)) {
            const error = new Error("insert denied");
            error.code = "42501";
            throw error;
          }
          if (/\bWHERE\b/u.test(text) || /=\s*(?:trust_root_id|trust_root_commitment|publisher_key_set_digest|committed_at)\b/u.test(text)) {
            const error = new Error("select denied");
            error.code = "42501";
            throw error;
          }
          return { rowCount: 1, rows: [] };
        }
      })
    }),
    /RECOVERY_RUNNER_CAN_REWRITE_PUBLISHER_TRUST_ROOT/
  );
});

test("every primary recovery runner credential must be denied protected base-table reads", async () => {
  const queries = [];
  const denied = await assertRecoveryRunnerBaseTableReadsDenied({
    credentialLabel: "unit-source",
    clientFactory: () => ({
      async connect() {},
      async end() {},
      async query(text) {
        queries.push(text.trim());
        const error = new Error("denied");
        error.code = "42501";
        throw error;
      }
    })
  });
  assert.deepEqual(denied, {
    denied: true,
    sqlstate: "42501",
    tableCount: 22
  });
  assert.equal(queries.length, denied.tableCount);
  for (const query of queries) {
    assert.match(query, /^SELECT 1 FROM (?:tp_private|tp_ledger)\./u);
    assert.match(query, / LIMIT 1$/u);
  }

  await assert.rejects(
    assertRecoveryRunnerBaseTableReadsDenied({
      credentialLabel: "unit-readable",
      clientFactory: () => ({
        async connect() {},
        async end() {},
        async query() {
          return { rowCount: 0, rows: [] };
        }
      })
    }),
    /RECOVERY_RUNNER_CAN_READ_PROTECTED_BASE_TABLE/
  );
});

test("primary source and audit credentials must bind one exact endpoint", () => {
  const binding = {
    primaryConnectionString:
      "postgresql://source@primary.example:26257/tideproof?sslmode=verify-full",
    primaryAuditConnectionString:
      "postgresql://audit@primary.example:26257/tideproof?sslmode=verify-full",
    recoveryConnectionString:
      "postgresql://publisher@recovery.example:26257/defaultdb?sslmode=verify-full",
    expectedPrimaryHostname: "primary.example",
    expectedRecoveryHostname: "recovery.example",
    primaryClusterId: "11111111-1111-4111-8111-111111111111",
    recoveryClusterId: "22222222-2222-4222-8222-222222222222"
  };
  assert.equal(
    assertSeparatedDatabaseEndpoints(binding).primaryAuditHostname,
    "primary.example"
  );
  for (const changedAuditUrl of [
    "postgresql://audit@other.example:26257/tideproof?sslmode=verify-full",
    "postgresql://audit@primary.example:26258/tideproof?sslmode=verify-full",
    "postgresql://audit@primary.example:26257/other?sslmode=verify-full"
  ]) {
    assert.throws(
      () => assertSeparatedDatabaseEndpoints({
        ...binding,
        primaryAuditConnectionString: changedAuditUrl
      }),
      /RECOVERY_(?:DATABASE_HOST|PRIMARY_CREDENTIAL_ENDPOINT)_MISMATCH/
    );
  }
});

test("recovery audit evidence is re-read only by exact id and digest", async () => {
  const tenantId = "11111111-1111-4111-8111-111111111111";
  const eventId = "66666666-6666-4666-8666-666666666666";
  const eventDigest = "9".repeat(64);
  const resolved = await resolveCommittedRecoveryAuditEvent({
    tenantId,
    eventId,
    eventDigest,
    clientFactory: () => ({
      async connect() {},
      async end() {},
      async query(text, values) {
        assert.match(text, /g1_resolve_recovery_audit_event_v1/u);
        assert.deepEqual(values, [eventId, tenantId, eventDigest]);
        return {
          rowCount: 1,
          rows: [{
            tenant_id: tenantId,
            event_id: eventId,
            event_digest: eventDigest,
            phase: "pre_read"
          }]
        };
      }
    })
  });
  assert.equal(resolved.phase, "pre_read");
});
