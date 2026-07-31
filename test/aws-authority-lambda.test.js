import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const authority = require("../infra/aws/lambda/authority.cjs").__test;

const FIXTURE = Object.freeze({
  tenantId: "11111111-1111-4111-8111-111111111111",
  runId: "22222222-2222-4222-8222-222222222222",
  incidentId: "33333333-3333-4333-8333-333333333333",
  evidenceId: "44444444-4444-4444-8444-444444444444",
  raceId: "55555555-5555-4555-8555-555555555555",
  resourceId: "synthetic-rescue-unit-aws-proof"
});

const CONNECTION_STRING =
  "postgresql://tp_authorizer_user:0123456789abcdef@synthetic.cockroachlabs.cloud/tideproof?sslmode=verify-full";

function configureEnvironment() {
  Object.assign(process.env, {
    AUTHORITY_DATABASE_SECRET_ARN:
      "arn:aws:secretsmanager:us-east-1:111111111111:secret:tideproof/authorizer-AbCd12",
    AUTHORITY_TENANT_ID: FIXTURE.tenantId,
    AUTHORITY_RUN_ID: FIXTURE.runId,
    AUTHORITY_INCIDENT_ID: FIXTURE.incidentId,
    AUTHORITY_EVIDENCE_ID: FIXTURE.evidenceId,
    AUTHORITY_RACE_ID: FIXTURE.raceId,
    AUTHORITY_RESOURCE_ID: FIXTURE.resourceId,
    SOURCE_COMMIT: "a".repeat(40),
    CONFIG_DIGEST: "b".repeat(64),
    TREE_DIGEST: "c".repeat(40),
    PACKAGE_LOCK_DIGEST: "d".repeat(64),
    AUTHORITY_SOURCE_DIGEST: "e".repeat(64),
    AUTHORITY_ARTIFACT_DIGEST: "f".repeat(64),
    AWS_LAMBDA_FUNCTION_VERSION: "7"
  });
}

function validEvent(contender = "alpha") {
  return {
    schemaVersion: authority.REQUEST_SCHEMA,
    mode: "reserve",
    raceId: FIXTURE.raceId,
    contender
  };
}

function proofEvent() {
  return {
    schemaVersion: authority.REQUEST_SCHEMA,
    mode: "proof",
    raceId: FIXTURE.raceId
  };
}

function spendRow(request, outcome = "resource_reserved") {
  const winner = outcome === "resource_reserved";
  return {
    decision_outcome: outcome,
    decision_reason: winner ? null : "active_holder",
    decision_fencing_token: winner ? "1" : null,
    decision_lease_expires_at: winner
      ? "2026-08-01T12:05:00.000Z"
      : null,
    decision_operation_id: request.operationId,
    decision_request_digest: request.requestDigest,
    decision_replay_kind: null
  };
}

function successfulClient(request, options = {}) {
  const queries = [];
  return {
    queries,
    ended: false,
    async connect() {
      queries.push("CONNECT");
    },
    async query(sql) {
      queries.push(sql);
      if (sql === "SHOW TRANSACTION ISOLATION LEVEL") {
        return {
          rowCount: 1,
          rows: [{ transaction_isolation: "serializable" }]
        };
      }
      if (sql.includes("pg_backend_pid")) {
        return {
          rowCount: 1,
          rows: [
            {
              backend_id: "812345",
              started_at: "2026-08-01T12:00:00.000Z"
            }
          ]
        };
      }
      if (sql.includes("completed_at")) {
        return {
          rowCount: 1,
          rows: [
            { completed_at: "2026-08-01T12:00:01.000Z" }
          ]
        };
      }
      if (sql === authority.SPEND_SQL) {
        if (options.spendError) {
          throw options.spendError;
        }
        return {
          rowCount: 1,
          rows: [
            spendRow(request, options.outcome ?? "resource_reserved")
          ]
        };
      }
      if (sql === "COMMIT" && options.commitError) {
        throw options.commitError;
      }
      return { rowCount: 0, rows: [] };
    },
    async end() {
      this.ended = true;
    }
  };
}

function resolvedClient(request, outcome = "resource_reserved") {
  return {
    ended: false,
    async connect() {},
    async query(sql) {
      if (sql === authority.RESOLVE_SQL) {
        return {
          rowCount: 1,
          rows: [
            {
              operation_id: request.operationId,
              request_digest: request.requestDigest,
              outcome,
              reason: null,
              fencing_token:
                outcome === "resource_reserved" ? "1" : null,
              lease_expires_at:
                outcome === "resource_reserved"
                  ? "2026-08-01T12:05:00.000Z"
                  : null,
              outbox_intent_id:
                outcome === "resource_reserved"
                  ? "66666666-6666-4666-8666-666666666666"
                  : null,
              current_fence:
                outcome === "resource_reserved" ? "1" : null,
              active_run_id: request.runId,
              holder_operation_id:
                outcome === "resource_reserved"
                  ? request.operationId
                  : null
            }
          ]
        };
      }
      return { rowCount: 0, rows: [] };
    },
    async end() {
      this.ended = true;
    }
  };
}

function proofRow(config, changes = {}) {
  const alpha = authority.authorityRequestFor(
    validEvent("alpha"),
    config
  );
  const bravo = authority.authorityRequestFor(
    validEvent("bravo"),
    config
  );
  return {
    active_run_id: config.runId,
    current_fence: "1",
    holder_operation_id: alpha.operationId,
    race_receipt_count: "2",
    resource_receipt_count: "2",
    reserved_count: "1",
    held_denial_count: "1",
    pending_count: "0",
    outbox_count: "1",
    outbox_operation_id: alpha.operationId,
    protected_effect_count: "0",
    alpha_outcome: "resource_reserved",
    alpha_reason: null,
    alpha_fencing_token: "1",
    alpha_observed_holder_operation_id: null,
    alpha_observed_fence: null,
    bravo_outcome: "resource_held_denied",
    bravo_reason: "active_holder",
    bravo_fencing_token: null,
    bravo_observed_holder_operation_id: alpha.operationId,
    bravo_observed_fence: "1",
    observed_at: "2026-08-01T12:00:04.000Z",
    ...changes
  };
}

function proofClient(row) {
  const queries = [];
  return {
    queries,
    ended: false,
    async connect() {
      queries.push("CONNECT");
    },
    async query(sql) {
      queries.push(sql);
      if (sql === "SHOW TRANSACTION ISOLATION LEVEL") {
        return {
          rowCount: 1,
          rows: [{ transaction_isolation: "serializable" }]
        };
      }
      if (sql.includes("pg_backend_pid")) {
        return {
          rowCount: 1,
          rows: [{ backend_id: "812346" }]
        };
      }
      if (sql === authority.PROOF_SQL) {
        return { rowCount: 1, rows: [row] };
      }
      return { rowCount: 0, rows: [] };
    },
    async end() {
      this.ended = true;
    }
  };
}

test("authority derives capability fields from one exact two-contender request", () => {
  configureEnvironment();
  const config = authority.configuration();
  const alpha = authority.authorityRequestFor(validEvent("alpha"), config);
  const alphaReplay = authority.authorityRequestFor(
    validEvent("alpha"),
    config
  );
  const bravo = authority.authorityRequestFor(
    validEvent("bravo"),
    config
  );

  assert.deepEqual(alpha, alphaReplay);
  assert.notEqual(alpha.operationId, bravo.operationId);
  assert.notEqual(alpha.effectKey, bravo.effectKey);
  assert.notEqual(alpha.requestDigest, bravo.requestDigest);
  assert.equal(alpha.agentId, "aws-authority-alpha");
  assert.equal(alpha.payload.action, "dispatch_rescue_unit");
  assert.match(alpha.operationId, /^[0-9a-f-]{36}$/);

  for (const event of [
    { ...validEvent(), authorize: true },
    { ...validEvent(), raceId: FIXTURE.runId },
    { ...validEvent(), contender: "model-selected" },
    { mode: "reserve" }
  ]) {
    assert.throws(
      () => authority.authorityRequestFor(event, config),
      /AUTHORITY_REQUEST_REJECTED/
    );
  }
});

test("authority accepts only one exact current least-privilege secret", () => {
  configureEnvironment();
  const arn = process.env.AUTHORITY_DATABASE_SECRET_ARN;
  const valid = {
    ARN: arn,
    SecretString: JSON.stringify({
      connectionString: CONNECTION_STRING
    }),
    VersionStages: ["AWSCURRENT"]
  };
  assert.equal(
    authority.connectionStringFromSecret(valid, arn),
    CONNECTION_STRING
  );

  for (const changed of [
    { ...valid, ARN: `${arn}-other` },
    { ...valid, VersionStages: ["AWSPREVIOUS"] },
    {
      ...valid,
      SecretString: JSON.stringify({
        connectionString: CONNECTION_STRING,
        admin: true
      })
    },
    {
      ...valid,
      SecretString: JSON.stringify({
        connectionString: CONNECTION_STRING.replace(
          "tp_authorizer_user",
          "root"
        )
      })
    },
    {
      ...valid,
      SecretString: JSON.stringify({
        connectionString: CONNECTION_STRING.replace(
          "verify-full",
          "require"
        )
      })
    }
  ]) {
    assert.throws(
      () => authority.connectionStringFromSecret(changed, arn),
      /AUTHORITY_SECRET_REJECTED/
    );
  }
});

test("authority rejects inconsistent database decision shapes", () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const winning = spendRow(request);
  const held = spendRow(request, "resource_held_denied");

  assert.throws(
    () =>
      authority.normalizeSpendRow(
        { ...winning, decision_lease_expires_at: null },
        request
      ),
    /AUTHORITY_DATABASE_RESPONSE_REJECTED/
  );
  assert.throws(
    () =>
      authority.normalizeSpendRow(
        { ...held, decision_fencing_token: "1" },
        request
      ),
    /AUTHORITY_DATABASE_RESPONSE_REJECTED/
  );
  assert.throws(
    () =>
      authority.normalizeResolvedRow(
        {
          operation_id: request.operationId,
          request_digest: request.requestDigest,
          outcome: "resource_reserved",
          reason: null,
          fencing_token: "1",
          lease_expires_at: "2026-08-01T12:05:00.000Z",
          outbox_intent_id: null,
          current_fence: "1",
          active_run_id: request.runId,
          holder_operation_id: request.operationId
        },
        request
      ),
    /AUTHORITY_RECONCILIATION_REJECTED/
  );
});

test("authority commits one strict SERIALIZABLE decision without returning the secret", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const client = successfulClient(request);
  const result = await authority.runAuthority({
    event: validEvent(),
    context: {
      awsRequestId: "77777777-7777-4777-8777-777777777777"
    },
    getConnectionString: async () => CONNECTION_STRING,
    createClient: () => client,
    now: () => 1_000
  });

  assert.equal(result.status, "COMMITTED");
  assert.equal(result.outcome, "resource_reserved");
  assert.equal(result.fencingToken, "1");
  assert.equal(result.transaction.isolation, "serializable");
  assert.equal(result.transaction.attempts, 1);
  assert.equal(
    result.transaction.databaseStartedAt,
    "2026-08-01T12:00:00.000Z"
  );
  assert.equal(
    result.transaction.databaseCompletedAt,
    "2026-08-01T12:00:01.000Z"
  );
  assert.equal(result.authorityTransferred, false);
  assert.equal(result.requiresFreshAuthorization, false);
  assert.equal(result.modelAccess, false);
  assert.equal(result.operationId, request.operationId);
  assert.equal(client.ended, true);
  assert.ok(client.queries.includes(authority.SPEND_SQL));
  assert.equal(JSON.stringify(result).includes(CONNECTION_STRING), false);
  assert.equal("effectKey" in result, false);
});

test("authority retries only a pre-commit serialization failure", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const serializationFailure = Object.assign(
    new Error("restart transaction"),
    { code: "40001" }
  );
  const clients = [
    successfulClient(request, {
      spendError: serializationFailure
    }),
    successfulClient(request, {
      outcome: "resource_held_denied"
    })
  ];
  let created = 0;
  const result = await authority.runAuthority({
    event: validEvent(),
    context: {},
    getConnectionString: async () => CONNECTION_STRING,
    createClient: () => clients[created++],
    now: () => 1_000
  });

  assert.equal(result.status, "COMMITTED");
  assert.equal(result.outcome, "resource_held_denied");
  assert.equal(result.transaction.attempts, 2);
  assert.deepEqual(result.transaction.retryCodes, ["40001"]);
  assert.equal(clients.every(({ ended }) => ended), true);
});

test("authority reconciles an ambiguous COMMIT instead of retrying the spend", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const commitFailure = Object.assign(
    new Error("connection lost after dispatch"),
    { code: "ECONNRESET" }
  );
  const spendClient = successfulClient(request, {
    commitError: commitFailure
  });
  const reconciliationClient = resolvedClient(request);
  const clients = [spendClient, reconciliationClient];
  let created = 0;
  const result = await authority.runAuthority({
    event: validEvent(),
    context: {},
    getConnectionString: async () => CONNECTION_STRING,
    createClient: () => clients[created++],
    now: () => 1_000
  });

  assert.equal(created, 2);
  assert.equal(result.status, "COMMITTED");
  assert.equal(result.outcome, "resource_reserved");
  assert.equal(
    result.replayKind,
    "reconciled_after_ambiguous_commit"
  );
  assert.equal(result.transaction.reconciled, true);
  assert.equal(clients.every(({ ended }) => ended), true);
});

test("authority proves the exact durable race state through one read-only capability", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const client = proofClient(proofRow(config));
  const result = await authority.runAuthority({
    event: proofEvent(),
    context: {
      awsRequestId: "88888888-8888-4888-8888-888888888888"
    },
    getConnectionString: async () => CONNECTION_STRING,
    createClient: () => client
  });

  assert.equal(
    result.schemaVersion,
    authority.PROOF_RESPONSE_SCHEMA
  );
  assert.equal(result.status, "OBSERVED");
  assert.equal(result.readOnly, true);
  assert.equal(result.authorityTransferred, false);
  assert.equal(result.requiresFreshAuthorization, true);
  assert.equal(result.modelAccess, false);
  assert.equal(result.transaction.isolation, "serializable");
  assert.equal(result.state.counts.raceReceiptCount, "2");
  assert.equal(result.state.counts.outboxCount, "1");
  assert.equal(result.state.counts.protectedEffectCount, "0");
  assert.equal(
    result.state.holderOperationId,
    result.state.outboxOperationId
  );
  assert.ok(client.queries.includes(authority.PROOF_SQL));
  assert.equal(client.ended, true);
  assert.equal(JSON.stringify(result).includes(CONNECTION_STRING), false);
});

test("authority durable proof fails closed on extra receipts, effects, or a changed outbox", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const alpha = authority.authorityRequestFor(
    validEvent("alpha"),
    config
  );
  for (const changes of [
    { resource_receipt_count: "3" },
    { protected_effect_count: "1" },
    { outbox_operation_id: FIXTURE.evidenceId },
    { holder_operation_id: FIXTURE.evidenceId },
    { alpha_fencing_token: "2" },
    { bravo_observed_holder_operation_id: FIXTURE.evidenceId },
    { bravo_observed_fence: "2" },
    { observed_at: null },
    { unexpected_column: true }
  ]) {
    const result = await authority.runAuthority({
      event: proofEvent(),
      context: {},
      getConnectionString: async () => CONNECTION_STRING,
      createClient: () => proofClient(proofRow(config, changes))
    });
    assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
    assert.equal(result.code, "AUTHORITY_PROOF_REJECTED");
    assert.equal(result.authorityTransferred, false);
    assert.equal(result.requiresFreshAuthorization, true);
  }
  assert.notEqual(alpha.operationId, FIXTURE.evidenceId);
});

test("authority fails closed with bounded public errors", async () => {
  configureEnvironment();
  const secretFailure = await authority.runAuthority({
    event: validEvent(),
    context: {},
    getConnectionString: async () => {
      throw new Error("password=must-never-leak");
    }
  });
  assert.equal(secretFailure.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(secretFailure.code, "AUTHORITY_UNAVAILABLE");
  assert.equal(
    JSON.stringify(secretFailure).includes("must-never-leak"),
    false
  );

  const malformed = await authority.runAuthority({
    event: { ...validEvent(), authority: true },
    context: {}
  });
  assert.equal(malformed.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(malformed.code, "AUTHORITY_REQUEST_REJECTED");
  assert.equal(malformed.authorityTransferred, false);
  assert.equal(malformed.requiresFreshAuthorization, true);
});

test("authority status is capability-free and never reads the secret", async () => {
  configureEnvironment();
  let secretRead = false;
  const status = await authority.runAuthority({
    event: { mode: "status" },
    context: {},
    getConnectionString: async () => {
      secretRead = true;
      return CONNECTION_STRING;
    }
  });
  assert.equal(status.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(status.code, "STATUS_ONLY_NO_AUTHORIZATION");
  assert.equal(secretRead, false);
});
