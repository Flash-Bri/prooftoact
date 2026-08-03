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
  "postgresql://tp_gate2_authorizer_user:0123456789abcdef@synthetic.cockroachlabs.cloud:26257/tideproof?sslmode=verify-full";
const SECRET_VERSION_ID = "a".repeat(32);
const PROPOSAL_FIXTURES = new Map();

function proposalFixture({
  contender,
  evidenceId = FIXTURE.evidenceId,
  selectedEvidenceDigest = "3".repeat(64),
  runId = FIXTURE.runId,
  retrievalId,
  authorityEvidenceBindingSha256,
  logicalActionDigest: suppliedLogicalActionDigest
}) {
  const payload = {
    scenario: "synthetic-highwater",
    action: "dispatch_rescue_unit",
    destination: "synthetic-zone-aws-race",
    logicalDispatch: contender
  };
  const payloadDigest = authority.sha256Hex(payload);
  const logicalActionDigest = suppliedLogicalActionDigest ??
    authority.sha256Hex({
      schemaVersion: "tideproof.authority.logical-action.v1",
      tenantId: FIXTURE.tenantId,
      incidentId: FIXTURE.incidentId,
      resourceId: FIXTURE.resourceId,
      agency: "rescue",
      actionKind: "dispatch_rescue_unit",
      payloadDigest
    });
  const identity = {
    schemaVersion: "tideproof.authority.dvi-proposal-identity.v1",
    tenantId: FIXTURE.tenantId,
    runId,
    incidentId: FIXTURE.incidentId,
    retrievalId,
    logicalActionDigest,
    authorityEvidenceBindingSha256,
    selectedEvidenceId: evidenceId,
    selectedEvidenceDigest,
    policyVersion: "g1-admissibility-v2",
    selectedRank: 1,
    admittedAt: "2026-08-01T11:55:00.000Z",
    expiresAt: "2026-08-01T12:05:00.000Z"
  };
  const fixture = {
    ...identity,
    proposalDigest: authority.sha256Hex(identity),
    resourceId: FIXTURE.resourceId,
    agency: "rescue",
    actionKind: "dispatch_rescue_unit",
    payload,
    payloadCanonical: authority.canonicalJson(payload),
    payloadDigest
  };
  PROPOSAL_FIXTURES.set(fixture.proposalDigest, fixture);
  return fixture;
}

const ALPHA_PROPOSAL = proposalFixture({
  contender: "alpha",
  retrievalId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  authorityEvidenceBindingSha256: "6".repeat(64)
});
const BRAVO_PROPOSAL = proposalFixture({
  contender: "bravo",
  retrievalId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  authorityEvidenceBindingSha256: "7".repeat(64)
});

function configureEnvironment() {
  Object.assign(process.env, {
    AUTHORITY_DATABASE_SECRET_ARN:
      "arn:aws:secretsmanager:us-east-1:111111111111:secret:prooftoact/authorizer-AbCd12",
    AUTHORITY_DATABASE_SECRET_VERSION_ID: SECRET_VERSION_ID,
    AUTHORITY_DATABASE_HOST: "synthetic.cockroachlabs.cloud",
    AUTHORITY_DATABASE_PORT: "26257",
    AUTHORITY_TENANT_ID: FIXTURE.tenantId,
    AUTHORITY_RUN_ID: FIXTURE.runId,
    AUTHORITY_INCIDENT_ID: FIXTURE.incidentId,
    AUTHORITY_EVIDENCE_ID: FIXTURE.evidenceId,
    AUTHORITY_ALPHA_PROPOSAL_DIGEST: ALPHA_PROPOSAL.proposalDigest,
    AUTHORITY_BRAVO_PROPOSAL_DIGEST: BRAVO_PROPOSAL.proposalDigest,
    AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST:
      ALPHA_PROPOSAL.logicalActionDigest,
    AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST:
      BRAVO_PROPOSAL.logicalActionDigest,
    AUTHORITY_SELECTED_EVIDENCE_DIGEST: "3".repeat(64),
    AUTHORITY_RACE_ID: FIXTURE.raceId,
    AUTHORITY_RESOURCE_ID: FIXTURE.resourceId,
    SOURCE_COMMIT: "a".repeat(40),
    CONFIG_DIGEST: "b".repeat(64),
    TREE_DIGEST: "c".repeat(40),
    PACKAGE_LOCK_DIGEST: "d".repeat(64),
    AUTHORITY_SOURCE_DIGEST: "e".repeat(64),
    AUTHORITY_ARTIFACT_DIGEST: "f".repeat(64),
    AWS_REGION: "us-east-1",
    AWS_LAMBDA_FUNCTION_NAME: "prooftoact-gate2-authority",
    AWS_LAMBDA_FUNCTION_VERSION: "7",
    SEMANTIC_METRIC_DEPLOYMENT: "prooftoact-gate2"
  });
}

test("authority semantic failures emit provider-bound EMF without authority input", () => {
  configureEnvironment();
  const metric = authority.semanticFailureMetric(
    "AUTHORITY_UNAVAILABLE",
    { awsRequestId: "request-456" },
    () => 1_785_700_000_001
  );

  assert.deepEqual(metric, {
    _aws: {
      Timestamp: 1_785_700_000_001,
      CloudWatchMetrics: [
        {
          Namespace: "ProofToAct/GateTwo",
          Dimensions: [["Deployment", "Service"]],
          Metrics: [{ Name: "SemanticFailures", Unit: "Count" }]
        }
      ]
    },
    Deployment: "prooftoact-gate2",
    Service: "authority",
    SemanticFailures: 1,
    schemaVersion: "tideproof.aws-semantic-failure.v1",
    provider: "AWS_LAMBDA",
    status: "UNKNOWN_DO_NOT_ACT",
    code: "AUTHORITY_UNAVAILABLE",
    awsRequestId: "request-456",
    region: "us-east-1",
    functionName: "prooftoact-gate2-authority",
    functionVersion: "7",
    sourceCommit: "a".repeat(40),
    configDigest: "b".repeat(64),
    treeDigest: "c".repeat(40),
    artifactDigest: "f".repeat(64)
  });
  assert.equal(JSON.stringify(metric).includes("proposalDigest"), false);
  assert.equal(JSON.stringify(metric).includes("logicalActionDigest"), false);
});

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
  const identity = authority.authorityIdentityFor(request, 1);
  return {
    decision_outcome: outcome,
    decision_reason:
      winner
        ? null
        : outcome === "resource_held_denied"
          ? "active_holder"
          : "proposal_authorization_denied",
    decision_fencing_token: winner ? "1" : null,
    decision_lease_expires_at: winner
      ? "2026-08-01T12:05:00.000Z"
      : null,
    decision_operation_id: request.operationId,
    decision_request_digest: request.requestDigest,
    decision_replay_kind: null,
    decision_proposal_digest: request.proposalDigest,
    decision_logical_action_digest: request.logicalActionDigest,
    decision_authorization_epoch: String(identity.authorizationEpoch),
    decision_logical_authority_key_sha256:
      identity.logicalAuthorityKeySha256,
    decision_authorization_binding_sha256:
      identity.authorizationBindingSha256,
    decision_authority_evidence_binding_sha256:
      PROPOSAL_FIXTURES.get(request.proposalDigest)
        ?.authorityEvidenceBindingSha256,
    decision_authority_current: winner,
    decision_database_now: "2026-08-01T12:00:01.000Z",
    decision_durable_receipt: true,
    decision_committed_evidence_id: request.evidenceId,
    decision_committed_evidence_digest: request.selectedEvidenceDigest
  };
}

function nonDurableSpendRow(request, reason) {
  const bound = reason !== "proposal_authorization_missing_or_stale";
  const identity = bound
    ? authority.authorityIdentityFor(request, 1)
    : null;
  return {
    decision_outcome: "authorization_denied",
    decision_reason: reason,
    decision_fencing_token: null,
    decision_lease_expires_at: null,
    decision_operation_id: request.operationId,
    decision_request_digest: request.requestDigest,
    decision_replay_kind: null,
    decision_proposal_digest: request.proposalDigest,
    decision_logical_action_digest: request.logicalActionDigest,
    decision_authorization_epoch: bound ? "1" : null,
    decision_logical_authority_key_sha256:
      identity?.logicalAuthorityKeySha256 ?? null,
    decision_authorization_binding_sha256:
      identity?.authorizationBindingSha256 ?? null,
    decision_authority_evidence_binding_sha256:
      bound
        ? PROPOSAL_FIXTURES.get(request.proposalDigest)
            ?.authorityEvidenceBindingSha256
        : null,
    decision_authority_current: false,
    decision_database_now: "2026-08-01T12:00:01.000Z",
    decision_durable_receipt: false,
    decision_committed_evidence_id: null,
    decision_committed_evidence_digest: null
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
        const row = spendRow(request, options.outcome ?? "resource_reserved");
        Object.assign(row, options.decisionChanges ?? {});
        return {
          rowCount: 1,
          rows: [row]
        };
      }
      if (sql === "COMMIT" && options.commitError) {
        throw options.commitError;
      }
      return { rowCount: 0, rows: [] };
    },
    async end() {
      this.ended = true;
      options.events?.push("ambiguous_closed");
    }
  };
}

function replacementAuthorityRequest(request) {
  const replacement = {
    ...request,
    runId: "77777777-7777-4777-8777-777777777777",
    operationId: "88888888-8888-4888-8888-888888888888",
    agentId: "aws-authority-replacement",
    evidenceId: "99999999-9999-4999-8999-999999999999",
    intentNonce: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    effectKey: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    selectedEvidenceDigest: "5".repeat(64)
  };
  const storedProposal = proposalFixture({
    contender: request.payload.logicalDispatch,
    evidenceId: replacement.evidenceId,
    selectedEvidenceDigest: replacement.selectedEvidenceDigest,
    runId: replacement.runId,
    retrievalId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    authorityEvidenceBindingSha256: "8".repeat(64),
    logicalActionDigest: replacement.logicalActionDigest
  });
  replacement.proposalDigest = storedProposal.proposalDigest;
  replacement.requestPayload = {
    digestVersion: replacement.digestVersion,
    tenantId: replacement.tenantId,
    runId: replacement.runId,
    incidentId: replacement.incidentId,
    resourceId: replacement.resourceId,
    agentId: replacement.agentId,
    agency: replacement.agency,
    evidenceId: replacement.evidenceId,
    intentNonce: replacement.intentNonce,
    effectKey: replacement.effectKey,
    leaseMs: replacement.leaseMs,
    policyVersion: replacement.policyVersion,
    actionKind: replacement.actionKind,
    payloadDigest: replacement.payloadDigest,
    logicalActionDigest: replacement.logicalActionDigest,
    proposalDigest: replacement.proposalDigest,
    selectedEvidenceId: replacement.evidenceId,
    selectedEvidenceDigest: replacement.selectedEvidenceDigest
  };
  replacement.requestDigest = authority.sha256Hex(
    replacement.requestPayload
  );
  return replacement;
}

function resolvedClient(request, outcome = "resource_reserved", options = {}) {
  const identity = authority.authorityIdentityFor(request, 1);
  const proposal = PROPOSAL_FIXTURES.get(request.proposalDigest);
  assert.ok(proposal, "resolved fixture requires a registered proposal");
  return {
    ended: false,
    async connect() {
      options.events?.push("reconciliation_started");
    },
    async query(sql) {
      if (sql === authority.RESOLVE_SQL) {
        if (options.rowCount === 0) {
          return { rowCount: 0, rows: [] };
        }
        return {
          rowCount: 1,
          rows: [
            {
              operation_id: request.operationId,
              request_digest: request.requestDigest,
              request_payload: request.requestPayload,
              proposal_digest: request.proposalDigest,
              logical_action_digest: request.logicalActionDigest,
              authorization_epoch: String(identity.authorizationEpoch),
              logical_authority_key_sha256:
                identity.logicalAuthorityKeySha256,
              authorization_binding_sha256:
                identity.authorizationBindingSha256,
              run_id: request.runId,
              incident_id: request.incidentId,
              resource_id: request.resourceId,
              agent_id: request.agentId,
              agency: request.agency,
              evidence_id: request.evidenceId,
              evidence_digest: request.selectedEvidenceDigest,
              effect_key: request.effectKey,
              payload_digest: request.payloadDigest,
              policy_version: request.policyVersion,
              outcome,
              reason:
                outcome === "resource_reserved"
                  ? null
                  : outcome === "resource_held_denied"
                    ? "active_holder"
                    : "proposal_authorization_denied",
              fencing_token:
                outcome === "resource_reserved" ? "1" : null,
              lease_expires_at:
                outcome === "resource_reserved"
                  ? "2026-08-01T12:05:00.000Z"
                  : null,
              observed_holder_operation_id:
                outcome === "resource_held_denied"
                  ? "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
                  : null,
              observed_fence:
                outcome === "resource_held_denied" ? "1" : null,
              replay_kind: "operation_replay",
              outbox_intent_id:
                outcome === "resource_reserved"
                  ? "66666666-6666-4666-8666-666666666666"
                  : null,
              outbox_operation_id:
                outcome === "resource_reserved" ? request.operationId : null,
              outbox_request_digest:
                outcome === "resource_reserved" ? request.requestDigest : null,
              outbox_proposal_digest:
                outcome === "resource_reserved" ? request.proposalDigest : null,
              outbox_logical_action_digest:
                outcome === "resource_reserved"
                  ? request.logicalActionDigest
                  : null,
              outbox_authorization_epoch:
                outcome === "resource_reserved"
                  ? String(identity.authorizationEpoch)
                  : null,
              outbox_logical_authority_key_sha256:
                outcome === "resource_reserved"
                  ? identity.logicalAuthorityKeySha256
                  : null,
              outbox_authorization_binding_sha256:
                outcome === "resource_reserved"
                  ? identity.authorizationBindingSha256
                  : null,
              outbox_run_id:
                outcome === "resource_reserved" ? request.runId : null,
              outbox_incident_id:
                outcome === "resource_reserved" ? request.incidentId : null,
              outbox_resource_id:
                outcome === "resource_reserved" ? request.resourceId : null,
              outbox_fencing_token:
                outcome === "resource_reserved" ? "1" : null,
              outbox_effect_key:
                outcome === "resource_reserved" ? request.effectKey : null,
              outbox_intent_kind:
                outcome === "resource_reserved"
                  ? "dispatch_rescue_unit"
                  : null,
              outbox_payload:
                outcome === "resource_reserved" ? request.payload : null,
              outbox_payload_digest:
                outcome === "resource_reserved" ? request.payloadDigest : null,
              current_fence:
                outcome === "resource_reserved" ? "1" : null,
              active_run_id: request.runId,
              holder_operation_id:
                outcome === "resource_reserved"
                  ? request.operationId
                  : null,
              holder_proposal_digest:
                outcome === "resource_reserved"
                  ? request.proposalDigest
                  : null,
              holder_logical_authority_key_sha256:
                outcome === "resource_reserved"
                  ? identity.logicalAuthorityKeySha256
                  : null,
              resource_lease_expires_at:
                outcome === "resource_reserved"
                  ? "2026-08-01T12:05:00.000Z"
                  : null,
              receipt_proposal_tenant_id: proposal.tenantId,
              receipt_proposal_digest: proposal.proposalDigest,
              receipt_proposal_logical_action_digest:
                proposal.logicalActionDigest,
              receipt_proposal_resource_id: proposal.resourceId,
              receipt_proposal_agency: proposal.agency,
              receipt_proposal_action_kind: proposal.actionKind,
              receipt_proposal_payload: proposal.payload,
              receipt_proposal_payload_canonical:
                proposal.payloadCanonical,
              receipt_proposal_payload_digest: proposal.payloadDigest,
              receipt_proposal_retrieval_id: proposal.retrievalId,
              receipt_proposal_run_id: proposal.runId,
              receipt_proposal_incident_id: proposal.incidentId,
              receipt_proposal_authority_evidence_binding_sha256:
                proposal.authorityEvidenceBindingSha256,
              receipt_proposal_policy_version: proposal.policyVersion,
              receipt_proposal_selected_rank: String(proposal.selectedRank),
              receipt_proposal_selected_evidence_id:
                proposal.selectedEvidenceId,
              receipt_proposal_selected_evidence_digest:
                proposal.selectedEvidenceDigest,
              receipt_proposal_admitted_at: proposal.admittedAt,
              receipt_proposal_expires_at: proposal.expiresAt,
              receipt_proposal_authorization_epoch:
                String(identity.authorizationEpoch),
              receipt_proposal_logical_authority_key_sha256:
                identity.logicalAuthorityKeySha256,
              receipt_proposal_authorization_binding_sha256:
                identity.authorizationBindingSha256,
              authority_current: outcome === "resource_reserved",
              database_now: new Date("2026-08-01T12:00:01.000Z"),
              ...(options.rowChanges ?? {})
            }
          ]
        };
      }
      return { rowCount: 0, rows: [] };
    },
    async end() {
      this.ended = true;
      options.events?.push("reconciliation_closed");
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

test("authority derives two distinct logical acts that contend for one resource", () => {
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
  assert.notEqual(alpha.proposalDigest, bravo.proposalDigest);
  assert.notEqual(alpha.logicalActionDigest, bravo.logicalActionDigest);
  assert.notDeepEqual(alpha.payload, bravo.payload);
  assert.equal(alpha.resourceId, bravo.resourceId);
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
  const config = authority.configuration();
  const valid = {
    ARN: config.secretArn,
    VersionId: config.secretVersionId,
    SecretString: JSON.stringify({
      connectionString: CONNECTION_STRING
    }),
    VersionStages: ["AWSCURRENT"]
  };
  assert.equal(
    authority.connectionStringFromSecret(valid, config),
    CONNECTION_STRING
  );
  assert.deepEqual(authority.secretRequestFor(config), {
    SecretId: config.secretArn,
    VersionId: config.secretVersionId,
    VersionStage: "AWSCURRENT"
  });

  for (const changed of [
    { ...valid, ARN: `${config.secretArn}-other` },
    { ...valid, VersionId: "b".repeat(32) },
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
          "tp_gate2_authorizer_user",
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
    },
    {
      ...valid,
      SecretString: JSON.stringify({
        connectionString: CONNECTION_STRING.replace(
          "synthetic.cockroachlabs.cloud",
          "substituted.cockroachlabs.cloud"
        )
      })
    },
    {
      ...valid,
      SecretString: JSON.stringify({
        connectionString: CONNECTION_STRING.replace("26257", "26258")
      })
    }
  ]) {
    assert.throws(
      () => authority.connectionStringFromSecret(changed, config),
      /AUTHORITY_SECRET_REJECTED/
    );
  }
});

test("authority requires exact endpoint/version configuration and bounded database clients", () => {
  configureEnvironment();
  const config = authority.configuration();
  assert.equal(config.databaseHost, "synthetic.cockroachlabs.cloud");
  assert.equal(config.databasePort, "26257");
  assert.equal(config.secretVersionId, SECRET_VERSION_ID);

  for (const [name, value] of [
    ["AUTHORITY_DATABASE_HOST", "attacker.example"],
    ["AUTHORITY_DATABASE_PORT", "70000"],
    ["AUTHORITY_DATABASE_SECRET_VERSION_ID", "short"]
  ]) {
    const original = process.env[name];
    process.env[name] = value;
    assert.throws(
      () => authority.configuration(),
      /AUTHORITY_CONFIGURATION_REJECTED/
    );
    process.env[name] = original;
  }
  const originalBravo = process.env.AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST;
  process.env.AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST =
    process.env.AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST;
  assert.throws(
    () => authority.configuration(),
    /AUTHORITY_CONFIGURATION_REJECTED/
  );
  process.env.AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST = originalBravo;

  assert.deepEqual(
    authority.databaseClientConfiguration(
      CONNECTION_STRING,
      "tideproof-aws-authority"
    ),
    {
      connectionString: CONNECTION_STRING,
      application_name: "tideproof-aws-authority",
      connectionTimeoutMillis: 2_000,
      query_timeout: 4_500,
      statement_timeout: 4_000,
      idle_in_transaction_session_timeout: 3_000
    }
  );
  assert.deepEqual(
    authority.databaseClientConfiguration(
      CONNECTION_STRING,
      "tideproof-aws-authority-proof"
    ),
    {
      connectionString: CONNECTION_STRING,
      application_name: "tideproof-aws-authority-proof",
      ...authority.DATABASE_TIMEOUTS
    }
  );
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
      authority.normalizeSpendRow(
        {
          ...winning,
          decision_authority_evidence_binding_sha256: null
        },
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

test("logical-authority replay verifies and preserves the stored receipt identity", () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const storedProposalDigest = "4".repeat(64);
  const storedIdentity = authority.authorityIdentityFor(
    { ...request, proposalDigest: storedProposalDigest },
    1
  );
  const row = {
    ...spendRow(request),
    decision_operation_id: "77777777-7777-4777-8777-777777777777",
    decision_request_digest: "5".repeat(64),
    decision_replay_kind: "logical_authority_replay",
    decision_proposal_digest: storedProposalDigest,
    decision_authorization_binding_sha256:
      storedIdentity.authorizationBindingSha256
  };
  const normalized = authority.normalizeSpendRow(row, request);
  assert.equal(normalized.replayKind, "logical_authority_replay");
  assert.equal(
    normalized.committedAuthorityEvidenceBindingSha256,
    ALPHA_PROPOSAL.authorityEvidenceBindingSha256
  );
  assert.equal(
    normalized.authorizationBindingSha256,
    storedIdentity.authorizationBindingSha256
  );
  assert.equal(
    authority.databaseCommitResult(
      normalized,
      request,
      "direct_ack"
    ).operationDigest,
    row.decision_request_digest
  );
  assert.throws(
    () => authority.normalizeSpendRow({
      ...row,
      decision_authorization_binding_sha256: "6".repeat(64)
    }, request),
    /AUTHORITY_DATABASE_RESPONSE_REJECTED/u
  );
});

test("historical positive receipts never claim current authority", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const historicalLease = "2000-01-01T00:00:00.000Z";
  const direct = authority.normalizeSpendRow(
    {
      ...spendRow(request),
      decision_lease_expires_at: historicalLease,
      decision_authority_current: false
    },
    request
  );
  assert.equal(direct.outcome, "resource_reserved");
  assert.equal(direct.authorityCurrent, false);

  const resolvedRow = (
    await resolvedClient(request, "resource_reserved", {
      rowChanges: {
        lease_expires_at: historicalLease,
        authority_current: false
      }
    }).query(authority.RESOLVE_SQL)
  ).rows[0];
  const reconciled = authority.normalizeResolvedRow(resolvedRow, request);
  assert.equal(reconciled.outcome, "resource_reserved");
  assert.equal(reconciled.authorityCurrent, false);

  const client = successfulClient(request, {
    decisionChanges: {
      decision_lease_expires_at: historicalLease,
      decision_authority_current: false
    }
  });
  const response = await authority.runAuthority({
    event: validEvent(),
    context: { awsRequestId: "77777777-7777-4777-8777-777777777777" },
    getConnectionString: async () => CONNECTION_STRING,
    createClient: () => client,
    now: () => 1_000
  });
  assert.equal(response.status, "COMMITTED");
  assert.equal(response.outcome, "resource_reserved");
  assert.equal(response.authorityCurrent, false);
  assert.equal(response.requiresFreshAuthorization, true);
  assert.equal(
    response.commit.status,
    "COMMITTED_BUT_NO_LONGER_CURRENT"
  );
  assert.equal(response.commit.authority.requiresFreshAuthorization, true);
});

test("direct and reconciled denied commits preserve one durable reason", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const directDecision = authority.normalizeSpendRow(
    spendRow(request, "authorization_denied"),
    request
  );
  const direct = authority.databaseCommitResult(
    directDecision,
    request,
    "direct_ack"
  );
  const storedRequest = {
    ...request,
    operationId: "77777777-7777-4777-8777-777777777777"
  };
  const resolvedRow = (
    await resolvedClient(storedRequest, "authorization_denied", {
      rowChanges: { replay_kind: "semantic_replay" }
    }).query(authority.RESOLVE_SQL)
  ).rows[0];
  const reconciledDecision = authority.normalizeResolvedRow(
    resolvedRow,
    request
  );
  const reconciled = authority.databaseCommitResult(
    reconciledDecision,
    request,
    "read_reconciled"
  );

  assert.deepEqual(Object.keys(direct), Object.keys(reconciled));
  assert.equal(direct.outcome, "authorization_denied");
  assert.equal(reconciled.outcome, direct.outcome);
  assert.equal(direct.reason, "proposal_authorization_denied");
  assert.equal(reconciled.reason, direct.reason);
  assert.deepEqual(reconciled.authority, direct.authority);
});

test("early authority denials are explicit, non-durable, and retry-safe", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  for (const reason of [
    "proposal_authorization_missing_or_stale",
    "proposal_authorization_expired",
    "proposal_authorization_superseded"
  ]) {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const client = successfulClient(request, {
        outcome: "authorization_denied",
        decisionChanges: nonDurableSpendRow(request, reason)
      });
      const result = await authority.runAuthority({
        event: validEvent(),
        context: { awsRequestId: "77777777-7777-4777-8777-777777777777" },
        getConnectionString: async () => CONNECTION_STRING,
        createClient: () => client,
        now: () => 1_000
      });
      assert.equal(result.status, "DENIED_NOT_DURABLE");
      assert.equal(result.reason, reason);
      assert.equal(result.commit.status, "DENIED_NOT_DURABLE");
      assert.equal(result.commit.operationDigest, request.requestDigest);
      assert.equal(result.requiresFreshAuthorization, true);
      assert.equal("committedOperationId" in result, false);
      assert.equal("committedRequestDigest" in result, false);
      assert.equal("committedProposalDigest" in result, false);
      assert.equal("committedSelectedEvidenceId" in result, false);
      assert.equal(client.ended, true);
    }
  }
});

test("ACK loss after a non-durable denial never invents a commit", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const commitFailure = Object.assign(
    new Error("synthetic ACK loss after non-durable denial"),
    { code: "XX000" }
  );
  const spendClient = successfulClient(request, {
    outcome: "authorization_denied",
    decisionChanges: nonDurableSpendRow(
      request,
      "proposal_authorization_expired"
    ),
    commitError: commitFailure
  });
  const reconciliationClient = resolvedClient(request, "resource_reserved", {
    rowCount: 0
  });
  const clients = [spendClient, reconciliationClient];
  let created = 0;
  const result = await authority.runAuthority({
    event: validEvent(),
    context: {},
    getConnectionString: async () => CONNECTION_STRING,
    createClient: () => clients[created++],
    now: () => 1_000
  });

  assert.equal(result.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.code, "AUTHORITY_RECONCILIATION_REJECTED");
  assert.equal("committedOperationId" in result, false);
  assert.equal("committedRequestDigest" in result, false);
  assert.equal(created, 2);
  assert.equal(clients.every(({ ended }) => ended), true);
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
  assert.equal(result.authorityCurrent, true);
  assert.equal(result.requiresFreshAuthorization, false);
  assert.equal(
    result.commit.schemaVersion,
    "tideproof.database-commit-result.v1"
  );
  assert.equal(result.commit.observation, "direct_ack");
  assert.equal(result.commit.databaseNow, "2026-08-01T12:00:01.000Z");
  assert.deepEqual(result.commit.authority, {
    current: true,
    requiresFreshAuthorization: false
  });
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
  assert.equal(result.commit.outcome, "resource_held_denied");
  assert.equal(result.commit.reason, "active_holder");
  assert.equal(result.commit.authority.requiresFreshAuthorization, true);
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
  assert.equal(result.commit.status, "COMMITTED");
  assert.equal(result.commit.observation, "read_reconciled");
  assert.equal(result.commit.operationDigest, request.requestDigest);
  assert.equal(clients.every(({ ended }) => ended), true);
});

test("authority reconciles an ACK-lost semantic denial through its durable identity", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const storedRequest = {
    ...request,
    operationId: "77777777-7777-4777-8777-777777777777"
  };
  const commitFailure = Object.assign(
    new Error("connection lost after dispatch"),
    { code: "ECONNRESET" }
  );
  const clients = [
    successfulClient(request, { commitError: commitFailure }),
    resolvedClient(storedRequest, "authorization_denied", {
      rowChanges: { replay_kind: "semantic_replay" }
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
  assert.equal(result.outcome, "authorization_denied");
  assert.equal(result.replayKind, "semantic_replay");
  assert.equal(result.committedOperationId, storedRequest.operationId);
  assert.equal(result.committedRequestDigest, request.requestDigest);
  assert.equal(result.commit.operationDigest, request.requestDigest);
  assert.equal(result.commit.reason, "proposal_authorization_denied");
  assert.equal(result.requiresFreshAuthorization, true);
  assert.equal(clients.every(({ ended }) => ended), true);
});

test("authority reconciles a full transport replacement by one stable logical action", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const storedRequest = replacementAuthorityRequest(request);
  const commitFailure = Object.assign(
    new Error("connection lost after dispatch"),
    { code: "ECONNRESET" }
  );
  const events = [];
  const clients = [
    successfulClient(request, { commitError: commitFailure, events }),
    resolvedClient(storedRequest, "resource_reserved", {
      events,
      rowChanges: { replay_kind: "logical_authority_replay" }
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
  assert.equal(result.outcome, "resource_reserved");
  assert.equal(result.replayKind, "logical_authority_replay");
  assert.equal(result.committedOperationId, storedRequest.operationId);
  assert.equal(
    result.committedRequestDigest,
    storedRequest.requestDigest
  );
  assert.equal(result.commit.operationDigest, storedRequest.requestDigest);
  assert.notEqual(result.operationId, result.committedOperationId);
  assert.notEqual(result.requestDigest, result.committedRequestDigest);
  assert.equal(result.logicalActionDigest, storedRequest.logicalActionDigest);
  assert.equal(
    result.committedProposalDigest,
    storedRequest.proposalDigest
  );
  assert.equal(
    result.committedAuthorityEvidenceBindingSha256,
    PROPOSAL_FIXTURES.get(storedRequest.proposalDigest).authorityEvidenceBindingSha256,
  );
  assert.equal(
    result.committedSelectedEvidenceId,
    storedRequest.evidenceId
  );
  assert.equal(
    result.committedSelectedEvidenceDigest,
    storedRequest.selectedEvidenceDigest
  );
  const committedIdentity = authority.authorityIdentityFor(
    {
      ...request,
      proposalDigest: result.committedProposalDigest
    },
    result.authorizationEpoch
  );
  assert.equal(
    result.authorizationBindingSha256,
    committedIdentity.authorizationBindingSha256
  );
  assert.notEqual(result.proposalDigest, result.committedProposalDigest);
  assert.notEqual(
    result.selectedEvidenceDigest,
    result.committedSelectedEvidenceDigest
  );
  assert.equal(result.authorityCurrent, true);
  assert.equal(clients.every(({ ended }) => ended), true);
  assert.deepEqual(events, [
    "ambiguous_closed",
    "reconciliation_started",
    "reconciliation_closed"
  ]);
});

test("authority reconciliation rejects every drifted outbox binding", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const row = (
    await resolvedClient(request).query(authority.RESOLVE_SQL)
  ).rows[0];
  for (const [field, changed] of [
    ["outbox_operation_id", FIXTURE.evidenceId],
    ["outbox_request_digest", "6".repeat(64)],
    ["outbox_proposal_digest", "6".repeat(64)],
    ["outbox_logical_action_digest", "6".repeat(64)],
    ["outbox_authorization_epoch", "2"],
    ["outbox_logical_authority_key_sha256", "6".repeat(64)],
    ["outbox_authorization_binding_sha256", "6".repeat(64)],
    ["outbox_run_id", FIXTURE.evidenceId],
    ["outbox_incident_id", FIXTURE.evidenceId],
    ["outbox_resource_id", "drifted-resource"],
    ["outbox_fencing_token", "2"],
    ["outbox_effect_key", FIXTURE.evidenceId],
    ["outbox_intent_kind", "drifted_intent"],
    ["outbox_payload", { ...request.payload, destination: "drifted" }],
    [
      "receipt_proposal_payload",
      { ...request.payload, destination: "drifted" }
    ],
    ["outbox_payload_digest", "6".repeat(64)]
  ]) {
    assert.throws(
      () => authority.normalizeResolvedRow({ ...row, [field]: changed }, request),
      /AUTHORITY_RECONCILIATION_REJECTED/u,
      field
    );
  }
});

test("authority reconciliation rejects every drifted proposal binding", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const row = (
    await resolvedClient(request).query(authority.RESOLVE_SQL)
  ).rows[0];
  for (const [field, changed] of [
    ["receipt_proposal_tenant_id", FIXTURE.evidenceId],
    ["receipt_proposal_digest", "6".repeat(64)],
    ["receipt_proposal_logical_action_digest", "6".repeat(64)],
    ["receipt_proposal_resource_id", "drifted-resource"],
    ["receipt_proposal_agency", "drifted-agency"],
    ["receipt_proposal_action_kind", "drifted_action"],
    ["receipt_proposal_payload_canonical", "{}"],
    ["receipt_proposal_payload_digest", "6".repeat(64)],
    ["receipt_proposal_retrieval_id", FIXTURE.evidenceId],
    ["receipt_proposal_run_id", FIXTURE.evidenceId],
    ["receipt_proposal_incident_id", FIXTURE.evidenceId],
    [
      "receipt_proposal_authority_evidence_binding_sha256",
      "9".repeat(64)
    ],
    ["receipt_proposal_policy_version", "drifted-policy"],
    ["receipt_proposal_selected_rank", "2"],
    ["receipt_proposal_selected_evidence_id", FIXTURE.runId],
    ["receipt_proposal_selected_evidence_digest", "6".repeat(64)],
    ["receipt_proposal_admitted_at", row.receipt_proposal_expires_at],
    ["receipt_proposal_authorization_epoch", "2"],
    ["receipt_proposal_logical_authority_key_sha256", "6".repeat(64)],
    ["receipt_proposal_authorization_binding_sha256", "6".repeat(64)]
  ]) {
    assert.throws(
      () => authority.normalizeResolvedRow({ ...row, [field]: changed }, request),
      /AUTHORITY_RECONCILIATION_REJECTED/u,
      field
    );
  }

  const coordinatedForgedRequestPayload = {
    ...row.request_payload,
    selectedEvidenceDigest: "9".repeat(64)
  };
  assert.throws(
    () => authority.normalizeResolvedRow({
      ...row,
      request_payload: coordinatedForgedRequestPayload,
      request_digest: authority.sha256Hex(coordinatedForgedRequestPayload),
      evidence_digest: "9".repeat(64),
      receipt_proposal_selected_evidence_digest: "9".repeat(64)
    }, request),
    /AUTHORITY_RECONCILIATION_REJECTED/u
  );
});

test("authority reconciliation binds held-denial observation fields", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const row = (
    await resolvedClient(request, "resource_held_denied").query(
      authority.RESOLVE_SQL
    )
  ).rows[0];
  assert.equal(
    authority.normalizeResolvedRow(row, request).authorityCurrent,
    false
  );
  for (const changes of [
    { observed_holder_operation_id: null },
    { observed_fence: null },
    { observed_fence: "0" }
  ]) {
    assert.throws(
      () => authority.normalizeResolvedRow({ ...row, ...changes }, request),
      /AUTHORITY_RECONCILIATION_REJECTED/u
    );
  }
});

test("authority reconciliation rejects a current claim with an expired receipt lease", async () => {
  configureEnvironment();
  const config = authority.configuration();
  const request = authority.authorityRequestFor(validEvent(), config);
  const row = (
    await resolvedClient(request, "resource_reserved", {
      rowChanges: {
        lease_expires_at: "2000-01-01T00:00:00.000Z",
        authority_current: true
      }
    }).query(authority.RESOLVE_SQL)
  ).rows[0];
  assert.throws(
    () => authority.normalizeResolvedRow(row, request),
    /AUTHORITY_RECONCILIATION_REJECTED/u
  );
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
