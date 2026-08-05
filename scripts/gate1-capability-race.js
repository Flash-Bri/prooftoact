import { randomUUID } from "node:crypto";
import { Client } from "pg";
import {
  AuthorityStore,
  normalizedAuthorityRequestFor
} from "../src/cloud/authority-store.js";
import {
  authorizeSyntheticContenders,
  authorizeSyntheticProposal
} from "./lib/synthetic-authority-proposal.js";
import { createSyntheticEvidenceSigner } from "./lib/synthetic-evidence.js";

const CONTENDERS = 50;
const SPEND_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID, $2::UUID, $3, $4::JSONB,
    $5, $6, $7, $8::UUID, $9::UUID, $10, $11, $12,
    $13::UUID, $14::UUID, $15::JSONB, $16, $17, $18::INT8
  )
`;
const PROTECTED_EFFECT_SQL = `
  SELECT *
  FROM tp_api.g1_record_protected_effect_v1(
    $1::UUID, $2::UUID, $3::UUID, $4,
    $5::UUID, $6::UUID, $7, $8, $9::INT8, $10
  )
`;
const RECOVERY_SOURCE_SQL = `
  SELECT *
  FROM tp_api.g1_resolve_recovery_source_receipt_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5, $6::UUID, $7
  )
`;

class Barrier {
  #arrived = 0;
  #release;
  #released;
  #timer;

  constructor(expected, timeoutMs = 30_000) {
    this.expected = expected;
    this.#released = new Promise((resolve, reject) => {
      this.#release = resolve;
      this.#timer = setTimeout(
        () =>
          reject(
            new Error(`barrier timed out after ${this.#arrived}/${expected}`)
          ),
        timeoutMs
      );
    });
  }

  async wait() {
    this.#arrived += 1;
    if (this.#arrived === this.expected) {
      clearTimeout(this.#timer);
      this.#release();
    }
    await this.#released;
  }
}

class QueryReadyBarrier {
  #fail;
  #failure = null;
  #ready;
  #release;
  #settled = false;
  #timer;

  constructor(label, timeoutMs = 10_000) {
    this.label = label;
    this.#ready = new Promise((resolve, reject) => {
      this.#release = resolve;
      this.#fail = reject;
      this.#timer = setTimeout(
        () => this.fail(new Error(`${label} query-ready barrier timed out`)),
        timeoutMs
      );
    });
  }

  reach() {
    if (this.#settled) {
      if (this.#failure) {
        throw this.#failure;
      }
      return;
    }
    this.#settled = true;
    clearTimeout(this.#timer);
    this.#release();
  }

  fail(error) {
    if (this.#settled) {
      return;
    }
    this.#settled = true;
    this.#failure = error;
    clearTimeout(this.#timer);
    this.#fail(error);
  }

  async wait() {
    await this.#ready;
  }
}

function requiredEnvironment(name) {
  if (!process.env[name]) {
    throw new Error(`${name} is required`);
  }
  return process.env[name];
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function valuesFor(request) {
  return [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.proposalDigest,
    request.logicalActionDigest,
    request.selectedEvidenceDigest,
    request.runId,
    request.incidentId,
    request.resourceId,
    request.agentId,
    request.agency,
    request.evidenceId,
    request.effectKey,
    JSON.stringify(request.payload),
    request.payloadDigest,
    request.policyVersion,
    request.leaseMs
  ];
}

async function callCapability(
  connectionString,
  request,
  barrier,
  { queryReady = null } = {}
) {
  const retryCodes = [];
  const backendIds = [];
  for (let attempt = 0; attempt <= 20; attempt += 1) {
    const client = new Client({ connectionString });
    try {
      await client.connect();
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const isolation = await client.query(
        "SHOW TRANSACTION ISOLATION LEVEL"
      );
      const backend = await client.query(
        "SELECT pg_backend_pid()::STRING AS backend_id"
      );
      backendIds.push(backend.rows[0].backend_id);
      if (attempt === 0) {
        await barrier.wait();
        queryReady?.reach();
      }
      const result = await client.query(SPEND_SQL, valuesFor(request));
      await client.query("COMMIT");
      return {
        ...result.rows[0],
        transaction: {
          isolation: isolation.rows[0].transaction_isolation,
          backendIds,
          serializableRetries: attempt,
          retryCodes
        }
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      if (error.code === "40001" && attempt < 20) {
        retryCodes.push(error.code);
        continue;
      }
      queryReady?.fail(error);
      throw error;
    } finally {
      await client.end().catch(() => {});
    }
  }
  throw new Error("capability retry loop exhausted");
}

async function callStoredQuery(
  connectionString,
  sql,
  values,
  { readOnly = false, queryReady = null } = {}
) {
  const retryCodes = [];
  for (let attempt = 0; attempt <= 20; attempt += 1) {
    const client = new Client({ connectionString });
    try {
      await client.connect();
      await client.query(
        `BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE${
          readOnly ? " READ ONLY" : ""
        }`
      );
      if (attempt === 0) {
        queryReady?.reach();
      }
      const result = await client.query(sql, values);
      await client.query("COMMIT");
      return {
        rows: result.rows,
        rowCount: result.rowCount,
        serializableRetries: attempt,
        retryCodes
      };
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      if (error.code === "40001" && attempt < 20) {
        retryCodes.push(error.code);
        continue;
      }
      queryReady?.fail(error);
      throw error;
    } finally {
      await client.end().catch(() => {});
    }
  }
  throw new Error("stored-query retry loop exhausted");
}

async function databaseNow(connectionString) {
  const client = new Client({ connectionString });
  try {
    await client.connect();
    const result = await client.query(
      "SELECT clock_timestamp() AS database_now"
    );
    return new Date(result.rows[0].database_now).toISOString();
  } finally {
    await client.end().catch(() => {});
  }
}

async function waitForDatabaseTime({
  connectionString,
  target,
  timeoutMs = 30_000
}) {
  const targetMs = Date.parse(target);
  assert(Number.isFinite(targetMs), "database wait target was invalid");
  const deadline = Date.now() + timeoutMs;
  const client = new Client({ connectionString });
  try {
    await client.connect();
    while (Date.now() < deadline) {
      const result = await client.query(
        `
          SELECT
            clock_timestamp() AS database_now,
            clock_timestamp() >= $1::TIMESTAMPTZ AS reached
        `,
        [target]
      );
      if (result.rows[0].reached === true) {
        return new Date(result.rows[0].database_now).toISOString();
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  } finally {
    await client.end().catch(() => {});
  }
  throw new Error("database time boundary was not reached");
}

async function recoveryTimingSnapshot({
  connectionString,
  tenantId,
  operationId,
  evidenceId,
  conflictEvidenceId = null
}) {
  const client = new Client({ connectionString });
  try {
    await client.connect();
    const result = await client.query(
      `
        WITH observed_clock AS (
          SELECT clock_timestamp() AS database_now
        )
        SELECT
          observed_clock.database_now,
          receipt.lease_expires_at AS receipt_lease_expires_at,
          resource.lease_expires_at AS resource_lease_expires_at,
          proposal.expires_at AS proposal_expires_at,
          evidence.valid_until AS evidence_valid_until,
          conflict.valid_from AS conflict_valid_from,
          receipt.lease_expires_at > observed_clock.database_now
            AS receipt_live,
          resource.lease_expires_at > observed_clock.database_now
            AS resource_live,
          proposal.expires_at > observed_clock.database_now
            AS proposal_live,
          evidence.valid_until <= observed_clock.database_now
            AS evidence_expired,
          conflict.observed_at <=
              observed_clock.database_now + INTERVAL '5 minutes'
            AND conflict.valid_from <= observed_clock.database_now
            AND conflict.valid_until > observed_clock.database_now
            AS conflict_active
        FROM tp_ledger.g1_authority_receipts AS receipt
        JOIN tp_private.g1_resources AS resource
          ON resource.tenant_id = receipt.tenant_id
         AND resource.resource_id = receipt.resource_id
         AND resource.active_run_id = receipt.run_id
         AND resource.holder_incident_id = receipt.incident_id
         AND resource.holder_operation_id = receipt.operation_id
         AND resource.holder_agent_id = receipt.agent_id
         AND resource.holder_proposal_digest = receipt.proposal_digest
         AND resource.holder_logical_authority_key_sha256 =
           receipt.logical_authority_key_sha256
         AND resource.current_fence = receipt.fencing_token
        JOIN tp_ledger.g1_dvi_proposal_receipts AS proposal
          ON proposal.tenant_id = receipt.tenant_id
         AND proposal.proposal_digest = receipt.proposal_digest
         AND proposal.logical_action_digest = receipt.logical_action_digest
         AND proposal.authorization_epoch = receipt.authorization_epoch
         AND proposal.logical_authority_key_sha256 =
           receipt.logical_authority_key_sha256
         AND proposal.authorization_binding_sha256 =
           receipt.authorization_binding_sha256
         AND proposal.run_id = receipt.run_id
         AND proposal.incident_id = receipt.incident_id
         AND proposal.resource_id = receipt.resource_id
        JOIN tp_private.g1_evidence AS evidence
          ON evidence.tenant_id = receipt.tenant_id
         AND evidence.evidence_id = $3::UUID
        LEFT JOIN tp_private.g1_evidence AS conflict
          ON conflict.tenant_id = receipt.tenant_id
         AND conflict.evidence_id = $4::UUID
        CROSS JOIN observed_clock
        WHERE receipt.tenant_id = $1::UUID
          AND receipt.operation_id = $2::UUID
      `,
      [tenantId, operationId, evidenceId, conflictEvidenceId]
    );
    assert(result.rowCount === 1, "recovery timing snapshot was not singular");
    return result.rows[0];
  } finally {
    await client.end().catch(() => {});
  }
}

async function prepareReservedFixture({
  store,
  signer,
  authorizerUrl,
  prefix,
  evidenceObservedAt,
  evidenceValidFrom,
  evidenceValidUntil
}) {
  const fixture = {
    tenantId: randomUUID(),
    runId: randomUUID(),
    incidentId: randomUUID(),
    evidenceId: randomUUID(),
    resourceId: `${prefix}-${randomUUID()}`
  };
  await signer.register(store, fixture.tenantId);
  const evidence = await signer.append(store, {
    tenantId: fixture.tenantId,
    evidenceId: fixture.evidenceId,
    incidentId: fixture.incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt:
      evidenceObservedAt ?? new Date(Date.now() - 60_000).toISOString(),
    validFrom:
      evidenceValidFrom ?? new Date(Date.now() - 120_000).toISOString(),
    validUntil:
      evidenceValidUntil ?? new Date(Date.now() + 30 * 60_000).toISOString(),
    conflictStatus: "none",
    assertion: `Synthetic ${prefix} evidence.`,
    embedding: [0.86, 0.08, 0.06]
  });
  assert(evidence.outcome === "evidence_verified", `${prefix} evidence failed`);
  await store.prepareResource(fixture);
  const rawRequest = {
    ...fixture,
    operationId: randomUUID(),
    agentId: `${prefix}-agent`,
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: `synthetic-${prefix}`,
      action: "dispatch_rescue_unit",
      destination: `synthetic-zone-${prefix}`
    }
  };
  const authorization = await authorizeSyntheticProposal(store, rawRequest);
  const request = normalizedAuthorityRequestFor({
    ...rawRequest,
    dviAuthorization: authorization.dviAuthorization
  });
  const decision = await callCapability(authorizerUrl, request, {
    async wait() {}
  });
  assert(
    decision.decision_outcome === "resource_reserved" &&
      decision.decision_authority_current === true,
    `${prefix} authority was not reserved`
  );
  return { fixture, request, decision };
}

async function runStoredFunctionHeldExpiryProof({
  store,
  signer,
  adminUrl,
  authorizerUrl
}) {
  const fixture = {
    tenantId: randomUUID(),
    runId: randomUUID(),
    incidentId: randomUUID(),
    evidenceId: randomUUID(),
    resourceId: `capability-held-expiry-${randomUUID()}`
  };
  await signer.register(store, fixture.tenantId);
  const evidence = await signer.append(store, {
    tenantId: fixture.tenantId,
    evidenceId: fixture.evidenceId,
    incidentId: fixture.incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "available",
    observedAt: new Date(Date.now() - 60_000).toISOString(),
    validFrom: new Date(Date.now() - 120_000).toISOString(),
    validUntil: new Date(Date.now() + 30 * 60_000).toISOString(),
    conflictStatus: "none",
    assertion: "Synthetic stored-function lock-wait expiry evidence.",
    embedding: [0.86, 0.08, 0.06]
  });
  assert(evidence.outcome === "evidence_verified", "held evidence did not verify");
  await store.prepareResource(fixture);
  const rawRequest = {
    ...fixture,
    operationId: randomUUID(),
    agentId: "capability-held-expiry-agent",
    agency: "rescue",
    intentNonce: randomUUID(),
    effectKey: randomUUID(),
    leaseMs: 300_000,
    payload: {
      scenario: "synthetic-stored-function-held-expiry",
      action: "dispatch_rescue_unit",
      destination: "synthetic-zone-held-expiry"
    }
  };
  const authorization = await authorizeSyntheticProposal(store, rawRequest);
  const request = normalizedAuthorityRequestFor({
    ...rawRequest,
    dviAuthorization: authorization.dviAuthorization
  });
  const lockClient = new Client({ connectionString: adminUrl });
  let lockOpen = false;
  let pendingDecision = null;
  try {
    await lockClient.connect();
    await lockClient.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    lockOpen = true;
    const locked = await lockClient.query(
      `
        SELECT resource_id
        FROM tp_private.g1_resources
        WHERE tenant_id = $1::UUID
          AND resource_id = $2
        FOR UPDATE
      `,
      [fixture.tenantId, fixture.resourceId]
    );
    assert(locked.rowCount === 1, "held-expiry resource lock was not acquired");
    const queryReady = new QueryReadyBarrier("stored spend held expiry");
    let settled = false;
    pendingDecision = callCapability(
      authorizerUrl,
      request,
      { async wait() {} },
      { queryReady }
    );
    pendingDecision.then(
      () => { settled = true; },
      () => { settled = true; }
    );
    await queryReady.wait();
    await store.setProposalExpiryAfterMsForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest,
      delayMs: 1_500
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!settled, "stored spend did not wait behind the held resource lock");
    await store.waitForProposalExpiryForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest
    });
    await lockClient.query("COMMIT");
    lockOpen = false;
    const decision = await pendingDecision;
    const snapshot = await store.snapshot(fixture);
    assert(
      decision.decision_outcome === "authorization_denied" &&
        decision.decision_reason === "proposal_authorization_expired" &&
        decision.decision_authority_current === false,
      "stored spend held past proposal expiry retained authority"
    );
    assert(
      snapshot.receipts.length === 1 &&
        snapshot.receipts[0].outcome === "authorization_denied" &&
        snapshot.outbox.length === 0 &&
        snapshot.effects.length === 0 &&
        snapshot.resource.current_fence === "0",
      "stored held-expiry spend changed protected authority state"
    );
    return {
      decisionOutcome: decision.decision_outcome,
      decisionReason: decision.decision_reason,
      authorityCurrent: decision.decision_authority_current,
      receiptCount: snapshot.receipts.length,
      outboxCount: snapshot.outbox.length,
      effectCount: snapshot.effects.length,
      fence: snapshot.resource.current_fence
    };
  } finally {
    if (lockOpen) {
      if (pendingDecision) {
        await store.expireProposalAtDatabaseNowForTest({
          tenantId: fixture.tenantId,
          proposalDigest: request.proposalDigest
        }).catch(() => {});
      }
      await lockClient.query("ROLLBACK").catch(() => {});
    }
    if (pendingDecision) {
      await pendingDecision.catch(() => {});
    }
    await lockClient.end().catch(() => {});
  }
}

async function runReplayClockPairBoundaryControl({
  store,
  signer,
  authorizerUrl
}) {
  const { fixture, request } = await prepareReservedFixture({
    store,
    signer,
    authorizerUrl,
    prefix: "capability-replay-clock-boundary"
  });
  const client = new Client({ connectionString: authorizerUrl });
  let transactionOpen = false;
  try {
    await client.connect();
    const scheduled = await store.setProposalExpiryAfterMsForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest,
      delayMs: 1_500
    });
    await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    transactionOpen = true;
    const atBoundaryStart = await client.query(
      SPEND_SQL,
      valuesFor(request)
    );
    const replayAtA = atBoundaryStart.rows[0];
    const decisionAtA = Date.parse(replayAtA.decision_database_now);
    const proposalExpiry = Date.parse(scheduled.expires_at);
    assert(
      replayAtA.decision_replay_kind === "operation_replay" &&
        replayAtA.decision_authority_current === true &&
        decisionAtA < proposalExpiry,
      "replay was not current at boundary clock A"
    );
    await store.waitForProposalExpiryForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest
    });
    const laterClock = await client.query(
      "SELECT clock_timestamp() AS database_now"
    );
    const databaseNowAtB = Date.parse(laterClock.rows[0].database_now);
    assert(
      decisionAtA < proposalExpiry &&
        proposalExpiry <= databaseNowAtB &&
        replayAtA.decision_authority_current !==
          (databaseNowAtB < proposalExpiry),
      "amplified old two-clock replay control did not cross proposal expiry"
    );
    await client.query("ROLLBACK");
    transactionOpen = false;

    await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    transactionOpen = true;
    const atBoundaryEnd = await client.query(SPEND_SQL, valuesFor(request));
    const replayAtC = atBoundaryEnd.rows[0];
    await client.query("COMMIT");
    transactionOpen = false;
    const decisionAtC = Date.parse(replayAtC.decision_database_now);
    assert(
      replayAtC.decision_replay_kind === "operation_replay" &&
        replayAtC.decision_authority_current === false &&
        decisionAtC >= proposalExpiry &&
        decisionAtC - proposalExpiry <= 1_000 &&
        replayAtC.decision_authority_current ===
          (decisionAtC < proposalExpiry),
      "same-clock replay pair did not fail closed at boundary clock C"
    );
    const snapshot = await store.snapshot(fixture);
    assert(
      snapshot.receipts.length === 1 &&
        snapshot.outbox.length === 1 &&
        snapshot.effects.length === 0 &&
        snapshot.resource.current_fence === "1",
      "replay clock boundary control changed durable authority occupancy"
    );
    return {
      replayKind: replayAtC.decision_replay_kind,
      amplifiedOldPairContradicted: true,
      sameClockPairCurrent: replayAtC.decision_authority_current,
      receiptCount: snapshot.receipts.length,
      outboxCount: snapshot.outbox.length,
      effectCount: snapshot.effects.length,
      fence: snapshot.resource.current_fence
    };
  } finally {
    if (transactionOpen) {
      await client.query("ROLLBACK").catch(() => {});
    }
    await client.end().catch(() => {});
  }
}

async function runStoredReplayHeldExpiryProof({
  store,
  signer,
  adminUrl,
  authorizerUrl
}) {
  const { fixture, request } = await prepareReservedFixture({
    store,
    signer,
    authorizerUrl,
    prefix: "capability-replay-expiry"
  });
  const lockClient = new Client({ connectionString: adminUrl });
  let lockOpen = false;
  let pendingReplay = null;
  try {
    await lockClient.connect();
    await lockClient.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    lockOpen = true;
    const intent = await lockClient.query(
      `
        UPDATE tp_ledger.g1_outbox_intents
        SET payload = '{"temporary-replay-lock-probe":true}'::JSONB
        WHERE tenant_id = $1::UUID
          AND operation_id = $2::UUID
        RETURNING operation_id
      `,
      [fixture.tenantId, request.operationId]
    );
    assert(intent.rowCount === 1, "replay outbox intent was not created");
    const queryReady = new QueryReadyBarrier("stored replay held expiry");
    let settled = false;
    pendingReplay = callCapability(
      authorizerUrl,
      request,
      { async wait() {} },
      { queryReady }
    );
    pendingReplay.then(
      () => { settled = true; },
      () => { settled = true; }
    );
    await queryReady.wait();
    await store.setProposalExpiryAfterMsForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest,
      delayMs: 1_500
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!settled, "stored replay currentness did not wait on the outbox intent");
    const expired = await store.waitForProposalExpiryForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest
    });
    await lockClient.query("ROLLBACK");
    lockOpen = false;
    const replay = await pendingReplay;
    const snapshot = await store.snapshot(fixture);
    const replayDecisionTime = Date.parse(replay.decision_database_now);
    const proposalExpiry = Date.parse(expired.expires_at);
    assert(
      replay.decision_outcome === "resource_reserved" &&
        replay.decision_replay_kind === "operation_replay" &&
        replay.decision_authority_current === false &&
        replayDecisionTime >= proposalExpiry &&
        replayDecisionTime - proposalExpiry <= 1_000,
      "stored replay reported expired authority as current"
    );
    assert(
      replay.decision_authority_current ===
        (replayDecisionTime < proposalExpiry),
      "stored replay currentness and reported database time used different clocks"
    );
    assert(
      snapshot.receipts.length === 1 &&
        snapshot.outbox.length === 1 &&
        snapshot.effects.length === 0 &&
        snapshot.resource.current_fence === "1",
      "stored replay expiry changed durable authority occupancy"
    );
    return {
      replayKind: replay.decision_replay_kind,
      authorityCurrent: replay.decision_authority_current,
      receiptCount: snapshot.receipts.length,
      outboxCount: snapshot.outbox.length,
      effectCount: snapshot.effects.length,
      fence: snapshot.resource.current_fence
    };
  } finally {
    if (lockOpen) {
      if (pendingReplay) {
        await store.expireProposalAtDatabaseNowForTest({
          tenantId: fixture.tenantId,
          proposalDigest: request.proposalDigest
        }).catch(() => {});
      }
      await lockClient.query("ROLLBACK").catch(() => {});
    }
    if (pendingReplay) {
      await pendingReplay.catch(() => {});
    }
    await lockClient.end().catch(() => {});
  }
}

async function runStoredProtectedEffectHeldExpiryProof({
  store,
  signer,
  adminUrl,
  authorizerUrl,
  dispatchUrl
}) {
  const { fixture, request, decision } = await prepareReservedFixture({
    store,
    signer,
    authorizerUrl,
    prefix: "capability-effect-expiry"
  });
  const fencingToken = decision.decision_fencing_token;
  const blocker = new Client({ connectionString: adminUrl });
  let blockerOpen = false;
  let pendingEffect = null;
  try {
    await blocker.connect();
    await blocker.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    blockerOpen = true;
    await blocker.query(
      `
        INSERT INTO tp_ledger.g1_protected_effects (
          tenant_id, effect_key, operation_id, request_digest,
          proposal_digest, logical_action_digest, authorization_epoch,
          logical_authority_key_sha256, authorization_binding_sha256,
          run_id, incident_id, resource_id, agent_id, fencing_token,
          payload_digest
        ) VALUES (
          $1::UUID, $2::UUID, $3::UUID, $4,
          $5, $6, $7::INT8, $8, $9,
          $10::UUID, $11::UUID, $12, $13, $14::INT8, $15
        )
      `,
      [
        request.tenantId,
        request.effectKey,
        request.operationId,
        request.requestDigest,
        request.proposalDigest,
        request.logicalActionDigest,
        request.authorizationEpoch,
        request.logicalAuthorityKeySha256,
        request.authorizationBindingSha256,
        request.runId,
        request.incidentId,
        request.resourceId,
        request.agentId,
        fencingToken,
        request.payloadDigest
      ]
    );
    const queryReady = new QueryReadyBarrier("protected effect held expiry");
    let settled = false;
    pendingEffect = callStoredQuery(
      dispatchUrl,
      PROTECTED_EFFECT_SQL,
      [
        request.tenantId,
        request.effectKey,
        request.operationId,
        request.requestDigest,
        request.runId,
        request.incidentId,
        request.resourceId,
        request.agentId,
        fencingToken,
        request.payloadDigest
      ],
      { queryReady }
    );
    pendingEffect.then(
      () => { settled = true; },
      () => { settled = true; }
    );
    await queryReady.wait();
    await store.setProposalExpiryAfterMsForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest,
      delayMs: 1_500
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!settled, "protected effect did not wait on unique occupancy");
    await store.waitForProposalExpiryForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest
    });
    await blocker.query("ROLLBACK");
    blockerOpen = false;
    const effect = await pendingEffect;
    const snapshot = await store.snapshot(fixture);
    assert(
      effect.rowCount === 0 && snapshot.effects.length === 0,
      "protected effect survived post-wait proposal expiry"
    );
    return {
      returnedRows: effect.rowCount,
      serializableRetries: effect.serializableRetries,
      retryCodes: effect.retryCodes,
      effectCount: snapshot.effects.length
    };
  } finally {
    if (blockerOpen) {
      if (pendingEffect) {
        await store.expireProposalAtDatabaseNowForTest({
          tenantId: fixture.tenantId,
          proposalDigest: request.proposalDigest
        }).catch(() => {});
      }
      await blocker.query("ROLLBACK").catch(() => {});
    }
    if (pendingEffect) {
      await pendingEffect.catch(() => {});
    }
    await blocker.end().catch(() => {});
  }
}

async function runRecoveryResolverHeldExpiryProof({
  store,
  signer,
  adminUrl,
  authorizerUrl,
  recoverySourceUrl
}) {
  const { fixture, request } = await prepareReservedFixture({
    store,
    signer,
    authorizerUrl,
    prefix: "capability-recovery-expiry"
  });
  const blocker = new Client({ connectionString: adminUrl });
  let blockerOpen = false;
  let pendingResolution = null;
  try {
    await blocker.connect();
    await blocker.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    blockerOpen = true;
    const intent = await blocker.query(
      `
        UPDATE tp_ledger.g1_authority_receipts
        SET reason = 'temporary-recovery-lock-probe'
        WHERE tenant_id = $1::UUID
          AND operation_id = $2::UUID
        RETURNING operation_id
      `,
      [request.tenantId, request.operationId]
    );
    assert(intent.rowCount === 1, "recovery resolver intent was not created");
    const queryReady = new QueryReadyBarrier("recovery resolver held expiry");
    let settled = false;
    pendingResolution = callStoredQuery(
      recoverySourceUrl,
      RECOVERY_SOURCE_SQL,
      [
        request.tenantId,
        request.runId,
        request.incidentId,
        request.evidenceId,
        request.resourceId,
        request.operationId,
        request.requestDigest
      ],
      { readOnly: true, queryReady }
    );
    pendingResolution.then(
      () => { settled = true; },
      () => { settled = true; }
    );
    await queryReady.wait();
    await store.setProposalExpiryAfterMsForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest,
      delayMs: 1_500
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!settled, "recovery resolver did not wait behind the receipt intent");
    await store.waitForProposalExpiryForTest({
      tenantId: fixture.tenantId,
      proposalDigest: request.proposalDigest
    });
    await blocker.query("ROLLBACK");
    blockerOpen = false;
    const resolution = await pendingResolution;
    assert(
      resolution.rowCount === 0,
      "recovery resolver released context after post-wait expiry"
    );
    return {
      returnedRows: resolution.rowCount,
      serializableRetries: resolution.serializableRetries,
      retryCodes: resolution.retryCodes
    };
  } finally {
    if (blockerOpen) {
      if (pendingResolution) {
        await store.expireProposalAtDatabaseNowForTest({
          tenantId: fixture.tenantId,
          proposalDigest: request.proposalDigest
        }).catch(() => {});
      }
      await blocker.query("ROLLBACK").catch(() => {});
    }
    if (pendingResolution) {
      await pendingResolution.catch(() => {});
    }
    await blocker.end().catch(() => {});
  }
}

async function runRecoveryResolverEvidenceExpiryProof({
  store,
  signer,
  adminUrl,
  authorizerUrl,
  recoverySourceUrl
}) {
  const initialDatabaseNow = await databaseNow(adminUrl);
  const evidenceValidUntil = new Date(
    Date.parse(initialDatabaseNow) + 20_000
  ).toISOString();
  const { fixture, request } = await prepareReservedFixture({
    store,
    signer,
    authorizerUrl,
    prefix: "capability-recovery-evidence-expiry",
    evidenceObservedAt: new Date(
      Date.parse(initialDatabaseNow) - 60_000
    ).toISOString(),
    evidenceValidFrom: new Date(
      Date.parse(initialDatabaseNow) - 120_000
    ).toISOString(),
    evidenceValidUntil
  });
  await waitForDatabaseTime({
    connectionString: adminUrl,
    target: new Date(Date.parse(evidenceValidUntil) - 1_500).toISOString()
  });
  assert(
    Date.parse(await databaseNow(adminUrl)) < Date.parse(evidenceValidUntil),
    "selected evidence expired before the recovery wait began"
  );
  const blocker = new Client({ connectionString: adminUrl });
  let blockerOpen = false;
  let pendingResolution = null;
  try {
    await blocker.connect();
    await blocker.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    blockerOpen = true;
    const intent = await blocker.query(
      `
        UPDATE tp_ledger.g1_authority_receipts
        SET reason = 'temporary-recovery-evidence-expiry-lock-probe'
        WHERE tenant_id = $1::UUID
          AND operation_id = $2::UUID
        RETURNING operation_id
      `,
      [request.tenantId, request.operationId]
    );
    assert(intent.rowCount === 1, "evidence-expiry receipt intent was not created");
    const queryReady = new QueryReadyBarrier("recovery evidence expiry");
    let settled = false;
    pendingResolution = callStoredQuery(
      recoverySourceUrl,
      RECOVERY_SOURCE_SQL,
      [
        request.tenantId,
        request.runId,
        request.incidentId,
        request.evidenceId,
        request.resourceId,
        request.operationId,
        request.requestDigest
      ],
      { readOnly: true, queryReady }
    );
    pendingResolution.then(
      () => { settled = true; },
      () => { settled = true; }
    );
    await queryReady.wait();
    assert(
      Date.parse(await databaseNow(adminUrl)) < Date.parse(evidenceValidUntil),
      "selected evidence expired before the resolver query was ready"
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!settled, "recovery evidence expiry did not wait on the receipt intent");
    await waitForDatabaseTime({
      connectionString: adminUrl,
      target: evidenceValidUntil
    });
    await blocker.query("ROLLBACK");
    blockerOpen = false;
    const resolution = await pendingResolution;
    const timing = await recoveryTimingSnapshot({
      connectionString: adminUrl,
      tenantId: request.tenantId,
      operationId: request.operationId,
      evidenceId: request.evidenceId
    });
    assert(
      resolution.rowCount === 0 &&
        timing.evidence_expired === true &&
        timing.receipt_live === true &&
        timing.resource_live === true &&
        timing.proposal_live === true,
      "recovery resolver released expired evidence or authority did not remain live"
    );
    return {
      returnedRows: resolution.rowCount,
      serializableRetries: resolution.serializableRetries,
      retryCodes: resolution.retryCodes,
      selectedEvidenceExpired: timing.evidence_expired,
      receiptLive: timing.receipt_live,
      resourceLive: timing.resource_live,
      proposalLive: timing.proposal_live
    };
  } finally {
    if (blockerOpen) {
      if (pendingResolution) {
        await store.expireProposalAtDatabaseNowForTest({
          tenantId: fixture.tenantId,
          proposalDigest: request.proposalDigest
        }).catch(() => {});
      }
      await blocker.query("ROLLBACK").catch(() => {});
    }
    if (pendingResolution) {
      await pendingResolution.catch(() => {});
    }
    await blocker.end().catch(() => {});
  }
}

async function runRecoveryResolverConflictActivationProof({
  store,
  signer,
  adminUrl,
  authorizerUrl,
  recoverySourceUrl
}) {
  const { fixture, request } = await prepareReservedFixture({
    store,
    signer,
    authorizerUrl,
    prefix: "capability-recovery-conflict-activation"
  });
  const initialDatabaseNow = await databaseNow(adminUrl);
  const conflictValidFrom = new Date(
    Date.parse(initialDatabaseNow) + 10_000
  ).toISOString();
  const conflictEvidenceId = randomUUID();
  const conflict = await signer.append(store, {
    tenantId: fixture.tenantId,
    evidenceId: conflictEvidenceId,
    incidentId: fixture.incidentId,
    agencyScope: "rescue",
    claimKey: "rescue_unit_status",
    claimValue: "unavailable",
    observedAt: new Date(
      Date.parse(initialDatabaseNow) - 60_000
    ).toISOString(),
    validFrom: conflictValidFrom,
    validUntil: new Date(
      Date.parse(initialDatabaseNow) + 30 * 60_000
    ).toISOString(),
    conflictStatus: "none",
    assertion: "Synthetic recovery conflict-activation evidence.",
    embedding: [0.08, 0.86, 0.06]
  });
  assert(conflict.outcome === "evidence_verified", "conflict evidence failed");
  await waitForDatabaseTime({
    connectionString: adminUrl,
    target: new Date(Date.parse(conflictValidFrom) - 1_500).toISOString()
  });
  assert(
    Date.parse(await databaseNow(adminUrl)) < Date.parse(conflictValidFrom),
    "conflicting evidence became active before the recovery wait began"
  );
  const blocker = new Client({ connectionString: adminUrl });
  let blockerOpen = false;
  let pendingResolution = null;
  try {
    await blocker.connect();
    await blocker.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
    blockerOpen = true;
    const intent = await blocker.query(
      `
        UPDATE tp_ledger.g1_authority_receipts
        SET reason = 'temporary-recovery-conflict-activation-lock-probe'
        WHERE tenant_id = $1::UUID
          AND operation_id = $2::UUID
        RETURNING operation_id
      `,
      [request.tenantId, request.operationId]
    );
    assert(intent.rowCount === 1, "conflict-activation receipt intent was not created");
    const queryReady = new QueryReadyBarrier("recovery conflict activation");
    let settled = false;
    pendingResolution = callStoredQuery(
      recoverySourceUrl,
      RECOVERY_SOURCE_SQL,
      [
        request.tenantId,
        request.runId,
        request.incidentId,
        request.evidenceId,
        request.resourceId,
        request.operationId,
        request.requestDigest
      ],
      { readOnly: true, queryReady }
    );
    pendingResolution.then(
      () => { settled = true; },
      () => { settled = true; }
    );
    await queryReady.wait();
    assert(
      Date.parse(await databaseNow(adminUrl)) < Date.parse(conflictValidFrom),
      "conflicting evidence activated before the resolver query was ready"
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert(!settled, "recovery conflict activation did not wait on the receipt intent");
    await waitForDatabaseTime({
      connectionString: adminUrl,
      target: conflictValidFrom
    });
    await blocker.query("ROLLBACK");
    blockerOpen = false;
    const resolution = await pendingResolution;
    const timing = await recoveryTimingSnapshot({
      connectionString: adminUrl,
      tenantId: request.tenantId,
      operationId: request.operationId,
      evidenceId: request.evidenceId,
      conflictEvidenceId
    });
    assert(
      resolution.rowCount === 0 &&
        timing.conflict_active === true &&
        timing.evidence_expired === false &&
        timing.receipt_live === true &&
        timing.resource_live === true &&
        timing.proposal_live === true,
      "recovery resolver released an active conflict or authority did not remain live"
    );
    return {
      returnedRows: resolution.rowCount,
      serializableRetries: resolution.serializableRetries,
      retryCodes: resolution.retryCodes,
      conflictActive: timing.conflict_active,
      selectedEvidenceExpired: timing.evidence_expired,
      receiptLive: timing.receipt_live,
      resourceLive: timing.resource_live,
      proposalLive: timing.proposal_live
    };
  } finally {
    if (blockerOpen) {
      if (pendingResolution) {
        await store.expireProposalAtDatabaseNowForTest({
          tenantId: fixture.tenantId,
          proposalDigest: request.proposalDigest
        }).catch(() => {});
      }
      await blocker.query("ROLLBACK").catch(() => {});
    }
    if (pendingResolution) {
      await pendingResolution.catch(() => {});
    }
    await blocker.end().catch(() => {});
  }
}

async function main() {
  const adminUrl = requiredEnvironment("DATABASE_URL");
  const authorizerUrl = requiredEnvironment("AUTHORIZER_DATABASE_URL");
  const dispatchUrl = requiredEnvironment("DISPATCH_DATABASE_URL");
  const recoverySourceUrl = requiredEnvironment(
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL"
  );
  const store = new AuthorityStore({
    connectionString: adminUrl,
    databaseName: "tideproof",
    maxConnections: 8
  });
  const signer = createSyntheticEvidenceSigner();
  try {
    await store.migrate();
    const fixture = {
      tenantId: randomUUID(),
      runId: randomUUID(),
      incidentId: randomUUID(),
      evidenceId: randomUUID(),
      resourceId: `capability-race-${randomUUID()}`
    };
    await signer.register(store, fixture.tenantId);
    const evidence = await signer.append(store, {
      tenantId: fixture.tenantId,
      evidenceId: fixture.evidenceId,
      incidentId: fixture.incidentId,
      agencyScope: "rescue",
      claimKey: "rescue_unit_status",
      claimValue: "available",
      observedAt: new Date(Date.now() - 60_000).toISOString(),
      validFrom: new Date(Date.now() - 120_000).toISOString(),
      validUntil: new Date(Date.now() + 30 * 60_000).toISOString(),
      conflictStatus: "none",
      assertion: "Synthetic capability race evidence.",
      embedding: [0.86, 0.08, 0.06]
    });
    assert(evidence.outcome === "evidence_verified", "evidence did not verify");
    await store.prepareResource(fixture);

    const rawRequests = Array.from({ length: CONTENDERS }, (_, index) => ({
        ...fixture,
        operationId: randomUUID(),
        agentId: `capability-agent-${String(index + 1).padStart(2, "0")}`,
        agency: "rescue",
        intentNonce: randomUUID(),
        effectKey: randomUUID(),
        leaseMs: 300_000,
        payload: {
          scenario: "synthetic-highwater",
          action: "dispatch_rescue_unit",
          destination: "synthetic-zone-capability-race"
        }
      }));
    const requests = (
      await authorizeSyntheticContenders(store, rawRequests)
    ).map((request) => normalizedAuthorityRequestFor(request));
    const barrier = new Barrier(CONTENDERS);
    const settled = await Promise.allSettled(
      requests.map((request) =>
        callCapability(authorizerUrl, request, barrier)
      )
    );
    const failed = settled.filter(({ status }) => status === "rejected");
    assert(failed.length === 0, "a capability contender failed");
    const results = settled.map(({ value }) => value);
    const winners = results.filter(
      ({ decision_outcome }) => decision_outcome === "resource_reserved"
    );
    const denials = results.filter(
      ({ decision_outcome }) => decision_outcome === "resource_held_denied"
    );
    const snapshot = await store.snapshot(fixture);
    assert(winners.length === 1, "capability race did not have one winner");
    assert(denials.length === 49, "capability race did not have 49 denials");
    assert(
      snapshot.receipts.length === 50 &&
        snapshot.outbox.length === 1 &&
        snapshot.effects.length === 0 &&
        snapshot.resource.current_fence === "1",
      "capability race durable state was incorrect"
    );
    const initialBackends = new Set(
      results.map(({ transaction }) => transaction.backendIds[0])
    );
    assert(initialBackends.size === 50, "contenders did not use 50 sessions");
    assert(
      results.every(
        ({ transaction }) => transaction.isolation === "serializable"
      ),
      "a capability contender was not SERIALIZABLE"
    );

    const storedFunctionHeldExpiry = await runStoredFunctionHeldExpiryProof({
      store,
      signer,
      adminUrl,
      authorizerUrl
    });
    const replayClockPairBoundary = await runReplayClockPairBoundaryControl({
      store,
      signer,
      authorizerUrl
    });
    const storedReplayHeldExpiry = await runStoredReplayHeldExpiryProof({
      store,
      signer,
      adminUrl,
      authorizerUrl
    });
    const storedProtectedEffectHeldExpiry =
      await runStoredProtectedEffectHeldExpiryProof({
        store,
        signer,
        adminUrl,
        authorizerUrl,
        dispatchUrl
      });
    const recoveryResolverHeldExpiry =
      await runRecoveryResolverHeldExpiryProof({
        store,
        signer,
        adminUrl,
        authorizerUrl,
        recoverySourceUrl
      });
    const recoveryResolverEvidenceExpiry =
      await runRecoveryResolverEvidenceExpiryProof({
        store,
        signer,
        adminUrl,
        authorizerUrl,
        recoverySourceUrl
      });
    const recoveryResolverConflictActivation =
      await runRecoveryResolverConflictActivationProof({
        store,
        signer,
        adminUrl,
        authorizerUrl,
        recoverySourceUrl
      });

    const probe = new Client({ connectionString: authorizerUrl });
    await probe.connect();
    let directReadDenied = false;
    try {
      await probe.query(
        "SELECT * FROM tp_ledger.g1_authority_receipts LIMIT 1"
      );
    } catch (error) {
      directReadDenied = error.code === "42501";
    } finally {
      await probe.end();
    }
    assert(directReadDenied, "authorizer could read the base ledger directly");

    console.log(
      JSON.stringify(
        {
          gate: "least-privilege-capability-race",
          passed: true,
          contenders: CONTENDERS,
          distinctInitialSessions: initialBackends.size,
          winners: winners.length,
          durableDenials: denials.length,
          receiptCount: snapshot.receipts.length,
          outboxCount: snapshot.outbox.length,
          effectCount: snapshot.effects.length,
          fence: snapshot.resource.current_fence,
          serializableRetries: results.reduce(
            (sum, { transaction }) =>
              sum + transaction.serializableRetries,
            0
          ),
          retryCodes: results.flatMap(
            ({ transaction }) => transaction.retryCodes
          ),
          directBaseLedgerReadDenied: directReadDenied,
          storedFunctionHeldExpiry,
          replayClockPairBoundary,
          storedReplayHeldExpiry,
          storedProtectedEffectHeldExpiry,
          recoveryResolverHeldExpiry,
          recoveryResolverEvidenceExpiry,
          recoveryResolverConflictActivation,
          invariantViolations: 0
        },
        null,
        2
      )
    );
  } finally {
    await store.close();
  }
}

main().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "least-privilege-capability-race",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
