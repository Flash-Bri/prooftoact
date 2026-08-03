import { createHash, randomUUID } from "node:crypto";
import { Client } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import {
  databaseClientMustBeDiscarded,
  runtimeDatabaseConfig
} from "./database-runtime.js";
import {
  committedDatabaseResult,
  databaseTimestampFromDriver
} from "./database-commit-result.js";
import {
  recoveryQueryTemplateDigest,
  renderRecoveryQuery,
  validateRecoveryRow
} from "./recovery-store.js";

const FIXED_DATABASE = "tideproof_recovery";
const FIXED_TOOL = "select_query";
const RECOVERY_PUBLISHER_TRUST_ROOT_ID =
  "gate1-recovery-publisher-v1";

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function requireUuid(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      text
    )
  ) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text;
}

function requireSha256(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (!/^[a-f0-9]{64}$/u.test(text)) {
    throw new TypeError(`${name} must be a SHA-256 digest`);
  }
  return text;
}

function primaryRuntimeClient({
  connectionString,
  clientFactory,
  applicationName
}) {
  if (typeof clientFactory === "function") {
    return clientFactory(applicationName);
  }
  if (!connectionString) {
    throw new Error("connectionString is required");
  }
  return new Client(runtimeDatabaseConfig({
    connectionString: connectionStringForDatabase(
      connectionString,
      "tideproof"
    ),
    max: 1,
    applicationName
  }));
}

export async function assertRecoveryPublisherTrustRootWriteDenied({
  connectionString,
  clientFactory = null,
  credentialLabel = "recovery-runtime"
} = {}) {
  const client = primaryRuntimeClient({
    connectionString,
    clientFactory,
    applicationName: `tideproof-${requireText(
      credentialLabel,
      "credentialLabel"
    )}-trust-root-denial`
  });
  let transactionOpen = false;
  try {
    await client.connect();
    await client.query("BEGIN");
    transactionOpen = true;
    try {
      await client.query(`
        UPDATE tp_ledger.g1_recovery_publisher_trust_roots
        SET trust_root_commitment = trust_root_commitment
        WHERE trust_root_id = 'gate1-recovery-publisher-v1'
      `);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      transactionOpen = false;
      if (error?.code === "42501") {
        return Object.freeze({ denied: true, sqlstate: error.code });
      }
      throw error;
    }
    await client.query("ROLLBACK");
    transactionOpen = false;
    throw new Error("RECOVERY_RUNNER_CAN_REWRITE_PUBLISHER_TRUST_ROOT");
  } finally {
    if (transactionOpen) {
      await client.query("ROLLBACK").catch(() => {});
    }
    await client.end().catch(() => {});
  }
}

export async function resolveCommittedRecoverySourceReceipt({
  connectionString,
  binding,
  clientFactory = null
} = {}) {
  const expected = Object.freeze({
    tenantId: requireUuid(binding?.tenantId, "binding.tenantId"),
    runId: requireUuid(binding?.runId, "binding.runId"),
    incidentId: requireUuid(binding?.incidentId, "binding.incidentId"),
    evidenceId: requireUuid(binding?.evidenceId, "binding.evidenceId"),
    resourceId: requireText(binding?.resourceId, "binding.resourceId"),
    operationId: requireUuid(binding?.operationId, "binding.operationId"),
    requestDigest: requireSha256(
      binding?.requestDigest,
      "binding.requestDigest"
    )
  });
  const client = primaryRuntimeClient({
    connectionString,
    clientFactory,
    applicationName: "tideproof-recovery-source-resolver"
  });
  try {
    await client.connect();
    const result = await client.query(
      `
        SELECT *
        FROM tp_api.g1_resolve_recovery_source_receipt_v1(
          $1::UUID, $2::UUID, $3::UUID, $4::UUID,
          $5, $6::UUID, $7
        )
      `,
      [
        expected.tenantId,
        expected.runId,
        expected.incidentId,
        expected.evidenceId,
        expected.resourceId,
        expected.operationId,
        expected.requestDigest
      ]
    );
    if (result.rowCount !== 1) {
      throw new Error("RECOVERY_SOURCE_RECEIPT_NOT_CURRENT");
    }
    const row = result.rows[0];
    const recordedAt = new Date(row.recorded_at);
    const databaseNow = new Date(row.database_now);
    if (
      row.tenant_id !== expected.tenantId ||
      row.run_id !== expected.runId ||
      row.incident_id !== expected.incidentId ||
      row.evidence_id !== expected.evidenceId ||
      row.resource_id !== expected.resourceId ||
      row.operation_id !== expected.operationId ||
      row.request_digest !== expected.requestDigest ||
      row.outcome !== "resource_reserved" ||
      row.admissibility !== "admissible" ||
      row.has_durable_intent !== true ||
      !Number.isFinite(recordedAt.getTime()) ||
      !Number.isFinite(databaseNow.getTime()) ||
      recordedAt.getTime() > databaseNow.getTime() ||
      databaseNow.getTime() - recordedAt.getTime() > 50 * 60 * 1_000
    ) {
      throw new Error("RECOVERY_SOURCE_RECEIPT_INVALID");
    }
    for (const [name, value] of [
      ["proposal_digest", row.proposal_digest],
      ["logical_action_digest", row.logical_action_digest],
      ["logical_authority_key_sha256", row.logical_authority_key_sha256],
      ["authorization_binding_sha256", row.authorization_binding_sha256],
      ["evidence_digest", row.evidence_digest]
    ]) {
      requireSha256(value, name);
    }
    return Object.freeze({
      ...row,
      recorded_at: recordedAt.toISOString(),
      database_now: databaseNow.toISOString(),
      admittedCount: 1,
      unresolvedCount: 0
    });
  } finally {
    await client.end().catch(() => {});
  }
}

export async function resolveCommittedRecoveryAuditEvent({
  connectionString,
  tenantId,
  eventId,
  eventDigest,
  clientFactory = null
} = {}) {
  const expectedTenantId = requireUuid(tenantId, "tenantId");
  const expectedEventId = requireUuid(eventId, "eventId");
  const expectedEventDigest = requireSha256(eventDigest, "eventDigest");
  const client = primaryRuntimeClient({
    connectionString,
    clientFactory,
    applicationName: "tideproof-recovery-audit-resolver"
  });
  try {
    await client.connect();
    const result = await client.query(
      `
        SELECT *
        FROM tp_api.g1_resolve_recovery_audit_event_v1(
          $1::UUID, $2::UUID, $3
        )
      `,
      [expectedEventId, expectedTenantId, expectedEventDigest]
    );
    if (result.rowCount !== 1) {
      throw new Error("RECOVERY_AUDIT_EVENT_NOT_COMMITTED");
    }
    const row = result.rows[0];
    if (
      row.event_id !== expectedEventId ||
      row.tenant_id !== expectedTenantId ||
      row.event_digest !== expectedEventDigest
    ) {
      throw new Error("RECOVERY_AUDIT_EVENT_INVALID");
    }
    return Object.freeze({ ...row });
  } finally {
    await client.end().catch(() => {});
  }
}

export async function resolveCommittedRecoveryPublisherTrustRoot({
  connectionString,
  trustRootCommitment,
  publisherKeySetDigest,
  clientFactory = null
} = {}) {
  const expectedCommitment = requireSha256(
    trustRootCommitment,
    "trustRootCommitment"
  );
  const expectedKeySetDigest = requireSha256(
    publisherKeySetDigest,
    "publisherKeySetDigest"
  );
  const client = primaryRuntimeClient({
    connectionString,
    clientFactory,
    applicationName: "tideproof-recovery-publisher-trust-root"
  });
  try {
    await client.connect();
    const result = await client.query(
      `
        SELECT *
        FROM tp_api.g1_resolve_recovery_publisher_trust_root_v1(
          $1, $2, $3
        )
      `,
      [
        RECOVERY_PUBLISHER_TRUST_ROOT_ID,
        expectedCommitment,
        expectedKeySetDigest
      ]
    );
    if (result.rowCount !== 1) {
      throw new Error("RECOVERY_PUBLISHER_TRUST_ROOT_NOT_COMMITTED");
    }
    const row = result.rows[0];
    const committedAt = new Date(row.committed_at);
    const databaseNow = new Date(row.database_now);
    if (
      row.trust_root_id !== RECOVERY_PUBLISHER_TRUST_ROOT_ID ||
      row.trust_root_commitment !== expectedCommitment ||
      row.publisher_key_set_digest !== expectedKeySetDigest ||
      !Number.isFinite(committedAt.getTime()) ||
      !Number.isFinite(databaseNow.getTime()) ||
      committedAt.getTime() > databaseNow.getTime()
    ) {
      throw new Error("RECOVERY_PUBLISHER_TRUST_ROOT_INVALID");
    }
    return Object.freeze({
      trustRootId: row.trust_root_id,
      trustRootCommitment: row.trust_root_commitment,
      publisherKeySetDigest: row.publisher_key_set_digest,
      committedAt: committedAt.toISOString(),
      databaseNow: databaseNow.toISOString()
    });
  } finally {
    await client.end().catch(() => {});
  }
}

function errorCodeFor(error) {
  const value =
    typeof error?.code === "string"
      ? error.code
      : typeof error?.message === "string"
        ? error.message
        : "RECOVERY_UNKNOWN_ERROR";
  return value
    .replace(/[^A-Z0-9_]/giu, "_")
    .toUpperCase()
    .slice(0, 128);
}

function rowsFromMcpResult(result) {
  if (result && Array.isArray(result.rows)) {
    return result.rows;
  }
  const content = result?.content;
  if (!Array.isArray(content) || content.length !== 1) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  const text = content[0]?.text;
  if (typeof text !== "string") {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("RECOVERY_MCP_RESPONSE_JSON_INVALID");
  }
  if (!Array.isArray(parsed?.rows)) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  return parsed.rows;
}

export function principalBindingHash(authenticatedPrincipal) {
  return sha256(
    `tideproof-recovery-principal-v1\n${requireText(
      authenticatedPrincipal,
      "authenticatedPrincipal"
    )}`
  );
}

export function assertSeparatedDatabaseEndpoints({
  primaryConnectionString,
  recoveryConnectionString,
  expectedPrimaryHostname,
  expectedRecoveryHostname,
  primaryClusterId,
  recoveryClusterId
}) {
  const primary = new URL(primaryConnectionString);
  const recovery = new URL(recoveryConnectionString);
  const expectedPrimary = requireText(
    expectedPrimaryHostname,
    "expectedPrimaryHostname"
  ).toLowerCase();
  const expectedRecovery = requireText(
    expectedRecoveryHostname,
    "expectedRecoveryHostname"
  ).toLowerCase();
  const boundPrimaryClusterId = requireUuid(
    primaryClusterId,
    "primaryClusterId"
  );
  const boundRecoveryClusterId = requireUuid(
    recoveryClusterId,
    "recoveryClusterId"
  );
  if (
    primary.hostname.toLowerCase() !== expectedPrimary ||
    recovery.hostname.toLowerCase() !== expectedRecovery
  ) {
    throw new Error("RECOVERY_DATABASE_HOST_MISMATCH");
  }
  if (
    primary.hostname.toLowerCase() === recovery.hostname.toLowerCase() ||
    boundPrimaryClusterId === boundRecoveryClusterId
  ) {
    throw new Error("RECOVERY_CLUSTER_SEPARATION_REQUIRED");
  }
  return {
    primaryHostname: primary.hostname.toLowerCase(),
    recoveryHostname: recovery.hostname.toLowerCase(),
    primaryClusterId: boundPrimaryClusterId,
    recoveryClusterId: boundRecoveryClusterId
  };
}

export function recoveryBrokerConfigDigest({
  recoveryClusterId,
  expectedSourceClusterId,
  buildIdentity,
  trustedPublisherKeys
}) {
  return sha256(
    canonicalJson({
      auditSchema: "g1_recovery_audit_events_v3",
      buildIdentity: requireText(buildIdentity, "buildIdentity"),
      client: "tideproof-managed-mcp-client-v1",
      database: FIXED_DATABASE,
      expectedSourceClusterId: requireUuid(
        expectedSourceClusterId,
        "expectedSourceClusterId"
      ),
      mcpProtocolVersion: "2025-03-26",
      queryTemplateDigest: recoveryQueryTemplateDigest(),
      recoveryClusterId: requireUuid(recoveryClusterId, "recoveryClusterId"),
      tool: FIXED_TOOL,
      trustedPublisherKeysDigest:
        trustedPublisherKeysDigest(trustedPublisherKeys),
      validator: "tideproof-recovery-row-v2-p256-source-bound",
      version: "tideproof-deterministic-recovery-broker-v3"
    })
  );
}

export function trustedPublisherKeysDigest(trustedPublisherKeys) {
  if (
    !trustedPublisherKeys ||
    typeof trustedPublisherKeys !== "object" ||
    Array.isArray(trustedPublisherKeys)
  ) {
    throw new TypeError("trustedPublisherKeys must be an object");
  }
  const normalized = Object.entries(trustedPublisherKeys)
    .map(([keyId, publicKeySpkiBase64]) => {
      const encoded = requireText(
        publicKeySpkiBase64,
        `trustedPublisherKeys.${keyId}`
      );
      const bytes = Buffer.from(encoded, "base64");
      if (
        bytes.length === 0 ||
        bytes.toString("base64").replace(/=+$/u, "") !==
          encoded.replace(/=+$/u, "")
      ) {
        throw new TypeError(
          `trustedPublisherKeys.${keyId} must be canonical base64`
        );
      }
      return {
        keyId: requireText(keyId, "trustedPublisherKeys keyId"),
        publicKeyDigest: sha256(bytes)
      };
    })
    .sort(({ keyId: left }, { keyId: right }) => left.localeCompare(right));
  if (normalized.length === 0) {
    throw new TypeError("trustedPublisherKeys must not be empty");
  }
  return sha256(canonicalJson(normalized));
}

export function recoveryAuditEventDigest(event) {
  return sha256(
    canonicalJson({
      eventId: requireUuid(event.eventId, "event.eventId"),
      interactionId: requireUuid(event.interactionId, "event.interactionId"),
      tenantId: requireUuid(event.tenantId, "event.tenantId"),
      recoverySessionId: requireUuid(
        event.recoverySessionId,
        "event.recoverySessionId"
      ),
      callerSubjectHash: requireSha256(
        event.callerSubjectHash,
        "event.callerSubjectHash"
      ),
      phase: requireText(event.phase, "event.phase"),
      toolName: FIXED_TOOL,
      recoveryClusterId: requireUuid(
        event.recoveryClusterId,
        "event.recoveryClusterId"
      ),
      brokerConfigDigest: requireSha256(
        event.brokerConfigDigest,
        "event.brokerConfigDigest"
      ),
      queryTemplateDigest: requireSha256(
        event.queryTemplateDigest,
        "event.queryTemplateDigest"
      ),
      boundInputDigest: requireSha256(
        event.boundInputDigest,
        "event.boundInputDigest"
      ),
      resultDigest:
        event.resultDigest === null
          ? null
          : requireSha256(event.resultDigest, "event.resultDigest"),
      sourceWatermark:
        event.sourceWatermark === null
          ? null
          : new Date(event.sourceWatermark).toISOString(),
      outcome: requireText(event.outcome, "event.outcome"),
      errorCode:
        event.errorCode === null
          ? null
          : requireText(event.errorCode, "event.errorCode"),
      startedAt: new Date(event.startedAt).toISOString(),
      completedAt: new Date(event.completedAt).toISOString()
    })
  );
}

export class RecoveryAuditSink {
  #clientFactory;
  #connectionString;

  constructor({ connectionString, clientFactory = null } = {}) {
    if (typeof clientFactory === "function") {
      this.#clientFactory = clientFactory;
      return;
    }
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#connectionString = connectionStringForDatabase(
      connectionString,
      "tideproof"
    );
  }

  #client(applicationName) {
    if (this.#clientFactory) {
      return this.#clientFactory(applicationName);
    }
    return new Client(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: 1,
      applicationName
    }));
  }

  async #resolve(event, eventDigest) {
    const client = this.#client("tideproof-recovery-audit-reconcile");
    try {
      await client.connect();
      return await client.query(
        `
          SELECT *
          FROM tp_api.g1_resolve_recovery_audit_event_v1(
            $1::UUID, $2::UUID, $3
          )
        `,
        [event.eventId, event.tenantId, eventDigest]
      );
    } finally {
      await client.end().catch(() => {});
    }
  }

  async append(event) {
    const eventDigest = recoveryAuditEventDigest(event);
    const client = this.#client("tideproof-recovery-audit");
    let transactionStarted = false;
    let commitDispatched = false;
    let committed = false;
    let clientClosed = false;
    try {
      await client.connect();
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      const result = await client.query(
        `
          SELECT tp_api.g1_append_recovery_audit_event_v3(
            $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5, $6, $7, $8::UUID,
            $9, $10, $11, $12, $13::TIMESTAMPTZ, $14, $15, $16,
            $17::TIMESTAMPTZ, $18::TIMESTAMPTZ
          ) AS event_id
        `,
        [
          event.eventId,
          event.tenantId,
          event.interactionId,
          event.recoverySessionId,
          event.callerSubjectHash,
          event.phase,
          FIXED_TOOL,
          event.recoveryClusterId,
          event.brokerConfigDigest,
          event.queryTemplateDigest,
          event.boundInputDigest,
          event.resultDigest,
          event.sourceWatermark,
          event.outcome,
          event.errorCode,
          eventDigest,
          event.startedAt,
          event.completedAt
        ]
      );
      if (
        result.rowCount !== 1 ||
        result.rows[0].event_id !== event.eventId
      ) {
        throw new Error("RECOVERY_AUDIT_RECEIPT_MISMATCH");
      }
      const clock = await client.query(
        "SELECT transaction_timestamp() AS database_now"
      );
      commitDispatched = true;
      await client.query("COMMIT");
      committed = true;
      return {
        eventId: event.eventId,
        eventDigest,
        commit: committedDatabaseResult({
          operation: "recovery_audit",
          operationDigest: eventDigest,
          observation: "direct_ack",
          databaseNow: databaseTimestampFromDriver(
            clock.rows[0].database_now
          ),
          outcome: event.outcome
        })
      };
    } catch (error) {
      const commitDefinitivelyAborted =
        commitDispatched && error?.code === "40001";
      const discardClient =
        databaseClientMustBeDiscarded(error) ||
        (commitDispatched && !commitDefinitivelyAborted);
      if (commitDispatched && !commitDefinitivelyAborted) {
        await client.end().catch(() => {});
        clientClosed = true;
        const resolved = await this.#resolve(event, eventDigest);
        const row = resolved?.rows?.[0];
        if (
          resolved?.rowCount === 1 &&
          row.event_id === event.eventId &&
          row.event_digest === eventDigest &&
          row.outcome === event.outcome
        ) {
          return {
            eventId: event.eventId,
            eventDigest,
            commit: committedDatabaseResult({
              operation: "recovery_audit",
              operationDigest: eventDigest,
              observation: "read_reconciled",
              databaseNow: databaseTimestampFromDriver(row.database_now),
              outcome: row.outcome
            })
          };
        }
      }
      if (transactionStarted && !committed && !discardClient) {
        await client.query("ROLLBACK").catch(() => {});
      }
      throw error;
    } finally {
      if (!clientClosed) {
        await client.end().catch(() => {});
      }
    }
  }
}

export class DeterministicRecoveryBroker {
  #auditSink;
  #buildIdentity;
  #expectedSourceClusterId;
  #mcpClient;
  #recoveryClusterId;
  #sessionResolver;
  #trustedPublisherKeys;

  constructor({
    mcpClient,
    sessionResolver,
    auditSink,
    buildIdentity,
    recoveryClusterId,
    expectedSourceClusterId,
    trustedPublisherKeys
  } = {}) {
    if (typeof mcpClient?.selectQuery !== "function") {
      throw new TypeError("mcpClient.selectQuery is required");
    }
    if (typeof sessionResolver?.resolve !== "function") {
      throw new TypeError("sessionResolver.resolve is required");
    }
    if (typeof auditSink?.append !== "function") {
      throw new TypeError("auditSink.append is required");
    }
    this.#mcpClient = mcpClient;
    this.#sessionResolver = sessionResolver;
    this.#auditSink = auditSink;
    this.#buildIdentity = requireText(buildIdentity, "buildIdentity");
    this.#recoveryClusterId = requireUuid(
      recoveryClusterId,
      "recoveryClusterId"
    );
    this.#expectedSourceClusterId = requireUuid(
      expectedSourceClusterId,
      "expectedSourceClusterId"
    );
    this.#trustedPublisherKeys = trustedPublisherKeys;
  }

  async recover(input = {}) {
    const { authenticatedPrincipal } = input ?? {};
    const startedAt = new Date();
    let callerSubjectHash;
    try {
      callerSubjectHash = principalBindingHash(authenticatedPrincipal);
    } catch (error) {
      return {
        status: "UNKNOWN_DO_NOT_ACT",
        reason: errorCodeFor(error),
        authorityTransferred: false,
        requiresFreshAuthorization: true
      };
    }
    let auditContext = null;
    let observedResultDigest = null;
    let observedSourceWatermark = null;
    let preReadCommitted = false;
    try {
      const binding = await this.#sessionResolver.resolve({
        authenticatedPrincipal
      });
      const tenantId = requireUuid(binding.tenantId, "binding.tenantId");
      const recoverySessionId = requireUuid(
        binding.recoverySessionId,
        "binding.recoverySessionId"
      );
      const sourceDigest = requireSha256(
        binding.sourceDigest,
        "binding.sourceDigest"
      );
      if (
        requireSha256(
          binding.subjectBindingHash,
          "binding.subjectBindingHash"
        ) !== callerSubjectHash
      ) {
        throw new Error("RECOVERY_PRINCIPAL_BINDING_MISMATCH");
      }
      const boundInputDigest = sha256(
        canonicalJson({
          tenantId,
          recoverySessionId,
          subjectBindingHash: callerSubjectHash,
          sourceDigest
        })
      );
      const brokerConfigDigest = recoveryBrokerConfigDigest({
        recoveryClusterId: this.#recoveryClusterId,
        expectedSourceClusterId: this.#expectedSourceClusterId,
        buildIdentity: this.#buildIdentity,
        trustedPublisherKeys: this.#trustedPublisherKeys
      });
      const query = renderRecoveryQuery({
        tenantId,
        recoverySessionId,
        subjectBindingHash: callerSubjectHash,
        sourceDigest
      });
      const interactionId = randomUUID();
      const preReadEventId = randomUUID();
      auditContext = {
        tenantId,
        recoverySessionId,
        callerSubjectHash,
        recoveryClusterId: this.#recoveryClusterId,
        brokerConfigDigest,
        queryTemplateDigest: recoveryQueryTemplateDigest(),
        boundInputDigest,
        interactionId,
        preReadEventId
      };
      try {
        const preReadAudit = await this.#auditSink.append({
          ...auditContext,
          eventId: preReadEventId,
          phase: "pre_read",
          resultDigest: null,
          sourceWatermark: null,
          startedAt,
          completedAt: new Date(),
          outcome: "read_authorized",
          errorCode: null
        });
        auditContext.preReadEventDigest = preReadAudit.eventDigest;
      } catch {
        return {
          status: "UNKNOWN_DO_NOT_ACT",
          reason: "recovery_audit_unavailable",
          authorityTransferred: false,
          requiresFreshAuthorization: true
        };
      }
      preReadCommitted = true;
      const rawResult = await this.#mcpClient.selectQuery({
        clusterId: this.#recoveryClusterId,
        database: FIXED_DATABASE,
        query
      });
      observedResultDigest = sha256(canonicalJson(rawResult));
      const rows = rowsFromMcpResult(rawResult);
      if (rows.length === 1) {
        observedResultDigest = sha256(canonicalJson(rows[0]));
        const sourceCommitMs = new Date(
          rows[0]?.source_commit_ts
        ).getTime();
        if (Number.isFinite(sourceCommitMs)) {
          observedSourceWatermark = new Date(sourceCommitMs).toISOString();
        }
      }
      if (rows.length !== 1) {
        throw new Error("RECOVERY_MCP_RESULT_CARDINALITY_INVALID");
      }
      const validated = validateRecoveryRow(
        rows[0],
        {
          tenantId,
          recoverySessionId,
          subjectBindingHash: callerSubjectHash,
          sourceDigest,
          expectedSourceClusterId: this.#expectedSourceClusterId,
          trustedPublisherKeys: this.#trustedPublisherKeys
        },
        new Date()
      );
      const resultDigest = observedResultDigest;
      const completedAt = new Date();
      const terminalEventId = randomUUID();
      const terminalAudit = await this.#auditSink.append({
        ...auditContext,
        eventId: terminalEventId,
        phase: "terminal",
        resultDigest,
        sourceWatermark: validated.row.source_commit_ts,
        startedAt,
        completedAt,
        outcome: "recovered_context_only",
        errorCode: null
      });
      return {
        status: "RECOVERED_CONTEXT_ONLY",
        auditId: terminalEventId,
        auditDigest: terminalAudit.eventDigest,
        auditInteractionId: interactionId,
        preReadAuditId: preReadEventId,
        preReadAuditDigest: auditContext.preReadEventDigest,
        recoverySessionId,
        tenantId,
        sourceDigest: validated.sourceDigest,
        bundleDigest: validated.bundleDigest,
        context: {
          checkpoint: validated.row.checkpoint_summary,
          evidence: validated.row.evidence_summary,
          conflicts: validated.row.conflict_summary,
          receipt: validated.row.receipt_summary
        },
        authorityTransferred: false,
        requiresFreshAuthorization: true
      };
    } catch (error) {
      const completedAt = new Date();
      const errorCode = errorCodeFor(error);
      if (preReadCommitted && auditContext) {
        try {
          await this.#auditSink.append({
            ...auditContext,
            eventId: randomUUID(),
            phase: "terminal",
            resultDigest:
              observedResultDigest ?? sha256(canonicalJson({ errorCode })),
            sourceWatermark: observedSourceWatermark ?? completedAt,
            startedAt,
            completedAt,
            outcome: "unknown_do_not_act",
            errorCode
          });
        } catch {
          return {
            status: "UNKNOWN_DO_NOT_ACT",
            reason: "recovery_audit_unavailable",
            authorityTransferred: false,
            requiresFreshAuthorization: true
          };
        }
      }
      return {
        status: "UNKNOWN_DO_NOT_ACT",
        reason: errorCode,
        authorityTransferred: false,
        requiresFreshAuthorization: true
      };
    }
  }
}
