import { createHash, randomUUID } from "node:crypto";
import { Client } from "pg";
import { parseStrictJson } from "./strict-json.js";
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
  canonicalRecoveryAttempt,
  recoveryBrokerConfigDigest
} from "./recovery-continuity-identity.js";
import {
  recoveryQueryTemplateDigest,
  renderRecoveryQuery,
  validateRecoveryRow
} from "./recovery-store.js";
export { trustedPublisherKeysDigest } from
  "./recovery-publisher-trust.js";
import {
  PRIMARY_MANAGED_BASE_TABLES,
  RECOVERY_TRUST_ROOT_WRITE_PROBES
} from "./recovery-security-contract.js";

const FIXED_DATABASE = "tideproof_recovery";
const FIXED_TOOL = "select_query";
const RECOVERY_PUBLISHER_TRUST_ROOT_ID =
  "gate1-recovery-publisher-v1";
export {
  canonicalRecoveryAttempt,
  recoveryBrokerConfigDigest
} from "./recovery-continuity-identity.js";

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

export async function assertRecoveryPublisherTrustRootWriteDeniedWithClient(
  client
) {
  if (!client || typeof client.query !== "function") {
    throw new TypeError("client.query is required");
  }
  for (const writeProbe of RECOVERY_TRUST_ROOT_WRITE_PROBES) {
    await client.query("BEGIN");
    let probeReturned = false;
    let probeError;
    try {
      await client.query(writeProbe);
      probeReturned = true;
    } catch (error) {
      probeError = error;
    }
    try {
      await client.query("ROLLBACK");
    } catch (cause) {
      throw new Error(
        "RECOVERY_TRUST_ROOT_WRITE_PROBE_ROLLBACK_FAILED",
        { cause }
      );
    }
    if (probeReturned) {
      throw new Error("RECOVERY_RUNNER_CAN_REWRITE_PUBLISHER_TRUST_ROOT");
    }
    if (probeError?.code !== "42501") {
      throw probeError;
    }
  }
  return Object.freeze({
    denied: true,
    sqlstate: "42501",
    probeCount: RECOVERY_TRUST_ROOT_WRITE_PROBES.length
  });
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
  try {
    await client.connect();
    const result =
      await assertRecoveryPublisherTrustRootWriteDeniedWithClient(client);
    return Object.freeze({
      denied: result.denied,
      sqlstate: result.sqlstate
    });
  } finally {
    await client.end().catch(() => {});
  }
}

export async function assertRecoveryRunnerBaseTableReadsDenied({
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
    )}-base-table-denial`
  });
  try {
    await client.connect();
    for (const tableName of PRIMARY_MANAGED_BASE_TABLES) {
      try {
        await client.query(`SELECT 1 FROM ${tableName} LIMIT 1`);
      } catch (error) {
        if (error?.code === "42501") {
          continue;
        }
        throw error;
      }
      throw new Error("RECOVERY_RUNNER_CAN_READ_PROTECTED_BASE_TABLE");
    }
    return Object.freeze({
      denied: true,
      sqlstate: "42501",
      tableCount: PRIMARY_MANAGED_BASE_TABLES.length
    });
  } finally {
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
    ),
    authorityEvidenceBindingSha256: requireSha256(
      binding?.authorityEvidenceBindingSha256,
      "binding.authorityEvidenceBindingSha256"
    ),
    selectedEvidenceBindingSha256: requireSha256(
      binding?.selectedEvidenceBindingSha256,
      "binding.selectedEvidenceBindingSha256"
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
        FROM tp_api.g1_resolve_recovery_source_receipt_v2(
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
      ["evidence_digest", row.evidence_digest],
      [
        "authority_evidence_binding_sha256",
        row.authority_evidence_binding_sha256
      ]
    ]) {
      requireSha256(value, name);
    }
    const selectedEvidenceBindingSha256 = sha256(
      canonicalJson({
        evidenceId: row.evidence_id,
        evidenceDigest: row.evidence_digest
      })
    );
    if (
      row.authority_evidence_binding_sha256 !==
        expected.authorityEvidenceBindingSha256 ||
      selectedEvidenceBindingSha256 !==
        expected.selectedEvidenceBindingSha256
    ) {
      throw new Error("RECOVERY_SOURCE_DVI_BINDING_INVALID");
    }
    return Object.freeze({
      ...row,
      selected_evidence_binding_sha256: selectedEvidenceBindingSha256,
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
  clientFactory = null,
  beforeExternalAction = null
} = {}) {
  if (
    beforeExternalAction !== null &&
    typeof beforeExternalAction !== "function"
  ) {
    throw new TypeError("beforeExternalAction must be a function");
  }
  const expectedTenantId = requireUuid(tenantId, "tenantId");
  const expectedEventId = requireUuid(eventId, "eventId");
  const expectedEventDigest = requireSha256(eventDigest, "eventDigest");
  const client = primaryRuntimeClient({
    connectionString,
    clientFactory,
    applicationName: "tideproof-recovery-audit-resolver"
  });
  try {
    if (beforeExternalAction !== null) {
      beforeExternalAction("AUDIT_RESOLVE_CONNECT");
    }
    await client.connect();
    if (beforeExternalAction !== null) {
      beforeExternalAction("AUDIT_RESOLVE_QUERY");
    }
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

function hasExactKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key));
}

function rowsFromMcpResult(result) {
  const hasRows = result !== null &&
    typeof result === "object" &&
    Object.hasOwn(result, "rows");
  const hasContent = result !== null &&
    typeof result === "object" &&
    Object.hasOwn(result, "content");
  if (hasRows && hasContent) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_AMBIGUOUS");
  }
  if (hasRows) {
    if (!hasExactKeys(result, ["rows"]) || !Array.isArray(result.rows)) {
      throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
    }
    return result.rows;
  }
  if (!hasExactKeys(result, ["content"])) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  const content = result?.content;
  if (!Array.isArray(content) || content.length !== 1) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  if (
    !hasExactKeys(content[0], ["type", "text"]) ||
    content[0].type !== "text" ||
    typeof content[0].text !== "string"
  ) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  const text = content[0].text;
  let parsed;
  try {
    parsed = parseStrictJson(text, {
      duplicateCode: "RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER",
      invalidCode: "RECOVERY_MCP_RESPONSE_JSON_INVALID"
    });
  } catch (cause) {
    throw new Error(
      cause?.message === "RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER"
        ? "RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER"
        : "RECOVERY_MCP_RESPONSE_JSON_INVALID"
    );
  }
  const parsedHasRows = parsed !== null &&
    typeof parsed === "object" &&
    Object.hasOwn(parsed, "rows");
  const parsedHasContent = parsed !== null &&
    typeof parsed === "object" &&
    Object.hasOwn(parsed, "content");
  if (parsedHasRows && parsedHasContent) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_AMBIGUOUS");
  }
  if (!hasExactKeys(parsed, ["rows"]) || !Array.isArray(parsed.rows)) {
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
  primaryAuditConnectionString,
  recoveryConnectionString,
  expectedPrimaryHostname,
  expectedRecoveryHostname,
  primaryClusterId,
  recoveryClusterId
}) {
  const primary = new URL(primaryConnectionString);
  const primaryAudit = new URL(primaryAuditConnectionString);
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
    primaryAudit.hostname.toLowerCase() !== expectedPrimary ||
    recovery.hostname.toLowerCase() !== expectedRecovery
  ) {
    throw new Error("RECOVERY_DATABASE_HOST_MISMATCH");
  }
  if (
    primaryAudit.protocol !== primary.protocol ||
    primaryAudit.hostname.toLowerCase() !== primary.hostname.toLowerCase() ||
    primaryAudit.port !== primary.port ||
    primaryAudit.pathname !== primary.pathname
  ) {
    throw new Error("RECOVERY_PRIMARY_CREDENTIAL_ENDPOINT_MISMATCH");
  }
  if (
    primary.hostname.toLowerCase() === recovery.hostname.toLowerCase() ||
    boundPrimaryClusterId === boundRecoveryClusterId
  ) {
    throw new Error("RECOVERY_CLUSTER_SEPARATION_REQUIRED");
  }
  return {
    primaryHostname: primary.hostname.toLowerCase(),
    primaryAuditHostname: primaryAudit.hostname.toLowerCase(),
    recoveryHostname: recovery.hostname.toLowerCase(),
    primaryClusterId: boundPrimaryClusterId,
    recoveryClusterId: boundRecoveryClusterId
  };
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

  async #resolve(event, eventDigest, beforeExternalAction) {
    const client = this.#client("tideproof-recovery-audit-reconcile");
    try {
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_RESOLVE_CONNECT");
      }
      await client.connect();
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_RESOLVE_QUERY");
      }
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

  async resolve(event, { beforeExternalAction = null } = {}) {
    if (
      beforeExternalAction !== null &&
      typeof beforeExternalAction !== "function"
    ) {
      throw new TypeError("beforeExternalAction must be a function");
    }
    const normalized = Object.freeze({
      ...event,
      startedAt: new Date(event?.startedAt).toISOString(),
      completedAt: new Date(event?.completedAt).toISOString(),
      sourceWatermark:
        event?.sourceWatermark === null
          ? null
          : new Date(event?.sourceWatermark).toISOString()
    });
    const eventDigest = recoveryAuditEventDigest(normalized);
    const result = await this.#resolve(
      normalized,
      eventDigest,
      beforeExternalAction
    );
    const row = result?.rows?.[0];
    if (
      result?.rowCount !== 1 ||
      row?.event_id !== normalized.eventId ||
      row?.tenant_id !== normalized.tenantId ||
      row?.event_digest !== eventDigest
    ) {
      throw new Error("RECOVERY_AUDIT_EVENT_INVALID");
    }
    return Object.freeze({ ...row });
  }

  async append(event, { beforeExternalAction = null } = {}) {
    if (
      beforeExternalAction !== null &&
      typeof beforeExternalAction !== "function"
    ) {
      throw new TypeError("beforeExternalAction must be a function");
    }
    const eventDigest = recoveryAuditEventDigest(event);
    const client = this.#client("tideproof-recovery-audit");
    let transactionStarted = false;
    let commitDispatched = false;
    let committed = false;
    let clientClosed = false;
    try {
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_APPEND_CONNECT");
      }
      await client.connect();
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_APPEND_BEGIN");
      }
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      transactionStarted = true;
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_APPEND");
      }
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
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_APPEND_DATABASE_CLOCK");
      }
      const clock = await client.query(
        "SELECT transaction_timestamp() AS database_now"
      );
      if (beforeExternalAction !== null) {
        beforeExternalAction("AUDIT_APPEND_COMMIT");
      }
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
        const resolved = await this.#resolve(
          event,
          eventDigest,
          beforeExternalAction
        );
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

  #unknown(reason) {
    return Object.freeze({
      status: "UNKNOWN_DO_NOT_ACT",
      reason,
      authorityTransferred: false,
      requiresFreshAuthorization: true
    });
  }

  #validatePreparedRecovery(prepared) {
    const value = prepared ?? {};
    const startedAt = new Date(value.startedAt);
    const completedAt = new Date(value.preReadAuditEvent?.completedAt);
    const preparedKeys = [
      "boundInputDigest",
      "brokerConfigDigest",
      "callerSubjectHash",
      "interactionId",
      "preReadAuditDigest",
      "preReadAuditEvent",
      "preReadEventId",
      "query",
      "queryTemplateDigest",
      "recoverySessionId",
      "schemaVersion",
      "sourceDigest",
      "startedAt",
      "tenantId",
      "terminalEventId"
    ];
    const auditEventKeys = [
      "boundInputDigest",
      "brokerConfigDigest",
      "callerSubjectHash",
      "completedAt",
      "errorCode",
      "eventId",
      "interactionId",
      "outcome",
      "phase",
      "recoveryClusterId",
      "recoverySessionId",
      "resultDigest",
      "sourceWatermark",
      "startedAt",
      "tenantId",
      "queryTemplateDigest"
    ];
    const expectedBoundInputDigest = sha256(canonicalJson({
      tenantId: value.tenantId,
      recoverySessionId: value.recoverySessionId,
      subjectBindingHash: value.callerSubjectHash,
      sourceDigest: value.sourceDigest
    }));
    const expectedBrokerConfigDigest = recoveryBrokerConfigDigest({
      recoveryClusterId: this.#recoveryClusterId,
      expectedSourceClusterId: this.#expectedSourceClusterId,
      buildIdentity: this.#buildIdentity,
      trustedPublisherKeys: this.#trustedPublisherKeys
    });
    const expectedQuery = renderRecoveryQuery({
      tenantId: value.tenantId,
      recoverySessionId: value.recoverySessionId,
      subjectBindingHash: value.callerSubjectHash,
      sourceDigest: value.sourceDigest
    });
    if (
      !hasExactKeys(value, preparedKeys) ||
      !hasExactKeys(value.preReadAuditEvent, auditEventKeys) ||
      value.schemaVersion !== "tideproof.prepared-recovery.v1" ||
      requireUuid(value.tenantId, "prepared.tenantId") !== value.tenantId ||
      requireUuid(value.recoverySessionId, "prepared.recoverySessionId") !==
        value.recoverySessionId ||
      requireSha256(value.callerSubjectHash, "prepared.callerSubjectHash") !==
        value.callerSubjectHash ||
      requireSha256(value.sourceDigest, "prepared.sourceDigest") !==
        value.sourceDigest ||
      requireSha256(value.boundInputDigest, "prepared.boundInputDigest") !==
        expectedBoundInputDigest ||
      requireSha256(value.brokerConfigDigest, "prepared.brokerConfigDigest") !==
        expectedBrokerConfigDigest ||
      requireSha256(
        value.queryTemplateDigest,
        "prepared.queryTemplateDigest"
      ) !== recoveryQueryTemplateDigest() ||
      value.query !== expectedQuery ||
      requireUuid(value.interactionId, "prepared.interactionId") !==
        value.interactionId ||
      requireUuid(value.preReadEventId, "prepared.preReadEventId") !==
        value.preReadEventId ||
      requireUuid(value.terminalEventId, "prepared.terminalEventId") !==
        value.terminalEventId ||
      !Number.isFinite(startedAt.getTime()) ||
      startedAt.toISOString() !== value.startedAt ||
      !Number.isFinite(completedAt.getTime()) ||
      completedAt.toISOString() !== value.preReadAuditEvent?.completedAt ||
      completedAt.getTime() < startedAt.getTime() ||
      value.preReadAuditEvent?.eventId !== value.preReadEventId ||
      value.preReadAuditEvent?.interactionId !== value.interactionId ||
      value.preReadAuditEvent?.tenantId !== value.tenantId ||
      value.preReadAuditEvent?.recoverySessionId !== value.recoverySessionId ||
      value.preReadAuditEvent?.callerSubjectHash !== value.callerSubjectHash ||
      value.preReadAuditEvent?.recoveryClusterId !== this.#recoveryClusterId ||
      value.preReadAuditEvent?.brokerConfigDigest !== value.brokerConfigDigest ||
      value.preReadAuditEvent?.queryTemplateDigest !==
        value.queryTemplateDigest ||
      value.preReadAuditEvent?.boundInputDigest !== value.boundInputDigest ||
      value.preReadAuditEvent?.startedAt !== value.startedAt ||
      value.preReadAuditEvent?.phase !== "pre_read" ||
      value.preReadAuditEvent?.outcome !== "read_authorized" ||
      value.preReadAuditEvent?.resultDigest !== null ||
      value.preReadAuditEvent?.sourceWatermark !== null ||
      value.preReadAuditEvent?.errorCode !== null ||
      recoveryAuditEventDigest(value.preReadAuditEvent) !==
        value.preReadAuditDigest
    ) {
      throw new Error("RECOVERY_PREPARED_STATE_INVALID");
    }
    const preReadAuditEvent = Object.freeze({
      boundInputDigest: value.preReadAuditEvent.boundInputDigest,
      brokerConfigDigest: value.preReadAuditEvent.brokerConfigDigest,
      callerSubjectHash: value.preReadAuditEvent.callerSubjectHash,
      completedAt: value.preReadAuditEvent.completedAt,
      errorCode: value.preReadAuditEvent.errorCode,
      eventId: value.preReadAuditEvent.eventId,
      interactionId: value.preReadAuditEvent.interactionId,
      outcome: value.preReadAuditEvent.outcome,
      phase: value.preReadAuditEvent.phase,
      recoveryClusterId: value.preReadAuditEvent.recoveryClusterId,
      recoverySessionId: value.preReadAuditEvent.recoverySessionId,
      resultDigest: value.preReadAuditEvent.resultDigest,
      sourceWatermark: value.preReadAuditEvent.sourceWatermark,
      startedAt: value.preReadAuditEvent.startedAt,
      tenantId: value.preReadAuditEvent.tenantId,
      queryTemplateDigest: value.preReadAuditEvent.queryTemplateDigest
    });
    return Object.freeze({
      boundInputDigest: value.boundInputDigest,
      brokerConfigDigest: value.brokerConfigDigest,
      callerSubjectHash: value.callerSubjectHash,
      interactionId: value.interactionId,
      preReadAuditDigest: value.preReadAuditDigest,
      preReadAuditEvent,
      preReadEventId: value.preReadEventId,
      query: value.query,
      queryTemplateDigest: value.queryTemplateDigest,
      recoverySessionId: value.recoverySessionId,
      schemaVersion: value.schemaVersion,
      sourceDigest: value.sourceDigest,
      startedAt: value.startedAt,
      tenantId: value.tenantId,
      terminalEventId: value.terminalEventId
    });
  }

  async planRecovery(input = {}, { auditIdentity = null } = {}) {
    const { authenticatedPrincipal } = input ?? {};
    const callerSubjectHash = principalBindingHash(authenticatedPrincipal);
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
    const startedAt = auditIdentity?.startedAt === undefined
      ? new Date()
      : new Date(auditIdentity.startedAt);
    if (
      !Number.isFinite(startedAt.getTime()) ||
      startedAt.toISOString() !==
        (auditIdentity?.startedAt ?? startedAt.toISOString())
    ) {
      throw new Error("RECOVERY_AUDIT_IDENTITY_INVALID");
    }
    const interactionId = auditIdentity?.interactionId ?? randomUUID();
    const preReadEventId = auditIdentity?.preReadEventId ?? randomUUID();
    const terminalEventId = auditIdentity?.terminalEventId ?? randomUUID();
    requireUuid(interactionId, "auditIdentity.interactionId");
    requireUuid(preReadEventId, "auditIdentity.preReadEventId");
    requireUuid(terminalEventId, "auditIdentity.terminalEventId");
    if (new Set([interactionId, preReadEventId, terminalEventId]).size !== 3) {
      throw new Error("RECOVERY_AUDIT_IDENTITY_INVALID");
    }
    const boundInputDigest = sha256(canonicalJson({
      tenantId,
      recoverySessionId,
      subjectBindingHash: callerSubjectHash,
      sourceDigest
    }));
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
    const auditContext = Object.freeze({
      tenantId,
      recoverySessionId,
      callerSubjectHash,
      recoveryClusterId: this.#recoveryClusterId,
      brokerConfigDigest,
      queryTemplateDigest: recoveryQueryTemplateDigest(),
      boundInputDigest,
      interactionId
    });
    const preReadAuditEvent = Object.freeze({
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
    const preReadAuditDigest = recoveryAuditEventDigest(preReadAuditEvent);
    const prepared = Object.freeze({
      schemaVersion: "tideproof.prepared-recovery.v1",
      tenantId,
      recoverySessionId,
      callerSubjectHash,
      sourceDigest,
      boundInputDigest,
      brokerConfigDigest,
      queryTemplateDigest: recoveryQueryTemplateDigest(),
      query,
      interactionId,
      preReadEventId,
      terminalEventId,
      startedAt: startedAt.toISOString(),
      preReadAuditEvent: Object.freeze({
        ...preReadAuditEvent,
        startedAt: startedAt.toISOString(),
        completedAt: new Date(preReadAuditEvent.completedAt).toISOString()
      }),
      preReadAuditDigest
    });
    return this.#validatePreparedRecovery(prepared);
  }

  async commitPreparedRecoveryPreRead(
    prepared,
    { beforeAuditAppend = null } = {}
  ) {
    const value = this.#validatePreparedRecovery(prepared);
    if (
      beforeAuditAppend !== null &&
      typeof beforeAuditAppend !== "function"
    ) {
      throw new Error("RECOVERY_AUDIT_ACTION_GUARD_INVALID");
    }
    let preReadAudit;
    try {
      if (beforeAuditAppend !== null) {
        beforeAuditAppend("PRE_READ_AUDIT_APPEND");
      }
      preReadAudit = await this.#auditSink.append(
        value.preReadAuditEvent,
        { beforeExternalAction: beforeAuditAppend }
      );
    } catch (cause) {
      if (
        cause?.message ===
          "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
      ) {
        throw cause;
      }
      throw new Error("RECOVERY_AUDIT_UNAVAILABLE", { cause });
    }
    if (
      preReadAudit?.eventDigest !== undefined &&
      preReadAudit.eventDigest !== value.preReadAuditDigest
    ) {
      throw new Error("RECOVERY_AUDIT_RECEIPT_MISMATCH");
    }
    return Object.freeze({
      prepared: value,
      preReadAudit: Object.freeze({ ...preReadAudit })
    });
  }

  async resolvePreparedRecoveryAuditEvent(
    event,
    { beforeExternalAction = null } = {}
  ) {
    if (typeof this.#auditSink?.resolve !== "function") {
      throw new Error("RECOVERY_AUDIT_RESOLVER_REQUIRED");
    }
    if (
      beforeExternalAction !== null &&
      typeof beforeExternalAction !== "function"
    ) {
      throw new Error("RECOVERY_AUDIT_ACTION_GUARD_INVALID");
    }
    return this.#auditSink.resolve(event, {
      beforeExternalAction
    });
  }

  async prepareRecovery(input = {}, options = {}) {
    return this.commitPreparedRecoveryPreRead(
      await this.planRecovery(input, options)
    );
  }

  restorePreparedRecovery(prepared) {
    return this.#validatePreparedRecovery(prepared);
  }

  async validatePreparedRecoveryResume(
    prepared,
    { authenticatedPrincipal } = {}
  ) {
    const value = this.#validatePreparedRecovery(prepared);
    const callerSubjectHash = principalBindingHash(authenticatedPrincipal);
    const binding = await this.#sessionResolver.resolve({
      authenticatedPrincipal
    });
    if (
      callerSubjectHash !== value.callerSubjectHash ||
      requireUuid(binding.tenantId, "binding.tenantId") !== value.tenantId ||
      requireUuid(binding.recoverySessionId, "binding.recoverySessionId") !==
        value.recoverySessionId ||
      requireSha256(binding.subjectBindingHash, "binding.subjectBindingHash") !==
        value.callerSubjectHash ||
      requireSha256(binding.sourceDigest, "binding.sourceDigest") !==
        value.sourceDigest
    ) {
      throw new Error("RECOVERY_PREPARED_RESUME_BINDING_MISMATCH");
    }
    return value;
  }

  async executePreparedRecovery(
    prepared,
    { beforeProviderDispatch = null } = {}
  ) {
    const value = this.#validatePreparedRecovery(prepared);
    if (
      beforeProviderDispatch !== null &&
      typeof beforeProviderDispatch !== "function"
    ) {
      throw new Error("RECOVERY_PROVIDER_DISPATCH_GUARD_INVALID");
    }
    return this.#mcpClient.selectQuery({
      clusterId: this.#recoveryClusterId,
      database: FIXED_DATABASE,
      query: value.query,
      beforeExternalAction: beforeProviderDispatch
    });
  }

  async closePreparedRecoveryProviderSessionAndReadEvidence() {
    if (
      typeof this.#mcpClient.close !== "function" ||
      typeof this.#mcpClient.transportEvidence !== "function" ||
      typeof this.#mcpClient.semanticRequestEvidence !== "function"
    ) {
      throw new Error("RECOVERY_MCP_CLIENT_EVIDENCE_UNAVAILABLE");
    }
    await this.#mcpClient.close();
    return Object.freeze({
      semanticRequestEvidence: this.#mcpClient.semanticRequestEvidence(),
      transportEvidence: this.#mcpClient.transportEvidence()
    });
  }

  #buildPreparedRecoveryCompletion(prepared, rawResult, completedAtInput) {
    const value = this.#validatePreparedRecovery(prepared);
    const completedAt = new Date(completedAtInput);
    if (
      !Number.isFinite(completedAt.getTime()) ||
      completedAt.toISOString() !== completedAtInput ||
      completedAt.getTime() < Date.parse(value.startedAt)
    ) {
      throw new Error("RECOVERY_COMPLETION_PLAN_INVALID");
    }
    let observedResultDigest = sha256(canonicalJson(rawResult));
    let observedSourceWatermark = null;
    const rows = rowsFromMcpResult(rawResult);
    if (rows.length === 1) {
      observedResultDigest = sha256(canonicalJson(rows[0]));
      const sourceCommitMs = new Date(rows[0]?.source_commit_ts).getTime();
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
        tenantId: value.tenantId,
        recoverySessionId: value.recoverySessionId,
        subjectBindingHash: value.callerSubjectHash,
        sourceDigest: value.sourceDigest,
        expectedSourceClusterId: this.#expectedSourceClusterId,
        trustedPublisherKeys: this.#trustedPublisherKeys
      },
      completedAt
    );
    const terminalAuditEvent = Object.freeze({
      tenantId: value.tenantId,
      recoverySessionId: value.recoverySessionId,
      callerSubjectHash: value.callerSubjectHash,
      recoveryClusterId: this.#recoveryClusterId,
      brokerConfigDigest: value.brokerConfigDigest,
      queryTemplateDigest: value.queryTemplateDigest,
      boundInputDigest: value.boundInputDigest,
      interactionId: value.interactionId,
      eventId: value.terminalEventId,
      phase: "terminal",
      resultDigest: observedResultDigest,
      sourceWatermark: validated.row.source_commit_ts,
      startedAt: value.startedAt,
      completedAt,
      outcome: "recovered_context_only",
      errorCode: null
    });
    const terminalAuditDigest = recoveryAuditEventDigest(terminalAuditEvent);
    const recovery = Object.freeze({
      status: "RECOVERED_CONTEXT_ONLY",
      auditId: value.terminalEventId,
      auditDigest: terminalAuditDigest,
      auditInteractionId: value.interactionId,
      preReadAuditId: value.preReadEventId,
      preReadAuditDigest: value.preReadAuditDigest,
      recoverySessionId: value.recoverySessionId,
      tenantId: value.tenantId,
      sourceDigest: validated.sourceDigest,
      bundleDigest: validated.bundleDigest,
      context: Object.freeze({
        checkpoint: validated.row.checkpoint_summary,
        evidence: validated.row.evidence_summary,
        conflicts: validated.row.conflict_summary,
        receipt: validated.row.receipt_summary
      }),
      authorityTransferred: false,
      requiresFreshAuthorization: true
    });
    return Object.freeze({
      schemaVersion: "tideproof.prepared-recovery-completion.v1",
      preparedSha256: sha256(canonicalJson(value)),
      rawResultSha256: sha256(canonicalJson(rawResult)),
      recovery,
      resultDigest: observedResultDigest,
      sourceWatermark: observedSourceWatermark,
      terminalAuditEvent: Object.freeze({
        ...terminalAuditEvent,
        completedAt: new Date(terminalAuditEvent.completedAt).toISOString()
      }),
      terminalAuditDigest
    });
  }

  planPreparedRecoveryCompletion(prepared, rawResult) {
    return this.#buildPreparedRecoveryCompletion(
      prepared,
      rawResult,
      new Date().toISOString()
    );
  }

  async commitPreparedRecoveryCompletion(
    plan,
    prepared,
    rawResult,
    { beforeAuditAppend = null } = {}
  ) {
    if (
      beforeAuditAppend !== null &&
      typeof beforeAuditAppend !== "function"
    ) {
      throw new Error("RECOVERY_AUDIT_ACTION_GUARD_INVALID");
    }
    const expected = this.#buildPreparedRecoveryCompletion(
      prepared,
      rawResult,
      plan?.terminalAuditEvent?.completedAt
    );
    if (canonicalJson(plan) !== canonicalJson(expected)) {
      throw new Error("RECOVERY_COMPLETION_PLAN_INVALID");
    }
    const currentPrepared = this.#validatePreparedRecovery(prepared);
    const currentRows = rowsFromMcpResult(rawResult);
    if (currentRows.length !== 1) {
      throw new Error("RECOVERY_MCP_RESULT_CARDINALITY_INVALID");
    }
    validateRecoveryRow(
      currentRows[0],
      {
        tenantId: currentPrepared.tenantId,
        recoverySessionId: currentPrepared.recoverySessionId,
        subjectBindingHash: currentPrepared.callerSubjectHash,
        sourceDigest: currentPrepared.sourceDigest,
        expectedSourceClusterId: this.#expectedSourceClusterId,
        trustedPublisherKeys: this.#trustedPublisherKeys
      },
      new Date()
    );
    let terminalAudit;
    try {
      if (beforeAuditAppend !== null) {
        beforeAuditAppend("TERMINAL_AUDIT_APPEND");
      }
      terminalAudit = await this.#auditSink.append(
        expected.terminalAuditEvent,
        { beforeExternalAction: beforeAuditAppend }
      );
    } catch (cause) {
      if (
        cause?.message ===
          "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
      ) {
        throw cause;
      }
      throw new Error("RECOVERY_AUDIT_UNAVAILABLE", { cause });
    }
    if (
      terminalAudit?.eventDigest !== undefined &&
      terminalAudit.eventDigest !== expected.terminalAuditDigest
    ) {
      throw new Error("RECOVERY_AUDIT_RECEIPT_MISMATCH");
    }
    return Object.freeze({
      ...expected,
      terminalAudit: Object.freeze({ ...terminalAudit })
    });
  }

  async completePreparedRecovery(prepared, rawResult) {
    return this.commitPreparedRecoveryCompletion(
      this.planPreparedRecoveryCompletion(prepared, rawResult),
      prepared,
      rawResult
    );
  }

  async failPreparedRecovery(prepared, error, { rawResult = null } = {}) {
    const value = this.#validatePreparedRecovery(prepared);
    const errorCode = errorCodeFor(error);
    const completedAt = new Date();
    let observedResultDigest = sha256(canonicalJson({ errorCode }));
    let observedSourceWatermark = completedAt;
    if (rawResult !== null) {
      observedResultDigest = sha256(canonicalJson(rawResult));
      try {
        const rows = rowsFromMcpResult(rawResult);
        if (rows.length === 1) {
          observedResultDigest = sha256(canonicalJson(rows[0]));
          const sourceCommitMs = new Date(rows[0]?.source_commit_ts).getTime();
          if (Number.isFinite(sourceCommitMs)) {
            observedSourceWatermark = new Date(sourceCommitMs);
          }
        }
      } catch {
        // Preserve a digest of the exact observed result on malformed output.
      }
    }
    try {
      await this.#auditSink.append({
        tenantId: value.tenantId,
        recoverySessionId: value.recoverySessionId,
        callerSubjectHash: value.callerSubjectHash,
        recoveryClusterId: this.#recoveryClusterId,
        brokerConfigDigest: value.brokerConfigDigest,
        queryTemplateDigest: value.queryTemplateDigest,
        boundInputDigest: value.boundInputDigest,
        interactionId: value.interactionId,
        eventId: value.terminalEventId,
        phase: "terminal",
        resultDigest: observedResultDigest,
        sourceWatermark: observedSourceWatermark,
        startedAt: value.startedAt,
        completedAt,
        outcome: "unknown_do_not_act",
        errorCode
      });
    } catch {
      return this.#unknown("recovery_audit_unavailable");
    }
    return this.#unknown(errorCode);
  }

  async recover(input = {}) {
    let prepared;
    let rawResult = null;
    try {
      ({ prepared } = await this.prepareRecovery(input));
    } catch (error) {
      return this.#unknown(
        error?.message === "RECOVERY_AUDIT_UNAVAILABLE"
          ? "recovery_audit_unavailable"
          : errorCodeFor(error)
      );
    }
    try {
      rawResult = await this.executePreparedRecovery(prepared);
      const completed = await this.completePreparedRecovery(
        prepared,
        rawResult
      );
      return completed.recovery;
    } catch (error) {
      return this.failPreparedRecovery(prepared, error, { rawResult });
    }
  }
}
