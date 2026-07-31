"use strict";

const crypto = require("node:crypto");

const REQUEST_SCHEMA = "tideproof.aws-authority-request.v2";
const RESPONSE_SCHEMA = "tideproof.aws-authority-boundary.v2";
const PROOF_RESPONSE_SCHEMA =
  "tideproof.aws-authority-durable-proof.v1";
const POLICY_VERSION = "gate1-policy-v2";
const LEASE_MS = 300_000;
const MAX_TRANSACTION_RETRIES = 6;
const MAX_TRANSACTION_WINDOW_MS = 20_000;
const CONTENDERS = new Set(["alpha", "bravo"]);
const AUTHORITY_NAMESPACE = "7c952e66-76b8-5b66-8d13-20ef81e86241";
const RETRYABLE_TRANSACTION_CODES = new Set(["40001"]);
const AMBIGUOUS_TRANSACTION_CODES = new Set([
  "40003",
  "ECONNRESET",
  "EPIPE",
  "ETIMEDOUT",
  "57P01",
  "57P02",
  "57P03"
]);

const SPEND_SQL = `
  SELECT *
  FROM tp_api.g1_spend_authority_v1(
    $1::UUID, $2::UUID, $3, $4::JSONB,
    $5::UUID, $6::UUID, $7, $8, $9, $10,
    $11::UUID, $12::UUID, $13::JSONB, $14, $15, $16::INT8
  )
`;

const RESOLVE_SQL = `
  SELECT *
  FROM tp_api.g1_resolve_request_v1(
    $1::UUID, $2::UUID, $3
  )
`;

const PROOF_SQL = `
  SELECT *
  FROM tp_api.g1_observe_authority_race_v1(
    $1::UUID, $2::UUID, $3,
    $4::UUID, $5, $6::UUID, $7
  )
`;

function exactKeys(value, allowed) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...allowed].sort().join("\n")
  );
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(value) {
  return crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value))
    .digest("hex");
}

function uuidBytes(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value
    )
  ) {
    throw new Error("UUID_REJECTED");
  }
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function uuidV5(namespace, name) {
  const digest = crypto
    .createHash("sha1")
    .update(uuidBytes(namespace))
    .update(String(name), "utf8")
    .digest()
    .subarray(0, 16);
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20)
  ].join("-");
}

function requiredEnvironment(name, maximum = 512) {
  const value = process.env[name];
  if (
    typeof value !== "string" ||
    value.trim().length === 0 ||
    value.length > maximum
  ) {
    throw new Error("AUTHORITY_CONFIGURATION_REJECTED");
  }
  return value.trim();
}

function requiredUuidEnvironment(name) {
  const value = requiredEnvironment(name, 64).toLowerCase();
  uuidBytes(value);
  return value;
}

function configuration() {
  const config = {
    secretArn: requiredEnvironment("AUTHORITY_DATABASE_SECRET_ARN", 2_048),
    tenantId: requiredUuidEnvironment("AUTHORITY_TENANT_ID"),
    runId: requiredUuidEnvironment("AUTHORITY_RUN_ID"),
    incidentId: requiredUuidEnvironment("AUTHORITY_INCIDENT_ID"),
    evidenceId: requiredUuidEnvironment("AUTHORITY_EVIDENCE_ID"),
    raceId: requiredUuidEnvironment("AUTHORITY_RACE_ID"),
    resourceId: requiredEnvironment("AUTHORITY_RESOURCE_ID", 160),
    sourceCommit: requiredEnvironment("SOURCE_COMMIT", 64),
    configDigest: requiredEnvironment("CONFIG_DIGEST", 64),
    treeDigest: requiredEnvironment("TREE_DIGEST", 64),
    packageLockDigest: requiredEnvironment("PACKAGE_LOCK_DIGEST", 64),
    authoritySourceDigest: requiredEnvironment(
      "AUTHORITY_SOURCE_DIGEST",
      64
    ),
    authorityArtifactDigest: requiredEnvironment(
      "AUTHORITY_ARTIFACT_DIGEST",
      64
    )
  };
  if (
    !/^arn:aws[a-zA-Z-]*:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+$/.test(
      config.secretArn
    ) ||
    !/^[0-9a-f]{40}$/.test(config.sourceCommit) ||
    !/^[0-9a-f]{40}$/.test(config.treeDigest) ||
    ![
      config.configDigest,
      config.packageLockDigest,
      config.authoritySourceDigest,
      config.authorityArtifactDigest
    ].every((value) => /^[0-9a-f]{64}$/.test(value))
  ) {
    throw new Error("AUTHORITY_CONFIGURATION_REJECTED");
  }
  return config;
}

function parseReserveEvent(event, config) {
  if (
    !exactKeys(event, ["contender", "mode", "raceId", "schemaVersion"]) ||
    event.schemaVersion !== REQUEST_SCHEMA ||
    event.mode !== "reserve" ||
    event.raceId !== config.raceId ||
    !CONTENDERS.has(event.contender)
  ) {
    throw new Error("AUTHORITY_REQUEST_REJECTED");
  }
  return {
    raceId: event.raceId,
    contender: event.contender
  };
}

function parseProofEvent(event, config) {
  if (
    !exactKeys(event, ["mode", "raceId", "schemaVersion"]) ||
    event.schemaVersion !== REQUEST_SCHEMA ||
    event.mode !== "proof" ||
    event.raceId !== config.raceId
  ) {
    throw new Error("AUTHORITY_REQUEST_REJECTED");
  }
  return {
    raceId: event.raceId,
    contender: null
  };
}

function authorityRequestFor(event, config) {
  const { raceId, contender } = parseReserveEvent(event, config);
  const agentId = `aws-authority-${contender}`;
  const payload = {
    scenario: "synthetic-highwater",
    action: "dispatch_rescue_unit",
    destination: "synthetic-zone-aws-race"
  };
  const request = {
    digestVersion: 1,
    tenantId: config.tenantId,
    runId: config.runId,
    incidentId: config.incidentId,
    resourceId: config.resourceId,
    operationId: uuidV5(
      AUTHORITY_NAMESPACE,
      `${raceId}:${contender}:operation`
    ),
    agentId,
    agency: "rescue",
    evidenceId: config.evidenceId,
    intentNonce: uuidV5(
      AUTHORITY_NAMESPACE,
      `${raceId}:${contender}:intent`
    ),
    effectKey: uuidV5(
      AUTHORITY_NAMESPACE,
      `${raceId}:${contender}:effect`
    ),
    leaseMs: LEASE_MS,
    policyVersion: POLICY_VERSION,
    actionKind: "dispatch_rescue_unit",
    payload,
    payloadDigest: sha256Hex(payload)
  };
  request.requestPayload = {
    digestVersion: request.digestVersion,
    tenantId: request.tenantId,
    runId: request.runId,
    incidentId: request.incidentId,
    resourceId: request.resourceId,
    agentId: request.agentId,
    agency: request.agency,
    evidenceId: request.evidenceId,
    intentNonce: request.intentNonce,
    effectKey: request.effectKey,
    leaseMs: request.leaseMs,
    policyVersion: request.policyVersion,
    actionKind: request.actionKind,
    payloadDigest: request.payloadDigest
  };
  request.requestDigest = sha256Hex(request.requestPayload);
  return request;
}

function validateConnectionString(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  const queryKeys = [...parsed.searchParams.keys()].sort();
  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol) ||
    parsed.username !== "tp_authorizer_user" ||
    parsed.password.length < 16 ||
    parsed.hostname.length === 0 ||
    parsed.pathname !== "/tideproof" ||
    parsed.hash !== "" ||
    queryKeys.join("\n") !== "sslmode" ||
    parsed.searchParams.get("sslmode") !== "verify-full"
  ) {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  return parsed.toString();
}

function connectionStringFromSecret(response, expectedArn) {
  if (
    !response ||
    response.ARN !== expectedArn ||
    typeof response.SecretString !== "string" ||
    response.SecretBinary !== undefined ||
    !Array.isArray(response.VersionStages) ||
    !response.VersionStages.includes("AWSCURRENT")
  ) {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  let secret;
  try {
    secret = JSON.parse(response.SecretString);
  } catch {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  if (!exactKeys(secret, ["connectionString"])) {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  return validateConnectionString(secret.connectionString);
}

async function loadConnectionString(config) {
  const {
    GetSecretValueCommand,
    SecretsManagerClient
  } = require("@aws-sdk/client-secrets-manager");
  const { NodeHttpHandler } = require("@smithy/node-http-handler");
  const client = new SecretsManagerClient({
    region: process.env.AWS_REGION,
    maxAttempts: 1,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 5_000
    })
  });
  const response = await client.send(
    new GetSecretValueCommand({ SecretId: config.secretArn })
  );
  return connectionStringFromSecret(response, config.secretArn);
}

function spendValues(request) {
  return [
    request.tenantId,
    request.operationId,
    request.requestDigest,
    JSON.stringify(request.requestPayload),
    request.runId,
    request.incidentId,
    request.resourceId,
    request.agentId,
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

function normalizeTimestamp(value) {
  if (value === null || value === undefined) {
    return null;
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  return parsed.toISOString();
}

function normalizeSpendRow(row, request) {
  const allowedOutcomes = new Set([
    "authorization_denied",
    "resource_held_denied",
    "resource_reserved"
  ]);
  if (
    !row ||
    !allowedOutcomes.has(row.decision_outcome) ||
    row.decision_operation_id !== request.operationId ||
    row.decision_request_digest !== request.requestDigest ||
    ![null, "operation_replay"].includes(row.decision_replay_kind ?? null)
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  const winning = row.decision_outcome === "resource_reserved";
  const reason = row.decision_reason ?? null;
  const fencingToken =
    row.decision_fencing_token === null ||
    row.decision_fencing_token === undefined
      ? null
      : String(row.decision_fencing_token);
  const leaseExpiresAt = normalizeTimestamp(
    row.decision_lease_expires_at
  );
  if (
    (winning &&
      (reason !== null ||
        fencingToken === null ||
        !/^[1-9][0-9]*$/.test(fencingToken) ||
        leaseExpiresAt === null)) ||
    (!winning &&
      (typeof reason !== "string" ||
        reason.length === 0 ||
        fencingToken !== null ||
        leaseExpiresAt !== null)) ||
    (row.decision_outcome === "resource_held_denied" &&
      reason !== "active_holder")
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  return {
    outcome: row.decision_outcome,
    reason,
    fencingToken,
    leaseExpiresAt,
    replayKind: row.decision_replay_kind ?? null
  };
}

function normalizeResolvedRow(row, request) {
  const allowedOutcomes = new Set([
    "authorization_denied",
    "resource_held_denied",
    "resource_reserved"
  ]);
  if (
    !row ||
    row.operation_id !== request.operationId ||
    row.request_digest !== request.requestDigest ||
    !allowedOutcomes.has(row.outcome)
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  const winning = row.outcome === "resource_reserved";
  const reason = row.reason ?? null;
  const fencingToken =
    row.fencing_token === null || row.fencing_token === undefined
      ? null
      : String(row.fencing_token);
  const leaseExpiresAt = normalizeTimestamp(row.lease_expires_at);
  if (
    (winning &&
      (!row.outbox_intent_id ||
        reason !== null ||
        fencingToken === null ||
        !/^[1-9][0-9]*$/.test(fencingToken) ||
        leaseExpiresAt === null ||
        fencingToken !== String(row.current_fence) ||
        row.active_run_id !== request.runId ||
        row.holder_operation_id !== request.operationId)) ||
    (!winning &&
      (row.outbox_intent_id ||
        typeof reason !== "string" ||
        reason.length === 0 ||
        fencingToken !== null ||
        leaseExpiresAt !== null)) ||
    (row.outcome === "resource_held_denied" &&
      reason !== "active_holder")
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  return {
    outcome: row.outcome,
    reason,
    fencingToken,
    leaseExpiresAt,
    replayKind: "reconciled_after_ambiguous_commit"
  };
}

function normalizeProofRow(row, config, requests) {
  const rowKeys = [
    "active_run_id",
    "alpha_fencing_token",
    "alpha_observed_fence",
    "alpha_observed_holder_operation_id",
    "alpha_outcome",
    "alpha_reason",
    "bravo_fencing_token",
    "bravo_observed_fence",
    "bravo_observed_holder_operation_id",
    "bravo_outcome",
    "bravo_reason",
    "current_fence",
    "held_denial_count",
    "holder_operation_id",
    "observed_at",
    "outbox_count",
    "outbox_operation_id",
    "pending_count",
    "protected_effect_count",
    "race_receipt_count",
    "reserved_count",
    "resource_receipt_count"
  ];
  if (!exactKeys(row, rowKeys)) {
    throw new Error("AUTHORITY_PROOF_REJECTED");
  }
  const counts = {
    raceReceiptCount: String(row.race_receipt_count),
    resourceReceiptCount: String(row.resource_receipt_count),
    reservedCount: String(row.reserved_count),
    heldDenialCount: String(row.held_denial_count),
    pendingCount: String(row.pending_count),
    outboxCount: String(row.outbox_count),
    protectedEffectCount: String(row.protected_effect_count)
  };
  const outcomes = {
    alpha: {
      operationId: requests.alpha.operationId,
      requestDigest: requests.alpha.requestDigest,
      outcome: row.alpha_outcome,
      reason: row.alpha_reason ?? null,
      fencingToken:
        row.alpha_fencing_token === null ||
        row.alpha_fencing_token === undefined
          ? null
          : String(row.alpha_fencing_token),
      observedHolderOperationId:
        row.alpha_observed_holder_operation_id ?? null,
      observedFence:
        row.alpha_observed_fence === null ||
        row.alpha_observed_fence === undefined
          ? null
          : String(row.alpha_observed_fence)
    },
    bravo: {
      operationId: requests.bravo.operationId,
      requestDigest: requests.bravo.requestDigest,
      outcome: row.bravo_outcome,
      reason: row.bravo_reason ?? null,
      fencingToken:
        row.bravo_fencing_token === null ||
        row.bravo_fencing_token === undefined
          ? null
          : String(row.bravo_fencing_token),
      observedHolderOperationId:
        row.bravo_observed_holder_operation_id ?? null,
      observedFence:
        row.bravo_observed_fence === null ||
        row.bravo_observed_fence === undefined
          ? null
          : String(row.bravo_observed_fence)
    }
  };
  const winner = Object.values(outcomes).find(
    ({ outcome }) => outcome === "resource_reserved"
  );
  const denial = Object.values(outcomes).find(
    ({ outcome }) => outcome === "resource_held_denied"
  );
  const currentFence = String(row.current_fence);
  const observedAt = normalizeTimestamp(row.observed_at);
  if (
    row.active_run_id !== config.runId ||
    !winner ||
    !denial ||
    winner === denial ||
    winner.reason !== null ||
    !/^[1-9][0-9]*$/.test(winner.fencingToken ?? "") ||
    winner.observedHolderOperationId !== null ||
    winner.observedFence !== null ||
    denial.reason !== "active_holder" ||
    denial.fencingToken !== null ||
    denial.observedHolderOperationId !== winner.operationId ||
    denial.observedFence !== winner.fencingToken ||
    currentFence !== winner.fencingToken ||
    row.holder_operation_id !== winner.operationId ||
    row.outbox_operation_id !== winner.operationId ||
    observedAt === null ||
    !exactKeys(counts, [
      "heldDenialCount",
      "outboxCount",
      "pendingCount",
      "protectedEffectCount",
      "raceReceiptCount",
      "reservedCount",
      "resourceReceiptCount"
    ]) ||
    counts.raceReceiptCount !== "2" ||
    counts.resourceReceiptCount !== "2" ||
    counts.reservedCount !== "1" ||
    counts.heldDenialCount !== "1" ||
    counts.pendingCount !== "0" ||
    counts.outboxCount !== "1" ||
    counts.protectedEffectCount !== "0"
  ) {
    throw new Error("AUTHORITY_PROOF_REJECTED");
  }
  return {
    activeRunId: row.active_run_id,
    currentFence,
    holderOperationId: row.holder_operation_id,
    outboxOperationId: row.outbox_operation_id,
    observedAt,
    counts,
    outcomes
  };
}

async function closeQuietly(client) {
  await client?.end?.().catch(() => {});
}

async function rollbackQuietly(client) {
  await client?.query?.("ROLLBACK").catch(() => {});
}

async function reconcile({
  connectionString,
  request,
  createClient
}) {
  const client = createClient(connectionString);
  try {
    await client.connect();
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    const result = await client.query(RESOLVE_SQL, [
      request.tenantId,
      request.operationId,
      request.requestDigest
    ]);
    await client.query("COMMIT");
    if (result.rowCount !== 1 || result.rows.length !== 1) {
      throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
    }
    return normalizeResolvedRow(result.rows[0], request);
  } catch (error) {
    await rollbackQuietly(client);
    throw error;
  } finally {
    await closeQuietly(client);
  }
}

async function observeAuthorityRace({
  connectionString,
  config,
  createClient
}) {
  const requests = Object.fromEntries(
    ["alpha", "bravo"].map((contender) => [
      contender,
      authorityRequestFor(
        {
          schemaVersion: REQUEST_SCHEMA,
          mode: "reserve",
          raceId: config.raceId,
          contender
        },
        config
      )
    ])
  );
  const client = createClient(connectionString);
  try {
    await client.connect();
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    const isolation = await client.query(
      "SHOW TRANSACTION ISOLATION LEVEL"
    );
    const backend = await client.query(
      "SELECT pg_backend_pid()::STRING AS backend_id"
    );
    const result = await client.query(PROOF_SQL, [
      config.tenantId,
      config.runId,
      config.resourceId,
      requests.alpha.operationId,
      requests.alpha.requestDigest,
      requests.bravo.operationId,
      requests.bravo.requestDigest
    ]);
    await client.query("COMMIT");
    if (
      result.rowCount !== 1 ||
      result.rows.length !== 1 ||
      isolation.rows?.[0]?.transaction_isolation !== "serializable" ||
      typeof backend.rows?.[0]?.backend_id !== "string"
    ) {
      throw new Error("AUTHORITY_PROOF_REJECTED");
    }
    const state = normalizeProofRow(result.rows[0], config, requests);
    return {
      state,
      transaction: {
        isolation: "serializable",
        databaseObservedAt: state.observedAt,
        databaseSessionDigest: sha256Hex(
          `${config.raceId}:${backend.rows[0].backend_id}`
        )
      }
    };
  } catch (error) {
    await rollbackQuietly(client);
    throw error;
  } finally {
    await closeQuietly(client);
  }
}

async function spendAuthority({
  connectionString,
  request,
  createClient,
  now = () => Date.now()
}) {
  const startedAtMs = now();
  const retryCodes = [];
  for (let attempt = 0; attempt <= MAX_TRANSACTION_RETRIES; attempt += 1) {
    const client = createClient(connectionString);
    let commitDispatched = false;
    try {
      await client.connect();
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const isolation = await client.query(
        "SHOW TRANSACTION ISOLATION LEVEL"
      );
      const backend = await client.query(
        "SELECT pg_backend_pid()::STRING AS backend_id, clock_timestamp() AS started_at"
      );
      const result = await client.query(SPEND_SQL, spendValues(request));
      const completion = await client.query(
        "SELECT clock_timestamp() AS completed_at"
      );
      commitDispatched = true;
      await client.query("COMMIT");
      if (
        result.rowCount !== 1 ||
        result.rows.length !== 1 ||
        isolation.rows?.[0]?.transaction_isolation !== "serializable" ||
        typeof backend.rows?.[0]?.backend_id !== "string" ||
        completion.rowCount !== 1 ||
        completion.rows.length !== 1
      ) {
        throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
      }
      const databaseStartedAt = normalizeTimestamp(
        backend.rows[0].started_at
      );
      const databaseCompletedAt = normalizeTimestamp(
        completion.rows[0].completed_at
      );
      if (
        databaseStartedAt === null ||
        databaseCompletedAt === null ||
        Date.parse(databaseCompletedAt) < Date.parse(databaseStartedAt)
      ) {
        throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
      }
      return {
        decision: normalizeSpendRow(result.rows[0], request),
        transaction: {
          isolation: "serializable",
          attempts: attempt + 1,
          retryCodes,
          databaseStartedAt,
          databaseCompletedAt,
          databaseSessionDigest: sha256Hex(
            `${request.raceId}:${backend.rows[0].backend_id}`
          )
        }
      };
    } catch (error) {
      if (!commitDispatched) {
        await rollbackQuietly(client);
      }
      const elapsed = now() - startedAtMs;
      if (
        !commitDispatched &&
        RETRYABLE_TRANSACTION_CODES.has(error?.code) &&
        attempt < MAX_TRANSACTION_RETRIES &&
        elapsed < MAX_TRANSACTION_WINDOW_MS
      ) {
        retryCodes.push(error.code);
        continue;
      }
      if (
        commitDispatched ||
        AMBIGUOUS_TRANSACTION_CODES.has(error?.code)
      ) {
        const decision = await reconcile({
          connectionString,
          request,
          createClient
        });
        return {
          decision,
          transaction: {
            isolation: "serializable",
            attempts: attempt + 1,
            retryCodes,
            reconciled: true
          }
        };
      }
      throw error;
    } finally {
      await closeQuietly(client);
    }
  }
  throw new Error("AUTHORITY_RETRY_EXHAUSTED");
}

function buildBindings(config) {
  return {
    sourceCommit: config.sourceCommit,
    configDigest: config.configDigest,
    treeDigest: config.treeDigest,
    packageLockDigest: config.packageLockDigest,
    authoritySourceDigest: config.authoritySourceDigest,
    authorityArtifactDigest: config.authorityArtifactDigest
  };
}

function failClosed(code, config = null, parsed = null) {
  return {
    schemaVersion: RESPONSE_SCHEMA,
    status: "UNKNOWN_DO_NOT_ACT",
    code,
    raceId: parsed?.raceId ?? null,
    contender: parsed?.contender ?? null,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    modelAccess: false,
    ...(config ? buildBindings(config) : {})
  };
}

function safeCode(error) {
  if (
    [
      "AUTHORITY_CONFIGURATION_REJECTED",
      "AUTHORITY_DATABASE_RESPONSE_REJECTED",
      "AUTHORITY_PROOF_REJECTED",
      "AUTHORITY_RECONCILIATION_REJECTED",
      "AUTHORITY_REQUEST_REJECTED",
      "AUTHORITY_RETRY_EXHAUSTED",
      "AUTHORITY_SECRET_REJECTED"
    ].includes(error?.message)
  ) {
    return error.message;
  }
  return "AUTHORITY_UNAVAILABLE";
}

async function runAuthority({
  event,
  context,
  getConnectionString = loadConnectionString,
  createClient,
  now = () => Date.now()
}) {
  let config;
  let parsed;
  try {
    config = configuration();
    if (exactKeys(event, ["mode"]) && event.mode === "status") {
      return failClosed(
        "STATUS_ONLY_NO_AUTHORIZATION",
        config,
        null
      );
    }
    if (event?.mode === "proof") {
      parsed = parseProofEvent(event, config);
      const connectionString = await getConnectionString(config);
      const clientFactory =
        createClient ??
        ((value) => {
          const { Client } = require("pg");
          return new Client({
            connectionString: value,
            application_name: "tideproof-aws-authority-proof"
          });
        });
      const proof = await observeAuthorityRace({
        connectionString,
        config,
        createClient: clientFactory
      });
      return {
        schemaVersion: PROOF_RESPONSE_SCHEMA,
        status: "OBSERVED",
        raceId: parsed.raceId,
        transaction: proof.transaction,
        state: proof.state,
        invocationRequestId:
          typeof context?.awsRequestId === "string"
            ? context.awsRequestId.slice(0, 160)
            : null,
        functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
        readOnly: true,
        authorityTransferred: false,
        requiresFreshAuthorization: true,
        modelAccess: false,
        ...buildBindings(config)
      };
    }
    parsed = parseReserveEvent(event, config);
    const request = authorityRequestFor(event, config);
    request.raceId = parsed.raceId;
    const connectionString = await getConnectionString(config);
    const clientFactory =
      createClient ??
      ((value) => {
        const { Client } = require("pg");
        return new Client({
          connectionString: value,
          application_name: "tideproof-aws-authority"
        });
      });
    const result = await spendAuthority({
      connectionString,
      request,
      createClient: clientFactory,
      now
    });
    return {
      schemaVersion: RESPONSE_SCHEMA,
      status: "COMMITTED",
      raceId: parsed.raceId,
      contender: parsed.contender,
      operationId: request.operationId,
      requestDigest: request.requestDigest,
      outcome: result.decision.outcome,
      reason: result.decision.reason,
      fencingToken: result.decision.fencingToken,
      leaseExpiresAt: result.decision.leaseExpiresAt,
      replayKind: result.decision.replayKind,
      transaction: result.transaction,
      invocationRequestId:
        typeof context?.awsRequestId === "string"
          ? context.awsRequestId.slice(0, 160)
          : null,
      functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
      authorityTransferred: false,
      requiresFreshAuthorization: false,
      modelAccess: false,
      ...buildBindings(config)
    };
  } catch (error) {
    return failClosed(safeCode(error), config, parsed);
  }
}

async function handler(event, context) {
  return runAuthority({ event, context });
}

exports.handler = handler;
exports.__test = {
  AUTHORITY_NAMESPACE,
  PROOF_RESPONSE_SCHEMA,
  PROOF_SQL,
  REQUEST_SCHEMA,
  RESPONSE_SCHEMA,
  SPEND_SQL,
  RESOLVE_SQL,
  authorityRequestFor,
  canonicalJson,
  configuration,
  connectionStringFromSecret,
  exactKeys,
  normalizeResolvedRow,
  normalizeProofRow,
  normalizeSpendRow,
  observeAuthorityRace,
  parseProofEvent,
  parseReserveEvent,
  runAuthority,
  safeCode,
  sha256Hex,
  spendAuthority,
  uuidV5,
  validateConnectionString
};
