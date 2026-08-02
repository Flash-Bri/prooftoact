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
const DATABASE_TIMEOUTS = Object.freeze({
  connectionTimeoutMillis: 2_000,
  query_timeout: 4_500,
  statement_timeout: 4_000,
  idle_in_transaction_session_timeout: 3_000
});
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
  FROM tp_api.g2_spend_authority_race_v1(
    $1::UUID, $2::UUID, $3, $4::JSONB,
    $5, $6, $7, $8::UUID, $9::UUID, $10, $11, $12,
    $13::UUID, $14::UUID, $15::JSONB, $16, $17, $18::INT8
  )
`;

const RESOLVE_SQL = `
  SELECT *
  FROM tp_api.g1_resolve_request_v1(
    $1::UUID, $2::UUID, $3, $4
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

function authorityIdentityFor(request, epochValue) {
  const authorizationEpoch = Number(epochValue);
  if (
    !Number.isSafeInteger(authorizationEpoch) ||
    authorizationEpoch < 1 ||
    String(authorizationEpoch) !== String(epochValue)
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  const logicalAuthorityKeySha256 = sha256Hex({
    schemaVersion: "tideproof.authority.logical-authority-key.v1",
    logicalActionDigest: request.logicalActionDigest,
    authorizationEpoch
  });
  const authorizationBindingSha256 = sha256Hex({
    schemaVersion: "tideproof.authority.authorization-binding.v1",
    logicalActionDigest: request.logicalActionDigest,
    proposalDigest: request.proposalDigest,
    authorizationEpoch,
    logicalAuthorityKeySha256
  });
  return {
    authorizationEpoch,
    logicalAuthorityKeySha256,
    authorizationBindingSha256
  };
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

function requiredDatabaseHostEnvironment(name) {
  const value = requiredEnvironment(name, 253).toLowerCase();
  if (
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+cockroachlabs\.cloud$/.test(
      value
    )
  ) {
    throw new Error("AUTHORITY_CONFIGURATION_REJECTED");
  }
  return value;
}

function requiredDatabasePortEnvironment(name) {
  const value = requiredEnvironment(name, 5);
  const port = Number(value);
  if (!/^[1-9][0-9]{0,4}$/.test(value) || port > 65_535) {
    throw new Error("AUTHORITY_CONFIGURATION_REJECTED");
  }
  return value;
}

function configuration() {
  const config = {
    secretArn: requiredEnvironment("AUTHORITY_DATABASE_SECRET_ARN", 2_048),
    secretVersionId: requiredEnvironment(
      "AUTHORITY_DATABASE_SECRET_VERSION_ID",
      64
    ),
    databaseHost: requiredDatabaseHostEnvironment(
      "AUTHORITY_DATABASE_HOST"
    ),
    databasePort: requiredDatabasePortEnvironment(
      "AUTHORITY_DATABASE_PORT"
    ),
    tenantId: requiredUuidEnvironment("AUTHORITY_TENANT_ID"),
    runId: requiredUuidEnvironment("AUTHORITY_RUN_ID"),
    incidentId: requiredUuidEnvironment("AUTHORITY_INCIDENT_ID"),
    evidenceId: requiredUuidEnvironment("AUTHORITY_EVIDENCE_ID"),
    raceId: requiredUuidEnvironment("AUTHORITY_RACE_ID"),
    resourceId: requiredEnvironment("AUTHORITY_RESOURCE_ID", 160),
    alphaProposalDigest: requiredEnvironment(
      "AUTHORITY_ALPHA_PROPOSAL_DIGEST",
      64
    ),
    bravoProposalDigest: requiredEnvironment(
      "AUTHORITY_BRAVO_PROPOSAL_DIGEST",
      64
    ),
    alphaLogicalActionDigest: requiredEnvironment(
      "AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST",
      64
    ),
    bravoLogicalActionDigest: requiredEnvironment(
      "AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST",
      64
    ),
    selectedEvidenceDigest: requiredEnvironment(
      "AUTHORITY_SELECTED_EVIDENCE_DIGEST",
      64
    ),
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
    !/^[A-Za-z0-9-]{32,64}$/.test(config.secretVersionId) ||
    !/^[0-9a-f]{40}$/.test(config.sourceCommit) ||
    !/^[0-9a-f]{40}$/.test(config.treeDigest) ||
    ![
      config.configDigest,
      config.packageLockDigest,
      config.authoritySourceDigest,
      config.authorityArtifactDigest,
      config.alphaProposalDigest,
      config.bravoProposalDigest,
      config.alphaLogicalActionDigest,
      config.bravoLogicalActionDigest,
      config.selectedEvidenceDigest
    ].every((value) => /^[0-9a-f]{64}$/.test(value))
    || config.alphaProposalDigest === config.bravoProposalDigest
    || config.alphaLogicalActionDigest ===
      config.bravoLogicalActionDigest
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
    destination: "synthetic-zone-aws-race",
    logicalDispatch: contender
  };
  const request = {
    digestVersion: 2,
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
    payloadDigest: sha256Hex(payload),
    proposalDigest:
      contender === "alpha"
        ? config.alphaProposalDigest
        : config.bravoProposalDigest,
    logicalActionDigest:
      contender === "alpha"
        ? config.alphaLogicalActionDigest
        : config.bravoLogicalActionDigest,
    selectedEvidenceDigest: config.selectedEvidenceDigest
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
    payloadDigest: request.payloadDigest,
    logicalActionDigest: request.logicalActionDigest,
    proposalDigest: request.proposalDigest,
    selectedEvidenceId: request.evidenceId,
    selectedEvidenceDigest: request.selectedEvidenceDigest
  };
  request.requestDigest = sha256Hex(request.requestPayload);
  return request;
}

function validateConnectionString(value, expectedHost, expectedPort) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  const queryKeys = [...parsed.searchParams.keys()].sort();
  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol) ||
    parsed.username !== "tp_gate2_authorizer_user" ||
    parsed.password.length < 16 ||
    parsed.hostname !== expectedHost ||
    parsed.port !== expectedPort ||
    parsed.pathname !== "/tideproof" ||
    parsed.hash !== "" ||
    queryKeys.join("\n") !== "sslmode" ||
    parsed.searchParams.get("sslmode") !== "verify-full"
  ) {
    throw new Error("AUTHORITY_SECRET_REJECTED");
  }
  return parsed.toString();
}

function connectionStringFromSecret(response, config) {
  if (
    !response ||
    response.ARN !== config.secretArn ||
    response.VersionId !== config.secretVersionId ||
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
  return validateConnectionString(
    secret.connectionString,
    config.databaseHost,
    config.databasePort
  );
}

function secretRequestFor(config) {
  return {
    SecretId: config.secretArn,
    VersionId: config.secretVersionId,
    VersionStage: "AWSCURRENT"
  };
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
    new GetSecretValueCommand(secretRequestFor(config))
  );
  return connectionStringFromSecret(response, config);
}

function spendValues(request) {
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

function databaseClientConfiguration(connectionString, applicationName) {
  if (
    typeof connectionString !== "string" ||
    connectionString.length === 0 ||
    ![
      "tideproof-aws-authority",
      "tideproof-aws-authority-proof"
    ].includes(applicationName)
  ) {
    throw new Error("AUTHORITY_CONFIGURATION_REJECTED");
  }
  return {
    connectionString,
    application_name: applicationName,
    ...DATABASE_TIMEOUTS
  };
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

function databaseCommitResult(decision, request, observation) {
  const requiresFreshAuthorization = !decision.authorityCurrent;
  return {
    schemaVersion: "tideproof.database-commit-result.v1",
    status:
      decision.durableReceipt === false
        ? "DENIED_NOT_DURABLE"
        : decision.authorityCurrent === false &&
      !decision.outcome.includes("denied")
        ? "COMMITTED_BUT_NO_LONGER_CURRENT"
        : "COMMITTED",
    operation: "authority",
    operationDigest:
      decision.durableReceipt === false
        ? request.requestDigest
        : decision.committedRequestDigest,
    observation,
    databaseNow: decision.databaseNow,
    outcome: decision.outcome,
    authority: {
      current: decision.authorityCurrent,
      requiresFreshAuthorization
    },
    reason: decision.reason ?? null
  };
}

function normalizeSpendRow(row, request) {
  const allowedOutcomes = new Set([
    "authorization_denied",
    "resource_held_denied",
    "resource_reserved"
  ]);
  const replayKind = row?.decision_replay_kind ?? null;
  const committedSelectedEvidenceId =
    row?.decision_committed_evidence_id;
  const committedSelectedEvidenceDigest =
    row?.decision_committed_evidence_digest;
  const durableReceipt = row?.decision_durable_receipt;
  const reason = row?.decision_reason ?? null;
  const fencingToken =
    row?.decision_fencing_token === null ||
    row?.decision_fencing_token === undefined
      ? null
      : String(row.decision_fencing_token);
  const leaseExpiresAt = normalizeTimestamp(
    row?.decision_lease_expires_at
  );
  const databaseNow = normalizeTimestamp(row?.decision_database_now);
  const authorityCurrent = row?.decision_authority_current;
  if (
    !row ||
    typeof durableReceipt !== "boolean" ||
    !allowedOutcomes.has(row.decision_outcome) ||
    ![
      null,
      "operation_replay",
      "semantic_replay",
      "logical_authority_replay"
    ].includes(replayKind) ||
    row.decision_logical_action_digest !== request.logicalActionDigest ||
    (replayKind !== "logical_authority_replay" &&
      row.decision_proposal_digest !== request.proposalDigest) ||
    !/^[0-9a-f]{64}$/.test(row.decision_proposal_digest ?? "") ||
    row.decision_operation_id !== request.operationId && replayKind === null ||
    row.decision_request_digest !== request.requestDigest &&
      [null, "operation_replay", "semantic_replay"].includes(replayKind) ||
    databaseNow === null
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  if (!durableReceipt) {
    const missingProposal =
      reason === "proposal_authorization_missing_or_stale";
    const boundEarlyDenial = [
      "proposal_authorization_expired",
      "proposal_authorization_superseded"
    ].includes(reason);
    const hasNoCommittedEvidence =
      committedSelectedEvidenceId === null &&
      committedSelectedEvidenceDigest === null;
    const hasNoAuthorityIdentity =
      row.decision_authorization_epoch === null &&
      row.decision_logical_authority_key_sha256 === null &&
      row.decision_authorization_binding_sha256 === null;
    let boundIdentityValid = false;
    if (boundEarlyDenial) {
      try {
        const identity = authorityIdentityFor(
          request,
          row.decision_authorization_epoch
        );
        boundIdentityValid =
          row.decision_logical_authority_key_sha256 ===
            identity.logicalAuthorityKeySha256 &&
          row.decision_authorization_binding_sha256 ===
            identity.authorizationBindingSha256;
      } catch {
        boundIdentityValid = false;
      }
    }
    if (
      row.decision_outcome !== "authorization_denied" ||
      replayKind !== null ||
      row.decision_operation_id !== request.operationId ||
      row.decision_request_digest !== request.requestDigest ||
      row.decision_proposal_digest !== request.proposalDigest ||
      row.decision_logical_action_digest !== request.logicalActionDigest ||
      authorityCurrent !== false ||
      fencingToken !== null ||
      leaseExpiresAt !== null ||
      !hasNoCommittedEvidence ||
      (!missingProposal && !boundEarlyDenial) ||
      (missingProposal && !hasNoAuthorityIdentity) ||
      (boundEarlyDenial && !boundIdentityValid)
    ) {
      throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
    }
    return {
      durableReceipt: false,
      outcome: row.decision_outcome,
      reason,
      fencingToken: null,
      leaseExpiresAt: null,
      authorityCurrent: false,
      databaseNow,
      replayKind: null
    };
  }
  const committedEvidenceIdValid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      committedSelectedEvidenceId ?? ""
    );
  const committedEvidenceDigestValid =
    /^[0-9a-f]{64}$/.test(committedSelectedEvidenceDigest ?? "");
  const selectedDigestMismatch =
    row.decision_outcome === "authorization_denied" &&
    reason === "selected_evidence_digest_mismatch";
  const evidenceMissing =
    row.decision_outcome === "authorization_denied" &&
    reason === "evidence_missing";
  if (
    !committedEvidenceIdValid ||
    (replayKind !== "logical_authority_replay" &&
      committedSelectedEvidenceId !== request.evidenceId) ||
    (evidenceMissing && committedSelectedEvidenceDigest !== null) ||
    (selectedDigestMismatch &&
      (!committedEvidenceDigestValid ||
        committedSelectedEvidenceDigest === request.selectedEvidenceDigest)) ||
    (!evidenceMissing &&
      !selectedDigestMismatch &&
      (!committedEvidenceDigestValid ||
        (replayKind !== "logical_authority_replay" &&
          committedSelectedEvidenceDigest !==
            request.selectedEvidenceDigest)))
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  const identity = authorityIdentityFor(
    {
      ...request,
      proposalDigest: row.decision_proposal_digest
    },
    row.decision_authorization_epoch
  );
  if (
    row.decision_logical_authority_key_sha256 !==
      identity.logicalAuthorityKeySha256 ||
    row.decision_authorization_binding_sha256 !==
      identity.authorizationBindingSha256 ||
    ((replayKind === null || replayKind === "operation_replay") &&
      (row.decision_operation_id !== request.operationId ||
        row.decision_request_digest !== request.requestDigest)) ||
    (replayKind === "semantic_replay" &&
      row.decision_request_digest !== request.requestDigest) ||
    (replayKind === "logical_authority_replay" &&
      row.decision_outcome !== "resource_reserved")
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  const winning = row.decision_outcome === "resource_reserved";
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
      reason !== "active_holder") ||
    typeof authorityCurrent !== "boolean" ||
    (!winning && authorityCurrent) ||
    databaseNow === null ||
    (authorityCurrent &&
      new Date(leaseExpiresAt).getTime() <= new Date(databaseNow).getTime())
  ) {
    throw new Error("AUTHORITY_DATABASE_RESPONSE_REJECTED");
  }
  return {
    durableReceipt: true,
    outcome: row.decision_outcome,
    reason,
    fencingToken,
    leaseExpiresAt,
    authorityCurrent,
    databaseNow,
    replayKind,
    committedOperationId: row.decision_operation_id,
    committedRequestDigest: row.decision_request_digest,
    committedProposalDigest: row.decision_proposal_digest,
    committedSelectedEvidenceId,
    committedSelectedEvidenceDigest,
    ...identity
  };
}

function normalizeReceiptProposal(row, request) {
  const validUuid = (value) =>
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value
    );
  const validSha256 = (value) =>
    typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
  const admittedAt = normalizeTimestamp(
    row.receipt_proposal_admitted_at
  );
  const expiresAt = normalizeTimestamp(
    row.receipt_proposal_expires_at
  );
  const payload = row.receipt_proposal_payload;
  const payloadDigest = row.receipt_proposal_payload_digest;
  const selectedRank = Number(row.receipt_proposal_selected_rank);
  const proposalEpoch = Number(row.receipt_proposal_authorization_epoch);
  if (
    !validUuid(row.receipt_proposal_tenant_id) ||
    !validUuid(row.receipt_proposal_run_id) ||
    !validUuid(row.receipt_proposal_incident_id) ||
    !validUuid(row.receipt_proposal_retrieval_id) ||
    !validUuid(row.receipt_proposal_selected_evidence_id) ||
    !validSha256(row.receipt_proposal_digest) ||
    !validSha256(row.receipt_proposal_logical_action_digest) ||
    !validSha256(
      row.receipt_proposal_authority_evidence_binding_sha256
    ) ||
    !validSha256(payloadDigest) ||
    !validSha256(row.receipt_proposal_selected_evidence_digest) ||
    !validSha256(
      row.receipt_proposal_logical_authority_key_sha256
    ) ||
    !validSha256(
      row.receipt_proposal_authorization_binding_sha256
    ) ||
    admittedAt === null ||
    expiresAt === null ||
    typeof row.receipt_proposal_resource_id !== "string" ||
    row.receipt_proposal_resource_id.length === 0 ||
    typeof row.receipt_proposal_agency !== "string" ||
    row.receipt_proposal_agency.length === 0 ||
    typeof row.receipt_proposal_policy_version !== "string" ||
    row.receipt_proposal_policy_version.length === 0 ||
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    typeof row.receipt_proposal_payload_canonical !== "string" ||
    row.receipt_proposal_payload_canonical !== canonicalJson(payload) ||
    sha256Hex(payload) !== payloadDigest ||
    selectedRank !== 1 ||
    !Number.isSafeInteger(proposalEpoch) ||
    proposalEpoch < 1 ||
    String(proposalEpoch) !==
      String(row.receipt_proposal_authorization_epoch) ||
    Date.parse(expiresAt) <= Date.parse(admittedAt)
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  const logicalActionDigest = sha256Hex({
    schemaVersion: "tideproof.authority.logical-action.v1",
    tenantId: row.receipt_proposal_tenant_id,
    incidentId: row.receipt_proposal_incident_id,
    resourceId: row.receipt_proposal_resource_id,
    agency: row.receipt_proposal_agency,
    actionKind: row.receipt_proposal_action_kind,
    payloadDigest
  });
  const proposalDigest = sha256Hex({
    schemaVersion: "tideproof.authority.dvi-proposal-identity.v1",
    tenantId: row.receipt_proposal_tenant_id,
    runId: row.receipt_proposal_run_id,
    incidentId: row.receipt_proposal_incident_id,
    retrievalId: row.receipt_proposal_retrieval_id,
    logicalActionDigest,
    authorityEvidenceBindingSha256:
      row.receipt_proposal_authority_evidence_binding_sha256,
    selectedEvidenceId: row.receipt_proposal_selected_evidence_id,
    selectedEvidenceDigest:
      row.receipt_proposal_selected_evidence_digest,
    policyVersion: row.receipt_proposal_policy_version,
    selectedRank,
    admittedAt,
    expiresAt
  });
  const identity = authorityIdentityFor(
    {
      ...request,
      logicalActionDigest,
      proposalDigest
    },
    proposalEpoch
  );
  if (
    row.receipt_proposal_tenant_id !== request.tenantId ||
    row.receipt_proposal_digest !== row.proposal_digest ||
    proposalDigest !== row.proposal_digest ||
    logicalActionDigest !== row.logical_action_digest ||
    row.receipt_proposal_logical_action_digest !==
      row.logical_action_digest ||
    row.receipt_proposal_resource_id !== row.resource_id ||
    row.receipt_proposal_agency !== row.agency ||
    row.receipt_proposal_action_kind !== "dispatch_rescue_unit" ||
    payloadDigest !== row.payload_digest ||
    canonicalJson(payload) !== canonicalJson(request.payload) ||
    row.receipt_proposal_run_id !== row.run_id ||
    row.receipt_proposal_incident_id !== row.incident_id ||
    row.receipt_proposal_selected_evidence_id !== row.evidence_id ||
    String(proposalEpoch) !== String(row.authorization_epoch) ||
    row.receipt_proposal_logical_authority_key_sha256 !==
      identity.logicalAuthorityKeySha256 ||
    row.receipt_proposal_authorization_binding_sha256 !==
      identity.authorizationBindingSha256
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  return { expiresAt };
}

function normalizeResolvedRow(row, request) {
  const allowedOutcomes = new Set([
    "authorization_denied",
    "resource_held_denied",
    "resource_reserved"
  ]);
  const replayKinds = new Set([
    "operation_replay",
    "semantic_replay",
    "logical_authority_replay"
  ]);
  if (
    !row ||
    row.logical_action_digest !== request.logicalActionDigest ||
    !allowedOutcomes.has(row.outcome) ||
    !replayKinds.has(row.replay_kind) ||
    !row.request_payload ||
    typeof row.request_payload !== "object" ||
    Array.isArray(row.request_payload) ||
    sha256Hex(row.request_payload) !== row.request_digest ||
    row.request_payload.logicalActionDigest !== row.logical_action_digest ||
    row.request_payload.proposalDigest !== row.proposal_digest ||
    row.request_payload.runId !== row.run_id ||
    row.request_payload.incidentId !== row.incident_id ||
    row.request_payload.resourceId !== row.resource_id ||
    row.request_payload.agentId !== row.agent_id ||
    row.request_payload.agency !== row.agency ||
    row.request_payload.evidenceId !== row.evidence_id ||
    row.request_payload.selectedEvidenceId !==
      row.receipt_proposal_selected_evidence_id ||
    row.request_payload.selectedEvidenceDigest !==
      row.receipt_proposal_selected_evidence_digest ||
    row.evidence_id !== row.receipt_proposal_selected_evidence_id ||
    row.request_payload.effectKey !== row.effect_key ||
    row.request_payload.payloadDigest !== row.payload_digest ||
    row.request_payload.policyVersion !== row.policy_version
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  const logicalReplay = row.replay_kind === "logical_authority_replay";
  if (
    (!logicalReplay &&
      (row.request_digest !== request.requestDigest ||
        row.proposal_digest !== request.proposalDigest ||
        canonicalJson(row.request_payload) !==
          canonicalJson(request.requestPayload))) ||
    (row.replay_kind === "operation_replay" &&
      row.operation_id !== request.operationId) ||
    (logicalReplay && row.outcome !== "resource_reserved")
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  let identity;
  let receiptProposal;
  try {
    identity = authorityIdentityFor(
      { ...request, proposalDigest: row.proposal_digest },
      row.authorization_epoch
    );
    receiptProposal = normalizeReceiptProposal(row, request);
  } catch {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  if (
    row.logical_authority_key_sha256 !==
      identity.logicalAuthorityKeySha256 ||
    row.authorization_binding_sha256 !==
      identity.authorizationBindingSha256
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  const winning = row.outcome === "resource_reserved";
  const authorityCurrent = row.authority_current;
  const databaseNow = normalizeTimestamp(row.database_now);
  const reason = row.reason ?? null;
  const fencingToken =
    row.fencing_token === null || row.fencing_token === undefined
      ? null
      : String(row.fencing_token);
  const leaseExpiresAt = normalizeTimestamp(row.lease_expires_at);
  const resourceLeaseExpiresAt = normalizeTimestamp(
    row.resource_lease_expires_at
  );
  const receiptProposalExpiresAt = receiptProposal.expiresAt;
  const outboxFencingToken =
    row.outbox_fencing_token === null ||
    row.outbox_fencing_token === undefined
      ? null
      : String(row.outbox_fencing_token);
  const exactOutbox =
    row.outbox_intent_id &&
    row.outbox_operation_id === row.operation_id &&
    row.outbox_request_digest === row.request_digest &&
    row.outbox_proposal_digest === row.proposal_digest &&
    row.outbox_logical_action_digest === row.logical_action_digest &&
    String(row.outbox_authorization_epoch) ===
      String(row.authorization_epoch) &&
    row.outbox_logical_authority_key_sha256 ===
      row.logical_authority_key_sha256 &&
    row.outbox_authorization_binding_sha256 ===
      row.authorization_binding_sha256 &&
    row.outbox_run_id === row.run_id &&
    row.outbox_incident_id === row.incident_id &&
    row.outbox_resource_id === row.resource_id &&
    outboxFencingToken === fencingToken &&
    row.outbox_effect_key === row.effect_key &&
    row.outbox_intent_kind === "dispatch_rescue_unit" &&
    row.outbox_payload &&
    typeof row.outbox_payload === "object" &&
    !Array.isArray(row.outbox_payload) &&
    row.receipt_proposal_payload &&
    typeof row.receipt_proposal_payload === "object" &&
    !Array.isArray(row.receipt_proposal_payload) &&
    canonicalJson(row.outbox_payload) ===
      canonicalJson(row.receipt_proposal_payload) &&
    canonicalJson(row.outbox_payload) === canonicalJson(request.payload) &&
    sha256Hex(row.outbox_payload) === row.outbox_payload_digest &&
    row.outbox_payload_digest === row.payload_digest;
  const committedEvidenceDigestValid =
    /^[0-9a-f]{64}$/.test(row.evidence_digest ?? "");
  const selectedEvidenceMatches =
    row.evidence_digest === row.receipt_proposal_selected_evidence_digest;
  const selectedDigestMismatch =
    row.outcome === "authorization_denied" &&
    reason === "selected_evidence_digest_mismatch";
  const evidenceMissing =
    row.outcome === "authorization_denied" &&
      reason === "evidence_missing";
  const observedHolderOperationId =
    row.observed_holder_operation_id ?? null;
  const observedFence =
    row.observed_fence === null || row.observed_fence === undefined
      ? null
      : String(row.observed_fence);
  if (
    (winning &&
      (!exactOutbox ||
        reason !== null ||
        fencingToken === null ||
        !/^[1-9][0-9]*$/.test(fencingToken) ||
        leaseExpiresAt === null ||
        resourceLeaseExpiresAt === null ||
        receiptProposalExpiresAt === null ||
        (authorityCurrent &&
          (fencingToken !== String(row.current_fence) ||
            row.active_run_id !== row.run_id ||
            row.holder_operation_id !== row.operation_id ||
            row.holder_proposal_digest !== row.proposal_digest ||
            row.holder_logical_authority_key_sha256 !==
              identity.logicalAuthorityKeySha256)))) ||
    (!winning &&
      (row.outbox_intent_id ||
        typeof reason !== "string" ||
        reason.length === 0 ||
        fencingToken !== null ||
        leaseExpiresAt !== null)) ||
    (row.outcome === "resource_held_denied" &&
      (reason !== "active_holder" ||
        !selectedEvidenceMatches ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          observedHolderOperationId ?? ""
        ) ||
        !/^[1-9][0-9]*$/.test(observedFence ?? ""))) ||
    (row.outcome !== "resource_held_denied" &&
      (observedHolderOperationId !== null || observedFence !== null)) ||
    (winning && !selectedEvidenceMatches) ||
    (evidenceMissing && row.evidence_digest !== null) ||
    (selectedDigestMismatch &&
      (!committedEvidenceDigestValid || selectedEvidenceMatches)) ||
    (!evidenceMissing &&
      !selectedDigestMismatch &&
      !committedEvidenceDigestValid) ||
    typeof authorityCurrent !== "boolean" ||
    (!winning && authorityCurrent) ||
    databaseNow === null ||
    (authorityCurrent &&
      (new Date(leaseExpiresAt).getTime() <=
        new Date(databaseNow).getTime() ||
        new Date(resourceLeaseExpiresAt).getTime() <=
          new Date(databaseNow).getTime() ||
        new Date(receiptProposalExpiresAt).getTime() <=
          new Date(databaseNow).getTime()))
  ) {
    throw new Error("AUTHORITY_RECONCILIATION_REJECTED");
  }
  return {
    outcome: row.outcome,
    reason,
    fencingToken,
    leaseExpiresAt,
    authorityCurrent,
    databaseNow,
    replayKind:
      row.replay_kind === "operation_replay"
        ? "reconciled_after_ambiguous_commit"
        : row.replay_kind,
    committedOperationId: row.operation_id,
    committedRequestDigest: row.request_digest,
    committedProposalDigest: row.proposal_digest,
    committedSelectedEvidenceId: row.evidence_id,
    committedSelectedEvidenceDigest: row.evidence_digest,
    ...identity
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
      request.requestDigest,
      request.logicalActionDigest
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
    let clientClosed = false;
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
        await closeQuietly(client);
        clientClosed = true;
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
      if (!clientClosed) {
        await closeQuietly(client);
      }
    }
  }
  throw new Error("AUTHORITY_RETRY_EXHAUSTED");
}

function buildBindings(config, request = null) {
  const bindings = {
    sourceCommit: config.sourceCommit,
    configDigest: config.configDigest,
    treeDigest: config.treeDigest,
    packageLockDigest: config.packageLockDigest,
    authoritySourceDigest: config.authoritySourceDigest,
    authorityArtifactDigest: config.authorityArtifactDigest
  };
  if (request !== null) {
    bindings.proposalDigest = request.proposalDigest;
    bindings.logicalActionDigest = request.logicalActionDigest;
    bindings.selectedEvidenceDigest = request.selectedEvidenceDigest;
  }
  return bindings;
}

function failClosed(code, config = null, parsed = null, request = null) {
  return {
    schemaVersion: RESPONSE_SCHEMA,
    status: "UNKNOWN_DO_NOT_ACT",
    code,
    raceId: parsed?.raceId ?? null,
    contender: parsed?.contender ?? null,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    modelAccess: false,
    ...(config ? buildBindings(config, request) : {})
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

function telemetryText(value, maximum, fallback = "UNBOUND") {
  return typeof value === "string" && value.length > 0
    ? value.slice(0, maximum)
    : fallback;
}

function semanticFailureMetric(code, context, now = () => Date.now()) {
  return {
    _aws: {
      Timestamp: now(),
      CloudWatchMetrics: [
        {
          Namespace: "Tideproof/GateTwo",
          Dimensions: [["Deployment", "Service"]],
          Metrics: [{ Name: "SemanticFailures", Unit: "Count" }]
        }
      ]
    },
    Deployment: telemetryText(
      process.env.SEMANTIC_METRIC_DEPLOYMENT,
      255
    ),
    Service: "authority",
    SemanticFailures: 1,
    schemaVersion: "tideproof.aws-semantic-failure.v1",
    provider: "AWS_LAMBDA",
    status: "UNKNOWN_DO_NOT_ACT",
    code: telemetryText(code, 120, "AUTHORITY_UNAVAILABLE"),
    awsRequestId: telemetryText(context?.awsRequestId, 160, null),
    region: telemetryText(process.env.AWS_REGION, 32),
    functionName: telemetryText(
      process.env.AWS_LAMBDA_FUNCTION_NAME,
      64
    ),
    functionVersion: telemetryText(
      process.env.AWS_LAMBDA_FUNCTION_VERSION,
      12
    ),
    sourceCommit: telemetryText(process.env.SOURCE_COMMIT, 40),
    configDigest: telemetryText(process.env.CONFIG_DIGEST, 64),
    treeDigest: telemetryText(process.env.TREE_DIGEST, 40),
    artifactDigest: telemetryText(
      process.env.AUTHORITY_ARTIFACT_DIGEST,
      64
    )
  };
}

function emitSemanticFailure(code, context) {
  process.stdout.write(
    `${JSON.stringify(semanticFailureMetric(code, context))}\n`
  );
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
  let request;
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
          return new Client(
            databaseClientConfiguration(
              value,
              "tideproof-aws-authority-proof"
            )
          );
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
    request = authorityRequestFor(event, config);
    request.raceId = parsed.raceId;
    const connectionString = await getConnectionString(config);
    const clientFactory =
      createClient ??
      ((value) => {
        const { Client } = require("pg");
        return new Client(
          databaseClientConfiguration(
            value,
            "tideproof-aws-authority"
          )
        );
      });
    const result = await spendAuthority({
      connectionString,
      request,
      createClient: clientFactory,
      now
    });
    if (result.decision.durableReceipt === false) {
      return {
        schemaVersion: RESPONSE_SCHEMA,
        status: "DENIED_NOT_DURABLE",
        raceId: parsed.raceId,
        contender: parsed.contender,
        operationId: request.operationId,
        requestDigest: request.requestDigest,
        outcome: result.decision.outcome,
        reason: result.decision.reason,
        authorityCurrent: false,
        commit: databaseCommitResult(
          result.decision,
          request,
          "direct_ack"
        ),
        transaction: result.transaction,
        invocationRequestId:
          typeof context?.awsRequestId === "string"
            ? context.awsRequestId.slice(0, 160)
            : null,
        functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
        authorityTransferred: false,
        requiresFreshAuthorization: true,
        modelAccess: false,
        ...buildBindings(config, request)
      };
    }
    return {
      schemaVersion: RESPONSE_SCHEMA,
      status: "COMMITTED",
      raceId: parsed.raceId,
      contender: parsed.contender,
      operationId: request.operationId,
      requestDigest: request.requestDigest,
      committedOperationId: result.decision.committedOperationId,
      committedRequestDigest: result.decision.committedRequestDigest,
      outcome: result.decision.outcome,
      reason: result.decision.reason,
      fencingToken: result.decision.fencingToken,
      leaseExpiresAt: result.decision.leaseExpiresAt,
      replayKind: result.decision.replayKind,
      authorizationEpoch: result.decision.authorizationEpoch,
      logicalAuthorityKeySha256:
        result.decision.logicalAuthorityKeySha256,
      authorizationBindingSha256:
        result.decision.authorizationBindingSha256,
      committedProposalDigest:
        result.decision.committedProposalDigest,
      committedSelectedEvidenceId:
        result.decision.committedSelectedEvidenceId,
      committedSelectedEvidenceDigest:
        result.decision.committedSelectedEvidenceDigest,
      authorityCurrent: result.decision.authorityCurrent,
      commit: databaseCommitResult(
        result.decision,
        request,
        result.transaction.reconciled === true
          ? "read_reconciled"
          : "direct_ack"
      ),
      transaction: result.transaction,
      invocationRequestId:
        typeof context?.awsRequestId === "string"
          ? context.awsRequestId.slice(0, 160)
          : null,
      functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
      authorityTransferred: false,
      requiresFreshAuthorization: !result.decision.authorityCurrent,
      modelAccess: false,
      ...buildBindings(config, request)
    };
  } catch (error) {
    return failClosed(safeCode(error), config, parsed, request);
  }
}

async function handler(event, context) {
  const result = await runAuthority({ event, context });
  if (
    result?.status === "UNKNOWN_DO_NOT_ACT" &&
    result.code !== "STATUS_ONLY_NO_AUTHORIZATION"
  ) {
    emitSemanticFailure(result.code, context);
  }
  return result;
}

exports.handler = handler;
exports.__test = {
  AUTHORITY_NAMESPACE,
  DATABASE_TIMEOUTS,
  PROOF_RESPONSE_SCHEMA,
  PROOF_SQL,
  REQUEST_SCHEMA,
  RESPONSE_SCHEMA,
  SPEND_SQL,
  RESOLVE_SQL,
  authorityIdentityFor,
  authorityRequestFor,
  canonicalJson,
  configuration,
  connectionStringFromSecret,
  databaseCommitResult,
  databaseClientConfiguration,
  exactKeys,
  normalizeResolvedRow,
  normalizeProofRow,
  normalizeSpendRow,
  observeAuthorityRace,
  parseProofEvent,
  parseReserveEvent,
  runAuthority,
  safeCode,
  secretRequestFor,
  semanticFailureMetric,
  sha256Hex,
  spendValues,
  spendAuthority,
  uuidV5,
  validateConnectionString
};
