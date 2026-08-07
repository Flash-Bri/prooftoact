import { createHash, createPublicKey, verify } from "node:crypto";
import { Client, Pool } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import {
  bootstrapDatabaseConfig,
  databaseClientMustBeDiscarded,
  runtimeDatabaseConfig
} from "./database-runtime.js";
import {
  committedDatabaseResult,
  databaseTimestampFromDriver
} from "./database-commit-result.js";

const DEFAULT_DATABASE = "tideproof_recovery";
const QUERY_SESSION_TOKEN = "__RECOVERY_SESSION_ID__";
const QUERY_TENANT_TOKEN = "__TENANT_ID__";
const QUERY_SUBJECT_TOKEN = "__SUBJECT_BINDING_HASH__";
const QUERY_SOURCE_TOKEN = "__SOURCE_BINDING_DIGEST__";
const SAFE_BUNDLE_BYTES = 24_576;
export const RECOVERY_MAX_TTL_MS = 24 * 60 * 60 * 1_000;
export const RECOVERY_MAX_SOURCE_AGE_MS = 60 * 60 * 1_000;
export const RECOVERY_MAX_FUTURE_SKEW_MS = 60 * 1_000;
export const RECOVERY_SIGNATURE_ALGORITHM = "ecdsa-p256-sha256";
export const RECOVERY_PUBLISHER_VERSION = "tideproof-recovery-publisher-v2";

const RECOVERY_COLUMNS = [
  "tenant_id",
  "recovery_session_id",
  "subject_binding_hash",
  "schema_version",
  "snapshot_version",
  "source_cluster_id",
  "source_commit_ts",
  "source_digest",
  "bundle_digest",
  "policy_version",
  "publisher_key_id",
  "publisher_version",
  "signature_algorithm",
  "source_signature_base64",
  "signature_digest",
  "checkpoint_summary",
  "evidence_summary",
  "conflict_summary",
  "receipt_summary",
  "authority_transferred",
  "requires_fresh_authorization",
  "expires_at"
];

const RECOVERY_DATABASE_FRESHNESS_SQL = `
AND source_commit_ts >= statement_timestamp() - INTERVAL '1 hour'
AND source_commit_ts <= statement_timestamp() + INTERVAL '1 minute'
AND expires_at > statement_timestamp()
AND expires_at <= statement_timestamp() + INTERVAL '24 hours'
`.trim();

export const RECOVERY_QUERY_TEMPLATE = `
SELECT
  tenant_id,
  recovery_session_id,
  subject_binding_hash,
  schema_version,
  snapshot_version,
  source_cluster_id,
  source_commit_ts,
  source_digest,
  bundle_digest,
  policy_version,
  publisher_key_id,
  publisher_version,
  signature_algorithm,
  source_signature_base64,
  signature_digest,
  checkpoint_summary,
  evidence_summary,
  conflict_summary,
  receipt_summary,
  authority_transferred,
  requires_fresh_authorization,
  expires_at
FROM mcp_public.recovery_bundle_v2
WHERE recovery_session_id = '${QUERY_SESSION_TOKEN}'::UUID
  AND tenant_id = '${QUERY_TENANT_TOKEN}'::UUID
  AND subject_binding_hash = '${QUERY_SUBJECT_TOKEN}'
  AND source_digest = '${QUERY_SOURCE_TOKEN}'
  ${RECOVERY_DATABASE_FRESHNESS_SQL}
`.trim();

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`);
    return `{${entries.join(",")}}`;
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
  const text = requireText(value, name);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      text
    )
  ) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text.toLowerCase();
}

function requireSha256(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(text)) {
    throw new TypeError(`${name} must be a SHA-256 hex digest`);
  }
  return text;
}

function requirePositiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function requireNonNegativeInteger(value, name, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new TypeError(
      `${name} must be a non-negative safe integer no greater than ${maximum}`
    );
  }
  return value;
}

function requireBoolean(value, name) {
  if (typeof value !== "boolean") {
    throw new TypeError(`${name} must be a boolean`);
  }
  return value;
}

function requireBoundedText(value, name, maximum = 128) {
  const text = requireText(value, name);
  if (Buffer.byteLength(text, "utf8") > maximum) {
    throw new RangeError(`${name} exceeds ${maximum} bytes`);
  }
  return text;
}

function requireNullableBoundedText(value, name, maximum = 128) {
  if (value === null) {
    return null;
  }
  return requireBoundedText(value, name, maximum);
}

function requireEnum(value, name, allowed) {
  const text = requireBoundedText(value, name);
  if (!allowed.includes(text)) {
    throw new TypeError(`${name} must be one of ${allowed.join(", ")}`);
  }
  return text;
}

function requireTimestamp(value, name) {
  const text =
    value instanceof Date
      ? value.toISOString()
      : requireText(value, name);
  if (!Number.isFinite(Date.parse(text))) {
    throw new TypeError(`${name} must be an ISO-compatible timestamp`);
  }
  return new Date(text).toISOString();
}

function requireExactKeys(value, name, expectedKeys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new TypeError(`${name} has an unexpected shape`);
  }
}

export function recoverySourceBindingDigestFor(input) {
  requireExactKeys(input, "recoverySourceBinding", [
    "authorizationBindingSha256",
    "authorizationEpoch",
    "authorityEvidenceBindingSha256",
    "evidenceDigest",
    "incidentId",
    "logicalActionDigest",
    "logicalAuthorityKeySha256",
    "operationId",
    "outcome",
    "proposalDigest",
    "requestDigest",
    "resourceId",
    "runId",
    "selectedEvidenceBindingSha256",
    "tenantId"
  ]);
  return sha256(
    canonicalJson({
      schema: "tideproof.highwater-recovery-binding.v3",
      tenantId: requireUuid(input.tenantId, "recoverySourceBinding.tenantId"),
      runId: requireUuid(input.runId, "recoverySourceBinding.runId"),
      incidentId: requireUuid(
        input.incidentId,
        "recoverySourceBinding.incidentId"
      ),
      evidenceDigest: requireSha256(
        input.evidenceDigest,
        "recoverySourceBinding.evidenceDigest"
      ),
      resourceId: requireBoundedText(
        input.resourceId,
        "recoverySourceBinding.resourceId"
      ),
      operationId: requireUuid(
        input.operationId,
        "recoverySourceBinding.operationId"
      ),
      requestDigest: requireSha256(
        input.requestDigest,
        "recoverySourceBinding.requestDigest"
      ),
      proposalDigest: requireSha256(
        input.proposalDigest,
        "recoverySourceBinding.proposalDigest"
      ),
      logicalActionDigest: requireSha256(
        input.logicalActionDigest,
        "recoverySourceBinding.logicalActionDigest"
      ),
      authorizationEpoch: requirePositiveInteger(
        input.authorizationEpoch,
        "recoverySourceBinding.authorizationEpoch"
      ),
      logicalAuthorityKeySha256: requireSha256(
        input.logicalAuthorityKeySha256,
        "recoverySourceBinding.logicalAuthorityKeySha256"
      ),
      authorizationBindingSha256: requireSha256(
        input.authorizationBindingSha256,
        "recoverySourceBinding.authorizationBindingSha256"
      ),
      authorityEvidenceBindingSha256: requireSha256(
        input.authorityEvidenceBindingSha256,
        "recoverySourceBinding.authorityEvidenceBindingSha256"
      ),
      selectedEvidenceBindingSha256: requireSha256(
        input.selectedEvidenceBindingSha256,
        "recoverySourceBinding.selectedEvidenceBindingSha256"
      ),
      outcome: requireEnum(input.outcome, "recoverySourceBinding.outcome", [
        "resource_reserved",
        "resource_held_denied",
        "authorization_denied"
      ])
    })
  );
}

function requireCheckpointSummary(value) {
  requireExactKeys(value, "checkpointSummary", [
    "checkpointVersion",
    "failedAgent",
    "phase",
    "scenario"
  ]);
  return {
    checkpointVersion: requirePositiveInteger(
      value.checkpointVersion,
      "checkpointSummary.checkpointVersion"
    ),
    failedAgent: requireBoundedText(
      value.failedAgent,
      "checkpointSummary.failedAgent"
    ),
    phase: requireEnum(value.phase, "checkpointSummary.phase", [
      "successor-context-recovery"
    ]),
    scenario: requireEnum(value.scenario, "checkpointSummary.scenario", [
      "synthetic-highwater"
    ])
  };
}

function requireEvidenceSummary(value) {
  requireExactKeys(value, "evidenceSummary", [
    "admittedCount",
    "classification",
    "evidenceDigest"
  ]);
  return {
    admittedCount: requireNonNegativeInteger(
      value.admittedCount,
      "evidenceSummary.admittedCount",
      100
    ),
    classification: requireEnum(
      value.classification,
      "evidenceSummary.classification",
      ["synthetic"]
    ),
    evidenceDigest: requireSha256(
      value.evidenceDigest,
      "evidenceSummary.evidenceDigest"
    )
  };
}

function requireConflictSummary(value) {
  requireExactKeys(value, "conflictSummary", [
    "status",
    "unresolvedCount"
  ]);
  return {
    status: requireEnum(value.status, "conflictSummary.status", [
      "none",
      "quarantined",
      "resolved"
    ]),
    unresolvedCount: requireNonNegativeInteger(
      value.unresolvedCount,
      "conflictSummary.unresolvedCount",
      100
    )
  };
}

function requireReceiptSummary(value) {
  requireExactKeys(value, "receiptSummary", [
    "durableIntentPresent",
    "outcome",
    "reason",
    "resourceLabel"
  ]);
  return {
    durableIntentPresent: requireBoolean(
      value.durableIntentPresent,
      "receiptSummary.durableIntentPresent"
    ),
    outcome: requireEnum(value.outcome, "receiptSummary.outcome", [
      "resource_reserved",
      "resource_held_denied",
      "authorization_denied"
    ]),
    reason: requireNullableBoundedText(
      value.reason,
      "receiptSummary.reason"
    ),
    resourceLabel: requireBoundedText(
      value.resourceLabel,
      "receiptSummary.resourceLabel"
    )
  };
}

function requireBase64(value, name) {
  const text = requireText(value, name);
  const bytes = Buffer.from(text, "base64");
  if (
    bytes.length === 0 ||
    bytes.toString("base64") !== text
  ) {
    throw new TypeError(`${name} must be canonical base64`);
  }
  return { text, bytes };
}

function normalizeUnsignedBundle(input) {
  const normalized = {
    tenantId: requireUuid(input.tenantId, "tenantId"),
    recoverySessionId: requireUuid(
      input.recoverySessionId,
      "recoverySessionId"
    ),
    subjectBindingHash: requireSha256(
      input.subjectBindingHash,
      "subjectBindingHash"
    ),
    schemaVersion: requirePositiveInteger(
      input.schemaVersion ?? 2,
      "schemaVersion"
    ),
    snapshotVersion: requirePositiveInteger(
      input.snapshotVersion,
      "snapshotVersion"
    ),
    sourceClusterId: requireUuid(
      input.sourceClusterId,
      "sourceClusterId"
    ),
    sourceCommitTs: requireTimestamp(input.sourceCommitTs, "sourceCommitTs"),
    sourceDigest: requireSha256(input.sourceDigest, "sourceDigest"),
    policyVersion: requireBoundedText(
      input.policyVersion,
      "policyVersion"
    ),
    publisherKeyId: requireBoundedText(
      input.publisherKeyId,
      "publisherKeyId"
    ),
    publisherVersion: requireEnum(
      input.publisherVersion,
      "publisherVersion",
      [RECOVERY_PUBLISHER_VERSION]
    ),
    signatureAlgorithm: requireEnum(
      input.signatureAlgorithm,
      "signatureAlgorithm",
      [RECOVERY_SIGNATURE_ALGORITHM]
    ),
    checkpointSummary: requireCheckpointSummary(input.checkpointSummary),
    evidenceSummary: requireEvidenceSummary(input.evidenceSummary),
    conflictSummary: requireConflictSummary(input.conflictSummary),
    receiptSummary: requireReceiptSummary(input.receiptSummary),
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    expiresAt: requireTimestamp(input.expiresAt, "expiresAt")
  };
  if (normalized.schemaVersion !== 2) {
    throw new TypeError("schemaVersion must be 2");
  }
  const sourceMs = Date.parse(normalized.sourceCommitTs);
  const expiresMs = Date.parse(normalized.expiresAt);
  if (
    expiresMs <= sourceMs
  ) {
    throw new RangeError("expiresAt must be later than sourceCommitTs");
  }
  if (expiresMs - sourceMs > RECOVERY_MAX_TTL_MS) {
    throw new RangeError(
      `recovery bundle TTL exceeds ${RECOVERY_MAX_TTL_MS} milliseconds`
    );
  }
  const encoded = canonicalJson(normalized);
  if (Buffer.byteLength(encoded, "utf8") > SAFE_BUNDLE_BYTES) {
    throw new RangeError(`recovery bundle exceeds ${SAFE_BUNDLE_BYTES} bytes`);
  }
  return normalized;
}

function normalizeBundle(input) {
  const unsigned = normalizeUnsignedBundle(input);
  const bundleDigest = sha256(canonicalJson(unsigned));
  if (
    input.bundleDigest !== undefined &&
    requireSha256(input.bundleDigest, "bundleDigest") !== bundleDigest
  ) {
    throw new Error("RECOVERY_BUNDLE_DIGEST_MISMATCH");
  }
  const signature = requireBase64(
    input.sourceSignatureBase64,
    "sourceSignatureBase64"
  );
  const signatureDigest = sha256(signature.bytes);
  if (
    input.signatureDigest !== undefined &&
    requireSha256(input.signatureDigest, "signatureDigest") !== signatureDigest
  ) {
    throw new Error("RECOVERY_SIGNATURE_DIGEST_MISMATCH");
  }
  return {
    ...unsigned,
    bundleDigest,
    sourceSignatureBase64: signature.text,
    signatureDigest
  };
}

function validateBundleFreshness(bundle, now = new Date()) {
  const nowMs = now.getTime();
  const sourceMs = Date.parse(bundle.sourceCommitTs);
  const expiresMs = Date.parse(bundle.expiresAt);
  if (!Number.isFinite(nowMs)) {
    throw new TypeError("now must be a valid Date");
  }
  if (sourceMs > nowMs + RECOVERY_MAX_FUTURE_SKEW_MS) {
    throw new Error("RECOVERY_SOURCE_TIMESTAMP_IN_FUTURE");
  }
  if (nowMs - sourceMs > RECOVERY_MAX_SOURCE_AGE_MS) {
    throw new Error("RECOVERY_SOURCE_TOO_OLD");
  }
  if (expiresMs <= nowMs) {
    throw new Error("RECOVERY_BUNDLE_EXPIRED");
  }
  if (expiresMs - nowMs > RECOVERY_MAX_TTL_MS) {
    throw new Error("RECOVERY_EXPIRY_TOO_FAR");
  }
}

function publisherPublicKeyFor(trustedPublisherKeys, publisherKeyId) {
  const value =
    trustedPublisherKeys instanceof Map
      ? trustedPublisherKeys.get(publisherKeyId)
      : trustedPublisherKeys?.[publisherKeyId];
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error("RECOVERY_PUBLISHER_KEY_UNKNOWN");
  }
  const publicKey = createPublicKey({
    key: Buffer.from(value, "base64"),
    format: "der",
    type: "spki"
  });
  if (
    publicKey.asymmetricKeyType !== "ec" ||
    !["prime256v1", "P-256"].includes(
      publicKey.asymmetricKeyDetails?.namedCurve
    )
  ) {
    throw new Error("RECOVERY_PUBLISHER_KEY_INVALID");
  }
  return publicKey;
}

export function bundleDigestFor(input) {
  return sha256(canonicalJson(normalizeUnsignedBundle(input)));
}

export function normalizedRecoveryBundleFor(input) {
  return normalizeBundle(input);
}

export function recoverySignaturePayloadFor(input) {
  return `tideproof-recovery-bundle-v2\n${bundleDigestFor(input)}`;
}

function assertRecoveryBundleSourceSignature(
  normalized,
  trustedPublisherKeys
) {
  const publicKey = publisherPublicKeyFor(
    trustedPublisherKeys,
    normalized.publisherKeyId
  );
  const signatureValid = verify(
    "sha256",
    Buffer.from(recoverySignaturePayloadFor(normalized), "utf8"),
    publicKey,
    Buffer.from(normalized.sourceSignatureBase64, "base64")
  );
  if (!signatureValid) {
    throw new Error("RECOVERY_SIGNATURE_INVALID");
  }
}

export function verifyRecoveryBundleSourceSignature(
  input,
  trustedPublisherKeys
) {
  const normalized = normalizeBundle(input);
  assertRecoveryBundleSourceSignature(normalized, trustedPublisherKeys);
  return normalized;
}

export function recoveryQueryTemplateDigest() {
  return sha256(RECOVERY_QUERY_TEMPLATE);
}

export function renderRecoveryQuery({
  recoverySessionId,
  tenantId,
  subjectBindingHash,
  sourceDigest
}) {
  const sessionId = requireUuid(recoverySessionId, "recoverySessionId");
  const boundTenantId = requireUuid(tenantId, "tenantId");
  const boundSubjectHash = requireSha256(
    subjectBindingHash,
    "subjectBindingHash"
  );
  const boundSourceDigest = requireSha256(sourceDigest, "sourceDigest");
  return RECOVERY_QUERY_TEMPLATE.replace(QUERY_SESSION_TOKEN, sessionId)
    .replace(QUERY_TENANT_TOKEN, boundTenantId)
    .replace(QUERY_SUBJECT_TOKEN, boundSubjectHash)
    .replace(QUERY_SOURCE_TOKEN, boundSourceDigest);
}

export function recoveryQueryBindingsFor(query) {
  const text = requireText(query, "query");
  const match = text.match(
    /WHERE recovery_session_id = '([0-9a-f-]+)'::UUID\n  AND tenant_id = '([0-9a-f-]+)'::UUID\n  AND subject_binding_hash = '([a-f0-9]{64})'\n  AND source_digest = '([a-f0-9]{64})'/u
  );
  if (!match) {
    throw new Error("RECOVERY_QUERY_TEMPLATE_MISMATCH");
  }
  const bindings = {
    recoverySessionId: requireUuid(match[1], "recoverySessionId"),
    tenantId: requireUuid(match[2], "tenantId"),
    subjectBindingHash: requireSha256(match[3], "subjectBindingHash"),
    sourceDigest: requireSha256(match[4], "sourceDigest")
  };
  if (renderRecoveryQuery(bindings) !== text) {
    throw new Error("RECOVERY_QUERY_TEMPLATE_MISMATCH");
  }
  return bindings;
}

export function validateRecoveryRow(
  row,
  {
    recoverySessionId,
    tenantId,
    subjectBindingHash,
    sourceDigest,
    expectedSourceClusterId,
    trustedPublisherKeys
  },
  now = new Date()
) {
  if (!row || typeof row !== "object") {
    throw new TypeError("recovery query must return one object row");
  }
  const actualColumns = Object.keys(row).sort();
  const expectedColumns = [...RECOVERY_COLUMNS].sort();
  if (canonicalJson(actualColumns) !== canonicalJson(expectedColumns)) {
    throw new Error("RECOVERY_SCHEMA_MISMATCH");
  }
  const expectedSession = requireUuid(recoverySessionId, "recoverySessionId");
  const expectedTenant = requireUuid(tenantId, "tenantId");
  const expectedSubject = requireSha256(
    subjectBindingHash,
    "subjectBindingHash"
  );
  const expectedSourceDigest = requireSha256(sourceDigest, "sourceDigest");
  const expectedSourceCluster = requireUuid(
    expectedSourceClusterId,
    "expectedSourceClusterId"
  );
  if (row.recovery_session_id !== expectedSession) {
    throw new Error("RECOVERY_SESSION_MISMATCH");
  }
  if (row.tenant_id !== expectedTenant) {
    throw new Error("RECOVERY_TENANT_MISMATCH");
  }
  if (row.subject_binding_hash !== expectedSubject) {
    throw new Error("RECOVERY_SUBJECT_BINDING_MISMATCH");
  }
  if (row.source_digest !== expectedSourceDigest) {
    throw new Error("RECOVERY_SOURCE_BINDING_MISMATCH");
  }
  if (row.source_cluster_id !== expectedSourceCluster) {
    throw new Error("RECOVERY_SOURCE_CLUSTER_MISMATCH");
  }
  if (String(row.schema_version) !== "2") {
    throw new Error("RECOVERY_SCHEMA_VERSION_UNSUPPORTED");
  }
  if (
    row.authority_transferred !== false ||
    row.requires_fresh_authorization !== true
  ) {
    throw new Error("RECOVERY_AUTHORITY_INVARIANT_VIOLATION");
  }
  const normalized = normalizeBundle({
    tenantId: row.tenant_id,
    recoverySessionId: row.recovery_session_id,
    schemaVersion: Number(row.schema_version),
    snapshotVersion: Number(row.snapshot_version),
    subjectBindingHash: row.subject_binding_hash,
    sourceClusterId: row.source_cluster_id,
    sourceCommitTs: row.source_commit_ts,
    sourceDigest: row.source_digest,
    policyVersion: row.policy_version,
    publisherKeyId: row.publisher_key_id,
    publisherVersion: row.publisher_version,
    signatureAlgorithm: row.signature_algorithm,
    checkpointSummary: row.checkpoint_summary,
    evidenceSummary: row.evidence_summary,
    conflictSummary: row.conflict_summary,
    receiptSummary: row.receipt_summary,
    expiresAt: row.expires_at,
    bundleDigest: row.bundle_digest,
    sourceSignatureBase64: row.source_signature_base64,
    signatureDigest: row.signature_digest
  });
  validateBundleFreshness(normalized, now);
  assertRecoveryBundleSourceSignature(normalized, trustedPublisherKeys);
  return {
    status: "RECOVERED_CONTEXT_ONLY",
    recoverySessionId: expectedSession,
    tenantId: expectedTenant,
    subjectBindingHash: expectedSubject,
    sourceDigest: normalized.sourceDigest,
    bundleDigest: normalized.bundleDigest,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    row
  };
}

export class RecoveryBundleMismatchError extends Error {
  constructor() {
    super("Recovery session/snapshot was previously used with different input.");
    this.name = "RecoveryBundleMismatchError";
    this.code = "RECOVERY_BUNDLE_MISMATCH";
  }
}

export async function createRecoveryDatabase(
  connectionString,
  databaseName = DEFAULT_DATABASE
) {
  const pool = new Pool(bootstrapDatabaseConfig({
    connectionString,
    max: 1,
    applicationName: "tideproof-recovery-create"
  }));
  try {
    const safeName = requireText(databaseName, "databaseName");
    if (!/^[a-z][a-z0-9_]*$/.test(safeName)) {
      throw new TypeError("databaseName must be a safe lowercase identifier");
    }
    await pool.query(`CREATE DATABASE IF NOT EXISTS ${safeName}`);
  } finally {
    await pool.end();
  }
}

export class RecoveryStore {
  #connectionString;
  #pool;

  constructor({
    connectionString,
    databaseName = DEFAULT_DATABASE,
    maxConnections = 4
  } = {}) {
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#connectionString = connectionStringForDatabase(
      connectionString,
      databaseName
    );
    this.#pool = new Pool(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: maxConnections,
      idleTimeoutMillis: 10_000,
      applicationName: "tideproof-recovery-runtime"
    }));
  }

  async close() {
    await this.#pool.end();
  }

  async #resolveBundle(bundle) {
    const client = new Client(runtimeDatabaseConfig({
      connectionString: this.#connectionString,
      max: 1,
      applicationName: "tideproof-recovery-store-reconcile"
    }));
    try {
      await client.connect();
      return await client.query(
        `
          SELECT *, transaction_timestamp() AS database_now
          FROM mcp_private.recovery_bundles_v2
          WHERE tenant_id = $1::UUID
            AND recovery_session_id = $2::UUID
            AND snapshot_version = $3::INT8
            AND bundle_digest = $4
        `,
        [
          bundle.tenantId,
          bundle.recoverySessionId,
          bundle.snapshotVersion,
          bundle.bundleDigest
        ]
      );
    } finally {
      await client.end().catch(() => {});
    }
  }

  #committedBundle(row, bundle, outcome, observation, databaseNow) {
    if (row?.bundle_digest !== bundle.bundleDigest) {
      throw new RecoveryBundleMismatchError();
    }
    return {
      outcome,
      row,
      commit: committedDatabaseResult({
        operation: "recovery_publication",
        operationDigest: bundle.bundleDigest,
        observation,
        databaseNow: databaseTimestampFromDriver(databaseNow),
        outcome: "bundle_present",
        authorityCurrent: null,
        requiresFreshAuthorization: true
      })
    };
  }

  async migrate() {
    const bootstrapPool = new Pool(bootstrapDatabaseConfig({
      connectionString: this.#connectionString,
      max: 1,
      applicationName: "tideproof-recovery-migrate"
    }));
    try {
    await bootstrapPool.query("CREATE SCHEMA IF NOT EXISTS mcp_private");
    await bootstrapPool.query("CREATE SCHEMA IF NOT EXISTS mcp_public");
    await bootstrapPool.query("CREATE SCHEMA IF NOT EXISTS mcp_api");
    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS mcp_private.recovery_bundles_v1 (
        recovery_session_id UUID NOT NULL,
        schema_version INT8 NOT NULL,
        snapshot_version INT8 NOT NULL,
        source_commit_ts TIMESTAMPTZ NOT NULL,
        source_digest STRING(64) NOT NULL,
        bundle_digest STRING(64) NOT NULL,
        policy_version STRING NOT NULL,
        checkpoint_summary JSONB NOT NULL,
        evidence_summary JSONB NOT NULL,
        conflict_summary JSONB NOT NULL,
        receipt_summary JSONB NOT NULL,
        authority_transferred BOOL NOT NULL DEFAULT false,
        requires_fresh_authorization BOOL NOT NULL DEFAULT true,
        expires_at TIMESTAMPTZ NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (recovery_session_id, snapshot_version),
        UNIQUE (bundle_digest),
        CHECK (schema_version = 1),
        CHECK (length(source_digest) = 64),
        CHECK (length(bundle_digest) = 64),
        CHECK (authority_transferred = false),
        CHECK (requires_fresh_authorization = true),
        CHECK (expires_at > source_commit_ts)
      )
    `);
    await bootstrapPool.query(`
      CREATE OR REPLACE VIEW mcp_public.recovery_bundle_v1 AS
      SELECT
        recovery_session_id,
        schema_version,
        snapshot_version,
        source_commit_ts,
        source_digest,
        bundle_digest,
        policy_version,
        checkpoint_summary,
        evidence_summary,
        conflict_summary,
        receipt_summary,
        authority_transferred,
        requires_fresh_authorization,
        expires_at
      FROM mcp_private.recovery_bundles_v1
    `);
    await bootstrapPool.query(`
      CREATE TABLE IF NOT EXISTS mcp_private.recovery_bundles_v2 (
        tenant_id UUID NOT NULL,
        recovery_session_id UUID NOT NULL,
        subject_binding_hash STRING(64) NOT NULL,
        schema_version INT8 NOT NULL,
        snapshot_version INT8 NOT NULL,
        source_cluster_id UUID NOT NULL,
        source_commit_ts TIMESTAMPTZ NOT NULL,
        source_digest STRING(64) NOT NULL,
        bundle_digest STRING(64) NOT NULL,
        policy_version STRING NOT NULL,
        publisher_key_id STRING NOT NULL,
        publisher_version STRING NOT NULL,
        signature_algorithm STRING NOT NULL,
        source_signature_base64 STRING NOT NULL,
        signature_digest STRING(64) NOT NULL,
        checkpoint_summary JSONB NOT NULL,
        evidence_summary JSONB NOT NULL,
        conflict_summary JSONB NOT NULL,
        receipt_summary JSONB NOT NULL,
        authority_transferred BOOL NOT NULL DEFAULT false,
        requires_fresh_authorization BOOL NOT NULL DEFAULT true,
        expires_at TIMESTAMPTZ NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, recovery_session_id, snapshot_version),
        UNIQUE (bundle_digest),
        CHECK (length(subject_binding_hash) = 64),
        CHECK (schema_version = 2),
        CHECK (length(source_digest) = 64),
        CHECK (length(bundle_digest) = 64),
        CHECK (length(signature_digest) = 64),
        CHECK (publisher_version = '${RECOVERY_PUBLISHER_VERSION}'),
        CHECK (signature_algorithm = '${RECOVERY_SIGNATURE_ALGORITHM}'),
        CHECK (length(source_signature_base64) BETWEEN 32 AND 1024),
        CHECK (authority_transferred = false),
        CHECK (requires_fresh_authorization = true),
        CHECK (expires_at > source_commit_ts),
        CHECK (
          expires_at <= source_commit_ts + INTERVAL '24 hours'
        )
      )
    `);
    await bootstrapPool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_recovery_bundle_v2_broker_lookup_uidx
      ON mcp_private.recovery_bundles_v2 (
        tenant_id,
        recovery_session_id,
        subject_binding_hash,
        source_digest
      )
    `);
    await bootstrapPool.query(`
      CREATE OR REPLACE VIEW mcp_public.recovery_bundle_v2 AS
      SELECT
        tenant_id,
        recovery_session_id,
        subject_binding_hash,
        schema_version,
        snapshot_version,
        source_cluster_id,
        source_commit_ts,
        source_digest,
        bundle_digest,
        policy_version,
        publisher_key_id,
        publisher_version,
        signature_algorithm,
        source_signature_base64,
        signature_digest,
        checkpoint_summary,
        evidence_summary,
        conflict_summary,
        receipt_summary,
        authority_transferred,
        requires_fresh_authorization,
        expires_at
      FROM mcp_private.recovery_bundles_v2
    `);
    } finally {
      await bootstrapPool.end().catch(() => {});
    }
  }

  async appendBundle(input) {
    const bundle = normalizeBundle(input);
    validateBundleFreshness(bundle);
    const client = await this.#pool.connect();
    let releaseError;
    let discardClient = false;
    let commitDispatched = false;
    let clientReleased = false;
    try {
      await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
      const existing = await client.query(
        `
          SELECT *
          FROM mcp_private.recovery_bundles_v2
          WHERE (
            tenant_id = $1::UUID
            AND recovery_session_id = $2::UUID
            AND snapshot_version = $3::INT8
          )
          OR bundle_digest = $4
          OR (
            tenant_id = $1::UUID
            AND recovery_session_id = $2::UUID
            AND subject_binding_hash = $5
            AND source_digest = $6
          )
          ORDER BY recorded_at
          LIMIT 2
        `,
        [
          bundle.tenantId,
          bundle.recoverySessionId,
          bundle.snapshotVersion,
          bundle.bundleDigest,
          bundle.subjectBindingHash,
          bundle.sourceDigest
        ]
      );
      if (existing.rowCount > 1) {
        throw new RecoveryBundleMismatchError();
      }
      if (existing.rowCount === 1) {
        if (existing.rows[0].bundle_digest !== bundle.bundleDigest) {
          throw new RecoveryBundleMismatchError();
        }
        const clock = await client.query(
          "SELECT transaction_timestamp() AS database_now"
        );
        commitDispatched = true;
        await client.query("COMMIT");
        return this.#committedBundle(
          existing.rows[0],
          bundle,
          "bundle_replay",
          "direct_ack",
          clock.rows[0].database_now
        );
      }
      const inserted = await client.query(
        `
          INSERT INTO mcp_private.recovery_bundles_v2 (
            tenant_id,
            recovery_session_id,
            subject_binding_hash,
            schema_version,
            snapshot_version,
            source_cluster_id,
            source_commit_ts,
            source_digest,
            bundle_digest,
            policy_version,
            publisher_key_id,
            publisher_version,
            signature_algorithm,
            source_signature_base64,
            signature_digest,
            checkpoint_summary,
            evidence_summary,
            conflict_summary,
            receipt_summary,
            authority_transferred,
            requires_fresh_authorization,
            expires_at
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3,
            $4::INT8,
            $5::INT8,
            $6::UUID,
            $7::TIMESTAMPTZ,
            $8,
            $9,
            $10,
            $11,
            $12,
            $13,
            $14,
            $15,
            $16::JSONB,
            $17::JSONB,
            $18::JSONB,
            $19::JSONB,
            false,
            true,
            $20::TIMESTAMPTZ
          )
          RETURNING *
        `,
        [
          bundle.tenantId,
          bundle.recoverySessionId,
          bundle.subjectBindingHash,
          bundle.schemaVersion,
          bundle.snapshotVersion,
          bundle.sourceClusterId,
          bundle.sourceCommitTs,
          bundle.sourceDigest,
          bundle.bundleDigest,
          bundle.policyVersion,
          bundle.publisherKeyId,
          bundle.publisherVersion,
          bundle.signatureAlgorithm,
          bundle.sourceSignatureBase64,
          bundle.signatureDigest,
          JSON.stringify(bundle.checkpointSummary),
          JSON.stringify(bundle.evidenceSummary),
          JSON.stringify(bundle.conflictSummary),
          JSON.stringify(bundle.receiptSummary),
          bundle.expiresAt
        ]
      );
      const clock = await client.query(
        "SELECT transaction_timestamp() AS database_now"
      );
      commitDispatched = true;
      await client.query("COMMIT");
      return this.#committedBundle(
        inserted.rows[0],
        bundle,
        "bundle_appended",
        "direct_ack",
        clock.rows[0].database_now
      );
    } catch (error) {
      releaseError = error;
      const commitDefinitivelyAborted =
        commitDispatched && error?.code === "40001";
      discardClient =
        databaseClientMustBeDiscarded(error) ||
        (commitDispatched && !commitDefinitivelyAborted);
      if (commitDispatched && !commitDefinitivelyAborted) {
        client.release(releaseError);
        clientReleased = true;
        const resolved = await this.#resolveBundle(bundle);
        if (resolved.rowCount === 1) {
          return this.#committedBundle(
            resolved.rows[0],
            bundle,
            "bundle_present",
            "read_reconciled",
            resolved.rows[0].database_now
          );
        }
      }
      if (!discardClient) {
        try {
          await client.query("ROLLBACK");
        } catch (rollbackError) {
          releaseError = rollbackError;
          discardClient = true;
          throw new AggregateError(
            [error, rollbackError],
            "RECOVERY_STORE_ROLLBACK_FAILED"
          );
        }
      }
      throw error;
    } finally {
      if (!clientReleased) {
        client.release(discardClient ? releaseError : undefined);
      }
    }
  }

  async readExact({
    recoverySessionId,
    tenantId,
    subjectBindingHash,
    sourceDigest,
    expectedSourceClusterId,
    trustedPublisherKeys
  }) {
    const sessionId = requireUuid(recoverySessionId, "recoverySessionId");
    const boundTenantId = requireUuid(tenantId, "tenantId");
    const boundSubjectHash = requireSha256(
      subjectBindingHash,
      "subjectBindingHash"
    );
    const boundSourceDigest = requireSha256(sourceDigest, "sourceDigest");
    const result = await this.#pool.query(
      `
        SELECT
          tenant_id,
          recovery_session_id,
          subject_binding_hash,
          schema_version,
          snapshot_version,
          source_cluster_id,
          source_commit_ts,
          source_digest,
          bundle_digest,
          policy_version,
          publisher_key_id,
          publisher_version,
          signature_algorithm,
          source_signature_base64,
          signature_digest,
          checkpoint_summary,
          evidence_summary,
          conflict_summary,
          receipt_summary,
          authority_transferred,
          requires_fresh_authorization,
          expires_at
        FROM mcp_public.recovery_bundle_v2
        WHERE recovery_session_id = $1::UUID
          AND tenant_id = $2::UUID
          AND subject_binding_hash = $3
          AND source_digest = $4
          ${RECOVERY_DATABASE_FRESHNESS_SQL}
      `,
      [sessionId, boundTenantId, boundSubjectHash, boundSourceDigest]
    );
    if (result.rowCount !== 1) {
      return {
        status: "UNKNOWN_DO_NOT_ACT",
        reason: "recovery_bundle_not_available",
        recoverySessionId: sessionId
      };
    }
    return validateRecoveryRow(
      result.rows[0],
      {
        recoverySessionId: sessionId,
        tenantId: boundTenantId,
        subjectBindingHash: boundSubjectHash,
        sourceDigest: boundSourceDigest,
        expectedSourceClusterId,
        trustedPublisherKeys
      }
    );
  }
}
