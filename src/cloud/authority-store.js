import {
  createHash,
  createPublicKey,
  verify as verifySignature
} from "node:crypto";
import { Client, Pool } from "pg";

const RETRYABLE_TRANSACTION_CODE = "40001";
const AMBIGUOUS_TRANSACTION_CODE = "40003";
const DEFAULT_MAX_RETRIES = 20;
const DEFAULT_RETRY_DEADLINE_MS = 30_000;
const MIN_LEASE_MS = 1_000;
const MAX_LEASE_MS = 10 * 60_000;
const POLICY_VERSION = "gate1-policy-v2";
const ACTION_KIND = "dispatch_rescue_unit";

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
    throw new TypeError(`${name} must be a lowercase SHA-256 hex digest`);
  }
  return text;
}

function requireLeaseMs(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_LEASE_MS ||
    value > MAX_LEASE_MS
  ) {
    throw new RangeError(
      `leaseMs must be an integer from ${MIN_LEASE_MS} through ${MAX_LEASE_MS}`
    );
  }
  return value;
}

function requireTimestamp(value, name) {
  const text = requireText(value, name);
  if (!Number.isFinite(Date.parse(text))) {
    throw new TypeError(`${name} must be an ISO-compatible timestamp`);
  }
  return new Date(text).toISOString();
}

function requireEmbedding(value) {
  if (
    !Array.isArray(value) ||
    value.length !== 3 ||
    value.some((entry) => !Number.isFinite(entry))
  ) {
    throw new TypeError("embedding must contain exactly three finite numbers");
  }
  return `[${value.join(",")}]`;
}

function requireBase64(value, name) {
  const text = requireText(value, name);
  const bytes = Buffer.from(text, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== text) {
    throw new TypeError(`${name} must be canonical base64`);
  }
  return { text, bytes };
}

function requireJsonObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${name} must be a JSON object`);
  }
  const seen = new WeakSet();
  const inspect = (nested, path) => {
    if (
      nested === undefined ||
      typeof nested === "function" ||
      typeof nested === "symbol" ||
      typeof nested === "bigint"
    ) {
      throw new TypeError(`${path} is not JSON-safe`);
    }
    if (typeof nested === "number" && !Number.isFinite(nested)) {
      throw new TypeError(`${path} must be finite`);
    }
    if (!nested || typeof nested !== "object") {
      return;
    }
    if (seen.has(nested)) {
      throw new TypeError(`${path} must not contain a cycle`);
    }
    seen.add(nested);
    if (Array.isArray(nested)) {
      nested.forEach((entry, index) => inspect(entry, `${path}[${index}]`));
    } else {
      Object.entries(nested).forEach(([key, entry]) =>
        inspect(entry, `${path}.${key}`)
      );
    }
    seen.delete(nested);
  };
  inspect(value, name);
  return JSON.parse(JSON.stringify(value));
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(
        ([key, nested]) =>
          `${JSON.stringify(key)}:${canonicalJson(nested)}`
      );
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function connectionStringForDatabase(connectionString, databaseName) {
  const database = requireText(databaseName, "databaseName");
  const url = new URL(connectionString);
  url.pathname = `/${database}`;
  return url.toString();
}

function normalizeRequest(input) {
  if (
    input.at !== undefined ||
    input.authorizationTime !== undefined ||
    input.clientNow !== undefined ||
    input.now !== undefined ||
    input.leaseExpiresAt !== undefined
  ) {
    throw new TypeError(
      "authorization and lease time are database-controlled"
    );
  }
  const payload = requireJsonObject(
    input.payload ?? {
      scenario: "synthetic-highwater",
      action: ACTION_KIND
    },
    "payload"
  );
  const normalized = {
    digestVersion: 1,
    tenantId: requireUuid(input.tenantId, "tenantId"),
    runId: requireUuid(input.runId, "runId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    resourceId: requireText(input.resourceId, "resourceId"),
    operationId: requireUuid(input.operationId, "operationId"),
    agentId: requireText(input.agentId, "agentId"),
    agency: requireText(input.agency, "agency"),
    evidenceId: requireUuid(input.evidenceId, "evidenceId"),
    intentNonce: requireUuid(input.intentNonce, "intentNonce"),
    effectKey: requireUuid(input.effectKey, "effectKey"),
    leaseMs: requireLeaseMs(input.leaseMs ?? 300_000),
    policyVersion: POLICY_VERSION,
    actionKind: ACTION_KIND,
    payload,
    payloadDigest: sha256(canonicalJson(payload))
  };
  const semanticPayload = {
    digestVersion: normalized.digestVersion,
    tenantId: normalized.tenantId,
    runId: normalized.runId,
    incidentId: normalized.incidentId,
    resourceId: normalized.resourceId,
    agentId: normalized.agentId,
    agency: normalized.agency,
    evidenceId: normalized.evidenceId,
    intentNonce: normalized.intentNonce,
    effectKey: normalized.effectKey,
    leaseMs: normalized.leaseMs,
    policyVersion: normalized.policyVersion,
    actionKind: normalized.actionKind,
    payloadDigest: normalized.payloadDigest
  };
  return {
    ...normalized,
    requestPayload: semanticPayload,
    requestDigest: sha256(canonicalJson(semanticPayload))
  };
}

export function requestDigestFor(input) {
  return normalizeRequest(input).requestDigest;
}

export function normalizedAuthorityRequestFor(input) {
  return normalizeRequest(input);
}

export function isRetryableTransactionError(error) {
  return error?.code === RETRYABLE_TRANSACTION_CODE;
}

export function isAmbiguousTransactionError(error) {
  return error?.code === AMBIGUOUS_TRANSACTION_CODE;
}

function isTransportError(error) {
  return (
    ["ECONNRESET", "EPIPE", "ETIMEDOUT", "57P01", "57P02", "57P03"].includes(
      error?.code
    ) ||
    /connection (?:terminated|closed|lost)|socket|timeout/i.test(
      error?.message ?? ""
    )
  );
}

function evidenceDigestFor(row) {
  return sha256(
    canonicalJson({
      tenantId: row.tenant_id,
      evidenceId: row.evidence_id,
      incidentId: row.incident_id,
      issuer: row.issuer,
      agencyScope: row.agency_scope,
      claimKey: row.claim_key,
      claimValue: row.claim_value,
      verificationKeyId: row.verification_key_id,
      verifierVersion: row.verifier_version,
      signedPayloadDigest: row.signed_payload_digest,
      signatureDigest: row.signature_digest,
      observedAt: new Date(row.observed_at).toISOString(),
      validFrom: new Date(row.valid_from).toISOString(),
      validUntil: new Date(row.valid_until).toISOString(),
      provenanceStatus: row.provenance_status,
      conflictStatus: row.conflict_status,
      assertion: row.assertion,
      embedding: row.embedding
    })
  );
}

function normalizeEvidence(input) {
  return {
    tenantId: requireUuid(input.tenantId, "tenantId"),
    evidenceId: requireUuid(input.evidenceId, "evidenceId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    issuer: requireText(input.issuer, "issuer"),
    agencyScope: requireText(input.agencyScope, "agencyScope"),
    claimKey: requireText(input.claimKey, "claimKey"),
    claimValue: requireText(input.claimValue, "claimValue"),
    observedAt: requireTimestamp(input.observedAt, "observedAt"),
    validFrom: requireTimestamp(input.validFrom, "validFrom"),
    validUntil: requireTimestamp(input.validUntil, "validUntil"),
    conflictStatus: requireText(input.conflictStatus, "conflictStatus"),
    assertion: requireText(input.assertion, "assertion"),
    embedding: requireEmbedding(input.embedding)
  };
}

function signedEvidencePayloadFromNormalized(evidence) {
  return canonicalJson({
    digestVersion: 1,
    tenantId: evidence.tenantId,
    evidenceId: evidence.evidenceId,
    incidentId: evidence.incidentId,
    issuer: evidence.issuer,
    agencyScope: evidence.agencyScope,
    claimKey: evidence.claimKey,
    claimValue: evidence.claimValue,
    observedAt: evidence.observedAt,
    validFrom: evidence.validFrom,
    validUntil: evidence.validUntil,
    conflictStatus: evidence.conflictStatus,
    assertion: evidence.assertion,
    embedding: evidence.embedding
  });
}

export function signedEvidencePayloadFor(input) {
  return signedEvidencePayloadFromNormalized(normalizeEvidence(input));
}

export function signedEvidenceDigestFor(input) {
  return sha256(signedEvidencePayloadFor(input));
}

export function signedEvidenceEnvelopeFor(input) {
  const evidence = normalizeEvidence(input);
  const verificationKeyId = requireText(
    input.verificationKeyId,
    "verificationKeyId"
  );
  const verifierVersion = requireText(
    input.verifierVersion,
    "verifierVersion"
  );
  const signature = requireBase64(input.signatureBase64, "signatureBase64");
  const signedPayload = signedEvidencePayloadFromNormalized(evidence);
  const signedPayloadDigest = sha256(signedPayload);
  const signatureDigest = sha256(signature.bytes);
  const verificationRequestDigest = sha256(
    canonicalJson({
      digestVersion: 1,
      tenantId: evidence.tenantId,
      evidenceId: evidence.evidenceId,
      verificationKeyId,
      verifierVersion,
      signedPayloadDigest,
      signatureDigest
    })
  );
  const evidenceDigest = evidenceDigestFor({
    tenant_id: evidence.tenantId,
    evidence_id: evidence.evidenceId,
    incident_id: evidence.incidentId,
    issuer: evidence.issuer,
    agency_scope: evidence.agencyScope,
    claim_key: evidence.claimKey,
    claim_value: evidence.claimValue,
    verification_key_id: verificationKeyId,
    verifier_version: verifierVersion,
    signed_payload_digest: signedPayloadDigest,
    signature_digest: signatureDigest,
    observed_at: evidence.observedAt,
    valid_from: evidence.validFrom,
    valid_until: evidence.validUntil,
    provenance_status: "verified",
    conflict_status: evidence.conflictStatus,
    assertion: evidence.assertion,
    embedding: evidence.embedding
  });
  return {
    ...evidence,
    verificationKeyId,
    verifierVersion,
    signatureBase64: signature.text,
    signatureBytes: signature.bytes,
    signedPayload,
    signedPayloadDigest,
    signatureDigest,
    verificationRequestDigest,
    evidenceDigest
  };
}

function backoffMs(attempt) {
  const ceiling = Math.min(1_000, 25 * 2 ** attempt);
  return Math.floor(Math.random() * (ceiling + 1));
}

async function rollbackQuietly(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Broken or already-resolved sessions may not accept ROLLBACK.
  }
}

function observeCommitDispatch(client, observer) {
  if (typeof observer !== "function") {
    return () => {};
  }
  const stream = client.connection?.stream;
  if (!stream || typeof stream.write !== "function") {
    throw new InvariantViolationError(
      "pg connection stream is unavailable for COMMIT dispatch observation"
    );
  }
  const originalWrite = stream.write;
  let observed = false;
  stream.write = function observedWrite(chunk, encoding, callback) {
    const bytes = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk, typeof encoding === "string" ? encoding : undefined);
    const isCommit = bytes.includes(Buffer.from("COMMIT\u0000"));
    if (!isCommit) {
      return originalWrite.apply(this, arguments);
    }

    const suppliedCallback =
      typeof encoding === "function" ? encoding : callback;
    const wrappedCallback = (...callbackArguments) => {
      suppliedCallback?.(...callbackArguments);
      if (!observed) {
        observed = true;
        observer();
      }
    };
    if (typeof encoding === "function" || encoding === undefined) {
      return originalWrite.call(this, chunk, wrappedCallback);
    }
    return originalWrite.call(this, chunk, encoding, wrappedCallback);
  };
  return () => {
    stream.write = originalWrite;
  };
}

export class AmbiguousCommitError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = "AmbiguousCommitError";
    this.code = "AMBIGUOUS_COMMIT";
  }
}

export class OperationDigestMismatchError extends Error {
  constructor(operationId) {
    super(`Operation ${operationId} was previously used with different input.`);
    this.name = "OperationDigestMismatchError";
    this.code = "OPERATION_DIGEST_MISMATCH";
  }
}

export class InvariantViolationError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvariantViolationError";
    this.code = "INVARIANT_VIOLATION";
  }
}

export class EffectKeyMismatchError extends Error {
  constructor(effectKey) {
    super(`Effect key ${effectKey} was previously used with different input.`);
    this.name = "EffectKeyMismatchError";
    this.code = "EFFECT_KEY_MISMATCH";
  }
}

export class EvidenceVerificationMismatchError extends Error {
  constructor(evidenceId) {
    super(
      `Evidence ${evidenceId} was previously verified with different input.`
    );
    this.name = "EvidenceVerificationMismatchError";
    this.code = "EVIDENCE_VERIFICATION_MISMATCH";
  }
}

export class AuthorityStore {
  #connectionString;
  #pool;

  constructor({
    connectionString,
    databaseName = "tideproof",
    maxConnections = 64
  } = {}) {
    if (!connectionString) {
      throw new Error("connectionString is required");
    }
    this.#connectionString = connectionStringForDatabase(
      connectionString,
      databaseName
    );
    this.#pool = new Pool({
      connectionString: this.#connectionString,
      max: maxConnections,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 20_000
    });
  }

  async close() {
    await this.#pool.end();
  }

  async migrate() {
    await this.#pool.query("CREATE SCHEMA IF NOT EXISTS tp_private");
    await this.#pool.query("CREATE SCHEMA IF NOT EXISTS tp_ledger");
    await this.#pool.query("CREATE SCHEMA IF NOT EXISTS tp_api");

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_evidence (
        tenant_id UUID NOT NULL,
        evidence_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        issuer STRING NOT NULL,
        agency_scope STRING NOT NULL,
        claim_key STRING NULL,
        claim_value STRING NULL,
        verification_key_id STRING NULL,
        verifier_version STRING NULL,
        signed_payload_digest STRING(64) NULL,
        signature_digest STRING(64) NULL,
        evidence_digest STRING(64) NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL,
        valid_until TIMESTAMPTZ NOT NULL,
        provenance_status STRING NOT NULL,
        conflict_status STRING NOT NULL,
        assertion STRING NOT NULL,
        embedding VECTOR(3) NOT NULL,
        ingested_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, evidence_id),
        CHECK (valid_until > valid_from),
        CHECK (provenance_status IN ('verified', 'invalid', 'revoked')),
        CHECK (conflict_status IN ('none', 'unresolved', 'resolved')),
        CHECK (
          signed_payload_digest IS NULL
          OR length(signed_payload_digest) = 64
        ),
        CHECK (signature_digest IS NULL OR length(signature_digest) = 64),
        CHECK (evidence_digest IS NULL OR length(evidence_digest) = 64)
      )
    `);
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS claim_key STRING NULL"
    );
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS claim_value STRING NULL"
    );
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS verification_key_id STRING NULL"
    );
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS verifier_version STRING NULL"
    );
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS signed_payload_digest STRING(64) NULL"
    );
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS signature_digest STRING(64) NULL"
    );
    await this.#pool.query(
      "ALTER TABLE tp_private.g1_evidence ADD COLUMN IF NOT EXISTS evidence_digest STRING(64) NULL"
    );

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_verification_keys (
        tenant_id UUID NOT NULL,
        verification_key_id STRING NOT NULL,
        issuer STRING NOT NULL,
        algorithm STRING NOT NULL,
        public_key_spki_base64 STRING NOT NULL,
        public_key_digest STRING(64) NOT NULL,
        status STRING NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL,
        valid_until TIMESTAMPTZ NOT NULL,
        registered_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        revoked_at TIMESTAMPTZ NULL,
        PRIMARY KEY (tenant_id, verification_key_id),
        CHECK (algorithm = 'ed25519'),
        CHECK (length(public_key_digest) = 64),
        CHECK (status IN ('active', 'revoked')),
        CHECK (valid_until > valid_from),
        CHECK (
          (status = 'active' AND revoked_at IS NULL)
          OR (status = 'revoked' AND revoked_at IS NOT NULL)
        )
      )
    `);

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_evidence_verification_receipts (
        tenant_id UUID NOT NULL,
        evidence_id UUID NOT NULL,
        verification_request_digest STRING(64) NOT NULL,
        incident_id UUID NOT NULL,
        issuer STRING NOT NULL,
        verification_key_id STRING NOT NULL,
        verifier_version STRING NOT NULL,
        signed_payload_digest STRING(64) NOT NULL,
        signature_digest STRING(64) NOT NULL,
        public_key_digest STRING(64) NULL,
        outcome STRING NOT NULL,
        reason STRING NULL,
        verified_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, evidence_id),
        UNIQUE (tenant_id, verification_request_digest),
        CHECK (length(verification_request_digest) = 64),
        CHECK (length(signed_payload_digest) = 64),
        CHECK (length(signature_digest) = 64),
        CHECK (
          public_key_digest IS NULL
          OR length(public_key_digest) = 64
        ),
        CHECK (outcome IN ('verified', 'rejected')),
        CHECK (
          (outcome = 'verified' AND reason IS NULL
            AND public_key_digest IS NOT NULL)
          OR (outcome = 'rejected' AND reason IS NOT NULL)
        )
      )
    `);

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_resources (
        tenant_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        current_fence INT8 NOT NULL DEFAULT 0,
        active_run_id UUID NOT NULL,
        holder_incident_id UUID NULL,
        holder_operation_id UUID NULL,
        holder_agent_id STRING NULL,
        lease_expires_at TIMESTAMPTZ NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, resource_id),
        CHECK (current_fence >= 0),
        CHECK (
          (
            holder_incident_id IS NULL
            AND holder_operation_id IS NULL
            AND holder_agent_id IS NULL
            AND lease_expires_at IS NULL
          )
          OR
          (
            holder_incident_id IS NOT NULL
            AND holder_operation_id IS NOT NULL
            AND holder_agent_id IS NOT NULL
            AND lease_expires_at IS NOT NULL
          )
        )
      )
    `);

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_private.g1_retry_probes (
        tenant_id UUID NOT NULL,
        probe_id UUID NOT NULL,
        value INT8 NOT NULL,
        PRIMARY KEY (tenant_id, probe_id),
        CHECK (value >= 0)
      )
    `);

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_authority_receipts (
        tenant_id UUID NOT NULL,
        operation_id UUID NOT NULL,
        request_digest STRING(64) NOT NULL,
        request_payload JSONB NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        agent_id STRING NOT NULL,
        agency STRING NOT NULL,
        evidence_id UUID NOT NULL,
        evidence_digest STRING(64) NULL,
        effect_key UUID NOT NULL,
        payload_digest STRING(64) NOT NULL,
        policy_version STRING NOT NULL,
        outcome STRING NOT NULL,
        reason STRING NULL,
        fencing_token INT8 NULL,
        observed_holder_operation_id UUID NULL,
        observed_fence INT8 NULL,
        lease_expires_at TIMESTAMPTZ NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, operation_id),
        UNIQUE (tenant_id, request_digest),
        CHECK (outcome IN (
          'pending',
          'resource_reserved',
          'resource_held_denied',
          'authorization_denied'
        )),
        CHECK (
          (
            outcome = 'resource_reserved'
            AND evidence_digest IS NOT NULL
            AND fencing_token IS NOT NULL
            AND fencing_token > 0
            AND lease_expires_at IS NOT NULL
          )
          OR outcome <> 'resource_reserved'
        )
      )
    `);

    await this.#pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS g1_unique_winning_fence
      ON tp_ledger.g1_authority_receipts (
        tenant_id,
        resource_id,
        fencing_token
      )
      WHERE outcome = 'resource_reserved'
    `);

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_outbox_intents (
        tenant_id UUID NOT NULL,
        intent_id UUID NOT NULL DEFAULT gen_random_uuid(),
        operation_id UUID NOT NULL,
        request_digest STRING(64) NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        fencing_token INT8 NOT NULL,
        effect_key UUID NOT NULL,
        intent_kind STRING NOT NULL,
        payload JSONB NOT NULL,
        payload_digest STRING(64) NOT NULL,
        state STRING NOT NULL DEFAULT 'pending',
        created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, intent_id),
        UNIQUE (tenant_id, operation_id),
        UNIQUE (tenant_id, effect_key),
        CHECK (fencing_token > 0),
        CHECK (intent_kind = 'dispatch_rescue_unit'),
        CHECK (state IN ('pending', 'delivering', 'delivered', 'failed'))
      )
    `);

    await this.#pool.query(`
      CREATE TABLE IF NOT EXISTS tp_ledger.g1_protected_effects (
        tenant_id UUID NOT NULL,
        effect_key UUID NOT NULL,
        operation_id UUID NOT NULL,
        request_digest STRING(64) NOT NULL,
        run_id UUID NOT NULL,
        incident_id UUID NOT NULL,
        resource_id STRING NOT NULL,
        agent_id STRING NOT NULL,
        fencing_token INT8 NOT NULL,
        payload_digest STRING(64) NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
        PRIMARY KEY (tenant_id, effect_key),
        UNIQUE (tenant_id, operation_id),
        CHECK (fencing_token > 0)
      )
    `);

    await this.#pool.query(`
      CREATE VIEW IF NOT EXISTS tp_api.g1_recovery_bundle_v1 AS
      SELECT
        receipt.operation_id AS recovery_session_id,
        1::INT8 AS schema_version,
        receipt.recorded_at AS source_commit_ts,
        receipt.request_digest AS source_digest,
        receipt.policy_version,
        receipt.tenant_id,
        receipt.run_id,
        receipt.incident_id,
        receipt.resource_id,
        receipt.agent_id AS failed_agent_id,
        receipt.outcome,
        receipt.reason,
        receipt.evidence_digest,
        receipt.fencing_token AS committed_fencing_token,
        resource.current_fence,
        resource.holder_operation_id,
        resource.holder_agent_id,
        resource.lease_expires_at,
        outbox.intent_id,
        outbox.intent_kind,
        false AS authority_transferred,
        true AS requires_fresh_authorization
      FROM tp_ledger.g1_authority_receipts AS receipt
      LEFT JOIN tp_private.g1_resources AS resource
        ON resource.tenant_id = receipt.tenant_id
       AND resource.resource_id = receipt.resource_id
      LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
        ON outbox.tenant_id = receipt.tenant_id
       AND outbox.operation_id = receipt.operation_id
    `);
  }

  async registerVerificationKey(input) {
    const tenantId = requireUuid(input.tenantId, "tenantId");
    const verificationKeyId = requireText(
      input.verificationKeyId,
      "verificationKeyId"
    );
    const issuer = requireText(input.issuer, "issuer");
    const algorithm = requireText(
      input.algorithm ?? "ed25519",
      "algorithm"
    ).toLowerCase();
    if (algorithm !== "ed25519") {
      throw new TypeError("algorithm must be ed25519");
    }
    const publicKey = requireBase64(
      input.publicKeySpkiBase64,
      "publicKeySpkiBase64"
    );
    const parsedKey = createPublicKey({
      key: publicKey.bytes,
      format: "der",
      type: "spki"
    });
    if (parsedKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("publicKeySpkiBase64 must contain an Ed25519 key");
    }
    const publicKeyDigest = sha256(publicKey.bytes);
    const validFrom = requireTimestamp(input.validFrom, "validFrom");
    const validUntil = requireTimestamp(input.validUntil, "validUntil");
    if (Date.parse(validUntil) <= Date.parse(validFrom)) {
      throw new RangeError("verification key validUntil must follow validFrom");
    }

    return this.#runSerializable(async (client) => {
      const inserted = await client.query(
        `
          INSERT INTO tp_private.g1_verification_keys (
            tenant_id,
            verification_key_id,
            issuer,
            algorithm,
            public_key_spki_base64,
            public_key_digest,
            status,
            valid_from,
            valid_until
          )
          VALUES (
            $1::UUID,
            $2,
            $3,
            'ed25519',
            $4,
            $5,
            'active',
            $6::TIMESTAMPTZ,
            $7::TIMESTAMPTZ
          )
          ON CONFLICT DO NOTHING
          RETURNING *
        `,
        [
          tenantId,
          verificationKeyId,
          issuer,
          publicKey.text,
          publicKeyDigest,
          validFrom,
          validUntil
        ]
      );
      if (inserted.rowCount === 1) {
        return { outcome: "verification_key_registered", key: inserted.rows[0] };
      }
      const existing = await client.query(
        `
          SELECT *
          FROM tp_private.g1_verification_keys
          WHERE tenant_id = $1::UUID
            AND verification_key_id = $2
        `,
        [tenantId, verificationKeyId]
      );
      if (existing.rowCount !== 1) {
        throw new InvariantViolationError(
          "verification key conflict was not observable"
        );
      }
      const row = existing.rows[0];
      if (
        row.issuer !== issuer ||
        row.algorithm !== algorithm ||
        row.public_key_spki_base64 !== publicKey.text ||
        row.public_key_digest !== publicKeyDigest ||
        new Date(row.valid_from).toISOString() !== validFrom ||
        new Date(row.valid_until).toISOString() !== validUntil
      ) {
        throw new EvidenceVerificationMismatchError(verificationKeyId);
      }
      return { outcome: "verification_key_replay", key: row };
    });
  }

  async revokeVerificationKey({ tenantId, verificationKeyId }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const keyId = requireText(verificationKeyId, "verificationKeyId");
    return this.#runSerializable(async (client) => {
      const updated = await client.query(
        `
          UPDATE tp_private.g1_verification_keys
          SET status = 'revoked',
              revoked_at = COALESCE(revoked_at, transaction_timestamp())
          WHERE tenant_id = $1::UUID
            AND verification_key_id = $2
          RETURNING *
        `,
        [tenant, keyId]
      );
      if (updated.rowCount !== 1) {
        throw new InvariantViolationError("verification key does not exist");
      }
      return { outcome: "verification_key_revoked", key: updated.rows[0] };
    });
  }

  async appendSignedEvidence(input) {
    const evidence = signedEvidenceEnvelopeFor(input);
    const {
      verificationKeyId,
      verifierVersion,
      signedPayload,
      signedPayloadDigest,
      signatureDigest,
      verificationRequestDigest
    } = evidence;

    return this.#runSerializable(async (client) => {
      const byEvidence = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_evidence_verification_receipts
          WHERE tenant_id = $1::UUID
            AND evidence_id = $2::UUID
        `,
        [evidence.tenantId, evidence.evidenceId]
      );
      const byDigest = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_evidence_verification_receipts
          WHERE tenant_id = $1::UUID
            AND verification_request_digest = $2
        `,
        [evidence.tenantId, verificationRequestDigest]
      );
      const existingRows = [...byEvidence.rows];
      if (
        byDigest.rowCount === 1 &&
        !existingRows.some(
          ({ evidence_id }) => evidence_id === byDigest.rows[0].evidence_id
        )
      ) {
        existingRows.push(byDigest.rows[0]);
      }
      if (existingRows.length > 0) {
        if (
          existingRows.length !== 1 ||
          existingRows[0].verification_request_digest !==
            verificationRequestDigest
        ) {
          throw new EvidenceVerificationMismatchError(evidence.evidenceId);
        }
        return {
          outcome: "evidence_verification_replay",
          verification: existingRows[0]
        };
      }

      const keyResult = await client.query(
        `
          SELECT *, transaction_timestamp() AS database_now
          FROM tp_private.g1_verification_keys
          WHERE tenant_id = $1::UUID
            AND verification_key_id = $2
        `,
        [evidence.tenantId, verificationKeyId]
      );
      let reason = null;
      let publicKeyDigest = null;
      if (keyResult.rowCount !== 1) {
        reason = "verification_key_unknown";
      } else {
        const key = keyResult.rows[0];
        publicKeyDigest = key.public_key_digest;
        if (key.issuer !== evidence.issuer) {
          reason = "verification_issuer_mismatch";
        } else if (key.status !== "active") {
          reason = "verification_key_revoked";
        } else if (
          Date.parse(evidence.observedAt) < Date.parse(key.valid_from) ||
          Date.parse(evidence.observedAt) >= Date.parse(key.valid_until)
        ) {
          reason = "verification_key_not_valid_at_observation";
        } else {
          try {
            const publicKey = createPublicKey({
              key: Buffer.from(key.public_key_spki_base64, "base64"),
              format: "der",
              type: "spki"
            });
            if (
              publicKey.asymmetricKeyType !== "ed25519" ||
              !verifySignature(
                null,
                Buffer.from(signedPayload, "utf8"),
                publicKey,
                evidence.signatureBytes
              )
            ) {
              reason = "signature_invalid";
            }
          } catch {
            reason = "verification_key_invalid";
          }
        }
      }

      const outcome = reason ? "rejected" : "verified";
      const verification = await client.query(
        `
          INSERT INTO tp_ledger.g1_evidence_verification_receipts (
            tenant_id,
            evidence_id,
            verification_request_digest,
            incident_id,
            issuer,
            verification_key_id,
            verifier_version,
            signed_payload_digest,
            signature_digest,
            public_key_digest,
            outcome,
            reason
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3,
            $4::UUID,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12
          )
          RETURNING *
        `,
        [
          evidence.tenantId,
          evidence.evidenceId,
          verificationRequestDigest,
          evidence.incidentId,
          evidence.issuer,
          verificationKeyId,
          verifierVersion,
          signedPayloadDigest,
          signatureDigest,
          publicKeyDigest,
          outcome,
          reason
        ]
      );
      if (reason) {
        return {
          outcome: "evidence_rejected",
          reason,
          verification: verification.rows[0]
        };
      }

      const evidenceDigest = evidence.evidenceDigest;
      const inserted = await client.query(
        `
          INSERT INTO tp_private.g1_evidence (
            tenant_id,
            evidence_id,
            incident_id,
            issuer,
            agency_scope,
            claim_key,
            claim_value,
            verification_key_id,
            verifier_version,
            signed_payload_digest,
            signature_digest,
            evidence_digest,
            observed_at,
            valid_from,
            valid_until,
            provenance_status,
            conflict_status,
            assertion,
            embedding
          )
          VALUES (
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12,
            $13::TIMESTAMPTZ,
            $14::TIMESTAMPTZ,
            $15::TIMESTAMPTZ,
            'verified',
            $16,
            $17,
            $18::VECTOR(3)
          )
          RETURNING *
        `,
        [
          evidence.tenantId,
          evidence.evidenceId,
          evidence.incidentId,
          evidence.issuer,
          evidence.agencyScope,
          evidence.claimKey,
          evidence.claimValue,
          verificationKeyId,
          verifierVersion,
          signedPayloadDigest,
          signatureDigest,
          evidenceDigest,
          evidence.observedAt,
          evidence.validFrom,
          evidence.validUntil,
          evidence.conflictStatus,
          evidence.assertion,
          evidence.embedding
        ]
      );
      return {
        outcome: "evidence_verified",
        verification: verification.rows[0],
        evidence: inserted.rows[0]
      };
    });
  }

  async verificationSnapshot({ tenantId, evidenceId }) {
    const tenant = requireUuid(tenantId, "tenantId");
    const evidence = requireUuid(evidenceId, "evidenceId");
    const client = await this.#pool.connect();
    try {
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
      );
      const verification = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_evidence_verification_receipts
          WHERE tenant_id = $1::UUID
            AND evidence_id = $2::UUID
        `,
        [tenant, evidence]
      );
      const admittedEvidence = await client.query(
        `
          SELECT *
          FROM tp_private.g1_evidence
          WHERE tenant_id = $1::UUID
            AND evidence_id = $2::UUID
        `,
        [tenant, evidence]
      );
      await client.query("COMMIT");
      return {
        verification: verification.rows[0] ?? null,
        evidence: admittedEvidence.rows[0] ?? null
      };
    } catch (error) {
      await rollbackQuietly(client);
      throw error;
    } finally {
      client.release();
    }
  }

  async auditEvidenceStatusAt({
    tenantId,
    evidenceId,
    incidentId,
    agency,
    at
  }) {
    const values = [
      requireUuid(tenantId, "tenantId"),
      requireUuid(evidenceId, "evidenceId"),
      requireUuid(incidentId, "incidentId"),
      requireText(agency, "agency"),
      requireTimestamp(at, "at")
    ];
    const result = await this.#pool.query(
      `
        SELECT
          evidence.evidence_id,
          $5::TIMESTAMPTZ AS audit_time,
          CASE
            WHEN verification.evidence_id IS NULL
              OR verification.outcome <> 'verified'
              THEN 'verification_not_valid'
            WHEN verification_key.verification_key_id IS NULL
              OR verification_key.status <> 'active'
              OR verification_key.public_key_digest <>
                verification.public_key_digest
              THEN 'verification_key_not_valid'
            WHEN evidence.claim_key IS NULL
              OR evidence.claim_value IS NULL
              THEN 'claim_binding_missing'
            WHEN evidence.observed_at >
              $5::TIMESTAMPTZ + INTERVAL '5 minutes'
              THEN 'future_observation'
            WHEN evidence.valid_from > $5::TIMESTAMPTZ
              THEN 'not_yet_valid'
            WHEN evidence.valid_until <= $5::TIMESTAMPTZ
              THEN 'expired'
            WHEN evidence.agency_scope NOT IN ($4, '*')
              THEN 'out_of_scope'
            WHEN evidence.conflict_status = 'unresolved'
              THEN 'unresolved_conflict'
            WHEN EXISTS (
              SELECT 1
              FROM tp_private.g1_evidence AS other
              JOIN tp_ledger.g1_evidence_verification_receipts
                AS other_verification
                ON other_verification.tenant_id = other.tenant_id
               AND other_verification.evidence_id = other.evidence_id
              JOIN tp_private.g1_verification_keys AS other_key
                ON other_key.tenant_id = other.tenant_id
               AND other_key.verification_key_id =
                 other.verification_key_id
              WHERE other.tenant_id = evidence.tenant_id
                AND other.incident_id = evidence.incident_id
                AND other.evidence_id <> evidence.evidence_id
                AND other.claim_key = evidence.claim_key
                AND other.claim_value <> evidence.claim_value
                AND other.provenance_status = 'verified'
                AND other_verification.outcome = 'verified'
                AND other_verification.incident_id = other.incident_id
                AND other_verification.issuer = other.issuer
                AND other_verification.verification_key_id =
                  other.verification_key_id
                AND other_verification.verifier_version =
                  other.verifier_version
                AND other_verification.signed_payload_digest =
                  other.signed_payload_digest
                AND other_verification.signature_digest =
                  other.signature_digest
                AND other_key.status = 'active'
                AND other_key.issuer = other.issuer
                AND other_key.public_key_digest =
                  other_verification.public_key_digest
                AND other.observed_at >= other_key.valid_from
                AND other.observed_at < other_key.valid_until
                AND other.observed_at <=
                  $5::TIMESTAMPTZ + INTERVAL '5 minutes'
                AND other.valid_from <= $5::TIMESTAMPTZ
                AND other.valid_until > $5::TIMESTAMPTZ
                AND other.agency_scope IN ($4, '*')
            )
              THEN 'unresolved_conflict'
            ELSE 'admissible'
          END AS status
        FROM tp_private.g1_evidence AS evidence
        LEFT JOIN tp_ledger.g1_evidence_verification_receipts
          AS verification
          ON verification.tenant_id = evidence.tenant_id
         AND verification.evidence_id = evidence.evidence_id
        LEFT JOIN tp_private.g1_verification_keys AS verification_key
          ON verification_key.tenant_id = evidence.tenant_id
         AND verification_key.verification_key_id =
           evidence.verification_key_id
        WHERE evidence.tenant_id = $1::UUID
          AND evidence.evidence_id = $2::UUID
          AND evidence.incident_id = $3::UUID
      `,
      values
    );
    if (result.rowCount !== 1) {
      return { status: "evidence_missing", auditTime: values[4] };
    }
    return {
      status: result.rows[0].status,
      auditTime: new Date(result.rows[0].audit_time).toISOString()
    };
  }

  async appendEvidence(input) {
    const evidence = {
      ...normalizeEvidence(input),
      provenanceStatus: requireText(
        input.provenanceStatus,
        "provenanceStatus"
      )
    };
    const signedPayloadDigest = requireSha256(
      input.signedPayloadDigest ??
        sha256(
          canonicalJson({
            tenantId: evidence.tenantId,
            evidenceId: evidence.evidenceId,
            incidentId: evidence.incidentId,
            issuer: evidence.issuer,
            agencyScope: evidence.agencyScope,
            observedAt: evidence.observedAt,
            validFrom: evidence.validFrom,
            validUntil: evidence.validUntil,
            assertion: evidence.assertion
          })
        ),
      "signedPayloadDigest"
    );
    const verificationKeyId = requireText(
      input.verificationKeyId ?? "gate1-synthetic-key-v1",
      "verificationKeyId"
    );
    const verifierVersion = requireText(
      input.verifierVersion ?? "gate1-verifier-v1",
      "verifierVersion"
    );
    const signatureDigest = requireSha256(
      input.signatureDigest ??
        sha256(`gate1-test-signature:${signedPayloadDigest}`),
      "signatureDigest"
    );
    const evidenceDigest = evidenceDigestFor({
      tenant_id: evidence.tenantId,
      evidence_id: evidence.evidenceId,
      incident_id: evidence.incidentId,
      issuer: evidence.issuer,
      agency_scope: evidence.agencyScope,
      claim_key: evidence.claimKey,
      claim_value: evidence.claimValue,
      verification_key_id: verificationKeyId,
      verifier_version: verifierVersion,
      signed_payload_digest: signedPayloadDigest,
      signature_digest: signatureDigest,
      observed_at: evidence.observedAt,
      valid_from: evidence.validFrom,
      valid_until: evidence.validUntil,
      provenance_status: evidence.provenanceStatus,
      conflict_status: evidence.conflictStatus,
      assertion: evidence.assertion,
      embedding: evidence.embedding
    });
    const result = await this.#pool.query(
      `
        INSERT INTO tp_private.g1_evidence (
          tenant_id,
          evidence_id,
          incident_id,
          issuer,
          agency_scope,
          claim_key,
          claim_value,
          verification_key_id,
          verifier_version,
          signed_payload_digest,
          signature_digest,
          evidence_digest,
          observed_at,
          valid_from,
          valid_until,
          provenance_status,
          conflict_status,
          assertion,
          embedding
        )
        VALUES (
          $1::UUID,
          $2::UUID,
          $3::UUID,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10,
          $11,
          $12,
          $13::TIMESTAMPTZ,
          $14::TIMESTAMPTZ,
          $15::TIMESTAMPTZ,
          $16,
          $17,
          $18,
          $19::VECTOR(3)
        )
        RETURNING *
      `,
      [
        evidence.tenantId,
        evidence.evidenceId,
        evidence.incidentId,
        evidence.issuer,
        evidence.agencyScope,
        evidence.claimKey,
        evidence.claimValue,
        verificationKeyId,
        verifierVersion,
        signedPayloadDigest,
        signatureDigest,
        evidenceDigest,
        evidence.observedAt,
        evidence.validFrom,
        evidence.validUntil,
        evidence.provenanceStatus,
        evidence.conflictStatus,
        evidence.assertion,
        evidence.embedding
      ]
    );
    return result.rows[0];
  }

  async prepareResource({ tenantId, runId, resourceId }) {
    const result = await this.#pool.query(
      `
        INSERT INTO tp_private.g1_resources (
          tenant_id,
          resource_id,
          active_run_id
        )
        VALUES ($1::UUID, $2, $3::UUID)
        RETURNING *
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireText(resourceId, "resourceId"),
        requireUuid(runId, "runId")
      ]
    );
    return result.rows[0];
  }

  async expireLeaseForTest({ tenantId, resourceId }) {
    const result = await this.#pool.query(
      `
        UPDATE tp_private.g1_resources
        SET lease_expires_at = transaction_timestamp() - INTERVAL '1 microsecond',
            updated_at = transaction_timestamp()
        WHERE tenant_id = $1::UUID
          AND resource_id = $2
        RETURNING current_fence
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireText(resourceId, "resourceId")
      ]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError("resource missing during lease expiry");
    }
    return result.rows[0];
  }

  async expireLeaseAtDatabaseNowForTest({ tenantId, resourceId }) {
    const result = await this.#pool.query(
      `
        UPDATE tp_private.g1_resources
        SET lease_expires_at = transaction_timestamp(),
            updated_at = transaction_timestamp()
        WHERE tenant_id = $1::UUID
          AND resource_id = $2
        RETURNING
          current_fence,
          lease_expires_at,
          transaction_timestamp() AS database_now,
          lease_expires_at = transaction_timestamp() AS exact_boundary
      `,
      [
        requireUuid(tenantId, "tenantId"),
        requireText(resourceId, "resourceId")
      ]
    );
    if (result.rowCount !== 1) {
      throw new InvariantViolationError("resource missing during lease expiry");
    }
    return result.rows[0];
  }

  async #runSerializable(
    work,
    {
      barrier,
      commitDispatchObserver,
      afterCommitObserver,
      maxRetries = DEFAULT_MAX_RETRIES,
      retryDeadlineMs = DEFAULT_RETRY_DEADLINE_MS
    } = {}
  ) {
    const startedAt = Date.now();
    const retryCodes = [];
    const backendIds = [];
    let initialBackendId = null;

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      const client = await this.#pool.connect();
      let commitDispatched = false;
      let committed = false;
      let releaseError = null;
      try {
        await client.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE");
        const isolation = await client.query(
          "SHOW TRANSACTION ISOLATION LEVEL"
        );
        const backend = await client.query(
          "SELECT pg_backend_pid()::STRING AS backend_id"
        );
        const backendId = backend.rows[0].backend_id;
        initialBackendId ??= backendId;
        backendIds.push(backendId);
        const result = await work(client, {
          attempt,
          barrier: attempt === 0 ? barrier : null
        });
        const restoreCommitObserver = observeCommitDispatch(
          client,
          commitDispatchObserver
        );
        commitDispatched = true;
        try {
          await client.query("COMMIT");
        } finally {
          restoreCommitObserver();
        }
        committed = true;
        afterCommitObserver?.();
        return {
          ...result,
          transaction: {
            isolation: isolation.rows[0].transaction_isolation,
            backendId,
            initialBackendId,
            backendIds: [...backendIds],
            serializableRetries: attempt,
            retryCodes
          }
        };
      } catch (error) {
        if (!committed && !commitDispatched) {
          await rollbackQuietly(client);
        }

        if (
          isRetryableTransactionError(error) &&
          attempt < maxRetries &&
          Date.now() - startedAt < retryDeadlineMs
        ) {
          retryCodes.push(error.code);
          await rollbackQuietly(client);
          await new Promise((resolve) =>
            setTimeout(resolve, backoffMs(attempt))
          );
          continue;
        }

        if (
          isAmbiguousTransactionError(error) ||
          (commitDispatched && isTransportError(error))
        ) {
          releaseError = error;
          throw new AmbiguousCommitError(
            "COMMIT outcome is unknown; reconcile by exact request digest.",
            error
          );
        }

        if (isTransportError(error)) {
          releaseError = error;
        }
        throw error;
      } finally {
        client.release(releaseError ?? undefined);
      }
    }
    throw new Error("serializable retry loop exhausted");
  }

  async #existingReceipt(client, request) {
    const byOperation = await client.query(
      `
        SELECT *
        FROM tp_ledger.g1_authority_receipts
        WHERE tenant_id = $1::UUID
          AND operation_id = $2::UUID
      `,
      [request.tenantId, request.operationId]
    );
    const byDigest = await client.query(
      `
        SELECT *
        FROM tp_ledger.g1_authority_receipts
        WHERE tenant_id = $1::UUID
          AND request_digest = $2
      `,
      [request.tenantId, request.requestDigest]
    );
    const rows = [...byOperation.rows];
    if (
      byDigest.rowCount === 1 &&
      !rows.some(
        ({ operation_id }) => operation_id === byDigest.rows[0].operation_id
      )
    ) {
      rows.push(byDigest.rows[0]);
    }
    if (rows.length === 0) {
      return null;
    }
    if (
      byOperation.rowCount > 1 ||
      byDigest.rowCount > 1 ||
      rows.length !== 1
    ) {
      throw new InvariantViolationError(
        "operation ID and semantic digest matched different receipts"
      );
    }
    const receipt = rows[0];
    if (
      receipt.operation_id === request.operationId &&
      receipt.request_digest !== request.requestDigest
    ) {
      throw new OperationDigestMismatchError(request.operationId);
    }
    if (receipt.outcome === "pending") {
      throw new InvariantViolationError("committed pending receipt found");
    }
    return {
      outcome:
        receipt.operation_id === request.operationId
          ? "operation_replay"
          : "semantic_replay",
      receipt
    };
  }

  async spendAuthority(
    input,
    {
      barrier,
      beforeCommitObserver,
      commitDispatchObserver,
      afterCommitObserver
    } = {}
  ) {
    const request = normalizeRequest(input);

    return this.#runSerializable(
      async (client, transactionContext) => {
        const existing = await this.#existingReceipt(client, request);
        if (existing) {
          return {
            ...existing,
            requestDigest: request.requestDigest
          };
        }

        const insertedPending = await client.query(
          `
            INSERT INTO tp_ledger.g1_authority_receipts (
              tenant_id,
              operation_id,
              request_digest,
              request_payload,
              run_id,
              incident_id,
              resource_id,
              agent_id,
              agency,
              evidence_id,
              effect_key,
              payload_digest,
              policy_version,
              outcome
            )
            VALUES (
              $1::UUID,
              $2::UUID,
              $3,
              $4::JSONB,
              $5::UUID,
              $6::UUID,
              $7,
              $8,
              $9,
              $10::UUID,
              $11::UUID,
              $12,
              $13,
              'pending'
            )
            ON CONFLICT DO NOTHING
            RETURNING operation_id
          `,
          [
            request.tenantId,
            request.operationId,
            request.requestDigest,
            JSON.stringify(request.requestPayload),
            request.runId,
            request.incidentId,
            request.resourceId,
            request.agentId,
            request.agency,
            request.evidenceId,
            request.effectKey,
            request.payloadDigest,
            request.policyVersion
          ]
        );
        if (insertedPending.rowCount === 0) {
          const concurrentExisting = await this.#existingReceipt(
            client,
            request
          );
          if (!concurrentExisting) {
            throw new InvariantViolationError(
              "receipt conflict was not reconcilable by operation or digest"
            );
          }
          return {
            ...concurrentExisting,
            requestDigest: request.requestDigest
          };
        }

        const evidence = await client.query(
          `
            SELECT
              evidence.*,
              transaction_timestamp() AS database_now,
              CASE
                WHEN evidence.verification_key_id IS NULL
                  OR evidence.verifier_version IS NULL
                  OR evidence.signed_payload_digest IS NULL
                  OR evidence.signature_digest IS NULL
                  OR evidence.evidence_digest IS NULL
                  THEN 'verification_receipt_missing'
                WHEN verification.evidence_id IS NULL
                  THEN 'verification_receipt_missing'
                WHEN verification.outcome <> 'verified'
                  THEN COALESCE(
                    verification.reason,
                    'verification_rejected'
                  )
                WHEN verification.incident_id <> evidence.incident_id
                  OR verification.issuer <> evidence.issuer
                  OR verification.verification_key_id <>
                    evidence.verification_key_id
                  OR verification.verifier_version <>
                    evidence.verifier_version
                  OR verification.signed_payload_digest <>
                    evidence.signed_payload_digest
                  OR verification.signature_digest <>
                    evidence.signature_digest
                  THEN 'verification_binding_mismatch'
                WHEN verification_key.verification_key_id IS NULL
                  THEN 'verification_key_unknown'
                WHEN verification_key.public_key_digest <>
                  verification.public_key_digest
                  THEN 'verification_key_digest_mismatch'
                WHEN verification_key.issuer <> evidence.issuer
                  THEN 'verification_issuer_mismatch'
                WHEN verification_key.status <> 'active'
                  THEN 'verification_key_revoked'
                WHEN evidence.observed_at < verification_key.valid_from
                  OR evidence.observed_at >= verification_key.valid_until
                  THEN 'verification_key_not_valid_at_observation'
                WHEN evidence.provenance_status <> 'verified'
                  THEN 'provenance_not_verified'
                WHEN evidence.claim_key IS NULL
                  OR evidence.claim_value IS NULL
                  THEN 'claim_binding_missing'
                WHEN evidence.observed_at >
                  transaction_timestamp() + INTERVAL '5 minutes'
                  THEN 'future_observation'
                WHEN evidence.valid_from > transaction_timestamp()
                  THEN 'not_yet_valid'
                WHEN evidence.valid_until <= transaction_timestamp()
                  THEN 'expired'
                WHEN evidence.agency_scope NOT IN ($4, '*')
                  THEN 'out_of_scope'
                WHEN evidence.conflict_status = 'unresolved'
                  THEN 'unresolved_conflict'
                WHEN EXISTS (
                  SELECT 1
                  FROM tp_private.g1_evidence AS other
                  JOIN tp_ledger.g1_evidence_verification_receipts
                    AS other_verification
                    ON other_verification.tenant_id = other.tenant_id
                   AND other_verification.evidence_id = other.evidence_id
                  JOIN tp_private.g1_verification_keys AS other_key
                    ON other_key.tenant_id = other.tenant_id
                   AND other_key.verification_key_id =
                     other.verification_key_id
                  WHERE other.tenant_id = evidence.tenant_id
                    AND other.incident_id = evidence.incident_id
                    AND other.evidence_id <> evidence.evidence_id
                    AND other.claim_key = evidence.claim_key
                    AND other.claim_value <> evidence.claim_value
                    AND other.provenance_status = 'verified'
                    AND other_verification.outcome = 'verified'
                    AND other_verification.incident_id = other.incident_id
                    AND other_verification.issuer = other.issuer
                    AND other_verification.verification_key_id =
                      other.verification_key_id
                    AND other_verification.verifier_version =
                      other.verifier_version
                    AND other_verification.signed_payload_digest =
                      other.signed_payload_digest
                    AND other_verification.signature_digest =
                      other.signature_digest
                    AND other_key.status = 'active'
                    AND other_key.issuer = other.issuer
                    AND other_key.public_key_digest =
                      other_verification.public_key_digest
                    AND other.observed_at >= other_key.valid_from
                    AND other.observed_at < other_key.valid_until
                    AND other.observed_at <=
                      transaction_timestamp() + INTERVAL '5 minutes'
                    AND other.valid_from <= transaction_timestamp()
                    AND other.valid_until > transaction_timestamp()
                    AND other.agency_scope IN ($4, '*')
                )
                  THEN 'unresolved_conflict'
                ELSE 'admissible'
              END AS admissibility
            FROM tp_private.g1_evidence AS evidence
            LEFT JOIN tp_ledger.g1_evidence_verification_receipts
              AS verification
              ON verification.tenant_id = evidence.tenant_id
             AND verification.evidence_id = evidence.evidence_id
            LEFT JOIN tp_private.g1_verification_keys AS verification_key
              ON verification_key.tenant_id = evidence.tenant_id
             AND verification_key.verification_key_id =
               evidence.verification_key_id
            WHERE evidence.tenant_id = $1::UUID
              AND evidence.evidence_id = $2::UUID
              AND evidence.incident_id = $3::UUID
          `,
          [
            request.tenantId,
            request.evidenceId,
            request.incidentId,
            request.agency
          ]
        );

        if (
          evidence.rowCount !== 1 ||
          evidence.rows[0].admissibility !== "admissible"
        ) {
          const reason =
            evidence.rowCount === 1
              ? evidence.rows[0].admissibility
              : "evidence_missing";
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = $3
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId, reason]
          );
          return {
            outcome: "authorization_denied",
            reason,
            requestDigest: request.requestDigest,
            receipt: denied.rows[0]
          };
        }

        const evidenceDigest = evidenceDigestFor(evidence.rows[0]);
        if (evidence.rows[0].evidence_digest !== evidenceDigest) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = 'evidence_digest_mismatch'
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId]
          );
          return {
            outcome: "authorization_denied",
            reason: "evidence_digest_mismatch",
            requestDigest: request.requestDigest,
            receipt: denied.rows[0]
          };
        }
        if (transactionContext.barrier) {
          await transactionContext.barrier.wait();
        }

        const resource = await client.query(
          `
            SELECT *, transaction_timestamp() AS database_now
            FROM tp_private.g1_resources
            WHERE tenant_id = $1::UUID
              AND resource_id = $2
            FOR UPDATE
          `,
          [request.tenantId, request.resourceId]
        );
        if (resource.rowCount !== 1) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = 'resource_missing',
                  evidence_digest = $3
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId, evidenceDigest]
          );
          return {
            outcome: "authorization_denied",
            reason: "resource_missing",
            requestDigest: request.requestDigest,
            receipt: denied.rows[0]
          };
        }
        const current = resource.rows[0];
        if (current.active_run_id !== request.runId) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'authorization_denied',
                  reason = 'inactive_run',
                  evidence_digest = $3
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [request.tenantId, request.operationId, evidenceDigest]
          );
          return {
            outcome: "authorization_denied",
            reason: "inactive_run",
            requestDigest: request.requestDigest,
            receipt: denied.rows[0]
          };
        }

        if (
          current.holder_operation_id &&
          new Date(current.lease_expires_at).getTime() >
            new Date(current.database_now).getTime()
        ) {
          const denied = await client.query(
            `
              UPDATE tp_ledger.g1_authority_receipts
              SET outcome = 'resource_held_denied',
                  reason = 'active_holder',
                  evidence_digest = $3,
                  observed_holder_operation_id = $4::UUID,
                  observed_fence = $5::INT8
              WHERE tenant_id = $1::UUID
                AND operation_id = $2::UUID
              RETURNING *
            `,
            [
              request.tenantId,
              request.operationId,
              evidenceDigest,
              current.holder_operation_id,
              current.current_fence
            ]
          );
          return {
            outcome: "resource_held_denied",
            requestDigest: request.requestDigest,
            receipt: denied.rows[0]
          };
        }

        const acquired = await client.query(
          `
            UPDATE tp_private.g1_resources
            SET current_fence = current_fence + 1,
                holder_incident_id = $3::UUID,
                holder_operation_id = $4::UUID,
                holder_agent_id = $5,
                lease_expires_at =
                  transaction_timestamp() +
                  ($6::INT8 * INTERVAL '1 millisecond'),
                updated_at = transaction_timestamp()
            WHERE tenant_id = $1::UUID
              AND resource_id = $2
              AND active_run_id = $7::UUID
              AND current_fence < 9223372036854775807
              AND (
                holder_operation_id IS NULL
                OR lease_expires_at <= transaction_timestamp()
              )
            RETURNING current_fence, lease_expires_at
          `,
          [
            request.tenantId,
            request.resourceId,
            request.incidentId,
            request.operationId,
            request.agentId,
            request.leaseMs,
            request.runId
          ]
        );
        if (acquired.rowCount !== 1) {
          throw new InvariantViolationError(
            "locked resource could not be acquired or denied deterministically"
          );
        }

        const fencingToken = acquired.rows[0].current_fence;
        const leaseExpiresAt = acquired.rows[0].lease_expires_at;
        const receipt = await client.query(
          `
            UPDATE tp_ledger.g1_authority_receipts
            SET outcome = 'resource_reserved',
                evidence_digest = $3,
                fencing_token = $4::INT8,
                lease_expires_at = $5::TIMESTAMPTZ
            WHERE tenant_id = $1::UUID
              AND operation_id = $2::UUID
            RETURNING *
          `,
          [
            request.tenantId,
            request.operationId,
            evidenceDigest,
            fencingToken,
            leaseExpiresAt
          ]
        );
        const outbox = await client.query(
          `
            INSERT INTO tp_ledger.g1_outbox_intents (
              tenant_id,
              operation_id,
              request_digest,
              run_id,
              incident_id,
              resource_id,
              fencing_token,
              effect_key,
              intent_kind,
              payload,
              payload_digest
            )
            VALUES (
              $1::UUID,
              $2::UUID,
              $3,
              $4::UUID,
              $5::UUID,
              $6,
              $7::INT8,
              $8::UUID,
              'dispatch_rescue_unit',
              $9::JSONB,
              $10
            )
            RETURNING *
          `,
          [
            request.tenantId,
            request.operationId,
            request.requestDigest,
            request.runId,
            request.incidentId,
            request.resourceId,
            fencingToken,
            request.effectKey,
            JSON.stringify(request.payload),
            request.payloadDigest
          ]
        );

        beforeCommitObserver?.();
        return {
          outcome: "resource_reserved",
          requestDigest: request.requestDigest,
          receipt: receipt.rows[0],
          outbox: outbox.rows[0]
        };
      },
      { barrier, commitDispatchObserver, afterCommitObserver }
    );
  }

  async proveSerializableRetry({ tenantId, probeId }, { barrier } = {}) {
    const tenant = requireUuid(tenantId, "tenantId");
    const probe = requireUuid(probeId, "probeId");
    await this.#pool.query(
      `
        INSERT INTO tp_private.g1_retry_probes
          (tenant_id, probe_id, value)
        VALUES ($1::UUID, $2::UUID, 0)
      `,
      [tenant, probe]
    );

    const contenders = await Promise.all(
      ["left", "right"].map((name) =>
        this.#runSerializable(
          async (client, transactionContext) => {
            const observed = await client.query(
              `
                SELECT value
                FROM tp_private.g1_retry_probes
                WHERE tenant_id = $1::UUID
                  AND probe_id = $2::UUID
              `,
              [tenant, probe]
            );
            if (transactionContext.barrier) {
              await transactionContext.barrier.wait();
            }
            const updated = await client.query(
              `
                UPDATE tp_private.g1_retry_probes
                SET value = $3::INT8
                WHERE tenant_id = $1::UUID
                  AND probe_id = $2::UUID
                RETURNING value
              `,
              [
                tenant,
                probe,
                (BigInt(observed.rows[0].value) + 1n).toString()
              ]
            );
            return {
              contender: name,
              observedValue: observed.rows[0].value,
              committedValue: updated.rows[0].value
            };
          },
          { barrier }
        )
      )
    );
    const final = await this.#pool.query(
      `
        SELECT value
        FROM tp_private.g1_retry_probes
        WHERE tenant_id = $1::UUID
          AND probe_id = $2::UUID
      `,
      [tenant, probe]
    );
    return {
      contenders,
      finalValue: final.rows[0].value,
      retryCodes: contenders.flatMap(
        ({ transaction }) => transaction.retryCodes
      )
    };
  }

  async reconcileRequest(input) {
    const request = normalizeRequest(input);
    const client = new Client({ connectionString: this.#connectionString });
    try {
      await client.connect();
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
      );
      const result = await client.query(
        `
          SELECT
            receipt.*,
            outbox.intent_id,
            outbox.fencing_token AS outbox_fencing_token,
            resource.current_fence,
            resource.active_run_id,
            resource.holder_operation_id
          FROM tp_ledger.g1_authority_receipts AS receipt
          LEFT JOIN tp_ledger.g1_outbox_intents AS outbox
            ON outbox.tenant_id = receipt.tenant_id
           AND outbox.operation_id = receipt.operation_id
          LEFT JOIN tp_private.g1_resources AS resource
            ON resource.tenant_id = receipt.tenant_id
           AND resource.resource_id = receipt.resource_id
          WHERE receipt.tenant_id = $1::UUID
            AND (
              receipt.operation_id = $2::UUID
              OR receipt.request_digest = $3
            )
          LIMIT 2
        `,
        [request.tenantId, request.operationId, request.requestDigest]
      );
      await client.query("COMMIT");

      if (result.rowCount !== 1) {
        return {
          status: "UNKNOWN_DO_NOT_ACT",
          requestDigest: request.requestDigest,
          reason:
            result.rowCount === 0
              ? "terminal_receipt_not_observed"
              : "multiple_receipts_observed"
        };
      }
      const row = result.rows[0];
      if (row.outcome === "pending") {
        return {
          status: "UNKNOWN_DO_NOT_ACT",
          requestDigest: request.requestDigest,
          reason: "committed_pending_receipt_invariant"
        };
      }
      if (row.request_digest !== request.requestDigest) {
        return {
          status: "UNKNOWN_DO_NOT_ACT",
          requestDigest: request.requestDigest,
          reason: "digest_mismatch"
        };
      }
      if (
        row.outcome === "resource_reserved" &&
        (!row.intent_id ||
          row.fencing_token !== row.outbox_fencing_token)
      ) {
        return {
          status: "UNKNOWN_DO_NOT_ACT",
          requestDigest: request.requestDigest,
          reason: "partial_or_superseded_authority_state"
        };
      }
      const authorityStillCurrent =
        row.outcome !== "resource_reserved" ||
        (row.fencing_token === row.current_fence &&
          row.operation_id === row.holder_operation_id &&
          row.run_id === row.active_run_id);
      return {
        status: authorityStillCurrent
          ? "COMMITTED"
          : "COMMITTED_BUT_NO_LONGER_CURRENT",
        requestDigest: request.requestDigest,
        receipt: row
      };
    } catch (error) {
      await rollbackQuietly(client);
      return {
        status: "UNKNOWN_DO_NOT_ACT",
        requestDigest: request.requestDigest,
        reason: "reconciliation_unavailable",
        errorCode: error.code ?? error.name
      };
    } finally {
      await client.end().catch(() => {});
    }
  }

  async recordProtectedEffect(input, { authenticatedAgentId } = {}) {
    const request = normalizeRequest(input);
    const authenticatedActor = requireText(
      authenticatedAgentId,
      "authenticatedAgentId"
    );
    if (authenticatedActor !== request.agentId) {
      return { outcome: "stale_or_unauthorized_fence_denied" };
    }
    const fencingToken = requireText(
      String(input.fencingToken),
      "fencingToken"
    );
    if (!/^[1-9][0-9]*$/.test(fencingToken)) {
      throw new TypeError("fencingToken must be a positive INT8 value");
    }

    return this.#runSerializable(async (client) => {
      const existing = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_protected_effects
          WHERE tenant_id = $1::UUID
            AND (
              effect_key = $2::UUID
              OR operation_id = $3::UUID
            )
          LIMIT 2
        `,
        [request.tenantId, request.effectKey, request.operationId]
      );
      if (existing.rowCount > 1) {
        throw new InvariantViolationError(
          "effect key and operation matched different effects"
        );
      }
      if (existing.rowCount === 1) {
        const effect = existing.rows[0];
        if (
          effect.effect_key !== request.effectKey ||
          effect.operation_id !== request.operationId ||
          effect.request_digest !== request.requestDigest ||
          effect.fencing_token !== fencingToken ||
          effect.payload_digest !== request.payloadDigest
        ) {
          throw new EffectKeyMismatchError(request.effectKey);
        }
        return { outcome: "effect_already_recorded", effect };
      }

      const inserted = await client.query(
        `
          INSERT INTO tp_ledger.g1_protected_effects (
            tenant_id,
            effect_key,
            operation_id,
            request_digest,
            run_id,
            incident_id,
            resource_id,
            agent_id,
            fencing_token,
            payload_digest
          )
          SELECT
            $1::UUID,
            $2::UUID,
            $3::UUID,
            $4,
            $5::UUID,
            $6::UUID,
            $7,
            $8,
            $9::INT8,
            $10
          FROM tp_private.g1_resources AS resource
          JOIN tp_ledger.g1_outbox_intents AS outbox
            ON outbox.tenant_id = resource.tenant_id
           AND outbox.operation_id = $3::UUID
           AND outbox.request_digest = $4
           AND outbox.run_id = $5::UUID
           AND outbox.incident_id = $6::UUID
           AND outbox.resource_id = $7
           AND outbox.fencing_token = $9::INT8
           AND outbox.effect_key = $2::UUID
           AND outbox.payload_digest = $10
          JOIN tp_ledger.g1_authority_receipts AS receipt
            ON receipt.tenant_id = outbox.tenant_id
           AND receipt.operation_id = outbox.operation_id
           AND receipt.agent_id = $8
           AND receipt.outcome = 'resource_reserved'
          WHERE resource.tenant_id = $1::UUID
            AND resource.resource_id = $7
            AND resource.active_run_id = $5::UUID
            AND resource.holder_incident_id = $6::UUID
            AND resource.holder_operation_id = $3::UUID
            AND resource.holder_agent_id = $8
            AND resource.current_fence = $9::INT8
            AND resource.lease_expires_at > transaction_timestamp()
          ON CONFLICT DO NOTHING
          RETURNING *
        `,
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
        ]
      );
      if (inserted.rowCount !== 1) {
        const raced = await client.query(
          `
            SELECT *
            FROM tp_ledger.g1_protected_effects
            WHERE tenant_id = $1::UUID
              AND (
                effect_key = $2::UUID
                OR operation_id = $3::UUID
              )
            LIMIT 2
          `,
          [request.tenantId, request.effectKey, request.operationId]
        );
        if (raced.rowCount > 1) {
          throw new InvariantViolationError(
            "effect key and operation matched different effects"
          );
        }
        if (raced.rowCount === 1) {
          const effect = raced.rows[0];
          if (
            effect.effect_key !== request.effectKey ||
            effect.operation_id !== request.operationId ||
            effect.request_digest !== request.requestDigest ||
            effect.fencing_token !== fencingToken ||
            effect.payload_digest !== request.payloadDigest
          ) {
            throw new EffectKeyMismatchError(request.effectKey);
          }
          return { outcome: "effect_already_recorded", effect };
        }
        return { outcome: "stale_or_unauthorized_fence_denied" };
      }
      return {
        outcome: "protected_effect_recorded",
        effect: inserted.rows[0]
      };
    });
  }

  async snapshot({ tenantId, resourceId }) {
    const values = [
      requireUuid(tenantId, "tenantId"),
      requireText(resourceId, "resourceId")
    ];
    const client = await this.#pool.connect();
    try {
      await client.query(
        "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
      );
      const resource = await client.query(
        `
          SELECT *
          FROM tp_private.g1_resources
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
        `,
        values
      );
      const receipts = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_authority_receipts
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
          ORDER BY recorded_at, operation_id
        `,
        values
      );
      const outbox = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_outbox_intents
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
          ORDER BY created_at, operation_id
        `,
        values
      );
      const effects = await client.query(
        `
          SELECT *
          FROM tp_ledger.g1_protected_effects
          WHERE tenant_id = $1::UUID
            AND resource_id = $2
          ORDER BY recorded_at, operation_id
        `,
        values
      );
      await client.query("COMMIT");
      return {
        resource: resource.rows[0] ?? null,
        receipts: receipts.rows,
        outbox: outbox.rows,
        effects: effects.rows
      };
    } catch (error) {
      await rollbackQuietly(client);
      throw error;
    } finally {
      client.release();
    }
  }
}
