import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import { verifyRecoveryBundleSourceSignature } from
  "./recovery-bundle-signature.js";
import { trustedPublisherKeysDigest } from
  "./recovery-publisher-trust.js";

export { verifyRecoveryBundleSourceSignature } from
  "./recovery-bundle-signature.js";

const RECOVERY_ID_NAMESPACE = "50e8fa14-7b36-5cbc-8f65-5ef89eca266e";
const QUERY_SESSION_TOKEN = "__RECOVERY_SESSION_ID__";
const QUERY_TENANT_TOKEN = "__TENANT_ID__";
const QUERY_SUBJECT_TOKEN = "__SUBJECT_BINDING_HASH__";
const QUERY_SOURCE_TOKEN = "__SOURCE_BINDING_DIGEST__";
const RECOVERY_BUNDLE_MAX_BYTES = 64 * 1024;
const RECOVERY_BUNDLE_PERSISTENCE_SCHEMA =
  "tideproof.highwater-drill-live-recovery-bundle-persistence.v1";
const RECOVERY_BUNDLE_ENVELOPE_SCHEMA =
  "tideproof.highwater-drill-live-signed-recovery-bundle.v1";
export const RECOVERY_AUDIT_TARGET_IDENTITY_SCHEMA =
  "tideproof.highwater-drill-recovery-audit-target.v1";

export const RECOVERY_DATABASE_FRESHNESS_SQL = `
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

export function recoveryAuditEventDigest(event) {
  return sha256(canonicalJson({
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
    toolName: "select_query",
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
    resultDigest: event.resultDigest === null
      ? null
      : requireSha256(event.resultDigest, "event.resultDigest"),
    sourceWatermark: event.sourceWatermark === null
      ? null
      : new Date(event.sourceWatermark).toISOString(),
    outcome: requireText(event.outcome, "event.outcome"),
    errorCode: event.errorCode === null
      ? null
      : requireText(event.errorCode, "event.errorCode"),
    startedAt: new Date(event.startedAt).toISOString(),
    completedAt: new Date(event.completedAt).toISOString()
  }));
}

function requireSha256(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (!/^[a-f0-9]{64}$/u.test(text)) {
    throw new TypeError(`${name} must be a SHA-256 digest`);
  }
  return text;
}

function requireCanonicalTimestamp(value, name) {
  const milliseconds = value instanceof Date
    ? value.getTime()
    : Date.parse(value);
  if (!Number.isFinite(milliseconds)) {
    throw new TypeError(`${name} must be a timestamp`);
  }
  const canonical = new Date(milliseconds).toISOString();
  if (!(value instanceof Date) && canonical !== value) {
    throw new TypeError(`${name} must be canonical`);
  }
  return canonical;
}

function uuidBytes(value) {
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function uuidV5(namespace, name) {
  const digest = createHash("sha1")
    .update(uuidBytes(namespace))
    .update(name)
    .digest();
  digest[6] = (digest[6] & 0x0f) | 0x50;
  digest[8] = (digest[8] & 0x3f) | 0x80;
  const hex = digest.subarray(0, 16).toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20)
  ].join("-");
}

export function canonicalRecoveryAttempt({
  tenantId,
  subjectBindingHash,
  sourceDigest,
  sourceCommitTs
}) {
  const acceptedTenantId = requireUuid(tenantId, "tenantId");
  const acceptedSubjectBindingHash = requireSha256(
    subjectBindingHash,
    "subjectBindingHash"
  );
  const acceptedSourceDigest = requireSha256(sourceDigest, "sourceDigest");
  const sourceCommitMs = new Date(sourceCommitTs).getTime();
  if (!Number.isSafeInteger(sourceCommitMs) || sourceCommitMs < 1) {
    throw new TypeError("sourceCommitTs must be a canonical timestamp");
  }
  const canonicalSourceCommitTs = new Date(sourceCommitMs).toISOString();
  if (canonicalSourceCommitTs !== sourceCommitTs) {
    throw new TypeError("sourceCommitTs must be a canonical timestamp");
  }
  const binding = canonicalJson({
    schemaVersion: "tideproof.canonical-recovery-attempt.v1",
    tenantId: acceptedTenantId,
    subjectBindingHash: acceptedSubjectBindingHash,
    sourceDigest: acceptedSourceDigest,
    sourceCommitTs: canonicalSourceCommitTs
  });
  return Object.freeze({
    recoverySessionId: uuidV5(RECOVERY_ID_NAMESPACE, binding),
    snapshotVersion: sourceCommitMs,
    sourceCommitTs: canonicalSourceCommitTs,
    expiresAt: new Date(sourceCommitMs + 30 * 60 * 1_000).toISOString(),
    bindingSha256: sha256(binding)
  });
}

export function normalizedRecoverySourceReceiptForContinuity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("recoverySourceReceipt must be an object");
  }
  if (
    value.outcome !== "resource_reserved" ||
    value.admissibility !== "admissible" ||
    value.has_durable_intent !== true
  ) {
    throw new TypeError("recoverySourceReceipt is not a durable admission");
  }
  if (!Number.isSafeInteger(Number(value.authorization_epoch)) ||
      Number(value.authorization_epoch) < 1) {
    throw new TypeError("authorization_epoch must be a positive integer");
  }
  return Object.freeze({
    admissibility: value.admissibility,
    authorization_binding_sha256: requireSha256(
      value.authorization_binding_sha256,
      "authorization_binding_sha256"
    ),
    authorization_epoch: Number(value.authorization_epoch),
    authority_evidence_binding_sha256: requireSha256(
      value.authority_evidence_binding_sha256,
      "authority_evidence_binding_sha256"
    ),
    evidence_digest: requireSha256(value.evidence_digest, "evidence_digest"),
    evidence_id: requireUuid(value.evidence_id, "evidence_id"),
    has_durable_intent: true,
    incident_id: requireUuid(value.incident_id, "incident_id"),
    logical_action_digest: requireSha256(
      value.logical_action_digest,
      "logical_action_digest"
    ),
    logical_authority_key_sha256: requireSha256(
      value.logical_authority_key_sha256,
      "logical_authority_key_sha256"
    ),
    operation_id: requireUuid(value.operation_id, "operation_id"),
    outcome: value.outcome,
    proposal_digest: requireSha256(value.proposal_digest, "proposal_digest"),
    recorded_at: requireCanonicalTimestamp(value.recorded_at, "recorded_at"),
    request_digest: requireSha256(value.request_digest, "request_digest"),
    resource_id: requireText(value.resource_id, "resource_id"),
    run_id: requireUuid(value.run_id, "run_id"),
    selected_evidence_binding_sha256: requireSha256(
      value.selected_evidence_binding_sha256,
      "selected_evidence_binding_sha256"
    ),
    tenant_id: requireUuid(value.tenant_id, "tenant_id")
  });
}

export function recoverySourceBindingDigestFor(input) {
  const required = [
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
  ];
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).sort().join("\n") !== required.sort().join("\n")
  ) {
    throw new TypeError("recoverySourceBinding has an unexpected shape");
  }
  const resourceId = requireText(input.resourceId, "resourceId");
  if (Buffer.byteLength(resourceId, "utf8") > 128) {
    throw new TypeError("resourceId exceeds 128 bytes");
  }
  if (!Number.isSafeInteger(input.authorizationEpoch) ||
      input.authorizationEpoch < 1) {
    throw new TypeError("authorizationEpoch must be a positive safe integer");
  }
  if (![
    "resource_reserved",
    "resource_held_denied",
    "authorization_denied"
  ].includes(input.outcome)) {
    throw new TypeError("outcome is not an accepted recovery outcome");
  }
  return sha256(canonicalJson({
    schema: "tideproof.highwater-recovery-binding.v3",
    tenantId: requireUuid(input.tenantId, "tenantId"),
    runId: requireUuid(input.runId, "runId"),
    incidentId: requireUuid(input.incidentId, "incidentId"),
    evidenceDigest: requireSha256(input.evidenceDigest, "evidenceDigest"),
    resourceId,
    operationId: requireUuid(input.operationId, "operationId"),
    requestDigest: requireSha256(input.requestDigest, "requestDigest"),
    proposalDigest: requireSha256(input.proposalDigest, "proposalDigest"),
    logicalActionDigest: requireSha256(
      input.logicalActionDigest,
      "logicalActionDigest"
    ),
    authorizationEpoch: input.authorizationEpoch,
    logicalAuthorityKeySha256: requireSha256(
      input.logicalAuthorityKeySha256,
      "logicalAuthorityKeySha256"
    ),
    authorizationBindingSha256: requireSha256(
      input.authorizationBindingSha256,
      "authorizationBindingSha256"
    ),
    authorityEvidenceBindingSha256: requireSha256(
      input.authorityEvidenceBindingSha256,
      "authorityEvidenceBindingSha256"
    ),
    selectedEvidenceBindingSha256: requireSha256(
      input.selectedEvidenceBindingSha256,
      "selectedEvidenceBindingSha256"
    ),
    outcome: input.outcome
  }));
}

export function recoveryQueryTemplateDigest() {
  return sha256(RECOVERY_QUERY_TEMPLATE);
}

function exactObjectKeys(value, keys) {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

export function validateRecoveryAuditTargetIdentity(value) {
  const keys = [
    "connectionOptionsSha256",
    "database",
    "hostname",
    "port",
    "primaryClusterId",
    "protocol",
    "schemaVersion",
    "tlsPolicySha256",
    "usernameSha256"
  ];
  if (
    !exactObjectKeys(value, keys) ||
    value.schemaVersion !== RECOVERY_AUDIT_TARGET_IDENTITY_SCHEMA ||
    value.protocol !== "postgresql" ||
    typeof value.hostname !== "string" ||
    value.hostname.length === 0 ||
    value.hostname !== value.hostname.toLowerCase() ||
    !Number.isSafeInteger(value.port) ||
    value.port < 1 ||
    value.port > 65535 ||
    typeof value.database !== "string" ||
    value.database.length === 0 ||
    requireUuid(value.primaryClusterId, "primaryClusterId") !==
      value.primaryClusterId ||
    ![
      value.connectionOptionsSha256,
      value.tlsPolicySha256,
      value.usernameSha256
    ].every((entry) => /^[0-9a-f]{64}$/u.test(entry ?? ""))
  ) {
    throw new TypeError("auditTargetIdentity is invalid");
  }
  return Object.freeze(Object.fromEntries(keys.map((key) => [
    key,
    value[key]
  ])));
}

export function recoveryAuditTargetIdentity({
  connectionString,
  primaryClusterId
}) {
  let parsed;
  try {
    parsed = new URL(requireText(connectionString, "connectionString"));
  } catch (cause) {
    throw new TypeError("connectionString must be an absolute PostgreSQL URL", {
      cause
    });
  }
  if (
    !["postgres:", "postgresql:"].includes(parsed.protocol) ||
    parsed.hostname.length === 0 ||
    parsed.hash !== ""
  ) {
    throw new TypeError("connectionString must identify PostgreSQL exactly");
  }
  let database;
  try {
    const segments = parsed.pathname.split("/").filter(Boolean);
    if (segments.length !== 1) {
      throw new TypeError("connectionString must name one database");
    }
    database = decodeURIComponent(segments[0]);
  } catch (cause) {
    throw new TypeError("connectionString database is invalid", { cause });
  }
  if (database.length === 0 || database.length > 256) {
    throw new TypeError("connectionString database is invalid");
  }
  const credentialQueryName = /(?:password|passwd|secret|token|key)$/iu;
  const optionDigests = [...parsed.searchParams.entries()]
    .filter(([name]) => !credentialQueryName.test(name))
    .map(([name, optionValue]) => [
      name.toLowerCase(),
      sha256(optionValue)
    ])
    .sort(([leftName, leftValue], [rightName, rightValue]) =>
      leftName.localeCompare(rightName) || leftValue.localeCompare(rightValue)
    );
  const tlsOptionNames = new Set([
    "channel_binding",
    "sslcert",
    "sslcrl",
    "sslkey",
    "sslmaxprotocolversion",
    "sslminprotocolversion",
    "sslmode",
    "sslrootcert"
  ]);
  const tlsOptionDigests = optionDigests.filter(([name]) =>
    tlsOptionNames.has(name)
  );
  return validateRecoveryAuditTargetIdentity(Object.freeze({
    schemaVersion: RECOVERY_AUDIT_TARGET_IDENTITY_SCHEMA,
    connectionOptionsSha256: sha256(canonicalJson(optionDigests)),
    database,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port === "" ? 5432 : Number(parsed.port),
    primaryClusterId: requireUuid(primaryClusterId, "primaryClusterId"),
    protocol: "postgresql",
    tlsPolicySha256: sha256(canonicalJson({
      policy: "exact-postgresql-url-tls-options-v1",
      tlsOptionDigests
    })),
    usernameSha256: sha256(parsed.username)
  }));
}

export function recoveryBrokerConfigDigest({
  recoveryClusterId,
  expectedSourceClusterId,
  buildIdentity,
  trustedPublisherKeys,
  auditTargetIdentity = null
}) {
  const acceptedAuditTargetIdentity = auditTargetIdentity === null
    ? null
    : validateRecoveryAuditTargetIdentity(auditTargetIdentity);
  return sha256(
    canonicalJson({
      auditTargetIdentitySha256: acceptedAuditTargetIdentity === null
        ? null
        : sha256(canonicalJson(acceptedAuditTargetIdentity)),
      auditSchema: "g1_recovery_audit_events_v3",
      buildIdentity: requireText(buildIdentity, "buildIdentity"),
      client: "tideproof-managed-mcp-client-v1",
      database: "tideproof_recovery",
      expectedSourceClusterId: requireUuid(
        expectedSourceClusterId,
        "expectedSourceClusterId"
      ),
      mcpProtocolVersion: "2025-03-26",
      queryTemplateDigest: recoveryQueryTemplateDigest(),
      recoveryClusterId: requireUuid(recoveryClusterId, "recoveryClusterId"),
      tool: "select_query",
      trustedPublisherKeysDigest:
        trustedPublisherKeysDigest(trustedPublisherKeys),
      validator: "tideproof-recovery-row-v2-p256-source-bound",
      version: "tideproof-deterministic-recovery-broker-v3"
    })
  );
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
  if (!match) throw new Error("RECOVERY_QUERY_TEMPLATE_MISMATCH");
  const bindings = Object.freeze({
    recoverySessionId: requireUuid(match[1], "recoverySessionId"),
    tenantId: requireUuid(match[2], "tenantId"),
    subjectBindingHash: requireSha256(match[3], "subjectBindingHash"),
    sourceDigest: requireSha256(match[4], "sourceDigest")
  });
  if (renderRecoveryQuery(bindings) !== text) {
    throw new Error("RECOVERY_QUERY_TEMPLATE_MISMATCH");
  }
  return bindings;
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (
    !relative.startsWith("..") && !path.isAbsolute(relative)
  );
}

export function validatePersistedRecoveryBundleForContinuity({
  destinationPath,
  evidenceRootPath,
  forbiddenRootPath,
  spec,
  persistenceReceipt,
  trustedPublisherKeys
}) {
  const code = "RECOVERY_BUNDLE_PERSISTENCE_REJECTED";
  if (
    typeof destinationPath !== "string" ||
    typeof evidenceRootPath !== "string" ||
    typeof forbiddenRootPath !== "string" ||
    !path.isAbsolute(destinationPath) ||
    !path.isAbsolute(evidenceRootPath) ||
    !path.isAbsolute(forbiddenRootPath) ||
    path.resolve(destinationPath) !== destinationPath ||
    path.resolve(evidenceRootPath) !== evidenceRootPath ||
    path.resolve(forbiddenRootPath) !== forbiddenRootPath ||
    path.dirname(destinationPath) !== evidenceRootPath ||
    path.basename(destinationPath) !==
      `${spec?.runId}.signed-recovery-bundle.json`
  ) {
    throw new Error(code);
  }
  let rootStat;
  let forbidden;
  try {
    rootStat = fs.lstatSync(evidenceRootPath);
    forbidden = fs.realpathSync(forbiddenRootPath);
  } catch (cause) {
    throw new Error(code, { cause });
  }
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : rootStat.uid;
  if (
    fs.realpathSync(evidenceRootPath) !== evidenceRootPath ||
    !rootStat.isDirectory() ||
    rootStat.isSymbolicLink() ||
    rootStat.uid !== expectedUid ||
    (rootStat.mode & 0o777) !== 0o700 ||
    pathIsWithin(evidenceRootPath, forbidden)
  ) {
    throw new Error(code);
  }
  let descriptor;
  let bytes;
  try {
    descriptor = fs.openSync(
      destinationPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    if (
      !before.isFile() ||
      before.uid !== expectedUid ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      before.size < 1 ||
      before.size > RECOVERY_BUNDLE_MAX_BYTES
    ) {
      throw new Error(code);
    }
    bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(destinationPath);
    const currentRoot = fs.lstatSync(evidenceRootPath);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      !after.isFile() ||
      after.uid !== expectedUid ||
      after.nlink !== 1 ||
      (after.mode & 0o777) !== 0o600 ||
      named.dev !== after.dev ||
      named.ino !== after.ino ||
      named.isSymbolicLink() ||
      !named.isFile() ||
      named.uid !== expectedUid ||
      named.nlink !== 1 ||
      (named.mode & 0o777) !== 0o600 ||
      currentRoot.dev !== rootStat.dev ||
      currentRoot.ino !== rootStat.ino ||
      !currentRoot.isDirectory() ||
      currentRoot.isSymbolicLink() ||
      currentRoot.uid !== expectedUid ||
      (currentRoot.mode & 0o777) !== 0o700
    ) {
      throw new Error(code);
    }
  } catch (cause) {
    if (cause?.message === code) throw cause;
    throw new Error(code, { cause });
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  let envelope;
  try {
    envelope = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw new Error(code, { cause });
  }
  const envelopeKeys = [
    "configDigest",
    "runId",
    "schemaVersion",
    "signedBundle",
    "signedBundleSha256",
    "sourceBuildIdentitySha256",
    "sourceCommit",
    "treeDigest"
  ];
  if (
    !exactKeys(envelope, envelopeKeys) ||
    envelope.schemaVersion !== RECOVERY_BUNDLE_ENVELOPE_SCHEMA ||
    bytes.toString("utf8") !== `${canonicalJson(envelope)}\n` ||
    envelope.sourceCommit !== spec.sourceCommit ||
    envelope.treeDigest !== spec.treeDigest ||
    envelope.configDigest !== spec.configDigest ||
    envelope.runId !== spec.runId ||
    envelope.sourceBuildIdentitySha256 !== sha256(spec.sourceBuildIdentity) ||
    envelope.signedBundleSha256 !== sha256(canonicalJson(envelope.signedBundle))
  ) {
    throw new Error(code);
  }
  const signedBundle = verifyRecoveryBundleSourceSignature(
    envelope.signedBundle,
    trustedPublisherKeys
  );
  if (canonicalJson(signedBundle) !== canonicalJson(envelope.signedBundle)) {
    throw new Error(code);
  }
  const receiptKeys = [
    "atomicCreateOnly",
    "bundleDigest",
    "configDigest",
    "creationProtocolObserved",
    "directoryEntrySynced",
    "fileByteLength",
    "fileDataSynced",
    "fileMode",
    "parentDirectoryMode",
    "pathSha256",
    "receiptSha256",
    "rereadVerified",
    "reusedExisting",
    "runId",
    "sameFilesystemAtomicLink",
    "schemaVersion",
    "signatureDigest",
    "signedBundleSha256",
    "sourceBuildIdentitySha256",
    "sourceCommit",
    "treeDigest"
  ];
  const { receiptSha256, ...receiptBody } = persistenceReceipt ?? {};
  const creationObserved = persistenceReceipt?.reusedExisting === false;
  if (
    !exactKeys(persistenceReceipt, receiptKeys) ||
    persistenceReceipt.schemaVersion !== RECOVERY_BUNDLE_PERSISTENCE_SCHEMA ||
    receiptSha256 !== sha256(canonicalJson(receiptBody)) ||
    persistenceReceipt.sourceCommit !== spec.sourceCommit ||
    persistenceReceipt.treeDigest !== spec.treeDigest ||
    persistenceReceipt.configDigest !== spec.configDigest ||
    persistenceReceipt.runId !== spec.runId ||
    persistenceReceipt.sourceBuildIdentitySha256 !==
      envelope.sourceBuildIdentitySha256 ||
    persistenceReceipt.bundleDigest !== signedBundle.bundleDigest ||
    persistenceReceipt.signatureDigest !== signedBundle.signatureDigest ||
    persistenceReceipt.signedBundleSha256 !== envelope.signedBundleSha256 ||
    persistenceReceipt.fileByteLength !== bytes.length ||
    persistenceReceipt.pathSha256 !== sha256(destinationPath) ||
    persistenceReceipt.fileMode !== "0600" ||
    persistenceReceipt.parentDirectoryMode !== "0700" ||
    persistenceReceipt.fileDataSynced !== true ||
    persistenceReceipt.directoryEntrySynced !== true ||
    persistenceReceipt.rereadVerified !== true ||
    typeof persistenceReceipt.reusedExisting !== "boolean" ||
    persistenceReceipt.creationProtocolObserved !== creationObserved ||
    persistenceReceipt.atomicCreateOnly !== creationObserved ||
    persistenceReceipt.sameFilesystemAtomicLink !== creationObserved
  ) {
    throw new Error(code);
  }
  return Object.freeze({
    persistenceReceipt: Object.freeze({ ...persistenceReceipt }),
    signedBundle,
    signedBundleSha256: envelope.signedBundleSha256
  });
}
