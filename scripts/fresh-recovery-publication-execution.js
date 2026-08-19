import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  validateFreshPrimaryCredentialBundle
} from "./bootstrap-fresh-primary.js";
import {
  validateFreshRecoveryPublisherSecret
} from "./lib/fresh-recovery-publisher-key.js";
import {
  buildPrivateRecoveryQueryBinding,
  validatePrimaryClusterMapping
} from "./lib/private-recovery-query-binding.js";
import {
  createCommittedRecoveryPublisherSigner
} from "./lib/recovery-publisher-key.js";
import {
  CockroachManagedMcpRecoveryClient
} from "../src/cloud/managed-mcp-client.js";
import {
  parseStrictJson
} from "../src/cloud/strict-json.js";
import {
  normalizedRecoverySourceReceiptForContinuity
} from "../src/cloud/recovery-continuity-identity.js";
import {
  assertRecoveryPublisherTrustRootWriteDenied,
  assertRecoveryRunnerBaseTableReadsDenied,
  assertSeparatedDatabaseEndpoints,
  canonicalRecoveryAttempt,
  principalBindingHash,
  resolveCommittedRecoveryPublisherTrustRoot,
  resolveCommittedRecoverySourceReceipt,
  trustedPublisherKeysDigest
} from "../src/cloud/recovery-broker.js";
import {
  RecoveryPublisher
} from "../src/cloud/recovery-security.js";
import {
  managedMcpLogicalRequest
} from "../src/cloud/managed-mcp-client.js";
import {
  normalizedRecoveryBundleFor,
  recoverySourceBindingDigestFor,
  renderRecoveryQuery,
  validateRecoveryRow
} from "../src/cloud/recovery-store.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SYNTHETIC_PRINCIPAL = "principal://tideproof-demo-successor";
const PRIMARY_HOST =
  "prooftoact-gate2-32394.j77.aws-us-east-1.cockroachlabs.cloud";
const PRIMARY_PROVIDER_CLUSTER_ID =
  "59294a51-f2d3-4275-b893-7ddb530829c7";
const PRIMARY_SQL_CLUSTER_ID =
  "9fad7a1e-e440-4989-3823-04191b7f3f3b";
const RECOVERY_HOST =
  "tideproof-recovery-30570.j77.aws-us-east-1.cockroachlabs.cloud";
const RECOVERY_PROVIDER_CLUSTER_ID =
  "24f93c44-fa61-467c-bd3f-a1153618c309";
const RECOVERY_SQL_CLUSTER_ID =
  "9fad7a1e-e440-4989-383b-6a191b947e6e";
const RECOVERY_PUBLISHER_USER = "tp_recovery_publisher_user";
const MAX_SECRET_BYTES = 64 * 1024;
const FRESH_PUBLICATION_TTL_MS = 45 * 60 * 1_000;
const PRIMARY_MINIMUM_REMAINING_MS = 10 * 60 * 1_000;
const PROVIDER_MINIMUM_REMAINING_MS = 5 * 60 * 1_000;

export function freshRecoveryPublicationProviderBinding() {
  return Object.freeze({
    primaryProviderClusterId: PRIMARY_PROVIDER_CLUSTER_ID,
    primarySqlClusterId: PRIMARY_SQL_CLUSTER_ID,
    recoveryProviderClusterId: RECOVERY_PROVIDER_CLUSTER_ID,
    recoverySqlClusterId: RECOVERY_SQL_CLUSTER_ID
  });
}

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalBytes(value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= MAX_SECRET_BYTES,
    "FRESH_RECOVERY_PUBLICATION_CANONICAL_RECORD_REJECTED");
  return bytes;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function freshPublicationExpiryPolicy() {
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-recovery-publication-expiry-policy.v1",
    status: "FRESH_PUBLICATION_ONLY",
    canonicalRecoveryTtlMs: 30 * 60 * 1_000,
    freshPublicationTtlMs: FRESH_PUBLICATION_TTL_MS,
    primaryMinimumRemainingMs: PRIMARY_MINIMUM_REMAINING_MS,
    providerMinimumRemainingMs: PROVIDER_MINIMUM_REMAINING_MS
  });
}

function freshPublicationAttempt(value) {
  const code = "FRESH_RECOVERY_PUBLICATION_EXPIRY_REJECTED";
  const sourceCommitMs = Date.parse(value?.sourceCommitTs);
  const canonicalExpiryMs = Date.parse(value?.expiresAt);
  requireCondition(exactKeys(value, [
    "bindingSha256", "expiresAt", "recoverySessionId", "snapshotVersion",
    "sourceCommitTs"
  ]) && Number.isSafeInteger(sourceCommitMs) && sourceCommitMs > 0 &&
    value.sourceCommitTs === new Date(sourceCommitMs).toISOString() &&
    canonicalExpiryMs === sourceCommitMs + 30 * 60 * 1_000, code);
  return Object.freeze({
    ...value,
    expiresAt: new Date(sourceCommitMs + FRESH_PUBLICATION_TTL_MS).toISOString()
  });
}

export function validateFreshPublicationDatabaseClock({
  attempt,
  databaseNow,
  minimumRemainingMs,
  previousDatabaseNow = null
}) {
  const code = "FRESH_RECOVERY_PUBLICATION_DATABASE_CLOCK_REJECTED";
  const databaseMs = Date.parse(databaseNow);
  const sourceMs = Date.parse(attempt?.sourceCommitTs);
  const expiryMs = Date.parse(attempt?.expiresAt);
  const previousMs = previousDatabaseNow === null
    ? null
    : Date.parse(previousDatabaseNow);
  requireCondition(Number.isSafeInteger(databaseMs) &&
    databaseNow === new Date(databaseMs).toISOString() &&
    Number.isSafeInteger(sourceMs) &&
    attempt.sourceCommitTs === new Date(sourceMs).toISOString() &&
    Number.isSafeInteger(expiryMs) &&
    attempt.expiresAt === new Date(expiryMs).toISOString() &&
    expiryMs === sourceMs + FRESH_PUBLICATION_TTL_MS &&
    Number.isSafeInteger(minimumRemainingMs) &&
    [PRIMARY_MINIMUM_REMAINING_MS, PROVIDER_MINIMUM_REMAINING_MS]
      .includes(minimumRemainingMs) &&
    databaseMs >= sourceMs && expiryMs - databaseMs >= minimumRemainingMs &&
    (previousMs === null || Number.isSafeInteger(previousMs) &&
      previousDatabaseNow === new Date(previousMs).toISOString() &&
      databaseMs >= previousMs), code);
  return Object.freeze({
    databaseObservedAt: databaseNow,
    remainingWindowMs: expiryMs - databaseMs
  });
}

export async function executeFreshPublicationProviderAction({
  attempt,
  dispatch,
  previousDatabaseNow = null,
  readDatabaseNow
}) {
  requireCondition(typeof dispatch === "function" &&
    typeof readDatabaseNow === "function",
  "FRESH_RECOVERY_PUBLICATION_PROVIDER_ACTION_REJECTED");
  const clock = validateFreshPublicationDatabaseClock({
    attempt,
    databaseNow: await readDatabaseNow(),
    minimumRemainingMs: PROVIDER_MINIMUM_REMAINING_MS,
    previousDatabaseNow
  });
  return Object.freeze({ clock, result: await dispatch() });
}

function parseJsonSecret(value, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    Buffer.byteLength(value, "utf8") <= MAX_SECRET_BYTES, code);
  try {
    return parseStrictJson(value, {
      duplicateCode: code,
      invalidCode: code
    });
  } catch (cause) {
    reject(code, cause);
  }
}

function sourceBinding(value) {
  const code = "FRESH_RECOVERY_PUBLICATION_SOURCE_BINDING_REJECTED";
  requireCondition(exactKeys(value, [
    "authorityEvidenceBindingSha256",
    "evidenceId",
    "incidentId",
    "operationId",
    "requestDigest",
    "resourceId",
    "runId",
    "selectedEvidenceBindingSha256",
    "tenantId"
  ]) && [
    value.evidenceId,
    value.incidentId,
    value.operationId,
    value.runId,
    value.tenantId
  ].every((item) => UUID.test(item ?? "")) &&
    [
      value.authorityEvidenceBindingSha256,
      value.requestDigest,
      value.selectedEvidenceBindingSha256
    ].every((item) => HEX_64.test(item ?? "")) &&
    typeof value.resourceId === "string" && value.resourceId.length > 0 &&
    value.resourceId.length <= 160 && !/[\u0000\r\n]/u.test(value.resourceId),
  code);
  return Object.freeze({ ...value });
}

export function validateFreshRecoveryPublicationBinding(value) {
  const code = "FRESH_RECOVERY_PUBLICATION_BINDING_REJECTED";
  requireCondition(exactKeys(value, [
    "billingAuthorizationSha256",
    "credentialSecretValueSha256",
    "mcpSecretValueSha256",
    "operationId",
    "primaryClusterMapping",
    "primaryClusterMappingReceiptSha256",
    "primaryProviderClusterId",
    "primarySqlClusterId",
    "publisherSecretValueSha256",
    "recoveryProviderClusterId",
    "recoverySecurityReceiptSha256",
    "recoverySqlClusterId",
    "signerSecretValueSha256",
    "sourceBinding",
    "sourceBindingSha256",
    "sourceCommit",
    "treeDigest"
  ]) && UUID.test(value.operationId ?? "") &&
    value.primaryProviderClusterId === PRIMARY_PROVIDER_CLUSTER_ID &&
    value.primarySqlClusterId === PRIMARY_SQL_CLUSTER_ID &&
    value.recoveryProviderClusterId === RECOVERY_PROVIDER_CLUSTER_ID &&
    value.recoverySqlClusterId === RECOVERY_SQL_CLUSTER_ID &&
    value.primaryProviderClusterId !== value.recoveryProviderClusterId &&
    value.primarySqlClusterId !== value.recoverySqlClusterId &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") && [
      value.credentialSecretValueSha256,
      value.billingAuthorizationSha256,
      value.mcpSecretValueSha256,
      value.primaryClusterMappingReceiptSha256,
      value.publisherSecretValueSha256,
      value.recoverySecurityReceiptSha256,
      value.signerSecretValueSha256,
      value.sourceBindingSha256
    ].every((item) => HEX_64.test(item ?? "")), code);
  const acceptedSource = sourceBinding(value.sourceBinding);
  const primaryClusterMapping = validatePrimaryClusterMapping(
    value.primaryClusterMapping
  );
  requireCondition(value.sourceBindingSha256 === sha256(canonicalBytes(
    acceptedSource
  )) && primaryClusterMapping.receiptSha256 ===
      value.primaryClusterMappingReceiptSha256 &&
    primaryClusterMapping.providerClusterId ===
      value.primaryProviderClusterId &&
    primaryClusterMapping.sqlClusterId === value.primarySqlClusterId &&
    primaryClusterMapping.sourceCommit === value.sourceCommit &&
    primaryClusterMapping.treeDigest === value.treeDigest, code);
  return Object.freeze({
    ...value,
    primaryClusterMapping,
    sourceBinding: acceptedSource
  });
}

function secretReadback(value, expectedSha256, code) {
  requireCondition(exactKeys(value, [
    "createdAt",
    "secretArnSha256",
    "secretValue",
    "secretValueSha256",
    "secretVersionIdSha256"
  ]) && typeof value.secretValue === "string" &&
    value.secretValue.length > 0 &&
    Buffer.byteLength(value.secretValue, "utf8") <= MAX_SECRET_BYTES &&
    HEX_64.test(value.secretArnSha256 ?? "") &&
    HEX_64.test(value.secretVersionIdSha256 ?? "") &&
    value.secretValueSha256 === expectedSha256 &&
    sha256(Buffer.from(value.secretValue, "utf8")) === expectedSha256 &&
    Number.isFinite(Date.parse(value.createdAt)), code);
  return value;
}

function runtimeConnectionString(username, password) {
  const url = new URL(`postgresql://placeholder@${PRIMARY_HOST}:26257/tideproof`);
  url.username = username;
  url.password = password;
  url.searchParams.set("sslmode", "verify-full");
  return url.toString();
}

function validatePublisherConnectionString(value) {
  const code = "FRESH_RECOVERY_PUBLICATION_PUBLISHER_URL_REJECTED";
  let url;
  try {
    url = new URL(value);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(url.protocol === "postgresql:" &&
    decodeURIComponent(url.username) === RECOVERY_PUBLISHER_USER &&
    decodeURIComponent(url.password).length >= 24 &&
    url.hostname === RECOVERY_HOST && url.port === "26257" &&
    url.pathname === "/tideproof_recovery" &&
    url.searchParams.size === 1 &&
    url.searchParams.get("sslmode") === "verify-full" &&
    url.hash === "", code);
  return value;
}

function normalizeMaterial(material, binding) {
  const code = "FRESH_RECOVERY_PUBLICATION_SECRET_MATERIAL_REJECTED";
  requireCondition(exactKeys(material, [
    "credential", "mcp", "publisher", "signer"
  ]), code);
  const credentialReadback = secretReadback(
    material.credential, binding.credentialSecretValueSha256, code
  );
  const signerReadback = secretReadback(
    material.signer, binding.signerSecretValueSha256, code
  );
  const publisherReadback = secretReadback(
    material.publisher, binding.publisherSecretValueSha256, code
  );
  const mcpReadback = secretReadback(
    material.mcp, binding.mcpSecretValueSha256, code
  );
  const credential = validateFreshPrimaryCredentialBundle(parseJsonSecret(
    credentialReadback.secretValue,
    "FRESH_RECOVERY_PUBLICATION_CREDENTIAL_BUNDLE_REJECTED"
  ));
  const rawSigner = parseJsonSecret(
    signerReadback.secretValue,
    "FRESH_RECOVERY_PUBLICATION_SIGNER_SECRET_REJECTED"
  );
  const signer = validateFreshRecoveryPublisherSecret(rawSigner, {
    operationId: binding.operationId,
    sourceCommit: binding.sourceCommit,
    treeDigest: binding.treeDigest
  });
  requireCondition(signer.secretBytesSha256 ===
    binding.signerSecretValueSha256 &&
    typeof mcpReadback.secretValue === "string" &&
    mcpReadback.secretValue.length >= 24 &&
    mcpReadback.secretValue.length <= 4096 &&
    !/[\u0000-\u0020\u007f]/u.test(mcpReadback.secretValue), code);
  validatePublisherConnectionString(publisherReadback.secretValue);
  return Object.freeze({
    credential,
    credentialReadback,
    mcpApiKey: mcpReadback.secretValue,
    mcpReadback,
    publisherConnectionString: publisherReadback.secretValue,
    publisherReadback,
    signer,
    signerReadback
  });
}

function rowsFromManagedMcpResult(result) {
  const code = "FRESH_RECOVERY_PUBLICATION_MCP_RESPONSE_REJECTED";
  const hasRows = plainObject(result) && Object.hasOwn(result, "rows");
  const hasContent = plainObject(result) && Object.hasOwn(result, "content");
  requireCondition(hasRows !== hasContent, code);
  if (hasRows) {
    requireCondition(exactKeys(result, ["rows"]) && Array.isArray(result.rows),
      code);
    return result.rows;
  }
  requireCondition(exactKeys(result, ["content"]) &&
    Array.isArray(result.content) && result.content.length === 1 &&
    exactKeys(result.content[0], ["text", "type"]) &&
    result.content[0].type === "text" &&
    typeof result.content[0].text === "string", code);
  let parsed;
  try {
    parsed = parseStrictJson(result.content[0].text, {
      duplicateCode: code,
      invalidCode: code
    });
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(exactKeys(parsed, ["rows"]) && Array.isArray(parsed.rows),
    code);
  return parsed.rows;
}

function bundleFromRow(row) {
  return normalizedRecoveryBundleFor({
    tenantId: row.tenant_id,
    recoverySessionId: row.recovery_session_id,
    subjectBindingHash: row.subject_binding_hash,
    schemaVersion: Number(row.schema_version),
    snapshotVersion: Number(row.snapshot_version),
    sourceClusterId: row.source_cluster_id,
    sourceCommitTs: row.source_commit_ts,
    sourceDigest: row.source_digest,
    bundleDigest: row.bundle_digest,
    policyVersion: row.policy_version,
    publisherKeyId: row.publisher_key_id,
    publisherVersion: row.publisher_version,
    signatureAlgorithm: row.signature_algorithm,
    sourceSignatureBase64: row.source_signature_base64,
    signatureDigest: row.signature_digest,
    checkpointSummary: row.checkpoint_summary,
    evidenceSummary: row.evidence_summary,
    conflictSummary: row.conflict_summary,
    receiptSummary: row.receipt_summary,
    authorityTransferred: row.authority_transferred,
    requiresFreshAuthorization: row.requires_fresh_authorization,
    expiresAt: row.expires_at
  });
}

export function persistFreshRecoveryPublicationBundle({
  destinationPath,
  evidenceRootPath,
  forbiddenRootPath,
  signedBundle,
  spec
}) {
  const code = "FRESH_RECOVERY_PUBLICATION_BUNDLE_PERSISTENCE_REJECTED";
  requireCondition(path.isAbsolute(destinationPath) &&
    path.isAbsolute(evidenceRootPath) && path.isAbsolute(forbiddenRootPath) &&
    exactKeys(spec, [
      "operationId", "runId", "sourceCommit", "treeDigest"
    ]) && UUID.test(spec.operationId ?? "") && UUID.test(spec.runId ?? "") &&
    HEX_40.test(spec.sourceCommit ?? "") && HEX_40.test(spec.treeDigest ?? "") &&
    plainObject(signedBundle) && signedBundle.tenantId !== undefined &&
    signedBundle.recoverySessionId !== undefined,
  code);
  let root;
  let forbidden;
  try {
    root = fs.realpathSync(evidenceRootPath);
    forbidden = fs.realpathSync(forbiddenRootPath);
  } catch (cause) {
    reject(code, cause);
  }
  const rootStat = fs.lstatSync(root);
  requireCondition(root === evidenceRootPath && rootStat.isDirectory() &&
    !rootStat.isSymbolicLink() && rootStat.uid === process.getuid() &&
    (rootStat.mode & 0o077) === 0 &&
    path.relative(forbidden, root).startsWith("..") &&
    path.dirname(destinationPath) === root &&
    path.basename(destinationPath) ===
      `${spec.runId}.signed-recovery-bundle.json`,
  code);
  const bytes = canonicalBytes(signedBundle);
  let created = false;
  if (!fs.existsSync(destinationPath)) {
    let descriptor;
    try {
      descriptor = fs.openSync(destinationPath,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY |
          fs.constants.O_NOFOLLOW, 0o600);
      requireCondition(fs.writeSync(descriptor, bytes) === bytes.length, code);
      fs.fsyncSync(descriptor);
      created = true;
    } catch (cause) {
      if (cause?.message === code) throw cause;
      reject(code, cause);
    } finally {
      if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
    }
  }
  const observed = fs.readFileSync(destinationPath);
  const stat = fs.lstatSync(destinationPath);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.uid === process.getuid() && (stat.mode & 0o077) === 0 &&
    observed.equals(bytes), code);
  return Object.freeze({
    bundle: Object.freeze({ ...signedBundle }),
    receipt: Object.freeze({
      schemaVersion: "prooftoact.fresh-recovery-bundle-persistence.v1",
      status: created ? "CREATED" : "EXACT_REPLAY",
      bundleSha256: sha256(bytes),
      operationId: spec.operationId,
      runId: spec.runId,
      sourceCommit: spec.sourceCommit,
      treeDigest: spec.treeDigest
    })
  });
}

function defaultDependencies() {
  return Object.freeze({
    assertRecoveryPublisherTrustRootWriteDenied,
    assertRecoveryRunnerBaseTableReadsDenied,
    assertSeparatedDatabaseEndpoints,
    createManagedMcpClient: (apiKey) =>
      new CockroachManagedMcpRecoveryClient({
        apiKey,
        clusterId: RECOVERY_PROVIDER_CLUSTER_ID
      }),
    createPublisher: (connectionString) =>
      new RecoveryPublisher({ connectionString }),
    persistBundle: persistFreshRecoveryPublicationBundle,
    resolveCommittedRecoveryPublisherTrustRoot,
    resolveCommittedRecoverySourceReceipt
  });
}

function normalizeDependencies(value) {
  const expected = [
    "assertRecoveryPublisherTrustRootWriteDenied",
    "assertRecoveryRunnerBaseTableReadsDenied",
    "assertSeparatedDatabaseEndpoints",
    "createManagedMcpClient",
    "createPublisher",
    "persistBundle",
    "resolveCommittedRecoveryPublisherTrustRoot",
    "resolveCommittedRecoverySourceReceipt"
  ];
  requireCondition(exactKeys(value, expected) &&
    expected.every((name) => typeof value[name] === "function"),
  "FRESH_RECOVERY_PUBLICATION_DEPENDENCIES_REJECTED");
  return value;
}

export function createFreshRecoveryPublicationExecution({
  binding: rawBinding,
  bundlePath,
  dependencies = defaultDependencies(),
  evidenceRootPath,
  forbiddenRootPath,
  material: rawMaterial,
  spec
}) {
  const binding = validateFreshRecoveryPublicationBinding(rawBinding);
  const material = normalizeMaterial(rawMaterial, binding);
  const resolved = normalizeDependencies(dependencies);
  requireCondition(typeof bundlePath === "string" &&
    typeof evidenceRootPath === "string" &&
    typeof forbiddenRootPath === "string" && plainObject(spec) &&
    spec.sourceCommit === binding.sourceCommit &&
    spec.treeDigest === binding.treeDigest &&
    spec.runId === binding.sourceBinding.runId &&
    spec.operationId === binding.operationId &&
    exactKeys(spec, ["operationId", "runId", "sourceCommit", "treeDigest"]),
  "FRESH_RECOVERY_PUBLICATION_CONFIGURATION_REJECTED");

  let prepared = null;
  let appendReceipt = null;
  let replayReceipt = null;
  let managedMcpPlan = null;
  let managedMcpQuery = null;
  let lastRecoveryDatabaseObservedAt = null;

  return Object.freeze({
    async prepare() {
      requireCondition(prepared === null,
        "FRESH_RECOVERY_PUBLICATION_PREPARE_REPLAY_REJECTED");
      const primarySourceUrl = runtimeConnectionString(
        "tp_recovery_source_user",
        material.credential.passwords.tp_recovery_source_user
      );
      const primaryAuditUrl = runtimeConnectionString(
        "tp_recovery_audit_user",
        material.credential.passwords.tp_recovery_audit_user
      );
      resolved.assertSeparatedDatabaseEndpoints({
        primaryConnectionString: primarySourceUrl,
        primaryAuditConnectionString: primaryAuditUrl,
        recoveryConnectionString: material.publisherConnectionString,
        expectedPrimaryHostname: PRIMARY_HOST,
        expectedRecoveryHostname: RECOVERY_HOST,
        primaryClusterId: PRIMARY_PROVIDER_CLUSTER_ID,
        recoveryClusterId: RECOVERY_PROVIDER_CLUSTER_ID
      });
      const denials = await Promise.all([
        resolved.assertRecoveryPublisherTrustRootWriteDenied({
          connectionString: primarySourceUrl,
          credentialLabel: "recovery-source"
        }),
        resolved.assertRecoveryPublisherTrustRootWriteDenied({
          connectionString: primaryAuditUrl,
          credentialLabel: "recovery-audit"
        }),
        resolved.assertRecoveryRunnerBaseTableReadsDenied({
          connectionString: primarySourceUrl,
          credentialLabel: "recovery-source"
        }),
        resolved.assertRecoveryRunnerBaseTableReadsDenied({
          connectionString: primaryAuditUrl,
          credentialLabel: "recovery-audit"
        })
      ]);
      requireCondition(denials.every((item) => item?.denied === true &&
        item.sqlstate === "42501"),
      "FRESH_RECOVERY_PUBLICATION_PRIMARY_DENIAL_REJECTED");
      const rawSourceReceipt = await resolved.resolveCommittedRecoverySourceReceipt({
        binding: binding.sourceBinding,
        connectionString: primarySourceUrl
      });
      const recoverySourceReceipt =
        normalizedRecoverySourceReceiptForContinuity(rawSourceReceipt);
      const signer = createCommittedRecoveryPublisherSigner({
        privateKeyPkcs8Base64: material.signer.privateKeyPkcs8Base64,
        trustRootCommitment: material.signer.trustRootCommitment,
        trustRootJson: material.signer.trustRootJson
      });
      const publisherKeySetDigest = trustedPublisherKeysDigest(
        signer.trustedPublisherKeys
      );
      requireCondition(publisherKeySetDigest ===
        material.signer.publisherKeySetDigest,
      "FRESH_RECOVERY_PUBLICATION_SIGNER_COMMITMENT_REJECTED");
      await resolved.resolveCommittedRecoveryPublisherTrustRoot({
        connectionString: primaryAuditUrl,
        publisherKeySetDigest,
        trustRootCommitment: signer.trustRootCommitment
      });
      const subjectBindingHash = principalBindingHash(SYNTHETIC_PRINCIPAL);
      const sourceDigest = recoverySourceBindingDigestFor({
        tenantId: recoverySourceReceipt.tenant_id,
        runId: recoverySourceReceipt.run_id,
        incidentId: recoverySourceReceipt.incident_id,
        evidenceDigest: recoverySourceReceipt.evidence_digest,
        resourceId: recoverySourceReceipt.resource_id,
        operationId: recoverySourceReceipt.operation_id,
        requestDigest: recoverySourceReceipt.request_digest,
        proposalDigest: recoverySourceReceipt.proposal_digest,
        logicalActionDigest: recoverySourceReceipt.logical_action_digest,
        authorizationEpoch: Number(recoverySourceReceipt.authorization_epoch),
        logicalAuthorityKeySha256:
          recoverySourceReceipt.logical_authority_key_sha256,
        authorizationBindingSha256:
          recoverySourceReceipt.authorization_binding_sha256,
        authorityEvidenceBindingSha256:
          recoverySourceReceipt.authority_evidence_binding_sha256,
        selectedEvidenceBindingSha256:
          recoverySourceReceipt.selected_evidence_binding_sha256,
        outcome: recoverySourceReceipt.outcome
      });
      const canonicalAttempt = canonicalRecoveryAttempt({
        tenantId: recoverySourceReceipt.tenant_id,
        subjectBindingHash,
        sourceDigest,
        sourceCommitTs: recoverySourceReceipt.recorded_at
      });
      const attempt = freshPublicationAttempt(canonicalAttempt);
      const expiryPolicy = freshPublicationExpiryPolicy();
      const expiryPolicySha256 = sha256(canonicalBytes(expiryPolicy));
      const primaryClock = validateFreshPublicationDatabaseClock({
        attempt,
        databaseNow: rawSourceReceipt.database_now,
        minimumRemainingMs: PRIMARY_MINIMUM_REMAINING_MS
      });
      const candidate = signer.sign({
        tenantId: recoverySourceReceipt.tenant_id,
        recoverySessionId: attempt.recoverySessionId,
        subjectBindingHash,
        schemaVersion: 2,
        snapshotVersion: attempt.snapshotVersion,
        sourceClusterId: PRIMARY_PROVIDER_CLUSTER_ID,
        sourceCommitTs: attempt.sourceCommitTs,
        sourceDigest,
        policyVersion: rawSourceReceipt.policy_version,
        checkpointSummary: {
          checkpointVersion: 1,
          failedAgent: rawSourceReceipt.agent_id,
          phase: "successor-context-recovery",
          scenario: "synthetic-highwater"
        },
        evidenceSummary: {
          admittedCount: rawSourceReceipt.admittedCount,
          classification: "synthetic",
          evidenceDigest: recoverySourceReceipt.evidence_digest
        },
        conflictSummary: {
          unresolvedCount: rawSourceReceipt.unresolvedCount,
          status: rawSourceReceipt.unresolvedCount === 0
            ? "none"
            : "quarantined"
        },
        receiptSummary: {
          durableIntentPresent: true,
          outcome: recoverySourceReceipt.outcome,
          reason: rawSourceReceipt.reason,
          resourceLabel: recoverySourceReceipt.resource_id
        },
        expiresAt: attempt.expiresAt
      });
      const persisted = resolved.persistBundle({
        destinationPath: bundlePath,
        evidenceRootPath,
        forbiddenRootPath,
        signedBundle: candidate,
        spec,
        trustedPublisherKeys: signer.trustedPublisherKeys
      });
      requireCondition(persisted?.bundle?.bundleDigest ===
        candidate.bundleDigest,
      "FRESH_RECOVERY_PUBLICATION_BUNDLE_PERSISTENCE_REJECTED");
      const privateRecoveryQueryBinding = buildPrivateRecoveryQueryBinding({
        billingAuthorizationSha256: binding.billingAuthorizationSha256,
        expectedBundleDigest: persisted.bundle.bundleDigest,
        expectedSourceClusterId: binding.primaryProviderClusterId,
        expectedSourceSqlClusterId: binding.primarySqlClusterId,
        expiresAt: persisted.bundle.expiresAt,
        operationId: binding.operationId,
        primaryClusterMapping: binding.primaryClusterMapping,
        primaryClusterMappingReceiptSha256:
          binding.primaryClusterMappingReceiptSha256,
        publisherKeyId: persisted.bundle.publisherKeyId,
        publisherPublicKeySpkiBase64:
          signer.trustedPublisherKeys[persisted.bundle.publisherKeyId],
        recoveryClusterId: binding.recoveryProviderClusterId,
        recoverySessionId: persisted.bundle.recoverySessionId,
        sourceCommit: binding.sourceCommit,
        sourceCommitTs: persisted.bundle.sourceCommitTs,
        sourceDigest: persisted.bundle.sourceDigest,
        subjectBindingHash: persisted.bundle.subjectBindingHash,
        tenantId: persisted.bundle.tenantId,
        treeDigest: binding.treeDigest
      });
      prepared = Object.freeze({
        attempt,
        bundle: persisted.bundle,
        expiryPolicy,
        expiryPolicySha256,
        mcpApiKey: material.mcpApiKey,
        persistenceReceipt: persisted.receipt,
        publisherConnectionString: material.publisherConnectionString,
        privateRecoveryQueryBinding,
        primaryDatabaseClock: primaryClock,
        recoverySourceReceipt,
        signer,
        sourceDigest,
        subjectBindingHash
      });
      return Object.freeze({
        schemaVersion: "prooftoact.fresh-recovery-publication-preparation.v1",
        status: "PREPARED",
        authorityTransferred: false,
        bundleDigest: prepared.bundle.bundleDigest,
        expiresAt: prepared.bundle.expiresAt,
        expiryPolicy,
        expiryPolicySha256,
        persistenceReceiptSha256: sha256(canonicalBytes(persisted.receipt)),
        privateRecoveryQueryBinding,
        privateRecoveryQueryBindingSha256:
          privateRecoveryQueryBinding.bindingSha256,
        publisherKeySetDigest,
        primaryDatabaseObservedAt: primaryClock.databaseObservedAt,
        primaryRemainingWindowMs: primaryClock.remainingWindowMs,
        recoverySessionId: attempt.recoverySessionId,
        requiresFreshAuthorization: true,
        sourceDigest,
        sourceReceiptSha256: sha256(canonicalBytes(rawSourceReceipt))
      });
    },

    async append() {
      requireCondition(prepared !== null && appendReceipt === null,
        "FRESH_RECOVERY_PUBLICATION_APPEND_STATE_REJECTED");
      const publisher = resolved.createPublisher(
        prepared.publisherConnectionString
      );
      requireCondition(typeof publisher?.databaseNow === "function" &&
        typeof publisher?.appendSignedBundle === "function",
      "FRESH_RECOVERY_PUBLICATION_PUBLISHER_REJECTED");
      const guarded = await executeFreshPublicationProviderAction({
        attempt: prepared.attempt,
        dispatch: () => publisher.appendSignedBundle(prepared.bundle),
        previousDatabaseNow: lastRecoveryDatabaseObservedAt,
        readDatabaseNow: () => publisher.databaseNow()
      });
      const { clock } = guarded;
      lastRecoveryDatabaseObservedAt = clock.databaseObservedAt;
      appendReceipt = guarded.result;
      requireCondition(["bundle_appended", "bundle_replay", "bundle_present"]
        .includes(appendReceipt?.outcome) &&
        appendReceipt.bundleDigest === prepared.bundle.bundleDigest,
      "FRESH_RECOVERY_PUBLICATION_APPEND_REJECTED");
      return Object.freeze({
        schemaVersion: "prooftoact.fresh-recovery-publication-append.v1",
        status: "CONFIRMED",
        bundleDigest: appendReceipt.bundleDigest,
        commit: appendReceipt.commit,
        databaseObservedAt: clock.databaseObservedAt,
        expiryPolicySha256: prepared.expiryPolicySha256,
        remainingWindowMs: clock.remainingWindowMs,
        outcome: appendReceipt.outcome
      });
    },

    async replay() {
      requireCondition(appendReceipt !== null && replayReceipt === null,
        "FRESH_RECOVERY_PUBLICATION_REPLAY_STATE_REJECTED");
      const publisher = resolved.createPublisher(
        prepared.publisherConnectionString
      );
      requireCondition(typeof publisher?.databaseNow === "function" &&
        typeof publisher?.appendSignedBundle === "function",
      "FRESH_RECOVERY_PUBLICATION_PUBLISHER_REJECTED");
      const guarded = await executeFreshPublicationProviderAction({
        attempt: prepared.attempt,
        dispatch: () => publisher.appendSignedBundle(prepared.bundle),
        previousDatabaseNow: lastRecoveryDatabaseObservedAt,
        readDatabaseNow: () => publisher.databaseNow()
      });
      const { clock } = guarded;
      lastRecoveryDatabaseObservedAt = clock.databaseObservedAt;
      replayReceipt = guarded.result;
      requireCondition(replayReceipt?.outcome === "bundle_replay" &&
        replayReceipt.bundleDigest === prepared.bundle.bundleDigest,
      "FRESH_RECOVERY_PUBLICATION_REPLAY_REJECTED");
      return Object.freeze({
        schemaVersion: "prooftoact.fresh-recovery-publication-replay.v1",
        status: "CONFIRMED_REPLAY",
        bundleDigest: replayReceipt.bundleDigest,
        commit: replayReceipt.commit,
        databaseObservedAt: clock.databaseObservedAt,
        expiryPolicySha256: prepared.expiryPolicySha256,
        remainingWindowMs: clock.remainingWindowMs,
        outcome: replayReceipt.outcome
      });
    },

    planManagedMcp() {
      requireCondition(replayReceipt !== null && managedMcpPlan === null,
        "FRESH_RECOVERY_PUBLICATION_MCP_PLAN_STATE_REJECTED");
      managedMcpQuery = renderRecoveryQuery({
        recoverySessionId: prepared.attempt.recoverySessionId,
        tenantId: prepared.recoverySourceReceipt.tenant_id,
        subjectBindingHash: prepared.subjectBindingHash,
        sourceDigest: prepared.sourceDigest
      });
      const logicalRequest = managedMcpLogicalRequest({
        clusterId: RECOVERY_PROVIDER_CLUSTER_ID,
        query: managedMcpQuery
      });
      managedMcpPlan = Object.freeze({
        schemaVersion:
          "prooftoact.fresh-recovery-publication-mcp-plan.v1",
        status: "PLANNED_READ_ONLY_QUERY",
        bundleDigest: prepared.bundle.bundleDigest,
        database: "tideproof_recovery",
        logicalRequestSha256: sha256(canonicalJson(logicalRequest)),
        querySha256: sha256(managedMcpQuery),
        recoveryClusterId: RECOVERY_PROVIDER_CLUSTER_ID,
        recoverySessionId: prepared.attempt.recoverySessionId,
        sourceDigest: prepared.sourceDigest,
        subjectBindingSha256: prepared.subjectBindingHash,
        tenantId: prepared.recoverySourceReceipt.tenant_id,
        toolName: "select_query"
      });
      return managedMcpPlan;
    },

    async verifyManagedMcp({
      beforeExternalAction,
      durablePlanReadbackSha256,
      plannedRequestSha256
    } = {}) {
      requireCondition(replayReceipt !== null && managedMcpPlan !== null &&
        typeof beforeExternalAction === "function" &&
        HEX_64.test(durablePlanReadbackSha256 ?? "") &&
        plannedRequestSha256 === sha256(canonicalBytes(managedMcpPlan)),
        "FRESH_RECOVERY_PUBLICATION_MCP_STATE_REJECTED");
      const clockPublisher = resolved.createPublisher(
        prepared.publisherConnectionString
      );
      requireCondition(typeof clockPublisher?.databaseNow === "function",
        "FRESH_RECOVERY_PUBLICATION_PUBLISHER_REJECTED");
      const clock = validateFreshPublicationDatabaseClock({
        attempt: prepared.attempt,
        databaseNow: await clockPublisher.databaseNow(),
        minimumRemainingMs: PROVIDER_MINIMUM_REMAINING_MS,
        previousDatabaseNow: lastRecoveryDatabaseObservedAt
      });
      lastRecoveryDatabaseObservedAt = clock.databaseObservedAt;
      const client = resolved.createManagedMcpClient(prepared.mcpApiKey);
      const expectedActions = Object.freeze([
        "MCP_INITIALIZE",
        "MCP_INITIALIZED_NOTIFICATION",
        "MCP_TOOLS_CALL",
        "MCP_SESSION_DELETE"
      ]);
      const guardReceipts = [];
      const guardedDispatch = async (externalAction) => {
        const code = "FRESH_RECOVERY_PUBLICATION_MCP_GUARD_REJECTED";
        requireCondition(externalAction ===
          expectedActions[guardReceipts.length], code);
        const guard = await beforeExternalAction(Object.freeze({
          externalAction,
          plannedRequestSha256
        }));
        requireCondition(exactKeys(guard, [
          "externalAction",
          "planTransitionSha256",
          "plannedRequestSha256",
          "schemaVersion",
          "status",
          "strongReadbackSha256"
        ]) && guard.schemaVersion ===
            "prooftoact.fresh-recovery-mcp-dispatch-guard.v1" &&
          guard.status === "DURABLE_PLAN_STRONGLY_RECONCILED" &&
          guard.externalAction === externalAction &&
          guard.plannedRequestSha256 === plannedRequestSha256 &&
          HEX_64.test(guard.planTransitionSha256 ?? "") &&
          HEX_64.test(guard.strongReadbackSha256 ?? ""), code);
        guardReceipts.push(Object.freeze({ ...guard }));
      };
      let result;
      try {
        result = await client.selectQuery({
          clusterId: RECOVERY_PROVIDER_CLUSTER_ID,
          database: "tideproof_recovery",
          query: managedMcpQuery,
          beforeExternalAction: guardedDispatch
        });
      } finally {
        await client.close({ beforeExternalAction: guardedDispatch });
      }
      const rows = rowsFromManagedMcpResult(result);
      requireCondition(rows.length === 1,
        "FRESH_RECOVERY_PUBLICATION_MCP_ROW_COUNT_REJECTED");
      const recovered = validateRecoveryRow(rows[0], {
        recoverySessionId: prepared.attempt.recoverySessionId,
        tenantId: prepared.recoverySourceReceipt.tenant_id,
        subjectBindingHash: prepared.subjectBindingHash,
        sourceDigest: prepared.sourceDigest,
        expectedSourceClusterId: PRIMARY_PROVIDER_CLUSTER_ID,
        trustedPublisherKeys: prepared.signer.trustedPublisherKeys
      }, new Date(clock.databaseObservedAt));
      const observedBundle = bundleFromRow(rows[0]);
      requireCondition(canonicalJson(observedBundle) ===
        canonicalJson(prepared.bundle) &&
        recovered.status === "RECOVERED_CONTEXT_ONLY" &&
        recovered.authorityTransferred === false &&
        recovered.requiresFreshAuthorization === true,
      "FRESH_RECOVERY_PUBLICATION_MCP_BUNDLE_REJECTED");
      const transport = client.transportEvidence();
      const semantic = client.semanticRequestEvidence();
      requireCondition(transport?.rpcCalls?.filter((entry) =>
        entry.method === "tools/call").length === 1 &&
        semantic?.toolName === "select_query" &&
        semantic?.database === "tideproof_recovery" &&
        semantic.logicalMcpRequestSha256 ===
          managedMcpPlan.logicalRequestSha256 &&
        sha256(semantic.query) === managedMcpPlan.querySha256 &&
        guardReceipts.length === expectedActions.length &&
        canonicalJson(guardReceipts.map(({ externalAction }) =>
          externalAction)) === canonicalJson(expectedActions) &&
        transport?.close?.attempted === true &&
        Number.isSafeInteger(transport.close.httpStatus) &&
        transport.close.httpStatus >= 200 &&
        transport.close.httpStatus <= 299 &&
        transport.close.sessionContinuous === true &&
        HEX_64.test(transport.close.outboundSessionIdSha256 ?? "") &&
        (transport.close.responseSessionIdSha256 === null ||
          transport.close.responseSessionIdSha256 ===
            transport.close.outboundSessionIdSha256),
      "FRESH_RECOVERY_PUBLICATION_MCP_EVIDENCE_REJECTED");
      return Object.freeze({
        schemaVersion: "prooftoact.fresh-recovery-publication-mcp-proof.v1",
        status: "RECOVERED_CONTEXT_ONLY",
        authorityTransferred: false,
        bundleDigest: recovered.bundleDigest,
        closeSessionEvidenceSha256:
          sha256(canonicalBytes(transport.close)),
        dispatchGuardReceiptSetSha256:
          sha256(canonicalBytes(guardReceipts)),
        durablePlanReadbackSha256,
        databaseObservedAt: clock.databaseObservedAt,
        expiryPolicySha256: prepared.expiryPolicySha256,
        externalActionSequenceSha256:
          sha256(canonicalBytes(expectedActions)),
        managedMcpSemanticEvidenceSha256: sha256(canonicalBytes(semantic)),
        managedMcpTransportEvidenceSha256: sha256(canonicalBytes(transport)),
        plannedRequestSha256,
        querySha256: sha256(managedMcpQuery),
        remainingWindowMs: clock.remainingWindowMs,
        requiresFreshAuthorization: true,
        rowSha256: sha256(canonicalBytes(rows[0]))
      });
    }
  });
}

export const __test = Object.freeze({
  PRIMARY_HOST,
  PRIMARY_PROVIDER_CLUSTER_ID,
  PRIMARY_SQL_CLUSTER_ID,
  RECOVERY_HOST,
  RECOVERY_PROVIDER_CLUSTER_ID,
  RECOVERY_SQL_CLUSTER_ID,
  bundleFromRow,
  canonicalBytes,
  canonicalJson,
  normalizeMaterial,
  persistFreshRecoveryPublicationBundle,
  rowsFromManagedMcpResult,
  sha256,
  sourceBinding,
  validatePublisherConnectionString
});
