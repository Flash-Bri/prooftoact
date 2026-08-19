import crypto from "node:crypto";

import { FRESH_PRIMARY_RUNTIME_USERS } from "./bootstrap-fresh-primary.js";
import {
  buildFreshClusterCreateCommand,
  reconcileFreshClusterCreateIdentity,
  temporarySqlAllowlistEntry,
  validateFreshClusterCreateAcknowledgement,
  validateFreshClusterReadback,
  validateSqlUserInventory,
  validateTemporaryAllowlistReadback
} from "./fresh-cluster-cloud-controller.js";
import {
  validatePrivateRecoveryQueryBinding
} from "./lib/private-recovery-query-binding.js";

const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COCKROACH_SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const BOOTSTRAP_USERNAME = "prooftoact_bootstrap_admin";
const CONTROLLER_SCHEMA = "prooftoact.fresh-cluster-controller-receipt.v1";
const RESERVATION_SCHEMA = "prooftoact.fresh-cluster-reservation.v1";
const TRANSITION_SCHEMA = "prooftoact.fresh-cluster-transition.v1";
const TERMINAL_SCHEMA = "prooftoact.fresh-cluster-terminal.v1";
const AUTHENTICATION_MAX_AGE_MS = 5 * 60 * 1000;
const MAX_CANONICAL_BYTES = 128 * 1024;
const REQUIRED_PROVIDER_METHODS = Object.freeze([
  "appendTransition",
  "authenticate",
  "finalize",
  "readStrong",
  "reserve",
  "terminalize"
]);
const REQUIRED_RUNTIME_METHODS = Object.freeze([
  "addTemporaryIngress",
  "authenticateSqlAdmin",
  "createCluster",
  "createSqlAdmin",
  "discardLocalAdminCredential",
  "deleteSqlAdmin",
  "deleteTemporaryIngress",
  "listCompleteAllowlist",
  "listCompleteClusters",
  "listCompleteSqlUsers",
  "observeRunnerPublicIpv4",
  "prepareAdminCredential",
  "prepareFreshRecoveryPublication",
  "planFreshRecoveryManagedMcp",
  "readAdminSecret",
  "replayFreshRecoveryPublication",
  "runFreshPrimaryBootstrap",
  "sealAdminSecret",
  "appendFreshRecoveryPublication",
  "verifyFreshRecoveryManagedMcp",
  "waitForFreshClusterCreated"
]);

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

function canonicalBytes(value, code = "FRESH_CLUSTER_CANONICAL_RECORD_REJECTED") {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES,
    code);
  return bytes;
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function textDigest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function validateCommand(command) {
  const code = "FRESH_CLUSTER_CONTROLLER_COMMAND_REJECTED";
  requireCondition(plainObject(command), code);
  const rebuilt = buildFreshClusterCreateCommand({
    adoptedAdminPasswordSha256: command.adoptedAdminPasswordSha256,
    approvalId: command.approvalId,
    approvalSha256: command.approvalSha256,
    auditorAuthorityReceiptSha256:
      command.auditorAuthorityReceiptSha256,
    auditorServiceAccountId: command.auditorServiceAccountId,
    auditorTokenValueSha256: command.auditorTokenValueSha256,
    billingAuthorization: command.billingAuthorization,
    clusterMode: command.clusterMode,
    controllerTableArn: command.controllerTableArn,
    creatorAuthorityReceiptSha256:
      command.creatorAuthorityReceiptSha256,
    creatorProviderReadbackReceiptSha256:
      command.creatorProviderReadbackReceiptSha256,
    creatorServiceAccountId: command.creatorServiceAccountId,
    creatorTokenValueSha256: command.creatorTokenValueSha256,
    manualClusterReceiptSha256: command.manualClusterReceiptSha256,
    operationId: command.operationId,
    parentFolderId: command.parentFolderId,
    providerClusterId: command.providerClusterId,
    sourceCommit: command.sourceCommit,
    treeDigest: command.treeDigest
  });
  requireCondition(canonicalJson(rebuilt) === canonicalJson(command), code);
  return command;
}

function requireCapabilities(target, names, code) {
  requireCondition(target && names.every((name) =>
    typeof target[name] === "function"), code);
}

function nowIso(clock) {
  const value = clock();
  requireCondition(Number.isFinite(value), "FRESH_CLUSTER_CLOCK_REJECTED");
  return new Date(value).toISOString();
}

function validateAuthentication(value, command, observedNow) {
  const code = "FRESH_CLUSTER_PROVIDER_AUTHENTICATION_REJECTED";
  const observedAt = Date.parse(value?.observedAt);
  requireCondition(exactKeys(value, [
    "adminSecretState",
    "auditorAuthorityEvidenceSha256",
    "auditorServiceAccountId",
    "billingAuthorizationSha256",
    "controllerTableArn",
    "controllerTableReadbackSha256",
    "creatorAuthorityEvidenceSha256",
    "creatorReadbackSha256",
    "creatorServiceAccountId",
    "observedAt",
    "providerBacked",
    "schemaVersion",
    "status"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-cluster-authentication.v1" &&
    value.status === "AUTHENTICATED_PROVIDER_READBACK" &&
    value.adminSecretState === "ABSENT" &&
    value.controllerTableArn === command.controllerTableArn &&
    value.auditorServiceAccountId === command.auditorServiceAccountId &&
    value.creatorServiceAccountId === command.creatorServiceAccountId &&
    value.billingAuthorizationSha256 ===
      command.billingAuthorizationSha256 &&
    [value.auditorAuthorityEvidenceSha256,
      value.creatorAuthorityEvidenceSha256,
      value.controllerTableReadbackSha256,
      value.creatorReadbackSha256].every((item) => HEX_64.test(item ?? "")) &&
    value.providerBacked === true && Number.isFinite(observedAt) &&
    value.observedAt === new Date(observedAt).toISOString() &&
    observedAt <= observedNow &&
    observedNow - observedAt <= AUTHENTICATION_MAX_AGE_MS,
  code);
  return value;
}

function validateReservation(value, command, authentication) {
  const code = "FRESH_CLUSTER_RESERVATION_REJECTED";
  requireCondition(exactKeys(value, [
    "authenticationSha256",
    "commandSha256",
    "controllerTableArn",
    "durable",
    "globalKeySha256",
    "globallyAuthoritative",
    "operationId",
    "reservedAt",
    "schemaVersion",
    "status",
    "version"
  ]) && value.schemaVersion === RESERVATION_SCHEMA &&
    value.status === "RESERVED_BEFORE_PROVIDER_IDENTIFIERS" &&
    value.commandSha256 === command.commandSha256 &&
    value.controllerTableArn === command.controllerTableArn &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.operationId === command.operationId &&
    value.authenticationSha256 === digest(authentication) &&
    Number.isFinite(Date.parse(value.reservedAt)) && value.version === 1 &&
    value.durable === true && value.globallyAuthoritative === true, code);
  return value;
}

function safeTransitionPayload(value) {
  const code = "FRESH_CLUSTER_TRANSITION_PAYLOAD_REJECTED";
  requireCondition(plainObject(value), code);
  const visit = (nested, key = "") => {
    if (/(?:password|token|connectionstring|secretvalue)/iu.test(key)) {
      requireCondition(/Sha256$/u.test(key) && HEX_64.test(nested ?? ""), code);
    }
    if (typeof nested === "string") {
      requireCondition(!/^postgres(?:ql)?:\/\//iu.test(nested), code);
      return;
    }
    if (Array.isArray(nested)) {
      nested.forEach((item) => visit(item, key));
      return;
    }
    if (plainObject(nested)) {
      Object.entries(nested).forEach(([nestedKey, item]) =>
        visit(item, nestedKey));
      return;
    }
    requireCondition(nested === null || ["boolean", "number"].includes(
      typeof nested), code);
  };
  visit(value);
  canonicalBytes(value, code);
  return value;
}

function validateTransition(value, expected) {
  const code = "FRESH_CLUSTER_TRANSITION_REJECTED";
  requireCondition(canonicalJson(value) === canonicalJson(expected), code);
  return value;
}

function validateAdminCredential(value, command, cluster) {
  const code = "FRESH_CLUSTER_ADMIN_CREDENTIAL_REJECTED";
  requireCondition(exactKeys(value, [
    "connectionString",
    "connectionStringSha256",
    "password",
    "passwordSha256",
    "username"
  ]) && value.username === BOOTSTRAP_USERNAME &&
    typeof value.password === "string" && value.password.length >= 20 &&
    value.password.length <= 256 && !/[\u0000\r\n]/u.test(value.password) &&
    textDigest(value.password) === value.passwordSha256 &&
    textDigest(value.connectionString) === value.connectionStringSha256,
  code);
  let parsed;
  try {
    parsed = new URL(value.connectionString);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(parsed.protocol === "postgresql:" &&
    decodeURIComponent(parsed.username) === BOOTSTRAP_USERNAME &&
    decodeURIComponent(parsed.password) === value.password &&
    parsed.hostname === cluster.sqlDns && parsed.port === "26257" &&
    parsed.pathname === "/defaultdb" &&
    parsed.searchParams.size === 1 &&
    parsed.searchParams.get("sslmode") === "verify-full" &&
    command.createRequest.spec.serverless.regions[0] === "us-east-1", code);
  return value;
}

function validateAdminSeal(value, credential, command) {
  const code = "FRESH_CLUSTER_ADMIN_SECRET_SEAL_REJECTED";
  requireCondition(exactKeys(value, [
    "createdAt",
    "immutableVersion",
    "operationId",
    "provider",
    "providerBacked",
    "schemaVersion",
    "secretArnSha256",
    "secretValueSha256",
    "secretVersionIdSha256",
    "status"
  ]) && value.schemaVersion === "prooftoact.fresh-cluster-admin-seal.v1" &&
    value.status === "SEALED" && value.provider === "AWS_SECRETS_MANAGER" &&
    value.providerBacked === true && value.immutableVersion === true &&
    value.operationId === command.operationId &&
    value.secretValueSha256 === credential.connectionStringSha256 &&
    [value.secretArnSha256, value.secretVersionIdSha256].every((item) =>
      HEX_64.test(item ?? "")) && Number.isFinite(Date.parse(value.createdAt)),
  code);
  return value;
}

function validateAdminAuthentication(value, command, cluster, credential) {
  const code = "FRESH_CLUSTER_SQL_ADMIN_AUTHENTICATION_REJECTED";
  requireCondition(exactKeys(value, [
    "database",
    "observedAt",
    "port",
    "providerBacked",
    "providerClusterId",
    "schemaVersion",
    "sqlClusterId",
    "status",
    "username"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-cluster-admin-authentication.v1" &&
    value.status === "AUTHENTICATED" && value.providerBacked === true &&
    value.providerClusterId === cluster.clusterId &&
    COCKROACH_SQL_CLUSTER_ID.test(value.sqlClusterId ?? "") &&
    value.sqlClusterId !== value.providerClusterId &&
    value.database === "defaultdb" &&
    value.port === "26257" && value.username === credential.username &&
    Number.isFinite(Date.parse(value.observedAt)) &&
    command.operationId.length > 0, code);
  return value;
}

function buildPrimaryClusterMappingReceipt({
  adminAuthentication,
  cluster,
  command
}) {
  const code = "FRESH_CLUSTER_PRIMARY_MAPPING_REJECTED";
  requireCondition(adminAuthentication.providerClusterId ===
      cluster.clusterId &&
    adminAuthentication.providerClusterId !==
      adminAuthentication.sqlClusterId &&
    typeof cluster.sqlDns === "string" &&
    HEX_64.test(cluster.inventorySha256 ?? "") &&
    Number.isFinite(Date.parse(adminAuthentication.observedAt)), code);
  const body = Object.freeze({
    schemaVersion: "prooftoact.primary-provider-sql-mapping.v1",
    status: "PROVIDER_READBACK_BOUND",
    cloud: "COCKROACHDB_CLOUD_ON_AWS",
    clusterInventorySha256: cluster.inventorySha256,
    cockroachVersion: cluster.cockroachVersion,
    host: cluster.sqlDns,
    manualClusterReceiptSha256: command.manualClusterReceiptSha256,
    observedAt: adminAuthentication.observedAt,
    providerClusterId: adminAuthentication.providerClusterId,
    sourceBindingSha256: digest({
      sourceCommit: command.sourceCommit,
      treeDigest: command.treeDigest
    }),
    sourceCommit: command.sourceCommit,
    sqlClusterId: adminAuthentication.sqlClusterId,
    treeDigest: command.treeDigest
  });
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

function validateBootstrapReceipt(
  value,
  command,
  cluster,
  adminSeal,
  adminAuthentication
) {
  const code = "FRESH_CLUSTER_BOOTSTRAP_RECEIPT_REJECTED";
  requireCondition(plainObject(value) && value.schemaVersion ===
      "prooftoact.fresh-primary-bootstrap-receipt.v3" &&
    value.status === "PASS" && value.approvalId === command.approvalId &&
    value.operationId === command.operationId &&
    value.sourceCommit === command.sourceCommit &&
    value.treeDigest === command.treeDigest &&
    value.provider?.clusterIdSha256 ===
      textDigest(adminAuthentication.sqlClusterId) &&
    value.credentialLifecycle?.adminUrlLocalCopyDiscardedBeforeMutation ===
      true && value.bootstrap?.managedRoleCount === 29 &&
    value.postflight?.runtimeIdentity === "tp_gate2_authorizer_user" &&
    value.postflight?.directPrivateTableAccessDenied === true &&
    value.partialFailureDisposition ===
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD" &&
    value.credentialLifecycle?.providerReadbackAuthenticatedByThisModule ===
      false && adminSeal.secretValueSha256.length === 64, code);
  const recoveryPublisher = value.credentialLifecycle?.recoveryPublisher;
  requireCondition(exactKeys(recoveryPublisher, [
    "publisherKeyIdSha256",
    "publisherKeySetDigest",
    "signerSecretArnSha256",
    "signerSecretSealReceiptSha256",
    "signerSecretValueSha256",
    "signerSecretVersionIdSha256",
    "trustRootCommitment",
    "trustRootJsonSha256"
  ]) && Object.values(recoveryPublisher).every((item) =>
    HEX_64.test(item ?? "")), code);
  return value;
}

function validateFreshRecoveryPreparation(
  value,
  command,
  bootstrapReceipt,
  primaryClusterMapping
) {
  const code = "FRESH_CLUSTER_RECOVERY_PREPARATION_REJECTED";
  requireCondition(exactKeys(value, [
    "operationId",
    "preparationReceipt",
    "preparationReceiptSha256",
    "schemaVersion",
    "sourceCommit",
    "sourceReceipt",
    "sourceReceiptSha256",
    "status",
    "treeDigest"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-recovery-source-and-preparation.v1" &&
    value.status === "PREPARED" &&
    value.operationId === command.operationId &&
    value.sourceCommit === command.sourceCommit &&
    value.treeDigest === command.treeDigest, code);
  const source = value.sourceReceipt;
  requireCondition(exactKeys(source, [
    "authorityOutcome",
    "durableAuthorityReceipt",
    "dviPolicyVersion",
    "evidenceDigest",
    "evidenceVerified",
    "operationId",
    "schemaVersion",
    "sourceBinding",
    "sourceBindingSha256",
    "sourceCommit",
    "status",
    "treeDigest"
  ]) && source.schemaVersion ===
      "prooftoact.fresh-recovery-source-receipt.v1" &&
    source.status === "PASS" && source.operationId === command.operationId &&
    source.sourceCommit === command.sourceCommit &&
    source.treeDigest === command.treeDigest &&
    source.authorityOutcome === "resource_reserved" &&
    source.dviPolicyVersion === "g1-admissibility-v2" &&
    source.durableAuthorityReceipt === true &&
    source.evidenceVerified === true &&
    HEX_64.test(source.evidenceDigest ?? "") &&
    source.sourceBindingSha256 === digest(source.sourceBinding) &&
    value.sourceReceiptSha256 === digest(source), code);
  requireCondition(exactKeys(source.sourceBinding, [
    "authorityEvidenceBindingSha256",
    "evidenceId",
    "incidentId",
    "operationId",
    "requestDigest",
    "resourceId",
    "runId",
    "selectedEvidenceBindingSha256",
    "tenantId"
  ]) && source.sourceBinding.operationId === command.operationId &&
    [source.sourceBinding.evidenceId, source.sourceBinding.incidentId,
      source.sourceBinding.operationId, source.sourceBinding.runId,
      source.sourceBinding.tenantId].every((item) => UUID.test(item ?? "")) &&
    [source.sourceBinding.authorityEvidenceBindingSha256,
      source.sourceBinding.requestDigest,
      source.sourceBinding.selectedEvidenceBindingSha256].every((item) =>
      HEX_64.test(item ?? "")) &&
    typeof source.sourceBinding.resourceId === "string" &&
    source.sourceBinding.resourceId.length > 0, code);
  const preparation = value.preparationReceipt;
  requireCondition(exactKeys(preparation, [
    "authorityTransferred",
    "bundleDigest",
    "persistenceReceiptSha256",
    "privateRecoveryQueryBinding",
    "privateRecoveryQueryBindingSha256",
    "publisherKeySetDigest",
    "recoverySessionId",
    "requiresFreshAuthorization",
    "schemaVersion",
    "sourceDigest",
    "sourceReceiptSha256",
    "status"
  ]) && preparation.schemaVersion ===
      "prooftoact.fresh-recovery-publication-preparation.v1" &&
    preparation.status === "PREPARED" &&
    preparation.authorityTransferred === false &&
    preparation.requiresFreshAuthorization === true &&
    UUID.test(preparation.recoverySessionId ?? "") &&
    [preparation.bundleDigest, preparation.persistenceReceiptSha256,
      preparation.publisherKeySetDigest, preparation.sourceDigest,
      preparation.sourceReceiptSha256,
      preparation.privateRecoveryQueryBindingSha256].every((item) =>
      HEX_64.test(item ?? "")) &&
    preparation.publisherKeySetDigest === bootstrapReceipt
      .credentialLifecycle?.recoveryPublisher?.publisherKeySetDigest &&
    value.preparationReceiptSha256 === digest(preparation), code);
  const privateRecoveryQueryBinding = validatePrivateRecoveryQueryBinding(
    preparation.privateRecoveryQueryBinding
  );
  requireCondition(privateRecoveryQueryBinding.bindingSha256 ===
      preparation.privateRecoveryQueryBindingSha256 &&
    privateRecoveryQueryBinding.expectedBundleDigest ===
      preparation.bundleDigest &&
    privateRecoveryQueryBinding.recoverySessionId ===
      preparation.recoverySessionId &&
    privateRecoveryQueryBinding.sourceDigest === preparation.sourceDigest &&
    privateRecoveryQueryBinding.operationId === command.operationId &&
    privateRecoveryQueryBinding.sourceCommit === command.sourceCommit &&
    privateRecoveryQueryBinding.treeDigest === command.treeDigest &&
    privateRecoveryQueryBinding.billingAuthorizationSha256 ===
      command.billingAuthorizationSha256 &&
    textDigest(privateRecoveryQueryBinding.publisherKeyId) ===
      bootstrapReceipt.credentialLifecycle?.recoveryPublisher?.
        publisherKeyIdSha256 &&
    canonicalJson(privateRecoveryQueryBinding.primaryClusterMapping) ===
      canonicalJson(primaryClusterMapping) &&
    privateRecoveryQueryBinding.primaryClusterMappingReceiptSha256 ===
      primaryClusterMapping.receiptSha256, code);
  return value;
}

function validateRecoveryPublicationCommit(commit, bundleDigest, code) {
  requireCondition(exactKeys(commit, [
    "authority",
    "databaseNow",
    "observation",
    "operation",
    "operationDigest",
    "outcome",
    "reason",
    "schemaVersion",
    "status"
  ]) && commit.schemaVersion === "tideproof.database-commit-result.v1" &&
    commit.status === "COMMITTED" &&
    commit.operation === "recovery_publication" &&
    commit.operationDigest === bundleDigest &&
    ["direct_ack", "read_reconciled"].includes(commit.observation) &&
    commit.outcome === "bundle_present" && commit.reason === null &&
    Number.isFinite(Date.parse(commit.databaseNow)) &&
    exactKeys(commit.authority, ["current", "requiresFreshAuthorization"]) &&
    commit.authority.current === null &&
    commit.authority.requiresFreshAuthorization === true, code);
  return commit;
}

function validateFreshRecoveryAppend(value, bundleDigest) {
  const code = "FRESH_CLUSTER_RECOVERY_APPEND_REJECTED";
  requireCondition(exactKeys(value, [
    "bundleDigest", "commit", "outcome", "schemaVersion", "status"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-recovery-publication-append.v1" &&
    value.status === "CONFIRMED" && value.bundleDigest === bundleDigest &&
    ["bundle_appended", "bundle_replay", "bundle_present"].includes(
      value.outcome
    ), code);
  validateRecoveryPublicationCommit(value.commit, bundleDigest, code);
  return value;
}

function validateFreshRecoveryReplay(value, bundleDigest) {
  const code = "FRESH_CLUSTER_RECOVERY_REPLAY_REJECTED";
  requireCondition(exactKeys(value, [
    "bundleDigest", "commit", "outcome", "schemaVersion", "status"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-recovery-publication-replay.v1" &&
    value.status === "CONFIRMED_REPLAY" &&
    value.bundleDigest === bundleDigest && value.outcome === "bundle_replay",
  code);
  validateRecoveryPublicationCommit(value.commit, bundleDigest, code);
  return value;
}

function validateFreshRecoveryMcpPlan(value, preparation) {
  const code = "FRESH_CLUSTER_RECOVERY_MCP_PLAN_REJECTED";
  requireCondition(exactKeys(value, [
    "bundleDigest",
    "database",
    "logicalRequestSha256",
    "querySha256",
    "recoveryClusterId",
    "recoverySessionId",
    "schemaVersion",
    "sourceDigest",
    "status",
    "subjectBindingSha256",
    "tenantId",
    "toolName"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-recovery-publication-mcp-plan.v1" &&
    value.status === "PLANNED_READ_ONLY_QUERY" &&
    value.bundleDigest === preparation.bundleDigest &&
    value.recoverySessionId === preparation.recoverySessionId &&
    value.sourceDigest === preparation.sourceDigest &&
    value.database === "tideproof_recovery" &&
    value.toolName === "select_query" &&
    UUID.test(value.recoveryClusterId ?? "") &&
    UUID.test(value.tenantId ?? "") &&
    [value.logicalRequestSha256, value.querySha256,
      value.sourceDigest, value.subjectBindingSha256].every((item) =>
      HEX_64.test(item ?? "")), code);
  return value;
}

function validateFreshRecoveryMcpProof(value, plan, durableReadbackSha256) {
  const code = "FRESH_CLUSTER_RECOVERY_MCP_PROOF_REJECTED";
  requireCondition(exactKeys(value, [
    "authorityTransferred",
    "bundleDigest",
    "closeSessionEvidenceSha256",
    "dispatchGuardReceiptSetSha256",
    "durablePlanReadbackSha256",
    "externalActionSequenceSha256",
    "managedMcpSemanticEvidenceSha256",
    "managedMcpTransportEvidenceSha256",
    "plannedRequestSha256",
    "querySha256",
    "requiresFreshAuthorization",
    "rowSha256",
    "schemaVersion",
    "status"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-recovery-publication-mcp-proof.v1" &&
    value.status === "RECOVERED_CONTEXT_ONLY" &&
    value.authorityTransferred === false &&
    value.requiresFreshAuthorization === true &&
    value.bundleDigest === plan.bundleDigest &&
    value.querySha256 === plan.querySha256 &&
    value.plannedRequestSha256 === digest(plan) &&
    value.durablePlanReadbackSha256 === durableReadbackSha256 &&
    [value.closeSessionEvidenceSha256,
      value.dispatchGuardReceiptSetSha256,
      value.durablePlanReadbackSha256,
      value.externalActionSequenceSha256,
      value.managedMcpSemanticEvidenceSha256,
      value.managedMcpTransportEvidenceSha256,
      value.plannedRequestSha256,
      value.querySha256,
      value.rowSha256].every((item) => HEX_64.test(item ?? "")), code);
  return value;
}

function controllerReadRequest(command) {
  return Object.freeze({
    command,
    commandSha256: command.commandSha256,
    controllerTableArn: command.controllerTableArn,
    globalKeySha256: command.globalKeySha256,
    operationId: command.operationId,
    stronglyConsistent: true
  });
}

function validateMcpPlanStrongReadback(value, command, transition) {
  const code = "FRESH_CLUSTER_RECOVERY_MCP_PLAN_READBACK_REJECTED";
  requireCondition(plainObject(value) &&
    canonicalJson(value.command) === canonicalJson(command) &&
    value.finalReceipt === null && value.terminalReceipt === null &&
    Array.isArray(value.transitions) && value.transitions.length > 0 &&
    value.transitionCount === value.transitions.length &&
    value.state === transition.phase &&
    value.version === transition.version &&
    value.lastReceiptSha256 === digest(transition) &&
    canonicalJson(value.transitions.at(-1)) === canonicalJson(transition), code);
  return digest({
    commandSha256: command.commandSha256,
    lastReceiptSha256: value.lastReceiptSha256,
    state: value.state,
    transitionCount: value.transitionCount,
    transitionSha256: digest(transition),
    version: value.version
  });
}

export function validateFinalRuntimePrincipalCensus(value) {
  const code = "FRESH_CLUSTER_FINAL_PRINCIPAL_CENSUS_REJECTED";
  requireCondition(exactKeys(value, [
    "clusterId",
    "names",
    "observedAt",
    "providerBacked",
    "schemaVersion",
    "status"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-cluster-final-principal-census.v1" &&
    value.status === "EXACT_RUNTIME_USERS" && value.providerBacked === true &&
    COCKROACH_SQL_CLUSTER_ID.test(value.clusterId ?? "") &&
    Number.isFinite(Date.parse(value.observedAt)) &&
    Array.isArray(value.names) && new Set(value.names).size === 14 &&
    canonicalJson([...value.names].sort()) ===
      canonicalJson([...FRESH_PRIMARY_RUNTIME_USERS].sort()), code);
  return Object.freeze({
    clusterId: value.clusterId,
    count: 14,
    namesSha256: digest([...value.names].sort()),
    observedAt: value.observedAt
  });
}

function sameNames(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export async function runFreshClusterProviderController({
  clock = Date.now,
  command,
  provider,
  runtime
}) {
  validateCommand(command);
  requireCapabilities(provider, REQUIRED_PROVIDER_METHODS,
    "FRESH_CLUSTER_PROVIDER_CAPABILITY_REJECTED");
  requireCapabilities(runtime, REQUIRED_RUNTIME_METHODS,
    "FRESH_CLUSTER_RUNTIME_CAPABILITY_REJECTED");
  requireCondition(typeof clock === "function",
    "FRESH_CLUSTER_CLOCK_REJECTED");

  const authenticationNow = clock();
  requireCondition(Number.isFinite(authenticationNow) &&
    authenticationNow < Date.parse(command.billingAuthorization.approvalExpiresAt),
  "FRESH_CLUSTER_APPROVAL_EXPIRED");
  const authentication = validateAuthentication(
    await provider.authenticate(command), command, authenticationNow
  );
  const occupied = await provider.readStrong(controllerReadRequest(command));
  requireCondition(occupied === null,
    "FRESH_CLUSTER_OPERATION_OCCUPIED");
  const reservation = validateReservation(
    await provider.reserve({ command, authentication }),
    command,
    authentication
  );

  let previousReceiptSha256 = digest(reservation);
  let sequence = 0;
  const phases = new Set();
  const record = async (phase, payload, mutationDispatched = false) => {
    requireCondition(/^[A-Z][A-Z0-9_]{0,79}$/u.test(phase) &&
      !phases.has(phase) && typeof mutationDispatched === "boolean",
    "FRESH_CLUSTER_TRANSITION_REJECTED");
    safeTransitionPayload(payload);
    const transition = Object.freeze({
      schemaVersion: TRANSITION_SCHEMA,
      status: "DURABLE",
      commandSha256: command.commandSha256,
      controllerTableArn: command.controllerTableArn,
      durable: true,
      globallyAuthoritative: true,
      globalKeySha256: command.globalKeySha256,
      mutationDispatched,
      operationId: command.operationId,
      payloadSha256: digest(payload),
      phase,
      previousReceiptSha256,
      sequence,
      version: sequence + 2
    });
    const accepted = validateTransition(
      await provider.appendTransition({ command, transition }), transition
    );
    phases.add(phase);
    previousReceiptSha256 = digest(accepted);
    sequence += 1;
    return accepted;
  };

  let cluster;
  let clusterId;
  let ingressEntry;
  let ingressPossible = false;
  let ingressAbsent = false;
  let adminPossible = false;
  let adminAbsent = false;
  let sqlBaseline;
  let primaryCause;

  const snapshotTime = () => nowIso(clock);
  const readAllowlist = () => runtime.listCompleteAllowlist({
    asOfTime: snapshotTime(), clusterId
  });
  const readSqlUsers = () => runtime.listCompleteSqlUsers({
    asOfTime: snapshotTime(), clusterId
  });

  try {
    const dispatchedAt = snapshotTime();
    if (command.clusterMode === "CREATE_NEW") {
      await record("CLUSTER_CREATE_DISPATCHING", {
        createRequestSha256: command.createRequestSha256,
        dispatchedAt
      }, true);
      let acknowledgement;
      try {
        acknowledgement = validateFreshClusterCreateAcknowledgement(
          await runtime.createCluster({ command }), command
        );
      } catch (cause) {
        const reconciled = reconcileFreshClusterCreateIdentity(
          await runtime.listCompleteClusters({ asOfTime: snapshotTime() }),
          command
        );
        acknowledgement = reconciled;
        await record("CLUSTER_CREATE_ACKNOWLEDGEMENT_RECONCILED", {
          acknowledgementCauseSha256:
            textDigest(cause?.message ?? "UNKNOWN"),
          clusterIdSha256: reconciled.clusterIdSha256,
          inventorySnapshotSha256: reconciled.inventorySnapshotSha256
        });
      }
      clusterId = acknowledgement.clusterId;
    } else {
      clusterId = command.providerClusterId;
      await record("CLUSTER_ADOPTION_READBACK_STARTED", {
        manualClusterReceiptSha256: command.manualClusterReceiptSha256,
        providerClusterIdSha256: textDigest(clusterId),
        startedAt: dispatchedAt
      });
    }
    const observedAt = snapshotTime();
    cluster = validateFreshClusterReadback(
      await runtime.waitForFreshClusterCreated({ clusterId, command }),
      command,
      { dispatchedAt, observedAt }
    );
    await record(command.clusterMode === "CREATE_NEW"
      ? "CLUSTER_CREATE_OBSERVED"
      : "CLUSTER_ADOPTION_OBSERVED", {
      clusterIdSha256: cluster.clusterIdSha256,
      cockroachVersion: cluster.cockroachVersion,
      deleteProtection: cluster.deleteProtection,
      inventorySha256: cluster.inventorySha256,
      observedAt
    });

    const initialIp = await runtime.observeRunnerPublicIpv4();
    requireCondition(HEX_64.test(initialIp?.ipv4Sha256 ?? "") &&
      initialIp.sourceCount === 2,
    "FRESH_CLUSTER_RUNNER_EGRESS_REJECTED");
    await record("RUNNER_EGRESS_OBSERVED", {
      ipv4Sha256: initialIp.ipv4Sha256,
      sourceCount: initialIp.sourceCount,
      sourcesSha256: initialIp.sourcesSha256
    });
    ingressEntry = temporarySqlAllowlistEntry({
      operationId: command.operationId,
      ipv4: initialIp.ipv4
    });
    const ingressPrestate = validateTemporaryAllowlistReadback(
      await readAllowlist(), ingressEntry, { present: false }
    );
    ingressAbsent = true;
    await record("INGRESS_PRESTATE_EMPTY", ingressPrestate);

    await record("INGRESS_CREATE_DISPATCHING", {
      entrySha256: digest(ingressEntry)
    }, true);
    ingressPossible = true;
    // From the dispatch boundary onward, absence is unknown until an exact
    // provider readback proves otherwise. This prevents an ACK-loss or
    // readback failure from being mislabeled as an empty allowlist.
    ingressAbsent = false;
    try {
      await runtime.addTemporaryIngress({ clusterId, entry: ingressEntry });
    } catch (cause) {
      validateTemporaryAllowlistReadback(
        await readAllowlist(), ingressEntry, { present: true }
      );
      await record("INGRESS_CREATE_ACKNOWLEDGEMENT_RECONCILED", {
        acknowledgementCauseSha256: textDigest(cause?.message ?? "UNKNOWN"),
        entrySha256: digest(ingressEntry)
      });
    }
    const ingressObserved = validateTemporaryAllowlistReadback(
      await readAllowlist(), ingressEntry, { present: true }
    );
    ingressAbsent = false;
    await record("INGRESS_CREATE_OBSERVED", ingressObserved);

    const ingressIp = await runtime.observeRunnerPublicIpv4();
    requireCondition(ingressIp?.ipv4 === initialIp.ipv4,
      "FRESH_CLUSTER_RUNNER_EGRESS_CHANGED");
    await record("RUNNER_EGRESS_REOBSERVED_AFTER_INGRESS", {
      ipv4Sha256: ingressIp.ipv4Sha256,
      sourceCount: ingressIp.sourceCount,
      sourcesSha256: ingressIp.sourcesSha256
    });

    const credential = validateAdminCredential(
      await runtime.prepareAdminCredential({ cluster, command }),
      command,
      cluster
    );
    await record("ADMIN_SECRET_DISPATCHING", {
      connectionStringSha256: credential.connectionStringSha256,
      usernameSha256: textDigest(credential.username)
    }, true);
    let adminSeal;
    try {
      adminSeal = validateAdminSeal(
        await runtime.sealAdminSecret({ command, credential }),
        credential,
        command
      );
    } catch (cause) {
      adminSeal = validateAdminSeal(
        await runtime.readAdminSecret({ command, credential }),
        credential,
        command
      );
      await record("ADMIN_SECRET_ACKNOWLEDGEMENT_RECONCILED", {
        acknowledgementCauseSha256: textDigest(cause?.message ?? "UNKNOWN"),
        secretArnSha256: adminSeal.secretArnSha256,
        secretValueSha256: adminSeal.secretValueSha256,
        secretVersionIdSha256: adminSeal.secretVersionIdSha256
      });
    }
    await record("ADMIN_SECRET_SEALED", {
      createdAt: adminSeal.createdAt,
      secretArnSha256: adminSeal.secretArnSha256,
      secretValueSha256: adminSeal.secretValueSha256,
      secretVersionIdSha256: adminSeal.secretVersionIdSha256
    });

    await record("LOCAL_ADMIN_CREDENTIAL_DISCARDING", {
      adminSecretVersionIdSha256: adminSeal.secretVersionIdSha256
    });
    requireCondition(await runtime.discardLocalAdminCredential({
      adminSeal,
      command,
      credential
    }) === true, "FRESH_CLUSTER_LOCAL_ADMIN_CREDENTIAL_DISCARD_REJECTED");
    await record("LOCAL_ADMIN_CREDENTIAL_DISCARDED", {
      adminSecretVersionIdSha256: adminSeal.secretVersionIdSha256,
      localAdminCredentialFileRetained: false
    });

    const initialSqlInventory = validateSqlUserInventory(await readSqlUsers());
    const adminInitiallyPresent = initialSqlInventory.names.includes(
      BOOTSTRAP_USERNAME
    );
    requireCondition(adminInitiallyPresent ===
      (command.clusterMode === "ADOPT_VERIFIED_EXISTING"),
    "FRESH_CLUSTER_ADMIN_PRESTATE_REJECTED");
    sqlBaseline = Object.freeze({
      ...initialSqlInventory,
      names: Object.freeze(initialSqlInventory.names.filter((name) =>
        name !== BOOTSTRAP_USERNAME))
    });
    await record(adminInitiallyPresent
      ? "ADOPTED_ADMIN_USER_PRESTATE_PRESENT"
      : "ADMIN_USER_PRESTATE_ABSENT", {
      inventorySha256: initialSqlInventory.snapshotSha256,
      userCount: initialSqlInventory.names.length
    });

    adminPossible = true;
    if (!adminInitiallyPresent) {
      await record("ADMIN_CREATE_DISPATCHING", {
        usernameSha256: textDigest(BOOTSTRAP_USERNAME)
      }, true);
      try {
        await runtime.createSqlAdmin({
          clusterId,
          password: credential.password,
          username: credential.username
        });
      } catch (cause) {
        const reconciled = validateSqlUserInventory(await readSqlUsers());
        requireCondition(sameNames(reconciled.names, [
          ...sqlBaseline.names, BOOTSTRAP_USERNAME
        ].sort()), "FRESH_CLUSTER_ADMIN_CREATE_RECONCILIATION_REJECTED");
        await record("ADMIN_CREATE_ACKNOWLEDGEMENT_RECONCILED", {
          acknowledgementCauseSha256: textDigest(cause?.message ?? "UNKNOWN"),
          inventorySha256: reconciled.snapshotSha256
        });
      }
    }
    const adminInventory = validateSqlUserInventory(await readSqlUsers());
    requireCondition(sameNames(adminInventory.names, [
      ...sqlBaseline.names, BOOTSTRAP_USERNAME
    ].sort()), "FRESH_CLUSTER_ADMIN_CREATE_READBACK_REJECTED");
    adminAbsent = false;
    await record(adminInitiallyPresent
      ? "ADOPTED_ADMIN_USER_OBSERVED"
      : "ADMIN_CREATE_OBSERVED", {
      inventorySha256: adminInventory.snapshotSha256,
      userCount: adminInventory.names.length
    });

    const adminAuthentication = validateAdminAuthentication(
      await runtime.authenticateSqlAdmin({ cluster, command, credential }),
      command,
      cluster,
      credential
    );
    const primaryClusterMapping = buildPrimaryClusterMappingReceipt({
      adminAuthentication,
      cluster,
      command
    });
    await record("ADMIN_AUTHENTICATED", {
      primaryClusterMappingReceiptSha256:
        primaryClusterMapping.receiptSha256,
      providerClusterIdSha256:
        textDigest(adminAuthentication.providerClusterId),
      sqlClusterIdSha256: textDigest(adminAuthentication.sqlClusterId),
      observedAt: adminAuthentication.observedAt,
      usernameSha256: textDigest(adminAuthentication.username)
    });

    const preBootstrapIp = await runtime.observeRunnerPublicIpv4();
    requireCondition(preBootstrapIp?.ipv4 === initialIp.ipv4,
      "FRESH_CLUSTER_RUNNER_EGRESS_CHANGED");
    await record("RUNNER_EGRESS_REOBSERVED_BEFORE_BOOTSTRAP", {
      ipv4Sha256: preBootstrapIp.ipv4Sha256,
      sourceCount: preBootstrapIp.sourceCount,
      sourcesSha256: preBootstrapIp.sourcesSha256
    });

    await record("BOOTSTRAP_DISPATCHING", {
      adminSealSha256: digest(adminSeal),
      clusterIdSha256: cluster.clusterIdSha256
    }, true);
    const bootstrapReceipt = validateBootstrapReceipt(
      await runtime.runFreshPrimaryBootstrap({
        adminSeal,
        adminAuthentication,
        cluster,
        command,
        credential
      }),
      command,
      cluster,
      adminSeal,
      adminAuthentication
    );
    await record("BOOTSTRAP_ACCEPTED", {
      bootstrapReceiptSha256: digest(bootstrapReceipt),
      finalPostureDigest: bootstrapReceipt.bootstrap.finalPostureDigest,
      signerSecretArnSha256: bootstrapReceipt.credentialLifecycle?.
        recoveryPublisher?.signerSecretArnSha256,
      signerSecretVersionIdSha256: bootstrapReceipt.credentialLifecycle?.
        recoveryPublisher?.signerSecretVersionIdSha256
    });

    await record("RECOVERY_SOURCE_AND_PREPARATION_DISPATCHING", {
      bootstrapReceiptSha256: digest(bootstrapReceipt),
      controllerGeneratedSource: true,
      dviAuthoritySourceUsesBootstrapAdmin: true,
      operationIdSha256: textDigest(command.operationId),
      sqlClusterIdSha256: textDigest(adminAuthentication.sqlClusterId)
    }, true);
    const recoveryPreparation = validateFreshRecoveryPreparation(
      await runtime.prepareFreshRecoveryPublication({
        adminAuthentication,
        bootstrapReceipt,
        cluster,
        command,
        credential,
        primaryClusterMapping
      }),
      command,
      bootstrapReceipt,
      primaryClusterMapping
    );
    await record("RECOVERY_SOURCE_AND_PREPARATION_ACCEPTED", {
      bundleDigest: recoveryPreparation.preparationReceipt.bundleDigest,
      controllerGeneratedSource: true,
      dviPolicyVersion: recoveryPreparation.sourceReceipt.dviPolicyVersion,
      preparationReceiptSha256:
        recoveryPreparation.preparationReceiptSha256,
      sourceReceiptSha256: recoveryPreparation.sourceReceiptSha256
    });

    await record("RECOVERY_PUBLICATION_APPEND_DISPATCHING", {
      bundleDigest: recoveryPreparation.preparationReceipt.bundleDigest,
      preparationReceiptSha256:
        recoveryPreparation.preparationReceiptSha256
    }, true);
    const recoveryAppend = validateFreshRecoveryAppend(
      await runtime.appendFreshRecoveryPublication(),
      recoveryPreparation.preparationReceipt.bundleDigest
    );
    await record("RECOVERY_PUBLICATION_APPEND_ACCEPTED", {
      appendReceiptSha256: digest(recoveryAppend),
      bundleDigest: recoveryAppend.bundleDigest,
      commitObservation: recoveryAppend.commit.observation,
      outcome: recoveryAppend.outcome
    });

    await record("RECOVERY_PUBLICATION_REPLAY_DISPATCHING", {
      appendReceiptSha256: digest(recoveryAppend),
      bundleDigest: recoveryAppend.bundleDigest
    }, true);
    const recoveryReplay = validateFreshRecoveryReplay(
      await runtime.replayFreshRecoveryPublication(),
      recoveryPreparation.preparationReceipt.bundleDigest
    );
    await record("RECOVERY_PUBLICATION_REPLAY_ACCEPTED", {
      bundleDigest: recoveryReplay.bundleDigest,
      commitObservation: recoveryReplay.commit.observation,
      outcome: recoveryReplay.outcome,
      replayReceiptSha256: digest(recoveryReplay)
    });

    const recoveryMcpPlan = validateFreshRecoveryMcpPlan(
      await runtime.planFreshRecoveryManagedMcp(),
      recoveryPreparation.preparationReceipt
    );
    const plannedRequestSha256 = digest(recoveryMcpPlan);
    const planTransition = await record(
      "RECOVERY_MANAGED_MCP_REQUEST_PLANNED",
      recoveryMcpPlan
    );
    const planTransitionSha256 = digest(planTransition);
    const durablePlanReadbackSha256 = validateMcpPlanStrongReadback(
      await provider.readStrong(controllerReadRequest(command)),
      command,
      planTransition
    );
    const beforeManagedMcpExternalAction = async ({
      externalAction,
      plannedRequestSha256: guardedRequestSha256
    } = {}) => {
      requireCondition([
        "MCP_INITIALIZE",
        "MCP_INITIALIZED_NOTIFICATION",
        "MCP_TOOLS_CALL",
        "MCP_SESSION_DELETE"
      ].includes(externalAction) &&
        guardedRequestSha256 === plannedRequestSha256,
      "FRESH_CLUSTER_RECOVERY_MCP_DISPATCH_GUARD_REJECTED");
      const strongReadbackSha256 = validateMcpPlanStrongReadback(
        await provider.readStrong(controllerReadRequest(command)),
        command,
        planTransition
      );
      return Object.freeze({
        schemaVersion:
          "prooftoact.fresh-recovery-mcp-dispatch-guard.v1",
        status: "DURABLE_PLAN_STRONGLY_RECONCILED",
        externalAction,
        plannedRequestSha256,
        planTransitionSha256,
        strongReadbackSha256
      });
    };
    let recoveryMcpProof;
    try {
      recoveryMcpProof = validateFreshRecoveryMcpProof(
        await runtime.verifyFreshRecoveryManagedMcp({
          beforeExternalAction: beforeManagedMcpExternalAction,
          durablePlanReadbackSha256,
          plannedRequestSha256
        }),
        recoveryMcpPlan,
        durablePlanReadbackSha256
      );
    } catch (cause) {
      reject("FRESH_RECOVERY_MANAGED_MCP_UNKNOWN_DO_NOT_RETRY", cause);
    }
    await record("RECOVERY_MANAGED_MCP_QUERY_ACCEPTED", {
      authorityTransferred: recoveryMcpProof.authorityTransferred,
      closeSessionEvidenceSha256:
        recoveryMcpProof.closeSessionEvidenceSha256,
      managedMcpProofSha256: digest(recoveryMcpProof),
      plannedRequestSha256,
      requiresFreshAuthorization:
        recoveryMcpProof.requiresFreshAuthorization
    });

    const expectedRuntimeNames = [...FRESH_PRIMARY_RUNTIME_USERS].sort();
    const expectedPostBootstrapNames = [
      ...sqlBaseline.names,
      ...expectedRuntimeNames,
      BOOTSTRAP_USERNAME
    ].sort();
    const postBootstrapInventory = validateSqlUserInventory(
      await readSqlUsers()
    );
    requireCondition(sameNames(
      postBootstrapInventory.names,
      expectedPostBootstrapNames
    ), "FRESH_CLUSTER_POST_BOOTSTRAP_SQL_USER_INVENTORY_REJECTED");
    await record("POST_BOOTSTRAP_SQL_USER_INVENTORY_ACCEPTED", {
      inventorySha256: postBootstrapInventory.snapshotSha256,
      runtimeUserCount: expectedRuntimeNames.length,
      userCount: postBootstrapInventory.names.length
    });

    await record("ADMIN_DELETE_DISPATCHING", {
      usernameSha256: textDigest(BOOTSTRAP_USERNAME)
    }, true);
    try {
      await runtime.deleteSqlAdmin({ clusterId, username: BOOTSTRAP_USERNAME });
    } catch (cause) {
      const reconciled = validateSqlUserInventory(await readSqlUsers());
      requireCondition(sameNames(reconciled.names, [
        ...sqlBaseline.names,
        ...expectedRuntimeNames
      ].sort()),
        "FRESH_CLUSTER_ADMIN_DELETE_RECONCILIATION_REJECTED");
      await record("ADMIN_DELETE_ACKNOWLEDGEMENT_RECONCILED", {
        acknowledgementCauseSha256: textDigest(cause?.message ?? "UNKNOWN"),
        inventorySha256: reconciled.snapshotSha256
      });
    }
    const adminDeleted = validateSqlUserInventory(await readSqlUsers());
    requireCondition(sameNames(adminDeleted.names, [
      ...sqlBaseline.names,
      ...expectedRuntimeNames
    ].sort()),
      "FRESH_CLUSTER_ADMIN_DELETE_READBACK_REJECTED");
    adminAbsent = true;
    await record("ADMIN_DELETE_ABSENT", {
      inventorySha256: adminDeleted.snapshotSha256,
      userCount: adminDeleted.names.length
    });

    const baselineSet = new Set(sqlBaseline.names);
    const finalCensus = validateFinalRuntimePrincipalCensus({
      schemaVersion: "prooftoact.fresh-cluster-final-principal-census.v1",
      status: "EXACT_RUNTIME_USERS",
      clusterId: adminAuthentication.sqlClusterId,
      names: adminDeleted.names.filter((name) => !baselineSet.has(name)),
      observedAt: snapshotTime(),
      providerBacked: true
    });
    requireCondition(finalCensus.clusterId === adminAuthentication.sqlClusterId,
      "FRESH_CLUSTER_FINAL_PRINCIPAL_CENSUS_REJECTED");
    await record("FINAL_PRINCIPAL_CENSUS_ACCEPTED", finalCensus);

    await record("INGRESS_DELETE_DISPATCHING", {
      entrySha256: digest(ingressEntry)
    }, true);
    try {
      await runtime.deleteTemporaryIngress({ clusterId, entry: ingressEntry });
    } catch (cause) {
      validateTemporaryAllowlistReadback(
        await readAllowlist(), ingressEntry, { present: false }
      );
      await record("INGRESS_DELETE_ACKNOWLEDGEMENT_RECONCILED", {
        acknowledgementCauseSha256: textDigest(cause?.message ?? "UNKNOWN"),
        entrySha256: digest(ingressEntry)
      });
    }
    const ingressDeleted = validateTemporaryAllowlistReadback(
      await readAllowlist(), ingressEntry, { present: false }
    );
    ingressAbsent = true;
    await record("INGRESS_DELETE_ABSENT", ingressDeleted);

    const receipt = Object.freeze({
      schemaVersion: CONTROLLER_SCHEMA,
      status: "PASS",
      adminCredentialAbsent: true,
      adminSecretCredentialRevokedByPrincipalDeletion: true,
      adminSecretVersionRetained: true,
      adminSqlPrincipalAbsent: true,
      billingAuthorizationSha256: command.billingAuthorizationSha256,
      bootstrapReceiptSha256: digest(bootstrapReceipt),
      clusterDeleteProtection: cluster.deleteProtection,
      clusterIdSha256: cluster.clusterIdSha256,
      clusterMode: command.clusterMode,
      commandSha256: command.commandSha256,
      controllerGeneratedRecoverySource: true,
      controllerTableArn: command.controllerTableArn,
      finalPrincipalCensusSha256: finalCensus.namesSha256,
      freshClusterRetained: true,
      globalKeySha256: command.globalKeySha256,
      ingressEmpty: true,
      manualClusterReceiptSha256: command.manualClusterReceiptSha256,
      operationId: command.operationId,
      recoveryAppendReceiptSha256: digest(recoveryAppend),
      recoveryManagedMcpProofSha256: digest(recoveryMcpProof),
      recoveryManagedMcpRequestSha256: plannedRequestSha256,
      recoveryPreparationReceiptSha256:
        recoveryPreparation.preparationReceiptSha256,
      recoveryPublicationInputsCommittedBeforeAdminDeletion: true,
      recoveryReplayReceiptSha256: digest(recoveryReplay),
      recoverySourceBootstrapAdminUsed: true,
      recoverySourceReceiptSha256: recoveryPreparation.sourceReceiptSha256,
      sqlClusterIdSha256: textDigest(adminAuthentication.sqlClusterId),
      previousReceiptSha256,
      primaryClusterMapping,
      primaryClusterMappingReceiptSha256:
        primaryClusterMapping.receiptSha256,
      privateRecoveryQueryBinding:
        recoveryPreparation.preparationReceipt.privateRecoveryQueryBinding,
      privateRecoveryQueryBindingSha256:
        recoveryPreparation.preparationReceipt.
          privateRecoveryQueryBindingSha256,
      separateTeardownApprovalRequired: true,
      sourceCommit: command.sourceCommit,
      transitionCount: sequence,
      treeDigest: command.treeDigest
    });
    const finalized = await provider.finalize({ command, receipt });
    requireCondition(canonicalJson(finalized) === canonicalJson(receipt),
      "FRESH_CLUSTER_FINALIZATION_REJECTED");
    return finalized;
  } catch (cause) {
    primaryCause = cause;
  }

  let cleanupAmbiguous = false;
  if (!adminPossible && !adminAbsent && clusterId) {
    try {
      const discovered = validateSqlUserInventory(await readSqlUsers());
      if (discovered.names.includes(BOOTSTRAP_USERNAME)) {
        adminPossible = true;
        sqlBaseline = Object.freeze({
          ...discovered,
          names: Object.freeze(discovered.names.filter((name) =>
            name !== BOOTSTRAP_USERNAME))
        });
      } else {
        adminAbsent = true;
      }
      await record("FAILURE_ADMIN_PRESTATE_DISCOVERED", {
        adminPresent: adminPossible,
        inventorySha256: discovered.snapshotSha256,
        userCount: discovered.names.length
      });
    } catch {
      cleanupAmbiguous = true;
    }
  }
  if (adminPossible && !adminAbsent && clusterId && sqlBaseline) {
    try {
      if (!phases.has("ADMIN_DELETE_DISPATCHING")) {
        await record("ADMIN_DELETE_DISPATCHING", {
          usernameSha256: textDigest(BOOTSTRAP_USERNAME)
        }, true);
      }
      try {
        await runtime.deleteSqlAdmin({
          clusterId,
          username: BOOTSTRAP_USERNAME
        });
      } catch (cause) {
        const reconciled = validateSqlUserInventory(await readSqlUsers());
        requireCondition(!reconciled.names.includes(BOOTSTRAP_USERNAME),
          "FRESH_CLUSTER_ADMIN_CLEANUP_RECONCILIATION_REJECTED");
        if (!phases.has("ADMIN_DELETE_ACKNOWLEDGEMENT_RECONCILED")) {
          await record("ADMIN_DELETE_ACKNOWLEDGEMENT_RECONCILED", {
            acknowledgementCauseSha256:
              textDigest(cause?.message ?? "UNKNOWN"),
            inventorySha256: reconciled.snapshotSha256
          });
        }
      }
      const readback = validateSqlUserInventory(await readSqlUsers());
      requireCondition(!readback.names.includes(BOOTSTRAP_USERNAME),
        "FRESH_CLUSTER_ADMIN_CLEANUP_REJECTED");
      adminAbsent = true;
      if (!phases.has("ADMIN_DELETE_ABSENT")) {
        await record("ADMIN_DELETE_ABSENT", {
          inventorySha256: readback.snapshotSha256,
          userCount: readback.names.length
        });
      }
    } catch {
      cleanupAmbiguous = true;
    }
  }
  if (ingressPossible && !ingressAbsent && clusterId && ingressEntry) {
    try {
      if (!phases.has("INGRESS_DELETE_DISPATCHING")) {
        await record("INGRESS_DELETE_DISPATCHING", {
          entrySha256: digest(ingressEntry)
        }, true);
      }
      try {
        await runtime.deleteTemporaryIngress({
          clusterId,
          entry: ingressEntry
        });
      } catch (cause) {
        const reconciled = validateTemporaryAllowlistReadback(
          await readAllowlist(), ingressEntry, { present: false }
        );
        if (!phases.has("INGRESS_DELETE_ACKNOWLEDGEMENT_RECONCILED")) {
          await record("INGRESS_DELETE_ACKNOWLEDGEMENT_RECONCILED", {
            acknowledgementCauseSha256:
              textDigest(cause?.message ?? "UNKNOWN"),
            allowlistSha256: reconciled.allowlistSha256,
            entrySha256: digest(ingressEntry)
          });
        }
      }
      const readback = validateTemporaryAllowlistReadback(
        await readAllowlist(), ingressEntry, { present: false }
      );
      ingressAbsent = true;
      if (!phases.has("INGRESS_DELETE_ABSENT")) {
        await record("INGRESS_DELETE_ABSENT", readback);
      }
    } catch {
      cleanupAmbiguous = true;
    }
  }

  if (cleanupAmbiguous || !adminAbsent || !ingressAbsent) {
    reject("FRESH_CLUSTER_CLEANUP_PENDING_RETRY_REQUIRED", primaryCause);
  }

  const terminal = Object.freeze({
    schemaVersion: TERMINAL_SCHEMA,
    status: "FAILED_CLUSTER_RETAINED_NO_AUTOMATIC_TEARDOWN",
    adminCredentialAbsent: adminAbsent,
    adminSecretCredentialRevokedByPrincipalDeletion: adminAbsent,
    adminSecretVersionRetained: phases.has("ADMIN_SECRET_SEALED"),
    adminSqlPrincipalAbsent: adminAbsent,
    clusterIdSha256: clusterId === undefined ? null : textDigest(clusterId),
    commandSha256: command.commandSha256,
    controllerTableArn: command.controllerTableArn,
    failureCode: /^[A-Z][A-Z0-9_]{2,127}$/u.test(primaryCause?.message ?? "")
      ? primaryCause.message
      : "FRESH_CLUSTER_UNCLASSIFIED_FAILURE",
    globalKeySha256: command.globalKeySha256,
    ingressEmpty: ingressAbsent,
    operationId: command.operationId,
    previousReceiptSha256,
    separateTeardownApprovalRequired: true,
    transitionCount: sequence
  });
  const terminalized = await provider.terminalize({ command, terminal });
  requireCondition(canonicalJson(terminalized) === canonicalJson(terminal),
    "FRESH_CLUSTER_TERMINALIZATION_REJECTED");
  reject(terminal.failureCode, primaryCause);
}

export const __test = Object.freeze({
  BOOTSTRAP_USERNAME,
  buildPrimaryClusterMappingReceipt,
  canonicalJson,
  digest,
  textDigest,
  validateAdminCredential,
  validateAuthentication,
  validateReservation
});
