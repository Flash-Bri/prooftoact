import { createHash, createPublicKey } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";
import {
  managedMcpLogicalRequest
} from "./managed-mcp-client.js";
import {
  renderRecoveryQuery,
  validateRecoveryRow
} from "./recovery-store.js";
import { parseStrictJson } from "./strict-json.js";

const APPROVAL_SCHEMA = "prooftoact.private-recovery-query-approval.v1";
const PROVIDER_BINDING_SCHEMA =
  "prooftoact.private-recovery-query-binding.v1";
const COMMAND_SCHEMA = "prooftoact.private-recovery-query-command.v1";
const RECEIPT_SCHEMA = "prooftoact.private-recovery-query-receipt.v1";
const RECOVERY_DATABASE = "tideproof_recovery";
const RECEIPT_BOUNDARY = "RECOVERED_CONTEXT_ONLY";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const LEXICAL_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;
const FUNCTION_ARN =
  /^arn:aws:lambda:us-east-1:[0-9]{12}:function:prooftoact-private-recovery-query$/u;
const SECRET_ARN =
  /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/private-recovery-query\/managed-mcp-[A-Za-z0-9]{6}$/u;
const MANAGED_MCP_ENDPOINT = "https://cockroachlabs.cloud/mcp";
const MANAGED_MCP_PROTOCOL_VERSION = "2025-03-26";
const OPERATION_KEY_DOMAIN = "PRIVATE_AWS_MANAGED_MCP_RECOVERY_QUERY";
const GENERIC_EXECUTION_FAILURE = "PRIVATE_RECOVERY_QUERY_EXECUTION_FAILED";
const SAFE_EXECUTION_FAILURE_CODES = new Set([
  "PRIVATE_RECOVERY_QUERY_APPROVAL_BINDING_REJECTED",
  "PRIVATE_RECOVERY_QUERY_APPROVAL_REJECTED",
  "PRIVATE_RECOVERY_QUERY_CLOCK_REJECTED",
  "PRIVATE_RECOVERY_QUERY_DISPATCH_STATE_REJECTED",
  "PRIVATE_RECOVERY_QUERY_EXTERNAL_ACTION_SEQUENCE_REJECTED",
  "PRIVATE_RECOVERY_QUERY_FINALIZATION_REJECTED",
  "PRIVATE_RECOVERY_QUERY_LAMBDA_CONTEXT_REJECTED",
  "PRIVATE_RECOVERY_QUERY_MCP_CLIENT_REJECTED",
  "PRIVATE_RECOVERY_QUERY_MCP_RESULT_REJECTED",
  "PRIVATE_RECOVERY_QUERY_OPERATION_ALREADY_DISPATCHED",
  "PRIVATE_RECOVERY_QUERY_REQUEST_BINDING_REJECTED",
  "PRIVATE_RECOVERY_QUERY_RESULT_CARDINALITY_REJECTED",
  "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED",
  "PRIVATE_RECOVERY_QUERY_SECRET_READER_REJECTED",
  "PRIVATE_RECOVERY_QUERY_SIGNED_ROW_BINDING_REJECTED",
  "PRIVATE_RECOVERY_QUERY_STORED_STATE_REJECTED",
  "PRIVATE_RECOVERY_QUERY_STORE_REJECTED",
  "PRIVATE_RECOVERY_QUERY_TRANSPORT_EVIDENCE_REJECTED"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && [Object.prototype, null].includes(
      Object.getPrototypeOf(value)
    );
}

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalJson(value));
}

function lineDigest(value) {
  return sha256(`${canonicalJson(value)}\n`);
}

function requireText(value, pattern, code, maximum = 4096) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= maximum && !/[\u0000\r\n]/u.test(value) &&
    (pattern === null || pattern.test(value)), code);
  return value;
}

function requireTimestamp(value, code) {
  requireText(value, null, code, 64);
  const milliseconds = Date.parse(value);
  requireCondition(Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return value;
}

function requireCanonicalBase64(value, code, maximumBytes = 4096) {
  requireText(value, null, code, maximumBytes * 2);
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length > 0 && bytes.length <= maximumBytes &&
    bytes.toString("base64") === value, code);
  return value;
}

function requireP256Spki(value, code) {
  requireCanonicalBase64(value, code, 1024);
  const bytes = Buffer.from(value, "base64");
  let key;
  try {
    key = createPublicKey({ key: bytes, format: "der", type: "spki" });
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(key.asymmetricKeyType === "ec" &&
    ["prime256v1", "P-256"].includes(key.asymmetricKeyDetails?.namedCurve) &&
    key.export({ format: "der", type: "spki" }).equals(bytes), code);
  return value;
}

export function validatePrimaryClusterMapping(value) {
  const code = "PRIVATE_RECOVERY_QUERY_CLUSTER_MAPPING_REJECTED";
  requireCondition(exactKeys(value, [
    "cloud", "clusterInventorySha256", "cockroachVersion", "host",
    "manualClusterReceiptSha256", "observedAt", "providerClusterId",
    "receiptSha256", "schemaVersion", "sourceBindingSha256", "sourceCommit",
    "sqlClusterId", "status", "treeDigest"
  ]) &&
    value.schemaVersion === "prooftoact.primary-provider-sql-mapping.v1" &&
    value.status === "PROVIDER_READBACK_BOUND" &&
    value.cloud === "COCKROACHDB_CLOUD_ON_AWS" &&
    UUID.test(value.providerClusterId ?? "") &&
    LEXICAL_UUID.test(value.sqlClusterId ?? "") &&
    value.providerClusterId !== value.sqlClusterId &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    [value.clusterInventorySha256, value.sourceBindingSha256,
      value.receiptSha256].every((item) => HEX_64.test(item ?? "")) &&
    (value.manualClusterReceiptSha256 === null ||
      HEX_64.test(value.manualClusterReceiptSha256 ?? "")) &&
    /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.cockroachlabs\.cloud$/u
      .test(value.host ?? "") &&
    typeof value.cockroachVersion === "string" &&
    value.cockroachVersion.length >= 3 && value.cockroachVersion.length <= 256 &&
    !/[\u0000\r\n]/u.test(value.cockroachVersion), code);
  requireTimestamp(value.observedAt, code);
  const { receiptSha256, ...body } = value;
  requireCondition(receiptSha256 === lineDigest(body), code);
  return Object.freeze({ ...value });
}

export function validatePrivateRecoveryQueryProviderBinding(value, now = null) {
  const code = "PRIVATE_RECOVERY_QUERY_PROVIDER_BINDING_REJECTED";
  requireCondition(exactKeys(value, [
    "billingAuthorizationSha256", "bindingSha256", "expectedBundleDigest",
    "expectedSourceClusterId", "expectedSourceSqlClusterId", "expiresAt",
    "operationId", "primaryClusterMapping",
    "primaryClusterMappingReceiptSha256", "publisherKeyId",
    "publisherPublicKeySpkiBase64", "recoveryClusterId", "recoverySessionId",
    "schemaVersion", "sourceCommit", "sourceCommitTs", "sourceDigest",
    "status", "subjectBindingHash", "tenantId", "treeDigest"
  ]) && value.schemaVersion === PROVIDER_BINDING_SCHEMA &&
    value.status === "SANITIZED_PROVIDER_BOUND" &&
    UUID.test(value.operationId ?? "") &&
    HEX_40.test(value.sourceCommit ?? "") && HEX_40.test(value.treeDigest ?? "") &&
    [value.billingAuthorizationSha256, value.expectedBundleDigest,
      value.primaryClusterMappingReceiptSha256, value.sourceDigest,
      value.subjectBindingHash, value.bindingSha256]
      .every((item) => HEX_64.test(item ?? "")) &&
    [value.expectedSourceClusterId, value.recoveryClusterId,
      value.recoverySessionId, value.tenantId]
      .every((item) => UUID.test(item ?? "")) &&
    value.recoveryClusterId !== value.expectedSourceClusterId &&
    LEXICAL_UUID.test(value.expectedSourceSqlClusterId ?? "") &&
    value.expectedSourceSqlClusterId !== value.expectedSourceClusterId &&
    /^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(value.publisherKeyId ?? ""), code);
  const primaryClusterMapping = validatePrimaryClusterMapping(
    value.primaryClusterMapping
  );
  requireCondition(primaryClusterMapping.providerClusterId ===
      value.expectedSourceClusterId &&
    primaryClusterMapping.sqlClusterId === value.expectedSourceSqlClusterId &&
    primaryClusterMapping.receiptSha256 ===
      value.primaryClusterMappingReceiptSha256 &&
    primaryClusterMapping.sourceCommit === value.sourceCommit &&
    primaryClusterMapping.treeDigest === value.treeDigest, code);
  requireP256Spki(value.publisherPublicKeySpkiBase64, code);
  const sourceCommitTs = Date.parse(requireTimestamp(value.sourceCommitTs, code));
  const expiresAt = Date.parse(requireTimestamp(value.expiresAt, code));
  requireCondition(expiresAt > sourceCommitTs, code);
  const { bindingSha256, ...body } = value;
  requireCondition(bindingSha256 === lineDigest(body), code);
  if (now !== null) {
    const observedAt = now instanceof Date ? now.getTime() : Number.NaN;
    requireCondition(Number.isFinite(observedAt) && observedAt < expiresAt, code);
  }
  return Object.freeze({ ...value });
}

export function validatePrivateRecoveryQueryApproval(value, now = null) {
  const code = "PRIVATE_RECOVERY_QUERY_APPROVAL_REJECTED";
  requireCondition(exactKeys(value, [
    "approvedAt",
    "billingAuthorizationSha256",
    "expectedBundleDigest",
    "expectedSourceClusterId",
    "expectedSourceCommitTs",
    "expectedSourceSqlClusterId",
    "expiresAt",
    "mcpSecretArnSha256",
    "mcpSecretValueSha256",
    "mcpSecretVersionIdSha256",
    "operationId",
    "providerBindingSha256",
    "publisherKeyId",
    "publisherPublicKeySpkiBase64",
    "primaryClusterMapping",
    "recoveryClusterId",
    "recoverySessionId",
    "schemaVersion",
    "sourceCommit",
    "sourceClusterMappingReceiptSha256",
    "sourceDigest",
    "subjectBindingHash",
    "tenantId",
    "treeDigest"
  ]) && value.schemaVersion === APPROVAL_SCHEMA &&
    UUID.test(value.operationId ?? "") &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    [
      value.billingAuthorizationSha256,
      value.expectedBundleDigest,
      value.mcpSecretArnSha256,
      value.mcpSecretValueSha256,
      value.mcpSecretVersionIdSha256,
      value.providerBindingSha256,
      value.sourceClusterMappingReceiptSha256,
      value.sourceDigest,
      value.subjectBindingHash
    ].every((item) => HEX_64.test(item ?? "")) &&
    [
      value.expectedSourceClusterId,
      value.recoveryClusterId,
      value.recoverySessionId,
      value.tenantId
    ].every((item) => UUID.test(item ?? "")) &&
    LEXICAL_UUID.test(value.expectedSourceSqlClusterId ?? "") &&
    value.expectedSourceSqlClusterId !== value.expectedSourceClusterId &&
    /^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(value.publisherKeyId ?? ""), code);
  const primaryClusterMapping = validatePrimaryClusterMapping(
    value.primaryClusterMapping
  );
  requireCondition(primaryClusterMapping.providerClusterId ===
      value.expectedSourceClusterId &&
    primaryClusterMapping.sqlClusterId === value.expectedSourceSqlClusterId &&
    primaryClusterMapping.receiptSha256 ===
      value.sourceClusterMappingReceiptSha256 &&
    primaryClusterMapping.sourceCommit === value.sourceCommit &&
    primaryClusterMapping.treeDigest === value.treeDigest, code);
  requireP256Spki(value.publisherPublicKeySpkiBase64, code);
  requireTimestamp(value.expectedSourceCommitTs, code);
  const approvedAt = Date.parse(requireTimestamp(value.approvedAt, code));
  const expiresAt = Date.parse(requireTimestamp(value.expiresAt, code));
  requireCondition(expiresAt > approvedAt &&
    expiresAt - approvedAt <= 24 * 60 * 60 * 1_000, code);
  if (now !== null) {
    const observedAt = now instanceof Date ? now.getTime() : Number.NaN;
    requireCondition(Number.isFinite(observedAt) &&
      observedAt >= approvedAt - 60_000 && observedAt < expiresAt, code);
  }
  return Object.freeze({ ...value });
}

export function privateRecoveryQueryApprovalSha256(value) {
  return digest(validatePrivateRecoveryQueryApproval(value));
}

export function privateRecoveryQueryOperationGlobalKeySha256(value) {
  const approval = validatePrivateRecoveryQueryApproval(value);
  return digest({
    domain: OPERATION_KEY_DOMAIN,
    operationId: approval.operationId,
  });
}

export function buildPrivateRecoveryQueryCommand({
  approval: rawApproval,
  codeZipSha256,
  configSha256,
  functionArn,
  functionVersion,
  mcpSecretArn,
  mcpSecretVersionId,
  releaseControlTableArn,
  now = new Date()
}) {
  const code = "PRIVATE_RECOVERY_QUERY_COMMAND_REJECTED";
  const approval = validatePrivateRecoveryQueryApproval(rawApproval, now);
  requireCondition(HEX_64.test(codeZipSha256 ?? "") &&
    HEX_64.test(configSha256 ?? "") &&
    FUNCTION_ARN.test(functionArn ?? "") &&
    /^(?:[1-9][0-9]{0,8})$/u.test(functionVersion ?? "") &&
    SECRET_ARN.test(mcpSecretArn ?? "") &&
    /^[A-Za-z0-9_-]{32,64}$/u.test(mcpSecretVersionId ?? "") &&
    TABLE_ARN.test(releaseControlTableArn ?? "") &&
    sha256(mcpSecretArn) === approval.mcpSecretArnSha256 &&
    sha256(mcpSecretVersionId) === approval.mcpSecretVersionIdSha256, code);
  const query = renderRecoveryQuery({
    recoverySessionId: approval.recoverySessionId,
    tenantId: approval.tenantId,
    subjectBindingHash: approval.subjectBindingHash,
    sourceDigest: approval.sourceDigest
  });
  const logicalRequest = managedMcpLogicalRequest({
    clusterId: approval.recoveryClusterId,
    query
  });
  const base = Object.freeze({
    schemaVersion: COMMAND_SCHEMA,
    approvalSha256: digest(approval),
    codeZipSha256,
    configSha256,
    functionArn,
    functionVersion,
    logicalRequestSha256: digest(logicalRequest),
    operationId: approval.operationId,
    querySha256: sha256(query),
    releaseControlTableArn,
    sourceCommit: approval.sourceCommit,
    treeDigest: approval.treeDigest
  });
  return Object.freeze({
    ...base,
    commandSha256: digest(base),
    globalKeySha256: privateRecoveryQueryOperationGlobalKeySha256(approval)
  });
}

export function validatePrivateRecoveryQueryCommand(value) {
  const code = "PRIVATE_RECOVERY_QUERY_COMMAND_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalSha256",
    "codeZipSha256",
    "commandSha256",
    "configSha256",
    "functionArn",
    "functionVersion",
    "globalKeySha256",
    "logicalRequestSha256",
    "operationId",
    "querySha256",
    "releaseControlTableArn",
    "schemaVersion",
    "sourceCommit",
    "treeDigest"
  ]) && value.schemaVersion === COMMAND_SCHEMA &&
    [
      value.approvalSha256,
      value.codeZipSha256,
      value.commandSha256,
      value.configSha256,
      value.globalKeySha256,
      value.logicalRequestSha256,
      value.querySha256
    ].every((item) => HEX_64.test(item ?? "")) &&
    UUID.test(value.operationId ?? "") &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    FUNCTION_ARN.test(value.functionArn ?? "") &&
    /^(?:[1-9][0-9]{0,8})$/u.test(value.functionVersion ?? "") &&
    TABLE_ARN.test(value.releaseControlTableArn ?? ""), code);
  const { commandSha256, globalKeySha256, ...base } = value;
  requireCondition(commandSha256 === digest(base) &&
    globalKeySha256 === digest({
      domain: OPERATION_KEY_DOMAIN,
      operationId: value.operationId,
    }), code);
  return Object.freeze({ ...value });
}

function rowsFromMcpResult(result) {
  const code = "PRIVATE_RECOVERY_QUERY_MCP_RESULT_REJECTED";
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

function validateTransportEvidence({
  evidence,
  logicalRequest,
  query
}) {
  const code = "PRIVATE_RECOVERY_QUERY_TRANSPORT_EVIDENCE_REJECTED";
  const transport = evidence?.transportEvidence;
  const semantic = evidence?.semanticRequestEvidence;
  requireCondition(plainObject(transport) &&
    transport.schemaVersion === "tideproof.managed-mcp-transport-evidence.v2" &&
    transport.endpointAuthority === "cockroachlabs.cloud" &&
    transport.endpointSha256 === sha256(MANAGED_MCP_ENDPOINT) &&
    transport.clusterIdSha256 ===
      sha256(logicalRequest.recoveryClusterId) &&
    transport.protocolVersion === MANAGED_MCP_PROTOCOL_VERSION &&
    transport.redirectPolicy === "error" &&
    transport.boundedResponseBytes === 256 * 1024 &&
    Array.isArray(transport.rpcCalls) && transport.rpcCalls.length === 2 &&
    transport.rpcCalls[0]?.method === "initialize" &&
    transport.rpcCalls[1]?.method === "tools/call" &&
    transport.rpcCalls.every((call) => call.httpStatus === 200 &&
      call.responseCorrelated === true && call.sessionContinuous === true) &&
    Array.isArray(transport.notifications) &&
    transport.notifications.length === 1 &&
    transport.notifications[0]?.method === "notifications/initialized" &&
    transport.notifications[0]?.httpStatus === 202 &&
    transport.notifications[0]?.sessionContinuous === true &&
    transport.close?.attempted === true &&
    transport.close?.httpStatus === 204 &&
    transport.close?.sessionContinuous === true &&
    HEX_64.test(transport.sessionIdSha256 ?? "") &&
    plainObject(semantic) && semantic.database === RECOVERY_DATABASE &&
    semantic.toolName === "select_query" && semantic.query === query &&
    semantic.logicalMcpRequestSha256 === digest(logicalRequest) &&
    semantic.logicalRequest?.renderedQuerySha256 === sha256(query) &&
    semantic.logicalRequest?.recoveryClusterId ===
      logicalRequest.recoveryClusterId &&
    semantic.evidenceSha256 === digest(Object.fromEntries(
      Object.entries(semantic).filter(([key]) => key !== "evidenceSha256")
    )), code);
  return Object.freeze({
    closeHttpStatus: transport.close.httpStatus,
    endpointSha256: transport.endpointSha256,
    notificationCount: transport.notifications.length,
    protocolVersion: transport.protocolVersion,
    rpcCallCount: transport.rpcCalls.length,
    semanticEvidenceSha256: semantic.evidenceSha256,
    sessionContinuous: true,
    toolCallCount: transport.rpcCalls.filter(({ method }) =>
      method === "tools/call").length,
    transportEvidenceSha256: digest(transport)
  });
}

function errorCodeFor(cause) {
  let message = null;
  try {
    message = typeof cause?.message === "string" ? cause.message : null;
  } catch {
    return GENERIC_EXECUTION_FAILURE;
  }
  return SAFE_EXECUTION_FAILURE_CODES.has(message)
    ? message : GENERIC_EXECUTION_FAILURE;
}

function receiptWithDigest(body) {
  const receipt = Object.freeze({ ...body, receiptSha256: digest(body) });
  return validatePrivateRecoveryQueryReceipt(receipt);
}

export function validatePrivateRecoveryQueryReceipt(value) {
  const code = "PRIVATE_RECOVERY_QUERY_RECEIPT_REJECTED";
  requireCondition(plainObject(value) && value.schemaVersion === RECEIPT_SCHEMA &&
    ["PASS", "FAILED_NO_PROVIDER_CALL", "UNKNOWN_DO_NOT_RETRY"]
      .includes(value.status) && HEX_64.test(value.receiptSha256 ?? "") &&
    UUID.test(value.operationId ?? "") &&
    HEX_64.test(value.commandSha256 ?? "") &&
    HEX_64.test(value.approvalSha256 ?? "") &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    value.boundary === RECEIPT_BOUNDARY &&
    value.authorityTransferred === false &&
    value.requiresFreshAuthorization === true, code);
  const { receiptSha256, ...body } = value;
  requireCondition(receiptSha256 === digest(body), code);
  if (value.status === "PASS") {
    requireCondition(exactKeys(value, [
      "approvalSha256", "authorityTransferred", "boundary", "bundleDigest",
      "commandSha256", "completedAt", "functionArnSha256", "functionVersion",
      "lambdaRequestIdSha256", "managedMcp", "operationId", "publisherKeyIdSha256",
      "providerBindingSha256", "receiptSha256", "recoverySessionIdSha256",
      "requiresFreshAuthorization",
      "schemaVersion", "signatureDigest", "sourceClusterIdSha256",
      "sourceClusterMappingReceiptSha256", "sourceCommit", "sourceCommitTs",
      "sourceDigest", "sourceSqlClusterIdSha256", "status", "subjectBindingSha256",
      "tenantIdSha256", "treeDigest"
    ]) && [
      value.bundleDigest,
      value.functionArnSha256,
      value.lambdaRequestIdSha256,
      value.publisherKeyIdSha256,
      value.providerBindingSha256,
      value.recoverySessionIdSha256,
      value.signatureDigest,
      value.sourceClusterIdSha256,
      value.sourceClusterMappingReceiptSha256,
      value.sourceDigest,
      value.sourceSqlClusterIdSha256,
      value.subjectBindingSha256,
      value.tenantIdSha256
    ].every((item) => HEX_64.test(item ?? "")) &&
      /^(?:[1-9][0-9]{0,8})$/u.test(value.functionVersion ?? "") &&
      exactKeys(value.managedMcp, [
        "closeHttpStatus", "endpointSha256", "notificationCount",
        "protocolVersion", "rpcCallCount", "semanticEvidenceSha256",
        "sessionContinuous", "toolCallCount", "transportEvidenceSha256"
      ]) && value.managedMcp.closeHttpStatus === 204 &&
      value.managedMcp.notificationCount === 1 &&
      value.managedMcp.rpcCallCount === 2 &&
      value.managedMcp.toolCallCount === 1 &&
      value.managedMcp.sessionContinuous === true &&
      typeof value.managedMcp.protocolVersion === "string" &&
      /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(
        value.managedMcp.protocolVersion
      ) && [
        value.managedMcp.endpointSha256,
        value.managedMcp.semanticEvidenceSha256,
        value.managedMcp.transportEvidenceSha256
      ].every((item) => HEX_64.test(item ?? "")) &&
      Number.isFinite(Date.parse(value.completedAt)) &&
      Number.isFinite(Date.parse(value.sourceCommitTs)), code);
  } else {
    requireCondition(exactKeys(value, [
      "approvalSha256", "authorityTransferred", "boundary", "commandSha256",
      "errorCode", "lambdaRequestIdSha256", "operationId", "providerCallPossible",
      "receiptSha256", "requiresFreshAuthorization", "schemaVersion", "sourceCommit",
      "status", "treeDigest"
    ]) && /^[A-Z][A-Z0-9_]{2,127}$/u.test(value.errorCode ?? "") &&
      (value.lambdaRequestIdSha256 === null ||
        HEX_64.test(value.lambdaRequestIdSha256 ?? "")) &&
      value.providerCallPossible ===
        (value.status === "UNKNOWN_DO_NOT_RETRY"), code);
  }
  return Object.freeze({ ...value });
}

function validateStoredState(value, command) {
  const code = "PRIVATE_RECOVERY_QUERY_STORED_STATE_REJECTED";
  requireCondition(plainObject(value) &&
    ["RESERVED", "DISPATCHING", "FINAL", "FAILED", "UNKNOWN"]
      .includes(value.status) &&
    value.commandSha256 === command.commandSha256 &&
    value.operationId === command.operationId, code);
  if (["FINAL", "FAILED", "UNKNOWN"].includes(value.status)) {
    validatePrivateRecoveryQueryReceipt(value.receipt);
    requireCondition(value.receipt.commandSha256 === command.commandSha256 &&
      value.receipt.operationId === command.operationId, code);
  }
  return value;
}

function requireCapabilities(target, names, code) {
  requireCondition(target && names.every((name) =>
    typeof target[name] === "function"), code);
}

export async function reservePrivateRecoveryQuery({ command: rawCommand, store }) {
  const command = validatePrivateRecoveryQueryCommand(rawCommand);
  requireCapabilities(store, ["reserve"],
    "PRIVATE_RECOVERY_QUERY_STORE_REJECTED");
  return validateStoredState(await store.reserve(command), command);
}

export async function runPrivateRecoveryQuery({
  approval: rawApproval,
  clock = () => new Date(),
  command: rawCommand,
  createMcpClient,
  lambdaContext,
  secretReader,
  store
}) {
  const command = validatePrivateRecoveryQueryCommand(rawCommand);
  const invocationStartedAt = clock();
  const approval = validatePrivateRecoveryQueryApproval(rawApproval);
  requireCondition(digest(approval) === command.approvalSha256 &&
    approval.operationId === command.operationId &&
    approval.sourceCommit === command.sourceCommit &&
    approval.treeDigest === command.treeDigest,
  "PRIVATE_RECOVERY_QUERY_APPROVAL_BINDING_REJECTED");
  requireCapabilities(store, [
    "failBeforeDispatch", "finalize", "markDispatch", "markUnknown", "read"
  ], "PRIVATE_RECOVERY_QUERY_STORE_REJECTED");
  requireCapabilities(secretReader, ["readExactVersion"],
    "PRIVATE_RECOVERY_QUERY_SECRET_READER_REJECTED");
  requireCondition(typeof createMcpClient === "function" &&
    plainObject(lambdaContext) &&
    UUID.test(lambdaContext.awsRequestId ?? "") &&
    lambdaContext.functionVersion === command.functionVersion &&
    lambdaContext.invokedFunctionArn ===
      `${command.functionArn}:${command.functionVersion}`,
  "PRIVATE_RECOVERY_QUERY_LAMBDA_CONTEXT_REJECTED");
  const lambdaRequestIdSha256 = sha256(lambdaContext.awsRequestId);
  let dispatched = false;
  let client = null;
  try {
    const existing = validateStoredState(await store.read(command), command);
    if (["FINAL", "FAILED", "UNKNOWN"].includes(existing.status)) {
      return validatePrivateRecoveryQueryReceipt(existing.receipt);
    }
    requireCondition(existing.status === "RESERVED",
      "PRIVATE_RECOVERY_QUERY_OPERATION_ALREADY_DISPATCHED");
    requireCondition(invocationStartedAt instanceof Date &&
      Number.isFinite(invocationStartedAt.getTime()),
    "PRIVATE_RECOVERY_QUERY_CLOCK_REJECTED");
    validatePrivateRecoveryQueryApproval(approval, invocationStartedAt);
    const secret = await secretReader.readExactVersion();
    requireCondition(exactKeys(secret, [
      "secretArnSha256", "secretValue", "secretValueSha256",
      "secretVersionIdSha256"
    ]) && secret.secretArnSha256 === approval.mcpSecretArnSha256 &&
      secret.secretVersionIdSha256 === approval.mcpSecretVersionIdSha256 &&
      secret.secretValueSha256 === approval.mcpSecretValueSha256 &&
      typeof secret.secretValue === "string" &&
      secret.secretValue.length >= 24 && secret.secretValue.length <= 4096 &&
      !/[\u0000\r\n\u007f]/u.test(secret.secretValue),
    "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED");
    let secretPayload;
    try {
      secretPayload = parseStrictJson(secret.secretValue, {
        duplicateCode: "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED",
        invalidCode: "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED"
      });
    } catch (cause) {
      reject("PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED", cause);
    }
    requireCondition(exactKeys(secretPayload, ["apiKey"]) &&
      typeof secretPayload.apiKey === "string" &&
      secretPayload.apiKey.length >= 24 && secretPayload.apiKey.length <= 4096 &&
      !/[\u0000-\u0020\u007f]/u.test(secretPayload.apiKey) &&
      secret.secretValue === canonicalJson(secretPayload),
    "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED");
    const query = renderRecoveryQuery({
      recoverySessionId: approval.recoverySessionId,
      tenantId: approval.tenantId,
      subjectBindingHash: approval.subjectBindingHash,
      sourceDigest: approval.sourceDigest
    });
    const logicalRequest = managedMcpLogicalRequest({
      clusterId: approval.recoveryClusterId,
      query
    });
    requireCondition(sha256(query) === command.querySha256 &&
      digest(logicalRequest) === command.logicalRequestSha256,
    "PRIVATE_RECOVERY_QUERY_REQUEST_BINDING_REJECTED");
    const dispatch = Object.freeze({
      lambdaRequestIdSha256,
      logicalRequestSha256: command.logicalRequestSha256,
      querySha256: command.querySha256,
      secretValueSha256: secret.secretValueSha256
    });
    const dispatchState = validateStoredState(
      await store.markDispatch(command, dispatch), command
    );
    requireCondition(dispatchState.status === "DISPATCHING" &&
      canonicalJson(dispatchState.dispatch) === canonicalJson(dispatch),
    "PRIVATE_RECOVERY_QUERY_DISPATCH_STATE_REJECTED");
    dispatched = true;
    client = createMcpClient({
      apiKey: secretPayload.apiKey,
      clusterId: approval.recoveryClusterId
    });
    requireCapabilities(client, [
      "close", "selectQuery", "semanticRequestEvidence", "transportEvidence"
    ], "PRIVATE_RECOVERY_QUERY_MCP_CLIENT_REJECTED");
    const expectedActions = [
      "MCP_INITIALIZE", "MCP_INITIALIZED_NOTIFICATION", "MCP_TOOLS_CALL"
    ];
    const observedActions = [];
    const beforeExternalAction = (action) => {
      requireCondition(action === expectedActions[observedActions.length],
        "PRIVATE_RECOVERY_QUERY_EXTERNAL_ACTION_SEQUENCE_REJECTED");
      observedActions.push(action);
    };
    const result = await client.selectQuery({
      clusterId: approval.recoveryClusterId,
      database: RECOVERY_DATABASE,
      query,
      beforeExternalAction
    });
    requireCondition(observedActions.join("\n") === expectedActions.join("\n"),
      "PRIVATE_RECOVERY_QUERY_EXTERNAL_ACTION_SEQUENCE_REJECTED");
    await client.close();
    const evidence = Object.freeze({
      semanticRequestEvidence: client.semanticRequestEvidence(),
      transportEvidence: client.transportEvidence()
    });
    const managedMcp = validateTransportEvidence({ evidence, logicalRequest, query });
    const completedAt = clock();
    requireCondition(completedAt instanceof Date &&
      Number.isFinite(completedAt.getTime()) &&
      completedAt.getTime() >= invocationStartedAt.getTime(),
    "PRIVATE_RECOVERY_QUERY_CLOCK_REJECTED");
    const rows = rowsFromMcpResult(result);
    requireCondition(rows.length === 1,
      "PRIVATE_RECOVERY_QUERY_RESULT_CARDINALITY_REJECTED");
    const validated = validateRecoveryRow(rows[0], {
      recoverySessionId: approval.recoverySessionId,
      tenantId: approval.tenantId,
      subjectBindingHash: approval.subjectBindingHash,
      sourceDigest: approval.sourceDigest,
      expectedSourceClusterId: approval.expectedSourceClusterId,
      trustedPublisherKeys: {
        [approval.publisherKeyId]: approval.publisherPublicKeySpkiBase64
      }
    }, completedAt);
    requireCondition(validated.bundleDigest === approval.expectedBundleDigest &&
      rows[0].publisher_key_id === approval.publisherKeyId &&
      rows[0].source_commit_ts === approval.expectedSourceCommitTs,
    "PRIVATE_RECOVERY_QUERY_SIGNED_ROW_BINDING_REJECTED");
    const body = Object.freeze({
      schemaVersion: RECEIPT_SCHEMA,
      status: "PASS",
      approvalSha256: command.approvalSha256,
      authorityTransferred: false,
      boundary: RECEIPT_BOUNDARY,
      bundleDigest: validated.bundleDigest,
      commandSha256: command.commandSha256,
      completedAt: completedAt.toISOString(),
      functionArnSha256: sha256(command.functionArn),
      functionVersion: command.functionVersion,
      lambdaRequestIdSha256,
      managedMcp,
      operationId: command.operationId,
      publisherKeyIdSha256: sha256(approval.publisherKeyId),
      providerBindingSha256: approval.providerBindingSha256,
      recoverySessionIdSha256: sha256(approval.recoverySessionId),
      requiresFreshAuthorization: true,
      signatureDigest: rows[0].signature_digest,
      sourceClusterIdSha256: sha256(approval.expectedSourceClusterId),
      sourceClusterMappingReceiptSha256:
        approval.sourceClusterMappingReceiptSha256,
      sourceCommit: command.sourceCommit,
      sourceCommitTs: rows[0].source_commit_ts,
      sourceDigest: approval.sourceDigest,
      sourceSqlClusterIdSha256: sha256(approval.expectedSourceSqlClusterId),
      subjectBindingSha256: sha256(approval.subjectBindingHash),
      tenantIdSha256: sha256(approval.tenantId),
      treeDigest: command.treeDigest
    });
    const receipt = receiptWithDigest(body);
    const finalized = validateStoredState(
      await store.finalize(command, dispatch, receipt), command
    );
    requireCondition(finalized.status === "FINAL",
      "PRIVATE_RECOVERY_QUERY_FINALIZATION_REJECTED");
    return validatePrivateRecoveryQueryReceipt(finalized.receipt);
  } catch (cause) {
    await client?.close?.().catch(() => {});
    const body = Object.freeze({
      schemaVersion: RECEIPT_SCHEMA,
      status: dispatched ? "UNKNOWN_DO_NOT_RETRY" : "FAILED_NO_PROVIDER_CALL",
      approvalSha256: command.approvalSha256,
      authorityTransferred: false,
      boundary: RECEIPT_BOUNDARY,
      commandSha256: command.commandSha256,
      errorCode: errorCodeFor(cause),
      lambdaRequestIdSha256,
      operationId: command.operationId,
      providerCallPossible: dispatched,
      requiresFreshAuthorization: true,
      sourceCommit: command.sourceCommit,
      treeDigest: command.treeDigest
    });
    const receipt = receiptWithDigest(body);
    const stored = dispatched
      ? await store.markUnknown(command, receipt)
      : await store.failBeforeDispatch(command, receipt);
    const accepted = validateStoredState(stored, command);
    return ["FINAL", "FAILED", "UNKNOWN"].includes(accepted.status)
      ? validatePrivateRecoveryQueryReceipt(accepted.receipt)
      : receipt;
  }
}

export async function reconcilePrivateRecoveryQuery({ command: rawCommand, store }) {
  const command = validatePrivateRecoveryQueryCommand(rawCommand);
  requireCapabilities(store, ["read"],
    "PRIVATE_RECOVERY_QUERY_STORE_REJECTED");
  const state = validateStoredState(await store.read(command), command);
  if (["FINAL", "FAILED", "UNKNOWN"].includes(state.status)) {
    return validatePrivateRecoveryQueryReceipt(state.receipt);
  }
  return Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-reconciliation.v1",
    status: state.status === "RESERVED"
      ? "INVOCATION_ACK_UNKNOWN_WAIT"
      : "PROVIDER_OUTCOME_UNKNOWN_DO_NOT_RETRY",
    commandSha256: command.commandSha256,
    operationId: command.operationId,
    providerRetryAuthorized: false,
    stateSha256: digest(state)
  });
}

export const __test = Object.freeze({
  APPROVAL_SCHEMA,
  COMMAND_SCHEMA,
  RECEIPT_SCHEMA,
  digest,
  errorCodeFor,
  lineDigest,
  rowsFromMcpResult,
  sha256,
  validateTransportEvidence
});
