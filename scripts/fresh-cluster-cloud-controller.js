import crypto from "node:crypto";

const API_ORIGIN = "https://cockroachlabs.cloud";
const API_VERSION = "2024-09-16";
const CLUSTER_NAME = "prooftoact-gate2";
const BOOTSTRAP_USERNAME = "prooftoact_bootstrap_admin";
const REGION = "us-east-1";
const DELETE_PROTECTION = "ENABLED";
const UPGRADE_TYPE = "AUTOMATIC";
// Cockroach Cloud's OpenAPI exposes int64 values as canonical decimal strings.
const REQUEST_UNIT_LIMIT = "5000000";
const STORAGE_MIB_LIMIT = "1024";
const MAX_RESPONSE_BYTES = 512 * 1024;
const MAX_LIST_PAGES = 32;
// The provider rejects values above 500 even though older generated clients
// advertised a larger maximum.
const LIST_LIMIT = 500;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COCKROACH_SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const TOKEN = /^[A-Za-z0-9._~-]{20,4096}$/u;
const PAGE_TOKEN = /^[^\u0000-\u001f\u007f]{1,4096}$/u;

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
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function textDigest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function validParentFolderId(value) {
  return value === "root" || UUID.test(value ?? "");
}

function encodePath(value, pattern, code) {
  requireCondition(pattern.test(value ?? ""), code);
  return encodeURIComponent(value);
}

export function freshClusterCreateRequest({
  operationId,
  parentFolderId,
  sourceCommit,
  treeDigest
}) {
  const code = "FRESH_CLUSTER_CREATE_REQUEST_REJECTED";
  requireCondition(UUID.test(operationId ?? "") &&
    validParentFolderId(parentFolderId) && HEX_40.test(sourceCommit ?? "") &&
    HEX_40.test(treeDigest ?? ""), code);
  return Object.freeze({
    name: CLUSTER_NAME,
    provider: "AWS",
    spec: Object.freeze({
      delete_protection: DELETE_PROTECTION,
      labels: Object.freeze({
        prooftoact_operation: operationId,
        prooftoact_source: sourceCommit,
        prooftoact_tree: treeDigest
      }),
      parent_id: parentFolderId,
      plan: "BASIC",
      serverless: Object.freeze({
        regions: Object.freeze([REGION]),
        upgrade_type: UPGRADE_TYPE,
        usage_limits: Object.freeze({
          request_unit_limit: REQUEST_UNIT_LIMIT,
          storage_mib_limit: STORAGE_MIB_LIMIT
        }),
        with_empty_ip_allowlist: true
      })
    })
  });
}

export function buildFreshClusterCreateCommand(value) {
  const code = "FRESH_CLUSTER_COMMAND_REJECTED";
  requireCondition(exactKeys(value, [
    "adoptedAdminPasswordSha256",
    "approvalId",
    "approvalSha256",
    "auditorAuthorityReceiptSha256",
    "auditorServiceAccountId",
    "auditorTokenValueSha256",
    "billingAuthorization",
    "clusterMode",
    "controllerTableArn",
    "creatorServiceAccountId",
    "creatorAuthorityReceiptSha256",
    "creatorProviderReadbackReceiptSha256",
    "creatorTokenValueSha256",
    "manualClusterReceiptSha256",
    "operationId",
    "parentFolderId",
    "providerClusterId",
    "sourceCommit",
    "treeDigest"
  ]) && UUID.test(value.approvalId ?? "") &&
    UUID.test(value.auditorServiceAccountId ?? "") &&
    UUID.test(value.creatorServiceAccountId ?? "") &&
    value.auditorServiceAccountId !== value.creatorServiceAccountId &&
    HEX_64.test(value.auditorAuthorityReceiptSha256 ?? "") &&
    HEX_64.test(value.auditorTokenValueSha256 ?? "") &&
    HEX_64.test(value.creatorAuthorityReceiptSha256 ?? "") &&
    HEX_64.test(value.creatorProviderReadbackReceiptSha256 ?? "") &&
    HEX_64.test(value.creatorTokenValueSha256 ?? "") &&
    validParentFolderId(value.parentFolderId) &&
    ["ADOPT_VERIFIED_EXISTING", "CREATE_NEW"].includes(value.clusterMode) &&
    (value.clusterMode === "CREATE_NEW"
      ? UUID.test(value.parentFolderId ?? "") &&
        value.providerClusterId === null &&
        value.manualClusterReceiptSha256 === null &&
        value.adoptedAdminPasswordSha256 === null
      : value.parentFolderId === "root" &&
        UUID.test(value.providerClusterId ?? "") &&
        HEX_64.test(value.manualClusterReceiptSha256 ?? "") &&
        HEX_64.test(value.adoptedAdminPasswordSha256 ?? "")) &&
    /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u
      .test(value.controllerTableArn ?? "") &&
    HEX_64.test(value.approvalSha256 ?? ""), code);
  const billingAuthorization = validateFreshClusterBillingAuthorization(
    value.billingAuthorization
  );
  const createRequest = freshClusterCreateRequest(value);
  const effectIdentitySha256 = textDigest(
    `prooftoact-fresh-cluster-effect-v1\n${value.parentFolderId}\n${CLUSTER_NAME}`
  );
  const command = {
    schemaVersion: "prooftoact.fresh-cluster-command.v1",
    status: "AUTHORIZED_COORDINATES",
    action: value.clusterMode === "CREATE_NEW"
      ? "CREATE_ONE_FRESH_COCKROACH_CLUSTER"
      : "ADOPT_ONE_VERIFIED_FRESH_COCKROACH_CLUSTER",
    apiVersion: API_VERSION,
    region: REGION,
    ...value,
    billingAuthorization,
    billingAuthorizationSha256: digest(billingAuthorization),
    createRequest,
    createRequestSha256: digest(createRequest),
    effectIdentitySha256,
    globalKeySha256: textDigest(
      `prooftoact-fresh-cluster-global-key-v1\n${effectIdentitySha256}`
    )
  };
  return Object.freeze({
    ...command,
    commandSha256: digest(command)
  });
}

export function validateFreshClusterBillingAuthorization(value) {
  const code = "FRESH_CLUSTER_BILLING_AUTHORIZATION_REJECTED";
  const pricingObservedAt = Date.parse(value?.pricingObservedAt);
  const authorizedAt = Date.parse(value?.authorizedAt);
  const approvalExpiresAt = Date.parse(value?.approvalExpiresAt);
  const retentionDeadline = Date.parse(value?.retentionDeadline);
  requireCondition(exactKeys(value, [
    "approvalExpiresAt",
    "authorizationReceiptSha256",
    "authorizedAt",
    "authorizedMonthlyCeilingUsd",
    "clusterCreateApproved",
    "freeBenefitsAssumed",
    "paidWorstCaseMonthlyUsd",
    "pricingObservedAt",
    "pricingSource",
    "pricingSourceSha256",
    "requestUnitLimit",
    "requestUnitPriceUsdPerMillion",
    "retentionDeadline",
    "schemaVersion",
    "separateTeardownApprovalRequired",
    "status",
    "storageMiBLimit",
    "storagePriceUsdPerGiBMonth"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-cluster-billing-authorization.v1" &&
    value.status === "AUTHORIZED_PAID_WORST_CASE" &&
    value.pricingSource === "https://www.cockroachlabs.com/pricing/" &&
    HEX_64.test(value.pricingSourceSha256 ?? "") &&
    value.requestUnitLimit === REQUEST_UNIT_LIMIT &&
    value.storageMiBLimit === STORAGE_MIB_LIMIT &&
    value.requestUnitPriceUsdPerMillion === "0.20" &&
    value.storagePriceUsdPerGiBMonth === "0.50" &&
    value.freeBenefitsAssumed === false &&
    value.paidWorstCaseMonthlyUsd === "1.50" &&
    value.authorizedMonthlyCeilingUsd === "2.00" &&
    HEX_64.test(value.authorizationReceiptSha256 ?? "") &&
    Number(value.paidWorstCaseMonthlyUsd) <=
      Number(value.authorizedMonthlyCeilingUsd) &&
    value.clusterCreateApproved === true &&
    value.separateTeardownApprovalRequired === true &&
    Number.isFinite(pricingObservedAt) && Number.isFinite(authorizedAt) &&
    Number.isFinite(approvalExpiresAt) && Number.isFinite(retentionDeadline) &&
    authorizedAt <= pricingObservedAt &&
    pricingObservedAt <= approvalExpiresAt &&
    authorizedAt < approvalExpiresAt &&
    approvalExpiresAt - authorizedAt <= 60 * 60 * 1000 &&
    approvalExpiresAt <= retentionDeadline &&
    retentionDeadline - authorizedAt <= 24 * 60 * 60 * 1000 &&
    value.pricingObservedAt === new Date(pricingObservedAt).toISOString() &&
    value.authorizedAt === new Date(authorizedAt).toISOString() &&
    value.approvalExpiresAt === new Date(approvalExpiresAt).toISOString() &&
    value.retentionDeadline === new Date(retentionDeadline).toISOString(),
  code);
  return Object.freeze({ ...value });
}

function validateFreshClusterApprovalContract(value, binding) {
  const code = "FRESH_CLUSTER_APPROVAL_REJECTED";
  requireCondition(exactKeys(value, [
    "action",
    "adoptedAdminPasswordSha256",
    "approvalId",
    "approvedAt",
    "approvedBy",
    "auditorAuthorityReceiptSha256",
    "auditorServiceAccountId",
    "auditorTokenValueSha256",
    "billingAuthorization",
    "callerWorkflowRef",
    "callerWorkflowSha",
    "clusterMode",
    "controllerImportGraphSha256",
    "creatorServiceAccountId",
    "creatorAuthorityReceiptSha256",
    "creatorProviderReadbackReceiptSha256",
    "creatorTokenValueSha256",
    "derivedPrimaryApprovalAuthorized",
    "expiresAt",
    "humanAuthorizationReceiptSha256",
    "humanAuthorizedTextSha256",
    "oneShot",
    "operationId",
    "manualClusterReceiptSha256",
    "parentFolderId",
    "partialFailureDisposition",
    "schemaVersion",
    "separateClusterTeardownApprovalRequired",
    "sourceCommit",
    "providerClusterId",
    "sqlBootstrapPort",
    "sqlBootstrapUsername",
    "status",
    "treeDigest"
  ]) && exactKeys(binding, [
    "operationId", "sourceCommit", "treeDigest"
  ]) && value.schemaVersion === "prooftoact.fresh-cluster-approval.v1" &&
    value.status === "APPROVED" &&
    value.action === "CREATE_AND_BOOTSTRAP_ONE_FRESH_COCKROACH_CLUSTER" &&
    value.approvedBy === "BRIAN_SMITH" && value.oneShot === true &&
    value.callerWorkflowRef ===
      "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-fresh-primary.yml@refs/heads/main" &&
    HEX_40.test(value.callerWorkflowSha ?? "") &&
    HEX_64.test(value.controllerImportGraphSha256 ?? "") &&
    HEX_64.test(value.humanAuthorizationReceiptSha256 ?? "") &&
    HEX_64.test(value.humanAuthorizedTextSha256 ?? "") &&
    value.humanAuthorizationReceiptSha256 ===
      value.billingAuthorization?.authorizationReceiptSha256 &&
    value.operationId === binding.operationId &&
    value.sourceCommit === binding.sourceCommit &&
    value.treeDigest === binding.treeDigest &&
    UUID.test(value.approvalId ?? "") &&
    validParentFolderId(value.parentFolderId) &&
    UUID.test(value.creatorServiceAccountId ?? "") &&
    UUID.test(value.auditorServiceAccountId ?? "") &&
    value.creatorServiceAccountId !== value.auditorServiceAccountId &&
    HEX_64.test(value.auditorAuthorityReceiptSha256 ?? "") &&
    HEX_64.test(value.auditorTokenValueSha256 ?? "") &&
    HEX_64.test(value.creatorAuthorityReceiptSha256 ?? "") &&
    HEX_64.test(value.creatorProviderReadbackReceiptSha256 ?? "") &&
    HEX_64.test(value.creatorTokenValueSha256 ?? "") &&
    ["ADOPT_VERIFIED_EXISTING", "CREATE_NEW"].includes(value.clusterMode) &&
    (value.clusterMode === "CREATE_NEW"
      ? UUID.test(value.parentFolderId ?? "") &&
        value.providerClusterId === null &&
        value.manualClusterReceiptSha256 === null &&
        value.adoptedAdminPasswordSha256 === null
      : value.parentFolderId === "root" &&
        UUID.test(value.providerClusterId ?? "") &&
        HEX_64.test(value.manualClusterReceiptSha256 ?? "") &&
        HEX_64.test(value.adoptedAdminPasswordSha256 ?? "")) &&
    value.derivedPrimaryApprovalAuthorized === true &&
    value.separateClusterTeardownApprovalRequired === true &&
    value.sqlBootstrapPort === "26257" &&
    value.sqlBootstrapUsername === BOOTSTRAP_USERNAME &&
    value.partialFailureDisposition ===
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_SEPARATELY_TEARDOWN" &&
    canonicalJson(validateFreshClusterBillingAuthorization(
      value.billingAuthorization
    )) === canonicalJson(value.billingAuthorization), code);
  const approvedAt = Date.parse(value.approvedAt);
  const expiresAt = Date.parse(value.expiresAt);
  requireCondition(Number.isFinite(approvedAt) && Number.isFinite(expiresAt) &&
    value.approvedAt ===
      value.billingAuthorization.authorizedAt && value.expiresAt ===
      value.billingAuthorization.approvalExpiresAt && approvedAt < expiresAt,
  code);
  return Object.freeze({
    approval: Object.freeze({ ...value }),
    approvedAt,
    expiresAt
  });
}

export function validateFreshClusterApproval(value, binding, now = Date.now()) {
  const accepted = validateFreshClusterApprovalContract(value, binding);
  requireCondition(Number.isFinite(now) && accepted.approvedAt <= now &&
    now < accepted.expiresAt,
  "FRESH_CLUSTER_APPROVAL_REJECTED");
  return accepted.approval;
}

export function validateFreshClusterCleanupApproval(
  value,
  binding,
  now = Date.now()
) {
  const accepted = validateFreshClusterApprovalContract(value, binding);
  requireCondition(Number.isFinite(now) && accepted.approvedAt <= now &&
    now < Date.parse(accepted.approval.billingAuthorization.retentionDeadline),
    "FRESH_CLUSTER_CLEANUP_APPROVAL_REJECTED");
  return accepted.approval;
}

export function deriveFreshPrimaryApproval({
  clusterApproval,
  clusterHostSha256,
  credentialSealReceiptSha256,
  sqlClusterId
}) {
  const code = "FRESH_CLUSTER_DERIVED_PRIMARY_APPROVAL_REJECTED";
  requireCondition(clusterApproval?.derivedPrimaryApprovalAuthorized === true &&
    HEX_64.test(clusterHostSha256 ?? "") &&
    HEX_64.test(credentialSealReceiptSha256 ?? "") &&
    COCKROACH_SQL_CLUSTER_ID.test(sqlClusterId ?? ""), code);
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-primary-approval.v1",
    status: "APPROVED",
    action: "CREATE_ONE_FRESH_PRIMARY",
    approvalId: clusterApproval.approvalId,
    approvedAt: clusterApproval.approvedAt,
    approvedBy: clusterApproval.approvedBy,
    clusterHostSha256,
    credentialDisposition:
      "REQUIRE_PROVIDER_SEAL_THEN_UNLINK_LOCAL_COPY_BEFORE_MUTATION",
    credentialSealReceiptSha256,
    database: "tideproof",
    expectedClusterId: sqlClusterId,
    expiresAt: clusterApproval.expiresAt,
    maximumProjectedTotalUsd: 1.5,
    oneShot: true,
    operationId: clusterApproval.operationId,
    partialFailureDisposition:
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD",
    sourceCommit: clusterApproval.sourceCommit,
    treeDigest: clusterApproval.treeDigest
  });
}

export function validateFreshClusterReadback(
  value,
  command,
  { dispatchedAt, observedAt }
) {
  const code = "FRESH_CLUSTER_READBACK_REJECTED";
  const createdAt = Date.parse(value?.created_at);
  const dispatched = Date.parse(dispatchedAt);
  const observed = Date.parse(observedAt);
  const expected = command.createRequest;
  const createMode = command.clusterMode === "CREATE_NEW";
  requireCondition(UUID.test(value?.id ?? "") &&
    (createMode || value.id === command.providerClusterId) &&
    value.name === expected.name && value.cloud_provider === "AWS" &&
    value.plan === "BASIC" && value.parent_id === command.parentFolderId &&
    (!createMode || value.creator_id === command.creatorServiceAccountId) &&
    value.delete_protection === DELETE_PROTECTION &&
    value.state === "CREATED" && value.operation_status === "UNSPECIFIED" &&
    /^v?26\.2(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$/u
      .test(value.cockroach_version ?? "") &&
    (!createMode || canonicalJson(value.labels) ===
      canonicalJson(expected.spec.labels)) &&
    Array.isArray(value.regions) && value.regions.length === 1 &&
    value.regions[0]?.name === REGION &&
    exactKeys(value.config, ["serverless"]) &&
    exactKeys(value.config.serverless,
      ["routing_id", "upgrade_type", "usage_limits"]) &&
    typeof value.config.serverless.routing_id === "string" &&
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u
      .test(value.config.serverless.routing_id) &&
    value.config.serverless.upgrade_type === UPGRADE_TYPE &&
    exactKeys(value.config.serverless.usage_limits,
      ["request_unit_limit", "storage_mib_limit"]) &&
    value.config.serverless.usage_limits.request_unit_limit ===
      REQUEST_UNIT_LIMIT &&
    value.config.serverless.usage_limits.storage_mib_limit ===
      STORAGE_MIB_LIMIT &&
    value.regions[0]?.node_count === 0 &&
    value.regions[0]?.sql_dns === value.sql_dns &&
    Number.isFinite(createdAt) && Number.isFinite(dispatched) &&
    Number.isFinite(observed) &&
    (createMode ? dispatched <= createdAt : createdAt <= dispatched) &&
    createdAt <= observed && observed - dispatched <= 30 * 60 * 1000 &&
    typeof value.sql_dns === "string" &&
    /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.cockroachlabs\.cloud$/u
      .test(value.sql_dns), code);
  return Object.freeze({
    clusterId: value.id,
    clusterIdSha256: textDigest(value.id),
    createdAt: new Date(createdAt).toISOString(),
    creatorServiceAccountIdSha256: textDigest(value.creator_id),
    inventorySha256: digest(value),
    paidWorstCaseMonthlyUsd: 1.5,
    billingAuthorizationSha256: command.billingAuthorizationSha256,
    cockroachVersion: value.cockroach_version,
    deleteProtection: value.delete_protection,
    mode: command.clusterMode,
    manualClusterReceiptSha256: command.manualClusterReceiptSha256,
    sqlDns: value.sql_dns,
    sqlDnsSha256: textDigest(value.sql_dns)
  });
}

export function validateFreshClusterCreateAcknowledgement(value, command) {
  const code = "FRESH_CLUSTER_CREATE_ACKNOWLEDGEMENT_REJECTED";
  requireCondition(command.clusterMode === "CREATE_NEW" &&
    UUID.test(value?.id ?? "") &&
    value.name === CLUSTER_NAME && value.parent_id === command.parentFolderId &&
    value.creator_id === command.creatorServiceAccountId &&
    value.cloud_provider === "AWS" && value.plan === "BASIC" &&
    value.delete_protection === DELETE_PROTECTION &&
    canonicalJson(value.labels) === canonicalJson(command.createRequest.spec.labels),
  code);
  return Object.freeze({
    clusterId: value.id,
    clusterIdSha256: textDigest(value.id),
    acknowledgementSha256: digest(value)
  });
}

function validateCompleteSnapshot(value, collectionName, code) {
  requireCondition(exactKeys(value, [
    collectionName, "asOfTime", "complete", "pageCount"
  ]) && Array.isArray(value[collectionName]) && value.complete === true &&
    Number.isSafeInteger(value.pageCount) && value.pageCount >= 1 &&
    value.pageCount <= MAX_LIST_PAGES &&
    Number.isFinite(Date.parse(value.asOfTime)) &&
    value.asOfTime === new Date(Date.parse(value.asOfTime)).toISOString(), code);
  return value[collectionName];
}

export function reconcileFreshClusterInventory(value, command, times) {
  const code = "FRESH_CLUSTER_INVENTORY_RECONCILIATION_REJECTED";
  const clusters = validateCompleteSnapshot(value, "clusters", code);
  const physicalCollisions = clusters.filter((item) =>
    item?.name === CLUSTER_NAME && item?.parent_id === command.parentFolderId);
  requireCondition(physicalCollisions.length === 1, code);
  const accepted = validateFreshClusterReadback(
    physicalCollisions[0], command, times
  );
  return Object.freeze({
    ...accepted,
    inventoryPageCount: value.pageCount,
    inventorySnapshotSha256: digest(clusters)
  });
}

export function reconcileFreshClusterCreateIdentity(value, command) {
  const code = "FRESH_CLUSTER_CREATE_IDENTITY_RECONCILIATION_REJECTED";
  const clusters = validateCompleteSnapshot(value, "clusters", code);
  const physicalCollisions = clusters.filter((item) =>
    item?.name === CLUSTER_NAME && item?.parent_id === command.parentFolderId);
  requireCondition(physicalCollisions.length === 1, code);
  const accepted = validateFreshClusterCreateAcknowledgement(
    physicalCollisions[0], command
  );
  return Object.freeze({
    ...accepted,
    inventoryPageCount: value.pageCount,
    inventorySnapshotSha256: digest(clusters)
  });
}

export function validateSqlUserInventory(value) {
  const code = "FRESH_CLUSTER_SQL_USER_INVENTORY_REJECTED";
  const users = validateCompleteSnapshot(value, "users", code);
  requireCondition(users.every((item) => exactKeys(item, ["name"]) &&
    typeof item.name === "string" &&
    /^[a-z][a-z0-9_-]{0,62}$/u.test(item.name)), code);
  const names = users.map((item) => item.name).sort();
  requireCondition(new Set(names).size === names.length, code);
  return Object.freeze({
    names: Object.freeze(names),
    pageCount: value.pageCount,
    snapshotSha256: digest(names)
  });
}

function ipv4Number(value) {
  const parts = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/u
    .exec(value ?? "");
  if (!parts || parts.slice(1).some((part) => Number(part) > 255)) return null;
  return parts.slice(1).reduce((result, part) =>
    result * 256 + Number(part), 0);
}

function publicIpv4(value) {
  const number = ipv4Number(value);
  if (number === null) return false;
  const first = Math.floor(number / 0x1000000);
  const second = Math.floor(number / 0x10000) % 256;
  return !(
    first === 0 || first === 10 || first === 127 || first >= 224 ||
    first === 169 && second === 254 ||
    first === 172 && second >= 16 && second <= 31 ||
    first === 192 && second === 168 ||
    first === 100 && second >= 64 && second <= 127 ||
    first === 198 && [18, 19].includes(second)
  );
}

export function temporarySqlAllowlistEntry({ operationId, ipv4 }) {
  const code = "FRESH_CLUSTER_TEMPORARY_INGRESS_REJECTED";
  requireCondition(UUID.test(operationId ?? "") && publicIpv4(ipv4), code);
  return Object.freeze({
    cidr_ip: ipv4,
    cidr_mask: 32,
    name: `prooftoact-${operationId}`,
    sql: true,
    ui: false
  });
}

export function validateTemporaryAllowlistReadback(
  value,
  expected,
  { present }
) {
  const code = "FRESH_CLUSTER_TEMPORARY_INGRESS_READBACK_REJECTED";
  requireCondition(exactKeys(value, [
    "allowlist", "asOfTime", "complete", "pageCount", "propagating"
  ]) && Array.isArray(value.allowlist) && value.propagating === false &&
    value.complete === true && Number.isSafeInteger(value.pageCount) &&
    value.pageCount >= 1 && value.pageCount <= MAX_LIST_PAGES &&
    Number.isFinite(Date.parse(value.asOfTime)) &&
    value.asOfTime === new Date(Date.parse(value.asOfTime)).toISOString() &&
    typeof present === "boolean" && exactKeys(expected, [
      "cidr_ip", "cidr_mask", "name", "sql", "ui"
    ]), code);
  requireCondition(value.allowlist.length === (present ? 1 : 0) &&
    (!present || canonicalJson(value.allowlist[0]) ===
      canonicalJson(expected)), code);
  return Object.freeze({
    allowlistSha256: digest(value.allowlist),
    expectedEntryPresent: present,
    propagationComplete: true
  });
}

export function discoverTemporaryAllowlistEntry(value, operationId) {
  const code = "FRESH_CLUSTER_TEMPORARY_INGRESS_DISCOVERY_REJECTED";
  requireCondition(UUID.test(operationId ?? "") && exactKeys(value, [
    "allowlist", "asOfTime", "complete", "pageCount", "propagating"
  ]) && Array.isArray(value.allowlist) && value.allowlist.length <= 1 &&
    value.propagating === false && value.complete === true &&
    Number.isSafeInteger(value.pageCount) && value.pageCount >= 1 &&
    value.pageCount <= MAX_LIST_PAGES &&
    Number.isFinite(Date.parse(value.asOfTime)) &&
    value.asOfTime === new Date(Date.parse(value.asOfTime)).toISOString(),
  code);
  const entry = value.allowlist[0] ?? null;
  if (entry !== null) {
    requireCondition(canonicalJson(entry) === canonicalJson(
      temporarySqlAllowlistEntry({
        ipv4: entry?.cidr_ip,
        operationId
      })
    ), code);
  }
  return Object.freeze({
    allowlistSha256: digest(value.allowlist),
    entry: entry === null ? null : Object.freeze({ ...entry }),
    propagationComplete: true
  });
}

async function boundedResponse(response, expectedStatuses, expectedUrl) {
  const code = "FRESH_CLUSTER_CLOUD_RESPONSE_REJECTED";
  requireCondition(response && expectedStatuses.includes(response.status) &&
    response.redirected === false && response.url === expectedUrl, code);
  const contentType = response.headers?.get("content-type") ?? "";
  const contentLength = response.headers?.get("content-length");
  requireCondition(/^application\/json(?:\s*;|$)/iu.test(contentType) &&
    (contentLength === null || /^(?:0|[1-9][0-9]*)$/u.test(contentLength) &&
      Number(contentLength) <= MAX_RESPONSE_BYTES), code);
  const reader = response.body?.getReader();
  requireCondition(reader && typeof reader.read === "function", code);
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    requireCondition(value instanceof Uint8Array, code);
    length += value.length;
    requireCondition(length > 0 && length <= MAX_RESPONSE_BYTES, code);
    chunks.push(Buffer.from(value));
  }
  const bytes = Buffer.concat(chunks, length);
  requireCondition(bytes.length > 0, code);
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(plainObject(parsed), code);
  return parsed;
}

function authorization(token) {
  requireCondition(TOKEN.test(token ?? "") &&
    !/[\u0000-\u0020\u007f]/u.test(token),
  "FRESH_CLUSTER_CLOUD_TOKEN_REJECTED");
  return `Bearer ${token}`;
}

function paginationQuery({ asOfTime, page, sortBy }) {
  const code = "FRESH_CLUSTER_CLOUD_PAGINATION_REJECTED";
  const parsed = Date.parse(asOfTime);
  requireCondition(Number.isFinite(parsed) &&
    asOfTime === new Date(parsed).toISOString() &&
    (page === undefined || PAGE_TOKEN.test(page)) &&
    (sortBy === undefined || ["CREATED_AT", "NAME"].includes(sortBy)), code);
  const query = new URLSearchParams();
  query.set("pagination.limit", String(LIST_LIMIT));
  query.set("pagination.as_of_time", asOfTime);
  query.set("pagination.sort_order", "ASC");
  if (sortBy !== undefined) query.set("pagination.sort_by", sortBy);
  if (page !== undefined) query.set("pagination.page", page);
  return query.toString();
}

function nextPageToken(value, code) {
  requireCondition(plainObject(value) &&
    (value.pagination === undefined || value.pagination === null ||
      plainObject(value.pagination)), code);
  if (value.pagination === undefined || value.pagination === null) return null;
  requireCondition(Object.keys(value.pagination).every((key) =>
    ["next_page", "previous_page"].includes(key)) &&
    (value.pagination.previous_page === undefined ||
      PAGE_TOKEN.test(value.pagination.previous_page)), code);
  const next = value.pagination.next_page;
  requireCondition(next === undefined || PAGE_TOKEN.test(next), code);
  return next ?? null;
}

async function collectCompletePages({
  asOfTime,
  collectionName,
  fetchPage,
  responseKeys,
  code
}) {
  const collected = [];
  const seenPages = new Set();
  let page;
  let pageCount = 0;
  while (true) {
    requireCondition(pageCount < MAX_LIST_PAGES, code);
    const value = await fetchPage(page);
    requireCondition(exactKeys(value, value.pagination === undefined
      ? responseKeys
      : [...responseKeys, "pagination"]) &&
      Array.isArray(value[collectionName]), code);
    collected.push(...value[collectionName]);
    pageCount += 1;
    const next = nextPageToken(value, code);
    if (next === null) break;
    requireCondition(!seenPages.has(next), code);
    seenPages.add(next);
    page = next;
  }
  return Object.freeze({
    [collectionName]: Object.freeze(collected),
    asOfTime,
    complete: true,
    pageCount
  });
}

export function createFreshClusterCloudRuntime({
  fetchImpl = globalThis.fetch,
  timeoutMs = 10_000
} = {}) {
  requireCondition(typeof fetchImpl === "function" &&
    timeoutMs === 10_000, "FRESH_CLUSTER_CLOUD_RUNTIME_REJECTED");

  async function request({ body, method, path, query, token }) {
    requireCondition(typeof path === "string" && path.startsWith("/api/v1/") &&
      !path.includes("//") && ["DELETE", "GET", "POST"].includes(method) &&
      (query === undefined || typeof query === "string" &&
        query.length > 0 && query.length <= 8192),
    "FRESH_CLUSTER_CLOUD_REQUEST_REJECTED");
    const url = `${API_ORIGIN}${path}${query === undefined ? "" : `?${query}`}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetchImpl(url, {
        body: body === undefined ? undefined : canonicalJson(body),
        cache: "no-store",
        headers: {
          Accept: "application/json",
          Authorization: authorization(token),
          "Cc-Version": API_VERSION,
          ...(body === undefined ? {} : { "Content-Type": "application/json" })
        },
        method,
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: controller.signal
      });
    } catch (cause) {
      reject("FRESH_CLUSTER_CLOUD_REQUEST_FAILED_NO_RETRY", cause);
    } finally {
      clearTimeout(timer);
    }
    return boundedResponse(response, [200], url);
  }

  return Object.freeze({
    createCluster({ createRequest, token }) {
      return request({ body: createRequest, method: "POST",
        path: "/api/v1/clusters", token });
    },
    getCluster({ clusterId, token }) {
      return request({ method: "GET",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}`, token });
    },
    listClustersPage({ asOfTime, page, token }) {
      return request({ method: "GET", path: "/api/v1/clusters",
        query: paginationQuery({ asOfTime, page, sortBy: "CREATED_AT" }),
        token });
    },
    listCompleteClusters({ asOfTime, token }) {
      return collectCompletePages({
        asOfTime,
        code: "FRESH_CLUSTER_INVENTORY_PAGINATION_REJECTED",
        collectionName: "clusters",
        fetchPage: (page) => this.listClustersPage({ asOfTime, page, token }),
        responseKeys: ["clusters"]
      });
    },
    createSqlAdmin({ clusterId, password, token, username }) {
      requireCondition(username === BOOTSTRAP_USERNAME &&
        typeof password === "string" && password.length >= 20 &&
        password.length <= 256 && !/[\u0000\r\n]/u.test(password),
      "FRESH_CLUSTER_SQL_ADMIN_REJECTED");
      return request({ body: { name: username, password }, method: "POST",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}/sql-users`, token });
    },
    deleteSqlAdmin({ clusterId, token, username }) {
      requireCondition(username === BOOTSTRAP_USERNAME,
        "FRESH_CLUSTER_SQL_ADMIN_REJECTED");
      return request({ method: "DELETE",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}/sql-users/${username}`, token });
    },
    listSqlUsersPage({ asOfTime, clusterId, page, token }) {
      return request({ method: "GET",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}/sql-users`,
        query: paginationQuery({ asOfTime, page }), token });
    },
    listCompleteSqlUsers({ asOfTime, clusterId, token }) {
      return collectCompletePages({
        asOfTime,
        code: "FRESH_CLUSTER_SQL_USER_PAGINATION_REJECTED",
        collectionName: "users",
        fetchPage: (page) => this.listSqlUsersPage({
          asOfTime, clusterId, page, token
        }),
        responseKeys: ["users"]
      });
    },
    addTemporaryIngress({ clusterId, entry, token }) {
      return request({ body: entry, method: "POST",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}/networking/allowlist`, token });
    },
    deleteTemporaryIngress({ clusterId, entry, token }) {
      const ipv4 = encodePath(entry?.cidr_ip,
        /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/u,
        "FRESH_CLUSTER_TEMPORARY_INGRESS_REJECTED");
      requireCondition(entry?.cidr_mask === 32,
        "FRESH_CLUSTER_TEMPORARY_INGRESS_REJECTED");
      return request({ method: "DELETE",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}/networking/allowlist/${ipv4}/32`, token });
    },
    listAllowlistPage({ asOfTime, clusterId, page, token }) {
      return request({ method: "GET",
        path: `/api/v1/clusters/${encodePath(clusterId, UUID,
          "FRESH_CLUSTER_ID_REJECTED")}/networking/allowlist`,
        query: paginationQuery({ asOfTime, page }), token });
    },
    async listCompleteAllowlist({ asOfTime, clusterId, token }) {
      let propagating;
      const value = await collectCompletePages({
        asOfTime,
        code: "FRESH_CLUSTER_ALLOWLIST_PAGINATION_REJECTED",
        collectionName: "allowlist",
        fetchPage: async (page) => {
          const response = await this.listAllowlistPage({
            asOfTime, clusterId, page, token
          });
          requireCondition(typeof response?.propagating === "boolean" &&
            (propagating === undefined ||
              propagating === response.propagating),
          "FRESH_CLUSTER_ALLOWLIST_PAGINATION_REJECTED");
          propagating = response.propagating;
          return response;
        },
        responseKeys: ["allowlist", "propagating"]
      });
      return Object.freeze({ ...value, propagating });
    }
  });
}

async function readPublicIp(fetchImpl, url, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetchImpl(url, {
      cache: "no-store",
      method: "GET",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: controller.signal
    });
  } catch (cause) {
    reject("FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_FAILED", cause);
  } finally {
    clearTimeout(timer);
  }
  requireCondition(response?.status === 200 && response.redirected === false &&
    response.url === url, "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_REJECTED");
  const reader = response.body?.getReader();
  requireCondition(reader && typeof reader.read === "function",
    "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_REJECTED");
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    requireCondition(value instanceof Uint8Array,
      "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_REJECTED");
    length += value.length;
    requireCondition(length > 0 && length <= 64,
      "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_REJECTED");
    chunks.push(Buffer.from(value));
  }
  const text = Buffer.concat(chunks, length).toString("utf8").trim();
  requireCondition(text.length <= 15 && publicIpv4(text),
    "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_REJECTED");
  return text;
}

export async function observeRunnerPublicIpv4(
  fetchImpl = globalThis.fetch
) {
  requireCondition(typeof fetchImpl === "function",
    "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_REJECTED");
  const [aws, ipify] = await Promise.all([
    readPublicIp(fetchImpl, "https://checkip.amazonaws.com/"),
    readPublicIp(fetchImpl, "https://api.ipify.org/")
  ]);
  requireCondition(aws === ipify,
    "FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_MISMATCH");
  return Object.freeze({
    ipv4: aws,
    ipv4Sha256: textDigest(aws),
    sourceCount: 2,
    sourcesSha256: digest([
      "https://api.ipify.org/",
      "https://checkip.amazonaws.com/"
    ])
  });
}

export const __test = Object.freeze({
  API_VERSION,
  BOOTSTRAP_USERNAME,
  CLUSTER_NAME,
  DELETE_PROTECTION,
  LIST_LIMIT,
  MAX_LIST_PAGES,
  REGION,
  REQUEST_UNIT_LIMIT,
  STORAGE_MIB_LIMIT,
  UPGRADE_TYPE,
  canonicalJson,
  digest,
  publicIpv4,
  textDigest,
  validParentFolderId
});
