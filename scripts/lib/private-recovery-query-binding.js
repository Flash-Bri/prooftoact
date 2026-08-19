import crypto from "node:crypto";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COCKROACH_SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const BINDING_SCHEMA = "prooftoact.private-recovery-query-binding.v1";
const MAPPING_SCHEMA = "prooftoact.primary-provider-sql-mapping.v1";

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

function digest(value) {
  return crypto.createHash("sha256").update(
    Buffer.from(`${canonicalJson(value)}\n`, "utf8")
  ).digest("hex");
}

function canonicalTimestamp(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(Number.isFinite(milliseconds) &&
    value === new Date(milliseconds).toISOString(), code);
  return milliseconds;
}

function validatePublicKey(value, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= 1024, code);
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length > 0 && bytes.toString("base64") === value,
    code);
  try {
    const key = crypto.createPublicKey({ key: bytes, format: "der", type: "spki" });
    requireCondition(key.asymmetricKeyType === "ec" &&
      ["prime256v1", "P-256"].includes(key.asymmetricKeyDetails?.namedCurve) &&
      key.export({ format: "der", type: "spki" }).toString("base64") === value,
    code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return value;
}

export function validatePrimaryClusterMapping(value) {
  const code = "PRIVATE_RECOVERY_QUERY_BINDING_CLUSTER_MAPPING_REJECTED";
  requireCondition(exactKeys(value, [
    "cloud",
    "clusterInventorySha256",
    "cockroachVersion",
    "host",
    "manualClusterReceiptSha256",
    "observedAt",
    "providerClusterId",
    "receiptSha256",
    "schemaVersion",
    "sourceBindingSha256",
    "sourceCommit",
    "sqlClusterId",
    "status",
    "treeDigest"
  ]) && value.schemaVersion === MAPPING_SCHEMA &&
    value.status === "PROVIDER_READBACK_BOUND" &&
    value.cloud === "COCKROACHDB_CLOUD_ON_AWS" &&
    UUID.test(value.providerClusterId ?? "") &&
    COCKROACH_SQL_CLUSTER_ID.test(value.sqlClusterId ?? "") &&
    value.providerClusterId !== value.sqlClusterId &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    [value.clusterInventorySha256, value.sourceBindingSha256,
      value.receiptSha256]
      .every((item) => HEX_64.test(item ?? "")) &&
    (value.manualClusterReceiptSha256 === null ||
      HEX_64.test(value.manualClusterReceiptSha256 ?? "")) &&
    /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.cockroachlabs\.cloud$/u
      .test(value.host ?? "") &&
    typeof value.cockroachVersion === "string" &&
    value.cockroachVersion.length >= 3 &&
    value.cockroachVersion.length <= 256 &&
    !/[\u0000\r\n]/u.test(value.cockroachVersion), code);
  canonicalTimestamp(value.observedAt, code);
  const { receiptSha256, ...body } = value;
  requireCondition(receiptSha256 === digest(body) &&
    value.sourceBindingSha256 === digest({
      sourceCommit: value.sourceCommit,
      treeDigest: value.treeDigest
    }), code);
  return Object.freeze({ ...value });
}

export function validatePrivateRecoveryQueryBinding(value) {
  const code = "PRIVATE_RECOVERY_QUERY_BINDING_REJECTED";
  requireCondition(exactKeys(value, [
    "billingAuthorizationSha256",
    "bindingSha256",
    "expectedBundleDigest",
    "expectedSourceClusterId",
    "expectedSourceSqlClusterId",
    "expiresAt",
    "operationId",
    "primaryClusterMapping",
    "primaryClusterMappingReceiptSha256",
    "publisherKeyId",
    "publisherPublicKeySpkiBase64",
    "recoveryClusterId",
    "recoverySessionId",
    "schemaVersion",
    "sourceCommit",
    "sourceCommitTs",
    "sourceDigest",
    "status",
    "subjectBindingHash",
    "tenantId",
    "treeDigest"
  ]) && value.schemaVersion === BINDING_SCHEMA &&
    value.status === "SANITIZED_PROVIDER_BOUND" &&
    [value.operationId, value.expectedSourceClusterId,
      value.recoveryClusterId, value.recoverySessionId, value.tenantId]
      .every((item) => UUID.test(item ?? "")) &&
    COCKROACH_SQL_CLUSTER_ID.test(value.expectedSourceSqlClusterId ?? "") &&
    value.expectedSourceClusterId !== value.expectedSourceSqlClusterId &&
    value.expectedSourceClusterId !== value.recoveryClusterId &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    [value.billingAuthorizationSha256, value.bindingSha256,
      value.expectedBundleDigest, value.primaryClusterMappingReceiptSha256,
      value.sourceDigest, value.subjectBindingHash]
      .every((item) => HEX_64.test(item ?? "")) &&
    /^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(value.publisherKeyId ?? ""), code);
  const sourceCommitTs = canonicalTimestamp(value.sourceCommitTs, code);
  const expiresAt = canonicalTimestamp(value.expiresAt, code);
  requireCondition(expiresAt > sourceCommitTs &&
    expiresAt - sourceCommitTs <= 24 * 60 * 60 * 1_000, code);
  validatePublicKey(value.publisherPublicKeySpkiBase64, code);
  const mapping = validatePrimaryClusterMapping(value.primaryClusterMapping);
  requireCondition(mapping.receiptSha256 ===
      value.primaryClusterMappingReceiptSha256 &&
    mapping.providerClusterId === value.expectedSourceClusterId &&
    mapping.sqlClusterId === value.expectedSourceSqlClusterId &&
    mapping.sourceCommit === value.sourceCommit &&
    mapping.treeDigest === value.treeDigest, code);
  const { bindingSha256, ...body } = value;
  requireCondition(bindingSha256 === digest(body), code);
  return Object.freeze({ ...value, primaryClusterMapping: mapping });
}

export function buildPrivateRecoveryQueryBinding(value) {
  const body = Object.freeze({
    schemaVersion: BINDING_SCHEMA,
    status: "SANITIZED_PROVIDER_BOUND",
    ...value
  });
  return validatePrivateRecoveryQueryBinding(Object.freeze({
    ...body,
    bindingSha256: digest(body)
  }));
}

export const __test = Object.freeze({ canonicalJson, digest });
