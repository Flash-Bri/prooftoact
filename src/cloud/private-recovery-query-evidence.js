import {
  createPrivateKey,
  createPublicKey,
  createHash,
  sign,
  verify
} from "node:crypto";

import { canonicalJson } from "./canonical-json.js";

const EXPECTATION_SCHEMA =
  "prooftoact.private-recovery-query-evidence-expectation.v1";
const SNAPSHOT_SCHEMA =
  "prooftoact.private-recovery-query-deployment-snapshot.v1";
const RECEIPT_SCHEMA =
  "prooftoact.private-recovery-query-signed-evidence.v1";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const BASE64_SHA256 = /^[A-Za-z0-9+/]{43}=$/u;
const FUNCTION_ARN =
  /^arn:aws:lambda:us-east-1:[0-9]{12}:function:prooftoact-private-recovery-query$/u;
const ROLE_ARN =
  /^arn:aws:iam::[0-9]{12}:role\/ProofToActPrivateRecoveryQuery(?:CloudFormation|Runtime|Operator|Evidence|Teardown)$/u;
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;

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

function exactKeys(value, keys) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...keys].sort().join("\n");
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

function canonicalBase64(value, maximumBytes, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= maximumBytes * 2, code);
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length > 0 && bytes.length <= maximumBytes &&
    bytes.toString("base64") === value, code);
  return value;
}

function timestamp(value, code) {
  const milliseconds = Date.parse(value ?? "");
  requireCondition(typeof value === "string" && value.length <= 64 &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return value;
}

export function validatePrivateRecoveryEvidenceExpectation(value) {
  const code = "PRIVATE_RECOVERY_QUERY_EVIDENCE_EXPECTATION_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalSha256", "cloudFormationServiceRoleArn", "codeSha256Base64",
    "codeZipSha256", "configSha256", "evidenceKeyId",
    "evidencePublicKeySpkiBase64", "evidenceRoleArn",
    "expectedOperationReceiptSha256", "functionArn", "functionVersion",
    "mcpSecretArnSha256", "mcpSecretVersionIdSha256", "operationGlobalKeySha256",
    "operatorRoleArn", "permissionsBoundaryArn", "phase",
    "preEvidenceReceiptSha256", "releaseControlTableArn", "runtimeRoleArn",
    "schemaVersion", "sourceCommit", "stackName", "teardownRoleArn",
    "templateSha256", "treeDigest", "workflowCommit"
  ]) && value.schemaVersion === EXPECTATION_SCHEMA &&
    ["PRE_QUERY", "POST_QUERY"].includes(value.phase) &&
    value.stackName === "prooftoact-private-recovery-query" &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    HEX_40.test(value.workflowCommit ?? "") &&
    [
      value.approvalSha256,
      value.codeZipSha256,
      value.configSha256,
      value.mcpSecretArnSha256,
      value.mcpSecretVersionIdSha256,
      value.operationGlobalKeySha256,
      value.templateSha256
    ].every((item) => HEX_64.test(item ?? "")) &&
    BASE64_SHA256.test(value.codeSha256Base64 ?? "") &&
    FUNCTION_ARN.test(value.functionArn ?? "") &&
    /^(?:[1-9][0-9]{0,8})$/u.test(value.functionVersion ?? "") &&
    [
      value.cloudFormationServiceRoleArn,
      value.evidenceRoleArn,
      value.operatorRoleArn,
      value.runtimeRoleArn,
      value.teardownRoleArn
    ].every((item) => ROLE_ARN.test(item ?? "")) &&
    /^arn:aws:iam::[0-9]{12}:policy\/ProofToActPrivateRecoveryQueryBoundary$/u
      .test(value.permissionsBoundaryArn ?? "") &&
    TABLE_ARN.test(value.releaseControlTableArn ?? "") &&
    /^[A-Za-z0-9._:-]{1,128}$/u.test(value.evidenceKeyId ?? ""), code);
  canonicalBase64(value.evidencePublicKeySpkiBase64, 1024, code);
  if (value.phase === "PRE_QUERY") {
    requireCondition(value.expectedOperationReceiptSha256 === null &&
      value.preEvidenceReceiptSha256 === null, code);
  } else {
    requireCondition(HEX_64.test(value.expectedOperationReceiptSha256 ?? "") &&
      HEX_64.test(value.preEvidenceReceiptSha256 ?? ""), code);
  }
  return Object.freeze({ ...value });
}

export function validatePrivateRecoveryDeploymentSnapshot(value) {
  const code = "PRIVATE_RECOVERY_QUERY_EVIDENCE_SNAPSHOT_REJECTED";
  requireCondition(exactKeys(value, [
    "accountIdSha256", "callerArnSha256", "callerUserIdSha256",
    "function", "observedAt", "operation", "phase", "resourceInventorySha256",
    "rolePostureSha256", "schemaVersion", "secret", "stackIdSha256",
    "stackParametersSha256", "stackStatus", "templateSha256",
    "terminationProtection", "workflowCommit"
  ]) && value.schemaVersion === SNAPSHOT_SCHEMA &&
    ["PRE_QUERY", "POST_QUERY"].includes(value.phase) &&
    value.stackStatus === "CREATE_COMPLETE" &&
    value.terminationProtection === true &&
    [
      value.accountIdSha256, value.callerArnSha256, value.callerUserIdSha256,
      value.resourceInventorySha256, value.rolePostureSha256,
      value.stackIdSha256, value.stackParametersSha256, value.templateSha256
    ].every((item) => HEX_64.test(item ?? "")) &&
    HEX_40.test(value.workflowCommit ?? ""), code);
  timestamp(value.observedAt, code);
  requireCondition(exactKeys(value.function, [
    "architectures", "codeSha256Base64", "configurationSha256",
    "eventSourceCount", "functionArnSha256", "functionPolicySha256",
    "functionUrlCount", "memorySize", "reservedConcurrency", "runtime",
    "tagsSha256", "timeout", "version", "vpcAttached"
  ]) && value.function.runtime === "nodejs22.x" &&
    typeof value.function.version === "string" &&
    /^(?:[1-9][0-9]{0,8})$/u.test(value.function.version) &&
    BASE64_SHA256.test(value.function.codeSha256Base64 ?? "") &&
    value.function.memorySize === 256 && value.function.timeout === 120 &&
    value.function.reservedConcurrency === 1 &&
    value.function.eventSourceCount === 0 && value.function.functionUrlCount === 0 &&
    value.function.vpcAttached === false &&
    canonicalJson(value.function.architectures) === canonicalJson(["arm64"]) &&
    [
      value.function.configurationSha256,
      value.function.functionArnSha256,
      value.function.functionPolicySha256,
      value.function.tagsSha256
    ].every((item) => HEX_64.test(item ?? "")), code);
  requireCondition(exactKeys(value.secret, [
    "arnSha256", "currentVersion", "rotationEnabled", "versionIdSha256"
  ]) && value.secret.currentVersion === true &&
    value.secret.rotationEnabled === false &&
    HEX_64.test(value.secret.arnSha256 ?? "") &&
    HEX_64.test(value.secret.versionIdSha256 ?? ""), code);
  requireCondition(exactKeys(value.operation, [
    "receiptSha256", "state"
  ]) && ["ABSENT", "FINAL"].includes(value.operation.state) &&
    ((value.operation.state === "ABSENT" && value.operation.receiptSha256 === null) ||
      (value.operation.state === "FINAL" &&
        HEX_64.test(value.operation.receiptSha256 ?? ""))), code);
  return Object.freeze(structuredClone(value));
}

export function signPrivateRecoveryDeploymentEvidence({
  expectation: rawExpectation,
  privateKeyPem,
  snapshot: rawSnapshot
}) {
  const code = "PRIVATE_RECOVERY_QUERY_EVIDENCE_SIGNATURE_REJECTED";
  const expectation = validatePrivateRecoveryEvidenceExpectation(rawExpectation);
  const snapshot = validatePrivateRecoveryDeploymentSnapshot(rawSnapshot);
  requireCondition(snapshot.phase === expectation.phase &&
    snapshot.templateSha256 === expectation.templateSha256 &&
    snapshot.function.codeSha256Base64 === expectation.codeSha256Base64 &&
    snapshot.function.version === expectation.functionVersion &&
    snapshot.workflowCommit === expectation.workflowCommit &&
    snapshot.secret.arnSha256 === expectation.mcpSecretArnSha256 &&
    snapshot.secret.versionIdSha256 === expectation.mcpSecretVersionIdSha256 &&
    snapshot.operation.receiptSha256 ===
      expectation.expectedOperationReceiptSha256, code);
  let privateKey;
  try {
    privateKey = createPrivateKey(privateKeyPem);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(privateKey.asymmetricKeyType === "ed25519", code);
  const publicSpki = createPublicKey(privateKey).export({
    format: "der",
    type: "spki"
  }).toString("base64");
  requireCondition(publicSpki === expectation.evidencePublicKeySpkiBase64, code);
  const unsigned = Object.freeze({
    schemaVersion: RECEIPT_SCHEMA,
    status: "PASS",
    evidenceKeyId: expectation.evidenceKeyId,
    evidencePublicKeySha256: sha256(Buffer.from(publicSpki, "base64")),
    phase: expectation.phase,
    preEvidenceReceiptSha256: expectation.preEvidenceReceiptSha256,
    snapshot,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  const signature = sign(null, Buffer.from(canonicalJson(unsigned), "utf8"),
    privateKey);
  const body = Object.freeze({
    ...unsigned,
    signatureAlgorithm: "Ed25519",
    signatureBase64: signature.toString("base64")
  });
  return validateSignedPrivateRecoveryDeploymentEvidence({
    publicKeySpkiBase64: publicSpki,
    receipt: Object.freeze({ ...body, receiptSha256: lineDigest(body) })
  });
}

export function validateSignedPrivateRecoveryDeploymentEvidence({
  publicKeySpkiBase64,
  receipt
}) {
  const code = "PRIVATE_RECOVERY_QUERY_EVIDENCE_RECEIPT_REJECTED";
  canonicalBase64(publicKeySpkiBase64, 1024, code);
  requireCondition(exactKeys(receipt, [
    "evidenceKeyId", "evidencePublicKeySha256", "phase",
    "preEvidenceReceiptSha256", "receiptSha256", "schemaVersion",
    "signatureAlgorithm", "signatureBase64", "snapshot", "sourceCommit",
    "status", "treeDigest"
  ]) && receipt.schemaVersion === RECEIPT_SCHEMA && receipt.status === "PASS" &&
    receipt.signatureAlgorithm === "Ed25519" &&
    /^[A-Za-z0-9._:-]{1,128}$/u.test(receipt.evidenceKeyId ?? "") &&
    HEX_64.test(receipt.evidencePublicKeySha256 ?? "") &&
    HEX_64.test(receipt.receiptSha256 ?? "") &&
    HEX_40.test(receipt.sourceCommit ?? "") &&
    HEX_40.test(receipt.treeDigest ?? "") &&
    ["PRE_QUERY", "POST_QUERY"].includes(receipt.phase) &&
    ((receipt.phase === "PRE_QUERY" &&
      receipt.preEvidenceReceiptSha256 === null) ||
      (receipt.phase === "POST_QUERY" &&
        HEX_64.test(receipt.preEvidenceReceiptSha256 ?? ""))), code);
  const snapshot = validatePrivateRecoveryDeploymentSnapshot(receipt.snapshot);
  requireCondition(snapshot.phase === receipt.phase &&
    receipt.evidencePublicKeySha256 ===
      sha256(Buffer.from(publicKeySpkiBase64, "base64")), code);
  canonicalBase64(receipt.signatureBase64, 256, code);
  const { receiptSha256, signatureAlgorithm, signatureBase64, ...unsigned } =
    receipt;
  const body = { ...unsigned, signatureAlgorithm, signatureBase64 };
  requireCondition(receiptSha256 === lineDigest(body), code);
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(publicKeySpkiBase64, "base64"),
      format: "der",
      type: "spki"
    });
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(publicKey.asymmetricKeyType === "ed25519" &&
    verify(null, Buffer.from(canonicalJson(unsigned), "utf8"), publicKey,
      Buffer.from(signatureBase64, "base64")), code);
  return Object.freeze(structuredClone(receipt));
}

export const __test = Object.freeze({
  EXPECTATION_SCHEMA,
  RECEIPT_SCHEMA,
  SNAPSHOT_SCHEMA,
  digest,
  lineDigest,
  sha256
});
