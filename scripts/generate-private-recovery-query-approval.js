import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  privateRecoveryQueryApprovalSha256,
  validatePrivateRecoveryQueryApproval,
  validatePrivateRecoveryQueryProviderBinding
} from "../src/cloud/private-recovery-query.js";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SECRET_BINDING_SCHEMA =
  "prooftoact.private-recovery-query-mcp-secret-binding.v1";

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
  return crypto.createHash("sha256").update(value).digest("hex");
}

function lineDigest(value) {
  return sha256(`${canonicalJson(value)}\n`);
}

function requireTimestamp(value, code) {
  requireCondition(typeof value === "string" && value.length <= 64 &&
    Number.isFinite(Date.parse(value)) &&
    new Date(Date.parse(value)).toISOString() === value, code);
  return value;
}

function readCanonicalJson(filePath, maximumBytes, code) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximumBytes, code);
  const bytes = fs.readFileSync(resolved);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(bytes.toString("utf8") === `${canonicalJson(value)}\n`, code);
  return value;
}

function writeExclusive(filePath, value) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, `${canonicalJson(value)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

export function validatePrivateRecoveryQueryMcpSecretBinding(value) {
  const code = "PRIVATE_RECOVERY_QUERY_MCP_SECRET_BINDING_REJECTED";
  requireCondition(exactKeys(value, [
    "bindingSha256", "credentialSharingBoundary", "mcpSecretArnSha256",
    "mcpSecretValueSha256",
    "mcpSecretVersionIdSha256", "observedAt", "schemaVersion",
    "operatorAuthorizationSha256", "sealApprovalSha256",
    "sourceCommit", "sourceSecretArnSha256", "sourceSecretValueSha256",
    "sourceSecretVersionIdSha256", "status", "treeDigest"
  ]) && value.schemaVersion === SECRET_BINDING_SCHEMA &&
    value.status === "IMMUTABLE_AWSCURRENT_READBACK_BOUND" &&
    value.credentialSharingBoundary ===
      "SAME_READ_ONLY_MANAGED_MCP_PROVIDER_KEY_TWO_ISOLATED_AWS_SECRETS" &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    [value.bindingSha256, value.mcpSecretArnSha256,
      value.mcpSecretValueSha256, value.mcpSecretVersionIdSha256,
      value.operatorAuthorizationSha256, value.sealApprovalSha256,
      value.sourceSecretArnSha256, value.sourceSecretValueSha256,
      value.sourceSecretVersionIdSha256]
      .every((item) => HEX_64.test(item ?? "")), code);
  requireTimestamp(value.observedAt, code);
  const { bindingSha256, ...body } = value;
  requireCondition(bindingSha256 === lineDigest(body), code);
  return Object.freeze({ ...value });
}

export function generatePrivateRecoveryQueryApproval({
  approvedAt: rawApprovedAt,
  mcpSecretBinding: rawMcpSecretBinding,
  now = new Date(),
  providerBinding: rawProviderBinding
}) {
  const code = "PRIVATE_RECOVERY_QUERY_APPROVAL_GENERATION_REJECTED";
  requireCondition(now instanceof Date && Number.isFinite(now.getTime()), code);
  const approvedAt = Date.parse(requireTimestamp(rawApprovedAt, code));
  requireCondition(approvedAt >= now.getTime() - 60_000 &&
    approvedAt <= now.getTime() + 60_000, code);
  const providerBinding = validatePrivateRecoveryQueryProviderBinding(
    rawProviderBinding, now
  );
  const mcpSecretBinding = validatePrivateRecoveryQueryMcpSecretBinding(
    rawMcpSecretBinding
  );
  const expiresAt = Date.parse(providerBinding.expiresAt);
  const secretObservedAt = Date.parse(mcpSecretBinding.observedAt);
  requireCondition(approvedAt < expiresAt &&
    expiresAt - approvedAt <= 24 * 60 * 60 * 1_000 &&
    secretObservedAt <= approvedAt &&
    mcpSecretBinding.sourceCommit === providerBinding.sourceCommit &&
    mcpSecretBinding.treeDigest === providerBinding.treeDigest, code);
  const approval = validatePrivateRecoveryQueryApproval(Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-approval.v1",
    approvedAt: rawApprovedAt,
    billingAuthorizationSha256: providerBinding.billingAuthorizationSha256,
    expectedBundleDigest: providerBinding.expectedBundleDigest,
    expectedSourceClusterId: providerBinding.expectedSourceClusterId,
    expectedSourceCommitTs: providerBinding.sourceCommitTs,
    expectedSourceSqlClusterId: providerBinding.expectedSourceSqlClusterId,
    expiresAt: providerBinding.expiresAt,
    mcpSecretArnSha256: mcpSecretBinding.mcpSecretArnSha256,
    mcpSecretValueSha256: mcpSecretBinding.mcpSecretValueSha256,
    mcpSecretVersionIdSha256: mcpSecretBinding.mcpSecretVersionIdSha256,
    operationId: providerBinding.operationId,
    providerBindingSha256: providerBinding.bindingSha256,
    publisherKeyId: providerBinding.publisherKeyId,
    publisherPublicKeySpkiBase64:
      providerBinding.publisherPublicKeySpkiBase64,
    primaryClusterMapping: providerBinding.primaryClusterMapping,
    recoveryClusterId: providerBinding.recoveryClusterId,
    recoverySessionId: providerBinding.recoverySessionId,
    sourceCommit: providerBinding.sourceCommit,
    sourceClusterMappingReceiptSha256:
      providerBinding.primaryClusterMappingReceiptSha256,
    sourceDigest: providerBinding.sourceDigest,
    subjectBindingHash: providerBinding.subjectBindingHash,
    tenantId: providerBinding.tenantId,
    treeDigest: providerBinding.treeDigest
  }), now);
  const receiptBody = Object.freeze({
    schemaVersion:
      "prooftoact.private-recovery-query-approval-generation-receipt.v1",
    status: "PASS",
    approvalSha256: privateRecoveryQueryApprovalSha256(approval),
    approvedAt: approval.approvedAt,
    expiresAt: approval.expiresAt,
    mcpSecretBindingSha256: mcpSecretBinding.bindingSha256,
    providerBindingSha256: providerBinding.bindingSha256,
    sourceCommit: approval.sourceCommit,
    treeDigest: approval.treeDigest
  });
  return Object.freeze({
    approval,
    receipt: Object.freeze({
      ...receiptBody,
      receiptSha256: lineDigest(receiptBody)
    })
  });
}

function parseArguments(args) {
  const names = [
    "--approved-at", "--mcp-secret-binding-file", "--output-directory",
    "--provider-binding-file"
  ];
  requireCondition(args.length === names.length * 2,
    "PRIVATE_RECOVERY_QUERY_APPROVAL_ARGUMENT_REJECTED");
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    requireCondition(names.includes(args[index]) && parsed[args[index]] === undefined &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_APPROVAL_ARGUMENT_REJECTED");
    parsed[args[index]] = args[index + 1];
  }
  return Object.freeze(parsed);
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  const output = path.resolve(parsed["--output-directory"]);
  requireCondition(!fs.existsSync(output),
    "PRIVATE_RECOVERY_QUERY_APPROVAL_OUTPUT_REJECTED");
  const generated = generatePrivateRecoveryQueryApproval({
    approvedAt: parsed["--approved-at"],
    mcpSecretBinding: readCanonicalJson(
      parsed["--mcp-secret-binding-file"], 64 * 1024,
      "PRIVATE_RECOVERY_QUERY_MCP_SECRET_BINDING_REJECTED"
    ),
    providerBinding: readCanonicalJson(
      parsed["--provider-binding-file"], 128 * 1024,
      "PRIVATE_RECOVERY_QUERY_PROVIDER_BINDING_REJECTED"
    )
  });
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  writeExclusive(path.join(output, "private-recovery-query-approval.json"),
    generated.approval);
  writeExclusive(path.join(output,
    "private-recovery-query-approval-generation-receipt.json"),
  generated.receipt);
  process.stdout.write(
    `PRIVATE_RECOVERY_QUERY_APPROVAL_READY:${generated.receipt.approvalSha256}\n`
  );
  return generated;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch(() => {
    process.stderr.write("PRIVATE_RECOVERY_QUERY_APPROVAL_CLI_HOLD\n");
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  lineDigest,
  parseArguments,
  SECRET_BINDING_SCHEMA,
  sha256
});
