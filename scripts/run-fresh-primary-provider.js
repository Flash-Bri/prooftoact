import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  FRESH_PRIMARY_RUNTIME_USERS,
  runFreshPrimaryProviderControlledBootstrap,
  validateFreshClusterAdminConnectionString,
  validateFreshPrimaryApproval,
  validateFreshPrimaryCredentialBundle,
  validateFreshPrimaryCredentialSeal,
  verifyFreshPrimaryProviderPrerequisites
} from "./bootstrap-fresh-primary.js";
import {
  createFreshPrimaryAwsProvider,
  readFreshPrimarySecretMaterial
} from "./fresh-primary-aws-provider.js";
import { createFreshPrimaryAwsRuntime } from "./fresh-primary-aws-runtime.js";
import {
  buildFreshPrimaryProviderCommand
} from "./fresh-primary-provider-controller.js";
import {
  deriveFreshRecoveryPublisherSecret
} from "./lib/fresh-recovery-publisher-key.js";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COCKROACH_SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;

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
  requireCondition(bytes.length > 0 && bytes.length <= 1024 * 1024,
    "FRESH_PRIMARY_RUNNER_CANONICAL_RECORD_REJECTED");
  return bytes;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function parseArguments(args) {
  const accepted = new Set([
    "--admin-secret-arn",
    "--admin-secret-version-id",
    "--approval-file",
    "--build-receipt",
    "--caller-workflow-sha",
    "--cloud-api-secret-arn",
    "--cloud-api-secret-version-id",
    "--controller-table-arn",
    "--credential-secret-arn",
    "--credential-secret-version-id",
    "--expected-commit",
    "--expected-tree",
    "--operation-id",
    "--outer-authentication-receipt-sha256",
    "--outer-reservation-receipt-sha256",
    "--outer-reserved-at",
    "--outer-reservation-acknowledged-at",
    "--outer-command-sha256",
    "--provider-cluster-id",
    "--recovery-security-receipt-sha256",
    "--receipt-output",
    "--signer-secret-arn",
    "--signer-secret-version-id",
    "--sql-cluster-id"
  ]);
  requireCondition(args.length === accepted.size * 2,
    "FRESH_PRIMARY_RUNNER_ARGUMENTS_REJECTED");
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    requireCondition(accepted.has(name) && !Object.hasOwn(values, name) &&
      typeof args[index + 1] === "string" && args[index + 1] !== "",
    "FRESH_PRIMARY_RUNNER_ARGUMENTS_REJECTED");
    values[name] = args[index + 1];
  }
  requireCondition(HEX_40.test(values["--caller-workflow-sha"]) &&
    HEX_40.test(values["--expected-commit"]) &&
    HEX_40.test(values["--expected-tree"]) &&
    UUID.test(values["--operation-id"]) &&
    HEX_64.test(values["--outer-authentication-receipt-sha256"]) &&
    HEX_64.test(values["--outer-reservation-receipt-sha256"]) &&
    HEX_64.test(values["--outer-command-sha256"]) &&
    Number.isFinite(Date.parse(values["--outer-reserved-at"] ?? "")) &&
    values["--outer-reserved-at"] === new Date(Date.parse(
      values["--outer-reserved-at"]
    )).toISOString() &&
    Number.isFinite(Date.parse(
      values["--outer-reservation-acknowledged-at"] ?? ""
    )) &&
    values["--outer-reservation-acknowledged-at"] === new Date(Date.parse(
      values["--outer-reservation-acknowledged-at"]
    )).toISOString() &&
    Date.parse(values["--outer-reserved-at"]) <= Date.parse(
      values["--outer-reservation-acknowledged-at"]
    ) &&
    UUID.test(values["--provider-cluster-id"]) &&
    COCKROACH_SQL_CLUSTER_ID.test(values["--sql-cluster-id"]) &&
    values["--provider-cluster-id"] !== values["--sql-cluster-id"] &&
    HEX_64.test(values["--recovery-security-receipt-sha256"]) &&
    /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/fresh-primary\/recovery-signer-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[A-Za-z0-9]{6}$/u
      .test(values["--signer-secret-arn"] ?? "") &&
    values["--signer-secret-arn"].includes(
      `/recovery-signer-${values["--operation-id"]}-`
    ) &&
    /^[A-Za-z0-9_-]{32,64}$/u.test(
      values["--signer-secret-version-id"] ?? ""
    ) &&
    TABLE_ARN.test(values["--controller-table-arn"]),
  "FRESH_PRIMARY_RUNNER_ARGUMENTS_REJECTED");
  return Object.freeze(values);
}

function readPrivateFile(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    const parent = fs.realpathSync(path.dirname(filePath));
    const parentStat = fs.lstatSync(parent);
    requireCondition(parent === path.dirname(filePath) &&
      parentStat.isDirectory() && !parentStat.isSymbolicLink() &&
      parentStat.uid === process.getuid() && (parentStat.mode & 0o077) === 0,
    code);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(bytes.length === before.size && before.dev === after.dev &&
      before.ino === after.ino && before.mode === after.mode &&
      before.size === after.size, code);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function parseJson(bytes, code) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(plainObject(value), code);
  return value;
}

function explicitAwsCredentials(environment) {
  const value = {
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  };
  requireCondition(/^ASIA[A-Z0-9]{16}$/u.test(value.accessKeyId ?? "") &&
    typeof value.secretAccessKey === "string" &&
    value.secretAccessKey.length === 40 &&
    typeof value.sessionToken === "string" &&
    value.sessionToken.length >= 16,
  "FRESH_PRIMARY_RUNNER_AWS_CREDENTIALS_REJECTED");
  return Object.freeze(value);
}

function publishPrivateReceipt(filePath, value) {
  const code = "FRESH_PRIMARY_RUNNER_RECEIPT_PUBLICATION_REJECTED";
  requireCondition(path.isAbsolute(filePath), code);
  const parent = fs.realpathSync(path.dirname(filePath));
  const parentStat = fs.lstatSync(parent);
  requireCondition(parent === path.dirname(filePath) &&
    parentStat.isDirectory() && !parentStat.isSymbolicLink() &&
    parentStat.uid === process.getuid() && (parentStat.mode & 0o077) === 0 &&
    !fs.existsSync(filePath), code);
  const bytes = canonicalBytes(value);
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    requireCondition(fs.writeSync(descriptor, bytes) === bytes.length, code);
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && !stat.isSymbolicLink() &&
      stat.nlink === 1 && stat.uid === process.getuid() &&
      (stat.mode & 0o077) === 0 && stat.size === bytes.length, code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
  return sha256(bytes);
}

function runtimePolicySha256() {
  return sha256(canonicalBytes({
    schemaVersion: "prooftoact.fresh-primary-runtime-credential-policy.v1",
    database: "tideproof",
    runtimeUsers: FRESH_PRIMARY_RUNTIME_USERS
  }));
}

export function freshPrimaryRuntimePolicySha256() {
  return runtimePolicySha256();
}

export async function main(
  args = process.argv.slice(2),
  environment = process.env,
  credentialCustody = Object.freeze({})
) {
  const parsed = parseArguments(args);
  const buildReceipt = parseJson(readPrivateFile(
    parsed["--build-receipt"],
    16 * 1024 * 1024,
    "FRESH_PRIMARY_RUNNER_BUILD_RECEIPT_REJECTED"
  ), "FRESH_PRIMARY_RUNNER_BUILD_RECEIPT_REJECTED");
  const approval = parseJson(readPrivateFile(
    parsed["--approval-file"],
    64 * 1024,
    "FRESH_PRIMARY_RUNNER_APPROVAL_REJECTED"
  ), "FRESH_PRIMARY_RUNNER_APPROVAL_REJECTED");
  const source = await verifyFreshPrimaryProviderPrerequisites({
    buildReceipt,
    callerWorkflowSha: parsed["--caller-workflow-sha"],
    expectedCommit: parsed["--expected-commit"],
    expectedTree: parsed["--expected-tree"]
  });
  requireCondition(source.sourceCommit === parsed["--expected-commit"] &&
    source.treeDigest === parsed["--expected-tree"],
  "FRESH_PRIMARY_RUNNER_SOURCE_REJECTED");
  const secretCoordinates = Object.freeze({
    admin: Object.freeze({
      arn: parsed["--admin-secret-arn"],
      versionId: parsed["--admin-secret-version-id"]
    }),
    cloudApi: Object.freeze({
      arn: parsed["--cloud-api-secret-arn"],
      versionId: parsed["--cloud-api-secret-version-id"]
    }),
    credential: Object.freeze({
      arn: parsed["--credential-secret-arn"],
      versionId: parsed["--credential-secret-version-id"]
    }),
    signer: Object.freeze({
      arn: parsed["--signer-secret-arn"],
      versionId: parsed["--signer-secret-version-id"]
    })
  });
  const lowLevelProvider = await createFreshPrimaryAwsRuntime({
    credentials: explicitAwsCredentials(environment),
    dynamoDbRuntime: credentialCustody.dynamoDbRuntime,
    region: "us-east-1",
    secretCoordinates,
    tableArn: parsed["--controller-table-arn"]
  });
  const material = await readFreshPrimarySecretMaterial({
    provider: lowLevelProvider,
    secretCoordinates
  });
  const admin = validateFreshClusterAdminConnectionString(
    material.admin.secretValue
  );
  const credentialBundleRawBytes = Buffer.from(
    material.credential.secretValue,
    "utf8"
  );
  let credentialBundle;
  let credentialBundleRawSha256;
  let credentialBundleSha256;
  let recoveryPublisherSecret;
  try {
    credentialBundle = validateFreshPrimaryCredentialBundle(parseJson(
      credentialBundleRawBytes,
      "FRESH_PRIMARY_RUNNER_CREDENTIAL_BUNDLE_REJECTED"
    ));
    credentialBundleRawSha256 = sha256(credentialBundleRawBytes);
    credentialBundleSha256 = sha256(canonicalBytes(credentialBundle));
    recoveryPublisherSecret = deriveFreshRecoveryPublisherSecret({
      operationId: parsed["--operation-id"],
      sourceCommit: source.sourceCommit,
      treeDigest: source.treeDigest
    }, credentialBundleRawBytes);
  } finally {
    credentialBundleRawBytes.fill(0);
  }
  const credentialSeal = validateFreshPrimaryCredentialSeal({
    schemaVersion: "prooftoact.fresh-primary-credential-seal.v1",
    status: "SEALED",
    provider: "AWS_SECRETS_MANAGER",
    providerBacked: true,
    immutableVersion: true,
    operationId: parsed["--operation-id"],
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest,
    credentialBundleRawSha256,
    credentialBundleSha256,
    runtimePolicySha256: runtimePolicySha256(),
    sealedAt: material.credential.createdAt,
    secretArnSha256: material.credential.secretArnSha256,
    secretVersionIdSha256: material.credential.secretVersionIdSha256
  }, {
    credentialBundleRawSha256,
    credentialBundleSha256,
    operationId: parsed["--operation-id"],
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  const credentialSealReceiptSha256 = sha256(canonicalBytes(credentialSeal));
  const acceptedApproval = validateFreshPrimaryApproval(approval, {
    clusterHostSha256: admin.hostSha256,
    credentialSealReceiptSha256,
    operationId: parsed["--operation-id"],
    outerAuthenticationReceiptSha256:
      parsed["--outer-authentication-receipt-sha256"],
    outerCommandSha256: parsed["--outer-command-sha256"],
    outerReservedAt: parsed["--outer-reserved-at"],
    outerReservationAcknowledgedAt:
      parsed["--outer-reservation-acknowledged-at"],
    outerReservationReceiptSha256:
      parsed["--outer-reservation-receipt-sha256"],
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  requireCondition(acceptedApproval.expectedClusterId ===
    parsed["--sql-cluster-id"], "FRESH_PRIMARY_RUNNER_SQL_CLUSTER_REJECTED");
  const command = buildFreshPrimaryProviderCommand({
    adminSecretArnSha256: material.admin.secretArnSha256,
    adminSecretValueSha256: material.admin.secretValueSha256,
    adminSecretVersionIdSha256: material.admin.secretVersionIdSha256,
    approvalId: acceptedApproval.approvalId,
    approvalSha256: sha256(canonicalBytes(acceptedApproval)),
    cloudApiSecretArnSha256: material.cloudApi.secretArnSha256,
    cloudApiSecretValueSha256: material.cloudApi.secretValueSha256,
    cloudApiSecretVersionIdSha256: material.cloudApi.secretVersionIdSha256,
    controllerTableArn: parsed["--controller-table-arn"],
    credentialSecretArnSha256: material.credential.secretArnSha256,
    credentialSecretVersionIdSha256:
      material.credential.secretVersionIdSha256,
    credentialBundleRawSha256,
    credentialBundleSha256,
    credentialSealReceiptSha256,
    operationId: parsed["--operation-id"],
    outerAuthenticationReceiptSha256:
      parsed["--outer-authentication-receipt-sha256"],
    outerCommandSha256: parsed["--outer-command-sha256"],
    outerReservedAt: parsed["--outer-reserved-at"],
    outerReservationAcknowledgedAt:
      parsed["--outer-reservation-acknowledged-at"],
    outerReservationReceiptSha256:
      parsed["--outer-reservation-receipt-sha256"],
    providerClusterId: parsed["--provider-cluster-id"],
    recoveryPublisherKeySetDigest:
      recoveryPublisherSecret.publisherKeySetDigest,
    recoveryPublisherTrustRootCommitment:
      recoveryPublisherSecret.trustRootCommitment,
    recoverySecurityPostureReceiptSha256:
      parsed["--recovery-security-receipt-sha256"],
    signerSecretArnSha256: sha256(parsed["--signer-secret-arn"]),
    signerSecretValueSha256: recoveryPublisherSecret.secretBytesSha256,
    signerSecretVersionIdSha256:
      sha256(parsed["--signer-secret-version-id"]),
    sourceCommit: source.sourceCommit,
    sqlClusterId: parsed["--sql-cluster-id"],
    treeDigest: source.treeDigest,
    trustRootJsonSha256: recoveryPublisherSecret.trustRootJsonSha256
  });
  const provider = createFreshPrimaryAwsProvider({
    provider: lowLevelProvider,
    secretCoordinates,
    sqlHostSha256: admin.hostSha256,
    tableArn: parsed["--controller-table-arn"]
  });
  const receipt = await runFreshPrimaryProviderControlledBootstrap({
    adminConnectionString: admin.connectionString,
    approval: acceptedApproval,
    buildReceipt,
    callerWorkflowSha: parsed["--caller-workflow-sha"],
    command,
    credentialBundle,
    credentialBundleRawSha256,
    credentialBundleSha256,
    credentialSeal,
    databaseEnvironment: Object.freeze({}),
    discardAdminCredential: credentialCustody.discardAdminCredential,
    expectedCommit: source.sourceCommit,
    expectedTree: source.treeDigest,
    localCredentialDiscarded:
      credentialCustody.localCredentialDiscarded === true,
    operationId: parsed["--operation-id"],
    provider,
    recoveryPublisherSecret,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  requireCondition(receipt?.status === "PASS" &&
    receipt?.schemaVersion ===
      "prooftoact.fresh-primary-provider-controller-receipt.v3" &&
    receipt.commandSha256 === command.commandSha256,
  "FRESH_PRIMARY_RUNNER_RECEIPT_REJECTED");
  const receiptSha256 = publishPrivateReceipt(
    parsed["--receipt-output"], receipt
  );
  process.stdout.write(`FRESH_PRIMARY_PROVIDER_PASS:${receiptSha256}\n`);
  return receipt;
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^FRESH_PRIMARY_[A-Z0-9_]{1,100}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "FRESH_PRIMARY_RUNNER_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  canonicalBytes,
  canonicalJson,
  explicitAwsCredentials,
  parseArguments,
  parseJson,
  publishPrivateReceipt,
  runtimePolicySha256,
  sha256
});
