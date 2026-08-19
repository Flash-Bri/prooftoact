import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  validateFreshPrimaryApproval,
  validateFreshPrimaryCredentialBundle,
  validateFreshPrimaryCredentialSeal,
  verifyFreshPrimaryProviderPrerequisites
} from "./bootstrap-fresh-primary.js";
import {
  createFreshClusterAwsProvider,
  readFreshClusterSecretMaterial,
  readFreshRecoveryPublicationSecretMaterial
} from "./fresh-cluster-aws-provider.js";
import { createFreshClusterAwsRuntime } from
  "./fresh-cluster-aws-runtime.js";
import {
  buildFreshClusterCreateCommand,
  createFreshClusterCloudRuntime,
  deriveFreshPrimaryApproval,
  validateFreshClusterApproval,
  validateFreshClusterCleanupApproval
} from "./fresh-cluster-cloud-controller.js";
import {
  createFreshClusterCleanupRuntime,
  createFreshClusterExecutionRuntime
} from
  "./fresh-cluster-execution-runtime.js";
import { runFreshClusterProviderController } from
  "./fresh-cluster-provider-controller.js";
import { reconcileFreshClusterProviderAccess } from
  "./fresh-cluster-reconciliation-controller.js";
import {
  createFreshRecoveryPublicationExecution,
  freshRecoveryPublicationProviderBinding
} from "./fresh-recovery-publication-execution.js";
import { produceFreshRecoverySource } from
  "./fresh-recovery-source-execution.js";
import {
  freshPrimaryRuntimePolicySha256,
  main as runFreshPrimaryProvider
} from "./run-fresh-primary-provider.js";
import {
  validateProofToActB0A1HumanAuthorizationReceipt
} from "./lib/prooftoact-b0-a1-human-authorization.js";
import { loadReleaseControlRuntime } from
  "../release-control/src/release-control-runtime-loader.js";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;
const CALLER_WORKFLOW_REF =
  "Flash-Bri/prooftoact/.github/workflows/" +
  "prooftoact-fresh-primary.yml@refs/heads/main";
const APPROVED_ADOPTION = Object.freeze({
  adoptedAdminPasswordSha256:
    "94b8dd5d33cd6c92162fe203545fed13456bc26fcb5a5fb53b5df381c2dfcdd9",
  auditorAuthorityReceiptSha256:
    "b24aacad3eb5a3d5232870823694eda725c0baa9c0f6efe917215d6cf28d5579",
  auditorServiceAccountId: "485a992f-e5ea-45a3-b415-cb70fcb0a5f5",
  auditorTokenValueSha256:
    "c6da3f68f54d5dc96adbe79636fc0ee2783d238f41355381082e863e11feb22f",
  creatorAuthorityReceiptSha256:
    "35795f836dacdd5893097e6c5a524e59749db0f42ae00e157bfcbe3e16d2e3e4",
  creatorProviderReadbackReceiptSha256:
    "e16dab166ddc6342147023cf409f522278e29047d63659e3e2411a30d74e7c0e",
  creatorServiceAccountId: "f363a800-37e6-4f34-8440-44e37f224980",
  creatorTokenValueSha256:
    "627e1ebb12238d62e222479564ef76f3b4b5165c8a5c609a6bf414dcd1eeec64",
  host:
    "prooftoact-gate2-32394.j77.aws-us-east-1.cockroachlabs.cloud",
  manualClusterReceiptSha256:
    "7a370783c32e528db7f4892ea4720c7ae2fb19eb9e1d553b4dd09ea2a4eb5be8",
  providerClusterId: "59294a51-f2d3-4275-b893-7ddb530829c7",
  sqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b"
});

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
    "FRESH_CLUSTER_RUNNER_CANONICAL_RECORD_REJECTED");
  return bytes;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function parseArguments(args) {
  const accepted = new Set([
    "--admin-password-file",
    "--admin-secret-arn",
    "--admin-secret-version-id",
    "--approval-file",
    "--approval-sha256",
    "--auditor-secret-arn",
    "--auditor-secret-version-id",
    "--build-receipt",
    "--cloud-api-secret-arn",
    "--cloud-api-secret-version-id",
    "--caller-workflow-ref",
    "--caller-workflow-sha",
    "--controller-table-arn",
    "--credential-secret-arn",
    "--credential-secret-version-id",
    "--expected-commit",
    "--expected-tree",
    "--human-authorization-signer-sha256",
    "--mcp-secret-arn",
    "--mcp-secret-version-id",
    "--mode",
    "--operation-id",
    "--publisher-secret-arn",
    "--publisher-secret-version-id",
    "--receipt-output",
    "--release-control-runtime-receipt",
    "--recovery-security-receipt-sha256",
    "--signer-secret-arn",
    "--signer-secret-version-id"
  ]);
  requireCondition(args.length === accepted.size * 2,
    "FRESH_CLUSTER_RUNNER_ARGUMENTS_REJECTED");
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    requireCondition(accepted.has(name) && !Object.hasOwn(values, name) &&
      typeof args[index + 1] === "string" && args[index + 1] !== "",
    "FRESH_CLUSTER_RUNNER_ARGUMENTS_REJECTED");
    values[name] = args[index + 1];
  }
  requireCondition(HEX_40.test(values["--expected-commit"]) &&
    HEX_40.test(values["--expected-tree"]) &&
    HEX_40.test(values["--caller-workflow-sha"]) &&
    HEX_64.test(values["--approval-sha256"]) &&
    HEX_64.test(values["--human-authorization-signer-sha256"]) &&
    values["--caller-workflow-ref"] === CALLER_WORKFLOW_REF &&
    ["execute", "reconcile-only"].includes(values["--mode"]) &&
    UUID.test(values["--operation-id"]) &&
    HEX_64.test(values["--recovery-security-receipt-sha256"]) &&
    TABLE_ARN.test(values["--controller-table-arn"]),
  "FRESH_CLUSTER_RUNNER_ARGUMENTS_REJECTED");
  return Object.freeze(values);
}

function validateApprovedAdoption(approval, authority) {
  let sharedAuthorization;
  try {
    sharedAuthorization =
      validateProofToActB0A1HumanAuthorizationReceipt(
        approval?.humanAuthorizationBinding,
        authority?.humanAuthorizationSignerSha256
      );
  } catch (cause) {
    reject("FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED", cause);
  }
  requireCondition(approval?.clusterMode === "ADOPT_VERIFIED_EXISTING" &&
    plainObject(authority) &&
    HEX_64.test(authority.approvalSha256 ?? "") &&
    HEX_64.test(authority.controllerImportGraphSha256 ?? "") &&
    HEX_64.test(authority.humanAuthorizationSignerSha256 ?? "") &&
    HEX_40.test(authority.callerWorkflowSha ?? "") &&
    authority.callerWorkflowRef === CALLER_WORKFLOW_REF &&
    approval.callerWorkflowRef === authority.callerWorkflowRef &&
    approval.callerWorkflowSha === authority.callerWorkflowSha &&
    approval.controllerImportGraphSha256 ===
      authority.controllerImportGraphSha256 &&
    approval.humanAuthorizationReceiptSha256 ===
      approval.billingAuthorization?.authorizationReceiptSha256 &&
    approval.humanAuthorizationReceiptSha256 ===
      sharedAuthorization.receiptBindingSha256 &&
    approval.humanAuthorizedTextSha256 ===
      sharedAuthorization.humanAuthorizedTextSha256 &&
    sharedAuthorization.dynamicIntent.a1ProviderClusterId ===
      approval.providerClusterId &&
    sharedAuthorization.dynamicIntent.a1SqlClusterId ===
      approval.sqlClusterId &&
    sha256(canonicalBytes(approval)) === authority.approvalSha256 &&
    approval.adoptedAdminPasswordSha256 ===
      APPROVED_ADOPTION.adoptedAdminPasswordSha256 &&
    approval.billingAuthorization?.authorizedMonthlyCeilingUsd === "2.00" &&
    approval.auditorAuthorityReceiptSha256 ===
      APPROVED_ADOPTION.auditorAuthorityReceiptSha256 &&
    approval.auditorServiceAccountId ===
      APPROVED_ADOPTION.auditorServiceAccountId &&
    approval.auditorTokenValueSha256 ===
      APPROVED_ADOPTION.auditorTokenValueSha256 &&
    approval.creatorAuthorityReceiptSha256 ===
      APPROVED_ADOPTION.creatorAuthorityReceiptSha256 &&
    approval.creatorProviderReadbackReceiptSha256 ===
      APPROVED_ADOPTION.creatorProviderReadbackReceiptSha256 &&
    approval.creatorServiceAccountId ===
      APPROVED_ADOPTION.creatorServiceAccountId &&
    approval.creatorTokenValueSha256 ===
      APPROVED_ADOPTION.creatorTokenValueSha256 &&
    approval.providerClusterId === APPROVED_ADOPTION.providerClusterId &&
    approval.sqlClusterId === APPROVED_ADOPTION.sqlClusterId &&
    approval.manualClusterReceiptSha256 ===
      APPROVED_ADOPTION.manualClusterReceiptSha256,
  "FRESH_CLUSTER_RUNNER_ADOPTION_AUTHORITY_REJECTED");
  return approval;
}

function validateRunnerApproval(
  value,
  binding,
  mode,
  authority,
  now = Date.now()
) {
  requireCondition(["execute", "reconcile-only"].includes(mode),
    "FRESH_CLUSTER_RUNNER_APPROVAL_REJECTED");
  const accepted = mode === "reconcile-only"
    ? validateFreshClusterCleanupApproval(value, binding, now)
    : validateFreshClusterApproval(value, binding, now);
  return validateApprovedAdoption(accepted, authority);
}

function readPrivateFile(filePath, maximumBytes, code) {
  return readPrivateFileRecord(filePath, maximumBytes, code).bytes;
}

function readPrivateFileRecord(filePath, maximumBytes, code) {
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
    return Object.freeze({
      bytes,
      device: before.dev,
      filePath,
      inode: before.ino,
      mode: before.mode,
      size: before.size,
      uid: before.uid
    });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readApprovedAdoptedAdminPassword(filePath, approval) {
  const code = "FRESH_CLUSTER_RUNNER_ADMIN_PASSWORD_REJECTED";
  requireCondition(approval?.clusterMode === "ADOPT_VERIFIED_EXISTING" &&
    HEX_64.test(approval.adoptedAdminPasswordSha256 ?? ""), code);
  const record = readPrivateFileRecord(filePath, 1024, code);
  const password = record.bytes.toString("utf8");
  requireCondition(password.length >= 20 && password.length <= 256 &&
    !/[\u0000\r\n]/u.test(password) && sha256(record.bytes) ===
      approval.adoptedAdminPasswordSha256,
  code);
  return Object.freeze({ password, record });
}

function discardPrivateFile(record, code) {
  requireCondition(record && Buffer.isBuffer(record.bytes) &&
    path.isAbsolute(record.filePath) && record.bytes.length === record.size,
  code);
  let descriptor;
  let parentDescriptor;
  try {
    descriptor = fs.openSync(
      record.filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const current = fs.fstatSync(descriptor);
    requireCondition(current.isFile() && !current.isSymbolicLink() &&
      current.nlink === 1 && current.dev === record.device &&
      current.ino === record.inode && current.mode === record.mode &&
      current.size === record.size && current.uid === record.uid, code);
    record.bytes.fill(0);
    fs.unlinkSync(record.filePath);
    parentDescriptor = fs.openSync(
      path.dirname(record.filePath),
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    fs.fsyncSync(parentDescriptor);
    requireCondition(!fs.existsSync(record.filePath), code);
    return true;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
    if (Number.isSafeInteger(parentDescriptor)) fs.closeSync(parentDescriptor);
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
  "FRESH_CLUSTER_RUNNER_AWS_CREDENTIALS_REJECTED");
  return Object.freeze(value);
}

function exactSourceFileSha256(relativePath) {
  requireCondition([
    "release-control/package-lock.json",
    "release-control/package.json"
  ].includes(relativePath), "FRESH_CLUSTER_RUNNER_CONTROL_PACKAGE_REJECTED");
  const root = fs.realpathSync(process.cwd());
  const filePath = path.resolve(root, relativePath);
  requireCondition(path.relative(root, filePath) ===
    relativePath.split("/").join(path.sep) &&
    fs.realpathSync(filePath) === filePath,
  "FRESH_CLUSTER_RUNNER_CONTROL_PACKAGE_REJECTED");
  const stat = fs.lstatSync(filePath);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() &&
    stat.nlink === 1 && stat.size > 0 && stat.size <= 2 * 1024 * 1024,
  "FRESH_CLUSTER_RUNNER_CONTROL_PACKAGE_REJECTED");
  return sha256(fs.readFileSync(filePath));
}

function writePrivateNew(filePath, value, code) {
  requireCondition(path.isAbsolute(filePath) && !fs.existsSync(filePath), code);
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

function ensurePrivateDirectory(directoryPath, parentPath, code) {
  requireCondition(path.isAbsolute(directoryPath) &&
    path.isAbsolute(parentPath) && path.dirname(directoryPath) === parentPath,
  code);
  let parent;
  try {
    parent = fs.realpathSync(parentPath);
    const parentStat = fs.lstatSync(parent);
    requireCondition(parent === parentPath && parentStat.isDirectory() &&
      !parentStat.isSymbolicLink() && parentStat.uid === process.getuid() &&
      (parentStat.mode & 0o077) === 0, code);
    try {
      fs.mkdirSync(directoryPath, { mode: 0o700 });
    } catch (cause) {
      if (cause?.code !== "EEXIST") throw cause;
    }
    const resolved = fs.realpathSync(directoryPath);
    const stat = fs.lstatSync(resolved);
    requireCondition(resolved === directoryPath && stat.isDirectory() &&
      !stat.isSymbolicLink() && stat.uid === process.getuid() &&
      (stat.mode & 0o077) === 0, code);
    return resolved;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function credentialBundleFromMaterial(material) {
  const code = "FRESH_CLUSTER_RUNNER_CREDENTIAL_BUNDLE_REJECTED";
  requireCondition(typeof material?.credential?.secretValue === "string",
    code);
  const raw = Buffer.from(material.credential.secretValue, "utf8");
  try {
    return validateFreshPrimaryCredentialBundle(parseJson(raw, code));
  } finally {
    raw.fill(0);
  }
}

function secretCoordinates(parsed) {
  return Object.freeze({
    admin: Object.freeze({
      arn: parsed["--admin-secret-arn"],
      versionId: parsed["--admin-secret-version-id"]
    }),
    auditor: Object.freeze({
      arn: parsed["--auditor-secret-arn"],
      versionId: parsed["--auditor-secret-version-id"]
    }),
    cloudApi: Object.freeze({
      arn: parsed["--cloud-api-secret-arn"],
      versionId: parsed["--cloud-api-secret-version-id"]
    }),
    credential: Object.freeze({
      arn: parsed["--credential-secret-arn"],
      versionId: parsed["--credential-secret-version-id"]
    }),
    mcp: Object.freeze({
      arn: parsed["--mcp-secret-arn"],
      versionId: parsed["--mcp-secret-version-id"]
    }),
    publisher: Object.freeze({
      arn: parsed["--publisher-secret-arn"],
      versionId: parsed["--publisher-secret-version-id"]
    }),
    signer: Object.freeze({
      arn: parsed["--signer-secret-arn"],
      versionId: parsed["--signer-secret-version-id"]
    })
  });
}

function credentialSealForDerivedApproval({
  material,
  operationId,
  sourceCommit,
  treeDigest
}) {
  const raw = Buffer.from(material.credential.secretValue, "utf8");
  const bundle = validateFreshPrimaryCredentialBundle(parseJson(
    raw,
    "FRESH_CLUSTER_RUNNER_CREDENTIAL_BUNDLE_REJECTED"
  ));
  const credentialBundleRawSha256 = sha256(raw);
  const credentialBundleSha256 = sha256(canonicalBytes(bundle));
  raw.fill(0);
  const seal = validateFreshPrimaryCredentialSeal({
    schemaVersion: "prooftoact.fresh-primary-credential-seal.v1",
    status: "SEALED",
    provider: "AWS_SECRETS_MANAGER",
    providerBacked: true,
    immutableVersion: true,
    operationId,
    sourceCommit,
    treeDigest,
    credentialBundleRawSha256,
    credentialBundleSha256,
    runtimePolicySha256: freshPrimaryRuntimePolicySha256(),
    sealedAt: material.credential.createdAt,
    secretArnSha256: material.credential.secretArnSha256,
    secretVersionIdSha256: material.credential.secretVersionIdSha256
  }, {
    credentialBundleRawSha256,
    credentialBundleSha256,
    operationId,
    sourceCommit,
    treeDigest
  });
  return Object.freeze({
    credentialBundleRawSha256,
    credentialBundleSha256,
    credentialSealReceiptSha256: sha256(canonicalBytes(seal))
  });
}

function publishPrivateReceipt(filePath, receipt) {
  return writePrivateNew(
    filePath,
    receipt,
    "FRESH_CLUSTER_RUNNER_RECEIPT_PUBLICATION_REJECTED"
  );
}

export async function main(
  args = process.argv.slice(2),
  environment = process.env,
  trustedRuntime = Object.freeze({})
) {
  const parsed = parseArguments(args);
  const buildReceipt = parseJson(readPrivateFile(
    parsed["--build-receipt"],
    16 * 1024 * 1024,
    "FRESH_CLUSTER_RUNNER_BUILD_RECEIPT_REJECTED"
  ), "FRESH_CLUSTER_RUNNER_BUILD_RECEIPT_REJECTED");
  const source = await verifyFreshPrimaryProviderPrerequisites({
    buildReceipt,
    expectedCommit: parsed["--expected-commit"],
    expectedTree: parsed["--expected-tree"]
  });
  const approval = validateRunnerApproval(
    parseJson(readPrivateFile(
    parsed["--approval-file"],
    128 * 1024,
    "FRESH_CLUSTER_RUNNER_APPROVAL_REJECTED"
  ), "FRESH_CLUSTER_RUNNER_APPROVAL_REJECTED"), {
    accountId: parsed["--controller-table-arn"].split(":")[4],
    operationId: parsed["--operation-id"],
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  }, parsed["--mode"], {
    approvalSha256: parsed["--approval-sha256"],
    callerWorkflowRef: parsed["--caller-workflow-ref"],
    callerWorkflowSha: parsed["--caller-workflow-sha"],
    controllerImportGraphSha256:
      trustedRuntime.controllerImportGraphSha256,
    humanAuthorizationSignerSha256:
      parsed["--human-authorization-signer-sha256"]
  });
  const adoptedAdmin = parsed["--mode"] === "execute"
    ? readApprovedAdoptedAdminPassword(
      parsed["--admin-password-file"], approval
    )
    : null;
  const coordinates = secretCoordinates(parsed);
  const credentials = explicitAwsCredentials(environment);
  const privateRoot = path.dirname(parsed["--approval-file"]);
  const releaseControlReceipt = parseJson(readPrivateFile(
    parsed["--release-control-runtime-receipt"],
    1024 * 1024,
    "FRESH_CLUSTER_RUNNER_CONTROL_RUNTIME_RECEIPT_REJECTED"
  ), "FRESH_CLUSTER_RUNNER_CONTROL_RUNTIME_RECEIPT_REJECTED");
  const releaseControlRuntime = await loadReleaseControlRuntime({
    expectedControlPlaneCommit: source.sourceCommit,
    expectedControlPlaneTree: source.treeDigest,
    expectedPackageJsonSha256:
      exactSourceFileSha256("release-control/package.json"),
    expectedPackageLockSha256:
      exactSourceFileSha256("release-control/package-lock.json"),
    projectRoot: privateRoot,
    receipt: releaseControlReceipt
  });
  const dynamoDbRuntime =
    await releaseControlRuntime.createReleaseControlAwsRuntime({
      credentials,
      region: "us-east-1",
      tableArn: parsed["--controller-table-arn"]
    });
  const awsRuntime = await createFreshClusterAwsRuntime({
    credentials,
    dynamoDbRuntime,
    operationId: approval.operationId,
    region: "us-east-1",
    secretCoordinates: coordinates,
    tableArn: parsed["--controller-table-arn"]
  });
  const material = await readFreshClusterSecretMaterial({
    provider: awsRuntime,
    secretCoordinates: coordinates
  });
  const cloudRuntime = createFreshClusterCloudRuntime();
  const command = buildFreshClusterCreateCommand({
    adoptedAdminPasswordSha256: approval.adoptedAdminPasswordSha256,
    approvalId: approval.approvalId,
    approvalSha256: sha256(canonicalBytes(approval)),
    auditorAuthorityReceiptSha256:
      approval.auditorAuthorityReceiptSha256,
    auditorServiceAccountId: approval.auditorServiceAccountId,
    auditorTokenValueSha256: approval.auditorTokenValueSha256,
    billingAuthorization: approval.billingAuthorization,
    clusterMode: approval.clusterMode,
    controllerTableArn: parsed["--controller-table-arn"],
    creatorAuthorityReceiptSha256:
      approval.creatorAuthorityReceiptSha256,
    creatorProviderReadbackReceiptSha256:
      approval.creatorProviderReadbackReceiptSha256,
    creatorServiceAccountId: approval.creatorServiceAccountId,
    creatorTokenValueSha256: approval.creatorTokenValueSha256,
    manualClusterReceiptSha256: approval.manualClusterReceiptSha256,
    operationId: approval.operationId,
    parentFolderId: approval.parentFolderId,
    providerClusterId: approval.providerClusterId,
    sourceCommit: source.sourceCommit,
    treeDigest: source.treeDigest
  });
  const provider = createFreshClusterAwsProvider({
    provider: awsRuntime,
    secretCoordinates: coordinates,
    tableArn: parsed["--controller-table-arn"]
  });
  const assertCleanupOpen = () => {
    requireCondition(Date.now() < Date.parse(
      approval.billingAuthorization.retentionDeadline
    ), "FRESH_CLUSTER_RUNNER_CLEANUP_AUTHORIZATION_EXPIRED");
  };
  if (parsed["--mode"] === "reconcile-only") {
    const reconciliation = await reconcileFreshClusterProviderAccess({
      command,
      provider,
      runtime: createFreshClusterCleanupRuntime({
        assertCleanupOpen,
        cloudRuntime,
        material
      })
    });
    const reconciliationSha256 = publishPrivateReceipt(
      parsed["--receipt-output"], reconciliation
    );
    process.stdout.write(
      `FRESH_CLUSTER_RECONCILIATION_PASS:${reconciliationSha256}\n`
    );
    return reconciliation;
  }
  const adoptedAdminPasswordRecord = adoptedAdmin.record;
  const adoptedAdminPassword = adoptedAdmin.password;
  const execution = createFreshClusterExecutionRuntime({
    adoptedAdminPassword,
    assertCleanupOpen,
    awsRuntime,
    cloudRuntime,
    material,
    secretCoordinates: coordinates,
    async freshRecoveryPublicationFactory({
      adminAuthentication,
      bootstrapReceipt,
      cluster,
      command: acceptedCommand,
      credential,
      primaryClusterMapping
    }) {
      requireCondition(
        cluster.clusterId === APPROVED_ADOPTION.providerClusterId &&
        cluster.sqlDns === APPROVED_ADOPTION.host &&
        adminAuthentication.providerClusterId ===
          APPROVED_ADOPTION.providerClusterId &&
        adminAuthentication.sqlClusterId === APPROVED_ADOPTION.sqlClusterId &&
        typeof credential?.connectionString === "string" &&
        sha256(credential.connectionString) ===
          credential.connectionStringSha256,
      "FRESH_CLUSTER_RUNNER_RECOVERY_SOURCE_BINDING_REJECTED");
      const publicationMaterial =
        await readFreshRecoveryPublicationSecretMaterial({
          provider: awsRuntime,
          secretCoordinates: coordinates
        });
      const recoveryPublisher = bootstrapReceipt.credentialLifecycle
        ?.recoveryPublisher;
      requireCondition(
        publicationMaterial.credential.secretArnSha256 ===
          material.credential.secretArnSha256 &&
        publicationMaterial.credential.secretVersionIdSha256 ===
          material.credential.secretVersionIdSha256 &&
        publicationMaterial.credential.secretValueSha256 ===
          material.credential.secretValueSha256 &&
        publicationMaterial.signer.secretArnSha256 ===
          recoveryPublisher?.signerSecretArnSha256 &&
        publicationMaterial.signer.secretVersionIdSha256 ===
          recoveryPublisher?.signerSecretVersionIdSha256 &&
        publicationMaterial.signer.secretValueSha256 ===
          recoveryPublisher?.signerSecretValueSha256,
      "FRESH_CLUSTER_RUNNER_RECOVERY_SECRET_BINDING_REJECTED");
      const credentialBundle = credentialBundleFromMaterial(
        publicationMaterial
      );
      const sourceReceipt = await produceFreshRecoverySource({
        adminConnectionString: credential.connectionString,
        credentialBundle,
        operationId: acceptedCommand.operationId,
        sourceCommit: acceptedCommand.sourceCommit,
        treeDigest: acceptedCommand.treeDigest
      });
      const providerBinding = freshRecoveryPublicationProviderBinding();
      requireCondition(providerBinding.primaryProviderClusterId ===
          APPROVED_ADOPTION.providerClusterId &&
        providerBinding.primarySqlClusterId ===
          APPROVED_ADOPTION.sqlClusterId,
      "FRESH_CLUSTER_RUNNER_RECOVERY_PROVIDER_BINDING_REJECTED");
      const binding = Object.freeze({
        billingAuthorizationSha256:
          acceptedCommand.billingAuthorizationSha256,
        credentialSecretValueSha256:
          publicationMaterial.credential.secretValueSha256,
        mcpSecretValueSha256: publicationMaterial.mcp.secretValueSha256,
        operationId: acceptedCommand.operationId,
        primaryClusterMapping,
        primaryClusterMappingReceiptSha256:
          primaryClusterMapping.receiptSha256,
        primaryProviderClusterId:
          providerBinding.primaryProviderClusterId,
        primarySqlClusterId: providerBinding.primarySqlClusterId,
        publisherSecretValueSha256:
          publicationMaterial.publisher.secretValueSha256,
        recoveryProviderClusterId:
          providerBinding.recoveryProviderClusterId,
        recoverySecurityReceiptSha256:
          parsed["--recovery-security-receipt-sha256"],
        recoverySqlClusterId: providerBinding.recoverySqlClusterId,
        signerSecretValueSha256:
          publicationMaterial.signer.secretValueSha256,
        sourceBinding: sourceReceipt.sourceBinding,
        sourceBindingSha256: sourceReceipt.sourceBindingSha256,
        sourceCommit: acceptedCommand.sourceCommit,
        treeDigest: acceptedCommand.treeDigest
      });
      const evidenceRootPath = ensurePrivateDirectory(
        path.join(privateRoot, "fresh-recovery-evidence"),
        privateRoot,
        "FRESH_CLUSTER_RUNNER_RECOVERY_EVIDENCE_ROOT_REJECTED"
      );
      const spec = Object.freeze({
        operationId: acceptedCommand.operationId,
        runId: sourceReceipt.sourceBinding.runId,
        sourceCommit: acceptedCommand.sourceCommit,
        treeDigest: acceptedCommand.treeDigest
      });
      const publication = createFreshRecoveryPublicationExecution({
        binding,
        bundlePath: path.join(
          evidenceRootPath,
          `${sourceReceipt.sourceBinding.runId}.signed-recovery-bundle.json`
        ),
        evidenceRootPath,
        forbiddenRootPath: fs.realpathSync(process.cwd()),
        material: publicationMaterial,
        spec
      });
      return Object.freeze({
        async prepare() {
          const preparationReceipt = await publication.prepare();
          return Object.freeze({
            schemaVersion:
              "prooftoact.fresh-recovery-source-and-preparation.v1",
            status: "PREPARED",
            operationId: acceptedCommand.operationId,
            sourceCommit: acceptedCommand.sourceCommit,
            treeDigest: acceptedCommand.treeDigest,
            sourceReceipt,
            sourceReceiptSha256: sha256(canonicalBytes(sourceReceipt)),
            preparationReceipt,
            preparationReceiptSha256:
              sha256(canonicalBytes(preparationReceipt))
          });
        },
        append() {
          return publication.append();
        },
        replay() {
          return publication.replay();
        },
        planManagedMcp() {
          return publication.planManagedMcp();
        },
        verifyManagedMcp(value) {
          return publication.verifyManagedMcp(value);
        }
      });
    },
    async localAdminCredentialDiscarder() {
      return discardPrivateFile(
        adoptedAdminPasswordRecord,
        "FRESH_CLUSTER_RUNNER_ADMIN_PASSWORD_DISCARD_REJECTED"
      );
    },
    async freshPrimaryInvoker({
      adminAuthentication,
      cluster,
      command: acceptedCommand,
      outerAuthentication,
      outerReservationAcknowledgedAt,
      reservation
    }) {
      requireCondition(
        cluster.clusterId === APPROVED_ADOPTION.providerClusterId &&
        cluster.sqlDns === APPROVED_ADOPTION.host &&
        adminAuthentication.providerClusterId ===
          APPROVED_ADOPTION.providerClusterId &&
        adminAuthentication.sqlClusterId === APPROVED_ADOPTION.sqlClusterId,
      "FRESH_CLUSTER_RUNNER_ADOPTION_READBACK_REJECTED");
      const binding = credentialSealForDerivedApproval({
        material,
        operationId: acceptedCommand.operationId,
        sourceCommit: acceptedCommand.sourceCommit,
        treeDigest: acceptedCommand.treeDigest
      });
      const derivedApproval = validateFreshPrimaryApproval(
        deriveFreshPrimaryApproval({
          clusterApproval: approval,
          clusterCommand: acceptedCommand,
          clusterHostSha256: sha256(cluster.sqlDns),
          credentialSealReceiptSha256:
            binding.credentialSealReceiptSha256,
          outerAuthentication,
          outerReservation: reservation,
          outerReservationAcknowledgedAt,
          sqlClusterId: adminAuthentication.sqlClusterId
        }), {
          clusterHostSha256: sha256(cluster.sqlDns),
          credentialSealReceiptSha256:
            binding.credentialSealReceiptSha256,
          operationId: acceptedCommand.operationId,
          outerAuthenticationReceiptSha256:
            sha256(canonicalBytes(outerAuthentication)),
          outerCommandSha256: acceptedCommand.commandSha256,
          outerReservedAt: reservation.reservedAt,
          outerReservationAcknowledgedAt,
          outerReservationReceiptSha256:
            sha256(canonicalBytes(reservation)),
          sourceCommit: acceptedCommand.sourceCommit,
          treeDigest: acceptedCommand.treeDigest
        });
      const derivedPath = path.join(privateRoot, "derived-primary-approval.json");
      writePrivateNew(
        derivedPath,
        derivedApproval,
        "FRESH_CLUSTER_RUNNER_DERIVED_APPROVAL_WRITE_REJECTED"
      );
      const primaryReceiptPath = path.join(
        privateRoot,
        "fresh-primary-provider-receipt.json"
      );
      const primaryReceipt = await runFreshPrimaryProvider([
        "--admin-secret-arn", coordinates.admin.arn,
        "--admin-secret-version-id", coordinates.admin.versionId,
        "--approval-file", derivedPath,
        "--build-receipt", parsed["--build-receipt"],
        "--cloud-api-secret-arn", coordinates.cloudApi.arn,
        "--cloud-api-secret-version-id", coordinates.cloudApi.versionId,
        "--controller-table-arn", parsed["--controller-table-arn"],
        "--credential-secret-arn", coordinates.credential.arn,
        "--credential-secret-version-id", coordinates.credential.versionId,
        "--expected-commit", source.sourceCommit,
        "--expected-tree", source.treeDigest,
        "--operation-id", acceptedCommand.operationId,
        "--outer-authentication-receipt-sha256",
        sha256(canonicalBytes(outerAuthentication)),
        "--outer-command-sha256", acceptedCommand.commandSha256,
        "--outer-reservation-receipt-sha256",
        sha256(canonicalBytes(reservation)),
        "--outer-reserved-at", reservation.reservedAt,
        "--outer-reservation-acknowledged-at",
        outerReservationAcknowledgedAt,
        "--provider-cluster-id", cluster.clusterId,
        "--recovery-security-receipt-sha256",
        parsed["--recovery-security-receipt-sha256"],
        "--receipt-output", primaryReceiptPath,
        "--signer-secret-arn", coordinates.signer.arn,
        "--signer-secret-version-id", coordinates.signer.versionId,
        "--sql-cluster-id", adminAuthentication.sqlClusterId
      ], environment, {
        discardAdminCredential: async () =>
          !fs.existsSync(parsed["--admin-password-file"]),
        dynamoDbRuntime,
        localCredentialDiscarded: true
      });
      requireCondition(primaryReceipt?.status === "PASS" &&
        primaryReceipt.evidence?.bootstrapReceipt?.status === "PASS",
      "FRESH_CLUSTER_RUNNER_PRIMARY_RECEIPT_REJECTED");
      return primaryReceipt.evidence.bootstrapReceipt;
    }
  });
  const receipt = await runFreshClusterProviderController({
    command,
    provider,
    runtime: execution
  });
  requireCondition(
    receipt?.status === "PROVIDER_KEYS_REVOCATION_PENDING" &&
      receipt.coreStatus === "PASS" &&
      receipt.publicDisposition === "HOLD" &&
      receipt.providerKeysRevoked === false,
    "FRESH_CLUSTER_RUNNER_PROVIDER_KEY_CEREMONY_PENDING_REJECTED"
  );
  const receiptSha256 = publishPrivateReceipt(
    parsed["--receipt-output"], receipt
  );
  process.stdout.write(
    `FRESH_CLUSTER_PROVIDER_HOLD_PROVIDER_KEYS_REVOCATION_PENDING:${receiptSha256}\n`
  );
  return receipt;
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^FRESH_CLUSTER_[A-Z0-9_]{1,120}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "FRESH_CLUSTER_RUNNER_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  APPROVED_ADOPTION,
  canonicalBytes,
  canonicalJson,
  credentialSealForDerivedApproval,
  discardPrivateFile,
  explicitAwsCredentials,
  exactSourceFileSha256,
  parseArguments,
  parseJson,
  readApprovedAdoptedAdminPassword,
  readPrivateFileRecord,
  secretCoordinates,
  sha256,
  validateApprovedAdoption,
  validateRunnerApproval,
  writePrivateNew
});
