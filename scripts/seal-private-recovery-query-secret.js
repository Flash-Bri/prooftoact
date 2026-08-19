import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  DescribeSecretCommand,
  GetSecretValueCommand,
  ListSecretVersionIdsCommand,
  PutSecretValueCommand,
  SecretsManagerClient
} from "@aws-sdk/client-secrets-manager";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { validatePrivateRecoveryQueryMcpSecretBinding } from
  "./generate-private-recovery-query-approval.js";

const SOURCE_SECRET_ARN =
  /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/gate2\/managed-mcp-[A-Za-z0-9]{6}$/u;
const TARGET_SECRET_ARN =
  /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/private-recovery-query\/managed-mcp-[A-Za-z0-9]{6}$/u;
const VERSION_ID = /^[A-Za-z0-9_-]{32,64}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SEAL_APPROVAL_SCHEMA =
  "prooftoact.private-recovery-query-secret-seal-approval.v1";
const SHARING_BOUNDARY =
  "SAME_READ_ONLY_MANAGED_MCP_PROVIDER_KEY_TWO_ISOLATED_AWS_SECRETS";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function lineDigest(value) {
  return sha256(`${canonicalJson(value)}\n`);
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

function requireTimestamp(value, code) {
  const milliseconds = Date.parse(value ?? "");
  requireCondition(typeof value === "string" && value.length <= 64 &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

export function validatePrivateRecoveryQuerySecretSealApproval(value,
  now = null) {
  const code = "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_APPROVAL_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalSha256", "approvedAt", "credentialSharingBoundary", "expiresAt",
    "operatorAuthorizationSha256", "schemaVersion", "sourceCommit",
    "sourceSecretArnSha256", "sourceSecretVersionIdSha256", "status",
    "targetSecretArnSha256", "treeDigest"
  ]) && value.schemaVersion === SEAL_APPROVAL_SCHEMA &&
    value.status === "APPROVED_EXACT_SHARED_READ_ONLY_CREDENTIAL_COPY" &&
    value.credentialSharingBoundary === SHARING_BOUNDARY &&
    HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    [value.approvalSha256, value.operatorAuthorizationSha256,
      value.sourceSecretArnSha256, value.sourceSecretVersionIdSha256,
      value.targetSecretArnSha256].every((item) => HEX_64.test(item ?? "")),
  code);
  const approvedAt = requireTimestamp(value.approvedAt, code);
  const expiresAt = requireTimestamp(value.expiresAt, code);
  requireCondition(expiresAt > approvedAt &&
    expiresAt - approvedAt <= 24 * 60 * 60 * 1_000, code);
  const { approvalSha256, ...body } = value;
  requireCondition(approvalSha256 === lineDigest(body), code);
  if (now !== null) {
    requireCondition(now instanceof Date && Number.isFinite(now.getTime()) &&
      now.getTime() >= approvedAt - 60_000 && now.getTime() < expiresAt, code);
  }
  return Object.freeze({ ...value });
}

function explicitCredentials(environment) {
  const value = Object.freeze({
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  });
  requireCondition(/^ASIA[A-Z0-9]{16}$/u.test(value.accessKeyId ?? "") &&
    typeof value.secretAccessKey === "string" &&
    value.secretAccessKey.length === 40 &&
    typeof value.sessionToken === "string" && value.sessionToken.length >= 16,
  "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_CREDENTIALS_REJECTED");
  return value;
}

function sdkOptions(credentials) {
  return {
    authSchemePreference: ["sigv4"],
    credentials,
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    region: "us-east-1",
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 15_000
    }),
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
}

function parseArguments(args) {
  const names = [
    "--approval-file", "--binding-output", "--receipt-output", "--source-commit",
    "--source-secret-arn", "--source-secret-version-id",
    "--target-secret-arn", "--tree-digest"
  ];
  requireCondition(args.length === names.length * 2,
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_ARGUMENT_REJECTED");
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    requireCondition(names.includes(args[index]) &&
      parsed[args[index]] === undefined &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_ARGUMENT_REJECTED");
    parsed[args[index]] = args[index + 1];
  }
  requireCondition(SOURCE_SECRET_ARN.test(parsed["--source-secret-arn"]) &&
    TARGET_SECRET_ARN.test(parsed["--target-secret-arn"]) &&
    VERSION_ID.test(parsed["--source-secret-version-id"]) &&
    HEX_40.test(parsed["--source-commit"]) &&
    HEX_40.test(parsed["--tree-digest"]),
  "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_ARGUMENT_REJECTED");
  return Object.freeze(parsed);
}

function writeExclusive(filePath, value) {
  const resolved = path.resolve(filePath);
  requireCondition(!fs.existsSync(resolved),
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_OUTPUT_REJECTED");
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const descriptor = fs.openSync(resolved,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, `${canonicalJson(value)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
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

function validateDescription(value, expectedArn, expectedName, code) {
  requireCondition(value?.ARN === expectedArn && value.Name === expectedName &&
    value.DeletedDate === undefined && value.RotationEnabled === false &&
    value.OwningService === undefined &&
    (value.ReplicationStatus === undefined || value.ReplicationStatus.length === 0),
  code);
}

function requireUnpaginatedVersionList(value, code) {
  requireCondition(Array.isArray(value?.Versions) &&
    value.NextToken === undefined, code);
  return value.Versions;
}

function requireExactSecretVersion(value, coordinate, code) {
  requireCondition(value?.ARN === coordinate.arn &&
    value.Name === coordinate.name &&
    value.VersionId === coordinate.versionId &&
    Array.isArray(value.VersionStages) &&
    value.VersionStages.length === 1 &&
    value.VersionStages[0] === "AWSCURRENT" &&
    typeof value.SecretString === "string" &&
    value.SecretBinary === undefined &&
    value.CreatedDate instanceof Date &&
    Number.isFinite(value.CreatedDate.getTime()), code);
  return value.SecretString;
}

function versionIdFor({ sourceCommit, sourceSecretArn, sourceSecretVersionId,
  targetSecretArn, treeDigest, sealApprovalSha256 }) {
  return sha256(canonicalJson({
    purpose: "PRIVATE_RECOVERY_QUERY_MCP_SECRET_SEAL",
    sourceCommit,
    sourceSecretArnSha256: sha256(sourceSecretArn),
    sourceSecretVersionIdSha256: sha256(sourceSecretVersionId),
    targetSecretArnSha256: sha256(targetSecretArn),
    sealApprovalSha256,
    treeDigest
  }));
}

export async function sealPrivateRecoveryQuerySecret({
  clients,
  approval: rawApproval,
  clock = () => new Date(),
  sourceCommit,
  sourceSecretArn,
  sourceSecretVersionId,
  targetSecretArn,
  treeDigest
}) {
  const code = "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_REJECTED";
  requireCondition(clients?.secrets && clients?.sts &&
    typeof clients.secrets.send === "function" &&
    typeof clients.sts.send === "function" &&
    SOURCE_SECRET_ARN.test(sourceSecretArn ?? "") &&
    TARGET_SECRET_ARN.test(targetSecretArn ?? "") &&
    VERSION_ID.test(sourceSecretVersionId ?? "") &&
    HEX_40.test(sourceCommit ?? "") && HEX_40.test(treeDigest ?? "") &&
    sourceSecretArn !== targetSecretArn, code);
  const authorizationTime = clock();
  const approval = validatePrivateRecoveryQuerySecretSealApproval(
    rawApproval, authorizationTime
  );
  requireCondition(approval.sourceCommit === sourceCommit &&
    approval.treeDigest === treeDigest &&
    approval.sourceSecretArnSha256 === sha256(sourceSecretArn) &&
    approval.sourceSecretVersionIdSha256 === sha256(sourceSecretVersionId) &&
    approval.targetSecretArnSha256 === sha256(targetSecretArn), code);
  const sourceName = "prooftoact/gate2/managed-mcp";
  const targetName = "prooftoact/private-recovery-query/managed-mcp";
  const targetVersionId = versionIdFor({
    sourceCommit,
    sourceSecretArn,
    sourceSecretVersionId,
    targetSecretArn,
    treeDigest,
    sealApprovalSha256: approval.approvalSha256
  });
  const [identity, sourceDescription, sourceVersions, sourceReadback,
    targetDescription, targetVersionsBefore] = await Promise.all([
    clients.sts.send(new GetCallerIdentityCommand({})),
    clients.secrets.send(new DescribeSecretCommand({
      SecretId: sourceSecretArn
    })),
    clients.secrets.send(new ListSecretVersionIdsCommand({
      SecretId: sourceSecretArn,
      IncludeDeprecated: true,
      MaxResults: 100
    })),
    clients.secrets.send(new GetSecretValueCommand({
      SecretId: sourceSecretArn,
      VersionId: sourceSecretVersionId,
      VersionStage: "AWSCURRENT"
    })),
    clients.secrets.send(new DescribeSecretCommand({
      SecretId: targetSecretArn
    })),
    clients.secrets.send(new ListSecretVersionIdsCommand({
      SecretId: targetSecretArn,
      IncludeDeprecated: true,
      MaxResults: 100
    }))
  ]);
  requireCondition(/^[0-9]{12}$/u.test(identity?.Account ?? "") &&
    new RegExp(`^arn:aws:sts::${identity.Account}:assumed-role/` +
      "ProofToActPrivateRecoveryQuerySecretSealer/" +
      "[A-Za-z0-9+=,.@_-]{1,64}$", "u").test(identity.Arn ?? "") &&
    typeof identity.UserId === "string" && identity.UserId.length >= 16,
  "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_IDENTITY_REJECTED");
  validateDescription(sourceDescription, sourceSecretArn, sourceName, code);
  validateDescription(targetDescription, targetSecretArn, targetName, code);
  const sourceVersionList = requireUnpaginatedVersionList(sourceVersions, code);
  requireCondition(sourceVersionList.some((version) =>
    version.VersionId === sourceSecretVersionId &&
    Array.isArray(version.VersionStages) &&
    version.VersionStages.includes("AWSCURRENT")), code);
  const sourceApiKey = requireExactSecretVersion(sourceReadback, {
    arn: sourceSecretArn,
    name: sourceName,
    versionId: sourceSecretVersionId
  }, code);
  requireCondition(sourceApiKey.length >= 24 && sourceApiKey.length <= 4096 &&
    !/[\u0000-\u0020\u007f]/u.test(sourceApiKey), code);
  const targetSecretString = canonicalJson({ apiKey: sourceApiKey });
  const before = requireUnpaginatedVersionList(targetVersionsBefore, code);
  requireCondition(before.length === 0 ||
    (before.length === 1 && before[0]?.VersionId === targetVersionId &&
      Array.isArray(before[0].VersionStages) &&
      before[0].VersionStages.length === 1 &&
      before[0].VersionStages[0] === "AWSCURRENT"), code);
  let disposition = "EXACT_VERSION_ALREADY_PRESENT";
  if (before.length === 0) {
    disposition = "SEALED";
    try {
      await clients.secrets.send(new PutSecretValueCommand({
        ClientRequestToken: targetVersionId,
        SecretId: targetSecretArn,
        SecretString: targetSecretString,
        VersionStages: ["AWSCURRENT"]
      }));
    } catch (cause) {
      disposition = "RECONCILED_AFTER_ACK_LOSS";
    }
  }
  let targetReadback;
  try {
    targetReadback = await clients.secrets.send(new GetSecretValueCommand({
      SecretId: targetSecretArn,
      VersionId: targetVersionId,
      VersionStage: "AWSCURRENT"
    }));
  } catch (cause) {
    reject("PRIVATE_RECOVERY_QUERY_SECRET_SEAL_UNKNOWN_DO_NOT_RETRY", cause);
  }
  const targetValue = requireExactSecretVersion(targetReadback, {
    arn: targetSecretArn,
    name: targetName,
    versionId: targetVersionId
  }, "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_READBACK_REJECTED");
  requireCondition(targetValue === targetSecretString,
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_READBACK_REJECTED");
  const targetVersionsAfter = requireUnpaginatedVersionList(
    await clients.secrets.send(new ListSecretVersionIdsCommand({
      SecretId: targetSecretArn,
      IncludeDeprecated: true,
      MaxResults: 100
    })),
    "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_READBACK_REJECTED"
  );
  requireCondition(targetVersionsAfter.length === 1 &&
    targetVersionsAfter[0]?.VersionId === targetVersionId &&
    Array.isArray(targetVersionsAfter[0].VersionStages) &&
    targetVersionsAfter[0].VersionStages.length === 1 &&
    targetVersionsAfter[0].VersionStages[0] === "AWSCURRENT",
  "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_READBACK_REJECTED");
  const observedAt = clock();
  requireCondition(observedAt instanceof Date &&
    Number.isFinite(observedAt.getTime()) &&
    observedAt.getTime() >= targetReadback.CreatedDate.getTime(), code);
  const bindingBody = Object.freeze({
    schemaVersion:
      "prooftoact.private-recovery-query-mcp-secret-binding.v1",
    status: "IMMUTABLE_AWSCURRENT_READBACK_BOUND",
    mcpSecretArnSha256: sha256(targetSecretArn),
    mcpSecretValueSha256: sha256(targetSecretString),
    mcpSecretVersionIdSha256: sha256(targetVersionId),
    observedAt: observedAt.toISOString(),
    credentialSharingBoundary: SHARING_BOUNDARY,
    operatorAuthorizationSha256: approval.operatorAuthorizationSha256,
    sealApprovalSha256: approval.approvalSha256,
    sourceCommit,
    sourceSecretArnSha256: sha256(sourceSecretArn),
    sourceSecretValueSha256: sha256(sourceApiKey),
    sourceSecretVersionIdSha256: sha256(sourceSecretVersionId),
    treeDigest
  });
  const binding = validatePrivateRecoveryQueryMcpSecretBinding(Object.freeze({
    ...bindingBody,
    bindingSha256: lineDigest(bindingBody)
  }));
  const receiptBody = Object.freeze({
    schemaVersion:
      "prooftoact.private-recovery-query-secret-seal-receipt.v1",
    status: "PASS",
    accountIdSha256: sha256(identity.Account),
    bindingSha256: binding.bindingSha256,
    callerArnSha256: sha256(identity.Arn),
    callerUserIdSha256: sha256(identity.UserId),
    credentialSharingBoundary: SHARING_BOUNDARY,
    disposition,
    operatorAuthorizationSha256: approval.operatorAuthorizationSha256,
    sealApprovalSha256: approval.approvalSha256,
    sourceCommit,
    targetVersionCreatedAt: targetReadback.CreatedDate.toISOString(),
    treeDigest
  });
  return Object.freeze({
    binding,
    receipt: Object.freeze({
      ...receiptBody,
      receiptSha256: lineDigest(receiptBody)
    })
  });
}

export async function main(args = process.argv.slice(2),
  environment = process.env) {
  const parsed = parseArguments(args);
  requireCondition(environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1",
  "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_ENVIRONMENT_REJECTED");
  const options = sdkOptions(explicitCredentials(environment));
  const sealed = await sealPrivateRecoveryQuerySecret({
    approval: readCanonicalJson(parsed["--approval-file"], 64 * 1024,
      "PRIVATE_RECOVERY_QUERY_SECRET_SEAL_APPROVAL_REJECTED"),
    clients: {
      secrets: new SecretsManagerClient(options),
      sts: new STSClient(options)
    },
    sourceCommit: parsed["--source-commit"],
    sourceSecretArn: parsed["--source-secret-arn"],
    sourceSecretVersionId: parsed["--source-secret-version-id"],
    targetSecretArn: parsed["--target-secret-arn"],
    treeDigest: parsed["--tree-digest"]
  });
  writeExclusive(parsed["--binding-output"], sealed.binding);
  writeExclusive(parsed["--receipt-output"], sealed.receipt);
  process.stdout.write(
    `PRIVATE_RECOVERY_QUERY_SECRET_SEAL_PASS:${sealed.receipt.receiptSha256}\n`
  );
  return sealed;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch(() => {
    process.stderr.write("PRIVATE_RECOVERY_QUERY_SECRET_SEAL_CLI_HOLD\n");
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  SEAL_APPROVAL_SCHEMA,
  SHARING_BOUNDARY,
  explicitCredentials,
  lineDigest,
  parseArguments,
  sdkOptions,
  sha256,
  versionIdFor
});
