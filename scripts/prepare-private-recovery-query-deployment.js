import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  privateRecoveryQueryApprovalSha256,
  privateRecoveryQueryOperationGlobalKeySha256,
  validatePrivateRecoveryQueryApproval
} from "../src/cloud/private-recovery-query.js";
import { privateRecoveryQueryTemplateReceipt } from
  "../src/cloud/private-recovery-query-template.js";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalJson(value));
}

function readCanonicalJson(filePath, maximumBytes, code) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximumBytes, code);
  const bytes = fs.readFileSync(resolved);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (cause) {
    reject(code, cause);
  }
  requireCondition(bytes.toString("utf8") === `${canonicalJson(value)}\n`, code);
  return value;
}

function parseArguments(args) {
  const names = [
    "--approval-file", "--artifact-bucket", "--artifact-object-version",
    "--build-receipt", "--cloudformation-service-role-arn",
    "--evidence-workflow-commit", "--github-oidc-provider-arn",
    "--mcp-secret-arn", "--mcp-secret-version-id", "--output-directory",
    "--permissions-boundary-arn", "--release-control-table-arn",
    "--sealed-workflow-commit", "--source-commit", "--teardown-workflow-commit",
    "--tree-digest"
  ];
  requireCondition(args.length === names.length * 2,
    "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_ARGUMENT_REJECTED");
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    requireCondition(names.includes(args[index]) && parsed[args[index]] === undefined &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_ARGUMENT_REJECTED");
    parsed[args[index]] = args[index + 1];
  }
  return Object.freeze(parsed);
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

export function preparePrivateRecoveryQueryDeployment({
  approval: rawApproval,
  artifactBucket,
  artifactObjectVersion,
  buildReceipt,
  cloudFormationServiceRoleArn,
  evidenceWorkflowCommit,
  githubOidcProviderArn,
  mcpSecretArn,
  mcpSecretVersionId,
  minimumRemainingMilliseconds = 15 * 60 * 1_000,
  now = new Date(),
  permissionsBoundaryArn,
  releaseControlTableArn,
  sealedWorkflowCommit,
  sourceCommit,
  teardownWorkflowCommit,
  treeDigest
}) {
  const code = "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_INPUT_REJECTED";
  requireCondition(now instanceof Date && Number.isFinite(now.getTime()) &&
    Number.isSafeInteger(minimumRemainingMilliseconds) &&
    minimumRemainingMilliseconds >= 60_000 &&
    minimumRemainingMilliseconds <= 30 * 60 * 1_000, code);
  const approval = validatePrivateRecoveryQueryApproval(rawApproval, now);
  requireCondition(Date.parse(approval.expiresAt) - now.getTime() >=
    minimumRemainingMilliseconds, code);
  requireCondition(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(
    artifactBucket ?? "") && /^[A-Za-z0-9._~-]{1,1024}$/u.test(
    artifactObjectVersion ?? "") &&
    /^arn:aws:iam::[0-9]{12}:role\/ProofToActPrivateRecoveryQueryCloudFormation$/u
      .test(cloudFormationServiceRoleArn ?? "") &&
    /^arn:aws:iam::[0-9]{12}:policy\/ProofToActPrivateRecoveryQueryBoundary$/u
      .test(permissionsBoundaryArn ?? "") &&
    /^arn:aws:iam::[0-9]{12}:oidc-provider\/token\.actions\.githubusercontent\.com$/u
      .test(githubOidcProviderArn ?? "") &&
    /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u
      .test(releaseControlTableArn ?? "") &&
    /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/private-recovery-query\/managed-mcp-[A-Za-z0-9]{6}$/u
      .test(mcpSecretArn ?? "") &&
    /^[A-Za-z0-9_-]{32,64}$/u.test(mcpSecretVersionId ?? "") &&
    [sourceCommit, treeDigest, sealedWorkflowCommit, evidenceWorkflowCommit,
      teardownWorkflowCommit].every((value) => /^[0-9a-f]{40}$/u.test(value ?? "")) &&
    sourceCommit === approval.sourceCommit && treeDigest === approval.treeDigest &&
    sha256(mcpSecretArn) === approval.mcpSecretArnSha256 &&
    sha256(mcpSecretVersionId) === approval.mcpSecretVersionIdSha256,
  code);
  requireCondition(buildReceipt?.schemaVersion ===
      "prooftoact.private-recovery-query-build-receipt.v1" &&
    buildReceipt.status === "PASS" &&
    /^[0-9a-f]{64}$/u.test(buildReceipt.artifactSha256 ?? "") &&
    /^[A-Za-z0-9+/]{43}=$/u.test(buildReceipt.artifactSha256Base64 ?? "") &&
    buildReceipt.archiveEntryCount === 2 &&
    buildReceipt.noticeSha256 === sha256(fs.readFileSync(
      new URL("../THIRD_PARTY_NOTICES.txt", import.meta.url)
    )), code);
  const templateReceipt = privateRecoveryQueryTemplateReceipt();
  requireCondition(buildReceipt.templateReceipt?.templateSha256 ===
    templateReceipt.templateSha256, code);
  const approvalSha256 = privateRecoveryQueryApprovalSha256(approval);
  const operationGlobalKeySha256 =
    privateRecoveryQueryOperationGlobalKeySha256(approval);
  const artifactKey =
    `private-recovery-query/${sourceCommit}/` +
    `private-recovery-query-${buildReceipt.artifactSha256}.zip`;
  const configRecord = Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-config.v1",
    approvalSha256,
    codeZipSha256: buildReceipt.artifactSha256,
    cloudFormationServiceRoleArnSha256: sha256(cloudFormationServiceRoleArn),
    evidenceWorkflowCommit,
    githubOidcProviderArnSha256: sha256(githubOidcProviderArn),
    mcpSecretArnSha256: approval.mcpSecretArnSha256,
    mcpSecretVersionIdSha256: approval.mcpSecretVersionIdSha256,
    operationGlobalKeySha256,
    permissionsBoundaryArnSha256: sha256(permissionsBoundaryArn),
    releaseControlTableArnSha256: sha256(releaseControlTableArn),
    sealedWorkflowCommit,
    sourceCommit,
    teardownWorkflowCommit,
    templateSha256: templateReceipt.templateSha256,
    treeDigest
  });
  const configSha256 = digest(configRecord);
  const parameters = Object.entries({
    ApprovalSha256: approvalSha256,
    ArtifactBucketName: artifactBucket,
    ArtifactKey: artifactKey,
    ArtifactObjectVersion: artifactObjectVersion,
    CloudFormationServiceRoleArn: cloudFormationServiceRoleArn,
    CodeSha256Base64: buildReceipt.artifactSha256Base64,
    CodeZipSha256: buildReceipt.artifactSha256,
    ConfigSha256: configSha256,
    EvidenceWorkflowCommit: evidenceWorkflowCommit,
    GitHubOidcProviderArn: githubOidcProviderArn,
    McpSecretArn: mcpSecretArn,
    McpSecretVersionId: mcpSecretVersionId,
    OperationGlobalKeySha256: operationGlobalKeySha256,
    PermissionsBoundaryArn: permissionsBoundaryArn,
    ReleaseControlTableArn: releaseControlTableArn,
    SealedWorkflowCommit: sealedWorkflowCommit,
    SourceCommit: sourceCommit,
    TeardownWorkflowCommit: teardownWorkflowCommit,
    TemplateSha256: templateReceipt.templateSha256,
    TreeDigest: treeDigest
  }).map(([ParameterKey, ParameterValue]) => ({
    ParameterKey,
    ParameterValue,
    UsePreviousValue: false
  }));
  const privateInput = Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-deployment-private-input.v1",
    artifactBucket,
    artifactKey,
    artifactObjectVersion,
    cloudFormationServiceRoleArn,
    configRecord,
    configSha256,
    mcpSecretArn,
    mcpSecretVersionId,
    parameters
  });
  const intentBody = Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-deployment-intent.v1",
    status: "READY_FOR_CREATE_CHANGE_SET",
    approvalSha256,
    artifactBucketSha256: sha256(artifactBucket),
    artifactKeySha256: sha256(artifactKey),
    artifactObjectVersionSha256: sha256(artifactObjectVersion),
    codeSha256Base64: buildReceipt.artifactSha256Base64,
    codeZipSha256: buildReceipt.artifactSha256,
    configSha256,
    operationGlobalKeySha256,
    sourceCommit,
    templateSha256: templateReceipt.templateSha256,
    treeDigest
  });
  return Object.freeze({
    privateInput,
    sanitizedIntent: Object.freeze({
      ...intentBody,
      intentSha256: digest(intentBody)
    })
  });
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  const output = path.resolve(parsed["--output-directory"]);
  requireCondition(!fs.existsSync(output),
    "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_OUTPUT_REJECTED");
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  const prepared = preparePrivateRecoveryQueryDeployment({
    approval: readCanonicalJson(parsed["--approval-file"], 64 * 1024,
      "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_INPUT_REJECTED"),
    artifactBucket: parsed["--artifact-bucket"],
    artifactObjectVersion: parsed["--artifact-object-version"],
    buildReceipt: readCanonicalJson(parsed["--build-receipt"], 64 * 1024,
      "PRIVATE_RECOVERY_QUERY_DEPLOYMENT_INPUT_REJECTED"),
    cloudFormationServiceRoleArn: parsed["--cloudformation-service-role-arn"],
    evidenceWorkflowCommit: parsed["--evidence-workflow-commit"],
    githubOidcProviderArn: parsed["--github-oidc-provider-arn"],
    mcpSecretArn: parsed["--mcp-secret-arn"],
    mcpSecretVersionId: parsed["--mcp-secret-version-id"],
    permissionsBoundaryArn: parsed["--permissions-boundary-arn"],
    releaseControlTableArn: parsed["--release-control-table-arn"],
    sealedWorkflowCommit: parsed["--sealed-workflow-commit"],
    sourceCommit: parsed["--source-commit"],
    teardownWorkflowCommit: parsed["--teardown-workflow-commit"],
    treeDigest: parsed["--tree-digest"]
  });
  writeExclusive(path.join(output, "private-input.json"), prepared.privateInput);
  writeExclusive(path.join(output, "parameters.json"),
    prepared.privateInput.parameters);
  writeExclusive(path.join(output, "sanitized-deployment-intent.json"),
    prepared.sanitizedIntent);
  process.stdout.write(
    `PRIVATE_RECOVERY_QUERY_DEPLOYMENT_READY:${prepared.sanitizedIntent.intentSha256}\n`
  );
  return prepared;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch(() => {
    process.stderr.write("PRIVATE_RECOVERY_QUERY_DEPLOYMENT_CLI_HOLD\n");
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  digest,
  parseArguments,
  sha256
});
