import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TEMPLATE_PATH =
  "infra/aws/fresh-primary-credential-custody-stack.json";
const TEMPLATE_SHA256 =
  "0d23509291626d7e3d91d1454e581e36bb6721166e84747791ce5a3c7d6bb474";
const REGION = "us-east-1";
const ACCOUNT = /^[0-9]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const WRITER_PATH = "/prooftoact/bootstrap/";

const SECRET_LOGICAL_IDS = Object.freeze({
  admin: "FreshPrimaryAdminSecret",
  auditor: "FreshClusterAuditorSecret",
  cloudApi: "FreshPrimaryCloudApiSecret",
  credential: "FreshPrimaryRuntimeCredentialsSecret",
  mcp: "ManagedMcpSecret",
  publisher: "RecoveryPublisherSecret",
  signer: "FreshPrimaryRecoverySignerSecret"
});

function reject(code) {
  throw new Error(code);
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
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
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

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function domainDigest(domain, fields) {
  return sha256(Buffer.from(`${domain}\n${fields.join("\n")}\n`, "utf8"));
}

export function freshPrimaryCredentialOperationToken(operationId) {
  requireCondition(UUID.test(operationId ?? ""),
    "FRESH_CREDENTIAL_OPERATION_TOKEN_REJECTED");
  return domainDigest(
    "prooftoact-fresh-primary-credential-writer-v1",
    [operationId]
  ).slice(0, 16);
}

function names(operationId) {
  return Object.freeze({
    admin: `prooftoact/fresh-primary/admin-${operationId}`,
    auditor: "prooftoact/fresh-cluster/auditor",
    cloudApi: "prooftoact/fresh-primary/cloud-api",
    credential: "prooftoact/fresh-primary/runtime-credentials",
    mcp: "prooftoact/gate2/managed-mcp",
    publisher: "prooftoact/gate2/recovery-publisher",
    signer: `prooftoact/fresh-primary/recovery-signer-${operationId}`
  });
}

function readReviewedTemplate() {
  const bytes = fs.readFileSync(path.join(ROOT, TEMPLATE_PATH));
  requireCondition(sha256(bytes) === TEMPLATE_SHA256,
    "FRESH_CREDENTIAL_TEMPLATE_DIGEST_REJECTED");
  const template = JSON.parse(bytes.toString("utf8"));
  requireCondition(exactKeys(template.Resources, [
    ...Object.values(SECRET_LOGICAL_IDS),
    "FreshPrimaryCredentialWriterRole"
  ]) && exactKeys(template.Parameters, [
    "BootstrapCreatorRoleArn",
    "CredentialSealExternalId",
    "OperationId",
    "OperationToken",
    "OperatorAuthorizationSha256",
    "SourceCommit",
    "TemplateSha256",
    "TreeDigest"
  ]) && Object.values(SECRET_LOGICAL_IDS).every((logicalId) =>
    template.Resources[logicalId]?.Type === "AWS::SecretsManager::Secret") &&
    template.Resources.FreshPrimaryCredentialWriterRole?.Type ===
      "AWS::IAM::Role",
  "FRESH_CREDENTIAL_TEMPLATE_CONTRACT_REJECTED");
  return Object.freeze({ bytes, template });
}

function secretArnPatterns(accountId, operationId) {
  const prefix = `arn:aws:secretsmanager:${REGION}:${accountId}:secret:`;
  return Object.fromEntries(Object.entries(names(operationId)).map(
    ([key, name]) => [key, `${prefix}${name}-??????`]
  ));
}

export function prepareFreshPrimaryCredentialCustody({
  accountId,
  operationId,
  operatorAuthorizationSha256,
  sourceCommit,
  treeDigest
}) {
  const code = "FRESH_CREDENTIAL_PREPARE_REJECTED";
  requireCondition(ACCOUNT.test(accountId ?? "") &&
    UUID.test(operationId ?? "") && HEX_40.test(sourceCommit ?? "") &&
    HEX_40.test(treeDigest ?? "") &&
    HEX_64.test(operatorAuthorizationSha256 ?? ""), code);
  const reviewed = readReviewedTemplate();
  const operationToken = freshPrimaryCredentialOperationToken(operationId);
  const bootstrapCreatorRoleName =
    `ProofToActBootstrapCreator-${operationToken}`;
  const bootstrapCreatorRoleArn = `arn:aws:iam::${accountId}:role` +
    `${WRITER_PATH}${bootstrapCreatorRoleName}`;
  const writerRoleName = `ProofToActFreshCredentialWriter-${operationToken}`;
  const writerRoleArn = `arn:aws:iam::${accountId}:role` +
    `${WRITER_PATH}${writerRoleName}`;
  const stackName =
    `prooftoact-fresh-primary-credential-custody-${operationId}`;
  const credentialSealExternalId = domainDigest(
    "prooftoact-fresh-primary-credential-seal-external-id-v1",
    [
      accountId,
      operationId,
      operationToken,
      operatorAuthorizationSha256,
      sourceCommit,
      treeDigest,
      TEMPLATE_SHA256
    ]
  );
  const secretNames = names(operationId);
  const plan = {
    schemaVersion: "prooftoact.fresh-primary-credential-custody-plan.v1",
    status: "READY_FOR_EXACT_CREATE_ONLY_APPLY",
    accountId,
    bootstrapCreatorRoleArn,
    capabilities: ["CAPABILITY_NAMED_IAM"],
    cloudFormationServiceRoleArn: null,
    createOnly: true,
    credentialSealExternalId,
    expectedOutputKeys: [
      "AdminSecretArn",
      "AuditorSecretArn",
      "CloudApiSecretArn",
      "ManagedMcpSecretArn",
      "RecoveryPublisherSecretArn",
      "RuntimeCredentialsSecretArn",
      "SignerSecretArn",
      "WriterRoleArn"
    ],
    expectedResourceCount: 8,
    initialVersionContract: {
      admin: 0,
      auditor: 0,
      cloudApi: 0,
      credential: 0,
      mcp: 0,
      publisher: 0,
      signer: 0
    },
    onFailure: "DELETE",
    operationId,
    operationToken,
    operatorAuthorizationSha256,
    parameters: {
      BootstrapCreatorRoleArn: bootstrapCreatorRoleArn,
      CredentialSealExternalId: credentialSealExternalId,
      OperationId: operationId,
      OperationToken: operationToken,
      OperatorAuthorizationSha256: operatorAuthorizationSha256,
      SourceCommit: sourceCommit,
      TemplateSha256: TEMPLATE_SHA256,
      TreeDigest: treeDigest
    },
    region: REGION,
    requiredBootstrapAuthority: {
      cloudFormationActions: [
        "cloudformation:CreateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
        "cloudformation:ListStackResources",
        "cloudformation:UpdateTerminationProtection"
      ],
      cloudFormationCreateResource: "*",
      cloudFormationStackResource:
        `arn:aws:cloudformation:${REGION}:${accountId}:stack/${stackName}/*`,
      iamActions: [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:PutRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRoleDescription"
      ],
      iamResource: writerRoleArn,
      secretActions: [
        "secretsmanager:CreateSecret",
        "secretsmanager:DeleteSecret",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:TagResource",
        "secretsmanager:UntagResource"
      ],
      secretResources: Object.values(secretArnPatterns(accountId, operationId)),
      valueActionsExplicitlyAbsent: [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue"
      ],
      writerAssumeActions: ["sts:AssumeRole"],
      writerAssumeResource: writerRoleArn
    },
    requiredStackTags: {
      OperationId: operationId,
      Project: "ProofToAct"
    },
    secretArnPatterns: secretArnPatterns(accountId, operationId),
    secretNames,
    sourceCommit,
    stackName,
    templateBytes: reviewed.bytes.length,
    templatePath: TEMPLATE_PATH,
    templateSha256: TEMPLATE_SHA256,
    terminationProtection: true,
    treeDigest,
    updateAllowed: false,
    writerRoleArn,
    writerRoleName,
    writerRolePath: WRITER_PATH,
    writerSessionName: `prooftoact-credential-seal-${operationToken}`,
    writerTargets: ["auditor", "cloudApi", "credential", "mcp", "publisher"],
    runtimeGeneratedTargets: ["admin", "signer"]
  };
  return Object.freeze({ ...plan, planSha256: digest(plan) });
}

export function verifyFreshPrimaryCredentialCustodyPlan(value) {
  const rebuilt = prepareFreshPrimaryCredentialCustody({
    accountId: value?.accountId,
    operationId: value?.operationId,
    operatorAuthorizationSha256: value?.operatorAuthorizationSha256,
    sourceCommit: value?.sourceCommit,
    treeDigest: value?.treeDigest
  });
  requireCondition(canonicalJson(rebuilt) === canonicalJson(value),
    "FRESH_CREDENTIAL_PLAN_REJECTED");
  return rebuilt;
}

function main(argv) {
  requireCondition(argv.length === 5, "FRESH_CREDENTIAL_USAGE_REJECTED");
  process.stdout.write(`${JSON.stringify(prepareFreshPrimaryCredentialCustody({
    accountId: argv[0],
    operationId: argv[1],
    operatorAuthorizationSha256: argv[2],
    sourceCommit: argv[3],
    treeDigest: argv[4]
  }), null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) ===
  fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (cause) {
    process.stderr.write(`${cause?.message ?? "FRESH_CREDENTIAL_FAILED"}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({
  SECRET_LOGICAL_IDS,
  TEMPLATE_PATH,
  TEMPLATE_SHA256,
  WRITER_PATH,
  canonicalJson,
  digest,
  domainDigest,
  names,
  readReviewedTemplate,
  secretArnPatterns
});
