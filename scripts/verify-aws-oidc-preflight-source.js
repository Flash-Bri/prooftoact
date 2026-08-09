import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const IDENTITY_WORKFLOW_PATH =
  ".github/workflows/aws-oidc-identity-bootstrap.yml";
const READ_ONLY_WORKFLOW_PATH =
  ".github/workflows/aws-oidc-read-only-preflight.yml";
const READ_ONLY_RUNNER_PATH =
  "scripts/run-aws-oidc-read-only-preflight.sh";
const ROLE_TEMPLATE_PATH =
  "infra/aws/oidc-read-only-preflight-role-template.json";
const PREFLIGHT_RUNNER_PATH = "scripts/gate2-aws-preflight.js";
const PREFLIGHT_VALIDATOR_PATH = "src/cloud/aws-gate2-preflight.js";
const LEDGER_PATH = "docs/AWS_OIDC_PREFLIGHT.md";
const RECEIPT_SCHEMA =
  "prooftoact.aws-oidc-preflight-source-verification.v2";
const RECEIPT_STATUS =
  "SOURCE_CONTRACT_PASS_PROVIDER_SETUP_AND_EXECUTION_PENDING";
const HEX_64 = /^[0-9a-f]{64}$/;
const EXACT_RECEIPT_SECRET_PATTERN =
  "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$";

const EXACT_READ_ACTIONS = Object.freeze([
  "account:GetRegionOptStatus",
  "bedrock:GetFoundationModel",
  "budgets:ViewBudget",
  "ce:GetCostAndUsage",
  "cloudformation:DescribeStacks",
  "cloudformation:ListStacks",
  "s3:GetBucketOwnershipControls",
  "s3:GetBucketPolicy",
  "s3:GetBucketPolicyStatus",
  "s3:GetBucketPublicAccessBlock",
  "s3:GetBucketVersioning",
  "s3:GetEncryptionConfiguration",
  "servicequotas:ListServiceQuotas",
  "sts:GetCallerIdentity"
]);

const EXACT_PREFLIGHT_RUNTIME_CALL_INVENTORY = Object.freeze([
  Object.freeze(["sts", "get-caller-identity", 1]),
  Object.freeze(["cloudformation", "describe-stacks", 1]),
  Object.freeze(["budgets", "describe-budget", 1]),
  Object.freeze(["budgets", "describe-notifications-for-budget", 1]),
  Object.freeze(["budgets", "describe-subscribers-for-notification", 4]),
  Object.freeze(["ce", "get-cost-and-usage", 1]),
  Object.freeze(["s3api", "get-bucket-versioning", 1]),
  Object.freeze(["s3api", "get-bucket-encryption", 1]),
  Object.freeze(["s3api", "get-public-access-block", 1]),
  Object.freeze(["s3api", "get-bucket-ownership-controls", 1]),
  Object.freeze(["s3api", "get-bucket-policy-status", 1]),
  Object.freeze(["s3api", "get-bucket-policy", 1]),
  Object.freeze(["cloudformation", "list-stacks", 1]),
  Object.freeze(["bedrock", "get-foundation-model", 1])
]);

const EXACT_PREFLIGHT_RUNTIME_CALL_COUNT =
  EXACT_PREFLIGHT_RUNTIME_CALL_INVENTORY.reduce(
    (total, entry) => total + entry[2],
    0
  );

const EXPECTED_ROLE_STATEMENT_SIDS = Object.freeze([
  "ReadCallerIdentity",
  "ReadBootstrapStack",
  "ReadStackCensus",
  "ReadAccountBudget",
  "ReadAccountCost",
  "ReadArtifactBucketControls",
  "ReadFoundationModelMetadata",
  "ReadBedrockQuotaCensus",
  "ReadRegionStatus",
  "DenyEverythingExceptExactPreflightReads"
]);

const EXPECTED_IDENTITY_ACTION_PINS = Object.freeze([
  "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
]);

const EXPECTED_IDENTITY_FAILURE_STAGES = Object.freeze([
  "AWS_IDENTITY_STAGE_STS_ASSUME_REQUEST",
  "AWS_IDENTITY_STAGE_STS_ASSUME_RECEIPT",
  "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
  "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
  "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
  "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
  "AWS_IDENTITY_STAGE_STS_CALLER_REQUEST",
  "AWS_IDENTITY_STAGE_STS_CALLER_RECEIPT",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION",
  "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT",
  "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP"
]);

const EXPECTED_IDENTITY_FAILURE_STAGE_ALLOWLIST = Object.freeze([
  "AWS_IDENTITY_STAGE_STS_ASSUME_REQUEST",
  "AWS_IDENTITY_STAGE_STS_ASSUME_RECEIPT",
  "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
  "AWS_IDENTITY_STAGE_STS_CALLER_REQUEST",
  "AWS_IDENTITY_STAGE_STS_CALLER_RECEIPT",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
  "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT"
]);

const EXPECTED_IDENTITY_FAILURE_STAGE_FUNCTION = [
  "fail_closed_stage() {",
  'local stage="\${1:-}"',
  'case "$stage" in',
  "AWS_IDENTITY_STAGE_STS_ASSUME_REQUEST | \\",
  "AWS_IDENTITY_STAGE_STS_ASSUME_RECEIPT | \\",
  "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS | \\",
  "AWS_IDENTITY_STAGE_STS_CALLER_REQUEST | \\",
  "AWS_IDENTITY_STAGE_STS_CALLER_RECEIPT | \\",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE | \\",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION | \\",
  "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP | \\",
  "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT) ;;",
  "*) fail_closed ;;",
  "esac",
  'printf \'%s\\n\' "::error::\${stage}" >&2',
  "exit 1",
  "}"
].join("\n");

const EXPECTED_READ_ONLY_FAILURE_STAGE_ALLOWLIST = Object.freeze([
  "AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT",
  "AWS_READ_ONLY_STAGE_INHERITED_ENVIRONMENT",
  "AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY",
  "AWS_READ_ONLY_STAGE_OIDC_ENDPOINT",
  "AWS_READ_ONLY_STAGE_SOURCE_BINDING",
  "AWS_READ_ONLY_STAGE_NODE_DISCOVERY",
  "AWS_READ_ONLY_STAGE_NODE_PATH",
  "AWS_READ_ONLY_STAGE_NODE_OWNER",
  "AWS_READ_ONLY_STAGE_NODE_METADATA",
  "AWS_READ_ONLY_STAGE_NODE_INTEGRITY",
  "AWS_READ_ONLY_STAGE_NODE_VERSION",
  "AWS_READ_ONLY_STAGE_AWS_PATH",
  "AWS_READ_ONLY_STAGE_AWS_METADATA",
  "AWS_READ_ONLY_STAGE_GPG_METADATA",
  "AWS_READ_ONLY_STAGE_TEMPORARY_STATE",
  "AWS_READ_ONLY_STAGE_OIDC_REQUEST",
  "AWS_READ_ONLY_STAGE_OIDC_RECEIPT",
  "AWS_READ_ONLY_STAGE_OIDC_CLAIMS"
]);

const EXPECTED_READ_ONLY_FAILURE_STAGE_FUNCTION = [
  "fail_closed_stage() {",
  'local stage="\${1:-}"',
  'case "$stage" in',
  "AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT | \\",
  "AWS_READ_ONLY_STAGE_INHERITED_ENVIRONMENT | \\",
  "AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY | \\",
  "AWS_READ_ONLY_STAGE_OIDC_ENDPOINT | \\",
  "AWS_READ_ONLY_STAGE_SOURCE_BINDING | \\",
  "AWS_READ_ONLY_STAGE_NODE_DISCOVERY | \\",
  "AWS_READ_ONLY_STAGE_NODE_PATH | \\",
  "AWS_READ_ONLY_STAGE_NODE_OWNER | \\",
  "AWS_READ_ONLY_STAGE_NODE_METADATA | \\",
  "AWS_READ_ONLY_STAGE_NODE_INTEGRITY | \\",
  "AWS_READ_ONLY_STAGE_NODE_VERSION | \\",
  "AWS_READ_ONLY_STAGE_AWS_PATH | \\",
  "AWS_READ_ONLY_STAGE_AWS_METADATA | \\",
  "AWS_READ_ONLY_STAGE_GPG_METADATA | \\",
  "AWS_READ_ONLY_STAGE_TEMPORARY_STATE | \\",
  "AWS_READ_ONLY_STAGE_OIDC_REQUEST | \\",
  "AWS_READ_ONLY_STAGE_OIDC_RECEIPT | \\",
  "AWS_READ_ONLY_STAGE_OIDC_CLAIMS) ;;",
  "*) fail_closed ;;",
  "esac",
  'printf \'%s\\n\' "::error::\${stage}" >&2',
  "exit 1",
  "}"
].join("\n");

const EXPECTED_READ_ONLY_FAILURE_STAGE_SEQUENCE_SHA256 =
  "9857fc8d1376e809a3485d961cc74e5414baf0558abd8bb36ef052c5ce032a51";
const EXPECTED_READ_ONLY_FAILURE_STAGE_REFERENCE_COUNT = 92;

const EXPECTED_READ_ONLY_DIAGNOSTIC_BLOCK = [
  'if [[ "$PREFLIGHT_DIAGNOSTIC_ONLY" == "true" ]]; then',
  "  printf '%s\\n' '::notice::AWS_READ_ONLY_DIAGNOSTIC_PASS'",
  "  exit 0",
  "fi"
].join("\n");

const EXPECTED_READ_ONLY_DIAGNOSTIC_INPUT_BLOCK = [
  "      diagnostic_only:",
  "        description: Validate the protected pre-AWS runtime contract and stop before token exchange",
  "        required: true",
  "        default: true",
  "        type: boolean"
].join("\n");

const EXPECTED_READ_ONLY_PRE_DIAGNOSTIC_PREFIX_SHA256 =
  "1e1f54c20295437b1ee687101130598ed8c805044069ad812276c64d1c3dd716";
const EXPECTED_READ_ONLY_OUTPUT_COMMAND_SEQUENCE_SHA256 =
  "8d904a81633325a805bc789c40b80dfe4785055b76d00f2004c91f8188903946";
const EXPECTED_READ_ONLY_OUTPUT_COMMAND_COUNT = 8;

const EXPECTED_READ_ONLY_WORKFLOW_RUN_COMMANDS = Object.freeze([
  "/usr/bin/bash scripts/run-aws-oidc-read-only-preflight.sh",
  '/usr/bin/rm -f -- "${RUNNER_TEMP}/aws-read-only-preflight-receipt.json.gpg"'
]);

const EXPECTED_READ_ONLY_ACTION_PINS = Object.freeze([
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
  "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
]);

const EXPECTED_IDENTITY_AWS_CLI_REFERENCE_LINES = Object.freeze([
  'aws_candidate="/usr/local/bin/aws"',
  '[[ -L "$aws_candidate" ]] || fail_closed',
  'aws_cli="$(/usr/bin/readlink -f -- "$aws_candidate")" || fail_closed',
  String.raw`[[ "$aws_cli" =~ ^/usr/local/aws-cli/v2/[0-9]+\.[0-9]+\.[0-9]+/dist/aws$ ]] || fail_closed`,
  'aws_metadata="$(/usr/bin/stat -Lc \'%u:%a:%F\' -- "$aws_cli")" || fail_closed',
  '"$aws_cli" sts assume-role-with-web-identity \\',
  '"$aws_cli" sts get-caller-identity \\'
]);

const EXPECTED_READ_ONLY_AWS_CLI_REFERENCE_LINES = Object.freeze([
  'aws_candidate="/usr/local/bin/aws"',
  '[[ -L "$aws_candidate" ]] || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_PATH',
  'aws_cli="$(/usr/bin/readlink -f -- "$aws_candidate")" || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_PATH',
  String.raw`[[ "$aws_cli" =~ ^/usr/local/aws-cli/v2/[0-9]+\.[0-9]+\.[0-9]+/dist/aws$ ]] || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_PATH`,
  'aws_metadata="$(/usr/bin/stat -Lc \'%u:%a:%F\' -- "$aws_cli")" || fail_closed_stage AWS_READ_ONLY_STAGE_AWS_METADATA',
  "unset aws_candidate aws_metadata aws_uid aws_mode aws_type aws_mode_value",
  '"$aws_cli" sts assume-role-with-web-identity \\',
  '"$aws_cli" account get-region-opt-status \\',
  '"$aws_cli" service-quotas list-service-quotas \\'
]);

const EXPECTED_IDENTITY_GPG_REFERENCE_SHA256 =
  "1d79a393539e67b435fd0fe7a75ac318e44950724484cb9418cbe421698f7949";
const EXPECTED_READ_ONLY_GPG_REFERENCE_SHA256 =
  "307f188cb9b549e27d4aa74212da3eda8f3eb4dd82ba46e3d9b001d105d462f6";

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function exactKeys(value, keys, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      sameJson(sorted(Object.keys(value)), sorted(keys)),
    code
  );
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function readRegularFile(rootDir, relativePath, code) {
  const root = path.resolve(rootDir);
  const candidate = path.resolve(root, relativePath);
  const relative = path.relative(root, candidate);
  assert(
    relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      relativePath === relativePath.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(relativePath),
    code
  );
  let current = root;
  let stat;
  for (const segment of relativePath.split("/")) {
    assert(segment !== "" && segment !== "..", code);
    current = path.join(current, segment);
    stat = fs.lstatSync(current);
    assert(!stat.isSymbolicLink(), code);
  }
  assert(stat.isFile(), code);
  return fs.readFileSync(candidate);
}

function parseCanonicalJson(bytes, code) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(code);
  }
  assert(
    `${JSON.stringify(value, null, 2)}\n` === bytes.toString("utf8"),
    `${code}_CANONICAL`
  );
  return value;
}

function actionsPins(source) {
  return [...source.matchAll(/^\s*uses:\s*(\S+)(?:\s+#.*)?$/gmu)].map(
    (match) => match[1]
  );
}

function workflowRunCommands(source) {
  return [...source.matchAll(/^\s*run:\s*(.+?)\s*$/gmu)].map(
    (match) => match[1]
  );
}

function literalAwsCalls(source) {
  return [
    ...source.matchAll(
      /"\$aws_cli"\s+([a-z0-9-]+)\s+([a-z0-9-]+)/gu
    )
  ].map((match) => `${match[1]}:${match[2]}`);
}

function identityFailureStages(source) {
  return [
    ...source.matchAll(/\bfail_closed_stage (AWS_IDENTITY_STAGE_[A-Z0-9_]+)\b/gu)
  ].map((match) => match[1]);
}

function identityFailureStageAllowlist(source) {
  const block = source.match(
    /fail_closed_stage\(\) \{\n([\s\S]*?)\n\s*\}\n\n\s*\[\[/u
  );
  assert(block, "OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_FUNCTION");
  return [
    ...block[1].matchAll(/\bAWS_IDENTITY_STAGE_[A-Z0-9_]+\b/gu)
  ].map((match) => match[0]);
}

function normalizedIdentityFailureStageFunction(source) {
  const block = source.match(
    /^[ \t]*fail_closed_stage\(\) \{\n[\s\S]*?^[ \t]*\}$/mu
  );
  assert(block, "OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_FUNCTION");
  return block[0]
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .join("\n");
}

function readOnlyFailureStages(source) {
  return [
    ...source.matchAll(
      /\bfail_closed_stage (AWS_READ_ONLY_STAGE_[A-Z0-9_]+)\b/gu
    )
  ].map((match) => match[1]);
}

function readOnlyFailureStageAllowlist(source) {
  const block = source.match(
    /fail_closed_stage\(\) \{\n([\s\S]*?)\n\}\n\n\[\[/u
  );
  assert(block, "OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_FUNCTION");
  return [
    ...block[1].matchAll(/\bAWS_READ_ONLY_STAGE_[A-Z0-9_]+\b/gu)
  ].map((match) => match[0]);
}

function normalizedReadOnlyFailureStageFunction(source) {
  const block = source.match(
    /^fail_closed_stage\(\) \{\n[\s\S]*?^\}$/mu
  );
  assert(block, "OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_FUNCTION");
  return block[0]
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .join("\n");
}

function validateAwsCliReferenceLines(source, expected, code) {
  const references = source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) =>
      /\baws_candidate\b|\baws_cli\b|(?:^|\s)(?:command\s+|\/usr\/bin\/env\s+)?aws(?=[\s"'$])|\/(?:[^/\s"'`]+\/)*aws(?=[$"'\s])/u.test(line)
    );
  assert(sameJson(references, expected), code);
  return true;
}

function gpgReferenceLines(source) {
  return source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) =>
      /\bgnupg_[a-z_]+\b|\bcrypto_(?:cli|metadata|uid|mode|type|mode_value)\b|\bGNUPGHOME\b|--no-symkey-cache|\/usr\/bin\/gpg(?:conf)?\b|(?:^|\s)(?:command\s+)?gpg(?:conf)?(?=\s)/u.test(line)
    )
    .join("\n");
}

function validateGpgReferenceLines(source, expectedSha256, code) {
  assert(
    sha256(Buffer.from(gpgReferenceLines(source), "utf8")) ===
      expectedSha256,
    code
  );
  return true;
}

function runtimeCallInventory(source) {
  const block = source.match(
    /export const AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY = Object\.freeze\(\[\n([\s\S]*?)\n\]\);/u
  );
  assert(block, "OIDC_UNDERLYING_PREFLIGHT_INVENTORY_BLOCK");
  const tuplePattern =
    /^\s*Object\.freeze\(\["([a-z0-9-]+)", "([a-z0-9-]+)", ([1-9]\d*)\]\),?\s*$/gmu;
  const entries = [...block[1].matchAll(tuplePattern)].map((match) => [
    match[1],
    match[2],
    Number(match[3])
  ]);
  assert(
    block[1].replace(tuplePattern, "").trim() === "",
    "OIDC_UNDERLYING_PREFLIGHT_INVENTORY_SYNTAX"
  );
  return entries;
}

function validateReceiptSecretContract(source, code) {
  const occurrences = source.split(EXACT_RECEIPT_SECRET_PATTERN).length - 1;
  assert(
    occurrences === 1 &&
      !source.includes("${#RECEIPT_ENCRYPTION_PASSPHRASE} >= 20"),
    code
  );
  return true;
}

function assertMarkers(source, markers, code) {
  assert(markers.every((marker) => source.includes(marker)), code);
}

export function validateReadOnlyRoleTemplate(template) {
  exactKeys(
    template,
    [
      "AWSTemplateFormatVersion",
      "Description",
      "Outputs",
      "Parameters",
      "Resources"
    ],
    "OIDC_ROLE_TEMPLATE_KEYS"
  );
  assert(
    template.AWSTemplateFormatVersion === "2010-09-09" &&
      template.Description.includes("Source-only scaffold") &&
      template.Description.includes("separate human authorization"),
    "OIDC_ROLE_TEMPLATE_BOUNDARY"
  );
  exactKeys(
    template.Parameters,
    ["ArtifactBucketName"],
    "OIDC_ROLE_TEMPLATE_PARAMETERS"
  );
  exactKeys(
    template.Parameters.ArtifactBucketName,
    ["AllowedPattern", "Description", "Type"],
    "OIDC_ROLE_TEMPLATE_BUCKET_PARAMETER"
  );
  assert(
    template.Parameters.ArtifactBucketName.Type === "String" &&
      template.Parameters.ArtifactBucketName.AllowedPattern ===
        "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$",
    "OIDC_ROLE_TEMPLATE_BUCKET_PARAMETER"
  );
  exactKeys(
    template.Resources,
    ["ReadOnlyPreflightRole"],
    "OIDC_ROLE_TEMPLATE_RESOURCES"
  );
  const role = template.Resources.ReadOnlyPreflightRole;
  exactKeys(role, ["Properties", "Type"], "OIDC_ROLE_TEMPLATE_ROLE");
  assert(role.Type === "AWS::IAM::Role", "OIDC_ROLE_TEMPLATE_ROLE_TYPE");
  exactKeys(
    role.Properties,
    [
      "AssumeRolePolicyDocument",
      "Description",
      "MaxSessionDuration",
      "Path",
      "Policies",
      "RoleName",
      "Tags"
    ],
    "OIDC_ROLE_TEMPLATE_ROLE_PROPERTIES"
  );
  assert(
    role.Properties.RoleName === "ProofToActReadOnlyPreflight" &&
      role.Properties.Path === "/" &&
      role.Properties.MaxSessionDuration === 3600,
    "OIDC_ROLE_TEMPLATE_ROLE_IDENTITY"
  );
  assert(
    sameJson(role.Properties.AssumeRolePolicyDocument, {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "GitHubProtectedReadOnlyPreflight",
          Effect: "Allow",
          Principal: {
            Federated: {
              "Fn::Sub":
                "arn:${AWS::Partition}:iam::${AWS::AccountId}:oidc-provider/token.actions.githubusercontent.com"
            }
          },
          Action: "sts:AssumeRoleWithWebIdentity",
          Condition: {
            StringEquals: {
              "token.actions.githubusercontent.com:aud":
                "sts.amazonaws.com",
              "token.actions.githubusercontent.com:environment":
                "aws-read-only-preflight",
              "token.actions.githubusercontent.com:ref":
                "refs/heads/main",
              "token.actions.githubusercontent.com:repository":
                "Flash-Bri/prooftoact",
              "token.actions.githubusercontent.com:repository_id":
                "1317716765",
              "token.actions.githubusercontent.com:repository_owner_id":
                "252500266",
              "token.actions.githubusercontent.com:sub":
                "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-read-only-preflight",
              "token.actions.githubusercontent.com:workflow":
                "AWS Read-Only OIDC Preflight"
            }
          }
        }
      ]
    }),
    "OIDC_ROLE_TEMPLATE_TRUST"
  );
  assert(
    sameJson(role.Properties.Tags, [
      { Key: "Project", Value: "ProofToAct" },
      { Key: "Purpose", Value: "ReadOnlyPreflight" }
    ]),
    "OIDC_ROLE_TEMPLATE_TAGS"
  );
  assert(
    Array.isArray(role.Properties.Policies) &&
      role.Properties.Policies.length === 1,
    "OIDC_ROLE_TEMPLATE_POLICIES"
  );
  const policy = role.Properties.Policies[0];
  exactKeys(
    policy,
    ["PolicyDocument", "PolicyName"],
    "OIDC_ROLE_TEMPLATE_POLICY"
  );
  assert(
    policy.PolicyName === "ProofToActReadOnlyPreflightExactReads" &&
      policy.PolicyDocument?.Version === "2012-10-17" &&
      Array.isArray(policy.PolicyDocument.Statement),
    "OIDC_ROLE_TEMPLATE_POLICY"
  );
  const statements = policy.PolicyDocument.Statement;
  assert(
    sameJson(
      statements.map((statement) => statement.Sid),
      EXPECTED_ROLE_STATEMENT_SIDS
    ),
    "OIDC_ROLE_TEMPLATE_STATEMENTS"
  );
  const deny = statements.at(-1);
  assert(
    deny.Effect === "Deny" &&
      deny.Resource === "*" &&
      !Object.hasOwn(deny, "Action") &&
      sameJson(deny.NotAction, EXACT_READ_ACTIONS),
    "OIDC_ROLE_TEMPLATE_EXPLICIT_DENY"
  );
  const allowStatements = statements.slice(0, -1);
  assert(
    allowStatements.every(
      (statement) =>
        statement.Effect === "Allow" &&
        !Object.hasOwn(statement, "NotAction")
    ),
    "OIDC_ROLE_TEMPLATE_ALLOW_SHAPE"
  );
  const allowActions = sorted(
    allowStatements.flatMap((statement) =>
      Array.isArray(statement.Action)
        ? statement.Action
        : [statement.Action]
    )
  );
  assert(
    sameJson(allowActions, sorted(EXACT_READ_ACTIONS)) &&
      new Set(allowActions).size === allowActions.length,
    "OIDC_ROLE_TEMPLATE_ACTIONS"
  );
  const bySid = Object.fromEntries(
    statements.map((statement) => [statement.Sid, statement])
  );
  assert(
    bySid.ReadBootstrapStack.Resource?.["Fn::Sub"] ===
      "arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/tideproof-gate2-artifacts/*" &&
      bySid.ReadAccountBudget.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:budgets::${AWS::AccountId}:budget/tideproof-gate2-artifacts-account-safety" &&
      bySid.ReadArtifactBucketControls.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:s3:::${ArtifactBucketName}" &&
      bySid.ReadFoundationModelMetadata.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0",
    "OIDC_ROLE_TEMPLATE_SCOPED_RESOURCES"
  );
  const wildcardSids = allowStatements
    .filter((statement) => statement.Resource === "*")
    .map((statement) => statement.Sid);
  assert(
    sameJson(wildcardSids, [
      "ReadCallerIdentity",
      "ReadStackCensus",
      "ReadAccountCost",
      "ReadBedrockQuotaCensus",
      "ReadRegionStatus"
    ]),
    "OIDC_ROLE_TEMPLATE_WILDCARDS"
  );
  assert(
    sameJson(template.Outputs, {
      ReadOnlyPreflightRoleArn: {
        Value: {
          "Fn::GetAtt": ["ReadOnlyPreflightRole", "Arn"]
        }
      },
      ReadOnlyPreflightRoleName: {
        Value: { Ref: "ReadOnlyPreflightRole" }
      },
      RequiredGitHubEnvironment: {
        Value: "aws-read-only-preflight"
      }
    }),
    "OIDC_ROLE_TEMPLATE_OUTPUTS"
  );
  return template;
}

export function validateIdentityWorkflow(source) {
  assertMarkers(
    source,
    [
      "name: AWS OIDC Identity Bootstrap",
      "workflow_dispatch:",
      "official_main_commit:",
      "permissions:\n  contents: read\n  id-token: write",
      "environment: aws-preflight",
      "timeout-minutes: 5",
      "shell: /usr/bin/bash --noprofile --norc -euo pipefail {0}",
      "EXPECTED_OFFICIAL_MAIN_COMMIT: ${{ inputs.official_main_commit }}",
      "AWS_APPROVED_ACCOUNT_ID_SHA256: ${{ secrets.AWS_APPROVED_ACCOUNT_ID_SHA256 }}",
      "$(/usr/bin/id -u)",
      "GITHUB_REPOSITORY_ID:-}\" == \"1317716765",
      "GITHUB_SHA:-}\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
      "AWS_CONTAINER_CREDENTIALS_FULL_URI",
      "compgen -A variable AWS_ENDPOINT_URL",
      "oidc_request_url=\"${ACTIONS_ID_TOKEN_REQUEST_URL:-}\"",
      "${#oidc_request_url} <= 2048",
      "(pipelines|run-actions-[0-9]+-[a-z0-9]([a-z0-9-]*[a-z0-9])?)\\.actions\\.githubusercontent\\.com",
      "[[ \"$oidc_request_url\" =~ $oidc_request_url_pattern ]] || fail_closed",
      "oidc_url=\"${oidc_request_url}&audience=sts.amazonaws.com\"",
      ".workflow_sha == $sha",
      '.repository_owner_id == "252500266"',
      "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-preflight",
      "role/ProofToActPreflight",
      "--role-session-name release-proof",
      "--duration-seconds 900",
      "^ASIA[A-Z0-9]{16}$",
      ".UserId == $assumed_role_id",
      "--cli-connect-timeout 10",
      "--cli-read-timeout 20",
      "/usr/bin/timeout --signal=KILL 30s",
      "--disable",
      "--no-options",
      "GNUPGHOME",
      "for crypto_cli in /usr/bin/gpg /usr/bin/gpgconf; do",
      "receipt-gnupg.XXXXXX",
      '[[ "$gnupg_mode" == "700" ]] || fail_closed',
      '--homedir "$gnupg_home"',
      "--no-symkey-cache",
      '/usr/bin/gpgconf --homedir "$gnupg_home" --kill all',
      '/usr/bin/rm -rf -- "$gnupg_home"',
      EXACT_RECEIPT_SECRET_PATTERN,
      "--symmetric",
      "--cipher-algo AES256",
      "fail_closed_stage() {",
      'printf \'%s\\n\' "::error::${stage}" >&2',
      "retention-days: 1"
    ],
    "OIDC_IDENTITY_WORKFLOW_MARKERS"
  );
  assert(
    sameJson(actionsPins(source), EXPECTED_IDENTITY_ACTION_PINS),
    "OIDC_IDENTITY_WORKFLOW_ACTION_PINS"
  );
  assert(
    sameJson(literalAwsCalls(source), [
      "sts:assume-role-with-web-identity",
      "sts:get-caller-identity"
    ]),
    "OIDC_IDENTITY_WORKFLOW_STS_ONLY"
  );
  assert(
    sameJson(
      identityFailureStages(source),
      EXPECTED_IDENTITY_FAILURE_STAGES
    ),
    "OIDC_IDENTITY_WORKFLOW_FAILURE_STAGES"
  );
  assert(
    sameJson(
      identityFailureStageAllowlist(source),
      EXPECTED_IDENTITY_FAILURE_STAGE_ALLOWLIST
    ),
    "OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_ALLOWLIST"
  );
  assert(
    normalizedIdentityFailureStageFunction(source) ===
      EXPECTED_IDENTITY_FAILURE_STAGE_FUNCTION,
    "OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_FUNCTION"
  );
  assert(
    (source.match(/\bfail_closed_stage\b/gu) ?? []).length ===
      EXPECTED_IDENTITY_FAILURE_STAGES.length + 1,
    "OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_REFERENCES"
  );
  validateAwsCliReferenceLines(
    source,
    EXPECTED_IDENTITY_AWS_CLI_REFERENCE_LINES,
    "OIDC_IDENTITY_AWS_CLI_REFERENCES"
  );
  validateGpgReferenceLines(
    source,
    EXPECTED_IDENTITY_GPG_REFERENCE_SHA256,
    "OIDC_IDENTITY_GPG_REFERENCES"
  );
  assert(
    !source.includes("actions/checkout@") &&
      !source.includes("actions/setup-node@") &&
      !source.includes("vars.AWS_APPROVED_ACCOUNT_ID_SHA256") &&
      !source.includes("https://pipelines.actions.githubusercontent.com/") &&
      !/^\s*(?:push|pull_request|schedule):/mu.test(source) &&
      !/\bset\s+-x\b/u.test(source) &&
      !/\b(?:cat|tee)\b/u.test(source) &&
      !/^\s*aws\s+/mu.test(source),
    "OIDC_IDENTITY_WORKFLOW_MINIMAL"
  );
  validateReceiptSecretContract(
    source,
    "OIDC_IDENTITY_RECEIPT_SECRET"
  );
  return source;
}

export function validateReadOnlyWorkflow(source) {
  assertMarkers(
    source,
    [
      "name: AWS Read-Only OIDC Preflight",
      "workflow_dispatch:",
      "official_main_commit:",
      "diagnostic_only:",
      "permissions:\n  contents: read\n  id-token: write",
      "environment: aws-read-only-preflight",
      "timeout-minutes: 10",
      "shell: /usr/bin/bash --noprofile --norc -euo pipefail {0}",
      "ref: ${{ github.sha }}",
      "fetch-depth: 0",
      "persist-credentials: false",
      "node-version: 22.23.1",
      "EXPECTED_OFFICIAL_MAIN_COMMIT: ${{ inputs.official_main_commit }}",
      "PREFLIGHT_DIAGNOSTIC_ONLY: ${{ inputs.diagnostic_only }}",
      "AWS_READ_ONLY_PREFLIGHT_ROLE_ARN: ${{ secrets.AWS_READ_ONLY_PREFLIGHT_ROLE_ARN }}",
      "AWS_APPROVED_ACCOUNT_ID_SHA256: ${{ secrets.AWS_APPROVED_ACCOUNT_ID_SHA256 }}",
      "LD_PRELOAD: \"\"",
      "NODE_OPTIONS: \"\"",
      "/usr/bin/bash scripts/run-aws-oidc-read-only-preflight.sh",
      "if: ${{ !inputs.diagnostic_only }}",
      "if: ${{ always() && !inputs.diagnostic_only }}",
      "aws-read-only-preflight-receipt.json.gpg",
      "retention-days: 1"
    ],
    "OIDC_READ_ONLY_WORKFLOW_MARKERS"
  );
  assert(
    sameJson(actionsPins(source), EXPECTED_READ_ONLY_ACTION_PINS),
    "OIDC_READ_ONLY_WORKFLOW_ACTION_PINS"
  );
  assert(
    source.split(EXPECTED_READ_ONLY_DIAGNOSTIC_INPUT_BLOCK).length === 2,
    "OIDC_READ_ONLY_WORKFLOW_DIAGNOSTIC_INPUT"
  );
  assert(
    sameJson(
      workflowRunCommands(source),
      EXPECTED_READ_ONLY_WORKFLOW_RUN_COMMANDS
    ),
    "OIDC_READ_ONLY_WORKFLOW_RUN_COMMANDS"
  );
  assert(
    !/^\s*(?:push|pull_request|schedule):/mu.test(source) &&
      !/^\s*aws\s+/mu.test(source) &&
      !source.includes("configure-aws-credentials") &&
      !source.includes("AWS_ROLE_ARN:") &&
      !source.includes("vars.AWS_APPROVED_ACCOUNT_ID_SHA256") &&
      !/\bset\s+-x\b/u.test(source),
    "OIDC_READ_ONLY_WORKFLOW_BOUNDARY"
  );
  return source;
}

export function validateReadOnlyRunner(source) {
  assertMarkers(
    source,
    [
      "set -euo pipefail",
      "set +x",
      "umask 077",
      "fail_closed_stage() {",
      'printf \'%s\\n\' "::error::${stage}" >&2',
      "AWS_READ_ONLY_DIAGNOSTIC_PASS",
      "$(/usr/bin/id -u)",
      "GITHUB_REPOSITORY_ID:-}\" == \"1317716765",
      "GITHUB_SHA:-}\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
      "AWS_CONTAINER_CREDENTIALS_FULL_URI",
      "compgen -A variable AWS_ENDPOINT_URL",
      "/opt/hostedtoolcache/node/22.23.1/x64/bin/node",
      "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068",
      '[[ "$("$node_cli" --version)" == "v22.23.1" ]]',
      "oidc_request_url=\"${ACTIONS_ID_TOKEN_REQUEST_URL:-}\"",
      "${#oidc_request_url} <= 2048",
      "(pipelines|run-actions-[0-9]+-[a-z0-9]([a-z0-9-]*[a-z0-9])?)\\.actions\\.githubusercontent\\.com",
      "[[ \"$oidc_request_url\" =~ $oidc_request_url_pattern ]] || fail_closed",
      "oidc_url=\"${oidc_request_url}&audience=sts.amazonaws.com\"",
      "source_commit\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
      '.repository_owner_id == "252500266"',
      "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-read-only-preflight",
      ".workflow_sha == $sha",
      "role/ProofToActReadOnlyPreflight",
      "--role-session-name read-only-preflight",
      "--duration-seconds 900",
      "^ASIA[A-Z0-9]{16}$",
      "account get-region-opt-status",
      ".RegionOptStatus == \"ENABLED_BY_DEFAULT\"",
      "service-quotas list-service-quotas",
      "--service-code bedrock",
      "--max-results 1",
      "scripts/gate2-aws-preflight.js",
      "--cli-connect-timeout 10",
      "--cli-read-timeout 20",
      "--disable",
      "--no-options",
      "GNUPGHOME",
      "for crypto_cli in /usr/bin/gpg /usr/bin/gpgconf; do",
      "receipt-gnupg.XXXXXX",
      '[[ "$gnupg_mode" == "700" ]] || fail_closed',
      '--homedir "$gnupg_home"',
      "--no-symkey-cache",
      '/usr/bin/gpgconf --homedir "$gnupg_home" --kill all',
      '/usr/bin/rm -rf -- "$gnupg_home"',
      EXACT_RECEIPT_SECRET_PATTERN,
      "AWS_MAX_ATTEMPTS=1",
      "AWS_EC2_METADATA_DISABLED=true",
      "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true",
      "prooftoact.aws-oidc-read-only-preflight-receipt.v1",
      "exactOfficialMainCommit: true",
      "readOnlyAccountSafetyPreflight: true",
      "arn:aws:(iam|sts|s3)",
      "--symmetric",
      "--cipher-algo AES256"
    ],
    "OIDC_READ_ONLY_RUNNER_MARKERS"
  );
  assert(
    sameJson(literalAwsCalls(source), [
      "sts:assume-role-with-web-identity",
      "account:get-region-opt-status",
      "service-quotas:list-service-quotas"
    ]),
    "OIDC_READ_ONLY_RUNNER_DIRECT_CALLS"
  );
  const failureStages = readOnlyFailureStages(source);
  assert(
    failureStages.length ===
        EXPECTED_READ_ONLY_FAILURE_STAGE_REFERENCE_COUNT &&
      sha256(JSON.stringify(failureStages)) ===
        EXPECTED_READ_ONLY_FAILURE_STAGE_SEQUENCE_SHA256,
    "OIDC_READ_ONLY_RUNNER_FAILURE_STAGES"
  );
  assert(
    sameJson(
      readOnlyFailureStageAllowlist(source),
      EXPECTED_READ_ONLY_FAILURE_STAGE_ALLOWLIST
    ),
    "OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_ALLOWLIST"
  );
  assert(
    normalizedReadOnlyFailureStageFunction(source) ===
      EXPECTED_READ_ONLY_FAILURE_STAGE_FUNCTION,
    "OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_FUNCTION"
  );
  assert(
    (source.match(/\bfail_closed_stage\b/gu) ?? []).length ===
      EXPECTED_READ_ONLY_FAILURE_STAGE_REFERENCE_COUNT + 1,
    "OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_REFERENCES"
  );
  const sensitivePrintfLines = source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(
      (line) =>
        /\b(?:printf|echo|cat|tee|printenv)\b/u.test(line) &&
        /\b(?:AWS_ACCOUNT_ID|AWS_APPROVED_ACCOUNT_ID_SHA256|AWS_READ_ONLY_PREFLIGHT_ROLE_ARN|RECEIPT_ENCRYPTION_PASSPHRASE|ACTIONS_ID_TOKEN_REQUEST_(?:TOKEN|URL)|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|account_digest|expected_(?:role|caller)_arn|assumed_role_id|oidc_(?:request_url|url|token|header|payload))\b/u.test(
          line
        )
    );
  assert(
    sameJson(sensitivePrintfLines, [
      'account_digest="$(printf \'%s\' "$AWS_ACCOUNT_ID" | /usr/bin/sha256sum)" || fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY',
      'printf \'%s\\n\' "$RECEIPT_ENCRYPTION_PASSPHRASE" >"$passphrase_file"'
    ]) &&
      !/(?:echo|cat|tee|printenv)[^\n]*(?:AWS_ACCOUNT_ID|AWS_APPROVED_ACCOUNT_ID_SHA256|AWS_READ_ONLY_PREFLIGHT_ROLE_ARN|RECEIPT_ENCRYPTION_PASSPHRASE|ACTIONS_ID_TOKEN_REQUEST_(?:TOKEN|URL))/u.test(
        source
      ),
    "OIDC_READ_ONLY_RUNNER_AUTHORITY_LOGGING"
  );
  validateAwsCliReferenceLines(
    source,
    EXPECTED_READ_ONLY_AWS_CLI_REFERENCE_LINES,
    "OIDC_READ_ONLY_AWS_CLI_REFERENCES"
  );
  validateGpgReferenceLines(
    source,
    EXPECTED_READ_ONLY_GPG_REFERENCE_SHA256,
    "OIDC_READ_ONLY_GPG_REFERENCES"
  );
  assert(
      !/\bset\s+-x\b/u.test(source) &&
      !source.includes("https://pipelines.actions.githubusercontent.com/") &&
      !/\btee\b/u.test(source) &&
      !/(?:^|\n)\s*(?:env|printenv|declare\s+-p)(?:\s|$)/u.test(source),
    "OIDC_READ_ONLY_RUNNER_MUTATION"
  );
  validateReceiptSecretContract(
    source,
    "OIDC_READ_ONLY_RECEIPT_SECRET"
  );
  const diagnosticBlocks = source.split(EXPECTED_READ_ONLY_DIAGNOSTIC_BLOCK);
  const diagnosticIndex = source.indexOf(EXPECTED_READ_ONLY_DIAGNOSTIC_BLOCK);
  const providerExecutionMarkers = [
    "/usr/bin/curl \\",
    '"$aws_cli" sts assume-role-with-web-identity \\',
    '"$aws_cli" account get-region-opt-status \\',
    '"$aws_cli" service-quotas list-service-quotas \\',
    '"$node_cli" "$GITHUB_WORKSPACE/scripts/gate2-aws-preflight.js" \\'
  ];
  assert(
    diagnosticBlocks.length === 2 &&
      diagnosticIndex >= 0 &&
      sha256(source.slice(0, diagnosticIndex)) ===
        EXPECTED_READ_ONLY_PRE_DIAGNOSTIC_PREFIX_SHA256 &&
      (source.match(/\/usr\/bin\/curl\b/gu) ?? []).length === 1 &&
      providerExecutionMarkers.every((marker) => {
        const markerIndex = source.indexOf(marker);
        return markerIndex > diagnosticIndex;
      }),
    "OIDC_READ_ONLY_RUNNER_DIAGNOSTIC_BOUNDARY"
  );
  const outputCommandLines = source
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => /\b(?:printf|echo|cat|tee|printenv)\b/u.test(line));
  assert(
    outputCommandLines.length === EXPECTED_READ_ONLY_OUTPUT_COMMAND_COUNT &&
      sha256(JSON.stringify(outputCommandLines)) ===
        EXPECTED_READ_ONLY_OUTPUT_COMMAND_SEQUENCE_SHA256,
    "OIDC_READ_ONLY_RUNNER_OUTPUT_COMMANDS"
  );
  return source;
}

export function validateUnderlyingPreflight(
  runnerSource,
  validatorSource
) {
  const inventory = runtimeCallInventory(runnerSource);
  assert(
    sameJson(inventory, EXACT_PREFLIGHT_RUNTIME_CALL_INVENTORY) &&
      inventory.reduce((total, entry) => total + entry[2], 0) ===
        EXACT_PREFLIGHT_RUNTIME_CALL_COUNT,
    "OIDC_UNDERLYING_PREFLIGHT_INVENTORY"
  );
  assertMarkers(
    runnerSource,
    [
      "timeout: 30_000",
      "killSignal: \"SIGKILL\"",
      "--cli-connect-timeout",
      "--cli-read-timeout",
      "createAwsPreflightRuntimeCallReader(",
      "AWS_RUNTIME_CALL_INVENTORY",
      "AWS_RUNTIME_CALL_CARDINALITY",
      "exactBudgetNotifications(",
      "notifications.length !== EXPECTED_BUDGET_NOTIFICATIONS.length",
      "runtimeCalls.assertComplete()"
    ],
    "OIDC_UNDERLYING_PREFLIGHT_CALLS"
  );
  assert(
    (runnerSource.match(/\breadAwsJson\s*\(/gu) ?? []).length === 1 &&
      (runnerSource.match(/\bawsJson\s*\(/gu) ?? []).length === 1 &&
      (runnerSource.match(/\bcommandJson\s*\(/gu) ?? []).length === 2 &&
      (runnerSource.match(/\bspawnSync\s*\(/gu) ?? []).length === 1 &&
      (runnerSource.match(/\bspawnSync\b/gu) ?? []).length === 3 &&
      (runnerSource.match(/from "node:child_process"/gu) ?? []).length ===
        1 &&
      runnerSource.includes(
        'import { spawnSync } from "node:child_process";'
      ) &&
      runnerSource.includes(
        "const result = spawnSync(trustedAwsCliExecutable(), args, {"
      ),
    "OIDC_UNDERLYING_PREFLIGHT_READER_BYPASS"
  );
  assertMarkers(
    validatorSource,
    [
      'roleName: "ProofToActPreflight"',
      'sessionName: "release-proof"',
      'roleName: "ProofToActReadOnlyPreflight"',
      'sessionName: "read-only-preflight"',
      "APPROVED_PREFLIGHT_IDENTITY_LANES.find(",
      "AWS_PREFLIGHT_EXPECTED_ROLE",
      "AWS_PREFLIGHT_EXPECTED_CALLER_ARN",
      "AWS_PREFLIGHT_EXPECTED_CALLER_USER_ID",
      "USD_MICROS = 1_000_000",
      "APPROVED_PREFLIGHT_METERED_SPEND_CAP_USD",
      "conservativeReservedAwsExposureMicros <",
      "effectiveAwsSpendCeilingMicros",
      "conservativeReservedTotalExposureMicros <",
      "totalProjectExposureCeilingMicros",
      "PREFLIGHT_ALLOWANCE_AWS_CEILING",
      "PREFLIGHT_ALLOWANCE_TOTAL_EXPOSURE_CEILING",
      'schemaVersion: "tideproof.gate2.aws-preflight.v6"'
    ],
    "OIDC_UNDERLYING_PREFLIGHT_IDENTITIES"
  );
  return inventory;
}

function validateLedger(source) {
  assertMarkers(
    source,
    [
      "SOURCE SCAFFOLD VERIFIED — PROVIDER SETUP, EXECUTION, AND REVIEW PENDING",
      "This lane makes AWS CloudShell optional",
      "ProofToActPreflight/release-proof",
      "ProofToActReadOnlyPreflight/read-only-preflight",
      "AWS_APPROVED_ACCOUNT_ID_SHA256",
      "external setup gate that source cannot prove",
      "Do not embed an AWS account ID or its digest",
      "non-root",
      "900-second",
      "official_main_commit",
      "us-east-1",
      "exactly 20 AWS",
      "14 operation",
      "17 nested calls",
      "canonical unpadded Base64URL for 32 bytes",
      EXACT_RECEIPT_SECRET_PATTERN,
      "reference_policies_iam-condition-keys.html#condition-keys-wif",
      "oidc#immutable-subject-claims",
      "created_at` is `2026-07-30T22:07:23Z",
      "use_default: true",
      "repo:Flash-Bri@252500266/prooftoact@1317716765",
      "AWS does not document the direct",
      "provider-side gate and residual trust boundary",
      "observed AWS + $0.02 < $13.14",
      "exactly `$13.12` fails",
      "maximum `$0.02` complete-preflight cap",
      "encrypted with AES-256",
      "rollback",
      "separate authorization",
      "Deployment and evidence",
      "Deliberately absent and pending",
      "A source-verifier `PASS` is not a provider"
    ],
    "OIDC_LEDGER_BOUNDARY"
  );
  return source;
}

export function verifyAwsOidcPreflightSource({
  rootDir = DEFAULT_ROOT
} = {}) {
  const files = Object.fromEntries(
    [
      IDENTITY_WORKFLOW_PATH,
      READ_ONLY_WORKFLOW_PATH,
      READ_ONLY_RUNNER_PATH,
      ROLE_TEMPLATE_PATH,
      PREFLIGHT_RUNNER_PATH,
      PREFLIGHT_VALIDATOR_PATH,
      LEDGER_PATH
    ].map((relativePath) => [
      relativePath,
      readRegularFile(rootDir, relativePath, "OIDC_SOURCE_FILE")
    ])
  );
  const identityWorkflow = files[IDENTITY_WORKFLOW_PATH].toString("utf8");
  const readOnlyWorkflow = files[READ_ONLY_WORKFLOW_PATH].toString("utf8");
  const readOnlyRunner = files[READ_ONLY_RUNNER_PATH].toString("utf8");
  const preflightRunner = files[PREFLIGHT_RUNNER_PATH].toString("utf8");
  const preflightValidator = files[PREFLIGHT_VALIDATOR_PATH].toString("utf8");
  const ledger = files[LEDGER_PATH].toString("utf8");
  const roleTemplate = parseCanonicalJson(
    files[ROLE_TEMPLATE_PATH],
    "OIDC_ROLE_TEMPLATE_JSON"
  );

  validateIdentityWorkflow(identityWorkflow);
  validateReadOnlyWorkflow(readOnlyWorkflow);
  validateReadOnlyRunner(readOnlyRunner);
  validateReadOnlyRoleTemplate(roleTemplate);
  validateUnderlyingPreflight(preflightRunner, preflightValidator);
  validateLedger(ledger);

  const reviewedFiles = Object.entries(files).map(([relativePath, bytes]) => ({
    path: relativePath,
    sha256: sha256(bytes)
  }));
  assert(
    reviewedFiles.every((entry) => HEX_64.test(entry.sha256)),
    "OIDC_SOURCE_HASH"
  );

  return {
    schemaVersion: RECEIPT_SCHEMA,
    status: RECEIPT_STATUS,
    finalReleaseReady: false,
    providerSetup: "PENDING_HUMAN_AUTHORIZATION",
    providerExecution: "NOT_RUN",
    cloudShellRequired: false,
    deploymentRoleOrWorkflowAdded: false,
    approvedIdentityLaneCount: 2,
    exactReadActionCount: EXACT_READ_ACTIONS.length,
    identityWorkflowAwsCallCount: 2,
    exactPreflightRuntimeCallCount:
      EXACT_PREFLIGHT_RUNTIME_CALL_COUNT,
    exactReadOnlyWorkflowAwsCallCount:
      3 + EXACT_PREFLIGHT_RUNTIME_CALL_COUNT,
    reviewedFiles,
    checks: {
      identityWorkflowManualStsOnly: true,
      identityWorkflowExactCommitAndEnvironmentBound: true,
      readOnlyWorkflowSeparatelyProtected: true,
      temporaryNonRootCredentialsRequired: true,
      accountDigestRequiredButNotEmbedded: true,
      readOnlyRoleTrustExact: true,
      documentedGitHubIamTrustKeysOnly: true,
      readOnlyRoleActionsExact: true,
      providerMutationExplicitlyDenied: true,
      regionAndQuotaMetadataReadsBounded: true,
      accountSafetyPreflightCurrentSourceCallsExact: true,
      receiptSecretExact32ByteBase64url: true,
      encryptedSanitizedReceiptRequired: true,
      cloudShellOptionalWithoutGateWaiver: true,
      deploymentAndRollbackAuthoritySeparate: true,
      providerExecutionClaimAbsent: true
    },
    claimBoundary:
      "This receipt verifies only the current local source contract for two protected GitHub OIDC identity/preflight lanes. It does not prove GitHub environment settings, the required account-digest value, IAM or OIDC provider state, AWS identity, service state, spend, deployment, rollback, teardown, live evidence, publication, submission, or final release readiness, and it grants no provider authority."
  };
}

export const __test = Object.freeze({
  EXACT_PREFLIGHT_RUNTIME_CALL_COUNT,
  EXACT_PREFLIGHT_RUNTIME_CALL_INVENTORY,
  EXACT_READ_ACTIONS,
  EXACT_RECEIPT_SECRET_PATTERN,
  EXPECTED_IDENTITY_ACTION_PINS,
  EXPECTED_IDENTITY_FAILURE_STAGES,
  EXPECTED_IDENTITY_FAILURE_STAGE_ALLOWLIST,
  EXPECTED_IDENTITY_FAILURE_STAGE_FUNCTION,
  EXPECTED_READ_ONLY_ACTION_PINS,
  EXPECTED_READ_ONLY_FAILURE_STAGE_ALLOWLIST,
  EXPECTED_READ_ONLY_FAILURE_STAGE_FUNCTION,
  EXPECTED_READ_ONLY_FAILURE_STAGE_REFERENCE_COUNT,
  EXPECTED_READ_ONLY_FAILURE_STAGE_SEQUENCE_SHA256,
  EXPECTED_READ_ONLY_DIAGNOSTIC_BLOCK,
  EXPECTED_READ_ONLY_DIAGNOSTIC_INPUT_BLOCK,
  EXPECTED_READ_ONLY_OUTPUT_COMMAND_COUNT,
  EXPECTED_READ_ONLY_OUTPUT_COMMAND_SEQUENCE_SHA256,
  EXPECTED_READ_ONLY_PRE_DIAGNOSTIC_PREFIX_SHA256,
  EXPECTED_READ_ONLY_WORKFLOW_RUN_COMMANDS,
  EXPECTED_ROLE_STATEMENT_SIDS,
  RECEIPT_SCHEMA,
  RECEIPT_STATUS
});

const startedDirectly =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    if (process.argv.length !== 2) {
      throw new Error("OIDC_SOURCE_ARGUMENT");
    }
    process.stdout.write(
      `${JSON.stringify(verifyAwsOidcPreflightSource(), null, 2)}\n`
    );
  } catch (error) {
    const candidate = String(error?.message ?? "");
    const code = /^OIDC_[A-Z0-9_]{1,120}$/.test(candidate)
      ? candidate
      : "OIDC_SOURCE_UNKNOWN";
    process.stderr.write(`PROOFTOACT_AWS_OIDC_SOURCE_FAILED:${code}\n`);
    process.exitCode = 1;
  }
}
