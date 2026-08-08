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
  "prooftoact.aws-oidc-preflight-source-verification.v1";
const RECEIPT_STATUS =
  "SOURCE_CONTRACT_PASS_PROVIDER_SETUP_AND_EXECUTION_PENDING";
const HEX_64 = /^[0-9a-f]{64}$/;

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

const EXPECTED_READ_ONLY_ACTION_PINS = Object.freeze([
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
  "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
]);

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

function literalAwsCalls(source) {
  return [
    ...source.matchAll(
      /"\$aws_cli"\s+([a-z0-9-]+)\s+([a-z0-9-]+)/gu
    )
  ].map((match) => `${match[1]}:${match[2]}`);
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
              "token.actions.githubusercontent.com:sub":
                "repo:Flash-Bri/prooftoact:environment:aws-read-only-preflight"
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
      "AWS_APPROVED_ACCOUNT_ID_SHA256: ${{ vars.AWS_APPROVED_ACCOUNT_ID_SHA256 }}",
      "$(/usr/bin/id -u)",
      "GITHUB_REPOSITORY_ID:-}\" == \"1317716765",
      "GITHUB_SHA:-}\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
      "AWS_CONTAINER_CREDENTIALS_FULL_URI",
      "compgen -A variable AWS_ENDPOINT_URL",
      ".workflow_sha == $sha",
      "repo:Flash-Bri/prooftoact:environment:aws-preflight",
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
      "--symmetric",
      "--cipher-algo AES256",
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
    !source.includes("actions/checkout@") &&
      !source.includes("actions/setup-node@") &&
      !/^\s*(?:push|pull_request|schedule):/mu.test(source) &&
      !/\bset\s+-x\b/u.test(source) &&
      !/\b(?:cat|tee)\b/u.test(source) &&
      !/^\s*aws\s+/mu.test(source),
    "OIDC_IDENTITY_WORKFLOW_MINIMAL"
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
      "permissions:\n  contents: read\n  id-token: write",
      "environment: aws-read-only-preflight",
      "timeout-minutes: 10",
      "shell: /usr/bin/bash --noprofile --norc -euo pipefail {0}",
      "ref: ${{ github.sha }}",
      "fetch-depth: 0",
      "persist-credentials: false",
      "node-version: 22",
      "EXPECTED_OFFICIAL_MAIN_COMMIT: ${{ inputs.official_main_commit }}",
      "AWS_READ_ONLY_PREFLIGHT_ROLE_ARN: ${{ secrets.AWS_READ_ONLY_PREFLIGHT_ROLE_ARN }}",
      "AWS_APPROVED_ACCOUNT_ID_SHA256: ${{ vars.AWS_APPROVED_ACCOUNT_ID_SHA256 }}",
      "LD_PRELOAD: \"\"",
      "NODE_OPTIONS: \"\"",
      "/usr/bin/bash scripts/run-aws-oidc-read-only-preflight.sh",
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
    !/^\s*(?:push|pull_request|schedule):/mu.test(source) &&
      !/^\s*aws\s+/mu.test(source) &&
      !source.includes("configure-aws-credentials") &&
      !source.includes("AWS_ROLE_ARN:") &&
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
      "$(/usr/bin/id -u)",
      "GITHUB_REPOSITORY_ID:-}\" == \"1317716765",
      "GITHUB_SHA:-}\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
      "AWS_CONTAINER_CREDENTIALS_FULL_URI",
      "compgen -A variable AWS_ENDPOINT_URL",
      "source_commit\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
      "repo:Flash-Bri/prooftoact:environment:aws-read-only-preflight",
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
  assert(
    !/\bset\s+-x\b/u.test(source) &&
      !/\btee\b/u.test(source),
    "OIDC_READ_ONLY_RUNNER_MUTATION"
  );
  return source;
}

function validateUnderlyingPreflight(runnerSource, validatorSource) {
  assertMarkers(
    runnerSource,
    [
      "timeout: 30_000",
      "killSignal: \"SIGKILL\"",
      "--cli-connect-timeout",
      "--cli-read-timeout",
      '"get-caller-identity"',
      '"describe-stacks"',
      '"describe-budget"',
      '"describe-notifications-for-budget"',
      '"describe-subscribers-for-notification"',
      '"get-cost-and-usage"',
      '"get-bucket-versioning"',
      '"get-bucket-encryption"',
      '"get-public-access-block"',
      '"get-bucket-ownership-controls"',
      '"get-bucket-policy-status"',
      '"get-bucket-policy"',
      '"list-stacks"',
      '"get-foundation-model"'
    ],
    "OIDC_UNDERLYING_PREFLIGHT_CALLS"
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
      "AWS_PREFLIGHT_EXPECTED_CALLER_USER_ID"
    ],
    "OIDC_UNDERLYING_PREFLIGHT_IDENTITIES"
  );
  return true;
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
      "known missing setup gate",
      "Do not embed an AWS account ID or its digest",
      "non-root",
      "900-second",
      "official_main_commit",
      "us-east-1",
      "`$13.14`",
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
    reviewedFiles,
    checks: {
      identityWorkflowManualStsOnly: true,
      identityWorkflowExactCommitAndEnvironmentBound: true,
      readOnlyWorkflowSeparatelyProtected: true,
      temporaryNonRootCredentialsRequired: true,
      accountDigestRequiredButNotEmbedded: true,
      readOnlyRoleTrustExact: true,
      readOnlyRoleActionsExact: true,
      providerMutationExplicitlyDenied: true,
      regionAndQuotaMetadataReadsBounded: true,
      accountSafetyPreflightCallsBounded: true,
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
  EXACT_READ_ACTIONS,
  EXPECTED_IDENTITY_ACTION_PINS,
  EXPECTED_READ_ONLY_ACTION_PINS,
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
