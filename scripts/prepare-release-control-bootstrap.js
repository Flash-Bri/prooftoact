import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CURRENT_FILE = fileURLToPath(import.meta.url);
const OFFICIAL_ORIGIN = "https://github.com/Flash-Bri/prooftoact.git";
const TEMPLATE_PATH = "infra/aws/release-deployment-roles-template.json";
const PLANNER_PATH = "scripts/prepare-release-control-bootstrap.js";
const REVIEWED_TEMPLATE_SHA256 =
  "5f72ab835c93e6c8739405ed953d5c340dd13497a83eb1efff40fd70ba144da9";
const REVIEWED_BOUNDARY_POLICY_SHA256 =
  "beb78b947292ec8afd946ba9656c424b1bfa35ffa8ea59e095b38cc49523dd84";
const REGION = "us-east-1";
const STACK_NAME = "prooftoact-release-control-bootstrap";
const CONTROL_TABLE_NAME = "prooftoact-release-controller";
const BOUNDARY_NAME = "ProofToActGate2CloudFormationBoundary";
const BOOTSTRAP_RESERVATION_MICRO_USD = 250_000;
const CUMULATIVE_CAP_MICRO_USD = 20_000_000;
const MAX_CENSUS_AGE_MS = 5 * 60 * 1000;
const MAX_CENSUS_WINDOW_MS = 10 * 60 * 1000;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const BUCKET_NAME =
  /^(?!xn--)(?!.*\.\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u;

const ROLE_NAMES = Object.freeze({
  CloudFormationServiceRole: "ProofToActGate2CloudFormation",
  LiveDrillOperatorRole: "ProofToActLiveDrillOperator",
  ReleaseCoordinatorRole: "ProofToActReleaseCoordinator",
  ReleaseDeploymentRole: "ProofToActReleaseDeployment",
  ReleaseEvidenceRole: "ProofToActReleaseEvidence",
  ReleaseExecutionRole: "ProofToActReleaseExecution",
  ReleaseTeardownRole: "ProofToActReleaseTeardown",
  ReleaseTerminalizerRole: "ProofToActReleaseTerminalizer"
});

const EXPECTED_RESOURCE_IDS = Object.freeze([
  Object.freeze({
    logicalId: "ReleaseControlTable",
    physicalName: CONTROL_TABLE_NAME,
    retention: "RETAIN_DELETION_PROTECTED",
    type: "AWS::DynamoDB::Table"
  }),
  Object.freeze({
    logicalId: "CloudFormationPermissionsBoundary",
    physicalName: BOUNDARY_NAME,
    retention: "STACK_MANAGED",
    type: "AWS::IAM::ManagedPolicy"
  }),
  ...Object.entries(ROLE_NAMES).map(([logicalId, physicalName]) =>
    Object.freeze({
      logicalId,
      physicalName,
      retention: "STACK_MANAGED",
      type: "AWS::IAM::Role"
    })
  )
]);

const EXPECTED_PARAMETERS = Object.freeze({
  GitHubOidcProviderArn: Object.freeze({
    Type: "String",
    Description:
      "Existing GitHub Actions OIDC provider in the approved AWS account.",
    AllowedPattern:
      "^arn:aws:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$"
  }),
  ArtifactBucketName: Object.freeze({
    Type: "String",
    Description:
      "Existing private versioned artifact bucket accepted by the read-only preflight.",
    MinLength: 3,
    MaxLength: 63,
    AllowedPattern:
      "^(?!xn--)(?!.*\\.\\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$"
  })
});

const ALLOWED_GIT_COMMANDS = Object.freeze([
  Object.freeze(["rev-parse", "--show-toplevel"]),
  Object.freeze(["rev-parse", "--git-dir"]),
  Object.freeze(["rev-parse", "--is-bare-repository"]),
  Object.freeze(["rev-parse", "HEAD"]),
  Object.freeze(["rev-parse", "HEAD^{tree}"]),
  Object.freeze(["symbolic-ref", "--quiet", "--short", "HEAD"]),
  Object.freeze(["status", "--porcelain=v1", "--untracked-files=all"]),
  Object.freeze(["remote", "get-url", "origin"]),
  Object.freeze(["ls-files", "--error-unmatch", "--", TEMPLATE_PATH]),
  Object.freeze(["ls-files", "--error-unmatch", "--", PLANNER_PATH])
]);
const ALLOWED_GIT_COMMAND_KEYS = new Set(
  ALLOWED_GIT_COMMANDS.map((argv) => JSON.stringify(argv))
);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])])
    );
  }
  requireCondition(
    value === null ||
      typeof value === "string" ||
      typeof value === "boolean" ||
      (typeof value === "number" && Number.isSafeInteger(value)),
    "BOOTSTRAP_CANONICAL_VALUE_REJECTED"
  );
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function parseCanonicalInstant(value, code) {
  requireCondition(typeof value === "string", code);
  const milliseconds = Date.parse(value);
  requireCondition(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    code
  );
  return milliseconds;
}

function microUsd(value) {
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    "BOOTSTRAP_CENSUS_COST_REJECTED");
  return `${Math.floor(value / 1_000_000)}.${String(value % 1_000_000)
    .padStart(6, "0")}`;
}

function checkedRegularFile(filePath, code) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), code);
  return fs.readFileSync(filePath);
}

function gitEnvironment() {
  return {
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin"
  };
}

function runReadOnlyGit(root, argv) {
  requireCondition(
    Array.isArray(argv) &&
      ALLOWED_GIT_COMMAND_KEYS.has(JSON.stringify(argv)),
    "BOOTSTRAP_GIT_COMMAND_REJECTED"
  );
  try {
    return execFileSync(
      "/usr/bin/git",
      [
        "-c", "core.attributesFile=/dev/null",
        "-c", "core.autocrlf=false",
        "-c", "core.eol=lf",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.untrackedCache=false",
        ...argv
      ],
      {
        cwd: root,
        encoding: "utf8",
        env: gitEnvironment(),
        stdio: ["ignore", "pipe", "pipe"]
      }
    ).trim();
  } catch (error) {
    reject("BOOTSTRAP_GIT_READ_REJECTED", error);
  }
}

function exactBootstrapObjectKey() {
  return `gate2/control-plane-bootstrap/${REVIEWED_TEMPLATE_SHA256}/` +
    "release-deployment-roles-template.json";
}

export function approvedAccountBindingSha256(accountId) {
  requireCondition(
    typeof accountId === "string" && ACCOUNT_ID.test(accountId),
    "BOOTSTRAP_ACCOUNT_ID_REJECTED"
  );
  return sha256(canonicalBytes({
    accountId,
    partition: "aws",
    purpose: "prooftoact-approved-account-v1"
  }));
}

export function validateBootstrapTemplateStructure(template) {
  const code = "BOOTSTRAP_TEMPLATE_STRUCTURE_REJECTED";
  requireCondition(
    template !== null && typeof template === "object" &&
      !Array.isArray(template) &&
      canonicalJson(template.Parameters) === canonicalJson(EXPECTED_PARAMETERS),
    code
  );
  const resources = template.Resources;
  requireCondition(
    resources !== null && typeof resources === "object" &&
      !Array.isArray(resources) &&
      Object.keys(resources).sort().join("\n") ===
        EXPECTED_RESOURCE_IDS.map(({ logicalId }) => logicalId)
          .sort().join("\n"),
    code
  );
  const table = resources.ReleaseControlTable;
  requireCondition(
    table.Type === "AWS::DynamoDB::Table" &&
      table.DeletionPolicy === "Retain" &&
      table.UpdateReplacePolicy === "Retain" &&
      table.Properties?.TableName === CONTROL_TABLE_NAME &&
      table.Properties?.BillingMode === "PAY_PER_REQUEST" &&
      table.Properties?.DeletionProtectionEnabled === true &&
      canonicalJson(table.Properties?.AttributeDefinitions) ===
        canonicalJson([{ AttributeName: "pk", AttributeType: "S" }]) &&
      canonicalJson(table.Properties?.KeySchema) ===
        canonicalJson([{ AttributeName: "pk", KeyType: "HASH" }]) &&
      canonicalJson(table.Properties?.SSESpecification) === canonicalJson({
        KMSMasterKeyId: "alias/aws/dynamodb",
        SSEEnabled: true,
        SSEType: "KMS"
      }),
    code
  );
  const boundary = resources.CloudFormationPermissionsBoundary;
  requireCondition(
    boundary.Type === "AWS::IAM::ManagedPolicy" &&
      boundary.Properties?.ManagedPolicyName === BOUNDARY_NAME &&
      sha256(canonicalBytes(boundary.Properties?.PolicyDocument)) ===
        REVIEWED_BOUNDARY_POLICY_SHA256,
    code
  );
  for (const [logicalId, roleName] of Object.entries(ROLE_NAMES)) {
    const role = resources[logicalId];
    requireCondition(
      role.Type === "AWS::IAM::Role" &&
        role.Properties?.RoleName === roleName &&
        Array.isArray(role.Properties?.ManagedPolicyArns) &&
        role.Properties.ManagedPolicyArns.length === 0,
      code
    );
  }
  requireCondition(
    canonicalJson(
      resources.CloudFormationServiceRole.Properties.PermissionsBoundary
    ) === canonicalJson({ Ref: "CloudFormationPermissionsBoundary" }),
    code
  );
  return deepFreeze({
    boundaryPolicySha256: REVIEWED_BOUNDARY_POLICY_SHA256,
    expectedResources: EXPECTED_RESOURCE_IDS.map((entry) => ({ ...entry })),
    parameterNames: Object.keys(EXPECTED_PARAMETERS).sort(),
    resourceCount: EXPECTED_RESOURCE_IDS.length
  });
}

export function validateBootstrapTemplateBytes(bytes) {
  requireCondition(Buffer.isBuffer(bytes), "BOOTSTRAP_TEMPLATE_BYTES_REJECTED");
  requireCondition(
    sha256(bytes) === REVIEWED_TEMPLATE_SHA256,
    "BOOTSTRAP_TEMPLATE_DIGEST_REJECTED"
  );
  let template;
  try {
    template = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    reject("BOOTSTRAP_TEMPLATE_JSON_REJECTED", error);
  }
  const structure = validateBootstrapTemplateStructure(template);
  return deepFreeze({
    bytes: bytes.length,
    sha256: REVIEWED_TEMPLATE_SHA256,
    ...structure
  });
}

export function validateBootstrapCheckout({
  controlPlaneRoot,
  expectedCommit,
  expectedTree
}) {
  requireCondition(
    typeof controlPlaneRoot === "string" && controlPlaneRoot.length > 0 &&
      typeof expectedCommit === "string" && HEX_40.test(expectedCommit) &&
      typeof expectedTree === "string" && HEX_40.test(expectedTree),
    "BOOTSTRAP_CHECKOUT_INPUT_REJECTED"
  );
  const resolvedRoot = path.resolve(controlPlaneRoot);
  let realRoot;
  let rootStat;
  let gitStat;
  try {
    realRoot = fs.realpathSync(resolvedRoot);
    rootStat = fs.lstatSync(resolvedRoot);
    gitStat = fs.lstatSync(path.join(resolvedRoot, ".git"));
  } catch (error) {
    reject("BOOTSTRAP_STANDALONE_CHECKOUT_REJECTED", error);
  }
  requireCondition(
    realRoot === resolvedRoot &&
      rootStat.isDirectory() && !rootStat.isSymbolicLink() &&
      gitStat.isDirectory() && !gitStat.isSymbolicLink(),
    "BOOTSTRAP_STANDALONE_CHECKOUT_REJECTED"
  );
  requireCondition(
    runReadOnlyGit(resolvedRoot, ["rev-parse", "--show-toplevel"]) ===
      resolvedRoot &&
      runReadOnlyGit(resolvedRoot, ["rev-parse", "--git-dir"]) === ".git" &&
      runReadOnlyGit(
        resolvedRoot,
        ["rev-parse", "--is-bare-repository"]
      ) === "false" &&
      runReadOnlyGit(
        resolvedRoot,
        ["symbolic-ref", "--quiet", "--short", "HEAD"]
      ) === "main",
    "BOOTSTRAP_STANDALONE_CHECKOUT_REJECTED"
  );
  requireCondition(
    runReadOnlyGit(resolvedRoot, ["remote", "get-url", "origin"]) ===
      OFFICIAL_ORIGIN,
    "BOOTSTRAP_OFFICIAL_ORIGIN_REJECTED"
  );
  const commit = runReadOnlyGit(resolvedRoot, ["rev-parse", "HEAD"]);
  const tree = runReadOnlyGit(resolvedRoot, ["rev-parse", "HEAD^{tree}"]);
  requireCondition(
    commit === expectedCommit && tree === expectedTree,
    "BOOTSTRAP_CHECKOUT_IDENTITY_REJECTED"
  );
  requireCondition(
    runReadOnlyGit(
      resolvedRoot,
      ["status", "--porcelain=v1", "--untracked-files=all"]
    ) === "",
    "BOOTSTRAP_CHECKOUT_DIRTY_REJECTED"
  );
  for (const relativePath of [TEMPLATE_PATH, PLANNER_PATH]) {
    requireCondition(
      runReadOnlyGit(
        resolvedRoot,
        ["ls-files", "--error-unmatch", "--", relativePath]
      ) === relativePath,
      "BOOTSTRAP_REQUIRED_TRACKED_FILE_REJECTED"
    );
  }
  const plannerBytes = checkedRegularFile(
    path.join(resolvedRoot, PLANNER_PATH),
    "BOOTSTRAP_PLANNER_FILE_REJECTED"
  );
  const executingPlannerBytes = checkedRegularFile(
    CURRENT_FILE,
    "BOOTSTRAP_PLANNER_FILE_REJECTED"
  );
  requireCondition(
    plannerBytes.equals(executingPlannerBytes),
    "BOOTSTRAP_PLANNER_IDENTITY_REJECTED"
  );
  const templateBytes = checkedRegularFile(
    path.join(resolvedRoot, TEMPLATE_PATH),
    "BOOTSTRAP_TEMPLATE_FILE_REJECTED"
  );
  const template = validateBootstrapTemplateBytes(templateBytes);
  return deepFreeze({
    commit,
    officialOrigin: OFFICIAL_ORIGIN,
    plannerSha256: sha256(plannerBytes),
    template,
    tree
  });
}

function validateBucket(bucket, {
  accountId,
  expectedArtifactKey,
  expectedBucketName,
  oidcProviderArn
}) {
  const code = "BOOTSTRAP_CENSUS_BUCKET_REJECTED";
  requireCondition(
    exactKeys(bucket, [
      "defaultEncryptionEnabled",
      "encryptionAlgorithm",
      "exists",
      "expectedBootstrapObjectKey",
      "name",
      "objectOwnership",
      "publicAccessBlock",
      "region",
      "tlsOnlyPolicy",
      "versioningStatus"
    ]) &&
      bucket.exists === true &&
      bucket.name === expectedBucketName &&
      BUCKET_NAME.test(bucket.name) &&
      bucket.name.length >= 3 && bucket.name.length <= 63 &&
      bucket.region === REGION &&
      bucket.versioningStatus === "Enabled" &&
      bucket.defaultEncryptionEnabled === true &&
      ["AES256", "aws:kms"].includes(bucket.encryptionAlgorithm) &&
      bucket.objectOwnership === "BucketOwnerEnforced" &&
      bucket.tlsOnlyPolicy === true &&
      bucket.expectedBootstrapObjectKey === expectedArtifactKey &&
      exactKeys(bucket.publicAccessBlock, [
        "blockPublicAcls",
        "blockPublicPolicy",
        "ignorePublicAcls",
        "restrictPublicBuckets"
      ]) &&
      Object.values(bucket.publicAccessBlock).every((value) => value === true),
    code
  );
  requireCondition(
    oidcProviderArn ===
      `arn:aws:iam::${accountId}:oidc-provider/` +
        "token.actions.githubusercontent.com",
    "BOOTSTRAP_CENSUS_OIDC_REJECTED"
  );
}

function validateCollisionCensus(census) {
  const code = "BOOTSTRAP_CENSUS_COLLISION_REJECTED";
  requireCondition(
    exactKeys(census, [
      "checkedBoundaryName",
      "checkedRoleNames",
      "checkedStackName",
      "checkedTableName",
      "existingBoundary",
      "existingRoleNames",
      "existingStack",
      "existingTable",
      "unexpectedNamedResources"
    ]) &&
      census.checkedBoundaryName === BOUNDARY_NAME &&
      canonicalJson(census.checkedRoleNames) ===
        canonicalJson(Object.values(ROLE_NAMES).sort()) &&
      census.checkedStackName === STACK_NAME &&
      census.checkedTableName === CONTROL_TABLE_NAME &&
      census.existingBoundary === false &&
      census.existingStack === false &&
      census.existingTable === false &&
      Array.isArray(census.existingRoleNames) &&
      census.existingRoleNames.length === 0 &&
      Array.isArray(census.unexpectedNamedResources) &&
      census.unexpectedNamedResources.length === 0,
    code
  );
}

function validateCost(cost) {
  const code = "BOOTSTRAP_CENSUS_COST_REJECTED";
  requireCondition(
    exactKeys(cost, [
      "authorizedCumulativeCapMicroUsd",
      "bootstrapReservationMicroUsd",
      "currency",
      "observedCumulativeMicroUsd",
      "projectedCumulativeMicroUsd",
      "withinAuthorizedCap"
    ]) &&
      cost.currency === "USD" &&
      Number.isSafeInteger(cost.observedCumulativeMicroUsd) &&
      cost.observedCumulativeMicroUsd >= 0 &&
      cost.bootstrapReservationMicroUsd ===
        BOOTSTRAP_RESERVATION_MICRO_USD &&
      cost.authorizedCumulativeCapMicroUsd ===
        CUMULATIVE_CAP_MICRO_USD &&
      cost.projectedCumulativeMicroUsd ===
        cost.observedCumulativeMicroUsd +
          cost.bootstrapReservationMicroUsd &&
      cost.projectedCumulativeMicroUsd <=
        cost.authorizedCumulativeCapMicroUsd &&
      cost.withinAuthorizedCap === true,
    code
  );
}

export function validateBootstrapCensusReceipt(receipt, {
  expectedAccountBindingSha256,
  expectedArtifactBucketName,
  expectedArtifactKey,
  now
}) {
  const code = "BOOTSTRAP_CENSUS_RECEIPT_REJECTED";
  requireCondition(
    typeof expectedAccountBindingSha256 === "string" &&
      HEX_64.test(expectedAccountBindingSha256) &&
      typeof expectedArtifactBucketName === "string" &&
      typeof expectedArtifactKey === "string" &&
      typeof now === "string" &&
      exactKeys(receipt, [
        "account",
        "artifactBucket",
        "cost",
        "evidenceLevel",
        "expiresAt",
        "gitHubOidcProvider",
        "nameCollisionCensus",
        "observedAt",
        "providerMutationPerformed",
        "readOnly",
        "region",
        "schemaVersion",
        "status"
      ]),
    code
  );
  requireCondition(
    receipt.schemaVersion ===
      "prooftoact.release-control-bootstrap-census.v1" &&
      receipt.status === "ACCEPTED_READ_ONLY_CENSUS" &&
      receipt.evidenceLevel === "PROVIDER_READ_ONLY_CLAIM" &&
      receipt.readOnly === true &&
      receipt.providerMutationPerformed === false &&
      receipt.region === REGION,
    code
  );
  const observedAt = parseCanonicalInstant(
    receipt.observedAt,
    "BOOTSTRAP_CENSUS_TIME_REJECTED"
  );
  const expiresAt = parseCanonicalInstant(
    receipt.expiresAt,
    "BOOTSTRAP_CENSUS_TIME_REJECTED"
  );
  const nowMilliseconds = parseCanonicalInstant(
    now,
    "BOOTSTRAP_CENSUS_TIME_REJECTED"
  );
  requireCondition(
    observedAt <= nowMilliseconds &&
      nowMilliseconds - observedAt <= MAX_CENSUS_AGE_MS &&
      expiresAt >= nowMilliseconds &&
      expiresAt > observedAt &&
      expiresAt - observedAt <= MAX_CENSUS_WINDOW_MS,
    "BOOTSTRAP_CENSUS_STALE_REJECTED"
  );
  const account = receipt.account;
  requireCondition(
    exactKeys(account, [
      "approvedBindingSha256",
      "matchesApproved",
      "observedAccountId",
      "observedBindingSha256"
    ]) &&
      ACCOUNT_ID.test(account.observedAccountId) &&
      account.approvedBindingSha256 === expectedAccountBindingSha256 &&
      account.observedBindingSha256 === expectedAccountBindingSha256 &&
      account.observedBindingSha256 ===
        approvedAccountBindingSha256(account.observedAccountId) &&
      account.matchesApproved === true,
    "BOOTSTRAP_CENSUS_ACCOUNT_REJECTED"
  );
  const oidc = receipt.gitHubOidcProvider;
  requireCondition(
    exactKeys(oidc, ["arn", "audiencePresent", "exists", "issuer"]) &&
      oidc.exists === true &&
      oidc.issuer === "https://token.actions.githubusercontent.com" &&
      oidc.audiencePresent === true &&
      oidc.arn ===
        `arn:aws:iam::${account.observedAccountId}:oidc-provider/` +
          "token.actions.githubusercontent.com",
    "BOOTSTRAP_CENSUS_OIDC_REJECTED"
  );
  validateBucket(receipt.artifactBucket, {
    accountId: account.observedAccountId,
    expectedArtifactKey,
    expectedBucketName: expectedArtifactBucketName,
    oidcProviderArn: oidc.arn
  });
  validateCollisionCensus(receipt.nameCollisionCensus);
  validateCost(receipt.cost);
  return deepFreeze({
    accountBindingSha256: expectedAccountBindingSha256,
    artifactBucketName: receipt.artifactBucket.name,
    censusSha256: sha256(canonicalBytes(receipt)),
    expiresAt: receipt.expiresAt,
    gitHubOidcProviderArn: oidc.arn,
    observedAt: receipt.observedAt,
    observedCumulativeMicroUsd: receipt.cost.observedCumulativeMicroUsd,
    projectedCumulativeMicroUsd: receipt.cost.projectedCumulativeMicroUsd,
    region: REGION
  });
}

export function serializeReleaseControlBootstrapPlan(plan) {
  requireCondition(
    plan !== null && typeof plan === "object" && !Array.isArray(plan),
    "BOOTSTRAP_PLAN_REJECTED"
  );
  return canonicalBytes(plan);
}

export function buildReleaseControlBootstrapPlan(input) {
  requireCondition(
    exactKeys(input, [
      "censusReceipt",
      "controlPlaneRoot",
      "expectedAccountBindingSha256",
      "expectedArtifactBucketName",
      "expectedControlPlaneCommit",
      "expectedControlPlaneTree",
      "now",
      "requestedArtifactKey",
      "requestedRegion"
    ]),
    "BOOTSTRAP_PLAN_INPUT_REJECTED"
  );
  requireCondition(
    input.requestedRegion === REGION,
    "BOOTSTRAP_PLAN_REGION_REJECTED"
  );
  const artifactKey = exactBootstrapObjectKey();
  requireCondition(
    input.requestedArtifactKey === artifactKey,
    "BOOTSTRAP_PLAN_ARTIFACT_KEY_REJECTED"
  );
  const checkout = validateBootstrapCheckout({
    controlPlaneRoot: input.controlPlaneRoot,
    expectedCommit: input.expectedControlPlaneCommit,
    expectedTree: input.expectedControlPlaneTree
  });
  const census = validateBootstrapCensusReceipt(input.censusReceipt, {
    expectedAccountBindingSha256: input.expectedAccountBindingSha256,
    expectedArtifactBucketName: input.expectedArtifactBucketName,
    expectedArtifactKey: artifactKey,
    now: input.now
  });
  const body = {
    schemaVersion: "prooftoact.release-control-bootstrap-plan.v1",
    status: "HOLD_NOT_AUTHORIZED",
    evidenceLevel: "LOCAL_VERIFIED_PROVIDER_CENSUS_CLAIM",
    decision: "HOLD",
    preparedAt: input.now,
    executionAuthorized: false,
    providerMutationAuthorized: false,
    directProviderExecutionSupported: false,
    controlPlane: {
      commit: checkout.commit,
      tree: checkout.tree,
      officialOrigin: checkout.officialOrigin,
      cleanStandaloneCheckoutVerified: true,
      plannerSha256: checkout.plannerSha256,
      permissionsBoundaryPolicySha256:
        checkout.template.boundaryPolicySha256,
      templatePath: TEMPLATE_PATH,
      templateSha256: checkout.template.sha256,
      templateBytes: checkout.template.bytes
    },
    census: {
      receiptSha256: census.censusSha256,
      accountBindingSha256: census.accountBindingSha256,
      region: census.region,
      observedAt: census.observedAt,
      expiresAt: census.expiresAt,
      readOnlyClaimOnly: true,
      providerMutationObserved: false
    },
    spendEnvelope: {
      currency: "USD",
      observedCumulativeMicroUsd: census.observedCumulativeMicroUsd,
      observedCumulativeUsd: microUsd(census.observedCumulativeMicroUsd),
      bootstrapReservationMicroUsd: BOOTSTRAP_RESERVATION_MICRO_USD,
      bootstrapReservationUsd: microUsd(BOOTSTRAP_RESERVATION_MICRO_USD),
      projectedCumulativeMicroUsd: census.projectedCumulativeMicroUsd,
      projectedCumulativeUsd: microUsd(census.projectedCumulativeMicroUsd),
      authorizedCumulativeCapMicroUsd: CUMULATIVE_CAP_MICRO_USD,
      authorizedCumulativeCapUsd: microUsd(CUMULATIVE_CAP_MICRO_USD),
      withinCapVerifiedFromFreshCensus: true
    },
    templateUpload: {
      operation: "PUT_EXACT_VERSIONED_OBJECT_ONCE_NOT_EXECUTED",
      bucketName: census.artifactBucketName,
      key: artifactKey,
      bytes: checkout.template.bytes,
      sha256: checkout.template.sha256,
      contentAddressed: true,
      exactBytesNoMinificationOrRewrite: true,
      providerAssignedVersionIdRequired: true,
      versionId: null,
      readBackExactVersionBeforeStackCreate: true
    },
    stack: {
      operation: "CREATE_EXACT_CONTROL_STACK_NOT_EXECUTED",
      stackName: STACK_NAME,
      region: REGION,
      capabilities: ["CAPABILITY_NAMED_IAM"],
      templateUrlContract: {
        bucketName: census.artifactBucketName,
        key: artifactKey,
        versionId: "REQUIRED_PROVIDER_ASSIGNED_VERSION_ID"
      },
      parameters: [
        {
          parameterKey: "ArtifactBucketName",
          parameterValue: census.artifactBucketName
        },
        {
          parameterKey: "GitHubOidcProviderArn",
          parameterValue: census.gitHubOidcProviderArn
        }
      ],
      expectedResourceCount: EXPECTED_RESOURCE_IDS.length,
      expectedResources: EXPECTED_RESOURCE_IDS.map((entry) => ({ ...entry })),
      createOnly: true,
      updateAllowed: false,
      automaticRetryAllowed: false
    },
    requiredReadback: {
      beforeUpload: [
        "FRESH_CALLER_AND_ACCOUNT_BINDING",
        "FRESH_COST_AND_NAME_COLLISION_CENSUS",
        "EXACT_OIDC_PROVIDER_AND_BUCKET_IDENTITY"
      ],
      afterUploadBeforeCreate: [
        "S3_VERSION_ID_PRESENT",
        "EXACT_OBJECT_SIZE_AND_SHA256_READBACK",
        "EXACT_VERSIONED_OBJECT_PRIVATE_ENCRYPTED_TLS_ONLY"
      ],
      afterCreate: [
        "EXACT_STACK_ID_AND_CREATE_COMPLETE",
        "EXACT_TEN_RESOURCE_PHYSICAL_IDENTITIES",
        "TABLE_ID_KMS_ARN_TAGS_RETENTION_AND_DELETION_PROTECTION",
        "EIGHT_ROLE_TRUST_AND_POLICY_DIGESTS",
        "SOURCE_OWNED_BOUNDARY_DIGEST",
        "NO_UNEXPECTED_RESOURCES"
      ],
      iamSimulation: {
        exactPositiveActionsOnly: true,
        allNamedNegativeActionsDenied: true,
        permissionsBoundaryEffective: true,
        readbackPrincipalIndependent: true
      }
    },
    rollbackAndRetention: {
      cloudFormationRollbackRequired: true,
      noBlindRetryOrAutomaticUpdate: true,
      retainedControlTable: true,
      retainedTableDeletionProtection: true,
      retainedTemplateObjectVersion: true,
      failedRetainedTableRequiresSeparateIdentityReviewAndApproval: true,
      existingArtifactAndIdentityStacksUntouched: true,
      applicationDeploymentExcluded: true,
      liveDrillExcluded: true,
      publicReleaseAndSubmissionExcluded: true
    },
    nextGate:
      "SEPARATE_EXACT_HUMAN_AUTHORIZATION_AFTER_CONTROL_PLANE_SEAL_AND_FRESH_PROVIDER_CENSUS"
  };
  const plan = {
    ...body,
    planBodySha256: sha256(canonicalBytes(body))
  };
  return deepFreeze(plan);
}

export const __test = Object.freeze({
  ALLOWED_GIT_COMMANDS,
  BOOTSTRAP_RESERVATION_MICRO_USD,
  BOUNDARY_NAME,
  CONTROL_TABLE_NAME,
  CUMULATIVE_CAP_MICRO_USD,
  EXPECTED_RESOURCE_IDS,
  MAX_CENSUS_AGE_MS,
  OFFICIAL_ORIGIN,
  PLANNER_PATH,
  REGION,
  REVIEWED_BOUNDARY_POLICY_SHA256,
  REVIEWED_TEMPLATE_SHA256,
  ROLE_NAMES,
  STACK_NAME,
  TEMPLATE_PATH,
  canonicalBytes,
  canonicalJson,
  exactBootstrapObjectKey,
  sha256
});

if (process.argv[1] && path.resolve(process.argv[1]) === CURRENT_FILE) {
  process.stdout.write(
    "HOLD:RELEASE_CONTROL_BOOTSTRAP_PLANNER_IS_LOCAL_ONLY_AND_NEVER_AUTHORIZES_PROVIDER_EXECUTION\n"
  );
}
