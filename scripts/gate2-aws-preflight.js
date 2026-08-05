import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  awsBudgetDescribeArguments,
  awsCostExplorerPeriod,
  validateAwsGate2PreflightIdentityExpectation,
  validateAwsGate2Preflight
} from "../src/cloud/aws-gate2-preflight.js";
import {
  assertAwsSdkEvidenceEnvironment,
  explicitAwsCredentials,
  isolatedAwsCliEnvironment,
  isolatedEvidenceProcessEnvironment,
  validateAwsEvidenceCaller
} from "../src/cloud/aws-evidence-identity.js";
import {
  assertCleanExactGitCheckout,
  assertExactGitRepositoryLayout,
  gitInvariantArguments
} from "./lib/exact-git-source.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const TRUSTED_AWS_CLI_POLICY = Object.freeze({
  darwin: Object.freeze({
    candidates: Object.freeze(["/opt/homebrew/bin/aws"]),
    packageRoots: Object.freeze(["/opt/homebrew/Cellar/awscli"]),
    owner: "current"
  }),
  linux: Object.freeze({
    candidates: Object.freeze(["/usr/local/bin/aws"]),
    packageRoots: Object.freeze(["/usr/local/aws-cli"]),
    ownerUid: 0
  })
});
const TRUSTED_GIT_POLICY = Object.freeze({
  darwin: Object.freeze({
    candidates: Object.freeze(["/usr/bin/git"]),
    resolvedPaths: Object.freeze(["/usr/bin/git"]),
    packageRoots: Object.freeze([]),
    ownerUid: 0
  }),
  linux: Object.freeze({
    candidates: Object.freeze(["/usr/bin/git"]),
    resolvedPaths: Object.freeze(["/usr/bin/git"]),
    packageRoots: Object.freeze(["/usr/lib/git-core"]),
    ownerUid: 0
  })
});
const STANDARD_AWS_CLI_PATH_DIRECTORIES = Object.freeze([
  "/usr/bin",
  "/bin"
]);
const STANDARD_GIT_PATH_DIRECTORIES = Object.freeze([
  "/usr/bin",
  "/bin"
]);
const HEX_40 = /^[0-9a-f]{40}$/;
const ALLOWED_GIT_REQUESTS = new Set([
  JSON.stringify(["rev-parse", "HEAD"]),
  JSON.stringify(["rev-parse", "HEAD^{tree}"]),
  JSON.stringify([
    "status",
    "--porcelain=v1",
    "--untracked-files=all"
  ])
]);

function trustedAwsCliPolicy(platform) {
  const policy = TRUSTED_AWS_CLI_POLICY[platform];
  if (!policy) {
    throw new Error("AWS_CLI_UNSUPPORTED_PLATFORM");
  }
  return policy;
}

function trustedGitPolicy(platform) {
  const policy = TRUSTED_GIT_POLICY[platform];
  if (!policy) {
    throw new Error("GIT_UNSUPPORTED_PLATFORM");
  }
  return policy;
}

function currentUserId() {
  const uid = process.getuid?.();
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error("TRUSTED_EXECUTABLE_OWNER");
  }
  return uid;
}

function isWithinDirectory(candidate, directory) {
  const relative = path.relative(directory, candidate);
  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

export function controlledAwsCliPath({
  platform = process.platform,
  delimiter = path.delimiter
} = {}) {
  if (
    typeof delimiter !== "string" ||
    delimiter.length !== 1 ||
    /[\r\n\0]/.test(delimiter)
  ) {
    throw new Error("AWS_CLI_PATH_DELIMITER");
  }
  const policy = trustedAwsCliPolicy(platform);
  return [
    ...new Set([
      ...policy.candidates.map((candidate) => path.dirname(candidate)),
      ...STANDARD_AWS_CLI_PATH_DIRECTORIES
    ])
  ].join(delimiter);
}

export function controlledGitPath({
  platform = process.platform,
  delimiter = path.delimiter
} = {}) {
  trustedGitPolicy(platform);
  if (
    typeof delimiter !== "string" ||
    delimiter.length !== 1 ||
    /[\r\n\0]/.test(delimiter)
  ) {
    throw new Error("GIT_PATH_DELIMITER");
  }
  return STANDARD_GIT_PATH_DIRECTORIES.join(delimiter);
}

function trustedExecutable({
  candidates,
  expectedBasename,
  expectedOwnerUid,
  packageRoots = [],
  resolvedPaths = [],
  requirePackageIndirection = false,
  realpath = fs.realpathSync,
  lstat = fs.lstatSync,
  stat = fs.statSync,
  access = fs.accessSync
}) {
  if (
    !Array.isArray(candidates) ||
    candidates.length === 0 ||
    typeof expectedBasename !== "string" ||
    expectedBasename.length === 0 ||
    !Number.isSafeInteger(expectedOwnerUid) ||
    expectedOwnerUid < 0 ||
    !Array.isArray(packageRoots) ||
    !Array.isArray(resolvedPaths) ||
    candidates.some(
      (candidate) =>
        typeof candidate !== "string" ||
        !path.isAbsolute(candidate) ||
        path.basename(candidate) !== expectedBasename
    ) ||
    [...packageRoots, ...resolvedPaths].some(
      (approvedPath) =>
        typeof approvedPath !== "string" ||
        !path.isAbsolute(approvedPath)
    )
  ) {
    throw new Error("TRUSTED_EXECUTABLE_POLICY");
  }

  for (const candidate of candidates) {
    try {
      const candidateMetadata = lstat(candidate);
      const resolved = realpath(candidate);
      const resolvedMetadata = stat(resolved);
      const pathApproved =
        resolvedPaths.includes(resolved) ||
        packageRoots.some((trustedRoot) =>
          isWithinDirectory(resolved, trustedRoot)
        );
      if (
        path.isAbsolute(resolved) &&
        path.basename(resolved) === expectedBasename &&
        pathApproved &&
        (!requirePackageIndirection ||
          (candidateMetadata.isSymbolicLink() &&
            resolved !== candidate)) &&
        resolvedMetadata.isFile() &&
        resolvedMetadata.uid === expectedOwnerUid &&
        (resolvedMetadata.mode & 0o111) !== 0 &&
        (resolvedMetadata.mode & 0o022) === 0
      ) {
        access(resolved, fs.constants.X_OK);
        return resolved;
      }
    } catch {
      // Continue through the fixed executable allowlist.
    }
  }
  throw new Error("TRUSTED_EXECUTABLE_REJECTED");
}

export function trustedAwsCliExecutable({
  platform = process.platform,
  candidatePaths,
  packageRoots,
  expectedOwnerUid,
  realpath = fs.realpathSync,
  lstat = fs.lstatSync,
  stat = fs.statSync,
  access = fs.accessSync
} = {}) {
  const policy = trustedAwsCliPolicy(platform);
  try {
    return trustedExecutable({
      candidates: candidatePaths ?? policy.candidates,
      expectedBasename: "aws",
      expectedOwnerUid:
        expectedOwnerUid ??
        (policy.owner === "current"
          ? currentUserId()
          : policy.ownerUid),
      packageRoots: packageRoots ?? policy.packageRoots,
      requirePackageIndirection: true,
      realpath,
      lstat,
      stat,
      access
    });
  } catch {
    throw new Error("AWS_CLI_TRUSTED_EXECUTABLE");
  }
}

export function trustedGitExecutable({
  platform = process.platform,
  candidatePaths,
  packageRoots,
  resolvedPaths,
  expectedOwnerUid,
  realpath = fs.realpathSync,
  lstat = fs.lstatSync,
  stat = fs.statSync,
  access = fs.accessSync
} = {}) {
  const policy = trustedGitPolicy(platform);
  try {
    return trustedExecutable({
      candidates: candidatePaths ?? policy.candidates,
      expectedBasename: "git",
      expectedOwnerUid: expectedOwnerUid ?? policy.ownerUid,
      packageRoots: packageRoots ?? policy.packageRoots,
      resolvedPaths: resolvedPaths ?? policy.resolvedPaths,
      realpath,
      lstat,
      stat,
      access
    });
  } catch {
    throw new Error("GIT_TRUSTED_EXECUTABLE");
  }
}

export function awsPreflightAwsEnvironment(
  sourceEnvironment,
  pathOptions = {}
) {
  return {
    ...isolatedAwsCliEnvironment(sourceEnvironment, {
      requireSessionToken: true
    }),
    PATH: controlledAwsCliPath(pathOptions)
  };
}

export function gitPreflightEnvironment(
  sourceEnvironment,
  pathOptions = {}
) {
  return {
    ...isolatedEvidenceProcessEnvironment(sourceEnvironment),
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_PAGER: "cat",
    GIT_TERMINAL_PROMPT: "0",
    PATH: controlledGitPath(pathOptions)
  };
}

function commandJson(args, code) {
  const result = spawnSync(trustedAwsCliExecutable(), args, {
    cwd: root,
    encoding: "utf8",
    env: awsPreflightAwsEnvironment(process.env),
    maxBuffer: 10 * 1024 * 1024
  });
  if (result.error || result.status !== 0) {
    throw new Error(code);
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${code}_INVALID_JSON`);
  }
}

export function trustedGitText(
  command,
  args,
  code,
  {
    sourceEnvironment = process.env,
    executableOptions = {},
    rootDir = root,
    spawn = spawnSync
  } = {}
) {
  if (
    command !== "git" ||
    !ALLOWED_GIT_REQUESTS.has(JSON.stringify(args))
  ) {
    throw new Error("GIT_COMMAND_NOT_ALLOWED");
  }
  const result = spawn(
    trustedGitExecutable(executableOptions),
    [
      ...gitInvariantArguments(),
      "--no-pager",
      ...args
    ],
    {
      cwd: path.resolve(rootDir),
      encoding: "utf8",
      env: gitPreflightEnvironment(sourceEnvironment)
    }
  );
  if (result.error || result.status !== 0) {
    throw new Error(code);
  }
  return result.stdout.trim();
}

export function trustedGitCheckout({
  rootDir = root,
  readCommandText,
  verifyCheckout = assertCleanExactGitCheckout,
  verifyRepositoryLayout = assertExactGitRepositoryLayout
} = {}) {
  const resolvedRoot = path.resolve(rootDir);
  verifyRepositoryLayout({ rootDir: resolvedRoot });
  const read =
    readCommandText ??
    ((command, args, code) =>
      trustedGitText(command, args, code, {
        rootDir: resolvedRoot
      }));
  const sourceCommit = read(
    "git",
    ["rev-parse", "HEAD"],
    "GIT_SOURCE_COMMIT"
  );
  const treeDigest = read(
    "git",
    ["rev-parse", "HEAD^{tree}"],
    "GIT_TREE_DIGEST"
  );
  const status = read(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
    "GIT_STATUS"
  );
  if (status.length !== 0) {
    throw new Error("WORKING_TREE_DIRTY");
  }
  if (!HEX_40.test(sourceCommit) || !HEX_40.test(treeDigest)) {
    throw new Error("GIT_CHECKOUT_IDENTITY");
  }
  const verified = verifyCheckout({
    rootDir: resolvedRoot,
    sourceCommit,
    treeDigest
  });
  if (
    verified?.rootDir !== resolvedRoot ||
    verified?.sourceCommit !== sourceCommit ||
    verified?.treeDigest !== treeDigest
  ) {
    throw new Error("GIT_CHECKOUT_VERIFICATION");
  }
  return Object.freeze({
    sourceCommit,
    treeDigest,
    workingTreeClean: true
  });
}

function awsJson(region, service, operation, args = []) {
  return commandJson(
    [
      service,
      operation,
      ...args,
      "--region",
      region,
      "--output",
      "json",
      "--no-cli-pager"
    ],
    `AWS_${service.toUpperCase()}_${operation
      .replaceAll("-", "_")
      .toUpperCase()}`
  );
}

function stackOutput(stack, key) {
  const output = stack.Outputs?.find(
    (candidate) => candidate.OutputKey === key
  );
  if (!output?.OutputValue) {
    throw new Error(`BOOTSTRAP_OUTPUT_${key}`);
  }
  return output.OutputValue;
}

function notificationInput(notification) {
  return {
    NotificationType: notification.NotificationType,
    ComparisonOperator: notification.ComparisonOperator,
    Threshold: notification.Threshold,
    ThresholdType: notification.ThresholdType
  };
}

function exactSingleStack(response, expectedName) {
  const stacks = response.Stacks ?? [];
  if (
    stacks.length !== 1 ||
    stacks[0]?.StackName !== expectedName
  ) {
    throw new Error("BOOTSTRAP_STACK_LOOKUP");
  }
  return stacks[0];
}

function readBucketPolicy(region, bucketName, readAwsJson = awsJson) {
  const response = readAwsJson(
    region,
    "s3api",
    "get-bucket-policy",
    ["--bucket", bucketName]
  );
  try {
    return JSON.parse(response.Policy);
  } catch {
    throw new Error("ARTIFACT_BUCKET_POLICY_JSON");
  }
}

export function assertAwsPreflightParentEnvironment(environment) {
  assertAwsSdkEvidenceEnvironment(environment);
  const credentials = explicitAwsCredentials(environment, {
    requireSessionToken: true
  });
  if (!/^ASIA[A-Z0-9]{16}$/.test(credentials.accessKeyId)) {
    throw new Error("AWS_EVIDENCE_TEMPORARY_ACCESS_KEY");
  }
  return true;
}

export function awsPreflightIdentityExpectation(
  environment,
  bindingContext
) {
  const expectedAccountId =
    environment?.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID;
  const expectedPrincipalArn =
    environment?.AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN;
  const expectedCallerArn =
    environment?.AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN;
  const expectedCallerUserId =
    environment?.AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID;
  if (!/^\d{12}$/.test(expectedAccountId ?? "")) {
    throw new Error("AWS_EXPECTED_ACCOUNT_REQUIRED");
  }
  if (
    typeof expectedPrincipalArn !== "string" ||
    !expectedPrincipalArn.startsWith("arn:aws:iam::")
  ) {
    throw new Error("AWS_EXPECTED_PREFLIGHT_PRINCIPAL_REQUIRED");
  }
  if (
    typeof expectedCallerArn !== "string" ||
    typeof expectedCallerUserId !== "string"
  ) {
    throw new Error("AWS_EXPECTED_PREFLIGHT_IDENTITY_REQUIRED");
  }

  const expectation = {
    expectedAccountId,
    expectedPrincipalArn,
    expectedCallerArn,
    expectedCallerUserId
  };
  validateAwsGate2PreflightIdentityExpectation(expectation);
  const callerBinding = validateAwsEvidenceCaller(
    {
      Account: expectedAccountId,
      Arn: expectedCallerArn,
      UserId: expectedCallerUserId
    },
    {
      ...expectation,
      bindingContext
    }
  );
  if (callerBinding.principalType !== "assumed-role") {
    throw new Error("AWS_EXPECTED_PREFLIGHT_ASSUMED_ROLE_REQUIRED");
  }
  return expectation;
}

export function awsCostExplorerArguments(period) {
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(period?.periodStart ?? "") ||
    !/^\d{4}-\d{2}-\d{2}$/.test(
      period?.periodEndExclusive ?? ""
    )
  ) {
    throw new Error("AWS_COST_EXPLORER_PERIOD");
  }
  return [
    "--time-period",
    `Start=${period.periodStart},End=${period.periodEndExclusive}`,
    "--granularity",
    "MONTHLY",
    "--metrics",
    "UnblendedCost",
    "--no-paginate"
  ];
}

export function collectSnapshot(
  now = new Date(),
  {
    environment = process.env,
    readGitCheckout = trustedGitCheckout,
    readAwsJson = awsJson
  } = {}
) {
  assertAwsPreflightParentEnvironment(environment);
  const {
    region,
    modelId,
    bootstrapStackName,
    mainStackName,
    legacyMainStackName
  } = AWS_GATE2_PREFLIGHT_DEFAULTS;
  const checkout = readGitCheckout();
  if (
    !HEX_40.test(checkout?.sourceCommit) ||
    !HEX_40.test(checkout?.treeDigest) ||
    checkout?.workingTreeClean !== true
  ) {
    throw new Error("GIT_CHECKOUT_VERIFICATION");
  }
  const { sourceCommit, treeDigest, workingTreeClean } = checkout;

  const bindingContext = {
    purpose: "gate2-read-only-preflight",
    sourceCommit,
    treeDigest
  };
  const expectation = awsPreflightIdentityExpectation(
    environment,
    bindingContext
  );
  const {
    expectedAccountId,
    expectedPrincipalArn,
    expectedCallerArn,
    expectedCallerUserId
  } = expectation;

  const callerIdentity = readAwsJson(
    region,
    "sts",
    "get-caller-identity"
  );
  validateAwsEvidenceCaller(callerIdentity, {
    ...expectation,
    bindingContext
  });
  const bootstrapStack = exactSingleStack(
    readAwsJson(
      region,
      "cloudformation",
      "describe-stacks",
      ["--stack-name", bootstrapStackName]
    ),
    bootstrapStackName
  );
  const budgetName = stackOutput(
    bootstrapStack,
    "AccountBudgetName"
  );
  const bucketName = stackOutput(
    bootstrapStack,
    "ArtifactBucketName"
  );
  const accountId = callerIdentity.Account;
  const budget = readAwsJson(
    region,
    "budgets",
    "describe-budget",
    awsBudgetDescribeArguments(accountId, budgetName)
  ).Budget;
  const notifications = readAwsJson(
    region,
    "budgets",
    "describe-notifications-for-budget",
    [
      "--account-id",
      accountId,
      "--budget-name",
      budgetName
    ]
  ).Notifications ?? [];
  const notificationSubscribers = notifications.map((notification) => ({
    notification,
    subscribers:
      readAwsJson(
        region,
        "budgets",
        "describe-subscribers-for-notification",
        [
          "--account-id",
          accountId,
          "--budget-name",
          budgetName,
          "--notification",
          JSON.stringify(notificationInput(notification))
        ]
      ).Subscribers ?? []
  }));

  const period = awsCostExplorerPeriod(now);
  const currentCostResponse = readAwsJson(
    region,
    "ce",
    "get-cost-and-usage",
    awsCostExplorerArguments(period)
  );

  return {
    observedAt: now.toISOString(),
    sourceCommit,
    treeDigest,
    workingTreeClean,
    region,
    expectedAccountId,
    expectedPrincipalArn,
    expectedCallerArn,
    expectedCallerUserId,
    callerIdentity,
    bootstrapStackName,
    bootstrapStack,
    budget,
    notificationSubscribers,
    artifactBucket: {
      versioning: readAwsJson(
        region,
        "s3api",
        "get-bucket-versioning",
        ["--bucket", bucketName]
      ),
      encryption: readAwsJson(
        region,
        "s3api",
        "get-bucket-encryption",
        ["--bucket", bucketName]
      ),
      publicAccessBlock: readAwsJson(
        region,
        "s3api",
        "get-public-access-block",
        ["--bucket", bucketName]
      ),
      ownership: readAwsJson(
        region,
        "s3api",
        "get-bucket-ownership-controls",
        ["--bucket", bucketName]
      ),
      policyStatus: readAwsJson(
        region,
        "s3api",
        "get-bucket-policy-status",
        ["--bucket", bucketName]
      ),
      policy: readBucketPolicy(region, bucketName, readAwsJson)
    },
    mainStackName,
    legacyMainStackName,
    stackSummaries:
      readAwsJson(
        region,
        "cloudformation",
        "list-stacks"
      ).StackSummaries ?? [],
    currentCost: {
      ...period,
      response: currentCostResponse
    },
    foundationModel: readAwsJson(
      region,
      "bedrock",
      "get-foundation-model",
      ["--model-identifier", modelId]
    )
  };
}

export function main(argv = process.argv.slice(2)) {
  if (argv.length !== 0) {
    throw new Error("UNEXPECTED_ARGUMENT");
  }
  const receipt = validateAwsGate2Preflight(collectSnapshot());
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    main();
  } catch (error) {
    const candidate = String(error?.message ?? "");
    const code = /^(?:AWS|GIT|WORKING_TREE|UNEXPECTED)_[A-Z0-9_]{1,120}$/.test(
      candidate
    )
      ? candidate
      : "UNKNOWN_FAILURE";
    process.stderr.write(
      `TIDEPROOF_GATE2_AWS_PREFLIGHT_FAILED:${code}\n`
    );
    process.exitCode = 1;
  }
}
