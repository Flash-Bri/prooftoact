import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  awsBudgetDescribeArguments,
  awsCostExplorerPeriod,
  validateAwsGate2Preflight
} from "../src/cloud/aws-gate2-preflight.js";
import {
  assertAwsSdkEvidenceEnvironment,
  isolatedAwsCliEnvironment,
  isolatedEvidenceProcessEnvironment
} from "../src/cloud/aws-evidence-identity.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function commandJson(command, args, code) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: isolatedAwsCliEnvironment(process.env),
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

function commandText(command, args, code) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: isolatedEvidenceProcessEnvironment(process.env)
  });
  if (result.error || result.status !== 0) {
    throw new Error(code);
  }
  return result.stdout.trim();
}

function awsJson(region, service, operation, args = []) {
  return commandJson(
    "aws",
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

function readBucketPolicy(region, bucketName) {
  const response = awsJson(
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
  return true;
}

function collectSnapshot(now = new Date()) {
  assertAwsPreflightParentEnvironment(process.env);
  const {
    region,
    modelId,
    bootstrapStackName,
    mainStackName,
    legacyMainStackName
  } = AWS_GATE2_PREFLIGHT_DEFAULTS;
  const sourceCommit = commandText(
    "git",
    ["rev-parse", "HEAD"],
    "GIT_SOURCE_COMMIT"
  );
  const treeDigest = commandText(
    "git",
    ["rev-parse", "HEAD^{tree}"],
    "GIT_TREE_DIGEST"
  );
  const workingTreeClean =
    commandText(
      "git",
      ["status", "--short"],
      "GIT_STATUS"
    ).length === 0;
  if (!workingTreeClean) {
    throw new Error("WORKING_TREE_DIRTY");
  }

  const expectedAccountId =
    process.env.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID;
  const expectedPrincipalArn =
    process.env.AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN;
  const expectedCallerArn =
    process.env.AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN;
  const expectedCallerUserId =
    process.env.AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID;
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

  const callerIdentity = awsJson(region, "sts", "get-caller-identity");
  const bootstrapStack = exactSingleStack(
    awsJson(
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
  const budget = awsJson(
    region,
    "budgets",
    "describe-budget",
    awsBudgetDescribeArguments(accountId, budgetName)
  ).Budget;
  const notifications = awsJson(
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
      awsJson(
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
  const currentCostResponse = awsJson(
    region,
    "ce",
    "get-cost-and-usage",
    [
      "--time-period",
      `Start=${period.periodStart},End=${period.periodEndExclusive}`,
      "--granularity",
      "MONTHLY",
      "--metrics",
      "UnblendedCost"
    ]
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
      versioning: awsJson(
        region,
        "s3api",
        "get-bucket-versioning",
        ["--bucket", bucketName]
      ),
      encryption: awsJson(
        region,
        "s3api",
        "get-bucket-encryption",
        ["--bucket", bucketName]
      ),
      publicAccessBlock: awsJson(
        region,
        "s3api",
        "get-public-access-block",
        ["--bucket", bucketName]
      ),
      ownership: awsJson(
        region,
        "s3api",
        "get-bucket-ownership-controls",
        ["--bucket", bucketName]
      ),
      policyStatus: awsJson(
        region,
        "s3api",
        "get-bucket-policy-status",
        ["--bucket", bucketName]
      ),
      policy: readBucketPolicy(region, bucketName)
    },
    mainStackName,
    legacyMainStackName,
    stackSummaries:
      awsJson(
        region,
        "cloudformation",
        "list-stacks"
      ).StackSummaries ?? [],
    currentCost: {
      ...period,
      response: currentCostResponse
    },
    foundationModel: awsJson(
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
