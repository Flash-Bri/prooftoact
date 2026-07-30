import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  validateAwsGate2Preflight
} from "../src/cloud/aws-gate2-preflight.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function commandJson(command, args, code) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      AWS_PAGER: "",
      AWS_EC2_METADATA_DISABLED: "true"
    },
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
    encoding: "utf8"
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

function isoDate(date) {
  return date.toISOString().slice(0, 10);
}

function costPeriod(now) {
  const start = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    1
  ));
  let end = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate()
  ));
  if (end <= start) {
    end = new Date(start);
    end.setUTCDate(end.getUTCDate() + 1);
  }
  return {
    periodStart: isoDate(start),
    periodEndExclusive: isoDate(end)
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

function collectSnapshot(now = new Date()) {
  const {
    region,
    modelId,
    bootstrapStackName,
    mainStackName
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
    [
      "--account-id",
      accountId,
      "--budget-name",
      budgetName
    ]
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

  const period = costPeriod(now);
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

function main() {
  if (process.argv.length !== 2) {
    throw new Error("UNEXPECTED_ARGUMENT");
  }
  const receipt = validateAwsGate2Preflight(collectSnapshot());
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  const code = String(error?.message ?? "UNKNOWN_FAILURE")
    .replaceAll(/[^A-Z0-9_]/g, "_")
    .slice(0, 160);
  process.stderr.write(
    `TIDEPROOF_GATE2_AWS_PREFLIGHT_FAILED:${code}\n`
  );
  process.exitCode = 1;
}
