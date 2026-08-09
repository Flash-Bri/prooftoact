import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  AWS_GATE2_PREFLIGHT_BUDGET_FAILURES,
  AWS_GATE2_PREFLIGHT_CONTROL_FAILURES,
  AWS_GATE2_PREFLIGHT_COST_FAILURES,
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  AwsGate2PreflightControlFailure,
  awsBudgetDescribeArguments,
  awsCostExplorerPeriod,
  consumeAwsGate2PreflightBudgetFailure,
  consumeAwsGate2PreflightCostFailure,
  createAwsGate2PreflightDiagnosticContext,
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

export const AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY = Object.freeze([
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

const EXPANDED_AWS_GATE2_PREFLIGHT_RUNTIME_CALLS = Object.freeze(
  AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY.flatMap(
    ([service, operation, cardinality]) =>
      Array.from({ length: cardinality }, () =>
        Object.freeze([service, operation])
      )
  )
);

export const AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES = Object.freeze([
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_01",
    exitCode: 40
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_02",
    exitCode: 41
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_03",
    exitCode: 42
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_04",
    exitCode: 43
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_05",
    exitCode: 44
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_06",
    exitCode: 45
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_07",
    exitCode: 46
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_08",
    exitCode: 47
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_09",
    exitCode: 48
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_10",
    exitCode: 49
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_11",
    exitCode: 50
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_12",
    exitCode: 51
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_13",
    exitCode: 52
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_14",
    exitCode: 53
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_15",
    exitCode: 54
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_16",
    exitCode: 55
  }),
  Object.freeze({
    stage: "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_17",
    exitCode: 56
  })
]);

export const AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES = Object.freeze([
  Object.freeze({ stage: "CHILD_ENVIRONMENT", exitCode: 60 }),
  Object.freeze({ stage: "SOURCE_CHECKOUT", exitCode: 61 }),
  Object.freeze({ stage: "EXPECTED_IDENTITY", exitCode: 62 }),
  Object.freeze({ stage: "CALL_INVENTORY", exitCode: 63 }),
  Object.freeze({ stage: "CALLER_RECEIPT", exitCode: 64 }),
  Object.freeze({ stage: "BOOTSTRAP_RECEIPT", exitCode: 65 }),
  Object.freeze({ stage: "BUDGET_RECEIPT", exitCode: 66 }),
  Object.freeze({ stage: "NOTIFICATION_RECEIPT", exitCode: 67 }),
  Object.freeze({ stage: "SUBSCRIBER_RECEIPT", exitCode: 68 }),
  Object.freeze({ stage: "COST_REQUEST_PREPARE", exitCode: 69 }),
  Object.freeze({ stage: "BUCKET_POLICY_RECEIPT", exitCode: 70 }),
  Object.freeze({ stage: "STACK_CENSUS_RECEIPT", exitCode: 71 }),
  Object.freeze({ stage: "SNAPSHOT_COMPLETE", exitCode: 72 }),
  Object.freeze({ stage: "RECEIPT_OUTPUT", exitCode: 83 }),
  Object.freeze({ stage: "ARGUMENT", exitCode: 84 }),
  Object.freeze({ stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 })
]);

export const AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES = Object.freeze([
  Object.freeze({ stage: "VALIDATE_SOURCE_IDENTITY", exitCode: 73 }),
  Object.freeze({ stage: "VALIDATE_BOOTSTRAP", exitCode: 74 }),
  Object.freeze({ stage: "VALIDATE_BUDGET", exitCode: 75 }),
  Object.freeze({ stage: "VALIDATE_NOTIFICATIONS", exitCode: 76 }),
  Object.freeze({ stage: "VALIDATE_STACK_ABSENCE", exitCode: 77 }),
  Object.freeze({ stage: "VALIDATE_ARTIFACT_BUCKET", exitCode: 78 }),
  Object.freeze({ stage: "VALIDATE_COST", exitCode: 79 }),
  Object.freeze({ stage: "VALIDATE_EXPOSURE", exitCode: 80 }),
  Object.freeze({ stage: "VALIDATE_MODEL", exitCode: 81 }),
  Object.freeze({ stage: "VALIDATE_RECEIPT_ASSEMBLY", exitCode: 82 })
]);

export const AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES = Object.freeze([
  Object.freeze({ stage: "VALIDATE_BUDGET_NAME", exitCode: 86 }),
  Object.freeze({ stage: "VALIDATE_BUDGET_TYPE", exitCode: 87 }),
  Object.freeze({ stage: "VALIDATE_BUDGET_TIME_UNIT", exitCode: 88 }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_SCOPE_COST_FILTERS",
    exitCode: 89
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_SCOPE_FILTER_EXPRESSION",
    exitCode: 90
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_SCOPE_BILLING_VIEW",
    exitCode: 91
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_FIXED_AUTO_ADJUST",
    exitCode: 92
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_FIXED_PLANNED_LIMITS",
    exitCode: 93
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_METRICS_BASIS",
    exitCode: 94
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_COST_TYPES_BASIS",
    exitCode: 95
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_PERIOD_START",
    exitCode: 96
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_PERIOD_END",
    exitCode: 97
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_PERIOD_ORDER",
    exitCode: 98
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_PERIOD_NOT_STARTED",
    exitCode: 99
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_PERIOD_EXPIRED",
    exitCode: 100
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_PERIOD_RELEASE_HORIZON",
    exitCode: 101
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_LIMIT_UNIT",
    exitCode: 102
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_LIMIT_AMOUNT_FORMAT",
    exitCode: 103
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_LIMIT_NONNEGATIVE",
    exitCode: 104
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_LIMIT_FIXED",
    exitCode: 105
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_ACTUAL_SPEND_UNIT",
    exitCode: 106
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_ACTUAL_SPEND_AMOUNT_FORMAT",
    exitCode: 107
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_ACTUAL_SPEND_NONNEGATIVE",
    exitCode: 108
  }),
  Object.freeze({
    stage: "VALIDATE_BUDGET_ACTUAL_SPEND_CEILING",
    exitCode: 109
  })
]);

export const AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES = Object.freeze([
  Object.freeze({ stage: "VALIDATE_COST_OBSERVED_AT", exitCode: 57 }),
  Object.freeze({
    stage: "VALIDATE_COST_OBSERVED_AT_WINDOW",
    exitCode: 58
  }),
  Object.freeze({ stage: "VALIDATE_COST_PERIOD_START", exitCode: 110 }),
  Object.freeze({ stage: "VALIDATE_COST_PERIOD_END", exitCode: 111 }),
  Object.freeze({
    stage: "VALIDATE_COST_RESPONSE_GROUPED_UNPAGINATED",
    exitCode: 112
  }),
  Object.freeze({ stage: "VALIDATE_COST_ROWS", exitCode: 113 }),
  Object.freeze({ stage: "VALIDATE_COST_ROW_PERIOD", exitCode: 114 }),
  Object.freeze({
    stage: "VALIDATE_COST_RECORD_TYPE_GROUPS",
    exitCode: 115
  }),
  Object.freeze({
    stage: "VALIDATE_COST_RECORD_TYPE_SEMANTICS",
    exitCode: 116
  }),
  Object.freeze({
    stage: "VALIDATE_COST_RECORD_TYPE_UNBLENDED_UNIT",
    exitCode: 117
  }),
  Object.freeze({
    stage: "VALIDATE_COST_RECORD_TYPE_SIGNED_DECIMAL_FORMAT",
    exitCode: 118
  }),
  Object.freeze({
    stage: "VALIDATE_COST_RECORD_TYPE_SIGNED_RANGE",
    exitCode: 119
  }),
  Object.freeze({
    stage: "VALIDATE_COST_POSITIVE_RECORD_TYPE_TOTAL_RANGE",
    exitCode: 120
  }),
  Object.freeze({
    stage: "VALIDATE_COST_CEILING_DECIMAL_FORMAT",
    exitCode: 121
  }),
  Object.freeze({ stage: "VALIDATE_COST_CEILING_RANGE", exitCode: 122 }),
  Object.freeze({ stage: "VALIDATE_COST_CEILING", exitCode: 123 })
]);

class AwsPreflightRuntimeReadFailure extends Error {
  constructor(index) {
    super("AWS_RUNTIME_READ_FAILURE");
    this.name = "AwsPreflightRuntimeReadFailure";
    this.index = index;
  }
}

class AwsPreflightRuntimePhaseFailure extends Error {
  constructor(index) {
    super("AWS_RUNTIME_PHASE_FAILURE");
    this.name = "AwsPreflightRuntimePhaseFailure";
    this.index = index;
  }
}

function runtimePhase(index, operation, diagnosticFailureMode = true) {
  if (
    !Number.isSafeInteger(index) ||
    typeof AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[index]?.stage !==
      "string" ||
    typeof operation !== "function"
  ) {
    throw new AwsPreflightRuntimePhaseFailure(15);
  }
  try {
    return operation();
  } catch (error) {
    if (
      error instanceof AwsPreflightRuntimeReadFailure ||
      error instanceof AwsPreflightRuntimePhaseFailure ||
      error instanceof AwsGate2PreflightControlFailure
    ) {
      throw error;
    }
    if (diagnosticFailureMode !== true) {
      throw error;
    }
    throw new AwsPreflightRuntimePhaseFailure(index);
  }
}

export function awsPreflightRuntimeFailureDescriptor(
  error,
  diagnosticContext = null
) {
  const budgetFailureIndex =
    consumeAwsGate2PreflightBudgetFailure(error, diagnosticContext);
  if (budgetFailureIndex !== null) {
    const descriptor =
      AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[budgetFailureIndex];
    if (
      descriptor?.stage ===
      AWS_GATE2_PREFLIGHT_BUDGET_FAILURES[budgetFailureIndex]
    ) {
      return descriptor;
    }
    return AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15];
  }
  const costFailureIndex =
    consumeAwsGate2PreflightCostFailure(error, diagnosticContext);
  if (costFailureIndex !== null) {
    const descriptor =
      AWS_GATE2_PREFLIGHT_RUNTIME_COST_FAILURES[costFailureIndex];
    if (
      descriptor?.stage ===
      AWS_GATE2_PREFLIGHT_COST_FAILURES[costFailureIndex]
    ) {
      return descriptor;
    }
    return AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15];
  }
  if (error instanceof AwsPreflightRuntimeReadFailure) {
    return (
      AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES[error.index] ??
      AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15]
    );
  }
  if (error instanceof AwsPreflightRuntimePhaseFailure) {
    return (
      AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[error.index] ??
      AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15]
    );
  }
  if (error instanceof AwsGate2PreflightControlFailure) {
    const descriptor =
      AWS_GATE2_PREFLIGHT_RUNTIME_CONTROL_FAILURES[error.index];
    if (
      descriptor?.stage ===
      AWS_GATE2_PREFLIGHT_CONTROL_FAILURES[error.index]
    ) {
      return descriptor;
    }
    return AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15];
  }
  return AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15];
}

function writeAwsPreflightRuntimeFailure(
  error,
  diagnosticContext = null
) {
  const failure = awsPreflightRuntimeFailureDescriptor(
    error,
    diagnosticContext
  );
  process.stderr.write(
    `TIDEPROOF_GATE2_AWS_PREFLIGHT_FAILED:${failure.stage}\n`
  );
  process.exitCode = failure.exitCode;
}

const EXPECTED_BUDGET_NOTIFICATIONS = Object.freeze([
  Object.freeze({
    NotificationType: "ACTUAL",
    ComparisonOperator: "GREATER_THAN",
    Threshold: 1,
    ThresholdType: "ABSOLUTE_VALUE"
  }),
  Object.freeze({
    NotificationType: "ACTUAL",
    ComparisonOperator: "GREATER_THAN",
    Threshold: 5,
    ThresholdType: "ABSOLUTE_VALUE"
  }),
  Object.freeze({
    NotificationType: "ACTUAL",
    ComparisonOperator: "GREATER_THAN",
    Threshold: 10,
    ThresholdType: "ABSOLUTE_VALUE"
  }),
  Object.freeze({
    NotificationType: "FORECASTED",
    ComparisonOperator: "GREATER_THAN",
    Threshold: 15,
    ThresholdType: "ABSOLUTE_VALUE"
  })
]);

export function createAwsPreflightRuntimeCallReader(readAwsJson) {
  if (typeof readAwsJson !== "function") {
    throw new Error("AWS_RUNTIME_CALL_READER");
  }
  let callIndex = 0;
  return Object.freeze({
    read(region, service, operation, args = []) {
      const expected =
        EXPANDED_AWS_GATE2_PREFLIGHT_RUNTIME_CALLS[callIndex];
      const failure =
        AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES[callIndex];
      if (
        region !== AWS_GATE2_PREFLIGHT_DEFAULTS.region ||
        expected?.[0] !== service ||
        expected?.[1] !== operation ||
        typeof failure?.stage !== "string" ||
        !Number.isSafeInteger(failure?.exitCode)
      ) {
        throw new Error("AWS_RUNTIME_CALL_INVENTORY");
      }
      const failureIndex = callIndex;
      callIndex += 1;
      try {
        return readAwsJson(region, service, operation, args);
      } catch {
        throw new AwsPreflightRuntimeReadFailure(failureIndex);
      }
    },
    assertComplete() {
      if (
        callIndex !==
        EXPANDED_AWS_GATE2_PREFLIGHT_RUNTIME_CALLS.length
      ) {
        throw new Error("AWS_RUNTIME_CALL_CARDINALITY");
      }
      return callIndex;
    }
  });
}

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
    killSignal: "SIGKILL",
    maxBuffer: 10 * 1024 * 1024,
    timeout: 30_000
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
      "--cli-connect-timeout",
      "10",
      "--cli-read-timeout",
      "20",
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

function readBucketPolicy(region, bucketName, readBoundedAwsJson) {
  const response = readBoundedAwsJson(
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

function exactBudgetNotifications(notifications) {
  if (
    !Array.isArray(notifications) ||
    notifications.length !== EXPECTED_BUDGET_NOTIFICATIONS.length
  ) {
    throw new Error("AWS_BUDGET_NOTIFICATION_CARDINALITY");
  }
  return EXPECTED_BUDGET_NOTIFICATIONS.map((expected) => {
    const matches = notifications.filter(
      (notification) =>
        JSON.stringify(notificationInput(notification)) ===
        JSON.stringify(expected)
    );
    if (matches.length !== 1) {
      throw new Error("AWS_BUDGET_NOTIFICATION_INVENTORY");
    }
    return matches[0];
  });
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
    "--group-by",
    "Type=DIMENSION,Key=RECORD_TYPE",
    "--no-paginate"
  ];
}

export function collectSnapshot(
  now = new Date(),
  {
    environment = process.env,
    readGitCheckout = trustedGitCheckout,
    readAwsJson = awsJson,
    diagnosticFailureMode = false
  } = {}
) {
  const phase = (index, operation) =>
    runtimePhase(index, operation, diagnosticFailureMode);
  const defaults = phase(0, () => {
    assertAwsPreflightParentEnvironment(environment);
    const {
      region,
      modelId,
      bootstrapStackName,
      mainStackName,
      legacyMainStackName
    } = AWS_GATE2_PREFLIGHT_DEFAULTS;
    return {
      region,
      modelId,
      bootstrapStackName,
      mainStackName,
      legacyMainStackName
    };
  });
  const {
    region,
    modelId,
    bootstrapStackName,
    mainStackName,
    legacyMainStackName
  } = defaults;
  const checkout = phase(1, () => {
    const candidate = readGitCheckout();
    if (
      !HEX_40.test(candidate?.sourceCommit) ||
      !HEX_40.test(candidate?.treeDigest) ||
      candidate?.workingTreeClean !== true
    ) {
      throw new Error("GIT_CHECKOUT_VERIFICATION");
    }
    return candidate;
  });
  const { sourceCommit, treeDigest, workingTreeClean } = checkout;

  const bindingContext = {
    purpose: "gate2-read-only-preflight",
    sourceCommit,
    treeDigest
  };
  const expectation = phase(2, () =>
    awsPreflightIdentityExpectation(environment, bindingContext)
  );
  const {
    expectedAccountId,
    expectedPrincipalArn,
    expectedCallerArn,
    expectedCallerUserId
  } = expectation;
  const runtimeCalls = phase(3, () =>
    createAwsPreflightRuntimeCallReader(readAwsJson)
  );
  const readBoundedAwsJson = runtimeCalls.read;

  const callerIdentity = readBoundedAwsJson(
    region,
    "sts",
    "get-caller-identity"
  );
  phase(4, () => {
    validateAwsEvidenceCaller(callerIdentity, {
      ...expectation,
      bindingContext
    });
  });
  const bootstrapResponse = readBoundedAwsJson(
    region,
    "cloudformation",
    "describe-stacks",
    ["--stack-name", bootstrapStackName]
  );
  const bootstrapReceipt = phase(5, () => {
    const bootstrapStack = exactSingleStack(
      bootstrapResponse,
      bootstrapStackName
    );
    return {
      bootstrapStack,
      budgetName: stackOutput(
        bootstrapStack,
        "AccountBudgetName"
      ),
      bucketName: stackOutput(
        bootstrapStack,
        "ArtifactBucketName"
      )
    };
  });
  const { bootstrapStack, budgetName, bucketName } = bootstrapReceipt;
  const accountId = callerIdentity.Account;
  const budgetResponse = readBoundedAwsJson(
    region,
    "budgets",
    "describe-budget",
    awsBudgetDescribeArguments(accountId, budgetName)
  );
  const budget = phase(6, () => {
    if (
      !budgetResponse?.Budget ||
      typeof budgetResponse.Budget !== "object" ||
      Array.isArray(budgetResponse.Budget)
    ) {
      throw new Error("AWS_BUDGET_RECEIPT");
    }
    return budgetResponse.Budget;
  });
  const notificationResponse = readBoundedAwsJson(
    region,
    "budgets",
    "describe-notifications-for-budget",
    [
      "--account-id",
      accountId,
      "--budget-name",
      budgetName
    ]
  );
  const notifications = phase(7, () =>
    exactBudgetNotifications(notificationResponse?.Notifications)
  );
  const notificationSubscribers = phase(8, () =>
    notifications.map((notification) => {
      const response = readBoundedAwsJson(
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
      );
      if (!Array.isArray(response?.Subscribers)) {
        throw new Error("AWS_BUDGET_SUBSCRIBER_RECEIPT");
      }
      return {
        notification,
        subscribers: response.Subscribers
      };
    })
  );

  const costRequest = phase(9, () => {
    const period = awsCostExplorerPeriod(now);
    return {
      period,
      args: awsCostExplorerArguments(period)
    };
  });
  const currentCostResponse = readBoundedAwsJson(
    region,
    "ce",
    "get-cost-and-usage",
    costRequest.args
  );
  const artifactBucket = {
    versioning: readBoundedAwsJson(
      region,
      "s3api",
      "get-bucket-versioning",
      ["--bucket", bucketName]
    ),
    encryption: readBoundedAwsJson(
      region,
      "s3api",
      "get-bucket-encryption",
      ["--bucket", bucketName]
    ),
    publicAccessBlock: readBoundedAwsJson(
      region,
      "s3api",
      "get-public-access-block",
      ["--bucket", bucketName]
    ),
    ownership: readBoundedAwsJson(
      region,
      "s3api",
      "get-bucket-ownership-controls",
      ["--bucket", bucketName]
    ),
    policyStatus: readBoundedAwsJson(
      region,
      "s3api",
      "get-bucket-policy-status",
      ["--bucket", bucketName]
    ),
    policy: phase(10, () =>
      readBucketPolicy(region, bucketName, readBoundedAwsJson)
    )
  };
  const stackResponse = readBoundedAwsJson(
    region,
    "cloudformation",
    "list-stacks"
  );
  const stackSummaries = phase(11, () => {
    if (!Array.isArray(stackResponse?.StackSummaries)) {
      throw new Error("AWS_STACK_CENSUS_RECEIPT");
    }
    return stackResponse.StackSummaries;
  });
  const foundationModel = readBoundedAwsJson(
    region,
    "bedrock",
    "get-foundation-model",
    ["--model-identifier", modelId]
  );
  return phase(12, () => {
    runtimeCalls.assertComplete();
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
      artifactBucket,
      mainStackName,
      legacyMainStackName,
      stackSummaries,
      currentCost: {
        ...costRequest.period,
        response: currentCostResponse
      },
      foundationModel
    };
  });
}

export function main(argv = process.argv.slice(2)) {
  runtimePhase(14, () => {
    if (argv.length !== 0) {
      throw new Error("UNEXPECTED_ARGUMENT");
    }
  });
  const snapshot = collectSnapshot(undefined, {
    diagnosticFailureMode: true
  });
  const diagnosticContext =
    createAwsGate2PreflightDiagnosticContext();
  let receipt;
  try {
    receipt = validateAwsGate2Preflight(snapshot, {
      diagnosticFailureMode: true,
      diagnosticContext
    });
  } catch (error) {
    writeAwsPreflightRuntimeFailure(error, diagnosticContext);
    return;
  }
  runtimePhase(13, () => {
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  });
}

const startedDirectly =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    main();
  } catch (error) {
    writeAwsPreflightRuntimeFailure(error);
  }
}
