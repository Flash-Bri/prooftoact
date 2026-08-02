import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  DEPLOYMENT_FUNCTIONS,
  deploymentAttestationDigest,
  signDeploymentAttestationReceipt,
  validateDeploymentAttestationPair,
  validateDeploymentEvidenceBasis,
  validateDeploymentExpectation,
  validateDeploymentSnapshot
} from "../src/cloud/aws-deployment-attestation.js";
import {
  assertAwsSdkEvidenceEnvironment,
  isolatedAwsCliEnvironment
} from "../src/cloud/aws-evidence-identity.js";
import {
  exactNpmCli,
  isolatedEnvironment
} from "./build-gate2-exact.js";
import { validateBuildReceipt } from "./gate2-aws-readiness.js";
import { assertCleanExactGitCheckout } from "./lib/exact-git-source.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const LOGICAL_TITLES = Object.freeze({
  agent: "Agent",
  authority: "Authority",
  boundary: "Boundary",
  demo: "Demo",
  signer: "Signer"
});

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function exactBuildRecord(bytes, code) {
  requireCondition(
    Buffer.isBuffer(bytes) &&
      bytes.length > 0 &&
      bytes.length <= 5 * 1024 * 1024,
    code
  );
  try {
    return Object.freeze({
      bytes,
      digest: sha256(bytes),
      value: JSON.parse(bytes.toString("utf8"))
    });
  } catch {
    throw new Error(code);
  }
}

function reproduceExactBuild() {
  const npmCli = exactNpmCli(process.env);
  const result = spawnSync(
    process.execPath,
    [npmCli, "run", "--silent", "build:gate2"],
    {
      cwd: root,
      encoding: null,
      env: {
        ...isolatedEnvironment(process.env),
        npm_execpath: npmCli,
        npm_node_execpath: process.execPath
      },
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  requireCondition(
    !result.error && result.status === 0,
    "AWS_ATTEST_EXACT_BUILD_REPRODUCTION"
  );
  return exactBuildRecord(
    result.stdout,
    "AWS_ATTEST_EXACT_BUILD_RECEIPT"
  );
}

function validateExactBuildReproduction(provided, reproduced) {
  requireCondition(
    provided &&
      reproduced &&
      Buffer.isBuffer(provided.bytes) &&
      Buffer.isBuffer(reproduced.bytes) &&
      provided.digest === sha256(provided.bytes) &&
      reproduced.digest === sha256(reproduced.bytes) &&
      provided.digest === reproduced.digest &&
      provided.bytes.equals(reproduced.bytes),
    "AWS_ATTEST_EXACT_BUILD_MISMATCH"
  );
  return Object.freeze({
    buildReceiptSha256: provided.digest,
    reproducedBuildReceiptSha256: reproduced.digest
  });
}

function readPrivateFile(filePath, code, { secret = false } = {}) {
  const resolved = path.resolve(process.cwd(), filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0 &&
      stat.size <= 5 * 1024 * 1024 &&
      (!secret || (stat.mode & 0o077) === 0),
    code
  );
  const bytes = fs.readFileSync(resolved);
  return Object.freeze({ bytes, digest: sha256(bytes), path: resolved });
}

function readPrivateJson(filePath, code) {
  const record = readPrivateFile(filePath, code);
  try {
    return Object.freeze({
      ...record,
      value: JSON.parse(record.bytes.toString("utf8"))
    });
  } catch {
    throw new Error(code);
  }
}

function commandJson(service, operation, args = []) {
  const result = spawnSync(
    "aws",
    [
      service,
      operation,
      ...args,
      "--region",
      "us-east-1",
      "--output",
      "json",
      "--no-cli-pager"
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: isolatedAwsCliEnvironment(process.env, {
        requireSessionToken: true
      }),
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"]
    }
  );
  requireCondition(
    !result.error && result.status === 0,
    `AWS_ATTEST_COLLECT_${service.toUpperCase()}_${operation
      .replaceAll("-", "_")
      .toUpperCase()}`
  );
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error("AWS_ATTEST_COLLECT_JSON");
  }
}

function parseArguments(argv) {
  requireCondition(
    Array.isArray(argv) && argv.every((value) => typeof value === "string"),
    "AWS_ATTEST_ARGUMENTS"
  );
  const allowed = new Set([
    "--alternate-denial",
    "--build-receipt",
    "--configuration",
    "--expectation",
    "--phase",
    "--pre-receipt",
    "--receipt-key"
  ]);
  const parsed = {};
  requireCondition(argv.length % 2 === 0, "AWS_ATTEST_ARGUMENTS");
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition(
      allowed.has(name) &&
        typeof value === "string" &&
        value.length > 0 &&
        parsed[name] === undefined,
      "AWS_ATTEST_ARGUMENTS"
    );
    parsed[name] = value;
  }
  const phase = parsed["--phase"];
  for (const name of [
    "--build-receipt",
    "--configuration",
    "--expectation",
    "--receipt-key"
  ]) {
    requireCondition(parsed[name], "AWS_ATTEST_ARGUMENTS");
  }
  requireCondition(["pre", "post"].includes(phase), "AWS_ATTEST_ARGUMENTS");
  if (phase === "pre") {
    requireCondition(
      parsed["--pre-receipt"] === undefined &&
        parsed["--alternate-denial"] === undefined,
      "AWS_ATTEST_ARGUMENTS"
    );
  } else {
    requireCondition(
      parsed["--pre-receipt"] && parsed["--alternate-denial"],
      "AWS_ATTEST_ARGUMENTS"
    );
  }
  return Object.freeze({
    alternateDenialPath: parsed["--alternate-denial"],
    buildReceiptPath: parsed["--build-receipt"],
    configurationPath: parsed["--configuration"],
    expectationPath: parsed["--expectation"],
    phase,
    preReceiptPath: parsed["--pre-receipt"],
    receiptKeyPath: parsed["--receipt-key"]
  });
}

function exactOne(values, predicate, code) {
  const matches = (values ?? []).filter(predicate);
  requireCondition(matches.length === 1, code);
  return matches[0];
}

function roleName(roleArn) {
  const match = /:role\/([A-Za-z0-9+=,.@_-]{1,64})$/.exec(roleArn);
  requireCondition(match, "AWS_ATTEST_COLLECT_ROLE_ARN");
  return match[1];
}

function stackParameter(stack, key) {
  return exactOne(
    stack.Parameters,
    (candidate) => candidate.ParameterKey === key,
    `AWS_ATTEST_COLLECT_PARAMETER_${key.toUpperCase()}`
  ).ParameterValue;
}

function parsedTemplateBody(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      requireCondition(
        parsed && typeof parsed === "object" && !Array.isArray(parsed),
        "AWS_ATTEST_COLLECT_TEMPLATE"
      );
      return parsed;
    } catch (error) {
      if (error?.message === "AWS_ATTEST_COLLECT_TEMPLATE") {
        throw error;
      }
    }
  }
  throw new Error("AWS_ATTEST_COLLECT_TEMPLATE");
}

function driftFor(resourceDrifts, logicalResourceId) {
  const drift = exactOne(
    resourceDrifts,
    (candidate) => candidate.LogicalResourceId === logicalResourceId,
    `AWS_ATTEST_COLLECT_DRIFT_${logicalResourceId.toUpperCase()}`
  );
  return drift.StackResourceDriftStatus;
}

function stackResourceBinding(
  stackResources,
  logicalResourceId,
  resourceType,
  physicalResourceId
) {
  const resource = exactOne(
    stackResources,
    (candidate) => candidate.LogicalResourceId === logicalResourceId,
    "AWS_ATTEST_COLLECT_STACK_RESOURCE"
  );
  requireCondition(
    resource.ResourceType === resourceType &&
      resource.PhysicalResourceId === physicalResourceId &&
      ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(resource.ResourceStatus),
    "AWS_ATTEST_COLLECT_STACK_RESOURCE_BINDING"
  );
  return Object.freeze({
    physicalResourceId: resource.PhysicalResourceId,
    resourceStatus: resource.ResourceStatus,
    resourceType: resource.ResourceType
  });
}

function stackResourceBindings(expectation, stackResources) {
  const bindings = {};
  for (const name of DEPLOYMENT_FUNCTIONS) {
    const title = LOGICAL_TITLES[name];
    const expected = expectation.functions[name];
    bindings[`${title}Alias`] = stackResourceBinding(
      stackResources,
      `${title}Alias`,
      "AWS::Lambda::Alias",
      expected.aliasArn
    );
    bindings[`${title}Function`] = stackResourceBinding(
      stackResources,
      `${title}Function`,
      "AWS::Lambda::Function",
      expected.functionName
    );
    bindings[`${title}Role`] = stackResourceBinding(
      stackResources,
      `${title}Role`,
      "AWS::IAM::Role",
      roleName(expected.roleArn)
    );
    bindings[`${title}Version`] = stackResourceBinding(
      stackResources,
      `${title}Version`,
      "AWS::Lambda::Version",
      expected.numericVersionArn
    );
  }
  bindings.DeploymentEvidenceAlternateRole = stackResourceBinding(
    stackResources,
    "DeploymentEvidenceAlternateRole",
    "AWS::IAM::Role",
    roleName(expectation.alternatePrincipal.roleArn)
  );
  bindings.DeploymentEvidenceRole = stackResourceBinding(
    stackResources,
    "DeploymentEvidenceRole",
    "AWS::IAM::Role",
    roleName(expectation.evidenceOperator.roleArn)
  );
  return Object.freeze(
    Object.fromEntries(
      Object.entries(bindings).sort(([left], [right]) =>
        left.localeCompare(right)
      )
    )
  );
}

async function freshDrift(stackName) {
  const started = commandJson("cloudformation", "detect-stack-drift", [
    "--stack-name",
    stackName
  ]);
  const detectionId = started.StackDriftDetectionId;
  requireCondition(
    typeof detectionId === "string" && detectionId.length >= 20,
    "AWS_ATTEST_COLLECT_DRIFT_ID"
  );
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const result = commandJson(
      "cloudformation",
      "describe-stack-drift-detection-status",
      ["--stack-drift-detection-id", detectionId]
    );
    if (result.DetectionStatus === "DETECTION_COMPLETE") {
      requireCondition(
        result.StackDriftStatus === "IN_SYNC",
        "AWS_ATTEST_COLLECT_STACK_DRIFT"
      );
      return result.StackDriftStatus;
    }
    requireCondition(
      result.DetectionStatus === "DETECTION_IN_PROGRESS",
      "AWS_ATTEST_COLLECT_DRIFT_STATUS"
    );
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error("AWS_ATTEST_COLLECT_DRIFT_TIMEOUT");
}

function roleSnapshot(roleArn, resourceDrift) {
  const name = roleName(roleArn);
  const role = commandJson("iam", "get-role", ["--role-name", name]).Role;
  const inline = commandJson("iam", "list-role-policies", [
    "--role-name",
    name
  ]);
  const attached = commandJson("iam", "list-attached-role-policies", [
    "--role-name",
    name
  ]);
  requireCondition(
    inline.IsTruncated !== true &&
      attached.IsTruncated !== true &&
      Array.isArray(inline.PolicyNames) &&
      inline.PolicyNames.length <= 16 &&
      Array.isArray(attached.AttachedPolicies) &&
      attached.AttachedPolicies.length <= 16,
    "AWS_ATTEST_COLLECT_ROLE_CENSUS"
  );
  return {
    arn: role.Arn,
    attachedManagedPolicies: attached.AttachedPolicies.map((policy) => ({
      policyArn: policy.PolicyArn,
      policyName: policy.PolicyName
    })).sort((left, right) => left.policyArn.localeCompare(right.policyArn)),
    inlinePolicies: inline.PolicyNames.map((policyName) => ({
      document: commandJson("iam", "get-role-policy", [
        "--role-name",
        name,
        "--policy-name",
        policyName
      ]).PolicyDocument,
      name: policyName
    })).sort((left, right) => left.name.localeCompare(right.name)),
    maxSessionDuration: role.MaxSessionDuration,
    permissionsBoundary: role.PermissionsBoundary
      ? {
          arn: role.PermissionsBoundary.PermissionsBoundaryArn,
          type: role.PermissionsBoundary.PermissionsBoundaryType
        }
      : null,
    resourceDrift,
    roleId: role.RoleId,
    trustPolicy: role.AssumeRolePolicyDocument
  };
}

function normalizedFunctionConfiguration(configuration) {
  return {
    architectures: configuration.Architectures ?? [],
    deadLetterTargetArn: configuration.DeadLetterConfig?.TargetArn ?? null,
    environment: configuration.Environment?.Variables ?? {},
    ephemeralStorageSize: configuration.EphemeralStorage?.Size ?? null,
    fileSystemConfigs: (configuration.FileSystemConfigs ?? [])
      .map((item) => ({ arn: item.Arn, localMountPath: item.LocalMountPath }))
      .sort((left, right) => left.arn.localeCompare(right.arn)),
    handler: configuration.Handler,
    kmsKeyArn: configuration.KMSKeyArn ?? null,
    layers: (configuration.Layers ?? [])
      .map((layer) => ({ arn: layer.Arn, codeSize: layer.CodeSize }))
      .sort((left, right) => left.arn.localeCompare(right.arn)),
    loggingConfig: {
      applicationLogLevel:
        configuration.LoggingConfig?.ApplicationLogLevel ?? null,
      logFormat: configuration.LoggingConfig?.LogFormat ?? null,
      logGroup: configuration.LoggingConfig?.LogGroup ?? null,
      systemLogLevel: configuration.LoggingConfig?.SystemLogLevel ?? null
    },
    memorySize: configuration.MemorySize,
    packageType: configuration.PackageType,
    runtime: configuration.Runtime,
    runtimeVersion: {
      errorCode: configuration.RuntimeVersionConfig?.Error?.ErrorCode ?? null,
      errorMessage:
        configuration.RuntimeVersionConfig?.Error?.Message ?? null,
      runtimeVersionArn:
        configuration.RuntimeVersionConfig?.RuntimeVersionArn ?? null
    },
    signingJobArn: configuration.SigningJobArn ?? null,
    signingProfileVersionArn:
      configuration.SigningProfileVersionArn ?? null,
    snapStartApplyOn: configuration.SnapStart?.ApplyOn ?? "None",
    timeout: configuration.Timeout,
    tracingMode: configuration.TracingConfig?.Mode ?? null,
    vpcConfig: {
      ipv6AllowedForDualStack:
        configuration.VpcConfig?.Ipv6AllowedForDualStack ?? false,
      securityGroupIds: [...(configuration.VpcConfig?.SecurityGroupIds ?? [])]
        .sort(),
      subnetIds: [...(configuration.VpcConfig?.SubnetIds ?? [])].sort(),
      vpcId: configuration.VpcConfig?.VpcId ?? null
    }
  };
}

function functionSnapshot(name, expected, resourceDrifts) {
  const title = LOGICAL_TITLES[name];
  const configuration = commandJson(
    "lambda",
    "get-function-configuration",
    ["--function-name", expected.numericVersionArn]
  );
  const concurrency = commandJson(
    "lambda",
    "get-function-concurrency",
    ["--function-name", expected.functionName]
  );
  const alias = commandJson("lambda", "get-alias", [
    "--function-name",
    expected.functionName,
    "--name",
    "proof"
  ]);
  return {
    aliasArn: alias.AliasArn,
    aliasName: alias.Name,
    aliasRevisionId: alias.RevisionId,
    aliasRoutingConfiguration: alias.RoutingConfig ?? {},
    aliasTargetVersion: alias.FunctionVersion,
    codeSha256: configuration.CodeSha256,
    configuration: normalizedFunctionConfiguration(configuration),
    functionArn: expected.functionArn,
    functionName: configuration.FunctionName,
    lastUpdateStatus: configuration.LastUpdateStatus,
    numericRevisionId: configuration.RevisionId,
    numericVersion: configuration.Version,
    numericVersionArn: configuration.FunctionArn,
    reservedConcurrency: concurrency.ReservedConcurrentExecutions,
    resourceDrift: {
      alias: driftFor(resourceDrifts, `${title}Alias`),
      function: driftFor(resourceDrifts, `${title}Function`),
      role: driftFor(resourceDrifts, `${title}Role`),
      version: driftFor(resourceDrifts, `${title}Version`)
    },
    role: roleSnapshot(
      configuration.Role,
      driftFor(resourceDrifts, `${title}Role`)
    ),
    state: configuration.State
  };
}

async function collectState(expectation) {
  const stackResponse = commandJson("cloudformation", "describe-stacks", [
    "--stack-name",
    expectation.stackName
  ]);
  const stack = exactOne(
    stackResponse.Stacks,
    (candidate) => candidate.StackId === expectation.stackId,
    "AWS_ATTEST_COLLECT_STACK"
  );
  const driftStatus = await freshDrift(expectation.stackName);
  const driftResponse = commandJson(
    "cloudformation",
    "describe-stack-resource-drifts",
    ["--stack-name", expectation.stackName]
  );
  const template = commandJson("cloudformation", "get-template", [
    "--stack-name",
    expectation.stackName,
    "--template-stage",
    "Processed"
  ]);
  const stackResources = commandJson(
    "cloudformation",
    "describe-stack-resources",
    ["--stack-name", expectation.stackName]
  );
  const resourceDrifts = driftResponse.StackResourceDrifts ?? [];
  return {
    alternatePrincipalRole: roleSnapshot(
      expectation.alternatePrincipal.roleArn,
      driftFor(resourceDrifts, "DeploymentEvidenceAlternateRole")
    ),
    callerIdentity: commandJson("sts", "get-caller-identity"),
    evidenceOperatorRole: roleSnapshot(
      expectation.evidenceOperator.roleArn,
      driftFor(resourceDrifts, "DeploymentEvidenceRole")
    ),
    functions: Object.fromEntries(
      DEPLOYMENT_FUNCTIONS.map((name) => [
        name,
        functionSnapshot(name, expectation.functions[name], resourceDrifts)
      ])
    ),
    region: expectation.region,
    stack: {
      bindings: {
        configDigest: stackParameter(stack, "ConfigDigest"),
        sourceCommit: stackParameter(stack, "SourceCommit"),
        treeDigest: stackParameter(stack, "TreeDigest")
      },
      driftStatus,
      resourceBindings: stackResourceBindings(
        expectation,
        stackResources.StackResources ?? []
      ),
      stackId: stack.StackId,
      stackName: stack.StackName,
      stackStatus: stack.StackStatus,
      templateCanonicalDigest: deploymentAttestationDigest(
        parsedTemplateBody(template.TemplateBody)
      )
    }
  };
}

async function collectSnapshot(expectation, phase) {
  const startedAt = new Date().toISOString();
  const first = await collectState(expectation);
  const firstStateDigest = deploymentAttestationDigest(first);
  const second = await collectState(expectation);
  const secondStateDigest = deploymentAttestationDigest(second);
  requireCondition(
    firstStateDigest === secondStateDigest,
    "AWS_ATTEST_COLLECT_REVISION_FENCE"
  );
  const completedAt = new Date().toISOString();
  return {
    ...second,
    observationFence: {
      completedAt,
      firstStateDigest,
      secondStateDigest,
      startedAt
    },
    observedAt: completedAt,
    phase
  };
}

export function safeAwsAttestationFailureCode(error) {
  const candidate = String(error?.message ?? "");
  return /^AWS_ATTEST_[A-Z0-9_]{1,120}$/.test(candidate)
    ? candidate
    : "AWS_ATTEST_UNKNOWN";
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  assertAwsSdkEvidenceEnvironment(process.env);
  const expectationRecord = readPrivateJson(
    options.expectationPath,
    "AWS_ATTEST_EXPECTATION_FILE"
  );
  const configurationRecord = readPrivateJson(
    options.configurationPath,
    "AWS_ATTEST_CONFIGURATION_FILE"
  );
  const buildRecord = readPrivateJson(
    options.buildReceiptPath,
    "AWS_ATTEST_BUILD_RECEIPT_FILE"
  );
  const keyRecord = readPrivateFile(
    options.receiptKeyPath,
    "AWS_ATTEST_RECEIPT_KEY_FILE",
    { secret: true }
  );
  const expectation = validateDeploymentExpectation(expectationRecord.value);
  assertCleanExactGitCheckout({
    rootDir: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  const reproducedBuild = reproduceExactBuild();
  validateBuildReceipt(buildRecord.value, {
    projectRoot: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  validateBuildReceipt(reproducedBuild.value, {
    projectRoot: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  validateExactBuildReproduction(buildRecord, reproducedBuild);
  validateDeploymentEvidenceBasis({
    expectation,
    configuration: configurationRecord.value,
    buildReceipt: buildRecord.value,
    configurationSha256: configurationRecord.digest,
    buildReceiptSha256: buildRecord.digest
  });
  const expectedCallerArn =
    process.env.AWS_EVIDENCE_EXPECTED_ATTESTATION_CALLER_ARN;
  const expectedCallerUserId =
    process.env.AWS_EVIDENCE_EXPECTED_ATTESTATION_CALLER_USER_ID;
  const snapshot = await collectSnapshot(expectation, options.phase);
  const callerExpectation = {
    expectedCallerArn,
    expectedCallerUserId
  };
  const unsignedSnapshotReceipt = validateDeploymentSnapshot(
    snapshot,
    expectation,
    callerExpectation
  );
  const signedSnapshotReceipt = signDeploymentAttestationReceipt(
    unsignedSnapshotReceipt,
    keyRecord.bytes,
    expectation.receiptPublicKeys[options.phase]
  );
  let receipt = signedSnapshotReceipt;
  if (options.phase === "post") {
    const pair = validateDeploymentAttestationPair({
      preReceipt: readPrivateJson(
        options.preReceiptPath,
        "AWS_ATTEST_PRE_RECEIPT_FILE"
      ).value,
      postReceipt: signedSnapshotReceipt,
      expectation,
      alternateDenial: readPrivateJson(
        options.alternateDenialPath,
        "AWS_ATTEST_ALTERNATE_DENIAL_FILE"
      ).value
    });
    receipt = signDeploymentAttestationReceipt(
      pair,
      keyRecord.bytes,
      expectation.receiptPublicKeys.post
    );
  }
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion: "tideproof.gate2.aws-deployment-attestation-error.v2",
        status: "FAIL",
        code: safeAwsAttestationFailureCode(error)
      })}\n`
    );
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  collectSnapshot,
  exactBuildRecord,
  normalizedFunctionConfiguration,
  parseArguments,
  parsedTemplateBody,
  validateExactBuildReproduction,
  roleName,
  roleSnapshot,
  stackResourceBindings
});
