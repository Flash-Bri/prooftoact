import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  CloudFormationClient,
  CreateChangeSetCommand,
  DescribeChangeSetCommand,
  DescribeStacksCommand,
  ExecuteChangeSetCommand,
  GetTemplateCommand,
  UpdateTerminationProtectionCommand
} from "@aws-sdk/client-cloudformation";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { canonicalJson } from "../src/cloud/canonical-json.js";

const STACK_NAME = "prooftoact-private-recovery-query";

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

function explicitCredentials(environment) {
  const value = Object.freeze({
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  });
  requireCondition(/^ASIA[A-Z0-9]{16}$/u.test(value.accessKeyId ?? "") &&
    typeof value.secretAccessKey === "string" &&
    value.secretAccessKey.length === 40 &&
    typeof value.sessionToken === "string" && value.sessionToken.length >= 16,
  "PRIVATE_RECOVERY_QUERY_DEPLOY_CREDENTIALS_REJECTED");
  return value;
}

function sdkOptions(credentials) {
  return {
    authSchemePreference: ["sigv4"],
    credentials,
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    region: "us-east-1",
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 15_000
    }),
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
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

function writeExclusive(filePath, value) {
  const resolved = path.resolve(filePath);
  requireCondition(!fs.existsSync(resolved),
    "PRIVATE_RECOVERY_QUERY_DEPLOY_OUTPUT_REJECTED");
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const descriptor = fs.openSync(resolved,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, `${canonicalJson(value)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseTemplateBody(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= 1024 * 1024,
  "PRIVATE_RECOVERY_QUERY_DEPLOY_TEMPLATE_REJECTED");
  try {
    const parsed = JSON.parse(value);
    requireCondition(parsed && typeof parsed === "object" &&
      !Array.isArray(parsed), "PRIVATE_RECOVERY_QUERY_DEPLOY_TEMPLATE_REJECTED");
    return parsed;
  } catch (cause) {
    reject("PRIVATE_RECOVERY_QUERY_DEPLOY_TEMPLATE_REJECTED", cause);
  }
}

function parameterMap(value, code) {
  requireCondition(Array.isArray(value), code);
  const result = {};
  for (const entry of value) {
    requireCondition(entry && typeof entry === "object" &&
      typeof entry.ParameterKey === "string" &&
      typeof entry.ParameterValue === "string" &&
      result[entry.ParameterKey] === undefined &&
      entry.UsePreviousValue !== true, code);
    result[entry.ParameterKey] = entry.ParameterValue;
  }
  return Object.freeze(Object.fromEntries(Object.entries(result).sort(
    ([left], [right]) => left.localeCompare(right)
  )));
}

function validateInputs({
  cloudFormationServiceRoleArn,
  privateInput,
  sanitizedIntent,
  template
}) {
  const code = "PRIVATE_RECOVERY_QUERY_DEPLOY_INPUT_REJECTED";
  requireCondition(
    /^arn:aws:iam::[0-9]{12}:role\/ProofToActPrivateRecoveryQueryCloudFormation$/u
      .test(cloudFormationServiceRoleArn ?? "") &&
    privateInput?.schemaVersion ===
      "prooftoact.private-recovery-query-deployment-private-input.v1" &&
    sanitizedIntent?.schemaVersion ===
      "prooftoact.private-recovery-query-deployment-intent.v1" &&
    sanitizedIntent.status === "READY_FOR_CREATE_CHANGE_SET" &&
    /^[0-9a-f]{64}$/u.test(sanitizedIntent.intentSha256 ?? "") &&
    /^[0-9a-f]{40}$/u.test(sanitizedIntent.sourceCommit ?? "") &&
    /^[0-9a-f]{40}$/u.test(sanitizedIntent.treeDigest ?? "") &&
    /^[0-9a-f]{64}$/u.test(sanitizedIntent.templateSha256 ?? "") &&
    /^[0-9a-f]{64}$/u.test(sanitizedIntent.operationGlobalKeySha256 ?? "") &&
    Array.isArray(privateInput.parameters) &&
    privateInput.cloudFormationServiceRoleArn === cloudFormationServiceRoleArn &&
    privateInput.configRecord?.sourceCommit === sanitizedIntent.sourceCommit &&
    privateInput.configRecord?.treeDigest === sanitizedIntent.treeDigest &&
    privateInput.configSha256 === sanitizedIntent.configSha256 &&
    privateInput.configRecord?.operationGlobalKeySha256 ===
      sanitizedIntent.operationGlobalKeySha256 &&
    privateInput.configRecord?.templateSha256 ===
      sanitizedIntent.templateSha256 &&
    sanitizedIntent.intentSha256 === digest(Object.fromEntries(
      Object.entries(sanitizedIntent).filter(([key]) => key !== "intentSha256")
    )) && digest(template) === sanitizedIntent.templateSha256,
  code);
  const expectedParameters = parameterMap(privateInput.parameters, code);
  requireCondition(expectedParameters.SourceCommit === sanitizedIntent.sourceCommit &&
    expectedParameters.TreeDigest === sanitizedIntent.treeDigest &&
    expectedParameters.TemplateSha256 === sanitizedIntent.templateSha256 &&
    expectedParameters.CloudFormationServiceRoleArn ===
      cloudFormationServiceRoleArn &&
    expectedParameters.OperationGlobalKeySha256 ===
      sanitizedIntent.operationGlobalKeySha256, code);
  return Object.freeze({
    changeSetName:
      `prooftoact-private-recovery-query-create-${sanitizedIntent.intentSha256}`,
    clientToken: `pta-prq-${sanitizedIntent.intentSha256}`,
    description:
      `ProofToAct private recovery exact CREATE ${sanitizedIntent.intentSha256}`,
    expectedParameters
  });
}

function absentStackError(cause) {
  return cause?.name === "ValidationError" &&
    /does not exist/iu.test(cause?.message ?? "");
}

function absentChangeSetError(cause) {
  return ["ChangeSetNotFound", "ValidationError"].includes(cause?.name) &&
    /does not exist|not found/iu.test(cause?.message ?? "");
}

async function describeStack(cloudformation) {
  try {
    const result = await cloudformation.send(new DescribeStacksCommand({
      StackName: STACK_NAME
    }));
    requireCondition(Array.isArray(result?.Stacks) && result.Stacks.length === 1,
      "PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_REJECTED");
    return result.Stacks[0];
  } catch (cause) {
    if (absentStackError(cause)) return null;
    throw cause;
  }
}

async function describeChangeSet(cloudformation, changeSetName) {
  try {
    return await cloudformation.send(new DescribeChangeSetCommand({
      ChangeSetName: changeSetName,
      IncludePropertyValues: true,
      StackName: STACK_NAME
    }));
  } catch (cause) {
    if (absentChangeSetError(cause)) return null;
    throw cause;
  }
}

async function getProviderTemplate(cloudformation, input) {
  const response = await cloudformation.send(new GetTemplateCommand(input));
  return parseTemplateBody(response?.TemplateBody);
}

async function validateStack({
  cloudformation,
  cloudFormationServiceRoleArn,
  expectedParameters,
  expectedTemplateSha256,
  stack
}) {
  const code = "PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_REJECTED";
  requireCondition(stack?.StackName === STACK_NAME &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-private-recovery-query\/[0-9a-f-]{36}$/u
      .test(stack.StackId ?? "") &&
    stack.RoleARN === cloudFormationServiceRoleArn &&
    canonicalJson(parameterMap(stack.Parameters, code)) ===
      canonicalJson(expectedParameters), code);
  const observedTemplate = await getProviderTemplate(cloudformation, {
    StackName: stack.StackId,
    TemplateStage: "Processed"
  });
  requireCondition(digest(observedTemplate) === expectedTemplateSha256, code);
  return stack;
}

async function validateChangeSet({
  changeSet,
  cloudformation,
  cloudFormationServiceRoleArn,
  coordinates,
  expectedTemplateSha256
}) {
  const code = "PRIVATE_RECOVERY_QUERY_DEPLOY_CHANGE_SET_REJECTED";
  requireCondition(changeSet?.ChangeSetName === coordinates.changeSetName &&
    changeSet.StackName === STACK_NAME &&
    changeSet.ChangeSetType === "CREATE" &&
    changeSet.Description === coordinates.description &&
    changeSet.RoleARN === cloudFormationServiceRoleArn &&
    changeSet.IncludeNestedStacks === false &&
    canonicalJson(changeSet.Capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    changeSet.Status === "CREATE_COMPLETE" &&
    ["AVAILABLE", "EXECUTE_IN_PROGRESS", "EXECUTE_COMPLETE"].includes(
      changeSet.ExecutionStatus) &&
    canonicalJson(parameterMap(changeSet.Parameters, code)) ===
      canonicalJson(coordinates.expectedParameters), code);
  const observedTemplate = await getProviderTemplate(cloudformation, {
    ChangeSetName: changeSet.ChangeSetId ?? coordinates.changeSetName,
    StackName: STACK_NAME,
    TemplateStage: "Original"
  });
  requireCondition(digest(observedTemplate) === expectedTemplateSha256, code);
  return changeSet;
}

async function reconcileProtection({
  cloudformation,
  cloudFormationServiceRoleArn,
  coordinates,
  expectedTemplateSha256,
  stack
}) {
  if (stack.EnableTerminationProtection === true) return stack;
  requireCondition(stack.EnableTerminationProtection === false,
    "PRIVATE_RECOVERY_QUERY_DEPLOY_PROTECTION_REJECTED");
  try {
    await cloudformation.send(new UpdateTerminationProtectionCommand({
      EnableTerminationProtection: true,
      StackName: stack.StackId
    }));
  } catch (cause) {
    const observed = await describeStack(cloudformation);
    await validateStack({
      cloudformation,
      cloudFormationServiceRoleArn,
      expectedParameters: coordinates.expectedParameters,
      expectedTemplateSha256,
      stack: observed
    });
    requireCondition(observed.EnableTerminationProtection === true,
      "PRIVATE_RECOVERY_QUERY_DEPLOY_PROTECTION_ACK_UNKNOWN");
    return observed;
  }
  const observed = await describeStack(cloudformation);
  await validateStack({
    cloudformation,
    cloudFormationServiceRoleArn,
    expectedParameters: coordinates.expectedParameters,
    expectedTemplateSha256,
    stack: observed
  });
  requireCondition(observed.EnableTerminationProtection === true,
    "PRIVATE_RECOVERY_QUERY_DEPLOY_PROTECTION_REJECTED");
  return observed;
}

export async function deployPrivateRecoveryQuery({
  clients,
  clock = () => new Date(),
  cloudFormationServiceRoleArn,
  maximumPollAttempts = 120,
  privateInput,
  sanitizedIntent,
  template,
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))
}) {
  requireCondition(Number.isSafeInteger(maximumPollAttempts) &&
    maximumPollAttempts >= 1 && maximumPollAttempts <= 120,
  "PRIVATE_RECOVERY_QUERY_DEPLOY_INPUT_REJECTED");
  const coordinates = validateInputs({
    cloudFormationServiceRoleArn,
    privateInput,
    sanitizedIntent,
    template
  });
  const startedAt = clock();
  requireCondition(startedAt instanceof Date && Number.isFinite(startedAt.getTime()),
    "PRIVATE_RECOVERY_QUERY_DEPLOY_CLOCK_REJECTED");
  let stack = await describeStack(clients.cloudformation);
  if (stack === null) {
    let changeSet = await describeChangeSet(
      clients.cloudformation, coordinates.changeSetName
    );
    if (changeSet === null) {
      try {
        await clients.cloudformation.send(new CreateChangeSetCommand({
          Capabilities: ["CAPABILITY_NAMED_IAM"],
          ChangeSetName: coordinates.changeSetName,
          ChangeSetType: "CREATE",
          ClientToken: coordinates.clientToken,
          Description: coordinates.description,
          IncludeNestedStacks: false,
          OnStackFailure: "DELETE",
          Parameters: privateInput.parameters,
          RoleARN: cloudFormationServiceRoleArn,
          StackName: STACK_NAME,
          TemplateBody: canonicalJson(template)
        }));
      } catch (cause) {
        changeSet = await describeChangeSet(
          clients.cloudformation, coordinates.changeSetName
        );
        requireCondition(changeSet !== null,
          "PRIVATE_RECOVERY_QUERY_DEPLOY_CHANGE_SET_ACK_UNKNOWN");
      }
    }
  }
  let acceptedChangeSet = false;
  for (let attempt = 0; attempt < maximumPollAttempts; attempt += 1) {
    stack = await describeStack(clients.cloudformation);
    if (stack !== null && ["CREATE_IN_PROGRESS", "CREATE_COMPLETE"].includes(
      stack.StackStatus)) break;
    requireCondition(stack === null || stack.StackStatus === "REVIEW_IN_PROGRESS",
      "PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_REJECTED");
    const changeSet = await describeChangeSet(
      clients.cloudformation, coordinates.changeSetName
    );
    if (changeSet === null) {
      await wait(5_000);
      continue;
    }
    if (changeSet?.Status === "CREATE_PENDING" ||
        changeSet?.Status === "CREATE_IN_PROGRESS") {
      await wait(5_000);
      continue;
    }
    await validateChangeSet({
      changeSet,
      cloudformation: clients.cloudformation,
      cloudFormationServiceRoleArn,
      coordinates,
      expectedTemplateSha256: sanitizedIntent.templateSha256
    });
    if (changeSet.ExecutionStatus === "AVAILABLE") {
      try {
        await clients.cloudformation.send(new ExecuteChangeSetCommand({
          ChangeSetName: changeSet.ChangeSetId ?? coordinates.changeSetName,
          ClientRequestToken: coordinates.clientToken,
          DisableRollback: false,
          StackName: STACK_NAME
        }));
      } catch (cause) {
        const observed = await describeStack(clients.cloudformation);
        requireCondition(observed !== null &&
          ["CREATE_IN_PROGRESS", "CREATE_COMPLETE"].includes(
            observed.StackStatus),
        "PRIVATE_RECOVERY_QUERY_DEPLOY_EXECUTE_ACK_UNKNOWN");
      }
      acceptedChangeSet = true;
    } else {
      acceptedChangeSet = true;
    }
    await wait(5_000);
  }
  stack = await describeStack(clients.cloudformation);
  requireCondition(stack !== null &&
    ["CREATE_IN_PROGRESS", "CREATE_COMPLETE"].includes(stack.StackStatus),
  acceptedChangeSet
    ? "PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_TIMEOUT"
    : "PRIVATE_RECOVERY_QUERY_DEPLOY_CHANGE_SET_TIMEOUT");
  for (let attempt = 0; attempt < maximumPollAttempts; attempt += 1) {
    stack = await describeStack(clients.cloudformation);
    requireCondition(stack !== null &&
      ["CREATE_IN_PROGRESS", "CREATE_COMPLETE"].includes(stack.StackStatus),
    "PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_REJECTED");
    await validateStack({
      cloudformation: clients.cloudformation,
      cloudFormationServiceRoleArn,
      expectedParameters: coordinates.expectedParameters,
      expectedTemplateSha256: sanitizedIntent.templateSha256,
      stack
    });
    if (stack.StackStatus === "CREATE_COMPLETE") break;
    await wait(5_000);
  }
  requireCondition(stack?.StackStatus === "CREATE_COMPLETE",
    "PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_TIMEOUT");
  stack = await reconcileProtection({
    cloudformation: clients.cloudformation,
    cloudFormationServiceRoleArn,
    coordinates,
    expectedTemplateSha256: sanitizedIntent.templateSha256,
    stack
  });
  const completedAt = clock();
  requireCondition(completedAt instanceof Date &&
    Number.isFinite(completedAt.getTime()) &&
    completedAt.getTime() >= startedAt.getTime(),
  "PRIVATE_RECOVERY_QUERY_DEPLOY_CLOCK_REJECTED");
  const body = Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-deployment-receipt.v2",
    status: "CREATE_COMPLETE_READBACK_PENDING_EVIDENCE_ROLE",
    completedAt: completedAt.toISOString(),
    deploymentIntentSha256: sanitizedIntent.intentSha256,
    sourceCommit: sanitizedIntent.sourceCommit,
    stackIdSha256: sha256(stack.StackId),
    startedAt: startedAt.toISOString(),
    terminationProtection: true,
    treeDigest: sanitizedIntent.treeDigest
  });
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

function parseArguments(args) {
  const names = [
    "--cloudformation-service-role-arn", "--intent-file", "--private-input-file",
    "--receipt-output", "--template-file"
  ];
  requireCondition(args.length === names.length * 2,
    "PRIVATE_RECOVERY_QUERY_DEPLOY_ARGUMENT_REJECTED");
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    requireCondition(names.includes(args[index]) && parsed[args[index]] === undefined &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_DEPLOY_ARGUMENT_REJECTED");
    parsed[args[index]] = args[index + 1];
  }
  return parsed;
}

export async function main(args = process.argv.slice(2), environment = process.env) {
  const parsed = parseArguments(args);
  requireCondition(environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1",
  "PRIVATE_RECOVERY_QUERY_DEPLOY_ENVIRONMENT_REJECTED");
  const credentials = explicitCredentials(environment);
  const receipt = await deployPrivateRecoveryQuery({
    clients: {
      cloudformation: new CloudFormationClient(sdkOptions(credentials))
    },
    cloudFormationServiceRoleArn: parsed["--cloudformation-service-role-arn"],
    privateInput: readCanonicalJson(parsed["--private-input-file"], 256 * 1024,
      "PRIVATE_RECOVERY_QUERY_DEPLOY_INPUT_REJECTED"),
    sanitizedIntent: readCanonicalJson(parsed["--intent-file"], 64 * 1024,
      "PRIVATE_RECOVERY_QUERY_DEPLOY_INPUT_REJECTED"),
    template: readCanonicalJson(parsed["--template-file"], 1024 * 1024,
      "PRIVATE_RECOVERY_QUERY_DEPLOY_INPUT_REJECTED")
  });
  writeExclusive(parsed["--receipt-output"], receipt);
  process.stdout.write(`PRIVATE_RECOVERY_QUERY_DEPLOY_PASS:${receipt.receiptSha256}\n`);
  return receipt;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch((cause) => {
    const code = /^PRIVATE_RECOVERY_QUERY_[A-Z0-9_]{1,120}$/u.test(
      cause?.message ?? ""
    ) ? cause.message : "PRIVATE_RECOVERY_QUERY_DEPLOY_UNKNOWN_HOLD";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  absentChangeSetError,
  absentStackError,
  digest,
  explicitCredentials,
  parameterMap,
  parseArguments,
  sdkOptions,
  sha256,
  validateChangeSet,
  validateInputs,
  validateStack
});
