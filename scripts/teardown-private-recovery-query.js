import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  CloudFormationClient,
  DeleteStackCommand,
  DescribeStacksCommand,
  UpdateTerminationProtectionCommand
} from "@aws-sdk/client-cloudformation";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { validateSignedPrivateRecoveryDeploymentEvidence } from
  "../src/cloud/private-recovery-query-evidence.js";
import { validatePrivateRecoveryQueryReceipt } from
  "../src/cloud/private-recovery-query.js";

const STACK_NAME = "prooftoact-private-recovery-query";
const TABLE_NAME = "prooftoact-release-controller";
const CONFIRMATION = "DELETE_PROOFTOACT_PRIVATE_RECOVERY_QUERY_AFTER_POST_EVIDENCE";

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
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_CREDENTIALS_REJECTED");
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

function readPublicKey(filePath) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= 4096,
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_PUBLIC_KEY_REJECTED");
  const value = fs.readFileSync(resolved, "utf8").trim();
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length > 0 && bytes.length <= 1024 &&
    bytes.toString("base64") === value,
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_PUBLIC_KEY_REJECTED");
  return value;
}

function writeExclusive(filePath, value) {
  const resolved = path.resolve(filePath);
  requireCondition(!fs.existsSync(resolved),
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_OUTPUT_REJECTED");
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

function decodeTerminal(item, operationGlobalKeySha256, expectedReceiptSha256) {
  const code = "PRIVATE_RECOVERY_QUERY_TEARDOWN_TERMINAL_REJECTED";
  requireCondition(item?.pk?.S ===
      `PRIVATE_RECOVERY_QUERY#${operationGlobalKeySha256}` &&
    item.status?.S === "FINAL" && item.version?.N === "2" &&
    item.receipt?.B !== undefined, code);
  const bytes = Buffer.from(item.receipt.B);
  requireCondition(bytes.length > 0 && bytes.length <= 128 * 1024, code);
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch (cause) {
    reject(code, cause);
  }
  requireCondition(canonicalJson(parsed) === bytes.toString("utf8"), code);
  const receipt = validatePrivateRecoveryQueryReceipt(parsed);
  requireCondition(receipt.status === "PASS" &&
    receipt.receiptSha256 === expectedReceiptSha256, code);
  return receipt;
}

function absentStackError(cause) {
  return cause?.name === "ValidationError" &&
    /does not exist|does not exist$/iu.test(cause?.message ?? "");
}

async function describeStack(cloudformation) {
  try {
    const response = await cloudformation.send(new DescribeStacksCommand({
      StackName: STACK_NAME
    }));
    requireCondition(Array.isArray(response?.Stacks) && response.Stacks.length === 1,
      "PRIVATE_RECOVERY_QUERY_TEARDOWN_STACK_REJECTED");
    return response.Stacks[0];
  } catch (cause) {
    if (absentStackError(cause)) return null;
    throw cause;
  }
}

function validateExactStack(stack, evidence, cloudFormationServiceRoleArn) {
  requireCondition(stack?.StackName === STACK_NAME &&
    typeof stack.StackId === "string" &&
    sha256(stack.StackId) === evidence.snapshot.stackIdSha256 &&
    stack.RoleARN === cloudFormationServiceRoleArn,
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_STACK_REJECTED");
  return stack;
}

async function reconcileProtection({
  clients,
  cloudFormationServiceRoleArn,
  evidence,
  enable,
  stack
}) {
  validateExactStack(stack, evidence, cloudFormationServiceRoleArn);
  try {
    await clients.cloudformation.send(new UpdateTerminationProtectionCommand({
      StackName: stack.StackId,
      EnableTerminationProtection: enable
    }));
  } catch (cause) {
    const observed = await describeStack(clients.cloudformation);
    validateExactStack(observed, evidence, cloudFormationServiceRoleArn);
    requireCondition(observed.EnableTerminationProtection === enable,
      enable
        ? "PRIVATE_RECOVERY_QUERY_TEARDOWN_REPROTECTION_ACK_UNKNOWN"
        : "PRIVATE_RECOVERY_QUERY_TEARDOWN_PROTECTION_ACK_UNKNOWN");
    return observed;
  }
  const observed = await describeStack(clients.cloudformation);
  validateExactStack(observed, evidence, cloudFormationServiceRoleArn);
  requireCondition(observed.EnableTerminationProtection === enable,
    enable
      ? "PRIVATE_RECOVERY_QUERY_TEARDOWN_REPROTECTION_REJECTED"
      : "PRIVATE_RECOVERY_QUERY_TEARDOWN_PROTECTION_REJECTED");
  return observed;
}

export async function teardownPrivateRecoveryQuery({
  clients,
  clock = () => new Date(),
  cloudFormationServiceRoleArn,
  confirmation,
  operationGlobalKeySha256,
  postEvidenceReceipt,
  publicKeySpkiBase64,
  maximumPollAttempts = 120,
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds))
}) {
  const code = "PRIVATE_RECOVERY_QUERY_TEARDOWN_INPUT_REJECTED";
  requireCondition(confirmation === CONFIRMATION &&
    /^[0-9a-f]{64}$/u.test(operationGlobalKeySha256 ?? "") &&
    Number.isSafeInteger(maximumPollAttempts) && maximumPollAttempts >= 1 &&
    maximumPollAttempts <= 120 &&
    /^arn:aws:iam::[0-9]{12}:role\/ProofToActPrivateRecoveryQueryCloudFormation$/u
      .test(cloudFormationServiceRoleArn ?? ""), code);
  const evidence = validateSignedPrivateRecoveryDeploymentEvidence({
    publicKeySpkiBase64,
    receipt: postEvidenceReceipt
  });
  requireCondition(evidence.phase === "POST_QUERY" &&
    evidence.snapshot.operation.state === "FINAL", code);
  const [identity, item] = await Promise.all([
    clients.sts.send(new GetCallerIdentityCommand({})),
    clients.dynamodb.send(new GetItemCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: { S: `PRIVATE_RECOVERY_QUERY#${operationGlobalKeySha256}` }
      },
      ConsistentRead: true,
      ReturnConsumedCapacity: "NONE"
    }))
  ]);
  requireCondition(/^[0-9]{12}$/u.test(identity?.Account ?? "") &&
    new RegExp(`^arn:aws:sts::${identity.Account}:assumed-role/` +
      "ProofToActPrivateRecoveryQueryTeardown/[A-Za-z0-9+=,.@_-]{1,64}$", "u")
      .test(identity.Arn ?? "") && typeof identity.UserId === "string",
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_IDENTITY_REJECTED");
  const operationReceipt = decodeTerminal(item?.Item, operationGlobalKeySha256,
    evidence.snapshot.operation.receiptSha256);
  const startedAt = clock();
  requireCondition(startedAt instanceof Date && Number.isFinite(startedAt.getTime()),
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_CLOCK_REJECTED");
  let stack = await describeStack(clients.cloudformation);
  let absent = stack === null;
  if (stack !== null) {
    validateExactStack(stack, evidence, cloudFormationServiceRoleArn);
    if (stack.StackStatus === "DELETE_FAILED") {
      if (stack.EnableTerminationProtection !== true) {
        await reconcileProtection({
          clients,
          cloudFormationServiceRoleArn,
          enable: true,
          evidence,
          stack
        });
      }
      reject("PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_FAILED_HOLD");
    }
    requireCondition(["CREATE_COMPLETE", "DELETE_IN_PROGRESS"].includes(
      stack.StackStatus), "PRIVATE_RECOVERY_QUERY_TEARDOWN_STACK_REJECTED");
    if (stack.StackStatus === "CREATE_COMPLETE") {
      if (stack.EnableTerminationProtection === true) {
        stack = await reconcileProtection({
          clients,
          cloudFormationServiceRoleArn,
          enable: false,
          evidence,
          stack
        });
      } else {
        requireCondition(stack.EnableTerminationProtection === false,
          "PRIVATE_RECOVERY_QUERY_TEARDOWN_PROTECTION_REJECTED");
      }
      requireCondition(stack.StackStatus === "CREATE_COMPLETE",
        "PRIVATE_RECOVERY_QUERY_TEARDOWN_STACK_REJECTED");
      try {
        await clients.cloudformation.send(new DeleteStackCommand({
          StackName: stack.StackId,
          RoleARN: cloudFormationServiceRoleArn,
          ClientRequestToken:
            `pta-private-recovery-delete-${operationReceipt.operationId}`
        }));
      } catch (cause) {
        const observed = await describeStack(clients.cloudformation);
        requireCondition(observed === null ||
          observed.StackStatus === "DELETE_IN_PROGRESS",
        "PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_ACK_UNKNOWN");
        if (observed !== null) {
          validateExactStack(observed, evidence, cloudFormationServiceRoleArn);
        }
      }
    }
  }
  for (let attempt = 0; !absent && attempt < maximumPollAttempts; attempt += 1) {
    const observed = await describeStack(clients.cloudformation);
    if (observed === null) {
      absent = true;
      break;
    }
    validateExactStack(observed, evidence, cloudFormationServiceRoleArn);
    requireCondition(observed.StackStatus === "DELETE_IN_PROGRESS",
      "PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_REJECTED");
    await wait(5_000);
  }
  requireCondition(absent,
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_TIMEOUT");
  const completedAt = clock();
  requireCondition(completedAt instanceof Date && Number.isFinite(completedAt.getTime()) &&
    completedAt.getTime() >= startedAt.getTime(),
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_CLOCK_REJECTED");
  const body = Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-teardown-receipt.v1",
    status: "STACK_ABSENT",
    accountIdSha256: sha256(identity.Account),
    callerArnSha256: sha256(identity.Arn),
    completedAt: completedAt.toISOString(),
    operationReceiptSha256: operationReceipt.receiptSha256,
    postEvidenceReceiptSha256: evidence.receiptSha256,
    sourceCommit: evidence.sourceCommit,
    stackIdSha256: evidence.snapshot.stackIdSha256,
    startedAt: startedAt.toISOString(),
    treeDigest: evidence.treeDigest
  });
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

function parseArguments(args) {
  const names = [
    "--cloudformation-service-role-arn", "--confirmation",
    "--evidence-public-key-file", "--operation-global-key-sha256",
    "--post-evidence-receipt", "--receipt-output"
  ];
  requireCondition(args.length === names.length * 2,
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_ARGUMENT_REJECTED");
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    requireCondition(names.includes(args[index]) && parsed[args[index]] === undefined &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_TEARDOWN_ARGUMENT_REJECTED");
    parsed[args[index]] = args[index + 1];
  }
  return parsed;
}

export async function main(args = process.argv.slice(2), environment = process.env) {
  const parsed = parseArguments(args);
  requireCondition(environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1",
  "PRIVATE_RECOVERY_QUERY_TEARDOWN_ENVIRONMENT_REJECTED");
  const credentials = explicitCredentials(environment);
  const options = sdkOptions(credentials);
  const receipt = await teardownPrivateRecoveryQuery({
    clients: {
      cloudformation: new CloudFormationClient(options),
      dynamodb: new DynamoDBClient(options),
      sts: new STSClient(options)
    },
    cloudFormationServiceRoleArn: parsed["--cloudformation-service-role-arn"],
    confirmation: parsed["--confirmation"],
    operationGlobalKeySha256: parsed["--operation-global-key-sha256"],
    postEvidenceReceipt: readCanonicalJson(
      parsed["--post-evidence-receipt"], 256 * 1024,
      "PRIVATE_RECOVERY_QUERY_TEARDOWN_EVIDENCE_REJECTED"
    ),
    publicKeySpkiBase64: readPublicKey(parsed["--evidence-public-key-file"])
  });
  writeExclusive(parsed["--receipt-output"], receipt);
  process.stdout.write(`PRIVATE_RECOVERY_QUERY_TEARDOWN_PASS:${receipt.receiptSha256}\n`);
  return receipt;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch(() => {
    process.stderr.write("PRIVATE_RECOVERY_QUERY_TEARDOWN_CLI_HOLD\n");
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  CONFIRMATION,
  absentStackError,
  decodeTerminal,
  explicitCredentials,
  parseArguments,
  reconcileProtection,
  sdkOptions,
  sha256,
  validateExactStack
});
