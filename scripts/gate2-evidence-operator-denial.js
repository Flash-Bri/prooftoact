import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  signDeploymentAttestationReceipt,
  validateDeploymentExpectation
} from "../src/cloud/aws-deployment-attestation.js";
import {
  assertAwsSdkEvidenceEnvironment,
  explicitAwsCredentials,
  validateAwsEvidenceCaller
} from "../src/cloud/aws-evidence-identity.js";
import { assertCleanExactGitCheckout } from "./lib/exact-git-source.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
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
  return fs.readFileSync(resolved);
}

function readPrivateJson(filePath, code) {
  try {
    return JSON.parse(readPrivateFile(filePath, code).toString("utf8"));
  } catch (error) {
    if (error?.message === code) {
      throw error;
    }
    throw new Error(code);
  }
}

function parseArguments(argv) {
  requireCondition(
    Array.isArray(argv) && argv.length === 4,
    "AWS_ATTEST_DENIAL_ARGUMENTS"
  );
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition(
      ["--expectation", "--receipt-key"].includes(name) &&
        typeof value === "string" &&
        value.length > 0 &&
        parsed[name] === undefined,
      "AWS_ATTEST_DENIAL_ARGUMENTS"
    );
    parsed[name] = value;
  }
  requireCondition(
    parsed["--expectation"] && parsed["--receipt-key"],
    "AWS_ATTEST_DENIAL_ARGUMENTS"
  );
  return Object.freeze({
    expectationPath: parsed["--expectation"],
    receiptKeyPath: parsed["--receipt-key"]
  });
}

export function safeAlternateDenialFailureCode(error) {
  const candidate = String(error?.message ?? "");
  return /^AWS_ATTEST_DENIAL_[A-Z0-9_]{1,100}$/.test(candidate)
    ? candidate
    : "AWS_ATTEST_DENIAL_UNKNOWN";
}

async function clients(credentials) {
  const {
    AssumeRoleCommand,
    GetCallerIdentityCommand,
    STSClient
  } = await import("@aws-sdk/client-sts");
  const { NodeHttpHandler } = await import("@smithy/node-http-handler");
  const client = new STSClient({
    region: "us-east-1",
    credentials,
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 8_000
    })
  });
  return {
    async assume(targetRoleArn) {
      return client.send(
        new AssumeRoleCommand({
          RoleArn: targetRoleArn,
          RoleSessionName: "tideproof-evidence-denial"
        })
      );
    },
    async identity() {
      const value = await client.send(new GetCallerIdentityCommand({}));
      return {
        Account: value.Account,
        Arn: value.Arn,
        UserId: value.UserId
      };
    }
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  assertAwsSdkEvidenceEnvironment(process.env);
  const expectation = validateDeploymentExpectation(
    readPrivateJson(
      options.expectationPath,
      "AWS_ATTEST_DENIAL_EXPECTATION_FILE"
    )
  );
  const privateKey = readPrivateFile(
    options.receiptKeyPath,
    "AWS_ATTEST_DENIAL_RECEIPT_KEY_FILE",
    { secret: true }
  );
  assertCleanExactGitCheckout({
    rootDir: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  const credentials = explicitAwsCredentials(process.env, {
    requireSessionToken: true
  });
  const expectedAccountId = process.env.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID;
  const alternatePrincipalArn =
    process.env.AWS_EVIDENCE_EXPECTED_ALTERNATE_PRINCIPAL_ARN;
  const expectedCallerArn =
    process.env.AWS_EVIDENCE_EXPECTED_ALTERNATE_CALLER_ARN;
  const expectedCallerUserId =
    process.env.AWS_EVIDENCE_EXPECTED_ALTERNATE_CALLER_USER_ID;
  requireCondition(
    expectedAccountId === expectation.accountId &&
      alternatePrincipalArn === expectation.alternatePrincipal.roleArn,
    "AWS_ATTEST_DENIAL_EXPECTATION"
  );
  const observedAt = new Date().toISOString();
  const aws = await clients(credentials);
  const callerBinding = validateAwsEvidenceCaller(await aws.identity(), {
    expectedAccountId,
    expectedPrincipalArn: alternatePrincipalArn,
    expectedCallerArn,
    expectedCallerUserId,
    bindingContext: {
      purpose: "gate2-evidence-role-alternate-denial",
      sourceCommit: expectation.sourceCommit,
      treeDigest: expectation.treeDigest,
      configDigest: expectation.configDigest,
      stackId: expectation.stackId,
      targetRoleArn: expectation.evidenceOperator.roleArn,
      observedAt
    }
  });
  let denied;
  try {
    await aws.assume(expectation.evidenceOperator.roleArn);
    throw new Error("AWS_ATTEST_DENIAL_UNEXPECTEDLY_ALLOWED");
  } catch (error) {
    if (error?.message === "AWS_ATTEST_DENIAL_UNEXPECTEDLY_ALLOWED") {
      throw error;
    }
    requireCondition(
      /accessdenied/i.test(String(error?.name ?? "")) &&
        typeof error?.$metadata?.requestId === "string" &&
        error.$metadata.requestId.length >= 8,
      "AWS_ATTEST_DENIAL_PROVIDER_RESPONSE"
    );
    denied = error;
  }
  const unsignedReceipt = {
    schemaVersion: "tideproof.gate2.aws-alternate-principal-denial.v2",
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest,
    configDigest: expectation.configDigest,
    alternatePrincipalArn,
    alternatePrincipalDigest: sha256(alternatePrincipalArn),
    callerBinding,
    errorCode: "AccessDenied",
    observedAt,
    outcome: "DENIED",
    requestIdDigest: sha256(denied.$metadata.requestId),
    targetRoleArn: expectation.evidenceOperator.roleArn
  };
  const signedReceipt = signDeploymentAttestationReceipt(
    unsignedReceipt,
    privateKey,
    expectation.receiptPublicKeys.alternateDenial
  );
  process.stdout.write(`${JSON.stringify(signedReceipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion:
          "tideproof.gate2.aws-alternate-principal-denial-error.v2",
        status: "FAIL",
        code: safeAlternateDenialFailureCode(error)
      })}\n`
    );
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({ parseArguments, sha256 });
