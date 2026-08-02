import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  deploymentAttestationDigest,
  signDeploymentAttestationReceipt,
  validateDeploymentExpectation
} from "../src/cloud/aws-deployment-attestation.js";
import {
  assertAwsSdkEvidenceEnvironment,
  explicitAwsCredentials,
  validateAwsEvidenceCaller
} from "../src/cloud/aws-evidence-identity.js";
import { validateBuildReceipt } from "./gate2-aws-readiness.js";
import {
  exactBuildRecord,
  reproduceExactBuild,
  validateExactBuildReproduction
} from "./lib/exact-build-reproduction.js";
import { assertCleanExactGitCheckout } from "./lib/exact-git-source.js";
import { loadAwsProviderRuntime } from "./lib/aws-provider-runtime-loader.js";

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

function sha256Bytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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
    Array.isArray(argv) && argv.length === 6,
    "AWS_ATTEST_DENIAL_ARGUMENTS"
  );
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition(
      ["--build-receipt", "--expectation", "--receipt-key"].includes(name) &&
        typeof value === "string" &&
        value.length > 0 &&
        parsed[name] === undefined,
      "AWS_ATTEST_DENIAL_ARGUMENTS"
    );
    parsed[name] = value;
  }
  requireCondition(
    parsed["--build-receipt"] &&
      parsed["--expectation"] &&
      parsed["--receipt-key"],
    "AWS_ATTEST_DENIAL_ARGUMENTS"
  );
  return Object.freeze({
    buildReceiptPath: parsed["--build-receipt"],
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
  const buildReceiptBytes = readPrivateFile(
    options.buildReceiptPath,
    "AWS_ATTEST_DENIAL_BUILD_RECEIPT_FILE"
  );
  const buildRecord = exactBuildRecord(
    buildReceiptBytes,
    "AWS_ATTEST_DENIAL_BUILD_RECEIPT_FILE"
  );
  const reproducedBuild = reproduceExactBuild({
    projectRoot: root,
    codePrefix: "AWS_ATTEST_DENIAL_EXACT_BUILD"
  });
  validateExactBuildReproduction(
    buildRecord,
    reproducedBuild,
    "AWS_ATTEST_DENIAL_EXACT_BUILD_MISMATCH"
  );
  const buildReceipt = buildRecord.value;
  validateBuildReceipt(buildReceipt, {
    projectRoot: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  validateBuildReceipt(reproducedBuild.value, {
    projectRoot: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  requireCondition(
    expectation.basis.buildReceiptSha256 === sha256Bytes(buildReceiptBytes) &&
      expectation.basis.providerDependencyTreeDigest ===
        buildReceipt.dependencySnapshot.treeDigest &&
      expectation.basis.providerRuntimeSha256 ===
        buildReceipt.evidenceProviderRuntime.sha256,
    "AWS_ATTEST_DENIAL_BUILD_RECEIPT_BINDING"
  );
  const providerRuntime = await loadAwsProviderRuntime({
    buildReceipt,
    projectRoot: root
  });
  const { createAwsProviderClients } = providerRuntime;
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
  const aws = await createAwsProviderClients({
    credentials,
    region: expectation.region
  });
  const callerIdentity = await aws.callerIdentity();
  let denied;
  try {
    await aws.assumeRole(expectation.evidenceOperator.roleArn);
    throw new Error("AWS_ATTEST_DENIAL_UNEXPECTEDLY_ALLOWED");
  } catch (error) {
    if (error?.message === "AWS_ATTEST_DENIAL_UNEXPECTEDLY_ALLOWED") {
      throw error;
    }
    requireCondition(
      error?.name === "AccessDenied" &&
        error?.$fault === "client" &&
        error?.$metadata?.httpStatusCode === 403 &&
        typeof error?.$metadata?.requestId === "string" &&
        /^[A-Za-z0-9-]{8,128}$/.test(error.$metadata.requestId) &&
        error.$metadata.attempts === 1 &&
        error.$metadata.totalRetryDelay === 0,
      "AWS_ATTEST_DENIAL_PROVIDER_RESPONSE"
    );
    denied = error;
  }
  const observedAt = new Date().toISOString();
  const callerBinding = validateAwsEvidenceCaller(callerIdentity, {
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
  const unsignedReceipt = {
    schemaVersion: "tideproof.gate2.aws-alternate-principal-denial.v3",
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest,
    configDigest: expectation.configDigest,
    alternatePrincipalArn,
    alternatePrincipalDigest: sha256(alternatePrincipalArn),
    callerBinding,
    errorCode: "AccessDenied",
    expectationDigest: deploymentAttestationDigest(expectation),
    observedAt,
    outcome: "DENIED",
    providerDependencyTreeDigest: buildReceipt.dependencySnapshot.treeDigest,
    providerRuntimeSha256: providerRuntime.runtimeSha256,
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
