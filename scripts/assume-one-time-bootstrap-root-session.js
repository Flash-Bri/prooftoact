import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  AssumeRoleCommand,
  GetCallerIdentityCommand,
  STSClient
} from "@aws-sdk/client-sts";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import {
  oneTimeBootstrapConstants,
  rootLoginProfileMetadataSha256,
  validateBootstrapSessionReceipt,
  validateBootstrapTrustRequest,
  verifyRootMfaDiscoveryReceipt,
  verifyOneTimeBootstrapPlan
} from "./prepare-one-time-bootstrap-authority.js";

const AMBIENT_CREDENTIAL_ENVIRONMENT_KEYS = Object.freeze([
  "AWS_ACCESS_KEY_ID",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_ROLE_ARN",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_WEB_IDENTITY_TOKEN_FILE"
]);
const REDIRECT_OR_ENDPOINT_ENVIRONMENT_KEYS = Object.freeze([
  "AWS_CA_BUNDLE",
  "AWS_CONFIG_FILE",
  "AWS_DEFAULT_PROFILE",
  "AWS_SHARED_CREDENTIALS_FILE"
]);
const ROOT_STS_CONNECTION_TIMEOUT_MS = 5_000;
const ROOT_STS_REQUEST_TIMEOUT_MS = 30_000;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && Object.keys(value).sort().join("\n") ===
      [...keys].sort().join("\n");
}

function canonicalInstant(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

function readExactRootLoginProfile(plan) {
  const code = "ONE_TIME_BOOTSTRAP_ROOT_PROFILE_CONFIG_REJECTED";
  const configPath = path.join(os.homedir(), ".aws", "config");
  let descriptor;
  try {
    descriptor = fs.openSync(configPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= 256 * 1024, code);
    const source = fs.readFileSync(descriptor, "utf8");
    const after = fs.fstatSync(descriptor);
    requireCondition(before.dev === after.dev && before.ino === after.ino &&
      before.mode === after.mode && before.size === after.size, code);
    const sections = new Map();
    let current = null;
    for (const rawLine of source.split(/\r?\n/u)) {
      const line = rawLine.trim();
      if (line === "" || line.startsWith("#") || line.startsWith(";")) {
        continue;
      }
      const section = line.match(/^\[([^\]]+)\]$/u);
      if (section) {
        requireCondition(!sections.has(section[1]), code);
        current = new Map();
        sections.set(section[1], current);
        continue;
      }
      const setting = line.match(/^([A-Za-z0-9_]+)\s*=\s*(\S(?:.*\S)?)$/u);
      requireCondition(current !== null && setting !== null &&
        !current.has(setting[1]), code);
      current.set(setting[1], setting[2]);
    }
    const sectionName = plan.account.rootProfile === "default" ?
      "default" : `profile ${plan.account.rootProfile}`;
    const profile = sections.get(sectionName);
    const configuredRegion = profile?.has("region") ?
      profile.get("region") : null;
    const expectedKeys = configuredRegion === null ?
      ["login_session"] : ["login_session", "region"];
    requireCondition(profile instanceof Map &&
      [...profile.keys()].sort().join("\n") ===
        expectedKeys.join("\n") &&
      profile.get("login_session") ===
        plan.account.rootProfileLoginSessionArn &&
      configuredRegion === plan.account.rootProfileConfiguredRegion &&
      (configuredRegion === null ||
        configuredRegion === oneTimeBootstrapConstants.REGION) &&
      plan.account.rootProfileEffectiveRegion ===
        oneTimeBootstrapConstants.REGION, code);
    const metadataSha256 = rootLoginProfileMetadataSha256({
      configuredRegion,
      effectiveRegion: oneTimeBootstrapConstants.REGION,
      loginSessionArn: profile.get("login_session"),
      profile: plan.account.rootProfile
    });
    requireCondition(metadataSha256 ===
      plan.account.rootProfileConfigSha256, code);
    return Object.freeze({
      configPath,
      configuredRegion,
      effectiveRegion: oneTimeBootstrapConstants.REGION,
      loginSessionArn: profile.get("login_session"),
      metadataSha256,
      profile: plan.account.rootProfile,
      region: oneTimeBootstrapConstants.REGION
    });
  } catch (error) {
    if (error?.message === code) throw error;
    reject(code, error);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readSixDigitMfaTokenOnce(mfaFd) {
  const code = "ONE_TIME_BOOTSTRAP_ROOT_MFA_FD_REJECTED";
  requireCondition(Number.isSafeInteger(mfaFd) && mfaFd >= 3 && mfaFd <= 1024,
    code);
  let stat;
  try {
    stat = fs.fstatSync(mfaFd);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(!stat.isFile() && !stat.isDirectory() &&
    stat.uid === process.getuid() && (stat.mode & 0o077) === 0, code);
  const bytes = Buffer.alloc(7);
  let count;
  try {
    count = fs.readSync(mfaFd, bytes, 0, bytes.length, null);
    requireCondition(count === 6 && /^[0-9]{6}$/u.test(
      bytes.subarray(0, count).toString("ascii")
    ), code);
    return bytes.subarray(0, count).toString("ascii");
  } finally {
    bytes.fill(0);
  }
}

export function createNamedRootProfileStsClient(planValue) {
  const code = "ONE_TIME_BOOTSTRAP_ROOT_PROFILE_REJECTED";
  const plan = verifyOneTimeBootstrapPlan(planValue);
  requireCondition(AMBIENT_CREDENTIAL_ENVIRONMENT_KEYS.every((key) =>
    process.env[key] === undefined) &&
    REDIRECT_OR_ENDPOINT_ENVIRONMENT_KEYS.every((key) =>
      process.env[key] === undefined) &&
    !Object.keys(process.env).some((key) =>
      key.startsWith("AWS_ENDPOINT_URL")) &&
    process.env.AWS_PROFILE === plan.account.rootProfile &&
    process.env.AWS_EC2_METADATA_DISABLED === "true", code);
  readExactRootLoginProfile(plan);
  return new STSClient(rootStsClientConfiguration());
}

export function rootStsClientConfiguration() {
  return {
    maxAttempts: 1,
    region: oneTimeBootstrapConstants.REGION,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: ROOT_STS_CONNECTION_TIMEOUT_MS,
      requestTimeout: ROOT_STS_REQUEST_TIMEOUT_MS
    })
  };
}

export async function assumeOneTimeBootstrapRootSession(input) {
  const code = "ONE_TIME_BOOTSTRAP_ROOT_ASSUME_REJECTED";
  requireCondition(exactKeys(input, [
    "clock",
    "mfaDiscoveryReceipt",
    "mfaFd",
    "plan",
    "stsClient"
  ]) && typeof input.clock === "function" &&
    input.stsClient !== null && typeof input.stsClient.send === "function",
  code);
  const plan = verifyOneTimeBootstrapPlan(input.plan);
  verifyRootMfaDiscoveryReceipt(plan, input.mfaDiscoveryReceipt);
  const identity = await input.stsClient.send(new GetCallerIdentityCommand({}));
  requireCondition(identity?.Account === plan.account.accountId &&
    identity?.Arn === plan.account.rootPrincipalArn, code);
  const requestTime = input.clock();
  requireCondition(requestTime instanceof Date &&
    Number.isFinite(requestTime.getTime()), code);
  validateBootstrapTrustRequest(plan, {
    currentTime: requestTime.toISOString(),
    mfaAgeSeconds: 0,
    mfaAuthenticated: true,
    mfaSerialArn: plan.account.mfaSerialArn,
    principalArn: identity.Arn,
    roleSessionName: plan.sessionContract.roleSessionName,
    sessionTags: plan.sessionContract.sessionTags,
    sourceIdentity: plan.sessionContract.sourceIdentity
  });
  let tokenCode = readSixDigitMfaTokenOnce(input.mfaFd);
  const assumeInput = {
    DurationSeconds: oneTimeBootstrapConstants.SESSION_DURATION_SECONDS,
    RoleArn: plan.bootstrapRole.arn,
    RoleSessionName: plan.sessionContract.roleSessionName,
    SerialNumber: plan.account.mfaSerialArn,
    SourceIdentity: plan.sessionContract.sourceIdentity,
    Tags: plan.sessionContract.sessionTags.map(({ Key, Value }) => ({
      Key,
      Value
    })),
    TokenCode: tokenCode
  };
  let response;
  const dispatchTime = input.clock();
  requireCondition(dispatchTime instanceof Date &&
    Number.isFinite(dispatchTime.getTime()) &&
    dispatchTime.getTime() < Date.parse(plan.notAfter), code);
  try {
    response = await input.stsClient.send(new AssumeRoleCommand(assumeInput));
  } catch (error) {
    reject(
      "ONE_TIME_BOOTSTRAP_ROOT_ASSUME_AMBIGUOUS_RECONCILE_CLOUDTRAIL",
      error
    );
  } finally {
    tokenCode = null;
    assumeInput.TokenCode = "000000";
  }
  const credentials = response?.Credentials;
  const expiration = credentials?.Expiration;
  requireCondition(typeof credentials?.AccessKeyId === "string" &&
    credentials.AccessKeyId.length >= 16 &&
    typeof credentials?.SecretAccessKey === "string" &&
    credentials.SecretAccessKey.length >= 16 &&
    typeof credentials?.SessionToken === "string" &&
    credentials.SessionToken.length >= 16 && expiration instanceof Date &&
    Number.isFinite(expiration.getTime()) &&
    response?.AssumedRoleUser?.Arn ===
      `arn:aws:sts::${plan.account.accountId}:assumed-role/` +
      `${plan.bootstrapRole.name}/${plan.sessionContract.roleSessionName}`,
  code);
  const issuedAt = new Date(expiration.getTime() -
    oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000);
  requireCondition(issuedAt.getTime() >= requestTime.getTime() - 5_000 &&
    issuedAt.getTime() <= input.clock().getTime(), code);
  const sanitizedReceipt = {
    schemaVersion: "prooftoact.one-time-bootstrap-session-receipt.v1",
    status: "SANITIZED_PROVIDER_SESSION_ACCEPTED",
    accountId: plan.account.accountId,
    operationId: plan.operation.operationId,
    roleArn: plan.bootstrapRole.arn,
    assumedRoleArn: response.AssumedRoleUser.Arn,
    roleSessionName: plan.sessionContract.roleSessionName,
    sourceIdentity: plan.sessionContract.sourceIdentity,
    mfaAuthenticated: true,
    mfaSerialArn: plan.account.mfaSerialArn,
    durationSeconds: oneTimeBootstrapConstants.SESSION_DURATION_SECONDS,
    issuedAt: issuedAt.toISOString(),
    credentialsExpiration: expiration.toISOString(),
    rawCredentialFieldsPresent: false,
    credentialMaterialLogged: false
  };
  validateBootstrapSessionReceipt(plan, sanitizedReceipt);
  let liveCredentials = {
    accessKeyId: credentials.AccessKeyId,
    expiration,
    secretAccessKey: credentials.SecretAccessKey,
    sessionToken: credentials.SessionToken
  };
  response.Credentials = undefined;
  let consumed = false;
  function destroy() {
    if (liveCredentials !== null) {
      liveCredentials.accessKeyId = null;
      liveCredentials.expiration = null;
      liveCredentials.secretAccessKey = null;
      liveCredentials.sessionToken = null;
      liveCredentials = null;
    }
    consumed = true;
  }
  return Object.freeze({
    receipt: Object.freeze({ ...sanitizedReceipt }),
    async withPrivateCredentials(callback) {
      requireCondition(typeof callback === "function" &&
        liveCredentials !== null && consumed === false, code);
      consumed = true;
      const oneUseCredentials = liveCredentials;
      liveCredentials = null;
      try {
        return await callback(oneUseCredentials);
      } finally {
        oneUseCredentials.accessKeyId = null;
        oneUseCredentials.expiration = null;
        oneUseCredentials.secretAccessKey = null;
        oneUseCredentials.sessionToken = null;
      }
    },
    destroy
  });
}

export const rootAssumeRuntimeConstants = Object.freeze({
  AMBIENT_CREDENTIAL_ENVIRONMENT_KEYS,
  REDIRECT_OR_ENDPOINT_ENVIRONMENT_KEYS,
  ROOT_STS_CONNECTION_TIMEOUT_MS,
  ROOT_STS_REQUEST_TIMEOUT_MS
});
