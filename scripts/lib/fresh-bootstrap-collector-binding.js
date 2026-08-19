import crypto from "node:crypto";

import {
  freshPrimaryCredentialOperationToken
} from "../prepare-fresh-primary-credential-custody.js";

const ACCOUNT = /^[0-9]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ROLE_ID = /^AROA[A-Z0-9]{16}$/u;
const ASSUMED_USER = /^(AROA[A-Z0-9]{16}):([A-Za-z0-9+=,.@_-]{2,64})$/u;
const ROLE_PATH = "/prooftoact/bootstrap/";

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function validateFreshBootstrapCollectorBinding(value, expected = {}) {
  const code = "FRESH_BOOTSTRAP_COLLECTOR_BINDING_REJECTED";
  requireCondition(exactKeys(value, [
    "accountId", "assumedRoleArn", "operationId", "operationToken",
    "operatorAuthorizationSha256", "roleArn", "roleName", "rolePath",
    "sessionName", "sourceCommit", "sourceIdentity", "treeDigest"
  ]) && exactKeys(expected, [
    "accountId", "operationId", "operatorAuthorizationSha256",
    "sourceCommit", "treeDigest"
  ]) && ACCOUNT.test(value.accountId ?? "") &&
    UUID.test(value.operationId ?? "") && HEX_40.test(value.sourceCommit ?? "") &&
    HEX_40.test(value.treeDigest ?? "") &&
    HEX_64.test(value.operatorAuthorizationSha256 ?? "") &&
    value.accountId === expected.accountId &&
    value.operationId === expected.operationId &&
    value.operatorAuthorizationSha256 ===
      expected.operatorAuthorizationSha256 &&
    value.sourceCommit === expected.sourceCommit &&
    value.treeDigest === expected.treeDigest, code);
  const operationToken = freshPrimaryCredentialOperationToken(
    value.operationId
  );
  const roleName = `ProofToActBootstrapCreator-${operationToken}`;
  const roleArn = `arn:aws:iam::${value.accountId}:role` +
    `${ROLE_PATH}${roleName}`;
  const sessionName = `prooftoact-bootstrap-${operationToken}`;
  const rebuilt = {
    accountId: value.accountId,
    assumedRoleArn: `arn:aws:sts::${value.accountId}:assumed-role/` +
      `${roleName}/${sessionName}`,
    operationId: value.operationId,
    operationToken,
    operatorAuthorizationSha256: value.operatorAuthorizationSha256,
    roleArn,
    roleName,
    rolePath: ROLE_PATH,
    sessionName,
    sourceCommit: value.sourceCommit,
    sourceIdentity: `prooftoact-b0-${operationToken}`,
    treeDigest: value.treeDigest
  };
  requireCondition(Object.entries(rebuilt).every(([key, expectedValue]) =>
    value[key] === expectedValue), code);
  return Object.freeze(rebuilt);
}

export function validateFreshBootstrapCollectorCaller(value, binding) {
  const code = "FRESH_BOOTSTRAP_COLLECTOR_CALLER_REJECTED";
  const user = ASSUMED_USER.exec(value?.UserId ?? "");
  requireCondition(exactKeys(value, ["Account", "Arn", "UserId"]) &&
    value.Account === binding.accountId &&
    value.Arn === binding.assumedRoleArn && user && ROLE_ID.test(user[1]) &&
    user[2] === binding.sessionName, code);
  return Object.freeze({
    accountId: binding.accountId,
    assumedRoleArnSha256: sha256(value.Arn),
    operationToken: binding.operationToken,
    operatorAuthorizationSha256: binding.operatorAuthorizationSha256,
    roleId: user[1],
    roleName: binding.roleName,
    sessionName: binding.sessionName,
    sourceCommit: binding.sourceCommit,
    sourceIdentity: binding.sourceIdentity,
    treeDigest: binding.treeDigest
  });
}

export const __test = Object.freeze({
  ACCOUNT,
  ASSUMED_USER,
  HEX_40,
  HEX_64,
  ROLE_ID,
  ROLE_PATH,
  UUID,
  exactKeys,
  plainObject,
  sha256
});
