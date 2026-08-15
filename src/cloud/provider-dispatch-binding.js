import { createHash } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";

export const PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA =
  "tideproof.provider-dispatch-control-binding.v2";
export const PROVIDER_DISPATCH_CONTROL_STATES = Object.freeze({
  ABSENT: "ABSENT",
  COMPLETED: "COMPLETED",
  CREDENTIAL_REDEEMED: "CREDENTIAL_REDEEMED",
  EXECUTING: "EXECUTING",
  EXPIRED: "EXPIRED",
  GRANTED: "GRANTED",
  UNKNOWN_DO_NOT_ACT: "UNKNOWN_DO_NOT_ACT"
});

export const PROVIDER_DISPATCH_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const PROVIDER_DISPATCH_HEX_64 = /^[0-9a-f]{64}$/u;

const HEX_40 = /^[0-9a-f]{40}$/u;
const BINDING_KEYS = Object.freeze([
  "authorizationId",
  "controlBindingSha256",
  "expiresAt",
  "interactionId",
  "issuedAt",
  "logicalMcpRequestSha256",
  "providerDispatchAuthorizationSha256",
  "providerEffectKeySha256",
  "runId",
  "schemaVersion",
  "sourceBuildIdentity",
  "sourceCommit",
  "tenantId",
  "treeDigest"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactRecord(value, keys) {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) return false;
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length &&
    ownKeys.every((key) => typeof key === "string" && keys.includes(key)) &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactIso(value) {
  if (typeof value !== "string") return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value
    ? value
    : null;
}

export function providerDispatchSha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function providerDispatchEffectKeySha256({
  logicalMcpRequestSha256,
  recoveryClusterId
}) {
  if (
    !PROVIDER_DISPATCH_HEX_64.test(logicalMcpRequestSha256 ?? "") ||
    !PROVIDER_DISPATCH_UUID.test(recoveryClusterId ?? "")
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_BINDING_REJECTED");
  }
  return providerDispatchSha256(canonicalJson({
    schemaVersion: "tideproof.provider-effect-key.v1",
    database: "tideproof_recovery",
    logicalMcpRequestSha256,
    provider: "cockroachdb-managed-mcp",
    recoveryClusterId,
    tool: "select_query"
  }));
}

export function buildProviderDispatchControlBinding({
  context,
  dispatchAuthorizationSha256,
  earliestControllingExpiry,
  latestControllingIssuedAt
}) {
  const intent = context?.preCallIntent;
  const spec = context?.trustedRunContext?.spec;
  const issuedAt = Number.isSafeInteger(latestControllingIssuedAt)
    ? new Date(latestControllingIssuedAt).toISOString()
    : null;
  const expiresAt = Number.isSafeInteger(earliestControllingExpiry)
    ? new Date(earliestControllingExpiry).toISOString()
    : null;
  const body = {
    authorizationId: intent?.authorizationId,
    expiresAt,
    interactionId: intent?.interactionId,
    issuedAt,
    logicalMcpRequestSha256: intent?.logicalMcpRequestSha256,
    providerDispatchAuthorizationSha256: dispatchAuthorizationSha256,
    providerEffectKeySha256: providerDispatchEffectKeySha256({
      logicalMcpRequestSha256: intent?.logicalMcpRequestSha256,
      recoveryClusterId: intent?.recoveryClusterId
    }),
    runId: intent?.runId,
    schemaVersion: PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
    sourceBuildIdentity: spec?.sourceBuildIdentity,
    sourceCommit: spec?.sourceCommit,
    tenantId: intent?.tenantId,
    treeDigest: spec?.treeDigest
  };
  return validateProviderDispatchControlBinding(Object.freeze({
    ...body,
    controlBindingSha256: providerDispatchSha256(canonicalJson(body))
  }));
}

export function validateProviderDispatchControlBinding(value) {
  const issuedAt = exactIso(value?.issuedAt);
  const expiresAt = exactIso(value?.expiresAt);
  if (
    !exactRecord(value, BINDING_KEYS) ||
    value.schemaVersion !== PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA ||
    !PROVIDER_DISPATCH_UUID.test(value.authorizationId ?? "") ||
    !PROVIDER_DISPATCH_UUID.test(value.interactionId ?? "") ||
    !PROVIDER_DISPATCH_UUID.test(value.runId ?? "") ||
    !PROVIDER_DISPATCH_UUID.test(value.tenantId ?? "") ||
    !HEX_40.test(value.sourceCommit ?? "") ||
    !HEX_40.test(value.treeDigest ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(value.sourceBuildIdentity ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(value.logicalMcpRequestSha256 ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(
      value.providerDispatchAuthorizationSha256 ?? ""
    ) ||
    !PROVIDER_DISPATCH_HEX_64.test(value.providerEffectKeySha256 ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(value.controlBindingSha256 ?? "") ||
    issuedAt === null || expiresAt === null ||
    Date.parse(issuedAt) >= Date.parse(expiresAt)
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_BINDING_REJECTED");
  }
  const body = Object.fromEntries(
    BINDING_KEYS.filter((key) => key !== "controlBindingSha256")
      .map((key) => [key, value[key]])
  );
  if (
    providerDispatchSha256(canonicalJson(body)) !== value.controlBindingSha256
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_BINDING_REJECTED");
  }
  return Object.freeze({ ...value });
}
