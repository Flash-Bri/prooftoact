import crypto from "node:crypto";

export const REGION = "us-east-1";
export const TABLE_NAME = "prooftoact-release-controller";
export const APP_SOURCE = Object.freeze({
  repository: "Flash-Bri/prooftoact",
  commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
  tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
});
export const ARTIFACT_NAMES = Object.freeze([
  "agent", "authority", "boundary", "demo", "probe", "signer"
]);
export const PARAMETER_KEYS = Object.freeze([
  "AgentArtifactCodeSha256",
  "AgentArtifactDigest",
  "AgentArtifactKey",
  "AgentArtifactVersion",
  "AgentSourceDigest",
  "ArtifactBucket",
  "AuthorityArtifactCodeSha256",
  "AuthorityArtifactDigest",
  "AuthorityArtifactKey",
  "AuthorityArtifactVersion",
  "AuthorityDatabaseHost",
  "AuthorityDatabasePort",
  "AuthorityDatabaseSecretArn",
  "AuthorityDatabaseSecretVersionId",
  "AuthorityIncidentId",
  "AuthorityResourceId",
  "AuthoritySourceDigest",
  "AuthorityTenantId",
  "BedrockModelId",
  "BoundaryArtifactCodeSha256",
  "BoundaryArtifactDigest",
  "BoundaryArtifactKey",
  "BoundaryArtifactVersion",
  "BoundarySourceDigest",
  "ConfigDigest",
  "DemoArtifactCodeSha256",
  "DemoArtifactDigest",
  "DemoArtifactKey",
  "DemoArtifactVersion",
  "DemoSourceDigest",
  "EnableProbeFunctions",
  "EvidenceOperatorPrincipalArn",
  "PackageLockDigest",
  "ProbeArtifactCodeSha256",
  "ProbeArtifactDigest",
  "ProbeArtifactKey",
  "ProbeArtifactVersion",
  "ProbeSourceDigest",
  "SignerArtifactCodeSha256",
  "SignerArtifactDigest",
  "SignerArtifactKey",
  "SignerArtifactVersion",
  "SignerSourceDigest",
  "SourceCommit",
  "TreeDigest"
]);

export const HEX_40 = /^[0-9a-f]{40}$/u;
export const HEX_64 = /^[0-9a-f]{64}$/u;
export const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export const ACCOUNT_ID = /^[0-9]{12}$/u;
export const VERSION_ID = /^[A-Za-z0-9!_.*'()+,=:@/-]{1,1024}$/u;

export function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

export function requireCondition(condition, code) {
  if (!condition) reject(code);
}

export function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" ||
    typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    requireCondition(Number.isFinite(value), "RELEASE_PROVIDER_CANONICAL_REJECTED");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  requireCondition(plainObject(value), "RELEASE_PROVIDER_CANONICAL_REJECTED");
  return `{${Object.entries(value)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
    .join(",")}}`;
}

export function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

export function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function canonicalDigest(value) {
  return sha256(canonicalBytes(value));
}

export function base64Sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("base64");
}

export function tableArnFor(accountId) {
  requireCondition(ACCOUNT_ID.test(accountId ?? ""),
    "RELEASE_PROVIDER_ACCOUNT_REJECTED");
  return `arn:aws:dynamodb:${REGION}:${accountId}:table/${TABLE_NAME}`;
}

export function validateExplicitTemporaryCredentials(credentials) {
  const code = "RELEASE_PROVIDER_EXPLICIT_CREDENTIALS_REJECTED";
  requireCondition(exactKeys(credentials, [
    "accessKeyId", "secretAccessKey", "sessionToken"
  ]) && /^ASIA[A-Z0-9]{16}$/u.test(credentials.accessKeyId ?? "") &&
    typeof credentials.secretAccessKey === "string" &&
    credentials.secretAccessKey.length === 40 &&
    typeof credentials.sessionToken === "string" &&
    credentials.sessionToken.length >= 16 &&
    credentials.sessionToken.length <= 4096, code);
  return Object.freeze({ ...credentials });
}

export function fixedSdkOptions(endpoint, credentials) {
  requireCondition(typeof endpoint === "string" &&
    /^https:\/\/[a-z0-9.-]+\.amazonaws\.com$/u.test(endpoint),
  "RELEASE_PROVIDER_ENDPOINT_REJECTED");
  return Object.freeze({
    authSchemePreference: ["sigv4"],
    credentials: validateExplicitTemporaryCredentials(credentials),
    defaultsMode: "standard",
    endpoint,
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    region: REGION,
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  });
}

export function normalizeCallerIdentity(value, expectedRoleName) {
  const code = "RELEASE_PROVIDER_CALLER_IDENTITY_REJECTED";
  const arn = /^arn:aws:sts::([0-9]{12}):assumed-role\/([A-Za-z0-9+=,.@_-]{1,64})\/([A-Za-z0-9+=,.@_-]{2,64})$/u
    .exec(value?.Arn ?? "");
  const user = /^(AROA[A-Z0-9]{16}):([A-Za-z0-9+=,.@_-]{2,64})$/u
    .exec(value?.UserId ?? "");
  requireCondition(ACCOUNT_ID.test(value?.Account ?? "") && arn && user &&
    arn[1] === value.Account && arn[2] === expectedRoleName &&
    arn[3] === user[2], code);
  return Object.freeze({
    accountId: value.Account,
    assumedRoleArn: value.Arn,
    roleId: user[1],
    roleName: arn[2],
    sessionName: arn[3]
  });
}

export function providerRequestId(value, code) {
  requireCondition(typeof value === "string" && value.length >= 8 &&
    value.length <= 128 && /^[A-Za-z0-9._:/+=-]+$/u.test(value), code);
  return value;
}

export function asBytes(value, maximumBytes, code) {
  requireCondition((Buffer.isBuffer(value) || value instanceof Uint8Array) &&
    value.byteLength > 0 && value.byteLength <= maximumBytes, code);
  return Buffer.from(value);
}

export async function responseBodyBytes(body, expectedBytes, code) {
  let value;
  if (Buffer.isBuffer(body) || body instanceof Uint8Array) {
    value = Buffer.from(body);
  } else if (body && typeof body.transformToByteArray === "function") {
    value = Buffer.from(await body.transformToByteArray());
  } else {
    reject(code);
  }
  requireCondition(value.length === expectedBytes, code);
  return value;
}

export function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const nested of Object.values(value)) deepFreeze(nested);
  }
  return value;
}

export const __test = Object.freeze({
  canonicalJson,
  fixedSdkOptions,
  normalizeCallerIdentity,
  validateExplicitTemporaryCredentials
});
