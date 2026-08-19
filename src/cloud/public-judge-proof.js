import { createHash } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";
import {
  JUDGE_PROOF_PINNED_BINDING,
  JUDGE_PROOF_RESPONSE_LIMIT_BYTES,
  JUDGE_PROOF_STATUS,
  judgeProofResultSha256
} from "./judge-proof-query.js";
import { CockroachManagedMcpJudgeProofClient } from
  "./managed-mcp-client.js";
import { parseStrictJson } from "./strict-json.js";

export const PUBLIC_JUDGE_PROOF_PATH = "/api/judge-proof";
export const PUBLIC_JUDGE_PROOF_ORIGIN = "https://flash-bri.github.io";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SECRET_ARN =
  /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/judge-proof\/managed-mcp-[A-Za-z0-9]{6}$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function safeFailureCode(error) {
  const value = typeof error?.message === "string" ? error.message : "";
  return /^[A-Z][A-Z0-9_]{0,127}$/u.test(value)
    ? value
    : "PUBLIC_JUDGE_PROOF_EXECUTION_FAILED";
}

function exactKeys(value, expected) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateBinding(value) {
  if (
    !exactKeys(value, [
      "expectedApiId",
      "lambdaVersion",
      "mcpClusterId",
      "mcpSecretArn",
      "mcpSecretVersionId",
      "sourceCommit"
    ]) ||
    !/^[a-z0-9]{4,32}$/u.test(value.expectedApiId ?? "") ||
    !UUID.test(value.mcpClusterId ?? "") ||
    !SECRET_ARN.test(value.mcpSecretArn ?? "") ||
    !/^[A-Za-z0-9_-]{32,64}$/u.test(value.mcpSecretVersionId ?? "") ||
    !HEX_40.test(value.sourceCommit ?? "") ||
    !/^[1-9][0-9]{0,9}$/u.test(value.lambdaVersion ?? "")
  ) {
    reject("PUBLIC_JUDGE_PROOF_BINDING_REJECTED");
  }
  return Object.freeze({ ...value });
}

function requestAccepted(event, expectedApiId) {
  return event?.version === "2.0" &&
    event.rawPath === PUBLIC_JUDGE_PROOF_PATH &&
    event.rawQueryString === "" &&
    event.requestContext?.apiId === expectedApiId &&
    event.requestContext?.stage === "$default" &&
    event.requestContext?.routeKey === `GET ${PUBLIC_JUDGE_PROOF_PATH}` &&
    event.requestContext?.http?.method === "GET" &&
    [undefined, null].includes(event.queryStringParameters) &&
    [undefined, null].includes(event.pathParameters) &&
    [undefined, null, ""].includes(event.body) &&
    [undefined, false].includes(event.isBase64Encoded);
}

function publicHeaders() {
  return {
    "access-control-allow-origin": PUBLIC_JUDGE_PROOF_ORIGIN,
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "content-type": "application/json; charset=utf-8",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "cross-origin",
    "permissions-policy":
      "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    vary: "Origin"
  };
}

function response(statusCode, body) {
  return Object.freeze({
    statusCode,
    headers: publicHeaders(),
    body: JSON.stringify(body),
    isBase64Encoded: false
  });
}

function secretConfig(secret, binding) {
  const code = "PUBLIC_JUDGE_PROOF_SECRET_REJECTED";
  if (
    !exactKeys(secret, [
      "arn",
      "secretBinary",
      "secretString",
      "versionId",
      "versionStages"
    ]) ||
    secret.arn !== binding.mcpSecretArn ||
    secret.versionId !== binding.mcpSecretVersionId ||
    secret.secretBinary !== undefined ||
    !Array.isArray(secret.versionStages) ||
    secret.versionStages.length !== 1 ||
    secret.versionStages[0] !== "AWSCURRENT" ||
    typeof secret.secretString !== "string" ||
    Buffer.byteLength(secret.secretString, "utf8") > 4096
  ) {
    reject(code);
  }
  let parsed;
  try {
    parsed = parseStrictJson(secret.secretString, {
      duplicateCode: code,
      invalidCode: code
    });
  } catch (cause) {
    reject(code, cause);
  }
  if (
    !exactKeys(parsed, ["apiKey"]) ||
    typeof parsed.apiKey !== "string" ||
    parsed.apiKey.length < 24 ||
    parsed.apiKey.length > 4096 ||
    /[\0-\x20\x7f]/u.test(parsed.apiKey)
  ) {
    reject(code);
  }
  return Object.freeze({
    apiKey: parsed.apiKey
  });
}

function publicResult(value, binding) {
  const code = "PUBLIC_JUDGE_PROOF_RESULT_REJECTED";
  const observedAt = value?.observedAt;
  const proofKeys = [
    "authorityTransferred",
    "bindingSha256",
    "bundleDigest",
    "expiresAt",
    "publisherKeySha256",
    "receiptBoundary",
    "receiptReason",
    "requiresFreshAuthorization",
    "schemaVersion",
    "signatureDigest",
    "sourceClusterIdSha256",
    "sourceCommitTs",
    "sourceDigest"
  ];
  if (
    !exactKeys(value, [
      "observedAt",
      "proof",
      "proofSha256",
      "receiptExpiredContext",
      "schemaVersion",
      "semanticRequestEvidenceSha256",
      "status",
      "transport"
    ]) ||
    value.schemaVersion !== "prooftoact.public-judge-proof-read.v1" ||
    value.status !== JUDGE_PROOF_STATUS ||
    !exactKeys(value.proof, proofKeys) ||
    value.proof.schemaVersion !== 1 ||
    value.proof.receiptBoundary !==
      "HISTORICAL_SIGNED_RECOVERY_CONTEXT_ONLY" ||
    value.proof.bundleDigest !== JUDGE_PROOF_PINNED_BINDING.bundleDigest ||
    value.proof.signatureDigest !==
      JUDGE_PROOF_PINNED_BINDING.signatureDigest ||
    value.proof.publisherKeySha256 !==
      JUDGE_PROOF_PINNED_BINDING.publisherPublicKeySha256 ||
    value.proof.sourceDigest !== JUDGE_PROOF_PINNED_BINDING.sourceDigest ||
    value.proof.sourceClusterIdSha256 !==
      sha256(JUDGE_PROOF_PINNED_BINDING.expectedSourceClusterId) ||
    value.proof.authorityTransferred !== false ||
    value.proof.requiresFreshAuthorization !== true ||
    value.proof.receiptReason !== "transport-proof-only" ||
    typeof observedAt !== "string" ||
    observedAt.length > 64 ||
    !Number.isFinite(Date.parse(observedAt)) ||
    new Date(Date.parse(observedAt)).toISOString() !== observedAt ||
    value.receiptExpiredContext !==
      (Date.parse(value.proof.expiresAt) <= Date.parse(observedAt)) ||
    value.proofSha256 !== judgeProofResultSha256(value.proof) ||
    !HEX_64.test(value.semanticRequestEvidenceSha256 ?? "") ||
    value.transport?.endpointAuthority !== "cockroachlabs.cloud" ||
    value.transport?.protocolVersion !== "2025-03-26" ||
    value.transport?.boundedResponseBytes !== JUDGE_PROOF_RESPONSE_LIMIT_BYTES ||
    value.transport?.redirectPolicy !== "error" ||
    !HEX_64.test(value.transport?.clusterIdSha256 ?? "") ||
    value.transport.clusterIdSha256 !== sha256(binding.mcpClusterId) ||
    value.transport?.rpcCalls?.length !== 2 ||
    value.transport.rpcCalls[0]?.method !== "initialize" ||
    value.transport.rpcCalls[0]?.httpStatus !== 200 ||
    value.transport.rpcCalls[1]?.method !== "tools/call" ||
    value.transport.rpcCalls[1]?.httpStatus !== 200 ||
    !value.transport.rpcCalls.every((call) =>
      call.responseCorrelated === true && call.sessionContinuous === true
    ) ||
    value.transport?.notifications?.length !== 1 ||
    value.transport.notifications[0]?.method !== "notifications/initialized" ||
    value.transport.notifications[0]?.httpStatus !== 202 ||
    value.transport.notifications[0]?.sessionContinuous !== true ||
    value.transport?.close?.attempted !== true ||
    value.transport.close.httpStatus !== 204 ||
    value.transport.close.sessionContinuous !== true
  ) {
    reject(code);
  }
  const body = Object.freeze({
    schemaVersion: "prooftoact.public-judge-proof.v1",
    status: JUDGE_PROOF_STATUS,
    observedAt: value.observedAt,
    sourceCommit: binding.sourceCommit,
    lambdaVersion: binding.lambdaVersion,
    receiptExpiredContext: value.receiptExpiredContext,
    proof: value.proof,
    proofSha256: value.proofSha256,
    managedMcp: Object.freeze({
      endpointAuthority: value.transport.endpointAuthority,
      protocolVersion: value.transport.protocolVersion,
      clusterIdSha256: value.transport.clusterIdSha256,
      semanticRequestEvidenceSha256:
        value.semanticRequestEvidenceSha256,
      sessionClosed: true,
      initializeHttpStatus: value.transport.rpcCalls[0].httpStatus,
      toolCallHttpStatus: value.transport.rpcCalls[1].httpStatus,
      notificationHttpStatus: value.transport.notifications[0].httpStatus,
      closeHttpStatus: value.transport.close.httpStatus,
      responseLimitBytes: value.transport.boundedResponseBytes,
      redirectPolicy: value.transport.redirectPolicy
    })
  });
  return Object.freeze({
    ...body,
    responseSha256: sha256(canonicalJson(body))
  });
}

export function createPublicJudgeProofHandler({
  binding: rawBinding,
  createMcpClient = (options) =>
    new CockroachManagedMcpJudgeProofClient(options),
  readSecret
} = {}) {
  const binding = validateBinding(rawBinding);
  if (typeof createMcpClient !== "function" || typeof readSecret !== "function") {
    reject("PUBLIC_JUDGE_PROOF_RUNTIME_REJECTED");
  }
  let secretPromise;
  const readConfig = async () => {
    secretPromise ??= Promise.resolve().then(readSecret);
    return secretConfig(await secretPromise, binding);
  };
  return async function publicJudgeProofHandler(event) {
    if (!requestAccepted(event, binding.expectedApiId)) {
      return response(404, { error: "not_found" });
    }
    try {
      const secret = await readConfig();
      const client = createMcpClient({
        apiKey: secret.apiKey,
        clusterId: binding.mcpClusterId
      });
      const value = await client.readPinnedJudgeProof();
      return response(200, publicResult(value, binding));
    } catch (error) {
      console.error(JSON.stringify({
        schemaVersion: "prooftoact.public-judge-proof-failure.v1",
        code: safeFailureCode(error)
      }));
      return response(503, { error: "proof_unavailable" });
    }
  };
}

export const __test = Object.freeze({
  exactKeys,
  publicResult,
  requestAccepted,
  safeFailureCode,
  secretConfig,
  validateBinding
});
