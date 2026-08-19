import { createHash, randomUUID } from "node:crypto";
import { canonicalJson } from "./canonical-json.js";
import { parseStrictJson } from "./strict-json.js";
import {
  recoveryQueryBindingsFor,
  recoveryQueryTemplateDigest
} from "./recovery-continuity-identity.js";

const MCP_ENDPOINT = "https://cockroachlabs.cloud/mcp";
const MCP_PROTOCOL_VERSION = "2025-03-26";
const RECOVERY_DATABASE = "tideproof_recovery";
export const RECOVERY_MCP_RESPONSE_LIMIT_BYTES = 256 * 1024;
const JSON_DUPLICATE_MEMBER_CODE =
  "RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER";

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function managedMcpLogicalRequest({ clusterId, query }) {
  const bindings = recoveryQueryBindingsFor(query);
  const boundInputSha256 = sha256(canonicalJson({
    tenantId: bindings.tenantId,
    recoverySessionId: bindings.recoverySessionId,
    subjectBindingHash: bindings.subjectBindingHash,
    sourceDigest: bindings.sourceDigest
  }));
  return Object.freeze({
    schemaVersion:
      "tideproof.highwater-drill-logical-managed-mcp-request.v1",
    boundInputSha256,
    databaseNameSha256: sha256(RECOVERY_DATABASE),
    queryTemplateSha256: recoveryQueryTemplateDigest(),
    recoveryClusterId: clusterId,
    recoverySessionId: bindings.recoverySessionId,
    renderedQuerySha256: sha256(query),
    sourceDigest: bindings.sourceDigest,
    subjectBindingSha256: bindings.subjectBindingHash,
    tenantId: bindings.tenantId,
    toolNameSha256: sha256("select_query")
  });
}

function sessionId(value) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 1024 ||
    /[\0\r\n]/u.test(value)
  ) {
    throw new Error("RECOVERY_MCP_SESSION_INVALID");
  }
  return value;
}

function requireUuid(value, name) {
  const text = requireText(value, name).toLowerCase();
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      text
    )
  ) {
    throw new TypeError(`${name} must be a UUID`);
  }
  return text;
}

function normalizedMcpContentType(value) {
  if (typeof value !== "string") {
    throw new Error("RECOVERY_MCP_CONTENT_TYPE_INVALID");
  }
  const parts = value.split(";").map((part) => part.trim().toLowerCase());
  const mediaType = parts.shift();
  if (
    !["application/json", "text/event-stream"].includes(mediaType) ||
    parts.some((parameter) => parameter !== "charset=utf-8") ||
    new Set(parts).size !== parts.length
  ) {
    throw new Error("RECOVERY_MCP_CONTENT_TYPE_INVALID");
  }
  return mediaType;
}

function parseManagedMcpJson(text, invalidCode) {
  return parseStrictJson(text, {
    duplicateCode: JSON_DUPLICATE_MEMBER_CODE,
    invalidCode
  });
}

function hasExactOwnKeys(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === expected.length &&
    expected.every((key) => Object.hasOwn(value, key));
}

function validateJsonRpcResponse(message, expectedId) {
  if (
    message === null ||
    typeof message !== "object" ||
    Array.isArray(message)
  ) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  const hasResult = Object.hasOwn(message, "result");
  const hasError = Object.hasOwn(message, "error");
  if (hasResult === hasError) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  const expectedKeys = hasResult
    ? ["jsonrpc", "id", "result"]
    : ["jsonrpc", "id", "error"];
  if (!hasExactOwnKeys(message, expectedKeys)) {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  if (message.jsonrpc !== "2.0" || typeof message.id !== "string") {
    throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
  }
  if (message.id !== expectedId) {
    throw new Error("RECOVERY_MCP_RESPONSE_ID_MISMATCH");
  }
  if (hasError) {
    const errorKeys = Object.hasOwn(message.error ?? {}, "data")
      ? ["code", "message", "data"]
      : ["code", "message"];
    if (
      !hasExactOwnKeys(message.error, errorKeys) ||
      !Number.isSafeInteger(message.error.code) ||
      typeof message.error.message !== "string" ||
      message.error.message.trim() === ""
    ) {
      throw new Error("RECOVERY_MCP_RESPONSE_SHAPE_INVALID");
    }
  }
  return message;
}

function messageFromSse(text, expectedId) {
  const messages = [];
  let dataLines = [];
  let consumedLength = 0;
  let eventOpen = false;
  const dispatch = () => {
    if (dataLines.length === 0) return;
    const data = dataLines.join("\n");
    dataLines = [];
    const message = parseManagedMcpJson(
      data,
      "RECOVERY_MCP_RESPONSE_SSE_INVALID"
    );
    validateJsonRpcResponse(message, expectedId);
    messages.push(message);
  };
  for (const match of text.matchAll(/([^\r\n]*)(?:\r\n|\r|\n)/gu)) {
    consumedLength = match.index + match[0].length;
    const line = match[1];
    if (line === "") {
      dispatch();
      eventOpen = false;
      continue;
    }
    eventOpen = true;
    if (line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") {
      dataLines.push(value);
      continue;
    }
    if (["event", "id", "retry"].includes(field)) continue;
    // Unknown SSE fields are ignored by the WHATWG dispatch algorithm.
  }
  // This bounded one-shot transcript must end after an explicit blank event
  // boundary. WHATWG would discard a pending event at EOF; doing so here could
  // hide a malformed or additional provider response after the accepted one.
  if (consumedLength !== text.length || eventOpen || dataLines.length !== 0) {
    throw new Error("RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS");
  }
  if (messages.length !== 1) {
    throw new Error("RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS");
  }
  return messages[0];
}

async function cancelResponseBody(response) {
  try {
    await response?.body?.cancel();
  } catch {
    // Cancellation is best-effort after the response is no longer needed.
  }
}

export async function readBoundedUtf8Response(
  response,
  { limitBytes = RECOVERY_MCP_RESPONSE_LIMIT_BYTES } = {}
) {
  if (!Number.isSafeInteger(limitBytes) || limitBytes < 1) {
    throw new TypeError("limitBytes must be a positive safe integer");
  }
  const contentLength = response?.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^\d+$/u.test(contentLength)) {
      await cancelResponseBody(response);
      throw new Error("RECOVERY_MCP_CONTENT_LENGTH_INVALID");
    }
    const advertised = Number(contentLength);
    if (!Number.isSafeInteger(advertised)) {
      await cancelResponseBody(response);
      throw new Error("RECOVERY_MCP_CONTENT_LENGTH_INVALID");
    }
    if (advertised > limitBytes) {
      await cancelResponseBody(response);
      throw new Error("RECOVERY_MCP_RESPONSE_TOO_LARGE");
    }
  }

  if (!response?.body) {
    return "";
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!(value instanceof Uint8Array)) {
        throw new Error("RECOVERY_MCP_RESPONSE_ENCODING_INVALID");
      }
      received += value.byteLength;
      if (received > limitBytes) {
        await reader.cancel();
        throw new Error("RECOVERY_MCP_RESPONSE_TOO_LARGE");
      }
      chunks.push(value);
    }
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // Preserve the primary bounded-read error.
    }
    throw error;
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("RECOVERY_MCP_RESPONSE_ENCODING_INVALID");
  }
}

export class CockroachManagedMcpRecoveryClient {
  #apiKey;
  #clusterId;
  #fetch;
  #nextId = 1;
  #sessionId = null;
  #rpcEvidence = [];
  #notificationEvidence = [];
  #closeEvidence = null;
  #semanticRequestEvidence = null;

  constructor({ apiKey, clusterId, fetchImpl = globalThis.fetch } = {}) {
    this.#apiKey = requireText(apiKey, "apiKey");
    if (this.#apiKey.length < 24) {
      throw new TypeError("apiKey is too short");
    }
    this.#clusterId = requireUuid(clusterId, "clusterId");
    if (typeof fetchImpl !== "function") {
      throw new TypeError("fetchImpl must be a function");
    }
    this.#fetch = fetchImpl;
  }

  async close({ beforeExternalAction = null } = {}) {
    if (
      beforeExternalAction !== null &&
      typeof beforeExternalAction !== "function"
    ) {
      throw new Error("RECOVERY_MCP_EXTERNAL_ACTION_GUARD_INVALID");
    }
    if (!this.#sessionId) {
      return;
    }
    const expectedSessionId = this.#sessionId;
    const expectedSessionIdSha256 = sha256(expectedSessionId);
    this.#closeEvidence = Object.freeze({
      attempted: false,
      httpStatus: null,
      outboundSessionIdSha256: expectedSessionIdSha256,
      responseSessionIdSha256: null,
      sessionContinuous: false
    });
    try {
      if (beforeExternalAction !== null) {
        await beforeExternalAction("MCP_SESSION_DELETE");
      }
      this.#closeEvidence = Object.freeze({
        attempted: true,
        httpStatus: null,
        outboundSessionIdSha256: expectedSessionIdSha256,
        responseSessionIdSha256: null,
        sessionContinuous: false
      });
      const response = await this.#fetch(MCP_ENDPOINT, {
        method: "DELETE",
        headers: this.#headers(),
        redirect: "error",
        signal: AbortSignal.timeout(10_000)
      });
      const received = response.headers.get("mcp-session-id");
      if (received && sessionId(received) !== expectedSessionId) {
        await cancelResponseBody(response);
        throw new Error("RECOVERY_MCP_SESSION_CHANGED");
      }
      if (!response.ok) {
        await cancelResponseBody(response);
        throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
      }
      this.#closeEvidence = Object.freeze({
        attempted: true,
        httpStatus: response.status,
        outboundSessionIdSha256: expectedSessionIdSha256,
        responseSessionIdSha256: received ? sha256(received) : null,
        sessionContinuous: true
      });
      await cancelResponseBody(response);
    } catch {
      // Closing is best-effort, but the failed continuity receipt is retained.
    }
    this.#sessionId = null;
  }

  transportEvidence() {
    return Object.freeze({
      schemaVersion: "tideproof.managed-mcp-transport-evidence.v2",
      endpointSha256: sha256(MCP_ENDPOINT),
      endpointAuthority: "cockroachlabs.cloud",
      clusterIdSha256: sha256(this.#clusterId),
      protocolVersion: MCP_PROTOCOL_VERSION,
      rpcCalls: this.#rpcEvidence.map((entry) => Object.freeze({ ...entry })),
      notifications: this.#notificationEvidence.map((entry) =>
        Object.freeze({ ...entry })
      ),
      sessionIdSha256:
        this.#rpcEvidence.at(-1)?.sessionIdSha256 ?? null,
      close: this.#closeEvidence,
      redirectPolicy: "error",
      boundedResponseBytes: RECOVERY_MCP_RESPONSE_LIMIT_BYTES
    });
  }

  semanticRequestEvidence() {
    return this.#semanticRequestEvidence;
  }

  async #initialize(beforeExternalAction) {
    if (this.#sessionId) {
      return;
    }
    const response = await this.#rpc("initialize", {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: {
        name: "tideproof-deterministic-recovery-broker",
        version: "0.1.0"
      }
    }, { beforeExternalAction });
    if (
      response?.protocolVersion !== MCP_PROTOCOL_VERSION
    ) {
      throw new Error("RECOVERY_MCP_INITIALIZATION_INVALID");
    }
    await this.#notification(
      "notifications/initialized",
      {},
      beforeExternalAction
    );
  }

  #headers() {
    const headers = {
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${this.#apiKey}`,
      "Content-Type": "application/json",
      "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
      "mcp-cluster-id": this.#clusterId
    };
    if (this.#sessionId) {
      headers["Mcp-Session-Id"] = this.#sessionId;
    }
    return headers;
  }

  async #notification(method, params, beforeExternalAction) {
    const outboundSessionId = sessionId(this.#sessionId);
    const body = JSON.stringify({ jsonrpc: "2.0", method, params });
    if (beforeExternalAction !== null) {
      await beforeExternalAction("MCP_INITIALIZED_NOTIFICATION");
    }
    const response = await this.#fetch(MCP_ENDPOINT, {
      method: "POST",
      headers: this.#headers(),
      body,
      redirect: "error",
      signal: AbortSignal.timeout(20_000)
    });
    const received = response.headers.get("mcp-session-id");
    if (received && sessionId(received) !== outboundSessionId) {
      await cancelResponseBody(response);
      throw new Error("RECOVERY_MCP_SESSION_CHANGED");
    }
    if (!response.ok) {
      await cancelResponseBody(response);
      throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
    }
    this.#notificationEvidence.push(Object.freeze({
      method,
      requestBytes: Buffer.byteLength(body, "utf8"),
      requestPayloadSha256: sha256(body),
      httpStatus: response.status,
      outboundSessionIdSha256: sha256(outboundSessionId),
      responseSessionIdSha256: received ? sha256(received) : null,
      sessionContinuous: true
    }));
    await cancelResponseBody(response);
  }

  async #rpc(
    method,
    params,
    { beforeExternalAction = null, logicalRequest = null } = {}
  ) {
    const id = `${randomUUID()}:${this.#nextId}`;
    this.#nextId += 1;
    const outboundSessionId = this.#sessionId;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
    if (logicalRequest !== null) {
      if (method !== "tools/call" || this.#semanticRequestEvidence !== null) {
        throw new Error("RECOVERY_MCP_SEMANTIC_REQUEST_AMBIGUOUS");
      }
      const evidenceBody = Object.freeze({
        schemaVersion: "tideproof.managed-mcp-semantic-request-evidence.v1",
        clusterId: this.#clusterId,
        database: params?.arguments?.database,
        logicalRequest,
        logicalMcpRequestSha256: sha256(canonicalJson(logicalRequest)),
        query: params?.arguments?.query,
        requestId: id,
        requestIdSha256: sha256(id),
        requestParamsSha256: sha256(canonicalJson(params)),
        requestPayloadSha256: sha256(body),
        toolName: params?.name
      });
      this.#semanticRequestEvidence = Object.freeze({
        ...evidenceBody,
        evidenceSha256: sha256(canonicalJson(evidenceBody))
      });
    }
    if (beforeExternalAction !== null) {
      await beforeExternalAction(
        method === "initialize" ? "MCP_INITIALIZE" : "MCP_TOOLS_CALL"
      );
    }
    const response = await this.#fetch(MCP_ENDPOINT, {
      method: "POST",
      headers: this.#headers(),
      body,
      redirect: "error",
      signal: AbortSignal.timeout(30_000)
    });
    const receivedSessionId = response.headers.get("mcp-session-id");
    if (receivedSessionId) {
      const acceptedSessionId = sessionId(receivedSessionId);
      if (
        outboundSessionId !== null &&
        acceptedSessionId !== outboundSessionId
      ) {
        await cancelResponseBody(response);
        throw new Error("RECOVERY_MCP_SESSION_CHANGED");
      }
      this.#sessionId = acceptedSessionId;
    }
    if (method === "initialize" && this.#sessionId === null) {
      await cancelResponseBody(response);
      throw new Error("RECOVERY_MCP_SESSION_REQUIRED");
    }
    if (!response.ok) {
      await cancelResponseBody(response);
      throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
    }
    const contentType = normalizedMcpContentType(
      response.headers.get("content-type")
    );
    const responseText = await readBoundedUtf8Response(response);
    let message;
    if (contentType === "application/json") {
      message = parseManagedMcpJson(
        responseText,
        "RECOVERY_MCP_RESPONSE_JSON_INVALID"
      );
    } else if (contentType === "text/event-stream") {
      message = messageFromSse(responseText, id);
    }
    validateJsonRpcResponse(message, id);
    if (Object.hasOwn(message, "error")) {
      const code = String(message.error.code)
        .replace(/[^A-Z0-9_]/giu, "_")
        .toUpperCase();
      throw new Error(`RECOVERY_MCP_RPC_${code}`);
    }
    this.#rpcEvidence.push(Object.freeze({
      method,
      requestIdSha256: sha256(id),
      responseIdSha256: sha256(String(message.id)),
      requestBytes: Buffer.byteLength(body, "utf8"),
      responseBytes: Buffer.byteLength(responseText, "utf8"),
      requestPayloadSha256: sha256(body),
      responsePayloadSha256: sha256(responseText),
      resultSha256: sha256(canonicalJson(message.result)),
      responseCorrelated: true,
      httpStatus: response.status,
      contentType,
      sessionIdSha256:
        typeof this.#sessionId === "string" && this.#sessionId.length > 0
          ? sha256(this.#sessionId)
          : null,
      outboundSessionIdSha256:
        outboundSessionId === null ? null : sha256(outboundSessionId),
      responseSessionIdSha256:
        receivedSessionId === null ? null : sha256(receivedSessionId),
      sessionContinuous:
        outboundSessionId === null ||
        receivedSessionId === null ||
        outboundSessionId === receivedSessionId
    }));
    return message.result;
  }

  async selectQuery({
    clusterId,
    database,
    query,
    beforeExternalAction = null,
    beforeToolCall = null
  }) {
    if (requireUuid(clusterId, "clusterId") !== this.#clusterId) {
      throw new Error("RECOVERY_MCP_CLUSTER_MISMATCH");
    }
    if (requireText(database, "database") !== RECOVERY_DATABASE) {
      throw new Error("RECOVERY_MCP_DATABASE_MISMATCH");
    }
    const logicalRequest = managedMcpLogicalRequest({
      clusterId: this.#clusterId,
      query
    });
    if (beforeToolCall !== null && typeof beforeToolCall !== "function") {
      throw new Error("RECOVERY_MCP_TOOL_CALL_GUARD_INVALID");
    }
    if (
      beforeExternalAction !== null &&
      typeof beforeExternalAction !== "function"
    ) {
      throw new Error("RECOVERY_MCP_EXTERNAL_ACTION_GUARD_INVALID");
    }
    await this.#initialize(beforeExternalAction);
    if (beforeToolCall !== null) {
      await beforeToolCall();
    }
    const result = await this.#rpc("tools/call", {
      name: "select_query",
      arguments: {
        database: RECOVERY_DATABASE,
        query
      }
    }, { beforeExternalAction, logicalRequest });
    if (result?.isError === true) {
      throw new Error("RECOVERY_MCP_TOOL_REJECTED");
    }
    return result;
  }
}
