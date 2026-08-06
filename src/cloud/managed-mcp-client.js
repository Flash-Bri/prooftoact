import { createHash, randomUUID } from "node:crypto";
import { recoveryQueryBindingsFor } from "./recovery-store.js";

const MCP_ENDPOINT = "https://cockroachlabs.cloud/mcp";
const MCP_PROTOCOL_VERSION = "2025-03-26";
const RECOVERY_DATABASE = "tideproof_recovery";
export const RECOVERY_MCP_RESPONSE_LIMIT_BYTES = 256 * 1024;

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
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

function messageFromSse(text, expectedId) {
  const messages = text
    .split(/\r?\n/u)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trim())
    .filter((line) => line !== "" && line !== "[DONE]")
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  return (
    messages.find((message) => String(message.id) === String(expectedId)) ??
    messages.at(-1) ??
    null
  );
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
  #notificationCount = 0;
  #closeAttempted = false;

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

  async close() {
    if (!this.#sessionId) {
      return;
    }
    this.#closeAttempted = true;
    await this.#fetch(MCP_ENDPOINT, {
      method: "DELETE",
      headers: this.#headers(),
      redirect: "error",
      signal: AbortSignal.timeout(10_000)
    })
      .then(cancelResponseBody)
      .catch(() => {});
    this.#sessionId = null;
  }

  transportEvidence() {
    return Object.freeze({
      schemaVersion: "tideproof.managed-mcp-transport-evidence.v1",
      endpointSha256: sha256(MCP_ENDPOINT),
      endpointAuthority: "cockroachlabs.cloud",
      clusterIdSha256: sha256(this.#clusterId),
      protocolVersion: MCP_PROTOCOL_VERSION,
      rpcCalls: this.#rpcEvidence.map((entry) => Object.freeze({ ...entry })),
      notificationCount: this.#notificationCount,
      closeAttempted: this.#closeAttempted,
      redirectPolicy: "error",
      boundedResponseBytes: RECOVERY_MCP_RESPONSE_LIMIT_BYTES
    });
  }

  async #initialize() {
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
    });
    if (
      response?.protocolVersion !== MCP_PROTOCOL_VERSION
    ) {
      throw new Error("RECOVERY_MCP_INITIALIZATION_INVALID");
    }
    await this.#notification("notifications/initialized", {});
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

  async #notification(method, params) {
    const response = await this.#fetch(MCP_ENDPOINT, {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ jsonrpc: "2.0", method, params }),
      redirect: "error",
      signal: AbortSignal.timeout(20_000)
    });
    if (!response.ok) {
      await cancelResponseBody(response);
      throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
    }
    this.#notificationCount += 1;
    await cancelResponseBody(response);
  }

  async #rpc(method, params) {
    const id = `${randomUUID()}:${this.#nextId}`;
    this.#nextId += 1;
    const response = await this.#fetch(MCP_ENDPOINT, {
      method: "POST",
      headers: this.#headers(),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000)
    });
    const receivedSessionId = response.headers.get("mcp-session-id");
    if (receivedSessionId) {
      this.#sessionId = receivedSessionId;
    }
    if (!response.ok) {
      await cancelResponseBody(response);
      throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
    }
    const contentType = response.headers.get("content-type") ?? "";
    const responseText = await readBoundedUtf8Response(response);
    let message;
    if (contentType.includes("application/json")) {
      try {
        message = JSON.parse(responseText);
      } catch {
        throw new Error("RECOVERY_MCP_RESPONSE_JSON_INVALID");
      }
    } else if (contentType.includes("text/event-stream")) {
      message = messageFromSse(responseText, id);
    } else {
      throw new Error("RECOVERY_MCP_CONTENT_TYPE_INVALID");
    }
    if (
      !message ||
      message.jsonrpc !== "2.0" ||
      String(message.id) !== String(id)
    ) {
      throw new Error("RECOVERY_MCP_RESPONSE_ID_MISMATCH");
    }
    if (message.error) {
      const code = String(message.error.code ?? "UNKNOWN")
        .replace(/[^A-Z0-9_]/giu, "_")
        .toUpperCase();
      throw new Error(`RECOVERY_MCP_RPC_${code}`);
    }
    this.#rpcEvidence.push(Object.freeze({
      method,
      requestIdSha256: sha256(id),
      responseIdSha256: sha256(String(message.id)),
      responseCorrelated: true,
      httpStatus: response.status,
      contentType:
        contentType.includes("application/json")
          ? "application/json"
          : "text/event-stream",
      sessionIdSha256:
        typeof this.#sessionId === "string" && this.#sessionId.length > 0
          ? sha256(this.#sessionId)
          : null
    }));
    return message.result;
  }

  async selectQuery({ clusterId, database, query }) {
    if (requireUuid(clusterId, "clusterId") !== this.#clusterId) {
      throw new Error("RECOVERY_MCP_CLUSTER_MISMATCH");
    }
    if (requireText(database, "database") !== RECOVERY_DATABASE) {
      throw new Error("RECOVERY_MCP_DATABASE_MISMATCH");
    }
    recoveryQueryBindingsFor(query);
    await this.#initialize();
    const result = await this.#rpc("tools/call", {
      name: "select_query",
      arguments: {
        database: RECOVERY_DATABASE,
        query
      }
    });
    if (result?.isError === true) {
      throw new Error("RECOVERY_MCP_TOOL_REJECTED");
    }
    return result;
  }
}
