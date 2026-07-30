import { randomUUID } from "node:crypto";
import { recoveryQueryBindingsFor } from "./recovery-store.js";

const MCP_ENDPOINT = "https://cockroachlabs.cloud/mcp";
const MCP_PROTOCOL_VERSION = "2025-03-26";
const RECOVERY_DATABASE = "tideproof_recovery";

function requireText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
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

export class CockroachManagedMcpRecoveryClient {
  #apiKey;
  #clusterId;
  #fetch;
  #nextId = 1;
  #sessionId = null;

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
    await this.#fetch(MCP_ENDPOINT, {
      method: "DELETE",
      headers: this.#headers(),
      redirect: "error",
      signal: AbortSignal.timeout(10_000)
    }).catch(() => {});
    this.#sessionId = null;
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
      throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
    }
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
      throw new Error(`RECOVERY_MCP_HTTP_${response.status}`);
    }
    const contentType = response.headers.get("content-type") ?? "";
    let message;
    if (contentType.includes("application/json")) {
      message = await response.json();
    } else if (contentType.includes("text/event-stream")) {
      message = messageFromSse(await response.text(), id);
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
