import net from "node:net";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  PROVIDER_DISPATCH_HEX_64,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  validateIntegratedLiveDrillExecutionGrant
} from "./integrated-live-drill-dispatch-broker.js";

const REQUEST_SCHEMA = "tideproof.provider-operation-broker-request.v1";
const RESPONSE_SCHEMA = "tideproof.provider-operation-broker-response.v1";
const MAX_MESSAGE_BYTES = 2 * 1024 * 1024;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function requiredSocketPath(value) {
  requireCondition(
    typeof value === "string" && path.isAbsolute(value) &&
      path.resolve(value) === value && value.length <= 4096,
    "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_SOCKET_REJECTED"
  );
  return value;
}

function rpc(socketPath, request) {
  return new Promise((resolve, rejectPromise) => {
    const socket = net.createConnection({ path: socketPath });
    let bytes = 0;
    let response = "";
    let settled = false;
    const fail = (cause) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      rejectPromise(new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_UNAVAILABLE",
        { cause }
      ));
    };
    socket.setTimeout(90_000, () => fail(new Error("timeout")));
    socket.on("error", fail);
    socket.on("connect", () => {
      socket.end(`${canonicalJson(request)}\n`);
    });
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX_MESSAGE_BYTES) {
        fail(new Error("response too large"));
        return;
      }
      response += chunk;
    });
    socket.on("end", () => {
      if (settled) return;
      settled = true;
      try {
        requireCondition(
          response.endsWith("\n") && !response.slice(0, -1).includes("\n"),
          "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_RESPONSE_REJECTED"
        );
        const parsed = JSON.parse(response);
        requireCondition(
          exactRecord(parsed, ["errorCode", "result", "schemaVersion", "status"]) &&
            parsed.schemaVersion === RESPONSE_SCHEMA &&
            ["ERROR", "OK"].includes(parsed.status) &&
            (parsed.status === "OK"
              ? parsed.errorCode === null
              : /^[A-Z][A-Z0-9_]{2,160}$/u.test(parsed.errorCode ?? "")),
          "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_RESPONSE_REJECTED"
        );
        if (parsed.status === "ERROR") reject(parsed.errorCode);
        resolve(parsed.result);
      } catch (cause) {
        rejectPromise(cause);
      }
    });
  });
}

export class BrokeredProviderOperationClient {
  #binding;
  #clusterId;
  #executionGrant;
  #operationNonce;
  #semanticRequestEvidence = null;
  #socketPath;
  #transportEvidence = null;

  constructor({
    binding,
    clusterId,
    executionGrant,
    operationNonce,
    socketPath
  } = {}) {
    this.#binding = validateProviderDispatchControlBinding(binding);
    this.#executionGrant = validateIntegratedLiveDrillExecutionGrant(
      executionGrant
    );
    requireCondition(
      typeof clusterId === "string" &&
        /^[0-9a-f-]{36}$/u.test(clusterId) &&
        PROVIDER_DISPATCH_HEX_64.test(operationNonce ?? ""),
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_INPUT_REJECTED"
    );
    this.#clusterId = clusterId;
    this.#operationNonce = operationNonce;
    this.#socketPath = requiredSocketPath(socketPath);
  }

  #request(action, payload) {
    return Object.freeze({
      action,
      binding: this.#binding,
      executionGrant: this.#executionGrant,
      operationNonce: this.#operationNonce,
      payload,
      schemaVersion: REQUEST_SCHEMA
    });
  }

  async selectQuery({
    beforeExternalAction = null,
    clusterId,
    database,
    query
  }) {
    requireCondition(
      clusterId === this.#clusterId && database === "tideproof_recovery" &&
        typeof query === "string" && query.length > 0 &&
        query.length <= 1024 * 1024 &&
        (beforeExternalAction === null ||
          typeof beforeExternalAction === "function"),
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_INPUT_REJECTED"
    );
    for (const action of [
      "MCP_INITIALIZE",
      "MCP_INITIALIZED_NOTIFICATION",
      "MCP_TOOLS_CALL"
    ]) beforeExternalAction?.(action);
    const result = await rpc(this.#socketPath, this.#request("EXECUTE", {
      clusterId,
      database,
      query
    }));
    requireCondition(
      exactRecord(result, [
        "rawResult",
        "semanticRequestEvidence",
        "transportEvidence"
      ]),
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_RESPONSE_REJECTED"
    );
    this.#semanticRequestEvidence = result.semanticRequestEvidence;
    this.#transportEvidence = result.transportEvidence;
    return result.rawResult;
  }

  async complete(binding, grant, terminal) {
    requireCondition(
      canonicalJson(validateProviderDispatchControlBinding(binding)) ===
        canonicalJson(this.#binding) && grant?.grantId === this.#executionGrant.grantId,
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_INPUT_REJECTED"
    );
    return rpc(this.#socketPath, this.#request("COMPLETE", terminal));
  }

  async markUnknown(binding, grant) {
    requireCondition(
      canonicalJson(validateProviderDispatchControlBinding(binding)) ===
        canonicalJson(this.#binding) && grant?.grantId === this.#executionGrant.grantId,
      "INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_INPUT_REJECTED"
    );
    return rpc(this.#socketPath, this.#request("MARK_UNKNOWN", null));
  }

  async close() {}

  semanticRequestEvidence() { return this.#semanticRequestEvidence; }

  transportEvidence() { return this.#transportEvidence; }
}

export const __test = Object.freeze({
  MAX_MESSAGE_BYTES,
  REQUEST_SCHEMA,
  RESPONSE_SCHEMA
});
