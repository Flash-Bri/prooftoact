import { Client } from "pg";

import { connectionStringForDatabase } from "./authority-store.js";
import { runtimeDatabaseConfig } from "./database-runtime.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";

const RESULT_KEYS = Object.freeze([
  "authorization_id",
  "control_binding_sha256",
  "database_now",
  "expires_at",
  "grant_id",
  "mcp_result_sha256",
  "session_close_sha256",
  "state",
  "transition_outcome",
  "worker_spec_sha256"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactIso(value) {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function exactRow(value) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...RESULT_KEYS].sort().join("\n");
}

function optionalDigest(value) {
  return value === null || PROVIDER_DISPATCH_HEX_64.test(value ?? "");
}

export function validateProviderDispatchResult(
  result,
  bindingInput,
  { outcomes }
) {
  const binding = validateProviderDispatchControlBinding(bindingInput);
  const row = result?.rows?.[0];
  const databaseNow = exactIso(row?.database_now);
  const absent = row?.state === PROVIDER_DISPATCH_CONTROL_STATES.ABSENT;
  const expiresAt = row?.expires_at === null
    ? null
    : exactIso(row?.expires_at);
  if (
    result?.rowCount !== 1 || !exactRow(row) ||
    row.authorization_id !== binding.authorizationId ||
    row.control_binding_sha256 !== binding.controlBindingSha256 ||
    !Object.values(PROVIDER_DISPATCH_CONTROL_STATES).includes(row.state) ||
    !outcomes.includes(row.transition_outcome) || databaseNow === null ||
    !optionalDigest(row.mcp_result_sha256) ||
    !optionalDigest(row.session_close_sha256) ||
    (
      absent
        ? row.grant_id !== null || expiresAt !== null ||
          row.worker_spec_sha256 !== null ||
          row.mcp_result_sha256 !== null || row.session_close_sha256 !== null
        : !PROVIDER_DISPATCH_UUID.test(row.grant_id ?? "") ||
          expiresAt !== binding.expiresAt ||
          !PROVIDER_DISPATCH_HEX_64.test(row.worker_spec_sha256 ?? "")
    )
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_RESULT_REJECTED");
  }
  return Object.freeze({
    authorizationId: row.authorization_id,
    controlBindingSha256: row.control_binding_sha256,
    databaseNow,
    expiresAt,
    grantId: row.grant_id,
    mcpResultSha256: row.mcp_result_sha256,
    sessionCloseSha256: row.session_close_sha256,
    state: row.state,
    transitionOutcome: row.transition_outcome,
    workerSpecSha256: row.worker_spec_sha256
  });
}

function transientDatabaseFailure(cause) {
  return cause?.code === "40001" || /^08/u.test(cause?.code ?? "") ||
    ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"]
      .includes(cause?.code);
}

export class ProviderDispatchDatabaseClient {
  #applicationName;
  #clientFactory;
  #connectionString;

  constructor({ applicationName, clientFactory = null, connectionString } = {}) {
    if (!/^[a-z0-9-]{8,80}$/u.test(applicationName ?? "")) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED");
    }
    this.#applicationName = applicationName;
    if (typeof clientFactory === "function") {
      this.#clientFactory = clientFactory;
    } else if (typeof connectionString === "string" && connectionString) {
      this.#connectionString = connectionStringForDatabase(
        connectionString,
        "tideproof"
      );
    } else {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED");
    }
  }

  #client() {
    if (this.#clientFactory) return this.#clientFactory(this.#applicationName);
    return new Client(runtimeDatabaseConfig({
      applicationName: this.#applicationName,
      connectionString: this.#connectionString,
      max: 1
    }));
  }

  async query({ attempts = 1, params, sql }) {
    if (
      !Number.isSafeInteger(attempts) || attempts < 1 || attempts > 5 ||
      !Array.isArray(params) || typeof sql !== "string" || sql.length === 0
    ) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_QUERY_REJECTED");
    }
    let last;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const client = this.#client();
      try {
        await client.connect();
        return await client.query(sql, params);
      } catch (cause) {
        last = cause;
        if (!transientDatabaseFailure(cause) || attempt === attempts) break;
      } finally {
        await client.end().catch(() => {});
      }
    }
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_UNAVAILABLE", last);
  }
}
