import { Client } from "pg";

import {
  connectionStringForExactDatabase,
  runtimeDatabaseConfig
} from "./database-runtime.js";
import {
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
export { validateProviderDispatchResult } from "./provider-dispatch-result.js";
import { validateProviderDispatchResult } from "./provider-dispatch-result.js";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
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
      this.#connectionString = connectionStringForExactDatabase(
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
