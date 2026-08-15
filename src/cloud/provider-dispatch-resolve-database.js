import { Client } from "pg";

const APPLICATION_NAME = "tideproof-provider-dispatch-resolve";
const FORBIDDEN_AMBIENT = /^(?:PG.*|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|OPENSSL_.*|SSL_.*|SSLKEYLOGFILE)$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactConnectionString(value) {
  let url;
  try {
    url = new URL(value);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED", cause);
  }
  const parameters = [...url.searchParams.entries()];
  if (
    !["postgres:", "postgresql:"].includes(url.protocol) ||
    url.username.length === 0 || url.hostname.length === 0 ||
    parameters.length !== 1 || parameters[0][0] !== "sslmode" ||
    parameters[0][1] !== "verify-full"
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED");
  }
  url.pathname = "/tideproof";
  return url.toString();
}

function transientDatabaseFailure(cause) {
  return cause?.code === "40001" || /^08/u.test(cause?.code ?? "") ||
    ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT"]
      .includes(cause?.code);
}

export class ProviderDispatchResolveDatabase {
  #clientFactory;
  #connectionString;

  constructor({ clientFactory = null, connectionString } = {}) {
    if (typeof clientFactory === "function") {
      this.#clientFactory = clientFactory;
    } else {
      if (Object.keys(process.env).some((name) => FORBIDDEN_AMBIENT.test(name))) {
        reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED");
      }
      this.#connectionString = exactConnectionString(connectionString);
    }
  }

  #client() {
    if (this.#clientFactory) return this.#clientFactory(APPLICATION_NAME);
    return new Client({
      application_name: APPLICATION_NAME,
      connectionString: this.#connectionString,
      connectionTimeoutMillis: 2_000,
      idle_in_transaction_session_timeout: 3_000,
      max: 1,
      options:
        "-c statement_timeout=4000" +
        " -c idle_in_transaction_session_timeout=3000" +
        ` -c application_name=${APPLICATION_NAME}`,
      query_timeout: 4_500,
      statement_timeout: 4_000
    });
  }

  async query({ params, sql }) {
    let last;
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const client = this.#client();
      try {
        await client.connect();
        return await client.query(sql, params);
      } catch (cause) {
        last = cause;
        if (!transientDatabaseFailure(cause) || attempt === 3) break;
      } finally {
        await client.end().catch(() => {});
      }
    }
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_UNAVAILABLE", last);
  }
}
