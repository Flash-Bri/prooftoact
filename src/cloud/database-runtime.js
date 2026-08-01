const RUNTIME_CONNECTION_TIMEOUT_MS = 2_000;
const RUNTIME_QUERY_TIMEOUT_MS = 4_500;
const RUNTIME_STATEMENT_TIMEOUT_MS = 4_000;
const RUNTIME_IDLE_TRANSACTION_TIMEOUT_MS = 3_000;
const BOOTSTRAP_CONNECTION_TIMEOUT_MS = 10_000;
const BOOTSTRAP_QUERY_TIMEOUT_MS = 65_000;
const BOOTSTRAP_STATEMENT_TIMEOUT_MS = 60_000;
const BOOTSTRAP_IDLE_TRANSACTION_TIMEOUT_MS = 10_000;

const FORBIDDEN_CONNECTION_PARAMETERS = new Set([
  "application_name",
  "connect_timeout",
  "fallback_application_name",
  "idle_in_transaction_session_timeout",
  "lock_timeout",
  "options",
  "query_timeout",
  "statement_timeout"
]);
const REQUIRED_CONNECTION_PARAMETERS = Object.freeze({
  sslmode: "verify-full"
});
const APPLICATION_NAME = /^[a-z][a-z0-9-]{0,62}$/u;

const FORBIDDEN_ENVIRONMENT_NAMES = new Set([
  "PGAPPNAME",
  "PGCONNECT_TIMEOUT",
  "PGDATABASE",
  "PGHOST",
  "PGHOSTADDR",
  "PGOPTIONS",
  "PGPASSWORD",
  "PGPORT",
  "PGSERVICE",
  "PGSERVICEFILE",
  "PGSSLCERT",
  "PGSSLCRL",
  "PGSSLKEY",
  "PGSSLROOTCERT",
  "PGSSLMODE",
  "PGTARGETSESSIONATTRS",
  "PGUSER"
]);

function requireConnectionString(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError("DATABASE_CONNECTION_STRING_REQUIRED");
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("DATABASE_CONNECTION_STRING_INVALID");
  }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new TypeError("DATABASE_CONNECTION_SCHEME_INVALID");
  }
  const seen = new Set();
  for (const [name, parameterValue] of url.searchParams) {
    const normalizedName = name.toLowerCase();
    if (
      seen.has(normalizedName) ||
      FORBIDDEN_CONNECTION_PARAMETERS.has(normalizedName)
    ) {
      throw new Error("DATABASE_CONNECTION_RUNTIME_OVERRIDE_REJECTED");
    }
    seen.add(normalizedName);
    if (
      !Object.hasOwn(REQUIRED_CONNECTION_PARAMETERS, normalizedName) ||
      parameterValue !== REQUIRED_CONNECTION_PARAMETERS[normalizedName]
    ) {
      throw new Error("DATABASE_CONNECTION_TLS_POLICY_REJECTED");
    }
  }
  if (
    Object.keys(REQUIRED_CONNECTION_PARAMETERS).some(
      (name) => !seen.has(name)
    )
  ) {
    throw new Error("DATABASE_CONNECTION_TLS_POLICY_REJECTED");
  }
  return url;
}

function assertNoAmbientPgOverrides(environment) {
  if (!environment || typeof environment !== "object") {
    throw new TypeError("DATABASE_ENVIRONMENT_INVALID");
  }
  for (const name of Object.keys(environment)) {
    if (FORBIDDEN_ENVIRONMENT_NAMES.has(name.toUpperCase())) {
      throw new Error("DATABASE_AMBIENT_CONFIGURATION_REJECTED");
    }
  }
}

function positiveInteger(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${name} outside policy`);
  }
  return value;
}

function configFor({
  connectionString,
  max,
  idleTimeoutMillis,
  applicationName,
  environment,
  connectionTimeoutMillis,
  queryTimeoutMillis,
  statementTimeoutMillis,
  idleTransactionTimeoutMillis
}) {
  const url = requireConnectionString(connectionString);
  assertNoAmbientPgOverrides(environment);
  const acceptedMax = positiveInteger(max, "max", 64);
  const acceptedIdle = positiveInteger(
    idleTimeoutMillis,
    "idleTimeoutMillis",
    60_000
  );
  if (
    typeof applicationName !== "string" ||
    !APPLICATION_NAME.test(applicationName)
  ) {
    throw new TypeError("DATABASE_APPLICATION_NAME_INVALID");
  }
  return {
    connectionString: url.toString(),
    max: acceptedMax,
    idleTimeoutMillis: acceptedIdle,
    connectionTimeoutMillis,
    query_timeout: queryTimeoutMillis,
    statement_timeout: statementTimeoutMillis,
    idle_in_transaction_session_timeout: idleTransactionTimeoutMillis,
    application_name: applicationName,
    options:
      `-c statement_timeout=${statementTimeoutMillis}` +
      ` -c idle_in_transaction_session_timeout=${idleTransactionTimeoutMillis}` +
      ` -c application_name=${applicationName}`
  };
}

export function connectionStringForExactDatabase(
  connectionString,
  databaseName
) {
  const url = requireConnectionString(connectionString);
  if (
    typeof databaseName !== "string" ||
    !/^[a-z][a-z0-9_]{0,62}$/u.test(databaseName)
  ) {
    throw new TypeError("DATABASE_NAME_INVALID");
  }
  url.pathname = `/${databaseName}`;
  return url.toString();
}

export function runtimeDatabaseConfig({
  connectionString,
  max = 4,
  idleTimeoutMillis = 10_000,
  applicationName = "tideproof-runtime",
  environment = process.env
} = {}) {
  return configFor({
    connectionString,
    max,
    idleTimeoutMillis,
    applicationName,
    environment,
    connectionTimeoutMillis: RUNTIME_CONNECTION_TIMEOUT_MS,
    queryTimeoutMillis: RUNTIME_QUERY_TIMEOUT_MS,
    statementTimeoutMillis: RUNTIME_STATEMENT_TIMEOUT_MS,
    idleTransactionTimeoutMillis: RUNTIME_IDLE_TRANSACTION_TIMEOUT_MS
  });
}

export function bootstrapDatabaseConfig({
  connectionString,
  max = 1,
  idleTimeoutMillis = 10_000,
  applicationName = "tideproof-bootstrap",
  environment = process.env
} = {}) {
  return configFor({
    connectionString,
    max,
    idleTimeoutMillis,
    applicationName,
    environment,
    connectionTimeoutMillis: BOOTSTRAP_CONNECTION_TIMEOUT_MS,
    queryTimeoutMillis: BOOTSTRAP_QUERY_TIMEOUT_MS,
    statementTimeoutMillis: BOOTSTRAP_STATEMENT_TIMEOUT_MS,
    idleTransactionTimeoutMillis: BOOTSTRAP_IDLE_TRANSACTION_TIMEOUT_MS
  });
}

export function databaseClientMustBeDiscarded(error) {
  const code = typeof error?.code === "string" ? error.code.toUpperCase() : "";
  if (
    code.startsWith("08") ||
    code === "40003" ||
    code === "57P01" ||
    code === "57P02" ||
    code === "57P03" ||
    code === "ECONNRESET" ||
    code === "EPIPE" ||
    code === "ETIMEDOUT"
  ) {
    return true;
  }
  const message = typeof error?.message === "string"
    ? error.message.toLowerCase()
    : "";
  return (
    message.includes("query read timeout") ||
    message.includes("connection terminated") ||
    message.includes("connection timeout") ||
    message.includes("timeout expired")
  );
}

export const DATABASE_RUNTIME_LIMITS = Object.freeze({
  connectionTimeoutMillis: RUNTIME_CONNECTION_TIMEOUT_MS,
  queryTimeoutMillis: RUNTIME_QUERY_TIMEOUT_MS,
  statementTimeoutMillis: RUNTIME_STATEMENT_TIMEOUT_MS,
  idleTransactionTimeoutMillis: RUNTIME_IDLE_TRANSACTION_TIMEOUT_MS
});
