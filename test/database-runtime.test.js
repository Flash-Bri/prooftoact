import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "pg";

import {
  bootstrapDatabaseConfig,
  connectionStringForExactDatabase,
  databaseClientMustBeDiscarded,
  runtimeDatabaseConfig
} from "../src/cloud/database-runtime.js";

const CONNECTION =
  "postgresql://runtime:secret@example.invalid/defaultdb?sslmode=verify-full";

test("runtime database configuration enforces server and client deadlines", () => {
  const config = runtimeDatabaseConfig({
    connectionString: CONNECTION,
    max: 4,
    applicationName: "tideproof-test-runtime",
    environment: {}
  });
  assert.equal(config.connectionTimeoutMillis, 2_000);
  assert.equal(config.statement_timeout, 4_000);
  assert.equal(config.query_timeout, 4_500);
  assert.equal(config.idle_in_transaction_session_timeout, 3_000);
  assert.match(config.options, /statement_timeout=4000/u);
  assert.match(config.options, /idle_in_transaction_session_timeout=3000/u);

  const parameters = new Client(config).connectionParameters;
  assert.equal(parameters.statement_timeout, 4_000);
  assert.equal(parameters.query_timeout, 4_500);
  assert.equal(parameters.application_name, "tideproof-test-runtime");
  assert.match(parameters.options, /statement_timeout=4000/u);
});

test("bootstrap database configuration is separately bounded for DDL", () => {
  const config = bootstrapDatabaseConfig({
    connectionString: CONNECTION,
    applicationName: "tideproof-test-bootstrap",
    environment: {}
  });
  assert.equal(config.statement_timeout, 60_000);
  assert.equal(config.query_timeout, 65_000);
  assert.equal(config.connectionTimeoutMillis, 10_000);
});

test("database URLs cannot override reviewed runtime controls", () => {
  for (const query of [
    "statement_timeout=0",
    "query_timeout=0",
    "OpTiOnS=-c%20statement_timeout%3D0",
    "application_name=forged",
    "fallback_application_name=forged",
    "connect_timeout=9999",
    "lock_timeout=0"
  ]) {
    assert.throws(
      () => runtimeDatabaseConfig({
        connectionString: `postgresql://u:p@example.invalid/db?${query}`,
        environment: {}
      }),
      ({ message }) => message === "DATABASE_CONNECTION_RUNTIME_OVERRIDE_REJECTED"
    );
  }
});

test("database URLs require one verify-full TLS parameter and a safe application name", () => {
  for (const connectionString of [
    "postgresql://u:p@example.invalid/db",
    "postgresql://u:p@example.invalid/db?sslmode=disable",
    "postgresql://u:p@example.invalid/db?sslmode=no-verify",
    "postgresql://u:p@example.invalid/db?sslmode=verify-full&sslmode=disable",
    "postgresql://u:p@example.invalid/db?sslmode=verify-full&sslrootcert=/tmp/ca"
  ]) {
    assert.throws(
      () => runtimeDatabaseConfig({ connectionString, environment: {} }),
      /DATABASE_CONNECTION_(?:TLS_POLICY|RUNTIME_OVERRIDE)_REJECTED/u
    );
  }
  assert.throws(
    () => runtimeDatabaseConfig({
      connectionString: CONNECTION,
      applicationName: "safe -c statement_timeout=0",
      environment: {}
    }),
    /DATABASE_APPLICATION_NAME_INVALID/u
  );
});

test("ambient libpq controls fail closed without exposing credentials", () => {
  for (const name of [
    "NODE_DEBUG",
    "NODE_EXTRA_CA_CERTS",
    "NODE_OPTIONS",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "OPENSSL_CONF",
    "PGCHANNELBINDING",
    "PGOPTIONS",
    "PGPASSFILE",
    "PG_UNREVIEWED_FUTURE_OVERRIDE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSLKEYLOGFILE"
  ]) {
    assert.throws(
      () => runtimeDatabaseConfig({
        connectionString: CONNECTION,
        environment: { [name]: "unsafe-ambient-value" }
      }),
      ({ message }) =>
        message === "DATABASE_AMBIENT_CONFIGURATION_REJECTED"
    );
  }
  assert.throws(
    () => runtimeDatabaseConfig({
      connectionString: "postgresql://user:super-secret@example.invalid/db?statement_timeout=0",
      environment: {}
    }),
    (error) => {
      assert.equal(error.message.includes("super-secret"), false);
      assert.equal(error.message.includes("example.invalid"), false);
      return true;
    }
  );
});

test("database client discard policy distinguishes ambiguity from retry", () => {
  assert.equal(databaseClientMustBeDiscarded({ code: "40001" }), false);
  assert.equal(databaseClientMustBeDiscarded({ code: "57014" }), false);
  assert.equal(databaseClientMustBeDiscarded({ code: "40003" }), true);
  assert.equal(databaseClientMustBeDiscarded({ code: "08006" }), true);
  assert.equal(databaseClientMustBeDiscarded({ code: "57P01" }), true);
  assert.equal(databaseClientMustBeDiscarded({ code: "ECONNRESET" }), true);
  assert.equal(
    databaseClientMustBeDiscarded(new Error("Query read timeout")),
    true
  );
});

test("exact database pinning preserves reviewed TLS parameters", () => {
  const pinned = new URL(
    connectionStringForExactDatabase(CONNECTION, "tideproof")
  );
  assert.equal(pinned.pathname, "/tideproof");
  assert.equal(pinned.searchParams.get("sslmode"), "verify-full");
});
