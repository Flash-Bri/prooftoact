const SCHEMA_VERSION = "tideproof.database-commit-result.v1";
const SHA256 = /^[0-9a-f]{64}$/u;
const OPERATION = /^[a-z][a-z0-9_]{0,63}$/u;
const OBSERVATIONS = new Set(["direct_ack", "read_reconciled"]);

function requiredText(value, code) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(code);
  }
  return value.trim();
}

function operationIdentity(operation, operationDigest) {
  const acceptedOperation = requiredText(
    operation,
    "DATABASE_COMMIT_OPERATION_INVALID"
  );
  const acceptedDigest = requiredText(
    operationDigest,
    "DATABASE_COMMIT_DIGEST_INVALID"
  ).toLowerCase();
  if (!OPERATION.test(acceptedOperation)) {
    throw new TypeError("DATABASE_COMMIT_OPERATION_INVALID");
  }
  if (!SHA256.test(acceptedDigest)) {
    throw new TypeError("DATABASE_COMMIT_DIGEST_INVALID");
  }
  return { operation: acceptedOperation, operationDigest: acceptedDigest };
}

function databaseTimestamp(value) {
  if (typeof value !== "string") {
    throw new TypeError("DATABASE_COMMIT_TIME_INVALID");
  }
  return databaseTimestampFromDriver(value);
}

export function databaseTimestampFromDriver(value) {
  if (!(value instanceof Date) && typeof value !== "string") {
    throw new TypeError("DATABASE_COMMIT_TIME_INVALID");
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    throw new TypeError("DATABASE_COMMIT_TIME_INVALID");
  }
  return parsed.toISOString();
}

function authorityState({ authorityCurrent, requiresFreshAuthorization }) {
  if (
    authorityCurrent !== null &&
    typeof authorityCurrent !== "boolean"
  ) {
    throw new TypeError("DATABASE_COMMIT_AUTHORITY_INVALID");
  }
  if (typeof requiresFreshAuthorization !== "boolean") {
    throw new TypeError("DATABASE_COMMIT_AUTHORITY_INVALID");
  }
  if (
    (authorityCurrent === true && requiresFreshAuthorization) ||
    (authorityCurrent !== true && !requiresFreshAuthorization)
  ) {
    throw new TypeError("DATABASE_COMMIT_AUTHORITY_INVALID");
  }
  return {
    current: authorityCurrent,
    requiresFreshAuthorization
  };
}

export function committedDatabaseResult({
  operation,
  operationDigest,
  observation,
  databaseNow,
  outcome,
  authorityCurrent = null,
  requiresFreshAuthorization = true,
  reason = null
}) {
  const identity = operationIdentity(operation, operationDigest);
  if (!OBSERVATIONS.has(observation)) {
    throw new TypeError("DATABASE_COMMIT_OBSERVATION_INVALID");
  }
  const acceptedOutcome = requiredText(
    outcome,
    "DATABASE_COMMIT_OUTCOME_INVALID"
  );
  const authority = authorityState({
    authorityCurrent,
    requiresFreshAuthorization
  });
  if (
    acceptedOutcome.includes("denied") &&
    authority.current === true
  ) {
    throw new TypeError("DATABASE_COMMIT_AUTHORITY_INVALID");
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    status:
      authority.current === false && !acceptedOutcome.includes("denied")
        ? "COMMITTED_BUT_NO_LONGER_CURRENT"
        : "COMMITTED",
    ...identity,
    observation,
    databaseNow: databaseTimestamp(databaseNow),
    outcome: acceptedOutcome,
    authority,
    reason:
      reason === null
        ? null
        : requiredText(reason, "DATABASE_COMMIT_REASON_INVALID")
  };
}

export function nonDurableDatabaseResult({
  operation,
  operationDigest,
  observation = "direct_ack",
  databaseNow,
  outcome,
  reason
}) {
  const identity = operationIdentity(operation, operationDigest);
  if (observation !== "direct_ack") {
    throw new TypeError("DATABASE_COMMIT_OBSERVATION_INVALID");
  }
  const acceptedOutcome = requiredText(
    outcome,
    "DATABASE_COMMIT_OUTCOME_INVALID"
  );
  if (!acceptedOutcome.includes("denied")) {
    throw new TypeError("DATABASE_COMMIT_OUTCOME_INVALID");
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    status: "DENIED_NOT_DURABLE",
    ...identity,
    observation,
    databaseNow: databaseTimestamp(databaseNow),
    outcome: acceptedOutcome,
    authority: authorityState({
      authorityCurrent: false,
      requiresFreshAuthorization: true
    }),
    reason: requiredText(reason, "DATABASE_COMMIT_REASON_INVALID")
  };
}

export function unknownDatabaseResult({
  operation,
  operationDigest,
  reason,
  requiresFreshAuthorization = true
}) {
  const identity = operationIdentity(operation, operationDigest);
  return {
    schemaVersion: SCHEMA_VERSION,
    status: "UNKNOWN_DO_NOT_ACT",
    ...identity,
    observation: "read_reconciled",
    databaseNow: null,
    outcome: null,
    authority: authorityState({
      authorityCurrent: null,
      requiresFreshAuthorization
    }),
    reason: requiredText(reason, "DATABASE_COMMIT_REASON_INVALID")
  };
}

export const DATABASE_COMMIT_RESULT_SCHEMA = SCHEMA_VERSION;
