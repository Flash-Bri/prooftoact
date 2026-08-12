import { createHash, randomUUID } from "node:crypto";

import { Client } from "pg";

import { connectionStringForDatabase } from "./authority-store.js";
import { canonicalJson } from "./canonical-json.js";
import { runtimeDatabaseConfig } from "./database-runtime.js";

export const PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA =
  "tideproof.provider-dispatch-control-binding.v1";
export const PROVIDER_DISPATCH_CONTROL_STATES = Object.freeze({
  COMPLETED: "COMPLETED",
  CONSUMED: "CONSUMED",
  EXPIRED: "EXPIRED",
  UNKNOWN_DO_NOT_ACT: "UNKNOWN_DO_NOT_ACT"
});

const ACTIONS = Object.freeze({
  COMPLETE: "COMPLETE",
  CONSUME: "CONSUME",
  MARK_UNKNOWN: "MARK_UNKNOWN",
  RESOLVE: "RESOLVE"
});
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BINDING_KEYS = Object.freeze([
  "authorizationId",
  "controlBindingSha256",
  "expiresAt",
  "interactionId",
  "issuedAt",
  "logicalMcpRequestSha256",
  "providerDispatchAuthorizationSha256",
  "providerEffectKeySha256",
  "runId",
  "schemaVersion",
  "sourceBuildIdentity",
  "sourceCommit",
  "tenantId",
  "treeDigest"
]);

function fail(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactRecord(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    return false;
  }
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length &&
    ownKeys.every((key) => typeof key === "string") &&
    ownKeys.every((key) => keys.includes(key)) &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactIso(value) {
  if (typeof value !== "string") return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value
    ? value
    : null;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function providerDispatchEffectKeySha256({
  logicalMcpRequestSha256,
  recoveryClusterId
}) {
  if (
    !HEX_64.test(logicalMcpRequestSha256 ?? "") ||
    !UUID.test(recoveryClusterId ?? "")
  ) {
    fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_BINDING_REJECTED");
  }
  return sha256(canonicalJson({
    schemaVersion: "tideproof.provider-effect-key.v1",
    database: "tideproof_recovery",
    logicalMcpRequestSha256,
    provider: "cockroachdb-managed-mcp",
    recoveryClusterId,
    tool: "select_query"
  }));
}

export function buildProviderDispatchControlBinding({
  context,
  dispatchAuthorizationSha256,
  earliestControllingExpiry,
  latestControllingIssuedAt
}) {
  const intent = context?.preCallIntent;
  const spec = context?.trustedRunContext?.spec;
  const issuedAt = Number.isSafeInteger(latestControllingIssuedAt)
    ? new Date(latestControllingIssuedAt).toISOString()
    : null;
  const expiresAt = Number.isSafeInteger(earliestControllingExpiry)
    ? new Date(earliestControllingExpiry).toISOString()
    : null;
  const body = {
    authorizationId: intent?.authorizationId,
    expiresAt,
    interactionId: intent?.interactionId,
    issuedAt,
    logicalMcpRequestSha256: intent?.logicalMcpRequestSha256,
    providerDispatchAuthorizationSha256: dispatchAuthorizationSha256,
    providerEffectKeySha256: providerDispatchEffectKeySha256({
      logicalMcpRequestSha256: intent?.logicalMcpRequestSha256,
      recoveryClusterId: intent?.recoveryClusterId
    }),
    runId: intent?.runId,
    schemaVersion: PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA,
    sourceBuildIdentity: spec?.sourceBuildIdentity,
    sourceCommit: spec?.sourceCommit,
    tenantId: intent?.tenantId,
    treeDigest: spec?.treeDigest
  };
  const binding = Object.freeze({
    ...body,
    controlBindingSha256: sha256(canonicalJson(body))
  });
  return validateProviderDispatchControlBinding(binding);
}

export function validateProviderDispatchControlBinding(value) {
  const issuedAt = exactIso(value?.issuedAt);
  const expiresAt = exactIso(value?.expiresAt);
  if (
    !exactRecord(value, BINDING_KEYS) ||
    value.schemaVersion !== PROVIDER_DISPATCH_CONTROL_BINDING_SCHEMA ||
    !UUID.test(value.authorizationId ?? "") ||
    !UUID.test(value.interactionId ?? "") ||
    !UUID.test(value.runId ?? "") ||
    !UUID.test(value.tenantId ?? "") ||
    !HEX_40.test(value.sourceCommit ?? "") ||
    !HEX_40.test(value.treeDigest ?? "") ||
    !HEX_64.test(value.sourceBuildIdentity ?? "") ||
    !HEX_64.test(value.logicalMcpRequestSha256 ?? "") ||
    !HEX_64.test(value.providerDispatchAuthorizationSha256 ?? "") ||
    !HEX_64.test(value.providerEffectKeySha256 ?? "") ||
    !HEX_64.test(value.controlBindingSha256 ?? "") ||
    issuedAt === null ||
    expiresAt === null ||
    Date.parse(issuedAt) >= Date.parse(expiresAt)
  ) {
    fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_BINDING_REJECTED");
  }
  const body = Object.fromEntries(
    BINDING_KEYS
      .filter((key) => key !== "controlBindingSha256")
      .map((key) => [key, value[key]])
  );
  if (sha256(canonicalJson(body)) !== value.controlBindingSha256) {
    fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_BINDING_REJECTED");
  }
  return Object.freeze({ ...value });
}

function validateTerminalDigests(action, terminal) {
  const absent = terminal === null || terminal === undefined;
  if (action === ACTIONS.COMPLETE) {
    if (
      absent ||
      !exactRecord(terminal, ["mcpResultSha256", "sessionCloseSha256"]) ||
      !HEX_64.test(terminal.mcpResultSha256 ?? "") ||
      !HEX_64.test(terminal.sessionCloseSha256 ?? "")
    ) {
      fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TRANSITION_REJECTED");
    }
    return terminal;
  }
  if (!absent) {
    fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TRANSITION_REJECTED");
  }
  return Object.freeze({
    mcpResultSha256: null,
    sessionCloseSha256: null
  });
}

function validateTransitionResult(result, binding) {
  const row = result?.rows?.[0];
  if (
    result?.rowCount !== 1 ||
    row?.authorization_id !== binding.authorizationId ||
    row?.control_binding_sha256 !== binding.controlBindingSha256 ||
    !Object.values(PROVIDER_DISPATCH_CONTROL_STATES).includes(row?.state) ||
    typeof row?.transition_outcome !== "string" ||
    !UUID.test(row?.owner_nonce ?? "") ||
    exactIso(new Date(row?.database_now).toISOString()) === null ||
    exactIso(new Date(row?.expires_at).toISOString()) !== binding.expiresAt ||
    (
      row.mcp_result_sha256 !== null &&
      !HEX_64.test(row.mcp_result_sha256 ?? "")
    ) ||
    (
      row.session_close_sha256 !== null &&
      !HEX_64.test(row.session_close_sha256 ?? "")
    )
  ) {
    fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_RESULT_REJECTED");
  }
  return Object.freeze({
    authorizationId: row.authorization_id,
    controlBindingSha256: row.control_binding_sha256,
    databaseNow: new Date(row.database_now).toISOString(),
    expiresAt: new Date(row.expires_at).toISOString(),
    mcpResultSha256: row.mcp_result_sha256,
    ownerNonce: row.owner_nonce,
    sessionCloseSha256: row.session_close_sha256,
    state: row.state,
    transitionOutcome: row.transition_outcome
  });
}

export class ProviderDispatchControl {
  #clientFactory;
  #connectionString;
  #ownerNonce;

  constructor({
    connectionString,
    clientFactory = null,
    ownerNonce = randomUUID()
  } = {}) {
    if (!UUID.test(ownerNonce ?? "")) {
      fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_OWNER_REJECTED");
    }
    if (typeof clientFactory === "function") {
      this.#clientFactory = clientFactory;
    } else if (typeof connectionString === "string" && connectionString) {
      this.#connectionString = connectionStringForDatabase(
        connectionString,
        "tideproof"
      );
    } else {
      fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_DATABASE_REJECTED");
    }
    this.#ownerNonce = ownerNonce;
  }

  #client() {
    if (this.#clientFactory) {
      return this.#clientFactory("tideproof-provider-dispatch-control");
    }
    return new Client(runtimeDatabaseConfig({
      applicationName: "tideproof-provider-dispatch-control",
      connectionString: this.#connectionString,
      max: 1
    }));
  }

  async #transition(
    action,
    bindingInput,
    terminalInput = null,
    ownerNonceInput = this.#ownerNonce
  ) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    const terminal = validateTerminalDigests(action, terminalInput);
    if (!UUID.test(ownerNonceInput ?? "")) {
      fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_OWNER_REJECTED");
    }
    const client = this.#client();
    try {
      await client.connect();
      const result = await client.query(
        `
          SELECT *
          FROM tp_api.g1_transition_provider_dispatch_v1(
            $1, $2::UUID, $3::UUID, $4::UUID, $5::UUID, $6::UUID,
            $7, $8, $9, $10, $11, $12, $13, $14::TIMESTAMPTZ,
            $15::TIMESTAMPTZ, $16, $17
          )
        `,
        [
          action,
          binding.authorizationId,
          binding.tenantId,
          binding.runId,
          binding.interactionId,
          ownerNonceInput,
          binding.controlBindingSha256,
          binding.logicalMcpRequestSha256,
          binding.providerEffectKeySha256,
          binding.providerDispatchAuthorizationSha256,
          binding.sourceCommit,
          binding.treeDigest,
          binding.sourceBuildIdentity,
          binding.issuedAt,
          binding.expiresAt,
          terminal.mcpResultSha256,
          terminal.sessionCloseSha256
        ]
      );
      return validateTransitionResult(result, binding);
    } catch (cause) {
      if (
        /^INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_/u.test(
          String(cause?.message ?? "")
        )
      ) {
        throw cause;
      }
      fail("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_UNAVAILABLE", cause);
    } finally {
      await client.end().catch(() => {});
    }
  }

  consume(binding) {
    return this.#transition(ACTIONS.CONSUME, binding);
  }

  complete(binding, terminal, ownerNonce = this.#ownerNonce) {
    return this.#transition(ACTIONS.COMPLETE, binding, terminal, ownerNonce);
  }

  markUnknown(binding) {
    return this.#transition(ACTIONS.MARK_UNKNOWN, binding);
  }

  resolve(binding) {
    return this.#transition(ACTIONS.RESOLVE, binding);
  }
}
