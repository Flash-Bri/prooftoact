import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  ProviderDispatchDatabaseClient,
  validateProviderDispatchResult
} from "./provider-dispatch-client.js";

export const PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS = Object.freeze({
  DELIVER_CREDENTIAL_ONCE: "DELIVER_CREDENTIAL_ONCE",
  DO_NOT_DELIVER_CREDENTIAL: "DO_NOT_DELIVER_CREDENTIAL"
});

const OUTCOMES = Object.freeze([
  "ACTIVATION_ALREADY_CONSUMED",
  "ACTIVATION_GRANTED",
  "ACTIVATION_NOT_AUTHORIZED"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    Reflect.ownKeys(value).every((key) =>
      typeof key === "string" && keys.includes(key)
    ) && keys.every((key) => Object.hasOwn(value, key));
}

function databaseFailureCode(cause) {
  for (let current = cause, depth = 0;
    current && typeof current === "object" && depth < 4;
    current = current.cause, depth += 1) {
    if (typeof current.code === "string") return current.code;
  }
  return null;
}

function activationResult(result, binding) {
  const databaseNow = Date.parse(result.databaseNow);
  const issuedAt = Date.parse(binding.issuedAt);
  const expiresAt = Date.parse(binding.expiresAt);
  const current = databaseNow >= issuedAt && databaseNow < expiresAt;
  const freshlyGranted =
    result.transitionOutcome === "ACTIVATION_GRANTED";
  const alreadyConsumed =
    result.transitionOutcome === "ACTIVATION_ALREADY_CONSUMED";
  const notAuthorized =
    result.transitionOutcome === "ACTIVATION_NOT_AUTHORIZED";
  if (
    ((freshlyGranted || alreadyConsumed) &&
      (result.state !== PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED ||
        !current)) ||
    (notAuthorized &&
      result.state === PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED &&
      current)
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED");
  }
  return Object.freeze({
    ...result,
    activationDisposition: freshlyGranted
      ? PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DELIVER_CREDENTIAL_ONCE
      : PROVIDER_DISPATCH_ACTIVATION_DISPOSITIONS.DO_NOT_DELIVER_CREDENTIAL
  });
}

export class ProviderDispatchActivateControl {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchDatabaseClient({
      ...options,
      applicationName: "tideproof-provider-dispatch-activate"
    });
  }

  async activate(bindingInput, input) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    if (!exactRecord(input, [
      "activationRequestSha256",
      "grantId",
      "workerSpecSha256"
    ])) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED");
    const { activationRequestSha256, grantId, workerSpecSha256 } = input;
    if (
      !PROVIDER_DISPATCH_UUID.test(grantId ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(activationRequestSha256 ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(workerSpecSha256 ?? "")
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED");
    let databaseResult;
    try {
      databaseResult = await this.#database.query({
        attempts: 1,
        sql: `
          SELECT *
          FROM tp_api.g1_activate_provider_dispatch_v2(
            $1::UUID, $2::UUID, $3, $4
          )
        `,
        params: [
          binding.authorizationId,
          grantId,
          binding.controlBindingSha256,
          activationRequestSha256
        ]
      });
    } catch (cause) {
      const databaseCode = databaseFailureCode(cause);
      reject(
        ["22023", "42501"].includes(databaseCode)
          ? "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED"
          : "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATION_UNKNOWN_DO_NOT_DELIVER",
        cause
      );
    }
    try {
      const row = databaseResult?.rows?.[0];
      if (
        databaseResult?.rowCount !== 1 || !exactRecord(row, [
          "activated_at",
          "activation_request_sha256",
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
        ])
      ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATE_REJECTED");
      const common = Object.freeze({
        rowCount: 1,
        rows: [Object.fromEntries(Object.entries(row).filter(([name]) =>
          !["activated_at", "activation_request_sha256"].includes(name)
        ))]
      });
      const result = validateProviderDispatchResult(common, binding, {
        outcomes: OUTCOMES
      });
      const grantedOrConsumed = [
        "ACTIVATION_GRANTED", "ACTIVATION_ALREADY_CONSUMED"
      ].includes(result.transitionOutcome);
      const activatedAt = row.activated_at === null
        ? null
        : new Date(row.activated_at).toISOString();
      if (
        result.grantId !== grantId ||
        result.workerSpecSha256 !== workerSpecSha256 ||
        (grantedOrConsumed
          ? row.activation_request_sha256 !== activationRequestSha256 ||
            activatedAt === null ||
            (result.transitionOutcome === "ACTIVATION_GRANTED" &&
              activatedAt !== result.databaseNow) ||
            (result.transitionOutcome === "ACTIVATION_ALREADY_CONSUMED" &&
              Date.parse(activatedAt) > Date.parse(result.databaseNow))
          : row.activation_request_sha256 !== null || activatedAt !== null)
      ) throw new Error("provider activation database result identity mismatch");
      return activationResult(Object.freeze({ ...result, activatedAt }), binding);
    } catch (cause) {
      if (
        cause?.message ===
        "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATION_UNKNOWN_DO_NOT_DELIVER"
      ) throw cause;
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_ACTIVATION_UNKNOWN_DO_NOT_DELIVER",
        cause
      );
    }
  }
}
