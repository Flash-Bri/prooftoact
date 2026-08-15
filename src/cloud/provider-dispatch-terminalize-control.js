import {
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  ProviderDispatchDatabaseClient,
  validateProviderDispatchResult
} from "./provider-dispatch-client.js";

const OUTCOMES = Object.freeze([
  "ALREADY_TERMINAL",
  "EXPIRED_RECORDED",
  "NOT_EXPIRED",
  "UNKNOWN_RECORDED"
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

export class ProviderDispatchTerminalizeControl {
  #database;

  constructor(options = {}) {
    this.#database = new ProviderDispatchDatabaseClient({
      ...options,
      applicationName: "tideproof-provider-dispatch-terminalize"
    });
  }

  async terminalize(bindingInput, input) {
    const binding = validateProviderDispatchControlBinding(bindingInput);
    if (!exactRecord(input, ["grantId", "workerSpecSha256"])) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED");
    }
    const { grantId, workerSpecSha256 } = input;
    if (
      !PROVIDER_DISPATCH_UUID.test(grantId ?? "") ||
      !PROVIDER_DISPATCH_HEX_64.test(workerSpecSha256 ?? "")
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED");
    let databaseResult;
    try {
      databaseResult = await this.#database.query({
        attempts: 3,
        sql: `
          SELECT *
          FROM tp_api.g1_terminalize_provider_dispatch_v2(
            $1::UUID, $2::UUID, $3, $4
          )
        `,
        params: [
          binding.authorizationId,
          grantId,
          binding.controlBindingSha256,
          workerSpecSha256
        ]
      });
    } catch (cause) {
      const databaseCode = databaseFailureCode(cause);
      reject(
        ["22023", "42501"].includes(databaseCode)
          ? "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED"
          : "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZATION_RETRY_REQUIRED",
        cause
      );
    }
    const result = validateProviderDispatchResult(databaseResult, binding, {
      outcomes: OUTCOMES
    });
    if (
      result.grantId !== grantId ||
      result.workerSpecSha256 !== workerSpecSha256
    ) reject("INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED");
    return result;
  }
}
