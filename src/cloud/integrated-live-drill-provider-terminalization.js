import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_SCHEMA =
  "tideproof.highwater-drill-provider-terminalization.v1";

export const INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS =
  Object.freeze({
    NOT_DUE: "NOT_DUE",
    TERMINAL_COMPLETED: "TERMINAL_COMPLETED",
    TERMINAL_EXPIRED: "TERMINAL_EXPIRED",
    TERMINAL_UNKNOWN_DO_NOT_ACT: "TERMINAL_UNKNOWN_DO_NOT_ACT"
  });

const INPUT_KEYS = Object.freeze([
  "binding",
  "grantId",
  "workerSpecSha256"
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

export function validateIntegratedLiveDrillProviderTerminalizationInput(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_INPUT_REJECTED";
  if (
    !exactRecord(value, INPUT_KEYS) ||
    !PROVIDER_DISPATCH_UUID.test(value.grantId ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(value.workerSpecSha256 ?? "")
  ) reject(code);
  return Object.freeze({
    binding: validateProviderDispatchControlBinding(value.binding),
    grantId: value.grantId,
    workerSpecSha256: value.workerSpecSha256
  });
}

function classifyTerminalization(result, input) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_RESULT_REJECTED";
  const databaseNow = Date.parse(result?.databaseNow ?? "");
  const expiresAt = Date.parse(result?.expiresAt ?? "");
  const beforeExpiry = databaseNow < expiresAt;
  const exactIdentity = result?.grantId === input.grantId &&
    result?.workerSpecSha256 === input.workerSpecSha256 &&
    result?.authorizationId === input.binding.authorizationId &&
    result?.controlBindingSha256 === input.binding.controlBindingSha256 &&
    result?.expiresAt === input.binding.expiresAt;
  let disposition;
  if (
    result?.transitionOutcome === "NOT_EXPIRED" && beforeExpiry &&
    [
      PROVIDER_DISPATCH_CONTROL_STATES.GRANTED,
      PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING,
      PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED
    ].includes(result.state)
  ) {
    disposition =
      INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS.NOT_DUE;
  } else if (
    result?.transitionOutcome === "EXPIRED_RECORDED" && !beforeExpiry &&
    result.state === PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED
  ) {
    disposition =
      INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS.TERMINAL_EXPIRED;
  } else if (
    result?.transitionOutcome === "UNKNOWN_RECORDED" && !beforeExpiry &&
    result.state === PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT
  ) {
    disposition =
      INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
        .TERMINAL_UNKNOWN_DO_NOT_ACT;
  } else if (result?.transitionOutcome === "ALREADY_TERMINAL") {
    if (result.state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED) {
      disposition =
        INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
          .TERMINAL_COMPLETED;
    } else if (
      result.state === PROVIDER_DISPATCH_CONTROL_STATES.UNKNOWN_DO_NOT_ACT
    ) {
      disposition =
        INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
          .TERMINAL_UNKNOWN_DO_NOT_ACT;
    } else if (
      result.state === PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED && !beforeExpiry
    ) {
      disposition =
        INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_DISPOSITIONS
          .TERMINAL_EXPIRED;
    }
  }
  if (!exactIdentity || !Number.isFinite(databaseNow) || disposition === undefined) {
    reject(code);
  }
  return disposition;
}

export async function terminalizeIntegratedLiveDrillProviderDispatch({
  input,
  terminalizeControl
}) {
  const validated = validateIntegratedLiveDrillProviderTerminalizationInput(
    input
  );
  if (typeof terminalizeControl?.terminalize !== "function") {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_INPUT_REJECTED");
  }
  let result;
  try {
    result = await terminalizeControl.terminalize(validated.binding, {
      grantId: validated.grantId,
      workerSpecSha256: validated.workerSpecSha256
    });
  } catch (cause) {
    if (
      String(cause?.message ?? "") ===
      "INTEGRATED_LIVE_DRILL_PROVIDER_CONTROL_TERMINALIZE_REJECTED"
    ) {
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_REJECTED", cause);
    }
    reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_RETRY_REQUIRED",
      cause
    );
  }
  const disposition = classifyTerminalization(result, validated);
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_SCHEMA,
    authorizationId: result.authorizationId,
    controlBindingSha256: result.controlBindingSha256,
    databaseNow: result.databaseNow,
    disposition,
    expiresAt: result.expiresAt,
    grantId: result.grantId,
    state: result.state,
    transitionOutcome: result.transitionOutcome,
    workerSpecSha256: result.workerSpecSha256
  });
}
