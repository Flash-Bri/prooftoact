import { canonicalJson } from "./canonical-json.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  providerDispatchSha256
} from "./provider-dispatch-binding.js";
import {
  validateProviderDispatchReconciliationInput
} from "./provider-dispatch-reconciliation-input.js";
import { ProviderDispatchResolver } from "./provider-dispatch-resolver.js";
import {
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "./integrated-live-drill-runtime.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA =
  "tideproof.highwater-drill-provider-reconciliation.v3";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTCOMES =
  Object.freeze(["RESOLVED", "RESOLVED_ABSENT"]);

const SAFE_ENVIRONMENT_NAMES = Object.freeze([
  "__CF_USER_TEXT_ENCODING",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
  "PATH",
  "TMPDIR",
  "PRIMARY_PROVIDER_RECONCILE_DATABASE_URL",
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    Reflect.ownKeys(value).every((key) =>
      typeof key === "string" && keys.includes(key)
    ) && keys.every((key) => Object.hasOwn(value, key));
}

function requiredText(value, code, maximum = 8192) {
  requireCondition(
    typeof value === "string" && value.length > 0 &&
      value.length <= maximum && !/[\0\r\n]/u.test(value),
    code
  );
  return value;
}

function normalizedEnvironment(environment) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ENVIRONMENT_REJECTED";
  const real = environment === process.env;
  requireCondition(
    environment && typeof environment === "object" &&
      !Array.isArray(environment) &&
      (real || [Object.prototype, null].includes(
        Object.getPrototypeOf(environment)
      )),
    code
  );
  const ownKeys = Reflect.ownKeys(environment);
  requireCondition(
    ownKeys.every((key) => {
      const descriptor = typeof key === "string"
        ? Object.getOwnPropertyDescriptor(environment, key)
        : null;
      return typeof key === "string" && SAFE_ENVIRONMENT_NAMES.includes(key) &&
        descriptor !== null && descriptor !== undefined &&
        Object.hasOwn(descriptor, "value") && descriptor.enumerable === true &&
        typeof descriptor.value === "string";
    }) &&
      !Object.hasOwn(environment, "MCP_API_KEY"),
    code
  );
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(environment, key).value
  ])));
}

export function integratedLiveDrillProviderReconciliationEnvironment(
  sourceEnvironment
) {
  return normalizedEnvironment(Object.freeze({
    ...Object.fromEntries(
      ["__CF_USER_TEXT_ENCODING", "LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR",
        "PATH", "TMPDIR"]
        .filter((name) => typeof sourceEnvironment?.[name] === "string")
        .map((name) => [name, sourceEnvironment[name]])
    ),
    PRIMARY_PROVIDER_RECONCILE_DATABASE_URL: requiredText(
      sourceEnvironment?.PRIMARY_PROVIDER_RECONCILE_DATABASE_URL,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ENVIRONMENT_REJECTED",
      16_384
    )
  }));
}

export const validateIntegratedLiveDrillProviderReconciliationInput =
  validateProviderDispatchReconciliationInput;

export function validateIntegratedLiveDrillProviderReconciliationReceipt(
  value,
  { authorizationId, runId } = {}
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTPUT_REJECTED";
  requireCondition(
    exactRecord(value, [
      "accepted",
      "authorizationId",
      "controlBindingSha256",
      "databaseNow",
      "finalReleaseReady",
      "mcpResultSha256",
      "providerApiCredentialPresent",
      "providerBacked",
      "receiptSha256",
      "runId",
      "schemaVersion",
      "sessionCloseSha256",
      "state",
      "status",
      "transitionOutcome"
    ]),
    code
  );
  const { receiptSha256, ...body } = value;
  const completed = value.state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED;
  const absent = value.state === PROVIDER_DISPATCH_CONTROL_STATES.ABSENT;
  requireCondition(
    value.schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA &&
      value.status === "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED" &&
      value.accepted === false && value.finalReleaseReady === false &&
      value.providerBacked === false &&
      value.providerApiCredentialPresent === false &&
      value.authorizationId === authorizationId && value.runId === runId &&
      PROVIDER_DISPATCH_HEX_64.test(value.controlBindingSha256 ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(receiptSha256 ?? "") &&
      Object.values(PROVIDER_DISPATCH_CONTROL_STATES).includes(value.state) &&
      INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTCOMES.includes(
        value.transitionOutcome
      ) &&
      (value.mcpResultSha256 === null ||
        PROVIDER_DISPATCH_HEX_64.test(value.mcpResultSha256 ?? "")) &&
      (value.sessionCloseSha256 === null ||
        PROVIDER_DISPATCH_HEX_64.test(value.sessionCloseSha256 ?? "")) &&
      (completed
        ? PROVIDER_DISPATCH_HEX_64.test(value.mcpResultSha256 ?? "") &&
          PROVIDER_DISPATCH_HEX_64.test(value.sessionCloseSha256 ?? "")
        : value.mcpResultSha256 === null &&
          value.sessionCloseSha256 === null) &&
      (absent
        ? value.transitionOutcome === "RESOLVED_ABSENT"
        : value.transitionOutcome === "RESOLVED") &&
      Number.isFinite(Date.parse(value.databaseNow ?? "")) &&
      new Date(value.databaseNow).toISOString() === value.databaseNow &&
      providerDispatchSha256(canonicalJson(body)) === receiptSha256,
    code
  );
  return Object.freeze({ ...value });
}

export async function reconcileIntegratedLiveDrillProviderDispatchControl({
  binding,
  resolver
}) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_UNKNOWN_DO_NOT_ACT";
  requireCondition(
    resolver && typeof resolver === "object" &&
      typeof resolver.resolve === "function",
    code
  );
  try {
    return await resolver.resolve(binding);
  } catch (cause) {
    if (String(cause?.message ?? "") === code) throw cause;
    reject(code, cause);
  }
}

export async function runIntegratedLiveDrillProviderReconciliation({
  auditClientFactory = null,
  environment,
  input
}) {
  const isolated = normalizedEnvironment(environment);
  const validated = validateProviderDispatchReconciliationInput(input);
  const resolver = new ProviderDispatchResolver({
    connectionString: requiredText(
      isolated.PRIMARY_PROVIDER_RECONCILE_DATABASE_URL,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_DATABASE_REJECTED",
      16_384
    ),
    clientFactory: auditClientFactory
  });
  const resolved = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding: validated.binding,
    resolver
  });
  requireCondition(
    resolved.state === PROVIDER_DISPATCH_CONTROL_STATES.ABSENT ||
      (resolved.grantId === validated.admission.grantId &&
        resolved.workerSpecSha256 === validated.admission.workerSpecSha256),
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ADMISSION_REJECTED"
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
    accepted: false,
    authorizationId: validated.binding.authorizationId,
    controlBindingSha256: validated.binding.controlBindingSha256,
    databaseNow: resolved.databaseNow,
    finalReleaseReady: false,
    mcpResultSha256: resolved.mcpResultSha256,
    providerApiCredentialPresent: false,
    providerBacked: false,
    runId: validated.binding.runId,
    sessionCloseSha256: resolved.sessionCloseSha256,
    state: resolved.state,
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: resolved.transitionOutcome
  });
  return validateIntegratedLiveDrillProviderReconciliationReceipt(
    Object.freeze({
      ...body,
      receiptSha256: providerDispatchSha256(canonicalJson(body))
    }),
    {
      authorizationId: validated.binding.authorizationId,
      runId: validated.binding.runId
    }
  );
}
