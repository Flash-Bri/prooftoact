import { canonicalJson } from "./canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256
} from "./integrated-live-drill-authorization.js";
import {
  normalizeIntegratedLiveDrillProviderContext,
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "./integrated-live-drill-provider-evidence.js";
import {
  validateIntegratedLiveDrillProviderSupervisorCompletion
} from "./integrated-live-drill-provider-orchestration.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA,
  reconstructIntegratedLiveDrillProviderFinalizationCompletion
} from "./integrated-live-drill-provider-finalization.js";
import {
  readIntegratedLiveDrillDurableProviderDispatchResult,
  readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation
} from "./integrated-live-drill-provider-recovery.js";
import { buildProviderDispatchControlBinding } from
  "./provider-dispatch-binding.js";
import { ProviderDispatchResolver } from "./provider-dispatch-resolver.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA,
  validateIntegratedLiveDrillExecutionGrant
} from "./integrated-live-drill-dispatch-broker.js";
import {
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "./integrated-live-drill-runtime.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA =
  "tideproof.highwater-drill-provider-reconciliation.v2";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTCOMES =
  Object.freeze([
    "RESOLVED",
    "RESOLVED_ABSENT"
  ]);

const HEX_64 = /^[0-9a-f]{64}$/u;
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
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT,
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactRecord(value, keys) {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    Reflect.ownKeys(value).every((key) =>
      typeof key === "string" && keys.includes(key)
    ) &&
    keys.every((key) => Object.hasOwn(value, key));
}

function requiredText(value, code, maximum = 8192) {
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      !/[\0\r\n]/u.test(value),
    code
  );
  return value;
}

function normalizedEnvironment(environment) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ENVIRONMENT_REJECTED";
  const real = environment === process.env;
  requireCondition(
    environment &&
      typeof environment === "object" &&
      !Array.isArray(environment) &&
      (real || [Object.prototype, null].includes(Object.getPrototypeOf(environment))),
    code
  );
  const ownKeys = Reflect.ownKeys(environment);
  requireCondition(
    ownKeys.every((key) => {
      const descriptor = typeof key === "string"
        ? Object.getOwnPropertyDescriptor(environment, key)
        : null;
      return typeof key === "string" &&
        SAFE_ENVIRONMENT_NAMES.includes(key) &&
        descriptor !== null &&
        descriptor !== undefined &&
        Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true &&
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
  sourceEnvironment,
  additions
) {
  const environment = Object.freeze({
    ...Object.fromEntries(
      ["__CF_USER_TEXT_ENCODING", "LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "PATH", "TMPDIR"]
        .filter((name) => typeof sourceEnvironment?.[name] === "string")
        .map((name) => [name, sourceEnvironment[name]])
    ),
    PRIMARY_PROVIDER_RECONCILE_DATABASE_URL: requiredText(
      sourceEnvironment?.PRIMARY_PROVIDER_RECONCILE_DATABASE_URL,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ENVIRONMENT_REJECTED",
      16_384
    ),
    ...additions
  });
  return normalizedEnvironment(environment);
}

export function validateIntegratedLiveDrillProviderReconciliationInput(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED";
  requireCondition(
    exactRecord(value, [
      "context",
      "executionGrant",
      "schemaVersion"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA,
    code
  );
  const context = normalizeIntegratedLiveDrillProviderContext(value.context, {
    requireDispatchAuthorization: true
  });
  return Object.freeze({
    context,
    executionGrant: validateIntegratedLiveDrillExecutionGrant(
      value.executionGrant
    ),
    schemaVersion: value.schemaVersion
  });
}

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
      "providerCompletion",
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
  requireCondition(
    value.schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA &&
      value.status === "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED" &&
      value.accepted === false &&
      value.finalReleaseReady === false &&
      value.providerBacked === false &&
      value.providerApiCredentialPresent === false &&
      value.authorizationId === authorizationId &&
      value.runId === runId &&
      HEX_64.test(value.controlBindingSha256 ?? "") &&
      HEX_64.test(receiptSha256 ?? "") &&
      ["ABSENT", "COMPLETED", "EXECUTING", "EXPIRED", "GRANTED",
        "UNKNOWN_DO_NOT_ACT"]
        .includes(value.state) &&
      INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTCOMES.includes(
        value.transitionOutcome
      ) &&
      (value.mcpResultSha256 === null ||
        HEX_64.test(value.mcpResultSha256 ?? "")) &&
      (value.providerCompletion === null ||
        canonicalJson(
          validateIntegratedLiveDrillProviderSupervisorCompletion(
            value.providerCompletion
          )
        ) === canonicalJson(value.providerCompletion)) &&
      (value.sessionCloseSha256 === null ||
        HEX_64.test(value.sessionCloseSha256 ?? "")) &&
      Number.isFinite(Date.parse(value.databaseNow ?? "")) &&
      new Date(value.databaseNow).toISOString() === value.databaseNow &&
      integratedLiveDrillCanonicalSha256(body) === receiptSha256,
    code
  );
  return Object.freeze({ ...value });
}

export async function reconcileIntegratedLiveDrillProviderDispatchControl({
  binding,
  resolver,
  durable
}) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_UNKNOWN_DO_NOT_ACT";
  requireCondition(
    resolver &&
      typeof resolver === "object" &&
      typeof resolver.resolve === "function" &&
      (durable === null ||
        exactRecord(durable, [
          "mcpResultSha256",
          "sessionCloseSha256"
        ])),
    code
  );
  let resolved;
  try {
    resolved = await resolver.resolve(binding);
    if (durable !== null) {
      requireCondition(
        HEX_64.test(durable.mcpResultSha256 ?? "") &&
          HEX_64.test(durable.sessionCloseSha256 ?? "") &&
          (resolved.state !== "COMPLETED" ||
          resolved.mcpResultSha256 === durable.mcpResultSha256 &&
            resolved.sessionCloseSha256 === durable.sessionCloseSha256),
        code
      );
    }
    return resolved;
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
  const validated = validateIntegratedLiveDrillProviderReconciliationInput(input);
  const preparation =
    readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation(
      validated.context
    );
  const dispatch = validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    validated.context.providerDispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        validated.context.preCallInputs.consumedChildAuthorization.attestation
          .payload.issuedAt,
      humanAuthorizationTrustRoot:
        validated.context.trustedRunContext.humanAuthorizationTrustRoot,
      intent: validated.context.preCallIntent,
      requireCurrent: false
    }
  );
  requireCondition(
    canonicalJson(dispatch.payload) === canonicalJson(preparation.signingPayload),
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_BINDING_REJECTED"
  );
  const issued = [
    Date.parse(validated.context.providerDispatchAuthorization.payload.issuedAt),
    Date.parse(validated.context.preCallIntent.startedAt),
    Date.parse(
      validated.context.preCallInputs.consumedChildAuthorization.attestation
        .payload.issuedAt
    ),
    validated.context.authorization.issuedAt
  ];
  const expiries = [
    Date.parse(validated.context.providerDispatchAuthorization.payload.expiresAt),
    Date.parse(validated.context.preCallIntent.expiresAt),
    Date.parse(validated.context.preCallIntent.childAuthorizationExpiresAt),
    validated.context.authorization.expiresAt
  ];
  requireCondition(
    [...issued, ...expiries].every(Number.isSafeInteger),
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_BINDING_REJECTED"
  );
  const binding = buildProviderDispatchControlBinding({
    context: validated.context,
    dispatchAuthorizationSha256: dispatch.attestationSha256,
    earliestControllingExpiry: Math.min(...expiries),
    latestControllingIssuedAt: Math.max(...issued)
  });
  requireCondition(
    validated.executionGrant.authorizationId === binding.authorizationId &&
      validated.executionGrant.controlBindingSha256 ===
        binding.controlBindingSha256 &&
      validated.executionGrant.state === "EXECUTING",
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ADMISSION_REJECTED"
  );
  const resolver = new ProviderDispatchResolver({
    connectionString: requiredText(
      isolated.PRIMARY_PROVIDER_RECONCILE_DATABASE_URL,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_DATABASE_REJECTED",
      16_384
    ),
    clientFactory: auditClientFactory
  });
  const durable = readIntegratedLiveDrillDurableProviderDispatchResult(
    validated.context
  );
  const resolved = await reconcileIntegratedLiveDrillProviderDispatchControl({
    binding,
    resolver,
    durable
  });
  let providerCompletion = null;
  if (durable !== null && resolved.state === "COMPLETED") {
    providerCompletion =
      reconstructIntegratedLiveDrillProviderFinalizationCompletion({
        context: validated.context,
        schemaVersion:
          INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA
      });
  }
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA,
    accepted: false,
    authorizationId: binding.authorizationId,
    controlBindingSha256: binding.controlBindingSha256,
    databaseNow: resolved.databaseNow,
    finalReleaseReady: false,
    mcpResultSha256: resolved.mcpResultSha256,
    providerCompletion,
    providerApiCredentialPresent: false,
    providerBacked: false,
    runId: binding.runId,
    sessionCloseSha256: resolved.sessionCloseSha256,
    state: resolved.state,
    status: "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED",
    transitionOutcome: resolved.transitionOutcome
  });
  return validateIntegratedLiveDrillProviderReconciliationReceipt(
    Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
    }),
    { authorizationId: binding.authorizationId, runId: binding.runId }
  );
}
