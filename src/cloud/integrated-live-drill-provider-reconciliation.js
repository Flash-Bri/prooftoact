import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256
} from "./integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  normalizeIntegratedLiveDrillProviderContext,
  readIntegratedLiveDrillExactPrivateJson,
  secureIntegratedLiveDrillPrivateRoot,
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "./integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT,
  readBoundIntegratedLiveDrillProviderOrchestrationAdmission,
  validateIntegratedLiveDrillProviderSupervisorCompletion
} from "./integrated-live-drill-provider-orchestration.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA,
  reconstructIntegratedLiveDrillProviderFinalizationCompletion
} from "./integrated-live-drill-provider-finalization.js";
import {
  readIntegratedLiveDrillDurableProviderDispatchResult,
  readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation,
  runIntegratedLiveDrillProviderRecovery
} from "./integrated-live-drill-provider-recovery.js";
import {
  buildProviderDispatchControlBinding,
  ProviderDispatchControl
} from "./provider-dispatch-control.js";
import {
  DeterministicRecoveryBroker,
  principalBindingHash,
  RecoveryAuditSink
} from "./recovery-broker.js";
import { recoveryAuditTargetIdentity } from
  "./recovery-continuity-identity.js";
import {
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "./integrated-live-drill-runtime.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_SCHEMA =
  "tideproof.highwater-drill-provider-reconciliation.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-reconciliation-input.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_OUTCOMES =
  Object.freeze([
    "ALREADY_TERMINAL_OR_CONSUMED",
    "AUTHORITY_NOT_CURRENT",
    "COMPLETED",
    "DISPATCH_GRANTED",
    "RESOLVED",
    "UNKNOWN_RECORDED"
  ]);

const HEX_64 = /^[0-9a-f]{64}$/u;
const MAX_INPUT_BYTES = 8 * 1024 * 1024;
const RECONCILIATION_PRINCIPAL =
  "principal://tideproof-demo-successor";
const SAFE_ENVIRONMENT_NAMES = Object.freeze([
  "__CF_USER_TEXT_ENCODING",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
  "PATH",
  "TMPDIR",
  "PRIMARY_AUDIT_DATABASE_URL",
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_PATH_ENVIRONMENT,
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT",
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
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
    PRIMARY_AUDIT_DATABASE_URL: requiredText(
      sourceEnvironment?.PRIMARY_AUDIT_DATABASE_URL,
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
      "providerAdmissionReceiptSha256",
      "schemaVersion"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA &&
      HEX_64.test(value.providerAdmissionReceiptSha256 ?? ""),
    code
  );
  const context = normalizeIntegratedLiveDrillProviderContext(value.context, {
    requireDispatchAuthorization: true
  });
  return Object.freeze({
    context,
    providerAdmissionReceiptSha256: value.providerAdmissionReceiptSha256,
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
      ["COMPLETED", "CONSUMED", "EXPIRED", "UNKNOWN_DO_NOT_ACT"]
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
  control,
  durable
}) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_UNKNOWN_DO_NOT_ACT";
  requireCondition(
    control &&
      typeof control === "object" &&
      typeof control.resolve === "function" &&
      typeof control.complete === "function" &&
      (durable === null ||
        exactRecord(durable, [
          "mcpResultSha256",
          "providerDispatchOwnerNonce",
          "sessionCloseSha256"
        ])),
    code
  );
  let resolved;
  try {
    resolved = await control.resolve(binding);
    if (durable !== null) {
      requireCondition(
        HEX_64.test(durable.mcpResultSha256 ?? "") &&
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu
            .test(durable.providerDispatchOwnerNonce ?? "") &&
          HEX_64.test(durable.sessionCloseSha256 ?? ""),
        code
      );
      if (resolved.state === "CONSUMED") {
        resolved = await control.complete(
          binding,
          {
            mcpResultSha256: durable.mcpResultSha256,
            sessionCloseSha256: durable.sessionCloseSha256
          },
          durable.providerDispatchOwnerNonce
        );
      }
      requireCondition(
        resolved.state === "COMPLETED" &&
          resolved.mcpResultSha256 === durable.mcpResultSha256 &&
          resolved.sessionCloseSha256 === durable.sessionCloseSha256,
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
  decisionRootDescriptor,
  environment,
  evidenceRootDescriptor,
  input
}) {
  const isolated = normalizedEnvironment(environment);
  const validated = validateIntegratedLiveDrillProviderReconciliationInput(input);
  requireCondition(
    Number.isSafeInteger(decisionRootDescriptor) &&
      Number.isSafeInteger(evidenceRootDescriptor),
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_ADMISSION_REJECTED"
  );
  const assertProviderAdmission = () =>
    readBoundIntegratedLiveDrillProviderOrchestrationAdmission({
      context: validated.context,
      decisionRootDescriptor,
      evidenceRootDescriptor,
      expectedReceiptSha256: validated.providerAdmissionReceiptSha256,
      forbiddenRootPath: validated.context.forbiddenRootPath
    });
  assertProviderAdmission();
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
  const control = new ProviderDispatchControl({
    connectionString: requiredText(
      isolated.PRIMARY_AUDIT_DATABASE_URL,
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
    control,
    durable
  });
  let providerCompletion = null;
  if (durable !== null) {
    const trusted = validated.context.trustedRunContext;
    const intent = validated.context.preCallIntent;
    const databaseUrl = requiredText(
      isolated.PRIMARY_AUDIT_DATABASE_URL,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_DATABASE_REJECTED",
      16_384
    );
    const currentAuditTargetIdentity = recoveryAuditTargetIdentity({
      connectionString: databaseUrl,
      primaryClusterId:
        trusted.recoveryBrokerConfiguration.expectedSourceClusterId
    });
    requireCondition(
      canonicalJson(currentAuditTargetIdentity) === canonicalJson(
        trusted.recoveryBrokerConfiguration.auditTargetIdentity
      ) &&
        principalBindingHash(RECONCILIATION_PRINCIPAL) ===
          intent.subjectBindingSha256,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_BINDING_REJECTED"
    );
    const denyProvider = () => reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_PROVIDER_ACTION_REJECTED"
    );
  const providerDeniedClient = Object.freeze({
      async close() {},
      semanticRequestEvidence() { denyProvider(); },
      selectQuery() { denyProvider(); },
      transportEvidence() { denyProvider(); }
    });
    const broker = new DeterministicRecoveryBroker({
      auditSink: new RecoveryAuditSink({
        connectionString: databaseUrl,
        clientFactory: auditClientFactory
      }),
      auditTargetIdentity: currentAuditTargetIdentity,
      buildIdentity: trusted.spec.sourceBuildIdentity,
      expectedSourceClusterId:
        trusted.recoveryBrokerConfiguration.expectedSourceClusterId,
      mcpClient: providerDeniedClient,
      providerDispatchControl: control,
      recoveryClusterId: intent.recoveryClusterId,
      sessionResolver: Object.freeze({
        async resolve({ authenticatedPrincipal }) {
          requireCondition(
            authenticatedPrincipal === RECONCILIATION_PRINCIPAL &&
              principalBindingHash(authenticatedPrincipal) ===
                intent.subjectBindingSha256,
            "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_BINDING_REJECTED"
          );
          return Object.freeze({
            recoverySessionId: intent.recoverySessionId,
            sourceDigest: intent.sourceDigest,
            subjectBindingHash: intent.subjectBindingSha256,
            tenantId: intent.tenantId
          });
        }
      }),
      trustedPublisherKeys:
        trusted.committedTrustRoot.trustedPublisherKeys
    });
    await runIntegratedLiveDrillProviderRecovery({
      authenticatedPrincipal: RECONCILIATION_PRINCIPAL,
      assertProviderAdmission,
      broker,
      context: validated.context
    });
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

export function readIntegratedLiveDrillProviderReconciliationInput(
  environment
) {
  const isolated = normalizedEnvironment(environment);
  const rootPath = requiredText(
    isolated.TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT,
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED"
  );
  const forbiddenRootPath = requiredText(
    isolated.TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT,
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED"
  );
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED"
  );
  const inputPath = path.resolve(requiredText(
    isolated[INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_PATH_ENVIRONMENT],
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED"
  ));
  requireCondition(
    path.dirname(inputPath) === secure.rootPath,
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED"
  );
  return validateIntegratedLiveDrillProviderReconciliationInput(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED",
      filePath: inputPath,
      maximumBytes: MAX_INPUT_BYTES,
      secure
    })
  );
}
