import path from "node:path";

import { canonicalJson } from "./canonical-json.js";

import {
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";
import {
  assertIntegratedLiveDrillPrivateRootCurrent,
  assertIntegratedLiveDrillPrivateRootMatchesBinding,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  normalizeIntegratedLiveDrillProviderContext,
  readIntegratedLiveDrillExactPrivateJson,
  secureIntegratedLiveDrillPrivateRoot
} from "./integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT,
  readBoundIntegratedLiveDrillProviderOrchestrationAdmission
} from "./integrated-live-drill-provider-orchestration.js";
import { runIntegratedLiveDrillProviderRecovery } from
  "./integrated-live-drill-provider-recovery.js";
import { CockroachManagedMcpRecoveryClient } from
  "./managed-mcp-client.js";
import {
  DeterministicRecoveryBroker,
  principalBindingHash,
  RecoveryAuditSink
} from "./recovery-broker.js";
import { ProviderDispatchControl } from "./provider-dispatch-control.js";
import {
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "./integrated-live-drill-runtime.js";
import {
  recoveryAuditTargetIdentity
} from "./recovery-continuity-identity.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-worker-input.v2";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_BINDING_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING";

const MAX_WORKER_INPUT_BYTES = 8 * 1024 * 1024;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SAFE_PROCESS_ENVIRONMENT_NAMES = Object.freeze([
  "__CF_USER_TEXT_ENCODING",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
  "PATH",
  "TMPDIR"
]);
const WORKER_ENVIRONMENT_NAMES = Object.freeze([
  ...SAFE_PROCESS_ENVIRONMENT_NAMES,
  "MCP_API_KEY",
  "PRIMARY_AUDIT_DATABASE_URL",
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_BINDING_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
]);
const WORKER_ENVIRONMENT_NAME_SET = new Set(WORKER_ENVIRONMENT_NAMES);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    return false;
  }
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length &&
    ownKeys.every((key) => typeof key === "string") &&
    keys.every((key) => Object.hasOwn(value, key)) &&
    ownKeys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined &&
        Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true;
    });
}

function normalizeWorkerEnvironment(environment, code) {
  const realProcessEnvironment = environment === process.env;
  requireCondition(
    environment &&
      typeof environment === "object" &&
      !Array.isArray(environment) &&
      (
        realProcessEnvironment ||
        [Object.prototype, null].includes(Object.getPrototypeOf(environment))
      ),
    code
  );
  const ownKeys = Reflect.ownKeys(environment);
  requireCondition(
    ownKeys.every((key) => {
      if (
        typeof key !== "string"
      ) {
        return false;
      }
      const descriptor = Object.getOwnPropertyDescriptor(environment, key);
      return descriptor !== undefined &&
        Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true &&
        typeof descriptor.value === "string" &&
        WORKER_ENVIRONMENT_NAME_SET.has(key);
    }),
    code
  );
  return Object.freeze(Object.fromEntries(
    ownKeys
      .filter((key) => WORKER_ENVIRONMENT_NAME_SET.has(key))
      .map((key) => [
        key,
        Object.getOwnPropertyDescriptor(environment, key).value
      ])
  ));
}

function requiredText(value, code, maximum = 4096) {
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      !/[\0\r\n]/u.test(value),
    code
  );
  return value;
}

export function validateIntegratedLiveDrillProviderWorkerInput(value) {
  requireCondition(
    exactKeys(value, [
      "authenticatedPrincipal",
      "context",
      "providerAdmissionReceiptSha256",
      "schemaVersion"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED"
  );
  const authenticatedPrincipal = requiredText(
    value.authenticatedPrincipal,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED",
    512
  );
  let context;
  try {
    context = normalizeIntegratedLiveDrillProviderContext(value.context);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED", cause);
  }
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    context.preCallIntent,
    {
      authorization: context.authorization,
      controlLedgerReceipt: context.controlLedgerReceipt
    }
  );
  requireCondition(
    principalBindingHash(authenticatedPrincipal) ===
        intent.subjectBindingSha256 &&
      HEX_64.test(value.providerAdmissionReceiptSha256 ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
  );
  return Object.freeze({
    authenticatedPrincipal,
    context,
    providerAdmissionReceiptSha256: value.providerAdmissionReceiptSha256,
    schemaVersion: value.schemaVersion
  });
}

export function readIntegratedLiveDrillProviderWorkerInput({
  forbiddenRootPath,
  inputPath,
  rootPath
}) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED";
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    code
  );
  const input = validateIntegratedLiveDrillProviderWorkerInput(
    readIntegratedLiveDrillExactPrivateJson({
      code,
      filePath: inputPath,
      maximumBytes: MAX_WORKER_INPUT_BYTES,
      secure
    })
  );
  requireCondition(
    input.context?.recoveryEvidenceRootPath === secure.rootPath &&
      input.context?.forbiddenRootPath === secure.forbiddenRootPath,
    code
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    input.context.evidenceRootBinding,
    code
  );
  assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
  return input;
}

export function integratedLiveDrillProviderWorkerEnvironment(
  sourceEnvironment,
  {
    authenticatedPrincipal,
    forbiddenRootPath,
    inputPath,
    rootBinding,
    rootPath
  }
) {
  const apiKey = requiredText(
    sourceEnvironment?.MCP_API_KEY,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED",
    8192
  );
  requireCondition(
    apiKey.length >= 24,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED"
  );
  const auditDatabaseUrl = requiredText(
    sourceEnvironment?.PRIMARY_AUDIT_DATABASE_URL,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_DATABASE_REJECTED",
    8192
  );
  const value = {
    ...Object.fromEntries(
      Object.entries(sourceEnvironment ?? {}).filter(([name]) =>
        SAFE_PROCESS_ENVIRONMENT_NAMES.includes(name)
      )
    ),
    MCP_API_KEY: apiKey,
    PRIMARY_AUDIT_DATABASE_URL: auditDatabaseUrl,
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT]:
      requiredText(
        inputPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT]:
      requiredText(
        authenticatedPrincipal,
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED",
        512
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT]:
      requiredText(
        rootPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT]:
      requiredText(
        forbiddenRootPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_BINDING_ENVIRONMENT]:
      canonicalJson(rootBinding),
    [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "3",
    [INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT]: "4"
  };
  return assertIntegratedLiveDrillProviderWorkerEnvironment(value, {
    authenticatedPrincipal,
    forbiddenRootPath,
    rootBinding,
    rootPath
  });
}

export function assertIntegratedLiveDrillProviderWorkerEnvironment(
  environment,
  { authenticatedPrincipal, forbiddenRootPath, rootBinding, rootPath }
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED";
  const normalized = normalizeWorkerEnvironment(environment, code);
  const inputPath = normalized[
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT
  ];
  requireCondition(
    normalized[
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_ENVIRONMENT
      ] === authenticatedPrincipal &&
      normalized[
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT
      ] === rootPath &&
      normalized[
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT
      ] === forbiddenRootPath &&
      typeof inputPath === "string" &&
      path.isAbsolute(inputPath) &&
      path.resolve(inputPath) === inputPath &&
      path.dirname(inputPath) === rootPath &&
      normalized[
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_BINDING_ENVIRONMENT
      ] === canonicalJson(rootBinding) &&
      normalized[INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT] ===
        "3" &&
      normalized[
        INTEGRATED_LIVE_DRILL_PROVIDER_DECISION_ROOT_DESCRIPTOR_ENVIRONMENT
      ] === "4",
    code
  );
  requiredText(
    normalized.MCP_API_KEY,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED",
    8192
  );
  requireCondition(
    normalized.MCP_API_KEY.length >= 24,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED"
  );
  requiredText(
    normalized.PRIMARY_AUDIT_DATABASE_URL,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_DATABASE_REJECTED",
    8192
  );
  requiredText(inputPath, code, 8192);
  requiredText(rootPath, code, 8192);
  requiredText(forbiddenRootPath, code, 8192);
  requiredText(authenticatedPrincipal, code, 512);
  return normalized;
}

async function runIntegratedLiveDrillProviderWorkerInternal({
  decisionRootDescriptor,
  evidenceRootDescriptor,
  input,
  environment
}, {
  fetchImpl,
  auditClientFactory
}) {
  const validated = validateIntegratedLiveDrillProviderWorkerInput(input);
  const isolatedEnvironment =
    assertIntegratedLiveDrillProviderWorkerEnvironment(environment, {
      authenticatedPrincipal: validated.authenticatedPrincipal,
      forbiddenRootPath: validated.context.forbiddenRootPath,
      rootBinding: validated.context.evidenceRootBinding,
      rootPath: validated.context.recoveryEvidenceRootPath
    });
  const intent = validated.context.preCallIntent;
  requireCondition(
    Number.isSafeInteger(decisionRootDescriptor) &&
      decisionRootDescriptor >= 0 &&
      Number.isSafeInteger(evidenceRootDescriptor) &&
      evidenceRootDescriptor >= 0,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ADMISSION_REJECTED"
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
  const apiKey = requiredText(
    isolatedEnvironment.MCP_API_KEY,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED",
    8192
  );
  requireCondition(
    apiKey.length >= 24 && typeof fetchImpl === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED"
  );
  const auditDatabaseUrl = requiredText(
    isolatedEnvironment.PRIMARY_AUDIT_DATABASE_URL,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_DATABASE_REJECTED",
    8192
  );
  const trustedRunContext = validated.context.trustedRunContext;
  const currentAuditTargetIdentity = recoveryAuditTargetIdentity({
    connectionString: auditDatabaseUrl,
    primaryClusterId:
      trustedRunContext.recoveryBrokerConfiguration.expectedSourceClusterId
  });
  requireCondition(
    canonicalJson(currentAuditTargetIdentity) === canonicalJson(
      trustedRunContext.recoveryBrokerConfiguration.auditTargetIdentity
    ),
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_TARGET_REJECTED"
  );
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey,
    clusterId: intent.recoveryClusterId,
    fetchImpl
  });
  const broker = new DeterministicRecoveryBroker({
    auditSink: new RecoveryAuditSink({
      connectionString: auditDatabaseUrl,
      clientFactory: auditClientFactory
    }),
    auditTargetIdentity: currentAuditTargetIdentity,
    buildIdentity: trustedRunContext.spec.sourceBuildIdentity,
    expectedSourceClusterId:
      trustedRunContext.recoveryBrokerConfiguration.expectedSourceClusterId,
    mcpClient: client,
    providerDispatchControl: new ProviderDispatchControl({
      connectionString: auditDatabaseUrl,
      clientFactory: auditClientFactory
    }),
    recoveryClusterId: intent.recoveryClusterId,
    sessionResolver: Object.freeze({
      async resolve({ authenticatedPrincipal }) {
        requireCondition(
          authenticatedPrincipal === validated.authenticatedPrincipal &&
            principalBindingHash(authenticatedPrincipal) ===
              intent.subjectBindingSha256,
          "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
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
      trustedRunContext.committedTrustRoot.trustedPublisherKeys
  });
  try {
    const result = await runIntegratedLiveDrillProviderRecovery({
      authenticatedPrincipal: validated.authenticatedPrincipal,
      assertProviderAdmission,
      broker,
      context: validated.context
    });
    requireCondition(
      !JSON.stringify(result).includes(apiKey),
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_LEAK_REJECTED"
    );
    return result;
  } finally {
    await client.close();
  }
}

export async function runIntegratedLiveDrillProviderWorker(args) {
  return runIntegratedLiveDrillProviderWorkerInternal(args, {
    auditClientFactory: null,
    fetchImpl: globalThis.fetch
  });
}

export const __test = Object.freeze({
  runWithLocalTransports(args, { auditClientFactory, fetchImpl }) {
    requireCondition(
      typeof auditClientFactory === "function" &&
        typeof fetchImpl === "function",
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_TEST_TRANSPORT_REJECTED"
    );
    return runIntegratedLiveDrillProviderWorkerInternal(args, {
      auditClientFactory,
      fetchImpl
    });
  }
});
