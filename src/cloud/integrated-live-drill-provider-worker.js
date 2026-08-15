import { createHash } from "node:crypto";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";
import {
  assertIntegratedLiveDrillPrivateRootCurrent,
  assertIntegratedLiveDrillPrivateRootMatchesBinding,
  normalizeIntegratedLiveDrillProviderContext,
  readIntegratedLiveDrillExactPrivateJson,
  secureIntegratedLiveDrillPrivateRoot
} from "./integrated-live-drill-provider-evidence.js";
import {
  integratedLiveDrillProviderAuthorityTimes,
  runIntegratedLiveDrillProviderRecovery
} from "./integrated-live-drill-provider-recovery.js";
import { readSystemdCredentialText } from "./systemd-credential.js";
import { BrokeredProviderOperationClient } from
  "./brokered-provider-operation-client.js";
import {
  DeterministicRecoveryBroker,
  principalBindingHash,
  RecoveryAuditSink
} from "./recovery-broker.js";
import {
  buildProviderDispatchControlBinding,
  PROVIDER_DISPATCH_HEX_64
} from "./provider-dispatch-binding.js";
import {
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "./integrated-live-drill-runtime.js";
import {
  recoveryAuditTargetIdentity
} from "./recovery-continuity-identity.js";
import {
  INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA,
  validateIntegratedLiveDrillExecutionGrant
} from "./integrated-live-drill-dispatch-broker.js";
import {
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "./integrated-live-drill-provider-evidence.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-worker-input.v3";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIALS_DIRECTORY =
  "CREDENTIALS_DIRECTORY";

const MAX_WORKER_INPUT_BYTES = 8 * 1024 * 1024;
const SAFE_PROCESS_ENVIRONMENT_NAMES = Object.freeze([
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
  "PATH",
  "TMPDIR"
]);
const WORKER_ENVIRONMENT_NAMES = new Set([
  ...SAFE_PROCESS_ENVIRONMENT_NAMES,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIALS_DIRECTORY,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    Reflect.ownKeys(value).every((key) =>
      typeof key === "string" && keys.includes(key)
    ) && keys.every((key) => Object.hasOwn(value, key));
}

function requiredText(value, code, maximum = 8192) {
  requireCondition(
    typeof value === "string" && value.length > 0 && value.length <= maximum &&
      !/[\0\r\n]/u.test(value),
    code
  );
  return value;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function normalizedWorkerEnvironment(environment) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED";
  const real = environment === process.env;
  requireCondition(
    environment && typeof environment === "object" && !Array.isArray(environment) &&
      (real || [Object.prototype, null].includes(Object.getPrototypeOf(environment))),
    code
  );
  const keys = Reflect.ownKeys(environment);
  requireCondition(
    keys.every((key) => {
      const descriptor = typeof key === "string"
        ? Object.getOwnPropertyDescriptor(environment, key)
        : null;
      return typeof key === "string" && WORKER_ENVIRONMENT_NAMES.has(key) &&
        descriptor && Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true && typeof descriptor.value === "string";
    }) &&
      !Object.hasOwn(environment, "MCP_API_KEY") &&
      !Object.hasOwn(environment, "PRIMARY_AUDIT_DATABASE_URL") &&
      !Object.hasOwn(environment, "PRIMARY_PROVIDER_FINALIZE_DATABASE_URL"),
    code
  );
  return Object.freeze(Object.fromEntries(keys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(environment, key).value
  ])));
}

function normalizeExecutionGrant(value) {
  const grant = validateIntegratedLiveDrillExecutionGrant(value);
  requireCondition(
    grant.schemaVersion === INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_EXECUTION_GRANT_REJECTED"
  );
  return grant;
}

export function validateIntegratedLiveDrillProviderWorkerInput(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED";
  requireCondition(
    exactKeys(value, [
      "authenticatedPrincipal",
      "context",
      "executionGrant",
      "schemaVersion"
    ]),
    code
  );
  const descriptors = Object.fromEntries(Reflect.ownKeys(value).map((key) => [
    key,
    Object.getOwnPropertyDescriptor(value, key)
  ]));
  requireCondition(
    Object.values(descriptors).every((descriptor) =>
      descriptor && Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true
    ) && descriptors.schemaVersion.value ===
      INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_SCHEMA,
    code
  );
  const authenticatedPrincipal = requiredText(
    descriptors.authenticatedPrincipal.value,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED",
    512
  );
  const context = normalizeIntegratedLiveDrillProviderContext(
    descriptors.context.value
  );
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    context.preCallIntent,
    {
      authorization: context.authorization,
      controlLedgerReceipt: context.controlLedgerReceipt
    }
  );
  const executionGrant = normalizeExecutionGrant(
    descriptors.executionGrant.value
  );
  requireCondition(
    principalBindingHash(authenticatedPrincipal) === intent.subjectBindingSha256 &&
      executionGrant.authorizationId === intent.authorizationId,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_PRINCIPAL_REJECTED"
  );
  return Object.freeze({
    authenticatedPrincipal,
    context,
    executionGrant,
    schemaVersion: descriptors.schemaVersion.value
  });
}

export function readIntegratedLiveDrillProviderWorkerInput({
  forbiddenRootPath,
  inputPath,
  rootPath
}) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_REJECTED";
  const secure = secureIntegratedLiveDrillPrivateRoot(rootPath, forbiddenRootPath, code);
  const input = validateIntegratedLiveDrillProviderWorkerInput(
    readIntegratedLiveDrillExactPrivateJson({
      code,
      filePath: inputPath,
      maximumBytes: MAX_WORKER_INPUT_BYTES,
      secure
    })
  );
  requireCondition(
    input.context.recoveryEvidenceRootPath === secure.rootPath &&
      input.context.forbiddenRootPath === secure.forbiddenRootPath,
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

export function integratedLiveDrillProviderWorkerEnvironment(sourceEnvironment, {
  credentialsDirectory,
  forbiddenRootPath,
  rootPath
}) {
  void forbiddenRootPath;
  const value = Object.freeze({
    ...Object.fromEntries(SAFE_PROCESS_ENVIRONMENT_NAMES
      .filter((name) => typeof sourceEnvironment?.[name] === "string")
      .map((name) => [name, sourceEnvironment[name]])),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIALS_DIRECTORY]:
      requiredText(credentialsDirectory, "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_REJECTED"),
    [INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT]: rootPath
  });
  return assertIntegratedLiveDrillProviderWorkerEnvironment(value, {
    forbiddenRootPath,
    rootPath
  });
}

export function assertIntegratedLiveDrillProviderWorkerEnvironment(
  environment,
  { forbiddenRootPath, rootPath }
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ENVIRONMENT_REJECTED";
  const value = normalizedWorkerEnvironment(environment);
  const credentialsDirectory = value[
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIALS_DIRECTORY
  ];
  requireCondition(
    value[INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_ROOT_ENVIRONMENT] === rootPath &&
      !Object.hasOwn(
        value,
        INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_FORBIDDEN_ROOT_ENVIRONMENT
      ) &&
      [credentialsDirectory].every((candidate) =>
        typeof candidate === "string" && path.isAbsolute(candidate) &&
        path.resolve(candidate) === candidate
      ),
    code
  );
  return value;
}

function readExecutorCredentials(environment, input) {
  const credentialsDirectory = environment[
    INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIALS_DIRECTORY
  ];
  const operationNonce = readSystemdCredentialText({
    credentialsDirectory,
    maximumBytes: 65,
    name: "operation-nonce"
  });
  requireCondition(
    PROVIDER_DISPATCH_HEX_64.test(operationNonce) &&
      sha256(operationNonce) === input.executionGrant.operationNonceSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_EXECUTION_GRANT_REJECTED"
  );
  return Object.freeze({
    operationNonce,
    providerOperationSocket: readSystemdCredentialText({
      credentialsDirectory,
      maximumBytes: 4097,
      name: "provider-operation-socket"
    }),
    recoveryAuditDatabaseUrl: readSystemdCredentialText({
      credentialsDirectory,
      name: "recovery-audit-database-url"
    })
  });
}

async function runIntegratedLiveDrillProviderWorkerInternal({
  environment,
  input
}, { auditClientFactory, fetchImpl }) {
  const validated = validateIntegratedLiveDrillProviderWorkerInput(input);
  const isolated = assertIntegratedLiveDrillProviderWorkerEnvironment(
    environment,
    {
      forbiddenRootPath: validated.context.forbiddenRootPath,
      rootPath: validated.context.recoveryEvidenceRootPath
    }
  );
  const assertProviderAdmission = () => validated.executionGrant;
  const context = validated.context;
  const intent = context.preCallIntent;
  const dispatch = validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    context.providerDispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        context.preCallInputs.consumedChildAuthorization.attestation.payload.issuedAt,
      humanAuthorizationTrustRoot: context.trustedRunContext.humanAuthorizationTrustRoot,
      intent,
      requireCurrent: false
    }
  );
  const authorityTimes = integratedLiveDrillProviderAuthorityTimes(
    context,
    intent,
    dispatch,
    Date.parse(
      context.preCallInputs.consumedChildAuthorization.attestation.payload.issuedAt
    )
  );
  const binding = buildProviderDispatchControlBinding({
    context,
    dispatchAuthorizationSha256: dispatch.attestationSha256,
    earliestControllingExpiry: authorityTimes.earliestControllingExpiry,
    latestControllingIssuedAt: authorityTimes.latestControllingIssuedAt
  });
  requireCondition(
    binding.controlBindingSha256 === validated.executionGrant.controlBindingSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_EXECUTION_GRANT_REJECTED"
  );

  // No provider client or raw provider credential exists in JavaScript before
  // the exact database EXECUTING grant and local admission have been rebound.
  const credentials = readExecutorCredentials(isolated, validated);
  const currentAuditTargetIdentity = recoveryAuditTargetIdentity({
    connectionString: credentials.recoveryAuditDatabaseUrl,
    primaryClusterId:
      context.trustedRunContext.recoveryBrokerConfiguration.expectedSourceClusterId
  });
  requireCondition(
    canonicalJson(currentAuditTargetIdentity) === canonicalJson(
      context.trustedRunContext.recoveryBrokerConfiguration.auditTargetIdentity
    ),
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_AUDIT_TARGET_REJECTED"
  );
  requireCondition(
    fetchImpl === null,
    "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_NETWORK_REJECTED"
  );
  const client = new BrokeredProviderOperationClient({
    binding,
    clusterId: intent.recoveryClusterId,
    executionGrant: validated.executionGrant,
    operationNonce: credentials.operationNonce,
    socketPath: credentials.providerOperationSocket
  });
  const broker = new DeterministicRecoveryBroker({
    auditSink: new RecoveryAuditSink({
      connectionString: credentials.recoveryAuditDatabaseUrl,
      clientFactory: auditClientFactory
    }),
    auditTargetIdentity: currentAuditTargetIdentity,
    buildIdentity: context.trustedRunContext.spec.sourceBuildIdentity,
    expectedSourceClusterId:
      context.trustedRunContext.recoveryBrokerConfiguration.expectedSourceClusterId,
    mcpClient: client,
    providerDispatchFinalizer: client,
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
    trustedPublisherKeys: context.trustedRunContext.committedTrustRoot.trustedPublisherKeys
  });
  try {
    const result = await runIntegratedLiveDrillProviderRecovery({
      authenticatedPrincipal: validated.authenticatedPrincipal,
      assertProviderAdmission,
      broker,
      context,
      executionGrant: Object.freeze({
        executionCapabilitySha256:
          validated.executionGrant.executionCapabilitySha256,
        grantId: validated.executionGrant.grantId,
        operationNonceSha256: validated.executionGrant.operationNonceSha256,
        workerSpecSha256: validated.executionGrant.workerSpecSha256
      })
    });
    requireCondition(
      !JSON.stringify(result).includes(credentials.operationNonce),
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_CREDENTIAL_LEAK_REJECTED"
    );
    return result;
  } finally {
    await client.close();
  }
}

export function runIntegratedLiveDrillProviderWorker(args) {
  return runIntegratedLiveDrillProviderWorkerInternal(args, {
    auditClientFactory: null,
    fetchImpl: null
  });
}

export const __test = Object.freeze({
  runWithLocalTransports(args, { auditClientFactory, fetchImpl }) {
    requireCondition(
      typeof auditClientFactory === "function" && fetchImpl === null,
      "INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_TEST_TRANSPORT_REJECTED"
    );
    return runIntegratedLiveDrillProviderWorkerInternal(args, {
      auditClientFactory,
      fetchImpl
    });
  }
});
