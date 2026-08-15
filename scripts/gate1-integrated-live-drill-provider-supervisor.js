import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  authorizeOrVerifyIntegratedLiveDrillChildLaunch,
  integratedLiveDrillChildCommittedTrustRoot,
  assertIntegratedLiveDrillChildAuthorizationCurrent
} from "../src/cloud/integrated-live-drill-child-authorization.js";
import {
  acquireIntegratedLiveDrillPrivateRootLease,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  normalizeIntegratedLiveDrillProviderContext
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES,
  INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA,
  normalizeIntegratedLiveDrillProviderOrchestrationBoundary,
  persistIntegratedLiveDrillExactPrivateJson,
  validateIntegratedLiveDrillProviderSupervisorPreparation
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";
import {
  prepareIntegratedLiveDrillProviderRecoveryAuthorization,
  readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import {
  integratedLiveDrillRecoveryContinuityPreCallIntent
} from "../src/cloud/integrated-live-drill-recovery-continuity.js";
import {
  assertIntegratedLiveDrillRuntime
} from "../src/cloud/integrated-live-drill-runtime.js";
import {
  normalizedRecoverySourceReceiptForContinuity,
  recoveryAuditTargetIdentity
} from "../src/cloud/recovery-continuity-identity.js";
import {
  parseIntegratedLiveDrillSpec,
  persistOrReuseIntegratedLiveDrillRecoveryBundle
} from "../src/cloud/integrated-live-drill.js";
import {
  assertRecoveryPublisherTrustRootWriteDenied,
  assertRecoveryRunnerBaseTableReadsDenied,
  assertSeparatedDatabaseEndpoints,
  canonicalRecoveryAttempt,
  principalBindingHash,
  recoveryBrokerConfigDigest,
  resolveCommittedRecoveryPublisherTrustRoot,
  resolveCommittedRecoverySourceReceipt,
  trustedPublisherKeysDigest
} from "../src/cloud/recovery-broker.js";
import { RecoveryPublisher } from "../src/cloud/recovery-security.js";
import {
  recoverySourceBindingDigestFor
} from "../src/cloud/recovery-store.js";
import {
  loadCommittedRecoveryPublisherSigner,
  loadCommittedRecoveryPublisherTrustRoot
} from "./lib/recovery-publisher-key.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE";
export const INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION";
export const INTEGRATED_LIVE_DRILL_PROVIDER_WORKER_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_WORKER_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_FINALIZATION_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING";
export const
INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_CONTEXT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_CONTEXT_SHA256";
export const
INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_RECEIPT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_PREPARATION_RECEIPT_SHA256";
export const
INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_SIGNING_PAYLOAD_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_EXPECTED_SIGNING_PAYLOAD_SHA256";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ADMISSION_RECEIPT_SHA256_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ADMISSION_RECEIPT_SHA256";

const SYNTHETIC_PRINCIPAL = "principal://tideproof-demo-successor";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function boundaryRecord(value, allowedKeys, code, { exact = false } = {}) {
  requireCondition(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    code
  );
  const ownKeys = Reflect.ownKeys(value);
  requireCondition(
    ownKeys.every((key) => {
      const descriptor = typeof key === "string"
        ? Object.getOwnPropertyDescriptor(value, key)
        : null;
      return typeof key === "string" &&
        allowedKeys.includes(key) &&
        descriptor !== null &&
        descriptor !== undefined &&
        Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true;
    }) &&
      (!exact || ownKeys.length === allowedKeys.length) &&
      (!exact || allowedKeys.every((key) => Object.hasOwn(value, key))),
    code
  );
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(value, key).value
  ])));
}

function normalizedSupervisorEnvironment(environment) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_ENVIRONMENT_REJECTED";
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
      const descriptor = typeof key === "string"
        ? Object.getOwnPropertyDescriptor(environment, key)
        : null;
      return typeof key === "string" &&
        descriptor !== null &&
        descriptor !== undefined &&
        Object.hasOwn(descriptor, "value") &&
        descriptor.enumerable === true &&
        typeof descriptor.value === "string";
    }),
    code
  );
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(environment, key).value
  ])));
}

function normalizedDependencies(value) {
  const keys = [
    "assertRecoveryPublisherTrustRootWriteDenied",
    "assertRecoveryRunnerBaseTableReadsDenied",
    "assertSeparatedDatabaseEndpoints",
    "authorizeOrVerifyIntegratedLiveDrillChildLaunch",
    "createPublisher",
    "loadSigner",
    "randomUuid",
    "resolveCommittedRecoveryPublisherTrustRoot",
    "resolveCommittedRecoverySourceReceipt"
  ];
  const normalized = boundaryRecord(
    value,
    keys,
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_DEPENDENCIES_REJECTED",
    { exact: true }
  );
  requireCondition(
    keys.every((key) => typeof normalized[key] === "function"),
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_DEPENDENCIES_REJECTED"
  );
  return normalized;
}

function requiredEnvironment(environment, name, maximum = 8192) {
  const value = environment?.[name];
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= maximum &&
      !/[\0\r\n]/u.test(value),
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_ENVIRONMENT_REJECTED"
  );
  return value;
}

function parseEnvironmentJson(environment, name, maximum) {
  try {
    return JSON.parse(requiredEnvironment(environment, name, maximum));
  } catch (cause) {
    reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_ENVIRONMENT_REJECTED",
      cause
    );
  }
}

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

function exactSourceBinding(environment) {
  return Object.freeze({
    tenantId: requiredEnvironment(environment, "RECOVERY_SOURCE_TENANT_ID", 64),
    runId: requiredEnvironment(environment, "RECOVERY_SOURCE_RUN_ID", 64),
    incidentId: requiredEnvironment(environment, "RECOVERY_SOURCE_INCIDENT_ID", 64),
    evidenceId: requiredEnvironment(environment, "RECOVERY_SOURCE_EVIDENCE_ID", 64),
    resourceId: requiredEnvironment(environment, "RECOVERY_SOURCE_RESOURCE_ID", 160),
    operationId: requiredEnvironment(environment, "RECOVERY_SOURCE_OPERATION_ID", 64),
    requestDigest: requiredEnvironment(environment, "RECOVERY_SOURCE_REQUEST_DIGEST", 64),
    authorityEvidenceBindingSha256: requiredEnvironment(
      environment,
      "RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256",
      64
    ),
    selectedEvidenceBindingSha256: requiredEnvironment(
      environment,
      "RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256",
      64
    )
  });
}

function defaultDependencies(environment) {
  return Object.freeze({
    assertRecoveryPublisherTrustRootWriteDenied,
    assertRecoveryRunnerBaseTableReadsDenied,
    assertSeparatedDatabaseEndpoints,
    authorizeOrVerifyIntegratedLiveDrillChildLaunch,
    createPublisher: (connectionString) => new RecoveryPublisher({
      connectionString
    }),
    loadSigner: () => loadCommittedRecoveryPublisherSigner(environment),
    randomUuid: randomUUID,
    resolveCommittedRecoveryPublisherTrustRoot,
    resolveCommittedRecoverySourceReceipt
  });
}

function supervisorPreparationBody({ context, preparation }) {
  const intent = context.preCallIntent;
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId: intent.authorizationId,
    authorizationAttestationSha256: intent.authorizationAttestationSha256,
    finalReleaseReady: false,
    logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
    preCallIntentSha256: intent.intentSha256,
    preparationContextSha256:
      integratedLiveDrillCanonicalSha256(context),
    preparationReceiptSha256: preparation.preparationReceiptSha256,
    providerBacked: false,
    recoveryBrokerConfigDigest: intent.recoveryBrokerConfigDigest,
    runId: intent.runId,
    signingPayload: preparation.signingPayload,
    signingPayloadSha256: preparation.signingPayloadSha256,
    stateHistory: Object.freeze([
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
        .RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION
    ]),
    status: preparation.status
  });
}

export function persistIntegratedLiveDrillProviderSupervisorPreparation(args) {
  const normalizedArgs =
    normalizeIntegratedLiveDrillProviderOrchestrationBoundary(args);
  requireCondition(
    [5, 6].includes(Reflect.ownKeys(normalizedArgs).length) &&
      [
        "context",
        "contextPath",
        "forbiddenRootPath",
        "issuedAt",
        "rootPath"
      ].every((key) => Object.hasOwn(normalizedArgs, key)) &&
      Reflect.ownKeys(normalizedArgs).every((key) => [
        "context",
        "contextPath",
        "expiresAt",
        "forbiddenRootPath",
        "issuedAt",
        "rootPath"
      ].includes(key)),
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_REJECTED"
  );
  const {
    context,
    contextPath,
    forbiddenRootPath,
    issuedAt,
    expiresAt,
    rootPath
  } = normalizedArgs;
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context,
    { requireDispatchAuthorization: false }
  );
  const preparation = prepareIntegratedLiveDrillProviderRecoveryAuthorization({
    context: normalizedContext,
    issuedAt,
    expiresAt
  });
  const persistedContext = persistIntegratedLiveDrillExactPrivateJson({
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_REJECTED",
    filePath: contextPath,
    forbiddenRootPath,
    rootPath,
    value: normalizedContext
  });
  requireCondition(
    canonicalJson(persistedContext) === canonicalJson(normalizedContext),
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_REJECTED"
  );
  return validateIntegratedLiveDrillProviderSupervisorPreparation(
    withReceipt(supervisorPreparationBody({
      context: persistedContext,
      preparation
    })),
    {
      context: persistedContext,
      dispatchPreparation:
        readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation(
          persistedContext
        )
    }
  );
}

export async function prepareIntegratedLiveDrillProviderSupervisor(args = {}) {
  const options = boundaryRecord(
    args,
    ["clock", "dependencies", "environment", "rootDescriptor"],
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_OPTIONS_REJECTED"
  );
  const clock = options.clock ?? Date.now;
  const environment = normalizedSupervisorEnvironment(
    options.environment ?? process.env
  );
  requireCondition(
    typeof clock === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_TIME_REJECTED"
  );
  const resolvedDependencies = normalizedDependencies(
    options.dependencies ?? defaultDependencies(environment)
  );
  const now = clock();
  requireCondition(
    Number.isSafeInteger(now),
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_TIME_REJECTED"
  );
  const recoveryEvidenceRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT"
  );
  const forbiddenRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
  );
  const expectedRootBinding = parseEnvironmentJson(
    environment,
    INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING_ENVIRONMENT,
    4096
  );
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    binding: expectedRootBinding,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_ROOT_REJECTED",
    descriptor: options.rootDescriptor,
    forbiddenRootPath,
    rootPath: recoveryEvidenceRootPath
  });
  try {
  await rootLease.assertSettled();
  const child = resolvedDependencies.authorizeOrVerifyIntegratedLiveDrillChildLaunch(
    environment,
    "MANAGED_MCP_RECOVERY",
    {
      forbiddenRootPath: requiredEnvironment(
        environment,
        "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
      ),
      now
    }
  );
  assertIntegratedLiveDrillChildAuthorizationCurrent(child, { now });
  const primarySourceUrl = requiredEnvironment(
    environment,
    "PRIMARY_RECOVERY_SOURCE_DATABASE_URL"
  );
  const recoveryPublisherUrl = requiredEnvironment(
    environment,
    "RECOVERY_PUBLISHER_DATABASE_URL"
  );
  const primaryAuditUrl = requiredEnvironment(
    environment,
    "PRIMARY_AUDIT_DATABASE_URL"
  );
  const primaryClusterId = requiredEnvironment(
    environment,
    "PRIMARY_CLUSTER_ID",
    64
  ).toLowerCase();
  const recoveryClusterId = requiredEnvironment(
    environment,
    "RECOVERY_CLUSTER_ID",
    64
  ).toLowerCase();
  const spec = parseIntegratedLiveDrillSpec(parseEnvironmentJson(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    8192
  ));
  requireCondition(
    requiredEnvironment(environment, "SOURCE_BUILD_IDENTITY", 64) ===
      spec.sourceBuildIdentity &&
      requiredEnvironment(environment, "RECOVERY_SOURCE_RUN_ID", 64) ===
        spec.runId,
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_BINDING_REJECTED"
  );
  resolvedDependencies.assertSeparatedDatabaseEndpoints({
    primaryConnectionString: primarySourceUrl,
    primaryAuditConnectionString: primaryAuditUrl,
    recoveryConnectionString: recoveryPublisherUrl,
    expectedPrimaryHostname: requiredEnvironment(
      environment,
      "EXPECTED_PRIMARY_HOSTNAME"
    ),
    expectedRecoveryHostname: requiredEnvironment(
      environment,
      "EXPECTED_RECOVERY_HOSTNAME"
    ),
    primaryClusterId,
    recoveryClusterId
  });
  await Promise.all([
    resolvedDependencies.assertRecoveryPublisherTrustRootWriteDenied({
      connectionString: primarySourceUrl,
      credentialLabel: "recovery-source"
    }),
    resolvedDependencies.assertRecoveryPublisherTrustRootWriteDenied({
      connectionString: primaryAuditUrl,
      credentialLabel: "recovery-audit"
    }),
    resolvedDependencies.assertRecoveryRunnerBaseTableReadsDenied({
      connectionString: primarySourceUrl,
      credentialLabel: "recovery-source"
    }),
    resolvedDependencies.assertRecoveryRunnerBaseTableReadsDenied({
      connectionString: primaryAuditUrl,
      credentialLabel: "recovery-audit"
    })
  ]);
  assertIntegratedLiveDrillChildAuthorizationCurrent(child, { now: clock() });
  const rawRecoverySourceReceipt =
    normalizeIntegratedLiveDrillProviderOrchestrationBoundary(
      await resolvedDependencies.resolveCommittedRecoverySourceReceipt({
      binding: exactSourceBinding(environment),
      connectionString: primarySourceUrl
      })
    );
  const recoverySourceReceipt =
    normalizedRecoverySourceReceiptForContinuity(rawRecoverySourceReceipt);
  const subjectBindingSha256 = principalBindingHash(SYNTHETIC_PRINCIPAL);
  const sourceDigest = recoverySourceBindingDigestFor({
    tenantId: recoverySourceReceipt.tenant_id,
    runId: recoverySourceReceipt.run_id,
    incidentId: recoverySourceReceipt.incident_id,
    evidenceDigest: recoverySourceReceipt.evidence_digest,
    resourceId: recoverySourceReceipt.resource_id,
    operationId: recoverySourceReceipt.operation_id,
    requestDigest: recoverySourceReceipt.request_digest,
    proposalDigest: recoverySourceReceipt.proposal_digest,
    logicalActionDigest: recoverySourceReceipt.logical_action_digest,
    authorizationEpoch: Number(recoverySourceReceipt.authorization_epoch),
    logicalAuthorityKeySha256:
      recoverySourceReceipt.logical_authority_key_sha256,
    authorizationBindingSha256:
      recoverySourceReceipt.authorization_binding_sha256,
    authorityEvidenceBindingSha256:
      recoverySourceReceipt.authority_evidence_binding_sha256,
    selectedEvidenceBindingSha256:
      recoverySourceReceipt.selected_evidence_binding_sha256,
    outcome: recoverySourceReceipt.outcome
  });
  const attempt = canonicalRecoveryAttempt({
    tenantId: recoverySourceReceipt.tenant_id,
    subjectBindingHash: subjectBindingSha256,
    sourceDigest,
    sourceCommitTs: recoverySourceReceipt.recorded_at
  });
  const signer = resolvedDependencies.loadSigner();
  const publisherKeySetDigest = trustedPublisherKeysDigest(
    signer.trustedPublisherKeys
  );
  await resolvedDependencies.resolveCommittedRecoveryPublisherTrustRoot({
    connectionString: primaryAuditUrl,
    trustRootCommitment: signer.trustRootCommitment,
    publisherKeySetDigest
  });
  assertIntegratedLiveDrillChildAuthorizationCurrent(child, { now: clock() });
  const candidateBundle = signer.sign({
    tenantId: recoverySourceReceipt.tenant_id,
    recoverySessionId: attempt.recoverySessionId,
    subjectBindingHash: subjectBindingSha256,
    schemaVersion: 2,
    snapshotVersion: attempt.snapshotVersion,
    sourceClusterId: primaryClusterId,
    sourceCommitTs: attempt.sourceCommitTs,
    sourceDigest,
    policyVersion: rawRecoverySourceReceipt.policy_version,
    checkpointSummary: {
      checkpointVersion: 1,
      failedAgent: rawRecoverySourceReceipt.agent_id,
      phase: "successor-context-recovery",
      scenario: "synthetic-highwater"
    },
    evidenceSummary: {
      admittedCount: rawRecoverySourceReceipt.admittedCount,
      classification: "synthetic",
      evidenceDigest: recoverySourceReceipt.evidence_digest
    },
    conflictSummary: {
      unresolvedCount: rawRecoverySourceReceipt.unresolvedCount,
      status: "none"
    },
    receiptSummary: {
      durableIntentPresent: true,
      outcome: recoverySourceReceipt.outcome,
      reason: rawRecoverySourceReceipt.reason,
      resourceLabel: recoverySourceReceipt.resource_id
    },
    expiresAt: attempt.expiresAt
  });
  const signedBundle = persistOrReuseIntegratedLiveDrillRecoveryBundle({
    destinationPath: requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH"
    ),
    evidenceRootPath: recoveryEvidenceRootPath,
    forbiddenRootPath,
    spec,
    signedBundle: candidateBundle,
    trustedPublisherKeys: signer.trustedPublisherKeys
  });
  const publisher = resolvedDependencies.createPublisher(recoveryPublisherUrl);
  const recoveryAppendReceipt = await publisher.appendSignedBundle(
    signedBundle.bundle
  );
  const recoveryReplayReceipt = await publisher.appendSignedBundle(
    signedBundle.bundle
  );
  requireCondition(
    ["bundle_appended", "bundle_replay", "bundle_present"].includes(
      recoveryAppendReceipt.outcome
    ) && recoveryReplayReceipt.outcome === "bundle_replay",
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PUBLICATION_REJECTED"
  );
  assertIntegratedLiveDrillChildAuthorizationCurrent(child, { now: clock() });
  const auditStartedAt = new Date(clock()).toISOString();
  const recoveryBinding = Object.freeze({
    recoveryClusterId,
    recoverySessionId: attempt.recoverySessionId,
    subjectBindingSha256,
    tenantId: recoverySourceReceipt.tenant_id
  });
  const audit = Object.freeze({
    interactionId: resolvedDependencies.randomUuid(),
    preReadAuditEventId: resolvedDependencies.randomUuid(),
    startedAt: auditStartedAt,
    terminalAuditEventId: resolvedDependencies.randomUuid()
  });
  const committedTrustRoot = integratedLiveDrillChildCommittedTrustRoot(
    loadCommittedRecoveryPublisherTrustRoot(environment)
  );
  const expectation = parseEnvironmentJson(
    environment,
    "TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION",
    1024 * 1024
  );
  const humanAuthorizationTrustRoot = parseEnvironmentJson(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT",
    16_384
  );
  const runnerIdentity = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
    512
  );
  const recoveryBrokerConfiguration = Object.freeze({
    auditTargetIdentity: recoveryAuditTargetIdentity({
      connectionString: primaryAuditUrl,
      primaryClusterId
    }),
    expectedSourceClusterId: primaryClusterId,
    recoveryBrokerConfigDigest: recoveryBrokerConfigDigest({
      recoveryClusterId,
      expectedSourceClusterId: primaryClusterId,
      buildIdentity: spec.sourceBuildIdentity,
      trustedPublisherKeys: signer.trustedPublisherKeys,
      auditTargetIdentity: recoveryAuditTargetIdentity({
        connectionString: primaryAuditUrl,
        primaryClusterId
      })
    }),
    recoveryClusterId
  });
  const trustedRunContext = Object.freeze({
    committedTrustRoot,
    expectation,
    humanAuthorizationTrustRoot,
    recoveryBrokerConfiguration,
    runnerIdentity,
    spec
  });
  const preCallInputs = Object.freeze({
    audit,
    claim: child.value.claim,
    consumedChildAuthorization: Object.freeze({
      attestation: child.attestation
    }),
    consumedManagedMcpLaunch: child.launchReceipt,
    controlLedgerReceipt: child.controlLedgerReceipt,
    managedMcpReservation: child.reservations[2],
    recoveryAppendReceipt,
    recoveryBinding,
    recoveryReplayReceipt,
    recoverySourceReceipt,
    signedBundlePersistenceReceipt: signedBundle.receipt
  });
  const preCallIntent = integratedLiveDrillRecoveryContinuityPreCallIntent({
    ...preCallInputs,
    authorization: child.authorization,
    ledgerRootPath: requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT"
    ),
    forbiddenRootPath,
    recoveryEvidenceRootPath,
    trustedRunContext,
    now: Date.parse(auditStartedAt)
  });
  const context = Object.freeze({
    authorization: child.authorization,
    controlLedgerReceipt: child.controlLedgerReceipt,
    evidenceRootBinding: rootLease.binding,
    forbiddenRootPath,
    ledgerRootPath: requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT"
    ),
    preCallInputs,
    preCallIntent,
    recoveryEvidenceRootPath,
    trustedRunContext
  });
  const persistedPreparation =
    persistIntegratedLiveDrillProviderSupervisorPreparation({
    context,
    contextPath: requiredEnvironment(
      environment,
      INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT
    ),
    forbiddenRootPath,
    issuedAt: auditStartedAt,
    rootPath: recoveryEvidenceRootPath
  });
  await rootLease.assertSettled();
  return persistedPreparation;
  } finally {
    rootLease.release();
  }
}

export function resumeIntegratedLiveDrillProviderSupervisor(args = {}) {
  void args;
  reject("INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_RESUME_DISABLED");
}

export async function main() {
  const environment = normalizedSupervisorEnvironment(process.env);
  const runtimeSpec = parseIntegratedLiveDrillSpec(parseEnvironmentJson(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
    8192
  ));
  assertIntegratedLiveDrillRuntime({
    environment: process.env,
    expectedComponent: "supervisor",
    spec: runtimeSpec
  });
  const mode = requiredEnvironment(
    environment,
    INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE_ENVIRONMENT,
    16
  );
  const rootDescriptor = Number(requiredEnvironment(
    environment,
    INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
    8
  ));
  requireCondition(
    rootDescriptor === 3,
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_ROOT_REJECTED"
  );
  requireCondition(
    mode === "PREPARE",
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_RESUME_DISABLED"
  );
  const result = await prepareIntegratedLiveDrillProviderSupervisor({
    environment,
    rootDescriptor
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  exactSourceBinding,
  supervisorPreparationBody
});
