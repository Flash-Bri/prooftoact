import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import { parseStrictJson } from "./strict-json.js";
import {
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillSha256,
  validateIntegratedLiveDrillHumanAuthorizationTrustRoot,
  verifyIntegratedLiveDrillEvidence
} from "./integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
  integratedLiveDrillRecoveryContinuityPreCallIntent,
  inspectIntegratedLiveDrillRecoveryContinuity,
  validateIntegratedLiveDrillRecoveryContinuityJournal,
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";
import {
  recoveryAuditEventDigest,
  renderRecoveryQuery
} from "./recovery-continuity-identity.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_HANDOFF_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-handoff.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-pre-read.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_RESULT_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-result.v2";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-terminal.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA =
  "tideproof.highwater-drill-provider-dispatch-authorization.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT =
  "Authorize at most one bounded CockroachDB Managed MCP session initialization and one initialized notification, exactly one select_query tools/call for the exact recovery broker configuration and logical request digests bound below, and required close or cleanup of any opened session. No additional session, tools/call, provider action, or retry is authorized; close remains permitted solely to terminate an opened session after any denial or expiry.";
export const INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_BINDING_SCHEMA =
  "tideproof.highwater-drill-private-root-binding.v2";
export const INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT_FD";

export const INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_CLAIM_BOUNDARY =
  "This handoff binds one integrated W1 pre-read audit, one W2 owner-only actual Managed MCP client path with private raw result, independently recomputable exact semantic tools/call request bytes, strictly validated locally recorded transport/session-close evidence, and one independently resolved full-event W3 terminal audit. Initialize and response byte hashes are locally recorded rather than provider-signed or fully reconstructable; this scaffold does not establish provider origin, a provider-global exact-call count, cross-host continuity, or an accepted live result. The reviewed broker/audit-sink resolver resamples current authority immediately before its database connect and query boundaries. Gate1/Gate2 PREPARE/HOLD/RESUME is source-wired and locally tested, but it has not been deployed or executed against the live provider; copied-ledger and cross-host authority, live provider continuity, finalization, acceptance, and release remain unproven. The broad signed run authorization does not directly bind the derived recovery broker configuration or exact logical MCP request; W2 therefore requires a second human-signed exact provider-dispatch authorization at the immediate client boundary. It remains non-accepting until a governed live run establishes the remaining W4/W5, finalizer, release, deployment, and evidence gates. Ambiguous claim, dispatch, provider-result, persistence, or audit states are permanent UNKNOWN_DO_NOT_ACT and never authorize retry.";

const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REQUEST_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[1-9][0-9]*$/u;
const MAX_PRIVATE_ARTIFACT_BYTES = 1024 * 1024;
const MAX_PROVIDER_DISPATCH_AUTHORIZATION_MS = 15 * 60 * 1_000;
const PROVIDER_PRE_CALL_INPUT_KEYS = Object.freeze([
  "audit",
  "claim",
  "consumedChildAuthorization",
  "consumedManagedMcpLaunch",
  "controlLedgerReceipt",
  "managedMcpReservation",
  "recoveryAppendReceipt",
  "recoveryBinding",
  "recoveryReplayReceipt",
  "recoverySourceReceipt",
  "signedBundlePersistenceReceipt"
]);
const PROVIDER_PREPARATION_CONTEXT_KEYS = Object.freeze([
  "authorization",
  "controlLedgerReceipt",
  "evidenceRootBinding",
  "forbiddenRootPath",
  "ledgerRootPath",
  "preCallInputs",
  "preCallIntent",
  "recoveryEvidenceRootPath",
  "trustedRunContext"
]);
const PROVIDER_RUN_CONTEXT_KEYS = Object.freeze([
  ...PROVIDER_PREPARATION_CONTEXT_KEYS,
  "providerDispatchAuthorization"
]);
const RECOGNIZABLE_CREDENTIAL_TEXT_PATTERNS = Object.freeze([
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/iu,
  /^(?:Bearer|Basic)\s+\S+/iu,
  /^(?:AKIA|ASIA)[A-Z0-9]{16}$/u,
  /^(?:gh[oprsu]_|github_pat_)[A-Za-z0-9_]+$/u,
  /^(?:sk-(?:proj-)?|xox[baprs]-|AIza)[A-Za-z0-9_-]{8,}$/u,
  /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u,
  /"(?:d|p|q|dp|dq|qi|k)"\s*:/u
]);
const FINALIZER_CONTEXT_FORBIDDEN_KEY_CLASSES = Object.freeze({
  credentialMaterialAbsent:
    /(?:accesskey|apikey|clientsecret|credential|databaseurl|password|privatekey|secret)/u,
  providerCapabilityAbsent:
    /^(?:broker|databaseclient|fetchimpl|mcpclient|providercapability|providerclient)$/u,
  rawProviderResultAbsent:
    /(?:providerresult|rawproviderresult|rawresult|transportevidence)/u,
  retryNamedKeyAbsent: /retry/u
});
const HANDOFF_KEYS = Object.freeze([
  "accepted",
  "authorizationId",
  "claimBoundary",
  "finalReleaseReady",
  "logicalMcpRequestSha256",
  "observedInitializeCount",
  "observedInitializedNotificationCount",
  "observedSessionCloseCount",
  "observedToolsCallCount",
  "postPrivateEvidenceReconciliationPathAvailable",
  "preCallIntentSha256",
  "preReadAuditReconciled",
  "preReadEvidenceReceiptSha256",
  "providerBacked",
  "providerDispatchAuthorizationSha256",
  "providerEvidenceReceiptSha256",
  "receiptSha256",
  "runAuthorizationDirectlyBindsExactRecoveryRequest",
  "schemaVersion",
  "separateExactProviderDispatchAuthorizationRequired",
  "separateExactProviderDispatchAuthorizationValidated",
  "sessionClosed",
  "terminalAuditReconciled",
  "terminalEvidenceReceiptSha256",
  "transportEvidenceSha256",
  "w1W3ActualProviderPathIntegrated"
]);
const HANDOFF_BOOLEAN_KEYS = Object.freeze([
  "accepted",
  "finalReleaseReady",
  "postPrivateEvidenceReconciliationPathAvailable",
  "preReadAuditReconciled",
  "providerBacked",
  "runAuthorizationDirectlyBindsExactRecoveryRequest",
  "separateExactProviderDispatchAuthorizationRequired",
  "separateExactProviderDispatchAuthorizationValidated",
  "sessionClosed",
  "terminalAuditReconciled",
  "w1W3ActualProviderPathIntegrated"
]);
const HANDOFF_COUNT_KEYS = Object.freeze([
  "observedInitializeCount",
  "observedInitializedNotificationCount",
  "observedSessionCloseCount",
  "observedToolsCallCount"
]);
const HANDOFF_STRING_KEYS = Object.freeze([
  "authorizationId",
  "claimBoundary",
  "logicalMcpRequestSha256",
  "preCallIntentSha256",
  "preReadEvidenceReceiptSha256",
  "providerDispatchAuthorizationSha256",
  "providerEvidenceReceiptSha256",
  "receiptSha256",
  "schemaVersion",
  "terminalEvidenceReceiptSha256",
  "transportEvidenceSha256"
]);
const RECOVERY_AUDIT_EVENT_KEYS = Object.freeze([
  "boundInputDigest",
  "brokerConfigDigest",
  "callerSubjectHash",
  "completedAt",
  "errorCode",
  "eventId",
  "interactionId",
  "outcome",
  "phase",
  "recoveryClusterId",
  "recoverySessionId",
  "resultDigest",
  "sourceWatermark",
  "startedAt",
  "tenantId",
  "queryTemplateDigest"
]);
const PREPARED_RECOVERY_KEYS = Object.freeze([
  "boundInputDigest",
  "brokerConfigDigest",
  "callerSubjectHash",
  "interactionId",
  "preReadAuditDigest",
  "preReadAuditEvent",
  "preReadEventId",
  "query",
  "queryTemplateDigest",
  "recoverySessionId",
  "schemaVersion",
  "sourceDigest",
  "startedAt",
  "tenantId",
  "terminalEventId"
]);
const RECOVERY_RESULT_KEYS = Object.freeze([
  "auditDigest",
  "auditId",
  "auditInteractionId",
  "authorityTransferred",
  "bundleDigest",
  "context",
  "preReadAuditDigest",
  "preReadAuditId",
  "recoverySessionId",
  "requiresFreshAuthorization",
  "sourceDigest",
  "status",
  "tenantId"
]);
const RECOVERY_ROW_KEYS = Object.freeze([
  "authority_transferred",
  "bundle_digest",
  "checkpoint_summary",
  "conflict_summary",
  "evidence_summary",
  "expires_at",
  "policy_version",
  "publisher_key_id",
  "publisher_version",
  "receipt_summary",
  "recovery_session_id",
  "requires_fresh_authorization",
  "schema_version",
  "signature_algorithm",
  "signature_digest",
  "snapshot_version",
  "source_cluster_id",
  "source_commit_ts",
  "source_digest",
  "source_signature_base64",
  "subject_binding_hash",
  "tenant_id"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactIsoMilliseconds(value, code) {
  requireCondition(
    typeof value === "string" &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value),
    code
  );
  const milliseconds = Date.parse(value);
  requireCondition(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    code
  );
  return milliseconds;
}

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const ownKeys = Object.keys(value);
  return ownKeys.length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactContextRecord(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    return false;
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    !ownKeys.every((key) => typeof key === "string") ||
    !keys.every((key) => Object.hasOwn(value, key))
  ) {
    return false;
  }
  return ownKeys.every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      descriptor.enumerable === true;
  });
}

function normalizedContextKey(value) {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function contextKeyAssertions(value, seen = new Set()) {
  const assertions = {
    credentialMaterialAbsent: true,
    providerCapabilityAbsent: true,
    rawProviderResultAbsent: true,
    retryNamedKeyAbsent: true
  };
  const visit = (entry) => {
    if (
      entry === null ||
      typeof entry === "string" ||
      typeof entry === "boolean" ||
      (typeof entry === "number" && Number.isFinite(entry))
    ) {
      if (typeof entry === "string") {
        assertions.credentialMaterialAbsent &&=
          !RECOGNIZABLE_CREDENTIAL_TEXT_PATTERNS.some((pattern) =>
            pattern.test(entry)
          );
      }
      return;
    }
    requireCondition(
      typeof entry === "object" &&
        entry !== null &&
        !seen.has(entry),
      "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
    );
    seen.add(entry);
    if (Array.isArray(entry)) {
      const ownKeys = Reflect.ownKeys(entry);
      requireCondition(
        Object.getPrototypeOf(entry) === Array.prototype &&
          ownKeys.length === entry.length + 1 &&
          ownKeys.every((key) =>
            key === "length" || /^(?:0|[1-9][0-9]*)$/u.test(String(key))
          ),
        "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
      );
      for (let index = 0; index < entry.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          entry,
          String(index)
        );
        requireCondition(
          descriptor !== undefined &&
            Object.hasOwn(descriptor, "value") &&
            descriptor.enumerable === true,
          "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
        );
        visit(descriptor.value);
      }
      seen.delete(entry);
      return;
    }
    requireCondition(
      [Object.prototype, null].includes(Object.getPrototypeOf(entry)),
      "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
    );
    for (const key of Reflect.ownKeys(entry)) {
      const descriptor = typeof key === "string"
        ? Object.getOwnPropertyDescriptor(entry, key)
        : null;
      requireCondition(
        typeof key === "string" &&
          descriptor !== undefined &&
          Object.hasOwn(descriptor, "value") &&
          descriptor.enumerable === true,
        "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
      );
      const normalized = normalizedContextKey(key);
      for (const [assertion, pattern] of Object.entries(
        FINALIZER_CONTEXT_FORBIDDEN_KEY_CLASSES
      )) {
        assertions[assertion] &&= !pattern.test(normalized);
      }
      visit(descriptor.value);
    }
    seen.delete(entry);
  };
  visit(value);
  return Object.freeze(assertions);
}

function requireSafeContextAssertions(assertions) {
  requireCondition(
    Object.values(assertions).every((value) => value === true),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  return assertions;
}

function normalizeContextJson(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    requireCondition(
      Object.getPrototypeOf(value) === Array.prototype,
      "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
    );
    return Object.freeze(value.map((entry) => normalizeContextJson(entry)));
  }
  requireCondition(
    value !== null &&
      typeof value === "object" &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  const normalized = {};
  for (const key of Object.keys(value)) {
    normalized[key] = normalizeContextJson(value[key]);
  }
  return Object.freeze(normalized);
}

function normalizeContextScalar(value) {
  requireCondition(
    value === null ||
      typeof value === "string" ||
      typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value)),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  return value;
}

function normalizeContextScalarArray(value) {
  requireCondition(
    Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype,
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  return Object.freeze(value.map((entry) => normalizeContextScalar(entry)));
}

function normalizeContextExactRecord(value, keys, nested = {}) {
  requireCondition(
    exactContextRecord(value, keys),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  const normalized = {};
  for (const key of keys) {
    normalized[key] = Object.hasOwn(nested, key)
      ? nested[key](value[key])
      : normalizeContextScalar(value[key]);
  }
  return Object.freeze(normalized);
}

function normalizeContextClaim(value) {
  return normalizeContextExactRecord(value, [
    "authorizationClaimSha256",
    "authorizationId",
    "fileByteLength",
    "fileNameSha256",
    "schemaVersion",
    "spendAuthorizationSha256"
  ]);
}

function normalizeContextReservation(value) {
  return normalizeContextExactRecord(value, [
    "authorizationId",
    "cumulativeAuthorizedExposureUsd",
    "fileByteLength",
    "fileNameSha256",
    "reservationSha256",
    "schemaVersion",
    "scopeId",
    "sequence"
  ]);
}

function normalizeContextChildScope(value) {
  return normalizeContextExactRecord(value, [
    "component",
    "maximumExecutions",
    "maximumExposureUsd",
    "provider",
    "scopeId",
    "sequence"
  ]);
}

function normalizeContextChildAttestation(value) {
  return normalizeContextExactRecord(value, [
    "payload",
    "schemaVersion",
    "signature"
  ], {
    payload: (payload) => normalizeContextExactRecord(payload, [
      "authorizationAttestationSha256",
      "authorizationId",
      "claim",
      "configDigest",
      "expectationSha256",
      "expiresAt",
      "issuedAt",
      "nonceSha256",
      "reservation",
      "runId",
      "runnerIdentitySha256",
      "schemaVersion",
      "scope",
      "sourceCommit",
      "specSha256",
      "tokenId",
      "treeDigest"
    ], {
      claim: normalizeContextClaim,
      reservation: normalizeContextReservation,
      scope: normalizeContextChildScope
    }),
    signature: (signature) => normalizeContextExactRecord(signature, [
      "algorithm",
      "keyIdSha256",
      "value"
    ])
  });
}

function normalizeContextControlLedgerReceipt(value) {
  return normalizeContextExactRecord(value, [
    "authorizationAttestationSha256",
    "authorizationClaimSha256",
    "authorizationId",
    "authorizedMaximumCumulativeExposureUsd",
    "childLaunchDigests",
    "exactChildLaunchCount",
    "exactScopeCount",
    "receiptSha256",
    "reservationDigests",
    "reservedCumulativeExposureUsd",
    "runId",
    "schemaVersion",
    "spendAuthorizationSha256"
  ], {
    childLaunchDigests: normalizeContextScalarArray,
    reservationDigests: normalizeContextScalarArray
  });
}

function normalizeContextPublicationReceipt(value) {
  return normalizeContextExactRecord(value, [
    "bundleDigest",
    "commit",
    "outcome"
  ], {
    commit: (commit) => normalizeContextExactRecord(commit, [
      "authority",
      "databaseNow",
      "observation",
      "operation",
      "operationDigest",
      "outcome",
      "reason",
      "schemaVersion",
      "status"
    ], {
      authority: (authority) => normalizeContextExactRecord(authority, [
        "current",
        "requiresFreshAuthorization"
      ])
    })
  });
}

function normalizeContextPreCallInputs(value) {
  return normalizeContextExactRecord(value, PROVIDER_PRE_CALL_INPUT_KEYS, {
    audit: (audit) => normalizeContextExactRecord(audit, [
      "interactionId",
      "preReadAuditEventId",
      "startedAt",
      "terminalAuditEventId"
    ]),
    claim: normalizeContextClaim,
    consumedChildAuthorization: (authorization) =>
      normalizeContextExactRecord(authorization, ["attestation"], {
        attestation: normalizeContextChildAttestation
      }),
    consumedManagedMcpLaunch: (launch) => normalizeContextExactRecord(
      launch,
      [
        "authorizationId",
        "childLaunchSha256",
        "fileByteLength",
        "fileNameSha256",
        "reservationSha256",
        "schemaVersion",
        "scopeId",
        "sequence",
        "tokenId"
      ]
    ),
    controlLedgerReceipt: normalizeContextControlLedgerReceipt,
    managedMcpReservation: normalizeContextReservation,
    recoveryAppendReceipt: normalizeContextPublicationReceipt,
    recoveryBinding: (binding) => normalizeContextExactRecord(binding, [
      "recoveryClusterId",
      "recoverySessionId",
      "subjectBindingSha256",
      "tenantId"
    ]),
    recoveryReplayReceipt: normalizeContextPublicationReceipt,
    recoverySourceReceipt: (receipt) => normalizeContextExactRecord(receipt, [
      "admissibility",
      "authority_evidence_binding_sha256",
      "authorization_binding_sha256",
      "authorization_epoch",
      "evidence_digest",
      "evidence_id",
      "has_durable_intent",
      "incident_id",
      "logical_action_digest",
      "logical_authority_key_sha256",
      "operation_id",
      "outcome",
      "proposal_digest",
      "recorded_at",
      "request_digest",
      "resource_id",
      "run_id",
      "selected_evidence_binding_sha256",
      "tenant_id"
    ]),
    signedBundlePersistenceReceipt: (receipt) => normalizeContextExactRecord(
      receipt,
      [
        "atomicCreateOnly",
        "bundleDigest",
        "configDigest",
        "creationProtocolObserved",
        "directoryEntrySynced",
        "fileByteLength",
        "fileDataSynced",
        "fileMode",
        "parentDirectoryMode",
        "pathSha256",
        "receiptSha256",
        "rereadVerified",
        "reusedExisting",
        "runId",
        "sameFilesystemAtomicLink",
        "schemaVersion",
        "signatureDigest",
        "signedBundleSha256",
        "sourceBuildIdentitySha256",
        "sourceCommit",
        "treeDigest"
      ]
    )
  });
}

export function normalizeIntegratedLiveDrillProviderContext(
  context,
  options = {}
) {
  requireCondition(
    exactContextRecord(options, []) ||
      exactContextRecord(options, ["requireDispatchAuthorization"]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  const requireDispatchAuthorization = Object.hasOwn(
    options,
    "requireDispatchAuthorization"
  )
    ? options.requireDispatchAuthorization
    : true;
  const keys = requireDispatchAuthorization
    ? PROVIDER_RUN_CONTEXT_KEYS
    : PROVIDER_PREPARATION_CONTEXT_KEYS;
  requireCondition(
    typeof requireDispatchAuthorization === "boolean" &&
      exactContextRecord(context, keys),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  requireSafeContextAssertions(contextKeyAssertions(context));
  const preCallInputs = normalizeContextPreCallInputs(context.preCallInputs);
  const trustedRunContext = normalizeContextExactRecord(
    context.trustedRunContext,
    [
      "committedTrustRoot",
      "expectation",
      "humanAuthorizationTrustRoot",
      "recoveryBrokerConfiguration",
      "runnerIdentity",
      "spec"
    ],
    Object.fromEntries([
      "committedTrustRoot",
      "expectation",
      "humanAuthorizationTrustRoot",
      "recoveryBrokerConfiguration",
      "spec"
    ].map((key) => [key, normalizeContextJson]))
  );
  const authorization = normalizeContextJson(context.authorization);
  const evidenceRootBinding = validateIntegratedLiveDrillPrivateRootBinding(
    context.evidenceRootBinding
  );
  const controlLedgerReceipt = normalizeContextControlLedgerReceipt(
    context.controlLedgerReceipt
  );
  requireCondition(
    canonicalJson(controlLedgerReceipt) ===
      canonicalJson(preCallInputs.controlLedgerReceipt),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  const childAuthorizationIssuedAt =
    preCallInputs.consumedChildAuthorization.attestation.payload.issuedAt;
  const preCallIntent = integratedLiveDrillRecoveryContinuityPreCallIntent({
    ...preCallInputs,
    authorization,
    ledgerRootPath: normalizeContextScalar(context.ledgerRootPath),
    forbiddenRootPath: normalizeContextScalar(context.forbiddenRootPath),
    recoveryEvidenceRootPath: normalizeContextScalar(
      context.recoveryEvidenceRootPath
    ),
    trustedRunContext,
    now: exactIsoMilliseconds(
      childAuthorizationIssuedAt,
      "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
    )
  });
  requireCondition(
    canonicalJson(preCallIntent) === canonicalJson(context.preCallIntent),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  const normalized = {
    authorization,
    controlLedgerReceipt,
    evidenceRootBinding,
    forbiddenRootPath: normalizeContextScalar(context.forbiddenRootPath),
    ledgerRootPath: normalizeContextScalar(context.ledgerRootPath),
    preCallInputs,
    preCallIntent,
    recoveryEvidenceRootPath: normalizeContextScalar(
      context.recoveryEvidenceRootPath
    ),
    trustedRunContext
  };
  requireCondition(
    evidenceRootBinding.rootPathSha256 ===
        integratedLiveDrillCanonicalSha256(normalized.recoveryEvidenceRootPath) &&
      evidenceRootBinding.forbiddenRootPathSha256 ===
        integratedLiveDrillCanonicalSha256(normalized.forbiddenRootPath),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  if (requireDispatchAuthorization) {
    const providerDispatchAuthorization = normalizeContextJson(
      context.providerDispatchAuthorization
    );
    validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
      providerDispatchAuthorization,
      {
        childAuthorizationIssuedAt,
        humanAuthorizationTrustRoot:
          trustedRunContext.humanAuthorizationTrustRoot,
        intent: preCallIntent,
        requireCurrent: false
      }
    );
    normalized.providerDispatchAuthorization = providerDispatchAuthorization;
  }
  const frozen = Object.freeze(normalized);
  requireCondition(
    canonicalJson(frozen) === canonicalJson(context),
    "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
  );
  requireSafeContextAssertions(contextKeyAssertions(frozen));
  return frozen;
}

export function integratedLiveDrillProviderContextAssertions(context) {
  const normalized = normalizeIntegratedLiveDrillProviderContext(context);
  const assertions = contextKeyAssertions(normalized);
  return Object.freeze({
    contextExactSchemaValidated:
      exactContextRecord(normalized, PROVIDER_RUN_CONTEXT_KEYS),
    ...assertions
  });
}

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (
    !relative.startsWith("..") && !path.isAbsolute(relative)
  );
}

export function secureIntegratedLiveDrillPrivateRoot(
  rootPath,
  forbiddenRootPath,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_REJECTED"
) {
  requireCondition(
    typeof rootPath === "string" &&
      path.isAbsolute(rootPath) &&
      path.resolve(rootPath) === rootPath &&
      typeof forbiddenRootPath === "string" &&
      path.isAbsolute(forbiddenRootPath) &&
      path.resolve(forbiddenRootPath) === forbiddenRootPath,
    code
  );
  let canonicalRoot;
  let canonicalForbidden;
  let canonicalParent;
  let parentStat;
  let parentCtimeNs;
  let stat;
  const parentPath = path.dirname(rootPath);
  try {
    canonicalRoot = fs.realpathSync(rootPath);
    canonicalForbidden = fs.realpathSync(forbiddenRootPath);
    canonicalParent = fs.realpathSync(parentPath);
    parentStat = fs.lstatSync(parentPath);
    parentCtimeNs = String(
      fs.lstatSync(parentPath, { bigint: true }).ctimeNs
    );
    stat = fs.lstatSync(rootPath);
  } catch (cause) {
    reject(code, cause);
  }
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : stat.uid;
  requireCondition(
    canonicalRoot === rootPath &&
      stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === expectedUid &&
      (stat.mode & 0o777) === 0o700 &&
      !pathIsWithin(canonicalRoot, canonicalForbidden),
    code
  );
  return Object.freeze({
    expectedUid,
    forbiddenRootPath: canonicalForbidden,
    parentCtimeNs,
    parentPath: canonicalParent,
    parentStat,
    rootPath: canonicalRoot,
    stat
  });
}

function assertIntegratedLiveDrillPrivateRootGuardCurrent(
  secure,
  code
) {
  let parent;
  let parentCtimeNs;
  let canonicalParent;
  let entries;
  try {
    parent = fs.lstatSync(secure.parentPath);
    parentCtimeNs = String(
      fs.lstatSync(secure.parentPath, { bigint: true }).ctimeNs
    );
    canonicalParent = fs.realpathSync(secure.parentPath);
    entries = fs.readdirSync(secure.parentPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    secure.parentPath === path.dirname(secure.rootPath) &&
      parent.isDirectory() &&
      !parent.isSymbolicLink() &&
      parent.dev === secure.parentStat.dev &&
      parent.ino === secure.parentStat.ino &&
      parent.uid === secure.expectedUid &&
      (parent.mode & 0o777) === 0o700 &&
      parentCtimeNs === secure.parentCtimeNs &&
      canonicalParent === secure.parentPath &&
      !pathIsWithin(secure.parentPath, secure.forbiddenRootPath) &&
      entries.length === 1 &&
      entries[0] === path.basename(secure.rootPath),
    code
  );
}

function privateRootBindingBody(
  secure,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
) {
  assertIntegratedLiveDrillPrivateRootGuardCurrent(secure, code);
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_BINDING_SCHEMA,
    device: String(secure.stat.dev),
    forbiddenRootPathSha256: integratedLiveDrillCanonicalSha256(
      secure.forbiddenRootPath
    ),
    inode: String(secure.stat.ino),
    mode: "0700",
    parentCtimeNs: secure.parentCtimeNs,
    parentDevice: String(secure.parentStat.dev),
    parentInode: String(secure.parentStat.ino),
    parentMode: "0700",
    parentPathSha256: integratedLiveDrillCanonicalSha256(secure.parentPath),
    parentUid: secure.expectedUid,
    rootPathSha256: integratedLiveDrillCanonicalSha256(secure.rootPath),
    uid: secure.expectedUid
  });
}

export function integratedLiveDrillPrivateRootBinding(
  secure,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
) {
  const body = privateRootBindingBody(secure, code);
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export function validateIntegratedLiveDrillPrivateRootBinding(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED";
  requireCondition(
    exactKeys(value, [
      "device",
      "forbiddenRootPathSha256",
      "inode",
      "mode",
      "parentCtimeNs",
      "parentDevice",
      "parentInode",
      "parentMode",
      "parentPathSha256",
      "parentUid",
      "receiptSha256",
      "rootPathSha256",
      "schemaVersion",
      "uid"
    ]),
    code
  );
  const { receiptSha256, ...body } = value;
  requireCondition(
    body.schemaVersion === INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_BINDING_SCHEMA &&
      /^(?:0|[1-9][0-9]*)$/u.test(body.device ?? "") &&
      /^(?:0|[1-9][0-9]*)$/u.test(body.inode ?? "") &&
      /^(?:0|[1-9][0-9]*)$/u.test(body.parentCtimeNs ?? "") &&
      /^(?:0|[1-9][0-9]*)$/u.test(body.parentDevice ?? "") &&
      /^(?:0|[1-9][0-9]*)$/u.test(body.parentInode ?? "") &&
      Number.isSafeInteger(body.uid) &&
      body.uid >= 0 &&
      Number.isSafeInteger(body.parentUid) &&
      body.parentUid >= 0 &&
      body.parentUid === body.uid &&
      body.mode === "0700" &&
      body.parentMode === "0700" &&
      HEX_64.test(body.forbiddenRootPathSha256 ?? "") &&
      HEX_64.test(body.parentPathSha256 ?? "") &&
      HEX_64.test(body.rootPathSha256 ?? "") &&
      HEX_64.test(receiptSha256 ?? "") &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body),
    code
  );
  return Object.freeze({ ...value });
}

export function assertIntegratedLiveDrillPrivateRootMatchesBinding(
  secure,
  binding,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
) {
  const accepted = validateIntegratedLiveDrillPrivateRootBinding(binding);
  assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
  assertIntegratedLiveDrillPrivateRootGuardCurrent(secure, code);
  requireCondition(
    canonicalJson(accepted) ===
      canonicalJson(integratedLiveDrillPrivateRootBinding(secure, code)),
    code
  );
  return accepted;
}

export function acquireIntegratedLiveDrillPrivateRootLease({
  binding,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED",
  descriptor: inheritedDescriptor,
  forbiddenRootPath,
  rootPath
}) {
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    code
  );
  const acceptedBinding = binding === undefined
    ? integratedLiveDrillPrivateRootBinding(secure, code)
    : assertIntegratedLiveDrillPrivateRootMatchesBinding(
        secure,
        binding,
        code
      );
  let descriptor;
  let parentDescriptor;
  const descriptorInherited = inheritedDescriptor !== undefined;
  const parentPath = secure.parentPath;
  try {
    requireCondition(
      inheritedDescriptor === undefined ||
        (Number.isSafeInteger(inheritedDescriptor) && inheritedDescriptor >= 0),
      code
    );
    descriptor = inheritedDescriptor ?? fs.openSync(
        secure.rootPath,
        fs.constants.O_RDONLY |
          fs.constants.O_NOFOLLOW |
          (fs.constants.O_DIRECTORY ?? 0)
      );
    parentDescriptor = fs.openSync(
      parentPath,
      fs.constants.O_RDONLY |
        fs.constants.O_NOFOLLOW |
        (fs.constants.O_DIRECTORY ?? 0)
    );
    const opened = fs.fstatSync(descriptor);
    const openedParent = fs.fstatSync(parentDescriptor);
    const openedParentCtimeNs = String(
      fs.fstatSync(parentDescriptor, { bigint: true }).ctimeNs
    );
    const namedParent = fs.lstatSync(parentPath);
    requireCondition(
      opened.isDirectory() &&
        opened.dev === secure.stat.dev &&
        opened.ino === secure.stat.ino &&
        opened.uid === secure.expectedUid &&
        (opened.mode & 0o777) === 0o700 &&
        openedParent.isDirectory() &&
        !namedParent.isSymbolicLink() &&
        openedParent.dev === secure.parentStat.dev &&
        openedParent.ino === secure.parentStat.ino &&
        openedParent.uid === secure.expectedUid &&
        (openedParent.mode & 0o777) === 0o700 &&
        openedParentCtimeNs === secure.parentCtimeNs &&
        openedParent.dev === namedParent.dev &&
        openedParent.ino === namedParent.ino &&
        fs.realpathSync(parentPath) === parentPath,
      code
    );
  } catch (cause) {
    if (descriptor !== undefined && !descriptorInherited) {
      try { fs.closeSync(descriptor); } catch { /* Preserve first failure. */ }
    }
    if (parentDescriptor !== undefined) {
      try { fs.closeSync(parentDescriptor); } catch { /* Preserve first failure. */ }
    }
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  let released = false;
  const assertCurrent = () => {
    requireCondition(!released, code);
    let opened;
    let openedParent;
    let openedParentCtimeNs;
    let namedParent;
    try {
      opened = fs.fstatSync(descriptor);
      openedParent = fs.fstatSync(parentDescriptor);
      openedParentCtimeNs = String(
        fs.fstatSync(parentDescriptor, { bigint: true }).ctimeNs
      );
      namedParent = fs.lstatSync(parentPath);
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(
      opened.isDirectory() &&
        opened.dev === secure.stat.dev &&
        opened.ino === secure.stat.ino &&
        opened.uid === secure.expectedUid &&
        (opened.mode & 0o777) === 0o700 &&
        openedParent.isDirectory() &&
        !namedParent.isSymbolicLink() &&
        openedParent.dev === secure.parentStat.dev &&
        openedParent.ino === secure.parentStat.ino &&
        openedParent.uid === secure.expectedUid &&
        (openedParent.mode & 0o777) === 0o700 &&
        openedParentCtimeNs === secure.parentCtimeNs &&
        openedParent.dev === namedParent.dev &&
        openedParent.ino === namedParent.ino &&
        fs.realpathSync(parentPath) === parentPath,
      code
    );
    const accepted = assertIntegratedLiveDrillPrivateRootMatchesBinding(
      secure,
      acceptedBinding,
      code
    );
    return accepted;
  };
  const assertSettled = async () => {
    return assertCurrent();
  };
  const operations = new WeakSet();
  const beginOperation = () => {
    assertCurrent();
    const parent = fs.fstatSync(parentDescriptor, { bigint: true });
    const operation = Object.freeze({
      device: parent.dev,
      inode: parent.ino,
      ctimeNs: parent.ctimeNs
    });
    operations.add(operation);
    return operation;
  };
  const assertOperation = (operation) => {
    requireCondition(
      operation &&
        typeof operation === "object" &&
        operations.has(operation),
      code
    );
    operations.delete(operation);
    const parent = fs.fstatSync(parentDescriptor, { bigint: true });
    requireCondition(
      parent.dev === operation.device &&
        parent.ino === operation.inode &&
        parent.ctimeNs === operation.ctimeNs,
      code
    );
    return assertCurrent();
  };
  const release = () => {
    if (released) return;
    released = true;
    if (!descriptorInherited) fs.closeSync(descriptor);
    fs.closeSync(parentDescriptor);
  };
  assertCurrent();
  return Object.freeze({
    assertOperation,
    assertCurrent,
    assertSettled,
    beginOperation,
    binding: acceptedBinding,
    descriptor,
    release,
    secure
  });
}

export function assertIntegratedLiveDrillPrivateRootCurrent(
  secure,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_DRIFT"
) {
  let current;
  try {
    current = fs.lstatSync(secure.rootPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    current.isDirectory() &&
      !current.isSymbolicLink() &&
      current.dev === secure.stat.dev &&
      current.ino === secure.stat.ino &&
      current.uid === secure.expectedUid &&
      (current.mode & 0o777) === 0o700 &&
      fs.realpathSync(secure.rootPath) === secure.rootPath &&
      !pathIsWithin(secure.rootPath, secure.forbiddenRootPath),
    code
  );
}

export function readIntegratedLiveDrillExactPrivateJson({
  code,
  filePath,
  maximumBytes = MAX_PRIVATE_ARTIFACT_BYTES,
  secure
}) {
  requireCondition(
    typeof code === "string" &&
      typeof filePath === "string" &&
      path.isAbsolute(filePath) &&
      path.resolve(filePath) === filePath &&
      path.dirname(filePath) === secure.rootPath &&
      Number.isSafeInteger(maximumBytes) &&
      maximumBytes > 0,
    code
  );
  let descriptor;
  try {
    assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    requireCondition(
      before.isFile() &&
        before.uid === secure.expectedUid &&
        before.nlink === 1 &&
        (before.mode & 0o777) === 0o600 &&
        before.size > 0 &&
        before.size <= maximumBytes,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        after.uid === secure.expectedUid &&
        after.nlink === 1 &&
        (after.mode & 0o777) === 0o600 &&
        named.isFile() &&
        !named.isSymbolicLink() &&
        named.dev === after.dev &&
        named.ino === after.ino &&
        named.uid === after.uid &&
        named.nlink === 1 &&
        (named.mode & 0o777) === 0o600 &&
        named.size === after.size &&
        bytes.length === after.size &&
        fs.realpathSync(filePath) === filePath,
      code
    );
    let value;
    try {
      value = parseStrictJson(bytes.toString("utf8"), {
        duplicateCode: code,
        invalidCode: code
      });
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(
      bytes.equals(Buffer.from(`${canonicalJson(value)}\n`, "utf8")),
      code
    );
    assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
    requireCondition(
      path.dirname(fs.realpathSync(filePath)) === secure.rootPath,
      code
    );
    return value;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function normalizePersistedJson(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(value.map((entry) => normalizePersistedJson(entry)));
  }
  requireCondition(
    value !== null &&
      typeof value === "object" &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  const normalized = {};
  for (const key of Object.keys(value)) {
    normalized[key] = normalizePersistedJson(value[key]);
  }
  return Object.freeze(normalized);
}

function normalizeExactRecord(value, keys, nested = {}) {
  requireCondition(
    exactKeys(value, keys),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  const normalized = {};
  for (const key of keys) {
    normalized[key] = Object.hasOwn(nested, key)
      ? nested[key](value[key])
      : normalizePersistedJson(value[key]);
  }
  return Object.freeze(normalized);
}

function validateReceipt(value, keys, schema) {
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactKeys(value, [...keys, "receiptSha256"]) &&
      body.schemaVersion === schema &&
      HEX_64.test(receiptSha256 ?? "") &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
}

function normalizeAuditEvent(value) {
  const event = normalizeExactRecord(value, RECOVERY_AUDIT_EVENT_KEYS);
  requireCondition(
    UUID.test(event.eventId ?? "") &&
      UUID.test(event.interactionId ?? "") &&
      UUID.test(event.tenantId ?? "") &&
      UUID.test(event.recoverySessionId ?? "") &&
      UUID.test(event.recoveryClusterId ?? "") &&
      [
        event.callerSubjectHash,
        event.brokerConfigDigest,
        event.queryTemplateDigest,
        event.boundInputDigest
      ].every((digest) => HEX_64.test(digest ?? "")) &&
      (event.resultDigest === null || HEX_64.test(event.resultDigest ?? "")) &&
      (event.errorCode === null || typeof event.errorCode === "string") &&
      (event.sourceWatermark === null ||
        new Date(event.sourceWatermark).toISOString() === event.sourceWatermark) &&
      new Date(event.startedAt).toISOString() === event.startedAt &&
      new Date(event.completedAt).toISOString() === event.completedAt,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return event;
}

function auditEventDigest(event) {
  return integratedLiveDrillSha256(canonicalJson({
    ...event,
    toolName: "select_query"
  }));
}

function normalizePrepared(value, intent) {
  const prepared = normalizeExactRecord(value, PREPARED_RECOVERY_KEYS, {
    preReadAuditEvent: normalizeAuditEvent
  });
  const event = prepared.preReadAuditEvent;
  requireCondition(
    prepared.schemaVersion === "tideproof.prepared-recovery.v1" &&
      prepared.tenantId === intent.tenantId &&
      prepared.recoverySessionId === intent.recoverySessionId &&
      prepared.callerSubjectHash === intent.subjectBindingSha256 &&
      prepared.sourceDigest === intent.sourceDigest &&
      prepared.boundInputDigest === intent.boundInputSha256 &&
      prepared.brokerConfigDigest === intent.recoveryBrokerConfigDigest &&
      prepared.queryTemplateDigest === intent.queryTemplateSha256 &&
      prepared.query === renderRecoveryQuery({
        tenantId: intent.tenantId,
        recoverySessionId: intent.recoverySessionId,
        subjectBindingHash: intent.subjectBindingSha256,
        sourceDigest: intent.sourceDigest
      }) &&
      prepared.interactionId === intent.interactionId &&
      prepared.preReadEventId === intent.preReadAuditEventId &&
      prepared.terminalEventId === intent.terminalAuditEventId &&
      prepared.startedAt === intent.startedAt &&
      event.eventId === prepared.preReadEventId &&
      event.interactionId === prepared.interactionId &&
      event.tenantId === prepared.tenantId &&
      event.recoverySessionId === prepared.recoverySessionId &&
      event.callerSubjectHash === prepared.callerSubjectHash &&
      event.recoveryClusterId === intent.recoveryClusterId &&
      event.brokerConfigDigest === prepared.brokerConfigDigest &&
      event.queryTemplateDigest === prepared.queryTemplateDigest &&
      event.boundInputDigest === prepared.boundInputDigest &&
      event.startedAt === prepared.startedAt &&
      event.phase === "pre_read" &&
      event.resultDigest === null &&
      event.sourceWatermark === null &&
      event.outcome === "read_authorized" &&
      event.errorCode === null &&
      prepared.preReadAuditDigest === auditEventDigest(event),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return prepared;
}

function normalizeRecoveryResult(value) {
  const recovery = normalizeExactRecord(value, RECOVERY_RESULT_KEYS, {
    context: (context) => normalizeExactRecord(
      context,
      ["checkpoint", "conflicts", "evidence", "receipt"],
      {
        checkpoint: (entry) => normalizeExactRecord(
          entry,
          ["checkpointVersion", "failedAgent", "phase", "scenario"]
        ),
        conflicts: (entry) => normalizeExactRecord(
          entry,
          ["status", "unresolvedCount"]
        ),
        evidence: (entry) => normalizeExactRecord(
          entry,
          ["admittedCount", "classification", "evidenceDigest"]
        ),
        receipt: (entry) => normalizeExactRecord(
          entry,
          ["durableIntentPresent", "outcome", "reason", "resourceLabel"]
        )
      }
    )
  });
  requireCondition(
    recovery.status === "RECOVERED_CONTEXT_ONLY" &&
      recovery.authorityTransferred === false &&
      recovery.requiresFreshAuthorization === true &&
      [
        recovery.auditId,
        recovery.auditInteractionId,
        recovery.preReadAuditId,
        recovery.recoverySessionId,
        recovery.tenantId
      ].every((entry) => UUID.test(entry ?? "")) &&
      [
        recovery.auditDigest,
        recovery.preReadAuditDigest,
        recovery.sourceDigest,
        recovery.bundleDigest
      ].every((entry) => HEX_64.test(entry ?? "")),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return recovery;
}

function normalizeRecoveryRow(value) {
  const row = normalizeExactRecord(value, RECOVERY_ROW_KEYS);
  requireCondition(
    row.authority_transferred === false &&
      row.requires_fresh_authorization === true,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return row;
}

function normalizeRawResult(value) {
  if (exactKeys(value, ["rows"])) {
    requireCondition(
      Array.isArray(value.rows) && value.rows.length === 1,
      "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
    );
    return Object.freeze({
      rows: Object.freeze(value.rows.map(normalizeRecoveryRow))
    });
  }
  requireCondition(
    exactKeys(value, ["content"]) &&
      Array.isArray(value.content) &&
      value.content.length === 1 &&
      exactKeys(value.content[0], ["type", "text"]) &&
      value.content[0].type === "text" &&
      typeof value.content[0].text === "string",
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  let parsed;
  try {
    parsed = parseStrictJson(value.content[0].text, {
      duplicateCode:
        "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED",
      invalidCode:
        "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
    });
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED", cause);
  }
  requireCondition(
    exactKeys(parsed, ["rows"]) &&
      Array.isArray(parsed.rows) &&
      parsed.rows.length === 1,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  parsed.rows.map(normalizeRecoveryRow);
  return Object.freeze({
    content: Object.freeze([Object.freeze({
      type: "text",
      text: value.content[0].text
    })])
  });
}

function validDigest(value) {
  return typeof value === "string" && HEX_64.test(value);
}

function validOptionalDigest(value) {
  return value === null || validDigest(value);
}

function validByteCount(value, maximum) {
  return Number.isSafeInteger(value) && value > 0 && value <= maximum;
}

function validRpcEntry(entry, {
  contentTypes,
  maximumBytes,
  method,
  outboundSessionIdSha256,
  responseSessionIdSha256,
  sessionIdSha256
}) {
  return exactKeys(entry, [
    "contentType",
    "httpStatus",
    "method",
    "outboundSessionIdSha256",
    "requestBytes",
    "requestIdSha256",
    "requestPayloadSha256",
    "responseBytes",
    "responseCorrelated",
    "responseIdSha256",
    "responsePayloadSha256",
    "responseSessionIdSha256",
    "resultSha256",
    "sessionContinuous",
    "sessionIdSha256"
  ]) &&
    entry.method === method &&
    entry.httpStatus === 200 &&
    contentTypes.includes(entry.contentType) &&
    validByteCount(entry.requestBytes, maximumBytes) &&
    validByteCount(entry.responseBytes, maximumBytes) &&
    validDigest(entry.requestIdSha256) &&
    entry.requestIdSha256 === entry.responseIdSha256 &&
    validDigest(entry.requestPayloadSha256) &&
    validDigest(entry.responsePayloadSha256) &&
    validDigest(entry.resultSha256) &&
    entry.responseCorrelated === true &&
    entry.sessionContinuous === true &&
    entry.sessionIdSha256 === sessionIdSha256 &&
    entry.outboundSessionIdSha256 === outboundSessionIdSha256 &&
    responseSessionIdSha256(entry.responseSessionIdSha256);
}

export function validateIntegratedLiveDrillManagedMcpTransportEvidencePure(
  value
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_TRANSPORT_REJECTED";
  const rpcCalls = value?.rpcCalls;
  const notifications = value?.notifications;
  const close = value?.close;
  requireCondition(
    exactKeys(value, [
      "boundedResponseBytes",
      "close",
      "clusterIdSha256",
      "endpointAuthority",
      "endpointSha256",
      "notifications",
      "protocolVersion",
      "redirectPolicy",
      "rpcCalls",
      "schemaVersion",
      "sessionIdSha256"
    ]) &&
      value.schemaVersion === "tideproof.managed-mcp-transport-evidence.v2" &&
      value.endpointAuthority === "cockroachlabs.cloud" &&
      value.endpointSha256 === integratedLiveDrillSha256(
        "https://cockroachlabs.cloud/mcp"
      ) &&
      HEX_64.test(value.clusterIdSha256 ?? "") &&
      value.protocolVersion === "2025-03-26" &&
      value.redirectPolicy === "error" &&
      value.boundedResponseBytes === 256 * 1024 &&
      Array.isArray(rpcCalls) &&
      rpcCalls.length === 2 &&
      validDigest(value.sessionIdSha256) &&
      validRpcEntry(rpcCalls[0], {
        contentTypes: ["application/json", "text/event-stream"],
        maximumBytes: value.boundedResponseBytes,
        method: "initialize",
        outboundSessionIdSha256: null,
        responseSessionIdSha256: (digest) => digest === value.sessionIdSha256,
        sessionIdSha256: value.sessionIdSha256
      }) &&
      validRpcEntry(rpcCalls[1], {
        contentTypes: ["application/json", "text/event-stream"],
        maximumBytes: value.boundedResponseBytes,
        method: "tools/call",
        outboundSessionIdSha256: value.sessionIdSha256,
        responseSessionIdSha256: (digest) =>
          digest === null || digest === value.sessionIdSha256,
        sessionIdSha256: value.sessionIdSha256
      }) &&
      Array.isArray(notifications) &&
      notifications.length === 1 &&
      exactKeys(notifications[0], [
        "httpStatus",
        "method",
        "outboundSessionIdSha256",
        "requestBytes",
        "requestPayloadSha256",
        "responseSessionIdSha256",
        "sessionContinuous"
      ]) &&
      notifications[0].method === "notifications/initialized" &&
      notifications[0].sessionContinuous === true &&
      [200, 202, 204].includes(notifications[0].httpStatus) &&
      validByteCount(
        notifications[0].requestBytes,
        value.boundedResponseBytes
      ) &&
      notifications[0].requestBytes === Buffer.byteLength(
        JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
          params: {}
        }),
        "utf8"
      ) &&
      notifications[0].requestPayloadSha256 === integratedLiveDrillSha256(
        JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
          params: {}
        })
      ) &&
      exactKeys(close, [
        "attempted",
        "httpStatus",
        "outboundSessionIdSha256",
        "responseSessionIdSha256",
        "sessionContinuous"
      ]) &&
      close.attempted === true &&
      [200, 202, 204].includes(close.httpStatus) &&
      close.sessionContinuous === true &&
      close.outboundSessionIdSha256 === value.sessionIdSha256 &&
      (close.responseSessionIdSha256 === null ||
        close.responseSessionIdSha256 === value.sessionIdSha256) &&
      notifications[0].outboundSessionIdSha256 === value.sessionIdSha256 &&
      (notifications[0].responseSessionIdSha256 === null ||
        notifications[0].responseSessionIdSha256 === value.sessionIdSha256) &&
      validDigest(notifications[0].requestPayloadSha256) &&
      validDigest(notifications[0].outboundSessionIdSha256) &&
      validOptionalDigest(notifications[0].responseSessionIdSha256) &&
      validDigest(close.outboundSessionIdSha256) &&
      validOptionalDigest(close.responseSessionIdSha256),
    code
  );
  const body = Object.freeze({
    schemaVersion: "tideproof.managed-mcp-observed-transport-counts.v1",
    initializeCount: rpcCalls.filter(({ method }) => method === "initialize")
      .length,
    initializedNotificationCount: notifications.filter(
      ({ method }) => method === "notifications/initialized"
    ).length,
    toolsCallCount: rpcCalls.filter(({ method }) => method === "tools/call")
      .length,
    sessionCloseCount: close.attempted ? 1 : 0,
    sessionClosed: true,
    transportEvidenceSha256: integratedLiveDrillCanonicalSha256(value)
  });
  requireCondition(
    body.initializeCount === 1 &&
      body.initializedNotificationCount === 1 &&
      body.toolsCallCount === 1 &&
      body.sessionCloseCount === 1,
    code
  );
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export function validateIntegratedLiveDrillManagedMcpSemanticEvidencePure(
  value,
  { intent, transportEvidence }
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_SEMANTIC_REQUEST_REJECTED";
  const expectedQuery = renderRecoveryQuery({
    tenantId: intent?.tenantId,
    recoverySessionId: intent?.recoverySessionId,
    subjectBindingHash: intent?.subjectBindingSha256,
    sourceDigest: intent?.sourceDigest
  });
  const logicalRequest = Object.freeze({
    schemaVersion: "tideproof.highwater-drill-logical-managed-mcp-request.v1",
    boundInputSha256: intent?.boundInputSha256,
    databaseNameSha256: intent?.databaseNameSha256,
    queryTemplateSha256: intent?.queryTemplateSha256,
    recoveryClusterId: intent?.recoveryClusterId,
    recoverySessionId: intent?.recoverySessionId,
    renderedQuerySha256: intent?.renderedQuerySha256,
    sourceDigest: intent?.sourceDigest,
    subjectBindingSha256: intent?.subjectBindingSha256,
    tenantId: intent?.tenantId,
    toolNameSha256: intent?.toolNameSha256
  });
  const params = Object.freeze({
    name: "select_query",
    arguments: Object.freeze({
      database: "tideproof_recovery",
      query: expectedQuery
    })
  });
  const requestPayload = JSON.stringify({
    jsonrpc: "2.0",
    id: value?.requestId,
    method: "tools/call",
    params
  });
  const { evidenceSha256, ...body } = value ?? {};
  requireCondition(
    exactKeys(value, [
      "clusterId",
      "database",
      "evidenceSha256",
      "logicalMcpRequestSha256",
      "logicalRequest",
      "query",
      "requestId",
      "requestIdSha256",
      "requestParamsSha256",
      "requestPayloadSha256",
      "schemaVersion",
      "toolName"
    ]) &&
      value.schemaVersion ===
        "tideproof.managed-mcp-semantic-request-evidence.v1" &&
      value.clusterId === intent.recoveryClusterId &&
      value.database === "tideproof_recovery" &&
      value.toolName === "select_query" &&
      value.query === expectedQuery &&
      REQUEST_ID.test(value.requestId ?? "") &&
      canonicalJson(value.logicalRequest) === canonicalJson(logicalRequest) &&
      value.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256 &&
      value.logicalMcpRequestSha256 ===
        integratedLiveDrillCanonicalSha256(value.logicalRequest) &&
      value.requestIdSha256 === integratedLiveDrillSha256(value.requestId) &&
      value.requestParamsSha256 ===
        integratedLiveDrillCanonicalSha256(params) &&
      value.requestPayloadSha256 ===
        integratedLiveDrillSha256(requestPayload) &&
      value.requestIdSha256 ===
        transportEvidence?.rpcCalls?.[1]?.requestIdSha256 &&
      value.requestPayloadSha256 ===
        transportEvidence?.rpcCalls?.[1]?.requestPayloadSha256 &&
      transportEvidence?.clusterIdSha256 ===
        integratedLiveDrillSha256(intent.recoveryClusterId) &&
      evidenceSha256 === integratedLiveDrillCanonicalSha256(body),
    code
  );
  return Object.freeze({ ...value });
}

function validatePreReadArtifact(value, intent) {
  validateReceipt(
    value,
    [
      "authorizationId",
      "preCallIntentSha256",
      "preReadAuditDigest",
      "preReadAuditEventSha256",
      "preReadAuditResolutionSha256",
      "prepared",
      "preparedSha256",
      "schemaVersion"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_SCHEMA
  );
  const prepared = normalizePrepared(value.prepared, intent);
  requireCondition(
    value.authorizationId === intent.authorizationId &&
      value.preCallIntentSha256 === intent.intentSha256 &&
      value.preReadAuditDigest === prepared.preReadAuditDigest &&
      value.preparedSha256 === integratedLiveDrillCanonicalSha256(prepared) &&
      value.preReadAuditEventSha256 ===
        integratedLiveDrillCanonicalSha256(prepared.preReadAuditEvent) &&
      HEX_64.test(value.preReadAuditResolutionSha256 ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return Object.freeze({ ...value, prepared });
}

function validateProviderArtifact(value, intent, context) {
  validateReceipt(
    value,
    [
      "authorizationId",
      "logicalMcpRequestSha256",
      "mcpResultSha256",
      "observedTransportCounts",
      "providerDispatchGrantId",
      "preCallIntentSha256",
      "providerDispatchAuthorizationSha256",
      "rawResult",
      "schemaVersion",
      "semanticRequestEvidence",
      "semanticRequestEvidenceSha256",
      "sessionCloseSha256",
      "transportEvidence",
      "transportEvidenceSha256"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_RESULT_SCHEMA
  );
  const rawResult = normalizeRawResult(value.rawResult);
  const observed = validateIntegratedLiveDrillManagedMcpTransportEvidencePure(
    value.transportEvidence
  );
  const semantic = validateIntegratedLiveDrillManagedMcpSemanticEvidencePure(
    value.semanticRequestEvidence,
    { intent, transportEvidence: value.transportEvidence }
  );
  requireCondition(
    value.authorizationId === intent.authorizationId &&
      value.preCallIntentSha256 === intent.intentSha256 &&
      value.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256 &&
      HEX_64.test(context?.providerDispatchAuthorization?.attestationSha256 ?? "") &&
      value.providerDispatchAuthorizationSha256 ===
        context.providerDispatchAuthorization.attestationSha256 &&
      UUID.test(value.providerDispatchGrantId ?? "") &&
      value.mcpResultSha256 === integratedLiveDrillCanonicalSha256(rawResult) &&
      value.transportEvidence.rpcCalls[1].resultSha256 ===
        value.mcpResultSha256 &&
      value.sessionCloseSha256 ===
        integratedLiveDrillCanonicalSha256(value.transportEvidence.close) &&
      value.transportEvidenceSha256 === observed.transportEvidenceSha256 &&
      canonicalJson(value.observedTransportCounts) === canonicalJson(observed) &&
      value.semanticRequestEvidenceSha256 === semantic.evidenceSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return Object.freeze({
    ...value,
    observedTransportCounts: observed,
    rawResult,
    semanticRequestEvidence: semantic
  });
}

function validateTerminalArtifact(value, intent, preRead) {
  validateReceipt(
    value,
    [
      "authorizationId",
      "preCallIntentSha256",
      "recovery",
      "recoverySha256",
      "resultDigest",
      "schemaVersion",
      "terminalAuditDigest",
      "terminalAuditEvent",
      "terminalAuditEventSha256",
      "terminalAuditResolutionSha256"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_SCHEMA
  );
  const recovery = normalizeRecoveryResult(value.recovery);
  const event = normalizeAuditEvent(value.terminalAuditEvent);
  requireCondition(
    value.authorizationId === intent.authorizationId &&
      value.preCallIntentSha256 === intent.intentSha256 &&
      recovery.auditId === intent.terminalAuditEventId &&
      recovery.auditInteractionId === intent.interactionId &&
      recovery.preReadAuditId === intent.preReadAuditEventId &&
      recovery.preReadAuditDigest === preRead.preReadAuditDigest &&
      recovery.tenantId === intent.tenantId &&
      recovery.recoverySessionId === intent.recoverySessionId &&
      recovery.sourceDigest === intent.sourceDigest &&
      value.recoverySha256 === integratedLiveDrillCanonicalSha256(recovery) &&
      event.eventId === intent.terminalAuditEventId &&
      event.interactionId === intent.interactionId &&
      event.tenantId === intent.tenantId &&
      event.recoverySessionId === intent.recoverySessionId &&
      event.callerSubjectHash === intent.subjectBindingSha256 &&
      event.recoveryClusterId === intent.recoveryClusterId &&
      event.brokerConfigDigest === intent.recoveryBrokerConfigDigest &&
      event.queryTemplateDigest === intent.queryTemplateSha256 &&
      event.boundInputDigest === intent.boundInputSha256 &&
      event.startedAt === intent.startedAt &&
      event.phase === "terminal" &&
      value.terminalAuditDigest === recovery.auditDigest &&
      value.terminalAuditDigest === auditEventDigest(event) &&
      value.resultDigest === event.resultDigest &&
      value.terminalAuditEventSha256 ===
        integratedLiveDrillCanonicalSha256(event) &&
      HEX_64.test(value.resultDigest ?? "") &&
      HEX_64.test(value.terminalAuditResolutionSha256 ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return Object.freeze({ ...value, recovery, terminalAuditEvent: event });
}

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export function reconstructIntegratedLiveDrillProviderRecoveryHandoff(
  context
) {
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context,
    { requireDispatchAuthorization: true }
  );
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    normalizedContext.preCallIntent,
    {
      authorization: normalizedContext.authorization,
      controlLedgerReceipt: normalizedContext.controlLedgerReceipt
    }
  );
  const childAuthorizationIssuedAt =
    normalizedContext.preCallInputs.consumedChildAuthorization.attestation
      .payload.issuedAt;
  const dispatchAuthorization =
    validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
      normalizedContext.providerDispatchAuthorization,
      {
        childAuthorizationIssuedAt,
        humanAuthorizationTrustRoot:
          normalizedContext.trustedRunContext.humanAuthorizationTrustRoot,
        intent,
        requireCurrent: false
      }
    );
  const secure = secureIntegratedLiveDrillPrivateRoot(
    normalizedContext.recoveryEvidenceRootPath,
    normalizedContext.forbiddenRootPath
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    normalizedContext.evidenceRootBinding,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
  );
  const preRead = validatePreReadArtifact(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS",
      filePath: artifactPath(secure, intent.authorizationId, "pre-read"),
      secure
    }),
    intent
  );
  const provider = validateProviderArtifact(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS",
      filePath: artifactPath(secure, intent.authorizationId, "mcp"),
      secure
    }),
    intent,
    Object.freeze({ providerDispatchAuthorization: dispatchAuthorization })
  );
  const terminal = validateTerminalArtifact(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS",
      filePath: artifactPath(secure, intent.authorizationId, "terminal"),
      secure
    }),
    intent,
    preRead
  );
  const observed = provider.observedTransportCounts;
  assertIntegratedLiveDrillPrivateRootCurrent(secure);
  return withReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_HANDOFF_SCHEMA,
    authorizationId: intent.authorizationId,
    preCallIntentSha256: intent.intentSha256,
    logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
    preReadEvidenceReceiptSha256: preRead.receiptSha256,
    providerEvidenceReceiptSha256: provider.receiptSha256,
    providerDispatchAuthorizationSha256:
      provider.providerDispatchAuthorizationSha256,
    terminalEvidenceReceiptSha256: terminal.receiptSha256,
    transportEvidenceSha256: provider.transportEvidenceSha256,
    observedInitializeCount: observed.initializeCount,
    observedInitializedNotificationCount: observed.initializedNotificationCount,
    observedToolsCallCount: observed.toolsCallCount,
    observedSessionCloseCount: observed.sessionCloseCount,
    sessionClosed: observed.sessionClosed,
    preReadAuditReconciled: true,
    terminalAuditReconciled: true,
    w1W3ActualProviderPathIntegrated: true,
    runAuthorizationDirectlyBindsExactRecoveryRequest: false,
    separateExactProviderDispatchAuthorizationRequired: true,
    separateExactProviderDispatchAuthorizationValidated: true,
    postPrivateEvidenceReconciliationPathAvailable: true,
    providerBacked: false,
    accepted: false,
    finalReleaseReady: false,
    claimBoundary: INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_CLAIM_BOUNDARY
  }));
}

export function validateIntegratedLiveDrillProviderRecoveryHandoff(value) {
  requireCondition(
    exactContextRecord(value, HANDOFF_KEYS),
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED"
  );
  const normalized = Object.freeze(Object.fromEntries(
    HANDOFF_KEYS.map((key) => [
      key,
      Object.getOwnPropertyDescriptor(value, key).value
    ])
  ));
  requireCondition(
    HANDOFF_BOOLEAN_KEYS.every(
      (key) => typeof normalized[key] === "boolean"
    ) &&
      HANDOFF_COUNT_KEYS.every(
        (key) => Number.isSafeInteger(normalized[key])
      ) &&
      HANDOFF_STRING_KEYS.every(
        (key) => typeof normalized[key] === "string"
      ),
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED"
  );
  const { receiptSha256, ...body } = normalized;
  requireCondition(
    normalized.schemaVersion ===
      INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_HANDOFF_SCHEMA &&
      UUID.test(normalized.authorizationId ?? "") &&
      [
        normalized.logicalMcpRequestSha256,
        normalized.preCallIntentSha256,
        normalized.preReadEvidenceReceiptSha256,
        normalized.providerDispatchAuthorizationSha256,
        normalized.providerEvidenceReceiptSha256,
        normalized.terminalEvidenceReceiptSha256,
        normalized.transportEvidenceSha256,
        receiptSha256
      ].every((entry) => HEX_64.test(entry ?? "")) &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body) &&
      normalized.observedInitializeCount === 1 &&
      normalized.observedInitializedNotificationCount === 1 &&
      normalized.observedToolsCallCount === 1 &&
      normalized.observedSessionCloseCount === 1 &&
      normalized.sessionClosed === true &&
      normalized.preReadAuditReconciled === true &&
      normalized.terminalAuditReconciled === true &&
      normalized.w1W3ActualProviderPathIntegrated === true &&
      normalized.runAuthorizationDirectlyBindsExactRecoveryRequest === false &&
      normalized.separateExactProviderDispatchAuthorizationRequired === true &&
      normalized.separateExactProviderDispatchAuthorizationValidated === true &&
      normalized.postPrivateEvidenceReconciliationPathAvailable === true &&
      normalized.providerBacked === false &&
      normalized.accepted === false &&
      normalized.finalReleaseReady === false &&
      normalized.claimBoundary ===
        INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_CLAIM_BOUNDARY,
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED"
  );
  return normalized;
}

function artifactPath(secure, authorizationId, suffix) {
  requireCondition(
    UUID.test(authorizationId ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return path.join(
    secure.rootPath,
    `${authorizationId}.provider-recovery-${suffix}.json`
  );
}

export function validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
  attestation,
  {
    childAuthorizationIssuedAt,
    humanAuthorizationTrustRoot,
    intent,
    now = Date.now(),
    requireCurrent = true
  }
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED";
  const trustRoot = validateIntegratedLiveDrillHumanAuthorizationTrustRoot(
    humanAuthorizationTrustRoot
  );
  const payload = verifyIntegratedLiveDrillEvidence(
    attestation,
    {
      keyIdSha256: trustRoot.keyIdSha256,
      publicKeySpkiDerBase64: trustRoot.publicKeySpkiDerBase64
    },
    INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA,
    code
  );
  const issuedAt = exactIsoMilliseconds(payload?.issuedAt, code);
  const expiresAt = exactIsoMilliseconds(payload?.expiresAt, code);
  const childIssuedAt = exactIsoMilliseconds(
    childAuthorizationIssuedAt,
    code
  );
  const payloadChildIssuedAt = exactIsoMilliseconds(
    payload?.childAuthorizationIssuedAt,
    code
  );
  const intentStartedAt = exactIsoMilliseconds(intent?.startedAt, code);
  const runExpiresAt = exactIsoMilliseconds(intent?.expiresAt, code);
  requireCondition(
    exactKeys(payload, [
      "auditTargetIdentitySha256",
      "authorityStatement",
      "authorizationAttestationSha256",
      "authorizationId",
      "childAuthorizationIssuedAt",
      "expiresAt",
      "issuedAt",
      "logicalMcpRequestSha256",
      "maximumInitializeCount",
      "maximumInitializedNotificationCount",
      "maximumManagedMcpToolCallCount",
      "preCallIntentSha256",
      "requiredSessionCloseCount",
      "requiredToolsCallCount",
      "recoveryBrokerConfigDigest",
      "runId",
      "schemaVersion"
    ]) &&
      payload.authorityStatement ===
        INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT &&
      payload.auditTargetIdentitySha256 ===
        intent.auditTargetIdentitySha256 &&
      payload.authorizationAttestationSha256 ===
        intent.authorizationAttestationSha256 &&
      payload.authorizationId === intent.authorizationId &&
      payload.runId === intent.runId &&
      payload.preCallIntentSha256 === intent.intentSha256 &&
      payload.recoveryBrokerConfigDigest ===
        intent.recoveryBrokerConfigDigest &&
      payload.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256 &&
      payload.maximumInitializeCount === 1 &&
      payload.maximumInitializedNotificationCount === 1 &&
      payload.maximumManagedMcpToolCallCount === 1 &&
      payload.requiredToolsCallCount === 1 &&
      payload.requiredSessionCloseCount === 1 &&
      payloadChildIssuedAt === childIssuedAt &&
      intentStartedAt <= issuedAt &&
      childIssuedAt <= issuedAt &&
      issuedAt < expiresAt &&
      expiresAt <= issuedAt + MAX_PROVIDER_DISPATCH_AUTHORIZATION_MS &&
      (!requireCurrent || (issuedAt <= now && now < expiresAt)) &&
      expiresAt <= runExpiresAt,
    code
  );
  return Object.freeze({
    attestationSha256: integratedLiveDrillCanonicalSha256(attestation),
    payload: Object.freeze({ ...payload })
  });
}

export function verifyIntegratedLiveDrillProviderEvidenceBundle(value) {
  requireCondition(
    exactContextRecord(value, ["context", "providerContinuity"]) ||
      exactContextRecord(value, [
        "context",
        "providerContinuity",
        "requireCompleteJournal"
      ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_JOURNAL_BINDING_REJECTED"
  );
  const { context, providerContinuity } = value;
  const requireCompleteJournal = Object.hasOwn(
    value,
    "requireCompleteJournal"
  )
    ? value.requireCompleteJournal
    : true;
  requireCondition(
    typeof requireCompleteJournal === "boolean",
    "INTEGRATED_LIVE_DRILL_PROVIDER_JOURNAL_BINDING_REJECTED"
  );
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context
  );
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    normalizedContext.preCallIntent,
    {
      authorization: normalizedContext.authorization,
      controlLedgerReceipt: normalizedContext.controlLedgerReceipt
    }
  );
  const reported = validateIntegratedLiveDrillProviderRecoveryHandoff(
    providerContinuity
  );
  const dispatchAuthorization =
    validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
      normalizedContext.providerDispatchAuthorization,
      {
        childAuthorizationIssuedAt:
          normalizedContext.preCallInputs.consumedChildAuthorization.attestation
            .payload.issuedAt,
        humanAuthorizationTrustRoot:
          normalizedContext.trustedRunContext.humanAuthorizationTrustRoot,
        intent,
        requireCurrent: false
      }
    );
  const secure = secureIntegratedLiveDrillPrivateRoot(
    normalizedContext.recoveryEvidenceRootPath,
    normalizedContext.forbiddenRootPath
  );
  const preRead = validatePreReadArtifact(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS",
      filePath: artifactPath(secure, intent.authorizationId, "pre-read"),
      secure
    }),
    intent
  );
  const provider = validateProviderArtifact(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS",
      filePath: artifactPath(secure, intent.authorizationId, "mcp"),
      secure
    }),
    intent,
    Object.freeze({
      providerDispatchAuthorization: dispatchAuthorization
    })
  );
  const terminal = validateTerminalArtifact(
    readIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS",
      filePath: artifactPath(secure, intent.authorizationId, "terminal"),
      secure
    }),
    intent,
    preRead
  );
  const observed = provider.observedTransportCounts;
  const recomputed = reconstructIntegratedLiveDrillProviderRecoveryHandoff(
    normalizedContext
  );
  requireCondition(
    canonicalJson(recomputed) === canonicalJson(reported),
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_BINDING_REJECTED"
  );
  const journal = requireCompleteJournal
    ? validateIntegratedLiveDrillRecoveryContinuityJournal(normalizedContext)
    : inspectIntegratedLiveDrillRecoveryContinuity(normalizedContext);
  requireCondition(
    journal.status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE &&
      (!requireCompleteJournal ||
        (journal.authorizationId === intent.authorizationId &&
          journal.preCallIntentSha256 === intent.intentSha256 &&
          journal.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256)) &&
      journal.mcpResultSha256 === provider.mcpResultSha256 &&
      journal.sessionCloseSha256 === provider.sessionCloseSha256 &&
      journal.sessionClosed === observed.sessionClosed,
    "INTEGRATED_LIVE_DRILL_PROVIDER_JOURNAL_BINDING_REJECTED"
  );
  assertIntegratedLiveDrillPrivateRootCurrent(secure);
  return Object.freeze({
    handoff: recomputed,
    intent,
    journal,
    preRead,
    provider,
    terminal
  });
}
