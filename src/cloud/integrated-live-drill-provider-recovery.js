import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import { parseStrictJson } from "./strict-json.js";
import {
  assertIntegratedLiveDrillPrivateRootMatchesBinding,
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_CLAIM_BOUNDARY,
  normalizeIntegratedLiveDrillProviderContext,
  secureIntegratedLiveDrillPrivateRoot,
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "./integrated-live-drill-provider-evidence.js";
import {
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillSha256
} from "./integrated-live-drill-authorization.js";
import {
  recoveryAuditEventDigest,
  renderRecoveryQuery
} from "./recovery-continuity-identity.js";
import {
  buildProviderDispatchControlBinding,
  PROVIDER_DISPATCH_CONTROL_STATES
} from "./provider-dispatch-control.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
  runIntegratedLiveDrillRecoveryContinuityW1,
  runIntegratedLiveDrillRecoveryContinuityW2,
  runIntegratedLiveDrillRecoveryContinuityW3,
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_HANDOFF_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-handoff.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-pre-read.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_PLAN_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-pre-read-plan.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_RESULT_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-result.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-terminal.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_PLAN_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-terminal-plan.v1";
export { INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA } from
  "./integrated-live-drill-provider-evidence.js";
export const INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_PREPARATION_SCHEMA =
  "tideproof.highwater-drill-provider-dispatch-preparation.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_EXPIRY_BURN_SCHEMA =
  "tideproof.highwater-drill-provider-expiry-burn.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AWAITING_AUTHORIZATION =
  "AWAITING_AUTHORIZATION";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const REQUEST_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[1-9][0-9]*$/u;
const MAX_PRIVATE_ARTIFACT_BYTES = 1024 * 1024;
const MAX_PROVIDER_DISPATCH_AUTHORIZATION_MS = 15 * 60 * 1_000;
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
const PREPARED_RECOVERY_COMPLETION_KEYS = Object.freeze([
  "preparedSha256",
  "rawResultSha256",
  "recovery",
  "resultDigest",
  "schemaVersion",
  "sourceWatermark",
  "terminalAuditDigest",
  "terminalAuditEvent"
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
const PROCESS_STICKY_PROVIDER_AUTHORITY_BURNS = new Set();

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const ownKeys = Object.keys(value);
  return ownKeys.length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function exactIsoMilliseconds(value, code) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  requireCondition(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    code
  );
  return milliseconds;
}

function validateProviderRecoveryContext(
  context,
  { requireDispatchAuthorization }
) {
  return normalizeIntegratedLiveDrillProviderContext(context, {
    requireDispatchAuthorization
  }).preCallInputs;
}

function childAuthorizationIssuedAtFromNormalizedInputs(
  normalizedPreCallInputs,
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_CONTEXT_REJECTED"
) {
  return exactIsoMilliseconds(
    normalizedPreCallInputs?.consumedChildAuthorization?.attestation?.payload
      ?.issuedAt,
    code
  );
}

export function integratedLiveDrillProviderDispatchAuthorizationPayload({
  intent,
  childAuthorizationIssuedAt,
  issuedAt,
  expiresAt
}) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED";
  const childIssued = exactIsoMilliseconds(childAuthorizationIssuedAt, code);
  const issued = exactIsoMilliseconds(issuedAt, code);
  const expires = exactIsoMilliseconds(expiresAt, code);
  const intentStarted = exactIsoMilliseconds(intent?.startedAt, code);
  requireCondition(
    intentStarted <= issued &&
      childIssued <= issued &&
      issued < expires &&
      expires <= issued + MAX_PROVIDER_DISPATCH_AUTHORIZATION_MS &&
      expires <= exactIsoMilliseconds(intent?.expiresAt, code),
    code
  );
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA,
    auditTargetIdentitySha256: intent.auditTargetIdentitySha256,
    authorityStatement:
      INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
    authorizationAttestationSha256: intent.authorizationAttestationSha256,
    authorizationId: intent.authorizationId,
    childAuthorizationIssuedAt,
    expiresAt,
    issuedAt,
    logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
    maximumInitializeCount: 1,
    maximumInitializedNotificationCount: 1,
    maximumManagedMcpToolCallCount: 1,
    requiredSessionCloseCount: 1,
    requiredToolsCallCount: 1,
    preCallIntentSha256: intent.intentSha256,
    recoveryBrokerConfigDigest: intent.recoveryBrokerConfigDigest,
    runId: intent.runId
  });
}

export function validateIntegratedLiveDrillProviderDispatchAuthorization(
  attestation,
  options
) {
  return validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    attestation,
    options
  );
}

function providerDispatchGuard(context, intent, clock = () => Date.now()) {
  requireCondition(
    typeof clock === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
  );
  const secure = secureEvidenceRoot(
    context.recoveryEvidenceRootPath,
    context.forbiddenRootPath
  );
  const normalizedPreCallInputs = validateProviderRecoveryContext(context, {
    requireDispatchAuthorization: true
  });
  const childAuthorizationIssuedAt =
    childAuthorizationIssuedAtFromNormalizedInputs(
      normalizedPreCallInputs,
      "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
    );
  const dispatchAuthorization =
    validateIntegratedLiveDrillProviderDispatchAuthorization(
      context.providerDispatchAuthorization,
      {
        humanAuthorizationTrustRoot:
          context.trustedRunContext.humanAuthorizationTrustRoot,
        childAuthorizationIssuedAt:
          new Date(childAuthorizationIssuedAt).toISOString(),
        intent,
        requireCurrent: false
      }
    );
  const authorityTimes = providerAuthorityTimes(
    context,
    intent,
    dispatchAuthorization,
    childAuthorizationIssuedAt
  );
  const burnPath = providerAuthorityExpiryBurnPath(
    secure,
    intent.authorizationId
  );
  const burnBody = providerAuthorityExpiryBurnBody(
    context,
    intent,
    dispatchAuthorization,
    childAuthorizationIssuedAt
  );
  const stickyBurnKey = providerAuthorityProcessStickyBurnKey(
    burnPath,
    burnBody
  );
  return () => {
    if (PROCESS_STICKY_PROVIDER_AUTHORITY_BURNS.has(stickyBurnKey)) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
      );
    }
    const existingBurn = readArtifactIfPresent(burnPath, secure);
    if (existingBurn !== null) {
      validateProviderAuthorityExpiryBurn(
        existingBurn,
        context,
        intent,
        dispatchAuthorization,
        childAuthorizationIssuedAt
      );
      PROCESS_STICKY_PROVIDER_AUTHORITY_BURNS.add(stickyBurnKey);
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
      );
    }
    const now = clock();
    if (
      Number.isSafeInteger(now) &&
      now >= authorityTimes.earliestControllingExpiry
    ) {
      PROCESS_STICKY_PROVIDER_AUTHORITY_BURNS.add(stickyBurnKey);
      try {
        validateProviderAuthorityExpiryBurn(
          createOrReadExact(
            burnPath,
            withReceipt(burnBody),
            secure
          ),
          context,
          intent,
          dispatchAuthorization,
          childAuthorizationIssuedAt
        );
      } catch (cause) {
        reject(
          "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED",
          cause
        );
      }
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
      );
    }
    requireCondition(
      Number.isSafeInteger(now) &&
        now >= authorityTimes.latestControllingIssuedAt &&
        recoveryWorkerAuthorityIsCurrent(context, now),
      "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
    );
    try {
      return validateIntegratedLiveDrillProviderDispatchAuthorization(
        context.providerDispatchAuthorization,
        {
          humanAuthorizationTrustRoot:
            context.trustedRunContext.humanAuthorizationTrustRoot,
          childAuthorizationIssuedAt:
            new Date(childAuthorizationIssuedAt).toISOString(),
          intent,
          now
        }
      );
    } catch (cause) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED",
        cause
      );
    }
  };
}

function recoveryWorkerAuthorityIsCurrent(context, now = Date.now()) {
  const childIssuedAt = Date.parse(
    context?.preCallInputs?.consumedChildAuthorization?.attestation?.payload
      ?.issuedAt
  );
  const childExpiresAt = Date.parse(
    context?.preCallIntent?.childAuthorizationExpiresAt
  );
  const runExpiresAt = Date.parse(context?.preCallIntent?.expiresAt);
  return Number.isSafeInteger(now) &&
    Number.isSafeInteger(context?.authorization?.issuedAt) &&
    Number.isSafeInteger(context?.authorization?.expiresAt) &&
    Number.isFinite(childIssuedAt) &&
    Number.isFinite(childExpiresAt) &&
    Number.isFinite(runExpiresAt) &&
    now >= context.authorization.issuedAt &&
    now >= childIssuedAt &&
    now < context.authorization.expiresAt &&
    now < childExpiresAt &&
    now < runExpiresAt;
}

function providerExternalActionAuthorityIsCurrent(context, intent, clock) {
  try {
    providerDispatchGuard(context, intent, clock)();
    return true;
  } catch (cause) {
    if (
      cause?.message ===
        "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
    ) {
      return false;
    }
    throw cause;
  }
}

const POST_PROVIDER_AUDIT_ACTIONS = new Set([
  "AFTER_TERMINAL_AUDIT_COMMIT",
  "AUDIT_APPEND",
  "AUDIT_APPEND_BEGIN",
  "AUDIT_APPEND_COMMIT",
  "AUDIT_APPEND_CONNECT",
  "AUDIT_APPEND_DATABASE_CLOCK",
  "AUDIT_RESOLVE_CONNECT",
  "AUDIT_RESOLVE_DISPATCH",
  "AUDIT_RESOLVE_QUERY",
  "POST_PROVIDER_AUDIT_AUTHORITY",
  "TERMINAL_AUDIT_APPEND"
]);

async function postProviderAuditGuard({
  assertProviderAdmission,
  providerControlIsTerminal
}) {
  requireCondition(
    typeof providerControlIsTerminal === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_POST_PROVIDER_AUDIT_GUARD_REJECTED"
  );
  assertProviderAdmission?.();
  const terminal = await providerControlIsTerminal();
  requireCondition(
    terminal === true,
    "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED"
  );
  const auditAuthority = Object.freeze({
    auditOnly: true,
    authoritySource: "DURABLE_PROVIDER_CONTROL_COMPLETION",
    providerActionAuthorized: false
  });
  return (action) => {
    assertProviderAdmission?.();
    requireCondition(
      POST_PROVIDER_AUDIT_ACTIONS.has(action),
      "INTEGRATED_LIVE_DRILL_PROVIDER_POST_PROVIDER_ACTION_REJECTED"
    );
    return auditAuthority;
  };
}

function requirePostProviderAuditAuthority(actionGuard, action) {
  try {
    return actionGuard(action ?? "POST_PROVIDER_AUDIT_AUTHORITY");
  } catch (cause) {
    if (
      cause?.message ===
        "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
    ) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_AUDIT_AUTHORIZATION_REQUIRED",
        cause
      );
    }
    throw cause;
  }
}

function secureEvidenceRoot(rootPath, forbiddenRootPath) {
  return secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_REJECTED"
  );
}

function assertSameRoot(secure) {
  let current;
  try {
    current = fs.lstatSync(secure.rootPath);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_DRIFT", cause);
  }
  requireCondition(
    current.isDirectory() &&
      !current.isSymbolicLink() &&
      current.dev === secure.stat.dev &&
      current.ino === secure.stat.ino &&
      current.uid === secure.expectedUid &&
      (current.mode & 0o777) === 0o700,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_DRIFT"
  );
}

function syncDirectory(secure) {
  let descriptor;
  try {
    assertSameRoot(secure);
    descriptor = fs.openSync(
      secure.rootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const opened = fs.fstatSync(descriptor);
    requireCondition(
      opened.dev === secure.stat.dev &&
        opened.ino === secure.stat.ino &&
        opened.uid === secure.expectedUid &&
        (opened.mode & 0o777) === 0o700,
      "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_DRIFT"
    );
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readArtifact(filePath, secure) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS";
  let descriptor;
  try {
    assertSameRoot(secure);
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
        before.size <= MAX_PRIVATE_ARTIFACT_BYTES,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      after.isFile() &&
        after.uid === secure.expectedUid &&
        after.nlink === 1 &&
        (after.mode & 0o777) === 0o600 &&
        after.size > 0 &&
        after.size <= MAX_PRIVATE_ARTIFACT_BYTES &&
        bytes.length === after.size &&
        before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        before.uid === after.uid &&
        before.nlink === after.nlink &&
        (before.mode & 0o777) === (after.mode & 0o777) &&
        named.isFile() &&
        named.dev === after.dev &&
        named.ino === after.ino &&
        named.uid === after.uid &&
        named.nlink === 1 &&
        (named.mode & 0o777) === 0o600 &&
        named.size === after.size &&
        !named.isSymbolicLink(),
      code
    );
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(
      bytes.equals(Buffer.from(`${canonicalJson(value)}\n`, "utf8")),
      code
    );
    assertSameRoot(secure);
    return value;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readArtifactIfPresent(filePath, secure) {
  try {
    return readArtifact(filePath, secure);
  } catch (cause) {
    if (cause?.cause?.code === "ENOENT") return null;
    throw cause;
  }
}

function createOrReadExact(filePath, value, secure) {
  const serialized = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(
    serialized.length > 0 && serialized.length <= MAX_PRIVATE_ARTIFACT_BYTES,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED"
  );
  let descriptor;
  try {
    assertSameRoot(secure);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    fs.writeFileSync(descriptor, serialized);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    syncDirectory(secure);
  } catch (cause) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve first error. */ }
    }
    if (cause?.code !== "EEXIST") {
      if (cause?.message?.startsWith("INTEGRATED_LIVE_DRILL_")) throw cause;
      reject("INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_WRITE_REJECTED", cause);
    }
  }
  const reread = readArtifact(filePath, secure);
  requireCondition(
    canonicalJson(reread) === canonicalJson(value),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_AMBIGUOUS"
  );
  return reread;
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

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
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
  return value;
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

function normalizeExactPersistedRecord(value, keys, nested = {}) {
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

function normalizeRecoveryAuditEvent(value) {
  return normalizeExactPersistedRecord(value, RECOVERY_AUDIT_EVENT_KEYS);
}

function normalizePreparedRecoveryArtifact(value) {
  return normalizeExactPersistedRecord(value, PREPARED_RECOVERY_KEYS, {
    preReadAuditEvent: normalizeRecoveryAuditEvent
  });
}

function validatePreparedRecoveryArtifact(value, intent) {
  const prepared = normalizePreparedRecoveryArtifact(value);
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
      prepared.preReadAuditDigest === recoveryAuditEventDigest(event),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return prepared;
}

function normalizeRecoveryResultArtifact(value) {
  const normalized = normalizeExactPersistedRecord(
    value,
    RECOVERY_RESULT_KEYS,
    {
      context: (context) => normalizeExactPersistedRecord(
        context,
        ["checkpoint", "conflicts", "evidence", "receipt"],
        {
          checkpoint: (checkpoint) => normalizeExactPersistedRecord(
            checkpoint,
            ["checkpointVersion", "failedAgent", "phase", "scenario"]
          ),
          conflicts: (conflicts) => normalizeExactPersistedRecord(
            conflicts,
            ["status", "unresolvedCount"]
          ),
          evidence: (evidence) => normalizeExactPersistedRecord(
            evidence,
            ["admittedCount", "classification", "evidenceDigest"]
          ),
          receipt: (receipt) => normalizeExactPersistedRecord(
            receipt,
            ["durableIntentPresent", "outcome", "reason", "resourceLabel"]
          )
        }
      )
    }
  );
  requireCondition(
    normalized.status === "RECOVERED_CONTEXT_ONLY" &&
      normalized.authorityTransferred === false &&
      normalized.requiresFreshAuthorization === true &&
      UUID.test(normalized.auditId ?? "") &&
      UUID.test(normalized.auditInteractionId ?? "") &&
      UUID.test(normalized.preReadAuditId ?? "") &&
      UUID.test(normalized.recoverySessionId ?? "") &&
      UUID.test(normalized.tenantId ?? "") &&
      HEX_64.test(normalized.auditDigest ?? "") &&
      HEX_64.test(normalized.preReadAuditDigest ?? "") &&
      HEX_64.test(normalized.sourceDigest ?? "") &&
      HEX_64.test(normalized.bundleDigest ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
}

function normalizePreparedRecoveryCompletion(value) {
  return normalizeExactPersistedRecord(
    value,
    PREPARED_RECOVERY_COMPLETION_KEYS,
    {
      recovery: normalizeRecoveryResultArtifact,
      terminalAuditEvent: normalizeRecoveryAuditEvent
    }
  );
}

function normalizeRecoveryRowArtifact(value) {
  const normalized = normalizeExactPersistedRecord(value, RECOVERY_ROW_KEYS);
  requireCondition(
    normalized.authority_transferred === false &&
      normalized.requires_fresh_authorization === true,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
}

function normalizeManagedMcpRawResult(value) {
  if (exactKeys(value, ["rows"])) {
    requireCondition(
      Array.isArray(value.rows) && value.rows.length === 1,
      "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
    );
    return Object.freeze({
      rows: Object.freeze(value.rows.map(normalizeRecoveryRowArtifact))
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
    reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED",
      cause
    );
  }
  requireCondition(
    exactKeys(parsed, ["rows"]) &&
      Array.isArray(parsed.rows) &&
      parsed.rows.length === 1,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  parsed.rows.map(normalizeRecoveryRowArtifact);
  return Object.freeze({
    content: Object.freeze([Object.freeze({
      type: "text",
      text: value.content[0].text
    })])
  });
}

function providerAuthorityTimes(
  context,
  intent,
  dispatchAuthorization,
  childAuthorizationIssuedAt
) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED";
  const authorizationIssuedAt = context?.authorization?.issuedAt;
  const authorizationExpiresAt = context?.authorization?.expiresAt;
  requireCondition(
    Number.isSafeInteger(authorizationIssuedAt) &&
      Number.isSafeInteger(authorizationExpiresAt) &&
      authorizationIssuedAt < authorizationExpiresAt,
    code
  );
  const childExpiresAt = exactIsoMilliseconds(
    intent?.childAuthorizationExpiresAt,
    code
  );
  requireCondition(
    Number.isSafeInteger(childAuthorizationIssuedAt),
    code
  );
  const intentStartedAt = exactIsoMilliseconds(intent?.startedAt, code);
  const intentExpiresAt = exactIsoMilliseconds(intent?.expiresAt, code);
  const dispatchIssuedAt = exactIsoMilliseconds(
    dispatchAuthorization?.payload?.issuedAt,
    code
  );
  const dispatchExpiresAt = exactIsoMilliseconds(
    dispatchAuthorization?.payload?.expiresAt,
    code
  );
  const earliestControllingExpiry = Math.min(
    authorizationExpiresAt,
    childExpiresAt,
    intentExpiresAt,
    dispatchExpiresAt
  );
  const latestControllingIssuedAt = Math.max(
    authorizationIssuedAt,
    childAuthorizationIssuedAt,
    intentStartedAt,
    dispatchIssuedAt
  );
  requireCondition(
    Number.isSafeInteger(earliestControllingExpiry) &&
      Number.isSafeInteger(latestControllingIssuedAt) &&
      latestControllingIssuedAt < earliestControllingExpiry,
    code
  );
  return Object.freeze({
    controllingExpiries: Object.freeze({
      childAuthorizationExpiresAt: new Date(childExpiresAt).toISOString(),
      humanAuthorizationExpiresAt:
        new Date(authorizationExpiresAt).toISOString(),
      preCallIntentExpiresAt: new Date(intentExpiresAt).toISOString(),
      providerDispatchAuthorizationExpiresAt:
        new Date(dispatchExpiresAt).toISOString()
    }),
    controllingIssuedAts: Object.freeze({
      childAuthorizationIssuedAt:
        new Date(childAuthorizationIssuedAt).toISOString(),
      humanAuthorizationIssuedAt:
        new Date(authorizationIssuedAt).toISOString(),
      preCallIntentStartedAt: new Date(intentStartedAt).toISOString(),
      providerDispatchAuthorizationIssuedAt:
        new Date(dispatchIssuedAt).toISOString()
    }),
    earliestControllingExpiry,
    latestControllingIssuedAt
  });
}

function providerAuthorityExpiryBurnBody(
  context,
  intent,
  dispatchAuthorization,
  childAuthorizationIssuedAt
) {
  const authorityTimes = providerAuthorityTimes(
    context,
    intent,
    dispatchAuthorization,
    childAuthorizationIssuedAt
  );
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_EXPIRY_BURN_SCHEMA,
    accepted: false,
    authorizationAttestationSha256: intent.authorizationAttestationSha256,
    authorizationId: intent.authorizationId,
    burnedAtControllingExpiry:
      new Date(authorityTimes.earliestControllingExpiry).toISOString(),
    clockRollbackCanReactivateAfterDurableBurn: false,
    controllingExpiries: authorityTimes.controllingExpiries,
    controllingIssuedAts: authorityTimes.controllingIssuedAts,
    failedBurnPersistenceRequiresRunAbandonment: true,
    finalReleaseReady: false,
    preCallIntentSha256: intent.intentSha256,
    providerBacked: false,
    providerDispatchAuthorizationSha256:
      dispatchAuthorization.attestationSha256,
    processRestartSafetyAfterFailedPersistenceProven: false,
    processStickyBurnPrecedesPersistenceAttempt: true,
    retryPermitted: false,
    runId: intent.runId,
    status: "BURNED_EXPIRED"
  });
}

function providerAuthorityExpiryBurnPath(secure, authorizationId) {
  return artifactPath(secure, authorizationId, "authority-expiry-burn");
}

function providerAuthorityProcessStickyBurnKey(burnPath, burnBody) {
  return integratedLiveDrillCanonicalSha256({
    burnArtifactPathSha256: integratedLiveDrillSha256(burnPath),
    burnBodySha256: integratedLiveDrillCanonicalSha256(burnBody)
  });
}

function validateProviderAuthorityExpiryBurn(
  value,
  context,
  intent,
  dispatchAuthorization,
  childAuthorizationIssuedAt
) {
  validateReceipt(
    value,
    [
      "accepted",
      "authorizationAttestationSha256",
      "authorizationId",
      "burnedAtControllingExpiry",
      "clockRollbackCanReactivateAfterDurableBurn",
      "controllingExpiries",
      "controllingIssuedAts",
      "failedBurnPersistenceRequiresRunAbandonment",
      "finalReleaseReady",
      "preCallIntentSha256",
      "providerBacked",
      "providerDispatchAuthorizationSha256",
      "processRestartSafetyAfterFailedPersistenceProven",
      "processStickyBurnPrecedesPersistenceAttempt",
      "retryPermitted",
      "runId",
      "schemaVersion",
      "status"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_EXPIRY_BURN_SCHEMA
  );
  const expected = withReceipt(
    providerAuthorityExpiryBurnBody(
      context,
      intent,
      dispatchAuthorization,
      childAuthorizationIssuedAt
    )
  );
  requireCondition(
    canonicalJson(value) === canonicalJson(expected),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return expected;
}

function validateDispatchPreparation(value, context) {
  const normalizedPreCallInputs = validateProviderRecoveryContext(context, {
    requireDispatchAuthorization:
      Object.hasOwn(context, "providerDispatchAuthorization")
  });
  validateReceipt(
    value,
    [
      "accepted",
      "authorizationId",
      "claimBoundary",
      "createdAt",
      "dedicatedCredentialFieldAcceptedOrPersisted",
      "expiresAt",
      "finalReleaseReady",
      "humanPrivateKeyRequired",
      "humanSignatureProducedOutsidePreparationApi",
      "humanAuthorizationTrustRootSha256",
      "preCallInputs",
      "preCallInputsSha256",
      "preCallIntent",
      "preCallIntentSha256",
      "providerBacked",
      "runId",
      "schemaVersion",
      "signingPayload",
      "signingPayloadSha256",
      "status",
      "preparationContextStrictlyAllowlisted"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_PREPARATION_SCHEMA
  );
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    value.preCallIntent,
    {
      authorization: context?.authorization,
      controlLedgerReceipt: context?.controlLedgerReceipt
    }
  );
  const expectedPayload =
    integratedLiveDrillProviderDispatchAuthorizationPayload({
      childAuthorizationIssuedAt:
        normalizedPreCallInputs.consumedChildAuthorization.attestation.payload
          .issuedAt,
      intent,
      issuedAt: value.createdAt,
      expiresAt: value.expiresAt
    });
  const normalized = Object.freeze({
    accepted: value.accepted,
    authorizationId: value.authorizationId,
    claimBoundary: value.claimBoundary,
    createdAt: value.createdAt,
    dedicatedCredentialFieldAcceptedOrPersisted:
      value.dedicatedCredentialFieldAcceptedOrPersisted,
    expiresAt: value.expiresAt,
    finalReleaseReady: value.finalReleaseReady,
    humanAuthorizationTrustRootSha256:
      value.humanAuthorizationTrustRootSha256,
    humanPrivateKeyRequired: value.humanPrivateKeyRequired,
    humanSignatureProducedOutsidePreparationApi:
      value.humanSignatureProducedOutsidePreparationApi,
    preCallInputs: normalizedPreCallInputs,
    preCallInputsSha256: value.preCallInputsSha256,
    preCallIntent: intent,
    preCallIntentSha256: value.preCallIntentSha256,
    preparationContextStrictlyAllowlisted:
      value.preparationContextStrictlyAllowlisted,
    providerBacked: value.providerBacked,
    receiptSha256: value.receiptSha256,
    runId: value.runId,
    schemaVersion: value.schemaVersion,
    signingPayload: expectedPayload,
    signingPayloadSha256: value.signingPayloadSha256,
    status: value.status
  });
  requireCondition(
    canonicalJson(normalized) === canonicalJson(value) &&
      value.status ===
        INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AWAITING_AUTHORIZATION &&
      value.authorizationId === intent.authorizationId &&
      value.runId === intent.runId &&
      value.createdAt === value.signingPayload?.issuedAt &&
      value.expiresAt === value.signingPayload?.expiresAt &&
      value.preCallIntentSha256 === intent.intentSha256 &&
      canonicalJson(value.preCallIntent) === canonicalJson(intent) &&
      canonicalJson(context?.preCallIntent) === canonicalJson(intent) &&
      value.preCallInputsSha256 ===
        integratedLiveDrillCanonicalSha256(value.preCallInputs) &&
      canonicalJson(value.preCallInputs) ===
        canonicalJson(normalizedPreCallInputs) &&
      value.signingPayloadSha256 ===
        integratedLiveDrillCanonicalSha256(value.signingPayload) &&
      canonicalJson(value.signingPayload) === canonicalJson(expectedPayload) &&
      value.humanAuthorizationTrustRootSha256 ===
        integratedLiveDrillCanonicalSha256(
          context?.trustedRunContext?.humanAuthorizationTrustRoot
        ) &&
      value.dedicatedCredentialFieldAcceptedOrPersisted === false &&
      value.humanPrivateKeyRequired === false &&
      value.humanSignatureProducedOutsidePreparationApi === true &&
      value.preparationContextStrictlyAllowlisted === true &&
      value.providerBacked === false &&
      value.accepted === false &&
      value.finalReleaseReady === false &&
      value.claimBoundary ===
        "B2a recursively allowlists and freshly reconstructs every exact pre-call input schema, requires canonical equality with the caller input, rejects recognizable credential text as defense in depth, and persists only that normalized object plus the exact dispatch-signing payload before any Managed MCP client is required. Its preparation API exposes no dedicated credential or private-key field, requires no human private key, and produces no human signature; a separate human-held private key must sign those exact bytes outside this API. Arbitrary allowed text is not claimed to be a complete secret classifier. Gate1/Gate2 PREPARE/HOLD/RESUME is source-wired and locally tested, but it has not been deployed or executed against the live provider; copied-ledger and cross-host authority, live provider continuity, finalization, acceptance, and release remain unproven.",
    "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_PREPARATION_REJECTED"
  );
  return normalized;
}

export function prepareIntegratedLiveDrillProviderRecoveryAuthorization({
  context,
  issuedAt = new Date().toISOString(),
  expiresAt
}) {
  const normalizedPreCallInputs = validateProviderRecoveryContext(context, {
    requireDispatchAuthorization: false
  });
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    context?.preCallIntent,
    {
      authorization: context?.authorization,
      controlLedgerReceipt: context?.controlLedgerReceipt
    }
  );
  const secure = secureEvidenceRoot(
    context.recoveryEvidenceRootPath,
    context.forbiddenRootPath
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    context.evidenceRootBinding,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
  );
  const resolvedExpiresAt = expiresAt ?? new Date(Math.min(
    exactIsoMilliseconds(
      context.preCallIntent.expiresAt,
      "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_PREPARATION_REJECTED"
    ),
    exactIsoMilliseconds(
      issuedAt,
      "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_PREPARATION_REJECTED"
    ) + MAX_PROVIDER_DISPATCH_AUTHORIZATION_MS
  )).toISOString();
  const signingPayload =
    integratedLiveDrillProviderDispatchAuthorizationPayload({
      childAuthorizationIssuedAt:
        normalizedPreCallInputs.consumedChildAuthorization.attestation.payload
          .issuedAt,
      intent,
      issuedAt,
      expiresAt: resolvedExpiresAt
    });
  const body = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_PREPARATION_SCHEMA,
    accepted: false,
    authorizationId: intent.authorizationId,
    claimBoundary:
      "B2a recursively allowlists and freshly reconstructs every exact pre-call input schema, requires canonical equality with the caller input, rejects recognizable credential text as defense in depth, and persists only that normalized object plus the exact dispatch-signing payload before any Managed MCP client is required. Its preparation API exposes no dedicated credential or private-key field, requires no human private key, and produces no human signature; a separate human-held private key must sign those exact bytes outside this API. Arbitrary allowed text is not claimed to be a complete secret classifier. Gate1/Gate2 PREPARE/HOLD/RESUME is source-wired and locally tested, but it has not been deployed or executed against the live provider; copied-ledger and cross-host authority, live provider continuity, finalization, acceptance, and release remain unproven.",
    createdAt: signingPayload.issuedAt,
    dedicatedCredentialFieldAcceptedOrPersisted: false,
    expiresAt: signingPayload.expiresAt,
    finalReleaseReady: false,
    humanPrivateKeyRequired: false,
    humanSignatureProducedOutsidePreparationApi: true,
    humanAuthorizationTrustRootSha256:
      integratedLiveDrillCanonicalSha256(
        context.trustedRunContext.humanAuthorizationTrustRoot
      ),
    preCallInputs: normalizedPreCallInputs,
    preCallInputsSha256:
      integratedLiveDrillCanonicalSha256(normalizedPreCallInputs),
    preCallIntent: intent,
    preCallIntentSha256: intent.intentSha256,
    providerBacked: false,
    runId: intent.runId,
    signingPayload,
    signingPayloadSha256:
      integratedLiveDrillCanonicalSha256(signingPayload),
    status: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AWAITING_AUTHORIZATION,
    preparationContextStrictlyAllowlisted: true
  });
  const preparation = validateDispatchPreparation(
    createOrReadExact(
      artifactPath(secure, intent.authorizationId, "dispatch-preparation"),
      withReceipt(body),
      secure
    ),
    context
  );
  return Object.freeze({
    accepted: false,
    dedicatedCredentialFieldAcceptedOrPersisted: false,
    finalReleaseReady: false,
    humanPrivateKeyRequired: false,
    humanSignatureProducedOutsidePreparationApi: true,
    preparationReceiptSha256: preparation.receiptSha256,
    providerBacked: false,
    signingPayload: preparation.signingPayload,
    signingPayloadSha256: preparation.signingPayloadSha256,
    status: INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AWAITING_AUTHORIZATION,
    preparationContextStrictlyAllowlisted: true
  });
}

function readDispatchPreparation(secure, intent, context) {
  return validateDispatchPreparation(
    readArtifact(
      artifactPath(secure, intent.authorizationId, "dispatch-preparation"),
      secure
    ),
    context
  );
}

export function readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation(
  context
) {
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context,
    { requireDispatchAuthorization: false }
  );
  const secure = secureEvidenceRoot(
    normalizedContext.recoveryEvidenceRootPath,
    normalizedContext.forbiddenRootPath
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    normalizedContext.evidenceRootBinding,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
  );
  return readDispatchPreparation(
    secure,
    normalizedContext.preCallIntent,
    normalizedContext
  );
}

export function validateIntegratedLiveDrillProviderRecoveryAuthorizationPreparation(
  value,
  context
) {
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context,
    { requireDispatchAuthorization: false }
  );
  return validateDispatchPreparation(value, normalizedContext);
}

function validTransportDigest(value) {
  return typeof value === "string" && HEX_64.test(value);
}

function validOptionalTransportDigest(value) {
  return value === null || validTransportDigest(value);
}

function validTransportByteCount(value, maximum) {
  return Number.isSafeInteger(value) && value > 0 && value <= maximum;
}

function validRpcTransportEntry(entry, {
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
    validTransportByteCount(entry.requestBytes, maximumBytes) &&
    validTransportByteCount(entry.responseBytes, maximumBytes) &&
    validTransportDigest(entry.requestIdSha256) &&
    entry.requestIdSha256 === entry.responseIdSha256 &&
    validTransportDigest(entry.requestPayloadSha256) &&
    validTransportDigest(entry.responsePayloadSha256) &&
    validTransportDigest(entry.resultSha256) &&
    entry.responseCorrelated === true &&
    entry.sessionContinuous === true &&
    entry.sessionIdSha256 === sessionIdSha256 &&
    entry.outboundSessionIdSha256 === outboundSessionIdSha256 &&
    responseSessionIdSha256(entry.responseSessionIdSha256);
}

export function validateIntegratedLiveDrillManagedMcpTransportEvidence(value) {
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
      validTransportDigest(value.sessionIdSha256) &&
      validRpcTransportEntry(rpcCalls[0], {
        contentTypes: ["application/json", "text/event-stream"],
        maximumBytes: value.boundedResponseBytes,
        method: "initialize",
        outboundSessionIdSha256: null,
        responseSessionIdSha256: (digest) =>
          digest === value.sessionIdSha256,
        sessionIdSha256: value.sessionIdSha256
      }) &&
      validRpcTransportEntry(rpcCalls[1], {
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
      notifications[0]?.method === "notifications/initialized" &&
      notifications[0]?.sessionContinuous === true &&
      [200, 202, 204].includes(notifications[0].httpStatus) &&
      validTransportByteCount(
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
      notifications[0].requestPayloadSha256 ===
        integratedLiveDrillSha256(JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
          params: {}
        })) &&
      exactKeys(close, [
        "attempted",
        "httpStatus",
        "outboundSessionIdSha256",
        "responseSessionIdSha256",
        "sessionContinuous"
      ]) &&
      close?.attempted === true &&
      [200, 202, 204].includes(close.httpStatus) &&
      close.sessionContinuous === true &&
      close.outboundSessionIdSha256 === value.sessionIdSha256 &&
      (close.responseSessionIdSha256 === null ||
        close.responseSessionIdSha256 === value.sessionIdSha256) &&
      notifications[0].outboundSessionIdSha256 === value.sessionIdSha256 &&
      (notifications[0].responseSessionIdSha256 === null ||
        notifications[0].responseSessionIdSha256 === value.sessionIdSha256) &&
      validTransportDigest(notifications[0].requestPayloadSha256) &&
      validTransportDigest(notifications[0].outboundSessionIdSha256) &&
      validOptionalTransportDigest(
        notifications[0].responseSessionIdSha256
      ) &&
      validTransportDigest(close.outboundSessionIdSha256) &&
      validOptionalTransportDigest(close.responseSessionIdSha256),
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

export function validateIntegratedLiveDrillManagedMcpSemanticRequestEvidence(
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
  const expectedLogicalRequest = Object.freeze({
    schemaVersion:
      "tideproof.highwater-drill-logical-managed-mcp-request.v1",
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
      canonicalJson(value.logicalRequest) ===
        canonicalJson(expectedLogicalRequest) &&
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
  return Object.freeze({
    clusterId: value.clusterId,
    database: value.database,
    evidenceSha256: value.evidenceSha256,
    logicalMcpRequestSha256: value.logicalMcpRequestSha256,
    logicalRequest: expectedLogicalRequest,
    query: value.query,
    requestId: value.requestId,
    requestIdSha256: value.requestIdSha256,
    requestParamsSha256: value.requestParamsSha256,
    requestPayloadSha256: value.requestPayloadSha256,
    schemaVersion: value.schemaVersion,
    toolName: value.toolName
  });
}

function canonicalAuditTimestamp(value) {
  if (value === null || value === undefined) return null;
  const milliseconds = new Date(value).getTime();
  requireCondition(
    Number.isFinite(milliseconds),
    "INTEGRATED_LIVE_DRILL_PROVIDER_AUDIT_RECONCILIATION_REJECTED"
  );
  return new Date(milliseconds).toISOString();
}

function normalizeResolvedAudit(row, expectedEvent) {
  const normalized = Object.freeze({
    eventId: row?.event_id ?? row?.eventId,
    tenantId: row?.tenant_id ?? row?.tenantId,
    interactionId: row?.interaction_id ?? row?.interactionId,
    recoverySessionId:
      row?.recovery_session_id ?? row?.recoverySessionId,
    callerSubjectHash:
      row?.caller_subject_hash ?? row?.callerSubjectHash,
    phase: row?.phase,
    recoveryClusterId:
      row?.recovery_cluster_id ?? row?.recoveryClusterId,
    brokerConfigDigest:
      row?.broker_config_digest ?? row?.brokerConfigDigest,
    queryTemplateDigest:
      row?.query_template_digest ?? row?.queryTemplateDigest,
    boundInputDigest:
      row?.bound_input_digest ?? row?.boundInputDigest,
    resultDigest: row?.result_digest ?? row?.resultDigest ?? null,
    sourceWatermark: canonicalAuditTimestamp(
      row?.source_watermark ?? row?.sourceWatermark ?? null
    ),
    outcome: row?.outcome,
    errorCode: row?.error_code ?? row?.errorCode ?? null,
    startedAt: canonicalAuditTimestamp(row?.started_at ?? row?.startedAt),
    completedAt: canonicalAuditTimestamp(
      row?.completed_at ?? row?.completedAt
    )
  });
  const eventDigest = row?.event_digest ?? row?.eventDigest;
  requireCondition(
    canonicalJson(normalized) === canonicalJson(expectedEvent) &&
      eventDigest === recoveryAuditEventDigest(normalized),
    "INTEGRATED_LIVE_DRILL_PROVIDER_AUDIT_RECONCILIATION_REJECTED"
  );
  return Object.freeze({
    event: normalized,
    eventDigest: row?.event_digest ?? row?.eventDigest,
    resolutionSha256: integratedLiveDrillCanonicalSha256(normalized)
  });
}

function validatePreReadPlanArtifact(value, intent) {
  validateReceipt(
    value,
    [
      "authorizationId",
      "preCallIntentSha256",
      "prepared",
      "preparedSha256",
      "preReadAuditDigest",
      "preReadAuditEventSha256",
      "schemaVersion"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_PLAN_SCHEMA
  );
  const prepared = validatePreparedRecoveryArtifact(value.prepared, intent);
  const normalized = Object.freeze({
    authorizationId: value.authorizationId,
    preCallIntentSha256: value.preCallIntentSha256,
    prepared,
    preparedSha256: value.preparedSha256,
    preReadAuditDigest: value.preReadAuditDigest,
    preReadAuditEventSha256: value.preReadAuditEventSha256,
    receiptSha256: value.receiptSha256,
    schemaVersion: value.schemaVersion
  });
  requireCondition(
    canonicalJson(normalized) === canonicalJson(value) &&
      normalized.authorizationId === intent.authorizationId &&
      normalized.preCallIntentSha256 === intent.intentSha256 &&
      prepared.preReadEventId === intent.preReadAuditEventId &&
      prepared.terminalEventId === intent.terminalAuditEventId &&
      prepared.interactionId === intent.interactionId &&
      prepared.startedAt === intent.startedAt &&
      prepared.preReadAuditEvent.eventId ===
        intent.preReadAuditEventId &&
      prepared.preReadAuditEvent.interactionId ===
        intent.interactionId &&
      prepared.preReadAuditEvent.tenantId === intent.tenantId &&
      prepared.preReadAuditEvent.recoverySessionId ===
        intent.recoverySessionId &&
      prepared.preReadAuditEvent.phase === "pre_read" &&
      normalized.preReadAuditDigest === prepared.preReadAuditDigest &&
      normalized.preReadAuditDigest ===
        recoveryAuditEventDigest(prepared.preReadAuditEvent) &&
      normalized.preparedSha256 ===
        integratedLiveDrillCanonicalSha256(prepared) &&
      normalized.preReadAuditEventSha256 ===
        integratedLiveDrillCanonicalSha256(prepared.preReadAuditEvent),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
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
  const prepared = validatePreparedRecoveryArtifact(value.prepared, intent);
  const normalized = Object.freeze({
    authorizationId: value.authorizationId,
    preCallIntentSha256: value.preCallIntentSha256,
    preReadAuditDigest: value.preReadAuditDigest,
    preReadAuditEventSha256: value.preReadAuditEventSha256,
    preReadAuditResolutionSha256: value.preReadAuditResolutionSha256,
    prepared,
    preparedSha256: value.preparedSha256,
    receiptSha256: value.receiptSha256,
    schemaVersion: value.schemaVersion
  });
  requireCondition(
    canonicalJson(normalized) === canonicalJson(value) &&
      normalized.authorizationId === intent.authorizationId &&
      normalized.preCallIntentSha256 === intent.intentSha256 &&
      normalized.preReadAuditDigest === prepared.preReadAuditDigest &&
      prepared.preReadEventId === intent.preReadAuditEventId &&
      prepared.terminalEventId === intent.terminalAuditEventId &&
      prepared.interactionId === intent.interactionId &&
      prepared.startedAt === intent.startedAt &&
      normalized.preparedSha256 ===
        integratedLiveDrillCanonicalSha256(prepared) &&
      normalized.preReadAuditEventSha256 ===
        integratedLiveDrillCanonicalSha256(prepared.preReadAuditEvent) &&
      HEX_64.test(normalized.preReadAuditResolutionSha256 ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
}

function validateTerminalPlanArtifact(value, intent, prepared, provider) {
  validateReceipt(
    value,
    [
      "authorizationId",
      "completionPlan",
      "completionPlanSha256",
      "preCallIntentSha256",
      "providerEvidenceReceiptSha256",
      "schemaVersion",
      "terminalAuditDigest",
      "terminalAuditEventSha256"
    ],
    INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_PLAN_SCHEMA
  );
  const normalizedPrepared = validatePreparedRecoveryArtifact(
    prepared,
    intent
  );
  const completionPlan = normalizePreparedRecoveryCompletion(
    value.completionPlan
  );
  const normalized = Object.freeze({
    authorizationId: value.authorizationId,
    completionPlan,
    completionPlanSha256: value.completionPlanSha256,
    preCallIntentSha256: value.preCallIntentSha256,
    providerEvidenceReceiptSha256: value.providerEvidenceReceiptSha256,
    receiptSha256: value.receiptSha256,
    schemaVersion: value.schemaVersion,
    terminalAuditDigest: value.terminalAuditDigest,
    terminalAuditEventSha256: value.terminalAuditEventSha256
  });
  requireCondition(
    canonicalJson(normalized) === canonicalJson(value) &&
      normalized.authorizationId === intent.authorizationId &&
      normalized.preCallIntentSha256 === intent.intentSha256 &&
      normalized.providerEvidenceReceiptSha256 === provider.receiptSha256 &&
      completionPlan.preparedSha256 ===
        integratedLiveDrillCanonicalSha256(normalizedPrepared) &&
      completionPlan.rawResultSha256 ===
        integratedLiveDrillCanonicalSha256(provider.rawResult) &&
      completionPlan.terminalAuditEvent.eventId ===
        intent.terminalAuditEventId &&
      completionPlan.terminalAuditEvent.interactionId ===
        intent.interactionId &&
      completionPlan.terminalAuditEvent.tenantId === intent.tenantId &&
      completionPlan.terminalAuditEvent.recoverySessionId ===
        intent.recoverySessionId &&
      completionPlan.terminalAuditEvent.phase === "terminal" &&
      completionPlan.recovery.authorityTransferred === false &&
      completionPlan.recovery.requiresFreshAuthorization === true &&
      completionPlan.recovery.auditId === intent.terminalAuditEventId &&
      completionPlan.recovery.auditInteractionId === intent.interactionId &&
      completionPlan.recovery.preReadAuditId === intent.preReadAuditEventId &&
      completionPlan.recovery.preReadAuditDigest ===
        normalizedPrepared.preReadAuditDigest &&
      completionPlan.recovery.tenantId === intent.tenantId &&
      completionPlan.recovery.recoverySessionId === intent.recoverySessionId &&
      completionPlan.recovery.sourceDigest === intent.sourceDigest &&
      completionPlan.terminalAuditEvent.callerSubjectHash ===
        intent.subjectBindingSha256 &&
      completionPlan.terminalAuditEvent.recoveryClusterId ===
        intent.recoveryClusterId &&
      completionPlan.terminalAuditEvent.brokerConfigDigest ===
        intent.recoveryBrokerConfigDigest &&
      completionPlan.terminalAuditEvent.queryTemplateDigest ===
        intent.queryTemplateSha256 &&
      completionPlan.terminalAuditEvent.boundInputDigest ===
        intent.boundInputSha256 &&
      completionPlan.terminalAuditDigest === normalized.terminalAuditDigest &&
      normalized.terminalAuditDigest === recoveryAuditEventDigest(
        completionPlan.terminalAuditEvent
      ) &&
      normalized.completionPlanSha256 ===
        integratedLiveDrillCanonicalSha256(completionPlan) &&
      normalized.terminalAuditEventSha256 ===
        integratedLiveDrillCanonicalSha256(
          completionPlan.terminalAuditEvent
        ),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
}

function validateProviderArtifact(value, intent, context) {
  const normalizedPreCallInputs = validateProviderRecoveryContext(context, {
    requireDispatchAuthorization: true
  });
  const childAuthorizationIssuedAt =
    normalizedPreCallInputs.consumedChildAuthorization.attestation.payload
      .issuedAt;
  validateReceipt(
    value,
    [
      "authorizationId",
      "logicalMcpRequestSha256",
      "mcpResultSha256",
      "observedTransportCounts",
      "providerDispatchOwnerNonce",
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
  const rawResult = normalizeManagedMcpRawResult(value.rawResult);
  const observed = validateIntegratedLiveDrillManagedMcpTransportEvidence(
    value.transportEvidence
  );
  const transportEvidence = normalizePersistedJson(value.transportEvidence);
  const semantic =
    validateIntegratedLiveDrillManagedMcpSemanticRequestEvidence(
      value.semanticRequestEvidence,
      { intent, transportEvidence }
    );
  const dispatchAuthorization =
    validateIntegratedLiveDrillProviderDispatchAuthorization(
      context.providerDispatchAuthorization,
      {
        humanAuthorizationTrustRoot:
          context.trustedRunContext.humanAuthorizationTrustRoot,
        childAuthorizationIssuedAt,
        intent,
        requireCurrent: false
      }
    );
  const normalized = Object.freeze({
    authorizationId: value.authorizationId,
    logicalMcpRequestSha256: value.logicalMcpRequestSha256,
    mcpResultSha256: value.mcpResultSha256,
    observedTransportCounts: observed,
    providerDispatchOwnerNonce: value.providerDispatchOwnerNonce,
    preCallIntentSha256: value.preCallIntentSha256,
    providerDispatchAuthorizationSha256:
      value.providerDispatchAuthorizationSha256,
    rawResult,
    receiptSha256: value.receiptSha256,
    schemaVersion: value.schemaVersion,
    semanticRequestEvidence: semantic,
    semanticRequestEvidenceSha256: value.semanticRequestEvidenceSha256,
    sessionCloseSha256: value.sessionCloseSha256,
    transportEvidence,
    transportEvidenceSha256: value.transportEvidenceSha256
  });
  requireCondition(
    canonicalJson(normalized) === canonicalJson(value) &&
      normalized.authorizationId === intent.authorizationId &&
      normalized.preCallIntentSha256 === intent.intentSha256 &&
      normalized.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256 &&
      normalized.providerDispatchAuthorizationSha256 ===
        dispatchAuthorization.attestationSha256 &&
      UUID.test(normalized.providerDispatchOwnerNonce ?? "") &&
      normalized.mcpResultSha256 ===
        integratedLiveDrillCanonicalSha256(rawResult) &&
      transportEvidence.rpcCalls[1].resultSha256 ===
        normalized.mcpResultSha256 &&
      normalized.sessionCloseSha256 ===
        integratedLiveDrillCanonicalSha256(transportEvidence.close) &&
      normalized.transportEvidenceSha256 === observed.transportEvidenceSha256 &&
      normalized.semanticRequestEvidenceSha256 === semantic.evidenceSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
}

export function readIntegratedLiveDrillDurableProviderDispatchResult(
  context
) {
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context,
    { requireDispatchAuthorization: true }
  );
  const intent = normalizedContext.preCallIntent;
  const secure = secureEvidenceRoot(
    normalizedContext.recoveryEvidenceRootPath,
    normalizedContext.forbiddenRootPath
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    normalizedContext.evidenceRootBinding,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
  );
  const existing = readArtifactIfPresent(
    artifactPath(secure, intent.authorizationId, "mcp"),
    secure
  );
  if (existing === null) return null;
  const provider = validateProviderArtifact(
    existing,
    intent,
    normalizedContext
  );
  return Object.freeze({
    mcpResultSha256: provider.mcpResultSha256,
    providerDispatchOwnerNonce: provider.providerDispatchOwnerNonce,
    sessionCloseSha256: provider.sessionCloseSha256
  });
}

function validateTerminalArtifact(value, intent) {
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
  const recovery = normalizeRecoveryResultArtifact(value.recovery);
  const terminalAuditEvent = normalizeRecoveryAuditEvent(
    value.terminalAuditEvent
  );
  const normalized = Object.freeze({
    authorizationId: value.authorizationId,
    preCallIntentSha256: value.preCallIntentSha256,
    receiptSha256: value.receiptSha256,
    recovery,
    recoverySha256: value.recoverySha256,
    resultDigest: value.resultDigest,
    schemaVersion: value.schemaVersion,
    terminalAuditDigest: value.terminalAuditDigest,
    terminalAuditEvent,
    terminalAuditEventSha256: value.terminalAuditEventSha256,
    terminalAuditResolutionSha256: value.terminalAuditResolutionSha256
  });
  requireCondition(
    canonicalJson(normalized) === canonicalJson(value) &&
      normalized.authorizationId === intent.authorizationId &&
      normalized.preCallIntentSha256 === intent.intentSha256 &&
      recovery.status === "RECOVERED_CONTEXT_ONLY" &&
      recovery.authorityTransferred === false &&
      recovery.requiresFreshAuthorization === true &&
      recovery.auditId === intent.terminalAuditEventId &&
      recovery.auditInteractionId === intent.interactionId &&
      recovery.preReadAuditId === intent.preReadAuditEventId &&
      recovery.tenantId === intent.tenantId &&
      recovery.recoverySessionId === intent.recoverySessionId &&
      recovery.sourceDigest === intent.sourceDigest &&
      normalized.recoverySha256 ===
        integratedLiveDrillCanonicalSha256(recovery) &&
      terminalAuditEvent.eventId === intent.terminalAuditEventId &&
      terminalAuditEvent.interactionId === intent.interactionId &&
      terminalAuditEvent.tenantId === intent.tenantId &&
      terminalAuditEvent.recoverySessionId === intent.recoverySessionId &&
      terminalAuditEvent.callerSubjectHash === intent.subjectBindingSha256 &&
      terminalAuditEvent.recoveryClusterId === intent.recoveryClusterId &&
      terminalAuditEvent.brokerConfigDigest ===
        intent.recoveryBrokerConfigDigest &&
      terminalAuditEvent.queryTemplateDigest === intent.queryTemplateSha256 &&
      terminalAuditEvent.boundInputDigest === intent.boundInputSha256 &&
      terminalAuditEvent.startedAt === intent.startedAt &&
      terminalAuditEvent.phase === "terminal" &&
      normalized.terminalAuditDigest === recovery.auditDigest &&
      normalized.terminalAuditDigest ===
        recoveryAuditEventDigest(terminalAuditEvent) &&
      normalized.resultDigest === terminalAuditEvent.resultDigest &&
      normalized.terminalAuditEventSha256 ===
        integratedLiveDrillCanonicalSha256(terminalAuditEvent) &&
      HEX_64.test(normalized.resultDigest ?? "") &&
      HEX_64.test(normalized.terminalAuditResolutionSha256 ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  return normalized;
}

async function runIntegratedLiveDrillProviderRecoveryInternal({
  authenticatedPrincipal,
  assertProviderAdmission,
  broker,
  context
}, {
  interruptAfterPhase = null,
  trustedClock = () => Date.now()
} = {}) {
  requireCondition(
    typeof authenticatedPrincipal === "string" &&
      typeof broker?.planRecovery === "function" &&
      typeof broker?.commitPreparedRecoveryPreRead === "function" &&
      typeof broker?.prepareRecovery === "function" &&
      typeof broker?.restorePreparedRecovery === "function" &&
      typeof broker?.validatePreparedRecoveryResume === "function" &&
      typeof broker?.executePreparedRecovery === "function" &&
      typeof broker?.closePreparedRecoveryProviderSessionAndReadEvidence ===
        "function" &&
      typeof broker?.resolvePreparedRecoveryAuditEvent === "function" &&
      typeof broker?.planPreparedRecoveryCompletion === "function" &&
      typeof broker?.commitPreparedRecoveryCompletion === "function" &&
      typeof broker?.completePreparedRecovery === "function" &&
      typeof broker?.consumeProviderDispatch === "function" &&
      typeof broker?.completeProviderDispatch === "function" &&
      typeof broker?.markProviderDispatchUnknown === "function" &&
      typeof broker?.resolveProviderDispatch === "function" &&
      typeof trustedClock === "function" &&
      (assertProviderAdmission === undefined ||
        typeof assertProviderAdmission === "function") &&
      context?.preCallIntent &&
      context?.providerDispatchAuthorization,
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_INPUT_REJECTED"
  );
  const normalizedPreCallInputs = validateProviderRecoveryContext(context, {
    requireDispatchAuthorization: true
  });
  const childAuthorizationIssuedAt =
    normalizedPreCallInputs.consumedChildAuthorization.attestation.payload
      .issuedAt;
  const intent = context.preCallIntent;
  const secure = secureEvidenceRoot(
    context.recoveryEvidenceRootPath,
    context.forbiddenRootPath
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    context.evidenceRootBinding,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_ROOT_BINDING_REJECTED"
  );
  const preparation = readDispatchPreparation(secure, intent, context);
  const boundDispatchAuthorization =
    validateIntegratedLiveDrillProviderDispatchAuthorization(
      context.providerDispatchAuthorization,
      {
        humanAuthorizationTrustRoot:
          context.trustedRunContext.humanAuthorizationTrustRoot,
        childAuthorizationIssuedAt,
        intent,
        requireCurrent: false
      }
    );
  requireCondition(
    canonicalJson(boundDispatchAuthorization.payload) ===
      canonicalJson(preparation.signingPayload),
    "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
  );
  const authorityTimes = providerAuthorityTimes(
    context,
    intent,
    boundDispatchAuthorization,
    exactIsoMilliseconds(
      childAuthorizationIssuedAt,
      "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
    )
  );
  const providerControlBinding = buildProviderDispatchControlBinding({
    context,
    dispatchAuthorizationSha256:
      boundDispatchAuthorization.attestationSha256,
    earliestControllingExpiry: authorityTimes.earliestControllingExpiry,
    latestControllingIssuedAt: authorityTimes.latestControllingIssuedAt
  });
  const dispatchAuthorityGuard = providerDispatchGuard(
    context,
    intent,
    trustedClock
  );
  const externalActionGuard = (action) => {
    assertProviderAdmission?.();
    return dispatchAuthorityGuard(action);
  };
  const providerPath = artifactPath(
    secure,
    intent.authorizationId,
    "mcp"
  );
  const providerAtEntry = readArtifactIfPresent(providerPath, secure);
  const postProviderReconciliation = providerAtEntry !== null;
  if (providerAtEntry === null) {
    externalActionGuard("PROVIDER_RECOVERY_ENTRY");
  } else {
    validateProviderArtifact(providerAtEntry, intent, context);
  }
  const durableProviderResult = () => {
    const existing = readArtifactIfPresent(providerPath, secure);
    if (existing === null) return null;
    const provider = validateProviderArtifact(existing, intent, context);
    return Object.freeze({
      logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
      mcpResultSha256: provider.mcpResultSha256,
      providerDispatchOwnerNonce: provider.providerDispatchOwnerNonce,
      sessionCloseSha256: provider.sessionCloseSha256,
      sessionClosed: true
    });
  };
  const reconcileProviderControlCompletion = async () => {
    const provider = validateProviderArtifact(
      readArtifact(providerPath, secure),
      intent,
      context
    );
    let control;
    try {
      control = await broker.resolveProviderDispatch(providerControlBinding);
      if (control.state === PROVIDER_DISPATCH_CONTROL_STATES.CONSUMED) {
        control = await broker.completeProviderDispatch(
          providerControlBinding,
          {
            mcpResultSha256: provider.mcpResultSha256,
            sessionCloseSha256: provider.sessionCloseSha256
          },
          provider.providerDispatchOwnerNonce
        );
      }
    } catch (cause) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT",
        cause
      );
    }
    requireCondition(
      control.state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED &&
        control.mcpResultSha256 === provider.mcpResultSha256 &&
        control.sessionCloseSha256 === provider.sessionCloseSha256,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
    );
    return provider;
  };
  const providerControlIsTerminal = async () => {
    const provider = validateProviderArtifact(
      readArtifact(providerPath, secure),
      intent,
      context
    );
    let control;
    try {
      control = await broker.resolveProviderDispatch(providerControlBinding);
    } catch (cause) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT",
        cause
      );
    }
    requireCondition(
      control.state === PROVIDER_DISPATCH_CONTROL_STATES.COMPLETED &&
        control.mcpResultSha256 === provider.mcpResultSha256 &&
        control.sessionCloseSha256 === provider.sessionCloseSha256,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
    );
    return true;
  };
  if (!providerExternalActionAuthorityIsCurrent(
    context,
    intent,
    trustedClock
  )) {
    requireCondition(
      providerAtEntry !== null,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_AUTHORIZATION_EXPIRED"
    );
    runIntegratedLiveDrillRecoveryContinuityW1(context);
    const evidenceOnlyW2 = await runIntegratedLiveDrillRecoveryContinuityW2(
      context,
      {
        reconcileDurableResult: async ({ logicalMcpRequestSha256 }) => {
          requireCondition(
            logicalMcpRequestSha256 === intent.logicalMcpRequestSha256,
            "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
          );
          return durableProviderResult();
        },
        mcpCall: async () => {
          reject(
            "INTEGRATED_LIVE_DRILL_PROVIDER_POST_EXPIRY_PROVIDER_ACTION_REJECTED"
          );
        }
      }
    );
    requireCondition(
      evidenceOnlyW2.status ===
          INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE &&
        evidenceOnlyW2.retried === false,
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
    );
    await reconcileProviderControlCompletion();
  }
  const preReadPath = artifactPath(
    secure,
    intent.authorizationId,
    "pre-read"
  );
  const preReadPlanPath = artifactPath(
    secure,
    intent.authorizationId,
    "pre-read-plan"
  );
  let preReadPlan;
  const existingPreReadPlan = readArtifactIfPresent(
    preReadPlanPath,
    secure
  );
  if (existingPreReadPlan !== null) {
    preReadPlan = validatePreReadPlanArtifact(
      existingPreReadPlan,
      intent
    );
    await broker.validatePreparedRecoveryResume(preReadPlan.prepared, {
      authenticatedPrincipal
    });
    if (!postProviderReconciliation) {
      externalActionGuard("AFTER_PRE_READ_PLAN_RESUME");
    }
  } else {
    const prepared = await broker.planRecovery(
      { authenticatedPrincipal },
      {
        auditIdentity: {
          interactionId: intent.interactionId,
          preReadEventId: intent.preReadAuditEventId,
          terminalEventId: intent.terminalAuditEventId,
          startedAt: intent.startedAt
        }
      }
    );
    externalActionGuard("AFTER_PRE_READ_SESSION_RESOLUTION");
    const body = Object.freeze({
      schemaVersion:
        INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_PLAN_SCHEMA,
      authorizationId: intent.authorizationId,
      preCallIntentSha256: intent.intentSha256,
      prepared,
      preparedSha256: integratedLiveDrillCanonicalSha256(prepared),
      preReadAuditDigest: prepared.preReadAuditDigest,
      preReadAuditEventSha256: integratedLiveDrillCanonicalSha256(
        prepared.preReadAuditEvent
      )
    });
    preReadPlan = validatePreReadPlanArtifact(
      createOrReadExact(preReadPlanPath, withReceipt(body), secure),
      intent
    );
  }
  let preRead;
  const existingPreRead = readArtifactIfPresent(preReadPath, secure);
  if (existingPreRead !== null) {
    preRead = validatePreReadArtifact(existingPreRead, intent);
    await broker.validatePreparedRecoveryResume(preRead.prepared, {
      authenticatedPrincipal
    });
    if (!postProviderReconciliation) {
      externalActionGuard("AFTER_PRE_READ_EVIDENCE_RESUME");
      externalActionGuard("PRE_READ_AUDIT_RESOLVE");
      const resolved = await broker.resolvePreparedRecoveryAuditEvent(
        preRead.prepared.preReadAuditEvent,
        { beforeExternalAction: externalActionGuard }
      );
      externalActionGuard("AFTER_PRE_READ_AUDIT_RESOLVE");
      const reconciliation = normalizeResolvedAudit(
        resolved,
        preRead.prepared.preReadAuditEvent
      );
      requireCondition(
        reconciliation.resolutionSha256 ===
          preRead.preReadAuditResolutionSha256,
        "INTEGRATED_LIVE_DRILL_PROVIDER_AUDIT_RECONCILIATION_REJECTED"
      );
    }
  } else {
    const preparedResult = await broker.commitPreparedRecoveryPreRead(
      preReadPlan.prepared,
      { beforeAuditAppend: externalActionGuard }
    );
    externalActionGuard("AFTER_PRE_READ_AUDIT_APPEND");
    if (interruptAfterPhase === "AFTER_PRE_READ_AUDIT_COMMIT") {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_PRE_READ_AUDIT_COMMIT"
      );
    }
    externalActionGuard("PRE_READ_AUDIT_RESOLVE");
    const resolved = await broker.resolvePreparedRecoveryAuditEvent(
      preparedResult.prepared.preReadAuditEvent,
      { beforeExternalAction: externalActionGuard }
    );
    externalActionGuard("AFTER_PRE_READ_AUDIT_RESOLVE");
    const reconciliation = normalizeResolvedAudit(
      resolved,
      preparedResult.prepared.preReadAuditEvent
    );
    const body = Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_PRE_READ_SCHEMA,
      authorizationId: intent.authorizationId,
      preCallIntentSha256: intent.intentSha256,
      prepared: preparedResult.prepared,
      preparedSha256:
        integratedLiveDrillCanonicalSha256(preparedResult.prepared),
      preReadAuditDigest: preparedResult.prepared.preReadAuditDigest,
      preReadAuditEventSha256: integratedLiveDrillCanonicalSha256(
        preparedResult.prepared.preReadAuditEvent
      ),
      preReadAuditResolutionSha256: reconciliation.resolutionSha256
    });
    preRead = validatePreReadArtifact(
      createOrReadExact(preReadPath, withReceipt(body), secure),
      intent
    );
  }
  assertProviderAdmission?.();
  runIntegratedLiveDrillRecoveryContinuityW1(context);
  const w2 = await runIntegratedLiveDrillRecoveryContinuityW2(context, {
    reconcileDurableResult: async ({ logicalMcpRequestSha256 }) => {
      requireCondition(
        logicalMcpRequestSha256 === intent.logicalMcpRequestSha256,
        "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
      );
      return durableProviderResult();
    },
    mcpCall: async ({ logicalMcpRequestSha256 }) => {
      requireCondition(
        logicalMcpRequestSha256 === intent.logicalMcpRequestSha256,
        "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
      );
      const durable = durableProviderResult();
      if (durable !== null) {
        return durable;
      }
      const preliminaryDispatchAuthorization =
        externalActionGuard("BEFORE_MANAGED_MCP_SEQUENCE");
      let controlGrant;
      try {
        controlGrant = await broker.consumeProviderDispatch(
          providerControlBinding
        );
      } catch (cause) {
        reject(
          "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT",
          cause
        );
      }
      if (controlGrant.state === PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED) {
        reject(
          "INTEGRATED_LIVE_DRILL_PROVIDER_EXTERNAL_ACTION_AUTHORIZATION_REQUIRED"
        );
      }
      requireCondition(
        controlGrant.state === PROVIDER_DISPATCH_CONTROL_STATES.CONSUMED &&
          controlGrant.transitionOutcome === "DISPATCH_GRANTED",
        "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
      );
      let dispatchAuthorization = null;
      let rawResult;
      let providerEvidence;
      try {
        try {
          rawResult = await broker.executePreparedRecovery(
            preRead.prepared,
            {
              beforeProviderDispatch(action) {
                dispatchAuthorization = externalActionGuard(action);
              }
            }
          );
        } finally {
          providerEvidence =
            await broker.closePreparedRecoveryProviderSessionAndReadEvidence();
        }
        requireCondition(
          dispatchAuthorization !== null &&
            dispatchAuthorization.attestationSha256 ===
              preliminaryDispatchAuthorization.attestationSha256,
          "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
        );
        const transportEvidence = providerEvidence.transportEvidence;
        const semanticRequestEvidence =
          providerEvidence.semanticRequestEvidence;
        const observedTransportCounts =
          validateIntegratedLiveDrillManagedMcpTransportEvidence(
            transportEvidence
          );
        const body = Object.freeze({
          schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_RESULT_SCHEMA,
          authorizationId: intent.authorizationId,
          preCallIntentSha256: intent.intentSha256,
          providerDispatchAuthorizationSha256:
            dispatchAuthorization.attestationSha256,
          logicalMcpRequestSha256,
          rawResult,
          mcpResultSha256: integratedLiveDrillCanonicalSha256(rawResult),
          transportEvidence,
          transportEvidenceSha256:
            observedTransportCounts.transportEvidenceSha256,
          observedTransportCounts,
          providerDispatchOwnerNonce: controlGrant.ownerNonce,
          semanticRequestEvidence,
          semanticRequestEvidenceSha256:
            semanticRequestEvidence?.evidenceSha256,
          sessionCloseSha256:
            integratedLiveDrillCanonicalSha256(transportEvidence.close)
        });
        const provider = validateProviderArtifact(
          createOrReadExact(providerPath, withReceipt(body), secure),
          intent,
          context
        );
        return Object.freeze({
          logicalMcpRequestSha256,
          mcpResultSha256: provider.mcpResultSha256,
          sessionCloseSha256: provider.sessionCloseSha256,
          sessionClosed: true
        });
      } catch (cause) {
        try {
          await broker.markProviderDispatchUnknown(providerControlBinding);
        } catch {
          // A consumed or ambiguously completed global record already denies
          // every fresh provider attempt. Preserve the original failure.
        }
        reject(
          "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT",
          cause
        );
      }
    }
  });
  requireCondition(
    w2.status !== INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN &&
      w2.status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    "INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_UNKNOWN_DO_NOT_ACT"
  );
  const provider = validateProviderArtifact(
    readArtifact(providerPath, secure),
    intent,
    context
  );
  requireCondition(
    w2.mcpResultSha256 === provider.mcpResultSha256 &&
      w2.sessionCloseSha256 === provider.sessionCloseSha256 &&
      w2.sessionClosed === true,
    "INTEGRATED_LIVE_DRILL_PROVIDER_EVIDENCE_BINDING_REJECTED"
  );
  if (interruptAfterPhase === "AFTER_PROVIDER_EVIDENCE_DURABLE") {
    reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_PROVIDER_EVIDENCE_DURABLE"
    );
  }
  await reconcileProviderControlCompletion();

  const auditActionGuard = await postProviderAuditGuard({
    assertProviderAdmission,
    providerControlIsTerminal
  });
  await requirePostProviderAuditAuthority(auditActionGuard);
  const terminalPath = artifactPath(
    secure,
    intent.authorizationId,
    "terminal"
  );
  const terminalPlanPath = artifactPath(
    secure,
    intent.authorizationId,
    "terminal-plan"
  );
  let terminalPlan;
  const existingTerminalPlan = readArtifactIfPresent(
    terminalPlanPath,
    secure
  );
  if (existingTerminalPlan !== null) {
    terminalPlan = validateTerminalPlanArtifact(
      existingTerminalPlan,
      intent,
      preRead.prepared,
      provider
    );
  } else {
    const completionPlan = broker.planPreparedRecoveryCompletion(
      preRead.prepared,
      provider.rawResult
    );
    const body = Object.freeze({
      schemaVersion:
        INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_PLAN_SCHEMA,
      authorizationId: intent.authorizationId,
      preCallIntentSha256: intent.intentSha256,
      providerEvidenceReceiptSha256: provider.receiptSha256,
      completionPlan,
      completionPlanSha256:
        integratedLiveDrillCanonicalSha256(completionPlan),
      terminalAuditDigest: completionPlan.terminalAuditDigest,
      terminalAuditEventSha256: integratedLiveDrillCanonicalSha256(
        completionPlan.terminalAuditEvent
      )
    });
    terminalPlan = validateTerminalPlanArtifact(
      createOrReadExact(terminalPlanPath, withReceipt(body), secure),
      intent,
      preRead.prepared,
      provider
    );
  }
  let terminal;
  const existingTerminal = readArtifactIfPresent(terminalPath, secure);
  if (existingTerminal !== null) {
    terminal = validateTerminalArtifact(
      existingTerminal,
      intent
    );
    await requirePostProviderAuditAuthority(auditActionGuard);
    const resolved = await broker.resolvePreparedRecoveryAuditEvent(
      terminal.terminalAuditEvent,
      {
        beforeExternalAction: (action) =>
          requirePostProviderAuditAuthority(auditActionGuard, action)
      }
    );
    await requirePostProviderAuditAuthority(auditActionGuard);
    const reconciliation = normalizeResolvedAudit(
      resolved,
      terminal.terminalAuditEvent
    );
    requireCondition(
      reconciliation.resolutionSha256 ===
        terminal.terminalAuditResolutionSha256,
      "INTEGRATED_LIVE_DRILL_PROVIDER_AUDIT_RECONCILIATION_REJECTED"
    );
  } else {
    await requirePostProviderAuditAuthority(auditActionGuard);
    const completed = await broker.commitPreparedRecoveryCompletion(
      terminalPlan.completionPlan,
      preRead.prepared,
      provider.rawResult,
      {
        beforeAuditAppend: (action) =>
          requirePostProviderAuditAuthority(auditActionGuard, action)
      }
    );
    await requirePostProviderAuditAuthority(auditActionGuard);
    if (interruptAfterPhase === "AFTER_TERMINAL_AUDIT_COMMIT") {
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_SYNTHETIC_CRASH_AFTER_TERMINAL_AUDIT_COMMIT"
      );
    }
    await requirePostProviderAuditAuthority(auditActionGuard);
    const resolved = await broker.resolvePreparedRecoveryAuditEvent(
      completed.terminalAuditEvent,
      {
        beforeExternalAction: (action) =>
          requirePostProviderAuditAuthority(auditActionGuard, action)
      }
    );
    await requirePostProviderAuditAuthority(auditActionGuard);
    const reconciliation = normalizeResolvedAudit(
      resolved,
      completed.terminalAuditEvent
    );
    const body = Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECOVERY_TERMINAL_SCHEMA,
      authorizationId: intent.authorizationId,
      preCallIntentSha256: intent.intentSha256,
      recovery: completed.recovery,
      recoverySha256: integratedLiveDrillCanonicalSha256(completed.recovery),
      resultDigest: completed.resultDigest,
      terminalAuditDigest: completed.recovery.auditDigest,
      terminalAuditEvent: completed.terminalAuditEvent,
      terminalAuditEventSha256: integratedLiveDrillCanonicalSha256(
        completed.terminalAuditEvent
      ),
      terminalAuditResolutionSha256: reconciliation.resolutionSha256
    });
    terminal = validateTerminalArtifact(
      createOrReadExact(terminalPath, withReceipt(body), secure),
      intent
    );
  }
  await requirePostProviderAuditAuthority(auditActionGuard);
  runIntegratedLiveDrillRecoveryContinuityW3(context);

  const handoffBody = Object.freeze({
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
    observedInitializeCount:
      provider.observedTransportCounts.initializeCount,
    observedInitializedNotificationCount:
      provider.observedTransportCounts.initializedNotificationCount,
    observedToolsCallCount: provider.observedTransportCounts.toolsCallCount,
    observedSessionCloseCount:
      provider.observedTransportCounts.sessionCloseCount,
    sessionClosed: true,
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
  });
  await requirePostProviderAuditAuthority(auditActionGuard);
  return Object.freeze({
    recovery: terminal.recovery,
    providerContinuity: withReceipt(handoffBody)
  });
}

export async function runIntegratedLiveDrillProviderRecovery(args) {
  return runIntegratedLiveDrillProviderRecoveryInternal(args);
}

export const __test = Object.freeze({
  artifactPath,
  providerDispatchGuard,
  runProviderRecoveryWithInterruption(args, interruptAfterPhase) {
    requireCondition(
      [
        "AFTER_PRE_READ_AUDIT_COMMIT",
        "AFTER_PROVIDER_EVIDENCE_DURABLE",
        "AFTER_TERMINAL_AUDIT_COMMIT"
      ].includes(interruptAfterPhase),
      "INTEGRATED_LIVE_DRILL_PROVIDER_TEST_INTERRUPTION_REJECTED"
    );
    return runIntegratedLiveDrillProviderRecoveryInternal(args, {
      interruptAfterPhase
    });
  },
  runProviderRecoveryWithTrustedClock(args, trustedClock) {
    return runIntegratedLiveDrillProviderRecoveryInternal(args, {
      trustedClock
    });
  },
  runProviderRecoveryWithInterruptionAndTrustedClock(
    args,
    interruptAfterPhase,
    trustedClock
  ) {
    requireCondition(
      [
        "AFTER_PRE_READ_AUDIT_COMMIT",
        "AFTER_PROVIDER_EVIDENCE_DURABLE",
        "AFTER_TERMINAL_AUDIT_COMMIT"
      ].includes(interruptAfterPhase),
      "INTEGRATED_LIVE_DRILL_PROVIDER_TEST_INTERRUPTION_REJECTED"
    );
    return runIntegratedLiveDrillProviderRecoveryInternal(args, {
      interruptAfterPhase,
      trustedClock
    });
  },
  validatePreReadArtifact,
  validatePreReadPlanArtifact,
  validateProviderArtifact,
  validateTerminalArtifact,
  validateTerminalPlanArtifact
});
