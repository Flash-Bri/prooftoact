import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256
} from "./integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA,
  assertIntegratedLiveDrillPrivateRootCurrent,
  readIntegratedLiveDrillExactPrivateJson,
  secureIntegratedLiveDrillPrivateRoot
} from "./integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AWAITING_AUTHORIZATION
} from "./integrated-live-drill-provider-recovery.js";
import {
  acceptedIntegratedLiveDrillDvi,
  acceptedIntegratedLiveDrillRace,
  parseIntegratedLiveDrillSpec,
  selectedEvidenceBindingSha256
} from "./integrated-live-drill.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_SCHEMA =
  "tideproof.highwater-drill-provider-orchestration-preparation.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_SCHEMA =
  "tideproof.highwater-drill-provider-orchestration-completion.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA =
  "tideproof.highwater-drill-provider-supervisor-preparation.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_COMPLETION_SCHEMA =
  "tideproof.highwater-drill-provider-supervisor-completion.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_CHECKPOINT_PERSISTENCE_SCHEMA =
  "tideproof.highwater-drill-provider-checkpoint-persistence.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_SCHEMA =
  "tideproof.highwater-drill-provider-orchestration-stop.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD =
  "HOLD_AWAITING_EXACT_PROVIDER_DISPATCH_AUTHORIZATION";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETE =
  "LOCAL_PROVIDER_ORCHESTRATION_COMPLETED_NOT_RELEASED";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER =
  "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES = Object.freeze({
  DVI_AND_RACE_DURABLE: "DVI_AND_RACE_DURABLE",
  RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION:
    "RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION",
  DISPATCH_AUTHORIZATION_ACCEPTED: "DISPATCH_AUTHORIZATION_ACCEPTED",
  PROVIDER_WORKER_HANDOFF_DURABLE: "PROVIDER_WORKER_HANDOFF_DURABLE",
  PROVIDER_FINALIZATION_DURABLE: "PROVIDER_FINALIZATION_DURABLE",
  CANDIDATE_BUILT_NON_ACCEPTING: "CANDIDATE_BUILT_NON_ACCEPTING",
  UNKNOWN_DO_NOT_ACT: "UNKNOWN_DO_NOT_ACT",
  EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED:
    "EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED"
});
const PREPARATION_STATE_HISTORY = Object.freeze([
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.DVI_AND_RACE_DURABLE,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
    .RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION
]);
const COMPLETION_STATE_HISTORY = Object.freeze([
  ...PREPARATION_STATE_HISTORY,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
    .DISPATCH_AUTHORIZATION_ACCEPTED,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
    .PROVIDER_WORKER_HANDOFF_DURABLE,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
    .PROVIDER_FINALIZATION_DURABLE,
  INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
    .CANDIDATE_BUILT_NON_ACCEPTING
]);

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactRecord(value, keys) {
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

function normalizeJson(value, seen = new Set()) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  requireCondition(
    value && typeof value === "object" && !seen.has(value),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  seen.add(value);
  if (Array.isArray(value)) {
    const ownKeys = Reflect.ownKeys(value);
    requireCondition(
      Object.getPrototypeOf(value) === Array.prototype &&
        ownKeys.length === value.length + 1 &&
        ownKeys.every((key) =>
          key === "length" || /^(?:0|[1-9][0-9]*)$/u.test(String(key))
        ) &&
        Array.from({ length: value.length }, (_, index) =>
          Object.getOwnPropertyDescriptor(value, String(index))
        ).every((descriptor) =>
          descriptor !== undefined &&
          Object.hasOwn(descriptor, "value") &&
          descriptor.enumerable === true
        ),
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
    );
    const normalized = Object.freeze(
      Array.from({ length: value.length }, (_, index) =>
        normalizeJson(
          Object.getOwnPropertyDescriptor(value, String(index)).value,
          seen
        )
      )
    );
    seen.delete(value);
    return normalized;
  }
  requireCondition(
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
      Reflect.ownKeys(value).every((key) => {
        const descriptor = typeof key === "string"
          ? Object.getOwnPropertyDescriptor(value, key)
          : null;
        return typeof key === "string" &&
          descriptor !== null &&
          descriptor !== undefined &&
          Object.hasOwn(descriptor, "value") &&
          descriptor.enumerable === true;
      }),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  const normalized = Object.create(null);
  for (const key of Object.keys(value)) {
    Object.defineProperty(normalized, key, {
      configurable: false,
      enumerable: true,
      value: normalizeJson(
        Object.getOwnPropertyDescriptor(value, key).value,
        seen
      ),
      writable: false
    });
  }
  seen.delete(value);
  return Object.freeze(normalized);
}

export function normalizeIntegratedLiveDrillProviderOrchestrationBoundary(
  value
) {
  return normalizeJson(value);
}

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

function exactStateHistory(value, expected) {
  return Array.isArray(value) &&
    Object.getPrototypeOf(value) === Array.prototype &&
    value.length === expected.length &&
    value.every((entry, index) =>
      typeof entry === "string" && entry === expected[index]
    );
}

function validateReceipt(value, keys, schema, code) {
  requireCondition(
    exactRecord(value, [...keys, "receiptSha256"]),
    code
  );
  const { receiptSha256, ...body } = value;
  requireCondition(
    body.schemaVersion === schema &&
      HEX_64.test(receiptSha256 ?? "") &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body),
    code
  );
  return Object.freeze({ ...value });
}

function syncPrivateRoot(secure, code) {
  let descriptor;
  try {
    assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
    descriptor = fs.openSync(
      secure.rootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const opened = fs.fstatSync(descriptor);
    requireCondition(
      opened.isDirectory() &&
        opened.dev === secure.stat.dev &&
        opened.ino === secure.stat.ino &&
        opened.uid === secure.expectedUid &&
        (opened.mode & 0o777) === 0o700,
      code
    );
    fs.fsyncSync(descriptor);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function persistIntegratedLiveDrillExactPrivateJsonInternal({
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_CHECKPOINT_REJECTED",
  filePath,
  forbiddenRootPath,
  maximumBytes = MAX_CHECKPOINT_BYTES,
  rootPath,
  value
}) {
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    code
  );
  requireCondition(
    typeof filePath === "string" &&
      path.isAbsolute(filePath) &&
      path.resolve(filePath) === filePath &&
      path.dirname(filePath) === secure.rootPath &&
      Number.isSafeInteger(maximumBytes) &&
      maximumBytes > 0,
    code
  );
  const normalized = normalizeJson(value);
  requireCondition(canonicalJson(normalized) === canonicalJson(value), code);
  const bytes = Buffer.from(`${canonicalJson(normalized)}\n`, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= maximumBytes, code);
  let descriptor;
  let createdIdentity = null;
  try {
    assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW,
      0o600
    );
    const created = fs.fstatSync(descriptor);
    requireCondition(
      created.isFile() &&
        created.uid === secure.expectedUid &&
        created.nlink === 1 &&
        (created.mode & 0o777) === 0o600,
      code
    );
    createdIdentity = Object.freeze({ dev: created.dev, ino: created.ino });
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    syncPrivateRoot(secure, code);
  } catch (cause) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve first failure. */ }
    }
    if (cause?.code !== "EEXIST") {
      if (cause?.message === code) throw cause;
      reject(code, cause);
    }
  }
  syncPrivateRoot(secure, code);
  const reread = readIntegratedLiveDrillExactPrivateJson({
    code,
    filePath,
    maximumBytes,
    secure
  });
  requireCondition(canonicalJson(reread) === canonicalJson(normalized), code);
  const finalStat = fs.lstatSync(filePath);
  requireCondition(
    finalStat.isFile() &&
      !finalStat.isSymbolicLink() &&
      finalStat.uid === secure.expectedUid &&
      finalStat.dev === secure.stat.dev &&
      finalStat.nlink === 1 &&
      (finalStat.mode & 0o777) === 0o600 &&
      finalStat.size === bytes.length,
    code
  );
  requireCondition(
    createdIdentity === null ||
      (
        finalStat.dev === createdIdentity.dev &&
        finalStat.ino === createdIdentity.ino
      ),
    code
  );
  assertIntegratedLiveDrillPrivateRootCurrent(secure, code);
  return Object.freeze(normalizeJson(reread));
}

export function persistIntegratedLiveDrillExactPrivateJson(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "filePath",
      "forbiddenRootPath",
      "rootPath",
      "value"
    ]) || exactRecord(normalized, [
      "code",
      "filePath",
      "forbiddenRootPath",
      "rootPath",
      "value"
    ]) || exactRecord(normalized, [
      "code",
      "filePath",
      "forbiddenRootPath",
      "maximumBytes",
      "rootPath",
      "value"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  return persistIntegratedLiveDrillExactPrivateJsonInternal(normalized);
}

function readIntegratedLiveDrillOrchestrationPrivateJsonInternal({
  code = "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_CHECKPOINT_REJECTED",
  filePath,
  forbiddenRootPath,
  maximumBytes = MAX_CHECKPOINT_BYTES,
  rootPath
}) {
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    code
  );
  return Object.freeze(normalizeJson(
    readIntegratedLiveDrillExactPrivateJson({
      code,
      filePath,
      maximumBytes,
      secure
    })
  ));
}

export function readIntegratedLiveDrillOrchestrationPrivateJson(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "filePath",
      "forbiddenRootPath",
      "rootPath"
    ]) || exactRecord(normalized, [
      "code",
      "filePath",
      "forbiddenRootPath",
      "rootPath"
    ]) || exactRecord(normalized, [
      "code",
      "filePath",
      "forbiddenRootPath",
      "maximumBytes",
      "rootPath"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  return readIntegratedLiveDrillOrchestrationPrivateJsonInternal(normalized);
}

export function validateIntegratedLiveDrillProviderSupervisorPreparation(value) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_REJECTED";
  const normalized = validateReceipt(normalizeJson(value), [
    "accepted",
    "ambiguityBlocker",
    "authorizationId",
    "authorizationAttestationSha256",
    "finalReleaseReady",
    "logicalMcpRequestSha256",
    "preCallIntentSha256",
    "preparationContextSha256",
    "preparationReceiptSha256",
    "providerBacked",
    "recoveryBrokerConfigDigest",
    "runId",
    "schemaVersion",
    "signingPayload",
    "signingPayloadSha256",
    "stateHistory",
    "status"
  ], INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_PREPARATION_SCHEMA, code);
  const payload = normalizeJson(normalized.signingPayload);
  const payloadKeys = [
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
    "recoveryBrokerConfigDigest",
    "requiredSessionCloseCount",
    "requiredToolsCallCount",
    "runId",
    "schemaVersion"
  ];
  const issuedAt = Date.parse(payload.issuedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  requireCondition(
    normalized.status ===
      INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AWAITING_AUTHORIZATION &&
      normalized.accepted === false &&
      normalized.providerBacked === false &&
      normalized.finalReleaseReady === false &&
      normalized.ambiguityBlocker ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER &&
      exactRecord(payload, payloadKeys) &&
      payload.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_SCHEMA &&
      payload.authorityStatement ===
        INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORITY_STATEMENT &&
      UUID.test(normalized.authorizationId ?? "") &&
      UUID.test(normalized.runId ?? "") &&
      HEX_64.test(normalized.preCallIntentSha256 ?? "") &&
      HEX_64.test(normalized.authorizationAttestationSha256 ?? "") &&
      HEX_64.test(normalized.logicalMcpRequestSha256 ?? "") &&
      HEX_64.test(normalized.recoveryBrokerConfigDigest ?? "") &&
      HEX_64.test(normalized.preparationContextSha256 ?? "") &&
      HEX_64.test(normalized.preparationReceiptSha256 ?? "") &&
      HEX_64.test(normalized.signingPayloadSha256 ?? "") &&
      normalized.signingPayloadSha256 ===
        integratedLiveDrillCanonicalSha256(payload) &&
      payload.authorizationId === normalized.authorizationId &&
      payload.runId === normalized.runId &&
      payload.preCallIntentSha256 === normalized.preCallIntentSha256 &&
      payload.authorizationAttestationSha256 ===
        normalized.authorizationAttestationSha256 &&
      payload.logicalMcpRequestSha256 ===
        normalized.logicalMcpRequestSha256 &&
      payload.recoveryBrokerConfigDigest ===
        normalized.recoveryBrokerConfigDigest &&
      [
        payload.maximumInitializeCount,
        payload.maximumInitializedNotificationCount,
        payload.maximumManagedMcpToolCallCount,
        payload.requiredSessionCloseCount,
        payload.requiredToolsCallCount
      ].every((count) => count === 1) &&
      Number.isFinite(issuedAt) &&
      Number.isFinite(expiresAt) &&
      new Date(issuedAt).toISOString() === payload.issuedAt &&
      new Date(expiresAt).toISOString() === payload.expiresAt &&
      issuedAt < expiresAt &&
      expiresAt <= issuedAt + 15 * 60 * 1_000 &&
      exactStateHistory(normalized.stateHistory, [
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .RECOVERY_PREPARED_AWAITING_EXACT_DISPATCH_AUTHORIZATION
      ]),
    code
  );
  return Object.freeze({ ...normalized, signingPayload: payload });
}

export function validateIntegratedLiveDrillProviderSupervisorCompletion(value) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_COMPLETION_REJECTED";
  const normalized = validateReceipt(normalizeJson(value), [
    "accepted",
    "ambiguityBlocker",
    "authorizationId",
    "finalReleaseReady",
    "finalizationReceiptSha256",
    "observedInitializeCount",
    "observedInitializedNotificationCount",
    "observedSessionCloseCount",
    "observedToolsCallCount",
    "preCallIntentSha256",
    "providerBacked",
    "providerHandoffReceiptSha256",
    "recoveryReceiptSha256",
    "runId",
    "schemaVersion",
    "stateHistory",
    "status"
  ], INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_COMPLETION_SCHEMA, code);
  requireCondition(
    normalized.status === "LOCAL_PROVIDER_SUPERVISOR_COMPLETED_NOT_RELEASED" &&
      normalized.accepted === false &&
      normalized.providerBacked === false &&
      normalized.finalReleaseReady === false &&
      normalized.ambiguityBlocker ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER &&
      UUID.test(normalized.authorizationId ?? "") &&
      UUID.test(normalized.runId ?? "") &&
      [
        normalized.finalizationReceiptSha256,
        normalized.preCallIntentSha256,
        normalized.providerHandoffReceiptSha256,
        normalized.recoveryReceiptSha256
      ].every((entry) => HEX_64.test(entry ?? "")) &&
      normalized.observedInitializeCount === 1 &&
      normalized.observedInitializedNotificationCount === 1 &&
      normalized.observedToolsCallCount === 1 &&
      normalized.observedSessionCloseCount === 1 &&
      exactStateHistory(normalized.stateHistory, [
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .DISPATCH_AUTHORIZATION_ACCEPTED,
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .PROVIDER_WORKER_HANDOFF_DURABLE,
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .PROVIDER_FINALIZATION_DURABLE
      ]),
    code
  );
  return normalized;
}

function buildIntegratedLiveDrillProviderOrchestrationPreparationInternal({
  authorityEvidenceId,
  authoritySelectedEvidenceDigest,
  dvi,
  gate1Preparation,
  journalIntentBindingSha256,
  journalPathSha256,
  race,
  spec
}) {
  const acceptedSpec = parseIntegratedLiveDrillSpec(spec);
  const selectedBinding = selectedEvidenceBindingSha256(
    authorityEvidenceId,
    authoritySelectedEvidenceDigest
  );
  const acceptedDvi = normalizeJson(dvi);
  const acceptedRace = normalizeJson(race);
  requireCondition(
    acceptedIntegratedLiveDrillDvi(
      acceptedDvi,
      acceptedSpec,
      selectedBinding
    ) &&
      acceptedIntegratedLiveDrillRace(
        acceptedRace,
        acceptedSpec,
        acceptedDvi
      ),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPONENT_REJECTED"
  );
  const supervisor = validateIntegratedLiveDrillProviderSupervisorPreparation(
    gate1Preparation
  );
  requireCondition(
    supervisor.runId === acceptedSpec.runId &&
      HEX_64.test(journalIntentBindingSha256 ?? "") &&
      HEX_64.test(journalPathSha256 ?? ""),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
  );
  const body = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorityEvidenceId,
    authoritySelectedEvidenceDigest,
    authorizationId: supervisor.authorizationId,
    dvi: acceptedDvi,
    dviSha256: integratedLiveDrillCanonicalSha256(acceptedDvi),
    finalReleaseReady: false,
    gate1Preparation: supervisor,
    gate1PreparationReceiptSha256: supervisor.receiptSha256,
    journalIntentBindingSha256,
    journalPathSha256,
    providerBacked: false,
    race: acceptedRace,
    raceSha256: integratedLiveDrillCanonicalSha256(acceptedRace),
    runId: acceptedSpec.runId,
    signingPayloadSha256: supervisor.signingPayloadSha256,
    sourceCommit: acceptedSpec.sourceCommit,
    stateHistory: PREPARATION_STATE_HISTORY,
    status: INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD,
    treeDigest: acceptedSpec.treeDigest
  });
  return withReceipt(body);
}

export function buildIntegratedLiveDrillProviderOrchestrationPreparation(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "authorityEvidenceId",
      "authoritySelectedEvidenceDigest",
      "dvi",
      "gate1Preparation",
      "journalIntentBindingSha256",
      "journalPathSha256",
      "race",
      "spec"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  return buildIntegratedLiveDrillProviderOrchestrationPreparationInternal(
    normalized
  );
}

export function validateIntegratedLiveDrillProviderOrchestrationPreparation(
  value,
  spec
) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED";
  const acceptedSpec = parseIntegratedLiveDrillSpec(normalizeJson(spec));
  const normalized = validateReceipt(normalizeJson(value), [
    "accepted",
    "ambiguityBlocker",
    "authorityEvidenceId",
    "authoritySelectedEvidenceDigest",
    "authorizationId",
    "dvi",
    "dviSha256",
    "finalReleaseReady",
    "gate1Preparation",
    "gate1PreparationReceiptSha256",
    "journalIntentBindingSha256",
    "journalPathSha256",
    "providerBacked",
    "race",
    "raceSha256",
    "runId",
    "schemaVersion",
    "signingPayloadSha256",
    "sourceCommit",
    "stateHistory",
    "status",
    "treeDigest"
  ], INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_SCHEMA, code);
  const expected = buildIntegratedLiveDrillProviderOrchestrationPreparation({
    authorityEvidenceId: normalized.authorityEvidenceId,
    authoritySelectedEvidenceDigest:
      normalized.authoritySelectedEvidenceDigest,
    dvi: normalized.dvi,
    gate1Preparation: normalized.gate1Preparation,
    journalIntentBindingSha256: normalized.journalIntentBindingSha256,
    journalPathSha256: normalized.journalPathSha256,
    race: normalized.race,
    spec: acceptedSpec
  });
  requireCondition(canonicalJson(expected) === canonicalJson(normalized), code);
  return expected;
}

function checkpointPersistenceReceipt({
  checkpointPath,
  forbiddenRootPath,
  preparation,
  rootPath
}) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_CHECKPOINT_REJECTED";
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    code
  );
  let checkpointStat;
  let rootStat;
  try {
    rootStat = fs.lstatSync(rootPath);
    checkpointStat = fs.lstatSync(checkpointPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    fs.realpathSync(rootPath) === rootPath &&
      fs.realpathSync(checkpointPath) === checkpointPath &&
      path.dirname(checkpointPath) === rootPath &&
      rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      rootStat.dev === secure.stat.dev &&
      rootStat.ino === secure.stat.ino &&
      rootStat.uid === secure.expectedUid &&
      (rootStat.mode & 0o777) === 0o700 &&
      checkpointStat.isFile() &&
      !checkpointStat.isSymbolicLink() &&
      checkpointStat.uid === secure.expectedUid &&
      checkpointStat.dev === rootStat.dev &&
      checkpointStat.nlink === 1 &&
      (checkpointStat.mode & 0o777) === 0o600 &&
      checkpointStat.size > 0,
    code
  );
  return withReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_CHECKPOINT_PERSISTENCE_SCHEMA,
    checkpointDevice: String(checkpointStat.dev),
    checkpointInode: String(checkpointStat.ino),
    checkpointLinkCount: checkpointStat.nlink,
    checkpointMode: "0600",
    checkpointPathSha256: integratedLiveDrillCanonicalSha256(checkpointPath),
    checkpointSize: checkpointStat.size,
    checkpointUid: checkpointStat.uid,
    preparationReceiptSha256: preparation.receiptSha256,
    rootDevice: String(rootStat.dev),
    rootInode: String(rootStat.ino),
    rootMode: "0700",
    rootPathSha256: integratedLiveDrillCanonicalSha256(rootPath),
    rootUid: rootStat.uid
  }));
}

function persistOrValidateCheckpointPersistence({
  checkpointPath,
  forbiddenRootPath,
  preparation,
  readOnly = false,
  rootPath
}) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_CHECKPOINT_REJECTED";
  const receiptPath = `${checkpointPath}.persistence.json`;
  requireCondition(path.dirname(receiptPath) === rootPath, code);
  const expected = checkpointPersistenceReceipt({
    checkpointPath,
    forbiddenRootPath,
    preparation,
    rootPath
  });
  const observed = readOnly
    ? readIntegratedLiveDrillOrchestrationPrivateJson({
        code,
        filePath: receiptPath,
        forbiddenRootPath,
        rootPath
      })
    : persistIntegratedLiveDrillExactPrivateJson({
        code,
        filePath: receiptPath,
        forbiddenRootPath,
        rootPath,
        value: expected
      });
  requireCondition(
    canonicalJson(observed) === canonicalJson(expected),
    code
  );
  return expected;
}

function persistIntegratedLiveDrillProviderOrchestrationPreparationInternal({
  checkpointPath,
  forbiddenRootPath,
  preparation,
  rootPath,
  spec
}) {
  const accepted = validateIntegratedLiveDrillProviderOrchestrationPreparation(
    preparation,
    spec
  );
  const persisted = validateIntegratedLiveDrillProviderOrchestrationPreparation(
    persistIntegratedLiveDrillExactPrivateJson({
      filePath: checkpointPath,
      forbiddenRootPath,
      rootPath,
      value: accepted
    }),
    spec
  );
  persistOrValidateCheckpointPersistence({
    checkpointPath,
    forbiddenRootPath,
    preparation: persisted,
    rootPath
  });
  return persisted;
}

export function persistIntegratedLiveDrillProviderOrchestrationPreparation(
  args
) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "checkpointPath",
      "forbiddenRootPath",
      "preparation",
      "rootPath",
      "spec"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  return persistIntegratedLiveDrillProviderOrchestrationPreparationInternal(
    normalized
  );
}

function readIntegratedLiveDrillProviderOrchestrationPreparationInternal({
  checkpointPath,
  forbiddenRootPath,
  rootPath,
  spec
}) {
  const preparation = validateIntegratedLiveDrillProviderOrchestrationPreparation(
    readIntegratedLiveDrillOrchestrationPrivateJson({
      filePath: checkpointPath,
      forbiddenRootPath,
      rootPath
    }),
    spec
  );
  const persistence = persistOrValidateCheckpointPersistence({
    checkpointPath,
    forbiddenRootPath,
    preparation,
    readOnly: true,
    rootPath
  });
  return Object.freeze({ persistence, preparation });
}

export function readIntegratedLiveDrillProviderOrchestrationPreparation(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "checkpointPath",
      "forbiddenRootPath",
      "rootPath",
      "spec"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  return readIntegratedLiveDrillProviderOrchestrationPreparationInternal(
    normalized
  );
}

export function sanitizedIntegratedLiveDrillProviderOrchestrationHold(
  preparation,
  spec
) {
  const normalizedPreparation =
    validateIntegratedLiveDrillProviderOrchestrationPreparation(
      normalizeJson(preparation),
      normalizeJson(spec)
    );
  const supervisor = validateIntegratedLiveDrillProviderSupervisorPreparation(
    normalizedPreparation.gate1Preparation
  );
  requireCondition(
    normalizedPreparation.status ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD &&
      normalizedPreparation.receiptSha256 ===
        integratedLiveDrillCanonicalSha256(
          Object.fromEntries(Object.entries(normalizedPreparation).filter(
            ([key]) => key !== "receiptSha256"
          ))
        ),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
  );
  return Object.freeze({
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId: supervisor.authorizationId,
    finalReleaseReady: false,
    preparationReceiptSha256: normalizedPreparation.receiptSha256,
    providerBacked: false,
    runId: supervisor.runId,
    signingPayload: supervisor.signingPayload,
    signingPayloadSha256: supervisor.signingPayloadSha256,
    stateHistory: PREPARATION_STATE_HISTORY,
    status: INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD
  });
}

export function buildIntegratedLiveDrillProviderOrchestrationCompletion(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, ["completion", "preparation", "spec"]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_INPUT_REJECTED"
  );
  const preparation =
    validateIntegratedLiveDrillProviderOrchestrationPreparation(
      normalized.preparation,
      normalized.spec
    );
  const acceptedCompletion =
    validateIntegratedLiveDrillProviderSupervisorCompletion(
      normalized.completion
    );
  requireCondition(
    preparation.status === INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_HOLD &&
      acceptedCompletion.authorizationId === preparation.authorizationId &&
      acceptedCompletion.runId === preparation.runId &&
      acceptedCompletion.preCallIntentSha256 ===
        preparation.gate1Preparation.preCallIntentSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_REJECTED"
  );
  return withReceipt(Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId: acceptedCompletion.authorizationId,
    finalReleaseReady: false,
    gate1CompletionReceiptSha256: acceptedCompletion.receiptSha256,
    observedInitializeCount: acceptedCompletion.observedInitializeCount,
    observedInitializedNotificationCount:
      acceptedCompletion.observedInitializedNotificationCount,
    observedSessionCloseCount: acceptedCompletion.observedSessionCloseCount,
    observedToolsCallCount: acceptedCompletion.observedToolsCallCount,
    preparationReceiptSha256: preparation.receiptSha256,
    providerBacked: false,
    providerHandoffReceiptSha256:
      acceptedCompletion.providerHandoffReceiptSha256,
    runId: acceptedCompletion.runId,
    sourceCommit: preparation.sourceCommit,
    stateHistory: COMPLETION_STATE_HISTORY,
    status: INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_COMPLETE,
    treeDigest: preparation.treeDigest
  }));
}

export function integratedLiveDrillProviderOrchestrationStopDisposition(value) {
  const normalized = normalizeJson(value);
  requireCondition(
    exactRecord(normalized, [
      "authorizationId",
      "causeCode",
      "preparationReceiptSha256",
      "runId",
      "state"
    ]) &&
      UUID.test(normalized.authorizationId ?? "") &&
      UUID.test(normalized.runId ?? "") &&
      /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
        normalized.causeCode ?? ""
      ) &&
      HEX_64.test(normalized.preparationReceiptSha256 ?? "") &&
      [
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .UNKNOWN_DO_NOT_ACT,
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED
      ].includes(normalized.state),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_REJECTED"
  );
  return withReceipt(Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId: normalized.authorizationId,
    finalReleaseReady: false,
    providerBacked: false,
    retryPermitted: false,
    causeCodeSha256: integratedLiveDrillCanonicalSha256(
      normalized.causeCode
    ),
    preparationReceiptSha256: normalized.preparationReceiptSha256,
    runId: normalized.runId,
    state: normalized.state,
    status: normalized.state
  }));
}

export function validateIntegratedLiveDrillProviderOrchestrationStop(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_REJECTED";
  const normalized = validateReceipt(normalizeJson(value), [
    "accepted",
    "ambiguityBlocker",
    "authorizationId",
    "causeCodeSha256",
    "finalReleaseReady",
    "preparationReceiptSha256",
    "providerBacked",
    "retryPermitted",
    "runId",
    "schemaVersion",
    "state",
    "status"
  ], INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_SCHEMA, code);
  requireCondition(
    normalized.accepted === false &&
      normalized.providerBacked === false &&
      normalized.finalReleaseReady === false &&
      normalized.retryPermitted === false &&
      normalized.ambiguityBlocker ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER &&
      UUID.test(normalized.authorizationId ?? "") &&
      UUID.test(normalized.runId ?? "") &&
      HEX_64.test(normalized.causeCodeSha256 ?? "") &&
      HEX_64.test(normalized.preparationReceiptSha256 ?? "") &&
      normalized.status === normalized.state &&
      [
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES.UNKNOWN_DO_NOT_ACT,
        INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STATES
          .EXPIRED_FRESH_AUDIT_AUTHORITY_REQUIRED
      ].includes(normalized.state),
    code
  );
  return normalized;
}

export function persistIntegratedLiveDrillProviderOrchestrationStop(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "causeCode",
      "forbiddenRootPath",
      "preparation",
      "rootPath",
      "state",
      "stopPath"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_REJECTED"
  );
  const stop = integratedLiveDrillProviderOrchestrationStopDisposition({
    authorizationId: normalized.preparation.authorizationId,
    causeCode: normalized.causeCode,
    preparationReceiptSha256: normalized.preparation.receiptSha256,
    runId: normalized.preparation.runId,
    state: normalized.state
  });
  return validateIntegratedLiveDrillProviderOrchestrationStop(
    persistIntegratedLiveDrillExactPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_REJECTED",
      filePath: normalized.stopPath,
      forbiddenRootPath: normalized.forbiddenRootPath,
      rootPath: normalized.rootPath,
      value: stop
    })
  );
}

export function readIntegratedLiveDrillProviderOrchestrationStop(args) {
  const normalized = normalizeJson(args);
  requireCondition(
    exactRecord(normalized, [
      "forbiddenRootPath",
      "rootPath",
      "stopPath"
    ]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_REJECTED"
  );
  return validateIntegratedLiveDrillProviderOrchestrationStop(
    readIntegratedLiveDrillOrchestrationPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_STOP_REJECTED",
      filePath: normalized.stopPath,
      forbiddenRootPath: normalized.forbiddenRootPath,
      rootPath: normalized.rootPath
    })
  );
}

export const __test = Object.freeze({
  exactRecord,
  normalizeJson,
  withReceipt
});
