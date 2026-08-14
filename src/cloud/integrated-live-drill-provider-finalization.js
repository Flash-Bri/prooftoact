import fs from "node:fs";
import path from "node:path";
import { publishOrReadExactOwnedFile } from "./atomic-create-only-file.js";

import { canonicalJson } from "./canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256
} from "./integrated-live-drill-authorization.js";
import {
  runIntegratedLiveDrillRecoveryContinuityW4,
  runIntegratedLiveDrillRecoveryContinuityW5,
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";
import {
  assertIntegratedLiveDrillPrivateRootMatchesBinding,
  assertIntegratedLiveDrillPrivateRootCurrent,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  integratedLiveDrillProviderContextAssertions,
  normalizeIntegratedLiveDrillProviderContext,
  readIntegratedLiveDrillExactPrivateJson,
  reconstructIntegratedLiveDrillProviderRecoveryHandoff,
  secureIntegratedLiveDrillPrivateRoot,
  validateIntegratedLiveDrillProviderRecoveryHandoff,
  verifyIntegratedLiveDrillProviderEvidenceBundle
} from "./integrated-live-drill-provider-evidence.js";
import {
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "./integrated-live-drill-runtime.js";

export { validateIntegratedLiveDrillProviderRecoveryHandoff } from
  "./integrated-live-drill-provider-evidence.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_COMPONENT_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-provider-component-receipt.v2";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_SCHEMA =
  "tideproof.highwater-drill-provider-finalization.v2";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-finalization-input.v2";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_BINDING_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_CLAIM_BOUNDARY =
  "This provider-free W5 finalization process treats the supplied handoff as untrusted, rereads the exact owner-only W1 pre-read, W2 raw-result/transport/session-close, and W3 terminal artifacts from the bound evidence root, recomputes their receipt digests and observed counts, and cross-binds the W2 result and close digests to the complete continuity journal before writing the sanitized W4 component receipt. Its exact schema rejects provider clients, credential material, raw provider results, and every supplied context key whose normalized name contains retry; the key-name check does not prove that arbitrary data cannot semantically encode retry intent. The finalizer exposes no retry or provider operation. It does not independently prove provider origin, live provider execution, process-level network denial, cross-host continuity, deployment, acceptance, or release.";

const MAX_RECEIPT_BYTES = 64 * 1024;
const PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER =
  "DURABLE_EXACT_ONE_MCP_CRASH_RESTART_AMBIGUOUS_RESULT_RECONCILIATION_NOT_PROVEN";
const PROVIDER_SUPERVISOR_COMPLETION_SCHEMA =
  "tideproof.highwater-drill-provider-supervisor-completion.v1";
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
const FINALIZER_ENVIRONMENT_NAMES = new Set([
  ...SAFE_PROCESS_ENVIRONMENT_NAMES,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_BINDING_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
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

function requiredEnvironmentText(value, code) {
  requireCondition(
    typeof value === "string" &&
      value.length > 0 &&
      value.length <= 8192 &&
      !/[\0\r\n]/u.test(value),
    code
  );
  return value;
}

function normalizeFinalizerEnvironment(environment, code) {
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
        FINALIZER_ENVIRONMENT_NAMES.has(key);
    }),
    code
  );
  return Object.freeze(Object.fromEntries(
    ownKeys
      .filter((key) => FINALIZER_ENVIRONMENT_NAMES.has(key))
      .map((key) => [
        key,
        Object.getOwnPropertyDescriptor(environment, key).value
      ])
  ));
}

export function integratedLiveDrillProviderFinalizerEnvironment(
  sourceEnvironment,
  { forbiddenRootPath, inputPath, rootBinding, rootPath }
) {
  const value = {
    ...Object.fromEntries(
      Object.entries(sourceEnvironment ?? {}).filter(([name]) =>
        SAFE_PROCESS_ENVIRONMENT_NAMES.includes(name)
      )
    ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT]:
      requiredEnvironmentText(
        inputPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT]:
      requiredEnvironmentText(
        rootPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT]:
      requiredEnvironmentText(
        forbiddenRootPath,
        "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED"
      ),
    [INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_BINDING_ENVIRONMENT]:
      canonicalJson(rootBinding),
    [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "3"
  };
  return assertIntegratedLiveDrillProviderFinalizerEnvironment(value);
}

export function assertIntegratedLiveDrillProviderFinalizerEnvironment(
  environment
) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ENVIRONMENT_REJECTED";
  const normalized = normalizeFinalizerEnvironment(environment, code);
  for (const name of [
    INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_PATH_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_FORBIDDEN_ROOT_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_BINDING_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT
  ]) {
    requiredEnvironmentText(normalized[name], code);
  }
  requireCondition(
    normalized[INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT] ===
      "3",
    code
  );
  return normalized;
}

function secureRoot(rootPath, forbiddenRootPath) {
  return secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_REJECTED"
  );
}

function assertSameRoot(secure) {
  let current;
  try {
    current = fs.lstatSync(secure.rootPath);
  } catch (cause) {
    reject("INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_DRIFT", cause);
  }
  requireCondition(
    current.isDirectory() &&
      !current.isSymbolicLink() &&
      current.dev === secure.stat.dev &&
      current.ino === secure.stat.ino &&
      current.uid === secure.expectedUid &&
      (current.mode & 0o777) === 0o700,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_DRIFT"
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
      "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_DRIFT"
    );
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readCanonicalReceipt(filePath, secure) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_AMBIGUOUS";
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
        before.size <= MAX_RECEIPT_BYTES,
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
        named.dev === after.dev &&
        named.ino === after.ino &&
        named.uid === after.uid &&
        named.nlink === 1 &&
        (named.mode & 0o777) === 0o600 &&
        !named.isSymbolicLink() &&
        bytes.length === after.size,
      code
    );
    let parsed;
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(
      bytes.equals(Buffer.from(`${canonicalJson(parsed)}\n`, "utf8")),
      code
    );
    assertSameRoot(secure);
    return parsed;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function createOrReadCanonicalReceipt(filePath, value, secure) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(
    bytes.length > 0 && bytes.length <= MAX_RECEIPT_BYTES,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_WRITE_REJECTED"
  );
  publishOrReadExactOwnedFile({
    assertRoot: () => assertSameRoot(secure),
    bytes,
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_WRITE_REJECTED",
    filePath,
    maximumBytes: MAX_RECEIPT_BYTES,
    mode: 0o600,
    rootPath: secure.rootPath,
    uid: secure.expectedUid
  });
  const reread = readCanonicalReceipt(filePath, secure);
  requireCondition(
    canonicalJson(reread) === canonicalJson(value),
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_AMBIGUOUS"
  );
  return reread;
}

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export function reconstructIntegratedLiveDrillProviderFinalizationCompletion({
  context,
  schemaVersion
}) {
  requireCondition(
    schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  const normalizedContext = normalizeIntegratedLiveDrillProviderContext(
    context,
    { requireDispatchAuthorization: true }
  );
  const providerContinuity =
    reconstructIntegratedLiveDrillProviderRecoveryHandoff(normalizedContext);
  const verified = verifyIntegratedLiveDrillProviderEvidenceBundle({
    context: normalizedContext,
    providerContinuity,
    requireCompleteJournal: false
  });
  const recovery = verified.terminal.recovery;
  const finalization = finalizeIntegratedLiveDrillProviderRecovery({
    context: normalizedContext,
    providerContinuity
  });
  return withReceipt({
    schemaVersion: PROVIDER_SUPERVISOR_COMPLETION_SCHEMA,
    accepted: false,
    ambiguityBlocker:
      PROVIDER_ORCHESTRATION_AMBIGUITY_BLOCKER,
    authorizationId: normalizedContext.preCallIntent.authorizationId,
    finalReleaseReady: false,
    finalizationReceiptSha256: finalization.receiptSha256,
    observedInitializeCount: finalization.observedInitializeCount,
    observedInitializedNotificationCount:
      finalization.observedInitializedNotificationCount,
    observedSessionCloseCount: finalization.observedSessionCloseCount,
    observedToolsCallCount: finalization.observedToolsCallCount,
    preCallIntentSha256: normalizedContext.preCallIntent.intentSha256,
    providerBacked: false,
    providerHandoffReceiptSha256: providerContinuity.receiptSha256,
    recoveryReceiptSha256: integratedLiveDrillCanonicalSha256(recovery),
    runId: normalizedContext.preCallIntent.runId,
    stateHistory: Object.freeze([
      "DISPATCH_AUTHORIZATION_ACCEPTED",
      "PROVIDER_WORKER_HANDOFF_DURABLE",
      "PROVIDER_FINALIZATION_DURABLE"
    ]),
    status: "LOCAL_PROVIDER_SUPERVISOR_COMPLETED_NOT_RELEASED"
  });
}

export function validateIntegratedLiveDrillProviderFinalizationInput(value) {
  requireCondition(
    exactKeys(value, ["context", "providerContinuity", "schemaVersion"]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  let context;
  try {
    context = normalizeIntegratedLiveDrillProviderContext(value.context);
  } catch (cause) {
    reject(
      "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED",
      cause
    );
  }
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    context.preCallIntent,
    {
      authorization: context.authorization,
      controlLedgerReceipt: context.controlLedgerReceipt
    }
  );
  const handoff = validateIntegratedLiveDrillProviderRecoveryHandoff(
    value.providerContinuity
  );
  requireCondition(
    handoff.authorizationId === intent.authorizationId &&
      handoff.preCallIntentSha256 === intent.intentSha256 &&
      handoff.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  return Object.freeze({
    context,
    providerContinuity: handoff,
    schemaVersion: value.schemaVersion
  });
}

export function readIntegratedLiveDrillProviderFinalizationInput({
  forbiddenRootPath,
  inputPath,
  rootPath
}) {
  const code =
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED";
  const secure = secureIntegratedLiveDrillPrivateRoot(
    rootPath,
    forbiddenRootPath,
    code
  );
  const input = validateIntegratedLiveDrillProviderFinalizationInput(
    readIntegratedLiveDrillExactPrivateJson({
      code,
      filePath: inputPath,
      maximumBytes: MAX_RECEIPT_BYTES,
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

function validateComponentReceipt(value, expected) {
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactKeys(value, [...Object.keys(expected), "receiptSha256"]) &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body) &&
      canonicalJson(body) === canonicalJson(expected),
    "INTEGRATED_LIVE_DRILL_PROVIDER_COMPONENT_RECEIPT_REJECTED"
  );
  return Object.freeze({ ...value });
}

export function validateIntegratedLiveDrillProviderFinalizationReceipt(
  value,
  options
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_REJECTED";
  requireCondition(
    exactKeys(options, ["context", "providerContinuity"]),
    code
  );
  const input = validateIntegratedLiveDrillProviderFinalizationInput({
    context: Object.getOwnPropertyDescriptor(options, "context").value,
    providerContinuity: Object.getOwnPropertyDescriptor(
      options,
      "providerContinuity"
    ).value,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA
  });
  const keys = [
    "accepted",
    "authorizationId",
    "claimBoundary",
    "componentReceiptSha256",
    "contextCredentialMaterialAbsent",
    "contextExactSchemaValidated",
    "contextProviderCapabilityAbsent",
    "contextRawProviderResultAbsent",
    "contextRetryNamedKeyAbsent",
    "credentialOptionAccepted",
    "finalReleaseReady",
    "journalReceiptSha256",
    "logicalMcpRequestSha256",
    "observedInitializeCount",
    "observedInitializedNotificationCount",
    "observedSessionCloseCount",
    "observedToolsCallCount",
    "preCallIntentSha256",
    "providerBacked",
    "providerCapabilityAccepted",
    "providerHandoffReceiptSha256",
    "providerWorkerImportGraphProvenAbsent",
    "rawProviderResultAccepted",
    "receiptSha256",
    "retryNamedKeyAccepted",
    "runId",
    "schemaVersion",
    "status"
  ];
  requireCondition(exactKeys(value, keys), code);
  const normalized = Object.freeze(Object.fromEntries(keys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(value, key).value
  ])));
  const { receiptSha256, ...body } = normalized;
  const verified = verifyIntegratedLiveDrillProviderEvidenceBundle({
    context: input.context,
    providerContinuity: input.providerContinuity
  });
  const handoff = verified.handoff;
  requireCondition(
    normalized.schemaVersion ===
      INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_SCHEMA &&
      normalized.status === "LOCAL_FAKE_PRODUCTION_WIRING_VALIDATED" &&
      normalized.claimBoundary ===
        INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_CLAIM_BOUNDARY &&
      normalized.accepted === false &&
      normalized.providerBacked === false &&
      normalized.finalReleaseReady === false &&
      normalized.contextCredentialMaterialAbsent === true &&
      normalized.contextExactSchemaValidated === true &&
      normalized.contextProviderCapabilityAbsent === true &&
      normalized.contextRawProviderResultAbsent === true &&
      normalized.contextRetryNamedKeyAbsent === true &&
      normalized.credentialOptionAccepted === false &&
      normalized.providerCapabilityAccepted === false &&
      normalized.rawProviderResultAccepted === false &&
      normalized.retryNamedKeyAccepted === false &&
      normalized.providerWorkerImportGraphProvenAbsent === false &&
      [
        normalized.componentReceiptSha256,
        normalized.journalReceiptSha256,
        receiptSha256
      ].every((entry) => HEX_64.test(entry ?? "")) &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body) &&
      normalized.authorizationId === verified.intent.authorizationId &&
      normalized.runId === verified.intent.runId &&
      normalized.preCallIntentSha256 === verified.intent.intentSha256 &&
      normalized.logicalMcpRequestSha256 ===
        verified.intent.logicalMcpRequestSha256 &&
      normalized.providerHandoffReceiptSha256 === handoff.receiptSha256 &&
      normalized.journalReceiptSha256 === verified.journal.receiptSha256 &&
      normalized.observedInitializeCount === handoff.observedInitializeCount &&
      normalized.observedInitializedNotificationCount ===
        handoff.observedInitializedNotificationCount &&
      normalized.observedToolsCallCount === handoff.observedToolsCallCount &&
      normalized.observedSessionCloseCount ===
        handoff.observedSessionCloseCount,
    code
  );
  return normalized;
}

export function finalizeIntegratedLiveDrillProviderRecovery(args) {
  requireCondition(
    exactKeys(args, ["context", "providerContinuity"]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  const validatedInput = validateIntegratedLiveDrillProviderFinalizationInput({
    context: args.context,
    providerContinuity: args.providerContinuity,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA
  });
  const { context, providerContinuity } = validatedInput;
  const contextAssertions = integratedLiveDrillProviderContextAssertions(
    context
  );
  requireCondition(
    Object.values(contextAssertions).every((value) => value === true),
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    context?.preCallIntent,
    {
      authorization: context?.authorization,
      controlLedgerReceipt: context?.controlLedgerReceipt
    }
  );
  validateIntegratedLiveDrillProviderRecoveryHandoff(providerContinuity);
  verifyIntegratedLiveDrillProviderEvidenceBundle({
    context,
    providerContinuity,
    requireCompleteJournal: false
  });
  runIntegratedLiveDrillRecoveryContinuityW4(context);
  runIntegratedLiveDrillRecoveryContinuityW5({
    authorization: context.authorization,
    controlLedgerReceipt: context.controlLedgerReceipt,
    forbiddenRootPath: context.forbiddenRootPath,
    ledgerRootPath: context.ledgerRootPath
  });
  const verified = verifyIntegratedLiveDrillProviderEvidenceBundle({
    context,
    providerContinuity
  });
  const { handoff, intent, journal } = verified;
  const secure = secureRoot(
    context.recoveryEvidenceRootPath,
    context.forbiddenRootPath
  );
  assertIntegratedLiveDrillPrivateRootMatchesBinding(
    secure,
    context.evidenceRootBinding,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_REJECTED"
  );
  const componentBody = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_COMPONENT_RECEIPT_SCHEMA,
    accepted: false,
    authorizationId: intent.authorizationId,
    containsCredentialMaterial:
      !contextAssertions.credentialMaterialAbsent,
    containsRawProviderResult:
      !contextAssertions.rawProviderResultAbsent,
    contextCredentialMaterialAbsent:
      contextAssertions.credentialMaterialAbsent,
    contextExactSchemaValidated:
      contextAssertions.contextExactSchemaValidated,
    contextProviderCapabilityAbsent:
      contextAssertions.providerCapabilityAbsent,
    contextRawProviderResultAbsent:
      contextAssertions.rawProviderResultAbsent,
    contextRetryNamedKeyAbsent:
      contextAssertions.retryNamedKeyAbsent,
    finalReleaseReady: false,
    logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
    observedInitializeCount: handoff.observedInitializeCount,
    observedInitializedNotificationCount:
      handoff.observedInitializedNotificationCount,
    observedSessionCloseCount: handoff.observedSessionCloseCount,
    observedToolsCallCount: handoff.observedToolsCallCount,
    preCallIntentSha256: intent.intentSha256,
    preReadEvidenceReceiptSha256: handoff.preReadEvidenceReceiptSha256,
    providerBacked: false,
    providerEvidenceReceiptSha256: handoff.providerEvidenceReceiptSha256,
    providerHandoffReceiptSha256: handoff.receiptSha256,
    runId: intent.runId,
    status: "DURABLE_SANITIZED_COMPONENT_RECEIPT",
    terminalEvidenceReceiptSha256: handoff.terminalEvidenceReceiptSha256,
    transportEvidenceSha256: handoff.transportEvidenceSha256
  });
  const componentReceipt = validateComponentReceipt(
    createOrReadCanonicalReceipt(
      path.join(
        secure.rootPath,
        `${intent.authorizationId}.provider-recovery-component.json`
      ),
      withReceipt(componentBody),
      secure
    ),
    componentBody
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_SCHEMA,
    accepted: false,
    authorizationId: intent.authorizationId,
    componentReceiptSha256: componentReceipt.receiptSha256,
    contextCredentialMaterialAbsent:
      contextAssertions.credentialMaterialAbsent,
    contextExactSchemaValidated:
      contextAssertions.contextExactSchemaValidated,
    contextProviderCapabilityAbsent:
      contextAssertions.providerCapabilityAbsent,
    contextRawProviderResultAbsent:
      contextAssertions.rawProviderResultAbsent,
    contextRetryNamedKeyAbsent:
      contextAssertions.retryNamedKeyAbsent,
    credentialOptionAccepted:
      !contextAssertions.credentialMaterialAbsent,
    finalReleaseReady: false,
    journalReceiptSha256: journal.receiptSha256,
    logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
    observedInitializeCount: handoff.observedInitializeCount,
    observedInitializedNotificationCount:
      handoff.observedInitializedNotificationCount,
    observedSessionCloseCount: handoff.observedSessionCloseCount,
    observedToolsCallCount: handoff.observedToolsCallCount,
    preCallIntentSha256: intent.intentSha256,
    providerBacked: false,
    providerCapabilityAccepted:
      !contextAssertions.providerCapabilityAbsent,
    rawProviderResultAccepted:
      !contextAssertions.rawProviderResultAbsent,
    retryNamedKeyAccepted:
      !contextAssertions.retryNamedKeyAbsent,
    providerHandoffReceiptSha256: handoff.receiptSha256,
    providerWorkerImportGraphProvenAbsent: false,
    runId: intent.runId,
    status: "LOCAL_FAKE_PRODUCTION_WIRING_VALIDATED",
    claimBoundary: INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_CLAIM_BOUNDARY
  });
  return validateIntegratedLiveDrillProviderFinalizationReceipt(
    withReceipt(body),
    { context, providerContinuity }
  );
}
