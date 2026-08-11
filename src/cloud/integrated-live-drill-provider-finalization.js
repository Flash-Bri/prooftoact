import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "./canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256
} from "./integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
  runIntegratedLiveDrillRecoveryContinuityW4,
  runIntegratedLiveDrillRecoveryContinuityW5,
  validateIntegratedLiveDrillRecoveryContinuityJournal,
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent
} from "./integrated-live-drill-recovery-continuity.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_COMPONENT_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-provider-component-receipt.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_SCHEMA =
  "tideproof.highwater-drill-provider-finalization.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-finalization-input.v1";

const HANDOFF_SCHEMA =
  "tideproof.highwater-drill-provider-recovery-handoff.v1";
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_RECEIPT_BYTES = 64 * 1024;
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

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (
    !relative.startsWith("..") && !path.isAbsolute(relative)
  );
}

function secureRoot(rootPath, forbiddenRootPath) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_ROOT_REJECTED";
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
  let stat;
  try {
    canonicalRoot = fs.realpathSync(rootPath);
    canonicalForbidden = fs.realpathSync(forbiddenRootPath);
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
  return Object.freeze({ expectedUid, rootPath, stat });
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
    fs.writeFileSync(descriptor, bytes);
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
      reject(
        "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_WRITE_REJECTED",
        cause
      );
    }
  }
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

export function validateIntegratedLiveDrillProviderRecoveryHandoff(value) {
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactKeys(value, HANDOFF_KEYS) &&
      value.schemaVersion === HANDOFF_SCHEMA &&
      UUID.test(value.authorizationId ?? "") &&
      [
        value.logicalMcpRequestSha256,
        value.preCallIntentSha256,
        value.preReadEvidenceReceiptSha256,
        value.providerDispatchAuthorizationSha256,
        value.providerEvidenceReceiptSha256,
        value.terminalEvidenceReceiptSha256,
        value.transportEvidenceSha256,
        receiptSha256
      ].every((entry) => HEX_64.test(entry ?? "")) &&
      receiptSha256 === integratedLiveDrillCanonicalSha256(body) &&
      value.observedInitializeCount === 1 &&
      value.observedInitializedNotificationCount === 1 &&
      value.observedToolsCallCount === 1 &&
      value.observedSessionCloseCount === 1 &&
      value.sessionClosed === true &&
      value.preReadAuditReconciled === true &&
      value.terminalAuditReconciled === true &&
      value.w1W3ActualProviderPathIntegrated === true &&
      value.runAuthorizationDirectlyBindsExactRecoveryRequest === false &&
      value.separateExactProviderDispatchAuthorizationRequired === true &&
      value.separateExactProviderDispatchAuthorizationValidated === true &&
      value.postPrivateEvidenceReconciliationPathAvailable === true &&
      value.providerBacked === false &&
      value.accepted === false &&
      value.finalReleaseReady === false &&
      typeof value.claimBoundary === "string" &&
      value.claimBoundary.length > 0,
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_REJECTED"
  );
  return Object.freeze({ ...value });
}

export function validateIntegratedLiveDrillProviderFinalizationInput(value) {
  requireCondition(
    exactKeys(value, ["context", "providerContinuity", "schemaVersion"]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_SCHEMA,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    value.context?.preCallIntent,
    {
      authorization: value.context?.authorization,
      controlLedgerReceipt: value.context?.controlLedgerReceipt
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
    context: value.context,
    providerContinuity: handoff,
    schemaVersion: value.schemaVersion
  });
}

export function readIntegratedLiveDrillProviderFinalizationInput({
  forbiddenRootPath,
  inputPath,
  rootPath
}) {
  const secure = secureRoot(rootPath, forbiddenRootPath);
  requireCondition(
    typeof inputPath === "string" &&
      path.isAbsolute(inputPath) &&
      path.resolve(inputPath) === inputPath &&
      pathIsWithin(inputPath, secure.rootPath),
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  return validateIntegratedLiveDrillProviderFinalizationInput(
    readCanonicalReceipt(inputPath, secure)
  );
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

export function finalizeIntegratedLiveDrillProviderRecovery(args) {
  requireCondition(
    exactKeys(args, ["context", "providerContinuity"]),
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_INPUT_REJECTED"
  );
  const { context, providerContinuity } = args;
  const intent = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    context?.preCallIntent,
    {
      authorization: context?.authorization,
      controlLedgerReceipt: context?.controlLedgerReceipt
    }
  );
  const handoff = validateIntegratedLiveDrillProviderRecoveryHandoff(
    providerContinuity
  );
  requireCondition(
    handoff.authorizationId === intent.authorizationId &&
      handoff.preCallIntentSha256 === intent.intentSha256 &&
      handoff.logicalMcpRequestSha256 ===
        intent.logicalMcpRequestSha256,
    "INTEGRATED_LIVE_DRILL_PROVIDER_HANDOFF_BINDING_REJECTED"
  );
  const secure = secureRoot(
    context.recoveryEvidenceRootPath,
    context.forbiddenRootPath
  );
  const componentBody = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_COMPONENT_RECEIPT_SCHEMA,
    accepted: false,
    authorizationId: intent.authorizationId,
    containsCredentialMaterial: false,
    containsRawProviderResult: false,
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
  runIntegratedLiveDrillRecoveryContinuityW4(context);
  runIntegratedLiveDrillRecoveryContinuityW5({
    authorization: context.authorization,
    controlLedgerReceipt: context.controlLedgerReceipt,
    forbiddenRootPath: context.forbiddenRootPath,
    ledgerRootPath: context.ledgerRootPath
  });
  const journal = validateIntegratedLiveDrillRecoveryContinuityJournal(
    context
  );
  requireCondition(
    journal.status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE &&
      journal.logicalMcpRequestSha256 === intent.logicalMcpRequestSha256 &&
      HEX_64.test(journal.mcpResultSha256 ?? "") &&
      journal.sessionClosed === true,
    "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_REJECTED"
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_SCHEMA,
    accepted: false,
    authorizationId: intent.authorizationId,
    componentReceiptSha256: componentReceipt.receiptSha256,
    credentialOptionAccepted: false,
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
    providerCapabilityAccepted: false,
    providerHandoffReceiptSha256: handoff.receiptSha256,
    providerWorkerImportGraphProvenAbsent: false,
    runId: intent.runId,
    status: "LOCAL_FAKE_PRODUCTION_WIRING_VALIDATED",
    claimBoundary:
      "This provider-free W5 finalization process binds the sanitized W4 component receipt to the completed local continuity journal and the W1-W3 provider handoff without accepting a provider client, key, raw result, or retry authority. It validates exact locally observed transport counts but does not independently prove provider origin, live provider execution, process-level network denial, worker import-graph absence, cross-host continuity, deployment, acceptance, or release."
  });
  return withReceipt(body);
}
