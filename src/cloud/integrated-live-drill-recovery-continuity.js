import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillRunnerIdentityDigest,
  integratedLiveDrillSha256,
  validateIntegratedLiveDrillRunAuthorization,
  verifyIntegratedLiveDrillEvidence
} from "./integrated-live-drill-authorization.js";
import {
  validateIntegratedLiveDrillConsumedChildLaunch,
  validateIntegratedLiveDrillConsumedControlLedger
} from "./integrated-live-drill-control-ledger.js";
import {
  INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT,
  parseIntegratedLiveDrillChildAuthorization
} from "./integrated-live-drill-child-authorization.js";
import {
  canonicalRecoveryAttempt,
  normalizedRecoverySourceReceiptForContinuity,
  validateRecoveryAuditTargetIdentity,
  recoveryBrokerConfigDigest,
  recoveryQueryTemplateDigest,
  recoverySourceBindingDigestFor,
  renderRecoveryQuery,
  validatePersistedRecoveryBundleForContinuity
} from "./recovery-continuity-identity.js";

export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ENTRY_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-journal-entry.v2";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-journal-receipt.v2";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-unknown.v2";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_INTENT_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-pre-call-intent.v1";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE =
  "LOCAL_SAME_HOST_SCAFFOLD_COMPLETED_NO_RETRY";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN =
  "UNKNOWN_DO_NOT_ACT";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_LEDGER_FILE_BYTES = 64 * 1024;

const W1 = "W1_PRE_READ_CHECKPOINT";
const W2 = "W2_SINGLE_MCP_READ_AND_DURABLE_RESULT";
const W3 = "W3_TERMINAL_AUDIT_ACK_LOSS";
const W4 = "W4_RECEIPT_PUBLICATION_LOSS";
const W5 = "W5_NO_PROVIDER_RECONCILIATION";

export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN = Object.freeze([
  Object.freeze({ sequence: 1, worker: W1, event: "RUN_INTENT_DURABLE" }),
  Object.freeze({ sequence: 2, worker: W1, event: "W1_STARTED" }),
  Object.freeze({ sequence: 3, worker: W1, event: "PRE_READ_CHECKPOINT" }),
  Object.freeze({ sequence: 4, worker: W1, event: "W1_COMPLETED" }),
  Object.freeze({ sequence: 5, worker: W2, event: "W2_STARTED" }),
  Object.freeze({ sequence: 6, worker: W2, event: "MCP_CALL_CLAIMED" }),
  Object.freeze({ sequence: 7, worker: W2, event: "MCP_DISPATCH_MARKER_DURABLE" }),
  Object.freeze({
    sequence: 8,
    worker: W2,
    event: "MCP_RESULT_AND_CLOSE_DURABLE"
  }),
  Object.freeze({ sequence: 9, worker: W2, event: "W2_COMPLETED" }),
  Object.freeze({ sequence: 10, worker: W3, event: "W3_STARTED" }),
  Object.freeze({
    sequence: 11,
    worker: W3,
    event: "TERMINAL_AUDIT_ROW_VISIBLE_ACK_LOSS"
  }),
  Object.freeze({ sequence: 12, worker: W3, event: "W3_COMPLETED" }),
  Object.freeze({ sequence: 13, worker: W4, event: "W4_STARTED" }),
  Object.freeze({
    sequence: 14,
    worker: W4,
    event: "RECEIPT_DURABLE_PUBLICATION_LOSS"
  }),
  Object.freeze({ sequence: 15, worker: W4, event: "W4_COMPLETED" }),
  Object.freeze({ sequence: 16, worker: W5, event: "W5_STARTED" }),
  Object.freeze({ sequence: 17, worker: W5, event: "W5_COMPLETED" })
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

function secureLedgerRoot(ledgerRootPath, forbiddenRootPath) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ROOT_REJECTED";
  requireCondition(
    typeof ledgerRootPath === "string" &&
      path.isAbsolute(ledgerRootPath) &&
      path.resolve(ledgerRootPath) === ledgerRootPath &&
      typeof forbiddenRootPath === "string" &&
      path.isAbsolute(forbiddenRootPath) &&
      path.resolve(forbiddenRootPath) === forbiddenRootPath,
    code
  );
  let canonicalLedger;
  let canonicalForbidden;
  let stat;
  try {
    canonicalLedger = fs.realpathSync(ledgerRootPath);
    canonicalForbidden = fs.realpathSync(forbiddenRootPath);
    stat = fs.lstatSync(ledgerRootPath);
  } catch (cause) {
    reject(code, cause);
  }
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : stat.uid;
  requireCondition(
    canonicalLedger === ledgerRootPath &&
      stat.isDirectory() &&
      !stat.isSymbolicLink() &&
      stat.uid === expectedUid &&
      (stat.mode & 0o777) === 0o700 &&
      !pathIsWithin(canonicalLedger, canonicalForbidden),
    code
  );
  return Object.freeze({ expectedUid, ledgerRootPath, stat });
}

function assertSameRoot(secure) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ROOT_DRIFT";
  let current;
  try {
    current = fs.lstatSync(secure.ledgerRootPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    current.isDirectory() &&
      !current.isSymbolicLink() &&
      current.dev === secure.stat.dev &&
      current.ino === secure.stat.ino &&
      current.uid === secure.expectedUid &&
      (current.mode & 0o777) === 0o700,
    code
  );
}

function ledgerEntryPresent(filePath, secure) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS";
  try {
    assertSameRoot(secure);
    fs.lstatSync(filePath);
    assertSameRoot(secure);
    return true;
  } catch (cause) {
    if (cause?.code === "ENOENT") {
      assertSameRoot(secure);
      return false;
    }
    if (cause?.message ===
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ROOT_DRIFT") {
      throw cause;
    }
    reject(code, cause);
  }
}

function syncDirectory(secure) {
  let descriptor;
  try {
    assertSameRoot(secure);
    descriptor = fs.openSync(
      secure.ledgerRootPath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const opened = fs.fstatSync(descriptor);
    requireCondition(
      opened.dev === secure.stat.dev &&
        opened.ino === secure.stat.ino &&
        opened.uid === secure.expectedUid &&
        (opened.mode & 0o777) === 0o700,
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ROOT_DRIFT"
    );
    fs.fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readLedgerFile(filePath, secure) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS";
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
        before.size <= MAX_LEDGER_FILE_BYTES,
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
        after.size <= MAX_LEDGER_FILE_BYTES &&
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
    assertSameRoot(secure);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function parseCanonicalRecord(bytes) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS";
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
  return value;
}

function createDurableFile(filePath, body, secure) {
  const serialized = Buffer.from(`${canonicalJson(body)}\n`, "utf8");
  requireCondition(
    serialized.length > 0 && serialized.length <= MAX_LEDGER_FILE_BYTES,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_WRITE_REJECTED"
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
    const reread = readLedgerFile(filePath, secure);
    requireCondition(
      reread.equals(serialized),
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_REREAD_REJECTED"
    );
  } catch (cause) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve first error. */ }
    }
    if (cause?.code === "EEXIST") {
      reject("INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ALREADY_RECORDED");
    }
    if (cause?.message?.startsWith("INTEGRATED_LIVE_DRILL_")) throw cause;
    reject("INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_WRITE_REJECTED", cause);
  }
}

function fileName(authorizationId, step) {
  requireCondition(
    UUID.test(authorizationId ?? ""),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED"
  );
  return `${authorizationId}.recovery-continuity.` +
    `${String(step.sequence).padStart(2, "0")}.` +
    `${step.event.toLowerCase().replaceAll("_", "-")}.json`;
}

function journalFilePrefix(authorizationId) {
  return `${authorizationId}.recovery-continuity.`;
}

function unknownFileName(authorizationId) {
  return `${authorizationId}.recovery-continuity-unknown-do-not-act.json`;
}

function intentFileName(authorizationId) {
  return `${authorizationId}.recovery-continuity-intent.json`;
}

function unknownDispositionExists(secure, authorizationId) {
  return ledgerEntryPresent(path.join(
    secure.ledgerRootPath,
    unknownFileName(authorizationId)
  ), secure);
}

function unknownDoNotAct() {
  return Object.freeze({
    status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
    retryPermitted: false
  });
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

export function integratedLiveDrillRecoveryContinuityPreCallIntent({
  authorization,
  claim,
  controlLedgerReceipt,
  managedMcpReservation,
  consumedManagedMcpLaunch,
  consumedChildAuthorization,
  ledgerRootPath,
  forbiddenRootPath,
  recoveryEvidenceRootPath,
  recoverySourceReceipt,
  recoveryAppendReceipt,
  recoveryReplayReceipt,
  signedBundlePersistenceReceipt,
  recoveryBinding,
  audit,
  trustedRunContext,
  now = Date.now()
}) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED";
  requireCondition(
    exactKeys(trustedRunContext, [
      "committedTrustRoot",
      "expectation",
      "humanAuthorizationTrustRoot",
      "recoveryBrokerConfiguration",
      "runnerIdentity",
      "spec"
    ]),
    code
  );
  const trustedAuthorization = validateIntegratedLiveDrillRunAuthorization(
    authorization?.attestation,
    {
      spec: trustedRunContext.spec,
      expectation: trustedRunContext.expectation,
      committedTrustRoot: trustedRunContext.committedTrustRoot,
      humanAuthorizationTrustRoot:
        trustedRunContext.humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: ledgerRootPath,
      now
    }
  );
  requireCondition(
    canonicalJson(trustedAuthorization) === canonicalJson(authorization) &&
      trustedAuthorization.payload.authorizationClaimAuthority
        .runnerIdentitySha256 ===
          integratedLiveDrillRunnerIdentityDigest(
            trustedRunContext.runnerIdentity
          ),
    code
  );
  const ledger = validateIntegratedLiveDrillConsumedControlLedger({
    authorization: trustedAuthorization,
    claim,
    controlLedgerReceipt,
    ledgerRootPath,
    forbiddenRootPath
  });
  const resolvedControlLedgerReceipt = ledger.controlLedgerReceipt;
  const resolvedManagedMcpReservation = ledger.reservations[2];
  requireCondition(
    canonicalJson(managedMcpReservation) ===
      canonicalJson(resolvedManagedMcpReservation),
    code
  );
  const resolvedManagedMcpLaunch =
    validateIntegratedLiveDrillConsumedChildLaunch({
      authorization: trustedAuthorization,
      claim: ledger.claim,
      reservation: resolvedManagedMcpReservation,
      tokenId: consumedManagedMcpLaunch?.tokenId,
      launchReceipt: consumedManagedMcpLaunch,
      ledgerRootPath,
      forbiddenRootPath
    });
  const parsedChildAuthorization = parseIntegratedLiveDrillChildAuthorization(
    {
      [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]:
        canonicalJson(consumedChildAuthorization?.attestation)
    },
    "MANAGED_MCP_RECOVERY",
    { now }
  );
  const childPayload = verifyIntegratedLiveDrillEvidence(
    consumedChildAuthorization?.attestation,
    authorization.payload.childLaunchPublicKey,
    "tideproof.highwater-drill-child-launch-token.v1",
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_CHILD_AUTHORIZATION_REJECTED"
  );
  const childExpiresAt = exactIsoMilliseconds(childPayload?.expiresAt, code);
  const {
    receiptSha256: controlLedgerReceiptSha256,
    ...ledgerBody
  } = resolvedControlLedgerReceipt;
  const startedAt = exactIsoMilliseconds(audit?.startedAt, code);
  const expiresAt = exactIsoMilliseconds(
    authorization?.payload?.expiresAt,
    code
  );
  const normalizedRecoverySourceReceipt =
    normalizedRecoverySourceReceiptForContinuity(recoverySourceReceipt);
  const recoverySourceRecordedAt = Date.parse(
    normalizedRecoverySourceReceipt.recorded_at
  );
  const sourceDigest = recoverySourceBindingDigestFor({
    tenantId: normalizedRecoverySourceReceipt.tenant_id,
    runId: normalizedRecoverySourceReceipt.run_id,
    incidentId: normalizedRecoverySourceReceipt.incident_id,
    evidenceDigest: normalizedRecoverySourceReceipt.evidence_digest,
    resourceId: normalizedRecoverySourceReceipt.resource_id,
    operationId: normalizedRecoverySourceReceipt.operation_id,
    requestDigest: normalizedRecoverySourceReceipt.request_digest,
    proposalDigest: normalizedRecoverySourceReceipt.proposal_digest,
    logicalActionDigest: normalizedRecoverySourceReceipt.logical_action_digest,
    authorizationEpoch:
      normalizedRecoverySourceReceipt.authorization_epoch,
    logicalAuthorityKeySha256:
      normalizedRecoverySourceReceipt.logical_authority_key_sha256,
    authorizationBindingSha256:
      normalizedRecoverySourceReceipt.authorization_binding_sha256,
    authorityEvidenceBindingSha256:
      normalizedRecoverySourceReceipt.authority_evidence_binding_sha256,
    selectedEvidenceBindingSha256:
      normalizedRecoverySourceReceipt.selected_evidence_binding_sha256,
    outcome: normalizedRecoverySourceReceipt.outcome
  });
  const canonicalAttempt = canonicalRecoveryAttempt({
    tenantId: normalizedRecoverySourceReceipt.tenant_id,
    subjectBindingHash: recoveryBinding?.subjectBindingSha256,
    sourceDigest,
    sourceCommitTs: normalizedRecoverySourceReceipt.recorded_at
  });
  const persistedRecoveryBundle =
    validatePersistedRecoveryBundleForContinuity({
      destinationPath: path.join(
        recoveryEvidenceRootPath,
        `${trustedRunContext.spec.runId}.signed-recovery-bundle.json`
      ),
      evidenceRootPath: recoveryEvidenceRootPath,
      forbiddenRootPath,
      spec: trustedRunContext.spec,
      persistenceReceipt: signedBundlePersistenceReceipt,
      trustedPublisherKeys:
        trustedRunContext.committedTrustRoot.trustedPublisherKeys
    });
  const acceptedBundle = persistedRecoveryBundle.signedBundle;
  const validRecoveryPublicationReceipt = (receipt, outcomes) =>
    receipt &&
    typeof receipt === "object" &&
    !Array.isArray(receipt) &&
    outcomes.includes(receipt.outcome) &&
    receipt.bundleDigest === acceptedBundle.bundleDigest &&
    receipt.commit?.schemaVersion === "tideproof.database-commit-result.v1" &&
    receipt.commit?.status === "COMMITTED" &&
    receipt.commit?.operation === "recovery_publication" &&
    receipt.commit?.operationDigest === acceptedBundle.bundleDigest &&
    ["direct_ack", "read_reconciled"].includes(
      receipt.commit?.observation
    ) &&
    receipt.commit?.outcome === "bundle_present" &&
    receipt.commit?.authority?.current === null &&
    receipt.commit?.authority?.requiresFreshAuthorization === true &&
    receipt.commit?.reason === null &&
    Number.isFinite(Date.parse(receipt.commit?.databaseNow));
  const trustedRecoveryBrokerConfiguration =
    trustedRunContext.recoveryBrokerConfiguration;
  const acceptedAuditTargetIdentity = validateRecoveryAuditTargetIdentity(
    trustedRecoveryBrokerConfiguration?.auditTargetIdentity
  );
  const acceptedExpectedSourceClusterId =
    typeof trustedRecoveryBrokerConfiguration?.expectedSourceClusterId ===
      "string"
      ? trustedRecoveryBrokerConfiguration.expectedSourceClusterId.toLowerCase()
      : null;
  const acceptedRecoveryClusterId =
    typeof trustedRecoveryBrokerConfiguration?.recoveryClusterId === "string"
      ? trustedRecoveryBrokerConfiguration.recoveryClusterId.toLowerCase()
      : null;
  const expectedRecoveryBrokerConfigDigest = recoveryBrokerConfigDigest({
    recoveryClusterId: acceptedRecoveryClusterId,
    expectedSourceClusterId: acceptedExpectedSourceClusterId,
    buildIdentity: trustedRunContext.spec.sourceBuildIdentity,
    trustedPublisherKeys:
      trustedRunContext.committedTrustRoot.trustedPublisherKeys,
    auditTargetIdentity: acceptedAuditTargetIdentity
  });
  const auditTargetIdentitySha256 = integratedLiveDrillCanonicalSha256(
    acceptedAuditTargetIdentity
  );
  const signedBundlePersistenceReceiptSha256 =
    persistedRecoveryBundle.persistenceReceipt.receiptSha256;
  const signedBundleSha256 = persistedRecoveryBundle.signedBundleSha256;
  const databaseNameSha256 = integratedLiveDrillSha256(
    "tideproof_recovery"
  );
  const toolNameSha256 = integratedLiveDrillSha256("select_query");
  const queryTemplateSha256 = recoveryQueryTemplateDigest();
  const renderedQuerySha256 = integratedLiveDrillSha256(renderRecoveryQuery({
    tenantId: recoveryBinding?.tenantId,
    recoverySessionId: recoveryBinding?.recoverySessionId,
    subjectBindingHash: recoveryBinding?.subjectBindingSha256,
    sourceDigest
  }));
  const boundInputSha256 = integratedLiveDrillCanonicalSha256({
    tenantId: recoveryBinding?.tenantId,
    recoverySessionId: recoveryBinding?.recoverySessionId,
    subjectBindingHash: recoveryBinding?.subjectBindingSha256,
    sourceDigest
  });
  const logicalMcpRequest = Object.freeze({
    schemaVersion:
      "tideproof.highwater-drill-logical-managed-mcp-request.v1",
    boundInputSha256,
    databaseNameSha256,
    queryTemplateSha256,
    recoveryClusterId: recoveryBinding?.recoveryClusterId,
    recoverySessionId: recoveryBinding?.recoverySessionId,
    renderedQuerySha256,
    sourceDigest,
    subjectBindingSha256: recoveryBinding?.subjectBindingSha256,
    tenantId: recoveryBinding?.tenantId,
    toolNameSha256
  });
  requireCondition(
    authorization?.attestation &&
      authorization?.payload &&
      UUID.test(authorization.payload.authorizationId ?? "") &&
      UUID.test(authorization.payload.runId ?? "") &&
      HEX_40.test(authorization.payload.sourceCommit ?? "") &&
      HEX_40.test(authorization.payload.treeDigest ?? "") &&
      HEX_64.test(authorization.payload.configDigest ?? "") &&
      HEX_64.test(authorization.payload.specSha256 ?? "") &&
      HEX_64.test(authorization.payload.expectationSha256 ?? "") &&
      HEX_64.test(
        authorization.payload.authorizationClaimAuthority
          ?.runnerIdentitySha256 ?? ""
      ) &&
      authorization.issuedAt <= startedAt &&
      startedAt <= expiresAt &&
      authorization.expiresAt === expiresAt &&
      HEX_64.test(controlLedgerReceiptSha256 ?? "") &&
      controlLedgerReceiptSha256 ===
        integratedLiveDrillCanonicalSha256(ledgerBody) &&
      resolvedControlLedgerReceipt.authorizationId ===
        authorization.payload.authorizationId &&
      resolvedControlLedgerReceipt.runId === authorization.payload.runId &&
      HEX_64.test(
        resolvedControlLedgerReceipt.authorizationClaimSha256 ?? ""
      ) &&
      Array.isArray(resolvedControlLedgerReceipt.reservationDigests) &&
      resolvedControlLedgerReceipt.reservationDigests.length === 3 &&
      Array.isArray(resolvedControlLedgerReceipt.childLaunchDigests) &&
      resolvedControlLedgerReceipt.childLaunchDigests.length === 3 &&
      resolvedManagedMcpReservation.authorizationId ===
        authorization.payload.authorizationId &&
      resolvedManagedMcpReservation.scopeId === "MANAGED_MCP_RECOVERY" &&
      resolvedManagedMcpReservation.sequence === 3 &&
      HEX_64.test(resolvedManagedMcpReservation.reservationSha256 ?? "") &&
      resolvedControlLedgerReceipt.reservationDigests[2] ===
        resolvedManagedMcpReservation.reservationSha256 &&
      resolvedManagedMcpLaunch.authorizationId ===
        authorization.payload.authorizationId &&
      resolvedManagedMcpLaunch.scopeId === "MANAGED_MCP_RECOVERY" &&
      resolvedManagedMcpLaunch.sequence === 3 &&
      resolvedManagedMcpLaunch.reservationSha256 ===
        resolvedManagedMcpReservation.reservationSha256 &&
      UUID.test(resolvedManagedMcpLaunch.tokenId ?? "") &&
      HEX_64.test(resolvedManagedMcpLaunch.childLaunchSha256 ?? "") &&
      resolvedControlLedgerReceipt.childLaunchDigests[2] ===
        resolvedManagedMcpLaunch.childLaunchSha256 &&
      childPayload.authorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      childPayload.authorizationId === authorization.payload.authorizationId &&
      canonicalJson(childPayload) ===
        canonicalJson(parsedChildAuthorization.value) &&
      childPayload.runId === authorization.payload.runId &&
      childPayload.sourceCommit === authorization.payload.sourceCommit &&
      childPayload.treeDigest === authorization.payload.treeDigest &&
      childPayload.configDigest === authorization.payload.configDigest &&
      childPayload.specSha256 === authorization.payload.specSha256 &&
      childPayload.expectationSha256 ===
        integratedLiveDrillCanonicalSha256(trustedRunContext.expectation) &&
      childPayload.runnerIdentitySha256 ===
        authorization.payload.authorizationClaimAuthority
          .runnerIdentitySha256 &&
      childPayload.scope?.scopeId === "MANAGED_MCP_RECOVERY" &&
      childPayload.scope?.sequence === 3 &&
      canonicalJson(childPayload.scope) === canonicalJson(
        authorization.payload.spendAuthorization.scopes[2]
      ) &&
      childPayload.claim?.authorizationClaimSha256 ===
        ledger.claim.authorizationClaimSha256 &&
      canonicalJson(childPayload.claim) === canonicalJson(ledger.claim) &&
      childPayload.reservation?.reservationSha256 ===
        resolvedManagedMcpReservation.reservationSha256 &&
      canonicalJson(childPayload.reservation) ===
        canonicalJson(resolvedManagedMcpReservation) &&
      childPayload.tokenId === resolvedManagedMcpLaunch.tokenId &&
      childExpiresAt === authorization.expiresAt &&
      recoverySourceReceipt &&
      typeof recoverySourceReceipt === "object" &&
      !Array.isArray(recoverySourceReceipt) &&
      normalizedRecoverySourceReceipt.tenant_id === recoveryBinding.tenantId &&
      normalizedRecoverySourceReceipt.run_id === authorization.payload.runId &&
      recoverySourceRecordedAt <= now + 60 * 1_000 &&
      now - recoverySourceRecordedAt <=
        authorization.payload.maximumRecoverySourceAgeSeconds * 1_000 &&
      HEX_64.test(sourceDigest) &&
      acceptedBundle &&
      typeof acceptedBundle === "object" &&
      !Array.isArray(acceptedBundle) &&
      acceptedBundle.tenantId === recoveryBinding.tenantId &&
      acceptedBundle.recoverySessionId === recoveryBinding.recoverySessionId &&
      acceptedBundle.subjectBindingHash ===
        recoveryBinding.subjectBindingSha256 &&
      acceptedBundle.sourceDigest === sourceDigest &&
      acceptedBundle.sourceClusterId === acceptedExpectedSourceClusterId &&
      acceptedBundle.sourceCommitTs ===
        normalizedRecoverySourceReceipt.recorded_at &&
      acceptedBundle.snapshotVersion === canonicalAttempt.snapshotVersion &&
      Date.parse(acceptedBundle.expiresAt) > now &&
      persistedRecoveryBundle.persistenceReceipt.signedBundleSha256 ===
        signedBundleSha256 &&
      persistedRecoveryBundle.persistenceReceipt.bundleDigest ===
        acceptedBundle.bundleDigest &&
      persistedRecoveryBundle.persistenceReceipt.sourceCommit ===
        authorization.payload.sourceCommit &&
      persistedRecoveryBundle.persistenceReceipt.treeDigest ===
        authorization.payload.treeDigest &&
      persistedRecoveryBundle.persistenceReceipt.configDigest ===
        authorization.payload.configDigest &&
      persistedRecoveryBundle.persistenceReceipt.runId ===
        authorization.payload.runId &&
      validRecoveryPublicationReceipt(recoveryAppendReceipt, [
        "bundle_appended",
        "bundle_replay",
        "bundle_present"
      ]) &&
      validRecoveryPublicationReceipt(recoveryReplayReceipt, [
        "bundle_replay"
      ]) &&
      exactKeys(recoveryBinding, [
        "recoveryClusterId",
        "recoverySessionId",
        "subjectBindingSha256",
        "tenantId"
      ]) &&
      UUID.test(recoveryBinding.tenantId ?? "") &&
      UUID.test(recoveryBinding.recoverySessionId ?? "") &&
      UUID.test(recoveryBinding.recoveryClusterId ?? "") &&
      exactKeys(trustedRecoveryBrokerConfiguration, [
        "auditTargetIdentity",
        "expectedSourceClusterId",
        "recoveryBrokerConfigDigest",
        "recoveryClusterId"
      ]) &&
      UUID.test(acceptedExpectedSourceClusterId ?? "") &&
      UUID.test(acceptedRecoveryClusterId ?? "") &&
      HEX_64.test(
        trustedRecoveryBrokerConfiguration.recoveryBrokerConfigDigest ?? ""
      ) &&
      trustedRecoveryBrokerConfiguration.recoveryBrokerConfigDigest ===
        expectedRecoveryBrokerConfigDigest &&
      acceptedRecoveryClusterId === recoveryBinding.recoveryClusterId &&
      acceptedExpectedSourceClusterId !== acceptedRecoveryClusterId &&
      recoveryBinding.recoverySessionId ===
        canonicalAttempt.recoverySessionId &&
      HEX_64.test(recoveryBinding.subjectBindingSha256 ?? "") &&
      exactKeys(audit, [
        "interactionId",
        "preReadAuditEventId",
        "startedAt",
        "terminalAuditEventId"
      ]) &&
      UUID.test(audit.interactionId ?? "") &&
      UUID.test(audit.preReadAuditEventId ?? "") &&
      UUID.test(audit.terminalAuditEventId ?? "") &&
      new Set([
        audit.interactionId,
        audit.preReadAuditEventId,
        audit.terminalAuditEventId
      ]).size === 3 &&
      audit.preReadAuditEventId !== audit.terminalAuditEventId &&
      authorization.payload.requiredManagedMcpToolCallCount === 1 &&
      authorization.payload.requiredRecoveryJournalEntryCount ===
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.length &&
      canonicalJson(authorization.payload.requiredRecoveryWorkers) ===
        canonicalJson(INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS) &&
      canonicalJson(authorization.payload.requiredRecoveryFailpoints) ===
        canonicalJson(INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS),
    code
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_INTENT_SCHEMA,
    auditTargetIdentitySha256,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationClaimSha256:
      resolvedControlLedgerReceipt.authorizationClaimSha256,
    authorizationId: authorization.payload.authorizationId,
    boundInputSha256,
    configDigest: authorization.payload.configDigest,
    consumedManagedMcpLaunchSha256:
      resolvedManagedMcpLaunch.childLaunchSha256,
    consumedManagedMcpLaunchTokenId: resolvedManagedMcpLaunch.tokenId,
    consumedChildAuthorizationSha256:
      integratedLiveDrillCanonicalSha256(
        consumedChildAuthorization.attestation
      ),
    childAuthorizationExpiresAt: new Date(childExpiresAt).toISOString(),
    controlLedgerReceiptSha256,
    databaseNameSha256,
    expectationSha256: authorization.payload.expectationSha256,
    expiresAt: authorization.payload.expiresAt,
    expectedSourceClusterId: acceptedExpectedSourceClusterId,
    logicalMcpRequestSha256:
      integratedLiveDrillCanonicalSha256(logicalMcpRequest),
    managedMcpReservationSha256:
      resolvedManagedMcpReservation.reservationSha256,
    preReadAuditEventId: audit.preReadAuditEventId,
    interactionId: audit.interactionId,
    queryTemplateSha256,
    recoveryBrokerConfigDigest: expectedRecoveryBrokerConfigDigest,
    recoveryClusterId: recoveryBinding.recoveryClusterId,
    recoverySessionId: recoveryBinding.recoverySessionId,
    recoverySourceReceiptSha256:
      integratedLiveDrillCanonicalSha256(normalizedRecoverySourceReceipt),
    recoveryAppendReceiptSha256:
      integratedLiveDrillCanonicalSha256(recoveryAppendReceipt),
    recoveryReplayReceiptSha256:
      integratedLiveDrillCanonicalSha256(recoveryReplayReceipt),
    recoverySourceOperationId:
      normalizedRecoverySourceReceipt.operation_id,
    recoverySourceRequestDigest:
      normalizedRecoverySourceReceipt.request_digest,
    renderedQuerySha256,
    runId: authorization.payload.runId,
    runnerIdentitySha256:
      authorization.payload.authorizationClaimAuthority.runnerIdentitySha256,
    signedBundlePersistenceReceiptSha256:
      signedBundlePersistenceReceiptSha256,
    signedBundleSha256,
    sourceCommit: authorization.payload.sourceCommit,
    sourceClusterId: acceptedBundle.sourceClusterId,
    sourceDigest,
    specSha256: authorization.payload.specSha256,
    startedAt: audit.startedAt,
    subjectBindingSha256: recoveryBinding.subjectBindingSha256,
    tenantId: recoveryBinding.tenantId,
    terminalAuditEventId: audit.terminalAuditEventId,
    toolNameSha256,
    treeDigest: authorization.payload.treeDigest
  });
  return Object.freeze({
    ...body,
    intentSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export function validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
  value,
  { authorization, controlLedgerReceipt }
) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED";
  const { intentSha256, ...body } = value ?? {};
  const { receiptSha256: controlLedgerReceiptSha256, ...ledgerBody } =
    controlLedgerReceipt ?? {};
  const startedAt = exactIsoMilliseconds(body.startedAt, code);
  const expiresAt = exactIsoMilliseconds(body.expiresAt, code);
  const childExpiresAt = exactIsoMilliseconds(
    body.childAuthorizationExpiresAt,
    code
  );
  requireCondition(
    exactKeys(value, [
      "auditTargetIdentitySha256",
      "authorizationAttestationSha256",
      "authorizationClaimSha256",
      "authorizationId",
      "boundInputSha256",
      "childAuthorizationExpiresAt",
      "configDigest",
      "consumedChildAuthorizationSha256",
      "consumedManagedMcpLaunchSha256",
      "consumedManagedMcpLaunchTokenId",
      "controlLedgerReceiptSha256",
      "databaseNameSha256",
      "expectationSha256",
      "expiresAt",
      "expectedSourceClusterId",
      "intentSha256",
      "interactionId",
      "logicalMcpRequestSha256",
      "managedMcpReservationSha256",
      "preReadAuditEventId",
      "queryTemplateSha256",
      "recoveryBrokerConfigDigest",
      "recoveryAppendReceiptSha256",
      "recoveryClusterId",
      "recoveryReplayReceiptSha256",
      "recoverySessionId",
      "recoverySourceOperationId",
      "recoverySourceRequestDigest",
      "recoverySourceReceiptSha256",
      "renderedQuerySha256",
      "runId",
      "runnerIdentitySha256",
      "schemaVersion",
      "signedBundlePersistenceReceiptSha256",
      "signedBundleSha256",
      "sourceCommit",
      "sourceClusterId",
      "sourceDigest",
      "specSha256",
      "startedAt",
      "subjectBindingSha256",
      "tenantId",
      "terminalAuditEventId",
      "toolNameSha256",
      "treeDigest"
    ]) &&
      body.schemaVersion ===
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_INTENT_SCHEMA &&
      HEX_64.test(body.auditTargetIdentitySha256 ?? "") &&
      intentSha256 === integratedLiveDrillCanonicalSha256(body) &&
      body.authorizationAttestationSha256 ===
        integratedLiveDrillAuthorizationAttestationDigest(
          authorization.attestation
        ) &&
      body.authorizationClaimSha256 ===
        controlLedgerReceipt.authorizationClaimSha256 &&
      body.authorizationId === authorization.payload.authorizationId &&
      body.configDigest === authorization.payload.configDigest &&
      body.controlLedgerReceiptSha256 === controlLedgerReceiptSha256 &&
      controlLedgerReceiptSha256 ===
        integratedLiveDrillCanonicalSha256(ledgerBody) &&
      body.expectationSha256 === authorization.payload.expectationSha256 &&
      body.expiresAt === authorization.payload.expiresAt &&
      expiresAt === authorization.expiresAt &&
      childExpiresAt === expiresAt &&
      startedAt >= authorization.issuedAt &&
      startedAt <= authorization.expiresAt &&
      body.runId === authorization.payload.runId &&
      body.runnerIdentitySha256 ===
        authorization.payload.authorizationClaimAuthority
          .runnerIdentitySha256 &&
      body.sourceCommit === authorization.payload.sourceCommit &&
      body.specSha256 === authorization.payload.specSha256 &&
      body.treeDigest === authorization.payload.treeDigest &&
      UUID.test(body.authorizationId ?? "") &&
      UUID.test(body.runId ?? "") &&
      UUID.test(body.preReadAuditEventId ?? "") &&
      UUID.test(body.terminalAuditEventId ?? "") &&
      UUID.test(body.interactionId ?? "") &&
      new Set([
        body.interactionId,
        body.preReadAuditEventId,
        body.terminalAuditEventId
      ]).size === 3 &&
      UUID.test(body.tenantId ?? "") &&
      UUID.test(body.recoverySessionId ?? "") &&
      UUID.test(body.recoveryClusterId ?? "") &&
      UUID.test(body.expectedSourceClusterId ?? "") &&
      UUID.test(body.sourceClusterId ?? "") &&
      body.expectedSourceClusterId === body.sourceClusterId &&
      body.expectedSourceClusterId !== body.recoveryClusterId &&
      HEX_64.test(body.recoveryBrokerConfigDigest ?? "") &&
      UUID.test(body.recoverySourceOperationId ?? "") &&
      UUID.test(body.consumedManagedMcpLaunchTokenId ?? "") &&
      body.databaseNameSha256 ===
        integratedLiveDrillSha256("tideproof_recovery") &&
      body.toolNameSha256 === integratedLiveDrillSha256("select_query") &&
      body.queryTemplateSha256 === recoveryQueryTemplateDigest() &&
      body.renderedQuerySha256 === integratedLiveDrillSha256(
        renderRecoveryQuery({
          tenantId: body.tenantId,
          recoverySessionId: body.recoverySessionId,
          subjectBindingHash: body.subjectBindingSha256,
          sourceDigest: body.sourceDigest
        })
      ) &&
      body.boundInputSha256 === integratedLiveDrillCanonicalSha256({
        tenantId: body.tenantId,
        recoverySessionId: body.recoverySessionId,
        subjectBindingHash: body.subjectBindingSha256,
        sourceDigest: body.sourceDigest
      }) &&
      body.logicalMcpRequestSha256 === integratedLiveDrillCanonicalSha256({
        schemaVersion:
          "tideproof.highwater-drill-logical-managed-mcp-request.v1",
        boundInputSha256: body.boundInputSha256,
        databaseNameSha256: body.databaseNameSha256,
        queryTemplateSha256: body.queryTemplateSha256,
        recoveryClusterId: body.recoveryClusterId,
        recoverySessionId: body.recoverySessionId,
        renderedQuerySha256: body.renderedQuerySha256,
        sourceDigest: body.sourceDigest,
        subjectBindingSha256: body.subjectBindingSha256,
        tenantId: body.tenantId,
        toolNameSha256: body.toolNameSha256
      }) &&
      authorization.payload.requiredManagedMcpToolCallCount === 1 &&
      [
        body.authorizationAttestationSha256,
        body.authorizationClaimSha256,
        body.boundInputSha256,
        body.configDigest,
        body.consumedChildAuthorizationSha256,
        body.consumedManagedMcpLaunchSha256,
        body.controlLedgerReceiptSha256,
        body.databaseNameSha256,
        body.expectationSha256,
        body.logicalMcpRequestSha256,
        body.managedMcpReservationSha256,
        body.queryTemplateSha256,
        body.recoveryBrokerConfigDigest,
        body.recoveryAppendReceiptSha256,
        body.recoveryReplayReceiptSha256,
        body.recoverySourceRequestDigest,
        body.recoverySourceReceiptSha256,
        body.sourceDigest,
        body.renderedQuerySha256,
        body.runnerIdentitySha256,
        body.signedBundlePersistenceReceiptSha256,
        body.signedBundleSha256,
        body.specSha256,
        body.subjectBindingSha256,
        body.toolNameSha256
      ].every((entry) => HEX_64.test(entry ?? "")) &&
      controlLedgerReceipt.reservationDigests?.[2] ===
        body.managedMcpReservationSha256 &&
      controlLedgerReceipt.childLaunchDigests?.[2] ===
        body.consumedManagedMcpLaunchSha256,
    code
  );
  return Object.freeze(value);
}

function readPersistedPreCallIntent(context, secure) {
  const authorizationId = context.authorization?.payload?.authorizationId;
  requireCondition(
    UUID.test(authorizationId ?? ""),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED"
  );
  const value = parseCanonicalRecord(readLedgerFile(
    path.join(secure.ledgerRootPath, intentFileName(authorizationId)),
    secure
  ));
  const validated = validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    value,
    context
  );
  if (context.preCallIntent !== undefined) {
    requireCondition(
      canonicalJson(context.preCallIntent) === canonicalJson(validated),
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED"
    );
  }
  return validated;
}

function assemblePreCallIntent(context, now) {
  const preCallInputKeys = [
    "audit",
    "claim",
    "consumedChildAuthorization",
    "consumedManagedMcpLaunch",
    "controlLedgerReceipt",
    "managedMcpReservation",
    "recoveryBinding",
    "recoveryAppendReceipt",
    "recoveryReplayReceipt",
    "recoverySourceReceipt",
    "signedBundlePersistenceReceipt"
  ];
  requireCondition(
    context.preCallInputs &&
      typeof context.preCallInputs === "object" &&
      !Array.isArray(context.preCallInputs) &&
      exactKeys(context.preCallInputs, preCallInputKeys),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED"
  );
  return integratedLiveDrillRecoveryContinuityPreCallIntent({
    ...context.preCallInputs,
    authorization: context.authorization,
    ledgerRootPath: context.ledgerRootPath,
    forbiddenRootPath: context.forbiddenRootPath,
    recoveryEvidenceRootPath: context.recoveryEvidenceRootPath,
    trustedRunContext: context.trustedRunContext,
    now
  });
}

function persistPreCallIntent(context, trustedClock) {
  const secure = secureLedgerRoot(
    context.ledgerRootPath,
    context.forbiddenRootPath
  );
  const value = assemblePreCallIntent(context, trustedClock());
  if (context.preCallIntent !== undefined) {
    requireCondition(
      canonicalJson(context.preCallIntent) === canonicalJson(value),
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED"
    );
  }
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(
    value,
    context
  );
  const filePath = path.join(
    secure.ledgerRootPath,
    intentFileName(value.authorizationId)
  );
  try {
    createDurableFile(filePath, value, secure);
  } catch (cause) {
    if (
      cause?.message !==
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ALREADY_RECORDED"
    ) {
      throw cause;
    }
  }
  return readPersistedPreCallIntent(context, secure);
}

function assertProviderCapableContextCurrent(context, secure, trustedClock) {
  requireCondition(
    typeof trustedClock === "function",
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AUTHORIZATION_EXPIRED"
  );
  const now = trustedClock();
  requireCondition(
    context.preCallIntent !== undefined &&
      Number.isSafeInteger(now) &&
      now >= context.authorization.issuedAt &&
      now <= context.authorization.expiresAt,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AUTHORIZATION_EXPIRED"
  );
  const assembled = assemblePreCallIntent(context, now);
  const persisted = readPersistedPreCallIntent(context, secure);
  const childExpiresAt = Date.parse(assembled.childAuthorizationExpiresAt);
  requireCondition(
    canonicalJson(assembled) === canonicalJson(context.preCallIntent) &&
      canonicalJson(assembled) === canonicalJson(persisted) &&
      Number.isFinite(childExpiresAt) &&
      now <= childExpiresAt,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AUTHORIZATION_EXPIRED"
  );
  return assembled;
}

function bindings(context, secure) {
  const intent = readPersistedPreCallIntent(context, secure);
  return Object.freeze({
    authorizationAttestationSha256: intent.authorizationAttestationSha256,
    authorizationClaimSha256: intent.authorizationClaimSha256,
    authorizationId: intent.authorizationId,
    configDigest: intent.configDigest,
    controlLedgerReceiptSha256: intent.controlLedgerReceiptSha256,
    logicalMcpRequestSha256: intent.logicalMcpRequestSha256,
    preCallIntentSha256: intent.intentSha256,
    runId: intent.runId,
    sourceCommit: intent.sourceCommit,
    treeDigest: intent.treeDigest
  });
}

function defaultArtifact(step) {
  if (step.event === "W5_STARTED") {
    return Object.freeze({
      topLevelProviderClientOptionReceived: false,
      providerClientInvoked: false,
      reconciliation: "CLAIM_AND_COMPLETE_RESULT_PRESENT"
    });
  }
  if (step.event === "W5_COMPLETED") {
    return Object.freeze({
      disposition: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
      mcpRetryCount: 0
    });
  }
  return Object.freeze({ status: "DURABLE" });
}

function validateArtifact(step, artifact) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS";
  if (step.event === "MCP_CALL_CLAIMED") {
    requireCondition(
      exactKeys(artifact, [
        "attemptOwnershipTokenSha256",
        "disposition"
      ]) &&
        HEX_64.test(artifact.attemptOwnershipTokenSha256 ?? "") &&
        artifact.disposition === "CLAIMED_BEFORE_DISPATCH",
      code
    );
    return;
  }
  if (step.event === "MCP_DISPATCH_MARKER_DURABLE") {
    requireCondition(
      exactKeys(artifact, [
        "attemptOwnershipTokenSha256",
        "disposition"
      ]) &&
        HEX_64.test(artifact.attemptOwnershipTokenSha256 ?? "") &&
        artifact.disposition === "DURABLE_BEFORE_BOUND_CALL",
      code
    );
    return;
  }
  if (step.event === "MCP_RESULT_AND_CLOSE_DURABLE") {
    requireCondition(
      exactKeys(artifact, [
        "mcpResultSha256",
        "sessionCloseSha256",
        "sessionClosed"
      ]) &&
        HEX_64.test(artifact.mcpResultSha256 ?? "") &&
        HEX_64.test(artifact.sessionCloseSha256 ?? "") &&
        artifact.sessionClosed === true,
      code
    );
    return;
  }
  requireCondition(
    canonicalJson(artifact) === canonicalJson(defaultArtifact(step)),
    code
  );
}

function validateEntry(value, expected, previousDigest, bound) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS";
  requireCondition(
    exactKeys(value, [
      "artifact",
      "authorizationAttestationSha256",
      "authorizationClaimSha256",
      "authorizationId",
      "configDigest",
      "controlLedgerReceiptSha256",
      "event",
      "logicalMcpRequestSha256",
      "preCallIntentSha256",
      "previousEntrySha256",
      "recordedAt",
      "runId",
      "schemaVersion",
      "sequence",
      "sourceCommit",
      "treeDigest",
      "worker"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ENTRY_SCHEMA &&
      value.authorizationAttestationSha256 ===
        bound.authorizationAttestationSha256 &&
      value.authorizationClaimSha256 === bound.authorizationClaimSha256 &&
      value.authorizationId === bound.authorizationId &&
      value.configDigest === bound.configDigest &&
      value.controlLedgerReceiptSha256 ===
        bound.controlLedgerReceiptSha256 &&
      value.event === expected.event &&
      value.logicalMcpRequestSha256 === bound.logicalMcpRequestSha256 &&
      value.preCallIntentSha256 === bound.preCallIntentSha256 &&
      value.previousEntrySha256 === previousDigest &&
      value.runId === bound.runId &&
      value.sequence === expected.sequence &&
      value.sourceCommit === bound.sourceCommit &&
      value.treeDigest === bound.treeDigest &&
      value.worker === expected.worker,
    code
  );
  const recordedAt = Date.parse(value.recordedAt);
  requireCondition(
    typeof value.recordedAt === "string" &&
      Number.isFinite(recordedAt) &&
      new Date(recordedAt).toISOString() === value.recordedAt,
    code
  );
  validateArtifact(expected, value.artifact);
  return recordedAt;
}

function readEntries(context, secure, { allowPartial = true } = {}) {
  const bound = bindings(context, secure);
  const journalStartedAt = Date.parse(
    readPersistedPreCallIntent(context, secure).startedAt
  );
  const names = fs.readdirSync(secure.ledgerRootPath)
    .filter((name) => name.startsWith(journalFilePrefix(bound.authorizationId)))
    .sort();
  requireCondition(
    names.length <= INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.length,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  const entries = [];
  const digests = [];
  let previousDigest = null;
  let previousTime = journalStartedAt;
  for (const [index, name] of names.entries()) {
    const expected = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[index];
    requireCondition(
      name === fileName(bound.authorizationId, expected),
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
    );
    const body = parseCanonicalRecord(readLedgerFile(
      path.join(secure.ledgerRootPath, name),
      secure
    ));
    const recordedAt = validateEntry(body, expected, previousDigest, bound);
    requireCondition(
      recordedAt >= previousTime &&
        recordedAt >= journalStartedAt,
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
    );
    const digest = integratedLiveDrillCanonicalSha256(body);
    entries.push(Object.freeze(body));
    digests.push(digest);
    previousDigest = digest;
    previousTime = recordedAt;
  }
  requireCondition(
    allowPartial ||
      entries.length === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.length,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_INCOMPLETE"
  );
  return Object.freeze({
    bound,
    digests: Object.freeze(digests),
    entries: Object.freeze(entries),
    previousDigest,
    previousTime
  });
}

function readUnknownDisposition(
  context,
  secure,
  bound = bindings(context, secure)
) {
  const filePath = path.join(
    secure.ledgerRootPath,
    unknownFileName(bound.authorizationId)
  );
  if (!ledgerEntryPresent(filePath, secure)) return null;
  const body = parseCanonicalRecord(readLedgerFile(filePath, secure));
  const recordedAt = Date.parse(body?.recordedAt);
  requireCondition(
    exactKeys(body, [
      "authorizationAttestationSha256",
      "authorizationClaimSha256",
      "authorizationId",
      "controlLedgerReceiptSha256",
      "logicalMcpRequestSha256",
      "mcpCallClaimEntrySha256",
      "preCallIntentSha256",
      "reason",
      "recordedAt",
      "schemaVersion",
      "status"
    ]) &&
      body.schemaVersion ===
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN_SCHEMA &&
      body.authorizationAttestationSha256 ===
        bound.authorizationAttestationSha256 &&
      body.authorizationClaimSha256 === bound.authorizationClaimSha256 &&
      body.authorizationId === bound.authorizationId &&
      body.controlLedgerReceiptSha256 ===
        bound.controlLedgerReceiptSha256 &&
      body.logicalMcpRequestSha256 === bound.logicalMcpRequestSha256 &&
      HEX_64.test(body.mcpCallClaimEntrySha256 ?? "") &&
      body.preCallIntentSha256 === bound.preCallIntentSha256 &&
      body.reason === "CLAIM_PRESENT_RESULT_ABSENT" &&
      typeof body.recordedAt === "string" &&
      Number.isFinite(recordedAt) &&
      new Date(recordedAt).toISOString() === body.recordedAt &&
      recordedAt >= Date.parse(
        readPersistedPreCallIntent(context, secure).startedAt
      ) &&
      body.status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  return Object.freeze(body);
}

function persistUnknownDisposition(context, secure, journal, now) {
  const bound = journal.bound;
  if (unknownDispositionExists(secure, bound.authorizationId)) return null;
  requireCondition(
    journal.entries.length >= 6 &&
      journal.entries.length < 8 &&
      Number.isSafeInteger(now) &&
      now >= journal.previousTime,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN_SCHEMA,
    authorizationAttestationSha256:
      bound.authorizationAttestationSha256,
    authorizationClaimSha256: bound.authorizationClaimSha256,
    authorizationId: bound.authorizationId,
    controlLedgerReceiptSha256: bound.controlLedgerReceiptSha256,
    logicalMcpRequestSha256: bound.logicalMcpRequestSha256,
    mcpCallClaimEntrySha256: journal.digests[5],
    preCallIntentSha256: bound.preCallIntentSha256,
    reason: "CLAIM_PRESENT_RESULT_ABSENT",
    recordedAt: new Date(now).toISOString(),
    status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
  });
  try {
    createDurableFile(
      path.join(
        secure.ledgerRootPath,
        unknownFileName(bound.authorizationId)
      ),
      body,
      secure
    );
  } catch (cause) {
    if (
      cause?.message !==
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ALREADY_RECORDED"
    ) {
      throw cause;
    }
    return null;
  }
  return body;
}

function recordStep(
  context,
  step,
  artifact,
  now,
  { acceptExistingArtifact = false } = {}
) {
  const secure = secureLedgerRoot(
    context.ledgerRootPath,
    context.forbiddenRootPath
  );
  const journal = readEntries(context, secure);
  if (journal.entries.length >= step.sequence) {
    const existing = journal.entries[step.sequence - 1];
    if (artifact !== undefined && !acceptExistingArtifact) {
      requireCondition(
        canonicalJson(existing.artifact) === canonicalJson(artifact),
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
      );
    }
    return Object.freeze({ created: false, entry: existing });
  }
  requireCondition(
    journal.entries.length === step.sequence - 1 &&
      Number.isSafeInteger(now) &&
      now >= journal.previousTime,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ORDER_REJECTED"
  );
  const bound = journal.bound;
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ENTRY_SCHEMA,
    ...bound,
    artifact: artifact ?? defaultArtifact(step),
    event: step.event,
    previousEntrySha256: journal.previousDigest,
    recordedAt: new Date(now).toISOString(),
    sequence: step.sequence,
    worker: step.worker
  });
  validateEntry(body, step, journal.previousDigest, bound);
  try {
    createDurableFile(
      path.join(context.ledgerRootPath, fileName(bound.authorizationId, step)),
      body,
      secure
    );
  } catch (cause) {
    if (
      cause?.message !==
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ALREADY_RECORDED"
    ) {
      throw cause;
    }
    if (acceptExistingArtifact) {
      return Object.freeze({ created: false, entry: null });
    }
    const raced = readEntries(context, secure);
    requireCondition(
      raced.entries.length >= step.sequence,
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
    );
    const existing = raced.entries[step.sequence - 1];
    if (artifact !== undefined && !acceptExistingArtifact) {
      requireCondition(
        canonicalJson(existing.artifact) === canonicalJson(artifact),
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
      );
    }
    return Object.freeze({ created: false, entry: existing });
  }
  return Object.freeze({ created: true, entry: body });
}

function syntheticCrash(event) {
  reject(`INTEGRATED_LIVE_DRILL_SYNTHETIC_CRASH_${event}`);
}

function journalNow(trustedClock) {
  const now = trustedClock();
  requireCondition(
    Number.isSafeInteger(now),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_TIME_REJECTED"
  );
  return now;
}

function requirePublicWorkerOptions(options, keys) {
  requireCondition(
    options &&
      typeof options === "object" &&
      !Array.isArray(options) &&
      Object.keys(options).every((key) => keys.includes(key)),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_OPTIONS_REJECTED"
  );
}

function maybeCrash(options, event) {
  if (options?.crashAfterEvent === event) syntheticCrash(event);
}

function runIntegratedLiveDrillRecoveryContinuityW1Internal(
  context,
  options,
  trustedClock
) {
  const secure = secureLedgerRoot(
    context.ledgerRootPath,
    context.forbiddenRootPath
  );
  const authorizationId = context.authorization?.payload?.authorizationId;
  if (
    UUID.test(authorizationId ?? "") &&
    ledgerEntryPresent(path.join(
      secure.ledgerRootPath,
      intentFileName(authorizationId)
    ), secure)
  ) {
    readPersistedPreCallIntent(context, secure);
    const existing = readEntries(context, secure);
    if (existing.entries.length >= 4) {
      return Object.freeze({ status: "W1_COMPLETE", resumed: true });
    }
  }
  persistPreCallIntent(context, trustedClock);
  assertProviderCapableContextCurrent(context, secure, trustedClock);
  for (const step of INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.slice(0, 4)) {
    recordStep(context, step, undefined, journalNow(trustedClock));
    maybeCrash(options, step.event);
  }
  return Object.freeze({ status: "W1_COMPLETE" });
}

export function runIntegratedLiveDrillRecoveryContinuityW1(
  context,
  options = {}
) {
  requirePublicWorkerOptions(options, ["crashAfterEvent"]);
  return runIntegratedLiveDrillRecoveryContinuityW1Internal(
    context,
    options,
    () => Date.now()
  );
}

async function runIntegratedLiveDrillRecoveryContinuityW2Internal(
  context,
  { mcpCall, reconcileDurableResult, ...options },
  trustedClock
) {
  const secure = secureLedgerRoot(
    context.ledgerRootPath,
    context.forbiddenRootPath
  );
  let journal;
  try {
    journal = readEntries(context, secure);
  } catch (cause) {
    if (
      cause?.message ===
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
    ) {
      return unknownDoNotAct();
    }
    throw cause;
  }
  requireCondition(
    journal.entries.length >= 4,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ORDER_REJECTED"
  );
  const claimPresent = journal.entries.length >= 6;
  const resultPresent = journal.entries.length >= 8;
  const unknown = unknownDispositionExists(
    secure,
    journal.bound.authorizationId
  );
  requireCondition(
    !(unknown && resultPresent),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  if (unknown) {
    return unknownDoNotAct();
  }
  if (claimPresent && !resultPresent) {
    if (
      journal.entries.length === 7 &&
      typeof reconcileDurableResult === "function"
    ) {
      let reconciled;
      try {
        reconciled = await reconcileDurableResult(Object.freeze({
          logicalMcpRequestSha256: journal.bound.logicalMcpRequestSha256
        }));
      } catch {
        reconciled = null;
      }
      if (reconciled !== null && reconciled !== undefined) {
        const resultArtifact = Object.freeze({
          mcpResultSha256: reconciled?.mcpResultSha256,
          sessionCloseSha256: reconciled?.sessionCloseSha256,
          sessionClosed: reconciled?.sessionClosed
        });
        requireCondition(
          reconciled?.logicalMcpRequestSha256 ===
            journal.bound.logicalMcpRequestSha256,
          "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_LOGICAL_REQUEST_REJECTED"
        );
        validateArtifact(
          INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[7],
          resultArtifact
        );
        recordStep(
          context,
          INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[7],
          resultArtifact,
          journalNow(trustedClock)
        );
        recordStep(
          context,
          INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[8],
          undefined,
          journalNow(trustedClock)
        );
        return Object.freeze({
          status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
          retried: false,
          reconciledFromDurableResult: true,
          ...resultArtifact
        });
      }
    }
    persistUnknownDisposition(
      context,
      secure,
      journal,
      journalNow(trustedClock)
    );
    return unknownDoNotAct();
  }
  if (resultPresent) {
    const result = journal.entries[7].artifact;
    const step = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[8];
    recordStep(context, step, undefined, journalNow(trustedClock));
    return Object.freeze({
      status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
      retried: false,
      ...result
    });
  }
  assertProviderCapableContextCurrent(context, secure, trustedClock);
  requireCondition(
    typeof mcpCall === "function",
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_MCP_CLIENT_REQUIRED"
  );
  const startedStep = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[4];
  try {
    recordStep(
      context,
      startedStep,
      undefined,
      journalNow(trustedClock)
    );
  } catch (cause) {
    if (
      cause?.message ===
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
    ) {
      return unknownDoNotAct();
    }
    throw cause;
  }
  maybeCrash(options, startedStep.event);
  const attemptOwnershipToken = randomBytes(32).toString("hex");
  const attemptOwnershipTokenSha256 = integratedLiveDrillSha256(
    attemptOwnershipToken
  );
  const claimStep = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[5];
  assertProviderCapableContextCurrent(context, secure, trustedClock);
  let claim;
  try {
    claim = recordStep(
      context,
      claimStep,
      Object.freeze({
        attemptOwnershipTokenSha256,
        disposition: "CLAIMED_BEFORE_DISPATCH"
      }),
      journalNow(trustedClock),
      { acceptExistingArtifact: true }
    );
  } catch (cause) {
    if (
      cause?.message ===
        "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
    ) {
      return unknownDoNotAct();
    }
    throw cause;
  }
  if (!claim.created) {
    return unknownDoNotAct();
  }
  requireCondition(
    claim.entry.artifact.attemptOwnershipTokenSha256 ===
      integratedLiveDrillSha256(attemptOwnershipToken),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_CLAIM_OWNERSHIP_REJECTED"
  );
  maybeCrash(options, claimStep.event);
  const dispatchStep = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[6];
  recordStep(
    context,
    dispatchStep,
    Object.freeze({
      attemptOwnershipTokenSha256,
      disposition: "DURABLE_BEFORE_BOUND_CALL"
    }),
    journalNow(trustedClock)
  );
  maybeCrash(options, dispatchStep.event);
  assertProviderCapableContextCurrent(context, secure, trustedClock);
  let result;
  try {
    result = await mcpCall(Object.freeze({
      logicalMcpRequestSha256: journal.bound.logicalMcpRequestSha256
    }));
  } catch {
    journal = readEntries(context, secure);
    persistUnknownDisposition(
      context,
      secure,
      journal,
      journalNow(trustedClock)
    );
    return unknownDoNotAct();
  }
  if (options.interruptAfterMcpCall === true) {
    syntheticCrash("PROVIDER_RESULT_DURABLE_BEFORE_JOURNAL");
  }
  const resultArtifact = Object.freeze({
    mcpResultSha256: result?.mcpResultSha256,
    sessionCloseSha256: result?.sessionCloseSha256,
    sessionClosed: result?.sessionClosed
  });
  requireCondition(
    result?.logicalMcpRequestSha256 ===
      journal.bound.logicalMcpRequestSha256,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_LOGICAL_REQUEST_REJECTED"
  );
  validateArtifact(
    INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[7],
    resultArtifact
  );
  journal = readEntries(context, secure);
  if (unknownDispositionExists(secure, journal.bound.authorizationId)) {
    return unknownDoNotAct();
  }
  const resultStep = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[7];
  recordStep(
    context,
    resultStep,
    resultArtifact,
    journalNow(trustedClock)
  );
  maybeCrash(options, resultStep.event);
  const completeStep = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[8];
  recordStep(
    context,
    completeStep,
    undefined,
    journalNow(trustedClock)
  );
  journal = readEntries(context, secure);
  requireCondition(
    journal.entries.length >= 9,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_INCOMPLETE"
  );
  return Object.freeze({
    status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    retried: false,
    ...resultArtifact
  });
}

export async function runIntegratedLiveDrillRecoveryContinuityW2(
  context,
  options = {}
) {
  requirePublicWorkerOptions(options, [
    "crashAfterEvent",
    "mcpCall",
    "reconcileDurableResult"
  ]);
  return runIntegratedLiveDrillRecoveryContinuityW2Internal(
    context,
    options,
    () => Date.now()
  );
}

function runDeterministicWorker(
  context,
  options,
  start,
  end,
  status,
  trustedClock
) {
  for (const step of INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.slice(
    start,
    end
  )) {
    recordStep(context, step, undefined, journalNow(trustedClock));
    maybeCrash(options, step.event);
  }
  return Object.freeze({ status });
}

export function runIntegratedLiveDrillRecoveryContinuityW3(
  context,
  options = {}
) {
  requirePublicWorkerOptions(options, ["crashAfterEvent"]);
  return runDeterministicWorker(
    context,
    options,
    9,
    12,
    "W3_COMPLETE",
    () => Date.now()
  );
}

export function runIntegratedLiveDrillRecoveryContinuityW4(
  context,
  options = {}
) {
  requirePublicWorkerOptions(options, ["crashAfterEvent"]);
  return runDeterministicWorker(
    context,
    options,
    12,
    15,
    "W4_COMPLETE",
    () => Date.now()
  );
}

export function runIntegratedLiveDrillRecoveryContinuityW5(
  context,
  options = {}
) {
  requireCondition(
    exactKeys(context, [
      "authorization",
      "controlLedgerReceipt",
      "forbiddenRootPath",
      "ledgerRootPath"
    ]) &&
      options &&
      typeof options === "object" &&
      !Array.isArray(options) &&
      Object.keys(options).every((key) =>
        ["crashAfterEvent"].includes(key)
      ),
    "INTEGRATED_LIVE_DRILL_W5_PROVIDER_CLIENT_REJECTED"
  );
  const disposition = inspectIntegratedLiveDrillRecoveryContinuity(context);
  requireCondition(
    disposition.status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    "INTEGRATED_LIVE_DRILL_W5_RECONCILIATION_REJECTED"
  );
  return runDeterministicWorker(
    context,
    options,
    15,
    17,
    "W5_COMPLETE",
    () => Date.now()
  );
}

export function inspectIntegratedLiveDrillRecoveryContinuity(context) {
  const secure = secureLedgerRoot(
    context.ledgerRootPath,
    context.forbiddenRootPath
  );
  const journal = readEntries(context, secure);
  const unknown = readUnknownDisposition(context, secure, journal.bound);
  const claimPresent = journal.entries.length >= 6;
  const resultPresent = journal.entries.length >= 8;
  requireCondition(
    !(unknown && resultPresent),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  if (unknown) {
    return Object.freeze({
      status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
      retryPermitted: false
    });
  }
  if (claimPresent && !resultPresent) {
    return Object.freeze({
      status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
      retryPermitted: false
    });
  }
  if (resultPresent) {
    return Object.freeze({
      status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
      retryPermitted: false,
      ...journal.entries[7].artifact
    });
  }
  return Object.freeze({
    status: "MCP_CALL_NOT_CLAIMED",
    retryPermitted: true
  });
}

export function validateIntegratedLiveDrillRecoveryContinuityJournal(
  context,
  { allowAbsent = false } = {}
) {
  const secure = secureLedgerRoot(
    context.ledgerRootPath,
    context.forbiddenRootPath
  );
  if (allowAbsent) {
    const authorizationId = context.authorization?.payload?.authorizationId;
    const intentPresent = UUID.test(authorizationId ?? "") &&
      ledgerEntryPresent(
        path.join(secure.ledgerRootPath, intentFileName(authorizationId)),
        secure
      );
    const journalPresent = UUID.test(authorizationId ?? "") &&
      fs.readdirSync(secure.ledgerRootPath).some((name) =>
        name.startsWith(journalFilePrefix(authorizationId))
      );
    if (!intentPresent && !journalPresent) return null;
    requireCondition(
      intentPresent,
      "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED"
    );
  }
  const journal = readEntries(context, secure);
  if (allowAbsent && journal.entries.length === 0) return null;
  requireCondition(
    readUnknownDisposition(context, secure, journal.bound) === null,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  requireCondition(
    journal.entries.length ===
      INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.length,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_INCOMPLETE"
  );
  const resultArtifact = journal.entries[7].artifact;
  const claimEntries = journal.entries.filter(
    ({ event }) => event === "MCP_CALL_CLAIMED"
  );
  const dispatchEntries = journal.entries.filter(
    ({ event }) => event === "MCP_DISPATCH_MARKER_DURABLE"
  );
  const exactMcpCallClaimCount = claimEntries.length;
  const exactMcpDispatchMarkerCount = dispatchEntries.length;
  requireCondition(
    exactMcpCallClaimCount === 1 &&
      exactMcpDispatchMarkerCount === 1 &&
      claimEntries[0].artifact.attemptOwnershipTokenSha256 ===
        dispatchEntries[0].artifact.attemptOwnershipTokenSha256 &&
      journal.entries[7].event === "MCP_RESULT_AND_CLOSE_DURABLE" &&
      journal.entries[15].artifact.topLevelProviderClientOptionReceived ===
        false &&
      journal.entries[15].artifact.providerClientInvoked === false &&
      journal.entries[16].artifact.disposition ===
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  const body = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_RECEIPT_SCHEMA,
    authorizationAttestationSha256:
      journal.bound.authorizationAttestationSha256,
    authorizationClaimSha256: journal.bound.authorizationClaimSha256,
    authorizationId: journal.bound.authorizationId,
    controlLedgerReceiptSha256: journal.bound.controlLedgerReceiptSha256,
    entryCount: journal.entries.length,
    entryDigests: journal.digests,
    exactMcpCallClaimCount,
    exactMcpDispatchMarkerCount,
    firstEntrySha256: journal.digests[0],
    lastEntrySha256: journal.digests.at(-1),
    logicalMcpRequestSha256: journal.bound.logicalMcpRequestSha256,
    mcpResultSha256: resultArtifact.mcpResultSha256,
    liveProviderBoundW1W5ContinuityProven: false,
    liveProviderDispatchAuthorizationProven: false,
    localSameHostScaffoldValidated: true,
    providerBacked: false,
    providerCallCountProven: false,
    providerFreeW5ImportGraphProven: false,
    preCallIntentSha256: journal.bound.preCallIntentSha256,
    reconciledWithoutRetry: true,
    runId: journal.bound.runId,
    sessionCloseSha256: resultArtifact.sessionCloseSha256,
    sessionClosed: true,
    status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    workerCount: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS.length,
    claimBoundary:
      "Local same-host scaffold only; actual provider-bound W1-W5 continuity remains unproven. The journal validates one local claim and one local dispatch marker, not an observed provider call count, provider authorization, provider origin, or crash continuity of the live Managed MCP path. The human authorization and consumed child token do not cryptographically authorize the derived recovery cluster or exact logical request. The W5 statement means only that its exact minimal reconciliation API accepted no top-level provider/client/key option and its local scaffold code path invoked no provider client; a provider-free import graph, nested-data capability absence, process credential isolation, and network isolation remain unproven for B2. The local scaffold records truthful post-dispatch evidence after authority expiry without authorizing a second provider action; provider-bound persistence and crash reconciliation on the live Managed MCP path remain unproven. Its unkeyed digest chain detects ordinary isolated mutation but is not independently anchored against same-owner full-chain rewriting."
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export const __test = Object.freeze({
  bindings,
  fileName,
  intentFileName,
  journalFilePrefix,
  runW2WithTrustedClock: (context, options, now) =>
    runIntegratedLiveDrillRecoveryContinuityW2Internal(
      context,
      options,
      () => now
    ),
  runW2WithPostCallInterruption: (context, mcpCall) =>
    runIntegratedLiveDrillRecoveryContinuityW2Internal(
      context,
      { interruptAfterMcpCall: true, mcpCall },
      () => Date.now()
    ),
  unknownFileName
});
