import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillSha256
} from "./integrated-live-drill-authorization.js";

export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_ENTRY_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-journal-entry.v1";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_RECEIPT_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-journal-receipt.v1";
export const INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN_SCHEMA =
  "tideproof.highwater-drill-recovery-continuity-unknown.v1";
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
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
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
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        named.dev === after.dev &&
        named.ino === after.ino &&
        !named.isSymbolicLink(),
      code
    );
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

function unknownDispositionExists(secure, authorizationId) {
  return fs.existsSync(path.join(
    secure.ledgerRootPath,
    unknownFileName(authorizationId)
  ));
}

function unknownDoNotAct() {
  return Object.freeze({
    status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
    retryPermitted: false
  });
}

function bindings(context) {
  const code = "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_BINDING_REJECTED";
  const {
    authorization,
    candidateReceipt,
    controlLedgerReceipt,
    mcpRequestSha256
  } = context ?? {};
  const { receiptSha256: candidateReceiptSha256, ...candidateBody } =
    candidateReceipt ?? {};
  const { receiptSha256: controlLedgerReceiptSha256, ...ledgerBody } =
    controlLedgerReceipt ?? {};
  requireCondition(
    authorization?.attestation &&
      authorization?.payload &&
      UUID.test(authorization.payload.authorizationId ?? "") &&
      HEX_40.test(authorization.payload.sourceCommit ?? "") &&
      HEX_40.test(authorization.payload.treeDigest ?? "") &&
      HEX_64.test(authorization.payload.configDigest ?? "") &&
      HEX_64.test(candidateReceiptSha256 ?? "") &&
      candidateReceiptSha256 ===
        integratedLiveDrillCanonicalSha256(candidateBody) &&
      candidateReceipt.authorizationId === undefined &&
      candidateReceipt.sourceCommit === authorization.payload.sourceCommit &&
      candidateReceipt.treeDigest === authorization.payload.treeDigest &&
      candidateReceipt.configDigest === authorization.payload.configDigest &&
      candidateReceipt.runId === authorization.payload.runId &&
      candidateReceipt.providerBacked === false &&
      candidateReceipt.recovery?.managedMcpCallCount === 1 &&
      HEX_64.test(controlLedgerReceiptSha256 ?? "") &&
      controlLedgerReceiptSha256 ===
        integratedLiveDrillCanonicalSha256(ledgerBody) &&
      controlLedgerReceipt.authorizationId ===
        authorization.payload.authorizationId &&
      controlLedgerReceipt.runId === authorization.payload.runId &&
      HEX_64.test(controlLedgerReceipt.authorizationClaimSha256 ?? "") &&
      HEX_64.test(mcpRequestSha256 ?? "") &&
      authorization.payload.requiredRecoveryJournalEntryCount ===
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.length &&
      canonicalJson(authorization.payload.requiredRecoveryWorkers) ===
        canonicalJson(INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS) &&
      canonicalJson(authorization.payload.requiredRecoveryFailpoints) ===
        canonicalJson(INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS),
    code
  );
  return Object.freeze({
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorization.attestation
      ),
    authorizationClaimSha256:
      controlLedgerReceipt.authorizationClaimSha256,
    authorizationId: authorization.payload.authorizationId,
    candidateReceiptSha256,
    configDigest: authorization.payload.configDigest,
    controlLedgerReceiptSha256,
    mcpRequestSha256,
    runId: authorization.payload.runId,
    sourceCommit: authorization.payload.sourceCommit,
    treeDigest: authorization.payload.treeDigest
  });
}

function defaultArtifact(step) {
  if (step.event === "W5_STARTED") {
    return Object.freeze({
      providerClientInvoked: false,
      providerClientReceived: false,
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
        artifact.disposition === "DURABLE_BEFORE_LOCAL_SCAFFOLD_CALL",
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
      "candidateReceiptSha256",
      "configDigest",
      "controlLedgerReceiptSha256",
      "event",
      "mcpRequestSha256",
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
      value.candidateReceiptSha256 === bound.candidateReceiptSha256 &&
      value.configDigest === bound.configDigest &&
      value.controlLedgerReceiptSha256 ===
        bound.controlLedgerReceiptSha256 &&
      value.event === expected.event &&
      value.mcpRequestSha256 === bound.mcpRequestSha256 &&
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
  const bound = bindings(context);
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
  let previousTime = context.authorization.issuedAt;
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
        recordedAt >= context.authorization.issuedAt &&
        recordedAt <= context.authorization.expiresAt,
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

function readUnknownDisposition(context, secure, bound = bindings(context)) {
  const filePath = path.join(
    secure.ledgerRootPath,
    unknownFileName(bound.authorizationId)
  );
  if (!fs.existsSync(filePath)) return null;
  const body = parseCanonicalRecord(readLedgerFile(filePath, secure));
  const recordedAt = Date.parse(body?.recordedAt);
  requireCondition(
    exactKeys(body, [
      "authorizationAttestationSha256",
      "authorizationClaimSha256",
      "authorizationId",
      "candidateReceiptSha256",
      "controlLedgerReceiptSha256",
      "mcpCallClaimEntrySha256",
      "mcpRequestSha256",
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
      body.candidateReceiptSha256 === bound.candidateReceiptSha256 &&
      body.controlLedgerReceiptSha256 ===
        bound.controlLedgerReceiptSha256 &&
      HEX_64.test(body.mcpCallClaimEntrySha256 ?? "") &&
      body.mcpRequestSha256 === bound.mcpRequestSha256 &&
      body.reason === "CLAIM_PRESENT_RESULT_ABSENT" &&
      typeof body.recordedAt === "string" &&
      Number.isFinite(recordedAt) &&
      new Date(recordedAt).toISOString() === body.recordedAt &&
      recordedAt >= context.authorization.issuedAt &&
      recordedAt <= context.authorization.expiresAt &&
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
      now >= journal.previousTime &&
      now <= context.authorization.expiresAt,
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_AMBIGUOUS"
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN_SCHEMA,
    authorizationAttestationSha256:
      bound.authorizationAttestationSha256,
    authorizationClaimSha256: bound.authorizationClaimSha256,
    authorizationId: bound.authorizationId,
    candidateReceiptSha256: bound.candidateReceiptSha256,
    controlLedgerReceiptSha256: bound.controlLedgerReceiptSha256,
    mcpCallClaimEntrySha256: journal.digests[5],
    mcpRequestSha256: bound.mcpRequestSha256,
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
      now >= journal.previousTime &&
      now >= context.authorization.issuedAt &&
      now <= context.authorization.expiresAt,
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

function nowFor(options, sequence) {
  const base = options?.now ?? Date.now();
  requireCondition(
    Number.isSafeInteger(base),
    "INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_TIME_REJECTED"
  );
  return base + sequence;
}

function maybeCrash(options, event) {
  if (options?.crashAfterEvent === event) syntheticCrash(event);
}

export function runIntegratedLiveDrillRecoveryContinuityW1(
  context,
  options = {}
) {
  for (const step of INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.slice(0, 4)) {
    recordStep(context, step, undefined, nowFor(options, step.sequence));
    maybeCrash(options, step.event);
  }
  return Object.freeze({ status: "W1_COMPLETE" });
}

export async function runIntegratedLiveDrillRecoveryContinuityW2(
  context,
  { mcpCall, ...options } = {}
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
    persistUnknownDisposition(
      context,
      secure,
      journal,
      nowFor(options, journal.entries.length + 1)
    );
    return unknownDoNotAct();
  }
  if (resultPresent) {
    const result = journal.entries[7].artifact;
    const step = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[8];
    recordStep(context, step, undefined, nowFor(options, step.sequence));
    return Object.freeze({
      status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
      retried: false,
      ...result
    });
  }
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
      nowFor(options, startedStep.sequence)
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
  let claim;
  try {
    claim = recordStep(
      context,
      claimStep,
      Object.freeze({
        attemptOwnershipTokenSha256,
        disposition: "CLAIMED_BEFORE_DISPATCH"
      }),
      nowFor(options, claimStep.sequence),
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
      disposition: "DURABLE_BEFORE_LOCAL_SCAFFOLD_CALL"
    }),
    nowFor(options, dispatchStep.sequence)
  );
  maybeCrash(options, dispatchStep.event);
  let result;
  try {
    result = await mcpCall(Object.freeze({
      mcpRequestSha256: bindings(context).mcpRequestSha256
    }));
  } catch {
    return unknownDoNotAct();
  }
  const resultArtifact = Object.freeze({
    mcpResultSha256: result?.mcpResultSha256,
    sessionCloseSha256: result?.sessionCloseSha256,
    sessionClosed: result?.sessionClosed
  });
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
    nowFor(options, resultStep.sequence)
  );
  maybeCrash(options, resultStep.event);
  const completeStep = INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN[8];
  recordStep(
    context,
    completeStep,
    undefined,
    nowFor(options, completeStep.sequence)
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

function runDeterministicWorker(context, options, start, end, status) {
  for (const step of INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.slice(
    start,
    end
  )) {
    recordStep(context, step, undefined, nowFor(options, step.sequence));
    maybeCrash(options, step.event);
  }
  return Object.freeze({ status });
}

export function runIntegratedLiveDrillRecoveryContinuityW3(
  context,
  options = {}
) {
  return runDeterministicWorker(context, options, 9, 12, "W3_COMPLETE");
}

export function runIntegratedLiveDrillRecoveryContinuityW4(
  context,
  options = {}
) {
  return runDeterministicWorker(context, options, 12, 15, "W4_COMPLETE");
}

export function runIntegratedLiveDrillRecoveryContinuityW5(
  context,
  { providerClient, ...options } = {}
) {
  requireCondition(
    providerClient === undefined,
    "INTEGRATED_LIVE_DRILL_W5_PROVIDER_CLIENT_REJECTED"
  );
  const disposition = inspectIntegratedLiveDrillRecoveryContinuity(context);
  requireCondition(
    disposition.status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    "INTEGRATED_LIVE_DRILL_W5_RECONCILIATION_REJECTED"
  );
  return runDeterministicWorker(context, options, 15, 17, "W5_COMPLETE");
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
      journal.entries[15].artifact.providerClientReceived === false &&
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
    candidateReceiptSha256: journal.bound.candidateReceiptSha256,
    controlLedgerReceiptSha256: journal.bound.controlLedgerReceiptSha256,
    entryCount: journal.entries.length,
    entryDigests: journal.digests,
    exactMcpCallClaimCount,
    exactMcpDispatchMarkerCount,
    firstEntrySha256: journal.digests[0],
    lastEntrySha256: journal.digests.at(-1),
    mcpRequestSha256: journal.bound.mcpRequestSha256,
    mcpResultSha256: resultArtifact.mcpResultSha256,
    liveProviderBoundW1W5ContinuityProven: false,
    liveProviderDispatchAuthorizationProven: false,
    localSameHostScaffoldValidated: true,
    providerBacked: false,
    providerCallCountProven: false,
    reconciledWithoutRetry: true,
    runId: journal.bound.runId,
    sessionCloseSha256: resultArtifact.sessionCloseSha256,
    sessionClosed: true,
    status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
    workerCount: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS.length,
    claimBoundary:
      "Local same-host scaffold only; actual provider-bound W1-W5 continuity remains unproven. The journal validates one local claim and one local dispatch marker, not an observed provider call count, provider authorization, provider origin, or crash continuity of the live Managed MCP path. Its unkeyed digest chain detects ordinary isolated mutation but is not independently anchored against same-owner full-chain rewriting."
  });
  return Object.freeze({
    ...body,
    receiptSha256: integratedLiveDrillCanonicalSha256(body)
  });
}

export const __test = Object.freeze({
  bindings,
  fileName,
  journalFilePrefix,
  unknownFileName
});
