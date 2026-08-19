import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  CloudFormationClient,
  CreateChangeSetCommand,
  DescribeChangeSetCommand,
  DescribeStacksCommand,
  ExecuteChangeSetCommand,
  GetTemplateCommand,
  ListChangeSetsCommand,
  ListStackResourcesCommand,
  UpdateTerminationProtectionCommand
} from "@aws-sdk/client-cloudformation";
import {
  CreateRoleCommand,
  DeleteRoleCommand,
  DeleteRolePolicyCommand,
  GetOpenIDConnectProviderCommand,
  GetRoleCommand,
  GetRolePolicyCommand,
  IAMClient,
  ListAttachedRolePoliciesCommand,
  ListMFADevicesCommand,
  ListRolePoliciesCommand,
  ListRoleTagsCommand,
  PutRolePolicyCommand,
  SimulatePrincipalPolicyCommand,
  TagRoleCommand
} from "@aws-sdk/client-iam";
import {
  DescribeSecretCommand,
  GetResourcePolicyCommand,
  GetSecretValueCommand,
  ListSecretVersionIdsCommand,
  PutSecretValueCommand,
  SecretsManagerClient
} from "@aws-sdk/client-secrets-manager";
import {
  AssumeRoleCommand,
  GetCallerIdentityCommand,
  STSClient
} from "@aws-sdk/client-sts";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import {
  buildBootstrapNegativeSimulationPlan,
  oneTimeBootstrapConstants,
  operationTokenFor,
  validateBootstrapCompletionEvidence,
  validateBootstrapNegativeSimulation,
  validateBootstrapSessionReceipt,
  validateOneTimeBootstrapCleanupReceipt,
  validateOneTimeBootstrapCheckout,
  validatePostCreateStackEvidence,
  validatePreExecuteChangeSetEvidence,
  validateRootMfaDiscoveryEvidence,
  verifyOneTimeBootstrapPlan
} from "./prepare-one-time-bootstrap-authority.js";
import {
  assumeOneTimeBootstrapRootSession,
  createNamedRootProfileStsClient
} from "./assume-one-time-bootstrap-root-session.js";

const execFileAsync = promisify(execFile);

const CURRENT_FILE = fileURLToPath(import.meta.url);
const JOURNAL_SCHEMA = "prooftoact.one-time-bootstrap-journal.v1";
const JOURNAL_FILE_PREFIX = "one-time-bootstrap-";
const REGION = oneTimeBootstrapConstants.REGION;
const WRITER_VALUE_FDS = Object.freeze({
  auditor: 5,
  cloudApi: 6,
  credential: 7,
  mcp: 8,
  publisher: 9
});
const WRITER_VALUE_MAXIMUM_BYTES = Object.freeze({
  auditor: 16 * 1024,
  cloudApi: 16 * 1024,
  credential: 64 * 1024,
  mcp: 16 * 1024,
  publisher: 16 * 1024
});
const AUTHORIZATION_RECEIPT_FD = 4;
const MFA_TOKEN_FD = 3;
const CLOUDTRAIL_EVENT_LAG_MS = 5 * 60 * 1000;
const SESSION_CLEANUP_RESERVE_MS = 2 * CLOUDTRAIL_EVENT_LAG_MS;
const ROOT_ACTIONS_BY_PHASE = Object.freeze({
  discovery: Object.freeze([
    "sts:GetCallerIdentity",
    "iam:ListMFADevices"
  ]),
  setup: Object.freeze([
    "cloudtrail:LookupEvents",
    "iam:CreateRole",
    "iam:GetRole",
    "iam:TagRole",
    "iam:ListRoleTags",
    "iam:PutRolePolicy",
    "iam:GetRolePolicy",
    "sts:AssumeRole"
  ]),
  reconcile: Object.freeze([
    "cloudtrail:LookupEvents",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListRoleTags"
  ]),
  cleanup: Object.freeze([
    "cloudtrail:LookupEvents",
    "iam:DeleteRolePolicy",
    "iam:DeleteRole",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "aws:Logout"
  ])
});
const ROOT_PHASE_ORDER = Object.freeze([
  "discovery",
  "setup",
  "reconcile",
  "cleanup"
]);
const A1_INTEGRATION_PATHS = Object.freeze({
  bootstrapPlan: "scripts/prepare-fresh-primary-bootstrap-role.js",
  bootstrapReadback: "scripts/fresh-primary-bootstrap-role-readback.js",
  custodyPlan: "scripts/prepare-fresh-primary-credential-custody.js",
  custodyReadback: "scripts/fresh-primary-credential-custody-readback.js",
  sealer: "scripts/fresh-primary-credential-sealer.js"
});

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...keys].sort().join("\n");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalValue(value[key])]));
  }
  requireCondition(value === null || typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value)),
  "ONE_TIME_BOOTSTRAP_RUNNER_CANONICAL_VALUE_REJECTED");
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function canonicalInstant(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

export function validateOneTimeBootstrapTimingBudget({
  notAfter,
  preparedAt
}) {
  const code = "ONE_TIME_BOOTSTRAP_TIMING_BUDGET_REJECTED";
  const start = canonicalInstant(preparedAt, code);
  const deadline = canonicalInstant(notAfter, code);
  requireCondition(deadline - start ===
    oneTimeBootstrapConstants.MAX_PLAN_WINDOW_MS, code);
  const sessionMs = oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000;
  const normalSessionExpiration = start + sessionMs;
  const noEventRetrySafeAt = start + sessionMs + CLOUDTRAIL_EVENT_LAG_MS;
  const replacementSessionExpiration = noEventRetrySafeAt + sessionMs;
  const worstCaseCleanupBound = replacementSessionExpiration +
    SESSION_CLEANUP_RESERVE_MS;
  requireCondition(normalSessionExpiration + SESSION_CLEANUP_RESERVE_MS <
    deadline && noEventRetrySafeAt < replacementSessionExpiration &&
    worstCaseCleanupBound < deadline, code);
  return Object.freeze({
    cleanupStrictlyBeforeNotAfter: true,
    cloudTrailEventLagMs: CLOUDTRAIL_EVENT_LAG_MS,
    noEventRetrySafeAt: new Date(noEventRetrySafeAt).toISOString(),
    normalSessionExpiration: new Date(normalSessionExpiration).toISOString(),
    replacementSessionExpiration:
      new Date(replacementSessionExpiration).toISOString(),
    sessionCleanupReserveMs: SESSION_CLEANUP_RESERVE_MS,
    worstCaseCleanupBound: new Date(worstCaseCleanupBound).toISOString()
  });
}

function assertNoCredentialMaterial(value) {
  const code = "ONE_TIME_BOOTSTRAP_JOURNAL_SECRET_MATERIAL_REJECTED";
  const forbidden = /(?:password|apiKey|connectionString|privateKey|bearer|rawQuery|tokenValue|accessKeyId|secretAccessKey|sessionToken|tokenCode|secretString|secretBinary|rawValues|^values$)/iu;
  function visit(item) {
    if (Array.isArray(item)) {
      for (const child of item) visit(child);
      return;
    }
    if (!plainObject(item)) return;
    for (const [key, child] of Object.entries(item)) {
      requireCondition(!forbidden.test(key), code);
      visit(child);
    }
  }
  visit(value);
}

function checkedPrivateDirectory(directoryPath, code) {
  requireCondition(typeof directoryPath === "string" &&
    path.isAbsolute(directoryPath), code);
  let real;
  let stat;
  try {
    real = fs.realpathSync(directoryPath);
    stat = fs.lstatSync(directoryPath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(real === directoryPath && stat.isDirectory() &&
    !stat.isSymbolicLink() && stat.uid === process.getuid() &&
    (stat.mode & 0o077) === 0, code);
  return real;
}

function readPrivateRegularFile(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(bytes.length === before.size &&
      before.dev === after.dev && before.ino === after.ino &&
      before.mode === after.mode && before.size === after.size &&
      named.isFile() && !named.isSymbolicLink() && named.nlink === 1 &&
      named.dev === after.dev && named.ino === after.ino &&
      named.mode === after.mode && named.size === after.size, code);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readReviewedRegularFile(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.size > 0 &&
      before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(bytes.length === before.size &&
      before.dev === after.dev && before.ino === after.ino &&
      before.mode === after.mode && before.size === after.size &&
      named.isFile() && !named.isSymbolicLink() && named.nlink === 1 &&
      named.dev === after.dev && named.ino === after.ino &&
      named.mode === after.mode && named.size === after.size, code);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function atomicOwnerOnlyWrite(directoryPath, filePath, bytes) {
  const code = "ONE_TIME_BOOTSTRAP_JOURNAL_WRITE_REJECTED";
  requireCondition(Buffer.isBuffer(bytes) && bytes.length > 0 &&
    path.dirname(filePath) === directoryPath, code);
  const temporaryPath = path.join(directoryPath,
    `.${path.basename(filePath)}.${process.pid}.` +
      `${crypto.randomBytes(8).toString("hex")}.tmp`);
  let fileDescriptor;
  let directoryDescriptor;
  try {
    fileDescriptor = fs.openSync(temporaryPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
      fs.constants.O_NOFOLLOW, 0o600);
    let offset = 0;
    while (offset < bytes.length) {
      offset += fs.writeSync(fileDescriptor, bytes, offset,
        bytes.length - offset, null);
    }
    fs.fsyncSync(fileDescriptor);
    fs.closeSync(fileDescriptor);
    fileDescriptor = undefined;
    fs.renameSync(temporaryPath, filePath);
    directoryDescriptor = fs.openSync(directoryPath,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY |
      fs.constants.O_NOFOLLOW);
    fs.fsyncSync(directoryDescriptor);
  } catch (cause) {
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(fileDescriptor)) fs.closeSync(fileDescriptor);
    if (Number.isSafeInteger(directoryDescriptor)) {
      fs.closeSync(directoryDescriptor);
    }
  }
}

function fsyncDirectory(directoryPath, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(directoryPath,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY |
      fs.constants.O_NOFOLLOW);
    fs.fsyncSync(descriptor);
  } catch (cause) {
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function acquireOperationLock(directoryPath, plan, now) {
  const code = "ONE_TIME_BOOTSTRAP_OPERATION_LOCK_REJECTED";
  const filePath = path.join(directoryPath,
    `${JOURNAL_FILE_PREFIX}${plan.operation.operationToken}.lock`);
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-operation-lock.v1",
    createdAt: now,
    operationId: plan.operation.operationId,
    operationToken: plan.operation.operationToken,
    pid: process.pid,
    planBodySha256: plan.planBodySha256
  };
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
      fs.constants.O_NOFOLLOW, 0o600);
    const bytes = canonicalBytes(body);
    let offset = 0;
    while (offset < bytes.length) {
      offset += fs.writeSync(descriptor, bytes, offset,
        bytes.length - offset, null);
    }
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1 &&
      stat.uid === process.getuid() && (stat.mode & 0o077) === 0, code);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fsyncDirectory(directoryPath, code);
    return { dev: stat.dev, ino: stat.ino, filePath };
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export function inspectOneTimeBootstrapOperationLock({ directoryPath, plan }) {
  const code = "ONE_TIME_BOOTSTRAP_STALE_LOCK_INSPECTION_REJECTED";
  const directory = checkedPrivateDirectory(directoryPath, code);
  const filePath = path.join(directory,
    `${JOURNAL_FILE_PREFIX}${plan.operation.operationToken}.lock`);
  const bytes = readPrivateRegularFile(filePath, 64 * 1024, code);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(exactKeys(value, [
    "createdAt",
    "operationId",
    "operationToken",
    "pid",
    "planBodySha256",
    "schemaVersion"
  ]) && value.schemaVersion ===
      "prooftoact.one-time-bootstrap-operation-lock.v1" &&
    value.operationId === plan.operation.operationId &&
    value.operationToken === plan.operation.operationToken &&
    value.planBodySha256 === plan.planBodySha256 &&
    Number.isSafeInteger(value.pid) && value.pid > 0, code);
  canonicalInstant(value.createdAt, code);
  const stat = fs.lstatSync(filePath);
  return Object.freeze({
    createdAt: value.createdAt,
    dev: stat.dev,
    filePath,
    ino: stat.ino,
    lockFileSha256: sha256(bytes),
    pid: value.pid
  });
}

export function recoverOneTimeBootstrapStaleLock({
  auditReceipt,
  directoryPath,
  plan
}) {
  const code = "ONE_TIME_BOOTSTRAP_STALE_LOCK_RECOVERY_REJECTED";
  const lock = inspectOneTimeBootstrapOperationLock({ directoryPath, plan });
  requireCondition(exactKeys(auditReceipt, [
    "confirmedAt",
    "confirmedPid",
    "confirmedProcessDead",
    "journalPreserved",
    "lockFileSha256",
    "manualRemovalAuthorized",
    "operationId",
    "operatorAuthorizationReceiptSha256",
    "planBodySha256",
    "schemaVersion",
    "status"
  ]) && auditReceipt.schemaVersion ===
      "prooftoact.one-time-bootstrap-stale-lock-recovery.v1" &&
    auditReceipt.status === "CONFIRMED_DEAD_PROCESS_LOCK_REMOVAL_AUTHORIZED" &&
    auditReceipt.confirmedProcessDead === true &&
    auditReceipt.manualRemovalAuthorized === true &&
    auditReceipt.journalPreserved === true &&
    auditReceipt.confirmedPid === lock.pid &&
    auditReceipt.lockFileSha256 === lock.lockFileSha256 &&
    auditReceipt.operationId === plan.operation.operationId &&
    auditReceipt.planBodySha256 === plan.planBodySha256 &&
    auditReceipt.operatorAuthorizationReceiptSha256 ===
      plan.authorization.userAuthorizationReceiptSha256, code);
  canonicalInstant(auditReceipt.confirmedAt, code);
  const journalPath = path.join(directoryPath,
    `${JOURNAL_FILE_PREFIX}${plan.operation.operationToken}.json`);
  requireCondition(fs.existsSync(journalPath), code);
  const stat = fs.lstatSync(lock.filePath);
  requireCondition(stat.dev === lock.dev && stat.ino === lock.ino &&
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, code);
  try {
    fs.unlinkSync(lock.filePath);
    fsyncDirectory(directoryPath, code);
  } catch (cause) {
    reject(code, cause);
  }
  return Object.freeze({
    journalPreserved: true,
    lockRemoved: true,
    recoveryReceiptSha256: digest(auditReceipt)
  });
}

function journalBodySha256(journal) {
  const body = { ...journal };
  delete body.journalBodySha256;
  return digest(body);
}

function verifyJournal(value, plan) {
  const code = "ONE_TIME_BOOTSTRAP_JOURNAL_INTEGRITY_REJECTED";
  requireCondition(exactKeys(value, [
    "createdAt",
    "journalBodySha256",
    "operationId",
    "operationToken",
    "planBodySha256",
    "schemaVersion",
    "steps",
    "updatedAt"
  ]) && value.schemaVersion === JOURNAL_SCHEMA &&
    value.operationId === plan.operation.operationId &&
    value.operationToken === plan.operation.operationToken &&
    value.planBodySha256 === plan.planBodySha256 &&
    plainObject(value.steps) &&
    /^[0-9a-f]{64}$/u.test(value.journalBodySha256 ?? "") &&
    value.journalBodySha256 === journalBodySha256(value), code);
  canonicalInstant(value.createdAt, code);
  canonicalInstant(value.updatedAt, code);
  assertNoCredentialMaterial(value);
  return value;
}

export class OneTimeBootstrapJournal {
  constructor({ clock, directoryPath, mode, plan }) {
    const code = "ONE_TIME_BOOTSTRAP_JOURNAL_OPEN_REJECTED";
    requireCondition(typeof clock === "function" &&
      ["NEW", "RECONCILE_ONLY"].includes(mode), code);
    this.clock = clock;
    this.directoryPath = checkedPrivateDirectory(directoryPath, code);
    this.filePath = path.join(this.directoryPath,
      `${JOURNAL_FILE_PREFIX}${plan.operation.operationToken}.json`);
    this.mode = mode;
    this.plan = plan;
    this.lock = acquireOperationLock(
      this.directoryPath,
      plan,
      this.now()
    );
    const exists = fs.existsSync(this.filePath);
    requireCondition(mode === "NEW" ? !exists : exists, code);
    if (exists) {
      let parsed;
      try {
        parsed = JSON.parse(readPrivateRegularFile(
          this.filePath,
          4 * 1024 * 1024,
          code
        ).toString("utf8"));
      } catch (cause) {
        if (cause?.message === code) throw cause;
        reject(code, cause);
      }
      this.value = verifyJournal(parsed, plan);
    } else {
      const now = this.now();
      const body = {
        schemaVersion: JOURNAL_SCHEMA,
        operationId: plan.operation.operationId,
        operationToken: plan.operation.operationToken,
        planBodySha256: plan.planBodySha256,
        createdAt: now,
        updatedAt: now,
        steps: {}
      };
      this.value = { ...body, journalBodySha256: digest(body) };
      this.persist();
    }
  }

  releaseLock() {
    if (this.lock === null) return;
    const code = "ONE_TIME_BOOTSTRAP_OPERATION_LOCK_RELEASE_REJECTED";
    let stat;
    try {
      stat = fs.lstatSync(this.lock.filePath);
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(stat.isFile() && !stat.isSymbolicLink() &&
      stat.dev === this.lock.dev && stat.ino === this.lock.ino &&
      stat.nlink === 1 && stat.uid === process.getuid() &&
      (stat.mode & 0o077) === 0, code);
    try {
      fs.unlinkSync(this.lock.filePath);
      fsyncDirectory(this.directoryPath, code);
      this.lock = null;
    } catch (cause) {
      reject(code, cause);
    }
  }

  now() {
    const value = this.clock();
    requireCondition(value instanceof Date &&
      Number.isFinite(value.getTime()),
    "ONE_TIME_BOOTSTRAP_JOURNAL_CLOCK_REJECTED");
    return value.toISOString();
  }

  persist() {
    verifyJournal(this.value, this.plan);
    atomicOwnerOnlyWrite(
      this.directoryPath,
      this.filePath,
      canonicalBytes(this.value)
    );
  }

  step(id) {
    requireCondition(/^[a-z0-9][a-z0-9-]{1,127}$/u.test(id),
      "ONE_TIME_BOOTSTRAP_JOURNAL_STEP_ID_REJECTED");
    return this.value.steps[id] ?? null;
  }

  updateStep(id, next) {
    assertNoCredentialMaterial(next);
    const updatedAt = this.now();
    const body = {
      ...this.value,
      updatedAt,
      steps: { ...this.value.steps, [id]: next }
    };
    delete body.journalBodySha256;
    this.value = { ...body, journalBodySha256: digest(body) };
    this.persist();
    return this.value.steps[id];
  }

  recordIntent(id, mutationClass, contract) {
    const code = "ONE_TIME_BOOTSTRAP_JOURNAL_INTENT_REJECTED";
    requireCondition(/^[A-Za-z][A-Za-z0-9:.-]{1,127}$/u.test(mutationClass) &&
      plainObject(contract), code);
    assertNoCredentialMaterial(contract);
    const contractSha256 = digest(contract);
    const prior = this.step(id);
    if (prior !== null) {
      requireCondition(prior.mutationClass === mutationClass &&
        prior.contractSha256 === contractSha256, code);
      return prior;
    }
    return this.updateStep(id, {
      state: "INTENT_RECORDED",
      mutationClass,
      contractSha256,
      intentRecordedAt: this.now(),
      dispatchStartedAt: null,
      acceptedAt: null,
      acceptedBy: null,
      receipt: null
    });
  }

  recordDispatchStarted(id) {
    const prior = this.step(id);
    requireCondition(prior?.state === "INTENT_RECORDED" &&
      prior.dispatchStartedAt === null,
    "ONE_TIME_BOOTSTRAP_JOURNAL_DISPATCH_REJECTED");
    return this.updateStep(id, {
      ...prior,
      state: "DISPATCH_STARTED",
      dispatchStartedAt: this.now()
    });
  }

  recordContinuationContext(id, context) {
    const prior = this.step(id);
    requireCondition(prior?.state === "INTENT_RECORDED" &&
      prior.dispatchStartedAt === null && plainObject(context),
    "ONE_TIME_BOOTSTRAP_JOURNAL_CONTINUATION_CONTEXT_REJECTED");
    assertNoCredentialMaterial(context);
    return this.updateStep(id, {
      ...prior,
      continuationContext: context,
      continuationCount: 0,
      continuationStartedAt: null
    });
  }

  recordNestedContinuation(id) {
    const prior = this.step(id);
    requireCondition(prior?.state === "DISPATCH_STARTED" &&
      plainObject(prior.continuationContext) &&
      Number.isSafeInteger(prior.continuationCount) &&
      prior.continuationCount >= 0,
    "ONE_TIME_BOOTSTRAP_JOURNAL_CONTINUATION_REJECTED");
    return this.updateStep(id, {
      ...prior,
      continuationCount: prior.continuationCount + 1,
      continuationStartedAt: this.now()
    });
  }

  recordAccepted(id, acceptedBy, receipt) {
    const prior = this.step(id);
    requireCondition(prior !== null &&
      ["INTENT_RECORDED", "DISPATCH_STARTED"].includes(prior.state) &&
      ["PRESTATE_RECONCILIATION", "POST_DISPATCH_RECONCILIATION"]
        .includes(acceptedBy) && plainObject(receipt),
    "ONE_TIME_BOOTSTRAP_JOURNAL_ACCEPT_REJECTED");
    assertNoCredentialMaterial(receipt);
    return this.updateStep(id, {
      ...prior,
      state: "ACCEPTED",
      acceptedAt: this.now(),
      acceptedBy,
      receipt
    });
  }
}

export async function runCrashConvergentMutation({
  acceptReceipt,
  classify,
  contract,
  dispatch,
  id,
  inspect,
  journal,
  mutationClass
}) {
  const code = "ONE_TIME_BOOTSTRAP_MUTATION_CONVERGENCE_REJECTED";
  requireCondition(journal instanceof OneTimeBootstrapJournal &&
    typeof classify === "function" && typeof dispatch === "function" &&
    typeof inspect === "function" && typeof acceptReceipt === "function" &&
    plainObject(contract), code);
  const prior = journal.recordIntent(id, mutationClass, contract);
  if (prior.state === "ACCEPTED") {
    const current = await inspect();
    requireCondition(classify(current) === "MATCH", code);
    acceptReceipt(current);
    return prior.receipt;
  }
  const before = await inspect();
  const beforeClass = classify(before);
  requireCondition(["ABSENT", "MATCH", "CONFLICT"].includes(beforeClass),
    code);
  if (beforeClass === "MATCH") {
    return journal.recordAccepted(
      id,
      "PRESTATE_RECONCILIATION",
      acceptReceipt(before)
    ).receipt;
  }
  requireCondition(beforeClass === "ABSENT", code);
  if (prior.state === "DISPATCH_STARTED") {
    reject("ONE_TIME_BOOTSTRAP_AMBIGUOUS_MUTATION_RETAIN_AND_RECONCILE");
  }
  if (journal.mode === "RECONCILE_ONLY") {
    reject("ONE_TIME_BOOTSTRAP_RECONCILE_ONLY_MUTATION_REQUIRED");
  }
  journal.recordDispatchStarted(id);
  let dispatchCause = null;
  try {
    await dispatch();
  } catch (cause) {
    dispatchCause = cause;
  }
  const after = await inspect();
  const afterClass = classify(after);
  if (afterClass === "MATCH") {
    return journal.recordAccepted(
      id,
      "POST_DISPATCH_RECONCILIATION",
      acceptReceipt(after)
    ).receipt;
  }
  reject("ONE_TIME_BOOTSTRAP_AMBIGUOUS_MUTATION_RETAIN_AND_RECONCILE",
    dispatchCause ?? new Error(`POST_DISPATCH_${afterClass}`));
}

export async function runCrashConvergentSecretSeal({
  approval,
  contract,
  id = "seal-five-a1-writer-values",
  journal,
  seal,
  validateSealReceipt
}) {
  const code = "ONE_TIME_BOOTSTRAP_SECRET_SEAL_CONVERGENCE_REJECTED";
  requireCondition(journal instanceof OneTimeBootstrapJournal &&
    plainObject(approval) && plainObject(contract) &&
    typeof seal === "function" && typeof validateSealReceipt === "function",
  code);
  let prior = journal.recordIntent(
    id,
    "secretsmanager:PutSecretValue",
    contract
  );
  if (prior.state === "ACCEPTED") {
    requireCondition(plainObject(prior.receipt?.sealReceipt), code);
    return prior.receipt.sealReceipt;
  }
  if (prior.state === "INTENT_RECORDED") {
    requireCondition(prior.dispatchStartedAt === null, code);
    prior = journal.recordContinuationContext(id, {
      approval,
      deterministicA1NestedContinuation: true
    });
    prior = journal.recordDispatchStarted(id);
  } else {
    requireCondition(prior.state === "DISPATCH_STARTED" &&
      canonicalJson(prior.continuationContext?.approval) ===
        canonicalJson(approval) &&
      prior.continuationContext?.deterministicA1NestedContinuation === true,
    code);
    prior = journal.recordNestedContinuation(id);
  }
  void prior;
  let receipt;
  try {
    receipt = await seal();
  } catch (cause) {
    reject("ONE_TIME_BOOTSTRAP_SECRET_SEAL_PARTIAL_RECONCILIATION_REQUIRED",
      cause);
  }
  const accepted = validateSealReceipt(receipt);
  requireCondition(plainObject(accepted), code);
  return journal.recordAccepted(
    id,
    "POST_DISPATCH_RECONCILIATION",
    { sealReceipt: accepted }
  ).receipt.sealReceipt;
}

export class RootActionGate {
  constructor() {
    this.phaseIndex = 0;
    this.invocations = [];
  }

  advance(phase) {
    const index = ROOT_PHASE_ORDER.indexOf(phase);
    requireCondition(index >= this.phaseIndex && index <= this.phaseIndex + 1,
      "ONE_TIME_BOOTSTRAP_ROOT_PHASE_REJECTED");
    this.phaseIndex = index;
  }

  async invoke(phase, action, callback) {
    requireCondition(ROOT_PHASE_ORDER[this.phaseIndex] === phase &&
      ROOT_ACTIONS_BY_PHASE[phase].includes(action) &&
      typeof callback === "function",
    "ONE_TIME_BOOTSTRAP_ROOT_ACTION_REJECTED");
    this.invocations.push(Object.freeze({ action, phase }));
    return callback();
  }
}

function validatePrivateFd(fd, code) {
  requireCondition(Number.isSafeInteger(fd) && fd >= 3 && fd <= 1024, code);
  let stat;
  try {
    stat = fs.fstatSync(fd);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(!stat.isFile() && !stat.isDirectory() &&
    stat.uid === process.getuid() && (stat.mode & 0o077) === 0, code);
}

function readPrivateFdToBuffer(fd, maximumBytes, code) {
  validatePrivateFd(fd, code);
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const chunk = Buffer.alloc(Math.min(16 * 1024,
        maximumBytes + 1 - total));
      let count;
      try {
        count = fs.readSync(fd, chunk, 0, chunk.length, null);
      } catch (cause) {
        chunk.fill(0);
        reject(code, cause);
      }
      if (count === 0) {
        chunk.fill(0);
        break;
      }
      chunks.push(chunk.subarray(0, count));
      total += count;
      requireCondition(total <= maximumBytes, code);
      if (count < chunk.length) {
        chunk.fill(0, count);
      }
    }
    requireCondition(total > 0, code);
    return Buffer.concat(chunks, total);
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

export function createFixedFdWriterValueLease() {
  let consumed = false;
  let prepared = false;
  const buffers = {};
  return Object.freeze({
    prepare(expectedValueSha256) {
      const code = "ONE_TIME_BOOTSTRAP_WRITER_VALUE_FD_REJECTED";
      requireCondition(!consumed && !prepared &&
        exactKeys(expectedValueSha256, Object.keys(WRITER_VALUE_FDS)), code);
      try {
        for (const [name, fd] of Object.entries(WRITER_VALUE_FDS)) {
          buffers[name] = readPrivateFdToBuffer(
            fd,
            WRITER_VALUE_MAXIMUM_BYTES[name],
            code
          );
          requireCondition(sha256(buffers[name]) ===
            expectedValueSha256[name], code);
        }
        prepared = true;
        return Object.freeze({
          exactDigestMatch: true,
          valueCount: Object.keys(buffers).length
        });
      } catch (cause) {
        for (const buffer of Object.values(buffers)) buffer.fill(0);
        consumed = true;
        throw cause;
      }
    },
    async withValues(callback) {
      const code = "ONE_TIME_BOOTSTRAP_WRITER_VALUE_FD_REJECTED";
      requireCondition(!consumed && prepared &&
        typeof callback === "function", code);
      consumed = true;
      const values = {};
      try {
        for (const name of Object.keys(WRITER_VALUE_FDS)) {
          values[name] = buffers[name].toString("utf8");
        }
        return await callback(values);
      } finally {
        for (const buffer of Object.values(buffers)) buffer.fill(0);
        for (const name of Object.keys(values)) values[name] = "";
      }
    },
    destroy() {
      for (const buffer of Object.values(buffers)) buffer.fill(0);
      consumed = true;
      prepared = false;
    }
  });
}

export function readAndValidateAuthorizationReceipt(plan, fd =
  AUTHORIZATION_RECEIPT_FD, clock = () => new Date()) {
  const bytes = readPrivateFdToBuffer(
    fd,
    256 * 1024,
    "ONE_TIME_BOOTSTRAP_AUTHORIZATION_FD_REJECTED"
  );
  try {
    const code = "ONE_TIME_BOOTSTRAP_AUTHORIZATION_RECEIPT_REJECTED";
    let receipt;
    try {
      receipt = JSON.parse(bytes.toString("utf8"));
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(sha256(bytes) ===
      plan.authorization.userAuthorizationReceiptSha256 &&
      canonicalBytes(receipt).equals(bytes), code);
    const now = clock();
    validateOneTimeBootstrapAuthorizationReceipt(plan, receipt, now);
    return Object.freeze({
      bytes: bytes.length,
      sha256: sha256(bytes),
      rawReceiptRetained: false,
      receipt,
      writerValueSha256: Object.freeze({ ...receipt.writerValueSha256 })
    });
  } finally {
    bytes.fill(0);
  }
}

export function validateOneTimeBootstrapAuthorizationReceipt(plan, receipt,
  observedAt) {
  const code = "ONE_TIME_BOOTSTRAP_AUTHORIZATION_RECEIPT_REJECTED";
  const rebuilt = buildOneTimeBootstrapAuthorizationReceipt({
    accountId: receipt?.accountId,
    approvedAt: receipt?.approvedAt,
    artifactBucketName: receipt?.existingInputs?.artifactBucketName,
    costCeiling: receipt?.costCeiling,
    expiresAt: receipt?.expiresAt,
    githubOidcProviderArn: receipt?.existingInputs?.githubOidcProviderArn,
    operationId: receipt?.operationId,
    sourceCommit: receipt?.sourceCommit,
    targetTemplateSha256: Object.fromEntries(
      oneTimeBootstrapConstants.TARGET_KEYS.map((key) =>
        [key, receipt?.targets?.[key]?.templateSha256])
    ),
    treeDigest: receipt?.treeDigest,
    writerValueSha256: receipt?.writerValueSha256
  });
  requireCondition(observedAt instanceof Date &&
    Number.isFinite(observedAt.getTime()) &&
    canonicalJson(rebuilt) === canonicalJson(receipt) &&
    receipt.accountId === plan.account.accountId &&
    receipt.operationId === plan.operation.operationId &&
    receipt.operationToken === plan.operation.operationToken &&
    receipt.sourceCommit === plan.source.commit &&
    receipt.treeDigest === plan.source.tree &&
    receipt.expiresAt === plan.notAfter &&
    sha256(canonicalBytes(receipt)) ===
      plan.authorization.userAuthorizationReceiptSha256 &&
    Date.parse(receipt.approvedAt) <= observedAt.getTime() &&
    observedAt.getTime() < Date.parse(receipt.expiresAt) &&
    canonicalJson(receipt.costCeiling) === canonicalJson(plan.costCeiling) &&
    receipt.existingInputs.artifactBucketName ===
      plan.existingInputs.artifactBucketName &&
    receipt.existingInputs.githubOidcProviderArn ===
      plan.existingInputs.githubOidcProviderArn &&
    oneTimeBootstrapConstants.TARGET_KEYS.every((key) =>
      receipt.targets[key].stackName === plan.targets[key].stackName &&
      receipt.targets[key].templateSha256 ===
        plan.targets[key].templateSha256), code);
  return receipt;
}

export function buildOneTimeBootstrapAuthorizationReceipt(input) {
  const code = "ONE_TIME_BOOTSTRAP_AUTHORIZATION_BUILD_REJECTED";
  const writerNames = ["auditor", "cloudApi", "credential", "mcp",
    "publisher"];
  requireCondition(exactKeys(input, [
    "accountId",
    "approvedAt",
    "artifactBucketName",
    "costCeiling",
    "expiresAt",
    "githubOidcProviderArn",
    "operationId",
    "sourceCommit",
    "targetTemplateSha256",
    "treeDigest",
    "writerValueSha256"
  ]) && /^[0-9]{12}$/u.test(input.accountId ?? "") &&
    /^[0-9a-f]{40}$/u.test(input.sourceCommit ?? "") &&
    /^[0-9a-f]{40}$/u.test(input.treeDigest ?? "") &&
    exactKeys(input.targetTemplateSha256,
      oneTimeBootstrapConstants.TARGET_KEYS) &&
    Object.values(input.targetTemplateSha256).every((value) =>
      /^[0-9a-f]{64}$/u.test(value ?? "")) &&
    exactKeys(input.writerValueSha256, writerNames) &&
    Object.values(input.writerValueSha256).every((value) =>
      /^[0-9a-f]{64}$/u.test(value ?? "")) &&
    exactKeys(input.costCeiling, [
      "currency",
      "maximumMonthlyUsdCents",
      "maximumOneTimeUsdCents",
      "reconciliationReceiptSha256"
    ]) && input.costCeiling.currency === "USD" &&
    Number.isSafeInteger(input.costCeiling.maximumMonthlyUsdCents) &&
    input.costCeiling.maximumMonthlyUsdCents >= 0 &&
    Number.isSafeInteger(input.costCeiling.maximumOneTimeUsdCents) &&
    input.costCeiling.maximumOneTimeUsdCents >= 0 &&
    /^[0-9a-f]{64}$/u.test(
      input.costCeiling.reconciliationReceiptSha256 ?? "") &&
    input.githubOidcProviderArn ===
      `arn:aws:iam::${input.accountId}:oidc-provider/` +
        "token.actions.githubusercontent.com" &&
    typeof input.artifactBucketName === "string", code);
  const approved = canonicalInstant(input.approvedAt, code);
  const expires = canonicalInstant(input.expiresAt, code);
  requireCondition(approved < expires && expires - approved ===
    oneTimeBootstrapConstants.MAX_PLAN_WINDOW_MS,
    code);
  const operationToken = operationTokenFor(input.operationId);
  const stackNames = {
    freshPrimaryBootstrapRole:
      "prooftoact-fresh-primary-bootstrap-role",
    freshPrimaryCredentialCustody:
      `prooftoact-fresh-primary-credential-custody-${input.operationId}`,
    privateRecoveryQueryBootstrap:
      "prooftoact-private-recovery-query-bootstrap"
  };
  return Object.freeze({
    schemaVersion: "prooftoact.one-time-bootstrap-authorization.v1",
    status: "AUTHORIZED_EXACT_ROOT_B0_CEREMONY_AND_COST_CEILING",
    accountId: input.accountId,
    approvedAt: input.approvedAt,
    costCeiling: { ...input.costCeiling },
    exactFiveWriterValuesAuthorized: true,
    existingInputs: {
      artifactBucketName: input.artifactBucketName,
      githubOidcProviderArn: input.githubOidcProviderArn
    },
    expiresAt: input.expiresAt,
    fixedPrivateFdContract: {
      authorizationReceiptFd: AUTHORIZATION_RECEIPT_FD,
      mfaTokenFd: MFA_TOKEN_FD,
      writerValueFds: { ...WRITER_VALUE_FDS }
    },
    operationId: input.operationId,
    operationToken,
    reconcileOnlyResumeRequired: true,
    rootScope: {
      actions: [
        "iam:CreateRole",
        "iam:TagRole",
        "iam:PutRolePolicy",
        "sts:AssumeRole",
        "iam:DeleteRolePolicy",
        "iam:DeleteRole",
        "aws:Logout"
      ],
      bootstrapRoleName:
        `ProofToActBootstrapCreator-${operationToken}`,
      bootstrapRolePath: "/prooftoact/bootstrap/",
      projectResourceAccessAuthorized: false
    },
    sourceCommit: input.sourceCommit,
    targets: Object.fromEntries(
      oneTimeBootstrapConstants.TARGET_KEYS.map((key) => [key, {
        stackName: stackNames[key],
        templateSha256: input.targetTemplateSha256[key]
      }])
    ),
    treeDigest: input.treeDigest,
    workloadStackAuthorized: false,
    writerValueSha256: { ...input.writerValueSha256 }
  });
}

function collectorBinding(plan) {
  return Object.freeze({
    accountId: plan.account.accountId,
    assumedRoleArn: `arn:aws:sts::${plan.account.accountId}:assumed-role/` +
      `${plan.bootstrapRole.name}/${plan.sessionContract.roleSessionName}`,
    operationId: plan.operation.operationId,
    operationToken: plan.operation.operationToken,
    operatorAuthorizationSha256:
      plan.authorization.userAuthorizationReceiptSha256,
    roleArn: plan.bootstrapRole.arn,
    roleName: plan.bootstrapRole.name,
    rolePath: plan.bootstrapRole.path,
    sessionName: plan.sessionContract.roleSessionName,
    sourceCommit: plan.source.commit,
    sourceIdentity: plan.sessionContract.sourceIdentity,
    treeDigest: plan.source.tree
  });
}

async function importExactModule(sourceRoot, relativePath) {
  const code = "ONE_TIME_BOOTSTRAP_A1_INTEGRATION_REJECTED";
  requireCondition(typeof sourceRoot === "string" &&
    path.isAbsolute(sourceRoot) &&
    Object.values(A1_INTEGRATION_PATHS).includes(relativePath), code);
  const absolutePath = path.join(sourceRoot, relativePath);
  let real;
  let stat;
  try {
    real = fs.realpathSync(absolutePath);
    stat = fs.lstatSync(absolutePath);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(real === absolutePath && stat.isFile() &&
    !stat.isSymbolicLink() && stat.nlink === 1, code);
  return import(pathToFileURL(absolutePath).href);
}

export async function loadA1Integration(plan, sourceRoot) {
  const [bootstrapPlanModule, bootstrapReadbackModule, custodyPlanModule,
    custodyReadbackModule, sealerModule] = await Promise.all([
    importExactModule(sourceRoot, A1_INTEGRATION_PATHS.bootstrapPlan),
    importExactModule(sourceRoot, A1_INTEGRATION_PATHS.bootstrapReadback),
    importExactModule(sourceRoot, A1_INTEGRATION_PATHS.custodyPlan),
    importExactModule(sourceRoot, A1_INTEGRATION_PATHS.custodyReadback),
    importExactModule(sourceRoot, A1_INTEGRATION_PATHS.sealer)
  ]);
  const bootstrapPlan = bootstrapPlanModule.prepareFreshPrimaryBootstrapRole({
    accountId: plan.account.accountId,
    sourceCommit: plan.source.commit,
    treeDigest: plan.source.tree
  });
  const custodyPlan = custodyPlanModule.prepareFreshPrimaryCredentialCustody({
    accountId: plan.account.accountId,
    operationId: plan.operation.operationId,
    operatorAuthorizationSha256:
      plan.authorization.userAuthorizationReceiptSha256,
    sourceCommit: plan.source.commit,
    treeDigest: plan.source.tree
  });
  const code = "ONE_TIME_BOOTSTRAP_A1_PLAN_BINDING_REJECTED";
  requireCondition(bootstrapPlan.templateSha256 ===
    plan.targets.freshPrimaryBootstrapRole.templateSha256 &&
    custodyPlan.templateSha256 ===
      plan.targets.freshPrimaryCredentialCustody.templateSha256 &&
    custodyPlan.credentialSealExternalId ===
      plan.writerContract.externalId &&
    custodyPlan.writerRoleArn === plan.writerContract.roleArn &&
    bootstrapPlan.stackName ===
      plan.targets.freshPrimaryBootstrapRole.stackName &&
    custodyPlan.stackName ===
      plan.targets.freshPrimaryCredentialCustody.stackName,
  code);
  return Object.freeze({
    bootstrapPlan,
    custodyPlan,
    buildApproval: sealerModule.buildFreshPrimaryCredentialSealApproval,
    collectorBinding: collectorBinding(plan),
    secretArnsFromOutputs:
      custodyReadbackModule.freshPrimaryCredentialSecretArnsFromStackOutputs,
    seal: sealerModule.sealFreshPrimaryCredentialCustody,
    verifyBootstrapReadback:
      bootstrapReadbackModule.verifyFreshPrimaryBootstrapRoleReadback,
    verifyCustodyReadback:
      custodyReadbackModule.verifyFreshPrimaryCredentialCustodyReadback,
    writerTargets: sealerModule.__test.WRITER_TARGETS,
    runtimeTargets: sealerModule.__test.RUNTIME_TARGETS
  });
}

function awsClientConfiguration(credentials) {
  return {
    ...(credentials === undefined ? {} : { credentials }),
    maxAttempts: 1,
    region: REGION,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 5_000,
      socketTimeout: 30_000
    })
  };
}

function decodeIamDocument(value, code) {
  if (plainObject(value)) return value;
  requireCondition(typeof value === "string" && value.length > 0, code);
  for (const candidate of [value, (() => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  })()]) {
    try {
      const parsed = JSON.parse(candidate);
      if (plainObject(parsed)) return parsed;
    } catch {
      // Try the other exact representation.
    }
  }
  reject(code);
}

function outputMap(items) {
  const output = {};
  for (const item of items ?? []) {
    requireCondition(typeof item.OutputKey === "string" &&
      typeof item.OutputValue === "string" &&
      !Object.hasOwn(output, item.OutputKey),
    "ONE_TIME_BOOTSTRAP_AWS_OUTPUT_REJECTED");
    output[item.OutputKey] = item.OutputValue;
  }
  return output;
}

function parameterMap(items) {
  const output = {};
  for (const item of items ?? []) {
    requireCondition(typeof item.ParameterKey === "string" &&
      typeof item.ParameterValue === "string" &&
      item.UsePreviousValue !== true &&
      !Object.hasOwn(output, item.ParameterKey),
    "ONE_TIME_BOOTSTRAP_AWS_PARAMETER_REJECTED");
    output[item.ParameterKey] = item.ParameterValue;
  }
  return output;
}

function exactTemplateBody(value, code) {
  requireCondition(typeof value === "string" && value.length > 0, code);
  return Buffer.from(value, "utf8").toString("base64");
}

function isNotFound(cause) {
  return cause?.name === "NoSuchEntityException" ||
    cause?.name === "ResourceNotFoundException" ||
    cause?.name === "ValidationError" &&
      /does not exist|does not exist for stack|not exist|not found/iu.test(
        String(cause?.message ?? "")
      );
}

async function waitBriefly() {
  await new Promise((resolve) => setTimeout(resolve, 1_000));
}

async function paginateMarker(sendPage) {
  const output = [];
  let marker;
  const observed = new Set();
  for (let page = 0; page < 100; page += 1) {
    const response = await sendPage(marker);
    output.push(response);
    if (response.IsTruncated !== true) return output;
    requireCondition(typeof response.Marker === "string" &&
      response.Marker.length > 0 && !observed.has(response.Marker),
    "ONE_TIME_BOOTSTRAP_AWS_PAGINATION_REJECTED");
    observed.add(response.Marker);
    marker = response.Marker;
  }
  reject("ONE_TIME_BOOTSTRAP_AWS_PAGINATION_REJECTED");
}

async function paginateToken(sendPage) {
  const output = [];
  let token;
  const observed = new Set();
  for (let page = 0; page < 100; page += 1) {
    const response = await sendPage(token);
    output.push(response);
    if (response.NextToken === undefined) return output;
    requireCondition(typeof response.NextToken === "string" &&
      response.NextToken.length > 0 && !observed.has(response.NextToken),
    "ONE_TIME_BOOTSTRAP_AWS_PAGINATION_REJECTED");
    observed.add(response.NextToken);
    token = response.NextToken;
  }
  reject("ONE_TIME_BOOTSTRAP_AWS_PAGINATION_REJECTED");
}

export class AwsOneTimeBootstrapRootProvider {
  constructor({ awsCliPath, clock = () => new Date(), plan }) {
    requireCondition(path.isAbsolute(awsCliPath) && typeof clock === "function",
      "ONE_TIME_BOOTSTRAP_AWS_ROOT_PROVIDER_REJECTED");
    this.awsCliPath = awsCliPath;
    this.clock = clock;
    this.plan = plan;
    this.sts = createNamedRootProfileStsClient(plan);
    this.iam = new IAMClient(awsClientConfiguration());
  }

  now() {
    const value = this.clock();
    requireCondition(value instanceof Date && Number.isFinite(value.getTime()) &&
      value.getTime() < Date.parse(this.plan.notAfter),
    "ONE_TIME_BOOTSTRAP_AWS_ROOT_CLOCK_REJECTED");
    return value;
  }

  async callerIdentity() {
    const value = await this.sts.send(new GetCallerIdentityCommand({}));
    requireCondition(value.Account === this.plan.account.accountId &&
      value.Arn === this.plan.account.rootPrincipalArn,
    "ONE_TIME_BOOTSTRAP_AWS_ROOT_IDENTITY_REJECTED");
    return value;
  }

  async discoverMfa() {
    const value = await this.iam.send(new ListMFADevicesCommand({}));
    return validateRootMfaDiscoveryEvidence(this.plan, {
      schemaVersion: "prooftoact.one-time-bootstrap-mfa-discovery.v1",
      accountId: this.plan.account.accountId,
      devices: (value.MFADevices ?? []).map((device) => ({
        enabled: device.EnableDate instanceof Date,
        serialArn: device.SerialNumber
      })),
      observedAt: this.now().toISOString(),
      readOnly: true,
      selectedSerialArn: this.plan.account.mfaSerialArn
    });
  }

  async inspectRole() {
    let value;
    try {
      value = await this.iam.send(new GetRoleCommand({
        RoleName: this.plan.bootstrapRole.name
      }));
    } catch (cause) {
      if (isNotFound(cause)) return { state: "ABSENT" };
      throw cause;
    }
    const role = value.Role;
    const matches = role?.Arn === this.plan.bootstrapRole.arn &&
      role?.RoleName === this.plan.bootstrapRole.name &&
      role?.Path === this.plan.bootstrapRole.path &&
      role?.MaxSessionDuration === this.plan.bootstrapRole.maxSessionDuration &&
      canonicalJson(decodeIamDocument(role?.AssumeRolePolicyDocument,
        "ONE_TIME_BOOTSTRAP_AWS_ROOT_ROLE_REJECTED")) ===
        canonicalJson(this.plan.bootstrapRole.trustPolicy);
    return {
      state: matches ? "MATCH" : "CONFLICT",
      receipt: {
        arn: role?.Arn ?? null,
        exactTrust: matches,
        roleId: role?.RoleId ?? null,
        roleName: role?.RoleName ?? null
      }
    };
  }

  async createRole() {
    await this.iam.send(new CreateRoleCommand({
      AssumeRolePolicyDocument: canonicalJson(
        this.plan.bootstrapRole.trustPolicy
      ),
      MaxSessionDuration: this.plan.bootstrapRole.maxSessionDuration,
      Path: this.plan.bootstrapRole.path,
      RoleName: this.plan.bootstrapRole.name
    }));
  }

  async inspectTags() {
    let pages;
    try {
      pages = await paginateMarker((Marker) => this.iam.send(
        new ListRoleTagsCommand({
          ...(Marker === undefined ? {} : { Marker }),
          RoleName: this.plan.bootstrapRole.name
        })
      ));
    } catch (cause) {
      if (isNotFound(cause)) return { state: "CONFLICT" };
      throw cause;
    }
    const tags = pages.flatMap((page) => page.Tags ?? []);
    const matches = canonicalJson(tags) ===
      canonicalJson(this.plan.bootstrapRole.roleTags);
    return {
      state: matches ? "MATCH" : tags.length === 0 ? "ABSENT" : "CONFLICT",
      receipt: {
        exactTags: matches,
        roleName: this.plan.bootstrapRole.name,
        tagsSha256: digest(tags)
      }
    };
  }

  async tagRole() {
    await this.iam.send(new TagRoleCommand({
      RoleName: this.plan.bootstrapRole.name,
      Tags: this.plan.bootstrapRole.roleTags
    }));
  }

  async inspectPolicy() {
    let value;
    try {
      value = await this.iam.send(new GetRolePolicyCommand({
        PolicyName: this.plan.bootstrapRole.inlinePolicyName,
        RoleName: this.plan.bootstrapRole.name
      }));
    } catch (cause) {
      if (isNotFound(cause)) return { state: "ABSENT" };
      throw cause;
    }
    const policy = decodeIamDocument(value.PolicyDocument,
      "ONE_TIME_BOOTSTRAP_AWS_ROOT_POLICY_REJECTED");
    const matches = value.PolicyName ===
      this.plan.bootstrapRole.inlinePolicyName &&
      value.RoleName === this.plan.bootstrapRole.name &&
      canonicalJson(policy) ===
        canonicalJson(this.plan.bootstrapRole.inlinePolicy);
    return {
      state: matches ? "MATCH" : "CONFLICT",
      receipt: {
        exactPolicy: matches,
        policySha256: digest(policy),
        roleName: value.RoleName
      }
    };
  }

  async putPolicy() {
    await this.iam.send(new PutRolePolicyCommand({
      PolicyDocument: canonicalJson(this.plan.bootstrapRole.inlinePolicy),
      PolicyName: this.plan.bootstrapRole.inlinePolicyName,
      RoleName: this.plan.bootstrapRole.name
    }));
  }

  async deletePolicy() {
    await this.iam.send(new DeleteRolePolicyCommand({
      PolicyName: this.plan.bootstrapRole.inlinePolicyName,
      RoleName: this.plan.bootstrapRole.name
    }));
  }

  async deleteRole() {
    await this.iam.send(new DeleteRoleCommand({
      RoleName: this.plan.bootstrapRole.name
    }));
  }

  async inspectPolicyAbsent() {
    const value = await this.inspectPolicy();
    if (value.state === "ABSENT") {
      return {
        state: "MATCH",
        receipt: {
          inlinePolicyAbsent: true,
          policyName: this.plan.bootstrapRole.inlinePolicyName,
          roleName: this.plan.bootstrapRole.name
        }
      };
    }
    return value.state === "MATCH" ? { state: "ABSENT" } : value;
  }

  async inspectRoleAbsent() {
    const value = await this.inspectRole();
    if (value.state === "ABSENT") {
      return {
        state: "MATCH",
        receipt: {
          bootstrapRoleAbsent: true,
          roleName: this.plan.bootstrapRole.name
        }
      };
    }
    return value.state === "MATCH" ? { state: "ABSENT" } : value;
  }

  async awsCliJson(argumentsList) {
    const code = "ONE_TIME_BOOTSTRAP_AWS_CLI_READBACK_REJECTED";
    requireCondition(Array.isArray(argumentsList) &&
      argumentsList.every((value) => typeof value === "string"), code);
    const { stdout, stderr } = await execFileAsync(
      this.awsCliPath,
      argumentsList,
      {
        encoding: "utf8",
        env: {
          AWS_EC2_METADATA_DISABLED: "true",
          AWS_PROFILE: this.plan.account.rootProfile,
          HOME: process.env.HOME,
          LANG: "C",
          LC_ALL: "C",
          PATH: "/usr/bin:/bin:/usr/local/bin"
        },
        maxBuffer: 8 * 1024 * 1024,
        timeout: 30_000
      }
    );
    requireCondition(stderr.trim() === "", code);
    try {
      const value = JSON.parse(stdout);
      requireCondition(plainObject(value), code);
      return value;
    } catch (cause) {
      reject(code, cause);
    }
  }

  async lookupRootMutationEvents() {
    const code = "ONE_TIME_BOOTSTRAP_CLOUDTRAIL_READBACK_REJECTED";
    const events = [];
    const seenTokens = new Set();
    let nextToken = null;
    for (let page = 0; page < 100; page += 1) {
      const response = await this.awsCliJson([
        "cloudtrail", "lookup-events",
        "--profile", this.plan.account.rootProfile,
        "--region", REGION,
        "--start-time", this.plan.preparedAt,
        "--end-time", this.now().toISOString(),
        "--max-results", "50",
        ...(nextToken === null ? [] : ["--next-token", nextToken]),
        "--output", "json",
        "--no-cli-pager"
      ]);
      requireCondition(Array.isArray(response.Events), code);
      events.push(...response.Events);
      if (response.NextToken === undefined) break;
      requireCondition(typeof response.NextToken === "string" &&
        response.NextToken.length > 0 &&
        !seenTokens.has(response.NextToken), code);
      seenTokens.add(response.NextToken);
      nextToken = response.NextToken;
      requireCondition(page < 99, code);
    }
    const rootEvents = [];
    const rootAssumeEventTimes = [];
    const writerAssumeEventTimes = [];
    for (const outer of events) {
      let event;
      try {
        event = JSON.parse(outer.CloudTrailEvent);
      } catch (cause) {
        reject(code, cause);
      }
      const request = event?.requestParameters;
      if (event?.eventName === "AssumeRole" &&
        event.errorCode === undefined && plainObject(request) &&
        request.roleArn === this.plan.writerContract.roleArn &&
        request.roleSessionName === this.plan.writerContract.roleSessionName &&
        request.externalId === this.plan.writerContract.externalId &&
        event.userIdentity?.type === "AssumedRole" &&
        event.userIdentity?.arn ===
          `arn:aws:sts::${this.plan.account.accountId}:assumed-role/` +
          `${this.plan.bootstrapRole.name}/` +
          `${this.plan.sessionContract.roleSessionName}`) {
        writerAssumeEventTimes.push(event.eventTime);
      }
      if (event?.userIdentity?.type === "Root" &&
        event.userIdentity.accountId === this.plan.account.accountId) {
        rootEvents.push({ event, outer });
        if (event.eventName === "AssumeRole" &&
          event.errorCode === undefined && plainObject(request) &&
          request.roleArn === this.plan.bootstrapRole.arn &&
          request.roleSessionName === this.plan.sessionContract.roleSessionName &&
          request.sourceIdentity === this.plan.sessionContract.sourceIdentity &&
          request.serialNumber === this.plan.account.mfaSerialArn) {
          rootAssumeEventTimes.push(event.eventTime);
        }
      }
    }
    const harmless = new Set([
      "ConsoleLogin", "GetCallerIdentity", "GetRole", "GetRolePolicy",
      "ListMFADevices", "ListRoleTags", "LookupEvents"
    ]);
    const expectedNames = [
      "CreateRole", "TagRole", "PutRolePolicy", "AssumeRole",
      "DeleteRolePolicy", "DeleteRole"
    ];
    const direct = [];
    const unexpected = [];
    for (const { event, outer } of rootEvents) {
      if (expectedNames.includes(event.eventName) &&
        event.errorCode === undefined) {
        direct.push(this.normalizeRootDirectEvent(event));
      } else if (event.readOnly !== true && !harmless.has(event.eventName)) {
        unexpected.push({
          eventIdSha256: sha256(String(outer.EventId ?? "")),
          eventName: String(event.eventName ?? ""),
          eventSource: String(event.eventSource ?? ""),
          eventTime: String(event.eventTime ?? "")
        });
      }
    }
    const order = new Map(expectedNames.map((name, index) => [name, index]));
    direct.sort((left, right) => order.get(left.eventName) -
      order.get(right.eventName));
    return Object.freeze({
      rootDirectEvents: direct,
      rootAssumeEventTimes: rootAssumeEventTimes.sort(),
      writerAssumeEventTimes: writerAssumeEventTimes.sort(),
      unexpectedRootMutationEvents: unexpected
    });
  }

  normalizeRootDirectEvent(event) {
    const code = "ONE_TIME_BOOTSTRAP_CLOUDTRAIL_EVENT_REJECTED";
    const request = event.requestParameters;
    requireCondition(plainObject(request), code);
    if (event.eventName === "CreateRole") {
      return {
        eventName: "CreateRole",
        roleName: request.roleName,
        rolePath: request.path
      };
    }
    if (event.eventName === "TagRole") {
      const tags = (request.tags ?? []).map((tag) => ({
        Key: tag.Key ?? tag.key,
        Value: tag.Value ?? tag.value
      }));
      return {
        eventName: "TagRole",
        roleName: request.roleName,
        tagsSha256: digest(tags)
      };
    }
    if (event.eventName === "PutRolePolicy") {
      const document = decodeIamDocument(request.policyDocument, code);
      return {
        eventName: "PutRolePolicy",
        policyName: request.policyName,
        policySha256: digest(document),
        roleName: request.roleName
      };
    }
    if (event.eventName === "AssumeRole") {
      return {
        durationSeconds: request.durationSeconds,
        eventName: "AssumeRole",
        mfaAuthenticated: request.serialNumber ===
          this.plan.account.mfaSerialArn,
        serialNumber: request.serialNumber,
        roleArn: request.roleArn,
        roleSessionName: request.roleSessionName,
        sourceIdentity: request.sourceIdentity
      };
    }
    if (event.eventName === "DeleteRolePolicy") {
      return {
        eventName: "DeleteRolePolicy",
        policyName: request.policyName,
        roleName: request.roleName
      };
    }
    if (event.eventName === "DeleteRole") {
      return { eventName: "DeleteRole", roleName: request.roleName };
    }
    reject(code);
  }

  async logout() {
    const { stderr } = await execFileAsync(this.awsCliPath, [
      "logout",
      "--profile",
      this.plan.account.rootProfile
    ], {
      encoding: "utf8",
      env: {
        AWS_EC2_METADATA_DISABLED: "true",
        AWS_PROFILE: this.plan.account.rootProfile,
        HOME: process.env.HOME,
        LANG: "C",
        LC_ALL: "C",
        PATH: "/usr/bin:/bin:/usr/local/bin"
      },
      maxBuffer: 64 * 1024,
      timeout: 30_000
    });
    requireCondition(stderr === "",
      "ONE_TIME_BOOTSTRAP_AWS_LOGOUT_REJECTED");
    return {
      cachedRootSessionAbsent: true,
      command: ["aws", "logout", "--profile",
        this.plan.account.rootProfile],
      exitCode: 0,
      profile: this.plan.account.rootProfile
    };
  }
}

export class AwsOneTimeBootstrapB0Provider {
  constructor({ clock = () => new Date(), credentials, plan }) {
    requireCondition(typeof clock === "function" && plainObject(credentials),
      "ONE_TIME_BOOTSTRAP_AWS_B0_PROVIDER_REJECTED");
    this.clock = clock;
    this.plan = plan;
    const configuration = awsClientConfiguration(credentials);
    this.cloudFormation = new CloudFormationClient(configuration);
    this.iam = new IAMClient(configuration);
    this.secrets = new SecretsManagerClient(configuration);
    this.sts = new STSClient(configuration);
  }

  now() {
    const value = this.clock();
    requireCondition(value instanceof Date && Number.isFinite(value.getTime()),
      "ONE_TIME_BOOTSTRAP_AWS_CLOCK_REJECTED");
    requireCondition(value.getTime() < Date.parse(this.plan.notAfter),
      "ONE_TIME_BOOTSTRAP_AWS_OPERATION_EXPIRED");
    return value;
  }

  destroy() {
    this.cloudFormation.destroy();
    this.iam.destroy();
    this.secrets.destroy();
    this.sts.destroy();
  }

  async createChangeSet({ targetKey, templateBody }) {
    const target = this.plan.targets[targetKey];
    await this.cloudFormation.send(new CreateChangeSetCommand({
      Capabilities: target.capabilities,
      ChangeSetName: target.changeSetName,
      ChangeSetType: "CREATE",
      ClientToken: `b0-${this.plan.operation.operationToken}-${targetKey}`,
      Parameters: Object.entries(target.parameters).map(
        ([ParameterKey, ParameterValue]) => ({
          ParameterKey,
          ParameterValue
        })
      ),
      StackName: target.stackName,
      Tags: target.tags,
      TemplateBody: templateBody
    }));
  }

  async inspectChangeSet({ targetKey }) {
    const target = this.plan.targets[targetKey];
    let response;
    for (let attempt = 0; attempt < 120; attempt += 1) {
      try {
        response = await this.cloudFormation.send(
          new DescribeChangeSetCommand({
            ChangeSetName: target.changeSetName,
            StackName: target.stackName
          })
        );
      } catch (cause) {
        if (isNotFound(cause)) return { state: "ABSENT" };
        throw cause;
      }
      if (!["CREATE_PENDING", "CREATE_IN_PROGRESS"].includes(
        response.Status
      )) break;
      this.now();
      await waitBriefly();
    }
    if (response?.Status !== "CREATE_COMPLETE" ||
      response.ExecutionStatus !== "AVAILABLE") {
      return {
        state: "CONFLICT",
        receipt: {
          executionStatus: response?.ExecutionStatus ?? null,
          status: response?.Status ?? null
        }
      };
    }
    const template = await this.cloudFormation.send(new GetTemplateCommand({
      ChangeSetName: target.changeSetName,
      StackName: target.stackName,
      TemplateStage: "Original"
    }));
    const evidence = {
      accountId: this.plan.account.accountId,
      capabilities: response.Capabilities ?? [],
      changeSetArn: response.ChangeSetId,
      changeSetName: response.ChangeSetName,
      changeSetType: response.ChangeSetType,
      executionStatus: response.ExecutionStatus,
      observedAt: this.now().toISOString(),
      parameters: parameterMap(response.Parameters),
      region: REGION,
      roleArn: response.RoleARN ?? null,
      stackArn: response.StackId,
      stackName: response.StackName,
      status: response.Status,
      tags: response.Tags ?? [],
      templateBodyBase64: exactTemplateBody(
        template.TemplateBody,
        "ONE_TIME_BOOTSTRAP_AWS_CHANGE_SET_TEMPLATE_REJECTED"
      )
    };
    let preExecuteReceipt;
    try {
      preExecuteReceipt = validatePreExecuteChangeSetEvidence(
        this.plan,
        targetKey,
        evidence
      );
    } catch {
      return { state: "CONFLICT", receipt: { exactReadback: false } };
    }
    return {
      state: "MATCH",
      evidence,
      receipt: {
        changeSetArn: evidence.changeSetArn,
        exactReadback: true,
        preExecuteReceipt,
        status: evidence.status,
        templateSha256: target.templateSha256
      }
    };
  }

  async executeChangeSet({ targetKey }) {
    const target = this.plan.targets[targetKey];
    await this.cloudFormation.send(new ExecuteChangeSetCommand({
      ChangeSetName: target.changeSetName,
      ClientRequestToken:
        `b0-exec-${this.plan.operation.operationToken}-${targetKey}`,
      StackName: target.stackName
    }));
  }

  async stackResources(stackName) {
    const pages = await paginateToken((NextToken) =>
      this.cloudFormation.send(new ListStackResourcesCommand({
        ...(NextToken === undefined ? {} : { NextToken }),
        StackName: stackName
      }))
    );
    return pages.flatMap((page) => page.StackResourceSummaries ?? []);
  }

  async stackSnapshot(targetKey, stackIdentifier =
    this.plan.targets[targetKey].stackName) {
    const target = this.plan.targets[targetKey];
    const response = await this.cloudFormation.send(new DescribeStacksCommand({
      StackName: stackIdentifier
    }));
    requireCondition(Array.isArray(response.Stacks) &&
      response.Stacks.length === 1,
    "ONE_TIME_BOOTSTRAP_AWS_STACK_REJECTED");
    const stack = response.Stacks[0];
    const [resources, template] = await Promise.all([
      this.stackResources(stackIdentifier),
      this.cloudFormation.send(new GetTemplateCommand({
        StackName: stackIdentifier,
        TemplateStage: "Original"
      }))
    ]);
    return { resources, stack, template };
  }

  async inspectStack({ expectedStackArn = null, targetKey }) {
    const target = this.plan.targets[targetKey];
    const stackIdentifier = expectedStackArn ?? target.stackName;
    let described;
    for (let attempt = 0; attempt < 900; attempt += 1) {
      try {
        described = await this.cloudFormation.send(
          new DescribeStacksCommand({ StackName: stackIdentifier })
        );
      } catch (cause) {
        if (isNotFound(cause)) return { state: "ABSENT" };
        throw cause;
      }
      requireCondition(Array.isArray(described.Stacks) &&
        described.Stacks.length === 1,
      "ONE_TIME_BOOTSTRAP_AWS_STACK_REJECTED");
      const status = described.Stacks[0].StackStatus;
      if (status === "REVIEW_IN_PROGRESS") return { state: "ABSENT" };
      if (!String(status).endsWith("_IN_PROGRESS")) break;
      this.now();
      await waitBriefly();
    }
    const stack = described?.Stacks?.[0];
    if (stack?.StackStatus !== "CREATE_COMPLETE") {
      return {
        state: "CONFLICT",
        receipt: { status: stack?.StackStatus ?? null }
      };
    }
    const snapshot = await this.stackSnapshot(targetKey, stackIdentifier);
    const evidence = {
      accountId: this.plan.account.accountId,
      capabilities: snapshot.stack.Capabilities ?? [],
      observedAt: this.now().toISOString(),
      parameters: parameterMap(snapshot.stack.Parameters),
      region: REGION,
      resources: snapshot.resources.map((resource) => ({
        logicalId: resource.LogicalResourceId,
        physicalId: resource.PhysicalResourceId,
        resourceStatus: resource.ResourceStatus,
        type: resource.ResourceType
      })),
      roleArn: snapshot.stack.RoleARN ?? null,
      stackArn: snapshot.stack.StackId,
      stackName: snapshot.stack.StackName,
      stackStatus: snapshot.stack.StackStatus,
      tags: snapshot.stack.Tags ?? [],
      templateBodyBase64: exactTemplateBody(
        snapshot.template.TemplateBody,
        "ONE_TIME_BOOTSTRAP_AWS_STACK_TEMPLATE_REJECTED"
      )
    };
    try {
      requireCondition(expectedStackArn === null ||
        evidence.stackArn === expectedStackArn,
      "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
      validatePostCreateStackEvidence(this.plan, targetKey, evidence);
    } catch {
      return { state: "CONFLICT", receipt: { exactReadback: false } };
    }
    return {
      state: "MATCH",
      evidence,
      receipt: {
        exactReadback: true,
        stackArn: evidence.stackArn,
        status: evidence.stackStatus,
        templateSha256: target.templateSha256
      }
    };
  }

  async enableTerminationProtection({ stackArn, targetKey }) {
    requireCondition(typeof stackArn === "string",
      "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
    await this.cloudFormation.send(new UpdateTerminationProtectionCommand({
      EnableTerminationProtection: true,
      StackName: stackArn
    }));
  }

  async inspectTerminationProtection({ stackArn, targetKey }) {
    const stack = await this.inspectStack({
      expectedStackArn: stackArn,
      targetKey
    });
    if (stack.state !== "MATCH") return stack;
    const response = await this.cloudFormation.send(new DescribeStacksCommand({
      StackName: stackArn
    }));
    requireCondition(response.Stacks?.length === 1 &&
      response.Stacks[0].StackId === stackArn,
    "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
    const enabled = response.Stacks[0].EnableTerminationProtection === true;
    return {
      state: enabled ? "MATCH" : "ABSENT",
      receipt: {
        enabled,
        exactStackReadback: true,
        stackArn,
        stackName: this.plan.targets[targetKey].stackName
      }
    };
  }

  async callerIdentity() {
    const value = await this.sts.send(new GetCallerIdentityCommand({}));
    return { Account: value.Account, Arn: value.Arn, UserId: value.UserId };
  }

  async collectStackForA1(targetKey, expectedStackArn) {
    requireCondition(typeof expectedStackArn === "string",
      "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
    const snapshot = await this.stackSnapshot(targetKey, expectedStackArn);
    requireCondition(snapshot.stack.StackId === expectedStackArn,
      "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
    let deployedTemplate;
    try {
      deployedTemplate = JSON.parse(snapshot.template.TemplateBody);
    } catch (cause) {
      reject("ONE_TIME_BOOTSTRAP_AWS_A1_TEMPLATE_REJECTED", cause);
    }
    return {
      deployedTemplate,
      resources: snapshot.resources.map((resource) => ({
        logicalResourceId: resource.LogicalResourceId,
        physicalResourceId: resource.PhysicalResourceId,
        resourceStatus: resource.ResourceStatus,
        resourceType: resource.ResourceType
      })),
      stack: {
        capabilities: snapshot.stack.Capabilities ?? [],
        creationTime: snapshot.stack.CreationTime.toISOString(),
        outputs: outputMap(snapshot.stack.Outputs),
        parameters: parameterMap(snapshot.stack.Parameters),
        stackId: snapshot.stack.StackId,
        stackName: snapshot.stack.StackName,
        stackStatus: snapshot.stack.StackStatus,
        tags: snapshot.stack.Tags ?? [],
        terminationProtection:
          snapshot.stack.EnableTerminationProtection === true
      }
    };
  }

  async collectRole(roleName, { includeCreatedAt }) {
    const [roleResponse, policyPages, attachedPages, tagPages] =
      await Promise.all([
        this.iam.send(new GetRoleCommand({ RoleName: roleName })),
        paginateMarker((Marker) => this.iam.send(
          new ListRolePoliciesCommand({
            ...(Marker === undefined ? {} : { Marker }),
            RoleName: roleName
          })
        )),
        paginateMarker((Marker) => this.iam.send(
          new ListAttachedRolePoliciesCommand({
            ...(Marker === undefined ? {} : { Marker }),
            RoleName: roleName
          })
        )),
        paginateMarker((Marker) => this.iam.send(
          new ListRoleTagsCommand({
            ...(Marker === undefined ? {} : { Marker }),
            RoleName: roleName
          })
        ))
      ]);
    const names = policyPages.flatMap((page) => page.PolicyNames ?? []);
    requireCondition(names.length === 1,
      "ONE_TIME_BOOTSTRAP_AWS_ROLE_POLICY_REJECTED");
    const inline = await this.iam.send(new GetRolePolicyCommand({
      PolicyName: names[0],
      RoleName: roleName
    }));
    const role = roleResponse.Role;
    requireCondition(role?.RoleName === roleName,
      "ONE_TIME_BOOTSTRAP_AWS_ROLE_REJECTED");
    return {
      arn: role.Arn,
      attachedPolicyArns: attachedPages.flatMap((page) =>
        (page.AttachedPolicies ?? []).map((item) => item.PolicyArn)),
      ...(includeCreatedAt ? { createdAt: role.CreateDate.toISOString() } : {}),
      description: role.Description ?? null,
      inlinePolicy: decodeIamDocument(
        inline.PolicyDocument,
        "ONE_TIME_BOOTSTRAP_AWS_ROLE_POLICY_REJECTED"
      ),
      inlinePolicyNames: names,
      maxSessionDuration: role.MaxSessionDuration,
      path: role.Path,
      permissionsBoundaryArn:
        role.PermissionsBoundary?.PermissionsBoundaryArn ?? null,
      roleId: role.RoleId,
      roleName: role.RoleName,
      tags: tagPages.flatMap((page) => page.Tags ?? []),
      trust: decodeIamDocument(
        role.AssumeRolePolicyDocument,
        "ONE_TIME_BOOTSTRAP_AWS_ROLE_TRUST_REJECTED"
      )
    };
  }

  async collectA1BootstrapReadback({ expectedStackArn, plan }) {
    const [callerIdentity, collected, role, oidc] = await Promise.all([
      this.callerIdentity(),
      this.collectStackForA1("freshPrimaryBootstrapRole", expectedStackArn),
      this.collectRole(plan.roleName, { includeCreatedAt: true }),
      this.iam.send(new GetOpenIDConnectProviderCommand({
        OpenIDConnectProviderArn: plan.githubOidcProviderArn
      }))
    ]);
    return {
      schemaVersion: "prooftoact.fresh-primary-bootstrap-role-readback-input.v1",
      callerIdentity,
      deployedTemplate: collected.deployedTemplate,
      observedAt: this.now().toISOString(),
      oidcProvider: {
        arn: plan.githubOidcProviderArn,
        clientIds: oidc.ClientIDList ?? [],
        thumbprints: oidc.ThumbprintList ?? [],
        url: oidc.Url
      },
      resources: collected.resources,
      role,
      stack: collected.stack
    };
  }

  async collectSecret(arn) {
    const [description, resourcePolicy, pages] = await Promise.all([
      this.secrets.send(new DescribeSecretCommand({ SecretId: arn })),
      this.secrets.send(new GetResourcePolicyCommand({ SecretId: arn })),
      paginateToken((NextToken) => this.secrets.send(
        new ListSecretVersionIdsCommand({
          IncludeDeprecated: true,
          MaxResults: 100,
          ...(NextToken === undefined ? {} : { NextToken }),
          SecretId: arn
        })
      ))
    ]);
    const versions = {};
    for (const version of pages.flatMap((page) => page.Versions ?? [])) {
      requireCondition(typeof version.VersionId === "string" &&
        !Object.hasOwn(versions, version.VersionId),
      "ONE_TIME_BOOTSTRAP_AWS_SECRET_VERSION_REJECTED");
      versions[version.VersionId] = version.VersionStages ?? [];
    }
    return {
      arn: description.ARN,
      kmsKeyId: description.KmsKeyId ?? null,
      name: description.Name,
      replicationRegions: (description.ReplicationStatus ?? []).map(
        (entry) => entry.Region
      ),
      resourcePolicy: resourcePolicy.ResourcePolicy ?? null,
      rotationEnabled: description.RotationEnabled === true,
      tags: description.Tags ?? [],
      versions
    };
  }

  async collectA1CustodyReadback({
    approval,
    phase,
    plan,
    sealReceipt,
    secretArnsFromOutputs,
    expectedStackArn
  }) {
    const [callerIdentity, collected, writerRole] = await Promise.all([
      this.callerIdentity(),
      this.collectStackForA1(
        "freshPrimaryCredentialCustody",
        expectedStackArn
      ),
      this.collectRole(plan.writerRoleName, { includeCreatedAt: false })
    ]);
    const secretArns = secretArnsFromOutputs({
      outputs: collected.stack.outputs,
      plan
    });
    const secrets = Object.fromEntries(await Promise.all(
      Object.entries(secretArns).map(async ([name, arn]) =>
        [name, await this.collectSecret(arn)])
    ));
    let creatorPresent = false;
    try {
      const response = await this.iam.send(new GetRoleCommand({
        RoleName: this.plan.bootstrapRole.name
      }));
      creatorPresent = response.Role?.Arn === this.plan.bootstrapRole.arn;
    } catch (cause) {
      if (!isNotFound(cause)) throw cause;
    }
    return {
      schemaVersion:
        "prooftoact.fresh-primary-credential-custody-readback-input.v1",
      approval,
      callerIdentity,
      creatorRole: creatorPresent ? {
        assumeRoleDenied: false,
        getRoleError: null,
        state: "PRESENT"
      } : {
        assumeRoleDenied: true,
        getRoleError: "NoSuchEntity",
        state: "DELETED"
      },
      deployedTemplate: collected.deployedTemplate,
      observedAt: this.now().toISOString(),
      phase,
      resources: collected.resources,
      sealReceipt,
      secrets,
      stack: collected.stack,
      writerRole
    };
  }

  async collectA1CustodyOutputs({ expectedStackArn }) {
    const collected = await this.collectStackForA1(
      "freshPrimaryCredentialCustody",
      expectedStackArn
    );
    return collected.stack.outputs;
  }

  async runNegativeSimulations({ plan }) {
    const results = [];
    for (const vector of plan) {
      const response = await this.iam.send(
        new SimulatePrincipalPolicyCommand({
          ActionNames: [vector.actionName],
          ContextEntries: [
            {
              ContextKeyName: "aws:CalledVia",
              ContextKeyType: "stringList",
              ContextKeyValues: ["direct.prooftoact.invalid"]
            },
            {
              ContextKeyName: "aws:CurrentTime",
              ContextKeyType: "date",
              ContextKeyValues: [this.now().toISOString()]
            }
          ],
          PolicySourceArn: this.plan.bootstrapRole.arn,
          ResourceArns: [vector.resourceArn]
        })
      );
      requireCondition(Array.isArray(response.EvaluationResults) &&
        response.EvaluationResults.length === 1,
      "ONE_TIME_BOOTSTRAP_AWS_SIMULATION_REJECTED");
      const result = response.EvaluationResults[0];
      results.push({
        actionName: vector.actionName,
        evalDecision: result.EvalDecision,
        id: vector.id,
        missingContextValues: result.MissingContextValues ?? [],
        resourceArn: vector.resourceArn
      });
    }
    return results;
  }

  async listInFlightChangeSets() {
    const inFlight = [];
    for (const targetKey of oneTimeBootstrapConstants.TARGET_KEYS) {
      const target = this.plan.targets[targetKey];
      const pages = await paginateToken((NextToken) =>
        this.cloudFormation.send(new ListChangeSetsCommand({
          ...(NextToken === undefined ? {} : { NextToken }),
          StackName: target.stackName
        }))
      );
      for (const summary of pages.flatMap((page) => page.Summaries ?? [])) {
        if (String(summary.Status).endsWith("_IN_PROGRESS") ||
          String(summary.Status).endsWith("_PENDING") ||
          summary.ExecutionStatus === "EXECUTE_IN_PROGRESS") {
          inFlight.push({
            changeSetName: summary.ChangeSetName,
            stackName: target.stackName,
            status: summary.Status
          });
        }
      }
    }
    return inFlight;
  }

  async countA2TargetSecretVersions({ expectedStackArn }) {
    requireCondition(typeof expectedStackArn === "string",
      "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
    const resources = await this.stackResources(
      expectedStackArn
    );
    const resource = resources.find((item) =>
      item.LogicalResourceId === "PrivateRecoveryMcpSecret");
    requireCondition(typeof resource?.PhysicalResourceId === "string",
      "ONE_TIME_BOOTSTRAP_AWS_A2_SECRET_REJECTED");
    const pages = await paginateToken((NextToken) =>
      this.secrets.send(new ListSecretVersionIdsCommand({
        IncludeDeprecated: true,
        MaxResults: 100,
        ...(NextToken === undefined ? {} : { NextToken }),
        SecretId: resource.PhysicalResourceId
      }))
    );
    return pages.reduce((count, page) =>
      count + (page.Versions ?? []).length, 0);
  }

  async createWriterProvider({ credentials, secretArns }) {
    const allowed = new Set(secretArns);
    const configuration = awsClientConfiguration(credentials);
    const secrets = new SecretsManagerClient(configuration);
    const sts = new STSClient(configuration);
    function exactArn(arn) {
      requireCondition(allowed.has(arn),
        "ONE_TIME_BOOTSTRAP_AWS_WRITER_ARN_REJECTED");
      return arn;
    }
    return Object.freeze({
      describeSecret: ({ arn }) => secrets.send(new DescribeSecretCommand({
        SecretId: exactArn(arn)
      })),
      getCallerIdentity: () => sts.send(new GetCallerIdentityCommand({})),
      getSecretResourcePolicy: ({ arn }) => secrets.send(
        new GetResourcePolicyCommand({ SecretId: exactArn(arn) })
      ),
      listSecretVersions: ({ arn, nextToken }) => secrets.send(
        new ListSecretVersionIdsCommand({
          IncludeDeprecated: true,
          MaxResults: 100,
          ...(nextToken === null ? {} : { NextToken: nextToken }),
          SecretId: exactArn(arn)
        })
      ),
      putSecretVersion: ({ arn, clientRequestToken, secretString }) =>
        secrets.send(new PutSecretValueCommand({
          ClientRequestToken: clientRequestToken,
          SecretId: exactArn(arn),
          SecretString: secretString,
          VersionStages: ["AWSCURRENT"]
        })),
      async readSecretVersion({ arn, versionId }) {
        try {
          return await secrets.send(new GetSecretValueCommand({
            SecretId: exactArn(arn),
            VersionId: versionId,
            VersionStage: "AWSCURRENT"
          }));
        } catch (cause) {
          if (isNotFound(cause)) return null;
          throw cause;
        }
      }
    });
  }

  async assumeBootstrapSession({ writer }) {
    requireCondition(writer === true,
      "ONE_TIME_BOOTSTRAP_AWS_WRITER_ASSUME_REJECTED");
    const requestTime = this.now();
    const response = await this.sts.send(new AssumeRoleCommand({
      DurationSeconds: oneTimeBootstrapConstants.SESSION_DURATION_SECONDS,
      ExternalId: this.plan.writerContract.externalId,
      RoleArn: this.plan.writerContract.roleArn,
      RoleSessionName: this.plan.writerContract.roleSessionName
    }));
    const credentials = response.Credentials;
    requireCondition(credentials?.Expiration instanceof Date &&
      typeof credentials.AccessKeyId === "string" &&
      typeof credentials.SecretAccessKey === "string" &&
      typeof credentials.SessionToken === "string",
    "ONE_TIME_BOOTSTRAP_AWS_WRITER_ASSUME_REJECTED");
    const issuedAt = new Date(credentials.Expiration.getTime() - 900_000);
    requireCondition(issuedAt.getTime() >= requestTime.getTime() - 5_000,
      "ONE_TIME_BOOTSTRAP_AWS_WRITER_ASSUME_REJECTED");
    const receipt = {
      schemaVersion: "prooftoact.one-time-bootstrap-session-receipt.v1",
      status: "SANITIZED_PROVIDER_SESSION_ACCEPTED",
      accountId: this.plan.account.accountId,
      operationId: this.plan.operation.operationId,
      roleArn: this.plan.writerContract.roleArn,
      assumedRoleArn: response.AssumedRoleUser?.Arn,
      roleSessionName: this.plan.writerContract.roleSessionName,
      sourceIdentity: this.plan.sessionContract.sourceIdentity,
      mfaAuthenticated: false,
      mfaSerialArn: null,
      durationSeconds: 900,
      issuedAt: issuedAt.toISOString(),
      credentialsExpiration: credentials.Expiration.toISOString(),
      rawCredentialFieldsPresent: false,
      credentialMaterialLogged: false
    };
    validateBootstrapSessionReceipt(this.plan, receipt, { writer: true });
    let live = {
      accessKeyId: credentials.AccessKeyId,
      expiration: credentials.Expiration,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken
    };
    response.Credentials = undefined;
    let consumed = false;
    return Object.freeze({
      receipt: Object.freeze(receipt),
      async withPrivateCredentials(callback) {
        requireCondition(!consumed && live !== null &&
          typeof callback === "function",
        "ONE_TIME_BOOTSTRAP_AWS_WRITER_LEASE_REJECTED");
        consumed = true;
        const value = live;
        live = null;
        try {
          return await callback(value);
        } finally {
          value.accessKeyId = null;
          value.expiration = null;
          value.secretAccessKey = null;
          value.sessionToken = null;
        }
      },
      destroy() {
        if (live !== null) {
          live.accessKeyId = null;
          live.expiration = null;
          live.secretAccessKey = null;
          live.sessionToken = null;
          live = null;
        }
        consumed = true;
      }
    });
  }
}

async function convergeRootSetup({ gate, journal, plan, rootProvider }) {
  await gate.invoke("discovery", "sts:GetCallerIdentity", () =>
    rootProvider.callerIdentity());
  const mfaDiscoveryReceipt = await gate.invoke(
    "discovery",
    "iam:ListMFADevices",
    () => rootProvider.discoverMfa()
  );
  gate.advance("setup");
  const createReceipt = await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      arn: plan.bootstrapRole.arn,
      maxSessionDuration: plan.bootstrapRole.maxSessionDuration,
      path: plan.bootstrapRole.path,
      roleName: plan.bootstrapRole.name,
      trustPolicySha256: plan.bootstrapRole.trustPolicySha256
    },
    dispatch: () => gate.invoke("setup", "iam:CreateRole", () =>
      rootProvider.createRole()),
    id: "root-create-b0-role",
    inspect: () => gate.invoke("setup", "iam:GetRole", () =>
      rootProvider.inspectRole()),
    journal,
    mutationClass: "iam:CreateRole"
  });
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      roleName: plan.bootstrapRole.name,
      tagsSha256: digest(plan.bootstrapRole.roleTags)
    },
    dispatch: () => gate.invoke("setup", "iam:TagRole", () =>
      rootProvider.tagRole()),
    id: "root-tag-b0-role",
    inspect: () => gate.invoke("setup", "iam:ListRoleTags", () =>
      rootProvider.inspectTags()),
    journal,
    mutationClass: "iam:TagRole"
  });
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      inlinePolicyName: plan.bootstrapRole.inlinePolicyName,
      inlinePolicySha256: plan.bootstrapRole.inlinePolicySha256,
      roleName: plan.bootstrapRole.name
    },
    dispatch: () => gate.invoke("setup", "iam:PutRolePolicy", () =>
      rootProvider.putPolicy()),
    id: "root-put-b0-inline-policy",
    inspect: () => gate.invoke("setup", "iam:GetRolePolicy", () =>
      rootProvider.inspectPolicy()),
    journal,
    mutationClass: "iam:PutRolePolicy"
  });
  return mfaDiscoveryReceipt;
}

async function assumeB0WithJournal({
  gate,
  journal,
  mfaDiscoveryReceipt,
  mfaFd,
  plan,
  rootProvider
}) {
  const code = "ONE_TIME_BOOTSTRAP_B0_SESSION_RECONCILIATION_REQUIRED";
  const ids = rootAssumeStepIds(journal);
  const reusable = ids.length > 0 &&
    journal.step(ids.at(-1))?.state === "INTENT_RECORDED" ? ids.at(-1) : null;
  const id = reusable ?? nextSessionStepId(
    journal,
    "root-assume-b0-session",
    ids
  );
  requireCondition(rootProvider.clock().getTime() +
    oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000 +
    SESSION_CLEANUP_RESERVE_MS <
      Date.parse(plan.notAfter), code);
  const step = journal.recordIntent(
    id,
    "sts:AssumeRole",
    {
      durationSeconds: 900,
      mfaSerialArn: plan.account.mfaSerialArn,
      roleArn: plan.bootstrapRole.arn,
      roleSessionName: plan.sessionContract.roleSessionName,
      sourceIdentity: plan.sessionContract.sourceIdentity
    }
  );
  requireCondition(step.state === "INTENT_RECORDED" &&
    step.dispatchStartedAt === null, code);
  journal.recordDispatchStarted(id);
  let lease;
  try {
    lease = await gate.invoke("setup", "sts:AssumeRole", () =>
      assumeOneTimeBootstrapRootSession({
        clock: rootProvider.clock,
        mfaDiscoveryReceipt,
        mfaFd,
        plan,
        stsClient: rootProvider.sts
      }));
  } catch (cause) {
    reject(code, cause);
  }
  journal.recordAccepted(
    id,
    "POST_DISPATCH_RECONCILIATION",
    { sessionReceipt: lease.receipt }
  );
  return lease;
}

async function assumeWriterWithJournal({ b0Provider, journal, plan }) {
  const code = "ONE_TIME_BOOTSTRAP_WRITER_SESSION_RECONCILIATION_REQUIRED";
  const ids = writerAssumeStepIds(journal);
  const reusable = ids.length > 0 &&
    journal.step(ids.at(-1))?.state === "INTENT_RECORDED" ? ids.at(-1) : null;
  const id = reusable ?? nextSessionStepId(
    journal,
    "b0-assume-a1-writer-session",
    ids
  );
  requireCondition(b0Provider.now().getTime() +
    oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000 +
    SESSION_CLEANUP_RESERVE_MS <
      Date.parse(plan.notAfter), code);
  const step = journal.recordIntent(
    id,
    "sts:AssumeRole",
    {
      durationSeconds: 900,
      externalIdSha256: sha256(plan.writerContract.externalId),
      roleArn: plan.writerContract.roleArn,
      roleSessionName: plan.writerContract.roleSessionName
    }
  );
  requireCondition(step.state === "INTENT_RECORDED" &&
    step.dispatchStartedAt === null, code);
  journal.recordDispatchStarted(id);
  let lease;
  try {
    lease = await b0Provider.assumeBootstrapSession({ writer: true });
  } catch (cause) {
    reject(code, cause);
  }
  journal.recordAccepted(
    id,
    "POST_DISPATCH_RECONCILIATION",
    { sessionReceipt: lease.receipt }
  );
  return lease;
}

function validateProviderSurface(provider) {
  const methods = [
    "assumeBootstrapSession",
    "collectA1BootstrapReadback",
    "collectA1CustodyReadback",
    "collectA1CustodyOutputs",
    "countA2TargetSecretVersions",
    "createChangeSet",
    "createWriterProvider",
    "enableTerminationProtection",
    "executeChangeSet",
    "inspectChangeSet",
    "inspectStack",
    "inspectTerminationProtection",
    "listInFlightChangeSets",
    "runNegativeSimulations"
  ];
  requireCondition(provider !== null && methods.every((name) =>
    typeof provider[name] === "function"),
  "ONE_TIME_BOOTSTRAP_PROVIDER_SURFACE_REJECTED");
}

function classifyMatch(value) {
  requireCondition(plainObject(value) &&
    ["ABSENT", "MATCH", "CONFLICT"].includes(value.state),
  "ONE_TIME_BOOTSTRAP_PROVIDER_INSPECTION_REJECTED");
  return value.state;
}

function sanitizedInspectionReceipt(value) {
  requireCondition(plainObject(value.receipt),
    "ONE_TIME_BOOTSTRAP_PROVIDER_INSPECTION_REJECTED");
  assertNoCredentialMaterial(value.receipt);
  return value.receipt;
}

async function convergeTarget({
  journal,
  plan,
  provider,
  sourceRoot,
  targetKey
}) {
  const target = plan.targets[targetKey];
  const templateBytes = readReviewedRegularFile(
    path.join(sourceRoot, target.path),
    51_200,
    "ONE_TIME_BOOTSTRAP_TEMPLATE_READ_REJECTED"
  );
  requireCondition(sha256(templateBytes) === target.templateSha256,
    "ONE_TIME_BOOTSTRAP_TEMPLATE_READ_REJECTED");
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      accountId: plan.account.accountId,
      changeSetName: target.changeSetName,
      changeSetType: "CREATE",
      stackName: target.stackName,
      templateSha256: target.templateSha256,
      transport: "TemplateBody"
    },
    dispatch: () => provider.createChangeSet({
      targetKey,
      templateBody: templateBytes.toString("utf8")
    }),
    id: `create-${targetKey}-change-set`,
    inspect: () => provider.inspectChangeSet({ targetKey }),
    journal,
    mutationClass: "cloudformation:CreateChangeSet"
  });
  const executeStep = journal.step(`execute-${targetKey}-change-set`);
  let preExecuteReceipt = createReceipt.preExecuteReceipt;
  if (executeStep === null) {
    const changeSet = await provider.inspectChangeSet({ targetKey });
    requireCondition(changeSet.state === "MATCH",
      "ONE_TIME_BOOTSTRAP_CHANGE_SET_READBACK_REJECTED");
    preExecuteReceipt = validatePreExecuteChangeSetEvidence(
      plan,
      targetKey,
      changeSet.evidence
    );
  }
  requireCondition(preExecuteReceipt?.status ===
    "EXACT_CREATE_CHANGE_SET_ACCEPTED_FOR_EXECUTION",
  "ONE_TIME_BOOTSTRAP_CHANGE_SET_READBACK_REJECTED");
  const executeReceipt = await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      changeSetName: target.changeSetName,
      preExecuteReceiptSha256: preExecuteReceipt.receiptSha256,
      stackName: target.stackName
    },
    dispatch: () => provider.executeChangeSet({ targetKey }),
    id: `execute-${targetKey}-change-set`,
    inspect: () => provider.inspectStack({ targetKey }),
    journal,
    mutationClass: "cloudformation:ExecuteChangeSet"
  });
  requireCondition(typeof executeReceipt.stackArn === "string",
    "ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED");
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      enabled: true,
      stackArn: executeReceipt.stackArn,
      stackName: target.stackName,
      templateSha256: target.templateSha256
    },
    dispatch: () => provider.enableTerminationProtection({
      stackArn: executeReceipt.stackArn,
      targetKey
    }),
    id: `protect-${targetKey}-stack`,
    inspect: () => provider.inspectTerminationProtection({
      stackArn: executeReceipt.stackArn,
      targetKey
    }),
    journal,
    mutationClass: "cloudformation:UpdateTerminationProtection"
  });
  const stack = await provider.inspectStack({
    expectedStackArn: executeReceipt.stackArn,
    targetKey
  });
  requireCondition(stack.state === "MATCH",
    "ONE_TIME_BOOTSTRAP_STACK_READBACK_REJECTED");
  const postCreateReceipt = validatePostCreateStackEvidence(
    plan,
    targetKey,
    stack.evidence
  );
  return Object.freeze({ postCreateReceipt, preExecuteReceipt });
}

async function collectAndVerifyA1CustodyPhase({
  a1,
  approval,
  b0Provider,
  expectedStackArn,
  phase,
  sealReceipt
}) {
  requireCondition(["EMPTY", "SEALED"].includes(phase) &&
    typeof a1?.secretArnsFromOutputs === "function" &&
    typeof a1?.verifyCustodyReadback === "function",
  "ONE_TIME_BOOTSTRAP_A1_CUSTODY_PHASE_REJECTED");
  const input = await b0Provider.collectA1CustodyReadback({
    approval,
    expectedStackArn,
    phase,
    plan: a1.custodyPlan,
    sealReceipt,
    secretArnsFromOutputs: a1.secretArnsFromOutputs
  });
  const receipt = a1.verifyCustodyReadback({
    collectorBinding: a1.collectorBinding,
    input,
    plan: a1.custodyPlan
  });
  return Object.freeze({ input, receipt });
}

export async function runOneTimeBootstrapB0Session({
  a1,
  authorizationReceipt,
  b0Provider,
  journal,
  plan,
  sourceRoot,
  valueLease
}) {
  validateProviderSurface(b0Provider);
  const preExecuteReceipts = {};
  const postCreateReceipts = {};
  for (const targetKey of oneTimeBootstrapConstants.TARGET_KEYS) {
    const receipts = await convergeTarget({
      journal,
      plan,
      provider: b0Provider,
      sourceRoot,
      targetKey
    });
    preExecuteReceipts[targetKey] = receipts.preExecuteReceipt;
    postCreateReceipts[targetKey] = receipts.postCreateReceipt;
  }
  const emptyBootstrapInput = await b0Provider.collectA1BootstrapReadback({
    expectedStackArn:
      postCreateReceipts.freshPrimaryBootstrapRole.stackArn,
    plan: a1.bootstrapPlan
  });
  a1.verifyBootstrapReadback({
    collectorBinding: a1.collectorBinding,
    input: emptyBootstrapInput,
    plan: a1.bootstrapPlan
  });
  const priorSealStep = journal.step("seal-five-a1-writer-values");
  let custodyOutputs;
  if (priorSealStep === null ||
    priorSealStep.state === "INTENT_RECORDED") {
    const emptyCustody = await collectAndVerifyA1CustodyPhase({
      a1,
      approval: null,
      b0Provider,
      expectedStackArn:
        postCreateReceipts.freshPrimaryCredentialCustody.stackArn,
      phase: "EMPTY",
      sealReceipt: null
    });
    custodyOutputs = emptyCustody.input.stack.outputs;
  } else {
    custodyOutputs = await b0Provider.collectA1CustodyOutputs({
      expectedStackArn:
        postCreateReceipts.freshPrimaryCredentialCustody.stackArn
    });
  }
  const secretArns = a1.secretArnsFromOutputs({
    outputs: custodyOutputs,
    plan: a1.custodyPlan
  });
  const negativeResults = await b0Provider.runNegativeSimulations({
    plan: buildBootstrapNegativeSimulationPlan(plan)
  });
  const negativeReceipt = validateBootstrapNegativeSimulation(
    plan,
    negativeResults
  );
  let writerSessionReceipt;
  let approval;
  let sealReceipt;
  if (priorSealStep?.state === "ACCEPTED") {
    approval = priorSealStep.continuationContext?.approval;
    sealReceipt = priorSealStep.receipt?.sealReceipt;
    requireCondition(plainObject(approval) && plainObject(sealReceipt),
      "ONE_TIME_BOOTSTRAP_SECRET_SEAL_RECEIPT_REJECTED");
    writerSessionReceipt = latestAcceptedSessionReceipt(
      journal,
      writerAssumeStepIds(journal),
      "ONE_TIME_BOOTSTRAP_WRITER_SESSION_RECONCILIATION_REQUIRED"
    );
  } else {
    const expectedValueSha256 = { ...authorizationReceipt.writerValueSha256 };
    approval = a1.buildApproval({
      approvedAt: authorizationReceipt.approvedAt,
      expectedValueSha256,
      expiresAt: authorizationReceipt.expiresAt,
      operatorAuthorizationSha256:
        plan.authorization.userAuthorizationReceiptSha256,
      plan: a1.custodyPlan,
      secretArns
    });
    const writerLease = await assumeWriterWithJournal({
      b0Provider,
      journal,
      plan
    });
    try {
      writerSessionReceipt = writerLease.receipt;
      await valueLease.withValues(async (values) => {
        const observedValueSha256 = Object.fromEntries(
          a1.writerTargets.map((name) =>
            [name, sha256(Buffer.from(values[name], "utf8"))])
        );
        requireCondition(canonicalJson(observedValueSha256) ===
          canonicalJson(expectedValueSha256),
        "ONE_TIME_BOOTSTRAP_WRITER_VALUE_AUTHORIZATION_REJECTED");
      sealReceipt = await runCrashConvergentSecretSeal({
        approval,
        contract: {
          approvalSha256: digest(approval),
          custodyPlanSha256: a1.custodyPlan.planSha256,
          exactWriteCount: 5,
          runtimeTargetWriteCount: 0
        },
        journal,
        seal: () => writerLease.withPrivateCredentials(
          async (writerCredentials) => a1.seal({
            approval,
            plan: a1.custodyPlan,
            provider: await b0Provider.createWriterProvider({
              credentials: writerCredentials,
              secretArns: Object.values(secretArns)
            }),
            secretArns,
            values
          })
        ),
        validateSealReceipt(receipt) {
          requireCondition(receipt?.schemaVersion ===
            "prooftoact.fresh-primary-credential-seal-receipt.v1" &&
            receipt?.status ===
              "EXACT_FIVE_VERSIONS_SEALED_TWO_TARGETS_EMPTY" &&
            /^[0-9a-f]{64}$/u.test(receipt?.receiptSha256 ?? ""),
          "ONE_TIME_BOOTSTRAP_SECRET_SEAL_RECEIPT_REJECTED");
          return receipt;
        }
        });
      });
    } finally {
      writerLease.destroy();
    }
  }
  const sealedCustody = await collectAndVerifyA1CustodyPhase({
    a1,
    approval,
    b0Provider,
    expectedStackArn:
      postCreateReceipts.freshPrimaryCredentialCustody.stackArn,
    phase: "SEALED",
    sealReceipt
  });
  const sealedCustodyReceipt = sealedCustody.receipt;
  const a1SecretCensus = deriveA1SecretCensus(
    a1,
    sealedCustodyReceipt
  );
  const a2TargetSecretVersionCount =
    await b0Provider.countA2TargetSecretVersions({
      expectedStackArn:
        postCreateReceipts.privateRecoveryQueryBootstrap.stackArn
    });
  const inFlightChangeSets = await b0Provider.listInFlightChangeSets();
  return Object.freeze({
    a2TargetSecretVersionCount,
    a1SecretCensus,
    inFlightChangeSets,
    negativeReceipt,
    postCreateReceipts,
    preExecuteReceipts,
    sealedCustodyReceipt,
    writerSessionReceipt
  });
}

export function deriveA1SecretCensus(a1, sealedCustodyReceipt) {
  const code = "ONE_TIME_BOOTSTRAP_A1_CENSUS_REJECTED";
  requireCondition(plainObject(a1?.custodyPlan?.secretNames) &&
    Array.isArray(a1.writerTargets) && Array.isArray(a1.runtimeTargets) &&
    plainObject(sealedCustodyReceipt?.secrets) &&
    /^[0-9a-f]{64}$/u.test(
      sealedCustodyReceipt.receiptSha256 ?? "") &&
    sealedCustodyReceipt.phase === "SEALED" &&
    sealedCustodyReceipt.status ===
      "EXACT_FIVE_SEALED_TWO_EMPTY_CREATOR_LIFECYCLE_ACCEPTED", code);
  const initializedWriterTargets = a1.writerTargets.map((name) => {
    requireCondition(sealedCustodyReceipt.secrets[name]?.versionCount === 1 &&
      typeof a1.custodyPlan.secretNames[name] === "string", code);
    return {
      secretName: a1.custodyPlan.secretNames[name],
      versionCount: sealedCustodyReceipt.secrets[name].versionCount
    };
  });
  const runtimeGeneratedTargets = a1.runtimeTargets.map((name) => {
    requireCondition(sealedCustodyReceipt.secrets[name]?.versionCount === 0 &&
      typeof a1.custodyPlan.secretNames[name] === "string", code);
    return {
      secretName: a1.custodyPlan.secretNames[name],
      versionCount: sealedCustodyReceipt.secrets[name].versionCount
    };
  });
  return Object.freeze({
    initializedWriterTargets,
    rawSecretValuesObserved: false,
    runtimeGeneratedTargets,
    sourceReadbackReceiptSha256: sealedCustodyReceipt.receiptSha256
  });
}

export function buildCompletionEvidenceFromB0Result(plan, result,
  observedAt) {
  return validateBootstrapCompletionEvidence(plan, {
    schemaVersion: "prooftoact.one-time-bootstrap-completion-evidence.v1",
    a1SecretCensus: result.a1SecretCensus,
    a2TargetSecretVersionCount: result.a2TargetSecretVersionCount,
    ambiguousState: false,
    b0CredentialsDestroyed: true,
    inFlightChangeSets: result.inFlightChangeSets,
    observedAt,
    postCreateReceipts: result.postCreateReceipts,
    preExecuteReceipts: result.preExecuteReceipts,
    rawCredentialFieldsPresent: false,
    stackStatuses: Object.fromEntries(
      oneTimeBootstrapConstants.TARGET_KEYS.map((key) =>
        [key, "CREATE_COMPLETE"])
    ),
    writerState: {
      completedExactlyFiveWrites: true,
      failedWrites: 0,
      rawCredentialFieldsPresent: false,
      roleArn: plan.writerContract.roleArn,
      sessionExpiration: result.writerSessionReceipt.credentialsExpiration,
      sessionExpired: Date.parse(result.writerSessionReceipt
        .credentialsExpiration) <= Date.parse(observedAt)
    }
  });
}

function rootAssumeStepIds(journal) {
  return Object.keys(journal.value.steps).filter((id) =>
    id === "root-assume-b0-session" ||
    /^root-assume-b0-session-continuation-[0-9]{3}$/u.test(id)
  ).sort();
}

function writerAssumeStepIds(journal) {
  return Object.keys(journal.value.steps).filter((id) =>
    id === "b0-assume-a1-writer-session" ||
    /^b0-assume-a1-writer-session-continuation-[0-9]{3}$/u.test(id)
  ).sort();
}

function nextSessionStepId(journal, base, ids) {
  if (ids.length === 0) return base;
  return `${base}-continuation-${String(ids.length).padStart(3, "0")}`;
}

function latestAcceptedSessionReceipt(journal, ids, code) {
  requireCondition(ids.length > 0, code);
  const receipt = journal.step(ids.at(-1))?.receipt?.sessionReceipt;
  requireCondition(plainObject(receipt) &&
    typeof receipt.credentialsExpiration === "string" &&
    typeof receipt.roleArn === "string", code);
  canonicalInstant(receipt.credentialsExpiration, code);
  return receipt;
}

function expectedRootDirectEvents(plan, includeCleanup, assumeCount = 1) {
  requireCondition(Number.isSafeInteger(assumeCount) && assumeCount >= 1,
    "ONE_TIME_BOOTSTRAP_ROOT_ASSUME_COUNT_REJECTED");
  const events = [
    {
      eventName: "CreateRole",
      roleName: plan.bootstrapRole.name,
      rolePath: plan.bootstrapRole.path
    },
    {
      eventName: "TagRole",
      roleName: plan.bootstrapRole.name,
      tagsSha256: digest(plan.bootstrapRole.roleTags)
    },
    {
      eventName: "PutRolePolicy",
      policyName: plan.bootstrapRole.inlinePolicyName,
      policySha256: plan.bootstrapRole.inlinePolicySha256,
      roleName: plan.bootstrapRole.name
    },
    ...Array.from({ length: assumeCount }, () => ({
      durationSeconds: oneTimeBootstrapConstants.SESSION_DURATION_SECONDS,
      eventName: "AssumeRole",
      mfaAuthenticated: true,
      serialNumber: plan.account.mfaSerialArn,
      roleArn: plan.bootstrapRole.arn,
      roleSessionName: plan.sessionContract.roleSessionName,
      sourceIdentity: plan.sessionContract.sourceIdentity
    }))
  ];
  if (includeCleanup) {
    events.push({
      eventName: "DeleteRolePolicy",
      policyName: plan.bootstrapRole.inlinePolicyName,
      roleName: plan.bootstrapRole.name
    }, {
      eventName: "DeleteRole",
      roleName: plan.bootstrapRole.name
    });
  }
  return events;
}

async function waitUntilInstant({ clock, instant, notAfter }) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_EXPIRY_WAIT_REJECTED";
  const target = canonicalInstant(instant, code);
  const deadline = canonicalInstant(notAfter, code);
  requireCondition(target < deadline, code);
  for (;;) {
    const now = clock();
    requireCondition(now instanceof Date && Number.isFinite(now.getTime()) &&
      now.getTime() < deadline, code);
    if (now.getTime() >= target) return now.toISOString();
    await new Promise((resolve) => setTimeout(resolve,
      Math.min(30_000, target - now.getTime())));
  }
}

function reconciledLostSessionReceipt({ eventTime, kind, plan }) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_EVENT_REJECTED";
  const observed = canonicalInstant(eventTime, code);
  const writer = kind === "writer";
  requireCondition(writer || kind === "root", code);
  return Object.freeze({
    schemaVersion:
      "prooftoact.one-time-bootstrap-cloudtrail-session-reconciliation.v1",
    status: "AMBIGUOUS_ASSUME_DISPATCH_OBSERVED_AND_CREDENTIALS_LOST",
    accountId: plan.account.accountId,
    credentialsExpiration: new Date(observed +
      oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000)
      .toISOString(),
    eventTime: new Date(observed).toISOString(),
    operationId: plan.operation.operationId,
    rawCredentialFieldsPresent: false,
    recoveredAmbiguousDispatch: true,
    roleArn: writer ? plan.writerContract.roleArn : plan.bootstrapRole.arn,
    roleSessionName: writer ? plan.writerContract.roleSessionName :
      plan.sessionContract.roleSessionName
  });
}

function expiredUnknownSessionReceipt({ dispatchStartedAt, kind, plan }) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_EVENT_REJECTED";
  const dispatched = canonicalInstant(dispatchStartedAt, code);
  const writer = kind === "writer";
  requireCondition(writer || kind === "root", code);
  return Object.freeze({
    schemaVersion:
      "prooftoact.one-time-bootstrap-no-event-session-reconciliation.v1",
    status: "AMBIGUOUS_ASSUME_MAX_LIFETIME_ELAPSED_WITHOUT_EVENT",
    accountId: plan.account.accountId,
    assumeEventObserved: false,
    credentialsExpiration: new Date(dispatched +
      oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000 +
      CLOUDTRAIL_EVENT_LAG_MS).toISOString(),
    dispatchStartedAt: new Date(dispatched).toISOString(),
    operationId: plan.operation.operationId,
    rawCredentialFieldsPresent: false,
    recoveredAmbiguousDispatch: true,
    roleArn: writer ? plan.writerContract.roleArn : plan.bootstrapRole.arn,
    roleSessionName: writer ? plan.writerContract.roleSessionName :
      plan.sessionContract.roleSessionName
  });
}

async function reconcilePriorLostSessions({
  gate,
  journal,
  plan,
  rootProvider
}) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_CONTINUATION_REJECTED";
  const groups = [
    { ids: rootAssumeStepIds(journal), kind: "root" },
    { ids: writerAssumeStepIds(journal), kind: "writer" }
  ];
  for (const group of groups) {
    for (const id of group.ids) {
      const step = journal.step(id);
      requireCondition(step !== null, code);
      if (step.state === "DISPATCH_STARTED") {
        let eventTime;
        const noEventSafeAt = Date.parse(step.dispatchStartedAt) +
          oneTimeBootstrapConstants.SESSION_DURATION_SECONDS * 1000 +
          CLOUDTRAIL_EVENT_LAG_MS;
        for (;;) {
          const evidence = await gate.invoke(
            "setup",
            "cloudtrail:LookupEvents",
            () => rootProvider.lookupRootMutationEvents()
          );
          requireCondition(
            evidence.unexpectedRootMutationEvents.length === 0,
            code
          );
          const times = group.kind === "root" ?
            evidence.rootAssumeEventTimes :
            evidence.writerAssumeEventTimes;
          requireCondition(Array.isArray(times), code);
          const matchingTimes = times.filter((value) =>
            Date.parse(value) >= Date.parse(step.dispatchStartedAt) - 30_000
          );
          if (matchingTimes.length > 0) {
            [eventTime] = matchingTimes;
            break;
          }
          const now = rootProvider.now();
          if (now.getTime() >= noEventSafeAt) break;
          requireCondition(Math.min(noEventSafeAt,
            now.getTime() + 5_000) < Date.parse(plan.notAfter), code);
          await new Promise((resolve) => setTimeout(resolve,
            Math.min(5_000, noEventSafeAt - now.getTime())));
        }
        journal.recordAccepted(
          id,
          "POST_DISPATCH_RECONCILIATION",
          {
            sessionReceipt: eventTime === undefined ?
              expiredUnknownSessionReceipt({
                dispatchStartedAt: step.dispatchStartedAt,
                kind: group.kind,
                plan
              }) :
              reconciledLostSessionReceipt({
                eventTime,
                kind: group.kind,
                plan
              })
          }
        );
      } else {
        requireCondition(["ACCEPTED", "INTENT_RECORDED"].includes(
          step.state
        ), code);
      }
    }
  }
  if (journal.mode !== "RECONCILE_ONLY") return;
  const acceptedExpirations = [...rootAssumeStepIds(journal),
    ...writerAssumeStepIds(journal)].flatMap((id) => {
    const step = journal.step(id);
    return step.state === "ACCEPTED" ?
      [step.receipt.sessionReceipt.credentialsExpiration] : [];
  });
  if (acceptedExpirations.length === 0) return;
  const latest = new Date(Math.max(...acceptedExpirations.map(
    (value) => canonicalInstant(value, code)
  ))).toISOString();
  await waitUntilInstant({
    clock: rootProvider.clock,
    instant: latest,
    notAfter: plan.notAfter
  });
}

async function reconcileExactRootEvents({
  gate,
  includeCleanup,
  phase,
  plan,
  rootProvider
}) {
  const code = "ONE_TIME_BOOTSTRAP_CLOUDTRAIL_RECONCILIATION_REJECTED";
  const setup = expectedRootDirectEvents(plan, false, 1).slice(0, 3);
  const expectedAssume = expectedRootDirectEvents(plan, false, 1)[3];
  const cleanup = expectedRootDirectEvents(plan, true, 1).slice(-2);
  for (;;) {
    const evidence = await gate.invoke(
      phase,
      "cloudtrail:LookupEvents",
      () => rootProvider.lookupRootMutationEvents()
    );
    requireCondition(Array.isArray(evidence.rootDirectEvents) &&
      Array.isArray(evidence.unexpectedRootMutationEvents), code);
    if (evidence.unexpectedRootMutationEvents.length > 0) reject(code);
    const observed = evidence.rootDirectEvents;
    const cleanupWidth = includeCleanup ? 2 : 0;
    const assumptions = observed.slice(3,
      cleanupWidth === 0 ? undefined : -cleanupWidth);
    const exact = observed.length >= 4 + cleanupWidth &&
      canonicalJson(observed.slice(0, 3)) === canonicalJson(setup) &&
      assumptions.length >= 1 && assumptions.every((event) =>
        canonicalJson(event) === canonicalJson(expectedAssume)) &&
      (!includeCleanup || canonicalJson(observed.slice(-2)) ===
        canonicalJson(cleanup));
    if (exact) {
      return evidence;
    }
    const now = rootProvider.now();
    requireCondition(now.getTime() + 5_000 < Date.parse(plan.notAfter), code);
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
}

async function cleanupAcceptedBootstrap({
  b0SessionReceipt,
  completionReceipt,
  gate,
  journal,
  plan,
  rootProvider,
  writerSessionReceipt
}) {
  requireCondition(completionReceipt?.status ===
    "EXACT_STATE_ACCEPTED_FOR_B0_DELETION",
  "ONE_TIME_BOOTSTRAP_CLEANUP_COMPLETION_REJECTED");
  gate.advance("reconcile");
  await reconcileExactRootEvents({
    gate,
    includeCleanup: false,
    phase: "reconcile",
    plan,
    rootProvider
  });
  gate.advance("cleanup");
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      completionReceiptSha256: completionReceipt.receiptSha256,
      policyName: plan.bootstrapRole.inlinePolicyName,
      roleName: plan.bootstrapRole.name
    },
    dispatch: () => gate.invoke("cleanup", "iam:DeleteRolePolicy", () =>
      rootProvider.deletePolicy()),
    id: "root-delete-b0-inline-policy",
    inspect: () => gate.invoke("cleanup", "iam:GetRolePolicy", () =>
      rootProvider.inspectPolicyAbsent()),
    journal,
    mutationClass: "iam:DeleteRolePolicy"
  });
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      completionReceiptSha256: completionReceipt.receiptSha256,
      roleName: plan.bootstrapRole.name
    },
    dispatch: () => gate.invoke("cleanup", "iam:DeleteRole", () =>
      rootProvider.deleteRole()),
    id: "root-delete-b0-role",
    inspect: () => gate.invoke("cleanup", "iam:GetRole", () =>
      rootProvider.inspectRoleAbsent()),
    journal,
    mutationClass: "iam:DeleteRole"
  });
  const cloudTrail = await reconcileExactRootEvents({
    gate,
    includeCleanup: true,
    phase: "cleanup",
    plan,
    rootProvider
  });
  const awsLogout = await gate.invoke("cleanup", "aws:Logout", () =>
    rootProvider.logout());
  const observedAt = rootProvider.clock().toISOString();
  return validateOneTimeBootstrapCleanupReceipt(plan, {
    schemaVersion: "prooftoact.one-time-bootstrap-cleanup.v1",
    accountId: plan.account.accountId,
    awsLogout,
    b0CredentialEnvironmentKeysPresent: [
      "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
      "AWS_SECURITY_TOKEN"
    ].filter((name) => process.env[name] !== undefined),
    b0CredentialsDestroyed: true,
    b0SessionExpiration: b0SessionReceipt.credentialsExpiration,
    bootstrapRoleAbsent: true,
    inlinePolicyAbsent: true,
    observedAt,
    operationId: plan.operation.operationId,
    rawCredentialFieldsPresent: false,
    rootDirectEvents: cloudTrail.rootDirectEvents,
    unexpectedRootMutationEvents:
      cloudTrail.unexpectedRootMutationEvents,
    writerSessionExpiration: writerSessionReceipt.credentialsExpiration,
    writerSessionExpired: Date.parse(writerSessionReceipt
      .credentialsExpiration) <= Date.parse(observedAt)
  });
}

function persistLocalReceipt({ contract, id, journal, receipt }) {
  const code = "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED";
  requireCondition(plainObject(contract) && plainObject(receipt), code);
  const prior = journal.recordIntent(id, "local:ValidateReceipt", contract);
  if (prior.state === "ACCEPTED") {
    requireCondition(plainObject(prior.receipt?.value), code);
    return prior.receipt.value;
  }
  requireCondition(prior.state === "INTENT_RECORDED" &&
    prior.dispatchStartedAt === null, code);
  return journal.recordAccepted(
    id,
    "PRESTATE_RECONCILIATION",
    { value: receipt }
  ).receipt.value;
}

function acceptedLocalReceipt(journal, id) {
  const step = journal.step(id);
  if (step === null) return null;
  requireCondition(step.state === "ACCEPTED" &&
    plainObject(step.receipt?.value),
  "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
  return step.receipt.value;
}

function writeTerminalReceipt(plan, completionReceipt, cleanupReceipt) {
  process.stdout.write(canonicalJson({
    cleanupReceipt,
    completionReceipt,
    operationId: plan.operation.operationId,
    rawCredentialFieldsPresent: false,
    schemaVersion: "prooftoact.one-time-bootstrap-run.v1",
    status: "CEREMONY_COMPLETED_AND_B0_DELETED"
  }) + "\n");
}

function parseMainArguments(argv) {
  const code = "ONE_TIME_BOOTSTRAP_RUNNER_ARGUMENTS_REJECTED";
  const names = ["--aws-cli-path", "--journal-directory", "--mode",
    "--plan-file", "--source-root"];
  requireCondition(Array.isArray(argv) && argv.length === names.length * 2,
    code);
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition(names.includes(name) && !Object.hasOwn(parsed, name) &&
      typeof value === "string" && value.length > 0, code);
    parsed[name] = value;
  }
  requireCondition(Object.keys(parsed).sort().join("\n") ===
    [...names].sort().join("\n") &&
    ["NEW", "RECONCILE_ONLY"].includes(parsed["--mode"]) &&
    ["--aws-cli-path", "--journal-directory", "--plan-file",
      "--source-root"].every(
      (name) => path.isAbsolute(parsed[name])
    ), code);
  return parsed;
}

async function main() {
  const parsed = parseMainArguments(process.argv.slice(2));
  let rawPlan;
  try {
    rawPlan = JSON.parse(readPrivateRegularFile(
      parsed["--plan-file"],
      2 * 1024 * 1024,
      "ONE_TIME_BOOTSTRAP_PLAN_FILE_REJECTED"
    ).toString("utf8"));
  } catch (cause) {
    reject("ONE_TIME_BOOTSTRAP_PLAN_FILE_REJECTED", cause);
  }
  const plan = verifyOneTimeBootstrapPlan(rawPlan);
  validateOneTimeBootstrapTimingBudget({
    notAfter: plan.notAfter,
    preparedAt: plan.preparedAt
  });
  validateOneTimeBootstrapCheckout({
    expectedCommit: plan.source.commit,
    expectedTree: plan.source.tree,
    operationId: plan.operation.operationId,
    sourceRoot: parsed["--source-root"],
    targetTemplateSha256: Object.fromEntries(
      oneTimeBootstrapConstants.TARGET_KEYS.map((key) =>
        [key, plan.targets[key].templateSha256])
    )
  });
  const executingBytes = readReviewedRegularFile(
    path.join(parsed["--source-root"], plan.source.ceremonyRunnerPath),
    2 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_RUNNER_IDENTITY_REJECTED"
  );
  requireCondition(path.resolve(CURRENT_FILE) === path.join(
    parsed["--source-root"], plan.source.ceremonyRunnerPath
  ) && sha256(executingBytes) === plan.source.ceremonyRunnerSha256,
  "ONE_TIME_BOOTSTRAP_RUNNER_IDENTITY_REJECTED");
  const authorization = readAndValidateAuthorizationReceipt(plan);
  const valueLease = createFixedFdWriterValueLease();
  let journal;
  let b0Lease;
  try {
    valueLease.prepare(authorization.receipt.writerValueSha256);
    const a1 = await loadA1Integration(
      plan,
      parsed["--source-root"]
    );
    journal = new OneTimeBootstrapJournal({
      clock: () => new Date(),
      directoryPath: parsed["--journal-directory"],
      mode: parsed["--mode"],
      plan
    });
    let result = acceptedLocalReceipt(journal, "local-b0-result");
    let completionReceipt = acceptedLocalReceipt(
      journal,
      "local-completion-receipt"
    );
    const priorCleanupReceipt = acceptedLocalReceipt(
      journal,
      "local-cleanup-receipt"
    );
    if (priorCleanupReceipt !== null) {
      requireCondition(completionReceipt?.schemaVersion ===
        "prooftoact.one-time-bootstrap-completion.v1" &&
        priorCleanupReceipt.schemaVersion ===
          "prooftoact.one-time-bootstrap-cleanup-accepted.v1",
      "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
      writeTerminalReceipt(plan, completionReceipt, priorCleanupReceipt);
      return;
    }
    const gate = new RootActionGate();
    const rootProvider = new AwsOneTimeBootstrapRootProvider({
      awsCliPath: parsed["--aws-cli-path"],
      plan
    });
    const cleanupStarted = journal.step("root-delete-b0-inline-policy") !==
      null || journal.step("root-delete-b0-role") !== null;
    let mfaDiscoveryReceipt;
    if (cleanupStarted) {
      await gate.invoke("discovery", "sts:GetCallerIdentity", () =>
        rootProvider.callerIdentity());
      await gate.invoke("discovery", "iam:ListMFADevices", () =>
        rootProvider.discoverMfa());
      gate.advance("setup");
    } else {
      mfaDiscoveryReceipt = await convergeRootSetup({
        gate,
        journal,
        plan,
        rootProvider
      });
    }
    let b0SessionReceipt = null;
    if (result !== null) {
      b0SessionReceipt = latestAcceptedSessionReceipt(
        journal,
        rootAssumeStepIds(journal),
        "ONE_TIME_BOOTSTRAP_B0_SESSION_RECONCILIATION_REQUIRED"
      );
    }
    if (result === null) {
      requireCondition(!cleanupStarted && completionReceipt === null,
        "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
      await reconcilePriorLostSessions({
        gate,
        journal,
        plan,
        rootProvider
      });
      b0Lease = await assumeB0WithJournal({
        gate,
        journal,
        mfaDiscoveryReceipt,
        mfaFd: MFA_TOKEN_FD,
        plan,
        rootProvider
      });
      b0SessionReceipt = b0Lease.receipt;
      result = await b0Lease.withPrivateCredentials(
        async (credentials) => {
          const b0Provider = new AwsOneTimeBootstrapB0Provider({
            credentials,
            plan
          });
          try {
            return await runOneTimeBootstrapB0Session({
              a1,
              authorizationReceipt: authorization.receipt,
              b0Provider,
              journal,
              plan,
              sourceRoot: parsed["--source-root"],
              valueLease
            });
          } finally {
            b0Provider.destroy();
          }
        }
      );
      b0Lease.destroy();
      b0Lease = undefined;
      result = persistLocalReceipt({
        contract: {
          planBodySha256: plan.planBodySha256,
          sealedReadbackReceiptSha256:
            result.sealedCustodyReceipt.receiptSha256
        },
        id: "local-b0-result",
        journal,
        receipt: result
      });
    }
    requireCondition(b0SessionReceipt !== null &&
      plainObject(result.writerSessionReceipt),
    "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
    if (completionReceipt === null) {
      const latestExpiration = new Date(Math.max(
        Date.parse(b0SessionReceipt.credentialsExpiration),
        Date.parse(result.writerSessionReceipt.credentialsExpiration)
      )).toISOString();
      const observedAt = await waitUntilInstant({
        clock: rootProvider.clock,
        instant: latestExpiration,
        notAfter: plan.notAfter
      });
      completionReceipt = buildCompletionEvidenceFromB0Result(
        plan,
        result,
        observedAt
      );
      completionReceipt = persistLocalReceipt({
        contract: {
          b0ResultSha256: digest(result),
          planBodySha256: plan.planBodySha256
        },
        id: "local-completion-receipt",
        journal,
        receipt: completionReceipt
      });
    }
    let cleanupReceipt = await cleanupAcceptedBootstrap({
      b0SessionReceipt,
      completionReceipt,
      gate,
      journal,
      plan,
      rootProvider,
      writerSessionReceipt: result.writerSessionReceipt
    });
    cleanupReceipt = persistLocalReceipt({
      contract: {
        completionReceiptSha256: completionReceipt.receiptSha256,
        planBodySha256: plan.planBodySha256
      },
      id: "local-cleanup-receipt",
      journal,
      receipt: cleanupReceipt
    });
    writeTerminalReceipt(plan, completionReceipt, cleanupReceipt);
  } finally {
    b0Lease?.destroy();
    valueLease.destroy();
    // A real process crash cannot run this finally and intentionally leaves
    // the exclusive lock in place for audited stale-lock recovery.
    journal?.releaseLock();
  }
}

const startedDirectly = process.argv[1] &&
  path.resolve(process.argv[1]) === CURRENT_FILE;

if (startedDirectly) {
  main().catch((cause) => {
    const message = String(cause?.message ?? "");
    const code = /^ONE_TIME_BOOTSTRAP_[A-Z0-9_]{1,160}$/u.test(message) ?
      message : "ONE_TIME_BOOTSTRAP_RUNNER_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const oneTimeBootstrapRunnerConstants = Object.freeze({
  A1_INTEGRATION_PATHS,
  AUTHORIZATION_RECEIPT_FD,
  CLOUDTRAIL_EVENT_LAG_MS,
  JOURNAL_FILE_PREFIX,
  JOURNAL_SCHEMA,
  MFA_TOKEN_FD,
  REGION,
  ROOT_ACTIONS_BY_PHASE,
  ROOT_PHASE_ORDER,
  SESSION_CLEANUP_RESERVE_MS,
  WRITER_VALUE_FDS,
  WRITER_VALUE_MAXIMUM_BYTES
});

export const __test = Object.freeze({
  assertNoCredentialMaterial,
  atomicOwnerOnlyWrite,
  canonicalBytes,
  canonicalJson,
  classifyMatch,
  collectAndVerifyA1CustodyPhase,
  collectorBinding,
  digest,
  journalBodySha256,
  parseMainArguments,
  readPrivateFdToBuffer,
  reconcilePriorLostSessions,
  sha256,
  verifyJournal
});
