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
  cleanupOnlyAuthorizationContract,
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
import {
  validateProofToActB0A1HumanAuthorizationReceipt
} from "./lib/prooftoact-b0-a1-human-authorization.js";
import {
  verifyProofToActB0A1HumanAuthorizationWithImsg
} from "./materialize-prooftoact-b0-a1-human-authorization.js";

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
const IDENTITY_RECORD_FD = 10;
const IDENTITY_HMAC_KEY_FD = 11;
const HUMAN_AUTHORITY_ID = "BRIAN_SMITH";
const CLOUDTRAIL_EVENT_LAG_MS = 5 * 60 * 1000;
const SESSION_CLEANUP_RESERVE_MS = 2 * CLOUDTRAIL_EVENT_LAG_MS;
const CLEANUP_START_RESERVE_MS = CLOUDTRAIL_EVENT_LAG_MS + 60 * 1000;
const PROVIDER_CONVERGENCE_TAIL_MS = 45 * 60 * 1000;
const ROOT_ACTIONS_BY_PHASE = Object.freeze({
  discovery: Object.freeze([
    "sts:GetCallerIdentity",
    "iam:ListMFADevices"
  ]),
  setup: Object.freeze([
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListChangeSets",
    "cloudtrail:LookupEvents",
    "iam:CreateRole",
    "iam:GetRole",
    "iam:TagRole",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:ListRoleTags",
    "iam:PutRolePolicy",
    "iam:GetRolePolicy",
    "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecretVersionIds",
    "sts:AssumeRole"
  ]),
  reconcile: Object.freeze([
    "cloudformation:DescribeStacks",
    "cloudformation:GetTemplate",
    "cloudformation:ListChangeSets",
    "cloudtrail:LookupEvents",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:ListRoleTags",
    "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecretVersionIds"
  ]),
  cleanup: Object.freeze([
    "cloudtrail:LookupEvents",
    "iam:DeleteRolePolicy",
    "iam:DeleteRole",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "sts:GetCallerIdentity",
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
    latestNewDispatchAt: new Date(deadline).toISOString(),
    providerConvergenceReadOnlyUntil: new Date(
      deadline + PROVIDER_CONVERGENCE_TAIL_MS
    ).toISOString(),
    providerConvergenceTailMs: PROVIDER_CONVERGENCE_TAIL_MS,
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
  // A durable INTENT_RECORDED step with a null dispatchStartedAt is positive
  // evidence that no provider call began. RECONCILE_ONLY may continue this
  // exact operation; only DISPATCH_STARTED plus absent state is ambiguous.
  requireCondition(prior.state === "INTENT_RECORDED" &&
    prior.dispatchStartedAt === null, code);
  if (journal.cleanupOnly === true) {
    requireCondition([
      "iam:DeleteRole", "iam:DeleteRolePolicy"
    ].includes(mutationClass),
    "ONE_TIME_BOOTSTRAP_EXPIRED_RECONCILIATION_MUTATION_REJECTED");
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
    return validateOneTimeBootstrapAuthorizationBytes(plan, bytes, clock);
  } finally {
    bytes.fill(0);
  }
}

export function validateOneTimeBootstrapAuthorizationBytes(plan, bytes,
  clock = () => new Date(), { allowExpiredReconcile = false } = {}) {
  const code = "ONE_TIME_BOOTSTRAP_AUTHORIZATION_RECEIPT_REJECTED";
  requireCondition(Buffer.isBuffer(bytes) && bytes.length > 0 &&
    bytes.length <= 256 * 1024 && typeof clock === "function", code);
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
  validateOneTimeBootstrapAuthorizationReceipt(plan, receipt, now, {
    allowExpiredReconcile
  });
  return Object.freeze({
    bytes: bytes.length,
    sha256: sha256(bytes),
    rawReceiptRetained: false,
    receipt,
    writerValueSha256: Object.freeze({ ...receipt.writerValueSha256 })
  });
}

export function validateOneTimeBootstrapAuthorizationReceipt(plan, receipt,
  observedAt, { allowExpiredReconcile = false } = {}) {
  const code = "ONE_TIME_BOOTSTRAP_AUTHORIZATION_RECEIPT_REJECTED";
  const rebuilt = buildOneTimeBootstrapAuthorizationReceipt({
    accountId: receipt?.accountId,
    approvedBy: receipt?.approvedBy,
    approvedAt: receipt?.approvedAt,
    artifactBucketName: receipt?.existingInputs?.artifactBucketName,
    cleanupOnlyAuthorizationApproved:
      receipt?.cleanupOnlyAuthorizationApproved,
    costCeiling: receipt?.costCeiling,
    expiresAt: receipt?.expiresAt,
    githubOidcProviderArn: receipt?.existingInputs?.githubOidcProviderArn,
    humanAuthorizationReceiptSha256:
      receipt?.humanAuthorizationReceiptSha256,
    humanAuthorizationBinding: receipt?.humanAuthorizationBinding,
    humanAuthorizedTextSha256: receipt?.humanAuthorizedTextSha256,
    operationId: receipt?.operationId,
    privateRecoveryWorkflowCommits:
      receipt?.privateRecoveryWorkflowCommits,
    runtimeExecutionBindingSha256:
      receipt?.runtimeExecutionBindingSha256,
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
    canonicalJson(receipt.cleanupOnlyAuthorization) ===
      canonicalJson(plan.authorization.cleanupOnlyAuthorization) &&
    sha256(canonicalBytes(receipt)) ===
      plan.authorization.userAuthorizationReceiptSha256 &&
    Date.parse(receipt.approvedAt) <= observedAt.getTime() &&
    (observedAt.getTime() < Date.parse(receipt.expiresAt) ||
      allowExpiredReconcile &&
      observedAt.getTime() >= Date.parse(receipt.expiresAt) &&
      observedAt.getTime() < Date.parse(
        receipt.cleanupOnlyAuthorization.expiresAt
      )) &&
    canonicalJson(receipt.costCeiling) === canonicalJson(plan.costCeiling) &&
    receipt.existingInputs.artifactBucketName ===
      plan.existingInputs.artifactBucketName &&
    receipt.existingInputs.githubOidcProviderArn ===
      plan.existingInputs.githubOidcProviderArn &&
    canonicalJson(receipt.privateRecoveryWorkflowCommits) ===
      canonicalJson(Object.fromEntries(
        oneTimeBootstrapConstants.PRIVATE_RECOVERY_WORKFLOW_KEYS.map((key) =>
          [key, plan.source.privateRecoveryWorkflowPins[key].commit])
      )) &&
    receipt.runtimeExecutionBindingSha256 ===
      digest(plan.source.runtimeExecutionBinding) &&
    oneTimeBootstrapConstants.PRIVATE_RECOVERY_WORKFLOW_KEYS.every((key) => {
      const definition =
        oneTimeBootstrapConstants.PRIVATE_RECOVERY_WORKFLOW_DEFINITIONS[key];
      return receipt.privateRecoveryWorkflowCommits[key] ===
        plan.source.privateRecoveryWorkflowPins[key].commit &&
        receipt.privateRecoveryWorkflowCommits[key] ===
          plan.targets.privateRecoveryQueryBootstrap.parameters[
            definition.parameterName
          ];
    }) &&
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
  let sharedAuthorization;
  try {
    sharedAuthorization =
      validateProofToActB0A1HumanAuthorizationReceipt(
        input?.humanAuthorizationBinding
      );
  } catch (cause) {
    reject(code, cause);
  }
  const sharedIntent = sharedAuthorization.dynamicIntent;
  requireCondition(exactKeys(input, [
    "accountId",
    "approvedBy",
    "approvedAt",
    "artifactBucketName",
    "cleanupOnlyAuthorizationApproved",
    "costCeiling",
    "expiresAt",
    "githubOidcProviderArn",
    "humanAuthorizationBinding",
    "humanAuthorizationReceiptSha256",
    "humanAuthorizedTextSha256",
    "operationId",
    "privateRecoveryWorkflowCommits",
    "runtimeExecutionBindingSha256",
    "sourceCommit",
    "targetTemplateSha256",
    "treeDigest",
    "writerValueSha256"
  ]) && input.cleanupOnlyAuthorizationApproved === true &&
    input.approvedBy === HUMAN_AUTHORITY_ID &&
    canonicalJson(sharedAuthorization) ===
      canonicalJson(input.humanAuthorizationBinding) &&
    input.humanAuthorizationReceiptSha256 ===
      sharedAuthorization.receiptBindingSha256 &&
    input.humanAuthorizedTextSha256 ===
      sharedAuthorization.humanAuthorizedTextSha256 &&
    /^[0-9]{12}$/u.test(input.accountId ?? "") &&
    /^[0-9a-f]{40}$/u.test(input.sourceCommit ?? "") &&
    /^[0-9a-f]{40}$/u.test(input.treeDigest ?? "") &&
    exactKeys(input.targetTemplateSha256,
      oneTimeBootstrapConstants.TARGET_KEYS) &&
    Object.values(input.targetTemplateSha256).every((value) =>
      /^[0-9a-f]{64}$/u.test(value ?? "")) &&
    exactKeys(input.writerValueSha256, writerNames) &&
    Object.values(input.writerValueSha256).every((value) =>
      /^[0-9a-f]{64}$/u.test(value ?? "")) &&
    sharedIntent.accountId === input.accountId &&
    sharedIntent.operationId === input.operationId &&
    sharedIntent.sourceCommit === input.sourceCommit &&
    sharedIntent.treeDigest === input.treeDigest &&
    sharedAuthorization.externalHumanAuthorizationEvidence
      .inboundApprovalEvent.receivedAt ===
      input.approvedAt &&
    Date.parse(sharedIntent.authorizationNotBefore) <=
      Date.parse(input.approvedAt) &&
    sharedIntent.b0DispatchDeadline === input.expiresAt &&
    sharedIntent.a1ReservationDeadline === input.expiresAt &&
    canonicalJson(sharedIntent.b0TargetTemplateSha256) ===
      canonicalJson(input.targetTemplateSha256) &&
    canonicalJson(sharedIntent.b0WriterValueSha256) ===
      canonicalJson(input.writerValueSha256) &&
    canonicalJson(sharedIntent.b0PrivateRecoveryWorkflowCommits) ===
      canonicalJson(input.privateRecoveryWorkflowCommits) &&
    sharedIntent.b0RuntimeExecutionBindingSha256 ===
      input.runtimeExecutionBindingSha256 &&
    exactKeys(input.costCeiling, [
      "currency",
      "maximumMonthlyUsdCents",
      "maximumOneTimeUsdCents",
      "reconciliationReceipt",
      "reconciliationReceiptSha256"
    ]) && input.costCeiling.currency === "USD" &&
    Number.isSafeInteger(input.costCeiling.maximumMonthlyUsdCents) &&
    input.costCeiling.maximumMonthlyUsdCents ===
      oneTimeBootstrapConstants.EXACT_MONTHLY_AUTHORIZATION_USD_CENTS &&
    Number.isSafeInteger(input.costCeiling.maximumOneTimeUsdCents) &&
    input.costCeiling.maximumOneTimeUsdCents ===
      oneTimeBootstrapConstants.EXACT_ONE_TIME_AUTHORIZATION_USD_CENTS &&
    sharedIntent.costAuthorization.currency === input.costCeiling.currency &&
    sharedIntent.costAuthorization.awsMonthlyResidualCeilingUsdCents ===
      input.costCeiling.maximumMonthlyUsdCents &&
    sharedIntent.costAuthorization.maximumOneTimeUsdCents ===
      input.costCeiling.maximumOneTimeUsdCents &&
    sharedIntent.costAuthorization.reconciliationReceiptSha256 ===
      input.costCeiling.reconciliationReceiptSha256 &&
    input.costCeiling.reconciliationReceipt?.receiptSha256 ===
      input.costCeiling.reconciliationReceiptSha256 &&
    /^[0-9a-f]{64}$/u.test(
      input.costCeiling.reconciliationReceiptSha256 ?? "") &&
    exactKeys(input.privateRecoveryWorkflowCommits,
      oneTimeBootstrapConstants.PRIVATE_RECOVERY_WORKFLOW_KEYS) &&
    oneTimeBootstrapConstants.PRIVATE_RECOVERY_WORKFLOW_KEYS.every((key) =>
      /^[0-9a-f]{40}$/u.test(
        input.privateRecoveryWorkflowCommits[key] ?? "") &&
      input.privateRecoveryWorkflowCommits[key] !== "0".repeat(40)) &&
    /^[0-9a-f]{64}$/u.test(input.runtimeExecutionBindingSha256 ?? "") &&
    input.githubOidcProviderArn ===
      `arn:aws:iam::${input.accountId}:oidc-provider/` +
        "token.actions.githubusercontent.com" &&
    typeof input.artifactBucketName === "string", code);
  const approved = canonicalInstant(input.approvedAt, code);
  const expires = canonicalInstant(input.expiresAt, code);
  requireCondition(approved < expires && expires - approved <=
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
    approvedBy: HUMAN_AUTHORITY_ID,
    approvedAt: input.approvedAt,
    cleanupOnlyAuthorizationApproved: true,
    cleanupOnlyAuthorization: cleanupOnlyAuthorizationContract({
      accountId: input.accountId,
      beginsAt: input.expiresAt,
      expiresAt: sharedIntent.cleanupRetentionDeadline,
      operationId: input.operationId
    }),
    costCeiling: { ...input.costCeiling },
    exactFiveWriterValuesAuthorized: true,
    humanAuthorizationBinding: sharedAuthorization,
    humanAuthorizationReceiptSha256: input.humanAuthorizationReceiptSha256,
    humanAuthorizedTextSha256: sharedAuthorization.humanAuthorizedTextSha256,
    existingInputs: {
      artifactBucketName: input.artifactBucketName,
      githubOidcProviderArn: input.githubOidcProviderArn
    },
    expiresAt: input.expiresAt,
    fixedPrivateFdContract: {
      authorizationReceiptFd: AUTHORIZATION_RECEIPT_FD,
      identityHmacKeyFd: IDENTITY_HMAC_KEY_FD,
      identityRecordFd: IDENTITY_RECORD_FD,
      mfaTokenFd: MFA_TOKEN_FD,
      writerValueFds: { ...WRITER_VALUE_FDS }
    },
    operationId: input.operationId,
    operationToken,
    privateRecoveryWorkflowCommits: {
      ...input.privateRecoveryWorkflowCommits
    },
    runtimeExecutionBindingSha256: input.runtimeExecutionBindingSha256,
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
  constructor({ allowExpiredCleanup = false, awsCliGuard, awsCliPath,
    clock = () => new Date(), plan }) {
    requireCondition(path.isAbsolute(awsCliPath) && typeof clock === "function" &&
      typeof awsCliGuard === "function" &&
      typeof allowExpiredCleanup === "boolean",
      "ONE_TIME_BOOTSTRAP_AWS_ROOT_PROVIDER_REJECTED");
    this.allowExpiredCleanup = allowExpiredCleanup;
    this.awsCliGuard = awsCliGuard;
    this.awsCliPath = awsCliPath;
    this.clock = clock;
    this.plan = plan;
    this.destroyed = false;
    this.sts = createNamedRootProfileStsClient(plan);
    const configuration = awsClientConfiguration();
    this.iam = new IAMClient(configuration);
    this.cloudFormation = new CloudFormationClient(configuration);
    this.secrets = new SecretsManagerClient(configuration);
  }

  now() {
    const value = this.clock();
    const preparedAt = Date.parse(this.plan.preparedAt);
    const upperBound = this.operationDeadline().getTime();
    requireCondition(value instanceof Date && Number.isFinite(value.getTime()) &&
      value.getTime() >= preparedAt && value.getTime() < upperBound,
    "ONE_TIME_BOOTSTRAP_AWS_ROOT_CLOCK_REJECTED");
    return value;
  }

  operationDeadline() {
    return new Date(this.allowExpiredCleanup ?
      this.plan.authorization.cleanupOnlyAuthorization.expiresAt :
      this.plan.notAfter);
  }

  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    this.sts.destroy();
    this.iam.destroy();
    this.cloudFormation.destroy();
    this.secrets.destroy();
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
        createdAt: role?.CreateDate instanceof Date ?
          role.CreateDate.toISOString() : null,
        exactTrust: matches,
        roleId: role?.RoleId ?? null,
        roleName: role?.RoleName ?? null
      }
    };
  }

  async createRole() {
    this.now();
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
    this.now();
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
    this.now();
    await this.iam.send(new PutRolePolicyCommand({
      PolicyDocument: canonicalJson(this.plan.bootstrapRole.inlinePolicy),
      PolicyName: this.plan.bootstrapRole.inlinePolicyName,
      RoleName: this.plan.bootstrapRole.name
    }));
  }

  async assertExactCleanupRole(expectedRoleId, {
    inlinePolicyPresent,
    tagsPresent = true
  }) {
    const code = "ONE_TIME_BOOTSTRAP_CLEANUP_ROLE_IDENTITY_REJECTED";
    requireCondition(typeof expectedRoleId === "string" &&
      /^[A-Z0-9]{8,128}$/u.test(expectedRoleId) &&
      typeof inlinePolicyPresent === "boolean" &&
      typeof tagsPresent === "boolean", code);
    const role = await this.inspectRole();
    const tags = await this.inspectTags();
    const policy = await this.inspectPolicy();
    requireCondition(role.state === "MATCH" &&
      role.receipt.roleId === expectedRoleId &&
      tags.state === (tagsPresent ? "MATCH" : "ABSENT") &&
      policy.state === (inlinePolicyPresent ? "MATCH" : "ABSENT"), code);
    const inlinePages = await paginateMarker((Marker) => this.iam.send(
      new ListRolePoliciesCommand({
        ...(Marker === undefined ? {} : { Marker }),
        RoleName: this.plan.bootstrapRole.name
      })
    ));
    const inlineNames = inlinePages.flatMap((page) =>
      page.PolicyNames ?? []).sort();
    const attachedPages = await paginateMarker((Marker) => this.iam.send(
      new ListAttachedRolePoliciesCommand({
        ...(Marker === undefined ? {} : { Marker }),
        RoleName: this.plan.bootstrapRole.name
      })
    ));
    const attachedArns = attachedPages.flatMap((page) =>
      (page.AttachedPolicies ?? []).map(({ PolicyArn }) => PolicyArn)).sort();
    requireCondition(canonicalJson(inlineNames) === canonicalJson(
      inlinePolicyPresent ? [this.plan.bootstrapRole.inlinePolicyName] : []
    ) && attachedArns.length === 0, code);
    return Object.freeze({
      attachedPolicyArnsSha256: digest(attachedArns),
      exactRoleId: expectedRoleId,
      inlinePolicyNamesSha256: digest(inlineNames),
      policySha256: inlinePolicyPresent ? policy.receipt.policySha256 : null,
      roleTagsSha256: tags.receipt.tagsSha256
    });
  }

  async deletePolicy(expectedRoleId, { tagsPresent = true } = {}) {
    await this.assertExactCleanupRole(expectedRoleId, {
      inlinePolicyPresent: true,
      tagsPresent
    });
    this.now();
    await this.iam.send(new DeleteRolePolicyCommand({
      PolicyName: this.plan.bootstrapRole.inlinePolicyName,
      RoleName: this.plan.bootstrapRole.name
    }));
  }

  async deleteRole(expectedRoleId, { tagsPresent = true } = {}) {
    await this.assertExactCleanupRole(expectedRoleId, {
      inlinePolicyPresent: false,
      tagsPresent
    });
    this.now();
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
    this.awsCliGuard();
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
    const rootCreateRoleReceipts = [];
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
        if (event.eventName === "CreateRole" &&
          event.errorCode === undefined) {
          const role = event.responseElements?.role;
          requireCondition(plainObject(role) &&
            typeof role.arn === "string" &&
            typeof role.createDate === "string" &&
            typeof role.path === "string" &&
            typeof role.roleId === "string" &&
            typeof role.roleName === "string", code);
          rootCreateRoleReceipts.push({
            arn: role.arn,
            createDate: role.createDate,
            eventTime: event.eventTime,
            path: role.path,
            roleId: role.roleId,
            roleName: role.roleName
          });
        }
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
      rootCreateRoleReceipts,
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

  async inspectAbandonedTarget(targetKey, invoke) {
    const code = "ONE_TIME_BOOTSTRAP_ABANDONED_RESOURCE_CENSUS_REJECTED";
    const target = this.plan.targets?.[targetKey];
    requireCondition(oneTimeBootstrapConstants.TARGET_KEYS.includes(targetKey) &&
      plainObject(target) && typeof invoke === "function", code);
    let stack = null;
    try {
      const response = await invoke("cloudformation:DescribeStacks", () =>
        this.cloudFormation.send(
          new DescribeStacksCommand({ StackName: target.stackName })
        ));
      requireCondition(Array.isArray(response.Stacks) &&
        response.Stacks.length === 1, code);
      [stack] = response.Stacks;
    } catch (cause) {
      if (!isNotFound(cause)) throw cause;
    }
    let stackReceipt;
    if (stack === null) {
      stackReceipt = {
        exactIdentity: true,
        stackIdSha256: null,
        stackStatus: "ABSENT",
        templateSha256: null,
        terminationProtection: null
      };
    } else {
      requireCondition(stack.StackName === target.stackName &&
        typeof stack.StackId === "string" &&
        !/(?:_IN_PROGRESS|_PENDING)$/u.test(stack.StackStatus ?? "") &&
        canonicalJson(parameterMap(stack.Parameters)) ===
          canonicalJson(target.parameters) && canonicalJson(stack.Tags ?? []) ===
          canonicalJson(target.tags), code);
      const template = await invoke("cloudformation:GetTemplate", () =>
        this.cloudFormation.send(new GetTemplateCommand({
          StackName: stack.StackId,
          TemplateStage: "Original"
        })));
      const templateBytes = Buffer.from(exactTemplateBody(
        template.TemplateBody,
        "ONE_TIME_BOOTSTRAP_ABANDONED_RESOURCE_CENSUS_REJECTED"
      ), "base64");
      requireCondition(sha256(templateBytes) === target.templateSha256, code);
      stackReceipt = {
        exactIdentity: true,
        stackIdSha256: sha256(stack.StackId),
        stackStatus: stack.StackStatus,
        templateSha256: target.templateSha256,
        terminationProtection: stack.EnableTerminationProtection === true
      };
    }
    const changeSets = [];
    const seenTokens = new Set();
    let nextToken;
    for (let page = 0; page < 100; page += 1) {
      let response;
      try {
        response = await invoke("cloudformation:ListChangeSets", () =>
          this.cloudFormation.send(new ListChangeSetsCommand({
            StackName: target.stackName,
            ...(nextToken === undefined ? {} : { NextToken: nextToken })
          })));
      } catch (cause) {
        if (stack === null && isNotFound(cause)) break;
        throw cause;
      }
      for (const summary of response.Summaries ?? []) {
        requireCondition(typeof summary.ChangeSetId === "string" &&
          typeof summary.ChangeSetName === "string" &&
          !["CREATE_PENDING", "CREATE_IN_PROGRESS", "DELETE_PENDING",
            "DELETE_IN_PROGRESS"].includes(summary.Status) &&
          summary.ExecutionStatus !== "EXECUTE_IN_PROGRESS", code);
        changeSets.push({
          changeSetIdSha256: sha256(summary.ChangeSetId),
          changeSetName: summary.ChangeSetName,
          executionStatus: summary.ExecutionStatus ?? null,
          status: summary.Status ?? null
        });
      }
      if (response.NextToken === undefined) break;
      requireCondition(typeof response.NextToken === "string" &&
        response.NextToken.length > 0 && !seenTokens.has(response.NextToken) &&
        page < 99, code);
      seenTokens.add(response.NextToken);
      nextToken = response.NextToken;
    }
    const secrets = [];
    for (const resource of target.resourceContract.filter(({ type }) =>
      type === "AWS::SecretsManager::Secret")) {
      let metadata;
      try {
        metadata = await invoke("secretsmanager:DescribeSecret", () =>
          this.secrets.send(new DescribeSecretCommand({
            SecretId: resource.secretName
          })));
      } catch (cause) {
        if (isNotFound(cause)) {
          secrets.push({
            present: false,
            secretNameSha256: sha256(resource.secretName),
            versionCount: 0,
            versionStageSetSha256: digest([])
          });
          continue;
        }
        throw cause;
      }
      requireCondition(metadata.Name === resource.secretName &&
        typeof metadata.ARN === "string", code);
      const versions = [];
      const versionTokens = new Set();
      let versionToken;
      for (let page = 0; page < 100; page += 1) {
        const response = await invoke("secretsmanager:ListSecretVersionIds",
          () => this.secrets.send(new ListSecretVersionIdsCommand({
            IncludeDeprecated: true,
            SecretId: metadata.ARN,
            ...(versionToken === undefined ? {} : { NextToken: versionToken })
          })));
        versions.push(...(response.Versions ?? []).map((version) => ({
          stages: [...(version.VersionStages ?? [])].sort(),
          versionIdSha256: sha256(String(version.VersionId ?? ""))
        })));
        if (response.NextToken === undefined) break;
        requireCondition(typeof response.NextToken === "string" &&
          response.NextToken.length > 0 &&
          !versionTokens.has(response.NextToken) && page < 99, code);
        versionTokens.add(response.NextToken);
        versionToken = response.NextToken;
      }
      secrets.push({
        present: true,
        secretNameSha256: sha256(resource.secretName),
        versionCount: versions.length,
        versionStageSetSha256: digest(versions)
      });
    }
    const body = {
      changeSetCount: changeSets.length,
      changeSetSetSha256: digest(changeSets),
      secretCensus: secrets,
      stack: stackReceipt,
      targetKey
    };
    return Object.freeze({ ...body, censusSha256: digest(body) });
  }

  async inspectNamedRootLogin() {
    const code = "ONE_TIME_BOOTSTRAP_AWS_LOGIN_READBACK_REJECTED";
    this.awsCliGuard();
    try {
      const { stdout, stderr } = await execFileAsync(this.awsCliPath, [
        "sts", "get-caller-identity", "--profile",
        this.plan.account.rootProfile, "--region", REGION, "--output", "json",
        "--no-cli-pager"
      ], {
        encoding: "utf8",
        env: {
          AWS_EC2_METADATA_DISABLED: "true",
          AWS_PROFILE: this.plan.account.rootProfile,
          HOME: process.env.HOME,
          LANG: "C",
          LC_ALL: "C",
          PATH: "/usr/bin:/bin"
        },
        maxBuffer: 64 * 1024,
        timeout: 30_000
      });
      requireCondition(stderr.trim() === "", code);
      const identity = JSON.parse(stdout);
      requireCondition(plainObject(identity) &&
        identity.Account === this.plan.account.accountId &&
        identity.Arn === this.plan.account.rootPrincipalArn, code);
      return Object.freeze({ state: "ACTIVE" });
    } catch (cause) {
      if (cause?.message === code) throw cause;
      const expected = "Error loading login session token: Unable to load a " +
        "existing login session for session " +
        `${this.plan.account.rootPrincipalArn}, Please reauthenticate with ` +
        "'aws login'.";
      const stderrValue = typeof cause?.stderr === "string" ?
        cause.stderr.trim() : "";
      const stdoutValue = typeof cause?.stdout === "string" ?
        cause.stdout.trim() : "";
      const negativeReadback = cause?.code === 255 &&
        (cause?.signal === null || cause?.signal === undefined) &&
        stdoutValue === "" && stderrValue === expected;
      requireCondition(negativeReadback, code);
      return Object.freeze({
        state: "ABSENT",
        receipt: Object.freeze({
          namedRootLoginSessionUnavailable: true,
          noninteractiveCallerIdentityRejected: true,
          profile: this.plan.account.rootProfile,
          rootSdkClientsDestroyed: true
        })
      });
    }
  }

  async logout() {
    this.awsCliGuard();
    this.destroy();
    this.now();
    const { stderr } = await execFileAsync(this.awsCliPath, [
      "logout", "--profile", this.plan.account.rootProfile
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
    return Object.freeze({ logoutCommandCompleted: true });
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
    requireCondition(value.getTime() < Date.parse(this.plan.notAfter) +
      PROVIDER_CONVERGENCE_TAIL_MS,
    "ONE_TIME_BOOTSTRAP_AWS_CONVERGENCE_EXPIRED");
    return value;
  }

  dispatchNow() {
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
    this.dispatchNow();
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
    this.dispatchNow();
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
    this.dispatchNow();
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
    const assertDispatchOpen = () => this.dispatchNow();
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
      putSecretVersion: ({ arn, clientRequestToken, secretString }) => {
        assertDispatchOpen();
        return secrets.send(new PutSecretValueCommand({
          ClientRequestToken: clientRequestToken,
          SecretId: exactArn(arn),
          SecretString: secretString,
          VersionStages: ["AWSCURRENT"]
        }));
      },
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
    const requestTime = this.dispatchNow();
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
  await runCrashConvergentMutation({
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
  const createReceipt = await runCrashConvergentMutation({
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
  if (preExecuteReceipt === undefined) {
    const changeSet = await provider.inspectChangeSet({ targetKey });
    requireCondition(changeSet.state === "MATCH",
      "ONE_TIME_BOOTSTRAP_CHANGE_SET_READBACK_REJECTED");
    preExecuteReceipt = validatePreExecuteChangeSetEvidence(
      plan,
      targetKey,
      changeSet.evidence
    );
  }
  requireCondition(executeStep === null || executeStep.state === "ACCEPTED" ||
    executeStep.state === "DISPATCH_STARTED" ||
    executeStep.state === "INTENT_RECORDED",
  "ONE_TIME_BOOTSTRAP_CHANGE_SET_READBACK_REJECTED");
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

function exactAssumeStepIds(journal, base) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_COUNT_REJECTED";
  const continuation = `${base}-continuation-001`;
  const relevant = Object.keys(journal.value.steps).filter((id) =>
    id === base || id.startsWith(`${base}-continuation-`)
  ).sort();
  requireCondition(relevant.length <= 2 && relevant.every((id) =>
    [base, continuation].includes(id)) &&
    (relevant.includes(continuation) ? relevant.includes(base) : true), code);
  return [base, continuation].filter((id) => relevant.includes(id));
}

function rootAssumeStepIds(journal) {
  return exactAssumeStepIds(journal, "root-assume-b0-session");
}

function writerAssumeStepIds(journal) {
  return exactAssumeStepIds(journal, "b0-assume-a1-writer-session");
}

function nextSessionStepId(journal, base, ids) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_COUNT_REJECTED";
  requireCondition(journal instanceof OneTimeBootstrapJournal &&
    ["root-assume-b0-session", "b0-assume-a1-writer-session"].includes(
      base
    ) && Array.isArray(ids) && ids.length <= 1 &&
    (ids.length === 0 || ids[0] === base), code);
  if (ids.length === 0) return base;
  return `${base}-continuation-001`;
}

function safeSessionReplacementAt(receipt, code) {
  const expiration = canonicalInstant(receipt?.credentialsExpiration, code);
  return receipt.schemaVersion ===
    "prooftoact.one-time-bootstrap-no-event-session-reconciliation.v1"
    ? expiration
    : expiration + CLOUDTRAIL_EVENT_LAG_MS;
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
  requireCondition(Number.isSafeInteger(assumeCount) && assumeCount >= 1 &&
    assumeCount <= 2,
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

async function waitUntilInstant({
  clock,
  instant,
  notAfter,
  sleep = (milliseconds) => new Promise((resolve) =>
    setTimeout(resolve, milliseconds))
}) {
  const code = "ONE_TIME_BOOTSTRAP_SESSION_EXPIRY_WAIT_REJECTED";
  const target = canonicalInstant(instant, code);
  const deadline = canonicalInstant(notAfter, code);
  requireCondition(target < deadline && typeof sleep === "function", code);
  for (;;) {
    const now = clock();
    requireCondition(now instanceof Date && Number.isFinite(now.getTime()) &&
      now.getTime() < deadline, code);
    if (now.getTime() >= target) return now.toISOString();
    await sleep(Math.min(30_000, target - now.getTime()));
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
  const operationDeadline = rootProvider.operationDeadline();
  requireCondition(operationDeadline instanceof Date &&
    Number.isFinite(operationDeadline.getTime()), code);
  const operationDeadlineIso = operationDeadline.toISOString();
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
            now.getTime() + 5_000) < operationDeadline.getTime(), code);
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
  const safeReplacementTimes = [...rootAssumeStepIds(journal),
    ...writerAssumeStepIds(journal)].flatMap((id) => {
    const step = journal.step(id);
    return step.state === "ACCEPTED" ?
      [safeSessionReplacementAt(step.receipt.sessionReceipt, code)] : [];
  });
  if (safeReplacementTimes.length === 0) return;
  const latest = new Date(Math.max(...safeReplacementTimes)).toISOString();
  await waitUntilInstant({
    clock: rootProvider.clock,
    instant: latest,
    notAfter: operationDeadlineIso,
    sleep: rootProvider.sleep
  });
}

async function reconcileExactRootEvents({
  gate,
  includeCleanup,
  journal,
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
    const rootAssumeCount = rootAssumeStepIds(journal).length;
    const writerAssumeCount = writerAssumeStepIds(journal).length;
    const exact = rootAssumeCount >= 1 && rootAssumeCount <= 2 &&
      writerAssumeCount >= 1 && writerAssumeCount <= 2 &&
      observed.length >= 4 + cleanupWidth &&
      canonicalJson(observed.slice(0, 3)) === canonicalJson(setup) &&
      assumptions.length === rootAssumeCount && assumptions.every((event) =>
        canonicalJson(event) === canonicalJson(expectedAssume)) &&
      Array.isArray(evidence.rootAssumeEventTimes) &&
      evidence.rootAssumeEventTimes.length === rootAssumeCount &&
      Array.isArray(evidence.writerAssumeEventTimes) &&
      evidence.writerAssumeEventTimes.length === writerAssumeCount &&
      (!includeCleanup || canonicalJson(observed.slice(-2)) ===
        canonicalJson(cleanup));
    if (exact) {
      return evidence;
    }
    const now = rootProvider.now();
    requireCondition(now.getTime() + 5_000 <
      rootProvider.operationDeadline().getTime(), code);
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
}

function validateLogoutReceipt(plan, receipt) {
  const code = "ONE_TIME_BOOTSTRAP_AWS_LOGOUT_RECEIPT_REJECTED";
  requireCondition(plainObject(receipt) && exactKeys(receipt, [
    "command", "dispatchOutcome", "namedRootLoginSessionUnavailable",
    "noninteractiveCallerIdentityRejected", "profile", "receiptSha256",
    "rootSdkClientsDestroyed", "schemaVersion", "status"
  ]) && receipt.schemaVersion ===
    "prooftoact.one-time-bootstrap-logout.v2" &&
    receipt.status === "NAMED_ROOT_LOGIN_SESSION_UNAVAILABLE" &&
    ["DISPATCHED_AND_NEGATIVELY_VERIFIED",
      "PRESTATE_ABSENT_AFTER_DURABLE_INTENT_OR_DISPATCH"].includes(
      receipt.dispatchOutcome
    ) && canonicalJson(receipt.command) === canonicalJson([
      "aws", "logout", "--profile", plan.account.rootProfile
    ]) && receipt.namedRootLoginSessionUnavailable === true &&
    receipt.noninteractiveCallerIdentityRejected === true &&
    receipt.profile === plan.account.rootProfile &&
    receipt.rootSdkClientsDestroyed === true &&
    receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
      receipt
    ).filter(([key]) => key !== "receiptSha256"))), code);
  return receipt;
}

async function convergeNamedRootLogout({ gate, journal, plan, rootProvider }) {
  const code = "ONE_TIME_BOOTSTRAP_AWS_LOGOUT_CONVERGENCE_REJECTED";
  const prior = journal.recordIntent("root-logout", "aws:Logout", {
    command: ["aws", "logout", "--profile", plan.account.rootProfile],
    rootPrincipalArn: plan.account.rootPrincipalArn
  });
  const before = await gate.invoke(
    "cleanup",
    "sts:GetCallerIdentity",
    () => rootProvider.inspectNamedRootLogin()
  );
  requireCondition(["ACTIVE", "ABSENT"].includes(before?.state), code);
  if (prior.state === "ACCEPTED") {
    requireCondition(before.state === "ABSENT", code);
    rootProvider.destroy();
    return validateLogoutReceipt(plan, prior.receipt);
  }
  let dispatchOutcome =
    "PRESTATE_ABSENT_AFTER_DURABLE_INTENT_OR_DISPATCH";
  if (before.state === "ACTIVE") {
    requireCondition(["INTENT_RECORDED", "DISPATCH_STARTED"].includes(
      prior.state
    ), code);
    if (prior.state === "INTENT_RECORDED") {
      journal.recordDispatchStarted("root-logout");
    }
    await gate.invoke("cleanup", "aws:Logout", () => rootProvider.logout());
    const after = await gate.invoke(
      "cleanup",
      "sts:GetCallerIdentity",
      () => rootProvider.inspectNamedRootLogin()
    );
    requireCondition(after?.state === "ABSENT", code);
    dispatchOutcome = "DISPATCHED_AND_NEGATIVELY_VERIFIED";
  } else {
    rootProvider.destroy();
  }
  const body = {
    schemaVersion: "prooftoact.one-time-bootstrap-logout.v2",
    status: "NAMED_ROOT_LOGIN_SESSION_UNAVAILABLE",
    command: ["aws", "logout", "--profile", plan.account.rootProfile],
    dispatchOutcome,
    namedRootLoginSessionUnavailable: true,
    noninteractiveCallerIdentityRejected: true,
    profile: plan.account.rootProfile,
    rootSdkClientsDestroyed: true
  };
  const receipt = Object.freeze({ ...body, receiptSha256: digest(body) });
  return journal.recordAccepted(
    "root-logout",
    before.state === "ABSENT" ? "PRESTATE_RECONCILIATION" :
      "POST_DISPATCH_RECONCILIATION",
    receipt
  ).receipt;
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
  const createdRoleStep = journal.step("root-create-b0-role");
  const expectedRoleId = createdRoleStep?.receipt?.roleId;
  requireCondition(createdRoleStep?.state === "ACCEPTED" &&
    typeof expectedRoleId === "string" && /^[A-Z0-9]{8,128}$/u.test(
      expectedRoleId
    ), "ONE_TIME_BOOTSTRAP_CLEANUP_ROLE_IDENTITY_REJECTED");
  let providerEvidence = acceptedLocalReceipt(
    journal,
    "local-accepted-cleanup-provider-evidence"
  );
  if (providerEvidence !== null) {
    providerEvidence = validateAcceptedCleanupProviderEvidence(
      plan,
      providerEvidence,
      expectedRoleId,
      journal
    );
    gate.advance("reconcile");
    gate.advance("cleanup");
    const awsLogout = await convergeNamedRootLogout({
      gate,
      journal,
      plan,
      rootProvider
    });
    return buildAcceptedCleanupReceipt({
      awsLogout,
      b0SessionReceipt,
      plan,
      providerEvidence,
      writerSessionReceipt
    });
  }
  gate.advance("reconcile");
  await reconcileExactRootEvents({
    gate,
    includeCleanup: false,
    journal,
    phase: "reconcile",
    plan,
    rootProvider
  });
  gate.advance("cleanup");
  const cleanupAlreadyStarted = journal.step("root-delete-b0-inline-policy") !==
    null || journal.step("root-delete-b0-role") !== null;
  if (!cleanupAlreadyStarted) {
    requireCondition(rootProvider.now().getTime() + CLEANUP_START_RESERVE_MS <
      rootProvider.operationDeadline().getTime(),
    "ONE_TIME_BOOTSTRAP_CLEANUP_RESERVE_REJECTED");
  }
  await runCrashConvergentMutation({
    acceptReceipt: sanitizedInspectionReceipt,
    classify: classifyMatch,
    contract: {
      completionReceiptSha256: completionReceipt.receiptSha256,
      expectedRoleId,
      policyName: plan.bootstrapRole.inlinePolicyName,
      roleName: plan.bootstrapRole.name
    },
    dispatch: () => gate.invoke("cleanup", "iam:DeleteRolePolicy", () =>
      rootProvider.deletePolicy(expectedRoleId)),
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
      expectedRoleId,
      roleName: plan.bootstrapRole.name
    },
    dispatch: () => gate.invoke("cleanup", "iam:DeleteRole", () =>
      rootProvider.deleteRole(expectedRoleId)),
    id: "root-delete-b0-role",
    inspect: () => gate.invoke("cleanup", "iam:GetRole", () =>
      rootProvider.inspectRoleAbsent()),
    journal,
    mutationClass: "iam:DeleteRole"
  });
  const cloudTrail = await reconcileExactRootEvents({
    gate,
    includeCleanup: true,
    journal,
    phase: "cleanup",
    plan,
    rootProvider
  });
  const providerEvidenceBody = {
    schemaVersion:
      "prooftoact.one-time-bootstrap-accepted-cleanup-provider-evidence.v1",
    status: "EXACT_B0_PROVIDER_CLEANUP_OBSERVED_BEFORE_LOGOUT",
    expectedRoleId,
    observedAt: rootProvider.now().toISOString(),
    operationId: plan.operation.operationId,
    planBodySha256: plan.planBodySha256,
    rootDirectEvents: cloudTrail.rootDirectEvents,
    rootAssumeEventTimes: cloudTrail.rootAssumeEventTimes,
    unexpectedRootMutationEvents: cloudTrail.unexpectedRootMutationEvents,
    writerAssumeEventTimes: cloudTrail.writerAssumeEventTimes
  };
  providerEvidence = persistLocalReceipt({
    contract: {
      completionReceiptSha256: completionReceipt.receiptSha256,
      expectedRoleId,
      planBodySha256: plan.planBodySha256
    },
    id: "local-accepted-cleanup-provider-evidence",
    journal,
    receipt: Object.freeze({
      ...providerEvidenceBody,
      receiptSha256: digest(providerEvidenceBody)
    })
  });
  providerEvidence = validateAcceptedCleanupProviderEvidence(
    plan,
    providerEvidence,
    expectedRoleId,
    journal
  );
  const awsLogout = await convergeNamedRootLogout({
    gate,
    journal,
    plan,
    rootProvider
  });
  return buildAcceptedCleanupReceipt({
    awsLogout,
    b0SessionReceipt,
    plan,
    providerEvidence,
    writerSessionReceipt
  });
}

function validateAcceptedCleanupProviderEvidence(plan, receipt,
  expectedRoleId, journal) {
  const code = "ONE_TIME_BOOTSTRAP_CLEANUP_PROVIDER_EVIDENCE_REJECTED";
  requireCondition(plainObject(receipt) && exactKeys(receipt, [
    "expectedRoleId", "observedAt", "operationId", "planBodySha256",
    "receiptSha256", "rootAssumeEventTimes", "rootDirectEvents",
    "schemaVersion", "status", "unexpectedRootMutationEvents",
    "writerAssumeEventTimes"
  ]) && receipt.schemaVersion ===
    "prooftoact.one-time-bootstrap-accepted-cleanup-provider-evidence.v1" &&
    receipt.status === "EXACT_B0_PROVIDER_CLEANUP_OBSERVED_BEFORE_LOGOUT" &&
    receipt.expectedRoleId === expectedRoleId &&
    receipt.operationId === plan.operation.operationId &&
    receipt.planBodySha256 === plan.planBodySha256 &&
    Number.isFinite(Date.parse(receipt.observedAt)) &&
    Array.isArray(receipt.rootDirectEvents) &&
    Array.isArray(receipt.rootAssumeEventTimes) &&
    receipt.rootAssumeEventTimes.length >= 1 &&
    receipt.rootAssumeEventTimes.length <= 2 &&
    receipt.rootAssumeEventTimes.length === rootAssumeStepIds(journal).length &&
    receipt.rootAssumeEventTimes.length === rootAssumeStepIdsFromEvents(
      receipt.rootDirectEvents
    ) &&
    Array.isArray(receipt.writerAssumeEventTimes) &&
    receipt.writerAssumeEventTimes.length >= 1 &&
    receipt.writerAssumeEventTimes.length <= 2 &&
    receipt.writerAssumeEventTimes.length ===
      writerAssumeStepIds(journal).length &&
    [...receipt.rootAssumeEventTimes,
      ...receipt.writerAssumeEventTimes].every((value) =>
      Number.isFinite(Date.parse(value)) &&
      new Date(Date.parse(value)).toISOString() === value) &&
    Array.isArray(receipt.unexpectedRootMutationEvents) &&
    receipt.unexpectedRootMutationEvents.length === 0 &&
    receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
      receipt
    ).filter(([key]) => key !== "receiptSha256"))), code);
  return receipt;
}

function rootAssumeStepIdsFromEvents(events) {
  return events.filter((event) => event?.eventName === "AssumeRole").length;
}

function buildAcceptedCleanupReceipt({
  awsLogout,
  b0SessionReceipt,
  plan,
  providerEvidence,
  writerSessionReceipt
}) {
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
    observedAt: providerEvidence.observedAt,
    operationId: plan.operation.operationId,
    rawCredentialFieldsPresent: false,
    rootAssumeEventTimes: providerEvidence.rootAssumeEventTimes,
    rootAssumeSessionCount: providerEvidence.rootAssumeEventTimes.length,
    rootDirectEvents: providerEvidence.rootDirectEvents,
    unexpectedRootMutationEvents:
      providerEvidence.unexpectedRootMutationEvents,
    writerSessionExpiration: writerSessionReceipt.credentialsExpiration,
    writerAssumeEventTimes: providerEvidence.writerAssumeEventTimes,
    writerAssumeSessionCount: providerEvidence.writerAssumeEventTimes.length,
    writerSessionExpired: Date.parse(writerSessionReceipt
      .credentialsExpiration) <= Date.parse(providerEvidence.observedAt)
  });
}

function validateAbandonedRootEvents(plan, journal, evidence, {
  requireCleanup
}) {
  const code = "ONE_TIME_BOOTSTRAP_ABANDONED_CLOUDTRAIL_REJECTED";
  requireCondition(plainObject(evidence) &&
    Array.isArray(evidence.rootDirectEvents) &&
    Array.isArray(evidence.unexpectedRootMutationEvents) &&
    evidence.unexpectedRootMutationEvents.length === 0, code);
  const canonicalAllowed = new Set(expectedRootDirectEvents(
    plan,
    true,
    1
  ).map((event) => canonicalJson(event)));
  const counts = new Map();
  for (const event of evidence.rootDirectEvents) {
    requireCondition(canonicalAllowed.has(canonicalJson(event)), code);
    counts.set(event.eventName, (counts.get(event.eventName) ?? 0) + 1);
  }
  for (const name of ["CreateRole", "TagRole", "PutRolePolicy",
    "DeleteRolePolicy", "DeleteRole"]) {
    requireCondition((counts.get(name) ?? 0) <= 1, code);
  }
  requireCondition((counts.get("AssumeRole") ?? 0) <=
    rootAssumeStepIds(journal).length, code);
  if (requireCleanup) {
    const policyDelete = journal.step("abandoned-root-delete-b0-inline-policy");
    const roleDelete = journal.step("abandoned-root-delete-b0-role");
    requireCondition((policyDelete?.state === "ACCEPTED" ?
      counts.get("DeleteRolePolicy") === 1 : true) &&
      (roleDelete?.state === "ACCEPTED" ?
        counts.get("DeleteRole") === 1 : true), code);
  }
  return evidence;
}

function abandonedCleanupRoleId(journal, role) {
  const code = "ONE_TIME_BOOTSTRAP_ABANDONED_CLEANUP_REJECTED";
  requireCondition(journal instanceof OneTimeBootstrapJournal &&
    plainObject(role) && ["ABSENT", "MATCH"].includes(role.state), code);
  const createStep = journal.step("root-create-b0-role");
  if (role.state === "ABSENT") {
    // IAM and CloudTrail are eventually consistent and publish no bounded
    // negative-delivery receipt. An ambiguous CreateRole dispatch therefore
    // cannot be converted into a durable absence claim, regardless of how
    // many adjacent negative reads are observed. Only an undispatched intent
    // proves no role could later appear under the exact name.
    requireCondition(createStep === null ||
      createStep.state === "INTENT_RECORDED" &&
      createStep.dispatchStartedAt === null, code);
    return null;
  }
  requireCondition(createStep?.state === "ACCEPTED" &&
    typeof createStep.receipt?.roleId === "string" &&
    /^[A-Z0-9]{8,128}$/u.test(createStep.receipt.roleId) &&
    role.receipt?.roleId === createStep.receipt.roleId, code);
  return createStep.receipt.roleId;
}

function exactCreateRoleReceipt(plan, role, receipt, dispatchStartedAt) {
  const code = "ONE_TIME_BOOTSTRAP_CREATE_ROLE_RECONCILIATION_REJECTED";
  const eventTime = canonicalInstant(receipt?.eventTime, code);
  const createDate = Date.parse(receipt?.createDate);
  requireCondition(Number.isFinite(createDate) &&
    role.state === "MATCH" && role.receipt?.arn === plan.bootstrapRole.arn &&
    role.receipt.roleName === plan.bootstrapRole.name &&
    role.receipt.roleId === receipt.roleId &&
    role.receipt.createdAt === new Date(createDate).toISOString() &&
    receipt.arn === plan.bootstrapRole.arn &&
    receipt.roleName === plan.bootstrapRole.name &&
    receipt.path === plan.bootstrapRole.path &&
    eventTime >= Date.parse(dispatchStartedAt) - 30_000, code);
  return receipt;
}

async function reconcileAbandonedCreateRole({
  cloudTrail,
  gate,
  journal,
  plan,
  role,
  rootProvider
}) {
  const code = "ONE_TIME_BOOTSTRAP_CREATE_ROLE_RECONCILIATION_REJECTED";
  const step = journal.step("root-create-b0-role");
  if (step?.state !== "DISPATCH_STARTED") return role;
  requireCondition(Array.isArray(cloudTrail.rootCreateRoleReceipts), code);
  if (role.state === "MATCH") {
    requireCondition(cloudTrail.rootCreateRoleReceipts.length === 1, code);
    const providerReceipt = exactCreateRoleReceipt(
      plan,
      role,
      cloudTrail.rootCreateRoleReceipts[0],
      step.dispatchStartedAt
    );
    journal.recordAccepted(
      "root-create-b0-role",
      "POST_DISPATCH_RECONCILIATION",
      {
        ...role.receipt,
        cloudTrailCreateEventTime: new Date(Date.parse(
          providerReceipt.eventTime
        )).toISOString()
      }
    );
    return role;
  }
  // A negative IAM read plus missing CloudTrail event is not an authoritative
  // absence result. Preserve the journal and HOLD for later exact provider
  // reconciliation; never delete or terminalize by role name alone.
  requireCondition(role.state !== "ABSENT", code);
  return role;
}

function validateAbandonmentDisposition(plan, receipt) {
  const code = "ONE_TIME_BOOTSTRAP_ABANDONED_DISPOSITION_REJECTED";
  requireCondition(plainObject(receipt) && exactKeys(receipt, [
    "allObservedSessionsExpired", "authorizationReceiptSha256",
    "expectedRoleId", "expectedRoleIdSha256", "inlinePolicyPresent",
    "operationId", "planBodySha256",
    "postExecutionMutationContinuationAuthorized",
    "preCleanupCloudTrailSha256", "publicDisposition", "receiptSha256",
    "schemaVersion", "status", "tagsPresent", "targetCensus",
    "targetCensusSha256"
  ]) && receipt.schemaVersion ===
    "prooftoact.abandoned-partial-b0-disposition.v2" &&
    receipt.status ===
      "ABANDONED_PARTIAL_B0_TEMP_AUTHORITY_REMOVAL_AUTHORIZED" &&
    receipt.operationId === plan.operation.operationId &&
    receipt.planBodySha256 === plan.planBodySha256 &&
    receipt.authorizationReceiptSha256 ===
      plan.authorization.userAuthorizationReceiptSha256 &&
    Array.isArray(receipt.targetCensus) &&
    receipt.targetCensusSha256 === digest(receipt.targetCensus) &&
    /^[0-9a-f]{64}$/u.test(receipt.preCleanupCloudTrailSha256 ?? "") &&
    (receipt.expectedRoleId === null ?
      receipt.expectedRoleIdSha256 === null :
      /^[A-Z0-9]{8,128}$/u.test(receipt.expectedRoleId) &&
      receipt.expectedRoleIdSha256 === sha256(receipt.expectedRoleId)) &&
    typeof receipt.tagsPresent === "boolean" &&
    typeof receipt.inlinePolicyPresent === "boolean" &&
    receipt.allObservedSessionsExpired === true &&
    receipt.postExecutionMutationContinuationAuthorized === false &&
    receipt.publicDisposition === "HOLD" &&
    receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
      receipt
    ).filter(([key]) => key !== "receiptSha256"))), code);
  assertNoCredentialMaterial(receipt);
  return receipt;
}

function validateAbandonedCleanupProviderEvidence(plan, receipt,
  abandonmentReceipt) {
  const code = "ONE_TIME_BOOTSTRAP_ABANDONED_PROVIDER_EVIDENCE_REJECTED";
  requireCondition(plainObject(receipt) && exactKeys(receipt, [
    "abandonmentReceiptSha256", "operationId", "planBodySha256",
    "providerActionsCompletedAt", "receiptSha256", "rootDirectEvents",
    "rootDirectEventsSha256", "schemaVersion", "status"
  ]) && receipt.schemaVersion ===
    "prooftoact.abandoned-partial-b0-provider-evidence.v1" &&
    receipt.status === "ABANDONED_PARTIAL_B0_PROVIDER_CLEANUP_OBSERVED" &&
    receipt.abandonmentReceiptSha256 ===
      abandonmentReceipt.receiptSha256 &&
    receipt.operationId === plan.operation.operationId &&
    receipt.planBodySha256 === plan.planBodySha256 &&
    Number.isFinite(Date.parse(receipt.providerActionsCompletedAt)) &&
    Array.isArray(receipt.rootDirectEvents) &&
    receipt.rootDirectEventsSha256 === digest(receipt.rootDirectEvents) &&
    receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
      receipt
    ).filter(([key]) => key !== "receiptSha256"))), code);
  assertNoCredentialMaterial(receipt);
  return receipt;
}

function buildAbandonedCleanupReceipt({
  abandonmentReceipt,
  awsLogout,
  plan,
  providerEvidence
}) {
  const targetCensus = abandonmentReceipt.targetCensus;
  const body = {
    schemaVersion: "prooftoact.abandoned-partial-b0-cleanup.v2",
    status: "ABANDONED_PARTIAL_B0_TEMP_AUTHORITY_REMOVED",
    publicDisposition: "HOLD",
    operationId: plan.operation.operationId,
    planBodySha256: plan.planBodySha256,
    abandonmentReceiptSha256: abandonmentReceipt.receiptSha256,
    bootstrapRoleAbsent: true,
    inlinePolicyAbsent: true,
    targetCensus,
    targetCensusSha256: abandonmentReceipt.targetCensusSha256,
    allObservedSessionsExpired: true,
    providerActionsCompletedAt: providerEvidence.providerActionsCompletedAt,
    rootDirectEventsSha256: providerEvidence.rootDirectEventsSha256,
    awsLogout,
    retainedPartialResourcesRequireSeparateDisposition: targetCensus.some(
      (target) => target.stack.stackStatus !== "ABSENT" ||
        target.secretCensus.some(({ present }) => present)
    ),
    newProviderOrWorkloadMutationPerformed: false
  };
  assertNoCredentialMaterial(body);
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

async function cleanupAbandonedPartialBootstrap({
  gate,
  journal,
  plan,
  rootProvider
}) {
  const code = "ONE_TIME_BOOTSTRAP_ABANDONED_CLEANUP_REJECTED";
  requireCondition(journal.mode === "RECONCILE_ONLY" &&
    journal.cleanupOnly === true &&
    rootProvider.allowExpiredCleanup === true, code);
  const dispositionStep = journal.step("abandoned-partial-b0-disposition");
  let abandonmentReceipt = dispositionStep?.state === "ACCEPTED" ?
    validateAbandonmentDisposition(plan, dispositionStep.receipt) : null;
  let providerEvidence = acceptedLocalReceipt(
    journal,
    "local-abandoned-cleanup-provider-evidence"
  );
  if (providerEvidence !== null) {
    requireCondition(abandonmentReceipt !== null, code);
    providerEvidence = validateAbandonedCleanupProviderEvidence(
      plan,
      providerEvidence,
      abandonmentReceipt
    );
    gate.advance("reconcile");
    gate.advance("cleanup");
    const awsLogout = await convergeNamedRootLogout({
      gate,
      journal,
      plan,
      rootProvider
    });
    return buildAbandonedCleanupReceipt({
      abandonmentReceipt,
      awsLogout,
      plan,
      providerEvidence
    });
  }
  if (abandonmentReceipt === null) {
    await reconcilePriorLostSessions({ gate, journal, plan, rootProvider });
    const now = rootProvider.now();
    const sessionReceipts = [...rootAssumeStepIds(journal),
      ...writerAssumeStepIds(journal)].flatMap((id) => {
      const step = journal.step(id);
      return step?.state === "ACCEPTED" &&
        plainObject(step.receipt?.sessionReceipt) ?
        [step.receipt.sessionReceipt] : [];
    });
    requireCondition(sessionReceipts.every((receipt) =>
      Date.parse(receipt.credentialsExpiration) <= now.getTime()), code);
  }
  const preCloudTrail = validateAbandonedRootEvents(
    plan,
    journal,
    await gate.invoke("setup", "cloudtrail:LookupEvents", () =>
      rootProvider.lookupRootMutationEvents()),
    { requireCleanup: false }
  );
  const observedTargetCensus = [];
  for (const targetKey of oneTimeBootstrapConstants.TARGET_KEYS) {
    observedTargetCensus.push(await rootProvider.inspectAbandonedTarget(
      targetKey,
      (action, callback) => gate.invoke("setup", action, callback)
    ));
  }
  if (abandonmentReceipt !== null) {
    requireCondition(digest(observedTargetCensus) ===
      abandonmentReceipt.targetCensusSha256, code);
  }
  let role = await gate.invoke("setup", "iam:GetRole", () =>
    rootProvider.inspectRole());
  if (abandonmentReceipt === null) {
    role = await reconcileAbandonedCreateRole({
      cloudTrail: preCloudTrail,
      gate,
      journal,
      plan,
      role,
      rootProvider
    });
  }
  let expectedRoleId;
  let tagsPresent;
  let inlinePolicyPresent;
  if (abandonmentReceipt === null) {
    expectedRoleId = abandonedCleanupRoleId(journal, role);
    tagsPresent = false;
    inlinePolicyPresent = false;
  } else {
    expectedRoleId = abandonmentReceipt.expectedRoleId;
    tagsPresent = abandonmentReceipt.tagsPresent;
    inlinePolicyPresent = abandonmentReceipt.inlinePolicyPresent;
    requireCondition(role.state !== "CONFLICT" &&
      (expectedRoleId === null ? role.state === "ABSENT" :
        (role.state === "MATCH" &&
          role.receipt?.roleId === expectedRoleId) ||
        (role.state === "ABSENT" &&
          ["DISPATCH_STARTED", "ACCEPTED"].includes(journal.step(
            "abandoned-root-delete-b0-role"
          )?.state))), code);
  }
  if (role.state === "MATCH") {
    const tags = await gate.invoke("setup", "iam:ListRoleTags", () =>
      rootProvider.inspectTags());
    const policy = await gate.invoke("setup", "iam:GetRolePolicy", () =>
      rootProvider.inspectPolicy());
    requireCondition(["ABSENT", "MATCH"].includes(tags.state) &&
      ["ABSENT", "MATCH"].includes(policy.state), code);
    const currentTagsPresent = tags.state === "MATCH";
    const currentInlinePolicyPresent = policy.state === "MATCH";
    const tagStep = journal.step("root-tag-b0-role");
    const policyStep = journal.step("root-put-b0-inline-policy");
    if (abandonmentReceipt === null) {
      tagsPresent = currentTagsPresent;
      inlinePolicyPresent = currentInlinePolicyPresent;
      requireCondition(tagsPresent ?
        ["DISPATCH_STARTED", "ACCEPTED"].includes(tagStep?.state) :
        tagStep === null || ["INTENT_RECORDED", "DISPATCH_STARTED"].includes(
          tagStep.state
        ), code);
      requireCondition(inlinePolicyPresent ?
        ["DISPATCH_STARTED", "ACCEPTED"].includes(policyStep?.state) :
        policyStep === null ||
          ["INTENT_RECORDED", "DISPATCH_STARTED"].includes(
            policyStep.state
          ), code);
    } else {
      requireCondition(currentTagsPresent === tagsPresent &&
        (inlinePolicyPresent ?
          currentInlinePolicyPresent ||
            (!currentInlinePolicyPresent &&
            ["DISPATCH_STARTED", "ACCEPTED"].includes(journal.step(
              "abandoned-root-delete-b0-inline-policy"
            )?.state)) :
          !currentInlinePolicyPresent), code);
    }
    await rootProvider.assertExactCleanupRole(expectedRoleId, {
      inlinePolicyPresent: currentInlinePolicyPresent,
      tagsPresent: currentTagsPresent
    });
  }
  if (abandonmentReceipt === null) {
    const abandonmentBody = {
      schemaVersion: "prooftoact.abandoned-partial-b0-disposition.v2",
      status: "ABANDONED_PARTIAL_B0_TEMP_AUTHORITY_REMOVAL_AUTHORIZED",
      operationId: plan.operation.operationId,
      planBodySha256: plan.planBodySha256,
      authorizationReceiptSha256:
        plan.authorization.userAuthorizationReceiptSha256,
      targetCensus: observedTargetCensus,
      targetCensusSha256: digest(observedTargetCensus),
      preCleanupCloudTrailSha256: digest(preCloudTrail.rootDirectEvents),
      expectedRoleId,
      expectedRoleIdSha256: expectedRoleId === null ? null :
        sha256(expectedRoleId),
      tagsPresent,
      inlinePolicyPresent,
      allObservedSessionsExpired: true,
      postExecutionMutationContinuationAuthorized: false,
      publicDisposition: "HOLD"
    };
    const candidate = Object.freeze({
      ...abandonmentBody,
      receiptSha256: digest(abandonmentBody)
    });
    const abandonmentStep = journal.recordIntent(
      "abandoned-partial-b0-disposition",
      "local:AbandonedPartialB0Disposition",
      { receiptSha256: candidate.receiptSha256 }
    );
    if (abandonmentStep.state !== "ACCEPTED") {
      abandonmentReceipt = journal.recordAccepted(
        "abandoned-partial-b0-disposition",
        "PRESTATE_RECONCILIATION",
        candidate
      ).receipt;
    } else {
      abandonmentReceipt = abandonmentStep.receipt;
    }
    abandonmentReceipt = validateAbandonmentDisposition(
      plan,
      abandonmentReceipt
    );
  }
  gate.advance("reconcile");
  gate.advance("cleanup");
  const cleanupStarted = journal.step(
    "abandoned-root-delete-b0-inline-policy"
  ) !== null || journal.step("abandoned-root-delete-b0-role") !== null;
  if (!cleanupStarted) {
    requireCondition(rootProvider.now().getTime() + CLEANUP_START_RESERVE_MS <
      rootProvider.operationDeadline().getTime(),
    "ONE_TIME_BOOTSTRAP_CLEANUP_RESERVE_REJECTED");
  }
  if (expectedRoleId !== null && inlinePolicyPresent) {
    await runCrashConvergentMutation({
      acceptReceipt: sanitizedInspectionReceipt,
      classify: classifyMatch,
      contract: {
        abandonmentReceiptSha256: abandonmentReceipt.receiptSha256,
        expectedRoleId,
        policyName: plan.bootstrapRole.inlinePolicyName,
        roleName: plan.bootstrapRole.name,
        tagsPresent
      },
      dispatch: () => gate.invoke("cleanup", "iam:DeleteRolePolicy", () =>
        rootProvider.deletePolicy(expectedRoleId, { tagsPresent })),
      id: "abandoned-root-delete-b0-inline-policy",
      inspect: () => gate.invoke("cleanup", "iam:GetRolePolicy", () =>
        rootProvider.inspectPolicyAbsent()),
      journal,
      mutationClass: "iam:DeleteRolePolicy"
    });
  }
  if (expectedRoleId !== null) {
    await runCrashConvergentMutation({
      acceptReceipt: sanitizedInspectionReceipt,
      classify: classifyMatch,
      contract: {
        abandonmentReceiptSha256: abandonmentReceipt.receiptSha256,
        expectedRoleId,
        roleName: plan.bootstrapRole.name,
        tagsPresent
      },
      dispatch: () => gate.invoke("cleanup", "iam:DeleteRole", () =>
        rootProvider.deleteRole(expectedRoleId, { tagsPresent })),
      id: "abandoned-root-delete-b0-role",
      inspect: () => gate.invoke("cleanup", "iam:GetRole", () =>
        rootProvider.inspectRoleAbsent()),
      journal,
      mutationClass: "iam:DeleteRole"
    });
  } else {
    requireCondition((await gate.invoke("cleanup", "iam:GetRole", () =>
      rootProvider.inspectRoleAbsent())).state === "MATCH", code);
  }
  let postCloudTrail;
  for (;;) {
    postCloudTrail = await gate.invoke(
      "cleanup",
      "cloudtrail:LookupEvents",
      () => rootProvider.lookupRootMutationEvents()
    );
    try {
      validateAbandonedRootEvents(plan, journal, postCloudTrail, {
        requireCleanup: true
      });
      break;
    } catch (cause) {
      requireCondition(rootProvider.now().getTime() + 5_000 <
        rootProvider.operationDeadline().getTime(), code);
      await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
  }
  const providerEvidenceBody = {
    schemaVersion: "prooftoact.abandoned-partial-b0-provider-evidence.v1",
    status: "ABANDONED_PARTIAL_B0_PROVIDER_CLEANUP_OBSERVED",
    abandonmentReceiptSha256: abandonmentReceipt.receiptSha256,
    operationId: plan.operation.operationId,
    planBodySha256: plan.planBodySha256,
    providerActionsCompletedAt: rootProvider.now().toISOString(),
    rootDirectEvents: postCloudTrail.rootDirectEvents,
    rootDirectEventsSha256: digest(postCloudTrail.rootDirectEvents)
  };
  providerEvidence = persistLocalReceipt({
    contract: {
      abandonmentReceiptSha256: abandonmentReceipt.receiptSha256,
      planBodySha256: plan.planBodySha256
    },
    id: "local-abandoned-cleanup-provider-evidence",
    journal,
    receipt: Object.freeze({
      ...providerEvidenceBody,
      receiptSha256: digest(providerEvidenceBody)
    })
  });
  providerEvidence = validateAbandonedCleanupProviderEvidence(
    plan,
    providerEvidence,
    abandonmentReceipt
  );
  const awsLogout = await convergeNamedRootLogout({
    gate,
    journal,
    plan,
    rootProvider
  });
  return buildAbandonedCleanupReceipt({
    abandonmentReceipt,
    awsLogout,
    plan,
    providerEvidence
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

function writeAbandonedTerminalReceipt(plan, cleanupReceipt) {
  process.stdout.write(canonicalJson({
    cleanupReceipt,
    completionReceipt: null,
    operationId: plan.operation.operationId,
    rawCredentialFieldsPresent: false,
    schemaVersion: "prooftoact.one-time-bootstrap-run.v1",
    status: "ABANDONED_PARTIAL_B0_TEMP_AUTHORITY_REMOVED_PUBLIC_HOLD"
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

export async function main(args, launchContext) {
  const launchCode = "ONE_TIME_BOOTSTRAP_LAUNCH_CONTEXT_REJECTED";
  requireCondition(Array.isArray(args) && exactKeys(launchContext, [
    "authorizationBytes", "awsCliGuard", "bindingReceipt", "moduleRoot"
  ]) && Buffer.isBuffer(launchContext.authorizationBytes) &&
    typeof launchContext.awsCliGuard === "function" &&
    plainObject(launchContext.bindingReceipt) &&
    typeof launchContext.moduleRoot === "string" &&
    path.isAbsolute(launchContext.moduleRoot), launchCode);
  const parsed = parseMainArguments(args);
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
  const checkout = validateOneTimeBootstrapCheckout({
    awsCliPath: parsed["--aws-cli-path"],
    expectedCommit: plan.source.commit,
    expectedTree: plan.source.tree,
    homeDirectory: process.env.HOME,
    operationId: plan.operation.operationId,
    privateRecoveryWorkflowCommits: Object.fromEntries(
      oneTimeBootstrapConstants.PRIVATE_RECOVERY_WORKFLOW_KEYS.map((key) =>
        [key, plan.source.privateRecoveryWorkflowPins[key].commit]
      )
    ),
    sourceRoot: parsed["--source-root"],
    targetTemplateSha256: Object.fromEntries(
      oneTimeBootstrapConstants.TARGET_KEYS.map((key) =>
        [key, plan.targets[key].templateSha256])
    )
  });
  requireCondition(canonicalJson(checkout.runtimeExecutionBinding) ===
    canonicalJson(plan.source.runtimeExecutionBinding) &&
    launchContext.bindingReceipt.awsCliTreeSha256 ===
      plan.source.runtimeExecutionBinding.awsCli.treeDigest &&
    launchContext.bindingReceipt.dependencyTreeSha256 ===
      plan.source.runtimeExecutionBinding.dependencies.treeDigest &&
    launchContext.bindingReceipt.nodeExecutableSha256 ===
      plan.source.runtimeExecutionBinding.node.executableSha256,
  launchCode);
  const executingBytes = readReviewedRegularFile(
    path.join(launchContext.moduleRoot, plan.source.ceremonyRunnerPath),
    2 * 1024 * 1024,
    "ONE_TIME_BOOTSTRAP_RUNNER_IDENTITY_REJECTED"
  );
  requireCondition(path.resolve(CURRENT_FILE) === path.join(
    launchContext.moduleRoot, plan.source.ceremonyRunnerPath
  ) && sha256(executingBytes) === plan.source.ceremonyRunnerSha256,
  "ONE_TIME_BOOTSTRAP_RUNNER_IDENTITY_REJECTED");
  const authorization = validateOneTimeBootstrapAuthorizationBytes(
    plan,
    launchContext.authorizationBytes,
    () => new Date(),
    { allowExpiredReconcile: parsed["--mode"] === "RECONCILE_ONLY" }
  );
  const identityRecordBytes = readPrivateFdToBuffer(
    IDENTITY_RECORD_FD,
    16 * 1024,
    "ONE_TIME_BOOTSTRAP_IDENTITY_RECORD_FD_REJECTED"
  );
  let identityHmacKey;
  try {
    identityHmacKey = readPrivateFdToBuffer(
      IDENTITY_HMAC_KEY_FD,
      32,
      "ONE_TIME_BOOTSTRAP_IDENTITY_HMAC_KEY_FD_REJECTED"
    );
    requireCondition(identityHmacKey.length === 32 &&
      sha256(identityHmacKey) === authorization.receipt
        .humanAuthorizationBinding.dynamicIntent
        .humanIdentityHmacKeySha256,
    "ONE_TIME_BOOTSTRAP_IDENTITY_HMAC_KEY_FD_REJECTED");
    await verifyProofToActB0A1HumanAuthorizationWithImsg(
      authorization.receipt.humanAuthorizationBinding,
      identityRecordBytes,
      identityHmacKey
    );
  } finally {
    identityHmacKey?.fill(0);
    identityRecordBytes.fill(0);
  }
  const valueLease = createFixedFdWriterValueLease();
  let journal;
  let b0Lease;
  let rootProvider;
  try {
    const a1 = await loadA1Integration(
      plan,
      launchContext.moduleRoot
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
    const expiredCleanupOnly = Date.now() >= Date.parse(plan.notAfter);
    requireCondition(!expiredCleanupOnly ||
      parsed["--mode"] === "RECONCILE_ONLY" && Date.now() < Date.parse(
        plan.authorization.cleanupOnlyAuthorization.expiresAt
      ),
    "ONE_TIME_BOOTSTRAP_EXPIRED_RECONCILIATION_REJECTED");
    journal.cleanupOnly = expiredCleanupOnly;
    if (priorCleanupReceipt !== null) {
      if (priorCleanupReceipt.schemaVersion ===
        "prooftoact.abandoned-partial-b0-cleanup.v2") {
        requireCondition(priorCleanupReceipt.publicDisposition === "HOLD",
          "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
        writeAbandonedTerminalReceipt(plan, priorCleanupReceipt);
      } else {
        requireCondition(completionReceipt?.schemaVersion ===
          "prooftoact.one-time-bootstrap-completion.v1" &&
          priorCleanupReceipt.schemaVersion ===
            "prooftoact.one-time-bootstrap-cleanup-accepted.v1",
        "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
        writeTerminalReceipt(plan, completionReceipt, priorCleanupReceipt);
      }
      return;
    }
    if (!expiredCleanupOnly && result === null &&
      journal.step("seal-five-a1-writer-values")?.state !== "ACCEPTED") {
      valueLease.prepare(authorization.receipt.writerValueSha256);
    }
    const gate = new RootActionGate();
    rootProvider = new AwsOneTimeBootstrapRootProvider({
      allowExpiredCleanup: expiredCleanupOnly,
      awsCliGuard: launchContext.awsCliGuard,
      awsCliPath: parsed["--aws-cli-path"],
      plan
    });
    const cleanupStarted = journal.step("root-delete-b0-inline-policy") !==
      null || journal.step("root-delete-b0-role") !== null;
    const cleanupProviderEvidenceRecorded = [
      "local-accepted-cleanup-provider-evidence",
      "local-abandoned-cleanup-provider-evidence"
    ].some((id) => journal.step(id)?.state === "ACCEPTED");
    const logoutStarted = journal.step("root-logout") !== null;
    let mfaDiscoveryReceipt;
    if (expiredCleanupOnly || cleanupProviderEvidenceRecorded ||
      logoutStarted) {
      gate.advance("setup");
    } else if (cleanupStarted) {
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
    if (expiredCleanupOnly && result !== null && completionReceipt === null) {
      await reconcilePriorLostSessions({
        gate,
        journal,
        plan,
        rootProvider
      });
      const recoveredB0SessionReceipt = latestAcceptedSessionReceipt(
        journal,
        rootAssumeStepIds(journal),
        "ONE_TIME_BOOTSTRAP_B0_SESSION_RECONCILIATION_REQUIRED"
      );
      requireCondition(plainObject(result.writerSessionReceipt),
        "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
      const latestExpiration = new Date(Math.max(
        Date.parse(recoveredB0SessionReceipt.credentialsExpiration),
        Date.parse(result.writerSessionReceipt.credentialsExpiration)
      )).toISOString();
      const observedAt = await waitUntilInstant({
        clock: rootProvider.clock,
        instant: latestExpiration,
        notAfter: rootProvider.operationDeadline().toISOString()
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
    if (expiredCleanupOnly && result === null) {
      requireCondition(completionReceipt === null,
        "ONE_TIME_BOOTSTRAP_LOCAL_RECEIPT_REJECTED");
      let abandonedCleanupReceipt = await cleanupAbandonedPartialBootstrap({
        gate,
        journal,
        plan,
        rootProvider
      });
      abandonedCleanupReceipt = persistLocalReceipt({
        contract: {
          planBodySha256: plan.planBodySha256,
          targetCensusSha256: abandonedCleanupReceipt.targetCensusSha256
        },
        id: "local-cleanup-receipt",
        journal,
        receipt: abandonedCleanupReceipt
      });
      writeAbandonedTerminalReceipt(plan, abandonedCleanupReceipt);
      return;
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
    rootProvider?.destroy();
    valueLease.destroy();
    // A real process crash cannot run this finally and intentionally leaves
    // the exclusive lock in place for audited stale-lock recovery.
    journal?.releaseLock();
  }
}

const startedDirectly = process.argv[1] &&
  path.resolve(process.argv[1]) === CURRENT_FILE;

if (startedDirectly) {
  process.stderr.write("ONE_TIME_BOOTSTRAP_LAUNCHER_REQUIRED\n");
  process.exitCode = 1;
}

export const oneTimeBootstrapRunnerConstants = Object.freeze({
  A1_INTEGRATION_PATHS,
  AUTHORIZATION_RECEIPT_FD,
  CLOUDTRAIL_EVENT_LAG_MS,
  HUMAN_AUTHORITY_ID,
  IDENTITY_HMAC_KEY_FD,
  IDENTITY_RECORD_FD,
  JOURNAL_FILE_PREFIX,
  JOURNAL_SCHEMA,
  MFA_TOKEN_FD,
  PROVIDER_CONVERGENCE_TAIL_MS,
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
  abandonedCleanupRoleId,
  cleanupAbandonedPartialBootstrap,
  exactCreateRoleReceipt,
  nextSessionStepId,
  reconcileAbandonedCreateRole,
  reconcilePriorLostSessions,
  rootAssumeStepIds,
  safeSessionReplacementAt,
  sha256,
  validateAbandonedRootEvents,
  verifyJournal,
  writerAssumeStepIds
});
