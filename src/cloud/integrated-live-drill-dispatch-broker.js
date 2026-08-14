import { createHash, createHmac, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { publishOrReadExactOwnedFile } from "./atomic-create-only-file.js";

import { canonicalJson } from "./canonical-json.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import {
  buildProviderDispatchReconciliationInput,
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA,
  providerDispatchReconciliationInputBytes
} from "./provider-dispatch-reconciliation-input.js";

export {
  INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA
} from "./provider-dispatch-reconciliation-input.js";

export const INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_SCHEMA =
  "tideproof.integrated-live-drill-dispatch-broker-request.v1";
export const INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_RECEIPT_SCHEMA =
  "tideproof.integrated-live-drill-dispatch-broker-receipt.v1";
export const INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA =
  "tideproof.integrated-live-drill-execution-grant.v1";

const CAPABILITY_FILE_NAME = "execution-capability.json";
const OPERATION_NONCE_FILE_NAME = "operation-nonce";
const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const CLAIM_RETRY_LIMIT = 8;
const CLAIM_RETRYABLE_SQLSTATES = new Set([
  "40001",
  "08000",
  "08001",
  "08003",
  "08004",
  "08006",
  "08007",
  "08P01",
  "57P01",
  "57P02",
  "57P03"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    Reflect.ownKeys(value).every((key) =>
      typeof key === "string" && keys.includes(key)
    ) && keys.every((key) => Object.hasOwn(value, key));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function deriveOperationNonce({ executionCapability, grantId }) {
  return createHmac("sha256", executionCapability)
    .update(canonicalJson({
      grantId,
      purpose: "tideproof-provider-operation-nonce-v1"
    }))
    .digest("hex");
}

function providerControlRetryable(error) {
  const code = error?.code ?? error?.cause?.code;
  return CLAIM_RETRYABLE_SQLSTATES.has(code) ||
    ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EPIPE"]
      .includes(code);
}

async function claimWithBoundedPreEffectRetry(claimControl, binding, input) {
  let lastFailure;
  for (let attempt = 1; attempt <= CLAIM_RETRY_LIMIT; attempt += 1) {
    try {
      return await claimControl.claim(binding, input);
    } catch (cause) {
      lastFailure = cause;
      if (!providerControlRetryable(cause)) throw cause;
    }
  }
  reject("INTEGRATED_LIVE_DRILL_DISPATCH_CLAIM_UNAVAILABLE", lastFailure);
}

function withReceipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: sha256(canonicalJson(body))
  });
}

function canonicalBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
}

function assertPrivateDirectory(rootPath, code) {
  requireCondition(
    typeof rootPath === "string" && path.isAbsolute(rootPath) &&
      path.resolve(rootPath) === rootPath && fs.realpathSync(rootPath) === rootPath,
    code
  );
  const stat = fs.lstatSync(rootPath);
  const expectedUid = typeof process.getuid === "function"
    ? process.getuid()
    : stat.uid;
  requireCondition(
    stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === expectedUid &&
      (stat.mode & 0o777) === 0o700,
    code
  );
  return Object.freeze({ rootPath, uid: expectedUid });
}

function assertExactFileStat(stat, { code, mode, uid }) {
  requireCondition(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
      stat.uid === uid && (stat.mode & 0o777) === mode,
    code
  );
}

function readExactFile(filePath, { code, maximumBytes, mode, uid }) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    assertExactFileStat(before, { code, mode, uid });
    requireCondition(before.size > 0 && before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(
      before.dev === after.dev && before.ino === after.ino &&
        before.size === after.size && before.mode === after.mode &&
        before.uid === after.uid && named.dev === after.dev &&
        named.ino === after.ino,
      code
    );
    return bytes;
  } catch (cause) {
    if (String(cause?.message ?? "") === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function createOrReadExact(filePath, bytes, options) {
  const result = publishOrReadExactOwnedFile({
    assertRoot: () => assertPrivateDirectory(
      options.root.rootPath,
      options.code
    ),
    bytes,
    code: options.code,
    filePath,
    maximumBytes: Math.max(bytes.length, 16 * 1024 * 1024),
    mode: options.mode,
    rootPath: options.root.rootPath,
    uid: options.root.uid
  });
  return Object.freeze({ bytes: result.bytes, created: result.created });
}

function uuidFromBytes(bytesInput) {
  const bytes = Buffer.from(bytesInput);
  requireCondition(bytes.length === 16, "INTEGRATED_LIVE_DRILL_EXECUTION_CAPABILITY_REJECTED");
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${
    hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function validateIntegratedLiveDrillDispatchBrokerRequest(value) {
  const code = "INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_REJECTED";
  requireCondition(
    exactRecord(value, [
      "binding",
      "packageLockDigest",
      "schemaVersion",
      "workerInput",
      "workerSpecSha256"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_SCHEMA &&
      PROVIDER_DISPATCH_HEX_64.test(value.packageLockDigest ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(value.workerSpecSha256 ?? "") &&
      value.workerSpecSha256 === sha256(canonicalJson(value.workerInput)),
    code
  );
  return Object.freeze({
    binding: validateProviderDispatchControlBinding(value.binding),
    packageLockDigest: value.packageLockDigest,
    schemaVersion: value.schemaVersion,
    workerInput: value.workerInput,
    workerSpecSha256: value.workerSpecSha256
  });
}

export function dispatchBrokerRequestFromOrchestrationRequest(value) {
  const code = "INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_REJECTED";
  requireCondition(
    exactRecord(value, [
      "binding",
      "packageLockDigest",
      "receiptSha256",
      "schemaVersion",
      "workerInput",
      "workerSpecSha256"
    ]) &&
      value.schemaVersion ===
        "tideproof.highwater-drill-provider-dispatch-request.v1" &&
      PROVIDER_DISPATCH_HEX_64.test(value.receiptSha256 ?? "") &&
      sha256(canonicalJson(Object.fromEntries(
        Object.entries(value).filter(([key]) => key !== "receiptSha256")
      ))) === value.receiptSha256 &&
      sha256(canonicalJson(value.workerInput)) === value.workerSpecSha256,
    code
  );
  return validateIntegratedLiveDrillDispatchBrokerRequest(Object.freeze({
    binding: value.binding,
    packageLockDigest: value.packageLockDigest,
    schemaVersion: INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_SCHEMA,
    workerInput: value.workerInput,
    workerSpecSha256: value.workerSpecSha256
  }));
}

export function validateIntegratedLiveDrillExecutionGrant(value) {
  const code = "INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_REJECTED";
  requireCondition(
    exactRecord(value, [
      "authorizationId",
      "controlBindingSha256",
      "executionCapabilitySha256",
      "grantId",
      "operationNonceSha256",
      "receiptSha256",
      "requestSha256",
      "schemaVersion",
      "state",
      "workerSpecSha256"
    ]) &&
      value.schemaVersion === INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA &&
      PROVIDER_DISPATCH_UUID.test(value.authorizationId ?? "") &&
      PROVIDER_DISPATCH_UUID.test(value.grantId ?? "") &&
      [
        value.controlBindingSha256,
        value.executionCapabilitySha256,
        value.operationNonceSha256,
        value.receiptSha256,
        value.requestSha256,
        value.workerSpecSha256
      ].every((entry) => PROVIDER_DISPATCH_HEX_64.test(entry ?? "")) &&
      value.state === PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING,
    code
  );
  const { receiptSha256, ...body } = value;
  requireCondition(sha256(canonicalJson(body)) === receiptSha256, code);
  return Object.freeze({ ...value });
}

export function readIntegratedLiveDrillExecutionGrant({ filePath, uid }) {
  const code = "INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_REJECTED";
  let value;
  try {
    value = JSON.parse(readExactFile(filePath, {
      code,
      maximumBytes: 16 * 1024,
      mode: 0o600,
      uid
    }).toString("utf8"));
  } catch (cause) {
    if (String(cause?.message ?? "") === code) throw cause;
    reject(code, cause);
  }
  return validateIntegratedLiveDrillExecutionGrant(value);
}

export function readIntegratedLiveDrillDispatchBrokerRequest({
  filePath,
  uid = typeof process.getuid === "function" ? process.getuid() : 0
}) {
  const code = "INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REQUEST_REJECTED";
  let parsed;
  try {
    parsed = JSON.parse(readExactFile(filePath, {
      code,
      maximumBytes: MAX_REQUEST_BYTES,
      mode: 0o600,
      uid
    }).toString("utf8"));
  } catch (cause) {
    if (String(cause?.message ?? "") === code) throw cause;
    reject(code, cause);
  }
  return validateIntegratedLiveDrillDispatchBrokerRequest(parsed);
}

export function readIntegratedLiveDrillExecutionCapability({
  authorizationId,
  brokerRootPath
}) {
  const code = "INTEGRATED_LIVE_DRILL_EXECUTION_CAPABILITY_REJECTED";
  requireCondition(PROVIDER_DISPATCH_UUID.test(authorizationId ?? ""), code);
  const root = assertPrivateDirectory(brokerRootPath, code);
  const bytes = readExactFile(
    path.join(root.rootPath, CAPABILITY_FILE_NAME),
    { code, maximumBytes: 256, mode: 0o600, uid: root.uid }
  );
  let secret;
  try {
    secret = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(
    exactRecord(secret, ["executionCapability", "grantId"]) &&
      PROVIDER_DISPATCH_HEX_64.test(secret.executionCapability ?? "") &&
      PROVIDER_DISPATCH_UUID.test(secret.grantId ?? "") &&
      canonicalBytes(secret).equals(bytes),
    code
  );
  return Object.freeze({ ...secret });
}

export function readIntegratedLiveDrillOperationNonce({ brokerRootPath }) {
  const code = "INTEGRATED_LIVE_DRILL_OPERATION_NONCE_REJECTED";
  const root = assertPrivateDirectory(brokerRootPath, code);
  const value = readExactFile(
    path.join(root.rootPath, OPERATION_NONCE_FILE_NAME),
    { code, maximumBytes: 66, mode: 0o600, uid: root.uid }
  ).toString("utf8");
  requireCondition(/^[0-9a-f]{64}\n$/u.test(value), code);
  return value.slice(0, -1);
}

function createOrReadExecutionCapability({
  authorizationId,
  brokerRootPath,
  randomBytesImpl
}) {
  const code = "INTEGRATED_LIVE_DRILL_EXECUTION_CAPABILITY_REJECTED";
  const root = assertPrivateDirectory(brokerRootPath, code);
  requireCondition(PROVIDER_DISPATCH_UUID.test(authorizationId ?? ""), code);
  const filePath = path.join(
    root.rootPath,
    CAPABILITY_FILE_NAME
  );
  if (!fs.existsSync(filePath)) {
    const candidate = randomBytesImpl(48);
    requireCondition(Buffer.isBuffer(candidate) && candidate.length === 48, code);
    const secret = Object.freeze({
      executionCapability: candidate.subarray(0, 32).toString("hex"),
      grantId: uuidFromBytes(candidate.subarray(32))
    });
    try {
      createOrReadExact(filePath, canonicalBytes(secret), {
        code,
        mode: 0o600,
        root
      });
    } catch (cause) {
      if (!fs.existsSync(filePath)) throw cause;
    }
  }
  const secret = readIntegratedLiveDrillExecutionCapability({
    authorizationId,
    brokerRootPath
  });
  const operationNonce = deriveOperationNonce(secret);
  createOrReadExact(
    path.join(root.rootPath, OPERATION_NONCE_FILE_NAME),
    Buffer.from(`${operationNonce}\n`, "utf8"),
    { code, mode: 0o600, root }
  );
  return Object.freeze({
    executionCapability: secret.executionCapability,
    executionCapabilityPath: filePath,
    executionCapabilitySha256: sha256(secret.executionCapability),
    grantId: secret.grantId,
    operationNonce,
    operationNoncePath: path.join(root.rootPath, OPERATION_NONCE_FILE_NAME),
    operationNonceSha256: sha256(operationNonce)
  });
}

export async function runIntegratedLiveDrillDispatchBroker({
  beginControl,
  brokerRootPath,
  claimControl,
  executionGrantPath,
  executionGrantRootPath,
  providerWorkerInputPath = path.join(
    executionGrantRootPath,
    "provider-worker-input.json"
  ),
  reconciliationInputRootPath = executionGrantRootPath,
  providerReconciliationInputPath = path.join(
    reconciliationInputRootPath,
    "provider-reconciliation-input.json"
  ),
  randomBytesImpl = randomBytes,
  request
}) {
  const code = "INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_REJECTED";
  const accepted = validateIntegratedLiveDrillDispatchBrokerRequest(request);
  requireCondition(
    typeof claimControl?.claim === "function" &&
      typeof beginControl?.begin === "function" &&
      typeof randomBytesImpl === "function",
    code
  );
  const publicRoot = assertPrivateDirectory(executionGrantRootPath, code);
  const reconciliationRoot = reconciliationInputRootPath ===
    executionGrantRootPath
    ? publicRoot
    : assertPrivateDirectory(reconciliationInputRootPath, code);
  requireCondition(path.dirname(executionGrantPath) === publicRoot.rootPath, code);
  requireCondition(
    path.dirname(providerWorkerInputPath) === publicRoot.rootPath &&
      path.dirname(providerReconciliationInputPath) ===
        reconciliationRoot.rootPath,
    code
  );
  const requestSha256 = sha256(canonicalJson(accepted));
  const local = createOrReadExecutionCapability({
    authorizationId: accepted.binding.authorizationId,
    brokerRootPath,
    randomBytesImpl
  });
  const claim = await claimWithBoundedPreEffectRetry(
    claimControl,
    accepted.binding,
    {
    executionCapabilitySha256: local.executionCapabilitySha256,
    grantId: local.grantId,
    workerSpecSha256: accepted.workerSpecSha256
    }
  );
  const ownsGrant = claim.grantId === local.grantId &&
    claim.workerSpecSha256 === accepted.workerSpecSha256 &&
    claim.controlBindingSha256 === accepted.binding.controlBindingSha256;
  if (
    !ownsGrant || claim.state === PROVIDER_DISPATCH_CONTROL_STATES.EXPIRED ||
    claim.transitionOutcome === "AUTHORITY_NOT_CURRENT"
  ) {
    const body = Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_RECEIPT_SCHEMA,
      authorizationId: accepted.binding.authorizationId,
      controlBindingSha256: accepted.binding.controlBindingSha256,
      executionGrantCreated: false,
      grantId: null,
      providerCredentialPresent: false,
      requestSha256,
      state: claim.state,
      status: "NOT_SELECTED",
      transitionOutcome: claim.transitionOutcome,
      workerSpecSha256: accepted.workerSpecSha256
    });
    return withReceipt(body);
  }
  let begun;
  try {
    begun = await beginControl.begin(accepted.binding, {
      executionCapability: local.executionCapability,
      grantId: local.grantId,
      workerSpecSha256: accepted.workerSpecSha256
    });
  } catch (cause) {
    // A BEGIN acknowledgement can be ambiguous. It is never safe to retry
    // BEGIN here because EXECUTING is the provider-effect no-retry boundary.
    reject("INTEGRATED_LIVE_DRILL_DISPATCH_BEGIN_AMBIGUOUS", cause);
  }
  requireCondition(
    begun.state === PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING &&
      ["EXECUTION_STARTED", "ALREADY_EXECUTING_DO_NOT_START"]
        .includes(begun.transitionOutcome) &&
      begun.grantId === local.grantId &&
      begun.workerSpecSha256 === accepted.workerSpecSha256,
    code
  );
  const executionGrant = validateIntegratedLiveDrillExecutionGrant(withReceipt(
    Object.freeze({
      schemaVersion: INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA,
      authorizationId: accepted.binding.authorizationId,
      controlBindingSha256: accepted.binding.controlBindingSha256,
      executionCapabilitySha256: local.executionCapabilitySha256,
      grantId: local.grantId,
      operationNonceSha256: local.operationNonceSha256,
      requestSha256,
      state: PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING,
      workerSpecSha256: accepted.workerSpecSha256
    })
  ));
  const persisted = createOrReadExact(
    executionGrantPath,
    canonicalBytes(executionGrant),
    { code, mode: 0o600, root: publicRoot }
  );
  requireCondition(
    canonicalBytes(executionGrant).equals(persisted.bytes),
    code
  );
  const providerWorkerInput = Object.freeze({
    ...accepted.workerInput,
    executionGrant,
    schemaVersion: "tideproof.highwater-drill-provider-worker-input.v3"
  });
  createOrReadExact(
    providerWorkerInputPath,
    canonicalBytes(providerWorkerInput),
    { code, mode: 0o600, root: publicRoot }
  );
  const providerReconciliationInput = buildProviderDispatchReconciliationInput({
    binding: accepted.binding,
    grantId: local.grantId,
    packageLockDigest: accepted.packageLockDigest,
    workerSpecSha256: accepted.workerSpecSha256
  });
  createOrReadExact(
    providerReconciliationInputPath,
    providerDispatchReconciliationInputBytes(providerReconciliationInput),
    { code, mode: 0o600, root: reconciliationRoot }
  );
  const body = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_DISPATCH_BROKER_RECEIPT_SCHEMA,
    authorizationId: accepted.binding.authorizationId,
    controlBindingSha256: accepted.binding.controlBindingSha256,
    executionGrantCreated: persisted.created,
    grantId: local.grantId,
    providerCredentialPresent: false,
    requestSha256,
    state: PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING,
    status: "EXECUTION_GRANTED",
    transitionOutcome: begun.transitionOutcome,
    workerSpecSha256: accepted.workerSpecSha256
  });
  return withReceipt(body);
}

export const __test = Object.freeze({
  CAPABILITY_FILE_NAME,
  OPERATION_NONCE_FILE_NAME,
  CLAIM_RETRY_LIMIT,
  providerControlRetryable,
  uuidFromBytes
});
