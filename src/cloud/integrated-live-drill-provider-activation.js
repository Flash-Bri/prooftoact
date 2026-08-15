import { createHash } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";
import {
  PROVIDER_DISPATCH_CONTROL_STATES,
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_SCHEMA =
  "tideproof.provider-activation-request.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RECEIPT_SCHEMA =
  "tideproof.provider-activation-receipt.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_INPUT_SCHEMA =
  "tideproof.provider-exchange-input.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_REQUEST_SCHEMA =
  "tideproof.provider-exchange-request.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_READY_SCHEMA =
  "tideproof.provider-exchange-ready.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_SCHEMA =
  "tideproof.provider-exchange-result.v1";
export const INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_SCHEMA =
  "tideproof.provider-operation-broker-request.v1";
const INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA =
  "tideproof.integrated-live-drill-execution-grant.v1";

const ACTIVATION_RECEIPT_KEYS = Object.freeze([
  "activatedAt",
  "activationDisposition",
  "activationRequestSha256",
  "authorizationId",
  "controlBindingSha256",
  "databaseNow",
  "expiresAt",
  "grantId",
  "receiptSha256",
  "schemaVersion",
  "state",
  "transitionOutcome",
  "workerSpecSha256"
]);
const RESULT_KEYS = Object.freeze([
  "rawResult",
  "semanticRequestEvidence",
  "transportEvidence"
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

function receipt(body) {
  return Object.freeze({
    ...body,
    receiptSha256: sha256(canonicalJson(body))
  });
}

export function validateIntegratedLiveDrillProviderExecutionGrant(value) {
  const code = "INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_REJECTED";
  requireCondition(
    exactRecord(value, [
      "authorizationId", "controlBindingSha256", "executionCapabilitySha256",
      "grantId", "operationNonceSha256", "receiptSha256", "requestSha256",
      "schemaVersion", "state", "workerSpecSha256"
    ]) &&
      value.schemaVersion === INTEGRATED_LIVE_DRILL_EXECUTION_GRANT_SCHEMA &&
      PROVIDER_DISPATCH_UUID.test(value.authorizationId ?? "") &&
      PROVIDER_DISPATCH_UUID.test(value.grantId ?? "") &&
      [
        value.controlBindingSha256, value.executionCapabilitySha256,
        value.operationNonceSha256, value.receiptSha256,
        value.requestSha256, value.workerSpecSha256
      ].every((entry) => PROVIDER_DISPATCH_HEX_64.test(entry ?? "")) &&
      value.state === PROVIDER_DISPATCH_CONTROL_STATES.EXECUTING,
    code
  );
  const { receiptSha256, ...body } = value;
  requireCondition(sha256(canonicalJson(body)) === receiptSha256, code);
  return Object.freeze({ ...value });
}

export function validateIntegratedLiveDrillProviderActivationWorkerRequest(
  value
) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_REJECTED";
  requireCondition(
    exactRecord(value, [
      "action",
      "binding",
      "executionGrant",
      "operationNonce",
      "payload",
      "schemaVersion"
    ]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_OPERATION_REQUEST_SCHEMA &&
      value.action === "EXECUTE" &&
      PROVIDER_DISPATCH_HEX_64.test(value.operationNonce ?? "") &&
      exactRecord(value.payload, ["clusterId", "database", "query"]) &&
      PROVIDER_DISPATCH_UUID.test(value.payload.clusterId ?? "") &&
      value.payload.database === "tideproof_recovery" &&
      typeof value.payload.query === "string" &&
      value.payload.query.length > 0 && value.payload.query.length <= 1024 * 1024,
    code
  );
  const binding = validateProviderDispatchControlBinding(value.binding);
  const executionGrant = validateIntegratedLiveDrillProviderExecutionGrant(
    value.executionGrant
  );
  requireCondition(
    binding.authorizationId === executionGrant.authorizationId &&
      binding.controlBindingSha256 === executionGrant.controlBindingSha256 &&
      sha256(value.operationNonce) === executionGrant.operationNonceSha256,
    code
  );
  return Object.freeze({
    ...value,
    binding,
    executionGrant,
    payload: Object.freeze({ ...value.payload })
  });
}

export function providerActivationRequestBytes(envelopeInput) {
  const envelope = validateIntegratedLiveDrillProviderActivationEnvelope(
    envelopeInput
  );
  return Buffer.from(`${canonicalJson(envelope)}\n`, "utf8");
}

export function validateIntegratedLiveDrillProviderActivationEnvelope(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_REJECTED";
  requireCondition(
    exactRecord(value, ["packageLockDigest", "request", "schemaVersion"]) &&
      value.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_REQUEST_SCHEMA &&
      PROVIDER_DISPATCH_HEX_64.test(value.packageLockDigest ?? ""),
    code
  );
  return Object.freeze({
    packageLockDigest: value.packageLockDigest,
    request: validateIntegratedLiveDrillProviderActivationWorkerRequest(
      value.request
    ),
    schemaVersion: value.schemaVersion
  });
}

export function validateIntegratedLiveDrillProviderActivationReceipt(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RECEIPT_REJECTED";
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactRecord(value, ACTIVATION_RECEIPT_KEYS) &&
      body.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RECEIPT_SCHEMA &&
      body.activationDisposition === "DELIVER_CREDENTIAL_ONCE" &&
      body.transitionOutcome === "ACTIVATION_GRANTED" &&
      body.state === PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED &&
      PROVIDER_DISPATCH_HEX_64.test(body.activationRequestSha256 ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(body.controlBindingSha256 ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(body.workerSpecSha256 ?? "") &&
      PROVIDER_DISPATCH_UUID.test(body.authorizationId ?? "") &&
      PROVIDER_DISPATCH_UUID.test(body.grantId ?? "") &&
      Number.isFinite(Date.parse(body.activatedAt ?? "")) &&
      Number.isFinite(Date.parse(body.databaseNow ?? "")) &&
      Number.isFinite(Date.parse(body.expiresAt ?? "")) &&
      body.activatedAt === body.databaseNow &&
      Date.parse(body.activatedAt) < Date.parse(body.expiresAt) &&
      receiptSha256 === sha256(canonicalJson(body)),
    code
  );
  return Object.freeze({ ...body, receiptSha256 });
}

export function validateIntegratedLiveDrillProviderExchangeInput(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_INPUT_REJECTED";
  requireCondition(
    exactRecord(value, [
      "activationReceipt", "providerRequest", "schemaVersion"
    ]) &&
      value.schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_INPUT_SCHEMA,
    code
  );
  const activationReceipt =
    validateIntegratedLiveDrillProviderActivationReceipt(
      value.activationReceipt
    );
  const providerRequest = value.providerRequest;
  requireCondition(
    exactRecord(providerRequest, [
      "binding", "grantId", "packageLockDigest", "payload", "schemaVersion",
      "workerSpecSha256"
    ]) &&
      providerRequest.schemaVersion ===
        INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_REQUEST_SCHEMA &&
      exactRecord(providerRequest.payload, ["clusterId", "database", "query"]) &&
      PROVIDER_DISPATCH_UUID.test(providerRequest.payload.clusterId ?? "") &&
      providerRequest.payload.database === "tideproof_recovery" &&
      typeof providerRequest.payload.query === "string" &&
      providerRequest.payload.query.length > 0 &&
      providerRequest.payload.query.length <= 1024 * 1024 &&
      PROVIDER_DISPATCH_UUID.test(providerRequest.grantId ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(providerRequest.packageLockDigest ?? "") &&
      PROVIDER_DISPATCH_HEX_64.test(providerRequest.workerSpecSha256 ?? ""),
    code
  );
  const binding = validateProviderDispatchControlBinding(providerRequest.binding);
  requireCondition(
      activationReceipt.authorizationId === binding.authorizationId &&
      activationReceipt.controlBindingSha256 ===
        binding.controlBindingSha256 &&
      activationReceipt.expiresAt === binding.expiresAt &&
      activationReceipt.grantId === providerRequest.grantId &&
      activationReceipt.workerSpecSha256 ===
        providerRequest.workerSpecSha256,
    code
  );
  return Object.freeze({
    activationReceipt,
    providerRequest: Object.freeze({
      ...providerRequest,
      binding,
      payload: Object.freeze({ ...providerRequest.payload })
    }),
    schemaVersion: value.schemaVersion
  });
}

export function providerExchangeInputBytes(value) {
  const accepted = validateIntegratedLiveDrillProviderExchangeInput(value);
  return Buffer.from(`${canonicalJson(accepted)}\n`, "utf8");
}

export function buildIntegratedLiveDrillProviderResult({
  activationReceipt,
  result
}) {
  const acceptedReceipt = validateIntegratedLiveDrillProviderActivationReceipt(
    activationReceipt
  );
  requireCondition(
    exactRecord(result, RESULT_KEYS),
    "INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_REJECTED"
  );
  const body = Object.freeze({
    activationReceiptSha256: acceptedReceipt.receiptSha256,
    activationRequestSha256: acceptedReceipt.activationRequestSha256,
    result: Object.freeze({ ...result }),
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_SCHEMA
  });
  return receipt(body);
}

export function validateIntegratedLiveDrillProviderResult(value, {
  activationReceipt
}) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_REJECTED";
  const acceptedReceipt = validateIntegratedLiveDrillProviderActivationReceipt(
    activationReceipt
  );
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactRecord(value, [
      "activationReceiptSha256", "activationRequestSha256", "receiptSha256",
      "result", "schemaVersion"
    ]) &&
      body.schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_RESULT_SCHEMA &&
      body.activationReceiptSha256 ===
        acceptedReceipt.receiptSha256 &&
      body.activationRequestSha256 ===
        acceptedReceipt.activationRequestSha256 &&
      exactRecord(body.result, RESULT_KEYS) &&
      receiptSha256 === sha256(canonicalJson(body)),
    code
  );
  return Object.freeze({ ...body, receiptSha256 });
}

export async function runIntegratedLiveDrillProviderActivation({
  activateControl,
  envelope
}) {
  requireCondition(
    typeof activateControl?.activate === "function",
    "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_INPUT_REJECTED"
  );
  const accepted = validateIntegratedLiveDrillProviderActivationEnvelope(
    envelope
  );
  const request = accepted.request;
  const activationRequestSha256 = sha256(canonicalJson(accepted));
  const result = await activateControl.activate(request.binding, {
    activationRequestSha256,
    grantId: request.executionGrant.grantId,
    workerSpecSha256: request.executionGrant.workerSpecSha256
  });
  requireCondition(
    result.activationDisposition === "DELIVER_CREDENTIAL_ONCE" &&
      result.transitionOutcome === "ACTIVATION_GRANTED" &&
      result.state === PROVIDER_DISPATCH_CONTROL_STATES.CREDENTIAL_REDEEMED,
    "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_NOT_GRANTED"
  );
  const activationReceipt = receipt(Object.freeze({
    activatedAt: result.activatedAt,
    activationDisposition: result.activationDisposition,
    activationRequestSha256,
    authorizationId: request.binding.authorizationId,
    controlBindingSha256: request.binding.controlBindingSha256,
    databaseNow: result.databaseNow,
    expiresAt: request.binding.expiresAt,
    grantId: request.executionGrant.grantId,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_RECEIPT_SCHEMA,
    state: result.state,
    transitionOutcome: result.transitionOutcome,
    workerSpecSha256: request.executionGrant.workerSpecSha256
  }));
  validateIntegratedLiveDrillProviderActivationReceipt(activationReceipt);
  const exchangeInput = Object.freeze({
    activationReceipt,
    providerRequest: Object.freeze({
      binding: request.binding,
      grantId: request.executionGrant.grantId,
      packageLockDigest: accepted.packageLockDigest,
      payload: request.payload,
      schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_REQUEST_SCHEMA,
      workerSpecSha256: request.executionGrant.workerSpecSha256
    }),
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_EXCHANGE_INPUT_SCHEMA
  });
  validateIntegratedLiveDrillProviderExchangeInput(exchangeInput);
  return Object.freeze({ activationReceipt, exchangeInput });
}

export function buildIntegratedLiveDrillProviderReady(activationReceipt) {
  const accepted = validateIntegratedLiveDrillProviderActivationReceipt(
    activationReceipt
  );
  const body = Object.freeze({
    activationReceipt: accepted,
    activationRequestSha256: accepted.activationRequestSha256,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_READY_SCHEMA
  });
  return receipt(body);
}

export function validateIntegratedLiveDrillProviderReady(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_READY_REJECTED";
  const { receiptSha256, ...body } = value ?? {};
  requireCondition(
    exactRecord(value, [
      "activationReceipt", "activationRequestSha256", "receiptSha256",
      "schemaVersion"
    ]) && body.schemaVersion === INTEGRATED_LIVE_DRILL_PROVIDER_READY_SCHEMA &&
      PROVIDER_DISPATCH_HEX_64.test(body.activationRequestSha256 ?? "") &&
      receiptSha256 === sha256(canonicalJson(body)),
    code
  );
  const activationReceipt =
    validateIntegratedLiveDrillProviderActivationReceipt(
      body.activationReceipt
    );
  requireCondition(
    body.activationRequestSha256 ===
      activationReceipt.activationRequestSha256,
    code
  );
  return Object.freeze({ ...body, activationReceipt, receiptSha256 });
}

export const __test = Object.freeze({ exactRecord, receipt, sha256 });
