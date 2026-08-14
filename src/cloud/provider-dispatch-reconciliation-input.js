import {
  PROVIDER_DISPATCH_HEX_64,
  PROVIDER_DISPATCH_UUID,
  providerDispatchSha256,
  validateProviderDispatchControlBinding
} from "./provider-dispatch-binding.js";
import { canonicalJson } from "./canonical-json.js";

export const INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA =
  "tideproof.highwater-drill-provider-reconciliation-input.v3";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    Reflect.ownKeys(value).every((key) =>
      typeof key === "string" && keys.includes(key)
    ) && keys.every((key) => Object.hasOwn(value, key));
}

export function validateProviderDispatchReconciliationInput(value) {
  const code = "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_REJECTED";
  if (
    !exactRecord(value, [
      "admission",
      "binding",
      "packageLockDigest",
      "receiptSha256",
      "schemaVersion"
    ]) ||
    value.schemaVersion !==
      INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA ||
    !exactRecord(value.admission, ["grantId", "workerSpecSha256"]) ||
    !PROVIDER_DISPATCH_UUID.test(value.admission.grantId ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(
      value.admission.workerSpecSha256 ?? ""
    ) ||
    !PROVIDER_DISPATCH_HEX_64.test(value.packageLockDigest ?? "") ||
    !PROVIDER_DISPATCH_HEX_64.test(value.receiptSha256 ?? "")
  ) {
    reject(code);
  }
  let binding;
  try {
    binding = validateProviderDispatchControlBinding(value.binding);
  } catch (cause) {
    reject(code, cause);
  }
  const accepted = Object.freeze({
    admission: Object.freeze({ ...value.admission }),
    binding,
    packageLockDigest: value.packageLockDigest,
    receiptSha256: value.receiptSha256,
    schemaVersion: value.schemaVersion
  });
  const { receiptSha256, ...body } = accepted;
  if (providerDispatchSha256(canonicalJson(body)) !== receiptSha256) {
    reject(code);
  }
  return accepted;
}

export function buildProviderDispatchReconciliationInput({
  binding,
  grantId,
  packageLockDigest,
  workerSpecSha256
}) {
  const body = Object.freeze({
    admission: Object.freeze({ grantId, workerSpecSha256 }),
    binding,
    packageLockDigest,
    schemaVersion: INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_INPUT_SCHEMA
  });
  return validateProviderDispatchReconciliationInput(Object.freeze({
    ...body,
    receiptSha256: providerDispatchSha256(canonicalJson(body))
  }));
}

export function providerDispatchReconciliationInputBytes(value) {
  return Buffer.from(
    `${canonicalJson(validateProviderDispatchReconciliationInput(value))}\n`,
    "utf8"
  );
}
