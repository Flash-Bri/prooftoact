import crypto from "node:crypto";

const SCHEMA_VERSION =
  "prooftoact.b0-a1-human-authorization-contract.v1";
const RECEIPT_SCHEMA_VERSION =
  "prooftoact.b0-a1-human-authorization-receipt-binding.v1";
const CLUSTER_MODE = "ADOPT_VERIFIED_EXISTING";

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && [Object.prototype, null].includes(
      Object.getPrototypeOf(value)
    );
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
    typeof value === "number" && Number.isSafeInteger(value),
  "PROOFTOACT_B0_A1_AUTHORIZATION_CANONICAL_REJECTED");
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function deepFreeze(value) {
  if (Array.isArray(value)) {
    value.forEach(deepFreeze);
    return Object.freeze(value);
  }
  if (plainObject(value)) {
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
  }
  return value;
}

export const PROOFTOACT_B0_ACTIONS = deepFreeze([
  "AWS_ROOT_MFA_DISCOVERY_AND_READBACK",
  "CREATE_TAG_AND_INLINE_POLICY_ONE_TEMPORARY_B0_ROLE",
  "ASSUME_EXACT_900_SECOND_B0_AND_WRITER_SESSIONS",
  "CREATE_AND_EXECUTE_THREE_EXACT_CREATE_CHANGE_SETS",
  "ENABLE_TERMINATION_PROTECTION_ON_EXACT_STACK_IDS",
  "SEAL_EXACTLY_FIVE_PREAUTHORIZED_SECRET_VERSIONS",
  "READ_BACK_EXACT_STACK_ROLE_SECRET_AND_CLOUDTRAIL_POSTURE",
  "DELETE_EXACT_TEMPORARY_B0_INLINE_POLICY_AND_ROLE",
  "LOG_OUT_THE_NAMED_ROOT_SESSION"
]);

export const PROOFTOACT_A1_ACTIONS = deepFreeze([
  "DDB_RESERVE_ONE_IMMUTABLE_SOURCE_AND_OPERATION",
  "ADOPT_ONE_VERIFIED_EXISTING_COCKROACH_CLUSTER",
  "ADD_AND_DELETE_ONE_SQL_ONLY_RUNNER_IPV4_32",
  "SEAL_ONE_IMMUTABLE_BOOTSTRAP_ADMIN_SECRET_VERSION",
  "CREATE_AND_DELETE_ONE_BOOTSTRAP_SQL_ADMIN",
  "BOOTSTRAP_EXACT_14_RUNTIME_PRINCIPALS_AND_NOLOGIN_POSTURE",
  "EXECUTE_REAL_DVI_PLAN_AND_SERIALIZABLE_ONE_WINNER_RACE",
  "SEAL_AND_USE_ONE_RECOVERY_SIGNER",
  "APPEND_ONE_SIGNED_RECOVERY_BUNDLE",
  "EXECUTE_ONE_FIXED_MANAGED_MCP_SELECT_QUERY",
  "DDB_APPEND_TRANSITIONS_AND_FINALIZE_OR_TERMINALIZE",
  "READ_ONLY_RECONCILIATION_AND_EXACT_ACCESS_CLEANUP"
]);

export const PROOFTOACT_EXCLUDED_ACTIONS = deepFreeze([
  "CREATE_A_NEW_COCKROACH_CLUSTER",
  "DELETE_ANY_COCKROACH_CLUSTER",
  "DELETE_OR_ROTATE_CREATOR_OR_AUDITOR_PROVIDER_KEYS",
  "RETAIN_PROVIDER_KEYS_AS_PUBLIC_RUNTIME_CREDENTIALS",
  "MAKE_ANY_PUBLIC_LIVE_INTEGRATION_GO_CLAIM",
  "REDISPATCH_OR_RESERVE_AFTER_THE_APPLICABLE_DEADLINE",
  "USE_ANY_DIFFERENT_SOURCE_ACCOUNT_OPERATION_TEMPLATE_OR_CREDENTIAL",
  "MAKE_PROVIDER_SERVICES_AVAILABLE_TO_OPEN_SOURCE_USERS"
]);

export const PROOFTOACT_AUTHORIZATION_ACTION_ENUMS = deepFreeze({
  a1: [...PROOFTOACT_A1_ACTIONS],
  b0: [...PROOFTOACT_B0_ACTIONS],
  excluded: [...PROOFTOACT_EXCLUDED_ACTIONS]
});

const B0_TEXT =
  "For B0, the one-hour deadline is the latest-new-dispatch boundary. No " +
  "new CreateChangeSet, ExecuteChangeSet, UpdateTerminationProtection, " +
  "PutSecretValue, AssumeRole, workload, or mutating provider API dispatch " +
  "is authorized at or after it. An exact immutable operation dispatched " +
  "before it may complete provider-side; ProofToAct may perform read-only " +
  "Describe, Get, List, and CloudTrail convergence for at most 45 minutes " +
  "and must never redispatch it.";
const A1_TEXT =
  "For A1, approval expiry is the latest-durable-outer-reservation boundary. " +
  "Only the immutable one-shot whose reservation is durably acknowledged " +
  "before expiry may continue within the fixed 45-minute workflow timeout. " +
  "No new reservation, execute rerun, or different source or operation is " +
  "authorized at or after expiry.";
const CLEANUP_TEXT =
  "Until the exact 24-hour retention deadline, cleanup may perform readback, " +
  "logout, and immutable DynamoDB audit-transition and terminal-record " +
  "writes. Its only destructive provider mutations are deletion of the " +
  "exact temporary B0 inline policy and role, the exact bootstrap SQL admin, " +
  "and the temporary SQL /32 ingress. Cleanup may not create, seal, retry an " +
  "execution operation, or broaden authority.";

export const PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT =
  "I authorize the exact ProofToAct B0 and A1 ADOPT flow for the bound " +
  "source, account, operation, caller workflow, templates, runtime, existing " +
  "CockroachDB cluster, and credential digests. I authorize up to USD 5.00 " +
  "one-time and USD 5.00 monthly for the exact B0 AWS resources, and the " +
  "CockroachDB paid worst case of USD 1.50 monthly under a USD 2.00 monthly " +
  `ceiling. ${B0_TEXT} ${A1_TEXT} ${CLEANUP_TEXT} ` +
  `The exact B0 actions are: ${PROOFTOACT_B0_ACTIONS.join(", ")}. ` +
  `The exact A1 actions are: ${PROOFTOACT_A1_ACTIONS.join(", ")}. ` +
  `The excluded actions are: ${PROOFTOACT_EXCLUDED_ACTIONS.join(", ")}. ` +
  "The temporary creator and auditor provider keys may remain only pending a " +
  "separate organization-admin revocation authorization and ceremony; no " +
  "future CockroachDB revoker is authorized here. This authorization does " +
  "not authorize a public live-integration GO claim before provider-key " +
  "revocation and the complete joined evidence pass.";

const AUTHORIZATION_BYTES = Buffer.from(
  `${PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT}\n`,
  "utf8"
);

export const PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT_SHA256 =
  sha256(AUTHORIZATION_BYTES);

export const PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT = deepFreeze({
  schemaVersion: SCHEMA_VERSION,
  actionEnums: PROOFTOACT_AUTHORIZATION_ACTION_ENUMS,
  actionEnumsSha256: digest(PROOFTOACT_AUTHORIZATION_ACTION_ENUMS),
  a1ExecutionBoundary:
    "LATEST_DURABLE_OUTER_RESERVATION_BEFORE_APPROVAL_EXPIRY",
  a1MaximumReservedExecutionMinutes: 45,
  b0ExecutionBoundary: "LATEST_NEW_DISPATCH_BEFORE_EXECUTION_DEADLINE",
  b0MaximumReadOnlyConvergenceMinutes: 45,
  clusterCreateApproved: false,
  clusterMode: CLUSTER_MODE,
  futureCockroachRevokerAuthorized: false,
  humanAuthorizedTextSha256:
    PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT_SHA256,
  publicClaimAuthorized: false
});

export const PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT_SHA256 =
  digest(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT);

export function renderProofToActB0A1HumanAuthorization() {
  return Object.freeze({
    actionEnums: PROOFTOACT_AUTHORIZATION_ACTION_ENUMS,
    actionEnumsSha256:
      PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT.actionEnumsSha256,
    authorizationContractSha256:
      PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT_SHA256,
    bytes: Buffer.from(AUTHORIZATION_BYTES),
    clusterCreateApproved: false,
    clusterMode: CLUSTER_MODE,
    futureCockroachRevokerAuthorized: false,
    publicClaimAuthorized: false,
    schemaVersion: SCHEMA_VERSION,
    sha256: PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT_SHA256,
    text: PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT
  });
}

export function validateProofToActB0A1HumanAuthorizationBytes(value) {
  const code = "PROOFTOACT_B0_A1_AUTHORIZATION_BYTES_REJECTED";
  requireCondition(Buffer.isBuffer(value) &&
    value.equals(AUTHORIZATION_BYTES) &&
    value.at(-1) === 0x0a && value.at(-2) !== 0x0a &&
    sha256(value) === PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT_SHA256,
  code);
  return renderProofToActB0A1HumanAuthorization();
}

export function buildProofToActB0A1HumanAuthorizationReceiptBinding() {
  const rendered = renderProofToActB0A1HumanAuthorization();
  const body = {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    actionEnums: rendered.actionEnums,
    actionEnumsSha256: rendered.actionEnumsSha256,
    authorizationContractSha256: rendered.authorizationContractSha256,
    clusterCreateApproved: false,
    clusterMode: CLUSTER_MODE,
    futureCockroachRevokerAuthorized: false,
    humanAuthorizedText: rendered.text,
    humanAuthorizedTextSha256: rendered.sha256,
    publicClaimAuthorized: false
  };
  return deepFreeze({ ...body, receiptBindingSha256: digest(body) });
}

export function validateProofToActB0A1HumanAuthorizationReceipt(value) {
  const code = "PROOFTOACT_B0_A1_AUTHORIZATION_RECEIPT_REJECTED";
  const expected = buildProofToActB0A1HumanAuthorizationReceiptBinding();
  requireCondition(exactKeys(value, [
    "actionEnums",
    "actionEnumsSha256",
    "authorizationContractSha256",
    "clusterCreateApproved",
    "clusterMode",
    "futureCockroachRevokerAuthorized",
    "humanAuthorizedText",
    "humanAuthorizedTextSha256",
    "publicClaimAuthorized",
    "receiptBindingSha256",
    "schemaVersion"
  ]) && canonicalJson(value) === canonicalJson(expected), code);
  validateProofToActB0A1HumanAuthorizationBytes(Buffer.from(
    `${value.humanAuthorizedText}\n`, "utf8"
  ));
  return expected;
}

export const __test = Object.freeze({ canonicalJson, digest, sha256 });
