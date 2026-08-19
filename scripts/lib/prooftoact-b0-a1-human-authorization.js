import crypto from "node:crypto";

const DYNAMIC_INTENT_SCHEMA_VERSION =
  "prooftoact.b0-a1-dynamic-authorization-intent.v4";
const RECEIPT_SCHEMA_VERSION =
  "prooftoact.b0-a1-human-authorization-receipt-binding.v4";
const EVIDENCE_SCHEMA_VERSION =
  "prooftoact.external-human-authorization-evidence.v4";
const CONTRACT_SCHEMA_VERSION =
  "prooftoact.b0-a1-human-authorization-contract.v4";
const SIGNATURE_PAYLOAD_SCHEMA_VERSION =
  "prooftoact.external-human-authorization-signature-payload.v1";
const CLUSTER_MODE = "ADOPT_VERIFIED_EXISTING";
const ACCOUNT_ID = /^[0-9]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SQL_CLUSTER_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const CALLER_WORKFLOW_REF =
  "Flash-Bri/prooftoact/.github/workflows/" +
  "prooftoact-fresh-primary.yml@refs/heads/main";
const TARGET_TEMPLATE_KEYS = Object.freeze([
  "freshPrimaryBootstrapRole",
  "freshPrimaryCredentialCustody",
  "privateRecoveryQueryBootstrap"
]);
const PRIVATE_RECOVERY_WORKFLOW_KEYS = Object.freeze([
  "deployment",
  "secretSeal"
]);
const WRITER_VALUE_KEYS = Object.freeze([
  "auditor",
  "cloudApi",
  "credential",
  "mcp",
  "publisher"
]);
const A1_CREDENTIAL_KEYS = Object.freeze([
  "adoptedAdminPassword",
  "auditorTokenValue",
  "creatorTokenValue"
]);
const A1_PROVIDER_RECEIPT_KEYS = Object.freeze([
  "auditorAuthority",
  "creatorAuthority",
  "creatorProviderReadback",
  "manualCluster",
  "pricingSource"
]);
const COST_KEYS = Object.freeze([
  "awsMonthlyResidualCeilingUsdCents",
  "cockroachMonthlySubCeilingUsdCents",
  "cockroachPaidWorstCaseMonthlyUsdCents",
  "combinedMonthlyCeilingUsdCents",
  "currency",
  "freeBenefitsAssumed",
  "maximumOneTimeUsdCents",
  "noAdditiveMonthlyCeilings",
  "reconciliationReceiptSha256"
]);

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

export const PROOFTOACT_IMESSAGE_MATERIALIZER = deepFreeze({
  chatsInvocationSha256: digest({
    arguments: ["chats", "--limit", "200", "--json"],
    executablePath: "/opt/homebrew/bin/imsg",
    executableRealpath: "/opt/homebrew/Cellar/imsg/0.13.2/bin/imsg",
    executableSha256:
      "c569675e9ae7b28bff572dd111df99a5633f279ee6ea14c5f769bf87309c1f43",
    version: "0.13.2"
  }),
  chatsLimit: 200,
  executablePath: "/opt/homebrew/bin/imsg",
  executableRealpath: "/opt/homebrew/Cellar/imsg/0.13.2/bin/imsg",
  executableSha256:
    "c569675e9ae7b28bff572dd111df99a5633f279ee6ea14c5f769bf87309c1f43",
  historyChatId: 1,
  version: "0.13.2"
});

export function buildProofToActImessageMaterializer(dynamicIntent) {
  const code = "PROOFTOACT_IMESSAGE_MATERIALIZER_REJECTED";
  requireCondition(plainObject(dynamicIntent), code);
  canonicalInstant(dynamicIntent.authorizationNotBefore, code);
  canonicalInstant(dynamicIntent.b0DispatchDeadline, code);
  const history = {
    end: dynamicIntent.b0DispatchDeadline,
    invocationSha256: digest({
      arguments: [
        "history", "--chat-id", "1", "--start",
        dynamicIntent.authorizationNotBefore, "--end",
        dynamicIntent.b0DispatchDeadline, "--limit", "10000", "--json"
      ],
      executablePath: PROOFTOACT_IMESSAGE_MATERIALIZER.executablePath,
      executableRealpath: PROOFTOACT_IMESSAGE_MATERIALIZER.executableRealpath,
      executableSha256: PROOFTOACT_IMESSAGE_MATERIALIZER.executableSha256,
      version: PROOFTOACT_IMESSAGE_MATERIALIZER.version
    }),
    limit: 10000,
    start: dynamicIntent.authorizationNotBefore
  };
  return deepFreeze({
    history,
    tool: PROOFTOACT_IMESSAGE_MATERIALIZER
  });
}

function canonicalInstant(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
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

function validateHexMap(value, keys, code) {
  requireCondition(exactKeys(value, keys) &&
    keys.every((key) => HEX_64.test(value[key] ?? "")), code);
  return value;
}

function validateCommitMap(value, keys, code) {
  requireCondition(exactKeys(value, keys) &&
    keys.every((key) => HEX_40.test(value[key] ?? "") &&
      value[key] !== "0".repeat(40)), code);
  return value;
}

function orderedMap(value, keys) {
  return Object.fromEntries(keys.map((key) => [key, value[key]]));
}

export const PROOFTOACT_B0_ACTIONS = deepFreeze([
  "AWS_ROOT_MFA_DISCOVERY_AND_READBACK",
  "CREATE_TAG_AND_INLINE_POLICY_ONE_TEMPORARY_B0_ROLE",
  "ASSUME_AT_MOST_TWO_NONOVERLAPPING_900_SECOND_B0_SESSIONS_AND_AT_MOST_TWO_NONOVERLAPPING_900_SECOND_WRITER_SESSIONS_REPLACEMENT_ONLY_AFTER_PRIOR_MAX_LIFETIME_AND_CLOUDTRAIL_LAG",
  "CREATE_AND_EXECUTE_THREE_EXACT_CREATE_CHANGE_SETS",
  "ENABLE_TERMINATION_PROTECTION_ON_EXACT_STACK_IDS",
  "SEAL_EXACTLY_FIVE_PREAUTHORIZED_SECRET_VERSIONS",
  "READ_BACK_EXACT_STACK_ROLE_SECRET_AND_CLOUDTRAIL_POSTURE",
  "DELETE_EXACT_TEMPORARY_B0_INLINE_POLICY_AND_ROLE",
  "LOG_OUT_THE_NAMED_ROOT_SESSION"
]);

export const PROOFTOACT_A1_ACTIONS = deepFreeze([
  "DDB_RESERVE_ONE_IMMUTABLE_SOURCE_AND_OPERATION",
  "ADOPT_AND_BOOTSTRAP_ONE_BOUND_FRESH_COCKROACH_CLUSTER",
  "ADD_AND_DELETE_ONE_SQL_ONLY_RUNNER_IPV4_32",
  "SEAL_ONE_IMMUTABLE_BOOTSTRAP_ADMIN_SECRET_VERSION",
  "CREATE_AND_DELETE_ONE_BOOTSTRAP_SQL_ADMIN",
  "CREATE_AND_USE_ONLY_EXACT_PROOFTOACT_DATABASE_SCHEMA_TABLE_FUNCTION_INDEX_GRANT_AND_SYNTHETIC_EVIDENCE_OBJECTS",
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
  "MAKE_PROVIDER_SERVICES_AVAILABLE_TO_OPEN_SOURCE_USERS",
  "UPLOAD_DEPLOY_INVOKE_EVIDENCE_OR_TEARDOWN_THE_A2_PRIVATE_RECOVERY_LAMBDA_WITHOUT_A_SEPARATE_EXACT_AUTHORIZATION"
]);

export const PROOFTOACT_AUTHORIZATION_ACTION_ENUMS = deepFreeze({
  a1: [...PROOFTOACT_A1_ACTIONS],
  b0: [...PROOFTOACT_B0_ACTIONS],
  excluded: [...PROOFTOACT_EXCLUDED_ACTIONS]
});

export const PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT = deepFreeze({
  schemaVersion: CONTRACT_SCHEMA_VERSION,
  actionEnums: PROOFTOACT_AUTHORIZATION_ACTION_ENUMS,
  actionEnumsSha256: digest(PROOFTOACT_AUTHORIZATION_ACTION_ENUMS),
  a1ExecutionBoundary:
    "LATEST_DURABLE_OUTER_RESERVATION_BEFORE_APPROVAL_EXPIRY",
  a1MaximumReservedExecutionMinutes: 45,
  b0ExecutionBoundary: "LATEST_NEW_DISPATCH_BEFORE_EXECUTION_DEADLINE",
  b0MaximumAssumeRoleSessionsPerRole: 2,
  b0MaximumReadOnlyConvergenceMinutes: 45,
  b0ReplacementSessionRequiresPriorMaximumLifetimeAndCloudTrailLag: true,
  clusterCreateApproved: false,
  clusterMode: CLUSTER_MODE,
  combinedMonthlyCeilingUsdCents: 500,
  cockroachMonthlySubCeilingUsdCents: 200,
  cockroachPaidWorstCaseMonthlyUsdCents: 150,
  futureCockroachRevokerAuthorized: false,
  maximumOneTimeUsdCents: 500,
  noAdditiveMonthlyCeilings: true,
  publicClaimAuthorized: false
});

export const PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT_SHA256 =
  digest(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT);

function validateCostAuthorization(value, code) {
  requireCondition(exactKeys(value, COST_KEYS) &&
    value.currency === "USD" &&
    value.maximumOneTimeUsdCents === 500 &&
    value.combinedMonthlyCeilingUsdCents === 500 &&
    value.cockroachMonthlySubCeilingUsdCents === 200 &&
    value.cockroachPaidWorstCaseMonthlyUsdCents === 150 &&
    value.awsMonthlyResidualCeilingUsdCents === 350 &&
    value.noAdditiveMonthlyCeilings === true &&
    value.freeBenefitsAssumed === false &&
    value.cockroachPaidWorstCaseMonthlyUsdCents <=
      value.cockroachMonthlySubCeilingUsdCents &&
    value.cockroachMonthlySubCeilingUsdCents <=
      value.combinedMonthlyCeilingUsdCents &&
    value.awsMonthlyResidualCeilingUsdCents +
      value.cockroachPaidWorstCaseMonthlyUsdCents ===
        value.combinedMonthlyCeilingUsdCents &&
    HEX_64.test(value.reconciliationReceiptSha256 ?? ""), code);
  return value;
}

export function buildProofToActB0A1DynamicAuthorizationBinding(input) {
  const code = "PROOFTOACT_B0_A1_DYNAMIC_AUTHORIZATION_REJECTED";
  requireCondition(exactKeys(input, [
    "a1ApprovalId",
    "a1CallerWorkflowRef",
    "a1CallerWorkflowSha",
    "a1ControllerImportGraphSha256",
    "a1CredentialSha256",
    "a1ProviderClusterId",
    "a1ProviderReceiptSha256",
    "a1ReservationDeadline",
    "a1SqlClusterId",
    "accountId",
    "authorizationNotBefore",
    "b0DispatchDeadline",
    "b0PrivateRecoveryWorkflowCommits",
    "b0RuntimeExecutionBindingSha256",
    "b0TargetTemplateSha256",
    "b0WriterValueSha256",
    "cleanupRetentionDeadline",
    "costAuthorization",
    "humanAuthorizationConversationHmacSha256",
    "humanAuthorizationSignerPublicKeySha256",
    "humanAuthoritySenderHmacSha256",
    "humanIdentityHmacKeySha256",
    "humanIdentityRecordHmacSha256",
    "humanIdentityReceiptSha256",
    "operationId",
    "sourceCommit",
    "treeDigest"
  ]) && ACCOUNT_ID.test(input.accountId ?? "") &&
    UUID.test(input.operationId ?? "") &&
    UUID.test(input.a1ApprovalId ?? "") &&
    UUID.test(input.a1ProviderClusterId ?? "") &&
    SQL_CLUSTER_ID.test(input.a1SqlClusterId ?? "") &&
    input.a1ProviderClusterId !== input.a1SqlClusterId &&
    HEX_40.test(input.sourceCommit ?? "") &&
    input.sourceCommit !== "0".repeat(40) &&
    HEX_40.test(input.treeDigest ?? "") &&
    input.treeDigest !== "0".repeat(40) &&
    HEX_40.test(input.a1CallerWorkflowSha ?? "") &&
    input.a1CallerWorkflowSha !== "0".repeat(40) &&
    HEX_64.test(input.a1ControllerImportGraphSha256 ?? "") &&
    HEX_64.test(input.b0RuntimeExecutionBindingSha256 ?? "") &&
    HEX_64.test(input.humanAuthorizationConversationHmacSha256 ?? "") &&
    HEX_64.test(input.humanAuthorizationSignerPublicKeySha256 ?? "") &&
    HEX_64.test(input.humanAuthoritySenderHmacSha256 ?? "") &&
    HEX_64.test(input.humanIdentityHmacKeySha256 ?? "") &&
    HEX_64.test(input.humanIdentityRecordHmacSha256 ?? "") &&
    HEX_64.test(input.humanIdentityReceiptSha256 ?? "") &&
    input.a1CallerWorkflowRef === CALLER_WORKFLOW_REF, code);
  validateHexMap(input.b0TargetTemplateSha256, TARGET_TEMPLATE_KEYS, code);
  validateCommitMap(input.b0PrivateRecoveryWorkflowCommits,
    PRIVATE_RECOVERY_WORKFLOW_KEYS, code);
  validateHexMap(input.b0WriterValueSha256, WRITER_VALUE_KEYS, code);
  validateHexMap(input.a1CredentialSha256, A1_CREDENTIAL_KEYS, code);
  validateHexMap(input.a1ProviderReceiptSha256,
    A1_PROVIDER_RECEIPT_KEYS, code);
  validateCostAuthorization(input.costAuthorization, code);
  requireCondition(input.b0WriterValueSha256.cloudApi ===
    input.a1CredentialSha256.creatorTokenValue &&
    input.b0WriterValueSha256.auditor ===
      input.a1CredentialSha256.auditorTokenValue, code);
  const authorizationNotBefore = canonicalInstant(
    input.authorizationNotBefore,
    code
  );
  const b0Deadline = canonicalInstant(input.b0DispatchDeadline, code);
  const a1Deadline = canonicalInstant(input.a1ReservationDeadline, code);
  const cleanupDeadline = canonicalInstant(
    input.cleanupRetentionDeadline,
    code
  );
  requireCondition(b0Deadline === a1Deadline &&
    b0Deadline - authorizationNotBefore === 60 * 60 * 1000 &&
    cleanupDeadline - b0Deadline === 24 * 60 * 60 * 1000, code);
  const body = {
    schemaVersion: DYNAMIC_INTENT_SCHEMA_VERSION,
    authorizationContractSha256:
      PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT_SHA256,
    actionEnumsSha256:
      PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT.actionEnumsSha256,
    accountId: input.accountId,
    operationId: input.operationId,
    sourceCommit: input.sourceCommit,
    treeDigest: input.treeDigest,
    authorizationNotBefore: input.authorizationNotBefore,
    b0DispatchDeadline: input.b0DispatchDeadline,
    a1ReservationDeadline: input.a1ReservationDeadline,
    cleanupRetentionDeadline: input.cleanupRetentionDeadline,
    b0TargetTemplateSha256: orderedMap(
      input.b0TargetTemplateSha256,
      TARGET_TEMPLATE_KEYS
    ),
    b0PrivateRecoveryWorkflowCommits: orderedMap(
      input.b0PrivateRecoveryWorkflowCommits,
      PRIVATE_RECOVERY_WORKFLOW_KEYS
    ),
    b0RuntimeExecutionBindingSha256:
      input.b0RuntimeExecutionBindingSha256,
    b0WriterValueSha256: orderedMap(
      input.b0WriterValueSha256,
      WRITER_VALUE_KEYS
    ),
    a1ApprovalId: input.a1ApprovalId,
    a1CallerWorkflowRef: input.a1CallerWorkflowRef,
    a1CallerWorkflowSha: input.a1CallerWorkflowSha,
    a1ControllerImportGraphSha256:
      input.a1ControllerImportGraphSha256,
    a1ProviderClusterId: input.a1ProviderClusterId,
    a1SqlClusterId: input.a1SqlClusterId,
    a1CredentialSha256: orderedMap(
      input.a1CredentialSha256,
      A1_CREDENTIAL_KEYS
    ),
    a1ProviderReceiptSha256: orderedMap(
      input.a1ProviderReceiptSha256,
      A1_PROVIDER_RECEIPT_KEYS
    ),
    costAuthorization: orderedMap(input.costAuthorization, COST_KEYS),
    humanAuthorizationConversationHmacSha256:
      input.humanAuthorizationConversationHmacSha256,
    humanAuthorizationSignerPublicKeySha256:
      input.humanAuthorizationSignerPublicKeySha256,
    humanAuthoritySenderHmacSha256:
      input.humanAuthoritySenderHmacSha256,
    humanIdentityHmacKeySha256: input.humanIdentityHmacKeySha256,
    humanIdentityRecordHmacSha256: input.humanIdentityRecordHmacSha256,
    humanIdentityReceiptSha256: input.humanIdentityReceiptSha256,
    clusterMode: CLUSTER_MODE,
    clusterCreateApproved: false,
    futureCockroachRevokerAuthorized: false,
    publicClaimAuthorized: false
  };
  return deepFreeze({ ...body, dynamicIntentSha256: digest(body) });
}

export function validateProofToActB0A1DynamicAuthorizationBinding(value) {
  const code = "PROOFTOACT_B0_A1_DYNAMIC_AUTHORIZATION_REJECTED";
  requireCondition(exactKeys(value, [
    "a1ApprovalId",
    "a1CallerWorkflowRef",
    "a1CallerWorkflowSha",
    "a1ControllerImportGraphSha256",
    "a1CredentialSha256",
    "a1ProviderClusterId",
    "a1ProviderReceiptSha256",
    "a1ReservationDeadline",
    "a1SqlClusterId",
    "accountId",
    "actionEnumsSha256",
    "authorizationNotBefore",
    "authorizationContractSha256",
    "b0DispatchDeadline",
    "b0PrivateRecoveryWorkflowCommits",
    "b0RuntimeExecutionBindingSha256",
    "b0TargetTemplateSha256",
    "b0WriterValueSha256",
    "cleanupRetentionDeadline",
    "clusterCreateApproved",
    "clusterMode",
    "costAuthorization",
    "dynamicIntentSha256",
    "futureCockroachRevokerAuthorized",
    "humanAuthorizationConversationHmacSha256",
    "humanAuthorizationSignerPublicKeySha256",
    "humanAuthoritySenderHmacSha256",
    "humanIdentityHmacKeySha256",
    "humanIdentityRecordHmacSha256",
    "humanIdentityReceiptSha256",
    "operationId",
    "publicClaimAuthorized",
    "schemaVersion",
    "sourceCommit",
    "treeDigest"
  ]), code);
  const expected = buildProofToActB0A1DynamicAuthorizationBinding({
    a1ApprovalId: value.a1ApprovalId,
    a1CallerWorkflowRef: value.a1CallerWorkflowRef,
    a1CallerWorkflowSha: value.a1CallerWorkflowSha,
    a1ControllerImportGraphSha256: value.a1ControllerImportGraphSha256,
    a1CredentialSha256: value.a1CredentialSha256,
    a1ProviderClusterId: value.a1ProviderClusterId,
    a1ProviderReceiptSha256: value.a1ProviderReceiptSha256,
    a1ReservationDeadline: value.a1ReservationDeadline,
    a1SqlClusterId: value.a1SqlClusterId,
    accountId: value.accountId,
    authorizationNotBefore: value.authorizationNotBefore,
    b0DispatchDeadline: value.b0DispatchDeadline,
    b0PrivateRecoveryWorkflowCommits:
      value.b0PrivateRecoveryWorkflowCommits,
    b0RuntimeExecutionBindingSha256:
      value.b0RuntimeExecutionBindingSha256,
    b0TargetTemplateSha256: value.b0TargetTemplateSha256,
    b0WriterValueSha256: value.b0WriterValueSha256,
    cleanupRetentionDeadline: value.cleanupRetentionDeadline,
    costAuthorization: value.costAuthorization,
    humanAuthorizationConversationHmacSha256:
      value.humanAuthorizationConversationHmacSha256,
    humanAuthorizationSignerPublicKeySha256:
      value.humanAuthorizationSignerPublicKeySha256,
    humanAuthoritySenderHmacSha256: value.humanAuthoritySenderHmacSha256,
    humanIdentityHmacKeySha256: value.humanIdentityHmacKeySha256,
    humanIdentityRecordHmacSha256: value.humanIdentityRecordHmacSha256,
    humanIdentityReceiptSha256: value.humanIdentityReceiptSha256,
    operationId: value.operationId,
    sourceCommit: value.sourceCommit,
    treeDigest: value.treeDigest
  });
  requireCondition(canonicalJson(value) === canonicalJson(expected), code);
  return expected;
}

function renderMap(label, value, keys) {
  return `${label}: ${keys.map((key) => `${key}=${value[key]}`).join(", ")}`;
}

export function renderProofToActB0A1HumanAuthorization(dynamicIntent) {
  const intent = validateProofToActB0A1DynamicAuthorizationBinding(
    dynamicIntent
  );
  const lines = [
    "Proposed exact ProofToAct B0 and A1 ADOPT authorization scope:",
    "This outbound proposal grants no authority. Only the exact threaded " +
      "human reply instructed below can approve this exact scope hash.",
    `Dynamic authorization intent SHA-256: ${intent.dynamicIntentSha256}`,
    `AWS account: ${intent.accountId}`,
    `Operation ID: ${intent.operationId}`,
    `Private authorization conversation HMAC SHA-256: ${intent.humanAuthorizationConversationHmacSha256}`,
    `Independent authorization signer public-key SHA-256: ${intent.humanAuthorizationSignerPublicKeySha256}`,
    `Private human-authority sender HMAC SHA-256: ${intent.humanAuthoritySenderHmacSha256}`,
    `Private identity HMAC key SHA-256: ${intent.humanIdentityHmacKeySha256}`,
    `Private identity record HMAC SHA-256: ${intent.humanIdentityRecordHmacSha256}`,
    `Private pre-authorization identity receipt SHA-256: ${intent.humanIdentityReceiptSha256}`,
    `Source commit: ${intent.sourceCommit}`,
    `Source tree: ${intent.treeDigest}`,
    `Authorization not before: ${intent.authorizationNotBefore}`,
    `B0 latest new-dispatch deadline: ${intent.b0DispatchDeadline}`,
    `A1 latest durable reservation deadline: ${intent.a1ReservationDeadline}`,
    `Cleanup retention deadline: ${intent.cleanupRetentionDeadline}`,
    `A1 approval ID: ${intent.a1ApprovalId}`,
    `A1 caller workflow: ${intent.a1CallerWorkflowRef}`,
    `A1 caller workflow commit: ${intent.a1CallerWorkflowSha}`,
    `A1 controller import graph SHA-256: ${intent.a1ControllerImportGraphSha256}`,
    `Adopted CockroachDB provider cluster ID: ${intent.a1ProviderClusterId}`,
    `Adopted CockroachDB SQL cluster ID: ${intent.a1SqlClusterId}`,
    renderMap("B0 template SHA-256 values",
      intent.b0TargetTemplateSha256, TARGET_TEMPLATE_KEYS),
    renderMap("B0 private recovery workflow commits",
      intent.b0PrivateRecoveryWorkflowCommits,
      PRIVATE_RECOVERY_WORKFLOW_KEYS),
    `B0 runtime execution binding SHA-256: ${intent.b0RuntimeExecutionBindingSha256}`,
    renderMap("B0 exact five writer-value SHA-256 values",
      intent.b0WriterValueSha256, WRITER_VALUE_KEYS),
    renderMap("A1 credential SHA-256 values",
      intent.a1CredentialSha256, A1_CREDENTIAL_KEYS),
    renderMap("A1 provider-evidence SHA-256 values",
      intent.a1ProviderReceiptSha256, A1_PROVIDER_RECEIPT_KEYS),
    `Cost reconciliation receipt SHA-256: ${intent.costAuthorization.reconciliationReceiptSha256}`,
    "Cost authorization: USD 5.00 one-time maximum and one combined USD " +
      "5.00 monthly maximum across ProofToAct provider resources. This " +
      "scope, if approved by that exact threaded reply, permits only the " +
      "exact B0/A1 operation listed here; " +
      "any " +
      "later A2 authorization must remain inside the same combined project " +
      "ceiling and is not additive. " +
      "CockroachDB is a sub-ceiling inside that same combined monthly " +
      "maximum: USD 2.00 authorized, with USD 1.50 paid worst case. The " +
      "remaining AWS monthly allowance is at most USD 3.50 when " +
      "CockroachDB reaches that paid worst case. These ceilings are not " +
      "additive, and no free benefit is assumed.",
    "For B0, the one-hour deadline is the latest-new-dispatch boundary. " +
      "No new execution mutation other than the exact cleanup mutations " +
      "separately authorized below is permitted at or after it. In " +
      "particular, no new CreateChangeSet, ExecuteChangeSet, " +
      "UpdateTerminationProtection, PutSecretValue, AssumeRole, workload, " +
      "or mutating provider API dispatch is authorized at or after it. An " +
      "exact immutable operation dispatched before it may complete " +
      "provider-side; ProofToAct may perform read-only Describe, Get, List, " +
      "and CloudTrail convergence for at most 45 minutes and must never " +
      "redispatch it.",
    "At most two nonoverlapping 900-second B0 sessions and two " +
      "nonoverlapping 900-second writer sessions are authorized. A second " +
      "session is authorized only after the prior ambiguous session's " +
      "maximum lifetime and CloudTrail lag; no third session is authorized.",
    "For A1, approval expiry is the latest-durable-outer-reservation " +
      "boundary. Only the immutable one-shot whose reservation is durably " +
      "acknowledged before expiry may continue within the fixed 45-minute " +
      "workflow timeout. No new reservation, execute rerun, or different " +
      "source or operation is authorized at or after expiry.",
    "The A1 CockroachDB DDL and DML authority is limited to creating and " +
      "using the exact source-bound ProofToAct database, schemas, tables, " +
      "functions, vector index, grants, runtime principals, and synthetic " +
      "evidence rows required by the reviewed bootstrap, DVI, authority " +
      "race, signed recovery publication, and reconciliation paths. It " +
      "does not authorize mutation of an unrelated database, schema, role, " +
      "table, function, index, row, cluster, or customer data.",
    "Until the cleanup retention deadline, cleanup may perform readback, " +
      "logout, and immutable DynamoDB audit-transition and terminal-record " +
      "writes. Its only destructive provider mutations are deletion of the " +
      "exact temporary B0 inline policy and role, the exact bootstrap SQL " +
      "admin, and the temporary SQL /32 ingress. Cleanup may not create, " +
      "seal, retry an execution operation, or broaden authority.",
    `The exact B0 actions are: ${PROOFTOACT_B0_ACTIONS.join(", ")}.`,
    `The exact A1 actions are: ${PROOFTOACT_A1_ACTIONS.join(", ")}.`,
    `The excluded actions are: ${PROOFTOACT_EXCLUDED_ACTIONS.join(", ")}.`,
    "The temporary creator and auditor provider keys may remain only " +
      "pending a separate organization-admin revocation authorization and " +
      "ceremony; no future CockroachDB revoker is authorized here. This " +
      "scope, even if approved, does not authorize a public live-integration " +
      "GO claim " +
      "before provider-key revocation and the complete joined evidence pass.",
    "Even if approved, this B0/A1 scope does not authorize the A2 " +
      "private-recovery " +
      "artifact upload, application-stack change set, Lambda deployment, " +
      "numeric-version invocation, second Managed MCP query, DynamoDB " +
      "intent/result/finalization records, evidence collection, or governed " +
      "teardown. Those actions require one separate exact A2 authorization " +
      "bound to their final source, workflow, artifact, template, secret, " +
      "operation, deadlines, and the same non-additive cost ceiling."
  ];
  const authorizationScopeText = lines.join("\n");
  const authorizationScopeSha256 = sha256(Buffer.from(
    authorizationScopeText,
    "utf8"
  ));
  const replyInstruction =
    "Use iMessage Reply on this exact message, then send exactly: " +
    `I APPROVE PROOFTOACT B0+A1 ${authorizationScopeSha256}`;
  const text = `${authorizationScopeText}\n\n${replyInstruction}`;
  const bytes = Buffer.from(`${text}\n`, "utf8");
  const transportBytes = Buffer.from(text, "utf8");
  return deepFreeze({
    actionEnums: PROOFTOACT_AUTHORIZATION_ACTION_ENUMS,
    actionEnumsSha256:
      PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT.actionEnumsSha256,
    authorizationContractSha256:
      PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT_SHA256,
    authorizationScopeSha256,
    authorizationScopeText,
    bytes,
    canonicalFileSha256: sha256(bytes),
    clusterCreateApproved: false,
    clusterMode: CLUSTER_MODE,
    dynamicIntent: intent,
    dynamicIntentSha256: intent.dynamicIntentSha256,
    futureCockroachRevokerAuthorized: false,
    publicClaimAuthorized: false,
    replyInstruction,
    schemaVersion: CONTRACT_SCHEMA_VERSION,
    sha256: sha256(transportBytes),
    text,
    transportBytes
  });
}

export function validateProofToActB0A1HumanAuthorizationBytes(
  dynamicIntent,
  value
) {
  const code = "PROOFTOACT_B0_A1_AUTHORIZATION_BYTES_REJECTED";
  const rendered = renderProofToActB0A1HumanAuthorization(dynamicIntent);
  requireCondition(Buffer.isBuffer(value) &&
    value.equals(rendered.bytes) &&
    value.at(-1) === 0x0a && value.at(-2) !== 0x0a &&
    sha256(value) === rendered.canonicalFileSha256,
  code);
  return rendered;
}

export function renderProofToActB0A1ApprovalReply(dynamicIntent) {
  const rendered = renderProofToActB0A1HumanAuthorization(dynamicIntent);
  const text =
    `I APPROVE PROOFTOACT B0+A1 ${rendered.authorizationScopeSha256}`;
  const bytes = Buffer.from(text, "utf8");
  return deepFreeze({
    bytes,
    dynamicIntentSha256: rendered.dynamicIntentSha256,
    authorizationScopeSha256: rendered.authorizationScopeSha256,
    exactAuthorizationBodySha256: rendered.sha256,
    sha256: sha256(bytes),
    text
  });
}

export function buildProofToActB0A1HumanAuthorizationReceiptBinding(input) {
  const code = "PROOFTOACT_B0_A1_AUTHORIZATION_RECEIPT_REJECTED";
  requireCondition(exactKeys(input, [
    "dynamicIntent",
    "externalHumanAuthorizationEvidence"
  ]), code);
  const rendered = renderProofToActB0A1HumanAuthorization(
    input.dynamicIntent
  );
  const evidence = validateExternalHumanAuthorizationEvidence(
    input.externalHumanAuthorizationEvidence,
    rendered
  );
  const body = {
    schemaVersion: RECEIPT_SCHEMA_VERSION,
    actionEnumsSha256: rendered.actionEnumsSha256,
    authorizationContractSha256: rendered.authorizationContractSha256,
    clusterCreateApproved: false,
    clusterMode: CLUSTER_MODE,
    dynamicIntent: rendered.dynamicIntent,
    dynamicIntentSha256: rendered.dynamicIntentSha256,
    externalHumanAuthorizationEvidence: evidence,
    externalHumanAuthorizationEvidenceSha256: digest(evidence),
    futureCockroachRevokerAuthorized: false,
    humanAuthorizedTextSha256: rendered.sha256,
    publicClaimAuthorized: false
  };
  return deepFreeze({ ...body, receiptBindingSha256: digest(body) });
}

export function validateProofToActB0A1HumanAuthorizationReceipt(
  value,
  expectedSignerPublicKeySha256 = null
) {
  const code = "PROOFTOACT_B0_A1_AUTHORIZATION_RECEIPT_REJECTED";
  requireCondition(exactKeys(value, [
    "actionEnumsSha256",
    "authorizationContractSha256",
    "clusterCreateApproved",
    "clusterMode",
    "dynamicIntent",
    "dynamicIntentSha256",
    "externalHumanAuthorizationEvidence",
    "externalHumanAuthorizationEvidenceSha256",
    "futureCockroachRevokerAuthorized",
    "humanAuthorizedTextSha256",
    "publicClaimAuthorized",
    "receiptBindingSha256",
    "schemaVersion"
  ]), code);
  const expected = buildProofToActB0A1HumanAuthorizationReceiptBinding({
    dynamicIntent: value.dynamicIntent,
    externalHumanAuthorizationEvidence:
      value.externalHumanAuthorizationEvidence
  });
  requireCondition(canonicalJson(value) === canonicalJson(expected), code);
  if (expectedSignerPublicKeySha256 !== null) {
    requireCondition(HEX_64.test(expectedSignerPublicKeySha256 ?? "") &&
      expected.dynamicIntent.humanAuthorizationSignerPublicKeySha256 ===
        expectedSignerPublicKeySha256,
    code);
  }
  return expected;
}

export function buildProofToActHumanAuthorizationSignaturePayload({
  dynamicIntentSha256,
  unsignedExternalHumanAuthorizationEvidenceSha256
}) {
  const code = "PROOFTOACT_HUMAN_AUTHORIZATION_SIGNATURE_REJECTED";
  requireCondition(HEX_64.test(dynamicIntentSha256 ?? "") &&
    HEX_64.test(unsignedExternalHumanAuthorizationEvidenceSha256 ?? ""),
  code);
  const body = {
    schemaVersion: SIGNATURE_PAYLOAD_SCHEMA_VERSION,
    dynamicIntentSha256,
    unsignedExternalHumanAuthorizationEvidenceSha256
  };
  return deepFreeze({
    body,
    bytes: Buffer.from(`${canonicalJson(body)}\n`, "utf8"),
    sha256: digest(body)
  });
}

export function buildProofToActImessageEventReceiptSha256({
  direction,
  event,
  materializer
}) {
  const code = "PROOFTOACT_IMESSAGE_EVENT_RECEIPT_REJECTED";
  requireCondition(["INBOUND", "OUTBOUND"].includes(direction) &&
    plainObject(event) && exactKeys(materializer, ["history", "tool"]) &&
    canonicalJson(materializer.tool) ===
      canonicalJson(PROOFTOACT_IMESSAGE_MATERIALIZER) &&
    exactKeys(materializer.history, [
      "end", "invocationSha256", "limit", "start"
    ]) && HEX_64.test(materializer.history.invocationSha256 ?? "") &&
    materializer.history.limit === 10000, code);
  const projection = {
    schemaVersion:
      "prooftoact.imsg-human-authorization-event-projection.v1",
    bodySha256: event.bodySha256,
    channel: event.channel,
    conversationHmacSha256: event.conversationHmacSha256,
    createdAt: direction === "OUTBOUND" ? event.sentAt : event.receivedAt,
    direction,
    isFromMe: direction === "OUTBOUND",
    materializerSha256: digest(materializer),
    messageIdSha256: event.messageIdSha256,
    provider: event.provider
  };
  if (direction === "INBOUND") {
    projection.replyTargetMessageIdSha256 =
      event.replyTargetMessageIdSha256;
    projection.senderHmacSha256 = event.senderHmacSha256;
  }
  requireCondition(Object.values(projection).every((value) =>
    typeof value === "string" || typeof value === "boolean"), code);
  return digest(projection);
}

function validateExternalHumanAuthorizationEvidence(value, rendered) {
  const code = "PROOFTOACT_EXTERNAL_HUMAN_AUTHORIZATION_EVIDENCE_REJECTED";
  requireCondition(exactKeys(value, [
    "authorityId",
    "authorizationSignatureBase64",
    "inboundApprovalEvent",
    "materializer",
    "outboundAuthorizationEvent",
    "schemaVersion",
    "signerPublicKeySpkiBase64"
  ]) && value.schemaVersion === EVIDENCE_SCHEMA_VERSION &&
    value.authorityId === "REVIEWED_DIRECT_HUMAN_OPERATOR" &&
    exactKeys(value.outboundAuthorizationEvent, [
      "bodySha256", "bodyText", "channel", "conversationHmacSha256",
      "eventReceiptSha256", "messageIdSha256", "provider", "sentAt"
    ]) && exactKeys(value.inboundApprovalEvent, [
      "bodySha256", "bodyText", "channel", "conversationHmacSha256",
      "eventReceiptSha256", "messageIdSha256", "provider", "receivedAt",
      "replyTargetMessageIdSha256", "senderHmacSha256"
    ]) && exactKeys(value.materializer, ["history", "tool"]), code);
  const outbound = value.outboundAuthorizationEvent;
  const inbound = value.inboundApprovalEvent;
  const approvalReply = renderProofToActB0A1ApprovalReply(
    rendered.dynamicIntent
  );
  const materializer = value.materializer;
  const unsignedEvidence = {
    authorityId: value.authorityId,
    inboundApprovalEvent: inbound,
    materializer,
    outboundAuthorizationEvent: outbound,
    schemaVersion: value.schemaVersion
  };
  requireCondition(outbound.channel === "imessage" &&
    outbound.provider === "imessage" &&
    inbound.channel === outbound.channel &&
    inbound.provider === outbound.provider &&
    inbound.conversationHmacSha256 ===
      outbound.conversationHmacSha256 &&
    outbound.conversationHmacSha256 ===
      rendered.dynamicIntent.humanAuthorizationConversationHmacSha256 &&
    inbound.replyTargetMessageIdSha256 === outbound.messageIdSha256 &&
    [outbound.bodySha256, outbound.conversationHmacSha256,
      outbound.eventReceiptSha256, outbound.messageIdSha256,
      inbound.bodySha256, inbound.eventReceiptSha256,
      inbound.messageIdSha256, inbound.replyTargetMessageIdSha256,
    inbound.senderHmacSha256].every((item) => HEX_64.test(item ?? "")) &&
    outbound.bodyText === rendered.text &&
    sha256(Buffer.from(outbound.bodyText, "utf8")) === outbound.bodySha256 &&
    outbound.bodySha256 === rendered.sha256 &&
    inbound.bodyText === approvalReply.text &&
    sha256(Buffer.from(inbound.bodyText, "utf8")) === inbound.bodySha256 &&
    inbound.bodySha256 === approvalReply.sha256 &&
    inbound.senderHmacSha256 ===
      rendered.dynamicIntent.humanAuthoritySenderHmacSha256 &&
    outbound.eventReceiptSha256 ===
      buildProofToActImessageEventReceiptSha256({
        direction: "OUTBOUND",
        event: outbound,
        materializer
      }) &&
    inbound.eventReceiptSha256 ===
      buildProofToActImessageEventReceiptSha256({
        direction: "INBOUND",
        event: inbound,
        materializer
      }),
  code);
  requireCondition(canonicalJson(materializer) === canonicalJson(
    buildProofToActImessageMaterializer(rendered.dynamicIntent)
  ), code);
  let publicKeyBytes;
  let signatureBytes;
  let publicKey;
  try {
    publicKeyBytes = Buffer.from(value.signerPublicKeySpkiBase64, "base64");
    signatureBytes = Buffer.from(value.authorizationSignatureBase64,
      "base64");
    requireCondition(publicKeyBytes.length === 44 &&
      publicKeyBytes.toString("base64") ===
        value.signerPublicKeySpkiBase64 &&
      publicKeyBytes.subarray(0, 12).toString("hex") ===
        "302a300506032b6570032100" &&
      signatureBytes.length === 64 &&
      signatureBytes.toString("base64") ===
        value.authorizationSignatureBase64 &&
      sha256(publicKeyBytes) === rendered.dynamicIntent
        .humanAuthorizationSignerPublicKeySha256,
    code);
    publicKey = crypto.createPublicKey({
      format: "der",
      key: publicKeyBytes,
      type: "spki"
    });
    requireCondition(publicKey.asymmetricKeyType === "ed25519", code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code);
  }
  const signaturePayload = buildProofToActHumanAuthorizationSignaturePayload({
    dynamicIntentSha256: rendered.dynamicIntentSha256,
    unsignedExternalHumanAuthorizationEvidenceSha256: digest(unsignedEvidence)
  });
  requireCondition(crypto.verify(
    null,
    signaturePayload.bytes,
    publicKey,
    signatureBytes
  ), code);
  const sentAt = canonicalInstant(outbound.sentAt, code);
  const receivedAt = canonicalInstant(inbound.receivedAt, code);
  requireCondition(sentAt >= Date.parse(
    rendered.dynamicIntent.authorizationNotBefore
  ) && receivedAt >= sentAt && receivedAt < Date.parse(
    rendered.dynamicIntent.b0DispatchDeadline
  ), code);
  return deepFreeze({ ...value });
}

export const __test = Object.freeze({
  A1_CREDENTIAL_KEYS,
  A1_PROVIDER_RECEIPT_KEYS,
  COST_KEYS,
  PRIVATE_RECOVERY_WORKFLOW_KEYS,
  TARGET_TEMPLATE_KEYS,
  WRITER_VALUE_KEYS,
  canonicalJson,
  digest,
  validateExternalHumanAuthorizationEvidence,
  sha256
});
