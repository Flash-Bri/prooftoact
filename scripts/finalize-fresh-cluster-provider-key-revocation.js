import crypto from "node:crypto";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const KEY_ID = /^CCDB1_[A-Za-z0-9]{20,96}$/u;
const KEY_NAME = /^[a-z0-9][a-z0-9-]{2,62}$/u;
const TARGET_KEYS = Object.freeze(["creator", "auditor"]);
const ROLES = Object.freeze({
  creator: "CLUSTER_OPERATOR",
  auditor: "CLUSTER_DEVELOPER"
});
const PENDING_RECEIPT_KEYS = Object.freeze([
  "schemaVersion", "status", "coreStatus", "publicDisposition",
  "adminCredentialAbsent", "adminSecretCredentialRevokedByPrincipalDeletion",
  "adminSecretVersionRetained", "adminSqlPrincipalAbsent",
  "billingAuthorizationSha256", "bootstrapReceiptSha256",
  "clusterDeleteProtection", "clusterIdSha256", "clusterMode",
  "commandSha256", "controllerGeneratedRecoverySource", "controllerTableArn",
  "finalPrincipalCensusSha256", "finalProviderSqlUserInventorySha256",
  "freshClusterRetained", "globalKeySha256", "ingressEmpty",
  "manualClusterReceiptSha256", "operationId", "principalLoginPostureSha256",
  "completeShowUsersPrincipalCensusSha256",
  "completeShowUsersPrincipalCountBeforeAdminDeletion",
  "immutableBuiltinAdminRoleExceptionPresent",
  "noApplicationRetainedSqlAdministrator", "proofToActRootConnectionStringCreated",
  "proofToActRootConnectionStringUsed", "proofToActRootPasswordCreated",
  "proofToActRootSecretStored", "rootNoLoginProvedBeforeAdminDeletion",
  "runtimeLoginCountProvedBeforeAdminDeletion",
  "capabilityNoLoginCountProvedBeforeAdminDeletion",
  "bootstrapAdminAbsentInFinalProviderReadback",
  "rootPresentInFinalProviderReadback", "recoveryAppendReceiptSha256",
  "recoveryManagedMcpProofSha256", "recoveryManagedMcpRequestSha256",
  "recoveryPreparationReceiptSha256",
  "recoveryPublicationInputsCommittedBeforeAdminDeletion",
  "recoveryReplayReceiptSha256", "recoverySourceBootstrapAdminUsed",
  "recoverySourceReceiptSha256", "sqlClusterIdSha256",
  "previousReceiptSha256", "primaryClusterMapping",
  "primaryClusterMappingReceiptSha256", "privateRecoveryQueryBinding",
  "privateRecoveryQueryBindingSha256", "providerKeyRevocationCeremony",
  "providerKeyRevocationCeremonySha256", "providerKeysRevoked",
  "separateTeardownApprovalRequired", "sourceCommit", "transitionCount",
  "treeDigest"
]);
const REQUIRED_PROOF_SEQUENCE = Object.freeze([
  "RECORD_EXACT_CREATOR_KEY_ID_AND_UNIQUE_NAME",
  "DELETE_CREATOR_KEY",
  "PROVE_CREATOR_KEY_GET_404",
  "PROVE_CREATOR_FILTERED_KEY_LIST_ABSENCE",
  "OPTIONALLY_RETAIN_AUDITOR_FOR_INDEPENDENT_READBACK",
  "RECORD_EXACT_AUDITOR_KEY_ID_AND_UNIQUE_NAME",
  "DELETE_AUDITOR_KEY",
  "PROVE_AUDITOR_KEY_GET_404",
  "PROVE_AUDITOR_FILTERED_KEY_LIST_ABSENCE"
]);

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

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value).sort(([left], [right]) =>
      left.localeCompare(right)).map(([key, nested]) =>
      `${JSON.stringify(key)}:${canonicalJson(nested)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function canonicalInstant(value, code) {
  const time = Date.parse(value);
  requireCondition(typeof value === "string" && Number.isFinite(time) &&
    new Date(time).toISOString() === value, code);
  return time;
}

function validatePendingReceipt(receipt) {
  const code = "FRESH_CLUSTER_KEY_REVOCATION_PENDING_RECEIPT_REJECTED";
  const ceremony = receipt?.providerKeyRevocationCeremony;
  requireCondition(exactKeys(receipt, PENDING_RECEIPT_KEYS) &&
    receipt.schemaVersion ===
    "prooftoact.fresh-cluster-controller-receipt.v1" &&
    receipt.status === "PROVIDER_KEYS_REVOCATION_PENDING" &&
    receipt.coreStatus === "PASS" && receipt.publicDisposition === "HOLD" &&
    receipt.providerKeysRevoked === false && UUID.test(receipt.operationId ?? "") &&
    HEX_40.test(receipt.sourceCommit ?? "") && HEX_40.test(
      receipt.treeDigest ?? "") && HEX_64.test(receipt.commandSha256 ?? "") &&
    HEX_64.test(receipt.previousReceiptSha256 ?? "") &&
    Number.isSafeInteger(receipt.transitionCount) &&
    receipt.transitionCount > 0 && receipt.ingressEmpty === true &&
    receipt.adminSqlPrincipalAbsent === true &&
    HEX_64.test(receipt.providerKeyRevocationCeremonySha256 ?? "") &&
    exactKeys(ceremony, [
      "schemaVersion", "status", "operationId", "sourceCommit", "treeDigest",
      "organizationAdministratorRequired", "selfRevocationForbidden",
      "serviceAccountsAndRolesMustBePreserved",
      "creatorMustBeRevokedBeforeAuditor", "creator", "auditor",
      "requiredProofSequence", "ceremonyReceiptMustBindControllerReceiptSha256"
    ]) && ceremony.schemaVersion ===
      "prooftoact.cockroach-provider-key-revocation-ceremony.v1" &&
    ceremony.status === "PENDING_ORGANIZATION_ADMIN" &&
    ceremony.operationId === receipt.operationId &&
    ceremony.sourceCommit === receipt.sourceCommit &&
    ceremony.treeDigest === receipt.treeDigest &&
    ceremony.organizationAdministratorRequired === true &&
    ceremony.selfRevocationForbidden === true &&
    ceremony.serviceAccountsAndRolesMustBePreserved === true &&
    ceremony.creatorMustBeRevokedBeforeAuditor === true &&
    ceremony.ceremonyReceiptMustBindControllerReceiptSha256 === true &&
    canonicalJson(ceremony.requiredProofSequence) ===
      canonicalJson(REQUIRED_PROOF_SEQUENCE) &&
    receipt.providerKeyRevocationCeremonySha256 === digest(ceremony) &&
    TARGET_KEYS.every((key, index) => exactKeys(ceremony[key], [
      "serviceAccountId", "credentialPurpose", "exactUniqueProviderKeyName",
      "keyNameDisposition", "sequence"
    ]) && UUID.test(ceremony[key].serviceAccountId ?? "") &&
      ceremony[key].credentialPurpose === (key === "creator" ?
        "A1_PROVIDER_CREATOR" : "A1_PROVIDER_AUDITOR") &&
      ceremony[key].exactUniqueProviderKeyName === null &&
      ceremony[key].keyNameDisposition ===
        "ORG_ADMIN_MUST_RECORD_EXACT_UNIQUE_NAME_BEFORE_DELETE" &&
      ceremony[key].sequence === index + 1) &&
    ceremony.creator.serviceAccountId !== ceremony.auditor.serviceAccountId,
  code);
  return receipt;
}

export function buildProviderKeyRevocationCommand({
  approvedAt,
  auditorKeyId,
  auditorKeyName,
  creatorKeyId,
  creatorKeyName,
  pendingReceipt
}) {
  const code = "FRESH_CLUSTER_KEY_REVOCATION_COMMAND_REJECTED";
  validatePendingReceipt(pendingReceipt);
  canonicalInstant(approvedAt, code);
  requireCondition(KEY_ID.test(creatorKeyId ?? "") &&
    KEY_ID.test(auditorKeyId ?? "") && creatorKeyId !== auditorKeyId &&
    KEY_NAME.test(creatorKeyName ?? "") && KEY_NAME.test(auditorKeyName ?? "") &&
    creatorKeyName !== auditorKeyName, code);
  const body = {
    schemaVersion: "prooftoact.provider-key-revocation-proposal.v1",
    status:
      "HOLD_REQUIRES_SEPARATE_SIGNED_ORGANIZATION_ADMIN_AUTHORIZATION",
    approvedAt,
    operationId: pendingReceipt.operationId,
    sourceCommit: pendingReceipt.sourceCommit,
    treeDigest: pendingReceipt.treeDigest,
    pendingControllerReceiptSha256: digest(pendingReceipt),
    pendingCommandSha256: pendingReceipt.commandSha256,
    pendingPreviousReceiptSha256: pendingReceipt.previousReceiptSha256,
    pendingTransitionCount: pendingReceipt.transitionCount,
    pendingCeremonySha256: pendingReceipt.providerKeyRevocationCeremonySha256,
    creator: {
      sequence: 1,
      serviceAccountId:
        pendingReceipt.providerKeyRevocationCeremony.creator.serviceAccountId,
      expectedRole: ROLES.creator,
      keyId: creatorKeyId,
      keyName: creatorKeyName
    },
    auditor: {
      sequence: 2,
      serviceAccountId:
        pendingReceipt.providerKeyRevocationCeremony.auditor.serviceAccountId,
      expectedRole: ROLES.auditor,
      keyId: auditorKeyId,
      keyName: auditorKeyName
    },
    preserveServiceAccounts: true,
    unrelatedProviderMutationAuthorized: false
  };
  return Object.freeze({ ...body, commandSha256: digest(body) });
}

function validateCommand(command, pendingReceipt) {
  const rebuilt = buildProviderKeyRevocationCommand({
    approvedAt: command?.approvedAt,
    auditorKeyId: command?.auditor?.keyId,
    auditorKeyName: command?.auditor?.keyName,
    creatorKeyId: command?.creator?.keyId,
    creatorKeyName: command?.creator?.keyName,
    pendingReceipt
  });
  requireCondition(canonicalJson(rebuilt) === canonicalJson(command),
    "FRESH_CLUSTER_KEY_REVOCATION_COMMAND_REJECTED");
  return command;
}

function validateServiceAccount(value, target, code) {
  requireCondition(exactKeys(value, [
    "active", "observedAt", "responseSha256", "role", "serviceAccountId"
  ]) && value.active === true && value.serviceAccountId ===
    target.serviceAccountId && value.role === target.expectedRole &&
    HEX_64.test(value.responseSha256 ?? ""), code);
  canonicalInstant(value.observedAt, code);
  return value;
}

function validateKeyPresent(value, target, code) {
  requireCondition(exactKeys(value, [
    "found", "httpStatus", "keyId", "keyName", "observedAt",
    "responseSha256", "serviceAccountId"
  ]) && value.found === true && value.httpStatus === 200 &&
    value.keyId === target.keyId && value.keyName === target.keyName &&
    value.serviceAccountId === target.serviceAccountId &&
    HEX_64.test(value.responseSha256 ?? ""), code);
  canonicalInstant(value.observedAt, code);
  return value;
}

function validateKeyAbsent(getValue, listValue, target, code) {
  requireCondition(exactKeys(getValue, [
    "found", "httpStatus", "keyId", "observedAt", "responseSha256",
    "serviceAccountId"
  ]) && getValue.found === false && getValue.httpStatus === 404 &&
    getValue.keyId === target.keyId &&
    getValue.serviceAccountId === target.serviceAccountId &&
    HEX_64.test(getValue.responseSha256 ?? ""), code);
  canonicalInstant(getValue.observedAt, code);
  requireCondition(exactKeys(listValue, [
    "complete", "keyIds", "observedAt", "pageCount", "responseSetSha256",
    "serviceAccountId"
  ]) && listValue.complete === true &&
    listValue.serviceAccountId === target.serviceAccountId &&
    Number.isSafeInteger(listValue.pageCount) && listValue.pageCount > 0 &&
    Array.isArray(listValue.keyIds) && new Set(listValue.keyIds).size ===
      listValue.keyIds.length && listValue.keyIds.every((id) => KEY_ID.test(id)) &&
    !listValue.keyIds.includes(target.keyId) &&
    HEX_64.test(listValue.responseSetSha256 ?? ""), code);
  canonicalInstant(listValue.observedAt, code);
  return Object.freeze({
    get404Sha256: digest(getValue),
    completeListAbsenceSha256: digest(listValue)
  });
}

function validateState(value, command) {
  const code = "FRESH_CLUSTER_KEY_REVOCATION_STATE_REJECTED";
  requireCondition(plainObject(value) && value.commandSha256 ===
    command.commandSha256 && value.pendingControllerReceiptSha256 ===
    command.pendingControllerReceiptSha256 && plainObject(value.targets) &&
    TARGET_KEYS.every((key) => [null, "INTENT_RECORDED",
      "DISPATCH_STARTED", "ABSENT_ACCEPTED"].includes(value.targets[key])) &&
    (value.acceptance === null || plainObject(value.acceptance)), code);
  return value;
}

function validateAcceptance(receipt, command) {
  const code = "FRESH_CLUSTER_KEY_REVOCATION_ACCEPTANCE_REJECTED";
  requireCondition(plainObject(receipt) && receipt.schemaVersion ===
    "prooftoact.provider-key-revocation-acceptance.v1" &&
    receipt.status === "PROVIDER_KEYS_REVOCATION_ACCEPTED" &&
    receipt.providerKeyGateStatus === "PASS" &&
    receipt.publicDisposition === "HOLD_OTHER_RELEASE_GATES" &&
    receipt.finalReleaseReady === false && receipt.providerKeysRevoked === true &&
    receipt.commandSha256 === command.commandSha256 &&
    receipt.pendingControllerReceiptSha256 ===
      command.pendingControllerReceiptSha256 &&
    receipt.operationId === command.operationId &&
    receipt.sourceCommit === command.sourceCommit &&
    receipt.treeDigest === command.treeDigest &&
    receipt.creatorKeyId === command.creator.keyId &&
    receipt.auditorKeyId === command.auditor.keyId &&
    receipt.creatorServiceAccountId === command.creator.serviceAccountId &&
    receipt.auditorServiceAccountId === command.auditor.serviceAccountId &&
    receipt.serviceAccountsPreserved === true &&
    receipt.unrelatedProviderMutations === 0 &&
    HEX_64.test(receipt.creatorAbsenceReceiptSha256 ?? "") &&
    HEX_64.test(receipt.auditorAbsenceReceiptSha256 ?? "") &&
    HEX_64.test(receipt.serviceAccountReadbackSetSha256 ?? "") &&
    receipt.receiptSha256 === digest(Object.fromEntries(Object.entries(
      receipt
    ).filter(([key]) => key !== "receiptSha256"))), code);
  canonicalInstant(receipt.acceptedAt, code);
  return receipt;
}

function validateProvider(provider) {
  const methods = [
    "appendAccepted", "appendDispatchStarted", "appendIntent", "deleteApiKey",
    "finalizeAcceptance", "getApiKey", "getServiceAccount",
    "listCompleteApiKeys", "readStrong", "terminalizeUnknown"
  ];
  requireCondition(plainObject(provider) && methods.every((name) =>
    typeof provider[name] === "function"),
  "FRESH_CLUSTER_KEY_REVOCATION_PROVIDER_REJECTED");
}

async function serviceAccountSet(provider, command) {
  return Promise.all(TARGET_KEYS.map(async (key) => validateServiceAccount(
    await provider.getServiceAccount({
      command,
      serviceAccountId: command[key].serviceAccountId
    }), command[key], "FRESH_CLUSTER_KEY_REVOCATION_SERVICE_ACCOUNT_REJECTED"
  )));
}

async function reconcileTarget(provider, command, state, key) {
  const code = "FRESH_CLUSTER_KEY_REVOCATION_ABSENCE_REJECTED";
  const target = command[key];
  requireCondition(key === "creator" || state.targets.creator ===
    "ABSENT_ACCEPTED", "FRESH_CLUSTER_KEY_REVOCATION_ORDER_REJECTED");
  if (state.targets[key] === "ABSENT_ACCEPTED") return state;
  if (state.targets[key] === null) {
    validateKeyPresent(await provider.getApiKey({ command, ...target }),
      target, code);
    state = validateState(await provider.appendIntent({ command, key, target }),
      command);
  }
  if (state.targets[key] === "INTENT_RECORDED") {
    state = validateState(await provider.appendDispatchStarted({
      command, key, target
    }), command);
    let deleteCause = null;
    try {
      await provider.deleteApiKey({ command, ...target });
    } catch (cause) {
      deleteCause = cause;
    }
    const getValue = await provider.getApiKey({ command, ...target });
    const listValue = await provider.listCompleteApiKeys({
      command,
      serviceAccountId: target.serviceAccountId
    });
    let absence;
    try {
      absence = validateKeyAbsent(getValue, listValue, target, code);
    } catch (cause) {
      await provider.terminalizeUnknown({
        command,
        failureCode: "PROVIDER_KEY_DELETE_AMBIGUOUS_DO_NOT_RETRY",
        key,
        observedStateSha256: digest({ getValue, listValue })
      });
      reject("FRESH_CLUSTER_KEY_REVOCATION_UNKNOWN_DO_NOT_RETRY",
        deleteCause ?? cause);
    }
    state = validateState(await provider.appendAccepted({
      absence,
      command,
      key,
      target
    }), command);
  } else if (state.targets[key] === "DISPATCH_STARTED") {
    const getValue = await provider.getApiKey({ command, ...target });
    const listValue = await provider.listCompleteApiKeys({
      command,
      serviceAccountId: target.serviceAccountId
    });
    let absence;
    try {
      absence = validateKeyAbsent(getValue, listValue, target, code);
    } catch (cause) {
      await provider.terminalizeUnknown({
        command,
        failureCode: "PROVIDER_KEY_DELETE_AMBIGUOUS_DO_NOT_RETRY",
        key,
        observedStateSha256: digest({ getValue, listValue })
      });
      reject("FRESH_CLUSTER_KEY_REVOCATION_UNKNOWN_DO_NOT_RETRY", cause);
    }
    state = validateState(await provider.appendAccepted({
      absence, command, key, target
    }), command);
  }
  requireCondition(state.targets[key] === "ABSENT_ACCEPTED", code);
  return state;
}

export async function runProviderKeyRevocationFinalizer({
  command,
  pendingReceipt,
  provider
}) {
  void command;
  void pendingReceipt;
  void provider;
  reject(
    "FRESH_CLUSTER_KEY_REVOCATION_INDEPENDENT_ORG_ADMIN_AUTHORIZATION_REQUIRED"
  );
  /* c8 ignore next 45 -- unreachable retained design is not release authority */
  validateProvider(provider);
  validateCommand(command, pendingReceipt);
  let state = validateState(await provider.readStrong({ command }), command);
  if (state.acceptance !== null) {
    return validateAcceptance(state.acceptance, command);
  }
  const before = await serviceAccountSet(provider, command);
  state = await reconcileTarget(provider, command, state, "creator");
  state = await reconcileTarget(provider, command, state, "auditor");
  const after = await serviceAccountSet(provider, command);
  requireCondition(canonicalJson(before.map(({ serviceAccountId, role }) =>
    ({ serviceAccountId, role }))) === canonicalJson(after.map(
    ({ serviceAccountId, role }) => ({ serviceAccountId, role })
  )), "FRESH_CLUSTER_KEY_REVOCATION_SERVICE_ACCOUNT_REJECTED");
  const body = {
    schemaVersion: "prooftoact.provider-key-revocation-acceptance.v1",
    status: "PROVIDER_KEYS_REVOCATION_ACCEPTED",
    providerKeyGateStatus: "PASS",
    publicDisposition: "HOLD_OTHER_RELEASE_GATES",
    finalReleaseReady: false,
    providerKeysRevoked: true,
    acceptedAt: after.map(({ observedAt }) => observedAt).sort().at(-1),
    commandSha256: command.commandSha256,
    pendingControllerReceiptSha256: command.pendingControllerReceiptSha256,
    operationId: command.operationId,
    sourceCommit: command.sourceCommit,
    treeDigest: command.treeDigest,
    creatorKeyId: command.creator.keyId,
    creatorServiceAccountId: command.creator.serviceAccountId,
    auditorKeyId: command.auditor.keyId,
    auditorServiceAccountId: command.auditor.serviceAccountId,
    creatorAbsenceReceiptSha256: state.receipts.creator,
    auditorAbsenceReceiptSha256: state.receipts.auditor,
    serviceAccountReadbackSetSha256: digest({ before, after }),
    serviceAccountsPreserved: true,
    unrelatedProviderMutations: 0
  };
  const receipt = Object.freeze({ ...body, receiptSha256: digest(body) });
  const finalized = await provider.finalizeAcceptance({ command, receipt });
  return validateAcceptance(finalized, command);
}

export const __test = Object.freeze({
  canonicalJson,
  digest,
  validateAcceptance,
  validateKeyAbsent,
  validatePendingReceipt
});
