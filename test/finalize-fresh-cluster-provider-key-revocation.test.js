import assert from "node:assert/strict";
import test from "node:test";

import {
  __test as finalizerTest,
  buildProviderKeyRevocationCommand,
  runProviderKeyRevocationFinalizer
} from "../scripts/finalize-fresh-cluster-provider-key-revocation.js";

const CREATOR_ID = "f363a800-37e6-4f34-8440-44e37f224980";
const AUDITOR_ID = "485a992f-e5ea-45a3-b415-cb70fcb0a5f5";
const CREATOR_KEY_ID = "CCDB1_AKazdJnF2adJAg9fo7EH7e";
const AUDITOR_KEY_ID = "CCDB1_6HqZWMqRSl8djCZwkJb075";
const OBSERVED = "2026-08-19T07:00:00.000Z";

function pendingReceipt() {
  const ceremony = {
    schemaVersion:
      "prooftoact.cockroach-provider-key-revocation-ceremony.v1",
    status: "PENDING_ORGANIZATION_ADMIN",
    operationId: "123e4567-e89b-42d3-a456-426614174000",
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    organizationAdministratorRequired: true,
    selfRevocationForbidden: true,
    serviceAccountsAndRolesMustBePreserved: true,
    creatorMustBeRevokedBeforeAuditor: true,
    creator: {
      serviceAccountId: CREATOR_ID,
      credentialPurpose: "A1_PROVIDER_CREATOR",
      exactUniqueProviderKeyName: null,
      keyNameDisposition:
        "ORG_ADMIN_MUST_RECORD_EXACT_UNIQUE_NAME_BEFORE_DELETE",
      sequence: 1
    },
    auditor: {
      serviceAccountId: AUDITOR_ID,
      credentialPurpose: "A1_PROVIDER_AUDITOR",
      exactUniqueProviderKeyName: null,
      keyNameDisposition:
        "ORG_ADMIN_MUST_RECORD_EXACT_UNIQUE_NAME_BEFORE_DELETE",
      sequence: 2
    },
    requiredProofSequence: [
      "RECORD_EXACT_CREATOR_KEY_ID_AND_UNIQUE_NAME",
      "DELETE_CREATOR_KEY",
      "PROVE_CREATOR_KEY_GET_404",
      "PROVE_CREATOR_FILTERED_KEY_LIST_ABSENCE",
      "OPTIONALLY_RETAIN_AUDITOR_FOR_INDEPENDENT_READBACK",
      "RECORD_EXACT_AUDITOR_KEY_ID_AND_UNIQUE_NAME",
      "DELETE_AUDITOR_KEY",
      "PROVE_AUDITOR_KEY_GET_404",
      "PROVE_AUDITOR_FILTERED_KEY_LIST_ABSENCE"
    ],
    ceremonyReceiptMustBindControllerReceiptSha256: true
  };
  return {
    schemaVersion: "prooftoact.fresh-cluster-controller-receipt.v1",
    status: "PROVIDER_KEYS_REVOCATION_PENDING",
    coreStatus: "PASS",
    publicDisposition: "HOLD",
    providerKeysRevoked: false,
    operationId: "123e4567-e89b-42d3-a456-426614174000",
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    commandSha256: "c".repeat(64),
    previousReceiptSha256: "d".repeat(64),
    transitionCount: 38,
    ingressEmpty: true,
    adminSqlPrincipalAbsent: true,
    adminCredentialAbsent: true,
    adminSecretCredentialRevokedByPrincipalDeletion: true,
    adminSecretVersionRetained: true,
    billingAuthorizationSha256: "1".repeat(64),
    bootstrapReceiptSha256: "2".repeat(64),
    clusterDeleteProtection: "ENABLED",
    clusterIdSha256: "3".repeat(64),
    clusterMode: "CREATE_NEW",
    controllerGeneratedRecoverySource: true,
    controllerTableArn: "arn:aws:dynamodb:us-east-1:123456789012:table/test",
    finalPrincipalCensusSha256: "4".repeat(64),
    finalProviderSqlUserInventorySha256: "5".repeat(64),
    freshClusterRetained: true,
    globalKeySha256: "6".repeat(64),
    manualClusterReceiptSha256: "7".repeat(64),
    principalLoginPostureSha256: "8".repeat(64),
    completeShowUsersPrincipalCensusSha256: "9".repeat(64),
    completeShowUsersPrincipalCountBeforeAdminDeletion: 32,
    immutableBuiltinAdminRoleExceptionPresent: true,
    noApplicationRetainedSqlAdministrator: true,
    proofToActRootConnectionStringCreated: false,
    proofToActRootConnectionStringUsed: false,
    proofToActRootPasswordCreated: false,
    proofToActRootSecretStored: false,
    rootNoLoginProvedBeforeAdminDeletion: true,
    runtimeLoginCountProvedBeforeAdminDeletion: 14,
    capabilityNoLoginCountProvedBeforeAdminDeletion: 15,
    bootstrapAdminAbsentInFinalProviderReadback: true,
    rootPresentInFinalProviderReadback: true,
    recoveryAppendReceiptSha256: "a".repeat(64),
    recoveryManagedMcpProofSha256: "b".repeat(64),
    recoveryManagedMcpRequestSha256: "c".repeat(64),
    recoveryPreparationReceiptSha256: "d".repeat(64),
    recoveryPublicationInputsCommittedBeforeAdminDeletion: true,
    recoveryReplayReceiptSha256: "e".repeat(64),
    recoverySourceBootstrapAdminUsed: true,
    recoverySourceReceiptSha256: "f".repeat(64),
    sqlClusterIdSha256: "0".repeat(64),
    primaryClusterMapping: {},
    primaryClusterMappingReceiptSha256: "1".repeat(64),
    privateRecoveryQueryBinding: {},
    privateRecoveryQueryBindingSha256: "2".repeat(64),
    separateTeardownApprovalRequired: true,
    providerKeyRevocationCeremonySha256: finalizerTest.digest(ceremony),
    providerKeyRevocationCeremony: ceremony
  };
}

function command(receipt = pendingReceipt()) {
  return buildProviderKeyRevocationCommand({
    approvedAt: OBSERVED,
    auditorKeyId: AUDITOR_KEY_ID,
    auditorKeyName: "gate2-audit-20260819",
    creatorKeyId: CREATOR_KEY_ID,
    creatorKeyName: "gate2-bootstrap-20260819",
    pendingReceipt: receipt
  });
}

function providerHarness({ ackLoss = false, ambiguous = false } = {}) {
  const keys = new Map([
    [CREATOR_KEY_ID, { id: CREATOR_KEY_ID, name: "gate2-bootstrap-20260819",
      serviceAccountId: CREATOR_ID }],
    [AUDITOR_KEY_ID, { id: AUDITOR_KEY_ID, name: "gate2-audit-20260819",
      serviceAccountId: AUDITOR_ID }]
  ]);
  const state = {
    acceptance: null,
    commandSha256: null,
    pendingControllerReceiptSha256: null,
    receipts: { creator: null, auditor: null },
    targets: { creator: null, auditor: null }
  };
  const calls = [];
  const sha = () => "a".repeat(64);
  function bind(input) {
    state.commandSha256 ??= input.command.commandSha256;
    state.pendingControllerReceiptSha256 ??=
      input.command.pendingControllerReceiptSha256;
    return structuredClone(state);
  }
  const provider = {
    async readStrong(input) {
      calls.push("readStrong");
      return bind(input);
    },
    async getServiceAccount({ serviceAccountId }) {
      calls.push(`getServiceAccount:${serviceAccountId}`);
      return {
        active: true,
        observedAt: OBSERVED,
        responseSha256: sha(serviceAccountId),
        role: serviceAccountId === CREATOR_ID ?
          "CLUSTER_OPERATOR" : "CLUSTER_DEVELOPER",
        serviceAccountId
      };
    },
    async getApiKey({ keyId, keyName, serviceAccountId }) {
      calls.push(`getApiKey:${keyId}`);
      const value = keys.get(keyId);
      return value ? {
        found: true,
        httpStatus: 200,
        keyId,
        keyName,
        observedAt: OBSERVED,
        responseSha256: sha(keyId),
        serviceAccountId
      } : {
        found: false,
        httpStatus: 404,
        keyId,
        observedAt: OBSERVED,
        responseSha256: sha(`absent-${keyId}`),
        serviceAccountId
      };
    },
    async listCompleteApiKeys({ serviceAccountId }) {
      calls.push(`listCompleteApiKeys:${serviceAccountId}`);
      return {
        complete: true,
        keyIds: [...keys.values()].filter((value) =>
          value.serviceAccountId === serviceAccountId).map(({ id }) => id),
        observedAt: OBSERVED,
        pageCount: 2,
        responseSetSha256: sha(`list-${serviceAccountId}`),
        serviceAccountId
      };
    },
    async appendIntent({ command: input, key }) {
      calls.push(`intent:${key}`);
      state.commandSha256 = input.commandSha256;
      state.pendingControllerReceiptSha256 =
        input.pendingControllerReceiptSha256;
      state.targets[key] = "INTENT_RECORDED";
      return structuredClone(state);
    },
    async appendDispatchStarted({ command: input, key }) {
      calls.push(`dispatch:${key}`);
      state.commandSha256 = input.commandSha256;
      state.pendingControllerReceiptSha256 =
        input.pendingControllerReceiptSha256;
      state.targets[key] = "DISPATCH_STARTED";
      return structuredClone(state);
    },
    async deleteApiKey({ keyId }) {
      calls.push(`delete:${keyId}`);
      if (!ambiguous) keys.delete(keyId);
      if (ackLoss || ambiguous) throw new Error("DELETE_ACK_LOST");
    },
    async appendAccepted({ absence, key }) {
      calls.push(`accepted:${key}`);
      state.targets[key] = "ABSENT_ACCEPTED";
      state.receipts[key] = `${absence.get404Sha256.slice(0, 32)}` +
        absence.completeListAbsenceSha256.slice(0, 32);
      return structuredClone(state);
    },
    async finalizeAcceptance({ receipt }) {
      calls.push("finalizeAcceptance");
      state.acceptance = structuredClone(receipt);
      return receipt;
    },
    async terminalizeUnknown() {
      calls.push("terminalizeUnknown");
      return { status: "UNKNOWN_DO_NOT_RETRY" };
    }
  };
  return { calls, keys, provider, state };
}

test("revocation proposal remains fail-closed before any provider access", async () => {
  const pending = pendingReceipt();
  const exactCommand = command(pending);
  const harness = providerHarness();
  assert.equal(exactCommand.status,
    "HOLD_REQUIRES_SEPARATE_SIGNED_ORGANIZATION_ADMIN_AUTHORIZATION");
  await assert.rejects(runProviderKeyRevocationFinalizer({
    command: exactCommand,
    pendingReceipt: pending,
    provider: harness.provider
  }), /FRESH_CLUSTER_KEY_REVOCATION_INDEPENDENT_ORG_ADMIN_AUTHORIZATION_REQUIRED/u);
  assert.deepEqual(harness.calls, []);
  assert.equal(harness.keys.has(CREATOR_KEY_ID), true);
  assert.equal(harness.keys.has(AUDITOR_KEY_ID), true);
});

test("command rejects swapped, duplicate, or malformed live key coordinates", () => {
  const pending = pendingReceipt();
  assert.throws(() => buildProviderKeyRevocationCommand({
    approvedAt: OBSERVED,
    auditorKeyId: CREATOR_KEY_ID,
    auditorKeyName: "gate2-audit-20260819",
    creatorKeyId: CREATOR_KEY_ID,
    creatorKeyName: "gate2-bootstrap-20260819",
    pendingReceipt: pending
  }), /FRESH_CLUSTER_KEY_REVOCATION_COMMAND_REJECTED/u);
});
