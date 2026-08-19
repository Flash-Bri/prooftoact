import assert from "node:assert/strict";
import test from "node:test";

import { FRESH_PRIMARY_RUNTIME_USERS } from
  "../scripts/bootstrap-fresh-primary.js";
import {
  buildFreshClusterCreateCommand
} from "../scripts/fresh-cluster-cloud-controller.js";
import {
  __test,
  runFreshClusterProviderController,
  validateFinalRuntimePrincipalCensus
} from "../scripts/fresh-cluster-provider-controller.js";
import {
  generateFreshRecoveryPublisherSecret
} from "../scripts/lib/fresh-recovery-publisher-key.js";
import {
  buildPrivateRecoveryQueryBinding
} from "../scripts/lib/private-recovery-query-binding.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const FOLDER_ID = "323e4567-e89b-42d3-a456-426614174002";
const CREATOR_ID = "423e4567-e89b-42d3-a456-426614174003";
const CLUSTER_ID = "523e4567-e89b-42d3-a456-426614174004";
const AUDITOR_ID = "623e4567-e89b-42d3-a456-426614174005";
const SQL_CLUSTER_ID = "723e4567-e89b-42d3-a456-426614174006";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const TABLE_ARN =
  "arn:aws:dynamodb:us-east-1:111111111111:table/" +
  "prooftoact-release-controller";
const SQL_DNS = "fresh.aws.cockroachlabs.cloud";
const PASSWORD = "Z".repeat(40);
const START_MS = Date.parse("2026-08-19T08:00:00.000Z");
const RECOVERY_CLUSTER_ID = "d23e4567-e89b-42d3-a456-42661417400c";
const QUERY_SIGNER = generateFreshRecoveryPublisherSecret({
  operationId: OPERATION_ID,
  sourceCommit: SOURCE_COMMIT,
  treeDigest: TREE_DIGEST
});
const QUERY_TRUST_ROOT = JSON.parse(QUERY_SIGNER.trustRootJson);

function billingAuthorization() {
  return {
    schemaVersion: "prooftoact.fresh-cluster-billing-authorization.v1",
    status: "AUTHORIZED_PAID_WORST_CASE",
    pricingSource: "https://www.cockroachlabs.com/pricing/",
    pricingObservedAt: "2026-08-19T08:00:00.000Z",
    pricingSourceSha256: "9".repeat(64),
    authorizedAt: "2026-08-19T07:59:00.000Z",
    authorizedMonthlyCeilingUsd: "2.00",
    authorizationReceiptSha256: "8".repeat(64),
    approvalExpiresAt: "2026-08-19T09:00:00.000Z",
    retentionDeadline: "2026-08-19T20:00:00.000Z",
    requestUnitLimit: "5000000",
    storageMiBLimit: "1024",
    requestUnitPriceUsdPerMillion: "0.20",
    storagePriceUsdPerGiBMonth: "0.50",
    freeBenefitsAssumed: false,
    paidWorstCaseMonthlyUsd: "1.50",
    clusterCreateApproved: true,
    separateTeardownApprovalRequired: true
  };
}

function command(overrides = {}) {
  return buildFreshClusterCreateCommand({
    adoptedAdminPasswordSha256: null,
    approvalId: APPROVAL_ID,
    approvalSha256: "c".repeat(64),
    auditorAuthorityReceiptSha256: "1".repeat(64),
    auditorServiceAccountId: AUDITOR_ID,
    auditorTokenValueSha256: "2".repeat(64),
    billingAuthorization: billingAuthorization(),
    clusterMode: "CREATE_NEW",
    controllerTableArn: TABLE_ARN,
    creatorAuthorityReceiptSha256: "d".repeat(64),
    creatorProviderReadbackReceiptSha256: "e".repeat(64),
    creatorServiceAccountId: CREATOR_ID,
    creatorTokenValueSha256: "f".repeat(64),
    manualClusterReceiptSha256: null,
    operationId: OPERATION_ID,
    parentFolderId: FOLDER_ID,
    providerClusterId: null,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    ...overrides
  });
}

function cluster(input = command()) {
  return {
    id: CLUSTER_ID,
    name: "prooftoact-gate2",
    cloud_provider: "AWS",
    plan: "BASIC",
    parent_id: input.parentFolderId,
    creator_id: CREATOR_ID,
    created_at: input.clusterMode === "CREATE_NEW"
      ? "2026-08-19T08:00:02.000Z"
      : "2026-08-18T20:00:00.000Z",
    delete_protection: "ENABLED",
    cockroach_version: "v26.2.1",
    state: "CREATED",
    operation_status: "UNSPECIFIED",
    labels: input.createRequest.spec.labels,
    regions: [{
      name: "us-east-1",
      node_count: 0,
      sql_dns: SQL_DNS
    }],
    config: { serverless: {
      routing_id: "prooftoact-gate2-1234",
      upgrade_type: "AUTOMATIC",
      usage_limits: {
        request_unit_limit: "5000000",
        storage_mib_limit: "1024"
      }
    } },
    sql_dns: SQL_DNS
  };
}

function authentication(input) {
  return {
    schemaVersion: "prooftoact.fresh-cluster-authentication.v1",
    status: "AUTHENTICATED_PROVIDER_READBACK",
    adminSecretState: "ABSENT",
    auditorAuthorityEvidenceSha256: "1".repeat(64),
    auditorServiceAccountId: AUDITOR_ID,
    billingAuthorizationSha256: input.billingAuthorizationSha256,
    controllerTableArn: TABLE_ARN,
    controllerTableReadbackSha256: "e".repeat(64),
    creatorAuthorityEvidenceSha256: "d".repeat(64),
    creatorReadbackSha256: "f".repeat(64),
    creatorServiceAccountId: CREATOR_ID,
    observedAt: "2026-08-19T08:00:00.000Z",
    providerBacked: true
  };
}

function bootstrapReceipt(input) {
  return {
    schemaVersion: "prooftoact.fresh-primary-bootstrap-receipt.v3",
    status: "PASS",
    approvalId: APPROVAL_ID,
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    provider: { clusterIdSha256: __test.textDigest(SQL_CLUSTER_ID) },
    credentialLifecycle: {
      adminUrlLocalCopyDiscardedBeforeMutation: true,
      providerReadbackAuthenticatedByThisModule: false,
      recoveryPublisher: {
        publisherKeyIdSha256:
          __test.textDigest(QUERY_TRUST_ROOT.publisherKeyId),
        publisherKeySetDigest: QUERY_SIGNER.publisherKeySetDigest,
        signerSecretArnSha256: "1".repeat(64),
        signerSecretSealReceiptSha256: "5".repeat(64),
        signerSecretValueSha256: "6".repeat(64),
        signerSecretVersionIdSha256: "2".repeat(64),
        trustRootCommitment: QUERY_SIGNER.trustRootCommitment,
        trustRootJsonSha256: QUERY_SIGNER.trustRootJsonSha256
      }
    },
    bootstrap: {
      finalPostureDigest: "3".repeat(64),
      managedRoleCount: 29
    },
    postflight: {
      directPrivateTableAccessDenied: true,
      runtimeIdentity: "tp_gate2_authorizer_user"
    },
    partialFailureDisposition:
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD",
    inputSha256: input.commandSha256
  };
}

function recoveryCommit(bundleDigest, observation = "direct_ack") {
  return {
    schemaVersion: "tideproof.database-commit-result.v1",
    status: "COMMITTED",
    operation: "recovery_publication",
    operationDigest: bundleDigest,
    observation,
    databaseNow: "2026-08-19T08:00:18.000Z",
    outcome: "bundle_present",
    authority: { current: null, requiresFreshAuthorization: true },
    reason: null
  };
}

function recoveryPreparation(primaryClusterMapping, input) {
  const sourceBinding = {
    authorityEvidenceBindingSha256: "a".repeat(64),
    evidenceId: "823e4567-e89b-42d3-a456-426614174007",
    incidentId: "923e4567-e89b-42d3-a456-426614174008",
    operationId: OPERATION_ID,
    requestDigest: "b".repeat(64),
    resourceId: `prooftoact-fresh-recovery-${OPERATION_ID}`,
    runId: "a23e4567-e89b-42d3-a456-426614174009",
    selectedEvidenceBindingSha256: "c".repeat(64),
    tenantId: "b23e4567-e89b-42d3-a456-42661417400a"
  };
  const sourceReceipt = {
    schemaVersion: "prooftoact.fresh-recovery-source-receipt.v1",
    status: "PASS",
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    authorityOutcome: "resource_reserved",
    dviPolicyVersion: "g1-admissibility-v2",
    durableAuthorityReceipt: true,
    evidenceDigest: "d".repeat(64),
    evidenceVerified: true,
    sourceBinding,
    sourceBindingSha256: __test.digest(sourceBinding)
  };
  const preparationReceipt = {
    schemaVersion:
      "prooftoact.fresh-recovery-publication-preparation.v1",
    status: "PREPARED",
    authorityTransferred: false,
    bundleDigest: "e".repeat(64),
    persistenceReceiptSha256: "f".repeat(64),
    publisherKeySetDigest: QUERY_SIGNER.publisherKeySetDigest,
    recoverySessionId: "c23e4567-e89b-42d3-a456-42661417400b",
    requiresFreshAuthorization: true,
    sourceDigest: "0".repeat(64),
    sourceReceiptSha256: "1".repeat(64)
  };
  preparationReceipt.privateRecoveryQueryBinding =
    buildPrivateRecoveryQueryBinding({
      billingAuthorizationSha256: input.billingAuthorizationSha256,
      expectedBundleDigest: preparationReceipt.bundleDigest,
      expectedSourceClusterId: CLUSTER_ID,
      expectedSourceSqlClusterId: SQL_CLUSTER_ID,
      expiresAt: "2026-08-19T08:30:00.000Z",
      operationId: OPERATION_ID,
      primaryClusterMapping,
      primaryClusterMappingReceiptSha256:
        primaryClusterMapping.receiptSha256,
      publisherKeyId: QUERY_TRUST_ROOT.publisherKeyId,
      publisherPublicKeySpkiBase64:
        QUERY_TRUST_ROOT.publicKeySpkiBase64,
      recoveryClusterId: RECOVERY_CLUSTER_ID,
      recoverySessionId: preparationReceipt.recoverySessionId,
      sourceCommit: SOURCE_COMMIT,
      sourceCommitTs: "2026-08-19T08:00:16.000Z",
      sourceDigest: preparationReceipt.sourceDigest,
      subjectBindingHash: "4".repeat(64),
      tenantId: sourceBinding.tenantId,
      treeDigest: TREE_DIGEST
    });
  preparationReceipt.privateRecoveryQueryBindingSha256 =
    preparationReceipt.privateRecoveryQueryBinding.bindingSha256;
  return {
    schemaVersion: "prooftoact.fresh-recovery-source-and-preparation.v1",
    status: "PREPARED",
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    sourceReceipt,
    sourceReceiptSha256: __test.digest(sourceReceipt),
    preparationReceipt,
    preparationReceiptSha256: __test.digest(preparationReceipt)
  };
}

function recoveryMcpPlan(preparation) {
  return {
    schemaVersion:
      "prooftoact.fresh-recovery-publication-mcp-plan.v1",
    status: "PLANNED_READ_ONLY_QUERY",
    bundleDigest: preparation.preparationReceipt.bundleDigest,
    database: "tideproof_recovery",
    logicalRequestSha256: "2".repeat(64),
    querySha256: "3".repeat(64),
    recoveryClusterId: RECOVERY_CLUSTER_ID,
    recoverySessionId:
      preparation.preparationReceipt.recoverySessionId,
    sourceDigest: preparation.preparationReceipt.sourceDigest,
    subjectBindingSha256: "4".repeat(64),
    tenantId: preparation.sourceReceipt.sourceBinding.tenantId,
    toolName: "select_query"
  };
}

function createHarness({
  ackLoss = false,
  adopt = false,
  bootstrapFailure = false,
  cleanupFailure = false,
  ingressReadbackFailureAfterCreate = false,
  mcpFailure = false
} = {}) {
  const input = command(adopt ? {
    adoptedAdminPasswordSha256: "7".repeat(64),
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    manualClusterReceiptSha256: "8".repeat(64),
    parentFolderId: "root",
    providerClusterId: CLUSTER_ID
  } : {});
  const transitions = [];
  const calls = [];
  let allowlist = [];
  let users = adopt ? ["prooftoact_bootstrap_admin"] : [];
  let terminal;
  let sealedAdmin;
  let ingressReadbackFailed = false;
  let preparedRecovery;
  let reserved = false;
  let tick = 0;
  const clock = () => START_MS + tick++ * 1000;
  const provider = {
    async authenticate() {
      return authentication(input);
    },
    async readStrong() {
      if (!reserved) return null;
      const latest = transitions.at(-1);
      return {
        command: input,
        finalReceipt: null,
        lastReceiptSha256: __test.digest(latest),
        reservation: {},
        state: latest.phase,
        terminalReceipt: null,
        transitionCount: transitions.length,
        transitions: [...transitions],
        version: latest.version
      };
    },
    async reserve({ authentication: accepted }) {
      reserved = true;
      return {
        schemaVersion: "prooftoact.fresh-cluster-reservation.v1",
        status: "RESERVED_BEFORE_PROVIDER_IDENTIFIERS",
        authenticationSha256: __test.digest(accepted),
        commandSha256: input.commandSha256,
        controllerTableArn: TABLE_ARN,
        durable: true,
        globalKeySha256: input.globalKeySha256,
        globallyAuthoritative: true,
        operationId: OPERATION_ID,
        reservedAt: "2026-08-19T08:00:01.000Z",
        version: 1
      };
    },
    async appendTransition({ transition }) {
      transitions.push(transition);
      return transition;
    },
    async finalize({ receipt }) {
      return receipt;
    },
    async terminalize({ terminal: value }) {
      terminal = value;
      return value;
    }
  };
  const phaseExists = (phase) => transitions.some((item) =>
    item.phase === phase);
  const runtime = {
    async createCluster() {
      calls.push("createCluster");
      assert.equal(phaseExists("CLUSTER_CREATE_DISPATCHING"), true);
      if (ackLoss) throw new Error("CREATE_ACK_LOST");
      return cluster(input);
    },
    async listCompleteClusters({ asOfTime }) {
      return {
        clusters: [cluster(input)],
        asOfTime,
        complete: true,
        pageCount: 1
      };
    },
    async waitForFreshClusterCreated() {
      return cluster(input);
    },
    async getCreatorRoles() {
      return { roles: [
        ...(adopt ? [] : [{
          name: "CLUSTER_CREATOR",
          resource: { id: FOLDER_ID, type: "FOLDER" }
        }]),
        {
          name: adopt ? "CLUSTER_OPERATOR" : "CLUSTER_ADMIN",
          resource: { id: CLUSTER_ID, type: "CLUSTER" }
        }
      ] };
    },
    async observeRunnerPublicIpv4() {
      return {
        ipv4: "8.8.8.8",
        ipv4Sha256: "4".repeat(64),
        sourceCount: 2,
        sourcesSha256: "5".repeat(64)
      };
    },
    async listCompleteAllowlist({ asOfTime }) {
      if (ingressReadbackFailureAfterCreate && allowlist.length === 1 &&
        !ingressReadbackFailed) {
        ingressReadbackFailed = true;
        throw new Error("INGRESS_READBACK_INTERRUPTED");
      }
      return {
        allowlist: [...allowlist],
        asOfTime,
        complete: true,
        pageCount: 1,
        propagating: false
      };
    },
    async addTemporaryIngress({ entry }) {
      calls.push("addTemporaryIngress");
      assert.equal(phaseExists("INGRESS_CREATE_DISPATCHING"), true);
      allowlist = [entry];
      if (ackLoss) throw new Error("INGRESS_ACK_LOST");
      return entry;
    },
    async prepareAdminCredential() {
      const connectionString =
        `postgresql://prooftoact_bootstrap_admin:${PASSWORD}` +
        `@${SQL_DNS}:` +
        "26257/defaultdb?sslmode=verify-full";
      return {
        connectionString,
        connectionStringSha256: __test.textDigest(connectionString),
        password: PASSWORD,
        passwordSha256: __test.textDigest(PASSWORD),
        username: "prooftoact_bootstrap_admin"
      };
    },
    async sealAdminSecret({ credential }) {
      calls.push("sealAdminSecret");
      assert.equal(phaseExists("ADMIN_SECRET_DISPATCHING"), true);
      sealedAdmin = {
        schemaVersion: "prooftoact.fresh-cluster-admin-seal.v1",
        status: "SEALED",
        createdAt: "2026-08-19T08:00:10.000Z",
        immutableVersion: true,
        operationId: OPERATION_ID,
        provider: "AWS_SECRETS_MANAGER",
        providerBacked: true,
        secretArnSha256: "6".repeat(64),
        secretValueSha256: credential.connectionStringSha256,
        secretVersionIdSha256: "7".repeat(64)
      };
      if (ackLoss) throw new Error("ADMIN_SECRET_ACK_LOST");
      return sealedAdmin;
    },
    async readAdminSecret() {
      assert.ok(sealedAdmin);
      return sealedAdmin;
    },
    async discardLocalAdminCredential() {
      calls.push("discardLocalAdminCredential");
      assert.equal(phaseExists("LOCAL_ADMIN_CREDENTIAL_DISCARDING"), true);
      assert.equal(phaseExists("ADMIN_CREATE_DISPATCHING"), false);
      assert.equal(phaseExists("BOOTSTRAP_DISPATCHING"), false);
      return true;
    },
    async listCompleteSqlUsers({ asOfTime }) {
      return {
        users: users.map((name) => ({ name })),
        asOfTime,
        complete: true,
        pageCount: 1
      };
    },
    async createSqlAdmin({ username }) {
      calls.push("createSqlAdmin");
      assert.equal(phaseExists("ADMIN_CREATE_DISPATCHING"), true);
      users.push(username);
      if (ackLoss) throw new Error("ADMIN_ACK_LOST");
      return { name: username };
    },
    async authenticateSqlAdmin() {
      return {
        schemaVersion:
          "prooftoact.fresh-cluster-admin-authentication.v1",
        status: "AUTHENTICATED",
        database: "defaultdb",
        observedAt: "2026-08-19T08:00:15.000Z",
        port: "26257",
        providerBacked: true,
        providerClusterId: CLUSTER_ID,
        sqlClusterId: SQL_CLUSTER_ID,
        username: "prooftoact_bootstrap_admin"
      };
    },
    async runFreshPrimaryBootstrap() {
      calls.push("runFreshPrimaryBootstrap");
      assert.equal(phaseExists("BOOTSTRAP_DISPATCHING"), true);
      if (bootstrapFailure) throw new Error("FRESH_PRIMARY_TEST_FAILURE");
      users.push(...FRESH_PRIMARY_RUNTIME_USERS);
      return bootstrapReceipt(input);
    },
    async prepareFreshRecoveryPublication({ primaryClusterMapping }) {
      calls.push("prepareFreshRecoveryPublication");
      assert.equal(phaseExists(
        "RECOVERY_SOURCE_AND_PREPARATION_DISPATCHING"
      ), true);
      preparedRecovery = recoveryPreparation(primaryClusterMapping, input);
      return preparedRecovery;
    },
    async appendFreshRecoveryPublication() {
      calls.push("appendFreshRecoveryPublication");
      assert.equal(phaseExists(
        "RECOVERY_PUBLICATION_APPEND_DISPATCHING"
      ), true);
      const preparation = preparedRecovery;
      assert.ok(preparation);
      return {
        schemaVersion: "prooftoact.fresh-recovery-publication-append.v1",
        status: "CONFIRMED",
        bundleDigest: preparation.preparationReceipt.bundleDigest,
        commit: recoveryCommit(preparation.preparationReceipt.bundleDigest),
        outcome: "bundle_appended"
      };
    },
    async replayFreshRecoveryPublication() {
      calls.push("replayFreshRecoveryPublication");
      assert.equal(phaseExists(
        "RECOVERY_PUBLICATION_REPLAY_DISPATCHING"
      ), true);
      const preparation = preparedRecovery;
      assert.ok(preparation);
      return {
        schemaVersion: "prooftoact.fresh-recovery-publication-replay.v1",
        status: "CONFIRMED_REPLAY",
        bundleDigest: preparation.preparationReceipt.bundleDigest,
        commit: recoveryCommit(preparation.preparationReceipt.bundleDigest),
        outcome: "bundle_replay"
      };
    },
    async planFreshRecoveryManagedMcp() {
      calls.push("planFreshRecoveryManagedMcp");
      assert.ok(preparedRecovery);
      return recoveryMcpPlan(preparedRecovery);
    },
    async verifyFreshRecoveryManagedMcp({
      beforeExternalAction,
      durablePlanReadbackSha256,
      plannedRequestSha256
    }) {
      calls.push("verifyFreshRecoveryManagedMcp");
      for (const externalAction of [
        "MCP_INITIALIZE",
        "MCP_INITIALIZED_NOTIFICATION",
        "MCP_TOOLS_CALL",
        "MCP_SESSION_DELETE"
      ]) {
        const guard = await beforeExternalAction({
          externalAction,
          plannedRequestSha256
        });
        assert.equal(guard.status,
          "DURABLE_PLAN_STRONGLY_RECONCILED");
      }
      if (mcpFailure) throw new Error("MCP_RESPONSE_AMBIGUOUS");
      const preparation = preparedRecovery;
      assert.ok(preparation);
      const plan = recoveryMcpPlan(preparation);
      return {
        schemaVersion:
          "prooftoact.fresh-recovery-publication-mcp-proof.v1",
        status: "RECOVERED_CONTEXT_ONLY",
        authorityTransferred: false,
        bundleDigest: plan.bundleDigest,
        closeSessionEvidenceSha256: "5".repeat(64),
        dispatchGuardReceiptSetSha256: "6".repeat(64),
        durablePlanReadbackSha256,
        externalActionSequenceSha256: "7".repeat(64),
        managedMcpSemanticEvidenceSha256: "8".repeat(64),
        managedMcpTransportEvidenceSha256: "9".repeat(64),
        plannedRequestSha256,
        querySha256: plan.querySha256,
        requiresFreshAuthorization: true,
        rowSha256: "a".repeat(64)
      };
    },
    async deleteSqlAdmin({ username }) {
      calls.push("deleteSqlAdmin");
      assert.equal(phaseExists("ADMIN_DELETE_DISPATCHING"), true);
      if (cleanupFailure) throw new Error("ADMIN_DELETE_UNAVAILABLE");
      users = users.filter((name) => name !== username);
      if (ackLoss) throw new Error("ADMIN_DELETE_ACK_LOST");
      return { name: username };
    },
    async deleteTemporaryIngress() {
      calls.push("deleteTemporaryIngress");
      assert.equal(phaseExists("INGRESS_DELETE_DISPATCHING"), true);
      if (cleanupFailure) throw new Error("INGRESS_DELETE_UNAVAILABLE");
      allowlist = [];
      if (ackLoss) throw new Error("INGRESS_DELETE_ACK_LOST");
      return { deleted: true };
    }
  };
  return {
    calls,
    clock,
    command: input,
    getTerminal: () => terminal,
    provider,
    runtime,
    transitions
  };
}

test("fresh cluster lifecycle journals every mutation and cleans temporary access", async () => {
  const harness = createHarness();
  const receipt = await runFreshClusterProviderController(harness);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.adminCredentialAbsent, true);
  assert.equal(receipt.adminSecretVersionRetained, true);
  assert.equal(receipt.adminSecretCredentialRevokedByPrincipalDeletion, true);
  assert.equal(receipt.adminSqlPrincipalAbsent, true);
  assert.equal(receipt.ingressEmpty, true);
  assert.equal(receipt.freshClusterRetained, true);
  assert.equal(receipt.separateTeardownApprovalRequired, true);
  assert.equal(receipt.privateRecoveryQueryBinding.bindingSha256,
    receipt.privateRecoveryQueryBindingSha256);
  assert.equal(receipt.privateRecoveryQueryBinding.expectedSourceClusterId,
    CLUSTER_ID);
  assert.equal(receipt.privateRecoveryQueryBinding.expectedSourceSqlClusterId,
    SQL_CLUSTER_ID);
  assert.equal(receipt.privateRecoveryQueryBinding.
    primaryClusterMappingReceiptSha256,
  receipt.primaryClusterMappingReceiptSha256);
  assert.deepEqual(harness.transitions.filter((item) =>
    item.mutationDispatched).map((item) => item.phase), [
    "CLUSTER_CREATE_DISPATCHING",
    "INGRESS_CREATE_DISPATCHING",
    "ADMIN_SECRET_DISPATCHING",
    "ADMIN_CREATE_DISPATCHING",
    "BOOTSTRAP_DISPATCHING",
    "RECOVERY_SOURCE_AND_PREPARATION_DISPATCHING",
    "RECOVERY_PUBLICATION_APPEND_DISPATCHING",
    "RECOVERY_PUBLICATION_REPLAY_DISPATCHING",
    "ADMIN_DELETE_DISPATCHING",
    "INGRESS_DELETE_DISPATCHING"
  ]);
  assert.equal(harness.getTerminal(), undefined);
});

test("acknowledgement loss reconciles exact inventory and never retries mutation", async () => {
  const harness = createHarness({ ackLoss: true });
  const receipt = await runFreshClusterProviderController(harness);
  assert.equal(receipt.status, "PASS");
  for (const name of [
    "createCluster",
    "addTemporaryIngress",
    "createSqlAdmin",
    "deleteSqlAdmin",
    "deleteTemporaryIngress"
  ]) {
    assert.equal(harness.calls.filter((item) => item === name).length, 1);
  }
  assert.equal(harness.transitions.some((item) =>
    item.phase === "CLUSTER_CREATE_ACKNOWLEDGEMENT_RECONCILED"), true);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "ADMIN_SECRET_ACKNOWLEDGEMENT_RECONCILED"), true);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "INGRESS_DELETE_ACKNOWLEDGEMENT_RECONCILED"), true);
});

test("verified existing cluster is adopted without replaying create or admin create", async () => {
  const harness = createHarness({ adopt: true });
  const receipt = await runFreshClusterProviderController(harness);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.clusterMode, "ADOPT_VERIFIED_EXISTING");
  assert.equal(receipt.manualClusterReceiptSha256, "8".repeat(64));
  assert.equal(harness.calls.includes("createCluster"), false);
  assert.equal(harness.calls.includes("createSqlAdmin"), false);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "CLUSTER_ADOPTION_OBSERVED"), true);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "ADOPTED_ADMIN_USER_PRESTATE_PRESENT"), true);
});

test("bootstrap failure durably deletes admin and ingress but retains cluster", async () => {
  const harness = createHarness({ bootstrapFailure: true });
  await assert.rejects(
    runFreshClusterProviderController(harness),
    /FRESH_PRIMARY_TEST_FAILURE/u
  );
  assert.equal(harness.calls.filter((item) =>
    item === "deleteSqlAdmin").length, 1);
  assert.equal(harness.calls.filter((item) =>
    item === "deleteTemporaryIngress").length, 1);
  assert.equal(harness.getTerminal().adminCredentialAbsent, true);
  assert.equal(harness.getTerminal().adminSqlPrincipalAbsent, true);
  assert.equal(harness.getTerminal().ingressEmpty, true);
  assert.equal(harness.getTerminal().separateTeardownApprovalRequired, true);
  assert.equal(harness.calls.includes("deleteCluster"), false);
});

test("failed post-create ingress readback still deletes the possible /32", async () => {
  const harness = createHarness({ ingressReadbackFailureAfterCreate: true });
  await assert.rejects(
    runFreshClusterProviderController(harness),
    /INGRESS_READBACK_INTERRUPTED/u
  );
  assert.equal(harness.calls.filter((item) =>
    item === "addTemporaryIngress").length, 1);
  assert.equal(harness.calls.filter((item) =>
    item === "deleteTemporaryIngress").length, 1);
  assert.equal(harness.getTerminal().ingressEmpty, true);
  assert.equal(harness.getTerminal().status,
    "FAILED_CLUSTER_RETAINED_NO_AUTOMATIC_TEARDOWN");
});

test("cleanup acknowledgement loss reconciles exact absence without retry", async () => {
  const harness = createHarness({ ackLoss: true, bootstrapFailure: true });
  await assert.rejects(
    runFreshClusterProviderController(harness),
    /FRESH_PRIMARY_TEST_FAILURE/u
  );
  assert.equal(harness.calls.filter((item) =>
    item === "deleteSqlAdmin").length, 1);
  assert.equal(harness.calls.filter((item) =>
    item === "deleteTemporaryIngress").length, 1);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "ADMIN_DELETE_ACKNOWLEDGEMENT_RECONCILED"), true);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "INGRESS_DELETE_ACKNOWLEDGEMENT_RECONCILED"), true);
  assert.equal(harness.getTerminal().adminCredentialAbsent, true);
  assert.equal(harness.getTerminal().ingressEmpty, true);
  assert.equal(harness.getTerminal().status,
    "FAILED_CLUSTER_RETAINED_NO_AUTOMATIC_TEARDOWN");
});

test("ambiguous cleanup remains nonterminal for cleanup-only recovery", async () => {
  const harness = createHarness({
    adopt: true,
    bootstrapFailure: true,
    cleanupFailure: true
  });
  await assert.rejects(
    runFreshClusterProviderController(harness),
    /FRESH_CLUSTER_CLEANUP_PENDING_RETRY_REQUIRED/u
  );
  assert.equal(harness.getTerminal(), undefined);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "ADMIN_DELETE_DISPATCHING"), true);
  assert.equal(harness.transitions.some((item) =>
    item.phase === "INGRESS_DELETE_DISPATCHING"), true);
});

test("ambiguous Managed MCP outcome is terminal UNKNOWN only after cleanup", async () => {
  const harness = createHarness({ mcpFailure: true });
  await assert.rejects(
    runFreshClusterProviderController(harness),
    /FRESH_RECOVERY_MANAGED_MCP_UNKNOWN_DO_NOT_RETRY/u
  );
  assert.equal(harness.calls.filter((item) =>
    item === "deleteSqlAdmin").length, 1);
  assert.equal(harness.calls.filter((item) =>
    item === "deleteTemporaryIngress").length, 1);
  assert.equal(harness.getTerminal().failureCode,
    "FRESH_RECOVERY_MANAGED_MCP_UNKNOWN_DO_NOT_RETRY");
  assert.equal(harness.getTerminal().adminSqlPrincipalAbsent, true);
  assert.equal(harness.getTerminal().ingressEmpty, true);
});

test("final provider census is exactly the fourteen runtime users", () => {
  assert.equal(validateFinalRuntimePrincipalCensus({
    schemaVersion: "prooftoact.fresh-cluster-final-principal-census.v1",
    status: "EXACT_RUNTIME_USERS",
    clusterId: SQL_CLUSTER_ID,
    names: [...FRESH_PRIMARY_RUNTIME_USERS],
    observedAt: "2026-08-19T08:00:20.000Z",
    providerBacked: true
  }).count, 14);
  assert.throws(() => validateFinalRuntimePrincipalCensus({
    schemaVersion: "prooftoact.fresh-cluster-final-principal-census.v1",
    status: "EXACT_RUNTIME_USERS",
    clusterId: SQL_CLUSTER_ID,
    names: [...FRESH_PRIMARY_RUNTIME_USERS, "unexpected"],
    observedAt: "2026-08-19T08:00:20.000Z",
    providerBacked: true
  }), /FRESH_CLUSTER_FINAL_PRINCIPAL_CENSUS_REJECTED/u);
});
