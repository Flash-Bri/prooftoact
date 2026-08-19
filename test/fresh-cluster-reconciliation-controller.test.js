import assert from "node:assert/strict";
import test from "node:test";

import {
  buildFreshClusterCreateCommand,
  temporarySqlAllowlistEntry
} from "../scripts/fresh-cluster-cloud-controller.js";
import {
  reconcileFreshClusterProviderAccess
} from "../scripts/fresh-cluster-reconciliation-controller.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const FOLDER_ID = "323e4567-e89b-42d3-a456-426614174002";
const CREATOR_ID = "423e4567-e89b-42d3-a456-426614174003";
const CLUSTER_ID = "523e4567-e89b-42d3-a456-426614174004";
const AUDITOR_ID = "623e4567-e89b-42d3-a456-426614174005";
const TABLE_ARN = "arn:aws:dynamodb:us-east-1:111111111111:table/" +
  "prooftoact-release-controller";
const NOW = Date.parse("2026-08-19T10:00:00.000Z");

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

function command() {
  return buildFreshClusterCreateCommand({
    adoptedAdminPasswordSha256: "7".repeat(64),
    approvalId: APPROVAL_ID,
    approvalSha256: "c".repeat(64),
    auditorAuthorityReceiptSha256: "1".repeat(64),
    auditorServiceAccountId: AUDITOR_ID,
    auditorTokenValueSha256: "2".repeat(64),
    billingAuthorization: billingAuthorization(),
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    controllerTableArn: TABLE_ARN,
    creatorAuthorityReceiptSha256: "d".repeat(64),
    creatorProviderReadbackReceiptSha256: "e".repeat(64),
    creatorServiceAccountId: CREATOR_ID,
    creatorTokenValueSha256: "f".repeat(64),
    manualClusterReceiptSha256: "8".repeat(64),
    operationId: OPERATION_ID,
    parentFolderId: "root",
    providerClusterId: CLUSTER_ID,
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40)
  });
}

function cluster(input) {
  return {
    id: CLUSTER_ID,
    name: "prooftoact-gate2",
    cloud_provider: "AWS",
    plan: "BASIC",
    parent_id: input.parentFolderId,
    creator_id: CREATOR_ID,
    created_at: "2026-08-18T08:00:00.000Z",
    delete_protection: "ENABLED",
    cockroach_version: "v26.2.1",
    state: "CREATED",
    operation_status: "UNSPECIFIED",
    labels: input.createRequest.spec.labels,
    regions: [{
      name: "us-east-1",
      node_count: 0,
      sql_dns: "fresh.aws.cockroachlabs.cloud"
    }],
    config: { serverless: {
      routing_id: "prooftoact-gate2-1234",
      upgrade_type: "AUTOMATIC",
      usage_limits: {
        request_unit_limit: "5000000",
        storage_mib_limit: "1024"
      }
    } },
    sql_dns: "fresh.aws.cockroachlabs.cloud"
  };
}

function snapshot(name, values) {
  return {
    [name]: values,
    asOfTime: new Date(NOW).toISOString(),
    complete: true,
    pageCount: 1,
    ...(name === "allowlist" ? { propagating: false } : {})
  };
}

function harness({ adminDeleteFails = false, finalReceipt = null,
  terminalReceipt = null } = {}) {
  const input = command();
  const initial = {
    phase: "INGRESS_CREATE_DISPATCHING"
  };
  const stored = {
    finalReceipt,
    lastReceiptSha256: "3".repeat(64),
    state: initial.phase,
    terminalReceipt,
    transitionCount: 1,
    transitions: [initial],
    version: terminalReceipt || finalReceipt ? 3 : 2
  };
  let users = ["prooftoact_bootstrap_admin", "tp_gate2_authorizer_user"];
  let allowlist = [temporarySqlAllowlistEntry({
    operationId: OPERATION_ID,
    ipv4: "8.8.8.8"
  })];
  let failAdmin = adminDeleteFails;
  const calls = [];
  const provider = {
    async readStrong() {
      calls.push("readStrong");
      return stored;
    },
    async authenticateRecovery() {
      calls.push("authenticateRecovery");
      return {
        status: "AUTHENTICATED_PROVIDER_READBACK",
        adminSecretState: "SEALED",
        providerBacked: true
      };
    },
    async appendTransition({ transition }) {
      assert.equal(transition.sequence, stored.transitionCount);
      stored.transitions.push(transition);
      stored.transitionCount += 1;
      stored.lastReceiptSha256 = "4".repeat(64);
      stored.state = transition.phase;
      stored.version += 1;
      return transition;
    },
    async terminalize({ terminal }) {
      stored.terminalReceipt = terminal;
      return terminal;
    }
  };
  const runtime = {
    async waitForFreshClusterCreated() {
      calls.push("waitForFreshClusterCreated");
      return cluster(input);
    },
    async listCompleteSqlUsers() {
      calls.push("listCompleteSqlUsers");
      return snapshot("users", users.map((name) => ({ name })));
    },
    async deleteSqlAdmin() {
      calls.push("deleteSqlAdmin");
      if (failAdmin) throw new Error("ADMIN_DELETE_UNAVAILABLE");
      users = users.filter((name) => name !== "prooftoact_bootstrap_admin");
    },
    async listCompleteAllowlist() {
      calls.push("listCompleteAllowlist");
      return snapshot("allowlist", [...allowlist]);
    },
    async deleteTemporaryIngress() {
      calls.push("deleteTemporaryIngress");
      allowlist = [];
    }
  };
  return {
    calls,
    command: input,
    provider,
    runtime,
    stored,
    allowAdminRetry() { failAdmin = false; }
  };
}

test("post-expiry cleanup revokes exact admin and /32 without replay", async () => {
  const value = harness();
  assert.equal(NOW >= Date.parse(
    value.command.billingAuthorization.approvalExpiresAt
  ), true);
  const receipt = await reconcileFreshClusterProviderAccess({
    clock: () => NOW,
    command: value.command,
    provider: value.provider,
    runtime: value.runtime
  });
  assert.equal(receipt.status, "FAILED_CLUSTER_RETAINED_ACCESS_REVOKED");
  assert.equal(receipt.adminSqlPrincipalAbsent, true);
  assert.equal(receipt.ingressEmpty, true);
  assert.equal(value.calls.filter((item) => item === "deleteSqlAdmin").length, 1);
  assert.equal(value.calls.filter((item) =>
    item === "deleteTemporaryIngress").length, 1);
  assert.equal(value.calls.some((item) => [
    "createCluster", "createSqlAdmin", "runFreshPrimaryBootstrap"
  ].includes(item)), false);
});

test("ambiguous cleanup stays nonterminal and a later retry completes", async () => {
  const value = harness({ adminDeleteFails: true });
  await assert.rejects(reconcileFreshClusterProviderAccess({
    clock: () => NOW,
    command: value.command,
    provider: value.provider,
    runtime: value.runtime
  }), /FRESH_CLUSTER_CLEANUP_PENDING_RETRY_REQUIRED/u);
  assert.equal(value.stored.terminalReceipt, null);
  value.allowAdminRetry();
  const receipt = await reconcileFreshClusterProviderAccess({
    clock: () => NOW,
    command: value.command,
    provider: value.provider,
    runtime: value.runtime
  });
  assert.equal(receipt.adminCredentialAbsent, true);
  assert.equal(receipt.ingressEmpty, true);
});

test("only PASS or a clean-access terminal can fast-return", async () => {
  const pass = { status: "PASS" };
  const completed = harness({ finalReceipt: pass });
  assert.equal(await reconcileFreshClusterProviderAccess({
    command: completed.command,
    provider: completed.provider,
    runtime: completed.runtime
  }), pass);
  assert.deepEqual(completed.calls, ["readStrong"]);

  const unsafe = harness({ terminalReceipt: {
    status: "FAILED_CLEANUP_AMBIGUOUS_DO_NOT_RETRY",
    adminCredentialAbsent: false,
    adminSqlPrincipalAbsent: false,
    ingressEmpty: false
  } });
  await assert.rejects(reconcileFreshClusterProviderAccess({
    command: unsafe.command,
    provider: unsafe.provider,
    runtime: unsafe.runtime
  }), /FRESH_CLUSTER_RECONCILIATION_UNSAFE_TERMINAL_REJECTED/u);
  assert.deepEqual(unsafe.calls, ["readStrong"]);
});
