import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  buildFreshClusterCreateCommand,
  createFreshClusterCloudRuntime,
  deriveFreshPrimaryApproval,
  freshClusterCreateRequest,
  observeRunnerPublicIpv4,
  temporarySqlAllowlistEntry,
  validateFreshClusterApproval,
  validateFreshClusterCleanupApproval,
  validateFreshClusterReadback,
  validateTemporaryAllowlistReadback
} from "../scripts/fresh-cluster-cloud-controller.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const FOLDER_ID = "323e4567-e89b-42d3-a456-426614174002";
const CREATOR_ID = "423e4567-e89b-42d3-a456-426614174003";
const CLUSTER_ID = "523e4567-e89b-42d3-a456-426614174004";
const AUDITOR_ID = "823e4567-e89b-42d3-a456-426614174007";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const TOKEN = "creator-service-account-api-token";
const CALLER_WORKFLOW_REF =
  "Flash-Bri/prooftoact/.github/workflows/" +
  "prooftoact-fresh-primary.yml@refs/heads/main";

function billingAuthorization(overrides = {}) {
  return {
    schemaVersion: "prooftoact.fresh-cluster-billing-authorization.v1",
    status: "AUTHORIZED_PAID_WORST_CASE",
    pricingSource: "https://www.cockroachlabs.com/pricing/",
    pricingObservedAt: "2026-08-19T08:05:00.000Z",
    pricingSourceSha256: "9".repeat(64),
    authorizedAt: "2026-08-19T08:00:00.000Z",
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
    separateTeardownApprovalRequired: true,
    ...overrides
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
    controllerTableArn:
      "arn:aws:dynamodb:us-east-1:111111111111:table/" +
      "prooftoact-release-controller",
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

function jsonResponse(url, value) {
  const response = new Response(JSON.stringify(value), {
    headers: { "content-type": "application/json" },
    status: 200
  });
  Object.defineProperty(response, "url", { value: url });
  return response;
}

test("fresh cluster request pins Basic AWS, paid limits, labels, and empty ingress", () => {
  const request = freshClusterCreateRequest({
    operationId: OPERATION_ID,
    parentFolderId: FOLDER_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
  assert.deepEqual(request, {
    name: "prooftoact-gate2",
    provider: "AWS",
    spec: {
      delete_protection: "ENABLED",
      labels: {
        prooftoact_operation: OPERATION_ID,
        prooftoact_source: SOURCE_COMMIT,
        prooftoact_tree: TREE_DIGEST
      },
      parent_id: FOLDER_ID,
      plan: "BASIC",
      serverless: {
        regions: ["us-east-1"],
        upgrade_type: "AUTOMATIC",
        usage_limits: {
          request_unit_limit: "5000000",
          storage_mib_limit: "1024"
        },
        with_empty_ip_allowlist: true
      }
    }
  });
  assert.equal(request.spec.serverless.upgrade_type, "AUTOMATIC");
});

test("billing permits ceiling-first pricing only before expiry and under ceiling", () => {
  const accepted = command({
    billingAuthorization: billingAuthorization({
      authorizedAt: "2026-08-19T08:00:00.000Z",
      pricingObservedAt: "2026-08-19T08:05:00.000Z"
    })
  });
  assert.equal(accepted.billingAuthorization.paidWorstCaseMonthlyUsd, "1.50");
  assert.equal(accepted.billingAuthorization.authorizedMonthlyCeilingUsd,
    "2.00");
  for (const billing of [
    billingAuthorization({
      pricingObservedAt: "2026-08-19T09:00:00.001Z"
    }),
    billingAuthorization({ authorizedMonthlyCeilingUsd: "1.49" }),
    billingAuthorization({ authorizationReceiptSha256: "not-a-receipt" }),
    billingAuthorization({
      approvalExpiresAt: "2026-08-19T09:00:00.001Z"
    }),
    billingAuthorization({
      authorizedAt: "2026-08-19T08:06:00.000Z",
      pricingObservedAt: "2026-08-19T08:05:00.000Z"
    })
  ]) {
    assert.throws(() => command({ billingAuthorization: billing }),
      /FRESH_CLUSTER_BILLING_AUTHORIZATION_REJECTED/u);
  }
});

test("pre-ID global slot is stable across approvals and binds physical intent", () => {
  const first = command();
  const second = command({
    approvalId: "623e4567-e89b-42d3-a456-426614174005",
    approvalSha256: "e".repeat(64),
    operationId: "723e4567-e89b-42d3-a456-426614174006"
  });
  assert.equal(first.effectIdentitySha256, second.effectIdentitySha256);
  assert.equal(first.globalKeySha256, second.globalKeySha256);
  assert.notEqual(first.commandSha256, second.commandSha256);
  assert.match(first.globalKeySha256, /^[0-9a-f]{64}$/u);
  assert.equal(Object.hasOwn(first, "clusterId"), false);
});

test("root parent is an exact provider coordinate, never a fabricated UUID", () => {
  const adopted = command({
    adoptedAdminPasswordSha256: "7".repeat(64),
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    manualClusterReceiptSha256: "8".repeat(64),
    parentFolderId: "root",
    providerClusterId: CLUSTER_ID
  });
  assert.equal(adopted.parentFolderId, "root");
  assert.equal(adopted.createRequest.spec.parent_id, "root");
  assert.throws(() => command({ parentFolderId: "root" }),
    /FRESH_CLUSTER_COMMAND_REJECTED/u);
  assert.throws(() => command({
    adoptedAdminPasswordSha256: "7".repeat(64),
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    manualClusterReceiptSha256: "8".repeat(64),
    parentFolderId: FOLDER_ID,
    providerClusterId: CLUSTER_ID
  }), /FRESH_CLUSTER_COMMAND_REJECTED/u);
  for (const parentFolderId of [null, "ROOT", "root/"]) {
    assert.throws(() => command({ parentFolderId }),
      /FRESH_CLUSTER_COMMAND_REJECTED/u);
  }
  assert.throws(() => command({
    adoptedAdminPasswordSha256: "7".repeat(64),
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    manualClusterReceiptSha256: null,
    parentFolderId: "root",
    providerClusterId: CLUSTER_ID
  }), /FRESH_CLUSTER_COMMAND_REJECTED/u);

  const sqlDns = "prooftoact-gate2-32394.j77.aws-us-east-1." +
    "cockroachlabs.cloud";
  const liveShape = {
    id: CLUSTER_ID,
    name: "prooftoact-gate2",
    cloud_provider: "AWS",
    plan: "BASIC",
    parent_id: "root",
    creator_id: CREATOR_ID,
    delete_protection: "ENABLED",
    cockroach_version: "v26.2.5",
    created_at: "2026-08-19T00:39:00.000Z",
    state: "CREATED",
    operation_status: "UNSPECIFIED",
    labels: {},
    regions: [{
      name: "us-east-1",
      node_count: 0,
      sql_dns: sqlDns
    }],
    config: { serverless: {
      routing_id: "prooftoact-gate2-32394",
      upgrade_type: "AUTOMATIC",
      usage_limits: {
        request_unit_limit: "5000000",
        storage_mib_limit: "1024"
      }
    } },
    sql_dns: sqlDns
  };
  const time = {
    dispatchedAt: "2026-08-19T02:49:00.000Z",
    observedAt: "2026-08-19T02:49:19.000Z"
  };
  const accepted = validateFreshClusterReadback(liveShape, adopted, time);
  assert.equal(accepted.mode, "ADOPT_VERIFIED_EXISTING");
  assert.equal(accepted.manualClusterReceiptSha256, "8".repeat(64));
  for (const parent_id of [
    null,
    "ROOT",
    "623e4567-e89b-42d3-a456-426614174005"
  ]) {
    assert.throws(() => validateFreshClusterReadback({
      ...liveShape,
      parent_id
    }, adopted, time), /FRESH_CLUSTER_READBACK_REJECTED/u);
  }
});

test("outer approval safely derives only post-create primary coordinates", () => {
  const outer = {
    schemaVersion: "prooftoact.fresh-cluster-approval.v1",
    status: "APPROVED",
    action: "CREATE_AND_BOOTSTRAP_ONE_FRESH_COCKROACH_CLUSTER",
    adoptedAdminPasswordSha256: null,
    approvalId: APPROVAL_ID,
    approvedAt: "2026-08-19T08:00:00.000Z",
    approvedBy: "BRIAN_SMITH",
    auditorAuthorityReceiptSha256: "1".repeat(64),
    auditorServiceAccountId: AUDITOR_ID,
    auditorTokenValueSha256: "2".repeat(64),
    billingAuthorization: billingAuthorization(),
    callerWorkflowRef: CALLER_WORKFLOW_REF,
    callerWorkflowSha: "6".repeat(40),
    clusterMode: "CREATE_NEW",
    controllerImportGraphSha256: "7".repeat(64),
    creatorAuthorityReceiptSha256: "d".repeat(64),
    creatorProviderReadbackReceiptSha256: "e".repeat(64),
    creatorServiceAccountId: CREATOR_ID,
    creatorTokenValueSha256: "f".repeat(64),
    derivedPrimaryApprovalAuthorized: true,
    expiresAt: "2026-08-19T09:00:00.000Z",
    humanAuthorizationReceiptSha256: "8".repeat(64),
    humanAuthorizedTextSha256: "9".repeat(64),
    oneShot: true,
    operationId: OPERATION_ID,
    manualClusterReceiptSha256: null,
    parentFolderId: FOLDER_ID,
    partialFailureDisposition:
      "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_SEPARATELY_TEARDOWN",
    separateClusterTeardownApprovalRequired: true,
    sourceCommit: SOURCE_COMMIT,
    providerClusterId: null,
    sqlBootstrapPort: "26257",
    sqlBootstrapUsername: "prooftoact_bootstrap_admin",
    treeDigest: TREE_DIGEST
  };
  const accepted = validateFreshClusterApproval(outer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T08:10:00.000Z"));
  assert.throws(() => validateFreshClusterApproval({
    ...outer,
    parentFolderId: "root"
  }, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T08:10:00.000Z")),
  /FRESH_CLUSTER_APPROVAL_REJECTED/u);
  const adoptedOuter = {
    ...outer,
    adoptedAdminPasswordSha256: "7".repeat(64),
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    manualClusterReceiptSha256: "8".repeat(64),
    parentFolderId: "root",
    providerClusterId: CLUSTER_ID
  };
  assert.equal(validateFreshClusterApproval(adoptedOuter, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T08:10:00.000Z")).parentFolderId, "root");
  assert.throws(() => validateFreshClusterApproval(outer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T09:00:00.000Z")),
  /FRESH_CLUSTER_APPROVAL_REJECTED/u);
  assert.deepEqual(validateFreshClusterCleanupApproval(outer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T09:00:00.000Z")), outer);
  assert.deepEqual(validateFreshClusterCleanupApproval(outer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T19:59:59.999Z")), outer);
  assert.throws(() => validateFreshClusterCleanupApproval(outer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T20:00:00.000Z")),
  /FRESH_CLUSTER_CLEANUP_APPROVAL_REJECTED/u);
  assert.throws(() => validateFreshClusterCleanupApproval(outer, {
    operationId: OPERATION_ID,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  }, Date.parse("2026-08-19T07:59:59.999Z")),
  /FRESH_CLUSTER_CLEANUP_APPROVAL_REJECTED/u);
  const derived = deriveFreshPrimaryApproval({
    clusterApproval: accepted,
    clusterHostSha256: "1".repeat(64),
    credentialSealReceiptSha256: "2".repeat(64),
    sqlClusterId: CLUSTER_ID
  });
  assert.equal(derived.expectedClusterId, CLUSTER_ID);
  assert.equal(derived.maximumProjectedTotalUsd, 1.5);
  assert.equal(derived.approvedBy, "BRIAN_SMITH");
});

test("fresh cluster readback binds creator, time, folder, labels, limits, and region", () => {
  const input = command();
  const cluster = {
    id: CLUSTER_ID,
    name: "prooftoact-gate2",
    cloud_provider: "AWS",
    plan: "BASIC",
    parent_id: FOLDER_ID,
    creator_id: CREATOR_ID,
    delete_protection: "ENABLED",
    cockroach_version: "v26.2.1",
    created_at: "2026-08-19T08:01:00.000Z",
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
  const accepted = validateFreshClusterReadback(cluster, input, {
    dispatchedAt: "2026-08-19T08:00:00.000Z",
    observedAt: "2026-08-19T08:02:00.000Z"
  });
  assert.equal(accepted.clusterId, CLUSTER_ID);
  assert.equal(accepted.paidWorstCaseMonthlyUsd, 1.5);
  for (const drift of [
    { plan: "ADVANCED" },
    { parent_id: "root" },
    { parent_id: "623e4567-e89b-42d3-a456-426614174005" },
    { creator_id: "623e4567-e89b-42d3-a456-426614174005" },
    { delete_protection: "DISABLED" },
    { cockroach_version: "v26.1.9" },
    { created_at: "2026-08-19T07:59:59.999Z" },
    { labels: { ...cluster.labels, unexpected: "true" } },
    { regions: [{ name: "us-west-2" }] }
  ]) {
    assert.throws(() => validateFreshClusterReadback({
      ...cluster,
      ...drift
    }, input, {
      dispatchedAt: "2026-08-19T08:00:00.000Z",
      observedAt: "2026-08-19T08:02:00.000Z"
    }), /FRESH_CLUSTER_READBACK_REJECTED/u);
  }
});

test("Cloud runtime pins Cc-Version and exact POST, paged reads, and DELETE paths", async () => {
  const calls = [];
  const runtime = createFreshClusterCloudRuntime({
    async fetchImpl(url, options) {
      calls.push({ url, options });
      return jsonResponse(url, { ok: true });
    }
  });
  const createRequest = command().createRequest;
  const entry = temporarySqlAllowlistEntry({
    operationId: OPERATION_ID,
    ipv4: "8.8.8.8"
  });
  await runtime.createCluster({ createRequest, token: TOKEN });
  await runtime.getCluster({ clusterId: CLUSTER_ID, token: TOKEN });
  await runtime.createSqlAdmin({
    clusterId: CLUSTER_ID,
    password: "x".repeat(40),
    token: TOKEN,
    username: "prooftoact_bootstrap_admin"
  });
  await runtime.listSqlUsersPage({
    asOfTime: "2026-08-19T08:02:00.000Z",
    clusterId: CLUSTER_ID,
    token: TOKEN
  });
  await runtime.addTemporaryIngress({ clusterId: CLUSTER_ID, entry,
    token: TOKEN });
  await runtime.listAllowlistPage({
    asOfTime: "2026-08-19T08:02:00.000Z",
    clusterId: CLUSTER_ID,
    token: TOKEN
  });
  await runtime.deleteTemporaryIngress({ clusterId: CLUSTER_ID, entry,
    token: TOKEN });
  await runtime.deleteSqlAdmin({
    clusterId: CLUSTER_ID,
    token: TOKEN,
    username: "prooftoact_bootstrap_admin"
  });
  assert.equal(calls.length, 8);
  for (const call of calls) {
    assert.equal(call.options.headers["Cc-Version"], "2024-09-16");
    assert.equal(call.options.redirect, "error");
  }
  assert.equal(calls.every((call) =>
    call.options.headers.Authorization === `Bearer ${TOKEN}`), true);
  assert.deepEqual(JSON.parse(calls[0].options.body), createRequest);
  assert.deepEqual(JSON.parse(calls[2].options.body), {
    name: "prooftoact_bootstrap_admin",
    password: "x".repeat(40)
  });
  assert.deepEqual(JSON.parse(calls[4].options.body), entry);
  assert.match(calls[3].url,
    /pagination\.limit=500.*pagination\.as_of_time=/u);
  assert.match(calls[5].url,
    /pagination\.limit=500.*pagination\.as_of_time=/u);
  assert.equal(calls[6].url,
    `https://cockroachlabs.cloud/api/v1/clusters/${CLUSTER_ID}/` +
    "networking/allowlist/8.8.8.8/32");
  assert.equal(calls[7].url,
    `https://cockroachlabs.cloud/api/v1/clusters/${CLUSTER_ID}/` +
    "sql-users/prooftoact_bootstrap_admin");
});

test("two independent public-IP observations must match one safe IPv4", async () => {
  const responseFor = (url, value) => {
    const response = new Response(`${value}\n`, { status: 200 });
    Object.defineProperty(response, "url", { value: url });
    return response;
  };
  const accepted = await observeRunnerPublicIpv4(async (url) =>
    responseFor(url, "8.8.8.8"));
  assert.equal(accepted.ipv4, "8.8.8.8");
  assert.equal(accepted.sourceCount, 2);
  await assert.rejects(observeRunnerPublicIpv4(async (url) =>
    responseFor(url, url.includes("amazonaws") ? "8.8.8.8" : "1.1.1.1")),
  /FRESH_CLUSTER_PUBLIC_IP_OBSERVATION_MISMATCH/u);
  for (const unsafe of ["0.0.0.0", "10." + "0.0.1", "127.0.0.1",
    "169.254.169.254", "192.168." + "1.1", "224.0.0.1"]) {
    assert.equal(__test.publicIpv4(unsafe), false);
  }
});

test("temporary ingress is exact /32 SQL-only and absence is propagated", () => {
  const entry = temporarySqlAllowlistEntry({
    operationId: OPERATION_ID,
    ipv4: "8.8.8.8"
  });
  assert.deepEqual(entry, {
    cidr_ip: "8.8.8.8",
    cidr_mask: 32,
    name: `prooftoact-${OPERATION_ID}`,
    sql: true,
    ui: false
  });
  assert.equal(validateTemporaryAllowlistReadback({
    allowlist: [entry],
    asOfTime: "2026-08-19T08:02:00.000Z",
    complete: true,
    pageCount: 1,
    propagating: false
  }, entry, { present: true }).expectedEntryPresent, true);
  assert.equal(validateTemporaryAllowlistReadback({
    allowlist: [],
    asOfTime: "2026-08-19T08:02:00.000Z",
    complete: true,
    pageCount: 1,
    propagating: false
  }, entry, { present: false }).expectedEntryPresent, false);
  assert.throws(() => temporarySqlAllowlistEntry({
    operationId: OPERATION_ID,
    ipv4: "0.0.0.0"
  }), /FRESH_CLUSTER_TEMPORARY_INGRESS_REJECTED/u);
  assert.throws(() => validateTemporaryAllowlistReadback({
    allowlist: [{ ...entry, cidr_ip: "0.0.0.0", cidr_mask: 0 }],
    asOfTime: "2026-08-19T08:02:00.000Z",
    complete: true,
    pageCount: 1,
    propagating: false
  }, entry, { present: false }),
  /FRESH_CLUSTER_TEMPORARY_INGRESS_READBACK_REJECTED/u);
  assert.throws(() => validateTemporaryAllowlistReadback({
    allowlist: [entry, {
      cidr_ip: "1.1.1.1",
      cidr_mask: 32,
      name: "unexpected",
      sql: true,
      ui: false
    }],
    asOfTime: "2026-08-19T08:02:00.000Z",
    complete: true,
    pageCount: 1,
    propagating: false
  }, entry, { present: true }),
  /FRESH_CLUSTER_TEMPORARY_INGRESS_READBACK_REJECTED/u);
});

test("complete allowlist readback exhausts fixed snapshot pages", async () => {
  const entry = temporarySqlAllowlistEntry({
    operationId: OPERATION_ID,
    ipv4: "8.8.8.8"
  });
  const calls = [];
  const runtime = createFreshClusterCloudRuntime({
    async fetchImpl(url) {
      calls.push(url);
      if (calls.length === 1) {
        return jsonResponse(url, {
          allowlist: [],
          pagination: { next_page: "next-token" },
          propagating: false
        });
      }
      return jsonResponse(url, { allowlist: [entry], propagating: false });
    }
  });
  const readback = await runtime.listCompleteAllowlist({
    asOfTime: "2026-08-19T08:02:00.000Z",
    clusterId: CLUSTER_ID,
    token: TOKEN
  });
  assert.equal(readback.pageCount, 2);
  assert.deepEqual(readback.allowlist, [entry]);
  assert.match(calls[1], /pagination\.page=next-token/u);
  assert.equal(validateTemporaryAllowlistReadback(
    readback, entry, { present: true }
  ).expectedEntryPresent, true);
});

test("all complete list endpoints accept explicit null terminal pagination", async () => {
  const calls = [];
  const runtime = createFreshClusterCloudRuntime({
    async fetchImpl(url) {
      calls.push(url);
      if (url.includes("/networking/allowlist?")) {
        return jsonResponse(url, {
          allowlist: [],
          pagination: null,
          propagating: false
        });
      }
      if (url.includes("/sql-users?")) {
        return jsonResponse(url, {
          pagination: null,
          users: [{ name: "prooftoact_bootstrap_admin" }]
        });
      }
      return jsonResponse(url, { clusters: [], pagination: null });
    }
  });
  const asOfTime = "2026-08-19T08:02:00.000Z";
  const clusters = await runtime.listCompleteClusters({
    asOfTime,
    token: TOKEN
  });
  const users = await runtime.listCompleteSqlUsers({
    asOfTime,
    clusterId: CLUSTER_ID,
    token: TOKEN
  });
  const allowlist = await runtime.listCompleteAllowlist({
    asOfTime,
    clusterId: CLUSTER_ID,
    token: TOKEN
  });
  assert.equal(clusters.pageCount, 1);
  assert.equal(users.pageCount, 1);
  assert.equal(allowlist.pageCount, 1);
  assert.equal(allowlist.propagating, false);
  assert.equal(calls.length, 3);
});
