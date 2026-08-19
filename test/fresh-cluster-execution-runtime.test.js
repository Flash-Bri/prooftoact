import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  createFreshClusterCleanupRuntime,
  createFreshClusterExecutionRuntime
} from "../scripts/fresh-cluster-execution-runtime.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const CLUSTER_ID = "223e4567-e89b-42d3-a456-426614174001";
const PASSWORD = "P".repeat(22);
const ARN = "arn:aws:secretsmanager:us-east-1:111111111111:secret:" +
  `prooftoact/fresh-primary/admin-${OPERATION_ID}-Ab12Cd`;
const VERSION = "1".repeat(32);

function harness({ assertCleanupOpen = () => {} } = {}) {
  let sealed;
  let clusterReads = 0;
  let allowlistReads = 0;
  let deleteCalls = 0;
  const description = () => ({
    ARN,
    Name: `prooftoact/fresh-primary/admin-${OPERATION_ID}`,
    RotationEnabled: false,
    Tags: [
      { Key: "Project", Value: "ProofToAct" },
      { Key: "Purpose", Value: "FreshBootstrapAdmin" },
      { Key: "OperationId", Value: OPERATION_ID }
    ],
    VersionIdsToStages: sealed ? { [VERSION]: ["AWSCURRENT"] } : {}
  });
  const awsRuntime = {
    async describeAdminSecret() { return description(); },
    async getAdminSecretResourcePolicy() { return { ARN }; },
    async putAdminSecret({ secretString }) {
      sealed = {
        ARN,
        CreatedDate: new Date("2026-08-19T08:00:00.000Z"),
        SecretString: secretString,
        VersionId: VERSION,
        VersionStages: ["AWSCURRENT"]
      };
      return {};
    },
    async readAdminVersionIfPresent() { return sealed ?? null; }
  };
  const noOp = async () => ({ ok: true });
  const cloudRuntime = {
    addTemporaryIngress: noOp,
    createCluster: noOp,
    createSqlAdmin: noOp,
    async deleteSqlAdmin() { deleteCalls += 1; return { ok: true }; },
    async deleteTemporaryIngress() { deleteCalls += 1; return { ok: true }; },
    async getCluster() {
      clusterReads += 1;
      return {
        id: CLUSTER_ID,
        state: clusterReads === 1 ? "CREATING" : "CREATED",
        operation_status: clusterReads === 1 ? "PENDING" : "UNSPECIFIED"
      };
    },
    getCreatorRoles: noOp,
    async listCompleteAllowlist({ asOfTime }) {
      allowlistReads += 1;
      return {
        allowlist: [],
        asOfTime,
        complete: true,
        pageCount: 1,
        propagating: allowlistReads === 1
      };
    },
    listCompleteClusters: noOp,
    listCompleteSqlUsers: noOp
  };
  const runtime = createFreshClusterExecutionRuntime({
    adoptedAdminPassword: PASSWORD,
    assertCleanupOpen,
    awsRuntime,
    clock: () => Date.parse("2026-08-19T08:00:01.000Z"),
    cloudRuntime,
    fetchImpl: async () => {
      throw new Error("not used");
    },
    freshPrimaryInvoker: noOp,
    freshRecoveryPublicationFactory: async () => ({
      prepare: noOp,
      append: noOp,
      replay: noOp,
      planManagedMcp: noOp,
      verifyManagedMcp: noOp
    }),
    localAdminCredentialDiscarder: async () => true,
    material: {
      auditor: { secretValue: "auditor-token-with-twenty-characters" },
      cloudApi: { secretValue: "creator-token-with-twenty-characters" }
    },
    secretCoordinates: { admin: { arn: ARN, versionId: VERSION } },
    sleep: async () => {}
  });
  return {
    cloudRuntime,
    getAllowlistReads: () => allowlistReads,
    getDeleteCalls: () => deleteCalls,
    runtime
  };
}

test("provider-generated 22-character adoption password is accepted at port 26257", () => {
  assert.equal(__test.validatePassword(PASSWORD), PASSWORD);
  assert.throws(() => __test.validatePassword("short"),
    /FRESH_CLUSTER_EXECUTION_ADMIN_PASSWORD_REJECTED/u);
  const credential = __test.adminConnectionString(
    "fresh.aws.cockroachlabs.cloud",
    PASSWORD
  );
  assert.equal(credential.username, "prooftoact_bootstrap_admin");
  assert.match(credential.connectionString,
    /fresh\.aws\.cockroachlabs\.cloud:26257\/defaultdb\?sslmode=verify-full$/u);
});

test("execution runtime waits only with read calls and seals exact admin version", async () => {
  const { getAllowlistReads, runtime } = harness();
  const created = await runtime.waitForFreshClusterCreated({
    clusterId: CLUSTER_ID
  });
  assert.equal(created.state, "CREATED");
  const allowlist = await runtime.listCompleteAllowlist({
    asOfTime: "2026-08-19T08:00:00.000Z",
    clusterId: CLUSTER_ID
  });
  assert.equal(allowlist.propagating, false);
  assert.equal(getAllowlistReads(), 2);
  const command = {
    clusterMode: "ADOPT_VERIFIED_EXISTING",
    operationId: OPERATION_ID
  };
  const cluster = { sqlDns: "fresh.aws.cockroachlabs.cloud" };
  const credential = runtime.prepareAdminCredential({ cluster, command });
  const seal = await runtime.sealAdminSecret({ command, credential });
  assert.equal(seal.status, "SEALED");
  assert.equal(seal.operationId, OPERATION_ID);
  assert.equal(seal.secretValueSha256, credential.connectionStringSha256);
});

test("execution and cleanup runtime adapters guard immediately before both provider deletes", async () => {
  let open = true;
  const assertCleanupOpen = () => {
    if (!open) throw new Error("EXPIRED_AT_ADAPTER");
  };
  const execution = harness({ assertCleanupOpen });
  await execution.runtime.deleteSqlAdmin({
    clusterId: CLUSTER_ID,
    username: "prooftoact_bootstrap_admin"
  });
  await execution.runtime.deleteTemporaryIngress({
    clusterId: CLUSTER_ID,
    entry: { cidr: "203.0.113.7/32" }
  });
  assert.equal(execution.getDeleteCalls(), 2);
  open = false;
  assert.throws(() => execution.runtime.deleteSqlAdmin({
    clusterId: CLUSTER_ID,
    username: "prooftoact_bootstrap_admin"
  }), /EXPIRED_AT_ADAPTER/u);
  assert.throws(() => execution.runtime.deleteTemporaryIngress({
    clusterId: CLUSTER_ID,
    entry: { cidr: "203.0.113.7/32" }
  }), /EXPIRED_AT_ADAPTER/u);
  assert.equal(execution.getDeleteCalls(), 2);

  open = true;
  const cleanup = createFreshClusterCleanupRuntime({
    assertCleanupOpen,
    cloudRuntime: execution.cloudRuntime,
    material: {
      auditor: { secretValue: "auditor-token-with-twenty-characters" },
      cloudApi: { secretValue: "creator-token-with-twenty-characters" }
    },
    sleep: async () => {}
  });
  await cleanup.deleteSqlAdmin({ clusterId: CLUSTER_ID });
  await cleanup.deleteTemporaryIngress({
    clusterId: CLUSTER_ID,
    entry: { cidr: "203.0.113.7/32" }
  });
  assert.equal(execution.getDeleteCalls(), 4);
  open = false;
  assert.throws(() => cleanup.deleteSqlAdmin({ clusterId: CLUSTER_ID }),
    /EXPIRED_AT_ADAPTER/u);
  assert.throws(() => cleanup.deleteTemporaryIngress({
    clusterId: CLUSTER_ID,
    entry: { cidr: "203.0.113.7/32" }
  }), /EXPIRED_AT_ADAPTER/u);
  assert.equal(execution.getDeleteCalls(), 4);
});
