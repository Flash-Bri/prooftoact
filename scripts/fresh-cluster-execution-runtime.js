import crypto from "node:crypto";

import {
  normalizeFreshClusterAdminSealReadback
} from "./fresh-cluster-aws-provider.js";
import { observeRunnerPublicIpv4 } from
  "./fresh-cluster-cloud-controller.js";

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const BOOTSTRAP_USERNAME = "prooftoact_bootstrap_admin";
const MAX_CLUSTER_READS = 180;
const MAX_PROPAGATION_READS = 60;
const READ_DELAY_MS = 5_000;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sleepDefault(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function validatePassword(value) {
  requireCondition(typeof value === "string" && value.length >= 20 &&
    value.length <= 256 && !/[\u0000\r\n]/u.test(value),
  "FRESH_CLUSTER_EXECUTION_ADMIN_PASSWORD_REJECTED");
  return value;
}

function adminConnectionString(sqlDns, password) {
  requireCondition(
    /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.cockroachlabs\.cloud$/u
      .test(sqlDns ?? ""),
  "FRESH_CLUSTER_EXECUTION_SQL_DNS_REJECTED");
  const connection = new URL(`postgresql:${"//"}${sqlDns}`);
  connection.username = BOOTSTRAP_USERNAME;
  connection.password = password;
  connection.port = "26257";
  connection.pathname = "/defaultdb";
  connection.searchParams.set("sslmode", "verify-full");
  const value = connection.toString();
  return Object.freeze({
    connectionString: value,
    connectionStringSha256: sha256(value),
    password,
    passwordSha256: sha256(password),
    username: BOOTSTRAP_USERNAME
  });
}

function validateCloudTokens(material) {
  requireCondition(material &&
    typeof material.cloudApi?.secretValue === "string" &&
    typeof material.auditor?.secretValue === "string" &&
    material.cloudApi.secretValue !== material.auditor.secretValue,
  "FRESH_CLUSTER_EXECUTION_TOKEN_REJECTED");
  return Object.freeze({
    auditor: material.auditor.secretValue,
    creator: material.cloudApi.secretValue
  });
}

export function createFreshClusterExecutionRuntime({
  adoptedAdminPassword,
  assertCleanupOpen,
  awsRuntime,
  clock = Date.now,
  cloudRuntime,
  fetchImpl = globalThis.fetch,
  freshPrimaryInvoker,
  freshRecoveryPublicationFactory,
  localAdminCredentialDiscarder,
  material,
  secretCoordinates,
  sleep = sleepDefault
}) {
  const tokens = validateCloudTokens(material);
  requireCondition(awsRuntime && [
    "describeAdminSecret",
    "getAdminSecretResourcePolicy",
    "putAdminSecret",
    "readAdminVersionIfPresent"
  ].every((name) => typeof awsRuntime[name] === "function") &&
    cloudRuntime && [
      "addTemporaryIngress",
      "createCluster",
      "createSqlAdmin",
      "deleteSqlAdmin",
      "deleteTemporaryIngress",
      "getCluster",
      "listCompleteAllowlist",
      "listCompleteClusters",
      "listCompleteSqlUsers"
    ].every((name) => typeof cloudRuntime[name] === "function") &&
    typeof assertCleanupOpen === "function" &&
    typeof clock === "function" && typeof fetchImpl === "function" &&
    typeof freshPrimaryInvoker === "function" &&
    typeof freshRecoveryPublicationFactory === "function" &&
    typeof sleep === "function" &&
    typeof localAdminCredentialDiscarder === "function" &&
    secretCoordinates?.admin,
  "FRESH_CLUSTER_EXECUTION_CONFIGURATION_REJECTED");

  async function readAdminSeal(command, credential) {
    const [description, resourcePolicy, readback] = await Promise.all([
      awsRuntime.describeAdminSecret(),
      awsRuntime.getAdminSecretResourcePolicy(),
      awsRuntime.readAdminVersionIfPresent()
    ]);
    requireCondition(readback !== null,
      "FRESH_CLUSTER_EXECUTION_ADMIN_SECRET_ABSENT");
    return normalizeFreshClusterAdminSealReadback({
      command,
      coordinate: secretCoordinates.admin,
      description,
      readback,
      resourcePolicy,
      secretValueSha256: credential.connectionStringSha256
    });
  }

  let recoveryPublication = null;
  return Object.freeze({
    createCluster({ command }) {
      return cloudRuntime.createCluster({
        createRequest: command.createRequest,
        token: tokens.creator
      });
    },
    listCompleteClusters({ asOfTime }) {
      return cloudRuntime.listCompleteClusters({
        asOfTime,
        token: tokens.auditor
      });
    },
    async waitForFreshClusterCreated({ clusterId }) {
      requireCondition(UUID.test(clusterId ?? ""),
        "FRESH_CLUSTER_EXECUTION_CLUSTER_ID_REJECTED");
      for (let attempt = 0; attempt < MAX_CLUSTER_READS; attempt += 1) {
        const value = await cloudRuntime.getCluster({
          clusterId,
          token: tokens.auditor
        });
        if (value?.state === "CREATED" &&
          value.operation_status === "UNSPECIFIED") return value;
        requireCondition(!["FAILED", "DELETED"].includes(value?.state),
          "FRESH_CLUSTER_EXECUTION_CLUSTER_TERMINAL_REJECTED");
        if (attempt + 1 < MAX_CLUSTER_READS) await sleep(READ_DELAY_MS);
      }
      reject("FRESH_CLUSTER_EXECUTION_CLUSTER_TIMEOUT");
    },
    observeRunnerPublicIpv4() {
      return observeRunnerPublicIpv4(fetchImpl);
    },
    async listCompleteAllowlist({ asOfTime, clusterId }) {
      for (let attempt = 0; attempt < MAX_PROPAGATION_READS; attempt += 1) {
        const value = await cloudRuntime.listCompleteAllowlist({
          asOfTime: attempt === 0
            ? asOfTime
            : new Date(clock()).toISOString(),
          clusterId,
          token: tokens.auditor
        });
        if (value.propagating === false) return value;
        if (attempt + 1 < MAX_PROPAGATION_READS) await sleep(READ_DELAY_MS);
      }
      reject("FRESH_CLUSTER_EXECUTION_ALLOWLIST_PROPAGATION_TIMEOUT");
    },
    addTemporaryIngress({ clusterId, entry }) {
      return cloudRuntime.addTemporaryIngress({
        clusterId,
        entry,
        token: tokens.creator
      });
    },
    prepareAdminCredential({ cluster, command }) {
      const password = command.clusterMode === "ADOPT_VERIFIED_EXISTING"
        ? validatePassword(adoptedAdminPassword)
        : crypto.randomBytes(32).toString("base64url");
      return adminConnectionString(cluster.sqlDns, password);
    },
    async sealAdminSecret({ command, credential }) {
      await awsRuntime.putAdminSecret({
        clientRequestToken: secretCoordinates.admin.versionId,
        secretString: credential.connectionString
      });
      return readAdminSeal(command, credential);
    },
    readAdminSecret({ command, credential }) {
      return readAdminSeal(command, credential);
    },
    discardLocalAdminCredential(value) {
      return localAdminCredentialDiscarder(value);
    },
    listCompleteSqlUsers({ asOfTime, clusterId }) {
      return cloudRuntime.listCompleteSqlUsers({
        asOfTime,
        clusterId,
        token: tokens.auditor
      });
    },
    createSqlAdmin({ clusterId, password, username }) {
      return cloudRuntime.createSqlAdmin({
        clusterId,
        password,
        token: tokens.creator,
        username
      });
    },
    async authenticateSqlAdmin({ cluster, credential }) {
      const pg = await import("pg");
      const client = new pg.Client({
        application_name: "prooftoact-fresh-cluster-identity",
        connectionString: credential.connectionString,
        connectionTimeoutMillis: 10_000,
        query_timeout: 10_000,
        statement_timeout: 10_000
      });
      try {
        await client.connect();
        const result = await client.query(`
          SELECT
            crdb_internal.cluster_id()::STRING AS sql_cluster_id,
            current_user::STRING AS current_user_name,
            current_database()::STRING AS database_name,
            version()::STRING AS server_version,
            clock_timestamp()::STRING AS observed_at
        `);
        const row = result.rows?.[0];
        requireCondition(UUID.test(row?.sql_cluster_id ?? "") &&
          row.sql_cluster_id !== cluster.clusterId &&
          row.current_user_name === BOOTSTRAP_USERNAME &&
          row.database_name === "defaultdb" &&
          /^CockroachDB CCL v26\.2(?:\.[0-9]+)?\b/u
            .test(row.server_version ?? "") &&
          Number.isFinite(Date.parse(row.observed_at)),
        "FRESH_CLUSTER_EXECUTION_ADMIN_IDENTITY_REJECTED");
        return Object.freeze({
          schemaVersion:
            "prooftoact.fresh-cluster-admin-authentication.v1",
          status: "AUTHENTICATED",
          database: "defaultdb",
          observedAt: new Date(Date.parse(row.observed_at)).toISOString(),
          port: "26257",
          providerBacked: true,
          providerClusterId: cluster.clusterId,
          sqlClusterId: row.sql_cluster_id,
          username: BOOTSTRAP_USERNAME
        });
      } finally {
        await client.end().catch(() => {});
      }
    },
    runFreshPrimaryBootstrap(value) {
      return freshPrimaryInvoker(value);
    },
    async prepareFreshRecoveryPublication(value) {
      requireCondition(recoveryPublication === null,
        "FRESH_CLUSTER_RECOVERY_PUBLICATION_REPLAY_REJECTED");
      recoveryPublication = await freshRecoveryPublicationFactory(value);
      requireCondition(recoveryPublication &&
        typeof recoveryPublication.prepare === "function" &&
        typeof recoveryPublication.append === "function" &&
        typeof recoveryPublication.replay === "function" &&
        typeof recoveryPublication.planManagedMcp === "function" &&
        typeof recoveryPublication.verifyManagedMcp === "function",
      "FRESH_CLUSTER_RECOVERY_PUBLICATION_CONFIGURATION_REJECTED");
      return recoveryPublication.prepare();
    },
    appendFreshRecoveryPublication() {
      requireCondition(recoveryPublication !== null,
        "FRESH_CLUSTER_RECOVERY_PUBLICATION_STATE_REJECTED");
      return recoveryPublication.append();
    },
    replayFreshRecoveryPublication() {
      requireCondition(recoveryPublication !== null,
        "FRESH_CLUSTER_RECOVERY_PUBLICATION_STATE_REJECTED");
      return recoveryPublication.replay();
    },
    planFreshRecoveryManagedMcp() {
      requireCondition(recoveryPublication !== null,
        "FRESH_CLUSTER_RECOVERY_PUBLICATION_STATE_REJECTED");
      return recoveryPublication.planManagedMcp();
    },
    verifyFreshRecoveryManagedMcp(value) {
      requireCondition(recoveryPublication !== null,
        "FRESH_CLUSTER_RECOVERY_PUBLICATION_STATE_REJECTED");
      return recoveryPublication.verifyManagedMcp(value);
    },
    deleteSqlAdmin({ clusterId, username }) {
      assertCleanupOpen();
      return cloudRuntime.deleteSqlAdmin({
        clusterId,
        token: tokens.creator,
        username
      });
    },
    deleteTemporaryIngress({ clusterId, entry }) {
      assertCleanupOpen();
      return cloudRuntime.deleteTemporaryIngress({
        clusterId,
        entry,
        token: tokens.creator
      });
    }
  });
}

export function createFreshClusterCleanupRuntime({
  assertCleanupOpen,
  clock = Date.now,
  cloudRuntime,
  material,
  sleep = sleepDefault
}) {
  const tokens = validateCloudTokens(material);
  requireCondition(cloudRuntime && [
    "deleteSqlAdmin",
    "deleteTemporaryIngress",
    "getCluster",
    "listCompleteAllowlist",
    "listCompleteSqlUsers"
  ].every((name) => typeof cloudRuntime[name] === "function") &&
    typeof assertCleanupOpen === "function" &&
    typeof clock === "function" && typeof sleep === "function",
  "FRESH_CLUSTER_CLEANUP_CONFIGURATION_REJECTED");

  async function completeAllowlist(clusterId) {
    for (let attempt = 0; attempt < MAX_PROPAGATION_READS; attempt += 1) {
      const value = await cloudRuntime.listCompleteAllowlist({
        asOfTime: new Date(clock()).toISOString(),
        clusterId,
        token: tokens.auditor
      });
      if (value.propagating === false) return value;
      if (attempt + 1 < MAX_PROPAGATION_READS) await sleep(READ_DELAY_MS);
    }
    reject("FRESH_CLUSTER_CLEANUP_ALLOWLIST_PROPAGATION_TIMEOUT");
  }

  return Object.freeze({
    async waitForFreshClusterCreated({ clusterId }) {
      requireCondition(UUID.test(clusterId ?? ""),
        "FRESH_CLUSTER_CLEANUP_CLUSTER_ID_REJECTED");
      for (let attempt = 0; attempt < MAX_CLUSTER_READS; attempt += 1) {
        const value = await cloudRuntime.getCluster({
          clusterId,
          token: tokens.auditor
        });
        if (value?.state === "CREATED" &&
          value.operation_status === "UNSPECIFIED") return value;
        requireCondition(!["FAILED", "DELETED"].includes(value?.state),
          "FRESH_CLUSTER_CLEANUP_CLUSTER_TERMINAL_REJECTED");
        if (attempt + 1 < MAX_CLUSTER_READS) await sleep(READ_DELAY_MS);
      }
      reject("FRESH_CLUSTER_CLEANUP_CLUSTER_TIMEOUT");
    },
    listCompleteAllowlist({ clusterId }) {
      return completeAllowlist(clusterId);
    },
    listCompleteSqlUsers({ clusterId }) {
      return cloudRuntime.listCompleteSqlUsers({
        asOfTime: new Date(clock()).toISOString(),
        clusterId,
        token: tokens.auditor
      });
    },
    deleteSqlAdmin({ clusterId }) {
      assertCleanupOpen();
      return cloudRuntime.deleteSqlAdmin({
        clusterId,
        token: tokens.creator,
        username: BOOTSTRAP_USERNAME
      });
    },
    deleteTemporaryIngress({ clusterId, entry }) {
      assertCleanupOpen();
      return cloudRuntime.deleteTemporaryIngress({
        clusterId,
        entry,
        token: tokens.creator
      });
    }
  });
}

export const __test = Object.freeze({
  BOOTSTRAP_USERNAME,
  MAX_CLUSTER_READS,
  MAX_PROPAGATION_READS,
  READ_DELAY_MS,
  adminConnectionString,
  validatePassword
});
