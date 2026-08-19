import crypto from "node:crypto";

import {
  discoverTemporaryAllowlistEntry,
  validateFreshClusterReadback,
  validateSqlUserInventory
} from "./fresh-cluster-cloud-controller.js";

const TRANSITION_SCHEMA = "prooftoact.fresh-cluster-transition.v1";
const TERMINAL_SCHEMA = "prooftoact.fresh-cluster-terminal.v1";
const BOOTSTRAP_USERNAME = "prooftoact_bootstrap_admin";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
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

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return crypto.createHash("sha256")
    .update(`${canonicalJson(value)}\n`, "utf8").digest("hex");
}

function textDigest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function readRequest(command) {
  return Object.freeze({
    command,
    commandSha256: command.commandSha256,
    controllerTableArn: command.controllerTableArn,
    globalKeySha256: command.globalKeySha256,
    operationId: command.operationId,
    stronglyConsistent: true
  });
}

export async function reconcileFreshClusterProviderAccess({
  clock = Date.now,
  command,
  provider,
  runtime
}) {
  requireCondition(command?.clusterMode === "ADOPT_VERIFIED_EXISTING" &&
    provider && [
      "appendTransition", "authenticateRecovery", "readStrong", "terminalize"
    ].every((name) => typeof provider[name] === "function") &&
    runtime && [
      "deleteSqlAdmin", "deleteTemporaryIngress", "listCompleteAllowlist",
      "listCompleteSqlUsers", "waitForFreshClusterCreated"
    ].every((name) => typeof runtime[name] === "function") &&
    typeof clock === "function",
  "FRESH_CLUSTER_RECONCILIATION_CONFIGURATION_REJECTED");

  const stored = await provider.readStrong(readRequest(command));
  requireCondition(stored !== null,
    "FRESH_CLUSTER_RECONCILIATION_OPERATION_ABSENT");
  if (stored.finalReceipt !== null) return stored.finalReceipt;
  if (stored.terminalReceipt !== null) {
    requireCondition(stored.terminalReceipt.adminCredentialAbsent === true &&
      stored.terminalReceipt.adminSqlPrincipalAbsent === true &&
      stored.terminalReceipt.ingressEmpty === true,
    "FRESH_CLUSTER_RECONCILIATION_UNSAFE_TERMINAL_REJECTED");
    return stored.terminalReceipt;
  }
  const authentication = await provider.authenticateRecovery(command);
  requireCondition(authentication?.status ===
      "AUTHENTICATED_PROVIDER_READBACK" &&
    authentication.providerBacked === true &&
    ["ABSENT", "SEALED"].includes(authentication.adminSecretState),
  "FRESH_CLUSTER_RECONCILIATION_AUTHENTICATION_REJECTED");

  let sequence = stored.transitionCount;
  let previousReceiptSha256 = stored.lastReceiptSha256;
  const phases = new Set(stored.transitions.map(({ phase }) => phase));
  const record = async (phase, payload, mutationDispatched = false) => {
    if (phases.has(phase)) return;
    requireCondition(/^[A-Z][A-Z0-9_]{0,79}$/u.test(phase) &&
      plainObject(payload) && typeof mutationDispatched === "boolean",
    "FRESH_CLUSTER_RECONCILIATION_TRANSITION_REJECTED");
    const transition = Object.freeze({
      schemaVersion: TRANSITION_SCHEMA,
      status: "DURABLE",
      commandSha256: command.commandSha256,
      controllerTableArn: command.controllerTableArn,
      durable: true,
      globallyAuthoritative: true,
      globalKeySha256: command.globalKeySha256,
      mutationDispatched,
      operationId: command.operationId,
      payloadSha256: digest(payload),
      phase,
      previousReceiptSha256,
      sequence,
      version: sequence + 2
    });
    const accepted = await provider.appendTransition({ command, transition });
    requireCondition(canonicalJson(accepted) === canonicalJson(transition),
      "FRESH_CLUSTER_RECONCILIATION_TRANSITION_CONFLICT");
    phases.add(phase);
    previousReceiptSha256 = digest(accepted);
    sequence += 1;
  };

  const observedAt = new Date(clock()).toISOString();
  const cluster = validateFreshClusterReadback(
    await runtime.waitForFreshClusterCreated({
      clusterId: command.providerClusterId
    }),
    command,
    { dispatchedAt: observedAt, observedAt }
  );
  await record("RECOVERY_CLEANUP_STARTED", {
    authenticationSha256: digest(authentication),
    clusterIdSha256: cluster.clusterIdSha256,
    interruptedPhaseSha256: textDigest(stored.state)
  });

  let adminAbsent = false;
  let ingressEmpty = false;
  const failures = [];

  try {
    const initial = validateSqlUserInventory(
      await runtime.listCompleteSqlUsers({ clusterId: cluster.clusterId })
    );
    if (initial.names.includes(BOOTSTRAP_USERNAME)) {
      await record("RECOVERY_ADMIN_DELETE_DISPATCHING", {
        inventorySha256: initial.snapshotSha256,
        usernameSha256: textDigest(BOOTSTRAP_USERNAME)
      }, true);
      try {
        await runtime.deleteSqlAdmin({ clusterId: cluster.clusterId });
      } catch (cause) {
        const reconciled = validateSqlUserInventory(
          await runtime.listCompleteSqlUsers({ clusterId: cluster.clusterId })
        );
        requireCondition(!reconciled.names.includes(BOOTSTRAP_USERNAME),
          "FRESH_CLUSTER_RECONCILIATION_ADMIN_DELETE_AMBIGUOUS");
        await record("RECOVERY_ADMIN_DELETE_ACKNOWLEDGEMENT_RECONCILED", {
          acknowledgementCauseSha256:
            textDigest(cause?.message ?? "UNKNOWN"),
          inventorySha256: reconciled.snapshotSha256
        });
      }
    }
    const final = validateSqlUserInventory(
      await runtime.listCompleteSqlUsers({ clusterId: cluster.clusterId })
    );
    requireCondition(!final.names.includes(BOOTSTRAP_USERNAME),
      "FRESH_CLUSTER_RECONCILIATION_ADMIN_DELETE_AMBIGUOUS");
    adminAbsent = true;
    await record("RECOVERY_ADMIN_DELETE_ABSENT", {
      inventorySha256: final.snapshotSha256,
      userCount: final.names.length
    });
  } catch (cause) {
    failures.push(cause);
  }

  try {
    const initial = discoverTemporaryAllowlistEntry(
      await runtime.listCompleteAllowlist({ clusterId: cluster.clusterId }),
      command.operationId
    );
    if (initial.entry !== null) {
      requireCondition(phases.has("INGRESS_CREATE_DISPATCHING"),
        "FRESH_CLUSTER_RECONCILIATION_INGRESS_NOT_AUTHORIZED");
      await record("RECOVERY_INGRESS_DELETE_DISPATCHING", {
        allowlistSha256: initial.allowlistSha256,
        entrySha256: digest(initial.entry)
      }, true);
      try {
        await runtime.deleteTemporaryIngress({
          clusterId: cluster.clusterId,
          entry: initial.entry
        });
      } catch (cause) {
        const reconciled = discoverTemporaryAllowlistEntry(
          await runtime.listCompleteAllowlist({ clusterId: cluster.clusterId }),
          command.operationId
        );
        requireCondition(reconciled.entry === null,
          "FRESH_CLUSTER_RECONCILIATION_INGRESS_DELETE_AMBIGUOUS");
        await record("RECOVERY_INGRESS_DELETE_ACKNOWLEDGEMENT_RECONCILED", {
          acknowledgementCauseSha256:
            textDigest(cause?.message ?? "UNKNOWN"),
          allowlistSha256: reconciled.allowlistSha256
        });
      }
    }
    const final = discoverTemporaryAllowlistEntry(
      await runtime.listCompleteAllowlist({ clusterId: cluster.clusterId }),
      command.operationId
    );
    requireCondition(final.entry === null,
      "FRESH_CLUSTER_RECONCILIATION_INGRESS_DELETE_AMBIGUOUS");
    ingressEmpty = true;
    await record("RECOVERY_INGRESS_DELETE_ABSENT", {
      allowlistSha256: final.allowlistSha256,
      propagationComplete: true
    });
  } catch (cause) {
    failures.push(cause);
  }

  if (failures.length > 0 || !adminAbsent || !ingressEmpty) {
    reject("FRESH_CLUSTER_CLEANUP_PENDING_RETRY_REQUIRED",
      failures[0]);
  }
  await record("RECOVERY_ACCESS_REVOKED", {
    adminSecretVersionRetained: authentication.adminSecretState === "SEALED",
    adminSqlPrincipalAbsent: true,
    ingressEmpty: true
  });
  const terminal = Object.freeze({
    schemaVersion: TERMINAL_SCHEMA,
    status: "FAILED_CLUSTER_RETAINED_ACCESS_REVOKED",
    adminCredentialAbsent: true,
    adminSecretCredentialRevokedByPrincipalDeletion: true,
    adminSecretVersionRetained: authentication.adminSecretState === "SEALED",
    adminSqlPrincipalAbsent: true,
    clusterIdSha256: cluster.clusterIdSha256,
    commandSha256: command.commandSha256,
    controllerTableArn: command.controllerTableArn,
    failureCode: "FRESH_CLUSTER_INTERRUPTED_ACCESS_REVOKED",
    globalKeySha256: command.globalKeySha256,
    ingressEmpty: true,
    operationId: command.operationId,
    previousReceiptSha256,
    separateTeardownApprovalRequired: true,
    transitionCount: sequence
  });
  const accepted = await provider.terminalize({ command, terminal });
  requireCondition(canonicalJson(accepted) === canonicalJson(terminal),
    "FRESH_CLUSTER_RECONCILIATION_TERMINAL_CONFLICT");
  return accepted;
}

export const __test = Object.freeze({
  canonicalJson,
  digest,
  readRequest,
  textDigest
});
