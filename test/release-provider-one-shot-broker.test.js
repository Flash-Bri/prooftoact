import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  brokerCanonicalBytes,
  brokerPublicKeyFingerprint,
  brokerSha256,
  dispatchReservedProviderOneShotIntent,
  finalizeProviderOneShotIntent,
  providerBrokerConstants as constants,
  publishProviderBrokerReceipt,
  reserveProviderOneShotIntent,
  runProviderOneShotBroker,
  terminalizeExpiredProviderOneShotBroker,
  validateProviderBrokerApproval
} from "../scripts/release-provider-one-shot-broker.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BROKER_PATH = path.join(
  ROOT,
  "scripts/release-provider-one-shot-broker.js"
);
const CONTROL_PLANE_COMMIT = "a".repeat(40);
const CONTROL_PLANE_TREE = "b".repeat(40);
const NOW = Date.parse("2026-08-17T20:00:00.000Z");
const ISSUED_AT = "2026-08-17T19:58:00.000Z";
const EXPIRES_AT = "2026-08-17T20:28:00.000Z";
const EXPIRED_NOW = Date.parse("2026-08-17T20:28:01.000Z");
const APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000";
const SECOND_APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174009";
const STORE_REQUEST_ID = "223e4567-e89b-42d3-a456-426614174001";
const INTENT_ID = "323e4567-e89b-42d3-a456-426614174002";
const PROVIDER_REQUEST_ID = "423e4567-e89b-42d3-a456-426614174003";
const RECONCILIATION_REQUEST_ID =
  "523e4567-e89b-42d3-a456-426614174004";
const ACCOUNT_ID = "111111111111";
const CHANGE_SET_ARN =
  "arn:aws:cloudformation:us-east-1:111111111111:changeSet/" +
  "prooftoact-release-frozen/123e4567-e89b-42d3-a456-426614174000";
const STACK_ID =
  "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
  "prooftoact-gate2/823e4567-e89b-42d3-a456-426614174007";
const CHANGE_SET_NAME = "prooftoact-release-frozen";

const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "prime256v1"
});
const PUBLIC_KEY = publicKey.export({ format: "pem", type: "spki" });

function digest(value) {
  return brokerSha256(brokerCanonicalBytes(value));
}

function workspaceDigest(workspaceRoot) {
  return brokerSha256(Buffer.from(fs.realpathSync(workspaceRoot), "utf8"));
}

function controlPlaneClaims() {
  const value = {
    brokerArtifactSha256: brokerSha256(fs.readFileSync(BROKER_PATH)),
    buildSha256: "2".repeat(64),
    commit: CONTROL_PLANE_COMMIT,
    separation: "SEPARATE_CONTROL_PLANE_FROM_FROZEN_APPLICATION",
    tree: CONTROL_PLANE_TREE
  };
  return {
    ...value,
    identitySha256: digest(value)
  };
}

function approvalClaims(
  workspaceRoot,
  lane = "EXECUTE",
  approvalId = APPROVAL_ID
) {
  const laneContract = constants.LANE_CONTRACTS[lane];
  const namespaceArn =
    `arn:aws:dynamodb:us-east-1:${ACCOUNT_ID}:table/` +
    "prooftoact-release-controller";
  const tableIdentity = {
    attributeDefinitionsSha256: digest([
      { AttributeName: "pk", AttributeType: "S" }
    ]),
    billingMode: "PAY_PER_REQUEST",
    deletionProtectionEnabled: true,
    encryptionStatus: "ENABLED",
    keySchemaSha256: digest([
      { AttributeName: "pk", KeyType: "HASH" }
    ]),
    kmsKeyArnSha256: digest(
      `arn:aws:kms:us-east-1:${ACCOUNT_ID}:key/` +
      "923e4567-e89b-42d3-a456-426614174008"
    ),
    namespaceArn,
    region: "us-east-1",
    sseType: "KMS",
    tableId: "723e4567-e89b-42d3-a456-426614174006",
    tagsSha256: digest([
      { Key: "Project", Value: "ProofToAct" },
      { Key: "Purpose", Value: "release-control" }
    ])
  };
  const release = lane === "PREPARE" ? {
    artifactManifestSha256: "5".repeat(64),
    buildReceiptSha256: "4".repeat(64),
    changeSetName: CHANGE_SET_NAME,
    changeSetType: "CREATE",
    parameterManifestSha256: "7".repeat(64),
    region: "us-east-1",
    resourceInventorySha256: "8".repeat(64),
    stackName: "prooftoact-gate2",
    templateSha256: "3".repeat(64)
  } : {
    buildReceiptSha256: "4".repeat(64),
    artifactManifestSha256: "5".repeat(64),
    changeSetArn: CHANGE_SET_ARN,
    changeSetSha256: "6".repeat(64),
    changeSetType: "CREATE",
    parameterManifestSha256: "7".repeat(64),
    region: "us-east-1",
    resourceInventorySha256: "8".repeat(64),
    stackId: STACK_ID,
    stackName: "prooftoact-gate2"
  };
  const teardown = lane === "PREPARE" ? {
    required: true,
    separateApprovalRequired: true,
    deletePreparedChangeSetIfCreated: true,
    changeSetName: CHANGE_SET_NAME,
    stackName: "prooftoact-gate2",
    expectedResourceInventorySha256: "8".repeat(64),
    residualCensusRequired: true,
    deadline: "2026-09-16T00:30:00.000Z",
    workflow: constants.AUTHORITY_CONTRACTS.teardown.workflow,
    environment: constants.AUTHORITY_CONTRACTS.teardown.environment,
    roleArn:
      `arn:aws:iam::${ACCOUNT_ID}:role/` +
      constants.AUTHORITY_CONTRACTS.teardown.roleName
  } : {
    required: true,
    separateApprovalRequired: true,
    deleteExactStack: "prooftoact-gate2",
    deleteExactStackId: STACK_ID,
    expectedResourceInventorySha256: "8".repeat(64),
    residualCensusRequired: true,
    originatingChangeSetArn: CHANGE_SET_ARN,
    originatingChangeSetSha256: "6".repeat(64),
    deadline: "2026-09-16T00:30:00.000Z",
    workflow: constants.AUTHORITY_CONTRACTS.teardown.workflow,
    environment: constants.AUTHORITY_CONTRACTS.teardown.environment,
    roleArn:
      `arn:aws:iam::${ACCOUNT_ID}:role/` +
      constants.AUTHORITY_CONTRACTS.teardown.roleName
  };
  return {
    schemaVersion: constants.APPROVAL_CLAIMS_SCHEMA,
    approvalId,
    approvedBy: "BRIAN_SMITH",
    humanAuthorizationSha256: constants.HUMAN_AUTHORIZATION_SHA256,
    oneShot: true,
    lane,
    action: laneContract.action,
    appSource: { ...constants.APP_SOURCE },
    controlPlane: controlPlaneClaims(),
    release,
    budget: {
      currency: "USD",
      cumulativeCapUsd: 20,
      alreadySpentUsd: 4,
      authorizedAdditionalUsd: lane === "TEARDOWN" ? 1 : 2,
      projectedCumulativeUsd: lane === "TEARDOWN" ? 5 : 6,
      teardownReserveUsd: 1,
      unknownCostCount: 0,
      censusAsOf: "2026-08-17T19:57:00.000Z",
      censusReceiptSha256: "9".repeat(64)
    },
    limits: {
      maximumRuns: 1,
      maximumConcurrency: 2
    },
    database: {
      database: "tideproof",
      clusterId: "623e4567-e89b-42d3-a456-426614174005",
      clusterHostSha256: "a".repeat(64),
      freshPrimaryReceiptSha256: "b".repeat(64),
      managedPrincipalSetSha256: digest(
        [...constants.FRESH_PRIMARY_RUNTIME_PRINCIPALS].sort()
      ),
      runtimePrincipals: [...constants.FRESH_PRIMARY_RUNTIME_PRINCIPALS],
      freshCluster: true,
      principalsCreatedFromEmpty: true,
      distinctRuntimeCredentials: true,
      adminCredentialPresent: false,
      rootLoginPermitted: false
    },
    teardown,
    authoritySeparation: structuredClone(constants.AUTHORITY_CONTRACTS),
    globalStore: {
      atomicConditionalConsumeRequired: true,
      durableJournalRequired: true,
      strongReadRequired: true,
      ...tableIdentity,
      tableIdentitySha256: digest(tableIdentity)
    },
    workspaceRealpathSha256: workspaceDigest(workspaceRoot)
  };
}

function signApproval(claims, {
  expiresAt = EXPIRES_AT,
  issuedAt = ISSUED_AT
} = {}) {
  const envelope = {
    schemaVersion: constants.APPROVAL_SCHEMA,
    issuer: constants.OPERATOR_ISSUER,
    keyFingerprint: brokerPublicKeyFingerprint(PUBLIC_KEY),
    nonce: claims.approvalId,
    issuedAt,
    expiresAt,
    claims
  };
  const signature = crypto.sign("sha256", brokerCanonicalBytes(envelope), {
    key: privateKey,
    dsaEncoding: "ieee-p1363"
  });
  return { ...envelope, signature: signature.toString("base64") };
}

function runtimeFor(claims, workspaceRoot, authority = true) {
  const contract = constants.LANE_CONTRACTS[claims.lane];
  const runtime = {
    schemaVersion: constants.RUNTIME_SCHEMA,
    lane: claims.lane,
    workflow: contract.workflow,
    workflowRef:
      `Flash-Bri/prooftoact/.github/workflows/${contract.workflowFile}` +
      "@refs/heads/main",
    environment: contract.environment,
    providerAccountId: ACCOUNT_ID,
    principalArn:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/${contract.roleName}/` +
      "pta-1234567890-1",
    credentialSource: "GITHUB_OIDC_SHORT_LIVED",
    openClawOauthPresent: false,
    staticProviderCredentialsPresent: false,
    rootOrAdministratorPrincipal: false,
    adminDatabaseCredentialPresent: false,
    workspaceRoot,
    appSource: { ...constants.APP_SOURCE },
    brokerArtifactSha256: claims.controlPlane.brokerArtifactSha256,
    controlPlaneBuildSha256: claims.controlPlane.buildSha256,
    controlPlaneCommit: claims.controlPlane.commit,
    controlPlaneIdentitySha256: claims.controlPlane.identitySha256,
    controlPlaneTree: claims.controlPlane.tree,
    buildReceiptSha256: claims.release.buildReceiptSha256,
    artifactManifestSha256: claims.release.artifactManifestSha256,
    changeSetArn: claims.release.changeSetArn,
    changeSetSha256: claims.release.changeSetSha256,
    stackId: claims.release.stackId,
    region: "us-east-1",
    repositoryId: "1317716765",
    repositoryOwnerId: "252500266",
    runId: "1234567890",
    runAttempt: 1,
    workflowSha: claims.controlPlane.commit,
    authorityReceipts: null
  };
  if (authority) {
    runtime.authorityReceipts = {
      schemaVersion: constants.AUTHORITY_SCHEMA,
      status: "EXACT_RUNTIME_AUTHORITY_CONFIRMED",
      providerBacked: true,
      strongRead: true,
      observedAt: "2026-08-17T19:59:00.000Z",
      expiresAt: "2026-08-17T20:10:00.000Z",
      providerIdentitySha256: digest({
        accountId: runtime.providerAccountId,
        principalArn: runtime.principalArn,
        region: runtime.region
      }),
      sourceCheckoutSha256: digest(constants.APP_SOURCE),
      controlPlaneSha256: claims.controlPlane.identitySha256,
      buildReadbackSha256: claims.release.buildReceiptSha256,
      artifactReadbackSha256: claims.release.artifactManifestSha256,
      changeSetReadbackSha256: claims.release.changeSetSha256,
      stackReadbackSha256: digest({
        changeSetArn: claims.release.changeSetArn,
        changeSetSha256: claims.release.changeSetSha256,
        stackId: claims.release.stackId,
        stackName: claims.release.stackName
      }),
      costCensusSha256: claims.budget.censusReceiptSha256,
      freshDatabaseSha256: claims.database.freshPrimaryReceiptSha256,
      iamSeparationSha256: "d".repeat(64),
      teardownContractSha256: digest(claims.teardown),
      globalStoreSha256: claims.globalStore.tableIdentitySha256,
      workflowIdentitySha256: digest({
        environment: runtime.environment,
        lane: runtime.lane,
        principalArn: runtime.principalArn,
        providerAccountId: runtime.providerAccountId,
        repositoryId: runtime.repositoryId,
        repositoryOwnerId: runtime.repositoryOwnerId,
        runAttempt: runtime.runAttempt,
        runId: runtime.runId,
        workflow: runtime.workflow,
        workflowRef: runtime.workflowRef,
        workflowSha: runtime.workflowSha
      })
    };
  }
  return runtime;
}

function terminalizerRuntimeFor(claims, workspaceRoot, now = EXPIRED_NOW) {
  const runtime = runtimeFor(claims, workspaceRoot, true);
  const contract = constants.TERMINALIZER_CONTRACT;
  runtime.lane = "TERMINALIZE";
  runtime.workflow = contract.workflow;
  runtime.workflowRef =
    `Flash-Bri/prooftoact/.github/workflows/${contract.workflowFile}` +
    "@refs/heads/main";
  runtime.environment = contract.environment;
  runtime.principalArn =
    `arn:aws:sts::${ACCOUNT_ID}:assumed-role/${contract.roleName}/` +
      "pta-1234567890-1";
  if (claims.lane === "PREPARE") {
    delete runtime.changeSetArn;
    delete runtime.changeSetSha256;
    delete runtime.stackId;
    runtime.releaseReadbackSha256 = digest(claims.release);
    delete runtime.authorityReceipts.changeSetReadbackSha256;
    delete runtime.authorityReceipts.stackReadbackSha256;
    runtime.authorityReceipts.releaseReadbackSha256 = digest(claims.release);
  }
  runtime.authorityReceipts.observedAt = new Date(now - 1_000).toISOString();
  runtime.authorityReceipts.expiresAt = new Date(now + 10 * 60_000).toISOString();
  runtime.authorityReceipts.providerIdentitySha256 = digest({
    accountId: runtime.providerAccountId,
    principalArn: runtime.principalArn,
    region: runtime.region
  });
  runtime.authorityReceipts.workflowIdentitySha256 = digest({
    environment: runtime.environment,
    lane: runtime.lane,
    principalArn: runtime.principalArn,
    providerAccountId: runtime.providerAccountId,
    repositoryId: runtime.repositoryId,
    repositoryOwnerId: runtime.repositoryOwnerId,
    runAttempt: runtime.runAttempt,
    runId: runtime.runId,
    workflow: runtime.workflow,
    workflowRef: runtime.workflowRef,
    workflowSha: runtime.workflowSha
  });
  return runtime;
}

function phaseIdentity(runtime) {
  return {
    environment: runtime.environment,
    jobName: runtime.jobName,
    lane: runtime.lane,
    phase: runtime.phase,
    principalArn: runtime.principalArn,
    providerAccountId: runtime.providerAccountId,
    repositoryId: runtime.repositoryId,
    repositoryOwnerId: runtime.repositoryOwnerId,
    runAttempt: runtime.runAttempt,
    runId: runtime.runId,
    workflow: runtime.workflow,
    workflowRef: runtime.workflowRef,
    workflowSha: runtime.workflowSha
  };
}

function phaseRuntimeFor(
  claims,
  workspaceRoot,
  phase,
  runId = phase === "COORDINATOR_FINALIZE" ? "1234567892" :
    phase === "PROVIDER_DISPATCH" ? "1234567891" : "1234567890"
) {
  const phaseContract = constants.PHASE_CONTRACTS[phase];
  const laneContract = constants.LANE_CONTRACTS[claims.lane];
  const contract = phase === "PROVIDER_DISPATCH"
    ? laneContract
    : {
        ...constants.COORDINATOR_CONTRACT,
        workflow: laneContract.workflow,
        workflowFile: laneContract.workflowFile
      };
  const jobName = phaseContract.jobName;
  const runtime = {
    schemaVersion: constants.PHASE_RUNTIME_SCHEMA,
    phase,
    lane: claims.lane,
    workflow: contract.workflow,
    workflowRef:
      `Flash-Bri/prooftoact/.github/workflows/${contract.workflowFile}` +
      "@refs/heads/main",
    jobName,
    environment: contract.environment,
    providerAccountId: ACCOUNT_ID,
    principalArn:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/${contract.roleName}/` +
      `pta-${runId}-1-${jobName}`,
    credentialSource: "GITHUB_OIDC_SHORT_LIVED",
    openClawOauthPresent: false,
    staticProviderCredentialsPresent: false,
    rootOrAdministratorPrincipal: false,
    adminDatabaseCredentialPresent: false,
    workspaceRoot,
    appSource: { ...constants.APP_SOURCE },
    brokerArtifactSha256: claims.controlPlane.brokerArtifactSha256,
    controlPlaneBuildSha256: claims.controlPlane.buildSha256,
    controlPlaneCommit: claims.controlPlane.commit,
    controlPlaneIdentitySha256: claims.controlPlane.identitySha256,
    controlPlaneTree: claims.controlPlane.tree,
    buildReceiptSha256: claims.release.buildReceiptSha256,
    artifactManifestSha256: claims.release.artifactManifestSha256,
    releaseReadbackSha256: digest(claims.release),
    region: "us-east-1",
    repositoryId: "1317716765",
    repositoryOwnerId: "252500266",
    runId,
    runAttempt: 1,
    workflowSha: claims.controlPlane.commit,
    authorityReceipts: null
  };
  const identity = phaseIdentity(runtime);
  runtime.authorityReceipts = {
    schemaVersion: constants.PHASE_AUTHORITY_SCHEMA,
    status: "EXACT_PHASE_RUNTIME_AUTHORITY_CONFIRMED",
    providerBacked: true,
    strongRead: true,
    observedAt: "2026-08-17T19:59:00.000Z",
    expiresAt: "2026-08-17T20:10:00.000Z",
    providerIdentitySha256: digest({
      accountId: runtime.providerAccountId,
      principalArn: runtime.principalArn,
      region: runtime.region
    }),
    sourceCheckoutSha256: digest(constants.APP_SOURCE),
    controlPlaneSha256: claims.controlPlane.identitySha256,
    buildReadbackSha256: claims.release.buildReceiptSha256,
    artifactReadbackSha256: claims.release.artifactManifestSha256,
    releaseReadbackSha256: digest(claims.release),
    costCensusSha256: claims.budget.censusReceiptSha256,
    freshDatabaseSha256: claims.database.freshPrimaryReceiptSha256,
    iamSeparationSha256: "d".repeat(64),
    teardownContractSha256: digest(claims.teardown),
    globalStoreSha256: claims.globalStore.tableIdentitySha256,
    workflowIdentitySha256: digest(identity)
  };
  return runtime;
}

class LocalProviderGlobalStore {
  constructor(now = NOW) {
    this.now = now;
    this.records = new Map();
    this.budgets = new Map();
    this.consumeCalls = 0;
    this.intentCalls = 0;
    this.finalizeCalls = 0;
    this.readCalls = 0;
  }

  async consumeOnce(command) {
    this.consumeCalls += 1;
    const existing = this.records.get(command.globalKeySha256);
    if (existing) {
      return {
        ...existing.consumption,
        status: "REPLAY"
      };
    }
    const budget = this.budgets.get(command.budgetKeySha256) ?? {
      cumulativeSpendUsd: command.expectedPriorCumulativeSpendUsd,
      version: 0
    };
    if (budget.cumulativeSpendUsd !== command.expectedPriorCumulativeSpendUsd) {
      throw new Error("synthetic stale global budget census");
    }
    const resultingCumulativeSpendUsd = Number((
      budget.cumulativeSpendUsd + command.budgetReservationUsd
    ).toFixed(6));
    if (resultingCumulativeSpendUsd > command.cumulativeCapUsd) {
      throw new Error("synthetic global budget cap exceeded");
    }
    const consumption = {
      schemaVersion: constants.CONSUMPTION_SCHEMA,
      status: "CONSUMED",
      approvalId: command.approvalId,
      approvalSha256: command.approvalSha256,
      commandSha256: command.commandSha256,
      budgetKeySha256: command.budgetKeySha256,
      budgetVersion: budget.version + 1,
      effectIdentitySha256: command.effectIdentitySha256,
      globalKeySha256: command.globalKeySha256,
      namespaceArn: command.namespaceArn,
      oneShot: true,
      durable: true,
      globallyAuthoritative: true,
      stronglyConsistent: true,
      storeRequestId: STORE_REQUEST_ID,
      version: 1,
      consumedAt: new Date(this.now).toISOString(),
      priorCumulativeSpendUsd: budget.cumulativeSpendUsd,
      reservedSpendUsd: command.budgetReservationUsd,
      resultingCumulativeSpendUsd,
      cumulativeCapUsd: 20
    };
    this.budgets.set(command.budgetKeySha256, {
      cumulativeSpendUsd: resultingCumulativeSpendUsd,
      version: consumption.budgetVersion
    });
    this.records.set(command.globalKeySha256, { command, consumption });
    return consumption;
  }

  async appendIntent({ command, consumption }) {
    this.intentCalls += 1;
    const record = this.records.get(command.globalKeySha256);
    assert.ok(record);
    const intent = {
      schemaVersion: constants.INTENT_SCHEMA,
      status: "DURABLE",
      event: "BEFORE_PROVIDER_DISPATCH",
      action: command.action,
      lane: command.lane,
      approvalId: command.approvalId,
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      intentId: INTENT_ID,
      previousReceiptSha256: digest(consumption),
      version: consumption.version + 1,
      durable: true,
      globallyAuthoritative: true
    };
    if (record.intent) {
      if (digest(record.intent) !== digest(intent)) {
        throw new Error("synthetic create-only intent conflict");
      }
      return record.intent;
    }
    record.intent = intent;
    return intent;
  }

  writeTerminal({ command, predecessor, predecessorState, outcome }) {
    this.finalizeCalls += 1;
    const record = this.records.get(command.globalKeySha256);
    assert.ok(record);
    const terminal = {
      schemaVersion: constants.TERMINAL_SCHEMA,
      status: "TERMINAL",
      approvalId: command.approvalId,
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      predecessorReceiptSha256: digest(predecessor),
      predecessorState,
      outcome,
      recordedAt: new Date(this.now).toISOString(),
      durable: true,
      globallyAuthoritative: true,
      version: predecessor.version + 1
    };
    terminal.terminalSha256 = digest(terminal);
    if (record.terminal) {
      if (record.terminal.terminalSha256 !== terminal.terminalSha256) {
        throw new Error("synthetic create-only terminal conflict");
      }
      return record.terminal;
    }
    record.terminal = terminal;
    return terminal;
  }

  async finalize({ command, intent, outcome }) {
    return this.writeTerminal({
      command,
      outcome,
      predecessor: intent,
      predecessorState: "INTENT"
    });
  }

  async terminalize({ command, consumption, intent, outcome }) {
    return this.writeTerminal({
      command,
      outcome,
      predecessor: intent ?? consumption,
      predecessorState: intent ? "INTENT" : "CONSUMPTION"
    });
  }

  async terminalizeExpired({
    approvalExpiresAt,
    command,
    consumption,
    intent,
    outcome
  }) {
    if (this.now < Date.parse(approvalExpiresAt)) {
      throw new Error("synthetic terminalization not due");
    }
    return {
      schemaVersion: constants.TERMINALIZATION_SCHEMA,
      clockSource: "TRUSTED_RUNTIME_SAFETY_REDUCING_OBSERVATION",
      observedAt: new Date(this.now).toISOString(),
      approvalExpiresAt,
      safetyReducingOnly: true,
      effectOccupancyReleased: false,
      budgetReservationReleased: false,
      terminal: this.writeTerminal({
        command,
        outcome,
        predecessor: intent ?? consumption,
        predecessorState: intent ? "INTENT" : "CONSUMPTION"
      })
    };
  }

  async readStrong({ globalKeySha256 }) {
    this.readCalls += 1;
    const record = this.records.get(globalKeySha256);
    return {
      schemaVersion: constants.RECORD_SCHEMA,
      status: record?.terminal ? "TERMINAL" : record?.intent
        ? "INTENT" : "CONSUMED",
      command: record?.command ?? null,
      consumption: record?.consumption ?? null,
      intent: record?.intent ?? null,
      terminal: record?.terminal ?? null
    };
  }
}

function confirmedDispatcher(trace = []) {
  return {
    async dispatch({ command }) {
      trace.push(command.operationIdentitySha256);
      return {
        schemaVersion: constants.OUTCOME_SCHEMA,
        status: "CONFIRMED",
        operationIdentitySha256: command.operationIdentitySha256,
        possibleMutation: command.providerMutationExpected,
        providerRequestId: PROVIDER_REQUEST_ID,
        observedAt: new Date(NOW).toISOString(),
        providerReceiptSha256: "e".repeat(64)
      };
    }
  };
}

function readOnlyReconciler(trace = [], now = NOW) {
  return {
    async reconcile(input) {
      trace.push(input);
      return {
        schemaVersion: constants.RECONCILIATION_SCHEMA,
        status: "UNKNOWN",
        fresh: true,
        readOnly: true,
        workflow: constants.AUTHORITY_CONTRACTS.evidence.workflow,
        roleName: constants.AUTHORITY_CONTRACTS.evidence.roleName,
        operationIdentitySha256: input.operationIdentitySha256,
        providerRequestId: RECONCILIATION_REQUEST_ID,
        providerReceiptSha256: "f".repeat(64),
        observedAt: new Date(now).toISOString()
      };
    }
  };
}

function reserveStoreFacade(store) {
  return Object.freeze({
    appendIntent: store.appendIntent.bind(store),
    consumeOnce: store.consumeOnce.bind(store),
    readStrong: store.readStrong.bind(store)
  });
}

function permitReaderFacade(store) {
  return Object.freeze({
    readStrong: store.readStrong.bind(store)
  });
}

function finalizerStoreFacade(store) {
  return Object.freeze({
    finalize: store.finalize.bind(store),
    readStrong: store.readStrong.bind(store)
  });
}

function finalizerReadback(runtime, {
  preparedRelease = null,
  status = "CONFIRMED_APPLIED",
  trace = []
} = {}) {
  return Object.freeze({
    async readback(input) {
      trace.push(input);
      return {
        schemaVersion: constants.FINALIZER_READBACK_SCHEMA,
        status,
        fresh: true,
        readOnly: true,
        independentOfDispatcher: true,
        commandSha256: input.command.commandSha256,
        intentSha256: digest(input.intent),
        operationIdentitySha256: input.command.operationIdentitySha256,
        providerNativeIdempotencyTokenSha256:
          brokerSha256(Buffer.from(input.intent.intentId, "utf8")),
        providerRequestId: status === "UNKNOWN" ? null : PROVIDER_REQUEST_ID,
        providerReceiptSha256: "e".repeat(64),
        preparedRelease,
        readerPhaseRuntimeIdentitySha256: digest(phaseIdentity(runtime)),
        observedAt: new Date(NOW).toISOString()
      };
    }
  });
}

function phaseFixture(t, {
  approvalId = APPROVAL_ID,
  lane = "EXECUTE"
} = {}) {
  const base = fixture(t, { approvalId, lane });
  return {
    ...base,
    coordinatorReserveRuntime: phaseRuntimeFor(
      base.claims,
      base.workspaceRoot,
      "COORDINATOR_RESERVE"
    ),
    providerRuntime: phaseRuntimeFor(
      base.claims,
      base.workspaceRoot,
      "PROVIDER_DISPATCH"
    ),
    coordinatorFinalizerRuntime: phaseRuntimeFor(
      base.claims,
      base.workspaceRoot,
      "COORDINATOR_FINALIZE"
    )
  };
}

function fixture(t, {
  approvalId = APPROVAL_ID,
  authority = true,
  lane = "EXECUTE"
} = {}) {
  const workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pta-broker-work-"));
  fs.chmodSync(workspaceRoot, 0o700);
  t.after(() => fs.rmSync(workspaceRoot, { force: true, recursive: true }));
  const claims = approvalClaims(workspaceRoot, lane, approvalId);
  return {
    approvalEnvelope: signApproval(claims),
    claims,
    dispatcher: confirmedDispatcher(),
    environment: {},
    globalStore: new LocalProviderGlobalStore(),
    now: NOW,
    reconciler: readOnlyReconciler(),
    runtime: runtimeFor(claims, workspaceRoot, authority),
    trustedOperatorPublicKey: PUBLIC_KEY,
    workspaceRoot
  };
}

test("broker freezes the application while separating its control plane", (t) => {
  const input = fixture(t);
  const accepted = validateProviderBrokerApproval(
    input.approvalEnvelope,
    PUBLIC_KEY,
    NOW
  );
  assert.deepEqual(accepted.claims.appSource, {
    repository: "Flash-Bri/prooftoact",
    commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
    tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
  });
  assert.notEqual(
    accepted.claims.controlPlane.identitySha256,
    digest(accepted.claims.appSource)
  );
  assert.equal(accepted.claims.budget.cumulativeCapUsd, 20);
  assert.deepEqual(accepted.claims.limits, {
    maximumRuns: 1,
    maximumConcurrency: 2
  });
  assert.equal(accepted.claims.database.freshCluster, true);
  assert.equal(accepted.claims.teardown.separateApprovalRequired, true);
});

test("phase runtimes share one signed command while capabilities remain split", async (t) => {
  const input = phaseFixture(t);
  let forbiddenCoordinatorDispatches = 0;
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    dispatcher: {
      async dispatch() {
        forbiddenCoordinatorDispatches += 1;
        throw new Error("coordinator must never dispatch");
      }
    },
    globalStore: reserveStoreFacade(input.globalStore)
  });
  assert.equal(reserved.receipt.status, "INTENT_RECORDED");
  assert.equal(forbiddenCoordinatorDispatches, 0);
  assert.deepEqual(Object.keys(reserved.lookup).sort(), [
    "approvalSha256", "commandSha256", "globalKeySha256", "intentSha256",
    "lookupSha256", "namespaceArnSha256", "schemaVersion",
    "tableIdentitySha256"
  ]);

  const permitReader = permitReaderFacade(input.globalStore);
  assert.equal("consumeOnce" in permitReader, false);
  assert.equal("appendIntent" in permitReader, false);
  assert.equal("finalize" in permitReader, false);
  const dispatches = [];
  const dispatched = await dispatchReservedProviderOneShotIntent({
    ...input,
    dispatcher: {
      async dispatch(request) {
        dispatches.push(request);
        return confirmedDispatcher().dispatch(request);
      }
    },
    intentReader: permitReader,
    lookup: reserved.lookup,
    providerRuntime: input.providerRuntime
  });
  assert.equal(dispatched.receipt.status, "DISPATCH_OBSERVED");
  assert.equal(dispatched.lookup.commandSha256, reserved.lookup.commandSha256);
  assert.equal(dispatches.length, 1);
  assert.equal(dispatches[0].maxAttempts, 1);
  assert.equal(dispatches[0].providerNativeIdempotencyToken, INTENT_ID);
  assert.equal(dispatches[0].dispatchPlan.steps.length, 1);
  assert.equal(dispatches[0].dispatchPlan.steps[0].maximumAttempts, 1);
  assert.equal(
    dispatches[0].dispatchPlan.steps[0].providerNativeIdempotencyToken,
    INTENT_ID
  );

  const readbacks = [];
  const finalized = await finalizeProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    dispatcherOutcome: dispatched.receipt,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    providerReadback: finalizerReadback(
      input.coordinatorFinalizerRuntime,
      { trace: readbacks }
    )
  });
  assert.equal(finalized.receipt.status, "CONFIRMED");
  assert.equal(readbacks.length, 1);
  assert.equal(finalized.receipt.commandSha256, reserved.lookup.commandSha256);
  assert.notEqual(
    reserved.receipt.phaseRuntimeIdentity.phaseRuntimeIdentitySha256,
    dispatched.receipt.phaseRuntimeIdentity.phaseRuntimeIdentitySha256
  );
  assert.notEqual(
    dispatched.receipt.phaseRuntimeIdentity.phaseRuntimeIdentitySha256,
    finalized.receipt.phaseRuntimeIdentity.phaseRuntimeIdentitySha256
  );
});

test("phase APIs reject crossed store-write and provider capabilities", async (t) => {
  const input = phaseFixture(t);
  await assert.rejects(
    () => reserveProviderOneShotIntent({
      ...input,
      coordinatorRuntime: input.coordinatorReserveRuntime,
      globalStore: {
        ...reserveStoreFacade(input.globalStore),
        dispatch: async () => {
          throw new Error("must remain unreachable");
        }
      }
    }),
    /PROVIDER_BROKER_COORDINATOR_RESERVE_CAPABILITY_REJECTED/u
  );
  assert.equal(input.globalStore.consumeCalls, 0);

  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  let dispatches = 0;
  await assert.rejects(
    () => dispatchReservedProviderOneShotIntent({
      ...input,
      dispatcher: {
        async dispatch() {
          dispatches += 1;
        }
      },
      intentReader: {
        ...permitReaderFacade(input.globalStore),
        consumeOnce: input.globalStore.consumeOnce.bind(input.globalStore)
      },
      lookup: reserved.lookup,
      providerRuntime: input.providerRuntime
    }),
    /PROVIDER_BROKER_PERMIT_READER_CAPABILITY_REJECTED/u
  );
  assert.equal(dispatches, 0);
});

test("phase runtime binds exact workflow, ref, job, environment, STS session, and authority", async (t) => {
  const runtimeMutations = [
    (runtime) => { runtime.workflow = "ProofToAct Wrong Workflow"; },
    (runtime) => { runtime.workflowRef = runtime.workflowRef.replace("main", "dev"); },
    (runtime) => { runtime.jobName = "provider-dispatch"; },
    (runtime) => { runtime.environment = "aws-release-execution"; },
    (runtime) => {
      runtime.principalArn = runtime.principalArn.replace(
        /coordinator-reserve$/u,
        "unbound-session"
      );
    }
  ];
  for (const mutate of runtimeMutations) {
    const input = phaseFixture(t);
    mutate(input.coordinatorReserveRuntime);
    await assert.rejects(
      () => reserveProviderOneShotIntent({
        ...input,
        coordinatorRuntime: input.coordinatorReserveRuntime,
        globalStore: reserveStoreFacade(input.globalStore)
      }),
      /PROVIDER_BROKER_PHASE_RUNTIME_REJECTED/u
    );
    assert.equal(input.globalStore.consumeCalls, 0);
  }

  const forgedAuthority = phaseFixture(t);
  forgedAuthority.coordinatorReserveRuntime.authorityReceipts
    .workflowIdentitySha256 = "0".repeat(64);
  await assert.rejects(
    () => reserveProviderOneShotIntent({
      ...forgedAuthority,
      coordinatorRuntime: forgedAuthority.coordinatorReserveRuntime,
      globalStore: reserveStoreFacade(forgedAuthority.globalStore)
    }),
    /PROVIDER_BROKER_PHASE_RUNTIME_AUTHORITY_REJECTED/u
  );
  assert.equal(forgedAuthority.globalStore.consumeCalls, 0);
});

test("every lane derives coordinator workflow from its signed lane contract", async (t) => {
  for (const lane of ["PREPARE", "EXECUTE", "DRILL", "EVIDENCE", "TEARDOWN"]) {
    const input = phaseFixture(t, { lane });
    const laneContract = constants.LANE_CONTRACTS[lane];
    for (const runtime of [
      input.coordinatorReserveRuntime,
      input.coordinatorFinalizerRuntime
    ]) {
      assert.equal(runtime.workflow, laneContract.workflow);
      assert.equal(
        runtime.workflowRef,
        `Flash-Bri/prooftoact/.github/workflows/${laneContract.workflowFile}` +
          "@refs/heads/main"
      );
      assert.equal(runtime.environment, "aws-release-coordination");
      assert.match(runtime.principalArn, /\/ProofToActReleaseCoordinator\//u);
    }
    assert.equal(input.providerRuntime.workflow, laneContract.workflow);
    assert.equal(input.providerRuntime.environment, laneContract.environment);
    assert.match(
      input.providerRuntime.principalArn,
      new RegExp(`/${laneContract.roleName}/`, "u")
    );

    const reserved = await reserveProviderOneShotIntent({
      ...input,
      coordinatorRuntime: input.coordinatorReserveRuntime,
      globalStore: reserveStoreFacade(input.globalStore)
    });
    await dispatchReservedProviderOneShotIntent({
      ...input,
      dispatcher: confirmedDispatcher(),
      intentReader: permitReaderFacade(input.globalStore),
      lookup: reserved.lookup,
      providerRuntime: input.providerRuntime
    });
    const finalized = await finalizeProviderOneShotIntent({
      ...input,
      coordinatorRuntime: input.coordinatorFinalizerRuntime,
      globalStore: finalizerStoreFacade(input.globalStore),
      lookup: reserved.lookup,
      providerReadback: finalizerReadback(
        input.coordinatorFinalizerRuntime,
        { status: "UNKNOWN" }
      )
    });
    assert.equal(finalized.receipt.status, "UNKNOWN_DO_NOT_ACT");
  }
});

test("cross-lane coordinator workflow and provider role substitution reject", async (t) => {
  const coordinatorCross = phaseFixture(t, { lane: "EXECUTE" });
  const drill = constants.LANE_CONTRACTS.DRILL;
  coordinatorCross.coordinatorReserveRuntime.workflow = drill.workflow;
  coordinatorCross.coordinatorReserveRuntime.workflowRef =
    `Flash-Bri/prooftoact/.github/workflows/${drill.workflowFile}` +
    "@refs/heads/main";
  coordinatorCross.coordinatorReserveRuntime.authorityReceipts
    .workflowIdentitySha256 = digest(
      phaseIdentity(coordinatorCross.coordinatorReserveRuntime)
    );
  await assert.rejects(
    () => reserveProviderOneShotIntent({
      ...coordinatorCross,
      coordinatorRuntime: coordinatorCross.coordinatorReserveRuntime,
      globalStore: reserveStoreFacade(coordinatorCross.globalStore)
    }),
    /PROVIDER_BROKER_PHASE_RUNTIME_REJECTED/u
  );

  const providerCross = phaseFixture(t, { lane: "EXECUTE" });
  const reserved = await reserveProviderOneShotIntent({
    ...providerCross,
    coordinatorRuntime: providerCross.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(providerCross.globalStore)
  });
  providerCross.providerRuntime.environment = "aws-release-coordination";
  providerCross.providerRuntime.principalArn =
    providerCross.providerRuntime.principalArn.replace(
      /ProofToActReleaseExecution/u,
      "ProofToActReleaseCoordinator"
    );
  providerCross.providerRuntime.authorityReceipts.workflowIdentitySha256 =
    digest(phaseIdentity(providerCross.providerRuntime));
  providerCross.providerRuntime.authorityReceipts.providerIdentitySha256 =
    digest({
      accountId: providerCross.providerRuntime.providerAccountId,
      principalArn: providerCross.providerRuntime.principalArn,
      region: providerCross.providerRuntime.region
    });
  await assert.rejects(
    () => dispatchReservedProviderOneShotIntent({
      ...providerCross,
      dispatcher: confirmedDispatcher(),
      intentReader: permitReaderFacade(providerCross.globalStore),
      lookup: reserved.lookup,
      providerRuntime: providerCross.providerRuntime
    }),
    /PROVIDER_BROKER_PHASE_RUNTIME_REJECTED/u
  );
});

test("reserve does not append intent when approval expires after consumption", async (t) => {
  const input = phaseFixture(t);
  const expiresAt = NOW + 1_000;
  input.approvalEnvelope = signApproval(input.claims, {
    expiresAt: new Date(expiresAt).toISOString()
  });
  let currentTime = NOW;
  const consumeOnce = input.globalStore.consumeOnce.bind(input.globalStore);
  input.globalStore.consumeOnce = async (command) => {
    const consumption = await consumeOnce(command);
    currentTime = expiresAt;
    return consumption;
  };
  const result = await reserveProviderOneShotIntent({
    ...input,
    clock: () => currentTime,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore),
    now: undefined
  });
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(input.globalStore.consumeCalls, 1);
  assert.equal(input.globalStore.intentCalls, 0);
  assert.equal(
    input.globalStore.records.values().next().value.intent,
    undefined
  );
});

test("dispatch does not call provider at the exact approval expiry boundary", async (t) => {
  const input = phaseFixture(t);
  const expiresAt = NOW + 1_000;
  input.approvalEnvelope = signApproval(input.claims, {
    expiresAt: new Date(expiresAt).toISOString()
  });
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  let currentTime = NOW;
  let dispatches = 0;
  const reader = permitReaderFacade(input.globalStore);
  const intentReader = Object.freeze({
    async readStrong(request) {
      const record = await reader.readStrong(request);
      currentTime = expiresAt;
      return record;
    }
  });
  const result = await dispatchReservedProviderOneShotIntent({
    ...input,
    clock: () => currentTime,
    dispatcher: {
      async dispatch() {
        dispatches += 1;
        throw new Error("dispatch must remain unreachable");
      }
    },
    intentReader,
    lookup: reserved.lookup,
    now: undefined,
    providerRuntime: input.providerRuntime
  });
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(dispatches, 0);
});

test("dispatcher validates a delayed provider observation against post-await time", async (t) => {
  const input = phaseFixture(t);
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  let currentTime = NOW;
  const result = await dispatchReservedProviderOneShotIntent({
    ...input,
    clock: () => currentTime,
    dispatcher: {
      async dispatch({ command }) {
        currentTime = NOW + 5_000;
        return {
          schemaVersion: constants.OUTCOME_SCHEMA,
          status: "CONFIRMED",
          operationIdentitySha256: command.operationIdentitySha256,
          possibleMutation: command.providerMutationExpected,
          providerRequestId: PROVIDER_REQUEST_ID,
          observedAt: new Date(currentTime).toISOString(),
          providerReceiptSha256: "e".repeat(64)
        };
      }
    },
    intentReader: permitReaderFacade(input.globalStore),
    lookup: reserved.lookup,
    now: undefined,
    providerRuntime: input.providerRuntime
  });
  assert.equal(result.receipt.status, "DISPATCH_OBSERVED");
  assert.equal(result.receipt.outcomeStatus, "CONFIRMED");
});

test("finalizer accepts delayed readback only against its fresh post-await time", async (t) => {
  const input = phaseFixture(t);
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  let currentTime = NOW;
  const exactReadback = finalizerReadback(
    input.coordinatorFinalizerRuntime
  );
  const result = await finalizeProviderOneShotIntent({
    ...input,
    clock: () => currentTime,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    now: undefined,
    providerReadback: {
      async readback(request) {
        currentTime = NOW + 5_000;
        return {
          ...await exactReadback.readback(request),
          observedAt: new Date(currentTime).toISOString()
        };
      }
    }
  });
  assert.equal(result.receipt.status, "CONFIRMED");
  assert.equal(result.receipt.outcomeStatus, "CONFIRMED");
  assert.equal(input.globalStore.finalizeCalls, 1);
});

test("finalizer resamples after readback and refuses terminal write at expiry", async (t) => {
  const input = phaseFixture(t);
  const expiresAt = NOW + 1_000;
  input.approvalEnvelope = signApproval(input.claims, {
    expiresAt: new Date(expiresAt).toISOString()
  });
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  let currentTime = NOW;
  let readbackComplete = false;
  const clock = () => {
    if (readbackComplete) {
      currentTime = currentTime === NOW ? expiresAt - 1 : expiresAt;
    }
    return currentTime;
  };
  const exactReadback = finalizerReadback(
    input.coordinatorFinalizerRuntime
  );
  const result = await finalizeProviderOneShotIntent({
    ...input,
    clock,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    now: undefined,
    providerReadback: {
      async readback(request) {
        const observed = await exactReadback.readback(request);
        readbackComplete = true;
        return {
          ...observed,
          observedAt: new Date(expiresAt - 1).toISOString()
        };
      }
    }
  });
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(input.globalStore.finalizeCalls, 0);
  assert.equal(
    input.globalStore.records.values().next().value.terminal,
    undefined
  );
});

test("dispatcher rejects absent, consumed, terminal, expired, and mismatched intent", async (t) => {
  const makeReserved = async () => {
    const input = phaseFixture(t);
    const reserved = await reserveProviderOneShotIntent({
      ...input,
      coordinatorRuntime: input.coordinatorReserveRuntime,
      globalStore: reserveStoreFacade(input.globalStore)
    });
    return { input, reserved };
  };
  const attempt = ({ input, reserved, now = NOW }) =>
    dispatchReservedProviderOneShotIntent({
      ...input,
      dispatcher: confirmedDispatcher(),
      intentReader: permitReaderFacade(input.globalStore),
      lookup: reserved.lookup,
      now,
      providerRuntime: input.providerRuntime
    });

  const absent = await makeReserved();
  absent.input.globalStore.records.clear();
  await assert.rejects(
    () => attempt(absent),
    /PROVIDER_BROKER_DISPATCH_INTENT_REJECTED/u
  );

  const consumed = await makeReserved();
  const consumedRecord = consumed.input.globalStore.records.values().next().value;
  delete consumedRecord.intent;
  await assert.rejects(
    () => attempt(consumed),
    /PROVIDER_BROKER_DISPATCH_INTENT_REJECTED/u
  );

  const terminal = await makeReserved();
  await finalizeProviderOneShotIntent({
    ...terminal.input,
    coordinatorRuntime: terminal.input.coordinatorFinalizerRuntime,
    globalStore: finalizerStoreFacade(terminal.input.globalStore),
    lookup: terminal.reserved.lookup,
    providerReadback: finalizerReadback(
      terminal.input.coordinatorFinalizerRuntime
    )
  });
  await assert.rejects(
    () => attempt(terminal),
    /PROVIDER_BROKER_DISPATCH_INTENT_REJECTED/u
  );

  const expired = await makeReserved();
  await assert.rejects(
    () => attempt({ ...expired, now: Date.parse(EXPIRES_AT) }),
    /PROVIDER_BROKER_APPROVAL_REJECTED/u
  );

  const mismatch = await makeReserved();
  const mismatchedLookup = {
    ...mismatch.reserved.lookup,
    intentSha256: "0".repeat(64)
  };
  await assert.rejects(
    () => dispatchReservedProviderOneShotIntent({
      ...mismatch.input,
      dispatcher: confirmedDispatcher(),
      intentReader: permitReaderFacade(mismatch.input.globalStore),
      lookup: mismatchedLookup,
      providerRuntime: mismatch.input.providerRuntime
    }),
    /PROVIDER_BROKER_PHASE_LOOKUP_REJECTED/u
  );
});

test("finalizer ignores forged dispatcher success and trusts only fresh readback", async (t) => {
  const input = phaseFixture(t);
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  const forgedDispatcherSuccess = {
    schemaVersion: constants.OUTCOME_SCHEMA,
    status: "CONFIRMED",
    operationIdentitySha256: "0".repeat(64),
    possibleMutation: true,
    providerRequestId: PROVIDER_REQUEST_ID,
    observedAt: new Date(NOW).toISOString(),
    providerReceiptSha256: "0".repeat(64)
  };
  const unknown = await finalizeProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    dispatcherOutcome: forgedDispatcherSuccess,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    providerReadback: finalizerReadback(
      input.coordinatorFinalizerRuntime,
      { status: "UNKNOWN" }
    )
  });
  assert.equal(unknown.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(unknown.receipt.outcomeStatus, "AMBIGUOUS");
  assert.notEqual(
    unknown.receipt.outcomeProviderReceiptSha256,
    forgedDispatcherSuccess.providerReceiptSha256
  );
});

test("malformed or contradictory finalizer readback terminalizes as ambiguous", async (t) => {
  const input = phaseFixture(t);
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  const result = await finalizeProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    providerReadback: {
      async readback() {
        return { forged: "dispatcher success" };
      }
    }
  });
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(input.globalStore.records.values().next().value.terminal.outcome.status,
    "AMBIGUOUS");
});

test("PREPARE uses deterministic inputs and emits real IDs only after readback", async (t) => {
  const input = phaseFixture(t, { lane: "PREPARE" });
  assert.equal(Object.hasOwn(input.claims.release, "changeSetArn"), false);
  assert.equal(Object.hasOwn(input.claims.release, "stackId"), false);
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  const dispatchTrace = [];
  await dispatchReservedProviderOneShotIntent({
    ...input,
    dispatcher: {
      async dispatch(request) {
        dispatchTrace.push(request);
        return confirmedDispatcher().dispatch(request);
      }
    },
    intentReader: permitReaderFacade(input.globalStore),
    lookup: reserved.lookup,
    providerRuntime: input.providerRuntime
  });
  assert.equal(dispatchTrace[0].command.changeSetName, CHANGE_SET_NAME);
  assert.equal(dispatchTrace[0].command.templateSha256, "3".repeat(64));
  assert.equal(Object.hasOwn(dispatchTrace[0].command, "changeSetArn"), false);
  assert.equal(Object.hasOwn(dispatchTrace[0].command, "stackId"), false);
  assert.equal(dispatchTrace[0].providerNativeIdempotencyToken, INTENT_ID);
  assert.equal(dispatchTrace[0].dispatchPlan.brokerDispatcherInvocationCount, 1);
  assert.equal(dispatchTrace[0].dispatchPlan.noAutomaticRetry, true);
  assert.deepEqual(
    dispatchTrace[0].dispatchPlan.steps.map(({ name }) => name),
    [
      "CONDITIONAL_EXACT_S3_ARTIFACT_UPLOAD_SET",
      "CREATE_EXACT_CHANGE_SET"
    ]
  );
  assert.equal(
    dispatchTrace[0].dispatchPlan.steps.every(({ maximumAttempts }) =>
      maximumAttempts === 1),
    true
  );
  assert.equal(
    dispatchTrace[0].dispatchPlan.steps.every(({ idempotencyBindingSha256 }) =>
      /^[0-9a-f]{64}$/u.test(idempotencyBindingSha256)),
    true
  );
  assert.equal(
    dispatchTrace[0].dispatchPlan.steps[0].idempotencyMechanism,
    "CONTENT_ADDRESSED_CREATE_OR_EXACT_REUSE_ONLY"
  );
  assert.equal(
    dispatchTrace[0].dispatchPlan.steps[1].providerNativeIdempotencyToken,
    INTENT_ID
  );

  const preparedRelease = {
    changeSetArn: CHANGE_SET_ARN,
    changeSetName: CHANGE_SET_NAME,
    changeSetSha256: "6".repeat(64),
    changeSetType: "CREATE",
    stackId: STACK_ID,
    stackName: "prooftoact-gate2"
  };
  const finalized = await finalizeProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    providerReadback: finalizerReadback(
      input.coordinatorFinalizerRuntime,
      { preparedRelease }
    )
  });
  assert.equal(finalized.receipt.status, "CONFIRMED");
  assert.deepEqual(finalized.preparedRelease, preparedRelease);

  const executeClaims = approvalClaims(input.workspaceRoot, "EXECUTE");
  executeClaims.release.changeSetArn = finalized.preparedRelease.changeSetArn;
  executeClaims.release.changeSetSha256 =
    finalized.preparedRelease.changeSetSha256;
  executeClaims.release.stackId = finalized.preparedRelease.stackId;
  executeClaims.teardown.deleteExactStackId = finalized.preparedRelease.stackId;
  executeClaims.teardown.originatingChangeSetArn =
    finalized.preparedRelease.changeSetArn;
  executeClaims.teardown.originatingChangeSetSha256 =
    finalized.preparedRelease.changeSetSha256;
  assert.equal(
    validateProviderBrokerApproval(
      signApproval(executeClaims),
      PUBLIC_KEY,
      NOW
    ).claims.lane,
    "EXECUTE"
  );
});

test("PREPARE effect occupancy ignores approval and control-plane metadata", async (t) => {
  const first = phaseFixture(t, { lane: "PREPARE" });
  const second = phaseFixture(t, {
    approvalId: SECOND_APPROVAL_ID,
    lane: "PREPARE"
  });
  second.claims.teardown.deadline = "2026-09-17T00:30:00.000Z";
  second.claims.controlPlane.commit = "c".repeat(40);
  second.claims.controlPlane.tree = "d".repeat(40);
  second.claims.controlPlane.buildSha256 = "3".repeat(64);
  const unsignedControlPlane = { ...second.claims.controlPlane };
  delete unsignedControlPlane.identitySha256;
  second.claims.controlPlane.identitySha256 = digest(unsignedControlPlane);
  second.approvalEnvelope = signApproval(second.claims);
  second.coordinatorReserveRuntime = phaseRuntimeFor(
    second.claims,
    second.workspaceRoot,
    "COORDINATOR_RESERVE"
  );
  const firstReserved = await reserveProviderOneShotIntent({
    ...first,
    coordinatorRuntime: first.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(first.globalStore)
  });
  const secondReserved = await reserveProviderOneShotIntent({
    ...second,
    coordinatorRuntime: second.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(second.globalStore)
  });
  assert.equal(
    firstReserved.lookup.globalKeySha256,
    secondReserved.lookup.globalKeySha256
  );
  assert.notEqual(
    firstReserved.lookup.commandSha256,
    secondReserved.lookup.commandSha256
  );
});

test("expired PREPARE intent terminalizes without invented provider IDs", async (t) => {
  const input = phaseFixture(t, { lane: "PREPARE" });
  await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  input.globalStore.now = EXPIRED_NOW;
  const terminalized = await terminalizeExpiredProviderOneShotBroker({
    ...input,
    now: EXPIRED_NOW,
    reconciler: readOnlyReconciler([], EXPIRED_NOW),
    terminalizerRuntime: terminalizerRuntimeFor(
      input.claims,
      input.workspaceRoot
    )
  });
  assert.equal(terminalized.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(terminalized.receipt.outcomeProviderRequestId, null);
  assert.equal(Object.hasOwn(input.claims.release, "changeSetArn"), false);
  assert.equal(Object.hasOwn(input.claims.release, "stackId"), false);
});

test("one unexpired approval is consumed and dispatched exactly once globally", async (t) => {
  const input = fixture(t);
  const trace = [];
  input.dispatcher = confirmedDispatcher(trace);
  const first = await runProviderOneShotBroker(input);
  assert.equal(first.receipt.status, "CONFIRMED");
  assert.equal(first.authorityConsumptionStatus, "CONSUMED_THIS_INVOCATION");
  assert.equal(first.dispatchStatus, "OUTCOME_RECEIVED");
  assert.equal(first.replayRejected, false);
  assert.equal(input.globalStore.consumeCalls, 1);
  assert.equal(input.globalStore.intentCalls, 1);
  assert.equal(input.globalStore.finalizeCalls, 1);
  assert.equal(trace.length, 1);

  const replay = await runProviderOneShotBroker(input);
  assert.equal(replay.receipt.status, "CONFIRMED");
  assert.equal(replay.authorityConsumptionStatus, "PREVIOUSLY_CONSUMED");
  assert.equal(replay.dispatchStatus, "PREVIOUSLY_RECORDED");
  assert.equal(replay.replayRejected, true);
  assert.equal(replay.receipt.receiptSha256, first.receipt.receiptSha256);
  assert.equal(input.globalStore.consumeCalls, 2);
  assert.equal(input.globalStore.intentCalls, 1);
  assert.equal(input.globalStore.finalizeCalls, 1);
  assert.equal(input.globalStore.readCalls, 1);
  assert.equal(trace.length, 1);
});

test("racing brokers cannot turn one approval into two dispatches", async (t) => {
  const input = fixture(t);
  const trace = [];
  input.dispatcher = confirmedDispatcher(trace);
  const [left, right] = await Promise.all([
    runProviderOneShotBroker(input),
    runProviderOneShotBroker(input)
  ]);
  assert.equal(trace.length, 1);
  assert.equal(input.globalStore.intentCalls, 1);
  assert.equal(input.globalStore.finalizeCalls, 1);
  assert.equal(
    [left, right].filter(({ dispatchStatus }) =>
      dispatchStatus === "OUTCOME_RECEIVED").length,
    1
  );
  assert.equal(
    [left, right].every(({ receipt }) =>
      ["CONFIRMED", "UNKNOWN_DO_NOT_ACT"].includes(receipt.status)),
    true
  );
});

test("separate approvals cannot dispatch the same provider effect twice", async (t) => {
  const first = fixture(t);
  const second = fixture(t, { approvalId: SECOND_APPROVAL_ID });
  second.claims.teardown.deadline = "2026-09-17T00:30:00.000Z";
  second.claims.controlPlane.commit = "c".repeat(40);
  second.claims.controlPlane.tree = "d".repeat(40);
  second.claims.controlPlane.buildSha256 = "3".repeat(64);
  const unsignedControlPlane = { ...second.claims.controlPlane };
  delete unsignedControlPlane.identitySha256;
  second.claims.controlPlane.identitySha256 = digest(unsignedControlPlane);
  second.approvalEnvelope = signApproval(second.claims);
  second.runtime = runtimeFor(second.claims, second.workspaceRoot);
  const trace = [];
  first.dispatcher = confirmedDispatcher(trace);
  second.dispatcher = confirmedDispatcher(trace);
  second.globalStore = first.globalStore;

  const accepted = await runProviderOneShotBroker(first);
  const occupied = await runProviderOneShotBroker(second);

  assert.equal(accepted.receipt.status, "CONFIRMED");
  assert.equal(occupied.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(occupied.authorityConsumptionStatus, "UNKNOWN");
  assert.equal(occupied.dispatchStatus, "NOT_ATTEMPTED");
  assert.equal(trace.length, 1);
  assert.equal(first.globalStore.records.size, 1);
});

test("teardown occupancy is bound to the physical stack across approvals", async (t) => {
  const first = fixture(t, { lane: "TEARDOWN" });
  const second = fixture(t, {
    approvalId: SECOND_APPROVAL_ID,
    lane: "TEARDOWN"
  });
  second.claims.teardown.deadline = "2026-09-17T00:30:00.000Z";
  second.claims.controlPlane.commit = "c".repeat(40);
  second.claims.controlPlane.tree = "d".repeat(40);
  second.claims.controlPlane.buildSha256 = "3".repeat(64);
  const unsignedControlPlane = { ...second.claims.controlPlane };
  delete unsignedControlPlane.identitySha256;
  second.claims.controlPlane.identitySha256 = digest(unsignedControlPlane);
  second.approvalEnvelope = signApproval(second.claims);
  second.runtime = runtimeFor(second.claims, second.workspaceRoot);
  const trace = [];
  first.dispatcher = confirmedDispatcher(trace);
  second.dispatcher = confirmedDispatcher(trace);
  second.globalStore = first.globalStore;

  const removed = await runProviderOneShotBroker(first);
  const occupied = await runProviderOneShotBroker(second);

  assert.equal(removed.receipt.status, "CONFIRMED");
  assert.equal(removed.receipt.stackId, STACK_ID);
  assert.equal(occupied.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(occupied.dispatchStatus, "NOT_ATTEMPTED");
  assert.equal(trace.length, 1);
  assert.equal(first.globalStore.records.size, 1);
});

test("separate effects share one atomic cumulative budget ledger", async (t) => {
  const execute = fixture(t, { lane: "EXECUTE" });
  const drill = fixture(t, {
    approvalId: SECOND_APPROVAL_ID,
    lane: "DRILL"
  });
  const trace = [];
  execute.dispatcher = confirmedDispatcher(trace);
  drill.dispatcher = confirmedDispatcher(trace);
  drill.globalStore = execute.globalStore;

  const executed = await runProviderOneShotBroker(execute);
  const staleBudget = await runProviderOneShotBroker(drill);

  assert.equal(executed.receipt.status, "CONFIRMED");
  assert.equal(staleBudget.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(staleBudget.dispatchStatus, "NOT_ATTEMPTED");
  assert.equal(trace.length, 1);
  assert.equal(execute.globalStore.budgets.size, 1);
  assert.equal(
    execute.globalStore.budgets.values().next().value.cumulativeSpendUsd,
    6
  );
});

test("missing or stale runtime authority keeps provider execution disabled", async (t) => {
  const missing = fixture(t, { authority: false });
  const held = await runProviderOneShotBroker(missing);
  assert.equal(held.receipt.status, "HOLD");
  assert.equal(
    held.receipt.reason,
    "PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED"
  );
  assert.equal(held.receipt.authorityConsumed, false);
  assert.equal(missing.globalStore.consumeCalls, 0);

  const stale = fixture(t);
  stale.runtime.authorityReceipts.expiresAt =
    "2026-08-17T20:00:00.000Z";
  const staleHeld = await runProviderOneShotBroker(stale);
  assert.equal(staleHeld.receipt.status, "HOLD");
  assert.equal(stale.globalStore.consumeCalls, 0);
});

test("stale approval, copied directory, and crossed workflow fail before consume", async (t) => {
  const expired = fixture(t);
  await assert.rejects(
    () => runProviderOneShotBroker({
      ...expired,
      now: Date.parse(EXPIRES_AT)
    }),
    /PROVIDER_BROKER_APPROVAL_REJECTED/u
  );
  assert.equal(expired.globalStore.consumeCalls, 0);

  const copied = fixture(t);
  const other = fs.mkdtempSync(path.join(os.tmpdir(), "pta-broker-copy-"));
  fs.chmodSync(other, 0o700);
  t.after(() => fs.rmSync(other, { force: true, recursive: true }));
  copied.runtime.workspaceRoot = other;
  await assert.rejects(
    () => runProviderOneShotBroker(copied),
    /PROVIDER_BROKER_RUNTIME_REJECTED/u
  );
  assert.equal(copied.globalStore.consumeCalls, 0);

  const crossed = fixture(t);
  crossed.runtime.workflow = constants.LANE_CONTRACTS.DRILL.workflow;
  crossed.runtime.workflowRef =
    "Flash-Bri/prooftoact/.github/workflows/" +
    "prooftoact-bounded-live-drill.yml@refs/heads/main";
  await assert.rejects(
    () => runProviderOneShotBroker(crossed),
    /PROVIDER_BROKER_RUNTIME_REJECTED/u
  );
  assert.equal(crossed.globalStore.consumeCalls, 0);
});

test("loaded broker, control-plane, workflow, repository, and session drift reject", async (t) => {
  const mutations = [
    (runtime) => { runtime.brokerArtifactSha256 = "0".repeat(64); },
    (runtime) => { runtime.controlPlaneCommit = "0".repeat(40); },
    (runtime) => { runtime.controlPlaneTree = "0".repeat(40); },
    (runtime) => { runtime.controlPlaneBuildSha256 = "0".repeat(64); },
    (runtime) => { runtime.workflowSha = "0".repeat(40); },
    (runtime) => { runtime.stackId = runtime.stackId.replace(/007$/u, "008"); },
    (runtime) => { runtime.repositoryId = "999"; },
    (runtime) => { runtime.repositoryOwnerId = "999"; },
    (runtime) => {
      runtime.principalArn = runtime.principalArn.replace(
        /pta-[0-9]+-1$/u,
        "unbound-session"
      );
    }
  ];
  for (const mutate of mutations) {
    const input = fixture(t);
    mutate(input.runtime);
    await assert.rejects(
      () => runProviderOneShotBroker(input),
      /PROVIDER_BROKER_RUNTIME_REJECTED/u
    );
    assert.equal(input.globalStore.consumeCalls, 0);
  }
});

test("credential, OAuth, proxy, and loader environment reject before consume", async (t) => {
  for (const environment of [
    { AWS_ACCESS_KEY_ID: "not-used" },
    { AWS_WEB_IDENTITY_TOKEN_FILE: "/not-used" },
    { OPENCLAW_OAUTH_TOKEN: "not-used" },
    { HTTPS_PROXY: "https://not-used.invalid" },
    { NODE_OPTIONS: "--import=/not-used.mjs" }
  ]) {
    const input = fixture(t);
    input.environment = environment;
    await assert.rejects(
      () => runProviderOneShotBroker(input),
      /PROVIDER_BROKER_RUNTIME_ENVIRONMENT_REJECTED/u
    );
    assert.equal(input.globalStore.consumeCalls, 0);
  }
});

test("frozen source, cost, run, database, teardown, and credential drift reject", async (t) => {
  const mutations = [
    (claims) => { claims.appSource.commit = "0".repeat(40); },
    (claims) => { claims.appSource.tree = "0".repeat(40); },
    (claims) => {
      claims.controlPlane.identitySha256 = claims.controlPlane.buildSha256;
    },
    (claims) => { claims.release.region = "us-west-2"; },
    (claims) => { claims.release.stackId =
      claims.release.stackId.replace(/007$/u, "008"); },
    (claims) => { claims.budget.cumulativeCapUsd = 21; },
    (claims) => {
      claims.budget.alreadySpentUsd = 19;
      claims.budget.authorizedAdditionalUsd = 1;
      claims.budget.projectedCumulativeUsd = 20;
    },
    (claims) => { claims.limits.maximumRuns = 2; },
    (claims) => { claims.limits.maximumConcurrency = 3; },
    (claims) => { claims.database.runtimePrincipals[0] = "root"; },
    (claims) => { claims.database.freshCluster = false; },
    (claims) => { claims.globalStore.tableId =
      "823e4567-e89b-42d3-a456-426614174007"; },
    (claims) => { claims.globalStore.billingMode = "PROVISIONED"; },
    (claims) => { claims.teardown.separateApprovalRequired = false; },
    (claims) => { claims.teardown.deleteExactStackId =
      claims.teardown.deleteExactStackId.replace(/007$/u, "008"); },
    (claims) => { claims.authoritySeparation.teardown.roleName =
      claims.authoritySeparation.deploy.roleName; }
  ];
  for (const mutate of mutations) {
    const input = fixture(t);
    const claims = structuredClone(input.claims);
    mutate(claims);
    assert.throws(
      () => validateProviderBrokerApproval(signApproval(claims), PUBLIC_KEY, NOW),
      /PROVIDER_BROKER_(?:APPROVAL|APPROVAL_CLAIMS)_REJECTED/u
    );
  }

  const oauth = fixture(t);
  oauth.runtime.openClawOauthPresent = true;
  await assert.rejects(
    () => runProviderOneShotBroker(oauth),
    /PROVIDER_BROKER_RUNTIME_REJECTED/u
  );
});

test("ambiguous possible mutation becomes UNKNOWN and forces fresh read-only reconcile", async (t) => {
  const input = fixture(t);
  const reconciliations = [];
  let dispatches = 0;
  input.reconciler = readOnlyReconciler(reconciliations);
  input.dispatcher = {
    async dispatch() {
      dispatches += 1;
      throw new Error("synthetic acknowledgement loss after possible mutation");
    }
  };
  const result = await runProviderOneShotBroker(input);
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.retryAllowed, false);
  assert.equal(result.possibleMutation, true);
  assert.equal(result.dispatchStatus, "ATTEMPTED_OUTCOME_UNKNOWN");
  assert.equal(
    result.receipt.freshReadOnlyReconciliationAttempted,
    true
  );
  assert.equal(result.receipt.freshReadOnlyReconciliationStatus, "UNKNOWN");
  assert.equal(reconciliations.length, 1);
  assert.equal(reconciliations[0].fresh, true);
  assert.equal(reconciliations[0].readOnly, true);
  assert.equal(
    reconciliations[0].evidenceRoleName,
    constants.AUTHORITY_CONTRACTS.evidence.roleName
  );
  assert.equal(dispatches, 1);

  const replay = await runProviderOneShotBroker(input);
  assert.equal(replay.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(replay.replayRejected, true);
  assert.equal(replay.dispatchStatus, "PREVIOUSLY_RECORDED");
  assert.equal(dispatches, 1);
  assert.equal(reconciliations.length, 2);
});

test("explicit ambiguous provider outcome is retained and reconciled", async (t) => {
  const input = fixture(t);
  input.dispatcher = {
    async dispatch({ command }) {
      return {
        schemaVersion: constants.OUTCOME_SCHEMA,
        status: "AMBIGUOUS",
        operationIdentitySha256: command.operationIdentitySha256,
        possibleMutation: command.providerMutationExpected,
        providerRequestId: PROVIDER_REQUEST_ID,
        observedAt: new Date(NOW).toISOString(),
        providerReceiptSha256: "a".repeat(64)
      };
    }
  };

  const result = await runProviderOneShotBroker(input);

  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(result.receipt.outcomeProviderRequestId, PROVIDER_REQUEST_ID);
  assert.equal(result.receipt.outcomeProviderReceiptSha256, "a".repeat(64));
  assert.equal(result.receipt.freshReadOnlyReconciliationAttempted, true);
  assert.equal(result.authorityConsumptionStatus, "CONSUMED_THIS_INVOCATION");
  assert.equal(result.dispatchStatus, "ATTEMPTED_OUTCOME_UNKNOWN");
});

test("mutating terminal failure cannot bypass ambiguity reconciliation", async (t) => {
  const input = fixture(t);
  input.dispatcher = {
    async dispatch({ command }) {
      return {
        schemaVersion: constants.OUTCOME_SCHEMA,
        status: "FAILED_TERMINAL",
        operationIdentitySha256: command.operationIdentitySha256,
        possibleMutation: true,
        providerRequestId: PROVIDER_REQUEST_ID,
        observedAt: new Date(NOW).toISOString(),
        providerReceiptSha256: "b".repeat(64)
      };
    }
  };

  const result = await runProviderOneShotBroker(input);

  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(result.receipt.freshReadOnlyReconciliationAttempted, true);
  assert.equal(result.possibleMutation, true);
});

test("read-only terminal failure is terminal and cannot imply mutation", async (t) => {
  const input = fixture(t, { lane: "EVIDENCE" });
  input.dispatcher = {
    async dispatch({ command }) {
      return {
        schemaVersion: constants.OUTCOME_SCHEMA,
        status: "FAILED_TERMINAL",
        operationIdentitySha256: command.operationIdentitySha256,
        possibleMutation: false,
        providerRequestId: PROVIDER_REQUEST_ID,
        observedAt: new Date(NOW).toISOString(),
        providerReceiptSha256: "c".repeat(64)
      };
    }
  };

  const result = await runProviderOneShotBroker(input);

  assert.equal(result.receipt.status, "TERMINAL_FAILURE");
  assert.equal(result.receipt.freshReadOnlyReconciliationAttempted, false);
  assert.equal(result.possibleMutation, false);
  assert.equal(result.dispatchStatus, "OUTCOME_RECEIVED");
});

test("safety-reducing terminalizer converges an expired durable intent to UNKNOWN", async (t) => {
  const input = fixture(t);
  const originalAppendIntent = input.globalStore.appendIntent.bind(
    input.globalStore
  );
  input.globalStore.appendIntent = async (request) => {
    await originalAppendIntent(request);
    throw new Error("synthetic acknowledgement loss after durable intent");
  };

  const interrupted = await runProviderOneShotBroker(input);
  assert.equal(interrupted.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(interrupted.dispatchStatus, "NOT_ATTEMPTED");
  assert.equal(interrupted.possibleMutation, false);

  input.globalStore.now = EXPIRED_NOW;
  input.reconciler = readOnlyReconciler([], EXPIRED_NOW);
  const terminalized = await terminalizeExpiredProviderOneShotBroker({
    ...input,
    now: EXPIRED_NOW,
    originalRuntime: input.runtime,
    terminalizerRuntime: terminalizerRuntimeFor(
      input.claims,
      input.workspaceRoot
    )
  });

  assert.equal(terminalized.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(terminalized.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(terminalized.receipt.retryAllowed, false);
  assert.equal(terminalized.possibleMutation, true);
  assert.equal(
    terminalized.terminalizationObservedAt,
    new Date(EXPIRED_NOW).toISOString()
  );
  assert.equal(
    terminalized.receipt.freshReadOnlyReconciliationStatus,
    "UNKNOWN"
  );

  const repeated = await terminalizeExpiredProviderOneShotBroker({
    ...input,
    now: EXPIRED_NOW,
    originalRuntime: input.runtime,
    terminalizerRuntime: terminalizerRuntimeFor(
      input.claims,
      input.workspaceRoot
    )
  });
  assert.equal(repeated.receipt.receiptSha256, terminalized.receipt.receiptSha256);
  assert.equal(repeated.terminalizationObservedAt, null);
});

test("safety-reducing terminalizer records no provider mutation before intent", async (t) => {
  const input = fixture(t);
  input.globalStore.appendIntent = async () => {
    throw new Error("synthetic crash before durable intent");
  };

  await runProviderOneShotBroker(input);
  await assert.rejects(
    () => terminalizeExpiredProviderOneShotBroker({
      ...input,
      now: NOW,
      originalRuntime: input.runtime,
      terminalizerRuntime: terminalizerRuntimeFor(
        input.claims,
        input.workspaceRoot,
        NOW
      )
    }),
    /PROVIDER_BROKER_EXPIRED_TERMINALIZATION_REJECTED/u
  );

  input.globalStore.now = EXPIRED_NOW;
  const terminalized = await terminalizeExpiredProviderOneShotBroker({
    ...input,
    now: EXPIRED_NOW,
    originalRuntime: input.runtime,
    terminalizerRuntime: terminalizerRuntimeFor(
      input.claims,
      input.workspaceRoot
    )
  });

  assert.equal(terminalized.receipt.status, "TERMINAL_FAILURE");
  assert.equal(terminalized.receipt.outcomeStatus, "FAILED_TERMINAL");
  assert.equal(terminalized.possibleMutation, false);
  assert.equal(terminalized.receipt.freshReadOnlyReconciliationAttempted, false);
});

test("expired terminalization requires its distinct no-dispatch runtime", async (t) => {
  const input = fixture(t);
  await runProviderOneShotBroker(input);
  input.globalStore.now = EXPIRED_NOW;

  await assert.rejects(
    () => terminalizeExpiredProviderOneShotBroker({
      ...input,
      now: EXPIRED_NOW,
      originalRuntime: input.runtime,
      terminalizerRuntime: input.runtime
    }),
    /PROVIDER_BROKER_TERMINALIZER_RUNTIME_REJECTED/u
  );
});

test("terminalizer validates and uses the immutable command read from the store", async (t) => {
  const input = phaseFixture(t);
  await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  const storedCommand = input.globalStore.records.values().next().value.command;
  let terminalizedCommandSha256 = null;
  const originalTerminalizeExpired =
    input.globalStore.terminalizeExpired.bind(input.globalStore);
  input.globalStore.terminalizeExpired = async (request) => {
    terminalizedCommandSha256 = request.command.commandSha256;
    return originalTerminalizeExpired(request);
  };
  input.globalStore.now = EXPIRED_NOW;
  const result = await terminalizeExpiredProviderOneShotBroker({
    ...input,
    now: EXPIRED_NOW,
    originalRuntime: { forged: "must be ignored" },
    reconciler: readOnlyReconciler([], EXPIRED_NOW),
    terminalizerRuntime: terminalizerRuntimeFor(
      input.claims,
      input.workspaceRoot
    )
  });
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(terminalizedCommandSha256, storedCommand.commandSha256);

  const conflict = phaseFixture(t);
  await reserveProviderOneShotIntent({
    ...conflict,
    coordinatorRuntime: conflict.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(conflict.globalStore)
  });
  conflict.globalStore.records.values().next().value.command = {
    ...conflict.globalStore.records.values().next().value.command,
    commandSha256: "0".repeat(64)
  };
  conflict.globalStore.now = EXPIRED_NOW;
  await assert.rejects(
    () => terminalizeExpiredProviderOneShotBroker({
      ...conflict,
      now: EXPIRED_NOW,
      reconciler: readOnlyReconciler([], EXPIRED_NOW),
      terminalizerRuntime: terminalizerRuntimeFor(
        conflict.claims,
        conflict.workspaceRoot
      )
    }),
    /PROVIDER_BROKER_GLOBAL_RECORD_REJECTED/u
  );
});

test("coordinator finalizer and expiry terminalizer race is immutable and idempotent", async (t) => {
  const input = phaseFixture(t);
  const reserved = await reserveProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorReserveRuntime,
    globalStore: reserveStoreFacade(input.globalStore)
  });
  let signalReadback;
  const readbackStarted = new Promise((resolve) => {
    signalReadback = resolve;
  });
  let releaseReadback;
  const readbackGate = new Promise((resolve) => {
    releaseReadback = resolve;
  });
  const exactReadback = finalizerReadback(input.coordinatorFinalizerRuntime);
  const finalizer = finalizeProviderOneShotIntent({
    ...input,
    coordinatorRuntime: input.coordinatorFinalizerRuntime,
    globalStore: finalizerStoreFacade(input.globalStore),
    lookup: reserved.lookup,
    providerReadback: {
      async readback(request) {
        signalReadback();
        await readbackGate;
        return exactReadback.readback(request);
      }
    }
  });
  await readbackStarted;
  input.globalStore.now = EXPIRED_NOW;
  const terminalizerInput = {
    ...input,
    now: EXPIRED_NOW,
    reconciler: readOnlyReconciler([], EXPIRED_NOW),
    terminalizerRuntime: terminalizerRuntimeFor(
      input.claims,
      input.workspaceRoot
    )
  };
  const expired = await terminalizeExpiredProviderOneShotBroker(
    terminalizerInput
  );
  const terminalSha256 =
    input.globalStore.records.values().next().value.terminal.terminalSha256;
  releaseReadback();
  const finalized = await finalizer;
  assert.equal(expired.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(finalized.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(
    input.globalStore.records.values().next().value.terminal.terminalSha256,
    terminalSha256
  );
  const repeated = await terminalizeExpiredProviderOneShotBroker(
    terminalizerInput
  );
  assert.equal(repeated.receipt.receiptSha256, expired.receipt.receiptSha256);
  assert.equal(
    input.globalStore.records.values().next().value.terminal.terminalSha256,
    terminalSha256
  );
});

test("ambiguous terminal write cannot confirm a previously confirmed dispatch", async (t) => {
  const input = fixture(t);
  const originalFinalize = input.globalStore.finalize.bind(input.globalStore);
  input.globalStore.finalize = async (request) => {
    if (input.globalStore.finalizeCalls === 0) {
      await originalFinalize(request);
      throw new Error("synthetic acknowledgement loss after terminal write");
    }
    return originalFinalize(request);
  };

  const result = await runProviderOneShotBroker(input);

  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(result.receipt.outcomeProviderRequestId, null);
  assert.equal(result.receipt.freshReadOnlyReconciliationAttempted, true);
  assert.equal(result.authorityConsumptionStatus, "CONSUMED_THIS_INVOCATION");
  assert.equal(result.dispatchStatus, "ATTEMPTED_OUTCOME_UNKNOWN");
  assert.equal(result.receipt.retryAllowed, false);

  const replay = await runProviderOneShotBroker(input);
  assert.equal(replay.receipt.status, "CONFIRMED");
  assert.equal(replay.replayRejected, true);
  assert.equal(replay.authorityConsumptionStatus, "PREVIOUSLY_CONSUMED");
  assert.equal(replay.dispatchStatus, "PREVIOUSLY_RECORDED");
});

test("store cannot substitute a different valid terminal outcome", async (t) => {
  const input = fixture(t);
  const originalFinalize = input.globalStore.finalize.bind(input.globalStore);
  input.globalStore.finalize = async ({ command, intent }) => originalFinalize({
    command,
    intent,
    outcome: {
      schemaVersion: constants.OUTCOME_SCHEMA,
      status: "AMBIGUOUS",
      operationIdentitySha256: command.operationIdentitySha256,
      possibleMutation: true,
      providerRequestId: null,
      observedAt: new Date(NOW).toISOString(),
      providerReceiptSha256: "0".repeat(64)
    }
  });

  const result = await runProviderOneShotBroker(input);
  assert.equal(result.receipt.status, "UNKNOWN_DO_NOT_ACT");
  assert.equal(result.receipt.outcomeStatus, "AMBIGUOUS");
  assert.equal(result.dispatchStatus, "ATTEMPTED_OUTCOME_UNKNOWN");
  assert.equal(result.receipt.retryAllowed, false);
});

test("expired terminalizer rejects a substituted confirmed outcome", async (t) => {
  const input = fixture(t);
  input.globalStore.appendIntent = async ({ command, consumption }) => {
    const intent = await LocalProviderGlobalStore.prototype.appendIntent.call(
      input.globalStore,
      { command, consumption }
    );
    throw Object.assign(new Error("synthetic crash after durable intent"), {
      intent
    });
  };
  await runProviderOneShotBroker(input);
  input.globalStore.now = EXPIRED_NOW;
  const originalTerminalizeExpired =
    input.globalStore.terminalizeExpired.bind(input.globalStore);
  input.globalStore.terminalizeExpired = async (request) =>
    originalTerminalizeExpired({
      ...request,
      outcome: {
        schemaVersion: constants.OUTCOME_SCHEMA,
        status: "CONFIRMED",
        operationIdentitySha256: request.command.operationIdentitySha256,
        possibleMutation: true,
        providerRequestId: PROVIDER_REQUEST_ID,
        observedAt: new Date(EXPIRED_NOW).toISOString(),
        providerReceiptSha256: "1".repeat(64)
      }
    });

  await assert.rejects(
    () => terminalizeExpiredProviderOneShotBroker({
      ...input,
      now: EXPIRED_NOW,
      originalRuntime: input.runtime,
      terminalizerRuntime: terminalizerRuntimeFor(
        input.claims,
        input.workspaceRoot
      )
    }),
    /PROVIDER_BROKER_GLOBAL_TERMINAL_REJECTED/u
  );
});

test("receipt publication converges after a post-link fault and rejects conflict", async (t) => {
  const input = fixture(t);
  const result = await runProviderOneShotBroker(input);
  const receiptRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pta-receipt-"));
  fs.chmodSync(receiptRoot, 0o700);
  t.after(() => fs.rmSync(receiptRoot, { force: true, recursive: true }));

  const first = publishProviderBrokerReceipt({
    receipt: result.receipt,
    receiptRoot,
    fault(stage) {
      if (stage === "after-link") throw new Error("simulated crash after link");
    }
  });
  assert.equal(fs.existsSync(first.filePath), true);
  const recovered = publishProviderBrokerReceipt({
    receipt: result.receipt,
    receiptRoot
  });
  assert.equal(recovered.created, false);
  assert.equal(
    fs.readFileSync(recovered.filePath).equals(
      brokerCanonicalBytes(result.receipt)
    ),
    true
  );

  const conflictingUnsigned = {
    ...result.receipt,
    outcomeProviderReceiptSha256: "0".repeat(64)
  };
  delete conflictingUnsigned.receiptSha256;
  const conflicting = {
    ...conflictingUnsigned,
    receiptSha256: digest(conflictingUnsigned)
  };
  assert.throws(
    () => publishProviderBrokerReceipt({
      receipt: conflicting,
      receiptRoot
    }),
    /PROVIDER_BROKER_RECEIPT_PUBLICATION_REJECTED/u
  );
});

test("broker module has no provider, network, database, root, or OAuth client", () => {
  const source = fs.readFileSync(
    path.join(ROOT, "scripts/release-provider-one-shot-broker.js"),
    "utf8"
  );
  assert.doesNotMatch(
    source,
    /@aws-sdk|from\s+["']pg["']|\bfetch\s*\(|https?\.request|child_process/u
  );
  assert.match(source, /contains no\s+\* provider client/u);
  assert.match(source, /diagnostic-only and can never enable provider execution/u);
});
