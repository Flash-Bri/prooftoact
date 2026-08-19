import {
  brokerCanonicalBytes,
  brokerSha256,
  providerBrokerConstants as constants
} from "../../scripts/release-provider-one-shot-broker.js";

const ACCOUNT_ID = "111111111111";
const APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000";

function digest(value) {
  return brokerSha256(brokerCanonicalBytes(value));
}

function controlPlaneClaims() {
  const value = {
    brokerArtifactSha256: "1".repeat(64),
    buildSha256: "2".repeat(64),
    commit: "a".repeat(40),
    separation: "SEPARATE_CONTROL_PLANE_FROM_FROZEN_APPLICATION",
    tree: "b".repeat(40)
  };
  return {
    ...value,
    identitySha256: digest(value)
  };
}

export function createProviderApprovalClaims({ expiresAt, issuedAt }) {
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
  const release = {
    artifactManifestSha256: "5".repeat(64),
    buildReceiptSha256: "4".repeat(64),
    changeSetName: "prooftoact-release-signer-test",
    changeSetType: "CREATE",
    parameterManifestSha256: "7".repeat(64),
    region: "us-east-1",
    resourceInventorySha256: "8".repeat(64),
    stackName: "prooftoact-gate2",
    templateSha256: "3".repeat(64)
  };
  const teardownDeadline = new Date(
    Date.parse(expiresAt) + 24 * 60 * 60 * 1000
  ).toISOString();
  return {
    schemaVersion: constants.APPROVAL_CLAIMS_SCHEMA,
    approvalId: APPROVAL_ID,
    approvedBy: "BRIAN_SMITH",
    humanAuthorizationSha256: constants.HUMAN_AUTHORIZATION_SHA256,
    oneShot: true,
    lane: "PREPARE",
    action: constants.LANE_CONTRACTS.PREPARE.action,
    appSource: { ...constants.APP_SOURCE },
    controlPlane: controlPlaneClaims(),
    release,
    budget: {
      currency: "USD",
      cumulativeCapUsd: 20,
      alreadySpentUsd: 4,
      authorizedAdditionalUsd: 2,
      projectedCumulativeUsd: 6,
      teardownReserveUsd: 1,
      unknownCostCount: 0,
      censusAsOf: new Date(Date.parse(issuedAt) - 60 * 1000).toISOString(),
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
    teardown: {
      required: true,
      separateApprovalRequired: true,
      deletePreparedChangeSetIfCreated: true,
      changeSetName: release.changeSetName,
      stackName: release.stackName,
      expectedResourceInventorySha256: release.resourceInventorySha256,
      residualCensusRequired: true,
      deadline: teardownDeadline,
      workflow: constants.AUTHORITY_CONTRACTS.teardown.workflow,
      environment: constants.AUTHORITY_CONTRACTS.teardown.environment,
      roleArn:
        `arn:aws:iam::${ACCOUNT_ID}:role/` +
        constants.AUTHORITY_CONTRACTS.teardown.roleName
    },
    authoritySeparation: structuredClone(constants.AUTHORITY_CONTRACTS),
    globalStore: {
      atomicConditionalConsumeRequired: true,
      durableJournalRequired: true,
      strongReadRequired: true,
      ...tableIdentity,
      tableIdentitySha256: digest(tableIdentity)
    },
    workspaceRealpathSha256: "f".repeat(64)
  };
}
