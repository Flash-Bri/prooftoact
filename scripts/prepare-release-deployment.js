import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";
import { validateBuildReceipt } from "./gate2-aws-readiness.js";
import {
  assertCleanExactGitCheckout,
  assertExactGitRepositoryLayout,
  gitEnvironment,
  gitInvariantArguments,
  readExactGitBlob,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const CURRENT_FILE = fileURLToPath(import.meta.url);
const OFFICIAL_REMOTE = "https://github.com/Flash-Bri/prooftoact.git";
const APPLICATION_TEMPLATE_PATH = "infra/aws/gate2-template.json";
const CONTROL_PLANE_CONTROLLER_PATH =
  "scripts/release-provider-controller.js";
const CONTROL_PLANE_PREPARER_PATH =
  "scripts/prepare-release-deployment.js";
const CONTROL_PLANE_ROLES_TEMPLATE_PATH =
  "infra/aws/release-deployment-roles-template.json";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SEALED_WORKFLOW_COMMIT =
  "50d0cd261b8597fe74c80b84c49be0adde5bdf6f";
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const REVIEWED_GATE2_TEMPLATE_SHA256 =
  "a10066b23925cf2921b15eaa0d52e7ac8ef7a5f46e0ab260431a340e897cc3a1";
const REVIEWED_DEPLOYMENT_ROLES_TEMPLATE_SHA256 =
  "5f72ab835c93e6c8739405ed953d5c340dd13497a83eb1efff40fd70ba144da9";
const ARTIFACT_NAMES = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
]);
const PRIMARY_ROLE_LOGICAL_IDS = Object.freeze([
  "AdvisoryCallerRole",
  "AgentRole",
  "AuthorityRaceCallerRole",
  "AuthorityRole",
  "BoundaryRole",
  "DemoRole",
  "DeploymentEvidenceAlternateRole",
  "DeploymentEvidenceRole",
  "SignerRole"
]);
const PRIMARY_LAMBDA_LOGICAL_IDS = Object.freeze([
  "AgentFunction",
  "AuthorityFunction",
  "BoundaryFunction",
  "DemoFunction",
  "SignerFunction"
]);
const DEPLOYMENT_ROLE_LOGICAL_IDS = Object.freeze([
  "CloudFormationPermissionsBoundary",
  "CloudFormationServiceRole",
  "LiveDrillOperatorRole",
  "ReleaseControlTable",
  "ReleaseCoordinatorRole",
  "ReleaseDeploymentRole",
  "ReleaseEvidenceRole",
  "ReleaseExecutionRole",
  "ReleaseTeardownRole",
  "ReleaseTerminalizerRole"
]);
const OIDC_ROLE_CONTRACTS = Object.freeze({
  LiveDrillOperatorRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-live-drill.yml",
    environment: "aws-live-drill",
    roleName: "ProofToActLiveDrillOperator",
    workflow: "ProofToAct Bounded Live Drill",
    workflowFile: "prooftoact-bounded-live-drill.yml"
  }),
  ReleaseDeploymentRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-prepare.yml",
    environment: "aws-release-deployment",
    roleName: "ProofToActReleaseDeployment",
    workflow: "ProofToAct Release Candidate",
    workflowFile: "prooftoact-release-candidate.yml"
  }),
  ReleaseCoordinatorRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-coordinator.yml",
    environment: "aws-release-coordination",
    roleName: "ProofToActReleaseCoordinator",
    workflows: Object.freeze([
      "ProofToAct Release Candidate",
      "ProofToAct Execute Approved Release",
      "ProofToAct Bounded Live Drill",
      "ProofToAct Read Only Release Evidence",
      "ProofToAct Approved Teardown"
    ]),
    workflowFiles: Object.freeze([
      "prooftoact-release-candidate.yml",
      "prooftoact-execute-approved-release.yml",
      "prooftoact-bounded-live-drill.yml",
      "prooftoact-read-only-release-evidence.yml",
      "prooftoact-approved-teardown.yml"
    ])
  }),
  ReleaseEvidenceRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-evidence.yml",
    environment: "aws-release-evidence",
    roleName: "ProofToActReleaseEvidence",
    workflow: "ProofToAct Read Only Release Evidence",
    workflowFile: "prooftoact-read-only-release-evidence.yml"
  }),
  ReleaseExecutionRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-execute.yml",
    environment: "aws-release-execution",
    roleName: "ProofToActReleaseExecution",
    workflow: "ProofToAct Execute Approved Release",
    workflowFile: "prooftoact-execute-approved-release.yml"
  }),
  ReleaseTeardownRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-teardown.yml",
    environment: "aws-release-teardown",
    roleName: "ProofToActReleaseTeardown",
    workflow: "ProofToAct Approved Teardown",
    workflowFile: "prooftoact-approved-teardown.yml"
  }),
  ReleaseTerminalizerRole: Object.freeze({
    credentialWorkflowFile: "prooftoact-sealed-terminalizer.yml",
    environment: "aws-release-terminalization",
    roleName: "ProofToActReleaseTerminalizer",
    workflow: "ProofToAct Terminalize Expired Release",
    workflowFile: "prooftoact-terminalize-expired-release.yml"
  })
});

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, keys) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function validateArtifactBucket(value) {
  requireCondition(
    typeof value === "string" &&
      value.length >= 3 &&
      value.length <= 63 &&
      /^(?!xn--)(?!.*\.\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u.test(value) &&
      !/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value),
    "RELEASE_PLAN_ARTIFACT_BUCKET_REJECTED"
  );
  return value;
}

function policyStatements(role) {
  const policies = role?.Properties?.Policies;
  requireCondition(
    role?.Type === "AWS::IAM::Role" &&
      Array.isArray(policies) &&
      policies.length === 1 &&
      Array.isArray(policies[0]?.PolicyDocument?.Statement) &&
      Array.isArray(role.Properties.ManagedPolicyArns) &&
      role.Properties.ManagedPolicyArns.length === 0,
    "RELEASE_PLAN_ROLE_TEMPLATE_REJECTED"
  );
  return policies[0].PolicyDocument.Statement;
}

function actions(statement) {
  return Array.isArray(statement?.Action)
    ? [...statement.Action]
    : typeof statement?.Action === "string" ? [statement.Action] : [];
}

function statementBySid(statements, sid) {
  const matches = statements.filter((statement) => statement?.Sid === sid);
  requireCondition(
    matches.length === 1,
    "RELEASE_PLAN_ROLE_TEMPLATE_REJECTED"
  );
  return matches[0];
}

function requireExplicitDeny(statements, sid, requiredActions) {
  const statement = statementBySid(statements, sid);
  requireCondition(
    statement.Effect === "Deny" &&
      statement.Resource === "*" &&
      requiredActions.every((action) => actions(statement).includes(action)),
    "RELEASE_PLAN_ROLE_TEMPLATE_REJECTED"
  );
}

function exactControlTableArn(value) {
  return canonicalJson(value) === canonicalJson({
    "Fn::GetAtt": ["ReleaseControlTable", "Arn"]
  });
}

function validateOidcRoleTrust(role, contract) {
  const code = "RELEASE_PLAN_OIDC_TRUST_REJECTED";
  const statements = role?.Properties?.AssumeRolePolicyDocument?.Statement;
  const expectedWorkflows = contract.workflows ?? contract.workflow;
  requireCondition(
    role?.Type === "AWS::IAM::Role" &&
      role.Properties.RoleName === contract.roleName &&
      role.Properties.MaxSessionDuration === 3600 &&
      Array.isArray(statements) && statements.length === 1,
    code
  );
  const statement = statements[0];
  const equals = statement?.Condition?.StringEquals;
  requireCondition(
    statement.Effect === "Allow" &&
      statement.Action === "sts:AssumeRoleWithWebIdentity" &&
      canonicalJson(statement.Principal) === canonicalJson({
        Federated: { Ref: "GitHubOidcProviderArn" }
      }) &&
      exactKeys(equals, [
        "token.actions.githubusercontent.com:aud",
        "token.actions.githubusercontent.com:environment",
        "token.actions.githubusercontent.com:job_workflow_ref",
        "token.actions.githubusercontent.com:ref",
        "token.actions.githubusercontent.com:repository",
        "token.actions.githubusercontent.com:repository_id",
        "token.actions.githubusercontent.com:repository_owner",
        "token.actions.githubusercontent.com:repository_owner_id",
        "token.actions.githubusercontent.com:sub",
        "token.actions.githubusercontent.com:workflow"
      ]) &&
      equals["token.actions.githubusercontent.com:aud"] ===
        "sts.amazonaws.com" &&
      equals["token.actions.githubusercontent.com:environment"] ===
        contract.environment &&
      equals["token.actions.githubusercontent.com:job_workflow_ref"] ===
        `Flash-Bri/prooftoact/.github/workflows/${contract.credentialWorkflowFile}@${SEALED_WORKFLOW_COMMIT}` &&
      equals["token.actions.githubusercontent.com:ref"] ===
        "refs/heads/main" &&
      equals["token.actions.githubusercontent.com:repository"] ===
        "Flash-Bri/prooftoact" &&
      equals["token.actions.githubusercontent.com:repository_id"] ===
        "1317716765" &&
      equals["token.actions.githubusercontent.com:repository_owner"] ===
        "Flash-Bri" &&
      equals["token.actions.githubusercontent.com:repository_owner_id"] ===
        "252500266" &&
      equals["token.actions.githubusercontent.com:sub"] ===
        `repo:Flash-Bri@252500266/prooftoact@1317716765:environment:${contract.environment}` &&
      canonicalJson(
        equals["token.actions.githubusercontent.com:workflow"]
      ) === canonicalJson(expectedWorkflows),
    code
  );
}

function validateReleaseControlTable(resource) {
  const code = "RELEASE_PLAN_CONTROL_TABLE_REJECTED";
  const properties = resource?.Properties;
  requireCondition(
    exactKeys(resource, [
      "DeletionPolicy", "Properties", "Type", "UpdateReplacePolicy"
    ]) &&
      resource.Type === "AWS::DynamoDB::Table" &&
      resource.DeletionPolicy === "Retain" &&
      resource.UpdateReplacePolicy === "Retain" &&
      exactKeys(properties, [
        "AttributeDefinitions", "BillingMode", "DeletionProtectionEnabled",
        "KeySchema", "SSESpecification", "TableName", "Tags"
      ]) &&
      properties.TableName === "prooftoact-release-controller" &&
      properties.BillingMode === "PAY_PER_REQUEST" &&
      properties.DeletionProtectionEnabled === true &&
      canonicalJson(properties.AttributeDefinitions) === canonicalJson([
        { AttributeName: "pk", AttributeType: "S" }
      ]) &&
      canonicalJson(properties.KeySchema) === canonicalJson([
        { AttributeName: "pk", KeyType: "HASH" }
      ]) &&
      canonicalJson(properties.SSESpecification) === canonicalJson({
        KMSMasterKeyId: "alias/aws/dynamodb",
        SSEEnabled: true,
        SSEType: "KMS"
      }) &&
      canonicalJson(properties.Tags) === canonicalJson([
        { Key: "Project", Value: "ProofToAct" },
        { Key: "Purpose", Value: "RetainedReleaseControl" },
        { Key: "Retention", Value: "IntentionalOutsideApplicationTeardown" }
      ]),
    code
  );
}

function requireExactTableMetadata(statements) {
  const statement = statementBySid(
    statements,
    "ReadReleaseControlTableIdentity"
  );
  requireCondition(
    statement.Effect === "Allow" &&
      actions(statement).sort().join("\n") === [
        "dynamodb:DescribeTable", "dynamodb:ListTagsOfResource"
      ].sort().join("\n") &&
      exactControlTableArn(statement.Resource),
    "RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED"
  );
}

function requireExactTableItems(statements, sid, expectedActions, expectedKeys) {
  const statement = statementBySid(statements, sid);
  const actualKeys = statement.Condition?.["ForAllValues:StringLike"]?.[
    "dynamodb:LeadingKeys"
  ];
  const keys = Array.isArray(actualKeys) ? actualKeys : [actualKeys];
  requireCondition(
    statement.Effect === "Allow" &&
      actions(statement).sort().join("\n") ===
        [...expectedActions].sort().join("\n") &&
      exactControlTableArn(statement.Resource) &&
      keys.sort().join("\n") === [...expectedKeys].sort().join("\n") &&
      statement.Condition?.Null?.["dynamodb:LeadingKeys"] === "false",
    "RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED"
  );
}

const LANE_CONTROL_DENY_ACTIONS = Object.freeze([
  "dynamodb:BatchWriteItem",
  "dynamodb:CreateTable",
  "dynamodb:DeleteItem",
  "dynamodb:DeleteTable",
  "dynamodb:PartiQL*",
  "dynamodb:PutItem",
  "dynamodb:Query",
  "dynamodb:Scan",
  "dynamodb:TransactWriteItems",
  "dynamodb:UpdateItem",
  "dynamodb:UpdateTable"
]);

function requireLaneEffectReadOnly(statements, denySid) {
  requireExactTableMetadata(statements);
  requireExactTableItems(
    statements,
    "ReadExactReleaseControlItems",
    ["dynamodb:GetItem"],
    ["EFFECT#*"]
  );
  const allowedDynamoActions = statements
    .filter((statement) => statement.Effect === "Allow")
    .flatMap(actions)
    .filter((action) => action.startsWith("dynamodb:"))
    .sort();
  requireCondition(
    allowedDynamoActions.join("\n") === [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:ListTagsOfResource"
    ].sort().join("\n"),
    "RELEASE_PLAN_PROVIDER_STORE_SEPARATION_REJECTED"
  );
  requireExplicitDeny(statements, denySid, LANE_CONTROL_DENY_ACTIONS);
}

function requireExactCoordinatorReadback(
  coordinatorStatements,
  releaseStatements,
  evidenceStatements,
  coordinatorPolicyDocument
) {
  const code = "RELEASE_PLAN_COORDINATOR_ROLE_SEPARATION_REJECTED";
  const releaseReadSids = [
    "ReadExactArtifactVersions",
    "ListExactArtifactPrefix"
  ];
  const evidenceReadSids = [
    "ReadExactReleaseStack",
    "ReadOwnDriftDetectionStatus",
    "ReadGateTwoHttpApiDeployment",
    "ReadExactLambdaDeployment",
    "ReadLambdaEventSourceCensus",
    "ReadExactReleaseLogs",
    "ReadExactReleaseRoles",
    "ReadAndSimulateExactBootstrapRoles",
    "ReadExactPermissionsBoundary"
  ];
  for (const sid of releaseReadSids) {
    requireCondition(
      canonicalJson(statementBySid(coordinatorStatements, sid)) ===
        canonicalJson(statementBySid(releaseStatements, sid)),
      code
    );
  }
  for (const sid of evidenceReadSids) {
    requireCondition(
      canonicalJson(statementBySid(coordinatorStatements, sid)) ===
        canonicalJson(statementBySid(evidenceStatements, sid)),
      code
    );
  }
  const exactAllowedSids = [
    "ReadReleaseControlTableIdentity",
    "CoordinateExactReleaseControlItems",
    ...releaseReadSids,
    ...evidenceReadSids
  ].sort();
  const actualAllowedSids = coordinatorStatements
    .filter((statement) => statement.Effect === "Allow")
    .map((statement) => statement.Sid)
    .sort();
  requireCondition(
    actualAllowedSids.join("\n") === exactAllowedSids.join("\n") &&
      Buffer.byteLength(
        canonicalJson(coordinatorPolicyDocument),
        "utf8"
      ) <= 10_240,
    code
  );
}

function exactBootstrapRoleResources() {
  return [
    { "Fn::GetAtt": ["CloudFormationServiceRole", "Arn"] },
    {
      "Fn::Sub":
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" +
        "ProofToActReleaseDeployment"
    },
    {
      "Fn::Sub":
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" +
        "ProofToActReleaseCoordinator"
    },
    { "Fn::GetAtt": ["ReleaseExecutionRole", "Arn"] },
    { "Fn::GetAtt": ["LiveDrillOperatorRole", "Arn"] },
    {
      "Fn::Sub":
        "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" +
        "ProofToActReleaseEvidence"
    },
    { "Fn::GetAtt": ["ReleaseTeardownRole", "Arn"] },
    { "Fn::GetAtt": ["ReleaseTerminalizerRole", "Arn"] }
  ];
}

function requireExactBootstrapReadback(statements) {
  const roles = statementBySid(
    statements,
    "ReadAndSimulateExactBootstrapRoles"
  );
  const boundary = statementBySid(statements, "ReadExactPermissionsBoundary");
  requireCondition(
    roles.Effect === "Allow" &&
      actions(roles).sort().join("\n") === [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:SimulatePrincipalPolicy"
      ].sort().join("\n") &&
      canonicalJson(roles.Resource) ===
        canonicalJson(exactBootstrapRoleResources()) &&
      boundary.Effect === "Allow" &&
      actions(boundary).sort().join("\n") === [
        "iam:GetPolicy", "iam:GetPolicyVersion"
      ].sort().join("\n") &&
      canonicalJson(boundary.Resource) === canonicalJson({
        Ref: "CloudFormationPermissionsBoundary"
      }),
    "RELEASE_PLAN_IAM_READBACK_REJECTED"
  );
}

function requireLeadingKeysNullGuards(statements) {
  for (const statement of statements) {
    const condition = statement?.Condition;
    if (!condition || typeof condition !== "object") continue;
    const hasLeadingKeys = Object.values(condition).some((operator) =>
      operator && typeof operator === "object" &&
        Object.hasOwn(operator, "dynamodb:LeadingKeys")
    );
    if (!hasLeadingKeys) continue;
    requireCondition(
      condition.Null?.["dynamodb:LeadingKeys"] === "false",
      "RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED"
    );
  }
}

function validateSourceOwnedPermissionsBoundary(resource, serviceRole) {
  const code = "RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED";
  const properties = resource?.Properties;
  const boundaryDocument = properties?.PolicyDocument;
  const serviceDocument = serviceRole?.Properties?.Policies?.[0]
    ?.PolicyDocument;
  requireCondition(
    exactKeys(resource, ["Properties", "Type"]) &&
      resource.Type === "AWS::IAM::ManagedPolicy" &&
      exactKeys(properties, [
        "Description", "ManagedPolicyName", "PolicyDocument"
      ]) &&
      properties.ManagedPolicyName ===
        "ProofToActGate2CloudFormationBoundary" &&
      typeof properties.Description === "string" &&
      properties.Description.includes("Source-owned") &&
      exactKeys(boundaryDocument, ["Statement", "Version"]) &&
      boundaryDocument.Version === "2012-10-17" &&
      Array.isArray(boundaryDocument.Statement) &&
      Buffer.byteLength(canonicalJson(boundaryDocument), "utf8") <= 6_144 &&
      exactKeys(serviceDocument, ["Statement", "Version"]) &&
      serviceDocument.Version === "2012-10-17" &&
      Array.isArray(serviceDocument.Statement),
    code
  );
  const boundaryAllows = boundaryDocument.Statement
    .filter((statement) => statement.Effect === "Allow");
  const serviceAllows = serviceDocument.Statement
    .filter((statement) => statement.Effect === "Allow");
  const boundaryDenies = boundaryDocument.Statement
    .filter((statement) => statement.Effect === "Deny");
  const serviceDenies = serviceDocument.Statement
    .filter((statement) => statement.Effect === "Deny");
  const explicitDeny = boundaryDenies.find((statement) =>
    statement.Sid === "DenyUnrelatedIdentityAndAccountAuthority"
  );
  requireCondition(
    canonicalJson(boundaryAllows) === canonicalJson(serviceAllows) &&
      serviceDenies.every((expected) => boundaryDenies.some((actual) =>
        canonicalJson(actual) === canonicalJson(expected)
      )) &&
      explicitDeny?.Effect === "Deny" &&
      explicitDeny.Resource === "*" &&
      [
        "account:*",
        "organizations:*",
        "sts:*",
        "iam:CreateAccessKey",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:CreateUser",
        "iam:PutRolePermissionsBoundary",
        "iam:UpdateRole"
      ].every((action) => actions(explicitDeny).includes(action)) &&
      boundaryAllows.every((statement) =>
        actions(statement).length > 0 &&
          actions(statement).every((action) => action !== "*" &&
            !action.endsWith(":*") && action !== "sts:AssumeRole" &&
            !action.startsWith("organizations:") &&
            !action.startsWith("account:"))
      ),
    code
  );
  return Object.freeze({
    allowInventorySha256: sha256(canonicalBytes(boundaryAllows)),
    logicalId: "CloudFormationPermissionsBoundary",
    managedPolicyName: "ProofToActGate2CloudFormationBoundary",
    policySha256: sha256(canonicalBytes(boundaryDocument)),
    sourceOwned: true
  });
}

function validateIndispensableKmsContract(gate2Template) {
  const code = "RELEASE_PLAN_KMS_CONTRACT_REJECTED";
  const keys = Object.entries(gate2Template.Resources ?? {})
    .filter(([, resource]) => resource?.Type === "AWS::KMS::Key");
  const aliases = Object.entries(gate2Template.Resources ?? {})
    .filter(([, resource]) => resource?.Type === "AWS::KMS::Alias");
  const key = gate2Template.Resources?.ReceiptSigningKey;
  requireCondition(
    keys.length === 1 &&
      keys[0][0] === "ReceiptSigningKey" &&
      aliases.length === 1 &&
      aliases[0][0] === "ReceiptSigningAlias" &&
      key?.DeletionPolicy === "Delete" &&
      key?.UpdateReplacePolicy === "Delete" &&
      key?.Properties?.KeySpec === "ECC_NIST_P256" &&
      key?.Properties?.KeyUsage === "SIGN_VERIFY" &&
      key?.Properties?.MultiRegion === false &&
      key?.Properties?.PendingWindowInDays === 7 &&
      canonicalJson(gate2Template.Resources?.SignerRole ?? {}).includes(
        '"kms:Sign"'
      ) &&
      canonicalJson(gate2Template.Resources?.SignerFunction ?? {}).includes(
        '"ReceiptSigningKey"'
      ),
    code
  );
  return Object.freeze({
    keyLogicalId: "ReceiptSigningKey",
    purpose: "SYNTHETIC_ADVISORY_RECEIPT_SIGNING_ONLY"
  });
}

export function validateReleaseDeploymentRoleTemplate(
  template,
  gate2Template
) {
  const code = "RELEASE_PLAN_ROLE_TEMPLATE_REJECTED";
  requireCondition(
    exactKeys(template, [
      "AWSTemplateFormatVersion",
      "Description",
      "Outputs",
      "Parameters",
      "Resources"
    ]) &&
      exactKeys(template.Parameters, [
        "ArtifactBucketName",
        "GitHubOidcProviderArn"
      ]) &&
      exactKeys(template.Resources, DEPLOYMENT_ROLE_LOGICAL_IDS) &&
      exactKeys(template.Outputs, [
        "CloudFormationPermissionsBoundaryArn",
        "CloudFormationServiceRoleArn",
        "LiveDrillOperatorRoleArn",
        "ReleaseControlTableArn",
        "ReleaseControlTableName",
        "ReleaseCoordinatorRoleArn",
        "ReleaseDeploymentRoleArn",
        "ReleaseEvidenceRoleArn",
        "ReleaseExecutionRoleArn",
        "ReleaseTeardownRoleArn",
        "ReleaseTerminalizerRoleArn"
      ]) &&
      canonicalJson(template.Outputs.ReleaseCoordinatorRoleArn?.Value) ===
        canonicalJson({
          "Fn::GetAtt": ["ReleaseCoordinatorRole", "Arn"]
        }),
    code
  );
  const releaseStatements = policyStatements(
    template.Resources.ReleaseDeploymentRole
  );
  const liveStatements = policyStatements(
    template.Resources.LiveDrillOperatorRole
  );
  const coordinatorStatements = policyStatements(
    template.Resources.ReleaseCoordinatorRole
  );
  const executionStatements = policyStatements(
    template.Resources.ReleaseExecutionRole
  );
  const evidenceStatements = policyStatements(
    template.Resources.ReleaseEvidenceRole
  );
  const teardownStatements = policyStatements(
    template.Resources.ReleaseTeardownRole
  );
  const terminalizerStatements = policyStatements(
    template.Resources.ReleaseTerminalizerRole
  );
  const serviceStatements = policyStatements(
    template.Resources.CloudFormationServiceRole
  );
  const permissionsBoundary = validateSourceOwnedPermissionsBoundary(
    template.Resources.CloudFormationPermissionsBoundary,
    template.Resources.CloudFormationServiceRole
  );
  for (const statements of [
    releaseStatements,
    coordinatorStatements,
    executionStatements,
    liveStatements,
    evidenceStatements,
    teardownStatements,
    terminalizerStatements,
    serviceStatements
  ]) requireLeadingKeysNullGuards(statements);
  validateReleaseControlTable(template.Resources.ReleaseControlTable);
  for (const [logicalId, contract] of Object.entries(OIDC_ROLE_CONTRACTS)) {
    validateOidcRoleTrust(template.Resources[logicalId], contract);
  }
  for (const statements of [coordinatorStatements, terminalizerStatements]) {
    requireExactTableMetadata(statements);
  }
  requireLaneEffectReadOnly(releaseStatements, "DenyRuntimeAndSecretUse");
  requireLaneEffectReadOnly(
    executionStatements,
    "DenyReleaseControlMutation"
  );
  requireLaneEffectReadOnly(
    liveStatements,
    "DenyReleaseControlMutation"
  );
  requireLaneEffectReadOnly(
    evidenceStatements,
    "DenyEvidenceMutationAndSecrets"
  );
  requireLaneEffectReadOnly(
    teardownStatements,
    "DenyReleaseControlMutation"
  );
  requireExactTableItems(
    coordinatorStatements,
    "CoordinateExactReleaseControlItems",
    [
      "dynamodb:GetItem",
      "dynamodb:TransactWriteItems",
      "dynamodb:UpdateItem"
    ],
    ["BUDGET#*", "EFFECT#*"]
  );
  requireExactTableItems(
    terminalizerStatements,
    "ReadAndTerminalizeExactEffectItems",
    ["dynamodb:GetItem", "dynamodb:UpdateItem"],
    ["EFFECT#*"]
  );
  requireExactBootstrapReadback(releaseStatements);
  requireExactBootstrapReadback(coordinatorStatements);
  requireExactBootstrapReadback(evidenceStatements);
  requireCondition(
    template.Resources.CloudFormationServiceRole.Properties
      .PermissionsBoundary?.Ref === "CloudFormationPermissionsBoundary" &&
      canonicalJson(
        template.Outputs.CloudFormationPermissionsBoundaryArn?.Value
      ) === canonicalJson({ Ref: "CloudFormationPermissionsBoundary" }) &&
      template.Resources.CloudFormationServiceRole.Properties
        .AssumeRolePolicyDocument?.Statement?.[0]?.Condition?.ArnLike?.[
          "aws:SourceArn"
        ]?.["Fn::Sub"] ===
          "arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/prooftoact-gate2/*",
    "RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED"
  );
  requireCondition(
    releaseStatements.every((statement) =>
      statement.Effect !== "Allow" ||
        actions(statement).every((action) =>
          action !== "sts:AssumeRole" &&
          !action.startsWith("lambda:Invoke") &&
          !action.startsWith("kms:") &&
          !action.startsWith("secretsmanager:")
        )
    ),
    "RELEASE_PLAN_DEPLOYMENT_ROLE_ESCALATION_REJECTED"
  );
  requireExactCoordinatorReadback(
    coordinatorStatements,
    releaseStatements,
    evidenceStatements,
    template.Resources.ReleaseCoordinatorRole.Properties.Policies[0]
      .PolicyDocument
  );
  requireCondition(
    canonicalJson(template.Resources.ReleaseCoordinatorRole)
      .includes('"aws-release-coordination"'),
    "RELEASE_PLAN_COORDINATOR_ROLE_SEPARATION_REJECTED"
  );
  requireCondition(
    releaseStatements.every((statement) =>
      statement.Effect !== "Allow" ||
        actions(statement).every((action) =>
          action !== "cloudformation:ExecuteChangeSet"
        )
    ) &&
      executionStatements.some((statement) =>
        statement.Effect === "Allow" &&
          actions(statement).includes("cloudformation:ExecuteChangeSet")
      ) &&
      executionStatements.every((statement) =>
        statement.Effect !== "Allow" ||
          actions(statement).every((action) =>
            action !== "cloudformation:CreateChangeSet" &&
            action !== "s3:PutObject" &&
            action !== "sts:AssumeRole" &&
            !action.startsWith("lambda:Invoke")
          )
      ) &&
      canonicalJson(template.Resources.ReleaseExecutionRole)
        .includes('"aws-release-execution"'),
    "RELEASE_PLAN_EXECUTION_ROLE_SEPARATION_REJECTED"
  );
  requireExplicitDeny(releaseStatements, "DenyDirectStackMutation", [
    "cloudformation:CreateStack",
    "cloudformation:DeleteStack",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:UpdateStack"
  ]);
  requireExplicitDeny(releaseStatements, "DenyRuntimeAndSecretUse", [
    "execute-api:Invoke",
    "lambda:Invoke*",
    "sts:AssumeRole"
  ]);
  requireExplicitDeny(
    executionStatements,
    "DenyPreparationDirectMutationAndRuntime",
    [
      "cloudformation:Create*",
      "cloudformation:Delete*",
      "cloudformation:UpdateStack",
      "execute-api:Invoke",
      "lambda:Invoke*",
      "s3:Put*",
      "sts:AssumeRole"
    ]
  );
  requireExplicitDeny(
    liveStatements,
    "DenyDirectProviderAndDeploymentCapabilities",
    [
      "cloudformation:Create*",
      "cloudformation:Delete*",
      "cloudformation:Execute*",
      "cloudformation:Update*",
      "execute-api:Invoke",
      "lambda:Invoke*",
      "s3:Put*"
    ]
  );
  requireExplicitDeny(
    coordinatorStatements,
    "DenyUnsafeReleaseControlOperations",
    [
      "dynamodb:CreateTable",
      "dynamodb:DeleteItem",
      "dynamodb:DeleteTable",
      "dynamodb:PartiQL*",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateTable"
    ]
  );
  requireExplicitDeny(
    coordinatorStatements,
    "DenyProviderMutationAndAuthorityCapabilities",
    [
      "apigateway:POST",
      "cloudformation:Create*",
      "cloudformation:Delete*",
      "cloudformation:Execute*",
      "cloudformation:Update*",
      "iam:PassRole",
      "kms:*",
      "lambda:Invoke*",
      "s3:Delete*",
      "s3:Put*",
      "secretsmanager:*",
      "sts:AssumeRole"
    ]
  );
  requireExplicitDeny(
    evidenceStatements,
    "DenyEvidenceMutationAndSecrets",
    [
      "cloudformation:Delete*",
      "dynamodb:DeleteItem",
      "dynamodb:TransactWriteItems",
      "dynamodb:UpdateItem",
      "lambda:Invoke*",
      "secretsmanager:*",
      "sts:AssumeRole"
    ]
  );
  requireExplicitDeny(
    teardownStatements,
    "DenyNonTeardownCapabilities",
    [
      "cloudformation:Create*",
      "cloudformation:Execute*",
      "lambda:Invoke*",
      "secretsmanager:*",
      "sts:AssumeRole"
    ]
  );
  requireExplicitDeny(
    terminalizerStatements,
    "DenyUnsafeReleaseControlOperations",
    [
      "dynamodb:DeleteItem",
      "dynamodb:PartiQL*",
      "dynamodb:PutItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:TransactWriteItems"
    ]
  );
  requireExplicitDeny(
    terminalizerStatements,
    "DenyAllProviderAndAuthorityCapabilities",
    [
      "cloudformation:*",
      "iam:*",
      "lambda:Invoke*",
      "secretsmanager:*",
      "sts:AssumeRole"
    ]
  );
  const liveAllow = statementBySid(
    liveStatements,
    "AssumeOnlyInStackDrillAndInnerEvidenceRoles"
  );
  const expectedLiveTargets = [
    "AdvisoryCallerRole-*",
    "AuthorityRaceCallerRole-*",
    "evidence",
    "evidence-alternate"
  ];
  const liveTargets = Array.isArray(liveAllow.Resource)
    ? liveAllow.Resource.map((resource) => resource?.["Fn::Sub"] ?? "")
    : [];
  requireCondition(
    liveAllow.Effect === "Allow" &&
      actions(liveAllow).join("\n") === "sts:AssumeRole" &&
      liveTargets.length === expectedLiveTargets.length &&
      expectedLiveTargets.every((suffix) =>
        liveTargets.some((target) => target.endsWith(suffix))
      ) &&
      canonicalJson(template.Resources.LiveDrillOperatorRole)
        .includes('"aws-live-drill"') &&
      !canonicalJson(template.Resources.ReleaseDeploymentRole)
        .includes("AdvisoryCallerRole") &&
      !canonicalJson(template.Resources.ReleaseDeploymentRole)
        .includes("AuthorityRaceCallerRole") &&
      !canonicalJson(template.Resources.ReleaseDeploymentRole)
        .includes("gate2-evidence"),
    code
  );

  const evidenceAllows = evidenceStatements
    .filter((statement) => statement.Effect === "Allow")
    .flatMap(actions);
  const evidenceStack = statementBySid(
    evidenceStatements,
    "ReadExactReleaseStack"
  );
  const evidenceDrift = statementBySid(
    evidenceStatements,
    "ReadOwnDriftDetectionStatus"
  );
  const evidenceApi = statementBySid(
    evidenceStatements,
    "ReadGateTwoHttpApiDeployment"
  );
  const evidenceLambda = statementBySid(
    evidenceStatements,
    "ReadExactLambdaDeployment"
  );
  const evidenceEventSources = statementBySid(
    evidenceStatements,
    "ReadLambdaEventSourceCensus"
  );
  requireCondition(
    !evidenceAllows.some((action) =>
      action === "sts:AssumeRole" ||
      action === "dynamodb:UpdateItem" ||
      action === "dynamodb:TransactWriteItems" ||
      action.startsWith("lambda:Invoke") ||
      action.startsWith("cloudformation:Create") ||
      action.startsWith("cloudformation:Delete") ||
      action.startsWith("cloudformation:Execute") ||
      action.startsWith("cloudformation:Update")
    ) &&
      statementBySid(
        evidenceStatements,
        "DenyEvidenceMutationAndSecrets"
      ).Effect === "Deny" &&
      actions(evidenceStack).sort().join("\n") === [
        "cloudformation:DescribeChangeSet",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResourceDrifts",
        "cloudformation:DescribeStackResources",
        "cloudformation:DescribeStacks",
        "cloudformation:DetectStackDrift",
        "cloudformation:GetTemplate"
      ].sort().join("\n") &&
      actions(evidenceDrift).join("\n") ===
        "cloudformation:DescribeStackDriftDetectionStatus" &&
      evidenceDrift.Resource === "*" &&
      actions(evidenceApi).join("\n") === "apigateway:GET" &&
      evidenceApi.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:apigateway:us-east-1::/apis/*" &&
      actions(evidenceLambda).sort().join("\n") === [
        "lambda:GetAlias",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:GetFunctionConcurrency",
        "lambda:GetFunctionConfiguration",
        "lambda:GetFunctionRecursionConfig",
        "lambda:GetPolicy",
        "lambda:GetRuntimeManagementConfig",
        "lambda:ListAliases",
        "lambda:ListFunctionUrlConfigs",
        "lambda:ListProvisionedConcurrencyConfigs",
        "lambda:ListTags"
      ].sort().join("\n") &&
      evidenceLambda.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:lambda:us-east-1:${AWS::AccountId}:function:prooftoact-gate2-*" &&
      actions(evidenceEventSources).join("\n") ===
        "lambda:ListEventSourceMappings" &&
      evidenceEventSources.Resource === "*",
    "RELEASE_PLAN_EVIDENCE_ROLE_SEPARATION_REJECTED"
  );

  const deleteStack = statementBySid(
    teardownStatements,
    "DeleteOnlyExactReleaseStack"
  );
  const teardownPass = statementBySid(
    teardownStatements,
    "PassExactCloudFormationRole"
  );
  requireCondition(
    deleteStack.Effect === "Allow" &&
      actions(deleteStack).sort().join("\n") === [
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResources",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
        "cloudformation:UpdateTerminationProtection"
      ].sort().join("\n") &&
      deleteStack.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/prooftoact-gate2/*" &&
      teardownPass.Effect === "Allow" &&
      actions(teardownPass).join("\n") === "iam:PassRole" &&
      canonicalJson(teardownPass.Resource) === canonicalJson({
        "Fn::GetAtt": ["CloudFormationServiceRole", "Arn"]
      }) &&
      teardownPass.Condition?.StringEquals?.["iam:PassedToService"] ===
        "cloudformation.amazonaws.com",
    "RELEASE_PLAN_TEARDOWN_ROLE_SEPARATION_REJECTED"
  );

  const terminalizerAllowActions = terminalizerStatements
    .filter((statement) => statement.Effect === "Allow")
    .flatMap(actions)
    .sort();
  requireCondition(
    terminalizerAllowActions.join("\n") === [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:ListTagsOfResource",
      "dynamodb:UpdateItem"
    ].sort().join("\n") &&
      statementBySid(terminalizerStatements, "DenyBudgetMutation")
        .Effect === "Deny",
    "RELEASE_PLAN_TERMINALIZER_ROLE_SEPARATION_REJECTED"
  );

  const createKey = statementBySid(serviceStatements, "CreateTaggedReceiptKey");
  const bindAlias = statementBySid(
    serviceStatements,
    "BindReceiptKeyAliasToTaggedTargetKey"
  );
  requireCondition(
    createKey.Effect === "Allow" &&
      actions(createKey).join("\n") === "kms:CreateKey" &&
      createKey.Resource === "*" &&
      exactKeys(createKey.Condition?.StringEquals, [
        "aws:RequestTag/Project",
        "aws:RequestTag/Purpose",
        "kms:KeySpec",
        "kms:KeyUsage",
        "kms:MultiRegion"
      ]) &&
      createKey.Condition.StringEquals["aws:RequestTag/Project"] ===
        "ProofToAct" &&
      createKey.Condition.StringEquals["aws:RequestTag/Purpose"] ===
        "SyntheticGateTwoEvidence" &&
      createKey.Condition.StringEquals["kms:KeySpec"] === "ECC_NIST_P256" &&
      createKey.Condition.StringEquals["kms:KeyUsage"] === "SIGN_VERIFY" &&
      createKey.Condition.StringEquals["kms:MultiRegion"] === "false",
    "RELEASE_PLAN_KMS_PERMISSION_REJECTED"
  );
  requireCondition(
    actions(bindAlias).sort().join("\n") ===
      ["kms:CreateAlias", "kms:DeleteAlias"].sort().join("\n") &&
      bindAlias.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:kms:us-east-1:${AWS::AccountId}:key/*" &&
      exactKeys(bindAlias.Condition?.StringEquals, [
        "aws:ResourceTag/Project",
        "aws:ResourceTag/Purpose"
      ]),
    "RELEASE_PLAN_KMS_ALIAS_TARGET_REJECTED"
  );
  const createApi = statementBySid(serviceStatements, "CreateOneTaggedHttpApi");
  const manageApi = statementBySid(
    serviceStatements,
    "ManageOnlyTaggedHttpApiFamily"
  );
  requireCondition(
    createApi.Effect === "Allow" &&
      actions(createApi).join("\n") === "apigateway:POST" &&
      createApi.Resource?.["Fn::Sub"] ===
        "arn:${AWS::Partition}:apigateway:us-east-1::/apis" &&
      exactKeys(createApi.Condition?.StringEquals, [
        "aws:RequestTag/Gate",
        "aws:RequestTag/Project"
      ]) &&
      Array.isArray(manageApi.Resource) &&
      manageApi.Resource.length === 2 &&
      exactKeys(manageApi.Condition?.StringEquals, [
        "aws:ResourceTag/Gate",
        "aws:ResourceTag/Project"
      ]),
    "RELEASE_PLAN_API_PERMISSION_REJECTED"
  );
  for (const statement of [
    ...releaseStatements,
    ...coordinatorStatements,
    ...executionStatements,
    ...liveStatements,
    ...evidenceStatements,
    ...teardownStatements,
    ...terminalizerStatements,
    ...serviceStatements
  ]) {
    if (statement.Effect !== "Allow" || statement.Resource !== "*") continue;
    const exactReadOnlyWildcard =
      (statement.Sid === "ReadOwnDriftDetectionStatus" &&
        actions(statement).join("\n") ===
          "cloudformation:DescribeStackDriftDetectionStatus") ||
      (statement.Sid === "ReadLambdaEventSourceCensus" &&
        actions(statement).join("\n") === "lambda:ListEventSourceMappings");
    requireCondition(
      exactReadOnlyWildcard ||
        (["CreateTaggedReceiptKey", "ManageTaggedReceiptKey"].includes(
          statement.Sid
        ) && statement.Condition?.StringEquals),
      "RELEASE_PLAN_ALLOW_WILDCARD_REJECTED"
    );
  }
  const kms = validateIndispensableKmsContract(gate2Template);
  return Object.freeze({
    controlTable: Object.freeze({
      billingMode: "PAY_PER_REQUEST",
      deletionPolicy: "Retain",
      deletionProtectionEnabled: true,
      encryptionKeyAlias: "alias/aws/dynamodb",
      logicalId: "ReleaseControlTable",
      name: "prooftoact-release-controller",
      partitionKey: "pk",
      retainedOutsideApplicationTeardown: true,
      sseType: "KMS",
      updateReplacePolicy: "Retain"
    }),
    cloudFormationPermissionsBoundary: permissionsBoundary,
    coordinatorRoleLogicalId: "ReleaseCoordinatorRole",
    deploymentRoleLogicalId: "ReleaseDeploymentRole",
    executionRoleLogicalId: "ReleaseExecutionRole",
    liveDrillRoleLogicalId: "LiveDrillOperatorRole",
    independentEvidenceRoleLogicalId: "ReleaseEvidenceRole",
    teardownRoleLogicalId: "ReleaseTeardownRole",
    terminalizerRoleLogicalId: "ReleaseTerminalizerRole",
    cloudFormationRoleLogicalId: "CloudFormationServiceRole",
    evidenceOperatorParameterMustReference: "LiveDrillOperatorRoleArn",
    evidenceSeparationBoundary:
      "OUTER_EVIDENCE_IS_READ_ONLY;FROZEN_APP_USES_ONE_LIVE_DRILL_PRINCIPAL_FOR_INNER_DRILL_AND_EVIDENCE_ROLES",
    providerStoreSeparationBoundary:
      "COORDINATOR_HAS_ATOMIC_STORE_AND_READBACK_ONLY;LANE_DISPATCHERS_HAVE_EFFECT_ONLY_STRONG_READ",
    teardownPhysicalStackBindingRequired: true,
    oidcTrustBoundary:
      "IAM_BINDS_IMMUTABLE_REUSABLE_JOB_WORKFLOW_REF_AND_EXISTING_REPOSITORY_REF_ENVIRONMENT_CLAIMS",
    requiredRuntimeWorkflowRefs: Object.freeze(Object.fromEntries(
      Object.entries(OIDC_ROLE_CONTRACTS).map(([logicalId, contract]) => [
        logicalId,
        `Flash-Bri/prooftoact/.github/workflows/${contract.credentialWorkflowFile}@${SEALED_WORKFLOW_COMMIT}`
      ])
    )),
    kms
  });
}

export function validateReleaseControls(value, binding, now = Date.now()) {
  const code = "RELEASE_PLAN_CONTROLS_REJECTED";
  requireCondition(
    exactKeys(value, [
      "approvalId",
      "approvedAt",
      "approvedBy",
      "artifactBucket",
      "expiresAt",
      "forecastStatus",
      "maximumApprovedUsd",
      "oneShot",
      "partialFailureDisposition",
      "projectedTotalUsd",
      "resourceInventorySha256",
      "rolesTemplateSha256",
      "schemaVersion",
      "sourceCommit",
      "status",
      "teardown",
      "treeDigest"
    ]) &&
      exactKeys(binding, [
        "artifactBucket",
        "resourceInventorySha256",
        "rolesTemplateSha256",
        "sourceCommit",
        "treeDigest"
      ]) &&
      value.schemaVersion === "prooftoact.release-controls.v1" &&
      value.status === "REVIEWED_NOT_EXECUTED" &&
      value.approvedBy === "BRIAN_SMITH" &&
      value.oneShot === true &&
      UUID.test(value.approvalId ?? "") &&
      value.artifactBucket === binding.artifactBucket &&
      value.resourceInventorySha256 === binding.resourceInventorySha256 &&
      value.rolesTemplateSha256 === binding.rolesTemplateSha256 &&
      value.sourceCommit === binding.sourceCommit &&
      value.treeDigest === binding.treeDigest &&
      value.forecastStatus === "AVAILABLE" &&
      Number.isFinite(value.maximumApprovedUsd) &&
      value.maximumApprovedUsd >= 0 &&
      value.maximumApprovedUsd <= 12 &&
      Number.isFinite(value.projectedTotalUsd) &&
      value.projectedTotalUsd >= 0 &&
      value.projectedTotalUsd <= value.maximumApprovedUsd &&
      value.partialFailureDisposition ===
        "HOLD_RECONCILE_OR_TEARDOWN_NO_BLIND_RETRY" &&
      exactKeys(value.teardown, [
        "deleteExactStack",
        "expectedResourceInventorySha256",
        "judgingAccessThrough",
        "residualCensusRequired",
        "teardownDeadline"
      ]) &&
      value.teardown.deleteExactStack === "prooftoact-gate2" &&
      value.teardown.expectedResourceInventorySha256 ===
        binding.resourceInventorySha256 &&
      value.teardown.residualCensusRequired === true,
    code
  );
  const approvedAt = Date.parse(value.approvedAt);
  const expiresAt = Date.parse(value.expiresAt);
  const judgingAccessThrough = Date.parse(value.teardown.judgingAccessThrough);
  const teardownDeadline = Date.parse(value.teardown.teardownDeadline);
  requireCondition(
    Number.isFinite(now) &&
      Number.isFinite(approvedAt) &&
      Number.isFinite(expiresAt) &&
      Number.isFinite(judgingAccessThrough) &&
      Number.isFinite(teardownDeadline) &&
      approvedAt <= now &&
      now < expiresAt &&
      expiresAt - approvedAt <= 60 * 60 * 1000 &&
      teardownDeadline > judgingAccessThrough &&
      teardownDeadline - judgingAccessThrough <= 24 * 60 * 60 * 1000,
    code
  );
  return Object.freeze(structuredClone(value));
}

function resourcesForCreate(template) {
  const code = "RELEASE_PLAN_TEMPLATE_RESOURCE_REJECTED";
  requireCondition(
    exactKeys(template, [
      "AWSTemplateFormatVersion",
      "Conditions",
      "Description",
      "Outputs",
      "Parameters",
      "Resources",
      "Rules"
    ]) &&
      template.Parameters?.EnableProbeFunctions?.Default === "false",
    code
  );
  const resources = Object.entries(template.Resources)
    .filter(([, resource]) => resource?.Condition !== "ShouldDeployProbes")
    .map(([logicalId, resource]) => {
      requireCondition(
        /^[A-Za-z][A-Za-z0-9]{0,254}$/u.test(logicalId) &&
          typeof resource?.Type === "string" &&
          /^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$/u.test(resource.Type),
        code
      );
      return Object.freeze({ logicalId, type: resource.Type });
    })
    .sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  requireCondition(
    resources.length > 0 &&
      new Set(resources.map(({ logicalId }) => logicalId)).size ===
        resources.length,
    code
  );
  return Object.freeze(resources);
}

function assertPrimaryResourceContract(template, resources) {
  const code = "RELEASE_PLAN_PRIMARY_RESOURCE_CONTRACT_REJECTED";
  const roles = resources
    .filter(({ type }) => type === "AWS::IAM::Role")
    .map(({ logicalId }) => logicalId)
    .sort();
  const lambdas = resources
    .filter(({ type }) => type === "AWS::Lambda::Function")
    .map(({ logicalId }) => logicalId)
    .sort();
  requireCondition(
    JSON.stringify(roles) ===
      JSON.stringify([...PRIMARY_ROLE_LOGICAL_IDS].sort()) &&
      JSON.stringify(lambdas) ===
        JSON.stringify([...PRIMARY_LAMBDA_LOGICAL_IDS].sort()),
    code
  );
  for (const logicalId of PRIMARY_LAMBDA_LOGICAL_IDS) {
    const properties = template.Resources[logicalId]?.Properties;
    requireCondition(
      properties &&
        !Object.hasOwn(properties, "TracingConfig") &&
        properties.ReservedConcurrentExecutions !== undefined,
      code
    );
  }
  for (const resource of Object.values(template.Resources)) {
    if (resource?.Type !== "AWS::Logs::LogGroup" ||
      resource.Condition === "ShouldDeployProbes") continue;
    requireCondition(
      resource.Properties?.RetentionInDays === 7 ||
        resource.Properties?.RetentionInDays === 30,
      code
    );
  }
  for (const resource of Object.values(template.Resources)) {
    if (resource?.Type !== "AWS::IAM::Role") continue;
    for (const policy of resource.Properties?.Policies ?? []) {
      for (const statement of policy?.PolicyDocument?.Statement ?? []) {
        if (statement?.Effect !== "Allow") continue;
        requireCondition(
          actions(statement).every((action) =>
            action !== "*" && !action.endsWith(":*")
          ),
          "RELEASE_PLAN_PRIMARY_POLICY_WILDCARD_REJECTED"
        );
      }
    }
  }
  return Object.freeze({
    iamRoles: Object.freeze(roles),
    lambdaFunctions: Object.freeze(lambdas)
  });
}

export function buildReleaseUploadPlan({
  applicationIdentity,
  artifactBucket,
  controlPlaneIdentity,
  controlsNow = Date.now(),
  deploymentRolesTemplate,
  releaseControls,
  sourceCommit,
  treeDigest,
  validatedBuild,
  gate2Template
}) {
  const code = "RELEASE_PLAN_BUILD_REJECTED";
  const bucket = validateArtifactBucket(artifactBucket);
  requireCondition(
    exactKeys(applicationIdentity, [
      "identitySha256",
      "sourceCommit",
      "templateSha256",
      "treeDigest"
    ]) &&
      exactKeys(controlPlaneIdentity, [
        "controllerSha256",
        "identitySha256",
        "preparerSha256",
        "rolesTemplateSha256",
        "sourceCommit",
        "treeDigest"
      ]) &&
      HEX_40.test(sourceCommit ?? "") &&
      HEX_40.test(treeDigest ?? "") &&
      sourceCommit === applicationIdentity.sourceCommit &&
      treeDigest === applicationIdentity.treeDigest &&
      HEX_40.test(controlPlaneIdentity.sourceCommit ?? "") &&
      HEX_40.test(controlPlaneIdentity.treeDigest ?? "") &&
      HEX_64.test(applicationIdentity.templateSha256 ?? "") &&
      HEX_64.test(applicationIdentity.identitySha256 ?? "") &&
      HEX_64.test(controlPlaneIdentity.controllerSha256 ?? "") &&
      HEX_64.test(controlPlaneIdentity.preparerSha256 ?? "") &&
      HEX_64.test(controlPlaneIdentity.rolesTemplateSha256 ?? "") &&
      HEX_64.test(controlPlaneIdentity.identitySha256 ?? "") &&
      applicationIdentity.identitySha256 === sha256(canonicalBytes({
        sourceCommit: applicationIdentity.sourceCommit,
        templateSha256: applicationIdentity.templateSha256,
        treeDigest: applicationIdentity.treeDigest
      })) &&
      controlPlaneIdentity.identitySha256 === sha256(canonicalBytes({
        controllerSha256: controlPlaneIdentity.controllerSha256,
        preparerSha256: controlPlaneIdentity.preparerSha256,
        rolesTemplateSha256: controlPlaneIdentity.rolesTemplateSha256,
        sourceCommit: controlPlaneIdentity.sourceCommit,
        treeDigest: controlPlaneIdentity.treeDigest
      })) &&
      validatedBuild !== null &&
      typeof validatedBuild === "object" &&
      !Array.isArray(validatedBuild) &&
      exactKeys(validatedBuild.artifacts, ARTIFACT_NAMES) &&
      HEX_64.test(validatedBuild.gate2Template?.templateDigest ?? "") &&
      HEX_64.test(validatedBuild.packageLockDigest ?? ""),
    code
  );
  const resources = resourcesForCreate(gate2Template);
  const primary = assertPrimaryResourceContract(gate2Template, resources);
  const templateBytes = Buffer.from(
    `${JSON.stringify(gate2Template, null, 2)}\n`,
    "utf8"
  );
  requireCondition(
    sha256(templateBytes) === REVIEWED_GATE2_TEMPLATE_SHA256 &&
      sha256(templateBytes) === applicationIdentity.templateSha256 &&
      sha256(templateBytes) === validatedBuild.gate2Template.templateDigest,
    "RELEASE_PLAN_TEMPLATE_DIGEST_REJECTED"
  );
  const roleTemplateBytes = Buffer.from(
    `${JSON.stringify(deploymentRolesTemplate, null, 2)}\n`,
    "utf8"
  );
  const roleTemplateSha256 = sha256(roleTemplateBytes);
  const authority = validateReleaseDeploymentRoleTemplate(
    deploymentRolesTemplate,
    gate2Template
  );
  requireCondition(
    roleTemplateSha256 === REVIEWED_DEPLOYMENT_ROLES_TEMPLATE_SHA256 &&
      roleTemplateSha256 === controlPlaneIdentity.rolesTemplateSha256,
    "RELEASE_PLAN_ROLE_TEMPLATE_DIGEST_REJECTED"
  );

  const artifacts = ARTIFACT_NAMES.map((name) => {
    const artifact = validatedBuild.artifacts[name];
    requireCondition(
      exactKeys(artifact, [
        "artifactBytes",
        "artifactCodeSha256",
        "artifactDigest",
        "artifactPath",
        "bundledPackages",
        "exactGitInputs",
        "sourceDigest",
        "suggestedS3Key"
      ]) &&
        HEX_64.test(artifact.artifactDigest ?? "") &&
        HEX_64.test(artifact.sourceDigest ?? "") &&
        typeof artifact.artifactCodeSha256 === "string" &&
        /^[A-Za-z0-9+/]{43}=$/u.test(artifact.artifactCodeSha256) &&
        Number.isSafeInteger(artifact.artifactBytes) &&
        artifact.artifactBytes > 0 &&
        artifact.artifactPath ===
          `dist/aws/${name}-${artifact.artifactDigest}.zip` &&
        artifact.suggestedS3Key ===
          `gate2/${sourceCommit}/${name}-${artifact.artifactDigest}.zip`,
      code
    );
    return Object.freeze({
      name,
      localPath: artifact.artifactPath,
      s3Bucket: bucket,
      s3Key: artifact.suggestedS3Key,
      bytes: artifact.artifactBytes,
      sha256: artifact.artifactDigest,
      codeSha256: artifact.artifactCodeSha256,
      sourceSha256: artifact.sourceDigest,
      uploadContract: "PUT_ONCE_THEN_READ_BACK_EXACT_VERSION"
    });
  });
  const resourceInventorySha256 = sha256(canonicalBytes(resources));
  const controls = validateReleaseControls(releaseControls, {
    artifactBucket: bucket,
    resourceInventorySha256,
    rolesTemplateSha256: roleTemplateSha256,
    sourceCommit,
    treeDigest
  }, controlsNow);
  const sevenDayLogGroups = resources
    .filter(({ logicalId, type }) =>
      type === "AWS::Logs::LogGroup" &&
      gate2Template.Resources[logicalId].Properties.RetentionInDays === 7
    )
    .map(({ logicalId }) => logicalId);
  const plan = {
    schemaVersion: "prooftoact.release-upload-plan.v2",
    status: "PREPARED_NOT_AUTHORIZED",
    application: applicationIdentity,
    controlPlane: controlPlaneIdentity,
    sourceCommit,
    treeDigest,
    stack: {
      name: "prooftoact-gate2",
      region: "us-east-1",
      operation: "CREATE_CHANGE_SET_ONLY",
      probesEnabled: false,
      terminationProtectionRequired: true,
      directCreateStackAllowed: false,
      updateAllowed: false,
      deleteAllowedToDeploymentRole: false,
      capabilities: ["CAPABILITY_NAMED_IAM"]
    },
    costGate: {
      approvalId: controls.approvalId,
      maximumProjectedTotalUsd: controls.maximumApprovedUsd,
      projectedTotalUsd: controls.projectedTotalUsd,
      forecastStatus: controls.forecastStatus,
      perRunReserveUsd: 0.02,
      forecastUnavailableDisposition: "HOLD",
      currentResourceCensusRequired: true
    },
    build: {
      packageLockSha256: validatedBuild.packageLockDigest,
      templatePath: "infra/aws/gate2-template.json",
      templateSha256: validatedBuild.gate2Template.templateDigest
    },
    uploads: artifacts,
    createResourceInventory: resources,
    createResourceInventorySha256: resourceInventorySha256,
    primaryRuntime: primary,
    authoritySeparation: authority,
    deploymentRoles: {
      templatePath: "infra/aws/release-deployment-roles-template.json",
      templateSha256: roleTemplateSha256,
      cloudFormationPermissionsBoundaryRequired: true,
      cloudFormationPermissionsBoundarySourceOwned: true,
      cloudFormationPermissionsBoundaryPolicySha256:
        authority.cloudFormationPermissionsBoundary.policySha256,
      cloudFormationPermissionsBoundaryAllowInventorySha256:
        authority.cloudFormationPermissionsBoundary.allowInventorySha256,
      preparationCanExecuteChangeSet: false,
      executionCanCreateChangeSet: false,
      deploymentCanAssumeDrillOrEvidenceRoles: false,
      liveDrillCanDeployOrWriteArtifacts: false,
      independentEvidenceCanMutateOrAssumeRoles: false,
      releaseControlTableRetainedOutsideApplicationTeardown: true,
      teardownCanDeployInvokeOrAssumeRoles: false,
      terminalizerCanDispatchReserveBudgetOrDeleteState: false
    },
    executionGate: {
      status: "HOLD_RUNTIME_AUTHORITY_AND_RECEIPTS_REQUIRED",
      requiredChangeSetType: "CREATE",
      requiredStackAbsence: true,
      requiredStackName: "prooftoact-gate2",
      requiredChangeSetNamePrefix: "prooftoact-release-",
      requiredIndependentArtifacts: [
        "EXACT_CHANGE_SET_ARN_AND_PROVIDER_DIGEST",
        "RESOLVED_TEMPLATE_PARAMETER_AND_IAM_DIFF",
        "SOURCE_OWNED_PERMISSIONS_BOUNDARY_PROVIDER_DIGEST",
        "IAM_ALLOW_AND_DENY_SIMULATION_RECEIPT",
        "EXACT_RESOURCE_FORECAST_AND_SERVICE_CAPS",
        "CURRENT_RESOURCE_AND_COST_CENSUS",
        "SEPARATE_SCOPED_TEARDOWN_PRINCIPAL_AND_KEEP_ALIVE_CONTRACT",
        "POST_TEARDOWN_RESIDUAL_AND_DELAYED_COST_CENSUS",
        "SEPARATE_UNEXPIRED_ONE_SHOT_BRIAN_EXECUTION_APPROVAL"
      ],
      partialFailureDisposition:
        "HOLD_RECONCILE_OR_TEARDOWN_NO_BLIND_RETRY"
    },
    teardownGate: controls.teardown,
    logEvidence: {
      retentionDays: sevenDayLogGroups.length === 0 ? 30 : 7,
      immutableExportRequired: sevenDayLogGroups.length > 0,
      sevenDayLogGroups
    },
    nextGate:
      "Keep execution on HOLD. The provider-global one-shot broker is implemented as a provider-client-free control boundary, but it must receive fresh exact runtime authority and authenticated provider/global-store receipts before its separately protected adapter can atomically consume one unexpired approval and dispatch. Before that point, a separate preparer must upload exact artifacts, bind immutable S3 VersionIds, create but not execute one CREATE change set, and persist and independently review its exact ARN, type, template, parameters, permissions boundary, IAM action/resource policy, resolved resource inventory, current-resource/cost census, teardown contract, and provider policy-simulator matrix. This preparer cannot execute, invoke, assume drill/evidence roles, or authorize the broker.",
    claimBoundary:
      "This local plan separately binds one clean control-plane commit/tree and its preparer/controller/IAM-template bytes to one clean frozen-application commit/tree and its build/template bytes. It performs no AWS, CockroachDB, GitHub, deployment, spending, publication, or submission action and does not authorize upload or change-set execution."
  };
  return Object.freeze({
    ...plan,
    planSha256: sha256(canonicalBytes(plan))
  });
}

function parseArguments(args) {
  const names = new Set([
    "--application-root",
    "--artifact-bucket",
    "--build-receipt",
    "--control-plane-root",
    "--expected-application-commit",
    "--expected-application-tree",
    "--expected-control-plane-commit",
    "--expected-control-plane-tree",
    "--release-controls",
    "--output"
  ]);
  requireCondition(
    args.length === names.size * 2,
    "RELEASE_PLAN_ARGUMENTS_REJECTED"
  );
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    requireCondition(
      names.has(name) &&
        !Object.hasOwn(result, name) &&
        typeof args[index + 1] === "string" &&
        args[index + 1] !== "",
      "RELEASE_PLAN_ARGUMENTS_REJECTED"
    );
    result[name] = args[index + 1];
  }
  return result;
}

function gitValue(rootDir, args) {
  return execFileSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      cwd: rootDir,
      encoding: "utf8",
      env: gitEnvironment(process.env),
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000
    }
  ).trim();
}

function exactCheckout(rootDir, expectedCommit, expectedTree, code) {
  requireCondition(
    typeof rootDir === "string" &&
      path.isAbsolute(rootDir) &&
      path.resolve(rootDir) === rootDir &&
      fs.realpathSync(rootDir) === rootDir &&
      HEX_40.test(expectedCommit ?? "") &&
      HEX_40.test(expectedTree ?? ""),
    code
  );
  assertExactGitRepositoryLayout({ rootDir });
  const sourceCommit = gitValue(rootDir, ["rev-parse", "HEAD"]);
  const treeDigest = gitValue(rootDir, ["rev-parse", "HEAD^{tree}"]);
  const remote = gitValue(rootDir, ["remote", "get-url", "origin"]);
  requireCondition(
    sourceCommit === expectedCommit &&
      treeDigest === expectedTree &&
      [OFFICIAL_REMOTE, OFFICIAL_REMOTE.slice(0, -4)].includes(remote),
    code
  );
  const clean = assertCleanExactGitCheckout({
    rootDir,
    sourceCommit,
    treeDigest
  });
  requireCondition(
    clean.sourceCommit === sourceCommit && clean.treeDigest === treeDigest,
    code
  );
  return Object.freeze({ rootDir, sourceCommit, treeDigest });
}

function exactTrackedBytes(checkout, relativePath, code) {
  const absolutePath = path.join(checkout.rootDir, relativePath);
  let descriptor;
  try {
    requireCondition(
      path.resolve(absolutePath) === absolutePath &&
        fs.realpathSync(absolutePath) === absolutePath,
      code
    );
    descriptor = fs.openSync(
      absolutePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const stat = fs.fstatSync(descriptor);
    requireCondition(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.nlink === 1 &&
        stat.size > 0 &&
        stat.size <= 16 * 1024 * 1024,
      code
    );
    const bytes = fs.readFileSync(descriptor);
    const gitBlob = readExactGitBlob({
      rootDir: checkout.rootDir,
      sourceCommit: checkout.sourceCommit,
      filePath: absolutePath
    });
    requireCondition(bytes.equals(gitBlob.bytes), code);
    return Object.freeze({ bytes, sha256: sha256(bytes) });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function boundIdentity(value) {
  return Object.freeze({
    ...value,
    identitySha256: sha256(canonicalBytes(value))
  });
}

export function validateReleaseSourceComposition({
  applicationRoot,
  code = "RELEASE_PLAN_SOURCE_COMPOSITION_REJECTED",
  controlPlaneRoot,
  entrypointFile,
  entrypointRelativePath,
  expectedApplicationCommit,
  expectedApplicationTree,
  expectedControlPlaneCommit,
  expectedControlPlaneTree
}) {
  try {
    requireCondition(
      typeof code === "string" &&
        /^(?:CONTROLLER|RELEASE_PLAN)_[A-Z0-9_]{1,100}$/u.test(code) &&
        typeof applicationRoot === "string" &&
        typeof controlPlaneRoot === "string" &&
        path.isAbsolute(applicationRoot) &&
        path.isAbsolute(controlPlaneRoot) &&
        path.resolve(applicationRoot) === applicationRoot &&
        path.resolve(controlPlaneRoot) === controlPlaneRoot &&
        fs.realpathSync(applicationRoot) === applicationRoot &&
        fs.realpathSync(controlPlaneRoot) === controlPlaneRoot &&
        applicationRoot !== controlPlaneRoot,
      code
    );
    const applicationFromControl = path.relative(
      controlPlaneRoot,
      applicationRoot
    );
    const controlFromApplication = path.relative(
      applicationRoot,
      controlPlaneRoot
    );
    const applicationStat = fs.lstatSync(applicationRoot);
    const controlPlaneStat = fs.lstatSync(controlPlaneRoot);
    requireCondition(
      applicationStat.isDirectory() &&
        controlPlaneStat.isDirectory() &&
        !applicationStat.isSymbolicLink() &&
        !controlPlaneStat.isSymbolicLink() &&
        (applicationStat.dev !== controlPlaneStat.dev ||
          applicationStat.ino !== controlPlaneStat.ino) &&
        (applicationFromControl.startsWith(`..${path.sep}`) ||
          applicationFromControl === "..") &&
        (controlFromApplication.startsWith(`..${path.sep}`) ||
          controlFromApplication === ".."),
      code
    );
    const controlPlane = exactCheckout(
      controlPlaneRoot,
      expectedControlPlaneCommit,
      expectedControlPlaneTree,
      code
    );
    const application = exactCheckout(
      applicationRoot,
      expectedApplicationCommit,
      expectedApplicationTree,
      code
    );
    requireCondition(
      typeof entrypointRelativePath === "string" &&
        [
          CONTROL_PLANE_CONTROLLER_PATH,
          CONTROL_PLANE_PREPARER_PATH
        ].includes(entrypointRelativePath) &&
        typeof entrypointFile === "string" &&
        path.isAbsolute(entrypointFile) &&
        fs.realpathSync(entrypointFile) ===
          path.join(controlPlaneRoot, entrypointRelativePath),
      code
    );
    const applicationTemplate = exactTrackedBytes(
      application,
      APPLICATION_TEMPLATE_PATH,
      code
    );
    const controller = exactTrackedBytes(
      controlPlane,
      CONTROL_PLANE_CONTROLLER_PATH,
      code
    );
    const preparer = exactTrackedBytes(
      controlPlane,
      CONTROL_PLANE_PREPARER_PATH,
      code
    );
    const rolesTemplate = exactTrackedBytes(
      controlPlane,
      CONTROL_PLANE_ROLES_TEMPLATE_PATH,
      code
    );
    return Object.freeze({
      application: boundIdentity({
        sourceCommit: application.sourceCommit,
        templateSha256: applicationTemplate.sha256,
        treeDigest: application.treeDigest
      }),
      controlPlane: boundIdentity({
        controllerSha256: controller.sha256,
        preparerSha256: preparer.sha256,
        rolesTemplateSha256: rolesTemplate.sha256,
        sourceCommit: controlPlane.sourceCommit,
        treeDigest: controlPlane.treeDigest
      })
    });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function readJson(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const stat = fs.fstatSync(descriptor);
    requireCondition(
      stat.isFile() &&
        !stat.isSymbolicLink() &&
        stat.nlink === 1 &&
        stat.size > 0 &&
        stat.size <= maximumBytes,
      code
    );
    return JSON.parse(fs.readFileSync(descriptor).toString("utf8"));
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function publishPlan(filePath, plan) {
  requireCondition(path.isAbsolute(filePath), "RELEASE_PLAN_OUTPUT_REJECTED");
  const rootPath = fs.realpathSync(path.dirname(filePath));
  const rootStat = fs.lstatSync(rootPath);
  requireCondition(
    rootPath === path.dirname(filePath) &&
      rootStat.isDirectory() &&
      !rootStat.isSymbolicLink() &&
      rootStat.uid === process.getuid() &&
      (rootStat.mode & 0o077) === 0,
    "RELEASE_PLAN_OUTPUT_REJECTED"
  );
  const bytes = canonicalBytes(plan);
  const result = publishOrReadExactOwnedFile({
    bytes,
    code: "RELEASE_PLAN_OUTPUT_REJECTED",
    filePath,
    maximumBytes: 4 * 1024 * 1024,
    mode: 0o600,
    rootPath,
    assertRoot: () => {
      const stat = fs.lstatSync(rootPath);
      requireCondition(
        stat.isDirectory() &&
          !stat.isSymbolicLink() &&
          stat.uid === process.getuid() &&
          (stat.mode & 0o077) === 0,
        "RELEASE_PLAN_OUTPUT_REJECTED"
      );
    }
  });
  requireCondition(result.bytes.equals(bytes), "RELEASE_PLAN_OUTPUT_REJECTED");
  return bytes;
}

export async function main(args = process.argv.slice(2)) {
  const parsed = parseArguments(args);
  const composition = validateReleaseSourceComposition({
    applicationRoot: parsed["--application-root"],
    controlPlaneRoot: parsed["--control-plane-root"],
    entrypointFile: CURRENT_FILE,
    entrypointRelativePath: CONTROL_PLANE_PREPARER_PATH,
    expectedApplicationCommit: parsed["--expected-application-commit"],
    expectedApplicationTree: parsed["--expected-application-tree"],
    expectedControlPlaneCommit: parsed["--expected-control-plane-commit"],
    expectedControlPlaneTree: parsed["--expected-control-plane-tree"]
  });
  const buildReceipt = readJson(
    parsed["--build-receipt"],
    16 * 1024 * 1024,
    "RELEASE_PLAN_BUILD_RECEIPT_REJECTED"
  );
  const validatedBuild = validateBuildReceipt(buildReceipt, {
    projectRoot: parsed["--application-root"],
    sourceCommit: composition.application.sourceCommit,
    treeDigest: composition.application.treeDigest
  });
  const gate2Template = readJson(
    path.join(parsed["--application-root"], APPLICATION_TEMPLATE_PATH),
    4 * 1024 * 1024,
    "RELEASE_PLAN_TEMPLATE_REJECTED"
  );
  const deploymentRolesTemplate = readJson(
    path.join(
      parsed["--control-plane-root"],
      CONTROL_PLANE_ROLES_TEMPLATE_PATH
    ),
    4 * 1024 * 1024,
    "RELEASE_PLAN_ROLE_TEMPLATE_REJECTED"
  );
  const releaseControls = readJson(
    parsed["--release-controls"],
    1024 * 1024,
    "RELEASE_PLAN_CONTROLS_FILE_REJECTED"
  );
  const plan = buildReleaseUploadPlan({
    applicationIdentity: composition.application,
    artifactBucket: parsed["--artifact-bucket"],
    controlPlaneIdentity: composition.controlPlane,
    deploymentRolesTemplate,
    releaseControls,
    sourceCommit: composition.application.sourceCommit,
    treeDigest: composition.application.treeDigest,
    validatedBuild,
    gate2Template
  });
  const bytes = publishPlan(parsed["--output"], plan);
  process.stdout.write(`RELEASE_UPLOAD_PLAN_PASS:${sha256(bytes)}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^RELEASE_PLAN_[A-Z0-9_]{1,100}$/u.test(
      String(error?.message ?? "")
    )
      ? error.message
      : "RELEASE_PLAN_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  APPLICATION_TEMPLATE_PATH,
  ARTIFACT_NAMES,
  CONTROL_PLANE_CONTROLLER_PATH,
  CONTROL_PLANE_PREPARER_PATH,
  CONTROL_PLANE_ROLES_TEMPLATE_PATH,
  DEPLOYMENT_ROLE_LOGICAL_IDS,
  PRIMARY_LAMBDA_LOGICAL_IDS,
  PRIMARY_ROLE_LOGICAL_IDS,
  REVIEWED_DEPLOYMENT_ROLES_TEMPLATE_SHA256,
  REVIEWED_GATE2_TEMPLATE_SHA256,
  canonicalBytes,
  boundIdentity,
  parseArguments,
  resourcesForCreate,
  sha256
});
