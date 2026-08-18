import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  __test,
  bootstrapPrepareEnvironmentValues,
  bootstrapReadbackConstants,
  buildBootstrapIamSimulationPlan,
  buildReleaseControlBootstrapReadbackInputFromDirectory,
  buildReleaseControlBootstrapReadbackReceipt,
  renderBootstrapIamSimulationCommands,
  verifyReleaseControlBootstrapReadbackReceipt
} from "../scripts/release-provider-bootstrap-readback.js";

const TEMPLATE_BYTES = fs.readFileSync(new URL(
  "../infra/aws/release-deployment-roles-template.json",
  import.meta.url
));
const ACCOUNT_ID = "123456789012";
const ARTIFACT_BUCKET = "prooftoact-private-artifacts-123456789012";
const OBSERVED_AT = "2026-08-18T13:00:00.000Z";
const CREATED_AT = "2026-08-18T12:00:00.000Z";
const STACK_ID = `arn:aws:cloudformation:us-east-1:${ACCOUNT_ID}:stack/` +
  "prooftoact-release-control-bootstrap/00000000-0000-4000-8000-000000000000";
const TABLE_ID = "723e4567-e89b-42d3-a456-426614174006";
const KMS_ID = "123e4567-e89b-42d3-a456-426614174000";

function clone(value) {
  return structuredClone(value);
}

function contract() {
  return __test.buildContract(TEMPLATE_BYTES, ACCOUNT_ID, ARTIFACT_BUCKET);
}

function outputValues(resolved) {
  return Object.entries(resolved.template.Outputs).map(([OutputKey, output]) => ({
    OutputKey,
    OutputValue: __test.resolveIntrinsic(output.Value, resolved.context)
  }));
}

function roleReadback(expected, index, logicalId, boundaryArn) {
  const roleId = `AROA${String(index + 1).padStart(16, "A")}`;
  const role = {
    Path: "/",
    RoleName: expected.roleName,
    RoleId: roleId,
    Arn: expected.arn,
    CreateDate: CREATED_AT,
    AssumeRolePolicyDocument: clone(expected.trust),
    Description: expected.description,
    MaxSessionDuration: expected.maxSessionDuration,
    Tags: clone(expected.tags),
    RoleLastUsed: {}
  };
  if (logicalId === "CloudFormationServiceRole") {
    role.PermissionsBoundary = {
      PermissionsBoundaryType: "Policy",
      PermissionsBoundaryArn: boundaryArn
    };
  }
  return {
    getRole: { Role: role },
    getRolePolicy: {
      RoleName: expected.roleName,
      PolicyName: expected.policyName,
      PolicyDocument: clone(expected.inlinePolicy)
    },
    listAttachedRolePolicies: {
      AttachedPolicies: [],
      IsTruncated: false
    },
    listInstanceProfilesForRole: {
      InstanceProfiles: [],
      IsTruncated: false
    },
    listRolePolicies: {
      PolicyNames: [expected.policyName],
      IsTruncated: false
    },
    listRoleTags: {
      Tags: clone(expected.tags),
      IsTruncated: false
    }
  };
}

function simulationResponse(request, decision, boundary) {
  const result = {
    EvalActionName: request.ActionNames[0],
    EvalResourceName: request.ResourceArns[0],
    EvalDecision: decision,
    MissingContextValues: []
  };
  if (boundary) {
    result.PermissionsBoundaryDecisionDetail = {
      AllowedByPermissionsBoundary: decision === "allowed"
    };
  }
  return { EvaluationResults: [result], IsTruncated: false };
}

function fixture() {
  const resolved = contract();
  const tableArn = resolved.context.tableArn;
  const kmsArn = `arn:aws:kms:us-east-1:${ACCOUNT_ID}:key/${KMS_ID}`;
  const stackResourceSummaries = Object.entries(
    bootstrapReadbackConstants.ROLE_NAMES
  ).map(([LogicalResourceId, PhysicalResourceId]) => ({
    LogicalResourceId,
    PhysicalResourceId,
    ResourceType: "AWS::IAM::Role",
    LastUpdatedTimestamp: CREATED_AT,
    ResourceStatus: "CREATE_COMPLETE",
    DriftInformation: { StackResourceDriftStatus: "IN_SYNC" }
  }));
  stackResourceSummaries.push({
    LogicalResourceId: "CloudFormationPermissionsBoundary",
    PhysicalResourceId: resolved.context.boundaryArn,
    ResourceType: "AWS::IAM::ManagedPolicy",
    LastUpdatedTimestamp: CREATED_AT,
    ResourceStatus: "CREATE_COMPLETE",
    DriftInformation: { StackResourceDriftStatus: "IN_SYNC" }
  }, {
    LogicalResourceId: "ReleaseControlTable",
    PhysicalResourceId: bootstrapReadbackConstants.TABLE_NAME,
    ResourceType: "AWS::DynamoDB::Table",
    LastUpdatedTimestamp: CREATED_AT,
    ResourceStatus: "CREATE_COMPLETE",
    DriftInformation: { StackResourceDriftStatus: "IN_SYNC" }
  });
  const roles = Object.fromEntries(Object.keys(
    bootstrapReadbackConstants.ROLE_NAMES
  ).map((logicalId, index) => [logicalId, roleReadback(
    resolved.roles[logicalId],
    index,
    logicalId,
    resolved.context.boundaryArn
  )]));
  const serviceRoleId = roles.CloudFormationServiceRole.getRole.Role.RoleId;
  const plan = buildBootstrapIamSimulationPlan({
    accountId: ACCOUNT_ID,
    artifactBucketName: ARTIFACT_BUCKET
  });
  const simulations = Object.fromEntries(Object.entries(plan).map(
    ([logicalId, vectors]) => [logicalId, {
      negative: {
        request: clone(vectors.negative),
        response: simulationResponse(
          vectors.negative,
          "explicitDeny",
          vectors.permissionsBoundaryExpected
        )
      },
      positive: {
        request: clone(vectors.positive),
        response: simulationResponse(
          vectors.positive,
          "allowed",
          vectors.permissionsBoundaryExpected
        )
      }
    }]
  ));
  const resources = stackResourceSummaries.sort((left, right) =>
    left.LogicalResourceId.localeCompare(right.LogicalResourceId));
  const driftResources = resources.map((resource) => ({
    StackId: STACK_ID,
    LogicalResourceId: resource.LogicalResourceId,
    PhysicalResourceId: resource.PhysicalResourceId,
    ResourceType: resource.ResourceType,
    ExpectedProperties: "{}",
    ActualProperties: "{}",
    PropertyDifferences: [],
    StackResourceDriftStatus: "IN_SYNC",
    Timestamp: CREATED_AT
  }));
  const tableTags = clone(
    resolved.template.Resources.ReleaseControlTable.Properties.Tags
  );
  return {
    input: {
      schemaVersion: bootstrapReadbackConstants.INPUT_SCHEMA,
      accountId: ACCOUNT_ID,
      artifactBucketName: ARTIFACT_BUCKET,
      observedAt: OBSERVED_AT,
      providerMutationAbsenceCallerAsserted: true,
      readOnlyCollectionCallerAsserted: true,
      region: "us-east-1",
      responses: {
        boundary: {
          getPolicy: {
            Policy: {
              PolicyName: bootstrapReadbackConstants.BOUNDARY_NAME,
              PolicyId: "ANPAABCDEFGHIJKLMNOP",
              Arn: resolved.context.boundaryArn,
              Path: "/",
              DefaultVersionId: "v1",
              AttachmentCount: 0,
              PermissionsBoundaryUsageCount: 1,
              IsAttachable: true,
              Description: resolved.template.Resources
                .CloudFormationPermissionsBoundary.Properties.Description,
              CreateDate: CREATED_AT,
              UpdateDate: CREATED_AT,
              Tags: []
            }
          },
          getPolicyVersion: {
            PolicyVersion: {
              Document: clone(resolved.boundary),
              VersionId: "v1",
              IsDefaultVersion: true,
              CreateDate: CREATED_AT
            }
          },
          listPolicyVersions: {
            Versions: [{
              VersionId: "v1",
              IsDefaultVersion: true,
              CreateDate: CREATED_AT
            }],
            IsTruncated: false
          },
          listEntitiesForPolicy: {
            PolicyGroups: [],
            PolicyUsers: [],
            PolicyRoles: [{
              RoleName: "ProofToActGate2CloudFormation",
              RoleId: serviceRoleId
            }],
            IsTruncated: false
          }
        },
        callerIdentity: {
          UserId: ACCOUNT_ID,
          Account: ACCOUNT_ID,
          Arn: `arn:aws:iam::${ACCOUNT_ID}:root`
        },
        deployedTemplate: clone(resolved.template),
        describeKmsKey: {
          KeyMetadata: {
            AWSAccountId: ACCOUNT_ID,
            KeyId: KMS_ID,
            Arn: kmsArn,
            CreationDate: CREATED_AT,
            Enabled: true,
            KeyUsage: "ENCRYPT_DECRYPT",
            KeyState: "Enabled",
            Origin: "AWS_KMS",
            KeyManager: "AWS",
            CustomerMasterKeySpec: "SYMMETRIC_DEFAULT",
            KeySpec: "SYMMETRIC_DEFAULT",
            EncryptionAlgorithms: ["SYMMETRIC_DEFAULT"],
            MultiRegion: false,
            CurrentKeyMaterialId: "a".repeat(64)
          }
        },
        describeTable: {
          Table: {
            AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }],
            TableName: bootstrapReadbackConstants.TABLE_NAME,
            KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }],
            TableStatus: "ACTIVE",
            TableSizeBytes: 0,
            ItemCount: 0,
            TableArn: tableArn,
            TableId: TABLE_ID,
            BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" },
            SSEDescription: {
              Status: "ENABLED",
              SSEType: "KMS",
              KMSMasterKeyArn: kmsArn
            },
            DeletionProtectionEnabled: true
          }
        },
        listStackResourceDrifts: { StackResourceDrifts: driftResources },
        listStackResources: { StackResourceSummaries: resources },
        listTableTags: { Tags: tableTags },
        roles,
        simulations,
        stack: {
          Stacks: [{
            StackId: STACK_ID,
            StackName: bootstrapReadbackConstants.STACK_NAME,
            Description: resolved.template.Description,
            Parameters: [
              { ParameterKey: "ArtifactBucketName", ParameterValue: ARTIFACT_BUCKET },
              { ParameterKey: "GitHubOidcProviderArn",
                ParameterValue: resolved.context.oidcArn }
            ],
            CreationTime: CREATED_AT,
            RollbackConfiguration: {},
            StackStatus: "CREATE_COMPLETE",
            DisableRollback: false,
            NotificationARNs: [],
            TimeoutInMinutes: 15,
            Capabilities: ["CAPABILITY_NAMED_IAM"],
            Outputs: outputValues(resolved),
            Tags: [],
            EnableTerminationProtection: false,
            DeploymentConfig: {
              DisableRollback: false,
              Mode: "STANDARD"
            },
            LastOperations: [{
              OperationId: "10000000-0000-4000-8000-000000000000",
              OperationType: "CREATE_STACK"
            }],
            DriftInformation: { StackDriftStatus: "IN_SYNC" }
          }]
        }
      }
    },
    templateBytes: TEMPLATE_BYTES
  };
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

function materializeDirectory(t, input) {
  const root = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-bootstrap-readback-"
  ));
  const response = input.responses;
  const files = {
    "caller.json": response.callerIdentity,
    "deployed-template.json": response.deployedTemplate,
    "dynamodb-kms-key.json": response.describeKmsKey,
    "table.json": response.describeTable,
    "resource-drifts.json": response.listStackResourceDrifts,
    "resources.json": response.listStackResources,
    "table-tags.json": response.listTableTags,
    "stack.json": response.stack,
    "boundary.json": response.boundary.getPolicy,
    "boundary-version.json": response.boundary.getPolicyVersion,
    "boundary-entities.json": response.boundary.listEntitiesForPolicy,
    "boundary-versions.json": response.boundary.listPolicyVersions
  };
  for (const [name, value] of Object.entries(files)) {
    writeJson(path.join(root, name), value);
  }
  for (const [logicalId, roleName] of Object.entries(
    bootstrapReadbackConstants.ROLE_NAMES
  )) {
    const roleRoot = path.join(root, roleName);
    fs.mkdirSync(roleRoot, { mode: 0o700 });
    for (const [name, value] of Object.entries({
      "role.json": response.roles[logicalId].getRole,
      "inline-policy.json": response.roles[logicalId].getRolePolicy,
      "attached-list.json": response.roles[logicalId]
        .listAttachedRolePolicies,
      "instance-profiles.json": response.roles[logicalId]
        .listInstanceProfilesForRole,
      "inline-list.json": response.roles[logicalId].listRolePolicies,
      "tags.json": response.roles[logicalId].listRoleTags
    })) writeJson(path.join(roleRoot, name), value);
    for (const kind of ["negative", "positive"]) {
      writeJson(
        path.join(root, `${logicalId}-${kind}.json`),
        response.simulations[logicalId][kind].response
      );
    }
  }
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  return root;
}

function assertDirectoryRejected(directoryPath) {
  assert.throws(() => buildReleaseControlBootstrapReadbackInputFromDirectory({
    accountId: ACCOUNT_ID,
    artifactBucketName: ARTIFACT_BUCKET,
    directoryPath,
    observedAt: OBSERVED_AT
  }), /BOOTSTRAP_READBACK_DIRECTORY_REJECTED/u);
}

test("accepted bootstrap readback emits exactly five nonsecret PREPARE values", () => {
  const accepted = fixture();
  const receipt = buildReleaseControlBootstrapReadbackReceipt(accepted);
  assert.equal(receipt.status,
    "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED");
  assert.equal(receipt.inventory.count, 10);
  assert.equal(receipt.roles.count, 8);
  assert.equal(receipt.table.tableId, TABLE_ID);
  assert.equal(receipt.iamSimulation.checkCount, 16);
  assert.equal(receipt.iamSimulation.callerSuppliedResponsesValidated, true);
  assert.equal(receipt.iamSimulation.readbackPrincipalIndependenceProven,
    false);
  assert.equal(receipt.claimBoundary.providerMutationAuthorized, false);
  assert.equal(receipt.claimBoundary.providerMutationAbsenceCallerAsserted,
    true);
  assert.equal(
    receipt.claimBoundary.providerMutationAbsenceIndependentlyProven,
    false
  );
  assert.equal(receipt.claimBoundary.rawCollectorBundleRequiredForPublication,
    true);
  assert.equal(receipt.claimBoundary.applicationDeploymentProven, false);
  assert.equal(receipt.collectionBoundary.collectionMethod,
    "CALLER_SUPPLIED_JSON_RESPONSE_SET");
  assert.equal(receipt.collectionBoundary.collectorExecutionProven, false);
  assert.match(receipt.collectionBoundary.sourceOwnedCollectorSha256,
    /^[0-9a-f]{64}$/u);
  assert.match(receipt.collectionBoundary.sourceOwnedVerifierSha256,
    /^[0-9a-f]{64}$/u);
  assert.equal(
    verifyReleaseControlBootstrapReadbackReceipt({
      accountId: ACCOUNT_ID,
      receipt,
      templateBytes: TEMPLATE_BYTES
    }),
    receipt
  );
  const environment = bootstrapPrepareEnvironmentValues({
    accountId: ACCOUNT_ID,
    receipt,
    templateBytes: TEMPLATE_BYTES
  });
  assert.deepEqual(Object.keys(environment).sort(),
    [...bootstrapReadbackConstants.ENVIRONMENT_KEYS].sort());
  assert.equal(environment.PROOFTOACT_RELEASE_CONTROL_TABLE_ID, TABLE_ID);
  assert.equal(environment.PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256,
    receipt.receiptSha256);
  assert.equal(environment.PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256,
    receipt.stack.idSha256);
  assert.equal(Object.isFrozen(receipt), true);
});

test("simulation command renderer emits exactly sixteen read-only IAM calls", () => {
  const commands = renderBootstrapIamSimulationCommands({
    accountId: ACCOUNT_ID,
    artifactBucketName: ARTIFACT_BUCKET
  });
  const lines = commands.trimEnd().split("\n");
  assert.equal(lines.length, 16);
  assert.equal(lines.every((line) =>
    line.startsWith("aws iam simulate-principal-policy ") &&
    line.includes(" --no-cli-pager --output json > '") &&
    !line.includes("create-") && !line.includes("update-") &&
    !line.includes("delete-")), true);
  assert.equal(lines.filter((line) =>
    line.includes("CloudFormationServiceRole-positive.json")).length, 1);
  assert.equal(lines.filter((line) =>
    line.includes("ReleaseTerminalizerRole-negative.json")).length, 1);
});

test("live-simulator negative vectors use explicit-deny-compatible actions", () => {
  const plan = buildBootstrapIamSimulationPlan({
    accountId: ACCOUNT_ID,
    artifactBucketName: ARTIFACT_BUCKET
  });
  const lambdaArn = `arn:aws:lambda:us-east-1:${ACCOUNT_ID}:function:` +
    "prooftoact-gate2-negative";
  for (const logicalId of [
    "LiveDrillOperatorRole",
    "ReleaseDeploymentRole"
  ]) {
    assert.deepEqual(plan[logicalId].negative.ActionNames,
      ["lambda:InvokeFunction"]);
    assert.deepEqual(plan[logicalId].negative.ResourceArns, [lambdaArn]);
  }
});

test("source-owned directory assembly reproduces the exact input without hand edits", (t) => {
  const accepted = fixture();
  const root = materializeDirectory(t, accepted.input);
  const assembled = buildReleaseControlBootstrapReadbackInputFromDirectory({
    accountId: ACCOUNT_ID,
    artifactBucketName: ARTIFACT_BUCKET,
    directoryPath: root,
    observedAt: OBSERVED_AT
  });
  assert.equal(__test.canonicalJson(assembled),
    __test.canonicalJson(accepted.input));
  assert.equal(buildReleaseControlBootstrapReadbackReceipt({
    input: assembled,
    templateBytes: TEMPLATE_BYTES
  }).status, "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED");
  writeJson(
    path.join(root, "deployed-template.json"),
    JSON.stringify(accepted.input.responses.deployedTemplate)
  );
  const stringTemplateAssembled =
    buildReleaseControlBootstrapReadbackInputFromDirectory({
      accountId: ACCOUNT_ID,
      artifactBucketName: ARTIFACT_BUCKET,
      directoryPath: root,
      observedAt: OBSERVED_AT
    });
  assert.equal(__test.canonicalJson(stringTemplateAssembled),
    __test.canonicalJson(accepted.input));
  writeJson(path.join(root, "unknown.json"), {});
  assert.throws(() => buildReleaseControlBootstrapReadbackInputFromDirectory({
    accountId: ACCOUNT_ID,
    artifactBucketName: ARTIFACT_BUCKET,
    directoryPath: root,
    observedAt: OBSERVED_AT
  }), /BOOTSTRAP_READBACK_DIRECTORY_REJECTED/u);
});

test("directory assembly rejects symlinks, hardlinks, missing entries, and extras", (t) => {
  const input = fixture().input;

  const rootTarget = materializeDirectory(t, input);
  const rootLink = `${rootTarget}-link`;
  fs.symlinkSync(rootTarget, rootLink, "dir");
  t.after(() => fs.rmSync(rootLink, { force: true }));
  assertDirectoryRejected(rootLink);

  const roleRoot = materializeDirectory(t, input);
  const externalRoleRoot = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-bootstrap-role-target-"
  ));
  t.after(() => fs.rmSync(externalRoleRoot, { force: true, recursive: true }));
  const roleName = bootstrapReadbackConstants.ROLE_NAMES
    .ReleaseExecutionRole;
  const originalRole = path.join(roleRoot, roleName);
  const externalRole = path.join(externalRoleRoot, roleName);
  fs.renameSync(originalRole, externalRole);
  fs.symlinkSync(externalRole, originalRole, "dir");
  assertDirectoryRejected(roleRoot);

  const fileRoot = materializeDirectory(t, input);
  const externalFileRoot = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-bootstrap-file-target-"
  ));
  t.after(() => fs.rmSync(externalFileRoot, { force: true, recursive: true }));
  const callerFile = path.join(fileRoot, "caller.json");
  const externalCaller = path.join(externalFileRoot, "caller.json");
  fs.renameSync(callerFile, externalCaller);
  fs.symlinkSync(externalCaller, callerFile, "file");
  assertDirectoryRejected(fileRoot);

  const hardlinkRoot = materializeDirectory(t, input);
  const externalHardlinkRoot = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-bootstrap-hardlink-target-"
  ));
  t.after(() => fs.rmSync(externalHardlinkRoot, {
    force: true,
    recursive: true
  }));
  fs.linkSync(
    path.join(hardlinkRoot, "caller.json"),
    path.join(externalHardlinkRoot, "caller.json")
  );
  assertDirectoryRejected(hardlinkRoot);

  const missingRoot = materializeDirectory(t, input);
  fs.rmSync(path.join(missingRoot, "caller.json"));
  assertDirectoryRejected(missingRoot);

  const extraRoot = materializeDirectory(t, input);
  writeJson(path.join(extraRoot, "unexpected.json"), {});
  assertDirectoryRejected(extraRoot);
});

test("collector source contains only the exact read-only AWS command families", () => {
  const source = fs.readFileSync(new URL(
    "../scripts/release-provider-bootstrap-readback-collector.sh",
    import.meta.url
  ), "utf8");
  assert.match(source, /sts get-caller-identity/u);
  assert.match(source, /cloudformation describe-stacks/u);
  assert.match(source, /cloudformation get-template/u);
  assert.match(source, /dynamodb describe-table/u);
  assert.match(source, /kms describe-key/u);
  assert.match(source, /iam simulate-principal-policy/u);
  assert.doesNotMatch(source,
    /\b(?:cloudformation|dynamodb|kms|iam)\s+(?:create|delete|update|put|attach|detach|tag|untag|detect|execute)[a-z-]*/u);
  assert.doesNotMatch(source, /aws configure/u);
  assert.match(source, /--verify-input/u);
});

test("canonical hashes are deterministic across provider object key order", () => {
  const first = fixture();
  const second = fixture();
  second.input.responses.callerIdentity = {
    Arn: `arn:aws:iam::${ACCOUNT_ID}:root`,
    UserId: ACCOUNT_ID,
    Account: ACCOUNT_ID
  };
  const left = buildReleaseControlBootstrapReadbackReceipt(first);
  const right = buildReleaseControlBootstrapReadbackReceipt(second);
  assert.equal(left.receiptSha256, right.receiptSha256);
  assert.equal(left.stack.idSha256, right.stack.idSha256);
  const tampered = clone(left);
  tampered.stack.idSha256 = "0".repeat(64);
  assert.throws(() => verifyReleaseControlBootstrapReadbackReceipt({
    accountId: ACCOUNT_ID,
    receipt: tampered,
    templateBytes: TEMPLATE_BYTES
  }), /BOOTSTRAP_READBACK_RECEIPT_REJECTED/u);
});

test("IAM simulations accept the AWS CLI false omission and reject every truncated or malformed envelope", () => {
  const omitted = fixture();
  for (const role of Object.values(omitted.input.responses.simulations)) {
    delete role.negative.response.IsTruncated;
    delete role.positive.response.IsTruncated;
  }
  assert.doesNotThrow(() =>
    buildReleaseControlBootstrapReadbackReceipt(omitted));

  const explicitFalse = fixture();
  assert.doesNotThrow(() =>
    buildReleaseControlBootstrapReadbackReceipt(explicitFalse));

  const mutations = [
    (response) => response.IsTruncated = true,
    (response) => response.IsTruncated = null,
    (response) => response.IsTruncated = "false",
    (response) => response.IsTruncated = 0,
    (response) => response.NextToken = "unexpected",
    (response) => delete response.EvaluationResults
  ];
  for (const mutate of mutations) {
    const candidate = fixture();
    const response = candidate.input.responses.simulations
      .ReleaseExecutionRole.positive.response;
    mutate(response);
    assert.throws(() => buildReleaseControlBootstrapReadbackReceipt(candidate),
      /BOOTSTRAP_READBACK_IAM_SIMULATION_REJECTED/u);
  }
});

test("unknown resource, table, role, boundary, and simulation drift fail closed", () => {
  const mutations = [
    (value) => value.input.responses.listStackResources
      .StackResourceSummaries[0].PhysicalResourceId = "wrong",
    (value) => value.input.responses.describeTable.Table
      .DeletionProtectionEnabled = false,
    (value) => value.input.responses.listTableTags.Tags.push({
      Key: "Unexpected",
      Value: "drift"
    }),
    (value) => value.input.responses.describeKmsKey.KeyMetadata
      .CurrentKeyMaterialId = "not-a-digest",
    (value) => value.input.responses.roles.ReleaseDeploymentRole
      .getRolePolicy.PolicyDocument.Statement[0].Action = "s3:*",
    (value) => value.input.responses.roles.ReleaseDeploymentRole
      .getRole.Role.RoleLastUsed = { Region: "us-east-1" },
    (value) => value.input.responses.boundary.getPolicyVersion
      .PolicyVersion.Document.Statement[0].Action = "s3:*",
    (value) => value.input.responses.boundary.listPolicyVersions
      .IsTruncated = true,
    (value) => value.input.responses.roles.ReleaseExecutionRole
      .listRolePolicies.Marker = "unexpected-pagination-token",
    (value) => value.input.responses.simulations.ReleaseExecutionRole
      .negative.response.EvaluationResults[0].EvalDecision = "allowed"
  ];
  for (const mutate of mutations) {
    const candidate = fixture();
    mutate(candidate);
    assert.throws(() => buildReleaseControlBootstrapReadbackReceipt(candidate),
      /BOOTSTRAP_READBACK_/u);
  }
});

test("only the exact DynamoDB AWS-managed KMS normalization drift is accepted", () => {
  const accepted = fixture();
  const table = accepted.input.responses.describeTable.Table;
  const resource = accepted.input.responses.listStackResources
    .StackResourceSummaries.find(({ LogicalResourceId }) =>
      LogicalResourceId === "ReleaseControlTable");
  resource.DriftInformation.StackResourceDriftStatus = "MODIFIED";
  const stack = accepted.input.responses.stack.Stacks[0];
  stack.DriftInformation = {
    StackDriftStatus: "DRIFTED",
    LastCheckTimestamp: CREATED_AT
  };
  const drift = accepted.input.responses.listStackResourceDrifts
    .StackResourceDrifts.find(({ LogicalResourceId }) =>
      LogicalResourceId === "ReleaseControlTable");
  const expected = clone(
    accepted.input.responses.deployedTemplate.Resources
      .ReleaseControlTable.Properties
  );
  const actual = clone(expected);
  actual.SSESpecification.KMSMasterKeyId =
    table.SSEDescription.KMSMasterKeyArn;
  drift.ExpectedProperties = JSON.stringify(expected);
  drift.ActualProperties = JSON.stringify(actual);
  drift.PropertyDifferences = [{
    PropertyPath: "/SSESpecification/KMSMasterKeyId",
    ExpectedValue:
      bootstrapReadbackConstants.CLOUDFORMATION_KMS_SUMMARY_SENTINEL,
    ActualValue: table.SSEDescription.KMSMasterKeyArn,
    DifferenceType: "NOT_EQUAL"
  }];
  drift.StackResourceDriftStatus = "MODIFIED";
  const receipt = buildReleaseControlBootstrapReadbackReceipt(accepted);
  assert.equal(receipt.stack.driftDisposition,
    "KNOWN_DYNAMODB_AWS_MANAGED_KMS_NORMALIZATION_ONLY");
  assert.equal(receipt.stack.driftSourceExpectedKmsAlias,
    "alias/aws/dynamodb");
  assert.equal(receipt.stack.driftSummaryExpectedValue,
    bootstrapReadbackConstants.CLOUDFORMATION_KMS_SUMMARY_SENTINEL);
  assert.equal(receipt.stack.driftSummaryExpectedValueDisposition,
    "AWS_CLOUDFORMATION_KMS_ARN_PATTERN_SENTINEL");

  const directAliasSummary = {
    input: clone(accepted.input),
    templateBytes: TEMPLATE_BYTES
  };
  directAliasSummary.input.responses.listStackResourceDrifts
    .StackResourceDrifts.find(({ LogicalResourceId }) =>
      LogicalResourceId === "ReleaseControlTable")
    .PropertyDifferences[0].ExpectedValue = "alias/aws/dynamodb";
  assert.equal(buildReleaseControlBootstrapReadbackReceipt(
    directAliasSummary
  ).stack.driftSummaryExpectedValueDisposition, "SOURCE_ALIAS");

  const unknown = {
    input: clone(accepted.input),
    templateBytes: TEMPLATE_BYTES
  };
  unknown.input.responses.listStackResourceDrifts.StackResourceDrifts
    .find(({ LogicalResourceId }) => LogicalResourceId ===
      "ReleaseControlTable").PropertyDifferences[0].PropertyPath =
        "/DeletionProtectionEnabled";
  assert.throws(() => buildReleaseControlBootstrapReadbackReceipt(unknown),
    /BOOTSTRAP_READBACK_DRIFT_REJECTED/u);

  for (const nearMiss of [
    `${bootstrapReadbackConstants.CLOUDFORMATION_KMS_SUMMARY_SENTINEL}x`,
    bootstrapReadbackConstants.CLOUDFORMATION_KMS_SUMMARY_SENTINEL.slice(0, -1),
    "unreviewed-alias"
  ]) {
    const mismatchedExpectedValue = {
      input: clone(accepted.input),
      templateBytes: TEMPLATE_BYTES
    };
    mismatchedExpectedValue.input.responses.listStackResourceDrifts
      .StackResourceDrifts.find(({ LogicalResourceId }) =>
        LogicalResourceId === "ReleaseControlTable")
      .PropertyDifferences[0].ExpectedValue = nearMiss;
    assert.throws(() => buildReleaseControlBootstrapReadbackReceipt(
      mismatchedExpectedValue
    ), /BOOTSTRAP_READBACK_DRIFT_REJECTED/u);
  }
});
