import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  buildReleaseUploadPlan,
  validateReleaseDeploymentRoleTemplate,
  validateReleaseSourceComposition
} from "../scripts/prepare-release-deployment.js";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);
const SOURCE_COMMIT = "1".repeat(40);
const TREE_DIGEST = "2".repeat(40);
const CONTROL_PLANE_COMMIT = "3".repeat(40);
const CONTROL_PLANE_TREE = "4".repeat(40);
const ARTIFACT_BUCKET = "prooftoact-private-artifacts-123456789012";
const NOW = Date.parse("2026-08-17T18:00:00.000Z");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function jsonFile(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function gate2Template() {
  return jsonFile("infra/aws/gate2-template.json");
}

function deploymentRolesTemplate() {
  return jsonFile("infra/aws/release-deployment-roles-template.json");
}

function resourceDependencies(template) {
  const logicalIds = new Set(Object.keys(template.Resources));
  const dependencies = new Map(
    [...logicalIds].map((logicalId) => [logicalId, new Set()])
  );
  function visit(value, owner) {
    if (Array.isArray(value)) {
      for (const item of value) visit(item, owner);
      return;
    }
    if (value === null || typeof value !== "object") return;
    if (typeof value.Ref === "string" && logicalIds.has(value.Ref)) {
      dependencies.get(owner).add(value.Ref);
    }
    const getAtt = value["Fn::GetAtt"];
    if (Array.isArray(getAtt) && logicalIds.has(getAtt[0])) {
      dependencies.get(owner).add(getAtt[0]);
    }
    const substitution = value["Fn::Sub"];
    if (typeof substitution === "string") {
      for (const match of substitution.matchAll(/\$\{([A-Za-z0-9]+)(?:\.[^}]*)?\}/gu)) {
        if (logicalIds.has(match[1])) dependencies.get(owner).add(match[1]);
      }
    }
    for (const nested of Object.values(value)) visit(nested, owner);
  }
  for (const [logicalId, resource] of Object.entries(template.Resources)) {
    for (const explicit of [resource.DependsOn].flat().filter(Boolean)) {
      if (logicalIds.has(explicit)) dependencies.get(logicalId).add(explicit);
    }
    visit(resource.Properties, logicalId);
  }
  return dependencies;
}

function assertAcyclicResourceGraph(template) {
  const dependencies = resourceDependencies(template);
  const active = new Set();
  const complete = new Set();
  function visit(logicalId, path = []) {
    if (complete.has(logicalId)) return;
    assert.equal(
      active.has(logicalId),
      false,
      `circular CloudFormation dependency: ${[...path, logicalId].join(" -> ")}`
    );
    active.add(logicalId);
    for (const dependency of dependencies.get(logicalId)) {
      visit(dependency, [...path, logicalId]);
    }
    active.delete(logicalId);
    complete.add(logicalId);
  }
  for (const logicalId of dependencies.keys()) visit(logicalId);
}

function prettyDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"));
}

function compositionIdentities({
  template = gate2Template(),
  rolesTemplate = deploymentRolesTemplate()
} = {}) {
  return {
    applicationIdentity: __test.boundIdentity({
      sourceCommit: SOURCE_COMMIT,
      templateSha256: prettyDigest(template),
      treeDigest: TREE_DIGEST
    }),
    controlPlaneIdentity: __test.boundIdentity({
      controllerSha256: sha256(fs.readFileSync(
        path.join(ROOT, __test.CONTROL_PLANE_CONTROLLER_PATH)
      )),
      preparerSha256: sha256(fs.readFileSync(
        path.join(ROOT, __test.CONTROL_PLANE_PREPARER_PATH)
      )),
      rolesTemplateSha256: prettyDigest(rolesTemplate),
      sourceCommit: CONTROL_PLANE_COMMIT,
      treeDigest: CONTROL_PLANE_TREE
    })
  };
}

function validatedBuild(template = gate2Template()) {
  const artifacts = {};
  for (const [index, name] of __test.ARTIFACT_NAMES.entries()) {
    const digest = String(index + 3).repeat(64);
    artifacts[name] = {
      sourceDigest: String(index + 9).slice(-1).repeat(64),
      artifactDigest: digest,
      artifactCodeSha256: Buffer.alloc(32, index + 1).toString("base64"),
      artifactBytes: 1_000 + index,
      artifactPath: `dist/aws/${name}-${digest}.zip`,
      bundledPackages: [],
      exactGitInputs: [],
      suggestedS3Key: `gate2/${SOURCE_COMMIT}/${name}-${digest}.zip`
    };
  }
  return {
    artifacts,
    gate2Template: { templateDigest: prettyDigest(template) },
    packageLockDigest: "f".repeat(64)
  };
}

function releaseControls({
  template = gate2Template(),
  rolesTemplate = deploymentRolesTemplate()
} = {}) {
  const resources = __test.resourcesForCreate(template);
  const resourceInventorySha256 = sha256(__test.canonicalBytes(resources));
  return {
    schemaVersion: "prooftoact.release-controls.v1",
    status: "REVIEWED_NOT_EXECUTED",
    approvalId: "123e4567-e89b-42d3-a456-426614174000",
    approvedBy: "BRIAN_SMITH",
    approvedAt: "2026-08-17T17:55:00.000Z",
    expiresAt: "2026-08-17T18:25:00.000Z",
    oneShot: true,
    artifactBucket: ARTIFACT_BUCKET,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    rolesTemplateSha256: prettyDigest(rolesTemplate),
    resourceInventorySha256,
    forecastStatus: "AVAILABLE",
    maximumApprovedUsd: 12,
    projectedTotalUsd: 1.25,
    partialFailureDisposition:
      "HOLD_RECONCILE_OR_TEARDOWN_NO_BLIND_RETRY",
    teardown: {
      deleteExactStack: "prooftoact-gate2",
      expectedResourceInventorySha256: resourceInventorySha256,
      judgingAccessThrough: "2026-09-15T23:59:00.000Z",
      teardownDeadline: "2026-09-16T00:30:00.000Z",
      residualCensusRequired: true
    }
  };
}

function input({
  template = gate2Template(),
  rolesTemplate = deploymentRolesTemplate(),
  build = validatedBuild(template),
  controls = releaseControls({ template, rolesTemplate })
} = {}) {
  const composition = compositionIdentities({ template, rolesTemplate });
  return {
    ...composition,
    artifactBucket: ARTIFACT_BUCKET,
    controlsNow: NOW,
    deploymentRolesTemplate: rolesTemplate,
    releaseControls: controls,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    validatedBuild: build,
    gate2Template: template
  };
}

function statement(role, sid) {
  return role.Properties.Policies[0].PolicyDocument.Statement.find(
    (candidate) => candidate.Sid === sid
  );
}

function actionList(policyStatement) {
  return Array.isArray(policyStatement.Action)
    ? policyStatement.Action
    : [policyStatement.Action];
}

function git(root, args) {
  return execFileSync("/usr/bin/git", args, {
    cwd: root,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin"
    },
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

function exactRepository(root, files) {
  fs.mkdirSync(root, { mode: 0o700, recursive: true });
  for (const [relativePath, bytes] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(target), { mode: 0o700, recursive: true });
    fs.writeFileSync(target, bytes, { mode: 0o600 });
  }
  git(root, ["init", "--initial-branch=main"]);
  git(root, ["remote", "add", "origin",
    "https://github.com/Flash-Bri/prooftoact.git"]);
  git(root, ["add", "--all"]);
  git(root, [
    "-c", "user.name=ProofToAct Test",
    "-c", "user.email=prooftoact-test@example.invalid",
    "commit", "--no-gpg-sign", "-m", "exact fixture"
  ]);
  return {
    commit: git(root, ["rev-parse", "HEAD"]),
    tree: git(root, ["rev-parse", "HEAD^{tree}"])
  };
}

test("release upload plan binds exact artifacts, roles, controls, and HOLD posture", () => {
  const template = gate2Template();
  const rolesTemplate = deploymentRolesTemplate();
  assert.equal(
    prettyDigest(rolesTemplate),
    __test.REVIEWED_DEPLOYMENT_ROLES_TEMPLATE_SHA256
  );
  const plan = buildReleaseUploadPlan(input({ template, rolesTemplate }));

  assert.equal(plan.status, "PREPARED_NOT_AUTHORIZED");
  assert.equal(plan.schemaVersion, "prooftoact.release-upload-plan.v2");
  assert.equal(plan.application.sourceCommit, SOURCE_COMMIT);
  assert.equal(plan.controlPlane.sourceCommit, CONTROL_PLANE_COMMIT);
  assert.notEqual(plan.application.identitySha256,
    plan.controlPlane.identitySha256);
  assert.equal(plan.stack.operation, "CREATE_CHANGE_SET_ONLY");
  assert.equal(plan.stack.directCreateStackAllowed, false);
  assert.equal(plan.stack.updateAllowed, false);
  assert.equal(plan.stack.deleteAllowedToDeploymentRole, false);
  assert.equal(plan.stack.probesEnabled, false);
  assert.equal(plan.stack.terminationProtectionRequired, true);
  assert.deepEqual(plan.stack.capabilities, ["CAPABILITY_NAMED_IAM"]);
  assert.equal(plan.costGate.maximumProjectedTotalUsd, 12);
  assert.equal(plan.costGate.projectedTotalUsd, 1.25);
  assert.equal(plan.costGate.forecastUnavailableDisposition, "HOLD");
  assert.equal(plan.costGate.currentResourceCensusRequired, true);
  assert.equal(
    plan.executionGate.status,
    "HOLD_RUNTIME_AUTHORITY_AND_RECEIPTS_REQUIRED"
  );
  assert.equal(plan.executionGate.requiredChangeSetType, "CREATE");
  assert.equal(
    plan.executionGate.requiredIndependentArtifacts.includes(
      "SEPARATE_SCOPED_TEARDOWN_PRINCIPAL_AND_KEEP_ALIVE_CONTRACT"
    ),
    true
  );
  assert.equal(plan.uploads.length, 6);
  assert.equal(
    plan.uploads.every((artifact) =>
      artifact.s3Key.startsWith(`gate2/${SOURCE_COMMIT}/`) &&
      artifact.uploadContract === "PUT_ONCE_THEN_READ_BACK_EXACT_VERSION"
    ),
    true
  );
  assert.deepEqual(
    plan.primaryRuntime.iamRoles,
    [...__test.PRIMARY_ROLE_LOGICAL_IDS].sort()
  );
  assert.deepEqual(
    plan.primaryRuntime.lambdaFunctions,
    [...__test.PRIMARY_LAMBDA_LOGICAL_IDS].sort()
  );
  assert.equal(
    plan.createResourceInventory.some(({ logicalId }) =>
      logicalId.endsWith("ProbeFunction")
    ),
    false
  );
  assert.equal(plan.deploymentRoles.preparationCanExecuteChangeSet, false);
  assert.equal(
    plan.deploymentRoles.cloudFormationPermissionsBoundarySourceOwned,
    true
  );
  assert.match(
    plan.deploymentRoles.cloudFormationPermissionsBoundaryPolicySha256,
    /^[0-9a-f]{64}$/u
  );
  assert.equal(
    plan.deploymentRoles.cloudFormationPermissionsBoundaryPolicySha256,
    plan.authoritySeparation.cloudFormationPermissionsBoundary.policySha256
  );
  assert.equal(
    plan.deploymentRoles
      .cloudFormationPermissionsBoundaryAllowInventorySha256,
    plan.authoritySeparation.cloudFormationPermissionsBoundary
      .allowInventorySha256
  );
  assert.equal(plan.deploymentRoles.executionCanCreateChangeSet, false);
  assert.equal(plan.deploymentRoles.deploymentCanAssumeDrillOrEvidenceRoles, false);
  assert.equal(plan.deploymentRoles.liveDrillCanDeployOrWriteArtifacts, false);
  assert.equal(
    plan.deploymentRoles.independentEvidenceCanMutateOrAssumeRoles,
    false
  );
  assert.equal(
    plan.deploymentRoles.releaseControlTableRetainedOutsideApplicationTeardown,
    true
  );
  assert.equal(
    plan.deploymentRoles.teardownCanDeployInvokeOrAssumeRoles,
    false
  );
  assert.equal(
    plan.deploymentRoles.terminalizerCanDispatchReserveBudgetOrDeleteState,
    false
  );
  assert.equal(plan.authoritySeparation.controlTable.name,
    "prooftoact-release-controller");
  assert.equal(plan.authoritySeparation.controlTable.deletionPolicy, "Retain");
  assert.equal(plan.authoritySeparation.controlTable.deletionProtectionEnabled,
    true);
  assert.equal(plan.authoritySeparation.independentEvidenceRoleLogicalId,
    "ReleaseEvidenceRole");
  assert.equal(plan.authoritySeparation.evidenceOperatorParameterMustReference,
    "LiveDrillOperatorRoleArn");
  assert.equal(plan.teardownGate.residualCensusRequired, true);
  assert.equal(plan.logEvidence.retentionDays, 7);
  assert.equal(plan.logEvidence.immutableExportRequired, true);
  assert.match(plan.createResourceInventorySha256, /^[0-9a-f]{64}$/u);
  assert.match(plan.planSha256, /^[0-9a-f]{64}$/u);
});

test("source composition binds distinct control/application repositories and rejects aliases", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pta-composition-"));
  fs.chmodSync(directory, 0o700);
  const controlPlaneRoot = path.join(directory, "control-plane");
  const applicationRoot = path.join(directory, "application");
  const copiedControlRoot = path.join(directory, "copied-control");
  try {
    const controlPlane = exactRepository(controlPlaneRoot, {
      [__test.CONTROL_PLANE_CONTROLLER_PATH]: fs.readFileSync(path.join(
        ROOT,
        __test.CONTROL_PLANE_CONTROLLER_PATH
      )),
      [__test.CONTROL_PLANE_PREPARER_PATH]: fs.readFileSync(path.join(
        ROOT,
        __test.CONTROL_PLANE_PREPARER_PATH
      )),
      [__test.CONTROL_PLANE_ROLES_TEMPLATE_PATH]: fs.readFileSync(path.join(
        ROOT,
        __test.CONTROL_PLANE_ROLES_TEMPLATE_PATH
      ))
    });
    const application = exactRepository(applicationRoot, {
      [__test.APPLICATION_TEMPLATE_PATH]: fs.readFileSync(path.join(
        ROOT,
        __test.APPLICATION_TEMPLATE_PATH
      ))
    });
    const options = {
      applicationRoot,
      controlPlaneRoot,
      entrypointFile: path.join(
        controlPlaneRoot,
        __test.CONTROL_PLANE_PREPARER_PATH
      ),
      entrypointRelativePath: __test.CONTROL_PLANE_PREPARER_PATH,
      expectedApplicationCommit: application.commit,
      expectedApplicationTree: application.tree,
      expectedControlPlaneCommit: controlPlane.commit,
      expectedControlPlaneTree: controlPlane.tree
    };
    const composition = validateReleaseSourceComposition(options);
    assert.equal(composition.application.sourceCommit, application.commit);
    assert.equal(composition.controlPlane.sourceCommit, controlPlane.commit);
    assert.notEqual(
      composition.application.identitySha256,
      composition.controlPlane.identitySha256
    );

    assert.throws(
      () => validateReleaseSourceComposition({
        ...options,
        applicationRoot: controlPlaneRoot
      }),
      /RELEASE_PLAN_SOURCE_COMPOSITION_REJECTED/u
    );
    assert.throws(
      () => validateReleaseSourceComposition({
        ...options,
        applicationRoot: controlPlaneRoot,
        controlPlaneRoot: applicationRoot,
        entrypointFile: path.join(
          applicationRoot,
          __test.CONTROL_PLANE_PREPARER_PATH
        )
      }),
      /RELEASE_PLAN_SOURCE_COMPOSITION_REJECTED/u
    );

    fs.cpSync(controlPlaneRoot, copiedControlRoot, { recursive: true });
    assert.throws(
      () => validateReleaseSourceComposition({
        ...options,
        applicationRoot: copiedControlRoot
      }),
      /RELEASE_PLAN_SOURCE_COMPOSITION_REJECTED/u
    );

    fs.appendFileSync(
      path.join(applicationRoot, __test.APPLICATION_TEMPLATE_PATH),
      " \n"
    );
    assert.throws(
      () => validateReleaseSourceComposition(options),
      /RELEASE_PLAN_SOURCE_COMPOSITION_REJECTED/u
    );
  } finally {
    fs.rmSync(directory, { force: true, recursive: true });
  }
});

test("preparer CLI requires explicit control-plane and application identities", () => {
  const values = {
    "--application-root": "/tmp/frozen-application",
    "--artifact-bucket": ARTIFACT_BUCKET,
    "--build-receipt": "/tmp/build.json",
    "--control-plane-root": "/tmp/control-plane",
    "--expected-application-commit": SOURCE_COMMIT,
    "--expected-application-tree": TREE_DIGEST,
    "--expected-control-plane-commit": CONTROL_PLANE_COMMIT,
    "--expected-control-plane-tree": CONTROL_PLANE_TREE,
    "--output": "/tmp/plan.json",
    "--release-controls": "/tmp/controls.json"
  };
  const parsed = __test.parseArguments(Object.entries(values).flat());
  assert.deepEqual(parsed, values);
  assert.throws(
    () => __test.parseArguments([
      "--artifact-bucket", ARTIFACT_BUCKET,
      "--build-receipt", "/tmp/build.json",
      "--expected-commit", SOURCE_COMMIT,
      "--expected-tree", TREE_DIGEST,
      "--output", "/tmp/plan.json",
      "--release-controls", "/tmp/controls.json"
    ]),
    /RELEASE_PLAN_ARGUMENTS_REJECTED/u
  );
});

test("release upload plan rejects gate2 template digest drift", () => {
  const template = gate2Template();
  const build = validatedBuild(template);
  build.gate2Template.templateDigest = "0".repeat(64);
  assert.throws(
    () => buildReleaseUploadPlan(input({ template, build })),
    /RELEASE_PLAN_TEMPLATE_DIGEST_REJECTED/u
  );
});

test("release upload plan rejects deployment-role template digest drift", () => {
  const rolesTemplate = deploymentRolesTemplate();
  rolesTemplate.Description += " drift";
  assert.throws(
    () => buildReleaseUploadPlan(input({ rolesTemplate })),
    /RELEASE_PLAN_ROLE_TEMPLATE_DIGEST_REJECTED/u
  );
});

test("release upload plan rejects injected NAT or any extra primary resource", () => {
  const template = gate2Template();
  template.Resources.InjectedNatGateway = {
    Type: "AWS::EC2::NatGateway",
    Properties: { SubnetId: "subnet-not-reviewed" }
  };
  assert.throws(
    () => buildReleaseUploadPlan(input({ template })),
    /RELEASE_PLAN_TEMPLATE_DIGEST_REJECTED/u
  );
});

test("release upload plan rejects wildcard Action or Resource in primary IAM", () => {
  const wildcardAction = gate2Template();
  const agentAllow = wildcardAction.Resources.AgentRole.Properties.Policies[0]
    .PolicyDocument.Statement.find((candidate) => candidate.Effect === "Allow");
  agentAllow.Action = "*";
  agentAllow.Resource = "*";
  assert.throws(
    () => buildReleaseUploadPlan(input({ template: wildcardAction })),
    /RELEASE_PLAN_PRIMARY_POLICY_WILDCARD_REJECTED/u
  );

  const wildcardResource = gate2Template();
  const scopedAllow = wildcardResource.Resources.AgentRole.Properties.Policies[0]
    .PolicyDocument.Statement.find((candidate) => candidate.Effect === "Allow");
  scopedAllow.Resource = "*";
  assert.throws(
    () => buildReleaseUploadPlan(input({ template: wildcardResource })),
    /RELEASE_PLAN_TEMPLATE_DIGEST_REJECTED/u
  );
});

test("release preparer cannot execute, invoke, or cross into drill roles", () => {
  for (const forbiddenAction of [
    "cloudformation:ExecuteChangeSet",
    "lambda:InvokeFunction",
    "sts:AssumeRole"
  ]) {
    const rolesTemplate = deploymentRolesTemplate();
    const prepare = statement(
      rolesTemplate.Resources.ReleaseDeploymentRole,
      "WriteExactArtifactPrefix"
    );
    prepare.Action = [...actionList(prepare), forbiddenAction];
    assert.throws(
      () => buildReleaseUploadPlan(input({ rolesTemplate })),
      /RELEASE_PLAN_(?:DEPLOYMENT_ROLE_ESCALATION|EXECUTION_ROLE_SEPARATION)_REJECTED/u
    );
  }
});

test("CloudFormation service trust, boundary, and policy bytes cannot drift", () => {
  const exact = deploymentRolesTemplate();
  assert.equal(
    Object.hasOwn(exact.Parameters, "CloudFormationPermissionsBoundaryArn"),
    false
  );
  assert.equal(
    exact.Resources.CloudFormationPermissionsBoundary.Type,
    "AWS::IAM::ManagedPolicy"
  );
  assert.equal(
    exact.Resources.CloudFormationPermissionsBoundary.Properties
      .ManagedPolicyName,
    "ProofToActGate2CloudFormationBoundary"
  );
  assert.deepEqual(
    exact.Resources.CloudFormationServiceRole.Properties.PermissionsBoundary,
    { Ref: "CloudFormationPermissionsBoundary" }
  );
  const boundaryStatements = exact.Resources.CloudFormationPermissionsBoundary
    .Properties.PolicyDocument.Statement;
  const inlineStatements = exact.Resources.CloudFormationServiceRole.Properties
    .Policies[0].PolicyDocument.Statement;
  const boundaryAllows = boundaryStatements.filter(({ Effect }) =>
    Effect === "Allow");
  const inlineAllows = inlineStatements.filter(({ Effect }) =>
    Effect === "Allow");
  assert.deepEqual(boundaryAllows, inlineAllows);
  assert.equal(boundaryAllows.some((item) => actionList(item).some((action) =>
    action === "*" || action.endsWith(":*") ||
      action.startsWith("organizations:") || action.startsWith("account:") ||
      action === "sts:AssumeRole")), false);
  assert.deepEqual(
    exact.Outputs.CloudFormationPermissionsBoundaryArn.Value,
    { Ref: "CloudFormationPermissionsBoundary" }
  );

  const noBoundary = deploymentRolesTemplate();
  delete noBoundary.Resources.CloudFormationServiceRole.Properties
    .PermissionsBoundary;
  assert.throws(
    () => buildReleaseUploadPlan(input({ rolesTemplate: noBoundary })),
    /RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED/u
  );

  const missingBoundaryResource = deploymentRolesTemplate();
  delete missingBoundaryResource.Resources.CloudFormationPermissionsBoundary;
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      missingBoundaryResource,
      gate2Template()
    ),
    /RELEASE_PLAN_(?:ROLE_TEMPLATE|PERMISSIONS_BOUNDARY)_REJECTED/u
  );

  const expandedBoundary = deploymentRolesTemplate();
  expandedBoundary.Resources.CloudFormationPermissionsBoundary.Properties
    .PolicyDocument.Statement.push({
      Sid: "InjectedAdmin",
      Effect: "Allow",
      Action: "iam:CreateUser",
      Resource: "*"
    });
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(expandedBoundary,
      gate2Template()),
    /RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED/u
  );

  const missingRequiredAllow = deploymentRolesTemplate();
  missingRequiredAllow.Resources.CloudFormationPermissionsBoundary.Properties
    .PolicyDocument.Statement = missingRequiredAllow.Resources
      .CloudFormationPermissionsBoundary.Properties.PolicyDocument.Statement
      .filter(({ Sid }) => Sid !== "ManageExactAlarms");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(missingRequiredAllow,
      gate2Template()),
    /RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED/u
  );

  const oversizedBoundary = deploymentRolesTemplate();
  oversizedBoundary.Resources.CloudFormationPermissionsBoundary.Properties
    .PolicyDocument.Statement.push({
      Sid: `Oversized${"X".repeat(6_200)}`,
      Effect: "Deny",
      Action: "iam:CreateUser",
      Resource: "*"
    });
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(oversizedBoundary,
      gate2Template()),
    /RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED/u
  );

  const wrongTrust = deploymentRolesTemplate();
  wrongTrust.Resources.CloudFormationServiceRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.ArnLike[
      "aws:SourceArn"
    ]["Fn::Sub"] =
      "arn:${AWS::Partition}:cloudformation:us-east-1:${AWS::AccountId}:stack/*";
  assert.throws(
    () => buildReleaseUploadPlan(input({ rolesTemplate: wrongTrust })),
    /RELEASE_PLAN_PERMISSIONS_BOUNDARY_REJECTED/u
  );

  const broadenedPolicy = deploymentRolesTemplate();
  statement(
    broadenedPolicy.Resources.CloudFormationServiceRole,
    "ManageExactStackRoles"
  ).Resource = "*";
  assert.throws(
    () => buildReleaseUploadPlan(input({ rolesTemplate: broadenedPolicy })),
    /RELEASE_PLAN_(?:ALLOW_WILDCARD|PERMISSIONS_BOUNDARY|ROLE_TEMPLATE_DIGEST)_REJECTED/u
  );
});

test("release controller table is exact, retained, encrypted, and protected", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const table = rolesTemplate.Resources.ReleaseControlTable;
  assert.equal(table.Type, "AWS::DynamoDB::Table");
  assert.equal(table.DeletionPolicy, "Retain");
  assert.equal(table.UpdateReplacePolicy, "Retain");
  assert.equal(table.Properties.TableName, "prooftoact-release-controller");
  assert.equal(table.Properties.BillingMode, "PAY_PER_REQUEST");
  assert.equal(table.Properties.DeletionProtectionEnabled, true);
  assert.deepEqual(table.Properties.AttributeDefinitions, [
    { AttributeName: "pk", AttributeType: "S" }
  ]);
  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: "pk", KeyType: "HASH" }
  ]);
  assert.deepEqual(table.Properties.SSESpecification, {
    KMSMasterKeyId: "alias/aws/dynamodb",
    SSEEnabled: true,
    SSEType: "KMS"
  });
  assert.equal(Object.hasOwn(table.Properties, "TimeToLiveSpecification"), false);
  assert.equal(Object.hasOwn(table.Properties, "StreamSpecification"), false);
  assert.equal(
    rolesTemplate.Outputs.ReleaseControlTableArn.Value["Fn::GetAtt"][0],
    "ReleaseControlTable"
  );
  assert.equal(
    rolesTemplate.Outputs.ReleaseControlTableName.Value.Ref,
    "ReleaseControlTable"
  );

  for (const mutate of [
    (value) => { value.DeletionPolicy = "Delete"; },
    (value) => { value.UpdateReplacePolicy = "Delete"; },
    (value) => { value.Properties.BillingMode = "PROVISIONED"; },
    (value) => { value.Properties.DeletionProtectionEnabled = false; },
    (value) => { value.Properties.KeySchema[0].AttributeName = "approvalId"; },
    (value) => {
      value.Properties.SSESpecification.KMSMasterKeyId =
        "arn:aws:kms:us-east-1:111111111111:key/" +
        "00000000-0000-0000-0000-000000000000";
    },
    (value) => {
      value.Properties.TimeToLiveSpecification = {
        AttributeName: "expiresAt",
        Enabled: true
      };
    }
  ]) {
    const drift = deploymentRolesTemplate();
    mutate(drift.Resources.ReleaseControlTable);
    assert.throws(
      () => validateReleaseDeploymentRoleTemplate(drift, gate2Template()),
      /RELEASE_PLAN_CONTROL_TABLE_REJECTED/u
    );
  }
});

test("every GitHub role binds supported claims and requires runtime workflow-ref", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const expected = {
    LiveDrillOperatorRole: {
      environment: "aws-live-drill",
      workflows: ["ProofToAct Bounded Live Drill"],
      workflowFiles: ["prooftoact-bounded-live-drill.yml"]
    },
    ReleaseDeploymentRole: {
      environment: "aws-release-deployment",
      workflows: ["ProofToAct Release Candidate"],
      workflowFiles: ["prooftoact-release-candidate.yml"]
    },
    ReleaseCoordinatorRole: {
      environment: "aws-release-coordination",
      workflows: [
        "ProofToAct Release Candidate",
        "ProofToAct Execute Approved Release",
        "ProofToAct Bounded Live Drill",
        "ProofToAct Read Only Release Evidence",
        "ProofToAct Approved Teardown"
      ],
      workflowFiles: [
        "prooftoact-release-candidate.yml",
        "prooftoact-execute-approved-release.yml",
        "prooftoact-bounded-live-drill.yml",
        "prooftoact-read-only-release-evidence.yml",
        "prooftoact-approved-teardown.yml"
      ]
    },
    ReleaseEvidenceRole: {
      environment: "aws-release-evidence",
      workflows: ["ProofToAct Read Only Release Evidence"],
      workflowFiles: ["prooftoact-read-only-release-evidence.yml"]
    },
    ReleaseExecutionRole: {
      environment: "aws-release-execution",
      workflows: ["ProofToAct Execute Approved Release"],
      workflowFiles: ["prooftoact-execute-approved-release.yml"]
    },
    ReleaseTeardownRole: {
      environment: "aws-release-teardown",
      workflows: ["ProofToAct Approved Teardown"],
      workflowFiles: ["prooftoact-approved-teardown.yml"]
    },
    ReleaseTerminalizerRole: {
      environment: "aws-release-terminalization",
      workflows: ["ProofToAct Terminalize Expired Release"],
      workflowFiles: ["prooftoact-terminalize-expired-release.yml"]
    }
  };
  for (const [logicalId, { environment, workflowFiles, workflows }] of
    Object.entries(expected)) {
    const equals = rolesTemplate.Resources[logicalId].Properties
      .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
    assert.equal(equals["token.actions.githubusercontent.com:repository_id"],
      "1317716765");
    assert.equal(
      equals["token.actions.githubusercontent.com:repository_owner_id"],
      "252500266"
    );
    assert.equal(equals["token.actions.githubusercontent.com:ref"],
      "refs/heads/main");
    assert.equal(equals["token.actions.githubusercontent.com:environment"],
      environment);
    assert.deepEqual(
      equals["token.actions.githubusercontent.com:workflow"],
      logicalId === "ReleaseCoordinatorRole" ? workflows : workflows[0]
    );
    assert.equal(
      Object.hasOwn(equals, "token.actions.githubusercontent.com:workflow_ref"),
      false
    );
    const requiredRefs = workflowFiles.map((workflowFile) =>
      `Flash-Bri/prooftoact/.github/workflows/${workflowFile}@refs/heads/main`
    );
    assert.deepEqual(
      buildReleaseUploadPlan(input()).authoritySeparation
        .requiredRuntimeWorkflowRefs[logicalId],
      logicalId === "ReleaseCoordinatorRole" ? requiredRefs : requiredRefs[0]
    );

    const drift = deploymentRolesTemplate();
    const driftWorkflow = drift.Resources[logicalId].Properties
      .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
    if (logicalId === "ReleaseCoordinatorRole") {
      driftWorkflow["token.actions.githubusercontent.com:workflow"][0] =
        "ProofToAct Terminalize Expired Release";
    } else {
      driftWorkflow["token.actions.githubusercontent.com:workflow"] +=
        " drift";
    }
    assert.throws(
      () => validateReleaseDeploymentRoleTemplate(drift, gate2Template()),
      /RELEASE_PLAN_OIDC_TRUST_REJECTED/u
    );

    const unsupported = deploymentRolesTemplate();
    unsupported.Resources[logicalId].Properties.AssumeRolePolicyDocument
      .Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:workflow_ref"
      ] = `Flash-Bri/prooftoact/.github/workflows/${workflowFiles[0]}@refs/heads/main`;
    assert.throws(
      () => validateReleaseDeploymentRoleTemplate(unsupported, gate2Template()),
      /RELEASE_PLAN_OIDC_TRUST_REJECTED/u
    );
  }

  for (const workflows of [
    expected.ReleaseCoordinatorRole.workflows.slice(0, -1),
    [
      ...expected.ReleaseCoordinatorRole.workflows,
      "ProofToAct Terminalize Expired Release"
    ],
    [
      ...expected.ReleaseCoordinatorRole.workflows.slice(0, -1),
      "ProofToAct Execute Approved Release"
    ]
  ]) {
    const drift = deploymentRolesTemplate();
    drift.Resources.ReleaseCoordinatorRole.Properties
      .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
        "token.actions.githubusercontent.com:workflow"
      ] = workflows;
    assert.throws(
      () => validateReleaseDeploymentRoleTemplate(drift, gate2Template()),
      /RELEASE_PLAN_OIDC_TRUST_REJECTED/u
    );
  }
});

test("controller table policies are exact-key scoped and never delete state", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const roleIds = [
    "ReleaseDeploymentRole",
    "ReleaseCoordinatorRole",
    "ReleaseExecutionRole",
    "LiveDrillOperatorRole",
    "ReleaseEvidenceRole",
    "ReleaseTeardownRole",
    "ReleaseTerminalizerRole"
  ];
  for (const logicalId of roleIds) {
    const statements = rolesTemplate.Resources[logicalId].Properties.Policies[0]
      .PolicyDocument.Statement;
    const allows = statements.filter(({ Effect }) => Effect === "Allow");
    assert.equal(
      allows.some((candidate) => actionList(candidate).includes(
        "dynamodb:DeleteItem"
      )),
      false
    );
    for (const candidate of allows.filter((value) => actionList(value)
      .some((action) => action.startsWith("dynamodb:")))) {
      assert.deepEqual(candidate.Resource, {
        "Fn::GetAtt": ["ReleaseControlTable", "Arn"]
      });
      if (Object.values(candidate.Condition ?? {}).some((operator) =>
        operator && Object.hasOwn(operator, "dynamodb:LeadingKeys"))) {
        assert.equal(
          candidate.Condition.Null["dynamodb:LeadingKeys"],
          "false"
        );
      }
    }
  }

  const coordinator = rolesTemplate.Resources.ReleaseCoordinatorRole;
  const coordinatorDynamoAllows = coordinator.Properties.Policies[0]
    .PolicyDocument.Statement.filter(({ Effect }) => Effect === "Allow")
    .flatMap(actionList)
    .filter((action) => action.startsWith("dynamodb:"))
    .sort();
  assert.deepEqual(coordinatorDynamoAllows, [
    "dynamodb:DescribeTable",
    "dynamodb:GetItem",
    "dynamodb:ListTagsOfResource",
    "dynamodb:TransactWriteItems",
    "dynamodb:UpdateItem"
  ].sort());
  for (const logicalId of [
    "ReleaseDeploymentRole",
    "ReleaseExecutionRole",
    "LiveDrillOperatorRole",
    "ReleaseEvidenceRole",
    "ReleaseTeardownRole"
  ]) {
    const role = rolesTemplate.Resources[logicalId];
    const statements = role.Properties.Policies[0].PolicyDocument.Statement;
    const allowedDynamo = statements.filter(({ Effect }) => Effect === "Allow")
      .flatMap(actionList).filter((action) => action.startsWith("dynamodb:"));
    assert.deepEqual(allowedDynamo.sort(), [
      "dynamodb:DescribeTable",
      "dynamodb:GetItem",
      "dynamodb:ListTagsOfResource"
    ].sort());
    const effectRead = statement(role, "ReadExactReleaseControlItems");
    assert.equal(
      effectRead.Condition["ForAllValues:StringLike"]
        ["dynamodb:LeadingKeys"],
      "EFFECT#*"
    );
    assert.equal(effectRead.Condition.Null["dynamodb:LeadingKeys"], "false");
    assert.equal(allowedDynamo.includes("dynamodb:UpdateItem"), false);
    assert.equal(allowedDynamo.includes("dynamodb:TransactWriteItems"), false);
  }

  const terminalizer = rolesTemplate.Resources.ReleaseTerminalizerRole;
  const terminalize = statement(
    terminalizer,
    "ReadAndTerminalizeExactEffectItems"
  );
  assert.deepEqual(actionList(terminalize).sort(), [
    "dynamodb:GetItem", "dynamodb:UpdateItem"
  ]);
  assert.equal(
    terminalize.Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"],
    "EFFECT#*"
  );
  assert.equal(
    terminalize.Condition.Null["dynamodb:LeadingKeys"],
    "false"
  );
  const terminalizerAllows = terminalizer.Properties.Policies[0]
    .PolicyDocument.Statement.filter(({ Effect }) => Effect === "Allow")
    .flatMap(actionList);
  assert.equal(terminalizerAllows.includes("dynamodb:TransactWriteItems"), false);
  assert.equal(terminalizerAllows.includes("sts:AssumeRole"), false);
  assert.equal(terminalizerAllows.some((action) =>
    action.startsWith("lambda:Invoke")), false);
});

test("coordinator finalizer is store-write and exact provider-readback only", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const coordinator = rolesTemplate.Resources.ReleaseCoordinatorRole;
  const allows = coordinator.Properties.Policies[0].PolicyDocument.Statement
    .filter(({ Effect }) => Effect === "Allow").flatMap(actionList);
  assert.equal(allows.includes("dynamodb:TransactWriteItems"), true);
  assert.equal(allows.includes("cloudformation:DescribeStacks"), true);
  assert.equal(allows.includes("s3:GetObjectVersion"), true);
  assert.equal(allows.includes("lambda:GetFunctionConfiguration"), true);
  assert.equal(allows.includes("iam:SimulatePrincipalPolicy"), true);
  assert.equal(allows.includes("logs:FilterLogEvents"), true);
  assert.equal(allows.includes("apigateway:GET"), true);
  assert.equal(allows.some((action) =>
    action.startsWith("cloudformation:Create") ||
      action.startsWith("cloudformation:Delete") ||
      action.startsWith("cloudformation:Execute") ||
      action.startsWith("cloudformation:Update") ||
      action.startsWith("lambda:Invoke") ||
      action.startsWith("s3:Put") ||
      action.startsWith("s3:Delete") ||
      action.startsWith("secretsmanager:") ||
      action.startsWith("kms:") ||
      action === "sts:AssumeRole"), false);
  assert.equal(
    Buffer.byteLength(JSON.stringify(
      coordinator.Properties.Policies[0].PolicyDocument
    ), "utf8") <= 10_240,
    true
  );
  for (const sid of [
    "ReadExactReleaseStack",
    "ReadOwnDriftDetectionStatus",
    "ReadGateTwoHttpApiDeployment",
    "ReadExactLambdaDeployment",
    "ReadLambdaEventSourceCensus",
    "ReadExactReleaseLogs",
    "ReadExactReleaseRoles",
    "ReadAndSimulateExactBootstrapRoles",
    "ReadExactPermissionsBoundary"
  ]) {
    assert.deepEqual(
      statement(coordinator, sid),
      statement(rolesTemplate.Resources.ReleaseEvidenceRole, sid)
    );
  }
  for (const sid of ["ReadExactArtifactVersions", "ListExactArtifactPrefix"]) {
    assert.deepEqual(
      statement(coordinator, sid),
      statement(rolesTemplate.Resources.ReleaseDeploymentRole, sid)
    );
  }
  assert.equal(
    rolesTemplate.Outputs.ReleaseCoordinatorRoleArn.Value["Fn::GetAtt"][0],
    "ReleaseCoordinatorRole"
  );
  assert.equal(
    buildReleaseUploadPlan(input()).authoritySeparation
      .teardownPhysicalStackBindingRequired,
    true
  );

  for (const logicalId of [
    "ReleaseDeploymentRole",
    "ReleaseExecutionRole",
    "LiveDrillOperatorRole",
    "ReleaseEvidenceRole",
    "ReleaseTeardownRole"
  ]) {
    const drift = deploymentRolesTemplate();
    drift.Resources[logicalId].Properties.Policies[0].PolicyDocument.Statement
      .unshift({
        Sid: "InjectedControllerBypass",
        Effect: "Allow",
        Action: "dynamodb:UpdateItem",
        Resource: { "Fn::GetAtt": ["ReleaseControlTable", "Arn"] },
        Condition: {
          "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": "EFFECT#*"
          },
          Null: { "dynamodb:LeadingKeys": "false" }
        }
      });
    assert.throws(
      () => validateReleaseDeploymentRoleTemplate(drift, gate2Template()),
      /RELEASE_PLAN_PROVIDER_STORE_SEPARATION_REJECTED/u
    );
  }

  const providerCapability = deploymentRolesTemplate();
  statement(
    providerCapability.Resources.ReleaseCoordinatorRole,
    "CoordinateExactReleaseControlItems"
  ).Action.push("cloudformation:ExecuteChangeSet");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      providerCapability,
      gate2Template()
    ),
    /RELEASE_PLAN_(?:CONTROL_TABLE_POLICY|COORDINATOR_ROLE_SEPARATION)_REJECTED/u
  );

  const readbackExpansion = deploymentRolesTemplate();
  statement(
    readbackExpansion.Resources.ReleaseCoordinatorRole,
    "ReadExactArtifactVersions"
  ).Action.push("s3:GetBucketPolicy");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      readbackExpansion,
      gate2Template()
    ),
    /RELEASE_PLAN_COORDINATOR_ROLE_SEPARATION_REJECTED/u
  );

  const missingMutationDeny = deploymentRolesTemplate();
  statement(
    missingMutationDeny.Resources.ReleaseCoordinatorRole,
    "DenyProviderMutationAndAuthorityCapabilities"
  ).Action = actionList(statement(
    missingMutationDeny.Resources.ReleaseCoordinatorRole,
    "DenyProviderMutationAndAuthorityCapabilities"
  )).filter((action) => action !== "lambda:Invoke*");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      missingMutationDeny,
      gate2Template()
    ),
    /RELEASE_PLAN_ROLE_TEMPLATE_REJECTED/u
  );

  const oversizedCoordinator = deploymentRolesTemplate();
  oversizedCoordinator.Resources.ReleaseCoordinatorRole.Properties
    .Policies[0].PolicyDocument.Statement.push({
      Sid: `Oversized${"X".repeat(10_300)}`,
      Effect: "Deny",
      Action: "s3:PutObject",
      Resource: "*"
    });
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      oversizedCoordinator,
      gate2Template()
    ),
    /RELEASE_PLAN_COORDINATOR_ROLE_SEPARATION_REJECTED/u
  );
});

test("evidence role has the exact frozen attestation read inventory only", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const evidence = rolesTemplate.Resources.ReleaseEvidenceRole;
  assert.deepEqual(actionList(statement(evidence,
    "ReadExactReleaseStack")).sort(), [
    "cloudformation:DescribeChangeSet",
    "cloudformation:DescribeStackEvents",
    "cloudformation:DescribeStackResourceDrifts",
    "cloudformation:DescribeStackResources",
    "cloudformation:DescribeStacks",
    "cloudformation:DetectStackDrift",
    "cloudformation:GetTemplate"
  ].sort());
  assert.deepEqual(actionList(statement(evidence,
    "ReadExactLambdaDeployment")).sort(), [
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
  ].sort());
  assert.equal(actionList(statement(evidence,
    "ReadGateTwoHttpApiDeployment")).join("\n"), "apigateway:GET");
  assert.equal(actionList(statement(evidence,
    "ReadLambdaEventSourceCensus")).join("\n"),
  "lambda:ListEventSourceMappings");
  const allows = evidence.Properties.Policies[0].PolicyDocument.Statement
    .filter(({ Effect }) => Effect === "Allow").flatMap(actionList);
  assert.equal(allows.some((action) =>
    action === "sts:AssumeRole" || action.startsWith("lambda:Invoke") ||
      action.startsWith("cloudformation:Delete") ||
      action.startsWith("cloudformation:Execute") ||
      action.startsWith("cloudformation:Update") ||
      action === "dynamodb:UpdateItem"), false);
});

test("preparer and evidence independently read back every bootstrap role and boundary", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const expectedRoleResources = [
    { "Fn::GetAtt": ["CloudFormationServiceRole", "Arn"] },
    {
      "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" +
        "ProofToActReleaseDeployment"
    },
    {
      "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" +
        "ProofToActReleaseCoordinator"
    },
    { "Fn::GetAtt": ["ReleaseExecutionRole", "Arn"] },
    { "Fn::GetAtt": ["LiveDrillOperatorRole", "Arn"] },
    {
      "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" +
        "ProofToActReleaseEvidence"
    },
    { "Fn::GetAtt": ["ReleaseTeardownRole", "Arn"] },
    { "Fn::GetAtt": ["ReleaseTerminalizerRole", "Arn"] }
  ];
  for (const logicalId of [
    "ReleaseDeploymentRole",
    "ReleaseCoordinatorRole",
    "ReleaseEvidenceRole"
  ]) {
    const role = rolesTemplate.Resources[logicalId];
    assert.equal(role.Properties.RoleName,
      `ProofToAct${logicalId.replace(/Role$/u, "")}`);
    assert.equal(Object.hasOwn(role.Properties, "Path"), false);
    const readback = statement(role, "ReadAndSimulateExactBootstrapRoles");
    assert.deepEqual(actionList(readback).sort(), [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:ListRoleTags",
      "iam:SimulatePrincipalPolicy"
    ].sort());
    assert.deepEqual(readback.Resource, expectedRoleResources);
    assert.deepEqual(
      statement(role, "ReadExactPermissionsBoundary").Resource,
      { Ref: "CloudFormationPermissionsBoundary" }
    );
  }

  const missingRole = deploymentRolesTemplate();
  statement(missingRole.Resources.ReleaseEvidenceRole,
    "ReadAndSimulateExactBootstrapRoles").Resource.pop();
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(missingRole, gate2Template()),
    /RELEASE_PLAN_IAM_READBACK_REJECTED/u
  );
});

test("bootstrap CloudFormation resource dependency graph is acyclic", () => {
  assertAcyclicResourceGraph(deploymentRolesTemplate());

  const cyclic = deploymentRolesTemplate();
  statement(cyclic.Resources.ReleaseDeploymentRole,
    "ReadAndSimulateExactBootstrapRoles").Resource[1] = {
    "Fn::GetAtt": ["ReleaseDeploymentRole", "Arn"]
  };
  assert.throws(
    () => assertAcyclicResourceGraph(cyclic),
    /circular CloudFormation dependency/u
  );
});

test("every LeadingKeys policy requires Null false", () => {
  const rolesTemplate = deploymentRolesTemplate();
  for (const role of Object.values(rolesTemplate.Resources)
    .filter(({ Type }) => Type === "AWS::IAM::Role")) {
    for (const item of role.Properties.Policies[0].PolicyDocument.Statement) {
      const hasLeadingKeys = Object.values(item.Condition ?? {})
        .some((operator) => operator &&
          Object.hasOwn(operator, "dynamodb:LeadingKeys"));
      if (hasLeadingKeys) {
        assert.equal(item.Condition.Null["dynamodb:LeadingKeys"], "false");
      }
    }
  }
  const drift = deploymentRolesTemplate();
  delete statement(drift.Resources.ReleaseCoordinatorRole,
    "CoordinateExactReleaseControlItems").Condition.Null;
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(drift, gate2Template()),
    /RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED/u
  );
});

test("evidence, teardown, and terminalizer privilege broadening fails closed", () => {
  const evidenceWrite = deploymentRolesTemplate();
  statement(
    evidenceWrite.Resources.ReleaseEvidenceRole,
    "ReadExactReleaseControlItems"
  ).Action = ["dynamodb:GetItem", "dynamodb:UpdateItem"];
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(evidenceWrite, gate2Template()),
    /RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED/u
  );

  const evidenceAssume = deploymentRolesTemplate();
  statement(
    evidenceAssume.Resources.ReleaseEvidenceRole,
    "ReadExactReleaseStack"
  ).Action.push("sts:AssumeRole");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(evidenceAssume, gate2Template()),
    /RELEASE_PLAN_(?:COORDINATOR|EVIDENCE)_ROLE_SEPARATION_REJECTED/u
  );

  const terminalizerBudget = deploymentRolesTemplate();
  statement(
    terminalizerBudget.Resources.ReleaseTerminalizerRole,
    "ReadAndTerminalizeExactEffectItems"
  ).Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] = [
    "BUDGET#*", "EFFECT#*"
  ];
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      terminalizerBudget,
      gate2Template()
    ),
    /RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED/u
  );

  const terminalizerTransaction = deploymentRolesTemplate();
  statement(
    terminalizerTransaction.Resources.ReleaseTerminalizerRole,
    "ReadAndTerminalizeExactEffectItems"
  ).Action.push("dynamodb:TransactWriteItems");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(
      terminalizerTransaction,
      gate2Template()
    ),
    /RELEASE_PLAN_CONTROL_TABLE_POLICY_REJECTED/u
  );

  const teardownWildcard = deploymentRolesTemplate();
  statement(
    teardownWildcard.Resources.ReleaseTeardownRole,
    "DeleteOnlyExactReleaseStack"
  ).Resource = "*";
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(teardownWildcard,
      gate2Template()),
    /RELEASE_PLAN_TEARDOWN_ROLE_SEPARATION_REJECTED/u
  );

  const teardownInvoke = deploymentRolesTemplate();
  statement(
    teardownInvoke.Resources.ReleaseTeardownRole,
    "DeleteOnlyExactReleaseStack"
  ).Action.push("lambda:InvokeFunction");
  assert.throws(
    () => validateReleaseDeploymentRoleTemplate(teardownInvoke,
      gate2Template()),
    /RELEASE_PLAN_TEARDOWN_ROLE_SEPARATION_REJECTED/u
  );
});

test("release executor cannot prepare artifacts, create changes, or assume runtime", () => {
  for (const forbiddenAction of [
    "s3:PutObject",
    "cloudformation:CreateChangeSet",
    "sts:AssumeRole",
    "lambda:InvokeFunction"
  ]) {
    const rolesTemplate = deploymentRolesTemplate();
    const execute = statement(
      rolesTemplate.Resources.ReleaseExecutionRole,
      "ExecuteNamedReviewedChangeSet"
    );
    execute.Action = [...actionList(execute), forbiddenAction];
    assert.throws(
      () => buildReleaseUploadPlan(input({ rolesTemplate })),
      /RELEASE_PLAN_EXECUTION_ROLE_SEPARATION_REJECTED/u
    );
  }
});

test("live drill principal cannot gain deployment or artifact-write authority", () => {
  const rolesTemplate = deploymentRolesTemplate();
  const assume = statement(
    rolesTemplate.Resources.LiveDrillOperatorRole,
    "AssumeOnlyInStackDrillAndInnerEvidenceRoles"
  );
  assume.Action = ["sts:AssumeRole", "s3:PutObject"];
  assert.throws(
    () => buildReleaseUploadPlan(input({ rolesTemplate })),
    /RELEASE_PLAN_ROLE_TEMPLATE_REJECTED/u
  );
});

test("explicit deny contracts cannot be removed from preparer, executor, or drill", () => {
  for (const [logicalId, sid, action] of [
    ["ReleaseDeploymentRole", "DenyRuntimeAndSecretUse", "execute-api:Invoke"],
    ["ReleaseDeploymentRole", "DenyDirectStackMutation", "cloudformation:ExecuteChangeSet"],
    ["ReleaseExecutionRole", "DenyPreparationDirectMutationAndRuntime", "s3:Put*"],
    ["LiveDrillOperatorRole", "DenyDirectProviderAndDeploymentCapabilities", "cloudformation:Execute*"]
  ]) {
    const rolesTemplate = deploymentRolesTemplate();
    const denied = statement(rolesTemplate.Resources[logicalId], sid);
    denied.Action = actionList(denied).filter((candidate) => candidate !== action);
    assert.throws(
      () => buildReleaseUploadPlan(input({ rolesTemplate })),
      /RELEASE_PLAN_ROLE_TEMPLATE_REJECTED/u
    );
  }
});

test("release plan rejects missing or unavailable cost controls", () => {
  assert.throws(
    () => buildReleaseUploadPlan(input({ controls: null })),
    /RELEASE_PLAN_CONTROLS_REJECTED/u
  );

  for (const mutate of [
    (controls) => { controls.forecastStatus = "UNAVAILABLE"; },
    (controls) => { controls.projectedTotalUsd = 13; },
    (controls) => { controls.maximumApprovedUsd = 13; },
    (controls) => { controls.oneShot = false; }
  ]) {
    const controls = releaseControls();
    mutate(controls);
    assert.throws(
      () => buildReleaseUploadPlan(input({ controls })),
      /RELEASE_PLAN_CONTROLS_REJECTED/u
    );
  }
});

test("release plan rejects missing or drifted teardown controls", () => {
  for (const mutate of [
    (controls) => { delete controls.teardown; },
    (controls) => { controls.teardown.residualCensusRequired = false; },
    (controls) => { controls.teardown.deleteExactStack = "other-stack"; },
    (controls) => { controls.teardown.expectedResourceInventorySha256 = "0".repeat(64); },
    (controls) => { controls.teardown.teardownDeadline = "2026-09-17T00:30:00.000Z"; }
  ]) {
    const controls = releaseControls();
    mutate(controls);
    assert.throws(
      () => buildReleaseUploadPlan(input({ controls })),
      /RELEASE_PLAN_CONTROLS_REJECTED/u
    );
  }
});

test("release upload plan rejects an artifact key outside exact source prefix", () => {
  const template = gate2Template();
  const build = validatedBuild(template);
  build.artifacts.authority.suggestedS3Key =
    `gate2/${"9".repeat(40)}/authority-${"4".repeat(64)}.zip`;
  assert.throws(
    () => buildReleaseUploadPlan(input({ template, build })),
    /RELEASE_PLAN_BUILD_REJECTED/u
  );
});

test("release upload plan rejects probe-default or primary-role drift", () => {
  const probeTemplate = gate2Template();
  probeTemplate.Parameters.EnableProbeFunctions.Default = "true";
  assert.throws(
    () => buildReleaseUploadPlan(input({ template: probeTemplate })),
    /RELEASE_PLAN_TEMPLATE_RESOURCE_REJECTED/u
  );

  const roleTemplate = gate2Template();
  delete roleTemplate.Resources.AgentRole;
  assert.throws(
    () => buildReleaseUploadPlan(input({ template: roleTemplate })),
    /RELEASE_PLAN_PRIMARY_RESOURCE_CONTRACT_REJECTED/u
  );
});

test("release upload plan rejects invalid bucket names", () => {
  for (const artifactBucket of [
    "UppercaseBucket",
    "192.168.1.1",
    "bucket..gap"
  ]) {
    const candidate = input();
    candidate.artifactBucket = artifactBucket;
    assert.throws(
      () => buildReleaseUploadPlan(candidate),
      /RELEASE_PLAN_ARTIFACT_BUCKET_REJECTED/u
    );
  }
});
