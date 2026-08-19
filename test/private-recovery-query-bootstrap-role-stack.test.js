import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const template = JSON.parse(fs.readFileSync(new URL(
  "../infra/aws/private-recovery-query-bootstrap-role-stack.json",
  import.meta.url
), "utf8"));
const service = template.Resources.PrivateRecoveryCloudFormationRole;
const deployer = template.Resources.PrivateRecoveryDeploymentRole;
const boundary = template.Resources.PrivateRecoveryBoundary;
const secret = template.Resources.PrivateRecoveryMcpSecret;
const sealer = template.Resources.PrivateRecoverySecretSealerRole;

function statements(role) {
  return role.Properties.Policies[0].PolicyDocument.Statement;
}

function statement(role, sid) {
  const matches = statements(role).filter((entry) => entry.Sid === sid);
  assert.equal(matches.length, 1, `expected exactly one ${sid}`);
  return matches[0];
}

function actions(entry) {
  return Array.isArray(entry.Action) ? entry.Action : [entry.Action];
}

test("bootstrap stack owns only the isolated boundary, empty secret, and three roles", () => {
  assert.deepEqual(Object.keys(template.Parameters).sort(), [
    "ArtifactBucketName",
    "DeploymentWorkflowCommit",
    "GitHubOidcProviderArn",
    "SecretSealWorkflowCommit"
  ]);
  assert.equal(template.Parameters.DeploymentWorkflowCommit.AllowedPattern,
    "^[0-9a-f]{40}$");
  assert.equal(template.Parameters.SecretSealWorkflowCommit.AllowedPattern,
    "^[0-9a-f]{40}$");
  assert.deepEqual(Object.keys(template.Resources).sort(), [
    "PrivateRecoveryBoundary",
    "PrivateRecoveryCloudFormationRole",
    "PrivateRecoveryDeploymentRole",
    "PrivateRecoveryMcpSecret",
    "PrivateRecoverySecretSealerRole"
  ]);
  assert.equal(service.Type, "AWS::IAM::Role");
  assert.equal(deployer.Type, "AWS::IAM::Role");
  assert.equal(service.Properties.RoleName,
    "ProofToActPrivateRecoveryQueryCloudFormation");
  assert.equal(deployer.Properties.RoleName,
    "ProofToActPrivateRecoveryQueryDeployment");
  assert.equal(boundary.Type, "AWS::IAM::ManagedPolicy");
  assert.equal(boundary.Properties.ManagedPolicyName,
    "ProofToActPrivateRecoveryQueryBoundary");
  assert.deepEqual(service.Properties.PermissionsBoundary, {
    Ref: "PrivateRecoveryBoundary"
  });
  assert.deepEqual(service.Properties.ManagedPolicyArns, []);
  assert.deepEqual(deployer.Properties.ManagedPolicyArns, []);
  assert.equal(deployer.Properties.MaxSessionDuration, 3600);
  assert.equal(sealer.Properties.MaxSessionDuration, 3600);
  assert.equal(secret.Type, "AWS::SecretsManager::Secret");
  assert.equal(secret.DeletionPolicy, "Retain");
  assert.equal(secret.UpdateReplacePolicy, "Retain");
  assert.equal(secret.Properties.Name,
    "prooftoact/private-recovery-query/managed-mcp");
  assert.equal(Object.hasOwn(secret.Properties, "SecretString"), false);
  assert.equal(Object.hasOwn(secret.Properties, "GenerateSecretString"), false);
  assert.equal(Object.values(template.Resources).some(({ Type }) =>
    !["AWS::IAM::Role", "AWS::IAM::ManagedPolicy",
      "AWS::SecretsManager::Secret"].includes(Type)), false);
});

test("dispatcher trust is protected, main-only, and parameter-pinned", () => {
  const entry = deployer.Properties.AssumeRolePolicyDocument.Statement[0];
  assert.equal(entry.Action, "sts:AssumeRoleWithWebIdentity");
  assert.deepEqual(entry.Principal, {
    Federated: { Ref: "GitHubOidcProviderArn" }
  });
  assert.deepEqual(entry.Condition.StringEquals, {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub":
      "repo:Flash-Bri@252500266/prooftoact@1317716765:environment:aws-private-recovery-deploy",
    "token.actions.githubusercontent.com:repository": "Flash-Bri/prooftoact",
    "token.actions.githubusercontent.com:repository_id": "1317716765",
    "token.actions.githubusercontent.com:repository_owner_id": "252500266",
    "token.actions.githubusercontent.com:ref": "refs/heads/main",
    "token.actions.githubusercontent.com:environment":
      "aws-private-recovery-deploy",
    "token.actions.githubusercontent.com:job_workflow_ref": {
      "Fn::Sub": "Flash-Bri/prooftoact/.github/workflows/" +
        "prooftoact-sealed-private-recovery-deploy.yml@" +
        "${DeploymentWorkflowCommit}"
    },
    "token.actions.githubusercontent.com:workflow":
      "ProofToAct Private Recovery Deploy"
  });
  assert.equal(Object.hasOwn(entry.Condition.StringEquals,
    "token.actions.githubusercontent.com:repository_owner"), false);
});

test("CloudFormation service trust is exact and cannot be assumed by GitHub", () => {
  const trust = service.Properties.AssumeRolePolicyDocument.Statement;
  assert.equal(trust.length, 1);
  assert.deepEqual(trust[0].Principal, {
    Service: "cloudformation.amazonaws.com"
  });
  assert.equal(trust[0].Action, "sts:AssumeRole");
  assert.deepEqual(trust[0].Condition.ArnLike["aws:SourceArn"], {
    "Fn::Sub": "arn:${AWS::Partition}:cloudformation:us-east-1:" +
      "${AWS::AccountId}:stack/prooftoact-private-recovery-query/*"
  });
  const directDeny = statement(deployer,
    "DenyDirectServiceRoleAssumption");
  assert.equal(directDeny.Effect, "Deny");
  assert.equal(directDeny.Action, "sts:AssumeRole");
  assert.deepEqual(directDeny.Resource, {
    "Fn::GetAtt": ["PrivateRecoveryCloudFormationRole", "Arn"]
  });
});

test("secret sealer copies one exact source version into only the retained target", () => {
  assert.equal(sealer.Properties.RoleName,
    "ProofToActPrivateRecoveryQuerySecretSealer");
  assert.equal(Object.hasOwn(sealer.Properties, "PermissionsBoundary"), false);
  assert.deepEqual(sealer.Properties.ManagedPolicyArns, []);
  const trust = sealer.Properties.AssumeRolePolicyDocument.Statement;
  assert.equal(trust.length, 1);
  assert.equal(trust[0].Action, "sts:AssumeRoleWithWebIdentity");
  assert.equal(trust[0].Condition.StringEquals[
    "token.actions.githubusercontent.com:environment"
  ], "aws-private-recovery-deploy");
  assert.equal(trust[0].Condition.StringEquals[
    "token.actions.githubusercontent.com:workflow"
  ], "ProofToAct Private Recovery Secret Seal");
  assert.deepEqual(trust[0].Condition.StringEquals[
    "token.actions.githubusercontent.com:job_workflow_ref"
  ], {
    "Fn::Sub": "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-sealed-private-recovery-secret-seal.yml@" +
      "${SecretSealWorkflowCommit}"
  });
  const source = statement(sealer, "ReadOneImmutableSourceManagedMcpVersion");
  assert.deepEqual(actions(source).sort(), [
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetSecretValue",
    "secretsmanager:ListSecretVersionIds"
  ]);
  assert.equal(JSON.stringify(source.Resource).includes(
    "secret:prooftoact/gate2/managed-mcp-??????"), true);
  const target = statement(sealer, "SealAndReadBackOnePrivateTargetVersion");
  assert.deepEqual(actions(target).sort(), [
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetSecretValue",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:PutSecretValue"
  ]);
  assert.deepEqual(target.Resource, { Ref: "PrivateRecoveryMcpSecret" });
  assert.deepEqual(statement(sealer, "DenyWritingAnyOtherSecret").NotResource,
    { Ref: "PrivateRecoveryMcpSecret" });
  const deny = statement(sealer, "DenyApplicationAndAuthorityExpansion");
  for (const rejected of [
    "cloudformation:*", "dynamodb:*", "iam:*", "lambda:*", "s3:*",
    "secretsmanager:CreateSecret", "sts:AssumeRole"
  ]) assert.equal(actions(deny).includes(rejected), true);
});

test("dispatcher can prepare one CREATE stack and pass only the service role", () => {
  const list = statement(deployer, "ReconcileExactArtifactUploadByReadback");
  assert.equal(list.Action, "s3:ListBucketVersions");
  assert.deepEqual(list.Condition, {
    StringLike: { "s3:prefix": "private-recovery-query/*" }
  });
  const read = statement(deployer, "ReadExactArtifactVersionMetadata");
  assert.deepEqual(actions(read).sort(), ["s3:GetObject", "s3:GetObjectVersion"]);
  assert.equal(JSON.stringify(read.Resource).includes(
    "private-recovery-query/*"), true);
  const create = statement(deployer, "PrepareAndExecuteOneCreateChangeSet");
  assert.deepEqual(actions(create).sort(), [
    "cloudformation:CreateChangeSet",
    "cloudformation:DescribeChangeSet",
    "cloudformation:ExecuteChangeSet"
  ]);
  assert.equal(JSON.stringify(create.Resource).includes(
    "stack/prooftoact-private-recovery-query/*"), true);
  assert.equal(JSON.stringify(create.Resource).includes(
    "changeSet/prooftoact-private-recovery-query-create-*/*"), true);
  const pass = statement(deployer, "PassOnlyDedicatedCloudFormationRole");
  assert.equal(pass.Action, "iam:PassRole");
  assert.deepEqual(pass.Resource, {
    "Fn::GetAtt": ["PrivateRecoveryCloudFormationRole", "Arn"]
  });
  assert.deepEqual(pass.Condition, {
    StringEquals: { "iam:PassedToService": "cloudformation.amazonaws.com" }
  });
  const deny = statement(deployer, "DenyUpdateTeardownAndRuntime");
  for (const rejected of [
    "cloudformation:DeleteStack",
    "cloudformation:UpdateStack",
    "lambda:Invoke*",
    "secretsmanager:GetSecretValue",
    "sts:AssumeRole"
  ]) assert.equal(actions(deny).includes(rejected), true);
});

test("service role is exact-resource rollback capable without runtime authority", () => {
  const create = statement(service, "CreateExactStackRolesWithBoundary");
  assert.equal(create.Action, "iam:CreateRole");
  assert.deepEqual(create.Condition, {
    StringEquals: { "iam:PermissionsBoundary": { Ref: "PrivateRecoveryBoundary" } }
  });
  assert.equal(JSON.stringify(statement(service, "ManageExactStackRoles").Resource)
    .includes("ProofToActPrivateRecoveryQueryRuntime"), true);
  const pass = statement(service, "PassExactLambdaRuntimeRole");
  assert.deepEqual(pass.Condition, {
    StringEquals: { "iam:PassedToService": "lambda.amazonaws.com" }
  });
  const provider = statement(service, "ManageExactPrivateLambda");
  assert.equal(actions(provider).includes("lambda:CreateFunction"), true);
  assert.equal(actions(provider).includes("lambda:DeleteFunction"), true);
  assert.equal(actions(provider).some((action) => action.startsWith(
    "lambda:Invoke")), false);
  const deny = statement(service, "DenyRuntimeAndUnrelatedProviders");
  for (const rejected of [
    "dynamodb:*",
    "lambda:CreateFunctionUrlConfig",
    "lambda:Invoke*",
    "secretsmanager:*",
    "sts:AssumeRole"
  ]) assert.equal(actions(deny).includes(rejected), true);
});

test("dedicated boundary excludes public and unrelated provider capability", () => {
  const entries = boundary.Properties.PolicyDocument.Statement;
  const lane = entries.find(({ Sid }) =>
    Sid === "AllowExactLambdaLifecycleReadbackAndInvoke");
  assert.equal(JSON.stringify(lane.Resource).includes(
    "function:prooftoact-private-recovery-query:*"), true);
  const targetSecret = entries.find(({ Sid }) =>
    Sid === "AllowPrivateRecoverySecretReadAndMetadata");
  assert.equal(JSON.stringify(targetSecret.Resource).includes(
    "secret:prooftoact/private-recovery-query/managed-mcp-??????"), true);
  assert.equal(actions(targetSecret).includes("secretsmanager:PutSecretValue"),
    false);
  assert.equal(JSON.stringify(entries).includes(
    "secret:prooftoact/gate2/managed-mcp-??????"), false);
  const deny = entries.find(({ Sid }) =>
    Sid === "DenyPublicAndUnrelatedProviders");
  for (const rejected of [
    "apigateway:*",
    "bedrock:*",
    "lambda:CreateFunctionUrlConfig",
    "secretsmanager:CreateSecret",
    "secretsmanager:PutSecretValue",
    "sts:AssumeRole"
  ]) assert.equal(actions(deny).includes(rejected), true);
});
