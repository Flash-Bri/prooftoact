import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  freshPrimaryCredentialOperationToken,
  prepareFreshPrimaryCredentialCustody,
  verifyFreshPrimaryCredentialCustodyPlan
} from "../scripts/prepare-fresh-primary-credential-custody.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ACCOUNT = "111111111111";
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const OPERATOR_AUTHORIZATION = "f".repeat(64);
const TEMPLATE = JSON.parse(fs.readFileSync(path.join(
  ROOT, __test.TEMPLATE_PATH
), "utf8"));
const ROLE = TEMPLATE.Resources.FreshPrimaryCredentialWriterRole;
const STATEMENTS = ROLE.Properties.Policies[0].PolicyDocument.Statement;

function statement(sid) {
  const matches = STATEMENTS.filter((candidate) => candidate.Sid === sid);
  assert.equal(matches.length, 1);
  return matches[0];
}

function actions(candidate) {
  return (Array.isArray(candidate.Action)
    ? candidate.Action
    : [candidate.Action]).sort();
}

test("credential custody plan is operation-bound, create-only, and reproducible", () => {
  const plan = prepareFreshPrimaryCredentialCustody({
    accountId: ACCOUNT,
    operationId: OPERATION_ID,
    operatorAuthorizationSha256: OPERATOR_AUTHORIZATION,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
  const token = freshPrimaryCredentialOperationToken(OPERATION_ID);
  assert.match(token, /^[0-9a-f]{16}$/u);
  assert.equal(plan.operationToken, token);
  assert.equal(plan.stackName,
    `prooftoact-fresh-primary-credential-custody-${OPERATION_ID}`);
  assert.equal(plan.bootstrapCreatorRoleArn,
    `arn:aws:iam::${ACCOUNT}:role/prooftoact/bootstrap/` +
    `ProofToActBootstrapCreator-${token}`);
  assert.equal(plan.writerRoleArn,
    `arn:aws:iam::${ACCOUNT}:role/prooftoact/bootstrap/` +
    `ProofToActFreshCredentialWriter-${token}`);
  assert.equal(plan.cloudFormationServiceRoleArn, null);
  assert.equal(plan.createOnly, true);
  assert.equal(plan.updateAllowed, false);
  assert.equal(plan.terminationProtection, true);
  assert.equal(plan.expectedResourceCount, 8);
  assert.deepEqual(Object.values(plan.initialVersionContract),
    [0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(plan.writerTargets,
    ["auditor", "cloudApi", "credential", "mcp", "publisher"]);
  assert.deepEqual(plan.runtimeGeneratedTargets, ["admin", "signer"]);
  assert.deepEqual(plan.requiredBootstrapAuthority.
    valueActionsExplicitlyAbsent, [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ]);
  assert.deepEqual(verifyFreshPrimaryCredentialCustodyPlan(plan), plan);
  assert.match(plan.planSha256, /^[0-9a-f]{64}$/u);
});

test("credential custody plan rejects changed source, identity, or plan bytes", () => {
  for (const input of [
    {
      accountId: "root",
      operationId: OPERATION_ID,
      operatorAuthorizationSha256: OPERATOR_AUTHORIZATION,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    },
    {
      accountId: ACCOUNT,
      operationId: "ROOT",
      operatorAuthorizationSha256: OPERATOR_AUTHORIZATION,
      sourceCommit: SOURCE_COMMIT,
      treeDigest: TREE_DIGEST
    },
    {
      accountId: ACCOUNT,
      operationId: OPERATION_ID,
      operatorAuthorizationSha256: OPERATOR_AUTHORIZATION,
      sourceCommit: "A".repeat(40),
      treeDigest: TREE_DIGEST
    }
  ]) {
    assert.throws(() => prepareFreshPrimaryCredentialCustody(input),
      /FRESH_CREDENTIAL_PREPARE_REJECTED/u);
  }
  const plan = prepareFreshPrimaryCredentialCustody({
    accountId: ACCOUNT,
    operationId: OPERATION_ID,
    operatorAuthorizationSha256: OPERATOR_AUTHORIZATION,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST
  });
  assert.throws(() => verifyFreshPrimaryCredentialCustodyPlan({
    ...plan,
    terminationProtection: false
  }), /FRESH_CREDENTIAL_PLAN_REJECTED/u);
});

test("template creates seven empty exact-name secret containers", () => {
  const logicalIds = Object.values(__test.SECRET_LOGICAL_IDS);
  assert.equal(logicalIds.length, 7);
  for (const logicalId of logicalIds) {
    const resource = TEMPLATE.Resources[logicalId];
    assert.equal(resource.Type, "AWS::SecretsManager::Secret");
    assert.equal(resource.DeletionPolicy, "Retain");
    assert.equal(resource.UpdateReplacePolicy, "Retain");
    assert.equal(Object.hasOwn(resource.Properties, "SecretString"), false);
    assert.equal(Object.hasOwn(resource.Properties, "GenerateSecretString"),
      false);
    assert.equal(Object.hasOwn(resource.Properties, "KmsKeyId"), false);
    assert.equal(Object.hasOwn(resource.Properties, "ReplicaRegions"), false);
    assert.equal(Object.hasOwn(resource.Properties, "RotationRules"), false);
    assert.equal(Object.hasOwn(resource.Properties, "ResourcePolicy"), false);
    assert.equal(Array.isArray(resource.Properties.Tags), true);
  }
  assert.deepEqual(TEMPLATE.Resources.FreshClusterAuditorSecret.Properties.Name,
    "prooftoact/fresh-cluster/auditor");
  assert.deepEqual(TEMPLATE.Resources.FreshPrimaryCloudApiSecret.Properties.Name,
    "prooftoact/fresh-primary/cloud-api");
  assert.deepEqual(TEMPLATE.Resources.FreshPrimaryRuntimeCredentialsSecret.
    Properties.Name, "prooftoact/fresh-primary/runtime-credentials");
  assert.deepEqual(TEMPLATE.Resources.ManagedMcpSecret.Properties.Name,
    "prooftoact/gate2/managed-mcp");
  assert.deepEqual(TEMPLATE.Resources.RecoveryPublisherSecret.Properties.Name,
    "prooftoact/gate2/recovery-publisher");
  assert.deepEqual(TEMPLATE.Resources.FreshPrimaryAdminSecret.Properties.Name,
    { "Fn::Sub": "prooftoact/fresh-primary/admin-${OperationId}" });
  assert.deepEqual(TEMPLATE.Resources.FreshPrimaryRecoverySignerSecret.
    Properties.Name, {
    "Fn::Sub": "prooftoact/fresh-primary/recovery-signer-${OperationId}"
  });
  assert.equal(JSON.stringify(TEMPLATE).includes("SecretString"), false);
  assert.equal(JSON.stringify(TEMPLATE).includes("GenerateSecretString"),
    false);
});

test("writer trust is chained to exact temporary B0 identity", () => {
  assert.deepEqual(ROLE.Properties.RoleName, {
    "Fn::Sub": "ProofToActFreshCredentialWriter-${OperationToken}"
  });
  assert.equal(ROLE.Properties.Path, "/prooftoact/bootstrap/");
  assert.deepEqual(ROLE.Properties.ManagedPolicyArns, []);
  assert.deepEqual(ROLE.Properties.AssumeRolePolicyDocument, {
    Version: "2012-10-17",
    Statement: [{
      Effect: "Allow",
      Principal: { AWS: { Ref: "BootstrapCreatorRoleArn" } },
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: {
          "sts:ExternalId": { Ref: "CredentialSealExternalId" },
          "sts:RoleSessionName": {
            "Fn::Sub": "prooftoact-credential-seal-${OperationToken}"
          }
        }
      }
    }]
  });
});

test("writer may initialize exactly five values and never admin or signer", () => {
  const all = statement("InspectExactSevenCredentialContainers");
  assert.deepEqual(actions(all), [
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:ListSecretVersionIds"
  ]);
  assert.equal(all.Resource.length, 7);
  const seal = statement("SealAndReadExactFiveCredentialVersions");
  assert.deepEqual(actions(seal), [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue"
  ]);
  assert.deepEqual(seal.Resource, [
    { Ref: "FreshClusterAuditorSecret" },
    { Ref: "FreshPrimaryCloudApiSecret" },
    { Ref: "FreshPrimaryRuntimeCredentialsSecret" },
    { Ref: "ManagedMcpSecret" },
    { Ref: "RecoveryPublisherSecret" }
  ]);
  assert.equal(seal.Resource.some((value) =>
    ["FreshPrimaryAdminSecret", "FreshPrimaryRecoverySignerSecret"]
      .includes(value.Ref)), false);
  assert.deepEqual(seal.Condition.StringEquals, {
    "secretsmanager:ResourceTag/Project": "ProofToAct",
    "secretsmanager:ResourceTag/OperationId": { Ref: "OperationId" }
  });
  const deny = statement("DenyWritingAnyOtherSecret");
  assert.equal(deny.Effect, "Deny");
  assert.equal(actions(deny).includes("secretsmanager:PutSecretValue"), true);
  assert.equal(deny.NotResource.length, 5);
  const lifecycle = statement("DenySecretLifecycleMutation");
  for (const action of [
    "secretsmanager:CreateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:UpdateSecret",
    "secretsmanager:UpdateSecretVersionStage"
  ]) assert.equal(actions(lifecycle).includes(action), true);
  const unrelated = statement("DenyUnrelatedProviderCapabilities");
  for (const action of [
    "cloudformation:*", "dynamodb:*", "iam:*", "kms:*", "lambda:*",
    "s3:*", "secretsmanager:ListSecrets", "sts:AssumeRole"
  ]) assert.equal(actions(unrelated).includes(action), true);
});
