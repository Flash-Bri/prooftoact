import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TEMPLATE_PATH = path.join(
  ROOT,
  "infra/aws/fresh-primary-bootstrap-role-stack.json"
);
const TEMPLATE = JSON.parse(fs.readFileSync(TEMPLATE_PATH, "utf8"));
const ROLE = TEMPLATE.Resources.FreshPrimaryBootstrapRole;
const STATEMENTS = ROLE.Properties.Policies[0].PolicyDocument.Statement;

const TABLE_ARN = {
  "Fn::Sub":
    "arn:${AWS::Partition}:dynamodb:us-east-1:${AWS::AccountId}:" +
    "table/prooftoact-release-controller"
};
const ADMIN_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/fresh-primary/" +
    "admin-????????-????-????-????-????????????-??????"
};
const AUDITOR_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/fresh-cluster/auditor-??????"
};
const CREATOR_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/fresh-primary/cloud-api-??????"
};
const RUNTIME_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/fresh-primary/runtime-credentials-??????"
};
const SIGNER_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/fresh-primary/" +
    "recovery-signer-????????-????-????-????-????????????-??????"
};
const MCP_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/gate2/managed-mcp-??????"
};
const PUBLISHER_SECRET = {
  "Fn::Sub":
    "arn:${AWS::Partition}:secretsmanager:us-east-1:${AWS::AccountId}:" +
    "secret:prooftoact/gate2/recovery-publisher-??????"
};

function exactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

function statement(sid) {
  const matches = STATEMENTS.filter((candidate) => candidate.Sid === sid);
  assert.equal(matches.length, 1, `expected exactly one ${sid}`);
  return matches[0];
}

function actions(candidate) {
  return (Array.isArray(candidate.Action)
    ? candidate.Action
    : [candidate.Action]).sort();
}

test("fresh-primary bootstrap role stack is create-only and self-contained", () => {
  exactKeys(TEMPLATE, [
    "AWSTemplateFormatVersion",
    "Description",
    "Outputs",
    "Parameters",
    "Resources"
  ]);
  exactKeys(TEMPLATE.Parameters, ["GitHubOidcProviderArn"]);
  exactKeys(TEMPLATE.Resources, ["FreshPrimaryBootstrapRole"]);
  exactKeys(TEMPLATE.Outputs, ["FreshPrimaryBootstrapRoleArn"]);
  assert.equal(ROLE.Type, "AWS::IAM::Role");
  assert.equal(ROLE.Properties.RoleName, "ProofToActFreshPrimaryBootstrap");
  assert.deepEqual(ROLE.Properties.ManagedPolicyArns, []);
  assert.equal(Object.hasOwn(ROLE, "DeletionPolicy"), false);
  assert.equal(Object.hasOwn(ROLE, "UpdateReplacePolicy"), false);
  assert.equal(JSON.stringify(TEMPLATE).includes("ReleaseControlTable"), true);
  assert.equal(
    Object.values(TEMPLATE.Resources).some(({ Type }) =>
      Type === "AWS::DynamoDB::Table" ||
      Type === "AWS::SecretsManager::Secret" ||
      Type === "AWS::CloudFormation::Stack"),
    false
  );
});

test("trust is exact, protected, main-only, and source pinned", () => {
  const trust = ROLE.Properties.AssumeRolePolicyDocument;
  assert.equal(trust.Version, "2012-10-17");
  assert.equal(trust.Statement.length, 1);
  const entry = trust.Statement[0];
  assert.equal(entry.Effect, "Allow");
  assert.equal(entry.Action, "sts:AssumeRoleWithWebIdentity");
  assert.deepEqual(entry.Principal, {
    Federated: { Ref: "GitHubOidcProviderArn" }
  });
  assert.deepEqual(entry.Condition.StringEquals, {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:environment":
      "aws-release-database-bootstrap",
    "token.actions.githubusercontent.com:job_workflow_ref":
      "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-sealed-fresh-primary.yml@" +
      "b8f993a4a9a898673c89dbd8218ec7eb591f1f10",
    "token.actions.githubusercontent.com:ref": "refs/heads/main",
    "token.actions.githubusercontent.com:repository": "Flash-Bri/prooftoact",
    "token.actions.githubusercontent.com:repository_id": "1317716765",
    "token.actions.githubusercontent.com:repository_owner_id": "252500266",
    "token.actions.githubusercontent.com:sub":
      "repo:Flash-Bri@252500266/prooftoact@1317716765:" +
      "environment:aws-release-database-bootstrap",
    "token.actions.githubusercontent.com:workflow":
      "ProofToAct Fresh Cluster And Primary"
  });
});

test("journal access is fixed-table and exact-key scoped", () => {
  assert.deepEqual(statement("ReadReleaseControlTableIdentity"), {
    Sid: "ReadReleaseControlTableIdentity",
    Effect: "Allow",
    Action: ["dynamodb:DescribeTable", "dynamodb:ListTagsOfResource"],
    Resource: TABLE_ARN
  });
  const journal = statement("JournalOneFreshClusterAndPrimaryEffect");
  assert.deepEqual(actions(journal), [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem"
  ]);
  assert.deepEqual(journal.Resource, TABLE_ARN);
  assert.deepEqual(journal.Condition, {
    "ForAllValues:StringLike": {
      "dynamodb:LeadingKeys": ["FRESH_CLUSTER#*", "FRESH_PRIMARY#*"]
    },
    Null: { "dynamodb:LeadingKeys": "false" }
  });
  const deny = statement("DenyUnsafeReleaseControlOperations");
  assert.equal(deny.Effect, "Deny");
  for (const rejected of [
    "dynamodb:DeleteItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:TransactWriteItems"
  ]) assert.equal(actions(deny).includes(rejected), true);
});

test("secret reads and writes are exact-family scoped", () => {
  const read = statement("ReadExactNameFreshPrimarySecretVersions");
  assert.deepEqual(actions(read), [
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:GetSecretValue"
  ]);
  assert.deepEqual(read.Resource, [
    ADMIN_SECRET,
    AUDITOR_SECRET,
    CREATOR_SECRET,
    RUNTIME_SECRET,
    SIGNER_SECRET
  ]);
  const publication = statement(
    "ReadExactRecoveryPublicationSecretVersions"
  );
  assert.deepEqual(actions(publication), [
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetSecretValue"
  ]);
  assert.deepEqual(publication.Resource, [MCP_SECRET, PUBLISHER_SECRET]);
  const seal = statement("SealOperationBoundAdminAndRecoverySignerVersions");
  assert.deepEqual(actions(seal), ["secretsmanager:PutSecretValue"]);
  assert.deepEqual(seal.Resource, [ADMIN_SECRET, SIGNER_SECRET]);
  const deny = statement("DenyWritingAnyOtherSecret");
  assert.deepEqual(actions(deny), ["secretsmanager:PutSecretValue"]);
  assert.deepEqual(deny.NotResource, [ADMIN_SECRET, SIGNER_SECRET]);
  assert.equal(deny.NotResource.includes(MCP_SECRET), false);
  assert.equal(deny.NotResource.includes(PUBLISHER_SECRET), false);
});

test("role cannot deploy, invoke, assume, enumerate, or broaden state", () => {
  const deny = statement("DenyUnrelatedProviderCapabilities");
  assert.equal(deny.Effect, "Deny");
  assert.equal(deny.Resource, "*");
  for (const rejected of [
    "apigateway:*",
    "cloudformation:*",
    "iam:*",
    "kms:*",
    "lambda:*",
    "s3:*",
    "secretsmanager:ListSecrets",
    "sts:AssumeRole"
  ]) assert.equal(actions(deny).includes(rejected), true);

  const allows = STATEMENTS.filter(({ Effect }) => Effect === "Allow");
  for (const allow of allows) {
    if (allow.Sid === "ReadOwnCallerIdentity") {
      assert.deepEqual(allow, {
        Sid: "ReadOwnCallerIdentity",
        Effect: "Allow",
        Action: "sts:GetCallerIdentity",
        Resource: "*"
      });
      continue;
    }
    assert.notEqual(allow.Resource, "*");
  }
});
