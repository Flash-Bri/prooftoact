import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  verifyFreshPrimaryBootstrapRoleReadback
} from "../scripts/fresh-primary-bootstrap-role-readback.js";
import {
  __test as planTest,
  prepareFreshPrimaryBootstrapRole
} from "../scripts/prepare-fresh-primary-bootstrap-role.js";
import {
  freshPrimaryCredentialOperationToken
} from "../scripts/prepare-fresh-primary-credential-custody.js";

const ACCOUNT = "111111111111";
const PLAN = prepareFreshPrimaryBootstrapRole({
  accountId: ACCOUNT,
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40)
});
const TEMPLATE = planTest.readReviewedTemplate().template;
const CONTRACT = __test.sourceRoleContract(PLAN, TEMPLATE);
const OBSERVED_AT = "2026-08-19T05:00:00.000Z";
const OPERATION = "123e4567-e89b-42d3-a456-426614174000";
const OPERATION_TOKEN = freshPrimaryCredentialOperationToken(OPERATION);
const COLLECTOR_ROLE_NAME =
  `ProofToActBootstrapCreator-${OPERATION_TOKEN}`;
const COLLECTOR_SESSION_NAME = `prooftoact-bootstrap-${OPERATION_TOKEN}`;
const COLLECTOR_BINDING = Object.freeze({
  accountId: ACCOUNT,
  assumedRoleArn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
    `${COLLECTOR_ROLE_NAME}/${COLLECTOR_SESSION_NAME}`,
  operationId: OPERATION,
  operationToken: OPERATION_TOKEN,
  operatorAuthorizationSha256: "f".repeat(64),
  roleArn: `arn:aws:iam::${ACCOUNT}:role/prooftoact/bootstrap/` +
    COLLECTOR_ROLE_NAME,
  roleName: COLLECTOR_ROLE_NAME,
  rolePath: "/prooftoact/bootstrap/",
  sessionName: COLLECTOR_SESSION_NAME,
  sourceCommit: PLAN.sourceCommit,
  sourceIdentity: `prooftoact-b0-${OPERATION_TOKEN}`,
  treeDigest: PLAN.treeDigest
});

function fixture() {
  return {
    collectorBinding: structuredClone(COLLECTOR_BINDING),
    plan: PLAN,
    input: {
      schemaVersion: __test.INPUT_SCHEMA,
      callerIdentity: {
        Account: ACCOUNT,
        Arn: COLLECTOR_BINDING.assumedRoleArn,
        UserId: `AROA${"0".repeat(16)}:${COLLECTOR_SESSION_NAME}`
      },
      deployedTemplate: structuredClone(TEMPLATE),
      observedAt: OBSERVED_AT,
      oidcProvider: {
        arn: PLAN.githubOidcProviderArn,
        clientIds: ["sts.amazonaws.com"],
        thumbprints: ["1".repeat(40)],
        url: "token.actions.githubusercontent.com"
      },
      resources: [{
        logicalResourceId: "FreshPrimaryBootstrapRole",
        physicalResourceId: PLAN.roleName,
        resourceStatus: "CREATE_COMPLETE",
        resourceType: "AWS::IAM::Role"
      }],
      role: {
        arn: PLAN.expectedOutput.value,
        attachedPolicyArns: [],
        createdAt: "2026-08-19T04:55:00.000Z",
        description: CONTRACT.description,
        inlinePolicy: structuredClone(CONTRACT.inlinePolicy),
        inlinePolicyNames: [CONTRACT.inlinePolicyName],
        maxSessionDuration: CONTRACT.maxSessionDuration,
        path: "/",
        permissionsBoundaryArn: null,
        roleId: `AROA${"1".repeat(16)}`,
        roleName: PLAN.roleName,
        tags: Object.entries(CONTRACT.tags).map(([Key, Value]) => ({
          Key, Value
        })),
        trust: structuredClone(CONTRACT.trust)
      },
      stack: {
        capabilities: ["CAPABILITY_NAMED_IAM"],
        creationTime: "2026-08-19T04:54:00.000Z",
        outputs: {
          FreshPrimaryBootstrapRoleArn: PLAN.expectedOutput.value
        },
        parameters: {
          GitHubOidcProviderArn: PLAN.githubOidcProviderArn
        },
        stackId: `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
          `${PLAN.stackName}/123e4567-e89b-42d3-a456-426614174000`,
        stackName: PLAN.stackName,
        stackStatus: "CREATE_COMPLETE",
        tags: Object.entries(PLAN.requiredStackTags).map(([Key, Value]) => ({
          Key, Value
        })),
        terminationProtection: true
      }
    }
  };
}

test("standalone fresh-primary role readback binds exact stack, source role and non-root caller", () => {
  const receipt = verifyFreshPrimaryBootstrapRoleReadback(fixture());
  assert.equal(receipt.status,
    "EXACT_STANDALONE_ROLE_PROVIDER_READBACK_ACCEPTED");
  assert.equal(receipt.readOnly, true);
  assert.equal(receipt.templateSha256, PLAN.templateSha256);
  assert.equal(receipt.role.attachedPolicyCount, 0);
  assert.match(receipt.role.trustSha256, /^[0-9a-f]{64}$/u);
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/u);
  assert.equal(JSON.stringify(receipt).includes(PLAN.expectedOutput.value),
    false);
});

test("standalone readback rejects root, stack drift, extra resources and role policy drift", () => {
  for (const mutate of [
    ({ collectorBinding }) => {
      collectorBinding.sourceIdentity = "wrong";
    },
    ({ input }) => {
      input.callerIdentity = {
        Account: ACCOUNT,
        Arn: `arn:aws:iam::${ACCOUNT}:root`,
        UserId: ACCOUNT
      };
    },
    ({ input }) => {
      input.stack.terminationProtection = false;
    },
    ({ input }) => {
      input.resources.push({
        logicalResourceId: "Unexpected",
        physicalResourceId: "Unexpected",
        resourceStatus: "CREATE_COMPLETE",
        resourceType: "AWS::IAM::Role"
      });
    },
    ({ input }) => {
      input.role.inlinePolicy.Statement[0].Action.push("secretsmanager:*");
    },
    ({ input }) => {
      input.role.attachedPolicyArns.push(
        "arn:aws:iam::aws:policy/AdministratorAccess"
      );
    },
    ({ input }) => {
      input.role.permissionsBoundaryArn =
        "arn:aws:iam::aws:policy/AdministratorAccess";
    },
    ({ input }) => {
      input.deployedTemplate.Description = "changed";
    }
  ]) {
    const candidate = fixture();
    mutate(candidate);
    assert.throws(() => verifyFreshPrimaryBootstrapRoleReadback(candidate),
      /FRESH_(?:PRIMARY_ROLE_READBACK|BOOTSTRAP_COLLECTOR)_/u);
  }
});

test("readback accepts URL-encoded IAM policy documents but no unexpected tags", () => {
  const candidate = fixture();
  candidate.input.role.inlinePolicy = encodeURIComponent(JSON.stringify(
    candidate.input.role.inlinePolicy
  ));
  candidate.input.role.trust = encodeURIComponent(JSON.stringify(
    candidate.input.role.trust
  ));
  candidate.input.role.tags.push({
    Key: "aws:cloudformation:stack-name",
    Value: PLAN.stackName
  });
  assert.doesNotThrow(() =>
    verifyFreshPrimaryBootstrapRoleReadback(candidate));
  candidate.input.role.tags.push({ Key: "Unexpected", Value: "unsafe" });
  assert.throws(() => verifyFreshPrimaryBootstrapRoleReadback(candidate),
    /FRESH_PRIMARY_ROLE_READBACK_ROLE_REJECTED/u);
});
