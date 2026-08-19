import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  prepareFreshPrimaryBootstrapRole,
  verifyFreshPrimaryBootstrapRolePlan
} from "../scripts/prepare-fresh-primary-bootstrap-role.js";

const ACCOUNT = "111111111111";
const COMMIT = "a".repeat(40);
const TREE = "b".repeat(40);

test("standalone role plan is exact, create-only, and retained-stack free", () => {
  const plan = prepareFreshPrimaryBootstrapRole({
    accountId: ACCOUNT,
    sourceCommit: COMMIT,
    treeDigest: TREE
  });
  assert.equal(plan.status, "READY_FOR_EXACT_CREATE_ONLY_APPLY");
  assert.equal(plan.stackName, __test.STACK_NAME);
  assert.equal(plan.roleName, __test.ROLE_NAME);
  assert.equal(plan.templatePath,
    "infra/aws/fresh-primary-bootstrap-role-stack.json");
  assert.equal(plan.templateSha256, __test.TEMPLATE_SHA256);
  assert.equal(plan.expectedResourceCount, 1);
  assert.equal(plan.createOnly, true);
  assert.equal(plan.updateAllowed, false);
  assert.equal(plan.terminationProtection, true);
  assert.deepEqual(plan.capabilities, ["CAPABILITY_NAMED_IAM"]);
  assert.equal(plan.githubOidcProviderArn,
    "arn:aws:iam::111111111111:oidc-provider/" +
    "token.actions.githubusercontent.com");
  assert.equal(plan.requiredBootstrapAuthority.cloudFormationCreateResource,
    "*");
  assert.equal(plan.requiredBootstrapAuthority.cloudFormationStackResource,
    "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
    "prooftoact-fresh-primary-bootstrap-role/*");
  assert.equal(plan.requiredBootstrapAuthority.iamResource,
    "arn:aws:iam::111111111111:role/ProofToActFreshPrimaryBootstrap");
  assert.deepEqual(plan.requiredBootstrapAuthority.oidcReadActions,
    ["iam:GetOpenIDConnectProvider"]);
  assert.equal(plan.requiredBootstrapAuthority.passRoleExplicitlyAbsent, true);
  assert.deepEqual(plan.requiredStackTags, { Project: "ProofToAct" });
  assert.equal(JSON.stringify(plan.requiredBootstrapAuthority)
    .includes("iam:PassRole"), false);
  assert.equal(Object.isFrozen(plan), true);
  assert.deepEqual(verifyFreshPrimaryBootstrapRolePlan(plan), plan);
  const serialized = JSON.stringify(plan);
  assert.equal(serialized.includes("prooftoact-release-control-bootstrap"),
    false);
  assert.equal(serialized.includes("release-deployment-roles-template"), false);
});

test("standalone role plan rejects drift and invalid coordinates", () => {
  assert.throws(() => prepareFreshPrimaryBootstrapRole({
    accountId: "root",
    sourceCommit: COMMIT,
    treeDigest: TREE
  }), /FRESH_PRIMARY_ROLE_PREPARE_REJECTED/u);
  const plan = prepareFreshPrimaryBootstrapRole({
    accountId: ACCOUNT,
    sourceCommit: COMMIT,
    treeDigest: TREE
  });
  assert.throws(() => verifyFreshPrimaryBootstrapRolePlan({
    ...plan,
    updateAllowed: true
  }), /FRESH_PRIMARY_ROLE_PLAN_REJECTED/u);
});
