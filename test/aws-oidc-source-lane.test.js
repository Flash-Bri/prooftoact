import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  __test as sourceContract,
  validateIdentityWorkflow,
  validateReadOnlyRoleTemplate,
  validateReadOnlyRunner,
  validateReadOnlyWorkflow,
  verifyAwsOidcPreflightSource
} from "../scripts/verify-aws-oidc-preflight-source.js";
import {
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  validateAwsGate2PreflightIdentityExpectation
} from "../src/cloud/aws-gate2-preflight.js";

function source(relativePath) {
  return fs.readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8");
}

function roleTemplate() {
  return JSON.parse(
    source("infra/aws/oidc-read-only-preflight-role-template.json")
  );
}

function clone(value) {
  return structuredClone(value);
}

const IDENTITY_WORKFLOW = source(
  ".github/workflows/aws-oidc-identity-bootstrap.yml"
);
const READ_ONLY_WORKFLOW = source(
  ".github/workflows/aws-oidc-read-only-preflight.yml"
);
const READ_ONLY_RUNNER = source(
  "scripts/run-aws-oidc-read-only-preflight.sh"
);

test("OIDC source receipt remains explicitly local and provider-pending", () => {
  const receipt = verifyAwsOidcPreflightSource();

  assert.equal(
    receipt.schemaVersion,
    "prooftoact.aws-oidc-preflight-source-verification.v1"
  );
  assert.equal(
    receipt.status,
    "SOURCE_CONTRACT_PASS_PROVIDER_SETUP_AND_EXECUTION_PENDING"
  );
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.providerSetup, "PENDING_HUMAN_AUTHORIZATION");
  assert.equal(receipt.providerExecution, "NOT_RUN");
  assert.equal(receipt.cloudShellRequired, false);
  assert.equal(receipt.deploymentRoleOrWorkflowAdded, false);
  assert.equal(receipt.approvedIdentityLaneCount, 2);
  assert.equal(
    receipt.exactReadActionCount,
    sourceContract.EXACT_READ_ACTIONS.length
  );
  assert.equal(receipt.reviewedFiles.length, 7);
  assert.ok(Object.values(receipt.checks).every((value) => value === true));
  assert.match(receipt.claimBoundary, /does not prove GitHub environment/);
  assert.match(receipt.claimBoundary, /grants no provider authority/);
});

test("read-only role template is exact and rejects expanded trust or authority", () => {
  assert.doesNotThrow(() => validateReadOnlyRoleTemplate(roleTemplate()));

  const expandedTrust = clone(roleTemplate());
  expandedTrust.Resources.ReadOnlyPreflightRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
      "token.actions.githubusercontent.com:sub"
    ] = "repo:Flash-Bri/prooftoact:*";
  assert.throws(
    () => validateReadOnlyRoleTemplate(expandedTrust),
    /OIDC_ROLE_TEMPLATE_TRUST/
  );

  const expandedAction = clone(roleTemplate());
  expandedAction.Resources.ReadOnlyPreflightRole.Properties.Policies[0]
    .PolicyDocument.Statement.at(-1).NotAction.push("s3:PutObject");
  assert.throws(
    () => validateReadOnlyRoleTemplate(expandedAction),
    /OIDC_ROLE_TEMPLATE_EXPLICIT_DENY/
  );

  const noDeny = clone(roleTemplate());
  noDeny.Resources.ReadOnlyPreflightRole.Properties.Policies[0]
    .PolicyDocument.Statement.pop();
  assert.throws(
    () => validateReadOnlyRoleTemplate(noDeny),
    /OIDC_ROLE_TEMPLATE_STATEMENTS/
  );

  const wildcardBucket = clone(roleTemplate());
  wildcardBucket.Resources.ReadOnlyPreflightRole.Properties.Policies[0]
    .PolicyDocument.Statement.find(
      ({ Sid }) => Sid === "ReadArtifactBucketControls"
    ).Resource = "*";
  assert.throws(
    () => validateReadOnlyRoleTemplate(wildcardBucket),
    /OIDC_ROLE_TEMPLATE_SCOPED_RESOURCES/
  );
});

test("identity workflow stays manual, exact-commit-bound, and STS-only", () => {
  assert.doesNotThrow(() => validateIdentityWorkflow(IDENTITY_WORKFLOW));

  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace(
          "GITHUB_SHA:-}\" == \"$EXPECTED_OFFICIAL_MAIN_COMMIT",
          "GITHUB_SHA:-}\" != \"$EXPECTED_OFFICIAL_MAIN_COMMIT"
        )
      ),
    /OIDC_IDENTITY_WORKFLOW_MARKERS/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        `${IDENTITY_WORKFLOW}\n      - uses: actions/checkout@main\n`
      ),
    /OIDC_IDENTITY_WORKFLOW_MINIMAL/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        `${IDENTITY_WORKFLOW}\n\"$aws_cli\" s3 list-buckets\n`
      ),
    /OIDC_IDENTITY_WORKFLOW_STS_ONLY/
  );
});

test("read-only workflow stays separately protected and action-pinned", () => {
  assert.doesNotThrow(() => validateReadOnlyWorkflow(READ_ONLY_WORKFLOW));

  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        READ_ONLY_WORKFLOW.replace(
          "environment: aws-read-only-preflight",
          "environment: production"
        )
      ),
    /OIDC_READ_ONLY_WORKFLOW_MARKERS/
  );
  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        `${READ_ONLY_WORKFLOW}\n      - uses: aws-actions/configure-aws-credentials@main\n`
      ),
    /OIDC_READ_ONLY_WORKFLOW_BOUNDARY/
  );
  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        READ_ONLY_WORKFLOW.replace(
          "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
          "actions/setup-node@main"
        )
      ),
    /OIDC_READ_ONLY_WORKFLOW_ACTION_PINS/
  );
});

test("read-only runner rejects direct mutation calls and shell tracing", () => {
  assert.doesNotThrow(() => validateReadOnlyRunner(READ_ONLY_RUNNER));

  assert.throws(
    () =>
      validateReadOnlyRunner(
        `${READ_ONLY_RUNNER}\n\"$aws_cli\" cloudformation create-stack\n`
      ),
    /OIDC_READ_ONLY_RUNNER_DIRECT_CALLS/
  );
  assert.throws(
    () => validateReadOnlyRunner(`${READ_ONLY_RUNNER}\nset -x\n`),
    /OIDC_READ_ONLY_RUNNER_MUTATION/
  );
});

test("preflight identity accepts only the two exact role/session pairings", () => {
  const accountId = "111111111111";
  const roleId = `AROA${"A".repeat(16)}`;
  const expectation = (roleName, sessionName) => ({
    expectedAccountId: accountId,
    expectedPrincipalArn: `arn:aws:iam::${accountId}:role/${roleName}`,
    expectedCallerArn:
      `arn:aws:sts::${accountId}:assumed-role/${roleName}/${sessionName}`,
    expectedCallerUserId: `${roleId}:${sessionName}`
  });

  for (const lane of AWS_GATE2_PREFLIGHT_DEFAULTS.approvedPreflightIdentityLanes) {
    assert.doesNotThrow(() =>
      validateAwsGate2PreflightIdentityExpectation(
        expectation(lane.roleName, lane.sessionName)
      )
    );
  }
  assert.throws(
    () =>
      validateAwsGate2PreflightIdentityExpectation(
        expectation("ProofToActReadOnlyPreflight", "release-proof")
      ),
    /AWS_PREFLIGHT_EXPECTED_CALLER_ARN/
  );
  assert.throws(
    () =>
      validateAwsGate2PreflightIdentityExpectation(
        expectation("AdministratorAccess", "read-only-preflight")
      ),
    /AWS_PREFLIGHT_EXPECTED_ROLE/
  );
});
