import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  __test as sourceContract,
  validateIdentityWorkflow,
  validateReadOnlyRoleTemplate,
  validateReadOnlyRunner,
  validateReadOnlyWorkflow,
  validateUnderlyingPreflight,
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
const PREFLIGHT_RUNNER = source("scripts/gate2-aws-preflight.js");
const PREFLIGHT_VALIDATOR = source(
  "src/cloud/aws-gate2-preflight.js"
);

test("OIDC source receipt remains explicitly local and provider-pending", () => {
  const receipt = verifyAwsOidcPreflightSource();

  assert.equal(
    receipt.schemaVersion,
    "prooftoact.aws-oidc-preflight-source-verification.v2"
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
  assert.equal(receipt.identityWorkflowAwsCallCount, 2);
  assert.equal(receipt.exactPreflightRuntimeCallCount, 17);
  assert.equal(receipt.exactReadOnlyWorkflowAwsCallCount, 20);
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
    ] = "repo:Flash-Bri@252500266/prooftoact@1317716765:*";
  assert.throws(
    () => validateReadOnlyRoleTemplate(expandedTrust),
    /OIDC_ROLE_TEMPLATE_TRUST/
  );

  const wrongOwnerId = clone(roleTemplate());
  wrongOwnerId.Resources.ReadOnlyPreflightRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
      "token.actions.githubusercontent.com:repository_owner_id"
    ] = "252500267";
  assert.throws(
    () => validateReadOnlyRoleTemplate(wrongOwnerId),
    /OIDC_ROLE_TEMPLATE_TRUST/
  );

  const unsupportedWorkflowRef = clone(roleTemplate());
  unsupportedWorkflowRef.Resources.ReadOnlyPreflightRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
      "token.actions.githubusercontent.com:workflow_ref"
    ] =
    "Flash-Bri/prooftoact/.github/workflows/" +
    "aws-oidc-read-only-preflight.yml@refs/heads/main";
  assert.throws(
    () => validateReadOnlyRoleTemplate(unsupportedWorkflowRef),
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
  for (const bypass of [
    'command "${aws_cli}" s3api list-buckets',
    "/usr/local/bin/aws s3api list-buckets",
    "/opt/tools/aws s3api list-buckets",
    "command aws s3api list-buckets"
  ]) {
    assert.throws(
      () => validateIdentityWorkflow(`${IDENTITY_WORKFLOW}\n${bypass}\n`),
      /OIDC_IDENTITY_AWS_CLI_REFERENCES/
    );
  }
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace(
          "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
          "^[A-Za-z0-9_-]{20,}$"
        )
      ),
    /OIDC_IDENTITY_WORKFLOW_MARKERS/
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
  for (const bypass of [
    'command "${aws_cli}" s3api list-buckets',
    "/usr/local/bin/aws s3api list-buckets",
    "/opt/tools/aws s3api list-buckets",
    "command aws s3api list-buckets"
  ]) {
    assert.throws(
      () => validateReadOnlyRunner(`${READ_ONLY_RUNNER}\n${bypass}\n`),
      /OIDC_READ_ONLY_AWS_CLI_REFERENCES/
    );
  }
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
          "^[A-Za-z0-9_-]{42}$"
        )
      ),
    /OIDC_READ_ONLY_RUNNER_MARKERS/
  );
});

test("receipt secret contract is canonical unpadded Base64URL for 32 bytes", () => {
  const pattern = new RegExp(sourceContract.EXACT_RECEIPT_SECRET_PATTERN);
  const encoded = Buffer.alloc(32, 0xab).toString("base64url");
  assert.equal(encoded.length, 43);
  assert.match(encoded, pattern);
  assert.equal(Buffer.from(encoded, "base64url").length, 32);
  for (const rejected of [
    `${encoded}=`,
    encoded.slice(1),
    `${encoded.slice(0, -1)}B`,
    "x".repeat(43)
  ]) {
    assert.doesNotMatch(rejected, pattern);
  }
});

test("underlying preflight inventory is exact and cannot bypass its reader", () => {
  assert.deepEqual(
    validateUnderlyingPreflight(
      PREFLIGHT_RUNNER,
      PREFLIGHT_VALIDATOR
    ),
    sourceContract.EXACT_PREFLIGHT_RUNTIME_CALL_INVENTORY
  );
  assert.throws(
    () =>
      validateUnderlyingPreflight(
        PREFLIGHT_RUNNER.replace(
          'Object.freeze(["budgets", "describe-subscribers-for-notification", 4])',
          'Object.freeze(["budgets", "describe-subscribers-for-notification", 5])'
        ),
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_INVENTORY/
  );
  assert.throws(
    () =>
      validateUnderlyingPreflight(
        `${PREFLIGHT_RUNNER}\nreadAwsJson("us-east-1", "s3api", "list-buckets");\n`,
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_READER_BYPASS/
  );
  assert.throws(
    () =>
      validateUnderlyingPreflight(
        `${PREFLIGHT_RUNNER}\nawsJson("us-east-1", "s3api", "list-buckets");\n`,
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_READER_BYPASS/
  );
  assert.throws(
    () =>
      validateUnderlyingPreflight(
        `${PREFLIGHT_RUNNER}\nspawnSync(trustedAwsCliExecutable(), ["s3api", "list-buckets"]);\n`,
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_READER_BYPASS/
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
