import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  __test as sourceContract,
  validateIdentityWorkflow,
  validateActionsCheckoutNormalizer,
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
const ACTIONS_CHECKOUT_NORMALIZER = source(
  "scripts/normalize-actions-checkout.js"
);
const PREFLIGHT_RUNNER = source("scripts/gate2-aws-preflight.js");
const PREFLIGHT_VALIDATOR = source(
  "src/cloud/aws-gate2-preflight.js"
);

function oidcRequestUrlPattern(sourceText) {
  const match = sourceText.match(
    /^\s*oidc_request_url_pattern='([^'\n]+)'$/mu
  );
  assert.ok(match, "OIDC request URL pattern must be present exactly");
  assert.equal(
    sourceText.match(/^\s*oidc_request_url_pattern=/gmu)?.length,
    1,
    "OIDC request URL pattern must have one definition"
  );
  return match[1];
}

function acceptsOidcRequestUrl(pattern, requestUrl) {
  const result = spawnSync(
    "/bin/bash",
    [
      "--noprofile",
      "--norc",
      "-c",
      '(( ${#1} >= 1 && ${#1} <= 2048 )) && [[ "$1" =~ $2 ]]',
      "oidc-url-guard",
      requestUrl,
      pattern
    ],
    { encoding: "utf8" }
  );
  assert.equal(result.signal, null);
  return result.status === 0;
}

test("OIDC source receipt remains source-only with provider acceptance pending", () => {
  const receipt = verifyAwsOidcPreflightSource();

  assert.equal(
    receipt.schemaVersion,
    "prooftoact.aws-oidc-preflight-source-verification.v2"
  );
  assert.equal(
    receipt.status,
    "SOURCE_CONTRACT_PASS_ACCEPTED_PROVIDER_RECEIPT_PENDING"
  );
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.providerSetup, "EXTERNAL_STATE_NOT_ATTESTED");
  assert.equal(receipt.providerExecution, "OUTSIDE_SOURCE_RECEIPT");
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
  assert.equal(receipt.reviewedFiles.length, 8);
  assert(
    receipt.reviewedFiles.some(
      (entry) => entry.path === "scripts/normalize-actions-checkout.js"
    )
  );
  assert.ok(Object.values(receipt.checks).every((value) => value === true));
  assert.match(receipt.claimBoundary, /does not prove GitHub environment/);
  assert.match(receipt.claimBoundary, /grants no provider authority/);
});

test("OIDC source contract binds the exact protected checkout normalizer", () => {
  assert.equal(
    validateActionsCheckoutNormalizer(ACTIONS_CHECKOUT_NORMALIZER),
    ACTIONS_CHECKOUT_NORMALIZER
  );
  for (const mutation of [
    ACTIONS_CHECKOUT_NORMALIZER.replace(
      'environment?.GITHUB_JOB === "read-only-preflight"',
      'environment?.GITHUB_JOB === "verify"'
    ),
    ACTIONS_CHECKOUT_NORMALIZER.replace(
      'environment?.GITHUB_EVENT_NAME === "workflow_dispatch"',
      'environment?.GITHUB_EVENT_NAME === "push"'
    ),
    ACTIONS_CHECKOUT_NORMALIZER.replace(
      "environment?.EXPECTED_OFFICIAL_MAIN_COMMIT ===\n      environment?.GITHUB_SHA",
      "true"
    ),
    `${ACTIONS_CHECKOUT_NORMALIZER}\n// expanded context\n`
  ]) {
    assert.notEqual(mutation, ACTIONS_CHECKOUT_NORMALIZER);
    assert.throws(
      () => validateActionsCheckoutNormalizer(mutation),
      /OIDC_ACTIONS_CHECKOUT_NORMALIZER_(?:MARKERS|SHA256)/
    );
  }
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
  assert.match(
    IDENTITY_WORKFLOW,
    /AWS_APPROVED_ACCOUNT_ID_SHA256: \$\{\{ secrets\.AWS_APPROVED_ACCOUNT_ID_SHA256 \}\}/u
  );
  assert.doesNotMatch(
    IDENTITY_WORKFLOW,
    /vars\.AWS_APPROVED_ACCOUNT_ID_SHA256/u
  );

  assert.deepEqual(sourceContract.EXPECTED_IDENTITY_FAILURE_STAGES, [
    "AWS_IDENTITY_STAGE_STS_ASSUME_REQUEST",
    "AWS_IDENTITY_STAGE_STS_ASSUME_RECEIPT",
    "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
    "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
    "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
    "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
    "AWS_IDENTITY_STAGE_STS_CALLER_REQUEST",
    "AWS_IDENTITY_STAGE_STS_CALLER_RECEIPT",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION",
    "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT",
    "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
    "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP"
  ]);
  assert.deepEqual(
    sourceContract.EXPECTED_IDENTITY_FAILURE_STAGE_ALLOWLIST,
    [
      "AWS_IDENTITY_STAGE_STS_ASSUME_REQUEST",
      "AWS_IDENTITY_STAGE_STS_ASSUME_RECEIPT",
      "AWS_IDENTITY_STAGE_STS_ASSUME_FIELDS",
      "AWS_IDENTITY_STAGE_STS_CALLER_REQUEST",
      "AWS_IDENTITY_STAGE_STS_CALLER_RECEIPT",
      "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
      "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION",
      "AWS_IDENTITY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
      "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT"
    ]
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace(
          "fail_closed_stage AWS_IDENTITY_STAGE_STS_CALLER_RECEIPT",
          "fail_closed_stage AWS_IDENTITY_STAGE_UNREVIEWED"
        )
      ),
    /OIDC_IDENTITY_WORKFLOW_FAILURE_STAGES/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace(
          "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT) ;;",
          "AWS_IDENTITY_STAGE_ENCRYPTED_RECEIPT | \\\n              AWS_IDENTITY_STAGE_UNREVIEWED) ;;"
        )
      ),
    /OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_ALLOWLIST/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace("*) fail_closed ;;", "*) ;;")
      ),
    /OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_FUNCTION/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW +
          '\nfail_closed_stage "$AWS_ACCOUNT_ID"\n'
      ),
    /OIDC_IDENTITY_WORKFLOW_FAILURE_STAGE_REFERENCES/
  );

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
        IDENTITY_WORKFLOW.replace(
          '[[ "$oidc_request_url" =~ $oidc_request_url_pattern ]] || fail_closed',
          "true"
        )
      ),
    /OIDC_IDENTITY_WORKFLOW_MARKERS/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace(
          "(pipelines|run-actions-[0-9]+-[a-z0-9]([a-z0-9-]*[a-z0-9])?)\\.actions\\.githubusercontent\\.com",
          ".*"
        )
      ),
    /OIDC_IDENTITY_WORKFLOW_MARKERS/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        `${IDENTITY_WORKFLOW}\nhttps://pipelines.actions.githubusercontent.com/\n`
      ),
    /OIDC_IDENTITY_WORKFLOW_MINIMAL/
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
  assert.throws(
    () =>
      validateIdentityWorkflow(
        IDENTITY_WORKFLOW.replace(
          'gnupg_home=""',
          'gnupg_home="/tmp"'
        )
      ),
    /OIDC_IDENTITY_GPG_REFERENCES/
  );
  assert.throws(
    () =>
      validateIdentityWorkflow(
        `${IDENTITY_WORKFLOW}\ncommand gpg --version\n`
      ),
    /OIDC_IDENTITY_GPG_REFERENCES/
  );
  for (const requiredGpgControl of [
    "GNUPGHOME",
    '--homedir "$gnupg_home"',
    "--no-symkey-cache",
    '[[ "$gnupg_mode" == "700" ]] || fail_closed',
    '/usr/bin/gpgconf --homedir "$gnupg_home" --kill all',
    '/usr/bin/rm -rf -- "$gnupg_home"'
  ]) {
    assert.throws(
      () =>
        validateIdentityWorkflow(
          IDENTITY_WORKFLOW.replace(requiredGpgControl, "")
        ),
      /OIDC_IDENTITY_(?:WORKFLOW_MARKERS|GPG_REFERENCES)/
    );
  }
});

test("OIDC request URL guards accept GitHub regional hosts and reject authority confusion", () => {
  const identityPattern = oidcRequestUrlPattern(IDENTITY_WORKFLOW);
  const readOnlyPattern = oidcRequestUrlPattern(READ_ONLY_RUNNER);
  assert.equal(identityPattern, readOnlyPattern);

  for (const accepted of [
    "https://pipelines.actions.githubusercontent.com/_apis/distributedtask/hubs/build/plans/1/jobs/2/idtoken?api-version=2.0",
    "https://run-actions-2-azure-eastus.actions.githubusercontent.com/_apis/distributedtask/hubs/build/plans/1/jobs/2/idtoken?api-version=2.0"
  ]) {
    assert.equal(acceptsOidcRequestUrl(identityPattern, accepted), true);
  }

  for (const rejected of [
    "http://pipelines.actions.githubusercontent.com/idtoken?api-version=2.0",
    "https://actions.githubusercontent.com/idtoken?api-version=2.0",
    "https://foo.actions.githubusercontent.com/idtoken?api-version=2.0",
    "https://run-actions-2-azure-eastus-.actions.githubusercontent.com/idtoken?api-version=2.0",
    "https://foo.bar.actions.githubusercontent.com/idtoken?api-version=2.0",
    "https://foo.actions.githubusercontent.com.evil.example/idtoken?api-version=2.0",
    "https://foo.actions.githubusercontent.com:443/idtoken?api-version=2.0",
    "https://user" +
      "@foo.actions.githubusercontent.com/idtoken?api-version=2.0",
    "https://foo.actions.githubusercontent.com/idtoken",
    "https://foo.actions.githubusercontent.com/idtoken?api-version=2.0#fragment",
    "https://foo.actions.githubusercontent.com/id token?api-version=2.0",
    `https://run-actions-2-azure-eastus.actions.githubusercontent.com/${"x".repeat(2048)}?api-version=2.0`
  ]) {
    assert.equal(acceptsOidcRequestUrl(identityPattern, rejected), false);
  }
});

test("read-only workflow stays separately protected and action-pinned", () => {
  assert.doesNotThrow(() => validateReadOnlyWorkflow(READ_ONLY_WORKFLOW));

  assert.match(
    READ_ONLY_WORKFLOW,
    /diagnostic_only:\n\s+description: Validate the protected pre-AWS runtime contract and stop before token exchange\n\s+required: true\n\s+default: true\n\s+type: boolean/u
  );

  assert.match(
    READ_ONLY_WORKFLOW,
    /AWS_APPROVED_ACCOUNT_ID_SHA256: \$\{\{ secrets\.AWS_APPROVED_ACCOUNT_ID_SHA256 \}\}/u
  );
  assert.doesNotMatch(
    READ_ONLY_WORKFLOW,
    /vars\.AWS_APPROVED_ACCOUNT_ID_SHA256/u
  );

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
  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        READ_ONLY_WORKFLOW.replace(
          "secrets.AWS_APPROVED_ACCOUNT_ID_SHA256",
          "vars.AWS_APPROVED_ACCOUNT_ID_SHA256"
        )
      ),
    /OIDC_READ_ONLY_WORKFLOW_(?:MARKERS|BOUNDARY)/
  );
  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        READ_ONLY_WORKFLOW.replace("diagnostic_only:", "diagnostics:")
      ),
    /OIDC_READ_ONLY_WORKFLOW_MARKERS/
  );
  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        READ_ONLY_WORKFLOW.replace("default: true", "default: false")
      ),
    /OIDC_READ_ONLY_WORKFLOW_DIAGNOSTIC_INPUT/
  );
  assert.throws(
    () =>
      validateReadOnlyWorkflow(
        `${READ_ONLY_WORKFLOW}\nrun: /usr/bin/curl https://example.invalid\n`
      ),
    /OIDC_READ_ONLY_WORKFLOW_RUN_COMMANDS/
  );
});

test("read-only runner rejects direct mutation calls and shell tracing", () => {
  assert.doesNotThrow(() => validateReadOnlyRunner(READ_ONLY_RUNNER));

  assert.deepEqual(
    sourceContract.EXPECTED_READ_ONLY_FAILURE_STAGE_ALLOWLIST,
    [
      "AWS_READ_ONLY_STAGE_RUNTIME_CONTEXT",
      "AWS_READ_ONLY_STAGE_INHERITED_ENVIRONMENT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY",
      "AWS_READ_ONLY_STAGE_OIDC_ENDPOINT",
      "AWS_READ_ONLY_STAGE_SOURCE_BINDING",
      "AWS_READ_ONLY_STAGE_NODE_DISCOVERY",
      "AWS_READ_ONLY_STAGE_NODE_PATH",
      "AWS_READ_ONLY_STAGE_NODE_OWNER",
      "AWS_READ_ONLY_STAGE_NODE_METADATA",
      "AWS_READ_ONLY_STAGE_NODE_INTEGRITY",
      "AWS_READ_ONLY_STAGE_NODE_VERSION",
      "AWS_READ_ONLY_STAGE_AWS_PATH",
      "AWS_READ_ONLY_STAGE_AWS_METADATA",
      "AWS_READ_ONLY_STAGE_GPG_METADATA",
      "AWS_READ_ONLY_STAGE_TEMPORARY_STATE",
      "AWS_READ_ONLY_STAGE_OIDC_REQUEST",
      "AWS_READ_ONLY_STAGE_OIDC_RECEIPT",
      "AWS_READ_ONLY_STAGE_OIDC_CLAIMS",
      "AWS_READ_ONLY_STAGE_STS_ASSUME_REQUEST",
      "AWS_READ_ONLY_STAGE_STS_ASSUME_RECEIPT",
      "AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS",
      "AWS_READ_ONLY_STAGE_REGION_REQUEST",
      "AWS_READ_ONLY_STAGE_REGION_RECEIPT",
      "AWS_READ_ONLY_STAGE_QUOTA_REQUEST",
      "AWS_READ_ONLY_STAGE_QUOTA_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_01",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_02",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_03",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_04",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_05",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_06",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_07",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_08",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_09",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_10",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_11",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_12",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_13",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_14",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_15",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_16",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_17",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CHILD_ENVIRONMENT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SOURCE_CHECKOUT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXPECTED_IDENTITY",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CALL_INVENTORY",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_CALLER_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BOOTSTRAP_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BUDGET_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_NOTIFICATION_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SUBSCRIBER_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_COST_REQUEST_PREPARE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_BUCKET_POLICY_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_STACK_CENSUS_RECEIPT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_SNAPSHOT_COMPLETE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_SOURCE_IDENTITY",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BOOTSTRAP",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_NOTIFICATIONS",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_STACK_ABSENCE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_ARTIFACT_BUCKET",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_COST",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_EXPOSURE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_MODEL",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_RECEIPT_ASSEMBLY",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_NAME",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_TYPE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_TIME_UNIT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_SCOPE_COST_FILTERS",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_SCOPE_FILTER_EXPRESSION",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_SCOPE_BILLING_VIEW",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_FIXED_AUTO_ADJUST",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_FIXED_PLANNED_LIMITS",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_METRICS_BASIS",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_COST_TYPES_BASIS",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_PERIOD_START",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_PERIOD_END",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_PERIOD_ORDER",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_PERIOD_NOT_STARTED",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_PERIOD_EXPIRED",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_PERIOD_RELEASE_HORIZON",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_LIMIT_UNIT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_LIMIT_AMOUNT_FORMAT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_LIMIT_NONNEGATIVE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_LIMIT_FIXED",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_ACTUAL_SPEND_UNIT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_ACTUAL_SPEND_AMOUNT_FORMAT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_ACTUAL_SPEND_NONNEGATIVE",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_VALIDATE_BUDGET_ACTUAL_SPEND_CEILING",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_RECEIPT_OUTPUT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_ARGUMENT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_UNCLASSIFIED_CAUGHT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCAUGHT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TIMEOUT",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXECUTION",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TERMINATED",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCLASSIFIED",
      "AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_RECEIPT",
      "AWS_READ_ONLY_STAGE_SANITIZED_RECEIPT",
      "AWS_READ_ONLY_STAGE_PRIVACY_REDACTION",
      "AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_PREPARE",
      "AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION",
      "AWS_READ_ONLY_STAGE_ENCRYPTED_RECEIPT",
      "AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_CLEANUP",
      "AWS_READ_ONLY_STAGE_SENSITIVE_CLEANUP"
    ]
  );
  assert.equal(
    sourceContract.EXPECTED_READ_ONLY_FAILURE_STAGE_REFERENCE_COUNT,
    188
  );
  assert.equal(
    sourceContract.EXPECTED_READ_ONLY_GENERIC_FAILURE_REFERENCE_COUNT,
    2
  );
  assert.deepEqual(
    sourceContract.EXPECTED_READ_ONLY_PREFLIGHT_EXIT_STAGE_MAP,
    [
      "1:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCAUGHT",
      ...Array.from({ length: 17 }, (_, index) =>
        `${40 + index}:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_${String(
          index + 1
        ).padStart(2, "0")}`
      ),
      ...sourceContract.EXACT_PREFLIGHT_RUNTIME_PHASE_FAILURES
        .slice(0, 13)
        .map(
          ({ stage, exitCode }) =>
            `${exitCode}:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_${stage}`
        ),
      ...sourceContract.EXACT_PREFLIGHT_RUNTIME_CONTROL_FAILURES.map(
        ({ stage, exitCode }) =>
          `${exitCode}:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_${stage}`
      ),
      ...sourceContract.EXACT_PREFLIGHT_RUNTIME_PHASE_FAILURES
        .slice(13)
        .map(
          ({ stage, exitCode }) =>
            `${exitCode}:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_${stage}`
        ),
      ...sourceContract.EXACT_PREFLIGHT_RUNTIME_BUDGET_FAILURES.map(
        ({ stage, exitCode }) =>
          `${exitCode}:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_${stage}`
      ),
      "124:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TIMEOUT",
      "125 | 126 | 127:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_EXECUTION",
      "137:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TERMINATED",
      "*:AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCLASSIFIED"
    ]
  );
  assert.match(
    sourceContract.EXPECTED_READ_ONLY_SENSITIVE_CLEANUP_FUNCTION_SHA256,
    /^[0-9a-f]{64}$/u
  );
  assert.match(
    sourceContract.EXPECTED_READ_ONLY_POST_DIAGNOSTIC_EXECUTION_SUFFIX_SHA256,
    /^[0-9a-f]{64}$/u
  );
  assert.match(
    sourceContract.EXPECTED_READ_ONLY_FAILURE_STAGE_SEQUENCE_SHA256,
    /^[0-9a-f]{64}$/u
  );
  assert.match(
    sourceContract.EXPECTED_READ_ONLY_DIAGNOSTIC_BLOCK,
    /AWS_READ_ONLY_DIAGNOSTIC_PASS/u
  );
  assert.equal(
    sourceContract.EXPECTED_READ_ONLY_OUTPUT_COMMAND_COUNT,
    9
  );
  assert.match(
    sourceContract.EXPECTED_READ_ONLY_PRE_DIAGNOSTIC_PREFIX_SHA256,
    /^[0-9a-f]{64}$/u
  );
  assert.match(
    READ_ONLY_RUNNER,
    /93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068/u
  );
  assert.match(
    READ_ONLY_RUNNER,
    /runner_uid.*1001.*node_uid.*1000[\s\S]*\/usr\/bin\/getent passwd 1000/u
  );
  assert.doesNotMatch(
    READ_ONLY_RUNNER,
    /node_mode_value & 0022/u
  );
  assert.equal(
    (READ_ONLY_RUNNER.match(/(?:aws|crypto)_mode_value & 0022/gu) ?? [])
      .length,
    2
  );
  for (const requiredNodeControl of [
    "/opt/hostedtoolcache/node/22.23.1/x64/bin/node",
    "/usr/bin/getent passwd 1000",
    "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068",
    '[[ "$("$node_cli" --version)" == "v22.23.1" ]]'
  ]) {
    assert.throws(
      () =>
        validateReadOnlyRunner(
          READ_ONLY_RUNNER.replace(requiredNodeControl, "")
        ),
      /OIDC_READ_ONLY_(?:RUNNER_MARKERS|RUNNER_DIAGNOSTIC_BOUNDARY)/
    );
  }

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
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          "fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_AUTHORITY",
          "fail_closed_stage AWS_READ_ONLY_STAGE_UNREVIEWED"
        )
      ),
    /OIDC_READ_ONLY_RUNNER_FAILURE_STAGES/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          "AWS_READ_ONLY_STAGE_SENSITIVE_CLEANUP) ;;",
          "AWS_READ_ONLY_STAGE_SENSITIVE_CLEANUP | \\\n      AWS_READ_ONLY_STAGE_UNREVIEWED) ;;"
        )
      ),
    /OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_ALLOWLIST/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace("*) fail_closed ;;", "*) ;;" )
      ),
    /OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_FUNCTION/
  );
  assert.throws(
    () => validateReadOnlyRunner(`${READ_ONLY_RUNNER}\nfalse || fail_closed\n`),
    /OIDC_READ_ONLY_RUNNER_GENERIC_FAILURE_REFERENCES/
  );
  for (const mutatedExitMap of [
    READ_ONLY_RUNNER.replace(
      "40) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_01 ;;",
      "40) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_READ_02 ;;"
    ),
    READ_ONLY_RUNNER.replace(
      "124) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TIMEOUT ;;",
      "124 | 125) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_TIMEOUT ;;"
    ),
    READ_ONLY_RUNNER.replace(
      "*) fail_closed_stage AWS_READ_ONLY_STAGE_ACCOUNT_PREFLIGHT_PROCESS_UNCLASSIFIED ;;",
      "*) fail_closed_stage \"$preflight_status\" ;;"
    )
  ]) {
    assert.notEqual(mutatedExitMap, READ_ONLY_RUNNER);
    assert.throws(
      () => validateReadOnlyRunner(mutatedExitMap),
      /OIDC_READ_ONLY_RUNNER_(?:FAILURE_STAGES|PREFLIGHT_EXIT_STAGE_MAP|POST_DIAGNOSTIC_EXECUTION_SUFFIX)/
    );
  }
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace('/usr/bin/rm -f -- "$file"', "true")
      ),
    /OIDC_READ_ONLY_RUNNER_SENSITIVE_CLEANUP_FUNCTION/
  );
  for (const weakenedStderrRoute of [
    '"$sts_response" 2>"$error_file")" || fail_closed_stage AWS_READ_ONLY_STAGE_STS_ASSUME_FIELDS',
    '/usr/bin/rm -f -- "$encrypted_receipt" \\\n  2>"$error_file" || fail_closed_stage AWS_READ_ONLY_STAGE_RECEIPT_ENCRYPTION_PREPARE',
    '>"$preflight_receipt" 2>"$error_file"; then',
    '"$sanitized_receipt" 2>"$error_file"; then'
  ]) {
    assert.throws(
      () =>
        validateReadOnlyRunner(
          READ_ONLY_RUNNER.replace(
            weakenedStderrRoute,
            weakenedStderrRoute.replace('2>"$error_file"', "")
          )
        ),
      /OIDC_READ_ONLY_RUNNER_POST_DIAGNOSTIC_EXECUTION_SUFFIX/
    );
  }
  assert.throws(
    () =>
      validateReadOnlyRunner(
        `${READ_ONLY_RUNNER}\nfail_closed_stage "$AWS_ACCOUNT_ID"\n`
      ),
    /OIDC_READ_ONLY_RUNNER_FAILURE_STAGE_REFERENCES/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        `${READ_ONLY_RUNNER}\necho "$AWS_ACCOUNT_ID"\n`
      ),
    /OIDC_READ_ONLY_RUNNER_AUTHORITY_LOGGING/
  );
  for (const secretName of [
    "AWS_APPROVED_ACCOUNT_ID_SHA256",
    "AWS_READ_ONLY_PREFLIGHT_ROLE_ARN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL"
  ]) {
    assert.throws(
      () =>
        validateReadOnlyRunner(
          `${READ_ONLY_RUNNER}\nprintf '%s\\n' "$${secretName}"\n`
        ),
      /OIDC_READ_ONLY_RUNNER_AUTHORITY_LOGGING/
    );
  }
  const diagnosticBlock =
    sourceContract.EXPECTED_READ_ONLY_DIAGNOSTIC_BLOCK;
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          `${diagnosticBlock}\n\n`,
          `${diagnosticBlock}\n\ntrue\n`
        )
      ),
    /OIDC_READ_ONLY_RUNNER_POST_DIAGNOSTIC_EXECUTION_SUFFIX/
  );
  assert.throws(
    () => validateReadOnlyRunner(`${READ_ONLY_RUNNER}\ntrue\n`),
    /OIDC_READ_ONLY_RUNNER_POST_DIAGNOSTIC_EXECUTION_SUFFIX/
  );
  const movedDiagnostic = READ_ONLY_RUNNER.replace(
    `${diagnosticBlock}\n\n`,
    ""
  ).replace("unset oidc_now\n", `unset oidc_now\n\n${diagnosticBlock}\n`);
  assert.throws(
    () => validateReadOnlyRunner(movedDiagnostic),
    /OIDC_READ_ONLY_RUNNER_(?:DIAGNOSTIC_BOUNDARY|POST_DIAGNOSTIC_EXECUTION_SUFFIX)/
  );
  const earlyDiagnostic = READ_ONLY_RUNNER.replace(
    `${diagnosticBlock}\n\n`,
    ""
  ).replace("umask 077\n", `umask 077\n\n${diagnosticBlock}\n`);
  assert.throws(
    () => validateReadOnlyRunner(earlyDiagnostic),
    /OIDC_READ_ONLY_RUNNER_DIAGNOSTIC_BOUNDARY/
  );
  for (const unreviewedNetworkCommand of [
    `"$node_cli" -e 'fetch("https://example.invalid")'`,
    `/usr/bin/python3 -c 'import urllib.request; urllib.request.urlopen("https://example.invalid")'`
  ]) {
    assert.throws(
      () =>
        validateReadOnlyRunner(
          READ_ONLY_RUNNER.replace(
            diagnosticBlock,
            `${unreviewedNetworkCommand}\n${diagnosticBlock}`
          )
        ),
      /OIDC_READ_ONLY_RUNNER_DIAGNOSTIC_BOUNDARY/
    );
  }
  assert.throws(
    () =>
      validateReadOnlyRunner(
        `${READ_ONLY_RUNNER}\nleak="$ACTIONS_ID_TOKEN_REQUEST_TOKEN"\nprintf '%s\\n' "$leak"\n`
      ),
    /OIDC_READ_ONLY_RUNNER_OUTPUT_COMMANDS/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          diagnosticBlock,
          `/usr/bin/curl https://example.invalid\n${diagnosticBlock}`
        )
      ),
    /OIDC_READ_ONLY_RUNNER_DIAGNOSTIC_BOUNDARY/
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
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          '[[ "$oidc_request_url" =~ $oidc_request_url_pattern ]] || fail_closed',
          "true"
        )
      ),
    /OIDC_READ_ONLY_RUNNER_MARKERS/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          "(pipelines|run-actions-[0-9]+-[a-z0-9]([a-z0-9-]*[a-z0-9])?)\\.actions\\.githubusercontent\\.com",
          ".*"
        )
      ),
    /OIDC_READ_ONLY_RUNNER_MARKERS/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        `${READ_ONLY_RUNNER}\nhttps://pipelines.actions.githubusercontent.com/\n`
      ),
    /OIDC_READ_ONLY_RUNNER_MUTATION/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        READ_ONLY_RUNNER.replace(
          'gnupg_home=""',
          'gnupg_home="/tmp"'
        )
      ),
    /OIDC_READ_ONLY_GPG_REFERENCES/
  );
  assert.throws(
    () =>
      validateReadOnlyRunner(
        `${READ_ONLY_RUNNER}\ncommand gpg --version\n`
      ),
    /OIDC_READ_ONLY_GPG_REFERENCES/
  );
  for (const requiredGpgControl of [
    "GNUPGHOME",
    '--homedir "$gnupg_home"',
    "--no-symkey-cache",
    '[[ "$gnupg_mode" == "700" ]] || fail_closed',
    '/usr/bin/gpgconf --homedir "$gnupg_home" --kill all',
    '/usr/bin/rm -rf -- "$gnupg_home"'
  ]) {
    assert.throws(
      () =>
        validateReadOnlyRunner(
          READ_ONLY_RUNNER.replace(requiredGpgControl, "")
        ),
      /OIDC_READ_ONLY_(?:RUNNER_MARKERS|GPG_REFERENCES|RUNNER_SENSITIVE_CLEANUP_FUNCTION)/
    );
  }
});

test("sensitive cleanup attempts later deletions after an earlier failure", () => {
  const cleanupBlock = READ_ONLY_RUNNER.match(
    /^cleanup_sensitive_files\(\) \{\n[\s\S]*?^\}$/mu
  );
  assert.ok(cleanupBlock);
  const temporaryRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "prooftoact-sensitive-cleanup-")
  );
  const blockedDirectory = path.join(temporaryRoot, "blocked-directory");
  const laterSensitiveFile = path.join(temporaryRoot, "later-secret");
  fs.mkdirSync(blockedDirectory);
  fs.writeFileSync(laterSensitiveFile, "synthetic-secret", { mode: 0o600 });
  const shellSource = [
    "set -euo pipefail",
    "set +x",
    `RUNNER_TEMP=${JSON.stringify(temporaryRoot)}`,
    `oidc_response=${JSON.stringify(blockedDirectory)}`,
    `oidc_token=${JSON.stringify(laterSensitiveFile)}`,
    'oidc_header=""',
    'oidc_payload=""',
    'sts_response=""',
    'region_status=""',
    'quota_status=""',
    'preflight_receipt=""',
    'sanitized_receipt=""',
    'passphrase_file=""',
    'error_file=""',
    'gnupg_home=""',
    cleanupBlock[0].replaceAll(
      "/usr/bin/rm",
      process.platform === "linux" ? "/usr/bin/rm" : "/bin/rm"
    ),
    "trap cleanup_sensitive_files EXIT",
    "exit 7"
  ].join("\n");
  try {
    const result = spawnSync(
      "/bin/bash",
      ["--noprofile", "--norc", "-c", shellSource],
      { encoding: "utf8" }
    );
    assert.equal(result.status, 7);
    assert.equal(result.stdout, "");
    assert.equal(
      result.stderr,
      "::error::AWS_READ_ONLY_STAGE_SENSITIVE_CLEANUP\n"
    );
    assert.equal(fs.existsSync(laterSensitiveFile), false);
    assert.equal(fs.existsSync(blockedDirectory), true);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test(
  "hosted Node toolchain satisfies the pinned read-only policy on Linux",
  { skip: process.platform !== "linux" },
  () => {
    const probe = String.raw`set -euo pipefail
fail_probe() {
  local stage="$1"
  case "$stage" in
    NODE_DISCOVERY | NODE_PATH | NODE_OWNER | NODE_METADATA | NODE_INTEGRITY | NODE_VERSION) ;;
    *) stage=NODE_UNKNOWN ;;
  esac
  printf '%s\n' "NODE_TOOLCHAIN_POLICY_FAIL:$stage" >&2
  exit 1
}
node_candidate="$(command -v node)" || fail_probe NODE_DISCOVERY
[[ "$node_candidate" == /* && -x "$node_candidate" ]] || fail_probe NODE_DISCOVERY
node_cli="$(/usr/bin/readlink -f -- "$node_candidate")" || fail_probe NODE_PATH
[[ "$node_cli" == "/opt/hostedtoolcache/node/22.23.1/x64/bin/node" ]] || fail_probe NODE_PATH
node_metadata="$(/usr/bin/stat -Lc '%u:%a:%F' -- "$node_cli")" || fail_probe NODE_METADATA
IFS=':' read -r node_uid node_mode node_type <<<"$node_metadata"
runner_uid="$(/usr/bin/id -u)" || fail_probe NODE_OWNER
node_owner_allowed=false
if [[ "$node_uid" == "0" || "$node_uid" == "$runner_uid" ]]; then
  node_owner_allowed=true
elif [[ "$runner_uid" == "1001" && "$node_uid" == "1000" ]] && \
  ! /usr/bin/getent passwd 1000 >/dev/null; then
  node_owner_allowed=true
fi
[[ "$node_owner_allowed" == "true" ]] || fail_probe NODE_OWNER
[[ "$node_mode" =~ ^[0-7]{3,4}$ && "$node_type" == "regular file" ]] || fail_probe NODE_METADATA
node_mode_value=$((8#$node_mode))
(( (node_mode_value & 0111) != 0 )) || fail_probe NODE_METADATA
node_digest_output="$(/usr/bin/sha256sum "$node_cli")" || fail_probe NODE_INTEGRITY
read -r node_digest node_digest_path <<<"$node_digest_output" || fail_probe NODE_INTEGRITY
[[ -n "$node_digest_path" ]] || fail_probe NODE_INTEGRITY
[[ "$node_digest" == "93956de2e59480474a7b46571da1651180b1a050cdf32641ebec4ce6e478e068" ]] || fail_probe NODE_INTEGRITY
[[ "$("$node_cli" --version)" == "v22.23.1" ]] || fail_probe NODE_VERSION
printf '%s\n' 'NODE_TOOLCHAIN_POLICY_PASS'
`;
    const result = spawnSync(
      "/usr/bin/bash",
      ["--noprofile", "--norc", "-c", probe],
      {
        encoding: "utf8",
        env: {
          PATH: path.dirname(process.execPath)
        }
      }
    );
    assert.equal(
      result.status,
      0,
      result.stderr || "NODE_TOOLCHAIN_POLICY_FAIL"
    );
    assert.equal(result.stdout, "NODE_TOOLCHAIN_POLICY_PASS\n");
    assert.equal(result.stderr, "");
  }
);

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

test(
  "isolated GnuPG home round-trips a synthetic receipt on Linux",
  { skip: process.platform !== "linux" },
  () => {
    const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "prooftoact-gpg-roundtrip-")
    );
    const home = path.join(root, "home");
    const passphrase = path.join(root, "passphrase");
    const input = path.join(root, "receipt.json");
    const encrypted = path.join(root, "receipt.json.gpg");
    const decrypted = path.join(root, "receipt.decrypted.json");
    const fixture = '{"schema":"synthetic.gpg-roundtrip.v1"}\n';
    let shutdown;
    try {
      assert.equal(fs.existsSync("/usr/bin/gpg"), true);
      assert.equal(fs.existsSync("/usr/bin/gpgconf"), true);
      fs.mkdirSync(home, { mode: 0o700 });
      fs.writeFileSync(
        passphrase,
        `${Buffer.alloc(32, 0xab).toString("base64url")}\n`,
        { mode: 0o600 }
      );
      fs.writeFileSync(input, fixture, { mode: 0o600 });

      const common = [
        "--no-options",
        "--homedir",
        home,
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--no-symkey-cache",
        "--passphrase-file",
        passphrase
      ];
      const encrypt = spawnSync(
        "/usr/bin/timeout",
        [
          "--signal=KILL",
          "30s",
          "/usr/bin/gpg",
          ...common,
          "--symmetric",
          "--cipher-algo",
          "AES256",
          "--output",
          encrypted,
          input
        ],
        { stdio: "ignore" }
      );
      assert.equal(encrypt.signal, null);
      assert.equal(encrypt.status, 0);
      assert.ok(fs.statSync(encrypted).size > 0);

      const decrypt = spawnSync(
        "/usr/bin/timeout",
        [
          "--signal=KILL",
          "30s",
          "/usr/bin/gpg",
          ...common,
          "--output",
          decrypted,
          "--decrypt",
          encrypted
        ],
        { stdio: "ignore" }
      );
      assert.equal(decrypt.signal, null);
      assert.equal(decrypt.status, 0);
      assert.equal(fs.readFileSync(decrypted, "utf8"), fixture);
    } finally {
      shutdown = spawnSync(
        "/usr/bin/gpgconf",
        ["--homedir", home, "--kill", "all"],
        { stdio: "ignore" }
      );
      fs.rmSync(root, { recursive: true, force: true });
    }
    assert.equal(shutdown.signal, null);
    assert.equal(shutdown.status, 0);
    assert.equal(fs.existsSync(root), false);
  }
);

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
        PREFLIGHT_RUNNER.replace("exitCode: 40", "exitCode: 56"),
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_FAILURE_MAP/
  );
  assert.throws(
    () =>
      validateUnderlyingPreflight(
        PREFLIGHT_RUNNER.replace(
          "if (error instanceof AwsPreflightRuntimeReadFailure) {",
          "if (false)"
        ),
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_(?:CALLS|SOURCE_SHA256)/
  );
  assert.throws(
    () =>
      validateUnderlyingPreflight(
        `${PREFLIGHT_RUNNER}\nprocess.stderr.write(result.stderr);\n`,
        PREFLIGHT_VALIDATOR
      ),
    /OIDC_UNDERLYING_PREFLIGHT_RAW_FAILURE_OUTPUT/
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
  const diagnosticContractMutations = [
    PREFLIGHT_RUNNER.replace(
      "`TIDEPROOF_GATE2_AWS_PREFLIGHT_FAILED:${failure.stage}\\n`",
      "`TIDEPROOF_GATE2_AWS_PREFLIGHT_FAILED:${error.message}\\n`"
    ),
    PREFLIGHT_RUNNER.replace(
      "AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES[error.index]",
      "AWS_GATE2_PREFLIGHT_RUNTIME_FAILURES[0]"
    ),
    PREFLIGHT_RUNNER.replace(
      "AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[budgetFailureIndex]",
      "AWS_GATE2_PREFLIGHT_RUNTIME_BUDGET_FAILURES[0]"
    ),
    PREFLIGHT_RUNNER.replace(
      "throw new AwsPreflightRuntimeReadFailure(failureIndex)",
      "throw new AwsPreflightRuntimeReadFailure(0)"
    ),
    PREFLIGHT_RUNNER.replace(
      "return AWS_GATE2_PREFLIGHT_RUNTIME_PHASE_FAILURES[15];",
      "return { stage: error.message, exitCode: 85 };"
    ),
    PREFLIGHT_RUNNER.replace(
      'Object.freeze({ stage: "UNCLASSIFIED_CAUGHT", exitCode: 85 })',
      'Object.freeze({ stage: "UNCLASSIFIED_CAUGHT", exitCode: 0 })'
    ),
    PREFLIGHT_RUNNER.replace(
      "const defaults = phase(0, () => {",
      "const defaults = phase(1, () => {"
    ),
    PREFLIGHT_RUNNER.replace(
      "createAwsGate2PreflightDiagnosticContext();",
      "Object.freeze({});"
    ),
    PREFLIGHT_RUNNER.replace(
      "consumeAwsGate2PreflightBudgetFailure(error, diagnosticContext)",
      "consumeAwsGate2PreflightBudgetFailure(error, null)"
    ),
    PREFLIGHT_RUNNER.replace(
      "writeAwsPreflightRuntimeFailure(error, diagnosticContext);",
      "writeAwsPreflightRuntimeFailure(error);"
    )
  ];
  for (const mutatedRunner of diagnosticContractMutations) {
    assert.notEqual(mutatedRunner, PREFLIGHT_RUNNER);
    assert.throws(
      () =>
        validateUnderlyingPreflight(mutatedRunner, PREFLIGHT_VALIDATOR),
      /OIDC_UNDERLYING_PREFLIGHT_(?:CALLS|FAILURE_MAP|SOURCE_SHA256)/
    );
  }

  const diagnosticValidatorMutations = [
    PREFLIGHT_VALIDATOR.replace(
      "const sourceIdentity = validate(0, () => {",
      "const sourceIdentity = validate(1, () => {"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "const exposure = validate(7, () => {",
      "const exposure = validate(6, () => {"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "throw new AwsGate2PreflightControlFailure(index);",
      "throw error;"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "throw createAwsGate2PreflightBudgetFailure(\n      index,\n      invocationToken\n    );",
      "throw error;"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "budgetCheck(8, () =>",
      "budgetCheck(9, () =>"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "state.invocationToken !== diagnosticContext ||",
      "false ||"
    ),
    PREFLIGHT_VALIDATOR.replace(
      ') !== "settled" ||',
      ') !== "fresh" ||'
    ),
    PREFLIGHT_VALIDATOR.replace(
      "Object.freeze({ ...state, consumed: true })",
      "Object.freeze({ ...state, consumed: false })"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "return Object.freeze(error);",
      "return error;"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "function createAwsGate2PreflightBudgetFailure(",
      "export function createAwsGate2PreflightBudgetFailure("
    ),
    PREFLIGHT_VALIDATOR.replace(
      "? beginAwsGate2PreflightDiagnosticContext(diagnosticContext)",
      "? diagnosticContext"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "settleAwsGate2PreflightDiagnosticContext(\n        diagnosticInvocationToken\n      );",
      "void diagnosticInvocationToken;"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "value.length === 1",
      "value.length >= 1"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "value[0] === EXPECTED_BUDGET_COST_BASIS",
      "value.includes(EXPECTED_BUDGET_COST_BASIS)"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "hasExpectedBudgetMetrics(budget?.Metrics)",
      "true"
    ),
    PREFLIGHT_VALIDATOR.replace(
      "hasExpectedCostTypes(budget?.CostTypes)",
      "true"
    )
  ];
  for (const mutatedValidator of diagnosticValidatorMutations) {
    assert.notEqual(mutatedValidator, PREFLIGHT_VALIDATOR);
    assert.throws(
      () => validateUnderlyingPreflight(PREFLIGHT_RUNNER, mutatedValidator),
      /OIDC_UNDERLYING_PREFLIGHT_(?:IDENTITIES|BUDGET_PROVENANCE|VALIDATOR_SHA256)/
    );
  }
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
