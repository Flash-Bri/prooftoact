import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  RELEASE_COST_SURFACE_COUNT,
  assertBootstrapContract,
  assertBudgetReceipt,
  assertGate2TemplateContract,
  assertPrivateRecoveryBootstrapCostContract,
  assertPrivateRecoveryStackCostContract,
  validateReleaseCostReceipt,
  validateManifest,
  verifyReleaseCost
} from "../scripts/verify-release-cost.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HEX = "a".repeat(64);

function fixtureManifest(overrides = {}) {
  return {
    schema: __test.MANIFEST_SCHEMA,
    status: __test.MANIFEST_STATUS,
    reviewedOn: "2026-07-31",
    claimBoundary: "Fixture current-source cost boundary.",
    limits: { ...__test.EXPECTED_LIMITS },
    retainedMonthlyCost: structuredClone(
      __test.EXPECTED_RETAINED_MONTHLY_COST
    ),
    budgetAlerts: structuredClone(__test.EXPECTED_BUDGET_ALERTS),
    forbiddenResourceTypes: [...__test.EXPECTED_FORBIDDEN_RESOURCE_TYPES],
    unapprovedPurchaseClasses: [
      ...__test.EXPECTED_UNAPPROVED_PURCHASE_CLASSES
    ],
    surfaces: Object.entries(__test.EXPECTED_SURFACES).map(
      ([id, surface]) => ({
        id,
        path: surface.path,
        role: surface.role,
        sha256: HEX
      })
    ),
    finalReleaseRequirements: [
      ...__test.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    finalReleaseReady: false,
    ...overrides
  };
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(new URL(`../${relativePath}`, import.meta.url)));
}

test("current source cost guards match the reviewed non-final boundary", () => {
  const receipt = verifyReleaseCost({ rootDir: ROOT });
  assert.equal(receipt.status, "CURRENT_COST_GUARDS_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.surfaceCount, 20);
  assert.equal(receipt.budgetAlertCount, 4);
  assert.equal(receipt.forbiddenResourceTypeCount, 5);
  assert.equal(receipt.unapprovedPurchaseClassCount, 5);
  assert.equal(receipt.boundedFunctionCount, 10);
  assert.equal(receipt.logGroupCount, 11);
  assert.equal(
    Object.values(receipt.checks).every((value) => value === true),
    true
  );
});

test("cost manifest binds the bounded OIDC preflight lane", () => {
  const surfaces = __test.EXPECTED_SURFACES;
  for (const [id, path] of [
    ["aws-oidc-read-only-ledger", "docs/AWS_OIDC_PREFLIGHT.md"],
    [
      "aws-oidc-read-only-role-template",
      "infra/aws/oidc-read-only-preflight-role-template.json"
    ],
    [
      "aws-oidc-read-only-runner",
      "scripts/run-aws-oidc-read-only-preflight.sh"
    ],
    [
      "aws-oidc-read-only-workflow",
      ".github/workflows/aws-oidc-read-only-preflight.yml"
    ]
  ]) {
    assert.equal(surfaces[id]?.path, path);
  }
});

test("cost receipt contract is shared and rejects stale surface counts", () => {
  const receipt = verifyReleaseCost({ rootDir: ROOT });
  assert.equal(validateReleaseCostReceipt(receipt), receipt);
  for (const offset of [-1, 1]) {
    const stale = structuredClone(receipt);
    stale.surfaceCount = RELEASE_COST_SURFACE_COUNT + offset;
    assert.throws(
      () => validateReleaseCostReceipt(stale),
      /RELEASE_COST_RECEIPT_CONTRACT/
    );
  }
});

test("cost guard rejects semantic metric cardinality expansion", () => {
  for (const [file, service] of [
    ["infra/aws/lambda/authority.cjs", "authority"],
    ["infra/aws/lambda/boundary.cjs", "boundary"]
  ]) {
    const source = fs.readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    assert.equal(
      __test.assertSemanticMetricCardinality(
        source,
        service,
        "RELEASE_COST_TEST_METRIC_CARDINALITY"
      ),
      undefined
    );
    const expanded = source.replace(
      'Dimensions: [["Deployment", "Service"]]',
      'Dimensions: [["Deployment", "Service", "Request"]]'
    );
    assert.throws(
      () =>
        __test.assertSemanticMetricCardinality(
          expanded,
          service,
          "RELEASE_COST_TEST_METRIC_CARDINALITY"
        ),
      /RELEASE_COST_TEST_METRIC_CARDINALITY/
    );
  }
});

test("cost manifest rejects final approval, arithmetic drift, or surface drift", () => {
  assert.equal(validateManifest(fixtureManifest()).finalReleaseReady, false);
  assert.throws(
    () => validateManifest(fixtureManifest({ finalReleaseReady: true })),
    /RELEASE_COST_MANIFEST_BOUNDARY/
  );

  const changedLimit = fixtureManifest();
  changedLimit.limits.effectiveAwsSpendCeilingUsd = 15;
  assert.throws(
    () => validateManifest(changedLimit),
    /RELEASE_COST_MANIFEST_BOUNDARY/
  );

  const changedSurface = fixtureManifest();
  changedSurface.surfaces[0].path = "infra/aws/other.json";
  assert.throws(
    () => validateManifest(changedSurface),
    /RELEASE_COST_MANIFEST_SURFACE/
  );

  for (const mutate of [
    (posture) => { posture.totalRetainedSecretCount = 7; },
    (posture) => { posture.secretsManagerMonthlyEstimateUsd = 2.8; },
    (posture) => { posture.maximumMonthlyExposureUsd = 5.01; },
    (posture) => { posture.activationBlockedUntilAuthorization = false; }
  ]) {
    const changedPosture = fixtureManifest();
    mutate(changedPosture.retainedMonthlyCost);
    assert.throws(
      () => validateManifest(changedPosture),
      /RELEASE_COST_MANIFEST_BOUNDARY/
    );
  }
});

test("bootstrap contract rejects a weakened budget or alert", () => {
  const template = readJson("infra/aws/bootstrap-template.json");
  assert.equal(assertBootstrapContract(template), true);

  const raisedBudget = structuredClone(template);
  raisedBudget.Resources.AccountBudget.Properties.Budget.BudgetLimit.Amount = 25;
  assert.throws(
    () => assertBootstrapContract(raisedBudget),
    /RELEASE_COST_BOOTSTRAP_BUDGET/
  );

  const missingAlert = structuredClone(template);
  missingAlert.Resources.AccountBudget.Properties.NotificationsWithSubscribers.pop();
  assert.throws(
    () => assertBootstrapContract(missingAlert),
    /RELEASE_COST_BOOTSTRAP_BUDGET/
  );
});

test("Gate Two template contract rejects fixed-charge or expanded runtime resources", () => {
  const template = readJson("infra/aws/gate2-template.json");
  assert.deepEqual(assertGate2TemplateContract(template), {
    boundedFunctionCount: 10,
    logGroupCount: 11
  });

  const fixedCharge = structuredClone(template);
  fixedCharge.Resources.UnreviewedNatGateway = {
    Type: "AWS::EC2::NatGateway",
    Properties: {}
  };
  assert.throws(
    () => assertGate2TemplateContract(fixedCharge),
    /RELEASE_COST_GATE2_FIXED_CHARGE_RESOURCE/
  );

  const expandedMetrics = structuredClone(template);
  expandedMetrics.Resources.UnreviewedSemanticAlarm =
    structuredClone(template.Resources.BoundarySemanticFailureAlarm);
  assert.throws(
    () => assertGate2TemplateContract(expandedMetrics),
    /RELEASE_COST_GATE2_SEMANTIC_ALARMS/
  );

  const expanded = structuredClone(template);
  expanded.Resources.DemoFunction.Properties.ReservedConcurrentExecutions = 9;
  assert.throws(
    () => assertGate2TemplateContract(expanded),
    /RELEASE_COST_GATE2_FUNCTION_DemoFunction/
  );
});

test("private recovery forecast binds retained secret, bounded runtime, and one-day logs", async () => {
  const bootstrap = readJson(
    "infra/aws/private-recovery-query-bootstrap-role-stack.json"
  );
  assert.equal(assertPrivateRecoveryBootstrapCostContract(bootstrap), true);
  const { buildPrivateRecoveryQueryTemplate } = await import(
    "../src/cloud/private-recovery-query-template.js"
  );
  const stack = buildPrivateRecoveryQueryTemplate();
  assert.equal(assertPrivateRecoveryStackCostContract(stack), true);

  const extraSecret = structuredClone(bootstrap);
  extraSecret.Resources.UnreviewedSecret = {
    Type: "AWS::SecretsManager::Secret",
    Properties: { Name: "unreviewed" }
  };
  assert.throws(
    () => assertPrivateRecoveryBootstrapCostContract(extraSecret),
    /RELEASE_COST_PRIVATE_RECOVERY_SECRET_COUNT/
  );

  const longLogs = structuredClone(stack);
  longLogs.Resources.PrivateRecoveryLogGroup.Properties.RetentionInDays = 30;
  assert.throws(
    () => assertPrivateRecoveryStackCostContract(longLogs),
    /RELEASE_COST_PRIVATE_RECOVERY_LOG_POSTURE/
  );
});

test("historical budget receipt remains explicit about absent spend evidence", () => {
  const receipt = readJson("evidence/gate2-cost-guard-2026-07-30.json");
  assert.equal(assertBudgetReceipt(receipt), true);

  const overstated = structuredClone(receipt);
  overstated.awsSpendClaim = "current_spend_verified";
  assert.throws(
    () => assertBudgetReceipt(overstated),
    /RELEASE_COST_GUARD_RECEIPT/
  );

  const deployed = structuredClone(receipt);
  deployed.mainGateTwoStackDeployed = true;
  assert.throws(
    () => assertBudgetReceipt(deployed),
    /RELEASE_COST_GUARD_RECEIPT/
  );
});
