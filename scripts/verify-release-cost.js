import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { AWS_GATE2_PREFLIGHT_DEFAULTS } from "../src/cloud/aws-gate2-preflight.js";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "RELEASE_COST_MANIFEST.json";
const MANIFEST_SCHEMA = "tideproof.release-cost-manifest.v1";
const MANIFEST_STATUS =
  "CURRENT_SOURCE_COST_GUARDS_REVIEWED_LIVE_SPEND_PENDING";
const RECEIPT_SCHEMA = "tideproof.release-cost-verification.v1";
const HEX_64 = /^[0-9a-f]{64}$/;

const EXPECTED_LIMITS = Object.freeze({
  awsBudgetLimitUsd: 15,
  dailyStopUsd: 5,
  effectiveAwsSpendCeilingUsd: 13.14,
  expectedMeteredSpendHighUsd: 12,
  expectedMeteredSpendLowUsd: 3,
  minimumBudgetCoverageEnd: "2026-09-16T00:00:00.000Z",
  preflightAllowanceReserveUsd: 0.02,
  preflightObservedAwsRejectAtUsd: 13.12,
  projectCostWindowStart: "2026-07-01",
  recordedNonAwsSpendUsd: 11.86,
  releaseHorizonEnd: "2026-09-15",
  totalProjectExposureCeilingUsd: 25,
  unexplainedSpendStopUsd: 3
});

const EXPECTED_BUDGET_ALERTS = Object.freeze([
  Object.freeze({
    metric: "ACTUAL",
    comparison: "GREATER_THAN",
    thresholdUsd: 1,
    thresholdType: "ABSOLUTE_VALUE"
  }),
  Object.freeze({
    metric: "ACTUAL",
    comparison: "GREATER_THAN",
    thresholdUsd: 5,
    thresholdType: "ABSOLUTE_VALUE"
  }),
  Object.freeze({
    metric: "ACTUAL",
    comparison: "GREATER_THAN",
    thresholdUsd: 10,
    thresholdType: "ABSOLUTE_VALUE"
  }),
  Object.freeze({
    metric: "FORECASTED",
    comparison: "GREATER_THAN",
    thresholdUsd: 15,
    thresholdType: "ABSOLUTE_VALUE"
  })
]);

const EXPECTED_FORBIDDEN_RESOURCE_TYPES = Object.freeze([
  "AWS::EC2::Instance",
  "AWS::EC2::NatGateway",
  "AWS::ECS::Service",
  "AWS::ElasticLoadBalancingV2::LoadBalancer",
  "AWS::RDS::DBInstance"
]);

const EXPECTED_UNAPPROVED_PURCHASE_CLASSES = Object.freeze([
  "ADDITIONAL_DOMAIN",
  "DOMAIN_RENEWAL_OR_AUTO_RENEW_CHANGE",
  "PAID_DNS_OR_HOSTING_ADD_ON",
  "PROVISIONED_OR_ALWAYS_ON_COMPUTE",
  "UNNECESSARY_PERSISTENT_INFRASTRUCTURE"
]);

const EXPECTED_FINAL_RELEASE_REQUIREMENTS = Object.freeze([
  "Machine-verifiable preflight PASS from the exact clean authenticated checkout, with current account-wide AWS spend plus the full 0.02 USD allowance strictly below both effective ceilings and the main stack absent.",
  "Exact-release price and conservative forecast review for AWS, CockroachDB, Bedrock, Secrets Manager, DNS, and logging, bound to the final architecture and deployed hashes.",
  "Private registrar receipt and dated auto-renew-off evidence reviewed with personal and payment data protected.",
  "Final complete spend ledger plus teardown or explicitly approved keep-alive receipt after the judged keep-alive window."
]);

const EXPECTED_SURFACES = Object.freeze({
  "authority-semantic-metric-runtime": Object.freeze({
    path: "infra/aws/lambda/authority.cjs",
    role: "SEMANTIC_METRIC_CARDINALITY"
  }),
  "aws-bootstrap-template": Object.freeze({
    path: "infra/aws/bootstrap-template.json",
    role: "BUDGET_PREREQUISITE"
  }),
  "aws-gate2-template": Object.freeze({
    path: "infra/aws/gate2-template.json",
    role: "BOUNDED_DEPLOYMENT_CANDIDATE"
  }),
  "aws-oidc-read-only-ledger": Object.freeze({
    path: "docs/AWS_OIDC_PREFLIGHT.md",
    role: "OIDC_PREFLIGHT_COST_AND_AUTHORITY_BOUNDARY"
  }),
  "aws-oidc-read-only-role-template": Object.freeze({
    path: "infra/aws/oidc-read-only-preflight-role-template.json",
    role: "READ_ONLY_PREFLIGHT_PERMISSION_BOUNDARY"
  }),
  "aws-oidc-read-only-runner": Object.freeze({
    path: "scripts/run-aws-oidc-read-only-preflight.sh",
    role: "BOUNDED_READ_ONLY_PREFLIGHT_EXECUTION"
  }),
  "aws-oidc-read-only-workflow": Object.freeze({
    path: ".github/workflows/aws-oidc-read-only-preflight.yml",
    role: "MANUAL_TIME_BOUNDED_PREFLIGHT_WORKFLOW"
  }),
  "aws-preflight-library": Object.freeze({
    path: "src/cloud/aws-gate2-preflight.js",
    role: "FAIL_CLOSED_COST_POLICY"
  }),
  "aws-preflight-runner": Object.freeze({
    path: "scripts/gate2-aws-preflight.js",
    role: "READ_ONLY_AWS_PREFLIGHT"
  }),
  "aws-readiness-runner": Object.freeze({
    path: "scripts/gate2-aws-readiness.js",
    role: "EXACT_CHECKOUT_RELEASE_GATE"
  }),
  "boundary-semantic-metric-runtime": Object.freeze({
    path: "infra/aws/lambda/boundary.cjs",
    role: "SEMANTIC_METRIC_CARDINALITY"
  }),
  "cost-boundary-ledger": Object.freeze({
    path: "docs/COST_GATES.md",
    role: "COST_AND_RESOURCE_BOUNDARY"
  }),
  "cost-control-ledger": Object.freeze({
    path: "docs/RELEASE_COST.md",
    role: "RELEASE_COST_CONTROL_LEDGER"
  }),
  "cost-guard-receipt": Object.freeze({
    path: "evidence/gate2-cost-guard-2026-07-30.json",
    role: "SANITIZED_BUDGET_RECEIPT"
  }),
  "domain-cost-owner-record": Object.freeze({
    path: "evidence/domain-cost-owner-record-2026-07-30.md",
    role: "OWNER_REPORTED_NON_AWS_SPEND"
  }),
  "gate2-console-stop-receipt": Object.freeze({
    path: "evidence/gate2-console-stop-receipt-2026-07-30.md",
    role: "SANITIZED_FAIL_CLOSED_STOP_RECEIPT"
  })
});

const EXPECTED_FUNCTION_CAPS = Object.freeze({
  AgentFunction: Object.freeze({ concurrency: 1, timeout: 15 }),
  AgentProbeFunction: Object.freeze({ concurrency: 1, timeout: 25 }),
  AuthorityFunction: Object.freeze({ concurrency: 2, timeout: 25 }),
  AuthorityProbeFunction: Object.freeze({ concurrency: 1, timeout: 25 }),
  BoundaryFunction: Object.freeze({ concurrency: 2, timeout: 25 }),
  BoundaryProbeFunction: Object.freeze({ concurrency: 1, timeout: 25 }),
  DemoFunction: Object.freeze({ concurrency: 8, timeout: 5 }),
  DemoProbeFunction: Object.freeze({ concurrency: 1, timeout: 25 }),
  SignerFunction: Object.freeze({ concurrency: 1, timeout: 8 }),
  SignerProbeFunction: Object.freeze({ concurrency: 1, timeout: 25 })
});

export const RELEASE_COST_SURFACE_COUNT =
  Object.keys(EXPECTED_SURFACES).length;

const RELEASE_COST_RECEIPT_KEYS = Object.freeze([
  "budgetAlertCount",
  "boundedFunctionCount",
  "checks",
  "claimBoundary",
  "finalReleaseReady",
  "finalReleaseRequirements",
  "forbiddenResourceTypeCount",
  "logGroupCount",
  "manifestPath",
  "manifestSha256",
  "reviewedOn",
  "schemaVersion",
  "status",
  "surfaceCount",
  "unapprovedPurchaseClassCount"
]);

const RELEASE_COST_CHECK_KEYS = Object.freeze([
  "budgetAndAlertsBounded",
  "canonicalManifest",
  "deploymentStopPreserved",
  "exactSurfaceHashes",
  "fixedChargeResourcesAbsent",
  "liveSpendClaimAbsent",
  "preflightCostCeilingsFailClosed",
  "recordedSpendArithmeticExact",
  "runtimeAndLogBoundsExact",
  "unapprovedPurchasesRemainBlocked"
]);

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function validateReleaseCostReceipt(receipt) {
  exactKeys(
    receipt,
    RELEASE_COST_RECEIPT_KEYS,
    "RELEASE_COST_RECEIPT_CONTRACT"
  );
  exactKeys(
    receipt.checks,
    RELEASE_COST_CHECK_KEYS,
    "RELEASE_COST_RECEIPT_CONTRACT"
  );
  assert(
    receipt.schemaVersion === RECEIPT_SCHEMA &&
      receipt.status === "CURRENT_COST_GUARDS_PASS" &&
      receipt.finalReleaseReady === false &&
      /^\d{4}-\d{2}-\d{2}$/.test(receipt.reviewedOn) &&
      receipt.manifestPath === MANIFEST_PATH &&
      HEX_64.test(receipt.manifestSha256) &&
      receipt.surfaceCount === RELEASE_COST_SURFACE_COUNT &&
      receipt.budgetAlertCount === EXPECTED_BUDGET_ALERTS.length &&
      receipt.forbiddenResourceTypeCount ===
        EXPECTED_FORBIDDEN_RESOURCE_TYPES.length &&
      receipt.unapprovedPurchaseClassCount ===
        EXPECTED_UNAPPROVED_PURCHASE_CLASSES.length &&
      receipt.boundedFunctionCount ===
        Object.keys(EXPECTED_FUNCTION_CAPS).length &&
      receipt.logGroupCount ===
        Object.keys(EXPECTED_FUNCTION_CAPS).length + 1 &&
      sameJson(
        receipt.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ) &&
      Object.values(receipt.checks).every((value) => value === true) &&
      typeof receipt.claimBoundary === "string" &&
      receipt.claimBoundary.length > 0,
    "RELEASE_COST_RECEIPT_CONTRACT"
  );
  return receipt;
}

function exactKeys(value, keys, code) {
  assert(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      sameJson(sorted(Object.keys(value)), sorted(keys)),
    code
  );
}

function safeRelativePath(value, code) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      value === value.replaceAll("\\", "/") &&
      !path.posix.isAbsolute(value) &&
      value.split("/").every((part) => part !== "" && part !== ".."),
    code
  );
}

function readRegularFile(rootDir, relativePath, code) {
  safeRelativePath(relativePath, code);
  const resolvedRoot = path.resolve(rootDir);
  const resolved = path.resolve(resolvedRoot, relativePath);
  const relative = path.relative(resolvedRoot, resolved);
  assert(
    relative !== "" &&
      relative !== ".." &&
      !relative.startsWith(`..${path.sep}`),
    code
  );
  let current = resolvedRoot;
  let stat;
  for (const segment of relativePath.split("/")) {
    current = path.join(current, segment);
    stat = fs.lstatSync(current);
    assert(!stat.isSymbolicLink(), code);
  }
  assert(stat.isFile(), code);
  return fs.readFileSync(resolved);
}

function parseJson(bytes, code) {
  try {
    const parsed = JSON.parse(bytes.toString("utf8"));
    assert(parsed && typeof parsed === "object" && !Array.isArray(parsed), code);
    return parsed;
  } catch (error) {
    if (error?.message === code) {
      throw error;
    }
    throw new Error(code);
  }
}

function assertMarkers(value, markers, code) {
  assert(markers.every((marker) => value.includes(marker)), code);
}

function assertSemanticMetricCardinality(value, service, code) {
  assert(
    typeof value === "string" &&
      value.split("CloudWatchMetrics:").length - 1 === 1 &&
      value.split('Namespace: "ProofToAct/GateTwo"').length - 1 === 1 &&
      value.split('Dimensions: [["Deployment", "Service"]]').length - 1 === 1 &&
      value.split('Metrics: [{ Name: "SemanticFailures", Unit: "Count" }]').length - 1 === 1 &&
      value.split(`Service: "${service}"`).length - 1 === 1 &&
      value.split("SemanticFailures: 1").length - 1 === 1,
    code
  );
}

export function validateManifest(manifest) {
  exactKeys(
    manifest,
    [
      "budgetAlerts",
      "claimBoundary",
      "finalReleaseReady",
      "finalReleaseRequirements",
      "forbiddenResourceTypes",
      "limits",
      "reviewedOn",
      "schema",
      "status",
      "surfaces",
      "unapprovedPurchaseClasses"
    ],
    "RELEASE_COST_MANIFEST_KEYS"
  );
  exactKeys(
    manifest.limits,
    Object.keys(EXPECTED_LIMITS),
    "RELEASE_COST_LIMIT_KEYS"
  );
  assert(
    manifest.schema === MANIFEST_SCHEMA &&
      manifest.status === MANIFEST_STATUS &&
      /^\d{4}-\d{2}-\d{2}$/.test(manifest.reviewedOn) &&
      typeof manifest.claimBoundary === "string" &&
      manifest.claimBoundary.length > 0 &&
      manifest.finalReleaseReady === false &&
      sameJson(manifest.limits, EXPECTED_LIMITS) &&
      Number(
        (
          manifest.limits.totalProjectExposureCeilingUsd -
          manifest.limits.recordedNonAwsSpendUsd
        ).toFixed(2)
      ) === manifest.limits.effectiveAwsSpendCeilingUsd &&
      Number(
        (
          manifest.limits.effectiveAwsSpendCeilingUsd -
          manifest.limits.preflightAllowanceReserveUsd
        ).toFixed(2)
      ) === manifest.limits.preflightObservedAwsRejectAtUsd &&
      sameJson(manifest.budgetAlerts, EXPECTED_BUDGET_ALERTS) &&
      sameJson(
        manifest.forbiddenResourceTypes,
        EXPECTED_FORBIDDEN_RESOURCE_TYPES
      ) &&
      sameJson(
        manifest.unapprovedPurchaseClasses,
        EXPECTED_UNAPPROVED_PURCHASE_CLASSES
      ) &&
      sameJson(
        manifest.finalReleaseRequirements,
        EXPECTED_FINAL_RELEASE_REQUIREMENTS
      ),
    "RELEASE_COST_MANIFEST_BOUNDARY"
  );
  for (const alert of manifest.budgetAlerts) {
    exactKeys(
      alert,
      ["comparison", "metric", "thresholdType", "thresholdUsd"],
      "RELEASE_COST_MANIFEST_ALERT"
    );
  }
  assert(
    Array.isArray(manifest.surfaces) &&
      manifest.surfaces.length === Object.keys(EXPECTED_SURFACES).length &&
      sameJson(
        manifest.surfaces.map(({ id }) => id),
        sorted(Object.keys(EXPECTED_SURFACES))
      ),
    "RELEASE_COST_MANIFEST_SURFACES"
  );
  for (const surface of manifest.surfaces) {
    exactKeys(
      surface,
      ["id", "path", "role", "sha256"],
      "RELEASE_COST_MANIFEST_SURFACE_KEYS"
    );
    const expected = EXPECTED_SURFACES[surface.id];
    assert(
      expected &&
        surface.path === expected.path &&
        surface.role === expected.role &&
        HEX_64.test(surface.sha256),
      "RELEASE_COST_MANIFEST_SURFACE"
    );
    safeRelativePath(surface.path, "RELEASE_COST_MANIFEST_SURFACE_PATH");
  }
  return manifest;
}

function normalizedAlert(alert, thresholdKey = "Threshold") {
  return {
    metric: alert.NotificationType,
    comparison: alert.ComparisonOperator,
    thresholdUsd: Number(alert[thresholdKey]),
    thresholdType: alert.ThresholdType
  };
}

function sortAlerts(alerts) {
  return [...alerts].sort((left, right) => {
    const metric = left.metric.localeCompare(right.metric);
    return metric === 0 ? left.thresholdUsd - right.thresholdUsd : metric;
  });
}

export function assertBootstrapContract(template) {
  const resources = template?.Resources;
  assert(
    resources && typeof resources === "object" && !Array.isArray(resources),
    "RELEASE_COST_BOOTSTRAP_RESOURCES"
  );
  const budget = resources.AccountBudget;
  const config = budget?.Properties?.Budget;
  const notifications = budget?.Properties?.NotificationsWithSubscribers;
  assert(
    budget?.Type === "AWS::Budgets::Budget" &&
      sameJson(config?.BudgetName, {
        "Fn::Sub": "${AWS::StackName}-account-safety"
      }) &&
      sameJson(config?.BudgetLimit, { Amount: 15, Unit: "USD" }) &&
      config?.BudgetType === "COST" &&
      config?.TimeUnit === "MONTHLY" &&
      Array.isArray(notifications) &&
      notifications.length === EXPECTED_BUDGET_ALERTS.length,
    "RELEASE_COST_BOOTSTRAP_BUDGET"
  );
  const alerts = notifications.map((entry) => {
    assert(
      Array.isArray(entry?.Subscribers) &&
        entry.Subscribers.length === 1 &&
        entry.Subscribers[0]?.SubscriptionType === "EMAIL" &&
        sameJson(entry.Subscribers[0]?.Address, { Ref: "NotificationEmail" }),
      "RELEASE_COST_BOOTSTRAP_SUBSCRIBER"
    );
    return normalizedAlert(entry.Notification);
  });
  assert(
    sameJson(sortAlerts(alerts), EXPECTED_BUDGET_ALERTS),
    "RELEASE_COST_BOOTSTRAP_ALERTS"
  );
  const bucket = resources.ArtifactBucket;
  const rules = bucket?.Properties?.LifecycleConfiguration?.Rules;
  assert(
    bucket?.Type === "AWS::S3::Bucket" &&
      bucket.DependsOn === "AccountBudget" &&
      bucket.DeletionPolicy === "Retain" &&
      bucket.UpdateReplacePolicy === "Retain" &&
      Array.isArray(rules) &&
      rules.length === 2 &&
      rules.some(
        (rule) =>
          rule.Id === "ExpireNoncurrentArtifacts" &&
          rule.Status === "Enabled" &&
          rule.NoncurrentVersionExpiration?.NoncurrentDays === 45
      ) &&
      rules.some(
        (rule) =>
          rule.Id === "AbortIncompleteUploads" &&
          rule.Status === "Enabled" &&
          rule.AbortIncompleteMultipartUpload?.DaysAfterInitiation === 1
      ),
    "RELEASE_COST_BOOTSTRAP_BUCKET"
  );
  return true;
}

export function assertGate2TemplateContract(template) {
  const resources = template?.Resources;
  assert(
    resources && typeof resources === "object" && !Array.isArray(resources),
    "RELEASE_COST_GATE2_RESOURCES"
  );
  const resourceTypes = Object.values(resources).map((resource) => resource?.Type);
  assert(
    EXPECTED_FORBIDDEN_RESOURCE_TYPES.every(
      (resourceType) => !resourceTypes.includes(resourceType)
    ),
    "RELEASE_COST_GATE2_FIXED_CHARGE_RESOURCE"
  );
  const functions = Object.entries(resources).filter(
    ([, resource]) => resource?.Type === "AWS::Lambda::Function"
  );
  assert(
    functions.length === Object.keys(EXPECTED_FUNCTION_CAPS).length &&
      sameJson(
        functions.map(([name]) => name).sort(),
        Object.keys(EXPECTED_FUNCTION_CAPS).sort()
      ),
    "RELEASE_COST_GATE2_FUNCTION_SET"
  );
  for (const [name, resource] of functions) {
    const expected = EXPECTED_FUNCTION_CAPS[name];
    assert(
      resource.Properties?.MemorySize === 128 &&
        resource.Properties?.ReservedConcurrentExecutions ===
          expected.concurrency &&
        resource.Properties?.Timeout === expected.timeout,
      `RELEASE_COST_GATE2_FUNCTION_${name}`
    );
  }
  const logGroups = Object.values(resources).filter(
    (resource) => resource?.Type === "AWS::Logs::LogGroup"
  );
  assert(
    logGroups.length === 11 &&
      logGroups.every((resource) => resource.Properties?.RetentionInDays === 7),
    "RELEASE_COST_GATE2_LOGS"
  );
  const semanticAlarms = Object.values(resources).filter(
    (resource) =>
      resource?.Type === "AWS::CloudWatch::Alarm" &&
      resource.Properties?.Namespace === "ProofToAct/GateTwo"
  );
  assert(
    semanticAlarms.length === 2 &&
      semanticAlarms.every(
        (resource) =>
          resource.Properties.MetricName === "SemanticFailures" &&
          resource.Properties.Period === 60 &&
          resource.Properties.AlarmActions === undefined &&
          resource.Properties.OKActions === undefined &&
          resource.Properties.InsufficientDataActions === undefined
      ),
    "RELEASE_COST_GATE2_SEMANTIC_ALARMS"
  );
  const secrets = Object.values(resources).filter(
    (resource) => resource?.Type === "AWS::SecretsManager::Secret"
  );
  assert(secrets.length === 1, "RELEASE_COST_GATE2_SECRET_COUNT");
  const stage = resources.DefaultStage?.Properties;
  assert(
    sameJson(stage?.DefaultRouteSettings, {
      ThrottlingBurstLimit: 8,
      ThrottlingRateLimit: 0.05
    }) &&
      sameJson(stage?.RouteSettings?.["POST /advisory"], {
        ThrottlingBurstLimit: 1,
        ThrottlingRateLimit: 0.1
      }),
    "RELEASE_COST_GATE2_THROTTLE"
  );
  return {
    boundedFunctionCount: functions.length,
    logGroupCount: logGroups.length
  };
}

export function assertBudgetReceipt(receipt) {
  const alerts = receipt?.budget?.alerts;
  assert(
    receipt?.schema === "tideproof.gate2.cost-guard-receipt.v1" &&
      receipt.stack?.name === "tideproof-gate2-artifacts" &&
      ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(receipt.stack?.status) &&
      receipt.budget?.name ===
        "tideproof-gate2-artifacts-account-safety" &&
      receipt.budget?.type === "COST" &&
      receipt.budget?.timeUnit === "MONTHLY" &&
      receipt.budget?.limit?.amount === 15 &&
      receipt.budget?.limit?.unit === "USD" &&
      Array.isArray(alerts) &&
      alerts.length === EXPECTED_BUDGET_ALERTS.length &&
      receipt.mainGateTwoStackDeployed === false &&
      receipt.awsSpendClaim === "not_asserted_cost_data_not_yet_mature" &&
      typeof receipt.claimBoundary === "string" &&
      receipt.claimBoundary.includes("does not prove Gate Two deployment"),
    "RELEASE_COST_GUARD_RECEIPT"
  );
  const normalized = alerts.map((alert) => {
    assert(
      alert.emailRecipientCount >= 1,
      "RELEASE_COST_GUARD_RECEIPT_SUBSCRIBER"
    );
    return {
      metric: alert.metric,
      comparison: alert.comparison,
      thresholdUsd: Number(alert.threshold),
      thresholdType: alert.thresholdType
    };
  });
  assert(
    sameJson(sortAlerts(normalized), EXPECTED_BUDGET_ALERTS),
    "RELEASE_COST_GUARD_RECEIPT_ALERTS"
  );
  return true;
}

function assertPreflightDefaults() {
  assert(
    sameJson(AWS_GATE2_PREFLIGHT_DEFAULTS, {
      region: "us-east-1",
      modelId: "amazon.nova-micro-v1:0",
      bootstrapStackName: "tideproof-gate2-artifacts",
      mainStackName: "prooftoact-gate2",
      legacyMainStackName: "tideproof-gate2",
      budgetCeilingUsd: 15,
      totalProjectExposureCeilingUsd: 25,
      recordedNonAwsSpendUsd: 11.86,
      effectiveAwsSpendCeilingUsd: 13.14,
      projectCostWindowStart: "2026-07-01",
      budgetCostBasis: "UnblendedCost",
      expectedPreflightRoleName: "ProofToActPreflight",
      expectedPreflightSessionName: "release-proof",
      approvedPreflightIdentityLanes: [
        {
          roleName: "ProofToActPreflight",
          sessionName: "release-proof"
        },
        {
          roleName: "ProofToActReadOnlyPreflight",
          sessionName: "read-only-preflight"
        }
      ],
      maxCostExplorerRequests: 1,
      approvedPreflightMeteredSpendCapUsd: 0.02,
      minimumBudgetCoverageEnd: "2026-09-16T00:00:00.000Z"
    }),
    "RELEASE_COST_PREFLIGHT_DEFAULTS"
  );
  return true;
}

function assertSourceContracts(sources) {
  assertSemanticMetricCardinality(
    sources.get("authority-semantic-metric-runtime"),
    "authority",
    "RELEASE_COST_AUTHORITY_METRIC_CARDINALITY"
  );
  assertSemanticMetricCardinality(
    sources.get("boundary-semantic-metric-runtime"),
    "boundary",
    "RELEASE_COST_BOUNDARY_METRIC_CARDINALITY"
  );
  assertMarkers(
    sources.get("aws-oidc-read-only-ledger"),
    [
      "This lane makes AWS CloudShell optional",
      "external setup gate that source cannot prove",
      "account-wide `$15` budget",
      "observed AWS + $0.02 < $13.14",
      "exactly `$13.12` fails",
      "maximum remains `$0.02` for each complete preflight",
      "This source change grants",
      "no spend authority."
    ],
    "RELEASE_COST_OIDC_LEDGER_MARKERS"
  );
  const oidcRoleTemplate = sources.get(
    "aws-oidc-read-only-role-template"
  );
  assertMarkers(
    oidcRoleTemplate,
    [
      "Source-only scaffold",
      "budgets:ViewBudget",
      "ce:GetCostAndUsage",
      "DenyEverythingExceptExactPreflightReads",
      "NotAction"
    ],
    "RELEASE_COST_OIDC_ROLE_MARKERS"
  );
  assert(
    EXPECTED_FORBIDDEN_RESOURCE_TYPES.every(
      (resourceType) => !oidcRoleTemplate.includes(resourceType)
    ) &&
      !oidcRoleTemplate.includes("cloudformation:CreateStack") &&
      !oidcRoleTemplate.includes("s3:PutObject"),
    "RELEASE_COST_OIDC_ROLE_MUTATION_BOUNDARY"
  );
  assertMarkers(
    sources.get("aws-oidc-read-only-runner"),
    [
      "--duration-seconds 900",
      "--max-results 1",
      "--no-paginate",
      "--signal=KILL --kill-after=5s 180s",
      "scripts/gate2-aws-preflight.js",
      'tideproof.gate2.aws-preflight.v6',
      "approvedPreflightAllowanceUsd",
      "readOnlyAccountSafetyPreflight: true",
      "cannot authorize or prove upload, mutation, deployment"
    ],
    "RELEASE_COST_OIDC_RUNNER_MARKERS"
  );
  assertMarkers(
    sources.get("aws-oidc-read-only-workflow"),
    [
      "workflow_dispatch:",
      "official_main_commit:",
      "environment: aws-read-only-preflight",
      "timeout-minutes: 10",
      "retention-days: 1"
    ],
    "RELEASE_COST_OIDC_WORKFLOW_MARKERS"
  );
  assertMarkers(
    sources.get("aws-preflight-library"),
    [
      "USD_MICROS = 1_000_000",
      "conservativeReservedAwsExposureMicros <",
      "effectiveAwsSpendCeilingMicros",
      "conservativeReservedTotalExposureMicros <",
      "totalProjectExposureCeilingMicros",
      "PREFLIGHT_ALLOWANCE_AWS_CEILING",
      "PREFLIGHT_ALLOWANCE_TOTAL_EXPOSURE_CEILING",
      'schemaVersion: "tideproof.gate2.aws-preflight.v6"',
      "registrarReceiptVerified: false",
      "autoRenewReportedEnabled: false",
      "state: \"ABSENT\"",
      "CURRENT_COST_CEILING"
    ],
    "RELEASE_COST_PREFLIGHT_LIBRARY_MARKERS"
  );
  assertMarkers(
    sources.get("aws-preflight-runner"),
    [
      "AWS_GATE2_PREFLIGHT_RUNTIME_CALL_INVENTORY",
      "runtimeCalls.assertComplete()",
      "get-caller-identity",
      "get-cost-and-usage",
      "describe-budget",
      "describe-stacks",
      "validateAwsGate2Preflight"
    ],
    "RELEASE_COST_PREFLIGHT_RUNNER_MARKERS"
  );
  assertMarkers(
    sources.get("aws-readiness-runner"),
    [
      "preflightAllowanceMicros === 20_000n",
      "reservedAwsExposureMicros < effectiveAwsCeilingMicros",
      "reservedTotalExposureMicros < ceilingMicros",
      "projectExposure.registrarReceiptVerified === false",
      "controls?.mainGateTwoStack?.state === \"ABSENT\"",
      "awsPreflight: preflight ? \"PASS\" : \"NOT_RUN\"",
      "upload and deployment remain separate reviewed actions"
    ],
    "RELEASE_COST_READINESS_MARKERS"
  );
  return true;
}

export function verifyReleaseCost({ rootDir = DEFAULT_ROOT } = {}) {
  const manifestBytes = readRegularFile(
    rootDir,
    MANIFEST_PATH,
    "RELEASE_COST_MANIFEST_FILE"
  );
  const manifest = validateManifest(
    parseJson(manifestBytes, "RELEASE_COST_MANIFEST_JSON")
  );
  assert(
    manifestBytes.toString("utf8") === `${JSON.stringify(manifest, null, 2)}\n`,
    "RELEASE_COST_MANIFEST_CANONICAL"
  );

  const sources = new Map();
  for (const surface of manifest.surfaces) {
    const bytes = readRegularFile(
      rootDir,
      surface.path,
      "RELEASE_COST_SURFACE_FILE"
    );
    assert(sha256(bytes) === surface.sha256, "RELEASE_COST_SURFACE_HASH");
    sources.set(surface.id, bytes.toString("utf8"));
  }

  assertMarkers(
    sources.get("cost-control-ledger"),
    [
      "CURRENT COST GUARDS PASS — LIVE SPEND AND FINAL REVIEW PENDING",
      "CURRENT_COST_GUARDS_PASS",
      "no accepted AWS read-only preflight receipt exists",
      "main-stack deployment, DNS change",
      "semantic-failure alarms",
      "stack/service custom"
    ],
    "RELEASE_COST_LEDGER_MARKERS"
  );
  assertMarkers(
    sources.get("cost-boundary-ledger"),
    [
      "Approved AWS project ceiling: **$15**",
      "Approved total ProofToAct ceiling: **$25**",
      "**$13.14**",
      "daily cost exceeds $5",
      "unexplained spend exceeds $3",
      "introduces NAT Gateway"
    ],
    "RELEASE_COST_BOUNDARY_MARKERS"
  );
  assertMarkers(
    sources.get("domain-cost-owner-record"),
    [
      "OWNER-REPORTED INPUT — REGISTRAR RECEIPT NOT INSPECTED",
      "sunk registration cost: **$11.86 USD**",
      "auto-renew: reported disabled",
      "No additional domain, renewal, paid add-on, transfer, or auto-renew change"
    ],
    "RELEASE_COST_DOMAIN_MARKERS"
  );
  assertMarkers(
    sources.get("gate2-console-stop-receipt"),
    [
      "Cost Explorer returned `DataUnavailableException`",
      "AWS CloudShell refused to create an environment",
      "UNKNOWN_DO_NOT_ACT",
      "other AWS resource was created"
    ],
    "RELEASE_COST_STOP_RECEIPT_MARKERS"
  );

  assertBudgetReceipt(
    parseJson(
      Buffer.from(sources.get("cost-guard-receipt")),
      "RELEASE_COST_GUARD_RECEIPT_JSON"
    )
  );
  assertBootstrapContract(
    parseJson(
      Buffer.from(sources.get("aws-bootstrap-template")),
      "RELEASE_COST_BOOTSTRAP_JSON"
    )
  );
  const architecture = assertGate2TemplateContract(
    parseJson(
      Buffer.from(sources.get("aws-gate2-template")),
      "RELEASE_COST_GATE2_JSON"
    )
  );
  assertPreflightDefaults();
  assertSourceContracts(sources);

  return validateReleaseCostReceipt({
    schemaVersion: RECEIPT_SCHEMA,
    status: "CURRENT_COST_GUARDS_PASS",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    manifestPath: MANIFEST_PATH,
    manifestSha256: sha256(manifestBytes),
    surfaceCount: manifest.surfaces.length,
    budgetAlertCount: manifest.budgetAlerts.length,
    forbiddenResourceTypeCount: manifest.forbiddenResourceTypes.length,
    unapprovedPurchaseClassCount:
      manifest.unapprovedPurchaseClasses.length,
    boundedFunctionCount: architecture.boundedFunctionCount,
    logGroupCount: architecture.logGroupCount,
    finalReleaseRequirements: manifest.finalReleaseRequirements,
    checks: {
      canonicalManifest: true,
      exactSurfaceHashes: true,
      budgetAndAlertsBounded: true,
      recordedSpendArithmeticExact: true,
      liveSpendClaimAbsent: true,
      deploymentStopPreserved: true,
      preflightCostCeilingsFailClosed: true,
      fixedChargeResourcesAbsent: true,
      runtimeAndLogBoundsExact: true,
      unapprovedPurchasesRemainBlocked: true
    },
    claimBoundary:
      "This receipt verifies current source cost guards, recorded owner inputs, budget prerequisites, bounded deployment resources, and explicit stop conditions. It does not assert current AWS spend, independently verify registrar evidence, authorize cloud or DNS mutation, prove final cost, or approve publication or submission."
  });
}

function main() {
  assert(process.argv.length === 2, "RELEASE_COST_ARGUMENT");
  process.stdout.write(`${JSON.stringify(verifyReleaseCost(), null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    main();
  } catch (error) {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_COST_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_COST_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_COST_FAILED:${code}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({
  assertSemanticMetricCardinality,
  EXPECTED_BUDGET_ALERTS,
  EXPECTED_FINAL_RELEASE_REQUIREMENTS,
  EXPECTED_FORBIDDEN_RESOURCE_TYPES,
  EXPECTED_FUNCTION_CAPS,
  EXPECTED_LIMITS,
  EXPECTED_SURFACES,
  EXPECTED_UNAPPROVED_PURCHASE_CLASSES,
  MANIFEST_SCHEMA,
  MANIFEST_STATUS
});
