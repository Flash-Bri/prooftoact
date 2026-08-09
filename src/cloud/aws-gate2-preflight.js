import { validateAwsEvidenceCaller } from "./aws-evidence-identity.js";

const EXPECTED_REGION = "us-east-1";
const EXPECTED_MODEL_ID = "amazon.nova-micro-v1:0";
const EXPECTED_MAIN_STACK_NAME = "prooftoact-gate2";
const LEGACY_MAIN_STACK_NAME = "tideproof-gate2";
const EXPECTED_BUDGET_USD = 15;
const TOTAL_PROJECT_EXPOSURE_CEILING_USD = 25;
const RECORDED_NON_AWS_SPEND_USD = 11.86;
const PROJECT_COST_WINDOW_START = "2026-07-01";
const EFFECTIVE_AWS_SPEND_CEILING_USD = Number(
  (
    TOTAL_PROJECT_EXPOSURE_CEILING_USD -
    RECORDED_NON_AWS_SPEND_USD
  ).toFixed(2)
);
const EXPECTED_BUDGET_COST_BASIS = "UnblendedCost";
const APPROVED_PREFLIGHT_IDENTITY_LANES = Object.freeze([
  Object.freeze({
    roleName: "ProofToActPreflight",
    sessionName: "release-proof"
  }),
  Object.freeze({
    roleName: "ProofToActReadOnlyPreflight",
    sessionName: "read-only-preflight"
  })
]);
const MAX_COST_EXPLORER_REQUESTS = 1;
const APPROVED_PREFLIGHT_METERED_SPEND_CAP_USD = 0.02;
const USD_MICROS = 1_000_000;
const MINIMUM_BUDGET_COVERAGE_END =
  "2026-09-16T00:00:00.000Z";
const EXPECTED_COST_TYPES = Object.freeze({
  IncludeCredit: true,
  IncludeDiscount: true,
  IncludeOtherSubscription: true,
  IncludeRecurring: true,
  IncludeRefund: true,
  IncludeSubscription: true,
  IncludeSupport: true,
  IncludeTax: true,
  IncludeUpfront: true,
  UseAmortized: false,
  UseBlended: false
});
const REQUIRED_NOTIFICATIONS = [
  {
    notificationType: "ACTUAL",
    comparisonOperator: "GREATER_THAN",
    threshold: 1,
    thresholdType: "ABSOLUTE_VALUE"
  },
  {
    notificationType: "ACTUAL",
    comparisonOperator: "GREATER_THAN",
    threshold: 5,
    thresholdType: "ABSOLUTE_VALUE"
  },
  {
    notificationType: "ACTUAL",
    comparisonOperator: "GREATER_THAN",
    threshold: 10,
    thresholdType: "ABSOLUTE_VALUE"
  },
  {
    notificationType: "FORECASTED",
    comparisonOperator: "GREATER_THAN",
    threshold: 15,
    thresholdType: "ABSOLUTE_VALUE"
  }
];

export const AWS_GATE2_PREFLIGHT_CONTROL_FAILURES = Object.freeze([
  "VALIDATE_SOURCE_IDENTITY",
  "VALIDATE_BOOTSTRAP",
  "VALIDATE_BUDGET",
  "VALIDATE_NOTIFICATIONS",
  "VALIDATE_STACK_ABSENCE",
  "VALIDATE_ARTIFACT_BUCKET",
  "VALIDATE_COST",
  "VALIDATE_EXPOSURE",
  "VALIDATE_MODEL",
  "VALIDATE_RECEIPT_ASSEMBLY"
]);

export class AwsGate2PreflightControlFailure extends Error {
  constructor(index) {
    super("AWS_GATE2_PREFLIGHT_CONTROL_FAILURE");
    this.name = "AwsGate2PreflightControlFailure";
    this.index = index;
  }
}

function validateControl(index, operation, diagnosticFailureMode) {
  if (
    !Number.isSafeInteger(index) ||
    typeof AWS_GATE2_PREFLIGHT_CONTROL_FAILURES[index] !== "string" ||
    typeof operation !== "function"
  ) {
    throw new AwsGate2PreflightControlFailure(9);
  }
  try {
    return operation();
  } catch (error) {
    if (error instanceof AwsGate2PreflightControlFailure) {
      throw error;
    }
    if (diagnosticFailureMode !== true) {
      throw error;
    }
    throw new AwsGate2PreflightControlFailure(index);
  }
}

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function moneyAmount(value, code) {
  requireCondition(value?.Unit === "USD", `${code}_UNIT`);
  const amount = Number(value?.Amount);
  requireCondition(Number.isFinite(amount), `${code}_AMOUNT`);
  requireCondition(amount >= 0, `${code}_NEGATIVE`);
  return amount;
}

function conservativeUsdMicros(value, code) {
  const text = typeof value === "string" ? value : String(value);
  const match = /^(\d+)(?:\.(\d+))?$/.exec(text);
  requireCondition(match, `${code}_DECIMAL`);
  const fraction = match[2] ?? "";
  let micros =
    (BigInt(match[1]) * BigInt(USD_MICROS)) +
    BigInt(`${fraction}000000`.slice(0, 6));
  if (/[1-9]/.test(fraction.slice(6))) {
    micros += 1n;
  }
  requireCondition(
    micros <= BigInt(Number.MAX_SAFE_INTEGER),
    `${code}_RANGE`
  );
  return Number(micros);
}

function usdMicrosForConstant(value, code) {
  return conservativeUsdMicros(value.toFixed(6), code);
}

function formattedUsdMicros(value) {
  return (value / USD_MICROS).toFixed(6);
}

function isAbsentOrEmptyObject(value) {
  return (
    value == null ||
    (
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length === 0
    )
  );
}

export function validateAwsGate2PreflightIdentityExpectation(
  expectation
) {
  const expectedAccountId = expectation?.expectedAccountId;
  requireCondition(
    /^\d{12}$/.test(expectedAccountId ?? ""),
    "AWS_PREFLIGHT_EXPECTED_ACCOUNT"
  );
  const lane = APPROVED_PREFLIGHT_IDENTITY_LANES.find(
    ({ roleName }) =>
      expectation?.expectedPrincipalArn ===
      `arn:aws:iam::${expectedAccountId}:role/${roleName}`
  );
  requireCondition(lane, "AWS_PREFLIGHT_EXPECTED_ROLE");
  requireCondition(
    expectation?.expectedCallerArn ===
      `arn:aws:sts::${expectedAccountId}:assumed-role/` +
        `${lane.roleName}/${lane.sessionName}`,
    "AWS_PREFLIGHT_EXPECTED_CALLER_ARN"
  );
  requireCondition(
    new RegExp(
      `^AROA[A-Z0-9]{12,124}:${lane.sessionName}$`
    ).test(expectation?.expectedCallerUserId ?? ""),
    "AWS_PREFLIGHT_EXPECTED_CALLER_USER_ID"
  );
  return expectation;
}

function timestampMilliseconds(value, code) {
  let milliseconds = Number.NaN;
  if (typeof value === "number") {
    milliseconds = value < 1_000_000_000_000
      ? value * 1000
      : value;
  } else if (typeof value === "string" && value.length > 0) {
    milliseconds = Date.parse(value);
  }
  requireCondition(Number.isFinite(milliseconds), code);
  return milliseconds;
}

function isoDate(date) {
  return date.toISOString().slice(0, 10);
}

export function awsCostExplorerPeriod(observedAt) {
  const now = new Date(observedAt);
  requireCondition(
    Number.isFinite(now.getTime()),
    "CURRENT_COST_OBSERVED_AT"
  );
  const end = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1
  ));
  requireCondition(
    PROJECT_COST_WINDOW_START < isoDate(end),
    "CURRENT_COST_OBSERVED_AT_WINDOW"
  );
  return {
    periodStart: PROJECT_COST_WINDOW_START,
    periodEndExclusive: isoDate(end)
  };
}

export function awsBudgetDescribeArguments(accountId, budgetName) {
  return [
    "--account-id",
    accountId,
    "--budget-name",
    budgetName,
    "--show-filter-expression"
  ];
}

function exactStackOutput(stack, key) {
  const matches = asArray(stack?.Outputs).filter(
    (output) => output?.OutputKey === key
  );
  requireCondition(matches.length === 1, `BOOTSTRAP_OUTPUT_${key}`);
  requireCondition(
    typeof matches[0].OutputValue === "string" &&
      matches[0].OutputValue.length > 0,
    `BOOTSTRAP_OUTPUT_${key}_VALUE`
  );
  return matches[0].OutputValue;
}

function notificationMatches(actual, expected) {
  return (
    actual?.NotificationType === expected.notificationType &&
    actual?.ComparisonOperator === expected.comparisonOperator &&
    Number(actual?.Threshold) === expected.threshold &&
    actual?.ThresholdType === expected.thresholdType
  );
}

function validateNotifications(entries) {
  const notificationEntries = asArray(entries);
  requireCondition(
    notificationEntries.length === REQUIRED_NOTIFICATIONS.length,
    "BUDGET_NOTIFICATION_CARDINALITY"
  );
  const accepted = [];

  for (const required of REQUIRED_NOTIFICATIONS) {
    const matches = notificationEntries.filter((entry) =>
      notificationMatches(entry?.notification, required)
    );
    requireCondition(
      matches.length === 1,
      `BUDGET_NOTIFICATION_${required.notificationType}_${required.threshold}`
    );
    const emailSubscribers = asArray(matches[0].subscribers).filter(
      (subscriber) =>
        subscriber?.SubscriptionType === "EMAIL" &&
        typeof subscriber?.Address === "string" &&
        subscriber.Address.length > 0
    );
    requireCondition(
      emailSubscribers.length >= 1,
      `BUDGET_SUBSCRIBER_${required.notificationType}_${required.threshold}`
    );
    accepted.push({
      metric: required.notificationType,
      comparison: required.comparisonOperator,
      thresholdUsd: required.threshold,
      thresholdType: required.thresholdType,
      emailRecipientCount: emailSubscribers.length
    });
  }

  return accepted;
}

function hasExactObjectKeys(value, expectedKeys) {
  if (
    value == null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    return false;
  }
  return JSON.stringify(Object.keys(value).sort()) ===
    JSON.stringify([...expectedKeys].sort());
}

function hasExpectedCostTypes(value) {
  if (value == null) {
    return true;
  }
  return (
    hasExactObjectKeys(value, Object.keys(EXPECTED_COST_TYPES)) &&
    Object.entries(EXPECTED_COST_TYPES).every(
      ([key, expected]) => value[key] === expected
    )
  );
}

function hasExactTlsOnlyDenyPolicy(policy, bucketName) {
  const expectedResources = new Set([
    `arn:aws:s3:::${bucketName}`,
    `arn:aws:s3:::${bucketName}/*`
  ]);
  const statements = asArray(policy?.Statement);
  if (
    policy?.Version !== "2012-10-17" ||
    statements.length !== 1
  ) {
    return false;
  }

  const statement = statements[0];
  const resources = asArray(statement?.Resource);
  return (
    hasExactObjectKeys(
      statement,
      [
        "Sid",
        "Effect",
        "Principal",
        "Action",
        "Resource",
        "Condition"
      ]
    ) &&
    statement.Sid === "DenyInsecureTransport" &&
    statement.Effect === "Deny" &&
    statement.Principal === "*" &&
    statement.Action === "s3:*" &&
    resources.length === expectedResources.size &&
    resources.every((resource) => expectedResources.has(resource)) &&
    hasExactObjectKeys(statement.Condition, ["Bool"]) &&
    hasExactObjectKeys(
      statement.Condition.Bool,
      ["aws:SecureTransport"]
    ) &&
    statement.Condition.Bool["aws:SecureTransport"] === "false"
  );
}

function validateArtifactBucket(bucket, bucketName) {
  requireCondition(
    bucket?.versioning?.Status === "Enabled",
    "ARTIFACT_BUCKET_VERSIONING"
  );
  requireCondition(
    asArray(
      bucket?.encryption?.ServerSideEncryptionConfiguration?.Rules
    ).some(
      (rule) =>
        rule?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm === "AES256"
    ),
    "ARTIFACT_BUCKET_ENCRYPTION"
  );

  const publicBlock =
    bucket?.publicAccessBlock?.PublicAccessBlockConfiguration;
  for (const property of [
    "BlockPublicAcls",
    "BlockPublicPolicy",
    "IgnorePublicAcls",
    "RestrictPublicBuckets"
  ]) {
    requireCondition(
      publicBlock?.[property] === true,
      `ARTIFACT_BUCKET_${property}`
    );
  }

  requireCondition(
    asArray(bucket?.ownership?.OwnershipControls?.Rules).some(
      (rule) => rule?.ObjectOwnership === "BucketOwnerEnforced"
    ),
    "ARTIFACT_BUCKET_OWNERSHIP"
  );
  requireCondition(
    bucket?.policyStatus?.PolicyStatus?.IsPublic === false,
    "ARTIFACT_BUCKET_PUBLIC_POLICY"
  );
  requireCondition(
    hasExactTlsOnlyDenyPolicy(bucket?.policy, bucketName),
    "ARTIFACT_BUCKET_TLS_POLICY"
  );

  return {
    versioningEnabled: true,
    aes256AtRest: true,
    publicAccessBlocked: true,
    bucketOwnerEnforced: true,
    tlsOnlyPolicy: true
  };
}

function validateCost(cost, ceilingUsd, expectedPeriod) {
  requireCondition(
    cost?.periodStart === expectedPeriod.periodStart,
    "CURRENT_COST_PERIOD_START"
  );
  requireCondition(
    cost?.periodEndExclusive ===
      expectedPeriod.periodEndExclusive,
    "CURRENT_COST_PERIOD_END"
  );
  requireCondition(
    cost?.response &&
      typeof cost.response === "object" &&
      !Array.isArray(cost.response) &&
      !Object.prototype.hasOwnProperty.call(
        cost.response,
        "NextPageToken"
      ),
    "CURRENT_COST_NEXT_PAGE_TOKEN"
  );
  const rows = asArray(cost?.response?.ResultsByTime);
  const expectedRows = [];
  let cursor = new Date(`${expectedPeriod.periodStart}T00:00:00.000Z`);
  const end = new Date(
    `${expectedPeriod.periodEndExclusive}T00:00:00.000Z`
  );
  while (cursor < end) {
    const nextMonth = new Date(Date.UTC(
      cursor.getUTCFullYear(),
      cursor.getUTCMonth() + 1,
      1
    ));
    const rowEnd = nextMonth < end ? nextMonth : end;
    expectedRows.push({
      periodStart: isoDate(cursor),
      periodEndExclusive: isoDate(rowEnd)
    });
    cursor = rowEnd;
  }
  requireCondition(
    rows.length === expectedRows.length,
    "CURRENT_COST_ROWS"
  );

  let totalMicros = 0;
  let estimated = false;
  for (const [index, row] of rows.entries()) {
    requireCondition(
      row?.TimePeriod?.Start ===
        expectedRows[index].periodStart &&
        row?.TimePeriod?.End ===
          expectedRows[index].periodEndExclusive,
      "CURRENT_COST_ROW_PERIOD"
    );
    const unblendedCost = row?.Total?.UnblendedCost;
    moneyAmount(unblendedCost, "CURRENT_COST_UNBLENDED");
    totalMicros += conservativeUsdMicros(
      unblendedCost?.Amount,
      "CURRENT_COST_UNBLENDED"
    );
    requireCondition(
      Number.isSafeInteger(totalMicros),
      "CURRENT_COST_UNBLENDED_TOTAL_RANGE"
    );
    estimated ||= row?.Estimated === true;
  }
  requireCondition(
    totalMicros < usdMicrosForConstant(ceilingUsd, "CURRENT_COST_CEILING"),
    "CURRENT_COST_CEILING"
  );

  return {
    scope: "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE",
    periodStart: cost.periodStart,
    periodEndExclusive: cost.periodEndExclusive,
    amountUsd: formattedUsdMicros(totalMicros),
    estimated
  };
}

function validateModel(modelResponse, expectedModelId) {
  const model = modelResponse?.modelDetails;
  requireCondition(model?.modelId === expectedModelId, "BEDROCK_MODEL_ID");
  requireCondition(
    model?.modelLifecycle?.status === "ACTIVE",
    "BEDROCK_MODEL_LIFECYCLE"
  );
  requireCondition(
    asArray(model?.inputModalities).includes("TEXT"),
    "BEDROCK_MODEL_TEXT_INPUT"
  );
  requireCondition(
    asArray(model?.outputModalities).includes("TEXT"),
    "BEDROCK_MODEL_TEXT_OUTPUT"
  );
  requireCondition(
    asArray(model?.inferenceTypesSupported).includes("ON_DEMAND"),
    "BEDROCK_MODEL_ON_DEMAND"
  );

  return {
    modelId: expectedModelId,
    catalogStatus: "ACTIVE",
    textInput: true,
    textOutput: true,
    onDemandListed: true
  };
}

export function validateAwsGate2Preflight(
  snapshot,
  {
    expectedRegion = EXPECTED_REGION,
    expectedModelId = EXPECTED_MODEL_ID,
    budgetCeilingUsd = EXPECTED_BUDGET_USD,
    minimumBudgetCoverageEnd =
      MINIMUM_BUDGET_COVERAGE_END,
    diagnosticFailureMode = false
  } = {}
) {
  const validate = (index, operation) =>
    validateControl(index, operation, diagnosticFailureMode);
  const sourceIdentity = validate(0, () => {
    requireCondition(
      Number.isFinite(budgetCeilingUsd) && budgetCeilingUsd > 0,
      "BUDGET_CEILING_CONFIG"
    );
    const effectiveAwsSpendCeilingUsd = Math.min(
      budgetCeilingUsd,
      EFFECTIVE_AWS_SPEND_CEILING_USD
    );
    const observedAtMilliseconds = Date.parse(snapshot?.observedAt);
    requireCondition(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(
        snapshot?.observedAt
      ) && Number.isFinite(observedAtMilliseconds),
      "OBSERVED_AT"
    );
    requireCondition(snapshot?.region === expectedRegion, "AWS_REGION");
    requireCondition(
      /^[0-9a-f]{40}$/.test(snapshot?.sourceCommit),
      "SOURCE_COMMIT"
    );
    requireCondition(
      /^[0-9a-f]{40}$/.test(snapshot?.treeDigest),
      "TREE_DIGEST"
    );
    requireCondition(
      snapshot?.workingTreeClean === true,
      "WORKING_TREE_DIRTY"
    );
    validateAwsGate2PreflightIdentityExpectation({
      expectedAccountId: snapshot?.expectedAccountId,
      expectedPrincipalArn: snapshot?.expectedPrincipalArn,
      expectedCallerArn: snapshot?.expectedCallerArn,
      expectedCallerUserId: snapshot?.expectedCallerUserId
    });
    const callerBinding = validateAwsEvidenceCaller(
      snapshot?.callerIdentity,
      {
        expectedAccountId: snapshot?.expectedAccountId,
        expectedPrincipalArn: snapshot?.expectedPrincipalArn,
        expectedCallerArn: snapshot?.expectedCallerArn,
        expectedCallerUserId: snapshot?.expectedCallerUserId,
        bindingContext: {
          purpose: "gate2-read-only-preflight",
          sourceCommit: snapshot?.sourceCommit,
          treeDigest: snapshot?.treeDigest,
          region: snapshot?.region,
          bootstrapStackName: snapshot?.bootstrapStackName
        }
      }
    );
    requireCondition(
      callerBinding.principalType === "assumed-role",
      "AWS_PREFLIGHT_ASSUMED_ROLE_REQUIRED"
    );
    return {
      effectiveAwsSpendCeilingUsd,
      observedAtMilliseconds,
      callerBinding
    };
  });
  const {
    effectiveAwsSpendCeilingUsd,
    observedAtMilliseconds,
    callerBinding
  } = sourceIdentity;

  const bootstrapState = validate(1, () => {
    const bootstrap = snapshot?.bootstrapStack;
    requireCondition(
      bootstrap?.StackName === snapshot?.bootstrapStackName,
      "BOOTSTRAP_STACK_NAME"
    );
    requireCondition(
      ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
        bootstrap?.StackStatus
      ),
      "BOOTSTRAP_STACK_STATUS"
    );
    const budgetName = exactStackOutput(
      bootstrap,
      "AccountBudgetName"
    );
    requireCondition(
      budgetName === `${snapshot.bootstrapStackName}-account-safety`,
      "BUDGET_NAME_BINDING"
    );
    const bucketName = exactStackOutput(
      bootstrap,
      "ArtifactBucketName"
    );
    return { bootstrap, budgetName, bucketName };
  });
  const { bootstrap, budgetName, bucketName } = bootstrapState;

  const budgetState = validate(2, () => {
    const budget = snapshot?.budget;
    requireCondition(budget?.BudgetName === budgetName, "BUDGET_NAME");
    requireCondition(budget?.BudgetType === "COST", "BUDGET_TYPE");
    requireCondition(budget?.TimeUnit === "MONTHLY", "BUDGET_TIME_UNIT");
    requireCondition(
      isAbsentOrEmptyObject(budget?.CostFilters),
      "BUDGET_COST_FILTERS_ACCOUNT_WIDE"
    );
    requireCondition(
      isAbsentOrEmptyObject(budget?.FilterExpression),
      "BUDGET_FILTER_EXPRESSION_ACCOUNT_WIDE"
    );
    requireCondition(
      budget?.BillingViewArn == null,
      "BUDGET_BILLING_VIEW_ACCOUNT_WIDE"
    );
    requireCondition(
      budget?.AutoAdjustData == null,
      "BUDGET_AUTO_ADJUST_NOT_FIXED"
    );
    requireCondition(
      isAbsentOrEmptyObject(budget?.PlannedBudgetLimits),
      "BUDGET_PLANNED_LIMITS_NOT_FIXED"
    );
    requireCondition(budget?.Metrics == null, "BUDGET_METRICS_MODEL");
    requireCondition(
      hasExpectedCostTypes(budget?.CostTypes),
      "BUDGET_COST_TYPES"
    );
    const budgetPeriodStart = timestampMilliseconds(
      budget?.TimePeriod?.Start,
      "BUDGET_TIME_PERIOD_START"
    );
    const budgetPeriodEnd = timestampMilliseconds(
      budget?.TimePeriod?.End,
      "BUDGET_TIME_PERIOD_END"
    );
    requireCondition(
      budgetPeriodStart < budgetPeriodEnd,
      "BUDGET_TIME_PERIOD_ORDER"
    );
    requireCondition(
      observedAtMilliseconds >= budgetPeriodStart,
      "BUDGET_TIME_PERIOD_NOT_STARTED"
    );
    requireCondition(
      observedAtMilliseconds < budgetPeriodEnd,
      "BUDGET_TIME_PERIOD_EXPIRED"
    );
    requireCondition(
      budgetPeriodEnd >= timestampMilliseconds(
        minimumBudgetCoverageEnd,
        "BUDGET_TIME_PERIOD_RELEASE_HORIZON"
      ),
      "BUDGET_TIME_PERIOD_RELEASE_HORIZON"
    );
    const limit = moneyAmount(budget?.BudgetLimit, "BUDGET_LIMIT");
    requireCondition(limit === budgetCeilingUsd, "BUDGET_LIMIT_VALUE");
    const budgetActual = moneyAmount(
      budget?.CalculatedSpend?.ActualSpend,
      "BUDGET_ACTUAL"
    );
    requireCondition(
      budgetActual < effectiveAwsSpendCeilingUsd,
      "BUDGET_ACTUAL_CEILING"
    );
    return {
      budget,
      budgetPeriodStart,
      budgetPeriodEnd,
      limit,
      budgetActual
    };
  });
  const {
    budget,
    budgetPeriodStart,
    budgetPeriodEnd,
    limit,
    budgetActual
  } = budgetState;

  const notifications = validate(3, () =>
    validateNotifications(snapshot?.notificationSubscribers)
  );

  validate(4, () => {
    requireCondition(
      snapshot?.mainStackName === EXPECTED_MAIN_STACK_NAME,
      "MAIN_STACK_NAME"
    );
    requireCondition(
      snapshot?.legacyMainStackName === LEGACY_MAIN_STACK_NAME,
      "LEGACY_MAIN_STACK_NAME"
    );
    const activeStackNames = new Set(
      asArray(snapshot?.stackSummaries)
        .filter((stack) => stack?.StackStatus !== "DELETE_COMPLETE")
        .map((stack) => stack?.StackName)
    );
    requireCondition(
      !activeStackNames.has(snapshot.mainStackName),
      "MAIN_STACK_ALREADY_PRESENT"
    );
    requireCondition(
      !activeStackNames.has(snapshot.legacyMainStackName),
      "LEGACY_MAIN_STACK_ALREADY_PRESENT"
    );
  });

  const artifactBucket = validate(5, () =>
    validateArtifactBucket(snapshot?.artifactBucket, bucketName)
  );
  const currentCost = validate(6, () =>
    validateCost(
      snapshot?.currentCost,
      effectiveAwsSpendCeilingUsd,
      awsCostExplorerPeriod(snapshot.observedAt)
    )
  );
  const exposure = validate(7, () => {
    const budgetActualMicros = conservativeUsdMicros(
      budget?.CalculatedSpend?.ActualSpend?.Amount,
      "BUDGET_ACTUAL"
    );
    const currentCostMicros = conservativeUsdMicros(
      currentCost.amountUsd,
      "CURRENT_COST_TOTAL"
    );
    const conservativeActualMicros = Math.max(
      budgetActualMicros,
      currentCostMicros
    );
    const effectiveAwsSpendCeilingMicros = usdMicrosForConstant(
      effectiveAwsSpendCeilingUsd,
      "EFFECTIVE_AWS_SPEND_CEILING"
    );
    const preflightAllowanceMicros = usdMicrosForConstant(
      APPROVED_PREFLIGHT_METERED_SPEND_CAP_USD,
      "PREFLIGHT_ALLOWANCE"
    );
    const conservativeReservedAwsExposureMicros =
      conservativeActualMicros + preflightAllowanceMicros;
    requireCondition(
      conservativeReservedAwsExposureMicros <
        effectiveAwsSpendCeilingMicros,
      "PREFLIGHT_ALLOWANCE_AWS_CEILING"
    );
    const recordedNonAwsSpendMicros = usdMicrosForConstant(
      RECORDED_NON_AWS_SPEND_USD,
      "RECORDED_NON_AWS_SPEND"
    );
    const totalProjectExposureCeilingMicros = usdMicrosForConstant(
      TOTAL_PROJECT_EXPOSURE_CEILING_USD,
      "TOTAL_PROJECT_EXPOSURE_CEILING"
    );
    const conservativeObservedTotalExposureMicros =
      recordedNonAwsSpendMicros + conservativeActualMicros;
    const conservativeReservedTotalExposureMicros =
      recordedNonAwsSpendMicros +
      conservativeReservedAwsExposureMicros;
    requireCondition(
      conservativeReservedTotalExposureMicros <
        totalProjectExposureCeilingMicros,
      "PREFLIGHT_ALLOWANCE_TOTAL_EXPOSURE_CEILING"
    );
    return {
      conservativeActualMicros,
      effectiveAwsSpendCeilingMicros,
      preflightAllowanceMicros,
      conservativeReservedAwsExposureMicros,
      recordedNonAwsSpendMicros,
      totalProjectExposureCeilingMicros,
      conservativeObservedTotalExposureMicros,
      conservativeReservedTotalExposureMicros,
      remainingExposureMicros:
        totalProjectExposureCeilingMicros -
        conservativeObservedTotalExposureMicros,
      remainingExposureAfterPreflightAllowanceMicros:
        totalProjectExposureCeilingMicros -
        conservativeReservedTotalExposureMicros
    };
  });
  const bedrock = validate(8, () =>
    validateModel(snapshot?.foundationModel, expectedModelId)
  );

  return validate(9, () => ({
    schemaVersion: "tideproof.gate2.aws-preflight.v6",
    status: "PASS",
    observedAt: snapshot.observedAt,
    sourceCommit: snapshot.sourceCommit,
    treeDigest: snapshot.treeDigest,
    region: expectedRegion,
    controls: {
      authenticatedAwsCaller: true,
      callerBinding,
      bootstrapStack: {
        name: snapshot.bootstrapStackName,
        status: bootstrap.StackStatus
      },
      budget: {
        name: budgetName,
        scope: "ACCOUNT_WIDE",
        type: "COST",
        timeUnit: "MONTHLY",
        costBasis: EXPECTED_BUDGET_COST_BASIS,
        defaultCostTypes: true,
        fixedLimit: true,
        limitUsd: limit,
        coverageStart: new Date(budgetPeriodStart).toISOString(),
        coverageEnd: new Date(budgetPeriodEnd).toISOString(),
        budgetReportedActualUsd: budgetActual.toFixed(6),
        conservativeObservedActualUsd:
          formattedUsdMicros(exposure.conservativeActualMicros),
        notifications
      },
      currentCost,
      projectExposure: {
        scope: "TIDEPROOF_TOTAL_APPROVED_EXPOSURE",
        ceilingUsd: TOTAL_PROJECT_EXPOSURE_CEILING_USD.toFixed(6),
        recordedNonAwsSpendUsd:
          RECORDED_NON_AWS_SPEND_USD.toFixed(6),
        effectiveAwsSpendCeilingUsd:
          effectiveAwsSpendCeilingUsd.toFixed(6),
        approvedPreflightAllowanceUsd:
          formattedUsdMicros(exposure.preflightAllowanceMicros),
        conservativeReservedAwsExposureUsd:
          formattedUsdMicros(
            exposure.conservativeReservedAwsExposureMicros
          ),
        conservativeObservedTotalExposureUsd:
          formattedUsdMicros(
            exposure.conservativeObservedTotalExposureMicros
          ),
        conservativeReservedTotalExposureUsd:
          formattedUsdMicros(
            exposure.conservativeReservedTotalExposureMicros
          ),
        remainingExposureUsd:
          formattedUsdMicros(exposure.remainingExposureMicros),
        remainingExposureAfterPreflightAllowanceUsd:
          formattedUsdMicros(
            exposure.remainingExposureAfterPreflightAllowanceMicros
          ),
        awsCostWindowStart: PROJECT_COST_WINDOW_START,
        recordedSpendBasis:
          "OWNER_REPORTED_TIDEPROOF_NET_REGISTRATION",
        registrarReceiptVerified: false,
        autoRenewReportedEnabled: false
      },
      artifactBucket,
      mainGateTwoStack: {
        name: snapshot.mainStackName,
        state: "ABSENT",
        legacyName: snapshot.legacyMainStackName,
        legacyState: "ABSENT"
      },
      bedrock
    },
    privacy:
      "AWS account, caller ARN, expected principal ARN, bucket name, and subscriber addresses were validated but omitted; only caller-binding digests are public.",
    claimBoundary:
      "This read-only preflight validates account safety inputs and Bedrock catalog metadata only. It rejects both the ProofToAct main stack name and the former working-name main stack before a fresh create. Its total-exposure calculation treats the $11.86 tideproof.net registration and disabled auto-renew as owner-reported inputs; it does not verify a registrar receipt or renewal state. It does not validate current Nova pricing, model invocation access, artifact upload, CloudFormation deployment, IAM denials, KMS signing, API traversal, or application behavior."
  }));
}

export const AWS_GATE2_PREFLIGHT_DEFAULTS = Object.freeze({
  region: EXPECTED_REGION,
  modelId: EXPECTED_MODEL_ID,
  bootstrapStackName: "tideproof-gate2-artifacts",
  mainStackName: EXPECTED_MAIN_STACK_NAME,
  legacyMainStackName: LEGACY_MAIN_STACK_NAME,
  budgetCeilingUsd: EXPECTED_BUDGET_USD,
  totalProjectExposureCeilingUsd:
    TOTAL_PROJECT_EXPOSURE_CEILING_USD,
  recordedNonAwsSpendUsd: RECORDED_NON_AWS_SPEND_USD,
  effectiveAwsSpendCeilingUsd:
    EFFECTIVE_AWS_SPEND_CEILING_USD,
  projectCostWindowStart: PROJECT_COST_WINDOW_START,
  budgetCostBasis: EXPECTED_BUDGET_COST_BASIS,
  expectedPreflightRoleName:
    APPROVED_PREFLIGHT_IDENTITY_LANES[0].roleName,
  expectedPreflightSessionName:
    APPROVED_PREFLIGHT_IDENTITY_LANES[0].sessionName,
  approvedPreflightIdentityLanes:
    APPROVED_PREFLIGHT_IDENTITY_LANES,
  maxCostExplorerRequests: MAX_COST_EXPLORER_REQUESTS,
  approvedPreflightMeteredSpendCapUsd:
    APPROVED_PREFLIGHT_METERED_SPEND_CAP_USD,
  minimumBudgetCoverageEnd: MINIMUM_BUDGET_COVERAGE_END
});
