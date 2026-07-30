const EXPECTED_REGION = "us-east-1";
const EXPECTED_MODEL_ID = "amazon.nova-micro-v1:0";
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

  let total = 0;
  let estimated = false;
  for (const [index, row] of rows.entries()) {
    requireCondition(
      row?.TimePeriod?.Start ===
        expectedRows[index].periodStart &&
        row?.TimePeriod?.End ===
          expectedRows[index].periodEndExclusive,
      "CURRENT_COST_ROW_PERIOD"
    );
    total += moneyAmount(
      row?.Total?.UnblendedCost,
      "CURRENT_COST_UNBLENDED"
    );
    estimated ||= row?.Estimated === true;
  }
  requireCondition(total < ceilingUsd, "CURRENT_COST_CEILING");

  return {
    scope: "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE",
    periodStart: cost.periodStart,
    periodEndExclusive: cost.periodEndExclusive,
    amountUsd: total.toFixed(6),
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
      MINIMUM_BUDGET_COVERAGE_END
  } = {}
) {
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
  requireCondition(snapshot?.workingTreeClean === true, "WORKING_TREE_DIRTY");

  const caller = snapshot?.callerIdentity;
  requireCondition(/^\d{12}$/.test(caller?.Account), "AWS_CALLER_ACCOUNT");
  requireCondition(
    typeof caller?.Arn === "string" && caller.Arn.startsWith("arn:"),
    "AWS_CALLER_ARN"
  );
  requireCondition(
    typeof caller?.UserId === "string" && caller.UserId.length > 0,
    "AWS_CALLER_USER"
  );

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
  const budgetName = exactStackOutput(bootstrap, "AccountBudgetName");
  requireCondition(
    budgetName === `${snapshot.bootstrapStackName}-account-safety`,
    "BUDGET_NAME_BINDING"
  );
  const bucketName = exactStackOutput(bootstrap, "ArtifactBucketName");

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
  requireCondition(
    budget?.Metrics == null,
    "BUDGET_METRICS_MODEL"
  );
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
  const notifications = validateNotifications(
    snapshot?.notificationSubscribers
  );

  const mainStacks = asArray(snapshot?.stackSummaries).filter(
    (stack) =>
      stack?.StackName === snapshot?.mainStackName &&
      stack?.StackStatus !== "DELETE_COMPLETE"
  );
  requireCondition(mainStacks.length === 0, "MAIN_STACK_ALREADY_PRESENT");

  const artifactBucket = validateArtifactBucket(
    snapshot?.artifactBucket,
    bucketName
  );
  const currentCost = validateCost(
    snapshot?.currentCost,
    effectiveAwsSpendCeilingUsd,
    awsCostExplorerPeriod(snapshot.observedAt)
  );
  const conservativeActual = Math.max(
    budgetActual,
    Number(currentCost.amountUsd)
  );
  requireCondition(
    conservativeActual < effectiveAwsSpendCeilingUsd,
    "CONSERVATIVE_COST_CEILING"
  );
  const conservativeObservedTotalExposure =
    RECORDED_NON_AWS_SPEND_USD + conservativeActual;
  requireCondition(
    conservativeObservedTotalExposure <
      TOTAL_PROJECT_EXPOSURE_CEILING_USD,
    "TOTAL_PROJECT_EXPOSURE_CEILING"
  );
  const remainingExposure =
    TOTAL_PROJECT_EXPOSURE_CEILING_USD -
    conservativeObservedTotalExposure;
  const bedrock = validateModel(
    snapshot?.foundationModel,
    expectedModelId
  );

  return {
    schemaVersion: "tideproof.gate2.aws-preflight.v3",
    status: "PASS",
    observedAt: snapshot.observedAt,
    sourceCommit: snapshot.sourceCommit,
    treeDigest: snapshot.treeDigest,
    region: expectedRegion,
    controls: {
      authenticatedAwsCaller: true,
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
          conservativeActual.toFixed(6),
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
        conservativeObservedTotalExposureUsd:
          conservativeObservedTotalExposure.toFixed(6),
        remainingExposureUsd: remainingExposure.toFixed(6),
        awsCostWindowStart: PROJECT_COST_WINDOW_START,
        recordedSpendBasis:
          "OWNER_REPORTED_TIDEPROOF_NET_REGISTRATION",
        registrarReceiptVerified: false,
        autoRenewReportedEnabled: false
      },
      artifactBucket,
      mainGateTwoStack: {
        name: snapshot.mainStackName,
        state: "ABSENT"
      },
      bedrock
    },
    privacy:
      "AWS account, caller ARN, bucket name, and subscriber addresses were validated but omitted.",
    claimBoundary:
      "This read-only preflight validates account safety inputs and Bedrock catalog metadata only. Its total-exposure calculation treats the $11.86 tideproof.net registration and disabled auto-renew as owner-reported inputs; it does not verify a registrar receipt or renewal state. It does not validate current Nova pricing, model invocation access, artifact upload, CloudFormation deployment, IAM denials, KMS signing, API traversal, or application behavior."
  };
}

export const AWS_GATE2_PREFLIGHT_DEFAULTS = Object.freeze({
  region: EXPECTED_REGION,
  modelId: EXPECTED_MODEL_ID,
  bootstrapStackName: "tideproof-gate2-artifacts",
  mainStackName: "tideproof-gate2",
  budgetCeilingUsd: EXPECTED_BUDGET_USD,
  totalProjectExposureCeilingUsd:
    TOTAL_PROJECT_EXPOSURE_CEILING_USD,
  recordedNonAwsSpendUsd: RECORDED_NON_AWS_SPEND_USD,
  effectiveAwsSpendCeilingUsd:
    EFFECTIVE_AWS_SPEND_CEILING_USD,
  projectCostWindowStart: PROJECT_COST_WINDOW_START,
  budgetCostBasis: EXPECTED_BUDGET_COST_BASIS,
  minimumBudgetCoverageEnd: MINIMUM_BUDGET_COVERAGE_END
});
