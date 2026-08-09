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

export const AWS_GATE2_PREFLIGHT_BUDGET_FAILURES = Object.freeze([
  "VALIDATE_BUDGET_NAME",
  "VALIDATE_BUDGET_TYPE",
  "VALIDATE_BUDGET_TIME_UNIT",
  "VALIDATE_BUDGET_SCOPE_COST_FILTERS",
  "VALIDATE_BUDGET_SCOPE_FILTER_EXPRESSION",
  "VALIDATE_BUDGET_SCOPE_BILLING_VIEW",
  "VALIDATE_BUDGET_FIXED_AUTO_ADJUST",
  "VALIDATE_BUDGET_FIXED_PLANNED_LIMITS",
  "VALIDATE_BUDGET_METRICS_BASIS",
  "VALIDATE_BUDGET_COST_TYPES_BASIS",
  "VALIDATE_BUDGET_PERIOD_START",
  "VALIDATE_BUDGET_PERIOD_END",
  "VALIDATE_BUDGET_PERIOD_ORDER",
  "VALIDATE_BUDGET_PERIOD_NOT_STARTED",
  "VALIDATE_BUDGET_PERIOD_EXPIRED",
  "VALIDATE_BUDGET_PERIOD_RELEASE_HORIZON",
  "VALIDATE_BUDGET_LIMIT_UNIT",
  "VALIDATE_BUDGET_LIMIT_AMOUNT_FORMAT",
  "VALIDATE_BUDGET_LIMIT_NONNEGATIVE",
  "VALIDATE_BUDGET_LIMIT_FIXED",
  "VALIDATE_BUDGET_ACTUAL_SPEND_UNIT",
  "VALIDATE_BUDGET_ACTUAL_SPEND_AMOUNT_FORMAT",
  "VALIDATE_BUDGET_ACTUAL_SPEND_NONNEGATIVE",
  "VALIDATE_BUDGET_ACTUAL_SPEND_CEILING"
]);

export const AWS_GATE2_PREFLIGHT_COST_FAILURES = Object.freeze([
  "VALIDATE_COST_OBSERVED_AT",
  "VALIDATE_COST_OBSERVED_AT_WINDOW",
  "VALIDATE_COST_PERIOD_START",
  "VALIDATE_COST_PERIOD_END",
  "VALIDATE_COST_RESPONSE_GROUPED_UNPAGINATED",
  "VALIDATE_COST_ROWS",
  "VALIDATE_COST_ROW_PERIOD",
  "VALIDATE_COST_RECORD_TYPE_GROUPS",
  "VALIDATE_COST_RECORD_TYPE_SEMANTICS",
  "VALIDATE_COST_RECORD_TYPE_UNBLENDED_UNIT",
  "VALIDATE_COST_RECORD_TYPE_SIGNED_DECIMAL_FORMAT",
  "VALIDATE_COST_RECORD_TYPE_SIGNED_RANGE",
  "VALIDATE_COST_POSITIVE_RECORD_TYPE_TOTAL_RANGE",
  "VALIDATE_COST_CEILING_DECIMAL_FORMAT",
  "VALIDATE_COST_CEILING_RANGE",
  "VALIDATE_COST_CEILING"
]);

const NEGATIVE_COST_RECORD_TYPES = Object.freeze([
  "BundledDiscount",
  "Credit",
  "Discount",
  "Refund",
  "SavingsPlanNegation"
]);
const NONNEGATIVE_COST_RECORD_TYPES = Object.freeze([
  "DiscountedUsage",
  "Fee",
  "FlatRateSubscription",
  "RIFee",
  "SavingsPlanCoveredUsage",
  "SavingsPlanRecurringFee",
  "SavingsPlanUpfrontFee",
  "Tax",
  "Usage"
]);
const COST_RECORD_TYPES = Object.freeze([
  ...NEGATIVE_COST_RECORD_TYPES,
  ...NONNEGATIVE_COST_RECORD_TYPES
]);

export class AwsGate2PreflightControlFailure extends Error {
  constructor(index) {
    super("AWS_GATE2_PREFLIGHT_CONTROL_FAILURE");
    this.name = "AwsGate2PreflightControlFailure";
    this.index = index;
  }
}

const AWS_GATE2_PREFLIGHT_BUDGET_FAILURE_STATE = new WeakMap();
const AWS_GATE2_PREFLIGHT_COST_FAILURE_STATE = new WeakMap();
const AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE = new WeakMap();

export function createAwsGate2PreflightDiagnosticContext() {
  const diagnosticContext = Object.freeze({});
  AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.set(
    diagnosticContext,
    "fresh"
  );
  return diagnosticContext;
}

function beginAwsGate2PreflightDiagnosticContext(diagnosticContext) {
  if (
    AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.get(
      diagnosticContext
    ) !== "fresh"
  ) {
    throw new AwsGate2PreflightControlFailure(9);
  }
  AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.set(
    diagnosticContext,
    "active"
  );
  return diagnosticContext;
}

function settleAwsGate2PreflightDiagnosticContext(diagnosticContext) {
  if (
    AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.get(
      diagnosticContext
    ) === "active"
  ) {
    AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.set(
      diagnosticContext,
      "settled"
    );
  }
}

function createAwsGate2PreflightBudgetFailure(index, invocationToken) {
  const error = new Error("AWS_GATE2_PREFLIGHT_BUDGET_FAILURE");
  error.name = "AwsGate2PreflightBudgetFailure";
  AWS_GATE2_PREFLIGHT_BUDGET_FAILURE_STATE.set(
    error,
    Object.freeze({ index, invocationToken, consumed: false })
  );
  return Object.freeze(error);
}

function budgetFailureMatches(error, invocationToken) {
  const state = AWS_GATE2_PREFLIGHT_BUDGET_FAILURE_STATE.get(error);
  return state?.invocationToken === invocationToken && !state.consumed;
}

function createAwsGate2PreflightCostFailure(index, invocationToken) {
  const error = new Error("AWS_GATE2_PREFLIGHT_COST_FAILURE");
  error.name = "AwsGate2PreflightCostFailure";
  AWS_GATE2_PREFLIGHT_COST_FAILURE_STATE.set(
    error,
    Object.freeze({ index, invocationToken, consumed: false })
  );
  return Object.freeze(error);
}

function costFailureMatches(error, invocationToken) {
  const state = AWS_GATE2_PREFLIGHT_COST_FAILURE_STATE.get(error);
  return state?.invocationToken === invocationToken && !state.consumed;
}

export function consumeAwsGate2PreflightBudgetFailure(
  error,
  diagnosticContext
) {
  const state = AWS_GATE2_PREFLIGHT_BUDGET_FAILURE_STATE.get(error);
  if (
    AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.get(
      diagnosticContext
    ) !== "settled" ||
    !state ||
    state.consumed ||
    state.invocationToken !== diagnosticContext ||
    !Number.isSafeInteger(state.index) ||
    typeof AWS_GATE2_PREFLIGHT_BUDGET_FAILURES[state.index] !== "string"
  ) {
    return null;
  }
  AWS_GATE2_PREFLIGHT_BUDGET_FAILURE_STATE.set(
    error,
    Object.freeze({ ...state, consumed: true })
  );
  AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.set(
    diagnosticContext,
    "consumed"
  );
  return state.index;
}

export function consumeAwsGate2PreflightCostFailure(
  error,
  diagnosticContext
) {
  const state = AWS_GATE2_PREFLIGHT_COST_FAILURE_STATE.get(error);
  if (
    AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.get(
      diagnosticContext
    ) !== "settled" ||
    !state ||
    state.consumed ||
    state.invocationToken !== diagnosticContext ||
    !Number.isSafeInteger(state.index) ||
    typeof AWS_GATE2_PREFLIGHT_COST_FAILURES[state.index] !== "string"
  ) {
    return null;
  }
  AWS_GATE2_PREFLIGHT_COST_FAILURE_STATE.set(
    error,
    Object.freeze({ ...state, consumed: true })
  );
  AWS_GATE2_PREFLIGHT_DIAGNOSTIC_CONTEXT_STATE.set(
    diagnosticContext,
    "consumed"
  );
  return state.index;
}

function validateControl(
  index,
  operation,
  diagnosticFailureMode,
  invocationToken
) {
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
    if (
      error instanceof AwsGate2PreflightControlFailure ||
      budgetFailureMatches(error, invocationToken) ||
      costFailureMatches(error, invocationToken)
    ) {
      throw error;
    }
    if (diagnosticFailureMode !== true) {
      throw error;
    }
    throw new AwsGate2PreflightControlFailure(index);
  }
}

function validateCostPredicate(
  index,
  operation,
  diagnosticFailureMode,
  invocationToken
) {
  if (
    !Number.isSafeInteger(index) ||
    typeof AWS_GATE2_PREFLIGHT_COST_FAILURES[index] !== "string" ||
    typeof operation !== "function"
  ) {
    throw new AwsGate2PreflightControlFailure(6);
  }
  try {
    return operation();
  } catch (error) {
    if (costFailureMatches(error, invocationToken)) {
      throw error;
    }
    if (diagnosticFailureMode !== true) {
      throw error;
    }
    throw createAwsGate2PreflightCostFailure(
      index,
      invocationToken
    );
  }
}

function validateBudget(
  index,
  operation,
  diagnosticFailureMode,
  invocationToken
) {
  if (
    !Number.isSafeInteger(index) ||
    typeof AWS_GATE2_PREFLIGHT_BUDGET_FAILURES[index] !== "string" ||
    typeof operation !== "function"
  ) {
    throw new AwsGate2PreflightControlFailure(2);
  }
  try {
    return operation();
  } catch (error) {
    if (budgetFailureMatches(error, invocationToken)) {
      throw error;
    }
    if (diagnosticFailureMode !== true) {
      throw error;
    }
    throw createAwsGate2PreflightBudgetFailure(
      index,
      invocationToken
    );
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

function awsCostExplorerPeriodWithValidation(observedAt, check) {
  const now = check(0, () => {
    const parsed = new Date(observedAt);
    requireCondition(
      Number.isFinite(parsed.getTime()),
      "CURRENT_COST_OBSERVED_AT"
    );
    return parsed;
  });
  const end = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1
  ));
  check(1, () =>
    requireCondition(
      PROJECT_COST_WINDOW_START < isoDate(end),
      "CURRENT_COST_OBSERVED_AT_WINDOW"
    )
  );
  return {
    periodStart: PROJECT_COST_WINDOW_START,
    periodEndExclusive: isoDate(end)
  };
}

export function awsCostExplorerPeriod(observedAt) {
  return awsCostExplorerPeriodWithValidation(
    observedAt,
    (_index, operation) => operation()
  );
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

function hasExpectedBudgetMetrics(value) {
  return (
    value == null ||
    (
      Array.isArray(value) &&
      value.length === 1 &&
      value[0] === EXPECTED_BUDGET_COST_BASIS
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

function costDecimalMicros(
  value,
  code,
  check,
  decimalIndex,
  rangeIndex
) {
  const text = typeof value === "string" ? value : String(value);
  const match = check(decimalIndex, () => {
    const parsed = /^(\d+)(?:\.(\d+))?$/.exec(text);
    requireCondition(parsed, `${code}_DECIMAL`);
    return parsed;
  });
  const fraction = match[2] ?? "";
  let micros =
    (BigInt(match[1]) * BigInt(USD_MICROS)) +
    BigInt(`${fraction}000000`.slice(0, 6));
  if (/[1-9]/.test(fraction.slice(6))) {
    micros += 1n;
  }
  check(rangeIndex, () =>
    requireCondition(
      micros <= BigInt(Number.MAX_SAFE_INTEGER),
      `${code}_RANGE`
    )
  );
  return Number(micros);
}

function signedCostDecimalMicros(
  value,
  code,
  check,
  decimalIndex,
  rangeIndex
) {
  const match = check(decimalIndex, () => {
    requireCondition(
      typeof value === "string",
      `${code}_TYPE`
    );
    const text = value;
    const parsed = /^(-?)((?:0|[1-9]\d*))(?:\.(\d+))?$/.exec(text);
    requireCondition(parsed, `${code}_DECIMAL`);
    requireCondition(
      !(
        parsed[1] === "-" &&
        /^0+(?:\.0+)?$/.test(text.slice(1))
      ),
      `${code}_NEGATIVE_ZERO`
    );
    return parsed;
  });
  const text = value;
  const negative = match[1] === "-";
  const fraction = match[3] ?? "";
  const zero = match[2] === "0" && !/[1-9]/.test(fraction);
  let magnitudeMicros =
    (BigInt(match[2]) * BigInt(USD_MICROS)) +
    BigInt(`${fraction}000000`.slice(0, 6));
  if (!negative && /[1-9]/.test(fraction.slice(6))) {
    magnitudeMicros += 1n;
  }
  check(rangeIndex, () =>
    requireCondition(
      magnitudeMicros <= BigInt(Number.MAX_SAFE_INTEGER),
      `${code}_RANGE`
    )
  );
  return {
    micros: Number(negative ? -magnitudeMicros : magnitudeMicros),
    negative,
    zero
  };
}

function validateCost(
  cost,
  ceilingUsd,
  observedAt,
  diagnosticFailureMode,
  invocationToken
) {
  const check = (index, operation) =>
    validateCostPredicate(
      index,
      operation,
      diagnosticFailureMode,
      invocationToken
    );
  const expectedPeriod = awsCostExplorerPeriodWithValidation(
    observedAt,
    check
  );
  check(2, () =>
    requireCondition(
      cost?.periodStart === expectedPeriod.periodStart,
      "CURRENT_COST_PERIOD_START"
    )
  );
  check(3, () =>
    requireCondition(
      cost?.periodEndExclusive ===
        expectedPeriod.periodEndExclusive,
      "CURRENT_COST_PERIOD_END"
    )
  );
  check(4, () =>
    requireCondition(
      cost?.response &&
        typeof cost.response === "object" &&
        !Array.isArray(cost.response) &&
        !Object.prototype.hasOwnProperty.call(
          cost.response,
          "NextPageToken"
        ) &&
        Array.isArray(cost.response.GroupDefinitions) &&
        cost.response.GroupDefinitions.length === 1 &&
        hasExactObjectKeys(
          cost.response.GroupDefinitions[0],
          ["Key", "Type"]
        ) &&
        cost.response.GroupDefinitions[0]?.Type === "DIMENSION" &&
        cost.response.GroupDefinitions[0]?.Key === "RECORD_TYPE",
      "CURRENT_COST_GROUPED_RESPONSE"
    )
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
  check(5, () =>
    requireCondition(
      rows.length === expectedRows.length,
      "CURRENT_COST_ROWS"
    )
  );

  let positiveRecordTypeMicros = 0;
  let estimated = false;
  for (const [index, row] of rows.entries()) {
    check(6, () =>
      requireCondition(
        hasExactObjectKeys(row?.TimePeriod, ["End", "Start"]) &&
          row.TimePeriod.Start ===
          expectedRows[index].periodStart &&
          row.TimePeriod.End ===
            expectedRows[index].periodEndExclusive,
        "CURRENT_COST_ROW_PERIOD"
      )
    );
    check(7, () =>
      requireCondition(
        row &&
          typeof row === "object" &&
          !Array.isArray(row) &&
          hasExactObjectKeys(row, [
            "Estimated",
            "Groups",
            "TimePeriod",
            "Total"
          ]) &&
          typeof row.Estimated === "boolean" &&
          Array.isArray(row.Groups) &&
          hasExactObjectKeys(row.Total, []),
        "CURRENT_COST_RECORD_TYPE_GROUPS"
      )
    );
    const seenRecordTypes = new Set();
    for (const group of row.Groups) {
      const recordType = check(8, () => {
        requireCondition(
          group &&
            typeof group === "object" &&
            !Array.isArray(group) &&
            hasExactObjectKeys(group, ["Keys", "Metrics"]) &&
            Array.isArray(group.Keys) &&
            group.Keys.length === 1 &&
            typeof group.Keys[0] === "string" &&
            COST_RECORD_TYPES.includes(group.Keys[0]) &&
            !seenRecordTypes.has(group.Keys[0]),
          "CURRENT_COST_RECORD_TYPE_SEMANTICS"
        );
        seenRecordTypes.add(group.Keys[0]);
        return group.Keys[0];
      });
      const metrics = group.Metrics;
      const unblendedCost = metrics?.UnblendedCost;
      check(9, () =>
        requireCondition(
          metrics &&
            typeof metrics === "object" &&
            !Array.isArray(metrics) &&
            hasExactObjectKeys(metrics, ["UnblendedCost"]) &&
            unblendedCost &&
            typeof unblendedCost === "object" &&
            !Array.isArray(unblendedCost) &&
            hasExactObjectKeys(unblendedCost, ["Amount", "Unit"]) &&
            unblendedCost.Unit === "USD",
          "CURRENT_COST_RECORD_TYPE_UNBLENDED_UNIT"
        )
      );
      const signedAmount = signedCostDecimalMicros(
        unblendedCost.Amount,
        "CURRENT_COST_RECORD_TYPE_UNBLENDED",
        check,
        10,
        11
      );
      check(8, () =>
        requireCondition(
          signedAmount.zero ||
            (
              signedAmount.negative &&
              NEGATIVE_COST_RECORD_TYPES.includes(recordType)
            ) ||
            (
              !signedAmount.negative &&
              NONNEGATIVE_COST_RECORD_TYPES.includes(recordType)
            ),
          "CURRENT_COST_RECORD_TYPE_SIGN"
        )
      );
      if (signedAmount.micros > 0) {
        positiveRecordTypeMicros += signedAmount.micros;
      }
      check(12, () =>
        requireCondition(
          Number.isSafeInteger(positiveRecordTypeMicros),
          "CURRENT_COST_POSITIVE_RECORD_TYPE_TOTAL_RANGE"
        )
      );
    }
    estimated ||= row?.Estimated === true;
  }
  const ceilingMicros = costDecimalMicros(
    ceilingUsd.toFixed(6),
    "CURRENT_COST_CEILING",
    check,
    13,
    14
  );
  check(15, () =>
    requireCondition(
      positiveRecordTypeMicros < ceilingMicros,
      "CURRENT_COST_CEILING"
    )
  );

  return {
    scope:
      "ACCOUNT_WIDE_PROJECT_WINDOW_POSITIVE_RECORD_TYPE_EXPOSURE",
    groupedBy: "RECORD_TYPE",
    periodStart: cost.periodStart,
    periodEndExclusive: cost.periodEndExclusive,
    positiveRecordTypeExposureUsd:
      formattedUsdMicros(positiveRecordTypeMicros),
    negativeOffsetsAppliedToExposure: false,
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
    diagnosticFailureMode = false,
    diagnosticContext = null
  } = {}
) {
  const diagnosticInvocationToken =
    diagnosticFailureMode === true
      ? beginAwsGate2PreflightDiagnosticContext(diagnosticContext)
      : null;
  try {
    const validate = (index, operation) =>
      validateControl(
        index,
        operation,
        diagnosticFailureMode,
        diagnosticInvocationToken
      );
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
    const budgetCheck = (index, operation) =>
      validateBudget(
        index,
        operation,
        diagnosticFailureMode,
        diagnosticInvocationToken
      );
    budgetCheck(0, () =>
      requireCondition(budget?.BudgetName === budgetName, "BUDGET_NAME")
    );
    budgetCheck(1, () =>
      requireCondition(budget?.BudgetType === "COST", "BUDGET_TYPE")
    );
    budgetCheck(2, () =>
      requireCondition(
        budget?.TimeUnit === "MONTHLY",
        "BUDGET_TIME_UNIT"
      )
    );
    budgetCheck(3, () =>
      requireCondition(
        isAbsentOrEmptyObject(budget?.CostFilters),
        "BUDGET_COST_FILTERS_ACCOUNT_WIDE"
      )
    );
    budgetCheck(4, () =>
      requireCondition(
        isAbsentOrEmptyObject(budget?.FilterExpression),
        "BUDGET_FILTER_EXPRESSION_ACCOUNT_WIDE"
      )
    );
    budgetCheck(5, () =>
      requireCondition(
        budget?.BillingViewArn == null,
        "BUDGET_BILLING_VIEW_ACCOUNT_WIDE"
      )
    );
    budgetCheck(6, () =>
      requireCondition(
        budget?.AutoAdjustData == null,
        "BUDGET_AUTO_ADJUST_NOT_FIXED"
      )
    );
    budgetCheck(7, () =>
      requireCondition(
        isAbsentOrEmptyObject(budget?.PlannedBudgetLimits),
        "BUDGET_PLANNED_LIMITS_NOT_FIXED"
      )
    );
    budgetCheck(8, () =>
      requireCondition(
        hasExpectedBudgetMetrics(budget?.Metrics),
        "BUDGET_METRICS_MODEL"
      )
    );
    budgetCheck(9, () =>
      requireCondition(
        hasExpectedCostTypes(budget?.CostTypes),
        "BUDGET_COST_TYPES"
      )
    );
    const budgetPeriodStart = budgetCheck(10, () =>
      timestampMilliseconds(
        budget?.TimePeriod?.Start,
        "BUDGET_TIME_PERIOD_START"
      )
    );
    const budgetPeriodEnd = budgetCheck(11, () =>
      timestampMilliseconds(
        budget?.TimePeriod?.End,
        "BUDGET_TIME_PERIOD_END"
      )
    );
    budgetCheck(12, () =>
      requireCondition(
        budgetPeriodStart < budgetPeriodEnd,
        "BUDGET_TIME_PERIOD_ORDER"
      )
    );
    budgetCheck(13, () =>
      requireCondition(
        observedAtMilliseconds >= budgetPeriodStart,
        "BUDGET_TIME_PERIOD_NOT_STARTED"
      )
    );
    budgetCheck(14, () =>
      requireCondition(
        observedAtMilliseconds < budgetPeriodEnd,
        "BUDGET_TIME_PERIOD_EXPIRED"
      )
    );
    budgetCheck(15, () =>
      requireCondition(
        budgetPeriodEnd >= timestampMilliseconds(
          minimumBudgetCoverageEnd,
          "BUDGET_TIME_PERIOD_RELEASE_HORIZON"
        ),
        "BUDGET_TIME_PERIOD_RELEASE_HORIZON"
      )
    );
    budgetCheck(16, () =>
      requireCondition(
        budget?.BudgetLimit?.Unit === "USD",
        "BUDGET_LIMIT_UNIT"
      )
    );
    const limit = budgetCheck(17, () => {
      const amount = Number(budget?.BudgetLimit?.Amount);
      requireCondition(Number.isFinite(amount), "BUDGET_LIMIT_AMOUNT");
      return amount;
    });
    budgetCheck(18, () =>
      requireCondition(limit >= 0, "BUDGET_LIMIT_NEGATIVE")
    );
    budgetCheck(19, () =>
      requireCondition(limit === budgetCeilingUsd, "BUDGET_LIMIT_VALUE")
    );
    const actualSpend = budget?.CalculatedSpend?.ActualSpend;
    budgetCheck(20, () =>
      requireCondition(
        actualSpend?.Unit === "USD",
        "BUDGET_ACTUAL_UNIT"
      )
    );
    const budgetActual = budgetCheck(21, () => {
      const amount = Number(actualSpend?.Amount);
      requireCondition(Number.isFinite(amount), "BUDGET_ACTUAL_AMOUNT");
      return amount;
    });
    budgetCheck(22, () =>
      requireCondition(budgetActual >= 0, "BUDGET_ACTUAL_NEGATIVE")
    );
    budgetCheck(23, () =>
      requireCondition(
        budgetActual < effectiveAwsSpendCeilingUsd,
        "BUDGET_ACTUAL_CEILING"
      )
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
      snapshot.observedAt,
      diagnosticFailureMode,
      diagnosticInvocationToken
    )
  );
  const exposure = validate(7, () => {
    const budgetActualMicros = conservativeUsdMicros(
      budget?.CalculatedSpend?.ActualSpend?.Amount,
      "BUDGET_ACTUAL"
    );
    const currentCostMicros = conservativeUsdMicros(
      currentCost.positiveRecordTypeExposureUsd,
      "CURRENT_COST_POSITIVE_RECORD_TYPE_TOTAL"
    );
    const conservativeAwsExposureMicros = Math.max(
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
      conservativeAwsExposureMicros + preflightAllowanceMicros;
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
      recordedNonAwsSpendMicros + conservativeAwsExposureMicros;
    const conservativeReservedTotalExposureMicros =
      recordedNonAwsSpendMicros +
      conservativeReservedAwsExposureMicros;
    requireCondition(
      conservativeReservedTotalExposureMicros <
        totalProjectExposureCeilingMicros,
      "PREFLIGHT_ALLOWANCE_TOTAL_EXPOSURE_CEILING"
    );
    return {
      conservativeAwsExposureMicros,
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
    schemaVersion: "tideproof.gate2.aws-preflight.v7",
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
        conservativeObservedAwsExposureUsd:
          formattedUsdMicros(
            exposure.conservativeAwsExposureMicros
          ),
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
      "This read-only preflight validates account safety inputs and Bedrock catalog metadata only. It rejects both the ProofToAct main stack name and the former working-name main stack before a fresh create. Its budget costBasis is the normalized validated UnblendedCost semantic basis, and defaultCostTypes means CostTypes were absent or exactly the documented defaults; neither field claims the provider's wire representation. Cost Explorer is grouped by record type, and only positive record-type UnblendedCost amounts count toward conservative exposure; negative credits, refunds, discounts, or negations never create spending headroom. This grouped aggregate is not an invoice or line-item gross-spend proof. The receipt covers current provider observations plus only this run's $0.02 allowance; it does not reconcile pending or previous attempts, delayed charges, or the separate $5.00 aggregate preflight authorization, which remain operator-ledger pre-dispatch gates. Its total-exposure calculation treats the $11.86 tideproof.net registration and disabled auto-renew as owner-reported inputs; it does not verify a registrar receipt or renewal state. It does not validate current Nova pricing, model invocation access, artifact upload, CloudFormation deployment, IAM denials, KMS signing, API traversal, or application behavior."
    }));
  } finally {
    if (diagnosticInvocationToken !== null) {
      settleAwsGate2PreflightDiagnosticContext(
        diagnosticInvocationToken
      );
    }
  }
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
