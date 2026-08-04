import assert from "node:assert/strict";
import test from "node:test";
import {
  AWS_GATE2_PREFLIGHT_DEFAULTS,
  awsBudgetDescribeArguments,
  awsCostExplorerPeriod,
  validateAwsGate2Preflight
} from "../src/cloud/aws-gate2-preflight.js";
import {
  assertAwsPreflightParentEnvironment,
  awsPreflightIdentityExpectation,
  collectSnapshot
} from "../scripts/gate2-aws-preflight.js";

const ACCOUNT_ID = "111111111111";
const BUCKET_NAME = "private-tideproof-artifacts-111111111111";
const BOOTSTRAP_STACK = "tideproof-gate2-artifacts";
const BUDGET_NAME = `${BOOTSTRAP_STACK}-account-safety`;

test("direct AWS preflight rejects Node and endpoint injection before spawning", () => {
  for (const environment of [
    { NODE_DEBUG: "child_process" },
    { NODE_OPTIONS: "--require=/tmp/inject.js" },
    { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
    { AWS_ENDPOINT_URL_STS: "http://127.0.0.1:9000" }
  ]) {
    assert.throws(
      () => assertAwsPreflightParentEnvironment(environment),
      /AWS_EVIDENCE_(?:SDK_ENVIRONMENT|ENDPOINT_OVERRIDE)/
    );
  }
});

function expectedPreflightEnvironment(overrides = {}) {
  return {
    PATH: "/usr/bin",
    AWS_ACCESS_KEY_ID: "ASIAEXAMPLE12345678",
    AWS_SECRET_ACCESS_KEY: "secret-example-value",
    AWS_SESSION_TOKEN: "session-example-value",
    AWS_EVIDENCE_EXPECTED_ACCOUNT_ID: ACCOUNT_ID,
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
      `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActPreflight`,
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_ARN:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
      "ProofToActPreflight/release-proof",
    AWS_EVIDENCE_EXPECTED_PREFLIGHT_CALLER_USER_ID:
      "AROAPROOFTOACTROLE1:release-proof",
    ...overrides
  };
}

const PREFLIGHT_BINDING_CONTEXT = Object.freeze({
  purpose: "gate2-read-only-preflight",
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40)
});

test("AWS preflight validates a self-consistent identity expectation before STS", () => {
  const expectation = awsPreflightIdentityExpectation(
    expectedPreflightEnvironment(),
    PREFLIGHT_BINDING_CONTEXT
  );
  assert.deepEqual(expectation, {
    expectedAccountId: ACCOUNT_ID,
    expectedPrincipalArn:
      `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActPreflight`,
    expectedCallerArn:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
      "ProofToActPreflight/release-proof",
    expectedCallerUserId: "AROAPROOFTOACTROLE1:release-proof"
  });

  assert.throws(
    () =>
      awsPreflightIdentityExpectation(
        expectedPreflightEnvironment({
          AWS_EVIDENCE_EXPECTED_PREFLIGHT_PRINCIPAL_ARN:
            "arn:aws:iam::222222222222:role/ProofToActPreflight"
        }),
        PREFLIGHT_BINDING_CONTEXT
      ),
    /AWS_EVIDENCE_PRINCIPAL_ACCOUNT/
  );
});

test("AWS preflight stops after STS when the caller misses its expectation", () => {
  const awsCalls = [];
  const readCommandText = (_command, args) => {
    const request = args.join(" ");
    if (request === "rev-parse HEAD") {
      return "a".repeat(40);
    }
    if (request === "rev-parse HEAD^{tree}") {
      return "b".repeat(40);
    }
    if (request === "status --short") {
      return "";
    }
    throw new Error("UNEXPECTED_TEST_COMMAND");
  };
  const readAwsJson = (_region, service, operation) => {
    awsCalls.push({ service, operation });
    assert.equal(service, "sts");
    assert.equal(operation, "get-caller-identity");
    return {
      Account: "222222222222",
      Arn:
        "arn:aws:sts::222222222222:assumed-role/" +
        "ProofToActPreflight/release-proof",
      UserId: "AROAPROOFTOACTROLE1:release-proof"
    };
  };

  assert.throws(
    () =>
      collectSnapshot(new Date("2026-08-04T23:08:00.000Z"), {
        environment: expectedPreflightEnvironment(),
        readCommandText,
        readAwsJson
      }),
    /AWS_EVIDENCE_CALLER_ACCOUNT/
  );
  assert.deepEqual(awsCalls, [
    { service: "sts", operation: "get-caller-identity" }
  ]);
});

function notification(
  notificationType,
  threshold,
  subscribers = [
    {
      SubscriptionType: "EMAIL",
      Address: "private@example.invalid"
    }
  ]
) {
  return {
    notification: {
      NotificationType: notificationType,
      ComparisonOperator: "GREATER_THAN",
      Threshold: threshold,
      ThresholdType: "ABSOLUTE_VALUE"
    },
    subscribers
  };
}

function validSnapshot() {
  return {
    observedAt: "2026-07-30T19:30:00.000Z",
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40),
    workingTreeClean: true,
    region: "us-east-1",
    expectedAccountId: ACCOUNT_ID,
    expectedPrincipalArn:
      `arn:aws:iam::${ACCOUNT_ID}:user/tideproof-deployer`,
    expectedCallerArn:
      `arn:aws:iam::${ACCOUNT_ID}:user/tideproof-deployer`,
    expectedCallerUserId: "AIDATIDEPROOF",
    callerIdentity: {
      Account: ACCOUNT_ID,
      Arn: `arn:aws:iam::${ACCOUNT_ID}:user/tideproof-deployer`,
      UserId: "AIDATIDEPROOF"
    },
    bootstrapStackName: BOOTSTRAP_STACK,
    bootstrapStack: {
      StackName: BOOTSTRAP_STACK,
      StackStatus: "UPDATE_COMPLETE",
      Outputs: [
        {
          OutputKey: "AccountBudgetName",
          OutputValue: BUDGET_NAME
        },
        {
          OutputKey: "ArtifactBucketName",
          OutputValue: BUCKET_NAME
        }
      ]
    },
    budget: {
      BudgetName: BUDGET_NAME,
      BudgetType: "COST",
      TimeUnit: "MONTHLY",
      CostTypes: {
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
      },
      BudgetLimit: { Amount: "15", Unit: "USD" },
      TimePeriod: {
        Start: "2026-07-01T00:00:00.000Z",
        End: "2087-06-15T00:00:00.000Z"
      },
      CalculatedSpend: {
        ActualSpend: { Amount: "0.25", Unit: "USD" }
      }
    },
    notificationSubscribers: [
      notification("ACTUAL", 1),
      notification("ACTUAL", 5),
      notification("ACTUAL", 10),
      notification("FORECASTED", 15)
    ],
    artifactBucket: {
      versioning: { Status: "Enabled" },
      encryption: {
        ServerSideEncryptionConfiguration: {
          Rules: [
            {
              ApplyServerSideEncryptionByDefault: {
                SSEAlgorithm: "AES256"
              }
            }
          ]
        }
      },
      publicAccessBlock: {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true
        }
      },
      ownership: {
        OwnershipControls: {
          Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }]
        }
      },
      policyStatus: { PolicyStatus: { IsPublic: false } },
      policy: {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "DenyInsecureTransport",
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              `arn:aws:s3:::${BUCKET_NAME}`,
              `arn:aws:s3:::${BUCKET_NAME}/*`
            ],
            Condition: {
              Bool: { "aws:SecureTransport": "false" }
            }
          }
        ]
      }
    },
    mainStackName: "prooftoact-gate2",
    legacyMainStackName: "tideproof-gate2",
    stackSummaries: [
      {
        StackName: "deleted-unrelated-stack",
        StackStatus: "DELETE_COMPLETE"
      }
    ],
    currentCost: {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-07-31",
      response: {
        ResultsByTime: [
          {
            TimePeriod: {
              Start: "2026-07-01",
              End: "2026-07-31"
            },
            Estimated: true,
            Total: {
              UnblendedCost: { Amount: "0.20", Unit: "USD" }
            }
          }
        ]
      }
    },
    foundationModel: {
      modelDetails: {
        modelId: "amazon.nova-micro-v1:0",
        modelLifecycle: { status: "ACTIVE" },
        inputModalities: ["TEXT"],
        outputModalities: ["TEXT"],
        inferenceTypesSupported: ["ON_DEMAND"]
      }
    }
  };
}

test("AWS Gate Two preflight accepts exact read-only safety controls", () => {
  const receipt = validateAwsGate2Preflight(validSnapshot());

  assert.equal(receipt.status, "PASS");
  assert.equal(
    receipt.schemaVersion,
    "tideproof.gate2.aws-preflight.v5"
  );
  assert.equal(
    receipt.controls.budget.conservativeObservedActualUsd,
    "0.250000"
  );
  assert.equal(receipt.controls.mainGateTwoStack.state, "ABSENT");
  assert.match(
    receipt.controls.callerBinding.callerIdentityDigest,
    /^[0-9a-f]{64}$/
  );
  assert.equal(
    receipt.controls.callerBinding.callerIdentityDigest,
    receipt.controls.callerBinding.expectedIdentityDigest
  );
  assert.equal(receipt.controls.callerBinding.principalType, "iam-user");
  assert.equal(receipt.controls.bedrock.catalogStatus, "ACTIVE");
  assert.equal(receipt.controls.artifactBucket.tlsOnlyPolicy, true);
  assert.equal(receipt.controls.budget.scope, "ACCOUNT_WIDE");
  assert.equal(
    receipt.controls.budget.costBasis,
    "UnblendedCost"
  );
  assert.equal(receipt.controls.budget.defaultCostTypes, true);
  assert.equal(receipt.controls.budget.fixedLimit, true);
  assert.equal(
    receipt.controls.projectExposure.ceilingUsd,
    "25.000000"
  );
  assert.equal(
    receipt.controls.projectExposure.recordedNonAwsSpendUsd,
    "11.860000"
  );
  assert.equal(
    receipt.controls.projectExposure.effectiveAwsSpendCeilingUsd,
    "13.140000"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeObservedTotalExposureUsd,
    "12.110000"
  );
  assert.equal(
    receipt.controls.projectExposure.remainingExposureUsd,
    "12.890000"
  );
  assert.equal(
    receipt.controls.projectExposure.registrarReceiptVerified,
    false
  );
  assert.equal(
    AWS_GATE2_PREFLIGHT_DEFAULTS.effectiveAwsSpendCeilingUsd,
    13.14
  );

  const serialized = JSON.stringify(receipt);
  assert.doesNotMatch(serialized, new RegExp(ACCOUNT_ID));
  assert.doesNotMatch(serialized, new RegExp(BUCKET_NAME));
  assert.doesNotMatch(serialized, /private@example\.invalid/);
  assert.doesNotMatch(serialized, /tideproof-deployer/);
});

test("AWS Gate Two preflight requests modern filter visibility", () => {
  assert.deepEqual(
    awsBudgetDescribeArguments("111111111111", "account-safety"),
    [
      "--account-id",
      "111111111111",
      "--budget-name",
      "account-safety",
      "--show-filter-expression"
    ]
  );
});

test("AWS Gate Two preflight binds Cost Explorer through today", () => {
  assert.deepEqual(
    awsCostExplorerPeriod("2026-07-30T23:59:59.000Z"),
    {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-07-31"
    }
  );
  assert.deepEqual(
    awsCostExplorerPeriod("2026-08-31T12:00:00.000Z"),
    {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-09-01"
    }
  );
});

test("AWS Gate Two preflight accepts explicit empty filter maps", () => {
  const snapshot = validSnapshot();
  snapshot.budget.CostFilters = {};
  snapshot.budget.FilterExpression = {};
  assert.equal(validateAwsGate2Preflight(snapshot).status, "PASS");

  delete snapshot.budget.CostTypes;
  assert.equal(validateAwsGate2Preflight(snapshot).status, "PASS");
});

test("AWS Gate Two preflight rejects non-account-wide budgets", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.CostFilters = {
          Service: ["Amazon Simple Storage Service"]
        };
      },
      "BUDGET_COST_FILTERS_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.FilterExpression = {
          Dimensions: {
            Key: "SERVICE",
            Values: ["Amazon Simple Storage Service"]
          }
        };
      },
      "BUDGET_FILTER_EXPRESSION_ACCOUNT_WIDE"
    ],
    [
      (snapshot) => {
        snapshot.budget.BillingViewArn =
          "arn:aws:billing::111111111111:billingview/private";
      },
      "BUDGET_BILLING_VIEW_ACCOUNT_WIDE"
    ]
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight rejects non-fixed budget models", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.AutoAdjustData = {
          AutoAdjustType: "HISTORICAL"
        };
      },
      "BUDGET_AUTO_ADJUST_NOT_FIXED"
    ],
    [
      (snapshot) => {
        snapshot.budget.PlannedBudgetLimits = {
          "1785542400": { Amount: "15", Unit: "USD" }
        };
      },
      "BUDGET_PLANNED_LIMITS_NOT_FIXED"
    ],
    [
      (snapshot) => {
        snapshot.budget.Metrics = ["AmortizedCost"];
      },
      "BUDGET_METRICS_MODEL"
    ],
    [
      (snapshot) => {
        snapshot.budget.CostTypes.UseBlended = true;
      },
      "BUDGET_COST_TYPES"
    ],
    [
      (snapshot) => {
        delete snapshot.budget.CostTypes.IncludeCredit;
      },
      "BUDGET_COST_TYPES"
    ]
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight requires an active release-long budget", () => {
  for (const [mutate, expectedCode] of [
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.Start = "not-a-timestamp";
      },
      "BUDGET_TIME_PERIOD_START"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.End = "not-a-timestamp";
      },
      "BUDGET_TIME_PERIOD_END"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.Start =
          "2026-09-17T00:00:00.000Z";
        snapshot.budget.TimePeriod.End =
          "2026-09-16T00:00:00.000Z";
      },
      "BUDGET_TIME_PERIOD_ORDER"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.Start =
          "2026-08-01T00:00:00.000Z";
      },
      "BUDGET_TIME_PERIOD_NOT_STARTED"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.End = snapshot.observedAt;
      },
      "BUDGET_TIME_PERIOD_EXPIRED"
    ],
    [
      (snapshot) => {
        snapshot.budget.TimePeriod.End =
          "2026-09-15T23:59:59.999Z";
      },
      "BUDGET_TIME_PERIOD_RELEASE_HORIZON"
    ]
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      new RegExp(expectedCode)
    );
  }
});

test("AWS Gate Two preflight rejects a stale Cost Explorer window", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.periodEndExclusive = "2026-07-30";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_PERIOD_END/
  );
});

test("AWS Gate Two preflight binds the Cost Explorer response period", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.response.ResultsByTime[0].TimePeriod.End =
    "2026-07-30";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_ROW_PERIOD/
  );
});

test("AWS Gate Two preflight totals every month in the project window", () => {
  const snapshot = validSnapshot();
  snapshot.observedAt = "2026-08-31T12:00:00.000Z";
  snapshot.currentCost.periodEndExclusive = "2026-09-01";
  snapshot.currentCost.response.ResultsByTime = [
    {
      TimePeriod: {
        Start: "2026-07-01",
        End: "2026-08-01"
      },
      Estimated: false,
      Total: {
        UnblendedCost: { Amount: "0.20", Unit: "USD" }
      }
    },
    {
      TimePeriod: {
        Start: "2026-08-01",
        End: "2026-09-01"
      },
      Estimated: true,
      Total: {
        UnblendedCost: { Amount: "0.30", Unit: "USD" }
      }
    }
  ];

  const receipt = validateAwsGate2Preflight(snapshot);
  assert.equal(receipt.controls.currentCost.amountUsd, "0.500000");
  assert.equal(
    receipt.controls.currentCost.scope,
    "ACCOUNT_WIDE_PROJECT_WINDOW_TO_DATE"
  );
  assert.equal(
    receipt.controls.projectExposure
      .conservativeObservedTotalExposureUsd,
    "12.360000"
  );
});

test("AWS Gate Two preflight rejects a different region", () => {
  const snapshot = validSnapshot();
  snapshot.region = "us-west-2";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /AWS_REGION/
  );
});

test("AWS Gate Two preflight rejects missing cost alerts", () => {
  const snapshot = validSnapshot();
  snapshot.notificationSubscribers = snapshot.notificationSubscribers.slice(
    0,
    3
  );
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_NOTIFICATION_FORECASTED_15/
  );
});

test("AWS Gate Two preflight requires an email subscriber per alert", () => {
  const snapshot = validSnapshot();
  snapshot.notificationSubscribers[0].subscribers = [];
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_SUBSCRIBER_ACTUAL_1/
  );
});

test("AWS Gate Two preflight rejects unsafe artifact-bucket controls", () => {
  for (const mutate of [
    (snapshot) => {
      snapshot.artifactBucket.versioning.Status = "Suspended";
    },
    (snapshot) => {
      snapshot.artifactBucket.publicAccessBlock
        .PublicAccessBlockConfiguration.RestrictPublicBuckets = false;
    },
    (snapshot) => {
      snapshot.artifactBucket.policy.Statement = [];
    },
    (snapshot) => {
      snapshot.artifactBucket.policy.Statement.push({
        Sid: "DelegatePrivateRead",
        Effect: "Allow",
        Principal: {
          AWS: "arn:aws:iam::222222222222:root"
        },
        Action: "s3:GetObject",
        Resource: `arn:aws:s3:::${BUCKET_NAME}/*`
      });
    }
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /ARTIFACT_BUCKET/
    );
  }
});

test("AWS Gate Two preflight rejects an existing main stack", () => {
  const snapshot = validSnapshot();
  snapshot.stackSummaries.push({
    StackName: snapshot.mainStackName,
    StackStatus: "CREATE_COMPLETE"
  });
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /MAIN_STACK_ALREADY_PRESENT/
  );
});

test("AWS Gate Two preflight rejects a legacy working-name main stack", () => {
  const snapshot = validSnapshot();
  snapshot.stackSummaries.push({
    StackName: snapshot.legacyMainStackName,
    StackStatus: "CREATE_COMPLETE"
  });
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /LEGACY_MAIN_STACK_ALREADY_PRESENT/
  );
});

test("AWS Gate Two preflight rejects spend at the effective project ceiling", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.response.ResultsByTime[0]
    .Total.UnblendedCost.Amount = "13.14";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_CEILING/
  );
});

test("AWS Gate Two preflight applies the effective ceiling to budget spend", () => {
  const snapshot = validSnapshot();
  snapshot.budget.CalculatedSpend.ActualSpend.Amount = "13.14";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /BUDGET_ACTUAL_CEILING/
  );
});

test("AWS Gate Two preflight rejects unavailable Nova metadata", () => {
  for (const mutate of [
    (snapshot) => {
      snapshot.foundationModel.modelDetails.modelLifecycle.status =
        "LEGACY";
    },
    (snapshot) => {
      snapshot.foundationModel.modelDetails.inferenceTypesSupported = [];
    }
  ]) {
    const snapshot = validSnapshot();
    mutate(snapshot);
    assert.throws(
      () => validateAwsGate2Preflight(snapshot),
      /BEDROCK_MODEL/
    );
  }
});
