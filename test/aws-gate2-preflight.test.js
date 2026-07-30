import assert from "node:assert/strict";
import test from "node:test";
import {
  validateAwsGate2Preflight
} from "../src/cloud/aws-gate2-preflight.js";

const ACCOUNT_ID = "111111111111";
const BUCKET_NAME = "private-tideproof-artifacts-111111111111";
const BOOTSTRAP_STACK = "tideproof-gate2-artifacts";
const BUDGET_NAME = `${BOOTSTRAP_STACK}-account-safety`;

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
      BudgetLimit: { Amount: "15", Unit: "USD" },
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
    mainStackName: "tideproof-gate2",
    stackSummaries: [
      {
        StackName: "deleted-unrelated-stack",
        StackStatus: "DELETE_COMPLETE"
      }
    ],
    currentCost: {
      periodStart: "2026-07-01",
      periodEndExclusive: "2026-07-30",
      response: {
        ResultsByTime: [
          {
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
    receipt.controls.budget.conservativeObservedActualUsd,
    "0.250000"
  );
  assert.equal(receipt.controls.mainGateTwoStack.state, "ABSENT");
  assert.equal(receipt.controls.bedrock.catalogStatus, "ACTIVE");
  assert.equal(receipt.controls.artifactBucket.tlsOnlyPolicy, true);

  const serialized = JSON.stringify(receipt);
  assert.doesNotMatch(serialized, new RegExp(ACCOUNT_ID));
  assert.doesNotMatch(serialized, new RegExp(BUCKET_NAME));
  assert.doesNotMatch(serialized, /private@example\.invalid/);
  assert.doesNotMatch(serialized, /tideproof-deployer/);
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

test("AWS Gate Two preflight rejects spend at the approved ceiling", () => {
  const snapshot = validSnapshot();
  snapshot.currentCost.response.ResultsByTime[0]
    .Total.UnblendedCost.Amount = "15";
  assert.throws(
    () => validateAwsGate2Preflight(snapshot),
    /CURRENT_COST_CEILING/
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
