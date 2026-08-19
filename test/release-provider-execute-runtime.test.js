import assert from "node:assert/strict";
import test from "node:test";

import {
  APP_SOURCE,
  canonicalBytes,
  canonicalDigest,
  sha256
} from "../release-provider/src/release-provider-common.js";
import { attestReleaseControlTable } from
  "../scripts/lib/release-control-table-identity.js";
import { createExecutePermitReader } from
  "../release-provider/src/release-provider-permit-reader.js";
import {
  validateExecuteCommand,
  validateExecuteDispatchPlan
} from "../release-provider/src/release-provider-execute-common.js";
import { __test as dispatchTest } from
  "../release-provider/src/release-provider-execute-dispatcher.js";
import { __test as readbackTest } from
  "../release-provider/src/release-provider-execute-readback.js";

const NOW = Date.parse("2026-08-18T14:00:00.000Z");
const ACCOUNT = "111111111111";
const APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000";
const INTENT_ID = "223e4567-e89b-42d3-a456-426614174001";
const EXECUTE_REQUEST_ID = "323e4567-e89b-42d3-a456-426614174002";
const PROTECTION_REQUEST_ID = "423e4567-e89b-42d3-a456-426614174003";
const READBACK_REQUEST_ID = "523e4567-e89b-42d3-a456-426614174004";
const EVENT_REQUEST_ID = "623e4567-e89b-42d3-a456-426614174005";
const CHANGE_SET_ARN =
  `arn:aws:cloudformation:us-east-1:${ACCOUNT}:changeSet/` +
  "prooftoact-release-final/723e4567-e89b-42d3-a456-426614174006";
const STACK_ID =
  `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
  "prooftoact-gate2/823e4567-e89b-42d3-a456-426614174007";

function commandFixture() {
  const approvalSha256 = "1".repeat(64);
  const authorityContractSha256 = "2".repeat(64);
  const controlPlaneIdentitySha256 = "3".repeat(64);
  const effectIdentitySha256 = canonicalDigest({
    action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
    changeSetArn: CHANGE_SET_ARN,
    changeSetSha256: "4".repeat(64),
    lane: "EXECUTE",
    providerAccountId: ACCOUNT,
    region: "us-east-1",
    stackId: STACK_ID,
    stackName: "prooftoact-gate2"
  });
  const base = {
    schemaVersion: "prooftoact.provider-broker-command.v2",
    action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
    approvalId: APPROVAL_ID,
    approvalSha256,
    appSource: APP_SOURCE,
    artifactManifestSha256: "5".repeat(64),
    authorityContractSha256,
    budgetKeySha256: canonicalDigest({
      currency: "USD", project: "ProofToAct", providerAccountId: ACCOUNT,
      region: "us-east-1"
    }),
    budgetReservationUsd: 2,
    buildReceiptSha256: "6".repeat(64),
    changeSetArn: CHANGE_SET_ARN,
    changeSetSha256: "4".repeat(64),
    controlPlaneIdentitySha256,
    cumulativeCapUsd: 20,
    databaseIdentitySha256: "7".repeat(64),
    effectIdentitySha256,
    expectedPriorCumulativeSpendUsd: 4,
    globalKeySha256: sha256(Buffer.from(
      `prooftoact-provider-effect-v2\n${effectIdentitySha256}`, "utf8")),
    lane: "EXECUTE",
    maximumConcurrency: 2,
    maximumRuns: 1,
    namespaceArn:
      `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
      "prooftoact-release-controller",
    operationIdentitySha256: canonicalDigest({
      approvalId: APPROVAL_ID,
      approvalSha256,
      authorityContractSha256,
      controlPlaneIdentitySha256,
      effectIdentitySha256
    }),
    providerMutationExpected: true,
    region: "us-east-1",
    stackId: STACK_ID,
    teardownContractSha256: "8".repeat(64),
    teardownReserveUsd: 1,
    workspaceRealpathSha256: "9".repeat(64)
  };
  return Object.freeze({ ...base, commandSha256: canonicalDigest(base) });
}

function intentFixture(command) {
  return Object.freeze({
    schemaVersion: "prooftoact.provider-global-dispatch-intent.v1",
    status: "DURABLE",
    action: command.action,
    approvalId: command.approvalId,
    commandSha256: command.commandSha256,
    durable: true,
    event: "BEFORE_PROVIDER_DISPATCH",
    globalKeySha256: command.globalKeySha256,
    globallyAuthoritative: true,
    intentId: INTENT_ID,
    lane: "EXECUTE",
    previousReceiptSha256: "a".repeat(64),
    version: 2
  });
}

function planFixture(command, intent) {
  const stepIdentity = {
    action: command.action,
    effectIdentitySha256: command.effectIdentitySha256,
    step: command.action
  };
  const step = {
    idempotencyBindingSha256: canonicalDigest({
      commandSha256: command.commandSha256,
      intentId: intent.intentId,
      stepIdentity
    }),
    idempotencyMechanism: "PROVIDER_NATIVE_CLIENT_REQUEST_TOKEN",
    maximumAttempts: 1,
    mutating: true,
    name: command.action,
    providerNativeIdempotencyToken: intent.intentId
  };
  const base = {
    schemaVersion: "prooftoact.provider-broker-dispatch-plan.v1",
    brokerDispatcherInvocationCount: 1,
    commandSha256: command.commandSha256,
    intentSha256: canonicalDigest(intent),
    lane: "EXECUTE",
    noAutomaticRetry: true,
    steps: [step]
  };
  return Object.freeze({ ...base, dispatchPlanSha256: canonicalDigest(base) });
}

function changeSet(command, executionStatus = "AVAILABLE") {
  return {
    $metadata: { requestId: READBACK_REQUEST_ID },
    Capabilities: ["CAPABILITY_NAMED_IAM"],
    ChangeSetId: command.changeSetArn,
    ChangeSetName: "prooftoact-release-final",
    ChangeSetType: "CREATE",
    Changes: [{ Type: "Resource", ResourceChange: {
      Action: "Add", LogicalResourceId: "HttpApi",
      ResourceType: "AWS::ApiGatewayV2::Api"
    } }],
    Description: `ProofToAct PREPARE ${"b".repeat(64)}`,
    ExecutionStatus: executionStatus,
    IncludeNestedStacks: false,
    Parameters: Array.from({ length: 45 }, (_, index) => ({
      ParameterKey: `P${index}`, ParameterValue: `V${index}`
    })),
    RoleARN:
      `arn:aws:iam::${ACCOUNT}:role/ProofToActGate2CloudFormation`,
    StackId: command.stackId,
    StackName: "prooftoact-gate2",
    Status: "CREATE_COMPLETE"
  };
}

function stack(command, protectedState) {
  const api = "https://abcdefghij.execute-api.us-east-1.amazonaws.com";
  return {
    $metadata: { requestId: READBACK_REQUEST_ID },
    Stacks: [{
      CreationTime: new Date(NOW - 60_000),
      EnableTerminationProtection: protectedState,
      Outputs: [
        { OutputKey: "ApiEndpoint", OutputValue: api },
        { OutputKey: "PublicDemoUrl", OutputValue: `${api}/` },
        { OutputKey: "SourceCommit", OutputValue: APP_SOURCE.commit }
      ],
      Parameters: [
        { ParameterKey: "EnableProbeFunctions", ParameterValue: "false" },
        { ParameterKey: "SourceCommit", ParameterValue: APP_SOURCE.commit },
        { ParameterKey: "TreeDigest", ParameterValue: APP_SOURCE.tree }
      ],
      StackId: command.stackId,
      StackName: "prooftoact-gate2",
      StackStatus: "CREATE_COMPLETE",
      Tags: [
        { Key: "Project", Value: "ProofToAct" },
        { Key: "Purpose", Value: "BoundedHackathonRelease" },
        { Key: "SourceCommit", Value: APP_SOURCE.commit }
      ]
    }]
  };
}

function dispatchInput(command, intent, plan) {
  return {
    authorityNotAfter: new Date(NOW + 10 * 60_000).toISOString(),
    command,
    dispatchPlan: plan,
    intent,
    maxAttempts: 1,
    providerNativeIdempotencyToken: intent.intentId
  };
}

function executeIntentItem(command, intent) {
  const consumption = {
    schemaVersion: "prooftoact.provider-global-approval-consumption.v1",
    status: "CONSUMED",
    approvalId: command.approvalId,
    approvalSha256: command.approvalSha256,
    budgetKeySha256: command.budgetKeySha256,
    budgetVersion: 1,
    commandSha256: command.commandSha256,
    consumedAt: new Date(NOW - 10_000).toISOString(),
    cumulativeCapUsd: 20,
    durable: true,
    effectIdentitySha256: command.effectIdentitySha256,
    globalKeySha256: command.globalKeySha256,
    globallyAuthoritative: true,
    namespaceArn: command.namespaceArn,
    oneShot: true,
    priorCumulativeSpendUsd: 4,
    reservedSpendUsd: 2,
    resultingCumulativeSpendUsd: 6,
    storeRequestId: "923e4567-e89b-42d3-a456-426614174008",
    stronglyConsistent: true,
    version: 1
  };
  const boundIntent = { ...intent,
    previousReceiptSha256: canonicalDigest(consumption) };
  const s = (value) => ({ S: value });
  const n = (value) => ({ N: String(value) });
  const b = (value) => ({ B: canonicalBytes(value) });
  return {
    boundIntent,
    item: {
      approvalId: s(command.approvalId),
      approvalSha256: s(command.approvalSha256),
      budgetKeySha256: s(command.budgetKeySha256),
      budgetVersion: n(1),
      command: b(command),
      commandSha256: s(command.commandSha256),
      consumption: b(consumption),
      consumptionSha256: s(canonicalDigest(consumption)),
      effectIdentitySha256: s(command.effectIdentitySha256),
      entity: s("EFFECT_V1"),
      globalKeySha256: s(command.globalKeySha256),
      intent: b(boundIntent),
      intentSha256: s(canonicalDigest(boundIntent)),
      namespaceArn: s(command.namespaceArn),
      pk: s(`EFFECT#${command.globalKeySha256}`),
      state: s("INTENT"),
      version: n(2)
    }
  };
}

function releaseTableResponses() {
  return {
    describeResponse: {
      Table: {
        AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }],
        BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" },
        DeletionProtectionEnabled: true,
        KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }],
        SSEDescription: {
          KMSMasterKeyArn:
            `arn:aws:kms:us-east-1:${ACCOUNT}:key/` +
            "a23e4567-e89b-42d3-a456-426614174009",
          SSEType: "KMS",
          Status: "ENABLED"
        },
        TableArn:
          `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
          "prooftoact-release-controller",
        TableId: "b23e4567-e89b-42d3-a456-42661417400a",
        TableName: "prooftoact-release-controller",
        TableStatus: "ACTIVE"
      }
    },
    expectedAccountId: ACCOUNT,
    listTagsResponse: {
      Tags: [
        { Key: "Project", Value: "ProofToAct" },
        { Key: "Purpose", Value: "RetainedReleaseControl" },
        { Key: "Retention", Value: "IntentionalOutsideApplicationTeardown" }
      ]
    },
    region: "us-east-1"
  };
}

test("execute dispatcher binds one exact change set, one client token, and protection", async () => {
  const command = commandFixture();
  const intent = intentFixture(command);
  const plan = planFixture(command, intent);
  const calls = [];
  let stackReads = 0;
  const dispatcher = dispatchTest.dispatcherWithClock({
    clock: () => NOW,
    pause: async () => assert.fail("completed stack must not poll"),
    transport: {
      async describeChangeSet(input) {
        calls.push(["describeChangeSet", input]);
        return changeSet(command);
      },
      async describeStacks(input) {
        calls.push(["describeStacks", input]);
        stackReads += 1;
        return stack(command, stackReads > 1);
      },
      async executeChangeSet(input) {
        calls.push(["executeChangeSet", input]);
        return { $metadata: { requestId: EXECUTE_REQUEST_ID } };
      },
      async updateTerminationProtection(input) {
        calls.push(["updateTerminationProtection", input]);
        return { $metadata: { requestId: PROTECTION_REQUEST_ID },
          StackId: command.stackId };
      }
    }
  });
  const outcome = await dispatcher.dispatch(dispatchInput(command, intent, plan));
  assert.equal(outcome.status, "AMBIGUOUS");
  assert.equal(outcome.possibleMutation, true);
  assert.equal(outcome.providerRequestId, EXECUTE_REQUEST_ID);
  assert.deepEqual(calls.map(([name]) => name), [
    "describeChangeSet", "executeChangeSet", "describeStacks",
    "updateTerminationProtection", "describeStacks"
  ]);
  assert.deepEqual(calls[1][1], {
    ChangeSetName: CHANGE_SET_ARN,
    ClientRequestToken: INTENT_ID
  });
  assert.deepEqual(calls[3][1], {
    EnableTerminationProtection: true,
    StackName: STACK_ID
  });
});

test("sealed execute permit reader strongly decodes only the EXECUTE intent", async () => {
  const command = commandFixture();
  const { boundIntent, item } = executeIntentItem(command,
    intentFixture(command));
  const responses = releaseTableResponses();
  const expectedTableIdentity = attestReleaseControlTable(responses);
  const reader = createExecutePermitReader({
    accountId: ACCOUNT,
    expectedTableIdentity,
    transport: {
      async describeTable() { return responses.describeResponse; },
      async getCallerIdentity() {
        return {
          Account: ACCOUNT,
          Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
            "ProofToActReleaseExecution/execute-run",
          UserId: `AROA${"A".repeat(16)}:execute-run`
        };
      },
      async getIntentItem() {
        return { $metadata: { requestId: EXECUTE_REQUEST_ID }, Item: item };
      },
      async listTags() { return responses.listTagsResponse; }
    }
  });
  const record = await reader.readStrong({
    commandSha256: command.commandSha256,
    globalKeySha256: command.globalKeySha256,
    namespaceArn: command.namespaceArn,
    stronglyConsistent: true
  });
  assert.equal(record.command.lane, "EXECUTE");
  assert.deepEqual(Object.keys(record.command).sort(),
    Object.keys(command).sort());
  const permit = await reader.readIntent({
    commandSha256: command.commandSha256,
    globalKeySha256: command.globalKeySha256,
    intentId: boundIntent.intentId
  });
  assert.equal(permit.schemaVersion, "prooftoact.execute-provider-permit.v1");
  assert.equal(permit.intent.intentId, boundIntent.intentId);
  assert.equal(permit.command.commandSha256, command.commandSha256);
});

test("execute dispatcher consumes the effect without mutation on exact preflight drift", async () => {
  const command = commandFixture();
  const intent = intentFixture(command);
  let mutated = false;
  const dispatcher = dispatchTest.dispatcherWithClock({
    clock: () => NOW,
    pause: async () => {},
    transport: {
      async describeChangeSet() {
        return { ...changeSet(command), ExecutionStatus: "OBSOLETE" };
      },
      async describeStacks() { return stack(command, false); },
      async executeChangeSet() { mutated = true; },
      async updateTerminationProtection() { mutated = true; }
    }
  });
  const outcome = await dispatcher.dispatch(dispatchInput(
    command, intent, planFixture(command, intent)));
  assert.equal(outcome.status, "FAILED_TERMINAL");
  assert.equal(outcome.possibleMutation, false);
  assert.equal(mutated, false);
});

test("execute dispatch acknowledgement loss becomes UNKNOWN_DO_NOT_ACT", async () => {
  const command = commandFixture();
  const intent = intentFixture(command);
  const dispatcher = dispatchTest.dispatcherWithClock({
    clock: () => NOW,
    pause: async () => {},
    transport: {
      async describeChangeSet() { return changeSet(command); },
      async describeStacks() { return stack(command, false); },
      async executeChangeSet() { throw new Error("socket closed"); },
      async updateTerminationProtection() {
        assert.fail("must not continue after ambiguous execution");
      }
    }
  });
  const outcome = await dispatcher.dispatch(dispatchInput(
    command, intent, planFixture(command, intent)));
  assert.equal(outcome.status, "AMBIGUOUS");
  assert.equal(outcome.possibleMutation, true);
  assert.equal(outcome.providerRequestId, null);
});

test("independent execute readback confirms source, token, endpoint, and protection", async () => {
  const command = commandFixture();
  const intent = intentFixture(command);
  const readback = readbackTest.readbackWithClock({
    clock: () => NOW,
    transport: {
      async describeChangeSet() { return changeSet(command, "EXECUTE_COMPLETE"); },
      async describeStackEvents() {
        return {
          $metadata: { requestId: EVENT_REQUEST_ID },
          StackEvents: [{
            ClientRequestToken: intent.intentId,
            EventId: "root-create-complete",
            LogicalResourceId: "prooftoact-gate2",
            PhysicalResourceId: command.stackId,
            ResourceStatus: "CREATE_COMPLETE",
            ResourceType: "AWS::CloudFormation::Stack",
            StackId: command.stackId,
            Timestamp: new Date(NOW - 5_000)
          }]
        };
      },
      async describeStacks() { return stack(command, true); }
    }
  });
  const receipt = await readback.readback({
    command,
    fresh: true,
    independentOfDispatcher: true,
    intent,
    providerNativeIdempotencyToken: intent.intentId,
    readOnly: true,
    readerPhaseRuntimeIdentitySha256: "c".repeat(64)
  });
  assert.equal(receipt.status, "CONFIRMED_APPLIED");
  assert.equal(receipt.providerRequestId, READBACK_REQUEST_ID);
  assert.equal(receipt.preparedRelease, null);
  assert.match(receipt.providerReceiptSha256, /^[0-9a-f]{64}$/u);
});

test("execute readback never confirms the wrong client token or missing protection", async () => {
  const command = commandFixture();
  const intent = intentFixture(command);
  for (const failure of ["token", "protection"]) {
    const readback = readbackTest.readbackWithClock({
      clock: () => NOW,
      transport: {
        async describeChangeSet() {
          return changeSet(command, "EXECUTE_COMPLETE");
        },
        async describeStackEvents() {
          return {
            $metadata: { requestId: EVENT_REQUEST_ID },
            StackEvents: [{
              ClientRequestToken: failure === "token" ? APPROVAL_ID : INTENT_ID,
              EventId: "root-create-complete",
              LogicalResourceId: "prooftoact-gate2",
              PhysicalResourceId: command.stackId,
              ResourceStatus: "CREATE_COMPLETE",
              ResourceType: "AWS::CloudFormation::Stack",
              StackId: command.stackId,
              Timestamp: new Date(NOW - 5_000)
            }]
          };
        },
        async describeStacks() {
          return stack(command, failure !== "protection");
        }
      }
    });
    const receipt = await readback.readback({
      command,
      fresh: true,
      independentOfDispatcher: true,
      intent,
      providerNativeIdempotencyToken: intent.intentId,
      readOnly: true,
      readerPhaseRuntimeIdentitySha256: "c".repeat(64)
    });
    assert.equal(receipt.status, "UNKNOWN", failure);
    assert.equal(receipt.providerRequestId, null, failure);
  }
});

test("execute command and broker dispatch plan reject budget or token drift", () => {
  const command = commandFixture();
  const intent = intentFixture(command);
  assert.equal(validateExecuteCommand(command).accountId, ACCOUNT);
  assert.equal(validateExecuteDispatchPlan(
    planFixture(command, intent), command, intent).lane, "EXECUTE");
  const drift = { ...command, budgetReservationUsd: 16 };
  delete drift.commandSha256;
  drift.commandSha256 = canonicalDigest(drift);
  assert.throws(() => validateExecuteCommand(drift),
    /RELEASE_PROVIDER_EXECUTE_COMMAND_REJECTED/u);
  const plan = structuredClone(planFixture(command, intent));
  plan.steps[0].providerNativeIdempotencyToken = APPROVAL_ID;
  const unsigned = { ...plan };
  delete unsigned.dispatchPlanSha256;
  plan.dispatchPlanSha256 = canonicalDigest(unsigned);
  assert.throws(() => validateExecuteDispatchPlan(plan, command, intent),
    /RELEASE_PROVIDER_EXECUTE_DISPATCH_PLAN_REJECTED/u);
});
