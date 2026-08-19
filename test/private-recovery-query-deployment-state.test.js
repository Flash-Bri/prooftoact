import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { buildPrivateRecoveryQueryTemplate } from
  "../src/cloud/private-recovery-query-template.js";
import {
  deployPrivateRecoveryQuery,
  __test as deployInternals
} from "../scripts/deploy-private-recovery-query.js";

function fixture() {
  const template = buildPrivateRecoveryQueryTemplate();
  const sourceCommit = "a".repeat(40);
  const treeDigest = "b".repeat(40);
  const templateSha256 = deployInternals.digest(template);
  const operationGlobalKeySha256 = "c".repeat(64);
  const cloudFormationServiceRoleArn =
    "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation";
  const parameters = [
    ["CloudFormationServiceRoleArn", cloudFormationServiceRoleArn],
    ["OperationGlobalKeySha256", operationGlobalKeySha256],
    ["SourceCommit", sourceCommit],
    ["TemplateSha256", templateSha256],
    ["TreeDigest", treeDigest]
  ].map(([ParameterKey, ParameterValue]) => ({
    ParameterKey,
    ParameterValue,
    UsePreviousValue: false
  }));
  const configRecord = {
    operationGlobalKeySha256,
    sourceCommit,
    templateSha256,
    treeDigest
  };
  const configSha256 = deployInternals.digest(configRecord);
  const privateInput = {
    schemaVersion: "prooftoact.private-recovery-query-deployment-private-input.v1",
    cloudFormationServiceRoleArn,
    configRecord,
    configSha256,
    parameters
  };
  const body = {
    schemaVersion: "prooftoact.private-recovery-query-deployment-intent.v1",
    status: "READY_FOR_CREATE_CHANGE_SET",
    configSha256,
    operationGlobalKeySha256,
    sourceCommit,
    templateSha256,
    treeDigest
  };
  const sanitizedIntent = {
    ...body,
    intentSha256: deployInternals.digest(body)
  };
  return {
    cloudFormationServiceRoleArn,
    privateInput,
    sanitizedIntent,
    template
  };
}

function providerHarness({
  changeSetStatus = "CREATE_COMPLETE",
  createAckLoss = false,
  executeAckLoss = false,
  initialState = "ABSENT",
  parameterOverride,
  protection = false,
  protectionAckLoss = false,
  stackRoleArn,
  templateOverride
} = {}) {
  const input = fixture();
  const stackId =
    "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
    "prooftoact-private-recovery-query/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  let state = initialState;
  let enabled = protection;
  let changeSet = initialState === "REVIEW_IN_PROGRESS";
  let lostExecute = executeAckLoss;
  let lostCreate = createAckLoss;
  let lostProtection = protectionAckLoss;
  let changeStatus = changeSetStatus;
  const calls = [];
  let lastCreateInput;
  const expectedCoordinates = deployInternals.validateInputs({
    ...input,
    cloudFormationServiceRoleArn: input.cloudFormationServiceRoleArn
  });
  const stack = () => ({
    EnableTerminationProtection: enabled,
    Parameters: (parameterOverride ?? input.privateInput.parameters).map(({
      ParameterKey, ParameterValue
    }) => ({ ParameterKey, ParameterValue })),
    RoleARN: stackRoleArn ?? input.cloudFormationServiceRoleArn,
    StackId: stackId,
    StackName: "prooftoact-private-recovery-query",
    StackStatus: state
  });
  const change = () => ({
    Capabilities: ["CAPABILITY_NAMED_IAM"],
    ChangeSetId:
      "arn:aws:cloudformation:us-east-1:111111111111:changeSet/" +
      `${expectedCoordinates.changeSetName}/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb`,
    ChangeSetName: expectedCoordinates.changeSetName,
    ChangeSetType: "CREATE",
    Description: expectedCoordinates.description,
    ExecutionStatus: "AVAILABLE",
    IncludeNestedStacks: false,
    Parameters: (parameterOverride ?? input.privateInput.parameters).map(({
      ParameterKey, ParameterValue
    }) => ({ ParameterKey, ParameterValue })),
    RoleARN: stackRoleArn ?? input.cloudFormationServiceRoleArn,
    StackName: "prooftoact-private-recovery-query",
    Status: changeStatus
  });
  const cloudformation = { async send(command) {
    const name = command.constructor.name;
    calls.push(name);
    if (name === "DescribeStacksCommand") {
      if (state === "ABSENT") {
        const error = new Error("Stack does not exist");
        error.name = "ValidationError";
        throw error;
      }
      return { Stacks: [stack()] };
    }
    if (name === "DescribeChangeSetCommand") {
      if (!changeSet) {
        const error = new Error("ChangeSet does not exist");
        error.name = "ChangeSetNotFound";
        throw error;
      }
      return change();
    }
    if (name === "CreateChangeSetCommand") {
      lastCreateInput = structuredClone(command.input);
      changeSet = true;
      state = "REVIEW_IN_PROGRESS";
      if (lostCreate) {
        lostCreate = false;
        throw new Error("synthetic create-change-set acknowledgement loss");
      }
      return { Id: change().ChangeSetId, StackId: stackId };
    }
    if (name === "ExecuteChangeSetCommand") {
      state = "CREATE_IN_PROGRESS";
      if (lostExecute) {
        lostExecute = false;
        throw new Error("synthetic execute acknowledgement loss");
      }
      return {};
    }
    if (name === "GetTemplateCommand") {
      return { TemplateBody: canonicalJson(templateOverride ?? input.template) };
    }
    if (name === "UpdateTerminationProtectionCommand") {
      enabled = true;
      if (lostProtection) {
        lostProtection = false;
        throw new Error("synthetic protection acknowledgement loss");
      }
      return {};
    }
    throw new Error(`unexpected ${name}`);
  } };
  let clock = 0;
  return {
    calls,
    completeChangeSet() { changeStatus = "CREATE_COMPLETE"; },
    completeStack() { state = "CREATE_COMPLETE"; },
    get createInput() { return lastCreateInput; },
    input,
    options: {
      clients: { cloudformation },
      clock: () => new Date(Date.parse("2026-08-19T02:00:00.000Z") +
        clock++ * 1_000),
      ...input,
      maximumPollAttempts: 3,
      wait: async () => {
        if (state === "CREATE_IN_PROGRESS") state = "CREATE_COMPLETE";
      }
    }
  };
}

test("fresh deployment uses deterministic intent-bound CREATE and converges", async () => {
  const first = providerHarness();
  const receipt = await deployPrivateRecoveryQuery(first.options);
  assert.equal(receipt.status,
    "CREATE_COMPLETE_READBACK_PENDING_EVIDENCE_ROLE");
  assert.equal(first.calls.filter((name) => name === "CreateChangeSetCommand")
    .length, 1);
  assert.equal(first.calls.filter((name) => name === "ExecuteChangeSetCommand")
    .length, 1);
  assert.equal(first.calls.filter((name) =>
    name === "UpdateTerminationProtectionCommand").length, 1);
  const second = providerHarness();
  await deployPrivateRecoveryQuery(second.options);
  assert.equal(second.createInput.ChangeSetName, first.createInput.ChangeSetName);
  assert.equal(second.createInput.ClientToken, first.createInput.ClientToken);
});

for (const [label, initialState, expectedMutation] of [
  ["prepared change set", "REVIEW_IN_PROGRESS", "ExecuteChangeSetCommand"],
  ["accepted stack create", "CREATE_IN_PROGRESS", null],
  ["completed unprotected stack", "CREATE_COMPLETE", null]
]) {
  test(`deployment restarts from ${label}`, async () => {
    const harness = providerHarness({ initialState });
    const receipt = await deployPrivateRecoveryQuery(harness.options);
    assert.equal(receipt.status,
      "CREATE_COMPLETE_READBACK_PENDING_EVIDENCE_ROLE");
    assert.equal(harness.calls.includes("CreateChangeSetCommand"), false);
    assert.equal(harness.calls.includes("ExecuteChangeSetCommand"),
      expectedMutation === "ExecuteChangeSetCommand");
  });
}

test("completed protected stack returns without another provider mutation", async () => {
  const harness = providerHarness({
    initialState: "CREATE_COMPLETE",
    protection: true
  });
  await deployPrivateRecoveryQuery(harness.options);
  assert.equal(harness.calls.some((name) => [
    "CreateChangeSetCommand", "ExecuteChangeSetCommand",
    "UpdateTerminationProtectionCommand"
  ].includes(name)), false);
});

for (const [label, options] of [
  ["change-set creation", { createAckLoss: true }],
  ["execute", { executeAckLoss: true }],
  ["termination protection", { protectionAckLoss: true }]
]) {
  test(`deployment reconciles ${label} acknowledgement loss`, async () => {
    const harness = providerHarness(options);
    const receipt = await deployPrivateRecoveryQuery(harness.options);
    assert.equal(receipt.terminationProtection, true);
  });
}

test("change-set timeout is restartable after exact provider completion", async () => {
  const harness = providerHarness({ changeSetStatus: "CREATE_IN_PROGRESS" });
  await assert.rejects(() => deployPrivateRecoveryQuery({
    ...harness.options,
    maximumPollAttempts: 1
  }), /PRIVATE_RECOVERY_QUERY_DEPLOY_CHANGE_SET_TIMEOUT/u);
  harness.completeChangeSet();
  const receipt = await deployPrivateRecoveryQuery(harness.options);
  assert.equal(receipt.status,
    "CREATE_COMPLETE_READBACK_PENDING_EVIDENCE_ROLE");
});

test("stack timeout is restartable after exact provider completion", async () => {
  const harness = providerHarness({ initialState: "CREATE_IN_PROGRESS" });
  await assert.rejects(() => deployPrivateRecoveryQuery({
    ...harness.options,
    maximumPollAttempts: 1,
    wait: async () => {}
  }), /PRIVATE_RECOVERY_QUERY_DEPLOY_STACK_TIMEOUT/u);
  harness.completeStack();
  const receipt = await deployPrivateRecoveryQuery(harness.options);
  assert.equal(receipt.status,
    "CREATE_COMPLETE_READBACK_PENDING_EVIDENCE_ROLE");
});

test("deployment holds on provider template, parameter, or service-role drift", async () => {
  const changedTemplate = structuredClone(buildPrivateRecoveryQueryTemplate());
  changedTemplate.Description = "drift";
  const variants = [
    providerHarness({ templateOverride: changedTemplate }),
    providerHarness({ stackRoleArn:
      "arn:aws:iam::111111111111:role/UnexpectedRole" })
  ];
  const expected = fixture();
  const driftedParameters = structuredClone(expected.privateInput.parameters);
  driftedParameters[0].ParameterValue = "drift";
  const parameterDrift = providerHarness({
    initialState: "CREATE_COMPLETE",
    parameterOverride: driftedParameters
  });
  variants.push(parameterDrift);
  for (const harness of variants) {
    await assert.rejects(() => deployPrivateRecoveryQuery(harness.options),
      /PRIVATE_RECOVERY_QUERY_DEPLOY_(?:STACK|TEMPLATE|INPUT|CHANGE_SET)_REJECTED/u);
  }
});
