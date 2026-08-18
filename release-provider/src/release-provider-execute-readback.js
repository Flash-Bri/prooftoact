import {
  APP_SOURCE,
  HEX_64,
  UUID,
  canonicalDigest,
  exactKeys,
  requireCondition
} from "./release-provider-common.js";
import {
  finalizerReadback,
  validateExecuteCommand,
  validateExecuteIntent
} from "./release-provider-execute-common.js";

const MAXIMUM_EVENT_PAGES = 8;

function exactTransport(transport) {
  requireCondition(exactKeys(transport, [
    "describeChangeSet", "describeStackEvents", "describeStacks"
  ]) && Object.values(transport).every((entry) => typeof entry === "function"),
  "RELEASE_PROVIDER_EXECUTE_READBACK_TRANSPORT_REJECTED");
  return transport;
}

function sampledObservedAt(clock) {
  const value = clock();
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    "RELEASE_PROVIDER_EXECUTE_READBACK_CLOCK_REJECTED");
  return new Date(value).toISOString();
}

function iso(value, code) {
  const timestamp = value instanceof Date ? value.getTime() : Date.parse(value ?? "");
  requireCondition(Number.isFinite(timestamp), code);
  return new Date(timestamp).toISOString();
}

function valueByKey(entries, key, keyName, valueName, code) {
  requireCondition(Array.isArray(entries), code);
  const matches = entries.filter((entry) => entry?.[keyName] === key);
  requireCondition(matches.length === 1 &&
    typeof matches[0][valueName] === "string", code);
  return matches[0][valueName];
}

function normalizeExecutedChangeSet(value, command) {
  const code = "RELEASE_PROVIDER_EXECUTE_READBACK_CHANGE_SET_REJECTED";
  requireCondition(value && value.ChangeSetId === command.changeSetArn &&
    value.ChangeSetName === command.changeSetName &&
    value.StackId === command.stackId && value.StackName === "prooftoact-gate2" &&
    value.ChangeSetType === "CREATE" && value.Status === "CREATE_COMPLETE" &&
    value.ExecutionStatus === "EXECUTE_COMPLETE" &&
    value.IncludeNestedStacks === false && value.NextToken === undefined &&
    value.RoleARN === `arn:aws:iam::${command.accountId}:role/` +
      "ProofToActGate2CloudFormation" &&
    /^ProofToAct PREPARE [0-9a-f]{64}$/u.test(value.Description ?? "") &&
    Array.isArray(value.Parameters) && value.Parameters.length === 45 &&
    Array.isArray(value.Changes) && value.Changes.length > 0 &&
    value.Changes.length <= 128 && UUID.test(
      value?.$metadata?.requestId ?? ""), code);
  return Object.freeze({
    changeCount: value.Changes.length,
    changeSetArn: value.ChangeSetId,
    changeSetName: value.ChangeSetName,
    description: value.Description,
    executionStatus: value.ExecutionStatus,
    parameterCount: value.Parameters.length,
    providerRequestId: value.$metadata.requestId,
    roleArn: value.RoleARN,
    stackId: value.StackId,
    status: value.Status
  });
}

function normalizeStack(value, command) {
  const code = "RELEASE_PROVIDER_EXECUTE_READBACK_STACK_REJECTED";
  requireCondition(value && Array.isArray(value.Stacks) &&
    value.Stacks.length === 1 && value.NextToken === undefined &&
    UUID.test(value?.$metadata?.requestId ?? ""), code);
  const stack = value.Stacks[0];
  requireCondition(stack.StackId === command.stackId &&
    stack.StackName === "prooftoact-gate2" &&
    stack.StackStatus === "CREATE_COMPLETE" &&
    stack.EnableTerminationProtection === true &&
    valueByKey(stack.Parameters, "SourceCommit", "ParameterKey",
      "ParameterValue", code) === APP_SOURCE.commit &&
    valueByKey(stack.Parameters, "TreeDigest", "ParameterKey",
      "ParameterValue", code) === APP_SOURCE.tree &&
    valueByKey(stack.Parameters, "EnableProbeFunctions", "ParameterKey",
      "ParameterValue", code) === "false" &&
    valueByKey(stack.Tags, "Project", "Key", "Value", code) === "ProofToAct" &&
    valueByKey(stack.Tags, "Purpose", "Key", "Value", code) ===
      "BoundedHackathonRelease" &&
    valueByKey(stack.Tags, "SourceCommit", "Key", "Value", code) ===
      APP_SOURCE.commit, code);
  const apiEndpoint = valueByKey(stack.Outputs, "ApiEndpoint", "OutputKey",
    "OutputValue", code);
  const publicDemoUrl = valueByKey(stack.Outputs, "PublicDemoUrl", "OutputKey",
    "OutputValue", code);
  requireCondition(
    /^https:\/\/[a-z0-9]{10}\.execute-api\.us-east-1\.amazonaws\.com$/u
      .test(apiEndpoint) && publicDemoUrl === `${apiEndpoint}/` &&
    valueByKey(stack.Outputs, "SourceCommit", "OutputKey", "OutputValue",
      code) === APP_SOURCE.commit, code);
  return Object.freeze({
    apiEndpoint,
    creationTime: iso(stack.CreationTime, code),
    outputCount: stack.Outputs.length,
    parameterCount: stack.Parameters.length,
    providerRequestId: value.$metadata.requestId,
    publicDemoUrl,
    stackId: stack.StackId,
    stackName: stack.StackName,
    stackStatus: stack.StackStatus,
    tagCount: stack.Tags.length,
    terminationProtection: true
  });
}

async function readAllEvents(provider, command) {
  const code = "RELEASE_PROVIDER_EXECUTE_READBACK_EVENTS_REJECTED";
  const events = [];
  const tokens = new Set();
  let nextToken;
  let providerRequestId = null;
  for (let page = 0; page < MAXIMUM_EVENT_PAGES; page += 1) {
    const response = await provider.describeStackEvents({
      StackName: command.stackId,
      ...(nextToken === undefined ? {} : { NextToken: nextToken })
    });
    requireCondition(Array.isArray(response?.StackEvents) &&
      UUID.test(response?.$metadata?.requestId ?? ""), code);
    providerRequestId = response.$metadata.requestId;
    events.push(...response.StackEvents);
    nextToken = response.NextToken;
    if (nextToken === undefined) break;
    requireCondition(typeof nextToken === "string" && nextToken.length > 0 &&
      nextToken.length <= 4096 && !tokens.has(nextToken), code);
    tokens.add(nextToken);
  }
  requireCondition(nextToken === undefined && events.length > 0 &&
    events.length <= 1024, code);
  requireCondition(events.every((event) => event &&
    typeof event.EventId === "string" && event.EventId.length > 0 &&
    event.EventId.length <= 1024 &&
    typeof event.LogicalResourceId === "string" &&
    event.LogicalResourceId.length > 0 &&
    event.LogicalResourceId.length <= 255 &&
    typeof event.ResourceStatus === "string" &&
    /^[A-Z_]{1,64}$/u.test(event.ResourceStatus) &&
    typeof event.ResourceType === "string" &&
    /^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$/u.test(event.ResourceType) &&
    event.StackId === command.stackId &&
    Number.isFinite(event.Timestamp instanceof Date
      ? event.Timestamp.getTime() : Date.parse(event.Timestamp ?? ""))), code);
  const rootCompletion = events.filter((event) =>
    event?.StackId === command.stackId &&
    event?.PhysicalResourceId === command.stackId &&
    event?.LogicalResourceId === "prooftoact-gate2" &&
    event?.ResourceType === "AWS::CloudFormation::Stack" &&
    event?.ResourceStatus === "CREATE_COMPLETE" &&
    event?.ClientRequestToken === command.intentId);
  requireCondition(rootCompletion.length === 1 &&
    !events.some((event) => /FAILED|ROLLBACK/u.test(
      event?.ResourceStatus ?? "")), code);
  return Object.freeze({
    eventCount: events.length,
    eventSetSha256: canonicalDigest(events.map((event) => ({
      clientRequestToken: event.ClientRequestToken ?? null,
      eventId: event.EventId,
      logicalResourceId: event.LogicalResourceId,
      physicalResourceId: event.PhysicalResourceId ?? null,
      resourceStatus: event.ResourceStatus,
      resourceType: event.ResourceType,
      stackId: event.StackId,
      timestamp: iso(event.Timestamp, code)
    }))),
    providerRequestId,
    rootCompletionAt: iso(rootCompletion[0].Timestamp, code)
  });
}

function readbackWithClock({ clock, transport }) {
  const provider = exactTransport(transport);
  requireCondition(typeof clock === "function",
    "RELEASE_PROVIDER_EXECUTE_READBACK_CONFIGURATION_REJECTED");
  return Object.freeze({
    async readback(input) {
      let command;
      let intent;
      try {
        requireCondition(exactKeys(input, [
          "command", "fresh", "independentOfDispatcher", "intent",
          "providerNativeIdempotencyToken", "readOnly",
          "readerPhaseRuntimeIdentitySha256"
        ]) && input.fresh === true &&
          input.independentOfDispatcher === true && input.readOnly === true &&
          HEX_64.test(input.readerPhaseRuntimeIdentitySha256 ?? ""),
        "RELEASE_PROVIDER_EXECUTE_READBACK_INPUT_REJECTED");
        command = validateExecuteCommand(input.command);
        intent = validateExecuteIntent(input.intent, command);
        command = Object.freeze({ ...command, intentId: intent.intentId });
        requireCondition(input.providerNativeIdempotencyToken === intent.intentId,
          "RELEASE_PROVIDER_EXECUTE_READBACK_INPUT_REJECTED");
        const changeSet = normalizeExecutedChangeSet(
          await provider.describeChangeSet({
            ChangeSetName: command.changeSetArn,
            IncludePropertyValues: true,
            StackName: command.stackId
          }), command);
        const stack = normalizeStack(await provider.describeStacks({
          StackName: command.stackId
        }), command);
        const events = await readAllEvents(provider, command);
        const observedAt = sampledObservedAt(clock);
        const evidence = {
          changeSet,
          commandSha256: command.commandSha256,
          events,
          intentSha256: canonicalDigest(intent),
          stack
        };
        return finalizerReadback({
          command,
          intent,
          observedAt,
          providerReceiptSha256: canonicalDigest(evidence),
          providerRequestId: stack.providerRequestId,
          readerPhaseRuntimeIdentitySha256:
            input.readerPhaseRuntimeIdentitySha256,
          status: "CONFIRMED_APPLIED"
        });
      } catch (cause) {
        requireCondition(command && intent &&
          HEX_64.test(input?.readerPhaseRuntimeIdentitySha256 ?? ""),
        "RELEASE_PROVIDER_EXECUTE_READBACK_INPUT_REJECTED");
        const observedAt = sampledObservedAt(clock);
        return finalizerReadback({
          command,
          intent,
          observedAt,
          providerReceiptSha256: canonicalDigest({
            commandSha256: command.commandSha256,
            errorCode: String(cause?.message ?? "UNKNOWN")
              .replace(/[^A-Z0-9_]/giu, "_").toUpperCase().slice(0, 96),
            intentSha256: canonicalDigest(intent),
            observedAt,
            status: "UNKNOWN"
          }),
          providerRequestId: null,
          readerPhaseRuntimeIdentitySha256:
            input.readerPhaseRuntimeIdentitySha256,
          status: "UNKNOWN"
        });
      }
    }
  });
}

export function createExecuteReadback(configuration) {
  requireCondition(exactKeys(configuration, ["transport"]),
    "RELEASE_PROVIDER_EXECUTE_READBACK_CONFIGURATION_REJECTED");
  return readbackWithClock({ clock: Date.now, transport: configuration.transport });
}

export function exactExecuteReadbackChangeSetInput(input) {
  requireCondition(exactKeys(input, [
    "ChangeSetName", "IncludePropertyValues", "StackName"
  ]) && input.IncludePropertyValues === true &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
      .test(input.ChangeSetName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.ChangeSetName ?? "") ?? [])[1] ?? "") &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.StackName ?? "") ?? [])[1] ?? "") &&
    input.ChangeSetName.split(":")[4] === input.StackName.split(":")[4],
  "RELEASE_PROVIDER_EXECUTE_READBACK_CHANGE_SET_INPUT_REJECTED");
  return input;
}

export function exactExecuteReadbackStackInput(input) {
  requireCondition(exactKeys(input, ["StackName"]) &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.StackName ?? "") ?? [])[1] ?? ""),
  "RELEASE_PROVIDER_EXECUTE_READBACK_STACK_INPUT_REJECTED");
  return input;
}

export function exactExecuteReadbackEventsInput(input) {
  requireCondition(exactKeys(input, [
    "StackName", ...(input?.NextToken === undefined ? [] : ["NextToken"])
  ]) &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.StackName ?? "") ?? [])[1] ?? "") &&
    (input.NextToken === undefined || typeof input.NextToken === "string" &&
      input.NextToken.length > 0 && input.NextToken.length <= 4096 &&
      /^[A-Za-z0-9._:/+=-]+$/u.test(input.NextToken)),
  "RELEASE_PROVIDER_EXECUTE_READBACK_EVENTS_INPUT_REJECTED");
  return input;
}

export const __test = Object.freeze({
  MAXIMUM_EVENT_PAGES,
  normalizeExecutedChangeSet,
  normalizeStack,
  readAllEvents,
  readbackWithClock,
  valueByKey
});
