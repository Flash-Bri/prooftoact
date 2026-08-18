import { setTimeout as waitFor } from "node:timers/promises";

import {
  UUID,
  canonicalDigest,
  canonicalJson,
  exactKeys,
  requireCondition
} from "./release-provider-common.js";
import {
  providerOutcome,
  validateExecuteCommand,
  validateExecuteDispatchPlan,
  validateExecuteIntent
} from "./release-provider-execute-common.js";

const MAXIMUM_STACK_POLLS = 72;
const STACK_POLL_INTERVAL_MS = 5_000;
const MINIMUM_EXECUTE_AUTHORITY_MS =
  MAXIMUM_STACK_POLLS * STACK_POLL_INTERVAL_MS + 60_000;
const MINIMUM_PROTECTION_AUTHORITY_MS = 30_000;

function exactTransport(transport) {
  requireCondition(exactKeys(transport, [
    "describeChangeSet", "describeStacks", "executeChangeSet",
    "updateTerminationProtection"
  ]) && Object.values(transport).every((entry) => typeof entry === "function"),
  "RELEASE_PROVIDER_EXECUTE_TRANSPORT_REJECTED");
  return transport;
}

function errorCode(cause) {
  const raw = typeof cause?.message === "string" ? cause.message : "UNKNOWN";
  return raw.replace(/[^A-Z0-9_]/giu, "_").toUpperCase().slice(0, 96);
}

function sampledNow(clock) {
  const value = clock();
  requireCondition(Number.isSafeInteger(value) && value >= 0,
    "RELEASE_PROVIDER_EXECUTE_CLOCK_REJECTED");
  return value;
}

function authorityDeadline(value) {
  const code = "RELEASE_PROVIDER_EXECUTE_AUTHORITY_REJECTED";
  const timestamp = Date.parse(value ?? "");
  requireCondition(typeof value === "string" && Number.isSafeInteger(timestamp) &&
    new Date(timestamp).toISOString() === value, code);
  return timestamp;
}

function assertAuthority(clock, deadline, minimumRemainingMs) {
  const now = sampledNow(clock);
  requireCondition(deadline - now >= minimumRemainingMs,
    "RELEASE_PROVIDER_EXECUTE_AUTHORITY_REJECTED");
  return now;
}

function normalizeChangeSet(value, command) {
  const code = "RELEASE_PROVIDER_EXECUTE_CHANGE_SET_REJECTED";
  requireCondition(value && value.ChangeSetId === command.changeSetArn &&
    value.ChangeSetName === command.changeSetName &&
    value.StackId === command.stackId && value.StackName === "prooftoact-gate2" &&
    value.ChangeSetType === "CREATE" && value.Status === "CREATE_COMPLETE" &&
    value.ExecutionStatus === "AVAILABLE" &&
    value.IncludeNestedStacks === false && value.NextToken === undefined &&
    value.RoleARN === `arn:aws:iam::${command.accountId}:role/` +
      "ProofToActGate2CloudFormation" &&
    canonicalJson(value.Capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    /^ProofToAct PREPARE [0-9a-f]{64}$/u.test(value.Description ?? "") &&
    Array.isArray(value.Parameters) && value.Parameters.length === 45 &&
    Array.isArray(value.Changes) && value.Changes.length > 0 &&
    value.Changes.length <= 128, code);
  return Object.freeze({
    capabilities: value.Capabilities,
    changeCount: value.Changes.length,
    changeSetArn: value.ChangeSetId,
    changeSetName: value.ChangeSetName,
    description: value.Description,
    executionStatus: value.ExecutionStatus,
    parameterCount: value.Parameters.length,
    roleArn: value.RoleARN,
    stackId: value.StackId,
    stackName: value.StackName,
    status: value.Status,
    type: value.ChangeSetType
  });
}

function exactStack(value, command) {
  const code = "RELEASE_PROVIDER_EXECUTE_STACK_REJECTED";
  requireCondition(value && Array.isArray(value.Stacks) &&
    value.Stacks.length === 1 && value.NextToken === undefined &&
    value.Stacks[0].StackId === command.stackId &&
    value.Stacks[0].StackName === "prooftoact-gate2" &&
    typeof value.Stacks[0].StackStatus === "string", code);
  return value.Stacks[0];
}

function terminalFailureStatus(status) {
  return /(?:FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|DELETE_COMPLETE|DELETE_FAILED)$/u
    .test(status);
}

function outcomeReceipt(command, intent, details) {
  return canonicalDigest({
    commandSha256: command.commandSha256,
    intentSha256: canonicalDigest(intent),
    ...details
  });
}

function dispatcherWithClock({ clock, pause, transport }) {
  const provider = exactTransport(transport);
  requireCondition(typeof clock === "function" && typeof pause === "function",
    "RELEASE_PROVIDER_EXECUTE_CONFIGURATION_REJECTED");
  return Object.freeze({
    async dispatch(input) {
      const inputCode = "RELEASE_PROVIDER_EXECUTE_INPUT_REJECTED";
      requireCondition(exactKeys(input, [
        "authorityNotAfter", "command", "dispatchPlan", "intent",
        "maxAttempts", "providerNativeIdempotencyToken"
      ]) && input.maxAttempts === 1, inputCode);
      const command = validateExecuteCommand(input.command);
      const intent = validateExecuteIntent(input.intent, command);
      validateExecuteDispatchPlan(input.dispatchPlan, command, intent);
      requireCondition(input.providerNativeIdempotencyToken === intent.intentId,
        inputCode);
      const deadline = authorityDeadline(input.authorityNotAfter);
      let executeAttempted = false;
      let executeRequestId = null;
      let preflight = null;
      try {
        assertAuthority(clock, deadline, MINIMUM_EXECUTE_AUTHORITY_MS);
        preflight = normalizeChangeSet(await provider.describeChangeSet({
          ChangeSetName: command.changeSetArn,
          IncludePropertyValues: true,
          StackName: command.stackId
        }), command);
      } catch (cause) {
        const observedAt = new Date(sampledNow(clock)).toISOString();
        return providerOutcome({
          command,
          observedAt,
          possibleMutation: false,
          providerReceiptSha256: outcomeReceipt(command, intent, {
            errorCode: errorCode(cause),
            phase: "PRE_EXECUTION_EXACT_READBACK",
            status: "CONFIRMED_NOT_ATTEMPTED"
          }),
          providerRequestId: null,
          status: "FAILED_TERMINAL"
        });
      }
      try {
        assertAuthority(clock, deadline, MINIMUM_EXECUTE_AUTHORITY_MS);
        executeAttempted = true;
        const response = await provider.executeChangeSet({
          ChangeSetName: command.changeSetArn,
          ClientRequestToken: intent.intentId
        });
        requireCondition(UUID.test(response?.$metadata?.requestId ?? ""),
          "RELEASE_PROVIDER_EXECUTE_ACK_REJECTED");
        executeRequestId = response.$metadata.requestId;
        let stack = null;
        for (let index = 0; index < MAXIMUM_STACK_POLLS; index += 1) {
          stack = exactStack(await provider.describeStacks({
            StackName: command.stackId
          }), command);
          if (stack.StackStatus === "CREATE_COMPLETE" ||
            terminalFailureStatus(stack.StackStatus)) break;
          requireCondition([
            "REVIEW_IN_PROGRESS", "CREATE_IN_PROGRESS"
          ].includes(stack.StackStatus),
          "RELEASE_PROVIDER_EXECUTE_STACK_STATUS_REJECTED");
          await pause(STACK_POLL_INTERVAL_MS);
        }
        requireCondition(stack?.StackStatus === "CREATE_COMPLETE",
          "RELEASE_PROVIDER_EXECUTE_COMPLETION_UNCONFIRMED");
        assertAuthority(clock, deadline, MINIMUM_PROTECTION_AUTHORITY_MS);
        const protection = await provider.updateTerminationProtection({
          EnableTerminationProtection: true,
          StackName: command.stackId
        });
        requireCondition(protection?.StackId === command.stackId &&
          UUID.test(protection?.$metadata?.requestId ?? ""),
        "RELEASE_PROVIDER_EXECUTE_PROTECTION_ACK_REJECTED");
        const protectedStack = exactStack(await provider.describeStacks({
          StackName: command.stackId
        }), command);
        requireCondition(protectedStack.StackStatus === "CREATE_COMPLETE" &&
          protectedStack.EnableTerminationProtection === true,
        "RELEASE_PROVIDER_EXECUTE_PROTECTION_READBACK_REJECTED");
        const observedAt = new Date(sampledNow(clock)).toISOString();
        return providerOutcome({
          command,
          observedAt,
          possibleMutation: true,
          providerReceiptSha256: outcomeReceipt(command, intent, {
            executeRequestId,
            preflightSha256: canonicalDigest(preflight),
            protectionRequestId: protection.$metadata.requestId,
            stackStatus: protectedStack.StackStatus,
            status: "EXECUTION_ACKNOWLEDGED_INDEPENDENT_READBACK_REQUIRED",
            terminationProtection: true
          }),
          providerRequestId: executeRequestId,
          status: "AMBIGUOUS"
        });
      } catch (cause) {
        const observedAt = new Date(sampledNow(clock)).toISOString();
        return providerOutcome({
          command,
          observedAt,
          possibleMutation: true,
          providerReceiptSha256: outcomeReceipt(command, intent, {
            errorCode: errorCode(cause),
            executeAttempted,
            executeRequestId,
            preflightSha256: canonicalDigest(preflight),
            status: "UNKNOWN_DO_NOT_ACT"
          }),
          providerRequestId: executeRequestId,
          status: "AMBIGUOUS"
        });
      }
    }
  });
}

export function createExecuteDispatcher(configuration) {
  requireCondition(exactKeys(configuration, ["transport"]),
    "RELEASE_PROVIDER_EXECUTE_CONFIGURATION_REJECTED");
  return dispatcherWithClock({
    clock: Date.now,
    pause: (milliseconds) => waitFor(milliseconds),
    transport: configuration.transport
  });
}

export function exactDescribeChangeSetInput(input) {
  const code = "RELEASE_PROVIDER_EXECUTE_DESCRIBE_INPUT_REJECTED";
  requireCondition(exactKeys(input, [
    "ChangeSetName", "IncludePropertyValues", "StackName"
  ]) && input.IncludePropertyValues === true &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.ChangeSetName ?? "") ?? [])[1] ?? "") &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
      .test(input.ChangeSetName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.StackName ?? "") ?? [])[1] ?? "") &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? "") &&
    input.ChangeSetName.split(":")[4] === input.StackName.split(":")[4], code);
  return input;
}

export function exactExecuteChangeSetInput(input) {
  const code = "RELEASE_PROVIDER_EXECUTE_MUTATION_INPUT_REJECTED";
  requireCondition(exactKeys(input, ["ChangeSetName", "ClientRequestToken"]) &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
      .test(input.ChangeSetName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.ChangeSetName ?? "") ?? [])[1] ?? "") && UUID.test(
      input.ClientRequestToken ?? ""), code);
  return input;
}

export function exactExecuteStackInput(input) {
  requireCondition(exactKeys(input, ["StackName"]) &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.StackName ?? "") ?? [])[1] ?? ""),
  "RELEASE_PROVIDER_EXECUTE_STACK_INPUT_REJECTED");
  return input;
}

export function exactTerminationProtectionInput(input) {
  requireCondition(exactKeys(input, [
    "EnableTerminationProtection", "StackName"
  ]) && input.EnableTerminationProtection === true &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(input.StackName ?? "") &&
    UUID.test((/\/([0-9a-f-]{36})$/u.exec(input.StackName ?? "") ?? [])[1] ?? ""),
  "RELEASE_PROVIDER_EXECUTE_PROTECTION_INPUT_REJECTED");
  return input;
}

export const __test = Object.freeze({
  MAXIMUM_STACK_POLLS,
  MINIMUM_EXECUTE_AUTHORITY_MS,
  MINIMUM_PROTECTION_AUTHORITY_MS,
  STACK_POLL_INTERVAL_MS,
  dispatcherWithClock,
  exactStack,
  normalizeChangeSet,
  terminalFailureStatus
});
