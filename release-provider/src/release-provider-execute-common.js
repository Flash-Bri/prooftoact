import {
  ACCOUNT_ID,
  APP_SOURCE,
  HEX_64,
  REGION,
  UUID,
  canonicalDigest,
  canonicalJson,
  exactKeys,
  requireCondition,
  sha256
} from "./release-provider-common.js";

const COMMAND_SCHEMA = "prooftoact.provider-broker-command.v2";
const INTENT_SCHEMA = "prooftoact.provider-global-dispatch-intent.v1";
const DISPATCH_PLAN_SCHEMA = "prooftoact.provider-broker-dispatch-plan.v1";
const OUTCOME_SCHEMA = "prooftoact.provider-dispatch-outcome.v1";
const FINALIZER_READBACK_SCHEMA =
  "prooftoact.provider-broker-finalizer-readback.v1";
const EXECUTE_ACTION = "EXECUTE_EXACT_CREATE_CHANGE_SET";
const COMMAND_KEYS = Object.freeze([
  "action", "approvalId", "approvalSha256", "appSource",
  "artifactManifestSha256", "authorityContractSha256", "budgetKeySha256",
  "budgetReservationUsd", "buildReceiptSha256", "changeSetArn",
  "changeSetSha256", "commandSha256", "controlPlaneIdentitySha256",
  "cumulativeCapUsd", "databaseIdentitySha256", "effectIdentitySha256",
  "expectedPriorCumulativeSpendUsd", "globalKeySha256", "lane",
  "maximumConcurrency", "maximumRuns", "namespaceArn",
  "operationIdentitySha256", "providerMutationExpected", "region",
  "schemaVersion", "stackId", "teardownContractSha256",
  "teardownReserveUsd", "workspaceRealpathSha256"
]);

function exactMoney(value, code) {
  requireCondition(Number.isFinite(value) && value >= 0 && value <= 20 &&
    Number(value.toFixed(6)) === value, code);
  return Math.round(value * 1_000_000);
}

function accountFromNamespace(namespaceArn, code) {
  const match =
    /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u
      .exec(namespaceArn ?? "");
  requireCondition(match && ACCOUNT_ID.test(match[1]), code);
  return match[1];
}

export function validateExecuteCommand(command) {
  const code = "RELEASE_PROVIDER_EXECUTE_COMMAND_REJECTED";
  requireCondition(exactKeys(command, COMMAND_KEYS) &&
    command.schemaVersion === COMMAND_SCHEMA &&
    command.action === EXECUTE_ACTION && command.lane === "EXECUTE" &&
    command.providerMutationExpected === true && command.region === REGION &&
    canonicalJson(command.appSource) === canonicalJson(APP_SOURCE) &&
    UUID.test(command.approvalId ?? "") &&
    command.cumulativeCapUsd === 20 && command.maximumRuns === 1 &&
    command.maximumConcurrency === 2 && command.teardownReserveUsd === 1,
  code);
  const accountId = accountFromNamespace(command.namespaceArn, code);
  const changeSet = new RegExp(
    `^arn:aws:cloudformation:us-east-1:${accountId}:changeSet/` +
    "(prooftoact-release-[a-z0-9-]{1,64})/([0-9a-f-]{36})$", "u"
  ).exec(command.changeSetArn ?? "");
  const stack = new RegExp(
      `^arn:aws:cloudformation:us-east-1:${accountId}:stack/` +
      "prooftoact-gate2/([0-9a-f-]{36})$", "u"
    ).exec(command.stackId ?? "");
  requireCondition(changeSet && UUID.test(changeSet[2]) && stack &&
    UUID.test(stack[1]), code);
  for (const key of [
    "approvalSha256", "artifactManifestSha256", "authorityContractSha256",
    "budgetKeySha256", "buildReceiptSha256", "changeSetSha256",
    "commandSha256", "controlPlaneIdentitySha256", "databaseIdentitySha256",
    "effectIdentitySha256", "globalKeySha256", "operationIdentitySha256",
    "teardownContractSha256", "workspaceRealpathSha256"
  ]) requireCondition(HEX_64.test(command[key] ?? ""), code);
  const prior = exactMoney(command.expectedPriorCumulativeSpendUsd, code);
  const reserved = exactMoney(command.budgetReservationUsd, code);
  requireCondition(prior + reserved <= 19_000_000, code);
  const effectIdentitySha256 = canonicalDigest({
    action: EXECUTE_ACTION,
    changeSetArn: command.changeSetArn,
    changeSetSha256: command.changeSetSha256,
    lane: "EXECUTE",
    providerAccountId: accountId,
    region: REGION,
    stackId: command.stackId,
    stackName: "prooftoact-gate2"
  });
  requireCondition(command.effectIdentitySha256 === effectIdentitySha256 &&
    command.globalKeySha256 === sha256(Buffer.from(
      `prooftoact-provider-effect-v2\n${effectIdentitySha256}`, "utf8")) &&
    command.budgetKeySha256 === canonicalDigest({
      currency: "USD", project: "ProofToAct", providerAccountId: accountId,
      region: REGION
    }) && command.operationIdentitySha256 === canonicalDigest({
      approvalId: command.approvalId,
      approvalSha256: command.approvalSha256,
      authorityContractSha256: command.authorityContractSha256,
      controlPlaneIdentitySha256: command.controlPlaneIdentitySha256,
      effectIdentitySha256
    }), code);
  const unsigned = { ...command };
  delete unsigned.commandSha256;
  requireCondition(command.commandSha256 === canonicalDigest(unsigned), code);
  return Object.freeze({ ...command, accountId, changeSetName: changeSet[1] });
}

export function validateExecuteIntent(intent, command) {
  const code = "RELEASE_PROVIDER_EXECUTE_INTENT_REJECTED";
  requireCondition(exactKeys(intent, [
    "action", "approvalId", "commandSha256", "durable", "event",
    "globalKeySha256", "globallyAuthoritative", "intentId", "lane",
    "previousReceiptSha256", "schemaVersion", "status", "version"
  ]) && intent.schemaVersion === INTENT_SCHEMA && intent.status === "DURABLE" &&
    intent.event === "BEFORE_PROVIDER_DISPATCH" && intent.durable === true &&
    intent.globallyAuthoritative === true && intent.action === EXECUTE_ACTION &&
    intent.lane === "EXECUTE" && intent.approvalId === command.approvalId &&
    intent.commandSha256 === command.commandSha256 &&
    intent.globalKeySha256 === command.globalKeySha256 &&
    UUID.test(intent.intentId ?? "") && HEX_64.test(
      intent.previousReceiptSha256 ?? "") && intent.version === 2, code);
  return Object.freeze({ ...intent });
}

export function validateExecuteDispatchPlan(plan, command, intent) {
  const code = "RELEASE_PROVIDER_EXECUTE_DISPATCH_PLAN_REJECTED";
  const stepIdentity = {
    action: EXECUTE_ACTION,
    effectIdentitySha256: command.effectIdentitySha256,
    step: EXECUTE_ACTION
  };
  const expectedStep = {
    idempotencyBindingSha256: canonicalDigest({
      commandSha256: command.commandSha256,
      intentId: intent.intentId,
      stepIdentity
    }),
    idempotencyMechanism: "PROVIDER_NATIVE_CLIENT_REQUEST_TOKEN",
    maximumAttempts: 1,
    mutating: true,
    name: EXECUTE_ACTION,
    providerNativeIdempotencyToken: intent.intentId
  };
  requireCondition(exactKeys(plan, [
    "brokerDispatcherInvocationCount", "commandSha256", "dispatchPlanSha256",
    "intentSha256", "lane", "noAutomaticRetry", "schemaVersion", "steps"
  ]) && plan.schemaVersion === DISPATCH_PLAN_SCHEMA &&
    plan.brokerDispatcherInvocationCount === 1 &&
    plan.commandSha256 === command.commandSha256 &&
    plan.intentSha256 === canonicalDigest(intent) && plan.lane === "EXECUTE" &&
    plan.noAutomaticRetry === true && Array.isArray(plan.steps) &&
    plan.steps.length === 1 &&
    canonicalJson(plan.steps[0]) === canonicalJson(expectedStep), code);
  const unsigned = { ...plan };
  delete unsigned.dispatchPlanSha256;
  requireCondition(plan.dispatchPlanSha256 === canonicalDigest(unsigned), code);
  return Object.freeze({ ...plan, steps: Object.freeze([...plan.steps]) });
}

export function providerOutcome({ command, observedAt, possibleMutation,
  providerReceiptSha256, providerRequestId, status }) {
  return Object.freeze({
    schemaVersion: OUTCOME_SCHEMA,
    status,
    operationIdentitySha256: command.operationIdentitySha256,
    possibleMutation,
    providerRequestId,
    observedAt,
    providerReceiptSha256
  });
}

export function finalizerReadback({ command, intent, observedAt,
  preparedRelease = null, providerReceiptSha256, providerRequestId,
  readerPhaseRuntimeIdentitySha256, status }) {
  return Object.freeze({
    schemaVersion: FINALIZER_READBACK_SCHEMA,
    status,
    commandSha256: command.commandSha256,
    fresh: true,
    independentOfDispatcher: true,
    intentSha256: canonicalDigest(intent),
    observedAt,
    operationIdentitySha256: command.operationIdentitySha256,
    preparedRelease,
    providerNativeIdempotencyTokenSha256:
      sha256(Buffer.from(intent.intentId, "utf8")),
    providerReceiptSha256,
    providerRequestId,
    readOnly: true,
    readerPhaseRuntimeIdentitySha256
  });
}

export const executeConstants = Object.freeze({
  DISPATCH_PLAN_SCHEMA,
  EXECUTE_ACTION,
  FINALIZER_READBACK_SCHEMA,
  OUTCOME_SCHEMA
});
