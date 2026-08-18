import { attestReleaseControlTable } from
  "../../scripts/lib/release-control-table-identity.js";
import {
  ACCOUNT_ID,
  APP_SOURCE,
  HEX_64,
  REGION,
  TABLE_NAME,
  UUID,
  canonicalBytes,
  canonicalDigest,
  canonicalJson,
  deepFreeze,
  exactKeys,
  normalizeCallerIdentity,
  plainObject,
  providerRequestId,
  requireCondition,
  sha256,
  tableArnFor
} from "./release-provider-common.js";
import { validateExecuteCommand } from
  "./release-provider-execute-common.js";

const MAX_CANONICAL_BYTES = 128 * 1024;
const COMMAND_SCHEMA = "prooftoact.provider-broker-command.v2";
const CONSUMPTION_SCHEMA =
  "prooftoact.provider-global-approval-consumption.v1";
const INTENT_SCHEMA = "prooftoact.provider-global-dispatch-intent.v1";
const OUTCOME_SCHEMA = "prooftoact.provider-dispatch-outcome.v1";
const RECORD_SCHEMA = "prooftoact.provider-global-record.v1";
const TERMINAL_SCHEMA = "prooftoact.provider-global-terminal-record.v1";
const PREPARE_COMMAND_KEYS = Object.freeze([
  "action", "approvalId", "approvalSha256", "appSource",
  "artifactManifestSha256", "authorityContractSha256",
  "budgetKeySha256", "budgetReservationUsd", "buildReceiptSha256",
  "changeSetName", "commandSha256", "controlPlaneIdentitySha256",
  "cumulativeCapUsd", "databaseIdentitySha256", "effectIdentitySha256",
  "expectedPriorCumulativeSpendUsd", "globalKeySha256", "lane",
  "maximumConcurrency", "maximumRuns", "namespaceArn",
  "operationIdentitySha256", "parameterManifestSha256",
  "providerMutationExpected", "region", "resourceInventorySha256",
  "schemaVersion", "stackName", "teardownContractSha256", "teardownReserveUsd",
  "templateSha256", "workspaceRealpathSha256"
]);

function avString(item, key, code) {
  const attribute = item?.[key];
  requireCondition(exactKeys(attribute, ["S"]) &&
    typeof attribute.S === "string", code);
  return attribute.S;
}

function avInteger(item, key, code) {
  const attribute = item?.[key];
  requireCondition(exactKeys(attribute, ["N"]) &&
    /^(?:0|[1-9][0-9]*)$/u.test(attribute.N ?? ""), code);
  const value = Number(attribute.N);
  requireCondition(Number.isSafeInteger(value), code);
  return value;
}

function decodeCanonical(attribute, code) {
  requireCondition(exactKeys(attribute, ["B"]) &&
    (Buffer.isBuffer(attribute.B) || attribute.B instanceof Uint8Array), code);
  const bytes = Buffer.from(attribute.B);
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES,
    code);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    throw new Error(code, { cause });
  }
  requireCondition(canonicalBytes(value).equals(bytes), code);
  return value;
}

function exactMoney(value, code) {
  requireCondition(Number.isFinite(value) && value >= 0 && value <= 20 &&
    Number(value.toFixed(6)) === value, code);
  return Math.round(value * 1_000_000);
}

export function validatePrepareCommand(command, tableArn) {
  const code = "RELEASE_PROVIDER_PREPARE_COMMAND_REJECTED";
  const account = /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u
    .exec(tableArn ?? "")?.[1];
  requireCondition(ACCOUNT_ID.test(account ?? "") &&
    exactKeys(command, PREPARE_COMMAND_KEYS) &&
    command.schemaVersion === COMMAND_SCHEMA &&
    command.action === "PREPARE_EXACT_CREATE_CHANGE_SET" &&
    command.lane === "PREPARE" && command.providerMutationExpected === true &&
    command.region === REGION && command.namespaceArn === tableArn &&
    exactKeys(command.appSource, ["commit", "repository", "tree"]) &&
    canonicalJson(command.appSource) === canonicalJson(APP_SOURCE) &&
    UUID.test(command.approvalId ?? "") &&
    /^prooftoact-release-[a-z0-9-]{1,64}$/u.test(
      command.changeSetName ?? "") &&
    command.stackName === "prooftoact-gate2" &&
    command.cumulativeCapUsd === 20 && command.maximumRuns === 1 &&
    command.maximumConcurrency === 2 && command.teardownReserveUsd === 1,
  code);
  for (const key of [
    "approvalSha256", "artifactManifestSha256", "authorityContractSha256",
    "budgetKeySha256", "buildReceiptSha256", "commandSha256",
    "controlPlaneIdentitySha256", "databaseIdentitySha256",
    "effectIdentitySha256", "globalKeySha256", "operationIdentitySha256",
    "parameterManifestSha256", "resourceInventorySha256",
    "teardownContractSha256", "templateSha256", "workspaceRealpathSha256"
  ]) requireCondition(HEX_64.test(command[key] ?? ""), code);
  exactMoney(command.budgetReservationUsd, code);
  exactMoney(command.expectedPriorCumulativeSpendUsd, code);
  const effectIdentitySha256 = canonicalDigest({
    action: command.action,
    artifactManifestSha256: command.artifactManifestSha256,
    buildReceiptSha256: command.buildReceiptSha256,
    changeSetName: command.changeSetName,
    lane: command.lane,
    parameterManifestSha256: command.parameterManifestSha256,
    providerAccountId: account,
    region: REGION,
    resourceInventorySha256: command.resourceInventorySha256,
    stackName: command.stackName,
    templateSha256: command.templateSha256
  });
  requireCondition(command.effectIdentitySha256 === effectIdentitySha256 &&
    command.globalKeySha256 === sha256(Buffer.from(
      `prooftoact-provider-effect-v2\n${effectIdentitySha256}`, "utf8")) &&
    command.budgetKeySha256 === canonicalDigest({
      currency: "USD", project: "ProofToAct", providerAccountId: account,
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
  canonicalBytes(command);
  return deepFreeze(structuredClone(command));
}

function validateLaneCommand(command, tableArn, lane) {
  if (lane === "PREPARE") return validatePrepareCommand(command, tableArn);
  requireCondition(lane === "EXECUTE",
    "RELEASE_PROVIDER_COMMAND_LANE_REJECTED");
  validateExecuteCommand(command);
  requireCondition(command.namespaceArn === tableArn,
    "RELEASE_PROVIDER_EXECUTE_COMMAND_REJECTED");
  return deepFreeze(structuredClone(command));
}

function validateConsumption(value, command) {
  const code = "RELEASE_PROVIDER_CONSUMPTION_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalId", "approvalSha256", "budgetKeySha256", "budgetVersion",
    "commandSha256", "consumedAt", "cumulativeCapUsd", "durable",
    "effectIdentitySha256", "globalKeySha256", "globallyAuthoritative",
    "namespaceArn", "oneShot", "priorCumulativeSpendUsd", "reservedSpendUsd",
    "resultingCumulativeSpendUsd", "schemaVersion", "status", "storeRequestId",
    "stronglyConsistent", "version"
  ]) && value.schemaVersion === CONSUMPTION_SCHEMA &&
    value.status === "CONSUMED" && value.approvalId === command.approvalId &&
    value.approvalSha256 === command.approvalSha256 &&
    value.budgetKeySha256 === command.budgetKeySha256 &&
    value.commandSha256 === command.commandSha256 &&
    value.effectIdentitySha256 === command.effectIdentitySha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArn === command.namespaceArn &&
    value.cumulativeCapUsd === 20 && value.durable === true &&
    value.globallyAuthoritative === true && value.oneShot === true &&
    value.stronglyConsistent === true && value.version === 1 &&
    Number.isSafeInteger(value.budgetVersion) && value.budgetVersion >= 1 &&
    UUID.test(value.storeRequestId ?? "") &&
    Number.isFinite(Date.parse(value.consumedAt)), code);
  const prior = exactMoney(value.priorCumulativeSpendUsd, code);
  const reserved = exactMoney(value.reservedSpendUsd, code);
  const resulting = exactMoney(value.resultingCumulativeSpendUsd, code);
  requireCondition(prior ===
    exactMoney(command.expectedPriorCumulativeSpendUsd, code) &&
    reserved === exactMoney(command.budgetReservationUsd, code) &&
    prior + reserved === resulting, code);
  return value;
}

function validateIntent(value, command, consumption) {
  const code = "RELEASE_PROVIDER_INTENT_REJECTED";
  requireCondition(exactKeys(value, [
    "action", "approvalId", "commandSha256", "durable", "event",
    "globalKeySha256", "globallyAuthoritative", "intentId", "lane",
    "previousReceiptSha256", "schemaVersion", "status", "version"
  ]) && value.schemaVersion === INTENT_SCHEMA && value.status === "DURABLE" &&
    value.event === "BEFORE_PROVIDER_DISPATCH" &&
    value.action === command.action && value.approvalId === command.approvalId &&
    value.commandSha256 === command.commandSha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.lane === command.lane && value.previousReceiptSha256 ===
      canonicalDigest(consumption) && UUID.test(value.intentId ?? "") &&
    value.version === 2 && value.durable === true &&
    value.globallyAuthoritative === true, code);
  return value;
}

function validateOutcome(value, command) {
  const code = "RELEASE_PROVIDER_OUTCOME_REJECTED";
  requireCondition(exactKeys(value, [
    "observedAt", "operationIdentitySha256", "possibleMutation",
    "providerReceiptSha256", "providerRequestId", "schemaVersion", "status"
  ]) && value.schemaVersion === OUTCOME_SCHEMA && [
    "AMBIGUOUS", "CONFIRMED", "FAILED_TERMINAL"
  ].includes(value.status) && value.operationIdentitySha256 ===
    command.operationIdentitySha256 &&
    (value.status === "FAILED_TERMINAL"
      ? value.possibleMutation === false
      : value.possibleMutation === command.providerMutationExpected) &&
    (UUID.test(value.providerRequestId ?? "") ||
      ["AMBIGUOUS", "FAILED_TERMINAL"].includes(value.status) &&
        value.providerRequestId === null) &&
    HEX_64.test(value.providerReceiptSha256 ?? "") &&
    Number.isFinite(Date.parse(value.observedAt)), code);
  canonicalBytes(value);
  return value;
}

function validateTerminal(value, command, predecessor) {
  const code = "RELEASE_PROVIDER_TERMINAL_REJECTED";
  const predecessorState = predecessor?.schemaVersion === INTENT_SCHEMA
    ? "INTENT"
    : predecessor?.schemaVersion === CONSUMPTION_SCHEMA
      ? "CONSUMPTION" : null;
  requireCondition(exactKeys(value, [
    "approvalId", "commandSha256", "durable", "globalKeySha256",
    "globallyAuthoritative", "outcome", "predecessorReceiptSha256",
    "predecessorState", "recordedAt", "schemaVersion", "status",
    "terminalSha256", "version"
  ]) && predecessorState !== null && value.schemaVersion === TERMINAL_SCHEMA &&
    value.status === "TERMINAL" && value.approvalId === command.approvalId &&
    value.commandSha256 === command.commandSha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.durable === true && value.globallyAuthoritative === true &&
    value.predecessorState === predecessorState &&
    value.predecessorReceiptSha256 === canonicalDigest(predecessor) &&
    value.version === predecessor.version + 1 &&
    Number.isFinite(Date.parse(value.recordedAt)), code);
  validateOutcome(value.outcome, command);
  requireCondition(predecessorState !== "CONSUMPTION" ||
    value.outcome.status === "FAILED_TERMINAL" &&
      value.outcome.possibleMutation === false, code);
  const unsigned = { ...value };
  delete unsigned.terminalSha256;
  requireCondition(value.terminalSha256 === canonicalDigest(unsigned), code);
  canonicalBytes(value);
  return value;
}

function decodeImmutableLaneRecordItem({
  commandSha256,
  globalKeySha256,
  item,
  lane,
  tableArn
}) {
  const code = "RELEASE_PROVIDER_GLOBAL_RECORD_ITEM_REJECTED";
  requireCondition(HEX_64.test(commandSha256 ?? "") &&
    HEX_64.test(globalKeySha256 ?? "") && plainObject(item), code);
  const state = avString(item, "state", code);
  requireCondition(["CONSUMED", "INTENT", "TERMINAL"].includes(state), code);
  const hasIntent = item.intent !== undefined || item.intentSha256 !== undefined;
  const hasTerminal = item.terminal !== undefined ||
    item.terminalSha256 !== undefined;
  requireCondition((item.intent !== undefined) ===
    (item.intentSha256 !== undefined) && (item.terminal !== undefined) ===
    (item.terminalSha256 !== undefined) &&
    (state === "CONSUMED"
      ? !hasIntent && !hasTerminal
      : state === "INTENT"
        ? hasIntent && !hasTerminal
        : hasTerminal), code);
  requireCondition(exactKeys(item, [
    "approvalId", "approvalSha256", "budgetKeySha256", "budgetVersion",
    "command", "commandSha256", "consumption", "consumptionSha256",
    "effectIdentitySha256", "entity", "globalKeySha256", "namespaceArn",
    "pk", "state", "version",
    ...(hasIntent ? ["intent", "intentSha256"] : []),
    ...(hasTerminal ? ["terminal", "terminalSha256"] : [])
  ]), code);
  const command = validateLaneCommand(decodeCanonical(item.command, code),
    tableArn, lane);
  const consumption = validateConsumption(
    decodeCanonical(item.consumption, code), command);
  requireCondition(command.commandSha256 === commandSha256 &&
    command.globalKeySha256 === globalKeySha256 &&
    avString(item, "pk", code) === `EFFECT#${globalKeySha256}` &&
    avString(item, "entity", code) === "EFFECT_V1" &&
    avInteger(item, "budgetVersion", code) === consumption.budgetVersion &&
    avString(item, "commandSha256", code) === commandSha256 &&
    avString(item, "globalKeySha256", code) === globalKeySha256 &&
    avString(item, "effectIdentitySha256", code) ===
      command.effectIdentitySha256 &&
    avString(item, "approvalId", code) === command.approvalId &&
    avString(item, "approvalSha256", code) === command.approvalSha256 &&
    avString(item, "budgetKeySha256", code) === command.budgetKeySha256 &&
    avString(item, "namespaceArn", code) === tableArn &&
    avString(item, "consumptionSha256", code) ===
      canonicalDigest(consumption), code);
  let intent = null;
  if (hasIntent) {
    intent = validateIntent(decodeCanonical(item.intent, code), command,
      consumption);
    requireCondition(avString(item, "intentSha256", code) ===
      canonicalDigest(intent), code);
  }
  let terminal = null;
  if (hasTerminal) {
    terminal = validateTerminal(decodeCanonical(item.terminal, code), command,
      intent ?? consumption);
    requireCondition(avString(item, "terminalSha256", code) ===
      terminal.terminalSha256, code);
  }
  requireCondition(avInteger(item, "version", code) ===
    (state === "CONSUMED" ? 1 : state === "INTENT" ? 2 : terminal.version),
  code);
  canonicalBytes({ command, consumption, intent, terminal });
  return deepFreeze({
    schemaVersion: RECORD_SCHEMA,
    status: state,
    command,
    consumption,
    intent,
    terminal
  });
}

export function decodeImmutablePrepareRecordItem(options) {
  return decodeImmutableLaneRecordItem({ ...options, lane: "PREPARE" });
}

export function decodeImmutableExecuteRecordItem(options) {
  return decodeImmutableLaneRecordItem({ ...options, lane: "EXECUTE" });
}

export function decodeImmutablePrepareIntentItem({
  commandSha256,
  globalKeySha256,
  intentId,
  item,
  tableArn
}) {
  const code = "RELEASE_PROVIDER_INTENT_ITEM_REJECTED";
  requireCondition(UUID.test(intentId ?? ""), code);
  const record = decodeImmutablePrepareRecordItem({
    commandSha256, globalKeySha256, item, tableArn
  });
  requireCondition(record.status === "INTENT" && record.intent !== null &&
    record.intent.intentId === intentId && record.terminal === null, code);
  return deepFreeze({ command: record.command, consumption: record.consumption,
    intent: record.intent });
}

export function decodeImmutableExecuteIntentItem({
  commandSha256,
  globalKeySha256,
  intentId,
  item,
  tableArn
}) {
  const code = "RELEASE_PROVIDER_EXECUTE_INTENT_ITEM_REJECTED";
  requireCondition(UUID.test(intentId ?? ""), code);
  const record = decodeImmutableExecuteRecordItem({
    commandSha256, globalKeySha256, item, tableArn
  });
  requireCondition(record.status === "INTENT" && record.intent !== null &&
    record.intent.intentId === intentId && record.terminal === null, code);
  return deepFreeze({ command: record.command, consumption: record.consumption,
    intent: record.intent });
}

function exactTransport(transport) {
  requireCondition(exactKeys(transport, [
    "describeTable", "getCallerIdentity", "getIntentItem", "listTags"
  ]) && Object.values(transport).every((value) => typeof value === "function"),
  "RELEASE_PROVIDER_PERMIT_TRANSPORT_REJECTED");
  return transport;
}

function createPermitReader({
  accountId,
  expectedTableIdentity,
  lane,
  permitSchema,
  roleName,
  transport
}) {
  const provider = exactTransport(transport);
  const tableArn = tableArnFor(accountId);
  requireCondition(plainObject(expectedTableIdentity) &&
    expectedTableIdentity.namespaceArn === tableArn &&
    HEX_64.test(expectedTableIdentity.tableIdentitySha256 ?? ""),
  "RELEASE_PROVIDER_EXPECTED_TABLE_IDENTITY_REJECTED");

  async function readRecord({ commandSha256, globalKeySha256 }) {
    const caller = normalizeCallerIdentity(
      await provider.getCallerIdentity(), roleName);
    requireCondition(caller.accountId === accountId,
      "RELEASE_PROVIDER_CALLER_ACCOUNT_REJECTED");
    const [describeResponse, listTagsResponse] = await Promise.all([
      provider.describeTable({ TableName: TABLE_NAME }),
      provider.listTags({ ResourceArn: tableArn })
    ]);
    const tableIdentity = attestReleaseControlTable({
      describeResponse,
      expectedAccountId: accountId,
      listTagsResponse,
      region: REGION
    });
    requireCondition(canonicalJson(tableIdentity) ===
      canonicalJson(expectedTableIdentity),
    "RELEASE_PROVIDER_LIVE_TABLE_IDENTITY_REJECTED");
    const response = await provider.getIntentItem({
      ConsistentRead: true,
      Key: { pk: { S: `EFFECT#${globalKeySha256}` } },
      ReturnConsumedCapacity: "NONE",
      TableName: TABLE_NAME
    });
    requireCondition(exactKeys(response, ["$metadata", "Item"]),
      "RELEASE_PROVIDER_INTENT_READ_REJECTED");
    const storeReadRequestId = providerRequestId(
      response.$metadata?.requestId,
      "RELEASE_PROVIDER_INTENT_READ_REJECTED"
    );
    const record = lane === "PREPARE"
      ? decodeImmutablePrepareRecordItem({
          commandSha256, globalKeySha256, item: response.Item, tableArn
        })
      : decodeImmutableExecuteRecordItem({
          commandSha256, globalKeySha256, item: response.Item, tableArn
        });
    return deepFreeze({ caller, record, storeReadRequestId, tableIdentity });
  }

  return Object.freeze({
    async readIntent(request) {
      const code = "RELEASE_PROVIDER_INTENT_REQUEST_REJECTED";
      requireCondition(exactKeys(request, [
        "commandSha256", "globalKeySha256", "intentId"
      ]) && HEX_64.test(request.commandSha256 ?? "") &&
        HEX_64.test(request.globalKeySha256 ?? "") &&
        UUID.test(request.intentId ?? ""), code);
      const { caller, record, storeReadRequestId, tableIdentity } =
        await readRecord(request);
      requireCondition(record.status === "INTENT" && record.intent !== null &&
        record.intent.intentId === request.intentId && record.terminal === null,
      code);
      const permit = {
        schemaVersion: permitSchema,
        status: "EXACT_DURABLE_INTENT_CONFIRMED",
        caller,
        command: record.command,
        consumptionSha256: canonicalDigest(record.consumption),
        intent: record.intent,
        tableIdentity,
        readOnly: true,
        storeReadRequestId,
        stronglyConsistent: true
      };
      return deepFreeze({
        ...permit,
        permitSha256: canonicalDigest(permit)
      });
    },
    async readStrong(request) {
      const code = "RELEASE_PROVIDER_STRONG_READ_REQUEST_REJECTED";
      requireCondition(exactKeys(request, [
        "commandSha256", "globalKeySha256", "namespaceArn",
        "stronglyConsistent"
      ]) && HEX_64.test(request.commandSha256 ?? "") &&
        HEX_64.test(request.globalKeySha256 ?? "") &&
        request.namespaceArn === tableArn &&
        request.stronglyConsistent === true, code);
      const { record } = await readRecord(request);
      return record;
    }
  });
}

export function createPreparePermitReader(options) {
  return createPermitReader({
    ...options,
    lane: "PREPARE",
    permitSchema: "prooftoact.prepare-provider-permit.v1",
    roleName: "ProofToActReleaseDeployment"
  });
}

export function createExecutePermitReader(options) {
  return createPermitReader({
    ...options,
    lane: "EXECUTE",
    permitSchema: "prooftoact.execute-provider-permit.v1",
    roleName: "ProofToActReleaseExecution"
  });
}

export const __test = Object.freeze({
  COMMAND_KEYS: PREPARE_COMMAND_KEYS,
  decodeCanonical,
  exactMoney,
  validateConsumption,
  validateIntent,
  validateOutcome,
  validateTerminal
});
