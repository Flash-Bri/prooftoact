import crypto from "node:crypto";

import { canonicalJson } from "../../src/cloud/canonical-json.js";

// Provider-global state is confined to one exact DynamoDB table contract.

const TABLE_NAME = "prooftoact-release-controller";
const MAX_CANONICAL_BYTES = 128 * 1024;
const CAP_MICRO_USD = 20_000_000;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const COMMAND_SCHEMA = "prooftoact.provider-broker-command.v2";
const CONSUMPTION_SCHEMA =
  "prooftoact.provider-global-approval-consumption.v1";
const INTENT_SCHEMA = "prooftoact.provider-global-dispatch-intent.v1";
const OUTCOME_SCHEMA = "prooftoact.provider-dispatch-outcome.v1";
const RECORD_SCHEMA = "prooftoact.provider-global-record.v1";
const TERMINAL_SCHEMA = "prooftoact.provider-global-terminal-record.v1";
const TERMINALIZATION_SCHEMA =
  "prooftoact.provider-global-terminalization.v1";
const APP_SOURCE = Object.freeze({
  repository: "Flash-Bri/prooftoact",
  commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
  tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
});
const LANE_CONTRACTS = Object.freeze({
  PREPARE: Object.freeze({
    action: "PREPARE_EXACT_CREATE_CHANGE_SET",
    providerMutationExpected: true
  }),
  DRILL: Object.freeze({
    action: "RUN_ONE_BOUNDED_LIVE_DRILL",
    providerMutationExpected: true
  }),
  EVIDENCE: Object.freeze({
    action: "COLLECT_FRESH_READ_ONLY_RELEASE_EVIDENCE",
    providerMutationExpected: false
  }),
  EXECUTE: Object.freeze({
    action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
    providerMutationExpected: true
  }),
  TEARDOWN: Object.freeze({
    action: "TEARDOWN_EXACT_RELEASE_STACK",
    providerMutationExpected: true
  })
});
const COMMON_COMMAND_KEYS = Object.freeze([
  "action", "approvalId", "approvalSha256", "appSource",
  "artifactManifestSha256", "budgetKeySha256", "budgetReservationUsd",
  "buildReceiptSha256", "commandSha256", "controlPlaneIdentitySha256",
  "cumulativeCapUsd",
  "databaseIdentitySha256", "effectIdentitySha256",
  "expectedPriorCumulativeSpendUsd", "globalKeySha256", "lane",
  "maximumConcurrency", "maximumRuns", "namespaceArn",
  "operationIdentitySha256", "providerMutationExpected", "region",
  "authorityContractSha256", "schemaVersion",
  "teardownContractSha256", "teardownReserveUsd", "workspaceRealpathSha256"
]);
const POST_PREPARE_COMMAND_KEYS = Object.freeze([
  ...COMMON_COMMAND_KEYS,
  "changeSetArn", "changeSetSha256", "stackId"
]);
const PREPARE_COMMAND_KEYS = Object.freeze([
  ...COMMON_COMMAND_KEYS,
  "changeSetName", "parameterManifestSha256", "resourceInventorySha256",
  "stackName", "templateSha256"
]);
// Retain the historical test-facing name for the post-PREPARE command shape.
const COMMAND_KEYS = POST_PREPARE_COMMAND_KEYS;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function canonicalBytes(value, code = "RELEASE_CONTROL_CANONICAL_RECORD_REJECTED") {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES, code);
  return bytes;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function validateAggregateRecord(command, consumption, intent = null, terminal = null) {
  canonicalBytes(
    { command, consumption, intent, terminal },
    "RELEASE_CONTROL_AGGREGATE_RECORD_REJECTED"
  );
}

function exactMoney(value, code) {
  requireCondition(Number.isFinite(value) && value >= 0 && value <= 20 &&
    Number(value.toFixed(6)) === value, code);
  const micro = Math.round(value * 1_000_000);
  requireCondition(Number.isSafeInteger(micro) && micro >= 0 &&
    micro <= CAP_MICRO_USD && micro / 1_000_000 === value, code);
  return micro;
}

function iso(value, code) {
  requireCondition(Number.isFinite(value), code);
  return new Date(value).toISOString();
}

function validatePhysicalStackId(stackId, tableArn, code) {
  const tableMatch =
    /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u
      .exec(tableArn ?? "");
  requireCondition(tableMatch !== null, code);
  const prefix =
    `arn:aws:cloudformation:us-east-1:${tableMatch[1]}:stack/` +
    "prooftoact-gate2/";
  requireCondition(typeof stackId === "string" && stackId.startsWith(prefix) &&
    UUID.test(stackId.slice(prefix.length)), code);
  return stackId;
}

function validateChangeSetArn(changeSetArn, tableArn, code) {
  const tableMatch =
    /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u
      .exec(tableArn ?? "");
  requireCondition(tableMatch !== null, code);
  const prefix =
    `arn:aws:cloudformation:us-east-1:${tableMatch[1]}:changeSet/`;
  requireCondition(typeof changeSetArn === "string" &&
    changeSetArn.startsWith(prefix), code);
  const suffix = changeSetArn.slice(prefix.length);
  const separator = suffix.lastIndexOf("/");
  requireCondition(separator > 0 &&
    /^prooftoact-release-[a-z0-9-]{1,64}$/u.test(suffix.slice(0, separator)) &&
    UUID.test(suffix.slice(separator + 1)), code);
  return changeSetArn;
}

function validateCommand(command, tableArn) {
  const code = "RELEASE_CONTROL_COMMAND_REJECTED";
  const lane = LANE_CONTRACTS[command?.lane];
  const prepare = command?.lane === "PREPARE";
  const commandKeys = prepare
    ? PREPARE_COMMAND_KEYS : POST_PREPARE_COMMAND_KEYS;
  requireCondition(exactKeys(command, commandKeys) &&
    command.schemaVersion === COMMAND_SCHEMA &&
    command.namespaceArn === tableArn && command.region === "us-east-1" &&
    lane !== undefined && command.action === lane.action &&
    command.providerMutationExpected === lane.providerMutationExpected &&
    exactKeys(command.appSource, ["commit", "repository", "tree"]) &&
    command.appSource.repository === APP_SOURCE.repository &&
    command.appSource.commit === APP_SOURCE.commit &&
    command.appSource.tree === APP_SOURCE.tree &&
    UUID.test(command.approvalId ?? "") &&
    [
      command.approvalSha256,
      command.artifactManifestSha256,
      command.budgetKeySha256,
      command.buildReceiptSha256,
      command.commandSha256,
      command.controlPlaneIdentitySha256,
      command.databaseIdentitySha256,
      command.effectIdentitySha256,
      command.globalKeySha256,
      command.operationIdentitySha256,
      command.authorityContractSha256,
      command.teardownContractSha256,
      command.workspaceRealpathSha256
    ].every((value) => HEX_64.test(value ?? "")) &&
    command.cumulativeCapUsd === 20 && command.maximumRuns === 1 &&
    command.maximumConcurrency === 2, code);
  if (prepare) {
    requireCondition([
      command.parameterManifestSha256,
      command.resourceInventorySha256,
      command.templateSha256
    ].every((value) => HEX_64.test(value ?? "")) &&
      /^prooftoact-release-[a-z0-9-]{1,64}$/u
        .test(command.changeSetName ?? "") &&
      command.stackName === "prooftoact-gate2", code);
  } else {
    requireCondition(HEX_64.test(command.changeSetSha256 ?? ""), code);
    validateChangeSetArn(command.changeSetArn, tableArn, code);
    validatePhysicalStackId(command.stackId, tableArn, code);
  }
  exactMoney(command.budgetReservationUsd, code);
  exactMoney(command.expectedPriorCumulativeSpendUsd, code);
  requireCondition(exactMoney(command.teardownReserveUsd, code) === 1_000_000,
    code);
  const unsigned = { ...command };
  delete unsigned.commandSha256;
  requireCondition(command.commandSha256 === digest(unsigned), code);
  canonicalBytes(command, code);
  return command;
}

function validateConsumption(value, command, allowReplay = true) {
  const code = "RELEASE_CONTROL_CONSUMPTION_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalId", "approvalSha256", "budgetKeySha256", "budgetVersion",
    "commandSha256", "consumedAt", "cumulativeCapUsd", "durable",
    "effectIdentitySha256", "globalKeySha256", "globallyAuthoritative",
    "namespaceArn", "oneShot", "priorCumulativeSpendUsd", "reservedSpendUsd",
    "resultingCumulativeSpendUsd", "schemaVersion", "status", "storeRequestId",
    "stronglyConsistent", "version"
  ]) && value.schemaVersion === CONSUMPTION_SCHEMA &&
    (value.status === "CONSUMED" || allowReplay && value.status === "REPLAY") &&
    value.approvalId === command.approvalId &&
    value.approvalSha256 === command.approvalSha256 &&
    value.budgetKeySha256 === command.budgetKeySha256 &&
    value.commandSha256 === command.commandSha256 &&
    value.effectIdentitySha256 === command.effectIdentitySha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArn === command.namespaceArn && UUID.test(value.storeRequestId ?? "") &&
    value.oneShot === true && value.durable === true &&
    value.globallyAuthoritative === true && value.stronglyConsistent === true &&
    Number.isSafeInteger(value.version) && value.version === 1 &&
    Number.isSafeInteger(value.budgetVersion) && value.budgetVersion >= 1 &&
    Number.isFinite(Date.parse(value.consumedAt)), code);
  const prior = exactMoney(value.priorCumulativeSpendUsd, code);
  const reserved = exactMoney(value.reservedSpendUsd, code);
  const resulting = exactMoney(value.resultingCumulativeSpendUsd, code);
  requireCondition(value.cumulativeCapUsd === 20 &&
    prior === exactMoney(command.expectedPriorCumulativeSpendUsd, code) &&
    reserved === exactMoney(command.budgetReservationUsd, code) &&
    prior + reserved === resulting && resulting <= CAP_MICRO_USD, code);
  canonicalBytes(value, code);
  return value;
}

function validateIntent(value, command, consumption) {
  const code = "RELEASE_CONTROL_INTENT_REJECTED";
  requireCondition(exactKeys(value, [
    "action", "approvalId", "commandSha256", "durable", "event",
    "globalKeySha256", "globallyAuthoritative", "intentId", "lane",
    "previousReceiptSha256", "schemaVersion", "status", "version"
  ]) && value.schemaVersion === INTENT_SCHEMA && value.status === "DURABLE" &&
    value.event === "BEFORE_PROVIDER_DISPATCH" &&
    value.approvalId === command.approvalId &&
    value.commandSha256 === command.commandSha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.action === command.action && value.lane === command.lane &&
    value.previousReceiptSha256 === digest(consumption) &&
    UUID.test(value.intentId ?? "") && value.version === 2 &&
    value.durable === true && value.globallyAuthoritative === true, code);
  canonicalBytes(value, code);
  return value;
}

function validateOutcome(value, command) {
  const code = "RELEASE_CONTROL_OUTCOME_REJECTED";
  requireCondition(exactKeys(value, [
    "observedAt", "operationIdentitySha256", "possibleMutation",
    "providerReceiptSha256", "providerRequestId", "schemaVersion", "status"
  ]) && value.schemaVersion === OUTCOME_SCHEMA &&
    ["AMBIGUOUS", "CONFIRMED", "FAILED_TERMINAL"].includes(value.status) &&
    value.operationIdentitySha256 === command.operationIdentitySha256 &&
    HEX_64.test(value.providerReceiptSha256 ?? "") &&
    Number.isFinite(Date.parse(value.observedAt)) &&
    (value.providerRequestId === null || UUID.test(value.providerRequestId ?? "")) &&
    (value.status === "FAILED_TERMINAL"
      ? value.possibleMutation === false
      : value.possibleMutation === command.providerMutationExpected), code);
  canonicalBytes(value, code);
  return value;
}

function validateTerminal(value, command, predecessor) {
  const code = "RELEASE_CONTROL_TERMINAL_REJECTED";
  const predecessorState = predecessor.schemaVersion === INTENT_SCHEMA
    ? "INTENT" : "CONSUMPTION";
  requireCondition(exactKeys(value, [
    "approvalId", "commandSha256", "durable", "globalKeySha256",
    "globallyAuthoritative", "outcome", "predecessorReceiptSha256",
    "predecessorState", "recordedAt", "schemaVersion", "status",
    "terminalSha256", "version"
  ]) && value.schemaVersion === TERMINAL_SCHEMA && value.status === "TERMINAL" &&
    value.approvalId === command.approvalId &&
    value.commandSha256 === command.commandSha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.predecessorState === predecessorState &&
    value.predecessorReceiptSha256 === digest(predecessor) &&
    value.version === predecessor.version + 1 &&
    value.durable === true && value.globallyAuthoritative === true &&
    Number.isFinite(Date.parse(value.recordedAt)), code);
  validateOutcome(value.outcome, command);
  const unsigned = { ...value };
  delete unsigned.terminalSha256;
  requireCondition(value.terminalSha256 === digest(unsigned) &&
    (predecessorState !== "CONSUMPTION" ||
      value.outcome.status === "FAILED_TERMINAL" &&
      value.outcome.possibleMutation === false), code);
  canonicalBytes(value, code);
  return value;
}

function s(value) { return { S: value }; }
function n(value) { return { N: String(value) }; }
function b(value) { return { B: canonicalBytes(value) }; }

function decodeCanonical(attribute, code) {
  requireCondition(attribute && attribute.B !== undefined, code);
  const bytes = Buffer.from(attribute.B);
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES, code);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(canonicalBytes(value, code).equals(bytes), code);
  return value;
}

function stringAttribute(item, name, code) {
  requireCondition(typeof item?.[name]?.S === "string", code);
  return item[name].S;
}

function integerAttribute(item, name, code) {
  const raw = item?.[name]?.N;
  requireCondition(typeof raw === "string" && /^(?:0|[1-9][0-9]*)$/u.test(raw), code);
  const value = Number(raw);
  requireCondition(Number.isSafeInteger(value), code);
  return value;
}

function effectKey(globalKeySha256) {
  return `EFFECT#${globalKeySha256}`;
}

function budgetKey(budgetKeySha256) {
  return `BUDGET#${budgetKeySha256}`;
}

function requireProvider(provider) {
  requireCondition(provider && [
    "getReleaseControlItem", "transactReleaseControlItems",
    "updateReleaseControlItem"
  ].every((name) => typeof provider[name] === "function"),
  "RELEASE_CONTROL_PROVIDER_CAPABILITY_REJECTED");
}

export function createReleaseControlDynamoDbStore({
  clock = Date.now,
  provider,
  randomUUID = crypto.randomUUID,
  tableArn,
  tableName = TABLE_NAME
}) {
  requireProvider(provider);
  requireCondition(tableName === TABLE_NAME &&
    /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u
      .test(tableArn ?? "") && typeof clock === "function" &&
    typeof randomUUID === "function", "RELEASE_CONTROL_CONFIGURATION_REJECTED");

  async function getItem(pk) {
    const response = await provider.getReleaseControlItem({
      ConsistentRead: true,
      Key: { pk: s(pk) },
      ReturnConsumedCapacity: "NONE",
      TableName: tableName
    });
    requireCondition(plainObject(response), "RELEASE_CONTROL_READ_REJECTED");
    return response.Item ?? null;
  }

  function parseBudget(item, command) {
    const code = "RELEASE_CONTROL_BUDGET_RECORD_REJECTED";
    if (item === null) return { cumulativeMicroUsd: 0, version: 0 };
    requireCondition(exactKeys(item, [
      "budgetKeySha256", "capMicroUsd", "cumulativeMicroUsd", "entity",
      "namespaceArn", "pk", "updatedAt", "version"
    ]) && stringAttribute(item, "pk", code) === budgetKey(command.budgetKeySha256) &&
      stringAttribute(item, "entity", code) === "BUDGET_V1" &&
      stringAttribute(item, "budgetKeySha256", code) === command.budgetKeySha256 &&
      stringAttribute(item, "namespaceArn", code) === tableArn &&
      integerAttribute(item, "capMicroUsd", code) === CAP_MICRO_USD &&
      Number.isFinite(Date.parse(stringAttribute(item, "updatedAt", code))), code);
    const cumulativeMicroUsd = integerAttribute(item, "cumulativeMicroUsd", code);
    const version = integerAttribute(item, "version", code);
    requireCondition(cumulativeMicroUsd <= CAP_MICRO_USD && version >= 1, code);
    return { cumulativeMicroUsd, version };
  }

  function parseEffect(item, request = {}) {
    const code = "RELEASE_CONTROL_EFFECT_RECORD_REJECTED";
    requireCondition(item !== null && plainObject(item), code);
    const state = stringAttribute(item, "state", code);
    requireCondition(["CONSUMED", "INTENT", "TERMINAL"].includes(state), code);
    const hasIntent = item.intent !== undefined || item.intentSha256 !== undefined;
    requireCondition(state !== "INTENT" || hasIntent, code);
    const expectedKeys = [
      "approvalId", "approvalSha256", "budgetKeySha256", "budgetVersion",
      "command", "commandSha256", "consumption", "consumptionSha256",
      "effectIdentitySha256", "entity", "globalKeySha256", "namespaceArn",
      "pk", "state", "version",
      ...(hasIntent ? ["intent", "intentSha256"] : []),
      ...(state === "TERMINAL" ? ["terminal", "terminalSha256"] : [])
    ];
    requireCondition(exactKeys(item, expectedKeys) &&
      stringAttribute(item, "entity", code) === "EFFECT_V1", code);
    const command = decodeCanonical(item.command, code);
    validateCommand(command, tableArn);
    requireCondition(stringAttribute(item, "pk", code) ===
      effectKey(command.globalKeySha256) &&
      stringAttribute(item, "globalKeySha256", code) === command.globalKeySha256 &&
      stringAttribute(item, "effectIdentitySha256", code) ===
        command.effectIdentitySha256 &&
      stringAttribute(item, "commandSha256", code) === command.commandSha256 &&
      stringAttribute(item, "approvalId", code) === command.approvalId &&
      stringAttribute(item, "approvalSha256", code) === command.approvalSha256 &&
      stringAttribute(item, "budgetKeySha256", code) === command.budgetKeySha256 &&
      stringAttribute(item, "namespaceArn", code) === tableArn &&
      (!request.globalKeySha256 || request.globalKeySha256 === command.globalKeySha256) &&
      (!request.commandSha256 || request.commandSha256 === command.commandSha256) &&
      (!request.namespaceArn || request.namespaceArn === tableArn), code);
    const consumption = decodeCanonical(item.consumption, code);
    validateConsumption(consumption, command, false);
    requireCondition(stringAttribute(item, "consumptionSha256", code) ===
      digest(consumption) && integerAttribute(item, "budgetVersion", code) ===
      consumption.budgetVersion, code);
    let intent = null;
    if (hasIntent) {
      intent = decodeCanonical(item.intent, code);
      validateIntent(intent, command, consumption);
      requireCondition(stringAttribute(item, "intentSha256", code) ===
        digest(intent), code);
    }
    let terminal = null;
    if (state === "TERMINAL") {
      terminal = decodeCanonical(item.terminal, code);
      validateTerminal(terminal, command, intent ?? consumption);
      requireCondition(stringAttribute(item, "terminalSha256", code) ===
        terminal.terminalSha256, code);
    }
    const version = integerAttribute(item, "version", code);
    requireCondition(version === (state === "CONSUMED" ? 1 : state === "INTENT" ? 2 :
      terminal.version), code);
    validateAggregateRecord(command, consumption, intent, terminal);
    return { command, consumption, intent, state, terminal };
  }

  async function readRecord(request) {
    requireCondition(exactKeys(request, [
      "commandSha256", "globalKeySha256", "namespaceArn", "stronglyConsistent"
    ]) && HEX_64.test(request.commandSha256 ?? "") &&
      HEX_64.test(request.globalKeySha256 ?? "") &&
      request.namespaceArn === tableArn && request.stronglyConsistent === true,
    "RELEASE_CONTROL_READ_REQUEST_REJECTED");
    return parseEffect(await getItem(effectKey(request.globalKeySha256)), request);
  }

  async function recoverExact(command, expected = {}) {
    const record = await readRecord({
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      namespaceArn: tableArn,
      stronglyConsistent: true
    });
    if (expected.intent && canonicalJson(record.intent) !== canonicalJson(expected.intent)) {
      reject("RELEASE_CONTROL_INTENT_CONFLICT");
    }
    if (expected.terminal &&
      canonicalJson(record.terminal) !== canonicalJson(expected.terminal)) {
      reject("RELEASE_CONTROL_TERMINAL_CONFLICT");
    }
    return record;
  }

  return Object.freeze({
    async consumeOnce(command) {
      validateCommand(command, tableArn);
      let occupied;
      try {
        occupied = await getItem(effectKey(command.globalKeySha256));
      } catch (cause) {
        reject("RELEASE_CONTROL_EFFECT_READ_UNKNOWN", cause);
      }
      if (occupied !== null) {
        try {
          const existing = parseEffect(occupied, {
            commandSha256: command.commandSha256,
            globalKeySha256: command.globalKeySha256,
            namespaceArn: tableArn
          });
          return Object.freeze({ ...existing.consumption, status: "REPLAY" });
        } catch (cause) {
          reject("RELEASE_CONTROL_EFFECT_OCCUPIED_CONFLICT", cause);
        }
      }
      const expectedPriorMicroUsd = exactMoney(
        command.expectedPriorCumulativeSpendUsd,
        "RELEASE_CONTROL_BUDGET_REJECTED"
      );
      const reservationMicroUsd = exactMoney(
        command.budgetReservationUsd,
        "RELEASE_CONTROL_BUDGET_REJECTED"
      );
      let budget;
      try {
        budget = parseBudget(await getItem(budgetKey(command.budgetKeySha256)), command);
      } catch (cause) {
        reject("RELEASE_CONTROL_BUDGET_READ_UNKNOWN", cause);
      }
      requireCondition(budget.cumulativeMicroUsd === expectedPriorMicroUsd,
        "RELEASE_CONTROL_BUDGET_STALE");
      const resultingMicroUsd = expectedPriorMicroUsd + reservationMicroUsd;
      requireCondition(resultingMicroUsd <= CAP_MICRO_USD,
        "RELEASE_CONTROL_BUDGET_CAP_EXCEEDED");
      const now = iso(clock(), "RELEASE_CONTROL_CLOCK_REJECTED");
      const requestId = randomUUID();
      requireCondition(UUID.test(requestId ?? ""), "RELEASE_CONTROL_UUID_REJECTED");
      const consumption = Object.freeze({
        schemaVersion: CONSUMPTION_SCHEMA,
        status: "CONSUMED",
        approvalId: command.approvalId,
        approvalSha256: command.approvalSha256,
        commandSha256: command.commandSha256,
        budgetKeySha256: command.budgetKeySha256,
        budgetVersion: budget.version + 1,
        cumulativeCapUsd: 20,
        durable: true,
        effectIdentitySha256: command.effectIdentitySha256,
        globalKeySha256: command.globalKeySha256,
        globallyAuthoritative: true,
        namespaceArn: tableArn,
        oneShot: true,
        priorCumulativeSpendUsd: expectedPriorMicroUsd / 1_000_000,
        reservedSpendUsd: reservationMicroUsd / 1_000_000,
        resultingCumulativeSpendUsd: resultingMicroUsd / 1_000_000,
        storeRequestId: requestId,
        stronglyConsistent: true,
        consumedAt: now,
        version: 1
      });
      validateConsumption(consumption, command, false);
      validateAggregateRecord(command, consumption);
      const effectItem = {
        pk: s(effectKey(command.globalKeySha256)),
        entity: s("EFFECT_V1"),
        globalKeySha256: s(command.globalKeySha256),
        effectIdentitySha256: s(command.effectIdentitySha256),
        commandSha256: s(command.commandSha256),
        command: b(command),
        approvalId: s(command.approvalId),
        approvalSha256: s(command.approvalSha256),
        budgetKeySha256: s(command.budgetKeySha256),
        budgetVersion: n(consumption.budgetVersion),
        namespaceArn: s(tableArn),
        consumption: b(consumption),
        consumptionSha256: s(digest(consumption)),
        state: s("CONSUMED"),
        version: n(1)
      };
      const budgetWrite = budget.version === 0
        ? {
            Put: {
              ConditionExpression: "attribute_not_exists(#pk)",
              ExpressionAttributeNames: { "#pk": "pk" },
              Item: {
                pk: s(budgetKey(command.budgetKeySha256)),
                entity: s("BUDGET_V1"),
                budgetKeySha256: s(command.budgetKeySha256),
                namespaceArn: s(tableArn),
                capMicroUsd: n(CAP_MICRO_USD),
                cumulativeMicroUsd: n(resultingMicroUsd),
                updatedAt: s(now),
                version: n(1)
              },
              TableName: tableName
            }
          }
        : {
            Update: {
              ConditionExpression:
                "#entity = :entity AND #budgetKey = :budgetKey AND #namespace = :namespace AND #cap = :cap AND #cumulative = :prior AND #version = :priorVersion",
              ExpressionAttributeNames: {
                "#budgetKey": "budgetKeySha256", "#cap": "capMicroUsd",
                "#cumulative": "cumulativeMicroUsd", "#entity": "entity",
                "#namespace": "namespaceArn", "#updated": "updatedAt",
                "#version": "version"
              },
              ExpressionAttributeValues: {
                ":budgetKey": s(command.budgetKeySha256),
                ":cap": n(CAP_MICRO_USD), ":entity": s("BUDGET_V1"),
                ":next": n(resultingMicroUsd), ":nextVersion": n(budget.version + 1),
                ":namespace": s(tableArn), ":prior": n(expectedPriorMicroUsd),
                ":priorVersion": n(budget.version),
                ":updated": s(now)
              },
              Key: { pk: s(budgetKey(command.budgetKeySha256)) },
              TableName: tableName,
              UpdateExpression:
                "SET #cumulative = :next, #version = :nextVersion, #updated = :updated"
            }
          };
      try {
        await provider.transactReleaseControlItems({
          ClientRequestToken: command.approvalId,
          ReturnConsumedCapacity: "NONE",
          TransactItems: [budgetWrite, {
            Put: {
              ConditionExpression: "attribute_not_exists(#pk)",
              ExpressionAttributeNames: { "#pk": "pk" },
              Item: effectItem,
              TableName: tableName
            }
          }]
        });
        return consumption;
      } catch (cause) {
        try {
          const record = await recoverExact(command);
          return Object.freeze({ ...record.consumption, status: "REPLAY" });
        } catch (recoveryCause) {
          reject("RELEASE_CONTROL_CONSUME_UNKNOWN", { cause, recoveryCause });
        }
      }
    },

    async appendIntent({ command, consumption }) {
      validateCommand(command, tableArn);
      validateConsumption(consumption, command, false);
      const current = await readRecord({
        commandSha256: command.commandSha256,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: tableArn,
        stronglyConsistent: true
      });
      requireCondition(canonicalJson(current.consumption) ===
        canonicalJson(consumption), "RELEASE_CONTROL_CONSUMPTION_CONFLICT");
      if (current.state === "INTENT") return current.intent;
      requireCondition(current.state === "CONSUMED",
        "RELEASE_CONTROL_INTENT_ALREADY_TERMINAL");
      const intentId = randomUUID();
      requireCondition(UUID.test(intentId ?? ""), "RELEASE_CONTROL_UUID_REJECTED");
      const intent = Object.freeze({
        schemaVersion: INTENT_SCHEMA,
        status: "DURABLE",
        event: "BEFORE_PROVIDER_DISPATCH",
        action: command.action,
        approvalId: command.approvalId,
        commandSha256: command.commandSha256,
        durable: true,
        globalKeySha256: command.globalKeySha256,
        globallyAuthoritative: true,
        intentId,
        lane: command.lane,
        previousReceiptSha256: digest(consumption),
        version: 2
      });
      validateIntent(intent, command, consumption);
      validateAggregateRecord(command, consumption, intent);
      try {
        await provider.updateReleaseControlItem({
          ConditionExpression:
            "#state = :consumed AND #version = :one AND #commandSha = :commandSha AND #consumptionSha = :consumptionSha AND attribute_not_exists(#intent)",
          ExpressionAttributeNames: {
            "#commandSha": "commandSha256", "#consumptionSha": "consumptionSha256",
            "#intent": "intent", "#intentSha": "intentSha256", "#state": "state",
            "#version": "version"
          },
          ExpressionAttributeValues: {
            ":commandSha": s(command.commandSha256),
            ":consumed": s("CONSUMED"), ":consumptionSha": s(digest(consumption)),
            ":intent": b(intent), ":intentSha": s(digest(intent)),
            ":intentState": s("INTENT"), ":one": n(1), ":two": n(2)
          },
          Key: { pk: s(effectKey(command.globalKeySha256)) },
          ReturnConsumedCapacity: "NONE",
          ReturnValues: "NONE",
          TableName: tableName,
          UpdateExpression:
            "SET #intent = :intent, #intentSha = :intentSha, #state = :intentState, #version = :two"
        });
        return intent;
      } catch (cause) {
        try {
          const record = await recoverExact(command, { intent });
          requireCondition(record.state === "INTENT",
            "RELEASE_CONTROL_INTENT_TERMINALIZED");
          return record.intent;
        } catch (recoveryCause) {
          reject("RELEASE_CONTROL_INTENT_UNKNOWN", { cause, recoveryCause });
        }
      }
    },

    async finalize({ command, intent, outcome }) {
      return writeTerminal({ command, outcome, predecessor: intent });
    },

    async terminalize({ command, consumption, intent, outcome }) {
      return writeTerminal({
        command,
        outcome,
        predecessor: intent ?? consumption
      });
    },

    async terminalizeExpired({
      approvalExpiresAt,
      command,
      consumption,
      intent,
      outcome
    }) {
      const observed = clock();
      requireCondition(Number.isFinite(Date.parse(approvalExpiresAt)) &&
        observed >= Date.parse(approvalExpiresAt),
      "RELEASE_CONTROL_TERMINALIZATION_NOT_DUE");
      const predecessor = intent ?? consumption;
      requireCondition(
        intent === null
          ? outcome?.status === "FAILED_TERMINAL" &&
            outcome.possibleMutation === false
          : outcome?.status === "AMBIGUOUS" &&
            outcome.possibleMutation === command.providerMutationExpected,
        "RELEASE_CONTROL_SAFETY_REDUCING_OUTCOME_REJECTED"
      );
      const terminal = await writeTerminal({
        command,
        outcome,
        predecessor,
        recordedAt: observed
      });
      return Object.freeze({
        schemaVersion: TERMINALIZATION_SCHEMA,
        approvalExpiresAt,
        budgetReservationReleased: false,
        clockSource: "TRUSTED_RUNTIME_SAFETY_REDUCING_OBSERVATION",
        effectOccupancyReleased: false,
        observedAt: iso(observed, "RELEASE_CONTROL_CLOCK_REJECTED"),
        safetyReducingOnly: true,
        terminal
      });
    },

    async readStrong(request) {
      const record = await readRecord(request);
      return Object.freeze({
        schemaVersion: RECORD_SCHEMA,
        status: record.state,
        command: record.command,
        consumption: record.consumption,
        intent: record.intent,
        terminal: record.terminal
      });
    }
  });

  async function writeTerminal({ command, outcome, predecessor, recordedAt = clock() }) {
    validateCommand(command, tableArn);
    validateOutcome(outcome, command);
    requireCondition(predecessor && [CONSUMPTION_SCHEMA, INTENT_SCHEMA]
      .includes(predecessor.schemaVersion), "RELEASE_CONTROL_PREDECESSOR_REJECTED");
    const current = await readRecord({
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      namespaceArn: tableArn,
      stronglyConsistent: true
    });
    if (predecessor.schemaVersion === CONSUMPTION_SCHEMA) {
      validateConsumption(predecessor, command, false);
      requireCondition(current.intent === null &&
        canonicalJson(current.consumption) === canonicalJson(predecessor),
      "RELEASE_CONTROL_PREDECESSOR_CONFLICT");
    } else {
      validateIntent(predecessor, command, current.consumption);
      requireCondition(canonicalJson(current.intent) === canonicalJson(predecessor),
        "RELEASE_CONTROL_PREDECESSOR_CONFLICT");
    }
    if (current.terminal !== null) {
      requireCondition(canonicalJson(current.terminal.outcome) ===
        canonicalJson(outcome), "RELEASE_CONTROL_TERMINAL_CONFLICT");
      return current.terminal;
    }
    const terminalBase = {
      schemaVersion: TERMINAL_SCHEMA,
      status: "TERMINAL",
      approvalId: command.approvalId,
      commandSha256: command.commandSha256,
      durable: true,
      globalKeySha256: command.globalKeySha256,
      globallyAuthoritative: true,
      outcome,
      predecessorReceiptSha256: digest(predecessor),
      predecessorState: predecessor.schemaVersion === INTENT_SCHEMA
        ? "INTENT" : "CONSUMPTION",
      recordedAt: iso(recordedAt, "RELEASE_CONTROL_CLOCK_REJECTED"),
      version: predecessor.version + 1
    };
    const terminal = Object.freeze({
      ...terminalBase,
      terminalSha256: digest(terminalBase)
    });
    validateTerminal(terminal, command, predecessor);
    validateAggregateRecord(
      command,
      current.consumption,
      current.intent,
      terminal
    );
    const isIntent = predecessor.schemaVersion === INTENT_SCHEMA;
    const names = {
      "#commandSha": "commandSha256", "#predecessorSha": isIntent
        ? "intentSha256" : "consumptionSha256", "#state": "state",
      "#terminal": "terminal", "#terminalSha": "terminalSha256",
      "#version": "version"
    };
    const values = {
      ":commandSha": s(command.commandSha256),
      ":expectedState": s(isIntent ? "INTENT" : "CONSUMED"),
      ":expectedVersion": n(predecessor.version),
      ":predecessorSha": s(digest(predecessor)),
      ":terminal": b(terminal), ":terminalSha": s(terminal.terminalSha256),
      ":terminalState": s("TERMINAL"), ":terminalVersion": n(terminal.version)
    };
    try {
      await provider.updateReleaseControlItem({
        ConditionExpression:
          "#state = :expectedState AND #version = :expectedVersion AND #commandSha = :commandSha AND #predecessorSha = :predecessorSha AND attribute_not_exists(#terminal)",
        ExpressionAttributeNames: names,
        ExpressionAttributeValues: values,
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        ReturnValues: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #terminal = :terminal, #terminalSha = :terminalSha, #state = :terminalState, #version = :terminalVersion"
      });
      return terminal;
    } catch (cause) {
      try {
        const record = await recoverExact(command, { terminal });
        return record.terminal;
      } catch (recoveryCause) {
        reject("RELEASE_CONTROL_TERMINAL_UNKNOWN", { cause, recoveryCause });
      }
    }
  }
}

export const __test = Object.freeze({
  APP_SOURCE,
  CAP_MICRO_USD,
  COMMON_COMMAND_KEYS,
  COMMAND_KEYS,
  MAX_CANONICAL_BYTES,
  POST_PREPARE_COMMAND_KEYS,
  PREPARE_COMMAND_KEYS,
  TABLE_NAME,
  canonicalBytes,
  decodeCanonical,
  digest,
  exactMoney,
  validateAggregateRecord,
  validateChangeSetArn,
  validatePhysicalStackId
});
