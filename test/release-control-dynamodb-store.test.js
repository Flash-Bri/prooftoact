import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  createReleaseControlDynamoDbStore
} from "../release-control/src/release-control-dynamodb-store.js";

const ACCOUNT = "111111111111";
const TABLE_ARN =
  `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/prooftoact-release-controller`;
const STACK_ID =
  `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
  "prooftoact-gate2/823e4567-e89b-42d3-a456-426614174007";
const NOW = Date.parse("2026-08-17T20:00:00.000Z");
const APPROVAL = "123e4567-e89b-42d3-a456-426614174000";
const INTENT = "223e4567-e89b-42d3-a456-426614174001";
const REQUEST = "323e4567-e89b-42d3-a456-426614174002";

function digest(value) {
  return __test.digest(value);
}

function rehashCommand(value) {
  const unsigned = { ...value };
  delete unsigned.commandSha256;
  return { ...unsigned, commandSha256: digest(unsigned) };
}

function command(overrides = {}) {
  const value = {
    schemaVersion: "prooftoact.provider-broker-command.v2",
    action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
    approvalId: APPROVAL,
    approvalSha256: "1".repeat(64),
    appSource: {
      repository: "Flash-Bri/prooftoact",
      commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
      tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
    },
    artifactManifestSha256: "2".repeat(64),
    budgetKeySha256: "3".repeat(64),
    budgetReservationUsd: 12,
    buildReceiptSha256: "4".repeat(64),
    changeSetArn:
      `arn:aws:cloudformation:us-east-1:${ACCOUNT}:changeSet/` +
      "prooftoact-release-a/123e4567-e89b-42d3-a456-426614174000",
    changeSetSha256: "5".repeat(64),
    controlPlaneIdentitySha256: "6".repeat(64),
    cumulativeCapUsd: 20,
    databaseIdentitySha256: "7".repeat(64),
    effectIdentitySha256: "8".repeat(64),
    expectedPriorCumulativeSpendUsd: 0,
    globalKeySha256: "9".repeat(64),
    lane: "EXECUTE",
    maximumConcurrency: 2,
    maximumRuns: 1,
    namespaceArn: TABLE_ARN,
    operationIdentitySha256: "a".repeat(64),
    providerMutationExpected: true,
    region: "us-east-1",
    authorityContractSha256: "b".repeat(64),
    stackId: STACK_ID,
    teardownContractSha256: "c".repeat(64),
    teardownReserveUsd: 1,
    workspaceRealpathSha256: "d".repeat(64),
    ...overrides
  };
  return rehashCommand(value);
}

function prepareCommand(overrides = {}) {
  const value = command();
  delete value.changeSetArn;
  delete value.changeSetSha256;
  delete value.commandSha256;
  delete value.stackId;
  return rehashCommand({
    ...value,
    action: "PREPARE_EXACT_CREATE_CHANGE_SET",
    changeSetName: "prooftoact-release-a",
    lane: "PREPARE",
    parameterManifestSha256: "e".repeat(64),
    providerMutationExpected: true,
    resourceInventorySha256: "f".repeat(64),
    stackName: "prooftoact-gate2",
    templateSha256: "0".repeat(64),
    ...overrides
  });
}

class FakeDynamoProvider {
  constructor() {
    this.items = new Map();
    this.getCalls = [];
    this.transactCalls = [];
    this.updateCalls = [];
    this.throwAfterTransaction = false;
    this.throwAfterUpdate = false;
  }

  async getReleaseControlItem(input) {
    this.getCalls.push(input);
    assert.equal(input.ConsistentRead, true);
    return { Item: this.items.get(input.Key.pk.S) };
  }

  async transactReleaseControlItems(input) {
    this.transactCalls.push(input);
    const budget = input.TransactItems[0];
    const effect = input.TransactItems[1].Put;
    if (this.items.has(effect.Item.pk.S)) throw new Error("conditional effect");
    if (budget.Put) {
      if (this.items.has(budget.Put.Item.pk.S)) throw new Error("conditional budget");
      this.items.set(budget.Put.Item.pk.S, structuredClone(budget.Put.Item));
    } else {
      const current = this.items.get(budget.Update.Key.pk.S);
      if (!current || current.version.N !==
        budget.Update.ExpressionAttributeValues[":priorVersion"].N ||
        current.cumulativeMicroUsd.N !==
          budget.Update.ExpressionAttributeValues[":prior"].N) {
        throw new Error("conditional budget");
      }
      current.cumulativeMicroUsd =
        budget.Update.ExpressionAttributeValues[":next"];
      current.version = budget.Update.ExpressionAttributeValues[":nextVersion"];
      current.updatedAt = budget.Update.ExpressionAttributeValues[":updated"];
    }
    this.items.set(effect.Item.pk.S, structuredClone(effect.Item));
    if (this.throwAfterTransaction) {
      this.throwAfterTransaction = false;
      throw new Error("synthetic transaction acknowledgement loss");
    }
    return {};
  }

  async updateReleaseControlItem(input) {
    this.updateCalls.push(input);
    const item = this.items.get(input.Key.pk.S);
    if (!item) throw new Error("missing item");
    const values = input.ExpressionAttributeValues;
    if (values[":intent"]) {
      if (item.state.S !== "CONSUMED" || item.intent) {
        throw new Error("conditional intent");
      }
      item.intent = values[":intent"];
      item.intentSha256 = values[":intentSha"];
      item.state = values[":intentState"];
      item.version = values[":two"];
    } else {
      if (item.state.S !== values[":expectedState"].S || item.terminal) {
        throw new Error("conditional terminal");
      }
      item.terminal = values[":terminal"];
      item.terminalSha256 = values[":terminalSha"];
      item.state = values[":terminalState"];
      item.version = values[":terminalVersion"];
    }
    if (this.throwAfterUpdate) {
      this.throwAfterUpdate = false;
      throw new Error("synthetic update acknowledgement loss");
    }
    return {};
  }
}

function fixture(provider = new FakeDynamoProvider(), overrides = {}) {
  let uuidIndex = 0;
  const uuids = [REQUEST, INTENT, "423e4567-e89b-42d3-a456-426614174003"];
  return {
    provider,
    store: createReleaseControlDynamoDbStore({
      clock: () => NOW,
      provider,
      randomUUID: () => uuids[uuidIndex++],
      tableArn: TABLE_ARN,
      ...overrides
    })
  };
}

function confirmedOutcome(input = command()) {
  return {
    schemaVersion: "prooftoact.provider-dispatch-outcome.v1",
    status: "CONFIRMED",
    operationIdentitySha256: input.operationIdentitySha256,
    possibleMutation: input.providerMutationExpected,
    providerRequestId: "523e4567-e89b-42d3-a456-426614174004",
    observedAt: new Date(NOW).toISOString(),
    providerReceiptSha256: "e".repeat(64)
  };
}

function ambiguousOutcome(input = command()) {
  return {
    ...confirmedOutcome(input),
    status: "AMBIGUOUS",
    providerRequestId: null
  };
}

test("one transaction reserves integer-microdollar budget and effect", async () => {
  const input = command();
  const { provider, store } = fixture();
  const consumption = await store.consumeOnce(input);
  assert.equal(consumption.status, "CONSUMED");
  assert.equal(consumption.resultingCumulativeSpendUsd, 12);
  assert.equal(provider.transactCalls.length, 1);
  const transaction = provider.transactCalls[0];
  assert.equal(transaction.ClientRequestToken, APPROVAL);
  assert.equal(transaction.TransactItems.length, 2);
  assert.equal(
    transaction.TransactItems[0].Put.Item.cumulativeMicroUsd.N,
    "12000000"
  );
  assert.match(transaction.TransactItems[1].Put.Item.pk.S, /^EFFECT#/u);
  const storedCommand = JSON.parse(Buffer.from(
    transaction.TransactItems[1].Put.Item.command.B
  ).toString("utf8"));
  assert.equal(storedCommand.stackId, STACK_ID);
  assert.equal(storedCommand.teardownReserveUsd, 1);
  assert.equal(provider.getCalls.every((call) => call.ConsistentRead), true);
});

test("PREPARE canonical command round-trips through every durable store phase", async () => {
  const input = prepareCommand();
  const { provider, store } = fixture();
  const consumption = await store.consumeOnce(input);
  const effect = provider.items.get(`EFFECT#${input.globalKeySha256}`);
  assert.deepEqual(Buffer.from(effect.command.B), __test.canonicalBytes(input));
  const intent = await store.appendIntent({ command: input, consumption });
  const terminal = await store.finalize({
    command: input,
    intent,
    outcome: confirmedOutcome(input)
  });
  assert.equal(terminal.outcome.status, "CONFIRMED");
  const record = await store.readStrong({
    commandSha256: input.commandSha256,
    globalKeySha256: input.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  });
  assert.deepEqual(record.command, input);
  assert.equal(record.command.changeSetName, "prooftoact-release-a");
  assert.equal(record.command.stackName, "prooftoact-gate2");
  assert.equal(Object.hasOwn(record.command, "changeSetArn"), false);
  assert.equal(Object.hasOwn(record.command, "changeSetSha256"), false);
  assert.equal(Object.hasOwn(record.command, "stackId"), false);
});

test("PREPARE transaction, intent, and finalization acknowledgement loss converge", async () => {
  const input = prepareCommand();
  const { provider, store } = fixture();
  provider.throwAfterTransaction = true;
  const consumption = await store.consumeOnce(input);
  assert.equal(consumption.status, "REPLAY");
  provider.throwAfterUpdate = true;
  const intent = await store.appendIntent({ command: input, consumption: {
    ...consumption,
    status: "CONSUMED"
  } });
  provider.throwAfterUpdate = true;
  const terminal = await store.finalize({
    command: input,
    intent,
    outcome: confirmedOutcome(input)
  });
  assert.equal(terminal.outcome.status, "CONFIRMED");
  assert.equal(provider.transactCalls.length, 1);
  assert.equal(provider.updateCalls.length, 2);
});

test("PREPARE terminalization retains exact command bytes, occupancy, and budget", async () => {
  const input = prepareCommand();
  const { provider, store } = fixture();
  const consumption = await store.consumeOnce(input);
  const intent = await store.appendIntent({ command: input, consumption });
  const result = await store.terminalizeExpired({
    approvalExpiresAt: new Date(NOW).toISOString(),
    command: input,
    consumption,
    intent,
    outcome: ambiguousOutcome(input)
  });
  assert.equal(result.terminal.outcome.status, "AMBIGUOUS");
  assert.equal(result.effectOccupancyReleased, false);
  assert.equal(result.budgetReservationReleased, false);
  const record = await store.readStrong({
    commandSha256: input.commandSha256,
    globalKeySha256: input.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  });
  assert.deepEqual(record.command, input);
  assert.equal(
    provider.items.get(`BUDGET#${input.budgetKeySha256}`).cumulativeMicroUsd.N,
    "12000000"
  );
});

test("transaction acknowledgement loss performs one strong read and never rewrites", async () => {
  const input = command();
  const { provider, store } = fixture();
  provider.throwAfterTransaction = true;
  const consumption = await store.consumeOnce(input);
  assert.equal(consumption.status, "REPLAY");
  assert.equal(provider.transactCalls.length, 1);
  assert.equal(provider.getCalls.at(-1).ConsistentRead, true);
});

test("an exact later replay bypasses the already-reserved budget and never writes", async () => {
  const input = command();
  const { provider, store } = fixture();
  await store.consumeOnce(input);
  const replay = await store.consumeOnce(input);
  assert.equal(replay.status, "REPLAY");
  assert.equal(provider.transactCalls.length, 1);
});

test("separate approval cannot reuse occupied effect", async () => {
  const first = command();
  const { provider, store } = fixture();
  await store.consumeOnce(first);
  const second = command({
    approvalId: "623e4567-e89b-42d3-a456-426614174005",
    approvalSha256: "f".repeat(64),
    budgetReservationUsd: 0,
    expectedPriorCumulativeSpendUsd: 12
  });
  await assert.rejects(
    store.consumeOnce(second),
    /RELEASE_CONTROL_EFFECT_OCCUPIED_CONFLICT/u
  );
  assert.equal(provider.transactCalls.length, 1);
  assert.equal(provider.items.size, 2);
});

test("a second PREPARE approval for the same effect cannot reserve or dispatch", async () => {
  const first = prepareCommand();
  const { provider, store } = fixture();
  await store.consumeOnce(first);
  const second = prepareCommand({
    approvalId: "623e4567-e89b-42d3-a456-426614174005",
    approvalSha256: "0".repeat(64),
    budgetReservationUsd: 0,
    expectedPriorCumulativeSpendUsd: 12,
    operationIdentitySha256: "1".repeat(64)
  });
  await assert.rejects(
    store.consumeOnce(second),
    /RELEASE_CONTROL_EFFECT_OCCUPIED_CONFLICT/u
  );
  assert.equal(provider.transactCalls.length, 1);
  assert.equal(provider.items.size, 2);
});

test("distinct effects share one atomically versioned cumulative cap", async () => {
  const { provider, store } = fixture();
  await store.consumeOnce(command());
  const second = command({
    action: "RUN_ONE_BOUNDED_LIVE_DRILL",
    approvalId: "623e4567-e89b-42d3-a456-426614174005",
    approvalSha256: "f".repeat(64),
    budgetReservationUsd: 8,
    effectIdentitySha256: "0".repeat(64),
    expectedPriorCumulativeSpendUsd: 12,
    globalKeySha256: "1".repeat(64),
    lane: "DRILL"
  });
  const consumption = await store.consumeOnce(second);
  assert.equal(consumption.resultingCumulativeSpendUsd, 20);
  const budget = provider.items.get(`BUDGET#${second.budgetKeySha256}`);
  assert.equal(budget.cumulativeMicroUsd.N, "20000000");
  assert.equal(budget.version.N, "2");
  const over = command({
    approvalId: "723e4567-e89b-42d3-a456-426614174006",
    approvalSha256: "0".repeat(64),
    budgetReservationUsd: 1,
    effectIdentitySha256: "2".repeat(64),
    expectedPriorCumulativeSpendUsd: 20,
    globalKeySha256: "3".repeat(64)
  });
  await assert.rejects(store.consumeOnce(over), /BUDGET_CAP_EXCEEDED/u);
});

test("intent and terminal are create-only and converge after acknowledgement loss", async () => {
  const input = command();
  const { provider, store } = fixture();
  const consumption = await store.consumeOnce(input);
  provider.throwAfterUpdate = true;
  const intent = await store.appendIntent({ command: input, consumption });
  assert.equal(intent.status, "DURABLE");
  assert.deepEqual(
    await store.appendIntent({ command: input, consumption }),
    intent
  );
  assert.equal(provider.updateCalls.length, 1);
  provider.throwAfterUpdate = true;
  const terminal = await store.finalize({
    command: input,
    intent,
    outcome: confirmedOutcome(input)
  });
  assert.equal(terminal.outcome.status, "CONFIRMED");
  assert.equal(provider.updateCalls.length, 2);
  const record = await store.readStrong({
    commandSha256: input.commandSha256,
    globalKeySha256: input.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  });
  assert.equal(record.status, "TERMINAL");
  assert.equal(record.terminal.terminalSha256, terminal.terminalSha256);
  assert.deepEqual(
    await store.finalize({ command: input, intent, outcome: confirmedOutcome(input) }),
    terminal
  );
  assert.equal(provider.updateCalls.length, 2);
});

test("intent acknowledgement loss cannot dispatch through a concurrently terminalized record", async () => {
  const input = command();
  const provider = new FakeDynamoProvider();
  const { store } = fixture(provider);
  const consumption = await store.consumeOnce(input);
  const update = provider.updateReleaseControlItem.bind(provider);
  provider.updateReleaseControlItem = async (request) => {
    provider.updateReleaseControlItem = update;
    await update(request);
    const item = provider.items.get(`EFFECT#${input.globalKeySha256}`);
    const intent = JSON.parse(Buffer.from(item.intent.B).toString("utf8"));
    await store.terminalizeExpired({
      approvalExpiresAt: new Date(NOW).toISOString(),
      command: input,
      consumption,
      intent,
      outcome: ambiguousOutcome(input)
    });
    throw new Error("synthetic intent acknowledgement loss after terminalization");
  };
  await assert.rejects(
    store.appendIntent({ command: input, consumption }),
    /RELEASE_CONTROL_INTENT_UNKNOWN/u
  );
  const record = await store.readStrong({
    commandSha256: input.commandSha256,
    globalKeySha256: input.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  });
  assert.equal(record.status, "TERMINAL");
  assert.equal(record.terminal.outcome.status, "AMBIGUOUS");
});

test("conflicting terminal never overwrites the first terminal", async () => {
  const input = command();
  const { provider, store } = fixture();
  const consumption = await store.consumeOnce(input);
  const intent = await store.appendIntent({ command: input, consumption });
  await store.finalize({ command: input, intent, outcome: confirmedOutcome(input) });
  const substituted = {
    ...confirmedOutcome(input),
    providerReceiptSha256: "f".repeat(64)
  };
  await assert.rejects(
    store.finalize({ command: input, intent, outcome: substituted }),
    /RELEASE_CONTROL_TERMINAL_CONFLICT/u
  );
  const item = provider.items.get(`EFFECT#${input.globalKeySha256}`);
  const stored = JSON.parse(Buffer.from(item.terminal.B).toString("utf8"));
  assert.equal(stored.outcome.providerReceiptSha256, "e".repeat(64));
});

test("expired terminalization is safety-reducing and never releases occupancy or budget", async () => {
  const input = command();
  const { provider, store } = fixture();
  const consumption = await store.consumeOnce(input);
  const failed = {
    schemaVersion: "prooftoact.provider-dispatch-outcome.v1",
    status: "FAILED_TERMINAL",
    operationIdentitySha256: input.operationIdentitySha256,
    possibleMutation: false,
    providerRequestId: null,
    observedAt: new Date(NOW).toISOString(),
    providerReceiptSha256: "e".repeat(64)
  };
  await assert.rejects(
    store.terminalizeExpired({
      approvalExpiresAt: new Date(NOW + 1).toISOString(),
      command: input,
      consumption,
      intent: null,
      outcome: failed
    }),
    /TERMINALIZATION_NOT_DUE/u
  );
  const result = await store.terminalizeExpired({
    approvalExpiresAt: new Date(NOW).toISOString(),
    command: input,
    consumption,
    intent: null,
    outcome: failed
  });
  assert.equal(result.clockSource,
    "TRUSTED_RUNTIME_SAFETY_REDUCING_OBSERVATION");
  assert.equal(result.safetyReducingOnly, true);
  assert.equal(result.effectOccupancyReleased, false);
  assert.equal(result.budgetReservationReleased, false);
  assert.equal(result.terminal.outcome.status, "FAILED_TERMINAL");
  const record = await store.readStrong({
    commandSha256: input.commandSha256,
    globalKeySha256: input.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  });
  assert.equal(record.intent, null);
  assert.equal(record.status, "TERMINAL");
  assert.equal(record.command.stackId, STACK_ID);
  assert.equal(record.command.teardownReserveUsd, 1);
  assert.equal(
    provider.items.get(`BUDGET#${input.budgetKeySha256}`).cumulativeMicroUsd.N,
    "12000000"
  );
});

test("expired intent can only converge to an ambiguous safety-reducing terminal", async () => {
  const input = command();
  const { store } = fixture();
  const consumption = await store.consumeOnce(input);
  const intent = await store.appendIntent({ command: input, consumption });
  await assert.rejects(
    store.terminalizeExpired({
      approvalExpiresAt: new Date(NOW).toISOString(),
      command: input,
      consumption,
      intent,
      outcome: confirmedOutcome(input)
    }),
    /SAFETY_REDUCING_OUTCOME_REJECTED/u
  );
  const result = await store.terminalizeExpired({
    approvalExpiresAt: new Date(NOW).toISOString(),
    command: input,
    consumption,
    intent,
    outcome: ambiguousOutcome(input)
  });
  assert.equal(result.terminal.outcome.status, "AMBIGUOUS");
  assert.equal(result.effectOccupancyReleased, false);
  assert.equal(result.budgetReservationReleased, false);
});

test("PREPARE and post-PREPARE command variants reject every cross-variant field", async () => {
  const { store } = fixture();
  for (const crossVariant of [
    { changeSetArn: command().changeSetArn },
    { changeSetSha256: "5".repeat(64) },
    { stackId: STACK_ID }
  ]) {
    await assert.rejects(
      store.consumeOnce(prepareCommand(crossVariant)),
      /RELEASE_CONTROL_COMMAND_REJECTED/u
    );
  }
  for (const crossVariant of [
    { changeSetName: "prooftoact-release-a" },
    { parameterManifestSha256: "e".repeat(64) },
    { resourceInventorySha256: "f".repeat(64) },
    { stackName: "prooftoact-gate2" },
    { templateSha256: "0".repeat(64) }
  ]) {
    await assert.rejects(
      store.consumeOnce(command(crossVariant)),
      /RELEASE_CONTROL_COMMAND_REJECTED/u
    );
  }
  for (const field of ["changeSetName", "parameterManifestSha256",
    "resourceInventorySha256", "stackName", "templateSha256"]) {
    const missing = prepareCommand();
    delete missing[field];
    await assert.rejects(
      store.consumeOnce(rehashCommand(missing)),
      /RELEASE_CONTROL_COMMAND_REJECTED/u
    );
  }
  for (const field of ["changeSetArn", "changeSetSha256", "stackId"]) {
    const missing = command();
    delete missing[field];
    await assert.rejects(
      store.consumeOnce(rehashCommand(missing)),
      /RELEASE_CONTROL_COMMAND_REJECTED/u
    );
  }
});

test("PREPARE names and digest fields are exact and fail closed", async () => {
  const { store } = fixture();
  for (const changeSetName of [
    "prooftoact-release-A",
    "prooftoact-release-a/b",
    "release-a",
    "prooftoact-release-" + "a".repeat(65)
  ]) {
    await assert.rejects(
      store.consumeOnce(prepareCommand({ changeSetName })),
      /RELEASE_CONTROL_COMMAND_REJECTED/u
    );
  }
  await assert.rejects(
    store.consumeOnce(prepareCommand({ stackName: "prooftoact-gate2-copy" })),
    /RELEASE_CONTROL_COMMAND_REJECTED/u
  );
  for (const field of ["parameterManifestSha256", "resourceInventorySha256",
    "templateSha256"]) {
    await assert.rejects(
      store.consumeOnce(prepareCommand({ [field]: "not-a-digest" })),
      /RELEASE_CONTROL_COMMAND_REJECTED/u
    );
  }
});

test("command drift, fractional microdollars, and oversized canonical records reject", async () => {
  const { store } = fixture();
  await assert.rejects(
    store.consumeOnce(command({ budgetReservationUsd: 0.0000001 })),
    /RELEASE_CONTROL_(?:COMMAND|BUDGET)_REJECTED/u
  );
  const drifted = command();
  drifted.action = "CHANGED";
  await assert.rejects(store.consumeOnce(drifted), /COMMAND_REJECTED/u);
  await assert.rejects(
    store.consumeOnce(command({
      schemaVersion: "prooftoact.provider-broker-command.v1"
    })),
    /COMMAND_REJECTED/u
  );
  await assert.rejects(
    store.consumeOnce(command({ authorityContractSha256: "not-a-digest" })),
    /COMMAND_REJECTED/u
  );
  await assert.rejects(
    store.consumeOnce(command({ runtimeAuthoritySha256: "f".repeat(64) })),
    /COMMAND_REJECTED/u
  );
  for (const stackId of [
    STACK_ID.replace("us-east-1", "us-west-2"),
    STACK_ID.replace(ACCOUNT, "222222222222"),
    STACK_ID.replace("prooftoact-gate2", "another-stack"),
    `${STACK_ID}suffix`
  ]) {
    await assert.rejects(
      store.consumeOnce(command({ stackId })),
      /COMMAND_REJECTED/u
    );
  }
  for (const changeSetArn of [
    command().changeSetArn.replace("us-east-1", "us-west-2"),
    command().changeSetArn.replace(ACCOUNT, "222222222222"),
    command().changeSetArn.replace("prooftoact-release-a", "another-change-set"),
    `${command().changeSetArn}suffix`
  ]) {
    await assert.rejects(
      store.consumeOnce(command({ changeSetArn })),
      /COMMAND_REJECTED/u
    );
  }
  for (const teardownReserveUsd of [0, 0.999999, 1.000001, 2]) {
    await assert.rejects(
      store.consumeOnce(command({ teardownReserveUsd })),
      /COMMAND_REJECTED/u
    );
  }
  assert.throws(
    () => __test.canonicalBytes({ value: "x".repeat(129 * 1024) }),
    /CANONICAL_RECORD_REJECTED/u
  );
  assert.throws(
    () => __test.validateAggregateRecord(
      { value: "x".repeat(70 * 1024) },
      { value: "y".repeat(70 * 1024) }
    ),
    /AGGREGATE_RECORD_REJECTED/u
  );
});
