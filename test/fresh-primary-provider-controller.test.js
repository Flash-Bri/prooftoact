import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  buildFreshPrimaryProviderCommand,
  runFreshPrimaryProviderController
} from "../scripts/fresh-primary-provider-controller.js";

const NOW = Date.parse("2026-08-18T20:00:00.000Z");
const TABLE_ARN =
  "arn:aws:dynamodb:us-east-1:111111111111:table/" +
  "prooftoact-release-controller";
const APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000";
const OPERATION_ID = "223e4567-e89b-42d3-a456-426614174001";
const PROVIDER_CLUSTER_ID = "323e4567-e89b-42d3-a456-426614174002";
const SQL_CLUSTER_ID = "423e4567-e89b-42d3-a456-426614174003";

function commandInput(overrides = {}) {
  return {
    adminSecretArnSha256: "1".repeat(64),
    adminSecretVersionIdSha256: "2".repeat(64),
    adminSecretValueSha256: "b".repeat(64),
    approvalId: APPROVAL_ID,
    approvalSha256: "3".repeat(64),
    cloudApiSecretArnSha256: "4".repeat(64),
    cloudApiSecretVersionIdSha256: "5".repeat(64),
    cloudApiSecretValueSha256: "c".repeat(64),
    controllerTableArn: TABLE_ARN,
    credentialSecretArnSha256: "6".repeat(64),
    credentialSecretVersionIdSha256: "7".repeat(64),
    credentialBundleRawSha256: "d".repeat(64),
    credentialBundleSha256: "e".repeat(64),
    credentialSealReceiptSha256: "8".repeat(64),
    operationId: OPERATION_ID,
    outerAuthenticationReceiptSha256: "7".repeat(64),
    outerCommandSha256: "5".repeat(64),
    outerReservedAt: "2026-08-19T08:00:00.000Z",
    outerReservationAcknowledgedAt: "2026-08-19T08:00:01.000Z",
    outerReservationReceiptSha256: "6".repeat(64),
    providerClusterId: PROVIDER_CLUSTER_ID,
    recoveryPublisherKeySetDigest: "0".repeat(64),
    recoveryPublisherTrustRootCommitment: "1".repeat(64),
    recoverySecurityPostureReceiptSha256: "f".repeat(64),
    signerSecretArnSha256: "2".repeat(64),
    signerSecretValueSha256: "3".repeat(64),
    signerSecretVersionIdSha256: "4".repeat(64),
    sourceCommit: "9".repeat(40),
    sqlClusterId: SQL_CLUSTER_ID,
    treeDigest: "a".repeat(40),
    trustRootJsonSha256: "5".repeat(64),
    ...overrides
  };
}

function fakeProvider(command, { occupied = null } = {}) {
  const events = [];
  let version = occupied?.version ?? 0;
  return {
    events,
    async authenticate(received) {
      assert.deepEqual(received, command);
      events.push(["authenticate", command.providerClusterId]);
      return {
        schemaVersion:
          "prooftoact.fresh-primary-provider-authentication.v3",
        status: "AUTHENTICATED_PROVIDER_READBACK",
        callerIdentitySha256: "c".repeat(64),
        cloud: command.cloud,
        clusterInventorySha256: "d".repeat(64),
        namespaceArn: command.controllerTableArn,
        observedAt: new Date(NOW).toISOString(),
        providerBacked: true,
        providerClusterId: command.providerClusterId,
        readOnly: true,
        region: command.region,
        secretReadbacks: {
          admin: {
            immutableVersion: true,
            secretArnSha256: command.adminSecretArnSha256,
            secretValueSha256: command.adminSecretValueSha256,
            secretVersionIdSha256: command.adminSecretVersionIdSha256,
            versionStage: "AWSCURRENT"
          },
          cloudApi: {
            immutableVersion: true,
            secretArnSha256: command.cloudApiSecretArnSha256,
            secretValueSha256: command.cloudApiSecretValueSha256,
            secretVersionIdSha256: command.cloudApiSecretVersionIdSha256,
            versionStage: "AWSCURRENT"
          },
          credential: {
            immutableVersion: true,
            secretArnSha256: command.credentialSecretArnSha256,
            secretValueSha256: command.credentialBundleRawSha256,
            secretVersionIdSha256: command.credentialSecretVersionIdSha256,
            versionStage: "AWSCURRENT"
          },
          recoverySigner: {
            secretArnSha256: command.signerSecretArnSha256,
            targetVersionAbsent: true,
            targetVersionIdSha256: command.signerSecretVersionIdSha256
          }
        },
        stronglyConsistent: true
      };
    },
    async authenticateRecovery(received) {
      const result = await this.authenticate(received);
      events.at(-1)[0] = "authenticateRecovery";
      return result;
    },
    async readStrong(request) {
      events.push(["read", request]);
      return occupied;
    },
    async consumeOnce(received) {
      assert.deepEqual(received, command);
      events.push(["consume", command.commandSha256]);
      version = 1;
      return {
        schemaVersion: "prooftoact.fresh-primary-provider-consumption.v1",
        status: "CONSUMED",
        approvalId: command.approvalId,
        commandSha256: command.commandSha256,
        consumedAt: new Date(NOW).toISOString(),
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: command.controllerTableArn,
        oneShot: true,
        operationId: command.operationId,
        version
      };
    },
    async appendIntent({ authentication, command: received, consumption }) {
      assert.deepEqual(received, command);
      assert.equal(consumption.version, 1);
      assert.equal(authentication.status,
        "AUTHENTICATED_PROVIDER_READBACK");
      events.push(["intent", command.commandSha256]);
      version = 2;
      return {
        schemaVersion: "prooftoact.fresh-primary-provider-intent.v3",
        status: "DURABLE",
        commandSha256: command.commandSha256,
        durable: true,
        event: "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH",
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: command.controllerTableArn,
        operationId: command.operationId,
        previousReceiptSha256: __test.digest(consumption),
        providerAuthenticationReceiptSha256: __test.digest(authentication),
        version
      };
    },
    async appendTransition({ command: received, transition }) {
      assert.deepEqual(received, command);
      assert.equal(transition.version, version + 1);
      events.push(["transition", transition.phase]);
      version = transition.version;
      return transition;
    },
    async finalize({
      command: received,
      outcome,
      previousReceiptSha256,
      providerReceipt,
      transitionCount
    }) {
      assert.deepEqual(received, command);
      assert.equal(outcome.providerReceiptSha256,
        __test.digest(providerReceipt));
      events.push(["finalize", outcome.status]);
      version += 1;
      return {
        schemaVersion: "prooftoact.fresh-primary-provider-terminal.v1",
        status: "TERMINAL",
        commandSha256: command.commandSha256,
        operationId: command.operationId,
        namespaceArn: command.controllerTableArn,
        outcomeSha256: __test.digest(outcome),
        previousReceiptSha256,
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        transitionCount,
        version
      };
    }
  };
}

function occupiedRecord(command, transitionCount) {
  const consumption = {
    schemaVersion: "prooftoact.fresh-primary-provider-consumption.v1",
    status: "CONSUMED",
    approvalId: command.approvalId,
    commandSha256: command.commandSha256,
    consumedAt: new Date(NOW - 2_000).toISOString(),
    durable: true,
    globallyAuthoritative: true,
    globalKeySha256: command.globalKeySha256,
    namespaceArn: command.controllerTableArn,
    oneShot: true,
    operationId: command.operationId,
    version: 1
  };
  const intent = {
    schemaVersion: "prooftoact.fresh-primary-provider-intent.v3",
    status: "DURABLE",
    commandSha256: command.commandSha256,
    durable: true,
    event: "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH",
    globallyAuthoritative: true,
    globalKeySha256: command.globalKeySha256,
    namespaceArn: command.controllerTableArn,
    operationId: command.operationId,
    previousReceiptSha256: __test.digest(consumption),
    providerAuthenticationReceiptSha256: "a".repeat(64),
    version: 2
  };
  let previousReceiptSha256 = __test.digest(intent);
  const transitions = __test.EXPECTED_BOOTSTRAP_PHASES
    .slice(0, transitionCount)
    .map((phase, sequence) => {
      const transition = {
        schemaVersion: "prooftoact.fresh-primary-provider-transition.v1",
        status: "DURABLE",
        commandSha256: command.commandSha256,
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        mutationDispatched:
          __test.EXPECTED_MUTATION_DISPATCH[sequence],
        namespaceArn: command.controllerTableArn,
        operationId: command.operationId,
        payloadSha256: String(sequence).padStart(64, "0"),
        phase,
        previousReceiptSha256,
        sequence,
        version: sequence + 3
      };
      previousReceiptSha256 = __test.digest(transition);
      return transition;
    });
  return {
    occupied: true,
    command,
    consumption,
    intent,
    lastReceiptSha256: previousReceiptSha256,
    outcome: null,
    providerReceipt: null,
    state: transitionCount === 0 ? "INTENT" : "TRANSITION",
    terminal: null,
    transitionCount,
    transitions,
    version: transitionCount + 2
  };
}

function bootstrapReceipt(command) {
  return {
    schemaVersion: "prooftoact.fresh-primary-bootstrap-receipt.v3",
    status: "PASS",
    approvalId: command.approvalId,
    operationId: command.operationId,
    sourceCommit: command.sourceCommit,
    treeDigest: command.treeDigest,
    partialFailureDisposition: "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD",
    credentialLifecycle: {
      callerSuppliedSealReceiptSha256: command.credentialSealReceiptSha256,
      recoveryPublisher: {
        signerSecretArnSha256: command.signerSecretArnSha256,
        signerSecretVersionIdSha256: command.signerSecretVersionIdSha256,
        signerSecretValueSha256: command.signerSecretValueSha256,
        trustRootCommitment: command.recoveryPublisherTrustRootCommitment,
        publisherKeySetDigest: command.recoveryPublisherKeySetDigest
      }
    },
    provider: {
      clusterIdSha256: crypto.createHash("sha256")
        .update(command.sqlClusterId, "utf8").digest("hex")
    },
    postflight: {
      directPrivateTableAccessDenied: true,
      runtimeDatabase: "tideproof",
      runtimeIdentity: "tp_gate2_authorizer_user"
    }
  };
}

test("provider command binds distinct Cloud and SQL IDs plus all immutable secret versions", () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  assert.equal(command.providerClusterId, PROVIDER_CLUSTER_ID);
  assert.equal(command.sqlClusterId, SQL_CLUSTER_ID);
  assert.equal(command.cloud, "COCKROACHDB_CLOUD_ON_AWS");
  assert.equal(command.region, "us-east-1");
  assert.match(command.commandSha256, /^[0-9a-f]{64}$/u);
  assert.match(command.effectIdentitySha256, /^[0-9a-f]{64}$/u);
  assert.match(command.globalKeySha256, /^[0-9a-f]{64}$/u);
  const secondApproval = buildFreshPrimaryProviderCommand(commandInput({
    approvalId: "623e4567-e89b-42d3-a456-426614174005",
    approvalSha256: "b".repeat(64),
    operationId: "723e4567-e89b-42d3-a456-426614174006"
  }));
  assert.equal(secondApproval.effectIdentitySha256,
    command.effectIdentitySha256);
  assert.equal(secondApproval.globalKeySha256, command.globalKeySha256);
  assert.notEqual(secondApproval.commandSha256, command.commandSha256);
  assert.equal(buildFreshPrimaryProviderCommand(commandInput({
    sqlClusterId: "9fad7a1e-e440-4989-3823-04191b7f3f3b"
  })).sqlClusterId, "9fad7a1e-e440-4989-3823-04191b7f3f3b");
  for (const overrides of [
    { sqlClusterId: PROVIDER_CLUSTER_ID },
    { providerClusterId: "not-a-uuid" },
    { credentialSecretVersionIdSha256: "0".repeat(63) },
    { controllerTableArn: TABLE_ARN.replace("us-east-1", "us-west-2") }
  ]) {
    assert.throws(
      () => buildFreshPrimaryProviderCommand(commandInput(overrides)),
      /FRESH_PRIMARY_PROVIDER_COMMAND_REJECTED/u
    );
  }
});

test("provider controller durably consumes, intents, journals, and terminalizes once", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  const receipt = await runFreshPrimaryProviderController({
    clock: () => NOW,
    command,
    provider,
    async dispatch({ recordTransition }) {
      for (const [index, phase] of
        __test.EXPECTED_BOOTSTRAP_PHASES.entries()) {
        await recordTransition(phase, {
          mutationDispatched: __test.EXPECTED_MUTATION_DISPATCH[index]
        });
      }
      return bootstrapReceipt(command);
    }
  });
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.globallyAuthoritativeOneShot, true);
  assert.equal(receipt.transitionCount, 12);
  assert.equal(receipt.recoveredOccupiedJournal, false);
  assert.deepEqual(provider.events.map(([event, detail]) => [event, detail]), [
    ["read", {
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      namespaceArn: TABLE_ARN,
      operationId: OPERATION_ID,
      stronglyConsistent: true
    }],
    ["authenticate", command.providerClusterId],
    ["consume", command.commandSha256],
    ["intent", command.commandSha256],
    ...__test.EXPECTED_BOOTSTRAP_PHASES.map((phase) =>
      ["transition", phase]),
    ["finalize", "CONFIRMED"]
  ]);
});

test("occupied durable intent and every transition boundary terminalize ambiguous without redispatch", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  for (let transitionCount = 0;
    transitionCount <= __test.EXPECTED_BOOTSTRAP_PHASES.length;
    transitionCount += 1) {
    const provider = fakeProvider(command, {
      occupied: occupiedRecord(command, transitionCount)
    });
    let dispatched = false;
    await assert.rejects(
      runFreshPrimaryProviderController({
        clock: () => NOW,
        command,
        provider,
        async dispatch() { dispatched = true; }
      }),
      /FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY/u
    );
    assert.equal(dispatched, false);
    assert.deepEqual(provider.events.map(([event]) => event),
      ["read", "authenticateRecovery", "finalize"]);
    assert.deepEqual(provider.events.at(-1), ["finalize", "AMBIGUOUS"]);
  }
});

test("provider or immutable secret readback drift rejects before global state", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  const authenticate = provider.authenticate;
  provider.authenticate = async (received) => {
    const result = await authenticate(received);
    return {
      ...result,
      secretReadbacks: {
        ...result.secretReadbacks,
        admin: {
          ...result.secretReadbacks.admin,
          secretVersionIdSha256: "0".repeat(64)
        }
      }
    };
  };
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider,
      async dispatch() { throw new Error("must not dispatch"); }
    }),
    /FRESH_PRIMARY_PROVIDER_AUTHENTICATION_REJECTED/u
  );
  assert.deepEqual(provider.events.map(([event]) => event),
    ["read", "authenticate"]);
});

test("authenticated secret content digest drift rejects before global state", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  const authenticate = provider.authenticate;
  provider.authenticate = async (received) => {
    const result = await authenticate(received);
    return {
      ...result,
      secretReadbacks: {
        ...result.secretReadbacks,
        credential: {
          ...result.secretReadbacks.credential,
          secretValueSha256: "0".repeat(64)
        }
      }
    };
  };
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider,
      async dispatch() { throw new Error("must not dispatch"); }
    }),
    /FRESH_PRIMARY_PROVIDER_AUTHENTICATION_REJECTED/u
  );
  assert.deepEqual(provider.events.map(([event]) => event),
    ["read", "authenticate"]);
});

test("stale or future provider authentication rejects before global state", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  for (const observedAt of [
    new Date(NOW - (5 * 60 * 1000) - 1).toISOString(),
    new Date(NOW + 1).toISOString()
  ]) {
    const provider = fakeProvider(command);
    const authenticate = provider.authenticate;
    provider.authenticate = async (received) => ({
      ...await authenticate(received),
      observedAt
    });
    await assert.rejects(
      runFreshPrimaryProviderController({
        clock: () => NOW,
        command,
        provider,
        async dispatch() { throw new Error("must not dispatch"); }
      }),
      /FRESH_PRIMARY_PROVIDER_AUTHENTICATION_REJECTED/u
    );
    assert.deepEqual(provider.events.map(([event]) => event),
      ["read", "authenticate"]);
  }
});

test("PASS without the exact twelve-phase bootstrap chain rejects", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider,
      async dispatch() { return bootstrapReceipt(command); }
    }),
    /FRESH_PRIMARY_PROVIDER_DISPATCH_RECEIPT_REJECTED/u
  );
  assert.deepEqual(provider.events.at(-1), ["finalize", "FAILED_TERMINAL"]);

  const wrongOrderProvider = fakeProvider(command);
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider: wrongOrderProvider,
      async dispatch({ recordTransition }) {
        await recordTransition("CREATE_DATABASE_DISPATCHING", {
          mutationDispatched: true
        });
      }
    }),
    /FRESH_PRIMARY_PROVIDER_TRANSITION_REJECTED/u
  );
  assert.deepEqual(wrongOrderProvider.events.at(-1),
    ["finalize", "FAILED_TERMINAL"]);
});

test("pre-mutation failure terminalizes without authorizing a retry", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider,
      async dispatch() {
        throw new Error("FRESH_PRIMARY_CLUSTER_IDENTITY_REJECTED");
      }
    }),
    /FRESH_PRIMARY_CLUSTER_IDENTITY_REJECTED/u
  );
  assert.deepEqual(provider.events.at(-1), ["finalize", "FAILED_TERMINAL"]);
});

test("post-dispatch failure becomes globally terminal AMBIGUOUS and never retries", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider,
      async dispatch({ recordTransition }) {
        for (const [index, phase] of
          __test.EXPECTED_BOOTSTRAP_PHASES.entries()) {
          await recordTransition(phase, {
            mutationDispatched: __test.EXPECTED_MUTATION_DISPATCH[index]
          });
          if (phase === "CREATE_DATABASE_DISPATCHING") break;
        }
        throw new Error("FRESH_PRIMARY_PARTIAL_FAILURE_UNKNOWN_DO_NOT_RETRY");
      }
    }),
    /FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY/u
  );
  assert.deepEqual(provider.events.at(-1), ["finalize", "AMBIGUOUS"]);
});

test("provider journal drift fails closed", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  const provider = fakeProvider(command);
  const append = provider.appendTransition;
  provider.appendTransition = async (input) => ({
    ...await append(input),
    payloadSha256: "f".repeat(64)
  });
  await assert.rejects(
    runFreshPrimaryProviderController({
      clock: () => NOW,
      command,
      provider,
      async dispatch({ recordTransition }) {
        await recordTransition("SIGNER_SECRET_DISPATCHING", {
          mutationDispatched: true
        });
      }
    }),
    /FRESH_PRIMARY_PROVIDER_(?:TRANSITION_CONFLICT|FINALIZE_UNKNOWN)/u
  );
});

test("terminal must chain the last transition at the exact next version", async () => {
  const command = buildFreshPrimaryProviderCommand(commandInput());
  for (const drift of [
    { previousReceiptSha256: "f".repeat(64) },
    { transitionCount: 9 },
    { version: 999 }
  ]) {
    const provider = fakeProvider(command);
    const finalize = provider.finalize;
    provider.finalize = async (input) => ({
      ...await finalize(input),
      ...drift
    });
    await assert.rejects(
      runFreshPrimaryProviderController({
        clock: () => NOW,
        command,
        provider,
        async dispatch({ recordTransition }) {
          for (const [index, phase] of
            __test.EXPECTED_BOOTSTRAP_PHASES.entries()) {
            await recordTransition(phase, {
              mutationDispatched: __test.EXPECTED_MUTATION_DISPATCH[index]
            });
          }
          return bootstrapReceipt(command);
        }
      }),
      /FRESH_PRIMARY_PROVIDER_TERMINAL_REJECTED/u
    );
  }
});
