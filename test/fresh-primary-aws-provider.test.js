import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  createFreshPrimaryAwsProvider,
  readFreshPrimarySecretMaterial
} from "../scripts/fresh-primary-aws-provider.js";
import {
  __test as controllerTest,
  buildFreshPrimaryProviderCommand,
  runFreshPrimaryProviderController
} from "../scripts/fresh-primary-provider-controller.js";
import {
  freshRecoveryPublisherSecretBytes,
  generateFreshRecoveryPublisherSecret
} from "../scripts/lib/fresh-recovery-publisher-key.js";

const NOW = Date.parse("2026-08-18T20:00:00.000Z");
const ACCOUNT = "111111111111";
const TABLE_ARN =
  `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/` +
  "prooftoact-release-controller";
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const PROVIDER_CLUSTER_ID = "323e4567-e89b-42d3-a456-426614174002";
const SQL_CLUSTER_ID = "423e4567-e89b-42d3-a456-426614174003";
const SQL_HOST = "cluster-abc.us-east-1.cockroachlabs.cloud";
const ADMIN_URL =
  "postgresql://root:strong-password" +
  `@${SQL_HOST}:26257/defaultdb` +
  "?sslmode=verify-full";
const CLOUD_TOKEN = "cockroach-cloud-token-value";
const CREDENTIAL_BUNDLE = JSON.stringify({
  schemaVersion: "prooftoact.fresh-primary-credentials.v2",
  passwords: {}
});
const SECRET_COORDINATES = Object.freeze({
  admin: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      `prooftoact/fresh-primary/admin-${OPERATION_ID}-Ab12Cd`,
    versionId: "1".repeat(32)
  }),
  cloudApi: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      "prooftoact/fresh-primary/cloud-api-Ef34Gh",
    versionId: "2".repeat(32)
  }),
  credential: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      "prooftoact/fresh-primary/runtime-credentials-Ij56Kl",
    versionId: "3".repeat(32)
  }),
  signer: Object.freeze({
    arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:` +
      `prooftoact/fresh-primary/recovery-signer-${OPERATION_ID}-Mn78Op`,
    versionId: "4".repeat(32)
  })
});

const SIGNER_BINDING = Object.freeze({
  operationId: OPERATION_ID,
  sourceCommit: "7".repeat(40),
  treeDigest: "8".repeat(40)
});
const RECOVERY_SIGNER = generateFreshRecoveryPublisherSecret(SIGNER_BINDING);
const RECOVERY_SIGNER_STRING = freshRecoveryPublisherSecretBytes(
  RECOVERY_SIGNER,
  SIGNER_BINDING
).toString("utf8");

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function command() {
  return buildFreshPrimaryProviderCommand({
    adminSecretArnSha256: sha256(SECRET_COORDINATES.admin.arn),
    adminSecretValueSha256: sha256(ADMIN_URL),
    adminSecretVersionIdSha256:
      sha256(SECRET_COORDINATES.admin.versionId),
    approvalId: APPROVAL_ID,
    approvalSha256: "4".repeat(64),
    cloudApiSecretArnSha256: sha256(SECRET_COORDINATES.cloudApi.arn),
    cloudApiSecretValueSha256: sha256(CLOUD_TOKEN),
    cloudApiSecretVersionIdSha256:
      sha256(SECRET_COORDINATES.cloudApi.versionId),
    controllerTableArn: TABLE_ARN,
    credentialSecretArnSha256: sha256(SECRET_COORDINATES.credential.arn),
    credentialSecretVersionIdSha256:
      sha256(SECRET_COORDINATES.credential.versionId),
    credentialBundleRawSha256: sha256(CREDENTIAL_BUNDLE),
    credentialBundleSha256: "5".repeat(64),
    credentialSealReceiptSha256: "6".repeat(64),
    operationId: OPERATION_ID,
    providerClusterId: PROVIDER_CLUSTER_ID,
    recoveryPublisherKeySetDigest: RECOVERY_SIGNER.publisherKeySetDigest,
    recoveryPublisherTrustRootCommitment:
      RECOVERY_SIGNER.trustRootCommitment,
    recoverySecurityPostureReceiptSha256: "9".repeat(64),
    signerSecretArnSha256: sha256(SECRET_COORDINATES.signer.arn),
    signerSecretValueSha256: RECOVERY_SIGNER.secretBytesSha256,
    signerSecretVersionIdSha256:
      sha256(SECRET_COORDINATES.signer.versionId),
    sourceCommit: "7".repeat(40),
    sqlClusterId: SQL_CLUSTER_ID,
    treeDigest: "8".repeat(40),
    trustRootJsonSha256: RECOVERY_SIGNER.trustRootJsonSha256
  });
}

function bootstrapReceipt(input) {
  return {
    schemaVersion: "prooftoact.fresh-primary-bootstrap-receipt.v3",
    status: "PASS",
    approvalId: input.approvalId,
    operationId: input.operationId,
    sourceCommit: input.sourceCommit,
    treeDigest: input.treeDigest,
    partialFailureDisposition: "UNKNOWN_DO_NOT_RETRY_RECONCILE_OR_DISCARD",
    credentialLifecycle: {
      callerSuppliedSealReceiptSha256: input.credentialSealReceiptSha256,
      recoveryPublisher: {
        publisherKeySetDigest: input.recoveryPublisherKeySetDigest,
        signerSecretArnSha256: input.signerSecretArnSha256,
        signerSecretValueSha256: input.signerSecretValueSha256,
        signerSecretVersionIdSha256: input.signerSecretVersionIdSha256,
        trustRootCommitment: input.recoveryPublisherTrustRootCommitment
      }
    },
    provider: { clusterIdSha256: sha256(input.sqlClusterId) },
    postflight: {
      directPrivateTableAccessDenied: true,
      runtimeDatabase: "tideproof",
      runtimeIdentity: "tp_gate2_authorizer_user"
    }
  };
}

class FakeAwsProvider {
  constructor() {
    this.item = null;
    this.calls = [];
    this.ackLoss = new Set();
    this.signerSecret = null;
    this.cluster = {
      id: PROVIDER_CLUSTER_ID,
      name: "prooftoact-primary",
      cockroach_version: "v26.2.0",
      cloud_provider: "AWS",
      state: "CREATED",
      operation_status: "UNSPECIFIED",
      plan: "BASIC",
      sql_dns: SQL_HOST,
      regions: [{ name: "us-east-1", sql_dns: SQL_HOST }]
    };
  }

  async describeFreshPrimaryTable(input) {
    this.calls.push(["describe", input]);
    return {
      Table: {
        AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }],
        BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" },
        DeletionProtectionEnabled: true,
        KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }],
        SSEDescription: { SSEType: "KMS", Status: "ENABLED" },
        TableArn: TABLE_ARN,
        TableId: "table-id",
        TableName: "prooftoact-release-controller",
        TableStatus: "ACTIVE"
      }
    };
  }

  async getFreshPrimaryCallerIdentity() {
    this.calls.push(["identity"]);
    return {
      Account: ACCOUNT,
      Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
        "ProofToActFreshPrimaryBootstrap/pta-1234567890-1-bootstrap",
      UserId: "AROAABCDEFGHIJKLMNOP:pta-1234567890-1-bootstrap"
    };
  }

  async describeRecoverySignerSecret() {
    this.calls.push(["describe-signer"]);
    return {
      ARN: SECRET_COORDINATES.signer.arn,
      Name: `prooftoact/fresh-primary/recovery-signer-${OPERATION_ID}`,
      RotationEnabled: false,
      Tags: [
        { Key: "Project", Value: "ProofToAct" },
        { Key: "Purpose", Value: "FreshRecoveryPublisherSigner" },
        { Key: "OperationId", Value: OPERATION_ID }
      ],
      VersionIdsToStages: this.signerSecret === null ? {} : {
        [SECRET_COORDINATES.signer.versionId]: ["AWSCURRENT"]
      }
    };
  }

  async getRecoverySignerResourcePolicy() {
    this.calls.push(["signer-policy"]);
    return { ARN: SECRET_COORDINATES.signer.arn };
  }

  async readRecoverySignerVersionIfPresent() {
    this.calls.push(["signer-prestate"]);
    return this.signerSecret;
  }

  async getFreshPrimaryItem(input) {
    this.calls.push(["get", input]);
    return this.item === null ? {} : { Item: structuredClone(this.item) };
  }

  async listFreshPrimaryTableTags(input) {
    this.calls.push(["tags", input]);
    return { Tags: [
      { Key: "Project", Value: "ProofToAct" },
      { Key: "Purpose", Value: "RetainedReleaseControl" },
      {
        Key: "Retention",
        Value: "IntentionalOutsideApplicationTeardown"
      }
    ] };
  }

  async putFreshPrimaryItem(input) {
    this.calls.push(["put", input]);
    if (this.item !== null) throw new Error("conditional");
    this.item = structuredClone(input.Item);
    if (this.ackLoss.delete("put")) throw new Error("ack loss");
    return {};
  }

  async readCockroachCluster(input) {
    this.calls.push(["cluster", input]);
    assert.equal(input.bearerToken, CLOUD_TOKEN);
    assert.equal(input.clusterId, PROVIDER_CLUSTER_ID);
    return structuredClone(this.cluster);
  }

  async readSecretVersion(input) {
    this.calls.push(["secret", input]);
    const coordinate = Object.values(SECRET_COORDINATES).find((item) =>
      item.arn === input.arn && item.versionId === input.versionId);
    assert.ok(coordinate);
    const value = coordinate === SECRET_COORDINATES.admin
      ? ADMIN_URL
      : coordinate === SECRET_COORDINATES.cloudApi
        ? CLOUD_TOKEN
        : coordinate === SECRET_COORDINATES.credential
          ? CREDENTIAL_BUNDLE : this.signerSecret?.SecretString;
    assert.equal(typeof value, "string");
    return {
      ARN: coordinate.arn,
      CreatedDate: new Date(NOW - 60_000),
      SecretString: value,
      VersionId: coordinate.versionId,
      VersionStages: ["AWSCURRENT"]
    };
  }

  async putRecoverySignerSecret(input) {
    this.calls.push(["put-signer", input]);
    assert.equal(input.clientRequestToken,
      SECRET_COORDINATES.signer.versionId);
    assert.equal(input.secretString, RECOVERY_SIGNER_STRING);
    this.signerSecret = {
      ARN: SECRET_COORDINATES.signer.arn,
      CreatedDate: new Date(NOW),
      SecretString: input.secretString,
      VersionId: SECRET_COORDINATES.signer.versionId,
      VersionStages: ["AWSCURRENT"]
    };
    if (this.ackLoss.delete("put-signer")) throw new Error("ack loss");
    return {};
  }

  async updateFreshPrimaryItem(input) {
    this.calls.push(["update", input]);
    assert.ok(this.item);
    const names = input.ExpressionAttributeNames;
    const values = input.ExpressionAttributeValues;
    if (names["#intent"]) {
      assert.equal(this.item.state.S, values[":expectedState"].S);
      this.item.intent = structuredClone(values[":intent"]);
      this.item.intentSha256 = structuredClone(values[":intentSha256"]);
    } else if (names["#terminal"]) {
      assert.equal(this.item.state.S, values[":expectedState"].S);
      this.item.outcome = structuredClone(values[":outcome"]);
      this.item.outcomeSha256 = structuredClone(values[":outcomeSha256"]);
      this.item.providerReceipt = structuredClone(values[":providerReceipt"]);
      this.item.terminal = structuredClone(values[":terminal"]);
      this.item.terminalSha256 = structuredClone(values[":terminalSha256"]);
    } else {
      const attribute = names["#record"];
      assert.equal(this.item[attribute], undefined);
      this.item[attribute] = structuredClone(values[":record"]);
      this.item.transitionCount = structuredClone(values[":count"]);
    }
    this.item.lastReceiptSha256 = structuredClone(values[":last"]);
    this.item.state = structuredClone(values[":state"]);
    this.item.version = structuredClone(values[":version"]);
    if (this.ackLoss.delete("update")) throw new Error("ack loss");
    return {};
  }
}

function fixture(lowLevel = new FakeAwsProvider()) {
  return {
    lowLevel,
    provider: createFreshPrimaryAwsProvider({
      clock: () => NOW,
      provider: lowLevel,
      secretCoordinates: SECRET_COORDINATES,
      sqlHostSha256: sha256(SQL_HOST),
      tableArn: TABLE_ARN
    })
  };
}

test("exact secret versions and Cockroach Cloud inventory authenticate before state", async () => {
  const input = command();
  const { lowLevel, provider } = fixture();
  const authentication = await provider.authenticate(input);
  assert.equal(authentication.status, "AUTHENTICATED_PROVIDER_READBACK");
  assert.equal(authentication.providerClusterId, PROVIDER_CLUSTER_ID);
  assert.equal(authentication.secretReadbacks.admin.secretValueSha256,
    input.adminSecretValueSha256);
  assert.equal(authentication.secretReadbacks.credential.secretValueSha256,
    input.credentialBundleRawSha256);
  assert.equal(authentication.secretReadbacks.recoverySigner.
    targetVersionAbsent, true);
  assert.equal(lowLevel.calls.filter(([name]) => name === "secret").length, 3);
  assert.equal(lowLevel.calls.filter(([name]) => name === "cluster").length, 1);
  assert.equal(lowLevel.item, null);
});

test("fresh P-256 signer version is put once and reconciled only by exact readback", async () => {
  for (const acknowledgementLost of [false, true]) {
    const input = command();
    const { lowLevel, provider } = fixture();
    if (acknowledgementLost) lowLevel.ackLoss.add("put-signer");
    const seal = await provider.sealRecoveryPublisherSecret({
      command: input,
      secret: RECOVERY_SIGNER
    });
    assert.equal(seal.status, "SEALED");
    assert.equal(seal.secretValueSha256, input.signerSecretValueSha256);
    assert.equal(lowLevel.calls.filter(([name]) => name === "put-signer").length,
      1);
    assert.equal(lowLevel.signerSecret.SecretString, RECOVERY_SIGNER_STRING);
  }

  const input = command();
  const { lowLevel, provider } = fixture();
  await assert.rejects(provider.sealRecoveryPublisherSecret({
    command: input,
    secret: { ...RECOVERY_SIGNER, sourceCommit: "0".repeat(40) }
  }), /FRESH_(?:RECOVERY_PUBLISHER_SECRET|PRIMARY_AWS_SIGNER_SECRET)_REJECTED/u);
  assert.equal(lowLevel.calls.some(([name]) => name === "put-signer"), false);
});

test("signer prestate requires one empty operation-bound protected secret", async () => {
  const input = command();
  for (const mutate of [
    (lowLevel) => {
      lowLevel.signerSecret = {
        ARN: SECRET_COORDINATES.signer.arn,
        CreatedDate: new Date(NOW),
        SecretString: RECOVERY_SIGNER_STRING,
        VersionId: SECRET_COORDINATES.signer.versionId,
        VersionStages: ["AWSCURRENT"]
      };
    },
    (lowLevel) => {
      const describe = lowLevel.describeRecoverySignerSecret.bind(lowLevel);
      lowLevel.describeRecoverySignerSecret = async () => ({
        ...await describe(),
        KmsKeyId: "alias/unreviewed"
      });
    },
    (lowLevel) => {
      lowLevel.getRecoverySignerResourcePolicy = async () => ({
        ARN: SECRET_COORDINATES.signer.arn,
        ResourcePolicy: "{}"
      });
    }
  ]) {
    const lowLevel = new FakeAwsProvider();
    mutate(lowLevel);
    const { provider } = fixture(lowLevel);
    await assert.rejects(provider.authenticate(input),
      /FRESH_PRIMARY_AWS_SIGNER_SECRET_PRESTATE_REJECTED/u);
    assert.equal(lowLevel.calls.some(([name]) => name === "put-signer"), false);
  }
});

test("joined provider controller stores the exact twelve-phase terminal chain", async () => {
  const input = command();
  const { lowLevel, provider } = fixture();
  const receipt = await runFreshPrimaryProviderController({
    clock: () => NOW,
    command: input,
    provider,
    async dispatch({ recordTransition }) {
      for (const [index, phase] of
        controllerTest.EXPECTED_BOOTSTRAP_PHASES.entries()) {
        await recordTransition(phase, {
          mutationDispatched:
            controllerTest.EXPECTED_MUTATION_DISPATCH[index]
        });
      }
      return bootstrapReceipt(input);
    }
  });
  assert.equal(receipt.schemaVersion,
    "prooftoact.fresh-primary-provider-controller-receipt.v3");
  assert.equal(receipt.evidence.bootstrapReceipt.status, "PASS");
  assert.equal(receipt.evidence.providerAuthentication.providerBacked, true);
  assert.equal(receipt.evidence.terminalReceipt.status, "TERMINAL");
  assert.equal(lowLevel.item.state.S, "TERMINAL");
  assert.equal(lowLevel.item.version.N, "15");
  assert.equal(lowLevel.item.transitionCount.N, "12");
  assert.equal(Object.keys(lowLevel.item)
    .filter((name) => /^transition[0-9]{2}$/u.test(name)).length, 12);
  const stored = await provider.readStrong({
    commandSha256: input.commandSha256,
    globalKeySha256: input.globalKeySha256,
    namespaceArn: TABLE_ARN,
    operationId: input.operationId,
    stronglyConsistent: true
  });
  assert.equal(stored.outcome.status, "CONFIRMED");
  assert.equal(stored.providerReceipt.status, "PASS");
});

test("provider rerun seals every occupied intent or transition boundary ambiguous without redispatch", async () => {
  const input = command();
  for (let transitionCount = 0;
    transitionCount <= controllerTest.EXPECTED_BOOTSTRAP_PHASES.length;
    transitionCount += 1) {
    const { lowLevel, provider } = fixture();
    const authentication = await provider.authenticate(input);
    const consumption = await provider.consumeOnce(input);
    const intent = await provider.appendIntent({
      authentication,
      command: input,
      consumption
    });
    let previousReceiptSha256 = controllerTest.digest(intent);
    for (let sequence = 0; sequence < transitionCount; sequence += 1) {
      const transition = {
        schemaVersion: "prooftoact.fresh-primary-provider-transition.v1",
        status: "DURABLE",
        commandSha256: input.commandSha256,
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: input.globalKeySha256,
        mutationDispatched:
          controllerTest.EXPECTED_MUTATION_DISPATCH[sequence],
        namespaceArn: TABLE_ARN,
        operationId: input.operationId,
        payloadSha256: String(sequence).padStart(64, "0"),
        phase: controllerTest.EXPECTED_BOOTSTRAP_PHASES[sequence],
        previousReceiptSha256,
        sequence,
        version: sequence + 3
      };
      await provider.appendTransition({ command: input, intent, transition });
      previousReceiptSha256 = controllerTest.digest(transition);
    }
    if (transitionCount >= 2) {
      lowLevel.signerSecret = {
        ARN: SECRET_COORDINATES.signer.arn,
        CreatedDate: new Date(NOW),
        SecretString: RECOVERY_SIGNER_STRING,
        VersionId: SECRET_COORDINATES.signer.versionId,
        VersionStages: ["AWSCURRENT"]
      };
    }
    let dispatched = false;
    await assert.rejects(runFreshPrimaryProviderController({
      clock: () => NOW,
      command: input,
      provider,
      async dispatch() { dispatched = true; }
    }), /FRESH_PRIMARY_PROVIDER_UNKNOWN_DO_NOT_RETRY/u);
    assert.equal(dispatched, false);
    const recovered = await provider.readStrong({
      commandSha256: input.commandSha256,
      globalKeySha256: input.globalKeySha256,
      namespaceArn: TABLE_ARN,
      operationId: input.operationId,
      stronglyConsistent: true
    });
    assert.equal(recovered.state, "TERMINAL");
    assert.equal(recovered.transitionCount, transitionCount);
    assert.equal(recovered.outcome.status, "AMBIGUOUS");
    assert.equal(recovered.providerReceipt.causeCode,
      "FRESH_PRIMARY_PROCESS_INTERRUPTED_AFTER_DURABLE_INTENT");
    assert.equal(recovered.providerReceipt.lastReceiptSha256,
      previousReceiptSha256);
    assert.equal(recovered.providerReceipt.transitionCount, transitionCount);
  }
});

test("conditional-write acknowledgement loss reconciles by strong read only", async () => {
  const input = command();
  const { lowLevel, provider } = fixture();
  lowLevel.ackLoss.add("put");
  const consumption = await provider.consumeOnce(input);
  assert.equal(consumption.status, "CONSUMED");
  const authentication = await provider.authenticate(input);
  lowLevel.ackLoss.add("update");
  const intent = await provider.appendIntent({
    authentication,
    command: input,
    consumption
  });
  assert.equal(intent.status, "DURABLE");
  assert.equal(lowLevel.calls.filter(([name]) => name === "put").length, 1);
  assert.equal(lowLevel.calls.filter(([name]) => name === "update").length, 1);
  assert.equal(lowLevel.calls.filter(([name]) => name === "get").length, 2);
});

test("provider inventory or immutable secret drift rejects before any write", async () => {
  const input = command();
  for (const mutate of [
    (lowLevel) => { lowLevel.cluster.cloud_provider = "GCP"; },
    (lowLevel) => { lowLevel.cluster.sql_dns = "other.cockroachlabs.cloud"; },
    (lowLevel) => {
      const read = lowLevel.readSecretVersion.bind(lowLevel);
      lowLevel.readSecretVersion = async (coordinate) => ({
        ...await read(coordinate),
        VersionId: coordinate.arn === SECRET_COORDINATES.admin.arn
          ? "9".repeat(32) : coordinate.versionId
      });
    }
  ]) {
    const lowLevel = new FakeAwsProvider();
    mutate(lowLevel);
    const { provider } = fixture(lowLevel);
    await assert.rejects(provider.authenticate(input),
      /FRESH_PRIMARY_(?:COCKROACH_INVENTORY|AWS_SECRET_READBACK)_REJECTED/u);
    assert.equal(lowLevel.calls.some(([name]) =>
      ["put", "update"].includes(name)), false);
  }
});

test("secret material reader accepts only bounded AWSCURRENT strings", async () => {
  const lowLevel = new FakeAwsProvider();
  const material = await readFreshPrimarySecretMaterial({
    provider: lowLevel,
    secretCoordinates: SECRET_COORDINATES
  });
  assert.equal(material.admin.secretValue, ADMIN_URL);
  assert.equal(material.cloudApi.secretValue, CLOUD_TOKEN);
  assert.equal(material.credential.secretValue, CREDENTIAL_BUNDLE);
  const read = lowLevel.readSecretVersion.bind(lowLevel);
  lowLevel.readSecretVersion = async (coordinate) => ({
    ...await read(coordinate),
    VersionStages: ["AWSPREVIOUS"]
  });
  await assert.rejects(readFreshPrimarySecretMaterial({
    provider: lowLevel,
    secretCoordinates: SECRET_COORDINATES
  }), /FRESH_PRIMARY_AWS_SECRET_READBACK_REJECTED/u);
});

test("canonical DynamoDB key namespace is separate from release effects", () => {
  assert.equal(__test.effectKey("a".repeat(64)),
    `FRESH_PRIMARY#${"a".repeat(64)}`);
  assert.equal(__test.transitionAttribute(0), "transition00");
  assert.equal(__test.transitionAttribute(10), "transition10");
});
