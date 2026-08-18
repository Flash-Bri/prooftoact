import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { attestReleaseControlTable } from
  "../scripts/lib/release-control-table-identity.js";
import { canonicalJson as applicationCanonicalJson } from
  "../src/cloud/canonical-json.js";
import {
  APP_SOURCE,
  ARTIFACT_NAMES,
  PARAMETER_KEYS,
  base64Sha256,
  canonicalBytes,
  canonicalDigest,
  canonicalJson,
  fixedSdkOptions,
  sha256
} from "../release-provider/src/release-provider-common.js";
import {
  createPreparePermitReader
} from "../release-provider/src/release-provider-permit-reader.js";
import {
  createPrepareDispatcher,
  validatePrepareRequest
} from "../release-provider/src/release-provider-prepare-dispatcher.js";
import {
  createPrepareReadback
} from "../release-provider/src/release-provider-prepare-readback.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ACCOUNT = "111111111111";
const TABLE_ARN =
  `arn:aws:dynamodb:us-east-1:${ACCOUNT}:table/prooftoact-release-controller`;
const APPROVAL_ID = "123e4567-e89b-42d3-a456-426614174000";
const INTENT_ID = "223e4567-e89b-42d3-a456-426614174001";
const STORE_REQUEST_ID = "323e4567-e89b-42d3-a456-426614174002";
const CHANGE_SET_ID =
  `arn:aws:cloudformation:us-east-1:${ACCOUNT}:changeSet/` +
  "prooftoact-release-final/423e4567-e89b-42d3-a456-426614174003";
const STACK_ID =
  `arn:aws:cloudformation:us-east-1:${ACCOUNT}:stack/` +
  "prooftoact-gate2/523e4567-e89b-42d3-a456-426614174004";
const NOW = Date.parse("2026-08-17T23:00:00.000Z");
const AUTHORITY_NOT_AFTER = new Date(Date.now() + 10 * 60 * 1000)
  .toISOString();
const CREDENTIALS = Object.freeze({
  accessKeyId: `ASIA${"A".repeat(16)}`,
  secretAccessKey: "b".repeat(40),
  sessionToken: "temporary-session-token"
});

function tableResponses(kmsKey =
  `arn:aws:kms:us-east-1:${ACCOUNT}:key/` +
  "623e4567-e89b-42d3-a456-426614174005") {
  return {
    describeResponse: {
      Table: {
        AttributeDefinitions: [{ AttributeName: "pk", AttributeType: "S" }],
        BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" },
        DeletionProtectionEnabled: true,
        KeySchema: [{ AttributeName: "pk", KeyType: "HASH" }],
        SSEDescription: {
          KMSMasterKeyArn: kmsKey,
          SSEType: "KMS",
          Status: "ENABLED"
        },
        TableArn: TABLE_ARN,
        TableId: "723e4567-e89b-42d3-a456-426614174006",
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

function makeArtifacts(bucket) {
  return ARTIFACT_NAMES.map((name, index) => {
    const body = Buffer.from(`exact-${name}-zip-${index}\n`, "utf8");
    const digest = sha256(body);
    return {
      body,
      descriptor: {
        bytes: body.length,
        checksumSha256: base64Sha256(body),
        codeSha256: Buffer.alloc(32, index + 1).toString("base64"),
        contentType: "application/zip",
        kind: "LAMBDA_ZIP",
        name,
        s3Bucket: bucket,
        s3Key: `gate2/${APP_SOURCE.commit}/${name}-${digest}.zip`,
        sha256: digest,
        sourceSha256: String(index + 1).repeat(64)
      }
    };
  });
}

function literalParameters(account, bucket, artifacts) {
  const literal = {
    ArtifactBucket: bucket,
    AuthorityDatabaseHost: "synthetic.example.invalid",
    AuthorityDatabasePort: "26257",
    AuthorityDatabaseSecretArn:
      `arn:aws:secretsmanager:us-east-1:${account}:secret:synthetic`,
    AuthorityDatabaseSecretVersionId:
      "823e4567-e89b-42d3-a456-426614174007",
    AuthorityIncidentId: "923e4567-e89b-42d3-a456-426614174008",
    AuthorityResourceId: "a23e4567-e89b-42d3-a456-426614174009",
    AuthorityTenantId: "b23e4567-e89b-42d3-a456-42661417400a",
    BedrockModelId: "amazon.nova-micro-v1:0",
    ConfigDigest: "a".repeat(64),
    EnableProbeFunctions: "false",
    EvidenceOperatorPrincipalArn:
      `arn:aws:iam::${account}:role/ProofToActLiveDrillOperator`,
    PackageLockDigest: "b".repeat(64),
    SourceCommit: APP_SOURCE.commit,
    TreeDigest: APP_SOURCE.tree
  };
  for (const artifact of artifacts) {
    const prefix = artifact.descriptor.name[0].toUpperCase() +
      artifact.descriptor.name.slice(1);
    literal[`${prefix}ArtifactCodeSha256`] = artifact.descriptor.codeSha256;
    literal[`${prefix}ArtifactDigest`] = artifact.descriptor.sha256;
    literal[`${prefix}ArtifactKey`] = artifact.descriptor.s3Key;
    literal[`${prefix}SourceDigest`] = artifact.descriptor.sourceSha256;
  }
  return PARAMETER_KEYS.map((ParameterKey) => {
    if (ParameterKey.endsWith("ArtifactVersion")) {
      const prefix = ParameterKey.slice(0, -"ArtifactVersion".length);
      return { ParameterKey, Source: "OBJECT_VERSION",
        Value: prefix.toLowerCase() };
    }
    return { ParameterKey, Source: "LITERAL", Value: literal[ParameterKey] };
  });
}

function fixture() {
  const bucket = "prooftoact-exact-artifacts";
  const artifacts = makeArtifacts(bucket);
  const parameterBindings = literalParameters(ACCOUNT, bucket, artifacts);
  const gate2Body = fs.readFileSync(path.join(ROOT,
    "infra/aws/gate2-template.json"));
  const templateDigest = sha256(gate2Body);
  const template = {
    body: gate2Body,
    descriptor: {
      bytes: gate2Body.length,
      checksumSha256: base64Sha256(gate2Body),
      contentType: "application/json",
      kind: "CLOUDFORMATION_TEMPLATE",
      name: "gate2-template",
      s3Bucket: bucket,
      s3Key:
        `gate2/${APP_SOURCE.commit}/gate2-template-${templateDigest}.json`,
      sha256: templateDigest
    }
  };
  const gate2 = JSON.parse(gate2Body.toString("utf8"));
  const createResourceInventory = Object.entries(gate2.Resources)
    .filter(([, resource]) => resource.Condition !== "ShouldDeployProbes")
    .map(([logicalId, resource]) => ({ logicalId, type: resource.Type }))
    .sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  const artifactManifestSha256 = canonicalDigest({
    artifactBucket: bucket,
    artifacts: artifacts.map(({ descriptor }) => descriptor)
  });
  const authorityContractSha256 = "c".repeat(64);
  const controlPlaneIdentitySha256 = "d".repeat(64);
  const approvalSha256 = "e".repeat(64);
  const effectIdentitySha256 = canonicalDigest({
    action: "PREPARE_EXACT_CREATE_CHANGE_SET",
    artifactManifestSha256,
    buildReceiptSha256: "f".repeat(64),
    changeSetName: "prooftoact-release-final",
    lane: "PREPARE",
    parameterManifestSha256: canonicalDigest(parameterBindings),
    providerAccountId: ACCOUNT,
    region: "us-east-1",
    resourceInventorySha256: canonicalDigest(createResourceInventory),
    stackName: "prooftoact-gate2",
    templateSha256: templateDigest
  });
  const commandBase = {
    schemaVersion: "prooftoact.provider-broker-command.v2",
    action: "PREPARE_EXACT_CREATE_CHANGE_SET",
    approvalId: APPROVAL_ID,
    approvalSha256,
    appSource: APP_SOURCE,
    artifactManifestSha256,
    authorityContractSha256,
    budgetKeySha256: canonicalDigest({
      currency: "USD", project: "ProofToAct", providerAccountId: ACCOUNT,
      region: "us-east-1"
    }),
    budgetReservationUsd: 0.25,
    buildReceiptSha256: "f".repeat(64),
    changeSetName: "prooftoact-release-final",
    controlPlaneIdentitySha256,
    cumulativeCapUsd: 20,
    databaseIdentitySha256: "1".repeat(64),
    effectIdentitySha256,
    expectedPriorCumulativeSpendUsd: 0,
    globalKeySha256: sha256(Buffer.from(
      `prooftoact-provider-effect-v2\n${effectIdentitySha256}`, "utf8")),
    lane: "PREPARE",
    maximumConcurrency: 2,
    maximumRuns: 1,
    namespaceArn: TABLE_ARN,
    operationIdentitySha256: canonicalDigest({
      approvalId: APPROVAL_ID,
      approvalSha256,
      authorityContractSha256,
      controlPlaneIdentitySha256,
      effectIdentitySha256
    }),
    parameterManifestSha256: canonicalDigest(parameterBindings),
    providerMutationExpected: true,
    region: "us-east-1",
    resourceInventorySha256: canonicalDigest(createResourceInventory),
    stackName: "prooftoact-gate2",
    teardownContractSha256: "2".repeat(64),
    teardownReserveUsd: 1,
    templateSha256: templateDigest,
    workspaceRealpathSha256: "3".repeat(64)
  };
  const command = { ...commandBase,
    commandSha256: canonicalDigest(commandBase) };
  const consumption = {
    schemaVersion: "prooftoact.provider-global-approval-consumption.v1",
    status: "CONSUMED",
    approvalId: APPROVAL_ID,
    approvalSha256,
    budgetKeySha256: command.budgetKeySha256,
    budgetVersion: 1,
    commandSha256: command.commandSha256,
    consumedAt: new Date(NOW - 1000).toISOString(),
    cumulativeCapUsd: 20,
    durable: true,
    effectIdentitySha256,
    globalKeySha256: command.globalKeySha256,
    globallyAuthoritative: true,
    namespaceArn: TABLE_ARN,
    oneShot: true,
    priorCumulativeSpendUsd: 0,
    reservedSpendUsd: 0.25,
    resultingCumulativeSpendUsd: 0.25,
    storeRequestId: STORE_REQUEST_ID,
    stronglyConsistent: true,
    version: 1
  };
  const intent = {
    schemaVersion: "prooftoact.provider-global-dispatch-intent.v1",
    status: "DURABLE",
    action: command.action,
    approvalId: APPROVAL_ID,
    commandSha256: command.commandSha256,
    durable: true,
    event: "BEFORE_PROVIDER_DISPATCH",
    globalKeySha256: command.globalKeySha256,
    globallyAuthoritative: true,
    intentId: INTENT_ID,
    lane: "PREPARE",
    previousReceiptSha256: canonicalDigest(consumption),
    version: 2
  };
  const s = (value) => ({ S: value });
  const n = (value) => ({ N: String(value) });
  const b = (value) => ({ B: canonicalBytes(value) });
  const item = {
    approvalId: s(APPROVAL_ID),
    approvalSha256: s(approvalSha256),
    budgetKeySha256: s(command.budgetKeySha256),
    budgetVersion: n(1),
    command: b(command),
    commandSha256: s(command.commandSha256),
    consumption: b(consumption),
    consumptionSha256: s(canonicalDigest(consumption)),
    effectIdentitySha256: s(effectIdentitySha256),
    entity: s("EFFECT_V1"),
    globalKeySha256: s(command.globalKeySha256),
    intent: b(intent),
    intentSha256: s(canonicalDigest(intent)),
    namespaceArn: s(TABLE_ARN),
    pk: s(`EFFECT#${command.globalKeySha256}`),
    state: s("INTENT"),
    version: n(2)
  };
  const request = {
    schemaVersion: "prooftoact.prepare-provider-request.v1",
    accountId: ACCOUNT,
    artifactBucket: bucket,
    artifacts,
    capabilities: ["CAPABILITY_NAMED_IAM"],
    changeSetName: command.changeSetName,
    changeSetType: "CREATE",
    cloudFormationRoleArn:
      `arn:aws:iam::${ACCOUNT}:role/ProofToActGate2CloudFormation`,
    commandSha256: command.commandSha256,
    createResourceInventory,
    intentId: INTENT_ID,
    parameterBindings,
    region: "us-east-1",
    stackName: command.stackName,
    template
  };
  return { command, consumption, intent, item, request };
}

function dispatchInput(permit, request,
  authorityNotAfter = AUTHORITY_NOT_AFTER) {
  return { authorityNotAfter, permit, request };
}

function sequenceClock(values) {
  let index = 0;
  return () => values[Math.min(index++, values.length - 1)];
}

function testDispatcher(context, provider, clockValues) {
  context.mock.method(Date, "now", sequenceClock(clockValues));
  return createPrepareDispatcher({ transport: provider.dispatchTransport() });
}

function readerFor(input = fixture(), mutations = {}) {
  const responses = tableResponses();
  const expectedTableIdentity = attestReleaseControlTable(responses);
  const calls = [];
  const transport = {
    async describeTable(request) {
      calls.push(["describe", request]);
      return mutations.describeResponse ?? responses.describeResponse;
    },
    async getCallerIdentity() {
      calls.push(["identity"]);
      return mutations.caller ?? {
        Account: ACCOUNT,
        Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/` +
          "ProofToActReleaseDeployment/prepare-run",
        UserId: `AROA${"A".repeat(16)}:prepare-run`
      };
    },
    async getIntentItem(request) {
      calls.push(["get", request]);
      return {
        Item: mutations.item ?? input.item,
        $metadata: {
          requestId: "e23e4567-e89b-42d3-a456-42661417400e"
        }
      };
    },
    async listTags(request) {
      calls.push(["tags", request]);
      return mutations.listTagsResponse ?? responses.listTagsResponse;
    }
  };
  const reader = createPreparePermitReader({
    accountId: ACCOUNT, expectedTableIdentity, transport
  });
  return { calls, reader };
}

async function permitFor(input = fixture(), mutations = {}) {
  const { calls, reader } = readerFor(input, mutations);
  return {
    calls,
    reader,
    permit: await reader.readIntent({
      commandSha256: input.command.commandSha256,
      globalKeySha256: input.command.globalKeySha256,
      intentId: INTENT_ID
    })
  };
}

class FakePrepareProvider {
  constructor(input) {
    this.fixture = input;
    this.objects = new Map();
    this.putCalls = [];
    this.headCalls = [];
    this.getCalls = [];
    this.changeCalls = [];
    this.changeInput = null;
    this.ackLossKey = null;
    this.throwBeforeKey = null;
    this.changeAckLoss = false;
    this.parameterDrift = false;
    this.changeSetDescriptionDrift = false;
    this.originalTemplateDrift = false;
    this.describeStackResourcesCalls = [];
    this.getTemplateCalls = [];
  }

  objectKey(input) { return `${input.Bucket}/${input.Key}`; }

  async putObject(input) {
    this.putCalls.push(input);
    if (input.Key.includes(this.throwBeforeKey ?? "__never__")) {
      throw new Error("synthetic put before effect");
    }
    const key = this.objectKey(input);
    if (this.objects.has(key)) throw new Error("PreconditionFailed");
    const record = {
      body: Buffer.from(input.Body),
      checksum: input.ChecksumSHA256,
      contentLength: input.ContentLength,
      contentType: input.ContentType,
      metadata: structuredClone(input.Metadata),
      sse: input.ServerSideEncryption,
      versionId: `version-${this.objects.size + 1}`
    };
    this.objects.set(key, [record]);
    if (input.Key.includes(this.ackLossKey ?? "__never__")) {
      throw new Error("synthetic put acknowledgement loss");
    }
    return {
      ChecksumSHA256: record.checksum,
      ServerSideEncryption: record.sse,
      VersionId: record.versionId,
      $metadata: { requestId: `s3-put-${this.putCalls.length}` }
    };
  }

  record(input) {
    const versions = this.objects.get(this.objectKey(input));
    if (!versions) throw new Error("NoSuchKey");
    if (input.VersionId) {
      const match = versions.find((entry) =>
        entry.versionId === input.VersionId);
      if (!match) throw new Error("NoSuchVersion");
      return match;
    }
    return versions.at(-1);
  }

  async headObject(input) {
    this.headCalls.push(input);
    const value = this.record(input);
    return {
      ChecksumSHA256: value.checksum,
      ContentLength: value.contentLength,
      ContentType: value.contentType,
      ETag: '"exact"',
      Metadata: structuredClone(value.metadata),
      ServerSideEncryption: value.sse,
      VersionId: value.versionId
    };
  }

  async getObject(input) {
    this.getCalls.push(input);
    const value = this.record(input);
    return {
      Body: Buffer.from(value.body),
      ChecksumSHA256: value.checksum,
      ContentLength: value.contentLength,
      ContentType: value.contentType,
      Metadata: structuredClone(value.metadata),
      ServerSideEncryption: value.sse,
      VersionId: value.versionId
    };
  }

  async createChangeSet(input) {
    this.changeCalls.push(input);
    this.changeInput = structuredClone(input);
    if (this.changeAckLoss) throw new Error("synthetic create ack loss");
    return {
      Id: CHANGE_SET_ID,
      StackId: STACK_ID,
      $metadata: { requestId: "c23e4567-e89b-42d3-a456-42661417400c" }
    };
  }

  dispatchTransport() {
    return {
      createChangeSet: this.createChangeSet.bind(this),
      getObject: this.getObject.bind(this),
      headObject: this.headObject.bind(this),
      putObject: this.putObject.bind(this)
    };
  }

  readbackTransport() {
    return {
      describeChangeSet: async () => {
        const parameters = structuredClone(this.changeInput.Parameters);
        if (this.parameterDrift) parameters[0].ParameterValue = "drift";
        return {
          Capabilities: ["CAPABILITY_NAMED_IAM"],
          ChangeSetId: CHANGE_SET_ID,
          ChangeSetName: this.fixture.request.changeSetName,
          ChangeSetType: "CREATE",
          Changes: this.fixture.request.createResourceInventory.map((entry) => ({
            Type: "Resource",
            ResourceChange: {
              Action: "Add",
              LogicalResourceId: entry.logicalId,
              ResourceType: entry.type
            }
          })),
          Description: this.changeSetDescriptionDrift
            ? "drift" : this.changeInput.Description,
          ExecutionStatus: "AVAILABLE",
          IncludeNestedStacks: false,
          Parameters: parameters,
          RoleARN: this.fixture.request.cloudFormationRoleArn,
          StackId: STACK_ID,
          StackName: this.fixture.request.stackName,
          Status: "CREATE_COMPLETE",
          $metadata: { requestId: "d23e4567-e89b-42d3-a456-42661417400d" }
        };
      },
      describeStackEvents: async () => ({ StackEvents: [] }),
      describeStackResources: async (request) => {
        this.describeStackResourcesCalls.push(request);
        return { StackResources: [] };
      },
      describeStacks: async () => ({
        Stacks: [{
          EnableTerminationProtection: false,
          Parameters: structuredClone(this.changeInput.Parameters),
          StackId: STACK_ID,
          StackName: this.fixture.request.stackName,
          StackStatus: "REVIEW_IN_PROGRESS"
        }]
      }),
      getObject: this.getObject.bind(this),
      getTemplate: async (request) => {
        this.getTemplateCalls.push(request);
        return {
          StagesAvailable: ["Original", "Processed"],
          TemplateBody: this.originalTemplateDrift
            ? JSON.stringify({ AWSTemplateFormatVersion: "2010-09-09",
                Resources: {} })
            : this.fixture.request.template.body.toString("utf8"),
          $metadata: {
            requestId: "f23e4567-e89b-42d3-a456-42661417400f"
          }
        };
      },
      headObject: this.headObject.bind(this),
    };
  }

  overwrite(name) {
    const object = [...this.fixture.request.artifacts,
      this.fixture.request.template].find(({ descriptor }) =>
      descriptor.name === name);
    const key = `${object.descriptor.s3Bucket}/${object.descriptor.s3Key}`;
    const versions = this.objects.get(key);
    versions.push({
      ...versions.at(-1),
      body: Buffer.from("tampered", "utf8"),
      checksum: base64Sha256(Buffer.from("tampered", "utf8")),
      contentLength: 8,
      versionId: "version-tampered"
    });
  }
}

test("SDK configuration accepts only explicit ASIA credentials and fixes retry/endpoint policy", () => {
  const options = fixedSdkOptions(
    "https://s3.us-east-1.amazonaws.com", CREDENTIALS);
  assert.equal(options.maxAttempts, 1);
  assert.equal(options.ignoreConfiguredEndpointUrls, true);
  assert.throws(() => fixedSdkOptions(
    "https://s3.us-east-1.amazonaws.com",
    { ...CREDENTIALS, accessKeyId: `AKIA${"A".repeat(16)}` }
  ), /RELEASE_PROVIDER_EXPLICIT_CREDENTIALS_REJECTED/u);

});

test("provider canonicalization is byte-identical to the frozen application", () => {
  const value = {
    Zed: 1,
    alpha: [{ ParameterKey: "A", Source: "LITERAL", Value: "x" }],
    nested: { tree: APP_SOURCE.tree, Commit: APP_SOURCE.commit }
  };
  assert.equal(canonicalJson(value), applicationCanonicalJson(value));
});

test("permit reader attests exact live table and strongly decodes one immutable INTENT", async () => {
  const input = fixture();
  const { calls, permit, reader } = await permitFor(input);
  assert.deepEqual(Object.keys(reader), ["readIntent", "readStrong"]);
  assert.equal(permit.status, "EXACT_DURABLE_INTENT_CONFIRMED");
  assert.equal(permit.command.commandSha256, input.command.commandSha256);
  assert.equal(permit.intent.intentId, INTENT_ID);
  assert.match(permit.permitSha256, /^[0-9a-f]{64}$/u);
  const read = calls.find(([name]) => name === "get")[1];
  assert.equal(read.ConsistentRead, true);
  assert.deepEqual(read.Key,
    { pk: { S: `EFFECT#${input.command.globalKeySha256}` } });
});

test("permit reader rejects table recreation, KMS drift, role drift, and malformed item", async () => {
  const input = fixture();
  const changedTable = tableResponses().describeResponse;
  changedTable.Table.TableId = "823e4567-e89b-42d3-a456-426614174007";
  await assert.rejects(permitFor(input, { describeResponse: changedTable }),
    /RELEASE_PROVIDER_LIVE_TABLE_IDENTITY_REJECTED/u);

  const changedKms = tableResponses().describeResponse;
  changedKms.Table.SSEDescription.KMSMasterKeyArn =
    `arn:aws:kms:us-east-1:${ACCOUNT}:key/` +
    "923e4567-e89b-42d3-a456-426614174008";
  await assert.rejects(permitFor(input, { describeResponse: changedKms }),
    /RELEASE_PROVIDER_LIVE_TABLE_IDENTITY_REJECTED/u);

  await assert.rejects(permitFor(input, { caller: {
    Account: ACCOUNT,
    Arn: `arn:aws:sts::${ACCOUNT}:assumed-role/Administrator/prepare-run`,
    UserId: `AROA${"A".repeat(16)}:prepare-run`
  } }), /RELEASE_PROVIDER_CALLER_IDENTITY_REJECTED/u);

  await assert.rejects(permitFor(input, { caller: {
    Account: "222222222222",
    Arn: "arn:aws:sts::222222222222:assumed-role/" +
      "ProofToActReleaseDeployment/prepare-run",
    UserId: `AROA${"A".repeat(16)}:prepare-run`
  } }), /RELEASE_PROVIDER_CALLER_ACCOUNT_REJECTED/u);

  const malformed = structuredClone(input.item);
  malformed.intentSha256.S = "0".repeat(64);
  await assert.rejects(permitFor(input, { item: malformed }),
    /RELEASE_PROVIDER_GLOBAL_RECORD_ITEM_REJECTED/u);
});

test("broker-compatible readStrong returns the full canonical global record", async () => {
  const input = fixture();
  const { calls, reader } = readerFor(input);
  const record = await reader.readStrong({
    commandSha256: input.command.commandSha256,
    globalKeySha256: input.command.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  });
  assert.deepEqual(Object.keys(record), [
    "schemaVersion", "status", "command", "consumption", "intent", "terminal"
  ]);
  assert.equal(record.schemaVersion, "prooftoact.provider-global-record.v1");
  assert.equal(record.status, "INTENT");
  assert.equal(canonicalJson(record.command), canonicalJson(input.command));
  assert.equal(canonicalJson(record.consumption),
    canonicalJson(input.consumption));
  assert.equal(canonicalJson(record.intent), canonicalJson(input.intent));
  assert.equal(record.terminal, null);
  assert.equal(Object.isFrozen(record), true);
  assert.equal(Object.isFrozen(record.consumption), true);
  const read = calls.find(([name]) => name === "get")[1];
  assert.equal(read.ConsistentRead, true);
  assert.equal(typeof reader.consumeOnce, "undefined");
  assert.equal(typeof reader.appendIntent, "undefined");
  assert.equal(typeof reader.finalize, "undefined");
  await assert.rejects(reader.readStrong({
    commandSha256: input.command.commandSha256,
    globalKeySha256: input.command.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: false
  }), /RELEASE_PROVIDER_STRONG_READ_REQUEST_REJECTED/u);
});

test("readStrong validates consumed and terminal records without forging state", async () => {
  const input = fixture();
  const consumedItem = structuredClone(input.item);
  delete consumedItem.intent;
  delete consumedItem.intentSha256;
  consumedItem.state.S = "CONSUMED";
  consumedItem.version.N = "1";
  const consumedReader = readerFor(input, { item: consumedItem }).reader;
  const request = {
    commandSha256: input.command.commandSha256,
    globalKeySha256: input.command.globalKeySha256,
    namespaceArn: TABLE_ARN,
    stronglyConsistent: true
  };
  const consumed = await consumedReader.readStrong(request);
  assert.equal(consumed.status, "CONSUMED");
  assert.equal(consumed.intent, null);
  assert.equal(consumed.terminal, null);

  const outcome = {
    schemaVersion: "prooftoact.provider-dispatch-outcome.v1",
    status: "AMBIGUOUS",
    observedAt: new Date(NOW - 500).toISOString(),
    operationIdentitySha256: input.command.operationIdentitySha256,
    possibleMutation: true,
    providerReceiptSha256: "a".repeat(64),
    providerRequestId: null
  };
  const terminalBase = {
    schemaVersion: "prooftoact.provider-global-terminal-record.v1",
    status: "TERMINAL",
    approvalId: input.command.approvalId,
    commandSha256: input.command.commandSha256,
    durable: true,
    globalKeySha256: input.command.globalKeySha256,
    globallyAuthoritative: true,
    outcome,
    predecessorReceiptSha256: canonicalDigest(input.intent),
    predecessorState: "INTENT",
    recordedAt: new Date(NOW - 400).toISOString(),
    version: 3
  };
  const terminal = { ...terminalBase,
    terminalSha256: canonicalDigest(terminalBase) };
  const terminalItem = structuredClone(input.item);
  terminalItem.state.S = "TERMINAL";
  terminalItem.version.N = "3";
  terminalItem.terminal = { B: canonicalBytes(terminal) };
  terminalItem.terminalSha256 = { S: terminal.terminalSha256 };
  const terminalReader = readerFor(input, { item: terminalItem }).reader;
  const observed = await terminalReader.readStrong(request);
  assert.equal(observed.status, "TERMINAL");
  assert.equal(canonicalJson(observed.terminal), canonicalJson(terminal));

  const substituted = structuredClone(terminalItem);
  substituted.terminalSha256.S = "0".repeat(64);
  await assert.rejects(readerFor(input, { item: substituted }).reader
    .readStrong(request), /RELEASE_PROVIDER_GLOBAL_RECORD_ITEM_REJECTED/u);
});

test("dispatcher uploads six ZIPs and one exact template then creates one CREATE change set", async () => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  const result = await createPrepareDispatcher({
    transport: provider.dispatchTransport()
  }).dispatch(dispatchInput(permit, input.request));
  assert.equal(result.status,
    "CREATE_CHANGE_SET_ACKNOWLEDGED_READBACK_REQUIRED");
  assert.equal(result.accepted, false);
  assert.equal(result.retryAllowed, false);
  assert.equal(provider.putCalls.length, 7);
  assert.equal(provider.changeCalls.length, 1);
  assert.equal(provider.changeInput.ClientToken, INTENT_ID);
  assert.equal(provider.changeInput.ChangeSetType, "CREATE");
  assert.equal(provider.changeInput.Parameters.length, 45);
  assert.equal(provider.changeInput.RoleARN,
    input.request.cloudFormationRoleArn);
  assert.match(provider.changeInput.TemplateURL, /\?versionId=version-7$/u);
  assert.equal(Object.hasOwn(provider.dispatchTransport(),
    "executeChangeSet"), false);
});

test("conditional PUT acknowledgement loss converges only by exact readback", async () => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  provider.ackLossKey = "/agent-";
  const result = await createPrepareDispatcher({
    transport: provider.dispatchTransport()
  }).dispatch(dispatchInput(permit, input.request));
  assert.equal(result.status,
    "CREATE_CHANGE_SET_ACKNOWLEDGED_READBACK_REQUIRED");
  assert.equal(provider.putCalls.length, 7);
  assert.equal(provider.changeCalls.length, 1);
  assert.equal(result.uploaded[0].status, "PUT_ACK_UNKNOWN_EXACT_READBACK");
});

test("unresolved upload ambiguity stops all later mutation and never creates a change set", async () => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  provider.throwBeforeKey = "/agent-";
  const result = await createPrepareDispatcher({
    transport: provider.dispatchTransport()
  }).dispatch(dispatchInput(permit, input.request));
  assert.equal(result.status, "AMBIGUOUS_UPLOAD_STOPPED");
  assert.equal(provider.putCalls.length, 1);
  assert.equal(provider.changeCalls.length, 0);
  assert.equal(result.retryAllowed, false);
});

test("CreateChangeSet acknowledgement loss is one call, UNKNOWN, and never retried", async () => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  provider.changeAckLoss = true;
  const result = await createPrepareDispatcher({
    transport: provider.dispatchTransport()
  }).dispatch(dispatchInput(permit, input.request));
  assert.equal(result.status, "AMBIGUOUS_CREATE_CHANGE_SET_ACK");
  assert.equal(result.accepted, false);
  assert.equal(provider.changeCalls.length, 1);
  assert.equal(result.retryAllowed, false);
});

test("mutation authority expiry between uploads stops before the next write", async (context) => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  const authorityNotAfter = new Date(NOW + 60_000).toISOString();
  const result = await testDispatcher(context, provider, [NOW, NOW + 30_000])
    .dispatch(dispatchInput(permit, input.request, authorityNotAfter));
  assert.equal(result.status, "AUTHORITY_WINDOW_UPLOAD_STOPPED");
  assert.equal(result.reasonCode,
    "RELEASE_PROVIDER_MUTATION_AUTHORITY_WINDOW_REJECTED");
  assert.equal(result.authorityNotAfter, authorityNotAfter);
  assert.equal(provider.putCalls.length, 1);
  assert.equal(provider.changeCalls.length, 0);
  assert.equal(result.retryAllowed, false);
});

test("expiry after uploads prevents CreateChangeSet without a provider call", async (context) => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  const authorityNotAfter = new Date(NOW + 60_000).toISOString();
  const result = await testDispatcher(context, provider, [
    NOW, NOW, NOW, NOW, NOW, NOW, NOW, NOW + 30_000
  ]).dispatch(dispatchInput(permit, input.request, authorityNotAfter));
  assert.equal(result.status, "AUTHORITY_WINDOW_BEFORE_CHANGE_SET");
  assert.equal(result.changeSetCreateAttempted, false);
  assert.equal(provider.putCalls.length, 7);
  assert.equal(provider.changeCalls.length, 0);
  assert.equal(result.retryAllowed, false);
});

test("exact remaining-window boundary rejects before the first mutation", async (context) => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  const authorityNotAfter = new Date(NOW + 60_000).toISOString();
  const result = await testDispatcher(context, provider, [NOW + 30_000])
    .dispatch(dispatchInput(permit, input.request, authorityNotAfter));
  assert.equal(result.status, "AUTHORITY_WINDOW_UPLOAD_STOPPED");
  assert.equal(provider.putCalls.length, 0);
  assert.equal(provider.headCalls.length, 0);
  assert.equal(provider.getCalls.length, 0);
  assert.equal(provider.changeCalls.length, 0);
});

test("ACK-loss readback may finish after dispatch but expiry blocks later writes", async (context) => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  provider.ackLossKey = "/agent-";
  const authorityNotAfter = new Date(NOW + 60_000).toISOString();
  const result = await testDispatcher(context, provider, [NOW, NOW + 30_000])
    .dispatch(dispatchInput(permit, input.request, authorityNotAfter));
  assert.equal(result.status, "AUTHORITY_WINDOW_UPLOAD_STOPPED");
  assert.equal(result.uploaded.length, 1);
  assert.equal(result.uploaded[0].status,
    "PUT_ACK_UNKNOWN_EXACT_READBACK");
  assert.equal(provider.putCalls.length, 1);
  assert.equal(provider.headCalls.length, 1);
  assert.equal(provider.getCalls.length, 1);
  assert.equal(provider.changeCalls.length, 0);
  assert.equal(result.retryAllowed, false);
});

test("sealed production factories reject caller-supplied clocks", () => {
  const provider = new FakePrepareProvider(fixture());
  assert.throws(() => createPrepareDispatcher({
    clock: () => NOW,
    transport: provider.dispatchTransport()
  }), /RELEASE_PROVIDER_DISPATCH_CONFIGURATION_REJECTED/u);
  assert.throws(() => createPrepareReadback({
    clock: () => NOW,
    transport: provider.readbackTransport()
  }), /RELEASE_PROVIDER_READBACK_CONFIGURATION_REJECTED/u);
});

test("all request, artifact, template, parameter, and intent drift fails before mutation", async () => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const mutations = [
    (request) => { request.intentId = "923e4567-e89b-42d3-a456-426614174008"; },
    (request) => { request.artifacts[0].descriptor.sha256 = "0".repeat(64); },
    (request) => { request.template.descriptor.sha256 = "0".repeat(64); },
    (request) => { request.parameterBindings[0].Value = "drift"; },
    (request) => { request.region = "us-west-2"; }
  ];
  for (const mutate of mutations) {
    const request = structuredClone(input.request);
    mutate(request);
    const provider = new FakePrepareProvider(input);
    await assert.rejects(createPrepareDispatcher({
      transport: provider.dispatchTransport()
    }).dispatch(dispatchInput(permit, request)), /RELEASE_PROVIDER_/u);
    assert.equal(provider.putCalls.length, 0);
    assert.equal(provider.changeCalls.length, 0);
  }
});

test("independent readback confirms exact S3 versions and exact CREATE change set", async (context) => {
  const input = fixture();
  const { permit } = await permitFor(input);
  const provider = new FakePrepareProvider(input);
  await createPrepareDispatcher({ transport: provider.dispatchTransport() })
    .dispatch(dispatchInput(permit, input.request));
  context.mock.method(Date, "now", () => {
    assert.equal(provider.getTemplateCalls.length, 1);
    return NOW;
  });
  const readback = await createPrepareReadback({
    transport: provider.readbackTransport()
  }).readback({
    permit,
    readerPhaseRuntimeIdentitySha256: "4".repeat(64),
    request: input.request
  });
  assert.equal(readback.status, "CONFIRMED_APPLIED");
  assert.equal(readback.readOnly, true);
  assert.equal(readback.independentOfDispatcher, true);
  assert.equal(readback.preparedRelease.changeSetArn, CHANGE_SET_ID);
  assert.equal(readback.preparedRelease.stackId, STACK_ID);
  assert.match(readback.preparedRelease.changeSetSha256, /^[0-9a-f]{64}$/u);
  assert.deepEqual(provider.describeStackResourcesCalls,
    [{ StackName: STACK_ID }]);
  assert.deepEqual(provider.getTemplateCalls, [{
    ChangeSetName: CHANGE_SET_ID,
    StackName: STACK_ID,
    TemplateStage: "Original"
  }]);
});

test("readback rejects object, parameter, description, and original-template substitution", async () => {
  for (const mutate of [
    (provider) => provider.overwrite("agent"),
    (provider) => { provider.parameterDrift = true; },
    (provider) => { provider.changeSetDescriptionDrift = true; },
    (provider) => { provider.originalTemplateDrift = true; }
  ]) {
    const input = fixture();
    const { permit } = await permitFor(input);
    const provider = new FakePrepareProvider(input);
    await createPrepareDispatcher({ transport: provider.dispatchTransport() })
      .dispatch(dispatchInput(permit, input.request));
    mutate(provider);
    const readback = await createPrepareReadback({
      transport: provider.readbackTransport()
    }).readback({
      permit,
      readerPhaseRuntimeIdentitySha256: "4".repeat(64),
      request: input.request
    });
    assert.equal(readback.status, "UNKNOWN");
    assert.equal(readback.preparedRelease, null);
    assert.equal(readback.providerRequestId, null);
  }
});

test("readback rejects the ungranted ListStackResources API shape", () => {
  const provider = new FakePrepareProvider(fixture());
  const transport = provider.readbackTransport();
  transport.listStackResources = transport.describeStackResources;
  delete transport.describeStackResources;
  assert.throws(() => createPrepareReadback({ transport }),
    /RELEASE_PROVIDER_READBACK_TRANSPORT_REJECTED/u);
});

test("validated request binds all exact 45 parameters and seven object bodies", () => {
  const input = fixture();
  const accepted = validatePrepareRequest(input.request, input.command);
  assert.equal(accepted.parameterBindings.length, 45);
  assert.equal(accepted.artifacts.length, 6);
  assert.equal(accepted.template.descriptor.sha256,
    "a10066b23925cf2921b15eaa0d52e7ac8ef7a5f46e0ab260431a340e897cc3a1");
});
