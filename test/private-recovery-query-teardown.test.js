import assert from "node:assert/strict";
import crypto, { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { signPrivateRecoveryDeploymentEvidence } from
  "../src/cloud/private-recovery-query-evidence.js";
import { __test as queryInternals } from
  "../src/cloud/private-recovery-query.js";
import {
  teardownPrivateRecoveryQuery,
  __test as teardownInternals
} from "../scripts/teardown-private-recovery-query.js";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function operationReceipt() {
  const body = {
    schemaVersion: "prooftoact.private-recovery-query-receipt.v1",
    status: "PASS",
    approvalSha256: "1".repeat(64),
    authorityTransferred: false,
    boundary: "RECOVERED_CONTEXT_ONLY",
    bundleDigest: "2".repeat(64),
    commandSha256: "3".repeat(64),
    completedAt: "2026-08-19T02:10:00.000Z",
    functionArnSha256: "4".repeat(64),
    functionVersion: "7",
    lambdaRequestIdSha256: "5".repeat(64),
    managedMcp: {
      closeHttpStatus: 204,
      endpointSha256: "6".repeat(64),
      notificationCount: 1,
      protocolVersion: "2025-03-26",
      rpcCallCount: 2,
      semanticEvidenceSha256: "7".repeat(64),
      sessionContinuous: true,
      toolCallCount: 1,
      transportEvidenceSha256: "8".repeat(64)
    },
    operationId: "99999999-9999-4999-8999-999999999999",
    providerBindingSha256: "a".repeat(64),
    publisherKeyIdSha256: "b".repeat(64),
    recoverySessionIdSha256: "c".repeat(64),
    requiresFreshAuthorization: true,
    signatureDigest: "d".repeat(64),
    sourceClusterIdSha256: "e".repeat(64),
    sourceClusterMappingReceiptSha256: "f".repeat(64),
    sourceCommit: "1".repeat(40),
    sourceCommitTs: "2026-08-19T02:00:00.000Z",
    sourceDigest: "2".repeat(64),
    sourceSqlClusterIdSha256: "3".repeat(64),
    subjectBindingSha256: "4".repeat(64),
    tenantIdSha256: "5".repeat(64),
    treeDigest: "6".repeat(40)
  };
  return { ...body, receiptSha256: queryInternals.digest(body) };
}

function signedPostEvidence(receipt, stackId) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicSpki = publicKey.export({ format: "der", type: "spki" })
    .toString("base64");
  const expectation = {
    schemaVersion: "prooftoact.private-recovery-query-evidence-expectation.v1",
    approvalSha256: receipt.approvalSha256,
    cloudFormationServiceRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation",
    codeSha256Base64: Buffer.alloc(32, 1).toString("base64"),
    codeZipSha256: "2".repeat(64),
    configSha256: "3".repeat(64),
    evidenceKeyId: "private-recovery-evidence-v1",
    evidencePublicKeySpkiBase64: publicSpki,
    evidenceRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryEvidence",
    expectedOperationReceiptSha256: receipt.receiptSha256,
    functionArn:
      "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-private-recovery-query",
    functionVersion: "7",
    mcpSecretArnSha256: "4".repeat(64),
    mcpSecretVersionIdSha256: "5".repeat(64),
    operationGlobalKeySha256: "6".repeat(64),
    operatorRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryOperator",
    permissionsBoundaryArn:
      "arn:aws:iam::111111111111:policy/ProofToActPrivateRecoveryQueryBoundary",
    phase: "POST_QUERY",
    preEvidenceReceiptSha256: "7".repeat(64),
    releaseControlTableArn:
      "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller",
    runtimeRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryRuntime",
    sourceCommit: receipt.sourceCommit,
    stackName: "prooftoact-private-recovery-query",
    teardownRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryTeardown",
    templateSha256: "8".repeat(64),
    treeDigest: receipt.treeDigest,
    workflowCommit: "d".repeat(40)
  };
  const snapshot = {
    schemaVersion: "prooftoact.private-recovery-query-deployment-snapshot.v1",
    accountIdSha256: "9".repeat(64),
    callerArnSha256: "a".repeat(64),
    callerUserIdSha256: "b".repeat(64),
    function: {
      architectures: ["arm64"],
      codeSha256Base64: expectation.codeSha256Base64,
      configurationSha256: "c".repeat(64),
      eventSourceCount: 0,
      functionArnSha256: "d".repeat(64),
      functionPolicySha256: "e".repeat(64),
      functionUrlCount: 0,
      memorySize: 256,
      reservedConcurrency: 1,
      runtime: "nodejs22.x",
      tagsSha256: "f".repeat(64),
      timeout: 120,
      version: "7",
      vpcAttached: false
    },
    observedAt: "2026-08-19T02:15:00.000Z",
    operation: { receiptSha256: receipt.receiptSha256, state: "FINAL" },
    phase: "POST_QUERY",
    resourceInventorySha256: "1".repeat(64),
    rolePostureSha256: "2".repeat(64),
    secret: {
      arnSha256: expectation.mcpSecretArnSha256,
      currentVersion: true,
      rotationEnabled: false,
      versionIdSha256: expectation.mcpSecretVersionIdSha256
    },
    stackIdSha256: sha256(stackId),
    stackParametersSha256: "8".repeat(64),
    stackStatus: "CREATE_COMPLETE",
    templateSha256: expectation.templateSha256,
    terminationProtection: true,
    workflowCommit: expectation.workflowCommit
  };
  return {
    publicSpki,
    receipt: signPrivateRecoveryDeploymentEvidence({
      expectation,
      privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
      snapshot
    })
  };
}

function teardownHarness({
  deleteAckLoss = false,
  evidenceStackId,
  initialStatus = "CREATE_COMPLETE",
  initiallyAbsent = false,
  protection = true,
  roleArn =
    "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation",
  stackId = "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
    "prooftoact-private-recovery-query/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  updateAckLoss = false
} = {}) {
  const operation = operationReceipt();
  const operationKey = "6".repeat(64);
  const evidence = signedPostEvidence(operation, evidenceStackId ?? stackId);
  let absent = initiallyAbsent;
  let status = initialStatus;
  let enabled = protection;
  let updateLost = updateAckLoss;
  let deleteLost = deleteAckLoss;
  const calls = [];
  const cloudformation = { async send(command) {
    const name = command.constructor.name;
    calls.push(name);
    if (name === "UpdateTerminationProtectionCommand") {
      enabled = command.input.EnableTerminationProtection;
      if (updateLost) {
        updateLost = false;
        throw new Error("synthetic update acknowledgement loss");
      }
      return {};
    }
    if (name === "DeleteStackCommand") {
      status = "DELETE_IN_PROGRESS";
      if (deleteLost) {
        deleteLost = false;
        throw new Error("synthetic delete acknowledgement loss");
      }
      return {};
    }
    if (name === "DescribeStacksCommand") {
      if (absent) {
        const error = new Error(`Stack with id ${stackId} does not exist`);
        error.name = "ValidationError";
        throw error;
      }
      return { Stacks: [{
        EnableTerminationProtection: enabled,
        RoleARN: roleArn,
        StackId: stackId,
        StackName: "prooftoact-private-recovery-query",
        StackStatus: status
      }] };
    }
    throw new Error(`unexpected ${name}`);
  } };
  let clock = 0;
  return {
    calls,
    completeDeletion() { absent = true; },
    get protection() { return enabled; },
    operation,
    options: {
      clients: {
        cloudformation,
        dynamodb: { async send() {
          return { Item: {
            pk: { S: `PRIVATE_RECOVERY_QUERY#${operationKey}` },
            receipt: { B: Buffer.from(canonicalJson(operation), "utf8") },
            status: { S: "FINAL" },
            version: { N: "2" }
          } };
        } },
        sts: { async send() {
          return {
            Account: "111111111111",
            Arn: "arn:aws:sts::111111111111:assumed-role/" +
              "ProofToActPrivateRecoveryQueryTeardown/synthetic-session",
            UserId: "AROASYNTHETIC:synthetic-session"
          };
        } }
      },
      clock: () => new Date(Date.parse("2026-08-19T02:16:00.000Z") +
        clock++ * 1_000),
      cloudFormationServiceRoleArn:
        "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation",
      confirmation: teardownInternals.CONFIRMATION,
      maximumPollAttempts: 2,
      operationGlobalKeySha256: operationKey,
      postEvidenceReceipt: evidence.receipt,
      publicKeySpkiBase64: evidence.publicSpki,
      wait: async () => {}
    }
  };
}

test("governed teardown verifies POST evidence and deletes one exact stack once", async () => {
  const operation = operationReceipt();
  const operationKey = "6".repeat(64);
  const stackId =
    "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
    "prooftoact-private-recovery-query/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const evidence = signedPostEvidence(operation, stackId);
  let protection = true;
  let deleted = false;
  const calls = [];
  const cloudformation = {
    async send(command) {
      const name = command.constructor.name;
      calls.push(name);
      if (name === "UpdateTerminationProtectionCommand") {
        protection = false;
        return {};
      }
      if (name === "DeleteStackCommand") {
        deleted = true;
        return {};
      }
      if (name === "DescribeStacksCommand") {
        if (deleted) {
          const error = new Error(`Stack with id ${stackId} does not exist`);
          error.name = "ValidationError";
          throw error;
        }
        return { Stacks: [{
          StackId: stackId,
          StackName: "prooftoact-private-recovery-query",
          StackStatus: "CREATE_COMPLETE",
          EnableTerminationProtection: protection,
          RoleARN:
            "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation"
        }] };
      }
      throw new Error(`unexpected ${name}`);
    }
  };
  const clocks = [
    new Date("2026-08-19T02:16:00.000Z"),
    new Date("2026-08-19T02:16:01.000Z")
  ];
  const result = await teardownPrivateRecoveryQuery({
    clients: {
      cloudformation,
      dynamodb: { async send() {
        return { Item: {
          pk: { S: `PRIVATE_RECOVERY_QUERY#${operationKey}` },
          receipt: { B: Buffer.from(canonicalJson(operation), "utf8") },
          status: { S: "FINAL" },
          version: { N: "2" }
        } };
      } },
      sts: { async send() {
        return {
          Account: "111111111111",
          Arn: "arn:aws:sts::111111111111:assumed-role/" +
            "ProofToActPrivateRecoveryQueryTeardown/synthetic-session",
          UserId: "AROASYNTHETIC:synthetic-session"
        };
      } }
    },
    clock: () => clocks.shift(),
    cloudFormationServiceRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation",
    confirmation: teardownInternals.CONFIRMATION,
    operationGlobalKeySha256: operationKey,
    postEvidenceReceipt: evidence.receipt,
    publicKeySpkiBase64: evidence.publicSpki,
    wait: async () => {}
  });
  assert.equal(result.status, "STACK_ABSENT");
  assert.equal(result.operationReceiptSha256, operation.receiptSha256);
  assert.equal(calls.filter((name) => name === "DeleteStackCommand").length, 1);
  assert.equal(calls.filter((name) =>
    name === "UpdateTerminationProtectionCommand").length, 1);
});

test("teardown rejects wrong confirmation before any provider read", async () => {
  let calls = 0;
  await assert.rejects(() => teardownPrivateRecoveryQuery({
    clients: { cloudformation: {}, dynamodb: {}, sts: {} },
    cloudFormationServiceRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation",
    confirmation: "DELETE_SOMETHING_ELSE",
    operationGlobalKeySha256: "6".repeat(64),
    postEvidenceReceipt: {},
    publicKeySpkiBase64: "invalid",
    wait: async () => { calls += 1; }
  }), /PRIVATE_RECOVERY_QUERY_TEARDOWN_INPUT_REJECTED/u);
  assert.equal(calls, 0);
});

test("teardown restarts after protection was already disabled", async () => {
  const harness = teardownHarness({ protection: false });
  const promise = teardownPrivateRecoveryQuery({
    ...harness.options,
    wait: async () => harness.completeDeletion()
  });
  const receipt = await promise;
  assert.equal(receipt.status, "STACK_ABSENT");
  assert.equal(harness.calls.filter((name) =>
    name === "UpdateTerminationProtectionCommand").length, 0);
  assert.equal(harness.calls.filter((name) =>
    name === "DeleteStackCommand").length, 1);
});

test("teardown resumes DELETE_IN_PROGRESS without another mutation", async () => {
  const harness = teardownHarness({
    initialStatus: "DELETE_IN_PROGRESS",
    protection: false
  });
  const receipt = await teardownPrivateRecoveryQuery({
    ...harness.options,
    wait: async () => harness.completeDeletion()
  });
  assert.equal(receipt.status, "STACK_ABSENT");
  assert.equal(harness.calls.some((name) =>
    ["UpdateTerminationProtectionCommand", "DeleteStackCommand"].includes(name)),
  false);
});

test("teardown treats an already absent exact evidenced stack as success", async () => {
  const harness = teardownHarness({ initiallyAbsent: true });
  const receipt = await teardownPrivateRecoveryQuery(harness.options);
  assert.equal(receipt.status, "STACK_ABSENT");
  assert.equal(harness.calls.filter((name) =>
    name === "DescribeStacksCommand").length, 1);
});

for (const [label, options] of [
  ["termination-protection", { updateAckLoss: true }],
  ["delete", { deleteAckLoss: true }]
]) {
  test(`teardown reconciles ${label} acknowledgement loss`, async () => {
    const harness = teardownHarness(options);
    const receipt = await teardownPrivateRecoveryQuery({
      ...harness.options,
      wait: async () => harness.completeDeletion()
    });
    assert.equal(receipt.status, "STACK_ABSENT");
    assert.equal(harness.calls.filter((name) =>
      name === "DeleteStackCommand").length, 1);
  });
}

test("teardown timeout preserves DELETE_IN_PROGRESS for a later successful rerun", async () => {
  const harness = teardownHarness({
    initialStatus: "DELETE_IN_PROGRESS",
    protection: false
  });
  await assert.rejects(() => teardownPrivateRecoveryQuery({
    ...harness.options,
    maximumPollAttempts: 1
  }), /PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_TIMEOUT/u);
  harness.completeDeletion();
  const receipt = await teardownPrivateRecoveryQuery(harness.options);
  assert.equal(receipt.status, "STACK_ABSENT");
});

test("teardown rejects replacement identity or service-role drift", async () => {
  for (const options of [
    { stackId: "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
      "prooftoact-private-recovery-query/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      evidenceStackId:
        "arn:aws:cloudformation:us-east-1:111111111111:stack/" +
        "prooftoact-private-recovery-query/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
    { roleArn: "arn:aws:iam::111111111111:role/UnexpectedRole" }
  ]) {
    const harness = teardownHarness(options);
    await assert.rejects(() => teardownPrivateRecoveryQuery(harness.options),
      /PRIVATE_RECOVERY_QUERY_TEARDOWN_STACK_REJECTED/u);
  }
});

test("DELETE_FAILED is re-protected and held without a delete retry", async () => {
  const harness = teardownHarness({
    initialStatus: "DELETE_FAILED",
    protection: false
  });
  await assert.rejects(() => teardownPrivateRecoveryQuery(harness.options),
    /PRIVATE_RECOVERY_QUERY_TEARDOWN_DELETE_FAILED_HOLD/u);
  assert.equal(harness.protection, true);
  assert.equal(harness.calls.filter((name) =>
    name === "UpdateTerminationProtectionCommand").length, 1);
  assert.equal(harness.calls.filter((name) =>
    name === "DeleteStackCommand").length, 0);
});
