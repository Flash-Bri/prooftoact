import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  signPrivateRecoveryDeploymentEvidence,
  validatePrivateRecoveryDeploymentSnapshot,
  validatePrivateRecoveryEvidenceExpectation,
  validateSignedPrivateRecoveryDeploymentEvidence
} from "../src/cloud/private-recovery-query-evidence.js";
import { __test as readbackTest } from
  "../scripts/readback-private-recovery-query.js";
import { buildPrivateRecoveryQueryTemplate } from
  "../src/cloud/private-recovery-query-template.js";

function fixture(phase = "PRE_QUERY") {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicSpki = publicKey.export({ format: "der", type: "spki" })
    .toString("base64");
  const receiptSha = phase === "POST_QUERY" ? "1".repeat(64) : null;
  const expectation = {
    schemaVersion: "prooftoact.private-recovery-query-evidence-expectation.v1",
    approvalSha256: "2".repeat(64),
    cloudFormationServiceRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryCloudFormation",
    codeSha256Base64: Buffer.alloc(32, 3).toString("base64"),
    codeZipSha256: "4".repeat(64),
    configSha256: "5".repeat(64),
    evidenceKeyId: "private-recovery-evidence-v1",
    evidencePublicKeySpkiBase64: publicSpki,
    evidenceRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryEvidence",
    expectedOperationReceiptSha256: receiptSha,
    functionArn:
      "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-private-recovery-query",
    functionVersion: "7",
    mcpSecretArnSha256: "6".repeat(64),
    mcpSecretVersionIdSha256: "7".repeat(64),
    operationGlobalKeySha256: "8".repeat(64),
    operatorRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryOperator",
    permissionsBoundaryArn:
      "arn:aws:iam::111111111111:policy/ProofToActPrivateRecoveryQueryBoundary",
    phase,
    preEvidenceReceiptSha256: phase === "POST_QUERY" ? "9".repeat(64) : null,
    releaseControlTableArn:
      "arn:aws:dynamodb:us-east-1:111111111111:table/prooftoact-release-controller",
    runtimeRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryRuntime",
    schemaVersion: "prooftoact.private-recovery-query-evidence-expectation.v1",
    sourceCommit: "a".repeat(40),
    stackName: "prooftoact-private-recovery-query",
    teardownRoleArn:
      "arn:aws:iam::111111111111:role/ProofToActPrivateRecoveryQueryTeardown",
    templateSha256: "b".repeat(64),
    treeDigest: "c".repeat(40),
    workflowCommit: "d".repeat(40)
  };
  const snapshot = {
    schemaVersion: "prooftoact.private-recovery-query-deployment-snapshot.v1",
    accountIdSha256: "d".repeat(64),
    callerArnSha256: "e".repeat(64),
    callerUserIdSha256: "f".repeat(64),
    function: {
      architectures: ["arm64"],
      codeSha256Base64: expectation.codeSha256Base64,
      configurationSha256: "1".repeat(64),
      eventSourceCount: 0,
      functionArnSha256: "2".repeat(64),
      functionPolicySha256: "3".repeat(64),
      functionUrlCount: 0,
      memorySize: 256,
      reservedConcurrency: 1,
      runtime: "nodejs22.x",
      tagsSha256: "4".repeat(64),
      timeout: 120,
      version: "7",
      vpcAttached: false
    },
    observedAt: "2026-08-19T02:15:00.000Z",
    operation: {
      receiptSha256: receiptSha,
      state: phase === "POST_QUERY" ? "FINAL" : "ABSENT"
    },
    phase,
    resourceInventorySha256: "5".repeat(64),
    rolePostureSha256: "6".repeat(64),
    secret: {
      arnSha256: expectation.mcpSecretArnSha256,
      currentVersion: true,
      rotationEnabled: false,
      versionIdSha256: expectation.mcpSecretVersionIdSha256
    },
    stackIdSha256: "7".repeat(64),
    stackParametersSha256: "8".repeat(64),
    stackStatus: "CREATE_COMPLETE",
    templateSha256: expectation.templateSha256,
    terminationProtection: true,
    workflowCommit: expectation.workflowCommit
  };
  return {
    expectation,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicSpki,
    snapshot
  };
}

test("signed pre-query deployment evidence binds private exact-version posture", () => {
  const value = fixture();
  validatePrivateRecoveryEvidenceExpectation(value.expectation);
  validatePrivateRecoveryDeploymentSnapshot(value.snapshot);
  const receipt = signPrivateRecoveryDeploymentEvidence(value);
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.phase, "PRE_QUERY");
  assert.equal(receipt.snapshot.function.functionUrlCount, 0);
  assert.equal(receipt.snapshot.function.eventSourceCount, 0);
  assert.equal(receipt.snapshot.function.vpcAttached, false);
  assert.deepEqual(validateSignedPrivateRecoveryDeploymentEvidence({
    publicKeySpkiBase64: value.publicSpki,
    receipt
  }), receipt);
  const serialized = canonicalJson(receipt);
  for (const forbidden of ["AKIA", "ASIA", "managed-mcp-A1b2C3", "VersionId"])
    assert.equal(serialized.includes(forbidden), false);
});

test("signed post-query evidence requires the exact terminal receipt and pre-link", () => {
  const value = fixture("POST_QUERY");
  const receipt = signPrivateRecoveryDeploymentEvidence(value);
  assert.equal(receipt.phase, "POST_QUERY");
  assert.equal(receipt.preEvidenceReceiptSha256,
    value.expectation.preEvidenceReceiptSha256);
  assert.equal(receipt.snapshot.operation.receiptSha256,
    value.expectation.expectedOperationReceiptSha256);
  assert.throws(() => signPrivateRecoveryDeploymentEvidence({
    ...value,
    snapshot: {
      ...value.snapshot,
      operation: { ...value.snapshot.operation, receiptSha256: "0".repeat(64) }
    }
  }), /PRIVATE_RECOVERY_QUERY_EVIDENCE_SIGNATURE_REJECTED/u);
});

test("evidence signature and public-trigger posture fail closed on tampering", () => {
  const value = fixture();
  const receipt = signPrivateRecoveryDeploymentEvidence(value);
  assert.throws(() => validateSignedPrivateRecoveryDeploymentEvidence({
    publicKeySpkiBase64: value.publicSpki,
    receipt: {
      ...receipt,
      snapshot: {
        ...receipt.snapshot,
        function: { ...receipt.snapshot.function, functionUrlCount: 1 }
      }
    }
  }), /PRIVATE_RECOVERY_QUERY_EVIDENCE_/u);
});

test("deployment evidence accepts only the exact one-version secret posture", () => {
  const secretArn =
    "arn:aws:secretsmanager:us-east-1:111111111111:secret:" +
    "prooftoact/private-recovery-query/managed-mcp-A1b2C3";
  const versionId = "v".repeat(32);
  const valid = {
    ARN: secretArn,
    RotationEnabled: false,
    VersionIdsToStages: { [versionId]: ["AWSCURRENT"] }
  };
  assert.deepEqual(readbackTest.validateSecretPosture(
    valid, secretArn, versionId
  ), {
    arnSha256: readbackTest.sha256(secretArn),
    currentVersion: true,
    rotationEnabled: false,
    versionIdSha256: readbackTest.sha256(versionId)
  });
  assert.throws(() => readbackTest.validateSecretPosture({
    ...valid,
    VersionIdsToStages: {
      [versionId]: ["AWSCURRENT"],
      ["w".repeat(32)]: ["AWSPREVIOUS"]
    }
  }, secretArn, versionId), /PRIVATE_RECOVERY_QUERY_EVIDENCE_SECRET_REJECTED/u);
});

test("deployment role readback decodes exact IAM policy shapes and rejects drift", async () => {
  const accountId = "111111111111";
  const arn = `arn:aws:iam::${accountId}:role/` +
    "ProofToActPrivateRecoveryQueryRuntime";
  const boundary = `arn:aws:iam::${accountId}:policy/` +
    "ProofToActPrivateRecoveryQueryBoundary";
  const resource = buildPrivateRecoveryQueryTemplate().Resources
    .PrivateRecoveryRuntimeRole;
  const context = {
    "AWS::AccountId": accountId,
    "AWS::Partition": "aws",
    "AWS::Region": "us-east-1",
    McpSecretArn: `arn:aws:secretsmanager:us-east-1:${accountId}:secret:` +
      "prooftoact/private-recovery-query/managed-mcp-A1b2C3",
    OperationGlobalKeySha256: "1".repeat(64),
    ReleaseControlTableArn: `arn:aws:dynamodb:us-east-1:${accountId}:table/` +
      "prooftoact-release-controller"
  };
  const expectedTrust = readbackTest.resolveTemplateValue(
    resource.Properties.AssumeRolePolicyDocument, context
  );
  const expectedPolicy = readbackTest.resolveTemplateValue(
    resource.Properties.Policies[0].PolicyDocument, context
  );
  const responses = ({
    boundaryType = "Policy",
    policyDocument = expectedPolicy,
    trustDocument = expectedTrust
  } = {}) => ({ send: async (command) => {
    switch (command.constructor.name) {
      case "GetRoleCommand": return { Role: {
        Arn: arn,
        AssumeRolePolicyDocument: trustDocument,
        Description: resource.Properties.Description,
        MaxSessionDuration: 3600,
        Path: "/",
        PermissionsBoundary: {
          PermissionsBoundaryArn: boundary,
          PermissionsBoundaryType: boundaryType
        },
        RoleId: "A".repeat(16)
      } };
      case "ListRolePoliciesCommand": return {
        IsTruncated: false,
        PolicyNames: ["ProofToActPrivateRecoveryQueryRuntimeOnly"]
      };
      case "ListAttachedRolePoliciesCommand": return {
        AttachedPolicies: [], IsTruncated: false
      };
      case "ListRoleTagsCommand": return {
        IsTruncated: false,
        Tags: resource.Properties.Tags
      };
      case "GetRolePolicyCommand": return {
        PolicyDocument: policyDocument,
        PolicyName: "ProofToActPrivateRecoveryQueryRuntimeOnly",
        RoleName: "ProofToActPrivateRecoveryQueryRuntime"
      };
      default: throw new Error("unexpected command");
    }
  } });
  await readbackTest.rolePosture(
    responses(),
    arn,
    "ProofToActPrivateRecoveryQueryRuntimeOnly",
    boundary,
    resource,
    context
  );
  await readbackTest.rolePosture(
    responses({
      policyDocument: JSON.stringify(expectedPolicy),
      trustDocument: JSON.stringify(expectedTrust)
    }),
    arn,
    "ProofToActPrivateRecoveryQueryRuntimeOnly",
    boundary,
    resource,
    context
  );
  await readbackTest.rolePosture(
    responses({
      policyDocument: encodeURIComponent(JSON.stringify(expectedPolicy)),
      trustDocument: encodeURIComponent(JSON.stringify(expectedTrust))
    }),
    arn,
    "ProofToActPrivateRecoveryQueryRuntimeOnly",
    boundary,
    resource,
    context
  );
  const scalarEquivalent = structuredClone(expectedPolicy);
  const first = scalarEquivalent.Statement.find(({ Action }) =>
    Array.isArray(Action) && Action.length === 1
  );
  if (first) first.Action = first.Action[0];
  await readbackTest.rolePosture(
    responses({ policyDocument: scalarEquivalent }),
    arn,
    "ProofToActPrivateRecoveryQueryRuntimeOnly",
    boundary,
    resource,
    context
  );
  const drifted = structuredClone(expectedPolicy);
  drifted.Statement[0].Action = "*";
  await assert.rejects(() => readbackTest.rolePosture(
    responses({ policyDocument: drifted }),
    arn,
    "ProofToActPrivateRecoveryQueryRuntimeOnly",
    boundary,
    resource,
    context
  ), /PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED/u);
  for (const rejected of [
    { policyDocument: "%E0%A4%A" },
    { policyDocument: "[]" },
    { policyDocument: "not-json" },
    { boundaryType: "PermissionsBoundaryPolicy" }
  ]) {
    await assert.rejects(() => readbackTest.rolePosture(
      responses(rejected),
      arn,
      "ProofToActPrivateRecoveryQueryRuntimeOnly",
      boundary,
      resource,
      context
    ), /PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED/u);
  }
});

test("IAM policy normalization is bounded to documented scalar-list fields", () => {
  const policy = {
    Version: "2012-10-17",
    Statement: {
      Effect: "Allow",
      Action: "lambda:GetFunction",
      Resource: ["arn:aws:lambda:us-east-1:111111111111:function:b",
        "arn:aws:lambda:us-east-1:111111111111:function:a"],
      Condition: {
        StringEquals: { "aws:RequestedRegion": "us-east-1" }
      }
    }
  };
  const normalized = readbackTest.normalizePolicyDocument(policy);
  assert.deepEqual(normalized.Statement[0].Action, ["lambda:GetFunction"]);
  assert.deepEqual(normalized.Statement[0].Resource, [
    "arn:aws:lambda:us-east-1:111111111111:function:a",
    "arn:aws:lambda:us-east-1:111111111111:function:b"
  ]);
  assert.throws(() => readbackTest.normalizePolicyDocument({
    ...policy,
    ArbitraryArray: ["b", "a"]
  }), /PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED/u);
});
