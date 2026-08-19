import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  sealPrivateRecoveryQuerySecret,
  __test as sealInternals
} from "../scripts/seal-private-recovery-query-secret.js";

const SOURCE_ARN =
  "arn:aws:secretsmanager:us-east-1:111111111111:secret:" +
  "prooftoact/gate2/managed-mcp-Ab12Cd";
const TARGET_ARN =
  "arn:aws:secretsmanager:us-east-1:111111111111:secret:" +
  "prooftoact/private-recovery-query/managed-mcp-Ef34Gh";
const SOURCE_VERSION = "s".repeat(32);
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const API_KEY = "managed-mcp-provider-key-for-private-copy";
const CREATED_AT = new Date("2026-08-19T02:00:00.000Z");
const OBSERVED_AT = new Date("2026-08-19T02:00:01.000Z");

function mockClients({ acknowledgementLoss = false, targetVersions = [] } = {}) {
  let targetValue = null;
  let versions = structuredClone(targetVersions);
  const calls = [];
  const secrets = {
    async send(command) {
      const name = command.constructor.name;
      const input = command.input;
      calls.push({ input, name });
      if (name === "DescribeSecretCommand") {
        const source = input.SecretId === SOURCE_ARN;
        return {
          ARN: source ? SOURCE_ARN : TARGET_ARN,
          Name: source
            ? "prooftoact/gate2/managed-mcp"
            : "prooftoact/private-recovery-query/managed-mcp",
          RotationEnabled: false
        };
      }
      if (name === "ListSecretVersionIdsCommand") {
        if (input.SecretId === SOURCE_ARN) {
          return {
            Versions: [{
              CreatedDate: new Date("2026-08-19T01:55:00.000Z"),
              VersionId: SOURCE_VERSION,
              VersionStages: ["AWSCURRENT"]
            }]
          };
        }
        return { Versions: structuredClone(versions) };
      }
      if (name === "GetSecretValueCommand") {
        if (input.SecretId === SOURCE_ARN) {
          return {
            ARN: SOURCE_ARN,
            CreatedDate: new Date("2026-08-19T01:55:00.000Z"),
            Name: "prooftoact/gate2/managed-mcp",
            SecretString: API_KEY,
            VersionId: SOURCE_VERSION,
            VersionStages: ["AWSCURRENT"]
          };
        }
        if (targetValue === null) throw new Error("target version absent");
        return {
          ARN: TARGET_ARN,
          CreatedDate: CREATED_AT,
          Name: "prooftoact/private-recovery-query/managed-mcp",
          SecretString: targetValue,
          VersionId: input.VersionId,
          VersionStages: ["AWSCURRENT"]
        };
      }
      if (name === "PutSecretValueCommand") {
        assert.equal(input.SecretId, TARGET_ARN);
        assert.deepEqual(input.VersionStages, ["AWSCURRENT"]);
        assert.equal(input.SecretString, canonicalJson({ apiKey: API_KEY }));
        targetValue = input.SecretString;
        versions = [{
          CreatedDate: CREATED_AT,
          VersionId: input.ClientRequestToken,
          VersionStages: ["AWSCURRENT"]
        }];
        if (acknowledgementLoss) {
          acknowledgementLoss = false;
          throw new Error("synthetic acknowledgement loss");
        }
        return {
          ARN: TARGET_ARN,
          Name: "prooftoact/private-recovery-query/managed-mcp",
          VersionId: input.ClientRequestToken,
          VersionStages: ["AWSCURRENT"]
        };
      }
      throw new Error(`unexpected ${name}`);
    }
  };
  if (versions.length === 1 && versions[0].SecretString) {
    targetValue = versions[0].SecretString;
    versions = versions.map(({ SecretString, ...version }) => version);
  }
  return {
    calls,
    clients: {
      secrets,
      sts: {
        async send(command) {
          calls.push({ input: command.input, name: command.constructor.name });
          return {
            Account: "111111111111",
            Arn: "arn:aws:sts::111111111111:assumed-role/" +
              "ProofToActPrivateRecoveryQuerySecretSealer/synthetic-session",
            UserId: "AROASYNTHETICID:synthetic-session"
          };
        }
      }
    }
  };
}

function input(clients) {
  const approvalBody = {
    schemaVersion: sealInternals.SEAL_APPROVAL_SCHEMA,
    status: "APPROVED_EXACT_SHARED_READ_ONLY_CREDENTIAL_COPY",
    approvedAt: "2026-08-19T01:59:00.000Z",
    credentialSharingBoundary: sealInternals.SHARING_BOUNDARY,
    expiresAt: "2026-08-19T03:00:00.000Z",
    operatorAuthorizationSha256: "1".repeat(64),
    sourceCommit: SOURCE_COMMIT,
    sourceSecretArnSha256: sealInternals.sha256(SOURCE_ARN),
    sourceSecretVersionIdSha256: sealInternals.sha256(SOURCE_VERSION),
    targetSecretArnSha256: sealInternals.sha256(TARGET_ARN),
    treeDigest: TREE_DIGEST
  };
  return {
    approval: {
      ...approvalBody,
      approvalSha256: sealInternals.lineDigest(approvalBody)
    },
    clients,
    clock: () => OBSERVED_AT,
    sourceCommit: SOURCE_COMMIT,
    sourceSecretArn: SOURCE_ARN,
    sourceSecretVersionId: SOURCE_VERSION,
    targetSecretArn: TARGET_ARN,
    treeDigest: TREE_DIGEST
  };
}

test("secret sealer copies one exact source key into one canonical target version", async () => {
  const mock = mockClients();
  const sealed = await sealPrivateRecoveryQuerySecret(input(mock.clients));
  assert.equal(sealed.receipt.status, "PASS");
  assert.equal(sealed.receipt.disposition, "SEALED");
  assert.equal(sealed.binding.status, "IMMUTABLE_AWSCURRENT_READBACK_BOUND");
  assert.equal(sealed.binding.mcpSecretValueSha256,
    sealInternals.sha256(canonicalJson({ apiKey: API_KEY })));
  assert.equal(sealed.binding.sourceSecretValueSha256,
    sealInternals.sha256(API_KEY));
  assert.equal(mock.calls.filter(({ name }) =>
    name === "PutSecretValueCommand").length, 1);
});

test("secret sealer reconciles PutSecretValue acknowledgement loss without retry", async () => {
  const mock = mockClients({ acknowledgementLoss: true });
  const first = await sealPrivateRecoveryQuerySecret(input(mock.clients));
  assert.equal(first.receipt.disposition, "RECONCILED_AFTER_ACK_LOSS");
  assert.equal(mock.calls.filter(({ name }) =>
    name === "PutSecretValueCommand").length, 1);
  const second = await sealPrivateRecoveryQuerySecret(input(mock.clients));
  assert.equal(second.receipt.disposition, "EXACT_VERSION_ALREADY_PRESENT");
  assert.equal(second.binding.bindingSha256, first.binding.bindingSha256);
  assert.equal(mock.calls.filter(({ name }) =>
    name === "PutSecretValueCommand").length, 1);
});

test("secret sealer rejects any unexpected target version before writing", async () => {
  const mock = mockClients({
    targetVersions: [{
      CreatedDate: CREATED_AT,
      SecretString: canonicalJson({ apiKey: API_KEY }),
      VersionId: "x".repeat(64),
      VersionStages: ["AWSCURRENT"]
    }]
  });
  await assert.rejects(
    () => sealPrivateRecoveryQuerySecret(input(mock.clients)),
    /PRIVATE_RECOVERY_QUERY_SECRET_SEAL_REJECTED/u
  );
  assert.equal(mock.calls.some(({ name }) => name === "PutSecretValueCommand"),
    false);
});

test("secret sealer rejects missing operator authorization before provider read", async () => {
  const mock = mockClients();
  const value = input(mock.clients);
  value.approval = {
    ...value.approval,
    operatorAuthorizationSha256: "0".repeat(64)
  };
  await assert.rejects(
    () => sealPrivateRecoveryQuerySecret(value),
    /PRIVATE_RECOVERY_QUERY_SECRET_SEAL_APPROVAL_REJECTED/u
  );
  assert.equal(mock.calls.length, 0);
});
