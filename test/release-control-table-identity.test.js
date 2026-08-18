import assert from "node:assert/strict";
import test from "node:test";

import {
  attestReleaseControlTable,
  releaseControlTableIdentityConstants as constants
} from "../scripts/lib/release-control-table-identity.js";

const ACCOUNT_ID = "111111111111";
const TABLE_ID = "123e4567-e89b-42d3-a456-426614174000";

function response() {
  return {
    describeResponse: {
      Table: {
        AttributeDefinitions: [
          { AttributeName: "pk", AttributeType: "S" }
        ],
        BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" },
        DeletionProtectionEnabled: true,
        ItemCount: 0,
        KeySchema: [
          { AttributeName: "pk", KeyType: "HASH" }
        ],
        SSEDescription: {
          KMSMasterKeyArn:
            `arn:aws:kms:us-east-1:${ACCOUNT_ID}:key/` +
            "223e4567-e89b-42d3-a456-426614174001",
          SSEType: "KMS",
          Status: "ENABLED"
        },
        TableArn:
          `arn:aws:dynamodb:us-east-1:${ACCOUNT_ID}:table/` +
          constants.TABLE_NAME,
        TableId: TABLE_ID,
        TableName: constants.TABLE_NAME,
        TableSizeBytes: 0,
        TableStatus: "ACTIVE"
      }
    },
    expectedAccountId: ACCOUNT_ID,
    listTagsResponse: {
      Tags: [
        { Key: "Retention", Value: "IntentionalOutsideApplicationTeardown" },
        { Key: "Project", Value: "ProofToAct" },
        { Key: "Purpose", Value: "RetainedReleaseControl" }
      ]
    },
    region: "us-east-1"
  };
}

test("attests immutable table identity and reviewed control shape", () => {
  const first = attestReleaseControlTable(response());
  const reordered = response();
  reordered.listTagsResponse.Tags.reverse();
  const second = attestReleaseControlTable(reordered);
  assert.deepEqual(first, second);
  assert.equal(first.namespaceArn,
    `arn:aws:dynamodb:us-east-1:${ACCOUNT_ID}:table/` + constants.TABLE_NAME);
  assert.equal(first.tableId, TABLE_ID);
  assert.equal(first.billingMode, "PAY_PER_REQUEST");
  assert.equal(first.deletionProtectionEnabled, true);
  assert.equal(first.encryptionStatus, "ENABLED");
  assert.equal(first.sseType, "KMS");
  assert.match(first.kmsKeyArnSha256, /^[0-9a-f]{64}$/u);
  assert.match(first.tableIdentitySha256, /^[0-9a-f]{64}$/u);
});

test("delete/recreate, schema, billing, encryption, stream, and tag drift reject", () => {
  const mutations = [
    (input) => { input.describeResponse.Table.TableId = "invalid"; },
    (input) => { input.describeResponse.Table.TableArn += "-other"; },
    (input) => { input.describeResponse.Table.TableStatus = "CREATING"; },
    (input) => { input.describeResponse.Table.DeletionProtectionEnabled = false; },
    (input) => {
      input.describeResponse.Table.BillingModeSummary.BillingMode = "PROVISIONED";
    },
    (input) => { input.describeResponse.Table.SSEDescription.Status = "DISABLED"; },
    (input) => { input.describeResponse.Table.KeySchema[0].KeyType = "RANGE"; },
    (input) => { input.describeResponse.Table.AttributeDefinitions[0]
      .AttributeType = "N"; },
    (input) => { input.describeResponse.Table.StreamSpecification = {
      StreamEnabled: true
    }; },
    (input) => { input.listTagsResponse.Tags.pop(); },
    (input) => { input.listTagsResponse.NextToken = "unexpected"; }
  ];
  for (const mutate of mutations) {
    const input = response();
    mutate(input);
    assert.throws(() => attestReleaseControlTable(input),
      /RELEASE_CONTROL_TABLE_IDENTITY_REJECTED/u);
  }
});

test("extra tags are retained in the immutable identity digest", () => {
  const baseline = attestReleaseControlTable(response());
  const changed = response();
  changed.listTagsResponse.Tags.push({ Key: "Owner", Value: "ReleaseTeam" });
  const attested = attestReleaseControlTable(changed);
  assert.notEqual(attested.tagsSha256, baseline.tagsSha256);
  assert.notEqual(attested.tableIdentitySha256, baseline.tableIdentitySha256);
});

test("a different valid KMS key changes the immutable table identity", () => {
  const baseline = attestReleaseControlTable(response());
  const changed = response();
  changed.describeResponse.Table.SSEDescription.KMSMasterKeyArn =
    `arn:aws:kms:us-east-1:${ACCOUNT_ID}:key/` +
    "323e4567-e89b-42d3-a456-426614174002";
  const attested = attestReleaseControlTable(changed);
  assert.notEqual(attested.kmsKeyArnSha256, baseline.kmsKeyArnSha256);
  assert.notEqual(attested.tableIdentitySha256, baseline.tableIdentitySha256);
});
