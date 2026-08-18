import crypto from "node:crypto";

import { canonicalJson } from "../../src/cloud/canonical-json.js";

const TABLE_NAME = "prooftoact-release-controller";
const REGION = "us-east-1";
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const REQUIRED_TAGS = Object.freeze([
  Object.freeze({ Key: "Project", Value: "ProofToAct" }),
  Object.freeze({ Key: "Purpose", Value: "RetainedReleaseControl" }),
  Object.freeze({
    Key: "Retention",
    Value: "IntentionalOutsideApplicationTeardown"
  })
]);

function reject(code) {
  throw new Error(code);
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

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function exactArray(value, expected, code) {
  requireCondition(Array.isArray(value) &&
    canonicalJson(value) === canonicalJson(expected), code);
  return value;
}

function normalizedTags(value, code) {
  requireCondition(Array.isArray(value) && value.length >= REQUIRED_TAGS.length,
    code);
  const tags = value.map((tag) => {
    requireCondition(plainObject(tag) && Object.keys(tag).sort().join("\n") ===
      "Key\nValue" && typeof tag.Key === "string" && tag.Key.length > 0 &&
      tag.Key.length <= 128 && typeof tag.Value === "string" &&
      tag.Value.length <= 256, code);
    return { Key: tag.Key, Value: tag.Value };
  }).sort((left, right) => left.Key.localeCompare(right.Key) ||
    left.Value.localeCompare(right.Value));
  requireCondition(new Set(tags.map(({ Key }) => Key)).size === tags.length, code);
  for (const required of REQUIRED_TAGS) {
    requireCondition(tags.some((tag) => canonicalJson(tag) ===
      canonicalJson(required)), code);
  }
  return Object.freeze(tags.map((tag) => Object.freeze(tag)));
}

export function attestReleaseControlTable({
  describeResponse,
  expectedAccountId,
  listTagsResponse,
  region = REGION
}) {
  const code = "RELEASE_CONTROL_TABLE_IDENTITY_REJECTED";
  requireCondition(plainObject(describeResponse) &&
    plainObject(describeResponse.Table) && plainObject(listTagsResponse) &&
    ACCOUNT_ID.test(expectedAccountId ?? "") && region === REGION, code);
  const table = describeResponse.Table;
  const namespaceArn =
    `arn:aws:dynamodb:${REGION}:${expectedAccountId}:table/${TABLE_NAME}`;
  requireCondition(table.TableName === TABLE_NAME &&
    table.TableArn === namespaceArn && UUID.test(table.TableId ?? "") &&
    table.TableStatus === "ACTIVE" &&
    table.DeletionProtectionEnabled === true &&
    table.BillingModeSummary?.BillingMode === "PAY_PER_REQUEST" &&
    table.SSEDescription?.Status === "ENABLED" &&
    table.SSEDescription?.SSEType === "KMS" &&
    new RegExp(`^arn:aws:kms:${REGION}:${expectedAccountId}:key/` +
      "[0-9a-f-]{36}$", "u").test(
      table.SSEDescription?.KMSMasterKeyArn ?? ""
    ) &&
    table.LatestStreamArn === undefined &&
    table.StreamSpecification === undefined &&
    table.GlobalSecondaryIndexes === undefined &&
    table.LocalSecondaryIndexes === undefined &&
    table.Replicas === undefined, code);
  const attributeDefinitions = exactArray(table.AttributeDefinitions, [
    { AttributeName: "pk", AttributeType: "S" }
  ], code);
  const keySchema = exactArray(table.KeySchema, [
    { AttributeName: "pk", KeyType: "HASH" }
  ], code);
  requireCondition(listTagsResponse.NextToken === undefined, code);
  const tags = normalizedTags(listTagsResponse.Tags, code);
  const identity = Object.freeze({
    attributeDefinitionsSha256: digest(attributeDefinitions),
    billingMode: "PAY_PER_REQUEST",
    deletionProtectionEnabled: true,
    encryptionStatus: "ENABLED",
    keySchemaSha256: digest(keySchema),
    kmsKeyArnSha256: digest(table.SSEDescription.KMSMasterKeyArn),
    namespaceArn,
    region,
    sseType: "KMS",
    tableId: table.TableId,
    tagsSha256: digest(tags)
  });
  return Object.freeze({
    atomicConditionalConsumeRequired: true,
    durableJournalRequired: true,
    strongReadRequired: true,
    ...identity,
    tableIdentitySha256: digest(identity)
  });
}

export const releaseControlTableIdentityConstants = Object.freeze({
  REGION,
  REQUIRED_TAGS,
  TABLE_NAME
});

export const __test = Object.freeze({ digest, normalizedTags });
