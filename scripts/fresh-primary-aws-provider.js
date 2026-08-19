import crypto from "node:crypto";

import {
  validateFreshRecoveryPublisherSecret
} from "./lib/fresh-recovery-publisher-key.js";

const TABLE_NAME = "prooftoact-release-controller";
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ASSUMED_ROLE_ARN =
  /^arn:aws:sts::([0-9]{12}):assumed-role\/ProofToActFreshPrimaryBootstrap\/([A-Za-z0-9+=,.@_-]{2,64})$/u;
const ASSUMED_ROLE_USER_ID =
  /^(AROA[A-Z0-9]{16}):([A-Za-z0-9+=,.@_-]{2,64})$/u;
const MAX_CANONICAL_BYTES = 128 * 1024;
const REQUIRED_TABLE_TAGS = Object.freeze({
  Project: "ProofToAct",
  Purpose: "RetainedReleaseControl",
  Retention: "IntentionalOutsideApplicationTeardown"
});
const CONSUMPTION_SCHEMA =
  "prooftoact.fresh-primary-provider-consumption.v1";
const INTENT_SCHEMA = "prooftoact.fresh-primary-provider-intent.v3";
const TERMINAL_SCHEMA = "prooftoact.fresh-primary-provider-terminal.v1";

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

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalBytes(value, code = "FRESH_PRIMARY_AWS_RECORD_REJECTED") {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES,
    code);
  return bytes;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function s(value) {
  return { S: value };
}

function n(value) {
  return { N: String(value) };
}

function b(value) {
  return { B: canonicalBytes(value) };
}

function stringAttribute(item, name, code) {
  requireCondition(typeof item?.[name]?.S === "string", code);
  return item[name].S;
}

function integerAttribute(item, name, code) {
  const raw = item?.[name]?.N;
  requireCondition(typeof raw === "string" && /^(?:0|[1-9][0-9]*)$/u.test(raw),
    code);
  const value = Number(raw);
  requireCondition(Number.isSafeInteger(value), code);
  return value;
}

function decodeCanonical(attribute, code) {
  requireCondition(attribute?.B !== undefined, code);
  const bytes = Buffer.from(attribute.B);
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES,
    code);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(canonicalBytes(value, code).equals(bytes), code);
  return value;
}

function effectKey(globalKeySha256) {
  requireCondition(HEX_64.test(globalKeySha256 ?? ""),
    "FRESH_PRIMARY_AWS_KEY_REJECTED");
  return `FRESH_PRIMARY#${globalKeySha256}`;
}

function transitionAttribute(sequence) {
  requireCondition(Number.isSafeInteger(sequence) && sequence >= 0 &&
    sequence <= 99, "FRESH_PRIMARY_AWS_TRANSITION_REJECTED");
  return `transition${String(sequence).padStart(2, "0")}`;
}

function normalizeCallerIdentity(value, accountId) {
  const arnMatch = ASSUMED_ROLE_ARN.exec(value?.Arn ?? "");
  const userMatch = ASSUMED_ROLE_USER_ID.exec(value?.UserId ?? "");
  requireCondition(value?.Account === accountId && arnMatch && userMatch &&
    arnMatch[1] === accountId && arnMatch[2] === userMatch[2],
  "FRESH_PRIMARY_AWS_CALLER_IDENTITY_REJECTED");
  return Object.freeze({
    accountId,
    assumedRoleArn: value.Arn,
    roleId: userMatch[1],
    roleName: "ProofToActFreshPrimaryBootstrap",
    sessionName: arnMatch[2]
  });
}

function validateTableReadback(description, tags, tableArn) {
  const code = "FRESH_PRIMARY_AWS_TABLE_READBACK_REJECTED";
  const table = description?.Table;
  requireCondition(table?.TableArn === tableArn &&
    table.TableName === TABLE_NAME && table.TableStatus === "ACTIVE" &&
    table.DeletionProtectionEnabled === true &&
    table.BillingModeSummary?.BillingMode === "PAY_PER_REQUEST" &&
    Array.isArray(table.KeySchema) && table.KeySchema.length === 1 &&
    table.KeySchema[0]?.AttributeName === "pk" &&
    table.KeySchema[0]?.KeyType === "HASH" &&
    Array.isArray(table.AttributeDefinitions) &&
    table.AttributeDefinitions.length === 1 &&
    table.AttributeDefinitions[0]?.AttributeName === "pk" &&
    table.AttributeDefinitions[0]?.AttributeType === "S" &&
    table.SSEDescription?.Status === "ENABLED" &&
    table.SSEDescription?.SSEType === "KMS" &&
    Array.isArray(tags?.Tags), code);
  const tagMap = Object.fromEntries(tags.Tags.map((tag) =>
    [tag?.Key, tag?.Value]));
  requireCondition(Object.entries(REQUIRED_TABLE_TAGS).every(([key, value]) =>
    tagMap[key] === value), code);
  return Object.freeze({
    billingMode: table.BillingModeSummary.BillingMode,
    deletionProtectionEnabled: true,
    keySchema: "pk:S:HASH",
    sseStatus: table.SSEDescription.Status,
    sseType: table.SSEDescription.SSEType,
    tableArn,
    tableId: table.TableId,
    tableStatus: table.TableStatus,
    tags: REQUIRED_TABLE_TAGS
  });
}

function validateSecretCoordinate(value, code) {
  requireCondition(exactKeys(value, ["arn", "versionId"]) &&
    /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/fresh-primary\/(?:admin-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[A-Za-z0-9]{6}|cloud-api-[A-Za-z0-9]{6}|runtime-credentials-[A-Za-z0-9]{6}|recovery-signer-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[A-Za-z0-9]{6})$/u
      .test(value.arn ?? "") &&
    /^[A-Za-z0-9_-]{32,64}$/u.test(value.versionId ?? ""),
  code);
  return Object.freeze({ ...value });
}

function validateSecretCoordinates(value, accountId) {
  const code = "FRESH_PRIMARY_AWS_SECRET_COORDINATES_REJECTED";
  requireCondition(exactKeys(value, [
    "admin", "cloudApi", "credential", "signer"
  ]), code);
  const accepted = Object.fromEntries(Object.entries(value).map(([name, item]) =>
    [name, validateSecretCoordinate(item, code)]));
  requireCondition(Object.values(accepted).every((item) =>
    item.arn.split(":")[4] === accountId) &&
    new Set(Object.values(accepted).map((item) => item.arn)).size === 4,
  code);
  return Object.freeze(accepted);
}

function normalizeSecretReadback(value, coordinate, maximumBytes) {
  const code = "FRESH_PRIMARY_AWS_SECRET_READBACK_REJECTED";
  requireCondition(value?.ARN === coordinate.arn &&
    value.VersionId === coordinate.versionId &&
    Array.isArray(value.VersionStages) &&
    value.VersionStages.includes("AWSCURRENT") &&
    typeof value.SecretString === "string" &&
    !Object.hasOwn(value, "SecretBinary"), code);
  const bytes = Buffer.from(value.SecretString, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= maximumBytes, code);
  const createdAt = value.CreatedDate instanceof Date
    ? value.CreatedDate.getTime()
    : Date.parse(value.CreatedDate);
  requireCondition(Number.isFinite(createdAt), code);
  return {
    createdAt: new Date(createdAt).toISOString(),
    secretArnSha256: sha256(coordinate.arn),
    secretValue: value.SecretString,
    secretValueSha256: sha256(bytes),
    secretVersionIdSha256: sha256(coordinate.versionId)
  };
}

function secretUserTags(tags, code) {
  requireCondition(Array.isArray(tags), code);
  const accepted = {};
  for (const item of tags) {
    requireCondition(exactKeys(item, ["Key", "Value"]) &&
      typeof item.Key === "string" && typeof item.Value === "string", code);
    if (item.Key.startsWith("aws:cloudformation:")) continue;
    requireCondition(!item.Key.startsWith("aws:") &&
      !Object.hasOwn(accepted, item.Key), code);
    accepted[item.Key] = item.Value;
  }
  return accepted;
}

function validateSignerSecretPrestate(
  description,
  resourcePolicy,
  readback,
  coordinate,
  command
) {
  const code = "FRESH_PRIMARY_AWS_SIGNER_SECRET_PRESTATE_REJECTED";
  const expectedName =
    `prooftoact/fresh-primary/recovery-signer-${command.operationId}`;
  const tagMap = secretUserTags(description?.Tags, code);
  requireCondition(description?.ARN === coordinate.arn &&
    description.Name === expectedName &&
    coordinate.arn.endsWith(`:${expectedName}-${coordinate.arn.slice(-6)}`) &&
    description.DeletedDate === undefined &&
    description.RotationEnabled !== true &&
    plainObject(description.VersionIdsToStages) &&
    Object.keys(description.VersionIdsToStages).length === 0 &&
    description.KmsKeyId === undefined &&
    description.OwningService === undefined &&
    description.PrimaryRegion === undefined &&
    (description.ReplicationStatus === undefined ||
      Array.isArray(description.ReplicationStatus) &&
      description.ReplicationStatus.length === 0) &&
    tagMap.Project === "ProofToAct" &&
    tagMap.Purpose === "FreshRecoveryPublisherSigner" &&
    tagMap.OperationId === command.operationId &&
    Object.keys(tagMap).length === 3 &&
    resourcePolicy?.ARN === coordinate.arn &&
    resourcePolicy.ResourcePolicy === undefined &&
    readback === null, code);
  return Object.freeze({
    secretArnSha256: sha256(coordinate.arn),
    targetVersionAbsent: true,
    targetVersionIdSha256: sha256(coordinate.versionId)
  });
}

function validateSignerSecretRecoveryState(
  description,
  resourcePolicy,
  readback,
  coordinate,
  command
) {
  if (readback === null) {
    return validateSignerSecretPrestate(
      description,
      resourcePolicy,
      null,
      coordinate,
      command
    );
  }
  const code = "FRESH_PRIMARY_AWS_SIGNER_SECRET_RECOVERY_REJECTED";
  const expectedName =
    `prooftoact/fresh-primary/recovery-signer-${command.operationId}`;
  const tagMap = secretUserTags(description?.Tags, code);
  requireCondition(description?.ARN === coordinate.arn &&
    description.Name === expectedName &&
    coordinate.arn.endsWith(`:${expectedName}-${coordinate.arn.slice(-6)}`) &&
    description.DeletedDate === undefined &&
    description.RotationEnabled !== true &&
    canonicalJson(description.VersionIdsToStages) === canonicalJson({
      [coordinate.versionId]: ["AWSCURRENT"]
    }) && description.KmsKeyId === undefined &&
    description.OwningService === undefined &&
    description.PrimaryRegion === undefined &&
    (description.ReplicationStatus === undefined ||
      Array.isArray(description.ReplicationStatus) &&
      description.ReplicationStatus.length === 0) &&
    canonicalJson(tagMap) === canonicalJson({
      OperationId: command.operationId,
      Project: "ProofToAct",
      Purpose: "FreshRecoveryPublisherSigner"
    }) && resourcePolicy?.ARN === coordinate.arn &&
    resourcePolicy.ResourcePolicy === undefined, code);
  const sealed = normalizeSecretReadback(readback, coordinate, 32 * 1024);
  requireCondition(sealed.secretValueSha256 ===
    command.signerSecretValueSha256, code);
  return Object.freeze({
    immutableVersion: true,
    secretArnSha256: sealed.secretArnSha256,
    secretValueSha256: sealed.secretValueSha256,
    secretVersionIdSha256: sealed.secretVersionIdSha256,
    versionStage: "AWSCURRENT"
  });
}

function signerSecretPayload(value, command) {
  const code = "FRESH_PRIMARY_AWS_SIGNER_SECRET_REJECTED";
  requireCondition(exactKeys(value, [
    "operationId",
    "privateKeyPkcs8Base64",
    "publisherKeyId",
    "publisherKeySetDigest",
    "schemaVersion",
    "secretBytesSha256",
    "sourceCommit",
    "treeDigest",
    "trustRootCommitment",
    "trustRootJson",
    "trustRootJsonSha256"
  ]) && value.schemaVersion ===
      "prooftoact.fresh-recovery-publisher-secret.v1" &&
    UUID.test(value.operationId ?? "") &&
    /^[0-9a-f]{40}$/u.test(value.sourceCommit ?? "") &&
    /^[0-9a-f]{40}$/u.test(value.treeDigest ?? "") &&
    [
      value.publisherKeySetDigest,
      value.secretBytesSha256,
      value.trustRootCommitment,
      value.trustRootJsonSha256
    ].every((item) => HEX_64.test(item ?? "")), code);
  const payload = { ...value };
  delete payload.secretBytesSha256;
  delete payload.trustRootJsonSha256;
  const accepted = validateFreshRecoveryPublisherSecret(payload, {
    operationId: command.operationId,
    sourceCommit: command.sourceCommit,
    treeDigest: command.treeDigest
  });
  requireCondition(accepted.secretBytesSha256 ===
    command.signerSecretValueSha256 &&
    accepted.trustRootJsonSha256 === command.trustRootJsonSha256 &&
    accepted.trustRootCommitment ===
      command.recoveryPublisherTrustRootCommitment &&
    accepted.publisherKeySetDigest === command.recoveryPublisherKeySetDigest,
  code);
  const secretString = canonicalBytes(payload, code).toString("utf8");
  requireCondition(sha256(secretString) === value.secretBytesSha256, code);
  return secretString;
}

export async function readFreshPrimarySecretMaterial({
  provider,
  secretCoordinates
}) {
  requireCondition(provider && typeof provider.readSecretVersion === "function",
    "FRESH_PRIMARY_AWS_PROVIDER_CAPABILITY_REJECTED");
  const values = await Promise.all([
    provider.readSecretVersion(secretCoordinates.admin),
    provider.readSecretVersion(secretCoordinates.cloudApi),
    provider.readSecretVersion(secretCoordinates.credential)
  ]);
  const admin = normalizeSecretReadback(
    values[0], secretCoordinates.admin, 16 * 1024
  );
  const cloudApi = normalizeSecretReadback(
    values[1], secretCoordinates.cloudApi, 16 * 1024
  );
  const credential = normalizeSecretReadback(
    values[2], secretCoordinates.credential, 64 * 1024
  );
  requireCondition(cloudApi.secretValue.length >= 20 &&
    cloudApi.secretValue.length <= 4096 &&
    !/[\u0000-\u0020\u007f]/u.test(cloudApi.secretValue),
  "FRESH_PRIMARY_AWS_CLOUD_API_SECRET_REJECTED");
  return { admin, cloudApi, credential };
}

function validateClusterInventory(value, providerClusterId,
  sqlHostSha256) {
  const code = "FRESH_PRIMARY_COCKROACH_INVENTORY_REJECTED";
  requireCondition(plainObject(value) && value.id === providerClusterId &&
    value.cloud_provider === "AWS" && value.state === "CREATED" &&
    value.operation_status === "UNSPECIFIED" &&
    typeof value.name === "string" && value.name.length > 0 &&
    value.name.length <= 255 &&
    typeof value.cockroach_version === "string" &&
    /^v?26\.2(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.-]+)?$/u
      .test(value.cockroach_version) &&
    typeof value.sql_dns === "string" &&
    /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.cockroachlabs\.cloud$/u
      .test(value.sql_dns) &&
    sha256(value.sql_dns) === sqlHostSha256 &&
    Array.isArray(value.regions) && value.regions.length > 0 &&
    value.regions.every((region) => plainObject(region) &&
      typeof region.name === "string" && region.name.length > 0 &&
      typeof region.sql_dns === "string" &&
      sha256(region.sql_dns) === sqlHostSha256), code);
  return Object.freeze({
    cloudProvider: value.cloud_provider,
    cockroachVersion: value.cockroach_version,
    id: value.id,
    nameSha256: sha256(value.name),
    operationStatus: value.operation_status,
    plan: value.plan,
    regionNames: Object.freeze(value.regions.map((region) => region.name).sort()),
    sqlDnsSha256: sha256(value.sql_dns),
    state: value.state
  });
}

function validateReadRequest(value, tableArn) {
  requireCondition(exactKeys(value, [
    "commandSha256",
    "globalKeySha256",
    "namespaceArn",
    "operationId",
    "stronglyConsistent"
  ]) && HEX_64.test(value.commandSha256 ?? "") &&
    HEX_64.test(value.globalKeySha256 ?? "") &&
    value.namespaceArn === tableArn && UUID.test(value.operationId ?? "") &&
    value.stronglyConsistent === true,
  "FRESH_PRIMARY_AWS_READ_REQUEST_REJECTED");
}

function parseStoredItem(item, command) {
  const code = "FRESH_PRIMARY_AWS_STORED_RECORD_REJECTED";
  requireCondition(plainObject(item) &&
    stringAttribute(item, "pk", code) === effectKey(command.globalKeySha256) &&
    stringAttribute(item, "entity", code) === "FRESH_PRIMARY_V1" &&
    stringAttribute(item, "namespaceArn", code) ===
      command.controllerTableArn &&
    stringAttribute(item, "commandSha256", code) === command.commandSha256 &&
    stringAttribute(item, "globalKeySha256", code) ===
      command.globalKeySha256 &&
    stringAttribute(item, "operationId", code) === command.operationId,
  code);
  const storedCommand = decodeCanonical(item.command, code);
  requireCondition(storedCommand.commandSha256 === command.commandSha256 &&
    storedCommand.globalKeySha256 === command.globalKeySha256 &&
    storedCommand.operationId === command.operationId &&
    (command.schemaVersion === undefined ||
      canonicalJson(storedCommand) === canonicalJson(command)), code);
  const consumption = decodeCanonical(item.consumption, code);
  requireCondition(consumption.schemaVersion === CONSUMPTION_SCHEMA &&
    consumption.status === "CONSUMED" && consumption.version === 1 &&
    consumption.commandSha256 === storedCommand.commandSha256 &&
    consumption.globalKeySha256 === storedCommand.globalKeySha256 &&
    consumption.operationId === storedCommand.operationId &&
    consumption.namespaceArn === storedCommand.controllerTableArn &&
    stringAttribute(item, "consumptionSha256", code) === digest(consumption),
  code);
  const transitionCount = integerAttribute(item, "transitionCount", code);
  requireCondition(transitionCount >= 0 && transitionCount <= 99, code);
  const intent = item.intent === undefined
    ? null
    : decodeCanonical(item.intent, code);
  if (intent !== null) {
    requireCondition(intent.schemaVersion === INTENT_SCHEMA &&
      intent.status === "DURABLE" && intent.version === 2 &&
      intent.event === "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH" &&
      intent.commandSha256 === storedCommand.commandSha256 &&
      intent.globalKeySha256 === storedCommand.globalKeySha256 &&
      intent.operationId === storedCommand.operationId &&
      intent.namespaceArn === storedCommand.controllerTableArn &&
      intent.previousReceiptSha256 === digest(consumption) &&
      HEX_64.test(intent.providerAuthenticationReceiptSha256 ?? "") &&
      stringAttribute(item, "intentSha256", code) === digest(intent), code);
  }
  requireCondition(intent !== null || transitionCount === 0, code);
  const transitions = [];
  let previousReceiptSha256 = intent === null
    ? digest(consumption)
    : digest(intent);
  for (let sequence = 0; sequence < transitionCount; sequence += 1) {
    const attribute = transitionAttribute(sequence);
    const transition = decodeCanonical(item[attribute], code);
    requireCondition(exactKeys(transition, [
      "commandSha256", "durable", "globallyAuthoritative",
      "globalKeySha256", "mutationDispatched", "namespaceArn",
      "operationId", "payloadSha256", "phase", "previousReceiptSha256",
      "schemaVersion", "sequence", "status", "version"
    ]) && transition.schemaVersion ===
        "prooftoact.fresh-primary-provider-transition.v1" &&
      transition.status === "DURABLE" &&
      transition.commandSha256 === storedCommand.commandSha256 &&
      transition.globalKeySha256 === storedCommand.globalKeySha256 &&
      transition.operationId === storedCommand.operationId &&
      transition.namespaceArn === storedCommand.controllerTableArn &&
      transition.previousReceiptSha256 === previousReceiptSha256 &&
      transition.sequence === sequence &&
      transition.version === sequence + 3 &&
      typeof transition.mutationDispatched === "boolean" &&
      HEX_64.test(transition.payloadSha256 ?? "") &&
      transition.durable === true &&
      transition.globallyAuthoritative === true, code);
    transitions.push(Object.freeze(transition));
    previousReceiptSha256 = digest(transition);
  }
  const terminal = item.terminal === undefined
    ? null
    : decodeCanonical(item.terminal, code);
  const outcome = item.outcome === undefined
    ? null
    : decodeCanonical(item.outcome, code);
  const providerReceipt = item.providerReceipt === undefined
    ? null
    : decodeCanonical(item.providerReceipt, code);
  requireCondition((terminal === null) === (outcome === null) &&
    (terminal === null) === (providerReceipt === null), code);
  const state = stringAttribute(item, "state", code);
  const version = integerAttribute(item, "version", code);
  const lastReceiptSha256 = stringAttribute(item, "lastReceiptSha256", code);
  if (terminal !== null) {
    requireCondition(terminal.schemaVersion === TERMINAL_SCHEMA &&
      terminal.status === "TERMINAL" &&
      terminal.commandSha256 === storedCommand.commandSha256 &&
      terminal.globalKeySha256 === storedCommand.globalKeySha256 &&
      terminal.operationId === storedCommand.operationId &&
      terminal.namespaceArn === storedCommand.controllerTableArn &&
      terminal.previousReceiptSha256 === previousReceiptSha256 &&
      terminal.transitionCount === transitionCount &&
      terminal.version === transitionCount + 3 &&
      terminal.outcomeSha256 === digest(outcome) &&
      outcome.providerReceiptSha256 === digest(providerReceipt) &&
      stringAttribute(item, "terminalSha256", code) === digest(terminal) &&
      stringAttribute(item, "outcomeSha256", code) === digest(outcome) &&
      state === "TERMINAL" && version === transitionCount + 3 &&
      lastReceiptSha256 === digest(terminal), code);
  } else if (intent === null) {
    requireCondition(state === "CONSUMED" && transitionCount === 0 &&
      version === 1 && lastReceiptSha256 === digest(consumption), code);
  } else if (transitionCount === 0) {
    requireCondition(state === "INTENT" && version === 2 &&
      lastReceiptSha256 === digest(intent), code);
  } else {
    requireCondition(state === "TRANSITION" &&
      version === transitionCount + 2 &&
      lastReceiptSha256 === previousReceiptSha256, code);
  }
  const expectedKeys = [
    "command", "commandSha256", "consumption", "consumptionSha256",
    "entity", "globalKeySha256", "lastReceiptSha256", "namespaceArn",
    "operationId", "pk", "state", "transitionCount", "version",
    ...(intent === null ? [] : ["intent", "intentSha256"]),
    ...transitions.map((_, sequence) => transitionAttribute(sequence)),
    ...(terminal === null
      ? []
      : ["outcome", "outcomeSha256", "providerReceipt", "terminal",
        "terminalSha256"])
  ].sort();
  requireCondition(Object.keys(item).sort().join("\n") ===
    expectedKeys.join("\n"), code);
  return Object.freeze({
    command: storedCommand,
    consumption,
    intent,
    lastReceiptSha256,
    outcome,
    providerReceipt,
    state,
    terminal,
    transitionCount,
    transitions: Object.freeze(transitions),
    version
  });
}

async function reconcileWrite({ provider, tableName, command, accept, code }) {
  let response;
  try {
    response = await provider.getFreshPrimaryItem({
      ConsistentRead: true,
      Key: { pk: s(effectKey(command.globalKeySha256)) },
      ReturnConsumedCapacity: "NONE",
      TableName: tableName
    });
  } catch (cause) {
    reject("FRESH_PRIMARY_AWS_ACKNOWLEDGEMENT_UNKNOWN_DO_NOT_RETRY", cause);
  }
  requireCondition(plainObject(response) && response.Item, code);
  parseStoredItem(response.Item, command);
  requireCondition(accept(response.Item), code);
}

export function createFreshPrimaryAwsProvider({
  clock = Date.now,
  provider,
  secretCoordinates,
  sqlHostSha256,
  tableArn,
  tableName = TABLE_NAME
}) {
  const tableMatch = TABLE_ARN.exec(tableArn ?? "");
  requireCondition(tableMatch && tableName === TABLE_NAME &&
    HEX_64.test(sqlHostSha256 ?? "") && typeof clock === "function" &&
    provider && [
      "describeFreshPrimaryTable",
      "describeRecoverySignerSecret",
      "getRecoverySignerResourcePolicy",
      "getFreshPrimaryCallerIdentity",
      "getFreshPrimaryItem",
      "listFreshPrimaryTableTags",
      "putFreshPrimaryItem",
      "putRecoverySignerSecret",
      "readCockroachCluster",
      "readRecoverySignerVersionIfPresent",
      "readSecretVersion",
      "updateFreshPrimaryItem"
    ].every((name) => typeof provider[name] === "function"),
  "FRESH_PRIMARY_AWS_PROVIDER_CONFIGURATION_REJECTED");
  const accountId = tableMatch[1];
  const coordinates = validateSecretCoordinates(secretCoordinates, accountId);

  async function getRaw(command) {
    const response = await provider.getFreshPrimaryItem({
      ConsistentRead: true,
      Key: { pk: s(effectKey(command.globalKeySha256)) },
      ReturnConsumedCapacity: "NONE",
      TableName: tableName
    });
    requireCondition(plainObject(response), "FRESH_PRIMARY_AWS_READ_REJECTED");
    return response.Item ?? null;
  }

  async function updateOnce({ command, input, accept, code }) {
    try {
      await provider.updateFreshPrimaryItem(input);
    } catch (cause) {
      await reconcileWrite({ provider, tableName, command, accept, code });
    }
  }

  async function authenticateMode(command, recovery) {
      requireCondition(typeof recovery === "boolean",
        "FRESH_PRIMARY_AWS_AUTHENTICATION_MODE_REJECTED");
      requireCondition(command.controllerTableArn === tableArn &&
        command.providerClusterId !== command.sqlClusterId &&
        command.adminSecretArnSha256 === sha256(coordinates.admin.arn) &&
        command.adminSecretVersionIdSha256 ===
          sha256(coordinates.admin.versionId) &&
        command.cloudApiSecretArnSha256 ===
          sha256(coordinates.cloudApi.arn) &&
        command.cloudApiSecretVersionIdSha256 ===
          sha256(coordinates.cloudApi.versionId) &&
        command.credentialSecretArnSha256 ===
          sha256(coordinates.credential.arn) &&
        command.credentialSecretVersionIdSha256 ===
          sha256(coordinates.credential.versionId) &&
        command.signerSecretArnSha256 === sha256(coordinates.signer.arn) &&
        command.signerSecretVersionIdSha256 ===
          sha256(coordinates.signer.versionId) &&
        coordinates.signer.arn.includes(
          `/recovery-signer-${command.operationId}-`
        ) && coordinates.admin.arn.includes(
          `/admin-${command.operationId}-`
        ),
      "FRESH_PRIMARY_AWS_COMMAND_BINDING_REJECTED");
      const [identityValue, tableDescription, tags, material,
        signerDescription, signerResourcePolicy, signerReadback] =
        await Promise.all([
          provider.getFreshPrimaryCallerIdentity(),
          provider.describeFreshPrimaryTable({ TableName: tableName }),
          provider.listFreshPrimaryTableTags({ ResourceArn: tableArn }),
          readFreshPrimarySecretMaterial({
            provider,
            secretCoordinates: coordinates
          }),
          provider.describeRecoverySignerSecret(),
          provider.getRecoverySignerResourcePolicy(),
          provider.readRecoverySignerVersionIfPresent()
        ]);
      const identity = normalizeCallerIdentity(identityValue, accountId);
      const table = validateTableReadback(tableDescription, tags, tableArn);
      const signerPrestate = recovery
        ? validateSignerSecretRecoveryState(
          signerDescription,
          signerResourcePolicy,
          signerReadback,
          coordinates.signer,
          command
        )
        : validateSignerSecretPrestate(
          signerDescription,
          signerResourcePolicy,
          signerReadback,
          coordinates.signer,
          command
        );
      requireCondition(material.admin.secretValueSha256 ===
        command.adminSecretValueSha256 &&
        material.cloudApi.secretValueSha256 ===
          command.cloudApiSecretValueSha256 &&
        material.credential.secretValueSha256 ===
          command.credentialBundleRawSha256,
      "FRESH_PRIMARY_AWS_SECRET_CONTENT_REJECTED");
      const clusterValue = await provider.readCockroachCluster({
        bearerToken: material.cloudApi.secretValue,
        clusterId: command.providerClusterId
      });
      const cluster = validateClusterInventory(
        clusterValue,
        command.providerClusterId,
        sqlHostSha256
      );
      const observedAt = clock();
      requireCondition(Number.isFinite(observedAt),
        "FRESH_PRIMARY_AWS_CLOCK_REJECTED");
      return Object.freeze({
        schemaVersion:
          "prooftoact.fresh-primary-provider-authentication.v3",
        status: "AUTHENTICATED_PROVIDER_READBACK",
        callerIdentitySha256: digest(identity),
        cloud: command.cloud,
        clusterInventorySha256: digest(cluster),
        namespaceArn: tableArn,
        observedAt: new Date(observedAt).toISOString(),
        providerBacked: true,
        providerClusterId: command.providerClusterId,
        readOnly: true,
        region: command.region,
        secretReadbacks: Object.freeze({
          admin: Object.freeze({
            immutableVersion: true,
            secretArnSha256: material.admin.secretArnSha256,
            secretValueSha256: material.admin.secretValueSha256,
            secretVersionIdSha256: material.admin.secretVersionIdSha256,
            versionStage: "AWSCURRENT"
          }),
          cloudApi: Object.freeze({
            immutableVersion: true,
            secretArnSha256: material.cloudApi.secretArnSha256,
            secretValueSha256: material.cloudApi.secretValueSha256,
            secretVersionIdSha256: material.cloudApi.secretVersionIdSha256,
            versionStage: "AWSCURRENT"
          }),
          credential: Object.freeze({
            immutableVersion: true,
            secretArnSha256: material.credential.secretArnSha256,
            secretValueSha256: material.credential.secretValueSha256,
            secretVersionIdSha256: material.credential.secretVersionIdSha256,
            versionStage: "AWSCURRENT"
          }),
          recoverySigner: signerPrestate
        }),
        stronglyConsistent: true
      });
  }

  return Object.freeze({
    authenticate(command) {
      return authenticateMode(command, false);
    },

    authenticateRecovery(command) {
      return authenticateMode(command, true);
    },

    async sealRecoveryPublisherSecret({ command, secret }) {
      requireCondition(command.signerSecretArnSha256 ===
        sha256(coordinates.signer.arn) &&
        command.signerSecretVersionIdSha256 ===
          sha256(coordinates.signer.versionId),
      "FRESH_PRIMARY_AWS_SIGNER_SECRET_BINDING_REJECTED");
      const secretString = signerSecretPayload(secret, command);
      requireCondition(sha256(secretString) ===
        command.signerSecretValueSha256,
      "FRESH_PRIMARY_AWS_SIGNER_SECRET_BINDING_REJECTED");
      try {
        await provider.putRecoverySignerSecret({
          clientRequestToken: coordinates.signer.versionId,
          secretString
        });
      } catch (cause) {
        // PutSecretValue is never retried. Only the exact immutable target
        // version may reconcile an acknowledgement-lost call.
        try {
          const reconciled = await provider.readSecretVersion(
            coordinates.signer
          );
          const accepted = normalizeSecretReadback(
            reconciled, coordinates.signer, 32 * 1024
          );
          requireCondition(accepted.secretValueSha256 ===
            command.signerSecretValueSha256,
          "FRESH_PRIMARY_AWS_SIGNER_SECRET_RECONCILIATION_REJECTED");
        } catch (readbackCause) {
          reject("FRESH_PRIMARY_AWS_SIGNER_SECRET_UNKNOWN_DO_NOT_RETRY", {
            cause,
            readbackCause
          });
        }
      }
      const readback = normalizeSecretReadback(
        await provider.readSecretVersion(coordinates.signer),
        coordinates.signer,
        32 * 1024
      );
      requireCondition(readback.secretValueSha256 ===
        command.signerSecretValueSha256,
      "FRESH_PRIMARY_AWS_SIGNER_SECRET_READBACK_REJECTED");
      return Object.freeze({
        schemaVersion:
          "prooftoact.fresh-recovery-publisher-secret-seal.v1",
        status: "SEALED",
        provider: "AWS_SECRETS_MANAGER",
        providerBacked: true,
        immutableVersion: true,
        createdAt: readback.createdAt,
        secretArnSha256: readback.secretArnSha256,
        secretValueSha256: readback.secretValueSha256,
        secretVersionIdSha256: readback.secretVersionIdSha256
      });
    },

    async readStrong(request) {
      validateReadRequest(request, tableArn);
      const item = await getRaw({
        commandSha256: request.commandSha256,
        controllerTableArn: request.namespaceArn,
        globalKeySha256: request.globalKeySha256,
        operationId: request.operationId
      });
      if (item === null) return null;
      return Object.freeze({
        occupied: true,
        ...parseStoredItem(item, {
          commandSha256: request.commandSha256,
          controllerTableArn: request.namespaceArn,
          globalKeySha256: request.globalKeySha256,
          operationId: request.operationId
        })
      });
    },

    async consumeOnce(command) {
      const consumedAt = clock();
      requireCondition(Number.isFinite(consumedAt),
        "FRESH_PRIMARY_AWS_CLOCK_REJECTED");
      const consumption = Object.freeze({
        schemaVersion: CONSUMPTION_SCHEMA,
        status: "CONSUMED",
        approvalId: command.approvalId,
        commandSha256: command.commandSha256,
        consumedAt: new Date(consumedAt).toISOString(),
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: tableArn,
        oneShot: true,
        operationId: command.operationId,
        version: 1
      });
      const item = {
        pk: s(effectKey(command.globalKeySha256)),
        entity: s("FRESH_PRIMARY_V1"),
        namespaceArn: s(tableArn),
        commandSha256: s(command.commandSha256),
        globalKeySha256: s(command.globalKeySha256),
        operationId: s(command.operationId),
        command: b(command),
        consumption: b(consumption),
        consumptionSha256: s(digest(consumption)),
        lastReceiptSha256: s(digest(consumption)),
        state: s("CONSUMED"),
        transitionCount: n(0),
        version: n(1)
      };
      try {
        await provider.putFreshPrimaryItem({
          ConditionExpression: "attribute_not_exists(#pk)",
          ExpressionAttributeNames: { "#pk": "pk" },
          Item: item,
          ReturnConsumedCapacity: "NONE",
          TableName: tableName
        });
      } catch (cause) {
        await reconcileWrite({
          provider,
          tableName,
          command,
          code: "FRESH_PRIMARY_AWS_CONSUMPTION_CONFLICT",
          accept: (stored) =>
            canonicalJson(decodeCanonical(stored.consumption,
              "FRESH_PRIMARY_AWS_CONSUMPTION_CONFLICT")) ===
              canonicalJson(consumption) &&
            stringAttribute(stored, "commandSha256",
              "FRESH_PRIMARY_AWS_CONSUMPTION_CONFLICT") ===
              command.commandSha256
        });
      }
      return consumption;
    },

    async appendIntent({ command, consumption, authentication }) {
      const intent = Object.freeze({
        schemaVersion: INTENT_SCHEMA,
        status: "DURABLE",
        commandSha256: command.commandSha256,
        durable: true,
        event: "BEFORE_SIGNER_OR_DATABASE_PROVIDER_DISPATCH",
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: tableArn,
        operationId: command.operationId,
        previousReceiptSha256: digest(consumption),
        providerAuthenticationReceiptSha256: digest(authentication),
        version: 2
      });
      const intentSha256 = digest(intent);
      const input = {
        ConditionExpression:
          "#state = :expectedState AND #version = :expectedVersion AND " +
          "#last = :expectedLast AND attribute_not_exists(#intent)",
        ExpressionAttributeNames: {
          "#intent": "intent",
          "#intentSha256": "intentSha256",
          "#last": "lastReceiptSha256",
          "#state": "state",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":expectedLast": s(digest(consumption)),
          ":expectedState": s("CONSUMED"),
          ":expectedVersion": n(1),
          ":intent": b(intent),
          ":intentSha256": s(intentSha256),
          ":last": s(intentSha256),
          ":state": s("INTENT"),
          ":version": n(2)
        },
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #intent = :intent, #intentSha256 = :intentSha256, " +
          "#last = :last, #state = :state, #version = :version"
      };
      await updateOnce({
        command,
        input,
        code: "FRESH_PRIMARY_AWS_INTENT_CONFLICT",
        accept: (stored) => canonicalJson(decodeCanonical(stored.intent,
          "FRESH_PRIMARY_AWS_INTENT_CONFLICT")) === canonicalJson(intent) &&
          stringAttribute(stored, "intentSha256",
            "FRESH_PRIMARY_AWS_INTENT_CONFLICT") === intentSha256
      });
      return intent;
    },

    async appendTransition({ command, intent, transition }) {
      requireCondition(canonicalJson(decodeCanonical(
        b(intent), "FRESH_PRIMARY_AWS_TRANSITION_REJECTED"
      )) === canonicalJson(intent), "FRESH_PRIMARY_AWS_TRANSITION_REJECTED");
      const attribute = transitionAttribute(transition.sequence);
      const transitionSha256 = digest(transition);
      const expectedState = transition.sequence === 0 ? "INTENT" : "TRANSITION";
      const input = {
        ConditionExpression:
          "#state = :expectedState AND #version = :expectedVersion AND " +
          "#last = :expectedLast AND #count = :expectedCount AND " +
          "attribute_not_exists(#record)",
        ExpressionAttributeNames: {
          "#count": "transitionCount",
          "#last": "lastReceiptSha256",
          "#record": attribute,
          "#state": "state",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":count": n(transition.sequence + 1),
          ":expectedCount": n(transition.sequence),
          ":expectedLast": s(transition.previousReceiptSha256),
          ":expectedState": s(expectedState),
          ":expectedVersion": n(transition.sequence + 2),
          ":last": s(transitionSha256),
          ":record": b(transition),
          ":state": s("TRANSITION"),
          ":version": n(transition.version)
        },
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #record = :record, #last = :last, #count = :count, " +
          "#state = :state, #version = :version"
      };
      await updateOnce({
        command,
        input,
        code: "FRESH_PRIMARY_AWS_TRANSITION_CONFLICT",
        accept: (stored) => canonicalJson(decodeCanonical(stored[attribute],
          "FRESH_PRIMARY_AWS_TRANSITION_CONFLICT")) ===
          canonicalJson(transition) &&
          stringAttribute(stored, "lastReceiptSha256",
            "FRESH_PRIMARY_AWS_TRANSITION_CONFLICT") === transitionSha256
      });
      return transition;
    },

    async finalize({
      command,
      outcome,
      previousReceiptSha256,
      providerReceipt,
      transitionCount
    }) {
      requireCondition(plainObject(providerReceipt) &&
        outcome?.providerReceiptSha256 === digest(providerReceipt),
      "FRESH_PRIMARY_AWS_TERMINAL_RECEIPT_REJECTED");
      const terminal = Object.freeze({
        schemaVersion: TERMINAL_SCHEMA,
        status: "TERMINAL",
        commandSha256: command.commandSha256,
        durable: true,
        globallyAuthoritative: true,
        globalKeySha256: command.globalKeySha256,
        namespaceArn: tableArn,
        operationId: command.operationId,
        outcomeSha256: digest(outcome),
        previousReceiptSha256,
        transitionCount,
        version: transitionCount + 3
      });
      const expectedState = transitionCount === 0 ? "INTENT" : "TRANSITION";
      const terminalSha256 = digest(terminal);
      const outcomeSha256 = digest(outcome);
      const input = {
        ConditionExpression:
          "#state = :expectedState AND #version = :expectedVersion AND " +
          "#last = :expectedLast AND #count = :expectedCount AND " +
          "attribute_not_exists(#terminal)",
        ExpressionAttributeNames: {
          "#count": "transitionCount",
          "#last": "lastReceiptSha256",
          "#outcome": "outcome",
          "#outcomeSha256": "outcomeSha256",
          "#providerReceipt": "providerReceipt",
          "#state": "state",
          "#terminal": "terminal",
          "#terminalSha256": "terminalSha256",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":expectedCount": n(transitionCount),
          ":expectedLast": s(previousReceiptSha256),
          ":expectedState": s(expectedState),
          ":expectedVersion": n(transitionCount + 2),
          ":last": s(terminalSha256),
          ":outcome": b(outcome),
          ":outcomeSha256": s(outcomeSha256),
          ":providerReceipt": b(providerReceipt),
          ":state": s("TERMINAL"),
          ":terminal": b(terminal),
          ":terminalSha256": s(terminalSha256),
          ":version": n(transitionCount + 3)
        },
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #outcome = :outcome, #outcomeSha256 = :outcomeSha256, " +
          "#providerReceipt = :providerReceipt, " +
          "#terminal = :terminal, #terminalSha256 = :terminalSha256, " +
          "#last = :last, #state = :state, #version = :version"
      };
      await updateOnce({
        command,
        input,
        code: "FRESH_PRIMARY_AWS_TERMINAL_CONFLICT",
        accept: (stored) => canonicalJson(decodeCanonical(stored.terminal,
          "FRESH_PRIMARY_AWS_TERMINAL_CONFLICT")) ===
          canonicalJson(terminal) &&
          canonicalJson(decodeCanonical(stored.outcome,
            "FRESH_PRIMARY_AWS_TERMINAL_CONFLICT")) ===
          canonicalJson(outcome) &&
          canonicalJson(decodeCanonical(stored.providerReceipt,
            "FRESH_PRIMARY_AWS_TERMINAL_CONFLICT")) ===
          canonicalJson(providerReceipt) &&
          stringAttribute(stored, "outcomeSha256",
            "FRESH_PRIMARY_AWS_TERMINAL_CONFLICT") === outcomeSha256 &&
          stringAttribute(stored, "terminalSha256",
            "FRESH_PRIMARY_AWS_TERMINAL_CONFLICT") === terminalSha256
      });
      return terminal;
    }
  });
}

export const __test = Object.freeze({
  canonicalBytes,
  canonicalJson,
  decodeCanonical,
  digest,
  effectKey,
  normalizeCallerIdentity,
  normalizeSecretReadback,
  sha256,
  transitionAttribute,
  validateClusterInventory,
  validateSecretCoordinates,
  validateTableReadback
});
