import crypto from "node:crypto";

const TABLE_NAME = "prooftoact-release-controller";
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u;
const ASSUMED_ROLE_ARN =
  /^arn:aws:sts::([0-9]{12}):assumed-role\/ProofToActFreshPrimaryBootstrap\/([A-Za-z0-9+=,.@_-]{2,64})$/u;
const ASSUMED_ROLE_USER_ID =
  /^(AROA[A-Z0-9]{16}):([A-Za-z0-9+=,.@_-]{2,64})$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const MAX_CANONICAL_BYTES = 128 * 1024;
const REQUIRED_TABLE_TAGS = Object.freeze({
  Project: "ProofToAct",
  Purpose: "RetainedReleaseControl",
  Retention: "IntentionalOutsideApplicationTeardown"
});
const RECOVERY_PUBLISHER_SECRET_VALUE_SHA256 =
  "5485f056ccc172c28c56f90f2f75a01939fdc71ffd493d1efb323d254515ea13";
const MANAGED_MCP_SECRET_VALUE_SHA256 =
  "a4a257a5842a550abe18e6a5c03343defebb63504505c1e2a27de376e0bee4db";

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

function canonicalBytes(value, code = "FRESH_CLUSTER_AWS_RECORD_REJECTED") {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8");
  requireCondition(bytes.length > 0 && bytes.length <= MAX_CANONICAL_BYTES,
    code);
  return bytes;
}

function digest(value) {
  return crypto.createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
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

function effectKey(globalKeySha256) {
  requireCondition(HEX_64.test(globalKeySha256 ?? ""),
    "FRESH_CLUSTER_AWS_KEY_REJECTED");
  return `FRESH_CLUSTER#${globalKeySha256}`;
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

function normalizeCallerIdentity(value, accountId) {
  const arn = ASSUMED_ROLE_ARN.exec(value?.Arn ?? "");
  const user = ASSUMED_ROLE_USER_ID.exec(value?.UserId ?? "");
  requireCondition(value?.Account === accountId && arn && user &&
    arn[1] === accountId && arn[2] === user[2],
  "FRESH_CLUSTER_AWS_CALLER_IDENTITY_REJECTED");
  return Object.freeze({
    accountId,
    assumedRoleArn: value.Arn,
    roleId: user[1],
    roleName: "ProofToActFreshPrimaryBootstrap",
    sessionName: arn[2]
  });
}

function validateTableReadback(description, tags, tableArn) {
  const code = "FRESH_CLUSTER_AWS_TABLE_READBACK_REJECTED";
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
    table.SSEDescription?.SSEType === "KMS" && Array.isArray(tags?.Tags), code);
  const tagMap = Object.fromEntries(tags.Tags.map((item) =>
    [item?.Key, item?.Value]));
  requireCondition(Object.keys(tagMap).length ===
    Object.keys(REQUIRED_TABLE_TAGS).length &&
    Object.entries(REQUIRED_TABLE_TAGS).every(([key, value]) =>
      tagMap[key] === value), code);
  return Object.freeze({
    billingMode: "PAY_PER_REQUEST",
    deletionProtectionEnabled: true,
    keySchema: "pk:S:HASH",
    sseStatus: "ENABLED",
    sseType: "KMS",
    tableArn,
    tableId: table.TableId,
    tableStatus: "ACTIVE",
    tags: REQUIRED_TABLE_TAGS
  });
}

function normalizeSecretReadback(value, coordinate, maximumBytes) {
  const code = "FRESH_CLUSTER_AWS_SECRET_READBACK_REJECTED";
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
  return Object.freeze({
    createdAt: new Date(createdAt).toISOString(),
    secretArnSha256: sha256(coordinate.arn),
    secretValue: value.SecretString,
    secretValueSha256: sha256(bytes),
    secretVersionIdSha256: sha256(coordinate.versionId)
  });
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

function validateAdminSecretPrestate(
  description,
  resourcePolicy,
  readback,
  coordinate,
  operationId
) {
  const code = "FRESH_CLUSTER_AWS_ADMIN_SECRET_PRESTATE_REJECTED";
  const expectedName = `prooftoact/fresh-primary/admin-${operationId}`;
  const tags = secretUserTags(description?.Tags, code);
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
    canonicalJson(tags) === canonicalJson({
      OperationId: operationId,
      Project: "ProofToAct",
      Purpose: "FreshBootstrapAdmin"
    }) && resourcePolicy?.ARN === coordinate.arn &&
    resourcePolicy.ResourcePolicy === undefined && readback === null, code);
  return Object.freeze({
    secretArnSha256: sha256(coordinate.arn),
    targetVersionAbsent: true,
    targetVersionIdSha256: sha256(coordinate.versionId)
  });
}

function validateAdminSecretRecoveryState(
  description,
  resourcePolicy,
  readback,
  coordinate,
  command
) {
  if (readback === null) {
    return Object.freeze({
      ...validateAdminSecretPrestate(
        description,
        resourcePolicy,
        null,
        coordinate,
        command.operationId
      ),
      state: "ABSENT"
    });
  }
  requireCondition(typeof readback?.SecretString === "string",
    "FRESH_CLUSTER_AWS_ADMIN_SECRET_RECOVERY_REJECTED");
  return Object.freeze({
    ...normalizeFreshClusterAdminSealReadback({
      command,
      coordinate,
      description,
      readback,
      resourcePolicy,
      secretValueSha256: sha256(readback.SecretString)
    }),
    state: "SEALED"
  });
}

export async function readFreshClusterSecretMaterial({
  provider,
  secretCoordinates
}) {
  const code = "FRESH_CLUSTER_AWS_SECRET_MATERIAL_REJECTED";
  requireCondition(provider && typeof provider.readSecretVersion === "function" &&
    exactKeys(secretCoordinates, [
      "admin", "auditor", "cloudApi", "credential", "mcp", "publisher",
      "signer"
    ]), code);
  const [cloudApiValue, auditorValue, credentialValue] = await Promise.all([
    provider.readSecretVersion(secretCoordinates.cloudApi),
    provider.readSecretVersion(secretCoordinates.auditor),
    provider.readSecretVersion(secretCoordinates.credential)
  ]);
  const cloudApi = normalizeSecretReadback(
    cloudApiValue, secretCoordinates.cloudApi, 16 * 1024
  );
  const auditor = normalizeSecretReadback(
    auditorValue, secretCoordinates.auditor, 16 * 1024
  );
  const credential = normalizeSecretReadback(
    credentialValue, secretCoordinates.credential, 64 * 1024
  );
  requireCondition([cloudApi, auditor].every((item) =>
    item.secretValue.length >= 20 && item.secretValue.length <= 4096 &&
    !/[\u0000-\u0020\u007f]/u.test(item.secretValue)) &&
    cloudApi.secretValue !== auditor.secretValue, code);
  return Object.freeze({ auditor, cloudApi, credential });
}

export async function readFreshRecoveryPublicationSecretMaterial({
  provider,
  secretCoordinates
}) {
  const code = "FRESH_RECOVERY_PUBLICATION_AWS_SECRET_MATERIAL_REJECTED";
  requireCondition(provider && typeof provider.readSecretVersion === "function" &&
    exactKeys(secretCoordinates, [
      "admin", "auditor", "cloudApi", "credential", "mcp", "publisher",
      "signer"
    ]), code);
  const [credentialValue, signerValue, publisherValue, mcpValue] =
    await Promise.all([
      provider.readSecretVersion(secretCoordinates.credential),
      provider.readSecretVersion(secretCoordinates.signer),
      provider.readSecretVersion(secretCoordinates.publisher),
      provider.readSecretVersion(secretCoordinates.mcp)
    ]);
  const credential = normalizeSecretReadback(
    credentialValue, secretCoordinates.credential, 64 * 1024
  );
  const signer = normalizeSecretReadback(
    signerValue, secretCoordinates.signer, 32 * 1024
  );
  const publisher = normalizeSecretReadback(
    publisherValue, secretCoordinates.publisher, 16 * 1024
  );
  const mcp = normalizeSecretReadback(
    mcpValue, secretCoordinates.mcp, 16 * 1024
  );
  requireCondition(publisher.secretValueSha256 ===
      RECOVERY_PUBLISHER_SECRET_VALUE_SHA256 &&
    mcp.secretValueSha256 === MANAGED_MCP_SECRET_VALUE_SHA256,
  code);
  return Object.freeze({ credential, mcp, publisher, signer });
}

function parseStored(item, command) {
  const code = "FRESH_CLUSTER_AWS_STORED_RECORD_REJECTED";
  requireCondition(plainObject(item) &&
    stringAttribute(item, "pk", code) === effectKey(command.globalKeySha256) &&
    stringAttribute(item, "entity", code) === "FRESH_CLUSTER_V1" &&
    stringAttribute(item, "commandSha256", code) === command.commandSha256 &&
    stringAttribute(item, "operationId", code) === command.operationId,
  code);
  const storedCommand = decodeCanonical(item.command, code);
  requireCondition(command?.schemaVersion ===
      "prooftoact.fresh-cluster-command.v1" &&
    storedCommand.commandSha256 === command.commandSha256 &&
    storedCommand.globalKeySha256 === command.globalKeySha256 &&
    storedCommand.operationId === command.operationId &&
    canonicalJson(storedCommand) === canonicalJson(command), code);
  const reservation = decodeCanonical(item.reservation, code);
  requireCondition(reservation?.schemaVersion ===
      "prooftoact.fresh-cluster-reservation.v1" &&
    reservation.status === "RESERVED_BEFORE_PROVIDER_IDENTIFIERS" &&
    reservation.commandSha256 === command.commandSha256 &&
    reservation.controllerTableArn === command.controllerTableArn &&
    reservation.globalKeySha256 === command.globalKeySha256 &&
    reservation.operationId === command.operationId &&
    reservation.version === 1 && reservation.durable === true &&
    reservation.globallyAuthoritative === true, code);
  const transitionCount = integerAttribute(item, "transitionCount", code);
  requireCondition(transitionCount >= 0 && transitionCount <= 80, code);
  const transitions = [];
  let previousReceiptSha256 = digest(reservation);
  for (let sequence = 0; sequence < transitionCount; sequence += 1) {
    const name = `transition${String(sequence).padStart(2, "0")}`;
    const transition = decodeCanonical(item[name], code);
    requireCondition(exactKeys(transition, [
      "commandSha256", "controllerTableArn", "durable",
      "globallyAuthoritative", "globalKeySha256", "mutationDispatched",
      "operationId", "payloadSha256", "phase", "previousReceiptSha256",
      "schemaVersion", "sequence", "status", "version"
    ]) && transition.schemaVersion ===
        "prooftoact.fresh-cluster-transition.v1" &&
      transition.status === "DURABLE" &&
      transition.commandSha256 === command.commandSha256 &&
      transition.controllerTableArn === command.controllerTableArn &&
      transition.globalKeySha256 === command.globalKeySha256 &&
      transition.operationId === command.operationId &&
      transition.previousReceiptSha256 === previousReceiptSha256 &&
      transition.sequence === sequence && transition.version === sequence + 2 &&
      transition.durable === true &&
      transition.globallyAuthoritative === true &&
      typeof transition.mutationDispatched === "boolean" &&
      HEX_64.test(transition.payloadSha256 ?? "") &&
      /^[A-Z][A-Z0-9_]{0,79}$/u.test(transition.phase ?? ""), code);
    transitions.push(Object.freeze(transition));
    previousReceiptSha256 = digest(transition);
  }
  requireCondition(new Set(transitions.map(({ phase }) => phase)).size ===
    transitions.length, code);
  const finalReceipt = item.finalReceipt === undefined
    ? null : decodeCanonical(item.finalReceipt, code);
  const terminalReceipt = item.terminalReceipt === undefined
    ? null : decodeCanonical(item.terminalReceipt, code);
  requireCondition(!(finalReceipt && terminalReceipt), code);
  const expectedKeys = [
    "command", "commandSha256", "entity", "globalKeySha256",
    "lastReceiptSha256", "operationId", "pk", "reservation", "state",
    "transitionCount", "version",
    ...transitions.map((_, sequence) =>
      `transition${String(sequence).padStart(2, "0")}`),
    ...(finalReceipt ? ["finalReceipt"] : []),
    ...(terminalReceipt ? ["terminalReceipt"] : [])
  ].sort();
  requireCondition(Object.keys(item).sort().join("\n") ===
    expectedKeys.join("\n"), code);
  const version = integerAttribute(item, "version", code);
  const state = stringAttribute(item, "state", code);
  const lastReceiptSha256 = stringAttribute(item, "lastReceiptSha256", code);
  if (finalReceipt) {
    requireCondition(finalReceipt.commandSha256 === command.commandSha256 &&
      finalReceipt.operationId === command.operationId &&
      finalReceipt.previousReceiptSha256 === previousReceiptSha256 &&
      finalReceipt.transitionCount === transitionCount &&
      finalReceipt.status === "PASS" && version === transitionCount + 2 &&
      state === "PASS" && lastReceiptSha256 === digest(finalReceipt), code);
  } else if (terminalReceipt) {
    requireCondition(terminalReceipt.commandSha256 === command.commandSha256 &&
      terminalReceipt.operationId === command.operationId &&
      terminalReceipt.previousReceiptSha256 === previousReceiptSha256 &&
      terminalReceipt.transitionCount === transitionCount &&
      version === transitionCount + 2 &&
      state === terminalReceipt.status &&
      lastReceiptSha256 === digest(terminalReceipt), code);
  } else {
    requireCondition(version === transitionCount + 1 &&
      state === (transitions.at(-1)?.phase ?? "RESERVED") &&
      lastReceiptSha256 === previousReceiptSha256, code);
  }
  return Object.freeze({
    command: storedCommand,
    finalReceipt,
    lastReceiptSha256,
    reservation,
    state,
    terminalReceipt,
    transitionCount,
    transitions: Object.freeze(transitions),
    version
  });
}

export function createFreshClusterAwsProvider({
  clock = Date.now,
  provider,
  secretCoordinates,
  tableArn,
  tableName = TABLE_NAME
}) {
  const tableMatch = TABLE_ARN.exec(tableArn ?? "");
  requireCondition(tableMatch && tableName === TABLE_NAME &&
    typeof clock === "function" &&
    provider && [
      "describeAdminSecret",
      "describeControllerTable",
      "getAdminSecretResourcePolicy",
      "getCallerIdentity",
      "getControllerItem",
      "listControllerTableTags",
      "putControllerItem",
      "readAdminVersionIfPresent",
      "readSecretVersion",
      "updateControllerItem"
    ].every((name) => typeof provider[name] === "function"),
  "FRESH_CLUSTER_AWS_PROVIDER_CONFIGURATION_REJECTED");
  const accountId = tableMatch[1];

  async function getRaw(command) {
    const result = await provider.getControllerItem({
      ConsistentRead: true,
      Key: { pk: s(effectKey(command.globalKeySha256)) },
      ReturnConsumedCapacity: "NONE",
      TableName: tableName
    });
    requireCondition(plainObject(result), "FRESH_CLUSTER_AWS_READ_REJECTED");
    return result.Item ?? null;
  }

  async function reconcile(command, accept, code) {
    let item;
    try {
      item = await getRaw(command);
    } catch (cause) {
      reject("FRESH_CLUSTER_AWS_ACKNOWLEDGEMENT_UNKNOWN_DO_NOT_RETRY", cause);
    }
    requireCondition(item && accept(item), code);
  }

  async function updateOnce(command, input, accept, code) {
    try {
      await provider.updateControllerItem(input);
    } catch {
      await reconcile(command, accept, code);
    }
  }

  async function authenticateMode(command, recovery) {
    const [identityValue, tableValue, tagsValue, material,
      adminDescription, adminPolicy, adminReadback] = await Promise.all([
        provider.getCallerIdentity(),
        provider.describeControllerTable({ TableName: tableName }),
        provider.listControllerTableTags({ ResourceArn: tableArn }),
        readFreshClusterSecretMaterial({ provider, secretCoordinates }),
        provider.describeAdminSecret(),
        provider.getAdminSecretResourcePolicy(),
        provider.readAdminVersionIfPresent()
      ]);
    const identity = normalizeCallerIdentity(identityValue, accountId);
    const table = validateTableReadback(tableValue, tagsValue, tableArn);
    const admin = recovery
      ? validateAdminSecretRecoveryState(
        adminDescription,
        adminPolicy,
        adminReadback,
        secretCoordinates.admin,
        command
      )
      : validateAdminSecretPrestate(
        adminDescription,
        adminPolicy,
        adminReadback,
        secretCoordinates.admin,
        command.operationId
      );
    requireCondition(material.cloudApi.secretValueSha256 ===
      command.creatorTokenValueSha256 &&
      material.auditor.secretValueSha256 ===
        command.auditorTokenValueSha256,
    "FRESH_CLUSTER_TOKEN_BINDING_REJECTED");
    const observedAt = clock();
    requireCondition(Number.isFinite(observedAt),
      "FRESH_CLUSTER_AWS_CLOCK_REJECTED");
    return Object.freeze({
      schemaVersion: "prooftoact.fresh-cluster-authentication.v1",
      status: "AUTHENTICATED_PROVIDER_READBACK",
      adminSecretState: admin.state ?? "ABSENT",
      auditorAuthorityEvidenceSha256: digest({
        auditorAuthorityReceiptSha256:
          command.auditorAuthorityReceiptSha256,
        auditorServiceAccountId: command.auditorServiceAccountId,
        auditorTokenValueSha256: command.auditorTokenValueSha256,
        secretArnSha256: material.auditor.secretArnSha256,
        secretVersionIdSha256: material.auditor.secretVersionIdSha256
      }),
      auditorServiceAccountId: command.auditorServiceAccountId,
      billingAuthorizationSha256: command.billingAuthorizationSha256,
      controllerTableArn: tableArn,
      controllerTableReadbackSha256: digest({ identity, table }),
      creatorAuthorityEvidenceSha256: digest({
        creatorAuthorityReceiptSha256:
          command.creatorAuthorityReceiptSha256,
        creatorProviderReadbackReceiptSha256:
          command.creatorProviderReadbackReceiptSha256,
        creatorServiceAccountId: command.creatorServiceAccountId,
        creatorTokenValueSha256: command.creatorTokenValueSha256,
        secretArnSha256: material.cloudApi.secretArnSha256,
        secretVersionIdSha256: material.cloudApi.secretVersionIdSha256
      }),
      creatorReadbackSha256: digest({
        admin,
        creatorServiceAccountId: command.creatorServiceAccountId,
        recoveryMode: recovery,
        secretArnSha256: material.cloudApi.secretArnSha256,
        secretVersionIdSha256: material.cloudApi.secretVersionIdSha256
      }),
      creatorServiceAccountId: command.creatorServiceAccountId,
      observedAt: new Date(observedAt).toISOString(),
      providerBacked: true
    });
  }

  return Object.freeze({
    async authenticate(command) {
      return authenticateMode(command, false);
    },

    async authenticateRecovery(command) {
      return authenticateMode(command, true);
    },

    async readStrong(request) {
      requireCondition(exactKeys(request, [
        "command",
        "commandSha256",
        "controllerTableArn",
        "globalKeySha256",
        "operationId",
        "stronglyConsistent"
      ]) && request.controllerTableArn === tableArn &&
        request.stronglyConsistent === true &&
        request.command?.commandSha256 === request.commandSha256,
      "FRESH_CLUSTER_AWS_READ_REQUEST_REJECTED");
      const item = await getRaw({
        commandSha256: request.commandSha256,
        globalKeySha256: request.globalKeySha256,
        operationId: request.operationId
      });
      if (item === null) return null;
      return parseStored(item, request.command);
    },

    async reserve({ command, authentication }) {
      const reservedAt = clock();
      requireCondition(Number.isFinite(reservedAt),
        "FRESH_CLUSTER_AWS_CLOCK_REJECTED");
      const reservation = Object.freeze({
        schemaVersion: "prooftoact.fresh-cluster-reservation.v1",
        status: "RESERVED_BEFORE_PROVIDER_IDENTIFIERS",
        authenticationSha256: digest(authentication),
        commandSha256: command.commandSha256,
        controllerTableArn: tableArn,
        durable: true,
        globalKeySha256: command.globalKeySha256,
        globallyAuthoritative: true,
        operationId: command.operationId,
        reservedAt: new Date(reservedAt).toISOString(),
        version: 1
      });
      const item = {
        pk: s(effectKey(command.globalKeySha256)),
        entity: s("FRESH_CLUSTER_V1"),
        command: b(command),
        commandSha256: s(command.commandSha256),
        operationId: s(command.operationId),
        globalKeySha256: s(command.globalKeySha256),
        reservation: b(reservation),
        lastReceiptSha256: s(digest(reservation)),
        state: s("RESERVED"),
        transitionCount: n(0),
        version: n(1)
      };
      try {
        await provider.putControllerItem({
          ConditionExpression: "attribute_not_exists(#pk)",
          ExpressionAttributeNames: { "#pk": "pk" },
          Item: item,
          ReturnConsumedCapacity: "NONE",
          TableName: tableName
        });
      } catch {
        await reconcile(command, (stored) =>
          canonicalJson(decodeCanonical(stored.reservation,
            "FRESH_CLUSTER_AWS_RESERVATION_CONFLICT")) ===
            canonicalJson(reservation),
        "FRESH_CLUSTER_AWS_RESERVATION_CONFLICT");
      }
      return reservation;
    },

    async appendTransition({ command, transition }) {
      const name = `transition${String(transition.sequence).padStart(2, "0")}`;
      requireCondition(/^transition[0-9]{2}$/u.test(name) &&
        transition.version === transition.sequence + 2,
      "FRESH_CLUSTER_AWS_TRANSITION_REJECTED");
      const transitionSha256 = digest(transition);
      const input = {
        ConditionExpression:
          "#version = :expectedVersion AND #last = :expectedLast AND " +
          "attribute_not_exists(#transition)",
        ExpressionAttributeNames: {
          "#last": "lastReceiptSha256",
          "#state": "state",
          "#transition": name,
          "#transitionCount": "transitionCount",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":expectedLast": s(transition.previousReceiptSha256),
          ":expectedVersion": n(transition.version - 1),
          ":last": s(transitionSha256),
          ":state": s(transition.phase),
          ":transition": b(transition),
          ":transitionCount": n(transition.sequence + 1),
          ":version": n(transition.version)
        },
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #transition = :transition, #last = :last, #state = :state, " +
          "#transitionCount = :transitionCount, #version = :version"
      };
      await updateOnce(command, input, (stored) =>
        canonicalJson(decodeCanonical(stored[name],
          "FRESH_CLUSTER_AWS_TRANSITION_CONFLICT")) ===
          canonicalJson(transition),
      "FRESH_CLUSTER_AWS_TRANSITION_CONFLICT");
      return transition;
    },

    async finalize({ command, receipt }) {
      const receiptSha256 = digest(receipt);
      const input = {
        ConditionExpression:
          "#version = :expectedVersion AND #last = :expectedLast AND " +
          "attribute_not_exists(#final)",
        ExpressionAttributeNames: {
          "#final": "finalReceipt",
          "#last": "lastReceiptSha256",
          "#state": "state",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":expectedLast": s(receipt.previousReceiptSha256),
          ":expectedVersion": n(receipt.transitionCount + 1),
          ":final": b(receipt),
          ":last": s(receiptSha256),
          ":state": s("PASS"),
          ":version": n(receipt.transitionCount + 2)
        },
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #final = :final, #last = :last, #state = :state, " +
          "#version = :version"
      };
      await updateOnce(command, input, (stored) =>
        canonicalJson(decodeCanonical(stored.finalReceipt,
          "FRESH_CLUSTER_AWS_FINAL_CONFLICT")) === canonicalJson(receipt),
      "FRESH_CLUSTER_AWS_FINAL_CONFLICT");
      return receipt;
    },

    async terminalize({ command, terminal }) {
      const terminalSha256 = digest(terminal);
      const input = {
        ConditionExpression:
          "#version = :expectedVersion AND #last = :expectedLast AND " +
          "attribute_not_exists(#terminal)",
        ExpressionAttributeNames: {
          "#last": "lastReceiptSha256",
          "#state": "state",
          "#terminal": "terminalReceipt",
          "#version": "version"
        },
        ExpressionAttributeValues: {
          ":expectedLast": s(terminal.previousReceiptSha256),
          ":expectedVersion": n(terminal.transitionCount + 1),
          ":last": s(terminalSha256),
          ":state": s(terminal.status),
          ":terminal": b(terminal),
          ":version": n(terminal.transitionCount + 2)
        },
        Key: { pk: s(effectKey(command.globalKeySha256)) },
        ReturnConsumedCapacity: "NONE",
        TableName: tableName,
        UpdateExpression:
          "SET #terminal = :terminal, #last = :last, #state = :state, " +
          "#version = :version"
      };
      await updateOnce(command, input, (stored) =>
        canonicalJson(decodeCanonical(stored.terminalReceipt,
          "FRESH_CLUSTER_AWS_TERMINAL_CONFLICT")) === canonicalJson(terminal),
      "FRESH_CLUSTER_AWS_TERMINAL_CONFLICT");
      return terminal;
    }
  });
}

export function normalizeFreshClusterAdminSealReadback({
  command,
  coordinate,
  description,
  readback,
  resourcePolicy,
  secretValueSha256
}) {
  const code = "FRESH_CLUSTER_AWS_ADMIN_SECRET_SEAL_READBACK_REJECTED";
  const accepted = normalizeSecretReadback(readback, coordinate, 16 * 1024);
  const expectedName = `prooftoact/fresh-primary/admin-${command.operationId}`;
  const tags = secretUserTags(description?.Tags, code);
  requireCondition(accepted.secretValueSha256 === secretValueSha256 &&
    description?.ARN === coordinate.arn && description.Name === expectedName &&
    description.DeletedDate === undefined &&
    description.RotationEnabled !== true &&
    description.KmsKeyId === undefined &&
    canonicalJson(tags) === canonicalJson({
      OperationId: command.operationId,
      Project: "ProofToAct",
      Purpose: "FreshBootstrapAdmin"
    }) && resourcePolicy?.ARN === coordinate.arn &&
    resourcePolicy.ResourcePolicy === undefined &&
    plainObject(description.VersionIdsToStages) &&
    canonicalJson(description.VersionIdsToStages[coordinate.versionId]) ===
      canonicalJson(["AWSCURRENT"]) &&
    Object.keys(description.VersionIdsToStages).length === 1, code);
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-cluster-admin-seal.v1",
    status: "SEALED",
    createdAt: accepted.createdAt,
    immutableVersion: true,
    operationId: command.operationId,
    provider: "AWS_SECRETS_MANAGER",
    providerBacked: true,
    secretArnSha256: accepted.secretArnSha256,
    secretValueSha256: accepted.secretValueSha256,
    secretVersionIdSha256: accepted.secretVersionIdSha256
  });
}

export const __test = Object.freeze({
  canonicalJson,
  decodeCanonical,
  digest,
  effectKey,
  normalizeCallerIdentity,
  normalizeSecretReadback,
  parseStored,
  validateAdminSecretPrestate,
  validateTableReadback
});
