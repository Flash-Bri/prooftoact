const TABLE_NAME = "prooftoact-release-controller";
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u;
const FRESH_CLUSTER_KEY = /^FRESH_CLUSTER#[0-9a-f]{64}$/u;
const VERSION_ID = /^[A-Za-z0-9_-]{32,64}$/u;

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

function fixedSdkOptions() {
  return {
    authSchemePreference: ["sigv4"],
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
}

function validateExplicitCredentials(credentials) {
  requireCondition(exactKeys(credentials, [
    "accessKeyId", "secretAccessKey", "sessionToken"
  ]) && /^ASIA[A-Z0-9]{16}$/u.test(credentials.accessKeyId ?? "") &&
    typeof credentials.secretAccessKey === "string" &&
    credentials.secretAccessKey.length === 40 &&
    typeof credentials.sessionToken === "string" &&
    credentials.sessionToken.length >= 16,
  "FRESH_CLUSTER_AWS_EXPLICIT_CREDENTIALS_REJECTED");
  return Object.freeze({ ...credentials });
}

function coordinatePattern(name, operationId) {
  const suffix = "[A-Za-z0-9]{6}";
  const patterns = {
    admin: new RegExp(
      `^prooftoact/fresh-primary/admin-${operationId}-${suffix}$`, "u"
    ),
    auditor:
      /^prooftoact\/fresh-cluster\/auditor-[A-Za-z0-9]{6}$/u,
    cloudApi:
      /^prooftoact\/fresh-primary\/cloud-api-[A-Za-z0-9]{6}$/u,
    credential:
      /^prooftoact\/fresh-primary\/runtime-credentials-[A-Za-z0-9]{6}$/u,
    mcp:
      /^prooftoact\/gate2\/managed-mcp-[A-Za-z0-9]{6}$/u,
    publisher:
      /^prooftoact\/gate2\/recovery-publisher-[A-Za-z0-9]{6}$/u,
    signer: new RegExp(
      `^prooftoact/fresh-primary/recovery-signer-${operationId}-${suffix}$`,
      "u"
    )
  };
  return patterns[name];
}

function validateSecretCoordinates(value, accountId, operationId) {
  const code = "FRESH_CLUSTER_AWS_SECRET_COORDINATES_REJECTED";
  requireCondition(exactKeys(value, [
    "admin", "auditor", "cloudApi", "credential", "mcp", "publisher",
    "signer"
  ]), code);
  const accepted = Object.fromEntries(Object.entries(value).map(
    ([name, item]) => {
      requireCondition(exactKeys(item, ["arn", "versionId"]) &&
        VERSION_ID.test(item.versionId ?? ""), code);
      const prefix =
        `arn:aws:secretsmanager:us-east-1:${accountId}:secret:`;
      requireCondition(item.arn.startsWith(prefix) &&
        coordinatePattern(name, operationId).test(item.arn.slice(prefix.length)),
      code);
      return [name, Object.freeze({ ...item })];
    }
  ));
  requireCondition(new Set(Object.values(accepted).map((item) => item.arn)).size
    === 7, code);
  return Object.freeze(accepted);
}

function exactTable(input, tableName) {
  requireCondition(plainObject(input) && input.TableName === tableName,
    "FRESH_CLUSTER_AWS_TABLE_REJECTED");
  return input;
}

function exactKey(input, tableName) {
  exactTable(input, tableName);
  requireCondition(exactKeys(input.Key, ["pk"]) &&
    FRESH_CLUSTER_KEY.test(input.Key.pk?.S ?? ""),
  "FRESH_CLUSTER_AWS_KEY_REJECTED");
  return input;
}

function exactPut(input, tableName) {
  exactTable(input, tableName);
  requireCondition(input.ConditionExpression === "attribute_not_exists(#pk)" &&
    input.ExpressionAttributeNames?.["#pk"] === "pk" &&
    FRESH_CLUSTER_KEY.test(input.Item?.pk?.S ?? "") &&
    input.ReturnConsumedCapacity === "NONE",
  "FRESH_CLUSTER_AWS_PUT_REJECTED");
  return input;
}

function exactUpdate(input, tableName) {
  exactKey(input, tableName);
  requireCondition(typeof input.ConditionExpression === "string" &&
    input.ConditionExpression.length > 0 &&
    typeof input.UpdateExpression === "string" &&
    input.UpdateExpression.startsWith("SET ") &&
    plainObject(input.ExpressionAttributeNames) &&
    plainObject(input.ExpressionAttributeValues) &&
    input.ReturnConsumedCapacity === "NONE",
  "FRESH_CLUSTER_AWS_UPDATE_REJECTED");
  return input;
}

function exactSecret(input, coordinates) {
  requireCondition(exactKeys(input, ["arn", "versionId"]),
    "FRESH_CLUSTER_AWS_SECRET_REJECTED");
  const accepted = Object.values(coordinates).some((item) =>
    item.arn === input.arn && item.versionId === input.versionId);
  requireCondition(accepted, "FRESH_CLUSTER_AWS_SECRET_REJECTED");
  return {
    SecretId: input.arn,
    VersionId: input.versionId,
    VersionStage: "AWSCURRENT"
  };
}

function adminSecretInput(value, coordinate) {
  const code = "FRESH_CLUSTER_AWS_ADMIN_SECRET_REJECTED";
  requireCondition(exactKeys(value, ["clientRequestToken", "secretString"]) &&
    value.clientRequestToken === coordinate.versionId &&
    typeof value.secretString === "string" &&
    Buffer.byteLength(value.secretString, "utf8") > 0 &&
    Buffer.byteLength(value.secretString, "utf8") <= 16 * 1024, code);
  return {
    ClientRequestToken: coordinate.versionId,
    SecretId: coordinate.arn,
    SecretString: value.secretString,
    VersionStages: ["AWSCURRENT"]
  };
}

export async function createFreshClusterAwsRuntime({
  credentials,
  dynamoDbRuntime,
  operationId,
  region,
  secretCoordinates,
  tableArn,
  tableName = TABLE_NAME
}) {
  const tableMatch = TABLE_ARN.exec(tableArn ?? "");
  requireCondition(tableMatch && region === "us-east-1" &&
    tableName === TABLE_NAME &&
    dynamoDbRuntime && [
      "describeReleaseControlTable",
      "getReleaseControlItem",
      "listReleaseControlTags",
      "putReleaseControlItem",
      "updateReleaseControlItem"
    ].every((name) => typeof dynamoDbRuntime[name] === "function") &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
      .test(operationId ?? ""),
  "FRESH_CLUSTER_AWS_CONFIGURATION_REJECTED");
  const explicit = validateExplicitCredentials(credentials);
  const coordinates = validateSecretCoordinates(
    secretCoordinates, tableMatch[1], operationId
  );
  const [secrets, smithy, sts] = await Promise.all([
    import("@aws-sdk/client-secrets-manager"),
    import("@smithy/node-http-handler"),
    import("@aws-sdk/client-sts")
  ]);
  const requestHandler = new smithy.NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 10_000
  });
  const options = {
    credentials: explicit,
    ...fixedSdkOptions(),
    maxAttempts: 1,
    region,
    requestHandler
  };
  const secretStore = new secrets.SecretsManagerClient(options);
  const identity = new sts.STSClient(options);

  return Object.freeze({
    describeControllerTable(input) {
      return dynamoDbRuntime.describeReleaseControlTable(
        exactTable(input, tableName)
      );
    },
    getCallerIdentity() {
      return identity.send(new sts.GetCallerIdentityCommand({}));
    },
    getControllerItem(input) {
      exactKey(input, tableName);
      requireCondition(input.ConsistentRead === true &&
        input.ReturnConsumedCapacity === "NONE",
      "FRESH_CLUSTER_AWS_READ_REJECTED");
      return dynamoDbRuntime.getReleaseControlItem(input);
    },
    listControllerTableTags(input) {
      requireCondition(exactKeys(input, ["ResourceArn"]) &&
        input.ResourceArn === tableArn,
      "FRESH_CLUSTER_AWS_TABLE_ARN_REJECTED");
      return dynamoDbRuntime.listReleaseControlTags(input);
    },
    putControllerItem(input) {
      return dynamoDbRuntime.putReleaseControlItem(exactPut(input, tableName));
    },
    updateControllerItem(input) {
      return dynamoDbRuntime.updateReleaseControlItem(
        exactUpdate(input, tableName)
      );
    },
    readSecretVersion(input) {
      return secretStore.send(new secrets.GetSecretValueCommand(
        exactSecret(input, coordinates)
      ));
    },
    describeAdminSecret() {
      return secretStore.send(new secrets.DescribeSecretCommand({
        SecretId: coordinates.admin.arn
      }));
    },
    getAdminSecretResourcePolicy() {
      return secretStore.send(new secrets.GetResourcePolicyCommand({
        SecretId: coordinates.admin.arn
      }));
    },
    async readAdminVersionIfPresent() {
      try {
        return await secretStore.send(new secrets.GetSecretValueCommand(
          exactSecret(coordinates.admin, coordinates)
        ));
      } catch (cause) {
        if (cause?.name === "ResourceNotFoundException") return null;
        throw cause;
      }
    },
    putAdminSecret(input) {
      return secretStore.send(new secrets.PutSecretValueCommand(
        adminSecretInput(input, coordinates.admin)
      ));
    }
  });
}

export const __test = Object.freeze({
  adminSecretInput,
  exactKey,
  exactPut,
  exactSecret,
  exactUpdate,
  fixedSdkOptions,
  validateExplicitCredentials,
  validateSecretCoordinates
});
