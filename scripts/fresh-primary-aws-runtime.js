const TABLE_NAME = "prooftoact-release-controller";
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u;
const SECRET_ARN =
  /^arn:aws:secretsmanager:us-east-1:([0-9]{12}):secret:prooftoact\/fresh-primary\/(?:admin-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[A-Za-z0-9]{6}|cloud-api-[A-Za-z0-9]{6}|runtime-credentials-[A-Za-z0-9]{6}|recovery-signer-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[A-Za-z0-9]{6})$/u;
const FRESH_PRIMARY_KEY = /^FRESH_PRIMARY#[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_CLOUD_RESPONSE_BYTES = 512 * 1024;

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
  "FRESH_PRIMARY_AWS_EXPLICIT_CREDENTIALS_REJECTED");
  return Object.freeze({ ...credentials });
}

function validateSecretCoordinates(value, accountId) {
  const code = "FRESH_PRIMARY_AWS_RUNTIME_SECRET_COORDINATES_REJECTED";
  requireCondition(exactKeys(value, [
    "admin", "cloudApi", "credential", "signer"
  ]), code);
  const coordinates = Object.values(value);
  requireCondition(coordinates.length === 4 &&
    new Set(coordinates.map((item) => item?.arn)).size === 4 &&
    coordinates.every((item) => exactKeys(item, ["arn", "versionId"]) &&
      SECRET_ARN.exec(item.arn ?? "")?.[1] === accountId &&
      /^[A-Za-z0-9_-]{32,64}$/u.test(item.versionId ?? "")), code);
  const adminOperation = /\/admin-([0-9a-f-]{36})-[A-Za-z0-9]{6}$/u
    .exec(value.admin.arn)?.[1];
  const signerOperation =
    /\/recovery-signer-([0-9a-f-]{36})-[A-Za-z0-9]{6}$/u
      .exec(value.signer.arn)?.[1];
  requireCondition(UUID.test(adminOperation ?? "") &&
    adminOperation === signerOperation, code);
  return Object.freeze(Object.fromEntries(Object.entries(value).map(
    ([name, item]) => [name, Object.freeze({ ...item })]
  )));
}

function requireExactTable(input, tableName = TABLE_NAME) {
  requireCondition(plainObject(input) && input.TableName === tableName,
    "FRESH_PRIMARY_AWS_RUNTIME_TABLE_REJECTED");
  return input;
}

function requireExactKey(input, tableName = TABLE_NAME) {
  requireExactTable(input, tableName);
  requireCondition(exactKeys(input.Key, ["pk"]) &&
    FRESH_PRIMARY_KEY.test(input.Key.pk?.S ?? ""),
  "FRESH_PRIMARY_AWS_RUNTIME_KEY_REJECTED");
  return input;
}

function requirePut(input, tableName = TABLE_NAME) {
  requireExactTable(input, tableName);
  requireCondition(input.ConditionExpression === "attribute_not_exists(#pk)" &&
    exactKeys(input.ExpressionAttributeNames, ["#pk"]) &&
    input.ExpressionAttributeNames["#pk"] === "pk" &&
    FRESH_PRIMARY_KEY.test(input.Item?.pk?.S ?? "") &&
    input.ReturnConsumedCapacity === "NONE",
  "FRESH_PRIMARY_AWS_RUNTIME_PUT_REJECTED");
  return input;
}

function requireUpdate(input, tableName = TABLE_NAME) {
  requireExactKey(input, tableName);
  requireCondition(typeof input.ConditionExpression === "string" &&
    input.ConditionExpression.length > 0 &&
    typeof input.UpdateExpression === "string" &&
    input.UpdateExpression.startsWith("SET ") &&
    plainObject(input.ExpressionAttributeNames) &&
    plainObject(input.ExpressionAttributeValues) &&
    input.ReturnConsumedCapacity === "NONE",
  "FRESH_PRIMARY_AWS_RUNTIME_UPDATE_REJECTED");
  return input;
}

function requireSecret(input, allowed) {
  requireCondition(exactKeys(input, ["arn", "versionId"]) &&
    allowed.has(`${input.arn}\n${input.versionId}`),
  "FRESH_PRIMARY_AWS_RUNTIME_SECRET_REJECTED");
  return {
    SecretId: input.arn,
    VersionId: input.versionId,
    VersionStage: "AWSCURRENT"
  };
}

function requireSignerSecret(input, coordinate) {
  requireCondition(exactKeys(input, [
    "clientRequestToken", "secretString"
  ]) && input.clientRequestToken === coordinate.versionId &&
    typeof input.secretString === "string" &&
    Buffer.byteLength(input.secretString, "utf8") > 0 &&
    Buffer.byteLength(input.secretString, "utf8") <= 32 * 1024,
  "FRESH_PRIMARY_AWS_RUNTIME_SIGNER_SECRET_REJECTED");
  return {
    ClientRequestToken: coordinate.versionId,
    SecretId: coordinate.arn,
    SecretString: input.secretString,
    VersionStages: ["AWSCURRENT"]
  };
}

async function boundedJsonResponse(response) {
  const code = "FRESH_PRIMARY_COCKROACH_CLOUD_RESPONSE_REJECTED";
  requireCondition(response && response.status === 200 &&
    response.redirected === false && response.url.startsWith(
      "https://cockroachlabs.cloud/api/v1/clusters/"
    ), code);
  const contentType = response.headers?.get("content-type") ?? "";
  const contentLength = response.headers?.get("content-length");
  requireCondition(/^application\/json(?:\s*;|$)/iu.test(contentType) &&
    (contentLength === null ||
      /^(?:0|[1-9][0-9]*)$/u.test(contentLength) &&
      Number(contentLength) <= MAX_CLOUD_RESPONSE_BYTES), code);
  const reader = response.body?.getReader();
  requireCondition(reader && typeof reader.read === "function", code);
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    requireCondition(value instanceof Uint8Array, code);
    length += value.length;
    requireCondition(length > 0 && length <= MAX_CLOUD_RESPONSE_BYTES, code);
    chunks.push(Buffer.from(value));
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks, length).toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(plainObject(parsed), code);
  return parsed;
}

export async function createFreshPrimaryAwsRuntime({
  credentials,
  dynamoDbRuntime,
  fetchImpl = globalThis.fetch,
  region,
  secretCoordinates,
  tableArn,
  tableName = TABLE_NAME
}) {
  const tableMatch = TABLE_ARN.exec(tableArn ?? "");
  const explicit = validateExplicitCredentials(credentials);
  requireCondition(tableMatch && region === "us-east-1" &&
    tableName === TABLE_NAME && typeof fetchImpl === "function",
  "FRESH_PRIMARY_AWS_RUNTIME_CONFIGURATION_REJECTED");
  const coordinates = validateSecretCoordinates(
    secretCoordinates, tableMatch[1]
  );
  const allowedSecrets = new Set(Object.values(coordinates).map((item) =>
    `${item.arn}\n${item.versionId}`));
  requireCondition(dynamoDbRuntime && [
    "describeReleaseControlTable",
    "getReleaseControlItem",
    "listReleaseControlTags",
    "putReleaseControlItem",
    "updateReleaseControlItem"
  ].every((name) => typeof dynamoDbRuntime[name] === "function"),
  "FRESH_PRIMARY_AWS_RUNTIME_CONFIGURATION_REJECTED");
  const [secrets, smithy, sts] = await Promise.all([
    import("@aws-sdk/client-secrets-manager"),
    import("@smithy/node-http-handler"),
    import("@aws-sdk/client-sts")
  ]);
  const requestHandler = new smithy.NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 10_000
  });
  const clientOptions = {
    credentials: explicit,
    ...fixedSdkOptions(),
    maxAttempts: 1,
    region,
    requestHandler
  };
  const secretStore = new secrets.SecretsManagerClient(clientOptions);
  const identity = new sts.STSClient(clientOptions);

  return Object.freeze({
    async describeFreshPrimaryTable(input) {
      return dynamoDbRuntime.describeReleaseControlTable(
        requireExactTable(input, tableName)
      );
    },

    async getFreshPrimaryCallerIdentity() {
      return identity.send(new sts.GetCallerIdentityCommand({}));
    },

    async getFreshPrimaryItem(input) {
      requireExactKey(input, tableName);
      requireCondition(input.ConsistentRead === true &&
        input.ReturnConsumedCapacity === "NONE",
      "FRESH_PRIMARY_AWS_RUNTIME_READ_REJECTED");
      return dynamoDbRuntime.getReleaseControlItem(input);
    },

    async listFreshPrimaryTableTags(input) {
      requireCondition(exactKeys(input, ["ResourceArn"]) &&
        input.ResourceArn === tableArn,
      "FRESH_PRIMARY_AWS_RUNTIME_TABLE_ARN_REJECTED");
      return dynamoDbRuntime.listReleaseControlTags(input);
    },

    async putFreshPrimaryItem(input) {
      return dynamoDbRuntime.putReleaseControlItem(
        requirePut(input, tableName)
      );
    },

    async readCockroachCluster({ bearerToken, clusterId }) {
      requireCondition(UUID.test(clusterId ?? "") &&
        typeof bearerToken === "string" && bearerToken.length >= 20 &&
        bearerToken.length <= 4096 &&
        !/[\u0000-\u0020\u007f]/u.test(bearerToken),
      "FRESH_PRIMARY_COCKROACH_CLOUD_REQUEST_REJECTED");
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      let response;
      try {
        response = await fetchImpl(
          `https://cockroachlabs.cloud/api/v1/clusters/${clusterId}`,
          {
            cache: "no-store",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${bearerToken}`,
              "Cc-Version": "2024-09-16"
            },
            method: "GET",
            redirect: "error",
            referrerPolicy: "no-referrer",
            signal: controller.signal
          }
        );
      } catch (cause) {
        reject("FRESH_PRIMARY_COCKROACH_CLOUD_REQUEST_FAILED", cause);
      } finally {
        clearTimeout(timeout);
      }
      return boundedJsonResponse(response);
    },

    async readSecretVersion(input) {
      return secretStore.send(new secrets.GetSecretValueCommand(
        requireSecret(input, allowedSecrets)
      ));
    },

    async describeRecoverySignerSecret() {
      return secretStore.send(new secrets.DescribeSecretCommand({
        SecretId: coordinates.signer.arn
      }));
    },

    async getRecoverySignerResourcePolicy() {
      return secretStore.send(new secrets.GetResourcePolicyCommand({
        SecretId: coordinates.signer.arn
      }));
    },

    async readRecoverySignerVersionIfPresent() {
      try {
        return await secretStore.send(new secrets.GetSecretValueCommand(
          requireSecret(coordinates.signer, allowedSecrets)
        ));
      } catch (cause) {
        if (cause?.name === "ResourceNotFoundException") return null;
        throw cause;
      }
    },

    async putRecoverySignerSecret(input) {
      return secretStore.send(new secrets.PutSecretValueCommand(
        requireSignerSecret(input, coordinates.signer)
      ));
    },

    async updateFreshPrimaryItem(input) {
      return dynamoDbRuntime.updateReleaseControlItem(
        requireUpdate(input, tableName)
      );
    }
  });
}

export const __test = Object.freeze({
  boundedJsonResponse,
  fixedSdkOptions,
  requireExactKey,
  requirePut,
  requireSecret,
  requireUpdate,
  validateExplicitCredentials,
  validateSecretCoordinates
});
