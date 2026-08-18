function requireCondition(condition, code) {
  if (!condition) throw new Error(code);
}

// This factory accepts only explicit temporary credentials; no chain is exposed.

const TABLE_NAME = "prooftoact-release-controller";
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;
const ASSUMED_ROLE_ARN =
  /^arn:aws:sts::([0-9]{12}):assumed-role\/([A-Za-z0-9+=,.@_-]{1,64})\/([A-Za-z0-9+=,.@_-]{2,64})$/u;
const ASSUMED_ROLE_USER_ID =
  /^(AROA[A-Z0-9]{16}):([A-Za-z0-9+=,.@_-]{2,64})$/u;

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
  requireCondition(
    credentials && typeof credentials === "object" &&
      typeof credentials.accessKeyId === "string" &&
      /^ASIA[A-Z0-9]{16}$/u.test(credentials.accessKeyId) &&
      typeof credentials.secretAccessKey === "string" &&
      credentials.secretAccessKey.length === 40 &&
      typeof credentials.sessionToken === "string" &&
      credentials.sessionToken.length >= 16 &&
      Object.keys(credentials).sort().join("\n") ===
        ["accessKeyId", "secretAccessKey", "sessionToken"].sort().join("\n"),
    "RELEASE_CONTROL_AWS_EXPLICIT_CREDENTIALS_REJECTED"
  );
  return Object.freeze({ ...credentials });
}

function requireExactTable(input, tableName = TABLE_NAME) {
  requireCondition(input && typeof input === "object" && !Array.isArray(input) &&
    input.TableName === tableName, "RELEASE_CONTROL_AWS_TABLE_REJECTED");
  return input;
}

function requireExactTransaction(input, tableName = TABLE_NAME) {
  requireCondition(input && typeof input === "object" &&
    Array.isArray(input.TransactItems) && input.TransactItems.length === 2 &&
    input.TransactItems.every((entry) => {
      const operations = [entry?.Put, entry?.Update].filter(Boolean);
      return operations.length === 1 && operations[0].TableName === tableName;
    }), "RELEASE_CONTROL_AWS_TRANSACTION_REJECTED");
  return input;
}

function normalizeCallerIdentity(value) {
  const arnMatch = ASSUMED_ROLE_ARN.exec(value?.Arn ?? "");
  const userMatch = ASSUMED_ROLE_USER_ID.exec(value?.UserId ?? "");
  requireCondition(/^[0-9]{12}$/u.test(value?.Account ?? "") && arnMatch &&
    userMatch && arnMatch[1] === value.Account && arnMatch[3] === userMatch[2],
  "RELEASE_CONTROL_AWS_CALLER_IDENTITY_REJECTED");
  return Object.freeze({
    accountId: value.Account,
    assumedRoleArn: value.Arn,
    roleId: userMatch[1],
    roleName: arnMatch[2],
    sessionName: arnMatch[3]
  });
}

export async function createReleaseControlAwsRuntime({
  credentials,
  region,
  tableArn,
  tableName = TABLE_NAME
}) {
  const explicit = validateExplicitCredentials(credentials);
  requireCondition(region === "us-east-1", "RELEASE_CONTROL_AWS_REGION_REJECTED");
  requireCondition(tableName === TABLE_NAME && TABLE_ARN.test(tableArn ?? ""),
    "RELEASE_CONTROL_AWS_TABLE_IDENTITY_REJECTED");
  const [dynamodb, smithy, sts] = await Promise.all([
    import("@aws-sdk/client-dynamodb"),
    import("@smithy/node-http-handler"),
    import("@aws-sdk/client-sts")
  ]);
  const requestHandler = new smithy.NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 10_000
  });
  const client = new dynamodb.DynamoDBClient({
    credentials: explicit,
    ...fixedSdkOptions(),
    maxAttempts: 1,
    region,
    requestHandler
  });
  const identityClient = new sts.STSClient({
    credentials: explicit,
    ...fixedSdkOptions(),
    maxAttempts: 1,
    region,
    requestHandler
  });
  return Object.freeze({
    async describeReleaseControlTable(input) {
      return client.send(new dynamodb.DescribeTableCommand(
        requireExactTable(input, tableName)
      ));
    },
    async getReleaseControlItem(input) {
      return client.send(new dynamodb.GetItemCommand(
        requireExactTable(input, tableName)
      ));
    },
    async getReleaseControlCallerIdentity() {
      return normalizeCallerIdentity(await identityClient.send(
        new sts.GetCallerIdentityCommand({})
      ));
    },
    async listReleaseControlTags(input) {
      requireCondition(input && typeof input === "object" &&
        input.ResourceArn === tableArn,
      "RELEASE_CONTROL_AWS_TABLE_ARN_REJECTED");
      return client.send(new dynamodb.ListTagsOfResourceCommand(input));
    },
    async transactReleaseControlItems(input) {
      return client.send(new dynamodb.TransactWriteItemsCommand(
        requireExactTransaction(input, tableName)
      ));
    },
    async updateReleaseControlItem(input) {
      return client.send(new dynamodb.UpdateItemCommand(
        requireExactTable(input, tableName)
      ));
    }
  });
}

export const __test = Object.freeze({
  fixedSdkOptions,
  normalizeCallerIdentity,
  requireExactTable,
  requireExactTransaction,
  validateExplicitCredentials
});
