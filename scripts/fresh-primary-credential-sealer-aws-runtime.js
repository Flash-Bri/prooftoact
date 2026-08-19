const REGION = "us-east-1";
const OPERATION_ID =
  "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SECRET_ARN =
  new RegExp(
    "^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact/" +
    "(?:fresh-cluster/auditor|fresh-primary/(?:cloud-api|runtime-credentials|" +
    `admin-${OPERATION_ID}|recovery-signer-${OPERATION_ID})|` +
    "gate2/(?:managed-mcp|recovery-publisher))-[A-Za-z0-9]{6}$",
    "u"
  );
const VERSION_ID = /^[A-Za-z0-9_-]{32,64}$/u;

function reject(code) {
  throw new Error(code);
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function exactKeys(value, expected) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && Object.keys(value).sort().join("\n") ===
      [...expected].sort().join("\n");
}

function fixedSdkOptions() {
  return Object.freeze({
    maxAttempts: 1,
    region: REGION
  });
}

function exactArn(value, allowed) {
  requireCondition(typeof value === "string" && SECRET_ARN.test(value) &&
    allowed.has(value), "FRESH_CREDENTIAL_AWS_ARN_REJECTED");
  return value;
}

export async function createFreshPrimaryCredentialSealerAwsRuntime({
  secretArns
}) {
  const code = "FRESH_CREDENTIAL_AWS_CONFIGURATION_REJECTED";
  requireCondition(Array.isArray(secretArns) && secretArns.length === 7 &&
    new Set(secretArns).size === 7 &&
    secretArns.every((arn) => SECRET_ARN.test(arn ?? "")), code);
  const allowed = new Set(secretArns);
  const [secrets, smithy, sts] = await Promise.all([
    import("@aws-sdk/client-secrets-manager"),
    import("@smithy/node-http-handler"),
    import("@aws-sdk/client-sts")
  ]);
  const requestHandler = new smithy.NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 10_000
  });
  const options = { ...fixedSdkOptions(), requestHandler };
  const secretStore = new secrets.SecretsManagerClient(options);
  const identity = new sts.STSClient(options);

  return Object.freeze({
    describeSecret(input) {
      requireCondition(exactKeys(input, ["arn"]),
        "FRESH_CREDENTIAL_AWS_DESCRIBE_REJECTED");
      return secretStore.send(new secrets.DescribeSecretCommand({
        SecretId: exactArn(input.arn, allowed)
      }));
    },
    getCallerIdentity() {
      return identity.send(new sts.GetCallerIdentityCommand({}));
    },
    getSecretResourcePolicy(input) {
      requireCondition(exactKeys(input, ["arn"]),
        "FRESH_CREDENTIAL_AWS_POLICY_REJECTED");
      return secretStore.send(new secrets.GetResourcePolicyCommand({
        SecretId: exactArn(input.arn, allowed)
      }));
    },
    listSecretVersions(input) {
      requireCondition(exactKeys(input, ["arn", "nextToken"]) &&
        (input.nextToken === null || typeof input.nextToken === "string" &&
          input.nextToken.length > 0),
      "FRESH_CREDENTIAL_AWS_VERSION_LIST_REJECTED");
      return secretStore.send(new secrets.ListSecretVersionIdsCommand({
        IncludeDeprecated: true,
        MaxResults: 100,
        ...(input.nextToken === null ? {} : { NextToken: input.nextToken }),
        SecretId: exactArn(input.arn, allowed)
      }));
    },
    putSecretVersion(input) {
      requireCondition(exactKeys(input, [
        "arn", "clientRequestToken", "secretString"
      ]) && VERSION_ID.test(input.clientRequestToken ?? "") &&
        typeof input.secretString === "string" &&
        Buffer.byteLength(input.secretString, "utf8") > 0 &&
        Buffer.byteLength(input.secretString, "utf8") <= 64 * 1024,
      "FRESH_CREDENTIAL_AWS_PUT_REJECTED");
      return secretStore.send(new secrets.PutSecretValueCommand({
        ClientRequestToken: input.clientRequestToken,
        SecretId: exactArn(input.arn, allowed),
        SecretString: input.secretString,
        VersionStages: ["AWSCURRENT"]
      }));
    },
    async readSecretVersion(input) {
      requireCondition(exactKeys(input, ["arn", "versionId"]) &&
        VERSION_ID.test(input.versionId ?? ""),
      "FRESH_CREDENTIAL_AWS_READ_REJECTED");
      try {
        return await secretStore.send(new secrets.GetSecretValueCommand({
          SecretId: exactArn(input.arn, allowed),
          VersionId: input.versionId,
          VersionStage: "AWSCURRENT"
        }));
      } catch (cause) {
        if (cause?.name === "ResourceNotFoundException") return null;
        throw cause;
      }
    }
  });
}

export const __test = Object.freeze({
  SECRET_ARN,
  VERSION_ID,
  exactArn,
  fixedSdkOptions
});
