import { createHash } from "node:crypto";

import { SecretsManagerClient, GetSecretValueCommand } from
  "@aws-sdk/client-secrets-manager";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { createReleaseControlAwsRuntime } from
  "../../release-control/src/release-control-aws-runtime.js";
import { createPrivateRecoveryQueryAwsStore } from
  "./private-recovery-query-aws-store.js";

const SECRET_ARN =
  /^arn:aws:secretsmanager:us-east-1:[0-9]{12}:secret:prooftoact\/private-recovery-query\/managed-mcp-[A-Za-z0-9]{6}$/u;
const TABLE_ARN =
  /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u;

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function explicitCredentials(environment) {
  const value = {
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  };
  requireCondition(/^ASIA[A-Z0-9]{16}$/u.test(value.accessKeyId ?? "") &&
    typeof value.secretAccessKey === "string" &&
    value.secretAccessKey.length === 40 &&
    typeof value.sessionToken === "string" &&
    value.sessionToken.length >= 16,
  "PRIVATE_RECOVERY_QUERY_AWS_CREDENTIALS_REJECTED");
  return Object.freeze(value);
}

function fixedSdkOptions(credentials) {
  return {
    authSchemePreference: ["sigv4"],
    credentials,
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    region: "us-east-1",
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 10_000
    }),
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
}

export async function createPrivateRecoveryQueryAwsRuntime({
  environment = process.env
} = {}) {
  requireCondition(environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1" &&
    TABLE_ARN.test(environment.RELEASE_CONTROL_TABLE_ARN ?? "") &&
    SECRET_ARN.test(environment.MCP_SECRET_ARN ?? "") &&
    /^[A-Za-z0-9_-]{32,64}$/u.test(
      environment.MCP_SECRET_VERSION_ID ?? ""
    ), "PRIVATE_RECOVERY_QUERY_AWS_ENVIRONMENT_REJECTED");
  const credentials = explicitCredentials(environment);
  const releaseControlRuntime = await createReleaseControlAwsRuntime({
    credentials,
    region: "us-east-1",
    tableArn: environment.RELEASE_CONTROL_TABLE_ARN
  });
  const secrets = new SecretsManagerClient(fixedSdkOptions(credentials));
  const secretArn = environment.MCP_SECRET_ARN;
  const secretVersionId = environment.MCP_SECRET_VERSION_ID;
  return Object.freeze({
    store: createPrivateRecoveryQueryAwsStore({
      runtime: releaseControlRuntime
    }),
    secretReader: Object.freeze({
      async readExactVersion() {
        const value = await secrets.send(new GetSecretValueCommand({
          SecretId: secretArn,
          VersionId: secretVersionId,
          VersionStage: "AWSCURRENT"
        }));
        requireCondition(value?.ARN === secretArn &&
          value.VersionId === secretVersionId &&
          Array.isArray(value.VersionStages) &&
          value.VersionStages.includes("AWSCURRENT") &&
          typeof value.SecretString === "string" &&
          value.SecretBinary === undefined,
        "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED");
        const bytes = Buffer.from(value.SecretString, "utf8");
        requireCondition(bytes.length >= 24 && bytes.length <= 4096 &&
          !/[\u0000-\u0020\u007f]/u.test(value.SecretString),
        "PRIVATE_RECOVERY_QUERY_SECRET_READBACK_REJECTED");
        return Object.freeze({
          secretArnSha256: sha256(secretArn),
          secretValue: value.SecretString,
          secretValueSha256: sha256(bytes),
          secretVersionIdSha256: sha256(secretVersionId)
        });
      }
    })
  });
}

export const __test = Object.freeze({
  explicitCredentials,
  fixedSdkOptions,
  sha256
});
