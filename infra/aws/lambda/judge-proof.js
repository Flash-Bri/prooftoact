import { SecretsManagerClient, GetSecretValueCommand } from
  "@aws-sdk/client-secrets-manager";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { createPublicJudgeProofHandler } from
  "../../../src/cloud/public-judge-proof.js";

function reject(code) {
  throw new Error(code);
}

function explicitCredentials(environment) {
  const value = Object.freeze({
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  });
  if (
    !/^ASIA[A-Z0-9]{16}$/u.test(value.accessKeyId ?? "") ||
    typeof value.secretAccessKey !== "string" ||
    value.secretAccessKey.length !== 40 ||
    typeof value.sessionToken !== "string" ||
    value.sessionToken.length < 16
  ) {
    reject("PUBLIC_JUDGE_PROOF_AWS_CREDENTIALS_REJECTED");
  }
  return value;
}

function createSecretReader(environment = process.env) {
  if (
    environment.AWS_REGION !== "us-east-1" ||
    environment.AWS_DEFAULT_REGION !== "us-east-1"
  ) {
    reject("PUBLIC_JUDGE_PROOF_AWS_REGION_REJECTED");
  }
  const runtimeCredentials = explicitCredentials(environment);
  const client = new SecretsManagerClient({
    authSchemePreference: ["sigv4"],
    credentials: async () => ({ ...runtimeCredentials }),
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    region: "us-east-1",
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 500,
      socketTimeout: 2_000
    }),
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  });
  return async () => {
    const value = await client.send(new GetSecretValueCommand({
      SecretId: environment.JUDGE_PROOF_MCP_SECRET_ARN,
      VersionId: environment.JUDGE_PROOF_MCP_SECRET_VERSION_ID,
      VersionStage: "AWSCURRENT"
    }));
    return Object.freeze({
      arn: value?.ARN,
      versionId: value?.VersionId,
      versionStages: value?.VersionStages,
      secretString: value?.SecretString,
      secretBinary: value?.SecretBinary
    });
  };
}

export function createProductionJudgeProofHandler(environment = process.env) {
  return createPublicJudgeProofHandler({
    binding: {
      expectedApiId: environment.EXPECTED_API_ID,
      mcpClusterId: environment.JUDGE_PROOF_MCP_CLUSTER_ID,
      mcpSecretArn: environment.JUDGE_PROOF_MCP_SECRET_ARN,
      mcpSecretVersionId: environment.JUDGE_PROOF_MCP_SECRET_VERSION_ID,
      sourceCommit: environment.SOURCE_COMMIT,
      lambdaVersion: environment.AWS_LAMBDA_FUNCTION_VERSION
    },
    readSecret: createSecretReader(environment)
  });
}

let productionHandler;
export const handler = async (...args) => {
  productionHandler ??= createProductionJudgeProofHandler();
  return productionHandler(...args);
};

export const __test = Object.freeze({ createSecretReader, explicitCredentials });
