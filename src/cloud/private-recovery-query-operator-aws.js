import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { createReleaseControlAwsRuntime } from
  "../../release-control/src/release-control-aws-runtime.js";
import { canonicalJson } from "./canonical-json.js";
import { createPrivateRecoveryQueryAwsStore } from
  "./private-recovery-query-aws-store.js";
import { validatePrivateRecoveryQueryReceipt } from
  "./private-recovery-query.js";
import { parseStrictJson } from "./strict-json.js";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function explicitCredentials(environment) {
  const value = Object.freeze({
    accessKeyId: environment.AWS_ACCESS_KEY_ID,
    secretAccessKey: environment.AWS_SECRET_ACCESS_KEY,
    sessionToken: environment.AWS_SESSION_TOKEN
  });
  requireCondition(/^ASIA[A-Z0-9]{16}$/u.test(value.accessKeyId ?? "") &&
    typeof value.secretAccessKey === "string" &&
    value.secretAccessKey.length === 40 &&
    typeof value.sessionToken === "string" && value.sessionToken.length >= 16,
  "PRIVATE_RECOVERY_QUERY_OPERATOR_CREDENTIALS_REJECTED");
  return value;
}

function sdkOptions(credentials) {
  return {
    authSchemePreference: ["sigv4"],
    credentials,
    defaultsMode: "standard",
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    region: "us-east-1",
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 130_000
    }),
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
}

export async function createPrivateRecoveryQueryOperatorAwsRuntime({
  environment = process.env,
  releaseControlTableArn
}) {
  requireCondition(environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1" &&
    /^arn:aws:dynamodb:us-east-1:[0-9]{12}:table\/prooftoact-release-controller$/u
      .test(releaseControlTableArn ?? ""),
  "PRIVATE_RECOVERY_QUERY_OPERATOR_ENVIRONMENT_REJECTED");
  const credentials = explicitCredentials(environment);
  const releaseControl = await createReleaseControlAwsRuntime({
    credentials,
    region: "us-east-1",
    tableArn: releaseControlTableArn
  });
  const lambda = new LambdaClient(sdkOptions(credentials));
  return Object.freeze({
    store: createPrivateRecoveryQueryAwsStore({ runtime: releaseControl }),
    invoker: Object.freeze({
      async invokeExactVersion({ event, functionArn, functionVersion }) {
        requireCondition(
          /^arn:aws:lambda:us-east-1:[0-9]{12}:function:prooftoact-private-recovery-query$/u
            .test(functionArn ?? "") &&
          /^(?:[1-9][0-9]{0,8})$/u.test(functionVersion ?? ""),
        "PRIVATE_RECOVERY_QUERY_INVOKE_TARGET_REJECTED");
        const payload = Buffer.from(canonicalJson(event), "utf8");
        requireCondition(payload.length > 0 && payload.length <= 64 * 1024,
          "PRIVATE_RECOVERY_QUERY_INVOKE_PAYLOAD_REJECTED");
        const response = await lambda.send(new InvokeCommand({
          FunctionName: functionArn,
          Qualifier: functionVersion,
          InvocationType: "RequestResponse",
          LogType: "None",
          Payload: payload
        }));
        requireCondition(response?.StatusCode === 200 &&
          response.ExecutedVersion === functionVersion &&
          response.FunctionError === undefined &&
          response.LogResult === undefined &&
          response.Payload !== undefined,
        "PRIVATE_RECOVERY_QUERY_INVOKE_RESPONSE_REJECTED");
        const bytes = Buffer.from(response.Payload);
        requireCondition(bytes.length > 0 && bytes.length <= 128 * 1024,
          "PRIVATE_RECOVERY_QUERY_INVOKE_RESPONSE_REJECTED");
        let parsed;
        try {
          parsed = parseStrictJson(bytes.toString("utf8"), {
            duplicateCode: "PRIVATE_RECOVERY_QUERY_INVOKE_RESPONSE_REJECTED",
            invalidCode: "PRIVATE_RECOVERY_QUERY_INVOKE_RESPONSE_REJECTED"
          });
        } catch (cause) {
          reject("PRIVATE_RECOVERY_QUERY_INVOKE_RESPONSE_REJECTED", cause);
        }
        return validatePrivateRecoveryQueryReceipt(parsed);
      }
    })
  });
}

export const __test = Object.freeze({ explicitCredentials, sdkOptions });
