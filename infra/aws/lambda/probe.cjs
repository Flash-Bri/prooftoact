"use strict";

function codeFor(error) {
  return String(error?.name || error?.Code || "UNKNOWN").slice(0, 120);
}

function requestIdFor(value) {
  return String(
    value?.$metadata?.requestId ||
      value?.$metadata?.extendedRequestId ||
      ""
  ).slice(0, 180);
}

async function record(operation) {
  try {
    const result = await operation();
    return {
      outcome: "ALLOWED",
      code: "OK",
      requestId: requestIdFor(result)
    };
  } catch (error) {
    const code = codeFor(error);
    return {
      outcome: /accessdenied|unauthorized/i.test(code)
        ? "DENIED"
        : "ERROR",
      code,
      requestId: requestIdFor(error)
    };
  }
}

function clients() {
  const { NodeHttpHandler } = require("@smithy/node-http-handler");
  const requestHandler = new NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 5_000
  });
  const common = {
    region: process.env.AWS_REGION,
    maxAttempts: 1,
    requestHandler
  };
  const {
    BedrockRuntimeClient
  } = require("@aws-sdk/client-bedrock-runtime");
  const { KMSClient } = require("@aws-sdk/client-kms");
  const { LambdaClient } = require("@aws-sdk/client-lambda");
  const {
    SecretsManagerClient
  } = require("@aws-sdk/client-secrets-manager");
  return {
    bedrock: new BedrockRuntimeClient(common),
    kms: new KMSClient(common),
    lambda: new LambdaClient(common),
    secrets: new SecretsManagerClient(common)
  };
}

async function handler(event) {
  if (
    !event ||
    typeof event !== "object" ||
    Object.keys(event).sort().join("\n") !== "mode" ||
    event.mode !== "run"
  ) {
    throw new Error("PROBE_REQUEST_REJECTED");
  }

  const {
    InvokeModelCommand
  } = require("@aws-sdk/client-bedrock-runtime");
  const { SignCommand } = require("@aws-sdk/client-kms");
  const { InvokeCommand } = require("@aws-sdk/client-lambda");
  const {
    GetSecretValueCommand
  } = require("@aws-sdk/client-secrets-manager");
  const sdk = clients();
  const modelBody = Buffer.from(
    JSON.stringify({
      schemaVersion: "messages-v1",
      messages: [
        {
          role: "user",
          content: [{ text: "Return the JSON string {\"probe\":true}." }]
        }
      ],
      inferenceConfig: { maxTokens: 8, temperature: 0 }
    })
  );
  const invokeModel = (modelId) =>
    sdk.bedrock.send(
      new InvokeModelCommand({
        modelId,
        contentType: "application/json",
        accept: "application/json",
        body: modelBody
      })
    );
  const invokeDryRun = (functionName) =>
    sdk.lambda.send(
      new InvokeCommand({
        FunctionName: functionName,
        InvocationType: "DryRun",
        Payload: Buffer.from("{}")
      })
    );

  const checks = {
    approvedBedrockModel: await record(() =>
      invokeModel(process.env.BEDROCK_MODEL_ID)
    ),
    differentBedrockModel: await record(() =>
      invokeModel(process.env.PROBE_OTHER_MODEL_ID)
    ),
    kmsSignDigest: await record(() =>
      sdk.kms.send(
        new SignCommand({
          KeyId: process.env.PROBE_KMS_KEY_ARN,
          Message: Buffer.alloc(32),
          MessageType: "DIGEST",
          SigningAlgorithm: "ECDSA_SHA_256"
        })
      )
    ),
    kmsSignRaw: await record(() =>
      sdk.kms.send(
        new SignCommand({
          KeyId: process.env.PROBE_KMS_KEY_ARN,
          Message: Buffer.from("tideproof-probe"),
          MessageType: "RAW",
          SigningAlgorithm: "ECDSA_SHA_256"
        })
      )
    ),
    canarySecretRead: await record(() =>
      sdk.secrets.send(
        new GetSecretValueCommand({
          SecretId: process.env.PROBE_SECRET_ARN
        })
      )
    ),
    agentInvokeDryRun: await record(() =>
      invokeDryRun(process.env.PROBE_AGENT_FUNCTION_ARN)
    ),
    boundaryInvokeDryRun: await record(() =>
      invokeDryRun(process.env.PROBE_BOUNDARY_FUNCTION_ARN)
    ),
    signerInvokeDryRun: await record(() =>
      invokeDryRun(process.env.PROBE_SIGNER_FUNCTION_ARN)
    ),
    authorityInvokeDryRun: await record(() =>
      invokeDryRun(process.env.PROBE_AUTHORITY_FUNCTION_ARN)
    )
  };

  return {
    schemaVersion: "tideproof.capability-probe.v1",
    roleClass: process.env.PROBE_ROLE_CLASS,
    functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
    sourceCommit: process.env.SOURCE_COMMIT,
    configDigest: process.env.CONFIG_DIGEST,
    treeDigest: process.env.TREE_DIGEST,
    packageLockDigest: process.env.PACKAGE_LOCK_DIGEST,
    probeSourceDigest: process.env.PROBE_SOURCE_DIGEST,
    probeArtifactDigest: process.env.PROBE_ARTIFACT_DIGEST,
    checks
  };
}

exports.handler = handler;
