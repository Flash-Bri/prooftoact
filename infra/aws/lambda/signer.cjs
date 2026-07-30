"use strict";

const crypto = require("node:crypto");

const RECEIPT_KEYS = [
  "advisoryRunId",
  "agentArtifactDigest",
  "agentAwsSdkVersion",
  "agentFunctionVersion",
  "agentRuntimeVersion",
  "agentSourceDigest",
  "authorityTransferred",
  "apiRequestId",
  "bedrockInvocation",
  "boundaryAwsSdkVersion",
  "boundaryArtifactDigest",
  "boundaryFunctionVersion",
  "boundaryRuntimeVersion",
  "boundarySourceDigest",
  "callerPrincipalHash",
  "configDigest",
  "contextDigest",
  "fixtureType",
  "gateOneBundleDigest",
  "gateOneQueryTemplateDigest",
  "gateOneSourceDigest",
  "modelId",
  "modelRegion",
  "invocationMode",
  "outcome",
  "packageLockDigest",
  "promptTemplateDigest",
  "proposalDigest",
  "publicRequestDigest",
  "receiptType",
  "requiresFreshAuthorization",
  "scenarioId",
  "signerSourceDigest",
  "signerArtifactDigest",
  "sourceCommit",
  "treeDigest",
  "validatorDigest"
];

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value))
    .digest();
}

function isHex(value, length) {
  return (
    typeof value === "string" &&
    value.length === length &&
    /^[0-9a-f]+$/.test(value)
  );
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

function boundedString(value, maximum) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximum
  );
}

function validInvocation(value) {
  return (
    exactKeys(value, [
      "attempts",
      "inputTokens",
      "modelLatencyMs",
      "outputTokens",
      "promptDigest",
      "requestId",
      "responseDigest",
      "stopReason",
      "totalTokens",
      "wallLatencyMs"
    ]) &&
    value.attempts === 1 &&
    boundedString(value.requestId, 160) &&
    value.stopReason === "end_turn" &&
    Number.isInteger(value.inputTokens) &&
    value.inputTokens >= 0 &&
    value.inputTokens <= 10_000 &&
    Number.isInteger(value.outputTokens) &&
    value.outputTokens >= 0 &&
    value.outputTokens <= 160 &&
    value.totalTokens === value.inputTokens + value.outputTokens &&
    Number.isInteger(value.modelLatencyMs) &&
    value.modelLatencyMs >= 0 &&
    value.modelLatencyMs <= 15_000 &&
    Number.isInteger(value.wallLatencyMs) &&
    value.wallLatencyMs >= 0 &&
    value.wallLatencyMs <= 20_000 &&
    isHex(value.promptDigest, 64) &&
    isHex(value.responseDigest, 64)
  );
}

function validateUnsignedReceipt(value) {
  if (!exactKeys(value, RECEIPT_KEYS)) {
    throw new Error("RECEIPT_SHAPE_REJECTED");
  }
  if (
    value.receiptType !== "tideproof.advisory-receipt.v1" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      value.advisoryRunId
    ) ||
    value.scenarioId !== "highwater-v1" ||
    value.fixtureType !== "GATE_ONE_DIGEST_BOUND_FIXTURE" ||
    value.invocationMode !== "SIGNED_HTTP_API" ||
    !boundedString(value.apiRequestId, 160) ||
    !isHex(value.callerPrincipalHash, 64) ||
    !isHex(value.publicRequestDigest, 64) ||
    value.modelId !== process.env.BEDROCK_MODEL_ID ||
    value.modelRegion !== process.env.AWS_REGION ||
    value.sourceCommit !== process.env.SOURCE_COMMIT ||
    value.configDigest !== process.env.CONFIG_DIGEST ||
    !isHex(value.sourceCommit, 40) ||
    !isHex(value.configDigest, 64) ||
    !isHex(value.treeDigest, 40) ||
    !isHex(value.packageLockDigest, 64) ||
    value.treeDigest !== process.env.TREE_DIGEST ||
    value.packageLockDigest !== process.env.PACKAGE_LOCK_DIGEST ||
    !isHex(value.contextDigest, 64) ||
    !isHex(value.gateOneSourceDigest, 64) ||
    !isHex(value.gateOneBundleDigest, 64) ||
    !isHex(value.gateOneQueryTemplateDigest, 64) ||
    !isHex(value.agentSourceDigest, 64) ||
    !isHex(value.boundarySourceDigest, 64) ||
    !isHex(value.signerSourceDigest, 64) ||
    !isHex(value.agentArtifactDigest, 64) ||
    !isHex(value.boundaryArtifactDigest, 64) ||
    !isHex(value.signerArtifactDigest, 64) ||
    value.agentSourceDigest !== process.env.AGENT_SOURCE_DIGEST ||
    value.boundarySourceDigest !== process.env.BOUNDARY_SOURCE_DIGEST ||
    value.signerSourceDigest !== process.env.SIGNER_SOURCE_DIGEST ||
    value.agentArtifactDigest !== process.env.AGENT_ARTIFACT_DIGEST ||
    value.boundaryArtifactDigest !== process.env.BOUNDARY_ARTIFACT_DIGEST ||
    value.signerArtifactDigest !== process.env.SIGNER_ARTIFACT_DIGEST ||
    !isHex(value.promptTemplateDigest, 64) ||
    !isHex(value.validatorDigest, 64) ||
    !boundedString(value.agentFunctionVersion, 12) ||
    !boundedString(value.boundaryFunctionVersion, 12) ||
    !boundedString(value.boundaryRuntimeVersion, 40) ||
    !boundedString(value.boundaryAwsSdkVersion, 40) ||
    value.authorityTransferred !== false ||
    value.requiresFreshAuthorization !== true
  ) {
    throw new Error("RECEIPT_BINDING_REJECTED");
  }
  if (
    !["ADVISORY_READY", "UNKNOWN_DO_NOT_ACT"].includes(value.outcome)
  ) {
    throw new Error("RECEIPT_OUTCOME_REJECTED");
  }
  if (
    (value.outcome === "ADVISORY_READY" &&
      (!isHex(value.proposalDigest, 64) ||
        !validInvocation(value.bedrockInvocation) ||
        !boundedString(value.agentRuntimeVersion, 40) ||
        !boundedString(value.agentAwsSdkVersion, 40))) ||
    (value.outcome === "UNKNOWN_DO_NOT_ACT" &&
      (value.proposalDigest !== null ||
        value.bedrockInvocation !== null ||
        value.agentRuntimeVersion !== null ||
        value.agentAwsSdkVersion !== null))
  ) {
    throw new Error("RECEIPT_PROPOSAL_BINDING_REJECTED");
  }
  return { ...value };
}

async function signReceipt(unsignedReceipt) {
  const {
    GetPublicKeyCommand,
    KMSClient,
    SignCommand,
    VerifyCommand
  } = require("@aws-sdk/client-kms");
  const { NodeHttpHandler } = require("@smithy/node-http-handler");
  const kms = new KMSClient({
    region: process.env.AWS_REGION,
    maxAttempts: 1,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 5_000
    })
  });
  const receipt = {
    ...validateUnsignedReceipt(unsignedReceipt),
    signerFunctionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
    signerRuntimeVersion: process.version,
    signerAwsSdkVersion: require("@aws-sdk/client-kms/package.json").version,
    generatedAt: new Date().toISOString()
  };
  const digest = sha256(receipt);
  const signInput = {
    KeyId: process.env.SIGNING_KEY_ARN,
    Message: digest,
    MessageType: "DIGEST",
    SigningAlgorithm: "ECDSA_SHA_256"
  };
  const signed = await kms.send(new SignCommand(signInput));
  const verified = await kms.send(
    new VerifyCommand({
      ...signInput,
      Signature: signed.Signature
    })
  );
  if (verified.SignatureValid !== true) {
    throw new Error("KMS_SIGNATURE_VERIFICATION_FAILED");
  }
  const publicKey = await kms.send(
    new GetPublicKeyCommand({ KeyId: process.env.SIGNING_KEY_ARN })
  );
  return {
    receipt,
    receiptDigest: digest.toString("hex"),
    signatureDerBase64: Buffer.from(signed.Signature).toString("base64"),
    publicKeyDerBase64: Buffer.from(publicKey.PublicKey).toString("base64"),
    signingKeyArn: process.env.SIGNING_KEY_ARN,
    signingAlgorithm: "ECDSA_SHA_256",
    signatureVerified: true
  };
}

async function handler(event) {
  return signReceipt(event);
}

exports.handler = handler;
exports.__test = {
  canonicalJson,
  validateUnsignedReceipt
};
