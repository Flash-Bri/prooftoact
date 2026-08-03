"use strict";

const crypto = require("node:crypto");

const FIXED_CONTEXT = Object.freeze({
  schemaVersion: "tideproof.admitted-context.v1",
  scenarioId: "highwater-v1",
  fixtureType: "GATE_ONE_DIGEST_BOUND_FIXTURE",
  scenarioTime: "2026-08-01T12:00:00.000Z",
  admittedEvidence: [
    {
      evidenceId: "ev-shelter-capacity",
      assertion:
        "River Shelter has capacity for 18 synthetic evacuees.",
      issuer: "synthetic-county-sensor",
      scope: "rescue",
      provenance: "verified",
      validUntil: "2026-08-01T12:25:00.000Z"
    }
  ],
  excludedEvidence: {
    expired: 1,
    invalidProvenance: 1,
    unresolvedConflict: 2
  },
  recoveryBinding: {
    recoveryStatus: "RECOVERED_CONTEXT_ONLY",
    sourceBuildIdentity: "55892bf25a5286af30e30908ab5711e24f106629",
    sourceDigest:
      "6aac30b90f3dd5943f9d09790e9b8ca48d04ce784cd9e4f02d41eb11d8c7b5c4",
    bundleDigest:
      "15fdef2ee344791aa28152dc3769b4f978dd3f5e405e7f6e6f2599b338e8c860",
    queryTemplateDigest:
      "a2aaf3df68631b734473b4e5085367c2b42a03b0278f17bf590c4eede8f86ab8"
  },
  committedMemory: {
    resourceId: "synthetic-rescue-unit-7",
    authorityTransferred: false,
    requiresFreshAuthorization: true
  }
});

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

function sha256Hex(value) {
  return crypto
    .createHash("sha256")
    .update(typeof value === "string" ? value : canonicalJson(value))
    .digest("hex");
}

function sha256BytesHex(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error("SIGNING_PUBLIC_KEY_REJECTED");
  }
  return crypto
    .createHash("sha256")
    .update(Buffer.from(value))
    .digest("hex");
}

function validateExpectedSigningKey(value) {
  if (
    !exactKeys(value, ["keyArn", "publicKeyDer", "publicKeyDigest"]) ||
    value.keyArn !== process.env.SIGNING_KEY_ARN ||
    !Buffer.isBuffer(value.publicKeyDer) ||
    value.publicKeyDer.length < 80 ||
    value.publicKeyDer.length > 160 ||
    !/^[0-9a-f]{64}$/.test(value.publicKeyDigest) ||
    sha256BytesHex(value.publicKeyDer) !== value.publicKeyDigest
  ) {
    throw new Error("SIGNING_PUBLIC_KEY_REJECTED");
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey({
      key: value.publicKeyDer,
      format: "der",
      type: "spki"
    });
  } catch {
    throw new Error("SIGNING_PUBLIC_KEY_REJECTED");
  }
  if (
    publicKey.asymmetricKeyType !== "ec" ||
    publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new Error("SIGNING_PUBLIC_KEY_REJECTED");
  }
  return {
    keyArn: value.keyArn,
    publicKeyDer: Buffer.from(value.publicKeyDer),
    publicKeyDigest: value.publicKeyDigest
  };
}

function validateKmsPublicKey(value) {
  const publicKeyDer = Buffer.from(value?.PublicKey || []);
  if (
    value?.KeyId !== process.env.SIGNING_KEY_ARN ||
    value?.KeySpec !== "ECC_NIST_P256" ||
    value?.KeyUsage !== "SIGN_VERIFY" ||
    !Array.isArray(value?.SigningAlgorithms) ||
    !value.SigningAlgorithms.includes("ECDSA_SHA_256")
  ) {
    throw new Error("KMS_SIGNING_KEY_METADATA_REJECTED");
  }
  return validateExpectedSigningKey({
    keyArn: value.KeyId,
    publicKeyDer,
    publicKeyDigest: sha256BytesHex(publicKeyDer)
  });
}

async function loadSigningPublicKey() {
  const { GetPublicKeyCommand, KMSClient } = require("@aws-sdk/client-kms");
  const { NodeHttpHandler } = require("@smithy/node-http-handler");
  const kms = new KMSClient({
    region: process.env.AWS_REGION,
    maxAttempts: 1,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 5_000
    })
  });
  return validateKmsPublicKey(
    await kms.send(
      new GetPublicKeyCommand({ KeyId: process.env.SIGNING_KEY_ARN })
    )
  );
}

function buildContext() {
  const context = JSON.parse(JSON.stringify(FIXED_CONTEXT));
  return {
    ...context,
    contextDigest: sha256Hex(context)
  };
}

function exactKeys(value, allowed) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...allowed].sort().join("\n")
  );
}

function boundedString(value, maximum) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maximum
  );
}

function validateProposal(value) {
  if (
    !exactKeys(value, ["proposal", "summary", "uncertainties"]) ||
    !boundedString(value.summary, 360) ||
    !Array.isArray(value.uncertainties) ||
    value.uncertainties.length < 1 ||
    value.uncertainties.length > 4 ||
    !value.uncertainties.every((item) => boundedString(item, 160)) ||
    !exactKeys(value.proposal, [
      "action",
      "evidenceIds",
      "resourceId"
    ]) ||
    value.proposal.action !== "REQUEST_FRESH_AUTHORIZATION" ||
    value.proposal.resourceId !== "synthetic-rescue-unit-7" ||
    !Array.isArray(value.proposal.evidenceIds) ||
    value.proposal.evidenceIds.length !== 1 ||
    value.proposal.evidenceIds[0] !== "ev-shelter-capacity"
  ) {
    throw new Error("BOUNDARY_PROPOSAL_REJECTED");
  }
  return structuredClone(value);
}

function parsePublicRequest(event) {
  let text = event?.body ?? "";
  if (event?.isBase64Encoded === true) {
    text = Buffer.from(text, "base64").toString("utf8");
  }
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > 256) {
    throw new Error("REQUEST_SIZE_REJECTED");
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("REQUEST_JSON_REJECTED");
  }
  if (
    !exactKeys(parsed, ["scenarioId"]) ||
    parsed.scenarioId !== "highwater-v1"
  ) {
    throw new Error("REQUEST_SHAPE_REJECTED");
  }
  return parsed;
}

function isHttpEvent(event) {
  return event?.version === "2.0" && Boolean(event?.requestContext?.http);
}

function expectedAssumedRoleArnPattern(roleArn, expectedAccountId) {
  const match = /^arn:(aws(?:-[a-z0-9-]+)?):iam::(\d{12}):role\/([A-Za-z0-9+=,.@_-]{1,64})$/.exec(
    roleArn
  );
  if (!match || match[2] !== expectedAccountId) {
    throw new Error("SIGNED_CALLER_CONFIGURATION_REJECTED");
  }
  const [, partition, accountId, roleName] = match;
  const escapedRoleName = roleName.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );
  return new RegExp(
    `^arn:${partition}:sts::${accountId}:assumed-role/${escapedRoleName}/[A-Za-z0-9+=,.@_-]{2,64}$`
  );
}

function validateHttpCaller(event) {
  const context = event?.requestContext;
  const iam = context?.authorizer?.iam;
  const now = Date.now();
  const expectedAccountId = process.env.EXPECTED_ACCOUNT_ID;
  const expectedCaller = expectedAssumedRoleArnPattern(
    process.env.EXPECTED_ADVISORY_CALLER_ROLE_ARN,
    expectedAccountId
  );
  if (
    !isHttpEvent(event) ||
    context.accountId !== expectedAccountId ||
    context.apiId !== process.env.EXPECTED_API_ID ||
    context.routeKey !== "POST /advisory" ||
    context.stage !== "$default" ||
    context.http.method !== "POST" ||
    context.http.path !== "/advisory" ||
    !boundedString(context.requestId, 160) ||
    !Number.isSafeInteger(context.timeEpoch) ||
    context.timeEpoch < now - 300_000 ||
    context.timeEpoch > now + 300_000 ||
    typeof iam?.userArn !== "string" ||
    !expectedCaller.test(iam.userArn)
  ) {
    throw new Error("SIGNED_CALLER_REJECTED");
  }
}

function requestBinding(event, publicRequest) {
  return {
    invocationMode: "SIGNED_HTTP_API",
    callerPrincipalHash: sha256Hex(
      event.requestContext.authorizer.iam.userArn
    ),
    apiRequestId: event.requestContext.requestId,
    apiRequestTimeEpoch: event.requestContext.timeEpoch,
    publicRequestDigest: sha256Hex(publicRequest)
  };
}

function lambdaClient() {
  const { LambdaClient } = require("@aws-sdk/client-lambda");
  const { NodeHttpHandler } = require("@smithy/node-http-handler");
  return new LambdaClient({
    region: process.env.AWS_REGION,
    maxAttempts: 1,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 18_000
    })
  });
}

async function invokeFunction(functionName, payload) {
  const { InvokeCommand } = require("@aws-sdk/client-lambda");
  const response = await lambdaClient().send(
    new InvokeCommand({
      FunctionName: functionName,
      InvocationType: "RequestResponse",
      Payload: Buffer.from(JSON.stringify(payload))
    })
  );
  const body = JSON.parse(Buffer.from(response.Payload || []).toString("utf8"));
  if (response.FunctionError) {
    throw new Error("CHILD_LAMBDA_FAILED");
  }
  return body;
}

function unsignedReceipt({
  contextDigest,
  outcome,
  proposalDigest,
  request,
  signingKey,
  advisory = null
}) {
  return {
    advisoryRunId: crypto.randomUUID(),
    receiptType: "tideproof.advisory-receipt.v1",
    sourceCommit: process.env.SOURCE_COMMIT,
    configDigest: process.env.CONFIG_DIGEST,
    treeDigest: process.env.TREE_DIGEST,
    packageLockDigest: process.env.PACKAGE_LOCK_DIGEST,
    scenarioId: "highwater-v1",
    fixtureType: "GATE_ONE_DIGEST_BOUND_FIXTURE",
    invocationMode: request.invocationMode,
    callerPrincipalHash: request.callerPrincipalHash,
    apiRequestId: request.apiRequestId,
    apiRequestTimeEpoch: request.apiRequestTimeEpoch,
    publicRequestDigest: request.publicRequestDigest,
    contextDigest,
    gateOneSourceDigest:
      "6aac30b90f3dd5943f9d09790e9b8ca48d04ce784cd9e4f02d41eb11d8c7b5c4",
    gateOneBundleDigest:
      "15fdef2ee344791aa28152dc3769b4f978dd3f5e405e7f6e6f2599b338e8c860",
    gateOneQueryTemplateDigest:
      "a2aaf3df68631b734473b4e5085367c2b42a03b0278f17bf590c4eede8f86ab8",
    modelId: process.env.BEDROCK_MODEL_ID,
    modelRegion: process.env.AWS_REGION,
    outcome,
    proposalDigest,
    agentSourceDigest: process.env.AGENT_SOURCE_DIGEST,
    boundarySourceDigest: process.env.BOUNDARY_SOURCE_DIGEST,
    signerSourceDigest: process.env.SIGNER_SOURCE_DIGEST,
    agentArtifactDigest: process.env.AGENT_ARTIFACT_DIGEST,
    boundaryArtifactDigest: process.env.BOUNDARY_ARTIFACT_DIGEST,
    signerArtifactDigest: process.env.SIGNER_ARTIFACT_DIGEST,
    signingKeyArn: signingKey.keyArn,
    signingPublicKeyDigest: signingKey.publicKeyDigest,
    agentFunctionVersion: process.env.AGENT_FUNCTION_VERSION,
    boundaryFunctionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
    promptTemplateDigest: process.env.PROMPT_TEMPLATE_DIGEST,
    validatorDigest: process.env.AGENT_VALIDATOR_DIGEST,
    bedrockInvocation: advisory?.invocation ?? null,
    agentRuntimeVersion: advisory?.runtimeVersion ?? null,
    agentAwsSdkVersion: advisory?.awsSdkVersion ?? null,
    boundaryRuntimeVersion: process.version,
    boundaryAwsSdkVersion:
      require("@aws-sdk/client-lambda/package.json").version,
    boundaryKmsSdkVersion:
      require("@aws-sdk/client-kms/package.json").version,
    authorityTransferred: false,
    requiresFreshAuthorization: true
  };
}

async function sign(receipt) {
  return invokeFunction(process.env.SIGNER_FUNCTION_ARN, receipt);
}

function canonicalBase64(value, minimumBytes, maximumBytes) {
  if (
    typeof value !== "string" ||
    value.length < 4 ||
    value.length > Math.ceil(maximumBytes / 3) * 4 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new Error("SIGNER_BASE64_REJECTED");
  }
  const decoded = Buffer.from(value, "base64");
  if (
    decoded.length < minimumBytes ||
    decoded.length > maximumBytes ||
    decoded.toString("base64") !== value
  ) {
    throw new Error("SIGNER_BASE64_REJECTED");
  }
  return decoded;
}

function validateSignedEnvelope(
  value,
  expectedUnsignedReceipt,
  expectedSigningKey
) {
  const signingKey = validateExpectedSigningKey(expectedSigningKey);
  if (
    !exactKeys(value, [
      "publicKeyDerBase64",
      "receipt",
      "receiptDigest",
      "signatureDerBase64",
      "signatureVerified",
      "signingAlgorithm",
      "signingKeyArn"
    ]) ||
    value.signatureVerified !== true ||
    value.signingAlgorithm !== "ECDSA_SHA_256" ||
    value.signingKeyArn !== signingKey.keyArn ||
    !exactKeys(value.receipt, [
      ...Object.keys(expectedUnsignedReceipt),
      "generatedAt",
      "signerAwsSdkVersion",
      "signerFunctionVersion",
      "signerRuntimeVersion"
    ])
  ) {
    throw new Error("SIGNER_ENVELOPE_REJECTED");
  }

  for (const [key, expected] of Object.entries(expectedUnsignedReceipt)) {
    if (canonicalJson(value.receipt[key]) !== canonicalJson(expected)) {
      throw new Error("SIGNER_RECEIPT_ECHO_REJECTED");
    }
  }
  if (
    value.receipt.signerFunctionVersion !==
      process.env.SIGNER_FUNCTION_VERSION ||
    !boundedString(value.receipt.signerRuntimeVersion, 40) ||
    !boundedString(value.receipt.signerAwsSdkVersion, 40) ||
    !boundedString(value.receipt.generatedAt, 40) ||
    new Date(value.receipt.generatedAt).toISOString() !==
      value.receipt.generatedAt ||
    !/^[0-9a-f]{64}$/.test(value.receiptDigest) ||
    sha256Hex(value.receipt) !== value.receiptDigest
  ) {
    throw new Error("SIGNER_RECEIPT_BINDING_REJECTED");
  }

  const signature = canonicalBase64(
    value.signatureDerBase64,
    64,
    80
  );
  const publicKeyDer = canonicalBase64(
    value.publicKeyDerBase64,
    80,
    160
  );
  if (
    publicKeyDer.length !== signingKey.publicKeyDer.length ||
    !crypto.timingSafeEqual(publicKeyDer, signingKey.publicKeyDer)
  ) {
    throw new Error("SIGNER_PUBLIC_KEY_BINDING_REJECTED");
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey({
      key: publicKeyDer,
      format: "der",
      type: "spki"
    });
  } catch {
    throw new Error("SIGNER_PUBLIC_KEY_REJECTED");
  }
  if (
    publicKey.asymmetricKeyType !== "ec" ||
    publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1" ||
    crypto.verify(
      "sha256",
      Buffer.from(canonicalJson(value.receipt)),
      publicKey,
      signature
    ) !== true
  ) {
    throw new Error("SIGNER_SIGNATURE_REJECTED");
  }
  return structuredClone(value);
}

function response(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff"
    },
    body: JSON.stringify(body)
  };
}

function publicFailure(code, signedReceipt = null) {
  return {
    schemaVersion: "tideproof.boundary.v1",
    status: "UNKNOWN_DO_NOT_ACT",
    code,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    signedReceipt
  };
}

function telemetryText(value, maximum, fallback = "UNBOUND") {
  return typeof value === "string" && value.length > 0
    ? value.slice(0, maximum)
    : fallback;
}

function semanticFailureMetric(code, context, now = () => Date.now()) {
  return {
    _aws: {
      Timestamp: now(),
      CloudWatchMetrics: [
        {
          Namespace: "ProofToAct/GateTwo",
          Dimensions: [["Deployment", "Service"]],
          Metrics: [{ Name: "SemanticFailures", Unit: "Count" }]
        }
      ]
    },
    Deployment: telemetryText(
      process.env.SEMANTIC_METRIC_DEPLOYMENT,
      255
    ),
    Service: "boundary",
    SemanticFailures: 1,
    schemaVersion: "tideproof.aws-semantic-failure.v1",
    provider: "AWS_LAMBDA",
    status: "UNKNOWN_DO_NOT_ACT",
    code: telemetryText(code, 120, "BOUNDARY_UNAVAILABLE"),
    awsRequestId: telemetryText(context?.awsRequestId, 160, null),
    region: telemetryText(process.env.AWS_REGION, 32),
    functionName: telemetryText(
      process.env.AWS_LAMBDA_FUNCTION_NAME,
      64
    ),
    functionVersion: telemetryText(
      process.env.AWS_LAMBDA_FUNCTION_VERSION,
      12
    ),
    sourceCommit: telemetryText(process.env.SOURCE_COMMIT, 40),
    configDigest: telemetryText(process.env.CONFIG_DIGEST, 64),
    treeDigest: telemetryText(process.env.TREE_DIGEST, 40),
    artifactDigest: telemetryText(
      process.env.BOUNDARY_ARTIFACT_DIGEST,
      64
    )
  };
}

function emitSemanticFailure(code, context) {
  process.stdout.write(
    `${JSON.stringify(semanticFailureMetric(code, context))}\n`
  );
}

async function runAdvisory({
  request,
  invokeChild = invokeFunction,
  signReceipt = sign,
  getSigningPublicKey = loadSigningPublicKey
} = {}) {
  if (
    !exactKeys(request, [
      "apiRequestId",
      "apiRequestTimeEpoch",
      "callerPrincipalHash",
      "invocationMode",
      "publicRequestDigest"
    ]) ||
    request.invocationMode !== "SIGNED_HTTP_API" ||
    !boundedString(request.apiRequestId, 160) ||
    !Number.isSafeInteger(request.apiRequestTimeEpoch) ||
    request.apiRequestTimeEpoch < 1_600_000_000_000 ||
    !/^[0-9a-f]{64}$/.test(request.callerPrincipalHash) ||
    !/^[0-9a-f]{64}$/.test(request.publicRequestDigest)
  ) {
    throw new Error("REQUEST_BINDING_REJECTED");
  }
  let signingKey;
  try {
    signingKey = validateExpectedSigningKey(
      await getSigningPublicKey()
    );
  } catch {
    return {
      statusCode: 503,
      body: publicFailure("SIGNING_KEY_UNAVAILABLE")
    };
  }
  const context = buildContext();
  try {
    const advisory = await invokeChild(
      process.env.AGENT_FUNCTION_ARN,
      context
    );
    if (
      !exactKeys(advisory, [
        "agentArtifactDigest",
        "agentSourceDigest",
        "authorityTransferred",
        "awsSdkVersion",
        "configDigest",
        "contextDigest",
        "functionVersion",
        "invocation",
        "modelId",
        "packageLockDigest",
        "promptTemplateDigest",
        "proposal",
        "proposalDigest",
        "requiresFreshAuthorization",
        "runtimeVersion",
        "schemaVersion",
        "sourceCommit",
        "status",
        "treeDigest",
        "validatorDigest"
      ]) ||
      advisory.schemaVersion !== "tideproof.advisory.v1" ||
      advisory?.status !== "ADVISORY_READY" ||
      advisory.authorityTransferred !== false ||
      advisory.requiresFreshAuthorization !== true ||
      advisory.contextDigest !== context.contextDigest ||
      advisory.modelId !== process.env.BEDROCK_MODEL_ID ||
      advisory.sourceCommit !== process.env.SOURCE_COMMIT ||
      advisory.configDigest !== process.env.CONFIG_DIGEST ||
      advisory.treeDigest !== process.env.TREE_DIGEST ||
      advisory.packageLockDigest !== process.env.PACKAGE_LOCK_DIGEST ||
      advisory.agentSourceDigest !== process.env.AGENT_SOURCE_DIGEST ||
      advisory.agentArtifactDigest !== process.env.AGENT_ARTIFACT_DIGEST ||
      advisory.functionVersion !== process.env.AGENT_FUNCTION_VERSION ||
      advisory.promptTemplateDigest !==
        process.env.PROMPT_TEMPLATE_DIGEST ||
      advisory.validatorDigest !== process.env.AGENT_VALIDATOR_DIGEST ||
      !advisory.invocation ||
      advisory.invocation.attempts !== 1 ||
      advisory.invocation.stopReason !== "end_turn" ||
      advisory.invocation.outputTokens > 160 ||
      advisory.invocation.totalTokens !==
        advisory.invocation.inputTokens + advisory.invocation.outputTokens ||
      !/^[0-9a-f]{64}$/.test(advisory.proposalDigest) ||
      sha256Hex(validateProposal(advisory.proposal)) !==
        advisory.proposalDigest
    ) {
      throw new Error("ADVISORY_BINDING_REJECTED");
    }
    const receipt = unsignedReceipt({
      contextDigest: context.contextDigest,
      outcome: "ADVISORY_READY",
      proposalDigest: advisory.proposalDigest,
      request,
      signingKey,
      advisory
    });
    const signedReceipt = validateSignedEnvelope(
      await signReceipt(receipt),
      receipt,
      signingKey
    );
    return {
      statusCode: 200,
      body: {
        schemaVersion: "tideproof.boundary.v1",
        status: "ADVISORY_READY",
        scenarioId: "highwater-v1",
        proposal: advisory.proposal,
        authorityTransferred: false,
        requiresFreshAuthorization: true,
        signedReceipt
      }
    };
  } catch {
    try {
      const receipt = unsignedReceipt({
        contextDigest: context.contextDigest,
        outcome: "UNKNOWN_DO_NOT_ACT",
        proposalDigest: null,
        request,
        signingKey
      });
      const signedReceipt = validateSignedEnvelope(
        await signReceipt(receipt),
        receipt,
        signingKey
      );
      return {
        statusCode: 503,
        body: publicFailure("ADVISORY_UNAVAILABLE", signedReceipt)
      };
    } catch {
      return {
        statusCode: 503,
        body: publicFailure("ADVISORY_AND_RECEIPT_UNAVAILABLE")
      };
    }
  }
}

async function handler(event, context) {
  if (!isHttpEvent(event)) {
    throw new Error("DIRECT_EVENT_REJECTED");
  }

  let parsedRequest;
  try {
    validateHttpCaller(event);
    parsedRequest = parsePublicRequest(event);
  } catch {
    const code = event?.requestContext?.authorizer?.iam
      ? "INVALID_REQUEST"
      : "SIGNED_CALLER_REQUIRED";
    emitSemanticFailure(code, context);
    return response(
      event?.requestContext?.authorizer?.iam
        ? 400
        : 403,
      publicFailure(code)
    );
  }
  const result = await runAdvisory({
    request: requestBinding(event, parsedRequest)
  });
  if (result.body?.status === "UNKNOWN_DO_NOT_ACT") {
    emitSemanticFailure(result.body.code, context);
  }
  return response(result.statusCode, result.body);
}

exports.handler = handler;
exports.__test = {
  buildContext,
  canonicalJson,
  parsePublicRequest,
  runAdvisory,
  requestBinding,
  semanticFailureMetric,
  sha256Hex,
  sha256BytesHex,
  unsignedReceipt,
  validateExpectedSigningKey,
  expectedAssumedRoleArnPattern,
  validateHttpCaller,
  validateKmsPublicKey,
  validateProposal,
  validateSignedEnvelope
};
