import crypto from "node:crypto";

import { validateAwsEvidenceCaller } from "./aws-evidence-identity.js";
import { deploymentConfigDigest } from "./aws-gate2-template.js";

export const DEPLOYMENT_FUNCTIONS = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "signer"
]);
export const DEPLOYMENT_ARTIFACTS = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
]);
export const DEPLOYMENT_API_INTEGRATIONS = Object.freeze({
  BoundaryIntegration: Object.freeze({
    functionName: "boundary",
    timeoutInMillis: 29_000
  }),
  DemoIntegration: Object.freeze({
    functionName: "demo",
    timeoutInMillis: 6_000
  })
});
export const DEPLOYMENT_API_ROUTE_KEYS = Object.freeze({
  AdvisoryRoute: "POST /advisory",
  DemoAppRoute: "GET /app.js",
  DemoArchitectureRoute: "GET /architecture.svg",
  DemoAuthorityEvidenceRoute: "GET /evidence/gate1-authority",
  DemoClaimsRoute: "GET /claims",
  DemoHealthRoute: "GET /api/health",
  DemoIndexRoute: "GET /",
  DemoRecoveryEvidenceRoute: "GET /evidence/gate1-recovery",
  DemoScenarioRoute: "GET /api/scenario",
  DemoStylesRoute: "GET /styles.css",
  DemoAmbiguityEvidenceRoute: "GET /evidence/gate1-ambiguity"
});

const EXPECTATION_SCHEMA =
  "tideproof.gate2.aws-deployment-expectation.v4";
const SNAPSHOT_RECEIPT_SCHEMA =
  "tideproof.gate2.aws-deployment-attestation-snapshot.v5";
const PAIR_RECEIPT_SCHEMA =
  "tideproof.gate2.aws-deployment-attestation.v5";
const ALTERNATE_DENIAL_SCHEMA =
  "tideproof.gate2.aws-alternate-principal-denial.v3";
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const BASE64_SHA256 = /^[A-Za-z0-9+/]{43}=$/;
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
const REVISION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLE_ID = /^[A-Z0-9]{16,128}$/;
const EXPECTED_RESOURCE_TAGS = Object.freeze({
  Gate: "Two",
  Project: "ProofToAct"
});
const EXPECTED_ROLE_TAGS = Object.freeze([
  Object.freeze({ key: "Gate", value: "Two" }),
  Object.freeze({ key: "Project", value: "ProofToAct" })
]);
const SNAPSHOT_CLAIM_BOUNDARY =
  "This signed receipt validates one revision-fenced AWS deployment snapshot for the five primary runtime functions, their shared roles, the two evidence roles, and the exact HTTP API route/integration/stage and explicit active-deployment census against exact build, configuration, 37 drift-supported CloudFormation resources, two directly attested integrations, one directly attested explicit API deployment, and direct provider observations. It accepts only a never-updated CREATE_COMPLETE stack whose active deployment was created during that stack creation after every declared route; any stack update requires teardown and a fresh create before evidence can pass. Probe resources are required absent. Unmanaged Lambda aliases, function URLs, and event-source mappings are required absent for the five primary functions. Other account resources remain outside this census. It is not a pre/post stability receipt, administrator exclusion, application canary, or release authorization.";

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n")
  );
}

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
    .update(
      Buffer.isBuffer(value)
        ? value
        : typeof value === "string"
          ? value
          : canonicalJson(value)
    )
    .digest("hex");
}

export function deploymentAttestationDigest(value) {
  return sha256(value);
}

export function deploymentStackParameterBindings(configuration) {
  const configDigest = deploymentConfigDigest(configuration);
  const authority = configuration.authority;
  const bindings = {
    ArtifactBucket: configuration.artifactBucket,
    AuthorityDatabaseHost: authority.databaseHost,
    AuthorityDatabasePort: authority.databasePort,
    AuthorityDatabaseSecretArn: authority.databaseSecretArn,
    AuthorityDatabaseSecretVersionId: authority.databaseSecretVersionId,
    AuthorityIncidentId: authority.incidentId,
    AuthorityResourceId: authority.resourceId,
    AuthorityTenantId: authority.tenantId,
    BedrockModelId: configuration.bedrockModelId,
    ConfigDigest: configDigest,
    EnableProbeFunctions: configuration.probesEnabled ? "true" : "false",
    EvidenceOperatorPrincipalArn:
      configuration.evidenceOperator.principalArn,
    PackageLockDigest: configuration.packageLockDigest,
    SourceCommit: configuration.sourceCommit,
    TreeDigest: configuration.treeDigest
  };
  for (const name of DEPLOYMENT_ARTIFACTS) {
    const title = name[0].toUpperCase() + name.slice(1);
    bindings[title + "ArtifactCodeSha256"] =
      configuration.artifactCodeSha256[name];
    bindings[title + "ArtifactDigest"] =
      configuration.artifactDigests[name];
    bindings[title + "ArtifactKey"] = configuration.artifactKeys[name];
    bindings[title + "ArtifactVersion"] =
      configuration.artifactVersions[name];
    bindings[title + "SourceDigest"] =
      configuration.artifactSourceDigests[name];
  }
  requireCondition(
    Object.keys(bindings).length === 45 &&
      Object.values(bindings).every(
        (value) => typeof value === "string" && value.length > 0
      ),
    "AWS_ATTEST_STACK_PARAMETERS"
  );
  return Object.freeze(
    Object.fromEntries(
      Object.entries(bindings).sort(([left], [right]) =>
        left.localeCompare(right)
      )
    )
  );
}

export function deploymentFunctionConfigurationDigest(configuration) {
  requireCondition(
    configuration &&
      typeof configuration === "object" &&
      !Array.isArray(configuration) &&
      configuration.environment &&
      typeof configuration.environment === "object" &&
      !Array.isArray(configuration.environment) &&
      typeof configuration.environment.CONFIG_DIGEST === "string",
    "AWS_ATTEST_FUNCTION_CONFIGURATION_DIGEST"
  );
  return sha256({
    ...configuration,
    environment: {
      ...configuration.environment,
      CONFIG_DIGEST: "<bound-config-digest>"
    },
    runtimeVersion: "<provider-observed-runtime-version>"
  });
}

function isoMilliseconds(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(
    typeof value === "string" &&
      Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    code
  );
  return milliseconds;
}

function sameAccountPrincipalArn(value, accountId) {
  return new RegExp(
    `^arn:aws[a-zA-Z-]*:iam::${accountId}:` +
      "(?:role|user)/[A-Za-z0-9+=,.@_-]{1,64}$"
  ).test(value ?? "");
}

function functionArnPattern(region, accountId) {
  return new RegExp(
    `^arn:aws[a-zA-Z-]*:lambda:${region}:${accountId}:` +
      "function:[-A-Za-z0-9_]{1,64}$"
  );
}

function roleArnPattern(accountId) {
  return new RegExp(
    `^arn:aws[a-zA-Z-]*:iam::${accountId}:` +
      "role/[A-Za-z0-9+=,.@_-]{1,64}$"
  );
}

function roleNameFromArn(roleArn) {
  const match = /:role\/([A-Za-z0-9+=,.@_-]{1,64})$/.exec(roleArn ?? "");
  requireCondition(match, "AWS_ATTEST_STACK_RESOURCE_ROLE");
  return match[1];
}

function expectedStackResourceBindings(expectation) {
  const bindings = {};
  for (const name of DEPLOYMENT_FUNCTIONS) {
    const title = `${name[0].toUpperCase()}${name.slice(1)}`;
    const expected = expectation.functions[name];
    bindings[`${title}Alias`] = {
      physicalResourceId: expected.aliasArn,
      resourceType: "AWS::Lambda::Alias"
    };
    bindings[`${title}Function`] = {
      physicalResourceId: expected.functionName,
      resourceType: "AWS::Lambda::Function"
    };
    bindings[`${title}Role`] = {
      physicalResourceId: roleNameFromArn(expected.roleArn),
      resourceType: "AWS::IAM::Role"
    };
    bindings[`${title}Version`] = {
      physicalResourceId: expected.numericVersionArn,
      resourceType: "AWS::Lambda::Version"
    };
  }
  bindings.DeploymentEvidenceAlternateRole = {
    physicalResourceId: roleNameFromArn(
      expectation.alternatePrincipal.roleArn
    ),
    resourceType: "AWS::IAM::Role"
  };
  bindings.DeploymentEvidenceRole = {
    physicalResourceId: roleNameFromArn(expectation.evidenceOperator.roleArn),
    resourceType: "AWS::IAM::Role"
  };
  return Object.fromEntries(
    Object.entries(bindings).sort(([left], [right]) =>
      left.localeCompare(right)
    )
  );
}

function validateStackResourceBindings(actual, expectation) {
  const expected = expectedStackResourceBindings(expectation);
  requireCondition(
    exactKeys(actual, Object.keys(expected)) &&
      Object.entries(expected).every(([logicalId, binding]) =>
        exactKeys(actual[logicalId], [
          "physicalResourceId",
          "resourceStatus",
          "resourceType"
        ]) &&
        actual[logicalId].physicalResourceId === binding.physicalResourceId &&
        actual[logicalId].resourceType === binding.resourceType &&
        actual[logicalId].resourceStatus === "CREATE_COMPLETE"
      ),
    "AWS_ATTEST_STACK_RESOURCE_BINDINGS"
  );
  return actual;
}

function validatePublicKey(value, code) {
  requireCondition(
    typeof value === "string" &&
      value.length >= 56 &&
      value.length <= 128 &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(value) &&
      Buffer.from(value, "base64").toString("base64") === value,
    code
  );
  let key;
  try {
    key = crypto.createPublicKey({
      key: Buffer.from(value, "base64"),
      format: "der",
      type: "spki"
    });
  } catch {
    throw new Error(code);
  }
  requireCondition(
    key.asymmetricKeyType === "ed25519" &&
      key.export({ format: "der", type: "spki" }).toString("base64") ===
        value,
    code
  );
  return key;
}

function signaturePayload(receipt) {
  return Buffer.from(
    `tideproof.aws-deployment-evidence-signature.v1\0${canonicalJson(receipt)}`,
    "utf8"
  );
}

export function signDeploymentAttestationReceipt(
  unsignedReceipt,
  privateKeyBytes,
  expectedPublicKey
) {
  requireCondition(
    unsignedReceipt &&
      typeof unsignedReceipt === "object" &&
      !Array.isArray(unsignedReceipt) &&
      unsignedReceipt.signature === undefined &&
      (Buffer.isBuffer(privateKeyBytes) || typeof privateKeyBytes === "string"),
    "AWS_ATTEST_SIGN_INPUT"
  );
  const expectedKey = validatePublicKey(
    expectedPublicKey,
    "AWS_ATTEST_SIGN_PUBLIC_KEY"
  );
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(privateKeyBytes);
  } catch {
    throw new Error("AWS_ATTEST_SIGN_PRIVATE_KEY");
  }
  requireCondition(
    privateKey.asymmetricKeyType === "ed25519",
    "AWS_ATTEST_SIGN_PRIVATE_KEY"
  );
  const derivedPublicKey = crypto
    .createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .toString("base64");
  requireCondition(
    derivedPublicKey === expectedPublicKey &&
      crypto
        .createPublicKey(privateKey)
        .equals(expectedKey),
    "AWS_ATTEST_SIGN_KEY_MISMATCH"
  );
  const signatureValue = crypto
    .sign(null, signaturePayload(unsignedReceipt), privateKey)
    .toString("base64");
  requireCondition(
    BASE64_SIGNATURE.test(signatureValue),
    "AWS_ATTEST_SIGN_SIGNATURE"
  );
  return Object.freeze({
    ...unsignedReceipt,
    signature: {
      algorithm: "Ed25519",
      keyIdDigest: sha256(Buffer.from(expectedPublicKey, "base64")),
      value: signatureValue
    }
  });
}

function verifySignedReceipt(receipt, publicKey, code) {
  requireCondition(
    receipt &&
      typeof receipt === "object" &&
      !Array.isArray(receipt) &&
      exactKeys(receipt.signature, ["algorithm", "keyIdDigest", "value"]) &&
      receipt.signature.algorithm === "Ed25519" &&
      receipt.signature.keyIdDigest ===
        sha256(Buffer.from(publicKey, "base64")) &&
      BASE64_SIGNATURE.test(receipt.signature.value),
    code
  );
  const key = validatePublicKey(publicKey, code);
  const { signature, ...unsignedReceipt } = receipt;
  requireCondition(
    crypto.verify(
      null,
      signaturePayload(unsignedReceipt),
      key,
      Buffer.from(signature.value, "base64")
    ),
    code
  );
  return unsignedReceipt;
}

function validateExecutionRoleTrust(policy) {
  requireCondition(
    exactKeys(policy, ["Statement", "Version"]) &&
      policy.Version === "2012-10-17" &&
      Array.isArray(policy.Statement) &&
      policy.Statement.length === 1 &&
      exactKeys(policy.Statement[0], ["Action", "Effect", "Principal"]) &&
      policy.Statement[0].Effect === "Allow" &&
      policy.Statement[0].Action === "sts:AssumeRole" &&
      exactKeys(policy.Statement[0].Principal, ["Service"]) &&
      policy.Statement[0].Principal.Service === "lambda.amazonaws.com",
    "AWS_ATTEST_EXECUTION_ROLE_TRUST"
  );
  return sha256(policy);
}

function validateEvidenceOperatorTrust(policy, trustedPrincipalArn) {
  requireCondition(
    exactKeys(policy, ["Statement", "Version"]) &&
      policy.Version === "2012-10-17" &&
      Array.isArray(policy.Statement) &&
      policy.Statement.length === 1,
    "AWS_ATTEST_EVIDENCE_ROLE_TRUST"
  );
  const statement = policy.Statement[0];
  requireCondition(
    exactKeys(statement, ["Action", "Condition", "Effect", "Principal"]) &&
      statement.Effect === "Allow" &&
      statement.Action === "sts:AssumeRole" &&
      exactKeys(statement.Principal, ["AWS"]) &&
      statement.Principal.AWS === trustedPrincipalArn &&
      exactKeys(statement.Condition, ["StringEquals"]) &&
      exactKeys(statement.Condition.StringEquals, ["aws:PrincipalArn"]) &&
      statement.Condition.StringEquals["aws:PrincipalArn"] ===
        trustedPrincipalArn,
    "AWS_ATTEST_EVIDENCE_ROLE_TRUST"
  );
  return sha256(policy);
}

function validateAlternateRoleTrust(policy, accountId) {
  requireCondition(
    exactKeys(policy, ["Statement", "Version"]) &&
      policy.Version === "2012-10-17" &&
      Array.isArray(policy.Statement) &&
      policy.Statement.length === 1 &&
      exactKeys(policy.Statement[0], ["Action", "Effect", "Principal"]) &&
      policy.Statement[0].Action === "sts:AssumeRole" &&
      policy.Statement[0].Effect === "Allow" &&
      exactKeys(policy.Statement[0].Principal, ["AWS"]) &&
      policy.Statement[0].Principal.AWS ===
        `arn:aws:iam::${accountId}:root`,
    "AWS_ATTEST_ALTERNATE_ROLE_TRUST"
  );
  return sha256(policy);
}

function validateAlternateRolePolicy(policy, targetRoleArn) {
  requireCondition(
    exactKeys(policy, ["Statement", "Version"]) &&
      policy.Version === "2012-10-17" &&
      Array.isArray(policy.Statement),
    "AWS_ATTEST_ALTERNATE_ROLE_POLICY"
  );
  const allows = policy.Statement.filter(
    (statement) => statement?.Effect === "Allow"
  );
  const denyOther = policy.Statement.find(
    (statement) =>
      statement?.Effect === "Deny" &&
      statement?.Sid === "DenyOtherAssumeRoleTargets"
  );
  requireCondition(
    allows.length === 1 &&
      exactKeys(allows[0], ["Action", "Effect", "Resource", "Sid"]) &&
      allows[0].Sid === "AttemptOnlyDeploymentEvidenceRole" &&
      Array.isArray(allows[0].Action) &&
      allows[0].Action.length === 1 &&
      allows[0].Action[0] === "sts:AssumeRole" &&
      allows[0].Resource === targetRoleArn &&
      exactKeys(denyOther, ["Action", "Effect", "NotResource", "Sid"]) &&
      Array.isArray(denyOther.Action) &&
      denyOther.Action.length === 1 &&
      denyOther.Action[0] === "sts:AssumeRole" &&
      denyOther.NotResource === targetRoleArn,
    "AWS_ATTEST_ALTERNATE_ROLE_POLICY"
  );
}

function callerContextDigest(bindingContext) {
  return sha256(
    `tideproof.aws-evidence-context.v1\0${canonicalJson(bindingContext)}`
  );
}

function validatedCallerBinding(value, expectedPrincipalArn, bindingContext) {
  requireCondition(
    exactKeys(value, [
      "bindingDigest",
      "callerIdentityDigest",
      "contextDigest",
      "expectedIdentityDigest",
      "expectedPrincipalDigest",
      "principalIdDigest",
      "principalType"
    ]) &&
      HEX_64.test(value.callerIdentityDigest) &&
      value.expectedIdentityDigest === value.callerIdentityDigest &&
      value.expectedPrincipalDigest === sha256(expectedPrincipalArn) &&
      value.contextDigest === callerContextDigest(bindingContext) &&
      HEX_64.test(value.principalIdDigest) &&
      value.principalType ===
        (expectedPrincipalArn.includes(":role/")
          ? "assumed-role"
          : "iam-user"),
    "AWS_ATTEST_CALLER_BINDING"
  );
  const bindingDigest = sha256(
    [
      "tideproof.aws-evidence-caller-binding.v2",
      value.callerIdentityDigest,
      value.expectedIdentityDigest,
      value.expectedPrincipalDigest,
      value.principalIdDigest,
      value.contextDigest
    ].join("\0")
  );
  requireCondition(
    value.bindingDigest === bindingDigest,
    "AWS_ATTEST_CALLER_BINDING"
  );
  return value;
}

export function validateDeploymentExpectation(expectation) {
  requireCondition(
    exactKeys(expectation, [
      "accountId",
      "alternatePrincipal",
      "basis",
      "configDigest",
      "evidenceOperator",
      "functions",
      "receiptPublicKeys",
      "region",
      "schemaVersion",
      "sourceCommit",
      "stackId",
      "stackName",
      "templateCanonicalDigest",
      "treeDigest"
    ]) &&
      expectation.schemaVersion === EXPECTATION_SCHEMA &&
      /^\d{12}$/.test(expectation.accountId) &&
      expectation.region === "us-east-1" &&
      expectation.stackName === "prooftoact-gate2" &&
      HEX_40.test(expectation.sourceCommit) &&
      HEX_40.test(expectation.treeDigest) &&
      HEX_64.test(expectation.configDigest) &&
      HEX_64.test(expectation.templateCanonicalDigest) &&
      exactKeys(expectation.basis, [
        "buildReceiptSha256",
        "configurationSha256",
        "providerDependencyTreeDigest",
        "providerRuntimeSha256",
        "stackParameterCount",
        "stackParametersDigest"
      ]) &&
      HEX_64.test(expectation.basis.buildReceiptSha256) &&
      HEX_64.test(expectation.basis.configurationSha256) &&
      HEX_64.test(expectation.basis.providerDependencyTreeDigest) &&
      HEX_64.test(expectation.basis.providerRuntimeSha256) &&
      expectation.basis.stackParameterCount === 45 &&
      HEX_64.test(expectation.basis.stackParametersDigest),
    "AWS_ATTEST_EXPECTATION"
  );
  const stackPattern = new RegExp(
    `^arn:aws:cloudformation:${expectation.region}:` +
      `${expectation.accountId}:stack/${expectation.stackName}/` +
      "[0-9a-f-]{36}$"
  );
  requireCondition(
    stackPattern.test(expectation.stackId),
    "AWS_ATTEST_EXPECTATION_STACK"
  );
  const expectedEvidenceRoleArn =
    `arn:aws:iam::${expectation.accountId}:role/` +
    `${expectation.stackName}-evidence`;
  const expectedAlternateRoleArn = `${expectedEvidenceRoleArn}-alternate`;
  requireCondition(
    exactKeys(expectation.evidenceOperator, [
      "roleArn",
      "rolePolicyDigest",
      "trustedPrincipalArn"
    ]) &&
      expectation.evidenceOperator.roleArn === expectedEvidenceRoleArn &&
      HEX_64.test(expectation.evidenceOperator.rolePolicyDigest) &&
      sameAccountPrincipalArn(
        expectation.evidenceOperator.trustedPrincipalArn,
        expectation.accountId
      ) &&
      expectation.evidenceOperator.roleArn !==
        expectation.evidenceOperator.trustedPrincipalArn,
    "AWS_ATTEST_EXPECTATION_OPERATOR"
  );
  requireCondition(
    exactKeys(expectation.alternatePrincipal, [
      "roleArn",
      "rolePolicyDigest"
    ]) &&
      expectation.alternatePrincipal.roleArn === expectedAlternateRoleArn &&
      HEX_64.test(expectation.alternatePrincipal.rolePolicyDigest),
    "AWS_ATTEST_EXPECTATION_ALTERNATE"
  );
  requireCondition(
    exactKeys(expectation.receiptPublicKeys, [
      "alternateDenial",
      "post",
      "pre"
    ]),
    "AWS_ATTEST_EXPECTATION_RECEIPT_KEYS"
  );
  for (const [name, value] of Object.entries(
    expectation.receiptPublicKeys
  )) {
    validatePublicKey(
      value,
      `AWS_ATTEST_EXPECTATION_RECEIPT_KEY_${name.toUpperCase()}`
    );
  }
  requireCondition(
    new Set(Object.values(expectation.receiptPublicKeys)).size === 3,
    "AWS_ATTEST_EXPECTATION_RECEIPT_KEYS"
  );
  requireCondition(
    exactKeys(expectation.functions, DEPLOYMENT_FUNCTIONS),
    "AWS_ATTEST_EXPECTATION_FUNCTION_SET"
  );
  const baseArn = functionArnPattern(
    expectation.region,
    expectation.accountId
  );
  const roles = new Set();
  const functions = new Set();
  for (const name of DEPLOYMENT_FUNCTIONS) {
    const candidate = expectation.functions[name];
    requireCondition(
      exactKeys(candidate, [
        "aliasArn",
        "codeSha256",
        "configurationDigest",
        "functionArn",
        "functionName",
        "numericVersion",
        "numericVersionArn",
        "provisionedConcurrencyConfigurations",
        "reservedConcurrency",
        "roleArn",
        "rolePolicyDigest",
        "timeout"
      ]) &&
        baseArn.test(candidate.functionArn) &&
        candidate.functionName === candidate.functionArn.split(":").at(-1) &&
        /^[1-9][0-9]*$/.test(candidate.numericVersion) &&
        candidate.numericVersionArn ===
          `${candidate.functionArn}:${candidate.numericVersion}` &&
        candidate.aliasArn === `${candidate.functionArn}:proof` &&
        BASE64_SHA256.test(candidate.codeSha256) &&
        HEX_64.test(candidate.configurationDigest) &&
        roleArnPattern(expectation.accountId).test(candidate.roleArn) &&
        HEX_64.test(candidate.rolePolicyDigest) &&
        Array.isArray(candidate.provisionedConcurrencyConfigurations) &&
        candidate.provisionedConcurrencyConfigurations.length === 0 &&
        Number.isInteger(candidate.reservedConcurrency) &&
        candidate.reservedConcurrency >= 1 &&
        candidate.reservedConcurrency <= 8 &&
        Number.isInteger(candidate.timeout) &&
        candidate.timeout >= 1 &&
        candidate.timeout <= 30,
      `AWS_ATTEST_EXPECTATION_FUNCTION_${name.toUpperCase()}`
    );
    requireCondition(
      !roles.has(candidate.roleArn) && !functions.has(candidate.functionArn),
      "AWS_ATTEST_EXPECTATION_FUNCTION_UNIQUENESS"
    );
    roles.add(candidate.roleArn);
    functions.add(candidate.functionArn);
  }
  return expectation;
}

export function validateDeploymentEvidenceBasis({
  expectation: expectationInput,
  configuration,
  buildReceipt,
  configurationSha256,
  buildReceiptSha256
}) {
  const expectation = validateDeploymentExpectation(expectationInput);
  requireCondition(
    HEX_64.test(configurationSha256 ?? "") &&
      HEX_64.test(buildReceiptSha256 ?? "") &&
      expectation.basis.configurationSha256 === configurationSha256 &&
      expectation.basis.buildReceiptSha256 === buildReceiptSha256,
    "AWS_ATTEST_BASIS_FILE_DIGEST"
  );
  let computedConfigDigest;
  let stackParameters;
  try {
    computedConfigDigest = deploymentConfigDigest(configuration);
    stackParameters = deploymentStackParameterBindings(configuration);
  } catch {
    throw new Error("AWS_ATTEST_BASIS_CONFIGURATION");
  }
  requireCondition(
    computedConfigDigest === expectation.configDigest &&
      Object.keys(stackParameters).length ===
        expectation.basis.stackParameterCount &&
      sha256(stackParameters) === expectation.basis.stackParametersDigest &&
      configuration.sourceCommit === expectation.sourceCommit &&
      configuration.probesEnabled === false &&
      configuration.treeDigest === expectation.treeDigest &&
      configuration.accountId === expectation.accountId &&
      configuration.region === expectation.region &&
      configuration.stackName === expectation.stackName &&
      configuration.evidenceOperator.principalArn ===
        expectation.evidenceOperator.trustedPrincipalArn &&
      exactKeys(configuration.attestation.receiptPublicKeys, [
        "alternateDenial",
        "post",
        "pre"
      ]) &&
      DEPLOYMENT_FUNCTIONS.every(
        (name) =>
          configuration.attestation.functionConfigurationDigests[name] ===
            expectation.functions[name].configurationDigest &&
          configuration.attestation.functionRolePolicyDigests[name] ===
            expectation.functions[name].rolePolicyDigest &&
          configuration.reservedConcurrency[name] ===
            expectation.functions[name].reservedConcurrency &&
          configuration.artifactCodeSha256[name] ===
            expectation.functions[name].codeSha256
      ) &&
      configuration.attestation.evidenceRolePolicyDigest ===
        expectation.evidenceOperator.rolePolicyDigest &&
      configuration.attestation.alternateRolePolicyDigest ===
        expectation.alternatePrincipal.rolePolicyDigest &&
      canonicalJson(configuration.attestation.receiptPublicKeys) ===
        canonicalJson(expectation.receiptPublicKeys),
    "AWS_ATTEST_BASIS_CONFIGURATION_BINDING"
  );
  requireCondition(
    buildReceipt &&
      buildReceipt.schemaVersion === "tideproof.gate2-build.v6" &&
      buildReceipt.mode === "CLEAN_ARTIFACT_BUILD" &&
      buildReceipt.projectSourceMode ===
        "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
      buildReceipt.sourceCommit === expectation.sourceCommit &&
      buildReceipt.treeDigest === expectation.treeDigest &&
      buildReceipt.workingTreeClean === true &&
      buildReceipt.workingTreeCleanBeforeGeneration === true &&
      buildReceipt.dependencySnapshot?.treeDigest ===
        expectation.basis.providerDependencyTreeDigest &&
      buildReceipt.evidenceProviderRuntime?.sha256 ===
        expectation.basis.providerRuntimeSha256 &&
      buildReceipt.gate2Template?.templateDigest ===
        configuration.templateDigest &&
      buildReceipt.gate2Template?.canonicalDigest ===
        expectation.templateCanonicalDigest &&
      Array.isArray(buildReceipt.buildControlInputs) &&
      buildReceipt.buildControlInputs.length === 15 &&
      Array.isArray(buildReceipt.artifacts),
    "AWS_ATTEST_BASIS_BUILD_RECEIPT"
  );
  const artifacts = new Map(
    buildReceipt.artifacts.map((artifact) => [artifact?.name, artifact])
  );
  requireCondition(
    artifacts.size === DEPLOYMENT_ARTIFACTS.length &&
      DEPLOYMENT_ARTIFACTS.every((name) => artifacts.has(name)) &&
      DEPLOYMENT_ARTIFACTS.every((name) => {
        const artifact = artifacts.get(name);
        return (
          artifact?.artifactCodeSha256 ===
            configuration.artifactCodeSha256[name] &&
          artifact?.artifactDigest === configuration.artifactDigests[name] &&
          artifact?.sourceDigest === configuration.artifactSourceDigests[name] &&
          artifact?.suggestedS3Key === configuration.artifactKeys[name]
        );
      }),
    "AWS_ATTEST_BASIS_ARTIFACTS"
  );
  return Object.freeze({
    buildReceiptSha256,
    configurationSha256,
    configDigest: expectation.configDigest,
    sourceCommit: expectation.sourceCommit,
    providerRuntimeSha256: expectation.basis.providerRuntimeSha256,
    stackParameterCount: expectation.basis.stackParameterCount,
    stackParametersDigest: expectation.basis.stackParametersDigest,
    treeDigest: expectation.treeDigest,
    templateCanonicalDigest: expectation.templateCanonicalDigest
  });
}

function validateResourceDrift(value, name) {
  requireCondition(
    exactKeys(value, ["alias", "function", "role", "version"]) &&
      Object.values(value).every((status) => status === "IN_SYNC"),
    `AWS_ATTEST_RESOURCE_DRIFT_${name.toUpperCase()}`
  );
}

function validateRoleSnapshot(
  actual,
  {
    code,
    expectedArn,
    expectedPolicyDigest,
    trustValidator,
    alternateTargetRoleArn = null
  }
) {
  requireCondition(
    exactKeys(actual, [
      "arn",
      "attachedManagedPolicies",
      "inlinePolicies",
      "maxSessionDuration",
      "permissionsBoundary",
      "resourceDrift",
      "roleId",
      "tags",
      "trustPolicy"
    ]) &&
      actual.arn === expectedArn &&
      actual.maxSessionDuration === 3600 &&
      ROLE_ID.test(actual.roleId) &&
      actual.permissionsBoundary === null &&
      Array.isArray(actual.attachedManagedPolicies) &&
      actual.attachedManagedPolicies.length === 0 &&
      Array.isArray(actual.inlinePolicies) &&
      actual.inlinePolicies.length === 1 &&
      exactKeys(actual.inlinePolicies[0], ["document", "name"]) &&
      actual.inlinePolicies[0].name === "ProofToActExactCapabilities" &&
      canonicalJson(actual.tags) === canonicalJson(EXPECTED_ROLE_TAGS) &&
      actual.resourceDrift === "IN_SYNC",
    code
  );
  const policy = actual.inlinePolicies[0].document;
  const policyDigest = sha256(policy);
  requireCondition(policyDigest === expectedPolicyDigest, code);
  if (alternateTargetRoleArn) {
    validateAlternateRolePolicy(policy, alternateTargetRoleArn);
  }
  const trustDigest = trustValidator(actual.trustPolicy);
  const censusDigest = sha256({
    attachedManagedPolicies: actual.attachedManagedPolicies,
    inlinePolicyNames: actual.inlinePolicies.map((item) => item.name),
    permissionsBoundary: actual.permissionsBoundary
  });
  const deployment = {
    arnDigest: sha256(actual.arn),
    censusDigest,
    maxSessionDuration: actual.maxSessionDuration,
    policyDigest,
    roleIdDigest: sha256(actual.roleId),
    tagsDigest: sha256(actual.tags),
    trustDigest
  };
  return Object.freeze({
    ...deployment,
    roleId: actual.roleId,
    deploymentDigest: sha256({
      schemaVersion: "tideproof.gate2.role-deployment.v3",
      ...deployment
    })
  });
}

function validateFunctionResourcePolicies(
  actual,
  name,
  expected,
  expectation,
  httpApiId
) {
  requireCondition(
    exactKeys(actual, ["alias", "numeric", "unqualified"]) &&
      actual.alias === null &&
      actual.unqualified === null,
    `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
  );
  const sourcePrefix =
    `arn:aws:execute-api:${expectation.region}:` +
    `${expectation.accountId}:${httpApiId}/$default/`;
  const expectedSources = {
    agent: [],
    authority: [],
    boundary: [`${sourcePrefix}POST/advisory`],
    demo: [`${sourcePrefix}GET/`, `${sourcePrefix}GET/*`],
    signer: []
  }[name];
  requireCondition(
    Array.isArray(expectedSources),
    `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
  );
  if (expectedSources.length === 0) {
    requireCondition(
      actual.numeric === null,
      `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
    );
    return sha256(actual);
  }
  requireCondition(
    exactKeys(actual.numeric, ["policy", "revisionId"]) &&
      REVISION_ID.test(actual.numeric.revisionId),
    `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
  );
  const policy = actual.numeric.policy;
  requireCondition(
    exactKeys(policy, ["Id", "Statement", "Version"]) &&
      policy.Id === "default" &&
      policy.Version === "2012-10-17" &&
      Array.isArray(policy.Statement) &&
      policy.Statement.length === expectedSources.length,
    `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
  );
  const actualSources = policy.Statement.map((statement) => {
    requireCondition(
      exactKeys(statement, [
        "Action",
        "Condition",
        "Effect",
        "Principal",
        "Resource",
        "Sid"
      ]) &&
        statement.Action === "lambda:InvokeFunction" &&
        statement.Effect === "Allow" &&
        exactKeys(statement.Principal, ["Service"]) &&
        statement.Principal.Service === "apigateway.amazonaws.com" &&
        statement.Resource === expected.numericVersionArn &&
        typeof statement.Sid === "string" &&
        statement.Sid.length >= 1 &&
        statement.Sid.length <= 100 &&
        exactKeys(statement.Condition, ["ArnLike", "StringEquals"]) &&
        exactKeys(statement.Condition.ArnLike, ["AWS:SourceArn"]) &&
        exactKeys(statement.Condition.StringEquals, ["AWS:SourceAccount"]) &&
        statement.Condition.StringEquals["AWS:SourceAccount"] ===
          expectation.accountId &&
        typeof statement.Condition.ArnLike["AWS:SourceArn"] === "string",
      `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
    );
    return statement.Condition.ArnLike["AWS:SourceArn"];
  });
  requireCondition(
    actualSources.sort().join("\n") === expectedSources.sort().join("\n"),
    `AWS_ATTEST_FUNCTION_RESOURCE_POLICY_${name.toUpperCase()}`
  );
  return sha256(actual);
}

function validateFunctionSnapshot(
  name,
  actual,
  expected,
  expectation,
  httpApiId
) {
  requireCondition(
    exactKeys(actual, [
      "aliasArn",
      "aliasName",
      "aliasRevisionId",
      "aliasRoutingConfiguration",
      "aliasTargetVersion",
      "aliases",
      "codeSha256",
      "codeSigningConfig",
      "configuration",
      "functionArn",
      "functionName",
      "functionTags",
      "functionUrlConfigs",
      "lastUpdateStatus",
      "numericRevisionId",
      "numericVersion",
      "numericVersionArn",
      "eventSourceMappings",
      "provisionedConcurrencyConfigurations",
      "recursionConfig",
      "reservedConcurrency",
      "resourceDrift",
      "resourcePolicies",
      "role",
      "runtimeManagementConfig",
      "state"
    ]),
    `AWS_ATTEST_FUNCTION_SHAPE_${name.toUpperCase()}`
  );
  validateResourceDrift(actual.resourceDrift, name);
  const configuration = actual.configuration;
  requireCondition(
    exactKeys(configuration, [
      "architectures",
      "deadLetterTargetArn",
      "environment",
      "ephemeralStorageSize",
      "fileSystemConfigs",
      "handler",
      "kmsKeyArn",
      "layers",
      "loggingConfig",
      "memorySize",
      "packageType",
      "runtime",
      "runtimeVersion",
      "signingJobArn",
      "signingProfileVersionArn",
      "snapStartApplyOn",
      "timeout",
      "tracingMode",
      "vpcConfig"
    ]) &&
      Array.isArray(configuration.architectures) &&
      configuration.architectures.length === 1 &&
      configuration.architectures[0] === "arm64" &&
      configuration.deadLetterTargetArn === null &&
      configuration.ephemeralStorageSize === 512 &&
      Array.isArray(configuration.fileSystemConfigs) &&
      configuration.fileSystemConfigs.length === 0 &&
      configuration.handler === "index.handler" &&
      configuration.kmsKeyArn === null &&
      Array.isArray(configuration.layers) &&
      configuration.layers.length === 0 &&
      configuration.memorySize === 128 &&
      configuration.packageType === "Zip" &&
      configuration.runtime === "nodejs22.x" &&
      exactKeys(configuration.runtimeVersion, [
        "errorCode",
        "errorMessage",
        "runtimeVersionArn"
      ]) &&
      configuration.runtimeVersion.errorCode === null &&
      configuration.runtimeVersion.errorMessage === null &&
      typeof configuration.runtimeVersion.runtimeVersionArn === "string" &&
      configuration.runtimeVersion.runtimeVersionArn.startsWith(
        `arn:aws:lambda:${expectation.region}::runtime:`
      ) &&
      configuration.signingJobArn === null &&
      configuration.signingProfileVersionArn === null &&
      configuration.snapStartApplyOn === "None" &&
      configuration.timeout === expected.timeout &&
      configuration.tracingMode === "PassThrough" &&
      configuration.vpcConfig?.vpcId === null &&
      Array.isArray(configuration.vpcConfig?.subnetIds) &&
      configuration.vpcConfig.subnetIds.length === 0 &&
      Array.isArray(configuration.vpcConfig?.securityGroupIds) &&
      configuration.vpcConfig.securityGroupIds.length === 0 &&
      configuration.vpcConfig.ipv6AllowedForDualStack === false &&
      configuration.environment.CONFIG_DIGEST === expectation.configDigest &&
      configuration.environment.SOURCE_COMMIT === expectation.sourceCommit &&
      configuration.environment.TREE_DIGEST === expectation.treeDigest &&
      deploymentFunctionConfigurationDigest(configuration) ===
        expected.configurationDigest,
    `AWS_ATTEST_FUNCTION_CONFIGURATION_${name.toUpperCase()}`
  );
  const role = validateRoleSnapshot(actual.role, {
    code: `AWS_ATTEST_FUNCTION_ROLE_${name.toUpperCase()}`,
    expectedArn: expected.roleArn,
    expectedPolicyDigest: expected.rolePolicyDigest,
    trustValidator: validateExecutionRoleTrust
  });
  const resourcePolicyDigest = validateFunctionResourcePolicies(
    actual.resourcePolicies,
    name,
    expected,
    expectation,
    httpApiId
  );
  requireCondition(
    actual.functionArn === expected.functionArn &&
      actual.functionName === expected.functionName &&
      actual.numericVersion === expected.numericVersion &&
      actual.numericVersionArn === expected.numericVersionArn &&
      actual.aliasArn === expected.aliasArn &&
      actual.aliasName === "proof" &&
      actual.aliasTargetVersion === expected.numericVersion &&
      exactKeys(actual.aliasRoutingConfiguration, []) &&
      Array.isArray(actual.aliases) &&
      actual.aliases.length === 1 &&
      exactKeys(actual.aliases[0], [
        "aliasArn",
        "description",
        "functionVersion",
        "name",
        "revisionId",
        "routingConfiguration"
      ]) &&
      actual.aliases[0].aliasArn === actual.aliasArn &&
      actual.aliases[0].description ===
        "Monitored proof pointer; all reviewed invocations use the numeric version ARN." &&
      actual.aliases[0].functionVersion === actual.aliasTargetVersion &&
      actual.aliases[0].name === actual.aliasName &&
      actual.aliases[0].revisionId === actual.aliasRevisionId &&
      exactKeys(actual.aliases[0].routingConfiguration, []) &&
      Array.isArray(actual.eventSourceMappings) &&
      actual.eventSourceMappings.length === 0 &&
      Array.isArray(actual.functionUrlConfigs) &&
      actual.functionUrlConfigs.length === 0 &&
      canonicalJson(actual.functionTags) ===
        canonicalJson(EXPECTED_RESOURCE_TAGS) &&
      actual.codeSha256 === expected.codeSha256 &&
      exactKeys(actual.codeSigningConfig, ["codeSigningConfigArn"]) &&
      actual.codeSigningConfig.codeSigningConfigArn === null &&
      exactKeys(actual.recursionConfig, ["recursiveLoop"]) &&
      actual.recursionConfig.recursiveLoop === "Terminate" &&
      exactKeys(actual.runtimeManagementConfig, [
        "runtimeVersionArn",
        "updateRuntimeOn"
      ]) &&
      actual.runtimeManagementConfig.runtimeVersionArn === null &&
      actual.runtimeManagementConfig.updateRuntimeOn === "Auto" &&
      Array.isArray(actual.provisionedConcurrencyConfigurations) &&
      actual.provisionedConcurrencyConfigurations.length === 0 &&
      actual.reservedConcurrency === expected.reservedConcurrency &&
      actual.state === "Active" &&
      actual.lastUpdateStatus === "Successful" &&
      REVISION_ID.test(actual.numericRevisionId) &&
      REVISION_ID.test(actual.aliasRevisionId),
    `AWS_ATTEST_FUNCTION_BINDING_${name.toUpperCase()}`
  );
  const deployment = {
    aliasRevisionId: actual.aliasRevisionId,
    aliasTargetVersion: actual.aliasTargetVersion,
    codeSha256: actual.codeSha256,
    codeSigningConfigDigest: sha256(actual.codeSigningConfig),
    configurationDigest: expected.configurationDigest,
    functionArnDigest: sha256(actual.functionArn),
    ingressCensusDigest: sha256({
      aliases: actual.aliases,
      eventSourceMappings: actual.eventSourceMappings,
      functionUrlConfigs: actual.functionUrlConfigs,
      functionTags: actual.functionTags
    }),
    numericRevisionId: actual.numericRevisionId,
    numericVersion: actual.numericVersion,
    provisionedConcurrencyConfigurations: 0,
    recursionConfigDigest: sha256(actual.recursionConfig),
    resourcePolicyDigest,
    providerRuntimeVersionDigest: sha256(configuration.runtimeVersion),
    reservedConcurrency: actual.reservedConcurrency,
    roleDeploymentDigest: role.deploymentDigest,
    runtimeManagementConfigDigest: sha256(
      actual.runtimeManagementConfig
    )
  };
  return Object.freeze({
    numericVersion: actual.numericVersion,
    deploymentDigest: sha256({
      schemaVersion: "tideproof.gate2.function-deployment.v3",
      sourceCommit: expectation.sourceCommit,
      configDigest: expectation.configDigest,
      name,
      ...deployment
    })
  });
}

function validateApiGatewayStackBindings(actual) {
  const logicalIds = [
    "ApiAccessLogGroup",
    "ApiDeployment",
    "DefaultStage",
    "HttpApi",
    ...Object.keys(DEPLOYMENT_API_INTEGRATIONS),
    ...Object.keys(DEPLOYMENT_API_ROUTE_KEYS)
  ].sort();
  requireCondition(
    exactKeys(actual, logicalIds),
    "AWS_ATTEST_API_STACK_BINDINGS"
  );
  const physicalIds = [];
  for (const logicalId of logicalIds) {
    const binding = actual[logicalId];
    const resourceType =
      logicalId === "ApiAccessLogGroup"
        ? "AWS::Logs::LogGroup"
        : logicalId === "ApiDeployment"
          ? "AWS::ApiGatewayV2::Deployment"
        : logicalId === "HttpApi"
        ? "AWS::ApiGatewayV2::Api"
        : logicalId === "DefaultStage"
          ? "AWS::ApiGatewayV2::Stage"
          : Object.hasOwn(DEPLOYMENT_API_INTEGRATIONS, logicalId)
            ? "AWS::ApiGatewayV2::Integration"
            : "AWS::ApiGatewayV2::Route";
    const physicalPattern =
      logicalId === "ApiAccessLogGroup"
        ? /^[A-Za-z0-9._/#-]{1,512}$/
        : logicalId === "ApiDeployment"
          ? /^[a-z0-9]{1,64}$/
        : logicalId === "HttpApi"
        ? /^[a-z0-9]{10}$/
        : logicalId === "DefaultStage"
          ? /^\$default$/
          : /^[a-z0-9]{1,64}$/;
    requireCondition(
      exactKeys(binding, [
        "physicalResourceId",
        "resourceStatus",
        "resourceType"
      ]) &&
        physicalPattern.test(binding.physicalResourceId) &&
        binding.resourceStatus === "CREATE_COMPLETE" &&
        binding.resourceType === resourceType,
      "AWS_ATTEST_API_STACK_BINDINGS"
    );
    physicalIds.push(binding.physicalResourceId);
  }
  requireCondition(
    new Set(physicalIds).size === physicalIds.length,
    "AWS_ATTEST_API_STACK_BINDINGS"
  );
  return actual;
}

function validateApiRouteSettings(
  value,
  { burst, rate, code }
) {
  requireCondition(
    exactKeys(value, [
      "dataTraceEnabled",
      "detailedMetricsEnabled",
      "loggingLevel",
      "throttlingBurstLimit",
      "throttlingRateLimit"
    ]) &&
      value.dataTraceEnabled === false &&
      value.detailedMetricsEnabled === false &&
      value.loggingLevel === null &&
      value.throttlingBurstLimit === burst &&
      value.throttlingRateLimit === rate,
    code
  );
}

function validateApiGatewaySnapshot(actual, expectation) {
  requireCondition(
    exactKeys(actual, [
      "activeDeployment",
      "api",
      "census",
      "integrations",
      "routes",
      "stackResourceBindings",
      "stage"
    ]),
    "AWS_ATTEST_API_GATEWAY"
  );
  const bindings = validateApiGatewayStackBindings(
    actual.stackResourceBindings
  );
  const apiId = bindings.HttpApi.physicalResourceId;
  requireCondition(
    exactKeys(actual.api, [
      "apiGatewayManaged",
      "apiKeySelectionExpression",
      "apiEndpoint",
      "apiId",
      "corsConfiguration",
      "description",
      "disableExecuteApiEndpoint",
      "disableSchemaValidation",
      "importInfo",
      "ipAddressType",
      "name",
      "protocolType",
      "resourceDrift",
      "routeSelectionExpression",
      "tags",
      "version",
      "warnings"
    ]) &&
      actual.api.apiGatewayManaged === false &&
      actual.api.apiKeySelectionExpression ===
        "$request.header.x-api-key" &&
      actual.api.apiId === apiId &&
      actual.api.apiEndpoint ===
        `https://${apiId}.execute-api.${expectation.region}.amazonaws.com` &&
      actual.api.disableExecuteApiEndpoint === false &&
      exactKeys(actual.api.corsConfiguration, []) &&
      actual.api.description ===
        "Signed-out read-only ProofToAct demo plus an isolated IAM-authenticated advisory endpoint." &&
      actual.api.disableSchemaValidation === false &&
      Array.isArray(actual.api.importInfo) &&
      actual.api.importInfo.length === 0 &&
      actual.api.ipAddressType === "ipv4" &&
      actual.api.name === `${expectation.stackName}-api` &&
      actual.api.protocolType === "HTTP" &&
      actual.api.resourceDrift === "IN_SYNC" &&
      actual.api.routeSelectionExpression ===
        "$request.method $request.path" &&
      canonicalJson(actual.api.tags) ===
        canonicalJson(EXPECTED_RESOURCE_TAGS) &&
      actual.api.version === "" &&
      Array.isArray(actual.api.warnings) &&
      actual.api.warnings.length === 0,
    "AWS_ATTEST_API_GATEWAY_API"
  );
  requireCondition(
    exactKeys(
      actual.integrations,
      Object.keys(DEPLOYMENT_API_INTEGRATIONS)
    ),
    "AWS_ATTEST_API_GATEWAY_INTEGRATIONS"
  );
  for (const [logicalId, expected] of Object.entries(
    DEPLOYMENT_API_INTEGRATIONS
  )) {
    const integration = actual.integrations[logicalId];
    requireCondition(
      exactKeys(integration, [
        "apiGatewayManaged",
        "connectionId",
        "connectionType",
        "contentHandlingStrategy",
        "credentialsArn",
        "description",
        "integrationId",
        "integrationMethod",
        "integrationResponseSelectionExpression",
        "integrationSubtype",
        "integrationType",
        "integrationUri",
        "passthroughBehavior",
        "payloadFormatVersion",
        "requestParameters",
        "requestTemplates",
        "responseParameters",
        "templateSelectionExpression",
        "timeoutInMillis",
        "tlsConfig"
      ]) &&
        integration.apiGatewayManaged === false &&
        integration.connectionId === null &&
        integration.connectionType === "INTERNET" &&
        integration.contentHandlingStrategy === null &&
        integration.credentialsArn === null &&
        integration.description === "" &&
        integration.integrationId ===
          bindings[logicalId].physicalResourceId &&
        integration.integrationMethod === "POST" &&
        integration.integrationResponseSelectionExpression === null &&
        integration.integrationSubtype === null &&
        integration.integrationType === "AWS_PROXY" &&
        integration.integrationUri ===
          expectation.functions[expected.functionName].numericVersionArn &&
        integration.passthroughBehavior === null &&
        integration.payloadFormatVersion === "2.0" &&
        exactKeys(integration.requestParameters, []) &&
        exactKeys(integration.requestTemplates, []) &&
        exactKeys(integration.responseParameters, []) &&
        integration.templateSelectionExpression === null &&
        integration.timeoutInMillis === expected.timeoutInMillis &&
        integration.tlsConfig === null,
      `AWS_ATTEST_API_GATEWAY_INTEGRATION_${logicalId.toUpperCase()}`
    );
  }
  requireCondition(
    exactKeys(actual.routes, Object.keys(DEPLOYMENT_API_ROUTE_KEYS)),
    "AWS_ATTEST_API_GATEWAY_ROUTES"
  );
  for (const [logicalId, routeKey] of Object.entries(
    DEPLOYMENT_API_ROUTE_KEYS
  )) {
    const route = actual.routes[logicalId];
    const advisory = logicalId === "AdvisoryRoute";
    const targetIntegration = advisory
      ? bindings.BoundaryIntegration.physicalResourceId
      : bindings.DemoIntegration.physicalResourceId;
    requireCondition(
      exactKeys(route, [
        "apiKeyRequired",
        "authorizationScopes",
        "authorizationType",
        "authorizerId",
        "modelSelectionExpression",
        "operationName",
        "requestModels",
        "requestParameters",
        "resourceDrift",
        "routeId",
        "routeKey",
        "routeResponseSelectionExpression",
        "target"
      ]) &&
        route.apiKeyRequired === false &&
        Array.isArray(route.authorizationScopes) &&
        route.authorizationScopes.length === 0 &&
        route.authorizationType === (advisory ? "AWS_IAM" : "NONE") &&
        route.authorizerId === null &&
        route.modelSelectionExpression === null &&
        route.operationName === "" &&
        exactKeys(route.requestModels, []) &&
        exactKeys(route.requestParameters, []) &&
        route.resourceDrift === "IN_SYNC" &&
        route.routeId === bindings[logicalId].physicalResourceId &&
        route.routeKey === routeKey &&
        route.routeResponseSelectionExpression === null &&
        route.target === `integrations/${targetIntegration}`,
      `AWS_ATTEST_API_GATEWAY_ROUTE_${logicalId.toUpperCase()}`
    );
  }
  const expectedIntegrationIds = Object.keys(DEPLOYMENT_API_INTEGRATIONS)
    .map((logicalId) => bindings[logicalId].physicalResourceId)
    .sort();
  const expectedRouteIds = Object.keys(DEPLOYMENT_API_ROUTE_KEYS)
    .map((logicalId) => bindings[logicalId].physicalResourceId)
    .sort();
  requireCondition(
    exactKeys(actual.census, [
      "deployments",
      "integrationIds",
      "routeIds",
      "stageNames"
    ]) &&
      canonicalJson(actual.census.integrationIds) ===
        canonicalJson(expectedIntegrationIds) &&
      canonicalJson(actual.census.routeIds) ===
        canonicalJson(expectedRouteIds) &&
      canonicalJson(actual.census.stageNames) ===
        canonicalJson(["$default"]),
    "AWS_ATTEST_API_GATEWAY_CENSUS"
  );
  requireCondition(
    Array.isArray(actual.census.deployments) &&
      actual.census.deployments.length > 0 &&
      actual.census.deployments.every(
        (deployment) =>
          exactKeys(deployment, [
            "autoDeployed",
            "createdAt",
            "deploymentId",
            "deploymentStatus"
          ]) &&
          typeof deployment.autoDeployed === "boolean" &&
          typeof deployment.deploymentId === "string" &&
          typeof deployment.deploymentStatus === "string" &&
          !Number.isNaN(Date.parse(deployment.createdAt))
      ) &&
      new Set(
        actual.census.deployments.map(({ deploymentId }) => deploymentId)
      ).size === actual.census.deployments.length &&
      canonicalJson(actual.census.deployments) ===
        canonicalJson(
          [...actual.census.deployments].sort((left, right) =>
            left.createdAt.localeCompare(right.createdAt) ||
            left.deploymentId.localeCompare(right.deploymentId)
          )
        ),
    "AWS_ATTEST_API_GATEWAY_DEPLOYMENT_CENSUS"
  );
  const expectedAccessLogFormat = JSON.stringify({
    apiId: "$context.apiId",
    backendStatus: "$context.integration.status",
    callerArn: "$context.identity.userArn",
    lambdaServiceStatus: "$context.integration.integrationStatus",
    requestId: "$context.requestId",
    requestTimeEpoch: "$context.requestTimeEpoch",
    routeKey: "$context.routeKey",
    status: "$context.status"
  });
  const expectedAccessLogDestination =
    `arn:aws:logs:${expectation.region}:${expectation.accountId}:` +
    `log-group:${bindings.ApiAccessLogGroup.physicalResourceId}:*`;
  requireCondition(
    exactKeys(actual.stage, [
      "accessLogSettings",
      "autoDeploy",
      "clientCertificateId",
      "defaultRouteSettings",
      "deploymentId",
      "description",
      "lastDeploymentStatusMessage",
      "resourceDrift",
      "routeSettings",
      "stageName",
      "stageVariables",
      "tags"
    ]) &&
      exactKeys(actual.stage.accessLogSettings, [
        "destinationArn",
        "format"
      ]) &&
      actual.stage.accessLogSettings.destinationArn ===
        expectedAccessLogDestination &&
      actual.stage.accessLogSettings.format === expectedAccessLogFormat &&
      actual.stage.autoDeploy === false &&
      actual.stage.clientCertificateId === null &&
      actual.stage.deploymentId ===
        bindings.ApiDeployment.physicalResourceId &&
      actual.stage.description === "" &&
      actual.stage.lastDeploymentStatusMessage === "" &&
      actual.stage.resourceDrift === "IN_SYNC" &&
      exactKeys(actual.stage.routeSettings, ["POST /advisory"]) &&
      actual.stage.stageName === "$default" &&
      exactKeys(actual.stage.stageVariables, []) &&
      canonicalJson(actual.stage.tags) ===
        canonicalJson(EXPECTED_RESOURCE_TAGS),
    "AWS_ATTEST_API_GATEWAY_STAGE"
  );
  const activeDeployment = actual.activeDeployment;
  const activeCensusDeployment = actual.census.deployments.find(
    ({ deploymentId }) => deploymentId === actual.stage.deploymentId
  );
  const activeCreatedAt = Date.parse(activeDeployment?.createdAt);
  requireCondition(
    exactKeys(activeDeployment, [
      "autoDeployed",
      "createdAt",
      "deploymentId",
      "deploymentStatus",
      "deploymentStatusMessage",
      "description"
    ]) &&
      activeDeployment.autoDeployed === false &&
      activeDeployment.deploymentId ===
        bindings.ApiDeployment.physicalResourceId &&
      activeDeployment.deploymentStatus === "DEPLOYED" &&
      activeDeployment.deploymentStatusMessage === "" &&
      activeDeployment.description ===
        `ProofToAct exact API deployment ${expectation.sourceCommit} ${expectation.configDigest}` &&
      !Number.isNaN(activeCreatedAt) &&
      canonicalJson(activeCensusDeployment) ===
        canonicalJson({
          autoDeployed: activeDeployment.autoDeployed,
          createdAt: activeDeployment.createdAt,
          deploymentId: activeDeployment.deploymentId,
          deploymentStatus: activeDeployment.deploymentStatus
        }) &&
      actual.census.deployments.every(
        (deployment) =>
          deployment.deploymentId === activeDeployment.deploymentId ||
          Date.parse(deployment.createdAt) < activeCreatedAt
      ),
    "AWS_ATTEST_API_GATEWAY_ACTIVE_DEPLOYMENT"
  );
  validateApiRouteSettings(actual.stage.defaultRouteSettings, {
    burst: 8,
    code: "AWS_ATTEST_API_GATEWAY_DEFAULT_THROTTLE",
    rate: 0.05
  });
  validateApiRouteSettings(actual.stage.routeSettings["POST /advisory"], {
    burst: 1,
    code: "AWS_ATTEST_API_GATEWAY_ADVISORY_THROTTLE",
    rate: 0.1
  });
  return sha256({
    schemaVersion: "tideproof.gate2.api-gateway-deployment.v2",
    sourceCommit: expectation.sourceCommit,
    configDigest: expectation.configDigest,
    ...actual
  });
}

function snapshotStatePayload(snapshot) {
  return {
    callerIdentity: snapshot.callerIdentity,
    evidenceOperatorRole: snapshot.evidenceOperatorRole,
    alternatePrincipalRole: snapshot.alternatePrincipalRole,
    apiGateway: snapshot.apiGateway,
    functions: snapshot.functions,
    providerDependencyTreeDigest: snapshot.providerDependencyTreeDigest,
    providerRuntimeSha256: snapshot.providerRuntimeSha256,
    region: snapshot.region,
    stack: snapshot.stack
  };
}

function snapshotReceiptPayload(receipt) {
  return {
    schemaVersion: receipt.schemaVersion,
    status: receipt.status,
    phase: receipt.phase,
    observationStartedAt: receipt.observationStartedAt,
    observedAt: receipt.observedAt,
    sourceCommit: receipt.sourceCommit,
    treeDigest: receipt.treeDigest,
    configDigest: receipt.configDigest,
    templateCanonicalDigest: receipt.templateCanonicalDigest,
    basisDigest: receipt.basisDigest,
    apiGatewayDigest: receipt.apiGatewayDigest,
    expectationDigest: receipt.expectationDigest,
    callerBinding: receipt.callerBinding,
    evidenceOperator: receipt.evidenceOperator,
    alternatePrincipal: receipt.alternatePrincipal,
    stackDigest: receipt.stackDigest,
    observationFenceDigest: receipt.observationFenceDigest,
    functions: receipt.functions,
    providerDependencyTreeDigest: receipt.providerDependencyTreeDigest,
    providerRuntimeSha256: receipt.providerRuntimeSha256,
    finalReleaseReady: false,
    claimBoundary: receipt.claimBoundary
  };
}

function validateSnapshotReceipt(receipt, expectation, expectedPhase) {
  requireCondition(
    exactKeys(receipt, [
      "alternatePrincipal",
      "apiGatewayDigest",
      "basisDigest",
      "callerBinding",
      "claimBoundary",
      "configDigest",
      "evidenceOperator",
      "expectationDigest",
      "finalReleaseReady",
      "functions",
      "observationFenceDigest",
      "observationStartedAt",
      "observedAt",
      "phase",
      "providerDependencyTreeDigest",
      "providerRuntimeSha256",
      "schemaVersion",
      "signature",
      "snapshotDigest",
      "sourceCommit",
      "stackDigest",
      "status",
      "templateCanonicalDigest",
      "treeDigest"
    ]) &&
      receipt.schemaVersion === SNAPSHOT_RECEIPT_SCHEMA &&
      receipt.phase === expectedPhase &&
      receipt.status === `${expectedPhase.toUpperCase()}_ATTESTATION_PASS` &&
      receipt.finalReleaseReady === false &&
      receipt.claimBoundary === SNAPSHOT_CLAIM_BOUNDARY &&
      receipt.sourceCommit === expectation.sourceCommit &&
      receipt.treeDigest === expectation.treeDigest &&
      receipt.configDigest === expectation.configDigest &&
      receipt.templateCanonicalDigest === expectation.templateCanonicalDigest &&
      receipt.providerDependencyTreeDigest ===
        expectation.basis.providerDependencyTreeDigest &&
      receipt.providerRuntimeSha256 ===
        expectation.basis.providerRuntimeSha256 &&
      receipt.basisDigest === sha256(expectation.basis) &&
      HEX_64.test(receipt.apiGatewayDigest) &&
      receipt.expectationDigest === sha256(expectation) &&
      receipt.snapshotDigest === sha256(snapshotReceiptPayload(receipt)),
    "AWS_ATTEST_SNAPSHOT_RECEIPT"
  );
  verifySignedReceipt(
    receipt,
    expectation.receiptPublicKeys[expectedPhase],
    "AWS_ATTEST_SNAPSHOT_SIGNATURE"
  );
  const startedMs = isoMilliseconds(
    receipt.observationStartedAt,
    "AWS_ATTEST_SNAPSHOT_START_TIME"
  );
  const observedMs = isoMilliseconds(
    receipt.observedAt,
    "AWS_ATTEST_SNAPSHOT_TIME"
  );
  requireCondition(
    observedMs >= startedMs && observedMs - startedMs <= 10 * 60 * 1_000,
    "AWS_ATTEST_SNAPSHOT_TIME"
  );
  validatedCallerBinding(
    receipt.callerBinding,
    expectation.evidenceOperator.roleArn,
    {
      purpose: `gate2-deployment-${expectedPhase}-attestation`,
      sourceCommit: expectation.sourceCommit,
      treeDigest: expectation.treeDigest,
      configDigest: expectation.configDigest,
      stackId: expectation.stackId,
      observedAt: receipt.observedAt
    }
  );
  requireCondition(
    exactKeys(receipt.functions, DEPLOYMENT_FUNCTIONS) &&
      DEPLOYMENT_FUNCTIONS.every(
        (name) =>
          exactKeys(receipt.functions[name], [
            "deploymentDigest",
            "numericVersion"
          ]) &&
          HEX_64.test(receipt.functions[name].deploymentDigest) &&
          /^[1-9][0-9]*$/.test(receipt.functions[name].numericVersion)
      ) &&
      exactKeys(receipt.evidenceOperator, [
        "censusDigest",
        "deploymentDigest",
        "policyDigest",
        "roleIdDigest",
        "trustDigest"
      ]) &&
      exactKeys(receipt.alternatePrincipal, [
        "censusDigest",
        "deploymentDigest",
        "policyDigest",
        "roleIdDigest",
        "trustDigest"
      ]) &&
      Object.values(receipt.evidenceOperator).every((value) =>
        HEX_64.test(value)
      ) &&
      Object.values(receipt.alternatePrincipal).every((value) =>
        HEX_64.test(value)
      ) &&
      receipt.callerBinding.principalIdDigest ===
        receipt.evidenceOperator.roleIdDigest,
    "AWS_ATTEST_SNAPSHOT_BINDINGS"
  );
  return receipt;
}

export function validateDeploymentSnapshot(
  snapshot,
  expectationInput,
  callerExpectation
) {
  const expectation = validateDeploymentExpectation(expectationInput);
  requireCondition(
    exactKeys(snapshot, [
      "alternatePrincipalRole",
      "apiGateway",
      "callerIdentity",
      "evidenceOperatorRole",
      "functions",
      "observationFence",
      "observedAt",
      "phase",
      "providerDependencyTreeDigest",
      "providerRuntimeSha256",
      "region",
      "stack"
    ]) &&
      ["pre", "post"].includes(snapshot.phase) &&
      snapshot.providerDependencyTreeDigest ===
        expectation.basis.providerDependencyTreeDigest &&
      snapshot.providerRuntimeSha256 ===
        expectation.basis.providerRuntimeSha256 &&
      snapshot.region === expectation.region,
    "AWS_ATTEST_SNAPSHOT"
  );
  const observedMs = isoMilliseconds(
    snapshot.observedAt,
    "AWS_ATTEST_OBSERVED_AT"
  );
  requireCondition(
    exactKeys(snapshot.observationFence, [
      "completedAt",
      "firstStateDigest",
      "secondStateDigest",
      "startedAt"
    ]),
    "AWS_ATTEST_OBSERVATION_FENCE"
  );
  const startedMs = isoMilliseconds(
    snapshot.observationFence.startedAt,
    "AWS_ATTEST_OBSERVATION_FENCE_TIME"
  );
  const completedMs = isoMilliseconds(
    snapshot.observationFence.completedAt,
    "AWS_ATTEST_OBSERVATION_FENCE_TIME"
  );
  const stateDigest = sha256(snapshotStatePayload(snapshot));
  requireCondition(
    snapshot.observationFence.firstStateDigest === stateDigest &&
      snapshot.observationFence.secondStateDigest === stateDigest &&
      snapshot.observedAt === snapshot.observationFence.completedAt &&
      completedMs >= startedMs &&
      completedMs === observedMs &&
      completedMs - startedMs <= 10 * 60 * 1_000,
    "AWS_ATTEST_OBSERVATION_FENCE"
  );
  requireCondition(
    exactKeys(snapshot.stack, [
      "bindings",
      "cloudFormationServiceRoleArn",
      "createdAt",
      "driftStatus",
      "httpApiId",
      "lastUpdatedAt",
      "parameterCount",
      "parametersDigest",
      "resourceBindings",
      "semanticAlarmDrift",
      "stackId",
      "stackName",
      "stackStatus",
      "templateCanonicalDigest"
    ]) &&
      snapshot.stack.stackId === expectation.stackId &&
      snapshot.stack.stackName === expectation.stackName &&
      snapshot.stack.stackStatus === "CREATE_COMPLETE" &&
      snapshot.stack.cloudFormationServiceRoleArn === null &&
      snapshot.stack.lastUpdatedAt === null &&
      snapshot.stack.driftStatus === "IN_SYNC" &&
      /^[a-z0-9]{10}$/.test(snapshot.stack.httpApiId) &&
      snapshot.stack.httpApiId === snapshot.apiGateway.api?.apiId &&
      snapshot.stack.templateCanonicalDigest ===
        expectation.templateCanonicalDigest &&
      snapshot.stack.parameterCount ===
        expectation.basis.stackParameterCount &&
      snapshot.stack.parametersDigest ===
        expectation.basis.stackParametersDigest &&
      exactKeys(snapshot.stack.semanticAlarmDrift, ["authority", "boundary"]) &&
      snapshot.stack.semanticAlarmDrift.authority === "IN_SYNC" &&
      snapshot.stack.semanticAlarmDrift.boundary === "IN_SYNC" &&
      exactKeys(snapshot.stack.bindings, [
        "configDigest",
        "probesEnabled",
        "sourceCommit",
        "treeDigest"
      ]) &&
      snapshot.stack.bindings.sourceCommit === expectation.sourceCommit &&
      snapshot.stack.bindings.treeDigest === expectation.treeDigest &&
      snapshot.stack.bindings.configDigest === expectation.configDigest &&
      snapshot.stack.bindings.probesEnabled === "false" &&
      validateStackResourceBindings(
        snapshot.stack.resourceBindings,
        expectation
      ),
    "AWS_ATTEST_STACK_BINDING"
  );
  const stackCreatedMs = isoMilliseconds(
    snapshot.stack.createdAt,
    "AWS_ATTEST_STACK_CREATION_TIME"
  );
  const apiDeploymentCreatedMs = isoMilliseconds(
    snapshot.apiGateway.activeDeployment?.createdAt,
    "AWS_ATTEST_API_DEPLOYMENT_CREATION_TIME"
  );
  requireCondition(
    stackCreatedMs <= apiDeploymentCreatedMs &&
      apiDeploymentCreatedMs <= observedMs,
    "AWS_ATTEST_CREATE_ONLY_API_DEPLOYMENT"
  );
  const evidenceOperator = validateRoleSnapshot(
    snapshot.evidenceOperatorRole,
    {
      code: "AWS_ATTEST_EVIDENCE_ROLE",
      expectedArn: expectation.evidenceOperator.roleArn,
      expectedPolicyDigest: expectation.evidenceOperator.rolePolicyDigest,
      trustValidator: (policy) =>
        validateEvidenceOperatorTrust(
          policy,
          expectation.evidenceOperator.trustedPrincipalArn
        )
    }
  );
  const alternatePrincipal = validateRoleSnapshot(
    snapshot.alternatePrincipalRole,
    {
      code: "AWS_ATTEST_ALTERNATE_ROLE",
      expectedArn: expectation.alternatePrincipal.roleArn,
      expectedPolicyDigest: expectation.alternatePrincipal.rolePolicyDigest,
      trustValidator: (policy) =>
        validateAlternateRoleTrust(policy, expectation.accountId),
      alternateTargetRoleArn: expectation.evidenceOperator.roleArn
    }
  );
  const callerBinding = validateAwsEvidenceCaller(snapshot.callerIdentity, {
    ...callerExpectation,
    expectedAccountId: expectation.accountId,
    expectedPrincipalArn: expectation.evidenceOperator.roleArn,
    expectedRoleId: evidenceOperator.roleId,
    bindingContext: {
      purpose: `gate2-deployment-${snapshot.phase}-attestation`,
      sourceCommit: expectation.sourceCommit,
      treeDigest: expectation.treeDigest,
      configDigest: expectation.configDigest,
      stackId: expectation.stackId,
      observedAt: snapshot.observedAt
    }
  });
  requireCondition(
    exactKeys(snapshot.functions, DEPLOYMENT_FUNCTIONS),
    "AWS_ATTEST_FUNCTION_SET"
  );
  const functions = Object.fromEntries(
    DEPLOYMENT_FUNCTIONS.map((name) => [
      name,
      validateFunctionSnapshot(
        name,
        snapshot.functions[name],
        expectation.functions[name],
        expectation,
        snapshot.stack.httpApiId
      )
    ])
  );
  const apiGatewayDigest = validateApiGatewaySnapshot(
    snapshot.apiGateway,
    expectation
  );
  const receipt = {
    schemaVersion: SNAPSHOT_RECEIPT_SCHEMA,
    status: `${snapshot.phase.toUpperCase()}_ATTESTATION_PASS`,
    phase: snapshot.phase,
    observationStartedAt: snapshot.observationFence.startedAt,
    observedAt: snapshot.observedAt,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest,
    configDigest: expectation.configDigest,
    templateCanonicalDigest: expectation.templateCanonicalDigest,
    providerDependencyTreeDigest:
      expectation.basis.providerDependencyTreeDigest,
    providerRuntimeSha256: expectation.basis.providerRuntimeSha256,
    basisDigest: sha256(expectation.basis),
    apiGatewayDigest,
    expectationDigest: sha256(expectation),
    callerBinding,
    evidenceOperator: {
      censusDigest: evidenceOperator.censusDigest,
      deploymentDigest: evidenceOperator.deploymentDigest,
      policyDigest: evidenceOperator.policyDigest,
      roleIdDigest: evidenceOperator.roleIdDigest,
      trustDigest: evidenceOperator.trustDigest
    },
    alternatePrincipal: {
      censusDigest: alternatePrincipal.censusDigest,
      deploymentDigest: alternatePrincipal.deploymentDigest,
      policyDigest: alternatePrincipal.policyDigest,
      roleIdDigest: alternatePrincipal.roleIdDigest,
      trustDigest: alternatePrincipal.trustDigest
    },
    stackDigest: sha256({
      stackId: expectation.stackId,
      stackStatus: snapshot.stack.stackStatus,
      cloudFormationServiceRoleArn:
        snapshot.stack.cloudFormationServiceRoleArn,
      driftStatus: snapshot.stack.driftStatus,
      httpApiId: snapshot.stack.httpApiId,
      bindings: snapshot.stack.bindings,
      parameterCount: snapshot.stack.parameterCount,
      parametersDigest: snapshot.stack.parametersDigest,
      resourceBindings: snapshot.stack.resourceBindings,
      semanticAlarmDrift: snapshot.stack.semanticAlarmDrift,
      templateCanonicalDigest: snapshot.stack.templateCanonicalDigest
    }),
    observationFenceDigest: sha256(snapshot.observationFence),
    functions,
    finalReleaseReady: false,
    claimBoundary: SNAPSHOT_CLAIM_BOUNDARY
  };
  receipt.snapshotDigest = sha256(snapshotReceiptPayload(receipt));
  return Object.freeze(receipt);
}

function validateAlternateDenial(
  value,
  expectation,
  preCompletedMs,
  postStartedMs
) {
  requireCondition(
    exactKeys(value, [
      "alternatePrincipalArn",
      "alternatePrincipalDigest",
      "callerBinding",
      "configDigest",
      "errorCode",
      "expectationDigest",
      "observedAt",
      "outcome",
      "providerDependencyTreeDigest",
      "providerRuntimeSha256",
      "requestIdDigest",
      "schemaVersion",
      "signature",
      "sourceCommit",
      "targetRoleArn",
      "treeDigest"
    ]) &&
      value.schemaVersion === ALTERNATE_DENIAL_SCHEMA &&
      value.outcome === "DENIED" &&
      value.errorCode === "AccessDenied" &&
      value.sourceCommit === expectation.sourceCommit &&
      value.treeDigest === expectation.treeDigest &&
      value.configDigest === expectation.configDigest &&
      value.expectationDigest === sha256(expectation) &&
      value.providerDependencyTreeDigest ===
        expectation.basis.providerDependencyTreeDigest &&
      value.providerRuntimeSha256 ===
        expectation.basis.providerRuntimeSha256 &&
      value.targetRoleArn === expectation.evidenceOperator.roleArn &&
      value.alternatePrincipalArn ===
        expectation.alternatePrincipal.roleArn &&
      value.alternatePrincipalDigest ===
        sha256(expectation.alternatePrincipal.roleArn) &&
      HEX_64.test(value.requestIdDigest),
    "AWS_ATTEST_ALTERNATE_DENIAL"
  );
  verifySignedReceipt(
    value,
    expectation.receiptPublicKeys.alternateDenial,
    "AWS_ATTEST_ALTERNATE_DENIAL_SIGNATURE"
  );
  const observedMs = isoMilliseconds(
    value.observedAt,
    "AWS_ATTEST_ALTERNATE_DENIAL_TIME"
  );
  const binding = validatedCallerBinding(
    value.callerBinding,
    expectation.alternatePrincipal.roleArn,
    {
      purpose: "gate2-evidence-role-alternate-denial",
      sourceCommit: expectation.sourceCommit,
      treeDigest: expectation.treeDigest,
      configDigest: expectation.configDigest,
      stackId: expectation.stackId,
      targetRoleArn: expectation.evidenceOperator.roleArn,
      observedAt: value.observedAt
    }
  );
  requireCondition(
    observedMs > preCompletedMs && observedMs < postStartedMs,
    "AWS_ATTEST_ALTERNATE_DENIAL_BINDING"
  );
  return {
    alternatePrincipalDigest: value.alternatePrincipalDigest,
    callerBindingDigest: binding.bindingDigest,
    principalIdDigest: binding.principalIdDigest,
    observedAt: value.observedAt,
    requestIdDigest: value.requestIdDigest
  };
}

export function validateDeploymentAttestationPair({
  preReceipt: preReceiptInput,
  postReceipt: postReceiptInput,
  expectation: expectationInput,
  alternateDenial
}) {
  const expectation = validateDeploymentExpectation(expectationInput);
  const preReceipt = validateSnapshotReceipt(
    preReceiptInput,
    expectation,
    "pre"
  );
  const postReceipt = validateSnapshotReceipt(
    postReceiptInput,
    expectation,
    "post"
  );
  const preMs = isoMilliseconds(preReceipt.observedAt, "AWS_ATTEST_PRE_TIME");
  const postStartedMs = isoMilliseconds(
    postReceipt.observationStartedAt,
    "AWS_ATTEST_POST_START_TIME"
  );
  const postMs = isoMilliseconds(postReceipt.observedAt, "AWS_ATTEST_POST_TIME");
  requireCondition(
    postStartedMs > preMs &&
      postMs >= postStartedMs &&
      postMs - preMs <= 24 * 60 * 60 * 1_000,
    "AWS_ATTEST_PAIR_TIME"
  );
  requireCondition(
    preReceipt.stackDigest === postReceipt.stackDigest &&
      preReceipt.apiGatewayDigest === postReceipt.apiGatewayDigest &&
      preReceipt.evidenceOperator.deploymentDigest ===
        postReceipt.evidenceOperator.deploymentDigest &&
      preReceipt.alternatePrincipal.deploymentDigest ===
        postReceipt.alternatePrincipal.deploymentDigest &&
      preReceipt.callerBinding.principalIdDigest ===
        preReceipt.evidenceOperator.roleIdDigest &&
      postReceipt.callerBinding.principalIdDigest ===
        postReceipt.evidenceOperator.roleIdDigest,
    "AWS_ATTEST_PAIR_STACK_DRIFT"
  );
  for (const name of DEPLOYMENT_FUNCTIONS) {
    requireCondition(
      preReceipt.functions[name].numericVersion ===
        postReceipt.functions[name].numericVersion &&
        preReceipt.functions[name].deploymentDigest ===
          postReceipt.functions[name].deploymentDigest,
      `AWS_ATTEST_PAIR_FUNCTION_DRIFT_${name.toUpperCase()}`
    );
  }
  const denial = validateAlternateDenial(
    alternateDenial,
    expectation,
    preMs,
    postStartedMs
  );
  requireCondition(
    denial.principalIdDigest ===
      preReceipt.alternatePrincipal.roleIdDigest &&
      denial.principalIdDigest ===
        postReceipt.alternatePrincipal.roleIdDigest,
    "AWS_ATTEST_ALTERNATE_DENIAL_ROLE_ID"
  );
  return Object.freeze({
    schemaVersion: PAIR_RECEIPT_SCHEMA,
    status: "PASS",
    observedAt: postReceipt.observedAt,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest,
    configDigest: expectation.configDigest,
    templateCanonicalDigest: expectation.templateCanonicalDigest,
    basisDigest: sha256(expectation.basis),
    expectationDigest: sha256(expectation),
    preSnapshotDigest: preReceipt.snapshotDigest,
    postSnapshotDigest: postReceipt.snapshotDigest,
    signedPreReceiptDigest: sha256(preReceipt),
    signedPostReceiptDigest: sha256(postReceipt),
    signedAlternateDenialDigest: sha256(alternateDenial),
    evidence: {
      alternateDenial,
      postReceipt,
      preReceipt
    },
    stableStackDigest: postReceipt.stackDigest,
    functionDeploymentDigests: Object.fromEntries(
      DEPLOYMENT_FUNCTIONS.map((name) => [
        name,
        postReceipt.functions[name].deploymentDigest
      ])
    ),
    evidenceOperator: {
      preCallerBindingDigest: preReceipt.callerBinding.bindingDigest,
      postCallerBindingDigest: postReceipt.callerBinding.bindingDigest,
      deploymentDigest: postReceipt.evidenceOperator.deploymentDigest,
      alternatePrincipalDeploymentDigest:
        postReceipt.alternatePrincipal.deploymentDigest,
      alternateDenial: denial
    },
    controls: {
      authenticatedPreSnapshot: true,
      authenticatedPostSnapshot: true,
      authenticatedAlternateDenial: true,
      fullSignedInputsEmbedded: true,
      exactBuildAndConfigurationBasis: true,
      exactNumericVersions: true,
      apiGatewayActiveDeploymentBound: true,
      apiGatewayCensusBound: true,
      apiGatewayIntegrationsBound: true,
      apiGatewayRoutesBound: true,
      primaryRuntimeRolePolicyCensus: true,
      primaryRuntimeConfigurationsBound: true,
      providerDependencyTreeBound: true,
      provisionedConcurrencyAbsent: true,
      reservedConcurrencyBound: true,
      revisionsStable: true,
      aliasTargetsStable: true,
      revisionFencedSnapshots: true,
      attestedResourceDriftInSync: true,
      alternatePrincipalDenied: true
    },
    finalReleaseReady: false,
    claimBoundary:
      "This self-contained signed-evidence validator verifies and embeds two independently signed provider snapshots plus one independently signed end-to-end alternate-principal AccessDenied observation. It binds them to the exact build, all 45 CloudFormation parameter values, the five primary runtime functions, their shared roles, the two evidence roles, the exact HTTP API route/integration/stage and explicit active-deployment census, 37 drift-supported CloudFormation resources, two directly attested integrations, and one directly attested explicit API deployment. It accepts only a never-updated CREATE_COMPLETE stack whose active deployment was created during that stack creation; any update requires teardown and a fresh create. The denial observation does not by itself attribute AccessDenied to one IAM, session-policy, or organization-policy cause. Probe resources are required absent; other account resources remain outside this census. A PASS is not administrator exclusion, vulnerability absence, live CockroachDB proof, application correctness, public-release approval, or submission authorization."
  });
}

export function validateSignedDeploymentAttestationPair(
  receipt,
  expectationInput
) {
  const expectation = validateDeploymentExpectation(expectationInput);
  const unsigned = verifySignedReceipt(
    receipt,
    expectation.receiptPublicKeys.post,
    "AWS_ATTEST_PAIR_SIGNATURE"
  );
  requireCondition(
    exactKeys(unsigned.evidence, [
      "alternateDenial",
      "postReceipt",
      "preReceipt"
    ]),
    "AWS_ATTEST_PAIR_EVIDENCE"
  );
  const recomputed = validateDeploymentAttestationPair({
    alternateDenial: unsigned.evidence.alternateDenial,
    expectation,
    postReceipt: unsigned.evidence.postReceipt,
    preReceipt: unsigned.evidence.preReceipt
  });
  requireCondition(
    canonicalJson(unsigned) === canonicalJson(recomputed),
    "AWS_ATTEST_PAIR_RECEIPT"
  );
  return receipt;
}

export const __test = Object.freeze({
  ALTERNATE_DENIAL_SCHEMA,
  EXPECTATION_SCHEMA,
  PAIR_RECEIPT_SCHEMA,
  SNAPSHOT_RECEIPT_SCHEMA,
  canonicalJson,
  callerContextDigest,
  sha256,
  snapshotReceiptPayload,
  snapshotStatePayload,
  validateSnapshotReceipt,
  verifySignedReceipt
});
