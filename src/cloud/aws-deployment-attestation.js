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

const EXPECTATION_SCHEMA =
  "tideproof.gate2.aws-deployment-expectation.v2";
const SNAPSHOT_RECEIPT_SCHEMA =
  "tideproof.gate2.aws-deployment-attestation-snapshot.v2";
const PAIR_RECEIPT_SCHEMA =
  "tideproof.gate2.aws-deployment-attestation.v2";
const ALTERNATE_DENIAL_SCHEMA =
  "tideproof.gate2.aws-alternate-principal-denial.v2";
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const BASE64_SHA256 = /^[A-Za-z0-9+/]{43}=$/;
const BASE64_SIGNATURE = /^[A-Za-z0-9+/]{86}==$/;
const REVISION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ROLE_ID = /^[A-Z0-9]{16,128}$/;
const SNAPSHOT_CLAIM_BOUNDARY =
  "This signed receipt validates one revision-fenced AWS deployment snapshot for the five primary runtime functions, their shared roles, and the two evidence roles against exact build, configuration, CloudFormation-resource, and provider expectations. Conditional probe-function configurations remain outside this stage-three census. It is not a pre/post stability receipt, administrator exclusion, application canary, or release authorization.";

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
        ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
          actual[logicalId].resourceStatus
        )
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
      "principalType"
    ]) &&
      HEX_64.test(value.callerIdentityDigest) &&
      value.expectedIdentityDigest === value.callerIdentityDigest &&
      value.expectedPrincipalDigest === sha256(expectedPrincipalArn) &&
      value.contextDigest === callerContextDigest(bindingContext) &&
      ["assumed-role", "iam-user"].includes(value.principalType),
    "AWS_ATTEST_CALLER_BINDING"
  );
  const bindingDigest = sha256(
    [
      "tideproof.aws-evidence-caller-binding.v1",
      value.callerIdentityDigest,
      value.expectedIdentityDigest,
      value.expectedPrincipalDigest,
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
      expectation.stackName === "tideproof-gate2" &&
      HEX_40.test(expectation.sourceCommit) &&
      HEX_40.test(expectation.treeDigest) &&
      HEX_64.test(expectation.configDigest) &&
      HEX_64.test(expectation.templateCanonicalDigest) &&
      exactKeys(expectation.basis, [
        "buildReceiptSha256",
        "configurationSha256"
      ]) &&
      HEX_64.test(expectation.basis.buildReceiptSha256) &&
      HEX_64.test(expectation.basis.configurationSha256),
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
  try {
    computedConfigDigest = deploymentConfigDigest(configuration);
  } catch {
    throw new Error("AWS_ATTEST_BASIS_CONFIGURATION");
  }
  requireCondition(
    computedConfigDigest === expectation.configDigest &&
      configuration.sourceCommit === expectation.sourceCommit &&
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
      buildReceipt.schemaVersion === "tideproof.gate2-build.v5" &&
      buildReceipt.mode === "CLEAN_ARTIFACT_BUILD" &&
      buildReceipt.projectSourceMode ===
        "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS" &&
      buildReceipt.sourceCommit === expectation.sourceCommit &&
      buildReceipt.treeDigest === expectation.treeDigest &&
      buildReceipt.workingTreeClean === true &&
      buildReceipt.workingTreeCleanBeforeGeneration === true &&
      buildReceipt.gate2Template?.templateDigest ===
        configuration.templateDigest &&
      buildReceipt.gate2Template?.canonicalDigest ===
        expectation.templateCanonicalDigest &&
      Array.isArray(buildReceipt.buildControlInputs) &&
      buildReceipt.buildControlInputs.length >= 7 &&
      Array.isArray(buildReceipt.artifacts),
    "AWS_ATTEST_BASIS_BUILD_RECEIPT"
  );
  const artifacts = new Map(
    buildReceipt.artifacts.map((artifact) => [artifact?.name, artifact])
  );
  requireCondition(
    artifacts.size === 6 &&
      ["agent", "authority", "boundary", "demo", "probe", "signer"].every(
        (name) => artifacts.has(name)
      ) &&
      DEPLOYMENT_FUNCTIONS.every((name) => {
        const artifact = artifacts.get(name);
        return (
          artifact?.artifactCodeSha256 ===
            expectation.functions[name].codeSha256 &&
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
      actual.inlinePolicies[0].name === "TideproofExactCapabilities" &&
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
    trustDigest
  };
  return Object.freeze({
    ...deployment,
    deploymentDigest: sha256({
      schemaVersion: "tideproof.gate2.role-deployment.v2",
      ...deployment
    })
  });
}

function validateFunctionSnapshot(name, actual, expected, expectation) {
  requireCondition(
    exactKeys(actual, [
      "aliasArn",
      "aliasName",
      "aliasRevisionId",
      "aliasRoutingConfiguration",
      "aliasTargetVersion",
      "codeSha256",
      "configuration",
      "functionArn",
      "functionName",
      "lastUpdateStatus",
      "numericRevisionId",
      "numericVersion",
      "numericVersionArn",
      "reservedConcurrency",
      "resourceDrift",
      "role",
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
  requireCondition(
    actual.functionArn === expected.functionArn &&
      actual.functionName === expected.functionName &&
      actual.numericVersion === expected.numericVersion &&
      actual.numericVersionArn === expected.numericVersionArn &&
      actual.aliasArn === expected.aliasArn &&
      actual.aliasName === "proof" &&
      actual.aliasTargetVersion === expected.numericVersion &&
      exactKeys(actual.aliasRoutingConfiguration, []) &&
      actual.codeSha256 === expected.codeSha256 &&
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
    configurationDigest: expected.configurationDigest,
    functionArnDigest: sha256(actual.functionArn),
    numericRevisionId: actual.numericRevisionId,
    numericVersion: actual.numericVersion,
    providerRuntimeVersionDigest: sha256(configuration.runtimeVersion),
    reservedConcurrency: actual.reservedConcurrency,
    roleDeploymentDigest: role.deploymentDigest
  };
  return Object.freeze({
    numericVersion: actual.numericVersion,
    deploymentDigest: sha256({
      schemaVersion: "tideproof.gate2.function-deployment.v2",
      sourceCommit: expectation.sourceCommit,
      configDigest: expectation.configDigest,
      name,
      ...deployment
    })
  });
}

function snapshotStatePayload(snapshot) {
  return {
    callerIdentity: snapshot.callerIdentity,
    evidenceOperatorRole: snapshot.evidenceOperatorRole,
    alternatePrincipalRole: snapshot.alternatePrincipalRole,
    functions: snapshot.functions,
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
    callerBinding: receipt.callerBinding,
    evidenceOperator: receipt.evidenceOperator,
    alternatePrincipal: receipt.alternatePrincipal,
    stackDigest: receipt.stackDigest,
    observationFenceDigest: receipt.observationFenceDigest,
    functions: receipt.functions,
    finalReleaseReady: false,
    claimBoundary: receipt.claimBoundary
  };
}

function validateSnapshotReceipt(receipt, expectation, expectedPhase) {
  requireCondition(
    exactKeys(receipt, [
      "alternatePrincipal",
      "basisDigest",
      "callerBinding",
      "claimBoundary",
      "configDigest",
      "evidenceOperator",
      "finalReleaseReady",
      "functions",
      "observationFenceDigest",
      "observationStartedAt",
      "observedAt",
      "phase",
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
      receipt.basisDigest === sha256(expectation.basis) &&
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
      ),
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
      "callerIdentity",
      "evidenceOperatorRole",
      "functions",
      "observationFence",
      "observedAt",
      "phase",
      "region",
      "stack"
    ]) &&
      ["pre", "post"].includes(snapshot.phase) &&
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
      "driftStatus",
      "resourceBindings",
      "stackId",
      "stackName",
      "stackStatus",
      "templateCanonicalDigest"
    ]) &&
      snapshot.stack.stackId === expectation.stackId &&
      snapshot.stack.stackName === expectation.stackName &&
      ["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
        snapshot.stack.stackStatus
      ) &&
      snapshot.stack.driftStatus === "IN_SYNC" &&
      snapshot.stack.templateCanonicalDigest ===
        expectation.templateCanonicalDigest &&
      exactKeys(snapshot.stack.bindings, [
        "configDigest",
        "sourceCommit",
        "treeDigest"
      ]) &&
      snapshot.stack.bindings.sourceCommit === expectation.sourceCommit &&
      snapshot.stack.bindings.treeDigest === expectation.treeDigest &&
      snapshot.stack.bindings.configDigest === expectation.configDigest &&
      validateStackResourceBindings(
        snapshot.stack.resourceBindings,
        expectation
      ),
    "AWS_ATTEST_STACK_BINDING"
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
        expectation
      )
    ])
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
    basisDigest: sha256(expectation.basis),
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
      driftStatus: snapshot.stack.driftStatus,
      bindings: snapshot.stack.bindings,
      resourceBindings: snapshot.stack.resourceBindings,
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

function validateAlternateDenial(value, expectation, preMs, postMs) {
  requireCondition(
    exactKeys(value, [
      "alternatePrincipalArn",
      "alternatePrincipalDigest",
      "callerBinding",
      "configDigest",
      "errorCode",
      "observedAt",
      "outcome",
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
    observedMs >= preMs && observedMs <= postMs,
    "AWS_ATTEST_ALTERNATE_DENIAL_BINDING"
  );
  return {
    alternatePrincipalDigest: value.alternatePrincipalDigest,
    callerBindingDigest: binding.bindingDigest,
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
  const postMs = isoMilliseconds(postReceipt.observedAt, "AWS_ATTEST_POST_TIME");
  requireCondition(
    postMs > preMs && postMs - preMs <= 24 * 60 * 60 * 1_000,
    "AWS_ATTEST_PAIR_TIME"
  );
  requireCondition(
    preReceipt.stackDigest === postReceipt.stackDigest &&
      preReceipt.evidenceOperator.deploymentDigest ===
        postReceipt.evidenceOperator.deploymentDigest &&
      preReceipt.alternatePrincipal.deploymentDigest ===
        postReceipt.alternatePrincipal.deploymentDigest,
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
    postMs
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
    preSnapshotDigest: preReceipt.snapshotDigest,
    postSnapshotDigest: postReceipt.snapshotDigest,
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
      exactBuildAndConfigurationBasis: true,
      exactNumericVersions: true,
      primaryRuntimeRolePolicyCensus: true,
      primaryRuntimeConfigurationsBound: true,
      reservedConcurrencyBound: true,
      revisionsStable: true,
      aliasTargetsStable: true,
      revisionFencedSnapshots: true,
      stackAndResourceDriftInSync: true,
      alternatePrincipalDenied: true
    },
    finalReleaseReady: false,
    claimBoundary:
      "This signed-evidence validator binds two provider snapshots and one alternate-principal denial to the exact build plus the five primary runtime functions, their shared roles, and the two evidence roles. Conditional probe-function configurations remain stage-four evidence. A PASS is not administrator exclusion, vulnerability absence, live CockroachDB proof, application correctness, public-release approval, or submission authorization."
  });
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
