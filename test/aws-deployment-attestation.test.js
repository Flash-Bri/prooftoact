import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  DEPLOYMENT_FUNCTIONS,
  __test,
  deploymentFunctionConfigurationDigest,
  signDeploymentAttestationReceipt,
  validateDeploymentAttestationPair,
  validateDeploymentEvidenceBasis,
  validateDeploymentExpectation,
  validateDeploymentSnapshot
} from "../src/cloud/aws-deployment-attestation.js";
import { deploymentConfigDigest } from "../src/cloud/aws-gate2-template.js";
import { validateAwsEvidenceCaller } from "../src/cloud/aws-evidence-identity.js";
import {
  __test as runnerTest,
  safeAwsAttestationFailureCode
} from "../scripts/gate2-aws-attestation.js";
import {
  __test as denialRunnerTest,
  safeAlternateDenialFailureCode
} from "../scripts/gate2-evidence-operator-denial.js";

const ACCOUNT_ID = "111111111111";
const REGION = "us-east-1";
const STACK_NAME = "tideproof-gate2";
const STACK_ID =
  `arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/` +
  `${STACK_NAME}/11111111-1111-4111-8111-111111111111`;
const SOURCE_COMMIT = "a".repeat(40);
const TREE_DIGEST = "b".repeat(40);
const TEMPLATE_DIGEST = "c".repeat(64);
const TEMPLATE_CANONICAL_DIGEST = "d".repeat(64);
const BUILD_RECEIPT_SHA256 = "e".repeat(64);
const CONFIGURATION_SHA256 = "f".repeat(64);
const OPERATOR_ROLE_ARN =
  `arn:aws:iam::${ACCOUNT_ID}:role/tideproof-gate2-evidence`;
const ALTERNATE_ROLE_ARN = `${OPERATOR_ROLE_ARN}-alternate`;
const TRUSTED_PRINCIPAL_ARN =
  `arn:aws:iam::${ACCOUNT_ID}:role/tideproof-evidence-source`;
const OPERATOR_CALLER_ARN =
  `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
  "tideproof-gate2-evidence/deployment-proof";
const OPERATOR_CALLER_USER_ID =
  "AROATIDEPROOFEVIDENCE:deployment-proof";
const ALTERNATE_CALLER_ARN =
  `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
  "tideproof-gate2-evidence-alternate/negative-control";
const ALTERNATE_CALLER_USER_ID =
  "AROATIDEPROOFALTERNATE:negative-control";

function signingKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: publicKey
      .export({ format: "der", type: "spki" })
      .toString("base64")
  };
}

const RECEIPT_KEYS = Object.freeze({
  alternateDenial: signingKey(),
  post: signingKey(),
  pre: signingKey()
});

function lambdaTrustPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Service: "lambda.amazonaws.com" },
        Action: "sts:AssumeRole"
      }
    ]
  };
}

function operatorTrustPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: TRUSTED_PRINCIPAL_ARN },
        Action: "sts:AssumeRole",
        Condition: {
          StringEquals: {
            "aws:PrincipalArn": TRUSTED_PRINCIPAL_ARN
          }
        }
      }
    ]
  };
}

function accountTrustPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { AWS: `arn:aws:iam::${ACCOUNT_ID}:root` },
        Action: "sts:AssumeRole"
      }
    ]
  };
}

function rolePolicy(name) {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: `Write${name}`,
        Effect: "Allow",
        Action: ["logs:PutLogEvents"],
        Resource: `arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${name}:*`
      }
    ]
  };
}

function operatorPolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ReadExactDeployment",
        Effect: "Allow",
        Action: ["iam:GetRole", "iam:GetRolePolicy"],
        Resource: "*"
      }
    ]
  };
}

function alternatePolicy() {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AttemptOnlyDeploymentEvidenceRole",
        Effect: "Allow",
        Action: ["sts:AssumeRole"],
        Resource: OPERATOR_ROLE_ARN
      },
      {
        Sid: "DenyOtherAssumeRoleTargets",
        Effect: "Deny",
        Action: ["sts:AssumeRole"],
        NotResource: OPERATOR_ROLE_ARN
      },
      {
        Sid: "DenyIamCapabilities",
        Effect: "Deny",
        Action: ["iam:*"],
        Resource: "*"
      }
    ]
  };
}

function normalizedConfiguration(name, timeout, configDigest) {
  return {
    architectures: ["arm64"],
    deadLetterTargetArn: null,
    environment: {
      CONFIG_DIGEST: configDigest,
      FUNCTION_CLASS: name,
      SOURCE_COMMIT,
      TREE_DIGEST
    },
    ephemeralStorageSize: 512,
    fileSystemConfigs: [],
    handler: "index.handler",
    kmsKeyArn: null,
    layers: [],
    loggingConfig: {
      applicationLogLevel: null,
      logFormat: "JSON",
      logGroup: `/aws/lambda/${STACK_NAME}-${name}`,
      systemLogLevel: null
    },
    memorySize: 128,
    packageType: "Zip",
    runtime: "nodejs22.x",
    runtimeVersion: {
      errorCode: null,
      errorMessage: null,
      runtimeVersionArn: `arn:aws:lambda:${REGION}::runtime:fixture-${name}`
    },
    signingJobArn: null,
    signingProfileVersionArn: null,
    snapStartApplyOn: "None",
    timeout,
    tracingMode: "PassThrough",
    vpcConfig: {
      ipv6AllowedForDualStack: false,
      securityGroupIds: [],
      subnetIds: [],
      vpcId: null
    }
  };
}

function roleSnapshot({ arn, id, policy, trustPolicy, resourceDrift = "IN_SYNC" }) {
  return {
    arn,
    attachedManagedPolicies: [],
    inlinePolicies: [
      { name: "TideproofExactCapabilities", document: policy }
    ],
    maxSessionDuration: 3600,
    permissionsBoundary: null,
    resourceDrift,
    roleId: id,
    trustPolicy
  };
}

function functionFixture(name, index, configDigest) {
  const title = `${name[0].toUpperCase()}${name.slice(1)}`;
  const functionName = `${STACK_NAME}-${title}Function-A1B2C3D4`;
  const functionArn =
    `arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:${functionName}`;
  const numericVersion = String(index + 1);
  const roleArn =
    `arn:aws:iam::${ACCOUNT_ID}:role/` +
    `${STACK_NAME}-${title}Role-A1B2C3D4`;
  const policy = rolePolicy(name);
  const concurrency = {
    agent: 1,
    authority: 2,
    boundary: 2,
    demo: 8,
    signer: 1
  }[name];
  const timeout = {
    agent: 15,
    authority: 25,
    boundary: 25,
    demo: 5,
    signer: 8
  }[name];
  const configuration = normalizedConfiguration(name, timeout, configDigest);
  return {
    expected: {
      aliasArn: `${functionArn}:proof`,
      codeSha256: Buffer.alloc(32, index + 1).toString("base64"),
      configurationDigest:
        deploymentFunctionConfigurationDigest(configuration),
      functionArn,
      functionName,
      numericVersion,
      numericVersionArn: `${functionArn}:${numericVersion}`,
      reservedConcurrency: concurrency,
      roleArn,
      rolePolicyDigest: __test.sha256(policy),
      timeout
    },
    actual: {
      aliasArn: `${functionArn}:proof`,
      aliasName: "proof",
      aliasRevisionId: `10000000-0000-4000-8000-00000000000${index}`,
      aliasRoutingConfiguration: {},
      aliasTargetVersion: numericVersion,
      codeSha256: Buffer.alloc(32, index + 1).toString("base64"),
      configuration,
      functionArn,
      functionName,
      lastUpdateStatus: "Successful",
      numericRevisionId: `20000000-0000-4000-8000-00000000000${index}`,
      numericVersion,
      numericVersionArn: `${functionArn}:${numericVersion}`,
      reservedConcurrency: concurrency,
      resourceDrift: {
        alias: "IN_SYNC",
        function: "IN_SYNC",
        role: "IN_SYNC",
        version: "IN_SYNC"
      },
      role: roleSnapshot({
        arn: roleArn,
        id: `AROATIDEPROOFROLE${index}`,
        policy,
        trustPolicy: lambdaTrustPolicy()
      }),
      state: "Active"
    }
  };
}

function configurationFixture(functions, configDigestPlaceholder = "0".repeat(64)) {
  const artifactNames = ["agent", "authority", "boundary", "demo", "probe", "signer"];
  const artifactDigests = Object.fromEntries(
    artifactNames.map((name, index) => [name, String(index + 1).repeat(64).slice(0, 64)])
  );
  const sourceDigests = Object.fromEntries(
    artifactNames.map((name, index) => [name, String(index + 7).repeat(64).slice(0, 64)])
  );
  return {
    accountId: ACCOUNT_ID,
    apiAuthorization: "AWS_IAM",
    artifactBucket: "tideproof-gate2-artifacts",
    artifactCodeSha256: Object.fromEntries(
      artifactNames.map((name, index) => [
        name,
        name === "probe"
          ? Buffer.alloc(32, 6).toString("base64")
          : functions[name].expected.codeSha256
      ])
    ),
    artifactDigests,
    artifactKeys: Object.fromEntries(
      artifactNames.map((name) => [
        name,
        `gate2/${SOURCE_COMMIT}/${name}-${artifactDigests[name]}.zip`
      ])
    ),
    artifactSourceDigests: sourceDigests,
    artifactVersions: Object.fromEntries(
      artifactNames.map((name, index) => [name, `version-${index + 1}`])
    ),
    attestation: {
      alternateRolePolicyDigest: __test.sha256(alternatePolicy()),
      evidenceRolePolicyDigest: __test.sha256(operatorPolicy()),
      functionConfigurationDigests: Object.fromEntries(
        DEPLOYMENT_FUNCTIONS.map((name) => [
          name,
          functions[name].expected.configurationDigest
        ])
      ),
      functionRolePolicyDigests: Object.fromEntries(
        DEPLOYMENT_FUNCTIONS.map((name) => [
          name,
          functions[name].expected.rolePolicyDigest
        ])
      ),
      receiptPublicKeys: Object.fromEntries(
        Object.entries(RECEIPT_KEYS).map(([name, value]) => [
          name,
          value.publicKey
        ])
      )
    },
    authority: {
      databaseHost: "synthetic.cockroachlabs.cloud",
      databasePort: "26257",
      databaseSecretArn:
        `arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:tideproof/authorizer-AbCd12`,
      databaseSecretVersionId: "a".repeat(32),
      tenantId: "11111111-1111-4111-8111-111111111111",
      runId: "22222222-2222-4222-8222-222222222222",
      incidentId: "33333333-3333-4333-8333-333333333333",
      evidenceId: "44444444-4444-4444-8444-444444444444",
      raceId: "55555555-5555-4555-8555-555555555555",
      resourceId: "synthetic-rescue-unit-aws-proof",
      alphaProposalDigest: "1".repeat(64),
      bravoProposalDigest: "2".repeat(64),
      alphaLogicalActionDigest: "3".repeat(64),
      bravoLogicalActionDigest: "4".repeat(64),
      selectedEvidenceDigest: "5".repeat(64)
    },
    bedrockModelId: "amazon.nova-micro-v1:0",
    budgetUsd: 15,
    evidenceOperator: { principalArn: TRUSTED_PRINCIPAL_ARN },
    logRetentionDays: 7,
    notificationEmailDigest: "6".repeat(64),
    packageLockDigest: "7".repeat(64),
    probesEnabled: true,
    publicDemo: {
      authorization: "NONE",
      paths: ["/", "/app.js"]
    },
    region: REGION,
    reservedConcurrency: Object.fromEntries(
      DEPLOYMENT_FUNCTIONS.map((name) => [
        name,
        functions[name].expected.reservedConcurrency
      ])
    ),
    sourceCommit: SOURCE_COMMIT,
    stackName: STACK_NAME,
    templateDigest: TEMPLATE_DIGEST,
    throttle: {
      advisory: { burst: 1, rate: 0.1 },
      publicDemo: { burst: 8, rate: 0.05 }
    },
    treeDigest: TREE_DIGEST,
    configDigestPlaceholder
  };
}

function fixture() {
  const provisionalFunctions = Object.fromEntries(
    DEPLOYMENT_FUNCTIONS.map((name, index) => [
      name,
      functionFixture(name, index, "0".repeat(64))
    ])
  );
  const configuration = configurationFixture(provisionalFunctions);
  delete configuration.configDigestPlaceholder;
  const configDigest = deploymentConfigDigest(configuration);
  const functions = Object.fromEntries(
    DEPLOYMENT_FUNCTIONS.map((name, index) => [
      name,
      functionFixture(name, index, configDigest)
    ])
  );
  configuration.attestation.functionConfigurationDigests = Object.fromEntries(
    DEPLOYMENT_FUNCTIONS.map((name) => [
      name,
      functions[name].expected.configurationDigest
    ])
  );
  assert.equal(deploymentConfigDigest(configuration), configDigest);
  const expectation = {
    schemaVersion: __test.EXPECTATION_SCHEMA,
    accountId: ACCOUNT_ID,
    alternatePrincipal: {
      roleArn: ALTERNATE_ROLE_ARN,
      rolePolicyDigest: __test.sha256(alternatePolicy())
    },
    basis: {
      buildReceiptSha256: BUILD_RECEIPT_SHA256,
      configurationSha256: CONFIGURATION_SHA256
    },
    configDigest,
    evidenceOperator: {
      roleArn: OPERATOR_ROLE_ARN,
      rolePolicyDigest: __test.sha256(operatorPolicy()),
      trustedPrincipalArn: TRUSTED_PRINCIPAL_ARN
    },
    functions: Object.fromEntries(
      Object.entries(functions).map(([name, value]) => [name, value.expected])
    ),
    receiptPublicKeys: configuration.attestation.receiptPublicKeys,
    region: REGION,
    sourceCommit: SOURCE_COMMIT,
    stackId: STACK_ID,
    stackName: STACK_NAME,
    templateCanonicalDigest: TEMPLATE_CANONICAL_DIGEST,
    treeDigest: TREE_DIGEST
  };
  const buildReceipt = {
    schemaVersion: "tideproof.gate2-build.v5",
    mode: "CLEAN_ARTIFACT_BUILD",
    projectSourceMode: "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    workingTreeClean: true,
    workingTreeCleanBeforeGeneration: true,
    buildControlInputs: Array.from({ length: 7 }, (_, index) => ({
      path: `control-${index}.js`,
      gitBlobId: String(index + 1).repeat(40).slice(0, 40),
      sha256: String(index + 1).repeat(64).slice(0, 64)
    })),
    gate2Template: {
      templateDigest: TEMPLATE_DIGEST,
      canonicalDigest: TEMPLATE_CANONICAL_DIGEST
    },
    artifacts: ["agent", "authority", "boundary", "demo", "probe", "signer"].map(
      (name) => ({
        name,
        artifactCodeSha256: configuration.artifactCodeSha256[name],
        artifactDigest: configuration.artifactDigests[name],
        sourceDigest: configuration.artifactSourceDigests[name],
        suggestedS3Key: configuration.artifactKeys[name]
      })
    )
  };
  return { buildReceipt, configuration, expectation, functions };
}

function stackResourcesFor(expectation) {
  const resources = [];
  for (const name of DEPLOYMENT_FUNCTIONS) {
    const title = `${name[0].toUpperCase()}${name.slice(1)}`;
    const expected = expectation.functions[name];
    resources.push(
      {
        LogicalResourceId: `${title}Alias`,
        PhysicalResourceId: expected.aliasArn,
        ResourceStatus: "CREATE_COMPLETE",
        ResourceType: "AWS::Lambda::Alias"
      },
      {
        LogicalResourceId: `${title}Function`,
        PhysicalResourceId: expected.functionName,
        ResourceStatus: "CREATE_COMPLETE",
        ResourceType: "AWS::Lambda::Function"
      },
      {
        LogicalResourceId: `${title}Role`,
        PhysicalResourceId: expected.roleArn.split("/").at(-1),
        ResourceStatus: "CREATE_COMPLETE",
        ResourceType: "AWS::IAM::Role"
      },
      {
        LogicalResourceId: `${title}Version`,
        PhysicalResourceId: expected.numericVersionArn,
        ResourceStatus: "CREATE_COMPLETE",
        ResourceType: "AWS::Lambda::Version"
      }
    );
  }
  resources.push(
    {
      LogicalResourceId: "DeploymentEvidenceAlternateRole",
      PhysicalResourceId:
        expectation.alternatePrincipal.roleArn.split("/").at(-1),
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::IAM::Role"
    },
    {
      LogicalResourceId: "DeploymentEvidenceRole",
      PhysicalResourceId: expectation.evidenceOperator.roleArn.split("/").at(-1),
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::IAM::Role"
    }
  );
  return resources;
}

function state(phase, observedAt) {
  const value = fixture();
  const snapshotState = {
    alternatePrincipalRole: roleSnapshot({
      arn: ALTERNATE_ROLE_ARN,
      id: "AROATIDEPROOFALTERNATE",
      policy: alternatePolicy(),
      trustPolicy: accountTrustPolicy()
    }),
    callerIdentity: {
      Account: ACCOUNT_ID,
      Arn: OPERATOR_CALLER_ARN,
      UserId: OPERATOR_CALLER_USER_ID
    },
    evidenceOperatorRole: roleSnapshot({
      arn: OPERATOR_ROLE_ARN,
      id: "AROATIDEPROOFEVIDENCE",
      policy: operatorPolicy(),
      trustPolicy: operatorTrustPolicy()
    }),
    functions: Object.fromEntries(
      Object.entries(value.functions).map(([name, item]) => [name, item.actual])
    ),
    region: REGION,
    stack: {
      bindings: {
        configDigest: value.expectation.configDigest,
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      },
      driftStatus: "IN_SYNC",
      resourceBindings: runnerTest.stackResourceBindings(
        value.expectation,
        stackResourcesFor(value.expectation)
      ),
      stackId: STACK_ID,
      stackName: STACK_NAME,
      stackStatus: "CREATE_COMPLETE",
      templateCanonicalDigest: TEMPLATE_CANONICAL_DIGEST
    }
  };
  const stateDigest = __test.sha256(snapshotState);
  return {
    ...value,
    snapshot: {
      ...snapshotState,
      observationFence: {
        completedAt: observedAt,
        firstStateDigest: stateDigest,
        secondStateDigest: stateDigest,
        startedAt: new Date(Date.parse(observedAt) - 1_000).toISOString()
      },
      observedAt,
      phase
    }
  };
}

function callerExpectation() {
  return {
    expectedCallerArn: OPERATOR_CALLER_ARN,
    expectedCallerUserId: OPERATOR_CALLER_USER_ID
  };
}

function refreshFence(snapshot) {
  const statePayload = __test.snapshotStatePayload(snapshot);
  const digest = __test.sha256(statePayload);
  snapshot.observationFence.firstStateDigest = digest;
  snapshot.observationFence.secondStateDigest = digest;
  return snapshot;
}

function signedSnapshot(value) {
  const unsigned = validateDeploymentSnapshot(
    value.snapshot,
    value.expectation,
    callerExpectation()
  );
  return signDeploymentAttestationReceipt(
    unsigned,
    RECEIPT_KEYS[value.snapshot.phase].privateKey,
    RECEIPT_KEYS[value.snapshot.phase].publicKey
  );
}

function signedAlternateDenial(expectation, observedAt) {
  const callerBinding = validateAwsEvidenceCaller(
    {
      Account: ACCOUNT_ID,
      Arn: ALTERNATE_CALLER_ARN,
      UserId: ALTERNATE_CALLER_USER_ID
    },
    {
      expectedAccountId: ACCOUNT_ID,
      expectedPrincipalArn: ALTERNATE_ROLE_ARN,
      expectedCallerArn: ALTERNATE_CALLER_ARN,
      expectedCallerUserId: ALTERNATE_CALLER_USER_ID,
      bindingContext: {
        purpose: "gate2-evidence-role-alternate-denial",
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST,
        configDigest: expectation.configDigest,
        stackId: STACK_ID,
        targetRoleArn: OPERATOR_ROLE_ARN,
        observedAt
      }
    }
  );
  const unsigned = {
    schemaVersion: __test.ALTERNATE_DENIAL_SCHEMA,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    configDigest: expectation.configDigest,
    alternatePrincipalArn: ALTERNATE_ROLE_ARN,
    alternatePrincipalDigest: __test.sha256(ALTERNATE_ROLE_ARN),
    callerBinding,
    errorCode: "AccessDenied",
    observedAt,
    outcome: "DENIED",
    requestIdDigest: "9".repeat(64),
    targetRoleArn: OPERATOR_ROLE_ARN
  };
  return signDeploymentAttestationReceipt(
    unsigned,
    RECEIPT_KEYS.alternateDenial.privateKey,
    RECEIPT_KEYS.alternateDenial.publicKey
  );
}

test("deployment expectation and basis bind exact build and configuration evidence", () => {
  const value = fixture();
  assert.equal(validateDeploymentExpectation(value.expectation), value.expectation);
  assert.deepEqual(
    validateDeploymentEvidenceBasis({
      expectation: value.expectation,
      configuration: value.configuration,
      buildReceipt: value.buildReceipt,
      configurationSha256: CONFIGURATION_SHA256,
      buildReceiptSha256: BUILD_RECEIPT_SHA256
    }).configDigest,
    value.expectation.configDigest
  );
  const changed = structuredClone(value.buildReceipt);
  changed.artifacts[0].artifactCodeSha256 = Buffer.alloc(32, 9).toString("base64");
  assert.throws(
    () =>
      validateDeploymentEvidenceBasis({
        expectation: value.expectation,
        configuration: value.configuration,
        buildReceipt: changed,
        configurationSha256: CONFIGURATION_SHA256,
        buildReceiptSha256: BUILD_RECEIPT_SHA256
      }),
    /AWS_ATTEST_BASIS_ARTIFACTS/
  );
});

test("attestation runners accept only exact private-evidence modes", () => {
  assert.deepEqual(
    runnerTest.parseArguments([
      "--phase", "pre",
      "--expectation", "private-expectation.json",
      "--configuration", "private-config.json",
      "--build-receipt", "build.json",
      "--receipt-key", "pre.pem"
    ]).phase,
    "pre"
  );
  assert.deepEqual(
    runnerTest.parseArguments([
      "--phase", "post",
      "--expectation", "private-expectation.json",
      "--configuration", "private-config.json",
      "--build-receipt", "build.json",
      "--receipt-key", "post.pem",
      "--pre-receipt", "private-pre.json",
      "--alternate-denial", "private-denial.json"
    ]).phase,
    "post"
  );
  assert.throws(
    () => runnerTest.parseArguments(["--phase", "post"]),
    /AWS_ATTEST_ARGUMENTS/
  );
  assert.deepEqual(
    denialRunnerTest.parseArguments([
      "--expectation", "private-expectation.json",
      "--receipt-key", "denial.pem"
    ]),
    {
      expectationPath: "private-expectation.json",
      receiptKeyPath: "denial.pem"
    }
  );
  assert.equal(runnerTest.parsedTemplateBody('{"Resources":{}}').Resources != null, true);
  assert.equal(
    safeAwsAttestationFailureCode(new Error("AWS_ATTEST_COLLECT_STACK")),
    "AWS_ATTEST_COLLECT_STACK"
  );
  assert.equal(
    safeAwsAttestationFailureCode(new Error("private arn:aws:iam::111111111111:role/Admin")),
    "AWS_ATTEST_UNKNOWN"
  );
  assert.equal(
    safeAlternateDenialFailureCode(new Error("AWS_ATTEST_DENIAL_PROVIDER_RESPONSE")),
    "AWS_ATTEST_DENIAL_PROVIDER_RESPONSE"
  );
  const exactBytes = Buffer.from('{"schemaVersion":"fixture"}\n', "utf8");
  const exactRecord = runnerTest.exactBuildRecord(
    exactBytes,
    "AWS_ATTEST_EXACT_BUILD_RECEIPT"
  );
  assert.deepEqual(
    runnerTest.validateExactBuildReproduction(exactRecord, exactRecord),
    {
      buildReceiptSha256: exactRecord.digest,
      reproducedBuildReceiptSha256: exactRecord.digest
    }
  );
  const staleRecord = runnerTest.exactBuildRecord(
    Buffer.from('{"schemaVersion":"stale"}\n', "utf8"),
    "AWS_ATTEST_EXACT_BUILD_RECEIPT"
  );
  assert.throws(
    () => runnerTest.validateExactBuildReproduction(exactRecord, staleRecord),
    /AWS_ATTEST_EXACT_BUILD_MISMATCH/
  );
  const value = fixture();
  const stackResources = stackResourcesFor(value.expectation);
  const bindings = runnerTest.stackResourceBindings(
    value.expectation,
    stackResources
  );
  assert.equal(
    bindings.AgentFunction.physicalResourceId,
    value.expectation.functions.agent.functionName
  );
  stackResources.find(
    (resource) => resource.LogicalResourceId === "AgentFunction"
  ).PhysicalResourceId = "same-account-shadow-function";
  assert.throws(
    () => runnerTest.stackResourceBindings(value.expectation, stackResources),
    /AWS_ATTEST_COLLECT_STACK_RESOURCE_BINDING/
  );
});

test("one signed snapshot binds the five primary runtime functions and roles", () => {
  const value = state("pre", "2026-08-02T04:00:00.000Z");
  const receipt = signedSnapshot(value);
  assert.equal(receipt.status, "PRE_ATTESTATION_PASS");
  assert.equal(receipt.signature.algorithm, "Ed25519");
  assert.equal(receipt.finalReleaseReady, false);
  assert.match(receipt.claimBoundary, /not.*administrator exclusion/i);

  const mutations = [
    ["layer", (item) => { item.functions.agent.configuration.layers = [{ arn: "arn:aws:lambda:us-east-1:111111111111:layer:backdoor:1", codeSize: 10 }]; }],
    ["config", (item) => { item.functions.agent.configuration.environment.SOURCE_COMMIT = "f".repeat(40); }],
    ["managed policy", (item) => { item.functions.agent.role.attachedManagedPolicies = [{ policyArn: "arn:aws:iam::aws:policy/AdministratorAccess", policyName: "AdministratorAccess" }]; }],
    ["extra inline policy", (item) => { item.evidenceOperatorRole.inlinePolicies.push({ name: "Backdoor", document: rolePolicy("backdoor") }); }],
    ["permissions boundary", (item) => { item.alternatePrincipalRole.permissionsBoundary = { arn: "arn:aws:iam::111111111111:policy/Boundary", type: "Policy" }; }],
    ["resource drift", (item) => { item.functions.agent.resourceDrift.alias = "MODIFIED"; }],
    ["shadow function", (item) => {
      item.stack.resourceBindings.AgentFunction.physicalResourceId =
        "shadow-agent";
    }],
    ["stack drift", (item) => { item.stack.driftStatus = "DRIFTED"; }]
  ];
  for (const [label, mutate] of mutations) {
    const changed = structuredClone(value.snapshot);
    mutate(changed);
    refreshFence(changed);
    assert.throws(
      () => validateDeploymentSnapshot(changed, value.expectation, callerExpectation()),
      /AWS_ATTEST_/,
      label
    );
  }
});

test("pre/post pair rejects forged evidence, role replacement, and revision drift", () => {
  const pre = state("pre", "2026-08-02T04:00:00.000Z");
  const post = state("post", "2026-08-02T04:10:00.000Z");
  const preReceipt = signedSnapshot(pre);
  const postReceipt = signedSnapshot(post);
  const denial = signedAlternateDenial(
    post.expectation,
    "2026-08-02T04:05:00.000Z"
  );
  const receipt = validateDeploymentAttestationPair({
    preReceipt,
    postReceipt,
    expectation: post.expectation,
    alternateDenial: denial
  });
  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.controls.authenticatedPreSnapshot, true);
  assert.equal(receipt.controls.primaryRuntimeRolePolicyCensus, true);
  assert.equal(receipt.controls.primaryRuntimeConfigurationsBound, true);
  assert.equal(receipt.controls.revisionFencedSnapshots, true);
  assert.equal(receipt.finalReleaseReady, false);

  const forgedPre = structuredClone(preReceipt);
  forgedPre.claimBoundary = `${forgedPre.claimBoundary} forged`;
  forgedPre.snapshotDigest = __test.sha256(__test.snapshotReceiptPayload(forgedPre));
  assert.throws(
    () => validateDeploymentAttestationPair({
      preReceipt: forgedPre,
      postReceipt,
      expectation: post.expectation,
      alternateDenial: denial
    }),
    /AWS_ATTEST_SNAPSHOT_RECEIPT|AWS_ATTEST_SNAPSHOT_SIGNATURE/
  );

  const forgedDenial = structuredClone(denial);
  forgedDenial.requestIdDigest = "8".repeat(64);
  assert.throws(
    () => validateDeploymentAttestationPair({
      preReceipt,
      postReceipt,
      expectation: post.expectation,
      alternateDenial: forgedDenial
    }),
    /AWS_ATTEST_ALTERNATE_DENIAL_SIGNATURE/
  );

  const replacedPost = state("post", "2026-08-02T04:10:00.000Z");
  replacedPost.snapshot.evidenceOperatorRole.roleId = "AROATIDEPROOFREPLACED";
  refreshFence(replacedPost.snapshot);
  const replacedReceipt = signedSnapshot(replacedPost);
  assert.throws(
    () => validateDeploymentAttestationPair({
      preReceipt,
      postReceipt: replacedReceipt,
      expectation: post.expectation,
      alternateDenial: denial
    }),
    /AWS_ATTEST_PAIR_STACK_DRIFT/
  );

  const driftedPost = state("post", "2026-08-02T04:10:00.000Z");
  driftedPost.snapshot.functions.agent.numericRevisionId =
    "99999999-9999-4999-8999-999999999999";
  refreshFence(driftedPost.snapshot);
  const driftedReceipt = signedSnapshot(driftedPost);
  assert.throws(
    () => validateDeploymentAttestationPair({
      preReceipt,
      postReceipt: driftedReceipt,
      expectation: post.expectation,
      alternateDenial: denial
    }),
    /AWS_ATTEST_PAIR_FUNCTION_DRIFT_AGENT/
  );
});

test("snapshot revision fence must bind two identical provider observations", () => {
  const value = state("pre", "2026-08-02T04:00:00.000Z");
  value.snapshot.observationFence.secondStateDigest = "0".repeat(64);
  assert.throws(
    () => validateDeploymentSnapshot(value.snapshot, value.expectation, callerExpectation()),
    /AWS_ATTEST_OBSERVATION_FENCE/
  );
});
