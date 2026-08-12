import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { GATE2_BUILD_CONTROL_PATHS } from
  "../scripts/lib/gate2-build-contract.js";
import {
  DEPLOYMENT_API_INTEGRATIONS,
  DEPLOYMENT_API_ROUTE_KEYS,
  DEPLOYMENT_FUNCTIONS,
  __test,
  deploymentFunctionConfigurationDigest,
  deploymentStackParameterBindings,
  signDeploymentAttestationReceipt,
  validateDeploymentAttestationPair,
  validateDeploymentEvidenceBasis,
  validateDeploymentExpectation,
  validateDeploymentSnapshot,
  validateSignedDeploymentAttestationPair
} from "../src/cloud/aws-deployment-attestation.js";
import { deploymentConfigDigest } from "../src/cloud/aws-gate2-template.js";
import { deploymentConfigDigestPure } from
  "../src/cloud/deployment-config-digest.js";
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
const STACK_NAME = "prooftoact-gate2";
const STACK_ID =
  `arn:aws:cloudformation:${REGION}:${ACCOUNT_ID}:stack/` +
  `${STACK_NAME}/11111111-1111-4111-8111-111111111111`;
const SOURCE_COMMIT = "a".repeat(40);
const HTTP_API_ID = "a1b2c3d4e5";
const API_DEPLOYMENT_ID = "deployment1";
const API_DEPLOYMENT_CREATED_AT = "2026-08-02T03:59:00.000Z";
const STACK_CREATED_AT = "2026-08-02T03:58:00.000Z";
const API_INTEGRATION_IDS = Object.freeze({
  BoundaryIntegration: "i000000001",
  DemoIntegration: "i000000002"
});
const API_ROUTE_IDS = Object.freeze(
  Object.fromEntries(
    Object.keys(DEPLOYMENT_API_ROUTE_KEYS).map((logicalId, index) => [
      logicalId,
      `r${String(index + 1).padStart(9, "0")}`
    ])
  )
);
const TREE_DIGEST = "b".repeat(40);
const TEMPLATE_DIGEST = "c".repeat(64);
const TEMPLATE_CANONICAL_DIGEST = "d".repeat(64);
const BUILD_RECEIPT_SHA256 = "e".repeat(64);
const CONFIGURATION_SHA256 = "f".repeat(64);
const PROVIDER_DEPENDENCY_TREE_DIGEST = "9".repeat(64);
const PROVIDER_RUNTIME_SHA256 = "8".repeat(64);
const OPERATOR_ROLE_ARN =
  `arn:aws:iam::${ACCOUNT_ID}:role/prooftoact-gate2-evidence`;
const ALTERNATE_ROLE_ARN = `${OPERATOR_ROLE_ARN}-alternate`;
const TRUSTED_PRINCIPAL_ARN =
  `arn:aws:iam::${ACCOUNT_ID}:role/tideproof-evidence-source`;
const OPERATOR_CALLER_ARN =
  `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
  "prooftoact-gate2-evidence/deployment-proof";
const OPERATOR_CALLER_USER_ID =
  "AROATIDEPROOFEVIDENCE:deployment-proof";
const ALTERNATE_CALLER_ARN =
  `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
  "prooftoact-gate2-evidence-alternate/negative-control";
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
      { name: "ProofToActExactCapabilities", document: policy }
    ],
    maxSessionDuration: 3600,
    permissionsBoundary: null,
    resourceDrift,
    roleId: id,
    tags: [
      { key: "Gate", value: "Two" },
      { key: "Project", value: "ProofToAct" }
    ],
    trustPolicy
  };
}

function resourcePoliciesFor(name, numericVersionArn, index) {
  const prefix =
    `arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:` +
    `${HTTP_API_ID}/$default/`;
  const sources = {
    agent: [],
    authority: [],
    boundary: [`${prefix}POST/advisory`],
    demo: [`${prefix}GET/`, `${prefix}GET/*`],
    signer: []
  }[name];
  return {
    alias: null,
    numeric:
      sources.length === 0
        ? null
        : {
            policy: {
              Id: "default",
              Statement: sources.map((sourceArn, statementIndex) => ({
                Action: "lambda:InvokeFunction",
                Condition: {
                  ArnLike: { "AWS:SourceArn": sourceArn },
                  StringEquals: {
                    "AWS:SourceAccount": ACCOUNT_ID
                  }
                },
                Effect: "Allow",
                Principal: { Service: "apigateway.amazonaws.com" },
                Resource: numericVersionArn,
                Sid: `fixture-${name}-${statementIndex}`
              })),
              Version: "2012-10-17"
            },
            revisionId:
              `30000000-0000-4000-8000-00000000000${index}`
          },
    unqualified: null
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
  const aliasRevisionId =
    `10000000-0000-4000-8000-00000000000${index}`;
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
      provisionedConcurrencyConfigurations: [],
      reservedConcurrency: concurrency,
      roleArn,
      rolePolicyDigest: __test.sha256(policy),
      timeout
    },
    actual: {
      aliases: [
        {
          aliasArn: `${functionArn}:proof`,
          description:
            "Monitored proof pointer; all reviewed invocations use the numeric version ARN.",
          functionVersion: numericVersion,
          name: "proof",
          revisionId: aliasRevisionId,
          routingConfiguration: {}
        }
      ],
      aliasArn: `${functionArn}:proof`,
      aliasName: "proof",
      aliasRevisionId,
      aliasRoutingConfiguration: {},
      aliasTargetVersion: numericVersion,
      codeSha256: Buffer.alloc(32, index + 1).toString("base64"),
      codeSigningConfig: { codeSigningConfigArn: null },
      configuration,
      functionArn,
      functionName,
      functionTags: { Gate: "Two", Project: "ProofToAct" },
      functionUrlConfigs: [],
      lastUpdateStatus: "Successful",
      numericRevisionId: `20000000-0000-4000-8000-00000000000${index}`,
      numericVersion,
      numericVersionArn: `${functionArn}:${numericVersion}`,
      eventSourceMappings: [],
      provisionedConcurrencyConfigurations: [],
      recursionConfig: { recursiveLoop: "Terminate" },
      reservedConcurrency: concurrency,
      resourceDrift: {
        alias: "IN_SYNC",
        function: "IN_SYNC",
        role: "IN_SYNC",
        version: "IN_SYNC"
      },
      resourcePolicies: resourcePoliciesFor(
        name,
        `${functionArn}:${numericVersion}`,
        index
      ),
      role: roleSnapshot({
        arn: roleArn,
        id: `AROATIDEPROOFROLE${index}`,
        policy,
        trustPolicy: lambdaTrustPolicy()
      }),
      runtimeManagementConfig: {
        runtimeVersionArn: null,
        updateRuntimeOn: "Auto"
      },
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
        `arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:prooftoact/authorizer-AbCd12`,
      databaseSecretVersionId: "a".repeat(32),
      tenantId: "11111111-1111-4111-8111-111111111111",
      incidentId: "33333333-3333-4333-8333-333333333333",
      resourceId: "synthetic-rescue-unit-aws-proof"
    },
    bedrockModelId: "amazon.nova-micro-v1:0",
    budgetUsd: 15,
    evidenceOperator: { principalArn: TRUSTED_PRINCIPAL_ARN },
    logRetentionDays: 7,
    notificationEmailDigest: "6".repeat(64),
    packageLockDigest: "7".repeat(64),
    probesEnabled: false,
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
  assert.equal(deploymentConfigDigestPure(configuration), configDigest);
  const expectation = {
    schemaVersion: __test.EXPECTATION_SCHEMA,
    accountId: ACCOUNT_ID,
    alternatePrincipal: {
      roleArn: ALTERNATE_ROLE_ARN,
      rolePolicyDigest: __test.sha256(alternatePolicy())
    },
    basis: {
      buildReceiptSha256: BUILD_RECEIPT_SHA256,
      configurationSha256: CONFIGURATION_SHA256,
      providerDependencyTreeDigest: PROVIDER_DEPENDENCY_TREE_DIGEST,
      providerRuntimeSha256: PROVIDER_RUNTIME_SHA256,
      stackParameterCount: 45,
      stackParametersDigest: __test.sha256(
        deploymentStackParameterBindings(configuration)
      )
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
    integratedLiveDrillAuthorizationAttestationSha256: "f".repeat(64),
    receiptPublicKeys: configuration.attestation.receiptPublicKeys,
    region: REGION,
    sourceCommit: SOURCE_COMMIT,
    stackId: STACK_ID,
    stackName: STACK_NAME,
    templateCanonicalDigest: TEMPLATE_CANONICAL_DIGEST,
    treeDigest: TREE_DIGEST
  };
  const buildReceipt = {
    schemaVersion: "tideproof.gate2-build.v7",
    mode: "CLEAN_ARTIFACT_BUILD",
    projectSourceMode: "ISOLATED_EXACT_GIT_CHECKOUT_AND_BLOBS",
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    workingTreeClean: true,
    workingTreeCleanBeforeGeneration: true,
    dependencySnapshot: {
      treeDigest: PROVIDER_DEPENDENCY_TREE_DIGEST
    },
    evidenceProviderRuntime: {
      sha256: PROVIDER_RUNTIME_SHA256
    },
    buildControlInputs: Array.from(
      { length: GATE2_BUILD_CONTROL_PATHS.length },
      (_, index) => ({
        path: `control-${index}.js`,
        gitBlobId: String(index + 1).repeat(40).slice(0, 40),
        sha256: String(index + 1).repeat(64).slice(0, 64)
      })
    ),
    liveDrillRuntime: {
      manifestPath: `dist/runtime/runtime-manifest-${"9".repeat(64)}.json`,
      manifestSha256: "9".repeat(64)
    },
    outputPrivacy: {
      schemaVersion: "tideproof.gate2-build-output-privacy.v1",
      status: "PASS",
      outputCount: 19,
      inventorySha256: "8".repeat(64)
    },
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
      LogicalResourceId: "ApiAccessLogGroup",
      PhysicalResourceId:
        `${STACK_NAME}-ApiAccessLogGroup-A1B2C3D4`,
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::Logs::LogGroup"
    },
    {
      LogicalResourceId: "HttpApi",
      PhysicalResourceId: HTTP_API_ID,
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::ApiGatewayV2::Api"
    },
    {
      LogicalResourceId: "ApiDeployment",
      PhysicalResourceId: API_DEPLOYMENT_ID,
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::ApiGatewayV2::Deployment"
    },
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
  resources.push(
    {
      LogicalResourceId: "BoundaryIntegration",
      PhysicalResourceId: API_INTEGRATION_IDS.BoundaryIntegration,
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::ApiGatewayV2::Integration"
    },
    {
      LogicalResourceId: "DemoIntegration",
      PhysicalResourceId: API_INTEGRATION_IDS.DemoIntegration,
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::ApiGatewayV2::Integration"
    },
    ...Object.entries(API_ROUTE_IDS).map(
      ([LogicalResourceId, PhysicalResourceId]) => ({
        LogicalResourceId,
        PhysicalResourceId,
        ResourceStatus: "CREATE_COMPLETE",
        ResourceType: "AWS::ApiGatewayV2::Route"
      })
    ),
    {
      LogicalResourceId: "DefaultStage",
      PhysicalResourceId: "$default",
      ResourceStatus: "CREATE_COMPLETE",
      ResourceType: "AWS::ApiGatewayV2::Stage"
    }
  );
  return resources;
}

function apiGatewayFixture(expectation) {
  const stackResourceBindings = runnerTest.stackApiGatewayBindings(
    stackResourcesFor(expectation)
  );
  return {
    activeDeployment: {
      autoDeployed: false,
      createdAt: API_DEPLOYMENT_CREATED_AT,
      deploymentId: API_DEPLOYMENT_ID,
      deploymentStatus: "DEPLOYED",
      deploymentStatusMessage: "",
      description:
        `ProofToAct exact API deployment ${expectation.sourceCommit} ${expectation.configDigest}`
    },
    api: {
      apiGatewayManaged: false,
      apiKeySelectionExpression: "$request.header.x-api-key",
      apiEndpoint: `https://${HTTP_API_ID}.execute-api.${REGION}.amazonaws.com`,
      apiId: HTTP_API_ID,
      corsConfiguration: {},
      description:
        "Signed-out read-only ProofToAct demo plus an isolated IAM-authenticated advisory endpoint.",
      disableExecuteApiEndpoint: false,
      disableSchemaValidation: false,
      importInfo: [],
      ipAddressType: "ipv4",
      name: `${STACK_NAME}-api`,
      protocolType: "HTTP",
      resourceDrift: "IN_SYNC",
      routeSelectionExpression: "$request.method $request.path",
      tags: { Gate: "Two", Project: "ProofToAct" },
      version: "",
      warnings: []
    },
    census: {
      deployments: [
        {
          autoDeployed: false,
          createdAt: API_DEPLOYMENT_CREATED_AT,
          deploymentId: API_DEPLOYMENT_ID,
          deploymentStatus: "DEPLOYED"
        }
      ],
      integrationIds: Object.values(API_INTEGRATION_IDS).sort(),
      routeIds: Object.values(API_ROUTE_IDS).sort(),
      stageNames: ["$default"]
    },
    integrations: Object.fromEntries(
      Object.entries(DEPLOYMENT_API_INTEGRATIONS).map(
        ([logicalId, binding]) => [
          logicalId,
          {
            apiGatewayManaged: false,
            connectionId: null,
            connectionType: "INTERNET",
            contentHandlingStrategy: null,
            credentialsArn: null,
            description: "",
            integrationId: API_INTEGRATION_IDS[logicalId],
            integrationMethod: "POST",
            integrationResponseSelectionExpression: null,
            integrationSubtype: null,
            integrationType: "AWS_PROXY",
            integrationUri:
              expectation.functions[binding.functionName].numericVersionArn,
            passthroughBehavior: null,
            payloadFormatVersion: "2.0",
            requestParameters: {},
            requestTemplates: {},
            responseParameters: {},
            templateSelectionExpression: null,
            timeoutInMillis: binding.timeoutInMillis,
            tlsConfig: null
          }
        ]
      )
    ),
    routes: Object.fromEntries(
      Object.entries(DEPLOYMENT_API_ROUTE_KEYS).map(
        ([logicalId, routeKey]) => [
          logicalId,
          {
            apiKeyRequired: false,
            authorizationScopes: [],
            authorizationType:
              logicalId === "AdvisoryRoute" ? "AWS_IAM" : "NONE",
            authorizerId: null,
            modelSelectionExpression: null,
            operationName: "",
            requestModels: {},
            requestParameters: {},
            resourceDrift: "IN_SYNC",
            routeId: API_ROUTE_IDS[logicalId],
            routeKey,
            routeResponseSelectionExpression: null,
            target:
              `integrations/${
                logicalId === "AdvisoryRoute"
                  ? API_INTEGRATION_IDS.BoundaryIntegration
                  : API_INTEGRATION_IDS.DemoIntegration
              }`
          }
        ]
      )
    ),
    stackResourceBindings,
    stage: {
      accessLogSettings: {
        destinationArn:
          `arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:` +
          `${STACK_NAME}-ApiAccessLogGroup-A1B2C3D4:*`,
        format: JSON.stringify({
          apiId: "$context.apiId",
          backendStatus: "$context.integration.status",
          callerArn: "$context.identity.userArn",
          lambdaServiceStatus: "$context.integration.integrationStatus",
          requestId: "$context.requestId",
          requestTimeEpoch: "$context.requestTimeEpoch",
          routeKey: "$context.routeKey",
          status: "$context.status"
        })
      },
      autoDeploy: false,
      clientCertificateId: null,
      defaultRouteSettings: {
        dataTraceEnabled: false,
        detailedMetricsEnabled: false,
        loggingLevel: null,
        throttlingBurstLimit: 8,
        throttlingRateLimit: 0.05
      },
      deploymentId: API_DEPLOYMENT_ID,
      description: "",
      lastDeploymentStatusMessage: "",
      resourceDrift: "IN_SYNC",
      routeSettings: {
        "POST /advisory": {
          dataTraceEnabled: false,
          detailedMetricsEnabled: false,
          loggingLevel: null,
          throttlingBurstLimit: 1,
          throttlingRateLimit: 0.1
        }
      },
      stageName: "$default",
      stageVariables: {},
      tags: { Gate: "Two", Project: "ProofToAct" }
    }
  };
}

function state(phase, observedAt) {
  const value = fixture();
  const snapshotState = {
    alternatePrincipalRole: roleSnapshot({
      arn: ALTERNATE_ROLE_ARN,
      id: "AROATIDEPROOFALTERNATE",
      policy: alternatePolicy(),
      trustPolicy: operatorTrustPolicy()
    }),
    apiGateway: apiGatewayFixture(value.expectation),
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
    providerDependencyTreeDigest: PROVIDER_DEPENDENCY_TREE_DIGEST,
    providerRuntimeSha256: PROVIDER_RUNTIME_SHA256,
    region: REGION,
    stack: {
      bindings: {
        configDigest: value.expectation.configDigest,
        probesEnabled: "false",
        sourceCommit: SOURCE_COMMIT,
        treeDigest: TREE_DIGEST
      },
      cloudFormationServiceRoleArn: null,
      createdAt: STACK_CREATED_AT,
      driftStatus: "IN_SYNC",
      httpApiId: HTTP_API_ID,
      lastUpdatedAt: null,
      parameterCount: value.expectation.basis.stackParameterCount,
      parametersDigest: value.expectation.basis.stackParametersDigest,
      resourceBindings: runnerTest.stackResourceBindings(
        value.expectation,
        stackResourcesFor(value.expectation)
      ),
      semanticAlarmDrift: {
        authority: "IN_SYNC",
        boundary: "IN_SYNC"
      },
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
    expectationDigest: __test.sha256(expectation),
    observedAt,
    outcome: "DENIED",
    providerDependencyTreeDigest: PROVIDER_DEPENDENCY_TREE_DIGEST,
    providerRuntimeSha256: PROVIDER_RUNTIME_SHA256,
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
  const probeSubstitution = structuredClone(value.buildReceipt);
  probeSubstitution.artifacts.find(({ name }) => name === "probe").artifactDigest =
    "8".repeat(64);
  assert.throws(
    () =>
      validateDeploymentEvidenceBasis({
        expectation: value.expectation,
        configuration: value.configuration,
        buildReceipt: probeSubstitution,
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
      "--build-receipt", "build.json",
      "--expectation", "private-expectation.json",
      "--receipt-key", "denial.pem"
    ]),
    {
      buildReceiptPath: "build.json",
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
  assert.equal(runnerTest.stackHttpApiId(stackResources), HTTP_API_ID);
  stackResources.find(
    (resource) => resource.LogicalResourceId === "AgentFunction"
  ).PhysicalResourceId = "same-account-shadow-function";
  assert.throws(
    () => runnerTest.stackResourceBindings(value.expectation, stackResources),
    /AWS_ATTEST_COLLECT_STACK_RESOURCE_BINDING/
  );
  const expectedParameters = deploymentStackParameterBindings(
    value.configuration
  );
  const stack = {
    Parameters: Object.entries(expectedParameters).map(
      ([ParameterKey, ParameterValue]) => ({
        ParameterKey,
        ParameterValue
      })
    )
  };
  assert.deepEqual(runnerTest.stackParameterCensus(stack, expectedParameters), {
    parameterCount: 45,
    parametersDigest: value.expectation.basis.stackParametersDigest
  });
  stack.Parameters.find(
    (item) => item.ParameterKey === "AgentArtifactVersion"
  ).ParameterValue = "substituted-version";
  assert.throws(
    () => runnerTest.stackParameterCensus(stack, expectedParameters),
    /AWS_ATTEST_COLLECT_PARAMETERS/
  );
});

test("API Gateway provider census normalizes the exact direct-read surface", async () => {
  const value = fixture();
  const expected = apiGatewayFixture(value.expectation);
  const stackResources = stackResourcesFor(value.expectation);
  const resourceDrifts = runnerTest.ATTESTED_DRIFT_LOGICAL_IDS.map(
    (LogicalResourceId) => ({
      LogicalResourceId,
      StackResourceDriftStatus: "IN_SYNC"
    })
  );
  const provider = {
    async getApi() {
      return {
        ApiGatewayManaged: expected.api.apiGatewayManaged,
        ApiKeySelectionExpression:
          expected.api.apiKeySelectionExpression,
        ApiEndpoint: expected.api.apiEndpoint,
        ApiId: expected.api.apiId,
        CorsConfiguration: expected.api.corsConfiguration,
        Description: expected.api.description,
        DisableExecuteApiEndpoint: expected.api.disableExecuteApiEndpoint,
        DisableSchemaValidation: expected.api.disableSchemaValidation,
        ImportInfo: expected.api.importInfo,
        IpAddressType: expected.api.ipAddressType,
        Name: expected.api.name,
        ProtocolType: expected.api.protocolType,
        RouteSelectionExpression: expected.api.routeSelectionExpression,
        Tags: expected.api.tags,
        Version: expected.api.version,
        Warnings: expected.api.warnings
      };
    },
    async getDeployment() {
      return {
        AutoDeployed: expected.activeDeployment.autoDeployed,
        CreatedDate: new Date(expected.activeDeployment.createdAt),
        DeploymentId: expected.activeDeployment.deploymentId,
        DeploymentStatus: expected.activeDeployment.deploymentStatus,
        DeploymentStatusMessage:
          expected.activeDeployment.deploymentStatusMessage,
        Description: expected.activeDeployment.description
      };
    },
    async getDeployments() {
      return {
        Items: expected.census.deployments.map((deployment) => ({
          AutoDeployed: deployment.autoDeployed,
          CreatedDate: new Date(deployment.createdAt),
          DeploymentId: deployment.deploymentId,
          DeploymentStatus: deployment.deploymentStatus
        }))
      };
    },
    async getIntegration(_apiId, integrationId) {
      const item = Object.values(expected.integrations).find(
        (candidate) => candidate.integrationId === integrationId
      );
      return {
        ApiGatewayManaged: item.apiGatewayManaged,
        ConnectionId: item.connectionId,
        ConnectionType: item.connectionType,
        ContentHandlingStrategy: item.contentHandlingStrategy,
        CredentialsArn: item.credentialsArn,
        Description: item.description,
        IntegrationId: item.integrationId,
        IntegrationMethod: item.integrationMethod,
        IntegrationResponseSelectionExpression:
          item.integrationResponseSelectionExpression,
        IntegrationSubtype: item.integrationSubtype,
        IntegrationType: item.integrationType,
        IntegrationUri: item.integrationUri,
        PassthroughBehavior: item.passthroughBehavior,
        PayloadFormatVersion: item.payloadFormatVersion,
        RequestParameters: item.requestParameters,
        RequestTemplates: item.requestTemplates,
        ResponseParameters: item.responseParameters,
        TemplateSelectionExpression: item.templateSelectionExpression,
        TimeoutInMillis: item.timeoutInMillis,
        TlsConfig: item.tlsConfig
      };
    },
    async getIntegrations() {
      return {
        Items: expected.census.integrationIds.map((IntegrationId) => ({
          IntegrationId
        }))
      };
    },
    async getRoute(_apiId, routeId) {
      const item = Object.values(expected.routes).find(
        (candidate) => candidate.routeId === routeId
      );
      return {
        ApiKeyRequired: item.apiKeyRequired,
        AuthorizationScopes: item.authorizationScopes,
        AuthorizationType: item.authorizationType,
        AuthorizerId: item.authorizerId,
        ModelSelectionExpression: item.modelSelectionExpression,
        OperationName: item.operationName,
        RequestModels: item.requestModels,
        RequestParameters: item.requestParameters,
        RouteId: item.routeId,
        RouteKey: item.routeKey,
        RouteResponseSelectionExpression:
          item.routeResponseSelectionExpression,
        Target: item.target
      };
    },
    async getRoutes() {
      return {
        Items: expected.census.routeIds.map((RouteId) => ({ RouteId }))
      };
    },
    async getStage() {
      return {
        AccessLogSettings: {
          DestinationArn: expected.stage.accessLogSettings.destinationArn,
          Format: expected.stage.accessLogSettings.format
        },
        AutoDeploy: expected.stage.autoDeploy,
        ClientCertificateId: expected.stage.clientCertificateId,
        DefaultRouteSettings: {
          DataTraceEnabled:
            expected.stage.defaultRouteSettings.dataTraceEnabled,
          DetailedMetricsEnabled:
            expected.stage.defaultRouteSettings.detailedMetricsEnabled,
          LoggingLevel: expected.stage.defaultRouteSettings.loggingLevel,
          ThrottlingBurstLimit:
            expected.stage.defaultRouteSettings.throttlingBurstLimit,
          ThrottlingRateLimit:
            expected.stage.defaultRouteSettings.throttlingRateLimit
        },
        DeploymentId: expected.stage.deploymentId,
        Description: expected.stage.description,
        LastDeploymentStatusMessage:
          expected.stage.lastDeploymentStatusMessage,
        RouteSettings: {
          "POST /advisory": {
            DataTraceEnabled: false,
            DetailedMetricsEnabled: false,
            LoggingLevel: null,
            ThrottlingBurstLimit: 1,
            ThrottlingRateLimit: 0.1
          }
        },
        StageName: expected.stage.stageName,
        StageVariables: expected.stage.stageVariables,
        Tags: expected.stage.tags
      };
    },
    async getStages() {
      return {
        Items: expected.census.stageNames.map((StageName) => ({ StageName }))
      };
    }
  };
  assert.deepEqual(
    await runnerTest.apiGatewaySnapshot(
      provider,
      stackResources,
      resourceDrifts
    ),
    expected
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
    ["code signing", (item) => { item.functions.agent.codeSigningConfig.codeSigningConfigArn = "arn:aws:lambda:us-east-1:111111111111:code-signing-config:csc-123"; }],
    ["recursion", (item) => { item.functions.agent.recursionConfig.recursiveLoop = "Allow"; }],
    ["runtime management", (item) => { item.functions.agent.runtimeManagementConfig.updateRuntimeOn = "Manual"; }],
    ["resource policy", (item) => { item.functions.agent.resourcePolicies.numeric = resourcePoliciesFor("boundary", item.functions.agent.numericVersionArn, 0).numeric; }],
    ["config", (item) => { item.functions.agent.configuration.environment.SOURCE_COMMIT = "f".repeat(40); }],
    ["managed policy", (item) => { item.functions.agent.role.attachedManagedPolicies = [{ policyArn: "arn:aws:iam::aws:policy/AdministratorAccess", policyName: "AdministratorAccess" }]; }],
    ["extra inline policy", (item) => { item.evidenceOperatorRole.inlinePolicies.push({ name: "Backdoor", document: rolePolicy("backdoor") }); }],
    ["permissions boundary", (item) => { item.alternatePrincipalRole.permissionsBoundary = { arn: "arn:aws:iam::111111111111:policy/Boundary", type: "Policy" }; }],
    ["resource drift", (item) => { item.functions.agent.resourceDrift.alias = "MODIFIED"; }],
    ["semantic alarm drift", (item) => { item.stack.semanticAlarmDrift.authority = "MODIFIED"; }],
    ["shadow function", (item) => {
      item.stack.resourceBindings.AgentFunction.physicalResourceId =
        "shadow-agent";
    }],
    ["shadow alias", (item) => {
      item.functions.agent.aliases.push({
        ...item.functions.agent.aliases[0],
        aliasArn: `${item.functions.agent.functionArn}:shadow`,
        name: "shadow"
      });
    }],
    ["function URL", (item) => {
      item.functions.agent.functionUrlConfigs.push({
        AuthType: "NONE",
        FunctionArn: item.functions.agent.functionArn,
        FunctionUrl: "https://fixture.lambda-url.us-east-1.on.aws/"
      });
    }],
    ["event source", (item) => {
      item.functions.agent.eventSourceMappings.push({ UUID: "shadow" });
    }],
    ["function tag", (item) => {
      item.functions.agent.functionTags.Escalated = "true";
    }],
    ["API integration latest", (item) => {
      item.apiGateway.integrations.BoundaryIntegration.integrationUri =
        item.functions.boundary.functionArn;
    }],
    ["API integration request rewrite", (item) => {
      item.apiGateway.integrations.BoundaryIntegration.requestParameters = {
        "append:header.x-shadow": "injected"
      };
    }],
    ["API integration response rewrite", (item) => {
      item.apiGateway.integrations.BoundaryIntegration.responseParameters = {
        "200": { "overwrite:statuscode": "500" }
      };
    }],
    ["API route target", (item) => {
      item.apiGateway.routes.AdvisoryRoute.target =
        `integrations/${API_INTEGRATION_IDS.DemoIntegration}`;
    }],
    ["API route authorization", (item) => {
      item.apiGateway.routes.AdvisoryRoute.authorizationType = "NONE";
    }],
    ["extra API route", (item) => {
      item.apiGateway.census.routeIds.push("r999999999");
    }],
    ["extra API integration", (item) => {
      item.apiGateway.census.integrationIds.push("i999999999");
    }],
    ["extra API stage", (item) => {
      item.apiGateway.census.stageNames.push("shadow");
    }],
    ["API endpoint", (item) => {
      item.apiGateway.api.apiEndpoint =
        "https://shadow.execute-api.us-east-1.amazonaws.com";
    }],
    ["API permissive CORS", (item) => {
      item.apiGateway.api.corsConfiguration = {
        AllowOrigins: ["*"]
      };
    }],
    ["API tag", (item) => {
      item.apiGateway.api.tags.Project = "Shadow";
    }],
    ["API stage throttle", (item) => {
      item.apiGateway.stage.defaultRouteSettings.throttlingBurstLimit = 99;
    }],
    ["API stage auto deploy", (item) => {
      item.apiGateway.stage.autoDeploy = true;
    }],
    ["API deployment stack substitution", (item) => {
      item.apiGateway.stackResourceBindings.ApiDeployment.physicalResourceId =
        "deployment0";
    }],
    ["API deployment description", (item) => {
      item.apiGateway.activeDeployment.description = "unbound deployment";
    }],
    ["updated stack", (item) => {
      item.stack.stackStatus = "UPDATE_COMPLETE";
      item.stack.lastUpdatedAt = "2026-08-02T03:59:30.000Z";
    }],
    ["deployment older than stack", (item) => {
      item.stack.createdAt = "2026-08-02T03:59:30.000Z";
    }],
    ["API active deployment pending", (item) => {
      item.apiGateway.activeDeployment.deploymentStatus = "PENDING";
      item.apiGateway.census.deployments[0].deploymentStatus = "PENDING";
    }],
    ["API active deployment failed", (item) => {
      item.apiGateway.activeDeployment.deploymentStatus = "FAILED";
      item.apiGateway.activeDeployment.deploymentStatusMessage =
        "provider failure";
      item.apiGateway.census.deployments[0].deploymentStatus = "FAILED";
    }],
    ["API newer pending deployment", (item) => {
      item.apiGateway.census.deployments.push({
        autoDeployed: false,
        createdAt: "2026-08-02T04:00:00.000Z",
        deploymentId: "deployment2",
        deploymentStatus: "PENDING"
      });
    }],
    ["API old stage deployment", (item) => {
      item.apiGateway.stage.deploymentId = "deployment0";
    }],
    ["API stage deployment warning", (item) => {
      item.apiGateway.stage.lastDeploymentStatusMessage = "still deploying";
    }],
    ["API access log destination", (item) => {
      item.apiGateway.stage.accessLogSettings.destinationArn =
        `arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:` +
        `${STACK_NAME}-ApiAccessLogGroup-Shadow:*`;
    }],
    ["artifact parameter", (item) => {
      item.stack.parametersDigest = "0".repeat(64);
    }],
    ["HTTP API substitution", (item) => {
      item.stack.httpApiId = "z9y8x7w6v5";
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
  const provisioned = structuredClone(value.snapshot);
  provisioned.functions.agent.provisionedConcurrencyConfigurations = [
    {
      AllocatedProvisionedConcurrentExecutions: 1,
      FunctionArn: `${value.expectation.functions.agent.functionArn}:proof`,
      RequestedProvisionedConcurrentExecutions: 1,
      Status: "READY"
    }
  ];
  refreshFence(provisioned);
  assert.throws(
    () =>
      validateDeploymentSnapshot(
        provisioned,
        value.expectation,
        callerExpectation()
      ),
    /AWS_ATTEST_FUNCTION_BINDING_AGENT/
  );
});

test("an old API deployment cannot be relabeled across a stack update", () => {
  const value = state("pre", "2026-08-02T04:00:00.000Z");
  const changed = structuredClone(value.snapshot);
  changed.stack.stackStatus = "UPDATE_COMPLETE";
  changed.stack.lastUpdatedAt = "2026-08-02T03:59:30.000Z";
  refreshFence(changed);

  assert.equal(
    changed.apiGateway.activeDeployment.deploymentId,
    API_DEPLOYMENT_ID
  );
  assert.equal(
    changed.apiGateway.activeDeployment.description,
    `ProofToAct exact API deployment ${SOURCE_COMMIT} ${value.expectation.configDigest}`
  );
  assert.throws(
    () =>
      validateDeploymentSnapshot(
        changed,
        value.expectation,
        callerExpectation()
      ),
    /AWS_ATTEST_STACK_BINDING/
  );
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
  assert.equal(receipt.controls.apiGatewayActiveDeploymentBound, true);
  assert.equal(receipt.controls.apiGatewayCensusBound, true);
  assert.equal(receipt.controls.apiGatewayIntegrationsBound, true);
  assert.equal(receipt.controls.apiGatewayRoutesBound, true);
  assert.equal(receipt.controls.primaryRuntimeRolePolicyCensus, true);
  assert.equal(receipt.controls.primaryRuntimeConfigurationsBound, true);
  assert.equal(receipt.controls.providerDependencyTreeBound, true);
  assert.equal(receipt.controls.provisionedConcurrencyAbsent, true);
  assert.equal(receipt.controls.revisionFencedSnapshots, true);
  assert.equal(receipt.controls.fullSignedInputsEmbedded, true);
  assert.equal(receipt.finalReleaseReady, false);

  for (const deniedAt of [
    preReceipt.observedAt,
    postReceipt.observationStartedAt
  ]) {
    assert.throws(
      () =>
        validateDeploymentAttestationPair({
          preReceipt,
          postReceipt,
          expectation: post.expectation,
          alternateDenial: signedAlternateDenial(
            post.expectation,
            deniedAt
          )
        }),
      /AWS_ATTEST_ALTERNATE_DENIAL_BINDING/
    );
  }

  const overlappingPost = state("post", "2026-08-02T04:00:00.500Z");
  assert.throws(
    () =>
      validateDeploymentAttestationPair({
        preReceipt,
        postReceipt: signedSnapshot(overlappingPost),
        expectation: overlappingPost.expectation,
        alternateDenial: signedAlternateDenial(
          overlappingPost.expectation,
          "2026-08-02T04:00:00.250Z"
        )
      }),
    /AWS_ATTEST_PAIR_TIME/
  );

  const signedPair = signDeploymentAttestationReceipt(
    receipt,
    RECEIPT_KEYS.post.privateKey,
    RECEIPT_KEYS.post.publicKey
  );
  assert.equal(
    validateSignedDeploymentAttestationPair(
      signedPair,
      post.expectation
    ),
    signedPair
  );
  const postKeyForgery = structuredClone(receipt);
  postKeyForgery.evidence.preReceipt.signature.value =
    RECEIPT_KEYS.post.publicKey.padEnd(88, "A").slice(0, 86) + "==";
  const forgedPair = signDeploymentAttestationReceipt(
    postKeyForgery,
    RECEIPT_KEYS.post.privateKey,
    RECEIPT_KEYS.post.publicKey
  );
  assert.throws(
    () =>
      validateSignedDeploymentAttestationPair(
        forgedPair,
        post.expectation
      ),
    /AWS_ATTEST_SNAPSHOT_SIGNATURE/
  );

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

  const substitutedExpectation = structuredClone(post.expectation);
  substitutedExpectation.functions.agent.timeout += 1;
  assert.throws(
    () => validateDeploymentAttestationPair({
      preReceipt,
      postReceipt,
      expectation: substitutedExpectation,
      alternateDenial: denial
    }),
    /AWS_ATTEST_SNAPSHOT_RECEIPT/
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
  assert.throws(
    () => signedSnapshot(replacedPost),
    /AWS_EVIDENCE_CALLER_ROLE_ID/
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
