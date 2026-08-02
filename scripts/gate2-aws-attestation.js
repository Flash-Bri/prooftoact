import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  DEPLOYMENT_API_INTEGRATIONS,
  DEPLOYMENT_API_ROUTE_KEYS,
  DEPLOYMENT_FUNCTIONS,
  deploymentAttestationDigest,
  deploymentStackParameterBindings,
  signDeploymentAttestationReceipt,
  validateDeploymentAttestationPair,
  validateDeploymentEvidenceBasis,
  validateDeploymentExpectation,
  validateDeploymentSnapshot,
  validateSignedDeploymentAttestationPair
} from "../src/cloud/aws-deployment-attestation.js";
import {
  assertAwsSdkEvidenceEnvironment,
  explicitAwsCredentials
} from "../src/cloud/aws-evidence-identity.js";
import { validateBuildReceipt } from "./gate2-aws-readiness.js";
import {
  exactBuildRecord,
  reproduceExactBuild,
  validateExactBuildReproduction
} from "./lib/exact-build-reproduction.js";
import { assertCleanExactGitCheckout } from "./lib/exact-git-source.js";
import { loadAwsProviderRuntime } from "./lib/aws-provider-runtime-loader.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const LOGICAL_TITLES = Object.freeze({
  agent: "Agent",
  authority: "Authority",
  boundary: "Boundary",
  demo: "Demo",
  signer: "Signer"
});
const ATTESTED_DRIFT_LOGICAL_IDS = Object.freeze(
  [
    "DefaultStage",
    "AuthoritySemanticFailureAlarm",
    "BoundarySemanticFailureAlarm",
    "DeploymentEvidenceAlternateRole",
    "DeploymentEvidenceRole",
    "HttpApi",
    ...Object.keys(DEPLOYMENT_API_ROUTE_KEYS),
    ...DEPLOYMENT_FUNCTIONS.flatMap((name) => {
      const title = LOGICAL_TITLES[name];
      return [
        `${title}Alias`,
        `${title}Function`,
        `${title}Role`,
        `${title}Version`
      ];
    })
  ].sort()
);
const CONDITIONAL_PROBE_LOGICAL_IDS = Object.freeze(
  [
    "CapabilityCanarySecret",
    ...["Agent", "Authority", "Boundary", "Demo", "Signer"].flatMap(
      (title) => [
        `${title}ProbeFunction`,
        `${title}ProbeLogGroup`,
        `${title}ProbeVersion`
      ]
    )
  ].sort()
);

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function readPrivateFile(filePath, code, { secret = false } = {}) {
  const resolved = path.resolve(process.cwd(), filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(
    stat.isFile() &&
      !stat.isSymbolicLink() &&
      stat.size > 0 &&
      stat.size <= 5 * 1024 * 1024 &&
      (!secret || (stat.mode & 0o077) === 0),
    code
  );
  const bytes = fs.readFileSync(resolved);
  return Object.freeze({ bytes, digest: sha256(bytes), path: resolved });
}

function readPrivateJson(filePath, code) {
  const record = readPrivateFile(filePath, code);
  try {
    return Object.freeze({
      ...record,
      value: JSON.parse(record.bytes.toString("utf8"))
    });
  } catch {
    throw new Error(code);
  }
}

function parseArguments(argv) {
  requireCondition(
    Array.isArray(argv) && argv.every((value) => typeof value === "string"),
    "AWS_ATTEST_ARGUMENTS"
  );
  const allowed = new Set([
    "--alternate-denial",
    "--build-receipt",
    "--configuration",
    "--expectation",
    "--phase",
    "--pre-receipt",
    "--receipt-key"
  ]);
  const parsed = {};
  requireCondition(argv.length % 2 === 0, "AWS_ATTEST_ARGUMENTS");
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition(
      allowed.has(name) &&
        typeof value === "string" &&
        value.length > 0 &&
        parsed[name] === undefined,
      "AWS_ATTEST_ARGUMENTS"
    );
    parsed[name] = value;
  }
  const phase = parsed["--phase"];
  for (const name of [
    "--build-receipt",
    "--configuration",
    "--expectation",
    "--receipt-key"
  ]) {
    requireCondition(parsed[name], "AWS_ATTEST_ARGUMENTS");
  }
  requireCondition(["pre", "post"].includes(phase), "AWS_ATTEST_ARGUMENTS");
  if (phase === "pre") {
    requireCondition(
      parsed["--pre-receipt"] === undefined &&
        parsed["--alternate-denial"] === undefined,
      "AWS_ATTEST_ARGUMENTS"
    );
  } else {
    requireCondition(
      parsed["--pre-receipt"] && parsed["--alternate-denial"],
      "AWS_ATTEST_ARGUMENTS"
    );
  }
  return Object.freeze({
    alternateDenialPath: parsed["--alternate-denial"],
    buildReceiptPath: parsed["--build-receipt"],
    configurationPath: parsed["--configuration"],
    expectationPath: parsed["--expectation"],
    phase,
    preReceiptPath: parsed["--pre-receipt"],
    receiptKeyPath: parsed["--receipt-key"]
  });
}

function exactOne(values, predicate, code) {
  const matches = (values ?? []).filter(predicate);
  requireCondition(matches.length === 1, code);
  return matches[0];
}

function roleName(roleArn) {
  const match = /:role\/([A-Za-z0-9+=,.@_-]{1,64})$/.exec(roleArn);
  requireCondition(match, "AWS_ATTEST_COLLECT_ROLE_ARN");
  return match[1];
}

function stackParameterCensus(stack, expected) {
  requireCondition(
    Array.isArray(stack.Parameters) &&
      stack.Parameters.length === Object.keys(expected).length,
    "AWS_ATTEST_COLLECT_PARAMETERS"
  );
  const actual = {};
  for (const candidate of stack.Parameters) {
    requireCondition(
      candidate &&
        typeof candidate.ParameterKey === "string" &&
        typeof candidate.ParameterValue === "string" &&
        actual[candidate.ParameterKey] === undefined,
      "AWS_ATTEST_COLLECT_PARAMETERS"
    );
    actual[candidate.ParameterKey] = candidate.ParameterValue;
  }
  const sorted = Object.fromEntries(
    Object.entries(actual).sort(([left], [right]) =>
      left.localeCompare(right)
    )
  );
  requireCondition(
    JSON.stringify(sorted) === JSON.stringify(expected),
    "AWS_ATTEST_COLLECT_PARAMETERS"
  );
  return Object.freeze({
    parameterCount: Object.keys(sorted).length,
    parametersDigest: deploymentAttestationDigest(sorted)
  });
}

function parsedTemplateBody(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      requireCondition(
        parsed && typeof parsed === "object" && !Array.isArray(parsed),
        "AWS_ATTEST_COLLECT_TEMPLATE"
      );
      return parsed;
    } catch (error) {
      if (error?.message === "AWS_ATTEST_COLLECT_TEMPLATE") {
        throw error;
      }
    }
  }
  throw new Error("AWS_ATTEST_COLLECT_TEMPLATE");
}

function driftFor(resourceDrifts, logicalResourceId) {
  const drift = exactOne(
    resourceDrifts,
    (candidate) => candidate.LogicalResourceId === logicalResourceId,
    `AWS_ATTEST_COLLECT_DRIFT_${logicalResourceId.toUpperCase()}`
  );
  return drift.StackResourceDriftStatus;
}

function stackResourceBinding(
  stackResources,
  logicalResourceId,
  resourceType,
  physicalResourceId
) {
  const resource = exactOne(
    stackResources,
    (candidate) => candidate.LogicalResourceId === logicalResourceId,
    "AWS_ATTEST_COLLECT_STACK_RESOURCE"
  );
  requireCondition(
    resource.ResourceType === resourceType &&
      resource.PhysicalResourceId === physicalResourceId &&
      resource.ResourceStatus === "CREATE_COMPLETE",
    "AWS_ATTEST_COLLECT_STACK_RESOURCE_BINDING"
  );
  return Object.freeze({
    physicalResourceId: resource.PhysicalResourceId,
    resourceStatus: resource.ResourceStatus,
    resourceType: resource.ResourceType
  });
}

function stackResourceBindings(expectation, stackResources) {
  const bindings = {};
  for (const name of DEPLOYMENT_FUNCTIONS) {
    const title = LOGICAL_TITLES[name];
    const expected = expectation.functions[name];
    bindings[`${title}Alias`] = stackResourceBinding(
      stackResources,
      `${title}Alias`,
      "AWS::Lambda::Alias",
      expected.aliasArn
    );
    bindings[`${title}Function`] = stackResourceBinding(
      stackResources,
      `${title}Function`,
      "AWS::Lambda::Function",
      expected.functionName
    );
    bindings[`${title}Role`] = stackResourceBinding(
      stackResources,
      `${title}Role`,
      "AWS::IAM::Role",
      roleName(expected.roleArn)
    );
    bindings[`${title}Version`] = stackResourceBinding(
      stackResources,
      `${title}Version`,
      "AWS::Lambda::Version",
      expected.numericVersionArn
    );
  }
  bindings.DeploymentEvidenceAlternateRole = stackResourceBinding(
    stackResources,
    "DeploymentEvidenceAlternateRole",
    "AWS::IAM::Role",
    roleName(expectation.alternatePrincipal.roleArn)
  );
  bindings.DeploymentEvidenceRole = stackResourceBinding(
    stackResources,
    "DeploymentEvidenceRole",
    "AWS::IAM::Role",
    roleName(expectation.evidenceOperator.roleArn)
  );
  return Object.freeze(
    Object.fromEntries(
      Object.entries(bindings).sort(([left], [right]) =>
        left.localeCompare(right)
      )
    )
  );
}

function stackHttpApiId(stackResources) {
  const resource = exactOne(
    stackResources,
    (candidate) => candidate.LogicalResourceId === "HttpApi",
    "AWS_ATTEST_COLLECT_HTTP_API"
  );
  requireCondition(
    resource.ResourceType === "AWS::ApiGatewayV2::Api" &&
      resource.ResourceStatus === "CREATE_COMPLETE" &&
      /^[a-z0-9]{10}$/.test(resource.PhysicalResourceId),
    "AWS_ATTEST_COLLECT_HTTP_API"
  );
  return resource.PhysicalResourceId;
}

function generatedStackResourceBinding(
  stackResources,
  logicalResourceId,
  resourceType,
  physicalPattern
) {
  const resource = exactOne(
    stackResources,
    (candidate) => candidate.LogicalResourceId === logicalResourceId,
    "AWS_ATTEST_COLLECT_API_RESOURCE"
  );
  requireCondition(
    resource.ResourceType === resourceType &&
      resource.ResourceStatus === "CREATE_COMPLETE" &&
      physicalPattern.test(resource.PhysicalResourceId ?? ""),
    "AWS_ATTEST_COLLECT_API_RESOURCE_BINDING"
  );
  return Object.freeze({
    physicalResourceId: resource.PhysicalResourceId,
    resourceStatus: resource.ResourceStatus,
    resourceType: resource.ResourceType
  });
}

function stackApiGatewayBindings(stackResources) {
  const bindings = {
    ApiAccessLogGroup: generatedStackResourceBinding(
      stackResources,
      "ApiAccessLogGroup",
      "AWS::Logs::LogGroup",
      /^[A-Za-z0-9._/#-]{1,512}$/
    ),
    ApiDeployment: generatedStackResourceBinding(
      stackResources,
      "ApiDeployment",
      "AWS::ApiGatewayV2::Deployment",
      /^[a-z0-9]{1,64}$/
    ),
    DefaultStage: generatedStackResourceBinding(
      stackResources,
      "DefaultStage",
      "AWS::ApiGatewayV2::Stage",
      /^\$default$/
    ),
    HttpApi: generatedStackResourceBinding(
      stackResources,
      "HttpApi",
      "AWS::ApiGatewayV2::Api",
      /^[a-z0-9]{10}$/
    )
  };
  for (const logicalResourceId of Object.keys(
    DEPLOYMENT_API_INTEGRATIONS
  )) {
    bindings[logicalResourceId] = generatedStackResourceBinding(
      stackResources,
      logicalResourceId,
      "AWS::ApiGatewayV2::Integration",
      /^[a-z0-9]{1,64}$/
    );
  }
  for (const logicalResourceId of Object.keys(DEPLOYMENT_API_ROUTE_KEYS)) {
    bindings[logicalResourceId] = generatedStackResourceBinding(
      stackResources,
      logicalResourceId,
      "AWS::ApiGatewayV2::Route",
      /^[a-z0-9]{1,64}$/
    );
  }
  return Object.freeze(
    Object.fromEntries(
      Object.entries(bindings).sort(([left], [right]) =>
        left.localeCompare(right)
      )
    )
  );
}

function sortedStringMap(value) {
  return Object.fromEntries(
    Object.entries(value ?? {})
      .map(([key, candidate]) => [key, String(candidate)])
      .sort(([left], [right]) => left.localeCompare(right))
  );
}

function sortedJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortedJsonValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .map(([key, candidate]) => [key, sortedJsonValue(candidate)])
        .sort(([left], [right]) => left.localeCompare(right))
    );
  }
  return value;
}

function normalizedRouteSettings(value) {
  return {
    dataTraceEnabled: value?.DataTraceEnabled ?? false,
    detailedMetricsEnabled: value?.DetailedMetricsEnabled ?? false,
    loggingLevel: value?.LoggingLevel ?? null,
    throttlingBurstLimit: value?.ThrottlingBurstLimit ?? null,
    throttlingRateLimit: value?.ThrottlingRateLimit ?? null
  };
}

function normalizedApiIntegration(value) {
  return {
    apiGatewayManaged: value.ApiGatewayManaged ?? false,
    connectionType: value.ConnectionType ?? null,
    connectionId: value.ConnectionId ?? null,
    contentHandlingStrategy: value.ContentHandlingStrategy ?? null,
    credentialsArn: value.CredentialsArn ?? null,
    description: value.Description ?? "",
    integrationId: value.IntegrationId,
    integrationMethod: value.IntegrationMethod ?? null,
    integrationResponseSelectionExpression:
      value.IntegrationResponseSelectionExpression ?? null,
    integrationSubtype: value.IntegrationSubtype ?? null,
    integrationType: value.IntegrationType,
    integrationUri: value.IntegrationUri,
    passthroughBehavior: value.PassthroughBehavior ?? null,
    payloadFormatVersion: value.PayloadFormatVersion ?? null,
    requestParameters: sortedJsonValue(value.RequestParameters ?? {}),
    requestTemplates: sortedJsonValue(value.RequestTemplates ?? {}),
    responseParameters: sortedJsonValue(value.ResponseParameters ?? {}),
    templateSelectionExpression: value.TemplateSelectionExpression ?? null,
    timeoutInMillis: value.TimeoutInMillis ?? null,
    tlsConfig: value.TlsConfig ?? null
  };
}

function normalizedApiRoute(value) {
  return {
    apiKeyRequired: value.ApiKeyRequired ?? false,
    authorizationScopes: [...(value.AuthorizationScopes ?? [])].sort(),
    authorizationType: value.AuthorizationType,
    authorizerId: value.AuthorizerId ?? null,
    modelSelectionExpression: value.ModelSelectionExpression ?? null,
    operationName: value.OperationName ?? "",
    requestModels: sortedJsonValue(value.RequestModels ?? {}),
    requestParameters: sortedJsonValue(value.RequestParameters ?? {}),
    routeResponseSelectionExpression:
      value.RouteResponseSelectionExpression ?? null,
    routeId: value.RouteId,
    routeKey: value.RouteKey,
    target: value.Target
  };
}

function normalizedApiDeployment(value, { includeDetail = false } = {}) {
  const createdAt = new Date(value.CreatedDate);
  requireCondition(
    typeof value.DeploymentId === "string" &&
      !Number.isNaN(createdAt.getTime()),
    "AWS_ATTEST_COLLECT_API_DEPLOYMENT"
  );
  return {
    autoDeployed: value.AutoDeployed ?? false,
    createdAt: createdAt.toISOString(),
    deploymentId: value.DeploymentId,
    deploymentStatus: value.DeploymentStatus ?? null,
    ...(includeDetail
      ? {
          deploymentStatusMessage:
            value.DeploymentStatusMessage ?? "",
          description: value.Description ?? ""
        }
      : {})
  };
}

async function apiDeploymentCensus(provider, apiId) {
  const items = [];
  const seenTokens = new Set();
  let nextToken;
  for (let page = 0; page < 100; page += 1) {
    const response = await provider.getDeployments(apiId, nextToken);
    requireCondition(
      response && Array.isArray(response.Items),
      "AWS_ATTEST_COLLECT_API_DEPLOYMENT_CENSUS"
    );
    items.push(...response.Items.map((item) => normalizedApiDeployment(item)));
    if (response.NextToken === undefined) {
      return items.sort((left, right) =>
        left.createdAt.localeCompare(right.createdAt) ||
        left.deploymentId.localeCompare(right.deploymentId)
      );
    }
    requireCondition(
      typeof response.NextToken === "string" &&
        response.NextToken.length > 0 &&
        !seenTokens.has(response.NextToken),
      "AWS_ATTEST_COLLECT_API_DEPLOYMENT_CENSUS"
    );
    seenTokens.add(response.NextToken);
    nextToken = response.NextToken;
  }
  throw new Error("AWS_ATTEST_COLLECT_API_DEPLOYMENT_CENSUS");
}

async function apiGatewaySnapshot(
  provider,
  stackResources,
  resourceDrifts
) {
  const bindings = stackApiGatewayBindings(stackResources);
  const apiId = bindings.HttpApi.physicalResourceId;
  const [api, integrationCensus, routeCensus, stageCensus, stage] =
    await Promise.all([
      provider.getApi(apiId),
      provider.getIntegrations(apiId),
      provider.getRoutes(apiId),
      provider.getStages(apiId),
      provider.getStage(apiId, "$default")
    ]);
  requireCondition(
    integrationCensus.NextToken === undefined &&
      routeCensus.NextToken === undefined &&
      stageCensus.NextToken === undefined &&
      Array.isArray(integrationCensus.Items) &&
      Array.isArray(routeCensus.Items) &&
      Array.isArray(stageCensus.Items),
    "AWS_ATTEST_COLLECT_API_CENSUS"
  );
  const integrationEntries = await Promise.all(
    Object.entries(DEPLOYMENT_API_INTEGRATIONS).map(
      async ([logicalResourceId]) => {
        const physicalResourceId =
          bindings[logicalResourceId].physicalResourceId;
        return [
          logicalResourceId,
          {
            ...normalizedApiIntegration(
              await provider.getIntegration(apiId, physicalResourceId)
            )
          }
        ];
      }
    )
  );
  const routeEntries = await Promise.all(
    Object.entries(DEPLOYMENT_API_ROUTE_KEYS).map(
      async ([logicalResourceId]) => {
        const physicalResourceId =
          bindings[logicalResourceId].physicalResourceId;
        return [
          logicalResourceId,
          {
            ...normalizedApiRoute(
              await provider.getRoute(apiId, physicalResourceId)
            ),
            resourceDrift: driftFor(resourceDrifts, logicalResourceId)
          }
        ];
      }
    )
  );
  requireCondition(
    typeof stage.DeploymentId === "string" && stage.DeploymentId.length > 0,
    "AWS_ATTEST_COLLECT_API_DEPLOYMENT"
  );
  const [activeDeployment, deployments] = await Promise.all([
    provider.getDeployment(apiId, stage.DeploymentId),
    apiDeploymentCensus(provider, apiId)
  ]);
  return {
    activeDeployment: normalizedApiDeployment(activeDeployment, {
      includeDetail: true
    }),
    api: {
      apiGatewayManaged: api.ApiGatewayManaged ?? false,
      apiKeySelectionExpression: api.ApiKeySelectionExpression ?? null,
      apiEndpoint: api.ApiEndpoint,
      apiId: api.ApiId,
      corsConfiguration: sortedJsonValue(api.CorsConfiguration ?? {}),
      description: api.Description ?? "",
      disableExecuteApiEndpoint: api.DisableExecuteApiEndpoint ?? false,
      disableSchemaValidation: api.DisableSchemaValidation ?? false,
      importInfo: [...(api.ImportInfo ?? [])].sort(),
      ipAddressType: api.IpAddressType ?? null,
      name: api.Name,
      protocolType: api.ProtocolType,
      resourceDrift: driftFor(resourceDrifts, "HttpApi"),
      routeSelectionExpression: api.RouteSelectionExpression,
      tags: sortedStringMap(api.Tags),
      version: api.Version ?? "",
      warnings: [...(api.Warnings ?? [])].sort()
    },
    census: {
      deployments,
      integrationIds: integrationCensus.Items.map(
        (candidate) => candidate.IntegrationId
      ).sort(),
      routeIds: routeCensus.Items.map((candidate) => candidate.RouteId).sort(),
      stageNames: stageCensus.Items.map((candidate) => candidate.StageName).sort()
    },
    integrations: Object.fromEntries(
      integrationEntries.sort(([left], [right]) => left.localeCompare(right))
    ),
    routes: Object.fromEntries(
      routeEntries.sort(([left], [right]) => left.localeCompare(right))
    ),
    stage: {
      accessLogSettings: {
        destinationArn: stage.AccessLogSettings?.DestinationArn ?? null,
        format: stage.AccessLogSettings?.Format ?? null
      },
      autoDeploy: stage.AutoDeploy ?? false,
      clientCertificateId: stage.ClientCertificateId ?? null,
      defaultRouteSettings: normalizedRouteSettings(
        stage.DefaultRouteSettings
      ),
      deploymentId: stage.DeploymentId ?? null,
      description: stage.Description ?? "",
      lastDeploymentStatusMessage:
        stage.LastDeploymentStatusMessage ?? "",
      resourceDrift: driftFor(resourceDrifts, "DefaultStage"),
      routeSettings: Object.fromEntries(
        Object.entries(stage.RouteSettings ?? {})
          .map(([routeKey, settings]) => [
            routeKey,
            normalizedRouteSettings(settings)
          ])
          .sort(([left], [right]) => left.localeCompare(right))
      ),
      stageName: stage.StageName,
      stageVariables: sortedStringMap(stage.StageVariables),
      tags: sortedStringMap(stage.Tags)
    },
    stackResourceBindings: bindings
  };
}

async function freshDrift(provider, stackName, deadlineMs) {
  const started = await provider.detectStackDrift(
    stackName,
    ATTESTED_DRIFT_LOGICAL_IDS
  );
  const detectionId = started.StackDriftDetectionId;
  requireCondition(
    typeof detectionId === "string" && detectionId.length >= 20,
    "AWS_ATTEST_COLLECT_DRIFT_ID"
  );
  while (Date.now() < deadlineMs) {
    const result = await provider.describeStackDriftDetectionStatus(
      detectionId
    );
    if (result.DetectionStatus === "DETECTION_COMPLETE") {
      requireCondition(
        result.StackDriftStatus === "IN_SYNC",
        "AWS_ATTEST_COLLECT_STACK_DRIFT"
      );
      return result.StackDriftStatus;
    }
    requireCondition(
      result.DetectionStatus === "DETECTION_IN_PROGRESS",
      "AWS_ATTEST_COLLECT_DRIFT_STATUS"
    );
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(2_000, Math.max(1, deadlineMs - Date.now())))
    );
  }
  throw new Error("AWS_ATTEST_COLLECT_DRIFT_TIMEOUT");
}

async function roleSnapshot(provider, roleArn, resourceDrift) {
  const name = roleName(roleArn);
  const role = (await provider.getRole(name)).Role;
  const inline = await provider.listRolePolicies(name);
  const attached = await provider.listAttachedRolePolicies(name);
  const tags = await provider.listRoleTags(name);
  requireCondition(
    inline.IsTruncated !== true &&
      inline.Marker === undefined &&
      attached.IsTruncated !== true &&
      attached.Marker === undefined &&
      tags.IsTruncated !== true &&
      tags.Marker === undefined &&
      Array.isArray(inline.PolicyNames) &&
      inline.PolicyNames.length <= 16 &&
      Array.isArray(attached.AttachedPolicies) &&
      attached.AttachedPolicies.length <= 16,
    "AWS_ATTEST_COLLECT_ROLE_CENSUS"
  );
  return {
    arn: role.Arn,
    attachedManagedPolicies: attached.AttachedPolicies.map((policy) => ({
      policyArn: policy.PolicyArn,
      policyName: policy.PolicyName
    })).sort((left, right) => left.policyArn.localeCompare(right.policyArn)),
    inlinePolicies: (
      await Promise.all(
        inline.PolicyNames.map(async (policyName) => ({
          document: (
            await provider.getRolePolicy(name, policyName)
          ).PolicyDocument,
          name: policyName
        }))
      )
    ).sort((left, right) => left.name.localeCompare(right.name)),
    maxSessionDuration: role.MaxSessionDuration,
    permissionsBoundary: role.PermissionsBoundary
      ? {
          arn: role.PermissionsBoundary.PermissionsBoundaryArn,
          type: role.PermissionsBoundary.PermissionsBoundaryType
        }
      : null,
    resourceDrift,
    roleId: role.RoleId,
    tags: (tags.Tags ?? [])
      .map((tag) => ({ key: tag.Key, value: tag.Value }))
      .sort((left, right) => left.key.localeCompare(right.key)),
    trustPolicy: role.AssumeRolePolicyDocument
  };
}

function normalizedFunctionConfiguration(configuration) {
  return {
    architectures: configuration.Architectures ?? [],
    deadLetterTargetArn: configuration.DeadLetterConfig?.TargetArn ?? null,
    environment: configuration.Environment?.Variables ?? {},
    ephemeralStorageSize: configuration.EphemeralStorage?.Size ?? null,
    fileSystemConfigs: (configuration.FileSystemConfigs ?? [])
      .map((item) => ({ arn: item.Arn, localMountPath: item.LocalMountPath }))
      .sort((left, right) => left.arn.localeCompare(right.arn)),
    handler: configuration.Handler,
    kmsKeyArn: configuration.KMSKeyArn ?? null,
    layers: (configuration.Layers ?? [])
      .map((layer) => ({ arn: layer.Arn, codeSize: layer.CodeSize }))
      .sort((left, right) => left.arn.localeCompare(right.arn)),
    loggingConfig: {
      applicationLogLevel:
        configuration.LoggingConfig?.ApplicationLogLevel ?? null,
      logFormat: configuration.LoggingConfig?.LogFormat ?? null,
      logGroup: configuration.LoggingConfig?.LogGroup ?? null,
      systemLogLevel: configuration.LoggingConfig?.SystemLogLevel ?? null
    },
    memorySize: configuration.MemorySize,
    packageType: configuration.PackageType,
    runtime: configuration.Runtime,
    runtimeVersion: {
      errorCode: configuration.RuntimeVersionConfig?.Error?.ErrorCode ?? null,
      errorMessage:
        configuration.RuntimeVersionConfig?.Error?.Message ?? null,
      runtimeVersionArn:
        configuration.RuntimeVersionConfig?.RuntimeVersionArn ?? null
    },
    signingJobArn: configuration.SigningJobArn ?? null,
    signingProfileVersionArn:
      configuration.SigningProfileVersionArn ?? null,
    snapStartApplyOn: configuration.SnapStart?.ApplyOn ?? "None",
    timeout: configuration.Timeout,
    tracingMode: configuration.TracingConfig?.Mode ?? null,
    vpcConfig: {
      ipv6AllowedForDualStack:
        configuration.VpcConfig?.Ipv6AllowedForDualStack ?? false,
      securityGroupIds: [...(configuration.VpcConfig?.SecurityGroupIds ?? [])]
        .sort(),
      subnetIds: [...(configuration.VpcConfig?.SubnetIds ?? [])].sort(),
      vpcId: configuration.VpcConfig?.VpcId ?? null
    }
  };
}

async function functionSnapshot(provider, name, expected, resourceDrifts) {
  const title = LOGICAL_TITLES[name];
  const [
    configuration,
    concurrency,
    provisioned,
    alias,
    codeSigningConfig,
    recursionConfig,
    runtimeManagementConfig,
    unqualifiedPolicy,
    numericPolicy,
    aliasPolicy,
    aliases,
    eventSourceMappings,
    functionUrlConfigs,
    tags
  ] = await Promise.all([
    provider.getFunctionConfiguration(expected.numericVersionArn),
    provider.getFunctionConcurrency(expected.functionName),
    provider.listProvisionedConcurrencyConfigs(expected.functionName),
    provider.getAlias(expected.functionName, "proof"),
    provider.getFunctionCodeSigningConfig(expected.functionName),
    provider.getFunctionRecursionConfig(expected.functionName),
    provider.getRuntimeManagementConfig(
      expected.functionName,
      expected.numericVersion
    ),
    provider.getFunctionPolicy(expected.functionName),
    provider.getFunctionPolicy(
      expected.functionName,
      expected.numericVersion
    ),
    provider.getFunctionPolicy(expected.functionName, "proof"),
    provider.listAliases(expected.functionName),
    provider.listEventSourceMappings(expected.functionName),
    provider.listFunctionUrlConfigs(expected.functionName),
    provider.listTags(expected.functionArn)
  ]);
  requireCondition(
    provisioned.NextMarker === undefined &&
      Array.isArray(provisioned.ProvisionedConcurrencyConfigs),
    "AWS_ATTEST_COLLECT_PROVISIONED_CONCURRENCY"
  );
  requireCondition(
    aliases.NextMarker === undefined &&
      eventSourceMappings.NextMarker === undefined &&
      functionUrlConfigs.NextMarker === undefined &&
      Array.isArray(aliases.Aliases) &&
      Array.isArray(eventSourceMappings.EventSourceMappings) &&
      Array.isArray(functionUrlConfigs.FunctionUrlConfigs),
    "AWS_ATTEST_COLLECT_LAMBDA_INGRESS_CENSUS"
  );
  return {
    aliases: aliases.Aliases.map((candidate) => ({
      aliasArn: candidate.AliasArn,
      description: candidate.Description ?? "",
      functionVersion: candidate.FunctionVersion,
      name: candidate.Name,
      revisionId: candidate.RevisionId,
      routingConfiguration: candidate.RoutingConfig ?? {}
    })).sort((left, right) => left.name.localeCompare(right.name)),
    aliasArn: alias.AliasArn,
    aliasName: alias.Name,
    aliasRevisionId: alias.RevisionId,
    aliasRoutingConfiguration: alias.RoutingConfig ?? {},
    aliasTargetVersion: alias.FunctionVersion,
    codeSha256: configuration.CodeSha256,
    codeSigningConfig,
    configuration: normalizedFunctionConfiguration(configuration),
    functionArn: expected.functionArn,
    functionName: configuration.FunctionName,
    functionTags: Object.fromEntries(
      Object.entries(tags.Tags ?? {}).sort(([left], [right]) =>
        left.localeCompare(right)
      )
    ),
    functionUrlConfigs: functionUrlConfigs.FunctionUrlConfigs,
    lastUpdateStatus: configuration.LastUpdateStatus,
    numericRevisionId: configuration.RevisionId,
    numericVersion: configuration.Version,
    numericVersionArn: configuration.FunctionArn,
    eventSourceMappings: eventSourceMappings.EventSourceMappings,
    provisionedConcurrencyConfigurations:
      provisioned.ProvisionedConcurrencyConfigs,
    recursionConfig,
    reservedConcurrency: concurrency.ReservedConcurrentExecutions,
    resourceDrift: {
      alias: driftFor(resourceDrifts, `${title}Alias`),
      function: driftFor(resourceDrifts, `${title}Function`),
      role: driftFor(resourceDrifts, `${title}Role`),
      version: driftFor(resourceDrifts, `${title}Version`)
    },
    resourcePolicies: {
      alias: aliasPolicy,
      numeric: numericPolicy,
      unqualified: unqualifiedPolicy
    },
    role: await roleSnapshot(
      provider,
      configuration.Role,
      driftFor(resourceDrifts, `${title}Role`)
    ),
    runtimeManagementConfig,
    state: configuration.State
  };
}

async function collectState(
  provider,
  expectation,
  deadlineMs,
  expectedStackParameters
) {
  const stackResponse = await provider.describeStacks(expectation.stackName);
  const stack = exactOne(
    stackResponse.Stacks,
    (candidate) => candidate.StackId === expectation.stackId,
    "AWS_ATTEST_COLLECT_STACK"
  );
  const stackCreatedAt = new Date(stack.CreationTime);
  const stackLastUpdatedAt =
    stack.LastUpdatedTime === undefined
      ? null
      : new Date(stack.LastUpdatedTime);
  requireCondition(
    !Number.isNaN(stackCreatedAt.getTime()) &&
      (stackLastUpdatedAt === null ||
        !Number.isNaN(stackLastUpdatedAt.getTime())),
    "AWS_ATTEST_COLLECT_STACK_TIME"
  );
  const driftStatus = await freshDrift(
    provider,
    expectation.stackName,
    deadlineMs
  );
  const driftResponse = await provider.describeStackResourceDrifts(
    expectation.stackName
  );
  const template = await provider.getTemplate(expectation.stackName);
  const stackResources = await provider.describeStackResources(
    expectation.stackName
  );
  requireCondition(
    driftResponse.NextToken === undefined &&
      stackResources.NextToken === undefined,
    "AWS_ATTEST_COLLECT_PAGINATION"
  );
  requireCondition(
    (stackResources.StackResources ?? []).every(
      (candidate) =>
        !CONDITIONAL_PROBE_LOGICAL_IDS.includes(candidate.LogicalResourceId)
    ),
    "AWS_ATTEST_COLLECT_PROBE_RESOURCES"
  );
  const resourceDrifts = driftResponse.StackResourceDrifts ?? [];
  const attestedResourceDrifts = resourceDrifts.filter((candidate) =>
    ATTESTED_DRIFT_LOGICAL_IDS.includes(candidate.LogicalResourceId)
  );
  requireCondition(
    attestedResourceDrifts.length === ATTESTED_DRIFT_LOGICAL_IDS.length &&
      new Set(
        attestedResourceDrifts.map((candidate) => candidate.LogicalResourceId)
      ).size === ATTESTED_DRIFT_LOGICAL_IDS.length,
    "AWS_ATTEST_COLLECT_DRIFT_SCOPE"
  );
  const parameterCensus = stackParameterCensus(
    stack,
    expectedStackParameters
  );
  const apiGateway = await apiGatewaySnapshot(
    provider,
    stackResources.StackResources ?? [],
    attestedResourceDrifts
  );
  return {
    alternatePrincipalRole: await roleSnapshot(
      provider,
      expectation.alternatePrincipal.roleArn,
      driftFor(attestedResourceDrifts, "DeploymentEvidenceAlternateRole")
    ),
    apiGateway,
    callerIdentity: await provider.callerIdentity(),
    evidenceOperatorRole: await roleSnapshot(
      provider,
      expectation.evidenceOperator.roleArn,
      driftFor(attestedResourceDrifts, "DeploymentEvidenceRole")
    ),
    functions: Object.fromEntries(
      await Promise.all(
        DEPLOYMENT_FUNCTIONS.map(async (name) => [
          name,
          await functionSnapshot(
            provider,
            name,
            expectation.functions[name],
            attestedResourceDrifts
          )
        ])
      )
    ),
    region: expectation.region,
    stack: {
      bindings: {
        configDigest: expectedStackParameters.ConfigDigest,
        probesEnabled: expectedStackParameters.EnableProbeFunctions,
        sourceCommit: expectedStackParameters.SourceCommit,
        treeDigest: expectedStackParameters.TreeDigest
      },
      cloudFormationServiceRoleArn: stack.RoleARN ?? null,
      createdAt: stackCreatedAt.toISOString(),
      driftStatus,
      httpApiId: apiGateway.api.apiId,
      ...parameterCensus,
      semanticAlarmDrift: {
        authority: driftFor(
          attestedResourceDrifts,
          "AuthoritySemanticFailureAlarm"
        ),
        boundary: driftFor(
          attestedResourceDrifts,
          "BoundarySemanticFailureAlarm"
        )
      },
      resourceBindings: stackResourceBindings(
        expectation,
        stackResources.StackResources ?? []
      ),
      stackId: stack.StackId,
      lastUpdatedAt:
        stackLastUpdatedAt === null
          ? null
          : stackLastUpdatedAt.toISOString(),
      stackName: stack.StackName,
      stackStatus: stack.StackStatus,
      templateCanonicalDigest: deploymentAttestationDigest(
        parsedTemplateBody(template.TemplateBody)
      )
    }
  };
}

async function collectSnapshot(
  provider,
  expectation,
  phase,
  providerDependencyTreeDigest,
  providerRuntimeSha256,
  expectedStackParameters
) {
  const startedAt = new Date().toISOString();
  const deadlineMs = Date.now() + 9 * 60 * 1_000;
  const first = {
    ...(await collectState(
      provider,
      expectation,
      deadlineMs,
      expectedStackParameters
    )),
    providerDependencyTreeDigest,
    providerRuntimeSha256
  };
  const firstStateDigest = deploymentAttestationDigest(first);
  const second = {
    ...(await collectState(
      provider,
      expectation,
      deadlineMs,
      expectedStackParameters
    )),
    providerDependencyTreeDigest,
    providerRuntimeSha256
  };
  const secondStateDigest = deploymentAttestationDigest(second);
  requireCondition(
    firstStateDigest === secondStateDigest,
    "AWS_ATTEST_COLLECT_REVISION_FENCE"
  );
  const completedAt = new Date().toISOString();
  return {
    ...second,
    observationFence: {
      completedAt,
      firstStateDigest,
      secondStateDigest,
      startedAt
    },
    observedAt: completedAt,
    phase
  };
}

export function safeAwsAttestationFailureCode(error) {
  const candidate = String(error?.message ?? "");
  return /^AWS_ATTEST_[A-Z0-9_]{1,120}$/.test(candidate)
    ? candidate
    : "AWS_ATTEST_UNKNOWN";
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  assertAwsSdkEvidenceEnvironment(process.env);
  const expectationRecord = readPrivateJson(
    options.expectationPath,
    "AWS_ATTEST_EXPECTATION_FILE"
  );
  const configurationRecord = readPrivateJson(
    options.configurationPath,
    "AWS_ATTEST_CONFIGURATION_FILE"
  );
  const buildRecord = readPrivateJson(
    options.buildReceiptPath,
    "AWS_ATTEST_BUILD_RECEIPT_FILE"
  );
  const keyRecord = readPrivateFile(
    options.receiptKeyPath,
    "AWS_ATTEST_RECEIPT_KEY_FILE",
    { secret: true }
  );
  const expectation = validateDeploymentExpectation(expectationRecord.value);
  assertCleanExactGitCheckout({
    rootDir: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  const reproducedBuild = reproduceExactBuild({ projectRoot: root });
  validateBuildReceipt(buildRecord.value, {
    projectRoot: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  validateBuildReceipt(reproducedBuild.value, {
    projectRoot: root,
    sourceCommit: expectation.sourceCommit,
    treeDigest: expectation.treeDigest
  });
  validateExactBuildReproduction(buildRecord, reproducedBuild);
  validateDeploymentEvidenceBasis({
    expectation,
    configuration: configurationRecord.value,
    buildReceipt: buildRecord.value,
    configurationSha256: configurationRecord.digest,
    buildReceiptSha256: buildRecord.digest
  });
  const providerRuntime = await loadAwsProviderRuntime({
    buildReceipt: buildRecord.value,
    projectRoot: root
  });
  const { createAwsProviderClients } = providerRuntime;
  const provider = await createAwsProviderClients({
    credentials: explicitAwsCredentials(process.env, {
      requireSessionToken: true
    }),
    region: expectation.region
  });
  const expectedCallerArn =
    process.env.AWS_EVIDENCE_EXPECTED_ATTESTATION_CALLER_ARN;
  const expectedCallerUserId =
    process.env.AWS_EVIDENCE_EXPECTED_ATTESTATION_CALLER_USER_ID;
  const snapshot = await collectSnapshot(
    provider,
    expectation,
    options.phase,
    buildRecord.value.dependencySnapshot.treeDigest,
    providerRuntime.runtimeSha256,
    deploymentStackParameterBindings(configurationRecord.value)
  );
  const callerExpectation = {
    expectedCallerArn,
    expectedCallerUserId
  };
  const unsignedSnapshotReceipt = validateDeploymentSnapshot(
    snapshot,
    expectation,
    callerExpectation
  );
  const signedSnapshotReceipt = signDeploymentAttestationReceipt(
    unsignedSnapshotReceipt,
    keyRecord.bytes,
    expectation.receiptPublicKeys[options.phase]
  );
  let receipt = signedSnapshotReceipt;
  if (options.phase === "post") {
    const pair = validateDeploymentAttestationPair({
      preReceipt: readPrivateJson(
        options.preReceiptPath,
        "AWS_ATTEST_PRE_RECEIPT_FILE"
      ).value,
      postReceipt: signedSnapshotReceipt,
      expectation,
      alternateDenial: readPrivateJson(
        options.alternateDenialPath,
        "AWS_ATTEST_ALTERNATE_DENIAL_FILE"
      ).value
    });
    receipt = signDeploymentAttestationReceipt(
      pair,
      keyRecord.bytes,
      expectation.receiptPublicKeys.post
    );
    validateSignedDeploymentAttestationPair(receipt, expectation);
  }
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion: "tideproof.gate2.aws-deployment-attestation-error.v2",
        status: "FAIL",
        code: safeAwsAttestationFailureCode(error)
      })}\n`
    );
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  ATTESTED_DRIFT_LOGICAL_IDS,
  collectSnapshot,
  exactBuildRecord,
  normalizedFunctionConfiguration,
  parseArguments,
  parsedTemplateBody,
  validateExactBuildReproduction,
  roleName,
  roleSnapshot,
  apiGatewaySnapshot,
  stackApiGatewayBindings,
  stackHttpApiId,
  stackParameterCensus,
  stackResourceBindings
});
