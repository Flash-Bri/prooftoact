import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  CloudFormationClient,
  DescribeStackResourcesCommand,
  DescribeStacksCommand,
  GetTemplateCommand
} from "@aws-sdk/client-cloudformation";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import {
  GetRoleCommand,
  GetRolePolicyCommand,
  IAMClient,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
  ListRoleTagsCommand
} from "@aws-sdk/client-iam";
import {
  GetFunctionCommand,
  GetFunctionConcurrencyCommand,
  GetFunctionConfigurationCommand,
  GetPolicyCommand,
  LambdaClient,
  ListEventSourceMappingsCommand,
  ListFunctionUrlConfigsCommand
} from "@aws-sdk/client-lambda";
import {
  DescribeSecretCommand,
  SecretsManagerClient
} from "@aws-sdk/client-secrets-manager";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { NodeHttpHandler } from "@smithy/node-http-handler";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import { decodePolicyDocument } from "./lib/aws-provider-runtime.js";
import {
  signPrivateRecoveryDeploymentEvidence,
  validatePrivateRecoveryEvidenceExpectation
} from "../src/cloud/private-recovery-query-evidence.js";
import { buildPrivateRecoveryQueryTemplate } from
  "../src/cloud/private-recovery-query-template.js";
import { validatePrivateRecoveryQueryReceipt } from
  "../src/cloud/private-recovery-query.js";

const STACK_NAME = "prooftoact-private-recovery-query";
const FUNCTION_NAME = "prooftoact-private-recovery-query";
const TABLE_NAME = "prooftoact-release-controller";

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalJson(value));
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
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_CREDENTIALS_REJECTED");
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
      socketTimeout: 15_000
    }),
    retryMode: "standard",
    sigv4aSigningRegionSet: [],
    useDualstackEndpoint: false,
    useFipsEndpoint: false
  };
}

function exactObject(entries, code) {
  const result = {};
  for (const [key, value] of entries) {
    requireCondition(typeof key === "string" && typeof value === "string" &&
      result[key] === undefined, code);
    result[key] = value;
  }
  return Object.freeze(Object.fromEntries(Object.entries(result).sort(
    ([left], [right]) => left.localeCompare(right)
  )));
}

function parseTemplateBody(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  requireCondition(typeof value === "string" && value.length <= 1024 * 1024,
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_TEMPLATE_REJECTED");
  try {
    const parsed = JSON.parse(value);
    requireCondition(parsed && typeof parsed === "object" &&
      !Array.isArray(parsed), "PRIVATE_RECOVERY_QUERY_EVIDENCE_TEMPLATE_REJECTED");
    return parsed;
  } catch (cause) {
    reject("PRIVATE_RECOVERY_QUERY_EVIDENCE_TEMPLATE_REJECTED", cause);
  }
}

function stackParameterMap(parameters, expectedTemplate) {
  const values = exactObject((parameters ?? []).map(
    ({ ParameterKey, ParameterValue }) => [ParameterKey, ParameterValue]
  ), "PRIVATE_RECOVERY_QUERY_EVIDENCE_PARAMETERS_REJECTED");
  requireCondition(canonicalJson(Object.keys(values).sort()) === canonicalJson(
    Object.keys(expectedTemplate.Parameters).sort()
  ), "PRIVATE_RECOVERY_QUERY_EVIDENCE_PARAMETERS_REJECTED");
  return values;
}

function resolveTemplateValue(value, context) {
  const code = "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED";
  if (value === null || ["string", "number", "boolean"].includes(typeof value)) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => resolveTemplateValue(entry, context));
  }
  requireCondition(value && typeof value === "object", code);
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === "Ref") {
    requireCondition(typeof context[value.Ref] === "string", code);
    return context[value.Ref];
  }
  if (keys.length === 1 && keys[0] === "Fn::GetAtt") {
    const [resource, attribute] = value["Fn::GetAtt"] ?? [];
    const key = `${resource}.${attribute}`;
    requireCondition(typeof context[key] === "string", code);
    return context[key];
  }
  if (keys.length === 1 && keys[0] === "Fn::Sub") {
    const source = value["Fn::Sub"];
    const template = Array.isArray(source) ? source[0] : source;
    const variables = Array.isArray(source) ? Object.fromEntries(
      Object.entries(source[1]).map(([key, item]) => [
        key, resolveTemplateValue(item, context)
      ])
    ) : {};
    requireCondition(typeof template === "string", code);
    return template.replace(/\$\{([A-Za-z0-9:._-]+)\}/gu, (_match, name) => {
      const replacement = Object.hasOwn(variables, name)
        ? variables[name]
        : context[name];
      requireCondition(typeof replacement === "string", code);
      return replacement;
    });
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key, resolveTemplateValue(item, context)
  ]));
}

function normalizeStringOrList(value, code) {
  const values = Array.isArray(value) ? value : [value];
  requireCondition(values.length > 0 && values.every((entry) =>
    typeof entry === "string" && entry.length > 0), code);
  return [...new Set(values)].sort();
}

function normalizePolicyPrincipal(value, code) {
  if (typeof value === "string" || Array.isArray(value)) {
    return normalizeStringOrList(value, code);
  }
  requireCondition(value && typeof value === "object", code);
  const allowed = new Set(["AWS", "CanonicalUser", "Federated", "Service"]);
  requireCondition(Object.keys(value).length > 0 &&
    Object.keys(value).every((key) => allowed.has(key)), code);
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) =>
    left.localeCompare(right)).map(([key, entry]) => [
    key, normalizeStringOrList(entry, code)
  ]));
}

function normalizePolicyCondition(value, code) {
  requireCondition(value && typeof value === "object" &&
    !Array.isArray(value), code);
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) =>
    left.localeCompare(right)).map(([operator, entries]) => {
    requireCondition(entries && typeof entries === "object" &&
      !Array.isArray(entries), code);
    return [operator, Object.fromEntries(Object.entries(entries)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => [key, normalizeStringOrList(entry, code)]))];
  }));
}

function normalizePolicyDocument(value) {
  const code = "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED";
  let decoded;
  try {
    decoded = decodePolicyDocument(value);
  } catch (cause) {
    reject(code, cause);
  }
  const allowedDocumentKeys = new Set(["Id", "Statement", "Version"]);
  requireCondition(Object.keys(decoded).every((key) =>
    allowedDocumentKeys.has(key)) && decoded.Version === "2012-10-17" &&
    (decoded.Id === undefined || typeof decoded.Id === "string"), code);
  const statements = Array.isArray(decoded.Statement)
    ? decoded.Statement : [decoded.Statement];
  requireCondition(statements.length > 0, code);
  const normalizedStatements = statements.map((statement) => {
    requireCondition(statement && typeof statement === "object" &&
      !Array.isArray(statement), code);
    const allowedStatementKeys = new Set([
      "Action", "Condition", "Effect", "NotAction", "NotPrincipal",
      "NotResource", "Principal", "Resource", "Sid"
    ]);
    requireCondition(Object.keys(statement).every((key) =>
      allowedStatementKeys.has(key)) && ["Allow", "Deny"].includes(
      statement.Effect) && (statement.Sid === undefined ||
      typeof statement.Sid === "string"), code);
    const normalized = {};
    for (const [key, entry] of Object.entries(statement)) {
      if (["Action", "NotAction", "Resource", "NotResource"].includes(key)) {
        normalized[key] = normalizeStringOrList(entry, code);
      } else if (["Principal", "NotPrincipal"].includes(key)) {
        normalized[key] = normalizePolicyPrincipal(entry, code);
      } else if (key === "Condition") {
        normalized[key] = normalizePolicyCondition(entry, code);
      } else {
        normalized[key] = entry;
      }
    }
    return Object.fromEntries(Object.entries(normalized).sort(
      ([left], [right]) => left.localeCompare(right)
    ));
  });
  return Object.freeze({
    ...(decoded.Id === undefined ? {} : { Id: decoded.Id }),
    Statement: normalizedStatements,
    Version: decoded.Version
  });
}

function roleName(arn) {
  const match = /^arn:aws:iam::[0-9]{12}:role\/([A-Za-z0-9+=,.@_-]{1,64})$/u
    .exec(arn);
  requireCondition(match, "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED");
  return match[1];
}

async function rolePosture(
  iam,
  arn,
  policyName,
  boundaryArn,
  expectedResource,
  resolutionContext
) {
  const name = roleName(arn);
  const [roleResponse, policies, attached, tags, policy] = await Promise.all([
    iam.send(new GetRoleCommand({ RoleName: name })),
    iam.send(new ListRolePoliciesCommand({ RoleName: name, MaxItems: 100 })),
    iam.send(new ListAttachedRolePoliciesCommand({ RoleName: name, MaxItems: 100 })),
    iam.send(new ListRoleTagsCommand({ RoleName: name, MaxItems: 100 })),
    iam.send(new GetRolePolicyCommand({ RoleName: name, PolicyName: policyName }))
  ]);
  const role = roleResponse?.Role;
  const expectedProperties = expectedResource?.Properties;
  const expectedTrust = resolveTemplateValue(
    expectedProperties?.AssumeRolePolicyDocument, resolutionContext
  );
  const expectedPolicy = resolveTemplateValue(
    expectedProperties?.Policies?.[0]?.PolicyDocument, resolutionContext
  );
  const observedTrust = normalizePolicyDocument(role?.AssumeRolePolicyDocument);
  const observedPolicy = normalizePolicyDocument(policy?.PolicyDocument);
  const normalizedExpectedTrust = normalizePolicyDocument(expectedTrust);
  const normalizedExpectedPolicy = normalizePolicyDocument(expectedPolicy);
  const expectedTags = exactObject(resolveTemplateValue(
    expectedProperties?.Tags, resolutionContext
  ).map(({ Key, Value }) => [Key, Value]),
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED");
  requireCondition(role?.Arn === arn && typeof role.RoleId === "string" &&
    role.RoleId.length >= 16 &&
    role.PermissionsBoundary?.PermissionsBoundaryType === "Policy" &&
    role.PermissionsBoundary?.PermissionsBoundaryArn === boundaryArn &&
    policies?.IsTruncated === false &&
    canonicalJson(policies.PolicyNames) === canonicalJson([policyName]) &&
    attached?.IsTruncated === false && attached.AttachedPolicies?.length === 0 &&
    tags?.IsTruncated === false && Array.isArray(tags.Tags) &&
    policy?.PolicyName === policyName && policy.RoleName === name &&
    role.Path === "/" && role.MaxSessionDuration ===
      (expectedProperties.MaxSessionDuration ?? 3600) &&
    role.Description === expectedProperties.Description &&
    canonicalJson(observedTrust) === canonicalJson(normalizedExpectedTrust) &&
    canonicalJson(observedPolicy) === canonicalJson(normalizedExpectedPolicy),
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED");
  const tagMap = exactObject(tags.Tags.map(({ Key, Value }) => [Key, Value]),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED");
  requireCondition(canonicalJson(tagMap) === canonicalJson(expectedTags),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_ROLE_REJECTED");
  return Object.freeze({
    arnSha256: sha256(arn),
    assumeRolePolicySha256: digest(observedTrust),
    inlinePolicySha256: digest(observedPolicy),
    permissionsBoundaryArnSha256: sha256(boundaryArn),
    roleIdSha256: sha256(role.RoleId),
    tagsSha256: digest(tagMap)
  });
}

function decodeOperation(item, expectation) {
  if (item === undefined) {
    requireCondition(expectation.phase === "PRE_QUERY",
      "PRIVATE_RECOVERY_QUERY_EVIDENCE_OPERATION_REJECTED");
    return Object.freeze({ receiptSha256: null, state: "ABSENT" });
  }
  requireCondition(expectation.phase === "POST_QUERY" &&
    item.pk?.S ===
      `PRIVATE_RECOVERY_QUERY#${expectation.operationGlobalKeySha256}` &&
    item.status?.S === "FINAL" && item.version?.N === "2" &&
    item.receipt?.B !== undefined,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_OPERATION_REJECTED");
  const bytes = Buffer.from(item.receipt.B);
  requireCondition(bytes.length > 0 && bytes.length <= 128 * 1024,
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_OPERATION_REJECTED");
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject("PRIVATE_RECOVERY_QUERY_EVIDENCE_OPERATION_REJECTED", cause);
  }
  requireCondition(canonicalJson(parsed) === bytes.toString("utf8"),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_OPERATION_REJECTED");
  const receipt = validatePrivateRecoveryQueryReceipt(parsed);
  requireCondition(receipt.status === "PASS" &&
    receipt.receiptSha256 === expectation.expectedOperationReceiptSha256 &&
    receipt.approvalSha256 === expectation.approvalSha256 &&
    receipt.sourceCommit === expectation.sourceCommit &&
    receipt.treeDigest === expectation.treeDigest,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_OPERATION_REJECTED");
  return Object.freeze({ receiptSha256: receipt.receiptSha256, state: "FINAL" });
}

function validateSecretPosture(secret, mcpSecretArn, mcpSecretVersionId) {
  const versions = secret?.VersionIdsToStages;
  requireCondition(secret?.ARN === mcpSecretArn &&
    secret.DeletedDate === undefined && secret.RotationEnabled !== true &&
    secret.OwningService === undefined && versions &&
    Object.keys(versions).length === 1 &&
    Array.isArray(versions[mcpSecretVersionId]) &&
    canonicalJson(versions[mcpSecretVersionId]) === canonicalJson(["AWSCURRENT"]),
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_SECRET_REJECTED");
  return Object.freeze({
    arnSha256: sha256(mcpSecretArn),
    currentVersion: true,
    rotationEnabled: false,
    versionIdSha256: sha256(mcpSecretVersionId)
  });
}

async function getFunctionPolicyOrAbsent(lambda, input) {
  try {
    return await lambda.send(new GetPolicyCommand(input));
  } catch (cause) {
    if (cause?.name === "ResourceNotFoundException") {
      return Object.freeze({ policyAbsent: true });
    }
    throw cause;
  }
}

export async function collectPrivateRecoveryDeploymentSnapshot({
  clients,
  clock = () => new Date(),
  expectation: rawExpectation,
  mcpSecretArn,
  mcpSecretVersionId
}) {
  const expectation = validatePrivateRecoveryEvidenceExpectation(rawExpectation);
  requireCondition(sha256(mcpSecretArn) === expectation.mcpSecretArnSha256 &&
    sha256(mcpSecretVersionId) === expectation.mcpSecretVersionIdSha256,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_SECRET_BINDING_REJECTED");
  const [identity, stackResult, templateResult, resourcesResult,
    functionResult, configuration, concurrency, policyResult, urls, mappings,
    secret, operationResult] = await Promise.all([
    clients.sts.send(new GetCallerIdentityCommand({})),
    clients.cloudformation.send(new DescribeStacksCommand({ StackName: STACK_NAME })),
    clients.cloudformation.send(new GetTemplateCommand({
      StackName: STACK_NAME,
      TemplateStage: "Processed"
    })),
    clients.cloudformation.send(new DescribeStackResourcesCommand({
      StackName: STACK_NAME
    })),
    clients.lambda.send(new GetFunctionCommand({
      FunctionName: expectation.functionArn,
      Qualifier: expectation.functionVersion
    })),
    clients.lambda.send(new GetFunctionConfigurationCommand({
      FunctionName: expectation.functionArn,
      Qualifier: expectation.functionVersion
    })),
    clients.lambda.send(new GetFunctionConcurrencyCommand({
      FunctionName: expectation.functionArn
    })),
    getFunctionPolicyOrAbsent(clients.lambda, {
      FunctionName: expectation.functionArn,
      Qualifier: expectation.functionVersion
    }),
    clients.lambda.send(new ListFunctionUrlConfigsCommand({
      FunctionName: expectation.functionArn
    })),
    clients.lambda.send(new ListEventSourceMappingsCommand({
      FunctionName: expectation.functionArn,
      MaxItems: 100
    })),
    clients.secrets.send(new DescribeSecretCommand({ SecretId: mcpSecretArn })),
    clients.dynamodb.send(new GetItemCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: { S: `PRIVATE_RECOVERY_QUERY#${expectation.operationGlobalKeySha256}` }
      },
      ConsistentRead: true,
      ReturnConsumedCapacity: "NONE"
    }))
  ]);

  const accountId = /^(?:[0-9]{12})$/u.test(identity?.Account ?? "")
    ? identity.Account : null;
  requireCondition(accountId !== null &&
    new RegExp(`^arn:aws:sts::${accountId}:assumed-role/` +
      "ProofToActPrivateRecoveryQueryEvidence/[A-Za-z0-9+=,.@_-]{1,64}$", "u")
      .test(identity.Arn ?? "") &&
    typeof identity.UserId === "string" && identity.UserId.length >= 16,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_IDENTITY_REJECTED");

  requireCondition(Array.isArray(stackResult?.Stacks) &&
    stackResult.Stacks.length === 1,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_STACK_REJECTED");
  const stack = stackResult.Stacks[0];
  requireCondition(stack.StackName === STACK_NAME &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-private-recovery-query\/[0-9a-f-]{36}$/u
      .test(stack.StackId ?? "") &&
    stack.StackStatus === "CREATE_COMPLETE" &&
    stack.EnableTerminationProtection === true &&
    stack.RoleARN === expectation.cloudFormationServiceRoleArn &&
    stack.DisableRollback === false,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_STACK_REJECTED");
  const expectedSourceTemplate = buildPrivateRecoveryQueryTemplate();
  const parameters = stackParameterMap(stack.Parameters, expectedSourceTemplate);
  requireCondition(
    parameters.ApprovalSha256 === expectation.approvalSha256 &&
    /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(
      parameters.ArtifactBucketName ?? ""
    ) &&
    parameters.ArtifactKey ===
      `private-recovery-query/${expectation.sourceCommit}/` +
      `private-recovery-query-${expectation.codeZipSha256}.zip` &&
    /^[A-Za-z0-9._~-]{1,1024}$/u.test(
      parameters.ArtifactObjectVersion ?? ""
    ) &&
    parameters.CloudFormationServiceRoleArn ===
      expectation.cloudFormationServiceRoleArn &&
    parameters.CodeSha256Base64 === expectation.codeSha256Base64 &&
    parameters.CodeZipSha256 === expectation.codeZipSha256 &&
    parameters.ConfigSha256 === expectation.configSha256 &&
    parameters.EvidenceWorkflowCommit === expectation.workflowCommit &&
    parameters.GitHubOidcProviderArn ===
      `arn:aws:iam::${accountId}:oidc-provider/` +
      "token.actions.githubusercontent.com" &&
    parameters.McpSecretArn === mcpSecretArn &&
    /^\*{4,}$/u.test(parameters.McpSecretVersionId ?? "") &&
    parameters.OperationGlobalKeySha256 ===
      expectation.operationGlobalKeySha256 &&
    parameters.PermissionsBoundaryArn === expectation.permissionsBoundaryArn &&
    parameters.ReleaseControlTableArn === expectation.releaseControlTableArn &&
    parameters.SealedWorkflowCommit === expectation.workflowCommit &&
    parameters.SourceCommit === expectation.sourceCommit &&
    parameters.TeardownWorkflowCommit === expectation.workflowCommit &&
    parameters.TemplateSha256 === expectation.templateSha256 &&
    parameters.TreeDigest === expectation.treeDigest,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_PARAMETERS_REJECTED");
  const outputs = exactObject((stack.Outputs ?? []).map(({ OutputKey, OutputValue }) =>
    [OutputKey, OutputValue]), "PRIVATE_RECOVERY_QUERY_EVIDENCE_STACK_REJECTED");
  const expectedOutputs = Object.freeze({
    ApprovalSha256: expectation.approvalSha256,
    CodeZipSha256: expectation.codeZipSha256,
    ConfigSha256: expectation.configSha256,
    EvidenceRoleArn: expectation.evidenceRoleArn,
    FunctionArn: expectation.functionArn,
    FunctionVersion: expectation.functionVersion,
    OperationGlobalKeySha256: expectation.operationGlobalKeySha256,
    OperatorRoleArn: expectation.operatorRoleArn,
    RuntimeRoleArn: expectation.runtimeRoleArn,
    SourceCommit: expectation.sourceCommit,
    TeardownRoleArn: expectation.teardownRoleArn,
    TemplateSha256: expectation.templateSha256,
    TreeDigest: expectation.treeDigest
  });
  requireCondition(canonicalJson(outputs) === canonicalJson(expectedOutputs),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_STACK_REJECTED");
  const template = parseTemplateBody(templateResult?.TemplateBody);
  requireCondition(digest(template) === expectation.templateSha256 &&
    canonicalJson(template) === canonicalJson(expectedSourceTemplate),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_TEMPLATE_REJECTED");
  const resourceInventory = (resourcesResult?.StackResources ?? []).map(
    ({ LogicalResourceId, ResourceStatus, ResourceType }) => ({
      logicalResourceId: LogicalResourceId,
      resourceStatus: ResourceStatus,
      resourceType: ResourceType
    })
  ).sort((left, right) => left.logicalResourceId.localeCompare(
    right.logicalResourceId
  ));
  requireCondition(resourcesResult?.NextToken === undefined &&
    resourceInventory.length === 7 &&
    resourceInventory.every(({ resourceStatus }) =>
      resourceStatus === "CREATE_COMPLETE") &&
    canonicalJson(resourceInventory.map(({ logicalResourceId, resourceType }) =>
      [logicalResourceId, resourceType])) === canonicalJson([
      ["PrivateRecoveryEvidenceRole", "AWS::IAM::Role"],
      ["PrivateRecoveryFunction", "AWS::Lambda::Function"],
      ["PrivateRecoveryLogGroup", "AWS::Logs::LogGroup"],
      ["PrivateRecoveryOperatorRole", "AWS::IAM::Role"],
      ["PrivateRecoveryRuntimeRole", "AWS::IAM::Role"],
      ["PrivateRecoveryTeardownRole", "AWS::IAM::Role"],
      ["PrivateRecoveryVersion", "AWS::Lambda::Version"]
    ]), "PRIVATE_RECOVERY_QUERY_EVIDENCE_RESOURCE_INVENTORY_REJECTED");

  const functionConfiguration = functionResult?.Configuration;
  requireCondition(functionConfiguration?.FunctionArn ===
      `${expectation.functionArn}:${expectation.functionVersion}` &&
    configuration?.FunctionArn ===
      `${expectation.functionArn}:${expectation.functionVersion}` &&
    configuration.Version === expectation.functionVersion &&
    configuration.CodeSha256 === expectation.codeSha256Base64 &&
    configuration.Runtime === "nodejs22.x" && configuration.Handler === "index.handler" &&
    configuration.MemorySize === 256 && configuration.Timeout === 120 &&
    canonicalJson(configuration.Architectures) === canonicalJson(["arm64"]) &&
    configuration.PackageType === "Zip" &&
    configuration.Role === expectation.runtimeRoleArn &&
    configuration.TracingConfig?.Mode === "PassThrough" &&
    configuration.EphemeralStorage?.Size === 512 &&
    (configuration.Layers ?? []).length === 0 &&
    (configuration.FileSystemConfigs ?? []).length === 0 &&
    configuration.DeadLetterConfig?.TargetArn === undefined &&
    configuration.KMSKeyArn === undefined &&
    (configuration.VpcConfig?.SubnetIds ?? []).length === 0 &&
    (configuration.VpcConfig?.SecurityGroupIds ?? []).length === 0 &&
    configuration.VpcConfig?.VpcId === undefined &&
    concurrency?.ReservedConcurrentExecutions === 1,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_FUNCTION_REJECTED");
  const expectedEnvironment = Object.freeze({
    APPROVAL_SHA256: expectation.approvalSha256,
    CODE_ZIP_SHA256: expectation.codeZipSha256,
    CONFIG_SHA256: expectation.configSha256,
    FUNCTION_ARN: expectation.functionArn,
    MCP_SECRET_ARN: mcpSecretArn,
    MCP_SECRET_VERSION_ID: mcpSecretVersionId,
    OPERATION_GLOBAL_KEY_SHA256: expectation.operationGlobalKeySha256,
    RELEASE_CONTROL_TABLE_ARN: expectation.releaseControlTableArn,
    SOURCE_COMMIT: expectation.sourceCommit,
    TREE_DIGEST: expectation.treeDigest
  });
  requireCondition(canonicalJson(configuration.Environment?.Variables) ===
    canonicalJson(expectedEnvironment),
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_FUNCTION_REJECTED");
  const safeConfiguration = Object.freeze({
    architectures: configuration.Architectures,
    approvalSha256: expectation.approvalSha256,
    codeSha256Base64: configuration.CodeSha256,
    codeZipSha256: expectation.codeZipSha256,
    configSha256: expectation.configSha256,
    ephemeralStorage: configuration.EphemeralStorage,
    functionArnSha256: sha256(expectation.functionArn),
    handler: configuration.Handler,
    loggingConfig: configuration.LoggingConfig,
    mcpSecretArnSha256: expectation.mcpSecretArnSha256,
    mcpSecretVersionIdSha256: expectation.mcpSecretVersionIdSha256,
    memorySize: configuration.MemorySize,
    operationGlobalKeySha256: expectation.operationGlobalKeySha256,
    packageType: configuration.PackageType,
    releaseControlTableArnSha256: sha256(expectation.releaseControlTableArn),
    roleArnSha256: sha256(configuration.Role),
    runtime: configuration.Runtime,
    sourceCommit: expectation.sourceCommit,
    timeout: configuration.Timeout,
    tracingMode: configuration.TracingConfig.Mode,
    treeDigest: expectation.treeDigest,
    version: configuration.Version
  });
  requireCondition(policyResult?.policyAbsent === true,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_FUNCTION_POLICY_REJECTED");
  requireCondition(Array.isArray(urls?.FunctionUrlConfigs) &&
    urls.FunctionUrlConfigs.length === 0 && urls.NextMarker === undefined &&
    Array.isArray(mappings?.EventSourceMappings) &&
    mappings.EventSourceMappings.length === 0 && mappings.NextMarker === undefined,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_PUBLIC_TRIGGER_REJECTED");
  const tags = exactObject(Object.entries(functionResult.Tags ?? {}),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_FUNCTION_REJECTED");
  requireCondition(tags.Project === "ProofToAct" &&
    tags.Purpose === "PrivateRecoveryQuery",
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_FUNCTION_REJECTED");

  const bootstrapTemplate = JSON.parse(fs.readFileSync(new URL(
    "../infra/aws/private-recovery-query-bootstrap-role-stack.json",
    import.meta.url
  ), "utf8"));
  const resolutionContext = Object.freeze({
    ...parameters,
    "AWS::AccountId": accountId,
    "AWS::Partition": "aws",
    "AWS::Region": "us-east-1",
    PrivateRecoveryBoundary: expectation.permissionsBoundaryArn,
    PrivateRecoveryFunction: FUNCTION_NAME,
    "PrivateRecoveryFunction.Arn": expectation.functionArn,
    "PrivateRecoveryEvidenceRole.Arn": expectation.evidenceRoleArn,
    "PrivateRecoveryOperatorRole.Arn": expectation.operatorRoleArn,
    "PrivateRecoveryRuntimeRole.Arn": expectation.runtimeRoleArn,
    "PrivateRecoveryTeardownRole.Arn": expectation.teardownRoleArn,
    PrivateRecoveryVersion: expectation.functionVersion
  });
  const posture = await Promise.all([
    [expectation.cloudFormationServiceRoleArn,
      "ProofToActPrivateRecoveryQueryCloudFormationOnly",
      bootstrapTemplate.Resources.PrivateRecoveryCloudFormationRole],
    [expectation.runtimeRoleArn, "ProofToActPrivateRecoveryQueryRuntimeOnly",
      expectedSourceTemplate.Resources.PrivateRecoveryRuntimeRole],
    [expectation.operatorRoleArn, "ProofToActPrivateRecoveryQueryOperatorOnly",
      expectedSourceTemplate.Resources.PrivateRecoveryOperatorRole],
    [expectation.evidenceRoleArn, "ProofToActPrivateRecoveryQueryEvidenceOnly",
      expectedSourceTemplate.Resources.PrivateRecoveryEvidenceRole],
    [expectation.teardownRoleArn, "ProofToActPrivateRecoveryQueryTeardownOnly",
      expectedSourceTemplate.Resources.PrivateRecoveryTeardownRole]
  ].map(([arn, policyName, expectedResource]) => rolePosture(
    clients.iam,
    arn,
    policyName,
    expectation.permissionsBoundaryArn,
    expectedResource,
    resolutionContext
  )));
  const secretPosture = validateSecretPosture(
    secret, mcpSecretArn, mcpSecretVersionId
  );

  const now = clock();
  requireCondition(now instanceof Date && Number.isFinite(now.getTime()),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_CLOCK_REJECTED");
  return Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-deployment-snapshot.v1",
    accountIdSha256: sha256(accountId),
    callerArnSha256: sha256(identity.Arn),
    callerUserIdSha256: sha256(identity.UserId),
    function: Object.freeze({
      architectures: ["arm64"],
      codeSha256Base64: expectation.codeSha256Base64,
      configurationSha256: digest(safeConfiguration),
      eventSourceCount: 0,
      functionArnSha256: sha256(expectation.functionArn),
      functionPolicySha256: digest({ status: "ABSENT" }),
      functionUrlCount: 0,
      memorySize: 256,
      reservedConcurrency: 1,
      runtime: "nodejs22.x",
      tagsSha256: digest(tags),
      timeout: 120,
      version: expectation.functionVersion,
      vpcAttached: false
    }),
    observedAt: now.toISOString(),
    operation: decodeOperation(operationResult?.Item, expectation),
    phase: expectation.phase,
    resourceInventorySha256: digest(resourceInventory),
    rolePostureSha256: digest(posture),
    secret: secretPosture,
    stackIdSha256: sha256(stack.StackId),
    stackParametersSha256: digest(parameters),
    stackStatus: stack.StackStatus,
    templateSha256: expectation.templateSha256,
    terminationProtection: true,
    workflowCommit: expectation.workflowCommit
  });
}

function readCanonicalJson(filePath, maximumBytes, code) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= maximumBytes, code);
  const bytes = fs.readFileSync(resolved);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (cause) {
    reject(code, cause);
  }
  requireCondition(bytes.toString("utf8") === `${canonicalJson(value)}\n`, code);
  return value;
}

function readPrivateKey(filePath) {
  const resolved = path.resolve(filePath);
  const stat = fs.lstatSync(resolved);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= 16 * 1024 && (stat.mode & 0o077) === 0,
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_KEY_REJECTED");
  return fs.readFileSync(resolved);
}

function writeCreateOnly(filePath, value) {
  const resolved = path.resolve(filePath);
  requireCondition(!fs.existsSync(resolved),
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_OUTPUT_REJECTED");
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const descriptor = fs.openSync(resolved,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
  try {
    fs.writeFileSync(descriptor, `${canonicalJson(value)}\n`, "utf8");
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseArguments(args) {
  const names = [
    "--expectation-file", "--mcp-secret-arn", "--mcp-secret-version-id",
    "--receipt-key-file", "--receipt-output"
  ];
  requireCondition(args.length === names.length * 2,
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_ARGUMENT_REJECTED");
  const value = {};
  for (let index = 0; index < args.length; index += 2) {
    requireCondition(names.includes(args[index]) && value[args[index]] === undefined &&
      typeof args[index + 1] === "string" && args[index + 1].length > 0,
    "PRIVATE_RECOVERY_QUERY_EVIDENCE_ARGUMENT_REJECTED");
    value[args[index]] = args[index + 1];
  }
  return value;
}

export async function main(args = process.argv.slice(2), environment = process.env) {
  const parsed = parseArguments(args);
  requireCondition(environment.AWS_REGION === "us-east-1" &&
    environment.AWS_DEFAULT_REGION === "us-east-1",
  "PRIVATE_RECOVERY_QUERY_EVIDENCE_ENVIRONMENT_REJECTED");
  const expectation = validatePrivateRecoveryEvidenceExpectation(
    readCanonicalJson(parsed["--expectation-file"], 64 * 1024,
      "PRIVATE_RECOVERY_QUERY_EVIDENCE_EXPECTATION_REJECTED")
  );
  const credentials = explicitCredentials(environment);
  const options = sdkOptions(credentials);
  const snapshot = await collectPrivateRecoveryDeploymentSnapshot({
    clients: {
      cloudformation: new CloudFormationClient(options),
      dynamodb: new DynamoDBClient(options),
      iam: new IAMClient(options),
      lambda: new LambdaClient(options),
      secrets: new SecretsManagerClient(options),
      sts: new STSClient(options)
    },
    expectation,
    mcpSecretArn: parsed["--mcp-secret-arn"],
    mcpSecretVersionId: parsed["--mcp-secret-version-id"]
  });
  const receipt = signPrivateRecoveryDeploymentEvidence({
    expectation,
    privateKeyPem: readPrivateKey(parsed["--receipt-key-file"]),
    snapshot
  });
  writeCreateOnly(parsed["--receipt-output"], receipt);
  process.stdout.write(`PRIVATE_RECOVERY_QUERY_EVIDENCE_PASS:${receipt.receiptSha256}\n`);
  return receipt;
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch((cause) => {
    const code = /^PRIVATE_RECOVERY_QUERY_[A-Z0-9_]{1,120}$/u.test(
      cause?.message ?? ""
    ) ? cause.message : "PRIVATE_RECOVERY_QUERY_EVIDENCE_UNKNOWN_HOLD";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  decodeOperation,
  digest,
  explicitCredentials,
  getFunctionPolicyOrAbsent,
  normalizePolicyDocument,
  parseArguments,
  resolveTemplateValue,
  rolePosture,
  sdkOptions,
  sha256,
  stackParameterMap,
  validateSecretPosture
});
