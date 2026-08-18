import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  validateBootstrapTemplateBytes
} from "./prepare-release-control-bootstrap.js";
import {
  attestReleaseControlTable
} from "./lib/release-control-table-identity.js";

const INPUT_SCHEMA = "prooftoact.release-control-bootstrap-readback-input.v1";
const RECEIPT_SCHEMA = "prooftoact.release-control-bootstrap-readback-receipt.v1";
const STACK_ID_SCHEMA = "prooftoact.release-control-bootstrap-stack-id.v1";
const STATUS = "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED";
const REGION = "us-east-1";
const STACK_NAME = "prooftoact-release-control-bootstrap";
const TABLE_NAME = "prooftoact-release-controller";
const BOUNDARY_NAME = "ProofToActGate2CloudFormationBoundary";
const TEMPLATE_SHA256 =
  "6e8fd5c0ad6de5c5b0a52dc125b019857c3dd3f86298b91e05a6279edd220989";
const SOURCE_BOUNDARY_SHA256 =
  "beb78b947292ec8afd946ba9656c424b1bfa35ffa8ea59e095b38cc49523dd84";
const DYNAMODB_KMS_SOURCE_ALIAS = "alias/aws/dynamodb";
const CLOUDFORMATION_KMS_SUMMARY_SENTINEL =
  "arn:aws(-[a-z]{1,4}){0,2}:kms:[a-z]{2,4}(-[a-z]{1,4})?-" +
  "[a-z]{1,10}-[0-9]:[0-9]{12}:key/";
const ACCOUNT_ID = /^[0-9]{12}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ROLE_ID = /^[A-Z0-9]{16,64}$/u;
const POLICY_ID = /^[A-Z0-9]{16,64}$/u;
const VERSION_ID = /^v[1-9][0-9]*$/u;
const BUCKET_NAME =
  /^(?!xn--)(?!.*\.\.)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/u;

const ROLE_NAMES = Object.freeze({
  CloudFormationServiceRole: "ProofToActGate2CloudFormation",
  LiveDrillOperatorRole: "ProofToActLiveDrillOperator",
  ReleaseCoordinatorRole: "ProofToActReleaseCoordinator",
  ReleaseDeploymentRole: "ProofToActReleaseDeployment",
  ReleaseEvidenceRole: "ProofToActReleaseEvidence",
  ReleaseExecutionRole: "ProofToActReleaseExecution",
  ReleaseTeardownRole: "ProofToActReleaseTeardown",
  ReleaseTerminalizerRole: "ProofToActReleaseTerminalizer"
});

const RESOURCE_TYPES = Object.freeze({
  CloudFormationPermissionsBoundary: "AWS::IAM::ManagedPolicy",
  CloudFormationServiceRole: "AWS::IAM::Role",
  LiveDrillOperatorRole: "AWS::IAM::Role",
  ReleaseControlTable: "AWS::DynamoDB::Table",
  ReleaseCoordinatorRole: "AWS::IAM::Role",
  ReleaseDeploymentRole: "AWS::IAM::Role",
  ReleaseEvidenceRole: "AWS::IAM::Role",
  ReleaseExecutionRole: "AWS::IAM::Role",
  ReleaseTeardownRole: "AWS::IAM::Role",
  ReleaseTerminalizerRole: "AWS::IAM::Role"
});

const RESPONSE_KEYS = Object.freeze([
  "boundary",
  "callerIdentity",
  "deployedTemplate",
  "describeKmsKey",
  "describeTable",
  "listStackResourceDrifts",
  "listStackResources",
  "listTableTags",
  "roles",
  "simulations",
  "stack"
]);

const ENVIRONMENT_KEYS = Object.freeze([
  "PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256",
  "PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256",
  "PROOFTOACT_RELEASE_BOOTSTRAP_STATUS",
  "PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256",
  "PROOFTOACT_RELEASE_CONTROL_TABLE_ID"
]);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function allowedKeys(value, allowed, required = []) {
  return plainObject(value) &&
    Object.keys(value).every((key) => allowed.includes(key)) &&
    required.every((key) => Object.hasOwn(value, key));
}

function untruncatedEnvelope(value, payloadKeys, code) {
  requireCondition(allowedKeys(value, [...payloadKeys, "IsTruncated"],
    payloadKeys) && (!Object.hasOwn(value, "IsTruncated") ||
      value.IsTruncated === false), code);
  return value;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalValue(value[key])]));
  }
  requireCondition(value === null || typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value)),
  "BOOTSTRAP_READBACK_CANONICAL_VALUE_REJECTED");
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function exactLocalSourceSha256(sourceUrl) {
  const code = "BOOTSTRAP_READBACK_LOCAL_SOURCE_REJECTED";
  const sourcePath = fileURLToPath(sourceUrl);
  let stat;
  let real;
  try {
    stat = fs.lstatSync(sourcePath);
    real = fs.realpathSync(sourcePath);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    real === sourcePath && stat.size > 0 && stat.size <= 4 * 1024 * 1024,
  code);
  return sha256(fs.readFileSync(sourcePath));
}

function collectionBoundary() {
  return deepFreeze({
    collectionMethod: "CALLER_SUPPLIED_JSON_RESPONSE_SET",
    collectorExecutionProven: false,
    rawCollectorBundleRequiredForPublication: true,
    sourceOwnedCollectorSha256: exactLocalSourceSha256(new URL(
      "./release-provider-bootstrap-readback-collector.sh",
      import.meta.url
    )),
    sourceOwnedVerifierSha256: exactLocalSourceSha256(new URL(
      "./release-provider-bootstrap-readback.js",
      import.meta.url
    ))
  });
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function canonicalInstant(value, code) {
  requireCondition(typeof value === "string", code);
  const milliseconds = Date.parse(value);
  requireCondition(Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

function parseProviderInstant(value, observedAt, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" && Number.isFinite(milliseconds) &&
    milliseconds <= observedAt, code);
  return milliseconds;
}

function sortedTags(tags, code) {
  requireCondition(Array.isArray(tags), code);
  const normalized = tags.map((tag) => {
    requireCondition(exactKeys(tag, ["Key", "Value"]) &&
      typeof tag.Key === "string" && tag.Key.length > 0 &&
      typeof tag.Value === "string", code);
    return { Key: tag.Key, Value: tag.Value };
  }).sort((left, right) => left.Key.localeCompare(right.Key) ||
    left.Value.localeCompare(right.Value));
  requireCondition(new Set(normalized.map(({ Key }) => Key)).size ===
    normalized.length, code);
  return normalized;
}

function resolvedContext(accountId, artifactBucketName) {
  const roleArn = (logicalId) =>
    `arn:aws:iam::${accountId}:role/${ROLE_NAMES[logicalId]}`;
  return Object.freeze({
    accountId,
    artifactBucketName,
    boundaryArn: `arn:aws:iam::${accountId}:policy/${BOUNDARY_NAME}`,
    oidcArn: `arn:aws:iam::${accountId}:oidc-provider/` +
      "token.actions.githubusercontent.com",
    roleArn,
    tableArn: `arn:aws:dynamodb:${REGION}:${accountId}:table/${TABLE_NAME}`
  });
}

function resolveIntrinsic(value, context) {
  if (Array.isArray(value)) {
    return value.map((entry) => resolveIntrinsic(entry, context));
  }
  if (!plainObject(value)) return value;
  if (exactKeys(value, ["Ref"])) {
    const refs = {
      "AWS::AccountId": context.accountId,
      "AWS::Partition": "aws",
      "AWS::Region": REGION,
      ArtifactBucketName: context.artifactBucketName,
      CloudFormationPermissionsBoundary: context.boundaryArn,
      GitHubOidcProviderArn: context.oidcArn,
      ReleaseControlTable: TABLE_NAME
    };
    requireCondition(Object.hasOwn(refs, value.Ref),
      "BOOTSTRAP_READBACK_UNKNOWN_REF_REJECTED");
    return refs[value.Ref];
  }
  if (exactKeys(value, ["Fn::GetAtt"])) {
    const [logicalId, attribute] = value["Fn::GetAtt"] ?? [];
    requireCondition(attribute === "Arn",
      "BOOTSTRAP_READBACK_UNKNOWN_GETATT_REJECTED");
    if (logicalId === "ReleaseControlTable") return context.tableArn;
    requireCondition(Object.hasOwn(ROLE_NAMES, logicalId),
      "BOOTSTRAP_READBACK_UNKNOWN_GETATT_REJECTED");
    return context.roleArn(logicalId);
  }
  if (exactKeys(value, ["Fn::Sub"])) {
    requireCondition(typeof value["Fn::Sub"] === "string",
      "BOOTSTRAP_READBACK_UNKNOWN_SUB_REJECTED");
    const substitutions = {
      "AWS::AccountId": context.accountId,
      "AWS::Partition": "aws",
      "AWS::Region": REGION,
      ArtifactBucketName: context.artifactBucketName
    };
    return value["Fn::Sub"].replace(/\$\{([^}]+)\}/gu, (_match, name) => {
      requireCondition(Object.hasOwn(substitutions, name),
        "BOOTSTRAP_READBACK_UNKNOWN_SUB_REJECTED");
      return substitutions[name];
    });
  }
  return Object.fromEntries(Object.entries(value).map(([key, child]) =>
    [key, resolveIntrinsic(child, context)]));
}

function buildContract(templateBytes, accountId, artifactBucketName) {
  const templateReceipt = validateBootstrapTemplateBytes(templateBytes);
  requireCondition(templateReceipt.sha256 === TEMPLATE_SHA256,
    "BOOTSTRAP_READBACK_TEMPLATE_REJECTED");
  const template = JSON.parse(templateBytes.toString("utf8"));
  const context = resolvedContext(accountId, artifactBucketName);
  const roles = Object.fromEntries(Object.entries(ROLE_NAMES).map(
    ([logicalId, roleName]) => {
      const properties = template.Resources?.[logicalId]?.Properties;
      requireCondition(plainObject(properties) &&
        Array.isArray(properties.Policies) && properties.Policies.length === 1,
      "BOOTSTRAP_READBACK_SOURCE_ROLE_REJECTED");
      return [logicalId, deepFreeze({
        arn: context.roleArn(logicalId),
        description: properties.Description,
        inlinePolicy: resolveIntrinsic(
          properties.Policies[0].PolicyDocument,
          context
        ),
        policyName: properties.Policies[0].PolicyName,
        roleName,
        maxSessionDuration: properties.MaxSessionDuration,
        tags: sortedTags(properties.Tags,
          "BOOTSTRAP_READBACK_SOURCE_ROLE_REJECTED"),
        trust: resolveIntrinsic(properties.AssumeRolePolicyDocument, context)
      })];
    }
  ));
  const boundarySource = template.Resources
    ?.CloudFormationPermissionsBoundary?.Properties?.PolicyDocument;
  requireCondition(digest(boundarySource) === SOURCE_BOUNDARY_SHA256,
    "BOOTSTRAP_READBACK_SOURCE_BOUNDARY_REJECTED");
  return deepFreeze({
    boundary: resolveIntrinsic(boundarySource, context),
    context,
    roles,
    template,
    templateReceipt
  });
}

function expectedOutputs(template, context) {
  return Object.fromEntries(Object.entries(template.Outputs ?? {}).map(
    ([key, output]) => [key, resolveIntrinsic(output.Value, context)]
  ));
}

function validateCaller(value, accountId) {
  const code = "BOOTSTRAP_READBACK_CALLER_REJECTED";
  const rootArn = `arn:aws:iam::${accountId}:root`;
  const userArn = new RegExp(`^arn:aws:iam::${accountId}:user/` +
    "[A-Za-z0-9+=,.@_/-]{1,512}$", "u");
  requireCondition(exactKeys(value, ["Account", "Arn", "UserId"]) &&
    value.Account === accountId && typeof value.UserId === "string" &&
    value.UserId.length > 0 && typeof value.Arn === "string" &&
    (value.Arn === rootArn || userArn.test(value.Arn)) &&
    (value.Arn !== rootArn || value.UserId === accountId), code);
  return value.Arn;
}

function validateStack(value, contract, observedAt) {
  const code = "BOOTSTRAP_READBACK_STACK_REJECTED";
  requireCondition(exactKeys(value, ["Stacks"]) &&
    Array.isArray(value.Stacks) && value.Stacks.length === 1, code);
  const stack = value.Stacks[0];
  requireCondition(allowedKeys(stack, [
    "Capabilities", "CreationTime", "DeploymentConfig", "Description",
    "DisableRollback", "DriftInformation", "EnableTerminationProtection",
    "LastOperations", "NotificationARNs", "Outputs", "Parameters",
    "RollbackConfiguration", "StackId", "StackName", "StackStatus", "Tags",
    "TimeoutInMinutes"
  ], ["Capabilities", "CreationTime", "Description", "DisableRollback",
    "DriftInformation", "EnableTerminationProtection", "NotificationARNs",
    "Outputs", "Parameters", "RollbackConfiguration", "StackId", "StackName",
    "StackStatus", "Tags", "TimeoutInMinutes"]), code);
  const stackPrefix = `arn:aws:cloudformation:${REGION}:` +
    `${contract.context.accountId}:stack/${STACK_NAME}/`;
  requireCondition(stack.StackName === STACK_NAME &&
    typeof stack.StackId === "string" &&
    stack.StackId.startsWith(stackPrefix) &&
    UUID.test(stack.StackId.slice(stackPrefix.length)) &&
    stack.StackStatus === "CREATE_COMPLETE" &&
    stack.Description === contract.template.Description &&
    stack.DisableRollback === false && stack.EnableTerminationProtection === false &&
    stack.TimeoutInMinutes === 15 &&
    canonicalJson(stack.Capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    canonicalJson(stack.NotificationARNs) === "[]" &&
    canonicalJson(stack.RollbackConfiguration) === "{}" &&
    canonicalJson(stack.Tags) === "[]", code);
  parseProviderInstant(stack.CreationTime, observedAt, code);
  if (Object.hasOwn(stack, "DeploymentConfig")) {
    requireCondition(exactKeys(stack.DeploymentConfig,
      ["DisableRollback", "Mode"]) &&
      stack.DeploymentConfig.DisableRollback === false &&
      stack.DeploymentConfig.Mode === "STANDARD", code);
  }
  if (Object.hasOwn(stack, "LastOperations")) {
    requireCondition(Array.isArray(stack.LastOperations) &&
      stack.LastOperations.length === 1 &&
      exactKeys(stack.LastOperations[0], ["OperationId", "OperationType"]) &&
      UUID.test(stack.LastOperations[0].OperationId ?? "") &&
      stack.LastOperations[0].OperationType === "CREATE_STACK", code);
  }
  requireCondition(Array.isArray(stack.Parameters) &&
    stack.Parameters.length === 2 && Array.isArray(stack.Outputs) &&
    stack.Outputs.length === Object.keys(contract.template.Outputs ?? {}).length,
  code);
  const parameters = Object.fromEntries(stack.Parameters.map((entry) => {
    requireCondition(exactKeys(entry, ["ParameterKey", "ParameterValue"]), code);
    return [entry.ParameterKey, entry.ParameterValue];
  }));
  requireCondition(exactKeys(parameters, ["ArtifactBucketName",
    "GitHubOidcProviderArn"]) &&
    Object.keys(parameters).length === stack.Parameters.length &&
    parameters.ArtifactBucketName === contract.context.artifactBucketName &&
    parameters.GitHubOidcProviderArn === contract.context.oidcArn, code);
  const outputs = Object.fromEntries(stack.Outputs.map((entry) => {
    requireCondition(exactKeys(entry, ["OutputKey", "OutputValue"]), code);
    return [entry.OutputKey, entry.OutputValue];
  }));
  requireCondition(canonicalJson(outputs) ===
    canonicalJson(expectedOutputs(contract.template, contract.context)) &&
    Object.keys(outputs).length === stack.Outputs.length, code);
  requireCondition(allowedKeys(stack.DriftInformation,
    ["LastCheckTimestamp", "StackDriftStatus"], ["StackDriftStatus"]) &&
    ["IN_SYNC", "DRIFTED"].includes(
      stack.DriftInformation.StackDriftStatus), code);
  if (Object.hasOwn(stack.DriftInformation, "LastCheckTimestamp")) {
    parseProviderInstant(stack.DriftInformation.LastCheckTimestamp,
      observedAt, code);
  }
  return deepFreeze({
    createdAt: new Date(Date.parse(stack.CreationTime)).toISOString(),
    driftStatus: stack.DriftInformation.StackDriftStatus,
    stackId: stack.StackId,
    stackIdSha256: digest({
      schemaVersion: STACK_ID_SCHEMA,
      stackId: stack.StackId
    })
  });
}

function expectedPhysicalId(logicalId, context) {
  if (logicalId === "ReleaseControlTable") return TABLE_NAME;
  if (logicalId === "CloudFormationPermissionsBoundary") {
    return context.boundaryArn;
  }
  return ROLE_NAMES[logicalId];
}

function validateInventory(value, contract, stack, observedAt) {
  const code = "BOOTSTRAP_READBACK_RESOURCE_INVENTORY_REJECTED";
  requireCondition(exactKeys(value, ["StackResourceSummaries"]) &&
    Array.isArray(value.StackResourceSummaries) &&
    value.StackResourceSummaries.length === 10, code);
  const inventory = value.StackResourceSummaries.map((resource) => {
    requireCondition(allowedKeys(resource, [
      "DriftInformation", "LastUpdatedTimestamp", "LogicalResourceId",
      "PhysicalResourceId", "ResourceStatus", "ResourceType"
    ], ["DriftInformation", "LastUpdatedTimestamp", "LogicalResourceId",
      "PhysicalResourceId", "ResourceStatus", "ResourceType"]), code);
    const logicalId = resource.LogicalResourceId;
    requireCondition(Object.hasOwn(RESOURCE_TYPES, logicalId) &&
      resource.ResourceType === RESOURCE_TYPES[logicalId] &&
      resource.PhysicalResourceId ===
        expectedPhysicalId(logicalId, contract.context) &&
      resource.ResourceStatus === "CREATE_COMPLETE" &&
      exactKeys(resource.DriftInformation, ["StackResourceDriftStatus"]) &&
      ["IN_SYNC", "MODIFIED"].includes(
        resource.DriftInformation.StackResourceDriftStatus) &&
      (resource.DriftInformation.StackResourceDriftStatus === "MODIFIED") ===
        (logicalId === "ReleaseControlTable" && stack.driftStatus === "DRIFTED"),
    code);
    parseProviderInstant(resource.LastUpdatedTimestamp, observedAt, code);
    return {
      logicalId,
      physicalId: resource.PhysicalResourceId,
      resourceType: resource.ResourceType,
      status: resource.ResourceStatus
    };
  }).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  requireCondition(new Set(inventory.map(({ logicalId }) => logicalId)).size ===
    10 && Object.keys(RESOURCE_TYPES).every((logicalId) =>
      inventory.some((entry) => entry.logicalId === logicalId)), code);
  return deepFreeze({
    count: 10,
    inventory,
    inventorySha256: digest(inventory)
  });
}

function validateKmsKey(value, accountId, kmsArn, observedAt) {
  const code = "BOOTSTRAP_READBACK_TABLE_KMS_REJECTED";
  requireCondition(exactKeys(value, ["KeyMetadata"]), code);
  const metadata = value.KeyMetadata;
  requireCondition(allowedKeys(metadata, [
    "AWSAccountId", "Arn", "CreationDate", "CurrentKeyMaterialId",
    "CustomerMasterKeySpec", "Description", "Enabled",
    "EncryptionAlgorithms", "KeyId", "KeyManager", "KeySpec", "KeyState",
    "KeyUsage", "MultiRegion", "Origin"
  ], ["AWSAccountId", "Arn", "CustomerMasterKeySpec", "Enabled",
    "EncryptionAlgorithms", "KeyId", "KeyManager", "KeySpec", "KeyState",
    "KeyUsage", "MultiRegion", "Origin"]), code);
  requireCondition(metadata.AWSAccountId === accountId &&
    metadata.Arn === kmsArn && kmsArn.endsWith(`:key/${metadata.KeyId}`) &&
    UUID.test(metadata.KeyId ?? "") && metadata.Enabled === true &&
    metadata.KeyState === "Enabled" && metadata.KeyUsage === "ENCRYPT_DECRYPT" &&
    metadata.Origin === "AWS_KMS" && metadata.KeyManager === "AWS" &&
    metadata.KeySpec === "SYMMETRIC_DEFAULT" &&
    metadata.CustomerMasterKeySpec === "SYMMETRIC_DEFAULT" &&
    metadata.MultiRegion === false &&
    canonicalJson(metadata.EncryptionAlgorithms) ===
      canonicalJson(["SYMMETRIC_DEFAULT"]), code);
  if (Object.hasOwn(metadata, "CreationDate")) {
    parseProviderInstant(metadata.CreationDate, observedAt, code);
  }
  if (Object.hasOwn(metadata, "CurrentKeyMaterialId")) {
    requireCondition(HEX_64.test(metadata.CurrentKeyMaterialId), code);
  }
  return digest({
    arn: kmsArn,
    keyId: metadata.KeyId,
    keyManager: metadata.KeyManager,
    keySpec: metadata.KeySpec
  });
}

function validateTable(responses, contract, observedAt) {
  const code = "BOOTSTRAP_READBACK_TABLE_REJECTED";
  let identity;
  try {
    identity = attestReleaseControlTable({
      describeResponse: responses.describeTable,
      expectedAccountId: contract.context.accountId,
      listTagsResponse: responses.listTableTags,
      region: REGION
    });
  } catch (error) {
    reject(code, error);
  }
  const table = responses.describeTable.Table;
  const expectedTags = sortedTags(
    contract.template.Resources.ReleaseControlTable.Properties.Tags,
    code
  );
  const actualTags = sortedTags(responses.listTableTags.Tags, code);
  requireCondition(table.ItemCount === 0 && table.TableSizeBytes === 0 &&
    exactKeys(responses.listTableTags, ["Tags"]) &&
    canonicalJson(actualTags) === canonicalJson(expectedTags) &&
    contract.template.Resources.ReleaseControlTable.DeletionPolicy === "Retain" &&
    contract.template.Resources.ReleaseControlTable.UpdateReplacePolicy === "Retain",
  code);
  const kmsKeySha256 = validateKmsKey(
    responses.describeKmsKey,
    contract.context.accountId,
    table.SSEDescription.KMSMasterKeyArn,
    observedAt
  );
  return deepFreeze({
    ...identity,
    kmsKeySha256,
    retention: "RETAIN",
    updateReplaceRetention: "RETAIN"
  });
}

function validateBoundary(value, contract, observedAt) {
  const code = "BOOTSTRAP_READBACK_BOUNDARY_REJECTED";
  requireCondition(exactKeys(value, [
    "getPolicy", "getPolicyVersion", "listEntitiesForPolicy",
    "listPolicyVersions"
  ]), code);
  requireCondition(exactKeys(value.getPolicy, ["Policy"]) &&
    exactKeys(value.getPolicyVersion, ["PolicyVersion"]) &&
    plainObject(value.listPolicyVersions) &&
    plainObject(value.listEntitiesForPolicy), code);
  untruncatedEnvelope(value.listPolicyVersions, ["Versions"], code);
  untruncatedEnvelope(value.listEntitiesForPolicy,
    ["PolicyGroups", "PolicyRoles", "PolicyUsers"], code);
  const policy = value.getPolicy.Policy;
  requireCondition(allowedKeys(policy, [
    "Arn", "AttachmentCount", "CreateDate", "DefaultVersionId",
    "Description", "IsAttachable", "Path", "PermissionsBoundaryUsageCount",
    "PolicyId", "PolicyName", "Tags", "UpdateDate"
  ], ["Arn", "AttachmentCount", "CreateDate", "DefaultVersionId",
    "Description", "IsAttachable", "Path", "PermissionsBoundaryUsageCount",
    "PolicyId", "PolicyName", "Tags", "UpdateDate"]), code);
  const boundaryProperties = contract.template.Resources
    .CloudFormationPermissionsBoundary.Properties;
  requireCondition(policy.PolicyName === BOUNDARY_NAME &&
    policy.Arn === contract.context.boundaryArn && policy.Path === "/" &&
    POLICY_ID.test(policy.PolicyId ?? "") &&
    VERSION_ID.test(policy.DefaultVersionId ?? "") &&
    policy.AttachmentCount === 0 &&
    policy.PermissionsBoundaryUsageCount === 1 &&
    policy.IsAttachable === true &&
    policy.Description === boundaryProperties.Description &&
    canonicalJson(policy.Tags) === "[]", code);
  parseProviderInstant(policy.CreateDate, observedAt, code);
  parseProviderInstant(policy.UpdateDate, observedAt, code);
  const policyVersion = value.getPolicyVersion.PolicyVersion;
  requireCondition(allowedKeys(policyVersion, [
    "CreateDate", "Document", "IsDefaultVersion", "VersionId"
  ], ["CreateDate", "Document", "IsDefaultVersion", "VersionId"]) &&
    policyVersion.VersionId === policy.DefaultVersionId &&
    policyVersion.IsDefaultVersion === true &&
    canonicalJson(policyVersion.Document) === canonicalJson(contract.boundary),
  code);
  parseProviderInstant(policyVersion.CreateDate, observedAt, code);
  requireCondition(Array.isArray(value.listPolicyVersions.Versions) &&
    value.listPolicyVersions.Versions.length === 1 &&
    allowedKeys(value.listPolicyVersions.Versions[0],
      ["CreateDate", "IsDefaultVersion", "VersionId"],
      ["CreateDate", "IsDefaultVersion", "VersionId"]) &&
    value.listPolicyVersions.Versions[0].VersionId ===
      policy.DefaultVersionId &&
    value.listPolicyVersions.Versions[0].IsDefaultVersion === true, code);
  parseProviderInstant(
    value.listPolicyVersions.Versions[0].CreateDate,
    observedAt,
    code
  );
  const entities = value.listEntitiesForPolicy;
  requireCondition(canonicalJson(entities.PolicyGroups) === "[]" &&
    canonicalJson(entities.PolicyUsers) === "[]" &&
    Array.isArray(entities.PolicyRoles) && entities.PolicyRoles.length === 1 &&
    exactKeys(entities.PolicyRoles[0], ["RoleId", "RoleName"]) &&
    entities.PolicyRoles[0].RoleName ===
      ROLE_NAMES.CloudFormationServiceRole &&
    ROLE_ID.test(entities.PolicyRoles[0].RoleId ?? ""), code);
  return deepFreeze({
    arn: policy.Arn,
    policyId: policy.PolicyId,
    resolvedPolicySha256: digest(policyVersion.Document),
    sourcePolicySha256: SOURCE_BOUNDARY_SHA256,
    versionId: policy.DefaultVersionId
  });
}

function validateRoleReadback(value, expected, logicalId, boundary, observedAt) {
  const code = "BOOTSTRAP_READBACK_ROLE_REJECTED";
  requireCondition(exactKeys(value, [
    "getRole", "getRolePolicy", "listAttachedRolePolicies",
    "listInstanceProfilesForRole", "listRolePolicies", "listRoleTags"
  ]) && exactKeys(value.getRole, ["Role"]) &&
    exactKeys(value.getRolePolicy,
      ["PolicyDocument", "PolicyName", "RoleName"]) &&
    plainObject(value.listAttachedRolePolicies) &&
    plainObject(value.listInstanceProfilesForRole) &&
    plainObject(value.listRolePolicies) && plainObject(value.listRoleTags),
  code);
  untruncatedEnvelope(value.listAttachedRolePolicies,
    ["AttachedPolicies"], code);
  untruncatedEnvelope(value.listInstanceProfilesForRole,
    ["InstanceProfiles"], code);
  untruncatedEnvelope(value.listRolePolicies, ["PolicyNames"], code);
  untruncatedEnvelope(value.listRoleTags, ["Tags"], code);
  const role = value.getRole.Role;
  const roleKeys = [
    "Arn", "AssumeRolePolicyDocument", "CreateDate", "Description",
    "MaxSessionDuration", "Path", "RoleId", "RoleLastUsed", "RoleName", "Tags"
  ];
  if (logicalId === "CloudFormationServiceRole") {
    roleKeys.push("PermissionsBoundary");
  }
  requireCondition(exactKeys(role, roleKeys) && role.Path === "/" &&
    role.RoleName === expected.roleName && role.Arn === expected.arn &&
    ROLE_ID.test(role.RoleId ?? "") &&
    role.Description === expected.description &&
    role.MaxSessionDuration === expected.maxSessionDuration &&
    canonicalJson(role.AssumeRolePolicyDocument) ===
      canonicalJson(expected.trust) &&
    canonicalJson(sortedTags(role.Tags, code)) === canonicalJson(expected.tags) &&
    canonicalJson(sortedTags(value.listRoleTags.Tags, code)) ===
      canonicalJson(expected.tags) &&
    canonicalJson(value.listRolePolicies.PolicyNames) ===
      canonicalJson([expected.policyName]) &&
    canonicalJson(value.listAttachedRolePolicies.AttachedPolicies) === "[]" &&
    canonicalJson(value.listInstanceProfilesForRole.InstanceProfiles) === "[]",
  code);
  parseProviderInstant(role.CreateDate, observedAt, code);
  requireCondition(plainObject(role.RoleLastUsed), code);
  if (Object.keys(role.RoleLastUsed).length > 0) {
    requireCondition(exactKeys(role.RoleLastUsed,
      ["LastUsedDate", "Region"]) &&
      typeof role.RoleLastUsed.Region === "string" &&
      role.RoleLastUsed.Region.length > 0, code);
    parseProviderInstant(role.RoleLastUsed.LastUsedDate, observedAt, code);
  }
  const policy = value.getRolePolicy;
  requireCondition(policy.RoleName === expected.roleName &&
    policy.PolicyName === expected.policyName &&
    canonicalJson(policy.PolicyDocument) === canonicalJson(expected.inlinePolicy),
  code);
  if (logicalId === "CloudFormationServiceRole") {
    requireCondition(exactKeys(role.PermissionsBoundary,
      ["PermissionsBoundaryArn", "PermissionsBoundaryType"]) &&
      role.PermissionsBoundary.PermissionsBoundaryArn === boundary.arn &&
      role.PermissionsBoundary.PermissionsBoundaryType === "Policy", code);
  }
  return deepFreeze({
    arn: role.Arn,
    inlinePolicySha256: digest(policy.PolicyDocument),
    logicalId,
    policyName: policy.PolicyName,
    roleId: role.RoleId,
    roleName: role.RoleName,
    tagsSha256: digest(expected.tags),
    trustSha256: digest(role.AssumeRolePolicyDocument)
  });
}

function validateRoles(value, contract, boundary, observedAt) {
  const code = "BOOTSTRAP_READBACK_ROLES_REJECTED";
  requireCondition(exactKeys(value, Object.keys(ROLE_NAMES)), code);
  const roles = Object.entries(ROLE_NAMES).map(([logicalId]) =>
    validateRoleReadback(
      value[logicalId],
      contract.roles[logicalId],
      logicalId,
      boundary,
      observedAt
    )
  ).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  requireCondition(roles.length === 8 &&
    new Set(roles.map(({ arn }) => arn)).size === 8 &&
    new Set(roles.map(({ roleId }) => roleId)).size === 8, code);
  return deepFreeze({
    count: 8,
    roles,
    rolesSha256: digest(roles)
  });
}

function validateDriftEntry(entry, expected, stackId, observedAt) {
  const code = "BOOTSTRAP_READBACK_DRIFT_REJECTED";
  requireCondition(allowedKeys(entry, [
    "ActualProperties", "ExpectedProperties", "LogicalResourceId",
    "PhysicalResourceId", "PropertyDifferences", "ResourceType", "StackId",
    "StackResourceDriftStatus", "Timestamp"
  ], ["ActualProperties", "ExpectedProperties", "LogicalResourceId",
    "PhysicalResourceId", "PropertyDifferences", "ResourceType", "StackId",
    "StackResourceDriftStatus", "Timestamp"]) &&
    entry.StackId === stackId && entry.LogicalResourceId === expected.logicalId &&
    entry.PhysicalResourceId === expected.physicalId &&
    entry.ResourceType === expected.resourceType, code);
  parseProviderInstant(entry.Timestamp, observedAt, code);
}

function validateKnownTableNormalization(entry, table) {
  const code = "BOOTSTRAP_READBACK_DRIFT_REJECTED";
  requireCondition(entry.StackResourceDriftStatus === "MODIFIED" &&
    Array.isArray(entry.PropertyDifferences) &&
    entry.PropertyDifferences.length === 1 &&
    exactKeys(entry.PropertyDifferences[0], [
      "ActualValue", "DifferenceType", "ExpectedValue", "PropertyPath"
    ]) &&
    entry.PropertyDifferences[0].PropertyPath ===
      "/SSESpecification/KMSMasterKeyId" &&
    entry.PropertyDifferences[0].DifferenceType === "NOT_EQUAL" &&
    [DYNAMODB_KMS_SOURCE_ALIAS,
      CLOUDFORMATION_KMS_SUMMARY_SENTINEL].includes(
      entry.PropertyDifferences[0].ExpectedValue
    ) &&
    entry.PropertyDifferences[0].ActualValue ===
      table.SSEDescription.KMSMasterKeyArn, code);
  let expectedProperties;
  let actualProperties;
  try {
    expectedProperties = JSON.parse(entry.ExpectedProperties);
    actualProperties = JSON.parse(entry.ActualProperties);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(expectedProperties.SSESpecification.KMSMasterKeyId ===
    DYNAMODB_KMS_SOURCE_ALIAS, code);
  expectedProperties.SSESpecification.KMSMasterKeyId =
    table.SSEDescription.KMSMasterKeyArn;
  expectedProperties.Tags = sortedTags(expectedProperties.Tags, code);
  actualProperties.Tags = sortedTags(actualProperties.Tags, code);
  requireCondition(canonicalJson(expectedProperties) ===
    canonicalJson(actualProperties), code);
  return deepFreeze({
    summaryExpectedValue: entry.PropertyDifferences[0].ExpectedValue,
    summaryExpectedValueDisposition:
      entry.PropertyDifferences[0].ExpectedValue === DYNAMODB_KMS_SOURCE_ALIAS
        ? "SOURCE_ALIAS"
        : "AWS_CLOUDFORMATION_KMS_ARN_PATTERN_SENTINEL"
  });
}

function validateDrift(responses, inventory, stack, table, observedAt) {
  const code = "BOOTSTRAP_READBACK_DRIFT_REJECTED";
  const list = responses.listStackResourceDrifts;
  requireCondition(exactKeys(list, ["StackResourceDrifts"]) &&
    Array.isArray(list.StackResourceDrifts) &&
    list.StackResourceDrifts.length === 10, code);
  const byLogicalId = new Map(list.StackResourceDrifts.map((entry) =>
    [entry.LogicalResourceId, entry]));
  requireCondition(byLogicalId.size === 10, code);
  let knownNormalization = null;
  for (const expected of inventory.inventory) {
    const entry = byLogicalId.get(expected.logicalId);
    validateDriftEntry(entry, expected, stack.stackId, observedAt);
    if (expected.logicalId === "ReleaseControlTable" &&
      stack.driftStatus === "DRIFTED") {
      knownNormalization = validateKnownTableNormalization(entry, table);
    } else {
      requireCondition(entry.StackResourceDriftStatus === "IN_SYNC" &&
        canonicalJson(entry.PropertyDifferences) === "[]", code);
    }
  }
  requireCondition(list.StackResourceDrifts.filter((entry) =>
    entry.StackResourceDriftStatus !== "IN_SYNC").length ===
      (stack.driftStatus === "DRIFTED" ? 1 : 0), code);
  return deepFreeze({
    disposition: stack.driftStatus === "DRIFTED"
      ? "KNOWN_DYNAMODB_AWS_MANAGED_KMS_NORMALIZATION_ONLY"
      : "IN_SYNC",
    sourceExpectedKmsAlias: DYNAMODB_KMS_SOURCE_ALIAS,
    summaryExpectedValue: knownNormalization?.summaryExpectedValue ?? null,
    summaryExpectedValueDisposition:
      knownNormalization?.summaryExpectedValueDisposition ?? "NOT_APPLICABLE"
  });
}

function buildSimulationVectors(accountId, artifactBucketName) {
  requireCondition(ACCOUNT_ID.test(accountId ?? "") &&
    typeof artifactBucketName === "string" &&
    artifactBucketName.length >= 3 && artifactBucketName.length <= 63 &&
    BUCKET_NAME.test(artifactBucketName),
  "BOOTSTRAP_READBACK_IAM_SIMULATION_PLAN_REJECTED");
  const context = resolvedContext(accountId, artifactBucketName);
  const table = context.tableArn;
  const lambda = `arn:aws:lambda:${REGION}:${accountId}:function:` +
    "prooftoact-gate2-negative";
  const stack = `arn:aws:cloudformation:${REGION}:${accountId}:stack/` +
    "prooftoact-gate2/00000000-0000-4000-8000-000000000000";
  const changeSet = `arn:aws:cloudformation:${REGION}:${accountId}:changeSet/` +
    "prooftoact-release-negative/00000000-0000-4000-8000-000000000000";
  const entries = {
    CloudFormationServiceRole: {
      positive: ["s3:GetObjectVersion",
        `arn:aws:s3:::${artifactBucketName}/gate2/bootstrap-readback-probe`],
      negative: ["iam:CreateUser",
        `arn:aws:iam::${accountId}:user/prooftoact-bootstrap-negative`],
      boundary: true
    },
    LiveDrillOperatorRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["cloudformation:ExecuteChangeSet", changeSet]
    },
    ReleaseCoordinatorRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["lambda:InvokeFunction", lambda]
    },
    ReleaseDeploymentRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["cloudformation:ExecuteChangeSet", changeSet]
    },
    ReleaseEvidenceRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["dynamodb:UpdateItem", table]
    },
    ReleaseExecutionRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["cloudformation:CreateChangeSet", stack]
    },
    ReleaseTeardownRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["lambda:InvokeFunction", lambda]
    },
    ReleaseTerminalizerRole: {
      positive: ["dynamodb:DescribeTable", table],
      negative: ["s3:PutObject",
        `arn:aws:s3:::${artifactBucketName}/gate2/negative`]
    }
  };
  return deepFreeze(Object.fromEntries(Object.entries(entries).map(
    ([logicalId, value]) => [logicalId, {
      negative: {
        ActionNames: [value.negative[0]],
        PolicySourceArn: context.roleArn(logicalId),
        ResourceArns: [value.negative[1]]
      },
      positive: {
        ActionNames: [value.positive[0]],
        PolicySourceArn: context.roleArn(logicalId),
        ResourceArns: [value.positive[1]]
      },
      permissionsBoundaryExpected: value.boundary === true
    }]
  )));
}

function validateSimulationResult(response, request, decision, boundaryExpected) {
  const code = "BOOTSTRAP_READBACK_IAM_SIMULATION_REJECTED";
  requireCondition(allowedKeys(response, ["EvaluationResults", "IsTruncated"],
    ["EvaluationResults", "IsTruncated"]) &&
    response.IsTruncated === false &&
    Array.isArray(response.EvaluationResults) &&
    response.EvaluationResults.length === 1, code);
  const result = response.EvaluationResults[0];
  requireCondition(allowedKeys(result, [
    "EvalActionName", "EvalDecision", "EvalDecisionDetails",
    "EvalResourceName", "MatchedStatements", "MissingContextValues",
    "OrganizationsDecisionDetail", "PermissionsBoundaryDecisionDetail",
    "ResourceSpecificResults"
  ], ["EvalActionName", "EvalDecision", "EvalResourceName"]) &&
    result.EvalActionName === request.ActionNames[0] &&
    result.EvalResourceName === request.ResourceArns[0] &&
    result.EvalDecision === decision &&
    (!Object.hasOwn(result, "MissingContextValues") ||
      canonicalJson(result.MissingContextValues) === "[]"), code);
  if (boundaryExpected) {
    requireCondition(exactKeys(result.PermissionsBoundaryDecisionDetail,
      ["AllowedByPermissionsBoundary"]) &&
      result.PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary ===
        (decision === "allowed"), code);
  } else {
    requireCondition(!Object.hasOwn(result,
      "PermissionsBoundaryDecisionDetail") ||
      (exactKeys(result.PermissionsBoundaryDecisionDetail,
        ["AllowedByPermissionsBoundary"]) &&
        result.PermissionsBoundaryDecisionDetail
          .AllowedByPermissionsBoundary === true), code);
  }
  return {
    actionName: result.EvalActionName,
    decision: result.EvalDecision,
    resourceSha256: digest(result.EvalResourceName)
  };
}

function validateSimulations(value, contract) {
  const code = "BOOTSTRAP_READBACK_IAM_SIMULATION_REJECTED";
  const plan = buildSimulationVectors(
    contract.context.accountId,
    contract.context.artifactBucketName
  );
  requireCondition(exactKeys(value, Object.keys(ROLE_NAMES)), code);
  const results = [];
  for (const logicalId of Object.keys(ROLE_NAMES).sort()) {
    const simulation = value[logicalId];
    requireCondition(exactKeys(simulation,
      ["negative", "positive"]), code);
    for (const kind of ["negative", "positive"]) {
      const call = simulation[kind];
      requireCondition(exactKeys(call, ["request", "response"]) &&
        canonicalJson(call.request) === canonicalJson(plan[logicalId][kind]),
      code);
      results.push({
        kind,
        logicalId,
        ...validateSimulationResult(
          call.response,
          call.request,
          kind === "positive" ? "allowed" : "explicitDeny",
          plan[logicalId].permissionsBoundaryExpected
        )
      });
    }
  }
  return deepFreeze({
    allNamedNegativeActionsExplicitlyDenied: true,
    allNamedPositiveActionsAllowed: true,
    checkCount: results.length,
    checksSha256: digest(results),
    callerSuppliedResponsesValidated: true,
    permissionsBoundaryEffective: true,
    readbackPrincipalIndependenceProven: false
  });
}

function receiptBody(input, templateBytes) {
  const code = "BOOTSTRAP_READBACK_INPUT_REJECTED";
  requireCondition(exactKeys(input, [
    "accountId", "artifactBucketName", "observedAt",
    "providerMutationAbsenceCallerAsserted", "readOnlyCollectionCallerAsserted",
    "region", "responses", "schemaVersion"
  ]) && input.schemaVersion === INPUT_SCHEMA &&
    ACCOUNT_ID.test(input.accountId ?? "") &&
    typeof input.artifactBucketName === "string" &&
    input.artifactBucketName.length >= 3 &&
    input.artifactBucketName.length <= 63 &&
    BUCKET_NAME.test(input.artifactBucketName) && input.region === REGION &&
    input.readOnlyCollectionCallerAsserted === true &&
    input.providerMutationAbsenceCallerAsserted === true &&
    exactKeys(input.responses, RESPONSE_KEYS), code);
  const observedAt = canonicalInstant(input.observedAt, code);
  requireCondition(Buffer.isBuffer(templateBytes), code);
  const contract = buildContract(
    templateBytes,
    input.accountId,
    input.artifactBucketName
  );
  requireCondition(canonicalJson(input.responses.deployedTemplate) ===
    canonicalJson(contract.template),
  "BOOTSTRAP_READBACK_DEPLOYED_TEMPLATE_REJECTED");
  const callerArn = validateCaller(input.responses.callerIdentity,
    input.accountId);
  const stack = validateStack(input.responses.stack, contract, observedAt);
  const inventory = validateInventory(input.responses.listStackResources,
    contract, stack, observedAt);
  const table = validateTable(input.responses, contract, observedAt);
  const boundary = validateBoundary(input.responses.boundary,
    contract, observedAt);
  const roles = validateRoles(input.responses.roles, contract,
    boundary, observedAt);
  requireCondition(roles.roles.find(({ logicalId }) =>
    logicalId === "CloudFormationServiceRole")?.roleId ===
      input.responses.boundary.listEntitiesForPolicy.PolicyRoles[0].RoleId,
  "BOOTSTRAP_READBACK_BOUNDARY_ROLE_BINDING_REJECTED");
  const drift = validateDrift(input.responses, inventory, stack,
    input.responses.describeTable.Table, observedAt);
  const iamSimulation = validateSimulations(input.responses.simulations,
    contract);
  return deepFreeze({
    schemaVersion: RECEIPT_SCHEMA,
    status: STATUS,
    evidenceLevel: "CALLER_SUPPLIED_AWS_RESPONSE_SEMANTICS_VALIDATED",
    observedAt: input.observedAt,
    account: {
      accountId: input.accountId,
      callerArnSha256: digest(callerArn),
      partition: "aws"
    },
    region: REGION,
    stack: {
      createdAt: stack.createdAt,
      driftDisposition: drift.disposition,
      driftSourceExpectedKmsAlias: drift.sourceExpectedKmsAlias,
      driftSummaryExpectedValue: drift.summaryExpectedValue,
      driftSummaryExpectedValueDisposition:
        drift.summaryExpectedValueDisposition,
      idSha256: stack.stackIdSha256,
      name: STACK_NAME,
      status: "CREATE_COMPLETE"
    },
    template: {
      deployedCanonicalSha256: digest(input.responses.deployedTemplate),
      sourceBytesSha256: TEMPLATE_SHA256,
      tableDeletionPolicy: "Retain",
      tableUpdateReplacePolicy: "Retain"
    },
    inventory,
    table,
    boundary,
    roles,
    iamSimulation,
    collectionBoundary: collectionBoundary(),
    providerResponseSetSha256: digest(input.responses),
    claimBoundary: {
      applicationDeploymentProven: false,
      providerMutationAuthorized: false,
      providerMutationAbsenceCallerAsserted: true,
      providerMutationAbsenceIndependentlyProven: false,
      providerResponsesCallerSupplied: true,
      providerResponseSemanticsVerified: true,
      publicReleaseAuthorized: false,
      rawCollectorBundleRequiredForPublication: true,
      submissionAuthorized: false
    }
  });
}

export function buildReleaseControlBootstrapReadbackReceipt({
  input,
  templateBytes
}) {
  const body = receiptBody(input, templateBytes);
  return deepFreeze({
    ...body,
    receiptSha256: digest(body)
  });
}

function validReceiptDriftLabel(stack) {
  if (!plainObject(stack) ||
    stack.driftSourceExpectedKmsAlias !== DYNAMODB_KMS_SOURCE_ALIAS) {
    return false;
  }
  if (stack.driftDisposition === "IN_SYNC") {
    return stack.driftSummaryExpectedValue === null &&
      stack.driftSummaryExpectedValueDisposition === "NOT_APPLICABLE";
  }
  if (stack.driftDisposition !==
    "KNOWN_DYNAMODB_AWS_MANAGED_KMS_NORMALIZATION_ONLY") {
    return false;
  }
  return (stack.driftSummaryExpectedValue === DYNAMODB_KMS_SOURCE_ALIAS &&
      stack.driftSummaryExpectedValueDisposition === "SOURCE_ALIAS") ||
    (stack.driftSummaryExpectedValue ===
      CLOUDFORMATION_KMS_SUMMARY_SENTINEL &&
      stack.driftSummaryExpectedValueDisposition ===
        "AWS_CLOUDFORMATION_KMS_ARN_PATTERN_SENTINEL");
}

export function verifyReleaseControlBootstrapReadbackReceipt({
  accountId,
  receipt,
  templateBytes
}) {
  const code = "BOOTSTRAP_READBACK_RECEIPT_REJECTED";
  requireCondition(ACCOUNT_ID.test(accountId ?? "") &&
    Buffer.isBuffer(templateBytes) &&
    validateBootstrapTemplateBytes(templateBytes).sha256 === TEMPLATE_SHA256 &&
    plainObject(receipt), code);
  const { receiptSha256, ...body } = receipt;
  requireCondition(HEX_64.test(receiptSha256 ?? "") &&
    receiptSha256 === digest(body) && body.schemaVersion === RECEIPT_SCHEMA &&
    body.status === STATUS && body.account?.accountId === accountId &&
    body.region === REGION && body.stack?.name === STACK_NAME &&
    body.stack?.status === "CREATE_COMPLETE" &&
    validReceiptDriftLabel(body.stack) &&
    HEX_64.test(body.stack?.idSha256 ?? "") &&
    body.template?.sourceBytesSha256 === TEMPLATE_SHA256 &&
    body.template?.tableDeletionPolicy === "Retain" &&
    body.template?.tableUpdateReplacePolicy === "Retain" &&
    body.inventory?.count === 10 && body.roles?.count === 8 &&
    UUID.test(body.table?.tableId ?? "") &&
    body.table?.deletionProtectionEnabled === true &&
    body.table?.retention === "RETAIN" &&
    body.boundary?.sourcePolicySha256 === SOURCE_BOUNDARY_SHA256 &&
    body.iamSimulation?.checkCount === 16 &&
    body.iamSimulation?.allNamedPositiveActionsAllowed === true &&
    body.iamSimulation?.allNamedNegativeActionsExplicitlyDenied === true &&
    body.iamSimulation?.callerSuppliedResponsesValidated === true &&
    body.iamSimulation?.permissionsBoundaryEffective === true &&
    body.iamSimulation?.readbackPrincipalIndependenceProven === false &&
    canonicalJson(body.collectionBoundary) ===
      canonicalJson(collectionBoundary()) &&
    body.claimBoundary?.providerMutationAuthorized === false &&
    body.claimBoundary?.providerMutationAbsenceCallerAsserted === true &&
    body.claimBoundary?.providerMutationAbsenceIndependentlyProven === false &&
    body.claimBoundary?.providerResponsesCallerSupplied === true &&
    body.claimBoundary?.providerResponseSemanticsVerified === true &&
    body.claimBoundary?.applicationDeploymentProven === false &&
    body.claimBoundary?.publicReleaseAuthorized === false &&
    body.claimBoundary?.rawCollectorBundleRequiredForPublication === true &&
    body.claimBoundary?.submissionAuthorized === false, code);
  canonicalInstant(body.observedAt, code);
  return receipt;
}

export function bootstrapPrepareEnvironmentValues({
  accountId,
  receipt,
  templateBytes
}) {
  verifyReleaseControlBootstrapReadbackReceipt({
    accountId,
    receipt,
    templateBytes
  });
  const values = {
    PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256: receipt.receiptSha256,
    PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256: receipt.stack.idSha256,
    PROOFTOACT_RELEASE_BOOTSTRAP_STATUS: STATUS,
    PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256: TEMPLATE_SHA256,
    PROOFTOACT_RELEASE_CONTROL_TABLE_ID: receipt.table.tableId
  };
  requireCondition(exactKeys(values, ENVIRONMENT_KEYS) &&
    Object.values(values).every((value) =>
      typeof value === "string" && value.length > 0),
  "BOOTSTRAP_READBACK_ENVIRONMENT_VALUES_REJECTED");
  return deepFreeze(values);
}

export function buildBootstrapIamSimulationPlan({
  accountId,
  artifactBucketName
}) {
  requireCondition(ACCOUNT_ID.test(accountId ?? "") &&
    typeof artifactBucketName === "string" &&
    artifactBucketName.length >= 3 && artifactBucketName.length <= 63 &&
    BUCKET_NAME.test(artifactBucketName),
  "BOOTSTRAP_READBACK_IAM_SIMULATION_PLAN_REJECTED");
  return buildSimulationVectors(accountId, artifactBucketName);
}

export function renderBootstrapIamSimulationCommands({
  accountId,
  artifactBucketName
}) {
  const plan = buildBootstrapIamSimulationPlan({
    accountId,
    artifactBucketName
  });
  const lines = [];
  for (const logicalId of Object.keys(plan).sort()) {
    for (const kind of ["positive", "negative"]) {
      const request = plan[logicalId][kind];
      lines.push("aws iam simulate-principal-policy" +
        ` --policy-source-arn '${request.PolicySourceArn}'` +
        ` --action-names '${request.ActionNames[0]}'` +
        ` --resource-arns '${request.ResourceArns[0]}'` +
        " --no-cli-pager --output json" +
        ` > '${logicalId}-${kind}.json'`);
    }
  }
  return `${lines.join("\n")}\n`;
}

export const bootstrapReadbackConstants = Object.freeze({
  BOUNDARY_NAME,
  CLOUDFORMATION_KMS_SUMMARY_SENTINEL,
  DYNAMODB_KMS_SOURCE_ALIAS,
  ENVIRONMENT_KEYS,
  INPUT_SCHEMA,
  RECEIPT_SCHEMA,
  REGION,
  ROLE_NAMES,
  STACK_ID_SCHEMA,
  STACK_NAME,
  STATUS,
  TABLE_NAME,
  TEMPLATE_SHA256
});

export const __test = Object.freeze({
  buildContract,
  canonicalBytes,
  canonicalJson,
  digest,
  resolveIntrinsic,
  sha256,
  sortedTags
});

const DIRECTORY_RESPONSE_FILES = Object.freeze({
  callerIdentity: "caller.json",
  deployedTemplate: "deployed-template.json",
  describeKmsKey: "dynamodb-kms-key.json",
  describeTable: "table.json",
  listStackResourceDrifts: "resource-drifts.json",
  listStackResources: "resources.json",
  listTableTags: "table-tags.json",
  stack: "stack.json"
});

const BOUNDARY_DIRECTORY_FILES = Object.freeze({
  getPolicy: "boundary.json",
  getPolicyVersion: "boundary-version.json",
  listEntitiesForPolicy: "boundary-entities.json",
  listPolicyVersions: "boundary-versions.json"
});

const ROLE_DIRECTORY_FILES = Object.freeze({
  getRole: "role.json",
  getRolePolicy: "inline-policy.json",
  listAttachedRolePolicies: "attached-list.json",
  listInstanceProfilesForRole: "instance-profiles.json",
  listRolePolicies: "inline-list.json",
  listRoleTags: "tags.json"
});

function checkedDirectory(directoryPath, expectedEntries, code) {
  requireCondition(typeof directoryPath === "string" &&
    path.isAbsolute(directoryPath), code);
  let real;
  let stat;
  try {
    real = fs.realpathSync(directoryPath);
    stat = fs.lstatSync(directoryPath);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(real === path.resolve(directoryPath) && stat.isDirectory() &&
    !stat.isSymbolicLink() &&
    fs.readdirSync(real).sort().join("\n") ===
      [...expectedEntries].sort().join("\n"), code);
  return real;
}

function readDirectoryJson(directory, fileName, code) {
  const filePath = path.join(directory, fileName);
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 &&
    stat.size > 0 && stat.size <= 32 * 1024 * 1024 &&
    fs.realpathSync(filePath) === filePath, code);
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    reject(code, error);
  }
}

function normalizedDeployedTemplate(value, code) {
  if (plainObject(value)) return value;
  requireCondition(typeof value === "string" && value.length > 0 &&
    Buffer.byteLength(value, "utf8") <= 4 * 1024 * 1024, code);
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(plainObject(parsed), code);
  return parsed;
}

export function buildReleaseControlBootstrapReadbackInputFromDirectory({
  accountId,
  artifactBucketName,
  directoryPath,
  observedAt
}) {
  const code = "BOOTSTRAP_READBACK_DIRECTORY_REJECTED";
  requireCondition(ACCOUNT_ID.test(accountId ?? "") &&
    typeof artifactBucketName === "string" &&
    artifactBucketName.length >= 3 && artifactBucketName.length <= 63 &&
    BUCKET_NAME.test(artifactBucketName), code);
  canonicalInstant(observedAt, code);
  const simulationFiles = Object.keys(ROLE_NAMES).flatMap((logicalId) =>
    ["negative", "positive"].map((kind) =>
      `${logicalId}-${kind}.json`));
  const expectedTopLevel = [
    ...Object.values(DIRECTORY_RESPONSE_FILES),
    ...Object.values(BOUNDARY_DIRECTORY_FILES),
    ...Object.values(ROLE_NAMES),
    ...simulationFiles
  ];
  const root = checkedDirectory(directoryPath, expectedTopLevel, code);
  const responses = Object.fromEntries(Object.entries(
    DIRECTORY_RESPONSE_FILES
  ).map(([key, fileName]) => {
    const value = readDirectoryJson(root, fileName, code);
    return [key, key === "deployedTemplate"
      ? normalizedDeployedTemplate(value, code)
      : value];
  }));
  responses.boundary = Object.fromEntries(Object.entries(
    BOUNDARY_DIRECTORY_FILES
  ).map(([key, fileName]) => [key, readDirectoryJson(root, fileName, code)]));
  responses.roles = Object.fromEntries(Object.entries(ROLE_NAMES).map(
    ([logicalId, roleName]) => {
      const roleRoot = checkedDirectory(
        path.join(root, roleName),
        Object.values(ROLE_DIRECTORY_FILES),
        code
      );
      return [logicalId, Object.fromEntries(Object.entries(
        ROLE_DIRECTORY_FILES
      ).map(([key, fileName]) =>
        [key, readDirectoryJson(roleRoot, fileName, code)]))];
    }
  ));
  const plan = buildBootstrapIamSimulationPlan({
    accountId,
    artifactBucketName
  });
  responses.simulations = Object.fromEntries(Object.keys(ROLE_NAMES).map(
    (logicalId) => [logicalId, Object.fromEntries(
      ["negative", "positive"].map((kind) => [kind, {
        request: plan[logicalId][kind],
        response: readDirectoryJson(
          root,
          `${logicalId}-${kind}.json`,
          code
        )
      }])
    )]
  ));
  const input = {
    schemaVersion: INPUT_SCHEMA,
    accountId,
    artifactBucketName,
    observedAt,
    providerMutationAbsenceCallerAsserted: true,
    readOnlyCollectionCallerAsserted: true,
    region: REGION,
    responses
  };
  requireCondition(exactKeys(input.responses, RESPONSE_KEYS), code);
  return deepFreeze(input);
}

function checkedJsonFile(filePath) {
  const code = "BOOTSTRAP_READBACK_CLI_INPUT_REJECTED";
  requireCondition(typeof filePath === "string" && path.isAbsolute(filePath),
    code);
  let real;
  let stat;
  try {
    real = fs.realpathSync(filePath);
    stat = fs.lstatSync(filePath);
  } catch (error) {
    reject(code, error);
  }
  requireCondition(real === path.resolve(filePath) && stat.isFile() &&
    !stat.isSymbolicLink() && stat.nlink === 1 && stat.size > 0 &&
    stat.size <= 32 * 1024 * 1024,
  code);
  try {
    return JSON.parse(fs.readFileSync(real, "utf8"));
  } catch (error) {
    reject(code, error);
  }
}

function runCli(argv) {
  if (argv.length === 3 && argv[0] === "--simulation-plan") {
    const plan = buildBootstrapIamSimulationPlan({
      accountId: argv[1],
      artifactBucketName: argv[2]
    });
    process.stdout.write(`${canonicalJson(plan)}\n`);
    return;
  }
  if (argv.length === 3 && argv[0] === "--simulation-commands") {
    process.stdout.write(renderBootstrapIamSimulationCommands({
      accountId: argv[1],
      artifactBucketName: argv[2]
    }));
    return;
  }
  if (argv.length === 2 && argv[0] === "--verify-input") {
    const templateBytes = fs.readFileSync(new URL(
      "../infra/aws/release-deployment-roles-template.json",
      import.meta.url
    ));
    const input = checkedJsonFile(argv[1]);
    const receipt = buildReleaseControlBootstrapReadbackReceipt({
      input,
      templateBytes
    });
    const environmentVariables = bootstrapPrepareEnvironmentValues({
      accountId: input.accountId,
      receipt,
      templateBytes
    });
    process.stdout.write(`${canonicalJson({
      environmentVariables,
      receipt
    })}\n`);
    return;
  }
  if (argv.length === 5 && argv[0] === "--assemble-directory") {
    const input = buildReleaseControlBootstrapReadbackInputFromDirectory({
      directoryPath: argv[1],
      accountId: argv[2],
      artifactBucketName: argv[3],
      observedAt: argv[4]
    });
    process.stdout.write(`${canonicalJson(input)}\n`);
    return;
  }
  if (argv.length === 5 && argv[0] === "--verify-directory") {
    const templateBytes = fs.readFileSync(new URL(
      "../infra/aws/release-deployment-roles-template.json",
      import.meta.url
    ));
    const input = buildReleaseControlBootstrapReadbackInputFromDirectory({
      directoryPath: argv[1],
      accountId: argv[2],
      artifactBucketName: argv[3],
      observedAt: argv[4]
    });
    const receipt = buildReleaseControlBootstrapReadbackReceipt({
      input,
      templateBytes
    });
    const environmentVariables = bootstrapPrepareEnvironmentValues({
      accountId: input.accountId,
      receipt,
      templateBytes
    });
    process.stdout.write(`${canonicalJson({
      environmentVariables,
      receipt
    })}\n`);
    return;
  }
  reject("BOOTSTRAP_READBACK_CLI_ARGUMENT_REJECTED");
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    const code = /^BOOTSTRAP_READBACK_[A-Z0-9_]{1,100}$/u.test(
      String(error?.message ?? "")
    ) ? error.message : "BOOTSTRAP_READBACK_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  }
}
