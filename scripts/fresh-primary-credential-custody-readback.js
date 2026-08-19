import crypto from "node:crypto";

import {
  buildFreshPrimaryCredentialSealApproval,
  __test as sealerTest
} from "./fresh-primary-credential-sealer.js";
import {
  __test as planTest,
  verifyFreshPrimaryCredentialCustodyPlan
} from "./prepare-fresh-primary-credential-custody.js";
import {
  validateFreshBootstrapCollectorBinding,
  validateFreshBootstrapCollectorCaller
} from "./lib/fresh-bootstrap-collector-binding.js";

const INPUT_SCHEMA =
  "prooftoact.fresh-primary-credential-custody-readback-input.v1";
const RECEIPT_SCHEMA =
  "prooftoact.fresh-primary-credential-custody-readback-receipt.v1";
const ROLE_ID = /^AROA[A-Z0-9]{16}$/u;
const OPAQUE_PRINCIPAL_ID = /^AROA[A-Z0-9]{16}$/u;

const OUTPUT_TO_NAME = Object.freeze({
  AdminSecretArn: "admin",
  AuditorSecretArn: "auditor",
  CloudApiSecretArn: "cloudApi",
  ManagedMcpSecretArn: "mcp",
  RecoveryPublisherSecretArn: "publisher",
  RuntimeCredentialsSecretArn: "credential",
  SignerSecretArn: "signer"
});
const LOGICAL_TO_NAME = Object.freeze({
  FreshPrimaryAdminSecret: "admin",
  FreshClusterAuditorSecret: "auditor",
  FreshPrimaryCloudApiSecret: "cloudApi",
  FreshPrimaryRuntimeCredentialsSecret: "credential",
  ManagedMcpSecret: "mcp",
  RecoveryPublisherSecret: "publisher",
  FreshPrimaryRecoverySignerSecret: "signer"
});

function reject(code) {
  throw new Error(code);
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

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function canonicalInstant(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" && Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

function normalizeTags(value, code) {
  requireCondition(Array.isArray(value), code);
  const tags = {};
  for (const item of value) {
    requireCondition(exactKeys(item, ["Key", "Value"]) &&
      typeof item.Key === "string" && typeof item.Value === "string" &&
      !Object.hasOwn(tags, item.Key), code);
    if (item.Key.startsWith("aws:cloudformation:")) continue;
    requireCondition(!item.Key.startsWith("aws:"), code);
    tags[item.Key] = item.Value;
  }
  return tags;
}

function resolveTemplate(value, context) {
  if (Array.isArray(value)) {
    return value.map((item) => resolveTemplate(item, context));
  }
  if (!plainObject(value)) return value;
  if (exactKeys(value, ["Ref"])) {
    if (Object.hasOwn(context.parameters, value.Ref)) {
      return context.parameters[value.Ref];
    }
    if (Object.hasOwn(context.logicalArns, value.Ref)) {
      return context.logicalArns[value.Ref];
    }
    const refs = {
      "AWS::AccountId": context.accountId,
      "AWS::Partition": "aws",
      "AWS::Region": "us-east-1"
    };
    requireCondition(Object.hasOwn(refs, value.Ref),
      "FRESH_CREDENTIAL_READBACK_REF_REJECTED");
    return refs[value.Ref];
  }
  if (exactKeys(value, ["Fn::GetAtt"])) {
    requireCondition(canonicalJson(value["Fn::GetAtt"]) === canonicalJson([
      "FreshPrimaryCredentialWriterRole", "Arn"
    ]), "FRESH_CREDENTIAL_READBACK_GETATT_REJECTED");
    return context.writerRoleArn;
  }
  if (exactKeys(value, ["Fn::Sub"])) {
    requireCondition(typeof value["Fn::Sub"] === "string",
      "FRESH_CREDENTIAL_READBACK_SUB_REJECTED");
    const substitutions = {
      ...context.parameters,
      "AWS::AccountId": context.accountId,
      "AWS::Partition": "aws",
      "AWS::Region": "us-east-1"
    };
    return value["Fn::Sub"].replace(/\$\{([^}]+)\}/gu, (_match, name) => {
      requireCondition(Object.hasOwn(substitutions, name),
        "FRESH_CREDENTIAL_READBACK_SUB_REJECTED");
      return substitutions[name];
    });
  }
  return Object.fromEntries(Object.entries(value).map(([key, child]) =>
    [key, resolveTemplate(child, context)]));
}

function outputArns(outputs, plan) {
  const code = "FRESH_CREDENTIAL_READBACK_OUTPUTS_REJECTED";
  requireCondition(exactKeys(outputs, [
    ...Object.keys(OUTPUT_TO_NAME), "WriterRoleArn"
  ]) && outputs.WriterRoleArn === plan.writerRoleArn, code);
  const arns = Object.fromEntries(Object.entries(OUTPUT_TO_NAME).map(
    ([output, name]) => [name, outputs[output]]
  ));
  sealerTest.normalizeArns(arns, plan);
  return Object.freeze(arns);
}

export function freshPrimaryCredentialSecretArnsFromStackOutputs({
  outputs,
  plan: rawPlan
}) {
  const plan = verifyFreshPrimaryCredentialCustodyPlan(rawPlan);
  return outputArns(outputs, plan);
}

function validateStack(value, plan, observedAt) {
  const code = "FRESH_CREDENTIAL_READBACK_STACK_REJECTED";
  const prefix = `arn:aws:cloudformation:us-east-1:${plan.accountId}:stack/` +
    `${plan.stackName}/`;
  requireCondition(exactKeys(value, [
    "capabilities", "creationTime", "outputs", "parameters", "stackId",
    "stackName", "stackStatus", "tags", "terminationProtection"
  ]) && value.stackName === plan.stackName &&
    typeof value.stackId === "string" && value.stackId.startsWith(prefix) &&
    value.stackId.length > prefix.length &&
    value.stackStatus === "CREATE_COMPLETE" &&
    value.terminationProtection === true &&
    canonicalInstant(value.creationTime, code) <= observedAt &&
    canonicalJson(value.capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    canonicalJson(value.parameters) === canonicalJson(plan.parameters) &&
    canonicalJson(normalizeTags(value.tags, code)) ===
      canonicalJson(plan.requiredStackTags), code);
  const arns = outputArns(value.outputs, plan);
  return Object.freeze({
    arns,
    receipt: {
      creationTime: value.creationTime,
      stackIdSha256: sha256(value.stackId),
      status: value.stackStatus,
      terminationProtection: true
    }
  });
}

function sourceContract(plan, arns, deployedTemplate) {
  const code = "FRESH_CREDENTIAL_READBACK_TEMPLATE_REJECTED";
  const reviewed = planTest.readReviewedTemplate().template;
  requireCondition(canonicalJson(deployedTemplate) === canonicalJson(reviewed),
    code);
  const logicalArns = Object.fromEntries(Object.entries(LOGICAL_TO_NAME).map(
    ([logical, name]) => [logical, arns[name]]
  ));
  const context = {
    accountId: plan.accountId,
    logicalArns,
    parameters: plan.parameters,
    writerRoleArn: plan.writerRoleArn
  };
  const properties = reviewed.Resources.FreshPrimaryCredentialWriterRole
    .Properties;
  return Object.freeze({
    inlinePolicy: resolveTemplate(
      properties.Policies[0].PolicyDocument, context
    ),
    inlinePolicyName: properties.Policies[0].PolicyName,
    roleDescription: properties.Description,
    roleTags: Object.fromEntries(properties.Tags.map((tag) =>
      [tag.Key, resolveTemplate(tag.Value, context)])),
    trust: resolveTemplate(properties.AssumeRolePolicyDocument, context)
  });
}

function validateResources(value, plan, arns) {
  const code = "FRESH_CREDENTIAL_READBACK_RESOURCES_REJECTED";
  requireCondition(Array.isArray(value) && value.length === 8, code);
  const expected = {
    ...Object.fromEntries(Object.entries(LOGICAL_TO_NAME).map(
      ([logical, name]) => [logical, {
        physicalResourceId: arns[name],
        resourceType: "AWS::SecretsManager::Secret"
      }]
    )),
    FreshPrimaryCredentialWriterRole: {
      physicalResourceId: plan.writerRoleName,
      resourceType: "AWS::IAM::Role"
    }
  };
  const normalized = {};
  for (const item of value) {
    requireCondition(exactKeys(item, [
      "logicalResourceId", "physicalResourceId", "resourceStatus",
      "resourceType"
    ]) && Object.hasOwn(expected, item.logicalResourceId) &&
      !Object.hasOwn(normalized, item.logicalResourceId) &&
      item.resourceStatus === "CREATE_COMPLETE" &&
      item.physicalResourceId ===
        expected[item.logicalResourceId].physicalResourceId &&
      item.resourceType === expected[item.logicalResourceId].resourceType,
    code);
    normalized[item.logicalResourceId] = item;
  }
  requireCondition(Object.keys(normalized).length === 8, code);
  return digest(normalized);
}

function validateWriter(value, plan, contract, creatorState) {
  const code = "FRESH_CREDENTIAL_READBACK_WRITER_REJECTED";
  requireCondition(exactKeys(value, [
    "arn", "attachedPolicyArns", "description", "inlinePolicy",
    "inlinePolicyNames", "maxSessionDuration", "path",
    "permissionsBoundaryArn", "roleId", "roleName", "tags", "trust"
  ]) && value.arn === plan.writerRoleArn &&
    value.roleName === plan.writerRoleName &&
    value.path === plan.writerRolePath && ROLE_ID.test(value.roleId ?? "") &&
    value.description === contract.roleDescription &&
    value.maxSessionDuration === 3600 &&
    value.permissionsBoundaryArn === null &&
    Array.isArray(value.attachedPolicyArns) &&
    value.attachedPolicyArns.length === 0 &&
    canonicalJson(value.inlinePolicyNames) ===
      canonicalJson([contract.inlinePolicyName]) &&
    canonicalJson(value.inlinePolicy) === canonicalJson(contract.inlinePolicy) &&
    canonicalJson(normalizeTags(value.tags, code)) ===
      canonicalJson(contract.roleTags), code);
  const trust = structuredClone(value.trust);
  const sourceTrust = structuredClone(contract.trust);
  const principal = trust?.Statement?.[0]?.Principal?.AWS;
  requireCondition(creatorState === "PRESENT" || creatorState === "DELETED",
    code);
  if (creatorState === "PRESENT") {
    requireCondition(principal === plan.bootstrapCreatorRoleArn, code);
  } else {
    requireCondition(OPAQUE_PRINCIPAL_ID.test(principal ?? ""), code);
    sourceTrust.Statement[0].Principal.AWS = principal;
  }
  requireCondition(canonicalJson(trust) === canonicalJson(sourceTrust), code);
  return Object.freeze({
    arnSha256: sha256(value.arn),
    attachedPolicyCount: 0,
    creatorPrincipalOpaque: creatorState === "DELETED",
    inlinePolicySha256: digest(value.inlinePolicy),
    roleId: value.roleId,
    trustSha256: digest(trust)
  });
}

function validateSecret(value, plan, name, arn, expectedVersions) {
  const code = "FRESH_CREDENTIAL_READBACK_SECRET_REJECTED";
  requireCondition(exactKeys(value, [
    "arn", "kmsKeyId", "name", "replicationRegions", "resourcePolicy",
    "rotationEnabled", "tags", "versions"
  ]) && value.arn === arn && value.name === plan.secretNames[name] &&
    value.kmsKeyId === null && value.rotationEnabled === false &&
    Array.isArray(value.replicationRegions) &&
    value.replicationRegions.length === 0 && value.resourcePolicy === null &&
    canonicalJson(normalizeTags(value.tags, code)) ===
      canonicalJson(sealerTest.expectedTags(plan, name)) &&
    canonicalJson(value.versions) === canonicalJson(expectedVersions), code);
  return Object.freeze({
    arnSha256: sha256(arn),
    nameSha256: sha256(value.name),
    versionCount: Object.keys(value.versions).length,
    versionSetSha256: digest(value.versions)
  });
}

function validateApprovalAndSeal({
  approval,
  arns,
  plan,
  sealReceipt
}) {
  const code = "FRESH_CREDENTIAL_READBACK_SEAL_REJECTED";
  requireCondition(plainObject(approval) && plainObject(sealReceipt), code);
  let rebuilt;
  try {
    rebuilt = buildFreshPrimaryCredentialSealApproval({
      approvedAt: approval.approvedAt,
      expectedValueSha256: Object.fromEntries(
        sealerTest.WRITER_TARGETS.map((name) =>
          [name, approval.secretBindings?.[name]?.expectedValueSha256])
      ),
      expiresAt: approval.expiresAt,
      operatorAuthorizationSha256: approval.operatorAuthorizationSha256,
      plan,
      secretArns: arns
    });
  } catch {
    reject(code);
  }
  requireCondition(canonicalJson(rebuilt) === canonicalJson(approval), code);
  const approvalSha256 = digest(approval);
  const receiptBody = { ...sealReceipt };
  delete receiptBody.receiptSha256;
  requireCondition(exactKeys(sealReceipt, [
    "accountId", "approvalSha256", "caller", "custodyPlanSha256",
    "immutableVersionCount", "operationId", "receiptSha256",
    "runtimeGeneratedTargetCount", "runtimeGeneratedTargetsEmpty",
    "schemaVersion", "sealed", "sourceCommit", "status", "templateSha256",
    "treeDigest", "writerRoleArnSha256"
  ]) && sealReceipt.receiptSha256 === digest(receiptBody) &&
    sealReceipt.schemaVersion ===
      "prooftoact.fresh-primary-credential-seal-receipt.v1" &&
    sealReceipt.status ===
      "EXACT_FIVE_VERSIONS_SEALED_TWO_TARGETS_EMPTY" &&
    sealReceipt.approvalSha256 === approvalSha256 &&
    sealReceipt.custodyPlanSha256 === plan.planSha256 &&
    sealReceipt.immutableVersionCount === 5 &&
    sealReceipt.runtimeGeneratedTargetCount === 2 &&
    sealReceipt.runtimeGeneratedTargetsEmpty === true &&
    sealReceipt.accountId === plan.accountId &&
    sealReceipt.operationId === plan.operationId &&
    sealReceipt.sourceCommit === plan.sourceCommit &&
    sealReceipt.treeDigest === plan.treeDigest &&
    sealReceipt.templateSha256 === plan.templateSha256 &&
    sealReceipt.writerRoleArnSha256 === sha256(plan.writerRoleArn) &&
    exactKeys(sealReceipt.caller, [
      "accountId", "assumedRoleArnSha256", "roleId", "roleName", "sessionName"
    ]) && sealReceipt.caller.accountId === plan.accountId &&
    /^[0-9a-f]{64}$/u.test(sealReceipt.caller.assumedRoleArnSha256 ?? "") &&
    ROLE_ID.test(sealReceipt.caller.roleId ?? "") &&
    sealReceipt.caller.roleName === plan.writerRoleName &&
    sealReceipt.caller.sessionName === plan.writerSessionName &&
    exactKeys(sealReceipt.sealed, sealerTest.WRITER_TARGETS), code);
  for (const name of sealerTest.WRITER_TARGETS) {
    const entry = sealReceipt.sealed[name];
    requireCondition(plainObject(entry) &&
      Object.keys(entry).every((key) => [
        "createdAt", "dispatchCount", "reconciledAcknowledgementLoss",
        "reconciledExistingVersion", "secretArnSha256",
        "secretValueSha256", "secretVersionIdSha256", "versionStage"
      ].includes(key)) && canonicalInstant(entry.createdAt, code) > 0 &&
      [0, 1].includes(entry.dispatchCount) &&
      entry.secretArnSha256 === approval.secretBindings[name].secretArnSha256 &&
      entry.secretValueSha256 ===
        approval.secretBindings[name].expectedValueSha256 &&
      entry.secretVersionIdSha256 ===
        sha256(approval.secretBindings[name].clientRequestToken) &&
      entry.versionStage === "AWSCURRENT" &&
      (entry.dispatchCount === 0
        ? entry.reconciledExistingVersion === true &&
          !Object.hasOwn(entry, "reconciledAcknowledgementLoss")
        : typeof entry.reconciledAcknowledgementLoss === "boolean" &&
          !Object.hasOwn(entry, "reconciledExistingVersion")), code);
  }
  return Object.freeze({ approvalSha256, receiptSha256: sealReceipt.receiptSha256 });
}

export function verifyFreshPrimaryCredentialCustodyReadback({
  collectorBinding: rawCollectorBinding,
  plan: rawPlan,
  input
}) {
  const code = "FRESH_CREDENTIAL_READBACK_REJECTED";
  const plan = verifyFreshPrimaryCredentialCustodyPlan(rawPlan);
  requireCondition(exactKeys(input, [
    "approval", "callerIdentity", "creatorRole", "deployedTemplate",
    "observedAt", "phase", "resources", "schemaVersion", "sealReceipt",
    "secrets", "stack", "writerRole"
  ]) && input.schemaVersion === INPUT_SCHEMA &&
    ["EMPTY", "SEALED"].includes(input.phase), code);
  const observedAt = canonicalInstant(input.observedAt, code);
  const collectorBinding = validateFreshBootstrapCollectorBinding(
    rawCollectorBinding,
    {
      accountId: plan.accountId,
      operationId: plan.operationId,
      operatorAuthorizationSha256: plan.operatorAuthorizationSha256,
      sourceCommit: plan.sourceCommit,
      treeDigest: plan.treeDigest
    }
  );
  requireCondition(collectorBinding.roleArn === plan.bootstrapCreatorRoleArn,
    code);
  const caller = validateFreshBootstrapCollectorCaller(
    input.callerIdentity, collectorBinding
  );
  const stack = validateStack(input.stack, plan, observedAt);
  const resourcesSha256 = validateResources(
    input.resources, plan, stack.arns
  );
  const contract = sourceContract(plan, stack.arns, input.deployedTemplate);
  requireCondition(exactKeys(input.creatorRole, [
    "assumeRoleDenied", "getRoleError", "state"
  ]) && ["PRESENT", "DELETED"].includes(input.creatorRole.state) &&
    (input.creatorRole.state === "PRESENT"
      ? input.creatorRole.getRoleError === null &&
        input.creatorRole.assumeRoleDenied === false
      : input.creatorRole.getRoleError === "NoSuchEntity" &&
        input.creatorRole.assumeRoleDenied === true), code);
  const writer = validateWriter(
    input.writerRole, plan, contract, input.creatorRole.state
  );
  requireCondition(exactKeys(input.secrets, Object.keys(plan.secretNames)),
    code);
  let seal = null;
  if (input.phase === "SEALED") {
    seal = validateApprovalAndSeal({
      approval: input.approval,
      arns: stack.arns,
      plan,
      sealReceipt: input.sealReceipt
    });
  } else {
    requireCondition(input.approval === null && input.sealReceipt === null,
      code);
  }
  const secretReceipts = {};
  for (const name of Object.keys(plan.secretNames).sort()) {
    let expectedVersions = {};
    if (input.phase === "SEALED" && sealerTest.WRITER_TARGETS.includes(name)) {
      expectedVersions = {
        [input.approval.secretBindings[name].clientRequestToken]: ["AWSCURRENT"]
      };
    }
    secretReceipts[name] = validateSecret(
      input.secrets[name], plan, name, stack.arns[name], expectedVersions
    );
  }
  const body = {
    schemaVersion: RECEIPT_SCHEMA,
    status: input.phase === "EMPTY"
      ? "EXACT_SEVEN_EMPTY_CONTAINERS_ACCEPTED"
      : "EXACT_FIVE_SEALED_TWO_EMPTY_CREATOR_LIFECYCLE_ACCEPTED",
    accountId: plan.accountId,
    caller,
    creatorRoleState: input.creatorRole.state,
    observedAt: input.observedAt,
    phase: input.phase,
    planSha256: plan.planSha256,
    readOnly: true,
    resourcesSha256,
    seal,
    secrets: secretReceipts,
    sourceCommit: plan.sourceCommit,
    stack: stack.receipt,
    templateSha256: plan.templateSha256,
    treeDigest: plan.treeDigest,
    writer
  };
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

export const __test = Object.freeze({
  INPUT_SCHEMA,
  RECEIPT_SCHEMA,
  canonicalJson,
  digest,
  normalizeTags,
  outputArns,
  resolveTemplate,
  sourceContract,
  validateApprovalAndSeal,
  validateResources,
  validateSecret,
  validateStack,
  validateWriter
});
