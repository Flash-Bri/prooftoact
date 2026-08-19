import crypto from "node:crypto";

import {
  __test as planTest,
  verifyFreshPrimaryBootstrapRolePlan
} from "./prepare-fresh-primary-bootstrap-role.js";
import {
  validateFreshBootstrapCollectorBinding,
  validateFreshBootstrapCollectorCaller
} from "./lib/fresh-bootstrap-collector-binding.js";

const INPUT_SCHEMA =
  "prooftoact.fresh-primary-bootstrap-role-readback-input.v1";
const RECEIPT_SCHEMA =
  "prooftoact.fresh-primary-bootstrap-role-readback-receipt.v1";
const ROLE_ID = /^AROA[A-Z0-9]{16}$/u;
const STACK_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

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

function decodePolicy(value, code) {
  if (plainObject(value)) return value;
  requireCondition(typeof value === "string", code);
  let parsed;
  try {
    parsed = JSON.parse(decodeURIComponent(value));
  } catch {
    reject(code);
  }
  requireCondition(plainObject(parsed), code);
  return parsed;
}

function resolveTemplate(value, context) {
  if (Array.isArray(value)) {
    return value.map((item) => resolveTemplate(item, context));
  }
  if (!plainObject(value)) return value;
  if (exactKeys(value, ["Ref"])) {
    const refs = {
      "AWS::AccountId": context.accountId,
      "AWS::Partition": "aws",
      "AWS::Region": "us-east-1",
      GitHubOidcProviderArn: context.oidcArn
    };
    requireCondition(Object.hasOwn(refs, value.Ref),
      "FRESH_PRIMARY_ROLE_READBACK_REF_REJECTED");
    return refs[value.Ref];
  }
  if (exactKeys(value, ["Fn::Sub"])) {
    requireCondition(typeof value["Fn::Sub"] === "string",
      "FRESH_PRIMARY_ROLE_READBACK_SUB_REJECTED");
    const substitutions = {
      "AWS::AccountId": context.accountId,
      "AWS::Partition": "aws",
      "AWS::Region": "us-east-1"
    };
    return value["Fn::Sub"].replace(/\$\{([^}]+)\}/gu, (_match, name) => {
      requireCondition(Object.hasOwn(substitutions, name),
        "FRESH_PRIMARY_ROLE_READBACK_SUB_REJECTED");
      return substitutions[name];
    });
  }
  return Object.fromEntries(Object.entries(value).map(([key, child]) =>
    [key, resolveTemplate(child, context)]));
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

function validateStack(stack, plan, observedAt) {
  const code = "FRESH_PRIMARY_ROLE_READBACK_STACK_REJECTED";
  const prefix = `arn:aws:cloudformation:us-east-1:${plan.accountId}:stack/` +
    `${plan.stackName}/`;
  requireCondition(exactKeys(stack, [
    "capabilities", "creationTime", "outputs", "parameters", "stackId",
    "stackName", "stackStatus", "tags", "terminationProtection"
  ]) && stack.stackName === plan.stackName &&
    typeof stack.stackId === "string" && stack.stackId.startsWith(prefix) &&
    STACK_UUID.test(stack.stackId.slice(prefix.length)) &&
    stack.stackStatus === "CREATE_COMPLETE" &&
    stack.terminationProtection === true &&
    canonicalInstant(stack.creationTime, code) <= observedAt &&
    canonicalJson(stack.capabilities) ===
      canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    canonicalJson(stack.parameters) === canonicalJson({
      GitHubOidcProviderArn: plan.githubOidcProviderArn
    }) && canonicalJson(stack.outputs) === canonicalJson({
      FreshPrimaryBootstrapRoleArn: plan.expectedOutput.value
    }) && canonicalJson(normalizeTags(stack.tags, code)) ===
      canonicalJson(plan.requiredStackTags), code);
  return Object.freeze({
    creationTime: stack.creationTime,
    stackIdSha256: sha256(stack.stackId),
    status: stack.stackStatus,
    terminationProtection: true
  });
}

function validateResources(value, plan) {
  const code = "FRESH_PRIMARY_ROLE_READBACK_RESOURCES_REJECTED";
  requireCondition(Array.isArray(value) && value.length === 1 &&
    exactKeys(value[0], [
      "logicalResourceId", "physicalResourceId", "resourceStatus",
      "resourceType"
    ]) && value[0].logicalResourceId === "FreshPrimaryBootstrapRole" &&
    value[0].physicalResourceId === plan.roleName &&
    value[0].resourceStatus === "CREATE_COMPLETE" &&
    value[0].resourceType === "AWS::IAM::Role", code);
  return digest(value);
}

function sourceRoleContract(plan, deployedTemplate) {
  const code = "FRESH_PRIMARY_ROLE_READBACK_TEMPLATE_REJECTED";
  const reviewed = planTest.readReviewedTemplate().template;
  requireCondition(canonicalJson(deployedTemplate) === canonicalJson(reviewed),
    code);
  const properties = reviewed.Resources.FreshPrimaryBootstrapRole.Properties;
  const context = {
    accountId: plan.accountId,
    oidcArn: plan.githubOidcProviderArn
  };
  return Object.freeze({
    description: properties.Description,
    inlinePolicy: resolveTemplate(
      properties.Policies[0].PolicyDocument, context
    ),
    inlinePolicyName: properties.Policies[0].PolicyName,
    maxSessionDuration: properties.MaxSessionDuration,
    tags: Object.fromEntries(properties.Tags.map((item) =>
      [item.Key, item.Value])),
    trust: resolveTemplate(properties.AssumeRolePolicyDocument, context)
  });
}

function validateRole(value, plan, contract, observedAt) {
  const code = "FRESH_PRIMARY_ROLE_READBACK_ROLE_REJECTED";
  requireCondition(exactKeys(value, [
    "arn", "attachedPolicyArns", "createdAt", "description",
    "inlinePolicy", "inlinePolicyNames", "maxSessionDuration", "path",
    "permissionsBoundaryArn", "roleId", "roleName", "tags", "trust"
  ]) && value.arn === plan.expectedOutput.value &&
    value.roleName === plan.roleName && value.path === "/" &&
    ROLE_ID.test(value.roleId ?? "") &&
    canonicalInstant(value.createdAt, code) <= observedAt &&
    value.description === contract.description &&
    value.maxSessionDuration === contract.maxSessionDuration &&
    value.permissionsBoundaryArn === null &&
    Array.isArray(value.attachedPolicyArns) &&
    value.attachedPolicyArns.length === 0 &&
    canonicalJson(value.inlinePolicyNames) ===
      canonicalJson([contract.inlinePolicyName]) &&
    canonicalJson(decodePolicy(value.inlinePolicy, code)) ===
      canonicalJson(contract.inlinePolicy) &&
    canonicalJson(decodePolicy(value.trust, code)) ===
      canonicalJson(contract.trust) &&
    canonicalJson(normalizeTags(value.tags, code)) ===
      canonicalJson(contract.tags), code);
  return Object.freeze({
    arnSha256: sha256(value.arn),
    attachedPolicyCount: 0,
    inlinePolicySha256: digest(contract.inlinePolicy),
    roleId: value.roleId,
    trustSha256: digest(contract.trust)
  });
}

function validateOidc(value, plan) {
  const code = "FRESH_PRIMARY_ROLE_READBACK_OIDC_REJECTED";
  requireCondition(exactKeys(value, [
    "arn", "clientIds", "thumbprints", "url"
  ]) && value.arn === plan.githubOidcProviderArn &&
    value.url === "token.actions.githubusercontent.com" &&
    canonicalJson(value.clientIds) === canonicalJson(["sts.amazonaws.com"]) &&
    Array.isArray(value.thumbprints) && value.thumbprints.length >= 1 &&
    value.thumbprints.every((item) => /^[0-9a-f]{40}$/u.test(item)), code);
  return Object.freeze({
    arnSha256: sha256(value.arn),
    clientIds: value.clientIds,
    thumbprintSetSha256: digest([...value.thumbprints].sort()),
    url: value.url
  });
}

export function verifyFreshPrimaryBootstrapRoleReadback({
  collectorBinding: rawCollectorBinding,
  plan: rawPlan,
  input
}) {
  const code = "FRESH_PRIMARY_ROLE_READBACK_REJECTED";
  const plan = verifyFreshPrimaryBootstrapRolePlan(rawPlan);
  requireCondition(exactKeys(input, [
    "callerIdentity", "deployedTemplate", "observedAt", "oidcProvider",
    "resources", "role", "schemaVersion", "stack"
  ]) && input.schemaVersion === INPUT_SCHEMA, code);
  const observedAt = canonicalInstant(input.observedAt, code);
  const collectorBinding = validateFreshBootstrapCollectorBinding(
    rawCollectorBinding,
    {
      accountId: plan.accountId,
      operationId: rawCollectorBinding?.operationId,
      operatorAuthorizationSha256:
        rawCollectorBinding?.operatorAuthorizationSha256,
      sourceCommit: plan.sourceCommit,
      treeDigest: plan.treeDigest
    }
  );
  const caller = validateFreshBootstrapCollectorCaller(
    input.callerIdentity, collectorBinding
  );
  const stack = validateStack(input.stack, plan, observedAt);
  const resourcesSha256 = validateResources(input.resources, plan);
  const contract = sourceRoleContract(plan, input.deployedTemplate);
  const role = validateRole(input.role, plan, contract, observedAt);
  const oidcProvider = validateOidc(input.oidcProvider, plan);
  const body = {
    schemaVersion: RECEIPT_SCHEMA,
    status: "EXACT_STANDALONE_ROLE_PROVIDER_READBACK_ACCEPTED",
    accountId: plan.accountId,
    caller,
    observedAt: input.observedAt,
    oidcProvider,
    planSha256: plan.planSha256,
    readOnly: true,
    resourcesSha256,
    role,
    sourceCommit: plan.sourceCommit,
    stack,
    templateSha256: plan.templateSha256,
    treeDigest: plan.treeDigest
  };
  return Object.freeze({ ...body, receiptSha256: digest(body) });
}

export const __test = Object.freeze({
  INPUT_SCHEMA,
  RECEIPT_SCHEMA,
  canonicalJson,
  decodePolicy,
  digest,
  normalizeTags,
  resolveTemplate,
  sourceRoleContract,
  validateOidc,
  validateResources,
  validateRole,
  validateStack
});
