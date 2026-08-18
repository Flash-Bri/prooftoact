import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  validateReleaseDeploymentRoleTemplate,
  validateReleaseSourceComposition
} from
  "./prepare-release-deployment.js";

/*
 * This controller is deliberately stdlib-only. It validates authenticated
 * evidence and publishes a durable local decision record; it never calls a
 * provider and never treats local JSON or its local journal as provider proof.
 * The provider action belongs to a separately protected workflow/role.
 */

const CURRENT_FILE = fileURLToPath(import.meta.url);
const REVIEWED_GATE2_TEMPLATE_SHA256 =
  "a10066b23925cf2921b15eaa0d52e7ac8ef7a5f46e0ab260431a340e897cc3a1";
const REVIEWED_ROLES_TEMPLATE_SHA256 =
  "68128dfa0d72246bebd1c35fe8549f86e2827efc2769314d628e551d9c6f1cad";
const RECEIPT_SCHEMA = "prooftoact.authenticated-controller-receipt.v1";
const BUNDLE_SCHEMA = "prooftoact.provider-controller-bundle.v1";
const DECISION_SCHEMA = "prooftoact.provider-controller-decision.v1";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const ARTIFACT_NAMES = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "probe",
  "signer"
]);
const ACTIVE_LAMBDAS = Object.freeze({
  AgentFunction: Object.freeze({ concurrency: 1, memory: 128, timeout: 15 }),
  AuthorityFunction: Object.freeze({ concurrency: 2, memory: 128, timeout: 25 }),
  BoundaryFunction: Object.freeze({ concurrency: 2, memory: 128, timeout: 25 }),
  DemoFunction: Object.freeze({ concurrency: 8, memory: 128, timeout: 5 }),
  SignerFunction: Object.freeze({ concurrency: 1, memory: 128, timeout: 8 })
});
const PUBLIC_ROUTES = Object.freeze([
  "GET /",
  "GET /api/health",
  "GET /api/scenario",
  "GET /app.js",
  "GET /architecture.svg",
  "GET /claims",
  "GET /evidence/gate1-ambiguity",
  "GET /evidence/gate1-authority",
  "GET /evidence/gate1-recovery",
  "GET /styles.css"
]);
const IAM_ALLOW_CHECKS = Object.freeze([
  "CLOUDFORMATION_CREATE_ALIAS_EXACT_ALIAS",
  "CLOUDFORMATION_CREATE_ALIAS_TAGGED_TARGET_KEY",
  "COORDINATOR_ARTIFACT_PREFIX_READBACK",
  "COORDINATOR_CONTROLLER_TABLE_ATOMIC_TRANSITION",
  "COORDINATOR_CONTROLLER_TABLE_IDENTITY_READ",
  "COORDINATOR_PROVIDER_FINALIZER_READBACK",
  "EVIDENCE_BOOTSTRAP_ROLE_AND_BOUNDARY_READBACK",
  "EVIDENCE_CONTROLLER_TABLE_STRONG_READ",
  "EVIDENCE_FROZEN_ATTESTATION_API_READS",
  "EVIDENCE_READ_ONLY_DESCRIBE_EXACT_STACK",
  "EXECUTOR_DESCRIBE_EXACT_CHANGE_SET",
  "EXECUTOR_EXECUTE_EXACT_CHANGE_SET",
  "LIVE_ASSUME_EXACT_RUNTIME_ROLES",
  "LANE_EFFECT_STRONG_READ",
  "PREPARER_BOOTSTRAP_ROLE_AND_BOUNDARY_READBACK",
  "PREPARER_CREATE_EXACT_CHANGE_SET",
  "PREPARER_READ_EXACT_ARTIFACT_VERSION",
  "TEARDOWN_DELETE_EXACT_STACK",
  "TERMINALIZER_EFFECT_ONLY_UPDATE"
]);
const IAM_DENY_CHECKS = Object.freeze([
  "CLOUDFORMATION_ARBITRARY_PASS_ROLE",
  "CLOUDFORMATION_EXTERNAL_TRUST",
  "CLOUDFORMATION_UNTAGGED_KMS_KEY",
  "COORDINATOR_PROVIDER_MUTATION_OR_ROLE_CAPABILITY",
  "EVIDENCE_CROSS_LANE_ASSUME_ROLE",
  "EVIDENCE_CONTROLLER_TABLE_MUTATION",
  "EVIDENCE_PROVIDER_MUTATION",
  "EXECUTOR_ALTERNATE_STACK",
  "EXECUTOR_CONTROLLER_TABLE_MUTATION",
  "EXECUTOR_CREATE_CHANGE_SET",
  "EXECUTOR_DIRECT_INVOKE",
  "EXECUTOR_KMS_OR_SECRET_USE",
  "EXECUTOR_UPDATE_CHANGE_SET",
  "EXECUTOR_WRONG_CHANGE_SET_ARN",
  "LIVE_DEPLOYMENT_MUTATION",
  "LANE_BUDGET_READ_OR_STORE_WRITE",
  "LIVE_CONTROLLER_TABLE_MUTATION",
  "PREPARER_EXECUTE_CHANGE_SET",
  "PREPARER_RUNTIME_ROLE_ASSUME",
  "SERVICE_ROLE_WILDCARD_ROLE_POLICY",
  "STORE_DELETE_OR_TABLE_MUTATION",
  "TEARDOWN_LIVE_OR_DEPLOYMENT_MUTATION",
  "TEARDOWN_CONTROLLER_TABLE_MUTATION",
  "TEARDOWN_OTHER_STACK",
  "TERMINALIZER_BUDGET_MUTATION",
  "TERMINALIZER_PROVIDER_OR_ROLE_CAPABILITY"
]);
const LANE_ROLE_NAMES = Object.freeze({
  coordinator: "ProofToActReleaseCoordinator",
  evidence: "ProofToActReleaseEvidence",
  executor: "ProofToActReleaseExecution",
  live: "ProofToActLiveDrillOperator",
  preparer: "ProofToActReleaseDeployment",
  teardown: "ProofToActReleaseTeardown"
});
const STAGE_CONTRACT = Object.freeze({
  EXECUTE: Object.freeze({
    action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
    environment: "aws-release-execution",
    roleName: LANE_ROLE_NAMES.executor,
    storeState: "EXECUTION_RESERVED",
    journalEvent: "BEFORE_EXECUTE_CREATE_CHANGE_SET",
    workflow: "ProofToAct Execute Approved Release",
    nextAction: "EXECUTE_EXACT_CREATE_CHANGE_SET_ONCE_THEN_RECONCILE"
  }),
  RECONCILE: Object.freeze({
    action: "RECONCILE_CREATE_CHANGE_SET",
    environment: "aws-release-evidence",
    roleName: LANE_ROLE_NAMES.evidence,
    storeState: "RECONCILIATION_RESERVED",
    journalEvent: "BEFORE_READ_ONLY_RECONCILIATION",
    workflow: "ProofToAct Read Only Release Evidence",
    nextAction: "READ_ONLY_RECONCILIATION_ONLY"
  }),
  LIVE: Object.freeze({
    action: "RUN_ONE_BOUNDED_LIVE_DRILL",
    environment: "aws-live-drill",
    roleName: LANE_ROLE_NAMES.live,
    storeState: "LIVE_DRILL_RESERVED",
    journalEvent: "BEFORE_BOUNDED_LIVE_DRILL",
    workflow: "ProofToAct Bounded Live Drill",
    nextAction: "RUN_EXACT_BOUNDED_LIVE_DRILL_ONCE"
  }),
  EVIDENCE: Object.freeze({
    action: "COLLECT_READ_ONLY_RELEASE_EVIDENCE",
    environment: "aws-release-evidence",
    roleName: LANE_ROLE_NAMES.evidence,
    storeState: "EVIDENCE_COLLECTION_RESERVED",
    journalEvent: "BEFORE_READ_ONLY_EVIDENCE_COLLECTION",
    workflow: "ProofToAct Read Only Release Evidence",
    nextAction: "COLLECT_READ_ONLY_EVIDENCE_ONLY"
  }),
  TEARDOWN: Object.freeze({
    action: "TEARDOWN_EXACT_RELEASE_STACK",
    environment: "aws-release-teardown",
    roleName: LANE_ROLE_NAMES.teardown,
    storeState: "TEARDOWN_RESERVED",
    journalEvent: "BEFORE_EXACT_TEARDOWN",
    workflow: "ProofToAct Approved Teardown",
    nextAction: "TEARDOWN_EXACT_DECLARED_RESOURCES_ONCE_THEN_RECONCILE"
  }),
  RESIDUAL: Object.freeze({
    action: "VERIFY_POST_TEARDOWN_RESIDUALS",
    environment: "aws-release-evidence",
    roleName: LANE_ROLE_NAMES.evidence,
    storeState: "RESIDUAL_VERIFICATION_RESERVED",
    journalEvent: "BEFORE_DELAYED_RESIDUAL_CENSUS",
    workflow: "ProofToAct Read Only Release Evidence",
    nextAction: "READ_ONLY_RESIDUAL_AND_COST_CENSUS_ONLY"
  })
});

function fail(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) fail(code);
}

function exactKeys(value, keys) {
  return value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function canonicalJson(value) {
  const seen = new Set();
  function encode(current) {
    if (current === null) return "null";
    if (typeof current === "string" || typeof current === "boolean") {
      return JSON.stringify(current);
    }
    if (typeof current === "number") {
      requireCondition(Number.isFinite(current) && !Object.is(current, -0),
        "CONTROLLER_NON_CANONICAL_JSON_REJECTED");
      return JSON.stringify(current);
    }
    requireCondition(typeof current === "object",
      "CONTROLLER_NON_CANONICAL_JSON_REJECTED");
    requireCondition(!seen.has(current),
      "CONTROLLER_NON_CANONICAL_JSON_REJECTED");
    seen.add(current);
    let encoded;
    if (Array.isArray(current)) {
      encoded = `[${current.map((item) => encode(item)).join(",")}]`;
    } else {
      requireCondition(plainObject(current),
        "CONTROLLER_NON_CANONICAL_JSON_REJECTED");
      const keys = Object.keys(current).sort();
      requireCondition(keys.every((key) =>
        key !== "__proto__" && key !== "constructor" && key !== "prototype"),
      "CONTROLLER_NON_CANONICAL_JSON_REJECTED");
      encoded = `{${keys.map((key) =>
        `${JSON.stringify(key)}:${encode(current[key])}`).join(",")}}`;
    }
    seen.delete(current);
    return encoded;
  }
  return encode(value);
}

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function parseIso(value, code) {
  requireCondition(typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value), code);
  const timestamp = Date.parse(value);
  requireCondition(Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value,
    code);
  return timestamp;
}

function strictBase64(value, expectedBytes, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= 4096 && BASE64.test(value), code);
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length === expectedBytes && bytes.toString("base64") === value,
    code);
  return bytes;
}

function publicKeyDetails(value, code) {
  let key;
  try {
    key = crypto.createPublicKey(value);
  } catch (cause) {
    fail(code, cause);
  }
  requireCondition(key.type === "public" && key.asymmetricKeyType === "ec" &&
    key.asymmetricKeyDetails?.namedCurve === "prime256v1", code);
  const der = key.export({ type: "spki", format: "der" });
  return Object.freeze({ key, fingerprint: sha256(der) });
}

export function fingerprintPublicKey(value) {
  return publicKeyDetails(value, "CONTROLLER_TRUST_ANCHOR_REJECTED").fingerprint;
}

function receiptSignable(receipt) {
  const { signature: _signature, ...unsigned } = receipt;
  return canonicalBytes(unsigned);
}

function validateTrustAnchors(trustedPublicKeys) {
  requireCondition(exactKeys(trustedPublicKeys, [
    "CONTROLLER_STORE", "OPERATOR", "PROVIDER"
  ]), "CONTROLLER_TRUST_ANCHOR_REJECTED");
  const anchors = {};
  for (const issuer of ["CONTROLLER_STORE", "OPERATOR", "PROVIDER"]) {
    anchors[issuer] = publicKeyDetails(
      trustedPublicKeys[issuer],
      "CONTROLLER_TRUST_ANCHOR_REJECTED"
    );
  }
  requireCondition(new Set(Object.values(anchors)
    .map(({ fingerprint }) => fingerprint)).size === 3,
  "CONTROLLER_TRUST_ANCHOR_REJECTED");
  return Object.freeze(anchors);
}

function verifyReceipt(receipt, anchors, expected, now) {
  const code = "CONTROLLER_AUTHENTICATED_RECEIPT_REJECTED";
  requireCondition(exactKeys(receipt, [
    "claims", "expiresAt", "issuedAt", "issuer", "keyFingerprint", "kind",
    "nonce", "schemaVersion", "signature"
  ]) && receipt.schemaVersion === RECEIPT_SCHEMA &&
    receipt.kind === expected.kind && receipt.issuer === expected.issuer &&
    UUID.test(receipt.nonce ?? "") && plainObject(receipt.claims), code);
  const anchor = anchors[receipt.issuer];
  requireCondition(anchor && receipt.keyFingerprint === anchor.fingerprint, code);
  const issuedAt = parseIso(receipt.issuedAt, code);
  const expiresAt = parseIso(receipt.expiresAt, code);
  requireCondition(issuedAt <= now && now < expiresAt &&
    now - issuedAt <= expected.maximumAgeMs &&
    expiresAt - issuedAt <= expected.maximumLifetimeMs, code);
  const signature = strictBase64(receipt.signature, 64, code);
  requireCondition(crypto.verify("sha256", receiptSignable(receipt), {
    key: anchor.key,
    dsaEncoding: "ieee-p1363"
  }, signature), code);
  return receipt.claims;
}

function skipJsonWhitespace(text, state) {
  while (state.index < text.length &&
    /[\u0009\u000a\u000d\u0020]/u.test(text[state.index])) state.index += 1;
}

function scanJsonString(text, state, code) {
  requireCondition(text[state.index] === '"', code);
  state.index += 1;
  let decoded = "";
  while (state.index < text.length) {
    const character = text[state.index];
    const codeUnit = text.charCodeAt(state.index);
    if (character === '"') {
      state.index += 1;
      return decoded;
    }
    requireCondition(codeUnit > 0x1f, code);
    if (character !== "\\") {
      decoded += character;
      state.index += 1;
      continue;
    }
    state.index += 1;
    const escaped = text[state.index];
    const simple = {
      '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n",
      r: "\r", t: "\t"
    };
    if (Object.hasOwn(simple, escaped)) {
      decoded += simple[escaped];
      state.index += 1;
      continue;
    }
    requireCondition(escaped === "u", code);
    const hexadecimal = text.slice(state.index + 1, state.index + 5);
    requireCondition(/^[0-9a-fA-F]{4}$/u.test(hexadecimal), code);
    decoded += String.fromCharCode(Number.parseInt(hexadecimal, 16));
    state.index += 5;
  }
  fail(code);
}

function scanJsonValue(text, state, code, duplicateCode, depth = 0) {
  requireCondition(depth <= 64, code);
  skipJsonWhitespace(text, state);
  const character = text[state.index];
  if (character === '"') {
    scanJsonString(text, state, code);
    return;
  }
  if (character === "{") {
    state.index += 1;
    skipJsonWhitespace(text, state);
    const members = new Set();
    if (text[state.index] === "}") {
      state.index += 1;
      return;
    }
    while (state.index < text.length) {
      const member = scanJsonString(text, state, code);
      requireCondition(!members.has(member), duplicateCode);
      members.add(member);
      skipJsonWhitespace(text, state);
      requireCondition(text[state.index] === ":", code);
      state.index += 1;
      scanJsonValue(text, state, code, duplicateCode, depth + 1);
      skipJsonWhitespace(text, state);
      if (text[state.index] === "}") {
        state.index += 1;
        return;
      }
      requireCondition(text[state.index] === ",", code);
      state.index += 1;
      skipJsonWhitespace(text, state);
    }
    fail(code);
  }
  if (character === "[") {
    state.index += 1;
    skipJsonWhitespace(text, state);
    if (text[state.index] === "]") {
      state.index += 1;
      return;
    }
    while (state.index < text.length) {
      scanJsonValue(text, state, code, duplicateCode, depth + 1);
      skipJsonWhitespace(text, state);
      if (text[state.index] === "]") {
        state.index += 1;
        return;
      }
      requireCondition(text[state.index] === ",", code);
      state.index += 1;
      skipJsonWhitespace(text, state);
    }
    fail(code);
  }
  for (const literal of ["true", "false", "null"]) {
    if (text.startsWith(literal, state.index)) {
      state.index += literal.length;
      return;
    }
  }
  const match = text.slice(state.index).match(
    /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u
  );
  requireCondition(match && Number.isFinite(Number(match[0])), code);
  state.index += match[0].length;
}

export function parseStrictJson(text, code = "CONTROLLER_JSON_REJECTED") {
  requireCondition(typeof text === "string" && text.length > 0, code);
  const state = { index: 0 };
  scanJsonValue(text, state, code, "CONTROLLER_JSON_DUPLICATE_MEMBER_REJECTED");
  skipJsonWhitespace(text, state);
  requireCondition(state.index === text.length, code);
  try {
    const value = JSON.parse(text);
    requireCondition(plainObject(value), code);
    return value;
  } catch (cause) {
    if (cause?.message?.startsWith("CONTROLLER_")) throw cause;
    fail(code, cause);
  }
}

function readExactJson(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.size > 0 && before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && before.mtimeMs === after.mtimeMs, code);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value = parseStrictJson(text, code);
    requireCondition(plainObject(value), code);
    return Object.freeze({ bytes, value });
  } catch (cause) {
    if (cause?.message === code) throw cause;
    fail(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function actions(statement) {
  return Array.isArray(statement?.Action)
    ? [...statement.Action]
    : typeof statement?.Action === "string" ? [statement.Action] : [];
}

function statementBySid(role, sid, code) {
  const statements = role?.Properties?.Policies?.[0]?.PolicyDocument?.Statement;
  requireCondition(Array.isArray(statements), code);
  const matches = statements.filter((statement) => statement?.Sid === sid);
  requireCondition(matches.length === 1, code);
  return matches[0];
}

function validateKmsAliasPermissions(rolesTemplate) {
  const code = "CONTROLLER_KMS_ALIAS_TARGET_PERMISSION_REJECTED";
  const role = rolesTemplate.Resources?.CloudFormationServiceRole;
  const alias = statementBySid(role, "ManageExactReceiptKeyAlias", code);
  const target = statementBySid(role, "BindReceiptKeyAliasToTaggedTargetKey", code);
  const requiredActions = ["kms:CreateAlias", "kms:DeleteAlias"].sort().join("\n");
  requireCondition(alias.Effect === "Allow" &&
    actions(alias).sort().join("\n") === requiredActions &&
    alias.Resource?.["Fn::Sub"] ===
      "arn:${AWS::Partition}:kms:us-east-1:${AWS::AccountId}:alias/prooftoact-gate2-*" &&
    target.Effect === "Allow" &&
    actions(target).sort().join("\n") === requiredActions &&
    target.Resource?.["Fn::Sub"] ===
      "arn:${AWS::Partition}:kms:us-east-1:${AWS::AccountId}:key/*" &&
    exactKeys(target.Condition?.StringEquals, [
      "aws:ResourceTag/Project", "aws:ResourceTag/Purpose"
    ]) && target.Condition.StringEquals["aws:ResourceTag/Project"] === "ProofToAct" &&
    target.Condition.StringEquals["aws:ResourceTag/Purpose"] ===
      "SyntheticGateTwoEvidence", code);
}

function resourceEntries(template) {
  return Object.entries(template.Resources ?? {})
    .filter(([, resource]) => resource?.Condition !== "ShouldDeployProbes")
    .map(([logicalId, resource]) => Object.freeze({
      logicalId,
      type: resource.Type,
      condition: resource.Condition ?? null,
      deletionPolicy: resource.DeletionPolicy ?? null,
      updateReplacePolicy: resource.UpdateReplacePolicy ?? null,
      propertiesSha256: sha256(canonicalBytes(resource.Properties ?? {}))
    }))
    .sort((left, right) => left.logicalId.localeCompare(right.logicalId));
}

export function buildExactResourceContract(gate2Template, rolesTemplate, {
  gate2Bytes,
  rolesBytes
} = {}) {
  const code = "CONTROLLER_RESOURCE_CONTRACT_REJECTED";
  validateKmsAliasPermissions(rolesTemplate);
  const actualGate2Bytes = gate2Bytes ?? Buffer.from(
    `${JSON.stringify(gate2Template, null, 2)}\n`, "utf8");
  const actualRolesBytes = rolesBytes ?? Buffer.from(
    `${JSON.stringify(rolesTemplate, null, 2)}\n`, "utf8");
  requireCondition(sha256(actualGate2Bytes) === REVIEWED_GATE2_TEMPLATE_SHA256 &&
    sha256(actualRolesBytes) === REVIEWED_ROLES_TEMPLATE_SHA256, code);
  const releaseAuthority = validateReleaseDeploymentRoleTemplate(
    rolesTemplate,
    gate2Template
  );
  requireCondition(gate2Template.Parameters?.EnableProbeFunctions?.Default === "false" &&
    gate2Template.Resources?.ReceiptSigningKey?.DeletionPolicy === "Delete" &&
    gate2Template.Resources?.ReceiptSigningKey?.UpdateReplacePolicy === "Delete" &&
    gate2Template.Resources?.ReceiptSigningKey?.Properties?.PendingWindowInDays === 7 &&
    gate2Template.Resources?.ReceiptSigningKey?.Properties?.KeySpec === "ECC_NIST_P256" &&
    gate2Template.Resources?.ReceiptSigningKey?.Properties?.KeyUsage === "SIGN_VERIFY" &&
    gate2Template.Resources?.ReceiptSigningKey?.Properties?.MultiRegion === false, code);
  const entries = resourceEntries(gate2Template);
  requireCondition(entries.length > 0 && entries.every(({ type, condition }) =>
    typeof type === "string" && type.startsWith("AWS::") && condition === null) &&
    entries.every(({ type }) => !type.startsWith("AWS::EC2::") &&
      type !== "AWS::RDS::DBInstance" && type !== "AWS::ECS::Service"), code);
  const lambdas = {};
  for (const [logicalId, expected] of Object.entries(ACTIVE_LAMBDAS)) {
    const resource = gate2Template.Resources?.[logicalId];
    requireCondition(resource?.Type === "AWS::Lambda::Function" &&
      resource.Properties?.Runtime === "nodejs22.x" &&
      resource.Properties?.ReservedConcurrentExecutions === expected.concurrency &&
      resource.Properties?.MemorySize === expected.memory &&
      resource.Properties?.Timeout === expected.timeout &&
      !Object.hasOwn(resource.Properties, "TracingConfig"), code);
    lambdas[logicalId] = expected;
  }
  const routes = Object.values(gate2Template.Resources ?? {})
    .filter((resource) => resource?.Type === "AWS::ApiGatewayV2::Route")
    .map((resource) => Object.freeze({
      authorizationType: resource.Properties.AuthorizationType,
      routeKey: resource.Properties.RouteKey,
      targetSha256: sha256(canonicalBytes(resource.Properties.Target))
    })).sort((left, right) => left.routeKey.localeCompare(right.routeKey));
  const routeKeys = routes.map(({ routeKey }) => routeKey);
  requireCondition(routeKeys.filter((key) => key === "POST /advisory").length === 1 &&
    routes.find(({ routeKey }) => routeKey === "POST /advisory")
      ?.authorizationType === "AWS_IAM" &&
    PUBLIC_ROUTES.every((key) => routeKeys.includes(key)) &&
    routes.filter(({ routeKey }) => PUBLIC_ROUTES.includes(routeKey))
      .every(({ authorizationType }) => authorizationType === "NONE") &&
    routeKeys.length === PUBLIC_ROUTES.length + 1, code);
  const logGroups = Object.entries(gate2Template.Resources ?? {})
    .filter(([, resource]) => resource?.Type === "AWS::Logs::LogGroup" &&
      resource.Condition !== "ShouldDeployProbes")
    .map(([logicalId, resource]) => ({
      logicalId,
      retentionDays: resource.Properties.RetentionInDays
    })).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  requireCondition(logGroups.length === 6 &&
    logGroups.every(({ retentionDays }) => retentionDays === 7), code);
  const alarms = entries.filter(({ type }) => type === "AWS::CloudWatch::Alarm")
    .map(({ logicalId }) => logicalId);
  requireCondition(alarms.length === 7, code);
  const contract = {
    schemaVersion: "prooftoact.exact-provider-resource-contract.v1",
    templateSha256: REVIEWED_GATE2_TEMPLATE_SHA256,
    rolesTemplateSha256: REVIEWED_ROLES_TEMPLATE_SHA256,
    resources: entries,
    lambdas,
    routes,
    logGroups,
    alarms,
    kms: {
      aliasLogicalId: "ReceiptSigningAlias",
      aliasPermissionCoversExactAlias: true,
      aliasPermissionCoversTaggedTargetKey: true,
      keyDeletionPolicy: "Delete",
      keyPendingWindowDays: 7,
      keyPurpose: "SyntheticGateTwoEvidence",
      keySpec: "ECC_NIST_P256",
      keyUsage: "SIGN_VERIFY",
      multiRegion: false
    },
    cloudFormationServiceRole: {
      roleName: rolesTemplate.Resources.CloudFormationServiceRole.Properties.RoleName,
      maxSessionDuration: rolesTemplate.Resources.CloudFormationServiceRole.Properties
        .MaxSessionDuration,
      trustSha256: sha256(canonicalBytes(rolesTemplate.Resources
        .CloudFormationServiceRole.Properties.AssumeRolePolicyDocument)),
      inlinePolicySha256: sha256(canonicalBytes(rolesTemplate.Resources
        .CloudFormationServiceRole.Properties.Policies[0].PolicyDocument)),
      permissionsBoundaryLogicalId: rolesTemplate.Resources
        .CloudFormationServiceRole.Properties.PermissionsBoundary.Ref,
      permissionsBoundaryPolicySha256:
        releaseAuthority.cloudFormationPermissionsBoundary.policySha256,
      permissionsBoundaryAllowInventorySha256:
        releaseAuthority.cloudFormationPermissionsBoundary
          .allowInventorySha256,
      tagsSha256: sha256(canonicalBytes(rolesTemplate.Resources
        .CloudFormationServiceRole.Properties.Tags))
    },
    releaseCoordinatorRole: {
      roleName: rolesTemplate.Resources.ReleaseCoordinatorRole.Properties
        .RoleName,
      trustSha256: sha256(canonicalBytes(rolesTemplate.Resources
        .ReleaseCoordinatorRole.Properties.AssumeRolePolicyDocument)),
      inlinePolicySha256: sha256(canonicalBytes(rolesTemplate.Resources
        .ReleaseCoordinatorRole.Properties.Policies[0].PolicyDocument)),
      inlinePolicyBytes: Buffer.byteLength(canonicalJson(rolesTemplate.Resources
        .ReleaseCoordinatorRole.Properties.Policies[0].PolicyDocument),
      "utf8"),
      allowedWorkflows: rolesTemplate.Resources.ReleaseCoordinatorRole
        .Properties.AssumeRolePolicyDocument.Statement[0].Condition
        .StringEquals["token.actions.githubusercontent.com:workflow"],
      requiredRuntimeWorkflowRefs:
        releaseAuthority.requiredRuntimeWorkflowRefs.ReleaseCoordinatorRole,
      tagsSha256: sha256(canonicalBytes(rolesTemplate.Resources
        .ReleaseCoordinatorRole.Properties.Tags))
    },
    releaseControlPlane: releaseAuthority,
    forbiddenResourceFamilies: [
      "AWS::EC2::*", "AWS::RDS::DBInstance", "AWS::ECS::Service",
      "AWS::ElasticLoadBalancing*::*", "AWS::NATGateway"
    ],
    probeResourcesEnabled: false
  };
  return Object.freeze({
    ...contract,
    contractSha256: sha256(canonicalBytes(contract)),
    resourceInventorySha256: sha256(canonicalBytes(entries.map(({ logicalId, type }) => ({
      logicalId, type
    }))))
  });
}

function validatePlan(plan, contract) {
  const code = "CONTROLLER_RELEASE_PLAN_REJECTED";
  requireCondition(exactKeys(plan, [
    "application", "authoritySeparation", "build", "claimBoundary",
    "controlPlane", "costGate",
    "createResourceInventory", "createResourceInventorySha256",
    "deploymentRoles", "executionGate", "logEvidence", "nextGate",
    "planSha256", "primaryRuntime", "schemaVersion", "sourceCommit", "stack",
    "status", "teardownGate", "treeDigest", "uploads"
  ]) && plan.schemaVersion === "prooftoact.release-upload-plan.v2" &&
    plan.status === "PREPARED_NOT_AUTHORIZED" && HEX_40.test(plan.sourceCommit ?? "") &&
    HEX_40.test(plan.treeDigest ?? "") &&
    exactKeys(plan.application, [
      "identitySha256", "sourceCommit", "templateSha256", "treeDigest"
    ]) &&
    exactKeys(plan.controlPlane, [
      "controllerSha256", "identitySha256", "preparerSha256",
      "rolesTemplateSha256", "sourceCommit", "treeDigest"
    ]) &&
    plan.application.sourceCommit === plan.sourceCommit &&
    plan.application.treeDigest === plan.treeDigest &&
    plan.application.templateSha256 === REVIEWED_GATE2_TEMPLATE_SHA256 &&
    HEX_40.test(plan.controlPlane.sourceCommit ?? "") &&
    HEX_40.test(plan.controlPlane.treeDigest ?? "") &&
    HEX_64.test(plan.controlPlane.controllerSha256 ?? "") &&
    HEX_64.test(plan.controlPlane.preparerSha256 ?? "") &&
    plan.controlPlane.rolesTemplateSha256 === REVIEWED_ROLES_TEMPLATE_SHA256 &&
    plan.application.identitySha256 === sha256(canonicalBytes({
      sourceCommit: plan.application.sourceCommit,
      templateSha256: plan.application.templateSha256,
      treeDigest: plan.application.treeDigest
    })) &&
    plan.controlPlane.identitySha256 === sha256(canonicalBytes({
      controllerSha256: plan.controlPlane.controllerSha256,
      preparerSha256: plan.controlPlane.preparerSha256,
      rolesTemplateSha256: plan.controlPlane.rolesTemplateSha256,
      sourceCommit: plan.controlPlane.sourceCommit,
      treeDigest: plan.controlPlane.treeDigest
    })) &&
    plan.build?.templateSha256 === REVIEWED_GATE2_TEMPLATE_SHA256 &&
    plan.deploymentRoles?.templateSha256 === REVIEWED_ROLES_TEMPLATE_SHA256 &&
    plan.stack?.name === "prooftoact-gate2" && plan.stack?.region === "us-east-1" &&
    plan.stack?.operation === "CREATE_CHANGE_SET_ONLY" &&
    plan.stack?.probesEnabled === false && plan.stack?.updateAllowed === false &&
    plan.stack?.directCreateStackAllowed === false &&
    plan.stack?.terminationProtectionRequired === true &&
    plan.executionGate?.status ===
      "HOLD_RUNTIME_AUTHORITY_AND_RECEIPTS_REQUIRED" &&
    plan.executionGate?.requiredChangeSetType === "CREATE" &&
    plan.executionGate?.requiredStackAbsence === true &&
    plan.costGate?.forecastStatus === "AVAILABLE" &&
    Number.isFinite(plan.costGate?.maximumProjectedTotalUsd) &&
    plan.costGate.maximumProjectedTotalUsd <= 12 &&
    plan.teardownGate?.residualCensusRequired === true, code);
  const withoutDigest = { ...plan };
  delete withoutDigest.planSha256;
  requireCondition(plan.planSha256 === sha256(canonicalBytes(withoutDigest)), code);
  const expectedInventory = contract.resources.map(({ logicalId, type }) => ({
    logicalId, type
  }));
  requireCondition(canonicalJson(plan.createResourceInventory) ===
    canonicalJson(expectedInventory) &&
    plan.createResourceInventorySha256 === contract.resourceInventorySha256, code);
  requireCondition(Array.isArray(plan.uploads) && plan.uploads.length === 6 &&
    plan.uploads.map(({ name }) => name).sort().join("\n") ===
      [...ARTIFACT_NAMES].sort().join("\n"), code);
  for (const upload of plan.uploads) {
    requireCondition(exactKeys(upload, [
      "bytes", "codeSha256", "localPath", "name", "s3Bucket", "s3Key",
      "sha256", "sourceSha256", "uploadContract"
    ]) && ARTIFACT_NAMES.includes(upload.name) &&
      Number.isSafeInteger(upload.bytes) && upload.bytes > 0 &&
      HEX_64.test(upload.sha256 ?? "") && HEX_64.test(upload.sourceSha256 ?? "") &&
      typeof upload.codeSha256 === "string" && upload.codeSha256.length === 44 &&
      upload.uploadContract === "PUT_ONCE_THEN_READ_BACK_EXACT_VERSION" &&
      upload.s3Key === `gate2/${plan.sourceCommit}/${upload.name}-${upload.sha256}.zip`,
    code);
  }
  return plan;
}

function commonReceiptBinding(claims, context, code) {
  requireCondition(claims.operationId === context.operationId &&
    claims.controllerInstanceId === context.controllerInstanceId &&
    claims.controllerHostIdSha256 === context.controllerHostIdSha256 &&
    claims.journalRootSha256 === context.journalRootSha256 &&
    claims.planSha256 === context.plan.planSha256 &&
    claims.sourceCommit === context.plan.sourceCommit &&
    claims.treeDigest === context.plan.treeDigest && claims.stage === context.stage,
  code);
}

function validateApproval(claims, context, anchors, envelope) {
  const code = "CONTROLLER_OPERATOR_APPROVAL_REJECTED";
  requireCondition(exactKeys(claims, [
    "action", "approvalId", "approvedBy", "changeSetArn", "controllerHostIdSha256",
    "controllerInstanceId", "controllerKeySha256", "journalRootSha256",
    "maximumApprovedUsd",
    "oneShot", "operationId", "parameterManifestSha256", "planSha256",
    "providerAccountId", "resourceContractSha256", "sourceCommit", "stage",
    "storeNamespaceArn", "treeDigest", "trustFingerprints", "runtime"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.action === STAGE_CONTRACT[context.stage].action &&
    UUID.test(claims.approvalId ?? "") && claims.approvedBy === "BRIAN_SMITH" &&
    claims.oneShot === true && ACCOUNT_ID.test(claims.providerAccountId ?? "") &&
    Number.isFinite(claims.maximumApprovedUsd) && claims.maximumApprovedUsd >= 0 &&
    claims.maximumApprovedUsd <= 12 && HEX_64.test(claims.parameterManifestSha256 ?? "") &&
    claims.resourceContractSha256 === context.contract.contractSha256 &&
    HEX_64.test(claims.controllerKeySha256 ?? "") &&
    exactKeys(claims.runtime, [
      "controlPlaneCommit", "controlPlaneIdentitySha256",
      "controlPlaneTreeDigest", "controllerSha256", "gitPath", "gitSha256",
      "nodePath", "nodeSha256"
    ]) && HEX_64.test(claims.runtime.controllerSha256 ?? "") &&
    claims.runtime.controlPlaneCommit === context.plan.controlPlane.sourceCommit &&
    claims.runtime.controlPlaneTreeDigest === context.plan.controlPlane.treeDigest &&
    claims.runtime.controlPlaneIdentitySha256 ===
      context.plan.controlPlane.identitySha256 &&
    claims.runtime.controllerSha256 ===
      context.plan.controlPlane.controllerSha256 &&
    HEX_64.test(claims.runtime.gitSha256 ?? "") &&
    HEX_64.test(claims.runtime.nodeSha256 ?? "") &&
    path.isAbsolute(claims.runtime.gitPath ?? "") &&
    path.isAbsolute(claims.runtime.nodePath ?? "") &&
    typeof claims.changeSetArn === "string" &&
    exactKeys(claims.trustFingerprints, [
      "CONTROLLER_STORE", "OPERATOR", "PROVIDER"
    ]) && Object.entries(claims.trustFingerprints).every(([issuer, fingerprint]) =>
      fingerprint === anchors[issuer].fingerprint), code);
  const expectedNamespace =
    `arn:aws:dynamodb:us-east-1:${claims.providerAccountId}:table/prooftoact-release-controller`;
  requireCondition(claims.storeNamespaceArn === expectedNamespace &&
    !claims.storeNamespaceArn.startsWith("file:") &&
    !claims.storeNamespaceArn.startsWith("local:"), code);
  if (["EXECUTE", "RECONCILE", "LIVE", "EVIDENCE"].includes(context.stage)) {
    requireCondition(/^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
      .test(claims.changeSetArn) && claims.changeSetArn.split(":")[4] ===
        claims.providerAccountId, code);
  }
  if (["TEARDOWN", "RESIDUAL"].includes(context.stage)) {
    requireCondition(claims.action !== "EXECUTE_EXACT_CREATE_CHANGE_SET", code);
  }
  requireCondition(envelope.issuedAt === context.approvalIssuedAt &&
    envelope.expiresAt === context.approvalExpiresAt, code);
  return claims;
}

function validateStoreReservation(claims, context, approval) {
  const code = "CONTROLLER_GLOBAL_STORE_REJECTED";
  requireCondition(exactKeys(claims, [
    "action", "approvalId", "conditionalWrite", "controllerHostIdSha256",
    "controllerInstanceId", "globallyAuthoritative", "journalRootSha256",
    "leaseExpiresAt", "leaseId", "namespaceArn", "oneShot", "operationId",
    "planSha256", "previousVersion", "replayCount", "reservationVersion",
    "sourceCommit", "stage", "state", "storageStatus", "stronglyConsistentRead",
    "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.action === STAGE_CONTRACT[context.stage].action &&
    claims.approvalId === approval.approvalId && claims.namespaceArn ===
      approval.storeNamespaceArn && claims.globallyAuthoritative === true &&
    claims.stronglyConsistentRead === true && claims.conditionalWrite === true &&
    claims.oneShot === true && UUID.test(claims.leaseId ?? "") &&
    claims.state === STAGE_CONTRACT[context.stage].storeState &&
    claims.storageStatus === "AVAILABLE" && claims.replayCount === 0 &&
    Number.isSafeInteger(claims.reservationVersion) && claims.reservationVersion > 0 &&
    Number.isSafeInteger(claims.previousVersion) &&
    claims.previousVersion + 1 === claims.reservationVersion &&
    parseIso(claims.leaseExpiresAt, code) > context.now, code);
  return claims;
}

function validateStoreJournal(claims, context, reservation) {
  const code = "CONTROLLER_DURABLE_JOURNAL_REJECTED";
  requireCondition(exactKeys(claims, [
    "appendOnly", "conditionalWrite", "controllerHostIdSha256",
    "controllerInstanceId", "durable", "entrySha256", "event",
    "fsyncStatus", "journalRootSha256", "namespaceArn", "operationId",
    "planSha256", "previousEntrySha256", "sequence", "sourceCommit", "stage",
    "storageStatus", "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.namespaceArn === reservation.namespaceArn &&
    claims.appendOnly === true && claims.conditionalWrite === true &&
    claims.durable === true && claims.fsyncStatus === "DURABLE" &&
    claims.storageStatus === "AVAILABLE" && Number.isSafeInteger(claims.sequence) &&
    claims.sequence === reservation.reservationVersion + 1 &&
    claims.previousEntrySha256 === sha256(canonicalBytes(reservation)) &&
    plainObject(claims.event) && exactKeys(claims.event, [
      "action", "eventType", "leaseId", "operationId", "reservationVersion",
      "state"
    ]) && claims.event.action === STAGE_CONTRACT[context.stage].action &&
    claims.event.eventType === STAGE_CONTRACT[context.stage].journalEvent &&
    claims.event.leaseId === reservation.leaseId &&
    claims.event.operationId === context.operationId &&
    claims.event.reservationVersion === reservation.reservationVersion &&
    claims.event.state === reservation.state &&
    claims.entrySha256 === sha256(canonicalBytes({
      event: claims.event,
      namespaceArn: claims.namespaceArn,
      previousEntrySha256: claims.previousEntrySha256,
      sequence: claims.sequence
    })), code);
  return claims;
}

function executionJournalEntryDigest(namespaceArn, entry) {
  return sha256(canonicalBytes({
    event: entry.event,
    namespaceArn,
    previousEntrySha256: entry.previousEntrySha256,
    sequence: entry.sequence
  }));
}

function validateExecutionTransitionJournal(claims, context, approval) {
  const code = "CONTROLLER_EXECUTION_TRANSITION_JOURNAL_REJECTED";
  requireCondition(exactKeys(claims, [
    "after", "appendOnly", "before", "changeSetArn",
    "controllerHostIdSha256", "controllerInstanceId", "durable",
    "executionAttemptId", "journalRootSha256", "namespaceArn", "operationId",
    "planSha256", "sourceCommit", "stage", "storageStatus", "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.namespaceArn === approval.storeNamespaceArn &&
    claims.changeSetArn === approval.changeSetArn && claims.appendOnly === true &&
    claims.durable === true && claims.storageStatus === "AVAILABLE" &&
    UUID.test(claims.executionAttemptId ?? ""), code);
  for (const [position, expectedEvent] of [
    ["before", "BEFORE_EXECUTE_CHANGE_SET"],
    ["after", "AFTER_EXECUTE_CHANGE_SET_DISPATCH"]
  ]) {
    const entry = claims[position];
    requireCondition(exactKeys(entry, [
      "entrySha256", "event", "previousEntrySha256", "providerRequestId",
      "sequence"
    ]) && Number.isSafeInteger(entry.sequence) && entry.sequence > 0 &&
      HEX_64.test(entry.previousEntrySha256 ?? "") &&
      UUID.test(entry.providerRequestId ?? "") &&
      exactKeys(entry.event, [
        "action", "eventType", "executionAttemptId", "operationId"
      ]) && entry.event.action === "EXECUTE_EXACT_CREATE_CHANGE_SET" &&
      entry.event.eventType === expectedEvent &&
      entry.event.executionAttemptId === claims.executionAttemptId &&
      entry.event.operationId === context.operationId &&
      entry.entrySha256 === executionJournalEntryDigest(
        claims.namespaceArn,
        entry
      ), code);
  }
  requireCondition(claims.after.sequence === claims.before.sequence + 1 &&
    claims.after.previousEntrySha256 === claims.before.entrySha256, code);
  return claims;
}

function validateProviderIdentity(claims, context, approval) {
  const code = "CONTROLLER_PROVIDER_IDENTITY_REJECTED";
  requireCondition(exactKeys(claims, [
    "accountId", "authenticated", "controllerHostIdSha256",
    "controllerInstanceId", "environment", "evidenceMethod",
    "journalRootSha256", "operationId", "partition", "planSha256",
    "principalArn", "providerRequestId", "providerTimestamp", "ref", "region",
    "repository", "roleArn", "sessionExpiresAt", "sourceCommit", "sourceIdentity",
    "stage", "treeDigest", "workflow"
  ]), code);
  commonReceiptBinding(claims, context, code);
  const stage = STAGE_CONTRACT[context.stage];
  const roleArn = `arn:aws:iam::${approval.providerAccountId}:role/${stage.roleName}`;
  requireCondition(claims.accountId === approval.providerAccountId &&
    claims.authenticated === true && claims.evidenceMethod ===
      "AWS_STS_GET_CALLER_ID_LIVE" && claims.partition === "aws" &&
    claims.region === "us-east-1" && claims.repository === "Flash-Bri/prooftoact" &&
    claims.ref === "refs/heads/main" && claims.environment === stage.environment &&
    claims.workflow === stage.workflow &&
    claims.roleArn === roleArn && claims.sourceIdentity === context.controllerInstanceId &&
    claims.principalArn.startsWith(
      `arn:aws:sts::${approval.providerAccountId}:assumed-role/${stage.roleName}/`) &&
    UUID.test(claims.providerRequestId ?? "") &&
    parseIso(claims.providerTimestamp, code) <= context.now &&
    context.now - parseIso(claims.providerTimestamp, code) <= 5 * 60 * 1000 &&
    parseIso(claims.sessionExpiresAt, code) > context.now, code);
  return claims;
}

function validateStackAbsence(claims, context, approval) {
  const code = "CONTROLLER_STACK_ABSENCE_REJECTED";
  requireCondition(exactKeys(claims, [
    "absent", "controllerHostIdSha256", "controllerInstanceId", "journalRootSha256",
    "observedAt", "operationId", "planSha256", "providerRequestId", "region",
    "sourceCommit", "stackName", "stage", "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.absent === true && claims.stackName === "prooftoact-gate2" &&
    claims.region === "us-east-1" && UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000 &&
    parseIso(claims.observedAt, code) <= context.now && approval.providerAccountId,
  code);
  return claims;
}

function artifactIdentitySha256(value) {
  return sha256(canonicalBytes({
    bucket: value.bucket,
    codeSha256: value.codeSha256,
    contentLength: value.contentLength,
    etag: value.etag,
    key: value.key,
    name: value.name,
    sha256: value.sha256,
    sourceSha256: value.sourceSha256,
    versionId: value.versionId
  }));
}

function validateArtifactReadback(claims, context) {
  const code = "CONTROLLER_ARTIFACT_READBACK_REJECTED";
  requireCondition(exactKeys(claims, [
    "artifacts", "controllerHostIdSha256", "controllerInstanceId",
    "journalRootSha256", "observedAt", "operationId", "planSha256",
    "sourceCommit", "stage", "treeDigest"
  ]) && Array.isArray(claims.artifacts) && claims.artifacts.length === 6, code);
  commonReceiptBinding(claims, context, code);
  const byName = new Map(context.plan.uploads.map((upload) => [upload.name, upload]));
  const identities = new Set();
  for (const artifact of claims.artifacts) {
    requireCondition(exactKeys(artifact, [
      "bucket", "codeSha256", "contentLength", "etag", "immutable", "key",
      "name", "objectIdentitySha256", "providerRequestId", "readbackSha256",
      "sha256", "sourceSha256", "versionId", "versioningStatus"
    ]), code);
    const expected = byName.get(artifact.name);
    requireCondition(expected && artifact.bucket === expected.s3Bucket &&
      artifact.key === expected.s3Key && artifact.sha256 === expected.sha256 &&
      artifact.codeSha256 === expected.codeSha256 &&
      artifact.sourceSha256 === expected.sourceSha256 &&
      artifact.contentLength === expected.bytes && artifact.immutable === true &&
      artifact.versioningStatus === "Enabled" &&
      typeof artifact.versionId === "string" && artifact.versionId.length >= 8 &&
      artifact.versionId !== "null" && typeof artifact.etag === "string" &&
      artifact.etag.length >= 2 && UUID.test(artifact.providerRequestId ?? "") &&
      artifact.objectIdentitySha256 === artifactIdentitySha256(artifact) &&
      artifact.readbackSha256 === artifact.sha256, code);
    requireCondition(!identities.has(artifact.objectIdentitySha256), code);
    identities.add(artifact.objectIdentitySha256);
  }
  requireCondition([...byName.keys()].every((name) =>
    claims.artifacts.some((artifact) => artifact.name === name)) &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000,
  code);
  return claims;
}

function validateParameterManifest(manifest, context, artifacts) {
  const code = "CONTROLLER_PARAMETER_MANIFEST_REJECTED";
  requireCondition(Array.isArray(manifest) && manifest.length > 0 &&
    manifest.every((item) => exactKeys(item, ["name", "sensitivity", "valueSha256"]) &&
      typeof item.name === "string" && item.name.length > 0 &&
      ["PUBLIC", "PRIVATE_IDENTIFIER", "SECRET_REFERENCE"].includes(item.sensitivity) &&
      HEX_64.test(item.valueSha256 ?? "")), code);
  const names = manifest.map(({ name }) => name);
  requireCondition(new Set(names).size === names.length, code);
  const templateParameters = Object.keys(context.gate2Template.Parameters).sort();
  requireCondition(names.sort().join("\n") === templateParameters.join("\n"), code);
  const byName = new Map(manifest.map((item) => [item.name, item]));
  const known = {
    ArtifactBucket: context.plan.uploads[0].s3Bucket,
    EnableProbeFunctions: "false",
    PackageLockDigest: context.plan.build.packageLockSha256,
    SourceCommit: context.plan.sourceCommit,
    TreeDigest: context.plan.treeDigest
  };
  for (const artifact of artifacts.artifacts) {
    const prefix = artifact.name[0].toUpperCase() + artifact.name.slice(1);
    for (const [suffix, value] of [
      ["ArtifactCodeSha256", artifact.codeSha256],
      ["ArtifactDigest", artifact.sha256],
      ["ArtifactKey", artifact.key],
      ["ArtifactVersion", artifact.versionId],
      ["SourceDigest", artifact.sourceSha256]
    ]) {
      if (byName.has(`${prefix}${suffix}`)) known[`${prefix}${suffix}`] = value;
    }
  }
  for (const [name, value] of Object.entries(known)) {
    requireCondition(byName.get(name)?.valueSha256 === sha256(Buffer.from(value, "utf8")),
      code);
  }
  return Object.freeze({ manifest, digest: sha256(canonicalBytes(manifest)) });
}

function validateChangeSet(claims, context, approval, artifacts) {
  const code = "CONTROLLER_CHANGE_SET_REJECTED";
  requireCondition(exactKeys(claims, [
    "capabilities", "changeSetArn", "changeSetName", "changeSetType", "changes",
    "changesSha256", "controllerHostIdSha256", "controllerInstanceId",
    "executionStatus", "includeNestedStacks", "journalRootSha256", "observedAt",
    "operationId", "parameterManifest", "parameterManifestSha256", "planSha256",
    "providerRequestId", "resourceContractSha256", "roleArn", "sourceCommit",
    "stackName", "stage", "status", "templateSha256", "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  const manifest = validateParameterManifest(claims.parameterManifest, context, artifacts);
  requireCondition(claims.changeSetArn === approval.changeSetArn &&
    /^prooftoact-release-[a-z0-9-]{1,64}$/u.test(claims.changeSetName ?? "") &&
    claims.changeSetType === "CREATE" && claims.stackName === "prooftoact-gate2" &&
    claims.status === "CREATE_COMPLETE" && claims.executionStatus === "AVAILABLE" &&
    claims.includeNestedStacks === false &&
    canonicalJson(claims.capabilities) === canonicalJson(["CAPABILITY_NAMED_IAM"]) &&
    claims.templateSha256 === REVIEWED_GATE2_TEMPLATE_SHA256 &&
    claims.resourceContractSha256 === context.contract.contractSha256 &&
    claims.parameterManifestSha256 === manifest.digest &&
    claims.parameterManifestSha256 === approval.parameterManifestSha256 &&
    claims.roleArn ===
      `arn:aws:iam::${approval.providerAccountId}:role/ProofToActGate2CloudFormation` &&
    UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000, code);
  requireCondition(Array.isArray(claims.changes) &&
    claims.changes.length === context.contract.resources.length &&
    claims.changes.every((change) => exactKeys(change, [
      "action", "logicalId", "replacement", "resourceType"
    ]) && change.action === "Add" && change.replacement === "False") &&
    claims.changesSha256 === sha256(canonicalBytes(claims.changes)), code);
  const expected = context.contract.resources.map(({ logicalId, type }) => ({
    action: "Add", logicalId, replacement: "False", resourceType: type
  })).sort((left, right) => left.logicalId.localeCompare(right.logicalId));
  requireCondition(canonicalJson([...claims.changes]
    .sort((left, right) => left.logicalId.localeCompare(right.logicalId))) ===
    canonicalJson(expected), code);
  return claims;
}

function validateIamSimulation(claims, context, approval) {
  const code = "CONTROLLER_IAM_SIMULATION_REJECTED";
  requireCondition(exactKeys(claims, [
    "allowChecks", "allPoliciesReadBack", "boundaryPolicySha256",
    "cloudFormationServiceRole",
    "controllerHostIdSha256", "controllerInstanceId", "denyChecks",
    "journalRootSha256", "observedAt", "operationId", "planSha256",
    "providerRequestId", "rolesTemplateSha256", "sourceCommit", "stage",
    "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.allPoliciesReadBack === true &&
    claims.rolesTemplateSha256 === REVIEWED_ROLES_TEMPLATE_SHA256 &&
    claims.boundaryPolicySha256 ===
      context.contract.cloudFormationServiceRole
        .permissionsBoundaryPolicySha256 &&
    UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000, code);
  const serviceRole = claims.cloudFormationServiceRole;
  const expectedServiceRole = context.contract.cloudFormationServiceRole;
  requireCondition(exactKeys(serviceRole, [
    "arn", "inlinePolicySha256", "maxSessionDuration", "permissionsBoundaryArn",
    "permissionsBoundaryPolicySha256", "roleId", "roleName", "tagsSha256",
    "trustSha256"
  ]) && serviceRole.arn ===
      `arn:aws:iam::${approval.providerAccountId}:role/ProofToActGate2CloudFormation` &&
    /^[A-Z0-9]{16,64}$/u.test(serviceRole.roleId ?? "") &&
    serviceRole.roleName === expectedServiceRole.roleName &&
    serviceRole.maxSessionDuration === expectedServiceRole.maxSessionDuration &&
    serviceRole.trustSha256 === expectedServiceRole.trustSha256 &&
    serviceRole.inlinePolicySha256 === expectedServiceRole.inlinePolicySha256 &&
    serviceRole.tagsSha256 === expectedServiceRole.tagsSha256 &&
    serviceRole.permissionsBoundaryArn ===
      `arn:aws:iam::${approval.providerAccountId}:policy/ProofToActGate2CloudFormationBoundary` &&
    serviceRole.permissionsBoundaryPolicySha256 === claims.boundaryPolicySha256 &&
    expectedServiceRole.permissionsBoundaryLogicalId ===
      "CloudFormationPermissionsBoundary",
  code);
  const validateChecks = (checks, names, decision) => {
    requireCondition(Array.isArray(checks) && checks.length === names.length &&
      checks.every((check) => exactKeys(check, ["decision", "name", "resourceSha256"]) &&
        names.includes(check.name) && check.decision === decision &&
        HEX_64.test(check.resourceSha256 ?? "")) &&
      new Set(checks.map(({ name }) => name)).size === names.length, code);
  };
  validateChecks(claims.allowChecks, IAM_ALLOW_CHECKS, "allowed");
  validateChecks(claims.denyChecks, IAM_DENY_CHECKS, "explicitDeny");
  requireCondition(approval.providerAccountId, code);
  return claims;
}

function validateAuthoritySeparation(claims, context, approval) {
  const code = "CONTROLLER_AUTHORITY_SEPARATION_REJECTED";
  requireCondition(exactKeys(claims, [
    "controllerHostIdSha256", "controllerInstanceId", "journalRootSha256",
    "observedAt", "operationId", "planSha256", "principals",
    "providerRequestId", "sourceCommit", "stage", "treeDigest"
  ]) && plainObject(claims.principals) &&
    exactKeys(claims.principals, Object.keys(LANE_ROLE_NAMES)), code);
  commonReceiptBinding(claims, context, code);
  const arns = [];
  for (const [lane, roleName] of Object.entries(LANE_ROLE_NAMES)) {
    const principal = claims.principals[lane];
    const expectedPolicySha256 = lane === "coordinator"
      ? context.contract.releaseCoordinatorRole.inlinePolicySha256
      : null;
    requireCondition(exactKeys(principal, [
      "allowedLane", "arn", "deniedLanes", "policySha256", "readOnly"
    ]) && principal.allowedLane === lane &&
      principal.arn === `arn:aws:iam::${approval.providerAccountId}:role/${roleName}` &&
      HEX_64.test(principal.policySha256 ?? "") &&
      (expectedPolicySha256 === null ||
        principal.policySha256 === expectedPolicySha256) &&
      Array.isArray(principal.deniedLanes) &&
      [...principal.deniedLanes].sort().join("\n") ===
        Object.keys(LANE_ROLE_NAMES).filter((candidate) => candidate !== lane)
          .sort().join("\n") &&
      principal.readOnly === (lane === "evidence"), code);
    arns.push(principal.arn);
  }
  requireCondition(new Set(arns).size === arns.length &&
    UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000, code);
  return claims;
}

function validateCostCensus(claims, context, approval) {
  const code = "CONTROLLER_COST_CENSUS_REJECTED";
  requireCondition(exactKeys(claims, [
    "asOf", "caps", "controllerHostIdSha256", "controllerInstanceId",
    "currentResourceCensusStatus", "currentSpendUsd", "dataStatus",
    "forecastLineItems", "forecastTotalUsd", "journalRootSha256",
    "maximumApprovedUsd", "operationId", "planSha256", "providerRequestId",
    "resourceInventorySha256", "sourceCommit", "stage", "treeDigest",
    "undeclaredResourceCount", "unknownCostCount"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.dataStatus === "AVAILABLE" &&
    claims.currentResourceCensusStatus === "COMPLETE" &&
    Number.isFinite(claims.currentSpendUsd) && claims.currentSpendUsd >= 0 &&
    Number.isFinite(claims.forecastTotalUsd) && claims.forecastTotalUsd >= 0 &&
    claims.maximumApprovedUsd === approval.maximumApprovedUsd &&
    claims.maximumApprovedUsd <= 12 &&
    claims.currentSpendUsd + claims.forecastTotalUsd <= claims.maximumApprovedUsd &&
    claims.unknownCostCount === 0 && claims.undeclaredResourceCount === 0 &&
    claims.resourceInventorySha256 === context.contract.resourceInventorySha256 &&
    UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.asOf, code) <= 5 * 60 * 1000 &&
    exactKeys(claims.caps, [
      "apiRequests", "artifactBytes", "lambdaInvocations", "logBytes",
      "maximumLambdaConcurrency"
    ]) && Number.isSafeInteger(claims.caps.apiRequests) &&
    claims.caps.apiRequests > 0 && claims.caps.apiRequests <= 100 &&
    Number.isSafeInteger(claims.caps.lambdaInvocations) &&
    claims.caps.lambdaInvocations > 0 && claims.caps.lambdaInvocations <= 20 &&
    Number.isSafeInteger(claims.caps.maximumLambdaConcurrency) &&
    claims.caps.maximumLambdaConcurrency === 8 &&
    Number.isSafeInteger(claims.caps.logBytes) &&
    claims.caps.logBytes > 0 && claims.caps.logBytes <= 10 * 1024 * 1024 &&
    Number.isSafeInteger(claims.caps.artifactBytes) &&
    claims.caps.artifactBytes === context.plan.uploads
      .reduce((sum, upload) => sum + upload.bytes, 0), code);
  requireCondition(Array.isArray(claims.forecastLineItems) &&
    claims.forecastLineItems.length > 0 && claims.forecastLineItems.every((item) =>
      exactKeys(item, ["forecastUsd", "name", "unitCostUsd", "units"]) &&
      typeof item.name === "string" && item.name.length > 0 &&
      Number.isFinite(item.units) && item.units >= 0 &&
      Number.isFinite(item.unitCostUsd) && item.unitCostUsd >= 0 &&
      Number.isFinite(item.forecastUsd) && item.forecastUsd >= 0) &&
    Math.abs(claims.forecastLineItems.reduce((sum, item) =>
      sum + item.forecastUsd, 0) - claims.forecastTotalUsd) < 1e-9, code);
  return claims;
}

function validateResourceContractReceipt(claims, context) {
  const code = "CONTROLLER_PROVIDER_RESOURCE_CONTRACT_REJECTED";
  requireCondition(exactKeys(claims, [
    "activeResourceCount", "alwaysOnResourceCount", "apiRoutesSha256",
    "controllerHostIdSha256", "controllerInstanceId", "ec2ResourceCount",
    "journalRootSha256", "kmsPostureSha256", "lambdaPostureSha256",
    "logAndAlarmPostureSha256", "natGatewayCount", "observedAt", "operationId",
    "planSha256", "probeResourcesEnabled", "providerRequestId",
    "resourceContractSha256", "resourceInventorySha256", "rolesTemplateSha256",
    "sourceCommit", "stage", "templateSha256", "treeDigest",
    "undeclaredResourceCount"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.templateSha256 === REVIEWED_GATE2_TEMPLATE_SHA256 &&
    claims.rolesTemplateSha256 === REVIEWED_ROLES_TEMPLATE_SHA256 &&
    claims.resourceContractSha256 === context.contract.contractSha256 &&
    claims.resourceInventorySha256 === context.contract.resourceInventorySha256 &&
    claims.activeResourceCount === context.contract.resources.length &&
    claims.undeclaredResourceCount === 0 && claims.natGatewayCount === 0 &&
    claims.ec2ResourceCount === 0 && claims.alwaysOnResourceCount === 0 &&
    claims.probeResourcesEnabled === false &&
    claims.apiRoutesSha256 === sha256(canonicalBytes(context.contract.routes)) &&
    claims.lambdaPostureSha256 === sha256(canonicalBytes(context.contract.lambdas)) &&
    claims.logAndAlarmPostureSha256 === sha256(canonicalBytes({
      alarms: context.contract.alarms,
      logGroups: context.contract.logGroups
    })) && claims.kmsPostureSha256 === sha256(canonicalBytes(context.contract.kms)) &&
    UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000, code);
  return claims;
}

function validateExecutionResult(claims, context) {
  const code = "CONTROLLER_EXECUTION_RECONCILIATION_REJECTED";
  requireCondition(exactKeys(claims, [
    "changeSetArn", "controllerHostIdSha256", "controllerInstanceId",
    "cloudFormationServiceRole",
    "executionOutcome", "journalRootSha256", "observedAt", "operationId",
    "planSha256", "providerRequestId", "readOnlyReconciliation",
    "resourceContractSha256", "sourceCommit", "stackName", "stackStatus",
    "stage", "terminationProtection", "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  requireCondition(claims.stackName === "prooftoact-gate2" &&
    claims.resourceContractSha256 === context.contract.contractSha256 &&
    claims.readOnlyReconciliation === true && UUID.test(claims.providerRequestId ?? "") &&
    context.now - parseIso(claims.observedAt, code) <= 5 * 60 * 1000 &&
    ["CONFIRMED_CREATE_COMPLETE", "FAILED_TERMINAL", "AMBIGUOUS"]
      .includes(claims.executionOutcome), code);
  const serviceRole = claims.cloudFormationServiceRole;
  requireCondition(exactKeys(serviceRole, [
    "arn", "inlinePolicySha256", "permissionsBoundaryPolicySha256", "roleId",
    "trustSha256"
  ]) && /^[A-Z0-9]{16,64}$/u.test(serviceRole.roleId ?? "") &&
    serviceRole.trustSha256 === context.contract.cloudFormationServiceRole.trustSha256 &&
    serviceRole.inlinePolicySha256 ===
      context.contract.cloudFormationServiceRole.inlinePolicySha256 &&
    HEX_64.test(serviceRole.permissionsBoundaryPolicySha256 ?? "") &&
    serviceRole.arn.startsWith("arn:aws:iam::") &&
    serviceRole.arn.endsWith(":role/ProofToActGate2CloudFormation"), code);
  if (claims.executionOutcome === "CONFIRMED_CREATE_COMPLETE") {
    requireCondition(claims.stackStatus === "CREATE_COMPLETE" &&
      claims.terminationProtection === true, code);
  } else if (claims.executionOutcome === "AMBIGUOUS") {
    requireCondition(claims.stackStatus === "UNKNOWN" &&
      claims.terminationProtection === false, code);
  }
  return claims;
}

function validateKeepAliveAndTeardown(receipts, context, approval) {
  if (!["TEARDOWN", "RESIDUAL"].includes(context.stage)) return null;
  const code = "CONTROLLER_TEARDOWN_CONTRACT_REJECTED";
  const keepAlive = receipts.KEEP_ALIVE_STATE;
  requireCondition(keepAlive, code);
  const claims = keepAlive.claims;
  requireCondition(exactKeys(claims, [
    "controllerHostIdSha256", "controllerInstanceId", "judgeAccessThrough",
    "journalRootSha256", "observedAt", "operationId", "planSha256",
    "providerRequestId", "resourceInventorySha256", "sourceCommit", "stage",
    "treeDigest"
  ]), code);
  commonReceiptBinding(claims, context, code);
  const accessThrough = parseIso(claims.judgeAccessThrough, code);
  requireCondition(context.now > accessThrough &&
    claims.resourceInventorySha256 === context.contract.resourceInventorySha256 &&
    UUID.test(claims.providerRequestId ?? "") &&
    claims.observedAt && approval.action === STAGE_CONTRACT[context.stage].action,
  code);
  if (context.stage === "RESIDUAL") {
    const censuses = receipts.RESIDUAL_CENSUS?.claims;
    requireCondition(censuses && exactKeys(censuses, [
      "controllerHostIdSha256", "controllerInstanceId", "censuses",
      "journalRootSha256", "operationId", "planSha256", "sourceCommit", "stage",
      "treeDigest"
    ]) && Array.isArray(censuses.censuses) && censuses.censuses.length === 2, code);
    commonReceiptBinding(censuses, context, code);
    requireCondition(censuses.censuses.every((census) => exactKeys(census, [
      "asOf", "costStatus", "kmsPendingDeletionCount", "providerRequestId",
      "residualResourceCount"
    ]) && census.costStatus === "AVAILABLE" &&
      census.residualResourceCount === 0 && census.kmsPendingDeletionCount === 1 &&
      UUID.test(census.providerRequestId ?? "")) &&
      parseIso(censuses.censuses[1].asOf, code) -
        parseIso(censuses.censuses[0].asOf, code) >= 15 * 60 * 1000, code);
  }
  return claims;
}

function receiptMap(bundle, anchors, context) {
  const code = "CONTROLLER_RECEIPT_SET_REJECTED";
  requireCondition(Array.isArray(bundle.receipts), code);
  const expected = {
    OPERATOR_APPROVAL: ["OPERATOR", 30 * 60 * 1000, 30 * 60 * 1000],
    STORE_RESERVATION: ["CONTROLLER_STORE", 5 * 60 * 1000, 10 * 60 * 1000],
    STORE_JOURNAL: ["CONTROLLER_STORE", 5 * 60 * 1000, 10 * 60 * 1000],
    PROVIDER_IDENTITY: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000],
    COST_CENSUS: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000],
    AUTHORITY_SEPARATION: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000],
    IAM_SIMULATION: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000],
    RESOURCE_CONTRACT: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000]
  };
  if (context.stage === "EXECUTE") {
    expected.STACK_ABSENCE = ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000];
  }
  if (["EXECUTE", "RECONCILE"].includes(context.stage)) {
    Object.assign(expected, {
      ARTIFACT_READBACK: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000],
      CHANGE_SET: ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000]
    });
  }
  if (["RECONCILE", "LIVE", "EVIDENCE", "TEARDOWN", "RESIDUAL"]
    .includes(context.stage)) {
    expected.EXECUTION_RESULT = ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000];
    expected.EXECUTION_TRANSITION = [
      "CONTROLLER_STORE",
      5 * 60 * 1000,
      10 * 60 * 1000
    ];
  }
  if (["TEARDOWN", "RESIDUAL"].includes(context.stage)) {
    expected.KEEP_ALIVE_STATE = ["PROVIDER", 5 * 60 * 1000, 10 * 60 * 1000];
  }
  if (context.stage === "RESIDUAL") {
    expected.RESIDUAL_CENSUS = ["PROVIDER", 30 * 60 * 1000, 30 * 60 * 1000];
  }
  requireCondition(bundle.receipts.length === Object.keys(expected).length, code);
  const result = {};
  for (const receipt of bundle.receipts) {
    const contract = expected[receipt?.kind];
    requireCondition(contract && !result[receipt.kind], code);
    const claims = verifyReceipt(receipt, anchors, {
      issuer: contract[0],
      kind: receipt.kind,
      maximumAgeMs: contract[1],
      maximumLifetimeMs: contract[2]
    }, context.now);
    result[receipt.kind] = Object.freeze({ claims, envelope: receipt });
  }
  requireCondition(Object.keys(expected).every((kind) => result[kind]), code);
  return Object.freeze(result);
}

function holdDecision(
  context,
  reason,
  evidence = {},
  requiredNextAction =
    "READ_ONLY_RECONCILIATION_OR_SEPARATELY_APPROVED_TEARDOWN"
) {
  const decision = {
    schemaVersion: DECISION_SCHEMA,
    status: "HOLD",
    stage: context.stage,
    operationId: context.operationId,
    controllerInstanceId: context.controllerInstanceId,
    planSha256: context.plan.planSha256,
    reason,
    retryAllowed: false,
    requiredNextAction,
    evidence
  };
  return Object.freeze({
    ...decision,
    decisionSha256: sha256(canonicalBytes(decision))
  });
}

export function evaluateProviderControllerBundle({
  bundle,
  gate2Template,
  gate2Bytes,
  rolesTemplate,
  rolesBytes,
  trustedPublicKeys,
  runtime,
  now = Date.now()
}) {
  const code = "CONTROLLER_BUNDLE_REJECTED";
  requireCondition(Number.isFinite(now) && exactKeys(bundle, [
    "controllerHostIdSha256", "controllerInstanceId", "journalRootSha256",
    "operationId", "plan", "receipts", "requestedAt", "schemaVersion", "stage"
  ]) && bundle.schemaVersion === BUNDLE_SCHEMA &&
    Object.hasOwn(STAGE_CONTRACT, bundle.stage) && UUID.test(bundle.operationId ?? "") &&
    typeof bundle.controllerInstanceId === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9:._/-]{15,255}$/u.test(bundle.controllerInstanceId) &&
    HEX_64.test(bundle.controllerHostIdSha256 ?? "") &&
    HEX_64.test(bundle.journalRootSha256 ?? "") &&
    parseIso(bundle.requestedAt, code) <= now &&
    now - parseIso(bundle.requestedAt, code) <= 5 * 60 * 1000, code);
  requireCondition(exactKeys(runtime, [
    "controllerHostIdSha256", "controllerInstanceId", "journalRootSha256"
  ]) && bundle.controllerInstanceId === runtime.controllerInstanceId &&
    bundle.controllerHostIdSha256 === runtime.controllerHostIdSha256 &&
    bundle.journalRootSha256 === runtime.journalRootSha256, code);
  const anchors = validateTrustAnchors(trustedPublicKeys);
  const contract = buildExactResourceContract(gate2Template, rolesTemplate, {
    gate2Bytes, rolesBytes
  });
  const plan = validatePlan(bundle.plan, contract);
  const context = {
    approvalExpiresAt: null,
    approvalIssuedAt: null,
    contract,
    controllerHostIdSha256: bundle.controllerHostIdSha256,
    controllerInstanceId: bundle.controllerInstanceId,
    gate2Template,
    journalRootSha256: bundle.journalRootSha256,
    now,
    operationId: bundle.operationId,
    plan,
    stage: bundle.stage
  };
  const receipts = receiptMap(bundle, anchors, context);
  context.approvalIssuedAt = receipts.OPERATOR_APPROVAL.envelope.issuedAt;
  context.approvalExpiresAt = receipts.OPERATOR_APPROVAL.envelope.expiresAt;
  const approval = validateApproval(receipts.OPERATOR_APPROVAL.claims, context,
    anchors, receipts.OPERATOR_APPROVAL.envelope);
  const reservation = validateStoreReservation(receipts.STORE_RESERVATION.claims,
    context, approval);
  validateStoreJournal(receipts.STORE_JOURNAL.claims, context, reservation);
  validateProviderIdentity(receipts.PROVIDER_IDENTITY.claims, context, approval);
  validateCostCensus(receipts.COST_CENSUS.claims, context, approval);
  validateAuthoritySeparation(receipts.AUTHORITY_SEPARATION.claims, context, approval);
  validateIamSimulation(receipts.IAM_SIMULATION.claims, context, approval);
  validateResourceContractReceipt(receipts.RESOURCE_CONTRACT.claims, context);
  if (context.stage === "EXECUTE") {
    validateStackAbsence(receipts.STACK_ABSENCE.claims, context, approval);
  }
  if (["EXECUTE", "RECONCILE"].includes(context.stage)) {
    const artifacts = validateArtifactReadback(receipts.ARTIFACT_READBACK.claims,
      context);
    validateChangeSet(receipts.CHANGE_SET.claims, context, approval, artifacts);
  }
  if (receipts.EXECUTION_TRANSITION) {
    validateExecutionTransitionJournal(
      receipts.EXECUTION_TRANSITION.claims,
      context,
      approval
    );
  }
  let executionResult;
  if (receipts.EXECUTION_RESULT) {
    executionResult = validateExecutionResult(receipts.EXECUTION_RESULT.claims,
      context);
  }
  validateKeepAliveAndTeardown(receipts, context, approval);
  if (executionResult?.executionOutcome === "AMBIGUOUS") {
    return holdDecision(context, "UNKNOWN_DO_NOT_RETRY", {
      changeSetArn: executionResult.changeSetArn,
      providerRequestId: executionResult.providerRequestId
    });
  }
  if (executionResult?.executionOutcome === "FAILED_TERMINAL") {
    return holdDecision(context, "TERMINAL_PROVIDER_FAILURE", {
      changeSetArn: executionResult.changeSetArn,
      providerRequestId: executionResult.providerRequestId
    });
  }
  if (["LIVE", "EVIDENCE", "TEARDOWN", "RESIDUAL"].includes(context.stage)) {
    requireCondition(executionResult?.executionOutcome === "CONFIRMED_CREATE_COMPLETE",
      "CONTROLLER_DEPLOYED_RELEASE_NOT_PROVEN");
  }
  if (["EXECUTE", "LIVE", "TEARDOWN"].includes(context.stage)) {
    return holdDecision(
      context,
      "PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED",
      {
        approvalId: approval.approvalId,
        brokerContractImplemented: true,
        changeSetArn: approval.changeSetArn,
        globalStoreLeaseId: reservation.leaseId,
        localJsonIsProviderProof: false,
        providerExecutionEnabled: false
      },
      "PROVIDER_BROKER_REQUIRES_EXACT_RUNTIME_AUTHORITY_AND_DURABLE_RECEIPTS"
    );
  }
  const decision = {
    schemaVersion: DECISION_SCHEMA,
    status: "GO_CONFIRMED",
    stage: context.stage,
    operationId: context.operationId,
    controllerInstanceId: context.controllerInstanceId,
    planSha256: context.plan.planSha256,
    approvalId: approval.approvalId,
    leaseId: reservation.leaseId,
    changeSetArn: approval.changeSetArn,
    nextAction: STAGE_CONTRACT[context.stage].nextAction,
    retryAllowed: false,
    ambiguousDisposition: "HOLD_UNKNOWN_DO_NOT_RETRY",
    evidenceLevel: "AUTHENTICATED_OPERATOR_PROVIDER_AND_GLOBAL_STORE_RECEIPTS",
    localJsonIsProviderProof: false
  };
  return Object.freeze({
    ...decision,
    decisionSha256: sha256(canonicalBytes(decision))
  });
}

function assertSecureDirectory(directory, code) {
  const real = fs.realpathSync(directory);
  const stat = fs.lstatSync(real);
  requireCondition(real === path.resolve(directory) && stat.isDirectory() &&
    !stat.isSymbolicLink() && stat.uid === process.getuid() &&
    (stat.mode & 0o077) === 0, code);
  return real;
}

function syncDirectory(directory, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      directory,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW |
        (fs.constants.O_DIRECTORY ?? 0)
    );
    requireCondition(fs.fstatSync(descriptor).isDirectory(), code);
    fs.fsyncSync(descriptor);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    fail(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readExactPublishedDecision(filePath, bytes, code) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW
    );
    const before = fs.fstatSync(descriptor);
    const observed = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.nlink === 1 && before.uid === process.getuid() &&
      (before.mode & 0o077) === 0 && observed.equals(bytes) &&
      before.dev === after.dev && before.ino === after.ino &&
      before.size === after.size && named.isFile() && !named.isSymbolicLink() &&
      named.nlink === 1 && named.uid === before.uid && named.dev === before.dev &&
      named.ino === before.ino && named.size === before.size, code);
    return before;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    fail(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export function publishDurableDecision({
  decision,
  fault = () => {},
  journalRoot
}) {
  const code = "CONTROLLER_LOCAL_JOURNAL_REJECTED";
  requireCondition(path.isAbsolute(journalRoot) && typeof fault === "function" &&
    exactKeys(decision, [
      ...(decision.status === "HOLD"
        ? ["controllerInstanceId", "decisionSha256", "evidence", "operationId",
          "planSha256", "reason", "requiredNextAction", "retryAllowed",
          "schemaVersion", "stage", "status"]
        : ["ambiguousDisposition", "approvalId", "changeSetArn",
          "controllerInstanceId", "decisionSha256", "evidenceLevel", "leaseId",
          "localJsonIsProviderProof", "nextAction", "operationId", "planSha256",
          "retryAllowed", "schemaVersion", "stage", "status"])
    ]), code);
  const root = assertSecureDirectory(journalRoot, code);
  const expectedRootSha256 = sha256(Buffer.from(root, "utf8"));
  const fileName = `${decision.operationId}-${decision.stage.toLowerCase()}.json`;
  const finalPath = path.join(root, fileName);
  const tempPath = path.join(root,
    `.${fileName}.${process.pid}.${crypto.randomBytes(12).toString("hex")}.tmp`);
  const bytes = canonicalBytes({
    ...decision,
    localJournal: {
      providerProof: false,
      rootSha256: expectedRootSha256
    }
  });
  requireCondition(bytes.length <= 1024 * 1024, code);
  let descriptor;
  let linked = false;
  try {
    if (fs.existsSync(finalPath)) {
      readExactPublishedDecision(finalPath, bytes, code);
      syncDirectory(root, code);
      return Object.freeze({
        created: false,
        filePath: finalPath,
        rootSha256: expectedRootSha256
      });
    }
    descriptor = fs.openSync(tempPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR |
      fs.constants.O_NOFOLLOW, 0o600);
    fault("after-open");
    let offset = 0;
    while (offset < bytes.length) {
      const written = fs.writeSync(descriptor, bytes, offset, bytes.length - offset,
        offset);
      requireCondition(written > 0, code);
      offset += written;
    }
    fault("after-write");
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
    fault("after-file-fsync");
    const opened = fs.fstatSync(descriptor);
    requireCondition(opened.isFile() && opened.nlink === 1 &&
      opened.uid === process.getuid() && (opened.mode & 0o077) === 0 &&
      opened.size === bytes.length, code);
    const observed = Buffer.alloc(bytes.length);
    let readOffset = 0;
    while (readOffset < observed.length) {
      const count = fs.readSync(
        descriptor,
        observed,
        readOffset,
        observed.length - readOffset,
        readOffset
      );
      requireCondition(count > 0, code);
      readOffset += count;
    }
    requireCondition(observed.equals(bytes), code);
    fault("after-readback");
    try {
      fs.linkSync(tempPath, finalPath);
      linked = true;
    } catch (cause) {
      if (cause?.code !== "EEXIST") throw cause;
      readExactPublishedDecision(finalPath, bytes, code);
    }
    fault("after-link");
    if (linked) {
      const temporary = fs.lstatSync(tempPath);
      const published = fs.lstatSync(finalPath);
      requireCondition(temporary.dev === opened.dev &&
        temporary.ino === opened.ino && temporary.nlink === 2 &&
        published.dev === opened.dev && published.ino === opened.ino &&
        published.nlink === 2, code);
    }
    fs.unlinkSync(tempPath);
    fault("after-temp-unlink");
    syncDirectory(root, code);
    fault("after-directory-fsync");
    readExactPublishedDecision(finalPath, bytes, code);
    return Object.freeze({
      created: linked,
      filePath: finalPath,
      rootSha256: expectedRootSha256
    });
  } catch (cause) {
    if (Number.isSafeInteger(descriptor)) {
      try { fs.closeSync(descriptor); } catch { /* best-effort close */ }
      descriptor = undefined;
    }
    try {
      if (fs.existsSync(tempPath)) {
        const temporary = fs.lstatSync(tempPath);
        const final = fs.existsSync(finalPath) ? fs.lstatSync(finalPath) : null;
        if (temporary.isFile() && !temporary.isSymbolicLink() &&
          temporary.uid === process.getuid() &&
          (temporary.nlink === 1 || temporary.nlink === 2 && final &&
            final.dev === temporary.dev && final.ino === temporary.ino)) {
          fs.unlinkSync(tempPath);
        }
      }
    } catch {
      /* Leave only this invocation's exact temporary for explicit recovery. */
    }
    if (cause?.message?.startsWith("CONTROLLER_")) throw cause;
    fail(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) {
      try { fs.closeSync(descriptor); } catch { /* best-effort close */ }
    }
  }
}

function readFd(fd, maximumBytes, code) {
  requireCondition(Number.isSafeInteger(fd) && fd >= 3 && fd <= 1023, code);
  try {
    const stat = fs.fstatSync(fd);
    requireCondition((stat.isFile() || stat.isFIFO()) && stat.size <= maximumBytes,
      code);
    const value = fs.readFileSync(fd);
    requireCondition(value.length > 0 && value.length <= maximumBytes, code);
    return value;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    fail(code, cause);
  }
}

function parseArguments(args) {
  const names = new Set([
    "--application-root", "--bundle", "--control-plane-root",
    "--controller-instance", "--controller-key-fd",
    "--expected-application-commit", "--expected-application-tree",
    "--expected-control-plane-commit", "--expected-control-plane-tree",
    "--host-id-fd", "--journal-root", "--operator-key-fd",
    "--provider-key-fd", "--store-key-fd"
  ]);
  requireCondition(args.length === names.size * 2,
    "CONTROLLER_ARGUMENTS_REJECTED");
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    requireCondition(names.has(name) && !Object.hasOwn(result, name) &&
      typeof value === "string" && value.length > 0,
    "CONTROLLER_ARGUMENTS_REJECTED");
    result[name] = value;
  }
  return result;
}

function rejectTestCapabilityEnvironment(env, argv) {
  const forbiddenEnvironment = [
    "NODE_TEST_CONTEXT", "PROOFTOACT_CONTROLLER_TEST_MODE",
    "PROOFTOACT_PROVIDER_TEST_CAPABILITY"
  ];
  const forbiddenProviderEnvironment = Object.keys(env).filter((name) =>
    /^(?:ALL|HTTP|HTTPS|NO)_PROXY$/u.test(name) ||
    /^AWS_(?:ACCESS_KEY_ID|CONFIG_FILE|CONTAINER_CREDENTIALS_FULL_URI|CONTAINER_CREDENTIALS_RELATIVE_URI|EC2_METADATA_SERVICE_ENDPOINT|ENDPOINT_URL(?:_.+)?|PROFILE|SECRET_ACCESS_KEY|SESSION_TOKEN|SHARED_CREDENTIALS_FILE|WEB_IDENTITY_TOKEN_FILE)$/u.test(name) ||
    /^(?:npm_config_)?(?:https?_proxy|no_proxy)$/u.test(name)
  );
  requireCondition(forbiddenEnvironment.every((name) => !Object.hasOwn(env, name)) &&
    forbiddenProviderEnvironment.length === 0 &&
    !String(env.NODE_OPTIONS ?? "").includes("--test") &&
    !String(env.NODE_OPTIONS ?? "").includes("--loader") &&
    !String(env.NODE_OPTIONS ?? "").includes("--import") &&
    !String(env.NODE_PATH ?? "") &&
    argv.every((argument) => !String(argument).includes("test-capability")),
  "CONTROLLER_TEST_CAPABILITY_REJECTED");
}

function executableSha256(filePath, expected, code) {
  requireCondition(path.isAbsolute(filePath) && fs.realpathSync(filePath) === filePath,
    code);
  const stat = fs.lstatSync(filePath);
  requireCondition(stat.isFile() && !stat.isSymbolicLink() &&
    stat.nlink >= 1 && (stat.mode & 0o022) === 0 &&
    (stat.nlink === 1 || stat.uid === 0), code);
  const digest = sha256(fs.readFileSync(filePath));
  requireCondition(digest === expected, code);
  return digest;
}

export function verifyExactRuntimeAndSource({
  applicationRoot,
  approvalClaims,
  bundle,
  controllerFile = CURRENT_FILE,
  controllerKey,
  controlPlaneRoot,
  expectedApplicationCommit,
  expectedApplicationTree,
  expectedControlPlaneCommit,
  expectedControlPlaneTree,
  gitPath
}) {
  const code = "CONTROLLER_RUNTIME_SOURCE_REJECTED";
  requireCondition(exactKeys(approvalClaims.runtime, [
    "controlPlaneCommit", "controlPlaneIdentitySha256",
    "controlPlaneTreeDigest", "controllerSha256", "gitPath", "gitSha256",
    "nodePath", "nodeSha256"
  ]) && approvalClaims.runtime.nodePath === process.execPath &&
    approvalClaims.runtime.gitPath === gitPath && gitPath === "/usr/bin/git",
  code);
  executableSha256(process.execPath, approvalClaims.runtime.nodeSha256, code);
  executableSha256(gitPath, approvalClaims.runtime.gitSha256, code);
  const composition = validateReleaseSourceComposition({
    applicationRoot,
    code,
    controlPlaneRoot,
    entrypointFile: controllerFile,
    entrypointRelativePath: "scripts/release-provider-controller.js",
    expectedApplicationCommit,
    expectedApplicationTree,
    expectedControlPlaneCommit,
    expectedControlPlaneTree
  });
  requireCondition(
    canonicalJson(composition.application) ===
      canonicalJson(bundle.plan.application) &&
    canonicalJson(composition.controlPlane) ===
      canonicalJson(bundle.plan.controlPlane) &&
    expectedApplicationCommit === bundle.plan.sourceCommit &&
    expectedApplicationTree === bundle.plan.treeDigest &&
    expectedControlPlaneCommit === bundle.plan.controlPlane.sourceCommit &&
    expectedControlPlaneTree === bundle.plan.controlPlane.treeDigest &&
    approvalClaims.runtime.controlPlaneCommit ===
      composition.controlPlane.sourceCommit &&
    approvalClaims.runtime.controlPlaneTreeDigest ===
      composition.controlPlane.treeDigest &&
    approvalClaims.runtime.controlPlaneIdentitySha256 ===
      composition.controlPlane.identitySha256 &&
    approvalClaims.runtime.controllerSha256 ===
      composition.controlPlane.controllerSha256 &&
    executableSha256(
      controllerFile,
      composition.controlPlane.controllerSha256,
      code
    ) === approvalClaims.runtime.controllerSha256 &&
    fingerprintPublicKey(controllerKey) === approvalClaims.controllerKeySha256,
    code
  );
  return composition;
}

export async function main(args = process.argv.slice(2), env = process.env) {
  rejectTestCapabilityEnvironment(env, args);
  const parsed = parseArguments(args);
  const bundleFile = readExactJson(path.resolve(parsed["--bundle"]),
    32 * 1024 * 1024, "CONTROLLER_BUNDLE_FILE_REJECTED");
  const gate2 = readExactJson(path.join(
    parsed["--application-root"],
    "infra/aws/gate2-template.json"
  ),
    8 * 1024 * 1024, "CONTROLLER_TEMPLATE_FILE_REJECTED");
  const roles = readExactJson(
    path.join(
      parsed["--control-plane-root"],
      "infra/aws/release-deployment-roles-template.json"
    ),
    8 * 1024 * 1024, "CONTROLLER_ROLES_FILE_REJECTED");
  const journalRoot = assertSecureDirectory(
    path.resolve(parsed["--journal-root"]), "CONTROLLER_LOCAL_JOURNAL_REJECTED");
  const runtime = {
    controllerInstanceId: parsed["--controller-instance"],
    controllerHostIdSha256: sha256(readFd(Number(parsed["--host-id-fd"]),
      4096, "CONTROLLER_HOST_ID_REJECTED")),
    journalRootSha256: sha256(Buffer.from(journalRoot, "utf8"))
  };
  const trustedPublicKeys = {
    OPERATOR: readFd(Number(parsed["--operator-key-fd"]), 16 * 1024,
      "CONTROLLER_TRUST_ANCHOR_REJECTED"),
    PROVIDER: readFd(Number(parsed["--provider-key-fd"]), 16 * 1024,
      "CONTROLLER_TRUST_ANCHOR_REJECTED"),
    CONTROLLER_STORE: readFd(Number(parsed["--store-key-fd"]), 16 * 1024,
      "CONTROLLER_TRUST_ANCHOR_REJECTED")
  };
  const controllerKey = readFd(Number(parsed["--controller-key-fd"]), 16 * 1024,
    "CONTROLLER_TRUST_ANCHOR_REJECTED");
  const anchors = validateTrustAnchors(trustedPublicKeys);
  const provisionalContext = {
    contract: buildExactResourceContract(gate2.value, roles.value, {
      gate2Bytes: gate2.bytes, rolesBytes: roles.bytes
    }),
    controllerHostIdSha256: runtime.controllerHostIdSha256,
    controllerInstanceId: runtime.controllerInstanceId,
    gate2Template: gate2.value,
    journalRootSha256: runtime.journalRootSha256,
    now: Date.now(),
    operationId: bundleFile.value.operationId,
    plan: validatePlan(bundleFile.value.plan,
      buildExactResourceContract(gate2.value, roles.value, {
        gate2Bytes: gate2.bytes, rolesBytes: roles.bytes
      })),
    stage: bundleFile.value.stage
  };
  const receipts = receiptMap(bundleFile.value, anchors, provisionalContext);
  const approvalClaims = receipts.OPERATOR_APPROVAL.claims;
  /* Runtime/source material is an additional operator-signed CLI-only binding. */
  requireCondition(plainObject(approvalClaims.runtime) &&
    HEX_64.test(approvalClaims.controllerKeySha256 ?? ""),
  "CONTROLLER_RUNTIME_SOURCE_REJECTED");
  const gitPath = approvalClaims.runtime.gitPath;
  verifyExactRuntimeAndSource({
    applicationRoot: parsed["--application-root"],
    approvalClaims,
    bundle: bundleFile.value,
    controllerFile: CURRENT_FILE,
    controllerKey,
    controlPlaneRoot: parsed["--control-plane-root"],
    expectedApplicationCommit: parsed["--expected-application-commit"],
    expectedApplicationTree: parsed["--expected-application-tree"],
    expectedControlPlaneCommit: parsed["--expected-control-plane-commit"],
    expectedControlPlaneTree: parsed["--expected-control-plane-tree"],
    gitPath
  });
  const decision = evaluateProviderControllerBundle({
    bundle: bundleFile.value,
    gate2Template: gate2.value,
    gate2Bytes: gate2.bytes,
    rolesTemplate: roles.value,
    rolesBytes: roles.bytes,
    trustedPublicKeys,
    runtime
  });
  const publication = publishDurableDecision({ decision, journalRoot });
  process.stdout.write(`${decision.status}:${decision.decisionSha256}:` +
    `${publication.filePath}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^CONTROLLER_[A-Z0-9_]{1,100}$/u.test(String(error?.message ?? ""))
      ? error.message
      : "CONTROLLER_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}

export const controllerConstants = Object.freeze({
  ARTIFACT_NAMES,
  BUNDLE_SCHEMA,
  DECISION_SCHEMA,
  IAM_ALLOW_CHECKS,
  IAM_DENY_CHECKS,
  LANE_ROLE_NAMES,
  RECEIPT_SCHEMA,
  REVIEWED_GATE2_TEMPLATE_SHA256,
  REVIEWED_ROLES_TEMPLATE_SHA256,
  STAGE_CONTRACT
});
