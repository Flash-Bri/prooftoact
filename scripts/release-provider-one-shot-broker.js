import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";

/*
 * This module is the provider-global one-shot control contract. It contains no
 * provider client and performs no network I/O. Provider implementations must
 * use the phase-separated reserve, dispatch, finalizer, and terminalizer APIs.
 * The legacy monolithic runner remains only for local compatibility testing;
 * combining store-write and provider-mutation capability is unsafe for a live
 * provider. The executable entrypoint is diagnostic-only and can never enable provider execution.
 */

const APPROVAL_SCHEMA = "prooftoact.provider-broker-approval.v1";
const APPROVAL_CLAIMS_SCHEMA =
  "prooftoact.provider-broker-approval-claims.v1";
const RUNTIME_SCHEMA = "prooftoact.provider-broker-runtime.v1";
const AUTHORITY_SCHEMA = "prooftoact.provider-broker-runtime-authority.v1";
const PHASE_RUNTIME_SCHEMA = "prooftoact.provider-broker-phase-runtime.v1";
const PHASE_AUTHORITY_SCHEMA =
  "prooftoact.provider-broker-phase-runtime-authority.v1";
const PHASE_LOOKUP_SCHEMA = "prooftoact.provider-broker-phase-lookup.v1";
const PHASE_RECEIPT_SCHEMA = "prooftoact.provider-broker-phase-receipt.v1";
const FINALIZER_READBACK_SCHEMA =
  "prooftoact.provider-broker-finalizer-readback.v1";
const DISPATCH_PLAN_SCHEMA = "prooftoact.provider-broker-dispatch-plan.v1";
const COMMAND_SCHEMA = "prooftoact.provider-broker-command.v2";
const CONSUMPTION_SCHEMA =
  "prooftoact.provider-global-approval-consumption.v1";
const INTENT_SCHEMA = "prooftoact.provider-global-dispatch-intent.v1";
const OUTCOME_SCHEMA = "prooftoact.provider-dispatch-outcome.v1";
const RECORD_SCHEMA = "prooftoact.provider-global-record.v1";
const TERMINAL_SCHEMA = "prooftoact.provider-global-terminal-record.v1";
const TERMINALIZATION_SCHEMA =
  "prooftoact.provider-global-terminalization.v1";
const RECONCILIATION_SCHEMA =
  "prooftoact.provider-read-only-reconciliation.v1";
const RECEIPT_SCHEMA = "prooftoact.provider-one-shot-broker-receipt.v1";
const APP_SOURCE = Object.freeze({
  repository: "Flash-Bri/prooftoact",
  commit: "963937a9873f0199b91897fe88da1b91bc84b5e3",
  tree: "a330e0d57328e63a568be73c523b2cae6338f26c"
});
const REGION = "us-east-1";
const REPOSITORY_ID = "1317716765";
const REPOSITORY_OWNER_ID = "252500266";
const CUMULATIVE_SPEND_CAP_USD = 20;
const TEARDOWN_BUDGET_RESERVE_USD = 1;
const HUMAN_AUTHORIZATION_SHA256 =
  "64c234d1e4b7336d528fe76041951a2e53a60b76e085bd7cfeb358c22f76ef97";
const OPERATOR_ISSUER = "NUNAN_PROOFTOACT_RELEASE_OPERATOR";
const MAXIMUM_RUNS = 1;
const MAXIMUM_CONCURRENCY = 2;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;

const LANE_CONTRACTS = Object.freeze({
  PREPARE: Object.freeze({
    action: "PREPARE_EXACT_CREATE_CHANGE_SET",
    authority: "prepare",
    environment: "aws-release-deployment",
    mutating: true,
    roleName: "ProofToActReleaseDeployment",
    workflow: "ProofToAct Release Candidate",
    workflowFile: "prooftoact-release-candidate.yml"
  }),
  EXECUTE: Object.freeze({
    action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
    authority: "deploy",
    environment: "aws-release-execution",
    mutating: true,
    roleName: "ProofToActReleaseExecution",
    workflow: "ProofToAct Execute Approved Release",
    workflowFile: "prooftoact-execute-approved-release.yml"
  }),
  DRILL: Object.freeze({
    action: "RUN_ONE_BOUNDED_LIVE_DRILL",
    authority: "drill",
    environment: "aws-live-drill",
    mutating: true,
    roleName: "ProofToActLiveDrillOperator",
    workflow: "ProofToAct Bounded Live Drill",
    workflowFile: "prooftoact-bounded-live-drill.yml"
  }),
  EVIDENCE: Object.freeze({
    action: "COLLECT_FRESH_READ_ONLY_RELEASE_EVIDENCE",
    authority: "evidence",
    environment: "aws-release-evidence",
    mutating: false,
    roleName: "ProofToActReleaseEvidence",
    workflow: "ProofToAct Read Only Release Evidence",
    workflowFile: "prooftoact-read-only-release-evidence.yml"
  }),
  TEARDOWN: Object.freeze({
    action: "TEARDOWN_EXACT_RELEASE_STACK",
    authority: "teardown",
    environment: "aws-release-teardown",
    mutating: true,
    roleName: "ProofToActReleaseTeardown",
    workflow: "ProofToAct Approved Teardown",
    workflowFile: "prooftoact-approved-teardown.yml"
  })
});

const TERMINALIZER_CONTRACT = Object.freeze({
  environment: "aws-release-terminalization",
  readOnly: false,
  roleName: "ProofToActReleaseTerminalizer",
  workflow: "ProofToAct Terminalize Expired Release",
  workflowFile: "prooftoact-terminalize-expired-release.yml"
});

const COORDINATOR_CONTRACT = Object.freeze({
  environment: "aws-release-coordination",
  readOnly: false,
  roleName: "ProofToActReleaseCoordinator",
  workflow: "LANE_DERIVED_FROM_SIGNED_LANE_CONTRACT"
});

const PHASE_CONTRACTS = Object.freeze({
  COORDINATOR_RESERVE: Object.freeze({
    contract: COORDINATOR_CONTRACT,
    jobName: "coordinator-reserve",
    storeMode: "RESERVE_AND_APPEND_INTENT"
  }),
  PROVIDER_DISPATCH: Object.freeze({
    jobName: "provider-dispatch",
    storeMode: "STRONG_READ_ONLY"
  }),
  COORDINATOR_FINALIZE: Object.freeze({
    contract: COORDINATOR_CONTRACT,
    jobName: "coordinator-finalize",
    storeMode: "STRONG_READ_AND_FINALIZE"
  })
});

const AUTHORITY_CONTRACTS = Object.freeze({
  coordinator: Object.freeze({
    environment: COORDINATOR_CONTRACT.environment,
    readOnly: COORDINATOR_CONTRACT.readOnly,
    roleName: COORDINATOR_CONTRACT.roleName,
    workflow: COORDINATOR_CONTRACT.workflow
  }),
  prepare: Object.freeze({
    environment: "aws-release-deployment",
    readOnly: false,
    roleName: "ProofToActReleaseDeployment",
    workflow: "ProofToAct Release Candidate"
  }),
  deploy: Object.freeze({
    environment: "aws-release-execution",
    readOnly: false,
    roleName: "ProofToActReleaseExecution",
    workflow: "ProofToAct Execute Approved Release"
  }),
  drill: Object.freeze({
    environment: "aws-live-drill",
    readOnly: false,
    roleName: "ProofToActLiveDrillOperator",
    workflow: "ProofToAct Bounded Live Drill"
  }),
  evidence: Object.freeze({
    environment: "aws-release-evidence",
    readOnly: true,
    roleName: "ProofToActReleaseEvidence",
    workflow: "ProofToAct Read Only Release Evidence"
  }),
  teardown: Object.freeze({
    environment: "aws-release-teardown",
    readOnly: false,
    roleName: "ProofToActReleaseTeardown",
    workflow: "ProofToAct Approved Teardown"
  }),
  terminalizer: Object.freeze({
    environment: TERMINALIZER_CONTRACT.environment,
    readOnly: TERMINALIZER_CONTRACT.readOnly,
    roleName: TERMINALIZER_CONTRACT.roleName,
    workflow: TERMINALIZER_CONTRACT.workflow
  })
});

const FRESH_PRIMARY_RUNTIME_PRINCIPALS = Object.freeze([
  "tp_ingest_user",
  "tp_authorizer_user",
  "tp_gate2_authorizer_user",
  "tp_dispatch_user",
  "tp_recovery_source_user",
  "tp_recovery_audit_user",
  "tp_provider_claim_user",
  "tp_provider_begin_user",
  "tp_provider_redeem_user",
  "tp_provider_activate_user",
  "tp_provider_finalize_user",
  "tp_provider_terminalize_user",
  "tp_provider_reconcile_user",
  "tp_audit_user"
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

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

export function brokerCanonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

export function brokerSha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalDigest(value) {
  return brokerSha256(brokerCanonicalBytes(value));
}

function parseIso(value, code) {
  requireCondition(typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value), code);
  const timestamp = Date.parse(value);
  requireCondition(Number.isFinite(timestamp) &&
    new Date(timestamp).toISOString() === value, code);
  return timestamp;
}

function boundedNumber(value, minimum, maximum, code) {
  requireCondition(Number.isFinite(value) && value >= minimum &&
    value <= maximum && Number((value).toFixed(6)) === value, code);
  return value;
}

function publicKey(value, code) {
  let key;
  try {
    key = crypto.createPublicKey(value);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(key.type === "public" && key.asymmetricKeyType === "ec" &&
    key.asymmetricKeyDetails?.namedCurve === "prime256v1", code);
  const der = key.export({ format: "der", type: "spki" });
  return Object.freeze({ key, fingerprint: brokerSha256(der) });
}

export function brokerPublicKeyFingerprint(value) {
  return publicKey(value, "PROVIDER_BROKER_OPERATOR_KEY_REJECTED").fingerprint;
}

function approvalSignableBytes(envelope) {
  const { signature: _signature, ...unsigned } = envelope;
  return brokerCanonicalBytes(unsigned);
}

function expectedWorkflowRef(contract) {
  return `Flash-Bri/prooftoact/.github/workflows/${contract.workflowFile}` +
    "@refs/heads/main";
}

function authorityContractIsExact(value, expected) {
  return exactKeys(value, ["environment", "readOnly", "roleName", "workflow"]) &&
    canonicalJson(value) === canonicalJson(expected);
}

function validateAuthoritySeparation(value, code) {
  requireCondition(exactKeys(value, Object.keys(AUTHORITY_CONTRACTS)), code);
  for (const [name, expected] of Object.entries(AUTHORITY_CONTRACTS)) {
    requireCondition(authorityContractIsExact(value[name], expected), code);
  }
  const roles = Object.values(value).map(({ roleName }) => roleName);
  const environments = Object.values(value).map(({ environment }) => environment);
  requireCondition(new Set(roles).size === roles.length &&
    new Set(environments).size === environments.length, code);
  return value;
}

function validateAppSource(value, code) {
  requireCondition(exactKeys(value, ["commit", "repository", "tree"]) &&
    value.repository === APP_SOURCE.repository &&
    value.commit === APP_SOURCE.commit && value.tree === APP_SOURCE.tree &&
    HEX_40.test(value.commit) && HEX_40.test(value.tree), code);
  return value;
}

function validateControlPlane(value, code) {
  requireCondition(exactKeys(value, [
    "brokerArtifactSha256", "buildSha256", "commit", "identitySha256",
    "separation", "tree"
  ]) && [value.brokerArtifactSha256, value.buildSha256, value.identitySha256]
    .every((digest) => HEX_64.test(digest ?? "")) &&
    HEX_40.test(value.commit ?? "") && HEX_40.test(value.tree ?? "") &&
    new Set([
      value.brokerArtifactSha256, value.buildSha256, value.identitySha256
    ]).size === 3 && value.separation ===
      "SEPARATE_CONTROL_PLANE_FROM_FROZEN_APPLICATION", code);
  const appIdentity = canonicalDigest(APP_SOURCE);
  requireCondition(![
    value.brokerArtifactSha256, value.buildSha256, value.identitySha256
  ].includes(appIdentity) &&
    !(value.commit === APP_SOURCE.commit && value.tree === APP_SOURCE.tree) &&
    value.identitySha256 === canonicalDigest({
      brokerArtifactSha256: value.brokerArtifactSha256,
      buildSha256: value.buildSha256,
      commit: value.commit,
      separation: value.separation,
      tree: value.tree
    }), code);
  return value;
}

function loadedBrokerArtifactSha256(code) {
  const filePath = fileURLToPath(import.meta.url);
  try {
    const real = fs.realpathSync(filePath);
    const stat = fs.lstatSync(real);
    requireCondition(real === filePath && stat.isFile() &&
      !stat.isSymbolicLink() && stat.nlink === 1, code);
    return brokerSha256(fs.readFileSync(real));
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function validateRelease(value, lane, code) {
  if (lane === "PREPARE") {
    requireCondition(exactKeys(value, [
      "artifactManifestSha256", "buildReceiptSha256", "changeSetName",
      "changeSetType", "parameterManifestSha256", "region",
      "resourceInventorySha256", "stackName", "templateSha256"
    ]) && [
      value.artifactManifestSha256, value.buildReceiptSha256,
      value.parameterManifestSha256, value.resourceInventorySha256,
      value.templateSha256
    ].every((digest) => HEX_64.test(digest ?? "")) &&
      value.changeSetType === "CREATE" && value.region === REGION &&
      value.stackName === "prooftoact-gate2" &&
      /^prooftoact-release-[a-z0-9-]{1,64}$/u.test(value.changeSetName ?? ""),
    code);
    return value;
  }
  requireCondition(exactKeys(value, [
    "artifactManifestSha256", "buildReceiptSha256", "changeSetArn",
    "changeSetSha256", "changeSetType", "parameterManifestSha256",
    "region", "resourceInventorySha256", "stackId", "stackName"
  ]) && [
    value.artifactManifestSha256, value.buildReceiptSha256,
    value.changeSetSha256, value.parameterManifestSha256,
    value.resourceInventorySha256
  ].every((digest) => HEX_64.test(digest ?? "")) &&
    value.changeSetType === "CREATE" && value.region === REGION &&
    value.stackName === "prooftoact-gate2" &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(value.stackId ?? "") &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
      .test(value.changeSetArn ?? ""), code);
  return value;
}

function validateBudget(value, lane, envelopeIssuedAt, code) {
  requireCondition(exactKeys(value, [
    "alreadySpentUsd", "authorizedAdditionalUsd", "censusAsOf",
    "censusReceiptSha256", "cumulativeCapUsd", "currency",
    "projectedCumulativeUsd", "teardownReserveUsd", "unknownCostCount"
  ]) && value.currency === "USD" && value.unknownCostCount === 0 &&
    HEX_64.test(value.censusReceiptSha256 ?? ""), code);
  boundedNumber(value.alreadySpentUsd, 0, CUMULATIVE_SPEND_CAP_USD, code);
  boundedNumber(value.authorizedAdditionalUsd, 0,
    CUMULATIVE_SPEND_CAP_USD, code);
  boundedNumber(value.projectedCumulativeUsd, 0,
    CUMULATIVE_SPEND_CAP_USD, code);
  boundedNumber(value.cumulativeCapUsd, 0,
    CUMULATIVE_SPEND_CAP_USD, code);
  boundedNumber(value.teardownReserveUsd, 0,
    CUMULATIVE_SPEND_CAP_USD, code);
  requireCondition(value.cumulativeCapUsd === CUMULATIVE_SPEND_CAP_USD &&
    value.teardownReserveUsd === TEARDOWN_BUDGET_RESERVE_USD &&
    Number((value.alreadySpentUsd + value.authorizedAdditionalUsd).toFixed(6)) ===
      value.projectedCumulativeUsd && value.projectedCumulativeUsd <=
      value.cumulativeCapUsd &&
    (lane === "TEARDOWN"
      ? value.authorizedAdditionalUsd <= value.teardownReserveUsd
      : value.projectedCumulativeUsd <=
        value.cumulativeCapUsd - value.teardownReserveUsd) &&
    parseIso(value.censusAsOf, code) <=
      envelopeIssuedAt && envelopeIssuedAt - parseIso(value.censusAsOf, code) <=
      5 * 60 * 1000, code);
  return value;
}

function validateDatabase(value, code) {
  requireCondition(exactKeys(value, [
    "adminCredentialPresent", "clusterHostSha256", "clusterId", "database",
    "distinctRuntimeCredentials", "freshCluster", "freshPrimaryReceiptSha256",
    "managedPrincipalSetSha256", "principalsCreatedFromEmpty",
    "rootLoginPermitted", "runtimePrincipals"
  ]) && value.database === "tideproof" && value.freshCluster === true &&
    value.principalsCreatedFromEmpty === true &&
    value.adminCredentialPresent === false && value.rootLoginPermitted === false &&
    value.distinctRuntimeCredentials === true && UUID.test(value.clusterId ?? "") &&
    [value.clusterHostSha256, value.freshPrimaryReceiptSha256,
      value.managedPrincipalSetSha256].every((digest) =>
      HEX_64.test(digest ?? "")) && Array.isArray(value.runtimePrincipals) &&
    canonicalJson([...value.runtimePrincipals].sort()) ===
      canonicalJson([...FRESH_PRIMARY_RUNTIME_PRINCIPALS].sort()) &&
    new Set(value.runtimePrincipals).size === value.runtimePrincipals.length &&
    value.managedPrincipalSetSha256 === canonicalDigest(
      [...FRESH_PRIMARY_RUNTIME_PRINCIPALS].sort()
    ) && value.runtimePrincipals.every((principal) =>
      !/(?:^|[_-])(?:root|admin|administrator)(?:$|[_-])/iu.test(principal)), code);
  return value;
}

function validateTeardown(
  value,
  release,
  providerAccountId,
  approvalExpiresAt,
  lane,
  code
) {
  if (lane === "PREPARE") {
    requireCondition(exactKeys(value, [
      "changeSetName", "deadline", "deletePreparedChangeSetIfCreated",
      "environment", "expectedResourceInventorySha256",
      "residualCensusRequired", "required", "roleArn",
      "separateApprovalRequired", "stackName", "workflow"
    ]) && value.required === true && value.separateApprovalRequired === true &&
      value.deletePreparedChangeSetIfCreated === true &&
      value.changeSetName === release.changeSetName &&
      value.stackName === release.stackName &&
      value.environment === AUTHORITY_CONTRACTS.teardown.environment &&
      value.workflow === AUTHORITY_CONTRACTS.teardown.workflow &&
      value.roleArn === `arn:aws:iam::${providerAccountId}:role/` +
        AUTHORITY_CONTRACTS.teardown.roleName &&
      value.residualCensusRequired === true &&
      value.expectedResourceInventorySha256 ===
        release.resourceInventorySha256 &&
      HEX_64.test(value.expectedResourceInventorySha256 ?? "") &&
      parseIso(value.deadline, code) > approvalExpiresAt, code);
    return value;
  }
  requireCondition(exactKeys(value, [
    "deadline", "deleteExactStack", "deleteExactStackId", "environment",
    "expectedResourceInventorySha256", "residualCensusRequired", "required",
    "originatingChangeSetArn", "originatingChangeSetSha256", "roleArn",
    "separateApprovalRequired", "workflow"
  ]) && value.required === true && value.separateApprovalRequired === true &&
    value.deleteExactStack === "prooftoact-gate2" &&
    value.deleteExactStackId === release.stackId &&
    value.originatingChangeSetArn === release.changeSetArn &&
    value.originatingChangeSetSha256 === release.changeSetSha256 &&
    value.environment === AUTHORITY_CONTRACTS.teardown.environment &&
    value.workflow === AUTHORITY_CONTRACTS.teardown.workflow &&
    value.roleArn === `arn:aws:iam::${providerAccountId}:role/` +
      AUTHORITY_CONTRACTS.teardown.roleName &&
    value.residualCensusRequired === true &&
    HEX_64.test(value.expectedResourceInventorySha256 ?? "") &&
    parseIso(value.deadline, code) > approvalExpiresAt, code);
  return value;
}

function providerAccountFromNamespace(value, code) {
  const match = /^arn:aws:dynamodb:us-east-1:([0-9]{12}):table\/prooftoact-release-controller$/u
    .exec(value ?? "");
  requireCondition(match, code);
  return match[1];
}

function validateGlobalStore(value, code) {
  requireCondition(exactKeys(value, [
    "atomicConditionalConsumeRequired", "attributeDefinitionsSha256",
    "billingMode", "deletionProtectionEnabled", "durableJournalRequired",
    "encryptionStatus", "keySchemaSha256", "kmsKeyArnSha256", "namespaceArn",
    "region", "sseType", "strongReadRequired", "tableId",
    "tableIdentitySha256", "tagsSha256"
  ]) && value.region === REGION && value.strongReadRequired === true &&
    value.atomicConditionalConsumeRequired === true &&
    value.durableJournalRequired === true &&
    value.billingMode === "PAY_PER_REQUEST" &&
    value.deletionProtectionEnabled === true &&
    value.encryptionStatus === "ENABLED" &&
    value.sseType === "KMS" &&
    UUID.test(value.tableId ?? "") && [
      value.attributeDefinitionsSha256,
      value.keySchemaSha256,
      value.kmsKeyArnSha256,
      value.tableIdentitySha256,
      value.tagsSha256
    ].every((digest) => HEX_64.test(digest ?? "")), code);
  const accountId = providerAccountFromNamespace(value.namespaceArn, code);
  requireCondition(value.tableIdentitySha256 === canonicalDigest({
    attributeDefinitionsSha256: value.attributeDefinitionsSha256,
    billingMode: value.billingMode,
    deletionProtectionEnabled: value.deletionProtectionEnabled,
    encryptionStatus: value.encryptionStatus,
    keySchemaSha256: value.keySchemaSha256,
    kmsKeyArnSha256: value.kmsKeyArnSha256,
    namespaceArn: value.namespaceArn,
    region: value.region,
    sseType: value.sseType,
    tableId: value.tableId,
    tagsSha256: value.tagsSha256
  }), code);
  return Object.freeze({ value, accountId });
}

function validateApprovalClaims(claims, issuedAt, expiresAt) {
  const code = "PROVIDER_BROKER_APPROVAL_CLAIMS_REJECTED";
  requireCondition(exactKeys(claims, [
    "action", "approvalId", "appSource", "approvedBy",
    "authoritySeparation", "budget", "controlPlane", "database",
    "globalStore", "humanAuthorizationSha256", "lane", "limits", "oneShot", "release",
    "schemaVersion", "teardown", "workspaceRealpathSha256"
  ]) && claims.schemaVersion === APPROVAL_CLAIMS_SCHEMA &&
    Object.hasOwn(LANE_CONTRACTS, claims.lane) &&
    claims.action === LANE_CONTRACTS[claims.lane].action &&
    UUID.test(claims.approvalId ?? "") && claims.approvedBy === "BRIAN_SMITH" &&
    claims.oneShot === true &&
    claims.humanAuthorizationSha256 === HUMAN_AUTHORIZATION_SHA256 &&
    HEX_64.test(claims.workspaceRealpathSha256 ?? ""),
  code);
  validateAppSource(claims.appSource, code);
  validateControlPlane(claims.controlPlane, code);
  validateRelease(claims.release, claims.lane, code);
  validateBudget(claims.budget, claims.lane, issuedAt, code);
  validateDatabase(claims.database, code);
  validateAuthoritySeparation(claims.authoritySeparation, code);
  requireCondition(exactKeys(claims.limits, [
    "maximumConcurrency", "maximumRuns"
  ]) && claims.limits.maximumRuns === MAXIMUM_RUNS &&
    claims.limits.maximumConcurrency === MAXIMUM_CONCURRENCY, code);
  const globalStore = validateGlobalStore(claims.globalStore, code);
  if (claims.lane !== "PREPARE") {
    const changeSetAccount = claims.release.changeSetArn.split(":")[4];
    const stackAccount = claims.release.stackId.split(":")[4];
    requireCondition(changeSetAccount === globalStore.accountId &&
      stackAccount === globalStore.accountId, code);
  }
  validateTeardown(claims.teardown, claims.release, globalStore.accountId,
    expiresAt, claims.lane, code);
  requireCondition(claims.teardown.expectedResourceInventorySha256 ===
    claims.release.resourceInventorySha256, code);
  return Object.freeze({ claims, providerAccountId: globalStore.accountId });
}

function validateProviderBrokerApprovalEnvelope(
  envelope,
  trustedOperatorPublicKey,
  now,
  requireFresh
) {
  const code = "PROVIDER_BROKER_APPROVAL_REJECTED";
  requireCondition(Number.isFinite(now) && exactKeys(envelope, [
    "expiresAt", "issuedAt", "issuer", "keyFingerprint", "nonce",
    "schemaVersion", "signature", "claims"
  ]) && envelope.schemaVersion === APPROVAL_SCHEMA &&
    envelope.issuer === OPERATOR_ISSUER && UUID.test(envelope.nonce ?? "") &&
    typeof envelope.signature === "string", code);
  const issuedAt = parseIso(envelope.issuedAt, code);
  const expiresAt = parseIso(envelope.expiresAt, code);
  requireCondition(issuedAt <= now &&
    (!requireFresh || now < expiresAt) &&
    expiresAt - issuedAt <= 30 * 60 * 1000, code);
  const operator = publicKey(trustedOperatorPublicKey, code);
  requireCondition(envelope.keyFingerprint === operator.fingerprint, code);
  let signature;
  try {
    signature = Buffer.from(envelope.signature, "base64");
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(signature.length === 64 &&
    signature.toString("base64") === envelope.signature &&
    crypto.verify("sha256", approvalSignableBytes(envelope), {
      dsaEncoding: "ieee-p1363",
      key: operator.key
    }, signature), code);
  const accepted = validateApprovalClaims(envelope.claims, issuedAt, expiresAt);
  requireCondition(envelope.nonce === accepted.claims.approvalId, code);
  return Object.freeze({
    ...accepted,
    approvalSha256: canonicalDigest(envelope),
    expiresAt,
    issuedAt
  });
}

export function validateProviderBrokerApproval(
  envelope,
  trustedOperatorPublicKey,
  now = Date.now()
) {
  return validateProviderBrokerApprovalEnvelope(
    envelope,
    trustedOperatorPublicKey,
    now,
    true
  );
}

function workspaceRealpathSha256(workspaceRoot, code) {
  requireCondition(typeof workspaceRoot === "string" &&
    path.isAbsolute(workspaceRoot), code);
  let real;
  try {
    real = fs.realpathSync(workspaceRoot);
    const stat = fs.lstatSync(real);
    requireCondition(real === path.resolve(workspaceRoot) && stat.isDirectory() &&
      !stat.isSymbolicLink(), code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return brokerSha256(Buffer.from(real, "utf8"));
}

function validateRuntimeBase(runtime, approval, now) {
  const code = "PROVIDER_BROKER_RUNTIME_REJECTED";
  requireCondition(Number.isFinite(now) && exactKeys(runtime, [
    "adminDatabaseCredentialPresent", "appSource", "artifactManifestSha256",
    "authorityReceipts", "brokerArtifactSha256", "buildReceiptSha256",
    "changeSetArn", "changeSetSha256", "controlPlaneBuildSha256",
    "controlPlaneCommit", "controlPlaneIdentitySha256", "controlPlaneTree",
    "credentialSource",
    "environment", "lane", "openClawOauthPresent", "principalArn",
    "providerAccountId", "region", "repositoryId", "repositoryOwnerId",
    "rootOrAdministratorPrincipal",
    "runAttempt", "runId", "schemaVersion", "stackId",
    "staticProviderCredentialsPresent",
    "workflow", "workflowRef", "workflowSha", "workspaceRoot"
  ]) && runtime.schemaVersion === RUNTIME_SCHEMA && runtime.lane ===
    approval.claims.lane && ACCOUNT_ID.test(runtime.providerAccountId ?? "") &&
    runtime.providerAccountId === approval.providerAccountId &&
    runtime.region === REGION && runtime.credentialSource ===
      "GITHUB_OIDC_SHORT_LIVED" && runtime.openClawOauthPresent === false &&
    runtime.staticProviderCredentialsPresent === false &&
    runtime.rootOrAdministratorPrincipal === false &&
    runtime.adminDatabaseCredentialPresent === false &&
    runtime.repositoryId === REPOSITORY_ID &&
    runtime.repositoryOwnerId === REPOSITORY_OWNER_ID &&
    /^[1-9][0-9]{0,19}$/u.test(runtime.runId ?? "") &&
    runtime.runAttempt === 1, code);
  const contract = LANE_CONTRACTS[runtime.lane];
  requireCondition(runtime.workflow === contract.workflow &&
    runtime.workflowRef === expectedWorkflowRef(contract) &&
    runtime.environment === contract.environment &&
    new RegExp(`^arn:aws:sts::${runtime.providerAccountId}:assumed-role/` +
      `${contract.roleName}/pta-${runtime.runId}-${runtime.runAttempt}$`, "u")
      .test(runtime.principalArn ?? "") &&
    !/(?:^|\/)(?:root|admin|administrator)(?:$|\/)/iu
      .test(runtime.principalArn ?? ""), code);
  validateAppSource(runtime.appSource, code);
  requireCondition(runtime.controlPlaneIdentitySha256 ===
    approval.claims.controlPlane.identitySha256 &&
    runtime.controlPlaneCommit === approval.claims.controlPlane.commit &&
    runtime.controlPlaneTree === approval.claims.controlPlane.tree &&
    runtime.controlPlaneBuildSha256 === approval.claims.controlPlane.buildSha256 &&
    runtime.brokerArtifactSha256 ===
      approval.claims.controlPlane.brokerArtifactSha256 &&
    runtime.brokerArtifactSha256 === loadedBrokerArtifactSha256(code) &&
    runtime.workflowSha === runtime.controlPlaneCommit &&
    runtime.buildReceiptSha256 === approval.claims.release.buildReceiptSha256 &&
    runtime.artifactManifestSha256 ===
      approval.claims.release.artifactManifestSha256 &&
    runtime.changeSetArn === approval.claims.release.changeSetArn &&
    runtime.changeSetSha256 === approval.claims.release.changeSetSha256 &&
    runtime.stackId === approval.claims.release.stackId &&
    workspaceRealpathSha256(runtime.workspaceRoot, code) ===
      approval.claims.workspaceRealpathSha256, code);
  return Object.freeze({ runtime, contract });
}

function validateTerminalizerRuntimeBase(runtime, approval, now) {
  const code = "PROVIDER_BROKER_TERMINALIZER_RUNTIME_REJECTED";
  const prepare = approval.claims.lane === "PREPARE";
  const expectedKeys = [
    "adminDatabaseCredentialPresent", "appSource", "artifactManifestSha256",
    "authorityReceipts", "brokerArtifactSha256", "buildReceiptSha256",
    "controlPlaneBuildSha256", "controlPlaneCommit",
    "controlPlaneIdentitySha256", "controlPlaneTree",
    "credentialSource", "environment", "lane", "openClawOauthPresent",
    "principalArn", "providerAccountId", "region", "repositoryId",
    "repositoryOwnerId", "rootOrAdministratorPrincipal", "runAttempt",
    "runId", "schemaVersion", "staticProviderCredentialsPresent",
    "workflow", "workflowRef", "workflowSha", "workspaceRoot"
  ];
  expectedKeys.push(...(prepare
    ? ["releaseReadbackSha256"]
    : ["changeSetArn", "changeSetSha256", "stackId"]));
  requireCondition(Number.isFinite(now) && exactKeys(runtime, expectedKeys) &&
    runtime.schemaVersion === RUNTIME_SCHEMA &&
    runtime.lane === "TERMINALIZE" &&
    ACCOUNT_ID.test(runtime.providerAccountId ?? "") &&
    runtime.providerAccountId === approval.providerAccountId &&
    runtime.region === REGION &&
    runtime.credentialSource === "GITHUB_OIDC_SHORT_LIVED" &&
    runtime.openClawOauthPresent === false &&
    runtime.staticProviderCredentialsPresent === false &&
    runtime.rootOrAdministratorPrincipal === false &&
    runtime.adminDatabaseCredentialPresent === false &&
    runtime.repositoryId === REPOSITORY_ID &&
    runtime.repositoryOwnerId === REPOSITORY_OWNER_ID &&
    /^[1-9][0-9]{0,19}$/u.test(runtime.runId ?? "") &&
    runtime.runAttempt === 1 &&
    runtime.workflow === TERMINALIZER_CONTRACT.workflow &&
    runtime.workflowRef === expectedWorkflowRef(TERMINALIZER_CONTRACT) &&
    runtime.environment === TERMINALIZER_CONTRACT.environment &&
    new RegExp(`^arn:aws:sts::${runtime.providerAccountId}:assumed-role/` +
      `${TERMINALIZER_CONTRACT.roleName}/pta-${runtime.runId}-` +
      `${runtime.runAttempt}$`, "u").test(runtime.principalArn ?? "") &&
    !/(?:^|\/)(?:root|admin|administrator)(?:$|\/)/iu
      .test(runtime.principalArn ?? ""), code);
  validateAppSource(runtime.appSource, code);
  requireCondition(runtime.controlPlaneIdentitySha256 ===
    approval.claims.controlPlane.identitySha256 &&
    runtime.controlPlaneCommit === approval.claims.controlPlane.commit &&
    runtime.controlPlaneTree === approval.claims.controlPlane.tree &&
    runtime.controlPlaneBuildSha256 === approval.claims.controlPlane.buildSha256 &&
    runtime.brokerArtifactSha256 ===
      approval.claims.controlPlane.brokerArtifactSha256 &&
    runtime.brokerArtifactSha256 === loadedBrokerArtifactSha256(code) &&
    runtime.workflowSha === runtime.controlPlaneCommit &&
    runtime.buildReceiptSha256 === approval.claims.release.buildReceiptSha256 &&
    runtime.artifactManifestSha256 ===
      approval.claims.release.artifactManifestSha256 &&
    (prepare
      ? runtime.releaseReadbackSha256 === canonicalDigest(approval.claims.release)
      : runtime.changeSetArn === approval.claims.release.changeSetArn &&
        runtime.changeSetSha256 === approval.claims.release.changeSetSha256 &&
        runtime.stackId === approval.claims.release.stackId) &&
    workspaceRealpathSha256(runtime.workspaceRoot, code) ===
      approval.claims.workspaceRealpathSha256, code);
  return Object.freeze({ runtime, contract: TERMINALIZER_CONTRACT });
}

function validateRuntimeAuthority(
  value,
  approval,
  runtime,
  now,
  allowExpired = false
) {
  const code = "PROVIDER_BROKER_RUNTIME_AUTHORITY_REJECTED";
  if (value === null) return null;
  const prepareTerminalizer = approval.claims.lane === "PREPARE" &&
    runtime.lane === "TERMINALIZE";
  const expectedKeys = [
    "artifactReadbackSha256", "buildReadbackSha256",
    "controlPlaneSha256", "costCensusSha256", "expiresAt",
    "freshDatabaseSha256", "globalStoreSha256",
    "iamSeparationSha256", "observedAt", "providerBacked",
    "providerIdentitySha256", "schemaVersion", "sourceCheckoutSha256",
    "status", "strongRead",
    "teardownContractSha256", "workflowIdentitySha256"
  ];
  expectedKeys.push(...(prepareTerminalizer
    ? ["releaseReadbackSha256"]
    : ["changeSetReadbackSha256", "stackReadbackSha256"]));
  requireCondition(exactKeys(value, expectedKeys) &&
    value.schemaVersion === AUTHORITY_SCHEMA && value.status ===
    "EXACT_RUNTIME_AUTHORITY_CONFIRMED" && value.providerBacked === true &&
    value.strongRead === true, code);
  const digestFields = Object.entries(value)
    .filter(([name]) => name.endsWith("Sha256"));
  requireCondition(digestFields.length === (prepareTerminalizer ? 12 : 13) &&
    digestFields.every(([, digest]) => HEX_64.test(digest ?? "")), code);
  const observedAt = parseIso(value.observedAt, code);
  const expiresAt = parseIso(value.expiresAt, code);
  requireCondition(observedAt <= now &&
    (allowExpired || now - observedAt <= 5 * 60 * 1000) &&
    (allowExpired || now < expiresAt) &&
    expiresAt - observedAt <= 15 * 60 * 1000 &&
    value.sourceCheckoutSha256 === canonicalDigest(APP_SOURCE) &&
    value.providerIdentitySha256 === canonicalDigest({
      accountId: runtime.providerAccountId,
      principalArn: runtime.principalArn,
      region: runtime.region
    }) &&
    value.workflowIdentitySha256 === canonicalDigest({
      environment: runtime.environment,
      lane: runtime.lane,
      principalArn: runtime.principalArn,
      providerAccountId: runtime.providerAccountId,
      repositoryId: runtime.repositoryId,
      repositoryOwnerId: runtime.repositoryOwnerId,
      runAttempt: runtime.runAttempt,
      runId: runtime.runId,
      workflow: runtime.workflow,
      workflowRef: runtime.workflowRef,
      workflowSha: runtime.workflowSha
    }) &&
    value.controlPlaneSha256 === approval.claims.controlPlane.identitySha256 &&
    value.buildReadbackSha256 === runtime.buildReceiptSha256 &&
    value.artifactReadbackSha256 === runtime.artifactManifestSha256 &&
    (prepareTerminalizer
      ? value.releaseReadbackSha256 === canonicalDigest(approval.claims.release)
      : value.changeSetReadbackSha256 === runtime.changeSetSha256 &&
        value.stackReadbackSha256 === canonicalDigest({
          changeSetArn: runtime.changeSetArn,
          changeSetSha256: runtime.changeSetSha256,
          stackId: runtime.stackId,
          stackName: approval.claims.release.stackName
        })) &&
    value.costCensusSha256 === approval.claims.budget.censusReceiptSha256 &&
    value.freshDatabaseSha256 ===
      approval.claims.database.freshPrimaryReceiptSha256 &&
    value.globalStoreSha256 === approval.claims.globalStore.tableIdentitySha256 &&
    value.teardownContractSha256 === canonicalDigest(approval.claims.teardown),
  code);
  return Object.freeze({ ...value });
}

function contractForPhase(phase, lane, code) {
  requireCondition(Object.hasOwn(PHASE_CONTRACTS, phase) &&
    Object.hasOwn(LANE_CONTRACTS, lane), code);
  if (phase === "PROVIDER_DISPATCH") {
    return Object.freeze({
      ...LANE_CONTRACTS[lane],
      jobName: PHASE_CONTRACTS.PROVIDER_DISPATCH.jobName,
      storeMode: PHASE_CONTRACTS.PROVIDER_DISPATCH.storeMode
    });
  }
  const laneContract = LANE_CONTRACTS[lane];
  return Object.freeze({
    ...PHASE_CONTRACTS[phase].contract,
    jobName: PHASE_CONTRACTS[phase].jobName,
    storeMode: PHASE_CONTRACTS[phase].storeMode,
    workflow: laneContract.workflow,
    workflowFile: laneContract.workflowFile
  });
}

function phaseRuntimeIdentity(runtime) {
  const identity = {
    environment: runtime.environment,
    jobName: runtime.jobName,
    lane: runtime.lane,
    phase: runtime.phase,
    principalArn: runtime.principalArn,
    providerAccountId: runtime.providerAccountId,
    repositoryId: runtime.repositoryId,
    repositoryOwnerId: runtime.repositoryOwnerId,
    runAttempt: runtime.runAttempt,
    runId: runtime.runId,
    workflow: runtime.workflow,
    workflowRef: runtime.workflowRef,
    workflowSha: runtime.workflowSha
  };
  return Object.freeze({
    ...identity,
    phaseRuntimeIdentitySha256: canonicalDigest(identity)
  });
}

function validatePhaseRuntimeBase(runtime, approval, now, expectedPhase) {
  const code = "PROVIDER_BROKER_PHASE_RUNTIME_REJECTED";
  requireCondition(Number.isFinite(now) && exactKeys(runtime, [
    "adminDatabaseCredentialPresent", "appSource", "artifactManifestSha256",
    "authorityReceipts", "brokerArtifactSha256", "buildReceiptSha256",
    "controlPlaneBuildSha256", "controlPlaneCommit",
    "controlPlaneIdentitySha256", "controlPlaneTree", "credentialSource",
    "environment", "jobName", "lane", "openClawOauthPresent", "phase",
    "principalArn", "providerAccountId", "region", "releaseReadbackSha256",
    "repositoryId", "repositoryOwnerId", "rootOrAdministratorPrincipal",
    "runAttempt", "runId", "schemaVersion",
    "staticProviderCredentialsPresent", "workflow", "workflowRef",
    "workflowSha", "workspaceRoot"
  ]) && runtime.schemaVersion === PHASE_RUNTIME_SCHEMA &&
    runtime.phase === expectedPhase && runtime.lane === approval.claims.lane &&
    ACCOUNT_ID.test(runtime.providerAccountId ?? "") &&
    runtime.providerAccountId === approval.providerAccountId &&
    runtime.region === REGION &&
    runtime.credentialSource === "GITHUB_OIDC_SHORT_LIVED" &&
    runtime.openClawOauthPresent === false &&
    runtime.staticProviderCredentialsPresent === false &&
    runtime.rootOrAdministratorPrincipal === false &&
    runtime.adminDatabaseCredentialPresent === false &&
    runtime.repositoryId === REPOSITORY_ID &&
    runtime.repositoryOwnerId === REPOSITORY_OWNER_ID &&
    /^[1-9][0-9]{0,19}$/u.test(runtime.runId ?? "") &&
    runtime.runAttempt === 1, code);
  const contract = contractForPhase(runtime.phase, runtime.lane, code);
  const expectedSession = `pta-${runtime.runId}-${runtime.runAttempt}-` +
    runtime.jobName;
  requireCondition(runtime.workflow === contract.workflow &&
    runtime.workflowRef === expectedWorkflowRef(contract) &&
    runtime.jobName === contract.jobName &&
    runtime.environment === contract.environment &&
    runtime.principalArn === `arn:aws:sts::${runtime.providerAccountId}:` +
      `assumed-role/${contract.roleName}/${expectedSession}` &&
    !/(?:^|\/)(?:root|admin|administrator)(?:$|\/)/iu
      .test(runtime.principalArn ?? ""), code);
  validateAppSource(runtime.appSource, code);
  requireCondition(runtime.controlPlaneIdentitySha256 ===
    approval.claims.controlPlane.identitySha256 &&
    runtime.controlPlaneCommit === approval.claims.controlPlane.commit &&
    runtime.controlPlaneTree === approval.claims.controlPlane.tree &&
    runtime.controlPlaneBuildSha256 === approval.claims.controlPlane.buildSha256 &&
    runtime.brokerArtifactSha256 ===
      approval.claims.controlPlane.brokerArtifactSha256 &&
    runtime.brokerArtifactSha256 === loadedBrokerArtifactSha256(code) &&
    runtime.workflowSha === runtime.controlPlaneCommit &&
    runtime.buildReceiptSha256 === approval.claims.release.buildReceiptSha256 &&
    runtime.artifactManifestSha256 ===
      approval.claims.release.artifactManifestSha256 &&
    runtime.releaseReadbackSha256 === canonicalDigest(approval.claims.release) &&
    workspaceRealpathSha256(runtime.workspaceRoot, code) ===
      approval.claims.workspaceRealpathSha256, code);
  return Object.freeze({
    contract,
    identity: phaseRuntimeIdentity(runtime),
    runtime
  });
}

function validatePhaseRuntimeAuthority(value, approval, acceptedRuntime, now) {
  const code = "PROVIDER_BROKER_PHASE_RUNTIME_AUTHORITY_REJECTED";
  const { runtime, identity } = acceptedRuntime;
  requireCondition(exactKeys(value, [
    "artifactReadbackSha256", "buildReadbackSha256", "controlPlaneSha256",
    "costCensusSha256", "expiresAt", "freshDatabaseSha256",
    "globalStoreSha256", "iamSeparationSha256", "observedAt",
    "providerBacked", "providerIdentitySha256", "releaseReadbackSha256",
    "schemaVersion", "sourceCheckoutSha256", "status", "strongRead",
    "teardownContractSha256", "workflowIdentitySha256"
  ]) && value.schemaVersion === PHASE_AUTHORITY_SCHEMA &&
    value.status === "EXACT_PHASE_RUNTIME_AUTHORITY_CONFIRMED" &&
    value.providerBacked === true && value.strongRead === true, code);
  const digestFields = Object.entries(value)
    .filter(([name]) => name.endsWith("Sha256"));
  requireCondition(digestFields.length === 12 &&
    digestFields.every(([, digest]) => HEX_64.test(digest ?? "")), code);
  const observedAt = parseIso(value.observedAt, code);
  const expiresAt = parseIso(value.expiresAt, code);
  requireCondition(observedAt <= now && now - observedAt <= 5 * 60 * 1000 &&
    now < expiresAt && expiresAt - observedAt <= 15 * 60 * 1000 &&
    value.sourceCheckoutSha256 === canonicalDigest(APP_SOURCE) &&
    value.providerIdentitySha256 === canonicalDigest({
      accountId: runtime.providerAccountId,
      principalArn: runtime.principalArn,
      region: runtime.region
    }) &&
    value.workflowIdentitySha256 === identity.phaseRuntimeIdentitySha256 &&
    value.controlPlaneSha256 === approval.claims.controlPlane.identitySha256 &&
    value.buildReadbackSha256 === approval.claims.release.buildReceiptSha256 &&
    value.artifactReadbackSha256 ===
      approval.claims.release.artifactManifestSha256 &&
    value.releaseReadbackSha256 === canonicalDigest(approval.claims.release) &&
    value.costCensusSha256 === approval.claims.budget.censusReceiptSha256 &&
    value.freshDatabaseSha256 ===
      approval.claims.database.freshPrimaryReceiptSha256 &&
    value.globalStoreSha256 === approval.claims.globalStore.tableIdentitySha256 &&
    value.teardownContractSha256 === canonicalDigest(approval.claims.teardown),
  code);
  return Object.freeze({ ...value });
}

function commandFor(approval) {
  const lane = approval.claims.lane;
  const databaseIdentitySha256 = canonicalDigest(approval.claims.database);
  const teardownContractSha256 = canonicalDigest(approval.claims.teardown);
  const authorityContractSha256 = canonicalDigest({
    authoritySeparation: approval.claims.authoritySeparation,
    controlPlaneIdentitySha256: approval.claims.controlPlane.identitySha256,
    globalStoreIdentitySha256:
      approval.claims.globalStore.tableIdentitySha256,
    lane,
    laneContract: LANE_CONTRACTS[lane]
  });
  const effect = lane === "PREPARE" ? {
    action: approval.claims.action,
    artifactManifestSha256: approval.claims.release.artifactManifestSha256,
    buildReceiptSha256: approval.claims.release.buildReceiptSha256,
    changeSetName: approval.claims.release.changeSetName,
    lane,
    parameterManifestSha256: approval.claims.release.parameterManifestSha256,
    providerAccountId: approval.providerAccountId,
    region: REGION,
    resourceInventorySha256: approval.claims.release.resourceInventorySha256,
    stackName: approval.claims.release.stackName,
    templateSha256: approval.claims.release.templateSha256
  } : {
    action: approval.claims.action,
    lane,
    providerAccountId: approval.providerAccountId,
    region: REGION,
    stackId: approval.claims.release.stackId,
    stackName: approval.claims.release.stackName,
    ...(lane === "EXECUTE"
      ? {
          changeSetArn: approval.claims.release.changeSetArn,
          changeSetSha256: approval.claims.release.changeSetSha256
        }
      : {}),
    ...(["DRILL", "EVIDENCE"].includes(lane)
      ? {
          appSource: APP_SOURCE,
          artifactManifestSha256:
            approval.claims.release.artifactManifestSha256,
          buildReceiptSha256: approval.claims.release.buildReceiptSha256,
          changeSetArn: approval.claims.release.changeSetArn,
          changeSetSha256: approval.claims.release.changeSetSha256
        }
      : {}),
    ...(lane === "DRILL"
      ? { databaseIdentitySha256 }
      : {})
  };
  const effectIdentitySha256 = canonicalDigest(effect);
  const operation = {
    approvalId: approval.claims.approvalId,
    approvalSha256: approval.approvalSha256,
    authorityContractSha256,
    controlPlaneIdentitySha256:
      approval.claims.controlPlane.identitySha256,
    effectIdentitySha256
  };
  const budgetKeySha256 = canonicalDigest({
    currency: "USD",
    project: "ProofToAct",
    providerAccountId: approval.providerAccountId,
    region: REGION
  });
  const command = {
    schemaVersion: COMMAND_SCHEMA,
    action: approval.claims.action,
    approvalId: approval.claims.approvalId,
    approvalSha256: approval.approvalSha256,
    appSource: APP_SOURCE,
    artifactManifestSha256:
      approval.claims.release.artifactManifestSha256,
    authorityContractSha256,
    budgetReservationUsd: approval.claims.budget.authorizedAdditionalUsd,
    buildReceiptSha256: approval.claims.release.buildReceiptSha256,
    ...(lane === "PREPARE"
      ? {
          changeSetName: approval.claims.release.changeSetName,
          parameterManifestSha256:
            approval.claims.release.parameterManifestSha256,
          resourceInventorySha256:
            approval.claims.release.resourceInventorySha256,
          stackName: approval.claims.release.stackName,
          templateSha256: approval.claims.release.templateSha256
        }
      : {
          changeSetArn: approval.claims.release.changeSetArn,
          changeSetSha256: approval.claims.release.changeSetSha256,
          stackId: approval.claims.release.stackId
        }),
    controlPlaneIdentitySha256:
      approval.claims.controlPlane.identitySha256,
    cumulativeCapUsd: approval.claims.budget.cumulativeCapUsd,
    databaseIdentitySha256,
    effectIdentitySha256,
    budgetKeySha256,
    expectedPriorCumulativeSpendUsd: approval.claims.budget.alreadySpentUsd,
    globalKeySha256: brokerSha256(Buffer.from(
      `prooftoact-provider-effect-v2\n${effectIdentitySha256}`,
      "utf8"
    )),
    lane,
    maximumConcurrency: MAXIMUM_CONCURRENCY,
    maximumRuns: MAXIMUM_RUNS,
    namespaceArn: approval.claims.globalStore.namespaceArn,
    operationIdentitySha256: canonicalDigest(operation),
    providerMutationExpected: LANE_CONTRACTS[lane].mutating,
    region: REGION,
    teardownReserveUsd: approval.claims.budget.teardownReserveUsd,
    teardownContractSha256,
    workspaceRealpathSha256: approval.claims.workspaceRealpathSha256
  };
  return Object.freeze({
    ...command,
    commandSha256: canonicalDigest(command)
  });
}

function validateConsumption(value, command, approval, now) {
  const code = "PROVIDER_BROKER_GLOBAL_CONSUMPTION_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalId", "approvalSha256", "commandSha256", "consumedAt",
    "budgetKeySha256", "budgetVersion", "cumulativeCapUsd", "durable",
    "effectIdentitySha256", "globalKeySha256",
    "globallyAuthoritative", "namespaceArn", "oneShot",
    "priorCumulativeSpendUsd", "reservedSpendUsd", "resultingCumulativeSpendUsd",
    "schemaVersion", "status", "storeRequestId", "stronglyConsistent",
    "version"
  ]) && value.schemaVersion === CONSUMPTION_SCHEMA &&
    ["CONSUMED", "REPLAY"].includes(value.status) &&
    value.approvalId === command.approvalId &&
    value.approvalSha256 === command.approvalSha256 &&
    value.commandSha256 === command.commandSha256 &&
    value.budgetKeySha256 === command.budgetKeySha256 &&
    value.effectIdentitySha256 === command.effectIdentitySha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArn === command.namespaceArn && value.oneShot === true &&
    value.durable === true && value.globallyAuthoritative === true &&
    value.stronglyConsistent === true && UUID.test(value.storeRequestId ?? "") &&
    Number.isSafeInteger(value.version) && value.version >= 1 &&
    Number.isSafeInteger(value.budgetVersion) && value.budgetVersion >= 1,
  code);
  boundedNumber(value.priorCumulativeSpendUsd, 0,
    CUMULATIVE_SPEND_CAP_USD, code);
  boundedNumber(value.reservedSpendUsd, 0, CUMULATIVE_SPEND_CAP_USD, code);
  boundedNumber(value.resultingCumulativeSpendUsd, 0,
    CUMULATIVE_SPEND_CAP_USD, code);
  requireCondition(value.cumulativeCapUsd === CUMULATIVE_SPEND_CAP_USD &&
    value.reservedSpendUsd === command.budgetReservationUsd &&
    Number((value.priorCumulativeSpendUsd + value.reservedSpendUsd)
      .toFixed(6)) === value.resultingCumulativeSpendUsd &&
    value.resultingCumulativeSpendUsd <= value.cumulativeCapUsd &&
    value.priorCumulativeSpendUsd === command.expectedPriorCumulativeSpendUsd &&
    value.priorCumulativeSpendUsd === approval.claims.budget.alreadySpentUsd &&
    parseIso(value.consumedAt, code) <= now &&
    parseIso(value.consumedAt, code) >= approval.issuedAt &&
    parseIso(value.consumedAt, code) < approval.expiresAt, code);
  return Object.freeze({ ...value });
}

function validateIntent(value, command, consumption) {
  const code = "PROVIDER_BROKER_GLOBAL_INTENT_REJECTED";
  requireCondition(exactKeys(value, [
    "action", "approvalId", "commandSha256", "durable", "event",
    "globalKeySha256", "globallyAuthoritative", "intentId", "lane",
    "previousReceiptSha256", "schemaVersion", "status", "version"
  ]) && value.schemaVersion === INTENT_SCHEMA && value.status === "DURABLE" &&
    value.event === "BEFORE_PROVIDER_DISPATCH" && value.durable === true &&
    value.globallyAuthoritative === true && value.approvalId ===
      command.approvalId && value.commandSha256 === command.commandSha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.action === command.action && value.lane === command.lane &&
    UUID.test(value.intentId ?? "") && value.previousReceiptSha256 ===
      canonicalDigest(consumption) && Number.isSafeInteger(value.version) &&
    value.version === consumption.version + 1, code);
  return Object.freeze({ ...value });
}

function validateOutcome(value, command, now, allowHistorical = false) {
  const code = "PROVIDER_BROKER_DISPATCH_OUTCOME_REJECTED";
  requireCondition(exactKeys(value, [
    "observedAt", "operationIdentitySha256", "possibleMutation",
    "providerReceiptSha256", "providerRequestId", "schemaVersion", "status"
  ]) && value.schemaVersion === OUTCOME_SCHEMA && [
    "AMBIGUOUS", "CONFIRMED", "FAILED_TERMINAL"
  ].includes(value.status) && value.operationIdentitySha256 ===
    command.operationIdentitySha256 &&
    (value.status === "FAILED_TERMINAL"
      ? value.possibleMutation === false
      : value.possibleMutation === command.providerMutationExpected) &&
    (UUID.test(value.providerRequestId ?? "") ||
      ["AMBIGUOUS", "FAILED_TERMINAL"].includes(value.status) &&
        value.providerRequestId === null) &&
    HEX_64.test(value.providerReceiptSha256 ?? "") &&
    parseIso(value.observedAt, code) <= now &&
    (allowHistorical ||
      now - parseIso(value.observedAt, code) <= 5 * 60 * 1000), code);
  return Object.freeze({ ...value });
}

function validateTerminal(value, command, predecessor, now, expectedOutcome = null) {
  const code = "PROVIDER_BROKER_GLOBAL_TERMINAL_REJECTED";
  const predecessorState = predecessor?.schemaVersion === INTENT_SCHEMA
    ? "INTENT"
    : predecessor?.schemaVersion === CONSUMPTION_SCHEMA
      ? "CONSUMPTION"
      : null;
  requireCondition(exactKeys(value, [
    "approvalId", "commandSha256", "durable", "globalKeySha256",
    "globallyAuthoritative", "outcome", "predecessorReceiptSha256",
    "predecessorState", "recordedAt", "schemaVersion", "status",
    "terminalSha256", "version"
  ]) && value.schemaVersion === TERMINAL_SCHEMA && value.status === "TERMINAL" &&
    value.approvalId === command.approvalId && value.commandSha256 ===
      command.commandSha256 && value.globalKeySha256 === command.globalKeySha256 &&
    value.durable === true && value.globallyAuthoritative === true &&
    value.predecessorState === predecessorState &&
    value.predecessorReceiptSha256 === canonicalDigest(predecessor) &&
    Number.isSafeInteger(value.version) && value.version ===
      predecessor.version + 1 &&
    parseIso(value.recordedAt, code) <= now, code);
  validateOutcome(value.outcome, command, now, true);
  requireCondition(expectedOutcome === null ||
    canonicalJson(value.outcome) === canonicalJson(expectedOutcome), code);
  requireCondition(predecessorState !== "CONSUMPTION" ||
    value.outcome.status === "FAILED_TERMINAL" &&
    value.outcome.possibleMutation === false, code);
  const unsigned = { ...value };
  delete unsigned.terminalSha256;
  requireCondition(value.terminalSha256 === canonicalDigest(unsigned), code);
  return Object.freeze({ ...value, outcome: Object.freeze({ ...value.outcome }) });
}

function validateGlobalRecord(value, command, approval, now) {
  const code = "PROVIDER_BROKER_GLOBAL_RECORD_REJECTED";
  requireCondition(exactKeys(value, [
    "command", "consumption", "intent", "schemaVersion", "status", "terminal"
  ]) && value.schemaVersion === RECORD_SCHEMA && [
    "CONSUMED", "INTENT", "TERMINAL"
  ].includes(value.status) && canonicalJson(value.command) ===
    canonicalJson(command), code);
  const consumption = validateConsumption(
    value.consumption,
    command,
    approval,
    now
  );
  requireCondition(consumption.status === "CONSUMED", code);
  let intent = null;
  if (value.intent !== null) {
    intent = validateIntent(value.intent, command, consumption);
  }
  let terminal = null;
  if (value.terminal !== null) {
    terminal = validateTerminal(
      value.terminal,
      command,
      intent ?? consumption,
      now
    );
  }
  requireCondition(
    value.status === "CONSUMED"
      ? intent === null && terminal === null
      : value.status === "INTENT"
        ? intent !== null && terminal === null
        : terminal !== null,
    code
  );
  return Object.freeze({
    command: Object.freeze({ ...value.command }),
    consumption,
    intent,
    status: value.status,
    terminal
  });
}

function rejectCapabilities(value, names, code) {
  requireCondition(value !== null && typeof value === "object", code);
  requireCondition(names.every((name) => typeof value[name] !== "function"),
    code);
}

function reserveStoreCapability(value) {
  const code = "PROVIDER_BROKER_COORDINATOR_RESERVE_CAPABILITY_REJECTED";
  requireCondition(value && ["appendIntent", "consumeOnce", "readStrong"]
    .every((name) => typeof value[name] === "function"), code);
  rejectCapabilities(value, [
    "dispatch", "finalize", "providerReadback", "reconcile", "terminalize",
    "terminalizeExpired"
  ], code);
  return value;
}

function intentReaderCapability(value) {
  const code = "PROVIDER_BROKER_PERMIT_READER_CAPABILITY_REJECTED";
  requireCondition(value && typeof value.readStrong === "function", code);
  rejectCapabilities(value, [
    "appendIntent", "consumeOnce", "dispatch", "finalize", "providerReadback",
    "reconcile", "terminalize", "terminalizeExpired"
  ], code);
  return value;
}

function laneDispatcherCapability(value) {
  const code = "PROVIDER_BROKER_LANE_DISPATCH_CAPABILITY_REJECTED";
  requireCondition(value && typeof value.dispatch === "function", code);
  rejectCapabilities(value, [
    "appendIntent", "consumeOnce", "finalize", "providerReadback", "readStrong",
    "terminalize", "terminalizeExpired"
  ], code);
  return value;
}

function finalizerStoreCapability(value) {
  const code = "PROVIDER_BROKER_COORDINATOR_FINALIZER_CAPABILITY_REJECTED";
  requireCondition(value && ["finalize", "readStrong"]
    .every((name) => typeof value[name] === "function"), code);
  rejectCapabilities(value, [
    "appendIntent", "consumeOnce", "dispatch", "providerReadback",
    "terminalize", "terminalizeExpired"
  ], code);
  return value;
}

function providerReadbackCapability(value) {
  const code = "PROVIDER_BROKER_PROVIDER_READBACK_CAPABILITY_REJECTED";
  requireCondition(value && typeof value.readback === "function", code);
  rejectCapabilities(value, [
    "appendIntent", "consumeOnce", "dispatch", "finalize", "readStrong",
    "terminalize", "terminalizeExpired"
  ], code);
  return value;
}

function phaseLookupFor(approval, command, intent) {
  const lookup = {
    schemaVersion: PHASE_LOOKUP_SCHEMA,
    approvalSha256: approval.approvalSha256,
    commandSha256: command.commandSha256,
    globalKeySha256: command.globalKeySha256,
    intentSha256: intent === null ? null : canonicalDigest(intent),
    namespaceArnSha256: brokerSha256(Buffer.from(command.namespaceArn, "utf8")),
    tableIdentitySha256: approval.claims.globalStore.tableIdentitySha256
  };
  return Object.freeze({
    ...lookup,
    lookupSha256: canonicalDigest(lookup)
  });
}

function validatePhaseLookup(value, approval, command, intentRequired) {
  const code = "PROVIDER_BROKER_PHASE_LOOKUP_REJECTED";
  requireCondition(exactKeys(value, [
    "approvalSha256", "commandSha256", "globalKeySha256", "intentSha256",
    "lookupSha256", "namespaceArnSha256", "schemaVersion",
    "tableIdentitySha256"
  ]) && value.schemaVersion === PHASE_LOOKUP_SCHEMA &&
    value.approvalSha256 === approval.approvalSha256 &&
    value.commandSha256 === command.commandSha256 &&
    value.globalKeySha256 === command.globalKeySha256 &&
    value.namespaceArnSha256 ===
      brokerSha256(Buffer.from(command.namespaceArn, "utf8")) &&
    value.tableIdentitySha256 ===
      approval.claims.globalStore.tableIdentitySha256 &&
    (intentRequired ? HEX_64.test(value.intentSha256 ?? "") :
      value.intentSha256 === null), code);
  const unsigned = { ...value };
  delete unsigned.lookupSha256;
  requireCondition(value.lookupSha256 === canonicalDigest(unsigned), code);
  return Object.freeze({ ...value });
}

function phaseReceiptFor({
  approval,
  command,
  lookup,
  outcome = null,
  phase,
  preparedRelease = null,
  runtimeIdentity,
  status,
  terminal = null
}) {
  const receipt = {
    schemaVersion: PHASE_RECEIPT_SCHEMA,
    approvalId: command.approvalId,
    approvalSha256: approval.approvalSha256,
    commandSha256: command.commandSha256,
    globalKeySha256: command.globalKeySha256,
    lane: command.lane,
    lookupSha256: lookup.lookupSha256,
    outcomeProviderReceiptSha256: outcome?.providerReceiptSha256 ?? null,
    outcomeProviderRequestId: outcome?.providerRequestId ?? null,
    outcomeStatus: outcome?.status ?? null,
    phase,
    phaseRuntimeIdentity: runtimeIdentity,
    preparedRelease,
    providerDispatchPerformed: phase === "PROVIDER_DISPATCH",
    retryAllowed: false,
    status,
    terminalSha256: terminal?.terminalSha256 ?? null
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: canonicalDigest(receipt)
  });
}

function validatePreparedRelease(value, command, code) {
  requireCondition(exactKeys(value, [
    "changeSetArn", "changeSetName", "changeSetSha256", "changeSetType",
    "stackId", "stackName"
  ]) && command.lane === "PREPARE" &&
    value.changeSetName === command.changeSetName &&
    value.changeSetType === "CREATE" && value.stackName === command.stackName &&
    HEX_64.test(value.changeSetSha256 ?? "") &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:changeSet\/prooftoact-release-[a-z0-9-]{1,64}\/[0-9a-f-]{36}$/u
      .test(value.changeSetArn ?? "") &&
    /^arn:aws:cloudformation:us-east-1:[0-9]{12}:stack\/prooftoact-gate2\/[0-9a-f-]{36}$/u
      .test(value.stackId ?? "") &&
    value.changeSetArn.split(":")[4] === command.namespaceArn.split(":")[4] &&
    value.stackId.split(":")[4] === command.namespaceArn.split(":")[4], code);
  return Object.freeze({ ...value });
}

function validateFinalizerReadback(
  value,
  command,
  intent,
  runtimeIdentity,
  now
) {
  const code = "PROVIDER_BROKER_FINALIZER_READBACK_REJECTED";
  requireCondition(exactKeys(value, [
    "commandSha256", "fresh", "independentOfDispatcher", "intentSha256",
    "observedAt", "operationIdentitySha256", "preparedRelease",
    "providerNativeIdempotencyTokenSha256", "providerReceiptSha256",
    "providerRequestId", "readOnly", "readerPhaseRuntimeIdentitySha256",
    "schemaVersion", "status"
  ]) && value.schemaVersion === FINALIZER_READBACK_SCHEMA &&
    ["CONFIRMED_APPLIED", "CONFIRMED_NOT_APPLIED", "UNKNOWN"]
      .includes(value.status) && value.fresh === true && value.readOnly === true &&
    value.independentOfDispatcher === true &&
    value.commandSha256 === command.commandSha256 &&
    value.intentSha256 === canonicalDigest(intent) &&
    value.operationIdentitySha256 === command.operationIdentitySha256 &&
    value.providerNativeIdempotencyTokenSha256 ===
      brokerSha256(Buffer.from(intent.intentId, "utf8")) &&
    value.readerPhaseRuntimeIdentitySha256 ===
      runtimeIdentity.phaseRuntimeIdentitySha256 &&
    HEX_64.test(value.providerReceiptSha256 ?? "") &&
    parseIso(value.observedAt, code) <= now &&
    now - parseIso(value.observedAt, code) <= 5 * 60 * 1000 &&
    (value.status === "UNKNOWN"
      ? value.providerRequestId === null
      : UUID.test(value.providerRequestId ?? "")), code);
  let preparedRelease = null;
  if (command.lane === "PREPARE" && value.status === "CONFIRMED_APPLIED") {
    preparedRelease = validatePreparedRelease(value.preparedRelease, command, code);
  } else {
    requireCondition(value.preparedRelease === null, code);
  }
  return Object.freeze({ ...value, preparedRelease });
}

function errorCode(error) {
  const raw = typeof error?.message === "string"
    ? error.message
    : typeof error?.code === "string" ? error.code : "UNKNOWN";
  return raw.replace(/[^A-Z0-9_]/giu, "_").toUpperCase().slice(0, 96);
}

function syntheticAmbiguousOutcome(
  command,
  now,
  cause,
  possibleMutation = command.providerMutationExpected
) {
  const base = {
    schemaVersion: OUTCOME_SCHEMA,
    status: "AMBIGUOUS",
    operationIdentitySha256: command.operationIdentitySha256,
    possibleMutation,
    providerRequestId: null,
    observedAt: new Date(now).toISOString(),
    providerReceiptSha256: canonicalDigest({
      code: errorCode(cause),
      operationIdentitySha256: command.operationIdentitySha256,
      status: "AMBIGUOUS"
    })
  };
  return Object.freeze(base);
}

function syntheticTerminalFailureOutcome(command, now, cause) {
  return Object.freeze({
    schemaVersion: OUTCOME_SCHEMA,
    status: "FAILED_TERMINAL",
    operationIdentitySha256: command.operationIdentitySha256,
    possibleMutation: false,
    providerRequestId: null,
    observedAt: new Date(now).toISOString(),
    providerReceiptSha256: canonicalDigest({
      code: errorCode(cause),
      operationIdentitySha256: command.operationIdentitySha256,
      status: "FAILED_TERMINAL"
    })
  });
}

function validateReconciliation(value, command, now) {
  const code = "PROVIDER_BROKER_RECONCILIATION_REJECTED";
  requireCondition(exactKeys(value, [
    "fresh", "observedAt", "operationIdentitySha256", "providerReceiptSha256",
    "providerRequestId", "readOnly", "roleName", "schemaVersion", "status",
    "workflow"
  ]) && value.schemaVersion === RECONCILIATION_SCHEMA && [
    "CONFIRMED_APPLIED", "CONFIRMED_NOT_APPLIED", "UNKNOWN"
  ].includes(value.status) && value.fresh === true && value.readOnly === true &&
    value.workflow === AUTHORITY_CONTRACTS.evidence.workflow &&
    value.roleName === AUTHORITY_CONTRACTS.evidence.roleName &&
    value.operationIdentitySha256 === command.operationIdentitySha256 &&
    UUID.test(value.providerRequestId ?? "") &&
    HEX_64.test(value.providerReceiptSha256 ?? "") &&
    parseIso(value.observedAt, code) <= now &&
    now - parseIso(value.observedAt, code) <= 5 * 60 * 1000, code);
  return Object.freeze({ ...value });
}

async function reconcileFreshReadOnly(reconciler, command, nowOrClock) {
  const currentTime = () => typeof nowOrClock === "function"
    ? nowOrClock() : nowOrClock;
  let sampledAfterAwait = null;
  try {
    requireCondition(reconciler && typeof reconciler.reconcile === "function",
      "PROVIDER_BROKER_RECONCILER_REJECTED");
    const value = await reconciler.reconcile(Object.freeze({
      commandSha256: command.commandSha256,
      evidenceEnvironment: AUTHORITY_CONTRACTS.evidence.environment,
      evidenceRoleName: AUTHORITY_CONTRACTS.evidence.roleName,
      fresh: true,
      globalKeySha256: command.globalKeySha256,
      operationIdentitySha256: command.operationIdentitySha256,
      readOnly: true,
      workflow: AUTHORITY_CONTRACTS.evidence.workflow
    }));
    sampledAfterAwait = currentTime();
    return Object.freeze({
      attempted: true,
      receipt: validateReconciliation(value, command, sampledAfterAwait),
      status: value.status
    });
  } catch (cause) {
    if (sampledAfterAwait === null) currentTime();
    return Object.freeze({
      attempted: true,
      receipt: null,
      status: "UNAVAILABLE",
      failureCode: errorCode(cause)
    });
  }
}

function receiptFor({ approval, command, terminal, outcome, reconciliation }) {
  const status = outcome.status === "CONFIRMED"
    ? "CONFIRMED"
    : outcome.status === "FAILED_TERMINAL" ? "TERMINAL_FAILURE" :
      "UNKNOWN_DO_NOT_ACT";
  const receipt = {
    schemaVersion: RECEIPT_SCHEMA,
    action: command.action,
    approvalId: command.approvalId,
    approvalSha256: command.approvalSha256,
    appSource: APP_SOURCE,
    artifactManifestSha256: command.artifactManifestSha256,
    buildReceiptSha256: command.buildReceiptSha256,
    changeSetArn: command.changeSetArn ?? null,
    changeSetSha256: command.changeSetSha256 ?? null,
    stackId: command.stackId ?? null,
    commandSha256: command.commandSha256,
    controlPlaneIdentitySha256: command.controlPlaneIdentitySha256,
    cumulativeCapUsd: command.cumulativeCapUsd,
    databaseIdentitySha256: command.databaseIdentitySha256,
    freshReadOnlyReconciliationAttempted: reconciliation?.attempted ?? false,
    freshReadOnlyReconciliationReceiptSha256: reconciliation?.receipt
      ? canonicalDigest(reconciliation.receipt) : null,
    freshReadOnlyReconciliationStatus: reconciliation?.status ?? "NOT_REQUIRED",
    globalTerminalSha256: terminal?.terminalSha256 ?? null,
    lane: command.lane,
    maximumConcurrency: command.maximumConcurrency,
    maximumRuns: command.maximumRuns,
    operationIdentitySha256: command.operationIdentitySha256,
    outcomeProviderReceiptSha256: outcome.providerReceiptSha256,
    outcomeProviderRequestId: outcome.providerRequestId,
    outcomeStatus: outcome.status,
    region: command.region,
    retryAllowed: false,
    status,
    teardownReserveUsd: command.teardownReserveUsd,
    teardownContractSha256: command.teardownContractSha256
  };
  return Object.freeze({
    ...receipt,
    receiptSha256: canonicalDigest(receipt)
  });
}

function holdReceipt(approval, runtime, reason) {
  const receipt = {
    schemaVersion: RECEIPT_SCHEMA,
    status: "HOLD",
    reason,
    approvalId: approval.claims.approvalId,
    lane: runtime.lane,
    appSource: APP_SOURCE,
    controlPlaneIdentitySha256: runtime.controlPlaneIdentitySha256,
    providerExecutionEnabled: false,
    authorityConsumed: false,
    providerDispatchPerformed: false,
    retryAllowed: false,
    requiredNextAction:
      "PROVIDE_FRESH_EXACT_PROVIDER_BACKED_RUNTIME_AUTHORITY_RECEIPTS"
  };
  return Object.freeze({ ...receipt, receiptSha256: canonicalDigest(receipt) });
}

async function unknownAfterPossibleMutation({
  approval,
  authorityConsumptionStatus = "UNKNOWN",
  cause,
  command,
  dispatchAttempted = false,
  globalStore,
  intent,
  now,
  outcome,
  reconciler,
  terminalize = true
}) {
  const ambiguous = outcome ?? syntheticAmbiguousOutcome(
    command,
    now,
    cause,
    dispatchAttempted && command.providerMutationExpected
  );
  let terminal = null;
  if (intent && terminalize) {
    try {
      terminal = validateTerminal(await globalStore.finalize(Object.freeze({
        command,
        intent,
        outcome: ambiguous
      })), command, intent, now, ambiguous);
    } catch {
      terminal = null;
    }
  }
  const reconciliation = await reconcileFreshReadOnly(reconciler, command, now);
  return Object.freeze({
    receipt: receiptFor({
      approval,
      command,
      outcome: ambiguous,
      reconciliation,
      terminal
    }),
    authorityConsumptionStatus,
    dispatchStatus: dispatchAttempted
      ? "ATTEMPTED_OUTCOME_UNKNOWN"
      : "NOT_ATTEMPTED",
    replayRejected: false,
    possibleMutation: ambiguous.possibleMutation
  });
}

function exactCapabilities(globalStore, dispatcher) {
  requireCondition(globalStore && [
    "appendIntent", "consumeOnce", "finalize", "readStrong", "terminalize"
  ].every((name) => typeof globalStore[name] === "function"),
  "PROVIDER_BROKER_GLOBAL_STORE_CAPABILITY_REJECTED");
  requireCondition(dispatcher && typeof dispatcher.dispatch === "function",
    "PROVIDER_BROKER_DISPATCH_CAPABILITY_REJECTED");
}

async function recoverReplay({
  approval,
  command,
  consumption,
  globalStore,
  now,
  reconciler
}) {
  let observed;
  try {
    observed = await globalStore.readStrong(Object.freeze({
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      namespaceArn: command.namespaceArn,
      stronglyConsistent: true
    }));
  } catch (cause) {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "PREVIOUSLY_CONSUMED",
      cause,
      command,
      globalStore,
      intent: null,
      now,
      reconciler
    });
  }
  const record = validateGlobalRecord(observed, command, approval, now);
  requireCondition(consumption.version === record.consumption.version,
    "PROVIDER_BROKER_REPLAY_RECORD_REJECTED");
  if (record.status === "TERMINAL") {
    const terminal = record.terminal;
    const reconciliation = terminal.outcome.status === "AMBIGUOUS"
      ? await reconcileFreshReadOnly(reconciler, command, now)
      : null;
    return Object.freeze({
      receipt: receiptFor({
        approval,
        command,
        outcome: terminal.outcome,
        reconciliation,
        terminal
      }),
      authorityConsumptionStatus: "PREVIOUSLY_CONSUMED",
      dispatchStatus: "PREVIOUSLY_RECORDED",
      replayRejected: true,
      possibleMutation: terminal.outcome.possibleMutation
    });
  }
  if (record.status === "INTENT") {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "PREVIOUSLY_CONSUMED",
      cause: new Error("PROVIDER_BROKER_RECOVERED_INTENT_WITHOUT_TERMINAL"),
      command,
      dispatchAttempted: true,
      globalStore,
      intent: record.intent,
      now,
      reconciler,
      terminalize: false
    });
  }
  return unknownAfterPossibleMutation({
    approval,
    authorityConsumptionStatus: "PREVIOUSLY_CONSUMED",
    cause: new Error("PROVIDER_BROKER_RECOVERED_CONSUMPTION_WITHOUT_INTENT"),
    command,
    globalStore,
    intent: null,
    now,
    reconciler,
    terminalize: false
  });
}

function trustedPhaseClock(clock, now, code) {
  requireCondition(clock === undefined || typeof clock === "function", code);
  requireCondition(now === undefined || Number.isFinite(now), code);
  // `now` remains only for deterministic legacy tests. Production callers
  // omit it and therefore sample Date.now at every consequential boundary.
  const source = clock ?? (now === undefined ? Date.now : () => now);
  let previous = Number.NEGATIVE_INFINITY;
  return () => {
    let sampled;
    try {
      sampled = source();
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(Number.isFinite(sampled) && sampled >= previous, code);
    previous = sampled;
    return sampled;
  };
}

function validateFreshPhaseBoundary({
  approvalEnvelope,
  expectedApprovalSha256 = null,
  expectedPhase,
  now,
  runtime,
  trustedOperatorPublicKey
}) {
  const approval = validateProviderBrokerApproval(
    approvalEnvelope,
    trustedOperatorPublicKey,
    now
  );
  requireCondition(expectedApprovalSha256 === null ||
    approval.approvalSha256 === expectedApprovalSha256,
  "PROVIDER_BROKER_PHASE_APPROVAL_DRIFT_REJECTED");
  const acceptedRuntime = validatePhaseRuntimeBase(
    runtime,
    approval,
    now,
    expectedPhase
  );
  validatePhaseRuntimeAuthority(
    runtime.authorityReceipts,
    approval,
    acceptedRuntime,
    now
  );
  return Object.freeze({ acceptedRuntime, approval, now });
}

function validateFreshTerminalizerBoundary({
  approvalEnvelope,
  expectedApprovalSha256 = null,
  now,
  terminalizerRuntime,
  trustedOperatorPublicKey
}) {
  const code = "PROVIDER_BROKER_EXPIRED_TERMINALIZATION_REJECTED";
  const approval = validateProviderBrokerApprovalEnvelope(
    approvalEnvelope,
    trustedOperatorPublicKey,
    now,
    false
  );
  requireCondition(expectedApprovalSha256 === null ||
    approval.approvalSha256 === expectedApprovalSha256, code);
  requireCondition(now >= approval.expiresAt, code);
  validateTerminalizerRuntimeBase(terminalizerRuntime, approval, now);
  const authority = validateRuntimeAuthority(
    terminalizerRuntime.authorityReceipts,
    approval,
    terminalizerRuntime,
    now,
    false
  );
  requireCondition(authority !== null, code);
  return Object.freeze({ approval, authority, now });
}

async function readPhaseRecord(reader, approval, command, nowOrClock) {
  let observed;
  let observedAt;
  try {
    observed = await reader.readStrong(Object.freeze({
      commandSha256: command.commandSha256,
      globalKeySha256: command.globalKeySha256,
      namespaceArn: command.namespaceArn,
      stronglyConsistent: true
    }));
  } finally {
    observedAt = typeof nowOrClock === "function"
      ? nowOrClock() : nowOrClock;
  }
  return validateGlobalRecord(observed, command, approval, observedAt);
}

function phaseStatusForOutcome(outcome) {
  return outcome.status === "CONFIRMED"
    ? "CONFIRMED"
    : outcome.status === "FAILED_TERMINAL"
      ? "TERMINAL_FAILURE"
      : "UNKNOWN_DO_NOT_ACT";
}

function outcomeFromFinalizerReadback(readback, command) {
  const status = readback.status === "CONFIRMED_APPLIED"
    ? "CONFIRMED"
    : readback.status === "CONFIRMED_NOT_APPLIED"
      ? "FAILED_TERMINAL"
      : "AMBIGUOUS";
  return Object.freeze({
    schemaVersion: OUTCOME_SCHEMA,
    status,
    operationIdentitySha256: command.operationIdentitySha256,
    possibleMutation: status === "FAILED_TERMINAL"
      ? false
      : command.providerMutationExpected,
    providerRequestId: readback.providerRequestId,
    observedAt: readback.observedAt,
    providerReceiptSha256: readback.providerReceiptSha256
  });
}

function dispatchPlanFor(command, intent) {
  const step = ({
    idempotencyMechanism,
    name,
    providerNativeIdempotencyToken,
    stepIdentity
  }) => Object.freeze({
    idempotencyBindingSha256: canonicalDigest({
      commandSha256: command.commandSha256,
      intentId: intent.intentId,
      stepIdentity
    }),
    idempotencyMechanism,
    maximumAttempts: 1,
    mutating: command.providerMutationExpected,
    name,
    providerNativeIdempotencyToken
  });
  const steps = command.lane === "PREPARE" ? [
    step({
      idempotencyMechanism: "CONTENT_ADDRESSED_CREATE_OR_EXACT_REUSE_ONLY",
      name: "CONDITIONAL_EXACT_S3_ARTIFACT_UPLOAD_SET",
      providerNativeIdempotencyToken: null,
      stepIdentity: {
        artifactManifestSha256: command.artifactManifestSha256,
        buildReceiptSha256: command.buildReceiptSha256,
        changeSetName: command.changeSetName,
        step: "CONDITIONAL_EXACT_S3_ARTIFACT_UPLOAD_SET"
      }
    }),
    step({
      idempotencyMechanism: "CLOUDFORMATION_CLIENT_TOKEN",
      name: "CREATE_EXACT_CHANGE_SET",
      providerNativeIdempotencyToken: intent.intentId,
      stepIdentity: {
        changeSetName: command.changeSetName,
        parameterManifestSha256: command.parameterManifestSha256,
        stackName: command.stackName,
        step: "CREATE_EXACT_CHANGE_SET",
        templateSha256: command.templateSha256
      }
    })
  ] : [step({
    idempotencyMechanism: command.providerMutationExpected
      ? command.lane === "DRILL"
        ? "DURABLE_OPERATION_EFFECT_FENCE_IDENTITY"
        : "PROVIDER_NATIVE_CLIENT_REQUEST_TOKEN"
      : "READ_ONLY_NO_MUTATION",
    name: LANE_CONTRACTS[command.lane].action,
    providerNativeIdempotencyToken: command.providerMutationExpected
      ? intent.intentId : null,
    stepIdentity: {
      action: command.action,
      effectIdentitySha256: command.effectIdentitySha256,
      step: LANE_CONTRACTS[command.lane].action
    }
  })];
  const plan = {
    schemaVersion: DISPATCH_PLAN_SCHEMA,
    brokerDispatcherInvocationCount: 1,
    commandSha256: command.commandSha256,
    intentSha256: canonicalDigest(intent),
    lane: command.lane,
    noAutomaticRetry: true,
    steps: Object.freeze(steps)
  };
  return Object.freeze({
    ...plan,
    dispatchPlanSha256: canonicalDigest(plan)
  });
}

/*
 * Production phase 1. This API accepts a deliberately narrowed store facade:
 * it can reserve budget/effect occupancy, append one intent, and strongly read
 * that journal. It has no provider dispatcher or terminal-finalization surface.
 */
export async function reserveProviderOneShotIntent({
  approvalEnvelope,
  clock,
  coordinatorRuntime,
  environment = process.env,
  globalStore,
  now,
  trustedOperatorPublicKey
}) {
  const code = "PROVIDER_BROKER_COORDINATOR_CLOCK_REJECTED";
  rejectProviderEnvironment(environment);
  const trustedNow = trustedPhaseClock(clock, now, code);
  const initial = validateFreshPhaseBoundary({
    approvalEnvelope,
    expectedPhase: "COORDINATOR_RESERVE",
    now: trustedNow(),
    runtime: coordinatorRuntime,
    trustedOperatorPublicKey
  });
  const { approval, acceptedRuntime } = initial;
  const freshBoundary = () => validateFreshPhaseBoundary({
    approvalEnvelope,
    expectedApprovalSha256: approval.approvalSha256,
    expectedPhase: "COORDINATOR_RESERVE",
    now: trustedNow(),
    runtime: coordinatorRuntime,
    trustedOperatorPublicKey
  });
  const command = commandFor(approval);
  const unknown = () => {
    const lookup = phaseLookupFor(approval, command, null);
    return Object.freeze({
      lookup,
      receipt: phaseReceiptFor({
        approval,
        command,
        lookup,
        phase: "COORDINATOR_RESERVE",
        runtimeIdentity: acceptedRuntime.identity,
        status: "UNKNOWN_DO_NOT_ACT"
      })
    });
  };
  const stillFresh = () => {
    try {
      return freshBoundary();
    } catch {
      return null;
    }
  };
  reserveStoreCapability(globalStore);
  let consumption;
  let record = null;
  try {
    requireCondition(stillFresh() !== null,
      "PROVIDER_BROKER_COORDINATOR_RESERVE_EXPIRED");
    const observedConsumption = await globalStore.consumeOnce(command);
    const afterConsumption = freshBoundary();
    consumption = validateConsumption(
      observedConsumption,
      command,
      approval,
      afterConsumption.now
    );
  } catch (cause) {
    if (stillFresh() === null) return unknown();
    try {
      freshBoundary();
      record = await readPhaseRecord(
        globalStore,
        approval,
        command,
        trustedNow
      );
      freshBoundary();
    } catch {
      record = null;
    }
    if (record === null || stillFresh() === null) return unknown();
    consumption = record.consumption;
  }

  if (record?.status === "TERMINAL") {
    const lookup = phaseLookupFor(approval, command, record.intent);
    return Object.freeze({
      lookup,
      receipt: phaseReceiptFor({
        approval,
        command,
        lookup,
        outcome: record.terminal.outcome,
        phase: "COORDINATOR_RESERVE",
        runtimeIdentity: acceptedRuntime.identity,
        status: "TERMINAL_ALREADY_RECORDED",
        terminal: record.terminal
      })
    });
  }
  if (record?.status === "INTENT") {
    const lookup = phaseLookupFor(approval, command, record.intent);
    return Object.freeze({
      lookup,
      receipt: phaseReceiptFor({
        approval,
        command,
        lookup,
        phase: "COORDINATOR_RESERVE",
        runtimeIdentity: acceptedRuntime.identity,
        status: "INTENT_ALREADY_RECORDED"
      })
    });
  }
  if (consumption.status === "REPLAY") {
    try {
      freshBoundary();
      record = await readPhaseRecord(
        globalStore,
        approval,
        command,
        trustedNow
      );
      freshBoundary();
    } catch (cause) {
      if (stillFresh() === null) return unknown();
      reject("PROVIDER_BROKER_COORDINATOR_RESERVE_REPLAY_REJECTED", cause);
    }
    if (record.status === "TERMINAL") {
      const lookup = phaseLookupFor(approval, command, record.intent);
      return Object.freeze({
        lookup,
        receipt: phaseReceiptFor({
          approval,
          command,
          lookup,
          outcome: record.terminal.outcome,
          phase: "COORDINATOR_RESERVE",
          runtimeIdentity: acceptedRuntime.identity,
          status: "TERMINAL_ALREADY_RECORDED",
          terminal: record.terminal
        })
      });
    }
    if (record.status === "INTENT") {
      const lookup = phaseLookupFor(approval, command, record.intent);
      return Object.freeze({
        lookup,
        receipt: phaseReceiptFor({
          approval,
          command,
          lookup,
          phase: "COORDINATOR_RESERVE",
          runtimeIdentity: acceptedRuntime.identity,
          status: "INTENT_ALREADY_RECORDED"
        })
      });
    }
  }

  let intent;
  try {
    requireCondition(stillFresh() !== null,
      "PROVIDER_BROKER_COORDINATOR_INTENT_EXPIRED");
    const observedIntent = await globalStore.appendIntent(Object.freeze({
      command,
      consumption
    }));
    freshBoundary();
    intent = validateIntent(
      observedIntent,
      command,
      consumption
    );
  } catch (cause) {
    if (stillFresh() === null) return unknown();
    try {
      freshBoundary();
      record = await readPhaseRecord(
        globalStore,
        approval,
        command,
        trustedNow
      );
      freshBoundary();
      requireCondition(record.status === "INTENT",
        "PROVIDER_BROKER_COORDINATOR_INTENT_ACK_REJECTED");
      intent = record.intent;
    } catch {
      return unknown();
    }
  }
  const lookup = phaseLookupFor(approval, command, intent);
  return Object.freeze({
    lookup,
    receipt: phaseReceiptFor({
      approval,
      command,
      lookup,
      phase: "COORDINATOR_RESERVE",
      runtimeIdentity: acceptedRuntime.identity,
      status: "INTENT_RECORDED"
    })
  });
}

/*
 * Production phase 2. The authoritative permit is the strongly read durable
 * INTENT. The lookup is hashes only. This function performs one bounded broker
 * dispatcher invocation and never retries it. PREPARE contains conditional
 * content-addressed uploads plus CreateChangeSet; every mutating step is bound
 * to the intent and has a one-attempt idempotency contract.
 */
export async function dispatchReservedProviderOneShotIntent({
  approvalEnvelope,
  clock,
  dispatcher,
  environment = process.env,
  intentReader,
  lookup,
  now,
  providerRuntime,
  trustedOperatorPublicKey
}) {
  const code = "PROVIDER_BROKER_DISPATCH_CLOCK_REJECTED";
  rejectProviderEnvironment(environment);
  const trustedNow = trustedPhaseClock(clock, now, code);
  const initial = validateFreshPhaseBoundary({
    approvalEnvelope,
    expectedPhase: "PROVIDER_DISPATCH",
    now: trustedNow(),
    runtime: providerRuntime,
    trustedOperatorPublicKey
  });
  const { approval, acceptedRuntime } = initial;
  const validateAt = (sampledAt) => validateFreshPhaseBoundary({
    approvalEnvelope,
    expectedApprovalSha256: approval.approvalSha256,
    expectedPhase: "PROVIDER_DISPATCH",
    now: sampledAt,
    runtime: providerRuntime,
    trustedOperatorPublicKey
  });
  const freshBoundary = () => validateAt(trustedNow());
  intentReaderCapability(intentReader);
  laneDispatcherCapability(dispatcher);
  const command = commandFor(approval);
  validatePhaseLookup(lookup, approval, command, true);
  const unknown = (outcome = null) => Object.freeze({
    lookup,
    receipt: phaseReceiptFor({
      approval,
      command,
      lookup,
      outcome,
      phase: "PROVIDER_DISPATCH",
      runtimeIdentity: acceptedRuntime.identity,
      status: "UNKNOWN_DO_NOT_ACT"
    })
  });
  let record;
  try {
    freshBoundary();
    record = await readPhaseRecord(
      intentReader,
      approval,
      command,
      trustedNow
    );
    freshBoundary();
    requireCondition(record.status === "INTENT" && record.intent !== null &&
      lookup.intentSha256 === canonicalDigest(record.intent),
    "PROVIDER_BROKER_DISPATCH_INTENT_REJECTED");
  } catch (cause) {
    try {
      freshBoundary();
    } catch {
      return unknown();
    }
    reject("PROVIDER_BROKER_DISPATCH_INTENT_REJECTED", cause);
  }
  const dispatchPlan = dispatchPlanFor(command, record.intent);
  try {
    freshBoundary();
  } catch {
    return unknown();
  }
  let observedOutcome = null;
  let dispatchCause = null;
  try {
    observedOutcome = await dispatcher.dispatch(Object.freeze({
      command,
      dispatchPlan,
      intent: record.intent,
      maxAttempts: 1,
      providerNativeIdempotencyToken: record.intent.intentId
    }));
  } catch (cause) {
    dispatchCause = cause;
  }
  const postDispatchNow = trustedNow();
  let postDispatchFresh = true;
  try {
    validateAt(postDispatchNow);
  } catch (cause) {
    postDispatchFresh = false;
    dispatchCause ??= cause;
  }
  let outcome;
  if (dispatchCause !== null || !postDispatchFresh) {
    outcome = syntheticAmbiguousOutcome(
      command,
      postDispatchNow,
      dispatchCause ?? new Error("PROVIDER_BROKER_DISPATCH_EXPIRED"),
      command.providerMutationExpected
    );
  } else {
    try {
      outcome = validateOutcome(observedOutcome, command, postDispatchNow);
    } catch (cause) {
      outcome = syntheticAmbiguousOutcome(
        command,
        postDispatchNow,
        cause,
        command.providerMutationExpected
      );
    }
  }
  return Object.freeze({
    lookup,
    receipt: phaseReceiptFor({
      approval,
      command,
      lookup,
      outcome,
      phase: "PROVIDER_DISPATCH",
      runtimeIdentity: acceptedRuntime.identity,
      status: outcome.status === "AMBIGUOUS"
        ? "DISPATCH_OUTCOME_UNKNOWN"
        : "DISPATCH_OBSERVED"
    })
  });
}

/*
 * Production phase 3. Dispatcher output is intentionally not accepted. A
 * fresh coordinator runner strongly rereads INTENT, performs an independent
 * provider readback, and conditionally publishes the immutable terminal row.
 */
export async function finalizeProviderOneShotIntent({
  approvalEnvelope,
  clock,
  coordinatorRuntime,
  dispatcherOutcome: _untrustedDispatcherOutcome,
  environment = process.env,
  globalStore,
  lookup,
  now,
  providerReadback,
  trustedOperatorPublicKey
}) {
  const code = "PROVIDER_BROKER_FINALIZER_CLOCK_REJECTED";
  rejectProviderEnvironment(environment);
  const trustedNow = trustedPhaseClock(clock, now, code);
  const initial = validateFreshPhaseBoundary({
    approvalEnvelope,
    expectedPhase: "COORDINATOR_FINALIZE",
    now: trustedNow(),
    runtime: coordinatorRuntime,
    trustedOperatorPublicKey
  });
  const { approval, acceptedRuntime } = initial;
  const validateAt = (sampledAt) => validateFreshPhaseBoundary({
    approvalEnvelope,
    expectedApprovalSha256: approval.approvalSha256,
    expectedPhase: "COORDINATOR_FINALIZE",
    now: sampledAt,
    runtime: coordinatorRuntime,
    trustedOperatorPublicKey
  });
  const freshBoundary = () => validateAt(trustedNow());
  finalizerStoreCapability(globalStore);
  providerReadbackCapability(providerReadback);
  const command = commandFor(approval);
  validatePhaseLookup(lookup, approval, command, true);
  const unknown = (sampledAt, cause) => {
    const outcome = syntheticAmbiguousOutcome(
      command,
      sampledAt,
      cause,
      command.providerMutationExpected
    );
    return Object.freeze({
      lookup,
      preparedRelease: null,
      receipt: phaseReceiptFor({
        approval,
        command,
        lookup,
        outcome,
        phase: "COORDINATOR_FINALIZE",
        preparedRelease: null,
        runtimeIdentity: acceptedRuntime.identity,
        status: "UNKNOWN_DO_NOT_ACT",
        terminal: null
      })
    });
  };
  let record;
  try {
    freshBoundary();
    record = await readPhaseRecord(
      globalStore,
      approval,
      command,
      trustedNow
    );
    freshBoundary();
  } catch (cause) {
    let sampledAt;
    try {
      sampledAt = trustedNow();
      validateAt(sampledAt);
    } catch {
      return unknown(sampledAt ?? initial.now, cause);
    }
    reject("PROVIDER_BROKER_FINALIZER_INTENT_REJECTED", cause);
  }
  if (record.status === "TERMINAL") {
    requireCondition(record.intent !== null &&
      lookup.intentSha256 === canonicalDigest(record.intent),
    "PROVIDER_BROKER_FINALIZER_INTENT_REJECTED");
    return Object.freeze({
      lookup,
      receipt: phaseReceiptFor({
        approval,
        command,
        lookup,
        outcome: record.terminal.outcome,
        phase: "COORDINATOR_FINALIZE",
        runtimeIdentity: acceptedRuntime.identity,
        status: phaseStatusForOutcome(record.terminal.outcome),
        terminal: record.terminal
      })
    });
  }
  requireCondition(record.status === "INTENT" && record.intent !== null &&
    lookup.intentSha256 === canonicalDigest(record.intent),
  "PROVIDER_BROKER_FINALIZER_INTENT_REJECTED");
  let readback = null;
  let outcome;
  try {
    freshBoundary();
  } catch (cause) {
    return unknown(trustedNow(), cause);
  }
  let observedReadback = null;
  let readbackCause = null;
  try {
    observedReadback = await providerReadback.readback(Object.freeze({
      command,
      fresh: true,
      independentOfDispatcher: true,
      intent: record.intent,
      providerNativeIdempotencyToken: record.intent.intentId,
      readOnly: true
    }));
  } catch (cause) {
    readbackCause = cause;
  }
  const postReadbackNow = trustedNow();
  try {
    validateAt(postReadbackNow);
  } catch (cause) {
    return unknown(postReadbackNow, readbackCause ?? cause);
  }
  try {
    if (readbackCause !== null) throw readbackCause;
    readback = validateFinalizerReadback(
      observedReadback,
      command,
      record.intent,
      acceptedRuntime.identity,
      postReadbackNow
    );
    outcome = outcomeFromFinalizerReadback(readback, command);
  } catch (cause) {
    outcome = syntheticAmbiguousOutcome(
      command,
      postReadbackNow,
      cause,
      command.providerMutationExpected
    );
  }
  try {
    freshBoundary();
  } catch (cause) {
    return unknown(trustedNow(), cause);
  }
  let terminal = null;
  let observedTerminal = null;
  let finalizeCause = null;
  try {
    observedTerminal = await globalStore.finalize(Object.freeze({
      command,
      intent: record.intent,
      outcome
    }));
  } catch (cause) {
    finalizeCause = cause;
  }
  const postFinalizeNow = trustedNow();
  if (finalizeCause === null) {
    try {
      terminal = validateTerminal(
        observedTerminal,
        command,
        record.intent,
        postFinalizeNow,
        outcome
      );
    } catch (cause) {
      finalizeCause = cause;
    }
  }
  if (terminal === null && finalizeCause !== null) {
    try {
      validateAt(postFinalizeNow);
      freshBoundary();
      const recovered = await readPhaseRecord(
        globalStore,
        approval,
        command,
        trustedNow
      );
      freshBoundary();
      if (recovered.status === "TERMINAL") terminal = recovered.terminal;
    } catch {
      terminal = null;
    }
  }
  if (terminal === null) {
    outcome = syntheticAmbiguousOutcome(
      command,
      postFinalizeNow,
      new Error("PROVIDER_BROKER_FINALIZATION_OUTCOME_UNKNOWN"),
      command.providerMutationExpected
    );
  } else {
    outcome = terminal.outcome;
  }
  const preparedRelease = command.lane === "PREPARE" &&
    outcome.status === "CONFIRMED" &&
    readback?.status === "CONFIRMED_APPLIED"
    ? readback.preparedRelease
    : null;
  return Object.freeze({
    lookup,
    preparedRelease,
    receipt: phaseReceiptFor({
      approval,
      command,
      lookup,
      outcome,
      phase: "COORDINATOR_FINALIZE",
      preparedRelease,
      runtimeIdentity: acceptedRuntime.identity,
      status: phaseStatusForOutcome(outcome),
      terminal
    })
  });
}

export async function terminalizeExpiredProviderOneShotBroker({
  approvalEnvelope,
  clock,
  environment = process.env,
  globalStore,
  now,
  reconciler,
  terminalizerRuntime,
  trustedOperatorPublicKey
}) {
  const code = "PROVIDER_BROKER_EXPIRED_TERMINALIZATION_REJECTED";
  rejectProviderEnvironment(environment);
  const trustedNow = trustedPhaseClock(clock, now,
    "PROVIDER_BROKER_TERMINALIZER_CLOCK_REJECTED");
  const initial = validateFreshTerminalizerBoundary({
    approvalEnvelope,
    now: trustedNow(),
    terminalizerRuntime,
    trustedOperatorPublicKey,
  });
  const { approval } = initial;
  const freshBoundary = () => validateFreshTerminalizerBoundary({
    approvalEnvelope,
    expectedApprovalSha256: approval.approvalSha256,
    now: trustedNow(),
    terminalizerRuntime,
    trustedOperatorPublicKey
  });
  requireCondition(globalStore &&
    typeof globalStore.readStrong === "function" &&
    typeof globalStore.terminalizeExpired === "function", code);
  const expectedCommand = commandFor(approval);
  freshBoundary();
  const record = await readPhaseRecord(
    globalStore,
    approval,
    expectedCommand,
    trustedNow
  );
  freshBoundary();
  const command = record.command;
  let terminal = record.terminal;
  let terminalizationObservedAt = null;
  if (terminal === null) {
    const mutationBoundary = freshBoundary();
    const outcome = record.status === "INTENT"
      ? syntheticAmbiguousOutcome(
        command,
        mutationBoundary.now,
        new Error("PROVIDER_BROKER_EXPIRED_AFTER_INTENT"),
        command.providerMutationExpected
      )
      : syntheticTerminalFailureOutcome(
        command,
        mutationBoundary.now,
        new Error("PROVIDER_BROKER_EXPIRED_BEFORE_INTENT")
      );
    let terminalization;
    let postTerminalizationNow;
    try {
      terminalization = await globalStore.terminalizeExpired(Object.freeze({
        approvalExpiresAt: new Date(approval.expiresAt).toISOString(),
        command,
        consumption: record.consumption,
        intent: record.intent,
        outcome
      }));
    } finally {
      postTerminalizationNow = trustedNow();
    }
    requireCondition(exactKeys(terminalization, [
      "approvalExpiresAt", "budgetReservationReleased", "clockSource",
      "effectOccupancyReleased", "observedAt", "safetyReducingOnly",
      "schemaVersion", "terminal"
    ]) && terminalization.schemaVersion === TERMINALIZATION_SCHEMA &&
      terminalization.clockSource ===
        "TRUSTED_RUNTIME_SAFETY_REDUCING_OBSERVATION" &&
      terminalization.safetyReducingOnly === true &&
      terminalization.effectOccupancyReleased === false &&
      terminalization.budgetReservationReleased === false &&
      terminalization.approvalExpiresAt ===
        new Date(approval.expiresAt).toISOString(), code);
    const observedTimestamp = parseIso(terminalization.observedAt, code);
    requireCondition(observedTimestamp >= approval.expiresAt &&
      observedTimestamp <= postTerminalizationNow + 30 * 1000, code);
    terminal = validateTerminal(
      terminalization.terminal,
      command,
      record.intent ?? record.consumption,
      Math.max(postTerminalizationNow, observedTimestamp),
      outcome
    );
    terminalizationObservedAt = terminalization.observedAt;
  }
  let reconciliation = null;
  if (terminal.outcome.status === "AMBIGUOUS") {
    try {
      freshBoundary();
      reconciliation = await reconcileFreshReadOnly(
        reconciler,
        command,
        trustedNow
      );
      freshBoundary();
    } catch (cause) {
      reconciliation = Object.freeze({
        attempted: true,
        failureCode: errorCode(cause),
        receipt: null,
        status: "UNAVAILABLE"
      });
    }
  }
  return Object.freeze({
    receipt: receiptFor({
      approval,
      command,
      outcome: terminal.outcome,
      reconciliation,
      terminal
    }),
    authorityConsumptionStatus: "PREVIOUSLY_CONSUMED",
    terminalizationObservedAt,
    dispatchStatus: "PREVIOUSLY_RECORDED",
    replayRejected: true,
    possibleMutation: terminal.outcome.possibleMutation
  });
}

export async function runProviderOneShotBroker({
  approvalEnvelope,
  dispatcher,
  environment = process.env,
  globalStore,
  now = Date.now(),
  reconciler,
  runtime,
  trustedOperatorPublicKey
}) {
  rejectProviderEnvironment(environment);
  const approval = validateProviderBrokerApproval(
    approvalEnvelope,
    trustedOperatorPublicKey,
    now
  );
  requireCondition(approval.claims.lane !== "PREPARE",
    "PROVIDER_BROKER_MONOLITHIC_PREPARE_REJECTED");
  const acceptedRuntime = validateRuntimeBase(runtime, approval, now);
  let authority;
  try {
    authority = validateRuntimeAuthority(
      runtime.authorityReceipts,
      approval,
      runtime,
      now
    );
  } catch {
    authority = null;
  }
  if (authority === null) {
    return Object.freeze({
      receipt: holdReceipt(
        approval,
        runtime,
        "PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED"
      ),
      authorityConsumptionStatus: "NOT_CONSUMED",
      dispatchStatus: "NOT_ATTEMPTED",
      replayRejected: false,
      possibleMutation: false
    });
  }
  exactCapabilities(globalStore, dispatcher);
  const command = commandFor(approval);
  let consumption;
  try {
    consumption = validateConsumption(
      await globalStore.consumeOnce(command),
      command,
      approval,
      now
    );
  } catch (cause) {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "UNKNOWN",
      cause,
      command,
      globalStore,
      intent: null,
      now,
      reconciler
    });
  }
  if (consumption.status === "REPLAY") {
    return recoverReplay({
      approval, command, consumption, globalStore, now, reconciler
    });
  }
  let intent;
  try {
    intent = validateIntent(
      await globalStore.appendIntent(Object.freeze({ command, consumption })),
      command,
      consumption
    );
  } catch (cause) {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "CONSUMED_THIS_INVOCATION",
      cause,
      command,
      globalStore,
      intent: null,
      now,
      reconciler
    });
  }
  let outcome;
  try {
    outcome = validateOutcome(
      await dispatcher.dispatch(Object.freeze({ command, intent })),
      command,
      now
    );
  } catch (cause) {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "CONSUMED_THIS_INVOCATION",
      cause,
      command,
      dispatchAttempted: true,
      globalStore,
      intent,
      now,
      reconciler
    });
  }
  if (outcome.status === "AMBIGUOUS") {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "CONSUMED_THIS_INVOCATION",
      cause: new Error("PROVIDER_BROKER_AMBIGUOUS_DISPATCH"),
      command,
      dispatchAttempted: true,
      globalStore,
      intent,
      now,
      outcome,
      reconciler
    });
  }
  let terminal;
  try {
    terminal = validateTerminal(await globalStore.finalize(Object.freeze({
      command,
      intent,
      outcome
    })), command, intent, now, outcome);
  } catch (cause) {
    return unknownAfterPossibleMutation({
      approval,
      authorityConsumptionStatus: "CONSUMED_THIS_INVOCATION",
      cause,
      command,
      dispatchAttempted: true,
      globalStore,
      intent,
      now,
      reconciler
    });
  }
  return Object.freeze({
    receipt: receiptFor({
      approval,
      command,
      outcome,
      reconciliation: null,
      terminal
    }),
    authorityConsumptionStatus: "CONSUMED_THIS_INVOCATION",
    dispatchStatus: "OUTCOME_RECEIVED",
    replayRejected: false,
    possibleMutation: outcome.possibleMutation
  });
}

function assertPrivateReceiptRoot(receiptRoot, code) {
  requireCondition(typeof receiptRoot === "string" && path.isAbsolute(receiptRoot),
    code);
  let real;
  try {
    real = fs.realpathSync(receiptRoot);
    const stat = fs.lstatSync(real);
    requireCondition(real === path.resolve(receiptRoot) && stat.isDirectory() &&
      !stat.isSymbolicLink() && stat.uid === process.getuid() &&
      (stat.mode & 0o077) === 0, code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return real;
}

export function publishProviderBrokerReceipt({
  fault = () => {},
  receipt,
  receiptRoot
}) {
  const code = "PROVIDER_BROKER_RECEIPT_PUBLICATION_REJECTED";
  requireCondition(plainObject(receipt) && receipt.schemaVersion === RECEIPT_SCHEMA &&
    HEX_64.test(receipt.receiptSha256 ?? "") && typeof fault === "function", code);
  const unsigned = { ...receipt };
  delete unsigned.receiptSha256;
  requireCondition(receipt.receiptSha256 === canonicalDigest(unsigned), code);
  const rootPath = assertPrivateReceiptRoot(receiptRoot, code);
  const lane = typeof receipt.lane === "string" ? receipt.lane.toLowerCase() :
    "hold";
  const filePath = path.join(
    rootPath,
    `${receipt.approvalId}-${lane}.json`
  );
  const bytes = brokerCanonicalBytes(receipt);
  const result = publishOrReadExactOwnedFile({
    assertRoot: () => assertPrivateReceiptRoot(rootPath, code),
    bytes,
    code,
    fault,
    filePath,
    maximumBytes: 1024 * 1024,
    mode: 0o600,
    rootPath
  });
  return Object.freeze({
    created: result.created,
    filePath,
    receiptSha256: receipt.receiptSha256
  });
}

function rejectProviderEnvironment(env) {
  const forbidden = Object.keys(env).filter((name) =>
    /^(?:ALL|HTTP|HTTPS|NO)_PROXY$/u.test(name) ||
    /^(?:DYLD_.+|LD_PRELOAD|NODE_COMPILE_CACHE|NODE_OPTIONS|NODE_PATH)$/u
      .test(name) ||
    /^AWS_(?:ACCESS_KEY_ID|CONFIG_FILE|CONTAINER_CREDENTIALS_FULL_URI|CONTAINER_CREDENTIALS_RELATIVE_URI|EC2_METADATA_SERVICE_ENDPOINT|ENDPOINT_URL(?:_.+)?|PROFILE|SECRET_ACCESS_KEY|SESSION_TOKEN|SHARED_CREDENTIALS_FILE|WEB_IDENTITY_TOKEN_FILE)$/u.test(name) ||
    /OPENAI|OPENCLAW.*OAUTH|(?:npm_config_)?(?:https?_proxy|no_proxy)/iu.test(name)
  );
  requireCondition(forbidden.length === 0,
    "PROVIDER_BROKER_RUNTIME_ENVIRONMENT_REJECTED");
}

export async function main(args = process.argv.slice(2), env = process.env) {
  rejectProviderEnvironment(env);
  requireCondition(args.length === 0,
    "PROVIDER_BROKER_DIAGNOSTIC_ARGUMENTS_REJECTED");
  process.stdout.write(
    "HOLD:PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED\n"
  );
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((cause) => {
    const code = /^PROVIDER_BROKER_[A-Z0-9_]{1,100}$/u
      .test(String(cause?.message ?? ""))
      ? cause.message
      : "PROVIDER_BROKER_UNKNOWN_HOLD";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}

export const providerBrokerConstants = Object.freeze({
  APPROVAL_CLAIMS_SCHEMA,
  APPROVAL_SCHEMA,
  APP_SOURCE,
  AUTHORITY_CONTRACTS,
  AUTHORITY_SCHEMA,
  COORDINATOR_CONTRACT,
  COMMAND_SCHEMA,
  CONSUMPTION_SCHEMA,
  CUMULATIVE_SPEND_CAP_USD,
  TEARDOWN_BUDGET_RESERVE_USD,
  FRESH_PRIMARY_RUNTIME_PRINCIPALS,
  HUMAN_AUTHORIZATION_SHA256,
  INTENT_SCHEMA,
  LANE_CONTRACTS,
  MAXIMUM_CONCURRENCY,
  MAXIMUM_RUNS,
  OPERATOR_ISSUER,
  OUTCOME_SCHEMA,
  DISPATCH_PLAN_SCHEMA,
  FINALIZER_READBACK_SCHEMA,
  PHASE_AUTHORITY_SCHEMA,
  PHASE_CONTRACTS,
  PHASE_LOOKUP_SCHEMA,
  PHASE_RECEIPT_SCHEMA,
  PHASE_RUNTIME_SCHEMA,
  RECORD_SCHEMA,
  RECEIPT_SCHEMA,
  RECONCILIATION_SCHEMA,
  REGION,
  RUNTIME_SCHEMA,
  TERMINAL_SCHEMA,
  TERMINALIZER_CONTRACT,
  TERMINALIZATION_SCHEMA
});
