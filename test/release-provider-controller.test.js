import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildExactResourceContract,
  canonicalJson,
  controllerConstants,
  evaluateProviderControllerBundle,
  fingerprintPublicKey,
  main,
  parseStrictJson,
  publishDurableDecision,
  sha256,
  verifyExactRuntimeAndSource
} from "../scripts/release-provider-controller.js";
import {
  __test as prepareTest,
  buildReleaseUploadPlan,
  validateReleaseSourceComposition
} from "../scripts/prepare-release-deployment.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE_COMMIT = "1".repeat(40);
const TREE_DIGEST = "2".repeat(40);
const CONTROL_PLANE_COMMIT = "3".repeat(40);
const CONTROL_PLANE_TREE = "4".repeat(40);
const ACCOUNT_ID = "111111111111";
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const APPROVAL_ID = "223e4567-e89b-42d3-a456-426614174001";
const LEASE_ID = "323e4567-e89b-42d3-a456-426614174002";
const EXECUTION_ATTEMPT_ID = "423e4567-e89b-42d3-a456-426614174003";
const REQUEST_ID = "523e4567-e89b-42d3-a456-426614174004";
const NOW = Date.parse("2026-08-17T20:00:00.000Z");
const AFTER_JUDGING = Date.parse("2026-09-16T00:20:00.000Z");
const ARTIFACT_BUCKET = "prooftoact-private-artifacts-111111111111";
const CHANGE_SET_ARN =
  "arn:aws:cloudformation:us-east-1:111111111111:changeSet/" +
  "prooftoact-release-123e4567/123e4567-e89b-42d3-a456-426614174000";
const CONTROLLER_INSTANCE = "github-run:1234567890:attempt:1:job:release-controller";
const CONTROLLER_HOST = "a".repeat(64);
const JOURNAL_ROOT = "b".repeat(64);

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function iso(now, offset = 0) {
  return new Date(now + offset).toISOString();
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), "utf8"));
}

function prettyDigest(value) {
  return sha256(Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8"));
}

function git(root, args) {
  return execFileSync("/usr/bin/git", args, {
    cwd: root,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin"
    },
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

function exactRepository(root, files) {
  fs.mkdirSync(root, { mode: 0o700, recursive: true });
  for (const [relativePath, bytes] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(target), { mode: 0o700, recursive: true });
    fs.writeFileSync(target, bytes, { mode: 0o600 });
  }
  git(root, ["init", "--initial-branch=main"]);
  git(root, ["remote", "add", "origin",
    "https://github.com/Flash-Bri/prooftoact.git"]);
  git(root, ["add", "--all"]);
  git(root, [
    "-c", "user.name=ProofToAct Test",
    "-c", "user.email=prooftoact-test@example.invalid",
    "commit", "--no-gpg-sign", "-m", "exact fixture"
  ]);
  return {
    commit: git(root, ["rev-parse", "HEAD"]),
    tree: git(root, ["rev-parse", "HEAD^{tree}"])
  };
}

function validatedBuild(template) {
  const artifacts = {};
  for (const [index, name] of prepareTest.ARTIFACT_NAMES.entries()) {
    const digest = String(index + 3).repeat(64);
    artifacts[name] = {
      sourceDigest: String(index + 9).slice(-1).repeat(64),
      artifactDigest: digest,
      artifactCodeSha256: Buffer.alloc(32, index + 1).toString("base64"),
      artifactBytes: 1_000 + index,
      artifactPath: `dist/aws/${name}-${digest}.zip`,
      bundledPackages: [],
      exactGitInputs: [],
      suggestedS3Key: `gate2/${SOURCE_COMMIT}/${name}-${digest}.zip`
    };
  }
  return {
    artifacts,
    gate2Template: { templateDigest: prettyDigest(template) },
    packageLockDigest: "f".repeat(64)
  };
}

const GATE2_TEMPLATE = readJson("infra/aws/gate2-template.json");
const ROLES_TEMPLATE = readJson(
  "infra/aws/release-deployment-roles-template.json"
);
const GATE2_BYTES = fs.readFileSync(path.join(ROOT, "infra/aws/gate2-template.json"));
const ROLES_BYTES = fs.readFileSync(
  path.join(ROOT, "infra/aws/release-deployment-roles-template.json")
);
const CONTRACT = buildExactResourceContract(GATE2_TEMPLATE, ROLES_TEMPLATE, {
  gate2Bytes: GATE2_BYTES,
  rolesBytes: ROLES_BYTES
});

function buildPlan() {
  const controls = {
    schemaVersion: "prooftoact.release-controls.v1",
    status: "REVIEWED_NOT_EXECUTED",
    approvalId: APPROVAL_ID,
    approvedBy: "BRIAN_SMITH",
    approvedAt: "2026-08-17T19:55:00.000Z",
    expiresAt: "2026-08-17T20:25:00.000Z",
    oneShot: true,
    artifactBucket: ARTIFACT_BUCKET,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    rolesTemplateSha256: prettyDigest(ROLES_TEMPLATE),
    resourceInventorySha256: CONTRACT.resourceInventorySha256,
    forecastStatus: "AVAILABLE",
    maximumApprovedUsd: 12,
    projectedTotalUsd: 1.25,
    partialFailureDisposition:
      "HOLD_RECONCILE_OR_TEARDOWN_NO_BLIND_RETRY",
    teardown: {
      deleteExactStack: "prooftoact-gate2",
      expectedResourceInventorySha256: CONTRACT.resourceInventorySha256,
      judgingAccessThrough: "2026-09-15T23:59:00.000Z",
      teardownDeadline: "2026-09-16T00:30:00.000Z",
      residualCensusRequired: true
    }
  };
  const applicationIdentity = prepareTest.boundIdentity({
    sourceCommit: SOURCE_COMMIT,
    templateSha256: prettyDigest(GATE2_TEMPLATE),
    treeDigest: TREE_DIGEST
  });
  const controlPlaneIdentity = prepareTest.boundIdentity({
    controllerSha256: sha256(fs.readFileSync(path.join(
      ROOT,
      prepareTest.CONTROL_PLANE_CONTROLLER_PATH
    ))),
    preparerSha256: sha256(fs.readFileSync(path.join(
      ROOT,
      prepareTest.CONTROL_PLANE_PREPARER_PATH
    ))),
    rolesTemplateSha256: prettyDigest(ROLES_TEMPLATE),
    sourceCommit: CONTROL_PLANE_COMMIT,
    treeDigest: CONTROL_PLANE_TREE
  });
  return buildReleaseUploadPlan({
    applicationIdentity,
    artifactBucket: ARTIFACT_BUCKET,
    controlPlaneIdentity,
    controlsNow: NOW,
    deploymentRolesTemplate: ROLES_TEMPLATE,
    releaseControls: controls,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    validatedBuild: validatedBuild(GATE2_TEMPLATE),
    gate2Template: GATE2_TEMPLATE
  });
}

const PLAN = buildPlan();

function keyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  return Object.freeze({
    privateKey,
    publicKey: publicKey.export({ format: "pem", type: "spki" })
  });
}

const KEYS = Object.freeze({
  CONTROLLER_STORE: keyPair(),
  OPERATOR: keyPair(),
  PROVIDER: keyPair()
});
const TRUSTED_KEYS = Object.freeze(Object.fromEntries(
  Object.entries(KEYS).map(([issuer, pair]) => [issuer, pair.publicKey])
));
const TRUST_FINGERPRINTS = Object.freeze(Object.fromEntries(
  Object.entries(TRUSTED_KEYS).map(([issuer, publicKey]) => [
    issuer,
    fingerprintPublicKey(publicKey)
  ])
));

function signReceipt(kind, issuer, claims, now) {
  const receipt = {
    schemaVersion: controllerConstants.RECEIPT_SCHEMA,
    kind,
    issuer,
    keyFingerprint: TRUST_FINGERPRINTS[issuer],
    nonce: REQUEST_ID,
    issuedAt: iso(now, -30_000),
    expiresAt: iso(now, 5 * 60_000),
    claims
  };
  const signature = crypto.sign("sha256", canonicalBytes(receipt), {
    key: KEYS[issuer].privateKey,
    dsaEncoding: "ieee-p1363"
  });
  return { ...receipt, signature: signature.toString("base64") };
}

function common(stage) {
  return {
    operationId: OPERATION_ID,
    controllerInstanceId: CONTROLLER_INSTANCE,
    controllerHostIdSha256: CONTROLLER_HOST,
    journalRootSha256: JOURNAL_ROOT,
    planSha256: PLAN.planSha256,
    sourceCommit: SOURCE_COMMIT,
    treeDigest: TREE_DIGEST,
    stage
  };
}

function stageRole(stage) {
  const contract = controllerConstants.STAGE_CONTRACT[stage];
  return {
    ...contract,
    roleArn: `arn:aws:iam::${ACCOUNT_ID}:role/${contract.roleName}`
  };
}

function artifactReadback(stage, now) {
  const artifacts = PLAN.uploads.map((upload, index) => {
    const value = {
      name: upload.name,
      bucket: upload.s3Bucket,
      key: upload.s3Key,
      versionId: `version-${index + 1}`,
      etag: `"etag-${index + 1}"`,
      contentLength: upload.bytes,
      sha256: upload.sha256,
      codeSha256: upload.codeSha256,
      sourceSha256: upload.sourceSha256
    };
    const identity = {
      bucket: value.bucket,
      codeSha256: value.codeSha256,
      contentLength: value.contentLength,
      etag: value.etag,
      key: value.key,
      name: value.name,
      sha256: value.sha256,
      sourceSha256: value.sourceSha256,
      versionId: value.versionId
    };
    return {
      ...value,
      immutable: true,
      versioningStatus: "Enabled",
      providerRequestId: REQUEST_ID,
      objectIdentitySha256: sha256(canonicalBytes(identity)),
      readbackSha256: upload.sha256
    };
  });
  return {
    ...common(stage),
    observedAt: iso(now, -20_000),
    artifacts
  };
}

function parameterManifest(artifacts) {
  const known = {
    ArtifactBucket: PLAN.uploads[0].s3Bucket,
    EnableProbeFunctions: "false",
    PackageLockDigest: PLAN.build.packageLockSha256,
    SourceCommit: SOURCE_COMMIT,
    TreeDigest: TREE_DIGEST
  };
  for (const artifact of artifacts) {
    const prefix = artifact.name[0].toUpperCase() + artifact.name.slice(1);
    known[`${prefix}ArtifactCodeSha256`] = artifact.codeSha256;
    known[`${prefix}ArtifactDigest`] = artifact.sha256;
    known[`${prefix}ArtifactKey`] = artifact.key;
    known[`${prefix}ArtifactVersion`] = artifact.versionId;
    known[`${prefix}SourceDigest`] = artifact.sourceSha256;
  }
  return Object.keys(GATE2_TEMPLATE.Parameters).sort().map((name) => ({
    name,
    sensitivity: name.includes("Secret")
      ? "SECRET_REFERENCE"
      : name.includes("Host") || name.includes("Arn")
        ? "PRIVATE_IDENTIFIER"
        : "PUBLIC",
    valueSha256: sha256(Buffer.from(known[name] ?? `fixture:${name}`, "utf8"))
  }));
}

function approvalClaims(stage, manifest) {
  return {
    ...common(stage),
    action: stageRole(stage).action,
    approvalId: APPROVAL_ID,
    approvedBy: "BRIAN_SMITH",
    oneShot: true,
    maximumApprovedUsd: 12,
    providerAccountId: ACCOUNT_ID,
    changeSetArn: CHANGE_SET_ARN,
    parameterManifestSha256: sha256(canonicalBytes(manifest)),
    resourceContractSha256: CONTRACT.contractSha256,
    storeNamespaceArn:
      `arn:aws:dynamodb:us-east-1:${ACCOUNT_ID}:table/` +
      "prooftoact-release-controller",
    trustFingerprints: TRUST_FINGERPRINTS,
    controllerKeySha256: "c".repeat(64),
    runtime: {
      controlPlaneCommit: PLAN.controlPlane.sourceCommit,
      controlPlaneIdentitySha256: PLAN.controlPlane.identitySha256,
      controlPlaneTreeDigest: PLAN.controlPlane.treeDigest,
      controllerSha256: PLAN.controlPlane.controllerSha256,
      gitPath: "/usr/bin/git",
      gitSha256: "e".repeat(64),
      nodePath: process.execPath,
      nodeSha256: "f".repeat(64)
    }
  };
}

function storeReservation(stage, approval, now) {
  return {
    ...common(stage),
    action: stageRole(stage).action,
    approvalId: approval.approvalId,
    namespaceArn: approval.storeNamespaceArn,
    globallyAuthoritative: true,
    stronglyConsistentRead: true,
    conditionalWrite: true,
    oneShot: true,
    leaseId: LEASE_ID,
    state: stageRole(stage).storeState,
    storageStatus: "AVAILABLE",
    replayCount: 0,
    previousVersion: 7,
    reservationVersion: 8,
    leaseExpiresAt: iso(now, 4 * 60_000)
  };
}

function storeJournal(stage, reservation) {
  const event = {
    action: stageRole(stage).action,
    eventType: stageRole(stage).journalEvent,
    leaseId: reservation.leaseId,
    operationId: OPERATION_ID,
    reservationVersion: reservation.reservationVersion,
    state: reservation.state
  };
  const base = {
    event,
    namespaceArn: reservation.namespaceArn,
    previousEntrySha256: sha256(canonicalBytes(reservation)),
    sequence: reservation.reservationVersion + 1
  };
  return {
    ...common(stage),
    appendOnly: true,
    conditionalWrite: true,
    durable: true,
    fsyncStatus: "DURABLE",
    storageStatus: "AVAILABLE",
    ...base,
    entrySha256: sha256(canonicalBytes(base))
  };
}

function providerIdentity(stage, now, approval) {
  const role = stageRole(stage);
  return {
    ...common(stage),
    accountId: ACCOUNT_ID,
    authenticated: true,
    evidenceMethod: "AWS_STS_GET_CALLER_ID_LIVE",
    partition: "aws",
    region: "us-east-1",
    repository: "Flash-Bri/prooftoact",
    ref: "refs/heads/main",
    environment: role.environment,
    workflow: role.workflow,
    roleArn: role.roleArn,
    principalArn:
      `arn:aws:sts::${ACCOUNT_ID}:assumed-role/${role.roleName}/release-proof`,
    sourceIdentity: CONTROLLER_INSTANCE,
    providerRequestId: REQUEST_ID,
    providerTimestamp: iso(now, -15_000),
    sessionExpiresAt: iso(now, 20 * 60_000)
  };
}

function costCensus(stage, now, approval) {
  return {
    ...common(stage),
    asOf: iso(now, -10_000),
    dataStatus: "AVAILABLE",
    currentResourceCensusStatus: "COMPLETE",
    currentSpendUsd: 0.25,
    forecastTotalUsd: 1,
    maximumApprovedUsd: approval.maximumApprovedUsd,
    unknownCostCount: 0,
    undeclaredResourceCount: 0,
    resourceInventorySha256: CONTRACT.resourceInventorySha256,
    providerRequestId: REQUEST_ID,
    caps: {
      apiRequests: 50,
      artifactBytes: PLAN.uploads.reduce((sum, item) => sum + item.bytes, 0),
      lambdaInvocations: 10,
      logBytes: 1024 * 1024,
      maximumLambdaConcurrency: 8
    },
    forecastLineItems: [
      { name: "bounded-release", units: 1, unitCostUsd: 1, forecastUsd: 1 }
    ]
  };
}

function authoritySeparation(stage, now) {
  const principals = {};
  const lanes = Object.keys(controllerConstants.LANE_ROLE_NAMES);
  for (const lane of lanes) {
    principals[lane] = {
      allowedLane: lane,
      arn: `arn:aws:iam::${ACCOUNT_ID}:role/` +
        controllerConstants.LANE_ROLE_NAMES[lane],
      deniedLanes: lanes.filter((candidate) => candidate !== lane).sort(),
      policySha256: lane === "coordinator"
        ? CONTRACT.releaseCoordinatorRole.inlinePolicySha256
        : sha256(Buffer.from(`policy:${lane}`, "utf8")),
      readOnly: lane === "evidence"
    };
  }
  return {
    ...common(stage),
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    principals
  };
}

function iamSimulation(stage, now, approval) {
  const service = CONTRACT.cloudFormationServiceRole;
  return {
    ...common(stage),
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    allPoliciesReadBack: true,
    rolesTemplateSha256: controllerConstants.REVIEWED_ROLES_TEMPLATE_SHA256,
    boundaryPolicySha256:
      CONTRACT.cloudFormationServiceRole.permissionsBoundaryPolicySha256,
    cloudFormationServiceRole: {
      arn:
        `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActGate2CloudFormation`,
      roleId: "ABCDEFGHIJKLMNOPQRST",
      roleName: service.roleName,
      maxSessionDuration: service.maxSessionDuration,
      trustSha256: service.trustSha256,
      inlinePolicySha256: service.inlinePolicySha256,
      tagsSha256: service.tagsSha256,
      permissionsBoundaryArn:
        `arn:aws:iam::${ACCOUNT_ID}:policy/` +
        "ProofToActGate2CloudFormationBoundary",
      permissionsBoundaryPolicySha256:
        service.permissionsBoundaryPolicySha256
    },
    allowChecks: controllerConstants.IAM_ALLOW_CHECKS.map((name) => ({
      name,
      decision: "allowed",
      resourceSha256: sha256(Buffer.from(`allow:${name}`, "utf8"))
    })),
    denyChecks: controllerConstants.IAM_DENY_CHECKS.map((name) => ({
      name,
      decision: "explicitDeny",
      resourceSha256: sha256(Buffer.from(`deny:${name}`, "utf8"))
    }))
  };
}

function resourceContractReceipt(stage, now) {
  return {
    ...common(stage),
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    templateSha256: controllerConstants.REVIEWED_GATE2_TEMPLATE_SHA256,
    rolesTemplateSha256: controllerConstants.REVIEWED_ROLES_TEMPLATE_SHA256,
    resourceContractSha256: CONTRACT.contractSha256,
    resourceInventorySha256: CONTRACT.resourceInventorySha256,
    activeResourceCount: CONTRACT.resources.length,
    undeclaredResourceCount: 0,
    natGatewayCount: 0,
    ec2ResourceCount: 0,
    alwaysOnResourceCount: 0,
    probeResourcesEnabled: false,
    apiRoutesSha256: sha256(canonicalBytes(CONTRACT.routes)),
    lambdaPostureSha256: sha256(canonicalBytes(CONTRACT.lambdas)),
    logAndAlarmPostureSha256: sha256(canonicalBytes({
      alarms: CONTRACT.alarms,
      logGroups: CONTRACT.logGroups
    })),
    kmsPostureSha256: sha256(canonicalBytes(CONTRACT.kms))
  };
}

function stackAbsence(stage, now) {
  return {
    ...common(stage),
    absent: true,
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    region: "us-east-1",
    stackName: "prooftoact-gate2"
  };
}

function changeSet(stage, now, approval, artifactClaims, manifest) {
  const changes = CONTRACT.resources.map(({ logicalId, type }) => ({
    action: "Add",
    logicalId,
    replacement: "False",
    resourceType: type
  }));
  return {
    ...common(stage),
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    changeSetArn: approval.changeSetArn,
    changeSetName: "prooftoact-release-123e4567",
    changeSetType: "CREATE",
    stackName: "prooftoact-gate2",
    status: "CREATE_COMPLETE",
    executionStatus: "AVAILABLE",
    includeNestedStacks: false,
    capabilities: ["CAPABILITY_NAMED_IAM"],
    templateSha256: controllerConstants.REVIEWED_GATE2_TEMPLATE_SHA256,
    resourceContractSha256: CONTRACT.contractSha256,
    parameterManifest: manifest,
    parameterManifestSha256: sha256(canonicalBytes(manifest)),
    roleArn:
      `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActGate2CloudFormation`,
    changes,
    changesSha256: sha256(canonicalBytes(changes))
  };
}

function executionTransition(stage) {
  const namespaceArn =
    `arn:aws:dynamodb:us-east-1:${ACCOUNT_ID}:table/` +
    "prooftoact-release-controller";
  const before = {
    event: {
      action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
      eventType: "BEFORE_EXECUTE_CHANGE_SET",
      executionAttemptId: EXECUTION_ATTEMPT_ID,
      operationId: OPERATION_ID
    },
    previousEntrySha256: "3".repeat(64),
    providerRequestId: REQUEST_ID,
    sequence: 20
  };
  before.entrySha256 = sha256(canonicalBytes({
    event: before.event,
    namespaceArn,
    previousEntrySha256: before.previousEntrySha256,
    sequence: before.sequence
  }));
  const after = {
    event: {
      action: "EXECUTE_EXACT_CREATE_CHANGE_SET",
      eventType: "AFTER_EXECUTE_CHANGE_SET_DISPATCH",
      executionAttemptId: EXECUTION_ATTEMPT_ID,
      operationId: OPERATION_ID
    },
    previousEntrySha256: before.entrySha256,
    providerRequestId: REQUEST_ID,
    sequence: 21
  };
  after.entrySha256 = sha256(canonicalBytes({
    event: after.event,
    namespaceArn,
    previousEntrySha256: after.previousEntrySha256,
    sequence: after.sequence
  }));
  return {
    ...common(stage),
    namespaceArn,
    changeSetArn: CHANGE_SET_ARN,
    executionAttemptId: EXECUTION_ATTEMPT_ID,
    appendOnly: true,
    durable: true,
    storageStatus: "AVAILABLE",
    before,
    after
  };
}

function executionResult(stage, now, outcome = "CONFIRMED_CREATE_COMPLETE") {
  const service = CONTRACT.cloudFormationServiceRole;
  return {
    ...common(stage),
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    changeSetArn: CHANGE_SET_ARN,
    stackName: "prooftoact-gate2",
    stackStatus: outcome === "CONFIRMED_CREATE_COMPLETE"
      ? "CREATE_COMPLETE"
      : outcome === "AMBIGUOUS" ? "UNKNOWN" : "ROLLBACK_COMPLETE",
    terminationProtection: outcome === "CONFIRMED_CREATE_COMPLETE",
    executionOutcome: outcome,
    readOnlyReconciliation: true,
    resourceContractSha256: CONTRACT.contractSha256,
    cloudFormationServiceRole: {
      arn:
        `arn:aws:iam::${ACCOUNT_ID}:role/ProofToActGate2CloudFormation`,
      roleId: "ABCDEFGHIJKLMNOPQRST",
      trustSha256: service.trustSha256,
      inlinePolicySha256: service.inlinePolicySha256,
      permissionsBoundaryPolicySha256: "2".repeat(64)
    }
  };
}

function keepAlive(stage, now) {
  return {
    ...common(stage),
    judgeAccessThrough: "2026-09-15T23:59:00.000Z",
    observedAt: iso(now, -10_000),
    providerRequestId: REQUEST_ID,
    resourceInventorySha256: CONTRACT.resourceInventorySha256
  };
}

function residualCensus(stage, now, mismatch = false) {
  return {
    ...common(stage),
    censuses: [0, 16 * 60_000].map((offset, index) => ({
      asOf: iso(now, -17 * 60_000 + offset),
      costStatus: "AVAILABLE",
      kmsPendingDeletionCount: 1,
      providerRequestId: index === 0
        ? REQUEST_ID
        : "623e4567-e89b-42d3-a456-426614174005",
      residualResourceCount: mismatch && index === 1 ? 1 : 0
    }))
  };
}

function receipt(kind, issuer, claims, now) {
  return signReceipt(kind, issuer, claims, now);
}

function fixture(stage, {
  executionOutcome = "CONFIRMED_CREATE_COMPLETE",
  now = NOW,
  residualMismatch = false
} = {}) {
  const artifacts = artifactReadback(stage, now);
  const manifest = parameterManifest(artifacts.artifacts);
  const approval = approvalClaims(stage, manifest);
  const reservation = storeReservation(stage, approval, now);
  const claims = {
    OPERATOR_APPROVAL: ["OPERATOR", approval],
    STORE_RESERVATION: ["CONTROLLER_STORE", reservation],
    STORE_JOURNAL: ["CONTROLLER_STORE", storeJournal(stage, reservation)],
    PROVIDER_IDENTITY: ["PROVIDER", providerIdentity(stage, now, approval)],
    COST_CENSUS: ["PROVIDER", costCensus(stage, now, approval)],
    AUTHORITY_SEPARATION: ["PROVIDER", authoritySeparation(stage, now)],
    IAM_SIMULATION: ["PROVIDER", iamSimulation(stage, now, approval)],
    RESOURCE_CONTRACT: ["PROVIDER", resourceContractReceipt(stage, now)]
  };
  if (stage === "EXECUTE") {
    claims.STACK_ABSENCE = ["PROVIDER", stackAbsence(stage, now)];
  }
  if (["EXECUTE", "RECONCILE"].includes(stage)) {
    claims.ARTIFACT_READBACK = ["PROVIDER", artifacts];
    claims.CHANGE_SET = [
      "PROVIDER",
      changeSet(stage, now, approval, artifacts, manifest)
    ];
  }
  if (["RECONCILE", "LIVE", "EVIDENCE", "TEARDOWN", "RESIDUAL"]
    .includes(stage)) {
    claims.EXECUTION_RESULT = [
      "PROVIDER",
      executionResult(stage, now, executionOutcome)
    ];
    claims.EXECUTION_TRANSITION = [
      "CONTROLLER_STORE",
      executionTransition(stage)
    ];
  }
  if (["TEARDOWN", "RESIDUAL"].includes(stage)) {
    claims.KEEP_ALIVE_STATE = ["PROVIDER", keepAlive(stage, now)];
  }
  if (stage === "RESIDUAL") {
    claims.RESIDUAL_CENSUS = [
      "PROVIDER",
      residualCensus(stage, now, residualMismatch)
    ];
  }
  const receipts = Object.entries(claims).map(([kind, [issuer, value]]) =>
    receipt(kind, issuer, value, now));
  const bundle = {
    schemaVersion: controllerConstants.BUNDLE_SCHEMA,
    stage,
    operationId: OPERATION_ID,
    controllerInstanceId: CONTROLLER_INSTANCE,
    controllerHostIdSha256: CONTROLLER_HOST,
    journalRootSha256: JOURNAL_ROOT,
    requestedAt: iso(now, -10_000),
    plan: PLAN,
    receipts
  };
  return {
    bundle,
    gate2Template: GATE2_TEMPLATE,
    gate2Bytes: GATE2_BYTES,
    rolesTemplate: ROLES_TEMPLATE,
    rolesBytes: ROLES_BYTES,
    trustedPublicKeys: TRUSTED_KEYS,
    runtime: {
      controllerInstanceId: CONTROLLER_INSTANCE,
      controllerHostIdSha256: CONTROLLER_HOST,
      journalRootSha256: JOURNAL_ROOT
    },
    now
  };
}

function replaceReceipt(input, kind, mutate) {
  const index = input.bundle.receipts.findIndex((item) => item.kind === kind);
  assert.notEqual(index, -1);
  const current = input.bundle.receipts[index];
  const claims = structuredClone(current.claims);
  mutate(claims);
  input.bundle.receipts[index] = signReceipt(
    kind,
    current.issuer,
    claims,
    input.now
  );
}

test("exact resource contract and strict JSON bind the reviewed bytes", () => {
  assert.equal(
    CONTRACT.templateSha256,
    controllerConstants.REVIEWED_GATE2_TEMPLATE_SHA256
  );
  assert.equal(
    CONTRACT.rolesTemplateSha256,
    controllerConstants.REVIEWED_ROLES_TEMPLATE_SHA256
  );
  assert.equal(
    CONTRACT.releaseControlPlane.controlTable.name,
    "prooftoact-release-controller"
  );
  assert.equal(
    CONTRACT.releaseControlPlane.controlTable.retainedOutsideApplicationTeardown,
    true
  );
  assert.equal(
    CONTRACT.releaseControlPlane.independentEvidenceRoleLogicalId,
    "ReleaseEvidenceRole"
  );
  assert.equal(
    CONTRACT.releaseControlPlane.evidenceOperatorParameterMustReference,
    "LiveDrillOperatorRoleArn"
  );
  assert.equal(
    CONTRACT.releaseCoordinatorRole.roleName,
    "ProofToActReleaseCoordinator"
  );
  assert.equal(CONTRACT.releaseCoordinatorRole.inlinePolicyBytes <= 10_240,
    true);
  assert.deepEqual(CONTRACT.releaseCoordinatorRole.allowedWorkflows, [
    "ProofToAct Release Candidate",
    "ProofToAct Execute Approved Release",
    "ProofToAct Bounded Live Drill",
    "ProofToAct Read Only Release Evidence",
    "ProofToAct Approved Teardown"
  ]);
  assert.equal(
    CONTRACT.releaseCoordinatorRole.requiredRuntimeWorkflowRefs,
    "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-sealed-coordinator.yml@" +
      "50d0cd261b8597fe74c80b84c49be0adde5bdf6f"
  );
  assert.equal(
    controllerConstants.LANE_ROLE_NAMES.evidence,
    "ProofToActReleaseEvidence"
  );
  assert.throws(
    () => parseStrictJson('{"a":1,"a":2}'),
    /CONTROLLER_JSON_DUPLICATE_MEMBER_REJECTED/u
  );
});

test("valid EXECUTE evidence remains HOLD without exact broker runtime authority", () => {
  const result = evaluateProviderControllerBundle(fixture("EXECUTE"));
  assert.equal(result.status, "HOLD");
  assert.equal(
    result.reason,
    "PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED"
  );
  assert.equal(result.retryAllowed, false);
  assert.equal(result.evidence.brokerContractImplemented, true);
  assert.equal(result.evidence.providerExecutionEnabled, false);
  assert.equal(result.evidence.localJsonIsProviderProof, false);
});

test("post-CREATE reconciliation no longer demands a contradictory absent stack", () => {
  const input = fixture("RECONCILE");
  assert.equal(
    input.bundle.receipts.some(({ kind }) => kind === "STACK_ABSENCE"),
    false
  );
  const result = evaluateProviderControllerBundle(input);
  assert.equal(result.status, "GO_CONFIRMED");
  assert.equal(result.retryAllowed, false);
});

test("replay from a different directory or host cannot inherit authority", () => {
  const input = fixture("EXECUTE");
  input.runtime.journalRootSha256 = "0".repeat(64);
  assert.throws(
    () => evaluateProviderControllerBundle(input),
    /CONTROLLER_BUNDLE_REJECTED/u
  );

  const host = fixture("EXECUTE");
  host.runtime.controllerHostIdSha256 = "0".repeat(64);
  assert.throws(
    () => evaluateProviderControllerBundle(host),
    /CONTROLLER_BUNDLE_REJECTED/u
  );
});

test("forged and stale authenticated receipts fail closed", () => {
  const forged = fixture("EXECUTE");
  forged.bundle.receipts[0].claims.maximumApprovedUsd = 11;
  assert.throws(
    () => evaluateProviderControllerBundle(forged),
    /CONTROLLER_AUTHENTICATED_RECEIPT_REJECTED/u
  );

  const stale = fixture("EXECUTE");
  stale.bundle.receipts[0].issuedAt = iso(NOW, -31 * 60_000);
  stale.bundle.receipts[0].expiresAt = iso(NOW, 60_000);
  const unsigned = { ...stale.bundle.receipts[0] };
  delete unsigned.signature;
  stale.bundle.receipts[0].signature = crypto.sign(
    "sha256",
    canonicalBytes(unsigned),
    { key: KEYS.OPERATOR.privateKey, dsaEncoding: "ieee-p1363" }
  ).toString("base64");
  assert.throws(
    () => evaluateProviderControllerBundle(stale),
    /CONTROLLER_AUTHENTICATED_RECEIPT_REJECTED/u
  );
});

test("UPDATE change sets and artifact VersionId drift are rejected", () => {
  const update = fixture("EXECUTE");
  replaceReceipt(update, "CHANGE_SET", (claims) => {
    claims.changeSetType = "UPDATE";
  });
  assert.throws(
    () => evaluateProviderControllerBundle(update),
    /CONTROLLER_CHANGE_SET_REJECTED/u
  );

  const drift = fixture("EXECUTE");
  replaceReceipt(drift, "ARTIFACT_READBACK", (claims) => {
    claims.artifacts[0].versionId = "different-version";
    const artifact = claims.artifacts[0];
    artifact.objectIdentitySha256 = sha256(canonicalBytes({
      bucket: artifact.bucket,
      codeSha256: artifact.codeSha256,
      contentLength: artifact.contentLength,
      etag: artifact.etag,
      key: artifact.key,
      name: artifact.name,
      sha256: artifact.sha256,
      sourceSha256: artifact.sourceSha256,
      versionId: artifact.versionId
    }));
  });
  assert.throws(
    () => evaluateProviderControllerBundle(drift),
    /CONTROLLER_PARAMETER_MANIFEST_REJECTED/u
  );
});

test("IAM breadth, missing denies, and authority role crossing are rejected", () => {
  const iam = fixture("EXECUTE");
  replaceReceipt(iam, "IAM_SIMULATION", (claims) => {
    claims.denyChecks = claims.denyChecks.filter((item) =>
      item.name !== "EXECUTOR_DIRECT_INVOKE");
  });
  assert.throws(
    () => evaluateProviderControllerBundle(iam),
    /CONTROLLER_IAM_SIMULATION_REJECTED/u
  );

  const substitutedBoundary = fixture("EXECUTE");
  replaceReceipt(substitutedBoundary, "IAM_SIMULATION", (claims) => {
    const substitutedPolicySha256 = "0".repeat(64);
    claims.boundaryPolicySha256 = substitutedPolicySha256;
    claims.cloudFormationServiceRole.permissionsBoundaryPolicySha256 =
      substitutedPolicySha256;
  });
  assert.throws(
    () => evaluateProviderControllerBundle(substitutedBoundary),
    /CONTROLLER_IAM_SIMULATION_REJECTED/u
  );

  const crossing = fixture("EXECUTE");
  replaceReceipt(crossing, "AUTHORITY_SEPARATION", (claims) => {
    claims.principals.executor.arn = claims.principals.preparer.arn;
  });
  assert.throws(
    () => evaluateProviderControllerBundle(crossing),
    /CONTROLLER_AUTHORITY_SEPARATION_REJECTED/u
  );

  const coordinatorPolicySubstitution = fixture("EXECUTE");
  replaceReceipt(
    coordinatorPolicySubstitution,
    "AUTHORITY_SEPARATION",
    (claims) => {
      claims.principals.coordinator.policySha256 = "0".repeat(64);
    }
  );
  assert.throws(
    () => evaluateProviderControllerBundle(coordinatorPolicySubstitution),
    /CONTROLLER_AUTHORITY_SEPARATION_REJECTED/u
  );
});

test("missing, uncertain, stale, or over-cap cost evidence is rejected", () => {
  for (const mutate of [
    (claims) => { claims.dataStatus = "UNAVAILABLE"; },
    (claims) => { claims.unknownCostCount = 1; },
    (claims) => { claims.forecastTotalUsd = 12; },
    (claims) => { claims.currentResourceCensusStatus = "PARTIAL"; }
  ]) {
    const input = fixture("EXECUTE");
    replaceReceipt(input, "COST_CENSUS", mutate);
    assert.throws(
      () => evaluateProviderControllerBundle(input),
      /CONTROLLER_COST_CENSUS_REJECTED/u
    );
  }
});

test("ambiguous execution stays UNKNOWN_DO_NOT_RETRY until exact reconciliation", () => {
  const ambiguous = fixture("RECONCILE", { executionOutcome: "AMBIGUOUS" });
  const held = evaluateProviderControllerBundle(ambiguous);
  assert.equal(held.status, "HOLD");
  assert.equal(held.reason, "UNKNOWN_DO_NOT_RETRY");

  const exact = evaluateProviderControllerBundle(fixture("RECONCILE"));
  assert.equal(exact.status, "GO_CONFIRMED");
});

test("missing or broken after-execution journal chain fails closed", () => {
  const missing = fixture("RECONCILE");
  missing.bundle.receipts = missing.bundle.receipts.filter((receipt) =>
    receipt.kind !== "EXECUTION_TRANSITION");
  assert.throws(
    () => evaluateProviderControllerBundle(missing),
    /CONTROLLER_RECEIPT_SET_REJECTED/u
  );

  const broken = fixture("RECONCILE");
  replaceReceipt(broken, "EXECUTION_TRANSITION", (claims) => {
    claims.after.previousEntrySha256 = "0".repeat(64);
  });
  assert.throws(
    () => evaluateProviderControllerBundle(broken),
    /CONTROLLER_EXECUTION_TRANSITION_JOURNAL_REJECTED/u
  );
});

test("controller-store journal rejects unavailable storage and chain gaps", () => {
  for (const mutate of [
    (claims) => { claims.storageStatus = "ENOSPC"; },
    (claims) => { claims.fsyncStatus = "FAILED"; },
    (claims) => { claims.sequence += 1; },
    (claims) => { claims.previousEntrySha256 = "0".repeat(64); }
  ]) {
    const input = fixture("EXECUTE");
    replaceReceipt(input, "STORE_JOURNAL", (claims) => {
      mutate(claims);
      claims.entrySha256 = sha256(canonicalBytes({
        event: claims.event,
        namespaceArn: claims.namespaceArn,
        previousEntrySha256: claims.previousEntrySha256,
        sequence: claims.sequence
      }));
    });
    assert.throws(
      () => evaluateProviderControllerBundle(input),
      /CONTROLLER_DURABLE_JOURNAL_REJECTED/u
    );
  }
});

test("live drill and teardown remain separate broker-gated authorities", () => {
  const live = evaluateProviderControllerBundle(fixture("LIVE"));
  assert.equal(live.status, "HOLD");
  assert.equal(
    live.reason,
    "PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED"
  );

  const teardown = evaluateProviderControllerBundle(fixture("TEARDOWN", {
    now: AFTER_JUDGING
  }));
  assert.equal(teardown.status, "HOLD");
  assert.equal(
    teardown.reason,
    "PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED"
  );

  const crossed = fixture("TEARDOWN", { now: AFTER_JUDGING });
  replaceReceipt(crossed, "OPERATOR_APPROVAL", (claims) => {
    claims.action = "EXECUTE_EXACT_CREATE_CHANGE_SET";
  });
  assert.throws(
    () => evaluateProviderControllerBundle(crossed),
    /CONTROLLER_OPERATOR_APPROVAL_REJECTED/u
  );
});

test("residual reconciliation requires two clean provider censuses", () => {
  const complete = evaluateProviderControllerBundle(fixture("RESIDUAL", {
    now: AFTER_JUDGING
  }));
  assert.equal(complete.status, "GO_CONFIRMED");

  const mismatch = fixture("RESIDUAL", {
    now: AFTER_JUDGING,
    residualMismatch: true
  });
  assert.throws(
    () => evaluateProviderControllerBundle(mismatch),
    /CONTROLLER_TEARDOWN_CONTRACT_REJECTED/u
  );
});

test("decision publication is non-overwriting, convergent, and ENOSPC-safe", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "pta-controller-"));
  fs.chmodSync(directory, 0o700);
  const decision = evaluateProviderControllerBundle(fixture("EXECUTE"));
  try {
    assert.throws(
      () => publishDurableDecision({
        decision,
        journalRoot: directory,
        fault(stage) {
          if (stage === "after-write") {
            const error = new Error("disk full");
            error.code = "ENOSPC";
            throw error;
          }
        }
      }),
      /CONTROLLER_LOCAL_JOURNAL_REJECTED/u
    );
    assert.equal(
      fs.readdirSync(directory).some((name) => !name.startsWith(".")),
      false
    );

    assert.throws(
      () => publishDurableDecision({
        decision,
        journalRoot: directory,
        fault(stage) {
          if (stage === "after-link") throw new Error("simulated crash");
        }
      }),
      /CONTROLLER_LOCAL_JOURNAL_REJECTED/u
    );
    const recovered = publishDurableDecision({ decision, journalRoot: directory });
    assert.equal(recovered.created, false);

    const conflicting = {
      ...decision,
      evidence: { ...decision.evidence, localJsonIsProviderProof: true }
    };
    const withoutDigest = { ...conflicting };
    delete withoutDigest.decisionSha256;
    conflicting.decisionSha256 = sha256(canonicalBytes(withoutDigest));
    assert.throws(
      () => publishDurableDecision({
        decision: conflicting,
        journalRoot: directory
      }),
      /CONTROLLER_LOCAL_JOURNAL_REJECTED/u
    );
  } finally {
    fs.rmSync(directory, { force: true, recursive: true });
  }
});

test("test-only capability and provider environment fail before argument handling", async () => {
  await assert.rejects(
    main([], { NODE_TEST_CONTEXT: "child-v8" }),
    /CONTROLLER_TEST_CAPABILITY_REJECTED/u
  );
  await assert.rejects(
    main([], { AWS_ACCESS_KEY_ID: "not-used" }),
    /CONTROLLER_TEST_CAPABILITY_REJECTED/u
  );
  await assert.rejects(
    main([
      "--application-root", "/tmp/frozen-application",
      "--bundle", path.join(os.tmpdir(), `missing-${crypto.randomUUID()}.json`),
      "--control-plane-root", "/tmp/control-plane",
      "--controller-instance", CONTROLLER_INSTANCE,
      "--controller-key-fd", "10",
      "--expected-application-commit", SOURCE_COMMIT,
      "--expected-application-tree", TREE_DIGEST,
      "--expected-control-plane-commit", CONTROL_PLANE_COMMIT,
      "--expected-control-plane-tree", CONTROL_PLANE_TREE,
      "--host-id-fd", "11",
      "--journal-root", "/tmp/journal",
      "--operator-key-fd", "12",
      "--provider-key-fd", "13",
      "--store-key-fd", "14"
    ], {}),
    /CONTROLLER_BUNDLE_FILE_REJECTED/u
  );
  await assert.rejects(
    main([
      "--bundle", "/tmp/bundle.json",
      "--controller-instance", CONTROLLER_INSTANCE,
      "--controller-key-fd", "10",
      "--host-id-fd", "11",
      "--journal-root", "/tmp/journal",
      "--operator-key-fd", "12",
      "--provider-key-fd", "13",
      "--store-key-fd", "14"
    ], {}),
    /CONTROLLER_ARGUMENTS_REJECTED/u
  );
});

test("controller runtime binds its checkout separately from the frozen application", () => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "pta-controller-composition-")
  );
  fs.chmodSync(directory, 0o700);
  const controlPlaneRoot = path.join(directory, "control-plane");
  const applicationRoot = path.join(directory, "application");
  try {
    const controlPlane = exactRepository(controlPlaneRoot, {
      [prepareTest.CONTROL_PLANE_CONTROLLER_PATH]: fs.readFileSync(path.join(
        ROOT,
        prepareTest.CONTROL_PLANE_CONTROLLER_PATH
      )),
      [prepareTest.CONTROL_PLANE_PREPARER_PATH]: fs.readFileSync(path.join(
        ROOT,
        prepareTest.CONTROL_PLANE_PREPARER_PATH
      )),
      [prepareTest.CONTROL_PLANE_ROLES_TEMPLATE_PATH]: fs.readFileSync(path.join(
        ROOT,
        prepareTest.CONTROL_PLANE_ROLES_TEMPLATE_PATH
      ))
    });
    const application = exactRepository(applicationRoot, {
      [prepareTest.APPLICATION_TEMPLATE_PATH]: fs.readFileSync(path.join(
        ROOT,
        prepareTest.APPLICATION_TEMPLATE_PATH
      ))
    });
    const controllerFile = path.join(
      controlPlaneRoot,
      prepareTest.CONTROL_PLANE_CONTROLLER_PATH
    );
    const composition = validateReleaseSourceComposition({
      applicationRoot,
      code: "CONTROLLER_RUNTIME_SOURCE_REJECTED",
      controlPlaneRoot,
      entrypointFile: controllerFile,
      entrypointRelativePath: prepareTest.CONTROL_PLANE_CONTROLLER_PATH,
      expectedApplicationCommit: application.commit,
      expectedApplicationTree: application.tree,
      expectedControlPlaneCommit: controlPlane.commit,
      expectedControlPlaneTree: controlPlane.tree
    });
    const controllerKey = KEYS.OPERATOR.publicKey;
    const approvalClaims = {
      controllerKeySha256: fingerprintPublicKey(controllerKey),
      runtime: {
        controlPlaneCommit: composition.controlPlane.sourceCommit,
        controlPlaneIdentitySha256:
          composition.controlPlane.identitySha256,
        controlPlaneTreeDigest: composition.controlPlane.treeDigest,
        controllerSha256: composition.controlPlane.controllerSha256,
        gitPath: "/usr/bin/git",
        gitSha256: sha256(fs.readFileSync("/usr/bin/git")),
        nodePath: process.execPath,
        nodeSha256: sha256(fs.readFileSync(process.execPath))
      }
    };
    const bundle = {
      plan: {
        ...PLAN,
        application: composition.application,
        controlPlane: composition.controlPlane,
        sourceCommit: composition.application.sourceCommit,
        treeDigest: composition.application.treeDigest
      }
    };
    assert.deepEqual(verifyExactRuntimeAndSource({
      applicationRoot,
      approvalClaims,
      bundle,
      controllerFile,
      controllerKey,
      controlPlaneRoot,
      expectedApplicationCommit: application.commit,
      expectedApplicationTree: application.tree,
      expectedControlPlaneCommit: controlPlane.commit,
      expectedControlPlaneTree: controlPlane.tree,
      gitPath: "/usr/bin/git"
    }), composition);

    assert.throws(
      () => verifyExactRuntimeAndSource({
        applicationRoot: controlPlaneRoot,
        approvalClaims,
        bundle,
        controllerFile,
        controllerKey,
        controlPlaneRoot: applicationRoot,
        expectedApplicationCommit: application.commit,
        expectedApplicationTree: application.tree,
        expectedControlPlaneCommit: controlPlane.commit,
        expectedControlPlaneTree: controlPlane.tree,
        gitPath: "/usr/bin/git"
      }),
      /CONTROLLER_RUNTIME_SOURCE_REJECTED/u
    );
  } finally {
    fs.rmSync(directory, { force: true, recursive: true });
  }
});

test("controller stays stdlib-only and never calls a provider", () => {
  const source = fs.readFileSync(
    path.join(ROOT, "scripts/release-provider-controller.js"),
    "utf8"
  );
  assert.doesNotMatch(source, /@aws-sdk|from\s+["']pg["']/u);
  assert.match(source, /never calls a\s+\* provider/u);
});

test("PREPARE is phase-separated while every later workflow remains diagnostic-only", () => {
  const workflows = {
    "prooftoact-release-candidate.yml": [
      "ProofToAct Release Candidate",
      "aws-release-deployment"
    ],
    "prooftoact-execute-approved-release.yml": [
      "ProofToAct Execute Approved Release",
      "aws-release-execution"
    ],
    "prooftoact-bounded-live-drill.yml": [
      "ProofToAct Bounded Live Drill",
      "aws-live-drill"
    ],
    "prooftoact-read-only-release-evidence.yml": [
      "ProofToAct Read Only Release Evidence",
      "aws-release-evidence"
    ],
    "prooftoact-approved-teardown.yml": [
      "ProofToAct Approved Teardown",
      "aws-release-teardown"
    ],
    "prooftoact-terminalize-expired-release.yml": [
      "ProofToAct Terminalize Expired Release",
      "aws-release-terminalization"
    ]
  };
  for (const [file, [name, environment]] of Object.entries(workflows)) {
    const source = fs.readFileSync(
      path.join(ROOT, ".github/workflows", file),
      "utf8"
    );
    assert.match(source, new RegExp(`^name: ${name}$`, "mu"));
    assert.match(source, new RegExp(`^    environment: ${environment}$`, "mu"));
    assert.match(source, /^permissions:\n  contents: read$/mu);
    assert.match(source, /default: true/u);
    assert.match(
      source,
      /963937a9873f0199b91897fe88da1b91bc84b5e3/u
    );
    assert.match(
      source,
      /a330e0d57328e63a568be73c523b2cae6338f26c/u
    );

    if (file === "prooftoact-release-candidate.yml") {
      assert.match(source, /^  prepare-diagnostic:$/mu);
      assert.match(source, /^  coordinator-reserve:$/mu);
      assert.match(source, /^  provider-dispatch:$/mu);
      assert.match(source, /^  coordinator-finalize:$/mu);
      assert.match(source, /^  sealed-coordinator-reserve:$/mu);
      assert.match(source, /^  sealed-provider-dispatch:$/mu);
      assert.match(source, /^  sealed-coordinator-finalize:$/mu);
      assert.match(source, /^    environment: aws-release-coordination$/mu);
      assert.equal((source.match(/^      id-token: write$/gmu) ?? []).length, 0);
      assert.doesNotMatch(source, /configure-aws-credentials/u);
      assert.doesNotMatch(source, /run-release-prepare-preflight\.js/u);
      assert.equal((source.match(
        /actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/gu
      ) ?? []).length, 3);
      assert.equal((source.match(
        /\.github\/workflows\/prooftoact-sealed-(?:coordinator|prepare)\.yml@50d0cd261b8597fe74c80b84c49be0adde5bdf6f/gu
      ) ?? []).length, 3);
      assert.doesNotMatch(source, /\$\{\{ (?:secrets|vars)\./u);
      assert.doesNotMatch(source, /PROOFTOACT_RELEASE_PREPARE_LOOKUP_B64/u);
      assert.doesNotMatch(source, /PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED/u);
      const normalizers = [...source.matchAll(
        /run: node scripts\/(normalize-[a-z0-9-]+\.js)/gu
      )].map((match) => match[1]);
      assert.equal(normalizers.length, 4);
      assert.deepEqual(
        [...new Set(normalizers)],
        ["normalize-release-control-checkouts.js"]
      );
      assert.doesNotMatch(source, /normalize-actions-checkout\.js/u);
      continue;
    }

    assert.match(
      source,
      /PROVIDER_EXECUTION_DISABLED_RUNTIME_AUTHORITY_RECEIPTS_REQUIRED/u
    );
    assert.match(
      source,
      /node --test test\/release-provider-one-shot-broker\.test\.js test\/release-provider-controller\.test\.js/u
    );
    const normalizers = [...source.matchAll(
      /run: node scripts\/(normalize-[a-z0-9-]+\.js)/gu
    )].map((match) => match[1]);
    assert.equal(normalizers.length, 1);
    assert.deepEqual(
      [...new Set(normalizers)],
      ["normalize-release-control-checkouts.js"]
    );
    assert.doesNotMatch(source, /normalize-actions-checkout\.js/u);
    assert.doesNotMatch(source, /id-token|aws\s|cloudformation|cockroach|curl/u);
  }
});
