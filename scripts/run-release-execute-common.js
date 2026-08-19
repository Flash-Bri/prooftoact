import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  brokerCanonicalBytes,
  brokerSha256,
  providerBrokerConstants
} from "./release-provider-one-shot-broker.js";
import { APP_SOURCE } from
  "../release-provider/src/release-provider-common.js";
import {
  consumeBoundedSignedApproval,
  readTrackedOperatorPublicKey
} from "./run-release-prepare-common.js";

const WORKFLOW = "ProofToAct Execute Approved Release";
const WORKFLOW_REF =
  "Flash-Bri/prooftoact/.github/workflows/" +
  "prooftoact-execute-approved-release.yml@refs/heads/main";
const OFFICIAL_REPOSITORY = "Flash-Bri/prooftoact";
const OFFICIAL_REPOSITORY_ID = "1317716765";
const OFFICIAL_OWNER_ID = "252500266";
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SEALED_JOB = "sealed-credential-boundary";
const PHASES = Object.freeze({
  diagnostic: Object.freeze({
    environment: "DIAGNOSTIC_NO_PROVIDER",
    job: "execute-diagnostic",
    phase: null,
    role: null
  }),
  reserve: Object.freeze({
    environment: "aws-release-coordination",
    job: "coordinator-reserve",
    phase: "COORDINATOR_RESERVE",
    role: "ProofToActReleaseCoordinator"
  }),
  dispatch: Object.freeze({
    environment: "aws-release-execution",
    job: "provider-dispatch",
    phase: "PROVIDER_DISPATCH",
    role: "ProofToActReleaseExecution"
  }),
  finalize: Object.freeze({
    environment: "aws-release-coordination",
    job: "coordinator-finalize",
    phase: "COORDINATOR_FINALIZE",
    role: "ProofToActReleaseCoordinator"
  })
});

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

function digest(value) {
  return brokerSha256(brokerCanonicalBytes(value));
}

function exactDirectory(candidate, code) {
  try {
    requireCondition(typeof candidate === "string" && path.isAbsolute(candidate) &&
      path.resolve(candidate) === candidate && fs.realpathSync(candidate) === candidate,
    code);
    const stat = fs.lstatSync(candidate);
    requireCondition(stat.isDirectory() && !stat.isSymbolicLink(), code);
    return candidate;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

function exactFileSha256(root, relativePath, code) {
  const candidate = path.resolve(root, relativePath);
  requireCondition(path.relative(root, candidate) ===
    relativePath.split("/").join(path.sep), code);
  let descriptor;
  try {
    requireCondition(fs.realpathSync(candidate) === candidate, code);
    descriptor = fs.openSync(candidate,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile() && stat.nlink === 1 && stat.size > 0 &&
      stat.size <= 8 * 1024 * 1024, code);
    return crypto.createHash("sha256").update(fs.readFileSync(descriptor))
      .digest("hex");
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

export function validateExecuteWorkflowContext(
  environment,
  phaseName,
  platform = process.platform
) {
  const code = "RELEASE_EXECUTE_WORKFLOW_CONTEXT_REJECTED";
  const contract = PHASES[phaseName];
  const expectedSealedWorkflow = phaseName === "dispatch"
    ? "prooftoact-sealed-execute.yml"
    : "prooftoact-sealed-coordinator.yml";
  const sealedContext = environment.GITHUB_JOB === SEALED_JOB &&
    environment.PROOFTOACT_RELEASE_CALLER_JOB === contract?.job &&
    environment.PROOFTOACT_RELEASE_SEALED_WORKFLOW ===
      expectedSealedWorkflow &&
    environment.PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT ===
      environment.GITHUB_SHA;
  const directContext = phaseName === "diagnostic" &&
    environment.GITHUB_JOB === contract?.job &&
    environment.PROOFTOACT_RELEASE_CALLER_JOB === undefined &&
    environment.PROOFTOACT_RELEASE_SEALED_WORKFLOW === undefined &&
    environment.PROOFTOACT_RELEASE_SEALED_AUTHORITY_COMMIT === undefined;
  const exactEnvironmentCarrier = environment === process.env ||
    plainObject(environment);
  requireCondition(contract && exactEnvironmentCarrier && platform === "linux" &&
    environment.CI === "true" && environment.GITHUB_ACTIONS === "true" &&
    environment.RUNNER_OS === "Linux" &&
    environment.RUNNER_ENVIRONMENT === "github-hosted" &&
    environment.GITHUB_EVENT_NAME === "workflow_dispatch" &&
    environment.GITHUB_REF === "refs/heads/main" &&
    environment.GITHUB_REF_NAME === "main" &&
    environment.GITHUB_REF_TYPE === "branch" &&
    environment.GITHUB_SERVER_URL === "https://github.com" &&
    environment.GITHUB_API_URL === "https://api.github.com" &&
    environment.GITHUB_GRAPHQL_URL === "https://api.github.com/graphql" &&
    environment.GITHUB_REPOSITORY === OFFICIAL_REPOSITORY &&
    environment.GITHUB_REPOSITORY_ID === OFFICIAL_REPOSITORY_ID &&
    environment.GITHUB_REPOSITORY_OWNER_ID === OFFICIAL_OWNER_ID &&
    environment.GITHUB_WORKFLOW === WORKFLOW &&
    environment.GITHUB_WORKFLOW_REF === WORKFLOW_REF &&
    (directContext || sealedContext) &&
    environment.PROOFTOACT_RELEASE_PHASE_ENVIRONMENT ===
      contract.environment &&
    HEX_40.test(environment.GITHUB_SHA ?? "") &&
    environment.GITHUB_WORKFLOW_SHA === environment.GITHUB_SHA &&
    environment.EXPECTED_OFFICIAL_MAIN_COMMIT === environment.GITHUB_SHA &&
    /^[1-9][0-9]{0,19}$/u.test(environment.GITHUB_RUN_ID ?? "") &&
    environment.GITHUB_RUN_ATTEMPT === "1", code);
  const workspace = exactDirectory(environment.GITHUB_WORKSPACE, code);
  const controlRoot = exactDirectory(path.join(workspace, "control-plane"), code);
  const applicationRoot = exactDirectory(
    path.join(workspace, "frozen-application"), code);
  const control = fs.lstatSync(controlRoot);
  const application = fs.lstatSync(applicationRoot);
  requireCondition(controlRoot !== applicationRoot &&
    (control.dev !== application.dev || control.ino !== application.ino), code);
  return Object.freeze({ applicationRoot, contract, controlRoot, workspace });
}

export function assertExecuteDiagnosticCredentialAbsence(environment) {
  const names = Object.keys(environment);
  requireCondition(!names.some((name) =>
    name === "ACTIONS_ID_TOKEN_REQUEST_TOKEN" ||
    name === "ACTIONS_ID_TOKEN_REQUEST_URL" ||
    /^AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|WEB_IDENTITY_TOKEN_FILE)$/u
      .test(name) ||
    name === "PROOFTOACT_RELEASE_EXECUTE_APPROVAL_B64"),
  "RELEASE_EXECUTE_DIAGNOSTIC_CREDENTIAL_REJECTED");
  return true;
}

export function consumeBoundedExecuteApproval({
  clock = Date.now,
  environment,
  phaseName,
  trustedOperatorPublicKey
}) {
  return consumeBoundedSignedApproval({
    clock,
    environment,
    lane: "EXECUTE",
    phaseName,
    secretName: "PROOFTOACT_RELEASE_EXECUTE_APPROVAL_B64",
    trustedOperatorPublicKey
  });
}

export function validateExecuteProtectedBootstrapGate({
  approval,
  controlRoot,
  environment,
  phaseName
}) {
  const code = "RELEASE_EXECUTE_PROTECTED_BOOTSTRAP_GATE_REJECTED";
  const contract = PHASES[phaseName];
  const bootstrapTemplateSha256 = exactFileSha256(controlRoot,
    "infra/aws/release-deployment-roles-template.json", code);
  requireCondition(contract?.phase && approval?.claims?.globalStore &&
    environment.PROOFTOACT_RELEASE_BOOTSTRAP_STATUS ===
      "EXACT_BOOTSTRAP_PROVIDER_READBACK_ACCEPTED" &&
    HEX_64.test(environment
      .PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256 ?? "") &&
    HEX_64.test(environment
      .PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256 ?? "") &&
    environment.PROOFTOACT_RELEASE_BOOTSTRAP_TEMPLATE_SHA256 ===
      bootstrapTemplateSha256 &&
    environment.PROOFTOACT_RELEASE_CONTROL_TABLE_ID ===
      approval.claims.globalStore.tableId &&
    environment.PROOFTOACT_RELEASE_ROLE_ARN ===
      `arn:aws:iam::${approval.providerAccountId}:role/${contract.role}`,
  code);
  return Object.freeze({
    bootstrapReceiptSha256:
      environment.PROOFTOACT_RELEASE_BOOTSTRAP_RECEIPT_SHA256,
    bootstrapStackIdSha256:
      environment.PROOFTOACT_RELEASE_BOOTSTRAP_STACK_ID_SHA256,
    bootstrapTemplateSha256,
    tableId: environment.PROOFTOACT_RELEASE_CONTROL_TABLE_ID
  });
}

export function acceptedExecuteApproval(environment, controlRoot, phaseName,
  clock = Date.now) {
  const publicKey = readTrackedOperatorPublicKey(controlRoot);
  const accepted = consumeBoundedExecuteApproval({
    clock,
    environment,
    phaseName,
    trustedOperatorPublicKey: publicKey
  });
  requireCondition(accepted.approval.claims.controlPlane.commit ===
    environment.GITHUB_SHA,
  "RELEASE_EXECUTE_CONTROL_PLANE_COMMIT_REJECTED");
  validateExecuteProtectedBootstrapGate({
    approval: accepted.approval,
    controlRoot,
    environment,
    phaseName
  });
  return Object.freeze({ ...accepted, publicKey });
}

export function phaseRuntimeIdentity(runtime) {
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
  return Object.freeze({ ...identity,
    phaseRuntimeIdentitySha256: digest(identity) });
}

export function buildExecutePhaseRuntime({
  actualControlPlaneBuildSha256,
  approval,
  approvalEnvelope,
  brokerArtifactSha256,
  callerIdentity,
  context,
  now = Date.now(),
  phaseName
}) {
  const contract = PHASES[phaseName];
  const env = context.environment;
  const code = "RELEASE_EXECUTE_PHASE_RUNTIME_REJECTED";
  const expectedSession = `pta-${env.GITHUB_RUN_ID}-1-${contract?.job}`;
  requireCondition(contract?.phase && callerIdentity.accountId ===
    approval.providerAccountId && callerIdentity.roleName === contract.role &&
    callerIdentity.sessionName === expectedSession &&
    callerIdentity.assumedRoleArn ===
      `arn:aws:sts::${approval.providerAccountId}:assumed-role/` +
      `${contract.role}/${expectedSession}` &&
    actualControlPlaneBuildSha256 === approval.claims.controlPlane.buildSha256 &&
    brokerArtifactSha256 === approval.claims.controlPlane.brokerArtifactSha256,
  code);
  const runtime = {
    schemaVersion: providerBrokerConstants.PHASE_RUNTIME_SCHEMA,
    adminDatabaseCredentialPresent: false,
    appSource: APP_SOURCE,
    artifactManifestSha256: approval.claims.release.artifactManifestSha256,
    authorityReceipts: null,
    brokerArtifactSha256,
    buildReceiptSha256: approval.claims.release.buildReceiptSha256,
    controlPlaneBuildSha256: actualControlPlaneBuildSha256,
    controlPlaneCommit: approval.claims.controlPlane.commit,
    controlPlaneIdentitySha256: approval.claims.controlPlane.identitySha256,
    controlPlaneTree: approval.claims.controlPlane.tree,
    credentialSource: "GITHUB_OIDC_SHORT_LIVED",
    environment: contract.environment,
    jobName: contract.job,
    lane: "EXECUTE",
    openClawOauthPresent: false,
    phase: contract.phase,
    principalArn: callerIdentity.assumedRoleArn,
    providerAccountId: approval.providerAccountId,
    region: "us-east-1",
    releaseReadbackSha256: digest(approval.claims.release),
    repositoryId: OFFICIAL_REPOSITORY_ID,
    repositoryOwnerId: OFFICIAL_OWNER_ID,
    rootOrAdministratorPrincipal: false,
    runAttempt: 1,
    runId: env.GITHUB_RUN_ID,
    staticProviderCredentialsPresent: false,
    workflow: WORKFLOW,
    workflowRef: WORKFLOW_REF,
    workflowSha: env.GITHUB_SHA,
    workspaceRoot: context.controlRoot
  };
  const identity = phaseRuntimeIdentity(runtime);
  const envelopeExpiry = Date.parse(approvalEnvelope?.expiresAt ?? "");
  const expiresAt = Math.min(envelopeExpiry, now + 10 * 60 * 1000);
  requireCondition(Number.isSafeInteger(now) && Number.isSafeInteger(expiresAt) &&
    expiresAt > now, code);
  runtime.authorityReceipts = Object.freeze({
    schemaVersion: providerBrokerConstants.PHASE_AUTHORITY_SCHEMA,
    status: "EXACT_PHASE_RUNTIME_AUTHORITY_CONFIRMED",
    artifactReadbackSha256: approval.claims.release.artifactManifestSha256,
    buildReadbackSha256: approval.claims.release.buildReceiptSha256,
    controlPlaneSha256: approval.claims.controlPlane.identitySha256,
    costCensusSha256: approval.claims.budget.censusReceiptSha256,
    expiresAt: new Date(expiresAt).toISOString(),
    freshDatabaseSha256: approval.claims.database.freshPrimaryReceiptSha256,
    globalStoreSha256: approval.claims.globalStore.tableIdentitySha256,
    iamSeparationSha256: digest(approval.claims.authoritySeparation),
    observedAt: new Date(now).toISOString(),
    providerBacked: true,
    providerIdentitySha256: digest({
      accountId: runtime.providerAccountId,
      principalArn: runtime.principalArn,
      region: runtime.region
    }),
    releaseReadbackSha256: digest(approval.claims.release),
    sourceCheckoutSha256: digest(APP_SOURCE),
    strongRead: true,
    teardownContractSha256: digest(approval.claims.teardown),
    workflowIdentitySha256: identity.phaseRuntimeIdentitySha256
  });
  return Object.freeze({ ...runtime });
}

export const releaseExecuteConstants = Object.freeze({
  PHASES,
  WORKFLOW,
  WORKFLOW_REF
});

export const __test = Object.freeze({ digest, exactDirectory });
