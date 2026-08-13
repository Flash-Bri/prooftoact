import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  appendIntegratedLiveDrillJournal,
  parseIntegratedLiveDrillSpec,
  startIntegratedLiveDrillJournal
} from "../src/cloud/integrated-live-drill.js";
import {
  buildIntegratedLiveDrillProviderOrchestrationPreparation,
  integratedLiveDrillProviderDispatchRequest,
  persistIntegratedLiveDrillProviderOrchestrationPreparation,
  persistIntegratedLiveDrillProviderDispatchRequest,
  readIntegratedLiveDrillOrchestrationPrivateJson,
  readIntegratedLiveDrillProviderOrchestrationPreparation,
  sanitizedIntegratedLiveDrillProviderOrchestrationHold,
  validateIntegratedLiveDrillProviderSupervisorPreparation
} from "../src/cloud/integrated-live-drill-provider-orchestration.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillRunnerIdentityDigest,
  validateIntegratedLiveDrillPreAuthorizationBinding,
  validateIntegratedLiveDrillRunAuthorization
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  acquireIntegratedLiveDrillPrivateRootLease,
  normalizeIntegratedLiveDrillProviderContext,
  INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT,
  validateIntegratedLiveDrillProviderDispatchAuthorizationPure
} from "../src/cloud/integrated-live-drill-provider-evidence.js";
import {
  integratedLiveDrillProviderAuthorityTimes,
  readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation
} from "../src/cloud/integrated-live-drill-provider-recovery.js";
import { buildProviderDispatchControlBinding } from
  "../src/cloud/provider-dispatch-binding.js";
import {
  consumeIntegratedLiveDrillRunAuthorization,
  reserveIntegratedLiveDrillSpend
} from "../src/cloud/integrated-live-drill-control-ledger.js";
import {
  assertIntegratedLiveDrillRuntime,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
} from "../src/cloud/integrated-live-drill-runtime.js";
import { spawnIntegratedLiveDrillRuntimeComponent } from
  "../src/cloud/integrated-live-drill-runtime-spawn.js";
import {
  INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT,
  integratedLiveDrillChildCommittedTrustRoot,
  integratedLiveDrillChildAuthorizationContext
} from "../src/cloud/integrated-live-drill-child-authorization.js";
import {
  validateDeploymentExpectation,
  validateSignedPreDeploymentAttestation
} from "../src/cloud/aws-deployment-attestation.js";
import { parseAuthorityDrillBinding } from
  "../src/cloud/aws-authority-race.js";
import { isolatedEvidenceProcessEnvironment } from
  "../src/cloud/aws-evidence-identity.js";
import {
  assertExactCleanCheckout,
  createAuthorityRaceGitRunner,
  fetchOfficialMain
} from "./gate2-authority-race.js";
import { loadCommittedRecoveryPublisherTrustRoot } from
  "./lib/recovery-publisher-key.js";
import { readSystemdCredential } from "../src/cloud/systemd-credential.js";

const MODULE_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
);

const DVI_ENVIRONMENT = Object.freeze([
  "DATABASE_URL",
  "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
  "TIDEPROOF_AUDITOR_DATABASE_URL"
]);
const AUTHORITY_ENVIRONMENT = Object.freeze([
  "AWS_ACCESS_KEY_ID",
  "AWS_EVIDENCE_EXPECTED_ACCOUNT_ID",
  "AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_ARN",
  "AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_USER_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN"
]);
const RECOVERY_ENVIRONMENT = Object.freeze([
  "EXPECTED_PRIMARY_HOSTNAME",
  "EXPECTED_RECOVERY_HOSTNAME",
  "PRIMARY_AUDIT_DATABASE_URL",
  "PRIMARY_CLUSTER_ID",
  "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
  "RECOVERY_CLUSTER_ID",
  "RECOVERY_PUBLISHER_DATABASE_URL",
  "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64",
  "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT",
  "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT"
]);
const PROVIDER_PREPARATION_ENVIRONMENT = Object.freeze(
  RECOVERY_ENVIRONMENT
);
const PROVIDER_ORCHESTRATION_MODE_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE";
const PROVIDER_SUPERVISOR_MODE_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_MODE";
const PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_PATH";
const PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION";
const PROVIDER_ROOT_BINDING_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_ROOT_BINDING";
const PROVIDER_DISPATCH_REQUEST_PATH_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_REQUEST_PATH";
const SYSTEMD_BOUNDARY_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY";
const SYSTEMD_INSTANCE_ENVIRONMENT =
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_SYSTEMD_INSTANCE";
const SYSTEMD_ORCHESTRATOR_INPUT_SCHEMA =
  "tideproof.integrated-live-drill-systemd-orchestrator-input.v1";
const SYSTEMD_ORCHESTRATOR_INPUT_CREDENTIAL = "orchestrator-input";
const PRE_EXECUTION_INJECTION_ENVIRONMENT =
  /^(?:NODE_.*|LD_.*|DYLD_.*|GLIBC_TUNABLES|GCONV_PATH|PERL.*)$/u;
const PROVIDER_CAPABILITY_ENVIRONMENT =
  /^(?:MCP_API_KEY|PRIMARY_PROVIDER_(?:CLAIM|BEGIN|FINALIZE|RECONCILE)_DATABASE_URL)$/u;
const SYSTEMD_PREPARE_INPUT_NAMES = new Set([
  "AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST",
  "AUTHORITY_ALPHA_PROPOSAL_DIGEST",
  "AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST",
  "AUTHORITY_BRAVO_PROPOSAL_DIGEST",
  "AUTHORITY_EVIDENCE_ID",
  "AUTHORITY_INCIDENT_ID",
  "AUTHORITY_RESOURCE_ID",
  "AUTHORITY_SELECTED_EVIDENCE_DIGEST",
  "AUTHORITY_TENANT_ID",
  "AWS_ACCESS_KEY_ID",
  "AWS_EVIDENCE_EXPECTED_ACCOUNT_ID",
  "AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_ARN",
  "AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_USER_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "CONFIG_DIGEST",
  "DATABASE_URL",
  "EXPECTED_PRIMARY_HOSTNAME",
  "EXPECTED_RECOVERY_HOSTNAME",
  "PRIMARY_AUDIT_DATABASE_URL",
  "PRIMARY_CLUSTER_ID",
  "PRIMARY_RECOVERY_SOURCE_DATABASE_URL",
  "RECOVERY_CLUSTER_ID",
  "RECOVERY_PUBLISHER_DATABASE_URL",
  "RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64",
  "SOURCE_COMMIT",
  "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
  "TIDEPROOF_AUDITOR_DATABASE_URL",
  "TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION",
  "TIDEPROOF_GATE2_PRE_DEPLOYMENT_ATTESTATION",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
  "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT",
  "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT"
]);
const SYSTEMD_RESUME_INPUT_NAMES = new Set([
  PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT,
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC"
]);

function boundaryRecord(value, allowedKeys, code) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    throw new Error(code);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (!ownKeys.every((key) => {
    const descriptor = typeof key === "string"
      ? Object.getOwnPropertyDescriptor(value, key)
      : null;
    return typeof key === "string" &&
      allowedKeys.includes(key) &&
      descriptor !== null &&
      descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      descriptor.enumerable === true;
  })) {
    throw new Error(code);
  }
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(value, key).value
  ])));
}

function normalizedOrchestratorEnvironment(environment) {
  const code = "INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED";
  const realProcessEnvironment = environment === process.env;
  if (
    !environment ||
    typeof environment !== "object" ||
    Array.isArray(environment) ||
    (
      !realProcessEnvironment &&
      ![Object.prototype, null].includes(Object.getPrototypeOf(environment))
    )
  ) {
    throw new Error(code);
  }
  const ownKeys = Reflect.ownKeys(environment);
  if (!ownKeys.every((key) => {
    const descriptor = typeof key === "string"
      ? Object.getOwnPropertyDescriptor(environment, key)
      : null;
    return typeof key === "string" &&
      descriptor !== null &&
      descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      descriptor.enumerable === true &&
      typeof descriptor.value === "string";
  })) {
    throw new Error(code);
  }
  return Object.freeze(Object.fromEntries(ownKeys.map((key) => [
    key,
    Object.getOwnPropertyDescriptor(environment, key).value
  ])));
}

function requiredEnvironment(environment, name, maximum = 4096) {
  const value = environment[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\0\r\n]/.test(value)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED");
  }
  return value;
}

function parseJson(value, code) {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(code);
  }
}

function exactRecord(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)) &&
    Reflect.ownKeys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

export function systemdIntegratedLiveDrillEnvironment(
  processEnvironment = process.env
) {
  const code = "INTEGRATED_LIVE_DRILL_SYSTEMD_INPUT_REJECTED";
  let ambient;
  try {
    ambient = normalizedOrchestratorEnvironment(processEnvironment);
  } catch (cause) {
    throw new Error(code, { cause });
  }
  if (Object.keys(ambient).some((name) =>
    PRE_EXECUTION_INJECTION_ENVIRONMENT.test(name) ||
      PROVIDER_CAPABILITY_ENVIRONMENT.test(name)
  )) {
    throw new Error(code);
  }
  const boundary = ambient[SYSTEMD_BOUNDARY_ENVIRONMENT];
  const mode = boundary === "prepare-v1"
    ? "PREPARE"
    : boundary === "resume-v1"
      ? "RESUME"
      : null;
  const instance = ambient[SYSTEMD_INSTANCE_ENVIRONMENT];
  const credentialsDirectory = ambient.CREDENTIALS_DIRECTORY;
  if (
    mode === null ||
    typeof instance !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[4-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
      .test(instance) ||
    typeof credentialsDirectory !== "string" ||
    !path.isAbsolute(credentialsDirectory) ||
    path.resolve(credentialsDirectory) !== credentialsDirectory
  ) {
    throw new Error(code);
  }
  let input;
  try {
    input = JSON.parse(readSystemdCredential({
      credentialsDirectory,
      maximumBytes: 8 * 1024 * 1024,
      name: SYSTEMD_ORCHESTRATOR_INPUT_CREDENTIAL
    }).toString("utf8"));
  } catch (cause) {
    throw new Error(code, { cause });
  }
  if (
    !exactRecord(input, ["environment", "schemaVersion"]) ||
    input.schemaVersion !== SYSTEMD_ORCHESTRATOR_INPUT_SCHEMA ||
    !input.environment || typeof input.environment !== "object" ||
    Array.isArray(input.environment) ||
    ![Object.prototype, null].includes(
      Object.getPrototypeOf(input.environment)
    )
  ) {
    throw new Error(code);
  }
  const supplied = normalizedOrchestratorEnvironment(input.environment);
  const allowedInputNames = mode === "PREPARE"
    ? SYSTEMD_PREPARE_INPUT_NAMES
    : SYSTEMD_RESUME_INPUT_NAMES;
  const forbiddenNames = new Set([
    "CREDENTIALS_DIRECTORY",
    SYSTEMD_BOUNDARY_ENVIRONMENT,
    SYSTEMD_INSTANCE_ENVIRONMENT,
    PROVIDER_ORCHESTRATION_MODE_ENVIRONMENT,
    PROVIDER_DISPATCH_REQUEST_PATH_ENVIRONMENT,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH",
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
  ]);
  if (Object.keys(supplied).some((name) =>
    !allowedInputNames.has(name) || forbiddenNames.has(name) ||
      PRE_EXECUTION_INJECTION_ENVIRONMENT.test(name) ||
      PROVIDER_CAPABILITY_ENVIRONMENT.test(name)
  ) || Object.keys(supplied).length !== allowedInputNames.size) {
    throw new Error(code);
  }
  const spec = parseIntegratedLiveDrillSpec(parseJson(
    requiredEnvironment(
      supplied,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
      8192
    ),
    code
  ));
  if (spec.runId !== instance) throw new Error(code);
  const stateRoot = "/var/lib/prooftoact";
  const evidenceRoot = `${stateRoot}/evidence/${instance}`;
  const authorizationRoot = `${stateRoot}/authorization/${instance}`;
  const runtime = Object.fromEntries([
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "PATH",
    "TMPDIR",
    INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
    INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT
  ].filter((name) => typeof ambient[name] === "string")
    .map((name) => [name, ambient[name]]));
  const environment = Object.freeze({
    ...runtime,
    ...supplied,
    [PROVIDER_ORCHESTRATION_MODE_ENVIRONMENT]: mode,
    [PROVIDER_DISPATCH_REQUEST_PATH_ENVIRONMENT]:
      `${evidenceRoot}/dispatch-request.json`,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT:
      authorizationRoot,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH:
      `${evidenceRoot}/${instance}.journal`,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_PATH:
      `${evidenceRoot}/${instance}.private-evidence.json`,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT: evidenceRoot
  });
  if (
    (mode === "PREPARE" && Object.hasOwn(
      environment,
      PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT
    )) ||
    (mode === "RESUME" && !Object.hasOwn(
      environment,
      PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT
    ))
  ) {
    throw new Error(code);
  }
  return environment;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function strictPathEntryPresent(filePath, code) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (cause) {
    if (cause?.code === "ENOENT") return false;
    throw new Error(code, { cause });
  }
}

function pathIsWithin(candidate, root) {
  const relative = path.relative(root, candidate);
  return relative === "" || (
    !relative.startsWith("..") && !path.isAbsolute(relative)
  );
}

function isolatedComponentEnvironment(environment, names, additions = {}) {
  const selected = Object.fromEntries(
    names.map((name) => [name, requiredEnvironment(environment, name, 16_384)])
  );
  return Object.freeze({
    ...isolatedEvidenceProcessEnvironment(environment),
    ...selected,
    ...additions
  });
}

export function dviComponentEnvironment(environment, additions = {}) {
  return isolatedComponentEnvironment(
    environment,
    DVI_ENVIRONMENT,
    additions
  );
}

export function authorityComponentEnvironment(
  environment,
  drill,
  additions = {}
) {
  return isolatedComponentEnvironment(
    environment,
    AUTHORITY_ENVIRONMENT,
    {
      TIDEPROOF_AUTHORITY_DRILL_BINDING: JSON.stringify(
        parseAuthorityDrillBinding(drill)
      ),
      ...additions
    }
  );
}

export function recoveryComponentEnvironment(environment, additions) {
  return isolatedComponentEnvironment(
    environment,
    RECOVERY_ENVIRONMENT,
    additions
  );
}

export function providerPreparationComponentEnvironment(
  environment,
  additions
) {
  return isolatedComponentEnvironment(
    environment,
    PROVIDER_PREPARATION_ENVIRONMENT,
    additions
  );
}

function defaultRunComponent(
  script,
  args,
  environment,
  rootDir,
  { capabilityRootPath, decisionRootDescriptor, rootDescriptor, spec } = {}
) {
  const stdio = Number.isSafeInteger(rootDescriptor)
    ? Number.isSafeInteger(decisionRootDescriptor)
      ? ["ignore", "pipe", "pipe", rootDescriptor, decisionRootDescriptor]
      : ["ignore", "pipe", "pipe", rootDescriptor]
    : ["ignore", "pipe", "pipe"];
  const result = spawnIntegratedLiveDrillRuntimeComponent({
    args,
    childEnvironment: environment,
    cwd: Number.isSafeInteger(rootDescriptor)
      ? capabilityRootPath
      : rootDir,
    parentComponent: "orchestrator",
    parentEnvironment: process.env,
    script,
    spec,
    stdio
  });
  if (
    result.error ||
    result.status !== 0 ||
    typeof result.stdout !== "string" ||
    result.stdout.length === 0 ||
    result.stdout.length > 8 * 1024 * 1024
  ) {
    const childCode = typeof result.stderr === "string"
      ? result.stderr.trim()
      : "";
    throw new Error(
      /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(childCode)
        ? childCode
        : "INTEGRATED_LIVE_DRILL_COMPONENT_FAILED"
    );
  }
  return parseJson(
    result.stdout,
    "INTEGRATED_LIVE_DRILL_COMPONENT_OUTPUT_REJECTED"
  );
}

export async function verifyIntegratedRelease(spec, rootDir) {
  const readGit = createAuthorityRaceGitRunner({ rootDir });
  fetchOfficialMain(readGit, { rootDir });
  const checkout = assertExactCleanCheckout(spec.sourceCommit, {
    rootDir,
    readGit
  });
  const packageLockPath = path.join(rootDir, "package-lock.json");
  const packageLockStat = fs.lstatSync(packageLockPath);
  if (
    !packageLockStat.isFile() ||
    packageLockStat.isSymbolicLink() ||
    packageLockStat.nlink !== 1
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_REJECTED");
  }
  const packageLockDigest = createHash("sha256")
    .update(fs.readFileSync(packageLockPath))
    .digest("hex");
  if (
    checkout.treeDigest !== spec.treeDigest ||
    packageLockDigest !== spec.packageLockDigest
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_REJECTED");
  }
  return Object.freeze({
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    packageLockDigest: spec.packageLockDigest
  });
}

export function safeIntegratedLiveDrillFailureCode(error) {
  const value = String(error?.message ?? "");
  return /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,100}$/.test(value)
    ? value
    : "INTEGRATED_LIVE_DRILL_UNKNOWN";
}

function providerOrchestrationMode(environment) {
  const value = environment?.[PROVIDER_ORCHESTRATION_MODE_ENVIRONMENT];
  const dispatchPresent =
    environment?.[PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT] !== undefined;
  if (value === undefined) {
    throw new Error(
      dispatchPresent
        ? "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PARTIAL_CONFIG_REJECTED"
        : "INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED"
    );
  }
  if (!['PREPARE', 'RESUME'].includes(value)) {
    throw new Error("INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_MODE_REJECTED");
  }
  if (value === "PREPARE" && dispatchPresent) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PARTIAL_CONFIG_REJECTED"
    );
  }
  return value;
}

function providerOrchestrationPaths(privateEvidenceRootPath, spec) {
  return Object.freeze({
    checkpointPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-orchestration-preparation.json`
    ),
    completionPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-orchestration-completion.json`
    ),
    contextPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-supervisor-context.json`
    ),
    finalizationInputPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-finalization-input.json`
    ),
    dispatchRequestPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-dispatch-request.json`
    ),
    executionGrantPath: path.join(
      privateEvidenceRootPath,
      "execution-grant.json"
    ),
    reconciliationInputPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-reconciliation-input.json`
    ),
    workerInputPath: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.provider-worker-input.json`
    )
  });
}

export function verifyIntegratedLiveDrillProviderPreparationEvidence({
  forbiddenRootPath,
  gate1Preparation,
  paths,
  rootBinding,
  rootPath
}) {
  const context = normalizeIntegratedLiveDrillProviderContext(
    readIntegratedLiveDrillOrchestrationPrivateJson({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_CONTEXT_REJECTED",
      filePath: paths.contextPath,
      forbiddenRootPath,
      rootPath
    }),
    { requireDispatchAuthorization: false }
  );
  if (canonicalJson(context.evidenceRootBinding) !== canonicalJson(rootBinding)) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED"
    );
  }
  const dispatchPreparation =
    readIntegratedLiveDrillProviderRecoveryAuthorizationPreparation(context);
  const supervisorEvidence = Object.freeze({ context, dispatchPreparation });
  return Object.freeze({
    gate1Preparation: validateIntegratedLiveDrillProviderSupervisorPreparation(
      gate1Preparation,
      supervisorEvidence
    ),
    supervisorEvidence
  });
}

export function verifyIntegratedLiveDrillProviderDispatchAdmission({
  dispatchAuthorization,
  now,
  requireCurrent,
  supervisorEvidence
}) {
  if (
    !supervisorEvidence ||
    typeof supervisorEvidence !== "object" ||
    !supervisorEvidence.context
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
    );
  }
  const context = normalizeIntegratedLiveDrillProviderContext(
    supervisorEvidence.context,
    { requireDispatchAuthorization: false }
  );
  return validateIntegratedLiveDrillProviderDispatchAuthorizationPure(
    dispatchAuthorization,
    {
      childAuthorizationIssuedAt:
        context.preCallInputs.consumedChildAuthorization.attestation.payload
          .issuedAt,
      humanAuthorizationTrustRoot:
        context.trustedRunContext.humanAuthorizationTrustRoot,
      intent: context.preCallIntent,
      now,
      requireCurrent
    }
  );
}

async function resumeIntegratedLiveDrillProviderOrchestration({
  clock,
  environment,
  spec,
  verifiedRootDir,
  verifyProviderDispatchAuthorization,
  verifyProviderPreparationEvidence,
  verifyRelease
}) {
  const privateEvidenceRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    4096
  );
  const forbiddenRootPath = verifiedRootDir;
  const paths = providerOrchestrationPaths(privateEvidenceRootPath, spec);
  const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
    code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED",
    forbiddenRootPath,
    rootPath: privateEvidenceRootPath
  });
  try {
    const checkpoint = readIntegratedLiveDrillProviderOrchestrationPreparation({
      checkpointPath: paths.checkpointPath,
      forbiddenRootPath,
      rootPath: privateEvidenceRootPath,
      spec
    });
    const preparation = checkpoint.preparation;
    const persistence = checkpoint.persistence;
    if (
      canonicalJson(preparation.evidenceRootBinding) !==
        canonicalJson(rootLease.binding)
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED"
      );
    }
    const rebound = await verifyProviderPreparationEvidence({
      forbiddenRootPath,
      gate1Preparation: preparation.gate1Preparation,
      paths,
      rootBinding: rootLease.binding,
      rootPath: privateEvidenceRootPath
    });
    if (
      canonicalJson(rebound?.gate1Preparation) !==
        canonicalJson(preparation.gate1Preparation)
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
      );
    }
    const dispatchAuthorization = parseJson(
      requiredEnvironment(
        environment,
        PROVIDER_DISPATCH_AUTHORIZATION_ENVIRONMENT,
        1024 * 1024
      ),
      "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
    );
    const dispatchEvidence = await verifyProviderDispatchAuthorization({
      dispatchAuthorization,
      now: clock(),
      requireCurrent: true,
      supervisorEvidence: rebound.supervisorEvidence
    });
    if (!/^[0-9a-f]{64}$/u.test(dispatchEvidence?.attestationSha256 ?? "")) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_AUTHORIZATION_REJECTED"
      );
    }
    if (!rebound?.supervisorEvidence?.context) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_PREPARATION_REJECTED"
      );
    }
    const context = normalizeIntegratedLiveDrillProviderContext({
      ...rebound.supervisorEvidence.context,
      providerDispatchAuthorization: dispatchAuthorization
    });
    const childAuthorizationIssuedAt =
      context.preCallInputs.consumedChildAuthorization.attestation.payload
        .issuedAt;
    const authorityTimes = integratedLiveDrillProviderAuthorityTimes(
      context,
      context.preCallIntent,
      dispatchEvidence,
      Date.parse(childAuthorizationIssuedAt)
    );
    const binding = buildProviderDispatchControlBinding({
      context,
      dispatchAuthorizationSha256: dispatchEvidence.attestationSha256,
      earliestControllingExpiry: authorityTimes.earliestControllingExpiry,
      latestControllingIssuedAt: authorityTimes.latestControllingIssuedAt
    });
    const workerInput = Object.freeze({
      authenticatedPrincipal: "principal://tideproof-demo-successor",
      context
    });
    const workerSpecSha256 = integratedLiveDrillCanonicalSha256(workerInput);
    const request = integratedLiveDrillProviderDispatchRequest({
      binding,
      packageLockDigest: spec.packageLockDigest,
      workerInput,
      workerSpecSha256
    });
    const configuredDispatchPath = requiredEnvironment(
      environment,
      PROVIDER_DISPATCH_REQUEST_PATH_ENVIRONMENT,
      4096
    );
    if (
      !path.isAbsolute(configuredDispatchPath) ||
      path.resolve(configuredDispatchPath) !== configuredDispatchPath
    ) {
      throw new Error(
        "INTEGRATED_LIVE_DRILL_PROVIDER_DISPATCH_REQUEST_REJECTED"
      );
    }
    const requestRootPath = path.dirname(configuredDispatchPath);
    const requestForbiddenRootPath = requestRootPath === privateEvidenceRootPath
      ? forbiddenRootPath
      : privateEvidenceRootPath;
    const persistedRequest = persistIntegratedLiveDrillProviderDispatchRequest({
      filePath: configuredDispatchPath,
      forbiddenRootPath: requestForbiddenRootPath,
      request,
      rootPath: requestRootPath
    });
    await verifyRelease(spec, verifiedRootDir);
    await rootLease.assertSettled();
    return Object.freeze({
      schemaVersion: "tideproof.highwater-drill-provider-dispatch-handoff.v1",
      accepted: false,
      authorizationId: preparation.authorizationId,
      dispatchAuthorizationSha256: dispatchEvidence.attestationSha256,
      dispatchRequestReceiptSha256: persistedRequest.receiptSha256,
      finalReleaseReady: false,
      globalGrantPresent: false,
      providerApiCredentialPresent: false,
      providerBacked: false,
      retryPermitted: true,
      runId: preparation.runId,
      state: "AWAITING_GLOBAL_PROVIDER_DISPATCH",
      status: "HOLD_AWAITING_GLOBAL_PROVIDER_DISPATCH",
      workerSpecSha256,
      checkpointPersistenceReceiptSha256: persistence.receiptSha256
    });
  } finally {
    rootLease.release();
  }
}

export async function runIntegratedLiveDrill(args = {}) {
  const options = boundaryRecord(
    args,
    [
      "clock",
      "environment",
      "rootDir",
      "runComponent",
      "verifyProviderDispatchAuthorization",
      "verifyProviderPreparationEvidence",
      "verifyRelease"
    ],
    "INTEGRATED_LIVE_DRILL_OPTIONS_REJECTED"
  );
  const clock = options.clock ?? Date.now;
  const sourceEnvironment = options.environment ?? process.env;
  const environment = normalizedOrchestratorEnvironment(sourceEnvironment);
  const runComponent = options.runComponent ?? defaultRunComponent;
  const defaultRuntime = runComponent === defaultRunComponent;
  const rootDir = options.rootDir ?? (
    defaultRuntime
      ? process.env[INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT]
      : MODULE_ROOT
  );
  const verifyProviderPreparationEvidence =
    options.verifyProviderPreparationEvidence ??
      verifyIntegratedLiveDrillProviderPreparationEvidence;
  const verifyProviderDispatchAuthorization =
    options.verifyProviderDispatchAuthorization ??
      verifyIntegratedLiveDrillProviderDispatchAdmission;
  if (
    typeof clock !== "function" ||
      typeof rootDir !== "string" ||
      typeof runComponent !== "function" ||
      typeof verifyProviderDispatchAuthorization !== "function" ||
      typeof verifyProviderPreparationEvidence !== "function"
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_OPTIONS_REJECTED");
  }
  const verifiedRootDir = fs.realpathSync(rootDir);
  if (verifiedRootDir !== rootDir) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_REJECTED");
  }
  const spec = parseIntegratedLiveDrillSpec(
    parseJson(
      requiredEnvironment(
        environment,
        "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
        8192
      ),
      "INTEGRATED_LIVE_DRILL_SPEC_REJECTED"
    )
  );
  const runtime = defaultRuntime
    ? assertIntegratedLiveDrillRuntime({
      environment: process.env,
      expectedComponent: "orchestrator",
      spec
    })
    : null;
  const verifyRelease = options.verifyRelease ?? (
    runtime === null
      ? verifyIntegratedRelease
      : async () => Object.freeze({
          packageLockDigest: runtime.manifest.packageLockDigest,
          runtimeBundleManifestSha256: runtime.manifestSha256,
          sourceCommit: runtime.manifest.sourceCommit,
          stageRoot: runtime.stageRoot,
          treeDigest: runtime.manifest.treeDigest
        })
  );
  if (typeof verifyRelease !== "function") {
    throw new Error("INTEGRATED_LIVE_DRILL_OPTIONS_REJECTED");
  }
  const orchestrationMode = providerOrchestrationMode(environment);
  if (orchestrationMode === "RESUME") {
    return resumeIntegratedLiveDrillProviderOrchestration({
      clock,
      environment,
      spec,
      verifiedRootDir,
      verifyProviderDispatchAuthorization,
      verifyProviderPreparationEvidence,
      verifyRelease
    });
  }
  const authorityEvidenceId = requiredEnvironment(
    environment,
    "AUTHORITY_EVIDENCE_ID",
    64
  );
  const authoritySelectedEvidenceDigest = requiredEnvironment(
    environment,
    "AUTHORITY_SELECTED_EVIDENCE_DIGEST",
    64
  );
  if (
    environment.SOURCE_COMMIT !== spec.sourceCommit ||
    environment.CONFIG_DIGEST !== spec.configDigest
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_ENVIRONMENT_REJECTED");
  }
  const expectation = validateDeploymentExpectation(parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION",
      1024 * 1024
    ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  ));
  const preAttestation = parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_GATE2_PRE_DEPLOYMENT_ATTESTATION",
      8 * 1024 * 1024
    ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  );
  const authorizationAttestation = parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION",
      1024 * 1024
    ),
    "INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED"
  );
  const humanAuthorizationTrustRoot = parseJson(
    requiredEnvironment(
      environment,
      "TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT",
      16_384
    ),
    "INTEGRATED_LIVE_DRILL_HUMAN_TRUST_ROOT_REJECTED"
  );
  const authorizationLedgerRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT",
    4096
  );
  const runnerIdentity = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY",
    512
  );
  const committedTrustRoot = integratedLiveDrillChildCommittedTrustRoot(
    loadCommittedRecoveryPublisherTrustRoot(environment)
  );
  const childLaunchPrivateKeyPkcs8DerBase64 = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_PRIVATE_KEY_PKCS8_BASE64",
    1024
  );
  const validatedPreAttestation = validateSignedPreDeploymentAttestation(
    preAttestation,
    expectation
  );
  if (typeof clock !== "function") {
    throw new Error("INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED");
  }
  const validateCurrentLaunchAuthorization = (checkedAt = clock()) => {
    const currentAuthorization = validateIntegratedLiveDrillRunAuthorization(
      authorizationAttestation,
      {
        spec,
        expectation,
        committedTrustRoot,
        humanAuthorizationTrustRoot,
        authorizationLedgerRootPath,
        now: checkedAt
      }
    );
    validateIntegratedLiveDrillPreAuthorizationBinding(
      currentAuthorization,
      validatedPreAttestation,
      { now: checkedAt }
    );
    return currentAuthorization;
  };
  const authorization = validateCurrentLaunchAuthorization();
  if (
    authorization.payload.authorizationClaimAuthority.runnerIdentitySha256 !==
      integratedLiveDrillRunnerIdentityDigest(runnerIdentity)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY_REJECTED");
  }
  const preRelease = await verifyRelease(spec, verifiedRootDir);
  const privateEvidenceRootPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
    4096
  );
  if (
    orchestrationMode !== null &&
    (
      pathIsWithin(authorizationLedgerRootPath, privateEvidenceRootPath) ||
      pathIsWithin(privateEvidenceRootPath, authorizationLedgerRootPath)
    )
  ) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_SEPARATION_REJECTED"
    );
  }
  const journalPath = requiredEnvironment(
    environment,
    "TIDEPROOF_INTEGRATED_LIVE_DRILL_JOURNAL_PATH",
    4096
  );
  const forbiddenPrivateEvidenceRootPath = verifiedRootDir;
  const consumedAuthorization = consumeIntegratedLiveDrillRunAuthorization(
    authorizationAttestation,
    {
      spec,
      expectation,
      committedTrustRoot,
      humanAuthorizationTrustRoot,
      ledgerRootPath: authorizationLedgerRootPath,
      forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
      now: clock()
    }
  );
  validateIntegratedLiveDrillPreAuthorizationBinding(
    consumedAuthorization.authorization,
    validatedPreAttestation,
    { now: clock() }
  );
  const authorizationClaim = consumedAuthorization.claim;
  const spendReservations = [];
  const childLaunchEnvironment = (
    reservation,
    launchAuthorization,
    checkedAt
  ) => {
    const launchToken = integratedLiveDrillChildAuthorizationContext({
      authorization: launchAuthorization,
      claim: authorizationClaim,
      expectation,
      privateKeyPkcs8DerBase64: childLaunchPrivateKeyPkcs8DerBase64,
      reservation,
      spec,
      now: checkedAt
    });
    return Object.freeze({
      TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: canonicalJson(spec),
      TIDEPROOF_GATE2_DEPLOYMENT_EXPECTATION: canonicalJson(expectation),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION: canonicalJson(
        authorizationAttestation
      ),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT:
        canonicalJson(humanAuthorizationTrustRoot),
      TIDEPROOF_INTEGRATED_LIVE_DRILL_AUTHORIZATION_LEDGER_ROOT:
        authorizationLedgerRootPath,
      TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNNER_IDENTITY: runnerIdentity,
      [INTEGRATED_LIVE_DRILL_CHILD_COMMITTED_TRUST_ROOT_ENVIRONMENT]:
        canonicalJson(
          integratedLiveDrillChildCommittedTrustRoot(committedTrustRoot)
        ),
      [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]:
        canonicalJson(launchToken)
    });
  };
  const authorityAlphaProposalDigest = requiredEnvironment(
    environment,
    "AUTHORITY_ALPHA_PROPOSAL_DIGEST",
    64
  );
  const authorityBravoProposalDigest = requiredEnvironment(
    environment,
    "AUTHORITY_BRAVO_PROPOSAL_DIGEST",
    64
  );
  const authorityAlphaLogicalActionDigest = requiredEnvironment(
    environment,
    "AUTHORITY_ALPHA_LOGICAL_ACTION_DIGEST",
    64
  );
  const authorityBravoLogicalActionDigest = requiredEnvironment(
    environment,
    "AUTHORITY_BRAVO_LOGICAL_ACTION_DIGEST",
    64
  );
  const authorityTenantId = requiredEnvironment(
    environment,
    "AUTHORITY_TENANT_ID",
    64
  );
  const authorityIncidentId = requiredEnvironment(
    environment,
    "AUTHORITY_INCIDENT_ID",
    64
  );
  const authorityResourceId = requiredEnvironment(
    environment,
    "AUTHORITY_RESOURCE_ID",
    160
  );
  const journalIntentBindingSha256 = sha256(canonicalJson({
    schemaVersion: "tideproof.highwater-drill-live-journal-intent.v1",
    spec,
    authorityEvidenceId,
    authoritySelectedEvidenceDigest,
    authorityAlphaProposalDigest,
    authorityBravoProposalDigest,
    authorityAlphaLogicalActionDigest,
    authorityBravoLogicalActionDigest,
    authorityTenantId,
    authorityIncidentId,
    authorityResourceId,
    dviProofSpecSha256: sha256(requiredEnvironment(
      environment,
      "TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC",
      16_384
    )),
    primaryClusterId: requiredEnvironment(
      environment,
      "PRIMARY_CLUSTER_ID",
      16_384
    ),
    recoveryClusterId: requiredEnvironment(
      environment,
      "RECOVERY_CLUSTER_ID",
      16_384
    ),
    recoveryPublisherTrustRootCommitment: requiredEnvironment(
      environment,
      "TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT",
      16_384
    ),
    recoveryPublisherKeySetDigest: committedTrustRoot.publisherKeySetDigest,
    runAuthorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorizationAttestation
      ),
    authorizationClaimSha256:
      authorizationClaim.authorizationClaimSha256,
    spendAuthorizationSha256:
      authorizationClaim.spendAuthorizationSha256,
    preDeploymentAttestationSha256: sha256(
      canonicalJson(validatedPreAttestation)
    )
  }));
  startIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    intentBindingSha256: journalIntentBindingSha256
  });
  const dviCheckedAt = clock();
  const dviAuthorization = validateCurrentLaunchAuthorization(dviCheckedAt);
  const dviSpendReservation = reserveIntegratedLiveDrillSpend({
    authorization: dviAuthorization,
    claim: authorizationClaim,
    scopeId: "DVI_PROOF",
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    now: dviCheckedAt
  });
  spendReservations.push(dviSpendReservation);
  const dvi = await runComponent(
    path.join(rootDir, "scripts/gate1-admissible-vector.js"),
    ["--proof"],
    dviComponentEnvironment(environment, {
      ...childLaunchEnvironment(
        dviSpendReservation,
        dviAuthorization,
        dviCheckedAt
      )
    }),
    verifiedRootDir,
    { spec }
  );
  const postDviRelease = orchestrationMode === "PREPARE"
    ? await verifyRelease(spec, verifiedRootDir)
    : preRelease;
  if (canonicalJson(postDviRelease) !== canonicalJson(preRelease)) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
  }
  validateCurrentLaunchAuthorization();
  appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "DVI_RESULT",
    payload: dvi
  });
  const drill = parseAuthorityDrillBinding({
    runId: spec.runId,
    authorityEvidenceBindingSha256:
      dvi?.drill?.authorityEvidenceBindingSha256,
    selectedEvidenceId: authorityEvidenceId,
    selectedEvidenceDigest: authoritySelectedEvidenceDigest,
    alphaProposalDigest: authorityAlphaProposalDigest,
    bravoProposalDigest: authorityBravoProposalDigest,
    alphaLogicalActionDigest: authorityAlphaLogicalActionDigest,
    bravoLogicalActionDigest: authorityBravoLogicalActionDigest
  });
  const authorityCheckedAt = clock();
  const authorityAuthorization = validateCurrentLaunchAuthorization(
    authorityCheckedAt
  );
  const authoritySpendReservation = reserveIntegratedLiveDrillSpend({
    authorization: authorityAuthorization,
    claim: authorizationClaim,
    scopeId: "AWS_AUTHORITY_RACE",
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    now: authorityCheckedAt
  });
  spendReservations.push(authoritySpendReservation);
  const race = await runComponent(
    path.join(rootDir, "scripts/gate2-authority-race.js"),
    [
      "--config-digest",
      spec.configDigest,
      "--function-arn",
      spec.functionArn,
      "--race-id",
      spec.raceId,
      "--run-id",
      spec.runId,
      "--source-commit",
      spec.sourceCommit
    ],
    authorityComponentEnvironment(environment, drill, {
      ...childLaunchEnvironment(
        authoritySpendReservation,
        authorityAuthorization,
        authorityCheckedAt
      )
    }),
    verifiedRootDir,
    { spec }
  );
  const postRaceRelease = orchestrationMode === "PREPARE"
    ? await verifyRelease(spec, verifiedRootDir)
    : preRelease;
  if (
    canonicalJson(postRaceRelease) !== canonicalJson(preRelease) ||
    canonicalJson(postRaceRelease) !== canonicalJson(postDviRelease)
  ) {
    throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
  }
  validateCurrentLaunchAuthorization();
  appendIntegratedLiveDrillJournal({
    journalPath,
    evidenceRootPath: privateEvidenceRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    spec,
    phase: "AUTHORITY_RACE_RESULT",
    payload: race
  });
  const recoveryCheckedAt = clock();
  const recoveryAuthorization = validateCurrentLaunchAuthorization(
    recoveryCheckedAt
  );
  const recoverySpendReservation = reserveIntegratedLiveDrillSpend({
    authorization: recoveryAuthorization,
    claim: authorizationClaim,
    scopeId: "MANAGED_MCP_RECOVERY",
    ledgerRootPath: authorizationLedgerRootPath,
    forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
    now: recoveryCheckedAt
  });
  spendReservations.push(recoverySpendReservation);
  const recoveryAdditions = {
    RECOVERY_SOURCE_TENANT_ID: authorityTenantId,
    RECOVERY_SOURCE_RUN_ID: spec.runId,
    RECOVERY_SOURCE_INCIDENT_ID: authorityIncidentId,
    RECOVERY_SOURCE_EVIDENCE_ID: authorityEvidenceId,
    RECOVERY_SOURCE_RESOURCE_ID: authorityResourceId,
    RECOVERY_SOURCE_OPERATION_ID: race.winner?.operationId,
    RECOVERY_SOURCE_REQUEST_DIGEST: race.winner?.requestDigest,
    RECOVERY_SOURCE_AUTHORITY_EVIDENCE_BINDING_SHA256:
      race.dvi?.authorityEvidenceBindingSha256,
    RECOVERY_SOURCE_SELECTED_EVIDENCE_BINDING_SHA256:
      race.dvi?.selectedEvidenceBindingSha256,
    SOURCE_BUILD_IDENTITY: spec.sourceBuildIdentity,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT:
      forbiddenPrivateEvidenceRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT:
      privateEvidenceRootPath,
    TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH: path.join(
      privateEvidenceRootPath,
      `${spec.runId}.signed-recovery-bundle.json`
    ),
    TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC: canonicalJson(spec),
    ...childLaunchEnvironment(
      recoverySpendReservation,
      recoveryAuthorization,
      recoveryCheckedAt
    )
  };
  if (orchestrationMode === "PREPARE") {
    const paths = providerOrchestrationPaths(privateEvidenceRootPath, spec);
    const rootLease = acquireIntegratedLiveDrillPrivateRootLease({
      code: "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_ROOT_BINDING_REJECTED",
      forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
      rootPath: privateEvidenceRootPath
    });
    let decisionRootLease;
    try {
      decisionRootLease = acquireIntegratedLiveDrillPrivateRootLease({
        code:
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED",
        forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
        rootPath: authorizationLedgerRootPath
      });
      await rootLease.assertSettled();
      await decisionRootLease.assertSettled();
      const componentObservation = runComponent === defaultRunComponent
        ? null
        : rootLease.beginOperation();
      const rawGate1Preparation = await runComponent(
          path.join(
            rootDir,
            "scripts/gate1-integrated-live-drill-provider-supervisor.js"
          ),
          [],
          providerPreparationComponentEnvironment(environment, {
            ...recoveryAdditions,
            [PROVIDER_SUPERVISOR_MODE_ENVIRONMENT]: "PREPARE",
            [PROVIDER_SUPERVISOR_CONTEXT_PATH_ENVIRONMENT]: paths.contextPath,
            [PROVIDER_ROOT_BINDING_ENVIRONMENT]: canonicalJson(
              rootLease.binding
            ),
            [INTEGRATED_LIVE_DRILL_PRIVATE_ROOT_DESCRIPTOR_ENVIRONMENT]: "3"
          }),
          verifiedRootDir,
          {
            capabilityRootPath: privateEvidenceRootPath,
            rootDescriptor: rootLease.descriptor,
            spec
          }
        );
      if (componentObservation === null) {
        await rootLease.assertSettled();
      } else {
        rootLease.assertOperation(componentObservation);
      }
      const preparationEvidenceObservation = rootLease.beginOperation();
      const verifiedPreparationEvidence =
        verifyProviderPreparationEvidence({
          forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
          gate1Preparation: rawGate1Preparation,
          paths,
          rootBinding: rootLease.binding,
          rootPath: privateEvidenceRootPath
        });
      rootLease.assertOperation(preparationEvidenceObservation);
      const gate1Preparation =
        verifiedPreparationEvidence.gate1Preparation;
      const decisionPath = path.join(
        authorizationLedgerRootPath,
        `${spec.runId}.provider-orchestration-decision.json`
      );
      if (
        decisionRootLease.binding.rootPathSha256 !==
          integratedLiveDrillCanonicalSha256(authorizationLedgerRootPath)
      ) {
        throw new Error(
          "INTEGRATED_LIVE_DRILL_PROVIDER_ORCHESTRATION_DECISION_ROOT_REJECTED"
        );
      }
      const postSupervisorRelease = await verifyRelease(
        spec,
        verifiedRootDir
      );
      if (
        canonicalJson(postSupervisorRelease) !== canonicalJson(preRelease) ||
        canonicalJson(postSupervisorRelease) !== canonicalJson(postRaceRelease)
      ) {
        throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
      }
      const preparation =
        buildIntegratedLiveDrillProviderOrchestrationPreparation({
        authorityEvidenceId,
        authoritySelectedEvidenceDigest,
        decisionPathSha256: integratedLiveDrillCanonicalSha256(decisionPath),
        decisionRootBinding: decisionRootLease.binding,
        decisionRootPathSha256: integratedLiveDrillCanonicalSha256(
          authorizationLedgerRootPath
        ),
        dvi,
        evidenceRootBinding: rootLease.binding,
        gate1Preparation,
        journalIntentBindingSha256,
        journalPathSha256: sha256(journalPath),
        race,
        spec
      });
      const checkpointWriteObservation = rootLease.beginOperation();
      const persisted =
        persistIntegratedLiveDrillProviderOrchestrationPreparation({
        checkpointPath: paths.checkpointPath,
        forbiddenRootPath: forbiddenPrivateEvidenceRootPath,
        preparation,
        rootPath: privateEvidenceRootPath,
          spec
        });
      rootLease.assertOperation(checkpointWriteObservation);
      const preHoldRelease = await verifyRelease(spec, verifiedRootDir);
      if (
        canonicalJson(preHoldRelease) !== canonicalJson(preRelease) ||
        canonicalJson(preHoldRelease) !== canonicalJson(postDviRelease) ||
        canonicalJson(preHoldRelease) !== canonicalJson(postRaceRelease) ||
        canonicalJson(preHoldRelease) !== canonicalJson(postSupervisorRelease)
      ) {
        throw new Error("INTEGRATED_LIVE_DRILL_RELEASE_DRIFT");
      }
      await rootLease.assertSettled();
      await decisionRootLease.assertSettled();
      return sanitizedIntegratedLiveDrillProviderOrchestrationHold(
        persisted,
        spec
      );
    } finally {
      decisionRootLease?.release();
      rootLease.release();
    }
  }
  throw new Error("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED");
}

export async function main() {
  const receipt = await runIntegratedLiveDrill({
    environment: systemdIntegratedLiveDrillEnvironment(process.env)
  });
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  const exitCode = integratedLiveDrillCliExitCode(receipt);
  if (exitCode !== 0) {
    process.stderr.write(
      "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_REQUIRED\n"
    );
    process.exitCode = exitCode;
  }
}

export function integratedLiveDrillCliExitCode(receipt) {
  return [
    "HOLD_AWAITING_EXACT_PROVIDER_DISPATCH_AUTHORIZATION",
    "HOLD_AWAITING_GLOBAL_PROVIDER_DISPATCH",
    "AUDIT_ONLY_PROVIDER_RECONCILIATION_NOT_RELEASED"
  ].includes(receipt?.status)
    ? 3
    : 0;
}

export const __test = Object.freeze({
  defaultRunComponent,
  integratedLiveDrillCliExitCode,
  SYSTEMD_ORCHESTRATOR_INPUT_SCHEMA,
  systemdPrepareInputNames: Object.freeze([
    ...SYSTEMD_PREPARE_INPUT_NAMES
  ]),
  systemdResumeInputNames: Object.freeze([
    ...SYSTEMD_RESUME_INPUT_NAMES
  ])
});

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(
      `${safeIntegratedLiveDrillFailureCode(error)}\n`
    );
    process.exitCode = 1;
  });
}
